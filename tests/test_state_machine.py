"""状态机与调度原子性。"""
from __future__ import annotations

import threading


def test_cooldown_429_bounded_backoff(zp):
    pool = zp.POOL
    a = pool.accounts[0]
    pool.cooldown(a, 429, "rate limited", {})
    first = a.cool_until
    assert a.cool_reason == "rate_limited"
    # 连续 429 指数上升
    a.cool_until = 0
    a.fails = 2
    pool.cooldown(a, 429, "rate limited", {})
    assert a.cool_until > first


def test_cooldown_402_until_next_reset(zp):
    pool = zp.POOL
    a = pool.accounts[0]
    pool.cooldown(a, 402, "Insufficient balance")
    assert a.cool_reason == "exhausted"
    reset = zp.next_reset(pool.reset_hour)
    assert abs(a.cool_until - reset) < 1


def test_breaker_after_3_consecutive_5xx(zp):
    pool = zp.POOL
    a = pool.accounts[0]
    for _ in range(3):
        pool.cooldown(a, 503, "upstream error")
    assert a.breaker_until > 0, "3 连败触发熔断"
    assert a.retry_count == 1
    # 成功后清零
    pool.ok(a)
    assert a.fails == 0


def test_cooldown_never_extends_existing(zp):
    """markFailure 语义：已有更长冷却不被短冷却覆盖。"""
    pool = zp.POOL
    a = pool.accounts[0]
    a.cool_until = zp.time.time() + 86400  # 既有 1 天冷却
    a.cool_reason = "exhausted"
    pool.cooldown(a, 503, "server error")  # 60s 短冷却不得覆盖
    assert a.cool_reason == "exhausted"
    assert a.cool_until > zp.time.time() + 80000


def test_in_flight_atomic_lease(zp):
    """并发 pick+acquire 不得超过 max_in_flight（选号与租约同临界区）。"""
    pool = zp.POOL
    a = pool.accounts[0]
    a.max_in_flight = 2
    picked = []

    def worker():
        with zp._sched_lock:
            acc = pool.pick("", set())
            if acc and acc.in_flight < acc.max_in_flight:
                acc.in_flight += 1
                picked.append(acc.name)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert a.in_flight <= 2, f"并发租约超卖: {a.in_flight}"


def test_error_classification_pass_through(zp, tmp_path):
    """审查升级：真 HTTP 驱动 _relay——400 原样透传且账号不冷却；401 冷却。"""
    import urllib.request
    import urllib.error
    import threading
    mod = zp

    class FakeResp:
        def __init__(self, status, body):
            self.status = status
            self._b = body

        def read(self, n=-1):
            out, self._b = self._b, b""
            return out

        def getheaders(self):
            return [("content-type", "application/json")]

    cfg = {"listen": "127.0.0.1:0", "api_key": "test-key-0123456789abcdef",
           "max_retry": 3,
           "accounts": [{"name": "a1", "api_key": "P1"}, {"name": "a2", "api_key": "P2"}]}
    mod.POOL = mod.Pool(cfg)
    mod.STATE_FILE = ""
    a1, a2 = mod.POOL.accounts

    def fake_upstream(a, path, body=b"", extra=None, method="POST", host=None, timeout=600):
        # 与选号顺序解耦：body 里的模型名决定上游行为（真实上游语义：坏模型=400，与账号无关）
        try:
            model = json.loads(body).get("model")
        except Exception:
            model = ""
        if model == "bad-model":
            return 400, {"content-type": "application/json"}, FakeResp(400, b'{"error":{"message":"invalid model"}}')
        return 401, {"content-type": "application/json"}, FakeResp(401, b'{"error":"auth"}')

    mod.upstream_request = fake_upstream
    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        hdr = {"Authorization": "Bearer test-key-0123456789abcdef",
               "Content-Type": "application/json"}
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps({"model": "bad-model",
                             "messages": [{"role": "user", "content": "x"}]}).encode(),
            headers=hdr)
        code = None
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            code = e.code
            assert b"invalid model" in e.read()
        assert code == 400, "400 必须原样透传状态码"
        assert all(x.cool_until == 0 for x in (a1, a2)), "400 不得冷却任何账号"
        # 401：所有号都 401 → 冷却 → 换号 → 无号可用 → 503
        req2 = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps({"model": "glm-5.3-flash",
                             "messages": [{"role": "user", "content": "x"}]}).encode(),
            headers=hdr)
        try:
            urllib.request.urlopen(req2)
        except urllib.error.HTTPError as e:
            assert e.code == 503
        assert a1.cool_until > 0 and a2.cool_until > 0, "401 必须冷却"
    finally:
        srv.shutdown()


def test_alerter_pending_to_firing(zp):
    """修复回归：pending 态第二次坏 tick 必须转 firing（旧实现卡死在 pending）。"""
    al = zp.Alerter({"enabled": True, "webhook_url": "http://127.0.0.1:1/hook",
                     "min_healthy": 2, "for_ticks": 2, "clear_ticks": 2})
    al.started -= 60  # 跳过 StartupGrace
    sent = []
    al._send = lambda text: sent.append(text)
    al.tick(healthy=1, total=3)   # 第 1 次坏 → pending
    assert al.state == "pending"
    al.tick(healthy=1, total=3)   # 第 2 次坏 → firing（旧 bug 卡 pending）
    assert al.state == "firing"
    assert len(sent) == 1, "边沿触发只发一次"
    al.tick(healthy=1, total=3)   # firing 中不重发
    assert len(sent) == 1
    al.tick(healthy=3, total=3)   # 恢复 tick 1
    al.tick(healthy=3, total=3)   # 恢复 tick 2 → clear
    assert al.state == "ok"
    assert len(sent) == 2


def test_hot_reload_full_fields(zp, tmp_path):
    mod = zp
    cfg = {
        "api_key": "test-key-0123456789abcdef",
        "strategy": "balanced", "max_retry": 7, "reset_hour": 5, "sticky_minutes": 12,
        "accounts": [{"name": "a1", "api_key": "P1", "realm": "global",
                      "zcode_jwt": "JWT1", "device_mid": "MID1", "max_in_flight": 3}],
        "devices": [{"name": "devA", "key": "dkp-a", "accounts": ["a1"]}],
    }
    p = tmp_path / "pool.json"
    p.write_text(json.dumps(cfg))
    mod.CFG_PATH = str(p)
    mod.reload_config()
    assert mod.POOL.strategy == "balanced"
    assert mod.POOL.max_retry == 7
    assert mod.POOL.reset_hour == 5
    assert mod.POOL.sticky_min == 12
    a1 = mod.POOL.accounts[0]
    assert a1.zcode_jwt == "JWT1" and a1.device_mid == "MID1" and a1.max_in_flight == 3


import json  # noqa: E402  (置底避免顶部与 fixture 冲突)
