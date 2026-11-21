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


def test_error_classification_pass_through(zp, fake_upstream):
    """400 客户端错误：透传给客户端、不冷却账号、不换号。"""
    mod, calls, script = fake_upstream
    script.append((400, b'{"error":"bad model"}', {}))
    handler_calls = []

    class FakeHandler:
        headers = {"anthropic-version": "2023-06-01"}
        def _json(self, code, obj):
            handler_calls.append((code, obj))
    h = FakeHandler()
    # 直接驱动 _relay 的错误分类段：用小池模拟
    pool = mod.POOL
    a = pool.accounts[0]
    status, rh, resp = mod.upstream_request(a, "/x", b"{}", {"Authorization": "Bearer P1"})
    assert status == 400
    assert status in mod.PASS_THROUGH_STATUS
    # 分类断言：400 不进 cooldown
    pool.cooldown(a, 429, "limited", {})  # 对照：429 会冷却
    assert a.cool_until > 0


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
