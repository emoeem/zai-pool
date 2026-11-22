"""Phase 4：资源边界（连接上限/SSE 配额/增量解析/限流/超时分离）。"""
from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request


def test_sse_parser_split_across_chunks(zp):
    """一个 SSE 事件被拆到多个 TCP chunk：增量解析必须拼出 usage。"""
    p = zp.SSEUsageParser()
    p.feed(b'data: {"choices":[{"delta":{"content":"he')
    assert p.tin is None and p.tout is None
    p.feed(b'llo"}}]}\n\n')
    p.feed(b'data: {"usage":{"prompt_tokens":7,"completion_tok')
    p.feed(b'ens":9}}\n\ndata: [DONE]\n\n')
    assert (p.tin, p.tout) == (7, 9)


def test_sse_parser_multiple_events_one_chunk(zp):
    p = zp.SSEUsageParser()
    p.feed(b'data: {"choices":[]}\n\ndata: {"usage":{"prompt_tokens":3,"completion_tokens":5}}\n\ndata: [DONE]\n\n')
    assert (p.tin, p.tout) == (3, 5)


def test_sse_parser_ignores_malformed(zp):
    p = zp.SSEUsageParser()
    p.feed(b"data: not-json\n\nevent: ping\n\n")
    assert p.tin is None and p.tout is None


def test_token_bucket_semantics(zp):
    b = zp.TokenBucket(120, capacity=2)  # 2/秒，桶容量 2
    assert b.allow() and b.allow()       # 初始两枚
    assert not b.allow()                 # 空桶拒绝
    time.sleep(0.55)                     # 补 ~1 枚
    assert b.allow()


def test_rate_limit_local_429_no_upstream_cooldown(zp):
    """设备级限流：超限 429，且绝不触碰账号冷却状态机。"""
    mod = zp
    mod.POOL.server_cfg["device_rate_limit_per_min"] = 2
    mod.POOL._device_buckets.clear()
    devA = mod.POOL.device_by_name("devA")
    results = [mod.POOL.allow_request(devA) for _ in range(5)]
    assert results[:2] == [True, True] and not all(results), "第 3 次起必须被限流"
    assert all(a.cool_until == 0 for a in mod.POOL.accounts), "本地限流不得冷却上游账号"


def test_global_rate_limit_burst(zp):
    mod = zp
    mod.POOL.server_cfg["rate_limit_per_min"] = 3
    mod.POOL._global_bucket = mod.TokenBucket(3)
    results = [mod.POOL.allow_request(None) for _ in range(6)]
    assert results.count(True) <= 3 + 1  # 桶容量 + 一点补充


def test_connection_cap_rejects_with_503(zp):
    """4.1：max_connections=2，4 个并发慢请求 → 2 个被服务，2 个立即 503。"""
    mod = zp
    mod.POOL.server_cfg["max_connections"] = 2
    srv = mod.BoundedServer(("127.0.0.1", 0), mod.Handler, mod.POOL.server_cfg)
    port = srv.server_address[1]
    mod.upstream_request = lambda a, path, body=b"", extra=None, method="POST", host=None, timeout=600: (
        _sleep_resp(1.2))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    codes: list[int] = []

    def one():
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/chat/completions",
                data=json.dumps({"model": "m", "messages": [{"role": "user", "content": "x"}]}).encode(),
                headers={"Authorization": "Bearer test-key-0123456789abcdef",
                         "Content-Type": "application/json"}), timeout=8)
            codes.append(r.status)
        except urllib.error.HTTPError as e:
            codes.append(e.code)
        except Exception:
            codes.append(-1)

    threads = [threading.Thread(target=one) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    srv.shutdown()
    assert codes.count(503) >= 1, f"超限连接必须被拒绝: {codes}"
    assert 200 in codes


def _sleep_resp(seconds: float):
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "zp_sl", Path(__file__).resolve().parent.parent / "zai-pool.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class SlowResp:
        status = 200
        headers = {"content-type": "application/json"}

        def read(self, n=-1):
            time.sleep(seconds)
            return b'{"usage":{"prompt_tokens":1,"completion_tokens":1}}'

        def getheaders(self):
            return list(self.headers.items())
    return 200, {"content-type": "application/json"}, SlowResp()


def test_sse_quota_exhaustion(zp):
    """4.1：max_sse_connections=1，占住 SSE 后第二个流式请求明确 503，普通请求不受影响。"""
    mod = zp
    mod.POOL.server_cfg["max_sse_connections"] = 1
    srv = mod.BoundedServer(("127.0.0.1", 0), mod.Handler, mod.POOL.server_cfg)
    port = srv.server_address[1]

    def fake(a, path, body=b"", extra=None, method="POST", host=None, timeout=600):
        return _sleep_resp(2.5)
    mod.upstream_request = fake
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    hdr = {"Authorization": "Bearer test-key-0123456789abcdef",
           "Content-Type": "application/json"}
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    body = json.dumps({"model": "m", "stream": True,
                       "messages": [{"role": "user", "content": "x"}]})
    s.sendall((f"POST /v1/chat/completions HTTP/1.1\r\nHost: h\r\n"
               f"Authorization: Bearer test-key-0123456789abcdef\r\n"
               f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}").encode())
    time.sleep(0.4)
    assert srv.sse_active == 1
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=body.encode(), headers=hdr), timeout=5)
        second = 200
    except urllib.error.HTTPError as e:
        second = e.code
    # 普通（非流式）请求不受 SSE 配额影响
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps({"model": "m", "stream": False,
                             "messages": [{"role": "user", "content": "x"}]}).encode(),
            headers=hdr), timeout=8)
        third = 200
    except urllib.error.HTTPError as e:
        third = e.code
    s.close()
    srv.shutdown()
    assert second == 503, f"SSE 配额占满必须 503: {second}"
    assert third == 200, "普通请求不得被 SSE 占用影响"


def test_timeout_split_stream_vs_sync(zp, fake_upstream):
    """4.3：非流式与流式使用不同超时（真 HTTP 驱动 _relay，mock 捕获 timeout）。"""
    mod, calls, script = fake_upstream
    mod.POOL.server_cfg["request_timeout"] = 111
    mod.POOL.server_cfg["stream_idle_timeout"] = 42
    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    hdr = {"Authorization": "Bearer test-key-0123456789abcdef",
           "Content-Type": "application/json"}
    try:
        for want_stream, want_to in ((False, 111.0), (True, 42.0)):
            n0 = len(calls)
            urllib.request.urlopen(urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/chat/completions",
                data=json.dumps({"model": "m", "stream": want_stream,
                                 "messages": [{"role": "user", "content": "x"}]}).encode(),
                headers=hdr), timeout=10)
            assert calls[n0]["timeout"] == want_to, \
                f"stream={want_stream} 应使用 timeout={want_to}，实际 {calls[n0]['timeout']}"
    finally:
        srv.shutdown()
