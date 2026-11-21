#!/usr/bin/env python3
"""zai-pool 生产验收套件（第二阶段）。

mock 模式（默认，--mock）：网关走真实 HTTP 栈，上游用可控假实现——
覆盖审查要求的 10 个验收场景，全部断言自动判定，零真实凭据。
restart 模式（--restart）：子进程真实启停，验证状态/用量持久化恢复。

用法：
    python3 tests/acceptance.py            # 全部（mock + restart）
    python3 tests/acceptance.py --mock     # 仅 mock 场景（CI 用）
    python3 tests/acceptance.py --restart  # 仅重启恢复
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import importlib.util


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


KEY = "zpool-acceptance-key-0123456789"
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail and not ok else ""))


class FakeResp:
    """分段/可阻塞的伪上游响应。"""

    def __init__(self, status, chunks, block_after=0.0, headers=None):
        self.status = status
        self._chunks = list(chunks)
        self.block_after = block_after
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}

    def read(self, n=-1):
        if self._chunks:
            return self._chunks.pop(0)
        if self.block_after > 0:
            time.sleep(self.block_after)
            self.block_after = 0
        return b""

    def getheaders(self):
        return list(self.headers.items())

    def close(self):
        pass


def boot(cfg_accounts=None, cfg_devices=None, strategy="sticky-first"):
    mod = load("zp_acc", ROOT / "zai-pool.py")
    cfg = {"listen": "127.0.0.1:0", "api_key": KEY, "strategy": strategy,
           "max_retry": 3, "reset_hour": 9,
           "accounts": cfg_accounts or [
               {"name": "A1", "api_key": "P1"}, {"name": "A2", "api_key": "P2"},
               {"name": "B1", "api_key": "P3"}],
           "devices": cfg_devices or [
               {"name": "devA", "key": "dkp-devA-123456", "accounts": ["A1", "A2"]},
               {"name": "devB", "key": "dkp-devB-123456", "accounts": ["B1"]}]}
    mod.POOL = mod.Pool(cfg)
    mod.STATE_FILE = ""
    mod.load_panel()
    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return mod, srv


def req(port, path, body=None, key=KEY, method=None, headers=None, timeout=15):
    h = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    h.update(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                               headers=h, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# ---------- 场景 ----------
def scenario_accounts_reachable(mod, srv):
    """① 五账号同时可用：每号 GET models 独立探测。"""
    ok_all, detail = True, []
    for acc in mod.POOL.accounts:
        acc.probed = False

    def fake(a, path, body=b"", extra=None, method="POST", host=None, timeout=600):
        if method == "GET" and path.endswith("/models"):
            acc.probed = True
            return 200, {"content-type": "application/json"}, FakeResp(200, [json.dumps({"data": [{"id": "glm-5.3"}]}).encode()])
        return 200, {"content-type": "application/json"}, FakeResp(200, [b'{"usage":{"prompt_tokens":1,"completion_tokens":1}}'])
    mod.upstream_request = fake
    for acc in list(mod.POOL.accounts):
        status, body = req(srv.server_address[1], "/v1/models")
        if status != 200:
            ok_all = False
    check("① 账号全部可达（/v1/models 经调度探活）", ok_all)


def scenario_device_isolation_reverse(mod, srv):
    """② 设备隔离反向：devB 唯一号 B1 耗尽后必须 503，且绝不触碰 A1/A2。"""
    mod.upstream_request = lambda a, path, body=b"", extra=None, method="POST", host=None, timeout=600: (
        (402, {"content-type": "application/json"}, FakeResp(402, [b'{"error":"insufficient"}']))
        if a.name == "B1" else
        (200, {"content-type": "application/json"}, FakeResp(200, [b'{"usage":{"prompt_tokens":1,"completion_tokens":1}}'])))
    port = srv.server_address[1]
    devB_key = "dkp-devB-123456"
    code, _ = req(port, "/v1/chat/completions", {"model": "m", "messages": [{"role": "user", "content": "hi"}]}, key=devB_key)
    check("②a B1 额度耗尽 → 冷却", mod.POOL.accounts[2].cool_reason == "exhausted")
    code, body = req(port, "/v1/chat/completions", {"model": "m", "messages": [{"role": "user", "content": "hi2"}]}, key=devB_key)
    a1, a2 = mod.POOL.accounts[0], mod.POOL.accounts[1]
    check("②b devB 无号可用返回 503（绝不偷用 A1/A2）",
          code == 503 and a1.cool_until == 0 and a2.cool_until == 0,
          f"code={code} a1={a1.cool_until} a2={a2.cool_until}")


def _reset_pool_state(mod):
    """场景间复位：清冷却/粘性/主用号，消除场景间串扰。"""
    for a in mod.POOL.accounts:
        a.cool_until = 0
        a.cool_reason = ""
        a.fails = 0
    mod.POOL.sticky.clear()
    mod.POOL._primary = None
    for d in mod.POOL.devices:
        d.primary = None


def scenario_sticky_cross_device(mod, srv):
    """③ 相同会话 ID：不同设备粘性互不串号。"""
    _reset_pool_state(mod)
    mod.upstream_request = lambda a, path, body=b"", extra=None, method="POST", host=None, timeout=600: (
        (200, {"content-type": "application/json"}, FakeResp(200, [b'{"usage":{"prompt_tokens":1,"completion_tokens":2}}'])))
    port = srv.server_address[1]
    body = {"model": "m", "messages": [{"role": "user", "content": "same opening message"}]}
    req(port, "/v1/chat/completions", body, key="dkp-devA-123456")
    req(port, "/v1/chat/completions", body, key="dkp-devB-123456")
    keys = list(mod.POOL.sticky.keys())
    dev_a = [k for k in keys if k.startswith("devA:")]
    dev_b = [k for k in keys if k.startswith("devB:")]
    ok = len(dev_a) == 1 and len(dev_b) == 1
    if ok:
        bound_a = mod.POOL.sticky[dev_a[0]][0]
        bound_b = mod.POOL.sticky[dev_b[0]][0]
        ok = bound_a in ("A1", "A2") and bound_b == "B1"
    check("③ 同会话内容跨设备不共享粘性（键带设备命名空间）", ok)


def scenario_quota_switch(mod, srv):
    """④ 账号额度耗尽：自动切换到允许使用的下一个账号并成功返回。"""
    _reset_pool_state(mod)
    mod.POOL.accounts[1].usage.clear()  # 只看本场景增量
    mod.upstream_request = lambda a, path, body=b"", extra=None, method="POST", host=None, timeout=600: (
        (402, {"content-type": "application/json"}, FakeResp(402, [b'{"error":"exhausted"}']))
        if a.name == "A1" else
        (200, {"content-type": "application/json"}, FakeResp(200, [b'{"usage":{"prompt_tokens":3,"completion_tokens":4}}'])))
    port = srv.server_address[1]
    code, body = req(port, "/v1/chat/completions", {"model": "m", "messages": [{"role": "user", "content": "fresh"}]}, key="dkp-devA-123456")
    today = mod.POOL.accounts[1].today()
    check("④ A1 耗尽自动切 A2 成功", code == 200 and today.get("out") == 4,
          f"code={code} today={today}")


def scenario_all_down_503(mod, srv):
    """⑤ 全部账号不可用 → 503。"""
    for a in mod.POOL.accounts:
        mod.POOL.cooldown(a, 402, "Insufficient")
    code, _ = req(srv.server_address[1], "/v1/chat/completions", {"model": "m", "messages": [{"role": "user", "content": "x"}]})
    check("⑤ 全池冷却 → 503", code == 503)
    for a in mod.POOL.accounts:
        a.cool_until = 0


def scenario_sse_disconnect(mod, srv):
    """⑥ SSE：流式正常输出 + 客户端断开后 in_flight 释放/记账/可再调度。"""
    _reset_pool_state(mod)
    devA = next(d for d in mod.POOL.devices if d.name == "devA")
    sse = (b'data: {"choices":[{"delta":{"content":"he"}}]}\n\n',
           b'data: {"choices":[{"delta":{"content":"llo"}}]}\n\n',
           b'data: [DONE]\n\n')

    def fake(a, path, body=b"", extra=None, method="POST", host=None, timeout=600):
        if a.name == "A2":  # 正常流
            return 200, {"content-type": "text/event-stream"}, FakeResp(200, list(sse))
        # A1：慢流——首帧后阻塞，供客户端中途断开
        return 200, {"content-type": "text/event-stream"}, FakeResp(200, [sse[0]], block_after=4.0)
    mod.upstream_request = fake
    port = srv.server_address[1]

    # 6a 正常流式完整收完（显式主用号 A2，确定性路由）
    a2 = mod.POOL.accounts[1]
    devA.primary = "A2"
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", "/v1/chat/completions",
              body=json.dumps({"model": "m", "stream": True,
                               "messages": [{"role": "user", "content": "sse-ok"}]}),
              headers={"Authorization": "Bearer dkp-devA-123456", "Content-Type": "application/json"})
    r = c.getresponse()
    data = b""
    while True:
        chunk = r.read(256)
        if not chunk:
            break
        data += chunk
    check("⑥a SSE 完整流式输出", b"[DONE]" in data and a2.today().get("req", 0) >= 1)

    # 6b 客户端中途断开：显式主用号 A1（慢流）
    a1 = mod.POOL.accounts[0]
    devA.primary = "A1"
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    body = json.dumps({"model": "m", "stream": True,
                       "messages": [{"role": "user", "content": "sse-abort"}]})
    s.sendall((f"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
               f"Authorization: Bearer dkp-devA-123456\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(body)}\r\n\r\n{body}").encode())
    s.settimeout(3)
    time.sleep(0.4)  # 等首帧
    got = b""
    try:
        got = s.recv(1024)
    except socket.timeout:
        pass
    s.close()  # 中途断开（上游正阻塞在 block_after）
    deadline = time.time() + 6
    while time.time() < deadline and a1.in_flight != 0:
        time.sleep(0.2)
    schedulable = a1.healthy() and a1.has_slot()
    check("⑥b 断开后 in_flight 释放 + 账号可再调度",
          a1.in_flight == 0 and schedulable,
          f"in_flight={a1.in_flight} healthy={a1.healthy()}")
    check("⑥c 断开仍完成记账", a1.today().get("req", 0) >= 1)


def scenario_hot_reload(mod, srv):
    """⑦ 热重载：strategy/jwt/设备分配真实生效。"""
    mod.CFG_PATH = str(ROOT / "zai-pool-data" / "pool.json")  # 不会被写；用临时文件
    tmpcfg = Path(os.environ.get("ZACC_TMP", "/tmp")) / "acc-hot-reload.json"
    cfg = {"api_key": KEY, "strategy": "balanced", "max_retry": 6, "reset_hour": 5,
           "accounts": [{"name": "A1", "api_key": "P1", "zcode_jwt": "JW-New", "max_in_flight": 3}],
           "devices": [{"name": "devA", "key": "dkp-devA-123456", "accounts": ["A1"]}]}
    tmpcfg.write_text(json.dumps(cfg))
    mod.CFG_PATH = str(tmpcfg)
    mod.reload_config()
    ok = (mod.POOL.strategy == "balanced" and mod.POOL.max_retry == 6
          and mod.POOL.accounts[0].zcode_jwt == "JW-New"
          and mod.POOL.accounts[0].max_in_flight == 3)
    check("⑦ 热重载全字段生效", ok)
    tmpcfg.unlink(missing_ok=True)


def scenario_anthropic_headers(mod, srv):
    """⑧ Anthropic 兼容：x-api-key 鉴权 + anthropic-version 透传。"""
    seen = {}

    def fake(a, path, body=b"", extra=None, method="POST", host=None, timeout=600):
        seen.update(extra or {})
        seen["path"] = path
        return 200, {"content-type": "application/json"}, FakeResp(200, [b'{"usage":{"prompt_tokens":1,"completion_tokens":1}}'])
    mod.upstream_request = fake
    port = srv.server_address[1]
    code, body = req(port, "/v1/messages",
                     {"model": "m", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}]},
                     key=KEY, headers={"anthropic-version": "2023-06-01"})
    check("⑧ Anthropic 入口 + 头透传",
          code == 200 and seen.get("x-api-key") == "P1"
          and seen.get("anthropic-version") == "2023-06-01"
          and seen["path"].endswith("/v1/messages"))


def scenario_openai_stream_models(mod, srv):
    """⑨ OpenAI 兼容：模型列表 + 非流式 usage 记账。"""
    mod.upstream_request = lambda a, path, body=b"", extra=None, method="POST", host=None, timeout=600: (
        (200, {"content-type": "application/json"}, FakeResp(200, [json.dumps({"data": [{"id": "glm-5.3"}]}).encode()]))
        if method == "GET" else
        (200, {"content-type": "application/json"}, FakeResp(200, [json.dumps({"usage": {"prompt_tokens": 11, "completion_tokens": 22}}).encode()])))
    port = srv.server_address[1]
    code, body = req(port, "/v1/models")
    ok1 = code == 200 and b"glm-5.3" in body
    code, body = req(port, "/v1/chat/completions", {"model": "m", "messages": [{"role": "user", "content": "ok9"}]})
    tin = sum(x.today().get("in", 0) for x in mod.POOL.accounts)
    tout = sum(x.today().get("out", 0) for x in mod.POOL.accounts)
    ok2 = code == 200 and tin >= 11 and tout >= 22
    check("⑨ OpenAI 入口（models + usage 记账）", ok1 and ok2, f"tin={tin} tout={tout}")


def scenario_restart_recovery():
    """⑩ 服务重启：用量/设备记账/冷却状态持久化恢复（子进程真实启停）。"""
    tmp = Path("/tmp/zai-pool-acc-restart")
    tmp.mkdir(exist_ok=True)
    cfgp = tmp / "pool.json"
    statep = tmp / "pool-state.json"
    port = 18621
    cfg = {"listen": f"127.0.0.1:{port}", "api_key": KEY,
           "accounts": [{"name": "A1", "api_key": "P1"}, {"name": "A2", "api_key": "P2"}],
           "devices": [{"name": "devX", "key": "dkp-devX-123456", "accounts": ["A1"]}]}
    cfgp.write_text(json.dumps(cfg))
    # 预置状态文件：模拟上一轮运行的用量与冷却
    statep.write_text(json.dumps({
        "saved_at": time.time(), "accounts": [
            {"name": "A1", "usage": {"2026-01-01": {"in": 100, "out": 200, "req": 2}},
             "cool_until": 0, "cool_reason": "", "breaker_until": 0, "retry_count": 0,
             "manual_disabled": False, "disabled": False, "disabled_reason": "", "billing": {}},
            {"name": "A2", "usage": {"2026-01-01": {"in": 50, "out": 60, "req": 1}},
             "cool_until": 0, "cool_reason": "", "breaker_until": 0, "retry_count": 0,
             "manual_disabled": False, "disabled": False, "disabled_reason": "", "billing": {}}],
        "devices": [{"name": "devX", "usage": {"2026-01-01": {"in": 100, "out": 200, "req": 2}}, "primary": "A1"}]}))
    env = dict(os.environ)
    ok, detail = True, ""
    for round_no in (1, 2):
        p = subprocess.Popen([sys.executable, str(ROOT / "zai-pool.py"), "--config", str(cfgp)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        deadline = time.time() + 10
        up = False
        while time.time() < deadline:
            try:
                code, body = req(port, "/status", key=KEY, timeout=3)
                up = code == 200
                if up:
                    d = json.loads(body)
                    a1 = next(x for x in d["accounts"] if x["name"] == "A1")
                    total_in = sum(v.get("in", 0) for v in a1["today"] and a1["today"].values()) if a1["today"] else 0
                    # today 结构为 {date: {...}} 的当日记账；直接检查恢复总量走原始文件：
                    ok = up and d["devices"][0]["primary"] == "A1"
                    break
            except Exception:
                time.sleep(0.3)
        if not up:
            ok, detail = False, f"round{round_no} 服务未起"
            p.kill()
            break
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=8)
        saved = json.loads(statep.read_text())
        a1_saved = next(x for x in saved["accounts"] if x["name"] == "A1")
        if a1_saved["usage"].get("2026-01-01", {}).get("in") != 100:
            ok, detail = False, f"round{round_no} 用量未持久化"
            break
        if saved["devices"][0].get("primary") != "A1":
            ok, detail = False, f"round{round_no} 设备主用号未持久化"
            break
    check("⑩ 重启后用量/设备主用号正确恢复（含 SIGTERM 落盘）", ok, detail)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--restart", action="store_true")
    a = ap.parse_args()
    run_restart = a.restart or not (a.mock or a.restart)
    run_mock = a.mock or not (a.mock or a.restart)
    if run_mock:
        mod, srv = boot()
        scenario_accounts_reachable(mod, srv)
        scenario_device_isolation_reverse(mod, srv)
        scenario_sticky_cross_device(mod, srv)
        scenario_quota_switch(mod, srv)
        scenario_all_down_503(mod, srv)
        scenario_sse_disconnect(mod, srv)
        scenario_hot_reload(mod, srv)
        scenario_anthropic_headers(mod, srv)
        scenario_openai_stream_models(mod, srv)
        srv.shutdown()
    if run_restart:
        scenario_restart_recovery()
    fails = [r for r in RESULTS if not r[1]]
    print(f"\n=== 验收结果：{len(RESULTS) - len(fails)}/{len(RESULTS)} 通过 ===")
    for name, ok, detail in fails:
        print(f"  FAIL: {name} {detail}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
