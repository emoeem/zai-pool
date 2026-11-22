"""Phase 7：单账号探活/只读巡检/领取台账/设备禁用端点（mock 上游）。"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


def _hdr():
    return {"Authorization": "Bearer test-key-0123456789abcdef",
            "Content-Type": "application/json"}


def _req(port, path, body=None):
    data = json.dumps(body or {}).encode() if body is not None else b"{}"
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=_hdr())
    try:
        resp = urllib.request.urlopen(r, timeout=15)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_admin_probe_and_billing_check(zp, fake_upstream):
    mod, calls, script = fake_upstream
    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    port = srv.server_address[1]
    threading_start = threading.Thread(target=srv.serve_forever, daemon=True)
    threading_start.start()
    try:
        # 探活：a1 模型列表 200
        code, body = _req(port, "/admin/accounts/a1/probe", {})
        assert code == 200 and body["healthy"] is True and body["http"] == 200
        assert calls[-1]["method"] == "GET"
        # 只读巡检：无 zcode_jwt → 400（不盲查）
        code, body = _req(port, "/admin/accounts/a1/billing-check", {})
        assert code == 400 and "zcode_jwt" in body["error"]
        # 探活不存在的账号 → 404
        code, _ = _req(port, "/admin/accounts/nope/probe", {})
        assert code == 404
    finally:
        srv.shutdown()


import threading  # noqa: E402


def test_device_disable_blocks_relay(zp, fake_upstream):
    mod, calls, script = fake_upstream
    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        code, body = _req(port, "/admin/devices/devA/disable", {})
        assert code == 200 and body["disabled"] is True
        # 被禁设备 key → 403 device_disabled（租约/上游零接触）
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps({"model": "m", "messages": [{"role": "user", "content": "x"}]}).encode(),
            headers={"Authorization": "Bearer dkp-a", "Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10)
            blocked = False
        except urllib.error.HTTPError as e:
            blocked = e.code == 403
        assert blocked, "禁用设备的请求必须 403"
        assert all(a.stats["req"] == 0 for a in mod.POOL.accounts), "禁用不得消耗任何账号槽位"
        # 启用恢复
        code, body = _req(port, "/admin/devices/devA/enable", {})
        assert code == 200 and body["disabled"] is False
    finally:
        srv.shutdown()


def test_billing_ledger_endpoint(zp, fake_upstream, tmp_path):
    mod = zp
    ledger = tmp_path / "billing-ledger.jsonl"
    ledger.write_text(
        '{"date":"2026-11-22","account":"a1","plan_id":"p1","status":"success","detail":"ok","trigger":"manual","api_status":200,"verified_at":1}\n')
    mod.CFG_PATH = str(tmp_path / "pool.json")  # ledger 路径由 CFG_PATH 推导
    (tmp_path / "pool.json").write_text("{}")
    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = urllib.request.Request(f"http://127.0.0.1:{port}/billing/ledger",
                                   headers={"Authorization": "Bearer test-key-0123456789abcdef"})
        resp = urllib.request.urlopen(r, timeout=10)
        code = resp.status
        body = json.loads(resp.read())
        assert code == 200 and body["entries"][0]["account"] == "a1"
    finally:
        srv.shutdown()
