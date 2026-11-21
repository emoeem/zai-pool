"""zacc-web 安全集成测试：严格同源（防子串绕过）+ CSRF + exec 双闸。"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("ZACC_DIR", str(tmp_path / "accounts"))
    monkeypatch.setenv("ZCODE_V2_DIR", str(tmp_path / "v2"))
    (tmp_path / "v2").mkdir(parents=True)
    (tmp_path / "v2" / "credentials.json").write_text('{"oauth:zai:access_token":"T"}')

    spec = importlib.util.spec_from_file_location("zacc_web_mod", ROOT / "zacc-web.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["zacc_web_mod"] = mod
    spec.loader.exec_module(mod)

    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield mod, port
    srv.shutdown()


def _post(port, path, body=None, origin=None, csrf=None, host=None, extra=None):
    headers = {"Content-Type": "application/json"}
    if origin is not None:
        headers["Origin"] = origin
    if host is not None:
        headers["Host"] = host
    if csrf is not None:
        headers["X-CSRF"] = csrf
    headers.update(extra or {})
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 data=json.dumps(body or {}).encode(), headers=headers)
    try:
        r = urllib.request.urlopen(req)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_missing_origin_rejected(web):
    mod, port = web
    code, body = _post(port, "/api/use", {"name": "x"})
    assert code == 403 and "同源" in body["error"]


def test_substring_spoof_origin_rejected(web):
    """回归：旧版子串判断会被 127.0.0.1.attacker.example 绕过。"""
    mod, port = web
    for evil in (f"https://127.0.0.1.attacker.example",
                 f"http://127.0.0.1.attacker.example:{port}",
                 f"http://evil.com/?x=127.0.0.1:{port}",
                 f"http://127.0.0.1:{port + 1}"):
        code, _ = _post(port, "/api/use", {"name": "x"}, origin=evil)
        assert code == 403, f"恶意 Origin 未拦截: {evil}"


def test_valid_origin_but_wrong_port_rejected(web):
    mod, port = web
    code, _ = _post(port, "/api/use", {"name": "x"},
                    origin=f"http://127.0.0.1:{port + 5}")
    assert code == 403


def test_valid_origin_without_csrf_rejected(web):
    mod, port = web
    code, body = _post(port, "/api/use", {"name": "x"},
                       origin=f"http://127.0.0.1:{port}",
                       host=f"127.0.0.1:{port}")
    assert code == 403 and "CSRF" in body["error"]


def test_full_chain_with_csrf_reaches_handler(web):
    """同源 + CSRF 全对：403 消失（业务错误 500 = 越过了安全层）。"""
    mod, port = web
    r = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/list")
    csrf = json.loads(r.read())["csrf"]
    code, body = _post(port, "/api/use", {"name": "nonexistent"},
                       origin=f"http://127.0.0.1:{port}",
                       host=f"127.0.0.1:{port}", csrf=csrf)
    assert code != 403, body
    assert code == 500  # 业务层：档案不存在（安全层已放行）


def test_exec_double_gate(web):
    mod, port = web
    csrf = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/list").read())["csrf"]
    base = dict(origin=f"http://127.0.0.1:{port}", host=f"127.0.0.1:{port}", csrf=csrf)
    # 闸 1：env 未开
    code, body = _post(port, "/api/exec", {"name": "x", "cmd": "id"}, **base)
    assert code == 403 and "默认关闭" in body["error"]
    # 闸 2：env 开但无令牌
    os.environ["ZACC_WEB_ALLOW_EXEC"] = "1"
    try:
        code, body = _post(port, "/api/exec", {"name": "x", "cmd": "id"}, **base)
        assert code == 403 and "X-Auth" in body["error"]
        # 双闸全过 + 无效档案 → 业务 500（不真正执行）
        code, body = _post(port, "/api/exec", {"name": "nonexistent", "cmd": "id"},
                           **base, extra={"X-Auth": mod.WEB_TOKEN})
        assert code != 403
    finally:
        os.environ.pop("ZACC_WEB_ALLOW_EXEC", None)
