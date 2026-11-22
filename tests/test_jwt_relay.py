"""Phase9（zcode2api 借鉴移植）：JWT 通道接线 / chat_via / captcha 管理 / 迁移解析。"""
from __future__ import annotations

import base64
import importlib.util
import json
import sqlite3
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from zai_pool.core import Account, jwt_exp, _derive_chat_mode  # noqa: E402
from zai_pool.upstream import normalize_jwt_body  # noqa: E402
from zai_pool.captcha import CaptchaManager  # noqa: E402
from billing.adapter import BillingAdapter  # noqa: E402
from billing.parser import BillingParseError, parse_usage  # noqa: E402


def make_jwt(uid: str = "u1", exp=None) -> str:
    h = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
    p = {"user_id": uid}
    if exp is not None:
        p["exp"] = exp
    b = base64.urlsafe_b64encode(json.dumps(p).encode()).decode().rstrip("=")
    return f"{h}.{b}.sig"


# ---------- chat_via 推导 ----------
def test_chat_via_auto_derivation():
    assert _derive_chat_mode({"name": "a", "zcode_jwt": "j"}) == ("jwt", True)
    assert _derive_chat_mode({"name": "a", "api_key": "k", "zcode_jwt": "j"}) == ("apikey", True)
    assert _derive_chat_mode({"name": "a", "api_key": "k", "zcode_jwt": "j", "chat_via": "jwt"}) == ("jwt", True)
    assert _derive_chat_mode({"name": "a", "zcode_jwt": "j", "chat_via": "apikey"}) == ("apikey", False)


def test_jwt_exp_parse():
    assert jwt_exp(make_jwt(exp=123456)) == 123456
    assert jwt_exp("x.y.z") == 0
    assert jwt_exp("") == 0


def test_device_mid_derived_fallback():
    """JWT 账号缺 device_mid：恒定派生兜底（billing 缺它 3001）。"""
    from zai_pool.core import derive_device_ids
    j = make_jwt("542")
    a = Account({"name": "t", "zcode_jwt": j})
    assert a.device_mid == derive_device_ids(j)[0]
    assert Account({"name": "t", "zcode_jwt": j, "device_mid": "custom"}).device_mid == "custom"


def test_pick_filters_expired_jwt(zp):
    """exp 过期的 jwt 账号：pick 前 1h auth 冷却，不入调度。"""
    pool = zp.POOL
    pool.accounts = [Account({"name": "j1", "zcode_jwt": make_jwt(exp=1)})]
    assert pool.pick("", set()) is None
    a = pool.accounts[0]
    assert a.cool_reason == "auth" and a.cool_until > zp.time.time() + 3500
    # 未过期 → 正常入池
    a2 = Account({"name": "j2", "zcode_jwt": make_jwt(exp=2**31)})
    pool.accounts = [a2]
    assert pool.pick("", set()).name == "j2"


# ---------- 请求体归一化 ----------
def test_normalize_jwt_body_model_and_system():
    out = normalize_jwt_body({"model": "glm-5.3-flash", "messages": []})
    assert out["model"] == "GLM-5.3-Flash"
    assert out["system"], "缺 system 时必须注入官方提示词（3012 判定点）"
    prof = out["system"]
    out2 = normalize_jwt_body({"model": "GLM-5.2", "system": [{"type": "text", "text": "mine"}]})
    assert out2["system"] == [{"type": "text", "text": "mine"}], "已有 system 不覆盖"
    assert out2["model"] == "GLM-5.2", "大小写正确的模型名原样保留"
    out3 = normalize_jwt_body({"model": "glm-turbo", "messages": []}, inject_profile=False)
    assert "system" not in out3


# ---------- captcha 管理器 ----------
class _StubCaptcha:
    def __init__(self):
        self.invalidated = 0
        self.calls = 0

    def get_verify_param(self):
        self.calls += 1
        return f"vp-{self.calls}"

    def invalidate(self):
        self.invalidated += 1


def test_captcha_manager_ttl_and_invalidate(monkeypatch):
    solves = []

    def fake_solve(self, config):
        solves.append(config)
        return f"P{len(solves)}"

    monkeypatch.setattr(CaptchaManager, "_solve", fake_solve)
    monkeypatch.setattr(CaptchaManager, "fetch_config", lambda self: {"sceneId": "s", "region": "r", "prefix": "p"})
    cm = CaptchaManager(cache_ttl=45)
    assert cm.get_verify_param() == "P1"
    assert cm.get_verify_param() == "P1", "TTL 内命中缓存，不重复求解"
    assert len(solves) == 1
    cm.invalidate()
    assert cm.get_verify_param() == "P2", "失效后重新求解"


def test_captcha_failure_returns_none(monkeypatch):
    monkeypatch.setattr(CaptchaManager, "_solve", lambda self, config: None)
    monkeypatch.setattr(CaptchaManager, "fetch_config", lambda self: {})
    cm = CaptchaManager(retries=2)
    assert cm.get_verify_param() is None, "求解失败降级返回 None（不抛，调用方决定降级发送）"


# ---------- relay 接线（真 HTTP 驱动） ----------
class _R:
    def __init__(self, status, body):
        self.status = status
        self._b = body
        self.headers = {"content-type": "application/json"}

    def read(self, n=-1):
        out, self._b = self._b, b""
        return out

    def getheaders(self):
        return [("content-type", "application/json")]


def _jwt_pool(mod, max_retry=6):
    cfg = {"listen": "127.0.0.1:0", "api_key": "test-key-0123456789abcdef",
           "max_retry": max_retry,
           "accounts": [{"name": "j1", "zcode_jwt": make_jwt("u1", 2**31), "chat_via": "jwt"}]}
    mod.POOL = mod.Pool(cfg)
    mod.STATE_FILE = ""
    return mod.POOL.accounts[0]


def _serve(mod):
    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def _post(port, path, body, key="test-key-0123456789abcdef"):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        return urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as e:
        return e


def _wire_jwt(mod, script, calls):
    def fake(a, body, verify_param, timeout=90):
        status, b = script.pop(0)
        calls.append({"account": a.name, "body": json.loads(body), "vp": verify_param, "status": status})
        return status, {"content-type": "application/json"}, _R(status, b)
    mod.jwt_chat_request = fake


OK_BODY = json.dumps({"usage": {"prompt_tokens": 1, "completion_tokens": 2}}).encode()


def test_relay_jwt_channel_wired(zp):
    mod = zp
    a = _jwt_pool(mod)
    calls: list = []
    script = [(200, OK_BODY)]
    _wire_jwt(mod, script, calls)
    stub = _StubCaptcha()
    mod.CAPTCHA = stub
    srv, port = _serve(mod)
    try:
        r = _post(port, "/v1/messages", {"model": "glm-5.3-flash",
                                         "messages": [{"role": "user", "content": "hi"}]})
        assert r.status == 200
        assert calls and calls[0]["status"] == 200
        assert calls[0]["vp"] == "vp-1", "jwt 通道请求必须携带 verify_param"
        assert calls[0]["body"]["model"] == "GLM-5.3-Flash"
        assert calls[0]["body"]["system"], "relay 必须注入官方 system"
        assert a.stats["ok"] == 1
    finally:
        srv.shutdown()


def test_relay_captcha_403_retries_same_account(zp):
    """403+captcha：失效重取、同号重试、不冷却；恢复后 200。"""
    mod = zp
    a = _jwt_pool(mod)
    calls: list = []
    script = [(403, b'{"error":{"message":"Captcha verification failed (3012)"}}'),
              (200, OK_BODY)]
    _wire_jwt(mod, script, calls)
    stub = _StubCaptcha()
    mod.CAPTCHA = stub
    srv, port = _serve(mod)
    try:
        r = _post(port, "/v1/messages", {"model": "glm-5.2",
                                         "messages": [{"role": "user", "content": "hi"}]})
        assert r.status == 200, "captcha 重试后必须成功"
        assert stub.invalidated == 1
        assert len(calls) == 2 and calls[1]["vp"] == "vp-2", "重试必须带新 verify_param"
        assert a.cool_until == 0, "captcha 失效不得冷却账号"
        assert a.stats["ok"] == 1
    finally:
        srv.shutdown()


def test_relay_captcha_exhausted_then_auth_cooldown(zp):
    """持续 403 captcha：重试上限后走 auth 冷却，最终 503。"""
    mod = zp
    a = _jwt_pool(mod, max_retry=8)
    calls: list = []
    err = b'{"error":{"message":"Captcha verification failed"}}'
    script = [(403, err)] * 4 + [(200, OK_BODY)]
    _wire_jwt(mod, script, calls)
    mod.CAPTCHA = _StubCaptcha()
    srv, port = _serve(mod)
    try:
        r = _post(port, "/v1/messages", {"model": "glm-5.2",
                                         "messages": [{"role": "user", "content": "hi"}]})
        assert isinstance(r, urllib.error.HTTPError) and r.code == 503
        assert len(calls) == 4, f"初试+3 重试=4 次后放弃，实际 {len(calls)}"
        assert a.cool_reason == "auth" and a.cool_until > 0
    finally:
        srv.shutdown()


def test_relay_jwt_402_cooldown_exhausted(zp):
    mod = zp
    a = _jwt_pool(mod)
    calls: list = []
    script = [(402, b'{"error":{"message":"Insufficient balance"}}')]
    _wire_jwt(mod, script, calls)
    mod.CAPTCHA = _StubCaptcha()
    srv, port = _serve(mod)
    try:
        r = _post(port, "/v1/messages", {"model": "glm-5.2",
                                         "messages": [{"role": "user", "content": "hi"}]})
        assert isinstance(r, urllib.error.HTTPError) and r.code == 503
        assert a.cool_reason == "exhausted", "402 复用现有状态机：冷却至次日 reset"
    finally:
        srv.shutdown()


def test_relay_openai_never_picks_jwt_account(zp):
    """zcode-plan 端点仅 Anthropic：OpenAI 协议请求不得选 jwt 账号。"""
    mod = zp
    _jwt_pool(mod)
    calls: list = []
    _wire_jwt(mod, [(200, OK_BODY)], calls)
    mod.CAPTCHA = _StubCaptcha()
    srv, port = _serve(mod)
    try:
        r = _post(port, "/v1/chat/completions", {"model": "glm-5.2",
                                                 "messages": [{"role": "user", "content": "hi"}]})
        assert isinstance(r, urllib.error.HTTPError) and r.code == 503
        assert calls == [], "OpenAI 协议不得调用 jwt 通道"
    finally:
        srv.shutdown()


def test_models_local_list_for_jwt_only_pool(zp):
    mod = zp
    _jwt_pool(mod)
    called = []
    mod.upstream_request = lambda *args, **kw: called.append(args) or (0, {}, _R(0, b""))
    srv, port = _serve(mod)
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/models",
                                     headers={"Authorization": "Bearer test-key-0123456789abcdef"})
        r = urllib.request.urlopen(req, timeout=10)
        data = json.loads(r.read())["data"]
        ids = [m["id"] for m in data]
        assert "GLM-5.3-Flash" in ids and "GLM-5.2" in ids
        assert called == [], "jwt-only 池不得向上游代理 models"
    finally:
        srv.shutdown()


# ---------- billing usage ----------
def test_parse_usage_shape():
    assert parse_usage({"code": 0, "data": {"n": 1}}) == {"n": 1}
    with pytest.raises(BillingParseError):
        parse_usage({"code": 0})


def test_adapter_inspect_includes_usage():
    def transport(a, path, body=b"", extra=None, method="GET", host=None, timeout=None):
        if "/billing/balance" in path:
            payload = {"code": 0, "data": {"balances": [
                {"plan_id": "p1", "plan_name": "wk", "show_name": "Flash", "unit_type": "token",
                 "total_units": 10, "used_units": 1, "remaining_units": 9, "status": "active"}]}}
        elif "/billing/current" in path:
            payload = {"code": 0, "data": {"plans": []}}
        elif path.endswith("/usage"):
            payload = {"code": 0, "data": {"requests": 3}}
        else:
            payload = {"code": -1}
        return 200, {}, _R(200, json.dumps(payload).encode())

    out = BillingAdapter(transport=transport).inspect(Account({"name": "t", "zcode_jwt": "j"}))
    assert out["usage"] == {"requests": 3}
    assert out["balances"][0]["remaining_units"] == 9


# ---------- 迁移脚本 ----------
def test_import_script_loads_flat_schema(tmp_path):
    spec = importlib.util.spec_from_file_location("imp_z2a", ROOT / "scripts" / "import_zcode2api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    db = tmp_path / "accounts.db"
    conn = sqlite3.connect(db)
    conn.execute("create table accounts (id text, provider text, name text, mode text,"
                 " status text, enabled text, created_at text, data text)")
    blob = json.dumps({"id": "batch-1", "name": "batch", "mode": "jwt",
                       "jwt_token": "tok-abc", "api_key": "None"})
    conn.execute("insert into accounts values ('batch-1','zai','batch','jwt','active','True','0',?)", (blob,))
    conn.execute("insert into accounts values ('batch-2','zai','batch','apiKey','active','True','0','{}')")
    conn.commit()
    conn.close()
    accs = mod.load_accounts(db)
    assert len(accs) == 1, "apiKey 模式账号不迁移"
    assert accs[0] == {"name": "batch-1", "zcode_jwt": "tok-abc",
                       "chat_via": "jwt", "realm": "global"}
