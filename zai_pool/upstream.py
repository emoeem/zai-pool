"""zai_pool.upstream — Phase6 第二域：上游连接（代理隧道/源端口分流/请求出口）。

POOL 通过 set_pool_getter 注入（避免 entry↔包循环导入）；UPSTREAMS 族归 core，本模块自 core 导入。
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
import urllib.parse
from pathlib import Path
from typing import Callable
import http.client
import socket
import ssl
import struct
from urllib.parse import urlparse

from zai_pool.core import (DEFAULT_SERVER, UP_HOST, UP_OPENAI_PATH, UPSTREAMS,
                           _jwt_payload, derive_device_ids, jwt_exp)  # noqa: 私有名跨域复用（单一所有权）

POOL_GETTER: Callable | None = None  # 由 entry 注入 lambda: POOL

def set_pool_getter(fn):
    global POOL_GETTER
    POOL_GETTER = fn


UA = "zai-pool/3.0"


_ssl_ctx = ssl.create_default_context()


def _recv_exact(s: socket.socket, n: int) -> bytes:
    """TCP 不保证单次 recv 返回全部字节；循环读满 n 字节。"""
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise OSError("proxy closed mid-handshake")
        buf += c
    return buf


def open_tunnel(proxy: str, host: str = UP_HOST, port: int = 443,
                timeout: int = 20, bind_port: int | None = None) -> socket.socket:
    u = urllib.parse.urlparse(proxy)
    scheme = u.scheme.lower()
    if scheme == "https":
        # 未实现到代理本身的 TLS 握手，宁可拒绝也不静默降级
        raise OSError("不支持 https:// 代理（未实现代理侧 TLS），请改用 http:// 或 socks5://")
    phost, pport = u.hostname, u.port or (8080 if scheme == "http" else 1080)
    s = socket.socket()
    if bind_port:
        s.bind(("0.0.0.0", bind_port))
    s.settimeout(timeout)
    s.connect((phost, pport))
    creds = f"{u.username}:{u.password or ''}" if u.username else ""
    if scheme == "http":
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if creds:
            req += f"Proxy-Authorization: Basic {base64.b64encode(creds.encode()).decode()}\r\n"
        s.sendall((req + "\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(4096)
            if not c:
                raise OSError("proxy closed during CONNECT")
            buf += c
        line = buf.split(b"\r\n", 1)[0].decode(errors="replace")
        if " 200" not in line:
            raise OSError(f"proxy CONNECT failed: {line}")
        return s
    if scheme in ("socks5", "socks5h"):
        methods = b"\x02" if creds else b"\x00"
        s.sendall(b"\x05\x01" + methods)
        r = _recv_exact(s, 2)
        if r[1] == 0xFF:
            raise OSError("socks5 no acceptable auth")
        if r[1] == 0x02:
            ub = (u.username or "").encode()
            pb = (u.password or "").encode()
            s.sendall(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
            r = _recv_exact(s, 2)
            if r[1] != 0x00:
                raise OSError("socks5 auth failed")
        if scheme == "socks5h":
            # 远程 DNS：域名按 ATYP=0x03 直接交给代理解析
            hb = host.encode()
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
        else:
            hb = socket.gethostbyname(host)
            s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(hb) + struct.pack(">H", port))
        head = _recv_exact(s, 4)
        if head[1] != 0x00:
            raise OSError(f"socks5 connect failed rep={head[1]}")
        atyp = head[3]
        if atyp == 0x01:
            _recv_exact(s, 4 + 2)  # IPv4 + port
        elif atyp == 0x03:
            ln = _recv_exact(s, 1)[0]
            _recv_exact(s, ln + 2)
        elif atyp == 0x04:
            _recv_exact(s, 16 + 2)
        return s
    raise OSError(f"unsupported proxy scheme: {scheme}（支持 http:// socks5:// socks5h://）")


def _bind_sport(rng: list[int] | tuple[int, int] | None) -> socket.socket | None:
    """直连路径绑定 sport_range 内随机源端口（honk sport 分流用）。"""
    if not rng:
        return None
    lo, hi = int(rng[0]), int(rng[1])
    for _ in range(8):
        s = socket.socket()
        try:
            s.bind(("0.0.0.0", random.randint(lo, hi)))
            s.settimeout(20)
            s.connect((UP_HOST, 443))
            return s
        except OSError:
            try:
                s.close()
            except OSError:
                pass
    raise OSError(f"sport_range {lo}-{hi} 全部绑定失败")


class UpstreamConn(http.client.HTTPSConnection):
    """直连或经隧道的 HTTPS 连接；sock 由调用方预建。"""

    def __init__(self, sock: socket.socket | None, timeout: int = 600):
        super().__init__(UP_HOST, timeout=timeout)
        self._preset = sock

    def connect(self):
        if self._preset is not None:
            self.sock = _ssl_ctx.wrap_socket(self._preset, server_hostname=UP_HOST)
        else:
            super().connect()


def upstream_request(a: "Account", path: str, body: bytes = b"", extra: dict | None = None,
                     method: str = "POST", host: str | None = None, timeout: int = 600):
    """proxy / sport 分流感知请求（sport 分流仅对 api.z.ai 生效）；
    host 缺省时按账号 realm 选上游（global=api.z.ai / cn=open.bigmodel.cn）。
    返回 (status, headers-dict, response)。"""
    hdrs = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": UA}
    if extra:
        hdrs.update(extra)
    host = host or UPSTREAMS.get(a.realm, UPSTREAMS["global"])["host"]
    pool = POOL_GETTER() if POOL_GETTER else None
    connect_timeout = float((pool.server_cfg if pool else DEFAULT_SERVER).get("connect_timeout", 20))
    if a.proxy:
        conn = UpstreamConn(open_tunnel(a.proxy, host=host, timeout=int(connect_timeout)), timeout=timeout)
    elif a.sport_range and host == UP_HOST:
        conn = UpstreamConn(_bind_sport(a.sport_range), timeout=timeout)
    else:
        conn = http.client.HTTPSConnection(host, timeout=timeout)
    try:
        conn.request(method, path, body=body if method == "POST" else None, headers=hdrs)
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp
    except Exception:
        conn.close()
        raise



# ---------- JWT 对话通道（免费套餐；Phase4 审查结论修订：3012 三要素已破解） ----------
_PROFILE_PATH = Path(__file__).resolve().parents[1] / "zcode-profile.json"
_profile_cache: dict | None = None


def zcode_profile_system() -> list | None:
    """ZCode 官方 system 提示词（3012 判定点之一）；缓存加载。"""
    global _profile_cache
    if _profile_cache is None:
        try:
            _profile_cache = json.loads(_PROFILE_PATH.read_text()).get("system")
        except Exception:
            _profile_cache = None
    return _profile_cache


# ---------- JWT 通道请求体归一化（借鉴 zcode2api _normalize_body；补 GLM-5.3-Flash） ----------
MODEL_NAME_MAP = {
    "glm-5.3-flash": "GLM-5.3-Flash",
    "glm-5.2": "GLM-5.2",
    "glm-5-turbo": "GLM-5-Turbo",
    "glm-turbo": "GLM-5-Turbo",
    "glm-5.1": "GLM-5.1",
    "glm-4.7": "GLM-4.7",
}


def normalize_jwt_body(req: dict, inject_profile: bool = True) -> dict:
    """JWT 通道请求体预处理：模型名大小写映射（上游大小写敏感）+
    客户端未带 system 时注入官方 system 提示词（3012 判定点之一）。"""
    out = dict(req)
    m = str(out.get("model") or "").strip()
    if m:
        out["model"] = MODEL_NAME_MAP.get(m.lower(), m)
    if inject_profile and not out.get("system"):
        prof = zcode_profile_system()
        if prof:
            out["system"] = prof
    return out


# ---------- OAuth CLI 登录（移植 zcode2api ZaiAuthFlow，stdlib 版） ----------
def oauth_cli_init(provider: str = "zai") -> tuple[str, str, str]:
    """发起 OAuth CLI 流程。返回 (flow_id, authorize_url, poll_token)。"""
    import secrets
    poll_token = secrets.token_hex(32)
    body = json.dumps({"provider": provider}).encode()
    req = http.client.HTTPSConnection("zcode.z.ai", timeout=30)
    try:
        req.request("POST", "/api/v1/oauth/cli/init", body=body, headers={
            "Authorization": f"Bearer {poll_token}",
            "Content-Type": "application/json", "Accept": "application/json"})
        resp = req.getresponse()
        data = json.loads(resp.read()).get("data") or {}
    finally:
        req.close()
    flow_id, authorize_url = data.get("flow_id"), data.get("authorize_url")
    if not flow_id or not authorize_url:
        raise RuntimeError(f"OAuth init 返回不完整: {str(data)[:120]}")
    return flow_id, authorize_url, poll_token


def oauth_cli_poll(flow_id: str, poll_token: str) -> dict:
    """轮询 OAuth 流程。data.status=ready 时含 token（zcode JWT）与 zai.access_token。"""
    req = http.client.HTTPSConnection("zcode.z.ai", timeout=30)
    try:
        req.request("GET", f"/api/v1/oauth/cli/poll/{flow_id}", headers={
            "Authorization": f"Bearer {poll_token}", "Accept": "application/json"})
        resp = req.getresponse()
        return json.loads(resp.read()).get("data") or {}
    finally:
        req.close()


def oauth_exchange_api_key(access_token: str) -> str:
    """OAuth access_token → 业务 token → 默认机构/项目 → 复制/创建 zcode-api-key。
    返回 "apiKey.secretKey"；免费套餐可能无权创建，失败抛异常由调用方隔离。"""
    conn = http.client.HTTPSConnection("api.z.ai", timeout=30)
    try:
        conn.request("POST", "/api/auth/z/login", body=json.dumps({"token": access_token}).encode(),
                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        biz = (json.loads(conn.getresponse().read()).get("data") or {})
        biz_token = biz.get("access_token") or biz.get("accessToken")
        if not biz_token:
            raise RuntimeError("z/login 返回数据中不含业务凭证")
        conn.request("GET", "/api/biz/customer/getCustomerInfo",
                     headers={"Authorization": f"Bearer {biz_token}", "Accept": "application/json"})
        orgs = (json.loads(conn.getresponse().read()).get("data") or {}).get("organizations") or []
        org = next((o for o in orgs if "默认机构" in (o.get("organizationName") or "")), None) \
            or (orgs[0] if orgs else None)
        if not org:
            raise RuntimeError("找不到可用的机构")
        projects = org.get("projects") or []
        proj = next((p for p in projects if "默认项目" in (p.get("projectName") or "")), None) \
            or (projects[0] if projects else None)
        if not proj:
            raise RuntimeError("找不到可用的项目")
        key_path = (f"/api/biz/v1/organization/{org['organizationId']}"
                    f"/projects/{proj['projectId']}/api_keys")
        conn.request("GET", key_path,
                     headers={"Authorization": f"Bearer {biz_token}", "Accept": "application/json"})
        keys = json.loads(conn.getresponse().read()).get("data") or []
        key_obj = next((k for k in keys if k.get("name") == "zcode-api-key"), None)
        if not key_obj:
            conn.request("POST", key_path, body=json.dumps({"name": "zcode-api-key"}).encode(),
                         headers={"Authorization": f"Bearer {biz_token}",
                                  "Content-Type": "application/json", "Accept": "application/json"})
            key_obj = json.loads(conn.getresponse().read()).get("data")
        api_key = (key_obj or {}).get("apiKey")
        if not api_key:
            raise RuntimeError("获取 API Key 失败")
        conn.request("GET", f"{key_path}/copy/{api_key}",
                     headers={"Authorization": f"Bearer {biz_token}", "Accept": "application/json"})
        secret_key = (json.loads(conn.getresponse().read()).get("data") or {}).get("secretKey")
        if not secret_key:
            raise RuntimeError("未能解密 Secret Key")
    finally:
        conn.close()
    return f"{api_key}.{secret_key}"


def jwt_chat_request(a, body: bytes, verify_param: str | None, timeout: float = 90):
    """JWT 对话：zcode-plan anthropic 端点 + 全客户端头族 + metadata.user_id。
    返回 (status, headers, response)。verify_param 为空时不带验证码头（会 3012）。"""
    import uuid as _uuid
    device_id, session_id = derive_device_ids(a.zcode_jwt)
    app_version = "3.16.3"
    headers = {
        "authorization": f"Bearer {a.zcode_jwt}",
        "x-api-key": a.zcode_jwt,
        "content-type": "application/json",
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "mid-conversation-system-2026-04-07",
        "user-agent": f"ZCode/{app_version} ai-sdk/provider-utils/4.0.27 runtime/node.js/24",
        "http-referer": "https://zcode.z.ai",
        "x-zcode-app-version": app_version,
        "x-title": "Z Code@electron",
        "x-release-channel": "production",
        "x-platform": "linux-x64",
        "x-os-category": "linux",
        "x-os-version": "5.15.0",
        "x-client-timezone": "Asia/Shanghai",
        "x-client-language": "zh-CN",
        "x-device-mid": device_id,
        "x-session-id": session_id,
        "x-query-id": str(_uuid.uuid4()),
        "x-request-id": _uuid.uuid4().hex,
        "x-zcode-trace-id": str(_uuid.uuid4()),
        "x-zcode-agent": "glm",
        "x-zcode-query-source": "main_turn",
        "x-zcode-session-type": "main",
        "accept": "text/event-stream, application/json",
    }
    if verify_param:
        headers["x-aliyun-captcha-verify-param"] = verify_param
    host = "zcode.z.ai"
    if a.proxy:
        conn = UpstreamConn(open_tunnel(a.proxy, host=host), timeout=timeout)
    else:
        conn = http.client.HTTPSConnection(host, timeout=timeout)
    try:
        conn.request("POST", UP_OPENAI_PATH.replace("/api/coding", "") and "/api/v1/zcode-plan/anthropic/v1/messages",
                     body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp
    except Exception:
        conn.close()
        raise
