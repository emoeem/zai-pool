"""zai_pool.upstream — Phase6 第二域：上游连接（代理隧道/源端口分流/请求出口）。

POOL 通过 set_pool_getter 注入（避免 entry↔包循环导入）；UPSTREAMS 族归 core，本模块自 core 导入。
"""
from __future__ import annotations

import base64
import urllib.parse
from typing import Callable
import http.client
import socket
import ssl
import struct
from urllib.parse import urlparse

from zai_pool.core import DEFAULT_SERVER, UP_HOST, UP_OPENAI_PATH, UPSTREAMS

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

