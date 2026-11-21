"""代理协议与网关 HTTP 端点。"""
from __future__ import annotations

import socket
import struct
import threading
import json
import urllib.request

import pytest


def test_recv_exact_handles_short_reads():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "zp", Path(__file__).resolve().parent.parent / "zai-pool.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class ShortSocket:
        """每次最多吐 3 字节，模拟 TCP 分段。"""
        def __init__(self, data):
            self.data = data

        def recv(self, n):
            chunk = self.data[:min(3, max(1, n))]
            self.data = self.data[len(chunk):]
            return chunk

    s = ShortSocket(b"abcdefg")
    assert mod._recv_exact(s, 7) == b"abcdefg"
    assert mod._recv_exact(ShortSocket(b"ab"), 2) == b"ab"


def test_https_proxy_scheme_rejected():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "zp", Path(__file__).resolve().parent.parent / "zai-pool.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    with pytest.raises(OSError, match="https"):
        mod.open_tunnel("https://user:pass@proxy.example.com:8443")


def test_socks5h_sends_domain_for_remote_dns():
    """socks5h：域名按 ATYP=0x03 交给代理解析（不本地 gethostbyname）。"""
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "zp", Path(__file__).resolve().parent.parent / "zai-pool.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    got: list[bytes] = []

    def serve():
        conn, _ = server.accept()
        try:
            got.append(conn.recv(64))            # 握手
            conn.sendall(b"\x05\x00")
            got.append(conn.recv(64))            # 连接请求
            # 回 IPv4 响应
            conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("1.2.3.4") + struct.pack(">H", 443))
            conn.recv(64)                        # 等 TLS ClientHello 后再关
        finally:
            conn.close()
            server.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    tun = mod.open_tunnel(f"socks5h://127.0.0.1:{port}", host="api.z.ai", port=443, timeout=5)
    t.join(timeout=5)
    req = got[1]
    assert req[3] == 0x03, "socks5h 必须用 ATYP=域名（远程 DNS）"
    assert b"api.z.ai" in req


def test_gateway_metrics_and_404(tmp_path):
    """回归 /metrics 死代码修复 + 未识别 GET 有 404 兜底。"""
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("zp2", root / "zai-pool.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    cfg = {"listen": "127.0.0.1:0", "api_key": "test-key-0123456789abcdef",
           "accounts": [{"name": "a1", "api_key": "P1"}]}
    mod.POOL = mod.Pool(cfg)
    mod.STATE_FILE = ""
    mod.load_panel()
    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/metrics",
            headers={"Authorization": "Bearer test-key-0123456789abcdef"})
        r = urllib.request.urlopen(req)
        body = r.read().decode()
        assert r.status == 200 and "zaipool_" in body
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/no-such-path")
            raised = False
        except urllib.error.HTTPError as e:
            raised = e.code == 404
        assert raised, "未识别 GET 必须有 404 兜底（旧版直接断连）"
    finally:
        srv.shutdown()


def test_body_size_limit(tmp_path):
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("zp3", root / "zai-pool.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.MAX_BODY_BYTES == 32 * 1024 * 1024
