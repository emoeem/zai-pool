"""共享 fixture：不触网的内存化 zai-pool / zacc 测试环境。"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def zp(monkeypatch):
    """zai-pool 模块 + 测试池（占位 key，不触网）。"""
    mod = load_module("zai_pool", ROOT / "zai-pool.py")
    cfg = {
        "api_key": "test-key-0123456789abcdef",
        "reset_hour": 9,
        "strategy": "sticky-first",
        "accounts": [
            {"name": "a1", "api_key": "P1", "realm": "global"},
            {"name": "a2", "api_key": "P2", "realm": "global"},
            {"name": "a3", "api_key": "P3", "realm": "cn"},
        ],
        "devices": [
            {"name": "devA", "key": "dkp-a", "accounts": ["a1", "a2"]},
            {"name": "devB", "key": "dkp-b", "accounts": ["a3"]},
            {"name": "devAll", "key": "dkp-all", "accounts": []},
        ],
    }
    pool = mod.Pool(cfg)
    mod.POOL = pool
    mod.CFG_PATH = "/tmp/nonexistent-pool.json"
    mod.STATE_FILE = ""
    return mod


class FakeResp:
    def __init__(self, status=200, body=b"{}", headers=None):
        self.status = status
        self._body = body if isinstance(body, bytes) else body.encode()
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}

    def read(self, n=-1):
        out = self._body
        self._body = b""
        return out

    def getheaders(self):
        return list(self.headers.items())


@pytest.fixture()
def fake_upstream(monkeypatch, zp):
    """替换 upstream_request，按脚本队列返回伪响应，并记录每账号的调用头。"""
    calls: list[dict] = []
    script: list[tuple[int, str, bytes]] = []  # (status, body, extra_headers)

    def fake_upstream_req(a, path, body=b"", extra=None, method="POST", host=None, timeout=600):
        status, b, hdrs = script.pop(0) if script else (200, json.dumps({"usage": {"prompt_tokens": 1, "completion_tokens": 2}}), {})
        calls.append({"account": a.name, "path": path, "status": status,
                      "headers": extra or {}, "method": method})
        return status, {k.lower(): v for k, v in hdrs.items()}, FakeResp(status, b, hdrs)

    monkeypatch.setattr(zp, "upstream_request", fake_upstream_req)
    return zp, calls, script
