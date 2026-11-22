"""billing HTTP 客户端（计划书 5.1）：统一超时/异常/鉴权；JWT 永不进日志。

transport 由网关注入（复用其代理/源端口出口），签名与 zai-pool.upstream_request 一致：
    transport(account, path_with_query, body_bytes, headers, method, host, timeout)
    -> (status, headers_dict, response)
"""
from __future__ import annotations

import json
from typing import Callable

BILLING_HOST = "zcode.z.ai"
BILLING_BASE = "/api/v1/zcode-plan"
BILLING_APP_VERSION = "3.16.3"


class BillingClient:
    def __init__(self, transport: Callable | None = None, timeout: float = 45):
        self._transport = transport
        self.timeout = timeout

    def _headers(self, account, device_mid: str | None = None) -> dict:
        h = {"Authorization": f"Bearer {account.zcode_jwt}",
             "User-Agent": "zai-pool-billing/1.0"}
        mid = device_mid or account.device_mid
        if mid:
            h["x-device-mid"] = mid  # billing 域缺 device-mid 返回 3001
        return h

    def _call(self, account, path: str, body: dict | None = None) -> dict | str:
        if self._transport is None:
            raise RuntimeError("BillingClient 未注入 transport")
        q = f"?app_version={BILLING_APP_VERSION}" if path.startswith("/billing/balance") else ""
        b = json.dumps(body).encode() if body is not None else None
        method = "POST" if body is not None else "GET"
        status, _, resp = self._transport(
            account, BILLING_BASE + path + q, b or b"", self._headers(account),
            method, BILLING_HOST, self.timeout)
        raw = resp.read().decode(errors="replace")
        try:
            out = json.loads(raw)
        except Exception:
            return {"code": -1, "msg": f"非 JSON 响应: {raw[:120]}"}
        if not isinstance(out, dict):
            return {"code": -1, "msg": f"响应非对象: {str(out)[:120]}"}
        return out

    def balance(self, account) -> dict | str:
        return self._call(account, "/billing/balance")

    def current(self, account) -> dict | str:
        return self._call(account, "/billing/current")

    def usage(self, account) -> dict | str:
        """实时用量（借鉴 zcode2api fetch_quota 第三路；balance/current/usage 并行三端点之一）。"""
        return self._call(account, "/usage")

    def preview(self, account) -> dict | str:
        return self._call(account, "/billing/preview")

    def claim(self, account, plan_id: str) -> dict | str:
        return self._call(account, "/billing/claim", {"plan_id": plan_id})
