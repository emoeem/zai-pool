"""上游响应解析（计划书 5.2：缺失字段容错、类型校验、未知字段保留）。

任何结构不符 → BillingParseError，由调用方记 failed，绝不猜成 already/success。
"""
from __future__ import annotations

import time
from typing import Any

from billing.models import Balance


class BillingParseError(ValueError):
    pass


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        raise BillingParseError(f"非整数数量字段: {v!r}")


def parse_balance(account: str, payload: dict, now: float | None = None) -> list[Balance]:
    """billing/balance 响应 → [Balance]。data.plans[].entitlements[] 嵌套与
    data.balances[] 平铺两种形态都接受；其余结构抛 BillingParseError。"""
    now = now if now is not None else time.time()
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        raise BillingParseError("balance 响应缺 data 段")
    data = payload["data"]
    entries: list[dict] = []
    if isinstance(data.get("balances"), list):
        entries = [x for x in data["balances"] if isinstance(x, dict)]
    elif isinstance(data.get("plans"), list):
        for p in data["plans"]:
            if not isinstance(p, dict):
                continue
            for e in p.get("entitlements") or []:
                if isinstance(e, dict):
                    entries.append({**e,
                                    "plan_id": e.get("plan_id") or p.get("plan_id"),
                                    "plan_name": e.get("plan_name") or p.get("name"),
                                    "ends_at": e.get("ends_at") or p.get("ends_at")})
    else:
        raise BillingParseError("balance 响应无 balances/plans 段")
    out: list[Balance] = []
    for e in entries:
        known = {"bucket_id", "user_plan_id", "priority", "plan_priority",
                 "entitlement_priority", "meter", "capabilities"}
        out.append(Balance(
            account_name=account,
            plan_id=str(e.get("plan_id") or ""),
            plan_name=str(e.get("plan_name") or ""),
            show_name=str(e.get("show_name") or ""),
            unit_type=str(e.get("unit_type") or "token"),
            total_units=_as_int(e.get("total_units")),
            used_units=_as_int(e.get("used_units")),
            remaining_units=_as_int(e.get("remaining_units")),
            expires_at=float(e["expires_at"]) if e.get("expires_at") else None,
            status=str(e.get("status") or "active"),
            checked_at=now,
            extra={k: e[k] for k in known if k in e},
        ))
    return out


def parse_plans(payload: dict) -> list[dict]:
    """billing/current 或 preview 的 plans 段；结构不符抛错。"""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        raise BillingParseError("plans 响应缺 data 段")
    plans = payload["data"].get("plans")
    if not isinstance(plans, list):
        raise BillingParseError("plans 段不是数组")
    return [p for p in plans if isinstance(p, dict)]


def parse_claim_response(payload: Any) -> dict:
    """claim 响应必须可识别业务码（code==0 或明确的 already 语义），否则抛错。"""
    if not isinstance(payload, dict):
        raise BillingParseError("claim 响应不是对象")
    code = payload.get("code")
    if code == 0:
        return {"result": "accepted", "plan_id": str((payload.get("data") or {}).get("plan_id") or "")}
    msg = str(payload.get("msg") or "")
    if "already" in msg.lower() or "已领取" in msg or code in (3010,):
        return {"result": "already", "detail": msg[:120]}
    raise BillingParseError(f"claim 响应不可识别: code={code} msg={msg[:80]}")
