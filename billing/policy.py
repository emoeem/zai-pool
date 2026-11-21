"""额度→调度权重策略（计划书 5.2）：不同 unit_type 不混合；分条目处理。"""
from __future__ import annotations

from billing.models import Balance


def token_ratio(balances: list[Balance]) -> float | None:
    """仅聚合 unit_type == token 的条目；无 token 条目返回 None（网关取中性 0.5）。"""
    tok = [b for b in balances if b.unit_type == "token"]
    if not tok:
        return None
    total = sum(b.total_units for b in tok)
    remaining = sum(b.remaining_units for b in tok)
    if total <= 0:
        return 0.0
    return max(0.0, min(1.0, remaining / total))


def exhausted(balances: list[Balance]) -> bool:
    """整个账号耗尽 = 存在条目且每条 remaining<=0；单条目耗尽不代表账号耗尽。"""
    if not balances:
        return False
    return all(b.remaining_units <= 0 for b in balances)
