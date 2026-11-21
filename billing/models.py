"""统一数据模型（计划书 5.2）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Balance:
    """单个权益条目（不同 unit_type 不混合）。"""
    account_name: str
    plan_id: str
    plan_name: str
    show_name: str
    unit_type: str = "token"
    total_units: int = 0
    used_units: int = 0
    remaining_units: int = 0
    expires_at: float | None = None
    status: str = "active"
    checked_at: float = 0.0
    extra: dict = field(default_factory=dict)  # 未知字段保留不丢弃


@dataclass
class ClaimOutcome:
    status: Literal["success", "already", "failed", "unverified"]
    account_name: str
    plan_id: str = ""
    detail: str = ""
    verified_at: float = 0.0

    @property
    def ok_for_ledger(self) -> bool:
        return self.status in ("success", "already")
