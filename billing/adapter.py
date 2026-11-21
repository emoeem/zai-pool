"""BillingAdapter：巡检 + 领取状态机（pending→previewed→claiming→
success/already/failed→verified），auto_claim 由网关配置门控。"""
from __future__ import annotations

import time

from billing.client import BillingClient
from billing.models import ClaimOutcome
from billing.parser import (BillingParseError, parse_balance, parse_claim_response,
                            parse_plans)
from billing.tracker import BillingLedger


class BillingAdapter:
    def __init__(self, transport=None, ledger: BillingLedger | None = None,
                 claim_hour: int = 9, auto_claim: bool = False):
        self.client = BillingClient(transport)
        self.ledger = ledger or BillingLedger("/tmp/billing-ledger.jsonl")
        self.claim_hour = claim_hour
        self.auto_claim = auto_claim

    # ---------- 巡检（只读） ----------
    def inspect(self, account) -> dict:
        """拉 balance+current → {balances, plans}；失败抛异常由调用方隔离。"""
        bal = self.client.balance(account)
        if not isinstance(bal, dict) or bal.get("code") != 0:
            raise RuntimeError(f"balance 业务失败: {str(bal)[:100]}")
        balances = parse_balance(account.name, bal)
        out = {"balances": [
            {"plan_id": b.plan_id, "plan_name": b.plan_name, "show_name": b.show_name,
             "unit_type": b.unit_type, "total_units": b.total_units,
             "used_units": b.used_units, "remaining_units": b.remaining_units,
             "expires_at": b.expires_at, "status": b.status} for b in balances]}
        cur = self.client.current(account)
        if isinstance(cur, dict) and cur.get("code") == 0:
            try:
                out["plans"] = [{"plan_id": p.get("plan_id"), "name": p.get("name"),
                                 "ends_at": p.get("ends_at"), "status": p.get("status")}
                                for p in parse_plans(cur)]
            except BillingParseError:
                out["plans"] = []
        return out

    # ---------- 领取状态机 ----------
    def claim_flow(self, account, trigger: str = "schedule") -> ClaimOutcome:
        name = account.name
        if not self.auto_claim:
            return ClaimOutcome("failed", name, detail="auto_claim 未启用")
        if self.ledger.claimed_today(name):  # 幂等：当日已成功领取，重启/重跑不重复打上游
            return ClaimOutcome("already", name, detail="账本记录当日已领取")
        st = self.client.preview(account)
        # pending → previewed
        try:
            plans = parse_plans(st)
        except BillingParseError as e:
            return self._fail(name, "", f"preview 结构不可识别: {e}", trigger, st)
        today_md = time.strftime("%m%d")
        target = None
        for p in plans:
            pid = str(p.get("plan_id") or "")
            if "start-plan" in pid and today_md in pid:
                target = pid
                break
        if not target:
            # 当日 promo 不存在 → 视为 already（幂等：无物可领）
            self.ledger.append(name, "", "already", "preview 无当日 plan", trigger)
            return ClaimOutcome("already", name, detail="preview 无当日 plan")
        # claiming
        resp = self.client.claim(account, target)
        api_status = 200 if isinstance(resp, dict) else 0
        try:
            verdict = parse_claim_response(resp)
        except BillingParseError as e:
            return self._fail(name, target, f"claim 响应不可识别: {e}", trigger, resp, api_status)
        if verdict["result"] == "already":
            self.ledger.append(name, target, "already", verdict.get("detail", ""), trigger, api_status)
            return ClaimOutcome("already", name, target, verdict.get("detail", ""))
        # verified：回查确认计划生效（HTTP 200 ≠ 成功）
        self.ledger.append(name, target, "success", "claim 接受，待回查", trigger, api_status)
        outcome = ClaimOutcome("unverified", name, target, "claim 已受理")
        try:
            cur = self.client.current(account)
            for p in parse_plans(cur):
                if str(p.get("plan_id")) == target and p.get("status") == "active":
                    outcome = ClaimOutcome("success", name, target, "回查确认 active",
                                           verified_at=time.time())
                    break
        except Exception as e:
            outcome = ClaimOutcome("unverified", name, target, f"回查失败: {type(e).__name__}")
        self.ledger.append(name, target, outcome.status, outcome.detail, trigger,
                           api_status, outcome.verified_at)
        return outcome

    def _fail(self, name, plan_id, detail, trigger, raw=None, api_status=None) -> ClaimOutcome:
        self.ledger.append(name, plan_id, "failed", detail, trigger, api_status)
        return ClaimOutcome("failed", name, plan_id, detail)
