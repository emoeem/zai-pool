"""Phase 5 billing 包测试：解析/状态机/账本/策略，全部 mock，零真实凭据。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from billing.adapter import BillingAdapter                      # noqa: E402
from billing.client import BillingClient                        # noqa: E402
from billing.parser import (BillingParseError, parse_balance,   # noqa: E402
                            parse_claim_response, parse_plans)
from billing.policy import exhausted, token_ratio               # noqa: E402
from billing.tracker import BillingLedger                       # noqa: E402


class FakeAccount:
    def __init__(self):
        self.name = "acct-x"
        self.zcode_jwt = "JWT-SHOULD-NEVER-APPEAR"
        self.device_mid = "MID"


class FakeResp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self, n=-1):
        out, self._b = self._b, b""
        return out

    def getheaders(self):
        return []


BAL_OK = {"code": 0, "data": {"balances": [
    {"plan_id": "p-daily", "plan_name": "Start", "show_name": "GLM-5.3",
     "unit_type": "token", "total_units": 3000000, "used_units": 0,
     "remaining_units": 3000000},
    {"plan_id": "p-week", "plan_name": "Weekend", "show_name": "GLM-5.3-Flash",
     "unit_type": "token", "total_units": 500000000, "used_units": 374223520,
     "remaining_units": 125776480}]}}

CUR_OK = {"code": 0, "data": {"plans": [
    {"plan_id": "p-daily", "name": "Start", "status": "active"},
    {"plan_id": "zcode-v3-start-plan-1122-wk", "name": "ZCODE WEEKEND BUILD", "status": "active"}]}}

PREVIEW_TODAY = {"code": 0, "data": {"plans": [
    {"plan_id": "zcode-v3-start-plan-1122-wk", "status": "pending"}]}}

CLAIM_OK = {"code": 0, "data": {"plan_id": "zcode-v3-start-plan-1122-wk"}}


def make_adapter(script: dict, ledger_path, auto_claim=True):
    """script: path 前缀 → 响应队列。"""
    calls: list[dict] = []
    queues = {k: list(v) for k, v in script.items()}

    def transport(account, path, body=b"", headers=None, method="GET", host=None, timeout=45):
        key = next((k for k in queues if k in path), "/other")
        payload = queues[key].pop(0) if queues.get(key) else {"code": -1, "msg": "no script"}
        calls.append({"path": path, "method": method,
                      "auth": (headers or {}).get("Authorization", ""),
                      "device_mid": (headers or {}).get("x-device-mid", "")})
        return 200, {}, FakeResp(payload)
    ad = BillingAdapter(transport=transport,
                        ledger=BillingLedger(ledger_path), auto_claim=auto_claim)
    return ad, calls


def test_parse_balance_flat_and_nested(tmp_path):
    flat = parse_balance("acct", BAL_OK)
    assert len(flat) == 2 and flat[1].remaining_units == 125776480
    nested = {"code": 0, "data": {"plans": [
        {"plan_id": "p1", "name": "N", "ends_at": 1795395600,
         "entitlements": [{"show_name": "GLM-5.3", "unit_type": "token",
                           "total_units": 10, "used_units": 4, "remaining_units": 6}]}]}}
    out = parse_balance("acct", nested)
    assert out[0].plan_id == "p1" and out[0].remaining_units == 6
    with pytest.raises(BillingParseError):
        parse_balance("acct", {"code": 0})


def test_policy_no_unit_mixing():
    from billing.models import Balance
    tok = [Balance("a", "p", "", "x", "token", 100, 0, 50)]
    call_units = [Balance("a", "p", "", "y", "call", 10, 0, 0)]  # 次数单位耗尽
    assert token_ratio(tok) == 0.5
    assert token_ratio(tok + call_units) == 0.5, "call 单位不得混入 token 比例"
    assert not exhausted(tok + call_units), "单条目（call）耗尽 ≠ 账号耗尽"
    assert exhausted(call_units)  # 只有 call 条目时按该条目判定


def test_claim_flow_success_verified(tmp_path):
    ad, calls = make_adapter({"/billing/preview": [PREVIEW_TODAY],
                              "/billing/claim": [CLAIM_OK],
                              "/billing/current": [CUR_OK]}, tmp_path / "ledger.jsonl")
    out = ad.claim_flow(FakeAccount())
    assert out.status == "success" and out.plan_id.endswith("wk")
    assert out.verified_at > 0, "领取后必须回查确认（HTTP 200 ≠ 成功）"
    ent = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[-1])
    assert ent["status"] == "success" and "JWT-SHOULD" not in (tmp_path / "ledger.jsonl").read_text()


def test_claim_flow_unknown_response_never_success(tmp_path):
    ad, _ = make_adapter({"/billing/preview": [PREVIEW_TODAY],
                          "/billing/claim": [{"weird": "structure"}]}, tmp_path / "ledger.jsonl")
    out = ad.claim_flow(FakeAccount())
    assert out.status == "failed", "未知响应结构绝不误判成功"


def test_claim_flow_no_plan_today_is_already(tmp_path):
    ad, _ = make_adapter({"/billing/preview": [{"code": 0, "data": {"plans": []}}]},
                         tmp_path / "ledger.jsonl")
    out = ad.claim_flow(FakeAccount())
    assert out.status == "already"


def test_claim_idempotent_same_day(tmp_path):
    """同日已成功领取：再次 claim_flow 直接 already（账本幂等）。"""
    lp = tmp_path / "ledger.jsonl"
    ad, _ = make_adapter({"/billing/preview": [PREVIEW_TODAY],
                          "/billing/claim": [CLAIM_OK],
                          "/billing/current": [CUR_OK]}, lp)
    assert ad.claim_flow(FakeAccount()).status == "success"
    ad2, calls = make_adapter({"/billing/preview": [PREVIEW_TODAY],
                               "/billing/claim": [CLAIM_OK],
                               "/billing/current": [CUR_OK]}, lp)
    ad2.ledger = BillingLedger(lp)  # 共享账本
    assert ad2.claim_flow(FakeAccount()).status == "already"
    claim_calls = [c for c in calls if c["path"].startswith("/billing/claim")]
    assert not claim_calls, "账本已记录当日成功 → 不得重复打上游 claim"


def test_auto_claim_gate(tmp_path):
    ad, _ = make_adapter({}, tmp_path / "ledger.jsonl", auto_claim=False)
    assert ad.claim_flow(FakeAccount()).status == "failed"
    assert "auto_claim" in ad.claim_flow(FakeAccount()).detail


def test_inspect_failure_isolated(tmp_path):
    ad, _ = make_adapter({"/billing/balance": [{"code": -1, "msg": "down"}]},
                         tmp_path / "ledger.jsonl")
    with pytest.raises(RuntimeError):
        ad.inspect(FakeAccount())  # 调用方（worker）捕获后不影响 API 转发


def test_client_sends_device_mid(tmp_path):
    ad, calls = make_adapter({"/billing/balance": [BAL_OK]}, tmp_path / "l.jsonl")
    ad.client._transport = ad.client._transport
    # 直接走 client 层验证头
    ad2, calls2 = make_adapter({"/billing/balance": [BAL_OK]}, tmp_path / "l2.jsonl")
    ad2.client.balance(FakeAccount())
    assert calls2[0]["device_mid"] == "MID", "缺 device-mid 上游返回 3001"
    assert calls2[0]["auth"] == "Bearer JWT-SHOULD-NEVER-APPEAR"
