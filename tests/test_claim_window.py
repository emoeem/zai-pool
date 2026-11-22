"""领取窗口：claim_days/claim_hour/claim_minute 门控（用户口径：周一~五 19:10 后）。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from conftest import load_module
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CST = timezone(timedelta(hours=8))


def fresh_worker(tmp_path):
    mod = load_module("zp_claim", ROOT / "zai-pool.py")
    cfg = {"api_key": "k" * 20,
           "billing": {"enabled": True, "auto_claim": True,
                       "claim_days": "1-5", "claim_hour": 19, "claim_minute": 10},
           "accounts": [{"name": "a1", "api_key": "", "zcode_jwt": "JWT"}],
           "devices": []}
    mod.POOL = mod.Pool(cfg)
    mod.STATE_FILE = ""
    return mod


def test_parse_claim_days():
    mod = fresh_worker.__wrapped__ if hasattr(fresh_worker, "__wrapped__") else None
    import importlib.util
    spec = importlib.util.spec_from_file_location("zp_cd", ROOT / "zai-pool.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.parse_claim_days("1-5") == {1, 2, 3, 4, 5}
    assert mod.parse_claim_days("1,3,5") == {1, 3, 5}
    assert mod.parse_claim_days("6-7") == {6, 7}
    assert mod.parse_claim_days("*") == set(range(1, 8))
    assert mod.parse_claim_days("") == set(range(1, 8)), "空 = 全周兜底"
    assert mod.parse_claim_days("9-12") == set(range(1, 8)), "非法值兜底全周"


def _dt(y, mo, d, h, mi):
    return datetime(y, mo, d, h, mi, tzinfo=CST)


def test_claim_window_weekday_after_1910(zp, tmp_path, monkeypatch):
    mod = zp
    mod.CFG_PATH = str(tmp_path / "pool.json")
    (tmp_path / "pool.json").write_text("{}")
    from billing.tracker import BillingLedger
    mod._billing_adapter = None
    # 注入 adapter（preview→当日 plan, claim→接受, current→active）
    import billing.tracker as bt
    mod.BillingLedger = lambda p: bt.BillingLedger(tmp_path / "ledger.jsonl")
    fired = []

    def fake_transport(account, path, body=b"", headers=None, method="GET", host=None, timeout=45):
        if path.startswith("/billing/preview"):
            return 200, {}, _FakeResp({"code": 0, "data": {"plans": [
                {"plan_id": f"zcode-v3-start-plan-1121-wk", "status": "pending"}]}})
        if path.startswith("/billing/claim"):
            fired.append(account.name)
            return 200, {}, _FakeResp({"code": 0, "data": {"plan_id": "zcode-v3-start-plan-1121-wk"}})
        if path.startswith("/billing/current"):
            return 200, {}, _FakeResp({"code": 0, "data": {"plans": [
                {"plan_id": "zcode-v3-start-plan-1121-wk", "status": "active"}]}})
        return 200, {}, _FakeResp({"code": 0, "data": {"balances": []}})

    class _FakeResp:
        def __init__(self, payload):
            self._b = json.dumps(payload).encode()
        def read(self, n=-1):
            out, self._b = self._b, b""
            return out
        def getheaders(self):
            return []

    ad = mod.BillingAdapter(transport=fake_transport,
                            ledger=bt.BillingLedger(tmp_path / "ledger.jsonl"),
                            claim_hour=19, claim_minute=10, auto_claim=True)
    mod.set_billing_adapter(ad)

    # 周一 19:09 → 未到窗口，不领
    monday_1909 = _dt(2026, 11, 23, 19, 9)
    assert mod._claim_window_due(monday_1909, claim_days={1, 2, 3, 4, 5},
                                 claim_hour=19, claim_minute=10) is False
    # 周一 19:10 → 到窗口
    assert mod._claim_window_due(_dt(2026, 11, 23, 19, 10), {1, 2, 3, 4, 5}, 19, 10) is True
    # 周六 19:10 → 不在 claim_days
    assert mod._claim_window_due(_dt(2026, 11, 28, 19, 10), {1, 2, 3, 4, 5}, 19, 10) is False
    # 周日 → 不领
    assert mod._claim_window_due(_dt(2026, 11, 29, 20, 0), {1, 2, 3, 4, 5}, 19, 10) is False


import json  # noqa: E402
