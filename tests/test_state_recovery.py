"""Phase 3-3.2 状态恢复测试：损坏/空/缺失状态文件的行为契约。"""
from __future__ import annotations

import json

from conftest import load_module
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def fresh(tmp_path):
    mod = load_module("zp_state", ROOT / "zai-pool.py")
    cfg = {"api_key": "k" * 20,
           "accounts": [{"name": "a1", "api_key": "P1"}, {"name": "a2", "api_key": "P2"}],
           "devices": [{"name": "d1", "key": "dkp-1-123456", "accounts": ["a1"]}]}
    mod.POOL = mod.Pool(cfg)
    mod.STATE_FILE = str(tmp_path / "pool-state.json")
    mod.CFG_PATH = str(tmp_path / "pool.json")
    return mod


def test_missing_state_boots_clean(tmp_path):
    mod = fresh(tmp_path)
    mod.load_state()
    assert all(a.cool_until == 0 for a in mod.POOL.accounts)


def test_corrupt_state_preserved_not_overwritten(tmp_path):
    """审查 3.2：损坏状态必须保留原文件 + 诊断，绝不能被新状态静默覆盖。"""
    mod = fresh(tmp_path)
    sf = Path(mod.STATE_FILE)
    sf.write_text('{"accounts": [ broken json')
    mod.load_state()
    bak = list(sf.parent.glob("pool-state.json.corrupt-*"))
    assert bak, "损坏文件必须改名保留"
    assert b"broken json" in bak[0].read_bytes(), "保留的必须是原始字节"
    assert not sf.exists() or sf.read_text() != '{"accounts": [ broken json'
    # 后续 save_state 不会把损坏文件内容冲掉（备份仍在）
    mod.save_state()
    assert len(list(sf.parent.glob("pool-state.json.corrupt-*"))) == 1


def test_unreadable_state_dir_goes_readonly(tmp_path):
    """备份失败（目录不可写）→ 写盘跳过，绝不覆盖原文件。"""
    import os
    import stat
    mod = fresh(tmp_path)
    sf = Path(mod.STATE_FILE)
    sf.write_text("not-json-at-all{{{")
    sf.parent.chmod(0o500)  # 只读目录：os.replace 失败
    try:
        mod.load_state()
        assert mod._STATE_READONLY is True
        mod.save_state()  # 必须被跳过
        assert sf.read_text() == "not-json-at-all{{{", "原文件一个字节都不能动"
    finally:
        sf.parent.chmod(0o700)


def test_empty_state_renamed(tmp_path):
    mod = fresh(tmp_path)
    sf = Path(mod.STATE_FILE)
    sf.write_text("   ")
    mod.load_state()
    assert (sf.parent / "pool-state.json.empty").exists()


def test_unknown_structure_rejected_as_corrupt(tmp_path):
    mod = fresh(tmp_path)
    sf = Path(mod.STATE_FILE)
    sf.write_text(json.dumps({"hello": "world"}))  # 缺 accounts 段
    mod.load_state()
    assert list(sf.parent.glob("pool-state.json.corrupt-*"))


def test_stale_account_state_ignored_and_not_resurrected(tmp_path):
    """配置删除账号后：旧状态条目不迁移、不停用状态复活。"""
    mod = fresh(tmp_path)
    mod.STATE_FILE = str(tmp_path / "pool-state.json")
    (tmp_path / "pool-state.json").write_text(json.dumps({
        "accounts": [
            {"name": "a1", "usage": {"d": {"in": 5, "out": 6, "req": 1}},
             "manual_disabled": True, "disabled": False, "cool_until": 0,
             "breaker_until": 0, "retry_count": 0, "disabled_reason": "", "billing": {}},
            {"name": "removed-old", "usage": {"d": {"in": 9, "out": 9, "req": 1}},
             "disabled": True, "cool_until": 0, "breaker_until": 0, "retry_count": 0,
             "manual_disabled": False, "disabled_reason": "x", "billing": {}}],
        "devices": []}))
    mod.load_state()
    a1 = next(a for a in mod.POOL.accounts if a.name == "a1")
    assert a1.manual_disabled is True, "停用状态跨重启保留"
    assert a1.usage.get("d", {}).get("in") == 5, "历史日期用量条目完整恢复"
    assert a1.today().get("in", 0) == 0, "新的一天从零记账"
    assert all(a.name != "removed-old" for a in mod.POOL.accounts), "旧账号不复活"


def test_state_expired_cooldown_not_restored(tmp_path):
    """过期冷却/熔断不复活（陈旧状态不写入）。"""
    import time
    mod = fresh(tmp_path)
    (tmp_path / "pool-state.json").write_text(json.dumps({
        "accounts": [{"name": "a1", "usage": {},
                      "cool_until": time.time() - 100, "cool_reason": "rate_limited",
                      "breaker_until": time.time() - 100, "retry_count": 3,
                      "manual_disabled": False, "disabled": False,
                      "disabled_reason": "", "billing": {}}],
        "devices": []}))
    mod.load_state()
    a1 = mod.POOL.accounts[0]
    assert a1.cool_until == 0 and a1.breaker_until == 0
    assert a1.retry_count == 3  # 指数退避代数保留（防重复踩雷区）
