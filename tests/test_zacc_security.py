"""zacc 安全：路径穿越拦截（P0 回归）。"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def zacc_mod(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("zacc_mod", ROOT / "zacc.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["zacc_mod"] = mod
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "ACCOUNTS_DIR", tmp_path / "accounts")
    monkeypatch.setattr(mod, "V2_DIR", tmp_path / "v2")
    (tmp_path / "v2").mkdir(parents=True)
    (tmp_path / "v2" / "credentials.json").write_text('{"oauth:zai:access_token":"T"}')
    return mod


def test_name_whitelist_accepts_normal(zacc_mod):
    assert zacc_mod.sanitize_name("ok-name_1") == "ok-name_1"


@pytest.mark.parametrize("bad", ["../..", "..", "../../etc", "a/b", "a\\b", "带空格",
                                 ".hidden", "", "x" * 65, "name;rm"])
def test_name_whitelist_rejects_traversal(zacc_mod, bad):
    with pytest.raises(SystemExit):
        zacc_mod.sanitize_name(bad)


def test_rm_cannot_escape_accounts_dir(zacc_mod, tmp_path, monkeypatch):
    """回归：旧版 zacc rm ../.. 会把删除目标指到 HOME 级目录。"""
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep")
    with pytest.raises(SystemExit):
        zacc_mod.cmd_rm(["../victim"])
    assert (victim / "keep.txt").exists(), "越界目标必须原封不动"


def test_add_and_list_roundtrip(zacc_mod, capsys):
    zacc_mod.cmd_add(["prof1"])
    zacc_mod.cmd_list([])
    out = capsys.readouterr().out
    assert "prof1" in out


def test_infer_home_always_str(zacc_mod):
    src = zacc_mod.HOME / "not" / "a" / "zcode" / "path.json"
    assert isinstance(zacc_mod.infer_home(src), str)
