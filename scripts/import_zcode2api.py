#!/usr/bin/env python3
"""从 zcode2api 的 SQLite 账号库迁移 JWT 账号到 zai-pool 的 pool.json。

数据源：~/zcode2api/data/accounts.db（表 accounts）。两种 schema 兼容：
平铺列（jwt_token/id/mode，本机实测形态）或 data 列 JSON（secret 字段）。
迁移条目：name 沿用 id（batch-xxxxxxxx）、zcode_jwt=jwt_token、chat_via=jwt、
realm=global；同名账号跳过不覆盖。

用法：
    python3 scripts/import_zcode2api.py                # dry-run：只打印
    python3 scripts/import_zcode2api.py --write        # 写回 pool.json（自动 chmod 600）
    python3 scripts/import_zcode2api.py --db PATH --config PATH --write
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

DEFAULT_DB = Path.home() / "zcode2api" / "data" / "accounts.db"


def _clean(v) -> str:
    """DB 里的空值可能是字面量 'None'/'null' 字符串。"""
    s = str(v or "").strip()
    return "" if s.lower() in ("none", "null") else s


def load_accounts(db_path: Path) -> list[dict]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        cur = conn.execute("select * from accounts")
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()
    out = []
    for r in rows:
        blob = None
        if isinstance(r.get("data"), str) and r["data"].lstrip().startswith("{"):
            try:
                blob = json.loads(r["data"])
            except Exception:
                blob = None
        secret = _clean(r.get("jwt_token") or (blob or {}).get("jwt_token")
                        or (blob or {}).get("secret"))
        mode = str(r.get("mode") or (blob or {}).get("mode") or "").lower()
        if not secret or (mode and mode != "jwt"):
            continue
        out.append({
            "name": _clean(r.get("id") or r.get("name") or (blob or {}).get("name")) or "imported",
            "zcode_jwt": secret,
            "chat_via": "jwt",
            "realm": "global",
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default=str(DEFAULT_DB), help="zcode2api SQLite 路径")
    ap.add_argument("--config", default=os.environ.get("ZPOOL_CONFIG", "pool.json"),
                    help="zai-pool pool.json 路径")
    ap.add_argument("--write", action="store_true", help="实际写回（缺省 dry-run）")
    a = ap.parse_args()

    db = Path(a.db).expanduser()
    if not db.exists():
        print(f"[fail] 数据源不存在: {db}", file=sys.stderr)
        return 1
    cfg_path = Path(a.config).expanduser()
    if not cfg_path.exists():
        print(f"[fail] pool.json 不存在: {cfg_path}", file=sys.stderr)
        return 1

    incoming = load_accounts(db)
    cfg = json.loads(cfg_path.read_text())
    existing = {x.get("name") for x in cfg.get("accounts") or []}
    fresh = [x for x in incoming if x["name"] not in existing]

    print(f"{'name':<16} {'jwt[:16]':<18} plan")
    for x in incoming:
        mark = "" if x["name"] not in existing else "  (已存在，跳过)"
        jwt_head = x["zcode_jwt"][:16] + "…"
        print(f"{x['name']:<16} {jwt_head:<18} chat_via=jwt{mark}")
    if not fresh:
        print("[done] 无新增账号")
        return 0

    if not a.write:
        print(f"[dry-run] 将新增 {len(fresh)} 条到 {cfg_path}；加 --write 生效")
        return 0

    cfg["accounts"] = list(cfg.get("accounts") or []) + fresh
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
    os.chmod(cfg_path, 0o600)  # 含 JWT：启动安全闸口径
    print(f"[write] 已新增 {len(fresh)} 条 → {cfg_path}（chmod 600）；重启或 SIGHUP 热重载生效")
    return 0


if __name__ == "__main__":
    sys.exit(main())
