#!/usr/bin/env python3
"""Phase 8-8.1 数据备份/恢复。

备份对象（按计划书 8.1，凭据文件绝不进公开仓库）：
    pool-state.json / billing-ledger.jsonl / admin_audit.log / server.log(可选)
    --zacc 时附加 zacc 账号档案（含敏感凭据 → 必须加密）

加密：--encrypt 用 cryptography.Fernet，密钥取 $ZPOOL_BACKUP_KEY（无则生成
backups/backup.key，600）。无 cryptography 时明文 tar.gz + 600 并提示。

用法：
    python3 scripts/backup.py                       # 备份（不加密）
    python3 scripts/backup.py --encrypt --zacc      # 加密 + 含 zacc 档案
    python3 scripts/backup.py --list backups/x.tar.gz[.enc]
    python3 scripts/backup.py --restore backups/x.tar.gz [--to /tmp/restore]
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKUP_DIR = ROOT / "backups"
CORE_FILES = ["zai-pool-data/pool-state.json", "zai-pool-data/billing-ledger.jsonl",
              "zai-pool-data/admin_audit.log", "zai-pool-data/pool.json"]
ZACC_GLOB = "/home/emo/.zcode/accounts/*/data/.zcode/v2/credentials.json"


def _fernet():
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("[backup] cryptography 未安装 → 明文备份（权限 600）", file=sys.stderr)
        return None
    key = os.environ.get("ZPOOL_BACKUP_KEY")
    keyfile = BACKUP_DIR / "backup.key"
    if not key:
        if keyfile.exists():
            key = keyfile.read_text().strip()
        else:
            key = Fernet.generate_key().decode()
            BACKUP_DIR.mkdir(exist_ok=True)
            keyfile.write_text(key)
            os.chmod(keyfile, 0o600)
            print(f"[backup] 已生成备份密钥 {keyfile}（务必离线保存，丢失即不可恢复）")
    return Fernet(key.encode())


def backup(encrypt: bool, with_zacc: bool) -> Path:
    BACKUP_DIR.mkdir(exist_ok=True)
    buf = io.BytesIO()
    n = 0
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel in CORE_FILES:
            p = ROOT / rel
            if p.exists():
                tf.add(str(p), arcname=rel)
                n += 1
        if with_zacc:
            import glob
            for p in glob.glob(ZACC_GLOB):
                arc = "zacc/" + "/".join(Path(p).parts[-5:])
                tf.add(p, arcname=arc)
                n += 1
    raw = buf.getvalue()
    ts = time.strftime("%Y%m%d-%H%M%S")
    if encrypt:
        f = _fernet()
        if f:
            raw = f.encrypt(raw)
            out = BACKUP_DIR / f"zai-pool-backup-{ts}.tar.gz.enc"
        else:
            out = BACKUP_DIR / f"zai-pool-backup-{ts}.tar.gz"
    else:
        out = BACKUP_DIR / f"zai-pool-backup-{ts}.tar.gz"
    out.write_bytes(raw)
    os.chmod(out, 0o600)
    sha = hashlib.sha256(raw).hexdigest()[:16]
    print(f"[backup] {out}（{len(raw)} 字节，{n} 个文件，sha256[:16]={sha}"
          f"{'，加密' if encrypt and out.suffix == '.enc' else ''}）")
    return out


def list_archive(path: Path) -> int:
    data = path.read_bytes()
    f = _fernet() if path.suffix == ".enc" else None
    if path.suffix == ".enc":
        if not f:
            print("缺少加密密钥（ZPOOL_BACKUP_KEY / backups/backup.key）", file=sys.stderr)
            return 1
        data = f.decrypt(data)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf.getmembers():
            print(f"  {m.size:>9}  {m.name}")
    print(f"[backup] 校验 OK：{path}")
    return 0


def restore(path: Path, to: Path) -> int:
    data = path.read_bytes()
    if path.suffix == ".enc":
        f = _fernet()
        if not f:
            return 1
        data = f.decrypt(data)
    to.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        tf.extractall(str(to), filter="data")  # 拒绝绝对路径/越界成员
    print(f"[backup] 已恢复 {sum(1 for _ in to.rglob('*'))} 个文件 → {to}（预览确认后再覆盖正式目录）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--encrypt", action="store_true")
    ap.add_argument("--zacc", action="store_true", help="附加 zacc 账号档案（含凭据，必须加密）")
    ap.add_argument("--list")
    ap.add_argument("--restore")
    ap.add_argument("--to", default=str(ROOT / "backups" / "restore-preview"))
    a = ap.parse_args()
    if a.zacc and not a.encrypt:
        print("[backup] 含 zacc 凭据的备份必须 --encrypt", file=sys.stderr)
        return 2
    if a.list:
        return list_archive(Path(a.list))
    if a.restore:
        return restore(Path(a.restore), Path(a.to))
    backup(a.encrypt, a.zacc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
