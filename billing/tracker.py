"""领取账本（计划书 5.5）：JSONL 追加持久化，重启不丢；永不落 JWT/完整头。"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path


class BillingLedger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, account: str, plan_id: str, status: str,
               detail: str = "", trigger: str = "schedule",
               api_status: int | None = None, verified_at: float = 0.0) -> None:
        ent = {"ts": time.time(), "date": time.strftime("%Y-%m-%d"),
               "account": account, "plan_id": plan_id, "status": status,
               "detail": detail[:200], "trigger": trigger,
               "api_status": api_status, "verified_at": verified_at}
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a") as f:
                    f.write(json.dumps(ent, ensure_ascii=False) + "\n")
            except OSError:
                pass  # 账本是观测组件：写失败不拖垮关键路径

    def claimed_today(self, account: str, day: str | None = None) -> bool:
        day = day or time.strftime("%Y-%m-%d")
        if not self.path.exists():
            return False
        try:
            for line in self.path.read_text().splitlines():
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if (e.get("account") == account and e.get("date") == day
                        and e.get("status") in ("success", "already")):
                    return True
        except OSError:
            return False
        return False


def atomic_write(path: str | Path, data: str) -> None:
    p = Path(path)
    tmp = p.with_suffix(p.suffix + f".{os.getpid()}.tmp")
    with open(tmp, "w") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
