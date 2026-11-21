"""zai_pool.storage — Phase6 storage 域（单一所有权，2026-11-22 try2）。

自 zai-pool.py 按顶层节点机械搬移：save_state/load_state/_save_fail/_save_fail_throttled/
_save_fails/_STATE_READONLY/_RO_LAST_LOG/_persist_lock/audit/key_fp。
zai-pool.py 侧 re-export/薄包装回流，relay/admin/billing/main 调用点零改动。
归属明细见 ZAI-POOL-IMPROVEMENT-PLAN.md Phase 6。

全局句柄注入：POOL/STATE_FILE/AUDIT_FILE 原是 zai-pool.py 模块级全局，main 与测试
都会直接赋值，故 storage 侧以 init_storage 注入句柄、getter 延迟求值（每次调用读
最新值），保证「测试直接写 mod.STATE_FILE 不经 init_storage」这类既有用法不变。
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from zai_pool.core import Account, Device, Pool, _state_lock, CST, now_cst, log  # noqa: F401  计划书 storage 域头部清单位（Account/Device/CST 经 Pool 间接引用）


# ---- 可注入句柄（zai-pool.py 原全局变量赋值处经 init_storage 注入；getter 延迟求值） ----
_pool_getter = None
_state_file_getter = None
_audit_file_getter = None

_persist_lock = threading.Lock()  # 落盘临界区（独立于状态锁，避免序列化阻塞请求）

_STATE_READONLY = False
_RO_LAST_LOG = [0.0]
_save_fails = [0]


def init_storage(pool_getter, state_file, audit_file) -> None:
    """注入 POOL/STATE_FILE/AUDIT_FILE 句柄（zai-pool.py 装配点调用）。

    pool_getter : 0 元 callable，返回当前 Pool（POOL 在 main/测试中后置赋值）。
    state_file  : str 或 0 元 callable（延迟求值——直接赋值 mod.STATE_FILE 即时生效）。
    audit_file  : str 或 0 元 callable（同上）。
    重复注入以最新为准，并复位模块级落盘运行态（_STATE_READONLY/_save_fails/_RO_LAST_LOG）：
    原实现它们是 zai-pool.py 模块级全局，每次模块加载即全新；storage.py 在进程内单例化，
    由 init 原地复位保持等价（列表原地清零以维持 re-import 的对象身份）。
    """
    global _pool_getter, _state_file_getter, _audit_file_getter
    global _STATE_READONLY
    _pool_getter = pool_getter
    _state_file_getter = state_file
    _audit_file_getter = audit_file
    _STATE_READONLY = False
    _save_fails[0] = 0
    _RO_LAST_LOG[0] = 0.0


def _pool() -> Pool | None:
    return _pool_getter()


def _state_file() -> str:
    sf = _state_file_getter() if callable(_state_file_getter) else _state_file_getter
    return sf or ""


def _audit_file() -> str:
    af = _audit_file_getter() if callable(_audit_file_getter) else _audit_file_getter
    return af or ""


def _save_fail_throttled(msg: str) -> None:
    if time.time() - _RO_LAST_LOG[0] > 300:
        _RO_LAST_LOG[0] = time.time()
        log(f"[state] {msg}")


def save_state() -> None:
    sf = _state_file()
    if not sf or _STATE_READONLY:
        if _STATE_READONLY:
            _save_fail_throttled("状态文件只读保护中（损坏备份失败），跳过写盘")
        return
    # 1) 状态锁内做深拷贝快照（请求线程只短暂持锁）
    with _state_lock:
        pool = _pool()
        data = {"saved_at": time.time(), "accounts": [], "devices": []}
        for a in pool.accounts:
            data["accounts"].append({
                "name": a.name,
                "usage": {k: dict(v) for k, v in a.usage.items()},
                "cool_until": a.cool_until, "cool_reason": a.cool_reason,
                "breaker_until": a.breaker_until, "retry_count": a.retry_count,
                "manual_disabled": a.manual_disabled, "disabled": a.disabled,
                "disabled_reason": a.disabled_reason,
                "billing": json.loads(json.dumps(a.billing)),
            })
        for d in pool.devices:
            data["devices"].append({"name": d.name,
                                    "usage": {k: dict(v) for k, v in d.usage.items()},
                                    "primary": d.primary})
    # 2) 持久化锁内写唯一临时文件 → fsync → 原子替换
    with _persist_lock:
        tmp = f"{sf}.{os.getpid()}.{threading.get_ident()}.tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, sf)
        except OSError as e:
            _save_fail(e)
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _save_fail(e: OSError) -> None:
    _save_fails[0] += 1
    if _save_fails[0] == 1:
        p = Path(_state_file())
        log(f"[state] 写盘失败（首败详报）: {e} path={p} dir_writable={os.access(p.parent, os.W_OK)} "
            f"owner={p.parent.stat().st_uid if p.parent.exists() else '-'}")
    elif _save_fails[0] % 100 == 0:
        log(f"[state] 写盘持续失败 ×{_save_fails[0]}")


def load_state() -> None:
    sf = _state_file()
    if not sf or not Path(sf).exists():
        return
    raw = Path(sf).read_bytes()
    if not raw.strip():
        log(f"[state] 状态文件为空（{sf}），按全新状态启动；原文件保留为 .empty 标记")
        try:
            os.replace(sf, sf + ".empty")
        except OSError:
            pass
        return
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or "accounts" not in data:
            raise ValueError("结构不识别：缺少 accounts 段")
    except Exception as e:
        # 无法识别的状态：保留原文件 + 明确诊断，绝不静默覆盖（审查 3.2 要求）
        bak = f"{sf}.corrupt-{int(time.time())}"
        try:
            os.replace(sf, bak)
            log(f"[state] 状态文件损坏/不可识别（{e}），已原样保留为 {bak}，按全新状态启动")
        except OSError as e2:
            log(f"[state] 状态文件损坏且备份失败（{e} / {e2}）：后续写盘将被跳过以免覆盖原文件")
            global _STATE_READONLY
            _STATE_READONLY = True
        return
    by = {x["name"]: x for x in data.get("accounts", [])}
    now = time.time()
    pool = _pool()
    for a in pool.accounts:
        if a.name not in by:
            continue
        x = by[a.name]
        a.usage = x.get("usage", {})
        # 过期状态不复活
        a.cool_until = x.get("cool_until", 0) if x.get("cool_until", 0) > now else 0
        a.cool_reason = x.get("cool_reason", "")
        a.breaker_until = x.get("breaker_until", 0) if x.get("breaker_until", 0) > now else 0
        a.retry_count = x.get("retry_count", 0)
        a.manual_disabled = x.get("manual_disabled", False)
        a.disabled = x.get("disabled", False)
        a.disabled_reason = x.get("disabled_reason", "")
        a.billing = x.get("billing", {})
    dev_by = {x["name"]: x for x in data.get("devices", [])}
    for d in pool.devices:
        if d.name in dev_by:
            d.usage = dev_by[d.name].get("usage", {})
            d.primary = dev_by[d.name].get("primary")


# ---------- 审计 ----------
def audit(action: str, target: str, result: str, client_key_fp: str, reason: str = "") -> None:
    af = _audit_file()
    if not af:
        return
    ent = {"ts": now_cst().isoformat(), "action": action, "target": target,
           "result": result, "key_fp": client_key_fp, "reason": reason}
    try:
        with open(af, "a") as f:
            f.write(json.dumps(ent, ensure_ascii=False) + "\n")
    except OSError as e:
        log(f"[audit] 写失败: {e}")


def key_fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]
