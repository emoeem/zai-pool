"""zai_pool.core — Phase6 core 域（单一所有权，2026-11-22 try2）。

自 zai-pool.py 按顶层节点 AST 机械搬移；zai-pool.py 侧 re-import 全部名字，
下游（upstream/storage/billing/observability/http/entry）引用不变。
归属明细见 ZAI-POOL-IMPROVEMENT-PLAN.md Phase 6。
"""
from __future__ import annotations  # 节点源码依赖 PEP 563（Pool.device_by_key 前向注解 Device）

import hashlib  # noqa: F401  计划书头部清单位，当前 core 节点未直接引用
import json
import os
import random
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path  # noqa: F401  计划书头部清单位，当前 core 节点未直接引用

from billing.policy import exhausted as _bal_exhausted, token_ratio as _bal_ratio


CST = timezone(timedelta(hours=8))


# core 域：realm -> 上游 host/路径表（Account 归属校验 + upstream 域按 realm 读用）
UPSTREAMS = {
    # realm -> (host, openai 前缀, anthropic 前缀)；cn = bigmodel.cn 国内通道
    "global": {"host": "api.z.ai", "openai": "/api/coding/paas/v4", "anthropic": "/api/anthropic"},
    "cn": {"host": "open.bigmodel.cn", "openai": "/api/coding/paas/v4", "anthropic": "/api/anthropic"},
}


# core 域：UPSTREAMS 族派生——global 通道 host（upstream 域隧道/连接默认目标）
UP_HOST = UPSTREAMS["global"]["host"]


# core 域：UPSTREAMS 族派生——OpenAI 兼容路径前缀（http 域装配 /v1/chat/completions）
UP_OPENAI_PATH = UPSTREAMS["global"]["openai"]


# core 域：UPSTREAMS 族派生——Anthropic 兼容路径前缀（http 域装配 /v1/messages）
UP_ANTHROPIC_PATH = UPSTREAMS["global"]["anthropic"]


# core 域：请求体上限缺省（DEFAULT_SERVER.max_body_bytes 与 _relay 回退读用）
MAX_BODY_BYTES = 32 * 1024 * 1024


# core 域：服务器运行参数缺省（Pool.server_cfg 快照源；http/upstream 域经 server_cfg 读用）
DEFAULT_SERVER = {
    "max_connections": 100,      # 活跃连接上限（超限直接 503，不无限建线程）
    "max_queued_requests": 50,   # listen backlog
    "max_sse_connections": 30,   # SSE 独立配额（不被普通请求挤占，反之亦然）
    "request_timeout": 300,      # 非流式上游读取超时（秒）
    "stream_idle_timeout": 90,   # SSE 相邻数据块最大间隔（秒），超时即终止流
    "connect_timeout": 20,       # 上游 TCP/TLS/代理握手超时（秒）
    "max_body_bytes": MAX_BODY_BYTES,
    "rate_limit_per_min": 0,     # 全局限流（次/分钟，0=关闭）
    "device_rate_limit_per_min": 0,  # 设备级限流（次/分钟，0=关闭）
}


# core 域：请求限流桶（Pool 持有，Phase6 随 core 迁移）
class TokenBucket:
    """内存令牌桶（4.4）：rate_per_min=0 表示不限流。"""

    def __init__(self, rate_per_min: float, capacity: float | None = None):
        self.rate = rate_per_min / 60.0  # 每秒补充
        self.capacity = capacity if capacity is not None else max(1.0, rate_per_min)
        self.tokens = self.capacity
        self.last = time.monotonic()

    def allow(self) -> bool:
        if self.rate <= 0:
            return True
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


# http 域：SSE 增量解析器（仅 Handler._relay 消费，Phase6 随 http 迁移）
class SSEUsageParser:
    """SSE 增量解析器（4.2）：TCP chunk → 事件缓冲 → 行解析 → usage 提取。
    不假设一次 read 就是完整行；协议字节由调用方原样透传，解析器只读不改。"""

    def __init__(self):
        self._buf = b""
        self.tin: int | None = None
        self.tout: int | None = None

    def feed(self, chunk: bytes) -> None:
        self._buf += chunk
        while b"\n" in self._buf:
            raw, self._buf = self._buf.split(b"\n", 1)
            self._line(raw.strip(b"\r"))

    def _line(self, line: bytes) -> None:
        if not line.startswith(b"data:"):
            return
        payload = line[5:].strip()
        if not payload or payload == b"[DONE]":
            return
        try:
            u = (json.loads(payload.decode("utf-8", errors="replace")).get("usage") or {})
        except Exception:
            return
        if u.get("prompt_tokens") is not None:
            self.tin = int(u["prompt_tokens"])
        if u.get("completion_tokens") is not None:
            self.tout = int(u["completion_tokens"])


_state_lock = threading.Lock()


_sched_lock = threading.Lock()   # 选号+租约临界区


def now_cst() -> datetime:
    return datetime.now(CST)


def next_reset(hour: int = 9) -> float:
    dt = datetime.now(CST)
    r = dt.replace(hour=hour, minute=0, second=0, microsecond=0)
    if r <= dt:
        r += timedelta(days=1)
    return r.timestamp()


def log(msg: str) -> None:
    print(f"[{now_cst().strftime('%m-%d %H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


# ---------- 账号与状态机 ----------
class Account:
    def __init__(self, cfg: dict):
        self.name = cfg["name"]
        self.key = cfg["api_key"]
        self.realm = cfg.get("realm", "global")
        if self.realm not in UPSTREAMS:
            self.realm = "global"
        self.proxy = (cfg.get("proxy") or "").strip()
        self.sport_range = cfg.get("sport_range")
        self.expires = cfg.get("expires")
        self.zcode_jwt = (cfg.get("zcode_jwt") or "").strip()
        self.device_mid = (cfg.get("device_mid") or "").strip()
        self.max_in_flight = int(cfg.get("max_in_flight", 8))
        # 状态机字段（持久化）
        self.cool_until = 0.0
        self.cool_reason = ""
        self.fails = 0              # 429 streak（不持久化）
        self.breaker_until = 0.0    # 5xx 熔断（持久化）
        self.retry_count = 0        # 熔断指数（持久化）
        self.degrade_until = 0.0    # 未知失败降权（不持久化）
        self.unknown_fails = 0
        self.manual_disabled = False
        self.disabled = False
        self.disabled_reason = ""
        self.last_used = 0.0
        self.last_picked = 0.0
        self.in_flight = 0
        self.usage: dict[str, dict] = {}
        # 调度观测（3.3）：req/ok/fail 计数与最近错误（运行态，不持久化）
        self.stats = {"req": 0, "ok": 0, "fail": 0, "err_last": ""}
        # billing 巡检结果
        self.billing: dict = {}

    # --- 三截止（或门取更远） ---
    def healthy(self) -> bool:
        now = time.time()
        if self.manual_disabled or self.disabled:
            return False
        return max(self.cool_until, self.breaker_until, self.degrade_until) <= now

    def state_reasons(self) -> list[str]:
        now = time.time()
        out = []
        if self.manual_disabled:
            out.append("manual_disabled")
        if self.disabled:
            out.append(f"disabled({self.disabled_reason})")
        if self.cool_until > now:
            out.append(f"cooling({self.cool_reason}→{datetime.fromtimestamp(self.cool_until).strftime('%H:%M')})")
        if self.breaker_until > now:
            out.append(f"breaker(→{datetime.fromtimestamp(self.breaker_until).strftime('%H:%M')})")
        if self.degrade_until > now:
            out.append("degraded")
        if self.in_flight >= self.max_in_flight:
            out.append("in_flight_full")
        return out or ["healthy"]

    def has_slot(self) -> bool:
        return self.in_flight < self.max_in_flight

    def available(self) -> bool:
        return self.healthy() and self.has_slot()

    def today(self) -> dict:
        return self.usage.setdefault(now_cst().strftime("%Y-%m-%d"), {"in": 0, "out": 0, "req": 0})

    def record(self, tin: int | None, tout: int | None) -> None:
        with _state_lock:
            t = self.today()
            t["in"] += tin or 0
            t["out"] += tout or 0
            t["req"] += 1

    def remaining_ratio(self) -> float | None:
        """billing 巡检的剩余比例（仅 token 单位条目）；无 billing 数据返回 None。"""
        from billing.models import Balance
        b = [Balance(self.name, x.get("plan_id", ""), x.get("plan_name", ""),
                     x.get("show_name", ""), x.get("unit_type", "token"),
                     x.get("total_units", 0), x.get("used_units", 0),
                     x.get("remaining_units", 0)) for x in self.billing.get("balances") or []]
        return _bal_ratio(b)

    def exhausted(self) -> bool:
        """整个账号耗尽 = 有条目且全部 remaining<=0（不同套餐独立判断，不混合单位）。"""
        from billing.models import Balance
        b = [Balance(self.name, x.get("plan_id", ""), "", x.get("show_name", ""),
                     x.get("unit_type", "token"), x.get("total_units", 0),
                     x.get("used_units", 0), x.get("remaining_units", 0))
             for x in self.billing.get("balances") or []]
        return _bal_exhausted(b)


class Pool:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.accounts = [Account(a) for a in cfg["accounts"] if a.get("api_key")]
        self.devices = [Device(d) for d in (cfg.get("devices") or []) if d.get("key")]
        self.api_key = cfg.get("api_key", "")
        # 密钥轮换（7.3）：api_key 可为字符串或数组；新 key 生效前旧 key 不失效
        keys = cfg.get("api_keys") or [cfg.get("api_key") or ""]
        self.api_keys = {str(k).strip() for k in keys if str(k).strip()}
        self.reset_hour = int(cfg.get("reset_hour", 9))
        self.strategy = cfg.get("strategy", "sticky-first")
        self.max_retry = int(cfg.get("max_retry", max(2, len(self.accounts))))
        self.sticky_min = float(cfg.get("sticky_minutes", 30))
        self.sticky: dict[str, tuple[str, float]] = {}
        self._primary: str | None = None
        # 调度观测（3.3）
        self.sched = {"sticky_hits": 0, "sticky_unbind": 0, "primary_switches": 0,
                      "switch_reasons": {}}
        self.alert_cfg = cfg.get("alert") or {}
        self.admin_cfg = cfg.get("admin") or {}
        self.server_cfg = dict(DEFAULT_SERVER)
        self.server_cfg.update(cfg.get("server") or {})
        self._global_bucket = TokenBucket(float(self.server_cfg.get("rate_limit_per_min", 0)))
        self._device_buckets: dict[str, TokenBucket] = {}
        self.admin_bucket = TokenBucket(30)  # 7.3 管理操作限流（30/分钟）
        if not self.accounts:
            raise SystemExit("pool.json 没有有效账号")

    def device_bucket(self, dev: "Device | None") -> TokenBucket | None:
        """设备级限流桶；全局桶恒在。限流与账号 429 状态机完全隔离。"""
        if dev is None:
            return None
        b = self._device_buckets.get(dev.name)
        if b is None:
            rate = float(self.server_cfg.get("device_rate_limit_per_min", 0))
            b = TokenBucket(rate)
            self._device_buckets[dev.name] = b
        return b

    def allow_request(self, dev: "Device | None") -> bool:
        if not self._global_bucket.allow():
            return False
        b = self.device_bucket(dev)
        if b and not b.allow():
            return False
        return True

    def device_by_key(self, key: str) -> Device | None:
        for d in self.devices:
            if key in d.keys:
                return d
        return None

    def device_by_name(self, name: str) -> Device | None:
        return next((d for d in self.devices if d.name == name), None)

    # --- 选号 ---
    def _weights(self) -> dict[str, float]:
        now = time.time()
        deadline = next_reset(self.reset_hour)
        w = {}
        for a in self.accounts:
            r = a.remaining_ratio()
            x = 2.0 * (0.5 if r is None else max(0.0, r))  # 无配额数据取中性 0.5
            exp = a.expires_ts()
            if exp:
                remain = max(0.0, exp - now)
                x += 3.0 * (1.0 - min(1.0, remain / max(3600.0, deadline - now)))
            x += min(5.0, (now - (a.last_used or 0)) / 3600.0 * 0.5)  # 闲置补偿 0.5/h 封顶 5
            w[a.name] = x
        return w

    def pick(self, sticky_key: str, exclude: set[str], dev: "Device | None" = None) -> Account | None:
        # 设备分配子集（无分配 = 全池）；粘性与主用号都必须过此过滤（设备隔离）
        pool_names = set(dev.accounts) if dev and dev.accounts else None
        in_scope = (lambda a: True) if pool_names is None else (lambda a: a.name in pool_names)
        # 1) 会话粘性（五级键；键已含设备前缀，跨设备不冲突）
        if sticky_key:
            ent = self.sticky.get(sticky_key)
            if ent:
                name, until = ent
                if time.time() > until:
                    self.sticky.pop(sticky_key, None)
                    self.sched["sticky_unbind"] += 1
                else:
                    for a in self.accounts:
                        if (a.name == name and a.available() and a.name not in exclude
                                and in_scope(a)):
                            self.sched["sticky_hits"] += 1
                            return a
                    self.sticky.pop(sticky_key, None)  # 失败解绑
                    self.sched["sticky_unbind"] += 1
        alive = [a for a in self.accounts
                 if a.available() and a.name not in exclude and not a.exhausted()
                 and in_scope(a)]
        if not alive:
            return None
        now = time.time()
        # 2) 防惊群：跳过 100ms 内刚被选中的
        fresh = [a for a in alive if now - a.last_picked < 0.1 and len(alive) > 1]
        if fresh:
            alive = [a for a in alive if a not in fresh] or alive
        w = self._weights()
        primary_name = dev.primary if dev else self._primary
        # 3) 策略
        if self.strategy == "sticky-first":
            # 主用号复用（设备级或池级）；必须仍在分配子集内
            for a in self.accounts:
                if (a.name == primary_name and a.available() and a.name not in exclude
                        and not a.exhausted() and in_scope(a)):
                    a.last_picked = now
                    return a
            # 双段分配：新会话优先未被任何会话绑定的号
            bound = {v[0] for v in self.sticky.values()}
            free = [a for a in alive if a.name not in bound]
            cand = free or alive
            picked = max(cand, key=lambda a: w.get(a.name, 1.0) + random.random() * 0.3)
            if primary_name != picked.name:
                log(f"[primary]{f' dev={dev.name}' if dev else ''} {picked.name}")
                self.sched["primary_switches"] += 1
                if dev:
                    dev.primary = picked.name
                else:
                    self._primary = picked.name
            picked.last_picked = now
            return picked
        # balanced：Top-3 短名单，等权重先洗牌防字典序饿死
        alive.sort(key=lambda a: w.get(a.name, 1.0), reverse=True)
        top = alive[:3]
        random.shuffle(top)
        tot = sum(w.get(a.name, 1.0) for a in top)
        r = random.random() * tot
        for a in top:
            r -= w.get(a.name, 1.0)
            if r <= 0:
                a.last_picked = now
                return a
        top[-1].last_picked = now
        return top[-1]

    def device_sticky_key(self, dev: "Device | None", sticky_key: str) -> str:
        """粘性键带设备命名空间：同首条消息的不同设备不互相串号。"""
        return f"{dev.name}:{sticky_key}" if dev else sticky_key

    def prune_sticky_for(self, dev: "Device") -> None:
        """设备分配变更后：清掉该设备越界的粘性绑定与主用号。"""
        prefix = f"{dev.name}:"
        if not dev.accounts:
            return
        allowed = set(dev.accounts)
        for k in [k for k, v in self.sticky.items()
                  if k.startswith(prefix) and v[0] not in allowed]:
            self.sticky.pop(k, None)
        if dev.primary and dev.primary not in allowed:
            dev.primary = None

    def bind(self, sticky_key: str, a: Account) -> None:
        if sticky_key:  # 成功重绑：粘性跟随最终成功号
            self.sticky[sticky_key] = (a.name, time.time() + self.sticky_min * 60)
            if len(self.sticky) > 256:  # GC
                cutoff = time.time() - self.sticky_min * 60
                for k in [k for k, v in self.sticky.items() if v[1] < cutoff]:
                    self.sticky.pop(k, None)

    def unbind(self, sticky_key: str) -> None:
        self.sticky.pop(sticky_key, None)

    def cooldown(self, a: Account, status: int, msg: str, headers: dict | None = None) -> None:
        now = time.time()
        low = msg.lower()
        if status in (401, 403):
            until, reason = now + 3600, "auth"
        elif status in (402,) or "1113" in msg or "insufficient" in low or "余额" in msg or "额度" in low:
            until, reason = next_reset(self.reset_hour), "exhausted"
        elif status == 429:
            # Retry-After 对齐；无则有界指数退避封顶 2h；探测不叠加
            ra = (headers or {}).get("retry-after")
            if ra:
                try:
                    until = min(now + float(ra), next_reset(self.reset_hour))
                except ValueError:
                    until = min(now + max(300, 600 * (2 ** min(a.fails, 3))), now + 7200)
            else:
                until = now + max(300, 600 * (2 ** min(a.fails, 3))) if a.fails else now + 600
                until = min(until, now + 7200)
            reason = "rate_limited"
        elif status >= 500:
            # 熔断器：3 连败 → 30min ×2^retry 封顶 6h（与冷却解耦）
            a.fails += 1
            if a.fails >= 3:
                a.retry_count += 1
                a.breaker_until = now + min(1800 * (2 ** (a.retry_count - 1)), 21600)
                a.fails = 0
                reason = "breaker"
                until = a.breaker_until
            else:
                until, reason = now + 60, "server_error"
        else:
            until, reason = now + 30, "client_error"
        if until > a.cool_until:  # 不延长已有更长冷却（markFailure 语义）
            a.cool_until = until
            a.cool_reason = reason
        self.sched["switch_reasons"][reason] = self.sched["switch_reasons"].get(reason, 0) + 1
        a.stats["fail"] += 1
        a.stats["err_last"] = f"{status}:{msg[:60]}"
        if self._primary == a.name and not a.healthy():
            self._primary = None
        for d in self.devices:
            if d.primary == a.name and not a.healthy():
                d.primary = None
        log(f"[cooldown] {a.name} http={status} {reason} until={datetime.fromtimestamp(until).strftime('%m-%d %H:%M')} {msg[:70]}")

    def note_unknown_fail(self, a: Account) -> None:
        """未知失败（传输层/非分类 4xx）降权：5 次 → 固定 10m 出池。"""
        a.unknown_fails += 1
        if a.unknown_fails >= 5 and a.degrade_until < time.time():
            a.degrade_until = time.time() + 600
            a.unknown_fails = 0
            log(f"[degrade] {a.name} 出池 10m")

    def ok(self, a: Account) -> None:
        a.fails = 0
        a.unknown_fails = 0
        a.last_used = time.time()
        a.stats["ok"] += 1
        if a.breaker_until and a.breaker_until <= time.time():
            a.breaker_until = 0.0
            a.retry_count = 0


def _expires_ts(a: Account) -> float | None:
    if not a.expires:
        return None
    try:
        return datetime.fromisoformat(a.expires).timestamp()
    except ValueError:
        return None


Account.expires_ts = _expires_ts  # noqa: 统一挂载


class Device:
    """接入设备：独立 key（可数组，平滑轮换）+ 账号分配子集（空 = 全池）+ 每设备记账。"""

    def __init__(self, cfg: dict):
        self.name = cfg["name"]
        keys = cfg.get("keys") or [cfg.get("key") or ""]
        self.keys = {str(k).strip() for k in keys if str(k).strip()}
        self.accounts = list(cfg.get("accounts") or [])
        self.primary: str | None = None
        self.usage: dict[str, dict] = {}

    def today(self) -> dict:
        return self.usage.setdefault(now_cst().strftime("%Y-%m-%d"), {"in": 0, "out": 0, "req": 0})

    def record(self, tin: int | None, tout: int | None) -> None:
        with _state_lock:
            t = self.today()
            t["in"] += tin or 0
            t["out"] += tout or 0
            t["req"] += 1


DANGEROUS_KEYS = {"", "zpool-local-change-me", "change_me", "change-me", "test_key",
                  "your-api-key", "sk-xxx", "placeholder"}


def validate_security(cfg: dict, cfg_path: str) -> None:
    """启动安全闸：密钥强度 / 监听面 / 配置文件权限。不达标拒绝启动。
    api_key 支持数组（轮换期多 key 并存），每个 key 都必须达标。"""
    keys = [str(k).strip() for k in (cfg.get("api_keys") or [cfg.get("api_key") or ""])
            if str(k).strip()]
    if not keys:
        raise SystemExit(
            f"[security] api_key 为空——拒绝启动。\n"
            f"  生成强密钥：python3 -c \"import secrets; print('zpool-'+secrets.token_urlsafe(24))\"\n"
            f"  写入 {cfg_path} 的 api_key 字段后重启。")
    for k in keys:
        if k.lower() in DANGEROUS_KEYS:
            raise SystemExit(
                f"[security] api_keys 含模板默认值——拒绝启动。\n"
                f"  生成强密钥：python3 -c \"import secrets; print('zpool-'+secrets.token_urlsafe(24))\"")
        if len(k) < 16:
            raise SystemExit("[security] api_keys 存在 <16 字符的密钥，拒绝启动；"
                             "生成强密钥：python3 -c \"import secrets; print('zpool-'+secrets.token_urlsafe(24))\"")
    key = keys[0]
    listen = cfg.get("listen", "127.0.0.1:8602")
    loopback = listen.rsplit(":", 1)[0] in ("127.0.0.1", "localhost", "::1", "")
    if key.lower() in DANGEROUS_KEYS:
        raise SystemExit(
            f"[security] api_key 为空或使用了模板默认值——拒绝启动。\n"
            f"  生成强密钥：python3 -c \"import secrets; print('zpool-'+secrets.token_urlsafe(24))\"\n"
            f"  写入 {cfg_path} 的 api_key 字段后重启。")
    if len(key) < 16:
        raise SystemExit("[security] api_key 太短（<16 字符），拒绝启动；"
                         "生成强密钥：python3 -c \"import secrets; print('zpool-'+secrets.token_urlsafe(24))\"")
    if not loopback:
        log("[security] 监听非回环地址：请确保运行在可信局域网内，"
            "公网部署必须置于 TLS 反代（如 caddy/nginx）之后")
    for dev in cfg.get("devices") or []:
        dk = (dev.get("key") or "").strip()
        if not dk or len(dk) < 12:
            raise SystemExit(f"[security] 设备 {dev.get('name')} 的 key 为空或太短（<12），拒绝启动")
    st = os.stat(cfg_path)
    if st.st_mode & 0o077:
        log(f"[security] {cfg_path} 权限过宽（{oct(st.st_mode & 0o777)}）：含 API key，建议 chmod 600")
        try:
            os.chmod(cfg_path, 0o600)
            log("[security] 已自动收紧为 600")
        except OSError:
            pass
