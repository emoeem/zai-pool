#!/usr/bin/env python3
"""zai-pool v3 — Z.ai GLM 多账号自动化网关（对标 workbuddy2api 功能形态）。

上游（官方 API Key 通道，docs.z.ai 文档支持）：
    OpenAI 兼容    https://api.z.ai/api/coding/paas/v4/chat/completions
    Anthropic 兼容  https://api.z.ai/api/anthropic/v1/messages
    模型列表       https://api.z.ai/api/coding/paas/v4/models

额度自动化（billing 域，仅持有 zcode_jwt 的账号；无需签名/验证码）：
    GET  https://zcode.z.ai/api/v1/zcode-plan/billing/balance?app_version=3.16.3
    GET  https://zcode.z.ai/api/v1/zcode-plan/billing/current
    GET  .../billing/preview  +  POST .../billing/claim  {"plan_id": ...}   # 每日领取
    鉴权头：Authorization: Bearer <zcode_jwt> + x-device-mid: <device_mid>

风控对策：
    1. per-account 独立出口：proxy（http/socks5）或 sport_range（直连源端口段，
       配合 dae/honk 内核层 `dport(443) && sport(a-b) -> 组名` 分流）。
    2. sticky-first 主用号：非粘性流量固定走主用号，失败才切换（最少化切换）。
    3. 会话粘性 30min（五级键：metadata.* → conversation_id → prompt_cache_key
       → 首条 user 消息 sha256），失败解绑、成功重绑、双段分配。
    4. 冷却/熔断/降权三截止状态机（互不叠加，或门取更远）。
    5. 并发租约 max_in_flight；usage 缺失哨兵（记 "-" 不记 0）。

端点（入站）：
    POST /v1/chat/completions       OpenAI 协议（流式/非流式）
    POST /v1/messages               Anthropic 协议（流式/非流式）
    GET  /v1/models                 模型列表（经主用号上游）
    GET  /                          Web 管理面板
    GET  /status                    账号池台账 JSON（鉴权）
    GET  /metrics                   Prometheus 0.0.4（鉴权）
    POST /admin/accounts/{n}/{disable,enable,revive}   admin.enabled=true 时开放
    GET  /healthz                   健康（无需鉴权）

配置 pool.json 字段：
    listen / api_key / reset_hour=9 / strategy=sticky-first|balanced
    max_retry=4 / sticky_minutes=30
    admin:   {"enabled": false, "audit_file": "admin_audit.log"}
    alert:   {"enabled": false, "webhook_url": "", "secret": "", "min_healthy": 1,
              "interval_seconds": 30, "for_ticks": 2, "clear_ticks": 2}
    billing: {"enabled": true, "interval_minutes": 10, "claim_hour": 9}
    accounts: [{
      "name": "acct1", "api_key": "sk-...", "expires": "2026-11-22 09:00",
      "proxy": "socks5://u:p@1.2.3.4:1080",        # 与 sport_range 二选一
      "sport_range": [50001, 50032],               # 直连源端口段（honk 分流用）
      "zcode_jwt": "...", "device_mid": "...",     # billing 域自动化（可选）
      "max_in_flight": 8
    }]

子命令：
    python3 zai-pool.py --config pool.json            # 启动网关
    python3 zai-pool.py --config pool.json --probe    # 逐账号验 key + 出口 IP（零额度）
    python3 zai-pool.py --config pool.json --probe-chat  # 追加真实对话冒烟（少量额度）
    python3 zai-pool.py --config pool.json --honk-rules  # 生成 honk routing 片段
    python3 zai-pool.py --config pool.json --billing     # 手动跑一轮 billing 巡检+claim
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import random
import signal
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CST = timezone(timedelta(hours=8))
UPSTREAMS = {
    # realm -> (host, openai 前缀, anthropic 前缀)；cn = bigmodel.cn 国内通道
    "global": {"host": "api.z.ai", "openai": "/api/coding/paas/v4", "anthropic": "/api/anthropic"},
    "cn": {"host": "open.bigmodel.cn", "openai": "/api/coding/paas/v4", "anthropic": "/api/anthropic"},
}
UP_HOST = UPSTREAMS["global"]["host"]
UP_OPENAI_PATH = UPSTREAMS["global"]["openai"]
UP_ANTHROPIC_PATH = UPSTREAMS["global"]["anthropic"]
BILLING_HOST = "zcode.z.ai"
BILLING_BASE = "/api/v1/zcode-plan"
BILLING_APP_VERSION = "3.16.3"
UA = "zai-pool/3.0"
MODELS_PATH = UP_OPENAI_PATH + "/models"
PANEL_FILE = Path(__file__).resolve().parent / "zai-pool-panel.html"

_state_lock = threading.Lock()
_ssl_ctx = ssl.create_default_context()
_seq = [0]


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


# ---------- 代理隧道（v2 延续） ----------
def open_tunnel(proxy: str, host: str = UP_HOST, port: int = 443,
                timeout: int = 20, bind_port: int | None = None) -> socket.socket:
    u = urllib.parse.urlparse(proxy)
    phost, pport = u.hostname, u.port or (8080 if u.scheme in ("http", "https") else 1080)
    s = socket.socket()
    if bind_port:
        s.bind(("0.0.0.0", bind_port))
    s.settimeout(timeout)
    s.connect((phost, pport))
    creds = f"{u.username}:{u.password or ''}" if u.username else ""
    if u.scheme in ("http", "https"):
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if creds:
            req += f"Proxy-Authorization: Basic {base64.b64encode(creds.encode()).decode()}\r\n"
        s.sendall((req + "\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(4096)
            if not c:
                raise OSError("proxy closed during CONNECT")
            buf += c
        line = buf.split(b"\r\n", 1)[0].decode(errors="replace")
        if " 200" not in line:
            raise OSError(f"proxy CONNECT failed: {line}")
        return s
    if u.scheme in ("socks5", "socks5h"):
        methods = b"\x02" if creds else b"\x00"
        s.sendall(b"\x05\x01" + methods)
        r = s.recv(2)
        if r[1] == 0xFF:
            raise OSError("socks5 no acceptable auth")
        if r[1] == 0x02:
            s.sendall(b"\x01" + bytes([len(u.username)]) + u.username.encode()
                      + bytes([len(u.password or "")]) + (u.password or "").encode())
            r = s.recv(2)
            if r[1] != 0x00:
                raise OSError("socks5 auth failed")
        hb = socket.gethostbyname(host)
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(hb) + struct.pack(">H", port))
        r = s.recv(10)
        if r[1] != 0x00:
            raise OSError(f"socks5 connect failed rep={r[1] if len(r) > 1 else '?'}")
        return s
    raise OSError(f"unsupported proxy scheme: {u.scheme}")


def _bind_sport(rng: list[int] | tuple[int, int] | None) -> socket.socket | None:
    """直连路径绑定 sport_range 内随机源端口（honk sport 分流用）。"""
    if not rng:
        return None
    lo, hi = int(rng[0]), int(rng[1])
    for _ in range(8):
        s = socket.socket()
        try:
            s.bind(("0.0.0.0", random.randint(lo, hi)))
            s.settimeout(20)
            s.connect((UP_HOST, 443))
            return s
        except OSError:
            try:
                s.close()
            except OSError:
                pass
    raise OSError(f"sport_range {lo}-{hi} 全部绑定失败")


class UpstreamConn(http.client.HTTPSConnection):
    """直连或经隧道的 HTTPS 连接；sock 由调用方预建。"""

    def __init__(self, sock: socket.socket | None, timeout: int = 600):
        super().__init__(UP_HOST, timeout=timeout)
        self._preset = sock

    def connect(self):
        if self._preset is not None:
            self.sock = _ssl_ctx.wrap_socket(self._preset, server_hostname=UP_HOST)
        else:
            super().connect()


def upstream_request(a: "Account", path: str, body: bytes = b"", extra: dict | None = None,
                     method: str = "POST", host: str | None = None, timeout: int = 600):
    """proxy / sport 分流感知请求（sport 分流仅对 api.z.ai 生效）；
    host 缺省时按账号 realm 选上游（global=api.z.ai / cn=open.bigmodel.cn）。
    返回 (status, headers-dict, response)。"""
    hdrs = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": UA}
    if extra:
        hdrs.update(extra)
    host = host or UPSTREAMS.get(a.realm, UPSTREAMS["global"])["host"]
    if a.proxy:
        conn = UpstreamConn(open_tunnel(a.proxy, host=host), timeout=timeout)
    elif a.sport_range and host == UP_HOST:
        conn = UpstreamConn(_bind_sport(a.sport_range), timeout=timeout)
    else:
        conn = http.client.HTTPSConnection(host, timeout=timeout)
    try:
        conn.request(method, path, body=body if method == "POST" else None, headers=hdrs)
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp
    except Exception:
        conn.close()
        raise


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
        """billing 巡检的剩余比例；无 billing 数据返回 None（权重取中性 0.5）。"""
        b = self.billing.get("balances")
        if not b:
            return None
        tot = sum(x.get("total_units", 0) for x in b)
        rem = sum(x.get("remaining_units", 0) for x in b)
        return rem / tot if tot > 0 else 0.0

    def exhausted(self) -> bool:
        r = self.remaining_ratio()
        return r is not None and r <= 0.0


class Pool:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.accounts = [Account(a) for a in cfg["accounts"] if a.get("api_key")]
        self.devices = [Device(d) for d in (cfg.get("devices") or []) if d.get("key")]
        self.api_key = cfg.get("api_key", "")
        self.reset_hour = int(cfg.get("reset_hour", 9))
        self.strategy = cfg.get("strategy", "sticky-first")
        self.max_retry = int(cfg.get("max_retry", max(2, len(self.accounts))))
        self.sticky_min = float(cfg.get("sticky_minutes", 30))
        self.sticky: dict[str, tuple[str, float]] = {}
        self._primary: str | None = None
        self.alert_cfg = cfg.get("alert") or {}
        self.admin_cfg = cfg.get("admin") or {}
        if not self.accounts:
            raise SystemExit("pool.json 没有有效账号")

    def device_by_key(self, key: str) -> Device | None:
        for d in self.devices:
            if d.key and d.key == key:
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
        # 1) 会话粘性（五级键）
        if sticky_key:
            ent = self.sticky.get(sticky_key)
            if ent:
                name, until = ent
                if time.time() > until:
                    self.sticky.pop(sticky_key, None)
                else:
                    for a in self.accounts:
                        if a.name == name and a.available() and a.name not in exclude:
                            return a
                    self.sticky.pop(sticky_key, None)  # 失败解绑
        pool_names = set(dev.accounts) if dev and dev.accounts else None
        alive = [a for a in self.accounts
                 if a.available() and a.name not in exclude and not a.exhausted()
                 and (pool_names is None or a.name in pool_names)]
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
            # 主用号复用（设备级或池级）；失效重选
            for a in self.accounts:
                if (a.name == primary_name and a.available() and a.name not in exclude
                        and not a.exhausted()):
                    a.last_picked = now
                    return a
            # 双段分配：新会话优先未被任何会话绑定的号
            bound = {v[0] for v in self.sticky.values()}
            free = [a for a in alive if a.name not in bound]
            cand = free or alive
            picked = max(cand, key=lambda a: w.get(a.name, 1.0) + random.random() * 0.3)
            if primary_name != picked.name:
                log(f"[primary]{f' dev={dev.name}' if dev else ''} {picked.name}")
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
    """接入设备：独立 key + 账号分配子集（空 = 全池）+ 每设备记账。"""

    def __init__(self, cfg: dict):
        self.name = cfg["name"]
        self.key = (cfg.get("key") or "").strip()
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


POOL: Pool | None = None
CFG_PATH = ""
STATE_FILE = ""
AUDIT_FILE = ""
PANEL_HTML = "<html><body>panel not loaded</body></html>"


def save_state() -> None:
    if not STATE_FILE:
        return
    with _state_lock:
        data = {"saved_at": time.time(), "accounts": [], "devices": []}
        for a in POOL.accounts:
            data["accounts"].append({
                "name": a.name, "usage": a.usage,
                "cool_until": a.cool_until, "cool_reason": a.cool_reason,
                "breaker_until": a.breaker_until, "retry_count": a.retry_count,
                "manual_disabled": a.manual_disabled, "disabled": a.disabled,
                "disabled_reason": a.disabled_reason, "billing": a.billing,
            })
        for d in POOL.devices:
            data["devices"].append({"name": d.name, "usage": d.usage, "primary": d.primary})
    tmp = STATE_FILE + ".tmp"
    try:
        Path(tmp).write_text(json.dumps(data, ensure_ascii=False, indent=1))
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_FILE)
    except OSError as e:
        _save_fail(e)


_save_fails = [0]


def _save_fail(e: OSError) -> None:
    _save_fails[0] += 1
    if _save_fails[0] == 1:
        p = Path(STATE_FILE)
        log(f"[state] 写盘失败（首败详报）: {e} path={p} dir_writable={os.access(p.parent, os.W_OK)} "
            f"owner={p.parent.stat().st_uid if p.parent.exists() else '-'}")
    elif _save_fails[0] % 100 == 0:
        log(f"[state] 写盘持续失败 ×{_save_fails[0]}")


def load_state() -> None:
    if not STATE_FILE or not Path(STATE_FILE).exists():
        return
    try:
        data = json.loads(Path(STATE_FILE).read_text())
    except Exception as e:
        log(f"[state] 读取失败: {e}")
        return
    by = {x["name"]: x for x in data.get("accounts", [])}
    now = time.time()
    for a in POOL.accounts:
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
    for d in POOL.devices:
        if d.name in dev_by:
            d.usage = dev_by[d.name].get("usage", {})
            d.primary = dev_by[d.name].get("primary")


# ---------- billing 自动化 ----------
def billing_headers(a: Account) -> dict:
    h = {"Authorization": f"Bearer {a.zcode_jwt}", "User-Agent": UA}
    if a.device_mid:
        h["x-device-mid"] = a.device_mid
    return h


def billing_call(a: Account, path: str, body: dict | None = None) -> tuple[int, dict | str]:
    b = json.dumps(body).encode() if body else None
    status, _, resp = upstream_request(
        a, BILLING_BASE + path + ("?app_version=" + BILLING_APP_VERSION if path.startswith("/billing/balance") else ""),
        body=b, extra=billing_headers(a), method="POST" if body else "GET", host=BILLING_HOST, timeout=45)
    raw = resp.read().decode(errors="replace")
    try:
        return status, json.loads(raw)
    except Exception:
        return status, raw[:200]


def fetch_billing(a: Account) -> bool:
    """拉 balance+current 喂权重；返回账号是否已 active。"""
    try:
        st, bal = billing_call(a, "/billing/balance")
        if st == 200 and isinstance(bal, dict) and bal.get("code") == 0:
            a.billing["balances"] = (bal.get("data") or {}).get("balances") or []
        st2, cur = billing_call(a, "/billing/current")
        if st2 == 200 and isinstance(cur, dict) and cur.get("code") == 0:
            plans = ((cur.get("data") or {}).get("plans")) or []
            a.billing["plans"] = [{"plan_id": p.get("plan_id"), "name": p.get("name"),
                                   "ends_at": p.get("ends_at"), "status": p.get("status")} for p in plans]
    except Exception as e:
        log(f"[billing] {a.name} 巡检失败 {type(e).__name__}: {e}")
        return False
    ex = a.exhausted()
    if ex and a.cool_reason != "exhausted":
        a.cool_until = next_reset(POOL.reset_hour)
        a.cool_reason = "exhausted"
        log(f"[billing] {a.name} 额度耗尽 → 冷却至次日 {POOL.reset_hour}:00")
    elif not ex and a.cool_reason == "exhausted":
        a.cool_until = 0.0
        a.cool_reason = ""
        log(f"[billing] {a.name} 配额已恢复 → ACTIVE")
    return not ex


def claim_plan(a: Account) -> str:
    """领取当日 plan：preview 找未领取的 promo → claim。返回 ok/already/fail。"""
    try:
        st, prev = billing_call(a, "/billing/preview")
        if st != 200 or not isinstance(prev, dict) or prev.get("code") not in (0, None):
            return f"fail(preview {st})"
        plans = (prev.get("data") or {}).get("plans") or prev.get("data") or []
        today = now_cst().strftime("%m%d")
        target = None
        if isinstance(plans, list):
            for p in plans:
                pid = str(p.get("plan_id") or "")
                if "start-plan" in pid and today in pid:
                    target = pid
                    break
        if not target:
            return "already"
        st2, cl = billing_call(a, "/billing/claim", {"plan_id": target})
        if st2 == 200:
            return f"ok({target})"
        return f"fail(claim {st2} {str(cl)[:80]})"
    except Exception as e:
        return f"fail({type(e).__name__}: {e})"


LEDGER: dict = {}


def ledger_record(kind: str, result: str, trigger: str) -> None:
    day = now_cst().strftime("%Y-%m-%d")
    ent = LEDGER.setdefault(kind, {}).setdefault(day, {"total": 0, "ok": 0, "already": 0, "fail": 0, "all_failed": False})
    ent["total"] += 1
    if result.startswith("ok"):
        ent["ok"] += 1
    elif result == "already":
        ent["already"] += 1
    else:
        ent["fail"] += 1
    ent["all_failed"] = (ent["ok"] + ent["already"] == 0)


def billing_worker(stop: threading.Event) -> None:
    """巡检 + claim 排程线程（确定性 jitter，CST 日界）。"""
    bcfg = (POOL.cfg.get("billing") or {})
    if bcfg.get("enabled") is False:
        return
    interval = int(bcfg.get("interval_minutes", 10)) * 60
    claim_hour = int(bcfg.get("claim_hour", POOL.reset_hour))
    last_claim_day = None
    next_scan = time.time() + 5
    while not stop.is_set():
        now = time.time()
        if now >= next_scan:
            for a in POOL.accounts:
                if a.zcode_jwt and a.available():
                    fetch_billing(a)
                    time.sleep(random.uniform(0.5, 2.0))  # 账号间随机 delay
            save_state()
            next_scan = now + interval
        # 每日 claim（09:00 后触发一次；jitter = salt+kind+day 散列）
        day = now_cst().strftime("%Y-%m-%d")
        dt = now_cst()
        if dt.hour >= claim_hour and last_claim_day != day:
            jitter = int(hashlib.sha256(f"claim|{day}".encode()).hexdigest()[:8], 16) % 900
            if (dt.hour * 3600 + dt.minute * 60 + dt.second) >= jitter:
                results = {}
                for a in POOL.accounts:
                    if a.zcode_jwt:
                        r = claim_plan(a)
                        results[a.name] = r
                        ledger_record("claim", r, "schedule")
                        time.sleep(random.uniform(1.0, 4.0))
                last_claim_day = day
                log(f"[claim] {results}")
                save_state()
        stop.wait(5)


# ---------- 告警（三态机：OK→Pending→Firing，边沿触发+迟滞） ----------
class Alerter:
    def __init__(self, cfg: dict):
        self.enabled = bool(cfg.get("enabled"))
        self.url = cfg.get("webhook_url", "")
        self.secret = cfg.get("secret", "")
        self.min_healthy = int(cfg.get("min_healthy", 1))
        self.for_ticks = int(cfg.get("for_ticks", 2))
        self.clear_ticks = int(cfg.get("clear_ticks", 2))
        self.state = "ok"
        self.bad_ticks = 0
        self.good_ticks = 0
        self.started = time.time()

    def tick(self, healthy: int, total: int) -> None:
        if not self.enabled or not self.url:
            return
        if time.time() - self.started < 30:
            return  # StartupGrace
        bad = healthy < self.min_healthy
        if bad:
            self.bad_ticks += 1
            self.good_ticks = 0
            if self.state == "ok" and self.bad_ticks >= self.for_ticks:
                self.state = "firing"
                self._send(f"zai-pool: 健康账号数 {healthy}/{total} < {self.min_healthy}")
            elif self.state == "pending":
                pass
        else:
            self.good_ticks += 1
            self.bad_ticks = 0
            if self.state == "firing" and self.good_ticks >= self.clear_ticks:
                self.state = "ok"
                self._send(f"zai-pool: 已恢复 {healthy}/{total}")
            elif self.state in ("pending",):
                self.state = "ok"
        if self.state == "ok" and bad and self.bad_ticks < self.for_ticks:
            self.state = "pending"

    def _send(self, text: str) -> None:
        try:
            payload = json.dumps({"text": text, "ts": time.time(),
                                  "healthy": sum(1 for a in POOL.accounts if a.healthy()),
                                  "total": len(POOL.accounts)}).encode()
            req = urllib.request.Request(self.url, data=payload,
                                         headers={"Content-Type": "application/json"})
            if self.secret:
                sig = hmac.new(self.secret.encode(), payload, hashlib.sha256).hexdigest()
                req.add_header("X-ZaiPool-Signature", sig)
            urllib.request.urlopen(req, timeout=5)
            log(f"[alert] 已投递: {text}")
        except Exception as e:
            log(f"[alert] 投递失败: {e}")


ALERTER: Alerter | None = None


def alert_worker(stop: threading.Event) -> None:
    if not (ALERTER and ALERTER.enabled):
        return
    interval = int((POOL.alert_cfg or {}).get("interval_seconds", 30))
    while not stop.is_set():
        ALERTER.tick(sum(1 for a in POOL.accounts if a.healthy()), len(POOL.accounts))
        stop.wait(interval)


# ---------- 审计 ----------
def audit(action: str, target: str, result: str, client_key_fp: str, reason: str = "") -> None:
    if not AUDIT_FILE:
        return
    ent = {"ts": now_cst().isoformat(), "action": action, "target": target,
           "result": result, "key_fp": client_key_fp, "reason": reason}
    try:
        with open(AUDIT_FILE, "a") as f:
            f.write(json.dumps(ent, ensure_ascii=False) + "\n")
    except OSError as e:
        log(f"[audit] 写失败: {e}")


def key_fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


# ---------- 热重载 ----------
def config_fingerprint(path: str) -> str:
    try:
        st = os.stat(path)
        return f"{st.st_mtime_ns}:{st.st_size}"
    except OSError:
        return ""


def reload_config() -> None:
    try:
        cfg = json.loads(Path(CFG_PATH).read_text())
        new_keys = {a["name"]: a for a in cfg["accounts"] if a.get("api_key")}
        old = {a.name: a for a in POOL.accounts}
        merged = []
        for name, acfg in new_keys.items():
            if name in old and old[name].key == acfg["api_key"]:
                a = old[name]  # 保留运行态
                a.proxy = (acfg.get("proxy") or "").strip()
                a.sport_range = acfg.get("sport_range")
                a.expires = acfg.get("expires")
                a.realm = acfg.get("realm", a.realm)
            else:
                a = Account(acfg)
            merged.append(a)
        POOL.accounts = merged
        old_dev = {d.name: d for d in POOL.devices}
        merged_dev = []
        for dcfg in (cfg.get("devices") or []):
            if dcfg.get("key") and dcfg["name"] in old_dev:
                d = old_dev[dcfg["name"]]
                d.key = (dcfg.get("key") or d.key).strip()
                d.accounts = list(dcfg.get("accounts") or [])
            else:
                d = Device(dcfg)
            merged_dev.append(d)
        POOL.devices = merged_dev
        POOL.api_key = cfg.get("api_key", POOL.api_key)
        log(f"[reload] accounts={len(merged)} devices={len(merged_dev)}")
    except Exception as e:
        log(f"[reload] 失败: {e}")


def config_watcher(stop: threading.Event) -> None:
    fp = config_fingerprint(CFG_PATH)
    while not stop.is_set():
        stop.wait(5)
        cur = config_fingerprint(CFG_PATH)
        if cur != fp:
            fp = cur
            reload_config()


# ---------- Metrics ----------
def metrics_text() -> str:
    lines = []
    reasons = {}
    for a in POOL.accounts:
        for r in a.state_reasons():
            key = r.split("(")[0]
            reasons[key] = reasons.get(key, 0) + 1
    lines.append("# HELP zaipool_pool_accounts 账号状态（原因分解）")
    lines.append("# TYPE zaipool_pool_accounts gauge")
    for r, c in sorted(reasons.items()):
        lines.append(f'zaipool_pool_accounts{{state="{r}"}} {c}')
    lines.append(f'zaipool_pool_accounts_total {len(POOL.accounts)}')
    inflight = sum(a.in_flight for a in POOL.accounts)
    lines.append("# HELP zaipool_pool_in_flight 在途请求数")
    lines.append("# TYPE zaipool_pool_in_flight gauge")
    lines.append(f'zaipool_pool_in_flight {inflight}')
    lines.append("# TYPE zaipool_sticky_sessions gauge")
    lines.append(f'zaipool_sticky_sessions {len(POOL.sticky)}')
    today = now_cst().strftime("%Y-%m-%d")
    tin = sum(a.usage.get(today, {}).get("in", 0) for a in POOL.accounts)
    tout = sum(a.usage.get(today, {}).get("out", 0) for a in POOL.accounts)
    lines.append("# TYPE zaipool_tokens_in_total counter")
    lines.append(f"zaipool_tokens_in_total {tin}")
    lines.append("# TYPE zaipool_tokens_out_total counter")
    lines.append(f"zaipool_tokens_out_total {tout}")
    for kind, days in LEDGER.items():
        ent = days.get(today)
        if ent:
            lines.append(f'zaipool_task_ok{{kind="{kind}"}} {ent["ok"]}')
            lines.append(f'zaipool_task_already{{kind="{kind}"}} {ent["already"]}')
            lines.append(f'zaipool_task_fail{{kind="{kind}"}} {ent["fail"]}')
    lines.append("# HELP zaipool_device_tokens_out_total 设备当日出站 token")
    lines.append("# TYPE zaipool_device_tokens_out_total counter")
    for d in POOL.devices:
        t = d.usage.get(today, {})
        lines.append(f'zaipool_device_tokens_out_total{{device="{d.name}"}} {t.get("out", 0)}')
    return "\n".join(lines) + "\n"


# ---------- Web 面板 ----------
def load_panel() -> None:
    global PANEL_HTML
    try:
        PANEL_HTML = PANEL_FILE.read_text(encoding="utf-8")
    except OSError:
        PANEL_HTML = "<html><body><h3>zai-pool</h3><p>面板文件缺失: " + str(PANEL_FILE) + "</p></body></html>"


# ---------- HTTP Handler ----------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _authed(self) -> bool:
        if not POOL.api_key:
            return True
        h = self.headers.get("Authorization") or self.headers.get("x-api-key") or ""
        return h.replace("Bearer ", "").strip() == POOL.api_key

    def _json(self, code: int, obj: dict):
        raw = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            alive = sum(1 for a in POOL.accounts if a.healthy())
            return self._json(200 if alive else 503,
                              {"healthy": alive, "total": len(POOL.accounts),
                               "service": "zai-pool", "strategy": POOL.strategy})
        if self.path == "/":
            raw = PANEL_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if self.path == "/v1/models":
            if not self._authed():
                return self._json(401, {"error": "unauthorized"})
            for acc in POOL.accounts:
                if acc.available():
                    try:
                        status, _, resp = upstream_request(acc, MODELS_PATH, method="GET", timeout=30)
                        raw = resp.read()
                        return self._json(status, json.loads(raw) if status == 200 else {"error": raw.decode(errors="replace")[:300]})
                    except Exception as e:
                        last = str(e)
                        continue
            return self._json(502, {"error": f"no usable account for models; last={last if 'last' in dir() else '-'}"})
        if self.path == "/status":
            if not self._authed():
                return self._json(401, {"error": "unauthorized"})
            now = time.time()
            out = []
            for a in POOL.accounts:
                p = urllib.parse.urlparse(a.proxy) if a.proxy else None
                sr = a.sport_range
                out.append({
                    "name": a.name, "reasons": a.state_reasons(),
                    "in_flight": a.in_flight,
                    "exit": f"{p.scheme}://{p.hostname}:{p.port}" if p
                            else (f"sport {sr[0]}-{sr[1]}" if sr else "direct"),
                    "expires": a.expires,
                    "billing": {k: a.billing.get(k) for k in ("balances", "plans") if a.billing.get(k)},
                    "today": a.usage.get(now_cst().strftime("%Y-%m-%d"), {}),
                    "primary": a.name == POOL._primary,
                    "has_jwt": bool(a.zcode_jwt),
                })
            return self._json(200, {"accounts": out, "reset_hour": POOL.reset_hour,
                                    "strategy": POOL.strategy, "primary": POOL._primary,
                                    "sticky_sessions": len(POOL.sticky),
                                    "devices": self._devices_view()})

    def _devices_view(self) -> list[dict]:
        names = {a.name for a in POOL.accounts}
        healthy = {a.name for a in POOL.accounts if a.healthy()}
        out = []
        for d in POOL.devices:
            assigned = d.accounts or [a.name for a in POOL.accounts]
            out.append({
                "name": d.name,
                "accounts": d.accounts,
                "assigned_valid": [x for x in assigned if x in names],
                "assigned_missing": [x for x in assigned if x not in names],
                "healthy_assigned": len([x for x in assigned if x in healthy]),
                "serves_all": not d.accounts,
                "primary": d.primary,
                "today": d.usage.get(now_cst().strftime("%Y-%m-%d"), {}),
            })
        return out
        if self.path == "/metrics":
            if not self._authed():
                return self._json(401, {"error": "unauthorized"})
            raw = metrics_text().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self._json(404, {"error": "not found"})

    def _relay(self, upstream_path: str, protocol: str):
        auth = (self.headers.get("Authorization") or "").replace("Bearer ", "").strip()
        dev = POOL.device_by_key(auth) if auth else None
        if not dev and not self._authed():
            return self._json(401, {"error": "unauthorized"})
        n = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(n) if n else b"{}")
        except Exception:
            return self._json(400, {"error": "bad json"})
        body = json.dumps(req).encode()
        stream = bool(req.get("stream"))
        sk = sticky_key_of(req)
        tried: set[str] = set()
        last_err = None
        t0 = time.time()
        _seq[0] += 1
        seq = _seq[0]

        for _ in range(max(1, POOL.max_retry)):
            a = POOL.pick(sk, tried, dev=dev)
            if not a:
                break
            tried.add(a.name)
            extra = {"Authorization": f"Bearer {a.key}"} if protocol == "openai" else {"x-api-key": a.key}
            a.in_flight += 1
            try:
                try:
                    status, rh, resp = upstream_request(a, upstream_path, body, extra)
                except (OSError, http.client.HTTPException) as e:
                    POOL.note_unknown_fail(a)
                    last_err = f"{type(e).__name__}: {e}"
                    continue
                if status != 200:
                    err = resp.read()[:400].decode(errors="replace")
                    POOL.cooldown(a, status, err, rh)
                    if sk and status in (401, 403):
                        POOL.unbind(sk)
                    last_err = f"{status} {err[:120]}"
                    continue
                POOL.ok(a)
                POOL.bind(sk, a)
                ctype = rh.get("content-type", "application/json")
                if not stream:
                    raw = resp.read()
                    tin, tout = extract_usage(raw)
                    a.record(tin, tout)
                    if dev:
                        dev.record(tin, tout)
                    save_state()
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    self._reqlog(seq, req, "sync", 200, a, t0, tin, tout, dev)
                    return
                self.send_response(200)
                self.send_header("Content-Type", ctype or "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                tin = tout = None
                try:
                    while True:
                        chunk = resp.read(1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        if b'"usage"' in chunk:
                            try:
                                for line in chunk.decode(errors="ignore").splitlines():
                                    if line.startswith("data:") and '"usage"' in line:
                                        u = json.loads(line[5:].strip()).get("usage") or {}
                                        tin = int(u.get("prompt_tokens") or tin or 0)
                                        tout = int(u.get("completion_tokens") or tout or 0)
                            except Exception:
                                pass
                except (BrokenPipeError, OSError):
                    pass
                a.record(tin, tout)
                if dev:
                    dev.record(tin, tout)
                save_state()
                self._reqlog(seq, req, "stream", 200, a, t0, tin, tout, dev)
                return
            finally:
                a.in_flight -= 1
        self._json(503, {"error": {"message": f"no available account; last={last_err}",
                                   "type": "zai_pool_exhausted"}})
        log(f"| #{seq} | {req.get('model')} | {'stream' if stream else 'sync'} | 503 | - | - |"
            + (f" dev={dev.name}" if dev else ""))

    def _reqlog(self, seq: int, req: dict, mode: str, status: int, a: Account, t0: float,
                tin: int | None, tout: int | None, dev: "Device | None" = None) -> None:
        dt = time.time() - t0
        tps = f"{tout / dt:.1f}" if (tout and dt > 0) else "-"
        log(f"| #{seq} | {datetime.now().strftime('%H:%M:%S')} | {req.get('model')} | {mode} | {status} "
            f"| {a.name}{'@' + dev.name if dev else ''} | tok_in={tin if tin is not None else '-'} "
            f"tok_out={tout if tout is not None else '-'} | {tps}tok/s | {dt:.2f}s |")

    def do_POST(self):
        if self.path == "/v1/chat/completions":
            return self._relay(UP_OPENAI_PATH + "/chat/completions", "openai")
        if self.path in ("/v1/messages", "/api/anthropic/v1/messages"):
            return self._relay(UP_ANTHROPIC_PATH + "/v1/messages", "anthropic")
        m = urllib.parse.urlparse(self.path).path
        if m.startswith("/admin/accounts/") and POOL.admin_cfg.get("enabled"):
            if not self._authed():
                return self._json(401, {"error": "unauthorized"})
            parts = m.strip("/").split("/")
            name, action = parts[2], parts[3] if len(parts) > 3 else ""
            a = next((x for x in POOL.accounts if x.name == name), None)
            if not a or action not in ("disable", "enable", "revive"):
                return self._json(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length") or 0)
            reason = ""
            try:
                reason = (json.loads(self.rfile.read(n) or b"{}") or {}).get("reason", "")
            except Exception:
                pass
            if action == "disable":
                a.manual_disabled = True
                a.disabled_reason = reason
            elif action == "enable":
                a.manual_disabled = False
            elif action == "revive":
                a.disabled = False
                a.disabled_reason = ""
                a.fails = 0
                a.unknown_fails = 0
                a.cool_until = 0.0
                a.breaker_until = 0.0
                a.degrade_until = 0.0
            save_state()
            fp = key_fp(POOL.api_key or "-")
            audit(action, name, "ok", fp, reason)
            log(f"[admin] {action} {name} reason={reason}")
            return self._json(200, {"name": a.name, "manual_disabled": a.manual_disabled,
                                    "disabled": a.disabled, "healthy": a.healthy()})
        if m.startswith("/admin/devices/") and POOL.admin_cfg.get("enabled"):
            if not self._authed():
                return self._json(401, {"error": "unauthorized"})
            parts = m.strip("/").split("/")
            name, action = parts[2], parts[3] if len(parts) > 3 else ""
            d = POOL.device_by_name(name)
            if not d or action != "assign":
                return self._json(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length") or 0)
            try:
                new_accounts = json.loads(self.rfile.read(n) or b"{}").get("accounts")
            except Exception:
                return self._json(400, {"error": "bad json"})
            if not isinstance(new_accounts, list):
                return self._json(400, {"error": "accounts 必须是数组（空数组=全池）"})
            valid = {a.name for a in POOL.accounts}
            missing = [x for x in new_accounts if x not in valid]
            if missing:
                return self._json(400, {"error": f"未知账号: {missing}"})
            old = d.accounts
            d.accounts = [str(x) for x in new_accounts]
            d.primary = None  # 子集变了，重选主用号
            save_state()
            audit("assign", name, "ok", key_fp(POOL.api_key or "-"),
                  f"{old} -> {d.accounts}")
            log(f"[admin] assign dev={name} accounts={d.accounts}")
            return self._json(200, {"name": d.name, "accounts": d.accounts,
                                    "primary": d.primary})
        self._json(404, {"error": "not found"})


def sticky_key_of(body: dict) -> str:
    md = body.get("metadata") or {}
    for k in ("conversation_id", "conversationId"):
        if md.get(k):
            return str(md[k])
    if body.get("conversation_id"):
        return str(body["conversation_id"])
    if body.get("prompt_cache_key"):
        return str(body["prompt_cache_key"])
    for m in body.get("messages", []):
        if m.get("role") == "user":
            c = m.get("content")
            if isinstance(c, str) and c.strip():
                return "h:" + hashlib.sha256(c.encode()).hexdigest()[:16]
            if isinstance(c, list):
                txt = " ".join(x.get("text", "") for x in c if isinstance(x, dict))
                if txt.strip():
                    return "h:" + hashlib.sha256(txt.encode()).hexdigest()[:16]
    return ""


def extract_usage(raw: bytes) -> tuple[int | None, int | None]:
    try:
        u = json.loads(raw).get("usage") or {}
        return (int(u["prompt_tokens"]) if u.get("prompt_tokens") is not None else None,
                int(u["completion_tokens"]) if u.get("completion_tokens") is not None else None)
    except Exception:
        return None, None


# ---------- probe ----------
def run_probe(chat: bool) -> int:
    rc = 0
    for a in POOL.accounts:
        tag = f"{a.name:<10}"
        exit_ip = "-"
        try:
            st, _, resp = upstream_request(a, MODELS_PATH, method="GET", timeout=30)
            raw = resp.read()
            if st == 200:
                ids = [m.get("id") for m in (json.loads(raw).get("data") or [])][:6]
                print(f"{tag} KEY-OK    models={ids}")
                if chat:
                    s3, _, r3 = upstream_request(
                        a, UP_OPENAI_PATH + "/chat/completions",
                        json.dumps({"model": "glm-5.3-flash",
                                    "messages": [{"role": "user", "content": "只回复OK"}],
                                    "max_tokens": 16, "stream": False}).encode())
                    b3 = r3.read()
                    ok = s3 == 200
                    print(f"{tag} CHAT-{'OK' if ok else 'FAIL'}  [{s3}] {b3[:150].decode(errors='replace')}")
                    rc |= 0 if ok else 1
            else:
                print(f"{tag} KEY-FAIL  [{st}] {raw[:200].decode(errors='replace')}")
                rc = 1
        except Exception as e:
            print(f"{tag} PROXY/NET-FAIL {type(e).__name__}: {e}")
            rc = 1
    return rc


def probe_exit_ips() -> None:
    """经各账号出口访问 ipify 回显实际出口 IP（验证分流命中）。"""
    for a in POOL.accounts:
        tag = f"{a.name:<10}"
        try:
            if a.proxy:
                t = open_tunnel(a.proxy, host="api.ipify.org", port=80)
                t.sendall(b"GET /?format=json HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
                raw = b""
                while True:
                    c = t.recv(4096)
                    if not c:
                        break
                    raw += c
                body = raw.split(b"\r\n\r\n", 1)[-1]
                print(f"{tag} exit_ip={body.decode(errors='replace').strip()[:80]}")
            elif a.sport_range:
                print(f"{tag} exit_ip=(sport 分流，由 honk 决定，直连探测无意义)")
            else:
                import urllib.request
                ip = urllib.request.urlopen("https://api.ipify.org?format=json", timeout=10).read().decode()
                print(f"{tag} exit_ip={ip.strip()[:80]} (direct)")
        except Exception as e:
            print(f"{tag} exit_ip=FAIL {type(e).__name__}: {e}")


# ---------- honk 规则生成 ----------
def honk_rules(cfg: dict) -> str:
    lines = [
        "# zai-pool honk routing 片段（自动生成 by zai-pool --honk-rules）",
        "# honk 方言：无 ||、无 fallthrough、routing 目标必须是组名。",
        "# 用法：root 备份 /etc/honk/config.dae 后，把 node/group 段并入对应位置，",
        "#       routing 规则插在 fallback 之前，然后 systemctl restart honk-core。",
        "",
        "node {"]
    for a in POOL.accounts:
        if a.sport_range and not a.proxy:
            lines.append(f"  out-{a.name}: 'socks5://<出口IP-给{a.name}>:1080'   # 占位：填该账号专用出口节点")
    lines.append("}")
    lines.append("group {")
    for a in POOL.accounts:
        if a.sport_range and not a.proxy:
            lines.append(f"  zai-{a.name} {{ policy: fixed(0); filter: name(out-{a.name}) }}")
    lines.append("}")
    lines.append("routing {")
    for a in POOL.accounts:
        if a.sport_range and not a.proxy:
            lo, hi = int(a.sport_range[0]), int(a.sport_range[1])
            lines.append(f"  dport(443) && sport({lo}-{hi}) -> zai-{a.name}")
    lines.append("  # ↑ 插到现有 fallback 之前；下方 fallback 保持现有默认组")
    lines.append("}")
    return "\n".join(lines) + "\n"


# ---------- main ----------
STOP = threading.Event()


def main() -> int:
    global POOL, CFG_PATH, STATE_FILE, AUDIT_FILE, ALERTER
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.environ.get("ZPOOL_CONFIG", "pool.json"))
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--probe-chat", action="store_true")
    ap.add_argument("--probe-ip", action="store_true", help="仅出口 IP 校验")
    ap.add_argument("--honk-rules", action="store_true")
    ap.add_argument("--billing", action="store_true", help="手动跑一轮 billing 巡检+claim")
    a = ap.parse_args()
    CFG_PATH = a.config
    cfg = json.loads(Path(CFG_PATH).read_text())
    POOL = Pool(cfg)
    STATE_FILE = str(Path(CFG_PATH).with_name("pool-state.json"))
    load_state()
    if a.probe or a.probe_chat:
        rc = run_probe(a.probe_chat)
        probe_exit_ips()
        return rc
    if a.probe_ip:
        probe_exit_ips()
        return 0
    if a.honk_rules:
        out = Path(CFG_PATH).with_name("honk-rules.dae")
        out.write_text(honk_rules(cfg))
        print(f"[honk-rules] 已生成 {out}\n\n{honk_rules(cfg)}")
        return 0
    if a.billing:
        for acc in POOL.accounts:
            if acc.zcode_jwt:
                fetch_billing(acc)
                print(f"{acc.name}: claim={claim_plan(acc)}")
            else:
                print(f"{acc.name}: (无 zcode_jwt，跳过)")
        return 0

    AUDIT_FILE = str(Path(CFG_PATH).with_name(POOL.admin_cfg.get("audit_file", "admin_audit.log")))
    if POOL.admin_cfg.get("enabled"):
        try:
            with open(AUDIT_FILE, "a"):
                pass  # 启动写探测 fail-fast
        except OSError as e:
            raise SystemExit(f"[audit] 审计文件不可写: {e}")
    ALERTER = Alerter(POOL.alert_cfg)
    load_panel()

    host, _, port = cfg.get("listen", "0.0.0.0:8602").rpartition(":")
    srv = ThreadingHTTPServer((host or "0.0.0.0", int(port)), Handler)
    srv.daemon_threads = False

    def _term(signum, frame):
        log(f"[shutdown] signal={signum} → flush + shutdown(5s)")
        save_state()
        threading.Thread(target=srv.shutdown, daemon=True).start()

    def _hup(signum, frame):
        log("[reload] SIGHUP → 热重载配置")
        reload_config()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    try:
        signal.signal(signal.SIGHUP, _hup)
    except (AttributeError, ValueError):
        pass

    threads = [
        threading.Thread(target=billing_worker, args=(STOP,), daemon=True, name="billing"),
        threading.Thread(target=alert_worker, args=(STOP,), daemon=True, name="alert"),
        threading.Thread(target=config_watcher, args=(STOP,), daemon=True, name="watch"),
    ]
    for t in threads:
        t.start()

    sport_conflict = [a.name for a in POOL.accounts if a.sport_range and a.proxy]
    if sport_conflict:
        log(f"[warn] 以下账号同时填了 proxy 与 sport_range，proxy 优先生效: {sport_conflict}")
    log(f"zai-pool v3 up on {host or '0.0.0.0'}:{port} accounts={len(POOL.accounts)} "
        f"strategy={POOL.strategy} reset={POOL.reset_hour}:00 CST "
        f"billing={'on' if POOL.cfg.get('billing', {}).get('enabled', True) else 'off'} "
        f"admin={'on' if POOL.admin_cfg.get('enabled') else 'off'} "
        f"alert={'on' if ALERTER.enabled else 'off'}")
    for acc in POOL.accounts:
        p = urllib.parse.urlparse(acc.proxy) if acc.proxy else None
        log(f"  - {acc.name}[{acc.realm}] expires={acc.expires or '-'} "
            f"exit={p.hostname + ':' + str(p.port) if p else (('sport ' + str(acc.sport_range)) if acc.sport_range else 'direct')} "
            f"jwt={'yes' if acc.zcode_jwt else 'no'}")
    for d in POOL.devices:
        log(f"  dev {d.name} accounts={d.accounts or '(全池)'}")
    try:
        srv.serve_forever()
        STOP.set()
        save_state()
        log("[shutdown] done")
    except KeyboardInterrupt:
        STOP.set()
        save_state()
    return 0


if __name__ == "__main__":
    sys.exit(main())
