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
    billing: {"enabled": true, "interval_minutes": 10, "auto_claim": false,
             "claim_days": "1-5", "claim_hour": 19, "claim_minute": 10}  # 领取窗口=周一~五 19:10 CST
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
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from billing import BillingAdapter            # noqa: E402  Phase5 独立化
from billing.policy import exhausted as _bal_exhausted, token_ratio as _bal_ratio
from billing.tracker import BillingLedger     # noqa: E402
# ==== Phase6 core 域搬移（try2）：单一所有权在 zai_pool/core.py，re-import 保证下游引用不变 ====
# UPSTREAMS 族与 MAX_BODY_BYTES 属 re-export：upstream/http 域引用保持可用
from zai_pool.upstream import (UA, _bind_sport, _recv_exact, _ssl_ctx, derive_device_ids,  # noqa: E402
                           jwt_chat_request, MODEL_NAME_MAP, normalize_jwt_body, oauth_cli_init,
                           oauth_cli_poll, oauth_exchange_api_key, open_tunnel, set_pool_getter,
                           upstream_request, UpstreamConn, zcode_profile_system)
from zai_pool.captcha import CAPTCHA, init_captcha  # noqa: E402  captcha 管理器（Phase9 移植）
from zai_pool.core import (  # noqa: E402  core 域节点搬移，re-export 回流
    CST, DEFAULT_SERVER, DANGEROUS_KEYS, MAX_BODY_BYTES, SSEUsageParser, TokenBucket,
    UPSTREAMS, UP_ANTHROPIC_PATH, UP_HOST, UP_OPENAI_PATH,
    Account, Device, Pool, _derive_chat_mode, _expires_ts, _jwt_payload, _sched_lock,
    _state_lock, jwt_exp,
    log, next_reset, now_cst, validate_security,
)
# ==== 共享常量区（单一所有权：core 域常量已迁 zai_pool/core.py，经下方 re-import 回流） ====
# 单一所有权：每个常量只有一个归属域，他域只读引用、不得在域内复制定义。
# billing 域：zcode-plan 出站 host（运行副本在 billing/client.py:12，Phase6 收敛为单一来源）
BILLING_HOST = "zcode.z.ai"
# billing 域：zcode-plan API 基路径（运行副本在 billing/client.py:13）
BILLING_BASE = "/api/v1/zcode-plan"
# billing 域：billing 出站 app_version（运行副本在 billing/client.py:14；本文件内无引用，原散落在 BoundedServer 之后）
BILLING_APP_VERSION = "3.16.3"
# http 域：_relay 错误分类使用（Phase6 随 http 域迁移）
# 换号也无益的客户端错误：原样透传，不进入冷却/熔断状态机
PASS_THROUGH_STATUS = {400, 404, 405, 413, 422}
# http 域：captcha 失效判定（借鉴 zcode2api gateway._try_account 关键词法）
CAPTCHA_ERR_MARKS = ("captcha", "3012", "verify")
MAX_CAPTCHA_RETRIES = 3


def _captcha_err(err_text: str) -> bool:
    """上游 401/403 是否为 captcha 验证失败（verify_param 过期/3012）：非账号问题，不冷却。"""
    low = (err_text or "").lower()
    return any(m in low for m in CAPTCHA_ERR_MARKS)


# http 域：有界 HTTP 服务器（连接/SSE 配额，main 装配，Phase6 随 http 迁移）
class BoundedServer(ThreadingHTTPServer):
    """4.1 有界服务器：活跃连接上限 + listen backlog 可配。超限立即 503，不建线程。"""

    daemon_threads = True

    def __init__(self, addr, handler, server_cfg: dict):
        self.max_connections = int(server_cfg.get("max_connections", 100))
        self.request_queue_size = int(server_cfg.get("max_queued_requests", 50))
        self.max_sse_connections = int(server_cfg.get("max_sse_connections", 30))
        self._conn_lock = threading.Lock()
        self.active = 0
        self.sse_active = 0
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        with self._conn_lock:
            self.active += 1
        if self.active > self.max_connections:
            with self._conn_lock:
                self.active -= 1
            body = b'{"error":{"message":"connection limit exceeded"}}\n'
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                b"Content-Type: application/json\r\nConnection: close\r\n"
                                + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._conn_lock:
                self.active -= 1
# upstream 域：上游请求 UA
# core 域：UPSTREAMS 族派生——模型列表路径（http /v1/models 与 entry --probe 读用）
MODELS_PATH = UP_OPENAI_PATH + "/models"
# http 域：Web 面板静态文件路径
PANEL_FILE = Path(__file__).resolve().parent / "zai-pool-panel.html"

# ---- 模块级运行态（跨域共享锁/上下文；Phase6 拆包归属：_state_lock/_sched_lock→core、_persist_lock→storage（下方随 storage 域 re-export 回流）、_ssl_ctx→upstream、_seq→http） ----
_seq = [0]


# ==== domain: upstream ====
# ---------- 代理隧道 ----------










# ==== domain: core（调度/状态机） ====


# ---- 模块级全局句柄（main 装配；Phase6 拆包归属：POOL→core 运行态、STATE_FILE→storage、AUDIT_FILE→observability、PANEL_HTML→http、CFG_PATH→entry 装配） ----
POOL: Pool | None = None
set_pool_getter(lambda: POOL)  # Phase6 upstream 域注入（延迟读全局，测试赋值 mod.POOL 即生效）
CFG_PATH = ""
STATE_FILE = ""
AUDIT_FILE = ""
# http 域：JWT OAuth 登录流程（Phase9 移植 zcode2api ZaiAuthFlow；poll_token 只存服务端）
_JWT_LOGIN_FLOWS: dict[str, tuple[str, float, str]] = {}
_JWT_LOGIN_FLOW_TTL = 600
PANEL_HTML = "<html><body>panel not loaded</body></html>"
# ==== Phase6 storage 域搬移（try2）：单一所有权在 zai_pool/storage.py，本文件 re-export/薄包装回流，relay/admin 调用点零改动 ====
# 句柄注入（原全局变量赋值处）：getter 延迟求值——main 与测试对 POOL/STATE_FILE/AUDIT_FILE 的
# 直接赋值即时生效（测试直接写 mod.STATE_FILE 不经 init_storage，靠 getter 每次读最新值）；
# init 同时复位 storage 落盘运行态（_STATE_READONLY/_save_fails/_RO_LAST_LOG 原为 zai-pool
# 模块级全局：逐模块加载即全新，storage 单例化后由 init 复位保持等价）。
from zai_pool import storage as _storage  # noqa: E402  storage 域单一所有权
_storage.init_storage(lambda: POOL, lambda: STATE_FILE, lambda: AUDIT_FILE)
from zai_pool.storage import (  # noqa: E402  storage 域节点搬移，re-export 回流
    _persist_lock, _RO_LAST_LOG, _save_fails, audit, key_fp, save_state,
)
_STATE_READONLY = _storage._STATE_READONLY  # 只读标志初始对齐；load_state 薄包装负责回同步


# ==== domain: storage ====
# save_state/_save_fail/_save_fail_throttled/_save_fails/_RO_LAST_LOG/_persist_lock/audit/key_fp
# 已迁 zai_pool/storage.py（上方 re-export 回流；relay/admin/billing/main 调用点零改动）。
def load_state() -> None:
    """薄包装：委托 zai_pool.storage.load_state；_STATE_READONLY 是 bool（不可变对象），
    storage 内部改写无法经 re-import 传导，须显式回流本模块全局。"""
    _storage.load_state()
    global _STATE_READONLY
    _STATE_READONLY = _storage._STATE_READONLY


# ==== domain: billing ====
# ---------- billing 自动化（Phase5：走 billing/ 独立子系统） ----------
_billing_adapter: BillingAdapter | None = None


def set_billing_adapter(ad: BillingAdapter) -> None:
    global _billing_adapter
    _billing_adapter = ad


def get_billing_adapter() -> BillingAdapter:
    global _billing_adapter
    if _billing_adapter is None:
        bcfg = POOL.cfg.get("billing") or {}
        _billing_adapter = BillingAdapter(
            transport=upstream_request,
            ledger=BillingLedger(Path(CFG_PATH).with_name("billing-ledger.jsonl")),
            claim_hour=int(bcfg.get("claim_hour", 19)),
            auto_claim=bool(bcfg.get("auto_claim", False)))  # 默认关闭（计划书 5.4）
    return _billing_adapter


def fetch_billing(a: Account) -> bool:
    """巡检（只读）：失败隔离，不影响 API 转发；额度结果喂权重与自动恢复。"""
    try:
        a.billing = get_billing_adapter().inspect(a)
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
    """领取状态机入口；返回 ok/already/fail 摘要（账本由 adapter 落盘）。"""
    try:
        oc = get_billing_adapter().claim_flow(a, trigger="manual")
        tag = {"success": "ok", "already": "already", "unverified": "ok(unverified)"}.get(oc.status, "fail")
        return f"{tag}({oc.plan_id} {oc.detail})" if oc.plan_id else f"{tag}({oc.detail})"
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


def parse_claim_days(spec: str) -> set[int]:
    """claim_days 解析："1-5"=周一~周五，"1,3,5"=离散，"0-6"=每天。
    1=周一 … 7=周日（ISO 口径）。空/非法 → 全周。"""
    days: set[int] = set()
    try:
        for part in str(spec or "").split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo, hi = part.split("-", 1)
                lo_i, hi_i = int(lo), int(hi)
            elif part == "*":
                days |= set(range(1, 8))
                continue
            else:
                lo_i = hi_i = int(part)
            if not (1 <= lo_i <= 7 and 1 <= hi_i <= 7):
                continue
            days |= set(range(min(lo_i, hi_i), max(lo_i, hi_i) + 1))
    except ValueError:
        return set(range(1, 8))
    return days or set(range(1, 8))


def _claim_window_due(dt, claim_days: set[int], claim_hour: int, claim_minute: int) -> bool:
    """领取窗口判定（纯函数）：CST 星期在 claim_days 内且到达 claim_hour:claim_minute。"""
    return (dt.isoweekday() in claim_days
            and (dt.hour, dt.minute) >= (claim_hour, claim_minute))


def billing_worker(stop: threading.Event) -> None:
    """巡检 + claim 排程线程（CST；领取窗口可配：默认周一~周五 19:10 后）。"""
    bcfg = (POOL.cfg.get("billing") or {})
    if bcfg.get("enabled") is False:
        return
    interval = int(bcfg.get("interval_minutes", 10)) * 60
    claim_days = parse_claim_days(bcfg.get("claim_days", "1-5"))
    claim_hour = int(bcfg.get("claim_hour", 19))
    claim_minute = int(bcfg.get("claim_minute", 10))
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
        # 领取窗口：claim_days 内的 claim_hour:claim_minute 后触发一次/日（CST）
        # auto_claim 门控：关闭时 worker 完全不触领取路径；账本幂等防重复
        auto = bool((POOL.cfg.get("billing") or {}).get("auto_claim", False))
        day = now_cst().strftime("%Y-%m-%d")
        dt = now_cst()
        if (auto and last_claim_day != day
                and _claim_window_due(dt, claim_days, claim_hour, claim_minute)):
            results = {}
            for a in POOL.accounts:
                if a.zcode_jwt:
                    r = claim_plan(a)
                    results[a.name] = r
                    ledger_record("claim", r, "schedule")
                    time.sleep(random.uniform(1.0, 4.0))
            last_claim_day = day
            log(f"[claim] 窗口={claim_days} {claim_hour:02d}:{claim_minute:02d} → {results}")
            save_state()
        stop.wait(5)


# ==== domain: observability ====
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
            # ok/pending 都可进入 firing：连续 for_ticks 次坏 tick 即触发（边沿触发只发一次）
            if self.state in ("ok", "pending") and self.bad_ticks >= self.for_ticks:
                self.state = "firing"
                self._send(f"zai-pool: 健康账号数 {healthy}/{total} < {self.min_healthy}")
            elif self.state == "ok":
                self.state = "pending"
        else:
            self.good_ticks += 1
            self.bad_ticks = 0
            if self.state == "firing" and self.good_ticks >= self.clear_ticks:
                self.state = "ok"
                self._send(f"zai-pool: 已恢复 {healthy}/{total}")
            elif self.state == "pending" and self.good_ticks >= self.clear_ticks:
                self.state = "ok"

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
# audit/key_fp 已迁 zai_pool/storage.py（上方 re-export 回流；admin 调用点零改动）


# （core 域：热重载直接改写 Pool/Account/Device 运行态，Phase6 随 core 迁移）
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
        new_keys = {a["name"]: a for a in cfg["accounts"]
                    if a.get("api_key") or a.get("zcode_jwt")}
        old = {a.name: a for a in POOL.accounts}
        merged = []
        for name, acfg in new_keys.items():
            if name in old and old[name].key == (acfg.get("api_key") or ""):
                a = old[name]  # 保留运行态，但全部可热更字段同步
                a.proxy = (acfg.get("proxy") or "").strip()
                a.sport_range = acfg.get("sport_range")
                a.expires = acfg.get("expires")
                a.realm = acfg.get("realm", a.realm)
                a.zcode_jwt = (acfg.get("zcode_jwt") or "").strip()
                a.device_mid = ((acfg.get("device_mid") or "").strip()
                                or (derive_device_ids(a.zcode_jwt)[0] if a.zcode_jwt else ""))
                a.chat_via, a.chat_capable = _derive_chat_mode(acfg)  # 通道归属热更（billing-only ↔ jwt）
                a.jwt_exp = jwt_exp(a.zcode_jwt) if a.zcode_jwt else 0
                a.max_in_flight = int(acfg.get("max_in_flight", a.max_in_flight))
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
            POOL.prune_sticky_for(d)
            merged_dev.append(d)
        POOL.devices = merged_dev
        # 池级字段整体同步
        POOL.api_key = cfg.get("api_key", POOL.api_key)
        keys = cfg.get("api_keys") or [cfg.get("api_key") or ""]
        POOL.api_keys = {str(k).strip() for k in keys if str(k).strip()}
        POOL.cfg = cfg
        POOL.strategy = cfg.get("strategy", POOL.strategy)
        POOL.max_retry = int(cfg.get("max_retry", POOL.max_retry))
        POOL.reset_hour = int(cfg.get("reset_hour", POOL.reset_hour))
        POOL.sticky_min = float(cfg.get("sticky_minutes", POOL.sticky_min))
        POOL.alert_cfg = cfg.get("alert") or POOL.alert_cfg
        POOL.admin_cfg = cfg.get("admin") or POOL.admin_cfg
        if ALERTER and cfg.get("alert"):
            ALERTER.__init__(cfg["alert"])  # 告警配置热更
        log(f"[reload] accounts={len(merged)} devices={len(merged_dev)} "
            f"strategy={POOL.strategy} reset={POOL.reset_hour}")
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
    lines.append("# HELP zaipool_billing_usage_present 账号 /usage 实时用量在巡检结果中存在")
    lines.append("# TYPE zaipool_billing_usage_present gauge")
    for a in POOL.accounts:
        if a.billing.get("usage") is not None:
            lines.append(f'zaipool_billing_usage_present{{account="{a.name}"}} 1')
    lines.append("# HELP zaipool_sched_sticky_hits_total 粘性命中")
    lines.append("# TYPE zaipool_sched_sticky_hits_total counter")
    lines.append(f'zaipool_sched_sticky_hits_total {POOL.sched["sticky_hits"]}')
    lines.append("# TYPE zaipool_sched_sticky_unbind_total 粘性解绑（失败/过期）")
    lines.append("# TYPE zaipool_sched_sticky_unbind_total counter")
    lines.append(f'zaipool_sched_sticky_unbind_total {POOL.sched["sticky_unbind"]}')
    lines.append("# TYPE zaipool_sched_primary_switches_total 主用号切换")
    lines.append("# TYPE zaipool_sched_primary_switches_total counter")
    lines.append(f'zaipool_sched_primary_switches_total {POOL.sched["primary_switches"]}')
    lines.append("# TYPE zaipool_sched_switch_reasons_total 切号原因计数")
    lines.append("# TYPE zaipool_sched_switch_reasons_total counter")
    for r, c in sorted(POOL.sched["switch_reasons"].items()):
        lines.append(f'zaipool_sched_switch_reasons_total{{reason="{r}"}} {c}')
    lines.append("# TYPE zaipool_account_requests_total counter")
    for a in POOL.accounts:
        lines.append(f'zaipool_account_requests_total{{account="{a.name}",result="ok"}} {a.stats["ok"]}')
        lines.append(f'zaipool_account_requests_total{{account="{a.name}",result="fail"}} {a.stats["fail"]}')
    return "\n".join(lines) + "\n"


# ==== domain: http ====
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
    timeout = 600  # 客户端连接空闲上限（SSE 兼容：读超时足够宽）

    def log_message(self, *a):
        pass

    def _authed(self) -> bool:
        if not POOL.api_keys:
            return True
        h = self.headers.get("Authorization") or self.headers.get("x-api-key") or ""
        return h.replace("Bearer ", "").strip() in POOL.api_keys

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
            auth = (self.headers.get("Authorization") or "").replace("Bearer ", "").strip()
            dev = POOL.device_by_key(auth) if auth else None
            if not dev and not self._authed():
                return self._json(401, {"error": "unauthorized"})
            # JWT-only 池（免费套餐无 API Key）：本地公布模型清单，不走上游代理
            if not any(a.chat_via == "apikey" and a.key for a in POOL.accounts):
                names = sorted(set(MODEL_NAME_MAP.values()))
                return self._json(200, {"data": [{"type": "model", "id": m, "display_name": m}
                                                 for m in names]})
            last = "-"
            for _ in range(max(1, POOL.max_retry)):
                with _sched_lock:
                    acc = POOL.pick("", set(), dev=dev, jwt_ok=False)  # models 代理仅 apikey 通道
                    if acc:
                        acc.in_flight += 1
                if not acc:
                    break
                try:
                    status, _, resp = upstream_request(acc, MODELS_PATH, method="GET", timeout=30)
                    raw = resp.read()
                    if status == 200:
                        return self._json(status, json.loads(raw))
                    last = f"{status} {raw[:100].decode(errors='replace')}"
                    if status in (401, 403, 429) or status >= 500:
                        POOL.cooldown(acc, status, last)
                except (OSError, http.client.HTTPException) as e:
                    last = str(e)
                finally:
                    acc.in_flight -= 1
            return self._json(502, {"error": f"no usable account for models; last={last}"})
        if self.path.startswith("/admin/jwt/login_poll/") and POOL.admin_cfg.get("enabled"):
            if not self._authed():
                return self._json(401, {"error": "unauthorized"})
            if not POOL.admin_bucket.allow():
                return self._json(429, {"error": {"message": "admin rate limit exceeded",
                                                  "type": "admin_rate_limited"}})
            return self._jwt_login_poll(self.path.rstrip("/").rsplit("/", 1)[-1])
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
                    "stats": a.stats,
                    "exit": f"{p.scheme}://{p.hostname}:{p.port}" if p
                            else (f"sport {sr[0]}-{sr[1]}" if sr else "direct"),
                    "expires": a.expires,
                    "billing": {k: a.billing.get(k) for k in ("balances", "plans", "usage")
                                if a.billing.get(k)},
                    "today": a.usage.get(now_cst().strftime("%Y-%m-%d"), {}),
                    "primary": a.name == POOL._primary,
                    "has_jwt": bool(a.zcode_jwt),
                    "chat_via": a.chat_via,
                })
            return self._json(200, {"accounts": out, "reset_hour": POOL.reset_hour,
                                    "strategy": POOL.strategy, "primary": POOL._primary,
                                    "sticky_sessions": len(POOL.sticky),
                                    "sched": dict(POOL.sched),
                                    "devices": self._devices_view()})
        if self.path == "/billing/ledger":
            if not self._authed():
                return self._json(401, {"error": "unauthorized"})
            lp = Path(CFG_PATH).with_name("billing-ledger.jsonl")
            rows = []
            if lp.exists():
                for ln in lp.read_text().splitlines()[-50:]:
                    try:
                        rows.append(json.loads(ln))
                    except Exception:
                        pass
            return self._json(200, {"entries": rows})
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
        self._json(404, {"error": "not found"})

    def _jwt_login_poll(self, fid: str):
        """OAuth 轮询（GET/POST /admin/jwt/login_poll/{flow_id}）：ready → 账号入池。"""
        ent = _JWT_LOGIN_FLOWS.get(fid)
        if not fid or not ent:
            return self._json(404, {"error": "flow 不存在（先 POST /admin/jwt/login_start）"})
        poll_token, started, custom_name = ent
        if time.time() - started > _JWT_LOGIN_FLOW_TTL:
            _JWT_LOGIN_FLOWS.pop(fid, None)
            return self._json(410, {"error": "flow 已超时，重新 login_start"})
        try:
            data = oauth_cli_poll(fid, poll_token)
        except Exception as e:
            return self._json(502, {"error": f"poll 失败: {type(e).__name__}: {e}"})
        status = data.get("status")
        if status != "ready":
            if status == "failed":
                _JWT_LOGIN_FLOWS.pop(fid, None)
            return self._json(200, {"status": status or "pending"})
        _JWT_LOGIN_FLOWS.pop(fid, None)
        zcode_jwt = (data.get("token") or "").strip()
        if not zcode_jwt:
            return self._json(502, {"error": "ready 但缺 token 段", "data_keys": sorted(data.keys())})
        uid = str(_jwt_payload(zcode_jwt).get("user_id") or fid[:8])
        acc_name = custom_name or f"zcode-{uid[:8]}"
        api_key = ""
        access_token = ((data.get("zai") or {}).get("access_token") or "")
        if access_token:
            try:
                api_key = oauth_exchange_api_key(access_token)
            except Exception as e:
                log(f"[oauth] API key 兑换失败（仅入 JWT）: {type(e).__name__}: {e}")
        entry = {"name": acc_name, "zcode_jwt": zcode_jwt, "chat_via": "jwt", "realm": "global"}
        if api_key:
            entry["api_key"] = api_key  # 备用通道凭据；chat_via=jwt 优先走 zcode-plan 权益
        try:
            cfg = json.loads(Path(CFG_PATH).read_text())
            if any(x.get("name") == acc_name for x in cfg.get("accounts") or []):
                return self._json(200, {"status": "exists", "name": acc_name})
            cfg["accounts"] = list(cfg.get("accounts") or []) + [entry]
            Path(CFG_PATH).write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
            os.chmod(CFG_PATH, 0o600)
        except OSError as e:
            return self._json(500, {"error": f"pool.json 写回失败: {e}"})
        reload_config()
        audit("jwt_login", acc_name, "ok", key_fp(sorted(POOL.api_keys)[0]),
              f"api_key={'yes' if api_key else 'no'}")
        log(f"[oauth] {acc_name} 入池（api_key={'yes' if api_key else 'no'}）")
        return self._json(200, {"status": "ok", "name": acc_name, "api_key": bool(api_key)})

    def _relay(self, upstream_path: str, protocol: str):
        auth = (self.headers.get("Authorization") or "").replace("Bearer ", "").strip()
        dev = POOL.device_by_key(auth) if auth else None
        if not dev and not self._authed():
            return self._json(401, {"error": "unauthorized"})
        if dev and dev.disabled:
            return self._json(403, {"error": {"message": "device disabled",
                                              "type": "device_disabled"}})
        # 4.4 本地限流：超限 429，不触碰上游账号状态机
        if not POOL.allow_request(dev):
            return self._json(429, {"error": {"message": "local rate limit exceeded",
                                              "type": "rate_limited_local"}})
        n = int(self.headers.get("Content-Length") or 0)
        max_body = int(POOL.server_cfg.get("max_body_bytes", MAX_BODY_BYTES))
        if n > max_body:
            return self._json(413, {"error": f"body too large: {n} > {max_body}"})
        try:
            req = json.loads(self.rfile.read(n) if n else b"{}")
        except Exception:
            return self._json(400, {"error": "bad json"})
        body = json.dumps(req).encode()
        stream = bool(req.get("stream"))
        # 4.1 SSE 独立配额：占满即明确拒绝，不让长连接耗尽普通请求资源
        srv = self.server
        has_sse_quota = hasattr(srv, "sse_active")
        if (stream and has_sse_quota
                and srv.sse_active >= srv.max_sse_connections):
            return self._json(503, {"error": {"message": "sse connection limit exceeded",
                                              "type": "sse_limit_exceeded"}})
        sk = POOL.device_sticky_key(dev, sticky_key_of(req))
        tried: set[str] = set()
        last_err = None
        t0 = time.time()
        _seq[0] += 1
        seq = _seq[0]
        sse_entered = False  # SSE 配额跨 attempt 释放标志
        jwt_ok = protocol == "anthropic"  # zcode-plan 端点仅 Anthropic 协议；OpenAI 请求只用 apikey 号
        cap_retries = 0

        for _ in range(max(1, POOL.max_retry)):
            # 原子租约：选号与槽位预留同一临界区，杜绝并发超卖
            with _sched_lock:
                a = POOL.pick(sk, tried, dev=dev, jwt_ok=jwt_ok)
                if a:
                    a.in_flight += 1
            if not a:
                break
            tried.add(a.name)
            a.stats["req"] += 1
            # JWT 通道（Phase9）：模型归一化 + 官方 system 注入 + verify_param 预取
            req_body = body
            verify_param = None
            if a.chat_via == "jwt":
                req_body = json.dumps(normalize_jwt_body(
                    req, inject_profile=bool(POOL.server_cfg.get("jwt_inject_profile", True)))).encode()
                verify_param = CAPTCHA.get_verify_param()
                if not verify_param:
                    log(f"[captcha] {a.name} verify_param 缺失，仍发送（预期 3012）")
            extra = {"Authorization": f"Bearer {a.key}"} if protocol == "openai" else {"x-api-key": a.key}
            if protocol == "anthropic":
                for h in ("anthropic-version", "anthropic-beta"):
                    if self.headers.get(h):
                        extra[h] = self.headers[h]
            # 4.3 超时分离：非流式 request_timeout；流式 idle_timeout 按块生效
            timeout = (float(POOL.server_cfg.get("stream_idle_timeout", 90)) if stream
                       else float(POOL.server_cfg.get("request_timeout", 300)))
            try:
                try:
                    if a.chat_via == "jwt":
                        status, rh, resp = jwt_chat_request(a, req_body, verify_param, timeout=timeout)
                    else:
                        status, rh, resp = upstream_request(a, upstream_path, req_body, extra, timeout=timeout)
                except (OSError, http.client.HTTPException) as e:
                    POOL.note_unknown_fail(a)
                    last_err = f"{type(e).__name__}: {e}"
                    continue
                if status != 200:
                    err = resp.read()[:400].decode(errors="replace")
                    # captcha 失效（verify_param 过期/3012）：非账号问题——失效重取后同号重试，不冷却
                    if (status in (401, 403) and cap_retries < MAX_CAPTCHA_RETRIES
                            and _captcha_err(err)):
                        cap_retries += 1
                        CAPTCHA.invalidate()
                        tried.discard(a.name)  # 不占换号名额：同号可再选（verify_param 已刷新）
                        log(f"[captcha] {a.name} http={status} 验证失效 → 重取重试 "
                            f"{cap_retries}/{MAX_CAPTCHA_RETRIES}")
                        last_err = f"{status} captcha"
                        continue
                    # 错误分类：请求本身有错（换号也无益）→ 原样透传客户端，不冷却账号
                    if status in PASS_THROUGH_STATUS:
                        raw = err.encode()
                        self.send_response(status)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(raw)))
                        self.end_headers()
                        self.wfile.write(raw)
                        log(f"[passthru] {a.name} http={status} {err[:80]}")
                        return
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
                # 4.1 SSE 配额占用（进入即计数，任何退出路径释放）
                if has_sse_quota:
                    srv.sse_active += 1
                    sse_entered = True
                self.send_response(200)
                self.send_header("Content-Type", ctype or "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                parser = SSEUsageParser()
                tin = tout = None
                try:
                    while True:
                        chunk = resp.read(1024)  # 流式空闲超时：read 抛 socket.timeout(OSError) 即终止
                        if not chunk:
                            break
                        self.wfile.write(chunk)   # 协议字节原样透传
                        self.wfile.flush()
                        parser.feed(chunk)        # 增量解析只读不改
                        tin, tout = parser.tin, parser.tout
                except (BrokenPipeError, OSError):
                    pass  # 客户端断开：槽位由外层 finally 释放
                finally:
                    try:
                        resp.close()  # 显式关闭上游连接，不占上游/本地资源
                    except Exception:
                        pass
                a.record(tin, tout)
                if dev:
                    dev.record(tin, tout)
                save_state()
                self._reqlog(seq, req, "stream", 200, a, t0, tin, tout, dev)
                return
            finally:
                a.in_flight -= 1
                if sse_entered:
                    sse_entered = False
                    if has_sse_quota:
                        srv.sse_active -= 1
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
        if m.startswith("/admin/") and POOL.admin_cfg.get("enabled"):
            if not self._authed():
                return self._json(401, {"error": "unauthorized"})
            if not POOL.admin_bucket.allow():
                return self._json(429, {"error": {"message": "admin rate limit exceeded",
                                                  "type": "admin_rate_limited"}})
            parts = m.strip("/").split("/")
            name, action = parts[2], parts[3] if len(parts) > 3 else ""
            # ---- jwt OAuth 登录（Phase9 移植 zcode2api ZaiAuthFlow） ----
            # 注意段数：/admin/jwt/login_start 为 3 段（name=jwt, action 落空），按整路径匹配
            if m.rstrip("/") == "/admin/jwt/login_start":
                custom_name = ""
                try:
                    _n = int(self.headers.get("Content-Length") or 0)
                    custom_name = str((json.loads(self.rfile.read(_n) or b"{}") or {}).get("name") or "")
                except Exception:
                    custom_name = ""
                try:
                    flow_id, authorize_url, poll_token = oauth_cli_init()
                except Exception as e:
                    return self._json(502, {"error": f"oauth init 失败: {type(e).__name__}: {e}"})
                _JWT_LOGIN_FLOWS[flow_id] = (poll_token, time.time(), custom_name)
                audit("jwt_login_start", flow_id, "ok", key_fp(sorted(POOL.api_keys)[0]))
                log(f"[oauth] flow={flow_id[:12]}… 已发起，等待浏览器授权")
                return self._json(200, {"flow_id": flow_id, "authorize_url": authorize_url,
                                        "poll": f"/admin/jwt/login_poll/{flow_id}"})
            if name == "jwt" and action == "login_poll":
                return self._jwt_login_poll(parts[4] if len(parts) > 4 else "")
            n = int(self.headers.get("Content-Length") or 0)
            reason = ""
            try:
                reason = (json.loads(self.rfile.read(n) or b"{}") or {}).get("reason", "")
            except Exception:
                pass
            # ---- devices 管理（先于 accounts 判定，防宽守卫截获） ----
            if m.startswith("/admin/devices/"):
                d = POOL.device_by_name(name)
                if not d or action not in ("assign", "disable", "enable"):
                    return self._json(404, {"error": "not found"})
                if action in ("disable", "enable"):
                    d.disabled = action == "disable"
                    save_state()
                    audit(action, name, "ok", key_fp(POOL.api_keys and sorted(POOL.api_keys)[0] or "-"))
                    log(f"[admin] device {action} {name}")
                    return self._json(200, {"name": d.name, "disabled": d.disabled})
                new_accounts = json.loads(self.rfile.read(n) or b"{}").get("accounts")
                if not isinstance(new_accounts, list):
                    return self._json(400, {"error": "accounts 必须是数组（空数组=全池）"})
                valid = {x.name for x in POOL.accounts}
                missing = [x for x in new_accounts if x not in valid]
                if missing:
                    return self._json(400, {"error": f"未知账号: {missing}"})
                old = d.accounts
                d.accounts = [str(x) for x in new_accounts]
                POOL.prune_sticky_for(d)
                save_state()
                audit("assign", name, "ok", key_fp(POOL.api_keys and sorted(POOL.api_keys)[0] or "-"),
                      f"{old} -> {d.accounts}")
                log(f"[admin] assign dev={name} accounts={d.accounts}")
                return self._json(200, {"name": d.name, "accounts": d.accounts,
                                        "primary": d.primary})
            # ---- accounts 管理 ----
            a = next((x for x in POOL.accounts if x.name == name), None)
            if not a or action not in ("disable", "enable", "revive", "probe", "billing-check"):
                return self._json(404, {"error": "not found"})
            if action == "probe":
                try:
                    st_, _, resp_ = upstream_request(a, MODELS_PATH, method="GET", timeout=30)
                    raw_ = resp_.read()
                    ok_ = st_ == 200
                    audit("probe", name, "ok" if ok_ else f"http={st_}",
                          key_fp(sorted(POOL.api_keys)[0]))
                    return self._json(200 if ok_ else 502,
                                      {"name": name, "healthy": ok_, "http": st_,
                                       "models": json.loads(raw_).get("data") if ok_ else None,
                                       "error": None if ok_ else raw_[:200].decode(errors="replace")})
                except Exception as e:
                    audit("probe", name, f"fail {type(e).__name__}", key_fp(sorted(POOL.api_keys)[0]))
                    return self._json(502, {"name": name, "healthy": False,
                                            "error": f"{type(e).__name__}: {e}"})
            if action == "billing-check":
                if not a.zcode_jwt:
                    return self._json(400, {"error": "该账号未配置 zcode_jwt"})
                active = fetch_billing(a)
                audit("billing-check", name, "ok" if active else "exhausted",
                      key_fp(sorted(POOL.api_keys)[0]))
                return self._json(200, {"name": name, "active": active, "billing": a.billing})
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
            fp = key_fp(sorted(POOL.api_keys)[0])
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
            POOL.prune_sticky_for(d)  # 越界粘性/主用号清理（设备隔离兜底）
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


# ==== domain: entry ====
# ---------- probe ----------
def run_probe(chat: bool) -> int:
    rc = 0
    for a in POOL.accounts:
        tag = f"{a.name:<10}"
        exit_ip = "-"
        if a.chat_via == "jwt":
            # jwt 通道无 api.z.ai key：KEY 探测无意义，跳过（billing 巡检走 --billing）
            print(f"{tag} JWT-ONLY  chat_via=jwt expires={a.expires or '-'}")
            continue
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
    # Phase8-8.2 配置版本：不兼容 schema 明确拒绝，不做静默迁移
    sv = int(cfg.get("schema_version", 1))
    if sv not in (1, 2):
        raise SystemExit(f"[config] schema_version={sv} 不受支持（支持 1/2）；"
                         f"请参考 pool.example.json 与 CHANGELOG.md 迁移")
    cfg["schema_version"] = sv
    # 安全闸：probe/honk-rules 等只读子命令也需要有效 key（请求会带它出站），但
    # --probe 允许占位 key（自检就是来发现坏 key 的）→ 仅服务启动路径强制
    POOL = Pool(cfg)
    STATE_FILE = str(Path(CFG_PATH).with_name("pool-state.json"))
    load_state()
    if not (a.probe or a.probe_chat or a.probe_ip or a.honk_rules or a.billing):
        validate_security(cfg, CFG_PATH)
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
    init_captcha(POOL.server_cfg)  # captcha 管理器按 server 段装配（Phase9）

    host, _, port = cfg.get("listen", "127.0.0.1:8602").rpartition(":")
    srv = BoundedServer((host or "0.0.0.0", int(port)), Handler, POOL.server_cfg)
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
            f"jwt={'yes' if acc.zcode_jwt else 'no'} chat_via={acc.chat_via}")
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
