"""zai_pool.observability — Phase6 第三域：指标台账/告警三态机。

POOL/LEDGER/alert_cfg 经 init_observability getter 注入（entry 单向供给）。
"""
from __future__ import annotations

import hashlib
import json
import threading
import time


ALERTER = None
_pool_getter = None
_ledger_getter = None


def init_observability(pool_getter, ledger_getter):
    global _pool_getter, _ledger_getter
    _pool_getter, _ledger_getter = pool_getter, ledger_getter


def set_alerter(a) -> None:
    global ALERTER
    ALERTER = a


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
                                  "healthy": sum(1 for a in _pool_getter().accounts if a.healthy()),
                                  "total": len(_pool_getter().accounts)}).encode()
            req = urllib.request.Request(self.url, data=payload,
                                         headers={"Content-Type": "application/json"})
            if self.secret:
                sig = hmac.new(self.secret.encode(), payload, hashlib.sha256).hexdigest()
                req.add_header("X-ZaiPool-Signature", sig)
            urllib.request.urlopen(req, timeout=5)
            log(f"[alert] 已投递: {text}")
        except Exception as e:
            log(f"[alert] 投递失败: {e}")


_alert_cfg_getter = None


def set_alert_cfg_getter(fn):
    global _alert_cfg_getter
    _alert_cfg_getter = fn


def alert_worker(stop: threading.Event) -> None:
    if not (ALERTER and ALERTER.enabled):
        return
    interval = int((_alert_cfg_getter() or {}).get("interval_seconds", 30))
    while not stop.is_set():
        ALERTER.tick(sum(1 for a in _pool_getter().accounts if a.healthy()), len(_pool_getter().accounts))
        stop.wait(interval)


def metrics_text(_now_cst=None) -> str:
    lines = []
    reasons = {}
    for a in _pool_getter().accounts:
        for r in a.state_reasons():
            key = r.split("(")[0]
            reasons[key] = reasons.get(key, 0) + 1
    lines.append("# HELP zaipool_pool_accounts 账号状态（原因分解）")
    lines.append("# TYPE zaipool_pool_accounts gauge")
    for r, c in sorted(reasons.items()):
        lines.append(f'zaipool_pool_accounts{{state="{r}"}} {c}')
    lines.append(f'zaipool_pool_accounts_total {len(_pool_getter().accounts)}')
    inflight = sum(a.in_flight for a in _pool_getter().accounts)
    lines.append("# HELP zaipool_pool_in_flight 在途请求数")
    lines.append("# TYPE zaipool_pool_in_flight gauge")
    lines.append(f'zaipool_pool_in_flight {inflight}')
    lines.append("# TYPE zaipool_sticky_sessions gauge")
    lines.append(f'zaipool_sticky_sessions {len(_pool_getter().sticky)}')
    from zai_pool.core import now_cst as _core_now
    today = (_now_cst or _core_now)().strftime("%Y-%m-%d")
    tin = sum(a.usage.get(today, {}).get("in", 0) for a in _pool_getter().accounts)
    tout = sum(a.usage.get(today, {}).get("out", 0) for a in _pool_getter().accounts)
    lines.append("# TYPE zaipool_tokens_in_total counter")
    lines.append(f"zaipool_tokens_in_total {tin}")
    lines.append("# TYPE zaipool_tokens_out_total counter")
    lines.append(f"zaipool_tokens_out_total {tout}")
    for kind, days in _ledger_getter().items():
        ent = days.get(today)
        if ent:
            lines.append(f'zaipool_task_ok{{kind="{kind}"}} {ent["ok"]}')
            lines.append(f'zaipool_task_already{{kind="{kind}"}} {ent["already"]}')
            lines.append(f'zaipool_task_fail{{kind="{kind}"}} {ent["fail"]}')
    lines.append("# HELP zaipool_device_tokens_out_total 设备当日出站 token")
    lines.append("# TYPE zaipool_device_tokens_out_total counter")
    for d in _pool_getter().devices:
        t = d.usage.get(today, {})
        lines.append(f'zaipool_device_tokens_out_total{{device="{d.name}"}} {t.get("out", 0)}')
    lines.append("# HELP zaipool_sched_sticky_hits_total 粘性命中")
    lines.append("# TYPE zaipool_sched_sticky_hits_total counter")
    lines.append(f'zaipool_sched_sticky_hits_total {_pool_getter().sched["sticky_hits"]}')
    lines.append("# TYPE zaipool_sched_sticky_unbind_total 粘性解绑（失败/过期）")
    lines.append("# TYPE zaipool_sched_sticky_unbind_total counter")
    lines.append(f'zaipool_sched_sticky_unbind_total {_pool_getter().sched["sticky_unbind"]}')
    lines.append("# TYPE zaipool_sched_primary_switches_total 主用号切换")
    lines.append("# TYPE zaipool_sched_primary_switches_total counter")
    lines.append(f'zaipool_sched_primary_switches_total {_pool_getter().sched["primary_switches"]}')
    lines.append("# TYPE zaipool_sched_switch_reasons_total 切号原因计数")
    lines.append("# TYPE zaipool_sched_switch_reasons_total counter")
    for r, c in sorted(_pool_getter().sched["switch_reasons"].items()):
        lines.append(f'zaipool_sched_switch_reasons_total{{reason="{r}"}} {c}')
    lines.append("# TYPE zaipool_account_requests_total counter")
    for a in _pool_getter().accounts:
        lines.append(f'zaipool_account_requests_total{{account="{a.name}",result="ok"}} {a.stats["ok"]}')
        lines.append(f'zaipool_account_requests_total{{account="{a.name}",result="fail"}} {a.stats["fail"]}')
    return "\n".join(lines) + "\n"


