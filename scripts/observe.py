#!/usr/bin/env python3
"""Phase 3 运行观察采集器。

snapshot 模式（默认）：抓取 /healthz + /status 摘要 + 日志尾部计数，
追加一行 JSONL 到 reports/runtime-observations.jsonl（该文件不入库）。
report 模式（--report）：聚合 JSONL + server.log 计数 →
reports/phase3-runtime-observation.md（计划书 3.1 规定字段）。

用法：
    python3 scripts/observe.py snapshot
    python3 scripts/observe.py report
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CST = timezone(timedelta(hours=8))
JSONL = ROOT / "reports" / "runtime-observations.jsonl"
REPORT_MD = ROOT / "reports" / "phase3-runtime-observation.md"
LOG = ROOT / "zai-pool-data" / "server.log"


def _head_sha() -> str:
    try:
        return subprocess_sha()
    except Exception:
        return "unknown"


def subprocess_sha() -> str:
    import subprocess
    return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()


def fetch(url: str, key: str, timeout: int = 10):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except Exception as e:
        return 0, {"error": f"{type(e).__name__}: {e}"}


def snapshot(gw: str, key: str) -> int:
    JSONL.parent.mkdir(exist_ok=True)
    hz = fetch(f"{gw}/healthz", key)
    st = fetch(f"{gw}/status", key)
    accounts = st[1].get("accounts", []) if isinstance(st[1], dict) else []
    sched = st[1].get("sched", {}) if isinstance(st[1], dict) else {}
    devices = st[1].get("devices", []) if isinstance(st[1], dict) else []
    ent = {
        "ts": datetime.now(CST).isoformat(),
        "head": _head_sha(),
        "healthy": hz[1].get("healthy") if isinstance(hz[1], dict) else None,
        "total": hz[1].get("total") if isinstance(hz[1], dict) else None,
        "primary": st[1].get("primary") if isinstance(st[1], dict) else None,
        "strategy": st[1].get("strategy") if isinstance(st[1], dict) else None,
        "sticky_sessions": st[1].get("sticky_sessions") if isinstance(st[1], dict) else None,
        "sched": sched,
        "accounts": [{"name": a.get("name"), "reasons": a.get("reasons"),
                      "in_flight": a.get("in_flight"), "stats": a.get("stats"),
                      "exit": a.get("exit")} for a in accounts],
        "devices": [{"name": d.get("name"), "primary": d.get("primary"),
                     "today": d.get("today")} for d in devices],
    }
    with JSONL.open("a") as f:
        f.write(json.dumps(ent, ensure_ascii=False) + "\n")
    print(f"[observe] 快照追加：healthy={ent['healthy']}/{ent['total']} "
          f"sticky_hits={sched.get('sticky_hits')} primary_switches={sched.get('primary_switches')}")
    return 0


def _log_counts() -> dict:
    """从 server.log 提取运行计数（不在报告中写任何凭据内容）。"""
    out = {"req_ok": 0, "req_stream": 0, "req_503": 0, "primary_switch": 0,
           "cooldown": {}, "passthru_400": 0, "reload": 0}
    if not LOG.exists():
        return out
    pat_row = re.compile(r"\| #\d+ \|")
    for line in LOG.read_text(errors="replace").splitlines():
        if pat_row.search(line):
            if "| stream |" in line:
                out["req_stream"] += 1
            if "| 200 |" in line:
                out["req_ok"] += 1
            if "| 503 |" in line:
                out["req_503"] += 1
        elif "[primary]" in line:
            out["primary_switch"] += 1
        elif "[passthru]" in line:
            out["passthru_400"] += 1
        elif "[reload]" in line:
            out["reload"] += 1
        elif "[cooldown]" in line:
            m = re.search(r"http=\d+ (\w+)", line)
            if m:
                out["cooldown"][m.group(1)] = out["cooldown"].get(m.group(1), 0) + 1
    return out


def report() -> int:
    if not JSONL.exists():
        print("[observe] 无快照数据", file=sys.stderr)
        return 1
    snaps = [json.loads(x) for x in JSONL.read_text().splitlines() if x.strip()]
    if not snaps:
        return 1
    counts = _log_counts()
    first, last = snaps[0], snaps[-1]
    # 每账号聚合
    acc_agg: dict[str, dict] = {}
    for s in snaps:
        for a in s.get("accounts", []):
            n = a.get("name") or "?"
            st_ = a.get("stats") or {}
            agg = acc_agg.setdefault(n, {"req": 0, "ok": 0, "fail": 0})
            agg["req"] = max(agg["req"], st_.get("req", 0))
            agg["ok"] = max(agg["ok"], st_.get("ok", 0))
            agg["fail"] = max(agg["fail"], st_.get("fail", 0))
    sched_last = last.get("sched") or {}
    lines = [
        "# Phase 3 运行观察报告", "",
        f"- 观察窗口：{first['ts']} → {last['ts']}（CST）",
        f"- Git HEAD：{last.get('head')} · Python：{sys.version.split()[0]}",
        f"- 快照数：{len(snaps)}（30 分钟间隔）",
        f"- 账号数：{last.get('total')} · 设备数：{len(last.get('devices') or [])} · 策略：{last.get('strategy')}",
        f"- 当前主用号：{last.get('primary')} · sticky 会话：{last.get('sticky_sessions')}",
        "", "## 调度行为", "",
        f"- 粘性命中：{sched_last.get('sticky_hits', 0)} · 粘性解绑：{sched_last.get('sticky_unbind', 0)}",
        f"- 主用号切换：{sched_last.get('primary_switches', 0)}（日志口径 {counts['primary_switch']}）",
        f"- 切号原因：{json.dumps(sched_last.get('switch_reasons', {}), ensure_ascii=False)}",
        "", "## 请求与错误", "",
        f"- 请求成功：{counts['req_ok']} · 流式：{counts['req_stream']} · 503：{counts['req_503']}",
        f"- 400 透传：{counts['passthru_400']} · 冷却原因分布：{json.dumps(counts['cooldown'], ensure_ascii=False)}",
        f"- 热重载次数：{counts['reload']}",
        "", "## 每账号观测", "",
        "| 账号 | req | ok | fail |", "|---|---|---|---|",
    ]
    for n, v in sorted(acc_agg.items()):
        lines.append(f"| {n} | {v['req']} | {v['ok']} | {v['fail']} |")
    lines += ["", "## 异常与结论", "",
              "- （观察进行中，结束时回填）", ""]
    REPORT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"[observe] 报告已生成 {REPORT_MD}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", default="snapshot", choices=["snapshot", "report"])
    ap.add_argument("--url", default="http://127.0.0.1:8602")
    ap.add_argument("--config", default=str(ROOT / "zai-pool-data" / "pool.json"))
    a = ap.parse_args()
    if a.mode == "report":
        return report()
    key = ""
    try:
        key = json.loads(Path(a.config).read_text()).get("api_key", "")
    except Exception:
        pass
    return snapshot(a.url, key)


if __name__ == "__main__":
    sys.exit(main())
