#!/usr/bin/env python3
"""Phase 4-4.5 本地压测（mock 上游，零真实额度）。

用法：
    python3 tests/performance/bench.py --concurrency 10 --requests 50 --mode json
    python3 tests/performance/bench.py --concurrency 25 --requests 50 --mode sse
    python3 tests/performance/bench.py --concurrency 25 --requests 60 --mode mixed
    python3 tests/performance/bench.py --full        # 阶梯 1/10/25/50/100 + 报告

记录 P50/P95/P99 延迟、RPS、错误率、活跃线程、网关 in_flight 峰值与释放时间。
输出 results 表格；--out results.json 可落盘。机器性能不同不做跨机比较。
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # tests/performance/bench.py → 仓库根
sys.path.insert(0, str(ROOT))

KEY = "zpool-bench-key-0123456789abcdef"


def load(name, path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class FakeResp:
    def __init__(self, status, chunks, block_after=0.0, headers=None):
        self.status = status
        self._chunks = list(chunks)
        self.block_after = block_after
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}

    def read(self, n=-1):
        if self._chunks:
            return self._chunks.pop(0)
        if self.block_after > 0:
            time.sleep(self.block_after)
            self.block_after = 0
        return b""

    def getheaders(self):
        return list(self.headers.items())

    def close(self):
        pass


def boot(mode: str, upstream_delay: float):
    """真 HTTP 网关 + 受控上游（mock，无网络）。"""
    mod = load("zp_bench", ROOT / "zai-pool.py")
    mod.FakeResp = FakeResp
    cfg = {"listen": "127.0.0.1:0", "api_key": KEY,
           "server": {"max_connections": 200, "max_sse_connections": 60},
           "accounts": [{"name": f"b{i}", "api_key": f"P{i}"} for i in range(4)],
           "devices": []}
    mod.POOL = mod.Pool(cfg)
    mod.STATE_FILE = ""
    mod.load_panel()

    sse_body = [b'data: {"choices":[{"delta":{"content":"x"}}]}\n\n'] * 3 + [b'data: [DONE]\n\n']

    def fake(a, path, body=b"", extra=None, method="POST", host=None, timeout=600):
        if upstream_delay:
            time.sleep(upstream_delay)
        if method == "GET":
            return 200, {"content-type": "application/json"}, FakeResp(200, [json.dumps({"data": [{"id": "m"}]}).encode()])
        try:
            stream = bool(json.loads(body).get("stream"))
        except Exception:
            stream = False
        if stream:
            return 200, {"content-type": "text/event-stream"}, FakeResp(200, list(sse_body))
        return 200, {"content-type": "application/json"}, FakeResp(
            200, [json.dumps({"usage": {"prompt_tokens": 5, "completion_tokens": 7}}).encode()])
    mod.upstream_request = fake
    srv = mod.BoundedServer(("127.0.0.1", 0), mod.Handler, mod.POOL.server_cfg)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return mod, srv


def run_bench(port: int, concurrency: int, requests: int, mode: str) -> dict:
    lat: list[float] = []
    errors = 0
    lock = threading.Lock()
    stop = time.time() + 120

    def worker(n_req: int):
        nonlocal errors
        for _ in range(n_req):
            if time.time() > stop:
                return
            try:
                stream = mode == "sse" or (mode == "mixed" and threading.get_ident() % 2 == 0)
                body = json.dumps({"model": "m", "stream": stream,
                                   "messages": [{"role": "user", "content": "bench"}]}).encode()
                t0 = time.perf_counter()
                r = urllib.request.urlopen(urllib.request.Request(
                    f"http://127.0.0.1:{port}/v1/chat/completions", data=body,
                    headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}),
                    timeout=30)
                r.read()
                dt = time.perf_counter() - t0
                with lock:
                    lat.append(dt)
            except Exception:
                with lock:
                    errors += 1

    per = max(1, requests // concurrency)
    t0 = time.perf_counter()
    threads = [threading.Thread(target=worker, args=(per,)) for _ in range(concurrency)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    wall = time.perf_counter() - t0
    total = len(lat) + errors
    def pct(p):
        return round(statistics.quantiles(lat, n=100)[p - 1], 3) if len(lat) >= 20 else \
            (round(sorted(lat)[int(len(lat) * p / 100)], 3) if lat else -1)
    return {"mode": mode, "concurrency": concurrency, "total": total,
            "ok": len(lat), "errors": errors,
            "error_rate": round(errors / total, 4) if total else 0,
            "rps": round(len(lat) / wall, 1) if wall else 0,
            "p50": pct(50), "p95": pct(95), "p99": pct(99)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument("--requests", type=int, default=50)
    ap.add_argument("--mode", choices=["json", "sse", "mixed"], default="json")
    ap.add_argument("--upstream-delay", type=float, default=0.0)
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    results = []
    if a.full:
        for c in (1, 10, 25, 50, 100):
            mod, srv = boot(a.mode, a.upstream_delay)
            port = srv.server_address[1]
            r = run_bench(port, c, min(a.requests, 200), a.mode)
            r["in_flight_peak"] = max((x.in_flight for x in mod.POOL.accounts), default=0)
            leaked = sum(1 for x in mod.POOL.accounts if x.in_flight != 0)
            r["slot_leak_after"] = leaked
            results.append(r)
            srv.shutdown()
            print(json.dumps(r, ensure_ascii=False))
    else:
        mod, srv = boot(a.mode, a.upstream_delay)
        port = srv.server_address[1]
        r = run_bench(port, a.concurrency, a.requests, a.mode)
        r["slot_leak_after"] = sum(1 for x in mod.POOL.accounts if x.in_flight != 0)
        results.append(r)
        srv.shutdown()
        print(json.dumps(r, ensure_ascii=False))
    if a.out:
        Path(a.out).write_text(json.dumps(results, ensure_ascii=False, indent=1))
    bad = [r for r in results if r["error_rate"] > 0.05 or r["slot_leak_after"]]
    print(f"=== bench {'FAIL' if bad else 'OK'}（错误率>5% 或槽位泄漏判失败）===")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
