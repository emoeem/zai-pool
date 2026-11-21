"""CI 轻量基线（确定性，不做性能断言）：压测管线在 CI 环境跑小规模冒烟，
验证不崩、无槽位泄漏、错误率 0。真实数字以本机 --full 为准（机器相关）。"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_bench_smoke_json():
    r = subprocess.run([sys.executable, str(ROOT / "performance" / "bench.py"),
                        "--concurrency", "8", "--requests", "24", "--mode", "json"],
                       capture_output=True, text=True, timeout=120, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    assert '"slot_leak_after": 0' in r.stdout


def test_bench_smoke_sse():
    r = subprocess.run([sys.executable, str(ROOT / "performance" / "bench.py"),
                        "--concurrency", "6", "--requests", "18", "--mode", "sse"],
                       capture_output=True, text=True, timeout=120, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr


def test_bench_mixed_abort_safety():
    r = subprocess.run([sys.executable, str(ROOT / "performance" / "bench.py"),
                        "--concurrency", "10", "--requests", "30", "--mode", "mixed"],
                       capture_output=True, text=True, timeout=150, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
