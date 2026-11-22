"""zai_pool.captcha — JWT 通道验证码管理（移植 zcode2api app/captcha.py，同步版）。

职责：client/configs 拉取（TTL 缓存）→ verify_param 求解（45s 缓存 + 单飞锁）
→ 403 captcha 失效 invalidate。求解只走 playwright headed 子进程（jsdom 无头
被阿里云无痕风控判 F001，不移植该分支），脚本复用 scripts/solve_captcha.py。

本模块线程模型对齐 ThreadingHTTPServer：threading.Lock 单飞双检（B 为 asyncio.Lock）。
"""
from __future__ import annotations

import http.client
import json
import ssl
import subprocess
import sys
import threading
import time
from importlib.util import find_spec
from pathlib import Path

from zai_pool.core import log

SOLVER_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "solve_captcha.py"
CONFIG_URL_HOST = "zcode.z.ai"
CONFIG_URL_PATH = "/api/v1/client/configs?app_version=3.0.0&platform=win32"
DEFAULT_CONFIG = {"enabled": True, "prefix": "no8xfe", "region": "sgp", "sceneId": "11xygtvd"}

_ssl_ctx = ssl.create_default_context()


def _default_solver_python() -> str:
    """playwright 所在解释器：当前解释器可用则用之，否则探测已知 venv（含 zcode2api 部署）。"""
    if find_spec("playwright"):
        return sys.executable
    for cand in (sys.prefix + "/solver-venv/bin/python",
                 str(Path.home() / "zcode2api" / "solver-venv" / "bin" / "python")):
        if Path(cand).exists():
            return cand
    return sys.executable  # 兜底：solve 时报 FileNotFoundError，由调用方隔离


class CaptchaManager:
    def __init__(self, solver_python: str | None = None, solve_timeout: float = 40.0,
                 retries: int = 4, cache_ttl: float = 45.0, config_ttl: float = 600.0):
        self.solver_python = solver_python or _default_solver_python()
        self.solve_timeout = solve_timeout
        self.retries = retries
        self.cache_ttl = cache_ttl
        self.config_ttl = config_ttl
        self._cached: str | None = None
        self._cached_at = 0.0
        self._lock = threading.Lock()
        self._config_cache: dict | None = None
        self._config_cache_at = 0.0
        self._config_lock = threading.Lock()

    # ── 配置（sceneId/region/prefix 三要素） ─────────────────────────────────
    def fetch_config(self) -> dict:
        now = time.time()
        if self._config_cache and now - self._config_cache_at < self.config_ttl:
            return self._config_cache
        with self._config_lock:
            if self._config_cache and time.time() - self._config_cache_at < self.config_ttl:
                return self._config_cache
            try:
                conn = http.client.HTTPSConnection(CONFIG_URL_HOST, timeout=15)
                try:
                    conn.request("GET", CONFIG_URL_PATH,
                                 headers={"Accept": "application/json", "User-Agent": "zai-pool/3.0"})
                    resp = conn.getresponse()
                    raw = resp.read()
                finally:
                    conn.close()
                captcha = (((json.loads(raw).get("data") or {}).get("configs") or {})
                           .get("captcha"))
                if captcha:
                    self._config_cache = captcha
                    self._config_cache_at = now
                    return captcha
            except Exception as e:
                log(f"[captcha] 配置拉取失败，使用默认: {type(e).__name__}: {e}")
            return dict(DEFAULT_CONFIG)

    # ── 求解（45s TTL 缓存 + 单飞双检；失败返回 None，不抛——调用方降级不带头发送） ──
    def get_verify_param(self) -> str | None:
        now = time.time()
        if self._cached and now - self._cached_at < self.cache_ttl:
            return self._cached
        with self._lock:
            if self._cached and time.time() - self._cached_at < self.cache_ttl:
                return self._cached
            config = self.fetch_config()
            param = self._solve(config)
            if param:
                self._cached = param
                self._cached_at = time.time()
            return param

    def _solve(self, config: dict) -> str | None:
        if not SOLVER_SCRIPT.exists():
            log(f"[captcha] 求解脚本缺失: {SOLVER_SCRIPT}")
            return None
        scene = config.get("sceneId") or DEFAULT_CONFIG["sceneId"]
        region = config.get("region") or DEFAULT_CONFIG["region"]
        prefix = config.get("prefix") or DEFAULT_CONFIG["prefix"]
        last_err = ""
        for attempt in range(1, self.retries + 1):
            try:
                proc = subprocess.run(
                    [self.solver_python, str(SOLVER_SCRIPT),
                     "--scene", scene, "--region", region, "--prefix", prefix,
                     "--timeout", str(max(10, int(self.solve_timeout) - 5))],
                    capture_output=True, timeout=self.solve_timeout + 15)
            except FileNotFoundError:
                log(f"[captcha] 无法启动求解器 {self.solver_python}（缺 playwright?）")
                return None
            except subprocess.TimeoutExpired:
                last_err = "solve timeout"
                log(f"[captcha] 第 {attempt}/{self.retries} 次求解超时")
                continue
            for line in proc.stdout.decode("utf-8", "ignore").splitlines():
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                if j.get("verify_param"):
                    if attempt > 1:
                        log(f"[captcha] 求解成功（第 {attempt} 次尝试）")
                    return j["verify_param"]
            last_err = f"rc={proc.returncode} stderr={proc.stderr.decode('utf-8', 'ignore')[-160:]}"
            log(f"[captcha] 第 {attempt}/{self.retries} 次求解未果 {last_err}")
        log(f"[captcha] 求解失败: {last_err or '多次重试无结果'}")
        return None

    def invalidate(self) -> None:
        self._cached = None
        self._cached_at = 0.0


CAPTCHA = CaptchaManager()


def init_captcha(server_cfg: dict) -> None:
    """entry 装配：按 pool.json server 段重建单例（setter 注入模式）。"""
    global CAPTCHA
    CAPTCHA = CaptchaManager(
        solver_python=server_cfg.get("captcha_python"),
        solve_timeout=float(server_cfg.get("captcha_timeout", 40)),
        retries=int(server_cfg.get("captcha_retries", 4)),
        cache_ttl=float(server_cfg.get("captcha_cache_ttl", 45)),
        config_ttl=float(server_cfg.get("captcha_config_ttl", 600)))
