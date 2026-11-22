#!/usr/bin/env python3
"""阿里云无痕验证求解器（playwright headed chromium）。

产出 X-Aliyun-Captcha-Verify-Param 到 stdout（280B 上下文），供 zai-pool 的
JWT 对话通道（chat_via=jwt）随请求携带。headed 模式必需：headless 环境被
阿里云无痕风控判 F001（verifyResult:false）。

用法：
    python3 scripts/solve_captcha.py [--timeout 25]
输出：
    VERIFY_PARAM 成功时 stdout 最后一行以 JSON {"verify_param": "..."} 打印
退出码：0 成功 / 非 0 失败
"""
from __future__ import annotations

import argparse
import json
import sys

from playwright.sync_api import sync_playwright


def solve(scene="11xygtvd", region="sgp", prefix="no8xfe", timeout_s: int = 25) -> str | None:
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False, args=["--no-sandbox", "--window-size=420,420"])
        page = browser.new_context(viewport={"width": 400, "height": 400}).new_page()
        page.goto("https://zcode.z.ai/", timeout=20000)
        page.add_script_tag(url="https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js")
        page.wait_for_function("() => typeof window.initAliyunCaptcha === 'function'", timeout=15000)
        page.evaluate(f"""() => {{
          const c = document.createElement('div'); c.id = 'cap'; document.body.appendChild(c);
          const b = document.createElement('button'); document.body.appendChild(b);
          window.__vp = null; window.__fail = null;
          window.initAliyunCaptcha({{ SceneId: '{scene}', mode: 'popup', region: '{region}',
            prefix: '{prefix}', element: '#cap', button: '#btn', showErrorTip: false,
            getInstance: (i) => {{ try {{ (i.startTracelessVerification || i.show).call(i); }} catch (e) {{ window.__fail = 'start:' + e.message; }} }},
            success: (p) => {{ window.__vp = p; }},
            fail: (x) => {{ window.__fail = JSON.stringify(x); }},
            onError: (e) => {{ window.__fail = 'onError'; }} }});
        }}""")
        vp = None
        deadline = timeout_s
        for _ in range(int(deadline / 0.4)):
            vp = page.evaluate("() => window.__vp")
            if vp:
                break
            fail = page.evaluate("() => window.__fail")
            if fail:
                print(f"[solver] fail: {fail}", file=sys.stderr)
                break
            page.wait_for_timeout(400)
        browser.close()
        return vp


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scene", default="11xygtvd")
    ap.add_argument("--region", default="sgp")
    ap.add_argument("--prefix", default="no8xfe")
    ap.add_argument("--timeout", type=int, default=25)
    a = ap.parse_args()
    vp = solve(a.scene, a.region, a.prefix, a.timeout)
    if not vp:
        print(json.dumps({"verify_param": None}), file=sys.stderr)
        return 1
    print(json.dumps({"verify_param": vp}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
