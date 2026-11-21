#!/usr/bin/env python3
"""zacc-web — ZCode 多账号管理 Web 界面。

仅监听 127.0.0.1，浏览器打开 http://127.0.0.1:8600。
所有操作经 zacc.py CLI 执行（子进程，锁语义与行为与 CLI 完全一致），
凭据任何情况下不明文返回（指纹均掩码）。

用法：
    python3 zacc-web.py [--port 8600] [--no-open]

环境覆盖同 zacc.py：ZACC_DIR / ZCODE_V2_DIR。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ZACC = str(Path(__file__).resolve().parent / "zacc.py")


def run_zacc(*args: str, timeout: int = 30) -> tuple[int, str, str]:
    p = subprocess.run(
        [sys.executable, ZACC, *args],
        capture_output=True, text=True, timeout=timeout,
    )
    return p.returncode, p.stdout.strip(), p.stderr.strip()


PAGE = r"""<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>zacc · ZCode 账号切换</title>
<style>
:root{
  --bg:#0b0e14; --panel:#12161f; --card:#171c27; --card-h:#1d2330;
  --line:#232a38; --txt:#e6eaf2; --dim:#8b94a7; --faint:#5b6373;
  --acc:#6c8cff; --acc2:#22d3ee; --ok:#34d399; --warn:#fbbf24; --bad:#f87171;
  --grad:linear-gradient(135deg,#6c8cff,#22d3ee);
  --r:14px; --mono:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font:14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,'PingFang SC','Microsoft YaHei',sans-serif;
  min-height:100vh;background-image:radial-gradient(900px 500px at 85% -10%,rgba(108,140,255,.13),transparent),radial-gradient(700px 400px at -10% 110%,rgba(34,211,238,.09),transparent)}
.wrap{max-width:1060px;margin:0 auto;padding:28px 24px 48px}
header{display:flex;align-items:center;gap:14px;margin-bottom:8px}
.logo{width:42px;height:42px;border-radius:12px;background:var(--grad);display:grid;place-items:center;font-weight:800;font-size:17px;color:#fff;letter-spacing:-1px;box-shadow:0 6px 20px rgba(108,140,255,.35)}
h1{font-size:20px;font-weight:700}
.sub{color:var(--dim);font-size:12.5px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:18px 0 20px;flex-wrap:wrap}
.badge{display:inline-flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--line);border-radius:999px;padding:7px 14px;font-size:13px}
.badge b{font-weight:600}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok)}
.dot.off{background:var(--faint);box-shadow:none}
.actions{display:flex;gap:10px;flex-wrap:wrap}
button{cursor:pointer;border:1px solid var(--line);background:var(--card);color:var(--txt);border-radius:10px;padding:8px 15px;font-size:13px;font-weight:500;transition:.15s;display:inline-flex;align-items:center;gap:7px}
button:hover{background:var(--card-h);border-color:#2f394d;transform:translateY(-1px)}
button:active{transform:translateY(0)}
button.primary{background:var(--grad);border:none;color:#fff;font-weight:600;box-shadow:0 4px 14px rgba(108,140,255,.3)}
button.primary:hover{filter:brightness(1.08)}
button.danger{color:var(--bad)}
button.danger:hover{border-color:rgba(248,113,113,.5);background:rgba(248,113,113,.08)}
button.ghost{background:transparent}
button:disabled{opacity:.45;cursor:not-allowed;transform:none}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:16px 16px 13px;transition:.15s;position:relative}
.card:hover{background:var(--card-h);border-color:#2f394d;transform:translateY(-2px);box-shadow:0 10px 28px rgba(0,0,0,.35)}
.card.active{border-color:rgba(52,211,153,.45);box-shadow:0 0 0 1px rgba(52,211,153,.25),0 8px 24px rgba(52,211,153,.08)}
.card-top{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.avatar{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;font-weight:700;font-size:15px;color:#fff;flex:none}
.pname{font-weight:600;font-size:15px;display:flex;align-items:center;gap:8px;min-width:0}
.pname span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag{font-size:10.5px;font-weight:600;padding:2px 8px;border-radius:999px;flex:none}
.tag.current{background:rgba(108,140,255,.15);color:var(--acc);border:1px solid rgba(108,140,255,.35)}
.tag.last{background:rgba(251,191,36,.12);color:var(--warn);border:1px solid rgba(251,191,36,.3)}
.ident{color:var(--dim);font-size:12.5px;margin:2px 0 10px;padding-left:46px;min-height:16px}
.chips{display:flex;gap:6px;flex-wrap:wrap;padding-left:46px;margin-bottom:12px}
.chip{font-family:var(--mono);font-size:11px;color:var(--faint);background:rgba(255,255,255,.04);border:1px solid var(--line);border-radius:6px;padding:2px 7px}
.chip.fpd{color:var(--acc2)}
.chip.box{color:var(--acc);font-family:inherit;font-weight:600}
.card-foot{display:flex;align-items:center;justify-content:space-between;gap:8px}
.time{color:var(--faint);font-size:11.5px}
.ops{display:flex;gap:5px}
.ops button{padding:5px 8px;font-size:11.5px;border-radius:8px;white-space:nowrap}
.empty{border:1.5px dashed var(--line);border-radius:var(--r);padding:56px 20px;text-align:center;color:var(--dim)}
.empty .big{font-size:34px;margin-bottom:10px}
.log{margin-top:26px;background:var(--panel);border:1px solid var(--line);border-radius:var(--r);overflow:hidden}
.log-head{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--line);color:var(--dim);font-size:12px}
.log pre{padding:14px 16px;font-family:var(--mono);font-size:12px;color:#a8b3c7;white-space:pre-wrap;word-break:break-all;max-height:220px;overflow:auto;min-height:60px}
.overlay{position:fixed;inset:0;background:rgba(5,8,14,.66);backdrop-filter:blur(4px);display:none;place-items:center;z-index:50}
.overlay.show{display:grid}
.modal{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:24px;width:min(440px,92vw);box-shadow:0 24px 60px rgba(0,0,0,.5)}
.modal h3{font-size:16px;margin-bottom:6px}
.modal p{color:var(--dim);font-size:13px;margin-bottom:16px}
.modal input{width:100%;background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:10px 13px;color:var(--txt);font-size:14px;outline:none;margin-bottom:6px}
.modal input:focus{border-color:var(--acc)}
.modal .row{display:flex;justify-content:flex-end;gap:10px;margin-top:14px}
.showbox{max-height:340px;overflow:auto;background:var(--bg);border-radius:10px;padding:12px;font-family:var(--mono);font-size:12px;color:#a8b3c7;margin-bottom:4px}
#toast{position:fixed;bottom:26px;left:50%;transform:translateX(-50%) translateY(80px);background:var(--panel);border:1px solid var(--line);color:var(--txt);padding:11px 20px;border-radius:12px;font-size:13.5px;box-shadow:0 12px 32px rgba(0,0,0,.5);transition:.3s;z-index:99;display:flex;gap:9px;align-items:center}
#toast.show{transform:translateX(-50%) translateY(0)}
#toast.ok{border-color:rgba(52,211,153,.5)} #toast.err{border-color:rgba(248,113,113,.5)}
.spin{width:14px;height:14px;border:2px solid var(--line);border-top-color:var(--acc);border-radius:50%;animation:sp .7s linear infinite;display:none}
@keyframes sp{to{transform:rotate(360deg)}}
.busy .spin{display:inline-block}
.mono{font-family:var(--mono)}
</style></head><body>
<div class="wrap">
<header>
  <div class="logo">zc</div>
  <div><h1>zacc · ZCode 账号切换</h1>
  <div class="sub">本地多账号管理 · 凭据仅指纹显示 · 127.0.0.1</div></div>
</header>
<div class="topbar">
  <div class="badge"><span class="dot off" id="dot"></span>当前指向 <b id="cur">加载中…</b></div>
  <div class="actions">
    <button id="btn-refresh" onclick="load()"><span class="spin"></span>刷新</button>
    <button onclick="addDialog()" class="primary">＋ 新档案</button>
    <button onclick="execDialog()" class="ghost">▶ 运行命令</button>
  </div>
</div>
<div class="grid" id="grid"><div class="empty"><div class="big">📦</div>暂无档案</div></div>
<div class="log"><div class="log-head"><span>操作日志</span><button class="ghost" style="padding:3px 10px;font-size:11px" onclick="document.getElementById('out').textContent=''">清空</button></div>
<pre id="out">就绪。</pre></div>
</div>

<div class="overlay" id="ov"><div class="modal" id="modal"></div></div>
<div id="toast"><span id="toast-ic">✓</span><span id="toast-tx"></span></div>

<script>
const $=id=>document.getElementById(id);
let DATA={accounts:[],current:null};
const AV=['#6c8cff','#22d3ee','#34d399','#fbbf24','#f87171','#a78bfa','#fb923c'];
const avColor=n=>{let h=0;for(const c of n)h=(h*31+c.charCodeAt(0))>>>0;return AV[h%AV.length]};

function toast(tx,ok=true){$('toast-tx').textContent=tx;$('toast-ic').textContent=ok?'✓':'✕';
  $('toast').className='show '+(ok?'ok':'err');clearTimeout(toast.t);toast.t=setTimeout(()=>$('toast').className='',2600)}
function log(s){$('out').textContent+= (s+'\n');$('out').scrollTop=1e9}
async function api(path,body){
  const o=body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{};
  const r=await fetch(path,o);const j=await r.json().catch(()=>({error:'响应解析失败'}));
  if(!r.ok||j.error)throw new Error(j.error||('HTTP '+r.status));return j}

function render(){
  $('cur').textContent=DATA.current||'未跟踪';
  $('dot').className='dot'+(DATA.current?'':' off');
  const g=$('grid');
  if(!DATA.accounts.length){g.innerHTML='<div class="empty"><div class="big">📦</div>暂无档案 · 点「＋ 新档案」把当前登录账号收进来</div>';return}
  g.innerHTML=DATA.accounts.map(a=>{
    const tags=(a.current?'<span class="tag current">CURRENT</span>':'')+(a.note&&a.note.includes('切换前快照')?'<span class="tag last">快照</span>':'');
    const isBox=a.home&&a.home!=='__HOME__';
    const boxName=isBox?a.home.split('/').pop().replace('-home',''):null;
    return `<div class="card ${a.active?'active':''}">
      <div class="card-top">
        <div class="avatar" style="background:${avColor(a.name)}">${a.name==='_last'?'⏱':esc(a.name.slice(0,1).toUpperCase())}</div>
        <div class="pname"><span title="${esc(a.name)}">${esc(a.name)}</span>${tags}</div>
      </div>
      <div class="ident">${esc(a.ident||'身份加密 · 无法解密')}</div>
      <div class="chips"><span class="chip fpd">${a.fp||'—'}</span><span class="chip">${a.size}B</span>${isBox?`<span class="chip box">📦 ${esc(boxName)}</span>`:''}</div>
      <div class="card-foot"><span class="time">${a.mtime}</span>
        <div class="ops">
          <button onclick="act('use','${esc(a.name)}')">切换</button>
          <button onclick="execDialog('${esc(a.name)}')">运行</button>
          <button onclick="act('save','${esc(a.name)}')">保存</button>
          <button onclick="showDetail('${esc(a.name)}')">详情</button>
          <button class="danger" onclick="rmDialog('${esc(a.name)}')">删除</button>
        </div></div></div>`}).join('')}
const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

async function load(){
  $('btn-refresh').classList.add('busy');
  try{DATA=await api('/api/list');render()}catch(e){toast('加载失败：'+e.message,false)}
  finally{$('btn-refresh').classList.remove('busy')}}
async function act(cmd,name,extra={}){
  try{const j=await api('/api/'+cmd,{name,...extra});
    const verb={use:'已切换到',save:'已保存到',add:'已新建',rm:'已删除'}[cmd]||'已操作';
    toast(verb+' '+name);
    log(j.log||('['+cmd+'] '+name));
    await load()}catch(e){toast((cmd+' 失败：')+e.message,false)}}
async function showDetail(name){
  try{const j=await api('/api/show',{name});
    openModal(`<h3>详情 · ${esc(name)}</h3><p>${esc(j.ident||'')}</p>
      <div class="showbox">${esc(j.keys)}</div>
      <div class="row"><button onclick="closeModal()">关闭</button></div>`)}catch(e){toast(e.message,false)}}
function openModal(html){$('modal').innerHTML=html;$('ov').classList.add('show')}
function closeModal(){$('ov').classList.remove('show')}
$('ov').addEventListener('click',e=>{if(e.target===$('ov'))closeModal()});

function addDialog(){openModal(`<h3>新建档案</h3><p>把「当前 zcode 登录的凭据」保存为档案（含 provider_config，如存在）</p>
  <input id="m-name" placeholder="档案名，如 main / work" onkeydown="if(event.key=='Enter')doAdd()">
  <div class="row"><button onclick="closeModal()">取消</button><button class="primary" onclick="doAdd()">保存档案</button></div>`);
  $('m-name').focus()}
async function doAdd(){const n=$('m-name').value.trim();if(!n)return toast('请输入档案名',false);
  closeModal();await act('add',n)}

function execDialog(pref){
  if(!DATA.accounts.length)return toast('先创建档案',false);
  const init=(pref&&DATA.accounts.some(a=>a.name===pref))?pref:
    (DATA.current&&DATA.accounts.some(a=>a.name===DATA.current)?DATA.current:DATA.accounts[0].name);
  openModal(`<h3>以账号运行命令</h3><p>独立数据目录运行，不切换当前登录。容器来源账号自动注入原 HOME。长命令输出请看终端。</p>
  <input id="m-cmd" class="mono" value="zcode --version" onkeydown="if(event.key=='Enter')doExec()">
  <div class="row" style="justify-content:flex-start;gap:6px;flex-wrap:wrap;margin-bottom:0">
    ${DATA.accounts.map(a=>`<button data-pick="${esc(a.name)}" onclick="pickAcc('${esc(a.name)}')">${esc(a.name)}</button>`).join('')}
  </div>
  <div id="m-home" class="sub" style="margin-top:10px"></div>
  <div class="row"><button onclick="closeModal()">取消</button><button class="primary" onclick="doExec()">运行</button></div>`);
  execDialog.acc=init;
  pickAcc(init)}
function pickAcc(n){execDialog.acc=n;document.querySelectorAll('[data-pick]').forEach(b=>{
  b.style.borderColor=b.dataset.pick===n?'var(--acc)':'';b.style.color=b.dataset.pick===n?'var(--acc)':''});
  const a=DATA.accounts.find(x=>x.name===n);
  const el=$('m-home');
  if(el)el.textContent=a&&a.home&&a.home!=='__HOME__'?`将注入 HOME=${a.home}`:''}
async function doExec(){const c=$('m-cmd').value.trim();if(!c)return;
  closeModal();toast('运行中…',true);
  try{const j=await api('/api/exec',{name:execDialog.acc,cmd:c});
    log(`[exec ${execDialog.acc}] $ ${c}\n${j.output||'(无输出)'}\nexit=${j.code}`);
    toast(`exit=${j.code}`,j.code===0)}catch(e){toast('exec 失败：'+e.message,false)}}

function rmDialog(name){openModal(`<h3>删除档案</h3><p>确定删除 <b class="mono">${esc(name)}</b>？该档案保存的凭据文件将被移除，不可恢复。</p>
  <div class="row"><button onclick="closeModal()">取消</button><button class="danger" onclick="closeModal();act('rm','${esc(name)}')">确认删除</button></div>`)}

function openFromHash(){const h=location.hash.slice(1);
  if(!h)return;
  if(h!=='add'&&!DATA.accounts.length)return setTimeout(openFromHash,200);
  if(h==='add')addDialog();else if(h==='exec')execDialog();
  else if(h.startsWith('show-'))showDetail(decodeURIComponent(h.slice(5)))}
window.addEventListener('hashchange',openFromHash);
load();openFromHash()
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静默访问日志
        pass

    def _json(self, code: int, obj: dict) -> None:
        raw = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            raw = PAGE.replace("__HOME__", str(Path.home())).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if self.path.startswith("/api/list"):
            code, out, err = run_zacc("list", "--json")
            if code != 0:
                return self._json(500, {"error": err or out})
            accounts = json.loads(out or "[]")
            cur_code, cur_out, _ = run_zacc("current")
            return self._json(200, {
                "accounts": accounts,
                "current": cur_out if cur_code == 0 else None,
            })
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        try:
            body = self._body()
        except Exception:
            return self._json(400, {"error": "请求体不是合法 JSON"})
        name = str(body.get("name") or "")
        try:
            if self.path == "/api/use":
                args = ["use", name] + (["--keep-providers"] if body.get("keep") else [])
                code, out, err = run_zacc(*args)
                return self._json(200 if code == 0 else 500, {"ok": code == 0, "log": out} if code == 0 else {"error": err or out})
            if self.path == "/api/add":
                code, out, err = run_zacc("add", name)
                return self._json(200 if code == 0 else 500, {"ok": True, "log": out} if code == 0 else {"error": err or out})
            if self.path == "/api/save":
                code, out, err = run_zacc("save", name)
                return self._json(200 if code == 0 else 500, {"ok": True, "log": out} if code == 0 else {"error": err or out})
            if self.path == "/api/rm":
                code, out, err = run_zacc("rm", name)
                return self._json(200 if code == 0 else 500, {"ok": True, "log": out} if code == 0 else {"error": err or out})
            if self.path == "/api/show":
                code, out, err = run_zacc("show", name)
                if code != 0:
                    return self._json(500, {"error": err or out})
                ident = ""
                keys = out
                lines = out.splitlines()
                if lines and "(" in lines[0]:
                    ident = lines[0].rsplit("(", 1)[-1].rstrip(")")
                    keys = "\n".join(lines[1:])
                return self._json(200, {"ident": ident, "keys": keys})
            if self.path == "/api/exec":
                cmd = body.get("cmd") or ""
                if not name or not cmd:
                    return self._json(400, {"error": "name/cmd 缺失"})
                import shlex
                code, out, err = run_zacc("exec", name, "--", *shlex.split(cmd), timeout=60)
                return self._json(200, {"code": code, "output": out + (f"\n{err}" if err else "")})
            return self._json(404, {"error": "not found"})
        except subprocess.TimeoutExpired:
            return self._json(200, {"code": 124, "output": "(超时 60s，已终止；长命令请在终端运行)"})
        except Exception as e:
            return self._json(500, {"error": str(e)})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8600)
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    except OSError as e:
        print(f"[zacc-web] 端口 {a.port} 占用（{e}），换端口：python3 zacc-web.py --port {a.port + 1}", file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{a.port}"
    print(f"[zacc-web] {url}")
    if not a.no_open:
        threading.Timer(0.4, lambda: webbrowser.open(url, new=2) or print(f"[zacc-web] 若浏览器未自动打开，请手动访问 {url}")).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
