#!/usr/bin/env python3
"""zacc — ZCode 多账号本地切换管理。

凭据机制（取自 zcode.cjs 实测）：
- CLI 与桌面端共用 <baseDir>/.zcode/v2/credentials.json，键含
  oauth:zai:access_token / oauth:zai:user_info / zcodejwttoken /
  oauth:active_provider / oauth:session_revision。
- CLI 会自动刷新 access_token（刷新后文件内容变化），指纹判定因此
  优先使用账号身份键 oauth:zai:user_info，access_token 仅作回退。
- 环境变量 ZCODE_DATA_BASE_DIR 可重定向 baseDir，用于多账号并行。
- 凭据值加密格式（逆向自 zcode.cjs，wSt/cAo/fAo/pAo/Ike）：
    enc:v1:<nonce.tag.ct>                    key=sha256("zcode-credential-fallback:{platform}:{homedir}:{username}")
    enc:v2:os:<gen24hex>:<nonce.tag.ct>      key=Secret Service 条目 label "*@ZCode Credential Encryption"
    enc:v2:env:<nonce.tag.ct>                key=$ZCODE_CREDENTIAL_SECRET
  cipher 均为 base64url(nonce12).base64url(tag16).base64url(ct)，AES-256-GCM。
  本机 gnome-keyring 经 D-Bus 可读 key，distrobox 容器共享宿主 keyring。

账号档案布局：
    ~/.zcode/accounts/<name>/data/.zcode/v2/credentials.json
    ~/.zcode/accounts/<name>/data/.zcode/v2/provider_config.json

状态文件：
    ~/.zcode/accounts/.current   记录 use 当前指向的档案名（无则未跟踪）

命令：
    zacc add <name> [--file F]     当前(或 --file)的 credentials.json 存入档案 name
    zacc use <name> [--keep-providers]  切换到档案 name：
                                       - live 状态回写到 .current 指向的来源档案
                                         （无记录则快照到 _last），刷新过的 token 不丢
                                       - 目标档案含 provider_config 时默认一并还原
    zacc save <name>               当前凭据覆盖写入档案 name
    zacc list                      列出档案与指纹，● 为当前激活
    zacc current                   显示当前指向的档案
    zacc show <name>               显示档案内的键与掩码指纹（解密身份后显示 email）
    zacc ident <name>              解密并打印档案的账号身份（email）
    zacc exec <name> -- <cmd...>   以该账号的独立数据目录运行命令（不切换，不持锁）；
                                   档案 meta 记录了容器来源 home 时自动注入 env HOME
    zacc where <name>              打印档案 credentials.json 路径
    zacc rm <name>                 删除档案

环境覆盖（测试用）：
    ZACC_DIR      档案根目录，默认 ~/.zcode/accounts
    ZCODE_V2_DIR  当前活动的 v2 目录，默认 ~/.zcode/v2
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HOME = Path.home()
ACCOUNTS_DIR = Path(os.environ.get("ZACC_DIR") or HOME / ".zcode" / "accounts")
V2_DIR = Path(os.environ.get("ZCODE_V2_DIR") or HOME / ".zcode" / "v2")
CRED_NAME = "credentials.json"
PROVIDER_NAME = "provider_config.json"
LAST_PROFILE = "_last"
CURRENT_FILE = ".current"
NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


def sanitize_name(name: str) -> str:
    """档案名白名单：字母/数字/下划线/中划线。杜绝路径穿越（../、绝对路径、分隔符）。"""
    if not NAME_RE.match(name or ""):
        die(f"非法档案名: {name!r}（只允许字母/数字/_/-，1-64 位）")
    return name


def live_cred() -> Path:
    return V2_DIR / CRED_NAME


def profile_cred(name: str) -> Path:
    return ACCOUNTS_DIR / name / "data" / ".zcode" / "v2" / CRED_NAME


def profile_provider(name: str) -> Path:
    return ACCOUNTS_DIR / name / "data" / ".zcode" / "v2" / PROVIDER_NAME


def profile_data_dir(name: str) -> Path:
    return ACCOUNTS_DIR / name / "data"


def ensure_dir700(p: Path) -> None:
    """创建目录并把 ACCOUNTS_DIR 子树内的各级目录收紧为 700。"""
    p.mkdir(parents=True, exist_ok=True)
    cur = p
    while cur != ACCOUNTS_DIR and ACCOUNTS_DIR in cur.parents:
        os.chmod(cur, 0o700)
        cur = cur.parent


def atomic_copy(src: Path, dst: Path) -> None:
    """src -> dst 原子覆盖，保持 600 权限，目录 700。"""
    ensure_dir700(dst.parent)
    fd, tmp = tempfile.mkstemp(dir=str(dst.parent), prefix=".tmp-")
    with open(fd, "wb") as out, open(src, "rb") as fin:
        shutil.copyfileobj(fin, out)
    os.chmod(tmp, 0o600)
    os.replace(tmp, dst)


# ---------- 凭据解密（AES-256-GCM，格式见模块 docstring） ----------
_ENC_V1 = "enc:v1:"
_ENC_V2OS = "enc:v2:os:"
_KEYRING_LABEL = "@ZCode Credential Encryption"
_KEYS_CACHE: list[bytes] | None = None


def _keyring_keys() -> list[bytes]:
    """Secret Service 读 keyring 里的 zcode 加密 key（base64url 文本，32B）。"""
    global _KEYS_CACHE
    if _KEYS_CACHE is not None:
        return _KEYS_CACHE
    keys: list[bytes] = []
    try:
        import dbus  # type: ignore
        bus = dbus.SessionBus()
        svc = dbus.Interface(
            bus.get_object("org.freedesktop.secrets", "/org/freedesktop/secrets"),
            "org.freedesktop.Secret.Service")
        sess = svc.OpenSession("plain", dbus.String("", variant_level=1))[1]
        col = bus.get_object("org.freedesktop.secrets", "/org/freedesktop/secrets/collection/login")
        items = dbus.Interface(col, "org.freedesktop.DBus.Properties").Get(
            "org.freedesktop.Secret.Collection", "Items")
        for ip in items:
            obj = bus.get_object("org.freedesktop.secrets", ip)
            props = dbus.Interface(obj, "org.freedesktop.DBus.Properties")
            label = str(props.Get("org.freedesktop.Secret.Item", "Label"))
            if not label.endswith(_KEYRING_LABEL):
                continue
            raw = bytes(dbus.Interface(obj, "org.freedesktop.Secret.Item").GetSecret(sess)[2]).decode()
            key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            if len(key) == 32:
                keys.append(key)
    except Exception:
        pass
    _KEYS_CACHE = keys
    return keys


def _derived_keys(home: str = "", username: str = "") -> list[bytes]:
    """enc:v1 派生密钥：sha256("zcode-credential-fallback:{platform}:{homedir}:{username}")。"""
    import hashlib
    import getpass
    home = home or HOME
    username = username or getpass.getuser()
    base = f"zcode-credential-fallback:linux:{home}:{username}"
    out, seen = [], set()
    for variant in (base, base + ":"):
        k = hashlib.sha256(variant.encode()).digest()
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _aesgcm_decrypt(cipher: str, keys: list[bytes]) -> str | None:
    """nonce.tag.ct 三段 base64url，逐 key 试解，tag 校验保证正确性。"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None
    try:
        parts = cipher.split(".")
        if len(parts) != 3:
            return None
        n, t, c = (base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)) for s in parts)
        if len(n) != 12 or len(t) != 16:
            return None
    except Exception:
        return None
    for k in keys:
        try:
            return AESGCM(k).decrypt(n, c + t, None).decode("utf-8")
        except Exception:
            continue
    return None


def decrypt_value(value: str, extra_homes: tuple[str, ...] = ()) -> str:
    """解 enc:v1 / enc:v2:os / enc:v2:env 值；明文与解密失败原样/空串返回。
    v1 派生除宿主外再尝试 extra_homes（容器来源档案的 meta home）。"""
    if not isinstance(value, str) or not value.startswith("enc:"):
        return value
    if value.startswith(_ENC_V2OS):
        pt = _aesgcm_decrypt(value[len(_ENC_V2OS):].split(":", 1)[-1], _keyring_keys())
        return pt or ""
    if value.startswith(_ENC_V1):
        keys = list(_derived_keys())
        for h in extra_homes:
            if h and h != HOME:
                keys += _derived_keys(h)
        return _aesgcm_decrypt(value[len(_ENC_V1):], keys) or ""
    if value.startswith("enc:v2:env:"):
        import os as _os
        secret = _os.environ.get("ZCODE_CREDENTIAL_SECRET")
        return _aesgcm_decrypt(value[len("enc:v2:env:"):], _derived_keys() if not secret else
                               [hashlib.sha256(secret.encode()).digest()]) or ""
    return ""


def fingerprint(value: str) -> str:
    if not isinstance(value, str):
        return "?"
    return hashlib.sha256(value.encode()).hexdigest()[:10]


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def all_meta_homes() -> tuple[str, ...]:
    """所有档案 meta 记录的 home（供 live 状态的 v1 派生解密尝试）。"""
    out = []
    if ACCOUNTS_DIR.exists():
        for m in ACCOUNTS_DIR.glob("*/meta.json"):
            h = load_json(m).get("home")
            if h and h != HOME:
                out.append(h)
    return tuple(out)


def fingerprint_of(path: Path, extra_homes: tuple[str, ...] = ()) -> str:
    """账号指纹：解密后的 user_info（刷新不变）> 明文 user_info > access_token。
    同时识别国际（oauth:zai:*）与国内（oauth:zai_cn:* bigmodel.cn）账号。"""
    data = load_json(path)
    for key in ("oauth:zai:user_info", "oauth:zai_cn:user_info"):
        ui = data.get(key)
        if isinstance(ui, str):
            plain = decrypt_value(ui, extra_homes)
            if plain:
                return fingerprint(plain)
    tok = (data.get("oauth:zai:access_token") or data.get("oauth:zai_cn:access_token")
           or data.get("zcodejwttoken") or "")
    return fingerprint(tok) if tok else ""


def account_identity(path: Path, extra_homes: tuple[str, ...] = ()) -> str:
    """解密/解析 user_info 提取展示身份（email 或名称），失败返回空串。"""
    data = load_json(path)
    for key in ("oauth:zai:user_info", "oauth:zai_cn:user_info"):
        ui = data.get(key)
        if not isinstance(ui, str):
            continue
        plain = decrypt_value(ui, extra_homes)
        if not plain:
            continue
        try:
            info = json.loads(plain)
            return info.get("email") or info.get("name") or info.get("user_id") or ""
        except Exception:
            return ""
    return ""


def account_realm(path: Path) -> str:
    """账号域：oauth:active_provider=zai_cn → cn（bigmodel.cn），zai → global。"""
    data = load_json(path)
    ap = data.get("oauth:active_provider")
    if isinstance(ap, str):
        plain = decrypt_value(ap) or ap
        if "zai_cn" in plain or "bigmodel" in plain:
            return "cn"
    if data.get("oauth:zai_cn:user_info") or data.get("oauth:zai_cn:access_token"):
        return "cn"
    return "global"


def read_current() -> str:
    try:
        return (ACCOUNTS_DIR / CURRENT_FILE).read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def write_current(name: str) -> None:
    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    p = ACCOUNTS_DIR / CURRENT_FILE
    tmp = p.with_suffix(".tmp")
    tmp.write_text(name, encoding="utf-8")
    os.replace(tmp, p)


def lock():
    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    fp = open(ACCOUNTS_DIR / ".lock", "a")
    fcntl.flock(fp, fcntl.LOCK_EX)
    return fp


def key_masks(data: dict) -> str:
    lines = []
    for k in sorted(data):
        v = data[k]
        if isinstance(v, str):
            enc = "enc:" if v.startswith("enc:") else ""
            lines.append(f"    {k:<40} {enc}{fingerprint(v)}  ({len(v)}B)")
        else:
            lines.append(f"    {k:<40} {type(v).__name__}")
    return "\n".join(lines)


def cmd_add(args: list[str]) -> int:
    name = sanitize_name(args[0] if args else die("用法: zacc add <name> [--file F]"))
    src = Path(args[args.index("--file") + 1]) if "--file" in args else live_cred()
    if not src.exists():
        die(f"源文件不存在: {src}")
    atomic_copy(src, profile_cred(name))
    print(f"[add] {src} -> {profile_cred(name)}")
    write_meta(name, {"source": str(src.resolve()), "home": infer_home(src)})
    if src == live_cred() and (V2_DIR / PROVIDER_NAME).exists():
        atomic_copy(V2_DIR / PROVIDER_NAME, profile_provider(name))
        print(f"[add] {V2_DIR / PROVIDER_NAME} -> {profile_provider(name)}")
    return 0


def cmd_save(args: list[str]) -> int:
    name = sanitize_name(args[0] if args else die("用法: zacc save <name>"))
    src = live_cred()
    if not src.exists():
        die(f"当前凭据不存在: {src}")
    atomic_copy(src, profile_cred(name))
    print(f"[save] {src} -> {profile_cred(name)}")
    if (V2_DIR / PROVIDER_NAME).exists():
        atomic_copy(V2_DIR / PROVIDER_NAME, profile_provider(name))
        print(f"[save] provider_config -> {profile_provider(name)}")
    return 0


def cmd_use(args: list[str]) -> int:
    name = sanitize_name(args[0] if args else die("用法: zacc use <name> [--keep-providers]"))
    keep_providers = "--keep-providers" in args
    dst = profile_cred(name)
    if not dst.exists():
        die(f"档案不存在: {dst}（先 zacc add/save）")
    homes = all_meta_homes()
    # 当前状态回写：有 .current 记录则写回来源档案，否则快照到 _last
    if live_cred().exists():
        origin = read_current()
        if origin and profile_cred(origin).exists() and origin != name:
            atomic_copy(live_cred(), profile_cred(origin))
            print(f"[use] 当前凭据已回写来源档案 {origin}")
        elif origin == name:
            if fingerprint_of(live_cred(), homes) != fingerprint_of(dst, homes):
                atomic_copy(live_cred(), dst)
                print(f"[use] 已同步刷新后的凭据到档案 {name}")
        else:
            atomic_copy(live_cred(), profile_cred(LAST_PROFILE))
            print(f"[use] 当前凭据已快照 -> {profile_cred(LAST_PROFILE)}")
    atomic_copy(dst, live_cred())
    write_current(name)
    print(f"[use] 已应用档案 {name} -> {live_cred()}")
    if not keep_providers and profile_provider(name).exists():
        atomic_copy(profile_provider(name), V2_DIR / PROVIDER_NAME)
        print(f"[use] 已应用 provider_config -> {V2_DIR / PROVIDER_NAME}")
    print("提示: 若 zcode 正在运行，重启后生效")
    return 0


def cmd_list(args: list[str]) -> int:
    as_json = "--json" in args
    live = fingerprint_of(live_cred(), all_meta_homes()) if live_cred().exists() else ""
    cur = read_current()
    rows: list[dict] = []
    if ACCOUNTS_DIR.exists():
        for prof in sorted(ACCOUNTS_DIR.iterdir()):
            if not prof.is_dir() or not NAME_RE.match(prof.name):
                continue
            pc = profile_cred(prof.name)
            if not pc.exists():
                continue
            home = profile_meta(prof.name).get("home", "")
            ident = account_identity(pc, (home,) if home else ())
            note = " (切换前快照)" if prof.name == LAST_PROFILE else ""
            if prof.name == cur:
                note += " [current]"
            rows.append({
                "name": prof.name,
                "fp": fingerprint_of(pc, (home,) if home else ()),
                "ident": ident,
                "home": home,
                "mtime": time.strftime("%m-%d %H:%M", time.localtime(pc.stat().st_mtime)),
                "size": pc.stat().st_size,
                "active": bool(live) and fingerprint_of(pc, (home,) if home else ()) == live,
                "current": prof.name == cur,
                "note": note.strip(),
            })
    if as_json:
        print(json.dumps(rows, ensure_ascii=False))
        return 0
    print(f"{'':<2} {'档案':<20} {'指纹':<12} {'身份':<24} 更新时间")
    if not rows:
        print("（暂无档案）")
        return 0
    for r in rows:
        mark = "●" if r["active"] else ""
        print(f"{mark:<2} {r['name']:<20} {r['fp']:<12} {r['ident']:<24} {r['mtime']}"
              + (f" {r['note']}" if r["note"] else ""))
    return 0


def cmd_current(_: list[str]) -> int:
    cur = read_current()
    if not cur:
        print("（无记录：自 add/save 后未执行过 use，当前指向未知）")
        return 1
    print(cur)
    return 0


def cmd_show(args: list[str]) -> int:
    name = sanitize_name(args[0] if args else die("用法: zacc show <name>"))
    pc = profile_cred(name)
    if not pc.exists():
        die(f"档案不存在: {pc}")
    data = load_json(pc)
    ident = account_identity(pc, (profile_meta(name).get("home") or "",))
    print(f"{pc}" + (f"  ({ident})" if ident else ""))
    print(key_masks(data))
    return 0


def profile_meta(name: str) -> dict:
    return load_json(ACCOUNTS_DIR / name / "meta.json")


def write_meta(name: str, meta: dict) -> None:
    p = ACCOUNTS_DIR / name / "meta.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, p)


def infer_home(source: Path) -> str:
    """由凭据文件路径推断所属 HOME（容器档案 → 容器 home）。"""
    s = str(source.resolve())
    marker = "/.zcode/v2/credentials.json"
    if s.endswith(marker):
        return s[: -len(marker)] or str(HOME)
    return str(HOME)


def cmd_ident(args: list[str]) -> int:
    name = sanitize_name(args[0] if args else die("用法: zacc ident <name>"))
    pc = profile_cred(name)
    if not pc.exists():
        die(f"档案不存在: {pc}")
    ident = account_identity(pc, (profile_meta(name).get("home") or "",))
    print(ident if ident else "（无法解密身份：keyring 未解锁/密钥缺失/非加密格式）")
    return 0 if ident else 1


def cmd_exec(args: list[str]) -> int:
    if "--" not in args:
        die("用法: zacc exec <name> -- <cmd...>")
    i = args.index("--")
    name, cmd = args[0], args[i + 1:]
    if not cmd:
        die("exec: 命令为空")
    if os.environ.get("ZCODE_DATA_BASE_DIR"):
        die("exec: 外层已设置 ZCODE_DATA_BASE_DIR，禁止嵌套")
    ddir = profile_data_dir(name)
    if not profile_cred(name).exists():
        die(f"档案不存在: {profile_cred(name)}（先 zacc add/save）")
    env = dict(os.environ)
    env["ZCODE_DATA_BASE_DIR"] = str(ddir)
    # 容器来源档案：自动注入原 HOME（用户显式 HOME= 前缀时以用户为准）
    meta_home = profile_meta(name).get("home") or ""
    has_home_arg = any(a == "HOME" or a.startswith("HOME=") for a in cmd)
    if meta_home and meta_home != HOME and os.environ.get("HOME", HOME) != meta_home and not has_home_arg:
        env["HOME"] = meta_home
        print(f"[exec] 注入 HOME={meta_home}", file=sys.stderr)
    return subprocess.run(cmd, env=env).returncode


def cmd_where(args: list[str]) -> int:
    name = sanitize_name(args[0] if args else die("用法: zacc where <name>"))
    print(profile_cred(name))
    return 0


def cmd_rm(args: list[str]) -> int:
    name = sanitize_name(args[0] if args else die("用法: zacc rm <name>"))
    d = ACCOUNTS_DIR / name
    if not d.is_dir():
        die(f"档案不存在: {d}")
    shutil.rmtree(d)
    if read_current() == name:
        os.remove(ACCOUNTS_DIR / CURRENT_FILE)
    print(f"[rm] 已删除 {d}")
    return 0


def die(msg: str):
    print(msg, file=sys.stderr)
    sys.exit(2)


CMDS = {
    "add": cmd_add, "use": cmd_use, "save": cmd_save, "list": cmd_list,
    "current": cmd_current, "show": cmd_show, "ident": cmd_ident, "exec": cmd_exec,
    "where": cmd_where, "rm": cmd_rm,
}


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    fn = CMDS.get(argv[0]) or die(f"未知命令: {argv[0]}（可选: {', '.join(CMDS)}）")
    if argv[0] == "exec":
        return fn(argv[1:])  # exec 不持锁，长会话不阻塞其它 zacc 命令
    lk = lock()
    try:
        return fn(argv[1:])
    finally:
        fcntl.flock(lk, fcntl.LOCK_UN)
        lk.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
