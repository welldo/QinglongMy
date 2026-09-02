#!/bin/env python3
# -*- coding: utf-8 -*
"""
# cron: 33 0 * * * minimax_checkin.py
# new Env('MiniMax Code 每日签到');

==================== MiniMax Code 自动签到 ====================

相关端点（逆向自 MiniMax Code 桌面端 app.asar + 本机 api-*.log 实测）：
    续期登录  {host}/v1/api/user/renewal               (POST, body {}) -> {"data":{"token":"新JWT"}}
    状态查询  {host}/minimax-cloud/api/v1/signin/status (GET)
    领取积分  {host}/minimax-cloud/api/v1/signin/claim  (POST, body {})

【先续期再签到（本次核心优化）】
桌面端每次启动都会调 /v1/api/user/renewal 用旧 token 换新 token（新 token 有效期
顺延 ~40 天）。本脚本把这一步搬进签到流程：**每次运行先续期，再拿新 token 签到**，
并把新 token 写回同目录缓存文件 .minimax_token.json（青龙环境里环境变量改不动，
但脚本目录可写，缓存能让 token 一直保持新鲜，永不续期失败）。

流程：
    env token ──(有效?)──> renewal ──> 新 token ──> 写回缓存/.env ──> status ──> claim
                              │
                              └─ 401/异常 ──> 回落到缓存 token 再试一次 ──> 仍失败则如实上报

【为什么服务器上会 401（本地实测结论）】
    * 正常 token          -> HTTP 200
    * 空 / 截断 / 带引号  -> HTTP 401 且响应体为空（与服务器上报的现象完全一致）
    * x-timestamp 拨快拨慢 24 小时 -> 仍 200（说明**不是**签名/时钟问题）
    * renewal 用非法 token -> HTTP 401 {"statusInfo":{"code":1000021,"msg":"异常用户访问"}}
因此 401 基本只可能是 **token 本身不对**（过期/被截断/粘贴时带引号/串号），
本脚本会在失败信息里直接打印 token 剩余有效期与服务端原始报错，一眼可定位。

【DNS 污染（服务器/被管控网络跑总失败的真正元凶）】
实测发现：在被管控的服务器/网关上，`agent.minimax.io` 会被本地 DNS 解析到假 IP
（如 `198.20.0.x` 拦截网关，连接时 TLS 证书不匹配），表现为「连不上 / 偶发 401」，
**与 token 是否过期无关**（token 明明还有几十天有效却连不到真服务器）。
本脚本已内置【反 DNS 污染】回退：默认域名直连；一旦连接层失败，自动用 DoH
（dns.google，直连 8.8.8.8:443，不受本地污染 DNS 影响）解析出 Akamai 真实边缘 IP，
再以「真实 IP 直连 + Host 头=域名」绕过。如 DoH 也不可达，可手动设置环境变量
MINIMAX_REAL_IP=<真实IPv4> 强制指定（可在本机 `nslookup agent.minimax.io 8.8.8.8` 或
通过 DoH 取得）。

【签名机制（逆向 app.asar 结论）】
桌面端在 axios 请求拦截器中对每个请求计算两套签名头：

  (1) x-timestamp : 秒级时间戳 = floor(Date.parse(new Date())/1000)
  (2) x-signature : md5("{x_timestamp}I*7Cf%WZ#S&%1RlZJ&C2{body}")
                      —— GET 时 body 为空串 ""，POST/claim 时 body 为 "{}"
                      —— 已与抓包日志逐字节验证一致 ✅
  (3) yy          : md5( encodeURIComponent(hasSearchParamsPath)
                         + "_" + "{}"
                         + md5(String(time_ms)) + "ooui" )
                      —— hasSearchParamsPath = path + "?" + URLSearchParams(params)
                         params 为设备参数字典（见 DEVICE_PARAMS 顺序），末尾追加 client=desktop
                         time_ms 与 params.unix 取同一毫秒值
                         （该结构已在 app.asar 两处独立源码确认）

鉴权头： token: <本地 JWT>（HS256，存于 minimax-agent-config.json -> tokens.accessToken）
         —— 注意 token 仅出现在 HTTP 头，绝不进入签名用的 URL/yy 计算

【方式一 · 推荐：环境变量（脚本默认读取来源）】
在 .env 或运行环境中设置：
    MINIMAX_TOKEN=<tokens.accessToken>
    MINIMAX_USER_ID=<realUserID>
    MINIMAX_UUID=<设备 uuid，可选，留空则回落脚本内置稳定默认值>
    MINIMAX_DEVICE_ID=<数字设备 id，可选，留空则回落脚本内置稳定默认值>
脚本【默认只读取上述环境变量】，不再自动读取本机登录态，方便容器 / 跨机 / 青龙部署。
环境变量值会自动去除首尾空白与误粘贴的引号（青龙面板最常见的 401 元凶）。

【方式二 · 刷新 token：--export-env（仅本机、不进入默认运行链）】
token 过期时，在本机（已登录 MiniMax Agent 桌面端）执行：
    python minimax_checkin.py --export-env
会读取本机登录态、先续期再打印最新变量；追加 --save 可直接写回 .env：
    python minimax_checkin.py --export-env --save

【方式三 · 只续期：--renew（任意机器，只要当前 token 还有效）】
    python minimax_checkin.py --renew            # 续期并打印
    python minimax_checkin.py --renew --save     # 续期并写回 .env + 缓存
适合"本机 token 还有效、只想把服务器上的 token 换新的"场景。

本机登录态文件（仅供参考，不参与默认运行）：
    %APPDATA%\\MiniMax Agent\\minimax-agent-config.json  （键 tokens.accessToken）

依赖：pip install requests

声明：仅供学习与个人使用。MiniMax Code / MiniMax Agent 是 MiniMax 旗下产品，
本脚本与其无任何关联，使用产生的任何后果（账号风控、封禁等）由使用者自行承担。
============================================================================================
"""

import os
import sys
import json
import time
import hashlib
import re
import base64
import urllib.parse
from datetime import datetime, timezone

import requests
import urllib3

import subprocess
import shutil
import atexit
import tempfile

# MiniMax 域名在某些网络环境（如被管控的服务器/网关）会被 DNS 污染到假 IP，
# 导致连接失败。绕过方案：连接层失败时改用 DoH 动态解析真实 IP 直连（见 api_call）。
# 直连 IP 时 SNI 与证书 CN 不匹配，需关闭证书校验（仅跳过校验，Host 头仍指向真实域名）。
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 本地开发时自动加载同目录 .env；已设置的环境变量优先，不受影响。
# python-dotenv 为本项目依赖（见 requirements.txt），统一用官方库加载，不做自定义兜底。
from dotenv import load_dotenv
load_dotenv()

# 通知模块（同目录 sendNotify.py）；缺失则降级为仅打印
try:
    import sendNotify
    _HAS_NOTIFY = True
except Exception:
    _HAS_NOTIFY = False


def _save_env_values(values: dict):
    """把导出的环境变量写回同目录 .env（仅更新/追加给定 key，保留其它内容）。
    仅 --export-env --save / --renew --save 时调用。返回写入的变量数（0 表示失败）。"""
    env_path = os.path.join(BASE_DIR, ".env")
    lines = []
    if os.path.isfile(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except Exception:
            lines = []
    updated = set()
    out = []
    for line in lines:
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if m and m.group(1) in values:
            out.append(f"{m.group(1)}={values[m.group(1)]}")
            updated.add(m.group(1))
        else:
            out.append(line)
    for k, v in values.items():
        if k not in updated:
            out.append(f"{k}={v}")
    try:
        with open(env_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
        return len(values)
    except Exception as e:
        print(f"[warn] 写入 .env 失败: {e}")
        return 0


# ===== 端点常量 =====
HOST = "https://agent.minimax.io"
RENEW_PATH = "/v1/api/user/renewal"          # 续期登录：旧 token 换新 token
STATUS_PATH = "/minimax-cloud/api/v1/signin/status"
CLAIM_PATH = "/minimax-cloud/api/v1/signin/claim"

# 续期得到的新 token 缓存（脚本同目录）。青龙改不动环境变量，但脚本目录可写，
# 靠这个缓存让 token 每次运行都滚动续期。设 MINIMAX_NO_CACHE=1 可关闭。
CACHE_FILE = os.path.join(BASE_DIR, ".minimax_token.json")

# 默认本机登录态配置文件（Windows）。可用 MINIMAX_CONFIG_PATH 覆盖。
DEFAULT_CONFIG_REL = os.path.join("MiniMax Agent", "minimax-agent-config.json")

# 设备参数顺序严格对齐桌面端 mC() 构建顺序（影响 yy 签名）
DEVICE_PARAM_ORDER = [
    "device_platform", "biz_id", "app_id", "version_code", "unix",
    "timezone_offset", "is_desktop", "desktop_version", "sys_language",
    "lang", "uuid", "device_id", "os_name", "browser_name", "device_memory",
    "cpu_core_num", "browser_language", "browser_platform", "user_id",
    "op_ticket", "screen_width", "screen_height",
]


# ===== 签名工具 =====

def _md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def encode_uri_component(s: str) -> str:
    """忠实复刻 JavaScript 的 encodeURIComponent：
    仅放行 A-Z a-z 0-9 以及 - _ . ! ~ * ' ( )，其余按 %XX（大写）编码。"""
    return re.sub(
        r'([^A-Za-z0-9\-_.!~*\'()])',
        lambda m: '%%%02X' % ord(m.group(1)),
        s,
    )


def build_device_params(user_id: str, uuid_str: str, device_id: str) -> dict:
    """构建设备参数字典（严格保持 DEVICE_PARAM_ORDER 顺序）。"""
    now_ms = int(round(datetime.now(timezone.utc).timestamp() * 1000))
    values = {
        "device_platform": "web",
        "biz_id": "3",
        "app_id": "3001",
        "version_code": "22201",
        "unix": str(now_ms),
        "timezone_offset": "28800",
        "is_desktop": "1",
        "desktop_version": "",
        "sys_language": "en",
        "lang": "en",
        "uuid": uuid_str,
        "device_id": device_id,
        "os_name": "Windows",
        "browser_name": "Chrome",
        "device_memory": "16",
        "cpu_core_num": "4",
        "browser_language": "zh-CN",
        "browser_platform": "Win32",
        "user_id": str(user_id),
        "op_ticket": "undefined",
        "screen_width": "1536",
        "screen_height": "864",
    }
    return {k: values[k] for k in DEVICE_PARAM_ORDER}


def _sign_request(path: str, token: str, params: dict, method: str, body: dict):
    """对单个请求计算签名所需的 query 串、请求头与 body 串。返回 (url_query, headers, body_str)。"""
    now_ms = int(round(datetime.now(timezone.utc).timestamp() * 1000))
    now_sec = now_ms // 1000

    # 设备参数里 unix 必须与 now_ms 完全一致（yy 内部 md5 也用同一毫秒值）
    params = dict(params)
    params["unix"] = str(now_ms)
    params["client"] = "desktop"   # 拦截器末尾追加 client=desktop

    query = urllib.parse.urlencode(params)  # 与 requests 发送时的序列化一致
    has_search_params_path = f"{path}?{query}"

    # body 串：GET 为 ""，POST 为 JSON 串
    body_str = "" if method.lower() == "get" else json.dumps(body or {}, ensure_ascii=False)

    # x-signature = md5("{now_sec}I*7Cf%WZ#S&%1RlZJ&C2{body_str}")
    x_signature = _md5_hex(f"{now_sec}I*7Cf%WZ#S&%1RlZJ&C2{body_str}")

    # yy = md5( encodeURIComponent(hasSearchParamsPath) + "_" + "{}" + md5(str(now_ms)) + "ooui" )
    inner = _md5_hex(str(now_ms))
    yy = _md5_hex(encode_uri_component(has_search_params_path) + "_" + "{}" + inner + "ooui")

    headers = {
        "token": token,
        "yy": yy,
        "x-timestamp": str(now_sec),
        "x-signature": x_signature,
        "origin": "https://agent.minimax.io",
        "referer": "https://agent.minimax.io/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) MiniMaxAgent/desktop Chrome/124.0 Safari/537.36",
    }
    if method.lower() != "get":
        headers["content-type"] = "application/json"
    return params, headers, body_str


# ===== JWT 本地解析（用于判断 token 是否过期、给出可读诊断） =====

def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def decode_token(token: str):
    """本地解析 JWT（不校验签名，只读 exp / user.id）。
    返回 (exp_ts, user_id)；非 JWT 或解析失败返回 (0, "")。"""
    try:
        parts = str(token or "").split(".")
        if len(parts) != 3:
            return 0, ""
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        exp = int(payload.get("exp") or 0)
        uid = str(((payload.get("user") or {}).get("id")) or "")
        return exp, uid
    except Exception:
        return 0, ""


def token_exp_text(token: str) -> str:
    """把 token 有效期翻译成人话，供失败诊断使用。"""
    exp, _ = decode_token(token)
    if not exp:
        return "token 不是合法 JWT（疑似被截断 / 粘贴时带引号 / 复制不全）"
    delta = exp - time.time()
    if delta > 0:
        return f"token 剩余 {delta / 86400:.1f} 天有效"
    return f"token 已于 {-delta / 86400:.1f} 天前过期，必须重新 --export-env"


def clean_env_value(raw: str) -> str:
    """清洗环境变量：去首尾空白、去误粘贴的成对引号、去零宽/BOM 字符。"""
    if raw is None:
        return ""
    s = str(raw).strip().strip("\ufeff").strip()
    while len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1].strip()
    return s


# ===== token 缓存（青龙环境自愈的关键） =====

def _cache_enabled() -> bool:
    return os.environ.get("MINIMAX_NO_CACHE", "").strip() not in ("1", "true", "True")


def load_token_cache() -> str:
    if not _cache_enabled():
        return ""
    try:
        if not os.path.isfile(CACHE_FILE):
            return ""
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return clean_env_value(data.get("token") or "")
    except Exception as e:
        print(f"[warn] 读取 token 缓存失败: {e}")
        return ""


def save_token_cache(token: str, source: str = "renewal") -> bool:
    if not _cache_enabled() or not token:
        return False
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump({"token": token, "source": source,
                       "updated_at": int(time.time())}, fh)
        return True
    except Exception as e:
        print(f"[warn] 写入 token 缓存失败: {e}")
        return False


def persist_token(token: str, source: str = "renewal") -> list:
    """续期成功后落盘：缓存（青龙靠它）+ .env（本机靠它）。返回写入位置列表。"""
    saved = []
    if save_token_cache(token, source):
        saved.append("缓存")
    if os.environ.get("MINIMAX_SAVE_ENV", "1").strip() not in ("0", "false", "False"):
        if _save_env_values({"MINIMAX_TOKEN": token}):
            saved.append(".env")
    return saved


# ===== 凭据解析 =====

def read_local_credential():
    """读取本机 MiniMax Agent 登录态（tokens.accessToken）。"""
    cfg_path = os.environ.get("MINIMAX_CONFIG_PATH", "").strip() or \
        os.path.join(os.environ.get("APPDATA", ""), DEFAULT_CONFIG_REL)
    if not cfg_path or not os.path.isfile(cfg_path):
        return None
    try:
        with open(cfg_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        token = ((data.get("tokens") or {}).get("accessToken") or "").strip()
        if not token:
            return None
        user = data.get("user") or {}
        return {
            "token": token,
            "user_id": str(user.get("realUserID") or user.get("userID") or "").strip(),
            "user_name": (user.get("userName") or "").strip(),
            "mail": (user.get("userMail") or "").strip(),
        }
    except Exception as e:
        print(f"[warn] 解析 {cfg_path} 失败: {e}")
        return None


# 稳定的默认设备身份：仅在未设置对应环境变量时回落使用，避免每次随机导致设备指纹漂移。
# 如需更换，可在 .env / 运行环境中设置 MINIMAX_UUID 与 MINIMAX_DEVICE_ID 覆盖。
_DEFAULT_UUID = "3548c8fa-9ac2-4a28-8f6b-71ecd88bc048"
_DEFAULT_DEVICE_ID = "1790426211"


def load_persistent_device():
    """返回稳定的 uuid 与数字 device_id。
    优先取环境变量 MINIMAX_UUID / MINIMAX_DEVICE_ID（便于跨机/容器部署）；
    未设置时回落到脚本内写死的稳定常量。不再读写任何缓存文件。"""
    uid = clean_env_value(os.environ.get("MINIMAX_UUID", ""))
    did = clean_env_value(os.environ.get("MINIMAX_DEVICE_ID", ""))
    if uid and did:
        return uid, did
    return (uid or _DEFAULT_UUID), (did or _DEFAULT_DEVICE_ID)


def _token_alive(token: str) -> bool:
    """token 非空且（若是 JWT）未过期。"""
    if not token:
        return False
    exp, _ = decode_token(token)
    if exp == 0:
        return True          # 非 JWT，交给服务端判断
    return exp - time.time() > 60


def resolve_credentials():
    """读取环境变量（并按需回落到续期缓存），返回凭据 dict。
    - env token 有效  -> 直接用（先 env 后缓存的顺序在 checkin 里兜底重试）
    - env token 缺失/已过期 -> 用缓存里上次续期成功的 token
    - 都没有          -> 原样返回，由 checkin 阶段报 NO_CREDENTIAL / AUTH_EXPIRED"""
    env_token = clean_env_value(os.environ.get("MINIMAX_TOKEN", ""))
    cache_token = load_token_cache()
    token = env_token
    source = "env"
    if not _token_alive(env_token) and _token_alive(cache_token):
        token, source = cache_token, "cache"
    return {
        "token": token,
        "env_token": env_token,
        "cache_token": cache_token,
        "source": source,
        "user_id": clean_env_value(os.environ.get("MINIMAX_USER_ID", "")),
        "user_name": "",
        "mail": "",
    }


def _candidate_tokens(cred: dict):
    """生成待尝试的 token 列表 [(token, 来源标签)]，已过期的排后面、去重。"""
    env_t = clean_env_value(cred.get("env_token") or cred.get("token") or "")
    cache_t = clean_env_value(cred.get("cache_token") or "")
    ordered = []
    if _token_alive(env_t):
        ordered.append((env_t, "环境变量"))
    if cache_t and cache_t != env_t and _token_alive(cache_t):
        ordered.append((cache_t, "缓存"))
    for t, tag in ((env_t, "环境变量"), (cache_t, "缓存")):
        if t and t not in [x[0] for x in ordered]:
            ordered.append((t, tag))
    return ordered


# ===== 业务解析 =====

AUTH_FAIL_KEYWORDS = ("unauthorized", "token", "expired", "not login",
                      "not logged", "登录", "鉴权", "invalid", "异常用户")
RATE_LIMIT_KEYWORDS = ("频繁", "frequent", "too many", "太多", "稍后再试",
                       "繁忙", "busy", "limit")


def api_succeeded(data: dict) -> bool:
    if not isinstance(data, dict):
        return False
    # MiniMax 约定：base_resp.status_code == 0 表示业务成功
    br = data.get("base_resp") or {}
    if isinstance(br, dict) and br.get("status_code") == 0:
        return True
    code = data.get("code")
    if isinstance(code, (int, float)) and code in (0, 200):
        return True
    if isinstance(code, str) and code.strip() in ("0", "200"):
        return True
    if data.get("success") is True:
        return True
    return str(data.get("status", "")).lower() == "success"


def server_message(data) -> str:
    """从各种响应结构里抠出服务端给的文案，便于如实上报。"""
    if not isinstance(data, dict):
        return ""
    si = data.get("statusInfo") or {}
    if isinstance(si, dict) and si.get("message"):
        return str(si["message"])
    br = data.get("base_resp") or {}
    if isinstance(br, dict) and br.get("status_msg") and br.get("status_code") not in (0, None):
        return f"{br.get('status_msg')}(code={br.get('status_code')})"
    return str(data.get("message") or data.get("msg") or "")


def is_auth_failure(http_status: int, data) -> bool:
    if http_status in (401, 403):
        return True
    if not isinstance(data, dict):
        return False
    try:
        code = int(str(data.get("code")))
        if code in (401, 403):
            return True
    except (TypeError, ValueError):
        pass
    si = data.get("statusInfo") or {}
    if isinstance(si, dict):
        try:
            if int(str(si.get("code"))) in (1000021, 1000022, 1000023):
                return True
        except (TypeError, ValueError):
            pass
    msg = str(data.get("message") or data.get("msg") or "").lower()
    if any(k in msg for k in RATE_LIMIT_KEYWORDS):
        return False
    return any(k.lower() in msg for k in AUTH_FAIL_KEYWORDS)


def is_rate_limited(http_status: int, data) -> bool:
    if http_status in (429, 500, 502, 503, 504):
        return True
    if not isinstance(data, dict):
        return False
    msg = str(data.get("message") or data.get("msg") or "")
    return any(k in msg for k in RATE_LIMIT_KEYWORDS)


# ===== 反 DNS 污染：连接失败时改用真实 IP 直连 =====
# 某些网络（被管控的服务器/网关）会把 agent.minimax.io 解析到假 IP（如 198.20.0.x 拦截网关），
# 导致连接失败或伪 401。此时运行时解析出 Akamai 真实边缘 IP，再用「真实 IP 直连 +
# Host 头=域名 + verify=False」绕过。Akamai IP 动态变化，故必须运行时解析，不可硬编码。
# 解析优先走「原始 UDP/53 直连公共解析器」（绕过本地被污染的递归解析器，且多数网络
# 即便封锁 8.8.8.8:443 也放行 UDP/53）；UDP 不可达时再用 HTTPS DoH 兜底。
import socket as _sock
import struct as _struct
import base64 as _b64

_RESOLVED = {}   # 进程内缓存：domain -> 已验证可用的真实 IP
_POISON_PREFIX = "198.20.0."   # 已知拦截网关网段，解析到此处视为污染，直接跳过


def _domain_of(host: str) -> str:
    return host.split("//", 1)[-1].split("/", 1)[0] or host


def _dns_query_wire(domain: str) -> bytes:
    """构造一条 A 记录查询报文（DNS 线格式），供 UDP 直连与 HTTPS DoH 复用。"""
    txid = b"\x13\x57"
    header = txid + _struct.pack(">H", 0x0100) + _struct.pack(">H", 1) + b"\x00\x00\x00\x00\x00\x00"
    q = b""
    for label in domain.split("."):
        q += bytes([len(label)]) + label.encode("ascii")
    q += b"\x00" + _struct.pack(">H", 1) + _struct.pack(">H", 1)   # QTYPE=A, QCLASS=IN
    return header + q


def _parse_a_records(data: bytes):
    """从 DNS 响应里抽出所有 A 记录 IPv4（兼容响应中的名称压缩指针）。"""
    if len(data) < 12:
        return []
    n = _struct.unpack(">H", data[6:8])[0]
    i = 12
    while i < len(data) and data[i] != 0 and not (data[i] & 0xC0):
        i += 1
    if i >= len(data):
        return []
    i += 1 + 4   # 结尾 0 + QTYPE(2) + QCLASS(2)
    ips = []
    for _ in range(n):
        if i >= len(data):
            break
        if data[i] & 0xC0:
            i += 2
        else:
            while i < len(data) and data[i] != 0:
                i += 1
            i += 1
        if i + 10 > len(data):
            break
        typ, _cls, _ttl, rdlen = _struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if typ == 1 and rdlen == 4 and i + 4 <= len(data):
            ips.append(".".join(str(b) for b in data[i:i + 4]))
        i += rdlen
    return ips


_UDP_RESOLVERS = ["223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"]


def _udp_resolve(domain: str):
    """原始 UDP/53 直连公共解析器，绕过本地被污染的递归解析器。失败返回 []。"""
    pkt = _dns_query_wire(domain)
    for r in _UDP_RESOLVERS:
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(pkt, (r, 53))
            data, _ = s.recvfrom(4096)
            s.close()
            ips = _parse_a_records(data)
            if ips:
                return ips
        except Exception:
            try:
                s.close()
            except Exception:
                pass
    return []


# DoH 供应商：(url, 线格式?, 是否走系统代理?)。
# - 主机名类（cloudflare-dns.com / dns.google）走系统代理，且依赖「网关只毒特定域名」的假设：
#   若管控网关仅劫持 agent.minimax.io、不劫持这些 DoH 主机名，则它们能解析出真实 IP。
# - IP 类（223.5.5.5 / 8.8.8.8）强制直连（proxies=None），用于能直连公共解析器的网络。
_DOH_PROVIDERS = [
    ("https://cloudflare-dns.com/dns-query", True, True),   # 主机名，走系统代理
    ("https://dns.google/resolve", False, True),             # 主机名，走系统代理
    ("https://223.5.5.5/dns-query", True, False),            # 阿里 AliDNS DoH（线格式 dns=）
    ("https://8.8.8.8/resolve", False, False),               # Google DoH（name/type 格式）
]

# 最后兜底：当前（解析时）有效的 Akamai 边缘 IP。Akamai 边缘会轮换，故仅当 UDP/53 与
# 全部 DoH 均不可达时才用；api_call 回退循环会跳过污染网段与 nginx 404 的死边缘。
_FALLBACK_IPS = ["2.16.168.107", "2.16.168.102", "23.46.216.82", "23.32.91.196", "23.32.91.197"]


def _doh_resolve(domain: str):
    """HTTPS DoH 解析真实 IPv4（UDP/53 不可达时的兜底）。失败返回 []。"""
    wire = _b64.urlsafe_b64encode(_dns_query_wire(domain)).rstrip(b"=").decode()
    last_err = ""
    for url, wire_fmt, use_proxy in _DOH_PROVIDERS:
        try:
            if wire_fmt:
                params, headers = {"dns": wire}, {"Accept": "application/dns-message"}
            else:
                params, headers = {"name": domain, "type": "A"}, {"Accept": "application/dns-json"}
            proxies = None if not use_proxy else {}   # use_proxy=True 时让 requests 用环境代理
            r = requests.get(url, params=params, headers=headers,
                             timeout=10, verify=False, proxies=proxies)
            ips = []
            try:
                j = r.json()   # Google 等返回 JSON
                ips = [a["data"] for a in j.get("Answer", []) if a.get("type") == 1]
            except Exception:
                # AliDNS / Cloudflare 等可能返回二进制 application/dns-message，按线格式解析
                ips = _parse_a_records(r.content)
            if ips:
                return ips
        except Exception as e:
            last_err = f"{url}: {e}"
    if last_err:
        print(f"[miniMax] DoH 兜底解析 {domain} 失败：{last_err}")
    return []


def _resolve_real_ips(host: str):
    """返回真实 IP 候选列表（按成功率排序）：
    MINIMAX_REAL_IP 手动覆盖 > 主机名 DoH > UDP/53 > IP DoH > 内置兜底 IP。"""
    manual = clean_env_value(os.environ.get("MINIMAX_REAL_IP", ""))
    if manual:
        return [manual]
    domain = _domain_of(host)
    ips = _doh_resolve(domain)          # 主机名 DoH 优先（可能绕过仅毒特定域名的网关）
    if ips:
        print(f"[miniMax] DoH 解析 {domain} -> {ips}")
        return ips
    ips = _udp_resolve(domain)
    if ips:
        print(f"[miniMax] UDP/53 解析 {domain} -> {ips}")
        return ips
    if _FALLBACK_IPS:
        print(f"[miniMax] 解析均不可达，使用内置兜底 IP：{_FALLBACK_IPS}")
    return list(_FALLBACK_IPS)


# ===== 经代理出网（绕过透明 TLS 拦截网关）=====
# 当服务器出口被网关(198.20.0.6)全阻断（所有真实 IP 均 nginx 404）时，可经一个 VLESS
# 代理干净出网。做法：用 xray-core 把 vless 配置在本地拉起 HTTP 代理(127.0.0.1:10808)，
# 再让 requests 走该本地代理。用 http inbound（非 socks），无需 PySocks。
# 配置来源（任选其一，优先级高者优先）：
#   MINIMAX_PROXY : 已运行的本地代理 URL，如 http://127.0.0.1:10808
#                   （你自行起好 xray/v2ray 时填，脚本不再拉进程）
#   MINIMAX_VLESS : 一段 vless://... 链接，脚本自动拉起 xray-core 建本地代理
_PROXIES = None          # requests 代理 dict，start_proxy_from_env() 设置
_PROXY_PROC = None       # xray 子进程句柄
_PROXY_CFG = None        # xray 临时配置文件


def _find_xray():
    """在 PATH 与常见安装位置找 xray / vray 可执行文件；找不到返回 None。"""
    for name in ("xray", "xray.exe", "v2ray", "v2ray.exe"):
        p = shutil.which(name)
        if p:
            return p
    for cand in ("/usr/local/bin/xray", "/usr/bin/xray", "/ql/xray",
                 "/usr/local/bin/v2ray", "/usr/bin/v2ray"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _parse_vless_url(url: str):
    """解析 vless://uuid@host:port?query#tag -> dict。失败抛 ValueError。"""
    if not url.startswith("vless://"):
        raise ValueError("不是 vless:// 链接")
    body = url[len("vless://"):]
    if "#" in body:
        body = body.split("#", 1)[0]
    if "?" in body:
        addr, query = body.split("?", 1)
    else:
        addr, query = body, ""
    if "@" not in addr:
        raise ValueError("vless 链接缺少 @（应为 vless://uuid@host:port）")
    uuid, hostport = addr.split("@", 1)
    if ":" not in hostport:
        raise ValueError("vless 链接缺少端口")
    server, port = hostport.rsplit(":", 1)
    q = urllib.parse.parse_qs(query)
    get = lambda k, d="": (q.get(k, [d])[0] if q.get(k) else d)
    return {
        "uuid": uuid,
        "server": server,
        "port": int(port),
        "security": get("security", "tls"),
        "net": get("type", "ws"),
        "host": get("host", server),
        "sni": get("sni", get("host", server)),
        "path": get("path", "/"),
        "fp": get("fp", ""),
        "encryption": get("encryption", "none"),
    }


def _build_xray_config(v: dict, local_port: int):
    """由 vless 参数生成 xray-core 配置（本地 http inbound + vless outbound）。"""
    tls_settings = {"serverName": v["sni"]}
    if v["fp"]:
        tls_settings["fingerprint"] = v["fp"]      # uTLS 指纹，匹配客户端 fp=chrome
    out = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": v["server"],
                "port": v["port"],
                "users": [{"id": v["uuid"], "encryption": v["encryption"], "flow": ""}],
            }],
        },
        "streamSettings": {
            "network": v["net"],
            "security": v["security"],
            "tlsSettings": tls_settings,
        },
    }
    if v["net"] == "ws":
        out["streamSettings"]["wsSettings"] = {
            "path": v["path"] or "/",
            "headers": {"Host": v["host"] or v["server"]},
        }
    elif v["net"] == "grpc":
        out["streamSettings"]["grpcSettings"] = {"serviceName": v["path"].lstrip("/")}
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "protocol": "http",
            "listen": "127.0.0.1",
            "port": local_port,
            "settings": {},
        }],
        "outbounds": [out, {"protocol": "freedom", "tag": "direct"}],
    }


def _wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(1)
            s.connect(("127.0.0.1", port))
            s.close()
            return True
        except Exception:
            time.sleep(0.5)
    return False


def ensure_vless_proxy(vless_url: str, local_port: int = 10808):
    """拉起 xray-core 本地 HTTP 代理。成功返回 proxies dict，失败返回 None。"""
    binp = _find_xray()
    if not binp:
        print("[miniMax] 未找到 xray/v2ray 可执行文件，无法经代理出网。\n"
              "          安装：bash <(curl -L https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)\n"
              "          或自行起好代理后把地址填入 MINIMAX_PROXY。")
        return None
    try:
        v = _parse_vless_url(vless_url)
    except Exception as e:
        print(f"[miniMax] 解析 vless 链接失败：{e}")
        return None
    cfg = _build_xray_config(v, local_port)
    fd, cfgpath = tempfile.mkstemp(suffix=".json", prefix="xray_minimax_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)
    try:
        proc = subprocess.Popen([binp, "-c", cfgpath],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[miniMax] 启动 xray 失败：{e}")
        os.remove(cfgpath)
        return None
    if not _wait_port(local_port, 20):
        print("[miniMax] xray 已启动但本地代理端口未就绪（配置或网络问题），放弃代理出网")
        try:
            proc.terminate()
        except Exception:
            pass
        os.remove(cfgpath)
        return None
    print(f"[miniMax] 已用 xray({binp}) 在 127.0.0.1:{local_port} 拉起本地 HTTP 代理（vless→{v['server']}:{v['port']}）")
    global _PROXY_PROC, _PROXY_CFG
    _PROXY_PROC = proc
    _PROXY_CFG = cfgpath
    atexit.register(stop_proxy)
    return {"http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}"}


def start_proxy_from_env():
    """读环境变量决定代理方式，设置模块全局 _PROXIES。返回是否启用。"""
    global _PROXIES
    if _PROXIES is not None:
        return True
    explicit = clean_env_value(os.environ.get("MINIMAX_PROXY", ""))
    if explicit:
        _PROXIES = {"http": explicit, "https": explicit}
        print(f"[miniMax] 使用显式代理：{explicit}")
        return True
    vless = clean_env_value(os.environ.get("MINIMAX_VLESS", ""))
    if vless:
        p = ensure_vless_proxy(vless)
        if p:
            _PROXIES = p
            return True
    return False


def stop_proxy():
    """清理 xray 子进程与临时配置文件。"""
    global _PROXY_PROC, _PROXY_CFG
    if _PROXY_PROC is not None:
        try:
            _PROXY_PROC.terminate()
        except Exception:
            pass
        _PROXY_PROC = None
    if _PROXY_CFG and os.path.exists(_PROXY_CFG):
        try:
            os.remove(_PROXY_CFG)
        except Exception:
            pass
        _PROXY_CFG = None


def _do_request(connect_base, token, params, path, method, body, timeout, host_header=None, verify=True, proxies=None):
    """单次请求：计算签名 -> 发送 -> 返回 (status_code, json_or_raw)。"""
    signed_params, headers, body_str = _sign_request(path, token, params, method, body)
    if host_header:
        headers["Host"] = host_header
    url = f"{connect_base}{path}"
    # 用 PreparedRequest 精确控制最终发出的 header，避免 requests 自动注入多余默认值
    req = requests.Request(method.upper(), url, params=signed_params,
                            headers=headers, data=body_str or None)
    prepared = req.prepare()
    if host_header:
        prepared.headers["Host"] = host_header
    try:
        session = requests.Session()
        # proxies=None 时回落到模块全局 _PROXIES（若已配置代理）；否则强制直连
        if proxies is None:
            proxies = _PROXIES or {"http": None, "https": None}
        r = session.send(prepared, timeout=timeout, proxies=proxies, verify=verify)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"raw": r.text[:300]}
    except Exception as e:
        return 0, {"error": str(e)}


def api_call(host, token, params, path, method="GET", body=None, timeout=30):
    """带签名的请求，内置反 DNS 污染回退。

    正常网络：域名直连（verify=True）。若连接层失败（sc==0，多为 DNS 污染/拦截网关/
    TLS 证书不匹配被吞为错误），自动用 DoH 解析真实 Akamai IP 直连（verify=False + Host=域名）。
    """
    domain = _domain_of(host)
    # 0) 已配置出网代理(vless/本地)：优先经代理直连域名（代理侧为干净出口，绕过网关污染）
    if _PROXIES:
        sc, sb = _do_request(host, token, params, path, method, body, timeout,
                             None, verify=True, proxies=_PROXIES)
        if sc != 0:
            return sc, sb
        err = (sb or {}).get("error") if isinstance(sb, dict) else str(sb)
        print(f"[miniMax] 经代理直连失败（{err}），回退反污染兜底…")
    if domain in _RESOLVED and _RESOLVED[domain]:
        # 本次进程已探明可用真实 IP，直接走它（不再依赖被污染的 DNS）
        sc, sb = _do_request(f"https://{_RESOLVED[domain]}", token, params, path,
                             method, body, timeout, domain, verify=False,
                             proxies={"http": None, "https": None})
        return sc, sb

    sc, sb = _do_request(host, token, params, path, method, body, timeout, None,
                         verify=True, proxies={"http": None, "https": None})
    # 正常响应（非连接失败、非疑似拦截网关的 401）直接返回
    if sc not in (0, 401):
        return sc, sb

    # 连接层失败(sc==0) 或 疑似被拦截网关返回 401：改用 DoH 解析真实 IP 直连
    # （部分被管控网关会伪装成「HTTP 401」而非 TLS 错误，因此一并触发回退）
    reason = "连接失败（疑似 DNS 污染到假 IP）" if sc == 0 else "HTTP 401（疑似被拦截网关伪响应）"
    err0 = (sb or {}).get("error") if isinstance(sb, dict) else str(sb)
    print(f"[miniMax] 域名直连{reason}：{err0}；尝试 DoH 解析真实 IP 绕过…")
    last_err = err0
    for ip in _resolve_real_ips(host):
        if ip.startswith(_POISON_PREFIX):   # 解析结果仍是拦截网关，跳过
            print(f"[miniMax] 跳过疑似污染 IP {ip}（{reason}）")
            continue
        sc, sb = _do_request(f"https://{ip}", token, params, path, method, body, timeout,
                             domain, verify=False, proxies={"http": None, "https": None})
        # 个别 Akamai 边缘未映射该 vhost（返回 nginx 404），换下一个真实 IP 重试
        if sc == 404 and isinstance(sb, dict) and "nginx" in str(sb.get("raw", "")):
            print(f"[miniMax] 真实 IP {ip} 返回 nginx 404（非预期 vhost），尝试下一个…")
            continue
        # 真实 IP 仍被拦截网关伪响应（401）：继续尝试其他候选，不提前返回
        if sc == 401:
            print(f"[miniMax] 真实 IP {ip} 仍返回 401（疑似仍被拦截），尝试下一个…")
            last_err = "真实 IP 仍被拦截（401）"
            continue
        if sc != 0:
            _RESOLVED[domain] = ip
            print(f"[miniMax] 已通过真实 IP {ip} 绕过（{reason}）")
            return sc, sb
        last_err = (sb or {}).get("error") if isinstance(sb, dict) else str(sb)
    return 0, {"error": f"DNS 污染且 UDP/DoH 真实 IP 均不可达：{last_err}"}


def renew_token(token: str, params: dict):
    """续期登录：用旧 token 换新 token。返回 (新token, http状态码, 服务端文案)。
    失败时新 token 为空串。"""
    code, data = api_call(HOST, token, params, RENEW_PATH, method="POST", body={})
    if isinstance(data, dict):
        new_token = ((data.get("data") or {}).get("token") or "").strip()
        if new_token:
            return new_token, code, ""
    return "", code, server_message(data) or (str((data or {}).get("error")) if isinstance(data, dict) else "")


def _diag(token: str, http_status: int, data) -> str:
    """把失败原因拼成一句人话，供通知文本直接展示。"""
    bits = []
    if http_status:
        bits.append(f"HTTP {http_status}")
    else:
        bits.append("网络异常（无响应）")
    msg = server_message(data) or str((data or {}).get("error") or "")
    if msg:
        bits.append(msg)
    bits.append(token_exp_text(token))
    return "；".join(bits)


def _try_checkin(user_id: str, token: str, source: str):
    """用指定 token 走一遍「续期 -> 状态 -> 领取」。返回 (flag, content)。"""
    uid, did = load_persistent_device()
    base_params = build_device_params(user_id, uid, did)

    # 1) 先续期（等价于重新登录一次，新 token 有效期顺延 ~40 天）
    renewed = ""
    new_token, rcode, rmsg = renew_token(token, base_params)
    if new_token:
        renewed = new_token
        token = new_token
        where = persist_token(new_token, "renewal")
        print(f"[miniMax] 续期成功（来源 {source}），已写回：{'/'.join(where) or '仅内存'}")
    elif rcode:
        print(f"[miniMax] 续期失败：HTTP {rcode} {rmsg}（沿用原 token 继续尝试）")

    # 2) 状态查询（GET）
    sc, sb = api_call(HOST, token, base_params, STATUS_PATH, method="GET")
    if is_auth_failure(sc, sb):
        return "AUTH_EXPIRED", f"⚠️ 鉴权失败：{_diag(token, sc, sb)}｜token 来源：{source}"
    if not api_succeeded(sb):
        msg = server_message(sb) or json.dumps(sb, ensure_ascii=False)[:150]
        return "STATUS_ERR", f"⚠️ 状态查询异常：HTTP {sc} {msg}"

    # 解析今日签到状态：days[] 中 is_today=true 的那天，status==3 表示已领取
    days = (((sb or {}).get("data") or {}).get("days")) or []
    today = next((d for d in days if d.get("is_today")), None)
    today_done = bool(today and today.get("status") == 3)
    if today_done:
        extra = "（已自动续期 token）" if renewed else ""
        return "ALREADY_TODAY", f"ℹ️ 今日已签到（第 {today.get('day_no')} 天）{extra}"

    # 3) 领取（POST，body {}）
    cc, cb = api_call(HOST, token, base_params, CLAIM_PATH, method="POST", body={})
    if is_auth_failure(cc, cb):
        return "AUTH_EXPIRED", f"⚠️ 鉴权失败：{_diag(token, cc, cb)}｜token 来源：{source}"
    if is_rate_limited(cc, cb):
        msg = server_message(cb) or json.dumps(cb, ensure_ascii=False)[:120]
        return "RATE_LIMITED", f"⏳ 服务端限频：{msg}，建议错峰或稍后重试"
    if not api_succeeded(cb):
        msg = server_message(cb) or json.dumps(cb, ensure_ascii=False)[:150]
        return "FAIL", f"⚠️ 领取未成功：HTTP {cc} {msg}"

    # 解析领取结果：claim_result 1=新领取成功，2=今日已领取
    cdata = (cb or {}).get("data") or {}
    claim_result = cdata.get("claim_result")
    points = cdata.get("points")
    extra = "（已自动续期 token，下次仍可用）" if renewed else ""
    if claim_result == 2:
        return "ALREADY_TODAY", f"ℹ️ 今日已签到（claim_result=2）{extra}"
    if claim_result == 1 or points is not None:
        gain = f"本次 +{points} 积分" if points else "签到成功"
        return "SUCCESS", f"✅ {gain}（第 {cdata.get('day_no')} 天）{extra}"
    return "SUCCESS", f"✅ 领取成功{extra}"


def checkin_once(cred: dict):
    """执行签到，返回 (结果标记, 通知文本)。

    策略：先续期（相当于先登录）再签到；若某个 token 鉴权失败，自动换另一个
    候选 token（环境变量 / 上次续期缓存）重试，全部失败才如实上报。
    """
    cred = cred or {}
    user_id = clean_env_value(cred.get("user_id", ""))
    tag = cred.get("user_name") or user_id or "未知用户"

    candidates = _candidate_tokens(cred)
    if not candidates:
        return "NO_CREDENTIAL", ("未获取到 MiniMax 登录态，请设置环境变量 MINIMAX_TOKEN / MINIMAX_USER_ID"
                                 "（或运行 python minimax_checkin.py --export-env --save 刷新）")

    # 有候选 token 才拉起出网代理（如配置了 vless），覆盖本次所有请求；结束时清理
    start_proxy_from_env()
    try:
        last = ("NO_CREDENTIAL", "未获取到 MiniMax 登录态")
        for token, source in candidates:
            try:
                flag, content = _try_checkin(user_id, token, source)
            except Exception as e:                       # 单个候选异常不中断其余尝试
                flag, content = "ERROR", f"⚠️ 执行异常（token 来源：{source}）：{type(e).__name__}: {e}"
                print(f"[miniMax] {content}")
            if flag in ("SUCCESS", "ALREADY_TODAY", "RATE_LIMITED"):
                return flag, _with_tag(tag, content)
            last = (flag, content)
            print(f"[miniMax] token 来源 {source} 失败：RESULT={flag} | {content}")

        # 全部候选都失败：补一条可操作提示
        flag, content = last
        if flag == "AUTH_EXPIRED":
            content += "｜处理：①本机 python minimax_checkin.py --export-env --save 重新导出；" \
                       "②把新的 MINIMAX_TOKEN 填回青龙（注意别带引号）；" \
                       "③若确认 token 无误仍 401，多为服务器出口 IP 被风控"
        return flag, content
    finally:
        stop_proxy()


_LEADING_ICONS = ("✅", "ℹ️", "⏳", "⚠️", "❌", "🎉")


def _with_tag(tag: str, content: str) -> str:
    """把用户标识插到图标后面：'✅ 本次 +400 积分' -> '✅ 547901267608952833 本次 +400 积分'。"""
    tag = str(tag or "").strip()
    content = str(content or "")
    if not tag:
        return content
    for icon in _LEADING_ICONS:                       # 开头是图标时插到图标后，保持视觉一致
        if content.startswith(icon):
            return f"{icon} {tag} {content[len(icon):].lstrip()}"
    return f"{tag} {content}"


def export_env():
    """--export-env：从本机登录态读取并打印环境变量（token 过期时用来刷新）。
    读取后会先走一次续期，导出的是**最新** token；追加 --save 可直接写回 .env。"""
    c = read_local_credential()
    if not c:
        print("未发现 MiniMax 登录态，请先在本机登录 MiniMax Agent 桌面端")
        return 1
    uid, did = load_persistent_device()
    params = build_device_params(c["user_id"], uid, did)

    token = c["token"]
    new_token, rcode, rmsg = renew_token(token, params)
    if new_token:
        token = new_token
        print(f"# 已续期：token 有效期顺延（{token_exp_text(token)}）")
    elif rcode:
        print(f"# 续期未成功（HTTP {rcode} {rmsg}），导出本机现有 token")

    values = {
        "MINIMAX_TOKEN": token,
        "MINIMAX_USER_ID": c["user_id"],
        "MINIMAX_UUID": uid,
        "MINIMAX_DEVICE_ID": did,
    }
    for k, v in values.items():
        print(f"{k}={v}")
    if c.get("user_name") or c.get("mail"):
        print(f"# 用户: {c.get('user_name')} <{c.get('mail')}>")
    if "--save" in sys.argv:
        n = _save_env_values(values)
        if n:
            print(f"# 已将上述 {n} 个变量写回 .env")
        save_token_cache(token, "export-env")
    return 0


def run_renew():
    """--renew：只续期 token（要求当前 token 仍有效），并写回缓存/.env。"""
    cred = resolve_credentials()
    token = clean_env_value(cred.get("token") or "")
    if not token:
        print("未找到可用 token：请先设置 MINIMAX_TOKEN，或在本机执行 --export-env --save")
        return 1
    uid, did = load_persistent_device()
    params = build_device_params(cred.get("user_id", ""), uid, did)

    print(f"# 当前 {token_exp_text(token)}")
    new_token, rcode, rmsg = renew_token(token, params)
    if not new_token:
        print(f"续期失败：HTTP {rcode} {rmsg}｜{token_exp_text(token)}")
        return 1
    where = persist_token(new_token, "renew")
    print(new_token)
    print(f"# 续期成功：{token_exp_text(new_token)}；已写回 {'/'.join(where) or '仅内存'}")
    return 0


def main():
    # python minimax_checkin.py --export-env [--save]  仅导出环境变量后退出
    if "--export-env" in sys.argv:
        sys.exit(export_env())
    # python minimax_checkin.py --renew [--save]       仅续期 token 后退出
    if "--renew" in sys.argv:
        sys.exit(run_renew())

    title = "MiniMax Code 每日签到"
    cred = resolve_credentials()
    if not cred:
        flag, content = "NO_CREDENTIAL", "未获取到 MiniMax 登录态，请登录 MiniMax Agent 桌面端后重试"
    else:
        flag, content = checkin_once(cred)

    print(f"RESULT={flag} | {content}")

    # 本地调试不想刷推送时：CHECKIN_NO_NOTIFY=1
    no_push = os.environ.get("CHECKIN_NO_NOTIFY", "").strip() in ("1", "true", "True")
    if _HAS_NOTIFY and not no_push:
        try:
            sendNotify.serverJMy(title, content)
        except Exception as e:
            print(f"[warn] 通知发送失败: {e}")
    elif no_push:
        print("[info] CHECKIN_NO_NOTIFY 已设置，跳过推送")


if __name__ == "__main__":
    main()
