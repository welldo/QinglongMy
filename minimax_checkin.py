#!/bin/env python3
# -*- coding: utf-8 -*
"""
cron: 33 0 * * * minimax_checkin.py
new Env('MiniMax Code 每日签到');

==================== MiniMax Code 自动签到 ====================

签到点（逆向自 MiniMax Code 桌面端 app.asar，MiniMax Agent 客户端）：
    状态查询  {host}/minimax-cloud/api/v1/signin/status    (GET)
    领取积分  {host}/minimax-cloud/api/v1/signin/claim      (POST, body {})

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

【方式一 · 推荐，免维护，默认生效】
不填环境变量，脚本自动读取本机已登录的 MiniMax Agent 桌面端登录态：
    文件：%APPDATA%\\MiniMax Agent\\minimax-agent-config.json
    键：  tokens.accessToken
说明：该文件由 MiniMax Agent 客户端运行时刷新写回，token 跟随客户端保持有效
      （抓包实测当前 token 有效期至约 2026-10）；token 过期时在客户端重新登录即可。

【方式二 · 手动环境变量（跨机/容器部署）】
    在本机执行 python minimax_checkin.py --export-env 可一键导出：
    MINIMAX_TOKEN=<tokens.accessToken>
    MINIMAX_USER_ID=<realUserID>
    MINIMAX_UUID=<设备 uuid，可选>
    MINIMAX_DEVICE_ID=<数字设备 id，可选>

依赖：pip install requests

声明：仅供学习与个人使用。MiniMax Code / MiniMax Agent 是 MiniMax 旗下产品，
本脚本与其无任何关联，使用产生的任何后果（账号风控、封禁等）由使用者自行承担。
============================================================================================
"""

import os
import sys
import json
import uuid
import hashlib
import re
import urllib.parse
from datetime import datetime, timezone

import requests

# 本地开发时自动加载同目录 .env；已设置的环境变量优先，不受影响
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

# 通知模块（同目录 sendNotify.py）；缺失则降级为仅打印
try:
    import sendNotify
    _HAS_NOTIFY = True
except Exception:
    _HAS_NOTIFY = False


# ===== 端点常量 =====
HOST = "https://agent.minimax.io"
STATUS_PATH = "/minimax-cloud/api/v1/signin/status"
CLAIM_PATH = "/minimax-cloud/api/v1/signin/claim"

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


def load_persistent_device():
    """读取/生成并持久化稳定的 uuid 与数字 device_id（同机多次运行保持一致）。"""
    cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".minimax_device.json")
    uid = os.environ.get("MINIMAX_UUID", "").strip()
    did = os.environ.get("MINIMAX_DEVICE_ID", "").strip()
    if uid and did:
        return uid, did
    data = {}
    if os.path.isfile(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            data = {}
    uid = uid or data.get("uuid") or str(uuid.uuid4())
    did = did or data.get("device_id") or str(__import__("random").randint(10**9, 10**10 - 1))
    if not os.environ.get("MINIMAX_UUID") or not os.environ.get("MINIMAX_DEVICE_ID"):
        try:
            with open(cache_path, "w", encoding="utf-8") as fh:
                json.dump({"uuid": uid, "device_id": did}, fh)
        except Exception:
            pass
    return uid, did


def resolve_credentials():
    """返回凭据 dict 或 None。环境变量优先，否则读取本机登录态。"""
    token = os.environ.get("MINIMAX_TOKEN", "").strip()
    if token:
        user_id = os.environ.get("MINIMAX_USER_ID", "").strip()
        cred = {"token": token, "user_id": user_id, "user_name": "", "mail": ""}
        local = read_local_credential()
        if local:
            cred["user_id"] = cred["user_id"] or local["user_id"]
            cred["user_name"] = local["user_name"]
            cred["mail"] = local["mail"]
        return cred
    cred = read_local_credential()
    if not cred:
        print("未发现 MiniMax 登录态：请确保本机已登录 MiniMax Agent 桌面端"
              "（%APPDATA%\\MiniMax Agent\\minimax-agent-config.json），"
              "或设置 MINIMAX_TOKEN / MINIMAX_USER_ID 环境变量。")
    return cred


# ===== 业务解析 =====

AUTH_FAIL_KEYWORDS = ("unauthorized", "token", "expired", "not login",
                      "not logged", "登录", "鉴权", "invalid")
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


def api_call(host, token, params, path, method="GET", body=None, timeout=30):
    """带签名的请求：计算签名 -> 发送 -> 返回 (status_code, json_or_raw)。"""
    signed_params, headers, body_str = _sign_request(path, token, params, method, body)
    url = f"{host}{path}"
    # 用 PreparedRequest 精确控制最终发出的 header，避免 requests 自动注入多余默认值
    req = requests.Request(method.upper(), url, params=signed_params,
                           headers=headers, data=body_str or None)
    prepared = req.prepare()
    try:
        session = requests.Session()
        # proxies=None 强制直连，避免走代理导致被限频或连不上
        r = session.send(prepared, timeout=timeout, proxies={"http": None, "https": None})
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"raw": r.text[:300]}
    except Exception as e:
        return 0, {"error": str(e)}


def checkin_once(cred: dict):
    """执行单次签到，返回 (结果标记, 通知文本)。不做重试：结果如实上报。"""
    token = cred["token"]
    tag = cred["user_name"] or cred["user_id"] or "未知用户"

    uid, did = load_persistent_device()
    base_params = build_device_params(cred.get("user_id", ""), uid, did)

    # 1) 状态查询（GET）
    sc, sb = api_call(HOST, token, base_params, STATUS_PATH, method="GET")
    if is_auth_failure(sc, sb):
        return "AUTH_EXPIRED", f"⚠️ {tag} 鉴权失败（HTTP {sc}），请在 MiniMax Agent 客户端重新登录后重试"
    if not api_succeeded(sb):
        msg = (sb or {}).get("message") or (sb or {}).get("msg") or json.dumps(sb, ensure_ascii=False)[:150]
        return "STATUS_ERR", f"⚠️ {tag} 状态查询异常：HTTP {sc} {msg}"

    # 解析今日签到状态：days[] 中 is_today=true 的那天，status==3 表示已领取
    days = (((sb or {}).get("data") or {}).get("days")) or []
    today = next((d for d in days if d.get("is_today")), None)
    today_done = bool(today and today.get("status") == 3)
    if today_done:
        return "ALREADY_TODAY", f"ℹ️ {tag} 今日已签到（第 {today.get('day_no')} 天）"

    # 2) 领取（POST，body {}）
    cc, cb = api_call(HOST, token, base_params, CLAIM_PATH, method="POST", body={})
    if is_auth_failure(cc, cb):
        return "AUTH_EXPIRED", f"⚠️ {tag} 鉴权失败（HTTP {cc}），请在 MiniMax Agent 客户端重新登录后重试"
    if is_rate_limited(cc, cb):
        msg = (cb or {}).get("message") or (cb or {}).get("msg") or json.dumps(cb, ensure_ascii=False)[:120]
        return "RATE_LIMITED", f"⏳ {tag} 服务端限频：{msg}，建议错峰或稍后重试"
    if not api_succeeded(cb):
        msg = (cb or {}).get("message") or (cb or {}).get("msg") or json.dumps(cb, ensure_ascii=False)[:150]
        return "FAIL", f"⚠️ {tag} 领取未成功：HTTP {cc} {msg}"

    # 解析领取结果：claim_result 1=新领取成功，2=今日已领取
    cdata = (cb or {}).get("data") or {}
    claim_result = cdata.get("claim_result")
    points = cdata.get("points")
    if claim_result == 2:
        return "ALREADY_TODAY", f"ℹ️ {tag} 今日已签到（claim_result=2）"
    if claim_result == 1 or points is not None:
        gain = f"本次 +{points} 积分" if points else "签到成功"
        return "SUCCESS", f"✅ {tag} {gain}（第 {cdata.get('day_no')} 天）"
    return "SUCCESS", f"✅ {tag} 领取成功"


def export_env():
    """--export-env：从本机登录态读取并打印环境变量（供青龙/跨机部署拷贝）。"""
    c = read_local_credential()
    if not c:
        print("未发现 MiniMax 登录态，请先在本机登录 MiniMax Agent 桌面端")
        return 1
    uid, did = load_persistent_device()
    print(f"MINIMAX_TOKEN={c['token']}")
    print(f"MINIMAX_USER_ID={c['user_id']}")
    print(f"MINIMAX_UUID={uid}")
    print(f"MINIMAX_DEVICE_ID={did}")
    if c.get("user_name") or c.get("mail"):
        print(f"# 用户: {c.get('user_name')} <{c.get('mail')}>")
    return 0


def main():
    # python minimax_checkin.py --export-env  仅导出环境变量后退出
    if "--export-env" in sys.argv:
        sys.exit(export_env())

    title = "MiniMax Code 每日签到"
    cred = resolve_credentials()
    if not cred:
        flag, content = "NO_CREDENTIAL", "未获取到 MiniMax 登录态，请登录 MiniMax Agent 桌面端后重试"
    else:
        flag, content = checkin_once(cred)

    print(f"RESULT={flag} | {content}")

    if _HAS_NOTIFY:
        try:
            sendNotify.serverJMy(title, content)
        except Exception as e:
            print(f"[warn] 通知发送失败: {e}")


if __name__ == "__main__":
    main()
