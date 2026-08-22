#!/bin/env python3
# -*- coding: utf-8 -*
"""
cron: 23 8 * * * trae_checkin.py
new Env('TraeWork每日积分签到');

==================== Trae Work 自动签到（参考 luckymiaow/trae-mate 重写） ====================

签到点（POST，空 JSON body）：
    状态查询  {host}/trae/api/v2/ug/checkin_credits/status
    领取积分  {host}/trae/api/v2/ug/checkin_credits/claim

鉴权头：
    Content-Type:   application/json
    Authorization:  Cloud-IDE-JWT {token}
    x-device-id:    {deviceId}

【方式一 · 推荐，免维护，默认生效】
不填环境变量，脚本自动读取本机已登录的 Trae 桌面端登录态并解密：

    文件：%APPDATA%\\TRAE SOLO CN\\User\\globalStorage\\storage.json
    键：  iCubeAuthInfo://icube.cloudide  （base64 加密信封）

    信封解密算法（AES-128-CBC / SHA512 完整性校验）：
        HEADER(6) + randomKey(32) + ciphertext
        secret  = LEFT_SECRET ⊕ RIGHT_SECRET
        derived = SHA512( SHA512(randomKey) ++ secret )
        key = derived[0..16], iv = derived[16..32]
        明文 = digest(64) + payload(JSON)，校验 digest == SHA512(payload)

    说明：storage.json 由 Trae 客户端运行时自行刷新写回，脚本每次运行重新读取，
    token 跟随客户端保持有效；token 过期时打开一次 Trae 客户端即可。

【方式二 · 手动环境变量（跨机/容器部署）】
    在本机执行 python trae_checkin.py --export-env 可一键导出以下变量：
    TRAE_TOKEN=<auth_info.token>
    TRAE_DEVICE_ID=<telemetry.devDeviceId>
    TRAE_HOST=<auth_info.host>        # 如 https://api.trae.cn，可选

依赖：pip install requests pycryptodome

声明：仅供学习与个人使用。Trae Work 是字节跳动旗下产品，本脚本与其无任何关联，
使用产生的任何后果（账号风控、封禁等）由使用者自行承担。
============================================================================================
"""

import os
import sys
import json
import base64
import hashlib
from datetime import datetime, timezone

import requests

# 本地开发时自动加载同目录 .env；已设置的环境变量优先，不受影响
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

try:
    from Crypto.Cipher import AES
except ImportError:
    print("缺少依赖 pycryptodome，请执行: pip install pycryptodome")
    sys.exit(1)

# 通知模块（同目录 sendNotify.py）；缺失则降级为仅打印
try:
    import sendNotify
    _HAS_NOTIFY = True
except Exception:
    _HAS_NOTIFY = False

# ===== 加密信封常量（源自 TRAE 客户端 / trae-mate trae_auth.rs）=====
HEADER = bytes([116, 99, 5, 16, 0, 0])
LEFT_SECRET = bytes([
    82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
    124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
    84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
    8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
])
RIGHT_SECRET = bytes([
    31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
    96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
    160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
    23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
])

STATUS_PATH = "/trae/api/v2/ug/checkin_credits/status"
CLAIM_PATH = "/trae/api/v2/ug/checkin_credits/claim"
ENTITLEMENT_PATH = "/trae/api/v2/pay/user_current_entitlement_list"
STORAGE_REL = os.path.join("User", "globalStorage", "storage.json")
AUTH_KEY = "iCubeAuthInfo://icube.cloudide"


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def decrypt_trae_auth_info(encoded: str) -> dict:
    """解密 TRAE 桌面端 base64 登录信封，返回 auth_info JSON 字典。"""
    envelope = base64.b64decode(encoded)
    if len(envelope) <= 38 or envelope[:6] != HEADER:
        raise ValueError("Invalid TRAE desktop credential envelope")

    random_key = envelope[6:38]
    secret = bytes(a ^ b for a, b in zip(LEFT_SECRET, RIGHT_SECRET))
    derived = _sha512(_sha512(random_key) + secret)
    key, iv = derived[:16], derived[16:32]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(envelope[38:])
    pad = plaintext[-1]
    if 1 <= pad <= 16:
        plaintext = plaintext[:-pad]

    if len(plaintext) < 64:
        raise ValueError("decrypted payload too short")
    expected_digest, payload = plaintext[:64], plaintext[64:]
    if _sha512(payload) != expected_digest:
        raise ValueError("TRAE desktop credential integrity check failed")
    return json.loads(payload.decode("utf-8"))


def parse_time_ms(value) -> float:
    """expiredAt 可能是 RFC3339/ISO 字符串或毫秒数字，统一转毫秒时间戳；无法解析返回 0。"""
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if s.isdigit():
        return float(s)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp() * 1000
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s).timestamp() * 1000
    except ValueError:
        return 0


def read_local_credential():
    """读取主实例 %APPDATA%\\TRAE SOLO CN 登录态，返回凭据 dict 或 None。"""
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return None
    storage_path = os.path.join(appdata, "TRAE SOLO CN", STORAGE_REL)
    if not os.path.isfile(storage_path):
        return None
    try:
        with open(storage_path, "r", encoding="utf-8") as fh:
            storage = json.load(fh)
        encrypted = storage.get(AUTH_KEY)
        if not encrypted:
            return None
        auth = decrypt_trae_auth_info(encrypted)
        token = (auth.get("token") or "").strip()
        if not token:
            return None
        return {
            "token": token,
            "device_id": (storage.get("telemetry.devDeviceId") or "").strip(),
            "user_id": str(auth.get("userId") or ""),
            "host": (auth.get("host") or "").rstrip("/"),
            "expires_ms": parse_time_ms(auth.get("expiredAt")),
        }
    except Exception as e:
        print(f"[warn] 解析 {storage_path} 失败: {e}")
        return None


def resolve_credentials():
    """返回凭据 dict 或 None。环境变量优先，否则读取本机 Trae 主实例登录态。"""
    token = os.environ.get("TRAE_TOKEN", "").strip()
    if token:
        cred = {
            "token": token,
            "device_id": os.environ.get("TRAE_DEVICE_ID", "").strip(),
            "host": os.environ.get("TRAE_HOST", "").strip().rstrip("/"),
            "user_id": os.environ.get("TRAE_USER_ID", "").strip(),
            "expires_ms": 0,
        }
        # 从本机登录态回填 userId/过期时间（仅展示与提示用，不影响鉴权）
        local = read_local_credential()
        if local:
            cred["user_id"] = cred["user_id"] or local["user_id"]
            cred["expires_ms"] = local["expires_ms"]
        return cred

    cred = read_local_credential()
    if not cred:
        print("未发现 Trae 登录态：请确保本机已登录 Trae 桌面端"
              "（%APPDATA%\\TRAE SOLO CN\\User\\globalStorage\\storage.json），"
              "或设置 TRAE_TOKEN / TRAE_DEVICE_ID 环境变量。")
    return cred


AUTH_FAIL_KEYWORDS = ("unauthorized", "token", "expired", "not login",
                      "not logged", "登录", "鉴权")
RATE_LIMIT_KEYWORDS = ("频繁", "frequent", "too many", "太多", "稍后再试",
                       "繁忙", "busy")

def api_succeeded(data: dict) -> bool:
    if not isinstance(data, dict):
        return False
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
    """服务端活动限流：HTTP 429/5xx 或业务消息命中限频关键词。"""
    if http_status in (429, 500, 502, 503, 504):
        return True
    if not isinstance(data, dict):
        return False
    msg = str(data.get("message") or data.get("msg") or "")
    return any(k in msg for k in RATE_LIMIT_KEYWORDS)


# 请求头 User-Agent：对齐真实 Trae 桌面端（Chromium/Electron 内核）。
# 高峰期服务端对 python-requests 等非浏览器 UA 限流更严格，统一用浏览器 UA。
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def api_call(host, token, device_id, path, body=None, timeout=30):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        "Authorization": f"Cloud-IDE-JWT {token}",
    }
    if device_id:
        headers["x-device-id"] = device_id
    url = f"{host}{path}"
    try:
        r = requests.post(url, headers=headers,
                          data=json.dumps(body or {}), timeout=timeout)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"raw": r.text[:300]}
    except Exception as e:
        return 0, {"error": str(e)}


def query_points(host, token, device_id):
    """查询剩余积分（entitlement_list 结构化解析，失败则忽略）。"""
    sc, sb = api_call(host, token, device_id, ENTITLEMENT_PATH,
                      body={"require_usage": True}, timeout=15)
    try:
        packs = (((sb or {}).get("data") or {}).get("user_entitlement_pack_list")) or []
        total = 0
        found = False
        for p in packs:
            limit = ((((p.get("entitlement_base_info") or {}).get("quota")) or {})
                     .get("credits_limit")) or 0
            used = (((p.get("usage") or {}).get("credits_amount"))) or 0
            if limit > 0:
                found = True
                total += max(limit - used, 0)
        if found:
            return total
    except Exception:
        pass
    return None


def checkin_once(cred: dict):
    """执行单次签到，返回 (结果标记, 通知文本)。不做重试：结果如实上报。"""
    host = cred["host"] or "https://api.trae.cn"
    tag = cred["user_id"] or "未知用户"

    if cred["expires_ms"]:
        remain_h = (cred["expires_ms"] - datetime.now(timezone.utc).timestamp() * 1000) / 3600000
        if remain_h <= 0:
            return "AUTH_EXPIRED", f"⚠️ {tag} token 已过期，请打开 Trae 桌面端刷新登录态后重试"

    # 1) 状态查询
    sc, sb = api_call(host, cred["token"], cred["device_id"], STATUS_PATH)
    if isinstance(sb, dict) and sb.get("checked_in"):
        pts = query_points(host, cred["token"], cred["device_id"])
        extra = f"，剩余积分 {pts}" if pts is not None else ""
        return "ALREADY_TODAY", f"ℹ️ {tag} 今日已签到{extra}"
    if is_auth_failure(sc, sb):
        return "AUTH_EXPIRED", f"⚠️ {tag} 鉴权失败（HTTP {sc}），请打开 Trae 桌面端刷新登录态后重试"
    if not api_succeeded(sb):
        msg = (sb or {}).get("message") or (sb or {}).get("msg") or json.dumps(sb, ensure_ascii=False)[:120]
        if is_rate_limited(sc, sb):
            return "RATE_LIMITED", f"⏳ {tag} 服务端限频：{msg}，请稍后手动再跑一次"
        return "STATUS_ERR", f"⚠️ {tag} 状态查询异常：HTTP {sc} {msg}"

    # 2) 领取
    cc, cb = api_call(host, cred["token"], cred["device_id"], CLAIM_PATH)
    if is_auth_failure(cc, cb):
        return "AUTH_EXPIRED", f"⚠️ {tag} 鉴权失败（HTTP {cc}），请打开 Trae 桌面端刷新登录态后重试"
    if api_succeeded(cb):
        points = ((cb.get("data") or {}).get("points")) or cb.get("points")
        message = cb.get("message") or cb.get("msg") or ""
        pts = query_points(host, cred["token"], cred["device_id"])
        extra = f"，剩余积分 {pts}" if pts is not None else ""
        text = "签到成功" if message == "success" else message
        gain = f"本次 +{points} 积分" if points else text
        return "SUCCESS", f"✅ {tag} {gain}{extra}"

    msg = (cb or {}).get("message") or (cb or {}).get("msg") or json.dumps(cb, ensure_ascii=False)[:150]
    if is_rate_limited(cc, cb):
        return "RATE_LIMITED", f"⏳ {tag} 服务端限频：{msg}，请稍后手动再跑一次"
    return "FAIL", f"⚠️ {tag} 签到未成功：HTTP {cc} {msg}"


def export_env():
    """--export-env：从本机登录态解密并打印环境变量（供青龙/跨机部署拷贝）。"""
    c = read_local_credential()
    if not c:
        print("未发现 Trae 登录态，请先在本机登录 Trae 桌面端")
        return 1
    print(f"TRAE_TOKEN={c['token']}")
    print(f"TRAE_DEVICE_ID={c['device_id']}")
    print(f"TRAE_HOST={c['host'] or 'https://api.trae.cn'}")
    print(f"TRAE_USER_ID={c['user_id']}")
    if c["expires_ms"]:
        exp = datetime.fromtimestamp(c["expires_ms"] / 1000, tz=timezone.utc)
        print(f"# token 过期时间(UTC): {exp:%Y-%m-%d %H:%M}")
    return 0


def main():
    # python trae_checkin.py --export-env  仅导出环境变量后退出
    if "--export-env" in sys.argv:
        sys.exit(export_env())

    title = "Trae Work 每日签到"
    cred = resolve_credentials()
    if not cred:
        flag, content = "NO_CREDENTIAL", "未获取到 Trae 登录态，请登录 Trae 桌面端后重试"
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
