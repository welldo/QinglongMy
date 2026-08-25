#!/bin/env python3
# -*- coding: utf-8 -*
"""
# cron: 23 0 * * * trae_checkin.py
# new Env('TraeWork每日积分签到');

==================== Trae Work 自动签到 ====================

签到点（POST，空 JSON body）：
    状态查询  {host}/trae/api/v2/ug/checkin_credits/status
    领取积分  {host}/trae/api/v2/ug/checkin_credits/claim

鉴权头（对齐逆向仓库 traeClient.ts#postUg 最小集）：
    Content-Type:   application/json
    Authorization:  Cloud-IDE-JWT {token}
    x-device-id:    {数字格式设备id}   # 取自 storage.json 的 iCubeAuthInfo://icube-dc:<numeric> 键

【方式一 · 推荐：环境变量（脚本默认且唯一读取来源）】
在 .env 或运行环境中设置：
    TRAE_TOKEN=<auth_info.token>
    TRAE_DEVICE_ID=<iCubeAuthInfo://icube-dc:<numeric> 键中的数字设备id>
    TRAE_HOST=<auth_info.host>               # 如 https://api.trae.cn，可选
    TRAE_USER_ID=<auth_info.userId>           # 可选，仅用于展示
脚本【默认只读取上述环境变量】，不再自动读取本机登录态，方便容器 / 跨机 / 青龙部署。

【方式二 · 刷新 token：--export-env（仅本机、不进入默认运行链）】
token 过期时，在本机（已登录 Trae 桌面端）执行：
    python trae_checkin.py --export-env
会解密本机 storage.json 并打印最新变量；追加 --save 可直接写回 .env：
    python trae_checkin.py --export-env --save

本机登录态文件（仅供参考，不参与默认运行）：
    %APPDATA%\\TRAE SOLO CN\\User\\globalStorage\\storage.json
    键： iCubeAuthInfo://icube.cloudide  （base64 加密信封，AES-128-CBC / SHA512 完整性校验）

依赖：pip install requests pycryptodome

声明：仅供学习与个人使用。Trae Work 是字节跳动旗下产品，本脚本与其无任何关联，
使用产生的任何后果（账号风控、封禁等）由使用者自行承担。
============================================================================================
"""

import os
import sys
import re
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


def _save_env_values(values: dict):
    """把导出的环境变量写回同目录 .env（仅更新/追加给定 key，保留其它内容）。
    仅 --export-env --save 时调用。返回写入的变量数（0 表示失败）。"""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
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

# ===== 加密信封常量（源自 TRAE 客户端 ）=====
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


def extract_dc_device_id(storage: dict) -> str:
    """从 storage.json 的 iCubeAuthInfo://icube-dc:<did> 键提取真实设备 id。

    逆向仓库（BlueChonk/trae-credential-reverse-engineering）证明：服务端校验的
    x-device-id 即此 <did>，为数字格式（如 1448485154478571 / 2417165752872746），
    与 iCubeAuthInfo://icube-dc:<numeric> 键对应；UUID 格式的 telemetry.devDeviceId
    不被服务端识别为注册设备，可能触发更严格的限流。优先取纯数字 <did>。
    """
    cands = []
    for k in storage.keys():
        if k.startswith("iCubeAuthInfo://icube-dc:"):
            did = k.split(":", 3)[-1]  # iCubeAuthInfo://icube-dc:<did> 的 did 部分
            cands.append(did)
    numeric = [d for d in cands if d.isdigit()]
    if numeric:
        return numeric[0]
    if cands:
        return cands[0]
    return ""


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
        # 真实设备 id：优先 iCubeAuthInfo://icube-dc:<numeric> 键，回退到 telemetry.devDeviceId
        device_id = extract_dc_device_id(storage) or (storage.get("telemetry.devDeviceId") or "").strip()
        return {
            "token": token,
            "device_id": device_id,
            "user_id": str(auth.get("userId") or ""),
            "host": (auth.get("host") or "").rstrip("/"),
            "expires_ms": parse_time_ms(auth.get("expiredAt")),
        }
    except Exception as e:
        print(f"[warn] 解析 {storage_path} 失败: {e}")
        return None


def resolve_credentials():
    """【仅读取环境变量】返回凭据 dict（永不读本机登录态）。
    未设置 TRAE_TOKEN 时返回空 token，checkin 阶段判为 NO_CREDENTIAL。
    刷新 token 请用 `python trae_checkin.py --export-env`。"""
    token = os.environ.get("TRAE_TOKEN", "").strip()
    if not token:
        # 不回退读取本机登录态：保持“只读环境变量”的纯净模型
        return {
            "token": "",
            "device_id": os.environ.get("TRAE_DEVICE_ID", "").strip(),
            "host": os.environ.get("TRAE_HOST", "").strip().rstrip("/"),
            "user_id": os.environ.get("TRAE_USER_ID", "").strip(),
            "expires_ms": 0,
            "src": "none",
        }
    return {
        "token": token,
        "device_id": os.environ.get("TRAE_DEVICE_ID", "").strip(),
        "host": os.environ.get("TRAE_HOST", "").strip().rstrip("/"),
        "user_id": os.environ.get("TRAE_USER_ID", "").strip(),
        "expires_ms": 0,
        "src": "env",
    }


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


# 请求头：对齐逆向仓库 BlueChonk/trae-credential-reverse-engineering 中
# traeClient.ts#postUg 的实测最小集（checkin_status / checkin_claim 仅发这 3 个头）：
#   - Content-Type:    application/json
#   - Authorization:   Cloud-IDE-JWT <token>
#   - x-device-id:     <数字格式设备 id，取自 iCubeAuthInfo://icube-dc:<numeric> 键>
# 逆向证明该端点的服务端校验只认这 3 个头；附加 UA / 多余 x-* 头反而偏离真机。
def build_checkin_headers(token: str, device_id: str, user_id: str = "") -> dict:
    """签到/状态/积分接口共用的请求头，对齐逆向仓库 postUg 的最小集。"""
    return {
        "content-type": "application/json",
        "authorization": token if str(token).startswith("Cloud-IDE-JWT ")
                          else f"Cloud-IDE-JWT {token}",
        "x-device-id": device_id or "",
    }


def api_call(host, token, device_id, path, body=None, timeout=30, user_id=""):
    # 对齐真实 Trae 桌面端完整请求头（含 VSCode UA + x-market-user-id + vscode-sessionid 等）
    headers = build_checkin_headers(token, device_id, user_id)
    url = f"{host}{path}"
    req_body = json.dumps(body or {})

    # 打印完整请求信息
    print(f"\n{'='*60}")
    print(f"[REQUEST] POST {url}")
    print(f"[REQUEST] Headers:")
    for k, v in headers.items():
        if k == "Authorization":
            print(f"  {k}: Cloud-IDE-JWT {v[len('Cloud-IDE-JWT '):len('Cloud-IDE-JWT ')+20]}...")
        else:
            print(f"  {k}: {v}")
    print(f"[REQUEST] Body: {req_body}")

    try:
        # 用 PreparedRequest 精确控制最终发出的 header，避免 requests 自动注入多余默认值
        req = requests.Request("POST", url, headers=headers, data=req_body)
        prepared = req.prepare()

        print(f"[REQUEST] 最终发出 Headers (含库自动添加):")
        for k, v in prepared.headers.items():
            if k == "Authorization":
                print(f"  {k}: Cloud-IDE-JWT {v[len('Cloud-IDE-JWT '):len('Cloud-IDE-JWT ')+20]}...")
            else:
                print(f"  {k}: {v}")

        session = requests.Session()
        # proxies=None 强制直连 api.trae.cn，避免走系统/本地代理导致被限频或连不上
        r = session.send(prepared, timeout=timeout, proxies={"http": None, "https": None})

        # 打印完整响应信息
        print(f"\n[RESPONSE] Status: {r.status_code}")
        print(f"[RESPONSE] Headers:")
        for k, v in r.headers.items():
            print(f"  {k}: {v}")
        print(f"[RESPONSE] Body: {r.text[:1000]}")
        print(f"{'='*60}\n")

        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"raw": r.text[:300]}
    except Exception as e:
        print(f"[RESPONSE] Error: {e}")
        print(f"{'='*60}\n")
        return 0, {"error": str(e)}


def query_points(host, token, device_id, user_id=""):
    """查询剩余积分（entitlement_list 结构化解析，失败则忽略）。"""
    sc, sb = api_call(host, token, device_id, ENTITLEMENT_PATH,
                      body={"require_usage": True}, timeout=15, user_id=user_id)
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
    cred = cred or {}
    token = cred.get("token", "").strip()
    if not token:
        return "NO_CREDENTIAL", "未获取到 Trae 登录态，请设置环境变量 TRAE_TOKEN / TRAE_DEVICE_ID（或运行 python trae_checkin.py --export-env --save 刷新）"

    host = cred.get("host") or "https://api.trae.cn"
    tag = cred.get("user_id") or "未知用户"
    device_id = cred.get("device_id", "")
    user_id = cred.get("user_id", "")

    if cred.get("expires_ms"):
        remain_h = (cred["expires_ms"] - datetime.now(timezone.utc).timestamp() * 1000) / 3600000
        if remain_h <= 0:
            return "AUTH_EXPIRED", f"⚠️ {tag} token 已过期，请打开 Trae 桌面端刷新登录态后重试"

    # 1) 状态查询
    sc, sb = api_call(host, token, device_id, STATUS_PATH, user_id=user_id)
    if isinstance(sb, dict) and sb.get("checked_in"):
        pts = query_points(host, token, device_id, user_id)
        extra = f"，剩余积分 {pts}" if pts is not None else ""
        return "ALREADY_TODAY", f"ℹ️ {tag} 今日已签到{extra}"
    if is_auth_failure(sc, sb):
        return "AUTH_EXPIRED", f"⚠️ {tag} 鉴权失败（HTTP {sc}），请打开 Trae 桌面端刷新登录态后重试"
    if not api_succeeded(sb):
        msg = (sb or {}).get("message") or (sb or {}).get("msg") or json.dumps(sb, ensure_ascii=False)[:120]
        if is_rate_limited(sc, sb):
            return "RATE_LIMITED", f"⏳ {tag} 服务端限频（活动高峰容量不足，与请求特征无关）：{msg}，建议错峰或稍后重试"
        return "STATUS_ERR", f"⚠️ {tag} 状态查询异常：HTTP {sc} {msg}"

    # 2) 领取
    cc, cb = api_call(host, token, device_id, CLAIM_PATH, user_id=user_id)
    if is_auth_failure(cc, cb):
        return "AUTH_EXPIRED", f"⚠️ {tag} 鉴权失败（HTTP {cc}），请打开 Trae 桌面端刷新登录态后重试"
    if api_succeeded(cb):
        points = ((cb.get("data") or {}).get("points")) or cb.get("points")
        message = cb.get("message") or cb.get("msg") or ""
        pts = query_points(host, token, device_id, user_id)
        extra = f"，剩余积分 {pts}" if pts is not None else ""
        text = "签到成功" if message == "success" else message
        gain = f"本次 +{points} 积分" if points else text
        return "SUCCESS", f"✅ {tag} {gain}{extra}"

    msg = (cb or {}).get("message") or (cb or {}).get("msg") or json.dumps(cb, ensure_ascii=False)[:150]
    if is_rate_limited(cc, cb):
        return "RATE_LIMITED", f"⏳ {tag} 服务端限频（活动高峰容量不足，与请求特征无关）：{msg}，建议错峰或稍后重试"
    return "FAIL", f"⚠️ {tag} 签到未成功：HTTP {cc} {msg}"


def export_env():
    """--export-env：从本机登录态解密并打印环境变量（token 过期时用来刷新）。
    追加 --save 可直接写回同目录 .env。"""
    c = read_local_credential()
    if not c:
        print("未发现 Trae 登录态，请先在本机登录 Trae 桌面端")
        return 1
    values = {
        "TRAE_TOKEN": c["token"],
        "TRAE_DEVICE_ID": c["device_id"],
        "TRAE_HOST": c["host"] or "https://api.trae.cn",
        "TRAE_USER_ID": c["user_id"],
    }
    for k, v in values.items():
        print(f"{k}={v}")
    if c["expires_ms"]:
        exp = datetime.fromtimestamp(c["expires_ms"] / 1000, tz=timezone.utc)
        print(f"# token 过期时间(UTC): {exp:%Y-%m-%d %H:%M}")
    if "--save" in sys.argv:
        n = _save_env_values(values)
        if n:
            print(f"# 已将上述 {n} 个变量写回 .env")
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
