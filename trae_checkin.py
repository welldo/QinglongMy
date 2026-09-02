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
    TRAE_USER_ID=<auth_info.userId>           # 可选，仅用于展示
    # —— 以下为【自动续期】所需材料（一次性引导后持续生效）——
    TRAE_REFRESH_TOKEN=<auth_info.refreshToken>
    TRAE_DEVICE_KEY_PEM=<设备 ECDSA 私钥 PEM>        # ExchangeToken 设备证明签名用
    TRAE_DEVICE_PUB_PEM=<设备 ECDSA 公钥 PEM>
    TRAE_MACHINE_ID=<telemetry.machineId>
脚本【默认只读取上述环境变量】，不再自动读取本机登录态，方便容器 / 跨机 / 青龙部署。
续期后最新凭据写入同目录 .trae_token.json（已加入 .gitignore），是续期后的权威来源。

【自动续期 / 自愈】
Trae 的 access token 仅约 14 天有效。脚本内置 ExchangeToken 续期：用 refreshToken + 设备
ECDSA 私钥（纯标准库签名，无需第三方库）向 {host}/trae/api/v3/oauth/ExchangeToken 换发新
token。触发条件：
  - 无 token 但有续期材料：先续期再签到；
  - token 即将过期（<48h）：先续期；
  - 状态/领取返回鉴权失败：自动续期并重试一次。
材料缺失时退化为原行为并提示先 --export-keys 引导。

【方式二 · 引导 / 刷新：--export-env（仅本机、不进入默认运行链）】
在本机（已登录 Trae 桌面端）执行会解密 storage.json 并打印【全部】变量（含设备私钥）：
    python trae_checkin.py --export-keys          # 或 --export-env（同义）
追加 --save 直接写回 .env 并写入续期缓存：
    python trae_checkin.py --export-keys --save

【仅续期：--renew】
    python trae_checkin.py --renew     # 立即续期并写回缓存 / storage.json

本机登录态文件（仅供参考，不参与默认运行）：
    %APPDATA%\\TRAE SOLO CN\\User\\globalStorage\\storage.json
    键： iCubeAuthInfo://icube.cloudide  （base64 加密信封，AES-128-CBC / SHA512 完整性校验）
    键： iCubeAuthInfo://icube-dc:<numeric>  （设备 ECDSA 密钥对信封）

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
import time
import platform
from datetime import datetime, timezone

import requests

# 本地开发时自动加载同目录 .env；已设置的环境变量优先，不受影响。
# python-dotenv 为本项目依赖（见 requirements.txt），统一用官方库加载，不做自定义兜底。
from dotenv import load_dotenv
load_dotenv()

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
HOST = "https://api.trae.cn"
STORAGE_REL = os.path.join("User", "globalStorage", "storage.json")
AUTH_KEY = "iCubeAuthInfo://icube.cloudide"

# ===== 自动续期（ExchangeToken）相关常量 =====
# 续期端点与签到同域；用 refreshToken + 设备 ECDSA 私钥证明换取新 token。
EXCHANGE_PATH = "/trae/api/v3/oauth/ExchangeToken"
CLIENT_ID = "en1oxy7wnw8j9n"
# IDE/Client 版本：逆向仓库实测用 1.107.1 即放行；可用 TRAE_APP_VERSION 覆盖。
APP_VERSION = os.environ.get("TRAE_APP_VERSION", "1.107.1")
# 续期后把最新凭据写回同目录缓存（已加入 .gitignore）；青龙工作目录可写，靠它滚动续期，
# 只要脚本能跑起来就不会再因 token 过期而失败。
CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".trae_token.json")
# 设备证明指纹：OSInfo 必须为 'Windows' 且硬件串留空，否则服务端报 20405（设备证明缺失）。
DEVICE_OS_INFO = "Windows"


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


def encrypt_trae_auth_info(plaintext: str) -> str:
    """把 auth_info JSON 加密回 byteCrypto 信封（与 decrypt_trae_auth_info 对称）。
    用于把续期后得到的新 token/refreshToken 写回本机 storage.json，保持桌面端一致。"""
    import os as _os
    random_key = _os.urandom(32)
    secret = bytes(a ^ b for a, b in zip(LEFT_SECRET, RIGHT_SECRET))
    derived = _sha512(_sha512(random_key) + secret)
    key, iv = derived[:16], derived[16:32]

    body = plaintext.encode("utf-8")
    payload = _sha512(body) + body                     # 64B 摘要 || 明文
    pad_len = 16 - (len(payload) % 16)                 # PKCS7
    payload += bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(payload)

    envelope = HEADER + random_key + cipher
    return base64.b64encode(envelope).decode("utf-8")


# ===== 纯标准库 ECDSA P-256 设备证明（无第三方依赖，便于 qinglong 服务器运行）=====
# 服务端校验 ExchangeToken 的设备证明需要 ECDSA P-256 / SHA-256 签名（DER 编码 + 低 s 归一化），
# 与 Electron 客户端 node:crypto 的 createSign('sha256') 行为一致。
_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_A = (_P - 3) % _P
_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def _ec_inv(x, m):
    return pow(x % m, -1, m)


def _ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if x1 == x2 and y1 == y2:
        m = (3 * x1 * x1 + _A) * _ec_inv(2 * y1, _P) % _P
    else:
        m = (y2 - y1) * _ec_inv((x2 - x1) % _P, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    y3 = (m * (x1 - x3) - y1) % _P
    return (x3, y3)


def _ec_mul(k, p):
    r = None
    while k:
        if k & 1:
            r = _ec_add(r, p)
        p = _ec_add(p, p)
        k >>= 1
    return r


def _der_encode_signature(r, s):
    def _enc(x):
        b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b
    rb, sb = _enc(r), _enc(s)
    body = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
    return b"\x30" + bytes([len(body)]) + body


def _extract_private_d(private_pem: str) -> int:
    """从 P-256 PKCS#8 私钥 PEM 中提取私钥整数 d（仅依赖标准库）。

    兼容带/不带 -----BEGIN/END----- 标记、带或不带换行的各种存储形式
    （qinglong 等面板粘贴多行 PEM 时可能丢失标记或换行，只剩 base64 主体）。"""
    import re as _re
    s = (private_pem or "").strip()
    s = _re.sub(r"-----[A-Z0-9 ]+-----", "", s)   # 去掉 PEM 头尾标记
    s = _re.sub(r"\s+", "", s)                    # 去掉所有空白（含换行/回车/空格）
    if not s:
        raise ValueError("设备私钥 PEM 为空或缺少主体（请重新运行 python trae_checkin.py --export-keys --save 引导）")
    try:
        der = base64.b64decode(s)
    except Exception as e:
        raise ValueError(f"设备私钥 base64 解析失败（PEM 可能被截断/格式错误）: {e}")
    i = der.find(b"\x02\x01\x01")          # 内层 SEQUENCE 的 version INTEGER = 1
    if i < 0:
        raise ValueError("无法定位 EC 私钥结构（PEM 可能不完整，请重新引导）")
    j = der.find(b"\x04\x20", i)          # 紧跟其后的 32 字节 OCTET STRING 即私钥 d
    if j < 0:
        raise ValueError("无法定位私钥 d 的 OCTET STRING（PEM 可能不完整，请重新引导）")
    return int.from_bytes(der[j + 2:j + 2 + 32], "big")


def _normalize_pem(raw: str) -> str:
    """把 env 里的 PEM 统一成标准 PEM 文本。支持两种输入：
    - 标准多行 PEM（含 -----BEGIN-----）；
    - 单行 base64（把整段 PEM 做了 base64 后去换行）——用于 qinglong config.sh 等
      不支持多行值的 shell 环境，避免多行未加引号导致 shell 把换行当成多条命令执行。
    返回标准 PEM 文本（含换行），后续 _extract_private_d 等可正常解析。"""
    s = (raw or "").strip()
    if not s:
        return ""
    if "-----BEGIN" in s:
        return s
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return s


def ecdsa_sign_pure(private_pem: str, data: bytes) -> str:
    """用设备 EC 私钥对数据做 ECDSA P-256/SHA-256 签名，返回 base64(DER)。"""
    d = _extract_private_d(private_pem)
    z = int.from_bytes(hashlib.sha256(data).digest(), "big")
    if z.bit_length() > 256:
        z >>= (z.bit_length() - 256)
    while True:
        k = int.from_bytes(os.urandom(32), "big") % _N
        if k == 0:
            continue
        R = _ec_mul(k, (_GX, _GY))
        r = R[0] % _N
        if r == 0:
            continue
        s = (_ec_inv(k, _N) * (z + r * d)) % _N
        if s == 0:
            continue
        if s > _N // 2:                     # 低 s 归一化（与 node/cryptography 默认一致）
            s = _N - s
        return base64.b64encode(_der_encode_signature(r, s)).decode("utf-8")


def build_device_proof(refresh_token: str, private_pem: str) -> dict:
    """构造 DeviceProof：对 canonical 串做 ECDSA 签名（服务端要求 PascalCase 字段名）。"""
    ts = int(time.time())
    nonce = os.urandom(16).hex()
    canonical = "\n".join(["POST", EXCHANGE_PATH, CLIENT_ID, refresh_token, str(ts), nonce])
    signature = ecdsa_sign_pure(private_pem, canonical.encode("utf-8"))
    return {"Timestamp": ts, "Nonce": nonce, "Signature": signature}


def build_device_info(public_pem: str, device_id: str, machine_id: str) -> dict:
    """设备指纹：保持与逆向仓库一致的精简集（Windows / 空硬件串），避免 20405。"""
    return {
        "DeviceID": device_id,
        "MachineID": machine_id or "",
        "PlatformCode": "SOLO_PC",
        "DeviceType": "PC",
        "DeviceName": os.environ.get("USERNAME", "user"),
        "DeviceModel": "",
        "ClientVersion": APP_VERSION,
        "DevicePublicKey": public_pem,
        "DeviceBrand": "",
        "DeviceCPU": "",
        "OSInfo": DEVICE_OS_INFO,
        "OSVersion": platform.release(),
    }


def decode_jwt_exp(token: str):
    """从 JWT 取 exp（秒）；无法解析返回 0。"""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return 0
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        return float(payload.get("exp") or 0)
    except Exception:
        return 0


def load_cache() -> dict:
    """读取续期缓存 .trae_token.json（含最新 token / refreshToken / 设备私钥等）。"""
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_cache(cred: dict):
    """把续期后的最新凭据落盘缓存（已加入 .gitignore）。"""
    try:
        data = {
            "token": cred.get("token", ""),
            "refresh_token": cred.get("refresh_token", ""),
            "device_id": cred.get("device_id", ""),
            "user_id": cred.get("user_id", ""),
            "machine_id": cred.get("machine_id", ""),
            "device_key_pem": cred.get("device_key_pem", ""),
            "device_pub_pem": cred.get("device_pub_pem", ""),
            "expires_ms": cred.get("expires_ms", 0),
            "refresh_expires_ms": cred.get("refresh_expires_ms", 0),
            "updated_at": int(time.time()),
        }
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[warn] 写入续期缓存失败: {e}")


def exchange_token(cred: dict):
    """用 refreshToken + 设备私钥换取新 token。返回 (ok, new_cred_fields, error)。"""
    refresh = cred.get("refresh_token", "").strip()
    priv = cred.get("device_key_pem", "").strip()
    pub = cred.get("device_pub_pem", "").strip()
    did = cred.get("device_id", "").strip()
    mid = cred.get("machine_id", "").strip()
    if not (refresh and priv and pub and did):
        return False, None, "缺少 refreshToken / 设备私钥材料（请先运行 python trae_checkin.py --export-keys --save 引导）"
    try:
        proof = build_device_proof(refresh, priv)
    except Exception as e:
        return False, None, (f"设备证明生成失败（设备私钥材料可能无效，"
                              f"请重新运行 python trae_checkin.py --export-keys --save 引导）: {e}")
    body = {
        "ClientID": CLIENT_ID,
        "ClientSecret": "",
        "RefreshToken": refresh,
        "DeviceInfo": build_device_info(pub, did, mid),
        "DeviceProof": proof,
        "IDEVersion": APP_VERSION,
    }
    headers = {"Content-Type": "application/json", "x-cloudide-token": ""}
    try:
        r = requests.post(HOST + EXCHANGE_PATH, headers=headers, data=json.dumps(body),
                          timeout=30, proxies={"http": None, "https": None})
    except Exception as e:
        return False, None, f"续期请求异常: {e}"
    try:
        j = r.json()
    except Exception:
        return False, None, f"续期响应非 JSON（HTTP {r.status_code}）: {r.text[:200]}"
    err = (j.get("ResponseMetadata") or {}).get("Error")
    if err:
        return False, None, f"续期被拒 HTTP {r.status_code} code={err.get('Code')} msg={err.get('Message')}"
    res = j.get("Result") or {}
    token = res.get("Token")
    if not token:
        return False, None, f"续期响应无 Token: {json.dumps(j, ensure_ascii=False)[:200]}"
    return True, {
        "token": token,
        "refresh_token": res.get("RefreshToken") or refresh,
        "expires_ms": float(res.get("TokenExpireAt") or 0),
        "refresh_expires_ms": float(res.get("RefreshExpireAt") or 0),
    }, None


def write_back_storage(new_token: str, new_refresh: str, token_expire_ms: float, refresh_expire_ms: float):
    """把续期结果写回本机 storage.json 的 cloudide 信封，保持桌面端 Trae 一致（避免被迫重登）。
    仅当本机存在 storage.json 且可写时执行；失败仅告警不中断。"""
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return
    sp = os.path.join(appdata, "TRAE SOLO CN", STORAGE_REL)
    if not os.path.isfile(sp):
        return
    try:
        with open(sp, "r", encoding="utf-8") as fh:
            st = json.load(fh)
        enc = st.get(AUTH_KEY)
        if not enc:
            return
        auth = decrypt_trae_auth_info(enc)
        auth["token"] = new_token
        if new_refresh:
            auth["refreshToken"] = new_refresh
        if token_expire_ms:
            auth["expiredAt"] = datetime.fromtimestamp(token_expire_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if refresh_expire_ms:
            auth["refreshExpiredAt"] = datetime.fromtimestamp(refresh_expire_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        auth["tokenReleaseAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        st[AUTH_KEY] = encrypt_trae_auth_info(json.dumps(auth, ensure_ascii=False))
        with open(sp, "w", encoding="utf-8") as fh:
            json.dump(st, fh, ensure_ascii=False)
        print("[trae] 已把续期结果同步写回本机 storage.json（桌面端登录态保持一致）")
    except Exception as e:
        print(f"[warn] 写回 storage.json 失败（不影响本次签到）: {e}")


def self_heal(cred: dict):
    """自动续期：用 refreshToken 换发新 token，更新 cred 并落盘缓存。返回 (ok, message)。"""
    ok, fields, err = exchange_token(cred)
    if not ok:
        return False, f"⚠️ {cred.get('user_id') or '未知用户'} 自动续期失败：{err}"
    cred["token"] = fields["token"]
    cred["refresh_token"] = fields["refresh_token"]
    cred["expires_ms"] = fields["expires_ms"]
    cred["refresh_expires_ms"] = fields["refresh_expires_ms"]
    save_cache(cred)
    # 本机有 Trae 桌面端时同步写回，保持两端刷新令牌一致
    write_back_storage(fields["token"], fields["refresh_token"], fields["expires_ms"], fields["refresh_expires_ms"])
    remain = (fields["expires_ms"] - datetime.now(timezone.utc).timestamp() * 1000) / 86400000
    return True, f"已自动续期 token（新有效期约 {remain:.1f} 天）"


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
    """读取主实例 %APPDATA%\\TRAE SOLO CN 登录态，返回完整凭据 dict（含续期材料）或 None。"""
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
        # 设备 ECDSA 密钥对（icube-dc 信封），服务端校验 ExchangeToken 设备证明所需
        device_key_pem = device_pub_pem = ""
        if device_id:
            dev_enc = storage.get(f"iCubeAuthInfo://icube-dc:{device_id}")
            if dev_enc:
                try:
                    dev = decrypt_trae_auth_info(dev_enc)
                    device_key_pem = (dev.get("privateKeyPEM") or "").strip()
                    device_pub_pem = (dev.get("publicKeyPEM") or dev.get("publicKeyPEM") or "").strip()
                except Exception as e:
                    print(f"[warn] 解密设备密钥失败: {e}")
        return {
            "token": token,
            "device_id": device_id,
            "user_id": str(auth.get("userId") or ""),
            "expires_ms": parse_time_ms(auth.get("expiredAt")),
            "refresh_token": (auth.get("refreshToken") or "").strip(),
            "device_key_pem": device_key_pem,
            "device_pub_pem": device_pub_pem,
            "machine_id": (storage.get("telemetry.machineId") or "").strip(),
        }
    except Exception as e:
        print(f"[warn] 解析 {storage_path} 失败: {e}")
        return None


def resolve_credentials():
    """读取环境变量 + 续期缓存（缓存优先），返回完整凭据 dict。

    自愈所需材料（一次性引导后持续有效）：
        TRAE_TOKEN / TRAE_DEVICE_ID / TRAE_USER_ID         —— 基础登录态
        TRAE_REFRESH_TOKEN / TRAE_DEVICE_KEY_PEM /          —— 自动续期材料
        TRAE_DEVICE_PUB_PEM / TRAE_MACHINE_ID
    缓存 .trae_token.json 在每次成功续期后写回，是续期后的权威来源。
    """
    cred = {
        "token": os.environ.get("TRAE_TOKEN", "").strip(),
        "device_id": os.environ.get("TRAE_DEVICE_ID", "").strip(),
        "user_id": os.environ.get("TRAE_USER_ID", "").strip(),
        "refresh_token": os.environ.get("TRAE_REFRESH_TOKEN", "").strip(),
        "device_key_pem": _normalize_pem(os.environ.get("TRAE_DEVICE_KEY_PEM", "")),
        "device_pub_pem": _normalize_pem(os.environ.get("TRAE_DEVICE_PUB_PEM", "")),
        "machine_id": os.environ.get("TRAE_MACHINE_ID", "").strip(),
        "expires_ms": 0,
        "refresh_expires_ms": 0,
    }
    # 缓存优先覆盖（续期后刷新令牌会轮换，env 里的旧 refresh 会失效）
    cache = load_cache()
    if cache:
        for k in ("token", "device_id", "user_id", "refresh_token",
                  "device_key_pem", "device_pub_pem", "machine_id",
                  "expires_ms", "refresh_expires_ms"):
            if cache.get(k):
                cred[k] = cache[k]
    return cred


AUTH_FAIL_KEYWORDS = ("unauthorized", "token", "expired", "not login",
                      "not logged", "登录", "鉴权", "authenticate")
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
        # 业务层鉴权失败：1001 = 无法认证（token 失效/无效，服务端常以 HTTP 200 + code 返回）
        if code in (401, 403, 1001):
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
def build_checkin_headers(token: str, device_id: str) -> dict:
    """签到/状态/积分接口共用的请求头，对齐逆向仓库 postUg 的最小集。"""
    return {
        "content-type": "application/json",
        "authorization": token if str(token).startswith("Cloud-IDE-JWT ")
                          else f"Cloud-IDE-JWT {token}",
        "x-device-id": device_id or "",
    }


def api_call(host, token, device_id, path, body=None, timeout=30):
    """发起签到接口请求。

    静默运行：成功不输出；仅当 HTTP 非 200（传输层失败）或请求异常时，打印一行
    简短日志（路径 + HTTP 状态 + 截断响应体），且绝不打印任何鉴权头与 token。
    """
    headers = build_checkin_headers(token, device_id)
    url = f"{host}{path}"
    req_body = json.dumps(body or {})

    try:
        # 用 PreparedRequest 精确控制最终发出的 header，避免 requests 自动注入多余默认值
        req = requests.Request("POST", url, headers=headers, data=req_body)
        prepared = req.prepare()

        session = requests.Session()
        # proxies=None 强制直连 api.trae.cn，避免走系统/本地代理导致被限频或连不上
        r = session.send(prepared, timeout=timeout, proxies={"http": None, "https": None})

        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text[:300]}

        # 成功静默；仅传输层失败时打印一行简短日志（不含 token）
        if r.status_code != 200:
            print(f"[trae] {path} -> HTTP {r.status_code} {r.text[:200]}")
        return r.status_code, data
    except Exception as e:
        print(f"[trae] {path} 请求异常: {e}")
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


def _can_self_heal(cred: dict) -> bool:
    """是否具备自动续期所需的材料（refreshToken + 设备 ECDSA 私钥 + 公钥）。"""
    return bool(cred.get("refresh_token") and cred.get("device_key_pem") and cred.get("device_pub_pem"))


def checkin_once(cred: dict):
    """执行单次签到，返回 (结果标记, 通知文本)。

    自愈策略（材料齐备时）：
      - 无 token：先用 refreshToken 续期再签到；
      - token 即将过期（<48h）：先续期，避免拿到马上失效的 token；
      - 状态/领取返回鉴权失败：自动续期并重试一次。
    材料缺失（纯环境变量 token、未引导设备私钥）时退化为原行为并给出可读指引。
    """
    cred = cred or {}
    token = cred.get("token", "").strip()
    device_id = cred.get("device_id", "")

    # 无 token 但有续期材料：先续期再签到
    if not token:
        if _can_self_heal(cred):
            ok, msg = self_heal(cred)
            if not ok:
                return "AUTH_EXPIRED", f"⚠️ 未获取到 token 且自动续期失败：{msg}"
            token = cred["token"]
            print(f"[trae] {msg}")
        else:
            return "NO_CREDENTIAL", ("未获取到 Trae 登录态，请设置环境变量 TRAE_TOKEN / TRAE_DEVICE_ID"
                                     "（或运行 python trae_checkin.py --export-keys --save 引导自动续期）")

    host = HOST

    # token 即将过期（<48h）或已过期且可自愈：先续期，避免用失效 token 去签到
    if _can_self_heal(cred):
        exp = cred.get("expires_ms") or (decode_jwt_exp(token) * 1000)
        remain_h = (exp - datetime.now(timezone.utc).timestamp() * 1000) / 3600000
        if remain_h <= 48:
            ok, msg = self_heal(cred)
            if ok:
                token = cred["token"]
                print(f"[trae] {msg}")

    # 1) 状态查询
    sc, sb = api_call(host, token, device_id, STATUS_PATH)
    if isinstance(sb, dict) and sb.get("checked_in"):
        pts = query_points(host, token, device_id)
        extra = f"，剩余积分 {pts}" if pts is not None else ""
        return "ALREADY_TODAY", f"ℹ️ 今日已签到{extra}"
    if is_auth_failure(sc, sb):
        if _can_self_heal(cred):
            ok, msg = self_heal(cred)
            if ok:
                token = cred["token"]
                print(f"[trae] {msg}")
            else:
                return "AUTH_EXPIRED", f"⚠️ 鉴权失败（HTTP {sc}）且自动续期失败：{msg}"
            sc, sb = api_call(host, token, device_id, STATUS_PATH)
            if isinstance(sb, dict) and sb.get("checked_in"):
                pts = query_points(host, token, device_id)
                extra = f"，剩余积分 {pts}" if pts is not None else ""
                return "ALREADY_TODAY", f"ℹ️ 今日已签到{extra}（已自动续期）"
            if is_auth_failure(sc, sb):
                return "AUTH_EXPIRED", f"⚠️ 续期后再次鉴权失败（HTTP {sc}），请检查设备证明材料是否完整"
        else:
            return "AUTH_EXPIRED", (f"⚠️ 鉴权失败（HTTP {sc}），请打开 Trae 桌面端刷新登录态，"
                                     "或运行 python trae_checkin.py --export-keys --save 引导自动续期")
    if not api_succeeded(sb):
        msg = (sb or {}).get("message") or (sb or {}).get("msg") or json.dumps(sb, ensure_ascii=False)[:120]
        if is_rate_limited(sc, sb):
            return "RATE_LIMITED", f"⏳ 服务端限频（活动高峰容量不足，与请求特征无关）：{msg}，建议错峰或稍后重试"
        return "STATUS_ERR", f"⚠️ 状态查询异常：HTTP {sc} {msg}"

    # 2) 领取
    cc, cb = api_call(host, token, device_id, CLAIM_PATH)
    if is_auth_failure(cc, cb):
        if _can_self_heal(cred):
            ok, msg = self_heal(cred)
            if ok:
                token = cred["token"]
                print(f"[trae] {msg}")
            else:
                return "AUTH_EXPIRED", f"⚠️ 领取时鉴权失败（HTTP {cc}）且自动续期失败：{msg}"
            cc, cb = api_call(host, token, device_id, CLAIM_PATH)
        else:
            return "AUTH_EXPIRED", f"⚠️ 领取时鉴权失败（HTTP {cc}），请打开 Trae 桌面端刷新登录态"
    if api_succeeded(cb):
        points = ((cb.get("data") or {}).get("points")) or cb.get("points")
        message = cb.get("message") or cb.get("msg") or ""
        pts = query_points(host, token, device_id)
        extra = f"，剩余积分 {pts}" if pts is not None else ""
        text = "签到成功" if message == "success" else message
        gain = f"本次 +{points} 积分" if points else text
        return "SUCCESS", f"✅ {gain}{extra}"

    msg = (cb or {}).get("message") or (cb or {}).get("msg") or json.dumps(cb, ensure_ascii=False)[:150]
    if is_rate_limited(cc, cb):
        return "RATE_LIMITED", f"⏳ 服务端限频（活动高峰容量不足，与请求特征无关）：{msg}，建议错峰或稍后重试"
    return "FAIL", f"⚠️ 签到未成功：HTTP {cc} {msg}"


def export_env():
    """--export-env / --export-keys：从本机登录态解密并打印完整环境变量（含自动续期材料）。
    追加 --save 直接写回同目录 .env，并写入续期缓存 .trae_token.json。"""
    c = read_local_credential()
    if not c:
        print("未发现 Trae 登录态，请先在本机登录 Trae 桌面端")
        return 1
    values = {
        "TRAE_TOKEN": c["token"],
        "TRAE_DEVICE_ID": c["device_id"],
        "TRAE_USER_ID": c["user_id"],
        "TRAE_REFRESH_TOKEN": c["refresh_token"],
        "TRAE_DEVICE_KEY_PEM": base64.b64encode((c["device_key_pem"] or "").encode()).decode(),
        "TRAE_DEVICE_PUB_PEM": base64.b64encode((c["device_pub_pem"] or "").encode()).decode(),
        "TRAE_MACHINE_ID": c["machine_id"],
    }
    for k, v in values.items():
        print(f"{k}={v}")
    if c["expires_ms"]:
        exp = datetime.fromtimestamp(c["expires_ms"] / 1000, tz=timezone.utc)
        print(f"# token 过期时间(UTC): {exp:%Y-%m-%d %H:%M}")
    print("# 说明：TRAE_DEVICE_KEY_PEM 为设备 ECDSA 私钥，请勿外泄；它使脚本可在无 Trae 桌面端的")
    print("#       服务器上用 refreshToken 自动续期，无需每天手动刷新。")
    if "--save" in sys.argv:
        n = _save_env_values(values)
        if n:
            print(f"# 已将上述 {n} 个变量写回 .env")
        # 同时写入续期缓存（与 .env 互为备份，缓存为续期后权威来源）
        save_cache({
            "token": c["token"],
            "refresh_token": c["refresh_token"],
            "device_id": c["device_id"],
            "user_id": c["user_id"],
            "machine_id": c["machine_id"],
            "device_key_pem": c["device_key_pem"],
            "device_pub_pem": c["device_pub_pem"],
            "expires_ms": c["expires_ms"],
        })
        print(f"# 已写入续期缓存 {os.path.basename(CACHE_FILE)}")
    return 0


def renew_cmd():
    """--renew：用 refreshToken 续期，写回缓存与（本机存在时）storage.json。"""
    cred = resolve_credentials()
    if not _can_self_heal(cred):
        # 环境/缓存无材料时，尝试从本机 storage.json 引导
        c = read_local_credential()
        if c:
            cred.update({k: c[k] for k in ("token", "device_id", "user_id", "expires_ms",
                                           "refresh_token", "device_key_pem",
                                           "device_pub_pem", "machine_id") if c.get(k)})
    if not _can_self_heal(cred):
        print("缺少自动续期材料（refreshToken / 设备私钥）。请先在本机登录 Trae 桌面端后运行：")
        print("  python trae_checkin.py --export-keys --save")
        return 1
    ok, msg = self_heal(cred)
    print(msg)
    return 0 if ok else 1


def main():
    # python trae_checkin.py --export-env / --export-keys  仅导出环境变量后退出
    if "--export-env" in sys.argv or "--export-keys" in sys.argv:
        sys.exit(export_env())
    # python trae_checkin.py --renew  仅续期（写回缓存与 storage.json）
    if "--renew" in sys.argv:
        sys.exit(renew_cmd())

    title = "Trae Work 每日签到"
    cred = resolve_credentials()
    flag, content = checkin_once(cred)

    print(f"RESULT={flag} | {content}")

    if _HAS_NOTIFY and not os.environ.get("CHECKIN_NO_NOTIFY"):
        try:
            sendNotify.serverJMy(title, content)
        except Exception as e:
            print(f"[warn] 通知发送失败: {e}")


if __name__ == "__main__":
    main()
