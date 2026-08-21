#!/bin/env python3
# -*- coding: utf-8 -*
"""
cron: 9 0 * * * workbuddy_checkin.py
new Env('WorkBuddy每日积分签到');

==================== 如何获取 WB_ACCESS_TOKEN / WB_USER_ID ====================

脚本签到点 = POST https://copilot.tencent.com/v2/billing/meter/daily-checkin
鉴权需要两个值：accessToken（Bearer） + uid（X-User-Id）。

【方式一 · 推荐，免维护，默认生效】
不填写任何环境变量，脚本自动读取本机已登录的 WorkBuddy 桌面端明文登录态：

    文件： %LOCALAPPDATA%\\CodeBuddyExtension\\Data\\Public\\auth\\workbuddy-desktop.info
    （v5.3.8+ 桌面端写入，纯文本 JSON，无需解密）

    字段提取：
        WB_ACCESS_TOKEN = JSON 中的  auth.accessToken
        WB_USER_ID      = JSON 中的  account.uid
        WB_DOMAIN       = JSON 中的  auth.domain  （一般无需填写，留空自动读取）

    说明：desktop.info 由桌面端定期刷新，脚本每次运行都重新读取，token 永不过期。
    macOS： ~/Library/Application Support/CodeBuddyExtension/Data/Public/auth/workbuddy-desktop.info
    Linux： ~/.config/CodeBuddyExtension/Data/Public/auth/workbuddy-desktop.info

【方式二 · 手动填入环境变量（适合跨机 / 容器部署）】
从本机登录态文件里取出上面两个字段，写入 .env：

        WB_ACCESS_TOKEN=<auth.accessToken 的值>
        WB_USER_ID=<account.uid 的值>

    注意：这是静态快照，桌面端刷新后旧 token 会失效（401），需重新拷贝或改回方式一。

【env 提取小技巧（本机一行命令）】
    python - <<'PY'
    import json,os
    p=os.path.join(os.environ['LOCALAPPDATA'],'CodeBuddyExtension','Data','Public','auth','workbuddy-desktop.info')
    j=json.load(open(p,encoding='utf-8'))
    print('WB_ACCESS_TOKEN='+j['auth']['accessToken'])
    print('WB_USER_ID='+str(j['account']['uid']))
    PY

优先级：环境变量 WB_ACCESS_TOKEN+WB_USER_ID > 本机明文登录态文件。
==============================================================================
"""

import os
import sys
import json
import platform
import requests

# 通知模块（同目录 sendNotify.py）；若缺失则降级为仅打印，不影响领取。
try:
    import sendNotify
    _HAS_NOTIFY = True
except Exception:
    _HAS_NOTIFY = False

API_BASE = "https://copilot.tencent.com"
CHECKIN_PATH = "/v2/billing/meter/daily-checkin"
STATUS_PATH = "/v2/billing/meter/checkin-status"

# 本地明文登录态候选路径（v5.3.8+ 桌面端写入）
def _local_info_candidates():
    cands = []
    if platform.system() == "Windows":
        local = os.environ.get("LOCALAPPDATA", "")
        app = os.environ.get("APPDATA", "")
        if local:
            cands.append(os.path.join(local, "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info"))
        if app:
            cands.append(os.path.join(app, "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info"))
    elif platform.system() == "Darwin":
        home = os.path.expanduser("~")
        cands.append(os.path.join(home, "Library", "Application Support",
                                  "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info"))
    else:
        home = os.path.expanduser("~")
        cands.append(os.path.join(home, ".config", "CodeBuddyExtension", "Data", "Public", "auth",
                                  "workbuddy-desktop.info"))
    return cands


def resolve_credentials():
    """优先用环境变量，缺失时回退读取本机明文登录态。"""
    token = os.environ.get("WB_ACCESS_TOKEN", "").strip()
    uid = os.environ.get("WB_USER_ID", "").strip()
    domain = os.environ.get("WB_DOMAIN", "").strip()

    if token and uid:
        return token, uid, domain, "env"

    for f in _local_info_candidates():
        if not os.path.isfile(f):
            continue
        try:
            with open(f, "r", encoding="utf-8") as fh:
                j = json.load(fh)
            token = (j.get("auth") or {}).get("accessToken", "")
            acct = j.get("account") or {}
            auth = j.get("auth") or {}
            uid = str(acct.get("uid", "") or "")
            domain = str(auth.get("domain", "") or "")
            if token and uid:
                return token, uid, domain, "local"
        except Exception as e:
            print(f"[warn] 读取本地登录态失败 {f}: {e}")
    return "", "", "", "none"


def _call(token, uid, domain, path):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "X-User-Id": uid,
    }
    if domain:
        headers["X-Domain"] = domain
    try:
        r = requests.post(API_BASE + path, headers=headers, data="{}", timeout=15)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"raw": r.text}
    except Exception as e:
        return 0, {"error": str(e)}


def main():
    token, uid, domain, src = resolve_credentials()
    if not token or not uid:
        msg = ("未获取到 WorkBuddy 登录态：请设置环境变量 WB_ACCESS_TOKEN / WB_USER_ID，"
               "或确保本机已登录 WorkBuddy 桌面端（v5.3.8+）。")
        print(msg)
        if _HAS_NOTIFY:
            sendNotify.send("WorkBuddy 签到失败", msg)
        return

    print(f"[info] 凭据来源={src} uid={uid} domain={domain or '-'}")

    # 查询状态（仅参考，today_checked_in 不可靠）
    sc, sb = _call(token, uid, domain, STATUS_PATH)
    print(f"[status] HTTP {sc} -> {json.dumps(sb, ensure_ascii=False)[:200]}")

    # 执行领取（幂等：code=10001 表示今日已签）
    cc, cb = _call(token, uid, domain, CHECKIN_PATH)
    print(f"[checkin] HTTP {cc} -> {json.dumps(cb, ensure_ascii=False)[:300]}")

    title = "WorkBuddy 每日签到"
    if cc == 0:
        content = f"⚠️ 网络异常，签到请求未发出：{json.dumps(cb, ensure_ascii=False)[:200]}"
        print("RESULT=NET_ERR")
    elif isinstance(cb, dict):
        code = cb.get("code")
        if code == 0:
            d = cb.get("data", {})
            content = (f"✅ 领取成功\n- 本次积分：{d.get('credit')}\n"
                       f"- 连续签到：第 {d.get('streak_days')} 天")
            print("RESULT=SUCCESS credit=%s streak_days=%s" % (d.get('credit'), d.get('streak_days')))
        elif code == 10001:
            content = "ℹ️ 今日已签到，无需重复领取"
            print("RESULT=ALREADY_TODAY")
        elif cc in (401, 403):
            content = f"⚠️ 令牌失效（HTTP {cc}），请打开 WorkBuddy 桌面端刷新登录态后重试"
            print("RESULT=TOKEN_EXPIRED")
        else:
            content = f"⚠️ 签到未成功：HTTP {cc} code={code} msg={cb.get('msg')}"
            print("RESULT=FAIL code=%s msg=%s" % (code, cb.get('msg')))
    else:
        content = f"⚠️ 请求异常（HTTP {cc}）：{json.dumps(cb, ensure_ascii=False)[:200]}"
        print("RESULT=HTTP_ERR code=%s" % cc)

    if _HAS_NOTIFY:
        sendNotify.serverJMy(title, content)


if __name__ == '__main__':
    main()
