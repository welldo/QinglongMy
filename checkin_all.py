#!/bin/env python3
# -*- coding: utf-8 -*
"""
cron: 8 0 * * * checkin_all.py
new Env('每日签到汇总');

==================== 聚合签到（单次定时，一次推送）====================

把多个独立签到脚本聚合到【一次定时任务】里依次执行，最后把各脚本结果
合并成一条消息，只推送一次（避免每个脚本各自推送刷屏）。

当前聚合（执行顺序即列表顺序）：
    - WorkBuddy 每日签到    (workbuddy_checkin.py)
    - Trae Work 每日签到    (trae_checkin.py)
    - MiniMax Code 每日签到 (minimax_checkin.py)

设计要点：
    - 子脚本均已提供 checkin_once(cred) -> (flag, content)，本脚本直接调用并
      收集结果，不触发子脚本自身的推送（最终合并推送由本脚本统一发出）。
    - 子脚本在【导入阶段】失败（如依赖缺失会 sys.exit）时，仅跳过该脚本并在
      汇总中标注，不中断其余脚本。
    - 任一脚本运行异常均被捕获，结果如实汇总。
    - 设置环境变量 CHECKIN_NO_NOTIFY=1 可关闭【最终合并推送】，便于本地调试。

在青龙/定时平台只需建【一个】任务指向本脚本即可，原 3 个独立签到任务的
定时可停用或删除。

依赖：pip install requests pycryptodome python-dotenv
==============================================================================
"""

import os
import sys
import importlib
import traceback
from datetime import datetime

# 本地开发时自动加载同目录 .env
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


# 聚合的脚本清单：(显示名, 模块文件名(不含 .py), 推送标题)
# 顺序即执行顺序：WorkBuddy -> Trae Work -> MiniMax Code
TASKS = [
    ("WorkBuddy", "workbuddy_checkin", "WorkBuddy 每日签到"),
    ("Trae Work", "trae_checkin", "Trae Work 每日签到"),
    ("MiniMax Code", "minimax_checkin", "MiniMax Code 每日签到"),
]

# 结果标记 -> 汇总行前缀图标
FLAG_ICON = {
    "SUCCESS": "✅",
    "ALREADY_TODAY": "ℹ️",
    "NET_ERR": "⚠️",
    "HTTP_ERR": "⚠️",
    "FAIL": "⚠️",
    "TOKEN_EXPIRED": "⚠️",
    "AUTH_EXPIRED": "⚠️",
    "RATE_LIMITED": "⏳",
    "NO_CREDENTIAL": "⚠️",
    "IMPORT_FAIL": "⚠️",
    "ERROR": "⚠️",
}


def _import_module(mod_name):
    """导入子模块；失败时返回 (None, 错误信息)。
    捕获 BaseException 以兼容子模块在 import 阶段 sys.exit / 依赖缺失等情况。"""
    try:
        return importlib.import_module(mod_name), None
    except BaseException as e:  # 含 SystemExit（如 trae 缺 pycryptodome 时 sys.exit(1)）
        return None, f"{type(e).__name__}: {e}"


def run_one(display_name, mod_name):
    """运行单个签到，返回 (display_name, flag, content)。异常被捕获并标注。"""
    mod, err = _import_module(mod_name)
    if mod is None:
        return display_name, "IMPORT_FAIL", f"⚠️ 模块导入失败，已跳过：{err}"
    try:
        cred = mod.resolve_credentials()
        flag, content = mod.checkin_once(cred)
        return display_name, flag, content
    except BaseException as e:
        return display_name, "ERROR", \
            f"⚠️ 执行异常：{type(e).__name__}: {e}\n{traceback.format_exc()[-500:]}"


def build_summary(results):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"【每日签到汇总 · {now}】", ""]
    ok = 0
    for name, flag, content in results:
        icon = FLAG_ICON.get(flag, "•")
        first_line = str(content).splitlines()[0] if str(content).strip() else "(空)"
        lines.append(f"{icon} {name}：{first_line}")
        if flag in ("SUCCESS", "ALREADY_TODAY"):
            ok += 1
    lines.append("")
    lines.append(f"共 {len(results)} 项，成功/已签 {ok} 项")
    return "\n".join(lines)


def main():
    if "--export-env" in sys.argv:
        print("本聚合脚本无需导出环境变量；请对单个签到脚本使用 --export-env")
        return

    results = []
    for display_name, mod_name, _title in TASKS:
        name, flag, content = run_one(display_name, mod_name)
        results.append((name, flag, content))
        # 实时打印（仅首行，便于日志查看；完整内容见下方汇总）
        print(f"[{name}] RESULT={flag} | {str(content).splitlines()[0]}")

    summary = build_summary(results)
    print("\n" + "=" * 50)
    print(summary)
    print("=" * 50)

    no_push = os.environ.get("CHECKIN_NO_NOTIFY", "").strip() in ("1", "true", "True")
    if _HAS_NOTIFY and not no_push:
        try:
            sendNotify.serverJMy("每日签到汇总", summary)
        except Exception as e:
            print(f"[warn] 合并推送失败: {e}")
    elif no_push:
        print("[info] CHECKIN_NO_NOTIFY 已设置，跳过合并推送")
    else:
        print("[warn] 未找到 sendNotify，跳过推送")


if __name__ == "__main__":
    main()
