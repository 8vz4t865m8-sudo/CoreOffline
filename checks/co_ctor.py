#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
构造函数早期安全性检查 (dyld 阶段)

这是从真机闪退里总结出来的一套规则，单独成文件是因为：
  · co_audit.py 的 A 节需要 /tmp/uishim 替身头才能跑 clang 语法检查，
    CI 上没有这套头文件；
  · 但下面这几条规则是纯文本分析，CI 上必须跑。

背景：constructor 的执行时机是 dyld 加载 dylib 的瞬间，
      此时 NSUserDefaults / Security / locale / runloop 都可能没就绪。
      在这里碰它们会直接崩 —— 典型症状是「一注入就闪退」。
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")

PASS, FAIL, WARN = [], [], []


def ok(m):
    PASS.append(m)


def bad(m):
    FAIL.append(m)


def warn(m):
    WARN.append(m)


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def strip_comments(t):
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    t = re.sub(r"//[^\n]*", "", t)
    t = re.sub(r"#pragma[^\n]*", "", t)
    return t


def brace_body(text, open_idx):
    """从 '{' 开始做括号配对，返回函数体字符串。"""
    depth, i = 0, open_idx
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx:i + 1]
        i += 1
    return text[open_idx:]


def main():
    core_path = os.path.join(SRC, "CoreOffline.m")
    if not os.path.exists(core_path):
        print(f"❌ 找不到 {core_path}")
        return 1
    core = read(core_path)

    print("=" * 74)
    print("构造函数早期安全性 (dyld 阶段)")
    print("=" * 74)

    # ── H1: constructor 里不许有早期不安全调用 ──────────────────
    UNSAFE = {
        "[COVerifyBridge shared]":        "COVerifyBridge 单例 (init 会读 NSUserDefaults)",
        "NSUserDefaults":                 "NSUserDefaults (_CFXPreferences 未就绪)",
        "NSClassFromString(@\"T3Verify\")": "T3Verify SDK (Security.framework 未就绪)",
        "NSDateFormatter":                "NSDateFormatter (locale/ICU 未就绪)",
        "NSTimer":                        "NSTimer (runloop 未跑)",
        "scheduledTimerWithTimeInterval": "NSTimer (runloop 未跑)",
    }

    ctor_re = re.search(
        r"__attribute__\(\(constructor\)\)\s*\n\s*static\s+void\s+\w+\s*\(void\)\s*\{",
        core,
    )
    ctor_body = None
    if ctor_re:
        ctor_body = strip_comments(brace_body(core, core.index("{", ctor_re.end() - 1)))
        hit = [f"{k} —— {v}" for k, v in UNSAFE.items() if k in ctor_body]
        if hit:
            for h in hit:
                bad(f"H1 constructor 里有早期不安全调用：{h}")
        else:
            ok("H1 constructor 无早期不安全调用")
    else:
        warn("H1 没找到 constructor，跳过")

    # ── H2: 卡密子系统必须延后到主队列 ─────────────────────────
    if ctor_body is not None:
        if "dispatch_async(dispatch_get_main_queue()" in ctor_body:
            ok("H2 卡密子系统经主队列延后启动")
        else:
            bad("H2 卡密子系统没有延后，ctor 里同步启动了")

    # ── H3: expiry getter 必须有子系统就绪守卫 ─────────────────
    exp_re = re.search(r"static\s+NSString\s*\*\s*CoreLicenseExpiryString\s*\(void\)\s*\{", core)
    if exp_re:
        ebody = strip_comments(brace_body(core, core.index("{", exp_re.end() - 1)))
        if "gLicenseSubsystemUp" in ebody:
            ok("H3 expiry getter 有子系统就绪守卫")
        else:
            bad("H3 expiry getter 缺守卫 —— 宿主在启动早期读 authorizationValue 会崩")
    else:
        warn("H3 找不到 CoreLicenseExpiryString")

    # ── H4: 守卫标志必须被置位，且顺序正确 ─────────────────────
    if "gLicenseSubsystemUp" in core:
        if re.search(r"gLicenseSubsystemUp\s*=\s*YES", core):
            ok("H4 子系统就绪标志被置位")
        else:
            bad("H4 守卫标志定义了但从未置位 —— 会导致永远判定为未授权")

        m_shared = core.find("[COVerifyBridge shared]")
        m_flag = core.find("gLicenseSubsystemUp = YES")
        if m_shared >= 0 and m_flag >= 0 and m_flag > m_shared:
            ok("H4b 置位在 shared 初始化之后")
        elif m_shared >= 0 and m_flag >= 0:
            bad("H4b 置位早于 shared 初始化 —— 中间窗口期不安全")
    else:
        bad("H4 没有子系统就绪守卫")

    # ── H5: CorePresentLicenseDialog 也要有守卫 ────────────────
    dlg_re = re.search(r"static\s+void\s+CorePresentLicenseDialog\s*\(void\)\s*\{", core)
    if dlg_re:
        dbody = strip_comments(brace_body(core, core.index("{", dlg_re.end() - 1)))
        if "gLicenseSubsystemUp" in dbody:
            ok("H5 弹窗函数有子系统守卫")
        else:
            warn("H5 弹窗函数没有子系统守卫（非致命，但建议加）")

    print()
    print("=" * 74)
    print("结果")
    print("=" * 74)
    print(f"  ✅ 通过 {len(PASS)}")
    print(f"  ⚠️  警告 {len(WARN)}")
    print(f"  ❌ 失败 {len(FAIL)}")
    if WARN:
        print("\n  警告明细：")
        for w in WARN:
            print(f"    ⚠️  {w}")
    if FAIL:
        print("\n  失败明细：")
        for f in FAIL:
            print(f"    ❌ {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
