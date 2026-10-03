#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoreOffline 真机 API 仿真检查

背景：
  沙箱里用替身头（/tmp/uishim）做语法检查，代价是「替身有什么就能编过」。
  本次 CI 第一次跑就抓到三个真错误 —— 全是因为替身里被我编了
  真实 SDK 不存在的 API：

    1. CGContextGetStrokeColor()          ← CoreGraphics 根本没这个函数
    2. animateWithDuration:delay:options:animations:
                                          ← UIKit 只有带 completion: 的那版
    3. T3Verify.m 用了 UIDevice 却没 import UIKit（只在 iOS 分支启用）

  这个脚本专门扫「已知不存在 / 需要前置条件」的 API 用法，
  把这类错误在推 CI 之前拦下来，不再靠 CI 兜底。
"""
import os, re, sys

ROOT = "/root/.codebuddy/artifact/coreoffline"
SRC = os.path.join(ROOT, "src")
SDK = os.path.join(ROOT, "sdk")

def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()

def strip_comments(t):
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    t = re.sub(r"//[^\n]*", "", t)
    t = re.sub(r"#pragma[^\n]*", "", t)
    return t

FILES = {}
for d in [SRC, SDK]:
    for f in sorted(os.listdir(d)):
        if f.endswith(".m"):
            FILES[f] = strip_comments(read(os.path.join(d, f)))

P, F = [], []
def ok(m): P.append(m)
def bad(m): F.append(m)

print("=" * 74)
print("L. 真机 API 仿真")
print("=" * 74)

# ── L1 CGContextGetStrokeColor / GetFillColor 不存在
#      ★ 用词边界匹配：CGContextSetStrokeColorWithColor 里
#        包含了 CGContextSetStrokeColor 这个子串，不用 \b 会误报。
GHOST_CG = [
    "CGContextGetStrokeColor",
    "CGContextGetFillColor",
    "CGContextSetStrokeColor",         # 只有 ...WithColor 版
    "CGContextSetFillColor",           # 只有 ...WithColor 版
    "CGContextGetLineWidth",
    "CGPathCreateCopyByStrokingPath",
]
hits = []
for fn, body in FILES.items():
    for g in GHOST_CG:
        # 后面不允许再跟 WithColorWithColor / WithColor
        if re.search(r"\b" + g + r"\b(?!WithColor)", body):
            hits.append(f"{fn}:{g}")
if not hits:
    ok("L1 未使用不存在的 CoreGraphics 取色 API")
else:
    bad(f"L1 用了真实 SDK 里不存在的 CG API：{hits}")

# ── L2 UIKit 动画必须带 completion:
#      animateWithDuration:delay:options:animations: 这版不存在，
#      只有 animateWithDuration:delay:options:animations:completion:
anim_calls = re.findall(
    r"animateWithDuration:[^;]*?options:[^;]*?animations:\s*\{[\s\S]*?\}\s*\]",
    "".join(FILES.values()))
bad_anim = []
for c in anim_calls:
    if "delay:" in c and "completion:" not in c:
        bad_anim.append(re.sub(r"\s+", " ", c)[:70])
if not bad_anim:
    ok("L2 带 delay 的动画都传了 completion:")
else:
    bad(f"L2 动画缺 completion:（该重载不存在）：{bad_anim}")

# ── L3 UIDevice / UIScreen / UIApplication 需要 UIKit
UIKIT_SYMS = ["UIDevice", "UIScreen", "UIApplication", "UIImage", "UIView", "UIColor"]
for fn, body in FILES.items():
    if fn.startswith("T3Verify"):
        continue   # SDK 单独判（见 L4）
    used = [s for s in UIKIT_SYMS if re.search(r"\b" + s + r"\b", body)]
    has_import = re.search(r'#import\s*[<"](UIKit/UIKit\.h|COTheme\.h|COIcon\.h|COLicenseDialog\.h|COVerifyBridge\.h)', body)
    if used and not has_import:
        bad(f"L3 {fn} 用了 {used} 但没 import UIKit 系头文件")
if not any("L3" in x for x in F):
    ok("L3 各源文件 UIKit 依赖与 import 匹配")

# ── L4 T3Verify.m 的 iOS 分支符号必须在 #if TARGET_OS_IOS 内且 import 了 UIKit
p = os.path.join(SDK, "T3Verify.m")
t = read(p)
if "UIDevice" in t:
    has_cond_import = re.search(r"#if\s+TARGET_OS_IOS[\s\S]{0,400}?#import\s*<UIKit/UIKit\.h>", t)
    if has_cond_import:
        ok("L4 T3Verify.m 在 iOS 分支补了 UIKit import")
    else:
        bad("L4 T3Verify.m 用了 UIDevice 但 iOS 分支没 import UIKit")

# ── L5 NSInvocation 的 setArgument:atIndex: 不能越界
#      初始化方法 6 个入参 + 1 个 error，索引 2..8
for fn, body in FILES.items():
    for m in re.finditer(r"setArgument:&(\w+)\s+atIndex:(\d+)", body):
        idx = int(m.group(2))
        if idx < 2:
            bad(f"L5 {fn} setArgument atIndex:{idx} 会踩到 self/_cmd")
if not any("L5" in x for x in F):
    ok("L5 NSInvocation 索引都从 2 起（未覆盖 self/_cmd）")

# ── L6 __unsafe_unretained 用在 getReturnValue 上（对象出参必须用这个）
for fn, body in FILES.items():
    if "getReturnValue:" in body:
        # 检查被传的变量是否标了 __unsafe_unretained
        for m in re.finditer(r"getReturnValue:&(\w+)", body):
            var = m.group(1)
            if not re.search(r"__unsafe_unretained\s+\w+\s+" + re.escape(var) + r"\b", body):
                bad(f"L6 {fn} getReturnValue:&{var} 未标 __unsafe_unretained")
if not any("L6" in x for x in F):
    ok("L6 getReturnValue 出参都标了 __unsafe_unretained")

# ── L7 objc_copyClassList 出参必须是 __unsafe_unretained Class *
for fn, body in FILES.items():
    if "objc_copyClassList" in body:
        if re.search(r"__unsafe_unretained\s+Class\s*\*\s*\w+\s*=\s*\(?\s*__unsafe_unretained\s+Class\s*\*\s*\)?\s*objc_copyClassList", body) \
           or re.search(r"__unsafe_unretained\s+Class\s*\*\s*\w+\s*=.*objc_copyClassList", body):
            ok("L7 objc_copyClassList 出参标了 __unsafe_unretained")
        else:
            bad("L7 objc_copyClassList 出参没标 __unsafe_unretained（ARC 会报错）")

# ── L8 不能用 CGContextSetStrokeColor/CGColorRef 直接空指针
for fn, body in FILES.items():
    if re.search(r"CGContextSet(Stroke|Fill)ColorWithColor\([^,]+,\s*NULL\s*\)", body):
        bad(f"L8 {fn} 有空指针颜色参数")

# ── L9 UIGraphicsImageRenderer 需要 iOS 10+，检查是否声明了版本下限
mk = read(os.path.join(ROOT, "Makefile"))
m = re.search(r"MINIOS\s*\?=\s*([\d.]+)", mk)
if m:
    ver = float(m.group(1))
    if ver >= 10.0:
        ok(f"L9 MINIOS={m.group(1)}（UIGraphicsImageRenderer 需 iOS 10+）")
    else:
        bad(f"L9 MINIOS={m.group(1)} 低于 UIGraphicsImageRenderer 要求的 10.0")
else:
    bad("L9 Makefile 没设 MINIOS")

# ── L10 检查用到的 iOS 13+ API 是否都有 @available 保护
#      ★ 判据改成「往前找最近的 @available(iOS 13/14)，且中间没有被右花括号闭合」。
#        单纯往前找 N 个字符不够稳 —— 块内插了新代码就会把距离撑开。
api_13 = ["UIAction", "connectedScenes", "showsMenuAsPrimaryAction", "enumerateEventHandlers"]
for fn, body in FILES.items():
    lines = body.splitlines()
    for i, ln in enumerate(lines):
        for a in api_13:
            if a not in ln:
                continue
            # 从当前行往上找 @available
            guarded = False
            for j in range(i, max(-1, i - 40), -1):
                if re.search(r"@available\(iOS\s+1[34]", lines[j]):
                    guarded = True
                    break
                # 遇到 if 块结束就停（说明保护不在同一块里）
                if j < i and lines[j].strip() == "}":
                    break
            if not guarded:
                bad(f"L10 {fn}:{i+1} 用了 {a} 但往上找不到 @available(iOS 13/14) 保护")
if not any("L10" in x for x in F):
    ok("L10 iOS 13+ API 都有 @available 保护")

# ── L11 mach 时间函数需要 <mach/mach_time.h>
#      mach-o/dyld.h 只给 dyld 那套，不含 mach_continuous_time。
for fn, body in FILES.items():
    if re.search(r"\bmach_(continuous|absolute)_time\b", body):
        if re.search(r'#import\s*<mach/mach_time\.h>', body):
            ok(f"L11 {fn} 用了 mach 时间函数并 import 了 mach_time.h")
        else:
            bad(f"L11 {fn} 用了 mach_continuous_time 但没 import <mach/mach_time.h>")

# ── L12 enumerateEventHandlers: 的 block 必须 5 个参数
#      真实签名：(UIAction *, id element, SEL, UIControlEvents, BOOL *stop)
#      写成 3 个参数在真机上 block 类型不匹配，编不过。
for fn, body in FILES.items():
    for m in re.finditer(r"enumerateEventHandlers:\s*\^\(([^)]*)\)", body):
        params = m.group(1)
        n = len([p for p in params.split(",") if p.strip()])
        if n != 5:
            bad(f"L12 {fn} enumerateEventHandlers block 有 {n} 个参数，应为 5")
if not any("L12" in x for x in F):
    ok("L12 enumerateEventHandlers block 参数个数正确（5）")

print()
print("=" * 74)
print(f"  ✅ 通过 {len(P)}   ❌ 失败 {len(F)}")
print("=" * 74)
if F:
    for x in F:
        print("   ❌ " + x)
sys.exit(1 if F else 0)
