#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoreOffline 构建一致性检查
  ① Makefile 的 SRC 清单与实际文件一一对应（不能漏文件，也不能列不存在的）
  ② 每个 .m 的 #import 都能在工程内或系统框架里找到
  ③ install name 与 CI 产物名一致
  ④ CI 的静态检查步骤与 Makefile 的路径一致
  ⑤ 公开 API 都有声明（头文件 ↔ 实现）
"""
import os, re, sys

# ROOT 自动探测：取本脚本所在目录的上一级。
# 这样本地沙箱和 CI 上都能跑，不用改路径。
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MK   = open(os.path.join(ROOT, "Makefile"), encoding="utf-8").read()
YML  = open(os.path.join(ROOT, ".github/workflows/build.yml"), encoding="utf-8").read()

P, F = [], []
def ok(m): P.append(m)
def bad(m): F.append(m)

print("=" * 74)
print("K. 构建一致性")
print("=" * 74)

# ── K1 Makefile SRC 清单 vs 实际文件
m = re.search(r"^SRC\s*=\s*((?:.*\\\n)*.*)$", MK, re.M)
src_line = re.sub(r"\\\n", " ", m.group(1)) if m else ""
listed = set(re.findall(r"[\w/]+\.m", src_line))
actual = set()
for d in ["src", "sdk"]:
    dp = os.path.join(ROOT, d)
    if os.path.isdir(dp):
        for f in os.listdir(dp):
            if f.endswith(".m"):
                actual.add(f"{d}/{f}")

missing = actual - listed          # 文件在，但没编进去 —— 会链接失败
extra   = listed - actual          # 列了但文件不存在 —— make 会报错
if not missing and not extra:
    ok(f"K1 Makefile SRC 与实际文件完全一致（{len(actual)} 个 .m）")
else:
    if missing: bad(f"K1 有 .m 未加入 SRC：{sorted(missing)}（会导致符号缺失）")
    if extra:   bad(f"K1 SRC 列了不存在的文件：{sorted(extra)}（make 会失败）")

# ── K2 每个自有 .m 的 #import "XXX.h" 都能找到
for rel in sorted(actual):
    p = os.path.join(ROOT, rel)
    t = open(p, encoding="utf-8").read()
    for h in re.findall(r'#import\s+"([^"]+)"', t):
        found = False
        for cand in [os.path.join(os.path.dirname(p), h),
                     os.path.join(ROOT, "include", os.path.basename(h)),
                     os.path.join(ROOT, "sdk", os.path.basename(h)),
                     os.path.join(ROOT, "src", os.path.basename(h))]:
            if os.path.exists(cand):
                found = True
                break
        if not found:
            bad(f"K2 {rel} 引用的 {h} 找不到")
if not any("K2" in x for x in F):
    ok("K2 所有本地 #import 均可解析")

# ── K3 install name 一致性
#      ★ Makefile 里 install name 写成 @executable_path/$(OUT)，
#        要先展开 OUT 变量再比对。
out_var = re.search(r"^OUT\s*=\s*([\w.]+)", MK, re.M)
out_val = out_var.group(1) if out_var else None

i_mk  = re.search(r"install_name,@executable_path/([\w.$()]+)", MK)
mk_name = i_mk.group(1) if i_mk else None
if mk_name and "$(OUT)" in mk_name:
    mk_name = out_val

i_yml = re.search(r"path:\s*([\w.]+\.dylib)", YML)
ci_name = i_yml.group(1) if i_yml else None

if mk_name and ci_name and mk_name == ci_name:
    ok(f"K3 install name 与 CI 产物名一致（{mk_name}）")
else:
    bad(f"K3 install name 不一致：Makefile={mk_name} CI={ci_name}")

# ── K4 CI 静态检查清单必须覆盖 Makefile 的全部自有源
ci_check = re.search(r"sources ok|for f in ([\s\S]*?); do", YML)
if ci_check:
    ci_files = set(re.findall(r"(?:src|sdk)/[\w]+\.m", YML))
    own = {f for f in actual if f.startswith("src/")}
    uncovered = own - ci_files
    if not uncovered:
        ok("K4 CI 静态检查覆盖全部 src/ 源文件")
    else:
        bad(f"K4 CI 静态检查漏了：{sorted(uncovered)}")
else:
    bad("K4 找不到 CI 静态检查步骤")

# ── K5 头文件里的公开方法必须在实现里存在
def strip_comments(t):
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    return re.sub(r"//[^\n]*", "", t)

for hf, mf in [("COLicenseDialog.h", "COLicenseDialog.m"),
               ("COVerifyBridge.h", "COVerifyBridge.m")]:
    ht = strip_comments(open(os.path.join(ROOT, "include", hf), encoding="utf-8").read())
    mt = strip_comments(open(os.path.join(ROOT, "src", mf), encoding="utf-8").read())
    # 抓头文件里的实例/类方法首段名
    decls = set(re.findall(r"^\s*[-+]\s*\([^)]*\)\s*([A-Za-z_]\w*)", ht, re.M))
    miss = []
    for d in decls:
        if d in ("init", "new"):   # 来自 NSObject
            continue
        if not re.search(r"^\s*[-+]\s*\([^)]*\)\s*" + re.escape(d) + r"\b", mt, re.M):
            miss.append(d)
    if not miss:
        ok(f"K5 {hf} 的公开方法在 {mf} 中均有实现（{len(decls)} 个）")
    else:
        bad(f"K5 {hf} 声明了但 {mf} 未实现：{miss}")

# ── K6 配置头里的 inline 函数必须无副作用（不能有 static 可变状态在函数外被改）
cfgh = open(os.path.join(ROOT, "include", "COVerifyConfig.h"), encoding="utf-8").read()
# 每个 static inline 都要有 return（除非 void）
for mm in re.finditer(r"static inline (\w+)\s+(\w+)\(void\)\s*\{([^}]*)\}", cfgh):
    ret, name, body = mm.group(1), mm.group(2), mm.group(3)
    if ret != "void" and "return" not in body:
        bad(f"K6 {name} 声明返回 {ret} 但无 return")
if not any("K6" in x for x in F):
    ok("K6 配置头 inline 函数均有返回值")

# ── K7 导出符号必须标 visibility("default")（否则 dylib 外看不到）
co = open(os.path.join(ROOT, "src", "CoreOffline.m"), encoding="utf-8").read()
exports = re.findall(r"__attribute__\(\(visibility\(\"default\"\)\)\)\s*\n\s*\w[\w \*]*?(Core\w+)\(", co)
if len(exports) >= 5:
    ok(f"K7 导出符号有 visibility 标注（{len(exports)} 个：{', '.join(exports)}）")
else:
    bad(f"K7 导出符号 visibility 标注不全，只找到 {exports}")

# ── K8 工作流里不能有会失败的硬编码（比如 Xcode 版本）
xm = re.search(r"Xcode_(\d+\.\d+)\.app", YML)
if xm:
    ok(f"K8 CI 指定 Xcode {xm.group(1)}")

# ── K9 Makefile 必须有 clean
if re.search(r"^clean:", MK, re.M):
    ok("K9 Makefile 有 clean 目标")
else:
    bad("K9 Makefile 缺 clean")

# ── K10 链的框架必须覆盖源码用到的跨框架类
#      ★ 这条是补的教训：CABasicAnimation 属于 QuartzCore，
#        Makefile 里没链它，编译全过、链接才炸（Undefined symbols）。
#        类名 → 必需框架的映射，写在这里做兜底。
FRAMEWORK_OF = {
    "CABasicAnimation":   "QuartzCore",
    "CAAnimation":        "QuartzCore",
    "CALayer":            "QuartzCore",
    "CATransaction":      "QuartzCore",
    "CGContext":          "CoreGraphics",
    "UIGraphicsImageRenderer": "UIKit",
    "CC_MD5":             "Security",      # CommonCrypto 随 Security 一起进来
    "CC_SHA256":          "Security",
    "SecKey":             "Security",
    "SecItem":            "Security",
}
all_src = ""
for d in ["src", "sdk"]:
    dp = os.path.join(ROOT, d)
    if os.path.isdir(dp):
        for f in os.listdir(dp):
            if f.endswith(".m"):
                all_src += open(os.path.join(dp, f), encoding="utf-8").read()

missing_fw = []
for cls, fw in FRAMEWORK_OF.items():
    if re.search(r"\b" + cls + r"\b", all_src):
        if f"-framework {fw}" not in MK:
            missing_fw.append(f"{cls} → 需要 {fw}")
if not missing_fw:
    ok("K10 Makefile 链的框架覆盖全部跨框架类引用")
else:
    bad("K10 Makefile 漏链框架（会链接失败）：" + "; ".join(missing_fw))

# ── K11 arm64e 必须用 -target，光靠 -arch 会静默降级成 arm64
#
# 这是真机上踩过的坑：Makefile 写 `-arch arm64e`，编译不报任何错，
# 但产物的 cpusubtype 是 0x0（普通 arm64）而不是 0x80000002（arm64e）。
# 原因：-arch 在多架构/fat 场景下由 driver 决定最终 target，
#       单编 dylib 时会退回默认 target（arm64）。
# 正确做法是 -target arm64e-apple-ios<ver>。
#
# ★ 只看「含 -target 的变量定义行」和「真正调 $(CC) 的行」，
#   不能扫全文 —— 注释里也会提到 -target，会造成假阳性。
build_lines = []
for line in MK.splitlines():
    s = line.strip()
    if s.startswith("#"):
        continue
    if re.match(r"^(COMMON|CFLAGS|SLICES)\s*[:?+]?=", s) or "$(CC)" in s:
        build_lines.append(line)
build_text = "\n".join(build_lines)

if "arm64e" in MK:
    if "-target" in build_text and "-apple-ios" in build_text:
        ok("K11 编译命令行用 -target 三元组（arm64e 不会被降级）")
    else:
        bad("K11 编译命令行没有 -target 三元组 —— cpusubtype 会静默变成 0x0")
else:
    warn("K11 Makefile 里没有 arm64e（如果目标就是 arm64 可忽略）")

# ── K12 多架构必须走 lipo（-target 一次只能一个架构）
if re.search(r"ARCHS\s*\?=\s*\S+\s+\S+", MK) or "ARCHS=\"arm64 arm64e\"" in MK:
    if "lipo" in MK:
        ok("K12 多架构走 lipo 合成")
    else:
        bad("K12 提到多架构但没有 lipo —— -target 不能一次指定多个架构")

print()
print("=" * 74)
print(f"  ✅ 通过 {len(P)}   ❌ 失败 {len(F)}")
print("=" * 74)
if F:
    for x in F:
        print("   ❌ " + x)
sys.exit(1 if F else 0)
