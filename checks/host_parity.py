#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
host_parity.py —— CoreOffline v3 vs 宿主 Core 1.6 行为一致性检查

★ 这个脚本的目标：证明 CoreOffline.m 的接管逻辑**严格对齐宿主真实结构**。

每一条检查都对应一段反汇编 / Mach-O 证据（见 /workspace/卡密逆向/）。
检查不通过 = 接管点写错了 = 装上去不生效或闪退。

用法：
    python3 checks/host_parity.py
退出码 0 = 全部通过；非 0 = 有偏离。
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "CoreOffline.m")
MK = os.path.join(ROOT, "Makefile")

PASS, FAIL, WARN = [], [], []


def ok(m):
    PASS.append(m)


def bad(m):
    FAIL.append(m)


def warn(m):
    WARN.append(m)


def read(p):
    try:
        with open(p, encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return ""


src = read(SRC)
mk = read(MK)

# 去掉注释，只检查真实代码
code = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
code = re.sub(r"//[^\n]*", "", code)


# ═══════════════════════════════════════════════════════════════════
#  H 组：宿主结构对齐（本轮反汇编所得的硬事实）
# ═══════════════════════════════════════════════════════════════════

# H1 宿主包名
if "qingxiugai.qingxiugai.qinxiugai" in src:
    ok("H1 宿主包名守卫正确 (qingxiugai.qingxiugai.qinxiugai)")
else:
    bad("H1 缺少宿主包名守卫 —— dylib 会在别人的 app 里也生效")

# H2 ★ 必须导出宿主预留的五个符号
#     宿主有 5 个 dlsym 跳板，逐条对应：
#       0x100003400 CoreOfflineBootstrap
#       0x100003500 CoreOfflinePrepare
#       0x100003600 CoreOfflineFinalize
#       0x100003800 CoreRemoteOpen
#       0x100003900 CoreRemoteFault
HOST_SYMBOLS = {
    "CoreOfflineBootstrap": r"void\s+CoreOfflineBootstrap\s*\(\s*void\s*\)\s*\{",
    "CoreOfflinePrepare":   r"void\s+CoreOfflinePrepare\s*\(\s*void\s*\)\s*\{",
    "CoreOfflineFinalize":  r"void\s+CoreOfflineFinalize\s*\(\s*void\s*\)\s*\{",
    "CoreRemoteOpen":       r"void\s*\*\s*CoreRemoteOpen\s*\([^)]*\)\s*\{",
    "CoreRemoteFault":      r"uint64_t\s+CoreRemoteFault\s*\([^)]*\)\s*\{",
}
for sym, pat in HOST_SYMBOLS.items():
    m = re.search(pat, code)
    if m:
        seg = code[: m.start()]
        if re.search(r'visibility\("default"\)', seg[-200:]):
            ok("H2 导出 %s（visibility default）" % sym)
        else:
            warn("H2 %s 已定义但未见 visibility(default) —— 可能被隐藏" % sym)
    else:
        bad("H2 缺少 %s 的定义 —— 宿主的 dlsym 跳板会走「跳过」分支" % sym)

# H2b ★ CoreRemoteOpen 的 handle 参数是「宿主算好的内存地址」，绝不能解引用
#     调用点反汇编：
#       0x10003a7a8  ldr  x8, [x8, #0x4a8]   ; 全局指针
#       0x10003a7b4  ldr  w9, [x9]           ; 全局 int
#       0x10003a7b8  add  x0, x8, x9         ; x0 = 基址 + 偏移
#     那块内存属于宿主、可能尚未初始化 —— 解引用就是踩空指针。
_ro = re.search(r"void\s*\*\s*CoreRemoteOpen\s*\(([^)]*)\)\s*\{(.*?)\n\}", code, re.S)
if _ro:
    _params, _body = _ro.group(1), _ro.group(2)
    _hdls = re.findall(r"\b(\w+)\b", _params.split(",")[0]) if _params.strip() else []
    _h = _hdls[-1] if _hdls else None
    if _h:
        # 解引用形态：*h 、h[...] 、h-> 、strlen(h)/strcmp(h,...) 等
        _deref = re.search(r"\*\s*%s\b|%s\s*\[|%s\s*->|strlen\s*\(\s*%s|strcmp\s*\([^)]*\b%s\b"
                           % (_h, _h, _h, _h, _h), _body)
        if _deref:
            bad("H2b CoreRemoteOpen 解引用了 handle(%s) —— 那是宿主的内存，可能未初始化" % _h)
        else:
            ok("H2b CoreRemoteOpen 不解引用 handle(%s)，只当数值用" % _h)
    if re.search(r"return\s+NULL\s*;", _body):
        ok("H2c CoreRemoteOpen 返回 NULL（宿主会当句柄用，非 NULL 会跳错约定）")
    else:
        bad("H2c CoreRemoteOpen 未返回 NULL —— 宿主会把它当有效句柄使用")

# H2d ★ 5 个注入点都必须有 @try 兜底（它们在宿主主流程上）
_impl = re.search(r"//  ★★★ 宿主预留的 5 个注入接口", code)
if _impl is None:
    # 注释被剥掉了，改判：5 个函数体里是否有 @try
    _fns = ["CoreOfflineBootstrap", "CoreOfflinePrepare", "CoreOfflineFinalize", "CoreRemoteFault"]
    _miss = []
    for _f in _fns:
        _m = re.search(r"\b%s\s*\([^)]*\)\s*\{(.*?)\n\}" % _f, code, re.S)
        if _m and "@try" not in _m.group(1):
            _miss.append(_f)
    if _miss:
        warn("H2d 这些注入点没有 @try 兜底: %s" % ", ".join(_miss))
    else:
        ok("H2d 4 个有函数体的注入点全部有 @try 兜底")

# H3 ★ 主接管点必须是 QXA117 finish:authorized:message:expiresAt:
if "finish:authorized:message:expiresAt:" in code:
    ok("H3 主接管点 = QXA117 finish:authorized:message:expiresAt: （收敛点）")
else:
    bad("H3 未 hook QXA117 finish: —— 卡密结论不会改变")

# H4 四个类名必须与宿主一致
for cls in ("QXA117", "QXA140", "QXA141", "QxF4"):
    if '"%s"' % cls in code or "'%s'" % cls in code or cls in code:
        ok("H4 目标类 %s 存在" % cls)
    else:
        bad("H4 缺少目标类 %s" % cls)

# H5 QXA140 的方法名必须完整
if "performPurpose:rootDeviceId:payload:completion:" in code:
    ok("H5 QXA140.performPurpose:rootDeviceId:payload:completion: 拼写正确")
else:
    bad("H5 QXA140 方法名拼错 —— swizzle 会静默失败")

# H6 QXA141 的方法名
if "inputCard:transfer:" in code:
    ok("H6 QXA141.inputCard:transfer: 拼写正确")
else:
    bad("H6 QXA141 方法名拼错")

# H7 QxF4 的方法名
if "qxRefreshExpiry" in code:
    ok("H7 QxF4.qxRefreshExpiry 拼写正确")
else:
    warn("H7 未找到 QxF4.qxRefreshExpiry")


# ═══════════════════════════════════════════════════════════════════
#  S 组：安全性（前几版闪退的三个根因）
# ═══════════════════════════════════════════════════════════════════

# S1 ★ 绝不自己调用 completion block
#    允许：把 completion 原样透传 / 存指针
#    禁止：把 completion 强转成 block 再 blk(...)
danger_block = re.findall(
    r"\(\s*void\s*\(\s*\^\s*\)[^)]*\)\s*(completion|block|blk)", code
)
direct_invoke = re.findall(r"\bblk\s*\(", code)
cast_invoke = re.findall(
    r"\^\s*\([^)]*\)\s*(?:completion|block)", code
)
if danger_block or direct_invoke or cast_invoke:
    bad(
        "S1 ★ 检测到「自己调用 completion block」的写法 —— "
        "这正是上一版闪退的原因（签名靠猜）。必须删掉。"
    )
else:
    ok("S1 ★ 未自己调用任何 completion block（零 ABI 风险）")

# S2 无全局类遍历
if "objc_copyClassList" in code or "objc_getClassList" in code:
    bad("S2 ★ 使用了全局类遍历 —— dyld 阶段可能崩")
else:
    ok("S2 零全局类遍历（只按名字取确定的类）")

# S3 无 Keychain / Security
for api in ("SecItemAdd", "SecItemCopyMatching", "SecItemDelete", "SecKeyCreateSignature"):
    if api in code:
        bad("S3 ★ 使用了 %s —— 自签下会返回 -34018 并崩" % api)
        break
else:
    ok("S3 零 Keychain / Security API")

# S4 无 NSURLSession 拦截
if "NSURLSession" in code or "NSURLProtocol" in code:
    bad("S4 ★ 拦截了 NSURLSession —— 会拦到宿主自己的卡密请求，导致状态机卡死")
else:
    ok("S4 未 hook 任何网络类")

# S5 无 method_exchangeImplementations（用 setImplementation 更干净）
if "method_exchangeImplementations" in code:
    warn("S5 使用了 method_exchangeImplementations（建议改 method_setImplementation）")
else:
    ok("S5 使用 method_setImplementation，语义更干净")

# S6 所有 hook 体有 @try/@catch
hook_funcs = re.findall(r"static\s+void\s+(co_\w+)\s*\([^)]*\)\s*\{", code)
if hook_funcs:
    missing = []
    for fn in hook_funcs:
        m = re.search(
            r"static\s+void\s+" + fn + r"\s*\([^)]*\)\s*\{(.*?)\n\}", code, re.S
        )
        if m and "@try" not in m.group(1):
            missing.append(fn)
    if missing:
        bad("S6 以下 hook 体没有 @try 兜底: %s" % ", ".join(missing))
    else:
        ok("S6 全部 %d 个 hook 体都有 @try 兜底" % len(hook_funcs))
else:
    warn("S6 未识别到 hook 体")

# S7 安装幂等
if re.search(r"static\s+int\s+done\s*=\s*0", code) and "if (done)" in code:
    ok("S7 安装幂等（重复调用无副作用）")
else:
    warn("S7 安装函数似乎不幂等 —— Bootstrap/Prepare 可能重复安装")


# ═══════════════════════════════════════════════════════════════════
#  B 组：构建配置
# ═══════════════════════════════════════════════════════════════════

# B1 install name（★ 必须与 Makefile 的 OUT 一致）
#    产物名带版本号：CoreOffline.v3.dylib
if "@executable_path/CoreOffline.v3.dylib" in mk:
    ok("B1 install name = @executable_path/CoreOffline.v3.dylib")
else:
    bad("B1 install name 不对 —— insert_dylib 插进去后 dyld 找不到")
    for ln in mk.splitlines():
        if ln.strip().startswith("OUT"):
            print("     实际 OUT 行: %s" % ln.strip())

# B1b 版本号一致性：文件头注释里的产物名要和 OUT 对得上
_out_m = re.search(r"^\s*OUT\s*=\s*(\S+)", mk, re.M)
_hdr_m = re.search(r"产物：\s*(\S+\.dylib)", mk)
if _out_m and _hdr_m:
    if _out_m.group(1) == _hdr_m.group(1):
        ok("B1b 头注释产物名与 OUT 一致（%s）" % _out_m.group(1))
    else:
        warn("B1b 头注释写 %s，OUT 却是 %s" % (_hdr_m.group(1), _out_m.group(1)))

# B2 只链 Foundation + UIKit（只看生效的 FRAMEWORKS 行，忽略注释）
fline = ""
for ln in mk.splitlines():
    if ln.strip().startswith("FRAMEWORKS"):
        fline = ln
        break
if "QuartzCore" in fline:
    warn("B2 Makefile 仍链 QuartzCore（v3 源码不需要）")
elif "Foundation" in fline and "UIKit" in fline:
    ok("B2 只链 Foundation + UIKit")
else:
    warn("B2 FRAMEWORKS 配置异常: %s" % fline.strip())

# B3 默认双切片
if re.search(r"ARCHS\s*\?=\s*arm64\s+arm64e", mk):
    ok("B3 默认编双切片 arm64 + arm64e")
else:
    warn("B3 默认架构不是双切片 —— 部分设备可能因架构被拒")

# B4 -fobjc-arc
if "-fobjc-arc" in mk:
    ok("B4 启用 ARC")
else:
    warn("B4 未启用 ARC")


# ═══════════════════════════════════════════════════════════════════
#  汇总
# ═══════════════════════════════════════════════════════════════════

print("=" * 68)
print(" CoreOffline v3 —— 宿主对齐 & 安全性检查")
print("=" * 68)
print()
for m in PASS:
    print("  \033[32m✓\033[0m " + m)
if WARN:
    print()
    for m in WARN:
        print("  \033[33m!\033[0m " + m)
if FAIL:
    print()
    for m in FAIL:
        print("  \033[31m✗\033[0m " + m)
print()
print("-" * 68)
print("  通过 %d   警告 %d   失败 %d" % (len(PASS), len(WARN), len(FAIL)))
print("-" * 68)

sys.exit(1 if FAIL else 0)
