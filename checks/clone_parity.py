#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clone_parity.py —— 复刻版 vs 测试版 行为一致性检查

★ 这个脚本的唯一目标：证明 CoreOfflineClone.m **没有偏离测试版**。

每一条检查（V1..V12）都对应一段反汇编证据。检查不通过 =
复刻版和测试版行为不一致 = 用户又会闪退。

用法：
    python3 checks/clone_parity.py
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
        with open(p, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def code_only(text):
    """剥掉注释和字符串，只留代码骨架 —— 避免注释里的词误命中。"""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def strip_comments(text):
    """★ 只去注释，**保留字符串字面量内容**。

    关键点：不能简单地 re.sub(r"//[^\\n]*") —— 那样会把
    @"https://t.me/cheatrev" 里的 "//" 当成注释起点，URL 就被吃掉了。
    所以要逐行扫描，跳过字符串内部。
    """
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    out = []
    for line in text.split("\n"):
        in_str = False
        esc = False
        cut = None
        for i, ch in enumerate(line):
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if not in_str and ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
                cut = i
                break
        out.append(line if cut is None else line[:cut])
    return "\n".join(out)


def code_and_strings(text):
    """保留字符串字面量内容（用于检查标题表之类），但去掉注释。"""
    return strip_comments(text)


RAW = read(SRC)
CODE = code_only(RAW)
WITHSTR = code_and_strings(RAW)
MAKE = read(MK)

if not RAW:
    print("!! 找不到源文件 %s" % SRC)
    sys.exit(2)


# ────────────────────────────────────────────────────────────
# V1  协议白名单恰好是 {http, https, ws, wss, ftp}
#
#     证据：反汇编 0x5668 `eor w20, w0, #1`（取反）
#           + CFString[5..9] = http/https/ws/wss/ftp
#     这是测试版判定的**第一层**，我上一轮整个漏掉了。
# ────────────────────────────────────────────────────────────
def v1():
    m = re.search(r"CoreAllowedSchemes\s*\(void\)\s*\{(.*?)\n\}", WITHSTR, re.S)
    if not m:
        bad("V1 找不到 CoreAllowedSchemes() 实现")
        return
    body = m.group(1)
    arr = re.search(r"@\[(.*?)\]", body, re.S)
    if not arr:
        bad("V1 CoreAllowedSchemes 里没有找到 @[...] 数组")
        return
    items = re.findall(r'@"([^"]*)"', arr.group(1))
    want = ["http", "https", "ws", "wss", "ftp"]
    if items == want:
        ok("V1 协议白名单 = {http, https, ws, wss, ftp}  ✔ 与 CFString[5..9] 一致")
    else:
        bad("V1 协议白名单错：得到 %s，期望 %s" % (items, want))

    # 取反语义：非白名单 → 不是环境资源 → 拦
    if re.search(r"if\s*\(\s*!\s*\[?\s*CoreAllowedSchemes", CODE) or \
       re.search(r"!\[CoreAllowedSchemes\(\)\s*containsObject", CODE):
        ok("V1b 判定顺序：先查协议白名单再取反  ✔ 对应 0x5668 eor w20,w0,#1")
    else:
        bad("V1b 没有找到「协议不在白名单 → 拦」的取反分支")


# ────────────────────────────────────────────────────────────
# V2  按钮标题恰好是那 5 个中文词
#
#     证据：__ustring (0x7fca) 的 UTF-16 字节
#           e567 0b77  6c51 4a54  d063 a44e  e55d 5553  db8f a65e
#           = 查看公告 / 提交工单 / 工单进度 / 激活续时 / 检查更新
# ────────────────────────────────────────────────────────────
def v2():
    m = re.search(r"CoreHomeTitles\s*\(void\)\s*\{(.*?)\n\}", WITHSTR, re.S)
    if not m:
        bad("V2 找不到 CoreHomeTitles() 实现")
        return
    arr = re.search(r"@\[(.*?)\]", m.group(1), re.S)
    if not arr:
        bad("V2 CoreHomeTitles 里没有 @[...] 数组")
        return
    items = re.findall(r'@"([^"]*)"', arr.group(1))
    want = ["查看公告", "提交工单", "工单进度", "激活续时", "检查更新"]
    if items == want:
        ok("V2 按钮标题 = %s  ✔ 与 __ustring UTF-16 解码一致" % "/".join(want))
    else:
        bad("V2 按钮标题错：得到 %s，期望 %s" % (items, want))

    # 必须没有我上轮凭空写的词。
    # ★ 注意：openCommunity: 是 __objc_selrefs[3] 的**真实选择子名**，必须保留；
    #   所以这里只在「字符面量 @\"...\"」里搜，而不是搜整个文件。
    ghost_words = ["社区", "交流群", "官方频道", "联系客服", "Community"]
    literals = re.findall(r'@"([^"]*)"', WITHSTR)
    hit = [w for w in ghost_words
           if any(w in lit and lit != "@selector(openCommunity:)" for lit in literals)]
    if hit:
        bad("V2b 出现了测试版里不存在的幽灵**标题字面量**：%s" % hit)
    else:
        ok("V2b 没有任何幽灵标题字面量（Community/社区/交流群/官方频道）  ✔")


# ────────────────────────────────────────────────────────────
# V3  按钮处理有 15 上限
#
#     证据：反汇编 0x54e8 `cmp w24, #0xf; b.hi`
#           （0x5480 是 ldaddal 原子自增，超 15 直接跳过整个处理）
# ────────────────────────────────────────────────────────────
def v3():
    m = re.search(r"kCoreHomeRewireLimit\s*=\s*(\d+)", CODE)
    if not m:
        bad("V3 找不到 kCoreHomeRewireLimit 常量")
    elif m.group(1) == "15":
        ok("V3 按钮处理上限 = 15  ✔ 对应 0x54e8 cmp w24,#0xf")
    else:
        bad("V3 上限是 %s，应为 15" % m.group(1))

    if re.search(r"rewired\s*>=\s*kCoreHomeRewireLimit", CODE):
        ok("V3b 上限有实际生效的守卫  ✔")
    else:
        bad("V3b 定义了上限但没有任何地方用它做守卫")


# ────────────────────────────────────────────────────────────
# V4  命中黑名单时直接 return，**不调 cancel**
#
#     证据：反汇编 0x565c `cbz w20, #0x566c` → 命中走 0x5674 `retab`
#           中间没有任何 cancel 调用
#     这是测试版和「我上一轮版本」最大的行为差异之一。
# ────────────────────────────────────────────────────────────
def v4():
    m = re.search(r"static\s+void\s+CoreTaskResume\s*\(.*?\n\}", CODE, re.S)
    if not m:
        bad("V4 找不到 CoreTaskResume 实现")
        return
    body = m.group(0)

    if re.search(r"CoreBlockNetworkURL\s*\(\s*url\s*\)", body):
        ok("V4 CoreTaskResume 里调用了 CoreBlockNetworkURL  ✔")
    else:
        bad("V4 CoreTaskResume 没有调用 CoreBlockNetworkURL")

    # 命中分支里绝不能有 cancel
    hit = re.search(
        r"(else\s+)?if\s*\(\s*CoreBlockNetworkURL.*?\n(.*?)(?:\n\s*\})", body, re.S)
    if hit:
        seg = hit.group(2)
        if re.search(r"\[\s*task\s+cancel", seg) or re.search(r"cancelWithError", seg):
            bad("V4b 命中黑名单时调用了 cancel —— 测试版没有这一步！"
                "（0x5674 是直接 retab 返回）")
        else:
            ok("V4b 命中黑名单时直接 return，未调 cancel  ✔ 对应 0x5674 retab")
    else:
        warn("V4b 无法定位命中分支，需人工确认")

    # 全文件不应有真的要 cancel 的调用（cancelNetworkTasks 是空壳）
    if re.search(r"\[\s*\w+\s+cancel\s*\]", CODE) or "cancelWithError" in CODE:
        bad("V4c 源文件里仍存在 [task cancel] / cancelWithError 调用")
    else:
        ok("V4c 全文件没有任何实际的 cancel 调用  ✔")


# ────────────────────────────────────────────────────────────
# V5  cancelNetworkTasks 是空壳
#
#     证据：反汇编 0x5290 函数体只有一次 record 调用
# ────────────────────────────────────────────────────────────
def v5():
    m = re.search(r"static\s+void\s+cancelNetworkTasks\s*\(void\)\s*\{(.*?)\n\}", CODE, re.S)
    if not m:
        bad("V5 找不到 cancelNetworkTasks 实现")
        return
    body = m.group(1)
    stmts = [s.strip() for s in body.split(";") if s.strip()]
    if len(stmts) == 1 and "record(" in stmts[0]:
        ok("V5 cancelNetworkTasks 是空壳（函数体只有 1 条 record）  ✔ 对应 0x5290")
    else:
        bad("V5 cancelNetworkTasks 有 %d 条语句，应为 1 条 record：%s"
            % (len(stmts), stmts[:4]))


# ────────────────────────────────────────────────────────────
# V6  遮罩 hook：类族向上遍历 + 跳过 UIImage + 透传
#
#     证据：
#       0x4d54 objc_copyClassList
#       0x4dac 跳过 UIImage 类自己（cset/ccmp）
#       0x4dbc class_getSuperclass（★ 向上遍历类族）
#       0x4e38 取 objc_msgSend 弱引用 → 透传，不是吞掉
# ────────────────────────────────────────────────────────────
def v6():
    m = re.search(r"static\s+void\s+CoreInstallMaskHooks\s*\(void\)\s*\{(.*?)\n\}", CODE, re.S)
    if not m:
        bad("V6 找不到 CoreInstallMaskHooks 实现")
        return
    body = m.group(1)

    if "objc_copyClassList" in body:
        ok("V6a 用 objc_copyClassList 拿全部类  ✔ 对应 0x4d54")
    else:
        bad("V6a 没有调用 objc_copyClassList")

    if re.search(r"if\s*\(\s*cls\s*==\s*uiImageClass\s*\)\s*continue", body):
        ok("V6b 跳过 UIImage 类自己  ✔ 对应 0x4dac")
    else:
        bad("V6b 没有跳过 UIImage 类（测试版 0x4dac 明确跳过了）")

    if "class_getSuperclass" in body:
        ok("V6c 有 class_getSuperclass 向上遍历类族  ✔ 对应 0x4dbc")
    else:
        bad("V6c 没有向上遍历类族（测试版 0x4dbc 会一路走到 NSObject）")

    # 透传：maskHook 必须调 maskOriginal
    mm = re.search(r"static\s+void\s+maskHook\s*\(.*?\n\}", CODE, re.S)
    if mm and re.search(r"maskOriginal\s*\(", mm.group(0)):
        ok("V6d maskHook 透传原实现（不是吞掉）  ✔ 对应 0x4e38 objc_msgSend")
    else:
        bad("V6d maskHook 没有透传原实现 —— 测试版是透传的")


# ────────────────────────────────────────────────────────────
# V7  完全不含卡密相关符号
#
#     证据：测试版 __bss = 0x5d8，没有任何授权全局；
#           98 个导入里没有 T3/VerifiedExport/键值/加密符号
# ────────────────────────────────────────────────────────────
def v7():
    ban = [
        "T3Verify", "COVerifyBridge", "COLicenseDialog", "COEntry",
        "COKeychain", "CORecord", "COGrantLicense", "CoreGrantLicense",
        "COVerifyIsUnauthorized", "COVerifyPerpetualExpiry",
        "verifiedExport", "authorizeWithCard", "CoreArmFailOpenWatchdog",
        "CoreFailOpen", "license.subsystem", "看门狗", "卡密",
    ]
    hit = [b for b in ban if b in WITHSTR]
    if hit:
        bad("V7 复刻版里残留卡密相关符号：%s" % hit)
    else:
        ok("V7 完全不含卡密符号（T3/桥接/弹窗/Keychain/看门狗）  ✔")


# ────────────────────────────────────────────────────────────
# V8  构造函数全同步：没有 dispatch_async 延迟启动
#
#     证据：反汇编 0x4b3c 一条直路走到底，无 dispatch_async
#     ★ 但 UI 改写内部的 dispatch_async 是允许的（要回主线程），
#       测试版在 attachToRootView hook 里也是主线程异步。
# ────────────────────────────────────────────────────────────
def v8():
    m = re.search(r"initializeOffline\s*\(void\)\s*\{(.*?)\n\}", CODE, re.S)
    if not m:
        bad("V8 找不到 initializeOffline 构造函数")
        return
    body = m.group(1)

    if "dispatch_async" in body:
        bad("V8 构造函数里有 dispatch_async —— 测试版是全同步的（0x4b3c）")
    else:
        ok("V8 构造函数全同步，无 dispatch_async  ✔ 对应 0x4b3c")

    # 包名守卫
    if "kHostBundleID" in body and "bundleIdentifier" in body:
        ok("V8b 有包名守卫（不是目标宿主就静默退出）  ✔ 对应 0x4b7c")
    else:
        bad("V8b 没有包名守卫")

    # 四段流程齐全
    order = ["CoreHomeUIInstall", "monitorBackend", "CoreOfflinePrepare", "CoreOfflineBootstrap"]
    pos = [body.find(x) for x in order]
    if all(p >= 0 for p in pos) and pos == sorted(pos):
        ok("V8c 四段流程顺序正确：UIInstall → monitorBackend → Prepare → Bootstrap  ✔")
    else:
        bad("V8c 构造流程缺失或顺序不对：%s" % dict(zip(order, pos)))


# ────────────────────────────────────────────────────────────
# V9  依赖只有 Foundation / UIKit / QuartzCore
#
#     证据：测试版的 LC_LOAD_DYLIB 就这 3 个 framework
#           （+ libobjc / libSystem / CoreFoundation，系统自动带）
#     ★ 绝不能出现 Security（Keychain / 卡密会引进来）
# ────────────────────────────────────────────────────────────
def v9():
    m = re.search(r"FRAMEWORKS\s*=\s*(.*)", MAKE)
    if not m:
        bad("V9 Makefile 里找不到 FRAMEWORKS")
        return
    fw = re.findall(r"-framework\s+(\w+)", m.group(1))
    want = ["Foundation", "UIKit", "QuartzCore"]
    if fw == want:
        ok("V9 依赖 framework = %s  ✔ 与测试版 LC_LOAD_DYLIB 一致" % fw)
    else:
        bad("V9 依赖 framework = %s，应为 %s" % (fw, want))

    for forbidden in ["Security", "CoreGraphics", "CFNetwork", "CoreTelephony"]:
        if forbidden in fw:
            bad("V9b 链了测试版没有的 %s" % forbidden)

    if re.search(r"ARCHS\s*\?=\s*arm64e", MAKE):
        ok("V9c 构建架构含 arm64e  ✔")
    else:
        bad("V9c Makefile 的 ARCHS 不是 arm64e")

    if "CoreOffline.work.dylib" in MAKE:
        ok("V9d 输出文件名是 CoreOffline.work.dylib  ✔")
    else:
        bad("V9d 输出文件名不是 CoreOffline.work.dylib")


# ────────────────────────────────────────────────────────────
# V10  导出符号与测试版一致
#
#     证据：测试版符号表里这 5 个是外部可见的 C 函数
# ────────────────────────────────────────────────────────────
def v10():
    want = ["CoreOfflineBootstrap", "CoreOfflinePrepare", "CoreOfflineFinalize",
            "CoreRemoteOpen", "CoreRemoteFault"]
    miss = [w for w in want if w not in CODE]
    if miss:
        bad("V10 缺少导出函数：%s" % miss)
    else:
        ok("V10 5 个导出 API 齐全（Bootstrap/Prepare/Finalize/RemoteOpen/RemoteFault）  ✔")

    for w in want:
        m = re.search(r"%s\s*\([^)]*\)\s*\{" % w, CODE)
        if m:
            seg = CODE[m.start():m.start() + 400]
            if 'visibility("default")' in CODE[max(0, m.start() - 200):m.start()]:
                continue
    vis = CODE.count('visibility("default")')
    if vis >= 5:
        ok("V10b 导出符号都带 visibility(\"default\")（共 %d 处）  ✔" % vis)
    else:
        bad("V10b 只有 %d 处 visibility(\"default\")，应为 ≥5" % vis)


# ────────────────────────────────────────────────────────────
# V11  monitorBackend 参数与测试版一致（2.0s / 1.0s / 0.1s / 8 次）
#
#     证据：反汇编 0x4f6c dispatch_source_set_timer(now+2.0s, 1.0s, 0.1s)
#           事件处理里 ticks >= 8 触发 cancellation
# ────────────────────────────────────────────────────────────
def v11():
    m = re.search(r"static\s+void\s+monitorBackend\s*\(void\)\s*\{(.*?)\n\}", CODE, re.S)
    if not m:
        bad("V11 找不到 monitorBackend")
        return
    body = m.group(1)
    checks = [
        (r"2\.0\s*\*\s*NSEC_PER_SEC", "起始延迟 2.0s"),
        (r"1\.0\s*\*\s*NSEC_PER_SEC", "间隔 1.0s"),
        (r"0\.1\s*\*\s*NSEC_PER_SEC", "leeway 0.1s"),
    ]
    miss = [name for pat, name in checks if not re.search(pat, body)]
    if miss:
        bad("V11 定时器参数缺失：%s" % miss)
    else:
        ok("V11 定时器参数 = 2.0s 起 / 1.0s 间隔 / 0.1s leeway  ✔ 对应 0x4f6c")

    if re.search(r"ticks\s*>=\s*8", body):
        ok("V11b ticks>=8 触发 cancellation  ✔")
    else:
        bad("V11b 没有 ticks>=8 的触发条件")


# ────────────────────────────────────────────────────────────
# V12  硬编码授权 2099
#
#     证据：反汇编 0x59c0 authorizationValue 直接返回 CFString[1]
#           = "2099-12-31 23:59:59"
# ────────────────────────────────────────────────────────────
def v12():
    if '"2099-12-31 23:59:59"' in WITHSTR:
        ok('V12 硬编码授权 "2099-12-31 23:59:59" 存在  ✔ 对应 CFString[1]')
    else:
        bad('V12 找不到硬编码授权 "2099-12-31 23:59:59"')

    m = re.search(r"CoreHomeExpiryValue\s*\(.*?\n\}", CODE, re.S)
    if m:
        if "return kPerpetualExpiry" in m.group(0):
            ok("V12b authorizationValue 直接返回常量，无分支判断  ✔ 对应 0x59c0")
        else:
            bad("V12b authorizationValue 里出现了判断逻辑（测试版是直接返回）")
    else:
        bad("V12b 找不到 CoreHomeExpiryValue")

    # 5 个 hook 方法的选择子名必须在
    for s in ["attachToRootView:", "refreshHomeLayoutArtwork",
              "authorizationValue", "setDisableUpdateMask:"]:
        if '"%s"' % s not in WITHSTR:
            bad("V12c 缺少选择子字符串 %s" % s)
    else:
        ok("V12c 4 个宿主选择子字符串齐全  ✔ 对应 CFString[18..21]")

    if '"OKDHomeMusicController"' in WITHSTR:
        ok("V12d 宿主类名 OKDHomeMusicController 存在  ✔ 对应 CFString[18]")
    else:
        bad("V12d 缺少宿主类名 OKDHomeMusicController")


# ────────────────────────────────────────────────────────────
# V13  附：不链接 libc++（测试版链了，但那是 C++ 静态局部的副作用）
# ────────────────────────────────────────────────────────────
def v13():
    # ★ 只看代码（剥注释），否则 Makefile 里那句
    #   "测试版另外还链了 libc++" 的说明文字会误报。
    mk_code = re.sub(r"#[^\n]*", " ", MAKE)
    if re.search(r"libc\+\+", mk_code) or re.search(r"-lc\+\+", mk_code):
        bad("V13 Makefile 链了 libc++（复刻版用 C 静态变量，不需要）")
    else:
        ok("V13 不链 libc++（用 C 静态变量 + dispatch_once 等价实现）  ✔")


# ────────────────────────────────────────────────────────────
# V14  闪退防护（这些是测试版靠 __objc_stubs 天然规避、我们必须显式做的）
#
#     每一条都对应一类真机上真实会崩的场景。
# ────────────────────────────────────────────────────────────
def v14():
    # ① NSURLSessionTask 是懒加载类，dyld 阶段可能 nil
    m = re.search(r"static\s+void\s+CoreHomeUIInstall\s*\(void\)\s*\{(.*?)\n\}", CODE, re.S)
    if not m:
        bad("V14 找不到 CoreHomeUIInstall")
        return
    body = m.group(1)

    if re.search(r'taskClass\s*\?\s*class_getInstanceMethod', body) or \
       re.search(r"if\s*\(\s*!taskClass\s*\)", body):
        ok("V14a NSURLSessionTask 取类时判空（懒加载类）  ✔")
    else:
        bad("V14a 没有对 NSURLSessionTask 判空 —— dyld 阶段拿到 nil 会崩")

    # ② 原实现必须先取到才替换
    if re.search(r"if\s*\(\s*old\s*\)\s*\{[^}]*method_setImplementation", body, re.S):
        ok("V14b 只有原实现非空才做 method_setImplementation  ✔")
    else:
        bad("V14b 没有「原实现非空才替换」的守卫")

    # ③ resume hook 里原实现为空要走 objc_msgSend 转发，不能直接返回
    mm = re.search(r"static\s+void\s+CoreTaskResume\s*\(.*?\n\}", CODE, re.S)
    if mm and "objc_msgSend" in mm.group(0):
        ok("V14c resume hook 在原实现为空时走 objc_msgSend 转发  ✔")
    else:
        bad("V14c resume hook 原实现为空时没有兜底转发（会导致 task 永久停住）")

    # ④ CoreHomeBanner 递归守卫 + 不用 dispatch_once
    mb = re.search(r"static\s+UIImage\s*\*\s*CoreHomeBanner\s*\(.*?\n\}", CODE, re.S)
    if mb:
        bb = mb.group(0)
        if "_Thread_local" in bb and "inBanner" in bb:
            ok("V14d CoreHomeBanner 有 _Thread_local 递归守卫  ✔")
        else:
            bad("V14d CoreHomeBanner 没有递归守卫（hook 自触发会栈溢出）")
        if "dispatch_once" in bb:
            bad("V14d2 CoreHomeBanner 用了 dispatch_once —— 递归时会死锁")
        else:
            ok("V14d2 CoreHomeBanner 用 @synchronized 而非 dispatch_once  ✔")
        if "_NSGetExecutablePath" in bb:
            ok("V14d3 CoreHomeBanner 用 _NSGetExecutablePath 而非 mainBundle  ✔")
        else:
            bad("V14d3 CoreHomeBanner 还在依赖 mainBundle（dyld 阶段不可靠）")
    else:
        bad("V14d 找不到 CoreHomeBanner")

    # ⑤ 遮罩 hook 必须在最后（要遍历全部类）
    pos_mask = body.rfind("CoreInstallMaskHooks")
    pos_img = body.find("CoreHomeImageNamed")
    if pos_mask > pos_img > 0:
        ok("V14e CoreInstallMaskHooks 放在 hook 安装的最后一步  ✔")
    else:
        warn("V14e 无法确认 CoreInstallMaskHooks 的安装顺序")


# ────────────────────────────────────────────────────────────
# V15  常量字面量必须与测试版 __cstring 逐条对齐
#
#     依据：测试版 __cstring (va=0x7788, size=0x4b1) 的完整 dump。
#     每一条都核对过地址，见 README 第 2 节。
# ────────────────────────────────────────────────────────────
def v15():
    # ① 定位宿主镜像必须用 ".app/Core"（0x78ed），不是 ".app/"
    if '".app/Core"' in WITHSTR:
        ok('V15a 用 ".app/Core" 定位宿主镜像  ✔ 对应 __cstring 0x78ed')
    else:
        bad('V15a 没用 ".app/Core" —— 用 ".app/" 可能先命中 framework 路径，'
            'imageBase 会拿错')

    # ② 环境资源：jsdelivr 的 "/ios/" 段（0x7b2e）
    if '"/ios/"' in WITHSTR or "'/ios/'" in WITHSTR:
        ok('V15b 含独立 "/ios/" 段  ✔ 对应 __cstring 0x7b2e')
    else:
        bad('V15b 缺 "/ios/" —— 测试版 ___cstring 0x7b2e 有这个独立常量')

    # ③ 资源兜底名 hf.png（0x7c1a）
    if '"hf.png"' in WITHSTR:
        ok('V15c 含资源兜底名 "hf.png"  ✔ 对应 __cstring 0x7c1a')
    else:
        bad('V15c 缺 "hf.png" 兜底名')

    # ④ "hf" 前缀（0x7c17）
    if '"hf"' in WITHSTR or 'hasPrefix:@"hf"' in WITHSTR:
        ok('V15d 含资源前缀 "hf"  ✔ 对应 __cstring 0x7c17')
    else:
        bad('V15d 缺 "hf" 前缀判定')

    # ⑤ 日志格式串里必须有 %llu 家族（record 的核心）
    for fmt in ['derive=%llu', 'material=%llu', 'lease=%llu',
                'credential=%llu', 'bootstrap=%llu']:
        if fmt not in WITHSTR:
            bad('V15e 缺日志格式串 "%s"' % fmt)
            break
    else:
        ok('V15e 5 个凭据日志格式串齐全  ✔ 对应 __cstring 0x7788..0x77b2')

    # ⑥ 协议白名单的 5 个字面量（0x7b08..0x7b1a）
    for p in ['"http"', '"https"', '"ws"', '"wss"', '"ftp"']:
        if p not in WITHSTR:
            bad('V15f 缺协议字面量 %s' % p)
            break
    else:
        ok('V15f 协议字面量 http/https/ws/wss/ftp 齐全  ✔ 对应 0x7b08..0x7b1a')

    # ⑦ 主机黑名单 4 条（0x7b70..0x7b93）
    for h in ['"apple.com"', '".apple.com"', '"cdn-apple.com"', '".cdn-apple.com"']:
        if h not in WITHSTR:
            bad('V15g 缺主机黑名单 %s' % h)
            break
    else:
        ok('V15g 主机黑名单 4 条齐全  ✔ 对应 0x7b70..0x7b93')

    # ⑧ #selector(openCommunity:) 必须保留（__objc_selrefs[3]）
    if "openCommunity:" in WITHSTR:
        ok('V15h 保留选择子 openCommunity:  ✔ 对应 __objc_selrefs[3]')
    else:
        bad('V15h 缺 openCommunity: 选择子 —— 测试版 __objc_selrefs[3] 有它')

    # ⑨ 推广链接（0x789d / CFString[0]）
    if "https://t.me/cheatrev" in WITHSTR:
        ok('V15i 推广链接存在  ✔ 对应 __cstring 0x789d')
    else:
        bad('V15i 缺推广链接 https://t.me/cheatrev')

    # ⑩ 日志文件路径（0x78f7 / CFString[3]）
    if "Documents/core-offline-original-id.log" in WITHSTR:
        ok('V15j 日志路径存在  ✔ 对应 __cstring 0x78f7')
    else:
        bad('V15j 缺日志路径')


def main():
    for fn in [v1, v2, v3, v4, v5, v6, v7, v8, v9, v10,
               v11, v12, v13, v14, v15]:
        try:
            fn()
        except Exception as e:
            bad("%s 检查抛异常：%r" % (fn.__name__, e))

    print("=" * 74)
    print("  复刻版 vs 测试版  行为一致性检查")
    print("  源文件：%s" % os.path.relpath(SRC, ROOT))
    print("=" * 74)
    for m in PASS:
        print("  \033[32m✔\033[0m %s" % m)
    if WARN:
        print()
        for m in WARN:
            print("  \033[33m⚠\033[0m %s" % m)
    if FAIL:
        print()
        for m in FAIL:
            print("  \033[31m✘\033[0m %s" % m)
    print("-" * 74)
    print("  通过 %d    警告 %d    失败 %d" % (len(PASS), len(WARN), len(FAIL)))
    if not FAIL:
        print("  \033[32m★ 复刻版与测试版行为一致\033[0m")
    print("=" * 74)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
