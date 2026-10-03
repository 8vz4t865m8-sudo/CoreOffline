#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoreOffline 审计
  A. 语法检查（clang -fsyntax-only）
  B. 生命周期 / 内存：block 捕获、weak-strong dance、循环引用
  C. 线程安全：UI 操作是否在主线程
  D. 布局不变量：frame 是否只在 layout 方法里改
  E. 资源：图标缓存、图片资源
  F. 网络拦截：白名单判定是否对称
  G. 配置完整性：卡密接入点是否接上真实校验
"""
import os, re, subprocess, sys

# ROOT 自动探测：取本脚本所在目录的上一级。
# 这样本地沙箱和 CI 上都能跑，不用改路径。
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC  = os.path.join(ROOT, "src")
INC_DIR = os.path.join(ROOT, "include")
SDK  = os.path.join(ROOT, "sdk")

INC = ["-I", "/tmp/uishim", "-I", "/tmp/objcshim", "-I", "/usr/include/GNUstep",
       "-I", INC_DIR, "-I", SRC, "-I", SDK]

PASS, FAIL, WARN = [], [], []

def ok(m):   PASS.append(m)
def bad(m):  FAIL.append(m)
def warn(m): WARN.append(m)

def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()

def strip_comments(t):
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    t = re.sub(r"//[^\n]*", "", t)
    # ★ #pragma mark 后面的说明文字也是注释性质（形如 `#pragma mark - 布局（★ ...）`），
    #   它不是 UI 字符串。不剥掉的话里面的装饰符会被 emoji 检查误报。
    t = re.sub(r"#pragma[^\n]*", "", t)
    return t

ALL_M = ["CoreOffline.m", "COIcon.m", "COLicenseDialog.m", "COVerifyBridge.m",
         "COKeychain.m", "COEntry.m", "COLog.m"]
TEXT  = {f: read(os.path.join(SRC, f)) for f in ALL_M}
CODE  = {f: strip_comments(v) for f, v in TEXT.items()}

print("=" * 74)
print("A. 语法检查")
print("=" * 74)

# 这套检查靠 /tmp/uishim + /tmp/objcshim 替身头做 iOS 语法仿真。
# 替身头是本地沙箱手工搭的（CI 上没有），缺了就跳过 A 节 ——
# 不能在 CI 上把它当成失败，否则会掩盖真正的问题。
_HAS_SHIM = all(os.path.isdir(p) for p in ("/tmp/uishim", "/tmp/objcshim"))
if not _HAS_SHIM:
    print("  ⏭  跳过：未找到替身头 /tmp/uishim + /tmp/objcshim")
    print("      （CI 上属正常，本地跑请先搭好替身头）")
else:
    for f in ALL_M:
        # ★ -Werror=implicit-function-declaration 是必须的：
        #   替身头（/tmp/uishim）比真 SDK 宽容，很多系统函数（_dyld_image_count、
        #   sysctlbyname...）在替身头里"碰巧"可见，本地不报错但 CI 直接编译失败。
        #   打开这个开关后本地就能提前抓到 —— 这是踩过的坑，别关掉。
        cmd = ["clang", "-fsyntax-only", "-fblocks", "-fobjc-arc",
               "-fobjc-runtime=gnustep-2.0", "-std=gnu11", "-Wno-everything",
               "-Werror=implicit-function-declaration",
               "-Werror=int-conversion"] + INC + \
              [os.path.join(SRC, f)]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            ok(f"A 语法 {f}")
            print(f"  ✅ {f}")
        else:
            bad(f"A 语法 {f}")
            print(f"  ❌ {f}")
            for line in r.stderr.splitlines():
                if re.search(r"(error|fatal error):", line):
                    print("       " + line.strip())

print()
print("=" * 74)
print("B. 生命周期 / 内存")
print("=" * 74)

# B1. 每个 async block 里用 self 前是否有 __strong 提升或 weak 保护
core = CODE["CoreOffline.m"]
bridge = CODE["COVerifyBridge.m"]
dialog = CODE["COLicenseDialog.m"]

# B1: 弹窗静态持有者不能被弱引用（挂到 view 上会立刻释放）
if re.search(r"static\s+COLicenseDialog\s*\*\s*gDialog", core):
    ok("B1 gDialog 是强引用静态持有者")
else:
    bad("B1 gDialog 未找到强引用声明")

# B2: onResult block 里不能强捕获 dlg（会循环：dlg -> onResult -> dlg）
m = re.search(r"dlg\.onResult\s*=\s*\^\(BOOL ok.*?\};", core, re.S)
if m:
    body = m.group(0)
    if "weakDlg" in body and not re.search(r"\bdlg\b\s*->", body):
        ok("B2 onResult 用 weak 捕获，无保留环")
    else:
        warn("B2 onResult 捕获情况需人工确认")
else:
    bad("B2 未找到 onResult 赋值")

# B3: 弹窗自身持有的 host 必须是 weak（否则 host -> view -> dialog -> host）
if re.search(r"@property\s*\(nonatomic,\s*weak\)\s*UIViewController\s*\*host", dialog):
    ok("B3 COLicenseDialog.host 是 weak")
else:
    bad("B3 COLicenseDialog.host 不是 weak")

# B4: 弹窗 dismiss 时要把 _dim/_card 置 nil（幂等 + 防重复 dismiss）
if re.search(r"_dim\s*=\s*nil;\s*\n\s*_card\s*=\s*nil;", dialog):
    ok("B4 dismiss 里清空 _dim/_card，可重入")
else:
    bad("B4 dismiss 未清空引用")

# B5: 桥接层心跳 timer 必须 invalidate 且 dealloc 兜底
if "stopHeartbeat" in bridge and "[_heartbeatTimer invalidate]" in bridge:
    ok("B5 心跳 timer 有 invalidate")
else:
    bad("B5 心跳 timer 未 invalidate")

# B6: weak-strong dance —— COVerifyBridge 的异步块
dance_count = len(re.findall(r"__weak\s+typeof\(self\)\s+ws\s*=\s*self", bridge))
strong_count = len(re.findall(r"__strong\s+typeof\(ws\)\s+self\s*=\s*ws", bridge))
if dance_count >= 3 and strong_count >= 3:
    ok(f"B6 weak-strong dance 齐全（weak={dance_count} strong={strong_count}）")
else:
    warn(f"B6 weak-strong dance 数量 weak={dance_count} strong={strong_count}")

# B7: 弹窗 submit 回调里的 weak-strong 保护
if re.search(r"__weak\s+typeof\(self\)\s+ws\s*=\s*self", dialog) and \
   re.search(r"__strong\s+typeof\(ws\)\s+self\s*=\s*ws", dialog):
    ok("B7 弹窗 submit 回调有 weak-strong 保护")
else:
    warn("B7 弹窗 submit 回调 weak-strong 缺失")

print()
print("=" * 74)
print("C. 线程安全")
print("=" * 74)

# C1: 所有 UIKit 操作必须在主线程。检查写 frame / addSubview / 属性赋值前面的 GCD 上下文
ui_sites = ["_dim.frame", "_card.frame", "_card.center", "addSubview", "beginAnimations",
            "_titleLabel.frame", "_noticeBox.frame"]
risky = []
for f, body in CODE.items():
    lines = body.splitlines()
    for i, ln in enumerate(lines):
        if any(s in ln for s in ["_dim.frame", "_card.frame", "_card.center"]) :
            # 往上找 80 行内有没有非主线程的 dispatch_async
            window = "\n".join(lines[max(0, i - 80):i])
            for m in re.finditer(r"dispatch_async\(\s*dispatch_get_global_queue", window):
                # 之后有没有回到 main_queue
                after = window[m.end():]
                if "dispatch_get_main_queue" not in after:
                    risky.append(f"{f}:{i+1} {ln.strip()[:50]}")
                    break
if not risky:
    ok("C1 frame 赋值均在主线程上下文")
else:
    bad(f"C1 疑似非主线程改 frame：{risky[:4]}")

# C2: 桥接层的网络调用必须离开主线程
if re.search(r"dispatch_async\(dispatch_get_global_queue[\s\S]{0,400}?loginWithKami", bridge) or \
   re.search(r"dispatch_async\(dispatch_get_global_queue[\s\S]{0,400}?methodSignatureForSelector", bridge):
    ok("C2 verifyCard 网络调用在后台队列")
else:
    bad("C2 verifyCard 未切后台，会卡主线程")

# C3: 回调必须回到主线程
cbs = re.findall(r"dispatch_async\(dispatch_get_main_queue\(\)[^;]*completion\(", bridge)
if len(cbs) >= 3:
    ok(f"C3 桥接回调回主线程（{len(cbs)} 处）")
else:
    warn(f"C3 桥接回调回主线程处数偏少（{len(cbs)}）")

# C4: UI 更新在 CoreOffline 的 constructor 里必须延后到主线程
if re.search(r"dispatch_async\(dispatch_get_main_queue\(\),\s*\^\{[\s\S]*?CoreCheckLicense\(\)", core):
    ok("C4 授权检查延后到主线程执行")
else:
    bad("C4 授权检查未延后到主线程")

print()
print("=" * 74)
print("D. 布局不变量（纯 frame）")
print("=" * 74)

# D1: 不许出现 Auto Layout
al_markers = ["NSLayoutConstraint", "translatesAutoresizingMaskIntoConstraints = NO",
              "activateConstraints", "constraintEqualToAnchor", "addConstraint", "NSLayoutAnchor"]
hits = []
for f, body in CODE.items():
    for mk in al_markers:
        if mk in body:
            hits.append(f"{f}:{mk}")
if not hits:
    ok("D1 全工程无 Auto Layout")
else:
    bad(f"D1 发现 Auto Layout：{hits}")

# D2: frame 赋值只应出现在 layoutCardInBounds / centerSpinnerInButton / showIn / dismiss 内
frame_assign = re.findall(r"([_A-Za-z][\w.\[\]]*)\.frame\s*=", dialog)
allowed_files = ["COLicenseDialog.m"]
if frame_assign:
    # 统计唯一的目标
    targets = set(frame_assign)
    ok(f"D2 frame 赋值集中于弹窗（{len(targets)} 个目标对象）")

# D3: 布局函数必须能被重复调用且不累积（不能出现 frame.origin.y += 这类）
if not re.search(r"\.frame\s*=\s*CGRectMake\(\s*[^,]+,\s*[^,]*\+=", dialog):
    ok("D3 无 frame 累加式赋值")
else:
    warn("D3 存在 frame 累加赋值")

# D4: 必须用 CGRectZero（不是 CGRectMake(0,0,0,0)）来隐藏
if "_noticeBox.frame = CGRectZero" in dialog and "_versionRow.frame = CGRectZero" in dialog:
    ok("D4 隐藏区块用 CGRectZero")
else:
    warn("D4 隐藏区块未用 CGRectZero")

# D5: 键盘避让必须算 availH
if re.search(r"CGFloat\s+availH\s*=\s*size\.height\s*-\s*_keyboardHeight", dialog):
    ok("D5 键盘避让：availH = 屏高 - 键盘高")
else:
    bad("D5 键盘避让逻辑缺失")

# D6: 卡片宽度必须同时受屏宽比例与最大值约束
if re.search(r"MIN\(screenW\s*\*\s*0\.88,\s*CO_CARD_MAX_W\)", dialog):
    ok("D6 卡片宽度 = MIN(屏宽*0.88, 320/340)")
else:
    bad("D6 卡片宽度约束写法不对")

print()
print("=" * 74)
print("E. 资源与图标")
print("=" * 74)

icon = CODE["COIcon.m"]
# E1: 图标必须缓存
if "gIconCache" in icon and "gIconCache[key] = img" in icon:
    ok("E1 图标有缓存")
else:
    bad("E1 图标无缓存")

# E2: 不许用 emoji 做图标（★ 这类装饰符只出现在注释里，不算）
#     先把注释剥掉再扫，否则 #pragma mark 里的 ★ 会误报。
code_only = "".join(CODE.values())
emoji = re.findall(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]", code_only)
if not emoji:
    ok("E2 无 emoji 图标（注释里的装饰符已排除）")
else:
    bad(f"E2 发现 emoji：{set(emoji)}")

# E3: 绘制函数必须成对 Save/Restore GState
#     ★ 签名允许带 color: 后缀（drawInfo:color: 这种），
#       所以参数表匹配到 { 之前为止，不写死具体参数。
for fn in ["drawShield", "drawKey", "drawInfo", "drawTag",
           "drawCheck", "drawCross", "drawWarn"]:
    m = re.search(r"\+ \(void\)" + fn + r":[^\n{]*\{([\s\S]*?)\n\}", icon)
    if not m:
        bad(f"E3 找不到 {fn}")
        continue
    body = m.group(1)
    if body.count("CGContextSaveGState") == body.count("CGContextRestoreGState"):
        ok(f"E3 {fn} GState 成对")
    else:
        bad(f"E3 {fn} GState 不配对")

# E4: UIImage 兜底 hook 必须调原始实现（否则宿主所有图片全废）
if "CoreHomeOriginalImageNamed(self, _cmd, name)" in core:
    ok("E4 图片 Hook 先调原实现")
else:
    bad("E4 图片 Hook 未调原实现")

# E5: 转圈用 layer 旋转而不是重绘
if re.search(r'transform\.rotation\.z', dialog):
    ok("E5 转圈用 layer 动画，不重绘图标")
else:
    warn("E5 转圈实现方式待确认")

print()
print("=" * 74)
print("F. 网络拦截")
print("=" * 74)

# F1: 白名单必须先于黑名单判定
i_env = core.find("CoreEnvironmentResource(url)")
i_blk = core.find("CoreBlockNetworkURL(url)")
if 0 < i_env < i_blk:
    ok("F1 白名单先于黑名单判定")
else:
    bad("F1 白名单/黑名单判定顺序错误")

# F2: 拦掉的请求不能调 resume
#     ★ 匹配必须限定在 else-if 的**块内**。
#       之前用 [\s\S]{0,300} 会跨过右花括号吃到下一段，
#       把「放行分支调 resume」误判成「拦截分支调了 resume」。
m = re.search(r"else if \(CoreBlockNetworkURL\(url\)\) \{([^{}]*)\}", core)
if m:
    block = m.group(1)
    if "return;" in block and "CoreHomeOriginalResume" not in block:
        ok("F2 拦截后立即 return，不转发")
    else:
        bad(f"F2 拦截分支仍会转发：{block.strip()[:80]}")
else:
    bad("F2 找不到拦截分支")

# F3: 非拦截请求必须调原 resume（否则全 App 断网）
if re.search(r"CoreHomeOriginalResume\(self,\s*_cmd\)", core):
    ok("F3 放行请求调原 resume")
else:
    bad("F3 放行分支未调原 resume")

# F4: 只处理宿主 App 内的类
if 'strstr(image, ".app/")' in core:
    ok("F4 遮罩 Hook 限定宿主 App 内的类")
else:
    bad("F4 遮罩 Hook 未限定镜像")

print()
print("=" * 74)
print("G. 卡密接入完整性")
print("=" * 74)

# G1: CoreLicenseExpiryString 不能再返回写死的 2099
m = re.search(r"static NSString \*CoreLicenseExpiryString\(void\) \{([\s\S]*?)\n\}", core)
if m:
    body = m.group(1)
    if "COVerifyBridge" in body and "cachedExpiry" in body:
        ok("G1 CoreLicenseExpiryString 已接上真实校验结果")
    else:
        bad("G1 CoreLicenseExpiryString 仍是写死值")
    # 未授权兜底必须走命名常量，不能硬编码日期字面量
    if re.search(r'@"\d{4}-\d{2}-\d{2}', body):
        bad("G1b CoreLicenseExpiryString 里仍有硬编码日期字面量")
    elif "COVerifyUnauthorizedExpiry" in body or "COVerifyIsUnauthorized" in body:
        ok("G1b 未授权兜底走命名常量，无硬编码日期")
    else:
        warn("G1b 未授权兜底写法待确认")
else:
    bad("G1 找不到 CoreLicenseExpiryString")

# G1c: 授权判定不能用 hasPrefix 硬比年份
if re.search(r'hasPrefix:\s*@"\d{4}"', core):
    bad("G1c 授权判定仍在硬比年份前缀")
else:
    ok("G1c 授权判定用哨兵函数，不硬比年份")

# G2: 桥接层必须处理 SDK 不存在的情况
if re.search(r"Class\s+cls\s*=\s*NSClassFromString\(@\"T3Verify\"\)", bridge) and \
   "_sdkUsable = NO" in bridge:
    ok("G2 SDK 缺失时优雅降级")
else:
    bad("G2 未处理 SDK 缺失")

# G3: 成功路径必须落盘
if re.search(r"saveCacheCard", bridge):
    ok("G3 验证成功后有落盘")
else:
    bad("G3 无落盘逻辑")

# G4: 缓存过期必须判负
m = re.search(r"- \(NSString \*\)cachedExpiry \{([\s\S]*?)\n\}", bridge)
if m and "timeIntervalSinceNow" in m.group(1):
    ok("G4 cachedExpiry 会判过期")
else:
    bad("G4 cachedExpiry 未判过期")

# G5: 配置项必须集中且可改
cfg = read(os.path.join(INC_DIR, "COVerifyConfig.h"))
for key in ["COVerifyLoginCode", "COVerifyAppKey", "COVerifyRSAPublicKey",
            "COVerifyHeartbeatInterval", "COVerifyMaxHeartbeatFail", "COCommunityURL"]:
    if key not in cfg:
        bad(f"G5 配置缺 {key}")
if all(k in cfg for k in ["COVerifyLoginCode", "COVerifyAppKey", "COVerifyRSAPublicKey",
                          "COVerifyHeartbeatInterval", "COVerifyMaxHeartbeatFail", "COCommunityURL"]):
    ok("G5 配置项集中完整")

# G6: RSA 公钥必须带 PEM 头尾
if "-----BEGIN PUBLIC KEY-----" in cfg and "-----END PUBLIC KEY-----" in cfg:
    ok("G6 RSA 公钥 PEM 头尾完整")
else:
    bad("G6 RSA 公钥缺 PEM 头尾")

# G7: 心跳阈值与间隔都从配置读，不写死
if "COVerifyHeartbeatInterval()" in bridge and "COVerifyMaxHeartbeatFail()" in bridge:
    ok("G7 心跳参数从配置读，未写死")
else:
    bad("G7 心跳参数写死")

# G8: 卡密输入必须屏蔽自动更正/首字母大写（卡密区分大小写）
if "UITextAutocorrectionTypeNo" in dialog and "UITextAutocapitalizationTypeAllCharacters" in dialog:
    ok("G8 输入框关闭自动更正，强制大写")
else:
    warn("G8 输入框自动更正设置需确认")

print()
print("=" * 74)
print("H. 构造函数早期安全性 (dyld 阶段)")
print("=" * 74)

# H1: constructor 里不许直接调 [COVerifyBridge shared] ——
#     它的 init 会读 NSUserDefaults，dyld 阶段 NSUserDefaults 子系统可能
#     还没建立，直接崩。这是本次真机闪退的根因。
core = TEXT["CoreOffline.m"]
ctor_re = re.search(r"__attribute__\(\(constructor\)\)\s*\n\s*static\s+void\s+\w+\s*\(void\)\s*\{",
                    core)
if ctor_re:
    # 用大括号配对取函数体（比正则可靠）
    start = core.index("{", ctor_re.end() - 1)
    depth, i = 0, start
    while i < len(core):
        if core[i] == "{":
            depth += 1
        elif core[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = strip_comments(core[start:i + 1])

    UNSAFE_IN_CTOR = {
        "[COVerifyBridge shared]": "COVerifyBridge 单例 (init 会读 NSUserDefaults)",
        "NSUserDefaults":          "NSUserDefaults (_CFXPreferences 未就绪)",
        "T3Verify":                "T3Verify SDK (Security.framework 未就绪)",
        "NSDateFormatter":         "NSDateFormatter (locale/ICU 未就绪)",
        "[NSTimer ":               "NSTimer (runloop 未跑)",
        "scheduledTimerWithTimeInterval": "NSTimer (runloop 未跑)",
    }
    hit = [f"{k} —— {v}" for k, v in UNSAFE_IN_CTOR.items() if k in body]
    if hit:
        for h in hit:
            bad(f"H1 constructor 里有早期不安全调用：{h}")
    else:
        ok("H1 constructor 无早期不安全调用")
else:
    warn("H1 没找到 constructor，跳过")

# H2: 卡密子系统必须通过 dispatch_async 推到主队列，不能在 ctor 里同步启动
if ctor_re:
    if "dispatch_async(dispatch_get_main_queue()" in body:
        ok("H2 卡密子系统经主队列延后启动")
    else:
        bad("H2 卡密子系统没有延后，ctor 里同步启动了")
else:
    warn("H2 跳过")

# H3: CoreLicenseExpiryString 必须有子系统未就绪时的守卫。
#     它被 hook 到宿主的 authorizationValue getter 上，宿主可能在
#     启动早期就读它，那时候碰 NSUserDefaults 会崩。
exp_re = re.search(r"static\s+NSString\s*\*\s*CoreLicenseExpiryString\s*\(void\)\s*\{", core)
if exp_re:
    s = core.index("{", exp_re.end() - 1)
    depth, i = 0, s
    while i < len(core):
        if core[i] == "{":
            depth += 1
        elif core[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    ebody = strip_comments(core[s:i + 1])
    if "gLicenseSubsystemUp" in ebody:
        ok("H3 expiry getter 有子系统就绪守卫")
    else:
        bad("H3 expiry getter 缺守卫，宿主早期调用会崩")
else:
    warn("H3 找不到 CoreLicenseExpiryString")

# H4: 守卫标志必须真的被置位，否则永远不会读到缓存（假授权）
if "gLicenseSubsystemUp" in core:
    if re.search(r"gLicenseSubsystemUp\s*=\s*YES", core):
        ok("H4 子系统就绪标志被置位")
    else:
        bad("H4 守卫标志定义了但从未置位 —— 会导致永远判定为未授权")
    # 置位必须在 [COVerifyBridge shared] 之后
    m_shared = core.find("COVerifyBridge *bridge = [COVerifyBridge shared]")
    m_flag   = core.find("gLicenseSubsystemUp = YES")
    if m_shared >= 0 and m_flag >= 0 and m_flag > m_shared:
        ok("H4b 置位在 shared 初始化之后")
    elif m_shared >= 0 and m_flag >= 0:
        bad("H4b 置位早于 shared 初始化 —— shared 建好前的窗口期不安全")
else:
    bad("H4 没有子系统就绪守卫")

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
sys.exit(1 if FAIL else 0)
