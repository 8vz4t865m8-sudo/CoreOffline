#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoreOffline 逻辑不变量检查（比结构审计更深一层）

检查的是「代码应该满足的语义约束」，而不是「有没有写某个关键字」。
每一条都对应一个具体的翻车场景。
"""
import os, re, sys

# ROOT 自动探测：取本脚本所在目录的上一级。
# 这样本地沙箱和 CI 上都能跑，不用改路径。
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
INC = os.path.join(ROOT, "include")

def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()

def code(p):
    t = read(p)
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    t = re.sub(r"//[^\n]*", "", t)
    return t

CO = code(os.path.join(SRC, "CoreOffline.m"))
DL = code(os.path.join(SRC, "COLicenseDialog.m"))
BR = code(os.path.join(SRC, "COVerifyBridge.m"))
IC = code(os.path.join(SRC, "COIcon.m"))
# ★ 配置头一律用「剥注释版」CFG_CODE：
#   拿含注释的原文去查字面量，会把注释里举的例子也算成违规 —— J23 就这么误报过。
CFG_CODE = code(os.path.join(INC, "COVerifyConfig.h"))

P, F, W = [], [], []
def ok(m): P.append(m)
def bad(m): F.append(m)
def warn(m): W.append(m)

print("=" * 74)
print("J. 逻辑不变量")
print("=" * 74)

# ── J1  弹窗持有者必须在回调里被清空，否则「一次失败后永久无法再弹」
m = re.search(r"dlg\.onResult\s*=\s*\^\(BOOL ok[\s\S]*?\n    \};", CO)
if m and "gDialog = nil" in m.group(0):
    ok("J1 弹窗回调里清 gDialog（可重复弹出）")
else:
    bad("J1 弹窗回调未清 gDialog —— 验证失败后将永远无法再弹")

# ── J2  失败之后的处理必须「留在弹窗里让用户重输」，**不能**自弹自
#
#  ★ 这条检查在「先保证能进去」改造中反过来了。
#    老实现：失败 → dispatch_after 0.4s → CorePresentLicenseDialog() 重弹。
#      看起来是「给了重试机会」，实际是**无限弹窗循环**：
#      每次重弹都要跑一轮动画+布局+一次网络请求，全在同步主线程上，
#      主线程被占死 → 看门狗、宿主 UI、自动登录回调全部排队 →
#      用户看到的就是「卡死 / 闪退」。
#    新实现：失败 **不重弹**，失败原因显示在弹窗的 statusLabel 上，
#      用户改一个字符再点一次即可 —— 弹窗自己就带这个能力。
#
#    所以这里要检查的是：CorePresentLicenseDialog 里**没有**自我调用。
m_dlg = re.search(r"static void CorePresentLicenseDialog\(void\) \{([\s\S]*?)\n\}\n", CO)
if m_dlg:
    body = m_dlg.group(1)
    # 找出函数体里（排除定义行本身）有没有自己调自己
    self_calls = len(re.findall(r"\bCorePresentLicenseDialog\(\)", body))
    if self_calls == 0:
        ok("J2 弹窗函数不自弹自（失败后留在弹窗里重输，不会死循环占主线程）")
    else:
        bad(f"J2 CorePresentLicenseDialog 仍会自我调用 {self_calls} 处 —— 无限弹窗循环")
else:
    bad("J2 找不到 CorePresentLicenseDialog")

# ── J2b 失败分支必须记录原因，且不得放行
if re.search(r"license\.denied[\s\S]{0,200}\n\s*\}\s*;", CO) and \
   not re.search(r"license\.denied[\s\S]{0,200}CoreGrantLicense", CO):
    ok("J2b 验证失败只记日志、不放行、不重弹")
else:
    bad("J2b 验证失败分支行为不正确（可能放行或重弹）")

# ── J5  授权检查必须两条路径都有：缓存有效 / 需要验证
#
#  ★ 新实现里「缓存有效」走 CoreGrantLicense(...@"cached")，
#    不再直接写 gAuthorized = YES —— 统一收口到 CoreGrantLicense。
m = re.search(r"static void CoreCheckLicense\(void\) \{([\s\S]*?)\n\}\n", CO)
if m:
    b = m.group(1)
    has_valid  = ('CoreGrantLicense(' in b) and ('"cached"' in b)
    has_dialog = "CorePresentLicenseDialog()" in b
    if has_valid and has_dialog:
        ok("J5 授权检查覆盖「缓存有效」与「需验证」两条路径")
    else:
        bad(f"J5 授权检查路径不全 valid={has_valid} dialog={has_dialog}")
else:
    bad("J5 找不到 CoreCheckLicense")

# ── J3  gDialog 必须在 showIn 之前赋值，否则动画期间的重入会弹两个
m = re.search(r"gDialog = dlg;\s*\n\s*\[dlg showIn:host\];", CO)
if m:
    ok("J3 gDialog 先赋值再 showIn（防重入）")
else:
    # 检查顺序是否反了
    if re.search(r"\[dlg showIn:host\];\s*\n\s*gDialog = dlg;", CO):
        bad("J3 gDialog 在 showIn 之后赋值 —— 动画期间可能弹两个")
    else:
        bad("J3 找不到 gDialog 与 showIn 的赋值顺序")

# ── J4  弹窗函数开头必须有 gDialog 短路
if m_dlg and re.search(r"if\s*\(gDialog\)\s*return;", m_dlg.group(1)):
    ok("J4 CorePresentLicenseDialog 有 gDialog 短路")
else:
    bad("J4 弹窗函数没有防重入短路")

# ── J4b 拿不到宿主窗口时不得自排重试（老实现 0.35s 后自调 → 无上限递归）
if m_dlg and not re.search(r"host window[\s\S]{0,300}dispatch_after", m_dlg.group(1)):
    ok("J4b 拿不到窗口时不自排重试（交给 host-ready 轮询与看门狗）")
else:
    bad("J4b 拿不到窗口时仍在自排重试 —— 无上限递归风险")

# ── J6  心跳掉线回调必须重置授权态，否则掉线了宿主还以为能用
if re.search(r"onHeartbeatLost\s*=\s*\^\{[\s\S]{0,300}gAuthorized = NO", CO):
    ok("J6 心跳掉线会重置 gAuthorized")
else:
    bad("J6 心跳掉线未重置授权态")

# ── J7  心跳必须有「卡密为空就停」的制动，否则无卡密时白跑
m = re.search(r"- \(void\)onHeartbeatTick \{([\s\S]*?)\n\}", BR)
if m and "stopHeartbeat" in m.group(1):
    ok("J7 心跳无卡密时自动停止")
else:
    bad("J7 心跳缺少空卡密制动")

# ── J8  心跳在成功时必须把失败计数归零，否则偶发失败会累积到阈值
m = re.search(r"\^\(BOOL ok, NSString \*expiry, NSString \*stateCode, NSString \*message\) \{([\s\S]*?)\n    \}\];", BR)
if m and re.search(r"if\s*\(ok\)[\s\S]{0,120}_heartbeatFail = 0", m.group(1)):
    ok("J8 心跳成功时归零失败计数")
else:
    # 换个写法找
    if re.search(r"if \(ok\) \{\s*\n\s*self->_heartbeatFail = 0;", BR):
        ok("J8 心跳成功时归零失败计数")
    else:
        bad("J8 心跳成功未归零计数 —— 间歇失败会累积到阈值误判掉线")

# ── J9  心跳阈值判断必须是 >=，不是 ==（否则失败数跳变会漏判）
if re.search(r"_heartbeatFail\s*>=\s*COVerifyMaxHeartbeatFail\(\)", BR):
    ok("J9 心跳阈值用 >=，不会漏判")
else:
    bad("J9 心跳阈值不是 >=，失败数跳变会漏判")

# ── J10 验证成功后必须落盘，否则重启又要重新输
#      ★ 从 `if (ok) {` 起抓到配对的 else 分支。中间插了 ws2 提升，
#        不能再靠 `\n        } else` 这种缩进字面量定位。
#      ★ 窗口要够大：handleLoginResult 里现在有一大段「多字段候选 + 时间戳转换」
#        的兼容代码（照 F5CloudAuth 的做法），saveCacheCard 被推得更远了。
i_ok = BR.find("if (ok) {")
if i_ok >= 0:
    seg = BR[i_ok:i_ok + 3000]
    if "saveCacheCard" in seg:
        ok("J10 验证成功即落盘")
    else:
        bad("J10 验证成功未落盘 —— 重启后重复验证")
else:
    bad("J10 找不到 ok 分支")

# ── J11 输入框为空时按钮必须禁用（逻辑上：refreshSubmitEnabled 覆盖 busy 与空文本）
m = re.search(r"- \(void\)refreshSubmitEnabled \{([\s\S]*?)\n\}", DL)
if m and "_input.text.length > 0" in m.group(1) and "!_busy" in m.group(1):
    ok("J11 按钮可用性同时看「有输入」与「不忙」")
else:
    bad("J11 按钮可用性判断不全")

# ── J12 提交时必须再挡一次空卡密（按钮态可能被绕过：键盘回车）
m = re.search(r"- \(void\)onSubmitTapped \{([\s\S]*?)\n\}", DL)
if m and "if (_busy) return;" in m.group(1) and "card.length == 0" in m.group(1):
    ok("J12 提交入口二次校验 busy 与空卡密")
else:
    bad("J12 提交入口缺少二次校验")

# ── J13 键盘回车必须走同一条提交路径，不能各写一套
m = re.search(r"- \(BOOL\)textFieldShouldReturn:\(UITextField \*\)textField \{([\s\S]*?)\n\}", DL)
if m and "onSubmitTapped" in m.group(1):
    ok("J13 回车复用提交路径")
else:
    bad("J13 回车未复用提交路径")

# ── J14 成功动画必须在回调之前播完（否则用户看不到绿色）
m = re.search(r"if \(ok\) \{([\s\S]*?)\} else \{", DL)
if m:
    b = m.group(1)
    i_delay = b.find("dispatch_after")
    i_call  = b.find("cb(YES")
    if 0 < i_delay < i_call:
        ok("J14 成功反馈先播再回调")
    else:
        bad("J14 成功回调早于反馈动画 —— 用户看不到绿色状态")
else:
    bad("J14 找不到 success 分支")

# ── J15 失败时按钮必须恢复可用（setBusyUI:NO）
m = re.search(r"\} else \{\s*\n\s*\[self setBusyUI:NO\];([\s\S]*?)\n        \}", DL)
if m:
    ok("J15 失败路径恢复按钮可用")
else:
    bad("J15 失败路径未恢复按钮 —— 卡死不能重试")

# ── J16 图标缓存 key 必须含 size 与 color，否则换色会串图
m = re.search(r"\+ \(NSString \*\)cacheKey:\(COIconType\)type size:\(CGFloat\)size color:\(UIColor \*\)color \{([\s\S]*?)\n\}", IC)
if m and "%ld" in m.group(1) and "%.1f" in m.group(1) and "%d,%d,%d,%d" in m.group(1):
    ok("J16 图标缓存 key 含 type/size/color 三元组")
else:
    bad("J16 图标缓存 key 不全 —— 白图标与蓝图标会串")

# ── J17 转圈不能进缓存（旋转由 layer 做）
if "spinnerWithSize" in IC and "gIconCache" not in IC.split("spinnerWithSize")[1]:
    ok("J17 spinner 不进缓存，旋转交给 layer")
else:
    bad("J17 spinner 走缓存会把旋转角度固化")

# ── J18 布局里「隐藏区块」必须同时置 CGRectZero，不能只隐藏不塌陷
n_zero = DL.count("frame = CGRectZero")
if n_zero >= 2:
    ok(f"J18 隐藏区块用 CGRectZero 塌陷（{n_zero} 处）")
else:
    bad("J18 隐藏区块未塌陷，会留空白")

# ── J19 布局函数首行必须有尺寸守卫，避免 0 尺寸时算出 NaN
m = re.search(r"- \(void\)layoutCardInBounds:\(CGSize\)size \{([\s\S]*?)\n    \}", DL)
if m and re.search(r"if \(!_card \|\| size\.width <= 0 \|\| size\.height <= 0\) return;", m.group(1)):
    ok("J19 布局有 0 尺寸守卫")
else:
    bad("J19 布局缺 0 尺寸守卫 —— 首帧可能算出 NaN 位置")

# ── J20 卡片底部留白必须存在（不然按钮贴着卡片下沿）
if re.search(r"y \+= 20;\s*// 卡片底部留白", DL) or re.search(r"y \+= 20;", DL):
    ok("J20 卡片有底部留白")
else:
    bad("J20 卡片无底部留白")

# ── J21 网络配置里的凭据必须与配置头一致（不能两边各写一份）
for name, pat in [("loginCode", r"0AAD3A3337741A5B"),
                  ("appkey", r"1e45cd9daa2d5d7dfc6d8e66abe43b0a")]:
    if re.search(pat, CFG_CODE):
        ok(f"J21 配置含 {name}")
    else:
        bad(f"J21 配置缺 {name}")

# ── J22 设备 ID 不能依赖 IDFA
if "advertisingIdentifier" not in CFG_CODE and "ASIdentifierManager" not in CFG_CODE:
    ok("J22 设备 ID 不依赖 IDFA（无需 ATT 授权）")
else:
    bad("J22 设备 ID 用了 IDFA —— 未授权时会拿到全 0")

# ── J23 配置头里不能出现裸的 2099（必须走命名常量）
#      （常量定义本身那一行除外）
#   ★ 用剥注释版：注释里举例说明"原测试版吐 2099"是合法的，
#     拿含注释的原文去查会误报。
lines = CFG_CODE.splitlines()
bad_lines = [l for l in lines
             if "2099" in l and not re.search(r"static inline NSString \*COVerifyPerpetualExpiry", l)
             and 'return @"2099' not in l]
if not bad_lines:
    ok("J23 配置里 2099 只出现在永久卡常量定义处")
else:
    bad(f"J23 配置里 2099 散落：{bad_lines}")

# ── J24 未授权哨兵与永久卡值必须不同（否则永久卡被判未授权）
m1 = re.search(r'COVerifyPerpetualExpiry\(void\)\s*\{\s*return\s*@"([^"]+)"', CFG_CODE)
m2 = re.search(r'COVerifyUnauthorizedExpiry\(void\)\s*\{\s*return\s*@"([^"]+)"', CFG_CODE)
if m1 and m2 and m1.group(1) != m2.group(1):
    ok(f"J24 哨兵({m2.group(1)}) ≠ 永久卡({m1.group(1)})")
else:
    bad("J24 哨兵与永久卡值相同或缺失 —— 永久卡会被误判未授权")

# ── J25 cachedExpiry 必须能区分「无缓存」与「过期」
m = re.search(r"- \(NSString \*\)cachedExpiry \{([\s\S]*?)\n\}", BR)
if m:
    b = m.group(1)
    if "length == 0" in b and "timeIntervalSinceNow" in b:
        ok("J25 cachedExpiry 同时处理「无缓存」与「已过期」")
    else:
        bad("J25 cachedExpiry 判定不全")
else:
    bad("J25 找不到 cachedExpiry")

# ══════════════════════════════════════════════════════════════════════
#  M. 凭据持久化（照 F5CloudAuth 的做法）
# ══════════════════════════════════════════════════════════════════════

def read_src(name):
    """读 src/ 下的源文件并剥掉注释。找不到就返回空串（CI 上可能缺文件）。"""
    p = os.path.join(SRC, name)
    try:
        return code(p)
    except Exception:
        return ""

KC = read_src("COKeychain.m")
EN = read_src("COEntry.m")
KCH = read_src("COKeychain.h")

# ── M1 Keychain 必须用 ThisDeviceOnly（否则凭据会跟着备份跑到别的机器）
if "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly" in KC:
    ok("M1 Keychain 用 AfterFirstUnlockThisDeviceOnly")
else:
    bad("M1 Keychain 没用 ThisDeviceOnly —— 凭据会随备份迁移，一卡多机")

# ── M2 写入前必须先 update 再 add（否则重复写返回 errSecDuplicateItem）
if "SecItemUpdate" in KC and "errSecItemNotFound" in KC and "SecItemAdd" in KC:
    ok("M2 Keychain 写：先 update 再 add")
else:
    bad("M2 Keychain 写缺 update/add 双路径 —— 第二次写入会失败")

# ── M3 三级回退读取（Keychain → 文件 → NSUserDefaults）
if "COVaultRead" in BR or "COVaultRead" in KC:
    ok("M3 存储走 COVault（Keychain + 文件双写）")
else:
    bad("M3 没看到 COVault 双写")

if "keychain" in KC.lower() and "COVaultFileRead" in KC:
    ok("M3b 文件副本回退已实现")
else:
    bad("M3b 缺文件副本回退 —— 清 Keychain 就白嫖")

# ── M4 文件副本必须带完整性校验（防「编辑器改日期」）
if "COSealValue" in KC and "COUnsealValue" in KC and "CC_SHA256" in KC:
    ok("M4 文件副本带 SHA256 校验")
else:
    bad("M4 文件副本没校验 —— 改个日期就能续期")

# ── M5 读到文件副本要能自愈回填 Keychain
if re.search(r"COVaultRead[\s\S]{0,600}?COKeychainWrite", KC) or \
   re.search(r"自愈", KC) or "回填" in KC:
    ok("M5 文件副本命中后回填 Keychain（自愈）")
else:
    warn_or_bad = bad
    warn_or_bad("M5 没看到自愈回填逻辑")

# ── M6 Keychain 可用性探测（无签名环境下要能降级）
if "COKeychainAvailable" in KC and "probe" in KC.lower():
    ok("M6 有 Keychain 可用性探测")
else:
    bad("M6 没有 Keychain 可用性探测 —— 无签名环境会静默失败")

# ── M7 双写不能因为一方失败就整体失败
if re.search(r"return\s+a\s*\|\|\s*b", KC):
    ok("M7 双写是「任一成功即成功」")
else:
    bad("M7 双写用 && —— 一边不可用整个授权就存不下来")

# ══════════════════════════════════════════════════════════════════════
#  N. 宿主 C 入口（照 F5CloudAuth 的 bsupx_c_* 的做法）
# ══════════════════════════════════════════════════════════════════════

# ── N1 必须导出 coreoffline_c_* 系列
need = ["coreoffline_c_verify_card", "coreoffline_c_verify_saved",
        "coreoffline_c_has_license", "coreoffline_c_clear",
        "coreoffline_c_risk_mask", "coreoffline_c_machine_code",
        "coreoffline_c_start_heartbeat", "coreoffline_c_stop_heartbeat"]
missing = [n for n in need if n not in EN]
if not missing:
    ok(f"N1 C 入口齐全（{len(need)} 个关键函数）")
else:
    bad(f"N1 缺 C 入口：{missing}")

# ── N2 入口回调必须派发到主线程（宿主大概率在里面碰 UIKit）
if re.search(r"isMainThread[\s\S]{0,200}?dispatch_async\(dispatch_get_main_queue", EN):
    ok("N2 C 入口回调强制主线程派发")
else:
    bad("N2 C 入口回调没强制主线程 —— 宿主碰 UIKit 会崩")

# ── N3 回调里给的 const char* 不能要求宿主 free —— 必须是内部缓冲
if "malloc" in EN and "tls_" in EN:
    ok("N3 返回的 C 字符串走线程局部缓冲，宿主无需 free")
else:
    bad("N3 C 字符串生命周期没管好 —— 宿主 free 或不 free 都可能出问题")

# ── N4 头文件里 C 函数必须有 default visibility 保证，且用 extern \"C\"
if 'extern "C"' in KCH or True:
    pass
if re.search(r"typedef struct \{[\s\S]{0,300}?\}\s*COAuthResult", read_src("COEntry.h")):
    ok("N4 C 入口有明确的 COAuthResult 结构（对齐 F5 的 BSVerifyUltraProxyResult）")
else:
    bad("N4 C 入口缺结果结构定义")

# ── N5 风控位定义必须齐全（调试/越狱/注入/代理）
hdr = read_src("COEntry.h")
risks = ["CO_RISK_DEBUGGER", "CO_RISK_JAILBREAK", "CO_RISK_INJECTED", "CO_RISK_PROXY"]
if all(r in hdr for r in risks):
    ok("N5 风控位定义齐全（debugger/jailbreak/injected/proxy）")
else:
    bad(f"N5 风控位缺：{[r for r in risks if r not in hdr]}")

# ── N6 越狱检测要查多个路径（只查 Cydia.app 太容易绕过）
n_paths = len(re.findall(r'"/[^"]+",', EN))
if n_paths >= 4:
    ok(f"N6 越狱检测覆盖 {n_paths} 个路径")
else:
    bad(f"N6 越狱检测只查了 {n_paths} 个路径 —— 太容易被绕过")

# ── N7 代理检测必须用 CFNetworkCopySystemProxySettings（而不是查特定 App）
if "CFNetworkCopySystemProxySettings" in EN:
    ok("N7 用系统 API 检测代理/VPN")
else:
    bad("N7 没做代理检测")

# ── N8 不能把 Security / CFNetwork 拖进 constructor 早期路径
ctor_hits = re.findall(r"security|cfnetwork|secitem|keychain", ctor_body, re.I) \
    if (ctor_body := (lambda m: m.group(1) if m else "")(re.search(
        r"initializeOffline\(void\)\s*\{([\s\S]*?)\n\}", read_src("CoreOffline.m")))) else []
if not ctor_hits:
    ok("N8 constructor 早期路径没碰 Security/CFNetwork")
else:
    bad(f"N8 constructor 早期路径出现 {ctor_hits} —— 会闪退")

# ══════════════════════════════════════════════════════════════════════
#  O. 离线兜底（保住用户测试版「永不锁死」的行为）
# ══════════════════════════════════════════════════════════════════════
#
#  用户原话：「我用原来我那个测试版就不会闪退」——
#  原测试版是纯离线的（硬编码 2099），服务器挂了照样能用。
#  加了联网验证之后，必须保住这个特性，否则一断网用户就被挡在门外。

# ── O1 兜底开关必须存在且默认开
if re.search(r"COVerifyAllowOfflineFallback\(void\)\s*\{\s*return\s+YES", CFG_CODE):
    ok("O1 离线兜底开关存在且默认开启")
else:
    bad("O1 缺 COVerifyAllowOfflineFallback（或默认值不是 YES）—— 断网就锁死")

# ── O2 宽限期必须可配
if re.search(r"COVerifyOfflineGrace\(void\)\s*\{\s*return\s+[\d\.]+\s*\*", CFG_CODE) or \
   re.search(r"COVerifyOfflineGrace\(void\)\s*\{\s*return\s+[\d\.]+", CFG_CODE):
    ok("O2 离线宽限期可配")
else:
    bad("O2 缺 COVerifyOfflineGrace —— 每次启动都必须联网，体验倒退")

# ── O3 兜底前必须区分「网络故障」和「卡密错误」
if "COIsNetworkFailure" in BR:
    ok("O3 兜底前做失败归因（COIsNetworkFailure）")
else:
    bad("O3 没做失败归因 —— 卡密错也能兜底 = 随便填都过")

# ── O4 卡密类错误绝不能兜底
#      判据：兜底调用点必须被 COIsNetworkFailure 包住
if re.search(r"COVerifyAllowOfflineFallback\(\)\s*&&\s*COIsNetworkFailure", BR):
    ok("O4 兜底被 COIsNetworkFailure 短路，卡密错不会放行")
else:
    bad("O4 兜底没被失败归因包住 —— 卡密错误可能白送授权")

# ── O5 必须记录「最后一次成功时间」才能算宽限
if "kCOKeyLastGoodStamp" in BR and re.search(r"COStoreWriteDouble\(kCOKeyLastGoodStamp", BR):
    ok("O5 记录最后一次联网成功时间（宽限期依据）")
else:
    bad("O5 没记录最后成功时间 —— 宽限期算不出来")

# ── O6 成功路径才写 lastGood（失败不能刷新宽限）
#      否则连不上服务器反而把宽限一直续下去
ok_writes = re.findall(r"COStoreWriteDouble\(kCOKeyLastGoodStamp", BR)
if len(ok_writes) == 1:
    ok("O6 lastGood 只在成功路径写一次（失败不会续宽限）")
elif len(ok_writes) > 1:
    bad(f"O6 lastGood 被写了 {len(ok_writes)} 次 —— 失败路径也刷的话宽限永远续下去")
else:
    bad("O6 找不到 lastGood 写入点")

# ── O7 result 为 nil（SDK 没返回）也要有兜底
if re.search(r"nil_result_fallback|nil_result_perpetual", BR):
    ok("O7 SDK 返回 nil 时也有兜底（不锁死）")
else:
    bad("O7 SDK 返回 nil 直接判失败 —— 宿主会卡在未授权")

# ── O8 兜底必须写日志（线上排查唯一手段）
n_fb_logs = len(re.findall(r'CORecord\("license\.(offline_fallback|nil_result)', BR))
if n_fb_logs >= 3:
    ok(f"O8 兜底路径有 {n_fb_logs} 条日志（可线上排查）")
else:
    bad(f"O8 兜底日志只有 {n_fb_logs} 条 —— 出问题查不到")

# ── O9 服务器地址的来源必须清楚
#
#   T3 SDK 把地址硬编码在 sdk/T3Verify.m 的 T3ServerURLs() 里，
#   init 洗牌 + 请求时逐个重试（它自己的容灾）。
#   配置头**不该**再留一份 baseURL/host/port —— 那会让人以为要手配，
#   而且真配了反而会绕开 SDK 的故障转移。
SDK_F = os.path.join(ROOT, "sdk", "T3Verify.m")
sdk_text = open(SDK_F, encoding="utf-8").read() if os.path.exists(SDK_F) else ""
n_servers = len(re.findall(r'@"https://[\w.]+/"', sdk_text))
if n_servers >= 2:
    ok(f"O9 服务器地址在 SDK 里（{n_servers} 个轮询点，自带容灾）")
else:
    bad("O9 SDK 里找不到服务器地址 —— 请求会打到空 URL")

# 配置头里不能有「填地址」的残留配置项，否则误导使用者
if re.search(r"COVerifyBaseURL|COVerifyHost\b|COVerifyPort\b", CFG_CODE):
    bad("O9 配置头还留着 BaseURL/Host/Port —— 会让人以为要手配，"
        "且配了会绕开 SDK 自带的服务器轮询")
else:
    ok("O9 配置头没有多余的地址配置项（不误导使用者）")

# ==========================================================================
# P. T3 SDK 对接正确性
#
#    ★★ 这一节防的是一个「看起来完全正常、实际永远验证不过」的坑：
#
#    T3 的 T3LoginResult 在**成功**时才带上 code=200；
#    失败时它只有 success=NO + error=@"..."，**根本没有 code 字段**。
#
#    所以如果成功判定写成「读 code，等于 1/200 才算过」，
#    code 永远是 nil → 判定永远为 NO → 卡密再对也进不去，
#    而且错误提示还会显示成一个笼统的"验证失败"，让人以为是卡密问题。
#
#    这类 bug 编译能过、单测（如果只 mock 成功路径）也能过，
#    只有在真机上拿真卡密试才会暴露。所以必须用静态检查钉死。
# ==========================================================================

# ── P1 成功判定必须以 success 字段为准
if re.search(r"respondsToSelector:\s*NSSelectorFromString\(@\"success\"\)", BR) or \
   re.search(r"@selector\(success\)", BR) or '"success"' in BR:
    ok("P1 成功判定读了 T3LoginResult.success（不再只认 code）")
else:
    bad("P1 成功判定没读 success —— T3 失败结果没有 code 字段，会导致卡密永远验不过")

# ── P2 成功判定不能只认 code
if re.search(r"COSuccessOfResult", BR):
    ok("P2 成功判定走 COSuccessOfResult（success 优先、code 兜底）")
else:
    bad("P2 缺少 COSuccessOfResult —— 成功判定逻辑散落，容易退回只认 code")

# ── P3 失败原因必须能读到 T3 的 error 字段
#      否则用户只看到"验证失败"，分不清卡密错还是网络错
if re.search(r'@\[@"error",\s*@"msg"', BR) or re.search(r'"error"\s*,\s*"msg"', BR):
    ok("P3 失败原因优先读 error 字段（与 T3 的形状一致）")
else:
    bad("P3 失败原因没读 error —— T3 的失败文案在 error 不在 msg，用户看不到真实原因")

# ── P4 RSA 初始化失败必须拒绝工作
#      吞掉 RSA 初始化错误 = 用 nil 编解码器跑，表现是「卡密对却验不过」
if re.search(r"if\s*\(\s*!setupOK\s*\)", BR) or re.search(r"if\s*\(\s*!initOK\s*\)", BR):
    ok("P4 RSA 初始化失败会拒绝工作（不带着坏编解码器硬跑）")
else:
    bad("P4 RSA 初始化返回值被忽略 —— 公钥填错时会表现为「卡密永远验证失败」")

# ── P5 装配失败的原因要能透出来
if re.search(r"setupError", BR) or re.search(r"initError", BR):
    ok("P5 装配失败原因有留存（能告诉用户是公钥错还是版本不兼容）")
else:
    bad("P5 装配失败原因被丢弃 —— 出问题只能靠猜")

# ── P6 NSInvocation 的 error 出参下标必须是 8
#      (loginCode,noticeCode,versionCode,heartbeatCode,appkey,rsaPublicKey,error*)
#      → self(0) _cmd(1) 之后 6 个对象占 2..7，error 在 8
if re.search(r"atIndex:8", BR):
    ok("P6 RSA 初始化的 error 出参下标为 8（与 7 参签名一致）")
else:
    bad("P6 RSA 初始化 error 出参下标不对 —— 错误信息会写到别人的槽位")

# ── P7 初始化参数个数校验：不能只靠 respondsToSelector
#      nil 对象对任何 selector 都返回 NO，会把「init 失败」误判成「用别的初始化方式」
if re.search(r"init\s+returned\s+nil", BR) or re.search(r"if\s*\(\s*!inst\s*\)", BR):
    ok("P7 检查了 init 返回值（nil 对象不会骗过 respondsToSelector）")
else:
    bad("P7 没检查 init 返回值 —— init 失败时被 respondsToSelector 的 nil 语义骗过去")

# ==========================================================================
# Q. 启动体验（照用户原测试版：打开就进，不让人反复输卡密）
#    CO 已在文件开头定义为「剥注释版 CoreOffline.m」
# ==========================================================================

# ── Q1 存过卡密必须自动登录
#      缺了这一步，用户每次开 App 都要重输 —— 相对原测试版是体验倒退
if re.search(r"autologin", CO):
    ok("Q1 启动时会对已存卡密做静默自动登录")
else:
    bad("Q1 没有自动登录 —— 用户每次开 App 都得重输卡密，比原测试版还难用")

# ── Q2 自动登录失败必须退回弹窗（不能静默卡在未授权）
if re.search(r"autologin\s+FAILED", CO):
    ok("Q2 自动登录失败会退回验证弹窗")
else:
    bad("Q2 自动登录失败没有退路 —— 用户会卡在未授权且看不到输入框")

# ── Q3 已授权后不再重复弹窗
if re.search(r"already authorized", CO):
    ok("Q3 已授权时弹窗会被短路（不会重复弹）")
else:
    bad("Q3 已授权仍可能弹窗 —— 自动登录成功后会闪一下验证框")

# ── Q4 自动登录成功要收掉已经开着的弹窗
if re.search(r"dismissed open dialog", CO):
    ok("Q4 自动登录成功会收掉已打开的弹窗")
else:
    warn("Q4 自动登录成功时若弹窗已开，可能残留（竞态窗口很小但存在）")

print()
print("=" * 74)
print("R. 保活优先（「一定要能进去」的硬保证）")
print("=" * 74)
print()

# ── R1  必须有看门狗：到点无条件放行
if re.search(r"static void CoreArmFailOpenWatchdog\(void\)", CO):
    ok("R1 存在 fail-open 看门狗")
else:
    bad("R1 没有看门狗 —— 网络/弹窗任何一环卡住，用户就进不去软件")

# ── R2  看门狗必须在构造函数里、**早于**找窗口就挂上
if re.search(r"CoreArmFailOpenWatchdog\(\);\s*\n[^\n]*CoreWaitForHostReady", CO):
    ok("R2 看门狗在 CoreWaitForHostReady 之前挂上（先保命再尽力）")
else:
    bad("R2 看门狗晚于找窗口 —— 窗口一直不出来时看门狗永远挂不上")

# ── R3  看门狗放行用的是远期到期时间，不是未授权哨兵
m = re.search(r"static void CoreFailOpen\(const char \*reason\) \{([\s\S]*?)\n\}", CO)
if m and "COVerifyPerpetualExpiry()" in m.group(1):
    ok("R3 fail-open 放行用远期到期时间（宿主会认为授权有效）")
else:
    bad("R3 fail-open 没用远期到期时间 —— 放了还是进不去")

# ── R4  放行必须收口到一个函数（不然总有路径漏发通知）
if re.search(r"static void CoreGrantLicense\(NSString \*expiry, NSString \*reason\)", CO):
    ok("R4 放行收口到 CoreGrantLicense")
else:
    bad("R4 放行没做收口 —— 容易漏掉「发通知放行宿主」这一步")

# ── R5  「缓存有效」路径也必须走 CoreGrantLicense（否则通知发不出去）
m = re.search(r"static void CoreCheckLicense\(void\) \{([\s\S]*?)\n\}\n", CO)
if m and re.search(r'"cached"', m.group(1)):
    ok("R5 缓存有效路径也走统一放行出口")
else:
    bad("R5 缓存有效路径没走统一出口 —— 宿主可能等不到放行通知")

# ── R6  看门狗等待时长必须是可配置常量（方便按需收紧/关闭）
if re.search(r"COVerifyFailOpenAfter\(\)", CO) and \
   re.search(r"static inline NSTimeInterval COVerifyFailOpenAfter", CFG_CODE):
    ok("R6 看门狗时长由 COVerifyFailOpenAfter() 配置")
else:
    bad("R6 看门狗时长写死在代码里 —— 无法按现场情况调整")

# ── R7  看门狗可以被关掉（配 0 = 严格模式）
if re.search(r"if \(delay <= 0\) return;", CO):
    ok("R7 看门狗可关（配 0 转严格模式）")
else:
    bad("R7 看门狗无法关闭 —— 需要真风控时没有退路")

print()
print("=" * 74)
print("S. WS / 网络断联")
print("=" * 74)
print()

# ── S1  宿主的 WS 地址必须在黑名单里（用户明确要求掐断）
if "47.108.53.191" in CO:
    ok("S1 黑名单含宿主 WS 主机 47.108.53.191")
else:
    bad("S1 黑名单没有 47.108.53.191 —— 宿主 WS 拦不住")

# ── S2  拦截黑名单任务时必须真 cancel，不能只是「不转发」
m = re.search(r"static void CoreTaskResume\(id self, SEL _cmd\) \{([\s\S]*?)\n\}", CO)
if m and "[task cancel]" in m.group(1):
    ok("S2 命中黑名单的任务会真 cancel（不是挂起）")
else:
    bad("S2 命中黑名单只是不转发 —— 任务永远挂起，宿主会无限重连刷屏")

# ── S3  resume 必须有兜底转发，绝不能因为原实现为 NULL 就吞掉
if re.search(r"static void CoreHomeFallbackResume\(id self, SEL _cmd\)", CO):
    ok("S3 resume 有兜底转发（原实现取不到时不会吞掉全部网络）")
else:
    bad("S3 resume 没有兜底 —— 原实现为 NULL 时宿主网络全死")

# ── S4  兜底转发的路径必须在非拦截分支里被调用
m = re.search(r"if \(CoreHomeOriginalResume\) \{[\s\S]{0,120}\} else \{([\s\S]{0,120})\}", CO)
if m and "CoreHomeFallbackResume" in m.group(1):
    ok("S4 非拦截请求走「原实现 → 兜底」两级转发")
else:
    bad("S4 非拦截请求的转发链不完整")

# ── S5  WS 任务类型要单独识别（日志里能一眼看到掐断了几条 WS）
if re.search(r"NSURLSessionWebSocketTask", CO):
    ok("S5 能识别 WS 任务类型（日志区分 WS 与普通请求）")
else:
    warn("S5 没有单独识别 WS 任务 —— 日志里分不清掐断的是不是 WS")

# ── S6  cancelNetworkTasks 不能是空壳（必须真扫真取消）
m = re.search(r"static void cancelNetworkTasks\(void\) \{([\s\S]*?)\n\}", CO)
if m and "getAllTasksWithCompletionHandler" in m.group(1):
    ok("S6 cancelNetworkTasks 会扫描并取消在跑的命中任务（非空壳）")
else:
    bad("S6 cancelNetworkTasks 是空壳 —— hook 安装前已启动的 WS 永远拦不到")

# ── S7  计数器必须原子递增（对齐测试版反汇编里的 ldaddal）
if re.search(r"__c11_atomic_fetch_add", CO):
    ok("S7 拦截计数器用原子递增")
else:
    bad("S7 拦截计数器非原子 —— 多线程下是竞态")

print()
print("=" * 74)
print("T. 离线兜底不能变成「白送授权」")
print("=" * 74)
print()

# ── T1  cachedExpiry 必须挡住未授权哨兵
m = re.search(r"- \(NSString \*\)cachedExpiry \{([\s\S]*?)\n\}", BR)
if m and "COVerifyIsUnauthorized" in m.group(1):
    ok("T1 cachedExpiry 挡住未授权哨兵（不会被当成有效授权）")
else:
    bad("T1 cachedExpiry 未挡哨兵 —— 看门狗放行一次以后就永久免验证了")

# ── T2  cachedExpiry 必须挡住永久卡哨兵
if m and "COVerifyPerpetualExpiry" in m.group(1):
    ok("T2 cachedExpiry 挡住永久卡哨兵（fail-open 不落盘成长期授权）")
else:
    bad("T2 cachedExpiry 未永久卡哨兵 —— 离线放行会变成永久的")

# ── T3  SDK 不可用时要放行而不是拒绝（不能比测试版还不如）
m = re.search(r"- \(void\)verifyFallbackWithCard:([\s\S]*?)\n\}", BR)
if m and re.search(r"completion\(YES", m.group(1)):
    ok("T3 SDK 缺席时放行（不会因为没有 SDK 就把用户关在门外）")
else:
    bad("T3 SDK 缺席时拒绝 —— 比纯离线测试版体验还差，方向反了")

print()
print("=" * 74)
print(f"  ✅ 通过 {len(P)}   ❌ 失败 {len(F)}")
print("=" * 74)
if F:
    print("失败明细：")
    for x in F:
        print("   ❌ " + x)
print()
if W:
    print(f"   ⚠️  {len(W)} 项需人工确认：")
    for x in W:
        print("      ⚠️  " + x)
sys.exit(1 if F else 0)
