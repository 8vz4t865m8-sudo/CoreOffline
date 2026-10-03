#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoreOffline 逻辑不变量检查（比结构审计更深一层）

检查的是「代码应该满足的语义约束」，而不是「有没有写某个关键字」。
每一条都对应一个具体的翻车场景。
"""
import os, re, sys

ROOT = "/root/.codebuddy/artifact/coreoffline"
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
CFG = read(os.path.join(INC, "COVerifyConfig.h"))

P, F = [], []
def ok(m): P.append(m)
def bad(m): F.append(m)

print("=" * 74)
print("J. 逻辑不变量")
print("=" * 74)

# ── J1  弹窗持有者必须在回调里被清空，否则「一次失败后永久无法再弹」
m = re.search(r"dlg\.onResult\s*=\s*\^\(BOOL ok[\s\S]*?\n    \};", CO)
if m and "gDialog = nil" in m.group(0):
    ok("J1 弹窗回调里清 gDialog（可重复弹出）")
else:
    bad("J1 弹窗回调未清 gDialog —— 验证失败后将永远无法再弹")

# ── J2  失败后必须能重试（重新弹），不能一次失败就锁死
if re.search(r"license\.denied[\s\S]{0,400}CorePresentLicenseDialog\(\)", CO):
    ok("J2 验证失败后会重新拉起弹窗，用户可重试")
else:
    bad("J2 验证失败后无重试路径")

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
m = re.search(r"static void CorePresentLicenseDialog\(void\) \{([\s\S]*?)\n\}", CO)
if m and re.search(r"if\s*\(gDialog\)\s*return;", m.group(1)):
    ok("J4 CorePresentLicenseDialog 有 gDialog 短路")
else:
    bad("J4 弹窗函数没有防重入短路")

# ── J5  授权检查必须两条路径都有：缓存有效 / 需要验证
m = re.search(r"static void CoreCheckLicense\(void\) \{([\s\S]*?)\n\}", CO)
if m:
    b = m.group(1)
    has_valid = "gAuthorized = YES" in b
    has_dialog = "CorePresentLicenseDialog()" in b
    if has_valid and has_dialog:
        ok("J5 授权检查覆盖「缓存有效」与「需验证」两条路径")
    else:
        bad(f"J5 授权检查路径不全 valid={has_valid} dialog={has_dialog}")
else:
    bad("J5 找不到 CoreCheckLicense")

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
i_ok = BR.find("if (ok) {")
if i_ok >= 0:
    seg = BR[i_ok:i_ok + 900]
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
    if re.search(pat, CFG):
        ok(f"J21 配置含 {name}")
    else:
        bad(f"J21 配置缺 {name}")

# ── J22 设备 ID 不能依赖 IDFA
if "advertisingIdentifier" not in CFG and "ASIdentifierManager" not in CFG:
    ok("J22 设备 ID 不依赖 IDFA（无需 ATT 授权）")
else:
    bad("J22 设备 ID 用了 IDFA —— 未授权时会拿到全 0")

# ── J23 配置头里不能出现裸的 2099（必须走命名常量）
#      （常量定义本身那一行除外）
lines = CFG.splitlines()
bad_lines = [l for l in lines
             if "2099" in l and not re.search(r"static inline NSString \*COVerifyPerpetualExpiry", l)
             and 'return @"2099' not in l]
if not bad_lines:
    ok("J23 配置里 2099 只出现在永久卡常量定义处")
else:
    bad(f"J23 配置里 2099 散落：{bad_lines}")

# ── J24 未授权哨兵与永久卡值必须不同（否则永久卡被判未授权）
m1 = re.search(r'COVerifyPerpetualExpiry\(void\)\s*\{\s*return\s*@"([^"]+)"', CFG)
m2 = re.search(r'COVerifyUnauthorizedExpiry\(void\)\s*\{\s*return\s*@"([^"]+)"', CFG)
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

print()
print("=" * 74)
print(f"  ✅ 通过 {len(P)}   ❌ 失败 {len(F)}")
print("=" * 74)
if F:
    print("失败明细：")
    for x in F:
        print("   ❌ " + x)
sys.exit(1 if F else 0)
