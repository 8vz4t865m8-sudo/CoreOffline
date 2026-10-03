#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoreOffline 产物验证

对 CI 编译出的 CoreOffline.work.dylib 做全维度核对：
  ① Mach-O 结构    （magic / CPU / 文件类型）
  ② install name   （必须 @executable_path/CoreOffline.work.dylib）
  ③ 链接的框架     （Foundation/UIKit/CoreGraphics/QuartzCore/Security 一个不能少）
  ④ 导出符号       （5 个 C 函数）
  ⑤ 自定义类       （COIcon/COLicenseDialog/COVerifyBridge + T3 SDK 类）
  ⑥ UI 中文串      （UTF-16LE，验证卡片文案真的编进去了）
  ⑦ 体积与摘要
"""
import os, struct, sys, hashlib

DYLIB = sys.argv[1] if len(sys.argv) > 1 else \
    "/tmp/co_out/CoreOffline.work.dylib/CoreOffline.work.dylib"

if not os.path.exists(DYLIB):
    print(f"找不到产物：{DYLIB}")
    sys.exit(1)

d = open(DYLIB, "rb").read()
P, F = [], []
def ok(m): P.append(m)
def bad(m): F.append(m)

print("=" * 74)
print("① Mach-O 结构")
print("=" * 74)
magic = struct.unpack("<I", d[:4])[0]
if magic == 0xfeedfacf:
    ok("① 64 位 Mach-O")
    print("  ✓ magic 0xfeedfacf (MH_MAGIC_64)")
else:
    bad(f"① magic 异常：{hex(magic)}")
    print(f"  ✗ magic {hex(magic)}")

cputype = struct.unpack("<i", d[4:8])[0]
cpu_name = {0x0100000c: "arm64", 0x0200000c: "arm64e"}.get(cputype, hex(cputype))
if cputype in (0x0100000c, 0x0200000c):
    ok(f"① CPU = {cpu_name}")
    print(f"  ✓ CPU {cpu_name}")
else:
    bad(f"① CPU 不是 arm64/arm64e：{cpu_name}")
    print(f"  ✗ CPU {cpu_name}")

ftype = struct.unpack("<I", d[12:16])[0]
if ftype == 6:
    ok("① MH_DYLIB")
    print("  ✓ 文件类型 MH_DYLIB")
else:
    bad(f"① 不是 dylib：filetype={ftype}")
    print(f"  ✗ 文件类型 {ftype}")

ncmds = struct.unpack("<I", d[16:20])[0]
print(f"  · load commands: {ncmds}")

# ── 解析 load commands
off = 32
installs, dylibs, exports_trie = [], [], None
LC_ID_DYLIB, LC_LOAD_DYLIB = 0xD, 0xC
LC_DYLD_INFO_ONLY, LC_DYLD_EXPORTS_TRIE = 0x80000022, 0x80000033
for _ in range(ncmds):
    cmd, sz = struct.unpack("<II", d[off:off + 8])
    body = d[off:off + sz]
    if cmd in (LC_ID_DYLIB, LC_LOAD_DYLIB):
        no = struct.unpack("<I", body[8:12])[0]
        nm = body[no:body.index(b"\0", no)].decode()
        (installs if cmd == LC_ID_DYLIB else dylibs).append(nm)
    elif cmd == LC_DYLD_EXPORTS_TRIE:
        exports_trie = struct.unpack("<II", body[8:16])
    elif cmd == LC_DYLD_INFO_ONLY:
        eo, es = struct.unpack("<II", body[32:40])
        if es:
            exports_trie = (eo, es)
    off += sz

print()
print("=" * 74)
print("② install name")
print("=" * 74)
WANT = "@executable_path/CoreOffline.work.dylib"
if installs and installs[0] == WANT:
    ok("② install name 正确")
    print(f"  ✓ {installs[0]}")
else:
    bad(f"② install name 错误：{installs}")
    print(f"  ✗ {installs}  期望 {WANT}")

print()
print("=" * 74)
print("③ 链接的框架")
print("=" * 74)
NEED = ["Foundation", "UIKit", "CoreGraphics", "QuartzCore", "Security"]
joined = " ".join(dylibs)
for fw in NEED:
    if f"/{fw}.framework/" in joined:
        ok(f"③ 链了 {fw}")
        print(f"  ✓ {fw}")
    else:
        bad(f"③ 漏链 {fw}")
        print(f"  ✗ {fw} 未链接")
print(f"  · 共 {len(dylibs)} 个依赖库")

print()
print("=" * 74)
print("④ 导出符号")
print("=" * 74)
EXPORTS = ["_CoreOfflineBootstrap", "_CoreOfflinePrepare", "_CoreOfflineFinalize",
           "_CoreRemoteOpen", "_CoreRemoteFault"]
for s in EXPORTS:
    if s.encode() in d:
        ok(f"④ 导出 {s}")
        print(f"  ✓ {s}")
    else:
        bad(f"④ 缺导出符号 {s}")
        print(f"  ✗ {s}")

print()
print("=" * 74)
print("⑤ 类符号")
print("=" * 74)
CLASSES = ["COIcon", "COLicenseDialog", "COVerifyBridge", "CoreHomeLinkTarget",
           "T3Verify", "T3LoginResult", "T3NoticeResult", "T3VersionResult"]
for c in CLASSES:
    if ("_OBJC_CLASS_$_" + c).encode() in d:
        ok(f"⑤ 类 {c}")
        print(f"  ✓ {c}")
    else:
        bad(f"⑤ 缺类 {c}")
        print(f"  ✗ {c}")

print()
print("=" * 74)
print("⑥ 验证页 UI 中文串（UTF-16LE）")
print("=" * 74)
UI_STRINGS = ["卡密验证", "请输入卡密以激活完整功能", "验证并激活", "正在验证，请稍候",
              "请先输入卡密", "剪贴板是空的", "验证成功", "服务端版本",
              "已用本地授权放行", "验证服务未接入，无法激活", "请输入卡密", "粘贴"]
for s in UI_STRINGS:
    if s.encode("utf-16-le") in d:
        ok(f"⑥ UI 串 {s}")
        print(f"  ✓ {s}")
    else:
        bad(f"⑥ 缺 UI 串 {s}")
        print(f"  ✗ {s}")

print()
print("=" * 74)
print("⑦ 体积与摘要")
print("=" * 74)
size = os.path.getsize(DYLIB)
sha = hashlib.sha256(d).hexdigest()
print(f"  · 体积   {size} 字节 ({size/1024:.1f} KB)")
print(f"  · SHA256 {sha}")
ok("⑦ 摘要已计算")

print()
print("=" * 74)
print(f"  ✅ 通过 {len(P)}   ❌ 失败 {len(F)}")
print("=" * 74)
if F:
    for x in F:
        print("   ❌ " + x)
sys.exit(1 if F else 0)
