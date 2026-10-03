# ─────────────────────────────────────────────────────────────
#  CoreOffline —— 测试版 1:1 复刻
#
#  构建（需 macOS + Xcode）：
#     make                        # 默认 arm64e（与原始测试版一致）
#     make ARCHS="arm64"          # 仅 arm64
#     make ARCHS="arm64 arm64e"   # 双切片 fat（自动调 lipo）
#     make check                  # 行为一致性检查（不需要 macOS）
#     make clean
#
#  产物：CoreOffline.work.dylib
#  注入要点：install name 必须是 @executable_path/CoreOffline.work.dylib，
#           这样 insert_dylib 插进宿主后能被 dyld 正确解析。
#
#  ★ 关于 arm64e：
#    只写 `-arch arm64e` 编出来的 cpusubtype 是 0x0（= 普通 arm64），
#    必须用 `-target arm64e-apple-ios<ver>` 才会得到
#    0x80000002（arm64e，带 PAC）。
#    而 `-target` 一次只能指定一个架构，所以多架构走「分别编译 + lipo」。
#
#  ★★ 关于依赖（这是复刻版最关键的一点）：
#    原始测试版的 LC_LOAD_DYLIB 只有 3 个 framework：
#        Foundation / UIKit / QuartzCore
#    外加系统自动带的 libobjc / libSystem / CoreFoundation。
#
#    所以这里**故意**不链 Security、不链 CFNetwork、不链 CoreGraphics。
#    少一个框架 = 少一个 dyld 阶段可能出问题的点。
#    卡密那一套（T3Verify / COVerifyBridge / Keychain / 弹窗）已经挪到
#    src/_license/ 留档，等这一步验证「能进」之后再重新接回来。
# ─────────────────────────────────────────────────────────────

SDK      ?= iphoneos
# ★ 默认编 arm64e：原始测试版就是 arm64e(PAC00)，
#   注入目标（越狱设备上的 arm64e 宿主）对它最友好。
#   想编 arm64 就显式传 ARCHS="arm64"。
ARCHS    ?= arm64e
MINIOS   ?= 13.0
CC        = xcrun -sdk $(SDK) clang
LIPO      = xcrun -sdk $(SDK) lipo

OUT      = CoreOffline.work.dylib

# ★★ 源码清单：**只有一个文件**。测试版也就是一个 TU。
#    卡密那一套全部在 src/_license/，本 Makefile 不引用。
SRC      = src/CoreOffline.m

# 头文件搜索路径
INC      = -Iinclude -Isrc

# ★★ 链接的框架：严格对齐测试版的 3 个。
#
#    绝对不能加：
#      Security      —— Keychain / RSA，卡密那套才会引进来
#      CFNetwork     —— 代理/VPN 自检，测试版没有
#      CoreGraphics  —— COIcon 手绘图标，测试版没有（它只链 QuartzCore）
#
#    加任何一个都会让 dyld 阶段多一层初始化，多一个闪退面。
FRAMEWORKS = -framework Foundation -framework UIKit -framework QuartzCore

# 公共编译参数（不含架构选择 —— 架构用 -target 逐个指定）
COMMON   = -dynamiclib -fobjc-arc -O2 -Wall -Wno-unused-variable \
           $(INC) \
           -Wl,-install_name,@executable_path/$(OUT)

# 每个架构的目标三元组：arm64 -> arm64-apple-ios13.0
SLICES   = $(foreach a,$(ARCHS),$(a)-apple-ios$(MINIOS))

all: $(OUT)

# 单架构：直接编，用 -target 保证 cpusubtype 正确
ifeq ($(words $(ARCHS)),1)
$(OUT): $(SRC)
	$(CC) $(COMMON) -target $(SLICES) $(FRAMEWORKS) -o $@ $(SRC)
	@echo "── built $(OUT)  arch=$(ARCHS)"
	@ls -l $(OUT)
else
# 多架构：逐个编到 .slice-<arch>，再 lipo 合成 fat
$(OUT): $(SRC)
	@set -e; \
	slices=""; \
	for s in $(SLICES); do \
	  a=$${s%%-apple-*}; \
	  echo "── compiling $$a"; \
	  $(CC) $(COMMON) -target $$s $(FRAMEWORKS) -o .slice-$$a $(SRC); \
	  slices="$$slices .slice-$$a"; \
	done; \
	$(LIPO) -create $$slices -output $@; \
	rm -f $$slices; \
	echo "── built $(OUT)  archs=$(ARCHS)"; \
	ls -l $(OUT)
endif

# 行为一致性检查：证明复刻版没有偏离测试版
# 纯 Python，任何机器都能跑，不需要 macOS。
check:
	@python3 checks/clone_parity.py

clean:
	rm -f $(OUT) .slice-*

.PHONY: all clean check
