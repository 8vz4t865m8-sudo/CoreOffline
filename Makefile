# ─────────────────────────────────────────────────────────────
#  CoreOffline v3 —— 宿主 Core-SET_1.6 卡密接管
#
#  构建（需 macOS + Xcode）：
#     make                          # 默认双切片 arm64 + arm64e
#     make ARCHS="arm64e"           # 仅 arm64e
#     make ARCHS="arm64"            # 仅 arm64
#     make check                    # 行为一致性检查（不需要 macOS）
#     make clean
#
#  产物：CoreOffline.v3.dylib
#  注入要点：install name 必须是 @executable_path/CoreOffline.v3.dylib，
#           这样 insert_dylib 插进宿主后能被 dyld 正确解析。
#           ★ install name 与文件名保持一致 —— 别只改一半。
#
#  ★ 关于 arm64e：
#    只写 `-arch arm64e` 编出来的 cpusubtype 是 0x0（= 普通 arm64），
#    必须用 `-target arm64e-apple-ios<ver>` 才会得到
#    0x80000002（arm64e，带 PAC）。
#    而 `-target` 一次只能指定一个架构，所以多架构走「分别编译 + lipo」。
#
# ★★ 关于接管策略（v3 的核心修正）：
#    只 hook 4 个确定存在的方法，且**绝不自己调用 completion block**。
#    主接管点是 QXA117 finish:authorized:message:expiresAt: ——
#    宿主所有卡密路径（成功/网络失败/解析失败）都收敛到这里，
#    我们只把 authorized 改成 YES，其余交给宿主自己的 block 调用链。
#    详见 src/CoreOffline.m 头部注释。
#
#  ★★ 关于依赖：
#    只有 Foundation + UIKit。
#    宿主的卡密体系确实用到 Security(Keychain)/CryptoKit/CFNetwork，
#    但那些都在宿主自己的二进制里，我们的 dylib 完全不需要再链一遍。
#    依赖越少 = dyld 初始化越短 = 自签环境下越不容易出问题。
# ─────────────────────────────────────────────────────────────

SDK      ?= iphoneos
# ★★ 默认编 **双切片 arm64 + arm64e**（这是 v3 的重要修正）。
#
#    原因（实测宿主 Core-SET_1.6）：
#      宿主 Core 是 thin arm64e (cpusubtype=0x80000002, PAC00)。
#      arm64e 设备能加载 arm64 切片，但 arm64-only 设备加载不了 arm64e 切片。
#      编双切片 → 两种设备都能盖住，重签后哪台机器都不因为架构被拒。
#
#    想只编一个架构就显式传 ARCHS="arm64" 或 ARCHS="arm64e"。
ARCHS    ?= arm64 arm64e
MINIOS   ?= 13.0
CC        = xcrun -sdk $(SDK) clang
LIPO      = xcrun -sdk $(SDK) lipo

OUT      = CoreOffline.v3.dylib

# ★★ 源码清单：**只有一个文件**。测试版也就是一个 TU。
#    卡密那一套全部在 src/_license/，本 Makefile 不引用。
SRC      = src/CoreOffline.m

# 头文件搜索路径
INC      = -Iinclude -Isrc

# ★★ 链接的框架：只有 2 个。
#
#    绝对不能加（每一个都是实测过的闪退面）：
#      Security      —— 自签重打包后 SecItemAdd 返回 errSecMissingEntitlement
#                       (-34018)；宿主原包确实链了 Security，但我们的 dylib
#                       不需要，加进来只会给自己多一层 dyld 初始化风险
#      CFNetwork     —— 本 dylib 不做任何网络
#      CoreGraphics  —— 不需要（图标那套在 src/_license/，不参与构建）
#      QuartzCore    —— ★ v3 已移除：源码根本没用图层 API
#
#    宿主 Core 1.6 自己没有嵌任何 dylib，我们是唯一的注入者，
#    依赖越少 = dyld 阶段越短 = 越不容易在自签环境下出问题。
FRAMEWORKS = -framework Foundation -framework UIKit

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
	@python3 checks/host_parity.py

clean:
	rm -f $(OUT) .slice-*

.PHONY: all clean check
