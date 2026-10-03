# ─────────────────────────────────────────────────────────────
#  CoreOffline —— 授权验证 dylib
#
#  构建（需 macOS + Xcode）：
#     make                        # 默认 arm64e（与原始测试版一致）
#     make ARCHS="arm64"          # 仅 arm64
#     make ARCHS="arm64 arm64e"   # 双切片 fat（自动调 lipo）
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

# 源码清单：dylib 本体 + 主题/图标/桥接/弹窗 + 密钥链 + C 入口
SRC      = src/CoreOffline.m \
           src/COIcon.m \
           src/COLicenseDialog.m \
           src/COVerifyBridge.m \
           src/COKeychain.m \
           src/COEntry.m \
           sdk/T3Verify.m

# 头文件搜索路径
INC      = -Iinclude -Isrc -Isdk

# 链接的框架：
#   Foundation / UIKit  —— 基础
#   CoreGraphics        —— COIcon 手绘矢量图标（CGContext 那套）
#   QuartzCore          —— CABasicAnimation，提交按钮里的转圈动画
#   Security            —— T3 SDK 的 RSA 公钥解密 + Keychain（COKeychain）
#                          + CommonCrypto（CC_SHA256）随它一起进来
#   CFNetwork           —— CFNetworkCopySystemProxySettings（代理/VPN 检测）
#
# ★ CFNetwork 是 F5CloudAuth 有、原测试版没有的 —— 加它是为了风控自检。
#   注意：这两个框架都**不能**在 constructor 早期路径里碰（见 co_ctor.py 的 H 节）。
FRAMEWORKS = -framework Foundation -framework UIKit \
             -framework CoreGraphics -framework QuartzCore \
             -framework Security -framework CFNetwork

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

clean:
	rm -f $(OUT) .slice-*

.PHONY: all clean
