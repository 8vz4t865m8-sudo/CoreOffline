# ─────────────────────────────────────────────────────────────
#  CoreOffline —— 授权验证 dylib
#
#  构建（需 macOS + Xcode）：
#     make                # 默认 arm64
#     make ARCHS="arm64 arm64e"
#     make clean
#
#  产物：CoreOffline.work.dylib
#  注入要点：install name 必须是 @executable_path/CoreOffline.work.dylib，
#           这样 insert_dylib 插进宿主后能被 dyld 正确解析。
# ─────────────────────────────────────────────────────────────

SDK      ?= iphoneos
ARCHS    ?= arm64            # 原文件是 arm64e(PAC); 如确有需要可改成 "arm64 arm64e"
MINIOS   ?= 13.0
CC        = xcrun -sdk $(SDK) clang

OUT      = CoreOffline.work.dylib

# 源码清单：dylib 本体 + 主题/图标/桥接/弹窗
SRC      = src/CoreOffline.m \
           src/COIcon.m \
           src/COLicenseDialog.m \
           src/COVerifyBridge.m \
           sdk/T3Verify.m

# 头文件搜索路径
INC      = -Iinclude -Isrc -Isdk

# T3 SDK 用到 CommonCrypto(md5) 与 Security(RSA)
FRAMEWORKS = -framework Foundation -framework UIKit \
             -framework Security -framework CoreGraphics

CFLAGS   = -dynamiclib -fobjc-arc -O2 -Wall -Wno-unused-variable \
           $(foreach a,$(ARCHS),-arch $(a)) \
           -miphoneos-version-min=$(MINIOS) \
           $(INC) \
           -Wl,-install_name,@executable_path/$(OUT)

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(FRAMEWORKS) -o $@ $(SRC)
	@echo "── built $(OUT)"
	@ls -l $(OUT)

clean:
	rm -f $(OUT)

.PHONY: all clean
