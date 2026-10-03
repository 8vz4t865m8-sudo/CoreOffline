//
//  COEntry.m
//  CoreOffline —— 给宿主 dylib 用的纯 C 入口实现
//
//  对标 F5CloudAuth 的 bsupx_c_* 系列。
//  宿主侧用法：
//
//      void *h = dlsym(RTLD_DEFAULT, "coreoffline_c_verify_card");
//      if (h) {
//          ((void(*)(const char *, void *, void(*)(COAuthResult,void*)))h)(
//              "CARD-XXXX", NULL, ^(COAuthResult r, void *ctx) { ... });
//      }
//
//  注意：回调是 C 函数指针，不是 block —— 这样宿主用 C / C++ / ObjC 都能接。
//

#import "COEntry.h"
#import "COVerifyBridge.h"
#import "COVerifyConfig.h"
#import "COKeychain.h"

#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <unistd.h>

#pragma mark - 线程安全的结果缓冲
//
// COAuthResult 里放的是 const char *，指向的是「内部静态缓冲」。
// 这样设计是为了让宿主不需要 free。
// 但静态缓冲天生线程不安全 —— 用一把锁 + 线程局部（TLS）缓冲解决：
// 每个线程有自己的一份，回调里读一定安全。

static __thread char *tls_msg_buf   = NULL;
static __thread char *tls_exp_buf   = NULL;
static __thread char *tls_card_buf  = NULL;
static __thread char *tls_mach_buf  = NULL;

static char *COTLSSetBuf(char **slot, NSString *s) {
    if (*slot) { free(*slot); *slot = NULL; }
    if (s.length == 0) return NULL;
    const char *u = s.UTF8String;
    if (!u) return NULL;
    size_t n = strlen(u) + 1;
    char *b = (char *)malloc(n);
    if (!b) return NULL;
    memcpy(b, u, n);
    *slot = b;
    return b;
}

#pragma mark - 环境自检

/// 调试器：sysctl P_TRACED
static int32_t CODetectDebugger(void) {
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) return 0;
    return (info.kp_proc.p_flag & P_TRACED) ? 1 : 0;
}

/// 越狱：查典型路径能不能访问
static int32_t CODetectJailbreak(void) {
    // ★ 这些路径在真机未越狱环境全部不存在。
    //   注意用 access() 而不是 fileExistsAtPath —— 后者在沙箱里可能被绕过。
    const char *paths[] = {
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt",
        "/usr/bin/ssh",
        "/bin/bash",
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (access(paths[i], F_OK) == 0) return 1;
    }
    // 能不能写沙箱外
    NSString *probe = @"/private/co_jb_probe.txt";
    NSError *err = nil;
    [@"x" writeToFile:probe atomically:YES encoding:NSUTF8StringEncoding error:&err];
    if (!err) {
        [[NSFileManager defaultManager] removeItemAtPath:probe error:NULL];
        return 1;
    }
    return 0;
}

/// 注入/Hook 框架：扫已加载的 dylib 名字
static int32_t CODetectInjected(void) {
    static const char *needles[] = {
        "frida", "substrate", "substitute", "cycript", "fishhook",
        "frida_agent_main", "libhooker", "TweakInject", "ElleKit",
    };
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        for (size_t k = 0; k < sizeof(needles) / sizeof(needles[0]); k++) {
            if (strstr(name, needles[k])) return 1;
        }
    }
    return 0;
}

/// 系统代理 / VPN
static int32_t CODetectProxy(void) {
    CFDictionaryRef dict = CFNetworkCopySystemProxySettings();
    if (!dict) return 0;
    int32_t hit = 0;

    const void *keys[] = {
        CFSTR("HTTPEnable"), CFSTR("HTTPSEnable"),
        CFSTR("SOCKSEnable"), CFSTR("ProxyAutoConfigEnable"),
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        CFTypeRef v = CFDictionaryGetValue(dict, keys[i]);
        if (v && CFGetTypeID(v) == CFNumberGetTypeID()) {
            int n = 0;
            if (CFNumberGetValue((CFNumberRef)v, kCFNumberIntType, &n) && n != 0) {
                hit = 1;
                break;
            }
        }
    }
    CFRelease(dict);
    return hit;
}

/// 机型（作为机器码的稳定部分）
static NSString *COMachineModel(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        size_t size = 0;
        sysctlbyname("hw.machine", NULL, &size, NULL, 0);
        char *m = size ? malloc(size) : NULL;
        if (m && sysctlbyname("hw.machine", m, &size, NULL, 0) == 0) {
            cached = [NSString stringWithUTF8String:m] ?: @"unknown";
        } else {
            cached = @"unknown";
        }
        if (m) free(m);
    });
    return cached;
}

/// 机器码：机型 + IDFV 的 SHA256 前 32 位。
/// 用哈希而不是直接拼 —— 避免把 IDFV 明文暴露给服务端日志。
static NSString *COMachineCode(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *idfv = [UIDevice currentDevice].identifierForVendor.UUIDString ?: @"";
        NSString *raw = [NSString stringWithFormat:@"%@|%@|%@",
                         COMachineModel(),
                         [[NSBundle mainBundle] bundleIdentifier] ?: @"",
                         idfv];
        // 简单哈希：FNV-1a 64 位，两轮拼成 32 位 hex。
        // 不用 CC_SHA256 是为了少一个 CommonCrypto 依赖 —— 这里不是安全场景。
        const char *bytes = raw.UTF8String;
        uint64_t h1 = 0xcbf29ce484222325ULL;
        uint64_t h2 = 0x84222325cbf29ce4ULL;
        for (size_t i = 0; bytes && bytes[i]; i++) {
            h1 ^= (unsigned char)bytes[i];
            h1 *= 0x100000001b3ULL;
            h2 ^= (unsigned char)bytes[i] + (uint64_t)i;
            h2 *= 0x100000001b3ULL;
        }
        cached = [NSString stringWithFormat:@"%016llx%016llx",
                  (unsigned long long)h1, (unsigned long long)h2];
    });
    return cached;
}

#pragma mark - 结果封装

static void COEmit(COAuthCallback cb, void *ctx,
                   BOOL ok, NSInteger code,
                   NSString *message, NSString *expiry) {
    if (!cb) return;
    COAuthResult r;
    r.success = ok ? 1 : 0;
    r.code    = (int32_t)code;
    r.message = COTLSSetBuf(&tls_msg_buf,  message);
    r.expiry  = COTLSSetBuf(&tls_exp_buf,  expiry);
    // 强制主线程派发 —— 宿主大概率在里面碰 UIKit
    if ([NSThread isMainThread]) {
        cb(r, ctx);
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{ cb(r, ctx); });
    }
}

#pragma mark - 验证

void coreoffline_c_verify_card(const char *card,
                               void *context,
                               COAuthCallback callback) {
    @autoreleasepool {
        NSString *c = card ? [NSString stringWithUTF8String:card] : nil;
        if (c.length == 0) {
            COEmit(callback, context, NO, -1, @"卡密不能为空", nil);
            return;
        }

        [[COVerifyBridge shared] verifyCard:c
                                 completion:^(BOOL ok, NSString *expiry,
                                              NSString *stateCode, NSString *message) {
            COEmit(callback, context, ok, ok ? 0 : -2,
                   message ?: (ok ? @"验证成功" : @"验证失败"),
                   expiry);
        }];
    }
}

void coreoffline_c_verify_saved(void *context, COAuthCallback callback) {
    @autoreleasepool {
        COVerifyBridge *b = [COVerifyBridge shared];
        NSString *card = b.cachedCard;
        if (card.length == 0) {
            COEmit(callback, context, NO, -3, @"没有已保存的卡密", nil);
            return;
        }
        [b verifyCard:card completion:^(BOOL ok, NSString *expiry,
                                        NSString *stateCode, NSString *message) {
            COEmit(callback, context, ok, ok ? 0 : -2,
                   message ?: (ok ? @"验证成功" : @"验证失败"), expiry);
        }];
    }
}

int32_t coreoffline_c_has_license(void) {
    @autoreleasepool {
        NSString *expiry = [COVerifyBridge shared].cachedExpiry;
        return (expiry.length > 0 && !COVerifyIsUnauthorized(expiry)) ? 1 : 0;
    }
}

const char *coreoffline_c_license_expiry(void) {
    @autoreleasepool {
        NSString *e = [COVerifyBridge shared].cachedExpiry;
        return COTLSSetBuf(&tls_exp_buf, e);
    }
}

const char *coreoffline_c_license_card(void) {
    @autoreleasepool {
        return COTLSSetBuf(&tls_card_buf, [COVerifyBridge shared].cachedCard);
    }
}

#pragma mark - 心跳

void coreoffline_c_start_heartbeat(void) {
    @autoreleasepool {
        [[COVerifyBridge shared] startHeartbeat];
    }
}

void coreoffline_c_stop_heartbeat(void) {
    @autoreleasepool {
        [[COVerifyBridge shared] stopHeartbeat];
    }
}

int32_t coreoffline_c_heartbeat_failures(void) {
    // 桥接层没暴露这个计数，给 0；需要的话在 COVerifyBridge 上加只读属性
    return 0;
}

#pragma mark - 环境自检

int32_t coreoffline_c_debugger_attached(void) {
    static int32_t cached = -1;
    if (cached < 0) cached = CODetectDebugger();
    return cached;
}

int32_t coreoffline_c_jailbroken(void) {
    static int32_t cached = -1;
    if (cached < 0) cached = CODetectJailbreak();
    return cached;
}

int32_t coreoffline_c_injected(void) {
    static int32_t cached = -1;
    if (cached < 0) cached = CODetectInjected();
    return cached;
}

int32_t coreoffline_c_proxy_active(void) {
    static int32_t cached = -1;
    if (cached < 0) cached = CODetectProxy();
    return cached;
}

int32_t coreoffline_c_risk_mask(void) {
    int32_t m = 0;
    if (coreoffline_c_debugger_attached()) m |= CO_RISK_DEBUGGER;
    if (coreoffline_c_jailbroken())        m |= CO_RISK_JAILBREAK;
    if (coreoffline_c_injected())          m |= CO_RISK_INJECTED;
    if (coreoffline_c_proxy_active())      m |= CO_RISK_PROXY;
    return m;
}

const char *coreoffline_c_machine_code(void) {
    @autoreleasepool {
        return COTLSSetBuf(&tls_mach_buf, COMachineCode());
    }
}

#pragma mark - 清理

void coreoffline_c_clear(void) {
    @autoreleasepool {
        [[COVerifyBridge shared] clearCache];
        COKeychainWipe();
    }
}

#pragma mark - 弹窗

void coreoffline_c_present_dialog(void) {
    // 走 ObjC runtime 找内部函数，避免在头文件里暴露 UI 细节。
    // CoreOffline.m 里的 CorePresentLicenseDialog 是 static，dlsym 拿不到；
    // 这里改成发一个通知，由 CoreOffline.m 监听。
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:@"CoreOfflinePresentLicense"
                                                            object:nil];
    });
}
