//
//  CoreOffline.m
//  宿主 App 的授权验证 dylib
//
//  职责：
//    1. 有效期下发 —— 宿主问 authorizationValue 时返回卡密校验得到的真实到期时间
//    2. 卡密验证   —— 未授权时弹出验证页，验证通过才放行
//    3. 网络白名单 —— 拦掉宿主对 apple.com 系的校验请求，放行环境资源
//    4. 更新遮罩   —— 吞掉 setDisableUpdateMask:，宿主无法弹更新遮罩
//    5. 心跳       —— 登录后周期校验，连续失败判定掉线
//
//  构建：make（macOS + Xcode），产物 CoreOffline.work.dylib
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <mach-o/dyld.h>
// mach_continuous_time 在这里声明（原来漏了，真机 SDK 上直接 undeclared）。
// mach-o/dyld.h 只给 dyld 那套，不含 mach 时间函数。
#import <mach/mach_time.h>
#import <unistd.h>
#import <fcntl.h>
#import <stdarg.h>
#import <string.h>
#import <stdlib.h>

#import "COTheme.h"
#import "COIcon.h"
#import "COVerifyBridge.h"
#import "COVerifyConfig.h"
#import "COLicenseDialog.h"

#pragma mark - 日志 (对应 record / logFD)

static int gLogFD = -1;

static void CoreLogOpen(void) {
    if (gLogFD >= 0) return;
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/core-offline.log"];
    gLogFD = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (gLogFD < 0) gLogFD = STDERR_FILENO;
}

static void record(const char *fmt, ...) {
    if (gLogFD < 0) CoreLogOpen();
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    strlcat(buf, "\n", sizeof(buf));
    write(gLogFD, buf, strlen(buf));
}

#pragma mark - 全局状态

static uint64_t imageBase   = 0;
static uint64_t credential  = 0;
static uint64_t score       = 0;
static dispatch_source_t stageTimer = NULL;

/// 授权是否已通过。宿主问有效期时先看它。
static BOOL gAuthorized = NO;

/// 验证弹窗持有者 —— 必须强引用，否则一挂到 view 上就被释放了
static COLicenseDialog *gDialog = nil;

/// 宿主根控制器（用来挂弹窗）
static __weak UIViewController *gHostController = nil;

#pragma mark - 导出 API

__attribute__((visibility("default")))
uint64_t CoreOfflineBootstrap(void) {
    record("bootstrap=%llu ready=%llu score=%llu",
           (unsigned long long)credential, 1ULL, (unsigned long long)score);
    record("activate=%llu", (unsigned long long)credential);
    return score;
}

__attribute__((visibility("default")))
uint64_t CoreOfflinePrepare(void) {
    record("startup=%llu", (unsigned long long)mach_continuous_time());
    return 0;
}

__attribute__((visibility("default")))
uint64_t CoreOfflineFinalize(uint64_t offset) {
    uint64_t result = offset ^ credential;
    record("finalize offset=%llx result=%llu",
           (unsigned long long)offset, (unsigned long long)result);
    return result;
}

__attribute__((visibility("default")))
void *CoreRemoteOpen(const char *name, uint64_t options) {
    record("remote.open enter name=%s options=%llu", name ? name : "?", (unsigned long long)options);
    void *handle = NULL;
    unsigned state = 1;
    const char *reason = "ok";
    record("remote.open return=%llx state=%u reason=%s",
           (unsigned long long)(uintptr_t)handle, state, reason);
    return handle;
}

__attribute__((visibility("default")))
uint64_t CoreRemoteFault(uint64_t mode, const char *reason) {
    record("remote.fault mode=%llu reason=%s",
           (unsigned long long)mode, reason ? reason : "?");
    return mode;
}

#pragma mark - 授权有效期 (★ 已接上卡密校验结果)

/// 卡密子系统是否已经启动完毕。
/// 在这个标志翻成 YES 之前，任何路径都不许碰 COVerifyBridge ——
/// 它的 init 会读 NSUserDefaults，在 dyld 阶段是未定义行为。
static volatile BOOL gLicenseSubsystemUp = NO;

/// 宿主问「这机器授权到什么时候」，答案来自卡密验证：
///   · 已通过验证  → COVerifyBridge.cachedExpiry（服务端下发的真实到期时间）
///   · 未通过验证  → COVerifyUnauthorizedExpiry()，一个早得离谱的时间戳
///
/// ★ 不用 nil：宿主拿到 nil 可能直接崩（比如塞进 NSDateFormatter）。
///   给个明确「早就过期」的值，宿主会走它自带的过期流程。
///
/// ★★ 这个函数会被 hook 到宿主的 authorizationValue getter 上。
///    宿主完全可能在 App 启动早期就读它（早于我们的卡密子系统起来），
///    那时候调 [COVerifyBridge shared] 会去碰 NSUserDefaults —— 直接崩。
///    所以：子系统没起来之前，一律回答「未授权」，不做任何 IO。
static NSString *CoreLicenseExpiryString(void) {
    if (!gLicenseSubsystemUp) {
        // 早期路径：一个字都不能多说，也一个字都不能多读。
        return COVerifyUnauthorizedExpiry();
    }

    COVerifyBridge *bridge = [COVerifyBridge shared];
    NSString *expiry = bridge.cachedExpiry;
    if (expiry.length) {
        record("license.expiry=%s", expiry.UTF8String);
        return expiry;
    }
    record("license.expiry=UNAUTHORIZED(no valid license)");
    return COVerifyUnauthorizedExpiry();
}

static id CoreHomeExpiryValue(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return CoreLicenseExpiryString();
}

#pragma mark - 卡密验证弹窗调度

static UIViewController *CoreTopViewController(void) {
    UIWindow *keyWindow = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (![scene isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                if (w.isKeyWindow) { keyWindow = w; break; }
            }
            if (keyWindow) break;
        }
    }
    if (!keyWindow) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        keyWindow = [UIApplication sharedApplication].keyWindow;
#pragma clang diagnostic pop
    }
    if (!keyWindow) return nil;

    UIViewController *vc = keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

/// 需要验证时弹出来。已经弹着就不重复弹。
static void CorePresentLicenseDialog(void) {
    if (gDialog) return;

    // 双保险：这个函数只该在卡密子系统起来之后被调。
    // 万一哪天有人从别处调进来，这里挡住比崩掉强。
    if (!gLicenseSubsystemUp) {
        record("license.dialog BLOCKED (subsystem not up yet)");
        return;
    }

    UIViewController *host = CoreTopViewController();
    if (!host) {
        // 窗口还没就绪，等一拍再来
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            CorePresentLicenseDialog();
        });
        return;
    }

    gHostController = host;

    COLicenseDialog *dlg = [COLicenseDialog dialog];
    dlg.prefilledCard = [COVerifyBridge shared].cachedCard;
    __weak typeof(dlg) weakDlg = dlg;
    dlg.onResult = ^(BOOL ok, NSString *expiry, NSString *stateCode, NSString *message) {
        (void)weakDlg;
        gDialog = nil;
        if (ok) {
            gAuthorized = YES;
            score = credential;
            record("license.granted expiry=%s state=%s", expiry.UTF8String ?: "-", stateCode.UTF8String ?: "-");
            // 放行宿主：发个通知，宿主侧有监听就可以刷新 UI
            [[NSNotificationCenter defaultCenter] postNotificationName:@"CoreOfflineLicenseGranted"
                                                                object:nil];
        } else {
            record("license.denied msg=%s", message.UTF8String ?: "-");
            // 失败不退：留个重试的机会，再弹一次
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                CorePresentLicenseDialog();
            });
        }
    };

    gDialog = dlg;
    [dlg showIn:host];
    record("license.dialog.present");
}

/// 检查授权状态，需要的话弹验证页
static void CoreCheckLicense(void) {
    NSString *expiry = CoreLicenseExpiryString();
    // ★ 用哨兵判断而不是 hasPrefix:@"1970" —— 后者一旦别人改了
    //   COVerifyUnauthorizedExpiry 的年份就会静默失效。
    BOOL valid = !COVerifyIsUnauthorized(expiry);
    if (valid) {
        gAuthorized = YES;
        score = credential;
        record("license.cached.valid expiry=%s", expiry.UTF8String);
        return;
    }
    record("license.required");
    CorePresentLicenseDialog();
}

#pragma mark - CoreHomeLinkTarget

@interface CoreHomeLinkTarget : NSObject
+ (instancetype)sharedTarget;
- (void)openCommunity:(id)sender;
@end

@implementation CoreHomeLinkTarget

+ (instancetype)sharedTarget {
    static CoreHomeLinkTarget *target = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ target = [[self alloc] init]; });
    return target;
}

- (void)openCommunity:(id)sender {
    (void)sender;
    NSURL *url = [NSURL URLWithString:COCommunityURL()];
    if (!url) return;
    UIApplication *app = [UIApplication sharedApplication];
    if ([app respondsToSelector:@selector(openURL:options:completionHandler:)]) {
        [app openURL:url options:@{} completionHandler:nil];
    }
}

@end

#pragma mark - 资源 (hf.png / CoreHomeBanner.work)

static UIImage *CoreHomeBanner(NSString *name, NSBundle *bundle) {
    (void)bundle;
    static UIImage *banner = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *workPath = [[NSBundle mainBundle].bundlePath
                              stringByAppendingPathComponent:@"CoreHomeBanner.work"];
        NSBundle *work = [NSBundle bundleWithPath:workPath];
        NSString *base = name.stringByDeletingPathExtension.length ? name.stringByDeletingPathExtension : name;
        NSString *ext  = name.pathExtension.length ? name.pathExtension : @"png";
        NSString *path = [work pathForResource:base ofType:ext];
        if (path) banner = [UIImage imageWithContentsOfFile:path];
    });
    return banner;
}

#pragma mark - UI Hook

typedef void (*CoreAttachImpl)(id, SEL, UIView *);
typedef void (*CoreRefreshImpl)(id, SEL);

static CoreAttachImpl  CoreHomeOriginalAttach  = NULL;
static CoreRefreshImpl CoreHomeOriginalRefresh = NULL;
static UIView *CoreHomeRoot = nil;

static BOOL CoreHomeMatchesTitle(NSString *title) {
    if (title.length == 0) return NO;
    static NSSet<NSString *> *titles = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        titles = [NSSet setWithArray:@[@"Community", @"社区", @"交流群", @"官方频道"]];
    });
    NSString *clean = [title stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return [titles containsObject:clean];
}

static void CoreHomeRewriteControls(UIView *root) {
    if (![root isKindOfClass:[UIView class]]) return;
    for (UIView *sub in root.subviews) {
        if ([sub isKindOfClass:[UIButton class]]) {
            UIButton *btn = (UIButton *)sub;
            NSString *text = btn.currentTitle
                ?: btn.currentAttributedTitle.string
                ?: btn.titleLabel.text
                ?: btn.accessibilityLabel;
            if (CoreHomeMatchesTitle(text)) {
                [btn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];

                // ★ showsMenuAsPrimaryAction 与 enumerateEventHandlers: 都是 iOS 14+。
                //   原来 showsMenuAsPrimaryAction 落在 @available 块外面 ——
                //   编译不报错（属性赋值），但 iOS 13 设备上会 unrecognized selector 崩。
                //   两个都收进同一个版本判断里。
                if (@available(iOS 14.0, *)) {
                    // 真实签名是 5 个参数：
                    //   (UIAction *, id element, SEL, UIControlEvents, BOOL *stop)
                    // 之前写成 3 个（UIAction/元素/stop），真机上 block 类型不匹配编不过。
                    [btn enumerateEventHandlers:^(UIAction *action,
                                                  id element,
                                                  SEL selector,
                                                  UIControlEvents events,
                                                  BOOL *stop) {
                        (void)element; (void)selector; (void)events; (void)stop;
                        [btn removeAction:action forControlEvents:UIControlEventTouchUpInside];
                    }];
                    btn.showsMenuAsPrimaryAction = NO;
                }

                [btn addTarget:[CoreHomeLinkTarget sharedTarget]
                        action:@selector(openCommunity:)
              forControlEvents:UIControlEventTouchUpInside];
            }
        }
        CoreHomeRewriteControls(sub);
    }
}

static void CoreHomeAttach(id self, SEL _cmd, UIView *root) {
    if (CoreHomeOriginalAttach) CoreHomeOriginalAttach(self, _cmd, root);
    CoreHomeRoot = root;
    dispatch_async(dispatch_get_main_queue(), ^{
        CoreHomeRewriteControls(root);
    });
}

static void CoreHomeRefresh(id self, SEL _cmd) {
    if (CoreHomeOriginalRefresh) CoreHomeOriginalRefresh(self, _cmd);
    dispatch_async(dispatch_get_main_queue(), ^{
        CoreHomeRewriteControls(CoreHomeRoot);
    });
}

#pragma mark - 图片 Hook

typedef id (*CoreImageNamedImpl)(id, SEL, NSString *);
typedef id (*CoreImageInBundleImpl)(id, SEL, NSString *, NSBundle *, UITraitCollection *);

static CoreImageNamedImpl    CoreHomeOriginalImageNamed    = NULL;
static CoreImageInBundleImpl CoreHomeOriginalImageInBundle = NULL;

static id CoreHomeImageNamed(id self, SEL _cmd, NSString *name) {
    id img = CoreHomeOriginalImageNamed ? CoreHomeOriginalImageNamed(self, _cmd, name) : nil;
    if (!img && [name hasPrefix:@"hf"]) img = CoreHomeBanner(name, nil);
    return img;
}

static id CoreHomeImageInBundle(id self, SEL _cmd, NSString *name, NSBundle *bundle, UITraitCollection *traits) {
    id img = CoreHomeOriginalImageInBundle ? CoreHomeOriginalImageInBundle(self, _cmd, name, bundle, traits) : nil;
    if (!img && [name hasPrefix:@"hf"]) img = CoreHomeBanner(name, bundle);
    return img;
}

#pragma mark - 更新遮罩拦截 (setDisableUpdateMask:)

typedef void (*MaskImpl)(id, SEL, id);
static MaskImpl maskOriginal = NULL;

static void maskHook(id self, SEL _cmd, id mask) {
    record("setDisableUpdateMask:");
    // 吞掉调用: 不转发给原实现, 宿主无法弹出更新遮罩
    (void)self; (void)_cmd; (void)mask;
}

static void CoreInstallMaskHooks(void) {
    unsigned count = 0;
    // ★ ARC 下 objc_copyClassList 返回的 Class * 必须标 __unsafe_unretained，
    //   否则编译器会当成「强引用指针数组」—— 但这些是运行时裸指针，
    //   由 free() 释放，不归 ARC 管。
    __unsafe_unretained Class *classes = (__unsafe_unretained Class *)objc_copyClassList(&count);
    if (!classes) return;
    for (unsigned i = 0; i < count; i++) {
        Class cls = classes[i];
        if (!cls) continue;
        const char *image = class_getImageName(cls);
        if (!image || !strstr(image, ".app/")) continue;   // 只处理宿主 App 内的类
        Method m = class_getInstanceMethod(cls, NSSelectorFromString(@"setDisableUpdateMask:"));
        if (!m) continue;
        maskOriginal = (MaskImpl)method_getImplementation(m);
        method_setImplementation(m, (IMP)maskHook);
        record("mask.hook class=%s", class_getName(cls));
    }
    free(classes);
}

#pragma mark - 网络拦截 (NSURLSessionTask resume)

static NSSet<NSString *> *CoreBlockedHosts(void) {
    static NSSet<NSString *> *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [NSSet setWithArray:@[@".apple.com", @"apple.com",
                                  @".cdn-apple.com", @"cdn-apple.com"]];
    });
    return s;
}

static BOOL CoreBlockNetworkURL(NSURL *url) {
    if (!url) return NO;
    NSString *host = url.host.lowercaseString;
    if (host.length == 0) return NO;
    for (NSString *h in CoreBlockedHosts()) {
        if ([host hasSuffix:h]) return YES;
        NSString *bare = [h hasPrefix:@"."] ? [h substringFromIndex:1] : h;
        if ([host isEqualToString:bare]) return YES;
    }
    return NO;
}

static BOOL CoreEnvironmentResource(NSURL *url) {
    if (!url) return NO;
    NSString *host = url.host.lowercaseString;
    NSString *path = url.path ?: @"";
    if ([host isEqualToString:@"api.appledb.dev"]) return YES;
    if ([host isEqualToString:@"fastly.jsdelivr.net"] &&
        [path hasPrefix:@"/gh/littlebyteorg/appledb@gh-pages/ios/"]) return YES;
    return NO;
}

typedef void (*ResumeImpl)(id, SEL);
static ResumeImpl CoreHomeOriginalResume = NULL;
static unsigned resumeInterceptors = 0;

static void CoreTaskResume(id self, SEL _cmd) {
    NSURLSessionTask *task = (NSURLSessionTask *)self;
    NSURLRequest *req = task.originalRequest ?: task.currentRequest;
    NSURL *url = req.URL;

    if (CoreEnvironmentResource(url)) {
        record("network.environment.allow host=%s path=%s",
               url.host.UTF8String ?: "?", url.path.UTF8String ?: "");
    } else if (CoreBlockNetworkURL(url)) {
        resumeInterceptors++;
        record("network.cancel host=%s", url.host.UTF8String ?: "?");
        return;   // 吞掉, 不发起请求
    }

    if (CoreHomeOriginalResume) CoreHomeOriginalResume(self, _cmd);
    record("network.resume.interceptors=%u", resumeInterceptors);
}

static void cancelNetworkTasks(void) {
    // 保留原符号结构: 超时诊断后调用
    record("network.cancel.pending interceptors=%u", resumeInterceptors);
}

#pragma mark - Hook 安装 (CoreHomeUIInstall)

static void CoreHomeUIInstall(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // 宿主控制器
        Class cls = NSClassFromString(@"OKDHomeMusicController");
        if (cls) {
            Method m = NULL;
            if ((m = class_getInstanceMethod(cls, NSSelectorFromString(@"attachToRootView:")))) {
                CoreHomeOriginalAttach = (CoreAttachImpl)method_getImplementation(m);
                method_setImplementation(m, (IMP)CoreHomeAttach);
            }
            if ((m = class_getInstanceMethod(cls, NSSelectorFromString(@"refreshHomeLayoutArtwork")))) {
                CoreHomeOriginalRefresh = (CoreRefreshImpl)method_getImplementation(m);
                method_setImplementation(m, (IMP)CoreHomeRefresh);
            }
            // 授权有效期: 替换返回值
            if ((m = class_getInstanceMethod(cls, NSSelectorFromString(@"authorizationValue")))) {
                method_setImplementation(m, (IMP)CoreHomeExpiryValue);
            }
        }

        // 图片资源
        Class imageClass = object_getClass([UIImage class]);
        Method m2 = NULL;
        if ((m2 = class_getClassMethod(imageClass, @selector(imageNamed:)))) {
            CoreHomeOriginalImageNamed = (CoreImageNamedImpl)method_getImplementation(m2);
            method_setImplementation(m2, (IMP)CoreHomeImageNamed);
        }
        if ((m2 = class_getClassMethod(imageClass, @selector(imageNamed:inBundle:compatibleWithTraitCollection:)))) {
            CoreHomeOriginalImageInBundle = (CoreImageInBundleImpl)method_getImplementation(m2);
            method_setImplementation(m2, (IMP)CoreHomeImageInBundle);
        }

        // 网络请求
        Method m3 = class_getInstanceMethod([NSURLSessionTask class], @selector(resume));
        if (m3) {
            CoreHomeOriginalResume = (ResumeImpl)method_getImplementation(m3);
            method_setImplementation(m3, (IMP)CoreTaskResume);
        }

        // 更新遮罩
        CoreInstallMaskHooks();
    });
}

#pragma mark - 后台监视 (monitorBackend)

static BOOL gCancelled = NO;

static void monitorBackend(void) {
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    stageTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(stageTimer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                              (uint64_t)(1.0 * NSEC_PER_SEC), (uint64_t)(0.1 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(stageTimer, ^{
        static unsigned ticks = 0;
        ticks++;
        record("backend stage=%.48s lane=%.24s state=%u ready=%u result=%d running=%u cancel=%u pass=%u base=%llx score=%llu",
               "offline", "main", 1u, 1u, 0, 1u, gCancelled ? 1u : 0u, 1u,
               (unsigned long long)imageBase, (unsigned long long)score);
        record("overlay enabled=%u capability=%u quarantine=%u hosted=%u registering=%u step=%u remote=%u reason=%.120s pending=%.120s ids=%u/%u,%u/%u,%u/%u",
               1u, 1u, 0u, 1u, 0u, (unsigned)ticks, 0u, "-", "-", 0u, 0u, 0u, 0u, 0u, 0u);
        if (ticks >= 8 && !gCancelled) {
            gCancelled = YES;
            record("backend diagnostic timeout: requesting original cancellation");
            cancelNetworkTasks();
        }
    });
    dispatch_resume(stageTimer);
}

#pragma mark - 构造函数

//
// ★★ 这里是整条链上最容易崩的地方，规矩只有一条：
//    constructor 里绝不做任何依赖「App 已启动」的事。
//
//    所有现有的 CoreOffline 逻辑（UI hook / 网络 hook / 凭据链）都是
//    纯 Mach-O + objc runtime 层面的操作，在 dyld 阶段就是安全的 ——
//    原始版证明了这一点。
//
//    但卡密模块不一样，它有四个「早期不安全」的依赖：
//      1. NSUserDefaults   —— _CFXPreferences 子系统可能还没建，
//                             早期访问会直接崩（iOS 开发经典陷阱）
//      2. Security.framework —— T3RSACrypto 解析 RSA 公钥走 SecKeyCreateWithData，
//                               早期调用会拿到未初始化的 CSP
//      3. NSDateFormatter / NSLocale —— 需要 ICU + locale 数据就绪
//      4. NSTimer          —— 需要 runloop 已经在跑
//
//    所以：constructor 只做「零依赖」的准备工作，
//         卡密侧一律延后到 App 启动完成之后（见 CoreStartLicenseSubsystem）。
//

/// 卡密子系统的启动：必须等主 runloop 跑起来之后再调。
/// 单独抽出来是为了让 constructor 保持「一眼能看完」的长度。
static void CoreStartLicenseSubsystem(void) {
    // 到了这里 NSUserDefaults / Security / locale 都齐了，
    // shared 单例可以安全地建。
    COVerifyBridge *bridge = [COVerifyBridge shared];

    // 心跳掉线 → 收回授权并拉回验证页
    bridge.onHeartbeatLost = ^{
        record("heartbeat.lost → present license dialog");
        gAuthorized = NO;
        CorePresentLicenseDialog();
    };

    // ★ 置位必须在 shared 建好之后、CoreCheckLicense 之前 ——
    //   CoreCheckLicense 会走 CoreLicenseExpiryString，
    //   而那个函数靠这个标志决定「能不能读缓存」。
    gLicenseSubsystemUp = YES;

    record("license.subsystem.start sdk=%d", (int)bridge.available);
    CoreCheckLicense();
}

/// 等宿主 App 启动到「有窗口」为止，然后交给 CoreStartLicenseSubsystem。
/// 用轮询而不是写死延时：宿主启动快慢差很多，写死 0.6s 在慢机器上会
/// 挂在 nil 窗口上，在快机器上又是白等。
static void CoreWaitForHostReady(NSInteger attemptsLeft) {
    UIViewController *host = CoreTopViewController();
    if (host) {
        record("host.ready after %ld retries", (long)(40 - attemptsLeft));
        CoreStartLicenseSubsystem();
        return;
    }
    if (attemptsLeft <= 0) {
        // 兜底：实在等不到窗口（比如宿主根本没有 UI），
        // 也把子系统跑起来，让缓存/心跳生效，只是弹不出窗。
        record("host.ready TIMEOUT, start subsystem anyway");
        CoreStartLicenseSubsystem();
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        CoreWaitForHostReady(attemptsLeft - 1);
    });
}

__attribute__((constructor))
static void initializeOffline(void) {
    @autoreleasepool {
        // ── 第 1 段：零依赖准备（dyld 阶段安全）──
        //
        // CoreLogOpen 走 NSHomeDirectory + open(2)，原始版就是这么干的，
        // 实测在 constructor 阶段可用。
        CoreLogOpen();
        record("constructor pid=%d base=%llx", getpid(),
               (unsigned long long)(uintptr_t)_dyld_get_image_header(0));

        // 凭据链 (对应 derive/material/lease/credential 日志)
        // arc4random_buf / mach_continuous_time 都是纯系统调用，无依赖。
        uint64_t material = 0, derive = 0;
        arc4random_buf(&material, sizeof(material));
        uint64_t lease = material ^ (uint64_t)mach_continuous_time();
        derive = lease & 0xFFFFFFFFFFFFULL;
        credential = derive;
        record("derive=%llu", (unsigned long long)derive);
        record("material=%llu", (unsigned long long)material);
        record("lease=%llu", (unsigned long long)lease);
        record("credential=%llu", (unsigned long long)credential);

        // 定位宿主镜像
        uint32_t count = _dyld_image_count();
        for (uint32_t i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, ".app/")) {
                imageBase = (uint64_t)(uintptr_t)_dyld_get_image_header(i);
                break;
            }
        }

        // ── 第 2 段：CoreOffline 本体（与原始版行为一致）──
        CoreHomeUIInstall();
        monitorBackend();
        CoreOfflinePrepare();
        CoreOfflineBootstrap();

        // ── 第 3 段：卡密子系统 —— 只调度，不执行 ──
        //
        // ★ 这里绝不能直接调 [COVerifyBridge shared]：
        //   那会在 dyld 阶段拉起 NSUserDefaults + Security，必崩。
        //   用 dispatch_async 把整个启动过程推到主队列，
        //   此时 App 的 runloop 已经在转，所有子系统都就绪。
        dispatch_async(dispatch_get_main_queue(), ^{
            CoreWaitForHostReady(40);   // 最多等 10s
        });
    }
}
