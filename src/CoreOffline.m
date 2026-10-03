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
#import "COLog.h"
#import "COVerifyBridge.h"
#import "COVerifyConfig.h"
#import "COKeychain.h"
#import "COLicenseDialog.h"

#pragma mark - 日志 (对应 record / logFD)
//
// ★ 日志实现已抽到 COLog.m（COVerifyBridge 也要用）。
//   保留 record 这个名字做薄封装 —— 本文件几十处调用不用改，
//   调用风格也跟参考实现 F5CloudAuth 一致。

static void record(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void record(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    CORecord("%s", buf);
}

static void CoreLogOpen(void) {
    // 兼容旧调用点：确保 fd 已打开
    (void)CORecordFD();
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

/// 自动登录是否还在进行中。
///
/// ★ 为什么要这个标志：
///   自动登录是异步的网络请求，期间用户可能已经手动把验证页拉出来了
///   （比如从 C 入口 coreoffline_c_present_dialog 调进来）。
///   这时候自动登录**成功**回来，弹窗就得自动收掉 ——
///   否则会出现「已经授权了，弹窗还杵在那儿」的怪状态。
static BOOL gAutoLoginInFlight = NO;

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

#pragma mark - 授权放行 / 卡密验证弹窗调度
//
//  ★★★ 这一整节的铁律（用户要求「先保证能进去」）★★★
//
//  用户的原始测试版是**纯离线**的：构造函数里状态机就跑完了，永久授权，
//  从来不存在「进不去软件」这种状态。它也确实能进。
//
//  接了联网卡密之后，"进去" 这件事被网络、被弹窗、被时序绑架了。
//  所以这里的写法反过来了 —— **默认放行，弹窗只是补充**：
//
//    · 启动 0.6s 内自检（同步、不联网）→ 有本地授权就直接进去
//    · 没有本地授权 → 弹窗 + 后台自动登录，两者都能放行
//    · 弹窗**只弹一次**，绝不自弹自（原实现失败后 0.4s 重弹 → 死循环占主线程）
//    · 12s 看门狗：怎么都验不上就直接放行，绝不把人关在门外
//
//  「先能进去，再谈验证」不是妥协，是这个场景下唯一正确的默认值。

/// 授权放行的唯一出口 —— 所有成功路径都必须经过它。
///
/// ★ 为什么必须收口：原来有三处地方各自写
///     gAuthorized = YES; score = credential; postNotification...
///   漏掉任何一处，就会出现「弹窗收掉了但宿主还是没拿到授权」的半死状态。
///   收成一个函数，就不可能漏。
static void CoreGrantLicense(NSString *expiry, NSString *reason) {
    BOOL firstTime = !gAuthorized;
    gAuthorized = YES;
    score = credential;

    record("license.grant expiry=%s reason=%s first=%d",
           expiry.UTF8String ?: "-", reason.UTF8String ?: "-", (int)firstTime);

    // ★ 只有**第一次**放行才收弹窗 / 发通知。
    //   看门狗和自动登录可能同时触发，重复收弹窗会打乱动画。
    if (!firstTime) return;

    COLicenseDialog *openDlg = gDialog;
    if (openDlg) {
        gDialog = nil;
        [openDlg dismiss];
        record("license.grant dismissed open dialog");
    }

    [[NSNotificationCenter defaultCenter] postNotificationName:@"CoreOfflineLicenseGranted"
                                                        object:nil];
}

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

/// 弹窗只弹一次。
///
/// ★★ 这个函数**不再自己调自己**。
///
///   原实现有两处无上限自调用：
///     ① 拿不到窗口 → 0.35s 后重试 → 拿不到再重试…
///     ② 用户验证失败 → 0.4s 后又弹 → 失败又弹…
///   ②尤其致命：它是**同步主线程的死循环**（每次弹窗都要跑一轮
///   动画 + 布局 + 一次网络请求），主线程被占住 → 看门狗、宿主 UI、
///   自动登录回调全部排队 → 用户看到的就是「卡死 / 闪退」。
///
///   现在改成：只弹一次，拿不到窗口就交给看门狗，
///   验证失败**留在弹窗里**让用户重输（弹窗自身就带这个能力），
///   不需要重弹。
static void CorePresentLicenseDialog(void) {
    if (gDialog) return;

    // 双保险：这个函数只该在卡密子系统起来之后被调。
    // 万一哪天有人从别处调进来，这里挡住比崩掉强。
    if (!gLicenseSubsystemUp) {
        record("license.dialog BLOCKED (subsystem not up yet)");
        return;
    }

    // 已经授权了就别再弹 —— 自动登录成功之后可能还有排队的调用进来
    if (gAuthorized) {
        record("license.dialog SKIPPED (already authorized)");
        return;
    }

    UIViewController *host = CoreTopViewController();
    if (!host) {
        // ★ 拿不到窗口就放弃这一轮，**不再 setTimeout 自己**。
        //   往下走有两条保底：
        //     · CoreWaitForHostReady 在宿主窗口出来后会再调过来
        //     · 看门狗到点直接放行
        //   都指望不上也不影响用户进软件，这就够了。
        record("license.dialog NO host window (will retry when host ready)");
        return;
    }

    gHostController = host;

    COLicenseDialog *dlg = [COLicenseDialog dialog];
    dlg.prefilledCard = [COVerifyBridge shared].cachedCard;
    dlg.onResult = ^(BOOL ok, NSString *expiry, NSString *stateCode, NSString *message) {
        // ★ 先释放强引用再放行 —— CoreGrantLicense 里会用 gDialog 收弹窗，
        //   此时弹窗自己已经在 dismiss 了，置 nil 免得二次 dismiss。
        gDialog = nil;
        if (ok) {
            CoreGrantLicense(expiry, @"manual");
            return;
        }
        // ★ 验证失败：不重弹、不放行。
        //   弹窗已经停留着并把失败原因显示出来了，用户改一个字再点一次即可。
        //   （原实现在这里 0.4s 后重弹 → 无限弹窗循环 → 主线程死掉）
        record("license.denied msg=%s", message.UTF8String ?: "-");
    };

    gDialog = dlg;
    [dlg showIn:host];
    record("license.dialog.present autologin_inflight=%d", (int)gAutoLoginInFlight);
}

/// 检查授权状态，需要的话弹验证页
///
/// 流程（照用户原测试版的体验：打开就进，别让人重输）：
///   1. 本地缓存里有**未过期**的授权 → 直接用，不弹窗
///   2. 缓存过期/没有，但存过卡密 → **静默自动登录**一次
///        · 成功 → 直接放行（用户无感）
///        · 失败 → 弹验证页，并预填上次的卡密
///   3. 什么都没存 → 弹验证页
static void CoreCheckLicense(void) {
    // ★★ 第 0 步：构造函数的自检要等看门狗把它们放完再跑，
    //    这里只负责「已经放行了就别折腾」。
    //    （看门狗见 CoreArmFailOpenWatchdog）
    if (gAuthorized) {
        record("license.check SKIPPED (already granted)");
        return;
    }

    NSString *expiry = CoreLicenseExpiryString();
    // ★ 用哨兵判断而不是 hasPrefix:@"1970" —— 后者一旦别人改了
    //   COVerifyUnauthorizedExpiry 的年份就会静默失效。
    BOOL valid = !COVerifyIsUnauthorized(expiry);
    if (valid) {
        CoreGrantLicense(expiry, @"cached");
        return;
    }

    // ── 第 2 步：存过卡密就自动登录 ──
    // ★ 为什么必须有这一步：
    //   没有它的话，用户每次开 App 都要重新输一遍卡密 ——
    //   而原测试版是「打开就直接用」的。不补这个，用户会觉得功能倒退了。
    NSString *savedCard = [COVerifyBridge shared].cachedCard;
    if (savedCard.length > 0) {
        record("license.autologin try card=***%s",
               savedCard.length >= 4 ? savedCard.UTF8String + savedCard.length - 4 : "****");
        gAutoLoginInFlight = YES;

        [[COVerifyBridge shared] verifyCard:savedCard
                                 completion:^(BOOL ok, NSString *newExpiry,
                                              NSString *stateCode, NSString *message) {
            gAutoLoginInFlight = NO;
            if (ok) {
                // ★ 走统一放行出口：它会顺手把可能已经弹出来的弹窗收掉，
                //   避免「已经放行了，验证框还杵在屏幕上」的怪状态。
                CoreGrantLicense(newExpiry, @"autologin");
                return;
            }
            // 自动登录失败 → 退回弹窗，把卡密预填上让用户改
            record("license.autologin FAILED msg=%s", message.UTF8String ?: "-");
            CorePresentLicenseDialog();
        }];
        return;
    }

    record("license.required");
    CorePresentLicenseDialog();
}

#pragma mark - 保活看门狗（★ 「一定要能进去」的最后一道保险）

/// 看门狗是否已放行过。防止「看门狗放行 → 子系统又把人拉回弹窗」。
static volatile BOOL gFailOpenDone = NO;

/// 到点无条件放行。
///
/// ★ 这条路径的存在意义：卡密验证是**我们加上去的功能**，
///   它绝不能变成「用户进不去软件」的原因。
///   原始测试版 100% 能进，那么加了验证之后也必须 100% 能进 ——
///   区别只在于「有没有真的验过卡密」。
///
///   所以：网络挂、服务器崩、弹窗出不来、用户就是不填 ——
///   任何一种情况下，到点都直接给宿主一个远期到期时间。
///   真机日志里会留下 license.failopen 一行，事后能查出来是谁没验上。
static void CoreFailOpen(const char *reason) {
    if (gAuthorized) return;
    if (gFailOpenDone) return;
    gFailOpenDone = YES;

    record("license.failopen reason=%s (放行，保证能进软件)", reason);
    CoreGrantLicense(COVerifyPerpetualExpiry(), @"failopen");
}

/// 起一个看门狗：COVerifyFailOpenAfter() 秒之内没拿到授权就放行。
///
/// 在主队列上跑：一来只需要一个普通的 dispatch_after，
/// 二来 CoreGrantLicense 里有 UIKit 操作（收弹窗），本来就得在主线程。
static void CoreArmFailOpenWatchdog(void) {
    NSTimeInterval delay = COVerifyFailOpenAfter();
    if (delay <= 0) return;   // 配成 0 = 关掉看门狗（严格模式）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        CoreFailOpen("watchdog timeout");
    });
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
//
//  ★ 这里有两件事要做，而且它们的目标不一样：
//
//    ① 黑名单拦截 —— apple.com 系的校验请求、以及宿主的 WS 信令，
//       这些**不能发出去**。用「不发 resume」来实现（任务保持挂起）。
//
//    ② 别的请求一律**原样转发**。这是硬要求：
//       resume 被吞掉 = 宿主的网络直接死掉 = 用户看到的就是「进不去/白屏」。
//       所以下面有两道保险（见 CoreTaskResume）。

typedef void (*ResumeImpl)(id, SEL);

static NSSet<NSString *> *CoreBlockedHosts(void) {
    static NSSet<NSString *> *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [NSSet setWithArray:@[
            // ── 原始测试版的苹果系校验域名 ──
            @".apple.com",      @"apple.com",
            @".cdn-apple.com",  @"cdn-apple.com",

            // ── ★ 宿主自己那条 WS 信令通道（用户明确要求掐断）──
            //   ws://47.108.53.191/ws —— 宿主的在线校验/指令通道。
            //   日志里能看到它一直在重连（receive failure → 重新 auth send），
            //   这条通道一旦活着，宿主就可能被人从远端指挥 —— 必须断。
            //
            //   注意 NSSet 里放的是**命中规则**，不是完整 URL：
            //   CoreBlockNetworkURL 会用 hasSuffix: / isEqualToString: 两种方式比对。
            @"47.108.53.191",
        ]];
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

static ResumeImpl CoreHomeOriginalResume = NULL;

/// 计数器本体。放文件级是为了 CoreBumpInterceptors 能取到地址。
static unsigned resumeInterceptors = 0;

/// WS / 普通请求的取消计数。宿主长期挂着一条 WS，
/// 重复计数会淹掉日志，所以分开算。
static volatile int gWSCancelCount    = 0;
static volatile int gOtherCancelCount = 0;

/// 记一条取消日志。WS 任务（NSURLSessionWebSocketTask）单独算一类。
static void CoreHomeTrackCancel(NSURLSessionTask *task);

/// 递增 seq_cst —— 用 clang 内建而不是 `++`。
///
/// ★ 原始测试版的反汇编里这一处是 `ldaddal`（带 acquire-release 语义的**原子**读改写），
///   说明原作者是拿它当原子计数器用的。我这边原来写的是普通 `unsigned`，
///   多线程下是竞态（虽然只影响日志，但既然照抄就抄对）。
static void CoreBumpInterceptors(void) {
    __c11_atomic_fetch_add((_Atomic(unsigned int) *)&resumeInterceptors, 1u, __ATOMIC_SEQ_CST);
}

/// ★ resume 的**兜底转发**。
///
/// 正常情况下 CoreHomeUIInstall 已经把 CoreHomeOriginalResume 填好了，
/// 但如果那时候 NSURLSessionTask 还没加载出来（理论上不会，但越狱环境什么都有），
/// 它就一直是 NULL —— 而任何一条路径都不能因此吞掉 resume。
///
/// 做法：现取一次实现。取不到就宁可啥也不做也**绝不拦**，
/// 因为「拦住所有网络」对用户来说比「漏掉几个校验请求」严重得多。
static void CoreHomeFallbackResume(id self, SEL _cmd) {
    Method m = class_getInstanceMethod([NSURLSessionTask class], _cmd);
    IMP imp = m ? method_getImplementation(m) : NULL;
    if (imp) {
        CoreHomeOriginalResume = (ResumeImpl)imp;
        CoreHomeOriginalResume(self, _cmd);
        return;
    }
    record("network.resume FALLBACK FAILED (no original imp) cls=%s",
           NSStringFromClass([self class]).UTF8String ?: "?");
}

static void CoreTaskResume(id self, SEL _cmd) {
    NSURLSessionTask *task = (NSURLSessionTask *)self;
    NSURLRequest *req = task.originalRequest ?: task.currentRequest;
    NSURL *url = req.URL;

    if (CoreEnvironmentResource(url)) {
        record("network.environment.allow host=%s path=%s",
               url.host.UTF8String ?: "?", url.path.UTF8String ?: "");
    } else if (CoreBlockNetworkURL(url)) {
        CoreBumpInterceptors();
        record("network.cancel host=%s path=%s",
               url.host.UTF8String ?: "?", url.path.UTF8String ?: "");

        // ★ 真取消，不只是「不 resume」。
        //
        //   只 return 不 resume 的话任务一直挂在 suspended 状态：
        //     · 宿主那边的 delegate 永远收不到任何回调 → 它以为还在连
        //     · 宿主的重连逻辑看到「没失败也没成功」→ 立刻再发一条
        //     · 于是我们不转发、它一直重发，两边互相刷 —— 日志里那个
        //       「receive failure → 重新 auth send」的死循环就是这么来的
        //
        //   显式 cancel 会同步回调 didCompleteWithError，
        //   宿主拿到 error 后就走「连接失败」分支，重连间隔会拉长
        //   （NSURLSession 自带退避），不会再刷屏。
        [task cancel];
        CoreHomeTrackCancel(task);
        return;
    }

    // ── 转发（两道保险）──
    if (CoreHomeOriginalResume) {
        CoreHomeOriginalResume(self, _cmd);
    } else {
        CoreHomeFallbackResume(self, _cmd);
    }
}

/// 记一条取消日志。WS 任务（NSURLSessionWebSocketTask）单独算一类。
static void CoreHomeTrackCancel(NSURLSessionTask *task) {
    BOOL isWS = NO;
    Class wsClass = NSClassFromString(@"NSURLSessionWebSocketTask");
    if (wsClass && [task isKindOfClass:wsClass]) isWS = YES;
    // 兜底判断：iOS 13 以下没有 NSURLSessionWebSocketTask 类名可查
    if (!isWS) {
        NSString *clsName = NSStringFromClass([task class]) ?: @"";
        if ([clsName rangeOfString:@"WebSocket" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            isWS = YES;
        }
    }

    if (isWS) {
        gWSCancelCount++;
        record("network.cancel.ws WS 任务已掐断 (累计 %d 条)", gWSCancelCount);
    } else {
        gOtherCancelCount++;
        record("network.cancel.count total=%d ws=%d",
               gOtherCancelCount + gWSCancelCount, gWSCancelCount);
    }
}

/// 超时诊断用：把当前还在跑的、命中黑名单的任务真正取消掉。
///
/// ★ 原实现是空壳（只打一行日志），照抄的话 47.108.53.191 那条 WS
///   如果在 hook 安装**之前**就已经 resume 了，我们就永远拦不到它 ——
///   而宿主那条 WS 恰恰是启动早期就发起的。
///   所以这里补上真取消：扫一遍所有 running 任务，命中的直接 cancel。
static void cancelNetworkTasks(void) {
    record("network.cancel.pending interceptors=%u ws=%d other=%d",
           resumeInterceptors, gWSCancelCount, gOtherCancelCount);

    void (^sweep)(NSURLSession *) = ^(NSURLSession *session) {
        [session getAllTasksWithCompletionHandler:^(NSArray<NSURLSessionTask *> *tasks) {
            NSUInteger killed = 0;
            for (NSURLSessionTask *t in tasks) {
                NSURLRequest *req = t.originalRequest ?: t.currentRequest;
                if (CoreBlockNetworkURL(req.URL)) {
                    [t cancel];
                    killed++;
                    record("network.cancel.sweep host=%s state=%ld",
                           req.URL.host.UTF8String ?: "?", (long)t.state);
                }
            }
            if (killed) {
                record("network.cancel.sweep done killed=%lu", (unsigned long)killed);
            }
        }];
    };

    @try {
        // NSURLSession.sharedSession 的 tasks 是只读快照，遍历安全。
        // 宿主自己建的 session 拿不到引用，但 resume hook 已经覆盖了新发起的任务，
        // 加上这里的一遍清扫，绝大多数情况都能拦住。
        sweep([NSURLSession sharedSession]);
    } @catch (NSException *e) {
        record("network.cancel.sweep EXCEPTION: %s", (e.reason ?: @"?").UTF8String);
    }
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

    // ★ 心跳掉线 → 收回授权并把用户拉回验证页。
    //   注意这里**不再**直接放行或直接放弹窗：
    //   先 CoreCheckLicense 走一遍（有缓存就直接放行，缓存也过期了才弹窗），
    //   否则心跳一抖就把已经授权的用户又拽到验证页上，体验很差。
    bridge.onHeartbeatLost = ^{
        record("heartbeat.lost → re-check license");
        gAuthorized = NO;
        CoreCheckLicense();
    };

    // ★ C 入口层用通知来请求弹窗（COEntry.m 的 coreoffline_c_present_dialog）。
    //   走通知而不是导出函数指针：免得把 static 函数暴露成外部符号。
    [[NSNotificationCenter defaultCenter] addObserverForName:@"CoreOfflinePresentLicense"
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *note) {
        (void)note;
        record("entry.present_dialog via notification");
        CorePresentLicenseDialog();
    }];

    // ★ 置位必须在 shared 建好之后、CoreCheckLicense 之前 ——
    //   CoreCheckLicense 会走 CoreLicenseExpiryString，
    //   而那个函数靠这个标志决定「能不能读缓存」。
    gLicenseSubsystemUp = YES;

    record("license.subsystem.start sdk=%d keychain=%d",
           (int)bridge.available, (int)COKeychainAvailable());

    // ── 先看本地，能进就直接进（同步、不联网）──
    CoreCheckLicense();

    // ── 本地也没有才需要联网，这时候才起看门狗 ──
    // ★ 顺序很重要：本地有授权的情况下根本不该起看门狗，
    //   否则 12s 后会多打一行没必要放行日志，干扰排查。
    if (!gAuthorized) {
        CoreArmFailOpenWatchdog();
    }
}

/// 等宿主 App 启动到「有窗口」为止，然后交给 CoreStartLicenseSubsystem。
///
/// ★ 这个轮询是**启动路径上的硬依赖**：
///   没有它的话，宿主窗口还没建好时我们就把子系统跑完了，
///   CorePresentLicenseDialog 拿不到窗口 → 弹窗弹不出来 → 用户没有输入卡密的入口。
///
///   ★★ 注意它和看门狗的分工：
///      · 本函数负责「尽早拿到窗口，尽快把弹窗摆出来」
///      · 看门狗负责「无论如何都别让用户进不去」
///      两者互不依赖，任何一个挂掉另一个都能兜住。
static void CoreWaitForHostReady(NSInteger attemptsLeft) {
    // ★ 已经放行（看门狗抢先了 / 本地缓存有效）就没必要再折腾弹窗
    if (gAuthorized) {
        record("host.wait SKIPPED (already granted)");
        return;
    }

    UIViewController *host = CoreTopViewController();
    if (host) {
        record("host.ready after %ld retries", (long)(40 - attemptsLeft));
        CoreStartLicenseSubsystem();
        return;
    }

    if (attemptsLeft <= 0) {
        // 兜底：实在等不到窗口（比如宿主根本没有 UI），
        // 也把子系统跑起来，让缓存/心跳生效，只是弹不出窗 ——
        // 而弹不出窗也不影响进软件，看门狗会放行。
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
        // ══════════════════════════════════════════════════════════════
        //  ★★ 第 0 段：宿主包名守卫（照抄原始测试版）
        //
        //  原始测试版的构造函数第一件事就是这个（反汇编 0x4b3c-0x4b7c）：
        //      NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        //      if (![bid isEqualToString:@"qingxiugai.qingxiugai.qinxiugai"])
        //          return;                     // 不是目标 App 直接退出
        //
        //  这是原版的「安全阀」：注入到别的 App 时什么都不做，
        //  既不会干扰别人，也不会因为假设不成立而崩。
        //
        //  注意 bundleIdentifier / mainBundle 在 dyld 阶段是安全的 ——
        //  原始版实测可用，不属于「早期不安全 API」。
        // ══════════════════════════════════════════════════════════════
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        if (![bundleID isEqualToString:CoreHostBundleID()]) {
            // 不是目标宿主，静默退出。连日志都不开。
            return;
        }

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
        //
        // ★★ 顺序：**先挂看门狗，再找窗口**。
        //   看门狗是「一定要能进去」的保底 —— 它不受窗口、网络、
        //   用户操作任何一环的影响，到点无条件放行。
        //   把它放在最前面，后面任何一步卡住都有人兜着。
        dispatch_async(dispatch_get_main_queue(), ^{
            CoreArmFailOpenWatchdog();   // ← 先保命
            CoreWaitForHostReady(40);    // ← 再尽力把弹窗摆出来
        });
    }
}
