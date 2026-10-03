//
//  CoreOfflineClone.m
//  CoreOffline —— 测试版 1:1 复刻
//
//  ★★ 这个文件的唯一目标：**行为等价于用户的测试版 CoreOffline.work.dylib**。
//
//  所有实现细节都来自对测试版二进制的逐条反汇编，不掺任何"我觉得应该更好"：
//
//    测试版二进制          →  本文件
//    ────────────────────────────────────────────────────────────
//    0x4b3c 构造函数          initializeOffline
//    0x6dc0 __objc_stubs      CoreHomeBanner / CoreHome... 
//    0x4a38 CoreHomeBanner    CoreHomeBanner
//    0x4d40 CoreInstallMaskHooks  CoreInstallMaskHooks
//    0x511c / 0x5240          CoreHome...（UI 改写）
//    0x5290 cancelNetworkTasks    cancelNetworkTasks（空壳）
//    0x53fc 按钮匹配          CoreHomeRewriteControls
//    0x5600 CoreBlockNetworkURL   CoreBlockNetworkURL
//    0x56a8 CoreEnvironmentResource CoreEnvironmentResource
//    0x5860 CoreHomeUIInstall     CoreHomeUIInstall
//    0x4f6c monitorBackend        monitorBackend
//
//  ★ 刻意**不包含**的东西（测试版里就没有）：
//    · 卡密验证（T3 / 桥接层 / 弹窗 / Keychain / C 入口）
//    · dispatch_async 延迟启动
//    · 看门狗
//    · 任何网络请求（只拦不发）
//
//  依赖也严格对齐：Foundation / UIKit / QuartzCore / CoreFoundation。
//  测试版链接了 libc++（因为用了 C++ 的静态局部变量 + __gxx_personality_v0），
//  本文件用 C 静态变量 + dispatch_once 达到同样效果，不需要 libc++。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <mach-o/dyld.h>
#import <mach/mach_time.h>
#import <unistd.h>
#import <fcntl.h>
#import <stdarg.h>
#import <string.h>
#import <stdlib.h>
#import <stdio.h>
#import <time.h>
#import <limits.h>

#pragma mark - 常量（对应测试版的 CFString 字面量）

// __cstring 0x7aa4 附近的格式串
static NSString *const kLogFileName = @"Documents/core-offline-original-id.log";
static NSString *const kCommunityURL = @"https://t.me/cheatrev";
static NSString *const kPerpetualExpiry = @"2099-12-31 23:59:59";
static NSString *const kHostBundleID = @"qingxiugai.qingxiugai.qinxiugai";

// 宿主类与选择子（__cfstring [18][19][20][21]）
static NSString *const kHostControllerClass = @"OKDHomeMusicController";
static NSString *const kSelAttach = @"attachToRootView:";
static NSString *const kSelRefresh = @"refreshHomeLayoutArtwork";
static NSString *const kSelAuthValue = @"authorizationValue";
static NSString *const kSelMask = @"setDisableUpdateMask:";

// ── ★★ 按钮标题表（__ustring __cfstring[22..26]，UTF-16 解码得来）──
//
//  这是测试版真正匹配的 5 个中文标题。反汇编证据：
//    0x5558 处有一个 6 路跳转表（cmp #0xf / b.hi 分支之前）
//    0xc590..0xc678 区间是这 5 个 CFString 的释放
//    0xc328..0xc3a8 区间是它们的 retain
//
//  ★ 千万别再凭感觉写 "Community"/"社区" 之类的 —— 那些词在测试版
//    二进制里一个都不存在。
static NSArray<NSString *> *CoreHomeTitles(void) {
    static NSArray<NSString *> *titles = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        titles = @[@"查看公告", @"提交工单", @"工单进度", @"激活续时", @"检查更新"];
    });
    return titles;
}

/// 测试版里按钮处理有硬上限（0x54e8 `cmp w24, #0xf; b.hi`）。
/// 超过 15 个匹配按钮就整个跳过 —— 防止某些宿主页面把同样的标题
/// 铺满整个列表，导致我们反复改写卡顿。
static const int kCoreHomeRewireLimit = 15;

/// 关联对象 key。测试版用 objc_setAssociatedObject 保存原实现，
/// 这个 key 就是符号表里的 __ZL18CoreHomeRewiredKey。
static const void *kCoreHomeRewiredKey = &kCoreHomeRewiredKey;

#pragma mark - 日志

static int gLogFD = -1;

static void CoreLogOpen(void) {
    if (gLogFD >= 0) return;
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:kLogFileName];
    gLogFD = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (gLogFD < 0) gLogFD = STDERR_FILENO;
}

/// 对应测试版的 record()。
///
/// 反汇编 0x4400 是它的实现体：用 time(2) 而不是 NSDateFormatter ——
/// 因为 ICU 在 dyld 阶段还没就绪，早期调用 NSDateFormatter 会崩。
/// 这个细节我照抄。
static void record(const char *fmt, ...) {
    if (gLogFD < 0) CoreLogOpen();
    if (gLogFD < 0) return;

    char buf[1024];
    char ts[32];
    time_t now = time(NULL);
    struct tm tmv;
    if (localtime_r(&now, &tmv)) {
        strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);
    } else {
        ts[0] = '\0';
    }

    int n = snprintf(buf, sizeof(buf), "[%s] ", ts);
    if (n < 0) n = 0;

    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(buf + n, sizeof(buf) - (size_t)n - 2, fmt, ap);
    va_end(ap);
    if (m < 0) m = 0;

    size_t len = (size_t)n + (size_t)m;
    if (len > sizeof(buf) - 2) len = sizeof(buf) - 2;
    buf[len++] = '\n';

    ssize_t ignored = write(gLogFD, buf, len);
    (void)ignored;
}

#pragma mark - 全局状态（对应测试版的 __bss）

static uint64_t imageBase = 0;
static uint64_t credential = 0;
static uint64_t score = 0;
static dispatch_source_t stageTimer = NULL;
static BOOL gCancelled = NO;

/// 被拦下的请求计数。测试版用 ldaddal（原子）递增，这里也用内建。
static unsigned blockedRequests = 0;
/// 放行的环境资源计数
static unsigned allowedEnvironmentRequests = 0;

#pragma mark - 导出 API（与测试版符号一致）

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
    record("remote.open enter name=%s options=%llu",
           name ? name : "?", (unsigned long long)options);
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

#pragma mark - 授权有效期（★ 硬编码，不联网，不验证）
//
//  测试版的 authorizationValue 直接返回 CFString[1] = "2099-12-31 23:59:59"。
//  反汇编 0x59c0 附近的实现：没有分支、没有判断，直接返回常量。
//
//  这就是"一定能进"的根本原因 —— 宿主问"授权到什么时候"，
//  答案永远是 2099 年。

static id CoreHomeExpiryValue(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return kPerpetualExpiry;
}

#pragma mark - 关联对象辅助

static BOOL CoreHomeAlreadyRewired(UIView *view) {
    return objc_getAssociatedObject(view, kCoreHomeRewiredKey) != nil;
}

static void CoreHomeMarkRewired(UIView *view) {
    // ★ 测试版用 objc_setAssociatedObject 保存原实现 + 打标记。
    //   这里用同一个 key 存一个 NSNumber，语义等价：
    //   "这个视图已经处理过了，别再处理第二遍"。
    objc_setAssociatedObject(view, kCoreHomeRewiredKey, @(YES),
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

#pragma mark - 社区按钮跳转

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
    NSURL *url = [NSURL URLWithString:kCommunityURL];
    if (!url) return;
    UIApplication *app = [UIApplication sharedApplication];
    if ([app respondsToSelector:@selector(openURL:options:completionHandler:)]) {
        [app openURL:url options:@{} completionHandler:nil];
    }
}

@end

#pragma mark - 资源（CoreHomeBanner.work / hf.png）
//
//  测试版 CoreHomeBanner 对应的反汇编在 0x4a38 附近：
//  从 mainBundle 下找 CoreHomeBanner.work 这个 bundle，
//  在里面按名字取图片；同样有 15 的上限计数。

/// ★★ 两个真实的坑（会导致闪退），必须照测试版的方式绕开：
///
///   ① `[[NSBundle mainBundle] bundlePath]` 在 dyld/constructor 阶段
///      是不可靠的 —— 此时 UIApplication 还没建，mainBundle 可能返回 nil。
///      测试版的做法是直接用 _NSGetExecutablePath + 去掉最后一段，
///      拿到可执行文件所在目录，再拼 CoreHomeBanner.work。
///
///   ② 这个函数被 `imageNamed:` 的 hook 调用，而 **hook 本身可能在
///      任意线程**（很多库在后台线程取图）。测试版在这里用 @synchronized
///      而不是 dispatch_once —— 因为 dispatch_once 在递归调用时**会死锁**，
///      而且如果 hook 内部再触发一次 imageNamed:，就是无限递归 → 栈溢出 → 闪退。
///      所以这里必须：@synchronized 串行化 + 递归守卫。
static UIImage *CoreHomeBanner(NSString *name, NSBundle *bundle) {
    (void)bundle;
    if (name.length == 0) return nil;

    // ★ 递归守卫：hook 内部绝不能再触发自己
    static _Thread_local int inBanner = 0;
    if (inBanner) return nil;
    inBanner = 1;

    UIImage *result = nil;
    @synchronized ([CoreHomeLinkTarget class]) {
        static NSMutableDictionary<NSString *, UIImage *> *cache = nil;
        if (!cache) cache = [NSMutableDictionary dictionary];

        NSString *key = name;
        result = cache[key];
        if (!result) {
            // ★ 不用 mainBundle，直接问 dyld 要可执行文件路径
            char exePath[PATH_MAX];
            uint32_t sz = sizeof(exePath);
            if (_NSGetExecutablePath(exePath, &sz) == 0) {
                NSString *exe = [NSString stringWithUTF8String:exePath];
                NSString *dir = [exe stringByDeletingLastPathComponent];
                NSString *workPath = [dir stringByAppendingPathComponent:@"CoreHomeBanner.work"];
                NSBundle *work = [NSBundle bundleWithPath:workPath];
                NSString *base = name.stringByDeletingPathExtension.length
                               ? name.stringByDeletingPathExtension : name;
                NSString *ext = name.pathExtension.length ? name.pathExtension : @"png";
                NSString *path = [work pathForResource:base ofType:ext];
                // ★ 兜底：bundle 里找不到就在可执行文件同目录直接找
                if (!path) {
                    path = [dir stringByAppendingPathComponent:
                            [base stringByAppendingPathExtension:ext]];
                    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) path = nil;
                }
                if (path) {
                    result = [UIImage imageWithContentsOfFile:path];
                }
            }
            if (result) cache[key] = result;
        }
    }

    inBanner = 0;
    return result;
}

#pragma mark - UI Hook 实现体

typedef void (*CoreAttachImpl)(id, SEL, UIView *);
typedef void (*CoreRefreshImpl)(id, SEL);

static CoreAttachImpl  CoreHomeOriginalAttach  = NULL;
static CoreRefreshImpl CoreHomeOriginalRefresh = NULL;
static UIView *CoreHomeRoot = nil;

static BOOL CoreHomeMatchesTitle(NSString *title) {
    if (title.length == 0) return NO;
    NSString *clean = [title stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return [CoreHomeTitles() containsObject:clean];
}

/// 改写匹配的按钮。
///
/// 反汇编 0x53fc–0x5558 的完整流程，含那个 15 上限。
static void CoreHomeRewriteControls(UIView *root) {
    if (![root isKindOfClass:[UIView class]]) return;

    // ★ 15 上限：测试版在 0x54e8 用 `cmp w24, #0xf; b.hi` 实现
    static int rewired = 0;
    if (rewired >= kCoreHomeRewireLimit) return;

    for (UIView *sub in root.subviews) {
        if ([sub isKindOfClass:[UIButton class]]) {
            UIButton *btn = (UIButton *)sub;
            NSString *text = btn.currentTitle
                           ?: btn.currentAttributedTitle.string
                           ?: btn.titleLabel.text
                           ?: btn.accessibilityLabel;

            if (CoreHomeMatchesTitle(text) && !CoreHomeAlreadyRewired(btn)) {
                rewired++;
                CoreHomeMarkRewired(btn);

                // 先摘掉原有全部事件
                [btn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];

                // iOS 14+ 的菜单与事件枚举
                if (@available(iOS 14.0, *)) {
                    [btn enumerateEventHandlers:^(UIAction *action, id element,
                                                  SEL selector, UIControlEvents events,
                                                  BOOL *stop) {
                        (void)element; (void)selector; (void)events; (void)stop;
                        [btn removeAction:action forControlEvents:UIControlEventTouchUpInside];
                    }];
                    btn.showsMenuAsPrimaryAction = NO;
                }

                [btn addTarget:[CoreHomeLinkTarget sharedTarget]
                        action:@selector(openCommunity:)
              forControlEvents:UIControlEventTouchUpInside];

                // ★ 测试版在这里只打一条日志（0x554c → record 0x7aa4 的格式串），
                //   不跳转、不做事。
                record("network.environment.allow host=%s path=%s", "?", "?");
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

/// ★★ 关键防护（测试版靠 __objc_stubs 天然规避，我们得显式做）：
///
///   CoreHomeOriginalImageNamed 在 hook 装好之后才非空。如果 hook 是在
///   `method_setImplementation` 那一刻就被别的线程撞上（dyld 阶段确实
///   有可能），原实现指针还是 NULL，直接调就是跳空 → 闪退。
///   所以这里**先取原实现，装之前必须拿到**；拿不到就整个不装。
/// 资源名匹配。
///
/// 测试版 __cstring 里有三个相关字面量：
///   0x7c17  hf        ← 前缀判定
///   0x7c1a  hf.png    ← 确切的兜底文件名
///   0x7c1d  png       ← 默认扩展名
///
/// 所以判定是「名字以 hf 开头」，兜底找的是 "hf.png"。
static BOOL CoreHomeIsBannerName(NSString *name) {
    if (name.length == 0) return NO;
    return [name hasPrefix:@"hf"];
}

static id CoreHomeImageNamed(id self, SEL _cmd, NSString *name) {
    id img = nil;
    if (CoreHomeOriginalImageNamed) {
        img = CoreHomeOriginalImageNamed(self, _cmd, name);
    }
    if (!img && CoreHomeIsBannerName(name)) {
        // 先按调用方给的名字找，找不到退到 hf.png
        img = CoreHomeBanner(name, nil);
        if (!img) img = CoreHomeBanner(@"hf.png", nil);
    }
    return img;
}

static id CoreHomeImageInBundle(id self, SEL _cmd, NSString *name,
                                NSBundle *bundle, UITraitCollection *traits) {
    id img = nil;
    if (CoreHomeOriginalImageInBundle) {
        img = CoreHomeOriginalImageInBundle(self, _cmd, name, bundle, traits);
    }
    if (!img && CoreHomeIsBannerName(name)) {
        img = CoreHomeBanner(name, bundle);
        if (!img) img = CoreHomeBanner(@"hf.png", bundle);
    }
    return img;
}

#pragma mark - 更新遮罩拦截 (setDisableUpdateMask:)
//
//  反汇编 0x4d40 CoreInstallMaskHooks。测试版的做法：
//    ① objc_copyClassList 拿全部类
//    ② 跳过 UIImage
//    ③ 对每个类**向上遍历父类族**直到 NSObject
//    ④ 在每一层用 class_copyMethodList + method_getName 找目标选择子
//    ⑤ 找到就用 objc_setAssociatedObject 存原实现
//    ⑥ 装一个透传 objc_msgSend 的 block 实现（0x4e38-0x4e50 的 pacda）
//
//  ★ 关键差异（我原来写错了）：测试版是**透传**，不是吞掉。
//   它只是把 mask 参数原样转给原实现 —— 效果是"调用照走，但我们的
//   hook 位先过一手"，而不是屏蔽遮罩。

typedef void (*MaskImpl)(id, SEL, id);
static MaskImpl maskOriginal = NULL;

static void maskHook(id self, SEL _cmd, id mask) {
    record("setDisableUpdateMask:");
    // ★ 透传（测试版行为）
    if (maskOriginal) maskOriginal(self, _cmd, mask);
}

static void CoreInstallMaskHooks(void) {
    unsigned count = 0;
    __unsafe_unretained Class *classes =
        (__unsafe_unretained Class *)objc_copyClassList(&count);
    if (!classes) return;

    // 测试版跳过 UIImage
    Class uiImageClass = [UIImage class];

    for (unsigned i = 0; i < count; i++) {
        Class cls = classes[i];
        if (!cls) continue;
        if (cls == uiImageClass) continue;   // 0x4dac 的跳过

        // ★ 向上遍历类族（0x4dbc class_getSuperclass）
        Class walk = cls;
        while (walk && walk != [NSObject class]) {
            unsigned mcount = 0;
            Method *methods = class_copyMethodList(walk, &mcount);
            if (methods) {
                for (unsigned j = 0; j < mcount; j++) {
                    SEL name = method_getName(methods[j]);
                    if (name == NSSelectorFromString(kSelMask)) {
                        IMP imp = method_getImplementation(methods[j]);
                        maskOriginal = (MaskImpl)imp;
                        __unsafe_unretained Method m = methods[j];
                        // 测试版用 objc_setAssociatedObject 存原实现，
                        // 这里存全局（语义等价，且更简单）
                        objc_setAssociatedObject(cls, kCoreHomeRewiredKey,
                                                 [NSValue valueWithPointer:(void *)imp],
                                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                        method_setImplementation(m, (IMP)maskHook);
                        record("mask.hook class=%s", class_getName(walk));
                        break;
                    }
                }
                free(methods);
            }
            walk = class_getSuperclass(walk);
        }
    }
    free(classes);
}

#pragma mark - 网络拦截
//
//  ★★ 测试版的核心逻辑，也是我上一轮漏掉最多的地方。
//
//  两层判定（反汇编 0x5600 / 0x56a8）：
//    ① 协议白名单：scheme 不在 {http,https,ws,wss,ftp} → 拦
//    ② 环境资源白名单：命中 → 放行
//    ③ 主机黑名单：命中 → 拦
//
//  反汇编铁证在 0x5668 的 `eor w20, w0, #1` —— 取反。
//  意思是「不在白名单 **且** 不是环境资源」才拦截。

/// 协议白名单（对应 CFString[5..9]）
static NSSet<NSString *> *CoreAllowedSchemes(void) {
    static NSSet<NSString *> *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [NSSet setWithArray:@[@"http", @"https", @"ws", @"wss", @"ftp"]];
    });
    return s;
}

/// 主机黑名单（对应 CFString[14..17]）
static NSSet<NSString *> *CoreBlockedHosts(void) {
    static NSSet<NSString *> *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [NSSet setWithArray:@[@"apple.com", @".apple.com",
                                  @"cdn-apple.com", @".cdn-apple.com"]];
    });
    return s;
}

/// 环境资源白名单（反汇编 0x56a8 CoreEnvironmentResource）
///
/// 三个字面量全部来自测试版 __cstring，地址都对得上：
///   0x7b1e  api.appledb.dev
///   0x7b2e  /ios/                                     ← 独立的段
///   0x7b34  fastly.jsdelivr.net
///   0x7b48  /gh/littlebyteorg/appledb@gh-pages/ios/
///
/// ★ 注意 "/ios/" 是**单独**一个字符串常量，说明测试版是**分段判**的：
///   先看 host 是不是 jsdelivr，再看 path 里含不含 "/ios/"。
///   之前我只判完整前缀，路径稍有不同（比如末尾没斜杠、多了 query）
///   就会漏掉，导致本该放行的请求被拦。
static BOOL CoreEnvironmentResource(NSURL *url) {
    if (!url) return NO;
    NSString *host = url.host.lowercaseString;
    NSString *path = url.path ?: @"";
    if (host.length == 0) return NO;

    if ([host isEqualToString:@"api.appledb.dev"]) return YES;

    if ([host isEqualToString:@"fastly.jsdelivr.net"]) {
        // ① 完整前缀（测试版 0x7b48）
        if ([path hasPrefix:@"/gh/littlebyteorg/appledb@gh-pages/ios/"]) return YES;
        // ② 宽松兜底（测试版 0x7b2e 的独立 "/ios/" 段）
        //    只要路径里出现过 /ios/ 就认，避免因 query / 尾斜杠差异漏判。
        if ([path containsString:@"/ios/"]) return YES;
    }
    return NO;
}

/// 主机是否命中黑名单
static BOOL CoreBlockHost(NSURL *url) {
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

/// ★ 主判定。注意先看协议 —— 这是我上轮漏掉的第一层。
static BOOL CoreBlockNetworkURL(NSURL *url) {
    if (!url) return NO;

    // ① 协议白名单（反汇编 0x5620–0x5668）
    NSString *scheme = url.scheme.lowercaseString;
    if (![CoreAllowedSchemes() containsObject:scheme]) {
        // 不在白名单 → 先看是不是环境资源（0x5660 bl CoreEnvironmentResource）
        if (!CoreEnvironmentResource(url)) return YES;
        return NO;
    }

    // ② 环境资源放行
    if (CoreEnvironmentResource(url)) return NO;

    // ③ 主机黑名单
    return CoreBlockHost(url);
}

typedef void (*ResumeImpl)(id, SEL);
static ResumeImpl CoreHomeOriginalResume = NULL;

static void CoreBumpBlocked(void) {
    __c11_atomic_fetch_add((_Atomic(unsigned int) *)&blockedRequests, 1u,
                           __ATOMIC_SEQ_CST);
}

static void CoreTaskResume(id self, SEL _cmd) {
    // ★ 原实现必须是有效的，否则连转发都没法做 —— 直接跳空 = 闪退。
    //   正常路径下 install 时已经保证非空；这里是二次保险。
    if (!CoreHomeOriginalResume) {
        // 拿不到原实现，只能走 objc_msgSend 硬转发一次。
        // 用 objc_msgSend 而不是直接返回 —— 否则 task 永远停住。
        ((void (*)(id, SEL))objc_msgSend)(self, _cmd);
        return;
    }

    NSURLSessionTask *task = (NSURLSessionTask *)self;
    NSURLRequest *req = nil;
    @try {
        req = task.originalRequest ?: task.currentRequest;
    } @catch (NSException *e) {
        (void)e;
        req = nil;
    }
    NSURL *url = req.URL;

    if (CoreEnvironmentResource(url)) {
        allowedEnvironmentRequests++;
        record("network.environment.allow host=%s path=%s",
               url.host.UTF8String ?: "?", url.path.UTF8String ?: "");
    } else if (CoreBlockNetworkURL(url)) {
        CoreBumpBlocked();
        record("network.cancel host=%s", url.host.UTF8String ?: "?");
        // ★★ 测试版行为：**直接返回，不调 cancel**。
        //
        //   反汇编 0x565c `cbz w20, #0x566c` → 命中黑名单时直接
        //   走到 0x5674 的 `retab` 返回，中间没有任何 cancel 调用。
        //
        //   这确实会导致宿主的 WS 一直挂着（你日志里的死循环就是这么来的），
        //   但既然这一轮的目标是 1:1 复刻，就先照抄。
        //   等确认能进之后，我们再单独讨论要不要加 cancel。
        return;
    }

    CoreHomeOriginalResume(self, _cmd);
    record("network.resume.interceptors=%u", blockedRequests);
}

/// ★ 测试版里这是**空壳**：只打一条日志，什么都不做。
///
/// 反汇编 0x5290：函数体只有一次 record 调用就返回了，
/// 没有任何 cancel / 遍历 / 清理。
static void cancelNetworkTasks(void) {
    record("network.cancel.pending interceptors=%u", blockedRequests);
}

#pragma mark - Hook 安装

static void CoreHomeUIInstall(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // ── 宿主控制器（反汇编 0x5860）──
        Class cls = NSClassFromString(kHostControllerClass);
        if (cls) {
            // 每个方法都用 class_addMethod 优先 —— 测试版就是这么干的
            // （0x58c4 / 0x5944 / 0x59c0），失败才退回 method_setImplementation。
            SEL sels[3] = { NSSelectorFromString(kSelAttach),
                            NSSelectorFromString(kSelRefresh),
                            NSSelectorFromString(kSelAuthValue) };
            IMP imps[3] = { (IMP)CoreHomeAttach,
                            (IMP)CoreHomeRefresh,
                            (IMP)CoreHomeExpiryValue };

            for (int k = 0; k < 3; k++) {
                SEL sel = sels[k];
                // ★ 类型必须先校验：class_getInstanceMethod 会把
                //   「父类里存在但子类没有」的方法也返回，签名可能不匹配 ——
                //   按错签名调用就是参数错位 → 闪退。
                Method m = class_getInstanceMethod(cls, sel);
                if (!m) continue;

                IMP old = method_getImplementation(m);
                const char *types = method_getTypeEncoding(m);

                // ★ 保存原实现（authorizationValue 不需要，它直接返回常量）
                if (k == 0)      CoreHomeOriginalAttach  = (CoreAttachImpl)old;
                else if (k == 1) CoreHomeOriginalRefresh = (CoreRefreshImpl)old;

                // ★ class_addMethod 只在子类**没有**这个方法时成功。
                //   测试版就是这个语义：装上了说明是新增，装不上说明本来就有，
                //   那就 method_setImplementation 顶掉。
                if (!class_addMethod(cls, sel, imps[k], types)) {
                    method_setImplementation(m, imps[k]);
                }
                record("hook.install cls=%s sel=%s", kHostControllerClass.UTF8String,
                       sel_getName(sel));
            }
        } else {
            record("hook.skip cls=%s not-found", kHostControllerClass.UTF8String);
        }

        // ── UIImage 类方法（0x5a38 / 0x5ab0）──
        //    imageNamed: 是**类方法**，必须拿元类。
        //
        //    ★★ 这里是全文件最危险的一处。UIImage 是所有图片加载的必经之路，
        //      而且很可能在构造阶段就被别的库调用。所以：
        //        ① 必须**先取到原实现**，取不到就整个不装（否则跳空指针）
        //        ② 装的时候用原方法自己的 type encoding，别自己编
        Class imageMeta = object_getClass([UIImage class]);
        Method m2 = NULL;

        m2 = class_getClassMethod(imageMeta, @selector(imageNamed:));
        if (m2) {
            IMP old = method_getImplementation(m2);
            if (old) {
                CoreHomeOriginalImageNamed = (CoreImageNamedImpl)old;
                // ★ 只有原实现确实保存成功，才真的替换
                if (CoreHomeOriginalImageNamed) {
                    method_setImplementation(m2, (IMP)CoreHomeImageNamed);
                }
            }
        }

        m2 = class_getClassMethod(imageMeta,
                @selector(imageNamed:inBundle:compatibleWithTraitCollection:));
        if (m2) {
            IMP old = method_getImplementation(m2);
            if (old) {
                CoreHomeOriginalImageInBundle = (CoreImageInBundleImpl)old;
                if (CoreHomeOriginalImageInBundle) {
                    method_setImplementation(m2, (IMP)CoreHomeImageInBundle);
                }
            }
        }

        // ── NSURLSessionTask resume ──
        //    ★★ 第二个大坑：NSURLSessionTask 是**懒加载**的类。
        //      dyld 阶段 [NSURLSessionTask class] 完全可能返回 nil
        //      （Foundation 的某些类要等首次用到才注册）——
        //      对 nil 取方法然后 method_setImplementation 必崩。
        //      测试版之所以没事，是因为它的 __objc_stubs 走的是
        //      objc_msgSend 转发，天然对 nil 容错。
        //      我们显式判空 + 记日志，不装就是了。
        Class taskClass = NSClassFromString(@"NSURLSessionTask");
        if (!taskClass) taskClass = [NSURLSessionTask class];
        Method m3 = taskClass ? class_getInstanceMethod(taskClass, @selector(resume)) : NULL;
        if (m3) {
            IMP old = method_getImplementation(m3);
            if (old) {
                CoreHomeOriginalResume = (ResumeImpl)old;
                method_setImplementation(m3, (IMP)CoreTaskResume);
                record("hook.install cls=NSURLSessionTask sel=resume");
            }
        } else {
            // ★ 拿不到就**什么都不做** —— 绝不能带着空原实现去替换。
            //   这不影响"能不能进"，只是网络拦截晚一点生效。
            record("hook.skip cls=NSURLSessionTask not-ready");
        }

        // ── 更新遮罩 ──
        //    ★ 这个必须放最后：它要遍历全部类，类还没注册完容易踩到
        //      半初始化的元类。测试版也是在 UIInstall 的最后一步做。
        CoreInstallMaskHooks();
    });
}

#pragma mark - 后台监视

static void monitorBackend(void) {
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    stageTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    // ★ 测试版：2.0s 起，1.0s 间隔，0.1s leeway
    dispatch_source_set_timer(stageTimer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                              (uint64_t)(1.0 * NSEC_PER_SEC),
                              (uint64_t)(0.1 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(stageTimer, ^{
        static unsigned ticks = 0;
        ticks++;
        record("backend stage=%.48s lane=%.24s state=%u ready=%u result=%d running=%u "
               "cancel=%u pass=%u base=%llx score=%llu",
               "offline", "main", 1u, 1u, 0, 1u, gCancelled ? 1u : 0u, 1u,
               (unsigned long long)imageBase, (unsigned long long)score);
        record("overlay enabled=%u capability=%u quarantine=%u hosted=%u registering=%u "
               "step=%u remote=%u reason=%.120s pending=%.120s ids=%u/%u,%u/%u,%u/%u",
               1u, 1u, 0u, 1u, 0u, (unsigned)ticks, 0u, "-", "-",
               0u, 0u, 0u, 0u, 0u, 0u);

        if (ticks >= 8 && !gCancelled) {
            gCancelled = YES;
            record("backend diagnostic timeout: requesting original cancellation");
            cancelNetworkTasks();   // 空壳，照抄
        }
    });
    dispatch_resume(stageTimer);
}

#pragma mark - 构造函数
//
//  ★★ 测试版是**全同步**的（反汇编 0x4b3c 一条直路走到底）。
//    没有 dispatch_async、没有延迟、没有等窗口、没有卡密。
//
//    这就是它"一定能进"的结构性原因：
//    dyld 阶段该做的全做完，之后 App 正常启动，跟没注入一样。

__attribute__((constructor))
static void initializeOffline(void) {
    @autoreleasepool {
        // ══ 第 0 段：包名守卫（0x4b3c-0x4b7c）══
        //    不是目标宿主就静默退出，连日志都不开。
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        if (![bundleID isEqualToString:kHostBundleID]) {
            return;
        }

        // ══ 第 1 段：日志 ══
        CoreLogOpen();
        record("constructor pid=%d base=%llx", getpid(),
               (unsigned long long)(uintptr_t)_dyld_get_image_header(0));

        // ══ 第 2 段：凭据链 ══
        //    全部是纯系统调用，无依赖。
        uint64_t material = 0, derive = 0;
        arc4random_buf(&material, sizeof(material));
        uint64_t lease = material ^ (uint64_t)mach_continuous_time();
        derive = lease & 0xFFFFFFFFFFFFULL;
        credential = derive;
        record("derive=%llu", (unsigned long long)derive);
        record("material=%llu", (unsigned long long)material);
        record("lease=%llu", (unsigned long long)lease);
        record("credential=%llu", (unsigned long long)credential);

        // ══ 第 3 段：定位宿主镜像 ══
        //    ★★ 必须用 ".app/Core" 而不是 ".app/"。
        //
        //    证据：测试版 __cstring 0x78ed = ".app/Core"，**不是** ".app/"。
        //
        //    为什么这个区别很重要：iOS 上 ".app/" 会命中一大堆路径 ——
        //      ×xx.app/Frameworks/YYY.framework/YYY   ← 也可能含 .app/
        //      ×xx.app/PlugIns/ZZZ.appex/ZZZ
        //      ×xx.app/YYY.dylib
        //    而主可执行文件固定是 <Name>.app/<Name>，所以 ".app/Core" 这种
        //    ".app/<可执行名>" 的形状才是精确的。用 ".app/" 很可能先撞上
        //    framework 的路径，imageBase 就是错的。
        uint32_t count = _dyld_image_count();
        for (uint32_t i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, ".app/Core")) {
                imageBase = (uint64_t)(uintptr_t)_dyld_get_image_header(i);
                break;
            }
        }

        // ══ 第 4 段：装 hook + 起定时器 + 跑导出 API ══
        //    ★ 全同步，一步不延。
        CoreHomeUIInstall();
        monitorBackend();
        CoreOfflinePrepare();
        CoreOfflineBootstrap();
    }
}
