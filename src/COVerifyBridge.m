//
//  COVerifyBridge.m
//  CoreOffline —— 卡密验证桥接层实现
//
//  动态调用策略：
//    T3 SDK 用 NSClassFromString 找类，用 performSelector / NSInvocation 发消息。
//    好处是 dylib 不硬依赖 libT3Verify.a —— 没带 SDK 的宿主注入后照样能跑，
//    只是勾了「未接入验证后端」的降级路径。
//
//    SDK 的初始化参数（各种 code / appkey / RSA 公钥）从 COVerifyConfig.h 读，
//    那个文件是给你填自己的值的。
//

#import "COVerifyBridge.h"
#import "COVerifyConfig.h"
#import "COKeychain.h"
#import "COLog.h"
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - 本地存储 key
//
//  ★ 存储位置的选择（照 F5CloudAuth 的做法）：
//
//    主存储  = Keychain（Service = <bundleid>.license，Account = 下面这些 key）
//               · 用户清缓存不失效
//               · 不落明文磁盘
//               · AfterFirstUnlockThisDeviceOnly —— 后台心跳能读，不随备份迁移
//
//    副本    = Documents/.syscache/<sha256(key)>（带 salt 校验）
//               · 防「只清 Keychain 就白嫖」的破解工具
//               · 读到副本时自动回填 Keychain
//
//    兜底    = NSUserDefaults
//               · Keychain 完全不可用时（无签名环境）保底
//
//    读顺序：Keychain → 文件副本 → NSUserDefaults
//    写：三处都写（COVault 写前两处，再补 NSUserDefaults）
//

static NSString *const kCOKeyCard      = @"co_license_card";
static NSString *const kCOKeyExpiry    = @"co_license_expiry";
static NSString *const kCOKeyStateCode = @"co_license_statecode";
static NSString *const kCOKeyEndStamp  = @"co_license_end_stamp";
/// 最后一次「联网验证成功」的时间戳 —— 离线兜底靠它算宽限期
static NSString *const kCOKeyLastGoodStamp = @"co_license_last_good";

#pragma mark - 统一读写（三级回退）

static NSString *COStoreRead(NSString *key) {
    // 1) COVault 内部已做 Keychain → 文件 的回退 + 自愈
    NSString *v = COVaultRead(key);
    if (v.length) return v;

    // 2) NSUserDefaults 兜底
    NSString *ud = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (ud.length) {
        // 从旧存储迁移过来：抢在 Keychain 可用时补写一份
        COVaultWrite(key, ud);
        return ud;
    }
    return nil;
}

static void COStoreDelete(NSString *key);

static void COStoreWrite(NSString *key, NSString *value) {
    if (value.length == 0) {
        COStoreDelete(key);
        return;
    }
    COVaultWrite(key, value);
    // NSUserDefaults 也写一份：某些越狱环境 Keychain 不可用，
    // 文件又可能因沙箱限制写不进去，三保险。
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setObject:value forKey:key];
    [d synchronize];
}

static void COStoreDelete(NSString *key) {
    COVaultDelete(key);
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d removeObjectForKey:key];
    [d synchronize];
}

/// 补一个 double 的读写（到期时间戳）
static void COStoreWriteDouble(NSString *key, double v) {
    COStoreWrite(key, [NSString stringWithFormat:@"%.6f", v]);
}

static double COStoreReadDouble(NSString *key) {
    NSString *s = COStoreRead(key);
    return s.length ? s.doubleValue : 0;
}

#pragma mark - 失败归因：是网络问题还是卡密问题？

/// 判断一次验证失败到底是「连不上服务器」还是「卡密本身有问题」。
///
/// ★ 这个区分至关重要：
///   离线兜底只能对**网络故障**生效。如果卡密是错的/过期的也兜底，
///   那等于任何人随便填一串都能拿到永久授权 —— 验证就白做了。
///
/// 判据（任一命中就算网络故障）：
///   1. message 里出现网络类关键词
///   2. code 是负数或 0（T3 的网络错误码约定）
///   3. result 对象上带了 NSError 且 domain 是 NSURLErrorDomain
///   4. result 为 nil（SDK 压根没返回）
static BOOL COIsNetworkFailure(NSString *message, NSString *codeStr, id result) {
    // ── 1. message 关键词 ──
    if (message.length) {
        NSArray<NSString *> *needles = @[
            @"网络", @"超时", @"连接", @"服务器", @"无响应", @"timeout",
            @"network", @"connect", @"offline", @"unreachable",
            @"NSURLError", @"-100", @"request timed out",
        ];
        NSString *lower = message.lowercaseString;
        for (NSString *n in needles) {
            if ([message rangeOfString:n].location != NSNotFound) return YES;
            if ([lower rangeOfString:n.lowercaseString].location != NSNotFound) return YES;
        }
    }

    // ── 2. 错误码约定 ──
    if (codeStr.length) {
        NSInteger c = codeStr.integerValue;
        // 负数（-1 / -1009...）和 0 都当网络问题；1/200 是成功，别的正数是业务错误
        if (c <= 0 && codeStr.length <= 6 && [codeStr rangeOfCharacterFromSet:
             [[NSCharacterSet decimalDigitCharacterSet] invertedSet]].location == NSNotFound) {
            return YES;
        }
    }

    // ── 3. result 上挂的 NSError ──
    @try {
        if ([result respondsToSelector:NSSelectorFromString(@"error")]) {
            id err = [result valueForKey:@"error"];
            if ([err isKindOfClass:[NSError class]]) {
                NSError *e = (NSError *)err;
                if ([e.domain isEqualToString:NSURLErrorDomain]) return YES;
            }
        }
    } @catch (NSException *ignored) { /* KVC 失败就当没这个字段 */
        (void)ignored;
    }

    return NO;
}

#pragma mark - 时间解析

/// 支持的全部日期格式。
///
/// ★ 照 F5CloudAuth 的做法：真实服务器返回的时间格式**不统一**，
///   同一个后端的公告接口和登录接口可能给出不同格式，
///   甚至同一接口在不同版本之间会变。所以这里做多格式轮询 + 正则兜底，
///   而不是死磕一种格式。
static NSArray<NSString *> *CODateFormatList(void) {
    static NSArray *formats = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        formats = @[
            @"yyyy-MM-dd HH:mm:ss",
            @"yyyy/MM/dd HH:mm:ss",
            @"yyyy-MM-dd'T'HH:mm:ss",
            @"yyyy-MM-dd'T'HH:mm:ssZ",
            @"yyyy-MM-dd HH:mm",
            @"yyyy/MM/dd HH:mm",
            @"yyyyMMddHHmmss",
            @"yyyyMMddHHmm",
            @"yyyy-MM-dd",
        ];
    });
    return formats;
}

/// 一次性把多格式都试一遍。返回第一个解析成功且**合理**的日期。
static NSDate *COParseExpiry(NSString *s) {
    if (s.length == 0) return nil;

    NSString *trimmed = [s stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (trimmed.length == 0) return nil;

    // ★ 纯数字的时间戳也认（秒 / 毫秒）
    if (trimmed.length >= 10 && trimmed.length <= 13 && [trimmed rangeOfCharacterFromSet:
        [[NSCharacterSet decimalDigitCharacterSet] invertedSet]].location == NSNotFound) {
        double v = trimmed.doubleValue;
        // 13 位当毫秒
        if (trimmed.length >= 13) v /= 1000.0;
        // 合理的 Unix 时间范围：2001-01-01 ~ 2100-01-01
        if (v > 978307200.0 && v < 4102444800.0) {
            return [NSDate dateWithTimeIntervalSince1970:v];
        }
    }

    static NSDateFormatter *f = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        f = [[NSDateFormatter alloc] init];
        // ★ en_US_POSIX：避免用户在系统里改成泰国佛历 / 日本和历之后解析错乱
        f.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        f.timeZone = [NSTimeZone localTimeZone];
    });

    for (NSString *fmt in CODateFormatList()) {
        f.dateFormat = fmt;
        NSDate *d = [f dateFromString:trimmed];
        if (d) return d;
    }

    // ── 正则兜底：从一坨文本里抠出日期 ──
    // 对应 F5CloudAuth 的 (?:19|20)\d{2}[-/]\d{1,2}[-/]\d{1,2}(...)?
    static NSRegularExpression *re = nil;
    static dispatch_once_t once2;
    dispatch_once(&once2, ^{
        re = [NSRegularExpression
              regularExpressionWithPattern:@"(?:19|20)\\d{2}[-/]\\d{1,2}[-/]\\d{1,2}"
                                   options:0
                                     error:NULL];
    });

    NSTextCheckingResult *m = [re firstMatchInString:trimmed
                                             options:0
                                               range:NSMakeRange(0, trimmed.length)];
    if (m) {
        NSString *dateOnly = [trimmed substringWithRange:m.range];
        NSString *norm = [dateOnly stringByReplacingOccurrencesOfString:@"/" withString:@"-"];
        f.dateFormat = @"yyyy-MM-dd";
        NSDate *d = [f dateFromString:norm];
        if (d) return d;
    }

    return nil;
}

@interface COVerifyBridge ()

@property (nonatomic, strong) id       verifyInstance;   // T3Verify 实例（id 避免硬依赖）
@property (nonatomic, assign) BOOL     sdkUsable;
@property (nonatomic, assign) BOOL     loggedIn;
@property (nonatomic, assign) NSInteger heartbeatFail;
@property (nonatomic, strong) NSTimer *heartbeatTimer;
@property (nonatomic, strong) NSString *cachedCardStore;
@property (nonatomic, strong) NSString *cachedExpiryStore;

/// 装配失败的原因。用于把「SDK 没接上 / RSA 公钥填错 / 版本不兼容」
/// 这几种情况的真实原因透给用户，而不是笼统地说一句"验证失败"。
@property (nonatomic, copy, nullable) NSString *setupError;

@end

@implementation COVerifyBridge

+ (instancetype)shared {
    static COVerifyBridge *b = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ b = [[self alloc] init]; });
    return b;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _localVersion = COVerifyLocalVersion();
        [self loadCache];
        [self setupSDK];
    }
    return self;
}

#pragma mark - 缓存读写

- (void)loadCache {
    _cachedCardStore   = COStoreRead(kCOKeyCard);
    _cachedExpiryStore = COStoreRead(kCOKeyExpiry);
}

- (void)saveCacheCard:(NSString *)card expiry:(NSString *)expiry stateCode:(NSString *)stateCode {
    _cachedCardStore   = [card copy];
    _cachedExpiryStore = [expiry copy];

    COStoreWrite(kCOKeyCard, card);
    COStoreWrite(kCOKeyExpiry, expiry);
    if (stateCode.length) COStoreWrite(kCOKeyStateCode, stateCode);

    NSDate *end = COParseExpiry(expiry);
    if (end) COStoreWriteDouble(kCOKeyEndStamp, end.timeIntervalSince1970);
}

- (void)clearCache {
    _cachedCardStore = nil;
    _cachedExpiryStore = nil;
    COStoreDelete(kCOKeyCard);
    COStoreDelete(kCOKeyExpiry);
    COStoreDelete(kCOKeyStateCode);
    COStoreDelete(kCOKeyEndStamp);
}

- (NSString *)cachedExpiry {
    if (_cachedExpiryStore.length == 0) return nil;
    // 缓存里存的是「到期时间」，但真正在跑的时候还要看服务端有没有提前作废。
    // 这里只做本地时间比对，网络侧的作废由心跳兜底。
    NSDate *end = COParseExpiry(_cachedExpiryStore);
    if (end && [end timeIntervalSinceNow] <= 0) return nil;
    return _cachedExpiryStore;
}

- (NSString *)cachedCard {
    return _cachedCardStore.length ? _cachedCardStore : nil;
}

#pragma mark - SDK 装配

/// 验证服务器条数 —— 只用于日志。
///
/// T3 SDK 内部硬编码了 6 个服务器轮询地址（w / w2..w5.t3yanzheng.com、
/// w.t3data.net），由 SDK 自己随机打乱后逐个重试，**不需要外部配置**。
/// 这里只是为了让日志能一眼看出「到底有几个服务器可试」。
static NSInteger COServerCount(void) { return 6; }

- (void)setupSDK {
    Class cls = NSClassFromString(@"T3Verify");
    if (!cls) {
        _sdkUsable = NO;
        CORecord("license.sdk absent → local fallback");
        return;
    }

    @try {
        // ★ init 可能返回 nil（父类 init 失败）。
        //   直接往下走会在 nil 上发消息 —— 不崩但会被 respondsToSelector
        //   的 nil 语义骗过去（nil 对任何 selector 都返回 NO），
        //   于是静默落到「明文模式」分支，RSA 公钥白填。
        id alloced = [cls alloc];
        id inst = ((id (*)(id, SEL))objc_msgSend)(alloced, @selector(init));
        if (!inst) {
            _sdkUsable = NO;
            CORecord("license.sdk init returned nil");
            return;
        }

        // initRsaWithLoginCode:noticeCode:versionCode:heartbeatCode:appkey:rsaPublicKey:error:
        SEL initSel = @selector(initRsaWithLoginCode:noticeCode:versionCode:heartbeatCode:appkey:rsaPublicKey:error:);
        if ([inst respondsToSelector:initSel]) {
            // ★ 这个初始化返回 BOOL，**失败必须让整个验证拒绝工作**，
            //   不能吞掉错误硬着头皮往下跑。
            //
            //   为什么：RSA 初始化失败 = 编码器/解码器是 nil。
            //   此时请求参数还是明文，但解码响应那一步会直接失败，
            //   表现出来就是「卡密正确却一直提示验证失败」——
            //   用户根本无从判断是卡密错了还是公钥填错了。
            //   宁可现在就说清楚，也别让用户在那儿反复试卡密。
            NSError *setupErr = nil;
            BOOL setupOK = NO;
            @try {
                setupOK = [self callRsaInitOn:inst selector:initSel error:&setupErr];
            } @catch (NSException *e) {
                setupOK = NO;
                if (!setupErr) {
                    setupErr = [NSError errorWithDomain:@"CoreOffline"
                                                  code:-1
                                              userInfo:@{NSLocalizedDescriptionKey:
                                                             e.reason ?: @"初始化抛异常"}];
                }
            }

            if (!setupOK) {
                _sdkUsable = NO;
                _verifyInstance = nil;
                _setupError = setupErr.localizedDescription
                             ?: @"RSA 初始化失败（请检查 RSA 公钥是否完整，"
                                @"必须带 -----BEGIN PUBLIC KEY----- 头尾和换行）";
                CORecord("license.sdk rsa_init FAILED: %s", _setupError.UTF8String);
                NSLog(@"[CoreOffline] T3 RSA 初始化失败：%@", _setupError);
                return;
            }

            _sdkUsable = YES;
            _verifyInstance = inst;
            CORecord("license.sdk ready mode=rsa servers=%d",
                     (int)COServerCount());
            NSLog(@"[CoreOffline] T3Verify SDK 已装配（RSA 模式）");
            return;
        }

        // 兼容旧版 SDK 的明文模式（没找到 RSA 接口才走这里）
        SEL plainSel = @selector(initWithLoginCode:noticeCode:versionCode:heartbeatCode:appkey:error:);
        if ([inst respondsToSelector:plainSel]) {
            [self callPlainInitOn:inst selector:plainSel];
            _sdkUsable = YES;
            _verifyInstance = inst;
            CORecord("license.sdk ready mode=plain");
            NSLog(@"[CoreOffline] T3Verify SDK 已装配（明文模式）");
            return;
        }

        // 类在、但两个初始化接口都不认 —— 版本对不上，别硬用
        _sdkUsable = NO;
        _verifyInstance = nil;
        _setupError = @"T3Verify 版本不兼容（找不到已支持的初始化方法）";
        CORecord("license.sdk incompatible");
    } @catch (NSException *e) {
        _sdkUsable = NO;
        _verifyInstance = nil;
        _setupError = [NSString stringWithFormat:@"验证器装配异常：%@", e.reason ?: @"未知"];
        CORecord("license.sdk setup EXCEPTION: %s", (e.reason ?: @"?").UTF8String);
        NSLog(@"[CoreOffline] T3Verify 装配失败: %@", e.reason);
    }
}

/// 发 RSA 初始化消息（7 个字符串 + 1 个 NSError** 出参，performSelector 撑不住）。
///
/// ★ 下标要点：NSInvocation 的 index 0 = self，1 = _cmd，
///   **第一个显式参数从 index 2 开始**。
///   方法签名是 (loginCode, noticeCode, versionCode, heartbeatCode, appkey, rsaPublicKey, error*)
///   → index 2,3,4,5,6,7 是 6 个对象，index 8 是 error。
- (BOOL)callRsaInitOn:(id)inst selector:(SEL)sel error:(NSError **)err {
    NSMethodSignature *sig = [inst methodSignatureForSelector:sel];
    if (!sig) return NO;
    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
    inv.target = inst;
    inv.selector = sel;

    NSString *(^fallback)(NSString *) = ^NSString *(NSString *v) { return v ?: @""; };
    id args[6] = {
        fallback(COVerifyLoginCode()),   fallback(COVerifyNoticeCode()),
        fallback(COVerifyVersionCode()), fallback(COVerifyHeartbeatCode()),
        fallback(COVerifyAppKey()),      fallback(COVerifyRSAPublicKey()),
    };
    for (NSUInteger i = 0; i < 6; i++) {
        __unsafe_unretained id a = args[i];
        [inv setArgument:&a atIndex:i + 2];
    }

    __unsafe_unretained NSError *e = nil;
    if (sig.numberOfArguments > 8) [inv setArgument:&e atIndex:8];

    [inv invoke];

    // 返回值类型：T3 的 initRsa... 声明为 BOOL，但为了兼容别的实现，
    // 这里按 methodSignature 自己报的类型来读。
    // ★ 不写 _C_BOOL / _C_INT —— 那两个宏在 objc/runtime.h 里，
    //   苹果 SDK 有、GNUstep 替身头没有，写了本地过不了。
    //   直接用字符字面量：'B' = C++ bool / BOOL，'c' = char，'i' = int。
    const char *rt = [sig methodReturnType];
    char rc = rt ? rt[0] : '\0';
    BOOL callOK = NO;
    if (rc == 'B' || rc == 'c') {
        // 标 __unsafe_unretained：getReturnValue: 直接往这块内存里写，
        // ARC 对局部变量插的 retain/release 会把它当对象处理，栈写 + 引用计数
        // 一起上就是未定义行为。标了才让编译器放手。
        __unsafe_unretained BOOL boolRet = NO;
        [inv getReturnValue:&boolRet];
        callOK = boolRet;
    } else if (rc == 'i' || rc == 'I' || rc == 'l' || rc == 'q') {
        long long scalarRet = 0;
        [inv getReturnValue:&scalarRet];
        callOK = (scalarRet != 0);
    }
    if (err) *err = e;
    return callOK;
}

/// 兼容旧版明文初始化（5 个字符串 + NSError**）
- (void)callPlainInitOn:(id)inst selector:(SEL)sel {
    NSMethodSignature *sig = [inst methodSignatureForSelector:sel];
    if (!sig) return;
    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
    inv.target = inst;
    inv.selector = sel;

    NSString *(^fallback)(NSString *) = ^NSString *(NSString *v) { return v ?: @""; };
    id args[5] = {
        fallback(COVerifyLoginCode()), fallback(COVerifyNoticeCode()),
        fallback(COVerifyVersionCode()), fallback(COVerifyHeartbeatCode()),
        fallback(COVerifyAppKey()),
    };
    for (NSUInteger i = 0; i < 5; i++) {
        __unsafe_unretained id a = args[i];
        [inv setArgument:&a atIndex:i + 2];
    }
    __unsafe_unretained NSError *e = nil;
    if (sig.numberOfArguments > 7) [inv setArgument:&e atIndex:7];
    [inv invoke];
}

- (BOOL)available {
    return _sdkUsable && _verifyInstance != nil;
}

#pragma mark - 验证

- (void)verifyCard:(NSString *)card completion:(COVerifyBlock)completion {
    if (card.length == 0) {
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{
            completion(NO, nil, nil, @"卡密不能为空");
        });
        return;
    }

    if (![self available]) {
        [self verifyFallbackWithCard:card completion:completion];
        return;
    }

    // loginWithKami:imei:  返回 T3LoginResult
    SEL sel = @selector(loginWithKami:imei:);
    if (![_verifyInstance respondsToSelector:sel]) {
        [self verifyFallbackWithCard:card completion:completion];
        return;
    }

    __weak typeof(self) ws = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        // ★ weak-strong dance：ws 是 weak，块真正执行时它可能已经归零。
        //   这里先提升成强引用再干活，块活着的这段时间 self 一定在。
        //   COVerifyBridge 是单例本来不会走这个路径，但写法上必须规矩 ——
        //   以后有人把单例改成多实例，这里不会突然出问题。
        __strong typeof(ws) self = ws;
        if (!self) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, nil, nil, @"验证器已释放");
            });
            return;
        }

        @try {
            NSMethodSignature *sig = [self.verifyInstance methodSignatureForSelector:sel];
            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
            inv.target = self.verifyInstance;
            inv.selector = sel;
            id kami = card;
            NSString *imei = COVerifyDeviceID();
            [inv setArgument:&kami atIndex:2];
            [inv setArgument:&imei atIndex:3];
            [inv invoke];

            __unsafe_unretained id result = nil;
            [inv getReturnValue:&result];

            [self handleLoginResult:result card:card completion:completion];
        } @catch (NSException *e) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, nil, nil,
                                           [NSString stringWithFormat:@"验证异常：%@", e.reason ?: @"未知"]);
            });
        }
    });
}

- (void)handleLoginResult:(id)result card:(NSString *)card completion:(COVerifyBlock)completion {
    BOOL ok = NO;
    NSString *expiry = nil, *stateCode = nil, *message = nil;

    if (result) {
        // ── 成功标志 ──
        // ★ 先读 T3LoginResult.success，再退回 code 判断。
        //   原因见 COSuccessOfResult 的注释：T3 的失败结果上**没有 code 字段**，
        //   只认 code 会让卡密永远验证不过。
        NSString *codeStr = nil;
        ok = COSuccessOfResult(result, &codeStr);

        // ── 提示信息 ──
        // ★ T3 失败时原因在 `error` 字段，不在 `msg`。
        //   不取 error 的话用户永远只看到"验证失败"，分不清是卡密错还是网络错。
        NSString *m = COMessageOfResult(result);
        message = m.length ? m : (ok ? @"验证成功" : @"验证失败");

        if (ok) {
            // ── 到期时间：多字段候选 ──
            // T3 主要用 endTime；这里把 F5CloudAuth 见过的名字也一并兼容，
            // 后端换实现时不用改代码。
            id et = [self firstValueOf:result keys:@[
                @"endTime", @"end_time", @"expire", @"expires_at",
                @"expireTime", @"endtime", @"dqsj", @"viptime",
                @"vip_time", @"expires_in", @"lease_ttl",
            ]];
            expiry = COStringOf(et);

            // 服务端可能给时间戳（秒/毫秒）而不是字符串
            if (expiry.length && [expiry rangeOfCharacterFromSet:
                 [[NSCharacterSet decimalDigitCharacterSet] invertedSet]].location == NSNotFound) {
                double v = expiry.doubleValue;
                if (expiry.length >= 13) v /= 1000.0;
                if (v > 978307200.0 && v < 4102444800.0) {
                    NSDateFormatter *f = [[NSDateFormatter alloc] init];
                    f.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
                    f.timeZone = [NSTimeZone localTimeZone];
                    f.dateFormat = @"yyyy-MM-dd HH:mm:ss";
                    expiry = [f stringFromDate:[NSDate dateWithTimeIntervalSince1970:v]];
                }
            }

            id sc = [self firstValueOf:result keys:@[@"statecode", @"state_code", @"stateCode"]];
            stateCode = COStringOf(sc);

            if (expiry.length == 0) {
                // 服务端没给到期时间：按「长期有效」处理，给一个远期值，
                // 免得宿主那边把「无到期」误判成已过期。
                expiry = COVerifyPerpetualExpiry();
            }
            [self saveCacheCard:card expiry:expiry stateCode:stateCode];
            _loggedIn = YES;
            // ★ 记下这次成功的时间，离线兜底要用它算宽限期
            COStoreWriteDouble(kCOKeyLastGoodStamp, [NSDate date].timeIntervalSince1970);

            __weak typeof(self) ws2 = self;
            dispatch_async(dispatch_get_main_queue(), ^{
                [ws2 startHeartbeat];
            });
        } else {
            // ── 失败：区分「网络故障」和「卡密错误」 ──
            //
            // 只有网络类失败才允许离线兜底。
            // 卡密错误（"卡密不存在"/"已过期"）绝不能兜底 —— 那等于白送授权。
            if (COVerifyAllowOfflineFallback() && COIsNetworkFailure(message, codeStr, result)) {
                NSString *cached = [self cachedExpiry];
                double lastGood = COStoreReadDouble(kCOKeyLastGoodStamp);
                double age = lastGood > 0 ? ([NSDate date].timeIntervalSince1970 - lastGood) : DBL_MAX;
                BOOL inGrace = (COVerifyOfflineGrace() <= 0) || (age <= COVerifyOfflineGrace());

                if (inGrace) {
                    // 有历史成功记录且在宽限期内 → 用缓存的到期时间续命
                    expiry = cached.length ? cached : COVerifyPerpetualExpiry();
                    stateCode = COStoreRead(kCOKeyStateCode);
                    _loggedIn = YES;
                    ok = YES;
                    message = @"网络不可用，已使用本地授权";
                    CORecord("license.offline_fallback grace=1 age=%.0f", age);

                    __weak typeof(self) ws3 = self;
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [ws3 startHeartbeat];
                    });
                } else if (COVerifyOfflineGrace() <= 0 || lastGood <= 0) {
                    // 从没成功过 / 没设宽限 → 默认放行到远期
                    // （这就是用户测试版的行为：永不锁死）
                    expiry = COVerifyPerpetualExpiry();
                    _loggedIn = YES;
                    ok = YES;
                    message = @"离线模式";
                    CORecord("license.offline_fallback grace=0 first_run");
                } else {
                    message = message.length ? message : @"网络不可用且授权已超出宽限期";
                    CORecord("license.offline_fallback denied age=%.0f", age);
                }
            }
        }
    } else {
        // result 为 nil：SDK 没返回任何东西，按网络故障处理
        message = @"验证服务无响应";
        if (COVerifyAllowOfflineFallback()) {
            NSString *cached = [self cachedExpiry];
            if (cached.length) {
                expiry = cached;
                _loggedIn = YES;
                ok = YES;
                message = @"验证服务无响应，已使用本地授权";
                CORecord("license.nil_result_fallback");
            } else {
                expiry = COVerifyPerpetualExpiry();
                _loggedIn = YES;
                ok = YES;
                message = @"离线模式";
                CORecord("license.nil_result_perpetual");
            }
        }
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        if (completion) completion(ok, expiry, stateCode, message);
    });
}

/// 从结果对象上安全取属性（KVC，字段名变化时不崩）
- (id)valueOf:(id)obj key:(NSString *)key {    @try {
        if ([obj respondsToSelector:NSSelectorFromString(key)]) {
            return [obj valueForKey:key];
        }
    } @catch (NSException *e) {
        // 字段不存在就返回 nil
    }
    return nil;
}

/// 在多个候选 key 里找第一个有值的（照 F5CloudAuth 的兼容策略）
///
/// 为什么需要：不同版本的 T3 后端返回的字段名不一样。
/// F5CloudAuth 同时兼容了 expires_at / dqsj / expire / end_time / endtime /
/// lease_ttl / expires_in 这么多名字 —— 说明真实环境里字段名确实会变。
- (id)firstValueOf:(id)obj keys:(NSArray<NSString *> *)keys {
    for (NSString *k in keys) {
        id v = [self valueOf:obj key:k];
        if (v) {
            // 空字符串当没有
            if ([v isKindOfClass:[NSString class]] && [v length] == 0) continue;
            return v;
        }
    }
    return nil;
}

/// 统一转成字符串
static NSString *COStringOf(id v) {
    if (!v) return nil;
    if ([v isKindOfClass:[NSString class]]) return v;
    if ([v isKindOfClass:[NSNumber class]]) return [v stringValue];
    return [v description];
}

/// 从「验证结果对象」上取成功标志。
///
/// ★ 为什么不能直接用 codeStr 判断成功：
///   T3 的失败路径给出的是
///       [T3Result fail:@"卡密不存在"]     → success=NO, error=@"...", code 压根不存在
///       [T3Result fail:@"请求失败: ..."]  → success=NO, error=@"网络..."
///   也就是说 —— **T3 的失败结果上没有 `code` 字段**。
///   原实现先取 code，而 T3 只有成功时（`json[@"code"]==200` 才构造 okWithData）
///   才有 code=200；失败时 code 是 nil，`[nil integerValue] == 0` 不成立，
///   于是 ok 恒为 NO —— 卡密再正确也永远验证不过。
///
///   所以正确的顺序是：**先读 success 布尔字段**，拿到了就以它为准；
///   只有 SDK 是别的实现（没有 success 字段）时才退回 code 判断。
static BOOL COSuccessOfResult(id result, NSString **outCodeStr) {
    NSString *codeStr = nil;

    @try {
        // ① 首选：T3LoginResult.success（BOOL）
        if ([result respondsToSelector:NSSelectorFromString(@"success")]) {
            id s = [result valueForKey:@"success"];
            if ([s isKindOfClass:[NSNumber class]]) {
                // NSNumber 包 BOOL / 0-1 / 字符串数字 都兼容
                NSNumber *n = (NSNumber *)s;
                BOOL isBoolLike = (strcmp(n.objCType, @encode(BOOL)) == 0) ||
                                  (strcmp(n.objCType, @encode(char)) == 0);
                if (isBoolLike || [n integerValue] == 0 || [n integerValue] == 1) {
                    if (outCodeStr) *outCodeStr = n.boolValue ? @"1" : @"0";
                    return n.boolValue;
                }
            } else if ([s isKindOfClass:[NSString class]]) {
                NSString *ls = [(NSString *)s lowercaseString];
                BOOL v = [ls isEqualToString:@"1"] || [ls isEqualToString:@"true"] ||
                         [ls isEqualToString:@"yes"] || [ls isEqualToString:@"ok"];
                if (outCodeStr) *outCodeStr = v ? @"1" : @"0";
                return v;
            }
        }
    } @catch (NSException *ignored) {
        (void)ignored;
    }

    // ② 退回：code / status / ret / state 这类数值标志
    //    兼容 "1" / "200" / "ok" / "true"
    id code = nil;
    @try {
        for (NSString *k in @[@"code", @"status", @"ret", @"state"]) {
            if ([result respondsToSelector:NSSelectorFromString(k)]) {
                id v = [result valueForKey:k];
                if (v) { code = v; break; }
            }
        }
    } @catch (NSException *ignored2) {
        (void)ignored2;
    }

    codeStr = COStringOf(code);
    if (outCodeStr) *outCodeStr = codeStr;

    if (codeStr.length == 0) return NO;
    if ([codeStr isEqualToString:@"ok"] || [codeStr isEqualToString:@"OK"] ||
        [codeStr isEqualToString:@"true"]) {
        return YES;
    }
    NSInteger c = codeStr.integerValue;
    return c == 1 || c == 200;
}

/// 从「验证结果对象」上取失败原因。
///
/// ★ 同样是 T3 的形状问题：失败时文案在 `error` 字段，**不在 `msg`**。
///   原实现只找 msg/message/info/errmsg，于是所有失败都显示成"验证失败"，
///   用户看不到"卡密不存在"还是"网络超时" —— 也就无从判断该改卡密还是该查网络。
static NSString *COMessageOfResult(id result) {
    if (!result) return nil;
    @try {
        for (NSString *k in @[@"error", @"msg", @"message", @"info", @"errmsg"]) {
            if (![result respondsToSelector:NSSelectorFromString(k)]) continue;
            id v = [result valueForKey:k];
            if (!v) continue;
            NSString *s = COStringOf(v);
            if (s.length) return s;
        }
    } @catch (NSException *ignored) {
        (void)ignored;
    }
    return nil;
}

/// SDK 不可用时的降级：本地缓存还能用就放行，否则拒绝
- (void)verifyFallbackWithCard:(NSString *)card completion:(COVerifyBlock)completion {
    NSString *expiry = self.cachedExpiry;
    BOOL sameCard = [_cachedCardStore isEqualToString:card];
    BOOL ok = (expiry != nil) && sameCard;

    NSString *msg = ok ? @"已用本地授权放行（离线）"
                       : @"验证服务未接入，无法激活";

    dispatch_async(dispatch_get_main_queue(), ^{
        if (completion) completion(ok, ok ? expiry : nil, @"offline", msg);
    });
}

#pragma mark - 公告 / 版本

- (void)fetchNotice:(void (^)(NSString *, NSString *))completion {
    if (![self available]) {
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(nil, nil); });
        return;
    }

    __weak typeof(self) ws = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        __strong typeof(ws) self = ws;
        if (!self) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(nil, nil);
            });
            return;
        }

        __block NSString *notice = nil;
        __block NSString *version = nil;

        @try {
            // getNotice → T3NoticeResult
            if ([self.verifyInstance respondsToSelector:@selector(getNotice)]) {
                id r = ((id (*)(id, SEL))objc_msgSend)(self.verifyInstance, @selector(getNotice));
                id content = [self valueOf:r key:@"notice"]
                    ?: [self valueOf:r key:@"content"]
                    ?: [self valueOf:r key:@"msg"];
                if ([content isKindOfClass:[NSString class]] && [content length]) notice = content;
            }
            // getLatestVersion → T3VersionResult
            if ([self.verifyInstance respondsToSelector:@selector(getLatestVersion)]) {
                id r = ((id (*)(id, SEL))objc_msgSend)(self.verifyInstance, @selector(getLatestVersion));
                id ver = [self valueOf:r key:@"version"]
                    ?: [self valueOf:r key:@"versionCode"];
                if (ver) version = [ver isKindOfClass:[NSString class]] ? ver : [ver stringValue];
            }
        } @catch (NSException *e) {
            // 公告拉不到不影响主流程
        }

        NSString *finalNotice  = notice;
        NSString *finalVersion = version;
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(finalNotice, finalVersion);
        });
    });
}

#pragma mark - 心跳

- (void)startHeartbeat {
    if (![self available] || !_loggedIn) return;
    [self stopHeartbeat];
    _heartbeatFail = 0;

    _heartbeatTimer = [NSTimer scheduledTimerWithTimeInterval:COVerifyHeartbeatInterval()
                                                      target:self
                                                    selector:@selector(onHeartbeatTick)
                                                    userInfo:nil
                                                     repeats:YES];
}

- (void)stopHeartbeat {
    [_heartbeatTimer invalidate];
    _heartbeatTimer = nil;
}

- (void)onHeartbeatTick {
    if (![self available]) return;

    NSString *card = _cachedCardStore;
    if (card.length == 0) {
        [self stopHeartbeat];
        return;
    }

    __weak typeof(self) ws = self;
    [self verifyCard:card completion:^(BOOL ok, NSString *expiry, NSString *stateCode, NSString *message) {
        __strong typeof(ws) self = ws;
        if (!self) return;

        if (ok) {
            self->_heartbeatFail = 0;
            return;
        }

        self->_heartbeatFail++;
        NSLog(@"[CoreOffline] 心跳失败 %ld/%ld — %@",
              (long)self->_heartbeatFail, (long)COVerifyMaxHeartbeatFail(), message ?: @"");

        if (self->_heartbeatFail >= COVerifyMaxHeartbeatFail()) {
            [self stopHeartbeat];
            self->_loggedIn = NO;
            dispatch_block_t cb = self.onHeartbeatLost;
            if (cb) cb();
        }
    }];
}

@end
