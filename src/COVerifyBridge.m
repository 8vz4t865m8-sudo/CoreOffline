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
@property (nonatomic, copy)   NSString *cachedCardStore;
@property (nonatomic, copy)   NSString *cachedExpiryStore;

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

- (void)setupSDK {
    Class cls = NSClassFromString(@"T3Verify");
    if (!cls) {
        _sdkUsable = NO;
        NSLog(@"[CoreOffline] T3Verify SDK 未接入，卡密验证走本地缓存降级");
        return;
    }

    @try {
        id inst = ((id (*)(id, SEL))objc_msgSend)([cls alloc], @selector(init));

        // initRsaWithLoginCode:noticeCode:versionCode:heartbeatCode:appkey:rsaPublicKey:error:
        SEL initSel = @selector(initRsaWithLoginCode:noticeCode:versionCode:heartbeatCode:appkey:rsaPublicKey:error:);
        if (![inst respondsToSelector:initSel]) {
            // 可能用的是明文模式
            SEL plainSel = @selector(initWithLoginCode:noticeCode:versionCode:heartbeatCode:appkey:error:);
            if ([inst respondsToSelector:plainSel]) {
                NSError *err = nil;
                [self callInitOn:inst selector:plainSel error:&err];
            }
            _sdkUsable = YES;
        } else {
            NSError *err = nil;
            [self callInitOn:inst selector:initSel error:&err];
            _sdkUsable = YES;
        }

        _verifyInstance = inst;
        NSLog(@"[CoreOffline] T3Verify SDK 已装配");
    } @catch (NSException *e) {
        _sdkUsable = NO;
        NSLog(@"[CoreOffline] T3Verify 装配失败: %@", e.reason);
    }
}

/// 用 NSInvocation 发初始化消息：参数多、有出参指针，performSelector 撑不住
- (void)callInitOn:(id)inst selector:(SEL)sel error:(NSError **)err {
    NSMethodSignature *sig = [inst methodSignatureForSelector:sel];
    if (!sig) return;
    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
    inv.target = inst;
    inv.selector = sel;

    id args[] = {
        COVerifyLoginCode(), COVerifyNoticeCode(), COVerifyVersionCode(),
        COVerifyHeartbeatCode(), COVerifyAppKey(), COVerifyRSAPublicKey()
    };
    // 参数 0/1 是 self/_cmd，从 2 开始
    for (NSUInteger i = 0; i < 6; i++) {
        id a = args[i] ?: @"";
        [inv setArgument:&a atIndex:i + 2];
    }
    if (err) {
        NSError *e = nil;
        [inv setArgument:&e atIndex:8];
    }
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
        // 兼容 code / status / ret / state 等多个字段名，值兼容 "1" / 1 / true / "ok"
        id code = [self firstValueOf:result keys:@[@"code", @"status", @"ret", @"state"]];
        NSString *codeStr = COStringOf(code);

        ok = [codeStr isEqualToString:@"1"]
          || [codeStr isEqualToString:@"200"]
          || [codeStr isEqualToString:@"ok"]
          || [codeStr isEqualToString:@"OK"]
          || [codeStr isEqualToString:@"true"]
          || [code integerValue] == 1;

        // ── 提示信息 ──
        id msg = [self firstValueOf:result keys:@[@"msg", @"message", @"info", @"errmsg"]];
        NSString *m = COStringOf(msg);
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
