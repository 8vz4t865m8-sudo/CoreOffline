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
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - 本地存储 key

static NSString *const kCOKeyCard      = @"co_license_card";
static NSString *const kCOKeyExpiry    = @"co_license_expiry";
static NSString *const kCOKeyStateCode = @"co_license_statecode";
static NSString *const kCOKeyEndStamp  = @"co_license_end_stamp";

#pragma mark - 时间解析

/// "yyyy-MM-dd HH:mm:ss" → NSDate。失败返回 nil。
static NSDate *COParseExpiry(NSString *s) {
    if (s.length == 0) return nil;
    static NSDateFormatter *f = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        f = [[NSDateFormatter alloc] init];
        f.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        f.dateFormat = @"yyyy-MM-dd HH:mm:ss";
        f.timeZone = [NSTimeZone localTimeZone];
    });
    return [f dateFromString:s];
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
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    _cachedCardStore   = [d stringForKey:kCOKeyCard];
    _cachedExpiryStore = [d stringForKey:kCOKeyExpiry];
}

- (void)saveCacheCard:(NSString *)card expiry:(NSString *)expiry stateCode:(NSString *)stateCode {
    _cachedCardStore   = [card copy];
    _cachedExpiryStore = [expiry copy];

    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setObject:card forKey:kCOKeyCard];
    [d setObject:expiry forKey:kCOKeyExpiry];
    if (stateCode) [d setObject:stateCode forKey:kCOKeyStateCode];

    NSDate *end = COParseExpiry(expiry);
    if (end) [d setDouble:end.timeIntervalSince1970 forKey:kCOKeyEndStamp];
    [d synchronize];
}

- (void)clearCache {
    _cachedCardStore = nil;
    _cachedExpiryStore = nil;
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d removeObjectForKey:kCOKeyCard];
    [d removeObjectForKey:kCOKeyExpiry];
    [d removeObjectForKey:kCOKeyStateCode];
    [d removeObjectForKey:kCOKeyEndStamp];
    [d synchronize];
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
        // T3LoginResult: code / msg / endTime / statecode / kamiId ...
        id code = [self valueOf:result key:@"code"];
        id msg  = [self valueOf:result key:@"msg"];
        NSString *codeStr = [code isKindOfClass:[NSString class]] ? code : [code stringValue];

        // SDK 约定：code 为 "1" 或 1 表示成功
        ok = [codeStr isEqualToString:@"1"] || [code integerValue] == 1;

        NSString *m = [msg isKindOfClass:[NSString class]] ? msg : nil;
        message = m.length ? m : (ok ? @"验证成功" : @"验证失败");

        if (ok) {
            id et = [self valueOf:result key:@"endTime"];
            expiry = [et isKindOfClass:[NSString class]] ? et : nil;
            id sc = [self valueOf:result key:@"statecode"];
            stateCode = [sc isKindOfClass:[NSString class]] ? sc : [sc stringValue];

            if (expiry.length == 0) {
                // 服务端没给到期时间：按「长期有效」处理，给一个远期值，
                // 免得宿主那边把「无到期」误判成已过期。
                expiry = COVerifyPerpetualExpiry();
            }
            [self saveCacheCard:card expiry:expiry stateCode:stateCode];
            _loggedIn = YES;

            __weak typeof(self) ws2 = self;
            dispatch_async(dispatch_get_main_queue(), ^{
                [ws2 startHeartbeat];
            });
        }
    } else {
        message = @"验证服务无响应";
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        if (completion) completion(ok, expiry, stateCode, message);
    });
}

/// 从结果对象上安全取属性（KVC，字段名变化时不崩）
- (id)valueOf:(id)obj key:(NSString *)key {
    @try {
        if ([obj respondsToSelector:NSSelectorFromString(key)]) {
            return [obj valueForKey:key];
        }
    } @catch (NSException *e) {
        // 字段不存在就返回 nil
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
