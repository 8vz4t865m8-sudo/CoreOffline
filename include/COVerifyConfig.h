//
//  COVerifyConfig.h
//  CoreOffline —— 卡密验证配置（★ 你只需要改这个文件）
//
//  这里集中所有跟你的 T3 后端相关的值：
//    各种 code / appkey / RSA 公钥 / 心跳参数 / 设备 ID 生成方式。
//
//  值来自 T3 后台的「应用设置」页。注意 RSA 公钥必须带
//  -----BEGIN PUBLIC KEY----- 头尾和换行，直接整段粘进来即可。
//

#ifndef CO_VERIFY_CONFIG_H
#define CO_VERIFY_CONFIG_H

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>

#pragma mark - T3 后端凭据（← 改成你自己的）

/// 登录接口 code
static inline NSString *COVerifyLoginCode(void)  { return @"0AAD3A3337741A5B"; }
/// 公告接口 code
static inline NSString *COVerifyNoticeCode(void) { return @"7EB0F4A8272A7EBD"; }
/// 版本接口 code
static inline NSString *COVerifyVersionCode(void){ return @"61D5FC87F536273F"; }
/// 心跳接口 code
static inline NSString *COVerifyHeartbeatCode(void){ return @"A44066FE62E69F9D"; }
/// 应用 appkey
static inline NSString *COVerifyAppKey(void)     { return @"1e45cd9daa2d5d7dfc6d8e66abe43b0a"; }

/// RSA 公钥（PEM，含头尾；T3 后台用 RSA 模式时必须填）
static inline NSString *COVerifyRSAPublicKey(void) {
    return @"-----BEGIN PUBLIC KEY-----\n"
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYYJ1hSbVwyCrgpkYi/XuCd9Jm\n"
            "FFji4HfuEG9g17rXkYRmj72xNIKZYZgIMH/8gpiS5AI660o0mMdhYnuQsYEP+5ZD\n"
            "+wVoyiM7EQ9Qnc0hxy7U4dytDKLTJR0RTtpv3LcCIal+jB7yqXY0u0QzOycRY09C\n"
            "4ewpg/EmXG9CslntyQIDAQAB\n"
            "-----END PUBLIC KEY-----";
}

/// 验证服务器地址 —— **不用配，SDK 内部已经写死了**。
///
/// ★ 别被旧注释误导（这里原来让你填域名/IP，是错的）：
///   T3 官方 SDK 在 sdk/T3Verify.m 里硬编码了 6 个服务器，
///   init 时用 arc4random_uniform 洗牌，请求时逐个重试，
///   全部打不通才报「无法连接到所有T3网络验证服务器」：
///
///       https://w.t3yanzheng.com/
///       https://w2.t3yanzheng.com/
///       https://w3.t3yanzheng.com/
///       https://w4.t3yanzheng.com/
///       https://w5.t3yanzheng.com/
///       https://w.t3data.net/
///
///   这套是 T3 自己的容灾机制（某台被打掉就自动换下一台），
///   在外部再配一遍反而会绕开它的故障转移。所以这里不留配置项。
///
/// 真要换线路：改 sdk/T3Verify.m 里 T3ServerURLs() 的数组。
/// 下面两个常量只为了让日志能看出「有几个可试的服务器」，不参与请求。

/// 可用的验证服务器条数（仅供日志；请求由 SDK 自己轮询）
static inline NSInteger COVerifyServerCount(void) { return 6; }

#pragma mark - 版本 / 心跳

/// 本地版本号（字符串，与 T3 后台登记的一致；服务端版本比它大就提示更新）
static inline NSString *COVerifyLocalVersion(void) { return @"1000"; }

/// 心跳间隔（秒）
static inline NSTimeInterval COVerifyHeartbeatInterval(void) { return 60.0; }

/// 心跳连续失败多少次判定掉线
static inline NSInteger COVerifyMaxHeartbeatFail(void) { return 5; }

/// 「长期有效」卡密用的远期到期时间。
///
/// 只在服务端明确不下发 endTime（永久卡）时使用。
/// 宿主那边拿这个值就是「不过期」，所以必须是一个明显在未来的日期 ——
/// 别改成过去的时间，那会让永久卡被当成已过期。
static inline NSString *COVerifyPerpetualExpiry(void) {
    return @"2099-12-31 23:59:59";
}

/// 「未授权」时回给宿主的到期时间。
///
/// ★ 这里刻意用「纪元 + 一秒」而不是 nil：
///   宿主拿到 nil 可能直接崩（比如塞进 NSDateFormatter），
///   给一个明确的「早得离谱」的时间戳，宿主就会乖乖走自带的过期流程。
///   判断是否未授权时用 COVerifyIsUnauthorized()，别去硬比字符串。
static inline NSString *COVerifyUnauthorizedExpiry(void) {
    return @"1970-01-01 00:00:01";
}

/// 判断一个到期时间串是不是「未授权」哨兵值
static inline BOOL COVerifyIsUnauthorized(NSString *expiry) {
    return expiry.length == 0 || [expiry isEqualToString:COVerifyUnauthorizedExpiry()];
}

#pragma mark - 设备 ID

/// 传给 T3 的设备标识。优先 IDFV，退化成机型+开机时长。
///
/// 为什么不用 IDFA：需要 ATT 授权，未授权时拿到一串 0，
/// 会导致同一台设备每次都被算成新设备。
static inline NSString *COVerifyDeviceID(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *idfv = [UIDevice currentDevice].identifierForVendor.UUIDString;
        if (idfv.length) {
            cached = idfv;
        } else {
            // IDFV 在某些场景（重装且无其他本厂商 App）会返回 nil，用机型 + 启动时间兜底
            size_t size = 0;
            sysctlbyname("hw.machine", NULL, &size, NULL, 0);
            char *machine = malloc(size);
            NSString *model = @"unknown";
            if (machine && sysctlbyname("hw.machine", machine, &size, NULL, 0) == 0) {
                model = [NSString stringWithUTF8String:machine] ?: @"unknown";
            }
            if (machine) free(machine);
            cached = [NSString stringWithFormat:@"%@-%lld", model,
                      (long long)([NSDate date].timeIntervalSince1970)];
        }
    });
    return cached;
}

#pragma mark - 目标宿主

/// ★★ 目标宿主的 Bundle ID —— 注入后只对这个 App 生效。
///
/// 原始测试版在构造函数第一件事就是校验它（反汇编 0x4b3c-0x4b7c）：
///     NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
///     if (![bid isEqualToString:@"qingxiugai.qingxiugai.qinxiugai"]) return;
///
/// 不匹配就直接退出，什么都不做。这是原版的安全阀 ——
/// 注入到别的 App 时不会干扰别人，也不会因为内部假设不成立而崩。
///
/// 换宿主 App 时改这里。
static inline NSString *CoreHostBundleID(void) {
    return @"qingxiugai.qingxiugai.qinxiugai";
}

/// 宿主首页「社区」按钮跳转地址（← 改成你自己的）
/// 原始测试版 / ViaOffline 用的都是 @"https://t.me/cheatrev"（Telegram 推广）
static inline NSString *COCommunityURL(void) { return @"https://t.me/cheatrev"; }

#pragma mark - 离线兜底（★ 照用户测试版的行为）

/// 网络不可用 / 服务器打不通时，是否回落到「永久授权」。
///
/// ★ 为什么要这个开关：
///   用户原来的测试版 CoreOffline.work.dylib 是**纯离线**的 ——
///   它内部状态机直接吐 2099-12-31 23:59:59，从不联网，所以永远不闪退、不锁死。
///   换成联网验证后，服务器一挂用户就被挡在门外，体验是倒退。
///   打开这个开关（默认 YES）就保持测试版的「永不锁死」特性：
///   联网成功 → 用服务器的真实到期时间；联网失败 → 用 COVerifyPerpetualExpiry()。
///
/// 关掉（NO）则变成严格模式：没网就等于没授权，适合需要真风控的场景。
static inline BOOL COVerifyAllowOfflineFallback(void) { return YES; }

/// 离线授权的宽限期（秒）。上次成功验证后多久之内断网仍算有效。
/// 0 表示不设宽限（每次启动都必须联网成功）。
static inline NSTimeInterval COVerifyOfflineGrace(void) { return 7 * 24 * 3600.0; }


#pragma mark - 保活优先（★ 默认开启，决定「能不能进软件」）

/// 启动自检的总时限（秒）。
///
/// 从构造函数起算，超过这个时间还没走到「已授权」，
/// 就直接给宿主一个远期到期时间放行 —— 绝不把用户关在门外。
///
/// ★ 为什么要这个：
///   用户的原始测试版是**纯离线**的，构造函数里就把状态机跑完，
///   从来不存在「卡在验证页」这种状态。接了联网验证之后，
///   一旦网络慢/服务器抖/弹窗出不来，用户就进不去软件 —— 体验是倒退。
///   这个看门狗保证：最坏情况也只是「没验上但先进去」。
///
///   正常网络下 T3 一般 1 秒内就回来了，这个时限根本不会触发。
static inline NSTimeInterval COVerifyFailOpenAfter(void) { return 12.0; }

#pragma mark - 社群链接

#endif /* CO_VERIFY_CONFIG_H */
