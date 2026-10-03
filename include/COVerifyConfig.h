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

#pragma mark - 社群链接

/// 宿主首页「社区」按钮跳转地址（← 改成你自己的）
static inline NSString *COCommunityURL(void) { return @"https://t.me/your_channel"; }

#endif /* CO_VERIFY_CONFIG_H */
