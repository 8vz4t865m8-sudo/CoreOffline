//
//  COVerifyBridge.h
//  CoreOffline —— 卡密验证桥接层
//
//  为什么要有这一层：
//    1. 弹窗（COLicenseDialog）不该知道 T3 SDK 的存在，换验证后端时不出汗
//    2. T3 SDK 是可选依赖：宿主没带这个 SDK 时，dylib 必须能正常编译链接
//       并在运行时优雅降级（走本地缓存），而不是崩在 dlsym 上
//    3. CoreLicenseExpiryString() 要拿「上次验证成功的到期时间」，
//       这个状态需要一个明确的持有者
//
//  验证链路：
//    弹窗 → COVerifyBridge.verifyCard: → T3 SDK 动态调用 → 结果落盘 → 回调
//                                                    ↓
//                            CoreLicenseExpiryString() 读缓存
//

#ifndef CO_VERIFY_BRIDGE_H
#define CO_VERIFY_BRIDGE_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^COVerifyBlock)(BOOL ok,
                              NSString * _Nullable expiry,
                              NSString * _Nullable stateCode,
                              NSString * _Nullable message);

@interface COVerifyBridge : NSObject

+ (instancetype)shared;

/// T3 SDK 是否可用（宿主里能动态找到 T3Verify 类）
@property (nonatomic, readonly) BOOL available;

/// 本地版本号，与 SDK 初始化时传的 versionCode 对应
@property (nonatomic, copy, readonly) NSString *localVersion;

/// 上次验证成功的到期时间字符串（"yyyy-MM-dd HH:mm:ss"）。
/// 从未验证过、或缓存已过期时返回 nil。
@property (nonatomic, copy, readonly, nullable) NSString *cachedExpiry;

/// 上次验证成功的卡密，用于预填
@property (nonatomic, copy, readonly, nullable) NSString *cachedCard;

/// 验证卡密。结果异步回调在主线程。
/// 内部流程：SDK 可用 → 走网络；SDK 不可用 → 读本地缓存降级。
- (void)verifyCard:(NSString *)card completion:(COVerifyBlock)completion;

/// 拉公告与服务端版本号。拿不到就回调 nil，弹窗那边会自动隐藏对应区块。
- (void)fetchNotice:(void (^)(NSString * _Nullable notice, NSString * _Nullable version))completion;

/// 心跳：登录成功后周期性调用，连续失败超阈值会回调 onHeartbeatLost。
/// 未登录时调用无副作用。
- (void)startHeartbeat;
- (void)stopHeartbeat;

/// 心跳连续失败达到阈值时触发（主线程）。宿主可在这里退到验证页。
@property (nonatomic, copy, nullable) dispatch_block_t onHeartbeatLost;

/// 清掉本地缓存（卡密换绑、用户主动退出登录时用）
- (void)clearCache;

@end

NS_ASSUME_NONNULL_END

#endif /* CO_VERIFY_BRIDGE_H */
