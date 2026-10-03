/**
 * T3验证SDK - Objective-C 版本
 * 官网: https://www.t3yanzheng.com
 *
 * 纯 Apple 原生框架实现，零外部依赖，兼容 iOS 9+ / macOS 10.11+
 * 依赖: Foundation + Security.framework
 */

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// ============================================================
// 结果类型
// ============================================================

/// 通用结果
@interface T3Result : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *error;
@property (nonatomic, copy, nullable) NSString *msg;
+ (instancetype)ok;
+ (instancetype)okWithMsg:(nullable NSString *)msg;
+ (instancetype)fail:(NSString *)error;
@end

/// 登录结果
@interface T3LoginResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *error;
@property (nonatomic, copy, nullable) NSString *kamiId;
@property (nonatomic, copy, nullable) NSString *endTime;
@property (nonatomic, copy, nullable) NSString *statecode;
@property (nonatomic, copy, nullable) NSString *recharge;
@property (nonatomic, copy, nullable) NSString *useTime;
@property (nonatomic, copy, nullable) NSString *amount;
@property (nonatomic, copy, nullable) NSString *available;
@property (nonatomic, copy, nullable) NSString *imei;
@property (nonatomic, copy, nullable) NSString *change;
@property (nonatomic, copy, nullable) NSString *core;
+ (instancetype)okWithData:(NSDictionary *)data;
+ (instancetype)fail:(NSString *)error;
@end

/// 公告结果
@interface T3NoticeResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *error;
@property (nonatomic, copy, nullable) NSString *notice;
+ (instancetype)okWithNotice:(NSString *)notice;
+ (instancetype)fail:(NSString *)error;
@end

/// 版本结果
@interface T3VersionResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *error;
@property (nonatomic, copy, nullable) NSString *version;
+ (instancetype)okWithVersion:(NSString *)version;
+ (instancetype)fail:(NSString *)error;
@end

/// 查询卡密结果
@interface T3QueryResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *error;
@property (nonatomic, copy, nullable) NSString *state;
@property (nonatomic, copy, nullable) NSString *use;
@property (nonatomic, copy, nullable) NSString *kamiId;
@property (nonatomic, copy, nullable) NSString *useTime;
@property (nonatomic, copy, nullable) NSString *endTime;
@property (nonatomic, copy, nullable) NSString *lineTime;
@property (nonatomic, copy, nullable) NSString *line;
@property (nonatomic, copy, nullable) NSString *amount;
@property (nonatomic, copy, nullable) NSString *available;
+ (instancetype)okWithData:(NSDictionary *)data;
+ (instancetype)fail:(NSString *)error;
@end

/// 检查更新结果
@interface T3UpdateResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *error;
@property (nonatomic, assign) BOOL hasUpdate;
@property (nonatomic, copy, nullable) NSString *ver;
@property (nonatomic, copy, nullable) NSString *version;
@property (nonatomic, copy, nullable) NSString *uplog;
@property (nonatomic, copy, nullable) NSString *upurl;
@property (nonatomic, copy, nullable) NSString *msg;
+ (instancetype)updatedWithData:(NSDictionary *)data;
+ (instancetype)noUpdateWithMsg:(NSString *)msg;
+ (instancetype)fail:(NSString *)error;
@end

/// 变量结果
@interface T3VariableResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *error;
@property (nonatomic, copy, nullable) NSString *value;
+ (instancetype)okWithValue:(NSString *)value;
+ (instancetype)fail:(NSString *)error;
@end

/// 云文档结果
@interface T3CloudDocResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *error;
@property (nonatomic, copy, nullable) NSString *content;
+ (instancetype)okWithContent:(NSString *)content;
+ (instancetype)fail:(NSString *)error;
@end

/// 核心数据结果
@interface T3CoreResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *error;
@property (nonatomic, copy, nullable) NSString *core;
+ (instancetype)okWithCore:(NSString *)core;
+ (instancetype)fail:(NSString *)error;
@end

/// 在线数量结果
@interface T3OnlineResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *error;
@property (nonatomic, assign) NSInteger count;
+ (instancetype)okWithCount:(NSInteger)count;
+ (instancetype)fail:(NSString *)error;
@end

/// 应用签名结果
@interface T3AppSignResult : NSObject
@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *error;
@property (nonatomic, copy, nullable) NSString *msg;
@property (nonatomic, copy, nullable) NSString *autograph;
@property (nonatomic, strong, nullable) NSNumber *time;
+ (instancetype)fail:(NSString *)error;
@end


// ============================================================
// T3Verify SDK 主类
// ============================================================

@interface T3Verify : NSObject

@property (nonatomic, copy, nullable) NSString *statecode;
@property (nonatomic, copy, nullable) NSString *endTime;

/// 初始化 (Base64模式)
- (void)initWithLoginCode:(NSString *)loginCode
               noticeCode:(NSString *)noticeCode
              versionCode:(NSString *)versionCode
            heartbeatCode:(NSString *)heartbeatCode
                   appkey:(NSString *)appkey
            base64Charset:(NSString *)base64Charset;

/// 初始化 (RSA模式)
- (BOOL)initRsaWithLoginCode:(NSString *)loginCode
                  noticeCode:(NSString *)noticeCode
                 versionCode:(NSString *)versionCode
               heartbeatCode:(NSString *)heartbeatCode
                      appkey:(NSString *)appkey
                rsaPublicKey:(NSString *)rsaPublicKey
                       error:(NSError *_Nullable *_Nullable)error;

/// 设置新增调用码
- (void)setCode:(NSString *)field code:(NSString *)code;

// ===== 卡密验证 =====
- (T3LoginResult *)loginWithKami:(NSString *)kami imei:(NSString *)imei;
- (T3QueryResult *)queryKami:(NSString *)kami;
- (T3Result *)heartbeatWithKami:(NSString *)kami statecode:(NSString *)statecode;

// ===== 数据与内容 =====
- (T3NoticeResult *)getNotice;
- (T3VersionResult *)getLatestVersion;
- (T3UpdateResult *)checkUpdateWithVer:(NSString *)ver;
- (T3CloudDocResult *)getCloudDocWithToken:(NSString *)token;
- (T3AppSignResult *)appSignWithAutograph:(NSString *)autograph;

// ===== 用户体系 =====
- (T3Result *)userRegisterWithUser:(NSString *)user pass:(NSString *)pass email:(nullable NSString *)email;
- (T3LoginResult *)userLoginWithUser:(NSString *)user pass:(NSString *)pass imei:(NSString *)imei;
- (T3Result *)userHeartbeatWithUser:(NSString *)user pass:(NSString *)pass statecode:(NSString *)statecode;
- (T3LoginResult *)qqLoginWithOpenid:(NSString *)openid accessToken:(NSString *)accessToken;
- (T3Result *)bindQQWithUser:(NSString *)user pass:(NSString *)pass openid:(NSString *)openid accessToken:(NSString *)accessToken;
- (T3Result *)changePasswordWithUser:(NSString *)user oldpass:(NSString *)oldpass newpass:(NSString *)newpass;
- (T3Result *)userCancelWithUser:(NSString *)user pass:(NSString *)pass;
- (T3Result *)rechargeWithUser:(NSString *)user card:(NSString *)card;
- (T3Result *)kamiRechargeWithTargetKami:(NSString *)targetKami sourceKami:(NSString *)sourceKami;

// ===== QQ 凭证扩展与统一心跳 =====
- (T3Result *)qqHeartbeatWithOpenid:(NSString *)openid accessToken:(NSString *)accessToken statecode:(NSString *)statecode;
- (T3VariableResult *)getVariableByQqWithOpenid:(NSString *)openid accessToken:(NSString *)accessToken valueid:(NSString *)valueid valuename:(NSString *)valuename;
- (T3CoreResult *)getUserCoreByQqWithOpenid:(NSString *)openid accessToken:(NSString *)accessToken;
- (T3Result *)modifyUserCoreByQqWithOpenid:(NSString *)openid accessToken:(NSString *)accessToken core:(NSString *)core;
- (T3Result *)unbindQqWithUser:(NSString *)user pass:(NSString *)pass;
- (T3Result *)heartbeatAnyWithStatecode:(NSString *)statecode;

// ===== 设备与安全 =====
- (T3Result *)unbindKamiWithKami:(NSString *)kami imei:(NSString *)imei;
- (T3Result *)unbindUserWithUser:(NSString *)user pass:(NSString *)pass imei:(NSString *)imei;
- (T3Result *)ipUnbindKamiWithKami:(NSString *)kami;
- (T3Result *)ipUnbindUserWithUser:(NSString *)user pass:(NSString *)pass;
- (T3Result *)disableKamiWithKami:(NSString *)kami;
- (T3Result *)disableUserWithUser:(NSString *)user pass:(NSString *)pass;

// ===== 远程变量 =====
- (T3VariableResult *)getVariableByKami:(NSString *)kami valueid:(NSString *)valueid valuename:(NSString *)valuename;
- (T3VariableResult *)getVariableByUser:(NSString *)user pass:(NSString *)pass valueid:(NSString *)valueid valuename:(NSString *)valuename;
- (T3Result *)modifyVariableByKami:(NSString *)kami valueid:(NSString *)valueid valuecontent:(NSString *)valuecontent;
- (T3Result *)modifyVariableByUser:(NSString *)user pass:(NSString *)pass valueid:(NSString *)valueid valuecontent:(NSString *)valuecontent;

// ===== 核心数据 =====
- (T3Result *)modifyCoreByKami:(NSString *)kami core:(NSString *)core;
- (T3Result *)modifyCoreByUser:(NSString *)user pass:(NSString *)pass core:(NSString *)core;
- (T3CoreResult *)getCoreByKami:(NSString *)kami;
- (T3CoreResult *)getCoreByUser:(NSString *)user pass:(NSString *)pass;

// ===== 在线数量 =====
- (T3OnlineResult *)getOnlineKamiCount;
- (T3OnlineResult *)getOnlineUserCount;

/// 获取设备机器码
+ (NSString *)getMachineCode;

@end

NS_ASSUME_NONNULL_END
