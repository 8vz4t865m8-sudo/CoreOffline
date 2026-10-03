//
//  COEntry.h
//  CoreOffline —— 给宿主 dylib 用的纯 C 入口
//
//  为什么要有这一层：
//
//    宿主层（比如别的 tweak / dylib）想调用 CoreOffline 的授权能力时，
//    如果只能走 ObjC 消息，就得先 dlsym 到 objc_msgSend 再拼 selector，
//    还要自己 NSClassFromString 找 COVerifyBridge —— 很麻烦，而且
//    符号一旦被 strip 就找不到。
//
//    F5CloudAuth 的做法是导出一组 C 函数：
//        bsupx_c_verify_card / bsupx_c_has_lease / bsupx_c_clear ...
//    宿主直接 dlsym(RTLD_DEFAULT, "bsupx_c_verify_card") 就能用。
//
//  本文件对标它，导出 coreoffline_c_* 系列。
//
//  ★ 全部符号用 __attribute__((visibility("default"))) 保证不被 strip。
//  ★ 回调一律在主线程派发。
//  ★ 不抛异常：内部全部 @try 包住，失败走回调。
//

#ifndef CO_ENTRY_H
#define CO_ENTRY_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#ifdef __cplusplus
extern "C" {
#endif

/// 授权结果（与 F5CloudAuth 的 BSVerifyUltraProxyResult 对齐）
typedef struct {
    int32_t     success;        ///< 1 = 通过，0 = 拒绝
    int32_t     code;           ///< 服务端/本地错误码
    const char *message;        ///< 错误信息（UTF-8，勿 free，生命周期到回调结束）
    const char *expiry;         ///< "yyyy-MM-dd HH:mm:ss"（可能为 NULL）
} COAuthResult;

/// 授权回调。在主线程调用。
typedef void (*COAuthCallback)(COAuthResult result, void * _Nullable context);

#pragma mark - 验证

/// 用卡密激活。card 为 UTF-8 C 串，不得为 NULL。
void coreoffline_c_verify_card(const char *card,
                               void * _Nullable context,
                               COAuthCallback _Nullable callback);

/// 用本地已保存的卡密重新验证（心跳/续期用）
void coreoffline_c_verify_saved(void * _Nullable context,
                                COAuthCallback _Nullable callback);

/// 只读本地缓存判断是否已授权（不联网，立即返回）
int32_t coreoffline_c_has_license(void);

/// 本地缓存的到期时间字符串（无则返回 NULL）
const char * _Nullable coreoffline_c_license_expiry(void);

/// 本地缓存的卡密（无则返回 NULL）
const char * _Nullable coreoffline_c_license_card(void);

#pragma mark - 心跳

void coreoffline_c_start_heartbeat(void);
void coreoffline_c_stop_heartbeat(void);
/// 心跳连续失败次数
int32_t coreoffline_c_heartbeat_failures(void);

#pragma mark - 环境自检

/// 调试器附加？
int32_t coreoffline_c_debugger_attached(void);
/// 越狱？
int32_t coreoffline_c_jailbroken(void);
/// 存在可疑框架（frida / substrate / cycript ...）？
int32_t coreoffline_c_injected(void);
/// 系统代理 / VPN 是否开启
int32_t coreoffline_c_proxy_active(void);
/// 综合风控位（各位含义见 CO_RISK_* ）
int32_t coreoffline_c_risk_mask(void);

#define CO_RISK_DEBUGGER    (1 << 0)
#define CO_RISK_JAILBREAK   (1 << 1)
#define CO_RISK_INJECTED    (1 << 2)
#define CO_RISK_PROXY       (1 << 3)

/// 设备机器码（返回内部静态缓冲，勿 free）
const char * _Nullable coreoffline_c_machine_code(void);

#pragma mark - 清理

/// 清掉所有本地授权状态（Keychain + 文件 + NSUserDefaults）
void coreoffline_c_clear(void);

/// 弹一次内嵌的卡密验证页。宿主没自己做 UI 时用这个。
void coreoffline_c_present_dialog(void);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END

#endif /* CO_ENTRY_H */
