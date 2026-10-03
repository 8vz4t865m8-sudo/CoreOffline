//
//  COKeychain.h
//  CoreOffline —— 凭据安全存储
//
//  为什么要有这一层（而不是直接用 NSUserDefaults）：
//
//    1. NSUserDefaults 存在 <App>/Library/Preferences/<bundleid>.plist，
//       用户「清理缓存」或者用 iCleaner 扫一遍就没了 —— 卡密白买。
//    2. Keychain 由 securityd 托管，App 删了都还在（除非显式 delete），
//       刷机/换机才会清（因为我们用 ThisDeviceOnly）。
//    3. NSUserDefaults 的 plist 是明文，越狱设备上随便看。
//
//  参考实现：F5CloudAuth 的 BSUPXKeychain* 系列
//    - kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
//        · AfterFirstUnlock ：首次解锁后即可读（后台心跳也能读）
//        · ThisDeviceOnly    ：不进 iCloud 钥匙串、不参与备份迁移
//
//  双写策略（可选，见 COVaultWrite）：
//    Keychain 为主，另在 Documents 落一份带校验的副本。
//    清 Keychain 的「越狱破解工具」往往只清 Keychain，
//    留着文件副本能提高破解成本。
//

#ifndef CO_KEYCHAIN_H
#define CO_KEYCHAIN_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Keychain 服务名（本 App 专属命名空间）
/// 默认取 bundle id + ".license"，可用 COKeychainSetService 覆盖
FOUNDATION_EXPORT NSString *COKeychainService(void);
FOUNDATION_EXPORT void      COKeychainSetService(NSString * _Nullable service);

/// 读写删。value 为 nil / 空串时 COKeychainWrite 等价于删除。
FOUNDATION_EXPORT NSString * _Nullable COKeychainRead(NSString *account);
FOUNDATION_EXPORT BOOL      COKeychainWrite(NSString *account, NSString * _Nullable value);
FOUNDATION_EXPORT BOOL      COKeychainDelete(NSString *account);

/// 清空本服务下的所有条目（换绑/退出登录时用）
FOUNDATION_EXPORT void      COKeychainWipe(void);

/// 可用性：某些环境下 Keychain 不可用（无签名 / 模拟器 / entitlement 缺失），
/// 此时所有操作静默失败，上层要能感知并降级到 NSUserDefaults。
FOUNDATION_EXPORT BOOL      COKeychainAvailable(void);

#pragma mark - 保险箱：Keychain + 文件双写

/// 双写读取：优先 Keychain，Keychain 没有时回落到文件。
/// 读到文件副本会自动回填 Keychain（自愈）。
FOUNDATION_EXPORT NSString * _Nullable COVaultRead(NSString *key);

/// 双写写入：Keychain 和文件都写。两处都失败返回 NO。
FOUNDATION_EXPORT BOOL      COVaultWrite(NSString *key, NSString * _Nullable value);

/// 双写删除：两处都删。
FOUNDATION_EXPORT void      COVaultDelete(NSString *key);

NS_ASSUME_NONNULL_END

#endif /* CO_KEYCHAIN_H */
