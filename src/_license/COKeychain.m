//
//  COKeychain.m
//  CoreOffline —— 凭据安全存储实现
//

#import "COKeychain.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

#pragma mark - 服务名

static NSString *gCOService = nil;

NSString *COKeychainService(void) {
    if (gCOService.length) return gCOService;
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (bid.length == 0) bid = @"com.coreoffline.work";
    return [bid stringByAppendingString:@".license"];
}

void COKeychainSetService(NSString *service) {
    gCOService = [service copy];
}

#pragma mark - Query 构造

static NSMutableDictionary *COBaseQuery(NSString *account) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass]       = (__bridge id)kSecClassGenericPassword;
    q[(__bridge id)kSecAttrService] = COKeychainService();
    if (account.length) {
        q[(__bridge id)kSecAttrAccount] = account;
    }
    return q;
}

#pragma mark - 基础读写删

NSString *COKeychainRead(NSString *account) {
    if (account.length == 0) return nil;

    NSMutableDictionary *q = COBaseQuery(account);
    q[(__bridge id)kSecReturnData]      = @YES;
    q[(__bridge id)kSecMatchLimit]      = (__bridge id)kSecMatchLimitOne;

    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st != errSecSuccess || out == NULL) return nil;

    NSData *data = (__bridge_transfer NSData *)out;
    if (data.length == 0) return nil;

    // 先按 UTF-8 解；失败说明里面是二进制（比如加密后的 blob）
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return s;
}

BOOL COKeychainWrite(NSString *account, NSString *value) {
    if (account.length == 0) return NO;

    if (value.length == 0) {
        return COKeychainDelete(account);
    }

    NSData *payload = [value dataUsingEncoding:NSUTF8StringEncoding];
    if (!payload) return NO;

    // 先试着「更新」，更新不到再「新增」。
    // 直接 SecItemAdd 会因 errSecDuplicateItem 失败，
    // 直接 SecItemUpdate 在不存在时返回 errSecItemNotFound。
    NSMutableDictionary *q = COBaseQuery(account);
    NSDictionary *attrs = @{
        (__bridge id)kSecValueData: payload,
    };

    OSStatus st = SecItemUpdate((__bridge CFDictionaryRef)q,
                                (__bridge CFDictionaryRef)attrs);
    if (st == errSecSuccess) return YES;

    if (st == errSecItemNotFound) {
        NSMutableDictionary *add = COBaseQuery(account);
        add[(__bridge id)kSecValueData] = payload;
        // ★ ThisDeviceOnly：不参与 iCloud 钥匙串同步，也不随备份迁移到新机。
        //   换机后需要重新激活 —— 对卡密系统来说这是正确行为。
        //   AfterFirstUnlock：设备首次解锁后即可读，后台心跳拿得到。
        add[(__bridge id)kSecAttrAccessible] =
            (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;

        OSStatus st2 = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
        return st2 == errSecSuccess;
    }

    return NO;
}

BOOL COKeychainDelete(NSString *account) {
    if (account.length == 0) return NO;
    NSMutableDictionary *q = COBaseQuery(account);
    OSStatus st = SecItemDelete((__bridge CFDictionaryRef)q);
    return st == errSecSuccess || st == errSecItemNotFound;
}

void COKeychainWipe(void) {
    NSMutableDictionary *q = COBaseQuery(nil);   // 不带 account = 整个 service
    SecItemDelete((__bridge CFDictionaryRef)q);
}

BOOL COKeychainAvailable(void) {
    // 用一个临时 key 探一次：写得进也读得出，才算可用。
    // 某些环境（无有效签名 / 缺 entitlement / 受限沙箱）会全部 errSecMissingEntitlement。
    static BOOL probed = NO;
    static BOOL usable = NO;
    if (probed) return usable;
    probed = YES;

    NSString *probeKey = @"__co_probe__";
    NSString *token = [NSString stringWithFormat:@"%u", arc4random()];

    if (!COKeychainWrite(probeKey, token)) {
        usable = NO;
        return NO;
    }
    NSString *back = COKeychainRead(probeKey);
    COKeychainDelete(probeKey);

    usable = [back isEqualToString:token];
    return usable;
}

#pragma mark - 保险箱：Keychain + 文件双写

// ── 文件副本路径 ──
// 放在 Documents 下的一个隐藏目录里。不用 Library/Caches —— 那个会被系统清。
static NSString *COVaultDir(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                          NSUserDomainMask, YES) firstObject];
    if (docs.length == 0) return nil;
    return [docs stringByAppendingPathComponent:@".syscache"];
}

static NSString *COVaultFilePath(NSString *key) {
    NSString *dir = COVaultDir();
    if (dir.length == 0 || key.length == 0) return nil;
    // 文件名做一次哈希，避免 key 里的特殊字符出问题
    NSData *raw = [key dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(raw.bytes, (CC_LONG)raw.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    return [dir stringByAppendingPathComponent:[hex substringToIndex:32]];
}

// 文件内容格式：  <salt-hex>:<sha256(salt|key|value)-hex>:<value>
// 单一 salt 能让「直接改文件」的人多花点功夫 —— 他不知道校验怎么算的。
// 这不是密码学意义上的强保护（salt 就在文件里），
// 目标是拦住「编辑器里改个日期」这种级别的破解。
static NSString *COSealValue(NSString *key, NSString *value) {
    uint32_t saltRaw = arc4random();
    NSString *salt = [NSString stringWithFormat:@"%08x", saltRaw];
    NSString *material = [NSString stringWithFormat:@"%@|%@|%@", salt, key, value];

    NSData *raw = [material dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(raw.bytes, (CC_LONG)raw.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    return [NSString stringWithFormat:@"%@:%@:%@", salt, hex, value];
}

static NSString *COUnsealValue(NSString *key, NSString *blob) {
    // salt:hash:value —— value 里可能有 ':'，所以按前两个 ':' 切
    NSRange r1 = [blob rangeOfString:@":"];
    if (r1.location == NSNotFound) return nil;
    NSRange r2 = [blob rangeOfString:@":"
                             options:0
                               range:NSMakeRange(r1.location + 1,
                                                 blob.length - r1.location - 1)];
    if (r2.location == NSNotFound) return nil;

    NSString *salt  = [blob substringToIndex:r1.location];
    NSString *hash  = [blob substringWithRange:NSMakeRange(r1.location + 1,
                                                          r2.location - r1.location - 1)];
    NSString *value = [blob substringFromIndex:r2.location + 1];

    NSString *material = [NSString stringWithFormat:@"%@|%@|%@", salt, key, value];
    NSData *raw = [material dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(raw.bytes, (CC_LONG)raw.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }

    if (![hex isEqualToString:hash]) return nil;   // 被改过
    return value;
}

static NSString *COVaultFileRead(NSString *key) {
    NSString *path = COVaultFilePath(key);
    if (path.length == 0) return nil;

    NSError *err = nil;
    NSString *blob = [NSString stringWithContentsOfFile:path
                                               encoding:NSUTF8StringEncoding
                                                  error:&err];
    if (blob.length == 0) return nil;

    return COUnsealValue(key, [blob stringByTrimmingCharactersInSet:
                               [NSCharacterSet whitespaceAndNewlineCharacterSet]]);
}

static BOOL COVaultFileWrite(NSString *key, NSString *value) {
    NSString *dir = COVaultDir();
    if (dir.length == 0) return NO;

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dir]) {
        NSError *err = nil;
        [fm createDirectoryAtPath:dir
      withIntermediateDirectories:YES
                       attributes:@{NSFileProtectionKey: NSFileProtectionCompleteUntilFirstUserAuthentication}
                            error:&err];
        if (err) return NO;
    }

    NSString *path = COVaultFilePath(key);
    if (path.length == 0) return NO;

    NSString *blob = COSealValue(key, value);
    NSError *err = nil;
    BOOL ok = [blob writeToFile:path
                     atomically:YES
                       encoding:NSUTF8StringEncoding
                          error:&err];
    if (ok) {
        // 让文件在首次解锁后可读（后台心跳要读）
        [fm setAttributes:@{NSFileProtectionKey:
                            NSFileProtectionCompleteUntilFirstUserAuthentication}
             ofItemAtPath:path
                    error:NULL];
    }
    return ok;
}

static void COVaultFileDelete(NSString *key) {
    NSString *path = COVaultFilePath(key);
    if (path.length == 0) return;
    [[NSFileManager defaultManager] removeItemAtPath:path error:NULL];
}

NSString *COVaultRead(NSString *key) {
    if (key.length == 0) return nil;

    // 1) Keychain 优先
    NSString *v = COKeychainRead(key);
    if (v.length) return v;

    // 2) 回落文件
    v = COVaultFileRead(key);
    if (v.length) {
        // 自愈：Keychain 被清了但文件还在，把 Keychain 补回来
        COKeychainWrite(key, v);
        return v;
    }
    return nil;
}

BOOL COVaultWrite(NSString *key, NSString *value) {
    if (key.length == 0) return NO;

    if (value.length == 0) {
        COVaultDelete(key);
        return YES;
    }

    BOOL a = COKeychainWrite(key, value);
    BOOL b = COVaultFileWrite(key, value);

    // 只要有一处成功就算成功 —— 不能因为 Keychain 不可用
    // （某些越狱环境/无签名场景）就让整个授权存不下来。
    return a || b;
}

void COVaultDelete(NSString *key) {
    if (key.length == 0) return;
    COKeychainDelete(key);
    COVaultFileDelete(key);
}
