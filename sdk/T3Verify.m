/**
 * T3验证SDK - Objective-C 版本
 * 官网: https://www.t3yanzheng.com
 *
 * 纯 Apple 原生框架实现，零外部依赖，兼容 iOS 9+ / macOS 10.11+
 * 依赖: Foundation + Security.framework
 */

#import "T3Verify.h"
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

// 服务器地址
static NSString *const T3_ALL_SERVERS_UNAVAILABLE = @"无法连接到所有T3网络验证服务器，可能是因为您的网络问题或T3网络验证服务器被攻击造成的，建议检查网络或稍后重试";
static NSArray<NSString *> *T3ServerURLs(void) {
    return @[@"https://w.t3yanzheng.com/", @"https://w2.t3yanzheng.com/", @"https://w3.t3yanzheng.com/",
             @"https://w4.t3yanzheng.com/", @"https://w5.t3yanzheng.com/", @"https://w.t3data.net/"];
}


#pragma mark - 工具函数

/// 字节数组转 HEX 大写字符串
static NSString *bytesToHex(const uint8_t *bytes, NSUInteger length) {
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (NSUInteger i = 0; i < length; i++) {
        [hex appendFormat:@"%02X", bytes[i]];
    }
    return [hex copy];
}

/// NSData 转 HEX 大写字符串
static NSString *dataToHex(NSData *data) {
    return bytesToHex(data.bytes, data.length);
}

/// MD5 哈希（返回32位小写十六进制）
static NSString *md5String(NSString *input) {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    return [result copy];
}


#pragma mark - CustomBase64

@interface T3CustomBase64 : NSObject
- (instancetype)initWithCustomCharset:(NSString *)customCharset;
- (NSString *)encode:(NSString *)data;
- (NSString *)decode:(NSString *)data;
- (NSString *)encodeToHex:(NSString *)data;
@end

@implementation T3CustomBase64 {
    NSString *_customCharset;
}

static NSString *const kStandardCharset = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

- (instancetype)initWithCustomCharset:(NSString *)customCharset {
    self = [super init];
    if (self) {
        NSAssert(customCharset.length == 64, @"自定义字符集必须是64位字符");
        _customCharset = [customCharset copy];
    }
    return self;
}

- (NSString *)encode:(NSString *)data {
    NSData *rawData = [data dataUsingEncoding:NSUTF8StringEncoding];
    NSString *standardB64 = [rawData base64EncodedStringWithOptions:0];
    
    NSMutableString *result = [NSMutableString stringWithCapacity:standardB64.length];
    for (NSUInteger i = 0; i < standardB64.length; i++) {
        unichar c = [standardB64 characterAtIndex:i];
        NSRange range = [kStandardCharset rangeOfString:[NSString stringWithCharacters:&c length:1]];
        if (range.location != NSNotFound) {
            [result appendFormat:@"%C", [_customCharset characterAtIndex:range.location]];
        } else {
            [result appendFormat:@"%C", c];
        }
    }
    return [result copy];
}

- (NSString *)decode:(NSString *)data {
    NSMutableString *standardB64 = [NSMutableString stringWithCapacity:data.length];
    for (NSUInteger i = 0; i < data.length; i++) {
        unichar c = [data characterAtIndex:i];
        NSRange range = [_customCharset rangeOfString:[NSString stringWithCharacters:&c length:1]];
        if (range.location != NSNotFound) {
            [standardB64 appendFormat:@"%C", [kStandardCharset characterAtIndex:range.location]];
        } else {
            [standardB64 appendFormat:@"%C", c];
        }
    }
    
    NSData *decoded = [[NSData alloc] initWithBase64EncodedString:standardB64 options:0];
    if (!decoded) return @"";
    return [[NSString alloc] initWithData:decoded encoding:NSUTF8StringEncoding] ?: @"";
}

- (NSString *)encodeToHex:(NSString *)data {
    NSString *encoded = [self encode:data];
    NSData *encodedData = [encoded dataUsingEncoding:NSUTF8StringEncoding];
    return dataToHex(encodedData);
}

@end


#pragma mark - BigUInt (轻量级大整数，仅用于 RSA 公钥解密)

/// 轻量级无符号大整数实现，仅支持 RSA 公钥解密所需的 modPow 运算
/// 使用 uint32_t 数组，小端序存储
@interface T3BigUInt : NSObject

@property (nonatomic, strong) NSMutableArray<NSNumber *> *digits; // uint32_t 小端序

- (instancetype)initWithValue:(uint32_t)value;
- (instancetype)initWithBytes:(const uint8_t *)bytes length:(NSUInteger)length;
- (NSData *)toBytesWithSize:(NSUInteger)size;
- (BOOL)isZero;

+ (T3BigUInt *)multiply:(T3BigUInt *)a with:(T3BigUInt *)b;
+ (T3BigUInt *)mod:(T3BigUInt *)a by:(T3BigUInt *)b;
+ (T3BigUInt *)modPowBase:(T3BigUInt *)base exp:(T3BigUInt *)exp mod:(T3BigUInt *)mod;

@end

@implementation T3BigUInt

- (instancetype)initWithValue:(uint32_t)value {
    self = [super init];
    if (self) {
        _digits = [NSMutableArray array];
        if (value != 0) {
            [_digits addObject:@(value)];
        }
    }
    return self;
}

- (instancetype)initWithBytes:(const uint8_t *)bytes length:(NSUInteger)length {
    self = [super init];
    if (self) {
        _digits = [NSMutableArray array];
        // 每 4 字节为一组，小端序排列
        NSInteger i = (NSInteger)length;
        while (i > 0) {
            NSInteger start = MAX(0, i - 4);
            uint32_t value = 0;
            for (NSInteger j = start; j < i; j++) {
                value = (value << 8) | bytes[j];
            }
            [_digits addObject:@(value)];
            i -= 4;
        }
        [self stripLeadingZeros];
    }
    return self;
}

- (void)stripLeadingZeros {
    while (_digits.count > 0 && [_digits.lastObject unsignedIntValue] == 0) {
        [_digits removeLastObject];
    }
}

- (BOOL)isZero {
    return _digits.count == 0;
}

- (NSData *)toBytesWithSize:(NSUInteger)size {
    NSMutableData *result = [NSMutableData dataWithLength:size];
    uint8_t *buf = (uint8_t *)result.mutableBytes;
    memset(buf, 0, size);
    
    NSInteger pos = (NSInteger)size - 1;
    for (NSUInteger idx = 0; idx < _digits.count && pos >= 0; idx++) {
        uint32_t val = [_digits[idx] unsignedIntValue];
        for (int b = 0; b < 4 && pos >= 0; b++) {
            buf[pos] = (uint8_t)(val & 0xFF);
            val >>= 8;
            pos--;
        }
    }
    return result;
}

- (T3BigUInt *)copy {
    T3BigUInt *c = [[T3BigUInt alloc] initWithValue:0];
    c.digits = [self.digits mutableCopy];
    return c;
}

// 比较: -1 小于, 0 等于, 1 大于
+ (int)compare:(T3BigUInt *)a with:(T3BigUInt *)b {
    if (a.digits.count != b.digits.count) {
        return a.digits.count < b.digits.count ? -1 : 1;
    }
    for (NSInteger i = (NSInteger)a.digits.count - 1; i >= 0; i--) {
        uint32_t av = [a.digits[i] unsignedIntValue];
        uint32_t bv = [b.digits[i] unsignedIntValue];
        if (av != bv) {
            return av < bv ? -1 : 1;
        }
    }
    return 0;
}

// 左移 1 位
+ (T3BigUInt *)shiftLeft1:(T3BigUInt *)a {
    if ([a isZero]) return [[T3BigUInt alloc] initWithValue:0];
    T3BigUInt *result = [[T3BigUInt alloc] initWithValue:0];
    result.digits = [NSMutableArray arrayWithCapacity:a.digits.count + 1];
    for (NSUInteger i = 0; i <= a.digits.count; i++) {
        [result.digits addObject:@(0)];
    }
    uint32_t carry = 0;
    for (NSUInteger i = 0; i < a.digits.count; i++) {
        uint32_t val = [a.digits[i] unsignedIntValue];
        result.digits[i] = @((val << 1) | carry);
        carry = val >> 31;
    }
    if (carry != 0) {
        result.digits[a.digits.count] = @(carry);
    }
    [result stripLeadingZeros];
    return result;
}

// 减法 (假设 a >= b)
+ (T3BigUInt *)subtract:(T3BigUInt *)a from:(T3BigUInt *)b {
    T3BigUInt *result = [[T3BigUInt alloc] initWithValue:0];
    result.digits = [NSMutableArray arrayWithCapacity:a.digits.count];
    for (NSUInteger i = 0; i < a.digits.count; i++) {
        [result.digits addObject:@(0)];
    }
    uint64_t borrow = 0;
    for (NSUInteger i = 0; i < a.digits.count; i++) {
        uint64_t aVal = [a.digits[i] unsignedIntValue];
        uint64_t bVal = (i < b.digits.count) ? [b.digits[i] unsignedIntValue] : 0;
        uint64_t diff;
        if (aVal >= bVal + borrow) {
            diff = aVal - bVal - borrow;
            borrow = 0;
        } else {
            diff = (uint64_t)0x100000000ULL + aVal - bVal - borrow;
            borrow = 1;
        }
        result.digits[i] = @((uint32_t)diff);
    }
    [result stripLeadingZeros];
    return result;
}

// 乘法
+ (T3BigUInt *)multiply:(T3BigUInt *)a with:(T3BigUInt *)b {
    if ([a isZero] || [b isZero]) return [[T3BigUInt alloc] initWithValue:0];
    NSUInteger n = a.digits.count;
    NSUInteger m = b.digits.count;
    T3BigUInt *result = [[T3BigUInt alloc] initWithValue:0];
    result.digits = [NSMutableArray arrayWithCapacity:n + m];
    for (NSUInteger i = 0; i < n + m; i++) {
        [result.digits addObject:@(0)];
    }
    
    for (NSUInteger i = 0; i < n; i++) {
        uint64_t carry = 0;
        uint64_t aVal = [a.digits[i] unsignedIntValue];
        for (NSUInteger j = 0; j < m; j++) {
            uint64_t bVal = [b.digits[j] unsignedIntValue];
            uint64_t product = aVal * bVal + [result.digits[i + j] unsignedIntValue] + carry;
            result.digits[i + j] = @((uint32_t)(product & 0xFFFFFFFF));
            carry = product >> 32;
        }
        result.digits[i + m] = @((uint32_t)([result.digits[i + m] unsignedIntValue] + carry));
    }
    
    [result stripLeadingZeros];
    return result;
}

// 取模 (使用位移长除法)
+ (T3BigUInt *)mod:(T3BigUInt *)a by:(T3BigUInt *)b {
    if ([b isZero]) {
        @throw [NSException exceptionWithName:@"T3BigUInt" reason:@"除以零" userInfo:nil];
    }
    if ([a isZero]) return [[T3BigUInt alloc] initWithValue:0];
    
    int cmp = [self compare:a with:b];
    if (cmp < 0) return [a copy];
    if (cmp == 0) return [[T3BigUInt alloc] initWithValue:0];
    
    T3BigUInt *remainder = [[T3BigUInt alloc] initWithValue:0];
    NSUInteger totalBits = a.digits.count * 32;
    
    for (NSInteger i = (NSInteger)totalBits - 1; i >= 0; i--) {
        remainder = [self shiftLeft1:remainder];
        NSUInteger wordIndex = i / 32;
        NSUInteger bitIndex = i % 32;
        if (wordIndex < a.digits.count && ([a.digits[wordIndex] unsignedIntValue] >> bitIndex) & 1) {
            if (remainder.digits.count == 0) {
                remainder.digits = [NSMutableArray arrayWithObject:@(1)];
            } else {
                uint32_t v = [remainder.digits[0] unsignedIntValue];
                remainder.digits[0] = @(v | 1);
            }
        }
        if ([self compare:remainder with:b] >= 0) {
            remainder = [self subtract:remainder from:b];
        }
    }
    
    return remainder;
}

// 模幂运算 (base^exp mod mod)
+ (T3BigUInt *)modPowBase:(T3BigUInt *)base exp:(T3BigUInt *)exp mod:(T3BigUInt *)mod {
    if ([mod isZero]) {
        @throw [NSException exceptionWithName:@"T3BigUInt" reason:@"模数不能为零" userInfo:nil];
    }
    T3BigUInt *result = [[T3BigUInt alloc] initWithValue:1];
    T3BigUInt *b = [self mod:base by:mod];
    NSUInteger totalBits = exp.digits.count * 32;
    
    for (NSUInteger i = 0; i < totalBits; i++) {
        NSUInteger wordIndex = i / 32;
        NSUInteger bitIndex = i % 32;
        if (wordIndex < exp.digits.count && ([exp.digits[wordIndex] unsignedIntValue] >> bitIndex) & 1) {
            result = [self mod:[self multiply:result with:b] by:mod];
        }
        b = [self mod:[self multiply:b with:b] by:mod];
    }
    
    return result;
}

@end


#pragma mark - RSACrypto

@interface T3RSACrypto : NSObject
- (instancetype)initWithPublicKeyPem:(NSString *)publicKeyPem error:(NSError **)error;
- (NSData *)encrypt:(NSString *)data error:(NSError **)error;
- (NSString *)decrypt:(NSData *)encryptedData error:(NSError **)error;
- (NSString *)encryptToHex:(NSString *)data error:(NSError **)error;
- (NSString *)decryptFromBase64:(NSString *)base64Str error:(NSError **)error;
@end

@implementation T3RSACrypto {
    SecKeyRef _publicKey;
    NSUInteger _keySize;        // 密钥字节数 (1024位 = 128字节)
    NSUInteger _encryptBlockSize; // 加密分段大小 (keySize - 11)
    NSUInteger _decryptBlockSize; // 解密分段大小 (keySize)
    T3BigUInt *_rsaN;           // 模数 n
    T3BigUInt *_rsaE;           // 指数 e
}

- (void)dealloc {
    if (_publicKey) {
        CFRelease(_publicKey);
    }
}

- (instancetype)initWithPublicKeyPem:(NSString *)publicKeyPem error:(NSError **)error {
    self = [super init];
    if (self) {
        // 清理公钥格式
        NSString *pem = [publicKeyPem stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (![pem hasPrefix:@"-----BEGIN"]) {
            pem = [NSString stringWithFormat:@"-----BEGIN PUBLIC KEY-----\n%@\n-----END PUBLIC KEY-----", pem];
        }
        
        // 提取 Base64 内容
        NSString *base64Key = pem;
        base64Key = [base64Key stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----" withString:@""];
        base64Key = [base64Key stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----" withString:@""];
        base64Key = [base64Key stringByReplacingOccurrencesOfString:@"-----BEGIN RSA PUBLIC KEY-----" withString:@""];
        base64Key = [base64Key stringByReplacingOccurrencesOfString:@"-----END RSA PUBLIC KEY-----" withString:@""];
        base64Key = [base64Key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
        base64Key = [base64Key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        base64Key = [base64Key stringByReplacingOccurrencesOfString:@" " withString:@""];
        
        NSData *keyData = [[NSData alloc] initWithBase64EncodedString:base64Key options:0];
        if (!keyData) {
            if (error) *error = [NSError errorWithDomain:@"T3Verify" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"RSA 公钥 Base64 解码失败"}];
            return nil;
        }
        
        // 解析 X.509 DER 获取 n 和 e
        NSData *nData = nil, *eData = nil;
        if (![self parseX509PublicKey:keyData n:&nData e:&eData error:error]) {
            return nil;
        }
        
        _rsaN = [[T3BigUInt alloc] initWithBytes:nData.bytes length:nData.length];
        _rsaE = [[T3BigUInt alloc] initWithBytes:eData.bytes length:eData.length];
        
        _keySize = nData.length;
        _encryptBlockSize = _keySize - 11;
        _decryptBlockSize = _keySize;
        
        // 提取 RSA 裸公钥数据（去除 AlgorithmIdentifier）创建 SecKey
        NSData *rsaPublicKeyData = [self extractRSAPublicKeyData:keyData error:error];
        if (!rsaPublicKeyData) {
            return nil;
        }
        
        NSDictionary *attributes = @{
            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
            (__bridge id)kSecAttrKeySizeInBits: @(_keySize * 8),
        };
        
        CFErrorRef cfError = NULL;
        _publicKey = SecKeyCreateWithData((__bridge CFDataRef)rsaPublicKeyData,
                                          (__bridge CFDictionaryRef)attributes,
                                          &cfError);
        if (!_publicKey) {
            NSString *desc = cfError ? (__bridge_transfer NSString *)CFErrorCopyDescription(cfError) : @"未知错误";
            if (cfError) CFRelease(cfError);
            if (error) *error = [NSError errorWithDomain:@"T3Verify" code:-2 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"创建 SecKey 失败: %@", desc]}];
            return nil;
        }
    }
    return self;
}

/// RSA 公钥加密（分段, PKCS1Padding）
- (NSData *)encrypt:(NSString *)data error:(NSError **)error {
    NSData *dataBytes = [data dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *encrypted = [NSMutableData data];
    NSUInteger offset = 0;
    
    while (offset < dataBytes.length) {
        NSUInteger end = MIN(offset + _encryptBlockSize, dataBytes.length);
        NSData *block = [dataBytes subdataWithRange:NSMakeRange(offset, end - offset)];
        
        CFErrorRef cfError = NULL;
        CFDataRef encryptedBlock = SecKeyCreateEncryptedData(_publicKey,
                                                             kSecKeyAlgorithmRSAEncryptionPKCS1,
                                                             (__bridge CFDataRef)block,
                                                             &cfError);
        if (!encryptedBlock) {
            NSString *desc = cfError ? (__bridge_transfer NSString *)CFErrorCopyDescription(cfError) : @"未知错误";
            if (cfError) CFRelease(cfError);
            if (error) *error = [NSError errorWithDomain:@"T3Verify" code:-3 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"RSA 加密失败: %@", desc]}];
            return nil;
        }
        [encrypted appendData:(__bridge_transfer NSData *)encryptedBlock];
        offset += _encryptBlockSize;
    }
    
    return encrypted;
}

/// RSA 公钥解密（分段, 用于解密服务端私钥加密的数据）
/// 服务端使用 openssl_private_encrypt 用私钥加密，客户端使用公钥解密
- (NSString *)decrypt:(NSData *)encryptedData error:(NSError **)error {
    NSMutableData *decrypted = [NSMutableData data];
    NSUInteger offset = 0;
    const uint8_t *bytes = encryptedData.bytes;
    
    while (offset < encryptedData.length) {
        NSUInteger end = MIN(offset + _decryptBlockSize, encryptedData.length);
        NSUInteger blockLen = end - offset;
        
        // 公钥解密: m = c^e mod n
        T3BigUInt *blockInt = [[T3BigUInt alloc] initWithBytes:bytes + offset length:blockLen];
        T3BigUInt *decryptedInt = [T3BigUInt modPowBase:blockInt exp:_rsaE mod:_rsaN];
        NSData *decryptedBlock = [decryptedInt toBytesWithSize:_keySize];
        
        // 移除 PKCS1 v1.5 填充: 0x00 0x01 [padding 0xFF...] 0x00 [data]
        const uint8_t *blockBytes = decryptedBlock.bytes;
        NSInteger padEnd = -1;
        for (NSUInteger i = 2; i < decryptedBlock.length; i++) {
            if (blockBytes[i] == 0x00) {
                padEnd = (NSInteger)i;
                break;
            }
        }
        if (padEnd != -1) {
            [decrypted appendBytes:blockBytes + padEnd + 1 length:decryptedBlock.length - padEnd - 1];
        } else {
            [decrypted appendData:decryptedBlock];
        }
        
        offset += _decryptBlockSize;
    }
    
    NSString *result = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
    if (!result) {
        if (error) *error = [NSError errorWithDomain:@"T3Verify" code:-4 userInfo:@{NSLocalizedDescriptionKey: @"RSA 解密后 UTF-8 解码失败"}];
        return nil;
    }
    return result;
}

/// RSA 公钥加密后转为 HEX 大写字符串
- (NSString *)encryptToHex:(NSString *)data error:(NSError **)error {
    NSData *encrypted = [self encrypt:data error:error];
    if (!encrypted) return nil;
    return dataToHex(encrypted);
}

/// 从 Base64 字符串解码后进行 RSA 公钥解密
- (NSString *)decryptFromBase64:(NSString *)base64Str error:(NSError **)error {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:base64Str options:0];
    if (!data) {
        if (error) *error = [NSError errorWithDomain:@"T3Verify" code:-5 userInfo:@{NSLocalizedDescriptionKey: @"Base64 解码失败"}];
        return nil;
    }
    return [self decrypt:data error:error];
}

#pragma mark - DER 解析工具

- (BOOL)readTag:(NSUInteger *)offset bytes:(const uint8_t *)bytes length:(NSUInteger)length expected:(uint8_t)expected error:(NSError **)error {
    if (*offset >= length) {
        if (error) *error = [NSError errorWithDomain:@"T3Verify" code:-6 userInfo:@{NSLocalizedDescriptionKey: @"DER 解析越界"}];
        return NO;
    }
    uint8_t tag = bytes[*offset];
    (*offset)++;
    if (tag != expected) {
        if (error) *error = [NSError errorWithDomain:@"T3Verify" code:-6 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"DER tag 不匹配: 期望 0x%02X, 实际 0x%02X", expected, tag]}];
        return NO;
    }
    return YES;
}

- (NSInteger)readLength:(NSUInteger *)offset bytes:(const uint8_t *)bytes length:(NSUInteger)totalLength error:(NSError **)error {
    if (*offset >= totalLength) {
        if (error) *error = [NSError errorWithDomain:@"T3Verify" code:-6 userInfo:@{NSLocalizedDescriptionKey: @"DER 解析越界"}];
        return -1;
    }
    NSInteger len = bytes[*offset];
    (*offset)++;
    if (len & 0x80) {
        NSInteger numBytes = len & 0x7F;
        len = 0;
        for (NSInteger i = 0; i < numBytes; i++) {
            if (*offset >= totalLength) {
                if (error) *error = [NSError errorWithDomain:@"T3Verify" code:-6 userInfo:@{NSLocalizedDescriptionKey: @"DER 解析越界"}];
                return -1;
            }
            len = (len << 8) | bytes[*offset];
            (*offset)++;
        }
    }
    return len;
}

/// 解析 X.509 SubjectPublicKeyInfo 格式的 DER 数据，提取 n 和 e
- (BOOL)parseX509PublicKey:(NSData *)data n:(NSData **)nData e:(NSData **)eData error:(NSError **)error {
    const uint8_t *bytes = data.bytes;
    NSUInteger length = data.length;
    NSUInteger offset = 0;
    
    // 外层 SEQUENCE
    if (![self readTag:&offset bytes:bytes length:length expected:0x30 error:error]) return NO;
    if ([self readLength:&offset bytes:bytes length:length error:error] < 0) return NO;
    
    // AlgorithmIdentifier SEQUENCE
    if (![self readTag:&offset bytes:bytes length:length expected:0x30 error:error]) return NO;
    NSInteger algLen = [self readLength:&offset bytes:bytes length:length error:error];
    if (algLen < 0) return NO;
    offset += algLen; // 跳过整个 AlgorithmIdentifier
    
    // BIT STRING
    if (![self readTag:&offset bytes:bytes length:length expected:0x03 error:error]) return NO;
    if ([self readLength:&offset bytes:bytes length:length error:error] < 0) return NO;
    offset += 1; // 跳过填充位数 (0x00)
    
    // 内层 SEQUENCE (RSAPublicKey)
    if (![self readTag:&offset bytes:bytes length:length expected:0x30 error:error]) return NO;
    if ([self readLength:&offset bytes:bytes length:length error:error] < 0) return NO;
    
    // INTEGER (Modulus / n)
    if (![self readTag:&offset bytes:bytes length:length expected:0x02 error:error]) return NO;
    NSInteger nLen = [self readLength:&offset bytes:bytes length:length error:error];
    if (nLen < 0) return NO;
    NSUInteger nStart = offset;
    offset += nLen;
    // 去掉前导0
    if (bytes[nStart] == 0x00) {
        nStart++;
        nLen--;
    }
    *nData = [NSData dataWithBytes:bytes + nStart length:nLen];
    
    // INTEGER (Exponent / e)
    if (![self readTag:&offset bytes:bytes length:length expected:0x02 error:error]) return NO;
    NSInteger eLen = [self readLength:&offset bytes:bytes length:length error:error];
    if (eLen < 0) return NO;
    NSUInteger eStart = offset;
    // 去掉前导0
    if (eLen > 1 && bytes[eStart] == 0x00) {
        eStart++;
        eLen--;
    }
    *eData = [NSData dataWithBytes:bytes + eStart length:eLen];
    
    return YES;
}

/// 从 X.509 SubjectPublicKeyInfo 中提取 RSA 公钥裸数据（PKCS#1 格式）
- (NSData *)extractRSAPublicKeyData:(NSData *)x509Data error:(NSError **)error {
    const uint8_t *bytes = x509Data.bytes;
    NSUInteger length = x509Data.length;
    NSUInteger offset = 0;
    
    // 外层 SEQUENCE
    if (![self readTag:&offset bytes:bytes length:length expected:0x30 error:error]) return nil;
    if ([self readLength:&offset bytes:bytes length:length error:error] < 0) return nil;
    
    // AlgorithmIdentifier SEQUENCE
    if (![self readTag:&offset bytes:bytes length:length expected:0x30 error:error]) return nil;
    NSInteger algLen = [self readLength:&offset bytes:bytes length:length error:error];
    if (algLen < 0) return nil;
    offset += algLen;
    
    // BIT STRING
    if (![self readTag:&offset bytes:bytes length:length expected:0x03 error:error]) return nil;
    if ([self readLength:&offset bytes:bytes length:length error:error] < 0) return nil;
    offset += 1; // 跳过 0x00 填充
    
    // 剩余部分就是 RSA 公钥裸数据
    return [NSData dataWithBytes:bytes + offset length:length - offset];
}

@end


#pragma mark - 结果类型实现

@implementation T3Result
+ (instancetype)ok {
    T3Result *r = [[T3Result alloc] init]; r.success = YES; return r;
}
+ (instancetype)okWithMsg:(NSString *)msg {
    T3Result *r = [[T3Result alloc] init]; r.success = YES; r.msg = msg; return r;
}
+ (instancetype)fail:(NSString *)error {
    T3Result *r = [[T3Result alloc] init]; r.success = NO; r.error = error; return r;
}
@end

@implementation T3LoginResult
+ (instancetype)okWithData:(NSDictionary *)data {
    T3LoginResult *r = [[T3LoginResult alloc] init]; r.success = YES;
    r.kamiId = [NSString stringWithFormat:@"%@", data[@"id"]];
    r.endTime = [NSString stringWithFormat:@"%@", data[@"end_time"]];
    r.statecode = data[@"statecode"];
    r.recharge = [NSString stringWithFormat:@"%@", data[@"recharge"] ?: @""];
    r.useTime = [NSString stringWithFormat:@"%@", data[@"use_time"] ?: @""];
    r.available = [NSString stringWithFormat:@"%@", data[@"available"] ?: @""];
    r.imei = data[@"imei"]; r.change = [NSString stringWithFormat:@"%@", data[@"change"] ?: @""];
    r.core = data[@"core"]; return r;
}
+ (instancetype)fail:(NSString *)error {
    T3LoginResult *r = [[T3LoginResult alloc] init]; r.success = NO; r.error = error; return r;
}
@end

@implementation T3NoticeResult
+ (instancetype)okWithNotice:(NSString *)notice {
    T3NoticeResult *r = [[T3NoticeResult alloc] init]; r.success = YES; r.notice = notice; return r;
}
+ (instancetype)fail:(NSString *)error {
    T3NoticeResult *r = [[T3NoticeResult alloc] init]; r.success = NO; r.error = error; return r;
}
@end

@implementation T3VersionResult
+ (instancetype)okWithVersion:(NSString *)version {
    T3VersionResult *r = [[T3VersionResult alloc] init]; r.success = YES; r.version = version; return r;
}
+ (instancetype)fail:(NSString *)error {
    T3VersionResult *r = [[T3VersionResult alloc] init]; r.success = NO; r.error = error; return r;
}
@end

@implementation T3QueryResult
+ (instancetype)okWithData:(NSDictionary *)data {
    T3QueryResult *r = [[T3QueryResult alloc] init]; r.success = YES;
    r.state = [NSString stringWithFormat:@"%@", data[@"state"] ?: @""];
    r.use = [NSString stringWithFormat:@"%@", data[@"use"] ?: @""];
    r.kamiId = [NSString stringWithFormat:@"%@", data[@"id"]];
    r.useTime = [NSString stringWithFormat:@"%@", data[@"use_time"] ?: @""];
    r.endTime = [NSString stringWithFormat:@"%@", data[@"end_time"]];
    r.lineTime = [NSString stringWithFormat:@"%@", data[@"line_time"] ?: @""];
    r.line = [NSString stringWithFormat:@"%@", data[@"line"] ?: @""];
    r.amount = [NSString stringWithFormat:@"%@", data[@"amount"] ?: @""];
    r.available = [NSString stringWithFormat:@"%@", data[@"available"] ?: @""];
    return r;
}
+ (instancetype)fail:(NSString *)error {
    T3QueryResult *r = [[T3QueryResult alloc] init]; r.success = NO; r.error = error; return r;
}
@end

@implementation T3UpdateResult
+ (instancetype)updatedWithData:(NSDictionary *)data {
    T3UpdateResult *r = [[T3UpdateResult alloc] init]; r.success = YES; r.hasUpdate = YES;
    r.ver = data[@"ver"]; r.version = data[@"version"]; r.uplog = data[@"uplog"]; r.upurl = data[@"upurl"]; return r;
}
+ (instancetype)noUpdateWithMsg:(NSString *)msg {
    T3UpdateResult *r = [[T3UpdateResult alloc] init]; r.success = YES; r.hasUpdate = NO; r.msg = msg; return r;
}
+ (instancetype)fail:(NSString *)error {
    T3UpdateResult *r = [[T3UpdateResult alloc] init]; r.success = NO; r.error = error; return r;
}
@end

@implementation T3VariableResult
+ (instancetype)okWithValue:(NSString *)value {
    T3VariableResult *r = [[T3VariableResult alloc] init]; r.success = YES; r.value = value; return r;
}
+ (instancetype)fail:(NSString *)error {
    T3VariableResult *r = [[T3VariableResult alloc] init]; r.success = NO; r.error = error; return r;
}
@end

@implementation T3CloudDocResult
+ (instancetype)okWithContent:(NSString *)content {
    T3CloudDocResult *r = [[T3CloudDocResult alloc] init]; r.success = YES; r.content = content; return r;
}
+ (instancetype)fail:(NSString *)error {
    T3CloudDocResult *r = [[T3CloudDocResult alloc] init]; r.success = NO; r.error = error; return r;
}
@end

@implementation T3CoreResult
+ (instancetype)okWithCore:(NSString *)core {
    T3CoreResult *r = [[T3CoreResult alloc] init]; r.success = YES; r.core = core; return r;
}
+ (instancetype)fail:(NSString *)error {
    T3CoreResult *r = [[T3CoreResult alloc] init]; r.success = NO; r.error = error; return r;
}
@end

@implementation T3OnlineResult
+ (instancetype)okWithCount:(NSInteger)count {
    T3OnlineResult *r = [[T3OnlineResult alloc] init]; r.success = YES; r.count = count; return r;
}
+ (instancetype)fail:(NSString *)error {
    T3OnlineResult *r = [[T3OnlineResult alloc] init]; r.success = NO; r.error = error; return r;
}
@end

@implementation T3AppSignResult
+ (instancetype)fail:(NSString *)error {
    T3AppSignResult *r = [[T3AppSignResult alloc] init]; r.success = NO; r.error = error; return r;
}
@end


#pragma mark - T3Verify 主类实现

@implementation T3Verify {
    NSArray<NSString *> *_serverUrls;
    NSString *_serverUrl;
    NSString *_loginCode, *_noticeCode, *_versionCode, *_heartbeatCode;
    NSString *_queryCode, *_registerCode, *_userLoginCode, *_userHeartbeatCode;
    NSString *_qqLoginCode, *_bindQQCode, *_changePasswordCode, *_userCancelCode;
    NSString *_rechargeCode, *_unbindCode, *_ipUnbindCode, *_disableCode;
    NSString *_checkUpdateCode, *_getVariableCode, *_modifyVariableCode, *_modifyCoreCode;
    NSString *_getKamiCoreCode, *_getUserCoreCode, *_onlineKamiCode, *_onlineUserCode;
    NSString *_cloudDocCode, *_appSignCode;
    NSString *_qqHeartbeatCode, *_getVariableByQqCode, *_getUserCoreByQqCode;
    NSString *_modifyUserCoreByQqCode, *_unbindQqCode, *_heartbeatAnyCode;
    NSString *_kamiRechargeCode;
    NSString *_appkey, *_encodeType;
    T3CustomBase64 *_encoder;
    T3RSACrypto *_rsaCrypto;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        NSMutableArray<NSString *> *urls = [T3ServerURLs() mutableCopy];
        for (NSUInteger i = urls.count; i > 1; i--) [urls exchangeObjectAtIndex:i - 1 withObjectAtIndex:arc4random_uniform((uint32_t)i)];
        _serverUrls = [urls copy]; _serverUrl = _serverUrls.firstObject; _encodeType = @"base64";
    }
    return self;
}

#pragma mark - 初始化方法

- (void)initWithLoginCode:(NSString *)loginCode noticeCode:(NSString *)noticeCode
              versionCode:(NSString *)versionCode heartbeatCode:(NSString *)heartbeatCode
                   appkey:(NSString *)appkey base64Charset:(NSString *)base64Charset {
    _loginCode = [loginCode copy]; _noticeCode = [noticeCode copy];
    _versionCode = [versionCode copy]; _heartbeatCode = [heartbeatCode copy];
    _appkey = [appkey copy]; _encodeType = @"base64";
    NSAssert(base64Charset.length == 64, @"Base64模式下必须提供64位字符集");
    _encoder = [[T3CustomBase64 alloc] initWithCustomCharset:base64Charset];
}

- (BOOL)initRsaWithLoginCode:(NSString *)loginCode noticeCode:(NSString *)noticeCode
                 versionCode:(NSString *)versionCode heartbeatCode:(NSString *)heartbeatCode
                      appkey:(NSString *)appkey rsaPublicKey:(NSString *)rsaPublicKey error:(NSError **)error {
    _loginCode = [loginCode copy]; _noticeCode = [noticeCode copy];
    _versionCode = [versionCode copy]; _heartbeatCode = [heartbeatCode copy];
    _appkey = [appkey copy]; _encodeType = @"rsa";
    if (rsaPublicKey.length == 0) {
        if (error) *error = [NSError errorWithDomain:@"T3Verify" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"RSA模式下必须提供 rsaPublicKey 参数"}];
        return NO;
    }
    _rsaCrypto = [[T3RSACrypto alloc] initWithPublicKeyPem:rsaPublicKey error:error];
    return (_rsaCrypto != nil);
}

- (void)setCode:(NSString *)field code:(NSString *)code {
    NSString *c = [code copy];
    if ([field isEqualToString:@"query"]) _queryCode = c;
    else if ([field isEqualToString:@"register"]) _registerCode = c;
    else if ([field isEqualToString:@"user_login"]) _userLoginCode = c;
    else if ([field isEqualToString:@"user_heartbeat"]) _userHeartbeatCode = c;
    else if ([field isEqualToString:@"qq_login"]) _qqLoginCode = c;
    else if ([field isEqualToString:@"bind_qq"]) _bindQQCode = c;
    else if ([field isEqualToString:@"change_password"]) _changePasswordCode = c;
    else if ([field isEqualToString:@"user_cancel"]) _userCancelCode = c;
    else if ([field isEqualToString:@"recharge"]) _rechargeCode = c;
    else if ([field isEqualToString:@"unbind"]) _unbindCode = c;
    else if ([field isEqualToString:@"ip_unbind"]) _ipUnbindCode = c;
    else if ([field isEqualToString:@"disable"]) _disableCode = c;
    else if ([field isEqualToString:@"check_update"]) _checkUpdateCode = c;
    else if ([field isEqualToString:@"get_variable"]) _getVariableCode = c;
    else if ([field isEqualToString:@"modify_variable"]) _modifyVariableCode = c;
    else if ([field isEqualToString:@"modify_core"]) _modifyCoreCode = c;
    else if ([field isEqualToString:@"get_kami_core"]) _getKamiCoreCode = c;
    else if ([field isEqualToString:@"get_user_core"]) _getUserCoreCode = c;
    else if ([field isEqualToString:@"online_kami"]) _onlineKamiCode = c;
    else if ([field isEqualToString:@"online_user"]) _onlineUserCode = c;
    else if ([field isEqualToString:@"cloud_doc"]) _cloudDocCode = c;
    else if ([field isEqualToString:@"app_sign"]) _appSignCode = c;
    else if ([field isEqualToString:@"qq_heartbeat"]) _qqHeartbeatCode = c;
    else if ([field isEqualToString:@"qq_get_variable"]) _getVariableByQqCode = c;
    else if ([field isEqualToString:@"qq_get_core"]) _getUserCoreByQqCode = c;
    else if ([field isEqualToString:@"qq_modify_core"]) _modifyUserCoreByQqCode = c;
    else if ([field isEqualToString:@"qq_unbind"]) _unbindQqCode = c;
    else if ([field isEqualToString:@"heartbeat_any"]) _heartbeatAnyCode = c;
    else if ([field isEqualToString:@"kami_recharge"]) _kamiRechargeCode = c;
}


#pragma mark - 内部方法

- (BOOL)checkInit:(NSString **)errorMsg {
    if (!_loginCode) { if (errorMsg) *errorMsg = @"未初始化，请先调用 init 方法"; return NO; }
    return YES;
}

- (NSString *)buildUrl:(NSString *)code {
    if ([_serverUrl hasSuffix:@"/"]) return [NSString stringWithFormat:@"%@%@", _serverUrl, code];
    return [NSString stringWithFormat:@"%@/%@", _serverUrl, code];
}

- (NSString *)encodeValue:(NSString *)value error:(NSString **)errorMsg {
    if ([_encodeType isEqualToString:@"base64"]) return [_encoder encodeToHex:value];
    NSError *err = nil;
    NSString *result = [_rsaCrypto encryptToHex:value error:&err];
    if (!result && errorMsg) *errorMsg = err.localizedDescription;
    return result;
}

- (NSString *)decodeResponse:(NSString *)responseText error:(NSString **)errorMsg {
    if ([_encodeType isEqualToString:@"base64"]) return [_encoder decode:responseText];
    NSError *err = nil;
    NSString *result = [_rsaCrypto decryptFromBase64:responseText error:&err];
    if (!result && errorMsg) *errorMsg = err.localizedDescription;
    return result;
}

- (NSArray<NSArray<NSString *> *> *)encodeParams:(NSArray<NSArray<NSString *> *> *)params
                                       sOriginal:(NSString **)sOriginal error:(NSString **)errorMsg {
    NSMutableArray *encodedPairs = [NSMutableArray array];
    for (NSArray *pair in params) {
        NSString *encoded = [self encodeValue:pair[1] error:errorMsg];
        if (!encoded) return nil;
        [encodedPairs addObject:@[pair[0], encoded]];
    }
    NSMutableString *sString = [NSMutableString string];
    for (NSUInteger i = 0; i < encodedPairs.count; i++) {
        if (i > 0) [sString appendString:@"&"];
        [sString appendFormat:@"%@=%@", encodedPairs[i][0], encodedPairs[i][1]];
    }
    [sString appendFormat:@"&%@", _appkey];
    if (sOriginal) *sOriginal = [sString copy];
    NSString *sEncoded = [self encodeValue:md5String(sString) error:errorMsg];
    if (!sEncoded) return nil;
    [encodedPairs addObject:@[@"s", sEncoded]];
    return encodedPairs;
}

- (NSString *)buildPostBody:(NSArray<NSArray<NSString *> *> *)pairs {
    NSMutableArray *parts = [NSMutableArray array];
    for (NSArray *pair in pairs) {
        NSString *ek = [pair[0] stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
        NSString *ev = [pair[1] stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
        [parts addObject:[NSString stringWithFormat:@"%@=%@", ek, ev]];
    }
    return [parts componentsJoinedByString:@"&"];
}

- (NSString *)httpPostOnce:(NSString *)urlString body:(NSString *)body error:(NSString **)errorMsg {
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) { if (errorMsg) *errorMsg = @"无效的URL"; return nil; }
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST"; request.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
    [request setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    request.timeoutInterval = 7;
    __block NSData *responseData; __block NSError *responseError; __block NSInteger responseStatus;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        responseData = data; responseError = err; responseStatus = [(NSHTTPURLResponse *)resp statusCode]; dispatch_semaphore_signal(sem);
    }];
    [task resume];
    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 15*NSEC_PER_SEC)) != 0) {
        [task cancel]; if (errorMsg) *errorMsg = @"请求超时"; return nil;
    }
    if (responseError) { if (errorMsg) *errorMsg = [NSString stringWithFormat:@"连接错误: %@", responseError.localizedDescription]; return nil; }
    if (responseStatus == 408 || responseStatus >= 500) { if (errorMsg) *errorMsg = [NSString stringWithFormat:@"HTTP %ld", (long)responseStatus]; return nil; }
    if (!responseData.length) { if (errorMsg) *errorMsg = @"响应数据为空"; return nil; }
    NSString *result = [[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
    if (!result.length) { if (errorMsg) *errorMsg = @"响应数据为空"; return nil; }
    return result;
}

- (NSString *)httpPost:(NSString *)urlString body:(NSString *)body error:(NSString **)errorMsg {
    NSURL *original = [NSURL URLWithString:urlString];
    if (!original) { if (errorMsg) *errorMsg = @"无效的URL"; return nil; }
    NSString *path = original.path ?: @"";
    if (original.query.length) path = [path stringByAppendingFormat:@"?%@", original.query];
    NSMutableArray<NSString *> *candidates = [NSMutableArray arrayWithObject:_serverUrl];
    for (NSString *base in _serverUrls) if (![base isEqualToString:_serverUrl]) [candidates addObject:base];
    for (NSString *base in candidates) {
        NSString *target = [NSString stringWithFormat:@"%@/%@", [base stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]], [path stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]]];
        NSString *attemptError = nil;
        NSString *result = [self httpPostOnce:target body:body error:&attemptError];
        if (result) { _serverUrl = base; return result; }
    }
    if (errorMsg) *errorMsg = T3_ALL_SERVERS_UNAVAILABLE;
    return nil;
}

/// 通用简单请求
- (T3Result *)simpleRequestWithCode:(NSString *)code codeName:(NSString *)codeName params:(NSArray<NSArray<NSString *> *> *)params {
    NSString *errorMsg = nil;
    if (![self checkInit:&errorMsg]) return [T3Result fail:errorMsg];
    if (!code || code.length == 0) return [T3Result fail:[NSString stringWithFormat:@"未设置 %@ 调用码", codeName]];
    NSMutableArray *allParams = [NSMutableArray arrayWithArray:params];
    [allParams addObject:@[@"t", [NSString stringWithFormat:@"%ld", (long)(NSInteger)[[NSDate date] timeIntervalSince1970]]]];
    NSArray *encoded = [self encodeParams:allParams sOriginal:nil error:&errorMsg];
    if (!encoded) return [T3Result fail:errorMsg ?: @"参数编码失败"];
    NSString *resp = [self httpPost:[self buildUrl:code] body:[self buildPostBody:encoded] error:&errorMsg];
    if (!resp) return [T3Result fail:[NSString stringWithFormat:@"请求失败: %@", errorMsg]];
    NSString *decoded = [self decodeResponse:resp error:&errorMsg];
    if (!decoded) return [T3Result fail:[NSString stringWithFormat:@"响应解码失败: %@", errorMsg]];
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[decoded dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    if (!json) return [T3Result fail:@"响应不是有效的JSON格式"];
    NSInteger c = [json[@"code"] integerValue];
    if (c != 200) return [T3Result fail:json[@"msg"] ?: @"未知错误"];
    return [T3Result okWithMsg:json[@"msg"]];
}

#pragma mark - 卡密验证

- (T3LoginResult *)loginWithKami:(NSString *)kami imei:(NSString *)imei {
    NSString *errorMsg = nil;
    if (![self checkInit:&errorMsg]) return [T3LoginResult fail:errorMsg];
    NSString *url = [self buildUrl:_loginCode];
    NSInteger t = (NSInteger)[[NSDate date] timeIntervalSince1970];
    NSArray *params = @[@[@"kami", kami], @[@"imei", imei], @[@"t", [NSString stringWithFormat:@"%ld", (long)t]]];
    NSString *sOriginal = nil;
    NSArray *encoded = [self encodeParams:params sOriginal:&sOriginal error:&errorMsg];
    if (!encoded) return [T3LoginResult fail:errorMsg ?: @"参数编码失败"];
    NSString *resp = [self httpPost:url body:[self buildPostBody:encoded] error:&errorMsg];
    if (!resp) return [T3LoginResult fail:[NSString stringWithFormat:@"请求失败: %@", errorMsg]];
    NSString *decoded = [self decodeResponse:resp error:&errorMsg];
    if (!decoded) return [T3LoginResult fail:[NSString stringWithFormat:@"响应解码失败: %@", errorMsg]];
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[decoded dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    if (!json) return [T3LoginResult fail:@"响应不是有效的JSON格式"];
    if ([json[@"code"] integerValue] != 200) return [T3LoginResult fail:json[@"msg"] ?: @"未知错误"];
    NSString *kamiId = [NSString stringWithFormat:@"%@", json[@"id"]];
    NSString *respEndTime = [NSString stringWithFormat:@"%@", json[@"end_time"]];
    NSString *token = json[@"token"]; NSString *respStatecode = json[@"statecode"];
    NSInteger respTime = [json[@"time"] integerValue];
    if (!token || !respStatecode) return [T3LoginResult fail:@"响应数据缺少必要字段"];
    NSInteger timeDiff = labs((NSInteger)[[NSDate date] timeIntervalSince1970] - respTime);
    if (timeDiff > 5) return [T3LoginResult fail:[NSString stringWithFormat:@"时间戳校验失败，相差%ld秒", (long)timeDiff]];
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init]; fmt.dateFormat = @"yyyyMMddHHmm";
    fmt.timeZone = [NSTimeZone timeZoneWithName:@"Asia/Shanghai"];
    NSString *expected = md5String([NSString stringWithFormat:@"%@%@%@%@%@", kamiId, _appkey, sOriginal, respEndTime, [fmt stringFromDate:[NSDate date]]]);
    if (![token.lowercaseString isEqualToString:expected]) return [T3LoginResult fail:@"token校验失败"];
    self.statecode = respStatecode; self.endTime = respEndTime;
    return [T3LoginResult okWithData:json];
}

- (T3QueryResult *)queryKami:(NSString *)kami {
    NSString *errorMsg = nil;
    if (![self checkInit:&errorMsg]) return [T3QueryResult fail:errorMsg];
    if (!_queryCode) return [T3QueryResult fail:@"未设置查询卡密调用码"];
    NSInteger t = (NSInteger)[[NSDate date] timeIntervalSince1970];
    NSArray *encoded = [self encodeParams:@[@[@"kami", kami], @[@"t", [NSString stringWithFormat:@"%ld", (long)t]]] sOriginal:nil error:&errorMsg];
    if (!encoded) return [T3QueryResult fail:errorMsg ?: @"参数编码失败"];
    NSString *resp = [self httpPost:[self buildUrl:_queryCode] body:[self buildPostBody:encoded] error:&errorMsg];
    if (!resp) return [T3QueryResult fail:[NSString stringWithFormat:@"请求失败: %@", errorMsg]];
    NSString *decoded = [self decodeResponse:resp error:&errorMsg];
    if (!decoded) return [T3QueryResult fail:[NSString stringWithFormat:@"响应解码失败: %@", errorMsg]];
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[decoded dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    if (!json) return [T3QueryResult fail:@"响应不是有效的JSON格式"];
    if ([json[@"code"] integerValue] != 200) return [T3QueryResult fail:json[@"msg"] ?: @"未知错误"];
    return [T3QueryResult okWithData:json];
}

- (T3Result *)heartbeatWithKami:(NSString *)kami statecode:(NSString *)statecode {
    return [self simpleRequestWithCode:_heartbeatCode codeName:@"单码心跳" params:@[@[@"kami", kami], @[@"statecode", statecode]]];
}

#pragma mark - 数据与内容

- (T3NoticeResult *)getNotice {
    T3Result *r = [self simpleRequestWithCode:_noticeCode codeName:@"公告" params:@[]];
    return r.success ? [T3NoticeResult okWithNotice:r.msg ?: @""] : [T3NoticeResult fail:r.error];
}

- (T3VersionResult *)getLatestVersion {
    T3Result *r = [self simpleRequestWithCode:_versionCode codeName:@"版本号" params:@[]];
    return r.success ? [T3VersionResult okWithVersion:r.msg ?: @""] : [T3VersionResult fail:r.error];
}

- (T3UpdateResult *)checkUpdateWithVer:(NSString *)ver {
    NSString *errorMsg = nil;
    if (![self checkInit:&errorMsg]) return [T3UpdateResult fail:errorMsg];
    if (!_checkUpdateCode) return [T3UpdateResult fail:@"未设置检查更新调用码"];
    NSInteger t = (NSInteger)[[NSDate date] timeIntervalSince1970];
    NSArray *encoded = [self encodeParams:@[@[@"ver", ver], @[@"t", [NSString stringWithFormat:@"%ld", (long)t]]] sOriginal:nil error:&errorMsg];
    if (!encoded) return [T3UpdateResult fail:errorMsg ?: @"参数编码失败"];
    NSString *resp = [self httpPost:[self buildUrl:_checkUpdateCode] body:[self buildPostBody:encoded] error:&errorMsg];
    if (!resp) return [T3UpdateResult fail:[NSString stringWithFormat:@"请求失败: %@", errorMsg]];
    NSString *decoded = [self decodeResponse:resp error:&errorMsg];
    if (!decoded) return [T3UpdateResult fail:[NSString stringWithFormat:@"响应解码失败: %@", errorMsg]];
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[decoded dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    if (!json) return [T3UpdateResult fail:@"响应不是有效的JSON格式"];
    NSInteger c = [json[@"code"] integerValue];
    if (c == 200) return [T3UpdateResult updatedWithData:json];
    if (c == 201) return [T3UpdateResult noUpdateWithMsg:json[@"msg"] ?: @""];
    return [T3UpdateResult fail:json[@"msg"] ?: @"未知错误"];
}

- (T3CloudDocResult *)getCloudDocWithToken:(NSString *)token {
    T3Result *r = [self simpleRequestWithCode:_cloudDocCode codeName:@"云文档" params:@[@[@"token", token]]];
    return r.success ? [T3CloudDocResult okWithContent:r.msg ?: @""] : [T3CloudDocResult fail:r.error];
}

- (T3AppSignResult *)appSignWithAutograph:(NSString *)autograph {
    NSString *errorMsg = nil;
    if (![self checkInit:&errorMsg]) return [T3AppSignResult fail:errorMsg];
    if (!_appSignCode) return [T3AppSignResult fail:@"未设置应用签名调用码"];
    NSInteger t = (NSInteger)[[NSDate date] timeIntervalSince1970];
    NSArray *encoded = [self encodeParams:@[@[@"autograph", autograph], @[@"t", [NSString stringWithFormat:@"%ld", (long)t]]] sOriginal:nil error:&errorMsg];
    if (!encoded) return [T3AppSignResult fail:errorMsg ?: @"参数编码失败"];
    NSString *resp = [self httpPost:[self buildUrl:_appSignCode] body:[self buildPostBody:encoded] error:&errorMsg];
    if (!resp) return [T3AppSignResult fail:[NSString stringWithFormat:@"请求失败: %@", errorMsg]];
    NSString *decoded = [self decodeResponse:resp error:&errorMsg];
    if (!decoded) return [T3AppSignResult fail:[NSString stringWithFormat:@"响应解码失败: %@", errorMsg]];
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[decoded dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    if (!json) return [T3AppSignResult fail:@"响应不是有效的JSON格式"];
    if ([json[@"code"] integerValue] != 200) return [T3AppSignResult fail:json[@"msg"] ?: @"未知错误"];
    T3AppSignResult *r = [[T3AppSignResult alloc] init];
    r.success = YES; r.msg = json[@"msg"]; r.autograph = json[@"autograph"]; r.time = json[@"time"];
    return r;
}

#pragma mark - 用户体系

- (T3Result *)userRegisterWithUser:(NSString *)user pass:(NSString *)pass email:(NSString *)email {
    NSMutableArray *p = [NSMutableArray arrayWithArray:@[@[@"user", user], @[@"pass", pass]]];
    if (email.length > 0) [p addObject:@[@"email", email]];
    return [self simpleRequestWithCode:_registerCode codeName:@"用户注册" params:p];
}

- (T3LoginResult *)userLoginWithUser:(NSString *)user pass:(NSString *)pass imei:(NSString *)imei {
    NSString *errorMsg = nil;
    if (![self checkInit:&errorMsg]) return [T3LoginResult fail:errorMsg];
    if (!_userLoginCode) return [T3LoginResult fail:@"未设置用户登录调用码"];
    NSInteger t = (NSInteger)[[NSDate date] timeIntervalSince1970];
    NSArray *encoded = [self encodeParams:@[@[@"user", user], @[@"pass", pass], @[@"imei", imei], @[@"t", [NSString stringWithFormat:@"%ld", (long)t]]] sOriginal:nil error:&errorMsg];
    if (!encoded) return [T3LoginResult fail:errorMsg ?: @"参数编码失败"];
    NSString *resp = [self httpPost:[self buildUrl:_userLoginCode] body:[self buildPostBody:encoded] error:&errorMsg];
    if (!resp) return [T3LoginResult fail:[NSString stringWithFormat:@"请求失败: %@", errorMsg]];
    NSString *decoded = [self decodeResponse:resp error:&errorMsg];
    if (!decoded) return [T3LoginResult fail:[NSString stringWithFormat:@"响应解码失败: %@", errorMsg]];
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[decoded dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    if (!json) return [T3LoginResult fail:@"响应不是有效的JSON格式"];
    if ([json[@"code"] integerValue] != 200) return [T3LoginResult fail:json[@"msg"] ?: @"未知错误"];
    self.statecode = json[@"statecode"]; self.endTime = [NSString stringWithFormat:@"%@", json[@"end_time"]];
    return [T3LoginResult okWithData:json];
}

- (T3Result *)userHeartbeatWithUser:(NSString *)user pass:(NSString *)pass statecode:(NSString *)statecode {
    return [self simpleRequestWithCode:_userHeartbeatCode codeName:@"用户心跳" params:@[@[@"user", user], @[@"pass", pass], @[@"statecode", statecode]]];
}

- (T3LoginResult *)qqLoginWithOpenid:(NSString *)openid accessToken:(NSString *)accessToken {
    NSString *errorMsg = nil;
    if (![self checkInit:&errorMsg]) return [T3LoginResult fail:errorMsg];
    if (!_qqLoginCode) return [T3LoginResult fail:@"未设置QQ登录调用码"];
    NSInteger t = (NSInteger)[[NSDate date] timeIntervalSince1970];
    NSArray *encoded = [self encodeParams:@[@[@"openid", openid], @[@"access_token", accessToken], @[@"t", [NSString stringWithFormat:@"%ld", (long)t]]] sOriginal:nil error:&errorMsg];
    if (!encoded) return [T3LoginResult fail:errorMsg ?: @"参数编码失败"];
    NSString *resp = [self httpPost:[self buildUrl:_qqLoginCode] body:[self buildPostBody:encoded] error:&errorMsg];
    if (!resp) return [T3LoginResult fail:[NSString stringWithFormat:@"请求失败: %@", errorMsg]];
    NSString *decoded = [self decodeResponse:resp error:&errorMsg];
    if (!decoded) return [T3LoginResult fail:[NSString stringWithFormat:@"响应解码失败: %@", errorMsg]];
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[decoded dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    if (!json) return [T3LoginResult fail:@"响应不是有效的JSON格式"];
    if ([json[@"code"] integerValue] != 200) return [T3LoginResult fail:json[@"msg"] ?: @"未知错误"];
    self.statecode = json[@"statecode"]; self.endTime = [NSString stringWithFormat:@"%@", json[@"end_time"]];
    return [T3LoginResult okWithData:json];
}

- (T3Result *)bindQQWithUser:(NSString *)user pass:(NSString *)pass openid:(NSString *)openid accessToken:(NSString *)accessToken {
    return [self simpleRequestWithCode:_bindQQCode codeName:@"绑定QQ" params:@[@[@"user", user], @[@"pass", pass], @[@"openid", openid], @[@"access_token", accessToken]]];
}

- (T3Result *)changePasswordWithUser:(NSString *)user oldpass:(NSString *)oldpass newpass:(NSString *)newpass {
    return [self simpleRequestWithCode:_changePasswordCode codeName:@"修改密码" params:@[@[@"user", user], @[@"oldpass", oldpass], @[@"newpass", newpass]]];
}

- (T3Result *)userCancelWithUser:(NSString *)user pass:(NSString *)pass {
    return [self simpleRequestWithCode:_userCancelCode codeName:@"用户注销" params:@[@[@"user", user], @[@"pass", pass]]];
}

- (T3Result *)rechargeWithUser:(NSString *)user card:(NSString *)card {
    return [self simpleRequestWithCode:_rechargeCode codeName:@"用户充值" params:@[@[@"user", user], @[@"card", card]]];
}

- (T3Result *)kamiRechargeWithTargetKami:(NSString *)targetKami sourceKami:(NSString *)sourceKami {
    return [self simpleRequestWithCode:_kamiRechargeCode codeName:@"单码以卡充卡" params:@[@[@"target_kami", targetKami], @[@"source_kami", sourceKami]]];
}

#pragma mark - QQ 凭证扩展与统一心跳

- (T3Result *)qqHeartbeatWithOpenid:(NSString *)openid accessToken:(NSString *)accessToken statecode:(NSString *)statecode {
    return [self simpleRequestWithCode:_qqHeartbeatCode codeName:@"QQ心跳" params:@[@[@"openid", openid], @[@"access_token", accessToken], @[@"statecode", statecode]]];
}

- (T3VariableResult *)getVariableByQqWithOpenid:(NSString *)openid accessToken:(NSString *)accessToken valueid:(NSString *)valueid valuename:(NSString *)valuename {
    T3Result *r = [self simpleRequestWithCode:_getVariableByQqCode codeName:@"QQ获取变量" params:@[@[@"openid", openid], @[@"access_token", accessToken], @[@"valueid", valueid], @[@"valuename", valuename]]];
    return r.success ? [T3VariableResult okWithValue:r.msg ?: @""] : [T3VariableResult fail:r.error];
}

- (T3CoreResult *)getUserCoreByQqWithOpenid:(NSString *)openid accessToken:(NSString *)accessToken {
    T3Result *r = [self simpleRequestWithCode:_getUserCoreByQqCode codeName:@"QQ获取核心数据" params:@[@[@"openid", openid], @[@"access_token", accessToken]]];
    return r.success ? [T3CoreResult okWithCore:r.msg ?: @""] : [T3CoreResult fail:r.error];
}

- (T3Result *)modifyUserCoreByQqWithOpenid:(NSString *)openid accessToken:(NSString *)accessToken core:(NSString *)core {
    return [self simpleRequestWithCode:_modifyUserCoreByQqCode codeName:@"QQ改核心数据" params:@[@[@"openid", openid], @[@"access_token", accessToken], @[@"core", core]]];
}

- (T3Result *)unbindQqWithUser:(NSString *)user pass:(NSString *)pass {
    return [self simpleRequestWithCode:_unbindQqCode codeName:@"解绑QQ" params:@[@[@"user", user], @[@"pass", pass]]];
}

- (T3Result *)heartbeatAnyWithStatecode:(NSString *)statecode {
    return [self simpleRequestWithCode:_heartbeatAnyCode codeName:@"统一心跳" params:@[@[@"statecode", statecode]]];
}

#pragma mark - 设备与安全

- (T3Result *)unbindKamiWithKami:(NSString *)kami imei:(NSString *)imei {
    return [self simpleRequestWithCode:_unbindCode codeName:@"解绑设备" params:@[@[@"kami", kami], @[@"imei", imei]]];
}

- (T3Result *)unbindUserWithUser:(NSString *)user pass:(NSString *)pass imei:(NSString *)imei {
    return [self simpleRequestWithCode:_unbindCode codeName:@"解绑设备" params:@[@[@"user", user], @[@"pass", pass], @[@"imei", imei]]];
}

- (T3Result *)ipUnbindKamiWithKami:(NSString *)kami {
    return [self simpleRequestWithCode:_ipUnbindCode codeName:@"IP解绑" params:@[@[@"kami", kami]]];
}

- (T3Result *)ipUnbindUserWithUser:(NSString *)user pass:(NSString *)pass {
    return [self simpleRequestWithCode:_ipUnbindCode codeName:@"IP解绑" params:@[@[@"user", user], @[@"pass", pass]]];
}

- (T3Result *)disableKamiWithKami:(NSString *)kami {
    return [self simpleRequestWithCode:_disableCode codeName:@"禁用" params:@[@[@"kami", kami]]];
}

- (T3Result *)disableUserWithUser:(NSString *)user pass:(NSString *)pass {
    return [self simpleRequestWithCode:_disableCode codeName:@"禁用" params:@[@[@"user", user], @[@"pass", pass]]];
}

#pragma mark - 远程变量

- (T3VariableResult *)getVariableByKami:(NSString *)kami valueid:(NSString *)valueid valuename:(NSString *)valuename {
    T3Result *r = [self simpleRequestWithCode:_getVariableCode codeName:@"获取变量" params:@[@[@"kami", kami], @[@"valueid", valueid], @[@"valuename", valuename]]];
    return r.success ? [T3VariableResult okWithValue:r.msg ?: @""] : [T3VariableResult fail:r.error];
}

- (T3VariableResult *)getVariableByUser:(NSString *)user pass:(NSString *)pass valueid:(NSString *)valueid valuename:(NSString *)valuename {
    T3Result *r = [self simpleRequestWithCode:_getVariableCode codeName:@"获取变量" params:@[@[@"user", user], @[@"pass", pass], @[@"valueid", valueid], @[@"valuename", valuename]]];
    return r.success ? [T3VariableResult okWithValue:r.msg ?: @""] : [T3VariableResult fail:r.error];
}

- (T3Result *)modifyVariableByKami:(NSString *)kami valueid:(NSString *)valueid valuecontent:(NSString *)valuecontent {
    return [self simpleRequestWithCode:_modifyVariableCode codeName:@"修改变量" params:@[@[@"kami", kami], @[@"valueid", valueid], @[@"valuecontent", valuecontent]]];
}

- (T3Result *)modifyVariableByUser:(NSString *)user pass:(NSString *)pass valueid:(NSString *)valueid valuecontent:(NSString *)valuecontent {
    return [self simpleRequestWithCode:_modifyVariableCode codeName:@"修改变量" params:@[@[@"user", user], @[@"pass", pass], @[@"valueid", valueid], @[@"valuecontent", valuecontent]]];
}

#pragma mark - 核心数据

- (T3Result *)modifyCoreByKami:(NSString *)kami core:(NSString *)core {
    return [self simpleRequestWithCode:_modifyCoreCode codeName:@"修改核心数据" params:@[@[@"kami", kami], @[@"core", core]]];
}

- (T3Result *)modifyCoreByUser:(NSString *)user pass:(NSString *)pass core:(NSString *)core {
    return [self simpleRequestWithCode:_modifyCoreCode codeName:@"修改核心数据" params:@[@[@"user", user], @[@"pass", pass], @[@"core", core]]];
}

- (T3CoreResult *)getCoreByKami:(NSString *)kami {
    T3Result *r = [self simpleRequestWithCode:_getKamiCoreCode codeName:@"获取卡密核心数据" params:@[@[@"kami", kami]]];
    return r.success ? [T3CoreResult okWithCore:r.msg ?: @""] : [T3CoreResult fail:r.error];
}

- (T3CoreResult *)getCoreByUser:(NSString *)user pass:(NSString *)pass {
    T3Result *r = [self simpleRequestWithCode:_getUserCoreCode codeName:@"获取用户核心数据" params:@[@[@"user", user], @[@"pass", pass]]];
    return r.success ? [T3CoreResult okWithCore:r.msg ?: @""] : [T3CoreResult fail:r.error];
}

// ===== 在线数量 =====
- (T3OnlineResult *)getOnlineKamiCount {
    T3Result *r = [self simpleRequestWithCode:_onlineKamiCode codeName:@"获取在线卡密数量" params:@[]];
    return r.success ? [T3OnlineResult okWithCount:[r.msg integerValue]] : [T3OnlineResult fail:r.error];
}

- (T3OnlineResult *)getOnlineUserCount {
    T3Result *r = [self simpleRequestWithCode:_onlineUserCode codeName:@"获取在线用户数量" params:@[]];
    return r.success ? [T3OnlineResult okWithCount:[r.msg integerValue]] : [T3OnlineResult fail:r.error];
}

+ (NSString *)getMachineCode {
    NSString *identifier = nil;
#if TARGET_OS_IOS
    identifier = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
#else
    io_service_t platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (platformExpert) {
        CFStringRef uuidRef = IORegistryEntryCreateCFProperty(platformExpert, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
        if (uuidRef) identifier = (__bridge_transfer NSString *)uuidRef;
        IOObjectRelease(platformExpert);
    }
#endif
    if (!identifier) identifier = [[NSUUID UUID] UUIDString];
    return [md5String(identifier) uppercaseString];
}

@end
