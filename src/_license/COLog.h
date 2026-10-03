//
//  COLog.h
//  CoreOffline —— 统一日志
//
//  为什么单独抽出来：
//    原来 record() 是 CoreOffline.m 里的 static，COVerifyBridge.m 想记一条
//    离线兜底的日志就得自己再开一个 fd。参考实现里 F5CloudAuth 是把日志
//    统一走 emit:message: 往外写，这里照做 —— 只有一条写日志的路径，
//    排查问题时不用满仓库找。
//
//  落盘位置：Documents/core-offline.log
//    ★ 用 open(2) 而不是 NSFileHandle / NSLog：
//      constructor 阶段前者安全，后者在 dyld 早期可能拿到 nil 路径。
//    ★ 打不开就退到 stderr —— 绝不因为记日志失败而影响主流程。
//

#ifndef CO_LOG_H
#define CO_LOG_H

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// 同 printf 风格。自动加换行。线程安全。
void CORecord(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/// 拿到当前日志 fd（-1 表示没打开）。给需要直接 write 的场景用。
int CORecordFD(void);

/// 日志文件路径（Documents/core-offline.log）
NSString *CORecordPath(void);

#ifdef __cplusplus
}
#endif

#endif /* CO_LOG_H */
