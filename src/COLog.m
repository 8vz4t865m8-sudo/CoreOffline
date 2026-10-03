//
//  COLog.m
//  CoreOffline —— 统一日志实现
//

#import "COLog.h"

#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdarg.h>
#import <stdio.h>

/// 日志 fd。初始 -1 = 还没打开。
static int gCOLogFD = -1;
/// 保护 fd 的打开/关闭，避免多线程同时 open 出两个 fd。
static dispatch_once_t gCOLogOnce;

NSString *CORecordPath(void) {
    // ★ NSHomeDirectory 在 dyld 早期就是安全的（纯 C 层拼路径）。
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/core-offline.log"];
}

static void COLogOpen(void) {
    // 这里刻意不用 dispatch_once 包整个函数体 ——
    // 如果 open 失败我们要能重试（比如 Documents 目录晚一点才建好）。
    if (gCOLogFD >= 0) return;

    const char *path = CORecordPath().fileSystemRepresentation;
    if (!path) { gCOLogFD = STDERR_FILENO; return; }

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    gCOLogFD = (fd >= 0) ? fd : STDERR_FILENO;
    (void)gCOLogOnce;
}

int CORecordFD(void) {
    if (gCOLogFD < 0) COLogOpen();
    return gCOLogFD;
}

void CORecord(const char *fmt, ...) {
    if (!fmt) return;
    if (gCOLogFD < 0) COLogOpen();

    char buf[1024];

    // ── 时间前缀 ──
    // 用 time(2) 而不是 NSDateFormatter（ICU 在 dyld 早期还没就绪）。
    char ts[32];
    time_t now = time(NULL);
    struct tm tmv;
    if (localtime_r(&now, &tmv)) {
        strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);
    } else {
        ts[0] = '\0';
    }

    int n = snprintf(buf, sizeof(buf), "[%s] ", ts);
    if (n < 0) n = 0;

    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(buf + n, sizeof(buf) - (size_t)n - 2, fmt, ap);
    va_end(ap);
    if (m < 0) m = 0;
    size_t len = (size_t)n + (size_t)m;
    if (len > sizeof(buf) - 2) len = sizeof(buf) - 2;

    buf[len++] = '\n';

    // ★ 一次 write 写完。多线程下交错最多是行级（因为 < PIPE_BUF），
    //   不会出现半行拼接 —— 比 NSLog 的分行输出好读。
    if (gCOLogFD >= 0) {
        ssize_t ignored = write(gCOLogFD, buf, len);
        (void)ignored;
    }
}
