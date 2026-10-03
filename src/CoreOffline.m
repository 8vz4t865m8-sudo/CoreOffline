// ═══════════════════════════════════════════════════════════════════════════
//  CoreOffline.m —— 宿主 Core 1.6 卡密接管版  (v3 · 全部签名经反汇编核实)
//
//  ── v3 相对 v2 的关键变化 ────────────────────────────────────────────────
//  ★★★ 导出宿主预留的三个 C 符号 ★★★
//
//  宿主二进制里内置了三个「弱符号跳板」（weak import trampoline），
//  它们会主动 dlsym 查找下面三个符号：
//
//      CoreOfflineBootstrap   @0x100003464 (符号名字符串所在偏移)
//      CoreOfflinePrepare     @0x100003564
//      CoreOfflineFinalize    @0x100003664
//
//  跳板代码（宿主 __text 最前端，0x100003400 起）：
//      100003420  mov  x0, #-2                       ; RTLD_DEFAULT
//      100003424  adr  x1, #"CoreOfflineBootstrap"
//      100003428  bl   #0x100725a10                  ; dlsym
//      ...
//      100003450  cbz  x16, skip                     ; NULL 就跳过
//      100003454  xpaci x16 ; br x16                 ; 有就执行
//
//  ★ 所以本 dylib 必须**导出**这三个符号（visibility default，非 static）。
//    宿主会主动来调用 —— 这比 constructor / +load 的时机可靠得多。
//
//  ── 接管策略 ────────────────────────────────────────────────────────────
//    主接管点：QXA117 finish:authorized:message:expiresAt:  @0x10017a5dc
//              v44@0:8@?16B24@28@36
//              x2=completion block  x3=BOOL authorized  x4=msg  x5=expiresAt
//
//      为什么选它：宿主所有卡密结论（成功/网络失败/解析失败/未授权）
//      最终都收敛到这一个方法。我们只把 authorized 改成 YES 就把结果改了，
//      而 block 的调用由宿主自己完成（它在栈上构造 block 再 invoke），
//      我们**绝不自己调 block** → 零 ABI 风险。
//
//    辅助 hook（仅观测/透传，不做改写）：
//      QXA140 performPurpose:rootDeviceId:payload:completion:  @0x10018a888
//      QXA141 inputCard:transfer:                              @0x100187608
//      QxF4   qxRefreshExpiry                                  @0x1001a28ec
//
//  ── 为什么前几版会闪退 ──────────────────────────────────────────────────
//    ① 自己手动调 completion block，参数个数靠猜（实测是 4 参数）
//    ② constructor 里 objc_copyClassList 全量遍历 119 个类
//    ③ 引 Security.framework + Keychain（自签下 SecItemAdd = -34018）
//
//  ── 本版原则 ────────────────────────────────────────────────────────────
//    1. 绝不自己调用任何 completion block
//    2. 零全局类遍历，只按名字取 4 个确定的类
//    3. 零 Keychain / 零 Security / 零 CFNetwork 依赖
//    4. 安装幂等，所有 hook 体 @try/@catch 兜底
//    5. 导出宿主预留的 3 个符号
//
//  依赖：仅 Foundation + UIKit
// ═══════════════════════════════════════════════════════════════════════════
//
//  ── 附：宿主关键方法地址（本轮逆向所得，全部已核实）─────────────────────
//
//  QXA117  (12 methods)  ro=0x100bc9d08
//    md5ForDeviceIdentifier:            @0x10017a3d8  @24@0:8@16
//    expiryDateFromString:              @0x10017a4f4  @24@0:8@16
//    finish:authorized:message:expiresAt: @0x10017a5dc  v44@0:8@?16B24@28@36
//        └ x2=block(@?16)  x3=BOOL(B24)  x4=msg(@28)  x5=expiresAt(@36)
//          10017a5f4  mov x19,x5      ; expiresAt
//          10017a5f8  mov x20,x4      ; message
//          10017a5fc  mov x21,x3      ; authorized
//          10017a65c  strb w21,[sp,#0x38]   ← 把三者塞进栈 block
//          10017a664  bl  #0x1007262f0      ← 然后 invoke
//          ★ 结论：宿主自己负责 block 调用。我们只要改 x3/x4/x5 的语义即可，
//                 完全不需要自己碰 block！
//    verifyDeviceIdentifier:completion: @0x10017a784  v32@0:8@16@?24
//        └ 10017a7e0  cmp x0,#0x20   ; device_hash 必须 32 字符
//          10017a7e4  b.ne 失败分支
//
//  QXA140  (9 methods)   ro=0x100bcaa88
//    performPurpose:rootDeviceId:payload:completion: @0x10018a888  v48@0:8@16@24@32@?40
//        └ 失败分支 0x10018aa28: mov x0=x22(block) mov x1,#0 mov x2=<CFString>
//          → block(result=0, ok=0, msg=NSString, extra=0)  【4 参数！】
//    post:body:generation:completion:    @0x10018a124  v48@0:8@24Q32@?40
//
//  QXA141  (29 methods)  ro=0x100bca878
//    inputCard:transfer:                 @0x100187608  v28@0:8@16B24
//    acceptBound:token:bindingRoot:      @0x1001862b8  v40@0:8@16@24@32
//    activateNewCard                     @0x100186e08  v16@0:8
//
//  QxF4    (41 methods)  ro=0x100bcc508
//    qxRefreshExpiry                     @0x1001a28ec  v16@0:8
//    qm581:expiry:                       @0x1001a20e8  v28@0:8i16@20
//
//  ── 宿主自带文案（已从 __cfstring 解出，UTF-16，用于对齐语义）──────────
//    '设备授权有效'          @0x100badf48   ← 成功
//    '设备授权已过期'        @0x100badf28
//    '当前设备尚未授权'      @0x100badee8
//    '设备身份不可用'        @0x100bade28   ← verifyDeviceIdentifier 失败文案
//    '授权服务连接失败'      @0x100bade68
//    '授权响应格式错误'      @0x100bade88
//    '授权至：%@'            @0x100bae388   ← UI 显示的到期格式
//    '授权信息不可用'        @0x100badf08
// ═══════════════════════════════════════════════════════════════════════════

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <stdio.h>
#import <stdarg.h>
#import <string.h>
#import <stdlib.h>
#import <stdint.h>
#import <unistd.h>

// ───────────────────────────────────────────────────────────────────────────
//  常量
// ───────────────────────────────────────────────────────────────────────────

static NSString *const kHostBundleID = @"qingxiugai.qingxiugai.qinxiugai";

/// 硬编码放行到期时间（用于 UI 的「授权至：%@」）
static NSString *const kPerpetualExpiry = @"2099-12-31 23:59:59";

/// 卡密真身类名（全部经 __objc_classlist 核实存在）
static NSString *const kClsFingerprint = @"QXA117";   // 设备指纹 + 终态判决
static NSString *const kClsNetLayer    = @"QXA140";   // 网络层（唯一出网点）
static NSString *const kClsBinder      = @"QXA141";   // 绑定状态机
static NSString *const kClsCardUI      = @"QxF4";     // 卡密 UI

/// 日志开关：验证阶段保持 1；稳定后可置 0 彻底消除文件 IO
#define CO_LOG 1

#if CO_LOG
static FILE *gLog = NULL;
static void COLogOpen(void) {
    if (gLog) return;
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char p[512];
    snprintf(p, sizeof(p), "%s/Documents/CoreOffline.log", home);
    gLog = fopen(p, "a");
    if (!gLog) {
        snprintf(p, sizeof(p), "/tmp/CoreOffline.log");
        gLog = fopen(p, "a");
    }
}
#endif

static void COLog(const char *fmt, ...) {
#if CO_LOG
    if (!gLog) COLogOpen();
    if (!gLog) return;
    @try {
        va_list ap; va_start(ap, fmt);
        vfprintf(gLog, fmt, ap);
        va_end(ap);
        fputc('\n', gLog);
        fflush(gLog);
    } @catch (NSException *e) { }
#endif
}

/// 运行期计数器
static volatile int gDidFP     = 0;   // QXA117 finish:
static volatile int gDidNet    = 0;   // QXA140 performPurpose:
static volatile int gDidBinder = 0;   // QXA141 inputCard:
static volatile int gDidUI     = 0;   // QxF4 qxRefreshExpiry

// ───────────────────────────────────────────────────────────────────────────
//  原始 IMP
// ───────────────────────────────────────────────────────────────────────────

// QXA117 finish:authorized:message:expiresAt:   v44@0:8@?16B24@28@36
static void (*orig_finish)(id, SEL, id, BOOL, id, id) = NULL;

// QXA140 performPurpose:rootDeviceId:payload:completion:  v48@0:8@16@24@32@?40
static void (*orig_perform)(id, SEL, id, id, id, id) = NULL;

// QXA141 inputCard:transfer:   v28@0:8@16B24
static void (*orig_inputCard)(id, SEL, id, BOOL) = NULL;

// QxF4 qxRefreshExpiry   v16@0:8
static void (*orig_refresh)(id, SEL) = NULL;

// ───────────────────────────────────────────────────────────────────────────
//  ① ★★★ 核心接管点：QXA117 - finish:authorized:message:expiresAt: ★★★
//
//  这是整个卡密链路的「终态判决」方法。宿主所有路径最终都收敛到这里：
//      verifyDeviceIdentifier: 成功 → finish:
//      网络失败                     → finish:authorized=NO
//      解析失败                     → finish:authorized=NO
//      "当前设备尚未授权"           → finish:authorized=NO
//
//  ★ 我们只做一件事：把 authorized 强制改 YES，并把 expiresAt 换成 2099。
//  ★ 绝对不自己调用 block —— 交给宿主的原实现去调，它自己知道怎么调。
// ───────────────────────────────────────────────────────────────────────────

static void co_finish(id self, SEL _cmd, id completion, BOOL authorized, id message, id expiresAt) {
    gDidFP++;

    COLog("[接管] QXA117 finish: authorized(orig)=%d message=%s expiresAt=%s",
          (int)authorized,
          message     ? [[message     description] UTF8String] : "(nil)",
          expiresAt   ? [[expiresAt   description] UTF8String] : "(nil)");

    // ★ 强制放行：无论宿主算出什么结论，都改成「已授权 + 2099 到期」
    authorized = YES;
    message    = @"设备授权有效";
    expiresAt  = kPerpetualExpiry;

    COLog("[接管] QXA117 → 改写为 authorized=YES expiresAt=%s，交回宿主原实现",
          kPerpetualExpiry);

    // ★ 关键：把改写后的参数交回宿主原实现。
    //   宿主自己会把它们塞进栈 block 再 invoke，我们完全不碰 block 调用约定。
    if (orig_finish) {
        @try {
            orig_finish(self, _cmd, completion, authorized, message, expiresAt);
        } @catch (NSException *e) {
            COLog("[接管] QXA117 finish 原实现抛出: %s", [[e reason] UTF8String]);
        }
    } else {
        COLog("[警告] QXA117 finish 原实现为空，无法继续");
    }
}

// ───────────────────────────────────────────────────────────────────────────
//  ② QXA140 - performPurpose:rootDeviceId:payload:completion:
//
//  宿主唯一的 identity 出网点。
//
//  ★★ 设计决定：本版**不接管 QXA140**，只做观测。
//
//  理由（这是本版最重要的取舍）：
//    ① 接管 ① 已经足够。
//       QXA140 的调用方拿到结果后，无论成功/失败，最终都会走到
//       QXA117 finish:authorized:message:expiresAt: —— 而那里我们强制放行。
//       也就是说：网络这一层就算失败，也影响不了最终结论。
//    ② 自己调用 completion block 必然要"猜签名"。
//       实测签名是 (id result, BOOL ok, NSString *message, id extra)，
//       但 block 的 ABI 不走 objc_msgSend 的 NSMethodSignature 通道，
//       NSInvocation 无法安全代劳；手写函数指针一旦差一个参数就崩。
//    ③ 少一个 hook = 少一个崩溃面。这是本版的核心原则。
//
//  所以这里保留方法占位与日志，但**原样调用宿主实现**，不做任何改写。
//  真正让卡密"通过"的工作全部交给 ① QXA117 finish:。
// ───────────────────────────────────────────────────────────────────────────

static void co_perform(id self, SEL _cmd, id purpose, id rootDeviceId,
                       id payload, id completion) {
    gDidNet++;
    COLog("[接管] QXA140 performPurpose:%s rootDeviceId=%s （仅观测，原样放行）",
          purpose     ? [[purpose     description] UTF8String] : "(nil)",
          rootDeviceId? [[rootDeviceId description] UTF8String] : "(nil)");

    // ★ 原样调用宿主实现，不改写任何参数。
    //   网络若通不了，宿主会自己走到 QXA117 finish: → 由 ① 强制放行。
    if (orig_perform) {
        @try {
            orig_perform(self, _cmd, purpose, rootDeviceId, payload, completion);
        } @catch (NSException *e) {
            COLog("[接管] QXA140 原实现抛出（已忽略）: %s", [[e reason] UTF8String]);
        }
    } else {
        COLog("[警告] QXA140 原实现为空，无法继续");
    }
}

// ───────────────────────────────────────────────────────────────────────────
//  ③ QXA141 - inputCard:transfer:
//
//  用户点「激活」时把卡密交给状态机。让它走原生流程（这样宿主自己的 UI
//  会正常变绿），但如果原生流程因为网络/签名原因失败，我们用 ① 兜底放行。
// ───────────────────────────────────────────────────────────────────────────

static void co_inputCard(id self, SEL _cmd, id card, BOOL transfer) {
    gDidBinder++;
    COLog("[接管] QXA141 inputCard:%s transfer=%d",
          card ? [[card description] UTF8String] : "(nil)", (int)transfer);

    if (orig_inputCard) {
        @try {
            orig_inputCard(self, _cmd, card, transfer);
            COLog("[接管] QXA141 原生实现已执行");
            return;
        } @catch (NSException *e) {
            COLog("[接管] QXA141 原生抛出: %s", [[e reason] UTF8String]);
        }
    }
    COLog("[接管] QXA141 原生实现不可用，依赖 QXA117 finish: 兜底放行");
}

// ───────────────────────────────────────────────────────────────────────────
//  ④ QxF4 - qxRefreshExpiry    （透传 + 日志）
// ───────────────────────────────────────────────────────────────────────────

static void co_refresh(id self, SEL _cmd) {
    gDidUI++;
    COLog("[接管] QxF4 qxRefreshExpiry");
    if (orig_refresh) {
        @try { orig_refresh(self, _cmd); }
        @catch (NSException *e) {
            COLog("[接管] qxRefreshExpiry 原实现抛出: %s", [[e reason] UTF8String]);
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
//  Swizzle 工具 —— 使用 method_setImplementation，不交换
//
//  ★ 为什么不用 method_exchangeImplementations：
//    交换后宿主内部任意 [self finish:...] 也会走到我们的实现，虽然通常没问题，
//    但 method_setImplementation 语义更干净：只有外部通过 SEL 派发的调用被改。
//    实际二者对 ObjC 消息派发等价（都改 method_t.imp），这里用 set 更直观。
// ───────────────────────────────────────────────────────────────────────────

static IMP COReplace(Class cls, NSString *selName, IMP replacement, const char *tag) {
    if (!cls || !selName || !replacement) {
        COLog("[跳过] %s: 入参为空", tag);
        return NULL;
    }
    SEL sel = NSSelectorFromString(selName);
    if (!sel) {
        COLog("[跳过] %s: SEL 无效", tag);
        return NULL;
    }
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        COLog("[跳过] %s: %s 上不存在 %s", tag, class_getName(cls), [selName UTF8String]);
        return NULL;
    }
    const char *types = method_getTypeEncoding(m);
    IMP orig = method_getImplementation(m);

    COLog("[接管] %s: cls=%s sel=%s types=%s imp=%p",
          tag, class_getName(cls), [selName UTF8String], types ? types : "(null)", orig);

    // ★ 只替换，不新增：类上必然已存在该 SEL，method_setImplementation 直接生效
    method_setImplementation(m, replacement);
    return orig;
}

// ───────────────────────────────────────────────────────────────────────────
//  安装（幂等）
// ───────────────────────────────────────────────────────────────────────────

static void COInstall(void) {
    static int done = 0;
    if (done) {
        COLog("[安装] 已安装过，跳过重复调用");
        return;
    }
    done = 1;

    int installed = 0;

    // ── ① QXA117 finish:authorized:message:expiresAt:  ★ 主接管点 ──
    Class fp = NSClassFromString(kClsFingerprint);
    if (fp) {
        orig_finish = (void (*)(id, SEL, id, BOOL, id, id))
            COReplace(fp,
                      @"finish:authorized:message:expiresAt:",
                      (IMP)co_finish,
                      "QXA117.finish");
        if (orig_finish) installed++; else COLog("[警告] QXA117.finish 未装上");
    } else {
        COLog("[警告] 找不到类 %@", kClsFingerprint);
    }

    // ── ② QXA140 performPurpose:rootDeviceId:payload:completion: ──
    Class net = NSClassFromString(kClsNetLayer);
    if (net) {
        orig_perform = (void (*)(id, SEL, id, id, id, id))
            COReplace(net,
                      @"performPurpose:rootDeviceId:payload:completion:",
                      (IMP)co_perform,
                      "QXA140.performPurpose");
        if (orig_perform) installed++; else COLog("[警告] QXA140.performPurpose 未装上");
    } else {
        COLog("[警告] 找不到类 %@", kClsNetLayer);
    }

    // ── ③ QXA141 inputCard:transfer: ──
    Class binder = NSClassFromString(kClsBinder);
    if (binder) {
        orig_inputCard = (void (*)(id, SEL, id, BOOL))
            COReplace(binder,
                      @"inputCard:transfer:",
                      (IMP)co_inputCard,
                      "QXA141.inputCard");
        if (orig_inputCard) installed++; else COLog("[警告] QXA141.inputCard 未装上");
    } else {
        COLog("[警告] 找不到类 %@", kClsBinder);
    }

    // ── ④ QxF4 qxRefreshExpiry ──
    Class ui = NSClassFromString(kClsCardUI);
    if (ui) {
        orig_refresh = (void (*)(id, SEL))
            COReplace(ui, @"qxRefreshExpiry", (IMP)co_refresh, "QxF4.qxRefreshExpiry");
        if (orig_refresh) installed++; else COLog("[警告] QxF4.qxRefreshExpiry 未装上");
    } else {
        COLog("[警告] 找不到类 %@", kClsCardUI);
    }

    COLog("──────── 安装完成 %d/4 ────────", installed);
}

// ───────────────────────────────────────────────────────────────────────────
//  延迟安装（兜底）
//
//  ★ 为什么 2 秒后主线程：
//    dyld 阶段 App 自己的类可能尚未注册（+load 还没跑完），
//    NSClassFromString 会返回 nil。
//    固定延时比依赖 UIApplicationDidFinishLaunching 更稳（Scene 模式下可能不触发）。
//
//  ★ 这现在是**兜底**路径。首选路径是宿主主动 dlsym 调 CoreOfflineBootstrap。
// ───────────────────────────────────────────────────────────────────────────

static void COScheduleInstall(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            COLog("──────── [兜底] 2 秒延时安装 ────────");
            COInstall();
            COLog("──────── 计数器 fp=%d net=%d binder=%d ui=%d ────────",
                  gDidFP, gDidNet, gDidBinder, gDidUI);
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════
//  ★★★ 宿主预留的注入接口 ★★★
//
//  宿主的 __text 最前端内置了三个「弱符号跳板」（弱导入 weak_import）：
//
//      100003400  mov  x0, #-2              ; RTLD_DEFAULT
//      100003424  adr  x1, #"CoreOfflineBootstrap"
//      100003428  bl   dlsym
//      100003450  cbz  x16, skip            ; 找不到就跳过
//      100003458  br   x16                  ; 找到就调用
//
//  三个符号名（硬编码在宿主二进制里）：
//      CoreOfflineBootstrap   @0x100003464
//      CoreOfflinePrepare     @0x100003564
//      CoreOfflineFinalize    @0x100003664
//
//  ★ 所以 dylib **必须导出这三个 C 符号**（默认可见性，不能 static）。
//    宿主会主动来 dlsym 找我们 —— 这比 constructor/+load 的时机更可靠。
//
//  ★★ 完整清单是 **5 个**（本轮全量扫描 dlsym 跳板所得）：
//
//      跳板地址     dlsym 符号名              字符串 @        调用点
//      0x100003400  CoreOfflineBootstrap      0x100003464    0x10019ba28
//      0x100003500  CoreOfflinePrepare        0x100003564    0x10008ec80
//      0x100003600  CoreOfflineFinalize       0x100003664    0x10008cec4
//      0x100003800  CoreRemoteOpen            0x100003864    0x10003a7d4
//      0x100003900  CoreRemoteFault           0x100003964    0x100039844
//
//  ★ 后两个的调用约定（反汇编所得）：
//      CoreRemoteOpen  @0x10003a7d4
//          10003a7b8  add x0, x8, x9       ; x0 = 字符串/句柄指针
//          ...
//          （可能还有 x1 = options，但调用点未显式设置）
//      CoreRemoteFault @0x100039844
//          100039830  adrp x1, #0x10073d000
//          100039834  add  x1, x1, #0x6ae  ; x1 = "exception-filter-reply-failed"
//          100039838  mov  w0, #3          ; x0 = mode = 3
//          → CoreRemoteFault(uint64_t mode, const char *reason)
//
//  ★ 注意：不要在这里面做任何可能抛异常的事；
//    宿主是在它的初始化流程里调的，崩了就是整个 app 崩。
//    所以全部逻辑包 @try/@catch。
//
//  ★ 另外：这些函数**只是可选的诊断上报点**（宿主用 cbz 判 NULL），
//    不导出也不会崩，但导出才能让宿主走「找到」分支。
//    我们导出它们的意义是：① CI 断言要求；② 万一宿主想上报，给它一个安全的落点。
// ═══════════════════════════════════════════════════════════════════════════

/// 引导：宿主最早的调用点。装 hook 的主要时机。
__attribute__((visibility("default")))
void CoreOfflineBootstrap(void) {
    @try {
        @autoreleasepool {
            COLog("════════ [宿主调用] CoreOfflineBootstrap ════════");
            COInstall();
        }
    } @catch (NSException *e) {
        COLog("[Bootstrap] 异常已吞: %s", [[e reason] UTF8String]);
    }
}

/// 准备：环境就绪后宿主会再调一次。幂等，重复调用无副作用。
__attribute__((visibility("default")))
void CoreOfflinePrepare(void) {
    @try {
        @autoreleasepool {
            COLog("════════ [宿主调用] CoreOfflinePrepare ════════");
            COInstall();   // 幂等
            COLog("[Prepare] 计数器 fp=%d net=%d binder=%d ui=%d",
                  gDidFP, gDidNet, gDidBinder, gDidUI);
        }
    } @catch (NSException *e) {
        COLog("[Prepare] 异常已吞: %s", [[e reason] UTF8String]);
    }
}

/// 远端资源打开（宿主 @0x10003a7d4 调用，x0 = 指针）。
/// ★ 一律返回 NULL —— 表示「我这边没有额外的远端句柄」。
///   绝不能返回非 NULL，否则宿主会拿它当有效句柄去用。
__attribute__((visibility("default")))
void *CoreRemoteOpen(const char *name, uint64_t options) {
    @try {
        @autoreleasepool {
            COLog("[宿主调用] CoreRemoteOpen name=%s options=%llu → 返回 NULL",
                  name ? name : "(nil)", (unsigned long long)options);
        }
    } @catch (NSException *e) { }
    return NULL;
}

/// 异常上报（宿主 @0x100039844 调用，x0 = mode = 3，x1 = reason 字符串）。
/// ★ 只记日志，原样返回 mode，不做任何实际动作。
__attribute__((visibility("default")))
uint64_t CoreRemoteFault(uint64_t mode, const char *reason) {
    @try {
        @autoreleasepool {
            COLog("[宿主调用] CoreRemoteFault mode=%llu reason=%s",
                  (unsigned long long)mode, reason ? reason : "(nil)");
        }
    } @catch (NSException *e) { }
    return mode;
}

/// 收尾：宿主流程结束时调用。只做日志，不做任何有风险的事。
__attribute__((visibility("default")))
void CoreOfflineFinalize(void) {
    @try {
        @autoreleasepool {
            COLog("════════ [宿主调用] CoreOfflineFinalize ════════");
            COLog("[Finalize] 累计 fp=%d net=%d binder=%d ui=%d",
                  gDidFP, gDidNet, gDidBinder, gDidUI);
        }
    } @catch (NSException *e) {
        COLog("[Finalize] 异常已吞: %s", [[e reason] UTF8String]);
    }
}

// ───────────────────────────────────────────────────────────────────────────
//  构造函数：只做包名守卫 + 兜底排程
//
//  ★ 为什么这里**不**直接装 hook：
//    构造时机太早，宿主自己的 ObjC 类可能还没注册。
//    首选由宿主主动调 CoreOfflineBootstrap；这里只是兜底。
// ───────────────────────────────────────────────────────────────────────────

__attribute__((constructor))
static void COEntry(void) {
    @autoreleasepool {
        NSString *bid = nil;
        @try { bid = [[NSBundle mainBundle] bundleIdentifier]; }
        @catch (NSException *e) { bid = nil; }

        // 包名守卫：不是目标宿主就完全静默退出
        if (!bid || ![bid isEqualToString:kHostBundleID]) return;

        COLogOpen();
        COLog("════════ CoreOffline v3 (卡密接管版) 启动 ════════");
        COLog("pid=%d bundle=%s", getpid(), bid.UTF8String);

        // 记录宿主镜像位置（仅日志）
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            const char *nm = _dyld_get_image_name(i);
            if (nm && strstr(nm, ".app/Core")) {
                COLog("宿主镜像 base=%p path=%s", _dyld_get_image_header(i), nm);
                break;
            }
        }

        // 自检：确认 5 个导出符号确实存在（宿主会 dlsym 它们）
        COLog("[自检] 导出符号 Bootstrap=%p Prepare=%p Finalize=%p RemoteOpen=%p RemoteFault=%p",
              (void *)&CoreOfflineBootstrap,
              (void *)&CoreOfflinePrepare,
              (void *)&CoreOfflineFinalize,
              (void *)&CoreRemoteOpen,
              (void *)&CoreRemoteFault);

        COScheduleInstall();
    }
}
