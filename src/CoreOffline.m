// ═══════════════════════════════════════════════════════════════════════════
//  CoreOffline.m —— 宿主 Core 1.6 卡密接管版  (v3 · 全部签名经反汇编核实)
//
//  ── v3 相对 v2 的关键变化 ────────────────────────────────────────────────
//  ★★★ 导出宿主预留的 5 个 C 符号 ★★★
//
//  宿主二进制里内置了 5 个「dlsym 跳板」，会主动查找并调用这 5 个符号：
//
//      CoreOfflineBootstrap   @0x100003464  ← 跳板 0x100003400，调用点 0x10019ba28
//      CoreOfflinePrepare     @0x100003564  ← 跳板 0x100003500，调用点 0x10008ec80
//      CoreOfflineFinalize    @0x100003664  ← 跳板 0x100003600，调用点 0x10008cec4
//      CoreRemoteOpen         @0x100003864  ← 跳板 0x100003800，调用点 0x10003a7d4
//      CoreRemoteFault        @0x100003964  ← 跳板 0x100003900，调用点 0x100039844
//
//  跳板代码（宿主 __text 最前端，0x100003400 起，5 个结构完全相同）：
//      100003408  stp  x0, x1, [sp]  ...             ; 保存全部参数寄存器
//      100003420  mov  x0, #-2                       ; RTLD_DEFAULT
//      100003424  adr  x1, #"CoreOfflineBootstrap"
//      100003428  bl   #0x100725a10                  ; dlsym
//      100003430  ldp  x0, x1, [sp]  ...             ; 恢复全部参数
//      100003450  cbz  x16, #0x10000345c             ; NULL 就返回 0
//      100003454  xpaci x16 ; br x16                 ; 有就执行（参数原样透传）
//
//  ★ 所以本 dylib 必须**导出**这 5 个符号（visibility default，非 static）。
//
//  ★★ 关键认识：这 5 个点是「功能留白」而不是「可选回调」。
//     宿主调用点都是 `b`（尾调用），跳板的 ret 回到调用者的上一层，
//     所以宿主自己跟在后面的那段代码是**死代码** —— 宿主把它留空，
//     等的就是注入方来实现。宿主未注入任何 dylib 时这 5 处全部扑空，
//     这就是「什么都不做也崩」的结构性原因。
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
//    ④ ★ 宿主预留的 5 个注入点一个都没实现（宿主自己那段是死代码）
//
//  ── 本版原则 ────────────────────────────────────────────────────────────
//    1. 绝不自己调用任何 completion block
//    2. 零全局类遍历，只按名字取 4 个确定的类
//    3. 零 Keychain / 零 Security / 零 CFNetwork 依赖
//    4. 安装幂等，所有 hook 体 @try/@catch 兜底
//    5. 导出宿主预留的 5 个符号，且全部「不做实事、立刻返回」
//       CoreRemoteOpen 必须返回 NULL（宿主会当句柄用）
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
//  ★★★ 宿主预留的 5 个注入接口 —— 这是「功能留白」，不是「可选回调」★★★
//
//  【机制】宿主在 5 个位置各放了一条**无条件 b 指令**，尾调用进跳板：
//
//      跳板（以 Bootstrap 为例，0x100003400）：
//        pacibsp
//        stp  x0, x1, [sp] ...          ; 保存全部 8 个参数寄存器 + x29/x30
//        mov  x0, #-2                   ; RTLD_DEFAULT
//        adr  x1, "CoreOfflineBootstrap" ; 符号名（在跳板内，adr 相对寻址）
//        bl   dlsym                     ; 找我们的导出符号
//        mov  x16, x0
//        ldp  x0, x1, [sp] ...          ; 恢复全部参数
//        cbz  x16, L_null               ; 没找到 → 走 L_null
//        xpaci x16                      ; ★ 解签名（所以我们导出未签名的普通 C 函数）
//        br   x16                       ; 找到 → 跳进我们的实现（参数原样透传）
//      L_null:
//        mov  x0, #0
//        ret
//
//  【为什么这是「留白」而不是「回调」】
//    宿主调用点是这样的：
//        0x10008ec80  b  #0x100003500      ; ← 跳到 CoreOfflinePrepare 跳板
//        0x10008ec84  sub sp, sp, #0x1f0   ; ← 宿主「原本的实现」，变成死代码
//    因为 `b` 是尾调用，跳板里的 `ret` 回到的是**调用 0x10008ec80 的那一层**，
//    而不是 0x10008ec84。所以：
//      · 没找到符号 → 直接返回给上层，0x10008ec84 那段永远不执行
//      · 找到符号   → 执行我们的函数，我们 ret 同样回到上层
//    两种情况宿主自己那段都被跳过 —— 宿主把那几处留空，等的就是注入方来填。
//
//  【5 个点的完整清单（全部实测反汇编确认）】
//
//    跳板地址     dlsym 符号名              字符串 @        调用点         性质
//    0x100003400  CoreOfflineBootstrap      0x100003464    0x10019ba28    启动/清理路径
//    0x100003500  CoreOfflinePrepare        0x100003564    0x10008ec80    初始化（网络前）
//    0x100003600  CoreOfflineFinalize       0x100003664    0x10008cec4    收尾（dealloc 路径）
//    0x100003800  CoreRemoteOpen            0x100003864    0x10003a7d4    读全局状态
//    0x100003900  CoreRemoteFault           0x100003964    0x100039844    异常上报
//
//  【调用约定（逐个反汇编所得，★ 本轮修正）】
//
//    · CoreOfflineBootstrap / Prepare / Finalize
//        无显式入参，返回值被宿主忽略。
//        跳板透传 x0~x7，我们拿到的是宿主调用点的原始寄存器值 —— 不要假设含义。
//
//    · CoreRemoteOpen  @0x10003a7d4
//        调用点前文：
//          0x10003a7a4  adrp x8, #0x100c53000
//          0x10003a7a8  ldr  x8, [x8, #0x4a8]   ; 全局指针
//          0x10003a7b0  add  x9, x9, #0x354
//          0x10003a7b4  ldr  w9, [x9]           ; 全局 int
//          0x10003a7b8  add  x0, x8, x9         ; ★ x0 = 全局对象基址 + 偏移
//        所以 x0 **不是函数名、不是字符串，是一个已算好的内存地址**。
//        （v3 早期版本把它当 const char * 打印是错的，已修正为只记数值。）
//        ★ 必须返回 NULL —— 宿主会把它当句柄用，返回非 NULL 会跳进对不上的约定。
//
//    · CoreRemoteFault @0x100039844
//        调用点前文：
//          0x100039830  adrp x1, #0x10073d000
//          0x100039834  add  x1, x1, #0x6ae      ; x1 = "exception-filter-reply-failed"
//          0x100039838  mov  w0, #3              ; w0 = 3
//          0x10003983c  bl   #0x100039844        ; 调到跳板
//          0x100039840  b    #0x1000397fc        ; ★ 返回值被完全忽略
//        → CoreRemoteFault(uint64_t mode, const char *reason)
//        ★ 返回值无关紧要（宿主 bl 完就 b 走了），但不能崩、不能阻塞。
//
//  【铁律】
//    ① 绝不做任何可能抛异常的事 —— 全部包 @try/@catch
//    ② 绝不阻塞（不等待、不 sleep、不发网络请求）—— 这些点在宿主主流程上
//    ③ CoreRemoteOpen 必须返回 NULL
//    ④ 日志也要防崩（COLog 内部有保护），并加静态计数器防日志淹没
// ═══════════════════════════════════════════════════════════════════════════

// 计数器：这 5 个点可能被高频调用，日志只打前若干次
static int gBootCalls = 0;
static int gPrepCalls = 0;
static int gFinCalls  = 0;
static int gOpenCalls = 0;
static int gFaultCalls = 0;
#define CO_LOG_EVERY 8   // 前 8 次全打，之后每 8 次打一次

/// 引导：宿主启动/清理路径上的必经点。装 hook 的时机。
__attribute__((visibility("default")))
void CoreOfflineBootstrap(void) {
    gBootCalls++;
    @try {
        @autoreleasepool {
            COLog("════════ [宿主调用] CoreOfflineBootstrap (#%d) ════════", gBootCalls);
            COInstall();
        }
    } @catch (NSException *e) {
        COLog("[Bootstrap] 异常已吞: %s", [[e reason] UTF8String]);
    }
}

/// 准备：宿主初始化早期（网络初始化之前）调用。幂等，重复调用无副作用。
__attribute__((visibility("default")))
void CoreOfflinePrepare(void) {
    gPrepCalls++;
    @try {
        @autoreleasepool {
            if (gPrepCalls <= CO_LOG_EVERY || (gPrepCalls % CO_LOG_EVERY) == 0) {
                COLog("════════ [宿主调用] CoreOfflinePrepare (#%d) ════════", gPrepCalls);
            }
            COInstall();   // 幂等
        }
    } @catch (NSException *e) {
        COLog("[Prepare] 异常已吞: %s", [[e reason] UTF8String]);
    }
}

/// 远端状态查询（宿主 @0x10003a7d4 调用）。
///
/// ★ x0 是宿主算好的「全局对象基址 + 偏移」地址，**不是字符串**。
///   我们只把它当数值记录，绝不解引用（那是宿主的内存，可能还没初始化）。
///
/// ★ 一律返回 NULL —— 表示「我这边没有额外的远端句柄」。
///   绝不能返回非 NULL：宿主会拿它当有效句柄用，而我们对不上它的结构。
__attribute__((visibility("default")))
void *CoreRemoteOpen(uint64_t opaque_handle, uint64_t arg2) {
    gOpenCalls++;
    if (gOpenCalls <= CO_LOG_EVERY || (gOpenCalls % CO_LOG_EVERY) == 0) {
        @try {
            @autoreleasepool {
                // ★ 不解引用 opaque_handle —— 只记录数值
                COLog("[宿主调用] CoreRemoteOpen (#%d) handle=0x%llx arg2=0x%llx → 返回 NULL",
                      gOpenCalls,
                      (unsigned long long)opaque_handle,
                      (unsigned long long)arg2);
            }
        } @catch (NSException *e) { }
    }
    return NULL;
}

/// 异常上报（宿主 @0x100039844 调用，w0 = mode = 3，x1 = reason 字符串）。
/// ★ 返回值被宿主忽略（bl 完就 b 走了），原样返回 mode 即可。
///   只记日志，不做任何实际动作。
__attribute__((visibility("default")))
uint64_t CoreRemoteFault(uint64_t mode, const char *reason) {
    gFaultCalls++;
    if (gFaultCalls <= CO_LOG_EVERY || (gFaultCalls % CO_LOG_EVERY) == 0) {
        @try {
            @autoreleasepool {
                // reason 是宿主的 __cstring 字面量，读它是安全的
                COLog("[宿主调用] CoreRemoteFault (#%d) mode=%llu reason=%s",
                      gFaultCalls,
                      (unsigned long long)mode,
                      reason ? reason : "(null)");
            }
        } @catch (NSException *e) { }
    }
    return mode;
}

/// 收尾：宿主流程结束时（dealloc 路径）调用。只做日志，不做任何有风险的事。
__attribute__((visibility("default")))
void CoreOfflineFinalize(void) {
    gFinCalls++;
    @try {
        @autoreleasepool {
            if (gFinCalls <= CO_LOG_EVERY || (gFinCalls % CO_LOG_EVERY) == 0) {
                COLog("════════ [宿主调用] CoreOfflineFinalize (#%d) ════════", gFinCalls);
                COLog("[Finalize] 累计 boot=%d prep=%d open=%d fault=%d | hook fp=%d net=%d binder=%d ui=%d",
                      gBootCalls, gPrepCalls, gOpenCalls, gFaultCalls,
                      gDidFP, gDidNet, gDidBinder, gDidUI);
            }
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
