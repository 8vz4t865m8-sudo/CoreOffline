# 宿主注入点逆向报告

**对象**：`Core-SET_1.6.ipa` → `Payload/Core.app/Core`
**二进制**：thin Mach-O，arm64e (cpusubtype `0x80000002`，PAC00)，12,999,856 字节
**时间**：2026-10-03
**结论**：宿主预留 5 个「功能留白」注入点，**一个都没被实现** —— 这是启动即崩的结构性原因。

---

## 一、宿主的 5 个 dlsym 跳板

宿主 `__text` 最前端（`0x100003400` ~ `0x100003970`）内置 5 个结构完全相同的跳板：

```asm
; ── CoreOfflineBootstrap 跳板 @0x100003400 ──
100003400  pacibsp
100003404  sub  sp, sp, #0x60
100003408  stp  x0, x1, [sp]          ; ★ 保存全部 8 个参数寄存器
10000340c  stp  x2, x3, [sp, #0x10]
100003410  stp  x4, x5, [sp, #0x20]
100003414  stp  x6, x7, [sp, #0x30]
100003418  stp  x8, x9, [sp, #0x40]
10000341c  stp  x29, x30, [sp, #0x50]
100003420  mov  x0, #-2               ; RTLD_DEFAULT
100003424  adr  x1, #0x100003464      ; "CoreOfflineBootstrap"（跳板内，adr 相对寻址）
100003428  bl   #0x100725a10          ; dlsym()
10000342c  mov  x16, x0
100003430  ldp  x0, x1, [sp]          ; ★ 恢复全部参数
100003434  ldp  x2, x3, [sp, #0x10]
100003438  ldp  x4, x5, [sp, #0x20]
10000343c  ldp  x6, x7, [sp, #0x30]
100003440  ldp  x8, x9, [sp, #0x40]
100003444  ldp  x29, x30, [sp, #0x50]
100003448  add  sp, sp, #0x60
10000344c  autibsp
100003450  cbz  x16, #0x10000345c     ; 找不到 → L_null
100003454  xpaci x16                  ; ★ 解签名（所以我们导出普通未签名 C 函数）
100003458  br   x16                   ; 找到 → 跳进我们的实现（参数原样透传）
10000345c  mov  x0, #0
100003460  ret
100003464  ...                        ; "CoreOfflineBootstrap" 字符串
```

### 完整清单

| 跳板地址 | 符号名 | 字符串 @ | 宿主调用点 | 调用形式 |
|---|---|---|---|---|
| `0x100003400` | `CoreOfflineBootstrap` | `0x100003464` | `0x10019ba28` | `b` |
| `0x100003500` | `CoreOfflinePrepare` | `0x100003564` | `0x10008ec80` | `b` |
| `0x100003600` | `CoreOfflineFinalize` | `0x100003664` | `0x10008cec4` | `b` |
| `0x100003800` | `CoreRemoteOpen` | `0x100003864` | `0x10003a7d4` | `b` |
| `0x100003900` | `CoreRemoteFault` | `0x100003964` | `0x100039844` | `b` |

**全部 5 个调用点都是无条件 `b`（尾调用）**，各只有 1 处引用（全量扫描 `b`/`bl` 确认）。

---

## 二、为什么这是「功能留白」而不是「可选回调」

宿主调用点的实际布局（以 `CoreOfflinePrepare` 为例）：

```asm
10008ec80  b  #0x100003500        ; ← 跳到跳板（尾调用，不返回）
10008ec84  sub sp, sp, #0x1f0     ; ← 宿主「原本的实现」，成为死代码
10008ec88  stp x24, x23, [sp, #0x1b0]
...
```

因为 `b` 是尾调用，跳板里的 `ret` 回到的是**调用 `0x10008ec80` 的那一层**，而不是 `0x10008ec84`：

| dlsym 结果 | 实际发生的事 |
|---|---|
| **找到符号** | 执行我们的函数，我们 `ret` 回到宿主的上层 |
| **没找到符号** | 跳板 `mov x0,#0; ret`，同样回到宿主的上层 |

**两种情况，宿主自己跟在 `b` 后面的那段都被跳过 —— 宿主把它留空，等的就是注入方来实现。**

宿主当前状态：`LC_LOAD_DYLIB` 共 68 条，**全是系统库**（唯一 `@executable_path` 是 `LC_RPATH @0x2fd4`）。一个注入方都没有 → 5 个点全部扑空。

**这就是「什么都不改也崩」的结构性原因。**

---

## 三、5 个调用点的语义还原

### 3.1 `CoreOfflineBootstrap` @`0x10019ba28`

所在函数起于 `0x10019b8e8`（**无任何静态调用者**，由 runtime / 地址表间接调用）。

```asm
10019ba1c  mov  x0, x20
10019ba20  bl   #0x100724d00      ; objc_release 一类
10019ba24  b    #0x10019cc70      ; ★ 正常出口
10019ba28  b    #0x100003400      ; ★ 另一出口 → Bootstrap
10019ba2c  sub  sp, sp, #0x90     ; （宿主原本的实现）
```

`0x10019ba24` 与 `0x10019ba28` 是**并排的两个出口**。Bootstrap 位于异常/清理路径上。

### 3.2 `CoreOfflinePrepare` @`0x10008ec80`

```asm
; 前文
10008ec60  add  x1, x1, #0x9f0
10008ec64  adrp x2, #0x100000000
10008ec68  add  x2, x2, #0
10008ec6c  adrp x16, #0x10008c000
10008ec70  add  x16, x16, #0xafc
10008ec74  paciza x16
10008ec78  mov  x0, x16
10008ec7c  b    #0x100725290
10008ec80  b    #0x100003500      ; ★ 这里
10008ec84  sub  sp, sp, #0x1f0     ; （死代码）
```

### 3.3 `CoreOfflineFinalize` @`0x10008cec4`

```asm
10008cea4  bl   #0x10008d794
10008cea8  ldp  x29, x30, [sp], #0x10
10008ceac  autibsp
10008ceb0  eor  x16, x30, x30, lsl #1   ; PAC 校验
10008ceb4  tbz  x16, #0x3e, #0x10008cebc
10008ceb8  brk  #0xc471
10008cebc  b    #0x100725240
10008cec0  ret
10008cec4  b    #0x100003600      ; ★ 这里（dealloc 路径）
```

### 3.4 `CoreRemoteOpen` @`0x10003a7d4` —— ★ 签名关键

```asm
10003a778  pacibsp
10003a77c  stp  x29, x30, [sp, #-0x10]!
10003a780  mov  x29, sp
10003a784  cbz  w0, #0x10003a79c    ; 入参 w0 决定分支
10003a788  bl   #0x1000387cc
10003a78c  mov  w0, #1
10003a790  bl   #0x100726a20
10003a794  bl   #0x1000387e4
10003a798  b    #0x10003a7a4
10003a79c  mov  w0, #1              ; 另一分支
10003a7a0  bl   #0x100726a20
10003a7a4  adrp x8, #0x100c53000
10003a7a8  ldr  x8, [x8, #0x4a8]    ; ★ 全局指针
10003a7ac  adrp x9, #0x100c53000
10003a7b0  add  x9, x9, #0x354
10003a7b4  ldr  w9, [x9]            ; ★ 全局 int
10003a7b8  add  x0, x8, x9          ; ★★ x0 = 基址 + 偏移（已算好的地址！）
10003a7bc  ldp  x29, x30, [sp], #0x10
10003a7c0  autibsp
10003a7c4  eor  x16, x30, x30, lsl #1
10003a7c8  tbz  x16, #0x3e, #0x10003a7d0
10003a7cc  brk  #0xc471
10003a7d0  b    #0x100035794        ; ★ 正常出口（宿主自己的实现）
10003a7d4  b    #0x100003800        ; ★ 注入出口
```

**`x0` 不是字符串、不是函数名，是一个已经算好的内存地址。**

宿主自己的实现（`0x100035794` → `0x1000322fc`）：

```asm
1000322fc  pacibsp
100032300  sub  sp, sp, #0x20
10003230c  str  xzr, [sp, #8]       ; 局部变量 = 0
100032310  add  x1, sp, #8          ; x1 = &local
100032314  mov  w2, #8              ; w2 = 8
100032318  bl   #0x1000321e0        ; 内部实现
10003231c  ldr  x0, [sp, #8]        ; ★ 返回读到的 8 字节
100032320  ldp  x29, x30, [sp, #0x10]
100032324  add  sp, sp, #0x20
100032328  retab
```

**结论**：这是个「读取全局状态」的函数，返回 8 字节值。

⚠️ **早期版本把它写成 `(const char *name, uint64_t options)` 并当字符串打印 —— 会去解引用宿主内存，是真实的踩空风险。已修正为 `(uint64_t opaque_handle, uint64_t arg2)`，只记数值、绝不解引用，且必须返回 `NULL`。**

### 3.5 `CoreRemoteFault` @`0x100039844` —— ★ 返回值无意义

```asm
1000397c0  bl   #0x100038618
1000397c4  cbz  w0, #0x1000397e8
1000397c8  ldr  w8, [sp, #0x20]
1000397cc  cmp  w8, #1
1000397d0  cset w21, eq              ; ★ w21 才是函数返回值
1000397d4  b.eq #0x10003981c
1000397d8  mov  x0, sp
1000397dc  add  x1, x23, #0x40
1000397e0  bl   #0x100038654
1000397e4  tbz  w0, #0, #0x100039830 ; ← 失败则跳下去
1000397e8  mov  w0, #4
1000397ec  bl   #0x1007257d0
1000397f0  cmp  x0, x22
1000397f4  b.lo #0x100039768
1000397f8  mov  w21, #0
1000397fc  mov  x0, x21              ; ★ 返回 w21
100039800  ldp  x29, x30, [sp, #0x1a0]
...
100039818  retab
10003981c  mov  x1, sp
100039820  mov  x0, x19
100039824  mov  w2, #0x160
100039828  bl   #0x100725ef0
10003982c  b    #0x1000397fc
100039830  adrp x1, #0x10073d000
100039834  add  x1, x1, #0x6ae      ; "exception-filter-reply-failed"
100039838  mov  w0, #3              ; mode = 3
10003983c  bl   #0x100039844        ; ★ 调用跳板
100039840  b    #0x1000397fc        ; ★★ 返回值被完全忽略，直接走人
```

**`bl` 后紧跟 `b` → 我们返回什么宿主都不看。** 这是纯「异常上报」接口。

---

## 四、宿主签名与版本信息

```
CFBundleIdentifier           = qingxiugai.qingxiugai.qinxiugai
CFBundleShortVersionString   = 1.6
CFBundleDisplayName          = Core-SET
MinimumOSVersion             = 10.0
UIRequiredDeviceCapabilities = ['arm64e']       ← 需 A12 及以上
UIBackgroundModes            = ['audio']
OKDDistributionMode          = 'self-signed'    ← 打包工具标记
OKDFeedbackBundleIdentifier  = 'com.apple.podcasts'

embedded.mobileprovision:
  Name                 : Zlq
  TeamIdentifier       : 4NL2FZJ2T5
  ExpirationDate       : 2027-01-14 15:35:36
  application-identifier : 4NL2FZJ2T5.com.COwPQ.B2t8tot   ← ★ 与 bundle id 不匹配
  get-task-allow         : False                          ← 崩了没日志

LC_ENCRYPTION_INFO_64: cryptoff=0x4000 cryptsize=0xb84000 cryptid=0 → 已解密
```

### 段布局

```
__PAGEZERO      va=0x000000000  size=0x100000000
__TEXT          va=0x100000000  size=0x0b88000   fo=0x0
__DATA_CONST    va=0x100b88000  size=0x003c000   fo=0xb88000
__DATA          va=0x100bc4000  size=0x00b0000   fo=0xbc4000
__LINKEDIT      va=0x100c74000  size=0x0058000   fo=0xc18000
```

### 两个 bundle id 字符串（★ 关键）

二进制里有**两个不同的** bundle id 字符串：

| 文件偏移 | VA | 位置 | 内容 |
|---|---|---|---|
| `0x750ca9` | `0x100750ca9` | `__TEXT`（CFString 常量池） | `qingxiugai.qingxiugai.qingxiugai` ← **全拼，无 `qinx`** |
| `0xc2c97c` | `0x100c8897c` | `__DATA` | `qingxiugai.qingxiugai.qinxiugai` |
| `0xc45053` | `0x100ca1053` | `__DATA`（plist 片段） | `qingxiugai.qingxiugai.qinxiugai` |

`0x100750ca9` 处的 CFString 结构：

```
[0x100bb0f18] cstr_ptr = 0x0010000000750ca9
[0x100bb0f20] length   = 0x20 = 32          ← 32 字符 = "qingxiugai.qingxiugai.qingxiugai"
[0x100bb0f28] flags    = 0xc0156ae10000039b （bit4 = 0 → UTF-8，不是 UTF-16）
```

自签工具弹的「请修改应用 Bundle ID」用的正是**全拼那个**（其"默认占位值"即此串）。

---

## 五、关于「改 Bundle ID 就弹窗」的解释

用户实测三种情况：

| Bundle ID | 结果 |
|---|---|
| 不改 | 直接闪退 |
| 改成 `ABCD` | 弹「请修改应用 Bundle ID」→ 干净退出 |
| 改成合规值 `com.xxx.yyy` | 仍然直接闪退 |

**三种都是「进不去」，只是失败位置不同：**

- **不改** → 自签工具放行 → 宿主走到 5 个注入点扑空 → 崩
- **乱改** → 自签工具的 bundle id 校验先拦住（那是**工具弹的，不是 App 弹的**）→ 根本没进 App
- **合规改** → 工具放行，但宿主那边仍因注入点缺失而崩

**结论：改 Bundle ID 是死路，且它同时会让 `application-identifier` 与 bundle id 的错配进一步变化。正确做法是保持 Bundle ID 原样不动，让 dylib 去补那 5 个注入点。**

---

## 六、相关字符串常量池（`0x100750600` ~ `0x100750eb6`）

这段是**连续的 `__cstring` 常量池**，混有 Lua 解释器字符串（`stack traceback:`、`main chunk`、`attempt to load a %s chunk`），表明宿主的卡密逻辑由 Lua 驱动。

```
0x7507a3  /api/version/check
0x7507e2  package_bundle_id
0x7508c5  CFBundleExecutable
0x7508d8  OKDDistributionMode
0x750923  Core-iOS17-26-v%@.ipa
0x750a7b  https://api.klpjwycb.xyz:2053/check/client-startup-status
0x750ab5  device_hash=%@&product=%@
0x750ade  NEEDS_IDENTITY_BINDING
0x750d1b  QXA120
0x750d36  Kernel
0x750d3d  GetTTEP
0x750d4f  kernel capability is provided by the DarkSword menu after V2 startup
0x750d94  GAME
0x750d99  self_signed
0x750da5  device_identifier
0x750db7  material_runtime_required
0x750dd1  v2_required
0x750df6  QXA118
0x750e01  qx.server.contact.v1
0x750e16  https://test.klpjwycb.xyz:2053/check/regist2cardunlimit
0x750e4e  mac=%@&card=%@
0x750e7c  ws://api.klpjwycb.xyz:8880/26sk/ios
0x750ea0  qx.startup.attempt.v1
```

### 环境注入函数 @`0x1001a4dec`

被 `0x10019ba50` 调用（即 Bootstrap 调用点**紧后面**那个函数的开头），向某个环境对象注入：

```asm
1001a4e40  add  x1, x1, #0xd36   ; "Kernel"
1001a4e64  add  x1, x1, #0xd3d   ; "GetTTEP"
1001a4e7c  add  x1, x1, #0xd45   ; "available"
1001a4e98  add  x2, x2, #0xd4f   ; "kernel capability ... DarkSword"
1001a4ea8  add  x1, x1, #0xd94   ; "GAME"
1001a4ec4  add  x1, x1, #0xd99   ; "self_signed"        ← 值 = 1
1001a4ee8  add  x1, x1, #0xda5   ; "device_identifier"
1001a4f04  add  x1, x1, #0xdb7   ; "material_runtime_required"  ← 值 = 1
1001a4f1c  add  x1, x1, #0xdd1   ; "v2_required"        ← 值 = 1
1001a4f64  add  x1, x1, #0xddd   ; "LOG"
```

以及 `0x1001a80c0` 处引用 `ws://api.klpjwycb.xyz:8880/26sk/ios`，紧接着 `0x1001a80d4 bl #0x10008ec80` —— **正是 `CoreOfflinePrepare` 的调用点**。

---

## 七、结论

| 编号 | 结论 | 证据 |
|---|---|---|
| **C1** | 宿主预留 5 个注入点，**一个都没实现** | 68 条 LC 全系统库；5 个跳板 dlsym 全部会返回 NULL |
| **C2** | 这 5 个点是「功能留白」，宿主自己那段是死代码 | 调用点全是 `b`（尾调用），跳板 ret 回到上层 |
| **C3** | `CoreRemoteOpen` 的 x0 是**内存地址**，非字符串 | `0x10003a7b8 add x0, x8, x9` |
| **C4** | `CoreRemoteFault` 返回值被完全忽略 | `0x10003983c bl` → `0x100039840 b` |
| **C5** | 改 Bundle ID 是死路 | 三种改法全部进不去 |
| **C6** | 宿主签名 `application-identifier` 与 bundle id 本就不匹配 | `4NL2FZJ2T5.com.COwPQ.B2t8tot` vs `qingxiugai...` |

**对应的 v3 实现**：导出全部 5 个符号，一律「不做实事、立刻返回」
（`CoreRemoteOpen` 返回 NULL 且不解引用参数），全部 `@try` 兜底，零阻塞、零网络。
详见 `src/CoreOffline.m` 与 `checks/host_parity.py`（29 项断言）。
