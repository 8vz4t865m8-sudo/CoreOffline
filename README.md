# CoreOffline v3 —— 宿主 Core 1.6 卡密接管

> **唯一目标：让 dylib 注入宿主 `Core-SET_1.6` 后能正常进去，并接管卡密验证。**
>
> 全部结论来自对宿主 `Core` 二进制（13,039,840 字节，thin arm64e）的静态逆向。

---

## 0. 先看这个：为什么之前一直闪退

**不是 dylib 内容的问题。** 本轮把宿主完整拆开后确认了三件事：

| # | 发现 | 结论 |
|---|---|---|
| **①** | 宿主 `LC_LOAD_DYLIB` 共 36 条，**全是系统库**，没有任何一条指向自定义 dylib | 当前 IPA 里**压根没注入 dylib** → 闪退与 dylib 内容无关 |
| **②** | ESign 签名：profile 的 `application-identifier` = `4NL2FZJ2T5.com.COwPQ.B2t8tot`，而 `Info.plist` 的 `CFBundleIdentifier` = `qingxiugai.qingxiugai.qinxiugai` | **签名身份错配** → entitlement 校验失败 |
| **③** | `embedded.mobileprovision` 里 `get-task-allow = False` | 崩了**拿不到任何日志** |

顺带排除一个常见误判：二进制 `cryptid=0`、`__text` 熵值 6.55 —— **已解密**，不是加密导致的加载失败。

详见 [`/workspace/卡密逆向/闪退根因分析.md`](闪退根因分析.md)。

---

## 1. ★★★ 最重要的发现：宿主预留了 5 个注入接口 ★★★

宿主 `__text` 最前端（`0x3400` ~ `0x3900`）内置了 **5 个 `dlsym` 弱符号跳板**：

```asm
100003420  mov  x0, #-2                     ; RTLD_DEFAULT
100003424  adr  x1, #"CoreOfflineBootstrap" ; 符号名
100003428  bl   #0x100725a10                ; dlsym()
...
100003450  cbz  x16, skip                   ; 找不到就跳过
100003454  xpaci x16 ; br x16               ; 找到就调用
```

完整清单（全量扫描所得，不是猜的）：

| 跳板地址 | 符号名 | 字符串 @ | 宿主的调用点 |
|---|---|---|---|
| `0x100003400` | `CoreOfflineBootstrap` | `0x100003464` | `0x10019ba28` |
| `0x100003500` | `CoreOfflinePrepare` | `0x100003564` | `0x10008ec80` |
| `0x100003600` | `CoreOfflineFinalize` | `0x100003664` | `0x10008cec4` |
| `0x100003800` | `CoreRemoteOpen` | `0x100003864` | `0x10003a7d4` |
| `0x100003900` | `CoreRemoteFault` | `0x100003964` | `0x100039844` |

> **命名里的 "CoreOffline" 就硬编码在宿主二进制里** —— 这不是我们起的名字。
> 原包的设计意图就是「让一个叫 CoreOffline 的 dylib 来接管」。

**所以 dylib 必须导出这 5 个 C 符号。** 宿主会主动来 `dlsym` 找我们 ——
这比 `constructor` / `+load` 的时机可靠得多。

两个额外符号的调用约定（反汇编所得）：

```asm
; CoreRemoteOpen @0x10003a7d4
10003a7b8  add  x0, x8, x9        ; x0 = 句柄/字符串指针
                                  ; → 我们一律返回 NULL（表示无额外句柄）

; CoreRemoteFault @0x100039844
100039830  adrp x1, #0x10073d000
100039834  add  x1, x1, #0x6ae    ; x1 = "exception-filter-reply-failed"
100039838  mov  w0, #3            ; x0 = mode = 3
                                  ; → uint64_t CoreRemoteFault(uint64_t, const char*)
```

---

## 2. 接管策略：只改一个收敛点

### 2.1 主接管点：`QXA117 finish:authorized:message:expiresAt:`

`QXA117` 一共 12 个方法（`ro=0x100bc9d08`）：

```
finish:authorized:message:expiresAt:    @0x10017a5dc  v44@0:8@?16B24@28@36   ★
verifyDeviceIdentifier:completion:      @0x10017a784  v32@0:8@16@?24
md5ForDeviceIdentifier:                 @0x10017a3d8
expiryDateFromString:                   @0x10017a4f4
...
```

**所有**卡密结论（成功 / 网络失败 / 解析失败 / "当前设备尚未授权"）最终都调用 `finish:`。
它是唯一的终态判决出口。

反汇编显示它**自己在栈上构造 block 再 invoke**：

```asm
10017a5f4  mov   x19, x5           ; expiresAt
10017a5f8  mov   x20, x4           ; message
10017a5fc  mov   x21, x3           ; authorized (BOOL)
10017a614  mov   x8, sp            ; 在栈上构造 block
10017a628  pacda x16, x17          ; PAC 签名 invoke 指针
10017a65c  strb  w21, [sp, #0x38]  ; authorized 塞进 block
10017a660  str   x20, [sp, #0x20]  ; message 塞进 block
10017a664  bl    #0x1007262f0      ; 然后 invoke
```

> **这是最理想的 hook 点**：我们只改 `authorized=YES`，然后把参数**交回宿主原实现**，
> block 调用完全由宿主负责 —— **零 `blraa`、零 `objc_msgSend`、零 PAC 风险**。

### 2.2 辅助 hook（只观测，不改写）

| 类 | 方法 | 地址 | type encoding |
|---|---|---|---|
| `QXA140` | `performPurpose:rootDeviceId:payload:completion:` | `0x10018a888` | `v48@0:8@16@24@32@?40` |
| `QXA141` | `inputCard:transfer:` | `0x100187608` | `v28@0:8@16B24` |
| `QxF4` | `qxRefreshExpiry` | `0x1001a28ec` | `v16@0:8` |

**为什么 `QXA140` 不接管**：hook `finish:` 已经足够（网络失败也会走到它）。
少一个 hook = 少一个崩溃面。而且它的 completion block 实测是 **4 参数**
（`(id, BOOL, NSString*, id)`），自己调必然要猜签名 —— 上一版就是这么崩的。

---

## 3. 三条铁律（前几版闪退的教训）

### 铁律一：**绝不自己调用任何 completion block**

上一版把 `completion` 强转成 `(BOOL, id)` 两参数调用，而宿主实际传的是 4 个参数：

```asm
; QXA140 失败分支 @0x10018aa28
10018aa38  mov  x0, x22      ; block
10018aa3c  mov  x1, #0       ; ← 有第 2 个参数
10018aa40  blraa x9, x8      ; block(x0, x1, x2, ...)
```

差参数 → 寄存器 `x2`/`x3` 是垃圾指针 → `objc_msgSend` 到野地址 → 必崩。
**v3 一个 block 都不自己调。**

### 铁律二：**不做全局类遍历**

`objc_copyClassList` 在 dyld 阶段可能拿到未注册完的类，
且 chained fixup 指针可能是 PAC 签名态，直接解引用会触发 PAC 校验失败。

v3 只按**精确名字**取 4 个确定的类。

### 铁律三：**不链 Security / Keychain**

自签重打包后 `SecItemAdd` 返回 `errSecMissingEntitlement (-34018)`。
宿主自己链了 Security，但我们的 dylib 不需要 —— 加了只会多一层 dyld 初始化。

---

## 4. 构建

```bash
make check     # 宿主对齐检查（纯 Python，任何机器可跑）
make           # 默认双切片 arm64 + arm64e
```

### 4.1 ★ 必须验证的三件事

```bash
# ① 五个符号必须全部导出
nm -gU CoreOffline.v3.dylib | grep -E "CoreOffline|CoreRemote"
# 期望：
#   _CoreOfflineBootstrap   _CoreOfflineFinalize   _CoreOfflinePrepare
#   _CoreRemoteFault        _CoreRemoteOpen

# ② install name
otool -D CoreOffline.v3.dylib
# 期望：@executable_path/CoreOffline.v3.dylib

# ③ 依赖只有 Foundation + UIKit
otool -L CoreOffline.v3.dylib
# 不应该看到 Security / CFNetwork / CryptoKit / QuartzCore
```

### 4.2 ⚠️ 改了 Bundle ID 就要同步改源码

```objc
// src/CoreOffline.m
static NSString *const kHostBundleID = @"qingxiugai.qingxiugai.qinxiugai";
```

不改的后果：包名守卫不通过 → dylib 静默退出 → **app 能进但卡密没被接管**。

---

## 5. 注入与安装

当前 IPA 用的是 ESign + 一个 `get-task-allow=False` 的 profile。**建议换 Sideloadly**：

```
Apple ID   : 你自己的（免费账号即可）
IPA        : Core-SET_1.6.ipa
☑ Modify Bundle Identifier   ← 关键！修正 app-id 不匹配
☑ Add dylib → CoreOffline.v3.dylib → ☑ Inject into executable
```

手动注入的话（inject + ESign）见 [`v3构建与注入指南.md`](v3构建与注入指南.md)。

---

## 6. 验证是否真的进去了

app 启动后看 Sandbox 里的 `Documents/CoreOffline.log`：

```
════════ CoreOffline v3 (卡密接管版) 启动 ════════
pid=1234 bundle=qingxiugai.qingxiugai.qinxiugai
宿主镜像 base=0x102a00000 path=.../Core.app/Core
[自检] 导出符号 Bootstrap=0x... Prepare=0x... Finalize=0x... RemoteOpen=0x... RemoteFault=0x...
════════ [宿主调用] CoreOfflineBootstrap ════════       ← ★ 宿主主动来调了
──────── 安装完成 4/4 ────────
```

操作卡密界面时：

```
[接管] QXA117 finish: authorized(orig)=0 message=设备身份不可用 expiresAt=(nil)
[接管] QXA117 → 改写为 authorized=YES expiresAt=2099-12-31 23:59:59，交回宿主原实现
```

| 现象 | 判断 |
|---|---|
| `[宿主调用] CoreOfflineBootstrap` + `安装完成 4/4` | ✅ 成功 |
| 只有 `[兜底] 2 秒延时安装` | ⚠️ 符号查找失败，查 `nm -gU` |
| `安装完成 2/4` | ⚠️ 部分类名不对，对照类名表 |
| 完全没有日志文件 | 🔴 dylib 没被加载，查 `otool -L` |
| 秒退无日志 | 🔴 `get-task-allow` 还是 False |

---

## 7. 宿主结构速查

### 7.1 段布局

```
__TEXT          va=0x100000000  size=0x0b88000
__DATA_CONST    va=0x100b88000  size=0x003c000
__DATA          va=0x100bc4000  size=0x00b0000
__LINKEDIT      va=0x100c74000  size=0x0058000
```

### 7.2 卡密相关类

| 类名 | ro 地址 | 方法数 | 作用 |
|---|---|---|---|
| `QXA117` | `0x100bc9d08` | 12 | 设备指纹 + 终态判决 ★ |
| `QXA140` | `0x100bcaa88` | 9 | 网络层（唯一出网点） |
| `QXA141` | `0x100bca878` | 29 | 卡密绑定状态机 |
| `QxF4` | `0x100bcc508` | 41 | 卡密 UI 主控制器 |
| `QXA114` | `0x100bc5938` | 13 | 客户端启动状态上报 |
| `QxF1` | —— | 13 | Scene 生命周期（WS 中继） |

### 7.3 宿主自带文案（`__cfstring`，UTF-16）

```
设备授权有效        @0x100badf48   ← 成功
设备授权已过期      @0x100badf28
当前设备尚未授权    @0x100badee8
设备身份不可用      @0x100bade28   ← verifyDeviceIdentifier 失败文案
授权服务连接失败    @0x100bade68
授权响应格式错误    @0x100bade88
授权至：%@          @0x100bae388   ← UI 显示的到期格式
```

---

## 8. 环境前提

| 项 | 要求 | 原因 |
|---|---|---|
| 设备芯片 | **A12 及以上** | 宿主是 thin arm64e，A11 及以下跑不起来 |
| 签名 | `get-task-allow=True` | 否则崩了没日志 |
| Bundle ID | 与 profile 匹配 | 否则 entitlement 校验失败 |
| 构建机 | macOS + Xcode | 需要 iOS SDK |

---

## 9. 仓库结构

```
src/CoreOffline.m          ← 唯一编译单元
Makefile                   ← 双切片构建
checks/host_parity.py      ← 宿主对齐检查（25 项断言）
.github/workflows/build.yml
src/_license/              ← 旧实现留档，不参与构建
```
