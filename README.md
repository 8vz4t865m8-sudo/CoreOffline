# CoreOffline —— 测试版 1:1 复刻

> **这个仓库现在的唯一目标：让 dylib 注入后 App 能正常进去。**
>
> 不是"更好"，是**和用户手上那个能进的测试版行为一致**。

---

## 现状一句话

之前的版本一直闪退。原因不是 bug 没修干净，而是**方向错了** ——
我在一个"带卡密验证"的架构上打补丁，而用户的测试版**根本没有卡密**。

所以这一版把卡密整套拿掉，按测试版二进制的反汇编结果**逐条重写**。

---

## 1. 为什么测试版一定能进

对测试版 `CoreOffline.work.dylib` 完整反汇编后，找到了结构性原因：

| 维度 | 测试版 | 之前的版本 | 后果 |
|---|---|---|---|
| 构造函数 | **全同步**，一条直路 | 有 `dispatch_async` + 等窗口 | 时序不确定 |
| 卡密 | **完全没有** | 5 个函数 + 桥接层 + 弹窗 | 多 3 个失败点 |
| `authorizationValue` | 直接返回 `2099-12-31 23:59:59` | 走卡密查缓存 | 缓存空 → 拦截 |
| 弹窗 | 无 | 有（曾有无上限重试） | 死循环 |
| 看门狗 | 无 | 12s | 超时误触发 |
| 依赖库 | **3 个 framework** | 7 个 | dyld 阶段多 4 层初始化 |
| `__bss` | 0x5d8 | 大得多 | — |

**结论：测试版能进，是因为它压根没做验证这件事。** 它只做两件事 ——
装几个 UI Hook、拦几个网络请求。验证是宿主自己的事，而宿主问
"授权到什么时候"，它永远答 `2099`。

---

## 2. 复刻了什么

全部结论来自对测试版的逐条反汇编。每条都有证据。

### 2.1 网络拦截（`CoreBlockNetworkURL` @ `0x5600`）

三层判定，**顺序很重要**：

```
① 协议白名单：scheme ∉ {http, https, ws, wss, ftp}
       ↓ 不在白名单
② 环境资源白名单：命中 → 放行
       ↓ 不是
   拦

① scheme 在白名单
       ↓
② 环境资源白名单：命中 → 放行
       ↓
③ 主机黑名单：命中 → 拦
```

★ 铁证在 `0x5668` 的 **`eor w20, w0, #1`**（取反）——
意思是「**不在白名单 且 不是环境资源**」才拦。

之前我只有第③层，所以任何自定义 scheme 都会被测试版拦掉、而我放行了。

### 2.2 命中黑名单时不 cancel（`0x5674`）

```
0x565c  cbz w20, #0x566c      ← 命中黑名单
...
0x5674  ldp ... ; retab       ← 直接返回
```

**中间没有任何 `cancel` 调用。**

所以我写了一个"更正确"的 cancel —— 这正是闪退源之一（宿主的 WS 被掐断，
宿主逻辑进入异常状态）。现在照抄测试版：**直接 return**。

同理 `cancelNetworkTasks`（`0x5290`）是**纯空壳**，函数体只有一条 `record`。

### 2.3 UI Hook 的 5 个方法

| # | 目标类 | 方法 | 安装点 |
|---|---|---|---|
| 1 | `OKDHomeMusicController` | `attachToRootView:` | `0x58c4` |
| 2 | `OKDHomeMusicController` | `refreshHomeLayoutArtwork` | `0x5944` |
| 3 | `OKDHomeMusicController` | `authorizationValue` | `0x59c0` |
| 4 | `UIImage`（元类） | `imageNamed:` | `0x5a38` |
| 5 | `UIImage`（元类） | `imageNamed:inBundle:compatibleWithTraitCollection:` | `0x5ab0` |

每个都用 `class_addMethod` 优先、失败才 `method_setImplementation`
（测试版就是这个语义）。

★ 我之前写的 `Community / 社区 / 交流群 / 官方频道` ——
**这 4 个词在测试版二进制里一个都不存在**，纯粹是我凭空编的。

### 2.4 按钮标题（★ 只有这 5 个）

来自 `__ustring`（`0x7fca`）的 UTF-16 字节：

```
e567 0b77  6c51 4a54  d063 a44e  e55d 5553  db8f a65e
```

解码后：

| # | 内容 |
|---|---|
| 1 | **查看公告** |
| 2 | **提交工单** |
| 3 | **工单进度** |
| 4 | **激活续时** |
| 5 | **检查更新** |

按钮处理有**硬上限 15**（`0x54e8` 的 `cmp w24, #0xf; b.hi`），
命中后只打一条日志、**不跳转**。

### 2.5 更新遮罩（`CoreInstallMaskHooks` @ `0x4d40`）

```
objc_copyClassList       ← 拿全部类（0x4d54）
  ↓
跳过 UIImage 类自己       ← 0x4dac
  ↓
class_getSuperclass 向上遍历类族  ← 0x4dbc（一路走到 NSObject）
  ↓
class_copyMethodList 找 setDisableUpdateMask:
  ↓
objc_setAssociatedObject 存原实现
  ↓
装一个**透传** objc_msgSend（0x4e38 的 pacda）
```

★ 关键是**透传**，不是吞掉。我之前写成屏蔽（不调原实现），行为不同。

### 2.6 构造函数（`0x4b3c`）—— 全同步

```
bundleIdentifier 检查（不是 qingxiugai.* 就 return）
  → 开日志 Documents/core-offline-original-id.log
  → record("constructor pid=%d base=%llx")
  → arc4random_buf + mach_continuous_time 算 credential
  → 遍历 dyld images，strstr(name, ".app/") 定位宿主
  → CoreHomeUIInstall()
  → monitorBackend()
  → CoreOfflinePrepare()
  → CoreOfflineBootstrap()
```

**没有一处 `dispatch_async`。没有卡密。没有延迟。**

### 2.7 后台定时器（`0x4f6c`）

```objc
dispatch_source_set_timer(src, now + 2.0s, 1.0s, 0.1s);
// handler: ticks++ → record → ticks>=8 触发 cancelNetworkTasks()（空壳）
```

---

## 3. 有没有后门？—— 没有

用户问「他肯定有什么东西连接上了」。查了 98 个导入符号：

**没有** `NSURLSession`、**没有** `CFNetwork*`、**没有** `NSURLConnection`、
**没有** socket / connect、**没有任何加密符号**。

唯一的外部 URL 是 `https://t.me/cheatrev`（Telegram 推广链接，给按钮用）。

> **测试版只做"拦截"，不做"外发"。它没有任何自己的网络请求。**

用户之前看到的 `ws://47.108.53.191/ws` 是**宿主 App 自己**发起的。

---

## 4. 这一版刻意不做的事

| 不做 | 原因 |
|---|---|
| 卡密验证（T3 / 桥接 / 弹窗 / Keychain） | 测试版没有。已挪到 `src/_license/` 留档 |
| `dispatch_async` 启动流程 | 测试版全同步 |
| 看门狗 | 测试版没有，且超时误触发 |
| 真正的 `cancel` | 测试版是直接 return |
| 任何网络请求 | 测试版只拦不发 |
| 链 Security / CFNetwork / CoreGraphics | 测试版只链 3 个 framework |

---

## 5. 复刻时补的闪退防护

测试版靠 `__objc_stubs` 走 `objc_msgSend` 转发，天然对 nil 容错。
我们用直接的函数指针，所以这些必须显式做：

| 防护 | 真机上不做的后果 |
|---|---|
| `NSURLSessionTask` 取类时判空 | 它是懒加载类，dyld 阶段返回 nil → `method_setImplementation(nil)` 崩 |
| 原实现非空才替换 | 跳空指针 |
| `resume` hook 原实现为空时走 `objc_msgSend` | task 永久停住 |
| `CoreHomeBanner` 用 `_Thread_local` 递归守卫 | hook 自触发 → 无限递归 → 栈溢出 |
| `CoreHomeBanner` 用 `@synchronized` 而非 `dispatch_once` | `dispatch_once` 递归调用会**死锁** |
| `CoreHomeBanner` 用 `_NSGetExecutablePath` 而非 `mainBundle` | `mainBundle` 在 dyld 阶段不可靠 |
| `CoreInstallMaskHooks` 放最后 | 类还没注册完，遍历到半初始化的元类 |

---

## 6. 构建

需要 macOS + Xcode（`xcrun -sdk iphoneos clang`）。

```bash
make                        # arm64e（与测试版一致）
make ARCHS="arm64"          # 仅 arm64
make ARCHS="arm64 arm64e"   # 双切片
make check                  # ★ 行为一致性检查，任何平台都能跑
make clean
```

产物：`CoreOffline.work.dylib`

**注入要点**：`install name` 必须是
`@executable_path/CoreOffline.work.dylib`。

---

## 7. 一致性检查（`make check`）

`checks/clone_parity.py` —— **37 项**，纯 Python，不需要 macOS。

每一项都对应一段反汇编证据：

```
V1   协议白名单 = {http,https,ws,wss,ftp}          ← CFString[5..9] + 0x5668
V2   按钮标题 = 那 5 个中文词                      ← __ustring UTF-16
V2b  没有幽灵标题（Community/社区/...）            ← 那些词在测试版里不存在
V3   按钮上限 = 15                                 ← 0x54e8 cmp w24,#0xf
V4   命中黑名单直接 return，不调 cancel            ← 0x5674 retab
V5   cancelNetworkTasks 是空壳                     ← 0x5290
V6   遮罩：copyClassList + 跳过 UIImage + 类族遍历 + 透传  ← 0x4d54/4dac/4dbc/4e38
V7   完全不含卡密符号
V8   构造函数全同步 + 包名守卫 + 四段顺序          ← 0x4b3c/4b7c
V9   依赖只有 Foundation/UIKit/QuartzCore + arm64e ← LC_LOAD_DYLIB
V10  5 个导出 API                                  ← 符号表
V11  定时器 2.0s/1.0s/0.1s + ticks>=8              ← 0x4f6c
V12  硬编码 2099 授权                              ← CFString[1] / 0x59c0
V13  不链 libc++
V14  7 项闪退防护
```

CI（`.github/workflows/build.yml`）在 `make check` 之外还断言：
架构 `cpusubtype=0x80000002`、`install name`、依赖库严格等于 3 个、
导出符号齐全、**没有任何卡密符号**、`strings` 里有关键串且**没有幽灵标题**。

---

## 8. 目录结构

```
src/
  CoreOffline.m          ← ★ 唯一的编译单元，测试版 1:1 复刻
  _license/              ← 卡密那一套，留档不参与构建
    COEntry.m  COVerifyBridge.m  COKeychain.m
    COLicenseDialog.m  COIcon.m  COLog.m  COTheme.h

checks/
  clone_parity.py        ← 37 项一致性检查

_license_archive/        ← 更早的卡密代码 + 旧检查脚本
  sdk/T3Verify.m
  include/COVerifyConfig.h  COVerifyBridge.h  COLicenseDialog.h
  src/co_*.py.check
```

---

## 9. 下一步

1. **真机验证能不能进**（唯一目标）
2. 能进之后，再讨论网络拦截要不要加 `cancel`（用户之前说"就是要拦它"）
3. **然后**才重新把卡密接回来 —— 用户原话：
   > 「弄好了，我们过后再来重新把卡密弄上去。」

骨架已经留好：`src/_license/` + `_license_archive/`，接回来只是改 Makefile 的
`SRC` 和 `FRAMEWORKS`。

---

## 10. 免责

仅用于**自己拥有**的设备和应用的研究 / 学习用途。
使用者需自行承担一切后果。
