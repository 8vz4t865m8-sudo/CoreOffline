# CoreOffline

宿主 App 的**授权验证 dylib**。编译出一个 `CoreOffline.work.dylib`，注入后接管四件事：

| 能力 | 做法 |
|---|---|
| **卡密验证** | 未授权时弹出深色验证页，走 T3 网络验证，通过后才放行 |
| **有效期下发** | 宿主问 `authorizationValue` 时，返回该卡密在服务端的真实到期时间 |
| **网络白名单** | 拦掉宿主对 `apple.com` 系的校验请求，放行 `appledb` 环境资源 |
| **更新遮罩拦截** | 吞掉 `setDisableUpdateMask:`，宿主弹不出更新遮罩 |

---

## 构建

需要 macOS + Xcode。仓库自带 CI，推上去就会编译出产物。

```bash
make                       # 默认 arm64
make ARCHS="arm64 arm64e"  # 需要 PAC 时
make clean
```

产物：`CoreOffline.work.dylib`

CI 跑完后在 Actions 页面的 artifacts 里下载。

---

## 目录

```
CoreOffline/
├── src/
│   ├── CoreOffline.m        dylib 入口：构造函数、Hook 安装、授权调度
│   ├── COTheme.h            深色主题常量（颜色 / 尺寸 / 字体）
│   ├── COIcon.h/.m          手绘矢量图标（盾/钥匙/公告/标签/勾/叉/警告/转圈）
│   ├── COLicenseDialog.m    卡密验证弹窗（纯 frame 布局）
│   └── COVerifyBridge.m     验证桥接层：SDK 装配、验卡、心跳、落盘
├── include/
│   ├── COLicenseDialog.h    弹窗对外接口
│   ├── COVerifyBridge.h     桥接层对外接口
│   └── COVerifyConfig.h  ★ 你只需要改这个文件
├── sdk/
│   └── T3Verify.h/.m        T3 网络验证 SDK
├── .github/workflows/build.yml
└── Makefile
```

---

## 你只需要改一个文件

`include/COVerifyConfig.h` 里集中了所有跟你的后端相关的值：

```objc
static inline NSString *COVerifyLoginCode(void)  { return @"你的登录code"; }
static inline NSString *COVerifyNoticeCode(void) { return @"你的公告code"; }
static inline NSString *COVerifyVersionCode(void){ return @"你的版本code"; }
static inline NSString *COVerifyHeartbeatCode(void){ return @"你的心跳code"; }
static inline NSString *COVerifyAppKey(void)     { return @"你的appkey"; }
static inline NSString *COVerifyRSAPublicKey(void) { return @"-----BEGIN PUBLIC KEY-----\n..."; }

static inline NSString *COVerifyLocalVersion(void) { return @"1000"; }
static inline NSTimeInterval COVerifyHeartbeatInterval(void) { return 60.0; }
static inline NSInteger COVerifyMaxHeartbeatFail(void) { return 5; }

static inline NSString *COCommunityURL(void) { return @"https://t.me/你的频道"; }
```

> **注意**：RSA 公钥要连 `-----BEGIN PUBLIC KEY-----` 头尾一起整段粘进来，
> 包括换行符 `\n`。少了头尾 SDK 解不出来，验证会一直失败。

---

## 卡密验证页

深色商业风、居中弹窗、**纯 frame 布局**（不用 Auto Layout，注入宿主后不受宿主约束体系影响）。

```
        ┌──────────────────────────┐
        │         ╭────╮           │   ← 盾牌图标（圆形底衬）
        │         │ 🛡 │           │
        │         ╰────╯           │
        │       卡密验证            │   ← 标题
        │   请输入卡密以激活完整功能  │   ← 副标题
        │  ┌────────────────────┐  │
        │  │ ⓘ 公告内容……       │  │   ← 公告块（拉不到就自动隐藏）
        │  └────────────────────┘  │
        │  🏷 服务端版本 1002·本地 1000 │   ← 版本行
        │ ─────────────────────────│
        │  ┌────────────────────┐  │
        │  │ 🔑 XXXX-XXXX-XXXX  │粘贴│  ← 卡密输入
        │  └────────────────────┘  │
        │  ┌────────────────────┐  │
        │  │     验证并激活      │  │   ← 主题蓝按钮
        │  └────────────────────┘  │
        │      错误提示 / 状态文字    │   ← 有内容才占位
        └──────────────────────────┘
```

行为要点：

- **点遮罩不关闭** —— 授权页必须走完流程，误触关掉用户不知道怎么再打开
- **键盘弹起卡片上移**，弹窗本身不滚（内容高度可控）
- **输入框关掉自动更正、强制大写** —— 卡密区分大小写，也避免被中文输入法改写
- **粘贴按钮**会顺手清掉空格和换行
- **成功后先播绿色反馈再收起**（0.55s），让用户看清结果
- **失败后按钮恢复可用**，可以立刻重试

---

## 授权链路

```
App 启动
   │
   ├─ dylib 构造函数
   │    ├─ 打开日志 Documents/core-offline.log
   │    ├─ 生成凭据链 material → lease → derive → credential
   │    ├─ 定位宿主镜像（.app/ 路径）
   │    ├─ 安装 Hook（控制器 / 图片 / 网络 / 更新遮罩）
   │    └─ 启动后台状态监视
   │
   └─ 延后 0.6s（等窗口就绪）→ 检查授权
         │
         ├─ 本地缓存有效 ──────────────→ 放行
         │
         └─ 需要验证 → 弹卡密页
                │
                ├─ 验证成功 → 落盘 → 启动心跳 → 放行
                │              （到期时间存 NSUserDefaults）
                │
                └─ 验证失败 → 提示错误 → 允许重试

心跳（60s 一次）
   │
   ├─ 成功 → 失败计数归零
   └─ 连续失败 5 次 → 停心跳 + 重置授权态 + 重新弹验证页
```

宿主侧问有效期时：

```objc
- (id)authorizationValue {
    return CoreLicenseExpiryString();
}
```

返回值只有两种：

| 情况 | 返回值 |
|---|---|
| 已验证 / 缓存有效 | 服务端下发的真实到期时间 `"2027-03-15 12:00:00"` |
| 未验证 | `"1970-01-01 00:00:01"`（哨兵值，宿主会走自带过期流程） |

> 用哨兵值而不是 `nil`：宿主拿到 `nil` 可能直接崩（比如塞进 `NSDateFormatter`）。
> 判断是否未授权请用 `COVerifyIsUnauthorized(expiry)`，别去硬比年份。

---

## 网络白名单

`NSURLSessionTask -resume` 被 Hook，按这个顺序判定：

1. **环境资源白名单**（放行）
   - `api.appledb.dev`
   - `fastly.jsdelivr.net/gh/littlebyteorg/appledb@gh-pages/ios/`
2. **拦截名单**（吞掉，不发起请求）
   - `apple.com` / `*.apple.com`
   - `cdn-apple.com` / `*.cdn-apple.com`
3. 其余 → 调原始 `resume` 正常放行

> 顺序不能反。白名单里如果有域名同时匹配了拦截规则，必须让白名单先判 ——
> 否则环境资源会被自己拦掉，宿主的图标全变空白。

---

## 更新遮罩拦截

遍历 `objc_copyClassList`，**只处理宿主 App 内**的类（`class_getImageName` 里含 `.app/`），
把它们的 `setDisableUpdateMask:` 实现换成空函数。

不改系统类，是为了避免影响别的进程/框架。

---

## 面板 / 弹窗布局的三条规矩

从实际踩坑总结，改布局前请先读：

### ① 所有 frame 赋值只能出现在 `layoutCardInBounds:`

页面里别处不写 `.frame =`。布局是一次算完的：从上往下堆区块，`y` 累加得到内容高，
中间不改两次。分成多处赋值，早晚出现「摆了哪些元素」和「总高」对不上。

### ② 隐藏区块必须同时塌陷

只 `hidden = YES` 不改 frame，会在原来的位置留一块空白。所以隐藏时必须
`frame = CGRectZero`，让后续元素往上收。

### ③ 布局函数首行必须有 0 尺寸守卫

```objc
if (!_card || size.width <= 0 || size.height <= 0) return;
```

首帧 `bounds` 可能是 0，除以 0 会算出 `NaN` 位置，卡片直接消失且再也回不来。

---

## 日志

运行时日志写在宿主的 `Documents/core-offline.log`，可以这样捞：

```bash
# 越狱设备
ssh root@<device> cat /var/mobile/Containers/Data/Application/<uuid>/Documents/core-offline.log
```

关键行：

```
constructor pid=1234 base=0x104abc000
derive=... material=... lease=... credential=...
license.expiry=2027-03-15 12:00:00          ← 授权成功
license.expiry=UNAUTHORIZED(no valid license) ← 未授权
license.dialog.present                       ← 弹了验证页
license.granted expiry=... state=...          ← 验证通过
license.denied msg=卡密不存在                  ← 验证失败
heartbeat.lost → present license dialog       ← 心跳掉线
network.cancel host=xxx.apple.com             ← 拦掉的请求
mask.hook class=XXX                           ← 更新遮罩 Hook 装上
```

---

## 常见问题

**验证一直失败？**
先看日志里 T3 SDK 有没有装配上（`T3Verify SDK 已装配`）。没有的话是 SDK 没编进 dylib，
或者 `T3Verify.h` 的类名不对。

**日志里出现 `T3Verify SDK 未接入`？**
SDK 类找不到，验证会走本地缓存降级路径 —— 有有效缓存才放行。检查 `sdk/T3Verify.m`
是否在 Makefile 的 `SRC` 里。

**宿主图标全变空白？**
网络白名单顺序写反了，环境资源被自己拦掉。

**弹窗弹不出来？**
dylib 构造函数里挂弹窗时窗口还没建好。现在改成轮询等宿主窗口就绪（最多 10s），
等不到也会把子系统跑起来，只是弹不出窗。日志里搜 `host.ready` 看等了多久。

**卡密输入被自动改成中文？**
输入框已设 `autocorrectionType = No` + `autocapitalizationType = AllCharacters`。
如果还串，检查有没有别的 dylib 也在 Hook `UITextField`。

---

## ★ 注入后闪退？先看这一节

**曾在真机上遇到「一注入就闪退」，根因是构造函数在 dyld 阶段做了重活。**

### 现象

- 注入后 App 直接崩，看不到任何界面
- 或者偶发：启动几秒后才崩（取决于宿主什么时候读授权值）

### 根因

`constructor` 的执行时机是 **dyld 加载 dylib 的瞬间**，此时宿主 App 的
`UIApplication` 还没创建、主 runloop 还没跑、一堆系统子系统还没初始化。

卡密模块有四类依赖在这个阶段**不安全**：

| 依赖 | 为什么不安全 |
|---|---|
| `NSUserDefaults` | `_CFXPreferences` 子系统可能还没建立，早期访问直接崩 |
| `Security.framework` | `T3RSACrypto` 解析 RSA 公钥走 `SecKeyCreateWithData`，早期 CSP 未就绪 |
| `NSDateFormatter` / `NSLocale` | 需要 ICU + locale 数据就绪 |
| `NSTimer` | 需要 runloop 已经在转 |

原始（能跑）的 CoreOffline 之所以没事，是因为它**整个 constructor 只做
Mach-O + objc runtime 层面的操作**（hook 方法、遍历类），这些都是 dyld 阶段安全的。

### 修法：构造函数只挂载，不执行

```objc
__attribute__((constructor))
static void initializeOffline(void) {
    // 第 1 段：零依赖准备（dyld 阶段安全）
    CoreLogOpen();                    // NSHomeDirectory + open(2)
    /* 凭据链：arc4random_buf / mach_continuous_time，纯系统调用 */
    /* 定位宿主镜像：_dyld_image_count 等纯 dyld API */

    // 第 2 段：CoreOffline 本体（与原始版行为一致，dyld 阶段安全）
    CoreHomeUIInstall();
    monitorBackend();
    CoreOfflinePrepare();
    CoreOfflineBootstrap();

    // 第 3 段：卡密子系统 —— 只调度，不执行
    dispatch_async(dispatch_get_main_queue(), ^{
        CoreWaitForHostReady(40);     // 轮询等窗口，最多 10s
    });
}
```

`CoreStartLicenseSubsystem()` 里才第一次碰 `[COVerifyBridge shared]`，
并且**先建单例、再置 `gLicenseSubsystemUp`、最后才 `CoreCheckLicense`**。

### 还有一条容易被忽略的雷

`CoreLicenseExpiryString()` 被 hook 到宿主的 `authorizationValue` getter 上。
**宿主完全可能在 App 启动早期就读这个值** —— 那时候它去调
`[COVerifyBridge shared]` 就会碰 `NSUserDefaults`，直接崩。

所以这个函数必须自带守卫：

```objc
static NSString *CoreLicenseExpiryString(void) {
    if (!gLicenseSubsystemUp) {
        // 早期路径：一个字都不能多说，也一个字都不能多读。
        return COVerifyUnauthorizedExpiry();
    }
    /* ...正常读缓存... */
}
```

### 怎么防止再犯

`checks/co_audit.py` 的 **H 节**专门查这个：

- **H1** — constructor 函数体里不许出现 `NSUserDefaults` / `T3Verify` /
  `NSDateFormatter` / `NSTimer` / `[COVerifyBridge shared]`
- **H2** — 卡密子系统必须经 `dispatch_async(main_queue)` 延后启动
- **H3** — `CoreLicenseExpiryString` 必须有 `gLicenseSubsystemUp` 守卫
- **H4** — 守卫标志必须被置位（定义了不置位会导致永远判定未授权），
  且置位必须在 `shared` 初始化之后

这套检查经过有效性验证：故意去掉守卫再跑，H1/H3 会准确报错。

### 架构也要对齐

原始测试版是 **arm64e (PAC00)**。Makefile 默认已改成 `ARCHS = arm64e`，
CI 里也加了 `ARM64E` + `PAC00` 断言。编成纯 arm64 虽然通常也能加载，
但和原始版不一致，在带 PAC 检查的越狱环境里可能出问题。

---

## 许可

仅供学习研究。
