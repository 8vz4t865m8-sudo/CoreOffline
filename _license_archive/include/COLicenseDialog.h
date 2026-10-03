//
//  COLicenseDialog.h
//  CoreOffline —— 卡密验证弹窗（深色商业风 / 纯 frame 布局）
//
//  设计要点：
//    · 居中卡片弹窗，浮在半透明遮罩上，点击遮罩外部不关闭
//      （授权页必须走完流程，不能误触关掉）
//    · 全部 frame 布局，禁用 Auto Layout —— 注入宿主后不受宿主约束体系影响
//    · 内容随键盘上移，卡片本身不滚（高度可控，撑得下）
//

#ifndef CO_LICENSE_DIALOG_H
#define CO_LICENSE_DIALOG_H

#import <UIKit/UIKit.h>

@class COLicenseDialog;

/// 验证结果回调。ok=YES 时 expiry 形如 "2027-03-15 12:00:00"；
/// stateCode 是服务端下发的状态码，失败时可能为 nil。
typedef void (^COLicenseResultBlock)(BOOL ok, NSString * _Nullable expiry, NSString * _Nullable stateCode, NSString * _Nullable message);

@interface COLicenseDialog : NSObject

/// 验证完成回调。dialog 内部会在回调前先把弹窗动画收掉，回调里直接放行宿主 UI 即可。
@property (nonatomic, copy, nullable) COLicenseResultBlock onResult;

/// 上一次输入过的卡密，用于预填（来自 NSUserDefaults）
@property (nonatomic, copy, nullable) NSString *prefilledCard;

/// 构造。title 显示在卡片顶部，subtitle 是一行说明。
+ (instancetype)dialog;

/// 在指定 viewController 上展示。
- (void)showIn:(UIViewController *)host;

/// 关掉弹窗（不触发 onResult）。
- (void)dismiss;

/// 让输入框拿焦点
- (void)focusInput;

@end

#endif /* CO_LICENSE_DIALOG_H */
