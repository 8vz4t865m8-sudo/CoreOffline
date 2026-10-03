//
//  COTheme.h
//  CoreOffline —— 深色商业风主题常量
//
//  设计语言与 FilzaHook 面板保持一致：
//    · 近黑背景 + 深灰卡片，光靠层次而不是线条分割
//    · 主题蓝做唯一强调色，绿/红只用于状态反馈
//    · 所有尺寸写死，全局禁用 Auto Layout
//

#ifndef CO_THEME_H
#define CO_THEME_H

#import <UIKit/UIKit.h>

#pragma mark - 颜色

#define CO_RGB(r, g, b)  [UIColor colorWithRed:(r)/255.0 green:(g)/255.0 blue:(b)/255.0 alpha:1.0]
#define CO_RGBA(r, g, b, a) [UIColor colorWithRed:(r)/255.0 green:(g)/255.0 blue:(b)/255.0 alpha:(a)]

/// 面板底色（比卡片更深一档，让卡片浮起来）
#define CO_C_BG          CO_RGB(0x14, 0x15, 0x1B)
/// 卡片底色
#define CO_C_CARD        CO_RGB(0x1E, 0x20, 0x28)
/// 卡片内嵌区域（输入框、说明块）
#define CO_C_INSET       CO_RGB(0x17, 0x18, 0x1F)
/// 分割线
#define CO_C_LINE        CO_RGBA(255, 255, 255, 0.07)

/// 主题蓝：唯一强调色
#define CO_C_ACCENT      CO_RGB(0x3B, 0x7D, 0xD8)
#define CO_C_ACCENT_DK   CO_RGB(0x2F, 0x66, 0xB5)

/// 文字
#define CO_C_TEXT        CO_RGB(0xEC, 0xEE, 0xF2)
#define CO_C_TEXT_SEC    CO_RGB(0x9A, 0xA0, 0xAC)
#define CO_C_TEXT_HINT   CO_RGB(0x6B, 0x71, 0x7E)

/// 状态
#define CO_C_OK          CO_RGB(0x26, 0xA1, 0x5C)
#define CO_C_FAIL        CO_RGB(0xC2, 0x3D, 0x3D)
#define CO_C_WARN        CO_RGB(0xF5, 0x9E, 0x0B)

/// 遮罩
#define CO_C_DIM         CO_RGBA(0, 0, 0, 0.55)

#pragma mark - 尺寸

/// 卡片最大宽度；窄屏时按屏宽 88% 收缩
#define CO_CARD_MAX_W    340.0
/// 卡片左右内边距
#define CO_CARD_PAD_X    20.0
/// 卡片圆角
#define CO_CARD_RADIUS   16.0
/// 输入框 / 按钮高度
#define CO_CTRL_H        44.0
/// 屏幕左右安全边距
#define CO_SCREEN_MARGIN 20.0

#pragma mark - 字体

#define CO_FONT_BOLD(s)   [UIFont boldSystemFontOfSize:(s)]
#define CO_FONT_MED(s)    [UIFont systemFontOfSize:(s) weight:UIFontWeightMedium]
#define CO_FONT_REG(s)    [UIFont systemFontOfSize:(s)]

/// 等宽字体，用来显示卡密、到期时间这类「一眼要看清字符」的内容
#define CO_FONT_MONO(s)   [UIFont monospacedSystemFontOfSize:(s) weight:UIFontWeightRegular]

#endif /* CO_THEME_H */
