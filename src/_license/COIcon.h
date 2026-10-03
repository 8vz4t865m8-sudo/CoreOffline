//
//  COIcon.h
//  CoreOffline —— 手绘矢量图标
//
//  为什么自己画：
//    1. dylib 注入的宿主 App 里没有我们的图片资源，imageNamed: 拿不到东西
//    2. emoji 在不同 iOS 版本上字形差异大，做授权页太随意
//    3. 纯 CoreGraphics 绘制没有额外文件，dylib 体积不变
//
//  所有图标均为「线段 + 填充」组合，用 COIcon 统一出口取图。
//

#ifndef CO_ICON_H
#define CO_ICON_H

#import <UIKit/UIKit.h>

typedef NS_ENUM(NSInteger, COIconType) {
    COIconTypeShield = 0,   // 盾牌 + 勾：授权/安全
    COIconTypeKey,          // 钥匙：卡密
    COIconTypeInfo,         // 圆圈 i：公告
    COIconTypeTag,          // 标签：版本
    COIconTypeCheck,        // 纯勾：成功
    COIconTypeCross,        // 纯叉：失败
    COIconTypeWarn,         // 三角感叹号：警告
    COIconTypeSpinner,      // 缺口圆弧：加载中
};

@interface COIcon : NSObject

/// 取一张图标。size 是画布边长，color 是描边/填充色。
/// 结果按屏幕 scale 渲染，带缓存。
+ (UIImage *)image:(COIconType)type size:(CGFloat)size color:(UIColor *)color;

/// 缺口圆弧单独用：rot 是当前旋转弧度，用于做转圈动画。
/// 传 0 得到静态图。会走同一个缓存 key 之外的分支，避免把旋转角度带进缓存。
+ (UIImage *)spinnerWithSize:(CGFloat)size color:(UIColor *)color rotation:(CGFloat)rot;

@end

#endif /* CO_ICON_H */
