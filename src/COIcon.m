//
//  COIcon.m
//  CoreOffline —— 手绘矢量图标实现
//

#import "COIcon.h"

@implementation COIcon

#pragma mark - 缓存

/// key = "type|size|colorHex"。旋转由调用方自己转 layer，不进缓存。
static NSMutableDictionary<NSString *, UIImage *> *gIconCache = nil;
static dispatch_once_t gIconCacheOnce;

+ (NSString *)cacheKey:(COIconType)type size:(CGFloat)size color:(UIColor *)color {
    CGFloat r = 0, g = 0, b = 0, a = 0;
    [color getRed:&r green:&g blue:&b alpha:&a];
    return [NSString stringWithFormat:@"%ld|%.1f|%d,%d,%d,%d",
            (long)type, size,
            (int)(r * 255), (int)(g * 255), (int)(b * 255), (int)(a * 255)];
}

+ (UIImage *)image:(COIconType)type size:(CGFloat)size color:(UIColor *)color {
    if (size <= 0) size = 20;
    if (!color) color = [UIColor whiteColor];

    dispatch_once(&gIconCacheOnce, ^{ gIconCache = [NSMutableDictionary dictionary]; });

    NSString *key = [self cacheKey:type size:size color:color];
    UIImage *hit = gIconCache[key];
    if (hit) return hit;

    UIGraphicsImageRendererFormat *fmt = [UIGraphicsImageRendererFormat defaultFormat];
    fmt.opaque = NO;
    UIGraphicsImageRenderer *renderer =
        [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(size, size) format:fmt];

    UIImage *img = [renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx) {
        CGContextRef c = ctx.CGContext;
        CGContextSetStrokeColorWithColor(c, color.CGColor);
        CGContextSetFillColorWithColor(c, color.CGColor);

        // 统一按 24x24 设计稿画，再缩放到目标尺寸。
        // 这样各图标的线宽相对比例恒定，不会被 size 拉变形。
        CGFloat s = size / 24.0;
        CGContextScaleCTM(c, s, s);
        CGContextSetLineWidth(c, 1.8);
        CGContextSetLineCap(c, kCGLineCapRound);
        CGContextSetLineJoin(c, kCGLineJoinRound);

        switch (type) {
            case COIconTypeShield:  [self drawShield:c];  break;
            case COIconTypeKey:     [self drawKey:c];     break;
            case COIconTypeInfo:    [self drawInfo:c];    break;
            case COIconTypeTag:     [self drawTag:c];     break;
            case COIconTypeCheck:   [self drawCheck:c];   break;
            case COIconTypeCross:   [self drawCross:c];   break;
            case COIconTypeWarn:    [self drawWarn:c];    break;
            case COIconTypeSpinner: [self drawSpinner:c rotation:0]; break;
        }
    }];

    if (img) gIconCache[key] = img;
    return img;
}

#pragma mark - 各图标

/// 盾牌轮廓 + 中间一个勾
+ (void)drawShield:(CGContextRef)c {
    CGContextSaveGState(c);
    CGMutablePathRef p = CGPathCreateMutable();
    // 从顶部中间起，左右对称下压，底部收成尖
    CGPathMoveToPoint(p, NULL, 12, 2.5);
    CGPathAddCurveToPoint(p, NULL, 12, 2.5, 19.5, 5.2, 19.5, 5.2);
    CGPathAddLineToPoint(p, NULL, 19.5, 12.5);
    CGPathAddCurveToPoint(p, NULL, 19.5, 18.0, 12, 21.5, 12, 21.5);
    CGPathAddCurveToPoint(p, NULL, 12, 21.5, 4.5, 18.0, 4.5, 12.5);
    CGPathAddLineToPoint(p, NULL, 4.5, 5.2);
    CGPathAddCurveToPoint(p, NULL, 4.5, 5.2, 12, 2.5, 12, 2.5);
    CGPathCloseSubpath(p);
    CGContextAddPath(c, p);
    CGContextStrokePath(c);
    CGPathRelease(p);

    // 勾
    CGContextSetLineWidth(c, 2.0);
    CGContextMoveToPoint(c, 9.0, 12.2);
    CGContextAddLineToPoint(c, 11.2, 14.4);
    CGContextAddLineToPoint(c, 15.4, 9.8);
    CGContextStrokePath(c);
    CGContextRestoreGState(c);
}

/// 钥匙：圆环 + 杆 + 两齿
+ (void)drawKey:(CGContextRef)c {
    CGContextSaveGState(c);
    // 圆环
    CGContextAddArc(c, 8.0, 8.0, 4.2, 0, (CGFloat)M_PI * 2, 0);
    CGContextStrokePath(c);

    // 杆
    CGContextMoveToPoint(c, 11.0, 11.0);
    CGContextAddLineToPoint(c, 19.5, 19.5);
    CGContextStrokePath(c);

    // 齿
    CGContextMoveToPoint(c, 15.6, 15.6);
    CGContextAddLineToPoint(c, 13.8, 17.4);
    CGContextMoveToPoint(c, 18.0, 18.0);
    CGContextAddLineToPoint(c, 16.2, 19.8);
    CGContextStrokePath(c);
    CGContextRestoreGState(c);
}

/// 圆圈 + i
+ (void)drawInfo:(CGContextRef)c {
    CGContextSaveGState(c);
    CGContextAddArc(c, 12, 12, 9.0, 0, (CGFloat)M_PI * 2, 0);
    CGContextStrokePath(c);

    // i 的点
    CGContextSetFillColorWithColor(c, CGContextGetStrokeColor(c));
    CGContextAddArc(c, 12, 7.6, 1.15, 0, (CGFloat)M_PI * 2, 0);
    CGContextFillPath(c);

    // i 的竖
    CGContextMoveToPoint(c, 12, 11.0);
    CGContextAddLineToPoint(c, 12, 16.6);
    CGContextStrokePath(c);
    CGContextRestoreGState(c);
}

/// 标签：带孔的吊牌
+ (void)drawTag:(CGContextRef)c {
    CGContextSaveGState(c);
    CGMutablePathRef p = CGPathCreateMutable();
    CGPathMoveToPoint(p, NULL, 3.5, 4.0);
    CGPathAddLineToPoint(p, NULL, 13.0, 4.0);
    CGPathAddLineToPoint(p, NULL, 20.5, 11.5);
    CGPathAddLineToPoint(p, NULL, 11.5, 20.5);
    CGPathAddLineToPoint(p, NULL, 3.5, 12.5);
    CGPathCloseSubpath(p);
    CGContextAddPath(c, p);
    CGContextStrokePath(c);
    CGPathRelease(p);

    // 吊孔
    CGContextSetFillColorWithColor(c, CGContextGetStrokeColor(c));
    CGContextAddArc(c, 8.0, 8.6, 1.3, 0, (CGFloat)M_PI * 2, 0);
    CGContextFillPath(c);
    CGContextRestoreGState(c);
}

/// 粗勾
+ (void)drawCheck:(CGContextRef)c {
    CGContextSaveGState(c);
    CGContextSetLineWidth(c, 2.6);
    CGContextMoveToPoint(c, 5.0, 12.8);
    CGContextAddLineToPoint(c, 10.0, 17.8);
    CGContextAddLineToPoint(c, 19.0, 7.0);
    CGContextStrokePath(c);
    CGContextRestoreGState(c);
}

/// 粗叉
+ (void)drawCross:(CGContextRef)c {
    CGContextSaveGState(c);
    CGContextSetLineWidth(c, 2.6);
    CGContextMoveToPoint(c, 6.5, 6.5);
    CGContextAddLineToPoint(c, 17.5, 17.5);
    CGContextMoveToPoint(c, 17.5, 6.5);
    CGContextAddLineToPoint(c, 6.5, 17.5);
    CGContextStrokePath(c);
    CGContextRestoreGState(c);
}

/// 三角 + 感叹号
+ (void)drawWarn:(CGContextRef)c {
    CGContextSaveGState(c);
    CGMutablePathRef p = CGPathCreateMutable();
    CGPathMoveToPoint(p, NULL, 12, 3.2);
    CGPathAddLineToPoint(p, NULL, 21.6, 20.0);
    CGPathAddLineToPoint(p, NULL, 2.4, 20.0);
    CGPathCloseSubpath(p);
    CGContextAddPath(c, p);
    CGContextStrokePath(c);
    CGPathRelease(p);

    CGContextSetFillColorWithColor(c, CGContextGetStrokeColor(c));
    CGContextAddArc(c, 12, 16.8, 1.1, 0, (CGFloat)M_PI * 2, 0);
    CGContextFillPath(c);

    CGContextMoveToPoint(c, 12, 9.2);
    CGContextAddLineToPoint(c, 12, 13.8);
    CGContextStrokePath(c);
    CGContextRestoreGState(c);
}

/// 缺口圆弧（270 度），旋转交给 layer
+ (void)drawSpinner:(CGContextRef)c rotation:(CGFloat)rot {
    CGContextSaveGState(c);
    CGContextSetLineWidth(c, 2.2);
    CGContextSetLineCap(c, kCGLineCapRound);
    CGContextAddArc(c, 12, 12, 8.5,
                    (CGFloat)(-M_PI_2) + rot,
                    (CGFloat)(-M_PI_2) + rot + (CGFloat)(M_PI * 1.5),
                    0);
    CGContextStrokePath(c);
    CGContextRestoreGState(c);
}

+ (UIImage *)spinnerWithSize:(CGFloat)size color:(UIColor *)color rotation:(CGFloat)rot {
    if (size <= 0) size = 20;
    if (!color) color = [UIColor whiteColor];

    UIGraphicsImageRendererFormat *fmt = [UIGraphicsImageRendererFormat defaultFormat];
    fmt.opaque = NO;
    UIGraphicsImageRenderer *renderer =
        [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(size, size) format:fmt];

    return [renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx) {
        CGContextRef c = ctx.CGContext;
        CGContextSetStrokeColorWithColor(c, color.CGColor);
        CGContextSetFillColorWithColor(c, color.CGColor);
        CGFloat s = size / 24.0;
        CGContextScaleCTM(c, s, s);
        [self drawSpinner:c rotation:rot];
    }];
}

@end
