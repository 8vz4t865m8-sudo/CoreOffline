//
//  COLicenseDialog.m
//  CoreOffline —— 卡密验证弹窗实现
//
//  布局约定（纯 frame，无 Auto Layout）：
//    卡片纵向由若干「区块」从上往下堆，每块自己算高度，
//    y 累加得到内容高，最后居中。所有 y 值在一次 layout 里算完，
//    不在多个方法里各改各的 —— 这是从 FilzaHook 那边踩过坑总结的规矩：
//    内容高和「摆了哪些元素」必须同源，否则早晚对不上。
//

#import "COLicenseDialog.h"
#import "COTheme.h"
#import "COIcon.h"
#import "COVerifyBridge.h"

#pragma mark - 内部常量

/// 卡片宽度：窄屏按 88% 收缩，上限 CO_CARD_MAX_W
static CGFloat COCardWidth(CGFloat screenW) {
    return MIN(screenW * 0.88, CO_CARD_MAX_W);
}

/// 弹入弹出的动画时长
static const NSTimeInterval kCOPresentDuration = 0.28;
static const NSTimeInterval kCODismissDuration = 0.20;

#pragma mark -

@interface COLicenseDialog () <UITextFieldDelegate>

@property (nonatomic, strong) UIView      *dim;
@property (nonatomic, strong) UIView      *card;
@property (nonatomic, strong) UIView      *iconWrap;
@property (nonatomic, strong) UIImageView *iconView;
@property (nonatomic, strong) UILabel     *titleLabel;
@property (nonatomic, strong) UILabel     *subtitleLabel;

@property (nonatomic, strong) UIView      *noticeBox;
@property (nonatomic, strong) UIImageView *noticeIcon;
@property (nonatomic, strong) UILabel     *noticeLabel;

@property (nonatomic, strong) UIView      *versionRow;
@property (nonatomic, strong) UIImageView *versionIcon;
@property (nonatomic, strong) UILabel     *versionLabel;

@property (nonatomic, strong) UIView      *divider;

@property (nonatomic, strong) UIView      *inputWrap;
@property (nonatomic, strong) UITextField *input;
@property (nonatomic, strong) UIButton    *pasteButton;

@property (nonatomic, strong) UIButton    *submitButton;
@property (nonatomic, strong) UILabel     *statusLabel;

@property (nonatomic, weak)   UIViewController *host;
@property (nonatomic, assign) BOOL busy;
@property (nonatomic, assign) CGFloat keyboardHeight;
@property (nonatomic, assign) CGSize  lastLayoutSize;

@end

@implementation COLicenseDialog

#pragma mark - 构造

+ (instancetype)dialog {
    return [[self alloc] init];
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _keyboardHeight = 0;
        _lastLayoutSize = CGSizeZero;
    }
    return self;
}

#pragma mark - 组装视图

/// 卡片内的小图标（带底衬）
- (UIImageView *)glyphView:(COIconType)type size:(CGFloat)size color:(UIColor *)color {
    UIImageView *iv = [[UIImageView alloc] initWithImage:[COIcon image:type size:size color:color]];
    iv.contentMode = UIViewContentModeCenter;
    return iv;
}

- (UILabel *)makeLabel:(NSString *)text font:(UIFont *)font color:(UIColor *)color {
    UILabel *l = [[UILabel alloc] initWithFrame:CGRectZero];
    l.text = text;
    l.font = font;
    l.textColor = color;
    l.numberOfLines = 0;
    return l;
}

- (UIView *)makeInsetBox {
    UIView *v = [[UIView alloc] initWithFrame:CGRectZero];
    v.backgroundColor = CO_C_INSET;
    v.layer.cornerRadius = 10;
    v.layer.masksToBounds = YES;
    return v;
}

- (UIButton *)makePrimaryButton:(NSString *)title {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    b.titleLabel.font = CO_FONT_MED(16);
    b.backgroundColor = CO_C_ACCENT;
    b.layer.cornerRadius = 10;
    b.layer.masksToBounds = YES;
    return b;
}

- (void)buildViewsIfNeeded {
    if (_card) return;

    // ── 遮罩：铺满，吃掉所有点击（授权页不允许点外部关闭）
    _dim = [[UIView alloc] initWithFrame:CGRectZero];
    _dim.backgroundColor = CO_C_DIM;
    UITapGestureRecognizer *swallow = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onDimTapped:)];
    [_dim addGestureRecognizer:swallow];

    // ── 卡片
    _card = [[UIView alloc] initWithFrame:CGRectZero];
    _card.backgroundColor = CO_C_CARD;
    _card.layer.cornerRadius = CO_CARD_RADIUS;
    _card.layer.masksToBounds = NO;
    _card.layer.shadowColor = [UIColor blackColor].CGColor;
    _card.layer.shadowOffset = CGSizeMake(0, 10);
    _card.layer.shadowRadius = 26;
    _card.layer.shadowOpacity = 0.45;

    // 圆角裁剪层：shadow 和 masksToBounds 不能共存，所以内容放一个内层视图
    UIView *clip = [[UIView alloc] initWithFrame:CGRectZero];
    clip.backgroundColor = [UIColor clearColor];
    clip.layer.cornerRadius = CO_CARD_RADIUS;
    clip.layer.masksToBounds = YES;
    clip.tag = 1001;
    [_card addSubview:clip];

    // ── 盾牌图标（圆形底衬 + 图标）
    _iconWrap = [[UIView alloc] initWithFrame:CGRectZero];
    _iconWrap.backgroundColor = CO_RGBA(59, 125, 216, 0.16);
    _iconWrap.layer.cornerRadius = 26;
    _iconWrap.layer.masksToBounds = YES;
    _iconView = [self glyphView:COIconTypeShield size:28 color:CO_C_ACCENT];
    [_iconWrap addSubview:_iconView];
    [clip addSubview:_iconWrap];

    // ── 标题 / 副标题
    _titleLabel = [self makeLabel:@"卡密验证" font:CO_FONT_BOLD(19) color:CO_C_TEXT];
    _titleLabel.textAlignment = NSTextAlignmentCenter;
    [clip addSubview:_titleLabel];

    _subtitleLabel = [self makeLabel:@"请输入卡密以激活完整功能" font:CO_FONT_REG(13) color:CO_C_TEXT_SEC];
    _subtitleLabel.textAlignment = NSTextAlignmentCenter;
    [clip addSubview:_subtitleLabel];

    // ── 公告块（可隐藏）
    _noticeBox = [self makeInsetBox];
    _noticeIcon = [self glyphView:COIconTypeInfo size:15 color:CO_C_WARN];
    [_noticeBox addSubview:_noticeIcon];
    _noticeLabel = [self makeLabel:@"" font:CO_FONT_REG(12.5) color:CO_C_TEXT_SEC];
    [_noticeBox addSubview:_noticeLabel];
    [clip addSubview:_noticeBox];

    // ── 版本行（可隐藏）
    _versionRow = [[UIView alloc] initWithFrame:CGRectZero];
    _versionIcon = [self glyphView:COIconTypeTag size:14 color:CO_C_TEXT_HINT];
    [_versionRow addSubview:_versionIcon];
    _versionLabel = [self makeLabel:@"" font:CO_FONT_REG(12.5) color:CO_C_TEXT_HINT];
    [_versionRow addSubview:_versionLabel];
    [clip addSubview:_versionRow];

    // ── 分割线
    _divider = [[UIView alloc] initWithFrame:CGRectZero];
    _divider.backgroundColor = CO_C_LINE;
    [clip addSubview:_divider];

    // ── 输入区
    _inputWrap = [[UIView alloc] initWithFrame:CGRectZero];
    _inputWrap.backgroundColor = CO_C_INSET;
    _inputWrap.layer.cornerRadius = 10;
    _inputWrap.layer.borderWidth = 1.0;
    _inputWrap.layer.borderColor = CO_RGBA(255, 255, 255, 0.10).CGColor;

    UIImageView *keyIcon = [self glyphView:COIconTypeKey size:16 color:CO_C_TEXT_HINT];
    keyIcon.tag = 2001;
    [_inputWrap addSubview:keyIcon];

    _input = [[UITextField alloc] initWithFrame:CGRectZero];
    _input.font = CO_FONT_MONO(15);
    _input.textColor = CO_C_TEXT;
    _input.tintColor = CO_C_ACCENT;
    _input.keyboardType = UIKeyboardTypeASCIICapable;
    _input.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    _input.autocorrectionType = UITextAutocorrectionTypeNo;
    _input.spellCheckingType = UITextSpellCheckingTypeNo;
    _input.returnKeyType = UIReturnKeyGo;
    _input.delegate = self;
    _input.attributedPlaceholder =
        [[NSAttributedString alloc] initWithString:@"请输入卡密"
                                        attributes:@{ NSForegroundColorAttributeName: CO_C_TEXT_HINT,
                                                      NSFontAttributeName: CO_FONT_MONO(15) }];
    [_input addTarget:self action:@selector(onEditingChanged) forControlEvents:UIControlEventEditingChanged];
    [_inputWrap addSubview:_input];

    _pasteButton = [UIButton buttonWithType:UIButtonTypeCustom];
    [_pasteButton setTitle:@"粘贴" forState:UIControlStateNormal];
    [_pasteButton setTitleColor:CO_C_ACCENT forState:UIControlStateNormal];
    _pasteButton.titleLabel.font = CO_FONT_MED(13);
    [_pasteButton addTarget:self action:@selector(onPasteTapped) forControlEvents:UIControlEventTouchUpInside];
    [_inputWrap addSubview:_pasteButton];

    [clip addSubview:_inputWrap];

    // ── 提交按钮
    _submitButton = [self makePrimaryButton:@"验证并激活"];
    [_submitButton addTarget:self action:@selector(onSubmitTapped) forControlEvents:UIControlEventTouchUpInside];
    [clip addSubview:_submitButton];

    // ── 状态行（错误提示 / 进度）
    _statusLabel = [self makeLabel:@"" font:CO_FONT_REG(12) color:CO_C_FAIL];
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    _statusLabel.hidden = YES;
    [clip addSubview:_statusLabel];

    // 键盘监听
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserver:self selector:@selector(onKeyboardWillChange:) name:UIKeyboardWillChangeFrameNotification object:nil];
}

#pragma mark - 展示 / 关闭

- (void)showIn:(UIViewController *)host {
    if (!host || _dim) return;
    _host = host;

    [self buildViewsIfNeeded];

    UIView *root = host.view;
    _dim.frame = root.bounds;
    _dim.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [root addSubview:_dim];

    // 卡片先按算出来的高度放好，起始位置在屏幕外偏下
    [self layoutCardInBounds:root.bounds.size];

    CGRect target = _card.frame;
    _card.frame = CGRectMake(target.origin.x,
                             root.bounds.size.height,
                             target.size.width,
                             target.size.height);
    _card.alpha = 0;
    _dim.alpha = 0;

    if (_prefilledCard.length) _input.text = _prefilledCard;
    [self refreshSubmitEnabled];

    [UIView animateWithDuration:kCOPresentDuration
                          delay:0
         usingSpringWithDamping:0.86
          initialSpringVelocity:0.4
                        options:UIViewAnimationOptionCurveEaseOut
                     animations:^{
        self->_dim.alpha = 1;
        self->_card.frame = target;
        self->_card.alpha = 1;
    } completion:nil];

    // 起手就把公告/版本拉一遍，异步回来后刷新
    [self loadRemoteInfo];
}

- (void)dismiss {
    [self dismissWithCompletion:nil];
}

- (void)dismissWithCompletion:(void (^)(void))completion {
    if (!_dim) {
        if (completion) completion();
        return;
    }
    [_input resignFirstResponder];

    CGRect from = _card.frame;
    UIView *dim = _dim;
    UIView *card = _card;
    _dim = nil;
    _card = nil;

    [UIView animateWithDuration:kCODismissDuration
                     animations:^{
        dim.alpha = 0;
        card.frame = CGRectOffset(from, 0, 24);
        card.alpha = 0;
    } completion:^(BOOL finished) {
        [dim removeFromSuperview];
        [card removeFromSuperview];
        if (completion) completion();
    }];
}

- (void)onDimTapped:(UITapGestureRecognizer *)g {
    // 刻意不关闭：授权页必须走完流程，误触关掉会让用户不知道怎么再打开
    (void)g;
}

- (void)focusInput {
    [_input becomeFirstResponder];
}

#pragma mark - 远程信息（公告 / 版本）

- (void)loadRemoteInfo {
    COVerifyBridge *bridge = [COVerifyBridge shared];
    if (!bridge.available) return;

    __weak typeof(self) ws = self;
    [bridge fetchNotice:^(NSString *notice, NSString *version) {
        __strong typeof(ws) self = ws;
        if (!self) return;
        if (notice.length) {
            self->_noticeLabel.text = notice;
            [self setNeedsCardLayout];
        }
        if (version.length) {
            self->_versionLabel.text = [NSString stringWithFormat:@"服务端版本 %@ · 本地 %@",
                                        version, bridge.localVersion ?: @"-"];
            [self setNeedsCardLayout];
        }
    }];
}

#pragma mark - 交互

- (void)onEditingChanged {
    [self refreshSubmitEnabled];
    if (_statusLabel.hidden == NO) {
        // 用户一改内容，旧错误就不该继续挂着
        _statusLabel.hidden = YES;
        [self setNeedsCardLayout];
    }
}

- (void)refreshSubmitEnabled {
    BOOL hasText = _input.text.length > 0;
    BOOL enabled = hasText && !_busy;
    _submitButton.enabled = enabled;
    _submitButton.backgroundColor = enabled ? CO_C_ACCENT : CO_RGBA(59, 125, 216, 0.35);
}

- (void)onPasteTapped {
    NSString *s = [UIPasteboard generalPasteboard].string;
    if (s.length == 0) {
        [self showStatus:@"剪贴板是空的" color:CO_C_WARN];
        return;
    }
    // 卡密通常不带空白，粘贴时顺手清掉换行和空格
    NSString *clean = [[s stringByTrimmingCharactersInSet:
                        [NSCharacterSet whitespaceAndNewlineCharacterSet]]
                       stringByReplacingOccurrencesOfString:@" " withString:@""];
    _input.text = clean.uppercaseString;
    [self onEditingChanged];
}

- (void)onSubmitTapped {
    if (_busy) return;
    NSString *card = [_input.text stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (card.length == 0) {
        [self showStatus:@"请先输入卡密" color:CO_C_WARN];
        return;
    }

    _busy = YES;
    [self setBusyUI:YES];
    [self showStatus:@"正在验证，请稍候…" color:CO_C_TEXT_SEC];

    __weak typeof(self) ws = self;
    [[COVerifyBridge shared] verifyCard:card completion:^(BOOL ok, NSString *expiry, NSString *stateCode, NSString *message) {
        __strong typeof(ws) self = ws;
        if (!self) return;

        self->_busy = NO;

        if (ok) {
            [self showStatus:message.length ? message : @"验证成功" color:CO_C_OK];
            [self setBusyUI:NO];
            // 成功时让用户看清绿色状态再收，收完才回调
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.55 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                __strong typeof(ws) self = ws;
                if (!self) return;
                COLicenseResultBlock cb = self.onResult;
                [self dismissWithCompletion:^{
                    if (cb) cb(YES, expiry, stateCode, message);
                }];
            });
        } else {
            [self setBusyUI:NO];
            [self showStatus:message.length ? message : @"验证失败，请检查卡密" color:CO_C_FAIL];
            [self refreshSubmitEnabled];
        }
    }];
}

- (void)setBusyUI:(BOOL)busy {
    _input.enabled = !busy;
    _pasteButton.hidden = busy;
    [_submitButton setTitle:(busy ? @"验证中…" : @"验证并激活") forState:UIControlStateNormal];
    [self refreshSubmitEnabled];

    if (busy) {
        // 转圈用 layer 的旋转动画，图标本身不重画
        _submitButton.imageView.hidden = YES;
        if (![_submitButton viewWithTag:3001]) {
            UIImageView *spin = [[UIImageView alloc] initWithImage:
                                 [COIcon image:COIconTypeSpinner size:17 color:[UIColor whiteColor]]];
            spin.tag = 3001;
            spin.frame = CGRectMake(0, 0, 17, 17);
            [_submitButton addSubview:spin];

            CABasicAnimation *a = [CABasicAnimation animationWithKeyPath:@"transform.rotation.z"];
            a.fromValue = @0;
            a.toValue = @(M_PI * 2);
            a.duration = 0.9;
            a.repeatCount = HUGE_VALF;
            [spin.layer addAnimation:a forKey:@"spin"];
        }
    } else {
        [[_submitButton viewWithTag:3001] removeFromSuperview];
    }
    [self layoutCardInBounds:self.card.superview ? self.card.superview.bounds.size : CGSizeZero];
}

- (void)showStatus:(NSString *)text color:(UIColor *)color {
    _statusLabel.text = text;
    _statusLabel.textColor = color;
    _statusLabel.hidden = (text.length == 0);
    [self setNeedsCardLayout];
}

#pragma mark - UITextFieldDelegate

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [self onSubmitTapped];
    return NO;
}

#pragma mark - 键盘

- (void)onKeyboardWillChange:(NSNotification *)n {
    NSDictionary *info = n.userInfo;
    CGRect end = [info[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    NSTimeInterval dur = [info[UIKeyboardAnimationDurationUserInfoKey] doubleValue];

    UIView *root = _host.view;
    if (!root) return;
    CGRect inRoot = [root convertRect:end fromView:nil];
    CGFloat overlap = MAX(0, root.bounds.size.height - inRoot.origin.y);
    _keyboardHeight = overlap;

    [UIView animateWithDuration:dur
                          delay:0
                        options:UIViewAnimationOptionCurveEaseOut | UIViewAnimationOptionBeginFromCurrentState
                     animations:^{
        [self layoutCardInBounds:root.bounds.size];
    }];
}

#pragma mark - 布局（★ 全部在这里算，别处不许改 frame）

- (void)setNeedsCardLayout {
    _lastLayoutSize = CGSizeZero;
    UIView *superview = _card.superview;
    if (superview) [self layoutCardInBounds:superview.bounds.size];
}

/// 一次算完：卡片高度 → 卡片原点（含键盘避让）→ 卡片内每个元素
- (void)layoutCardInBounds:(CGSize)size {
    if (!_card || size.width <= 0 || size.height <= 0) return;

    UIView *clip = [_card viewWithTag:1001];
    if (!clip) return;

    // ★ 幂等短路：尺寸和键盘高都没变就不重算。
    //   键盘通知会连发几次，每次都全量重排会闪。
    if (CGSizeEqualToSize(size, _lastLayoutSize) && _card.bounds.size.height > 0) {
        // 尺寸没变仍需处理键盘位移，往下走
    }
    _lastLayoutSize = size;

    CGFloat cardW = COCardWidth(size.width);
    CGFloat padX  = CO_CARD_PAD_X;
    CGFloat innerW = cardW - padX * 2;

    // ── 从上往下堆，y 是「下一个元素的顶边」
    CGFloat y = 22;

    // 盾牌
    CGFloat iconSize = 52;
    BOOL hasIcon = (_iconWrap != nil);
    if (hasIcon) {
        _iconWrap.frame = CGRectMake((cardW - iconSize) / 2, y, iconSize, iconSize);
        _iconView.frame = _iconWrap.bounds;
        y += iconSize + 12;
    }

    // 标题
    CGFloat titleH = [self heightFor:_titleLabel width:innerW];
    _titleLabel.frame = CGRectMake(padX, y, innerW, titleH);
    y += titleH + 5;

    // 副标题
    CGFloat subH = [self heightFor:_subtitleLabel width:innerW];
    _subtitleLabel.frame = CGRectMake(padX, y, innerW, subH);
    y += subH + 16;

    // 公告块
    if (_noticeBox.hidden == NO && _noticeLabel.text.length) {
        CGFloat textW = innerW - 14 - 8 - 14;   // 左内边距 + 图标 + 间距 + 右内边距
        CGFloat nh = [self heightFor:_noticeLabel width:textW];
        CGFloat boxH = MAX(38, nh + 18);
        _noticeBox.frame = CGRectMake(padX, y, innerW, boxH);
        _noticeIcon.frame = CGRectMake(14, (boxH - 15) / 2, 15, 15);
        _noticeLabel.frame = CGRectMake(14 + 15 + 8, (boxH - nh) / 2, textW, nh);
        y += boxH + 8;
    } else {
        _noticeBox.frame = CGRectZero;
    }

    // 版本行
    if (_versionRow.hidden == NO && _versionLabel.text.length) {
        CGFloat textW = innerW - 14 - 8;
        CGFloat vh = [self heightFor:_versionLabel width:textW];
        CGFloat rowH = MAX(18, vh);
        _versionRow.frame = CGRectMake(padX, y, innerW, rowH);
        _versionIcon.frame = CGRectMake(0, (rowH - 14) / 2, 14, 14);
        _versionLabel.frame = CGRectMake(14 + 6, (rowH - vh) / 2, textW, vh);
        y += rowH + 12;
    } else {
        _versionRow.frame = CGRectZero;
    }

    // 分割线
    _divider.frame = CGRectMake(padX, y, innerW, 1.0 / [UIScreen mainScreen].scale);
    y += 1 + 16;

    // 输入区
    _inputWrap.frame = CGRectMake(padX, y, innerW, CO_CTRL_H);
    CGFloat pasteW = 52;
    UIImageView *keyIcon = [_inputWrap viewWithTag:2001];
    keyIcon.frame = CGRectMake(12, (CO_CTRL_H - 16) / 2, 16, 16);
    BOOL showPaste = (_pasteButton.hidden == NO);
    _input.frame = CGRectMake(12 + 16 + 8, 0,
                              innerW - (12 + 16 + 8) - (showPaste ? pasteW + 10 : 12),
                              CO_CTRL_H);
    _pasteButton.frame = CGRectMake(innerW - pasteW - 10, 0, pasteW, CO_CTRL_H);
    y += CO_CTRL_H + 14;

    // 提交按钮
    _submitButton.frame = CGRectMake(padX, y, innerW, CO_CTRL_H);
    [self centerSpinnerInButton];
    y += CO_CTRL_H;

    // 状态行
    if (_statusLabel.hidden == NO) {
        y += 10;
        CGFloat sh = [self heightFor:_statusLabel width:innerW];
        _statusLabel.frame = CGRectMake(padX, y, innerW, sh);
        y += sh;
    } else {
        _statusLabel.frame = CGRectZero;
    }

    y += 20;    // 卡片底部留白

    clip.frame = CGRectMake(0, 0, cardW, y);
    _card.bounds = CGRectMake(0, 0, cardW, y);

    // ── 卡片整体位置：竖向居中，但要避开键盘
    CGFloat availH = size.height - _keyboardHeight;
    CGFloat originY = (availH - y) / 2.0;
    // 太靠上就贴顶（留 12pt），太小就不用管 —— 反正卡片不滚
    if (originY < 12) originY = 12;

    _card.center = CGPointMake(size.width / 2.0, originY + y / 2.0);
}

/// 按钮里的转圈图标居中
- (void)centerSpinnerInButton {
    UIView *spin = [_submitButton viewWithTag:3001];
    if (!spin) return;
    NSString *title = [_submitButton titleForState:UIControlStateNormal] ?: @"";
    CGSize ts = [title sizeWithAttributes:@{ NSFontAttributeName: _submitButton.titleLabel.font }];
    CGFloat total = 17 + 6 + ts.width;
    CGFloat x = (_submitButton.bounds.size.width - total) / 2.0;
    spin.frame = CGRectMake(x, (_submitButton.bounds.size.height - 17) / 2.0, 17, 17);
}

/// 单行/多行文本高度
- (CGFloat)heightFor:(UILabel *)label width:(CGFloat)width {
    if (!label || width <= 0) return 0;
    CGSize s = [label sizeThatFits:CGSizeMake(width, CGFLOAT_MAX)];
    return ceil(s.height);
}

#pragma mark - 清理

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

@end
