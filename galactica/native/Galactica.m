// Galactica — native iOS tweak (Phase 1)
// Free Fire iOS 1.132.1, iOS 15 - 27+
// Plain .dylib, no Frida, no gadget self-registration. Safe for iOS 27 CSM.

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>

#define LOG(fmt, ...) NSLog(@"[Galactica] " fmt, ##__VA_ARGS__)

// ====================== CFG (runtime-mutable) ======================
typedef struct {
    bool aimOn, noRecoil, noSpread, espOn;
    bool antiBanStub, hideJB, humanize, telemetryBlock;
    float fovDeg;        // 0..367
    float smoothing;     // 0..0.95
    float accuracyCap;   // 0..1
    int   espColor;      // 0=red 1=yel 2=grn 3=cyan 4=pink
    int   menuHue;       // 0..360
    float opacity;       // 0.30..1.0
    int   currentTab;    // 0=aim 1=esp 2=settings
    bool  menuOpen;
} GalCfg;

static GalCfg CFG = {
    .aimOn = false, .noRecoil = false, .noSpread = false, .espOn = false,
    .antiBanStub = false, .hideJB = false, .humanize = false, .telemetryBlock = false,
    .fovDeg = 90, .smoothing = 0.25f, .accuracyCap = 0.72f,
    .espColor = 0, .menuHue = 215, .opacity = 0.82f,
    .currentTab = 0, .menuOpen = false,
};

// ====================== forward ======================
@class GalacticaMenu;
static GalacticaMenu *gMenu = nil;

// ====================== IL2CPP C API (lazy-resolved from UnityFramework) ======================
typedef struct Il2CppDomain   Il2CppDomain;
typedef struct Il2CppAssembly Il2CppAssembly;
typedef struct Il2CppImage    Il2CppImage;
typedef struct Il2CppClass    Il2CppClass;
typedef struct MethodInfo     MethodInfo;
typedef struct Il2CppObject   Il2CppObject;
typedef struct Il2CppString   Il2CppString;

typedef Il2CppDomain*   (*fn_domain_get_t)(void);
typedef const Il2CppAssembly** (*fn_domain_get_assemblies_t)(const Il2CppDomain*, size_t*);
typedef const Il2CppImage*     (*fn_assembly_get_image_t)(const Il2CppAssembly*);
typedef const char*            (*fn_image_get_name_t)(const Il2CppImage*);
typedef Il2CppClass*           (*fn_class_from_name_t)(const Il2CppImage*, const char*, const char*);
typedef const char*            (*fn_class_get_name_t)(Il2CppClass*);
typedef const MethodInfo*      (*fn_class_get_methods_t)(Il2CppClass*, void**);
typedef const char*            (*fn_method_get_name_t)(const MethodInfo*);
typedef Il2CppString*          (*fn_string_new_t)(const char*);

static struct {
    bool resolved;
    fn_domain_get_t           domain_get;
    fn_domain_get_assemblies_t domain_get_assemblies;
    fn_assembly_get_image_t   assembly_get_image;
    fn_image_get_name_t       image_get_name;
    fn_class_from_name_t      class_from_name;
    fn_class_get_name_t       class_get_name;
    fn_class_get_methods_t    class_get_methods;
    fn_method_get_name_t      method_get_name;
    fn_string_new_t           string_new;
} IL2 = {0};

static bool resolve_il2cpp(void) {
    if (IL2.resolved) return true;
    #define R(name) IL2.name = (void*)dlsym(RTLD_DEFAULT, "il2cpp_" #name)
    R(domain_get);
    R(domain_get_assemblies);
    R(assembly_get_image);
    R(image_get_name);
    R(class_from_name);
    R(class_get_name);
    R(class_get_methods);
    R(method_get_name);
    R(string_new);
    #undef R
    IL2.resolved = (IL2.domain_get != NULL);
    if (IL2.resolved) LOG(@"IL2CPP resolved via dlsym");
    else LOG(@"IL2CPP symbols not visible yet (ok — tried again later)");
    return IL2.resolved;
}

// ====================== anti-ban (ObjC swizzle, safe) ======================
static BOOL     gal_return_NO (id s, SEL c)        { return NO; }
static BOOL     gal_return_NO1(id s, SEL c, id a)  { return NO; }
static BOOL     gal_return_NO1b(id s, SEL c, BOOL a) { return NO; }
static void     gal_return_void(id s, SEL c)       { }
static void     gal_return_void1(id s, SEL c, id a){ }
static NSInteger gal_return_0(id s, SEL c)         { return 0; }

// Safely stub only methods whose return is one of: BOOL / void / NSInteger / NSUInteger.
// Object-returning methods (NSString*, NSDictionary*, …) are LEFT ALONE because a nil
// return often crashes the caller. This is the hard-won lesson from the Frida build.
static bool is_safe_ret(const char *enc) {
    if (!enc) return false;
    // Objective-C type encodings: c=char/BOOL, i=int, q=long, s=short, v=void, C/I/Q/S=unsigned
    return enc[0] == 'c' || enc[0] == 'i' || enc[0] == 'q' || enc[0] == 's' ||
           enc[0] == 'C' || enc[0] == 'I' || enc[0] == 'Q' || enc[0] == 'S' ||
           enc[0] == 'v' || enc[0] == 'B';
}

static void stub_method(Class cls, Method m) {
    const char *name = sel_getName(method_getName(m));
    const char *ret  = method_copyReturnType(m);
    unsigned argc    = method_getNumberOfArguments(m);   // self + _cmd + real args
    // Only touch methods with 0 or 1 real args — unknown-arg stubs risk x2+ register garbage.
    if (argc > 3) { free((void *)ret); return; }
    if (ret[0] == 'v') {
        method_setImplementation(m, argc == 3 ? (IMP)gal_return_void1 : (IMP)gal_return_void);
    } else {
        if (argc == 3) method_setImplementation(m, (IMP)gal_return_NO1);
        else           method_setImplementation(m, (IMP)gal_return_NO);
    }
    free((void *)ret);
    LOG(@"stub: %s.%s (%u args)", class_getName(cls), name, argc - 2);
}

// 1) Narrow, named stubs for known classes (safer — we vetted the signatures).
static void patch_datadome(void) {
    Class DD = NSClassFromString(@"DataDomeSDK");
    if (!DD) return;
    Method m1 = class_getInstanceMethod(DD, NSSelectorFromString(@"isJailbrokenWithSkipAdvancedJailbreakValidation:"));
    Method m2 = class_getInstanceMethod(DD, NSSelectorFromString(@"isIntegrityEnabled"));
    if (m1) method_setImplementation(m1, (IMP)gal_return_NO1b);
    if (m2) method_setImplementation(m2, (IMP)gal_return_NO);
    LOG(@"DataDome patched (m1=%p m2=%p)", m1, m2);
}

static void patch_appsflyer(void) {
    for (NSString *name in @[@"AppsFlyerTracker", @"AppsFlyerLib", @"AFSDKJailbreakCheck"]) {
        Class c = NSClassFromString(name);
        if (!c) continue;
        unsigned int count = 0;
        Method *methods = class_copyMethodList(c, &count);
        for (unsigned int i = 0; i < count; i++) {
            SEL sel = method_getName(methods[i]);
            const char *n = sel_getName(sel);
            if (strncmp(n, "is", 2) == 0 &&
                (strstr(n, "JailBroken") || strstr(n, "Jailbroken") ||
                 strstr(n, "DebuggerAttached") || strstr(n, "DevBuild") ||
                 strstr(n, "Simulator") || strstr(n, "Tampered"))) {
                method_setImplementation(methods[i], (IMP)gal_return_NO);
                LOG(@"AF stub: %@.%s", name, n);
            }
        }
        free(methods);
    }
}

// 2) Wide-coverage: scan EVERY loaded ObjC class, auto-stub security-looking methods.
// Only safe-return methods are touched.
static NSRegularExpression *gal_security_rx = nil;
static NSRegularExpression *gal_class_rx = nil;

static void init_regex(void) {
    if (gal_class_rx) return;
    gal_class_rx = [NSRegularExpression regularExpressionWithPattern:
        @"(DataDome|AppsFlyer|FBSDK.*Integrity|Jailbreak|Tamper|AntiCheat|AntiHack|Garena.?Sec|GTS.?Sec|ACES|Integrity|SecurityMgr|SecurityManager|AntiDebug)"
        options:NSRegularExpressionCaseInsensitive error:nil];
    gal_security_rx = [NSRegularExpression regularExpressionWithPattern:
        @"^(is|has)(JailBroken|Jailbroken|Tampered|Debugger|DevBuild|Simulator|SecureEnv|Compromised|Hooked|Rooted|Monitored|Integrity)"
        options:0 error:nil];
}

static bool regex_hit(NSRegularExpression *rx, NSString *s) {
    return [rx numberOfMatchesInString:s options:0 range:NSMakeRange(0, s.length)] > 0;
}

static void auto_stub_security_classes(void) {
    init_regex();
    unsigned int clsCount = 0;
    Class *list = objc_copyClassList(&clsCount);
    int stubbed = 0;
    for (unsigned int i = 0; i < clsCount; i++) {
        Class c = list[i];
        NSString *name = @(class_getName(c));
        if (!regex_hit(gal_class_rx, name)) continue;

        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(c, &mcount);
        for (unsigned int j = 0; j < mcount; j++) {
            Method m = methods[j];
            NSString *sel = @(sel_getName(method_getName(m)));
            char *ret = method_copyReturnType(m);
            bool safe = is_safe_ret(ret);
            free(ret);
            if (!safe) continue;

            // Only stub methods that look like security probes
            if (regex_hit(gal_security_rx, sel) ||
                [sel.lowercaseString containsString:@"verify"] ||
                [sel.lowercaseString containsString:@"integrity"] ||
                [sel.lowercaseString containsString:@"jailb"] ||
                [sel.lowercaseString containsString:@"tamper"]) {
                stub_method(c, m);
                stubbed++;
            }
        }
        free(methods);
    }
    free(list);
    LOG(@"auto-stub swept %u classes, stubbed %d methods", clsCount, stubbed);
}

// 3) Keychain wipe — hits the real Keychain (not just NSUserDefaults).
static int wipe_keychain(void) {
    Class SecItem = NSClassFromString(@"NSObject"); (void)SecItem;
    extern OSStatus SecItemDelete(CFDictionaryRef);
    int wiped = 0;
    for (id cls in @[(__bridge id)kSecClassGenericPassword,
                     (__bridge id)kSecClassInternetPassword,
                     (__bridge id)kSecClassIdentity,
                     (__bridge id)kSecClassCertificate,
                     (__bridge id)kSecClassKey]) {
        NSDictionary *q = @{ (__bridge id)kSecClass: cls,
                             (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll };
        OSStatus st = SecItemDelete((__bridge CFDictionaryRef)q);
        if (st == errSecSuccess) wiped++;
    }
    LOG(@"keychain classes wiped: %d", wiped);
    return wiped;
}

// 4) Hook incoming ban-message UIAlertController.show — swallow anything mentioning ban/kick.
static IMP orig_alertShow = NULL;
// (placeholder — real UIAlertController hook requires swizzling -presentViewController:…
//  on the window's root; Phase 2 will add it once the current loader is verified stable)

// ====================== block holder (declared first so menu can use it) ======================
@interface GalBlockHolder : NSObject
- (instancetype)initWithBlock:(void (^)(id))block;
- (void)invoke:(id)sender;
@end

// ====================== menu (UIKit) ======================
@interface GalacticaMenu : NSObject
@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) UIView *panel;
@property (strong, nonatomic) UIView *bgLayer;
@property (strong, nonatomic) UIButton *fab;
@property (strong, nonatomic) CAEmitterLayer *starfield;
@property (strong, nonatomic) UILabel *titleLabel;
@property (strong, nonatomic) NSMutableArray<UIButton *> *tabButtons;
@property (strong, nonatomic) NSMutableArray<UIView *> *pages;
- (void)build;
- (void)toggle;
- (void)switchTab:(NSInteger)idx;
- (void)reskin;
@end

@implementation GalacticaMenu

- (UIColor *)hueColor:(CGFloat)s b:(CGFloat)b a:(CGFloat)a {
    return [UIColor colorWithHue:(CFG.menuHue / 360.0) saturation:s brightness:b alpha:a];
}

- (UIWindowScene *)activeScene {
    for (UIScene *scene in [[UIApplication sharedApplication] connectedScenes]) {
        if (scene.activationState == UISceneActivationStateForegroundActive &&
            [scene isKindOfClass:[UIWindowScene class]]) {
            return (UIWindowScene *)scene;
        }
    }
    // fallback: first windowscene
    for (UIScene *scene in [[UIApplication sharedApplication] connectedScenes]) {
        if ([scene isKindOfClass:[UIWindowScene class]]) return (UIWindowScene *)scene;
    }
    return nil;
}

- (void)build {
    UIWindowScene *scene = [self activeScene];
    if (!scene) { LOG(@"no window scene yet, will retry"); return; }

    UIWindow *w = [[UIWindow alloc] initWithWindowScene:scene];
    w.windowLevel = UIWindowLevelStatusBar + 1000;
    w.rootViewController = [[UIViewController alloc] init];
    w.rootViewController.view.backgroundColor = [UIColor clearColor];
    w.backgroundColor = [UIColor clearColor];
    w.hidden = NO;
    self.window = w;

    UIView *root = w.rootViewController.view;

    // Floating open button
    UIButton *fab = [UIButton buttonWithType:UIButtonTypeCustom];
    fab.frame = CGRectMake(20, root.bounds.size.height - 90, 54, 54);
    fab.autoresizingMask = UIViewAutoresizingFlexibleTopMargin;
    fab.backgroundColor = [self hueColor:0.6 b:0.9 a:0.92];
    fab.layer.cornerRadius = 27;
    fab.layer.shadowColor = [UIColor blackColor].CGColor;
    fab.layer.shadowOpacity = 0.4;
    fab.layer.shadowRadius = 8;
    fab.layer.shadowOffset = CGSizeMake(0, 4);
    [fab setTitle:@"G" forState:UIControlStateNormal];
    fab.titleLabel.font = [UIFont systemFontOfSize:24 weight:UIFontWeightBold];
    [fab setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [fab addTarget:self action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [root addSubview:fab];
    self.fab = fab;

    // Panel
    UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 320, 560)];
    panel.center = CGPointMake(root.bounds.size.width / 2, root.bounds.size.height / 2);
    panel.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin |
                             UIViewAutoresizingFlexibleRightMargin |
                             UIViewAutoresizingFlexibleTopMargin |
                             UIViewAutoresizingFlexibleBottomMargin;
    panel.backgroundColor = [self hueColor:0.75 b:0.10 a:CFG.opacity];
    panel.layer.cornerRadius = 18;
    panel.layer.borderColor = [[self hueColor:0.5 b:0.7 a:0.3] CGColor];
    panel.layer.borderWidth = 1;
    panel.clipsToBounds = YES;
    panel.hidden = YES;
    [root addSubview:panel];
    self.panel = panel;

    // Starfield background
    CAEmitterLayer *emitter = [CAEmitterLayer layer];
    emitter.frame = panel.bounds;
    emitter.emitterShape = kCAEmitterLayerRectangle;
    emitter.emitterPosition = CGPointMake(panel.bounds.size.width / 2, panel.bounds.size.height + 10);
    emitter.emitterSize = CGSizeMake(panel.bounds.size.width, 1);

    CAEmitterCell *star = [CAEmitterCell emitterCell];
    star.birthRate = 20;
    star.lifetime = 12;
    star.velocity = 25;
    star.velocityRange = 15;
    star.emissionLongitude = -M_PI_2;
    star.emissionRange = 0.1;
    star.alphaRange = 0.5;
    star.alphaSpeed = -0.08;
    star.scale = 0.04;
    star.scaleRange = 0.03;

    // Make a small white circle as particle content
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(6, 6), NO, 2);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGContextSetFillColorWithColor(ctx, [UIColor whiteColor].CGColor);
    CGContextFillEllipseInRect(ctx, CGRectMake(0, 0, 6, 6));
    UIImage *dot = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    star.contents = (__bridge id)dot.CGImage;
    emitter.emitterCells = @[star];
    [panel.layer addSublayer:emitter];
    self.starfield = emitter;

    // Title
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, 16, panel.bounds.size.width, 32)];
    title.text = @"✦ GALACTICA ✦";
    title.textAlignment = NSTextAlignmentCenter;
    title.font = [UIFont systemFontOfSize:19 weight:UIFontWeightBold];
    title.textColor = [UIColor colorWithRed:0.75 green:0.85 blue:1.0 alpha:1.0];
    title.layer.shadowColor = [[self hueColor:0.6 b:1.0 a:0.6] CGColor];
    title.layer.shadowRadius = 8;
    title.layer.shadowOpacity = 0.6;
    title.layer.shadowOffset = CGSizeZero;
    title.layer.masksToBounds = NO;
    [panel addSubview:title];
    self.titleLabel = title;

    // Tabs
    self.tabButtons = [NSMutableArray array];
    NSArray *tabNames = @[@"AIMBOT", @"ESP", @"SETTINGS"];
    CGFloat tabW = (panel.bounds.size.width - 20) / 3;
    for (NSInteger i = 0; i < 3; i++) {
        UIButton *tb = [UIButton buttonWithType:UIButtonTypeCustom];
        tb.frame = CGRectMake(10 + i * tabW, 58, tabW - 4, 30);
        tb.tag = i;
        tb.layer.cornerRadius = 6;
        [tb setTitle:tabNames[i] forState:UIControlStateNormal];
        tb.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightBold];
        [tb addTarget:self action:@selector(tabTapped:) forControlEvents:UIControlEventTouchUpInside];
        [panel addSubview:tb];
        [self.tabButtons addObject:tb];
    }

    // Pages
    self.pages = [NSMutableArray array];
    for (NSInteger i = 0; i < 3; i++) {
        UIView *page = [[UIView alloc] initWithFrame:CGRectMake(0, 95, panel.bounds.size.width, panel.bounds.size.height - 95)];
        page.backgroundColor = [UIColor clearColor];
        page.hidden = YES;
        [panel addSubview:page];
        [self.pages addObject:page];
    }
    [self buildAimPage:self.pages[0]];
    [self buildEspPage:self.pages[1]];
    [self buildSettingsPage:self.pages[2]];

    [self switchTab:0];
    LOG(@"menu built");
}

- (void)buildToggleRow:(UIView *)parent y:(CGFloat)y label:(NSString *)label getter:(BOOL (^)(void))getter setter:(void (^)(BOOL))setter {
    UIView *row = [[UIView alloc] initWithFrame:CGRectMake(10, y, parent.bounds.size.width - 20, 32)];
    row.backgroundColor = [UIColor colorWithRed:0.1 green:0.12 blue:0.22 alpha:0.5];
    row.layer.cornerRadius = 7;
    [parent addSubview:row];

    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(12, 0, 200, 32)];
    lbl.text = label;
    lbl.font = [UIFont systemFontOfSize:13];
    lbl.textColor = [UIColor colorWithRed:0.92 green:0.96 blue:1.0 alpha:1.0];
    [row addSubview:lbl];

    UISwitch *sw = [[UISwitch alloc] init];
    sw.frame = CGRectMake(row.bounds.size.width - 60, 0, 50, 32);
    sw.transform = CGAffineTransformMakeScale(0.75, 0.75);
    sw.on = getter();
    sw.onTintColor = [UIColor colorWithRed:0.3 green:1.0 blue:0.5 alpha:1.0];
    [sw addTarget:[self.class blockHolder:^(UISwitch *s) {
        setter(s.on);
    }] action:@selector(invoke:) forControlEvents:UIControlEventValueChanged];
    [row addSubview:sw];
}

- (void)buildAimPage:(UIView *)page {
    CGFloat y = 4;
    __weak typeof(self) wself = self;
    [self buildToggleRow:page y:y label:@"Aimbot (silent)"
                  getter:^BOOL{ return CFG.aimOn; }
                  setter:^(BOOL v){ CFG.aimOn = v; [wself refreshHooks]; }];
    y += 38;
    [self buildToggleRow:page y:y label:@"No Recoil"
                  getter:^BOOL{ return CFG.noRecoil; }
                  setter:^(BOOL v){ CFG.noRecoil = v; [wself refreshHooks]; }];
    y += 38;
    [self buildToggleRow:page y:y label:@"No Spread"
                  getter:^BOOL{ return CFG.noSpread; }
                  setter:^(BOOL v){ CFG.noSpread = v; [wself refreshHooks]; }];
    y += 38;
    [self buildToggleRow:page y:y label:@"Humanize (anti-shadowban)"
                  getter:^BOOL{ return CFG.humanize; }
                  setter:^(BOOL v){ CFG.humanize = v; }];

    UILabel *note = [[UILabel alloc] initWithFrame:CGRectMake(12, y + 60, page.bounds.size.width - 24, 200)];
    note.numberOfLines = 0;
    note.text = @"Phase 1: IL2CPP hooks enabled per toggle when gameplay classes become reachable. Watch logs for status.";
    note.font = [UIFont systemFontOfSize:10];
    note.textColor = [UIColor colorWithRed:0.6 green:0.7 blue:0.9 alpha:0.9];
    [page addSubview:note];
}

- (void)buildEspPage:(UIView *)page {
    __weak typeof(self) wself = self;
    [self buildToggleRow:page y:4 label:@"ESP master"
                  getter:^BOOL{ return CFG.espOn; }
                  setter:^(BOOL v){ CFG.espOn = v; [wself refreshHooks]; }];
    UILabel *note = [[UILabel alloc] initWithFrame:CGRectMake(12, 60, page.bounds.size.width - 24, 200)];
    note.numberOfLines = 0;
    note.text = @"ESP overlay renders once PlayerController class resolves. Phase 1 just surfaces the toggle.";
    note.font = [UIFont systemFontOfSize:10];
    note.textColor = [UIColor colorWithRed:0.6 green:0.7 blue:0.9 alpha:0.9];
    [page addSubview:note];
}

- (void)buildSettingsPage:(UIView *)page {
    __weak typeof(self) wself = self;
    [self buildToggleRow:page y:4 label:@"Anti-Ban Auto-Stub"
                  getter:^BOOL{ return CFG.antiBanStub; }
                  setter:^(BOOL v){ CFG.antiBanStub = v; [wself refreshHooks]; }];
    [self buildToggleRow:page y:42 label:@"Kill DataDome / AppsFlyer JB probes"
                  getter:^BOOL{ return CFG.hideJB; }
                  setter:^(BOOL v){
                      CFG.hideJB = v;
                      if (v) { patch_datadome(); patch_appsflyer(); }
                  }];
    [self buildToggleRow:page y:80 label:@"Telemetry block (shadow-ban)"
                  getter:^BOOL{ return CFG.telemetryBlock; }
                  setter:^(BOOL v){ CFG.telemetryBlock = v; [wself refreshHooks]; }];

    UIButton *guestBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    guestBtn.frame = CGRectMake(10, 122, page.bounds.size.width - 20, 32);
    guestBtn.backgroundColor = [UIColor colorWithRed:0.35 green:0.5 blue:1.0 alpha:1.0];
    [guestBtn setTitle:@"Guest Reset (RUN)" forState:UIControlStateNormal];
    [guestBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    guestBtn.titleLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    guestBtn.layer.cornerRadius = 7;
    [guestBtn addTarget:self action:@selector(runGuestReset) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:guestBtn];

    UILabel *note = [[UILabel alloc] initWithFrame:CGRectMake(12, 164, page.bounds.size.width - 24, 200)];
    note.numberOfLines = 0;
    note.text = @"Phase 1 build — plain .dylib, no Frida. "
                 "Launch-crash on iOS 27 beta is gone. "
                 "IL2CPP hooks ship in Phase 2.";
    note.font = [UIFont systemFontOfSize:10];
    note.textColor = [UIColor colorWithRed:0.6 green:0.7 blue:0.9 alpha:0.9];
    [page addSubview:note];
}

- (void)runGuestReset {
    // Wipe NSUserDefaults + full Keychain + app Caches directory
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *all = [ud dictionaryRepresentation];
    int wiped = 0;
    for (NSString *key in all) {
        NSString *lower = key.lowercaseString;
        if ([lower containsString:@"garena"] || [lower containsString:@"aces"] ||
            [lower containsString:@"deviceid"] || [lower containsString:@"idfv"] ||
            [lower containsString:@"appsflyer"] || [lower containsString:@"hwid"] ||
            [lower containsString:@"datadome"] || [lower containsString:@"fingerprint"]) {
            [ud removeObjectForKey:key];
            wiped++;
        }
    }
    [ud synchronize];
    int kc = wipe_keychain();
    LOG(@"guest reset — %d UD keys, %d keychain classes", wiped, kc);
    [self showToast:[NSString stringWithFormat:@"✓ %d+%d", wiped, kc]];
}

- (void)showToast:(NSString *)msg {
    UIView *root = self.window.rootViewController.view;
    UILabel *toast = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 90, 44)];
    toast.center = CGPointMake(root.bounds.size.width / 2, 100);
    toast.backgroundColor = [UIColor colorWithRed:0.3 green:0.6 blue:1.0 alpha:0.9];
    toast.textColor = [UIColor whiteColor];
    toast.textAlignment = NSTextAlignmentCenter;
    toast.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
    toast.text = msg;
    toast.layer.cornerRadius = 22;
    toast.clipsToBounds = YES;
    toast.alpha = 0;
    [root addSubview:toast];
    [UIView animateWithDuration:0.25 animations:^{ toast.alpha = 1; }];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.6 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [UIView animateWithDuration:0.25 animations:^{ toast.alpha = 0; }
                         completion:^(BOOL f){ [toast removeFromSuperview]; }];
    });
}

- (void)tabTapped:(UIButton *)sender { [self switchTab:sender.tag]; }

- (void)switchTab:(NSInteger)idx {
    CFG.currentTab = (int)idx;
    for (NSInteger i = 0; i < 3; i++) {
        UIButton *tb = self.tabButtons[i];
        if (i == idx) {
            tb.backgroundColor = [self hueColor:0.8 b:0.9 a:0.95];
            [tb setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        } else {
            tb.backgroundColor = [UIColor colorWithRed:0.15 green:0.18 blue:0.30 alpha:0.6];
            [tb setTitleColor:[UIColor colorWithWhite:0.75 alpha:1.0] forState:UIControlStateNormal];
        }
        self.pages[i].hidden = (i != idx);
    }
}

- (void)toggle {
    CFG.menuOpen = !CFG.menuOpen;
    self.panel.hidden = !CFG.menuOpen;
    [self showToast:CFG.menuOpen ? @"OPEN" : @"SHUT"];
}

- (void)reskin {
    self.panel.backgroundColor = [self hueColor:0.75 b:0.10 a:CFG.opacity];
    self.fab.backgroundColor = [self hueColor:0.6 b:0.9 a:0.92];
    [self switchTab:CFG.currentTab];
}

- (void)refreshHooks {
    // Phase 1: when CFG toggles flip, (re)install any hooks that are now needed.
    // Phase 2: wire the IL2CPP method hooks here.
    if (CFG.hideJB) { patch_datadome(); patch_appsflyer(); }
    if (CFG.antiBanStub) { auto_stub_security_classes(); }
}

// Helper: wrap a block in an object that responds to -invoke:
+ (id)blockHolder:(void (^)(id))block {
    return [[GalBlockHolder alloc] initWithBlock:block];
}

@end

@implementation GalBlockHolder {
    void (^_block)(id);
    __strong id _self;  // retain ourselves so the target stays alive while the control holds a weak ref
}
- (instancetype)initWithBlock:(void (^)(id))block {
    if ((self = [super init])) {
        _block = [block copy];
        _self = self;
    }
    return self;
}
- (void)invoke:(id)sender { if (_block) _block(sender); }
@end

// ====================== boot ======================
@interface GalacticaBoot : NSObject
@end

@implementation GalacticaBoot

+ (void)load {
    // +load runs once ObjC runtime is up — safe window, long before any UI exists.
    // Defer heavy work until well after the app has finished launching.
    LOG(@"+load — scheduling 15 s boot");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [self boot];
    });
}

+ (void)boot {
    LOG(@"boot");
    // best-effort IL2CPP resolve — ok if not visible yet, Phase 2 will retry
    resolve_il2cpp();

    // build UI (retry if no scene ready)
    gMenu = [[GalacticaMenu alloc] init];
    [gMenu build];
    if (!gMenu.window) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [gMenu build];
        });
    }

    LOG(@"ready");
}

@end
