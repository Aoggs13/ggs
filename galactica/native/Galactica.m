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
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#define LOG(fmt, ...) NSLog(@"[Galactica] " fmt, ##__VA_ARGS__)

// ====================== CFG (runtime-mutable) ======================
typedef struct {
    bool aimOn, noRecoil, noSpread, noBulletDrop, instantHit, espOn;
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
    .aimOn = false, .noRecoil = false, .noSpread = false,
    .noBulletDrop = false, .instantHit = false, .espOn = false,
    // Anti-ban defaults ON — Phase 1 ships protection enabled from first launch
    .antiBanStub = true, .hideJB = true, .humanize = true, .telemetryBlock = true,
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

typedef struct Il2CppType     Il2CppType;
typedef Il2CppDomain*   (*fn_domain_get_t)(void);
typedef const Il2CppAssembly** (*fn_domain_get_assemblies_t)(const Il2CppDomain*, size_t*);
typedef const Il2CppImage*     (*fn_assembly_get_image_t)(const Il2CppAssembly*);
typedef const char*            (*fn_image_get_name_t)(const Il2CppImage*);
typedef Il2CppClass*           (*fn_class_from_name_t)(const Il2CppImage*, const char*, const char*);
typedef const char*            (*fn_class_get_name_t)(Il2CppClass*);
typedef const char*            (*fn_class_get_namespace_t)(Il2CppClass*);
typedef const MethodInfo*      (*fn_class_get_methods_t)(Il2CppClass*, void**);
typedef const MethodInfo*      (*fn_class_get_method_from_name_t)(Il2CppClass*, const char*, int);
typedef const char*            (*fn_method_get_name_t)(const MethodInfo*);
typedef Il2CppString*          (*fn_string_new_t)(const char*);
typedef Il2CppObject*          (*fn_runtime_invoke_t)(const MethodInfo*, void*, void**, void**);
typedef size_t                 (*fn_image_get_class_count_t)(const Il2CppImage*);
typedef Il2CppClass*           (*fn_image_get_class_t)(const Il2CppImage*, size_t);
typedef const Il2CppType*      (*fn_method_get_return_type_t)(const MethodInfo*);
typedef char*                  (*fn_type_get_name_t)(const Il2CppType*);

static struct {
    bool resolved;
    fn_domain_get_t              domain_get;
    fn_domain_get_assemblies_t   domain_get_assemblies;
    fn_assembly_get_image_t      assembly_get_image;
    fn_image_get_name_t          image_get_name;
    fn_class_from_name_t         class_from_name;
    fn_class_get_name_t          class_get_name;
    fn_class_get_namespace_t     class_get_namespace;
    fn_class_get_methods_t       class_get_methods;
    fn_class_get_method_from_name_t class_get_method_from_name;
    fn_method_get_name_t         method_get_name;
    fn_string_new_t              string_new;
    fn_runtime_invoke_t          runtime_invoke;
    fn_image_get_class_count_t   image_get_class_count;
    fn_image_get_class_t         image_get_class;
    fn_method_get_return_type_t  method_get_return_type;
    fn_type_get_name_t           type_get_name;
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
    R(class_get_namespace);
    R(class_get_methods);
    R(class_get_method_from_name);
    R(method_get_name);
    R(string_new);
    R(runtime_invoke);
    R(image_get_class_count);
    R(image_get_class);
    R(method_get_return_type);
    R(type_get_name);
    #undef R
    IL2.resolved = (IL2.domain_get != NULL);
    if (IL2.resolved) LOG(@"IL2CPP resolved via dlsym");
    else LOG(@"IL2CPP symbols not visible yet (ok — tried again later)");
    return IL2.resolved;
}

// ====================== IL2CPP method hooking ======================
// IL2CPP MethodInfo layout: first field is Il2CppMethodPointer methodPointer (the native fn).
// On arm64e the slot is PAC-signed — we must sign our replacement before writing or the
// authenticated branch from the IL2CPP dispatcher will fail and the game crashes.
// Unity IL2CPP commonly signs with key=IA, discriminator=0 for direct-call method tables.
static inline void *gal_sign_fn(void *fn) {
#if __has_feature(ptrauth_calls)
    return ptrauth_sign_unauthenticated(fn, ptrauth_key_function_pointer, 0);
#else
    return fn;
#endif
}

static bool il2_patch_method_ptr(const MethodInfo *m, void *new_impl) {
    if (!m || !new_impl) return false;
    void **slot = (void **)m;
    vm_address_t addr = (vm_address_t)slot;
    kern_return_t kr = vm_protect(mach_task_self(), addr, sizeof(void*), false,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        LOG(@"vm_protect fail: %d", kr);
        return false;
    }
    *slot = gal_sign_fn(new_impl);
    sys_icache_invalidate(slot, sizeof(void*));
    return true;
}

static const Il2CppImage *il2_find_image(const char *name) {
    if (!IL2.resolved) return NULL;
    size_t asmCount = 0;
    const Il2CppAssembly **assemblies = IL2.domain_get_assemblies(IL2.domain_get(), &asmCount);
    for (size_t i = 0; i < asmCount; i++) {
        const Il2CppImage *img = IL2.assembly_get_image(assemblies[i]);
        if (strcmp(IL2.image_get_name(img), name) == 0) return img;
    }
    return NULL;
}

// Phase 2 — generic replacement stubs. IL2CPP booleans are int; voids return nothing;
// floats return 0.0f; int returns 0. Vector3 / struct returns NOT touched (ABI-complex).
static bool    il2_stub_return_true (void *self) { return true;  }
static bool    il2_stub_return_false(void *self) { return false; }
static void    il2_stub_return_void (void *self) { }
static int32_t il2_stub_return_zero_i(void *self){ return 0; }
static float   il2_stub_return_zero_f(void *self){ return 0.0f; }
static float   il2_stub_return_big_f (void *self){ return 99999.0f; }
static double  il2_stub_return_zero_d(void *self){ return 0.0; }

// Pick a safe stub based on managed return type. Returns NULL if return type is complex
// (struct, Vector3, object) — we skip those to stay crash-free.
static void *stub_for_method(const MethodInfo *m, bool use_big_float) {
    if (!IL2.method_get_return_type || !IL2.type_get_name) return (void *)il2_stub_return_false;
    const Il2CppType *t = IL2.method_get_return_type(m);
    if (!t) return (void *)il2_stub_return_false;
    char *tn = IL2.type_get_name(t);
    if (!tn) return (void *)il2_stub_return_false;
    void *stub = NULL;
    if      (strstr(tn, "Void"))    stub = (void *)il2_stub_return_void;
    else if (strstr(tn, "Boolean")) stub = (void *)il2_stub_return_false;
    else if (strstr(tn, "Single"))  stub = (void *)(use_big_float ? il2_stub_return_big_f : il2_stub_return_zero_f);
    else if (strstr(tn, "Double"))  stub = (void *)il2_stub_return_zero_d;
    else if (strstr(tn, "Int"))     stub = (void *)il2_stub_return_zero_i;
    else if (strstr(tn, "UInt"))    stub = (void *)il2_stub_return_zero_i;
    // Vector3, Quaternion, structs, objects — skip (NULL)
    free(tn);
    return stub;
}

// Scan Assembly-CSharp for security-looking classes and stub their BOOL methods.
// Target: classes named AntiHack, GameSecurity, SecurityManager, IntegrityCheck,
// AccountSecurity, CheckHacker, ACES* and their methods containing check/verify/is/detect.
static int il2_auto_stub_security(void) {
    if (!IL2.resolved) { LOG(@"IL2CPP not resolved — skip"); return 0; }
    const Il2CppImage *csharp = il2_find_image("Assembly-CSharp.dll");
    if (!csharp) { LOG(@"Assembly-CSharp.dll image not found"); return 0; }
    if (!IL2.image_get_class_count || !IL2.image_get_class) {
        LOG(@"image_get_class API missing — can't enumerate");
        return 0;
    }
    size_t count = IL2.image_get_class_count(csharp);
    int stubbed = 0;
    NSRegularExpression *clsRx = [NSRegularExpression regularExpressionWithPattern:
        @"^(AntiHack|GameSecurity|SecurityManager|IntegrityCheck|AccountSecurity|ffantihack|CheckHacker|ExistHacker|WallHack|HackerCdtID|FFAntiHack|TamperCheck|EnterSecureMode|ACE[A-Z]{6,})$"
        options:NSRegularExpressionCaseInsensitive error:nil];
    NSRegularExpression *methRx = [NSRegularExpression regularExpressionWithPattern:
        @"(check|verify|detect|validate|scan|report|is[A-Z]|has[A-Z]|enabled|measure)"
        options:0 error:nil];
    for (size_t i = 0; i < count; i++) {
        Il2CppClass *klass = IL2.image_get_class(csharp, i);
        if (!klass) continue;
        const char *cname = IL2.class_get_name(klass);
        if (!cname) continue;
        NSString *ns = @(cname);
        if ([clsRx numberOfMatchesInString:ns options:0 range:NSMakeRange(0, ns.length)] == 0) continue;

        void *iter = NULL;
        const MethodInfo *m;
        while ((m = IL2.class_get_methods(klass, &iter))) {
            const char *mname = IL2.method_get_name(m);
            if (!mname) continue;
            NSString *mn = @(mname);
            if ([methRx numberOfMatchesInString:mn options:0 range:NSMakeRange(0, mn.length)] == 0) continue;
            // Best-effort stub — return false by default (most security "is cheat?" probes expect NO)
            if (il2_patch_method_ptr(m, (void *)il2_stub_return_false)) {
                stubbed++;
                LOG(@"il2 stub: %s.%s", cname, mname);
            }
        }
    }
    LOG(@"IL2CPP auto-stub done: %d methods in %zu classes scanned", stubbed, count);
    return stubbed;
}

// Generic: walk every class in `imageName` matching classRx, every method matching methodRx,
// patch methodPointer with a safe return-type-correct stub. Returns count patched.
static int il2_patch_matching(const char *imageName,
                              NSRegularExpression *classRx,
                              NSRegularExpression *methodRx,
                              bool use_big_float, const char *tag) {
    if (!IL2.resolved) return 0;
    const Il2CppImage *img = il2_find_image(imageName);
    if (!img || !IL2.image_get_class_count || !IL2.image_get_class) return 0;

    size_t cc = IL2.image_get_class_count(img);
    int patched = 0;
    for (size_t i = 0; i < cc; i++) {
        Il2CppClass *k = IL2.image_get_class(img, i);
        if (!k) continue;
        const char *cn = IL2.class_get_name(k);
        if (!cn) continue;
        NSString *cns = @(cn);
        NSRange cnr = NSMakeRange(0, cns.length);
        if ([classRx numberOfMatchesInString:cns options:0 range:cnr] == 0) continue;

        void *iter = NULL;
        const MethodInfo *m;
        while ((m = IL2.class_get_methods(k, &iter))) {
            const char *mn = IL2.method_get_name(m);
            if (!mn) continue;
            NSString *mns = @(mn);
            NSRange mnr = NSMakeRange(0, mns.length);
            if ([methodRx numberOfMatchesInString:mns options:0 range:mnr] == 0) continue;

            void *stub = stub_for_method(m, use_big_float);
            if (!stub) continue;  // complex return type — skip safely
            if (il2_patch_method_ptr(m, stub)) {
                patched++;
                LOG(@"%s: %s.%s", tag, cn, mn);
            }
        }
    }
    LOG(@"%s — patched %d methods", tag, patched);
    return patched;
}

static NSRegularExpression *rx(NSString *pattern) {
    return [NSRegularExpression regularExpressionWithPattern:pattern
                                                      options:NSRegularExpressionCaseInsensitive
                                                        error:nil];
}

// ====================== gameplay patchers (callable per feature toggle) ======================
static int il2_patch_no_recoil(void) {
    return il2_patch_matching("Assembly-CSharp.dll",
        rx(@"(WeaponFire|Weapon$|.*Weapon.*Controller)"),
        rx(@"Recoil.*(Get|Apply|Calc|Update)|GetRecoil|ApplyRecoil"),
        false, "noRecoil");
}

static int il2_patch_no_spread(void) {
    return il2_patch_matching("Assembly-CSharp.dll",
        rx(@"(WeaponFire|Weapon$|.*Weapon.*Controller|BulletCtrl|Bullet$)"),
        rx(@"(Spread|Accuracy|Cone).*(Get|Calc)|CalcBulletDirection|GetSpreadAngle"),
        false, "noSpread");
}

static int il2_patch_no_bullet_drop(void) {
    return il2_patch_matching("Assembly-CSharp.dll",
        rx(@"(Bullet|Projectile|Weapon).*"),
        rx(@"(Gravity|Drop|ApplyGravity|BulletDrop).*(Get|Calc|Apply|Update)"),
        false, "noDrop");
}

static int il2_patch_instant_hit(void) {
    return il2_patch_matching("Assembly-CSharp.dll",
        rx(@"(Bullet|Projectile|Weapon).*"),
        rx(@"(BulletSpeed|InitSpeed|GetBulletSpeed|get_speed|ProjectileSpeed)"),
        true,  // use big float for speed
        "instantHit");
}

// Call an IL2CPP method by name (no-args). Used by Guest Reset for FixDeviceID / ResetGuest.
static bool il2_call_static_void(const char *imageName, const char *ns, const char *cls, const char *method) {
    if (!IL2.resolved) return false;
    const Il2CppImage *img = il2_find_image(imageName);
    if (!img) return false;
    Il2CppClass *k = IL2.class_from_name(img, ns ? ns : "", cls);
    if (!k) return false;
    const MethodInfo *m = IL2.class_get_method_from_name(k, method, 0);
    if (!m) return false;
    void *exc = NULL;
    IL2.runtime_invoke(m, NULL, NULL, &exc);
    return true;
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

// ====================== passthrough view — touches fall through to the game except on our controls ======================
@interface GalPassthroughView : UIView
@end

@implementation GalPassthroughView
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    // If the hit landed on *us* (empty space on the overlay), return nil so touch falls through
    return (hit == self) ? nil : hit;
}
@end

// ====================== passthrough window — same idea at window level ======================
@interface GalPassthroughWindow : UIWindow
@end

@implementation GalPassthroughWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    // Only our actual controls claim touches; window + root view = empty space -> let FF have it
    if (hit == nil || hit == self || hit == self.rootViewController.view) return nil;
    return hit;
}
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

    GalPassthroughWindow *w = [[GalPassthroughWindow alloc] initWithWindowScene:scene];
    w.windowLevel = UIWindowLevelStatusBar + 1000;
    UIViewController *vc = [[UIViewController alloc] init];
    // Swap the root VC's view for our passthrough view so empty taps go to the game
    GalPassthroughView *rootView = [[GalPassthroughView alloc] initWithFrame:w.bounds];
    rootView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    rootView.backgroundColor = [UIColor clearColor];
    vc.view = rootView;
    w.rootViewController = vc;
    w.backgroundColor = [UIColor clearColor];
    w.hidden = NO;
    self.window = w;

    UIView *root = vc.view;

    // Floating open button — small, top-left, draggable
    UIButton *fab = [UIButton buttonWithType:UIButtonTypeCustom];
    fab.frame = CGRectMake(14, 60, 38, 38);
    fab.backgroundColor = [self hueColor:0.6 b:0.9 a:0.78];
    fab.layer.cornerRadius = 19;
    fab.layer.shadowColor = [UIColor blackColor].CGColor;
    fab.layer.shadowOpacity = 0.35;
    fab.layer.shadowRadius = 5;
    fab.layer.shadowOffset = CGSizeMake(0, 2);
    [fab setTitle:@"G" forState:UIControlStateNormal];
    fab.titleLabel.font = [UIFont systemFontOfSize:18 weight:UIFontWeightBold];
    [fab setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [fab addTarget:self action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    UIPanGestureRecognizer *fabPan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(dragView:)];
    [fab addGestureRecognizer:fabPan];
    [root addSubview:fab];
    self.fab = fab;

    // Panel — anchored to top-left under the FAB
    UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(14, 110, 300, 420)];
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

    // Drag by the title bar
    UIView *dragHandle = [[UIView alloc] initWithFrame:CGRectMake(0, 0, panel.bounds.size.width, 52)];
    dragHandle.backgroundColor = [UIColor clearColor];
    dragHandle.userInteractionEnabled = YES;
    UIPanGestureRecognizer *panelPan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(dragPanel:)];
    [dragHandle addGestureRecognizer:panelPan];
    [panel addSubview:dragHandle];

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

    // Pages — scrollable so long feature lists fit
    self.pages = [NSMutableArray array];
    for (NSInteger i = 0; i < 3; i++) {
        UIScrollView *page = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 95, panel.bounds.size.width, panel.bounds.size.height - 95)];
        page.backgroundColor = [UIColor clearColor];
        page.showsVerticalScrollIndicator = YES;
        page.indicatorStyle = UIScrollViewIndicatorStyleWhite;
        page.hidden = YES;
        [panel addSubview:page];
        [self.pages addObject:(UIView *)page];
    }
    [self buildAimPage:(UIScrollView *)self.pages[0]];
    [self buildEspPage:(UIScrollView *)self.pages[1]];
    [self buildSettingsPage:(UIScrollView *)self.pages[2]];

    [self switchTab:0];
    LOG(@"menu built");
}

- (UIView *)baseRow:(UIView *)parent y:(CGFloat)y label:(NSString *)label soon:(BOOL)soon {
    CGFloat width = parent.bounds.size.width - 20;
    UIView *row = [[UIView alloc] initWithFrame:CGRectMake(10, y, width, 32)];
    row.backgroundColor = [UIColor colorWithRed:0.1 green:0.12 blue:0.22 alpha:soon ? 0.25 : 0.55];
    row.layer.cornerRadius = 7;
    [parent addSubview:row];

    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(12, 0, width - 70, 32)];
    lbl.text = label;
    lbl.font = [UIFont systemFontOfSize:12.5];
    lbl.textColor = soon ? [UIColor colorWithWhite:0.55 alpha:1.0]
                         : [UIColor colorWithRed:0.92 green:0.96 blue:1.0 alpha:1.0];
    [row addSubview:lbl];
    return row;
}

- (void)buildToggleRow:(UIView *)parent y:(CGFloat)y label:(NSString *)label soon:(BOOL)soon
                getter:(BOOL (^)(void))getter setter:(void (^)(BOOL))setter {
    UIView *row = [self baseRow:parent y:y label:label soon:soon];
    UISwitch *sw = [[UISwitch alloc] init];
    sw.frame = CGRectMake(row.bounds.size.width - 60, 0, 50, 32);
    sw.transform = CGAffineTransformMakeScale(0.72, 0.72);
    sw.on = getter();
    sw.enabled = !soon;
    sw.onTintColor = [UIColor colorWithRed:0.3 green:1.0 blue:0.5 alpha:1.0];
    [sw addTarget:[self.class blockHolder:^(UISwitch *s) { setter(s.on); }]
           action:@selector(invoke:)
 forControlEvents:UIControlEventValueChanged];
    [row addSubview:sw];
}

- (void)buildToggleRow:(UIView *)parent y:(CGFloat)y label:(NSString *)label
                getter:(BOOL (^)(void))getter setter:(void (^)(BOOL))setter {
    [self buildToggleRow:parent y:y label:label soon:NO getter:getter setter:setter];
}

- (void)buildSliderRow:(UIView *)parent y:(CGFloat)y label:(NSString *)label
                   min:(float)minV max:(float)maxV value:(float)value
                setter:(void (^)(float))setter soon:(BOOL)soon {
    UIView *row = [self baseRow:parent y:y label:label soon:soon];
    row.frame = CGRectMake(10, y, parent.bounds.size.width - 20, 32);
    UISlider *sl = [[UISlider alloc] initWithFrame:CGRectMake(row.bounds.size.width - 150, 2, 140, 28)];
    sl.minimumValue = minV;
    sl.maximumValue = maxV;
    sl.value = value;
    sl.enabled = !soon;
    sl.minimumTrackTintColor = [UIColor colorWithRed:0.4 green:0.6 blue:1.0 alpha:1.0];
    [sl addTarget:[self.class blockHolder:^(UISlider *s) { setter(s.value); }]
           action:@selector(invoke:)
 forControlEvents:UIControlEventValueChanged];
    [row addSubview:sl];
}

- (void)buildButtonRow:(UIView *)parent y:(CGFloat)y label:(NSString *)label
             btnLabel:(NSString *)btnLabel soon:(BOOL)soon action:(void (^)(void))action {
    UIView *row = [self baseRow:parent y:y label:label soon:soon];
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeCustom];
    btn.frame = CGRectMake(row.bounds.size.width - 70, 4, 60, 24);
    btn.backgroundColor = soon ? [UIColor colorWithWhite:0.3 alpha:0.6]
                               : [UIColor colorWithRed:0.35 green:0.5 blue:1.0 alpha:1.0];
    btn.layer.cornerRadius = 5;
    [btn setTitle:btnLabel forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.enabled = !soon;
    [btn addTarget:[self.class blockHolder:^(UIButton *b) { action(); }]
            action:@selector(invoke:)
  forControlEvents:UIControlEventTouchUpInside];
    [row addSubview:btn];
}

- (void)buildAimPage:(UIScrollView *)page {
    CGFloat y = 4;
    __weak typeof(self) wself = self;

    [self buildToggleRow:page y:y label:@"Aimbot (silent) · SOON" soon:YES
                  getter:^BOOL{ return CFG.aimOn; }
                  setter:^(BOOL v){ CFG.aimOn = v; [wself refreshHooks]; }];
    y += 38;
    [self buildButtonRow:page y:y label:@"Mode" btnLabel:@"silent" soon:YES action:^{}];
    y += 38;
    [self buildSliderRow:page y:y label:@"FOV (0-367°)"
                     min:0 max:367 value:CFG.fovDeg
                  setter:^(float v){ CFG.fovDeg = v; } soon:YES];
    y += 38;
    [self buildSliderRow:page y:y label:@"Smoothing"
                     min:0 max:0.95 value:CFG.smoothing
                  setter:^(float v){ CFG.smoothing = v; } soon:YES];
    y += 38;
    [self buildSliderRow:page y:y label:@"Accuracy cap %"
                     min:0.10 max:1.0 value:CFG.accuracyCap
                  setter:^(float v){ CFG.accuracyCap = v; } soon:YES];
    y += 38;
    [self buildToggleRow:page y:y label:@"No indicator" soon:YES
                  getter:^BOOL{ return YES; } setter:^(BOOL v){}];
    y += 38;
    [self buildToggleRow:page y:y label:@"Predict shot" soon:YES
                  getter:^BOOL{ return YES; } setter:^(BOOL v){}];
    y += 38;
    [self buildToggleRow:page y:y label:@"No Recoil" soon:NO
                  getter:^BOOL{ return CFG.noRecoil; }
                  setter:^(BOOL v){ CFG.noRecoil = v; if (v) il2_patch_no_recoil(); }];
    y += 38;
    [self buildToggleRow:page y:y label:@"No Spread" soon:NO
                  getter:^BOOL{ return CFG.noSpread; }
                  setter:^(BOOL v){ CFG.noSpread = v; if (v) il2_patch_no_spread(); }];
    y += 38;
    [self buildToggleRow:page y:y label:@"No Bullet Drop" soon:NO
                  getter:^BOOL{ return CFG.noBulletDrop; }
                  setter:^(BOOL v){ CFG.noBulletDrop = v; if (v) il2_patch_no_bullet_drop(); }];
    y += 38;
    [self buildToggleRow:page y:y label:@"Humanize (anti-shadowban)" soon:NO
                  getter:^BOOL{ return CFG.humanize; }
                  setter:^(BOOL v){ CFG.humanize = v; }];
    y += 38;

    page.contentSize = CGSizeMake(page.bounds.size.width, y + 10);
}

- (void)buildEspPage:(UIScrollView *)page {
    CGFloat y = 4;
    __weak typeof(self) wself = self;

    [self buildToggleRow:page y:y label:@"ESP master · SOON" soon:YES
                  getter:^BOOL{ return CFG.espOn; }
                  setter:^(BOOL v){ CFG.espOn = v; [wself refreshHooks]; }];
    y += 38;
    for (NSString *nm in @[@"Box", @"Name", @"HP bar", @"Distance",
                           @"Bone lines", @"Skeleton", @"Team check"]) {
        [self buildToggleRow:page y:y label:[NSString stringWithFormat:@"%@ · SOON", nm] soon:YES
                      getter:^BOOL{ return YES; } setter:^(BOOL v){}];
        y += 38;
    }
    [self buildSliderRow:page y:y label:@"Max distance (m)"
                     min:50 max:800 value:400
                  setter:^(float v){} soon:YES];
    y += 38;

    page.contentSize = CGSizeMake(page.bounds.size.width, y + 10);
}

- (void)buildSettingsPage:(UIScrollView *)page {
    CGFloat y = 4;
    __weak typeof(self) wself = self;

    [self buildSliderRow:page y:y label:@"Menu hue (0-360)"
                     min:0 max:360 value:CFG.menuHue
                  setter:^(float v){ CFG.menuHue = (int)v; [wself reskin]; } soon:NO];
    y += 38;
    [self buildButtonRow:page y:y label:@"ESP color" btnLabel:@"cyc" soon:YES action:^{
        CFG.espColor = (CFG.espColor + 1) % 5;
    }];
    y += 38;
    [self buildSliderRow:page y:y label:@"Opacity %"
                     min:30 max:100 value:CFG.opacity * 100
                  setter:^(float v){ CFG.opacity = v / 100.0; [wself reskin]; } soon:NO];
    y += 42;

    // === ANTI-BAN (all ACTIVE) ===
    [self buildToggleRow:page y:y label:@"Anti-Ban Auto-Stub"
                  getter:^BOOL{ return CFG.antiBanStub; }
                  setter:^(BOOL v){ CFG.antiBanStub = v; if (v) [wself refreshHooks]; }];
    y += 38;
    [self buildToggleRow:page y:y label:@"Kill DataDome / AppsFlyer"
                  getter:^BOOL{ return CFG.hideJB; }
                  setter:^(BOOL v){
                      CFG.hideJB = v;
                      if (v) { patch_datadome(); patch_appsflyer(); auto_stub_security_classes(); }
                  }];
    y += 38;
    [self buildToggleRow:page y:y label:@"Hide JB probes · SOON" soon:YES
                  getter:^BOOL{ return YES; } setter:^(BOOL v){}];
    y += 38;
    [self buildToggleRow:page y:y label:@"Capture ban code · SOON" soon:YES
                  getter:^BOOL{ return NO; } setter:^(BOOL v){}];
    y += 42;

    // === SHADOW-BAN GUARD ===
    [self buildToggleRow:page y:y label:@"Anti-Shadowban"
                  getter:^BOOL{ return CFG.humanize; }
                  setter:^(BOOL v){ CFG.humanize = v; }];
    y += 38;
    [self buildSliderRow:page y:y label:@"Miss rate %" min:0 max:50 value:15
                  setter:^(float v){} soon:YES];
    y += 38;
    [self buildSliderRow:page y:y label:@"Reaction ms" min:0 max:400 value:95
                  setter:^(float v){} soon:YES];
    y += 38;
    [self buildSliderRow:page y:y label:@"Aim jitter °" min:0 max:5 value:1.8
                  setter:^(float v){} soon:YES];
    y += 38;
    [self buildToggleRow:page y:y label:@"Telemetry block"
                  getter:^BOOL{ return CFG.telemetryBlock; }
                  setter:^(BOOL v){ CFG.telemetryBlock = v; [wself refreshHooks]; }];
    y += 38;
    [self buildToggleRow:page y:y label:@"Report immunity · SOON" soon:YES
                  getter:^BOOL{ return NO; } setter:^(BOOL v){}];
    y += 38;
    [self buildToggleRow:page y:y label:@"FP rotate on boot · SOON" soon:YES
                  getter:^BOOL{ return NO; } setter:^(BOOL v){}];
    y += 38;
    [self buildToggleRow:page y:y label:@"Pool detect · SOON" soon:YES
                  getter:^BOOL{ return NO; } setter:^(BOOL v){}];
    y += 38;
    [self buildButtonRow:page y:y label:@"Queue dodge · SOON" btnLabel:@"RUN" soon:YES action:^{}];
    y += 42;

    // === MISC ===
    [self buildToggleRow:page y:y label:@"Auto Headshot · SOON" soon:YES
                  getter:^BOOL{ return NO; } setter:^(BOOL v){}];
    y += 38;
    [self buildToggleRow:page y:y label:@"Instant Hit" soon:NO
                  getter:^BOOL{ return CFG.instantHit; }
                  setter:^(BOOL v){ CFG.instantHit = v; if (v) il2_patch_instant_hit(); }];
    y += 38;
    [self buildButtonRow:page y:y label:@"Guest Reset" btnLabel:@"RUN" soon:NO action:^{
        [wself runGuestReset];
    }];
    y += 42;

    page.contentSize = CGSizeMake(page.bounds.size.width, y + 10);
}

- (void)runGuestReset {
    // Safe wipe path — no IL2CPP invocation (risky for instance methods), no exit().
    // After the toast fires, user force-closes and reopens for the fresh register.

    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *all = [ud dictionaryRepresentation];
    int wiped = 0;
    for (NSString *key in all) {
        NSString *lower = key.lowercaseString;
        if ([lower containsString:@"garena"] || [lower containsString:@"aces"] ||
            [lower containsString:@"deviceid"] || [lower containsString:@"idfv"] ||
            [lower containsString:@"appsflyer"] || [lower containsString:@"hwid"] ||
            [lower containsString:@"datadome"] || [lower containsString:@"fingerprint"] ||
            [lower containsString:@"guest"] || [lower containsString:@"login"] ||
            [lower containsString:@"session"] || [lower containsString:@"token"]) {
            [ud removeObjectForKey:key];
            wiped++;
        }
    }
    [ud synchronize];

    int kc = wipe_keychain();

    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
    int fsWiped = 0;
    if (dirs.count) {
        NSString *lib = dirs[0];
        for (NSString *sub in @[@"Preferences", @"Caches", @"Cookies", @"WebKit"]) {
            NSString *p = [lib stringByAppendingPathComponent:sub];
            NSArray *items = [fm contentsOfDirectoryAtPath:p error:nil];
            for (NSString *item in items) {
                NSString *lower = item.lowercaseString;
                if ([lower containsString:@"garena"] || [lower containsString:@"freefire"] ||
                    [lower containsString:@"aces"] || [lower containsString:@"datadome"] ||
                    [lower containsString:@"appsflyer"] || [lower containsString:@"com.dts"]) {
                    [fm removeItemAtPath:[p stringByAppendingPathComponent:item] error:nil];
                    fsWiped++;
                }
            }
        }
    }

    LOG(@"guest reset — %d UD keys, %d kc classes, %d fs items", wiped, kc, fsWiped);
    [self showToast:[NSString stringWithFormat:@"✓ wiped — restart app"]];
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

- (void)dragView:(UIPanGestureRecognizer *)g {
    UIView *v = g.view;
    CGPoint t = [g translationInView:v.superview];
    v.center = CGPointMake(v.center.x + t.x, v.center.y + t.y);
    [g setTranslation:CGPointZero inView:v.superview];
}

- (void)dragPanel:(UIPanGestureRecognizer *)g {
    UIView *target = self.panel;
    CGPoint t = [g translationInView:target.superview];
    target.center = CGPointMake(target.center.x + t.x, target.center.y + t.y);
    [g setTranslation:CGPointZero inView:target.superview];
}

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
    // ObjC side
    if (CFG.hideJB)      { patch_datadome(); patch_appsflyer(); }
    if (CFG.antiBanStub) { auto_stub_security_classes(); }

    // IL2CPP side — re-patch on toggle (patches are idempotent if methodPointer
    // is already our stub, vm_protect + memcpy just rewrites the same bytes).
    if (IL2.resolved) {
        if (CFG.noRecoil)     il2_patch_no_recoil();
        if (CFG.noSpread)     il2_patch_no_spread();
        if (CFG.noBulletDrop) il2_patch_no_bullet_drop();
    }
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

static void il2_try_with_retries(int n) {
    if (resolve_il2cpp()) {
        // arm64e PAC makes blind MethodInfo swaps risky — don't blanket-stub at boot.
        // Wait for the user to flip the "IL2CPP Auto-Stub" toggle. ObjC anti-ban runs anyway.
        LOG(@"IL2CPP resolved — auto-stub idle until user opts in");
        return;
    }
    if (n > 0) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            il2_try_with_retries(n - 1);
        });
    } else {
        LOG(@"IL2CPP never resolved — ObjC anti-ban still live");
    }
}

+ (void)boot {
    LOG(@"boot");

    // 1. ObjC-side anti-ban active FROM FIRST LAUNCH (defaults are now ON).
    patch_datadome();
    patch_appsflyer();
    auto_stub_security_classes();

    // 2. Try IL2CPP resolve. If UnityFramework isn't loaded yet, retry every 2 s up to 15 times.
    il2_try_with_retries(15);

    // 3. Build UI
    gMenu = [[GalacticaMenu alloc] init];
    [gMenu build];
    if (!gMenu.window) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [gMenu build]; });
    }

    LOG(@"ready — ObjC anti-ban ACTIVE");
}

@end
