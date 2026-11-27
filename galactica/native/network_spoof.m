// network_spoof.m — hook NSURLSession so Fluck's license check at
// licensesync.io / licensely.net never actually leaves the device.
// We synthesize a successful "license valid" JSON and hand it to the
// completion handler so Fluck thinks the server said yes.
//
// Uses ObjC method_setImplementation on NSURLSession's two dataTask
// entry points. Pure runtime swizzle, no fishhook — these methods
// are published on NSURLSession via the Obj-C runtime.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSArray<NSString *> *gal_target_hosts(void) {
    static NSArray *hosts;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        hosts = @[ @"licensesync.io", @"licensely.net" ];
    });
    return hosts;
}

static BOOL gal_url_is_license(NSURL *url) {
    if (!url) return NO;
    NSString *host = url.host.lowercaseString;
    if (!host) return NO;
    for (NSString *h in gal_target_hosts()) {
        if ([host containsString:h]) return YES;
    }
    return NO;
}

static NSData *gal_fake_license_json(NSURL *url) {
    // Best-effort payload. Fluck's exact schema is unknown — ship the
    // common fields so one of them hits.
    NSDictionary *payload = @{
        @"status":      @"ok",
        @"result":      @"success",
        @"valid":       @YES,
        @"licensed":    @YES,
        @"trial":       @NO,
        @"active":      @YES,
        @"activated":   @YES,
        @"expires":     @"2099-12-31T23:59:59Z",
        @"expires_at":  @"2099-12-31T23:59:59Z",
        @"expiration":  @"2099-12-31T23:59:59Z",
        @"key":         @"GALACTICA-BYPASS",
        @"license_key": @"GALACTICA-BYPASS",
        @"features":    @[@"all", @"premium", @"anti_ban", @"aimbot", @"esp"],
        @"plan":        @"lifetime",
        @"user":        @{ @"id": @"galactica", @"name": @"galactica" },
        @"message":     @"OK",
        @"code":        @0,
    };
    NSError *err = nil;
    NSData *d = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&err];
    if (!d) {
        d = [@"{\"status\":\"ok\",\"valid\":true}" dataUsingEncoding:NSUTF8StringEncoding];
    }
    return d;
}

static NSURLResponse *gal_fake_response(NSURL *url, NSUInteger len) {
    return [[NSHTTPURLResponse alloc] initWithURL:url
                                        statusCode:200
                                       HTTPVersion:@"HTTP/1.1"
                                      headerFields:@{
                                          @"Content-Type": @"application/json",
                                          @"Content-Length": [NSString stringWithFormat:@"%lu", (unsigned long)len],
                                      }];
}

// Fallback stub dataTask — never runs real network; completion fires on next tick.
@interface _GalFakeDataTask : NSURLSessionDataTask
@property (nonatomic, copy)  void (^fakeCompletion)(NSData *, NSURLResponse *, NSError *);
@property (nonatomic, strong) NSData *fakeData;
@property (nonatomic, strong) NSURLResponse *fakeResponse;
@end

@implementation _GalFakeDataTask
- (void)resume {
    __weak typeof(self) wself = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.05 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (wself.fakeCompletion) {
            wself.fakeCompletion(wself.fakeData, wself.fakeResponse, nil);
        }
    });
}
- (void)cancel  {}
- (void)suspend {}
@end

static IMP g_orig_dataTaskWithRequest = NULL;
static IMP g_orig_dataTaskWithURL     = NULL;

static NSURLSessionDataTask *gal_dataTaskWithRequest(id self, SEL _cmd,
                                                     NSURLRequest *req,
                                                     void (^handler)(NSData *, NSURLResponse *, NSError *)) {
    NSURL *u = req.URL;
    if (gal_url_is_license(u) && handler) {
        NSLog(@"[Galactica-net] spoof license req: %@", u);
        NSData *d = gal_fake_license_json(u);
        _GalFakeDataTask *t = [[_GalFakeDataTask alloc] init];
        t.fakeCompletion = handler;
        t.fakeData = d;
        t.fakeResponse = gal_fake_response(u, d.length);
        return t;
    }
    typedef NSURLSessionDataTask *(*fn_t)(id, SEL, NSURLRequest *,
                                           void (^)(NSData *, NSURLResponse *, NSError *));
    return ((fn_t)g_orig_dataTaskWithRequest)(self, _cmd, req, handler);
}

static NSURLSessionDataTask *gal_dataTaskWithURL(id self, SEL _cmd,
                                                 NSURL *url,
                                                 void (^handler)(NSData *, NSURLResponse *, NSError *)) {
    if (gal_url_is_license(url) && handler) {
        NSLog(@"[Galactica-net] spoof license URL: %@", url);
        NSData *d = gal_fake_license_json(url);
        _GalFakeDataTask *t = [[_GalFakeDataTask alloc] init];
        t.fakeCompletion = handler;
        t.fakeData = d;
        t.fakeResponse = gal_fake_response(url, d.length);
        return t;
    }
    typedef NSURLSessionDataTask *(*fn_t)(id, SEL, NSURL *,
                                           void (^)(NSData *, NSURLResponse *, NSError *));
    return ((fn_t)g_orig_dataTaskWithURL)(self, _cmd, url, handler);
}

__attribute__((constructor(102)))
static void gal_install_network_spoof(void) {
    Class cls = objc_getClass("NSURLSession");
    if (!cls) {
        NSLog(@"[Galactica-net] NSURLSession class missing — skip");
        return;
    }
    Method m1 = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:completionHandler:));
    Method m2 = class_getInstanceMethod(cls, @selector(dataTaskWithURL:completionHandler:));
    if (m1) g_orig_dataTaskWithRequest = method_setImplementation(m1, (IMP)gal_dataTaskWithRequest);
    if (m2) g_orig_dataTaskWithURL     = method_setImplementation(m2, (IMP)gal_dataTaskWithURL);
    NSLog(@"[Galactica-net] NSURLSession swizzle installed (m1=%p m2=%p)", m1, m2);
}
