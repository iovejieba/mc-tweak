// MemberBypass.m v5 — 弹窗修复版
//
// v4 没弹窗的原因：iOS 13+ UIScene 架构下
//   [UIApplication sharedApplication].windows  返回空数组
// 所以 window 拿不到，presentViewController 永远不会执行。
//
// v5 修复：
//   1. 遍历 connectedScenes 找 keyWindow
//   2. 都失败时，直接用 UIWindow 手工建一个和 app 同级的 window 来弹
//   3. 弹窗失败则退回写文件 + 抄送 NSLog

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <dlfcn.h>
#include <string.h>
#include <unistd.h>

static BOOL g_done = NO;
static NSMutableArray<NSString *> *g_lines = nil;

#define ADD(fmt, ...) [g_lines addObject:[NSString stringWithFormat:(fmt), ##__VA_ARGS__]]

#pragma mark - keychain

static NSDictionary *Q(NSString *svc, NSString *acc) {
    return @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: svc,
        (__bridge id)kSecAttrAccount: acc,
    };
}

static NSString *ReadKC(NSString *svc, NSString *acc) {
    NSMutableDictionary *q = [Q(svc, acc) mutableCopy];
    q[(__bridge id)kSecReturnData] = @YES;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st != errSecSuccess || !out) return [NSString stringWithFormat:@"无(status=%d)", (int)st];
    NSData *d = (__bridge_transfer NSData *)out;
    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (s.length) return [NSString stringWithFormat:@"%luB %@", (unsigned long)d.length,
                          [s substringToIndex:MIN((NSUInteger)100, s.length)]];
    return [NSString stringWithFormat:@"%luB <非UTF8: %@>", (unsigned long)d.length,
            [d subdataWithRange:NSMakeRange(0, MIN(16u, (unsigned)d.length))]];
}

static OSStatus WriteKC(NSString *svc, NSString *acc, NSData *p) {
    SecItemDelete((__bridge CFDictionaryRef)Q(svc, acc));
    NSMutableDictionary *a = [Q(svc, acc) mutableCopy];
    a[(__bridge id)kSecValueData] = p;
    a[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    return SecItemAdd((__bridge CFDictionaryRef)a, NULL);
}

#pragma mark - hook

typedef OSStatus (*CopyMatchingFn)(CFDictionaryRef, CFTypeRef *);
static CopyMatchingFn g_orig = NULL;
static NSData *g_payload = nil;
static int g_hits = 0;

static OSStatus MB_Copy(CFDictionaryRef q, CFTypeRef *r) {
    if (q && g_payload) {
        NSDictionary *d = (__bridge NSDictionary *)q;
        NSString *acc = d[(__bridge id)kSecAttrAccount];
        BOOL wantData = [d[(__bridge id)kSecReturnData] boolValue];
        if ([acc isKindOfClass:[NSString class]] && wantData &&
            ([acc.lowercaseString containsString:@"transaction"] ||
             [acc.lowercaseString containsString:@"member"])) {
            g_hits++;
            if (r) *r = CFBridgingRetain(g_payload);
            return errSecSuccess;
        }
    }
    return g_orig ? g_orig(q, r) : (OSStatus)errSecItemNotFound;
}

static void PatchGOT(const char *sym, void *repl, void **origOut) {
    void *real = dlsym(RTLD_DEFAULT, sym);
    if (!real) { ADD(@"dlsym(%s) 失败", sym); return; }
    int n = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        const char *img = _dyld_get_image_name(i);
        if (!img || (!strstr(img, "mangaCapsule") && !strstr(img, "MemberBypass"))) continue;
        const struct load_command *lc =
            (const struct load_command *)((const char *)h + sizeof(struct mach_header_64));
        for (uint32_t c = 0; c < h->ncmds; c++) {
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (!strcmp(seg->segname, "__DATA_CONST") || !strcmp(seg->segname, "__DATA")) {
                    const struct section_64 *s =
                        (const struct section_64 *)((const char *)seg + sizeof(struct segment_command_64));
                    for (uint32_t j = 0; j < seg->nsects; j++, s++) {
                        if (strcmp(s->sectname, "__got") && strcmp(s->sectname, "__auth_got") &&
                            strcmp(s->sectname, "__la_symbol_ptr")) continue;
                        void **slots = (void **)((char *)h + s->offset);
                        for (uint32_t k = 0; k < s->size / sizeof(void *); k++) {
                            if (slots[k] != real) continue;
                            if (vm_protect(mach_task_self(), (vm_address_t)&slots[k],
                                           sizeof(void *), false,
                                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
                                continue;
                            if (origOut && !*origOut) *origOut = slots[k];
                            slots[k] = repl;
                            n++;
                        }
                    }
                }
            }
            lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
        }
    }
    ADD(@"hook %s: %d 处", sym, n);
}

#pragma mark - 正确的取窗口（iOS 13+）

static UIWindow *MBKeyWindow(void) {
    UIWindow *fallback = nil;

    // 1) connectedScenes 路线
    if (@available(iOS 13.0, *)) {
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)sc;
            for (UIWindow *w in ws.windows) {
                if (w.isKeyWindow) return w;
                if (!fallback) fallback = w;
            }
            if (!fallback && ws.windows.count) fallback = ws.windows.firstObject;
        }
    }

    // 2) 老 API
    if (!fallback) {
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.isKeyWindow) return w;
            if (!fallback) fallback = w;
        }
    }

    // 3) 都空：手工建一个
    if (!fallback && @available(iOS 13.0, *)) {
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)sc;
            UIWindow *w = [[UIWindow alloc] initWithWindowScene:ws];
            w.windowLevel = UIWindowLevelAlert + 1;
            w.frame = ws.coordinateSpace.bounds;
            w.hidden = NO;
            w.rootViewController = [[UIViewController alloc] init];
            fallback = w;
            ADD(@"(手工创建 window)");
            break;
        }
    }
    return fallback;
}

static void ShowAlert(int attempt) {
    UIWindow *win = MBKeyWindow();
    UIViewController *root = win.rootViewController;

    if (!root) {
        if (attempt < 20) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ ShowAlert(attempt + 1); });
        }
        return;
    }

    // root 可能已经 present 了别的东西，逐层找最顶层
    UIViewController *top = root;
    while (top.presentedViewController) top = top.presentedViewController;

    NSString *body = [g_lines componentsJoinedByString:@"\n"];
    UIAlertController *ac =
        [UIAlertController alertControllerWithTitle:@"MemberBypass 诊断"
                                            message:body
                                     preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"知道了"
                                           style:UIAlertActionStyleDefault
                                         handler:nil]];

    [top presentViewController:ac animated:YES completion:^{
        NSLog(@"[MB] alert presented");
    }];
    NSLog(@"[MB] alert attempted on %@", NSStringFromClass([top class]));
}

#pragma mark - 落盘兜底

static void DumpToFile(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                         NSUserDomainMask, YES) firstObject];
    if (!dir) return;
    NSString *p = [dir stringByAppendingPathComponent:@"mb.log"];
    NSString *txt = [g_lines componentsJoinedByString:@"\n"];
    [txt writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"[MB] log -> %@", p);
}

#pragma mark - init

static void MBInitOnce(void) {
    if (g_done) return;
    g_done = YES;
    g_lines = [NSMutableArray array];

    ADD(@"✅ dylib 已加载");
    ADD(@"bundle: %@", [[NSBundle mainBundle] bundleIdentifier]);
    ADD(@"iOS: %@", [[UIDevice currentDevice] systemVersion]);

    NSMutableDictionary *p = [NSMutableDictionary dictionary];
    p[@"id"] = @"local";
    p[@"isVIP"] = @YES;
    p[@"expireAt"] = @9021715200.0;
    p[@"VIPType"] = @2;
    p[@"hasGifted"] = @NO;
    p[@"shouldRefreshProducts"] = @NO;
    p[@"weeklyReadNum"] = @0;
    g_payload = [NSJSONSerialization dataWithJSONObject:p options:0 error:nil];

    ADD(@"");
    ADD(@"原始 Keychain:");
    ADD(@" rainy.lyn.mangaCapsule:");
    ADD(@"   %@", ReadKC(@"rainy.lyn.mangaCapsule", @"validTransaction"));

    OSStatus w1 = WriteKC(@"rainy.lyn.mangaCapsule", @"validTransaction", g_payload);
    OSStatus w2 = WriteKC(@"rainy.heichai.mangaCapsule3", @"validTransaction", g_payload);
    ADD(@"");
    ADD(@"写入: %d / %d", (int)w1, (int)w2);
    if (w1 == -34018 || w2 == -34018) ADD(@"⚠️ -34018 无 keychain 权限");

    ADD(@"写入后读回:");
    ADD(@"   %@", ReadKC(@"rainy.lyn.mangaCapsule", @"validTransaction"));

    PatchGOT("SecItemCopyMatching", (void *)MB_Copy, (void **)&g_orig);
    if (!g_orig) g_orig = (CopyMatchingFn)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");

    DumpToFile();

    // app 启动需要时间，延迟弹
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ShowAlert(0); });
}

__attribute__((used, visibility("default")))
void MBInit(void) { MBInitOnce(); }

__attribute__((objc_root_class))
@interface MBLoader
@end

@implementation MBLoader
+ (void)load { MBInitOnce(); }
@end
