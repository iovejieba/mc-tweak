// MemberBypass.m v4 — 弹窗诊断版
//
// 目的：不依赖你去翻沙盒日志，启动后直接用 UIAlertView 把关键结果显示出来。
//      同时保留完整 dylib 注入，确认它到底有没有被 dyld 加载。

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

#define ADD(fmt, ...) do { \
    [g_lines addObject:[NSString stringWithFormat:(fmt), ##__VA_ARGS__]]; \
} while (0)

#pragma mark - keychain 探测

static NSDictionary *Q(NSString *svc, NSString *acc) {
    return @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: svc,
        (__bridge id)kSecAttrAccount: acc,
    };
}

static NSString *ReadKeychain(NSString *svc, NSString *acc) {
    NSMutableDictionary *q = [Q(svc, acc) mutableCopy];
    q[(__bridge id)kSecReturnData] = @YES;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st != errSecSuccess || !out) return [NSString stringWithFormat:@"(status=%d)", (int)st];
    NSData *d = (__bridge_transfer NSData *)out;
    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (s.length) return [NSString stringWithFormat:@"%luB %@", (unsigned long)d.length,
                          [s substringToIndex:MIN((NSUInteger)120, s.length)]];
    return [NSString stringWithFormat:@"%luB <非UTF8>", (unsigned long)d.length];
}

static OSStatus WriteKeychain(NSString *svc, NSString *acc, NSData *payload) {
    SecItemDelete((__bridge CFDictionaryRef)Q(svc, acc));
    NSMutableDictionary *add = [Q(svc, acc) mutableCopy];
    add[(__bridge id)kSecValueData] = payload;
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    return SecItemAdd((__bridge CFDictionaryRef)add, NULL);
}

#pragma mark - GOT hook

typedef OSStatus (*CopyMatchingFn)(CFDictionaryRef, CFTypeRef *);
static CopyMatchingFn g_origCopy = NULL;
static NSData *g_payload = nil;
static int g_hitCount = 0;
static NSString *g_lastQuery = @"(未拦截到任何查询)";

static BOOL LooksLikeMember(NSString *acc) {
    if (!acc) return NO;
    NSString *low = acc.lowercaseString;
    return [low containsString:@"transaction"] || [low containsString:@"member"] ||
           [low containsString:@"vip"] || [low containsString:@"valid"];
}

static OSStatus MB_CopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    if (query) {
        NSDictionary *d = (__bridge NSDictionary *)query;
        NSString *acc = d[(__bridge id)kSecAttrAccount];
        NSString *svc = d[(__bridge id)kSecAttrService];
        BOOL wantData = [d[(__bridge id)kSecReturnData] boolValue];

        if ([acc isKindOfClass:[NSString class]] && LooksLikeMember(acc)) {
            g_lastQuery = [NSString stringWithFormat:@"svc=%@ acc=%@ wantData=%d",
                           svc, acc, wantData];
            if (wantData && g_payload) {
                g_hitCount++;
                if (result) *result = CFBridgingRetain(g_payload);
                return errSecSuccess;
            }
        }
    }
    return g_origCopy ? g_origCopy(query, result) : (OSStatus)errSecItemNotFound;
}

static void PatchGOT(const char *sym, void *repl, void **origOut) {
    void *real = dlsym(RTLD_DEFAULT, sym);
    if (!real) { ADD(@"dlsym(%s) 失败", sym); return; }
    int n = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        const char *img = _dyld_get_image_name(i);
        if (!img) continue;
        if (!strstr(img, "mangaCapsule") && !strstr(img, "MemberBypass")) continue;

        const struct load_command *lc =
            (const struct load_command *)((const char *)h + sizeof(struct mach_header_64));
        for (uint32_t c = 0; c < h->ncmds; c++) {
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (!strcmp(seg->segname, "__DATA_CONST") || !strcmp(seg->segname, "__DATA")) {
                    const struct section_64 *s =
                        (const struct section_64 *)((const char *)seg + sizeof(struct segment_command_64));
                    for (uint32_t j = 0; j < seg->nsects; j++, s++) {
                        if (strcmp(s->sectname, "__got") &&
                            strcmp(s->sectname, "__auth_got") &&
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

#pragma mark - 弹窗

static void ShowAlert(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIWindow *win = nil;
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.isKeyWindow) { win = w; break; }
        }
        if (!win) win = [UIApplication sharedApplication].windows.firstObject;
        if (!win) { NSLog(@"[MB] no window"); return; }

        NSString *body = [g_lines componentsJoinedByString:@"\n"];
        UIAlertController *ac =
            [UIAlertController alertControllerWithTitle:@"MemberBypass 诊断"
                                                message:body
                                         preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"知道了"
                                               style:UIAlertActionStyleDefault
                                             handler:nil]];
        [win.rootViewController presentViewController:ac animated:YES completion:nil];
        NSLog(@"[MB] alert shown");
    });
}

#pragma mark - init

static void MBInitOnce(void) {
    if (g_done) return;
    g_done = YES;
    g_lines = [NSMutableArray array];

    ADD(@"dylib 已加载 ✓");
    ADD(@"bundle: %@", [[NSBundle mainBundle] bundleIdentifier]);

    // 造 payload
    NSMutableDictionary *p = [NSMutableDictionary dictionary];
    p[@"id"] = @"local";
    p[@"isVIP"] = @YES;
    p[@"expireAt"] = @9021715200.0;
    p[@"VIPType"] = @2;
    p[@"hasGifted"] = @NO;
    p[@"shouldRefreshProducts"] = @NO;
    p[@"weeklyReadNum"] = @0;
    g_payload = [NSJSONSerialization dataWithJSONObject:p options:0 error:nil];

    // 读原始值
    ADD(@"原始 validTransaction:");
    ADD(@"  %@", ReadKeychain(@"rainy.lyn.mangaCapsule", @"validTransaction"));

    // 写入
    OSStatus w1 = WriteKeychain(@"rainy.lyn.mangaCapsule", @"validTransaction", g_payload);
    OSStatus w2 = WriteKeychain(@"rainy.heichai.mangaCapsule3", @"validTransaction", g_payload);
    ADD(@"写入 status: %d / %d", (int)w1, (int)w2);
    if (w1 == -34018 || w2 == -34018) {
        ADD(@"⚠️ -34018 缺 keychain entitlement");
    }

    // 回读确认
    ADD(@"写入后读回:");
    ADD(@"  %@", ReadKeychain(@"rainy.lyn.mangaCapsule", @"validTransaction"));

    // 装 hook
    PatchGOT("SecItemCopyMatching", (void *)MB_CopyMatching, (void **)&g_origCopy);
    if (!g_origCopy) g_origCopy = (CopyMatchingFn)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");

    ShowAlert();
}

__attribute__((used, visibility("default")))
void MBInit(void) { MBInitOnce(); }

__attribute__((objc_root_class))
@interface MBLoader
@end

@implementation MBLoader
+ (void)load { MBInitOnce(); }
@end
