// MemberBypass.m v6 — 修正 Codable 键名
//
// v5 弹窗证明：
//   dylib 已加载 ✅ / keychain 写入 status=0 ✅ / 读回 isVIP:true ✅
//   但 app 仍显示免费用户 ❌
//
// 根因：MemberObj 的存储属性全部带下划线（@Published 包装），
//       Codable 合成的 CodingKey 用的就是存储属性名：
//         id, _isVIP, _expireAt, _VIPType, _hasGifted,
//         _shouldRefreshProducts, _weeklyReadNum
//       v5 写的是 isVIP/expireAt/VIPType，解码时全部对不上，
//       但 JSONDecoder 对缺字段报错后 app 静默回落到免费用户。
//
// v6：只写正确的键名（干净 JSON，不塞多余字段）
//     并且把 hook 的匹配放宽到任意 keychain 读取

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
    return @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
              (__bridge id)kSecAttrService: svc,
              (__bridge id)kSecAttrAccount: acc };
}

static NSString *ReadKC(NSString *svc, NSString *acc) {
    NSMutableDictionary *q = [Q(svc, acc) mutableCopy];
    q[(__bridge id)kSecReturnData] = @YES;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef o = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &o);
    if (st != errSecSuccess || !o) return [NSString stringWithFormat:@"(st=%d)", (int)st];
    NSData *d = (__bridge_transfer NSData *)o;
    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    return s ?: [NSString stringWithFormat:@"%luB non-utf8", (unsigned long)d.length];
}

static OSStatus WriteKC(NSString *svc, NSString *acc, NSData *p) {
    SecItemDelete((__bridge CFDictionaryRef)Q(svc, acc));
    NSMutableDictionary *a = [Q(svc, acc) mutableCopy];
    a[(__bridge id)kSecValueData] = p;
    a[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    return SecItemAdd((__bridge CFDictionaryRef)a, NULL);
}

#pragma mark - payload：严格按 Swift 存储属性名

static NSData *BuildPayload(void) {
    // 键名 = MemberObj 的存储属性名（含下划线）
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    d[@"id"]                     = @"local";
    d[@"_isVIP"]                 = @YES;
    d[@"_expireAt"]              = @9021715200.0;   // 2286-11-21
    d[@"_VIPType"]               = @2;
    d[@"_hasGifted"]             = @NO;
    d[@"_shouldRefreshProducts"] = @NO;
    d[@"_weeklyReadNum"]         = @0;
    NSError *e = nil;
    NSData *out = [NSJSONSerialization dataWithJSONObject:d options:0 error:&e];
    if (e) ADD(@"payload err %@", e);
    return out;
}

#pragma mark - hooks

typedef OSStatus (*CopyFn)(CFDictionaryRef, CFTypeRef *);
static CopyFn g_orig = NULL;
static NSData *g_payload = nil;
static int g_hits = 0;

static OSStatus MB_Copy(CFDictionaryRef q, CFTypeRef *r) {
    // 放宽：任何带 ReturnData 的 keychain 读，只要 account 不含已知噪声就拦
    if (q && g_payload) {
        NSDictionary *d = (__bridge NSDictionary *)q;
        NSString *acc = d[(__bridge id)kSecAttrAccount];
        BOOL wantData = [d[(__bridge id)kSecReturnData] boolValue];
        id limit = d[(__bridge id)kSecMatchLimit];
        BOOL all = [limit isEqual:(__bridge id)kSecMatchLimitAll];
        if ([acc isKindOfClass:[NSString class]] && wantData && !all) {
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
    ADD(@"hook %s: %d", sym, n);
}

#pragma mark - alert

static UIWindow *KeyWindow(void) {
    UIWindow *fb = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)sc;
            for (UIWindow *w in ws.windows) {
                if (w.isKeyWindow) return w;
                if (!fb) fb = w;
            }
            if (!fb && ws.windows.count) fb = ws.windows.firstObject;
        }
    }
    if (!fb) {
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.isKeyWindow) return w;
            if (!fb) fb = w;
        }
    }
    return fb;
}

static void ShowAlert(int attempt) {
    UIWindow *win = KeyWindow();
    UIViewController *vc = win.rootViewController;
    if (!vc) {
        if (attempt < 15) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ ShowAlert(attempt + 1); });
        }
        return;
    }
    UIViewController *top = vc;
    while (top.presentedViewController) top = top.presentedViewController;

    UIAlertController *ac =
        [UIAlertController alertControllerWithTitle:@"MemberBypass v6"
                                            message:[g_lines componentsJoinedByString:@"\n"]
                                     preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleDefault handler:nil]];
    [top presentViewController:ac animated:YES completion:nil];
}

#pragma mark - init

static void MBInitOnce(void) {
    if (g_done) return;
    g_done = YES;
    g_lines = [NSMutableArray array];

    ADD(@"✅ dylib 已加载 (v6)");
    g_payload = BuildPayload();
    ADD(@"payload: %@", [[NSString alloc] initWithData:g_payload encoding:NSUTF8StringEncoding]);

    ADD(@"写入前: %@", ReadKC(@"rainy.lyn.mangaCapsule", @"validTransaction"));

    OSStatus w1 = WriteKC(@"rainy.lyn.mangaCapsule", @"validTransaction", g_payload);
    OSStatus w2 = WriteKC(@"rainy.heichai.mangaCapsule3", @"validTransaction", g_payload);
    OSStatus w3 = WriteKC(@"rainy.lyn.mangaCapsule", @"member", g_payload);
    ADD(@"写入: %d/%d/%d", (int)w1, (int)w2, (int)w3);
    ADD(@"写入后: %@", ReadKC(@"rainy.lyn.mangaCapsule", @"validTransaction"));

    PatchGOT("SecItemCopyMatching", (void *)MB_Copy, (void **)&g_orig);
    if (!g_orig) g_orig = (CopyFn)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");

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
