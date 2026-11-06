// MemberBypass.m — v8
//
// v5/v6 为什么失败（结合 Probe2 的实测数据）：
//   Probe2 枚举 keychain 得到 7 项，其中：
//     [1] service="rainy.lyn.mangaCapsule" account="validTransaction"  <- 我写的
//     [6] service=""                       account="rainy.lyn.mangaCapsule" -> UUID
//     [7] service=""                       account="lastActive..."          -> 时间戳
//   说明 app 真实读取的账号/服务组合与我猜的不同，而且很可能用
//   kSecMatchLimitAll 枚举后自己挑，而 v6 的 hook 把 All 查询直接放行了。
//
// v8 修三件事：
//   1. CopyMatching 同时支持「单选」和「MatchLimitAll 枚举」两种查询
//   2. hook SecItemUpdate / SecItemDelete，禁止改动我们这条
//   3. 键名同时给出两种变体（编译期宏 VIPKEY_UNDERSCORE），一次测两个
//
// 编译：
//   -DVIPKEY_UNDERSCORE=0  -> {"id","isVIP","expireAt","VIPType",...}
//   -DVIPKEY_UNDERSCORE=1  -> {"id","_isVIP","_expireAt","_VIPType",...}

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

#ifndef VIPKEY_UNDERSCORE
#define VIPKEY_UNDERSCORE 0
#endif

static const double kExpire = 9021715200.0;   // 2286-11-21
static const int    kVIPInt = 2;

static NSString *const kSvcA = @"rainy.lyn.mangaCapsule";
static NSString *const kSvcB = @"rainy.heichai.mangaCapsule3";
static NSString *const kSvcC = @"";
static NSString *const kAccV = @"validTransaction";

static BOOL    g_done = NO;
static FILE   *g_log  = NULL;
static NSData *g_payload = nil;
static NSMutableArray<NSString *> *g_lines = nil;
static int     g_hits = 0;

#define ADD(fmt, ...) [g_lines addObject:[NSString stringWithFormat:(fmt), ##__VA_ARGS__]]

static void MBLog(NSString *s) {
    NSLog(@"[MB] %@", s);
    if (g_log) { fprintf(g_log, "%s\n", s.UTF8String); fflush(g_log); }
}

#pragma mark - payload

static NSData *BuildPayload(void) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    d[@"id"] = @"local";
#if VIPKEY_UNDERSCORE
    d[@"_isVIP"]                 = @YES;
    d[@"_expireAt"]              = @(kExpire);
    d[@"_VIPType"]               = @(kVIPInt);
    d[@"_hasGifted"]             = @NO;
    d[@"_shouldRefreshProducts"] = @NO;
    d[@"_weeklyReadNum"]         = @0;
#else
    d[@"isVIP"]                 = @YES;
    d[@"expireAt"]              = @(kExpire);
    d[@"VIPType"]               = @(kVIPInt);
    d[@"hasGifted"]             = @NO;
    d[@"shouldRefreshProducts"] = @NO;
    d[@"weeklyReadNum"]         = @0;
#endif
    return [NSJSONSerialization dataWithJSONObject:d options:0 error:nil];
}

#pragma mark - keychain

static NSArray<NSString *> *AllSvcs(void) {
    return @[kSvcA, kSvcB, kSvcC];
}

static OSStatus WriteOne(NSString *svc, NSString *acc, NSData *p) {
    NSDictionary *q = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                         (__bridge id)kSecAttrService: svc,
                         (__bridge id)kSecAttrAccount: acc };
    SecItemDelete((__bridge CFDictionaryRef)q);
    NSMutableDictionary *a = [q mutableCopy];
    a[(__bridge id)kSecValueData] = p;
    a[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    return SecItemAdd((__bridge CFDictionaryRef)a, NULL);
}

static void WriteAll(void) {
    for (NSString *s in AllSvcs()) {
        OSStatus st = WriteOne(s, kAccV, g_payload);
        MBLog([NSString stringWithFormat:@"write svc='%@' acc='%@' -> %d", s, kAccV, (int)st]);
    }
}

#pragma mark - hooks

typedef OSStatus (*CopyFn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*AddFn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*UpdFn)(CFDictionaryRef, CFDictionaryRef);
typedef OSStatus (*DelFn)(CFDictionaryRef);

static CopyFn g_origCopy = NULL;
static AddFn  g_origAdd  = NULL;
static UpdFn  g_origUpd  = NULL;
static DelFn  g_origDel  = NULL;

// 我们关心的 account（会员那条）
static BOOL AccIsOurs(NSString *acc) {
    if (![acc isKindOfClass:[NSString class]]) return NO;
    return [acc isEqualToString:kAccV];
}

// 构造「属性+数据」字典，供 MatchLimitAll 返回
static NSDictionary *ItemDict(NSString *svc, NSString *acc, NSData *data) {
    return @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: svc ?: @"",
        (__bridge id)kSecAttrAccount: acc ?: @"",
        (__bridge id)kSecValueData:   data,
    };
}

static OSStatus MB_Copy(CFDictionaryRef query, CFTypeRef *result) {
    if (!query || !g_payload) return g_origCopy ? g_origCopy(query, result) : (OSStatus)errSecItemNotFound;

    NSDictionary *q = (__bridge NSDictionary *)query;
    NSString *acc = q[(__bridge id)kSecAttrAccount];
    NSString *svc = q[(__bridge id)kSecAttrService];
    BOOL wantData  = [q[(__bridge id)kSecReturnData] boolValue];
    BOOL wantAttrs = [q[(__bridge id)kSecReturnAttributes] boolValue];
    BOOL all = [q[(__bridge id)kSecMatchLimit] isEqual:(__bridge id)kSecMatchLimitAll];

    // 匹配条件：account 是我们的，或（service 是我们的且 account 没指定）
    BOOL match = AccIsOurs(acc);
    if (!match && [acc isKindOfClass:[NSString class]]) match = NO;
    if (!match && ![acc isKindOfClass:[NSString class]] && [svc isKindOfClass:[NSString class]]) {
        match = [svc isEqualToString:kSvcA] || [svc isEqualToString:kSvcB];
    }
    // account 为 nil 且 service 为 nil：全量枚举，交给下面
    BOOL enumerateAll = all && ![acc isKindOfClass:[NSString class]];

    if (match && !all) {
        g_hits++;
        if (result && wantData) { *result = CFBridgingRetain(g_payload); return errSecSuccess; }
        if (result && wantAttrs) {
            NSDictionary *attrs = @{
                (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
                (__bridge id)kSecAttrService: svc ?: kSvcA,
                (__bridge id)kSecAttrAccount: acc ?: kAccV,
            };
            *result = CFBridgingRetain(attrs);
            return errSecSuccess;
        }
    }

    // 全量枚举：先拿原始结果，再替换掉我们那条
    OSStatus st = g_origCopy ? g_origCopy(query, result) : (OSStatus)errSecItemNotFound;

    if (enumerateAll) {
        g_hits++;
        NSMutableArray *out = [NSMutableArray array];
        if (st == errSecSuccess && result && *result) {
            NSArray *arr = (__bridge_transfer NSArray *)*result;
            *result = NULL;
            if ([arr isKindOfClass:[NSArray class]]) {
                for (NSDictionary *it in arr) {
                    NSString *a = it[(__bridge id)kSecAttrAccount];
                    NSString *s = it[(__bridge id)kSecAttrService];
                    if ([a isEqualToString:kAccV]) continue;   // 干掉旧的
                    [out addObject:it];
                }
            }
        }
        // 塞入我们的（三条 service 都放，任 app 挑）
        for (NSString *s in @[kSvcA, kSvcB]) {
            [out addObject:ItemDict(s, kAccV, g_payload)];
        }
        if (result) *result = CFBridgingRetain(out);
        MBLog([NSString stringWithFormat:@"CopyMatching(All) -> 返回 %lu 项（含伪造）",
               (unsigned long)out.count]);
        return errSecSuccess;
    }

    return st;
}

static OSStatus MB_Add(CFDictionaryRef attrs, CFTypeRef *out) {
    OSStatus st = g_origAdd ? g_origAdd(attrs, out) : (OSStatus)errSecParam;
    if (attrs) {
        NSDictionary *d = (__bridge NSDictionary *)attrs;
        NSString *a = d[(__bridge id)kSecAttrAccount];
        if (AccIsOurs(a)) {
            MBLog(@"Add 动了会员项 -> 覆盖回伪造");
            WriteAll();
        }
    }
    return st;
}

static OSStatus MB_Update(CFDictionaryRef q, CFDictionaryRef attrs) {
    NSDictionary *qd = (__bridge NSDictionary *)q;
    if (qd && AccIsOurs(qd[(__bridge id)kSecAttrAccount])) {
        MBLog(@"Update 被拦截（保护伪造数据）");
        WriteAll();
        return errSecSuccess;
    }
    return g_origUpd ? g_origUpd(q, attrs) : (OSStatus)errSecParam;
}

static OSStatus MB_Delete(CFDictionaryRef q) {
    NSDictionary *qd = (__bridge NSDictionary *)q;
    if (qd && AccIsOurs(qd[(__bridge id)kSecAttrAccount])) {
        MBLog(@"Delete 被拦截");
        return errSecSuccess;
    }
    return g_origDel ? g_origDel(q) : (OSStatus)errSecParam;
}

#pragma mark - GOT patch

static void PatchGOT(const char *sym, void *repl, void **origOut) {
    void *real = dlsym(RTLD_DEFAULT, sym);
    if (!real) { MBLog([NSString stringWithFormat:@"dlsym(%s) 失败", sym]); return; }
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
    MBLog([NSString stringWithFormat:@"patch %s: %d 处", sym, n]);
}

#pragma mark - alert

static UIWindow *KW(void) {
    UIWindow *fb = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)sc).windows) {
                if (w.isKeyWindow) return w;
                if (!fb) fb = w;
            }
        }
    }
    return fb;
}

static void Show(int n) {
    @try {
        UIWindow *w = KW();
        UIViewController *vc = w.rootViewController;
        if (!vc) {
            if (n < 20)
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)NSEC_PER_SEC),
                               dispatch_get_main_queue(), ^{ Show(n + 1); });
            return;
        }
        while (vc.presentedViewController) vc = vc.presentedViewController;
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"MemberBypass v8"
                                                                   message:[g_lines componentsJoinedByString:@"\n"]
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [vc presentViewController:ac animated:YES completion:nil];
    } @catch (NSException *e) {}
}

#pragma mark - init

static void MBInitOnce(void) {
    if (g_done) return;
    g_done = YES;
    g_lines = [NSMutableArray array];

    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (dir) {
        NSString *p = [dir stringByAppendingPathComponent:@"mb8.log"];
        g_log = fopen(p.UTF8String, "a");
    }

    ADD(@"v8 键名模式: %s", VIPKEY_UNDERSCORE ? "下划线(_isVIP)" : "驼峰(isVIP)");
    g_payload = BuildPayload();
    MBLog([NSString stringWithFormat:@"payload = %@",
           [[NSString alloc] initWithData:g_payload encoding:NSUTF8StringEncoding]]);

    // 先装 hook，再写，避免写入被自己拦
    PatchGOT("SecItemCopyMatching", (void *)MB_Copy, (void **)&g_origCopy);
    if (!g_origCopy) g_origCopy = (CopyFn)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
    PatchGOT("SecItemAdd", (void *)MB_Add, (void **)&g_origAdd);
    if (!g_origAdd) g_origAdd = (AddFn)dlsym(RTLD_DEFAULT, "SecItemAdd");
    PatchGOT("SecItemUpdate", (void *)MB_Update, (void **)&g_origUpd);
    if (!g_origUpd) g_origUpd = (UpdFn)dlsym(RTLD_DEFAULT, "SecItemUpdate");
    PatchGOT("SecItemDelete", (void *)MB_Delete, (void **)&g_origDel);
    if (!g_origDel) g_origDel = (DelFn)dlsym(RTLD_DEFAULT, "SecItemDelete");

    WriteAll();
    ADD(@"写入完成");

    // 3 秒后再写一次（防止启动期被清），然后弹窗
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        WriteAll();
        ADD(@"二次写入完成, Copy 命中=%d", g_hits);
        Show(0);
    });
}

__attribute__((used, visibility("default")))
void MBInit(void) { MBInitOnce(); }

__attribute__((objc_root_class))
@interface MBLoader8
@end

@implementation MBLoader8
+ (void)load { MBInitOnce(); }
@end
