// MemberBypass.m v3 — 诊断优先
//
// v1/v2 都无效，说明我对 keychain 键名的假设可能是错的。
// v3 策略：不再猜，先把 app 实际调用的 keychain 查询全部记下来，
//          命中我们的 key 再返回伪造值，同时写入磁盘日志方便导出。
//
// 日志位置：<App沙盒>/Documents/mb.log
// 越狱机路径：/var/mobile/Containers/Data/Application/<UUID>/Documents/mb.log

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const double kExpire = 9021715200.0;   // 2286-11-21 UTC
static const int    kVIPInt = 2;

static BOOL    g_done = NO;
static FILE   *g_log  = NULL;
static NSData *g_payload = nil;
static int     g_queries = 0;

#pragma mark - 日志

static void MBOpenLog(void) {
    if (g_log) return;
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                         NSUserDomainMask, YES) firstObject];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *p = [dir stringByAppendingPathComponent:@"mb.log"];
    g_log = fopen(p.UTF8String, "a");
    if (g_log) {
        fprintf(g_log, "\n===== MemberBypass v3 (pid %d) =====\n", getpid());
        fflush(g_log);
    }
}

static void MBLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[MB] %@", s);
    if (g_log) { fprintf(g_log, "%s\n", s.UTF8String); fflush(g_log); }
}

// 把一个 CFDictionary 查询压成一行可读文本
static NSString *DescribeQuery(CFDictionaryRef q) {
    if (!q) return @"<nil>";
    NSDictionary *d = (__bridge NSDictionary *)q;
    NSMutableArray *parts = [NSMutableArray array];
    for (id k in d) {
        NSString *key = [k description];
        NSString *shortKey = key;
        // 只保留可读部分：kSecAttrService -> svce 之类
        if ([key hasPrefix:@"kSec"]) shortKey = [key substringFromIndex:4];
        id v = d[k];
        NSString *vs;
        if ([v isKindOfClass:[NSData class]]) {
            vs = [NSString stringWithFormat:@"<Data %luB>", (unsigned long)[v length]];
        } else if ([v isKindOfClass:[NSString class]]) {
            vs = v;
        } else {
            vs = [v description];
        }
        [parts addObject:[NSString stringWithFormat:@"%@=%@", shortKey, vs]];
    }
    return [parts componentsJoinedByString:@", "];
}

#pragma mark - payload

static NSData *BuildPayload(void) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    d[@"id"]     = @"local";
    d[@"ID"]     = @1;
    d[@"isVIP"]  = @YES;
    d[@"_isVIP"] = @YES;
    d[@"isVip"]  = @YES;
    d[@"isMember"] = @YES;
    d[@"expireAt"]   = @(kExpire);
    d[@"_expireAt"]  = @(kExpire);
    d[@"ExpireAt"]   = @(kExpire);
    d[@"VIPType"]    = @(kVIPInt);
    d[@"_VIPType"]   = @(kVIPInt);
    d[@"vipType"]    = @(kVIPInt);
    d[@"hasGifted"]             = @NO;
    d[@"_hasGifted"]            = @NO;
    d[@"shouldRefreshProducts"]  = @NO;
    d[@"_shouldRefreshProducts"] = @NO;
    d[@"weeklyReadNum"]  = @0;
    d[@"_weeklyReadNum"] = @0;
    return [NSJSONSerialization dataWithJSONObject:d options:0 error:nil];
}

#pragma mark - 动态决定 target key
// v3 不再硬编码 service/account：拦截所有查询并记录，
// 一旦发现形如 validTransaction / member / vip 的 account，就把它当作目标。

static NSMutableSet<NSString *> *g_seenAccounts = nil;

static BOOL AccountLooksInteresting(NSString *acc) {
    if (!acc) return NO;
    NSString *low = acc.lowercaseString;
    return [low containsString:@"transaction"] ||
           [low containsString:@"member"] ||
           [low containsString:@"vip"] ||
           [low containsString:@"valid"];
}

#pragma mark - hook

typedef OSStatus (*CopyMatchingFn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*AddFn)(CFDictionaryRef, CFTypeRef *);

static CopyMatchingFn g_origCopy = NULL;
static AddFn           g_origAdd  = NULL;

static OSStatus MB_CopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    g_queries++;
    NSDictionary *qd = (__bridge NSDictionary *)query;
    NSString *acc = qd[(__bridge id)kSecAttrAccount];
    NSString *svc = qd[(__bridge id)kSecAttrService];
    BOOL wantData = [qd[(__bridge id)kSecReturnData] boolValue];
    id limit = qd[(__bridge id)kSecMatchLimit];
    BOOL all = [limit isEqual:(__bridge id)kSecMatchLimitAll];

    // 前 200 次全记，避免日志爆掉
    if (g_queries <= 200) {
        MBLog(@"Q#%d %@", g_queries, DescribeQuery(query));
    }

    if ([acc isKindOfClass:[NSString class]]) {
        if (!g_seenAccounts) g_seenAccounts = [NSMutableSet set];
        [g_seenAccounts addObject:acc];
    }

    BOOL target = AccountLooksInteresting(acc) && wantData && !all;

    if (target && g_payload) {
        MBLog(@"** 命中疑似会员项 acc=%@ svc=%@ -> 返回伪造", acc, svc);
        if (result) *result = CFBridgingRetain(g_payload);
        return errSecSuccess;
    }

    OSStatus st = g_origCopy ? g_origCopy(query, result) : (OSStatus)errSecItemNotFound;
    if (target) {
        MBLog(@"   但未命中（st=%d）", (int)st);
    }
    return st;
}

static OSStatus MB_Add(CFDictionaryRef attrs, CFTypeRef *out) {
    OSStatus st = g_origAdd ? g_origAdd(attrs, out) : (OSStatus)errSecParam;
    if (attrs) {
        NSDictionary *d = (__bridge NSDictionary *)attrs;
        NSString *acc = d[(__bridge id)kSecAttrAccount];
        if ([acc isKindOfClass:[NSString class]] && AccountLooksInteresting(acc)) {
            MBLog(@"SecItemAdd 写入 %@ (st=%d)", acc, (int)st);
        }
    }
    return st;
}

#pragma mark - GOT patch

static void PatchGOT(const char *sym, void *repl, void **origOut) {
    void *real = dlsym(RTLD_DEFAULT, sym);
    if (!real) { MBLog(@"dlsym(%s) 失败", sym); return; }

    int patched = 0;
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
                        uint32_t n = s->size / sizeof(void *);
                        for (uint32_t k = 0; k < n; k++) {
                            if (slots[k] != real) continue;
                            if (vm_protect(mach_task_self(), (vm_address_t)&slots[k],
                                           sizeof(void *), false,
                                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
                                continue;
                            if (origOut && !*origOut) *origOut = slots[k];
                            slots[k] = repl;
                            patched++;
                        }
                    }
                }
            }
            lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
        }
    }
    MBLog(@"patch %s: %d 处", sym, patched);
}

#pragma mark - init

static void MBInitOnce(void) {
    if (g_done) return;
    g_done = YES;

    MBOpenLog();
    MBLog(@"===== v3 启动：dylib 已加载，初始化已执行 =====");
    MBLog(@"bundle=%@", [[NSBundle mainBundle] bundleIdentifier]);

    g_payload = BuildPayload();

    // 先装 hook，再写 keychain，这样写入也能被自己看到
    PatchGOT("SecItemCopyMatching", (void *)MB_CopyMatching, (void **)&g_origCopy);
    if (!g_origCopy) g_origCopy = (CopyMatchingFn)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
    PatchGOT("SecItemAdd", (void *)MB_Add, (void **)&g_origAdd);
    if (!g_origAdd) g_origAdd = (AddFn)dlsym(RTLD_DEFAULT, "SecItemAdd");

    // 主动写一份到最常见的两种 service
    NSArray *svcs = @[@"rainy.lyn.mangaCapsule",
                      @"rainy.heichai.mangaCapsule3",
                      [[NSBundle mainBundle] bundleIdentifier]];
    NSArray *accs = @[@"validTransaction"];
    for (NSString *svc in svcs) {
        if (!svc) continue;
        for (NSString *acc in accs) {
            NSDictionary *q = @{
                (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
                (__bridge id)kSecAttrService: svc,
                (__bridge id)kSecAttrAccount: acc,
            };
            SecItemDelete((__bridge CFDictionaryRef)q);
            NSMutableDictionary *add = [q mutableCopy];
            add[(__bridge id)kSecValueData] = g_payload;
            add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
            OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
            MBLog(@"写入 svc=%@ acc=%@ -> %d", svc, acc, (int)st);
        }
    }

    MBLog(@"init 完成，开始观察 app 的 keychain 调用…");
}

__attribute__((used, visibility("default")))
void MBInit(void) { MBInitOnce(); }

__attribute__((objc_root_class))
@interface MBLoader
@end

@implementation MBLoader
+ (void)load { MBInitOnce(); }
@end
