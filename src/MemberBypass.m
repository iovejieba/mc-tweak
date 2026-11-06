// MemberBypass.m v2 — 带自检日志 + 键名超集
//
// v1 为什么可能无效：
//  1) ld64.lld 生成的 __init_offsets 未必被 dyld 当成初始化表 → MBInit 没跑
//     → 本版改为 ObjC +load（运行时必定调用）+ __mod_init_func 双保险
//  2) MemberObj 的字段名带下划线（_isVIP/_expireAt/_VIPType…），Codable 键可能是
//     _isVIP 而不是 isVIP → 本版把两套命名一起塞进 JSON（JSONDecoder 忽略未知键）
//  3) 自签下 keychain 常报 -34018 → 本版把 SecItemAdd 的返回码写进日志

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <dlfcn.h>
#include <stdio.h>
#include <string.h>

// 2286-11-21 UTC，2001 纪元秒
static const double kExpire = 9021715200.0;
// VIPType 取值（Int 背书的 enum，先试 2）
static const int    kVIPInt = 2;

static NSString *const kSvc = @"rainy.lyn.mangaCapsule";
static NSString *const kAcc = @"validTransaction";

static BOOL  g_done = NO;
static FILE *g_log  = NULL;
static NSData *g_payload = nil;

#pragma mark - 日志

static void MBOpenLog(void) {
    if (g_log) return;
    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];
    NSString *p = [dir stringByAppendingPathComponent:@"mb.log"];
    g_log = fopen(p.UTF8String, "a");
    if (g_log) {
        fprintf(g_log, "\n===== MemberBypass v2 start (pid %d) =====\n", getpid());
        fflush(g_log);
    }
}

static void MBLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[MB] %@", s);
    if (g_log) {
        fprintf(g_log, "%s\n", s.UTF8String);
        fflush(g_log);
    }
}

#pragma mark - payload（键名超集）

static NSData *BuildPayload(void) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];

    // id
    d[@"id"]     = @"local";
    d[@"ID"]     = @1;

    // isVIP：三种可能命名
    d[@"isVIP"]  = @YES;
    d[@"_isVIP"] = @YES;
    d[@"isVip"]  = @YES;
    d[@"isMember"] = @YES;

    // expireAt
    d[@"expireAt"]  = @(kExpire);
    d[@"_expireAt"] = @(kExpire);
    d[@"ExpireAt"]  = @(kExpire);
    d[@"vipExpireAt"] = @(kExpire);

    // VIPType：两套命名都给 Int，避免 String/Int 冲突
    d[@"VIPType"]  = @(kVIPInt);
    d[@"_VIPType"] = @(kVIPInt);
    d[@"vipType"]  = @(kVIPInt);
    d[@"productType"] = @(kVIPInt);

    // 其余字段
    d[@"hasGifted"]             = @NO;
    d[@"_hasGifted"]            = @NO;
    d[@"shouldRefreshProducts"]  = @NO;
    d[@"_shouldRefreshProducts"] = @NO;
    d[@"weeklyReadNum"]  = @0;
    d[@"_weeklyReadNum"] = @0;

    NSError *err = nil;
    NSData *out = [NSJSONSerialization dataWithJSONObject:d options:0 error:&err];
    if (err) MBLog(@"payload build err: %@", err);
    return out;
}

#pragma mark - keychain 读写

static NSDictionary *BaseQuery(void) {
    return @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kSvc,
        (__bridge id)kSecAttrAccount: kAcc,
    };
}

static OSStatus WriteKeychain(NSData *payload) {
    NSDictionary *q = BaseQuery();
    OSStatus delSt = SecItemDelete((__bridge CFDictionaryRef)q);

    NSMutableDictionary *add = [q mutableCopy];
    add[(__bridge id)kSecValueData]          = payload;
    add[(__bridge id)kSecAttrAccessible]     = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    add[(__bridge id)kSecAttrSynchronizable] = @NO;
    OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);

    MBLog(@"keychain: delete=%d add=%d len=%lu", (int)delSt, (int)st,
          (unsigned long)payload.length);
    if (st == -34018) {
        MBLog(@"keychain -34018 = 缺 keychain-access-groups entitlement，改走 hook 路径");
    }
    return st;
}

// 把当前 keychain 里这条记录读出来（不经过我们的 hook）
static void DumpKeychain(void) {
    NSMutableDictionary *q = [BaseQuery() mutableCopy];
    q[(__bridge id)kSecReturnData]       = @YES;
    q[(__bridge id)kSecMatchLimit]       = (__bridge id)kSecMatchLimitOne;
    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st == errSecSuccess && out) {
        NSData *d = (__bridge_transfer NSData *)out;
        NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        MBLog(@"keychain 现有值(%lu B): %@", (unsigned long)d.length,
              s.length ? s : @"<非UTF8，可能是 NSKeyedArchiver>");
        if (!s.length) {
            MBLog(@"  头 32 字节: %@", [d subdataWithRange:NSMakeRange(0, MIN(32u, (unsigned)d.length))]);
        }
    } else {
        MBLog(@"keychain 当前无值 (status=%d)", (int)st);
    }
}

#pragma mark - hook

typedef OSStatus (*CopyMatchingFn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*AddFn)(CFDictionaryRef, CFTypeRef *);

static CopyMatchingFn g_origCopy = NULL;
static AddFn           g_origAdd  = NULL;

static BOOL QueryIsOurs(CFDictionaryRef q) {
    if (!q) return NO;
    NSDictionary *d = (__bridge NSDictionary *)q;
    id acc = d[(__bridge id)kSecAttrAccount];
    if (![acc isKindOfClass:[NSString class]] || ![acc isEqualToString:kAcc]) return NO;
    id svc = d[(__bridge id)kSecAttrService];
    if (svc == nil) return YES;
    if (![svc isKindOfClass:[NSString class]]) return NO;
    return [svc isEqualToString:kSvc];
}

static OSStatus MB_CopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    NSDictionary *qd = (__bridge NSDictionary *)query;
    BOOL ours = QueryIsOurs(query);
    BOOL wantData  = [qd[(__bridge id)kSecReturnData] boolValue];
    BOOL wantAttrs = [qd[(__bridge id)kSecReturnAttributes] boolValue];
    id limit = qd[(__bridge id)kSecMatchLimit];
    BOOL all = [limit isEqual:(__bridge id)kSecMatchLimitAll];

    if (ours && !all) {
        MBLog(@"hit CopyMatching (data=%d attrs=%d) -> 返回伪造值", wantData, wantAttrs);
        if (wantAttrs && !wantData) {
            return g_origCopy ? g_origCopy(query, result) : (OSStatus)errSecItemNotFound;
        }
        if (result && g_payload) {
            *result = CFBridgingRetain(g_payload);
        }
        return errSecSuccess;
    }

    if (ours && all) {
        MBLog(@"hit CopyMatching with MatchLimitAll，放行原逻辑");
    }
    if (g_origCopy) return g_origCopy(query, result);
    return (OSStatus)errSecItemNotFound;
}

static OSStatus MB_Add(CFDictionaryRef attrs, CFTypeRef *out) {
    OSStatus st = g_origAdd ? g_origAdd(attrs, out) : (OSStatus)errSecParam;
    if (attrs) {
        NSDictionary *d = (__bridge NSDictionary *)attrs;
        id acc = d[(__bridge id)kSecAttrAccount];
        if ([acc isKindOfClass:[NSString class]] && [acc isEqualToString:kAcc]) {
            MBLog(@"SecItemAdd 动了我们的 key (st=%d) -> 回写", (int)st);
            WriteKeychain(g_payload);
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
        BOOL isApp = strstr(img, "mangaCapsule") != NULL;
        BOOL isSelf = strstr(img, "MemberBypass") != NULL;
        if (!isApp && !isSelf) continue;

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
                            kern_return_t kr = vm_protect(mach_task_self(),
                                                          (vm_address_t)&slots[k],
                                                          sizeof(void *), false,
                                                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                            if (kr != KERN_SUCCESS) { MBLog(@"vm_protect 失败 %d", kr); continue; }
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
    MBLog(@"===== MBInit 进入（说明 dylib 已加载且初始化被调用）=====");
    MBLog(@"bundle=%@ ver=%@", [[NSBundle mainBundle] bundleIdentifier],
          [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"]);

    g_payload = BuildPayload();
    if (!g_payload) { MBLog(@"payload 构建失败"); return; }
    MBLog(@"payload = %@", [[NSString alloc] initWithData:g_payload encoding:NSUTF8StringEncoding]);

    // 先看原始状态，便于对比
    DumpKeychain();

    // 1) 直接写
    WriteKeychain(g_payload);
    DumpKeychain();

    // 2) hook 读
    PatchGOT("SecItemCopyMatching", (void *)MB_CopyMatching, (void **)&g_origCopy);
    if (!g_origCopy) g_origCopy = (CopyMatchingFn)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");

    // 3) hook 写
    PatchGOT("SecItemAdd", (void *)MB_Add, (void **)&g_origAdd);
    if (!g_origAdd) g_origAdd = (AddFn)dlsym(RTLD_DEFAULT, "SecItemAdd");

    MBLog(@"origCopy=%p origAdd=%p —— init 完成", g_origCopy, g_origAdd);
}

// 双保险 1：显式导出，供 __mod_init_func 用
__attribute__((used, visibility("default")))
void MBInit(void) { MBInitOnce(); }

// 双保险 2：ObjC +load —— 镜像加载后运行时必定调用，不依赖 __mod_init_func
__attribute__((objc_root_class))
@interface MBLoader
@end

@implementation MBLoader
+ (void)load { MBInitOnce(); }
@end
