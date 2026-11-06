// MemberBypass.dylib — rainy.heichai.mangaCapsule3 (v1.46) 本地会员激活
//
// 逆向结论（证据见 README.md）：
//   MemberService 是 Swift 类（非 @objc），ivar 布局：
//     +0x10 keyChainKey    = "rainy.lyn.mangaCapsule"
//     +0x20 transactionKey = "validTransaction"
//   读取链路：
//     SecItemCopyMatching({class:genp, svc:"rainy.lyn.mangaCapsule", acct:"validTransaction"})
//       -> NSData -> JSONDecoder().decode(MemberObj.self, from:)
//   MemberObj 的 Codable 键（__swift5_reflstr 顺序一致）：
//     id, isVIP, expireAt, VIPType, hasGifted, shouldRefreshProducts, weeklyReadNum
//   expireAt 为 Date（2001 纪元秒 Double）。
//
// 三层保险，任一生效即可：
//   1. constructor 里直接写 Keychain（正常签名首选）
//   2. hook SecItemCopyMatching，命中该项返回伪造 Data（应对自签下 keychain 报 -34018）
//   3. hook SecItemAdd，检测到写我们这条记录就立刻回写，防 StoreKit 真实结果覆盖
//
// 编译：arm64-apple-ios16.0，需链接 Foundation + Security

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <string.h>

#pragma mark - 参数

static const double  kExpireSeconds = 9021715200.0;   // 2286-11-21 UTC
static NSString *const kSvc = @"rainy.lyn.mangaCapsule";
static NSString *const kAcc = @"validTransaction";

static BOOL gDebug = YES;
#define MBLog(fmt, ...) do { if (gDebug) NSLog(@"[MB] " fmt, ##__VA_ARGS__); } while (0)

#pragma mark - 伪造 payload

// VIPType 是 Swift enum（无 @objc），JSON 里可能是 Int rawValue 或 String case 名。
// 这是唯一无法纯静态敲定的点：三个候选，改 kVIPVariant 实测哪个能进会员页。
static int kVIPVariant = 0;   // 0 -> Int 2 | 1 -> Int 0 | 2 -> "yearly"

static NSData *BuildPayload(void) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    d[@"id"]                    = @"local";
    d[@"isVIP"]                 = @YES;
    d[@"expireAt"]              = @(kExpireSeconds);
    d[@"hasGifted"]             = @YES;
    d[@"shouldRefreshProducts"] = @NO;
    d[@"weeklyReadNum"]         = @0;
    switch (kVIPVariant) {
        case 1:  d[@"VIPType"] = @0;        break;
        case 2:  d[@"VIPType"] = @"yearly"; break;
        default: d[@"VIPType"] = @2;        break;
    }
    return [NSJSONSerialization dataWithJSONObject:d options:0 error:nil];
}

#pragma mark - Keychain

static NSDictionary *BaseQuery(void) {
    return @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kSvc,
        (__bridge id)kSecAttrAccount: kAcc,
    };
}

static OSStatus WriteKeychain(NSData *payload) {
    NSDictionary *q = BaseQuery();
    SecItemDelete((__bridge CFDictionaryRef)q);

    NSMutableDictionary *add = [q mutableCopy];
    add[(__bridge id)kSecValueData]           = payload;
    add[(__bridge id)kSecAttrAccessible]      = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    add[(__bridge id)kSecAttrSynchronizable]  = @NO;
    OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    MBLog(@"keychain write status=%d len=%lu", (int)st, (unsigned long)payload.length);
    return st;
}

#pragma mark - 函数指针

typedef OSStatus (*CopyMatchingFn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*AddFn)(CFDictionaryRef, CFTypeRef *);

static CopyMatchingFn g_origCopyMatching = NULL;
static AddFn           g_origAdd          = NULL;
static NSData         *g_payload          = NULL;

#pragma mark - SecItemCopyMatching hook

static BOOL QueryIsOurs(CFDictionaryRef q) {
    if (!q) return NO;
    NSDictionary *d = (__bridge NSDictionary *)q;
    id acc = d[(__bridge id)kSecAttrAccount];
    if (![acc isKindOfClass:[NSString class]] || ![acc isEqualToString:kAcc]) return NO;
    id svc = d[(__bridge id)kSecAttrService];
    if (svc == nil) return YES;                        // service 未限定也拦
    if (![svc isKindOfClass:[NSString class]]) return NO;
    return [svc isEqualToString:kSvc];
}

static OSStatus MB_CopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    if (QueryIsOurs(query) && g_payload) {
        NSDictionary *d = (__bridge NSDictionary *)query;
        BOOL wantData  = [d[(__bridge id)kSecReturnData] boolValue];
        BOOL wantAttrs = [d[(__bridge id)kSecReturnAttributes] boolValue];
        MBLog(@"CopyMatching HIT data=%d attrs=%d", wantData, wantAttrs);

        if (wantAttrs && !wantData) {                  // 只要属性，交回系统
            return g_origCopyMatching ? g_origCopyMatching(query, result)
                                      : (OSStatus)errSecItemNotFound;
        }
        if (result) *result = CFBridgingRetain(g_payload);
        return errSecSuccess;
    }
    if (g_origCopyMatching) return g_origCopyMatching(query, result);
    return (OSStatus)errSecItemNotFound;
}

#pragma mark - SecItemAdd hook

static OSStatus MB_Add(CFDictionaryRef attrs, CFTypeRef *out) {
    if (!g_origAdd) return (OSStatus)errSecParam;
    CFTypeRef dummy = NULL;
    OSStatus st = g_origAdd(attrs, out ? out : &dummy);

    if (g_payload && attrs) {
        NSDictionary *d = (__bridge NSDictionary *)attrs;
        id acc = d[(__bridge id)kSecAttrAccount];
        if ([acc isKindOfClass:[NSString class]] && [acc isEqualToString:kAcc]) {
            MBLog(@"SecItemAdd touched our key (st=%d) -> rewrite", (int)st);
            WriteKeychain(g_payload);
        }
    }
    return st;
}

#pragma mark - GOT patch（chained fixups 兼容）

static void PatchGOT(const char *sym, void *replacement, void **origOut) {
    void *real = dlsym(RTLD_DEFAULT, sym);
    if (!real) { MBLog(@"dlsym(%s) failed", sym); return; }

    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *h =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        const char *img = _dyld_get_image_name(i);
        if (!img || !strstr(img, "mangaCapsule")) continue;

        const struct load_command *lc =
            (const struct load_command *)((const char *)h + sizeof(struct mach_header_64));
        for (uint32_t c = 0; c < h->ncmds; c++) {
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (strcmp(seg->segname, "__DATA_CONST") != 0 &&
                    strcmp(seg->segname, "__DATA") != 0) {
                    lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
                    continue;
                }
                const struct section_64 *s =
                    (const struct section_64 *)((const char *)seg + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++, s++) {
                    if (strcmp(s->sectname, "__got") &&
                        strcmp(s->sectname, "__auth_got") &&
                        strcmp(s->sectname, "__la_symbol_ptr")) {
                        continue;
                    }
                    void **slots = (void **)((char *)h + s->offset);
                    uint32_t n = s->size / sizeof(void *);
                    for (uint32_t k = 0; k < n; k++) {
                        if (slots[k] != real) continue;
                        kern_return_t kr = vm_protect(mach_task_self(),
                                                      (vm_address_t)&slots[k],
                                                      sizeof(void *), false,
                                                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                        if (kr != KERN_SUCCESS) {
                            MBLog(@"vm_protect fail %d (%s)", kr, sym);
                            continue;
                        }
                        if (origOut && !*origOut) *origOut = slots[k];
                        slots[k] = replacement;
                        MBLog(@"patched %s @ %s slot %u", sym, s->sectname, k);
                    }
                }
            }
            lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
        }
    }
}

#pragma mark - entry

__attribute__((constructor))
static void MBInit(void) {
    @autoreleasepool {
        g_payload = BuildPayload();
        if (!g_payload) return;
        MBLog(@"payload = %@",
              [[NSString alloc] initWithData:g_payload encoding:NSUTF8StringEncoding]);

        // 1) 直接写
        WriteKeychain(g_payload);

        // 2) hook 读
        PatchGOT("SecItemCopyMatching", (void *)MB_CopyMatching, (void **)&g_origCopyMatching);
        if (!g_origCopyMatching) {
            g_origCopyMatching = (CopyMatchingFn)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
        }

        // 3) hook 写
        PatchGOT("SecItemAdd", (void *)MB_Add, (void **)&g_origAdd);
        if (!g_origAdd) {
            g_origAdd = (AddFn)dlsym(RTLD_DEFAULT, "SecItemAdd");
        }

        MBLog(@"init done. origCopy=%p origAdd=%p", g_origCopyMatching, g_origAdd);
    }
}
