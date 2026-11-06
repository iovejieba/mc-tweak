// Probe2.m — 只读取证：枚举全部 Keychain 项 + UserDefaults
// 不做任何写入。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>

static NSMutableArray<NSString *> *L = nil;
static BOOL g_done = NO;
#define ADD(fmt, ...) [L addObject:[NSString stringWithFormat:(fmt), ##__VA_ARGS__]]

static void Dump(void) {
    @try {
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                             NSUserDomainMask, YES) firstObject];
        if (!dir) return;
        [[L componentsJoinedByString:@"\n"]
            writeToFile:[dir stringByAppendingPathComponent:@"probe.log"]
             atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (NSException *e) {}
}

static NSString *Hex(NSData *d, NSUInteger maxBytes) {
    NSUInteger n = MIN(d.length, maxBytes);
    const uint8_t *p = d.bytes;
    NSMutableString *s = [NSMutableString string];
    for (NSUInteger i = 0; i < n; i++) {
        [s appendFormat:@"%02x", p[i]];
        if (i % 40 == 39) [s appendString:@"\n    "];
    }
    if (d.length > maxBytes) [s appendFormat:@" ...(共%lu)", (unsigned long)d.length];
    return s;
}

static NSString *GuessFormat(NSData *d) {
    if (!d.length) return @"空";
    const uint8_t *b = d.bytes;
    if (d.length >= 8 && memcmp(b, "bplist00", 8) == 0) return @"BINARY-PLIST";
    if (b[0] == '{' || b[0] == '[') return @"JSON";
    if (d.length >= 4 && memcmp(b, "{\\rtf", 4) == 0) return @"RTF";
    return @"未知/NSKeyedArchiver";
}

/// 枚举全部 generic-password 项
static void DumpAllKeychain(void) {
    NSDictionary *q = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
    };
    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    ADD(@"SecItemCopyMatching(All) status=%d", (int)st);
    if (st != errSecSuccess || !out) return;

    NSArray *items = (__bridge_transfer NSArray *)out;
    ADD(@"Keychain 中共 %lu 项", (unsigned long)items.count);

    int i = 0;
    for (NSDictionary *it in items) {
        i++;
        NSString *svc = it[(__bridge id)kSecAttrService];
        NSString *acc = it[(__bridge id)kSecAttrAccount];
        NSData *d = it[(__bridge id)kSecValueData];
        ADD(@"");
        ADD(@"[%d] service=%@  account=%@", i, svc ?: @"(nil)", acc ?: @"(nil)");
        ADD(@"    长度=%lu  格式=%@", (unsigned long)d.length, GuessFormat(d));
        ADD(@"    hex: %@", Hex(d, 120));
        NSString *u = d.length ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
        if (u) ADD(@"    str: %@", [u substringToIndex:MIN((NSUInteger)180, u.length)]);
    }
}

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
        NSString *m = [L componentsJoinedByString:@"\n"];
        if (m.length > 2800) m = [m substringToIndex:2800];
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"Probe2 只读"
                                                                   message:m
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [vc presentViewController:ac animated:YES completion:nil];
    } @catch (NSException *e) {}
}

__attribute__((constructor))
static void ProbeInit(void) {
    if (g_done) return;
    g_done = YES;
    L = [NSMutableArray array];
    ADD(@"Probe2 只读 %s", __DATE__);

    @try {
        DumpAllKeychain();

        ADD(@"");
        ADD(@"=== UserDefaults ===");
        NSDictionary *ud = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        ADD(@"共 %lu 项", (unsigned long)ud.count);
        NSArray *keys = [[ud allKeys] sortedArrayUsingSelector:@selector(compare:)];
        int n = 0;
        for (NSString *k in keys) {
            if (n++ >= 40) { ADD(@"  ...(截断，完整见 probe.log)"); break; }
            NSString *vs = [ud[k] description];
            if (vs.length > 60) vs = [vs substringToIndex:60];
            ADD(@"  %@ = %@", k, vs);
        }
    } @catch (NSException *e) {
        ADD(@"异常: %@", e);
    }

    Dump();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ Show(0); });
}
