// Tracer.m v2 — 安全取证版
//
// v1 闪退原因：vm_region_64 传 info=NULL 但要求 VM_REGION_BASIC_INFO_64，
//             系统会写 struct vm_region_basic_info_data_64_t -> 空指针崩溃。
// v2：用 vm_region_recurse_64（info 传 uint32 array），并全程 @try 保护。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#include <string.h>

static NSMutableArray<NSString *> *g_lines = nil;
static BOOL g_done = NO;
static int g_udCount = 0;

#define ADD(fmt, ...) [g_lines addObject:[NSString stringWithFormat:(fmt), ##__VA_ARGS__]]

static void SafeDump(void) {
    @try {
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                             NSUserDomainMask, YES) firstObject];
        if (!dir) return;
        NSString *p = [dir stringByAppendingPathComponent:@"trace.log"];
        NSString *s = [g_lines componentsJoinedByString:@"\n"];
        [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSLog(@"[TR] log -> %@", p);
    } @catch (NSException *e) {
        NSLog(@"[TR] dump fail %@", e);
    }
}

#pragma mark - NSUserDefaults hook

static void HookUserDefaults(void) {
    @try {
        Class UD = objc_getClass("NSUserDefaults");
        if (!UD) { ADD(@"NSUserDefaults 不存在"); return; }

        NSArray *sels = @[@"objectForKey:", @"stringForKey:", @"boolForKey:",
                          @"integerForKey:", @"doubleForKey:"];
        int hooked = 0;
        for (NSString *sn in sels) {
            SEL sel = NSSelectorFromString(sn);
            Method m = class_getInstanceMethod(UD, sel);
            if (!m) continue;
            IMP orig = method_getImplementation(m);
            __block IMP o = orig;
            NSString *name = sn;
            IMP repl = imp_implementationWithBlock(^id(id self_, NSString *key) {
                id r = nil;
                @try {
                    r = ((id(*)(id, SEL, id))o)(self_, NSSelectorFromString(name), key);
                } @catch (NSException *e) { return nil; }
                @try {
                    if (g_udCount < 200) {
                        g_udCount++;
                        NSString *rs;
                        if ([r isKindOfClass:[NSString class]]) rs = r;
                        else if ([r isKindOfClass:[NSNumber class]]) rs = [r stringValue];
                        else if (!r) rs = @"nil";
                        else rs = NSStringFromClass([r class]);
                        if (rs.length > 50) rs = [rs substringToIndex:50];
                        ADD(@"UD[%@] = %@", key, rs);
                    }
                } @catch (NSException *e) {}
                return r;
            });
            method_setImplementation(m, repl);
            hooked++;
        }
        ADD(@"NSUserDefaults hook: %d", hooked);
    } @catch (NSException *e) {
        ADD(@"hook 异常: %@", e);
    }
}

#pragma mark - 安全内存扫描

static void ScanMemberObj(void) {
    @try {
        intptr_t slide = 0;
        const char *matched = NULL;
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            const char *n = _dyld_get_image_name(i);
            if (n && strstr(n, "mangaCapsule")) {
                slide = _dyld_get_image_vmaddr_slide(i);
                matched = n;
                break;
            }
        }
        ADD(@"镜像: %s slide=%p", matched ? matched : "?", (void *)slide);

        uintptr_t isa = (uintptr_t)(0x100b60344ULL + slide);
        ADD(@"MemberObj isa = %p", (void *)isa);

        vm_address_t addr = 0;
        int found = 0, regions = 0;
        int checked = 0;

        while (regions < 4000) {
            vm_size_t size = 0;
            vm_region_submap_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
            kern_return_t kr = vm_region_recurse_64(mach_task_self(), &addr, &size,
                                                    (natural_t *)&cnt,
                                                    (vm_region_recurse_info_t)&info);
            if (kr != KERN_SUCCESS) break;
            regions++;

            if (info.is_submap || size == 0) {
                addr += (size ? size : 0x1000);
                continue;
            }
            // 只扫可读写的数据区
            if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) !=
                (VM_PROT_READ | VM_PROT_WRITE) || size > (64u << 20)) {
                addr += size;
                continue;
            }

            uintptr_t *p = (uintptr_t *)addr;
            size_t n = size / sizeof(uintptr_t);
            for (size_t i = 0; i < n; i += 2) {
                checked++;
                if (p[i] != isa) continue;
                uint8_t *obj = (uint8_t *)(p + i);
                uint8_t v;
                @try { v = obj[0x18]; } @catch (NSException *e) { continue; }
                if (v > 1) continue;
                found++;
                if (found <= 8) {
                    uint8_t vt = 0;
                    uint64_t wk = 0;
                    @try { vt = obj[0x28]; wk = *(uint64_t *)(obj + 0x40); } @catch (NSException *e) {}
                    ADD(@"  #%d @%p isVIP=%u VIPType=%u weekly=%llu",
                        found, obj, v, vt, wk);
                }
            }
            addr += size;
        }
        ADD(@"扫描完成 regions=%d checked=%d found=%d", regions, checked, found);
    } @catch (NSException *e) {
        ADD(@"扫描异常: %@", e);
    }
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

static void Show(int attempt) {
    @try {
        UIWindow *w = KW();
        UIViewController *vc = w.rootViewController;
        if (!vc) {
            if (attempt < 20)
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ Show(attempt + 1); });
            return;
        }
        while (vc.presentedViewController) vc = vc.presentedViewController;
        NSString *msg = [g_lines componentsJoinedByString:@"\n"];
        if (msg.length > 3000) msg = [msg substringToIndex:3000];
        UIAlertController *ac =
            [UIAlertController alertControllerWithTitle:@"Tracer v2"
                                                message:msg
                                         preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"知道了"
                                              style:UIAlertActionStyleDefault handler:nil]];
        [vc presentViewController:ac animated:YES completion:nil];
    } @catch (NSException *e) {
        NSLog(@"[TR] show fail %@", e);
    }
}

__attribute__((constructor))
static void TracerInit(void) {
    if (g_done) return;
    g_done = YES;
    @try {
        g_lines = [NSMutableArray array];
        ADD(@"Tracer v2 已加载 %s %s", __DATE__, __TIME__);
        ADD(@"模式: 仅 UD hook（内存扫描已禁用）");
        SafeDump();   // 先落一次，保证有文件

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            HookUserDefaults();
            SafeDump();
        });

        // 内存扫描风险高（可能触发 EXC_BAD_ACCESS），默认关闭
        // 如需开启把下面注释解开
        // dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),
        //                dispatch_get_main_queue(), ^{
        //     ScanMemberObj();
        //     SafeDump();
        // });

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ Show(0); });
    } @catch (NSException *e) {
        NSLog(@"[TR] init fail %@", e);
    }
}
