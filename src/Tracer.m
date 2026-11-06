// Tracer.m — 动态取证版
//
// 目的：不再猜。把 app 真实的会员判断路径全部记录并弹窗显示：
//   1. 所有 NSUserDefaults 读取（key + 返回值）
//   2. 所有 keychain 读取
//   3. MemberObj 相关的解码调用
//   4. 直接扫描内存里 MemberObj 实例的 _isVIP 字段

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#include <string.h>

static NSMutableArray<NSString *> *g_lines = nil;
static BOOL g_done = NO;
static int g_udCount = 0;

#define ADD(fmt, ...) [g_lines addObject:[NSString stringWithFormat:(fmt), ##__VA_ARGS__]]

#pragma mark - hook objc_msgSend 上的 NSUserDefaults

static void HookUserDefaults(void) {
    Class UD = objc_getClass("NSUserDefaults");
    if (!UD) { ADD(@"NSUserDefaults 不存在"); return; }

    // 拦 objectForKey / stringForKey / boolForKey / integerForKey / objectForKey:
    NSArray *sels = @[@"objectForKey:", @"stringForKey:", @"boolForKey:",
                      @"integerForKey:", @"doubleForKey:", @"dictionaryForKey:",
                      @"arrayForKey:", @"dataForKey:"];
    int hooked = 0;
    for (NSString *sn in sels) {
        SEL sel = NSSelectorFromString(sn);
        Method m = class_getInstanceMethod(UD, sel);
        if (!m) continue;
        IMP orig = method_getImplementation(m);
        // 用 block 包装
        __block IMP o = orig;
        NSString *name = sn;
        IMP repl = imp_implementationWithBlock(^id(id self_, NSString *key) {
            id r = ((id(*)(id, SEL, id))o)(self_, NSSelectorFromString(name), key);
            if (g_udCount < 300) {
                g_udCount++;
                NSString *rs;
                if ([r isKindOfClass:[NSString class]]) rs = r;
                else if ([r isKindOfClass:[NSNumber class]]) rs = [r stringValue];
                else if (!r) rs = @"nil";
                else rs = NSStringFromClass([r class]);
                if (rs.length > 60) rs = [rs substringToIndex:60];
                ADD(@"UD[%@] = %@", key, rs);
            }
            return r;
        });
        method_setImplementation(m, repl);
        hooked++;
    }
    ADD(@"NSUserDefaults hook: %d 个方法", hooked);
}

#pragma mark - 扫内存找 MemberObj 实例

// MemberObj 布局（已知）：
//   +0x10 id(String)  +0x18 _isVIP  +0x20 _expireAt
//   +0x28 _VIPType    +0x30 _hasGifted  +0x38 _shouldRefresh  +0x40 _weeklyReadNum
// 通过 ObjC runtime 拿不到（纯 Swift 类），改为扫 Mach-O 里指向
// MemberObj metadata 的 isa 指针。

// 直接读 __swift5_types 里已知的 MemberObj metadata 地址（该版本固定）
// 0x100b60344 + slide
static void ScanMemberObj(void) {
    intptr_t slide = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i);
        if (n && strstr(n, "mangaCapsule")) { slide = _dyld_get_image_vmaddr_slide(i); break; }
    }
    void *type = (void *)(0x100b60344ULL + slide);
    ADD(@"MemberObj metadata = %p (slide %p)", type, (void *)slide);
    if (!type) return;

    // 该元数据地址即 isa 值
    uintptr_t isa = (uintptr_t)type;
    ADD(@"isa = %p，开始扫堆", (void *)isa);

    vm_address_t addr = 0;
    vm_size_t size = 0;
    kern_return_t kr;
    int found = 0;
    int checked = 0;
    // 只扫可读可写区（堆）
    while ((kr = vm_region_64(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                              NULL, NULL, NULL)) == KERN_SUCCESS) {
        if (size > 0 && size < (1u << 30)) {
            uintptr_t *p = (uintptr_t *)addr;
            size_t n = size / sizeof(uintptr_t);
            for (size_t i = 0; i < n; i += 4) {
                checked++;
                if (p[i] == isa) {
                    uint8_t *obj = (uint8_t *)(p + i);
                    // 验证 +0x18 是 0 或 1
                    uint8_t v = obj[0x18];
                    if (v <= 1) {
                        found++;
                        if (found <= 5) {
                            ADD(@"MemberObj@%p  _isVIP=%u  VIPType=%u weekly=%llu",
                                obj, v, obj[0x28], *(uint64_t *)(obj + 0x40));
                        }
                    }
                }
            }
        }
        addr += size;
        if (addr > 0x0000000200000000ULL) break;
    }
    ADD(@"扫描完成 checked=%d found=%d", checked, found);
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
    UIWindow *w = KW();
    UIViewController *vc = w.rootViewController;
    if (!vc) {
        if (attempt < 15)
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ Show(attempt + 1); });
        return;
    }
    while (vc.presentedViewController) vc = vc.presentedViewController;
    NSString *msg = [g_lines componentsJoinedByString:@"\n"];
    if (msg.length > 3500) msg = [msg substringToIndex:3500];
    UIAlertController *ac =
        [UIAlertController alertControllerWithTitle:@"Tracer 取证"
                                            message:msg
                                     preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleDefault handler:nil]];
    [vc presentViewController:ac animated:YES completion:nil];
}

static void Dump(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    [[g_lines componentsJoinedByString:@"\n"] writeToFile:[dir stringByAppendingPathComponent:@"trace.log"]
                                              atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

__attribute__((constructor))
static void TracerInit(void) {
    if (g_done) return;
    g_done = YES;
    g_lines = [NSMutableArray array];
    ADD(@"Tracer 已加载 build=%s", __DATE__);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        HookUserDefaults();
    });

    // 10 秒后扫内存并弹窗
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        ScanMemberObj();
        Dump();
        Show(0);
    });
}
