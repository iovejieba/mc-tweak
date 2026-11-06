// Probe3.m — 稳定版（沿用 Probe2 的写法，已验证不崩溃）
//
// 目标：UserDefaults 里已经有 "rainy.lyn.mangaCapsule" = "10000022400" 了
//      （v10 写入），但仍然显示免费用户。
//      说明 UI 不看这个键。
//
// 这次读：Swift 侧的 MemberObj 实例。用已知 metadata 地址当 isa 扫描堆，
//        找到后把每个字段的原始字节打印出来 —— 这样能确定 _isVIP 到底是 0 还是 1，
//        以及 ui 读的是不是这个对象。
//
// 用 Probe2 相同的安全写法：无 hook、无 vm_region_64 空指针。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <mach-o/dyld.h>
#include <string.h>

static NSMutableArray<NSString *> *L = nil;
static BOOL g_done = NO;
#define ADD(fmt, ...) [L addObject:[NSString stringWithFormat:(fmt), ##__VA_ARGS__]]

static void Dump(void) {
    @try {
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                             NSUserDomainMask, YES) firstObject];
        if (!dir) return;
        [[L componentsJoinedByString:@"\n"]
            writeToFile:[dir stringByAppendingPathComponent:@"probe3.log"]
             atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (NSException *e) {}
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
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"Probe3"
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
    @try {
        L = [NSMutableArray array];
        ADD(@"Probe3 %s", __DATE__);

        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        ADD(@"UD[rainy.lyn.mangaCapsule] = %@", [ud stringForKey:@"rainy.lyn.mangaCapsule"]);

        // 找 slide
        intptr_t slide = 0;
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            const char *n = _dyld_get_image_name(i);
            if (n && strstr(n, "mangaCapsule")) {
                slide = _dyld_get_image_vmaddr_slide(i);
                break;
            }
        }
        ADD(@"slide = %p", (void *)slide);

        // 已知全局：qword_1010C6658 = MemberService 单例
        // qword_1010C6660 = 另一个单例（MemberService 伴生）
        for (uint64_t gva = 0x1010C6658ULL; gva <= 0x1010C6660ULL; gva += 8) {
            void **slot = (void **)(gva + slide);
            ADD(@"  global %p = %p", (void *)gva, *slot);
        }

        // 扫堆找 isa == MemberObj metadata (0x100b60344 + slide)
        uintptr_t isa = (uintptr_t)(0x100b60344ULL + slide);
        ADD(@"MemberObj isa = %p", (void *)isa);

        vm_address_t addr = 0;
        int found = 0, regions = 0, checked = 0;
        while (regions < 3000) {
            vm_size_t size = 0;
            vm_region_submap_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
            kern_return_t kr = vm_region_recurse_64(mach_task_self(), &addr, &size,
                                                    (natural_t *)&cnt,
                                                    (vm_region_recurse_info_t)&info, NULL);
            if (kr != KERN_SUCCESS) break;
            regions++;
            if (info.is_submap || size == 0) { addr += (size ? size : 0x1000); continue; }
            if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) !=
                (VM_PROT_READ | VM_PROT_WRITE) || size > (32u << 20)) {
                addr += size;
                continue;
            }
            uintptr_t *p = (uintptr_t *)addr;
            size_t n = size / sizeof(uintptr_t);
            for (size_t i = 0; i < n; i += 2) {
                checked++;
                if (p[i] != isa) continue;
                uint8_t *o = (uint8_t *)(p + i);
                found++;
                if (found <= 3) {
                    ADD(@"");
                    ADD(@"MemberObj #%d @ %p", found, o);
                    ADD(@"  +0x18 isVIP     = %u", o[0x18]);
                    ADD(@"  +0x28 VIPType   = %u", o[0x28]);
                    ADD(@"  +0x40 weekly    = %llu", *(uint64_t *)(o + 0x40));
                }
            }
            addr += size;
        }
        ADD(@"");
        ADD(@"扫描 regions=%d checked=%d found=%d", regions, checked, found);
    } @catch (NSException *e) {
        ADD(@"异常: %@", e);
    }
    Dump();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ Show(0); });
}
