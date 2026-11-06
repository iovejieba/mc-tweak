// Probe.m — 用 ObjC runtime + Swift ABI 直接读 MemberService.memberObj
//
// 不再猜判定点。做两件事：
//   1. 找到 MemberService 单例（全局 qword，符号名可查）
//   2. 用 Swift ABI 读出 memberObj 的每个字段，打印真实值
//   3. 同时把所有 NSUserDefaults 的全部键值 dump 出来（不用 hook，直接读）

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#include <string.h>

static NSMutableArray<NSString *> *L = nil;
#define ADD(fmt, ...) [L addObject:[NSString stringWithFormat:(fmt), ##__VA_ARGS__]]

static void Dump(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!dir) return;
    [[L componentsJoinedByString:@"\n"] writeToFile:[dir stringByAppendingPathComponent:@"probe.log"]
                                         atomically:YES encoding:NSUTF8StringEncoding error:nil];
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
    if (m.length > 3000) m = [m substringToIndex:3000];
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"Probe"
                                                               message:m
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [vc presentViewController:ac animated:YES completion:nil];
}

__attribute__((constructor))
static void ProbeInit(void) {
    L = [NSMutableArray array];
    ADD(@"Probe 加载 %s", __DATE__);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            // ===== 1. dump 全部 UserDefaults =====
            NSDictionary *ud = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
            ADD(@"");
            ADD(@"=== UserDefaults 全部 %lu 项 ===", (unsigned long)ud.count);
            NSArray *keys = [[ud allKeys] sortedArrayUsingSelector:@selector(compare:)];
            int shown = 0;
            for (NSString *k in keys) {
                if (shown >= 60) { ADD(@"  ...(截断)"); break; }
                // 只显示可能是业务数据的（过滤系统日志键）
                if ([k hasPrefix:@"Log"] || [k hasPrefix:@"Apple"] ||
                    [k hasPrefix:@"Current"] || [k hasPrefix:@"NS"]) continue;
                id v = ud[k];
                NSString *vs = [v description];
                if (vs.length > 60) vs = [vs substringToIndex:60];
                ADD(@"  %@ = %@", k, vs);
                shown++;
            }

            // ===== 2. 找 MemberService 单例并读字段 =====
            ADD(@"");
            ADD(@"=== MemberService 探查 ===");
            // qword_1010C6658 是单例指针，基址 0x100000000
            Dl_info info;
            const char *img = NULL;
            for (uint32_t i = 0; i < _dyld_image_count(); i++) {
                const char *nm = _dyld_get_image_name(i);
                if (nm && strstr(nm, "mangaCapsule")) { img = nm; break; }
            }
            if (img && dladdr((void *)0x100000000ULL, &info)) {
                // 用 slide 计算
            }
            intptr_t slide = 0;
            for (uint32_t i = 0; i < _dyld_image_count(); i++) {
                const char *nm = _dyld_get_image_name(i);
                if (nm && strstr(nm, "mangaCapsule")) {
                    slide = _dyld_get_image_vmaddr_slide(i);
                    break;
                }
            }
            void **slot = (void **)(0x1010C6658ULL + slide);
            void *svc = *slot;
            ADD(@"slide=%p  qword_1010C6658=%p", (void *)slide, svc);

            if (svc) {
                uint8_t *p = (uint8_t *)svc;
                // MemberService 布局：+0x10/+0x20 等是 String(16B)
                // +0x60/+0x68 = "rainy.lyn.mangaCapsule"
                // memberObj 是 @Published<MemberObj?>，找哪个偏移像对象指针
                for (int off = 0x10; off <= 0xF0; off += 8) {
                    void *v = *(void **)(p + off);
                    if (!v) continue;
                    Dl_info di;
                    if (dladdr(v, &di) && di.dli_sname) {
                        ADD(@"  +%#04x -> %p (%s)", off, v, di.dli_sname);
                    }
                }
            }
            ADD(@"");
            ADD(@"（完整内容见 Documents/probe.log）");
        } @catch (NSException *e) {
            ADD(@"异常: %@", e);
        }
        Dump();
        Show(0);
    });
}
