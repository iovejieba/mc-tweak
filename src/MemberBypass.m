// MemberBypass.m — v10 最小可运行
//
// v8/v9 都闪退，且 v9 明明没有 hook 只写数据。
// v10 把变量降到最少：只往 UserDefaults 写一个键，不做任何 keychain 操作、
// 不用 Constructor.c、不用 for-in 快速枚举。

#import <Foundation/Foundation.h>

__attribute__((constructor))
static void boot(void) {
    @try {
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        [ud setObject:@"10000022400" forKey:@"rainy.lyn.mangaCapsule"];
        [ud synchronize];
        NSLog(@"[MB10] ok");
    } @catch (NSException *e) {
        NSLog(@"[MB10] %@", e);
    }
}
