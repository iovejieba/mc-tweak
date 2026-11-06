// MemberBypass.m — v9
//
// 方向修正确认（IDA 反编译 sub_1003895A4 + Probe2 实测）：
//
//   bool sub_1003895A4() {
//     if (sub_10038940C(1)) return 0;
//     obj = NSUserDefaults.stringForKey("rainy.lyn.mangaCapsule");   // ← UserDefaults
//     if (!obj) return 1;                    // 无值 -> 返回 1
//     ...
//     sub_100387F6C(v7);                     // 解析成 Date
//     return v9 != 1;                        // v9==1 表示已过期
//   }
//
// 而 Probe2 显示 UserDefaults 里**根本没有** "rainy.lyn.mangaCapsule" 这个键。
// 所以 v9 往 UserDefaults 写它。
//
// 写入格式：一个能被 Double/Int 解析的时间戳字符串（2001 纪元或 Unix 纪元都试）。
//
// 不 hook 任何函数，零崩溃风险。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>

#ifndef VIPKEY_UNDERSCORE
#define VIPKEY_UNDERSCORE 0
#endif

static BOOL g_done = NO;

// 2026-11-07 附近 vs 2286-11-21
static const double kUnixExpire  = 10000022400.0;   // 2286-11-21 Unix 秒
static const double kAppleExpire = 9021715200.0;    // 2286-11-21 2001 纪元秒

static void Log(NSString *s) { NSLog(@"[MB9] %@", s); }

__attribute__((constructor))
static void MBInit(void) {
    if (g_done) return;
    g_done = YES;
    @try {
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];

        // 1) 主目标：sub_1003895A4 明确读这个键
        //    值做成数字字符串（sub_100387F6C 里逐位 -48 解析，说明是数字文本）
        [ud setObject:@"10000022400" forKey:@"rainy.lyn.mangaCapsule"];
        [ud setObject:@"10000022400" forKey:@"lastActive.rainy.lyn.mangaCapsule"];

        // 2) 顺带把可能相关的布尔开关也置上
        [ud setBool:YES forKey:@"isVIP"];
        [ud setBool:YES forKey:@"isVip"];
        [ud setBool:YES forKey:@"vip"];
        [ud setInteger:2 forKey:@"VIPType"];
        [ud setBool:NO  forKey:@"ZH_HIDE_MVIP"];
        [ud setBool:NO  forKey:@"ZH_NOTSHOW_MVIP"];
        [ud setBool:YES forKey:@"ZH_SHOW_MVIP"];
        [ud synchronize];

        Log([NSString stringWithFormat:@"UD written. rainy.lyn.mangaCapsule=%@",
             [ud stringForKey:@"rainy.lyn.mangaCapsule"]]);

        // 3) keychain 那两条保持写入（万一也读）
        NSMutableDictionary *d = [NSMutableDictionary dictionary];
        d[@"id"] = @"local";
#if VIPKEY_UNDERSCORE
        d[@"_isVIP"] = @YES; d[@"_expireAt"] = @(kAppleExpire); d[@"_VIPType"] = @2;
        d[@"_hasGifted"] = @NO; d[@"_shouldRefreshProducts"] = @NO; d[@"_weeklyReadNum"] = @0;
#else
        d[@"isVIP"] = @YES; d[@"expireAt"] = @(kAppleExpire); d[@"VIPType"] = @2;
        d[@"hasGifted"] = @NO; d[@"shouldRefreshProducts"] = @NO; d[@"weeklyReadNum"] = @0;
#endif
        NSData *json = [NSJSONSerialization dataWithJSONObject:d options:0 error:nil];
        for (NSString *svc in @[@"rainy.lyn.mangaCapsule", @"rainy.heichai.mangaCapsule3"]) {
            NSDictionary *q = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                 (__bridge id)kSecAttrService: svc,
                                 (__bridge id)kSecAttrAccount: @"validTransaction" };
            SecItemDelete((__bridge CFDictionaryRef)q);
            NSMutableDictionary *a = [q mutableCopy];
            a[(__bridge id)kSecValueData] = json;
            a[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
            SecItemAdd((__bridge CFDictionaryRef)a, NULL);
        }
        Log(@"keychain written too");
    } @catch (NSException *e) {
        Log([NSString stringWithFormat:@"err %@", e]);
    }
}
