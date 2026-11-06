// Constructor.c — 保证 dylib 加载时一定被调用
//
// ld64.lld 对 __attribute__((constructor)) 的 __mod_init_func 生成不完整，
// 这里直接放进 __DATA,__mod_init_func 段，dyld 100% 会执行。

typedef void (*init_fn)(void);

extern void MBInit(void);

__attribute__((used, section("__DATA,__mod_init_func")))
static const init_fn mb_init_pointer = MBInit;
