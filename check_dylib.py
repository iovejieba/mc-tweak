import sys
import lief

path = sys.argv[1] if len(sys.argv) > 1 else 'MemberBypass.dylib'
b = lief.parse(path)
sects = [s.name for s in b.sections]
libs = [l.name for l in b.libraries]

print('file:', path)
print('sections:', sects)
print('libraries:', libs)

# dyld 执行初始化函数的三种载体，任一存在即可
has_mod_init = '__mod_init_func' in sects
has_init_offsets = '__init_offsets' in sects
has_routines = any('ROUTINES' in c.command.name for c in b.commands)

print('__mod_init_func :', has_mod_init)
print('__init_offsets  :', has_init_offsets)
print('LC_ROUTINES_64  :', has_routines)

bad = []
if not (has_mod_init or has_init_offsets or has_routines):
    bad.append('no init mechanism at all')
if not any('Security' in l for l in libs):
    bad.append('Security not linked')
if not any('Foundation' in l for l in libs):
    bad.append('Foundation not linked')
if '__text' not in sects:
    bad.append('no __text')

# 顺带确认 MBInit 符号是否导出（便于 Frida 调试）
try:
    syms = set(b.exported_symbols)
    print('_MBInit exported:', '_MBInit' in syms)
except Exception as e:
    print('exported_symbols unavailable:', e)

if bad:
    print('FAIL:', bad)
    sys.exit(1)
print('OK')
