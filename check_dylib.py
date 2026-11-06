import sys
import lief

path = sys.argv[1] if len(sys.argv) > 1 else 'MemberBypass.dylib'
b = lief.parse(path)
sects = [s.name for s in b.sections]
libs = [l.name for l in b.libraries]

print('file:', path)
print('sections:', sects)
print('libraries:', libs)

has_mod_init = '__mod_init_func' in sects
has_init_offsets = '__init_offsets' in sects
has_routines = any('ROUTINES' in c.command.name for c in b.commands)
# ObjC +load 依赖 __objc_classlist 里存在一个类
has_objc_class = '__objc_classlist' in sects

print('__mod_init_func :', has_mod_init)
print('__init_offsets  :', has_init_offsets)
print('LC_ROUTINES_64  :', has_routines)
print('__objc_classlist:', has_objc_class)

bad = []
# v2 的策略：ObjC +load 必须存在（最可靠），或至少有一种 init 机制
if not (has_objc_class or has_mod_init or has_init_offsets or has_routines):
    bad.append('no init mechanism')
if not any('Security' in l for l in libs):
    bad.append('Security not linked')
if not any('Foundation' in l for l in libs):
    bad.append('Foundation not linked')

# 确认 MBLoader 类被编进去
try:
    names = [c.name for c in b.objc_classes] if hasattr(b, 'objc_classes') else []
except Exception:
    names = []
if not names:
    # 退化为字符串扫描
    data = open(path, 'rb').read()
    has_loader = b'MBLoader' in data
    print('MBLoader string present:', has_loader)
    if not has_loader:
        bad.append('MBLoader class missing')

if bad:
    print('FAIL:', bad)
    sys.exit(1)
print('OK')
