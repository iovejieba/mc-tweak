import sys
import lief

path = sys.argv[1] if len(sys.argv) > 1 else 'MemberBypass.dylib'
b = lief.parse(path)
sects = [s.name for s in b.sections]
print('file:', path)
print('sections:', sects)
print('libraries:', [l.name for l in b.libraries])
print('has __mod_init_func:', '__mod_init_func' in sects)
print('has LC_ROUTINES:', any('ROUTINES' in c.command.name for c in b.commands))

bad = []
if '__mod_init_func' not in sects:
    bad.append('no __mod_init_func')
if not any('Security' in l.name for l in b.libraries):
    bad.append('Security not linked')
if not any('Foundation' in l.name for l in b.libraries):
    bad.append('Foundation not linked')

if bad:
    print('FAIL:', bad)
    sys.exit(1)
print('OK')
