"""Procura (somente leitura) a chave XOR de 16 bytes do L2 na memoria do L2.exe.
Padrao conhecido do cliente->servidor: 78 18 5b e0 cf ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 97
Uso: py -3 keyscan.py [pid]
"""
import ctypes, ctypes.wintypes as w, re, sys, subprocess
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
class MBI(ctypes.Structure):
    _fields_ = [('Base', ctypes.c_void_p), ('AllocBase', ctypes.c_void_p), ('AllocProt', w.DWORD),
                ('Size', ctypes.c_size_t), ('State', w.DWORD), ('Prot', w.DWORD), ('Type', w.DWORD)]
def pid_of(name='L2.exe'):
    out = subprocess.run(['tasklist', '/fi', f'imagename eq {name}', '/fo', 'csv', '/nh'], capture_output=True, text=True).stdout
    for l in out.splitlines():
        p = l.replace('"', '').split(',')
        if p[0].lower() == name.lower(): return int(p[1])
def scan(pid, pat):
    h = k32.OpenProcess(0x0410, False, pid)  # VM_READ | QUERY_INFORMATION
    if not h: raise OSError(ctypes.get_last_error())
    rx = re.compile(pat, re.S); addr = 0; hits = []
    mbi = MBI()
    while addr < 0x7FFF0000 and k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.State == 0x1000 and not (mbi.Prot & 0x101) and mbi.Size < 0x10000000:
            buf = ctypes.create_string_buffer(mbi.Size); n = ctypes.c_size_t()
            if k32.ReadProcessMemory(h, ctypes.c_void_p(mbi.Base), buf, mbi.Size, ctypes.byref(n)):
                for m in rx.finditer(buf.raw[:n.value]):
                    hits.append((mbi.Base + m.start(), m.group(0)))
        addr = (mbi.Base or 0) + mbi.Size
    return hits
if __name__ == '__main__':
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else pid_of()
    pat = rb'\x78\x18\x5b\xe0\xcf.{10}\x97'
    for a, b in scan(pid, pat): print(hex(a), b.hex(' '))
