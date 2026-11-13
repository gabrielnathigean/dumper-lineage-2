"""Pointer cells that reference a copy of NAME. Usage: nameptr.py snap NAME | diff NAME  (run diff with target selected)"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l2live as L
FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nameptr.json")
mode, name = sys.argv[1], sys.argv[2]
pat = name.encode("utf-16-le") + b"\0\0"
p = L.Proc(L.find_pid("l2.exe")[0])
chunks = L.snapshot(p)
names = []
for b, d in chunks:
    if not d: continue
    i = d.find(pat)
    while i != -1:
        names.append(b + i); i = d.find(pat, i + 1)
cells = {c: v for c, v, t in L.pointers_into(chunks, names, 0x20, p.ptr)}
print(len(names), "name copies,", len(cells), "pointer cells into them")
if mode == "snap":
    json.dump({str(k): v for k, v in cells.items()}, open(FILE, "w"))
else:
    old = {int(k): v for k, v in json.load(open(FILE)).items()}
    for c, v in sorted(cells.items()):
        if c not in old: print(f"  NEW     cell {c:#x} -> {v:#x}")
        elif old[c] != v: print(f"  CHANGED cell {c:#x} {old[c]:#x} -> {v:#x}")
    for c in sorted(old):
        if c not in cells: print(f"  GONE    cell {c:#x}")
