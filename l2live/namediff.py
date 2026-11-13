"""Find the copy of a name that belongs to the CURRENT target. Usage: namediff.py snap NAME | diff NAME"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l2live as L
FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "namediff.json")
mode, name = sys.argv[1], sys.argv[2]
pat = name.encode("utf-16-le") + b"\0\0"
p = L.Proc(L.find_pid("l2.exe")[0])
hits = {}
for b, n in p.rw_regions():
    d = p.read(b, n)
    if not d: continue
    i = d.find(pat)
    while i != -1:
        hits[b + i] = d[max(0, i - 0x40): i + 0x80].hex()
        i = d.find(pat, i + 1)
if mode == "snap":
    json.dump({str(k): v for k, v in hits.items()}, open(FILE, "w")); print(len(hits), "copies saved")
else:
    old = {int(k): v for k, v in json.load(open(FILE)).items()}
    gone = [a for a in old if a not in hits]
    chg = [a for a in old if a in hits and hits[a] != old[a]]
    new = [a for a in hits if a not in old]
    print(f"{len(hits)} copies now / {len(old)} before; gone {len(gone)}, changed {len(chg)}, new {len(new)}")
    for tag, lst in (("GONE", gone), ("CHANGED", chg), ("NEW", new)):
        for a in lst[:15]: print(" ", tag, hex(a))
