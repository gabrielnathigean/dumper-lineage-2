"""Find a 'MAX, 0, CUR' triple whose CUR drops while MAX stays (target HP). Usage: hpdiff.py snap|diff"""
import json, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l2live as L
FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hpdiff_snap.json")
p = L.Proc(L.find_pid("l2.exe")[0])

def full(p):          # triples at full health: [MAX, 0, MAX]
    out = {}
    for base, n in p.rw_regions():
        d = p.read(base, n)
        if not d: continue
        a = np.frombuffer(d[: len(d)//4*4], dtype="<i4")
        m = (a[:-2] == a[2:]) & (a[1:-1] == 0) & (a[:-2] > 8) & (a[:-2] < 5000)
        for i in np.nonzero(m)[0]:
            out[base + int(i) * 4] = int(a[i])
    return out

if sys.argv[1] == "snap":
    s = full(p); json.dump({str(k): v for k, v in s.items()}, open(FILE, "w")); print(len(s), "full-health triples saved")
else:
    s = {int(k): v for k, v in json.load(open(FILE)).items()}
    cand = L.read_vals(p, s.keys(), "i32")
    cur = L.read_vals(p, [a + 8 for a in s], "i32")
    hits = [(a, s[a], cur[a + 8]) for a in sorted(s) if cand.get(a) == s[a] and cur.get(a + 8) is not None and 0 <= cur[a + 8] < s[a]]
    print(len(hits), "triples where MAX stayed and CUR dropped")
    for a, mx, c in hits[:30]:
        print(f"  MAX @ {a:#x} = {mx}   CUR @ {a+8:#x} = {c}")
