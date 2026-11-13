"""List every 'gauge' struct (8, 12, MAX, 0, CUR) in the client. Usage: gauges.py snap|diff"""
import json, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l2live as L
FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gauges_snap.json")

def scan(p):
    out, hdr = {}, struct.pack("<2i", 8, 12)
    for base, n in p.rw_regions():
        d = p.read(base, n)
        if not d: continue
        i = d.find(hdr)
        while i != -1:
            if i % 4 == 0 and i + 20 <= len(d):
                _, _, mx, z, cur = struct.unpack_from("<5i", d, i)
                if z == 0 and 0 < mx < 10_000_000 and 0 <= cur <= mx:
                    out[base + i + 8] = (cur, mx)
            i = d.find(hdr, i + 1)
    return out

p = L.Proc(L.find_pid("l2.exe")[0])
now = scan(p)
if sys.argv[1] == "snap":
    json.dump({str(k): v for k, v in now.items()}, open(FILE, "w")); print(len(now), "gauges saved")
else:
    old = {int(k): tuple(v) for k, v in json.load(open(FILE)).items()}
    print(len(now), "gauges now,", len(old), "before")
    for a, v in sorted(now.items()):
        if a not in old: print("NEW    ", hex(a), v)
        elif old[a] != v: print("CHANGED", hex(a), old[a], "->", v)
