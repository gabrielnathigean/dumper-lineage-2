"""Unknown-value tracker: snap, then 'dec' keeps only int32 cells that went DOWN since the last step.
Usage: unk.py snap | dec     (state in unk_state.npz)"""
import os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l2live as L
ST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "unk_state.npz")
LO, HI = 2, 2000
p = L.Proc(L.find_pid("l2.exe")[0])
regs = list(p.rw_regions())

if sys.argv[1] == "snap":
    A, V = [], []
    for base, n in regs:
        d = p.read(base, n)
        if not d: continue
        a = np.frombuffer(d[: len(d)//4*4], dtype="<i4")
        idx = np.nonzero((a >= LO) & (a <= HI))[0]
        A.append((base + idx.astype(np.int64) * 4)); V.append(a[idx].astype(np.int32))
    A, V = np.concatenate(A), np.concatenate(V)
    np.savez(ST, A=A, V=V); print(len(A), "cells saved")
else:
    z = np.load(ST); A, V = z["A"], z["V"]
    keepA, keepV = [], []
    order = np.argsort(A); A, V = A[order], V[order]
    for base, n in regs:
        lo, hi = np.searchsorted(A, base), np.searchsorted(A, base + n)
        if lo == hi: continue
        d = p.read(base, n)
        if not d: continue
        a = np.frombuffer(d[: len(d)//4*4], dtype="<i4")
        sa, sv = A[lo:hi], V[lo:hi]
        offs = ((sa - base) // 4).astype(np.int64)
        offs = np.minimum(offs, len(a) - 1)
        cur = a[offs]
        m = (cur < sv) & (cur >= 0)
        keepA.append(sa[m]); keepV.append(cur[m])
    A, V = np.concatenate(keepA), np.concatenate(keepV)
    np.savez(ST, A=A, V=V)
    print(len(A), "cells went down")
    if len(A) <= 40:
        for a, v in zip(A, V): print(f"  {int(a):#x} = {int(v)}")
