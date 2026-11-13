"""Unknown float32 tracker: snap, then 'dec' keeps only cells that went DOWN. State in unkf_state.npz"""
import os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l2live as L
ST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "unkf_state.npz")
LO, HI = 0.001, 5000.0
p = L.Proc(L.find_pid("l2.exe")[0])
regs = list(p.rw_regions())
if sys.argv[1] == "snap":
    A, V = [], []
    for base, n in regs:
        d = p.read(base, n)
        if not d: continue
        a = np.frombuffer(d[: len(d)//4*4], dtype="<f4")
        with np.errstate(invalid="ignore"):
            idx = np.nonzero((a >= LO) & (a <= HI))[0]
        A.append(base + idx.astype(np.int64) * 4); V.append(a[idx].astype(np.float32))
    A, V = np.concatenate(A), np.concatenate(V)
    np.savez(ST, A=A, V=V); print(len(A), "float cells saved")
else:
    z = np.load(ST); order = np.argsort(z["A"]); A, V = z["A"][order], z["V"][order]
    kA, kV = [], []
    for base, n in regs:
        lo, hi = np.searchsorted(A, base), np.searchsorted(A, base + n)
        if lo == hi: continue
        d = p.read(base, n)
        if not d: continue
        a = np.frombuffer(d[: len(d)//4*4], dtype="<f4")
        sa, sv = A[lo:hi], V[lo:hi]
        offs = np.minimum(((sa - base) // 4).astype(np.int64), len(a) - 1)
        cur = a[offs]
        with np.errstate(invalid="ignore"):
            m = (cur < sv * 0.9999) & (cur >= 0)
        kA.append(sa[m]); kV.append(cur[m])
    A, V = np.concatenate(kA), np.concatenate(kV)
    np.savez(ST, A=A, V=V); print(len(A), "cells went down")
    if len(A) <= 40:
        for a, v in zip(A, V): print(f"  {int(a):#x} = {float(v):.4f}")
