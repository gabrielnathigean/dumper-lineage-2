#!/usr/bin/env python3
"""l2live - runtime offset finder (Windows, Python 3.10+, read-only).

Reads memory of a process YOU own (your own L2 Interlude client connected to your own
server). It never writes memory, never injects and never touches anticheat.

Workflow (every step is verified against live values, nothing is guessed):
  1. scan   NAME VALUE      first scan, then repeat with the new value to narrow (like CE)
  2. cluster                finds struct bases where HP/MP/CP/... sit close together
  3. ptr    ADDR            reverse pointer search -> chains  [module+RVA] -> +o1 -> ... -> ADDR
  4. intersect A.json B.json  keeps only chains that survive two different runs (restart client)
  5. verify chains.json VALUE re-reads the chains live and checks the value

Pointer search needs numpy (pip install numpy).
"""
import argparse, ctypes, ctypes.wintypes as wt, json, os, struct, sys

try:
    import numpy as np
except ImportError:
    np = None

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
k32.IsWow64Process.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.BOOL)]


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("PartitionId", wt.WORD),
                ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD)]


class PROCENTRY(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wt.DWORD),
                ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", wt.LONG), ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_wchar * 260)]


class MODENTRY(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("GlblcntUsage", wt.DWORD), ("ProccntUsage", wt.DWORD),
                ("modBaseAddr", ctypes.c_void_p), ("modBaseSize", wt.DWORD),
                ("hModule", ctypes.c_void_p), ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * 260)]


MEM_COMMIT = 0x1000
RW_PROT = {0x04, 0x08, 0x40, 0x80}  # READWRITE, WRITECOPY, EXEC_READWRITE, EXEC_WRITECOPY
PAGE_GUARD = 0x100
TYPES = {"i32": ("<i", 4), "u32": ("<I", 4), "f32": ("<f", 4), "f64": ("<d", 8), "i16": ("<h", 2)}


def find_pid(name):
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    e = PROCENTRY()
    e.dwSize = ctypes.sizeof(e)
    pids = []
    ok = k32.Process32FirstW(ctypes.c_void_p(snap), ctypes.byref(e))
    while ok:
        if e.szExeFile.lower() == name.lower():
            pids.append(e.th32ProcessID)
        ok = k32.Process32NextW(ctypes.c_void_p(snap), ctypes.byref(e))
    k32.CloseHandle(snap)
    return pids


class Proc:
    def __init__(self, pid):
        self.pid = pid
        self.h = k32.OpenProcess(0x0410, False, pid)  # QUERY_INFORMATION | VM_READ only
        if not self.h:
            raise OSError(f"OpenProcess({pid}) failed (err {ctypes.get_last_error()}); run as the same user/admin")
        w = wt.BOOL()
        k32.IsWow64Process(self.h, ctypes.byref(w))
        self.ptr = 4 if w.value else 8
        self.limit = 0x80000000 if self.ptr == 4 else 0x7FFFFFFEFFFF

    def read(self, addr, n):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t()
        k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got))
        return buf.raw[:got.value] if got.value else None

    def rptr(self, addr):
        d = self.read(addr, self.ptr)
        return int.from_bytes(d, "little") if d and len(d) == self.ptr else None

    def modules(self):
        snap = k32.CreateToolhelp32Snapshot(0x18, self.pid)  # SNAPMODULE | SNAPMODULE32
        out, e = [], MODENTRY()
        e.dwSize = ctypes.sizeof(e)
        ok = k32.Module32FirstW(ctypes.c_void_p(snap), ctypes.byref(e))
        while ok:
            out.append((e.szModule, e.modBaseAddr or 0, e.modBaseSize))
            ok = k32.Module32NextW(ctypes.c_void_p(snap), ctypes.byref(e))
        k32.CloseHandle(snap)
        return out

    def rw_regions(self):
        addr, m = 0, MBI()
        while addr < self.limit:
            if not k32.VirtualQueryEx(self.h, ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m)):
                break
            base, size = m.BaseAddress or 0, m.RegionSize
            if m.State == MEM_COMMIT and m.Protect in RW_PROT and not (m.Protect & PAGE_GUARD):
                off = 0
                while off < size:
                    n = min(size - off, 64 << 20)
                    yield base + off, n
                    off += n
            addr = base + size

    def close(self):
        k32.CloseHandle(self.h)


# ---------------------------------------------------------------- scanning
def first_scan(p, kind, value):
    fmt, al = TYPES[kind]
    pat = struct.pack(fmt, float(value) if kind[0] == "f" else int(value))
    hits = []
    for base, n in p.rw_regions():
        data = p.read(base, n)
        if not data:
            continue
        i = data.find(pat)
        while i != -1:
            if i % al == 0:
                hits.append(base + i)
            i = data.find(pat, i + 1)
    return hits


def range_scan(p, kind, lo, hi):
    """First scan for stats that keep changing: every aligned value in [lo, hi]."""
    if np is None:
        sys.exit("range scan needs numpy: pip install numpy")
    fmt, al = TYPES[kind]
    dt = np.dtype(fmt)
    hits = []
    for base, n in p.rw_regions():
        data = p.read(base, n)
        if not data:
            continue
        arr = np.frombuffer(data[: len(data) // al * al], dtype=dt)
        idx = np.nonzero((arr >= lo) & (arr <= hi))[0]
        hits.extend((base + idx * al).tolist())
    return hits


def next_scan(p, hits, kind, value):
    fmt, al = TYPES[kind]
    pat = struct.pack(fmt, float(value) if kind[0] == "f" else int(value))
    keep, hits = [], sorted(hits)
    i = 0
    while i < len(hits):
        start, j = hits[i], i
        while j + 1 < len(hits) and hits[j + 1] - start < (1 << 20) and hits[j + 1] - hits[j] < 0x10000:
            j += 1
        win = p.read(start, hits[j] - start + al)
        for a in hits[i:j + 1]:
            if win and a - start + al <= len(win) and win[a - start:a - start + al] == pat:
                keep.append(a)
        i = j + 1
    return keep


def read_vals(p, addrs, kind):
    """Current value of every address (coalesced reads). Missing -> None."""
    fmt, al = TYPES[kind]
    out, addrs, i = {}, sorted(addrs), 0
    while i < len(addrs):
        start, j = addrs[i], i
        while j + 1 < len(addrs) and addrs[j + 1] - start < (1 << 20) and addrs[j + 1] - addrs[j] < 0x10000:
            j += 1
        win = p.read(start, addrs[j] - start + al)
        for a in addrs[i:j + 1]:
            ok = win and a - start + al <= len(win)
            out[a] = struct.unpack_from(fmt, win, a - start)[0] if ok else None
        i = j + 1
    return out


def track(p, hits, kind, seconds, interval, min_up, cap):
    """For stats that regenerate: keep candidates that never go down, rise at least min_up
    times and stay <= cap. Static decoys (no change) and unrelated numbers drop out."""
    import time
    prev = read_vals(p, hits, kind)
    alive = {a for a, v in prev.items() if v is not None}
    ups = dict.fromkeys(alive, 0)
    t_end = time.time() + seconds
    while time.time() < t_end and alive:
        time.sleep(interval)
        cur = read_vals(p, alive, kind)
        for a in list(alive):
            v, o = cur.get(a), prev[a]
            if v is None or v < o or v > cap:
                alive.discard(a)
            elif v > o:
                ups[a] += 1
        prev.update({a: v for a, v in cur.items() if v is not None})
    return sorted(a for a in alive if ups[a] >= min_up), prev


def cluster(session, window):
    names = list(session["hits"])
    if len(names) < 2:
        return []
    anchor = names[0]
    res = []
    others = {n: sorted(session["hits"][n]) for n in names[1:]}
    import bisect
    for a in session["hits"][anchor]:
        row = {anchor: 0}
        for n, lst in others.items():
            k = bisect.bisect_left(lst, a - window)
            near = [x - a for x in lst[k:] if x <= a + window]
            if not near:
                break
            row[n] = min(near, key=abs)
        else:
            res.append((a, row))
    return res


# ---------------------------------------------------------------- pointer search
def snapshot(p):
    return [(b, p.read(b, n)) for b, n in p.rw_regions()]


def pointers_into(chunks, targets, maxoff, ptr):
    """All (cell_addr, value) with value in [t-maxoff, t] for some t in targets."""
    dt = np.dtype("<u4" if ptr == 4 else "<u8")
    ts = np.array(sorted(targets), dtype=dt)
    out = []
    for base, data in chunks:
        if not data:
            continue
        arr = np.frombuffer(data[: len(data) // ptr * ptr], dtype=dt)
        j = np.searchsorted(ts, arr)
        j[j >= len(ts)] = len(ts) - 1
        near = ts[j]
        mask = (near >= arr) & ((near - arr) <= maxoff) & (arr > 0x10000)
        for idx in np.nonzero(mask)[0]:
            out.append((base + int(idx) * ptr, int(arr[idx]), int(near[idx])))
    return out


def ptr_search(p, target, depth, maxoff, cap, extra_roots):
    if np is None:
        sys.exit("numpy needed for pointer search: pip install numpy")
    mods = [(n, b, b + s) for n, b, s in p.modules()] + extra_roots
    chunks = snapshot(p)
    frontier = {target: []}
    found = []
    for lvl in range(1, depth + 1):
        hits = pointers_into(chunks, list(frontier), maxoff, p.ptr)
        nxt = {}
        for cell, val, tgt in hits:
            chain = [tgt - val] + frontier[tgt]
            root = next(((n, cell - b) for n, b, e in mods if b <= cell < e), None)
            if root:
                found.append({"module": root[0], "rva": root[1], "offsets": chain, "depth": lvl})
            elif cell not in nxt and cell not in frontier:
                nxt[cell] = chain
        print(f"level {lvl}: {len(hits)} pointers, {len(found)} static roots so far, {len(nxt)} to expand")
        if len(nxt) > cap:  # keep chains with smallest offsets
            nxt = dict(sorted(nxt.items(), key=lambda kv: sum(kv[1]))[:cap])
        frontier = nxt
        if not frontier:
            break
    found.sort(key=lambda c: (c["depth"], sum(c["offsets"])))
    return found


def resolve(p, chain):
    mods = {n: b for n, b, _ in p.modules()}
    if chain["module"] not in mods:
        return None
    addr = p.rptr(mods[chain["module"]] + chain["rva"])
    for o in chain["offsets"][:-1]:
        if addr is None:
            return None
        addr = p.rptr(addr + o)
    return None if addr is None else addr + chain["offsets"][-1]


# ---------------------------------------------------------------- cli
def load(path, default):
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return default


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--proc", default="l2.exe")
    ap.add_argument("--pid", type=int)
    ap.add_argument("--session", default="session.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("name"); s.add_argument("value"); s.add_argument("--type", default="i32", choices=TYPES)
    s.add_argument("--reset", action="store_true")
    c = sub.add_parser("cluster"); c.add_argument("--keep-dups", action="store_true");c.add_argument("--window", type=lambda x: int(x, 0), default=0x400)
    sub.add_parser("modules"); sub.add_parser("reset")
    for nm, hp_ in (("snap", "save current values of the candidates"), ("dropped", "keep candidates that went down since snap")):
        q = sub.add_parser(nm, help=hp_); q.add_argument("names", nargs="+")
    t = sub.add_parser("track", help="narrow regenerating stats by watching them rise (no values needed)")
    t.add_argument("names", nargs="+"); t.add_argument("--seconds", type=float, default=20)
    t.add_argument("--interval", type=float, default=1.0); t.add_argument("--min-up", type=int, default=2)
    t.add_argument("--cap", type=int, default=100000)
    r = sub.add_parser("ptr"); r.add_argument("addr", type=lambda x: int(x, 0))
    r.add_argument("--depth", type=int, default=3); r.add_argument("--maxoff", type=lambda x: int(x, 0), default=0x400)
    r.add_argument("--cap", type=int, default=20000); r.add_argument("--out", default="chains.json")
    r.add_argument("--extra-root", action="append", default=[], help="START:SIZE (tests only)")
    i = sub.add_parser("intersect"); i.add_argument("a"); i.add_argument("b"); i.add_argument("--out", default="chains_stable.json")
    v = sub.add_parser("verify"); v.add_argument("chains"); v.add_argument("value"); v.add_argument("--type", default="i32", choices=TYPES)
    a = ap.parse_args()

    if a.cmd == "intersect":
        A, B = load(a.a, []), load(a.b, [])
        key = lambda c: (c["module"], c["rva"], tuple(c["offsets"]))
        kb = {key(c) for c in B}
        res = [c for c in A if key(c) in kb]
        json.dump(res, open(a.out, "w"), indent=1)
        return print(f"{len(res)} chains stable in both runs -> {a.out}")
    if a.cmd == "reset":
        return os.path.exists(a.session) and os.remove(a.session)

    pid = a.pid or (find_pid(a.proc) or [None])[0]
    if not pid:
        sys.exit(f"{a.proc} not running")
    p = Proc(pid)
    print(f"pid {pid}, {p.ptr * 8}-bit target")
    sess = load(a.session, {"hits": {}, "type": {}})

    if a.cmd == "modules":
        for n, b, sz in p.modules():
            print(f"{n:24s} base {b:#x} size {sz:#x}")
    elif a.cmd == "scan":
        old = None if a.reset else sess["hits"].get(a.name)
        if ":" in a.value:  # range LO:HI, for values that regenerate while we scan
            lo, hi = (float(x) for x in a.value.split(":"))
            hits = range_scan(p, a.type, lo, hi)
        else:
            hits = first_scan(p, a.type, a.value) if old is None else next_scan(p, old, a.type, a.value)
        sess["hits"][a.name], sess["type"][a.name] = hits, a.type
        json.dump(sess, open(a.session, "w"))
        print(f"{a.name}: {len(hits)} candidates" + ("  (first scan)" if old is None else "  (narrowed)"))
        if len(hits) <= 10:
            print("  ", ", ".join(hex(x) for x in hits))
    elif a.cmd == "track":
        for n in a.names:
            keep, last = track(p, sess["hits"][n], sess["type"][n], a.seconds, a.interval, a.min_up, a.cap)
            sess["hits"][n] = keep
            print(f"{n}: {len(keep)} candidates rose steadily")
            for x in keep[:10]:
                print(f"   {x:#x} = {last[x]}")
        json.dump(sess, open(a.session, "w"))
    elif a.cmd == "snap":
        sess["snap"] = {}
        for n in a.names:
            sess["snap"][n] = {str(x): v for x, v in read_vals(p, sess["hits"][n], sess["type"][n]).items()}
            print(f"{n}: baseline of {len(sess['snap'][n])} candidates saved")
        json.dump(sess, open(a.session, "w"))
    elif a.cmd == "dropped":
        for n in a.names:
            now = read_vals(p, sess["hits"][n], sess["type"][n])
            base = sess["snap"][n]
            keep = sorted(x for x, v in now.items() if v is not None and base.get(str(x)) is not None and v < base[str(x)])
            sess["hits"][n] = keep
            print(f"{n}: {len(keep)} candidates went down")
            for x in keep[:10]:
                print(f"   {x:#x}: {base[str(x)]} -> {now[x]}")
        json.dump(sess, open(a.session, "w"))
    elif a.cmd == "cluster":
        seen = {}
        for n, lst in sess["hits"].items():
            for x in lst:
                seen[x] = seen.get(x, 0) + 1
        if not a.keep_dups:  # same addr in 2 stats = timer; but exact-value overlaps (hp==maxhp) are legit
            sess["hits"] = {n: [x for x in lst if seen[x] == 1] for n, lst in sess["hits"].items()}
        res = cluster(sess, a.window)
        print(f"{len(res)} cluster(s), anchor = {list(sess['hits'])[0]}")
        for base, row in res[:30]:
            print(f"  {base:#x}: " + "  ".join(f"{n}{o:+#x}" for n, o in row.items()))
    elif a.cmd == "ptr":
        ex = [("extra", int(x.split(':')[0], 0), int(x.split(':')[0], 0) + int(x.split(':')[1], 0)) for x in a.extra_root]
        chains = ptr_search(p, a.addr, a.depth, a.maxoff, a.cap, ex)
        json.dump(chains, open(a.out, "w"), indent=1)
        for ch in chains[:10]:
            print(f"  [{ch['module']}+{ch['rva']:#x}] " + " ".join(f"+{o:#x}" for o in ch["offsets"]))
        print(f"{len(chains)} chains -> {a.out}")
    elif a.cmd == "verify":
        fmt, n = TYPES[a.type]
        want = struct.pack(fmt, float(a.value) if a.type[0] == "f" else int(a.value))
        chains = load(a.chains, [])
        good = 0
        for ch in chains:
            addr = resolve(p, ch)
            ok = addr is not None and p.read(addr, n) == want
            good += ok
            if ok and good <= 10:
                print(f"  OK  [{ch['module']}+{ch['rva']:#x}] " + " ".join(f"+{o:#x}" for o in ch["offsets"]))
        print(f"{good}/{len(chains)} chains resolve to the expected value")
    p.close()


if __name__ == "__main__":
    main()
