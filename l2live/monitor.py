#!/usr/bin/env python3
"""Live HP / MP / CP monitor for your own L2 Interlude client (read-only).

Reads the HUD gauges through the pointer chains found by l2live (chains_hp_stable.json).
If the chains stop resolving (different client build), it falls back to finding the gauges by
their memory pattern. Run:  py -3 monitor.py        (add --once to print one reading)
"""
import json, os, struct, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import l2live as L

GAP = 0x380                     # MP gauge = HP - GAP, CP gauge = HP + GAP
CHAINS = os.path.join(HERE, "chains_hp_stable.json")


def gauge(p, a):
    """a = address of the MAX field. Layout: 8, 12, MAX, 0, CUR. Returns (cur, max) or None."""
    d = p.read(a - 8, 20)
    if not d or len(d) < 20:
        return None
    h1, h2, mx, z, cur = struct.unpack("<5i", d)
    return (cur, mx) if (h1, h2, z) == (8, 12, 0) and 0 < mx < 10_000_000 and 0 <= cur <= mx else None


def plausible(p, hp):
    return gauge(p, hp) is not None and gauge(p, hp - GAP) is not None   # CP may be absent


def scan_for_gauges(p):
    """Fallback: find an 8,12 gauge header with another one exactly GAP below it."""
    hdr = struct.pack("<2i", 8, 12)
    heads = set()
    for base, n in p.rw_regions():
        d = p.read(base, n)
        if not d:
            continue
        i = d.find(hdr)
        while i != -1:
            if i % 4 == 0:
                heads.add(base + i)
            i = d.find(hdr, i + 1)
    for h in sorted(heads):
        if h + GAP in heads or h - GAP in heads:
            hp = h + 8 if (h - GAP in heads) else None   # HP is the middle one
            if hp and plausible(p, hp):
                return hp
    return None


class Reader:
    def __init__(self):
        self.p = None
        self.hp = None
        self.how = "-"
        self.chains = json.load(open(CHAINS)) if os.path.exists(CHAINS) else []
        self.scanning = False

    def attach(self):
        pids = L.find_pid("l2.exe")
        if not pids:
            self.p = self.hp = None
            return False
        if self.p is None or self.p.pid != pids[0]:
            self.p, self.hp = L.Proc(pids[0]), None
        return True

    def locate(self):
        for ch in self.chains:
            a = L.resolve(self.p, ch)
            if a and plausible(self.p, a):
                self.hp = a
                self.how = f"[{ch['module']}+{ch['rva']:#x}] " + " ".join(f"+{o:#x}" for o in ch["offsets"])
                return
        if not self.scanning:
            self.scanning = True
            threading.Thread(target=self._scan, daemon=True).start()

    def _scan(self):
        try:
            a = scan_for_gauges(self.p)
            if a:
                self.hp, self.how = a, "pattern scan (chains did not resolve)"
        finally:
            self.scanning = False

    def read(self):
        """-> dict stat -> (cur, max) or None, plus status text."""
        if not self.attach():
            return None, "l2.exe not running"
        if self.hp is None or gauge(self.p, self.hp) is None:
            self.hp = None
            self.locate()
            if self.hp is None:
                return None, "looking for the gauges..." if self.scanning else "gauges not found (are you in the game?)"
        v = {"HP": gauge(self.p, self.hp), "MP": gauge(self.p, self.hp - GAP), "CP": gauge(self.p, self.hp + GAP)}
        return v, f"pid {self.p.pid}  HP max field @ {self.hp:#x}   via {self.how}"


def main():
    r = Reader()
    if "--once" in sys.argv:
        v, st = r.read()
        for _ in range(60):                       # give the fallback scan time
            if v:
                break
            time.sleep(0.5)
            v, st = r.read()
        print(st)
        for k, x in (v or {}).items():
            print(f"{k}: {x[0]} / {x[1]}" if x else f"{k}: -")
        return

    import tkinter as tk
    BG, FG, DIM = "#14161c", "#e6e8ee", "#7c8296"
    COL = {"HP": "#d63b3b", "MP": "#3b7bd6", "CP": "#d6a53b"}
    root = tk.Tk()
    root.title("L2 Monitor - HP / MP / CP")
    root.configure(bg=BG)
    root.geometry("460x270")
    root.attributes("-topmost", True)
    rows = {}
    for i, k in enumerate(("HP", "MP", "CP")):
        tk.Label(root, text=k, bg=BG, fg=COL[k], font=("Segoe UI", 12, "bold"), width=3, anchor="w").grid(row=i, column=0, padx=(14, 4), pady=(16, 0))
        cv = tk.Canvas(root, width=260, height=26, bg="#222632", highlightthickness=0)
        cv.grid(row=i, column=1, pady=(16, 0))
        bar = cv.create_rectangle(0, 0, 0, 26, fill=COL[k], width=0)
        txt = tk.Label(root, text="-", bg=BG, fg=FG, font=("Consolas", 12), width=11, anchor="e")
        txt.grid(row=i, column=2, padx=(6, 4), pady=(16, 0))
        dl = tk.Label(root, text="", bg=BG, fg=DIM, font=("Consolas", 10), width=6, anchor="w")
        dl.grid(row=i, column=3, pady=(16, 0))
        rows[k] = [cv, bar, txt, dl, None, 0.0]       # last value, time of last change
    status = tk.Label(root, text="", bg=BG, fg=DIM, font=("Consolas", 8), wraplength=430, justify="left")
    status.grid(row=3, column=0, columnspan=4, padx=14, pady=(22, 0), sticky="w")
    log = tk.Label(root, text="", bg=BG, fg=DIM, font=("Consolas", 9), justify="left", anchor="w")
    log.grid(row=4, column=0, columnspan=4, padx=14, pady=(6, 0), sticky="w")
    history = []

    def tick():
        v, st = r.read()
        status.config(text=st)
        for k, (cv, bar, txt, dl, last, t0) in rows.items():
            g = (v or {}).get(k)
            if not g:
                cv.coords(bar, 0, 0, 0, 26)
                txt.config(text="-")
                continue
            cur, mx = g
            cv.coords(bar, 0, 0, 260 * cur / mx, 26)
            txt.config(text=f"{cur} / {mx}")
            if last is not None and cur != last:
                d = cur - last
                dl.config(text=f"{d:+d}", fg="#5fd37a" if d > 0 else "#e0605e")
                rows[k][5] = time.time()
                history.append(f"{time.strftime('%H:%M:%S')}  {k} {last} -> {cur} ({d:+d})")
                log.config(text="\n".join(history[-5:]))
            elif time.time() - rows[k][5] > 1.5:
                dl.config(text="")
            rows[k][4] = cur
        root.after(100, tick)

    tick()
    root.mainloop()


if __name__ == "__main__":
    main()
