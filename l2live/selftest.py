"""Self-test of l2live against a synthetic 'game' process (no real game involved).

The fake client keeps a Player struct reachable through a 2-level pointer chain, plus decoy
structs holding the same HP, like a real client has. We check that scan -> narrow -> cluster
-> ptr -> verify recovers the exact offsets we planted.
"""
import ctypes, subprocess, sys, os, json
HERE = os.path.dirname(os.path.abspath(__file__))
L2 = os.path.join(HERE, "l2live.py")

CHILD = r'''
import ctypes, sys
class P(ctypes.Structure):
    _fields_ = [("pad", ctypes.c_char * 0x30), ("hp", ctypes.c_int32), ("mp", ctypes.c_int32),
                ("cp", ctypes.c_int32), ("level", ctypes.c_int32), ("pad2", ctypes.c_char * 0x40)]
player = P(); decoys = [P() for _ in range(6)]
outer = (ctypes.c_void_p * 8)(); root = (ctypes.c_void_p * 4)()
outer[2] = ctypes.addressof(player); root[0] = ctypes.addressof(outer)
def setv(h, m, c):
    player.hp, player.mp, player.cp, player.level = h, m, c, 40
    for d in decoys: d.hp = h          # decoys share HP only
setv(*(int(x) for x in sys.argv[1:4]))
print(ctypes.addressof(root), ctypes.addressof(player), flush=True)
for line in sys.stdin:
    setv(*(int(x) for x in line.split())); print("ok", flush=True)
'''

def run(args):
    r = subprocess.run([sys.executable, "-I", L2] + args, capture_output=True, text=True)
    print("$ l2live", " ".join(args), "\n" + r.stdout.strip() + (r.stderr.strip() and "\nERR " + r.stderr.strip()))
    return r.stdout

ch = subprocess.Popen([sys.executable, "-I", "-c", CHILD, "1234", "567", "890"], stdin=subprocess.PIPE,
                      stdout=subprocess.PIPE, text=True)
root_addr, player_addr = (int(x) for x in ch.stdout.readline().split())
base = ["--pid", str(ch.pid), "--session", os.path.join(HERE, "t_session.json")]
run(base + ["reset"])
for name, v in (("hp", 1234), ("mp", 567), ("cp", 890)):
    run(base + ["scan", name, str(v)])
ch.stdin.write("1100 540 800\n"); ch.stdin.flush(); ch.stdout.readline()   # values change in game
for name, v in (("hp", 1100), ("mp", 540), ("cp", 800)):
    run(base + ["scan", name, str(v)])
out = run(base + ["cluster", "--window", "0x100"])
hp_addr = player_addr + 0x30
assert f"{player_addr + 0x30:#x}" in out, "cluster did not find the real player struct"
assert "mp+0x4" in out and "cp+0x8" in out, "relative offsets wrong"
run(base + ["ptr", hex(hp_addr), "--depth", "3", "--extra-root", f"{root_addr:#x}:0x20",
            "--out", os.path.join(HERE, "t_chains.json")])
chains = json.load(open(os.path.join(HERE, "t_chains.json")))
assert any(c["offsets"] == [0x10, 0x30] and c["rva"] == 0 for c in chains), "planted chain not recovered"
out = run(base + ["verify", os.path.join(HERE, "t_chains.json"), "1100"])
assert "chains resolve" in out
ch.stdin.close(); ch.terminate()
for f in ("t_session.json", "t_chains.json"):
    try: os.remove(os.path.join(HERE, f))
    except OSError: pass
print("SELFTEST OK")
