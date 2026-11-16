"""Acha os objetos de chave VIVOS da cifra L2 na memoria do L2.exe e avisa a l2hook.dll (somente leitura).

Fluxo (a chave e por conexao, entao rode depois de cada login):
 1. le frames do pipe da DLL por ~WINDOW s;
 2. deduz bytes da chave do cliente->servidor pelos pacotes ValidatePosition (corpo de 21 bytes, op 0x48,
    ultimos 4 bytes e heading alto = 0): K0=c0^0x48, K1..K4=d17..d20, K15=d15  (d[i]=c[i]^c[i-1]);
 3. varre a memoria (ReadProcessMemory) por K0..K4 .{10} K15 e amostra o contador (+8) de cada candidato;
 4. escolhe o objeto cujo contador avanca = soma dos corpos ENVIADOS (send) e o que avanca = soma dos RECEBIDOS (recv);
 5. grava "%TEMP%\\l2hook_addrs.txt" ("<send_obj_hex> <recv_obj_hex>"), que a DLL le a cada 1 s.
Uso: py -3 livefind.py [--window 12]
"""
import argparse, collections, ctypes, os, re, struct, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keyscan

PIPE = r"\\.\pipe\l2hook"


def read_exact(f, n):
    b = b""
    while len(b) < n:
        c = f.read(n - len(b))
        if not c: raise EOFError
        b += c
    return b


def split(buf, data):
    buf += data; pk = []
    while len(buf) >= 2:
        n, = struct.unpack_from("<H", buf, 0)
        if n < 2 or len(buf) < n: break
        pk.append(buf[2:n]); buf = buf[n:]
    return buf, pk


def collect(window):
    f = open(PIPE, "rb", buffering=0)
    bufs = {0: b"", 1: b""}; vp = []; sumb = {0: 0, 1: 0}; t0 = time.time(); started = None
    snap0 = None
    while time.time() - t0 < window:
        dir_, n, _a, _b = struct.unpack("<BIII", read_exact(f, 13)); data = read_exact(f, n)
        if dir_ == 2: continue
        bufs[dir_], pk = split(bufs[dir_], data)
        for p in pk:
            if dir_ == 1 and len(p) == 21: vp.append(p)
            sumb[dir_] += len(p)
        if started is None and sumb[0] + sumb[1] > 0: started = True
    return vp, sumb


def derive_key(vp):
    if len(vp) < 3: raise SystemExit("poucos ValidatePosition (%d): ande/espere alguns segundos e rode de novo" % len(vp))
    def mode(i): return collections.Counter(p[i] ^ p[i - 1] for p in vp).most_common(1)[0][0]
    k0 = collections.Counter(p[0] ^ 0x48 for p in vp).most_common(1)[0][0]
    if mode(16) != k0: raise SystemExit("inconsistente: d16=%02x != K0=%02x (cifra diferente?)" % (mode(16), k0))
    return bytes([k0, mode(17), mode(18), mode(19), mode(20)]), mode(15)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--window", type=float, default=12)
    a = ap.parse_args()
    pid = keyscan.pid_of()
    if not pid: raise SystemExit("L2.exe nao esta rodando")
    print("coletando %.0fs de trafego..." % a.window)
    vp, _ = collect(a.window)
    head, k15 = derive_key(vp)
    print("bytes de chave deduzidos: K0..K4 = %s, K15 = %02x" % (head.hex(" "), k15))
    pat = re.escape(head) + rb".{10}" + re.escape(bytes([k15]))
    hits = [h for h, _ in keyscan.scan(pid, pat)]
    print(len(hits), "candidatos")
    if not hits: raise SystemExit("nenhum candidato na memoria")
    k32 = keyscan.k32; hp = k32.OpenProcess(0x0410, False, pid)
    def counter(addr):
        buf = ctypes.create_string_buffer(4); n = ctypes.c_size_t()
        return struct.unpack("<I", buf.raw)[0] if k32.ReadProcessMemory(hp, ctypes.c_void_p(addr + 8), buf, 4, ctypes.byref(n)) else None
    c0 = {h: counter(h) for h in hits}
    f = open(PIPE, "rb", buffering=0); bufs = {0: b"", 1: b""}; sumb = {0: 0, 1: 0}; t0 = time.time()
    print("amostrando contadores por 8s...")
    while time.time() - t0 < 8:
        dir_, n, _a, _b = struct.unpack("<BIII", read_exact(f, 13)); data = read_exact(f, n)
        if dir_ == 2: continue
        bufs[dir_], pk = split(bufs[dir_], data); sumb[dir_] += sum(len(p) for p in pk)
    c1 = {h: counter(h) for h in hits}
    mv = {h: (c1[h] - c0[h]) & 0xFFFFFFFF for h in hits if c0[h] is not None and c1[h] is not None and c1[h] != c0[h]}
    print("somas de corpos na janela: send=%d recv=%d" % (sumb[1], sumb[0]))
    for h, d in sorted(mv.items()): print("  mexendo", hex(h), "delta", d)
    def best(total):
        c = [(abs(d - total), h) for h, d in mv.items() if d < 1 << 24]
        c.sort(); return c[0] if c and c[0][0] <= max(64, total // 10) else None
    s, r = best(sumb[1]), best(sumb[0])
    if not s or not r or s[1] == r[1]:
        raise SystemExit("nao consegui separar send/recv (send=%s recv=%s); tente de novo com mais trafego" % (s, r))
    path = os.path.join(tempfile.gettempdir(), "l2hook_addrs.txt")
    open(path, "w").write("%x %x\n" % (s[1], r[1]))
    print("OK send=0x%x recv=0x%x -> %s" % (s[1], r[1], path))


if __name__ == "__main__":
    main()
