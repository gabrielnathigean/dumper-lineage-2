"""Decodificador ao vivo do pipe da l2hook v4 (contadores sincronizados pela DLL).

Uso: py -3 livedecode.py [--out decoded.jsonl] [--raw]
Frame v2: u8 dir | u32 len | u32 cA | u32 cB | payload
  dir 0=recv 1=send 2=chaves(payload=keyA16||keyB16).  cA/cB = contadores K[8..11] dos dois objetos de chave
  lidos na memoria do cliente no instante do hook. A chave e por conexao e NAO e gravada em disco.
Recv: contador lido = estado ANTES de decifrar o chunk. Send: lido DEPOIS de cifrar -> subtrai os corpos do chunk.
Qual objeto de chave e send/recv e deduzido: o contador do send avanca exatamente a soma dos corpos enviados.
"""
import argparse, json, struct, sys, time
from l2cipher import L2Xor

PIPE = r"\\.\pipe\l2hook"
M = 0xFFFFFFFF
ATTR = {9: 'CUR_HP', 10: 'MAX_HP', 11: 'CUR_MP', 12: 'MAX_MP', 33: 'CUR_CP', 34: 'MAX_CP'}


def read_exact(f, n):
    b = b""
    while len(b) < n:
        c = f.read(n - len(b))
        if not c: raise EOFError
        b += c
    return b


class MemSrc:
    """Le chave/contador dos objetos vivos direto da memoria do L2.exe (somente leitura).
    Enderecos vem de %TEMP%\l2hook_addrs.txt (gravado por livefind.py). Nao precisa da DLL v6:
    o contador lido logo apos o frame chegar ja inclui o chunk (engine decifra em ms), entao
    inicio_do_chunk = contador_lido - soma_dos_corpos (valido p/ send e recv; confere a cada frame)."""
    def __init__(self):
        import ctypes, os, tempfile
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import keyscan
        self.k32 = keyscan.k32; self.ct = ctypes
        pid = keyscan.pid_of()
        self.h = self.k32.OpenProcess(0x0410, False, pid)
        t = open(os.path.join(tempfile.gettempdir(), "l2hook_addrs.txt")).read().split()
        self.addr = {1: int(t[0], 16), 0: int(t[1], 16)}   # dir -> endereco do objeto de chave

    def read(self, dir_):
        buf = self.ct.create_string_buffer(16); n = self.ct.c_size_t()
        self.k32.ReadProcessMemory(self.h, self.ct.c_void_p(self.addr[dir_]), buf, 16, self.ct.byref(n))
        return bytes(buf.raw)


class Live:
    def __init__(self, out=None, raw=False, mem=None):
        self.mem = mem; self.exp = {0: None, 1: None}
        self.keys = None
        self.buf = {0: b"", 1: b""}
        self.prev_s = None
        self.votes = [0, 0]          # votos: indice (0=A,1=B) e o contador do SEND
        self.out, self.raw = out, raw
        self.stats = {"pkts": 0, "bad_sync": 0}
        self.target = {}             # objectId -> {attr: valor}

    def send_idx(self):
        if self.votes[0] == self.votes[1]: return None
        return 0 if self.votes[0] > self.votes[1] else 1

    def split(self, dir_, data):
        self.buf[dir_] += data; pk = []
        while len(self.buf[dir_]) >= 2:
            n, = struct.unpack_from("<H", self.buf[dir_], 0)
            if n < 2 or len(self.buf[dir_]) < n: break
            pk.append(self.buf[dir_][2:n]); self.buf[dir_] = self.buf[dir_][n:]
        return pk

    def frame(self, dir_, cA, cB, data):
        if self.mem and dir_ in (0, 1):
            return self.frame_mem(dir_, data)
        if dir_ == 2:
            if self.mem: return
            self.keys = (data[:16], data[16:32]); self.votes = [0, 0]; self.prev_s = None
            print("[chaves recebidas da DLL]", file=sys.stderr); return
        pk = self.split(dir_, data)
        if not pk: return
        bodies = sum(len(p) for p in pk)
        if dir_ == 1:
            if self.prev_s is not None:
                dA, dB = (cA - self.prev_s[0]) & M, (cB - self.prev_s[1]) & M
                if dA == bodies and dB != bodies: self.votes[0] += 1
                if dB == bodies and dA != bodies: self.votes[1] += 1
            self.prev_s = (cA, cB)
        if self.keys is None or self.send_idx() is None:
            if self.raw: print("(sem papel de chave ainda)", "S>" if dir_ else "<R", [p[:1].hex() for p in pk])
            return
        si = self.send_idx(); idx = si if dir_ == 1 else 1 - si
        cnt = (cA, cB)[idx]
        start = (cnt - bodies) & M if dir_ == 1 else cnt
        key = bytearray(self.keys[idx]); key[8:12] = struct.pack("<I", start)
        c = L2Xor(bytes(key))
        for p in pk:
            self.show(dir_, c.decrypt(p))

    def frame_mem(self, dir_, data):
        pk = self.split(dir_, data)
        if not pk: return
        bodies = sum(len(p) for p in pk)
        k = self.mem.read(dir_)
        cnt = struct.unpack_from("<I", k, 8)[0]
        start = (cnt - bodies) & M
        e = self.exp[dir_]
        if e is not None and e != start:
            self.stats["bad_sync"] += 1
            if self.raw: print("resync", "S>" if dir_ else "<R", "esperado %x lido %x" % (e, start), file=sys.stderr)
        self.exp[dir_] = (start + bodies) & M if e is None or e == start else (cnt) & M
        key = bytearray(k); key[8:12] = struct.pack("<I", start)
        c = L2Xor(bytes(key))
        for p in pk: self.show(dir_, c.decrypt(p))

    def show(self, dir_, d):
        self.stats["pkts"] += 1
        tag = "S>" if dir_ else "<R"
        info = ""
        if dir_ == 0 and d[0] == 0x0E and len(d) >= 9 and (len(d) - 9) % 8 == 0:
            oid, n = struct.unpack_from("<II", d, 1)
            pairs = [struct.unpack_from("<II", d, 9 + 8 * i) for i in range(n)] if n < 64 else []
            st = self.target.setdefault(oid, {})
            for a, v in pairs: st[a] = v
            info = " StatusUpdate obj=0x%08x %s" % (oid, {ATTR.get(a, a): v for a, v in pairs})
        elif d[0] == 0x48 and len(d) == 21:
            x, y, z, h = struct.unpack_from("<iiii", d, 1); info = " ValidatePosition (%d,%d,%d) h=%d" % (x, y, z, h)
        elif d[0] == 0x0A and len(d) == 18:
            oid, x, y, z = struct.unpack_from("<Iiii", d, 1); info = " Attack obj=0x%08x" % oid
        if info or self.raw:
            print(tag, "op=0x%02x len=%d%s" % (d[0], len(d) + 2, info))
        if self.out:
            self.out.write(json.dumps({"t": time.time(), "dir": tag, "op": d[0], "hex": d.hex()}) + "\n"); self.out.flush()


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out"); ap.add_argument("--raw", action="store_true"); ap.add_argument("--mem", action="store_true", help="contadores lidos da memoria (usa l2hook_addrs.txt)")
    a = ap.parse_args()
    out = open(a.out, "a", encoding="utf-8") if a.out else None
    while True:
        try: f = open(PIPE, "rb", buffering=0)
        except OSError: time.sleep(1); continue
        print("conectado ao l2hook v4", file=sys.stderr)
        live = Live(out, a.raw, MemSrc() if a.mem else None)
        try:
            while True:
                dir_, n, cA, cB = struct.unpack("<BIII", read_exact(f, 13))
                live.frame(dir_, cA, cB, read_exact(f, n))
        except EOFError:
            print("pipe fechado; reconectando", file=sys.stderr)


if __name__ == "__main__":
    main()
