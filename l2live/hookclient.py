"""Cliente Python do pipe da l2hook.dll (fase 1: captura passiva).

Uso: py -3 hookclient.py [--hex] [--out capture.jsonl]
Frame do pipe: u8 dir (0=recv,1=send) | u32 len | bytes.
Os dados do L2 sao um fluxo: pacote = u16 len (inclui os 2 bytes) + corpo.
O corpo costuma estar cifrado (XOR com chave por conexao) - aqui so reagrupamos.
"""
import argparse, json, struct, sys, time

PIPE = r"\\.\pipe\l2hook"


def read_exact(f, n):
    b = b""
    while len(b) < n:
        c = f.read(n - len(b))
        if not c:
            raise EOFError
        b += c
    return b


def frames(f):
    while True:
        dir_, = struct.unpack("<B", read_exact(f, 1))
        n, = struct.unpack("<I", read_exact(f, 4))
        yield dir_, read_exact(f, n)


class Reassembler:
    """Reagrupa o fluxo TCP em pacotes L2 (u16 len little-endian, inclui o proprio campo)."""

    def __init__(self):
        self.buf = {0: b"", 1: b""}

    def feed(self, dir_, data):
        self.buf[dir_] += data
        out = []
        while len(self.buf[dir_]) >= 2:
            n, = struct.unpack_from("<H", self.buf[dir_], 0)
            if n < 2 or len(self.buf[dir_]) < n:
                break
            out.append(self.buf[dir_][2:n])
            self.buf[dir_] = self.buf[dir_][n:]
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hex", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    out = open(a.out, "a", encoding="utf-8") if a.out else None
    while True:
        try:
            f = open(PIPE, "rb", buffering=0)
        except OSError:
            time.sleep(1)
            continue
        print("conectado ao l2hook", file=sys.stderr)
        ra = Reassembler()
        try:
            for dir_, data in frames(f):
                for pkt in ra.feed(dir_, data):
                    tag = "S>" if dir_ else "<R"
                    line = {"t": time.time(), "dir": tag, "len": len(pkt) + 2,
                            "op": pkt[0] if pkt else None}
                    if a.hex:
                        line["hex"] = pkt.hex()
                    print(tag, "op=0x%02x" % pkt[0] if pkt else "-", "len", len(pkt) + 2,
                          pkt.hex()[:48] if a.hex else "")
                    if out:
                        out.write(json.dumps(line) + "\n"); out.flush()
        except EOFError:
            print("pipe fechado; reconectando", file=sys.stderr)


if __name__ == "__main__":
    main()
