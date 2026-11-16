"""Cifra XOR em cadeia do L2 (Interlude), chave de 16 bytes; bytes 8..11 sao um contador LE somado do tamanho do corpo a cada pacote."""

class L2Xor:
    def __init__(self, key16: bytes):
        self.key = bytearray(key16)

    def _bump(self, n):
        v = int.from_bytes(self.key[8:12], 'little')
        self.key[8:12] = ((v + n) & 0xFFFFFFFF).to_bytes(4, 'little')

    def decrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data)); t = 0
        for i, c in enumerate(data):
            out[i] = c ^ self.key[i & 15] ^ t; t = c
        self._bump(len(data)); return bytes(out)

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data)); t = 0
        for i, p in enumerate(data):
            t = p ^ self.key[i & 15] ^ t; out[i] = t
        self._bump(len(data)); return bytes(out)
