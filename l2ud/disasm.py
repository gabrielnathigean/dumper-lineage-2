"""Decodificação x86/x64 via Capstone (dependência OPCIONAL do modo avançado).

Sem Capstone, `available()` é False e o projeto usa o modo Lite (heurísticas de opcode).
Este módulo só DECODIFICA; grafo de fluxo, descoberta de funções e xrefs ficam em `cfg.py`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

try:  # pragma: no cover - depende do ambiente
    import capstone as _cs
    from capstone import x86 as _x86
    HAVE_CAPSTONE = True
except ImportError:  # pragma: no cover
    _cs = _x86 = None
    HAVE_CAPSTONE = False


class DisasmUnavailable(RuntimeError):
    pass


def available() -> bool:
    return HAVE_CAPSTONE


# ---- registradores canônicos: eax/ax/al -> ("rax", bits) ----
def _build_regs() -> dict[str, tuple[str, int]]:
    t: dict[str, tuple[str, int]] = {}
    for a, b, c, d in (("rax", "eax", "ax", "al"), ("rbx", "ebx", "bx", "bl"), ("rcx", "ecx", "cx", "cl"),
                       ("rdx", "edx", "dx", "dl"), ("rsi", "esi", "si", "sil"), ("rdi", "edi", "di", "dil"),
                       ("rbp", "ebp", "bp", "bpl"), ("rsp", "esp", "sp", "spl")):
        t[a], t[b], t[c], t[d] = (a, 64), (a, 32), (a, 16), (a, 8)
    for h, full in (("ah", "rax"), ("bh", "rbx"), ("ch", "rcx"), ("dh", "rdx")):
        t[h] = (full, 8)
    for n in range(8, 16):
        r = f"r{n}"
        t[r], t[r + "d"], t[r + "w"], t[r + "b"] = (r, 64), (r, 32), (r, 16), (r, 8)
    t["rip"], t["eip"] = ("rip", 64), ("rip", 32)
    return t


REGS = _build_regs()
_IGNORE_WRITES = {"eflags", "rflags", "fpsw", "mxcsr", "rip", "eip"}


def canon_reg(name: str) -> tuple[str, int]:
    """('ecx') -> ('rcx', 32). Registradores desconhecidos (xmm…) voltam como (nome, 0)."""
    return REGS.get(name.lower(), (name.lower(), 0))


@dataclass
class MemRef:
    base: str | None            # canônico (rcx para ecx/rcx)
    index: str | None
    scale: int
    disp: int                   # com sinal
    size: int
    access: int                 # bit0=read, bit1=write (0 = desconhecido)
    rip_target: int | None = None    # RVA, se base == rip (x64)
    abs_va: int | None = None        # VA absoluto (largura do ponteiro), se sem base/índice/segmento
    segment: bool = False            # fs:/gs: (TEB/TLS) — não é ponteiro de objeto


@dataclass
class Op:
    kind: str                   # 'reg' | 'imm' | 'mem'
    size: int = 0
    reg: str | None = None      # canônico
    bits: int = 0               # largura do registrador usado (64/32/16/8)
    imm: int = 0
    mem: MemRef | None = None
    access: int = 0


@dataclass
class Insn:
    rva: int
    size: int
    mnemonic: str
    op_str: str
    raw: bytes
    kind: str = "other"              # 'call' | 'jmp' | 'jcc' | 'ret' | 'other'
    target: int | None = None        # RVA de destino de branch direto
    ops: list[Op] = field(default_factory=list)
    mems: list[MemRef] = field(default_factory=list)
    imms: list[int] = field(default_factory=list)
    regs_read: list[str] = field(default_factory=list)      # canônicos
    regs_written: list[str] = field(default_factory=list)   # canônicos (sem flags/rip)
    disp_offset: int = 0             # offsets de CODIFICAÇÃO dentro da instrução (0 = ausente)
    disp_size: int = 0
    imm_offset: int = 0
    imm_size: int = 0

    @property
    def end(self) -> int:
        return self.rva + self.size

    def text(self) -> str:
        return f"{self.rva:#010x}  {self.raw.hex(' '):<24} {self.mnemonic} {self.op_str}".rstrip()


class Disassembler:
    def __init__(self, img):
        if not HAVE_CAPSTONE:
            raise DisasmUnavailable("Capstone não instalado (pip install capstone)")
        self.img = img
        self.md = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_64 if img.is64 else _cs.CS_MODE_32)
        self.md.detail = True
        self.mask = 0xFFFFFFFFFFFFFFFF if img.is64 else 0xFFFFFFFF
        self.ptr_size = 8 if img.is64 else 4
        self.ptr_bits = 64 if img.is64 else 32

    # ---- bytes ----
    def _bytes(self, rva: int, size: int) -> bytes:
        s = self.img.section_for_rva(rva)
        off = self.img.rva_to_file(rva)
        if s is None or off is None:
            return b""
        avail = s.raw_size - (rva - s.va)
        return self.img.raw[off:off + max(0, min(size, avail))]

    def is_code(self, rva: int) -> bool:
        s = self.img.section_for_rva(rva)
        return bool(s and s.executable and self.img.rva_to_file(rva) is not None)

    # ---- conversão ----
    def _convert(self, i) -> Insn:
        g = set(i.groups)
        kind = "other"
        if _cs.CS_GRP_CALL in g:
            kind = "call"
        elif _cs.CS_GRP_RET in g:
            kind = "ret"
        elif _cs.CS_GRP_JUMP in g:
            kind = "jmp" if i.mnemonic == "jmp" else "jcc"
        ins = Insn(i.address, i.size, i.mnemonic, i.op_str, bytes(i.bytes), kind)
        ins.disp_offset, ins.disp_size = getattr(i, "disp_offset", 0), getattr(i, "disp_size", 0)
        ins.imm_offset, ins.imm_size = getattr(i, "imm_offset", 0), getattr(i, "imm_size", 0)
        for op in i.operands:
            acc = getattr(op, "access", 0)
            if op.type == _cs.CS_OP_IMM:
                ins.ops.append(Op("imm", op.size, imm=op.imm & self.mask, access=acc))
                if kind in ("call", "jmp", "jcc"):
                    ins.target = op.imm & self.mask
                else:
                    ins.imms.append(op.imm & self.mask)
            elif op.type == _cs.CS_OP_REG:
                nm, bits = canon_reg(i.reg_name(op.reg))
                ins.ops.append(Op("reg", op.size, reg=nm, bits=bits, access=acc))
            elif op.type == _cs.CS_OP_MEM:
                m = op.mem
                base = canon_reg(i.reg_name(m.base))[0] if m.base else None
                index = canon_reg(i.reg_name(m.index))[0] if m.index else None
                seg = bool(getattr(m, "segment", 0))
                ref = MemRef(base, index, m.scale, m.disp, op.size, acc, segment=seg)
                if m.base == _x86.X86_REG_RIP:
                    ref.rip_target = (i.address + i.size + m.disp) & self.mask
                elif not m.base and not m.index and not seg:
                    ref.abs_va = m.disp & self.mask      # x64: moffs de 64 bits NÃO pode ser truncado para 32
                ins.mems.append(ref)
                ins.ops.append(Op("mem", op.size, mem=ref, access=acc))
        try:
            rd, wr = i.regs_access()
            ins.regs_read = list(dict.fromkeys(canon_reg(i.reg_name(r))[0] for r in rd))
            ins.regs_written = list(dict.fromkeys(
                canon_reg(i.reg_name(r))[0] for r in wr if i.reg_name(r) not in _IGNORE_WRITES))
        except Exception:  # alguns insns não expõem regs_access
            pass
        return ins

    # ---- decodificação ----
    def decode_one(self, rva: int) -> Insn | None:
        code = self._bytes(rva, 16)
        if not code:
            return None
        for i in self.md.disasm(code, rva, 1):
            return self._convert(i)
        return None

    def decode(self, rva: int, count: int = 32, max_bytes: int = 0x400) -> list[Insn]:
        out: list[Insn] = []
        for ins in self.sweep(rva, rva + max_bytes):
            out.append(ins)
            if len(out) >= count:
                break
        return out

    def sweep(self, start: int, end: int) -> Iterator[Insn]:
        """Varredura LINEAR de [start, end) com ressincronização (pula 1 byte em byte inválido).
        Pode interpretar dados como código: use `cfg.build_cfg` para código alcançável."""
        pos = start
        while pos < end:
            code = self._bytes(pos, end - pos)
            if not code:
                return
            for i in self.md.disasm(code, pos):
                yield self._convert(i)
                pos = i.address + i.size
            if pos >= end:
                return
            pos += 1

    def read_ptr_table(self, table_rva: int, max_entries: int = 256, stride: int = 4):
        """Lê entradas de tabela de saltos (VA absolutos de 32 bits em x86) -> lista de VAs brutos."""
        out = []
        for k in range(max_entries):
            b = self.img.read_rva(table_rva + k * stride, stride)
            if b is None:
                break
            out.append(int.from_bytes(b, "little"))
        return out
