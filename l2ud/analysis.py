"""Análise: strings, xrefs (modo Lite por opcode / modo Capstone), fingerprint, imports.

Modo Lite  : heurísticas de opcode. Pode confundir dados com instruções -> use como CANDIDATO.
Modo Capstone: varredura linear por função com decodificação real (opcional, `pip install capstone`).
Nenhum dos dois é prova semântica de que um endereço é "o" ponteiro de algo.
"""
from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass

from .functions import Function, FunctionMap, build_function_map
from .pe import PeImage

# ---- Lite: opcodes com ModRM [rip+disp32] (x64) ----
_IMM = {0xC7: 4, 0x81: 4, 0x83: 1, 0x80: 1, 0xC6: 1}
_PLAIN = [0x8D, 0x8B, 0x89, 0x3B, 0x39, 0x03, 0x2B, 0x01, 0x29, 0x33, 0x31, 0x85, 0x84, 0x88, 0x8A, 0x0B, 0x09, 0x23, 0x21, 0xFF]
_OPS = bytes(sorted(set(_PLAIN) | set(_IMM)))
_RIP_RX = re.compile(
    rb"(?=([\x40-\x4f]?)(\x0f[\x10\x11\x28\x29\xb6\xb7\xbe\xbf]|[" + re.escape(_OPS) + rb"])"
    rb"[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](....))", re.DOTALL)
_REL_RX = re.compile(rb"(?=([\xe8\xe9])(....))", re.DOTALL)


@dataclass
class Xref:
    from_rva: int          # início da instrução (Capstone) ou do operando (kind 'abs'/'ptr' do Lite)
    kind: str              # 'rip' | 'call' | 'jmp' | 'abs' | 'imm' | 'ptr'
    target_rva: int
    function: Function | None = None
    engine: str = "lite"       # 'lite' | 'capstone'
    via: str = "opcode"        # 'opcode' (heurística) | 'reloc' | 'cfg' (alcançável) | 'linear' (varredura, ambíguo)
    rw: str = ""               # 'r' | 'w' | 'rw' | 'addr' (lea) — só com Capstone

    @property
    def trusted(self) -> bool:
        """Usável como corroboração: nunca a varredura linear pura (pode ser dado lido como instrução)."""
        return self.via != "linear"


def _exec_sections(img: PeImage):
    for s in img.sections:
        if s.executable and s.raw_size and not s.discardable:
            yield s


def reloc_refs(img: PeImage) -> list[Xref]:
    """Referências absolutas descobertas via tabela de relocação (a única fonte confiável no modo Lite x86)."""
    out = []
    for rva, typ in img.relocs:
        if typ == 3:       # HIGHLOW (32 bits)
            b = img.read_rva(rva, 4)
            val = struct.unpack("<I", b)[0] if b else None
        elif typ == 10:    # DIR64
            b = img.read_rva(rva, 8)
            val = struct.unpack("<Q", b)[0] if b else None
        else:
            continue
        if val is None:
            continue
        tgt = val - img.image_base
        if 0 <= tgt < 0x80000000 and img.section_for_rva(tgt):
            s = img.section_for_rva(rva)
            out.append(Xref(rva, "abs" if s is not None and s.executable else "ptr", tgt, None, "lite", "reloc"))
    return out


def lite_xrefs(img: PeImage, fmap: FunctionMap | None = None) -> list[Xref]:
    out: dict[tuple[int, str], Xref] = {}
    for s in _exec_sections(img):
        data = img.raw[s.raw_ptr:s.raw_ptr + s.raw_size]
        if img.is64:
            for m in _RIP_RX.finditer(data):
                op = m.group(2)
                disp_pos = m.start(3)
                imm = _IMM.get(op[0], 0) if len(op) == 1 else 0
                disp = struct.unpack("<i", m.group(3))[0]
                end = s.va + disp_pos + 4 + imm
                start = s.va + m.start()
                key = (disp_pos + s.va, "rip")
                if key not in out or start < out[key].from_rva:
                    out[key] = Xref(start, "rip", (end + disp) & 0xFFFFFFFF)
        for m in _REL_RX.finditer(data):
            disp = struct.unpack("<i", m.group(2))[0]
            tgt = (s.va + m.start() + 5 + disp) & 0xFFFFFFFF
            t = img.section_for_rva(tgt)
            if t is not None and t.executable:
                out[(m.start() + s.va, "rel")] = Xref(s.va + m.start(), "call" if m.group(1) == b"\xe8" else "jmp", tgt)
    xs = list(out.values()) + reloc_refs(img)
    xs.sort(key=lambda x: (x.from_rva, x.kind))
    if fmap is not None:
        for x in xs:
            x.function = fmap.containing(x.from_rva)
    return xs


def all_code_xrefs(img: PeImage, fmap: FunctionMap | None = None) -> list[Xref]:
    """Compat: xrefs do modo Lite."""
    return lite_xrefs(img, fmap or build_function_map(img))


def get_xrefs(img: PeImage, engine: str = "auto", fmap: FunctionMap | None = None) -> tuple[list[Xref], str]:
    """engine: 'lite' | 'capstone' | 'auto' (capstone se instalado). Retorna (xrefs, motor_usado)."""
    ctx = Context(img, engine)
    if fmap is not None:
        ctx._fmap = fmap
    return ctx.xrefs, ctx.engine_used


def xrefs_to(img: PeImage, target_rva: int, xrefs: list[Xref] | None = None) -> list[Xref]:
    xs = xrefs if xrefs is not None else all_code_xrefs(img)
    return [x for x in xs if x.target_rva == target_rva]


def import_refs(img: PeImage, xrefs: list[Xref]) -> list[tuple[Xref, str]]:
    """Xrefs que apontam para um slot da IAT -> (xref, 'dll!nome')."""
    iat = {i.iat_rva: f"{i.dll}!{i.name}" for i in img.imports}
    return [(x, iat[x.target_rva]) for x in xrefs if x.target_rva in iat]


# ---------------- strings / fingerprint ----------------
@dataclass
class FoundString:
    rva: int
    text: str
    wide: bool
    section: str


def find_strings(img: PeImage, query: str | None = None, min_len: int = 5, limit: int = 50000) -> list[FoundString]:
    out: list[FoundString] = []
    ascii_rx = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    wide_rx = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    q = query.lower() if query else None
    for s in img.sections:
        if not s.raw_size or s.discardable or s.executable:
            continue
        data = img.raw[s.raw_ptr:s.raw_ptr + s.raw_size]
        for rx, wide in ((ascii_rx, False), (wide_rx, True)):
            for m in rx.finditer(data):
                txt = m.group().decode("utf-16le" if wide else "latin-1")
                if q and q not in txt.lower():
                    continue
                out.append(FoundString(s.va + m.start(), txt, wide, s.name))
                if len(out) >= limit:
                    return out
    out.sort(key=lambda f: f.rva)
    return out


def fingerprint(img: PeImage) -> str:
    h = hashlib.sha256()
    h.update(img.arch.encode())
    for s in img.sections:
        h.update(f"{s.name}:{s.vsize}:{s.raw_size}:{s.flags}".encode())
        if s.executable:
            h.update(hashlib.sha256(img.raw[s.raw_ptr:s.raw_ptr + s.raw_size]).digest())
    return h.hexdigest()[:32]


class Context:
    """Cache preguiçoso por imagem: mapa de funções, CFGs e xrefs (evita recomputar a cada assinatura).

    engine      : 'lite' | 'capstone' | 'auto'
    use_cfg     : com Capstone, deriva limites de função e xrefs por alcançabilidade (CFG)
    include_linear : mantém a varredura linear como complemento (xrefs via='linear', não confiáveis)
    """

    def __init__(self, img: PeImage, engine: str = "auto", use_cfg: bool = True, include_linear: bool = True):
        if engine not in ("lite", "capstone", "auto"):
            raise ValueError(f"engine inválido: {engine}")
        self.img, self.engine_req = img, engine
        self.use_cfg, self.include_linear = use_cfg, include_linear
        self._fmap: FunctionMap | None = None
        self._xrefs: list[Xref] | None = None
        self._disasm = None
        self.cfgs: dict = {}
        self.engine_used = ""

    @property
    def capstone(self) -> bool:
        from . import disasm
        if self.engine_req == "capstone" and not disasm.available():
            raise disasm.DisasmUnavailable("Capstone não instalado (pip install capstone)")
        return self.engine_req != "lite" and disasm.available()

    @property
    def reloc_locs(self) -> set[int]:
        """RVAs onde há relocação (HIGHLOW/DIR64): marcam campos que são ENDEREÇOS (e não constantes)."""
        if getattr(self, "_reloc_locs", None) is None:
            self._reloc_locs = {rva for rva, typ in self.img.relocs if typ in (3, 10)}
        return self._reloc_locs

    @property
    def engine_label(self) -> str:
        """Motor efetivo ('capstone' | 'lite'), mesmo antes de calcular xrefs."""
        return "capstone" if self.capstone else "lite"

    @property
    def disassembler(self):
        if self._disasm is None:
            from . import disasm
            self._disasm = disasm.Disassembler(self.img)
        return self._disasm

    @property
    def fmap(self) -> FunctionMap:
        if self._fmap is None:
            if self.capstone and self.use_cfg:
                from .cfg import build_function_map_cfg
                self._fmap, self.cfgs = build_function_map_cfg(self.img, self.disassembler)
            else:
                self._fmap = build_function_map(self.img)
        return self._fmap

    def cfg(self, fn_or_rva):
        """CFG da função (Function ou RVA). None sem Capstone ou sem função conhecida."""
        if not self.capstone:
            return None
        fn = fn_or_rva if isinstance(fn_or_rva, Function) else self.fmap.containing(fn_or_rva)
        if fn is None:
            return None
        if fn.start not in self.cfgs:
            from .cfg import build_cfg
            limit = (fn.start, fn.end) if fn.exact else None
            known = frozenset(f.start for f in self.fmap.funcs) if not fn.exact else frozenset()
            self.cfgs[fn.start] = build_cfg(self.img, self.disassembler, fn.start, limit, known)
        return self.cfgs[fn.start]

    @property
    def xrefs(self) -> list[Xref]:
        if self._xrefs is None:
            if self.capstone:
                from .cfg import collect_xrefs
                xs = collect_xrefs(self.img, self.fmap, self.cfg, self.include_linear)
                xs += [x for x in reloc_refs(self.img) if x.kind == "ptr"]  # ponteiros em dados
                xs.sort(key=lambda x: (x.from_rva, x.kind))
                for x in xs:
                    if x.function is None:
                        x.function = self.fmap.containing(x.from_rva)
                self._xrefs, self.engine_used = xs, "capstone"
            else:
                self._xrefs, self.engine_used = lite_xrefs(self.img, self.fmap), "lite"
        return self._xrefs


# ---------------- utilidades de inspeção ----------------
def hexdump(img: PeImage, rva: int, length: int = 256, width: int = 16) -> str:
    data = img.read_rva(rva, length)
    if data is None:  # tenta o que existir até o fim da seção
        s = img.section_for_rva(rva)
        off = img.rva_to_file(rva)
        if s is None or off is None:
            return f"RVA {rva:#x} não mapeado em disco"
        data = img.raw[off:off + min(length, s.raw_size - (rva - s.va))]
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{rva + i:#010x}  {hx}  {asc}")
    return "\n".join(lines)


def hexdump_file(img: PeImage, off: int, length: int = 256, width: int = 16) -> str:
    """Hexdump por FILE OFFSET (mostra também o RVA correspondente de cada linha, quando existir)."""
    data = img.raw[off:off + length]
    if not data:
        return f"file offset {off:#x} fora do arquivo ({len(img.raw):#x} bytes)"
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        r = img.file_to_rva(off + i)
        lines.append(f"{off + i:#010x}  {hx}  {asc}   rva={'-' if r is None else f'{r:#x}'}")
    return "\n".join(lines)


def string_at(img: PeImage, rva: int, min_len: int = 4) -> str | None:
    b = img.read_rva(rva, 160) or img.read_rva(rva, 16)
    if not b:
        return None
    m = re.match(rb"[\x20-\x7e]{%d,}\x00" % min_len, b)
    if m:
        return m.group()[:-1].decode("latin-1")
    m = re.match(rb"(?:[\x20-\x7e]\x00){%d,}\x00\x00" % min_len, b)
    if m:
        return m.group()[:-2].decode("utf-16le")
    return None


def analyze_function(img: PeImage, ctx: Context, rva: int) -> dict | None:
    """Limites, origem dos limites, chamadores, chamados, strings e imports referenciados."""
    fn = ctx.fmap.containing(rva)
    if fn is None:
        return None
    xs = ctx.xrefs
    imports = {i.iat_rva: f"{i.dll}!{i.name}" for i in img.imports}
    callers = sorted({x.from_rva for x in xs if x.kind in ("call", "jmp") and x.target_rva == fn.start})
    callees, strs, imps = set(), {}, set()
    for x in xs:
        if not (fn.start <= x.from_rva < fn.end):
            continue
        if x.kind in ("call", "jmp") and not (fn.start <= x.target_rva < fn.end):
            callees.add(x.target_rva)
        elif x.target_rva in imports:
            imps.add(imports[x.target_rva])
        else:
            s = string_at(img, x.target_rva)
            if s:
                strs[x.target_rva] = s
    out = {"function": fn, "exact_bounds": fn.exact, "bounds_label": fn.label,
           "engine": ctx.engine_used or ctx.engine_req,
           "callers": callers, "callees": sorted(callees), "strings": strs, "imports": sorted(imps)}
    cfg = ctx.cfg(fn)
    if cfg is not None:
        out["cfg"] = cfg.summary()
        out["ambiguous"] = [(a, b, t) for a, b, t in cfg.ambiguous if t != "padding"]
    return out
