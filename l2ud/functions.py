"""Mapa de funções.

x64 com .pdata  -> limites EXATOS (source="pdata").
x86 / sem .pdata -> limites HEURÍSTICOS (source="heuristic"): inícios vindos de entry point, exports,
                    prólogos clássicos e alvos de call rel32; o fim é o início da próxima função.
Com Capstone, `cfg.build_function_map_cfg` refina isso para source="cfg": a cobertura é a união dos blocos
ALCANÇADOS a partir da entrada (pode ser descontínua). Só "pdata" é exato; "cfg" e "heuristic" nunca devem
ser tratados como prova. A consulta `containing` usa a cobertura real e recusa regiões sobrepostas.
"""
from __future__ import annotations

import bisect
import re
import struct
from typing import NamedTuple

from .pe import PeImage


class Function(NamedTuple):
    start: int
    end: int                   # extremo do intervalo ENVOLVENTE (para exibição); a cobertura real é `cover`
    source: str = "pdata"      # 'pdata' (exato) | 'cfg' (derivado de alcançabilidade) | 'heuristic'
    name: str | None = None    # nome de export, se houver
    ranges: tuple = ()         # intervalos REALMENTE cobertos [(a, b), ...]; vazio = o intervalo contínuo [start, end)

    @property
    def cover(self) -> tuple:
        """Intervalos que pertencem à função. Para 'cfg' são só os blocos alcançados (sem dados/padding/outras funções)."""
        return self.ranges or ((self.start, self.end),)

    @property
    def contiguous(self) -> bool:
        return len(self.cover) == 1

    @property
    def exact(self) -> bool:
        return self.source == "pdata"

    @property
    def strength(self) -> str:
        """exact = .pdata; derived = extensão do CFG (provável, não provado); weak = heurística de prólogo/call."""
        return {"pdata": "exact", "cfg": "derived"}.get(self.source, "weak")

    @property
    def label(self) -> str:
        return {"pdata": "limites exatos (.pdata)", "cfg": "limites derivados de CFG",
                "heuristic": "limites HEURÍSTICOS"}.get(self.source, self.source)


class FunctionMap:
    """Índice de funções por COBERTURA REAL (não por menor/maior endereço).
    `containing(rva)` só responde quando exatamente UMA função cobre o endereço; em região não coberta ou
    sobreposta devolve None (use `covering` para ver todas)."""

    def __init__(self, funcs: list[Function]):
        self.funcs = sorted(funcs, key=lambda f: f.start)
        iv = sorted(((a, b, f) for f in self.funcs for a, b in f.cover), key=lambda t: (t[0], t[1]))
        self._iv = iv
        self._starts = [t[0] for t in iv]
        pm, m = [], -1
        for _, b, _f in iv:
            m = max(m, b)
            pm.append(m)
        self._pmax = pm

    def __len__(self) -> int:
        return len(self.funcs)

    def covering(self, rva: int) -> list[Function]:
        """Todas as funções cujos intervalos cobrem `rva`."""
        i = bisect.bisect_right(self._starts, rva) - 1
        out: list[Function] = []
        while i >= 0 and self._pmax[i] > rva:
            a, b, f = self._iv[i]
            if a <= rva < b and f not in out:
                out.append(f)
            i -= 1
        return out

    def containing(self, rva: int, strict: bool = True) -> Function | None:
        c = self.covering(rva)
        if len(c) == 1:
            return c[0]
        if not c or strict:
            return None
        return max(c, key=lambda f: f.start)      # modo não estrito: a mais específica (maior início)

    def overlaps(self) -> list[tuple[Function, Function, int, int]]:
        """Pares de funções com intervalos de cobertura sobrepostos: (f1, f2, início, fim da sobreposição)."""
        out, active = [], []
        for a, b, f in self._iv:
            active = [(e, g) for e, g in active if e > a]
            for e, g in active:
                if g != f:
                    out.append((g, f, a, min(b, e)))
            active.append((b, f))
        return out

    @property
    def source(self) -> str:
        return self.funcs[0].source if self.funcs else "none"


_CALL = re.compile(rb"(?=\xe8(....))", re.DOTALL)
_PRO_X86 = re.compile(rb"(?=(?:\x8b\xff)?\x55\x8b\xec)")
_PRO_X64 = re.compile(rb"(?=\x48\x89\x5c\x24|\x48\x83\xec|\x40\x53\x48\x83\xec|\x40\x55)")


def build_function_map(img: PeImage) -> FunctionMap:
    names = {e.rva: e.name for e in img.exports if e.name and not e.forwarder}
    if img.functions:
        return FunctionMap([Function(b, e, "pdata", names.get(b)) for b, e in img.functions])

    execs = [s for s in img.sections if s.executable and s.raw_size and not s.discardable]
    is_code = lambda r: any(s.va <= r < s.va + s.raw_size for s in execs)  # noqa: E731
    starts: dict[int, str] = {}
    callers: dict[int, set[int]] = {}
    pro = _PRO_X64 if img.is64 else _PRO_X86
    for s in execs:
        data = img.raw[s.raw_ptr:s.raw_ptr + s.raw_size]
        for m in pro.finditer(data):
            pos = m.start()
            if not img.is64 and pos >= 2 and data[pos - 2:pos] == b"\x8b\xff":
                continue  # já contado no início do prólogo com mov edi,edi
            starts[s.va + pos] = "prologue"
        for m in _CALL.finditer(data):
            tgt = (s.va + m.start() + 5 + struct.unpack("<i", m.group(1))[0]) & 0xFFFFFFFF
            if is_code(tgt):
                callers.setdefault(tgt, set()).add(s.va + m.start())
    for tgt, cs in callers.items():
        if len(cs) >= 2 or tgt in starts:
            starts[tgt] = "call"
    if is_code(img.entry_point):
        starts[img.entry_point] = "entry"
    for rva in names:
        if is_code(rva):
            starts[rva] = "export"

    funcs: list[Function] = []
    ordered = sorted(starts)
    for i, st in enumerate(ordered):
        sec = img.section_for_rva(st)
        if sec is None:
            continue
        sec_end = sec.va + sec.raw_size
        end = ordered[i + 1] if i + 1 < len(ordered) else sec_end
        end = min(end, sec_end)
        # remove padding final (int3/zeros)
        off = img.rva_to_file(st)
        if off is None:
            continue
        n = end - st
        while n > 1 and img.raw[off + n - 1] in (0xCC, 0x00):
            n -= 1
        if n > 0:
            funcs.append(Function(st, st + n, "heuristic", names.get(st)))
    return FunctionMap(funcs)
