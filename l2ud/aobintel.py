"""AOB Intelligence: valida assinaturas contra a instrução real (Capstone), gera padrões assistidos,
detecta bytes variáveis entre builds, analisa o contexto e acusa padrões genéricos demais.

Tudo aqui é auxílio: sugestões NUNCA são aplicadas sozinhas e nada aqui promove status de resultado.
Requer Capstone (exceto `variable_bytes_at`, que só compara bytes).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import aob
from .analysis import Context
from .siginfo import Quality, pattern_quality

MAX_FIELD_DISP = 0x10000


# ------------------------------------------------------------------ 1) validação da instrução
@dataclass
class SigCheck:
    ok: bool
    issues: list[str] = field(default_factory=list)
    instruction: str = ""
    actual: dict = field(default_factory=dict)      # disp_offset / insn_len reais
    suggestion: dict = field(default_factory=dict)  # valores corrigidos sugeridos


def _instruction_starts(ctx: Context, rva: int) -> tuple[set[int] | None, tuple[int, int] | None]:
    """Inícios de instrução ALCANÇÁVEIS na função que contém `rva` (via CFG, com cache por função).
    Retorna (None, None) se não houver função/CFG para o ponto."""
    cfg = ctx.cfg(rva)
    if cfg is None:
        return None, None
    cache = ctx.__dict__.setdefault("_istarts", {})
    starts = cache.get(cfg.entry)
    if starts is None:
        starts = cache[cfg.entry] = {i.rva for b in cfg.blocks.values() for i in b.insns}
    rng = next(((a, b) for a, b in cfg.reachable if a <= rva < b), None)
    return starts, rng


def _instruction_with_field(d, hit_rva: int, off: int, max_insns: int = 12):
    """Decodifica a partir do match até achar a instrução que CONTÉM o byte `hit+off`.
    (disp_offset é relativo ao início do match, que pode abranger várias instruções.)"""
    pos, target = hit_rva, hit_rva + off
    for _ in range(max_insns):
        ins = d.decode_one(pos)
        if ins is None:
            return None
        if ins.rva <= target < ins.end:
            return ins
        pos = ins.end
    return None


def check_resolution(img, ctx: Context, hit_rva: int, sig: dict) -> SigCheck:
    """Confere se `disp_offset`/`insn_len`/`kind` descrevem uma instrução real decodificada no match.
    Offsets da assinatura são relativos ao INÍCIO DO MATCH; a instrução que contém o campo pode não ser a primeira."""
    d = ctx.disassembler
    kind = sig.get("kind", "rip")
    first = d.decode_one(hit_rva)
    if first is None:
        return SigCheck(False, ["nenhuma instrução decodifica no endereço do match"])
    res = SigCheck(True, [], first.text().strip())
    starts, rng = _instruction_starts(ctx, hit_rva)
    if starts is not None and rng is not None and hit_rva not in starts:
        res.ok = False
        res.issues.append("o match começa no MEIO de uma instrução (fronteira de instrução diferente da decodificada pelo CFG)")
    if kind == "hit":
        return res
    off = int(sig.get("disp_offset", 0))
    declared_len = int(sig.get("insn_len", off + 4))
    ins = _instruction_with_field(d, hit_rva, off)
    if ins is None:
        res.ok = False
        res.issues.append(f"nenhuma instrução decodificada contém o byte do campo declarado (disp_offset {off})")
        return res
    res.instruction = ins.text().strip()
    rel = ins.rva - hit_rva                      # início da instrução relativo ao match
    exp_len = ins.end - hit_rva                  # fim da instrução relativo ao match (o RIP usa o FIM)
    res.actual = {"insn_len": exp_len, "disp_offset": rel + ins.disp_offset, "imm_offset": rel + ins.imm_offset,
                  "instruction_at": rel}

    if kind == "rip":
        m = next((m for m in ins.mems if m.rip_target is not None), None)
        if m is None:
            res.ok = False
            res.issues.append("a instrução decodificada não tem operando [rip+disp] (kind 'rip' inválido)")
            return res
        exp_off = rel + ins.disp_offset
        res.suggestion = {"disp_offset": exp_off, "insn_len": exp_len}
        if off != exp_off:
            res.ok = False
            res.issues.append(f"disp_offset declarado {off} != real {exp_off}")
        if declared_len != exp_len:
            res.ok = False
            res.issues.append(f"insn_len declarado {declared_len} != tamanho real da instrução {exp_len} "
                              "(o RIP relativo usa o FIM da instrução)")
    elif kind in ("rel", "rel8"):
        if ins.kind not in ("call", "jmp", "jcc") or ins.target is None:
            res.ok = False
            res.issues.append(f"a instrução decodificada não é um branch direto (kind '{kind}' inválido)")
            return res
        want = 4 if kind == "rel" else 1
        have = ins.imm_size or 0
        exp_off = rel + (ins.imm_offset if have else ins.size - want)
        right_kind = "rel" if have == 4 else "rel8" if have == 1 else kind
        res.suggestion = {"kind": right_kind, "disp_offset": exp_off, "insn_len": exp_len}
        if have and have != want:
            res.ok = False
            res.issues.append(f"kind '{kind}' exige operando rel{want * 8}, mas a instrução tem rel{have * 8}: "
                              f"use kind '{right_kind}'")
        if off != exp_off:
            res.ok = False
            res.issues.append(f"disp_offset declarado {off} != posição real do operando relativo ({exp_off})")
        if declared_len != exp_len:
            res.ok = False
            res.issues.append(f"insn_len declarado {declared_len} != tamanho real {exp_len}")
    elif kind == "abs":
        size = 8 if img.is64 else 4
        cand = []
        if any(m.abs_va is not None for m in ins.mems) and ins.disp_size == size:
            cand.append(rel + ins.disp_offset)
        if ins.imm_size == size:
            cand.append(rel + ins.imm_offset)
        if not cand:
            res.ok = False
            res.issues.append("a instrução não contém operando absoluto do tamanho de ponteiro")
            return res
        res.suggestion = {"disp_offset": cand[0]}
        if off not in cand:
            res.ok = False
            res.issues.append(f"disp_offset declarado {off} não coincide com operando absoluto real ({cand})")
    elif kind == "imm":
        size = int(sig.get("size", 4))
        fields_ = [(rel + ins.disp_offset, ins.disp_size, "deslocamento"), (rel + ins.imm_offset, ins.imm_size, "imediato")]
        match = next((f for f in fields_ if f[1] and f[0] == off and f[1] == size), None)
        if match is None:
            real = [f"{n}@{o} ({s} bytes)" for o, s, n in fields_ if s]
            res.ok = False
            res.issues.append(f"o campo declarado (offset {off}, {size} bytes) não coincide com a codificação real: "
                              f"{real or 'sem deslocamento/imediato'}")
            if real:
                o, s, _ = next(f for f in fields_ if f[1])
                res.suggestion = {"disp_offset": o, "size": s}
    return res


# ------------------------------------------------------------------ 2) geração assistida
@dataclass
class Suggestion:
    pattern: str
    hits: int
    unique: bool
    quality: Quality
    instructions: list[str]
    notes: list[str] = field(default_factory=list)
    start_reliable: bool | None = None      # True = RVA é início de instrução alcançada; False = não é; None = não verificável


def _wild_mask(img, ins, wild_fields: bool) -> tuple[list[bool], list[str]]:
    """Quais bytes da instrução devem virar wildcard (endereços mudam entre builds)."""
    mask = [False] * ins.size
    why: list[str] = []

    def mark(off: int, n: int, reason: str) -> None:
        if n and 0 <= off and off + n <= ins.size:
            for i in range(off, off + n):
                mask[i] = True
            why.append(f"{ins.rva:#x}: {reason}")

    for m in ins.mems:
        if m.rip_target is not None:
            mark(ins.disp_offset, ins.disp_size, "disp32 rip-relativo")
        elif m.abs_va is not None:
            mark(ins.disp_offset, ins.disp_size, "endereço absoluto (relocável)")
        elif wild_fields and m.base and 0 <= abs(m.disp) < MAX_FIELD_DISP and ins.disp_size:
            mark(ins.disp_offset, ins.disp_size, f"deslocamento de campo {m.disp:#x} (--wild-fields)")
    if ins.target is not None and ins.kind in ("call", "jmp", "jcc"):
        if ins.imm_size:
            mark(ins.imm_offset, ins.imm_size, "destino relativo de branch")
        else:
            mark(ins.size - min(4, ins.size - 1), min(4, ins.size - 1), "destino relativo de branch")
    if not img.is64:
        for v in ins.imms:
            r = v - img.image_base
            if r >= 0 and img.section_for_rva(r) and ins.imm_size:
                mark(ins.imm_offset, ins.imm_size, "imediato que é VA da imagem (relocável)")
    return mask, why


def generate(img, ctx: Context, rva: int, max_len: int = 48, wild_fields: bool = False,
             max_insns: int = 14, section: list[str] | None = None, require_boundary: bool = False) -> Suggestion:
    """Gera um padrão a partir de instruções reais começando em `rva`: opera/ModRM fixos, endereços e
    destinos relativos como wildcard; estende instrução a instrução até ser ÚNICO nesta imagem.
    Verifica se `rva` é INÍCIO de instrução alcançada (CFG): se não for, avisa (`start_reliable=False`) e, com
    `require_boundary=True`, recusa gerar."""
    d = ctx.disassembler
    starts, _rng = _instruction_starts(ctx, rva)
    start_ok: bool | None = None if starts is None else (rva in starts)
    boundary_note = None
    if start_ok is None:
        boundary_note = "fronteira de instrução NÃO verificável: sem função/CFG conhecido para este ponto"
    elif not start_ok:
        boundary_note = ("ATENÇÃO: este RVA NÃO é início de instrução alcançada pelo CFG (pode ser meio de instrução, "
                         "dado ou região ambígua): o padrão gerado pode ser inválido")
        if require_boundary:
            return Suggestion("", 0, False, pattern_quality("00 00 00 00 00"), [], [boundary_note, "geração recusada (--strict-boundary)"], False)
    pos = rva
    tokens: list[str] = []
    insns: list[str] = []
    notes: list[str] = [boundary_note] if boundary_note else []
    best: Suggestion | None = None
    last: Suggestion | None = None
    for _ in range(max_insns):
        ins = d.decode_one(pos)
        if ins is None:
            notes.append(f"instrução inválida em {pos:#x}; geração interrompida")
            break
        mask, why = _wild_mask(img, ins, wild_fields)
        notes += why
        tokens += ["??" if mask[i] else f"{b:02X}" for i, b in enumerate(ins.raw)]
        insns.append(ins.text().strip())
        pos = ins.end
        if len(tokens) > max_len:
            notes.append(f"limite de {max_len} bytes atingido")
            break
        pat = " ".join(tokens)
        fixed = sum(1 for t in tokens if t != "??")
        if fixed < 3:
            continue
        hits = len(aob.scan(img, pat, section))
        last = Suggestion(pat, hits, hits == 1, pattern_quality(pat), list(insns), list(notes), start_ok)
        if hits == 1 and not last.quality.fragile:
            best = last
            break
    out = best or last
    if out is None:
        return Suggestion("", 0, False, pattern_quality("00 00 00 00 00"), insns, notes + ["nada gerado"], start_ok)
    if not out.unique:
        out.notes.append(f"padrão ainda casa {out.hits} vez(es): aumente --max-len ou use outro ponto")
    elif out.quality.fragile:
        out.notes.append("único, porém frágil (poucos bytes fixos)")
    return out


# ------------------------------------------------------------------ 3) bytes variáveis entre builds
@dataclass
class VarReport:
    labels: list[str]
    start: int                    # offset relativo (negativo = antes do ponto)
    rows: dict[str, bytes]
    variable: list[int]           # offsets relativos que diferem entre builds
    stable: list[int]
    suggested_core: str           # só a região [0,length)
    suggested_extended: str       # janela completa, sem wildcards nas pontas
    notes: list[str] = field(default_factory=list)


def variable_bytes_at(points: dict[str, tuple[object, int]], length: int, before: int = 0, after: int = 0) -> VarReport:
    """`points`: rótulo -> (PeImage, rva do início da assinatura NAQUELA build).
    Compara a janela [rva-before, rva+length+after) entre as builds: o que muda vira wildcard sugerido."""
    rows: dict[str, bytes] = {}
    notes: list[str] = []
    for lbl, (img, rva) in points.items():
        b = img.read_rva(rva - before, before + length + after)
        if b is None:
            notes.append(f"{lbl}: janela não mapeada em disco; ignorada")
        else:
            rows[lbl] = b
    if len(rows) < 2:
        return VarReport(list(rows), -before, rows, [], [], "", "", notes + ["precisa de ≥2 builds com a janela mapeada"])
    n = before + length + after
    variable, stable = [], []
    for i in range(n):
        col = {r[i] for r in rows.values()}
        (variable if len(col) > 1 else stable).append(i - before)
    first = next(iter(rows.values()))
    tok = lambda i: f"{first[i + before]:02X}" if (i in stable) else "??"  # noqa: E731
    core = " ".join(tok(i) for i in range(0, length))
    win = [tok(i) for i in range(-before, length + after)]
    while win and win[0] == "??":
        win.pop(0)
    while win and win[-1] == "??":
        win.pop()
    return VarReport(list(rows), -before, rows, variable, stable, core, " ".join(win), notes)


def find_points(images: dict[str, object], pattern: str) -> tuple[dict[str, tuple[object, int]], list[str]]:
    """Localiza `pattern` em cada build (só aceita match ÚNICO). Retorna pontos e avisos."""
    pts, warn = {}, []
    for lbl, img in images.items():
        hs = aob.scan(img, pattern)
        if len(hs) == 1:
            pts[lbl] = (img, hs[0].rva)
        else:
            warn.append(f"{lbl}: {len(hs)} matches (precisa de exatamente 1)")
    return pts, warn


# ------------------------------------------------------------------ 4) contexto antes/depois
def analyze_context(img, ctx: Context, rva: int, before: int = 4, after: int = 6) -> dict:
    """Instruções vizinhas ao ponto. Usa as instruções ALCANÇÁVEIS da função (CFG), pois decodificar
    'para trás' em x86 é ambíguo; se não houver CFG, avisa."""
    fn = ctx.fmap.containing(rva)
    cfg = ctx.cfg(rva) if fn else None
    if cfg is None:
        return {"function": None, "before": [], "at": None, "after": [],
                "note": "sem função/CFG para este ponto: contexto anterior seria ambíguo (x86 tem instruções de tamanho variável)"}
    insns = sorted((i for b in cfg.blocks.values() for i in b.insns), key=lambda i: i.rva)
    idx = next((k for k, i in enumerate(insns) if i.rva == rva), None)
    if idx is None:
        return {"function": fn, "before": [], "at": None, "after": [],
                "note": "o ponto não é início de instrução alcançável nesta função (pode ser meio de instrução, dado ou região ambígua)"}
    return {"function": fn, "before": [i.text() for i in insns[max(0, idx - before):idx]],
            "at": insns[idx].text(), "after": [i.text() for i in insns[idx + 1:idx + 1 + after]],
            "note": f"{fn.label}; instruções em ordem de endereço (não necessariamente ordem de execução)"}


# ------------------------------------------------------------------ 5) genericidade
def genericity(img, ctx: Context, pattern: str, max_ok_hits: int = 1) -> dict:
    """Quantos matches, quantas instruções o padrão cobre e se é genérico demais."""
    hits = aob.scan(img, pattern)
    q = pattern_quality(pattern)
    flags: list[str] = []
    covered = None
    if hits:
        d = ctx.disassembler
        n = len(pattern.split())
        pos, covered = hits[0].rva, 0
        while pos < hits[0].rva + n:
            ins = d.decode_one(pos)
            if ins is None:
                break
            covered += 1
            pos = ins.end
        if covered <= 1 and len(hits) > 1:
            flags.append("single_instruction")        # cobre ≤1 instrução e casa em vários lugares
    if len(hits) > max_ok_hits:
        flags.append("too_many_matches")
    if len(hits) > 50:
        flags.append("generic")
    if q.fragile:
        flags.append("fragile_pattern")
    return {"hits": len(hits), "covered_instructions": covered, "quality": q.score, "flags": flags}


def analyze_signature(img, ctx: Context, sig: dict) -> dict:
    """Validação + genericidade + contexto de um item do sigs.json (usa o 1º match)."""
    hits = aob.scan(img, sig["pattern"], sig.get("sections"), bool(sig.get("executable_only", False)))
    out: dict = {"name": sig["name"], "hits": len(hits), "generic": genericity(img, ctx, sig["pattern"])}
    if hits:
        out["check"] = check_resolution(img, ctx, hits[0].rva, sig)
        out["context"] = analyze_context(img, ctx, hits[0].rva)
    return out
