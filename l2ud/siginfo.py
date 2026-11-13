"""Signature Intelligence: qualidade do padrão, duplicações e estabilidade entre builds."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import aob

_COMMON = {0x00, 0xCC, 0x90, 0xFF}


def _tokens(pattern: str) -> list[int | None]:
    out: list[int | None] = []
    for t in pattern.split():
        if t in ("?", "??", "**"):
            out.append(None)
        else:
            out.append(int(t, 16))
    return out


@dataclass
class Quality:
    length: int
    fixed: int
    wildcard_ratio: float
    longest_run: int
    common_ratio: float
    score: int                      # 0..100
    flags: list[str] = field(default_factory=list)

    @property
    def fragile(self) -> bool:
        return "too_short" in self.flags or self.score < 40


def pattern_quality(pattern: str) -> Quality:
    aob.compile_pattern(pattern)  # valida sintaxe (AobError)
    toks = _tokens(pattern)
    fixed = [t for t in toks if t is not None]
    run = best = 0
    for t in toks:
        run = run + 1 if t is not None else 0
        best = max(best, run)
    wr = 1 - len(fixed) / len(toks)
    cr = (sum(1 for t in fixed if t in _COMMON) / len(fixed)) if fixed else 1.0
    flags = []
    if len(fixed) < 5:
        flags.append("too_short")
    if wr > 0.6:
        flags.append("mostly_wildcards")
    if fixed and (cr > 0.6 or len(set(fixed)) <= 2) and len(fixed) >= 4:
        flags.append("low_entropy")
    if best < 3:
        flags.append("no_anchor")
    score = int(max(0, min(100, len(fixed) * 6 + best * 4 - wr * 20 - cr * 30)))
    return Quality(len(toks), len(fixed), round(wr, 2), best, round(cr, 2), score, flags)


def _generalizes(a: list, b: list) -> bool:
    """True se `a` casa em todo lugar que `b` casa (mesmo tamanho; bytes fixos de a == b)."""
    return len(a) == len(b) and all(x is None or x == y for x, y in zip(a, b))


def analyze_set(sigs: list[dict]) -> list[str]:
    """Problemas dentro de um conjunto de assinaturas: duplicadas, redundantes, nomes repetidos."""
    issues: list[str] = []
    names: dict[str, int] = {}
    items = []
    for s in sigs:
        names[s["name"]] = names.get(s["name"], 0) + 1
        items.append((s["name"], _tokens(s["pattern"])))
    for n, c in names.items():
        if c > 1:
            issues.append(f"nome repetido: {n} ({c}x)")
    for i, (na, ta) in enumerate(items):
        for nb, tb in items[i + 1:]:
            if na == nb:
                continue
            if ta == tb:
                issues.append(f"padrão idêntico: {na} == {nb}")
            elif _generalizes(ta, tb):
                issues.append(f"{na} é mais genérico que {nb} (casa onde {nb} casa)")
            elif _generalizes(tb, ta):
                issues.append(f"{nb} é mais genérico que {na} (casa onde {na} casa)")
    return issues


@dataclass
class Stability:
    name: str
    per_build: dict[str, tuple[str, int | None, int]]   # label -> (status, value, nº de hits)
    flags: list[str] = field(default_factory=list)


def stability(sigs: list[dict], images: dict[str, object], engine: str = "lite") -> list[Stability]:
    """Roda o conjunto em várias builds e sinaliza assinaturas frágeis/incompatíveis."""
    from .analysis import Context
    from .sigs import run_signature, Status
    out = {s["name"]: Stability(s["name"], {}) for s in sigs}
    for label, img in images.items():
        ctx = Context(img, engine)
        for s in sigs:
            r = run_signature(img, s, ctx)
            hits = len(aob.scan(img, s["pattern"], s.get("sections"), bool(s.get("executable_only", False))))
            out[s["name"]].per_build[label] = (r.status.value, r.value, hits)
    for st in out.values():
        statuses = {v[0] for v in st.per_build.values()}
        if Status.NOT_FOUND.value in statuses:
            miss = [k for k, v in st.per_build.items() if v[0] == Status.NOT_FOUND.value]
            st.flags.append(f"incompatível: NOT_FOUND em {', '.join(miss)}")
        if Status.AMBIGUOUS.value in statuses:
            st.flags.append("ambígua em alguma build")
        if any(v[2] > 1 for v in st.per_build.values()):
            st.flags.append("múltiplos matches em alguma build (frágil)")
        if not st.flags:
            st.flags.append("estável")
    return list(out.values())
