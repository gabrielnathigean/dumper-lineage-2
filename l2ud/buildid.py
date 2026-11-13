"""Identificação de builds.

  SHA-256 COMPLETO      identidade definitiva do arquivo (é a única coisa aceita em `known_value`).
  fingerprint           identificação ESTRUTURAL: mesma arquitetura, mesmas seções e mesmo conteúdo executável.
  profile / similarity  similaridade entre builds DIFERENTES (família): imports, exports, seções e um
                        sketch MinHash das strings. As famílias usam LIGAÇÃO COMPLETA (todo membro é similar a todos
                        os outros; sem encadeamento). NÃO é prova de que uma assinatura continuará válida.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

from .analysis import find_strings, fingerprint
from .pe import PeImage

K = 32
_MULT = [0x9E3779B97F4A7C15 + 2 * i * 0x1F1F1F1F1F1F1F1 for i in range(K)]
_ADD = [0xD6E8FEB86659FD93 ^ (i * 0x94D049BB133111EB) for i in range(K)]
_M64 = (1 << 64) - 1
MAX_STRINGS = 20000


@dataclass
class BuildProfile:
    sha256: str
    fingerprint: str
    arch: str
    machine: int
    timestamp: int
    module: str
    size: int
    sections: list[list] = field(default_factory=list)       # [nome, vsize]
    imports: list[str] = field(default_factory=list)         # "dll!nome" (minúsculo)
    exports: list[str] = field(default_factory=list)
    minhash: list[int] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(s: str) -> "BuildProfile":
        return BuildProfile(**json.loads(s))


def _minhash(strings: list[str]) -> list[int]:
    hs = [int.from_bytes(hashlib.blake2b(s.encode("utf-8", "ignore"), digest_size=8).digest(), "little")
          for s in set(strings)]
    if not hs:
        return []
    return [min(((m * h + a) & _M64) for h in hs) for m, a in zip(_MULT, _ADD)]


def compute_profile(img: PeImage) -> BuildProfile:
    strs = [f.text for f in find_strings(img, None, 8, MAX_STRINGS)]
    return BuildProfile(
        sha256=img.sha256, fingerprint=fingerprint(img), arch=img.arch, machine=img.machine,
        timestamp=img.timestamp, module=img.export_name or img.path.replace("\\", "/").rsplit("/", 1)[-1],
        size=len(img.raw), sections=[[s.name, s.vsize] for s in img.sections],
        imports=sorted({f"{i.dll}!{i.name}".lower() for i in img.imports}),
        exports=sorted(e.name for e in img.exports if e.name), minhash=_minhash(strs))


def _jaccard(a, b) -> float | None:
    a, b = set(a), set(b)
    if not a and not b:
        return None
    return len(a & b) / len(a | b)


def similarity(a: BuildProfile, b: BuildProfile) -> dict:
    """Pontuação 0..1 + partes. Componentes ausentes (ex.: sem exports) são ignorados e os pesos renormalizados."""
    if a.sha256 == b.sha256:
        return {"score": 1.0, "identical": True, "parts": {}, "same_arch": True}
    parts: dict[str, float | None] = {
        "imports": _jaccard(a.imports, b.imports),
        "exports": _jaccard(a.exports, b.exports),
        "sections": _jaccard([(n, v) for n, v in a.sections], [(n, v) for n, v in b.sections]),
        "section_names": _jaccard([n for n, _ in a.sections], [n for n, _ in b.sections]),
        "strings": (sum(1 for x, y in zip(a.minhash, b.minhash) if x == y) / K) if a.minhash and b.minhash else None,
    }
    w = {"imports": 0.25, "exports": 0.15, "sections": 0.1, "section_names": 0.1, "strings": 0.4}
    tot = sum(w[k] for k, v in parts.items() if v is not None)
    score = sum(w[k] * v for k, v in parts.items() if v is not None) / tot if tot else 0.0
    if a.arch != b.arch:
        score *= 0.5
    return {"score": round(score, 3), "identical": False, "parts": {k: (None if v is None else round(v, 3)) for k, v in parts.items()},
            "same_arch": a.arch == b.arch}


def families(profiles: dict[str, BuildProfile], threshold: float = 0.8) -> list[list[str]]:
    """Agrupa por LIGAÇÃO COMPLETA: uma build só entra numa família se for similar (>= threshold e mesma
    arquitetura) a TODOS os membros — sem o efeito de encadeamento (A~B, B~C, mas A≁C) dos componentes conexos."""
    labels = sorted(profiles)
    sims: dict[tuple[str, str], float] = {}
    for i, a in enumerate(labels):
        for b in labels[i + 1:]:
            s = similarity(profiles[a], profiles[b])
            sims[(a, b)] = sims[(b, a)] = s["score"] if s["same_arch"] else 0.0
    clusters = [[l] for l in labels]
    while True:
        best = None
        for i in range(len(clusters)):
            for j in range(i + 1, len(clusters)):
                link = min(sims[(a, b)] for a in clusters[i] for b in clusters[j])   # pior par entre os dois grupos
                if link >= threshold and (best is None or link > best[0]):
                    best = (link, i, j)
        if best is None:
            return clusters
        _, i, j = best
        clusters[i] = sorted(clusters[i] + clusters[j])
        del clusters[j]


def family_report(profiles: dict[str, BuildProfile], group: list[str]) -> list[dict]:
    """Compatibilidade INDIVIDUAL de cada membro: pior e média de similaridade com os demais da família.
    (Similaridade estrutural NÃO é compatibilidade de offsets/assinaturas.)"""
    out = []
    for a in group:
        others = [similarity(profiles[a], profiles[b])["score"] for b in group if b != a]
        out.append({"build": a, "min": min(others) if others else 1.0,
                    "mean": round(sum(others) / len(others), 3) if others else 1.0, "members": len(group)})
    return out


def identity(img: PeImage) -> dict:
    p = compute_profile(img)
    return {"sha256": p.sha256, "fingerprint": p.fingerprint, "arch": p.arch, "machine": f"{p.machine:#x}",
            "module": p.module, "timestamp": p.timestamp, "size": p.size}
