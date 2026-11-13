"""Padrões AOB com wildcards. Implementado via regex de bytes (rápido, com sobreposição)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .pe import PeImage


class AobError(ValueError):
    pass


def compile_pattern(text: str) -> re.Pattern[bytes]:
    """'48 8B ?? 05 ? ?' -> regex. '?' e '??' valem um byte cada."""
    parts: list[bytes] = []
    for tok in text.split():
        if tok in ("?", "??", "**"):
            parts.append(b".")
        elif re.fullmatch(r"[0-9A-Fa-f]{2}", tok):
            parts.append(re.escape(bytes([int(tok, 16)])))
        else:
            raise AobError(f"token inválido no padrão: {tok!r}")
    if not parts:
        raise AobError("padrão vazio")
    body = b"".join(parts)
    return re.compile(b"(?=(" + body + b"))", re.DOTALL)


@dataclass
class Hit:
    rva: int
    va: int
    file_offset: int
    section: str


def scan(img: PeImage, pattern: str, sections: list[str] | None = None,
         executable_only: bool = False, max_hits: int = 100000) -> list[Hit]:
    rx = compile_pattern(pattern)
    hits: list[Hit] = []
    for s in img.sections:
        if s.raw_size == 0 or s.discardable:
            continue
        if sections and s.name not in sections:
            continue
        if executable_only and not s.executable:
            continue
        data = img.raw[s.raw_ptr:s.raw_ptr + s.raw_size]
        for m in rx.finditer(data):
            off = s.raw_ptr + m.start()
            rva = s.va + m.start()
            hits.append(Hit(rva, img.rva_to_va(rva), off, s.name))
            if len(hits) >= max_hits:
                return hits
    return hits
