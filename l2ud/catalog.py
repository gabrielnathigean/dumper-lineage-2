"""Catálogo de candidatos da descoberta automática.

Categorias: GLOBAL_VARIABLES, GLOBAL_POINTER_CANDIDATES, FUNCTION_RVAS, STRUCTURE_CANDIDATES, STRUCTURE_FIELDS,
VTABLE_CANDIDATES, COLLECTION_CANDIDATES, POINTER_RELATIONSHIPS.

Cada item tem VALOR TIPADO (`value_kind`): RVA, FILE_OFFSET, STRUCT_MEMBER_OFFSET, STRUCT_SIZE, INTEGER ou RELATION.
Tipos NUNCA se misturam: um RVA tem `va_preferred`/`file_offset` separados; um offset de campo é
STRUCT_MEMBER_OFFSET (relativo ao início da estrutura, pode ser negativo); um inteiro é INTEGER.

Status: STATIC_CANDIDATE → STATIC_CORROBORATED (só pela regra do grafo de evidências) →
KNOWN_REFERENCE_VALIDATED / RUNTIME_VALIDATED (SÓ por importação de validação externa; ver `validation.py`).
Nomes são NEUTROS (`sub_…`, `g_…`, `vtbl_…`) ou vêm do próprio binário (export/RTTI): nunca semântica inventada.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field

CATEGORIES = ["GLOBAL_VARIABLES", "GLOBAL_POINTER_CANDIDATES", "FUNCTION_RVAS", "STRUCTURE_CANDIDATES",
              "STRUCTURE_FIELDS", "VTABLE_CANDIDATES", "COLLECTION_CANDIDATES", "POINTER_RELATIONSHIPS"]
CATEGORY_CODE = {"GLOBAL_VARIABLES": "GV", "GLOBAL_POINTER_CANDIDATES": "GP", "FUNCTION_RVAS": "FN",
                 "STRUCTURE_CANDIDATES": "ST", "STRUCTURE_FIELDS": "SF", "VTABLE_CANDIDATES": "VT",
                 "COLLECTION_CANDIDATES": "CC", "POINTER_RELATIONSHIPS": "PR"}
VALUE_KINDS = ("RVA", "FILE_OFFSET", "STRUCT_MEMBER_OFFSET", "STRUCT_SIZE", "INTEGER", "RELATION")

STATUSES = ["STATIC_CANDIDATE", "STATIC_CORROBORATED", "KNOWN_REFERENCE_VALIDATED", "RUNTIME_VALIDATED"]
STATUS_RANK = {s: i for i, s in enumerate(STATUSES)}


def item_id(category: str, module_sha: str, kind: str, value, extra: str = "") -> str:
    """Id ESTÁVEL: mesma build + mesma categoria + mesmo valor = mesmo id (reprodutível entre execuções)."""
    h = hashlib.sha1(f"{module_sha}|{category}|{kind}|{value}|{extra}".encode()).hexdigest()[:10]
    return f"{CATEGORY_CODE[category]}-{h}"


@dataclass
class CatalogItem:
    id: str
    category: str
    module: str
    module_sha256: str
    bundle_id: str
    arch: str
    name: str                                   # neutro ou vindo do binário (export/RTTI)
    value_kind: str
    value: int | None
    image_base: int = 0
    va_preferred: int | None = None             # só RVA (ImageBase preferida + RVA; informativo)
    file_offset: int | None = None              # só RVA mapeado em disco
    status: str = "STATIC_CANDIDATE"
    status_reason: str = ""
    evidence: list[str] = field(default_factory=list)            # ids no grafo
    independence: dict = field(default_factory=dict)
    references: list[dict] = field(default_factory=list)         # amostra
    reference_count: int = 0
    signature: dict | None = None
    limitations: list[str] = field(default_factory=list)
    attrs: dict = field(default_factory=dict)
    links: dict = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["typed"] = {"kind": self.value_kind, "value": None if self.value is None else f"{self.value:#x}"}
        return d

    @staticmethod
    def from_dict(d: dict) -> "CatalogItem":
        d = {k: v for k, v in d.items() if k != "typed"}
        return CatalogItem(**d)


class Catalog:
    def __init__(self, bundle_id: str = "", modules: dict | None = None) -> None:
        self.bundle_id = bundle_id
        self.modules: dict[str, dict] = modules or {}        # nome -> {sha256, arch, image_base, ...}
        self.items: dict[str, CatalogItem] = {}
        self.meta: dict = {}

    def add(self, item: CatalogItem) -> CatalogItem:
        if item.value_kind not in VALUE_KINDS:
            raise ValueError(f"value_kind inválido: {item.value_kind}")
        if item.category not in CATEGORIES:
            raise ValueError(f"categoria inválida: {item.category}")
        if item.value_kind != "RVA" and (item.va_preferred is not None or item.file_offset is not None):
            raise ValueError("va_preferred/file_offset só existem para value_kind RVA (tipos não se misturam)")
        self.items[item.id] = item
        return item

    def get(self, id: str) -> CatalogItem | None:
        return self.items.get(id)

    def by_category(self, category: str, module: str | None = None) -> list[CatalogItem]:
        return [i for i in self.items.values() if i.category == category and (module is None or i.module == module)]

    def counts(self) -> dict:
        c: dict[str, dict[str, int]] = {}
        for i in self.items.values():
            c.setdefault(i.category, Counter())[i.status] += 1
        return {k: dict(v) for k, v in c.items()}

    def finalize(self, graph) -> None:
        """Calcula independência de evidências e status (regra do grafo) para cada item. Não rebaixa
        KNOWN_REFERENCE_VALIDATED/RUNTIME_VALIDATED (esses só vêm de validação externa)."""
        for it in self.items.values():
            node = f"item:{it.id}"
            it.independence = graph.independence(node)
            st, why = graph.assess(node)
            if STATUS_RANK.get(it.status, 0) < STATUS_RANK["KNOWN_REFERENCE_VALIDATED"]:
                it.status, it.status_reason = st, why

    # ---- serialização ----
    def to_dict(self) -> dict:
        return {"schema": "l2ud-catalog/1", "bundle_id": self.bundle_id, "modules": self.modules, "meta": self.meta,
                "counts": self.counts(),
                "categories": {c: [i.to_dict() for i in self.by_category(c)] for c in CATEGORIES}}

    @staticmethod
    def from_dict(d: dict) -> "Catalog":
        if d.get("schema") != "l2ud-catalog/1":
            raise ValueError("schema de catálogo desconhecido")
        c = Catalog(d.get("bundle_id", ""), d.get("modules", {}))
        c.meta = d.get("meta", {})
        for items in d.get("categories", {}).values():
            for x in items:
                c.add(CatalogItem.from_dict(x))
        return c

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    # ---- exportações ----
    def to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["id", "category", "module", "module_sha256", "arch", "name", "value_kind", "value", "va_preferred_base",
                    "file_offset", "status", "observations", "evidence_types", "signature_pattern", "signature_roundtrip",
                    "limitations"])
        for c in CATEGORIES:
            for i in self.by_category(c):
                sig = i.signature or {}
                w.writerow([i.id, i.category, i.module, i.module_sha256, i.arch, i.name, i.value_kind,
                            "" if i.value is None else f"{i.value:#x}", "" if i.va_preferred is None else f"{i.va_preferred:#x}",
                            "" if i.file_offset is None else f"{i.file_offset:#x}", i.status,
                            i.independence.get("observations", 0), "|".join(i.independence.get("types", [])),
                            sig.get("pattern", ""), (sig.get("roundtrip") or {}).get("ok", ""), " | ".join(i.limitations)])
        return buf.getvalue()

    def to_hpp(self, include_candidates: bool = False) -> str:
        """Header C++: RVAs (`*_RVA`), tamanhos (`*_SIZE`) e offsets de campo (`*_OFFSET`) em namespaces separados.
        Por padrão só STATIC_CORROBORATED ou melhor; `include_candidates=True` inclui tudo com o status em comentário."""
        ok = {"STATIC_CORROBORATED", "KNOWN_REFERENCE_VALIDATED", "RUNTIME_VALIDATED"}
        lines = ["#pragma once", "#include <cstdint>", "",
                 "// Gerado por l2ud. *_RVA é relativo à BASE REAL do módulo carregado; *_OFFSET é deslocamento de campo",
                 "// (relativo ao início da estrutura); *_SIZE é tamanho mínimo estimado. NUNCA some o ImageBase preferido.",
                 f"// bundle: {self.bundle_id}", "namespace l2ud_offsets {",
                 "inline std::uintptr_t va_from_rva(std::uintptr_t module_base, std::uint32_t rva) { return module_base + rva; }"]
        used: set[str] = set()
        for mod, info in sorted(self.modules.items()):
            body = []
            for c in CATEGORIES:
                for i in self.by_category(c, mod):
                    if i.value is None or i.value_kind not in ("RVA", "STRUCT_MEMBER_OFFSET", "STRUCT_SIZE"):
                        continue
                    if not include_candidates and i.status not in ok:
                        continue
                    suf = {"RVA": "_RVA", "STRUCT_MEMBER_OFFSET": "_OFFSET", "STRUCT_SIZE": "_SIZE"}[i.value_kind]
                    base = re.sub(r"\W", "_", i.name).upper() or i.id.upper().replace("-", "_")
                    if base[:1].isdigit():
                        base = "_" + base
                    ident = base if base.endswith(suf) else base + suf
                    n, cand = 2, ident
                    while (mod, cand) in used:
                        cand, n = f"{ident}_{n}", n + 1
                    used.add((mod, cand))
                    if i.value_kind == "STRUCT_MEMBER_OFFSET" and i.value < 0:
                        body.append(f"constexpr std::int32_t {cand} = {i.value}; // {i.status}")
                    else:
                        body.append(f"constexpr std::uint32_t {cand} = {i.value:#x}; // {i.status}")
            if body:
                ns = re.sub(r"\W", "_", mod).lower()
                lines += [f"namespace {ns} {{", f"constexpr std::uint64_t PREFERRED_IMAGE_BASE = {info.get('image_base', 0):#x}; // informativo",
                          *body, "}"]
        lines.append("}")
        return "\n".join(lines) + "\n"

    def to_markdown(self, top: int = 40) -> str:
        L = ["# Catálogo de descoberta automática", "", f"- bundle: `{self.bundle_id}`", ""]
        L += ["> Todos os itens são **candidatos estáticos**. Nomes são neutros (ou vêm do próprio binário). "
              "RVA, offset de campo, tamanho e inteiro são tipos distintos e nunca se misturam.", "",
              "| módulo | arch | SHA-256 | ImageBase (preferida) |", "|---|---|---|---|"]
        for m, info in sorted(self.modules.items()):
            L.append(f"| {m} | {info.get('arch', '?')} | `{info.get('sha256', '')[:16]}…` | {info.get('image_base', 0):#x} |")
        L += ["", "## Resumo", "", "| categoria | total | " + " | ".join(STATUSES) + " |", "|---|---|" + "---|" * len(STATUSES)]
        for c in CATEGORIES:
            its = self.by_category(c)
            cnt = Counter(i.status for i in its)
            L.append(f"| {c} | {len(its)} | " + " | ".join(str(cnt.get(s, 0)) for s in STATUSES) + " |")
        for c in CATEGORIES:
            its = sorted(self.by_category(c), key=lambda i: (-STATUS_RANK.get(i.status, 0), -i.independence.get("observations", 0), i.id))
            if not its:
                continue
            L += ["", f"## {c} ({len(its)})", "", "| id | módulo | nome | tipo | valor | status | obs. indep. | tipos de evidência | assinatura |",
                  "|---|---|---|---|---|---|---|---|---|"]
            for i in its[:top]:
                v = "-" if i.value is None else f"{i.value:#x}"
                sig = "sim" if i.signature and (i.signature.get("roundtrip") or {}).get("ok") else ("não" if i.signature is None else "falhou")
                L.append(f"| {i.id} | {i.module} | {i.name} | {i.value_kind} | {v} | {i.status} | "
                         f"{i.independence.get('observations', 0)} | {', '.join(i.independence.get('types', []))} | {sig} |")
            if len(its) > top:
                L.append(f"\n_… e mais {len(its) - top} item(ns); veja o JSON/CSV._")
        L += ["", "## Limitações gerais",
              "- Análise estática: nenhum valor foi observado em execução. Um slot global tem o ENDEREÇO conhecido; o valor armazenado é dinâmico.",
              "- RUNTIME_VALIDATED/KNOWN_REFERENCE_VALIDATED só existem via importação de validação externa.",
              "- Compatibilidade com um cliente específico não é afirmada sem teste em cliente real."]
        return "\n".join(L) + "\n"

    def export(self, path: str, include_candidates: bool = False) -> None:
        from pathlib import Path
        ext = Path(path).suffix.lower()
        text = {".json": self.to_json, ".csv": self.to_csv, ".md": self.to_markdown,
                ".hpp": lambda: self.to_hpp(include_candidates), ".h": lambda: self.to_hpp(include_candidates)}.get(ext)
        if text is None:
            raise ValueError(f"formato de exportação desconhecido: {ext} (use .json .csv .hpp .md)")
        Path(path).write_text(text(), encoding="utf-8")
