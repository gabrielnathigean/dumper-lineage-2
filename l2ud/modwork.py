"""Contexto de trabalho de UM módulo durante a descoberta automática: análise (Context/CFG/xrefs), índices
compartilhados entre as etapas e fábrica de itens do catálogo + evidências do grafo."""
from __future__ import annotations

from dataclasses import dataclass, field

from .analysis import Context, Xref, string_at
from .bundle import ModuleInfo
from .catalog import Catalog, CatalogItem, item_id
from .evgraph import EvidenceGraph
from .pe import PeImage

NODE_KIND = {"FUNCTION_RVAS": "function", "GLOBAL_VARIABLES": "global", "GLOBAL_POINTER_CANDIDATES": "pointer_slot",
             "STRUCTURE_CANDIDATES": "struct", "STRUCTURE_FIELDS": "field", "VTABLE_CANDIDATES": "vtable",
             "COLLECTION_CANDIDATES": "collection", "POINTER_RELATIONSHIPS": "pointer_relation"}


@dataclass
class DiscoverOptions:
    max_functions: int | None = None            # por módulo (None = todas)
    max_globals: int | None = None              # por módulo (None = todas)
    max_vtables: int | None = None              # por módulo (None = todas)
    min_struct_fields: int = 4
    generate_aob: bool = True
    aob_limit: int = 300                        # máx. de itens por categoria que recebem assinatura
    include_packed: bool = False
    modules: list[str] | None = None            # restringe a estes nomes (None = todos os analisáveis)
    max_refs_per_item: int = 10                 # amostra de referências guardada em cada item
    max_evidence_per_item: int = 40


class ModuleWork:
    def __init__(self, img: PeImage, info: ModuleInfo, bundle_id: str, graph: EvidenceGraph, catalog: Catalog,
                 options: DiscoverOptions | None = None) -> None:
        self.img, self.info, self.bundle_id = img, info, bundle_id
        self.graph, self.catalog = graph, catalog
        self.opts = options or DiscoverOptions()
        self.name, self.sha = info.name, info.sha256
        self.ctx = Context(img, "capstone")
        self._by_target: dict[int, list[Xref]] | None = None
        self._by_fn: dict[int, list[Xref]] | None = None
        self._iat: dict[int, str] | None = None
        self.module_node = graph.add_node(f"module:{self.name}", "module", self.name, sha256=self.sha, arch=info.arch)
        catalog.modules[self.name] = {"sha256": self.sha, "arch": info.arch, "image_base": img.image_base,
                                      "timestamp": info.timestamp, "machine": f"{info.machine:#x}",
                                      "packing_level": info.packing_level, "fingerprint": info.fingerprint}

    # ---- índices ----
    @property
    def xrefs(self) -> list[Xref]:
        return self.ctx.xrefs

    def xrefs_to(self, rva: int) -> list[Xref]:
        if self._by_target is None:
            self._by_target = {}
            for x in self.xrefs:
                self._by_target.setdefault(x.target_rva, []).append(x)
        return self._by_target.get(rva, [])

    def xrefs_in(self, fn_start: int) -> list[Xref]:
        if self._by_fn is None:
            self._by_fn = {}
            for x in self.xrefs:
                if x.function is not None:
                    self._by_fn.setdefault(x.function.start, []).append(x)
        return self._by_fn.get(fn_start, [])

    @property
    def iat(self) -> dict[int, str]:
        if self._iat is None:
            self._iat = {i.iat_rva: f"{i.dll}!{i.name}" for i in self.img.imports}
        return self._iat

    def string_at(self, rva: int) -> str | None:
        s = self.img.section_for_rva(rva)
        if s is None or s.executable:
            return None
        return string_at(self.img, rva)

    # ---- chaves de proveniência ----
    def fkey(self, fn_start: int | None) -> str | None:
        return None if fn_start is None else f"{self.name}:{fn_start:#x}"

    def ikey(self, rva: int) -> str:
        return f"insn:{self.name}:{rva:#x}"

    # ---- fábrica ----
    def new_item(self, category: str, name: str, value_kind: str, value: int | None, extra_id: str = "",
                 **kw) -> CatalogItem:
        iid = item_id(category, self.sha, value_kind, value, extra_id)
        existing = self.catalog.get(iid)
        if existing is not None:
            return existing
        va = fo = None
        if value_kind == "RVA" and value is not None:
            va, fo = self.img.rva_to_va(value), self.img.rva_to_file(value)
        it = CatalogItem(iid, category, self.name, self.sha, self.bundle_id, self.info.arch, name, value_kind, value,
                         self.img.image_base, va_preferred=va, file_offset=fo, **kw)
        self.catalog.add(it)
        self.graph.add_node(f"item:{iid}", NODE_KIND[category], name, category=category, value_kind=value_kind,
                            value=value, module=self.name)
        self.graph.add_edge(self.module_node, f"item:{iid}", "contains")
        return it

    def node(self, it: CatalogItem) -> str:
        return f"item:{it.id}"

    def evidence(self, it: CatalogItem, type: str, origin: str, function: str | None = None, trusted: bool = True,
                 via: str = "", extra_nodes: tuple = (), **detail) -> str | None:
        if len(it.evidence) >= self.opts.max_evidence_per_item:
            return None
        eid = self.graph.add_evidence(type, origin, [self.node(it), *extra_nodes], function, trusted, via, **detail)
        if eid not in it.evidence:
            it.evidence.append(eid)
        return eid

    def ref_dict(self, x: Xref) -> dict:
        return {"from_rva": f"{x.from_rva:#x}", "kind": x.kind, "via": x.via, "rw": x.rw,
                "function": None if x.function is None else f"{x.function.start:#x}"}
