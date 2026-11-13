"""Descoberta automática de VARIÁVEIS GLOBAIS e SLOTS DE PONTEIRO.

Varre seções de dados (.data, .rdata, .bss) identificando endereços referenciados por:
- Instruções de código (x86 absoluto relocável, x64 RIP-relative, leituras/escritas/lea).
- Relocações (ponteiros estáticos em seções de dados ou referências de código).
- Dataflow / Structure Discovery (onde o valor carregado é usado como base de ponteiro).

Classificação:
- GLOBAL_POINTER_CANDIDATES: slots cujo conteúdo é um ponteiro para outro RVA da imagem ou é
  desreferenciado em código como base de objeto (pointer_use).
- GLOBAL_VARIABLES: variáveis escalares, contadores, flags, buffers estáticos ou estruturas globais.
"""
from __future__ import annotations

import struct
from collections import Counter
from typing import TYPE_CHECKING

from .catalog import CatalogItem
from .progress import Progress

if TYPE_CHECKING:
    from .modwork import ModuleWork


def run(work: ModuleWork, progress: Progress | None = None) -> list[CatalogItem]:
    img, ctx, g = work.img, work.ctx, work.graph
    fmap = ctx.fmap
    exports = {e.rva: e.name for e in img.exports if e.name and not e.forwarder}

    # Seções de dados não-executáveis
    data_sections = {s.name: s for s in img.sections if not s.executable and s.raw_size or (s.flags & 0xC0000000)}

    def in_data_section(rva: int):
        s = img.section_for_rva(rva)
        return s if (s is not None and not s.executable) else None

    # Mapear relocações na imagem:
    # 1) Relocações em seções executáveis que marcam o uso de um endereço absoluto
    # 2) Relocações dentro de seções de dados (indicando ponteiros estáticos armazenados)
    static_pointers: dict[int, int] = {}  # slot_rva -> target_rva
    data_relocs: set[int] = set()         # RVAs em dados que são alvos de relocação

    for reloc_rva, typ in img.relocs:
        s_reloc = img.section_for_rva(reloc_rva)
        if s_reloc is not None and not s_reloc.executable:
            # Esta relocação está DENTRO de uma seção de dados -> o valor armazenado aqui é um ponteiro
            val = None
            if typ == 3:  # HIGHLOW (32-bit)
                raw = img.read_rva(reloc_rva, 4)
                if raw and len(raw) == 4:
                    val = struct.unpack("<I", raw)[0]
            elif typ == 10:  # DIR64 (64-bit)
                raw = img.read_rva(reloc_rva, 8)
                if raw and len(raw) == 8:
                    val = struct.unpack("<Q", raw)[0]
            if val is not None:
                tgt_rva = val - img.image_base
                if 0 <= tgt_rva < (img.size_of_image or 0x7FFFFFFF) and img.section_for_rva(tgt_rva):
                    static_pointers[reloc_rva] = tgt_rva

    # Coletar xrefs direcionadas a seções de dados
    by_target: dict[int, list] = {}
    for x in work.xrefs:
        if in_data_section(x.target_rva):
            # Ignora se for slot de IAT de import
            if x.target_rva in work.iat:
                continue
            by_target.setdefault(x.target_rva, []).append(x)

    # Identificar slots de ponteiros detectados via Structure Discovery (dataflow)
    deref_pointer_slots: set[int] = set()
    try:
        from .structs import analyze_structures
        struct_res = analyze_structures(img, ctx, min_fields=work.opts.min_struct_fields)
        for sc in struct_res.candidates:
            for ps in sc.pointer_slots:
                deref_pointer_slots.add(ps)
    except Exception:
        pass

    # Unir todos os RVAs candidatos (alvos de xrefs de código + ponteiros estáticos em dados)
    all_candidate_rvas = set(by_target.keys()) | set(static_pointers.keys())
    # Também inclui exports que apontam para dados
    for exp_rva in exports:
        if in_data_section(exp_rva):
            all_candidate_rvas.add(exp_rva)

    max_globals = getattr(work.opts, "max_globals", None)
    sorted_rvas = sorted(all_candidate_rvas)
    if max_globals is not None:
        sorted_rvas = sorted_rvas[:max_globals]

    if progress:
        progress.stage("globals", len(sorted_rvas), f"{work.name}: {len(sorted_rvas)} global(is) candidato(s)")

    items: list[CatalogItem] = []

    for rva in sorted_rvas:
        sec = in_data_section(rva)
        sec_name = sec.name if sec else ".data"
        is_pointer = (rva in static_pointers) or (rva in deref_pointer_slots)

        category = "GLOBAL_POINTER_CANDIDATES" if is_pointer else "GLOBAL_VARIABLES"
        name = exports.get(rva) or (f"g_ptr_{rva:08X}" if is_pointer else f"g_{rva:08X}")

        it = work.new_item(category, name, "RVA", rva)

        xs = by_target.get(rva, [])
        rw_counter = Counter(x.rw or "r" for x in xs)

        # Registrar evidências de código
        functions_seen = set()
        for x in xs:
            fn_start = x.function.start if x.function else None
            if fn_start is not None:
                functions_seen.add(fn_start)
            # Evidência de acesso por instrução
            ev_type = "direct_access" if x.rw in ("r", "w", "rw") else "code_xref"
            work.evidence(it, ev_type, work.ikey(x.from_rva), work.fkey(fn_start), x.trusted, x.via, rw=x.rw)
            if fn_start is not None and fn_start in work.catalog.items:
                fn_item = work.catalog.get(work.catalog.items[fn_start].id) if hasattr(work.catalog, "items") else None
            # Aresta no grafo entre função e global
            if fn_start is not None:
                fn_node = f"fn:{work.name}:{fn_start:#x}"
                g.add_node(fn_node, "function", f"sub_{fn_start:08X}")
                g.add_edge(fn_node, work.node(it), "references")

        # Evidência de ponteiro estático
        if rva in static_pointers:
            tgt = static_pointers[rva]
            work.evidence(it, "static_data", f"data_ptr:{work.name}:{rva:#x}", None, True, "reloc", target_rva=f"{tgt:#x}")
            tgt_sec = img.section_for_rva(tgt)
            tgt_kind = "function" if (tgt_sec and tgt_sec.executable) else "global"
            tgt_node = g.add_node(f"target:{work.name}:{tgt:#x}", tgt_kind, f"target_{tgt:08X}", rva=tgt)
            g.add_edge(work.node(it), tgt_node, "points_to")

        # Evidência de uso como base de ponteiro
        if rva in deref_pointer_slots:
            work.evidence(it, "pointer_use", f"dataflow:{work.name}:{rva:#x}", None, True, "dataflow", role="pointer_base")

        # Evidência de export
        if rva in exports:
            work.evidence(it, "export", f"export:{work.name}:{exports[rva]}", None, True, "export", name=exports[rva])

        # Referências
        it.references = [work.ref_dict(x) for x in xs[:work.opts.max_refs_per_item]]
        it.reference_count = len(xs)

        it.attrs.update({
            "section": sec_name,
            "access_count": len(xs),
            "rw_counts": dict(rw_counter),
            "referencing_functions": sorted(functions_seen)[:30],
            "referencing_function_count": len(functions_seen),
            "is_pointer": is_pointer,
            "static_target_rva": static_pointers.get(rva),
            "exported_name": exports.get(rva),
            "name_source": "export" if rva in exports else "neutral",
        })

        it.limitations = [
            "análise estática: o valor em runtime pode ser alterado dinamicamente",
        ]
        if rva not in exports:
            it.limitations.append("nome neutro: semântica não inferida")

        rw_desc = ", ".join(f"{count} {op}" for op, count in rw_counter.items()) or "sem acessos diretos decodificados"
        ptr_desc = f"; aponta estaticamente para {static_pointers[rva]:#x}" if rva in static_pointers else ""
        it.summary = f"slot em {sec_name} ({'ponteiro' if is_pointer else 'variável'}); {len(xs)} ref(s) ({rw_desc}){ptr_desc}"

        items.append(it)
        if progress:
            progress.step(it.name)

    return items
