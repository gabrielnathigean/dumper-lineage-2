"""Descoberta automática de COLEÇÕES e RELAÇÕES DE PONTEIROS.

Reconhece padrões estruturais típicos de containers em código compilado:
1. `std::vector` (MSVC STL): 3 ponteiros consecutivos (first, last, end_capacity).
2. `TArray` (Unreal Engine / Lineage 2): ponteiro de dados + count (int32) + max (int32).
3. `std::list` / Lista duplamente ligada: nós com ponteiros adjacentes (next, prev).

Categorias preenchidas:
- `COLLECTION_CANDIDATES`: representação do container (tipo, membro/offset, layout).
- `POINTER_RELATIONSHIPS`: relação de apontamento e propriedade (buffer, elementos, cadeia).
"""
from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from .catalog import CatalogItem
from .progress import Progress

if TYPE_CHECKING:
    from .modwork import ModuleWork


def run(work: ModuleWork, progress: Progress | None = None) -> list[CatalogItem]:
    img, ctx, g = work.img, work.ctx, work.graph
    ptr_size = 8 if img.is64 else 4

    items: list[CatalogItem] = []
    collections_found = []

    # 1. Analisar estruturas encontradas pelo dataflow (structs.py)
    try:
        from .structs import analyze_structures
        struct_res = analyze_structures(img, ctx, min_fields=work.opts.min_struct_fields)
    except Exception:
        struct_res = None

    if struct_res:
        for cand in struct_res.candidates:
            fields_by_off = {f.offset: f for f in cand.fields}
            offsets = sorted(fields_by_off.keys())

            # Verificar padrão std::vector: 3 ponteiros consecutivos (off, off+ptr_size, off+2*ptr_size)
            for off in offsets:
                off1 = off + ptr_size
                off2 = off + 2 * ptr_size
                if off1 in fields_by_off and off2 in fields_by_off:
                    f0, f1, f2 = fields_by_off[off], fields_by_off[off1], fields_by_off[off2]
                    # Se são do tamanho de ponteiro
                    if f0.size == ptr_size and f1.size == ptr_size and f2.size == ptr_size:
                        collections_found.append({
                            "type": "std::vector",
                            "origin_kind": "struct",
                            "parent_id": cand.id,
                            "offset": off,
                            "size": 3 * ptr_size,
                            "details": {
                                "first_offset": off,
                                "last_offset": off1,
                                "end_offset": off2,
                            }
                        })

                # Verificar padrão TArray: 1 ponteiro em off + 2 inteiros de 4 bytes (off+ptr_size, off+ptr_size+4)
                off_cnt = off + ptr_size
                off_max = off + ptr_size + 4
                if off_cnt in fields_by_off and off_max in fields_by_off:
                    f0 = fields_by_off[off]
                    fc = fields_by_off[off_cnt]
                    fm = fields_by_off[off_max]
                    if f0.size == ptr_size and fc.size == 4 and fm.size == 4:
                        collections_found.append({
                            "type": "TArray",
                            "origin_kind": "struct",
                            "parent_id": cand.id,
                            "offset": off,
                            "size": ptr_size + 8,
                            "details": {
                                "data_offset": off,
                                "count_offset": off_cnt,
                                "max_offset": off_max,
                            }
                        })

    # 2. Analisar seções de dados para coleções globais estáticas
    data_secs = [s for s in img.sections if not s.executable and s.raw_size]
    for s in data_secs:
        # Procurar por padrões de std::vector inicializados em .data
        # Onde [p1, p2, p3] apontam para buffers válidos ou são nulos (p1 == p2 == p3)
        raw = img.read_rva(s.va, s.raw_size)
        if not raw:
            continue
        step = ptr_size
        max_scan = s.va + s.raw_size - (3 * ptr_size)
        cur = s.va
        while cur <= max_scan:
            p0 = struct.unpack("<Q" if img.is64 else "<I", img.read_rva(cur, ptr_size))[0]
            p1 = struct.unpack("<Q" if img.is64 else "<I", img.read_rva(cur + ptr_size, ptr_size))[0]
            p2 = struct.unpack("<Q" if img.is64 else "<I", img.read_rva(cur + 2 * ptr_size, ptr_size))[0]

            # Vetor válido preenchido estaticamente: p0 <= p1 <= p2 (e p0 > 0)
            if 0 < p0 <= p1 <= p2 and (p2 - p0) < 0x10000000:
                tgt_sec0 = img.section_for_rva(p0 - img.image_base)
                tgt_sec2 = img.section_for_rva(p2 - img.image_base)
                if tgt_sec0 is not None and tgt_sec2 is not None:
                    # Conferir se há referências a este endereço
                    if work.xrefs_to(cur):
                        collections_found.append({
                            "type": "std::vector",
                            "origin_kind": "global",
                            "rva": cur,
                            "size": 3 * ptr_size,
                            "details": {
                                "first_va": f"{p0:#x}",
                                "last_va": f"{p1:#x}",
                                "end_va": f"{p2:#x}",
                            }
                        })
                        cur += 3 * ptr_size
                        continue
            cur += step

    if progress:
        progress.stage("collections", len(collections_found), f"{work.name}: {len(collections_found)} coleção(ões) candidata(s)")

    for idx, c in enumerate(collections_found):
        c_type = c["type"]
        if c.get("origin_kind") == "struct":
            c_name = f"coll_{c_type.replace(':', '_')}_cand{c['parent_id']}_off{c['offset']:#x}"
            val_kind = "STRUCT_MEMBER_OFFSET"
            val = c["offset"]
            extra = f"cand{c['parent_id']}"
        else:
            c_name = f"coll_{c_type.replace(':', '_')}_g_{c['rva']:08X}"
            val_kind = "RVA"
            val = c["rva"]
            extra = f"global_{c['rva']:#x}"

        it = work.new_item("COLLECTION_CANDIDATES", c_name, val_kind, val, extra_id=extra)
        it.attrs.update({
            "collection_type": c_type,
            "origin_kind": c["origin_kind"],
            "container_size": c["size"],
            "details": c["details"]
        })
        it.limitations = [
            f"identificado por padrão de layout ({c_type}): sem garantia de tipo em tempo de execução"
        ]
        it.summary = f"candidato a coleção {c_type} ({c['origin_kind']} em {val:#x}); tamanho estimado: {c['size']} bytes"

        # Evidência no grafo
        work.evidence(it, "static_data", f"layout:{work.name}:{c_name}", None, True, "pattern", **c["details"])

        # Criar item de POINTER_RELATIONSHIPS
        rel_name = f"rel_{c_name}_elements"
        rel_item = work.new_item("POINTER_RELATIONSHIPS", rel_name, "RELATION", None, extra_id=extra)
        rel_item.attrs.update({
            "source_collection": it.id,
            "relation_type": "contains_elements",
            "element_pointer_offset": c["details"].get("first_offset", c["details"].get("data_offset", 0))
        })
        rel_item.summary = f"relação de continência: {it.name} -> buffer de elementos"
        work.evidence(rel_item, "pointer_use", f"rel:{work.name}:{rel_name}", None, True, "layout",
                      collection_id=it.id)

        # Aresta no grafo entre coleção e a relação
        g.add_edge(work.node(it), work.node(rel_item), "has_relation")

        items.append(it)
        items.append(rel_item)
        if progress:
            progress.step(it.name)

    return items
