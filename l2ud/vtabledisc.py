"""Descoberta automática de VTABLES (tabelas virtuais) com suporte a MSVC RTTI.

Identifica sequências de ponteiros em seções de dados (.rdata / .data) que apontam
para funções de código executável.

MSVC RTTI:
- Precedendo a vtable por sizeof(void*), busca o ponteiro para `_RTTICompleteObjectLocator`.
- Resolve `TypeDescriptor` e extrai o nome de classe descorado (ex.: `.?AVPlayer@@` -> `Player`).
- Quando RTTI presente: atribui nome qualificado `vtbl_ClassName` e evidência `rtti`.
- Quando ausente: nome neutro `vtbl_<RVA>`.
- Registra cada método virtual, vinculando ao grafo com arestas `contains_method`.
"""
from __future__ import annotations

import re
import struct
from typing import TYPE_CHECKING

from .catalog import CatalogItem
from .progress import Progress

if TYPE_CHECKING:
    from .modwork import ModuleWork

# Regex para descorar nomes MSVC: .?AVClass@Namespace@@ -> Namespace::Class
_MSVC_RTTI_RX = re.compile(r"^\.\?[AU]V?(.+)@@$")


def demangle_msvc_rtti(mangled: str) -> str | None:
    """Extrai nome amigável da classe a partir de .?AVClass@Namespace@@."""
    m = _MSVC_RTTI_RX.match(mangled)
    if not m:
        return None
    parts = m.group(1).split("@")
    parts.reverse()
    return "::".join(parts)


def sanitize_ident(name: str) -> str:
    """Converte nome de classe em identificador seguro para C++ (ex.: Namespace::Class -> Namespace_Class)."""
    return re.sub(r"[^\w]", "_", name)


def read_ptr(img, rva: int) -> int | None:
    """Lê um ponteiro no RVA (retornando o VA desempacotado)."""
    size = 8 if img.is64 else 4
    raw = img.read_rva(rva, size)
    if not raw or len(raw) < size:
        return None
    return struct.unpack("<Q" if img.is64 else "<I", raw)[0]


def parse_rtti(img, col_rva: int) -> tuple[str | None, str | None]:
    """Tenta ler um _RTTICompleteObjectLocator no col_rva.
    Retorna (mangled_name, clean_name) ou (None, None)."""
    # Em x86:
    #   signature (4), offset (4), cdOffset (4), pTypeDescriptor (4 VA), pClassHierarchy (4 VA)
    # Em x64:
    #   signature (4), offset (4), cdOffset (4), pTypeDescriptor (4 RVA), pClassHierarchy (4 RVA), pSelf (4 RVA)
    raw = img.read_rva(col_rva, 24 if img.is64 else 20)
    if not raw or len(raw) < (24 if img.is64 else 20):
        return None, None

    if img.is64:
        sig, off, cd_off, td_rva, ch_rva, self_rva = struct.unpack("<IIIIII", raw[:24])
        # Validação básica de consistência do RTTICompleteObjectLocator x64
        if self_rva != col_rva:
            return None, None
        if not (0 <= td_rva < (img.size_of_image or 0x7FFFFFFF)):
            return None, None
    else:
        sig, off, cd_off, td_va, ch_va = struct.unpack("<IIIII", raw[:20])
        td_rva = td_va - img.image_base
        if not (0 <= td_rva < (img.size_of_image or 0x7FFFFFFF)):
            return None, None

    td_sec = img.section_for_rva(td_rva)
    if not td_sec:
        return None, None

    # No TypeDescriptor:
    # x86: vtable_ptr (4), spare (4), name (char[])
    # x64: vtable_ptr (8), spare (8), name (char[])
    name_offset = 16 if img.is64 else 8
    name_bytes = img.read_rva(td_rva + name_offset, 256)
    if not name_bytes or b"\x00" not in name_bytes:
        return None, None

    str_raw = name_bytes.split(b"\x00")[0]
    try:
        mangled = str_raw.decode("ascii")
    except UnicodeDecodeError:
        return None, None

    if mangled.startswith(".?A"):
        clean = demangle_msvc_rtti(mangled) or mangled
        return mangled, clean
    return None, None


def run(work: ModuleWork, progress: Progress | None = None) -> list[CatalogItem]:
    img, ctx, g = work.img, work.ctx, work.graph
    ptr_size = 8 if img.is64 else 4
    min_methods = 2

    # Seções onde vtables podem residir (.rdata, .data)
    data_secs = [s for s in img.sections if not s.executable and (s.raw_size or s.vsize)]

    # Conjunto de funções válidas para validar ponteiros de método
    starts = {f.start for f in ctx.fmap.funcs}

    # Relocações se disponíveis
    reloc_set = {rva for rva, typ in img.relocs if typ in (3, 10)}

    # Mapear xrefs para detectar referências a vtables
    vtbl_xrefs: dict[int, list] = {}
    for x in work.xrefs:
        vtbl_xrefs.setdefault(x.target_rva, []).append(x)

    discovered_vtables: dict[int, dict] = {}

    for s in data_secs:
        raw_size = s.raw_size
        if not raw_size:
            continue
        data = img.read_rva(s.va, raw_size)
        if not data:
            continue

        rva = s.va
        end_rva = s.va + raw_size - (ptr_size * min_methods)

        while rva <= end_rva:
            # Checar se rva precede por RTTICompleteObjectLocator
            # e se rva aponta para uma sequência de métodos de código executável
            methods: list[int] = []
            cur_rva = rva

            while cur_rva + ptr_size <= s.va + raw_size:
                val = read_ptr(img, cur_rva)
                if val is None:
                    break
                method_rva = val - img.image_base
                # Deve apontar para uma seção executável
                tgt_sec = img.section_for_rva(method_rva)
                if tgt_sec is not None and tgt_sec.executable:
                    methods.append(method_rva)
                    cur_rva += ptr_size
                else:
                    break

            if len(methods) >= min_methods:
                # Checar se há RTTI imediatamente antes de rva
                col_ptr_rva = rva - ptr_size
                col_val = read_ptr(img, col_ptr_rva)
                rtti_mangled, rtti_clean = None, None
                col_rva = None

                if col_val is not None:
                    test_col_rva = col_val - img.image_base
                    if 0 <= test_col_rva < (img.size_of_image or 0x7FFFFFFF):
                        m, c = parse_rtti(img, test_col_rva)
                        if m:
                            rtti_mangled, rtti_clean = m, c
                            col_rva = test_col_rva

                discovered_vtables[rva] = {
                    "methods": methods,
                    "rtti_mangled": rtti_mangled,
                    "rtti_clean": rtti_clean,
                    "col_rva": col_rva,
                    "section": s.name
                }
                # Avançar para depois desta vtable
                rva = cur_rva
            else:
                rva += ptr_size

    max_vtables = getattr(work.opts, "max_vtables", None)
    sorted_rvas = sorted(discovered_vtables.keys())
    if max_vtables is not None:
        sorted_rvas = sorted_rvas[:max_vtables]

    if progress:
        progress.stage("vtables", len(sorted_rvas), f"{work.name}: {len(sorted_rvas)} vtable(s) candidata(s)")

    items: list[CatalogItem] = []

    for rva in sorted_rvas:
        info = discovered_vtables[rva]
        methods = info["methods"]
        rtti_clean = info["rtti_clean"]
        rtti_mangled = info["rtti_mangled"]
        col_rva = info["col_rva"]

        if rtti_clean:
            ident = sanitize_ident(rtti_clean)
            name = f"vtbl_{ident}"
            name_source = "rtti"
        else:
            name = f"vtbl_{rva:08X}"
            name_source = "neutral"

        it = work.new_item("VTABLE_CANDIDATES", name, "RVA", rva)

        # Evidência RTTI se presente
        if rtti_mangled and col_rva is not None:
            rtti_node = g.add_node(f"rtti:{work.name}:{col_rva:#x}", "rtti", rtti_clean or rtti_mangled,
                                   mangled=rtti_mangled, clean=rtti_clean)
            work.evidence(it, "rtti", f"rtti:{work.name}:{col_rva:#x}", None, True, "rtti",
                          extra_nodes=(rtti_node,), class_name=rtti_clean, mangled=rtti_mangled)
            g.add_edge(work.node(it), rtti_node, "has_rtti")

        # Evidências e arestas para métodos
        for idx, m_rva in enumerate(methods):
            m_node = f"fn:{work.name}:{m_rva:#x}"
            g.add_node(m_node, "function", f"sub_{m_rva:08X}")
            g.add_edge(work.node(it), m_node, "contains_method")
            # Registra evidência vtable_slot no método também
            slot_origin = f"vtbl_slot:{work.name}:{rva:#x}[{idx}]"
            work.evidence(it, "vtable_slot", slot_origin, None, True, "vtable", index=idx, method_rva=f"{m_rva:#x}")

        # Evidências de código (xrefs que usam a vtable, ex.: construtores)
        xs = vtbl_xrefs.get(rva, [])
        for x in xs:
            fn_start = x.function.start if x.function else None
            ev_type = "ctor_store" if x.rw in ("w", "rw") else "code_xref"
            work.evidence(it, ev_type, work.ikey(x.from_rva), work.fkey(fn_start), x.trusted, x.via, rw=x.rw)
            if fn_start is not None:
                fn_node = f"fn:{work.name}:{fn_start:#x}"
                g.add_node(fn_node, "function", f"sub_{fn_start:08X}")
                g.add_edge(fn_node, work.node(it), "references")

        it.references = [work.ref_dict(x) for x in xs[:work.opts.max_refs_per_item]]
        it.reference_count = len(xs)

        it.attrs.update({
            "section": info["section"],
            "method_count": len(methods),
            "methods": methods[:50],
            "rtti_mangled": rtti_mangled,
            "rtti_class": rtti_clean,
            "col_rva": col_rva,
            "name_source": name_source,
            "access_count": len(xs),
        })

        if rtti_clean:
            it.limitations = [f"classe identificada via MSVC RTTI ({rtti_clean})"]
        else:
            it.limitations = ["nome neutro: sem RTTI localizado"]

        it.summary = f"vtable em {info['section']} com {len(methods)} método(s)" + (f" ({rtti_clean})" if rtti_clean else "")

        items.append(it)
        if progress:
            progress.step(it.name)

    return items
