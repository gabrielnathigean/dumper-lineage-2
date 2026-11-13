"""Descoberta automática de FUNÇÕES (sem assinaturas manuais).

Fontes: `.pdata` (x64: limites exatos), exports, entry point, alvos de `call` e prólogos (x86), expandidos por
CFG (recursive descent). Cada função vira um item FUNCTION_RVAS com limites e a QUALIDADE deles (exatos /
derivados de CFG / heurísticos), instruções, blocos, chamadores/chamados, strings e imports associados.

Evidências (cada uma com origem própria): export, entry_point, pdata (limites exatos), direct_call (uma por
instrução `call` distinta), string_ref, import_ref. O nome é neutro (`sub_<RVA>`) ou o nome de export do binário.
"""
from __future__ import annotations

from .catalog import CatalogItem
from .modwork import ModuleWork
from .progress import Progress


def run(work: ModuleWork, progress: Progress | None = None) -> list[CatalogItem]:
    img, ctx, g = work.img, work.ctx, work.graph
    fmap = ctx.fmap
    funcs = fmap.funcs[:work.opts.max_functions] if work.opts.max_functions else fmap.funcs
    starts = {f.start for f in fmap.funcs}
    exports = {e.rva: e.name for e in img.exports if e.name and not e.forwarder}
    items: dict[int, CatalogItem] = {}
    if progress:
        progress.stage("functions", len(funcs), f"{work.name}: {len(funcs)} função(ões) candidata(s)")

    # chamadores por alvo (uma entrada por instrução `call`/`jmp` distinta e CONFIÁVEL)
    callers: dict[int, list] = {}
    for x in work.xrefs:
        if x.kind in ("call", "jmp") and x.target_rva in starts and x.trusted:
            callers.setdefault(x.target_rva, []).append(x)

    for fn in funcs:
        name = exports.get(fn.start) or f"sub_{fn.start:08X}"
        it = work.new_item("FUNCTION_RVAS", name, "RVA", fn.start)
        items[fn.start] = it
    for fn in funcs:
        it = items[fn.start]
        cfg = ctx.cfg(fn)
        xin = work.xrefs_in(fn.start)
        calls = sorted({x.target_rva for x in xin if x.kind == "call" and x.target_rva in starts})
        strings: dict[int, str] = {}
        imports: set[str] = set()
        for x in xin:
            if x.kind in ("call", "jmp"):
                continue
            imp = work.iat.get(x.target_rva)
            if imp:
                imports.add(imp)
                work.evidence(it, "import_ref", work.ikey(x.from_rva), work.fkey(fn.start), x.trusted, x.via,
                              extra_nodes=(g.add_node(f"import:{imp}", "import", imp),), import_name=imp)
                g.add_edge(work.node(it), f"import:{imp}", "references_import")
                continue
            s = work.string_at(x.target_rva)
            if s and len(strings) < 12:
                strings[x.target_rva] = s
                sid = g.add_node(f"string:{work.name}:{x.target_rva:#x}", "string", s[:60], rva=x.target_rva)
                work.evidence(it, "string_ref", work.ikey(x.from_rva), work.fkey(fn.start), x.trusted, x.via,
                              extra_nodes=(sid,), string=s[:80])
                g.add_edge(work.node(it), sid, "references_string")
        cs = callers.get(fn.start, [])
        distinct_callers = {x.function.start for x in cs if x.function and x.function.start != fn.start}
        for x in cs[:25]:
            work.evidence(it, "direct_call", work.ikey(x.from_rva), work.fkey(x.function.start if x.function else None),
                          x.trusted, x.via, caller=None if x.function is None else f"{x.function.start:#x}")
            if x.function is not None and x.function.start in items:
                g.add_edge(work.node(items[x.function.start]), work.node(it), "calls")
        if fn.start in exports:
            work.evidence(it, "export", f"export:{work.name}:{exports[fn.start]}", None, True, "export", name=exports[fn.start])
        if fn.start == img.entry_point:
            work.evidence(it, "entry_point", f"entry:{work.name}", None, True, "pe_header")
        if fn.exact:
            work.evidence(it, "pdata", f"pdata:{work.name}:{fn.start:#x}", None, True, "pdata", end=fn.end)
        s = cfg.summary() if cfg is not None else {}
        it.attrs.update({
            "end": fn.end, "bounds_source": fn.source, "bounds_label": fn.label, "contiguous": fn.contiguous,
            "cover": [[a, b] for a, b in fn.cover], "instructions": s.get("instructions"), "blocks": s.get("blocks"),
            "callees": calls[:30], "callee_count": len(calls), "callers": sorted(distinct_callers)[:30],
            "caller_count": len(distinct_callers), "strings": list(strings.values()), "imports": sorted(imports),
            "exported_name": exports.get(fn.start), "is_entry_point": fn.start == img.entry_point,
            "indirect_unresolved": s.get("indirect_unresolved", 0), "external_edges": s.get("external_edges", 0),
            "name_source": "export" if fn.start in exports else "neutral"})
        it.references = [work.ref_dict(x) for x in cs[:work.opts.max_refs_per_item]]
        it.reference_count = len(cs)
        it.limitations = ["nome neutro: nenhum significado semântico atribuído"] if fn.start not in exports else \
            ["nome de export do binário (não é interpretação do analisador)"]
        if fn.source == "heuristic":
            it.limitations.append("limites HEURÍSTICOS (prólogo/call): podem estar errados")
        elif fn.source == "cfg":
            it.limitations.append("limites derivados de alcançabilidade (CFG): não provados")
        if s.get("indirect_unresolved"):
            it.limitations.append(f"{s['indirect_unresolved']} salto(s) indireto(s) não resolvido(s): código alcançável pode estar incompleto")
        if s.get("invalid_edges"):
            it.limitations.append(f"{s['invalid_edges']} desvio(s) para o meio de instrução (ignorados)")
        it.summary = (f"{s.get('instructions', '?')} instruções em {s.get('blocks', '?')} bloco(s); {len(distinct_callers)} chamador(es); "
                      f"{len(calls)} chamado(s); {len(strings)} string(s); {len(imports)} import(s)")
        if progress:
            progress.step(it.name)
    return list(items.values())
