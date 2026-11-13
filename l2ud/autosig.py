"""Geração automática de assinaturas (AOB) com validação de unicidade.

Gera assinaturas de padrão de bytes com wildcards para itens do catálogo:
- Funções (FUNCTION_RVAS): padrão no início da função com kind 'hit'.
- Globais e Vtables (GLOBAL_VARIABLES, GLOBAL_POINTER_CANDIDATES, VTABLE_CANDIDATES):
  padrão a partir da instrução de código que referencia o RVA, mascarando o operando
  relativo ou absoluto e validando o roundtrip para o alvo original.

Garante UNICIDADE: a assinatura só é atribuída se encontrar exatamente 1 match
na imagem e resolver perfeitamente para o alvo (`roundtrip.ok == True`).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from . import aob, aobintel
from .catalog import CatalogItem
from .progress import Progress
from .sigs import _resolve

if TYPE_CHECKING:
    from .modwork import ModuleWork


def generate_for_function(work: ModuleWork, it: CatalogItem) -> dict | None:
    """Gera assinatura para uma função no seu entry point."""
    if it.value is None:
        return None
    rva = it.value
    img, ctx = work.img, work.ctx
    sug = aobintel.generate(img, ctx, rva, max_len=40, wild_fields=True, max_insns=10)
    if sug and sug.unique and sug.pattern:
        # Roundtrip check
        hits = aob.scan(img, sug.pattern)
        if len(hits) == 1 and hits[0].rva == rva:
            return {
                "pattern": sug.pattern,
                "kind": "hit",
                "hits": 1,
                "unique": True,
                "roundtrip": {"ok": True, "resolved_rva": f"{rva:#x}"},
                "instructions": sug.instructions,
            }
    return None


def generate_for_data_target(work: ModuleWork, it: CatalogItem) -> dict | None:
    """Gera assinatura a partir de instruções de código que referenciam um global ou vtable."""
    if it.value is None:
        return None
    target_rva = it.value
    img, ctx = work.img, work.ctx
    d = ctx.disassembler

    xs = [x for x in work.xrefs_to(target_rva) if x.trusted]
    for x in xs[:5]:
        ins = d.decode_one(x.from_rva)
        if ins is None:
            continue
        kind = "rip" if x.kind == "rip" else ("abs" if x.kind == "abs" else None)
        if not kind:
            continue
        disp_off = ins.disp_offset
        if disp_off <= 0:
            continue
        insn_len = len(ins.raw)

        # Gera padrão a partir de ins.rva com wildcards nos operandos
        sug = aobintel.generate(img, ctx, ins.rva, max_len=36, wild_fields=True, max_insns=6)
        if sug and sug.unique and sug.pattern:
            sig_dict = {
                "pattern": sug.pattern,
                "kind": kind,
                "disp_offset": disp_off,
                "insn_len": insn_len,
            }
            hits = aob.scan(img, sug.pattern)
            if len(hits) == 1:
                resolved, err = _resolve(img, hits[0], sig_dict)
                if resolved == target_rva:
                    sig_dict.update({
                        "hits": 1,
                        "unique": True,
                        "roundtrip": {"ok": True, "resolved_rva": f"{target_rva:#x}"},
                        "instructions": sug.instructions,
                    })
                    return sig_dict
    return None


def run(work: ModuleWork, progress: Progress | None = None) -> list[CatalogItem]:
    catalog, opts = work.catalog, work.opts
    items_to_sign: list[CatalogItem] = []

    # Selecionar itens elegíveis
    categories = ("FUNCTION_RVAS", "GLOBAL_VARIABLES", "GLOBAL_POINTER_CANDIDATES", "VTABLE_CANDIDATES")
    for cat in categories:
        cat_items = catalog.by_category(cat, work.name)
        # Priorizar itens já corroborados ou com mais referências
        cat_items.sort(key=lambda i: (-len(i.evidence), -i.reference_count, i.id))
        limit = opts.aob_limit if opts.aob_limit is not None else 100
        items_to_sign.extend(cat_items[:limit])

    if progress:
        progress.stage("autosig", len(items_to_sign), f"{work.name}: gerando assinaturas para {len(items_to_sign)} item(ns)")

    signed_count = 0
    for it in items_to_sign:
        if it.signature is not None:
            continue
        sig = None
        if it.category == "FUNCTION_RVAS":
            sig = generate_for_function(work, it)
        else:
            sig = generate_for_data_target(work, it)

        if sig is not None:
            it.signature = sig
            signed_count += 1
            # Evidência de assinatura automática estável
            work.evidence(it, "function_match", f"sig:{work.name}:{it.id}", None, True, "aob",
                          pattern=sig["pattern"])

        if progress:
            progress.step(it.name)

    return items_to_sign
