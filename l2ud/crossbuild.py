"""Comparação de catálogos entre builds diferentes (Cross-Build Diff).

Compara dois catálogos (`Catalog` da build antiga e da nova):
1. Casamento prioritário por:
   - Assinatura AOB estável (se presente).
   - Nome explícito (export ou classe RTTI).
   - Identificador estrutural único por categoria.
2. Classificação das alterações:
   - `UNCHANGED`: mesmo valor e categoria.
   - `MOVED`: valor deslocado (informa delta: new - old).
   - `STATUS_CHANGED`: alteração no status de evidência/validação.
   - `ADDED`: item novo na build recente.
   - `REMOVED`: item ausente na build recente.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .catalog import Catalog, CatalogItem


class CrossBuildDiff:
    def __init__(self, old_cat: Catalog, new_cat: Catalog) -> None:
        self.old_cat = old_cat
        self.new_cat = new_cat

    def compare(self) -> dict:
        old_items = list(self.old_cat.items.values())
        new_items = list(self.new_cat.items.values())

        matched_pairs: list[tuple[CatalogItem, CatalogItem]] = []
        unmatched_old = set(self.old_cat.items.keys())
        unmatched_new = set(self.new_cat.items.keys())

        # 1. Casamento por assinatura AOB
        sig_to_new: dict[str, str] = {}
        for it in new_items:
            if it.signature and it.signature.get("pattern"):
                sig_to_new[it.signature["pattern"]] = it.id

        for it in old_items:
            if it.signature and it.signature.get("pattern"):
                pat = it.signature["pattern"]
                if pat in sig_to_new and sig_to_new[pat] in unmatched_new:
                    new_id = sig_to_new[pat]
                    matched_pairs.append((it, self.new_cat.items[new_id]))
                    unmatched_old.discard(it.id)
                    unmatched_new.discard(new_id)

        # 2. Casamento por nome explícito (exports / RTTI)
        name_to_new: dict[tuple[str, str], str] = {}
        for it in new_items:
            if it.id in unmatched_new and not it.name.startswith(("sub_", "g_", "vtbl_0")):
                name_to_new[(it.category, it.name)] = it.id

        for it in old_items:
            if it.id in unmatched_old and not it.name.startswith(("sub_", "g_", "vtbl_0")):
                key = (it.category, it.name)
                if key in name_to_new and name_to_new[key] in unmatched_new:
                    new_id = name_to_new[key]
                    matched_pairs.append((it, self.new_cat.items[new_id]))
                    unmatched_old.discard(it.id)
                    unmatched_new.discard(new_id)

        # 3. Classificar diferenças dos itens casados
        unchanged = []
        moved = []
        status_changed = []

        for o_it, n_it in matched_pairs:
            pair_data = {
                "name": n_it.name,
                "category": n_it.category,
                "old_id": o_it.id,
                "new_id": n_it.id,
                "old_val": o_it.value,
                "new_val": n_it.value,
                "old_status": o_it.status,
                "new_status": n_it.status,
            }
            if o_it.value == n_it.value:
                unchanged.append(pair_data)
            else:
                delta = None if o_it.value is None or n_it.value is None else n_it.value - o_it.value
                pair_data["delta"] = delta
                moved.append(pair_data)

            if o_it.status != n_it.status:
                status_changed.append(pair_data)

        added = [self.new_cat.items[nid].to_dict() for nid in sorted(unmatched_new)]
        removed = [self.old_cat.items[oid].to_dict() for oid in sorted(unmatched_old)]

        summary = {
            "old_bundle": self.old_cat.bundle_id,
            "new_bundle": self.new_cat.bundle_id,
            "counts": {
                "matched": len(matched_pairs),
                "unchanged": len(unchanged),
                "moved": len(moved),
                "status_changed": len(status_changed),
                "added": len(added),
                "removed": len(removed),
            },
            "unchanged": unchanged,
            "moved": moved,
            "status_changed": status_changed,
            "added": added,
            "removed": removed,
        }
        return summary

    def to_markdown(self) -> str:
        diff = self.compare()
        c = diff["counts"]
        lines = [
            "# Relatório de Comparação entre Builds (Cross-Build)",
            "",
            f"- Bundle Antigo: `{diff['old_bundle']}`",
            f"- Bundle Novo: `{diff['new_bundle']}`",
            "",
            "## Resumo",
            f"- **Casados**: {c['matched']} ({c['unchanged']} inalterados, {c['moved']} deslocados)",
            f"- **Mudança de Status**: {c['status_changed']}",
            f"- **Novos na build**: {c['added']}",
            f"- **Removidos da build**: {c['removed']}",
            "",
        ]

        if diff["moved"]:
            lines += [
                "## Itens Deslocados (Offsets Alterados)",
                "| Categoria | Nome | Valor Antigo | Valor Novo | Delta |",
                "|---|---|---|---|---|",
            ]
            for m in diff["moved"][:50]:
                o_val = f"{m['old_val']:#x}" if m["old_val"] is not None else "-"
                n_val = f"{m['new_val']:#x}" if m["new_val"] is not None else "-"
                delta = f"{m['delta']:+#x}" if m["delta"] is not None else "-"
                lines.append(f"| {m['category']} | {m['name']} | {o_val} | {n_val} | {delta} |")
            lines.append("")

        return "\n".join(lines)
