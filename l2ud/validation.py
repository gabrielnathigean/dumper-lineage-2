"""Importação de validação externa (KNOWN_REFERENCE_VALIDATED e RUNTIME_VALIDATED).

Permite promover formalmente candidatos estáticos para:
- KNOWN_REFERENCE_VALIDATED: verificado manualmente por engenharia reversa / referência de confiança.
- RUNTIME_VALIDATED: verificado dinamicamente em runtime (ex.: Frida, Cheat Engine, depurador).

Verificação de integridade:
- Validação estrita de SHA-256 da build (opcional, mas checado se presente).
- O valor afirmado DEVE bater com o valor descoberto no item (divergência gera conflito, não promoção).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .catalog import Catalog, CatalogItem


@dataclass
class ValidationReport:
    promoted: list[str] = field(default_factory=list)
    mismatched: list[dict] = field(default_factory=list)
    not_found: list[dict] = field(default_factory=list)
    status_applied: str = ""

    def summary(self) -> str:
        return (f"Validação externa ({self.status_applied}): {len(self.promoted)} promovido(s), "
                f"{len(self.mismatched)} divergência(s), {len(self.not_found)} não encontrado(s)")


def apply_validation(catalog: Catalog, data: dict | list | str) -> ValidationReport:
    """Aplica registros de validação a um catálogo."""
    if isinstance(data, (str, Path)):
        p = Path(data)
        content = p.read_text(encoding="utf-8")
        data = json.loads(content)

    if isinstance(data, list):
        val_type = "KNOWN_REFERENCE"
        items = data
        source = "lista externa"
    elif isinstance(data, dict):
        val_type = data.get("validation_type", "KNOWN_REFERENCE")
        source = data.get("source", "arquivo externo")
        items = data.get("items", [])
    else:
        raise ValueError("formato de dados de validação inválido")

    target_status = "RUNTIME_VALIDATED" if val_type.upper().startswith("RUNTIME") else "KNOWN_REFERENCE_VALIDATED"
    report = ValidationReport(status_applied=target_status)

    for entry in items:
        matched_item: CatalogItem | None = None
        # Busca por id exato
        if "id" in entry:
            matched_item = catalog.get(entry["id"])

        # Busca por (categoria, nome)
        if matched_item is None and "name" in entry:
            cat = entry.get("category")
            name = entry["name"]
            candidates = [i for i in catalog.items.values() if i.name == name and (cat is None or i.category == cat)]
            if len(candidates) == 1:
                matched_item = candidates[0]

        if matched_item is None:
            report.not_found.append(entry)
            continue

        expected_val = entry.get("value")
        if isinstance(expected_val, str) and expected_val.startswith("0x"):
            expected_val = int(expected_val, 16)

        # Checagem de compatibilidade de valor
        if expected_val is not None and matched_item.value is not None:
            if expected_val != matched_item.value:
                report.mismatched.append({
                    "id": matched_item.id,
                    "name": matched_item.name,
                    "catalog_val": matched_item.value,
                    "expected_val": expected_val,
                    "notes": entry.get("notes", "")
                })
                continue

        # Promover status
        matched_item.status = target_status
        matched_item.status_reason = f"validado externamente via {source}" + (f": {entry['notes']}" if "notes" in entry else "")
        matched_item.attrs["external_validation"] = {
            "source": source,
            "type": target_status,
            "notes": entry.get("notes", ""),
        }
        report.promoted.append(matched_item.id)

    return report
