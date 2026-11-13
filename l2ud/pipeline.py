"""Pipeline 'AUTO DISCOVER OFFSETS' — orquestrador de descoberta automática.

Executa de ponta a ponta as etapas de análise sobre um bundle ou módulo individual:
1. Análise do bundle / módulos (arquitetura real, consistência, empacotamento).
2. Descoberta de funções (limites, chamadores/chamados, strings, imports).
3. Descoberta de variáveis globais e slots de ponteiro (leitura, escrita, relocações).
4. Descoberta de vtables com suporte a MSVC RTTI (desmangle de classes, métodos).
5. Descoberta de coleções (std::vector, TArray, listas) e relações de ponteiros.
6. Geração automática de assinaturas únicas (AOB) com validação de roundtrip.
7. Finalização e avaliação honesta de status contra o grafo de evidências.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from . import autosig, bundle, collectiondisc, funcdisc, globaldisc, vtabledisc
from .catalog import Catalog
from .evgraph import EvidenceGraph
from .modwork import DiscoverOptions, ModuleWork
from .pe import PeImage
from .progress import Progress

if TYPE_CHECKING:
    from .storage import Database


class AutoDiscoverPipeline:
    def __init__(self, options: DiscoverOptions | None = None) -> None:
        self.opts = options or DiscoverOptions()

    def run(self, target_path: str, progress: Progress | None = None,
            db: Database | None = None, db_note: str = "") -> tuple[Catalog, EvidenceGraph, object]:
        p = Path(target_path)
        if not p.exists():
            raise FileNotFoundError(f"caminho não encontrado: {target_path}")

        if p.is_dir():
            rep = bundle.analyze_bundle(p, recursive=False, progress=progress)
            analyzable = bundle.analyzable(rep, include_packed=self.opts.include_packed)
            if self.opts.modules:
                analyzable = [m for m in analyzable if m.name.lower() in [x.lower() for x in self.opts.modules]]
            bundle_id = rep.bundle_id
            mod_infos = analyzable
        else:
            mod_info = bundle.analyze_module(p)
            rep = mod_info
            bundle_id = f"single-{mod_info.sha256[:12]}"
            mod_infos = [mod_info]

        catalog = Catalog(bundle_id=bundle_id)
        graph = EvidenceGraph()

        if progress:
            progress.stage("pipeline", len(mod_infos), f"Processando {len(mod_infos)} módulo(s)")

        for mod_info in mod_infos:
            img = PeImage.load(mod_info.path)
            work = ModuleWork(img, mod_info, bundle_id, graph, catalog, self.opts)

            # Etapa 3 — Funções
            funcdisc.run(work, progress)

            # Etapa 4 — Globais e Slots de Ponteiro
            globaldisc.run(work, progress)

            # Etapa 5 — Vtables com RTTI
            vtabledisc.run(work, progress)

            # Etapa 6 — Coleções
            collectiondisc.run(work, progress)

            # Etapa 7 — Assinaturas Automáticas
            if self.opts.generate_aob:
                autosig.run(work, progress)

            if progress:
                progress.step(mod_info.name)

        # Avaliar status de todos os itens do catálogo segundo o grafo de evidências
        catalog.finalize(graph)

        if db is not None:
            db.save_catalog(catalog, graph, note=db_note or f"Auto-discovery: {bundle_id}")

        return catalog, graph, rep
