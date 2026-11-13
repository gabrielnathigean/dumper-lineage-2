# l2ud 0.5.0 — Arquitetura do Projeto

Analisador estático **offline** de PEs e Descoberta Automática de Offsets. Python 3.10+. **Lite** = só biblioteca padrão; **Avançado** = `capstone` opcional.

## 1. Estrutura
```
dumper 2/
├── README.md · PROJETO.md · DOCUMENTACAO_COMPLETA.md · CHANGELOG.md · requirements.txt
├── sigs.example.json · hints.example.json
├── demo/                 make_demos.py (gera PEs sintéticos) + sigs_demo.json + hints_demo.json
├── l2ud/
│   ├── pe.py             parser PE (seções, imports, exports+forwarders, relocs, .pdata, timestamp, nome do módulo)
│   ├── aob.py            scanner AOB (regex, sobreposição)
│   ├── functions.py      mapa de funções: pdata (exato) | cfg (derivado) | heuristic (fraco)
│   ├── disasm.py         Capstone: Insn/Op/MemRef, registradores canônicos, decode_one/sweep       [opcional]
│   ├── cfg.py            CFG, blocos, jump tables x86, regiões ambíguas, funções por alcançabilidade, xrefs [Capstone]
│   ├── analysis.py       xrefs (Lite/Capstone) com proveniência, strings, hexdump, análise de função, Context
│   ├── sigs.py           assinaturas, corroboração forte/fraca, validação Capstone, status
│   ├── siginfo.py        qualidade do padrão, duplicadas, estabilidade entre builds
│   ├── aobintel.py       validação de campos, geração assistida, bytes variáveis, contexto, genericidade [Capstone*]
│   ├── structs.py        Structure Discovery v2 (dataflow de ponteiros + classes de objetos)       [Capstone]
│   ├── intel.py          Offset Intelligence: relatórios explicativos
│   ├── buildid.py        identidade (SHA-256), perfil de similaridade, famílias
│   ├── bundle.py         pasta de módulos PE como conjunto (arch real, empacotamento, imports entre módulos)
│   ├── evgraph.py        grafo de evidências com proveniência e regras de corroboração
│   ├── catalog.py        catálogo com valores tipados (RVA, STRUCT_MEMBER_OFFSET, etc.) e exportadores
│   ├── modwork.py        contexto de trabalho compartilhado de módulos durante descoberta
│   ├── funcdisc.py       descoberta automática de funções (limites, chamadores, strings, imports)
│   ├── globaldisc.py     descoberta automática de variáveis globais e slots de ponteiro
│   ├── vtabledisc.py     descoberta de tabelas virtuais com parser MSVC RTTI
│   ├── collectiondisc.py descoberta de coleções (std::vector, TArray, listas) e relações de ponteiros
│   ├── autosig.py        gerador automático de assinaturas AOB com verificação de unicidade
│   ├── pipeline.py       pipeline "AUTO DISCOVER OFFSETS" orquestrando etapas 1 a 7
│   ├── crossbuild.py     comparação e diff de catálogos entre builds
│   ├── validation.py     importação de validação externa (KNOWN_REFERENCE_VALIDATED, RUNTIME_VALIDATED)
│   ├── progress.py       progresso e cancelamento cooperativo
│   ├── storage.py        SQLite (AnalysisRun, catálogos, migração), export explícito, diff, histórico
│   ├── cli.py · gui.py   interfaces (CLI com autodiscover/diff/validate e GUI com aba Catálogo)
├── tests/                builders.py (PEs sintéticos) + test_suite.py (116 testes) + test_v050.py (46 testes)
└── legacy_cpp_draft/     rascunho C++ original (referência)
```
`*` `variable_bytes_at`/`find_points` não precisam de Capstone.

## 2. Camadas
```
 cli.py / gui.py
      │
 intel.py      sigs.py ── siginfo.py ── aobintel.py      structs.py        storage.py ── buildid.py
      └───────────┬───────────┴───────────────┬───────────────┘
              analysis.py  (Context: fmap + CFGs + xrefs em cache)
              │         │
         functions.py   cfg.py ── disasm.py (opcional)
              └────┬────┘
                 pe.py ── aob.py
```

## 3. Decisões que importam
- **Proveniência de cada referência.** `Xref.via` ∈ `opcode` (heurística Lite) · `reloc` · `cfg` (código alcançável) · `linear`
  (varredura; pode ser dado lido como código). `linear` **nunca** corrobora um resultado.
- **Três qualidades de limite de função.** `pdata` = exato · `cfg` = derivado de alcançabilidade · `heuristic` = fraco.
  Só os dois primeiros promovem status; o fraco é anotado como "NÃO conta". **A cobertura é por intervalos reais** (`Function.cover`),
  não pelo envelope `[start,end)`; regiões sobrepostas/vãos não são atribuídas a nenhuma função.
- **Objetos por origem, não por registrador.** O mesmo objeto acessado por registradores diferentes cai na mesma classe; o mesmo
  registrador reutilizado vira objetos diferentes. Fusão só por evidência concreta; layout parecido nunca funde.
- **Status honestos.** `CONFIRMED` exige `known_value` com SHA-256 completo da mesma build, corroboração forte **e** validação
  de instrução completa. Só matches resolvidos e validados corroboram; cada evidência é ligada ao match que a sustenta.
- **Execuções independentes.** Cada `sigs --db` é uma `AnalysisRun`; nada de resultados antigos misturados; toda run explícita é
  verificada contra a build e as gravações são atômicas.
- **Sem sobreposição no CFG.** Destino no meio de instrução vira aresta inválida registrada; desvios externos são classificados.
- **Relatórios sem semântica inventada.** `intel.py` só afirma fatos observados e sempre lista "O que NÃO foi estabelecido".

## 4. Status
| Status | Regra |
|--------|-------|
| CONFIRMED | valor único + corroboração forte + igual a `known_value` (SHA-256 completo) da build |
| STATIC_CORROBORATED | valor único + corroboração forte |
| PROBABLE | valor único por AOB |
| CANDIDATE | padrão frágil, campos que não batem com a instrução, divergência da referência; estruturas |
| AMBIGUOUS | valores distintos |
| NOT_FOUND | sem match / alvo fora da imagem / padrão inválido |

## 5. Banco de dados
`builds` (sha256 único, fingerprint, módulo, arch, timestamp, perfil) · `build_events` · `runs` (engine, versão, hash e cópia das
assinaturas) · `run_results` · `run_structs`. Referências: `3` (última run da build 3), `3@5`, `@5`, sha256/prefixo.

## 6. Testes
`py -3 tests\test_suite.py` — 116 testes (58 exigem Capstone e são pulados sem ele): PE/AOB/status, x86 Lite, **CFG** (laço, jcc,
regiões ambíguas, jump table x86, indireto x64, PE real), Capstone, **AOB Intelligence**, **Structure Discovery** (reuso de registrador,
identidade por global, fusão por argumento, conflito, array/negativo, cadeia de ponteiros, x86 thiscall, hints), identidade de builds,
**AnalysisRun**, migração 0.2/0.3, relatórios, fiação da CLI e GUI (pulada sem display).

## 7. Pendências conhecidas
- Nenhum teste contra binário real de jogo; compatibilidade não afirmada.
- CFG: sem jump tables x64, sem chamadas indiretas/vtables, sem `noreturn`.
- Structure Discovery: sem aliasing por memória/pilha; pode ser lento em binários enormes.
- Sem importador de artefatos de análise dinâmica; Zydis não suportado.
- GUI testada por script (sem display real do usuário).

## 8. 0.4.1 — Reliability & Accuracy Update
Correções de lógica que produziam descobertas incorretas sem erro (CFG, mapa de funções, validação de assinaturas, fusão de
estruturas, pilha/convenção x86, banco, famílias de builds). Cada item: `CHANGELOG.md` (problema → correção → teste) e a seção 14
de `DOCUMENTACAO_COMPLETA.md` (invariantes e comportamentos não comprovados).

## 9. 0.5.0 — Auto Discovery of Offsets
Pipeline completo de descoberta automática offline (Etapas 1 a 12):
- Bundle Analyzer (`bundle.py`) e Grafo de Evidências (`evgraph.py`) com regras de independência.
- Catálogo de tipos estritos (`catalog.py`) com exportadores para JSON, CSV, Markdown e C++ `.hpp`.
- Descoberta automática de funções (`funcdisc.py`), variáveis globais e slots de ponteiro (`globaldisc.py`), vtables com MSVC RTTI (`vtabledisc.py`), coleções e relações (`collectiondisc.py`).
- Geração automática de assinaturas com validação de unicidade (`autosig.py`).
- Pipeline unificado (`pipeline.py`) e persistência de catálogos no SQLite (`storage.py`).
- Comparação entre builds (`crossbuild.py`) e importador de validações externas (`validation.py`).
- CLI (`autodiscover`, `diff-catalog`, `validate`, `catalog-runs`) e GUI com a aba Catálogo.
