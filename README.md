# l2ud 0.5.0 — análise estática de PEs e Descoberta Automática de Offsets

Ferramenta **offline** para localizar e catalogar offsets em executáveis PE (PE32/PE32+): AOB, strings, xrefs, **CFG**,
funções, variáveis globais, slots de ponteiro, **vtables com MSVC RTTI**, coleções (std::vector, TArray, listas),
**pipeline AUTO DISCOVER OFFSETS**, assinaturas com status honesto, histórico por execução, relatórios explicativos.
Não injeta, não lê processos e não contorna proteções.

| Modo | Dependências | O que dá |
|------|--------------|----------|
| **Lite** | só Python 3.10+ | PE parser, AOB, strings, xrefs por heurística de opcode (x64) / relocação (x86), limites `.pdata`/heurísticos, assinaturas, DB, export, diff, relatórios |
| **Avançado** | `pip install capstone` | tudo do Lite + decodificação x86/x64, **CFG**, xrefs por alcançabilidade, validação de `disp_offset`/`insn_len`, geração de assinaturas, **Structure Discovery**, abas Disassembly/CFG/Estruturas |

`--engine auto` (padrão) usa Capstone se instalado; `lite` força o Lite; `capstone` exige Capstone.

## Windows — instalar e rodar
```bat
py -3 --version
cd "caminho\para\dumper 2"
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt            :: opcional (modo avançado)
py -3 demo\make_demos.py                   :: gera PEs sintéticos de demonstração
py -3 -m l2ud gui
py -3 tests\test_suite.py                  :: testes (os de Capstone são pulados se não instalado)
```

## Demonstração rápida (arquivos sintéticos, nada de jogo)
```bat
py -3 -m l2ud sigs demo\demo_x64.exe demo\sigs_demo.json --db demo.db
py -3 -m l2ud cfg demo\demo_cfg_x64.exe 0x1100 --dot cfg.dot
py -3 -m l2ud structs demo\demo_cfg_x64.exe --out structs.md
py -3 -m l2ud siggen demo\demo_x64.exe 0x1000
py -3 -m l2ud report demo\demo_x64.exe demo\sigs_demo.json --structs --out relatorio.md
```

## Comandos
```
info FILE [--exports] [--imports]
scan FILE "48 8B 05 ?? ?? ?? ??" [--disp 3 --insn-len 7]
strings FILE [texto] [--xrefs]            xrefs FILE RVA            hex FILE RVA [--length N]
func FILE RVA                              limites, origem dos limites, CFG, callers/callees, strings, imports
cfg FILE RVA [--insns] [--dot saida.dot]   blocos, arestas, regiões ambíguas, desvios externos, arestas inválidas, jump tables (Capstone)
disasm FILE RVA [--count N]                (Capstone)
sigs FILE sigs.json [--db DB] [--note TXT] [--out .json|.csv|.hpp] [--include-probable] [--all]
sigcheck FILE sigs.json [--context]        valida campos contra a instrução real, genericidade, contexto
siggen FILE RVA [--max-len N] [--wild-fields] [--strict-boundary]   sugere padrão (nada é aplicado sozinho; avisa se o RVA não é início de instrução)
sigvar PE1 PE2 ... --pattern P | --at ARQ=RVA ...   bytes que mudam entre builds + wildcards sugeridos
sigctx FILE RVA                            instruções antes/depois
siginfo sigs.json [PE ...]                 qualidade, duplicadas, estabilidade entre builds
structs FILE [--hints H.json] [--min-fields N] [--max-functions N] [--function RVA] [--no-x86-reg-args] [--db DB] [--out .json|.md]
structs --from-db BUILD [--db DB]          lista estruturas gravadas
report FILE sigs.json [--structs] [--db DB] [--out .md|.json]     Offset Intelligence
builds | runs [BUILD] | events BUILD | history NOME | similar [PE ...] | buildinfo FILE     (--db l2ud.db)
bundle PASTA [--recursive] [--json R.json] [-v]    analisa uma pasta de módulos PE como conjunto (arch real, empacotamento, imports entre módulos)
funcs MODULO [--max-functions N] [--out C.json|.csv|.md|.hpp] [--force]    catálogo de funções (limites, chamadores/chamados, strings, imports)
autodiscover PASTA_OU_MODULO [--out C.hpp] [--db DB] [--note TXT]    descoberta automática completa (Etapas 1 a 7)
diff-catalog CAT_A.json CAT_B.json [--out diff.md]    comparação e diff de catálogos entre builds
validate CAT.json VAL.json [--out validado.json]      aplica registros de validação externa
catalog-runs [--db DB]                                lista execuções salvas de catálogo
export REF [--format json|csv|hpp|md] [--include-probable] [--all] [--structs]
diff REF_A REF_B                           REF = 3 (última run da build 3) | 3@5 (build 3, run 5) | @5 | sha256
gui
```
Flags comuns de xrefs/funções: `--engine auto|lite|capstone`, `--no-cfg` (volta ao comportamento 0.3), `--no-linear`.

## Status (nunca inflados)
| Status | Regra |
|--------|-------|
| `CONFIRMED` | valor único + corroboração **forte** + igual ao `known_value` (**SHA-256 completo**) da **mesma build** + validação de instrução **completa** |
| `STATIC_CORROBORATED` | valor único + corroboração **forte** (string/import/export na mesma função) |
| `PROBABLE` | valor único por AOB; corroboração **fraca** (limites heurísticos / só varredura linear) não conta |
| `CANDIDATE` | padrão frágil, campos que não batem com a instrução (Capstone) ou divergência da referência. Estruturas: sempre |
| `AMBIGUOUS` / `NOT_FOUND` | mais de um valor / nenhum resultado válido |

**Corroboração forte** = limites de função **exatos (.pdata)** ou **derivados de CFG** + referência confiável (opcode, relocação ou CFG;
nunca varredura linear pura). Só matches **resolvidos e validados** corroboram, e cada evidência fica ligada ao match que a sustenta.
`kind` de assinatura: `rip` · `rel` (**rel32**) · `rel8` (branch curto) · `abs` · `imm` · `hit`. `known_value` é verificação **manual sua**, por build:
```json
{"name": "X", "pattern": "…", "known_value": {"<sha256 completo, 64 hex>": "0x3010"}}
```

## Endereços — RVA, VA e File Offset são coisas diferentes
`value_kind = RVA` (relativo à base do módulo), `FIELD_OFFSET` (campo de struct) ou `INTEGER`. O export traz `rva`, `va_preferred_base`
e `file_offset` separados; `.hpp` usa `*_RVA` / `*_OFFSET` e `va_from_rva(module_base, rva)`. Nunca some o ImageBase do PE em runtime.
Export padrão: só `CONFIRMED` e `STATIC_CORROBORATED` (`--include-probable` adiciona PROBABLE; `--all` o resto).

## AnalysisRun e builds
Cada `sigs --db` grava **uma execução** (engine, versão, hash e cópia do conjunto de assinaturas). Resultados de execuções
diferentes **nunca se misturam**: remover uma assinatura faz ela sumir da última run, e o diff mostra `REMOVED`.
Identidade da build = SHA-256 completo; `fingerprint` é só estrutural; `similar` compara builds diferentes (família) — similaridade
**não** prova compatibilidade de assinaturas. Bancos 0.2/0.3 são migrados sozinhos.

## Structure Discovery v2 (resumo)
Dataflow sobre o CFG (com rastreio de ESP/pilha em x86): cada registrador carrega uma **origem** (argumento, global, retorno, ou campo de outro objeto). Objetos são
classes dessas origens; só fundem por **evidência concreta** (mesmo global, ponteiro passado como argumento, ponteiro gravado em campo).
Layout parecido **não** funde (vira relação `similar_layout`). **Nenhuma** fusão ignora a checagem de conflito (inclusive as implicadas por congruência) e "hubs" são ignorados. `pointer` exige uso como base (senão `pointer_candidate`); em x86, ecx/edx como argumentos são **hipótese** (confiança `low`; `--no-x86-reg-args` desliga); se o dataflow não converge, o resultado é marcado `dataflow_incomplete`. Reporta arrays,
offsets negativos (ponteiro interior), objetos aninhados e tabelas de função. **Sempre `CANDIDATE`, confiança máxima `medium`.**
Não identifica Player/NPC/Item: só `--hints` (strings suas) geram dica "NÃO verificado".

## Limitações
- CFG: jump tables só x86 `jmp [idx*4+tabela]` **com `cmp/ja|jae` antes** (sem limite provado não vira aresta); `jmp reg` (x64) fica "indireto não resolvido"; chamadas indiretas/vtables não são seguidas;
  sem detecção de funções `noreturn`. Funções só alcançadas por ponteiro não são descobertas em x86 sem `.pdata`.
- Structure Discovery não segue aliasing por memória nem ponteiros guardados na pilha; pode ser lento em binários enormes (`--max-functions`).
- Executáveis empacotados/criptografados: analise um dump em memória.
- Compatibilidade com qualquer cliente específico **não é afirmada**: valide por build.

**0.4.1 (Reliability & Accuracy):** correções de lógica que davam resultado errado sem erro — veja `CHANGELOG.md` (cada correção, teste, ressalva e limitação) e a seção 14 de `DOCUMENTACAO_COMPLETA.md`.

Documentação completa: `DOCUMENTACAO_COMPLETA.md` · arquitetura: `PROJETO.md` · mudanças: `CHANGELOG.md`.
