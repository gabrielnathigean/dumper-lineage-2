# l2ud 0.4.1 — Documentação Completa

Referência de tudo que existe no projeto: conceitos, fluxo de dados, **cada arquivo, classe e função**, formatos, banco,
CLI, GUI, testes e como estender.

> Escopo: análise **estática offline** de executáveis PE (PE32 / PE32+). Não injeta, não lê processos, não contorna proteções.
> Nenhum resultado afirma significado semântico (jogador, NPC, item…): tudo é evidência estática.

## Índice
1. [Visão geral](#1-visão-geral) · 2. [Conceitos](#2-conceitos) · 3. [Pastas](#3-estrutura-de-pastas) · 4. [Arquitetura](#4-arquitetura-e-fluxo)
5. [Referência por arquivo](#5-referência-por-arquivo) — `pe` `aob` `functions` `disasm` `cfg` `analysis` `sigs` `siginfo` `aobintel` `structs` `intel` `buildid` `storage` `cli` `gui`
6. [Formatos](#6-formatos-de-arquivo) · 7. [Banco](#7-banco-de-dados) · 8. [CLI](#8-cli) · 9. [GUI](#9-gui) · 10. [Testes](#10-testes) · 11. [Exemplo ponta a ponta](#11-exemplo-de-ponta-a-ponta) · 12. [Estender](#12-como-estender) · 13. [Limitações](#13-limitações-e-pendências)

---

## 1. Visão geral
O `l2ud` abre um `.exe`/`.dll` e ajuda a **localizar e catalogar offsets** de modo reproduzível entre builds:

- lê o PE com validação rígida (seções, imports, exports, relocações, `.pdata`);
- procura **assinaturas AOB** e as resolve em valores (RVA, offset de campo…);
- delimita **funções** (exatas via `.pdata`, derivadas de **CFG**, ou heurísticas);
- com Capstone: constrói **CFG**, separa **código alcançado × região ambígua**, valida os campos da assinatura contra a instrução real,
  sugere assinaturas e descobre **candidatos a estrutura** por dataflow de ponteiros;
- atribui a cada resultado um **status honesto** e gera **relatórios explicativos** (Offset Intelligence);
- guarda cada execução como **AnalysisRun** em SQLite, exporta (JSON/CSV/header C++/Markdown), compara execuções e builds.

Modos: **Lite** (só Python 3.10+) e **Avançado** (`pip install capstone`).

## 2. Conceitos
| Termo | Significado |
|-------|-------------|
| **RVA / VA / File offset** | RVA = relativo à base do módulo; VA = RVA + base (aqui só a **base preferida**, informativa); file offset = posição no arquivo (bss não tem). |
| **AOB** | Padrão de bytes com wildcards (`48 8B ?? 05`). |
| **xref** | Referência de `from_rva` para `target_rva`. Tem **proveniência** (`via`) e, com Capstone, acesso (`rw`). |
| **via** | `opcode` (heurística Lite) · `reloc` · `cfg` (código alcançável) · `linear` (varredura; pode ser dado lido como código). |
| **Limites de função** | `pdata` = exatos · `cfg` = derivados de alcançabilidade · `heuristic` = fracos (prólogo/call). |
| **CFG** | Grafo de fluxo de controle: blocos básicos + arestas. |
| **Região ambígua** | Bytes dentro de uma função que o CFG não alcança (dados, jump table, lixo); `padding` = CC/90 de compilador. |
| **Corroboração forte** | evidência na mesma função, com limites `pdata`/`cfg` **e** xref confiável (nunca `linear`). |
| **known_value** | Valor que **você** verificou manualmente para uma build; chave = **SHA-256 completo**. |
| **AnalysisRun** | Uma execução de `sigs` gravada com seu conjunto de assinaturas, independente das demais. |

### Status
| Status | Regra exata |
|--------|-------------|
| `CONFIRMED` | valor único **+** corroboração forte **+** igual ao `known_value` (SHA-256 completo) da mesma build **+** instrução validada (se Capstone) |
| `STATIC_CORROBORATED` | valor único **+** corroboração forte |
| `PROBABLE` | valor único (ou vários sites concordando) por AOB; corroboração fraca não conta |
| `CANDIDATE` | padrão frágil, instrução não bate com o declarado (Capstone), ou divergência do `known_value`; estruturas |
| `AMBIGUOUS` | matches resolvem para valores distintos |
| `NOT_FOUND` | sem match, padrão inválido, ou alvo fora da imagem |

Ordem de força (diff): `NOT_FOUND < AMBIGUOUS < CANDIDATE < PROBABLE < STATIC_CORROBORATED < CONFIRMED`.

---

## 3. Estrutura de pastas
```
dumper 2/
├── README.md · PROJETO.md · DOCUMENTACAO_COMPLETA.md · CHANGELOG.md · requirements.txt
├── sigs.example.json · hints.example.json
├── demo/ (make_demos.py, sigs_demo.json, hints_demo.json + PEs gerados)
├── l2ud/ (pe aob functions disasm cfg analysis sigs siginfo aobintel structs intel buildid storage cli gui)
├── tests/ (builders.py, test_suite.py)
└── legacy_cpp_draft/
```

## 4. Arquitetura e fluxo
```
 cli.py / gui.py
      │
 intel.py   sigs.py ─ siginfo.py ─ aobintel.py    structs.py     storage.py ─ buildid.py
      └──────────┬──────────┴───────────┬──────────────┘
           analysis.py (Context: fmap + CFGs + xrefs, em cache)
              │         │
         functions.py   cfg.py ─ disasm.py (opcional)
              └────┬────┘
                 pe.py ─ aob.py
```
**Fluxo de `sigs`:** `PeImage.load` → `Context` → por assinatura: `aob.scan` → `_resolve` → (Capstone) `aobintel.check_resolution` →
`_corroborate` (mapa de funções + xrefs) → `_known_for` → `Status` → `Result` → `Database.save_run` → `export`.

---

## 5. Referência por arquivo

### 5.1 `pe.py`
Parser conservador: inconsistência grave → `PeError`; diretórios são best-effort.
- `PeError` · `Section` (`executable`, `discardable`, `span`) · `Export` (`forwarder`) · `Import(dll, name, iat_rva)`.
- `PeImage`: campos `path, raw, is64, machine, image_base, entry_point, size_of_headers, size_of_image, sections, dirs, exports, imports, relocs, functions, timestamp, export_name`.
  - `load(path)` / `parse(raw)` — valida MZ/PE, `numberOfSections` 1..96, optional header, magic PE32/PE32+, lê tabela de seções (clampa `raw_size` truncado), lê TimeDateStamp.
  - `sha256` · `arch` · `section_for_rva` · `rva_to_file` (None para bss) · `file_to_rva` · `rva_to_va` (base preferida) · `read_rva` · `read_cstr` · `u32` · `uptr`.
  - `_parse_exports` (marca forwarders; guarda o **nome interno do módulo**) · `_parse_imports` · `_parse_relocs` · `_parse_pdata`.
  - `function_containing(rva)` — compat (só `.pdata`); o código novo usa `FunctionMap`.

### 5.2 `aob.py`
`AobError` · `compile_pattern` (regex com lookahead: **todas as ocorrências, inclusive sobrepostas**; `?`/`??`/`**` = 1 byte) ·
`Hit(rva, va, file_offset, section)` · `scan(img, pattern, sections, executable_only, max_hits)` (pula seções vazias/descartáveis).

### 5.3 `functions.py`
- `Function(start, end, source, name, ranges)` — `exact` (só `pdata`), `strength` (`exact|derived|weak`), `label`, **`cover`** (intervalos reais), `contiguous`. `end` é só o envelope.
- `FunctionMap` — `containing(rva, strict=True)` (**exatamente uma** função cobrindo o endereço, senão `None`), `covering(rva)`, `overlaps()`, `source`, `__len__`.
- `build_function_map(img)` — com `.pdata`: limites exatos. Sem: heurística (prólogos, alvos de call com ≥2 chamadores, entry, exports), fim = início da próxima, padding aparado.

### 5.4 `disasm.py` (Capstone opcional)
- `available()` · `DisasmUnavailable` · `canon_reg("ecx") -> ("rcx", 32)` (tabela `REGS`; `xmm*` voltam com 0 bits).
- `MemRef(base, index, scale, disp, size, access, rip_target, abs_va, segment)` — registradores **canônicos**.
- `Op(kind 'reg'|'imm'|'mem', size, reg, bits, imm, mem, access)` · `Insn` (`rva, size, end, mnemonic, op_str, raw, kind, target, ops, mems, imms, regs_read, regs_written, disp_offset, disp_size, imm_offset, imm_size`; `text()`).
- `Disassembler(img)`: `is_code(rva)` · `_bytes` (nunca lê fora dos dados da seção) · `_convert` · `decode_one` · `decode(rva, count)` · `sweep(start, end)` (**linear**, ressincroniza) · `read_ptr_table` (tabela de VAs).

### 5.5 `cfg.py` (Capstone)
Recursive descent: só é "código" o que é **alcançável**.
- `Block(start, end, insns, succs[(alvo, fall|jmp|jcc|table)], terminator, calls, indirect_calls, indirect_unresolved)`.
- **0.4.1:** `ExternalEdge(src, dst, kind, cls, known_function)` · `JumpTable(jmp_rva, table_rva, entry_format, bound, declared_count, entries, rejected, resolved)`.
- `CFG(entry, blocks, calls, tail_calls, reachable, ambiguous[(a,b,tag)], bounds, truncated, invalid, invalid_edges, external, jump_tables)` — `extent` (envelope, só exibição), `preds()`, `block_of`, `instruction_count`, `summary()`. `tail_calls` só tem alvos **executáveis**; `external` tem todos os desvios que saem da função.
- `build_cfg(img, d, entry, limit=None, known_starts, max_insns=20000)` — `limit` = limites **exatos** (nada fora é seguido; `jmp` para fora vira tail call). Resolve **jump table x86** (`jmp [idx*4+tabela]`, até 256 entradas, só alvos em código); `jmp reg` fica `indirect_unresolved`. Regiões: `padding` (só CC/00/90), `jump_table`, `ambiguous`; **padding CC/90 nas pontas é separado** (zeros não são aparados, podem ser dados).
- `build_function_map_cfg(img, d, seed_map)` — com `.pdata` devolve o mapa exato (CFGs sob demanda); sem `.pdata` descobre funções por alcançabilidade (`source="cfg"`, fim = extensão do CFG).
- `collect_xrefs(img, fmap, cfg_of, include_linear)` — `via="cfg"` para instruções alcançáveis; `via="linear"` para regiões ambíguas/lacunas (marcadas **não confiáveis**; cada região é varrida uma vez).
- `to_dot(cfg)` — Graphviz.

### 5.6 `analysis.py`
- `Xref(from_rva, kind, target_rva, function, engine, via, rw)` + `trusted` (`via != "linear"`).
- `reloc_refs` (relocs tipo 3/10 → `abs` em código, `ptr` em dados) · `lite_xrefs` (opcodes x64 + call/jmp rel32 + relocs) · `all_code_xrefs` (compat) · `get_xrefs(img, engine)` · `xrefs_to` · `import_refs` (xref → slot da IAT).
- `find_strings` (ASCII/UTF-16, seções de dados) · `fingerprint` (**estrutural**, não é identidade).
- `Context(img, engine, use_cfg, include_linear)` — cache preguiçoso: `capstone`, `engine_label`, `disassembler`, `fmap` (com CFG se Capstone), `cfg(fn|rva)` (limites exatos quando `.pdata`), `xrefs` (+ `engine_used`).
- `hexdump(img, rva, n)` · `hexdump_file(img, off, n)` (mostra o RVA de cada linha) · `string_at` · `analyze_function(img, ctx, rva)` (limites + `bounds_label`, callers, callees, strings, imports, **resumo do CFG**, regiões ambíguas).

### 5.7 `sigs.py`
- `Status`, `STATUS_ORDER`, `Result` (`value, kind, candidates, notes, evidence, value_kind, va, file_offset, pattern, hits, meta`; `hits`/`meta` não vão ao banco).
- `_resolve` por `kind`: `hit`, `rip` (`hit + insn_len + disp32`), **`rel`** (REL32 estrito: `insn_len - disp_offset == 4`), **`rel8`** (branch curto, 1 byte com sinal), **`abs`** (VA absoluto − ImageBase), `imm` (inteiro de `size` bytes). Sem Capstone, `_branch_width_conflict` confere o opcode anterior ao operando.
- `_known_for` — exige **SHA-256 completo** (64 hex); prefixo/fingerprint → `ValueError`.
- `_corroborate(img, sig, hits, ctx) -> list[Ev]`: só recebe matches **resolvidos e validados**; cada `Ev(source, fn, hit, xref, via, engine, strong, text)` está ligada ao match que a sustenta. Forte = limites `exact`/`derived` + xref confiável; fraca = limites heurísticos **ou** só varredura linear ("NÃO conta"). Evidências da mesma origem contam uma vez; `_independent` conta fontes (tipo, função).
- `run_signature` — (1) padrão/qualidade/scan; (2) resolve cada match (`hit_status`); (3) valores distintos → `AMBIGUOUS`; (4) **validação Capstone de TODOS os matches resolvidos** (`VALIDATION_LIMIT`=500; acima disso é parcial, declarada, e bloqueia `CONFIRMED`); (5) corroboração só dos matches válidos; (6) `known_value`; (7) fragilidade/validação rebaixam para `CANDIDATE`.
- `load_sigs` · `sigs_digest` (hash do conjunto) · `run_all`.

### 5.8 `siginfo.py`
`pattern_quality` (score = `fixos*6 + maior_run*4 − wildcards*20 − comuns*30`, 0..100; flags `too_short`, `mostly_wildcards`, `low_entropy`, `no_anchor`; `fragile` = `too_short` ou score<40) ·
`analyze_set` (nomes repetidos, padrões idênticos, "mais genérico que") · `stability` (roda em várias builds).

### 5.9 `aobintel.py` — AOB Intelligence
- `check_resolution(img, ctx, hit, sig) -> SigCheck(ok, issues, instruction, actual, suggestion)` — offsets são relativos ao **início do match**; acha a instrução que **contém** o campo e confere `disp_offset`/`insn_len`/`size` conforme `kind`; detecta match **no meio de instrução** (via CFG) e sugere valores corretos.
- `generate(img, ctx, rva, max_len, wild_fields)` → `Suggestion` — instruções reais; wildcard em `disp32` rip-relativo, endereços absolutos, destinos de branch e imediatos-VA (x86); `wild_fields` também em deslocamentos de campo; estende até ser **único** e não frágil.
- `variable_bytes_at(points, length, before, after)` → `VarReport` (offsets que variam, padrão sugerido para o núcleo e para a janela com contexto estável) · `find_points(images, pattern)`.
- `analyze_context` (instruções vizinhas via CFG; avisa quando decodificar "para trás" seria ambíguo) · `genericity` (matches, instruções cobertas, flags `single_instruction/too_many_matches/generic/fragile_pattern`) · `analyze_signature`.

### 5.10 `structs.py` — Structure Discovery v2 (Capstone)
**Origem em vez de registrador.** Dataflow por função sobre o CFG; cada registrador guarda `Ptr(obj, off)`:
`('arg', fn, i)` (reg: rcx/rdx/r8/r9; x86: ecx/edx; pilha: 10+k) · `('glob', rva)` · `('ret', callee)` · `('deref', obj, off)` · `('elem', obj, off)`.
- `_FnAnalyzer.step/run` — `mov/lea/add/sub/push/call` e escritas; `mov reg,[base+d]` de tamanho de ponteiro vira `deref`; chamadas limpam voláteis e produzem `ret`; `mov ebp,esp` marca o frame (x86: `[ebp+8+4k]` = argumento de pilha). Estado nos joins = interseção (iteração até ponto fixo).
- Coleta `Access` (inclui **índice** e **offsets negativos**), `CallSite` (argumentos), `Store` (ponteiro gravado em campo).
- **Classes** (`_Class`, `_UF`): uma por chave de objeto; fundem **só** por (a) igualdade estrutural (mesmo global/retorno/cadeia), (b) ponteiro (off 0) passado como argumento, (c) ponteiro gravado em campo, (d) congruência. Recusa fusão em **conflito** (offset ponteiro × float/inteiro pequeno) e ignora **hubs** (`hub_limit`, padrão 6 objetos distintos no mesmo argumento). Layout parecido **não** funde → relação `similar_layout`.
- Relações: `pointer_field`, `embedded_subobject`, `collection_hint` (hipótese fraca), `vtable_like`, `passed_to_hub`, `similar_layout`.
- `StructCandidate` (`fields`, `size_estimate`, `functions`, `roots`, `relations`, `evidence`, `interest`, `confidence`≤`medium`, `status="CANDIDATE"`; `to_dict`, `from_dict`, `render_text`). `evidence` ganhou `assumptions`, `dataflow_incomplete`, `pointer_strong/weak`, `x86_conventions`, `refused_merges`; cada campo tem `pointer_evidence`.
- `discover(img, ctx, hints, min_fields, max_functions, function, hub_limit, assume_x86_reg_args)` · `describe_key(k, is64)` · `_hint_functions` (hints = dicas "NÃO verificado"). `merge` nunca ignora conflito: `implied_conflict` antecipa os filhos implicados pela congruência. `pointer` = uso como base; senão `pointer_candidate`.
- `confidence = medium` se `score ≥ 16` (funções×2 até 6 + campos até 12 + 3 se global + fusões até 3) sem tamanhos mistos; `interest = score×4 − 8×ressalvas`.

### 5.11 `intel.py` — Offset Intelligence
`ref_stats` (total, funções, tipos, leitura/escrita, `via`, amostra) · `report_offset` (consolida assinatura, validação, função, referências, estruturas relacionadas, histórico; **explicação factual**; `interest` de triagem) ·
`explain_struct` · `build_report(img, ctx, results, structs, history_of)` · `to_markdown`. Sempre inclui **"O que NÃO foi estabelecido"** e nunca atribui significado.

### 5.12 `buildid.py`
`BuildProfile` (sha256, fingerprint, arch, machine, timestamp, módulo, tamanho, seções, imports, exports, **MinHash de strings**) · `compute_profile` · `similarity` (imports .25, exports .15, seções .1, nomes de seção .1, strings .4; arch diferente ×0.5) · `families(threshold)` (**ligação completa**: sem encadeamento) · `family_report` (mín/média por membro) · `identity`.
**SHA-256 completo = identidade definitiva; fingerprint = estrutural; similaridade ≠ compatibilidade de assinaturas.**

### 5.13 `storage.py`
- `Database` (context manager; **gravações atômicas**): `register_build`, `save_run` → `(build_id, run_id)` (recusa nomes repetidos), `save` (compat), `save_structs`, `builds`, `builds_info`, `latest_run`, `resolve` (id **exato** → SHA-256 completo → prefixo **único** ≥8 hex, ambíguo = `AmbiguousBuild`; `3@5`, `@5`) · `_check_run` (a run tem que pertencer à build), `runs`, `run_sigs`, `results(build, run)` (**uma run**), `image_base`, `build_events`, `profile`, `history`, `load_structs` (sem run explícita usa a mais recente **que tem** estruturas), `delete_run`, migração `0.2/0.3 → run "legacy"`.
- `select` / `export` (`json|csv|hpp`) / `write_export` · `export_structs` (`json|md`) · `diff` (`changed` com Δ, `added`, `removed`, `degraded`, `improved`, `pattern_changed`).
- `.hpp`: `constexpr std::uint32_t NOME_RVA`/`NOME_OFFSET`, `PREFERRED_IMAGE_BASE` (informativo), `va_from_rva(module_base, rva)`. Export padrão = `CONFIRMED` + `STATIC_CORROBORATED`.

### 5.14 `cli.py`
Um `cmd_*` por comando (ver §8). Helpers: `_load`, `_ctx` (flags `--engine/--no-cfg/--no-linear`), `_db` (fecha a conexão ao fim do comando), `_need_cs`.

### 5.15 `gui.py`
`App(tk.Tk)` — ver §9. Trabalho pesado em thread; **variáveis Tk só na thread principal** (valores são capturados antes); SQLite só na thread principal.

---

## 6. Formatos de arquivo
**Assinaturas** (`sigs.json`, lista): `name`, `pattern`, `kind` (`rip` · `rel` · `abs` · `imm` · `hit`), `disp_offset`, `insn_len`, `size`, `sections`, `executable_only`,
`confirm_string`, `confirm_import`, `confirm_export`, `known_value` (`{"<sha256 completo>": "0x…"}`), `value_kind`. Com Capstone, `disp_offset`/`insn_len`/`size` são **validados**.
**Hints** (`{"Categoria": ["string", …]}`) — só dicas "NÃO verificado" em `structs`.
**Export JSON:** `{build, image_base_preferred, results:[{name,status,kind,value_kind,value,rva,va_preferred_base,file_offset,candidates,notes,evidence}]}`.

## 7. Banco de dados
`builds(id, sha256 UNIQUE, path, arch, fingerprint, image_base, created, machine, timestamp, module, size, profile)` ·
`build_events(build_id, ts, kind, detail)` · `runs(build_id, started, tool_version, engine, sigs_digest, sigs_json, note)` ·
`run_results(run_id, name, status, kind, value, value_hex, value_kind, va, file_offset, pattern, candidates, notes, evidence)` ·
`run_structs(run_id, cand_id, data)`. Tabelas legadas (`results`, `structs`) permanecem após a migração, sem uso.

## 8. CLI
`python -m l2ud <comando>` (Windows: `py -3 -m l2ud …`). Comandos: `info scan strings xrefs func cfg disasm hex sigs sigcheck siggen sigvar sigctx siginfo structs report builds runs events export diff history similar buildinfo gui`.
Detalhes e flags no `README.md`. `--engine`, `--no-cfg`, `--no-linear` aplicam-se a `strings xrefs func cfg sigs sigcheck siggen sigctx siginfo report`.

## 9. GUI
Abas: **Resultados** (detalhe com RVA/VA/file offset, matches, validação Capstone, evidências) · **Hex** (RVA/file offset, paginação ◀▶, busca AOB) ·
**Disassembly** (cabeçalho com limites da função, próxima página) · **CFG** (blocos desenhados em camadas; arestas coloridas; exporta DOT) ·
**Referências** (xrefs com `via`/`rw` + análise da função) · **Estruturas** (árvore: origem/campos/relações/hints/evidência; descobrir, salvar/carregar no DB, exportar) ·
**Relatório** (Offset Intelligence, com histórico do DB opcional; salvar `.md`) · **Builds/DB** (builds, runs, comparar 2 runs, eventos, similaridade, salvar execução atual).

## 10. Testes
`py -3 tests\test_suite.py` — 116 testes (58 exigem Capstone); eles são pulados sem ele. `py -3 tests\test_v050.py` — 38 testes dos módulos pós-0.4.1 (GUI é pulada sem display). `tests/builders.py` gera PEs sintéticos
(x64 com `.pdata`, x86 com `.reloc`, jump table, função thiscall, laço com dados no meio, reuso de registrador, global compartilhado, passagem de argumento, conflito, array/negativo, cadeia de ponteiros).

## 11. Exemplo de ponta a ponta
```bat
py -3 -m l2ud info cliente.exe
py -3 -m l2ud strings cliente.exe "Login" --xrefs
py -3 -m l2ud func cliente.exe 0x1A2B30
py -3 -m l2ud siggen cliente.exe 0x1A2B30                 :: sugere padrão; confira à mão
py -3 -m l2ud sigcheck cliente.exe sigs.json --context    :: valida disp_offset/insn_len
py -3 -m l2ud siginfo sigs.json cliente_v1.exe cliente_v2.exe
py -3 -m l2ud sigs cliente_v1.exe sigs.json --db l2ud.db --note "v1"
py -3 -m l2ud sigs cliente_v2.exe sigs.json --db l2ud.db --out offsets.hpp
py -3 -m l2ud diff 1 2
py -3 -m l2ud report cliente_v2.exe sigs.json --structs --db l2ud.db --out relatorio.md
```
Depois de **você** verificar um valor numa build, acrescente `known_value` com o **SHA-256 completo** dela (`buildinfo` mostra).

## 12. Como estender
- Novo `kind`: ramo em `sigs._resolve` + validação em `aobintel.check_resolution`.
- Nova corroboração: bloco em `sigs._corroborate` (devolva fortes/fracas).
- Novo formato de export: ramo em `storage.export`.
- Outro desassembler: reimplemente `Disassembler`/`Insn`/`MemRef` em `disasm.py` mantendo os campos.
- Análise dinâmica: leitor JSON → `Result` (status ≤ `PROBABLE`) → `Database.save_run`.

## 13. Limitações e pendências
- Nenhum teste contra binário real de jogo; **compatibilidade não é afirmada**.
- CFG: sem jump tables x64, sem chamadas indiretas/vtables, sem `noreturn`; funções só alcançadas por ponteiro não são descobertas (x86 sem `.pdata`).
- Structure Discovery: sem aliasing por memória/pilha; pode ser lento em binários enormes; confiança máxima `medium`.
- Executáveis empacotados/criptografados: analise um dump em memória.
- Sem importador de artefatos de análise dinâmica; Zydis não suportado.
- GUI validada por script, não em uso interativo prolongado.

## 14. 0.4.1 — invariantes garantidas (e testadas)

Estas propriedades valem em qualquer imagem e têm teste de regressão em `tests/test_suite.py` (classes `TestAudit041*`).

**CFG / funções**
1. Nenhuma instrução decodificada se sobrepõe a outra. Um destino no meio de instrução vira `CFG.invalid_edges` (`inside_instruction` / `overlap`), nunca uma segunda decodificação.
2. Todo desvio que sai da função está em `CFG.external` com classe `tail_transfer | not_executable | outside_image | unmapped`; só `tail_transfer` entra em `tail_calls`.
3. Uma jump table só gera arestas com **limite provado** (`cmp reg,N` + `ja/jae`). Sem limite: `resolved=False`, entradas só candidatas, salto "indireto não resolvido". Entradas rejeitadas são registradas **uma a uma** com o motivo.
4. `Function.cover` é a cobertura REAL (blocos alcançados). `FunctionMap.containing(rva)` só responde quando **exatamente uma** função cobre o endereço; vãos e regiões sobrepostas devolvem `None` (`covering()`/`overlaps()` mostram o porquê).

**Assinaturas**
5. `kind: rel` é REL32 (`insn_len - disp_offset == 4`); branch curto exige `kind: rel8`. Sem Capstone o opcode anterior ao operando é conferido.
6. Com Capstone **todos** os matches resolvidos têm a instrução validada; acima de `VALIDATION_LIMIT` (500) a validação é parcial, **declarada**, e `CONFIRMED` fica bloqueado.
7. Só matches **resolvidos e validados** podem corroborar. Cada evidência está ligada ao match que a sustenta (`meta.evidence_items`); evidências da mesma origem contam uma vez (`meta.independent_sources`).
8. Corroboração só é "forte" com limites de função `pdata`/`cfg` **e** xref confiável (`opcode`/`reloc`/`cfg`; nunca `linear`).

**Estruturas**
9. Nenhuma fusão ignora a checagem de conflito, inclusive as implicadas por congruência (`implied_conflict`).
10. `pointer` exige **uso como base**; só argumento/store → `pointer_candidate`.
11. ecx/edx como argumentos x86 são **hipótese** (`evidence.assumptions`, confiança `low`); ESP/pilha x86 são rastreados.
12. Se o dataflow não converge, os candidatos afetados trazem `evidence.dataflow_incomplete` e confiança `low`.

**Banco / builds**
13. Toda run explícita é verificada contra a build (`results`, `load_structs`, `save_structs`, `resolve("b@r")`).
14. Resolução: id exato → SHA-256 completo → prefixo **único** de ≥8 hex (ambíguo = `AmbiguousBuild` com as candidatas).
15. Gravações são atômicas (build + run + resultados + evento: tudo ou nada); nomes repetidos na mesma run são recusados.
16. Famílias de builds usam ligação completa; arquitetura diferente nunca agrupa.

### Comportamentos NÃO comprovados (leia antes de confiar)
- A convenção de chamada x86 nunca é provada; só argumentos de pilha vindos de `esp`/`ebp` têm base concreta.
- O rastreio de pilha perde o ESP ao chamar callee desconhecido/indireto/API.
- Corroboração por string/import/export mostra coocorrência na função, não identidade semântica.
- O dataflow não foi visto não-convergindo em binário real (o teto é reportado, mas só foi exercitado em teste).
- Nenhum teste com binário de jogo.

## 15. 0.5.0 — Auto Discovery of Offsets & Data Structures

Escopo: análise **estática offline**. Pipeline completo de descoberta automática cobrindo funções, globais, vtables, coleções, assinaturas e persistência.

**`bundle.py`** — `analyze_bundle(pasta, recursive=False)` → `BundleReport`. Por módulo (`ModuleInfo`): SHA-256, arquitetura REAL
(`Machine` + `OptionalHeader.Magic`; `arch_consistent=False` se discordarem), timestamp, ImageBase, seções com **entropia**, imports/exports,
fingerprint e **indicadores de empacotamento** (nomes típicos de protetor, executável de entropia alta, EP fora da seção de código,
poucos imports, só imports de carregador, overlay grande; níveis `none|possible|likely`). O conjunto tem `bundle_id` (independe da ordem)
e `BundleIssue`s: `IMPORT_UNRESOLVED`, `TIMESTAMP_SPREAD`, `MIXED_ARCH`, `ARCH_MISMATCH`, `PACKING_*`, `DUPLICATE_NAME`.

**`progress.py`** — `Progress(callback, cancel)` (etapas) e `CancelToken` (cancelamento cooperativo: `check()` levanta `Cancelled` entre unidades).

**`evgraph.py`** — `EvidenceGraph`: nós (módulo, função, global, pointer_slot, struct, field, vtable, collection, import, string),
arestas e `Evidence(type, origin, function, trusted, via)`. Evidências de mesma origem colapsam em UMA observação. `assess(nó)`: `STATIC_CORROBORATED`
só com ≥2 observações independentes, ≥2 tipos e ≥2 confiáveis.

**`catalog.py`** — `Catalog`/`CatalogItem` com valores TIPADOS (`RVA`, `FILE_OFFSET`, `STRUCT_MEMBER_OFFSET`, `STRUCT_SIZE`, `INTEGER`, `RELATION`),
ids estáveis por (build, categoria, tipo, valor), status (`STATIC_CANDIDATE`, `STATIC_CORROBORATED`, `KNOWN_REFERENCE_VALIDATED`, `RUNTIME_VALIDATED`)
e exportação em `.json`, `.csv`, `.md` e C++ Header `.hpp`.

**`modwork.py`** — `ModuleWork`: contexto de análise de um módulo compartilhando índices de xrefs, IAT, strings e fábrica de itens e evidências.

**`funcdisc.py`** — descoberta automática de funções: limites (.pdata exatos / derivados CFG / heurísticos), chamadores/chamados, strings e imports.

**`globaldisc.py`** — descoberta de variáveis globais (`GLOBAL_VARIABLES`) e slots de ponteiro (`GLOBAL_POINTER_CANDIDATES`) em seções de dados,
mapeando relocações estáticas e referências de leitura/escrita decodificadas do código.

**`vtabledisc.py`** — descoberta de tabelas virtuais (`VTABLE_CANDIDATES`) com parser de MSVC RTTI (`_RTTICompleteObjectLocator` e `TypeDescriptor`),
descorando nomes de classes (`.?AVPlayer@@` -> `vtbl_Player`), contando métodos virtuais e vinculando ao grafo via `contains_method`.

**`collectiondisc.py`** — reconhecimento de containers em memória (`std::vector` de 3 ponteiros, `TArray` do Unreal de ponteiro + 2 inteiros de 4 bytes,
listas encadeadas), preenchendo `COLLECTION_CANDIDATES` e `POINTER_RELATIONSHIPS`.

**`autosig.py`** — geração automática de assinaturas AOB com wildcards em operandos variantes (rel32, ponteiros absolutos) e validação de unicidade
(roundtrip garantindo exatamente 1 match na imagem).

**`pipeline.py`** — `AutoDiscoverPipeline`: orquestrador de ponta a ponta executando as etapas 1 a 7 cooperativamente em bundles ou módulos individuais.

**`storage.py`** — persistência e recuperação do catálogo no SQLite (`catalog_runs`, `catalog_items`, `catalog_graphs`), com `save_catalog`, `load_catalog` e `list_catalog_runs`.

**`crossbuild.py`** — `CrossBuildDiff`: comparação entre catálogos de builds diferentes, casando itens por assinatura AOB e exports/RTTI, identificando itens `UNCHANGED`, `MOVED` (com delta numérico), `STATUS_CHANGED`, `ADDED` e `REMOVED`.

**`validation.py`** — `apply_validation`: importação de validação externa para promoção para `KNOWN_REFERENCE_VALIDATED` e `RUNTIME_VALIDATED` com checagem de divergência de valores.

**CLI**
```
l2ud bundle PASTA [--recursive] [--json relatorio.json] [-v]
l2ud funcs MODULO [--max-functions N] [--limit N] [--out catalogo.json] [--force]
l2ud autodiscover PASTA_OU_MODULO [--out catalogo.hpp] [--db l2ud.db] [--note "v1"]
l2ud diff-catalog catalogo_v1.json catalogo_v2.json [--out diff.md]
l2ud validate catalogo.json validacao.json [--out catalogo_validado.json]
l2ud catalog-runs [--db l2ud.db]
```

**GUI**
- Nova aba **Catálogo** com visualização em árvore, filtros dinâmicos por categoria e status, inspeção detalhada de evidências/assinaturas e exportação direta para `.hpp`, `.json`, `.csv` ou `.md`.
