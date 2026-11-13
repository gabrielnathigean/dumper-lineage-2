# Changelog

## 0.5.0 — Auto Discovery of Offsets & Data Structures

Implementação completa das 12 etapas do plano de descoberta automática de offsets e estruturas:

### Novas Funcionalidades
- **`bundle.py` (Etapa 1)**: Analisador de pasta de módulos PE como conjunto (Machine + Magic, consistência, empacotamento, progresso e cancelamento cooperativo).
- **`evgraph.py` & `catalog.py` (Etapa 2)**: Grafo de evidências com proveniência e regra estrita de corroboração (≥2 observações, ≥2 tipos, ≥2 confiáveis). Catálogo tipado que não mistura RVA com offsets relativos, e exportadores para `.json`, `.csv`, `.hpp` e `.md`.
- **`funcdisc.py` (Etapa 3)**: Descoberta automática de funções sem assinaturas manuais (limites exatos/CFG/heurísticos, chamadores/chamados, strings e imports).
- **`globaldisc.py` (Etapa 4)**: Descoberta de variáveis globais escalares (`GLOBAL_VARIABLES`) e slots de ponteiro (`GLOBAL_POINTER_CANDIDATES`) a partir de relocações em dados e instruções de código com rastreamento de leitura/escrita.
- **`vtabledisc.py` (Etapa 5)**: Descoberta de tabelas virtuais com parser completo de MSVC RTTI (`_RTTICompleteObjectLocator` e `TypeDescriptor`), descorando classes (`.?AVPlayer@@` -> `vtbl_Player`) e vinculando métodos no grafo (`contains_method`).
- **`collectiondisc.py` (Etapa 6)**: Reconhecimento de coleções (`std::vector`, `TArray`, listas duplamente encadeadas) e relações de propriedade/buffer em `COLLECTION_CANDIDATES` e `POINTER_RELATIONSHIPS`.
- **`autosig.py` (Etapa 7)**: Geração automática de assinaturas AOB únicas com wildcards em deslocamentos relativos e endereços absolutos, validando roundtrip exato (1 match na imagem).
- **`pipeline.py` & `storage.py` (Etapa 8)**: Orquestrador `AutoDiscoverPipeline` que executa todas as etapas cooperativamente; persistência e recuperação do catálogo no SQLite (`catalog_runs`, `catalog_items`, `catalog_graphs`).
- **`crossbuild.py` (Etapa 9)**: Comparação entre builds diferentes (`CrossBuildDiff`) casando itens por assinatura AOB, nome de export/RTTI e gerando relatório de itens inalterados, deslocados (com delta), novos e removidos.
- **`validation.py` (Etapa 10)**: Importador de validação externa para promoção segura para `KNOWN_REFERENCE_VALIDATED` e `RUNTIME_VALIDATED` com validação de convergência de valores.
- **CLI & GUI (Etapa 11)**:
  - Novos comandos CLI: `l2ud autodiscover`, `l2ud diff-catalog`, `l2ud validate`, `l2ud catalog-runs`.
  - Nova aba "Catálogo" na interface gráfica Tkinter com visualização em árvore, filtros por categoria/status, inspeção de detalhes e exportador integrado.
- **Testes (Etapa 12)**: 46 novos testes automatizados em `tests/test_v050.py` cobrindo 100% das etapas implementadas (totalizando 162 testes na suíte geral).

---

## 0.4.1 — Reliability & Accuracy Update

Atualização de **correção**, sem recursos novos grandes. Nasceu de uma auditoria da 0.4.0; antes de corrigir, cada
alegação foi **reproduzida contra o código real** com um fixture sintético, e cada correção virou um teste de regressão.
16 alegações se reproduziram, 4 tinham ressalvas (ver "Ressalvas à auditoria") e 1 cenário citado não era alcançável.

### Correções (item → o que mudou → teste)

| # | Problema (reproduzido) | Correção | Teste |
|---|---|---|---|
| 1.1 | CFG decodificava a partir do MEIO de uma instrução já decodificada → instruções e blocos **sobrepostos** | índice byte→instrução; destino no meio de instrução ou instrução que invadiria bytes decodificados vira `invalid_edges` (`inside_instruction`/`overlap`) e **não é decodificado** | `TestAudit041Cfg.test_branch_into_middle_of_instruction_creates_no_overlap` |
| 1.2 | `jcc` para fora da função sumia do grafo; `jmp` para região **não executável** virava "tail call" | todo desvio que sai da função é registrado em `cfg.external` e classificado (`tail_transfer`, `not_executable`, `outside_image`, `unmapped`); só alvo executável entra em `tail_calls` | `test_external_branches_are_classified_not_dropped` |
| 1.3 | tabela de saltos x86 lida por "parecer endereço" (podia **ler além do fim**) | a tabela só vira aresta com **limite provado** (`cmp reg,N; ja/jae`); sem limite fica `resolved=False` (entradas só candidatas, salto "indireto não resolvido"); `JumpTable` registra formato, limite, entradas aceitas e **rejeitadas por entrada** | `test_jump_table_needs_proven_bound`, `test_unbounded_jump_table_is_not_deduced`, `test_valid_looking_entry_past_the_proven_bound_is_not_read`, `test_rejected_table_entries_are_recorded_individually` |
| 4 | `FunctionMap.containing` usava só `[start, end)` (envelope): blocos descontínuos, dados e outras funções eram atribuídos; com extensões sobrepostas devolvia `None` em endereço válido | `Function.ranges/cover` (cobertura REAL = blocos alcançados); `containing` só responde com **exatamente uma** função cobrindo; `covering()` e `overlaps()` expõem ambiguidades | `TestAudit041FunctionMap.*`, `test_cfg_function_covers_only_reached_blocks` |
| 2.1 | congruência chamava `merge(..., check=False)` → fundia classes em conflito (ponteiro × float) | **nenhuma** fusão ignora a checagem; `implied_conflict` antecipa o conflito dos campos-ponteiro filhos que a congruência implicaria e recusa a fusão-pai (registrada em `refused_merges`) | `test_congruence_cannot_merge_classes_with_conflicting_children` |
| 2.2 | ecx/edx tratados como argumentos de toda função x86 | agora são **hipótese** declarada: raiz descrita como "HIPÓTESE thiscall/fastcall", `evidence.assumptions`, confiança forçada a `low`, `x86_conventions` (registradores lidos antes de escritos); `assume_x86_reg_args=False` / `--no-x86-reg-args` desliga | `test_x86_register_args_are_hypotheses` |
| 2.3 | pilha x86 = lista dos "últimos push"; ESP não era rastreado; `[esp+4]` (FPO) **não era visto** (0 candidatos) | ESP relativo à entrada, slots de pilha, frame pointer (`mov ebp,esp`/`leave`), `ret N` do callee (via CFG), argumentos de pilha por slot (`arg10+`); callee desconhecido → perde o rastreio (honesto) | `test_x86_fpo_argument_is_tracked_through_esp`, `test_x86_stack_args_merge_through_push_and_callee_ret_n`, `test_spilled_non_pointer_push_is_not_taken_as_argument` |
| 2.4 | teto de iterações do dataflow estourava em silêncio | `run()` devolve `converged`; blocos pendentes registrados; candidatos afetados: `evidence.dataflow_incomplete`, confiança `low`, interesse reduzido | `test_nonconvergence_is_reported_and_lowers_confidence` |
| 2.5 | `pointer` por qualquer leitura do tamanho de ponteiro usada como argumento/gravada | `pointer` exige **uso como base**; só argumento/store → `pointer_candidate` (`pointer_evidence`); só ponteiro forte gera `pointer_field` e conflito de tipo | `test_pointer_needs_use_as_base` |
| 3.1 | `kind: rel` lia sempre 4 bytes; `rel8` virava valor errado e a validação **aprovava** | `rel` = REL32 estrito (`insn_len - disp_offset == 4`), novo `rel8`; sem Capstone o opcode anterior denuncia a largura; com Capstone `imm_size` é conferido e a sugestão traz o `kind` certo | `test_rel8_is_not_resolved_as_rel32`, `test_rel32_is_not_accepted_as_rel8`, `TestAudit041Sigs.test_rel8_validated_and_wrong_kind_suggests_rel8` |
| 3.2 | validação Capstone olhava só `hit_rvas[:3]` | valida **todos** os matches resolvidos; acima de `VALIDATION_LIMIT` (500) a validação é **parcial, declarada** (`meta.validation.partial`, nota) e `CONFIRMED` fica bloqueado | `test_every_match_is_validated_including_the_hidden_one`, `test_partial_validation_is_declared_and_blocks_confirmed` |
| 3.3 | corroboração vinha de matches **não resolvidos** (função de outro match promovia o resultado) | `_corroborate` só recebe matches resolvidos **e** validados; cada evidência está ligada ao match que a sustenta; `meta.hit_status` por match | `TestAudit041SigsLite.test_unresolved_match_never_corroborates` |
| 3.4 | `generate()` partia de qualquer RVA, inclusive meio de instrução | verifica a fronteira via CFG: `start_reliable` True/False/None, aviso, e `require_boundary` / `--strict-boundary` recusa | `test_generate_warns_when_start_is_not_an_instruction_boundary` |
| 5 | abs de 64 bits truncado em 32; constante tratada como endereço | `abs_va` com a largura do ponteiro; com relocações na imagem, imediato/absoluto só é endereço se houver **relocação** no campo | `TestAudit041Disasm.*` |
| 8 | evidências da mesma origem podiam parecer independentes | deduplicação por (fonte, instrução, match); `meta.independent_sources` conta (tipo, função) distintos; preserva `cfg/opcode/reloc/linear` na evidência | `test_evidence_from_same_source_is_not_counted_as_independent` |
| 5.1 | run de OUTRA build era aceita; `save_structs(b1, [], run_de_b2)` **apagava** as estruturas de b2 | `_check_run` em `results`, `load_structs`, `save_structs` e `resolve("b@r")` | `TestAudit041Storage.test_run_must_belong_to_build` |
| 5.2 | `resolve("2")` devolvia a build cujo SHA começa com `2`; prefixo ambíguo devolvia uma qualquer | id exato primeiro; SHA completo; prefixo ≥8 hex **único** (ambíguo → `AmbiguousBuild` listando as candidatas); a CLI imprime `erro: …` | `test_numeric_id_priority_and_unique_prefix_rules`, `test_cli_reports_ambiguous_reference_as_error_message` |
| – | falha no meio de `save_run` deixava run parcial que o próximo `commit` consolidava | `save_run`, `save_structs`, `register_build`, migração e `delete_run` são **atômicos** (`with con:`); nomes de resultado repetidos na run são recusados; assinaturas com nome repetido são recusadas em `load_sigs` | `test_failed_save_run_rolls_back_everything`, `test_duplicate_result_names_are_rejected`, `test_duplicate_signature_names_are_rejected` |
| 5.3 | `families()` por componentes conexos **encadeava** A~B~C com A≁C | **ligação completa**: todo membro é similar a todos; `family_report` dá mín/média por membro; arquitetura diferente nunca agrupa | `TestAudit041BuildId.*` |

### Ressalvas à auditoria (o que NÃO era exatamente como alegado)
- **1.3** "parar na 1ª entrada inválida perde entradas válidas": em x86 `limit` é sempre `None`, então esse cenário não era alcançável; o defeito real era o oposto (ler além do fim).
- **2.5** a 0.4.0 já exigia uso como base **ou** argumento **ou** store; o defeito era tratar os dois últimos como prova.
- **2.2/2.3** não se reproduziu um falso positivo concreto; o efeito dominante era **perder** argumentos.
- **2.4** o teto foi atingido só artificialmente (teste); não foi observado em binários reais.

### Mudanças de comportamento / compatibilidade
- `CFG.tail_calls` agora só tem alvos **executáveis**; use `CFG.external` para ver todos os desvios que saem da função.
- `Function` ganhou `ranges`/`cover`/`contiguous`; `FunctionMap.containing` pode devolver `None` onde a 0.4.0 devolvia uma função (vãos, regiões sobrepostas).
- Jump tables x86 **sem** `cmp/ja` deixam de gerar arestas (antes geravam). `cfg.jump_tables` guarda as candidatas.
- `kind: rel` rejeita branch curto; use `rel8`.
- `Result.hits` = matches **resolvidos**; `meta.hit_status` traz o estado de cada match.
- Structs: tipo `pointer_candidate` novo; raízes x86 em ecx/edx rebaixam a confiança para `low`; `describe_key(k, is64)`.
- `Database.save_run` recusa nomes repetidos; referências ambíguas/curtas (<8 hex, não-id) agora dão erro.
- Resultados de Structure Discovery e `CONFIRMED` podem diferir dos da 0.4.0 (de propósito).

### Limitações que permanecem (e comportamentos não comprovados)
- **Jump tables:** só x86 `jmp [idx*4+tabela]` com `cmp/ja|jae` imediatamente antes; x64 (`jmp reg`) e limites em outro bloco ficam "não resolvidos".
- **Rastreio de pilha:** só x86; callee desconhecido/indireto/API zera o rastreio de ESP; sem alias por memória.
- **Convenção x86:** nunca é provada; ecx/edx é uma hipótese configurável. Argumentos de pilha (`[esp+k]`/`[ebp+8+k]`) são evidência melhor.
- **Corroboração por string/import/export** mostra coocorrência na função, **não** significado.
- Validação Capstone amostral acima de 500 matches (declarada).
- O dataflow não foi observado não-convergindo em binário real; o teto existe e é reportado.
- Nenhum teste contra binário de jogo; compatibilidade não é afirmada.

### Verificação nesta máquina
116 testes (58 exigem Capstone). Em `notepad.exe`/`kernel32.dll` (x64) e `SysWOW64\notepad.exe` (x86): 0 instruções sobrepostas em
nenhum CFG, todas as arestas para blocos existentes; no x86 real, 2 jump tables resolvidas com limite provado e 6 funções descontínuas.
No notepad x64, dos campos antes rotulados "pointer", 21 têm uso como base e 47 passam a `pointer_candidate`.

---

## 0.4.0

### Novo
- **`cfg.py`** — CFG por *recursive descent*: blocos básicos, arestas (`fall/jmp/jcc/table`), jump tables x86 resolvidas,
  tail calls, regiões **alcançadas × ambíguas × padding**, descoberta de funções por alcançabilidade (limites `cfg`),
  xrefs com proveniência (`via`), export Graphviz (`to_dot`).
- **`structs.py` reescrito** — dataflow de ponteiros por registrador; objetos identificados por **origem**
  (argumento / global / retorno / cadeia de ponteiros), não por "função + registrador". Fusão só por evidência concreta,
  com recusa por conflito de tipos e regra de "hub". Arrays, offsets negativos, objetos aninhados, vtable-like, relações.
- **`aobintel.py`** — validação de `disp_offset`/`insn_len` contra a instrução real, geração assistida de padrões,
  bytes variáveis entre builds, contexto antes/depois, detecção de padrões genéricos.
- **`intel.py`** — relatórios explicativos (Offset Intelligence) com seção obrigatória "O que NÃO foi estabelecido".
- **`buildid.py`** — identidade (SHA-256 completo), fingerprint estrutural, perfil de similaridade, famílias de builds.
- **Banco**: `AnalysisRun` (execuções independentes), estruturas por execução, eventos de build, migração automática.
- **GUI**: abas CFG, Estruturas hierárquicas, Relatório, Builds/DB; hex por RVA/file offset com paginação e busca AOB.
- **CLI**: `cfg`, `sigcheck`, `siggen`, `sigvar`, `sigctx`, `report`, `runs`, `events`, `similar`, `buildinfo`;
  `structs --from-db`, `export --structs`, referências `build@run`.

### Mudanças que quebram compatibilidade
- **`known_value` exige o SHA-256 COMPLETO (64 hex)**. Prefixos e fingerprint agora são **rejeitados** (`ValueError`).
- **Corroboração** (`confirm_*`) só promove status com limites de função **exatos (.pdata)** ou **derivados de CFG** e xref
  **confiável** (não só varredura linear). Com limites heurísticos (x86 sem Capstone) a evidência é anotada mas o resultado
  fica `PROBABLE` — antes virava `STATIC_CORROBORATED`.
- **Validação Capstone**: assinatura cujo `disp_offset`/`insn_len` não bate com a instrução real vira `CANDIDATE`.
- **Structure Discovery**: estruturas com layout parecido **não são mais fundidas**; os campos e as contagens mudam em relação à 0.3.
  A confiança nunca passa de `medium`.
- `Database.save()` continua existindo, mas agora grava **uma run nova**; `Database.results(build)` devolve a **última run**
  (resultados removidos de uma assinatura deixam de aparecer; as runs antigas continuam consultáveis com `build@run`).
- `Context(...)` ganhou `use_cfg` e `include_linear`; `Xref` ganhou `via` e `rw`; `Insn.regs_written` agora usa nomes canônicos.

### Migração de dados
- Bancos 0.2/0.3 são migrados ao abrir: os resultados soltos viram uma run `legacy` por build. As tabelas antigas permanecem.

## 0.3.0
Status `STATIC_CORROBORATED`, Capstone opcional, Structure Discovery v1, Signature Intelligence, export `*_RVA`/`*_OFFSET`.

## 0.2.0
Versão Python inicial (PE, AOB, xrefs por opcode, SQLite, export, GUI tkinter).
