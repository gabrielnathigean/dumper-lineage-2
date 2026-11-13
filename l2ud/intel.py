"""Offset Intelligence: consolida as evidências (assinatura, função, referências, estruturas, builds)
em um relatório EXPLICATIVO.

Regras do relatório:
  • só afirma fatos observados (contagens, locais, limites de função, status e o motivo dele);
  • nunca atribui significado ("player", "inventário"…): sempre lista "O que NÃO foi estabelecido";
  • "interesse" é um índice de TRIAGEM (quanto há para investigar), não uma medida de confiança nem de correção.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .analysis import Context, analyze_function, xrefs_to
from .siginfo import pattern_quality
from .sigs import Result, Status

_BASE_INTEREST = {Status.CONFIRMED: 50, Status.STATIC_CORROBORATED: 40, Status.PROBABLE: 25,
                  Status.CANDIDATE: 15, Status.AMBIGUOUS: 5, Status.NOT_FOUND: 0}


@dataclass
class OffsetReport:
    name: str
    status: str
    value_kind: str
    value: int | None
    pattern: str
    interest: int
    facts: dict = field(default_factory=dict)          # tabelas de evidência
    explanation: str = ""
    why_status: list[str] = field(default_factory=list)
    not_established: list[str] = field(default_factory=list)
    related_structs: list[int] = field(default_factory=list)


@dataclass
class IntelReport:
    build: dict
    engine: str
    offsets: list[OffsetReport]
    structs: list = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"build": self.build, "engine": self.engine, "warnings": self.warnings,
                "offsets": [o.__dict__ for o in self.offsets],
                "structs": [{**c.to_dict(), "explanation": explain_struct(c)} for c in self.structs]}


def ref_stats(img, ctx: Context, rva: int) -> dict:
    xs = xrefs_to(img, rva, ctx.xrefs)
    funcs = {x.function.start for x in xs if x.function}
    return {"total": len(xs), "functions": len(funcs), "kinds": dict(Counter(x.kind for x in xs)),
            "rw": dict(Counter(x.rw for x in xs if x.rw)), "via": dict(Counter(x.via for x in xs)),
            "trusted": sum(1 for x in xs if x.trusted),
            "sample": [f"{x.from_rva:#x} ({x.kind}{'/' + x.rw if x.rw else ''}, {x.via})" for x in xs[:6]]}


def _why_status(r: Result) -> list[str]:
    s = r.status
    out = {
        Status.CONFIRMED: ["valor único, corroboração estática forte e igual à referência verificada manualmente para esta build (SHA-256 completo)"],
        Status.STATIC_CORROBORATED: ["valor único e evidência estática independente na mesma função (limites exatos ou derivados de CFG)"],
        Status.PROBABLE: ["valor único pelo padrão de bytes; nenhuma corroboração forte adicional"],
        Status.CANDIDATE: ["hipótese: veja as notas abaixo (padrão frágil, instrução não confere ou divergência)"],
        Status.AMBIGUOUS: ["o padrão resolve para mais de um valor"],
        Status.NOT_FOUND: ["nenhum resultado válido"],
    }[s][:]
    if r.notes:
        out.append("notas: " + r.notes)
    return out


def _not_established(r: Result, ctx: Context, fn_label: str | None, stats: dict | None) -> list[str]:
    ne = ["o significado semântico deste valor (o que ele representa no jogo) — nenhuma análise estática o estabelece",
          "que o valor continue correto em outras builds (veja estabilidade/histórico)"]
    if not ctx.capstone:
        ne.append("a instrução do match não foi validada (modo Lite, sem Capstone); referências vêm de heurística de opcode/relocação")
    if fn_label and "HEUR" in fn_label:
        ne.append("os limites da função são heurísticos: a associação match↔função pode estar errada")
    if r.status == Status.STATIC_CORROBORATED:
        ne.append("a corroboração mostra coocorrência na mesma função, não identidade semântica")
    if stats and stats.get("via", {}).get("linear"):
        ne.append("parte das referências vem de varredura linear (pode ser dado interpretado como código)")
    return ne


def report_offset(img, ctx: Context, r: Result, structs: list | None = None, history: list[dict] | None = None) -> OffsetReport:
    q = pattern_quality(r.pattern) if r.pattern else None
    facts: dict = {"assinatura": {"matches": len(r.hits) or None, "qualidade": None if q is None else q.score,
                                  "flags": [] if q is None else q.flags}}
    if r.meta.get("validation"):
        facts["validacao_instrucao"] = r.meta["validation"]
    if r.meta.get("evidence_items") is not None:
        facts["evidencias"] = {"fontes_independentes": r.meta.get("independent_sources", 0),
                               "itens": len(r.meta["evidence_items"]),
                               "fortes": sum(1 for e in r.meta["evidence_items"] if e["strong"]),
                               "fracas_ou_ignoradas": sum(1 for e in r.meta["evidence_items"] if not e["strong"])}
    if r.meta.get("hit_status"):
        from collections import Counter as _C
        facts["matches"] = dict(_C(r.meta["hit_status"].values()))
    fn_label = None
    stats = None
    if r.hits:
        fn = ctx.fmap.containing(r.hits[0])
        if fn is not None:
            info = analyze_function(img, ctx, r.hits[0]) or {}
            fn_label = fn.label
            facts["funcao_do_match"] = {"inicio": f"{fn.start:#x}", "fim": f"{fn.end:#x}", "limites": fn.label,
                                        "chamadores": len(info.get("callers", [])), "chamados": len(info.get("callees", [])),
                                        "strings": list(info.get("strings", {}).values())[:8],
                                        "imports": info.get("imports", [])[:8]}
            if info.get("cfg"):
                facts["funcao_do_match"]["cfg"] = info["cfg"]
    related: list[int] = []
    if r.value is not None and r.value_kind == "RVA":
        stats = ref_stats(img, ctx, r.value)
        facts["referencias_ao_valor"] = stats
        related = [c.id for c in (structs or []) if any(f"{r.value:#x}" in root for root in c.roots)]
    elif r.value is not None and r.value_kind == "FIELD_OFFSET":
        hits = [(c.id, f) for c in (structs or []) for f in c.fields if f["offset_int"] == r.value]
        related = [cid for cid, _ in hits]
        facts["campos_com_esse_offset"] = [{"estrutura": cid, "tipo_provavel": f["type_guess"], "leituras": f["reads"],
                                           "escritas": f["writes"]} for cid, f in hits[:8]]
    if history:
        vals = [h["value"] for h in history]
        facts["historico"] = {"execucoes": len(history), "valores_distintos": len(set(vals)),
                              "status": dict(Counter(h["status"] for h in history))}

    interest = _BASE_INTEREST[r.status]
    if stats:
        interest += min(stats["functions"], 10) * 2 + min(stats["total"], 20)
    if related:
        interest += 10
    interest = min(100, interest)

    parts = []
    if r.hits:
        parts.append(f"O padrão casou {len(r.hits)} vez(es)" + (f" e a instrução foi validada com Capstone" if r.meta.get("validation", {}).get("ok") else ""))
    if r.value is not None:
        what = {"RVA": "o RVA", "FIELD_OFFSET": "o deslocamento de campo", "INTEGER": "o inteiro"}[r.value_kind]
        parts.append(f"{what} resolvido é {r.value:#x}")
    if stats and stats["total"]:
        parts.append(f"esse endereço é referenciado {stats['total']} vez(es) em {stats['functions']} função(ões) "
                     f"(tipos: {', '.join(f'{k}={v}' for k, v in stats['kinds'].items())})")
        if stats["rw"]:
            parts.append("acessos observados: " + ", ".join(f"{k}={v}" for k, v in stats["rw"].items()))
    if "funcao_do_match" in facts:
        f = facts["funcao_do_match"]
        parts.append(f"o match está na função {f['inicio']}–{f['fim']} ({f['limites']})")
    if related:
        parts.append(f"há candidato(s) a estrutura relacionado(s): {', '.join('#' + str(i) for i in related)}")
    expl = ". ".join(parts) + ("." if parts else "Sem evidências para consolidar.")
    return OffsetReport(r.name, r.status.value, r.value_kind, r.value, r.pattern, interest, facts, expl,
                        _why_status(r), _not_established(r, ctx, fn_label, stats), related)


def explain_struct(c) -> str:
    ptrs = sum(1 for f in c.fields if f["type_guess"] == "pointer")
    pcs = sum(1 for f in c.fields if f["type_guess"] == "pointer_candidate")
    flts = sum(1 for f in c.fields if f["type_guess"].startswith("float"))
    arrs = sum(1 for f in c.fields if "array" in f.get("notes", ""))
    e = c.evidence
    rels = sorted({r["kind"] for r in c.relations})
    s = (f"Foram observados {len(c.fields)} campos (ponteiros comprovados por uso como base: {ptrs}, candidatos a ponteiro: "
         f"{pcs}, floats: {flts}, arrays/indexados: {arrs}) em "
         f"{len(c.functions)} função(ões), com {e.get('reads', 0)} leitura(s) e {e.get('writes', 0)} escrita(s). "
         f"Tamanho mínimo estimado: {c.size_estimate:#x}.")
    if e.get("merge_reasons"):
        s += f" A classe reúne {len(e['merge_reasons'])} fusão(ões) por fluxo de dados concreto."
    if rels:
        s += " Relações: " + ", ".join(rels) + "."
    if e.get("conflicts"):
        s += " Há ressalvas: " + "; ".join(e["conflicts"][:2]) + "."
    if e.get("assumptions"):
        s += " HIPÓTESES não provadas: " + "; ".join(e["assumptions"][:2]) + "."
    if e.get("dataflow_incomplete"):
        s += " O dataflow NÃO convergiu em " + ", ".join(e["dataflow_incomplete"][:3]) + ": resultado incompleto."
    if e.get("refused_merges"):
        s += f" {len(e['refused_merges'])} fusão(ões) recusada(s) por conflito de tipos."
    return s + " A associação semântica (ex.: jogador, NPC, item) NÃO foi estabelecida."


def build_report(img, ctx: Context, results: list[Result], structs: list | None = None,
                 history_of=None) -> IntelReport:
    """`history_of(name) -> list[dict]` (opcional, ex.: Database.history) acrescenta a seção entre-builds."""
    offs = [report_offset(img, ctx, r, structs, history_of(r.name) if history_of else None) for r in results]
    offs.sort(key=lambda o: (-o.interest, o.name))
    warns = []
    if not ctx.capstone:
        warns.append("Modo Lite: sem validação de instrução, sem CFG e com limites de função x86 heurísticos.")
    from .buildid import identity
    return IntelReport(identity(img), ctx.engine_used or ctx.engine_req, offs, structs or [], warns)


def to_markdown(rep: IntelReport) -> str:
    b = rep.build
    L = ["# Relatório de Offset Intelligence", "",
         f"- módulo: `{b['module']}` ({b['arch']}) · SHA-256 `{b['sha256']}`",
         f"- motor: **{rep.engine}**", ""]
    L += [f"> ⚠ {w}" for w in rep.warnings]
    L += ["> Todos os itens abaixo são evidências estáticas. 'Interesse' é triagem, não confiança.", ""]
    for o in rep.offsets:
        v = "-" if o.value is None else f"{o.value:#x}"
        L += [f"## {o.name} — `{o.status}` · {o.value_kind} {v} · interesse {o.interest}/100", ""]
        if o.pattern:
            L += [f"Padrão: `{o.pattern}`", ""]
        L += ["**Explicação:** " + o.explanation, "", "**Por que este status:**"] + [f"- {w}" for w in o.why_status] + [""]
        for title, key in (("Assinatura", "assinatura"), ("Matches", "matches"), ("Evidências", "evidencias"),
                           ("Validação da instrução", "validacao_instrucao"),
                           ("Função do match", "funcao_do_match"), ("Referências ao valor", "referencias_ao_valor"),
                           ("Histórico entre execuções", "historico")):
            if key in o.facts:
                L += [f"**{title}**", "", "| campo | valor |", "|---|---|"]
                L += [f"| {k} | {v} |" for k, v in o.facts[key].items()] + [""]
        if "campos_com_esse_offset" in o.facts:
            L += ["**Campos de estruturas candidatas com este offset**", ""]
            L += [f"- estrutura #{x['estrutura']}: {x['tipo_provavel']} (r={x['leituras']}, w={x['escritas']})"
                  for x in o.facts["campos_com_esse_offset"]] + [""]
        L += ["**O que NÃO foi estabelecido:**"] + [f"- {n}" for n in o.not_established] + [""]
    if rep.structs:
        L += ["# Candidatos a estrutura", ""]
        for c in rep.structs:
            L += [f"## #{c.id} — CANDIDATE · confiança {c.confidence} · interesse {c.interest}/100", "",
                  "| Evidência | Resultado |", "|---|---|",
                  f"| Funções relacionadas | {len(c.functions)} |", f"| Campos observados | {len(c.fields)} |",
                  f"| Leituras | {c.evidence.get('reads', 0)} |", f"| Escritas | {c.evidence.get('writes', 0)} |",
                  f"| Acessos totais | {c.evidence.get('accesses', 0)} |", f"| Tamanho mínimo estimado | {c.size_estimate:#x} |", "",
                  "**Explicação:** " + explain_struct(c), ""]
    return "\n".join(L)
