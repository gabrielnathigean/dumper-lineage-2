"""Assinaturas (JSON) -> resultados com status explícito e honesto.

Formato (lista de objetos):
  name, pattern                      obrigatórios (nomes únicos)
  kind          "rip" | "rel" | "rel8" | "abs" | "imm" | "hit"
                  rip  = alvo de [rip+disp32]
                  rel  = alvo de call/jmp REL32 (insn_len - disp_offset tem que ser 4)
                  rel8 = alvo de branch curto REL8 (1 byte com sinal)
                  abs  = operando VA absoluto (típico x86) -> RVA
                  imm  = inteiro lido (ex.: offset de campo)         hit = o próprio RVA do match
  disp_offset, insn_len, size        conforme kind (com Capstone são VALIDADOS contra a instrução real)
  sections, executable_only          escopo do scan
  confirm_string  "texto"            string referenciada por código na MESMA função do match
  confirm_import  "GetTickCount"     import (IAT) referenciado na MESMA função do match
  confirm_export  "NomeExport"       match dentro da função exportada com esse nome
  known_value     {"<SHA-256 COMPLETO (64 hex)>": "0x..."}   valor verificado MANUALMENTE para aquela build
  value_kind      "RVA" | "FIELD_OFFSET" | "INTEGER"

Status (nunca inflados):
  CONFIRMED             valor único + corroboração FORTE + igual ao known_value (SHA-256 completo) da MESMA build
                        + validação de instrução COMPLETA (todos os matches resolvidos)
  STATIC_CORROBORATED   valor único + corroboração FORTE
  PROBABLE              valor único por AOB; corroboração só fraca não conta
  CANDIDATE             padrão frágil, instrução não bate com o declarado (Capstone), ou divergência do known_value
  AMBIGUOUS             mais de um valor possível
  NOT_FOUND             nenhum resultado válido

Regras de evidência (0.4.1):
- só matches que RESOLVERAM para o valor e (com Capstone) tiveram a instrução VALIDADA podem corroborar;
  evidência de match não resolvido/inválido nunca promove o resultado;
- cada evidência está ligada ao match que a sustenta (`meta["evidence_items"]`);
- corroboração FORTE = limites de função exatos (.pdata) ou derivados de CFG + referência confiável (opcode,
  relocação ou CFG; nunca varredura linear pura). Evidências da MESMA origem (mesma instrução/mesma fonte) são
  contadas uma vez; `meta["independent_sources"]` conta as fontes distintas.
"""
from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field
from enum import Enum

from . import aob
from .analysis import Context, find_strings, import_refs, xrefs_to
from .functions import Function
from .pe import PeImage
from .siginfo import pattern_quality

VALIDATION_LIMIT = 500          # acima disso a validação Capstone é AMOSTRAL e declarada como parcial


class Status(str, Enum):
    CONFIRMED = "CONFIRMED"
    STATIC_CORROBORATED = "STATIC_CORROBORATED"
    PROBABLE = "PROBABLE"
    CANDIDATE = "CANDIDATE"
    AMBIGUOUS = "AMBIGUOUS"
    NOT_FOUND = "NOT_FOUND"


STATUS_ORDER = [Status.NOT_FOUND, Status.AMBIGUOUS, Status.CANDIDATE, Status.PROBABLE,
                Status.STATIC_CORROBORATED, Status.CONFIRMED]


@dataclass
class Result:
    name: str
    status: Status
    value: int | None = None
    kind: str = "rip"
    candidates: list[int] = field(default_factory=list)
    notes: str = ""
    evidence: list[str] = field(default_factory=list)
    value_kind: str = "RVA"                 # RVA | FIELD_OFFSET | INTEGER
    va: int | None = None                   # só para value_kind == RVA (base preferida)
    file_offset: int | None = None          # só para value_kind == RVA mapeado em disco
    pattern: str = ""
    hits: list[int] = field(default_factory=list)      # RVAs dos matches RESOLVIDOS (não persistido no DB)
    meta: dict = field(default_factory=dict)           # função, validação, evidências estruturadas (não persistido)


@dataclass
class Ev:
    """Uma evidência de corroboração, ligada ao match que a sustenta."""
    source: str            # 'string' | 'import' | 'export'
    fn: Function
    hit: int
    xref: int | None
    via: str
    engine: str
    strong: bool
    text: str


_SHA = re.compile(r"^[0-9a-f]{64}$")


def _value_kind(sig: dict) -> str:
    vk = sig.get("value_kind")
    if vk:
        if vk not in ("RVA", "FIELD_OFFSET", "INTEGER"):
            raise ValueError(f"value_kind inválido em {sig['name']}: {vk}")
        return vk
    return "FIELD_OFFSET" if sig.get("kind") == "imm" else "RVA"


_SHORT_BRANCH_OPCODES = set(range(0x70, 0x80)) | {0xEB, 0xE0, 0xE1, 0xE2, 0xE3}     # jcc/jmp/loop/jcxz rel8


def _branch_width_conflict(img: PeImage, hit_rva: int, off: int, kind: str) -> str | None:
    """Sem Capstone: confere pelo(s) byte(s) de OPCODE imediatamente antes do operando se o kind (rel/rel8) combina."""
    prev = img.read_rva(hit_rva + off - 1, 1) if off >= 1 else None
    if prev is None:
        return None
    p = prev[0]
    if kind == "rel" and p in _SHORT_BRANCH_OPCODES:
        return f"o byte anterior ({p:#04x}) é opcode de branch CURTO (rel8): use kind 'rel8'"
    if kind == "rel8":
        before = img.read_rva(hit_rva + off - 2, 1) if off >= 2 else None
        if p in (0xE8, 0xE9) or (0x80 <= p <= 0x8F and before is not None and before[0] == 0x0F):
            return f"o byte anterior ({p:#04x}) é opcode de branch NEAR (rel32): use kind 'rel'"
    return None


def _resolve(img: PeImage, hit, sig: dict) -> tuple[int | None, str]:
    kind = sig.get("kind", "rip")
    if kind == "hit":
        return hit.rva, ""
    off = int(sig.get("disp_offset", 0))
    if kind in ("rip", "rel"):
        ilen = int(sig.get("insn_len", off + 4))
        if kind == "rel" and ilen - off != 4:
            return None, ("kind 'rel' é REL32: insn_len - disp_offset deve ser 4 "
                          f"(recebido {ilen - off}); para branch curto use kind 'rel8'")
        if kind == "rel":
            why = _branch_width_conflict(img, hit.rva, off, "rel")
            if why:
                return None, why
        b = img.read_rva(hit.rva + off, 4)
        if b is None:
            return None, "disp fora do arquivo"
        tgt = (hit.rva + ilen + struct.unpack("<i", b)[0]) & 0xFFFFFFFF
        if img.section_for_rva(tgt) is None:
            return None, f"alvo {tgt:#x} fora de qualquer seção"
        return tgt, ""
    if kind == "rel8":
        ilen = int(sig.get("insn_len", off + 1))
        if ilen - off != 1:
            return None, f"kind 'rel8': insn_len - disp_offset deve ser 1 (recebido {ilen - off})"
        why = _branch_width_conflict(img, hit.rva, off, "rel8")
        if why:
            return None, why
        b = img.read_rva(hit.rva + off, 1)
        if b is None:
            return None, "rel8 fora do arquivo"
        tgt = (hit.rva + ilen + struct.unpack("<b", b)[0]) & 0xFFFFFFFF
        if img.section_for_rva(tgt) is None:
            return None, f"alvo {tgt:#x} fora de qualquer seção"
        return tgt, ""
    if kind == "abs":  # operando é um VA absoluto (típico x86): valor = VA - ImageBase
        size = 8 if img.is64 else 4
        b = img.read_rva(hit.rva + off, size)
        if b is None:
            return None, "operando fora do arquivo"
        tgt = int.from_bytes(b, "little") - img.image_base
        if tgt < 0 or img.section_for_rva(tgt) is None:
            return None, f"VA absoluto aponta fora da imagem (rva {tgt:#x})"
        return tgt, ""
    if kind == "imm":
        size = int(sig.get("size", 4))
        b = img.read_rva(hit.rva + off, size) if size in (1, 2, 4, 8) else None
        if b is None:
            return None, "imm inválido"
        return int.from_bytes(b, "little"), ""
    return None, f"kind desconhecido: {kind}"


def _known_for(img: PeImage, sig: dict) -> int | None:
    """Referência verificada à mão. A chave TEM que ser o SHA-256 completo da build (nada de prefixo/fingerprint)."""
    kv = sig.get("known_value")
    if not kv:
        return None
    if not isinstance(kv, dict):
        raise ValueError(f"{sig['name']}: known_value deve ser {{sha256_completo: valor}} (referência é por build)")
    found = None
    for k, v in kv.items():
        key = str(k).lower()
        if not _SHA.match(key):
            raise ValueError(f"{sig['name']}: known_value exige SHA-256 COMPLETO (64 hex); recebido {k!r}. "
                             "Prefixos e fingerprint não são aceitos como validação definitiva.")
        if key == img.sha256:
            found = int(v, 0) if isinstance(v, str) else int(v)
    return found


def _corroborate(img: PeImage, sig: dict, hits: list[int], ctx: Context) -> list[Ev]:
    """Evidências na MESMA função de cada match em `hits` (só matches resolvidos e validados).
    forte = limites exact/derived + xref confiável; fraca = limites heurísticos OU só varredura linear."""
    fmap = ctx.fmap
    hit_fn = {h: fmap.containing(h) for h in hits}
    hit_fn = {h: f for h, f in hit_fn.items() if f is not None}
    if not hit_fn:
        return []
    evs: list[Ev] = []

    def add(source: str, what: str, x, h: int, f: Function) -> None:
        strong = f.strength != "weak" and x.trusted
        text = f"{what} em {f.start:#x}-{f.end:#x} ({f.label}) [{x.engine}/{x.via}] (match {h:#x})"
        if f.strength == "weak":
            text += " — NÃO conta: limites heurísticos"
        elif not x.trusted:
            text += " — NÃO conta: só varredura linear (pode ser dado lido como instrução)"
        evs.append(Ev(source, f, h, x.from_rva, x.via, x.engine, strong, text))

    if sig.get("confirm_string"):
        cs = sig["confirm_string"]
        for fs in find_strings(img, cs, min_len=max(3, len(cs))):
            for x in xrefs_to(img, fs.rva, ctx.xrefs):
                for h, f in hit_fn.items():
                    if x.function == f:
                        add("string", f"string {fs.text!r}@{fs.rva:#x} referenciada", x, h, f)
    if sig.get("confirm_import"):
        want = sig["confirm_import"].lower()
        for x, name in import_refs(img, ctx.xrefs):
            if want == name.lower() or want == name.split("!")[-1].lower():
                for h, f in hit_fn.items():
                    if x.function == f:
                        add("import", f"import {name} usado", x, h, f)
    if sig.get("confirm_export"):
        for e in img.exports:
            if e.name != sig["confirm_export"] or e.forwarder:
                continue
            f = fmap.containing(e.rva)
            for h, hf in hit_fn.items():
                if f is not None and f == hf:
                    strong = f.strength != "weak"
                    text = f"match {h:#x} dentro da função exportada {e.name} ({f.label})"
                    evs.append(Ev("export", f, h, None, "export", ctx.engine_label, strong,
                                  text + ("" if strong else " — NÃO conta: limites heurísticos")))
    seen, out = set(), []
    for e in evs:                                       # mesma origem não conta duas vezes
        key = (e.source, e.fn.start, e.xref, e.hit)
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out


def _independent(evs: list[Ev]) -> int:
    """Fontes INDEPENDENTES entre as evidências fortes: (tipo de fonte, função) distintos."""
    return len({(e.source, e.fn.start) for e in evs if e.strong})


def run_signature(img: PeImage, sig: dict, ctx: Context | None = None) -> Result:
    ctx = ctx or Context(img, "lite")
    name, kind, vk = sig["name"], sig.get("kind", "rip"), _value_kind(sig)
    base = dict(kind=kind, value_kind=vk, pattern=sig.get("pattern", ""))
    try:
        quality = pattern_quality(sig["pattern"])
        hits = aob.scan(img, sig["pattern"], sig.get("sections"), bool(sig.get("executable_only", False)))
    except aob.AobError as e:
        return Result(name, Status.NOT_FOUND, notes=f"padrão inválido: {e}", **base)
    if not hits:
        return Result(name, Status.NOT_FOUND, notes="nenhum match", **base)

    vals: dict[int, int] = {}
    hit_status: dict[int, str] = {}
    skipped: list[str] = []
    for h in hits:
        v, why = _resolve(img, h, sig)
        if v is None:
            skipped.append(why)
            hit_status[h.rva] = "unresolved"
        else:
            vals[h.rva] = v
            hit_status[h.rva] = "resolved"
    if not vals:
        return Result(name, Status.NOT_FOUND, notes="; ".join(dict.fromkeys(skipped)),
                      meta={"hit_status": hit_status}, **base)

    ev = [f"aob: {len(hits)} match(es) em {sorted({h.section for h in hits})}"
          + (f" ({len(hits) - len(vals)} não resolveram e foram IGNORADOS)" if len(hits) > len(vals) else ""),
          f"qualidade do padrão: {quality.score}/100 {quality.flags or ''}".strip()]
    distinct = sorted(set(vals.values()))
    resolved = sorted(vals)
    if len(distinct) > 1:
        return Result(name, Status.AMBIGUOUS, None, candidates=distinct,
                      notes=f"{len(distinct)} valores distintos; refine o padrão", evidence=ev, hits=resolved,
                      meta={"hit_status": hit_status}, **base)

    value = distinct[0]
    notes: list[str] = []
    meta: dict = {"hit_status": hit_status}
    if len(resolved) > 1:
        notes.append(f"{len(resolved)} sites concordam no mesmo valor")

    # ---- validação da instrução (Capstone) de TODOS os matches resolvidos (ou amostra declarada) ----
    validation_failed = False
    partial = False
    good = list(resolved)                       # matches que podem corroborar
    if kind != "hit" and ctx.capstone:
        from .aobintel import check_resolution
        to_check = resolved[:VALIDATION_LIMIT]
        partial = len(resolved) > VALIDATION_LIMIT
        checks = {h: check_resolution(img, ctx, h, sig) for h in to_check}
        bad = [h for h, c in checks.items() if not c.ok]
        good = [h for h in to_check if checks[h].ok]
        for h in resolved:
            hit_status[h] = "invalid" if h in bad else ("valid" if h in checks else "unvalidated")
        first_bad = checks[bad[0]] if bad else None
        meta["validation"] = {"ok": not bad, "checked": len(to_check), "total": len(resolved), "partial": partial,
                              "invalid": [f"{h:#x}" for h in bad],
                              "issues": [i for h in bad for i in checks[h].issues],
                              "suggestion": first_bad.suggestion if first_bad else {},
                              "instruction": checks[to_check[0]].instruction}
        if bad:
            validation_failed = True
            notes.append(f"campos da assinatura NÃO batem com a instrução real em {len(bad)} de {len(to_check)} "
                         f"match(es): " + "; ".join(first_bad.issues))
            ev.append(f"validação Capstone: FALHOU em {len(bad)}/{len(to_check)} match(es) "
                      f"({', '.join(f'{h:#x}' for h in bad[:5])}) — " + "; ".join(first_bad.issues))
        else:
            ev.append(f"validação Capstone: instrução confere em {len(to_check)}/{len(resolved)} match(es) "
                      f"({checks[to_check[0]].instruction})")
        if partial:
            notes.append(f"validação PARCIAL: só {len(to_check)} de {len(resolved)} matches foram validados "
                         "(os demais NÃO corroboram e CONFIRMED fica bloqueado)")
    elif kind != "hit":
        ev.append("validação Capstone: indisponível (disp_offset/insn_len não conferidos)")

    evs = _corroborate(img, sig, good, ctx)
    strong = [e for e in evs if e.strong]
    weak = [e for e in evs if not e.strong]
    wanted = any(sig.get(k) for k in ("confirm_string", "confirm_import", "confirm_export"))
    if wanted and not strong:
        notes.append("evidência pedida não corroborada com limites confiáveis" if weak else "evidência pedida não corroborada")
    ev += [e.text for e in strong + weak]
    meta["evidence_items"] = [{"source": e.source, "function": f"{e.fn.start:#x}", "hit": f"{e.hit:#x}",
                               "xref": None if e.xref is None else f"{e.xref:#x}", "via": e.via, "strong": e.strong}
                              for e in evs]
    meta["independent_sources"] = _independent(evs)
    fn0 = ctx.fmap.containing(resolved[0])
    if fn0:
        meta["function"] = (fn0.start, fn0.end, fn0.label)
    if strong:
        notes.append(f"{meta['independent_sources']} fonte(s) de evidência independente(s)")

    known = _known_for(img, sig)
    status = Status.PROBABLE
    if strong:
        status = Status.STATIC_CORROBORATED
    if known is not None:
        if known != value:
            status = Status.CANDIDATE
            notes.append(f"DIVERGE da referência conhecida desta build ({known:#x})")
        elif strong and not partial:
            status = Status.CONFIRMED
            ev.append(f"igual à referência conhecida desta build (SHA-256 completo) ({known:#x})")
        elif strong:
            notes.append("igual à referência conhecida, mas a validação foi parcial: CONFIRMED bloqueado")
        else:
            notes.append("igual à referência conhecida, mas sem corroboração forte")
    if quality.fragile and status == Status.PROBABLE:
        status = Status.CANDIDATE
        notes.append("padrão frágil (poucos bytes fixos / muitos wildcards)")
    if validation_failed:
        status = Status.CANDIDATE   # rebaixa qualquer status: o valor pode estar sendo lido no lugar errado

    va = fo = None
    if vk == "RVA":
        va, fo = img.rva_to_va(value), img.rva_to_file(value)
    return Result(name, status, value, candidates=[value], notes="; ".join(notes), evidence=ev,
                  va=va, file_offset=fo, hits=resolved, meta=meta, **base)


def load_sigs(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("arquivo de assinaturas deve ser uma lista JSON")
    names: set[str] = set()
    for i, s in enumerate(data):
        if "name" not in s or "pattern" not in s:
            raise ValueError(f"assinatura #{i} sem name/pattern")
        if s["name"] in names:
            raise ValueError(f"nome de assinatura repetido: {s['name']!r} (os resultados de uma run são indexados pelo nome)")
        names.add(s["name"])
        _value_kind(s)
    return data


def sigs_digest(sigs: list[dict]) -> str:
    """Identidade do CONJUNTO de assinaturas (usada pelo AnalysisRun)."""
    import hashlib
    return hashlib.sha256(json.dumps(sigs, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def run_all(img: PeImage, sigs: list[dict], engine: str = "auto", ctx: Context | None = None) -> list[Result]:
    ctx = ctx or Context(img, engine)
    return [run_signature(img, s, ctx) for s in sigs]
