from __future__ import annotations

import argparse
import contextlib
import json
import struct
import sys
from pathlib import Path

from . import aob, disasm
from .analysis import Context, analyze_function, find_strings, fingerprint, hexdump, xrefs_to
from .pe import PeError, PeImage
from .siginfo import analyze_set, pattern_quality, stability
from .sigs import load_sigs, run_all
from .storage import Database, diff, export, export_structs, write_export


def _load(path: str) -> PeImage:
    try:
        return PeImage.load(path)
    except (OSError, PeError) as e:
        sys.exit(f"erro: {path}: {e}")


def _int(s: str) -> int:
    return int(s, 0)


def _ctx(img: PeImage, a) -> Context:
    eng = getattr(a, "engine", "auto")
    if eng == "capstone" and not disasm.available():
        sys.exit("erro: --engine capstone requer 'pip install capstone'")
    return Context(img, eng, use_cfg=not getattr(a, "no_cfg", False), include_linear=not getattr(a, "no_linear", False))


def _db(a, path: str) -> Database:
    """Abre o banco e garante o fechamento ao fim do comando (ExitStack em `main`)."""
    return a._stack.enter_context(Database(path))


def _need_cs() -> None:
    if not disasm.available():
        sys.exit("erro: este comando requer Capstone (pip install capstone)")


def _fn(f) -> str:
    return f" fn={f.start:#x}-{f.end:#x}[{f.source}]" if f else ""


def _h(v) -> str:
    return "-" if v is None else hex(v)


# ---------------------------------------------------------------- análise básica
def cmd_info(a) -> None:
    img = _load(a.file)
    ctx = Context(img, "lite")   # rápido: limites .pdata (x64) ou heurísticos (x86); use `func`/`cfg` para CFG
    print(f"arquivo     : {img.path}\nsha256      : {img.sha256}\nfingerprint : {fingerprint(img)}   (estrutural; NÃO é identidade)")
    print(f"módulo      : {img.export_name or Path(img.path).name}   timestamp={img.timestamp:#x}")
    print(f"arch        : {img.arch}  imageBase(preferida)={img.image_base:#x}  entry={img.entry_point:#x}")
    print(f"exports={len(img.exports)} imports={len(img.imports)} relocs={len(img.relocs)} pdata={len(img.functions)}")
    print(f"funções     : {len(ctx.fmap)} (limites: {ctx.fmap.funcs[0].label if ctx.fmap.funcs else '-'})")
    print(f"capstone    : {'disponível' if disasm.available() else 'ausente (modo Lite)'}")
    print(f"{'seção':<10}{'RVA':>10}{'vsize':>10}{'raw':>10}{'rawsz':>10}  flags")
    for s in img.sections:
        print(f"{s.name:<10}{s.va:>#10x}{s.vsize:>#10x}{s.raw_ptr:>#10x}{s.raw_size:>#10x}  {s.flags:#010x}{' X' if s.executable else ''}")
    if a.exports:
        for e in img.exports:
            print(f"  export {e.ordinal:>5} {e.rva:#010x} {e.name}{' -> ' + e.forwarder if e.forwarder else ''}")
    if a.imports:
        for i in img.imports:
            print(f"  import {i.dll}!{i.name} @IAT {i.iat_rva:#x}")


def cmd_scan(a) -> None:
    img = _load(a.file)
    try:
        hits = aob.scan(img, a.pattern, a.section, a.exec_only)
        q = pattern_quality(a.pattern)
    except aob.AobError as e:
        sys.exit(f"erro: {e}")
    print(f"{len(hits)} hit(s) | qualidade do padrão {q.score}/100 {q.flags or ''}")
    for h in hits[:a.limit]:
        line = f"  RVA {h.rva:#010x}  VA(pref) {h.va:#x}  file {h.file_offset:#x}  [{h.section}]"
        if a.disp is not None:
            b = img.read_rva(h.rva + a.disp, 4)
            if b:
                tgt = (h.rva + (a.insn_len or a.disp + 4) + struct.unpack('<i', b)[0]) & 0xFFFFFFFF
                line += f"  -> target RVA {tgt:#x}"
        print(line)


def cmd_strings(a) -> None:
    img = _load(a.file)
    xs = _ctx(img, a).xrefs if a.xrefs else None
    for fs in find_strings(img, a.query, a.min_len)[:a.limit]:
        print(f"{fs.rva:#010x} {'W' if fs.wide else 'A'} [{fs.section}] {fs.text[:120]!r}")
        if xs is not None:
            for x in xrefs_to(img, fs.rva, xs)[:8]:
                print(f"            xref {x.kind} @ {x.from_rva:#x}{_fn(x.function)} [{x.engine}/{x.via}]")


def cmd_xrefs(a) -> None:
    img = _load(a.file)
    ctx = _ctx(img, a)
    for x in xrefs_to(img, a.rva, ctx.xrefs)[:a.limit]:
        print(f"{x.kind:<5} @ {x.from_rva:#010x}{_fn(x.function)} [{x.engine}/{x.via}{'/' + x.rw if x.rw else ''}]")
    print(f"(motor: {ctx.engine_used})")


def cmd_func(a) -> None:
    img = _load(a.file)
    ctx = _ctx(img, a)
    r = analyze_function(img, ctx, a.rva)
    if not r:
        sys.exit("nenhuma função conhecida contém esse RVA")
    f = r["function"]
    print(f"função {f.start:#x}-{f.end:#x} ({f.end - f.start:#x} bytes) nome={f.name or '-'}")
    print(f"limites: {r['bounds_label'].upper()}{'' if r['exact_bounds'] else ' — não são prova'}; motor xrefs: {r['engine']}")
    print("chamadores :", ", ".join(f"{c:#x}" for c in r["callers"][:20]) or "-")
    print("chamados   :", ", ".join(f"{c:#x}" for c in r["callees"][:20]) or "-")
    print("imports    :", ", ".join(r["imports"]) or "-")
    for rva, s in list(r["strings"].items())[:20]:
        print(f"  string {rva:#x}: {s!r}")
    if "cfg" in r:
        c = r["cfg"]
        print(f"CFG: {c['blocks']} blocos, {c['edges']} arestas, {c['instructions']} instruções, "
              f"{c['calls']} calls, {c['tail_calls']} tail calls, {c['external_edges']} desvios externos, "
              f"{c['invalid_edges']} arestas inválidas, {c['indirect_unresolved']} saltos indiretos não resolvidos"
              f"{' [TRUNCADO]' if c['truncated'] else ''}")
        for a0, b0, t in r["ambiguous"][:10]:
            print(f"  região {t}: {a0:#x}-{b0:#x}")


def cmd_cfg(a) -> None:
    _need_cs()
    img = _load(a.file)
    ctx = _ctx(img, a)
    cfg = ctx.cfg(a.rva)
    if cfg is None:
        sys.exit("nenhuma função conhecida contém esse RVA")
    fn = ctx.fmap.containing(a.rva)
    print(f"CFG da função {fn.start:#x}-{fn.end:#x} ({fn.label})  resumo: {cfg.summary()}")
    for b in sorted(cfg.blocks.values(), key=lambda x: x.start):
        succ = ", ".join(f"{t:#x}({k})" for t, k in b.succs) or "-"
        extra = " [indireto NÃO resolvido]" if b.indirect_unresolved else ""
        calls = f" calls={[hex(c) for c in b.calls]}" if b.calls else ""
        print(f"  bloco {b.start:#x}-{b.end:#x} {len(b.insns)} insn  term={b.terminator}{extra}  -> {succ}{calls}")
        if a.insns:
            for i in b.insns:
                print("      " + i.text())
    for s, e, t in cfg.ambiguous:
        print(f"  região {t}: {s:#x}-{e:#x}")
    for x in cfg.external:
        print(f"  desvio EXTERNO {x.kind} {x.src:#x} -> {x.dst:#x}: {x.cls}{' (início de função conhecida)' if x.known_function else ''}")
    for src, dst, why in cfg.invalid_edges:
        print(f"  aresta INVÁLIDA {src:#x} -> {dst:#x}: {why} (não foi decodificada para evitar instruções sobrepostas)")
    for j in cfg.jump_tables:
        st = "RESOLVIDA" if j.resolved else "NÃO resolvida (tamanho não provado)"
        print(f"  jump table @{j.table_rva:#x} ({j.entry_format}) por {j.jmp_rva:#x}: {st}; limite={j.bound}"
              f"{'' if j.declared_count is None else f' ({j.declared_count} entradas)'}; "
              f"aceitas={[hex(t) for _, t in j.entries]} rejeitadas={[(i, r) for i, _, r in j.rejected]}")
    if a.dot:
        from .cfg import to_dot
        Path(a.dot).write_text(to_dot(cfg), encoding="utf-8")
        print(f"DOT gravado em {a.dot} (Graphviz)")


def cmd_disasm(a) -> None:
    _need_cs()
    img = _load(a.file)
    for i in disasm.Disassembler(img).decode(a.rva, a.count):
        print(i.text())


def cmd_hex(a) -> None:
    print(hexdump(_load(a.file), a.rva, a.length))


# ---------------------------------------------------------------- assinaturas
def cmd_sigs(a) -> None:
    img = _load(a.file)
    try:
        sigs = load_sigs(a.sigs)
        ctx = _ctx(img, a)
        results = run_all(img, sigs, ctx=ctx)
    except (OSError, ValueError) as e:
        sys.exit(f"erro nas assinaturas: {e}")
    for r in results:
        print(f"{r.status.value:<20} {r.name:<28} {r.value_kind:<13} {_h(r.value):<12} {r.notes}")
        for e in r.evidence:
            print(f"                     · {e}")
        if r.meta.get("validation") and not r.meta["validation"]["ok"] and r.meta["validation"]["suggestion"]:
            print(f"                     > sugestão (Capstone): {r.meta['validation']['suggestion']}")
    print(f"(motor: {ctx.engine_label}; funções: {ctx.fmap.funcs[0].label if ctx.fmap.funcs else '-'})")
    if a.db:
        db = _db(a, a.db)
        bid, rid = db.save_run(img, results, sigs, ctx.engine_label, a.note or "")
        print(f"salvo em {a.db}: build #{bid}, run #{rid}")
    if a.out:
        write_export(results, a.out, a.include_probable, a.all, img.image_base, img.sha256[:16])
        print(f"exportado: {a.out}")


def cmd_sigcheck(a) -> None:
    _need_cs()
    from .aobintel import analyze_signature
    img = _load(a.file)
    ctx = _ctx(img, a)
    for s in load_sigs(a.sigs):
        r = analyze_signature(img, ctx, s)
        g = r["generic"]
        print(f"== {s['name']}: {r['hits']} match(es), qualidade {g['quality']}/100, "
              f"cobre {g['covered_instructions']} instrução(ões) {g['flags'] or ''}")
        c = r.get("check")
        if c:
            print(f"   instrução: {c.instruction}")
            print(f"   {'OK' if c.ok else 'PROBLEMAS'}: {'; '.join(c.issues) or 'campos conferem com a instrução real'}")
            if c.suggestion and not c.ok:
                print(f"   sugestão: {c.suggestion}")
        ctxi = r.get("context")
        if ctxi and ctxi["at"] and a.context:
            for t in ctxi["before"]:
                print("     " + t)
            print("  ►  " + ctxi["at"])
            for t in ctxi["after"]:
                print("     " + t)
            print(f"   ({ctxi['note']})")


def cmd_siggen(a) -> None:
    _need_cs()
    from .aobintel import generate
    img = _load(a.file)
    s = generate(img, _ctx(img, a), a.rva, a.max_len, a.wild_fields, require_boundary=a.strict_boundary)
    if s.start_reliable is False:
        print("!! ATENÇÃO: o RVA NÃO é início de instrução alcançada pelo CFG — o padrão pode ser inválido")
    elif s.start_reliable is None:
        print("!! aviso: fronteira de instrução não verificável (sem função/CFG para este ponto)")
    print(f"padrão: {s.pattern}\nmatches: {s.hits} ({'ÚNICO' if s.unique else 'NÃO único'}) · qualidade {s.quality.score}/100 {s.quality.flags or ''}")
    print("instruções cobertas:")
    for i in s.instructions:
        print("   " + i)
    for n in s.notes:
        print("  nota: " + n)
    print("(sugestão: confira à mão e valide entre builds com `sigvar`; nada é aplicado automaticamente)")


def cmd_sigvar(a) -> None:
    from .aobintel import find_points, variable_bytes_at
    if a.at:
        pts = {}
        for item in a.at:
            lbl, _, rva = item.partition("=")
            pts[lbl] = (_load(lbl) if Path(lbl).exists() else None, int(rva, 0))
        if any(v[0] is None for v in pts.values()):
            sys.exit("erro: --at espera ARQUIVO=RVA (arquivo existente)")
        warn = []
    else:
        imgs = {f: _load(f) for f in a.files}
        pts, warn = find_points(imgs, a.pattern)
    for w in warn:
        print("aviso:", w)
    length = a.length or (len(a.pattern.split()) if a.pattern else 16)
    rep = variable_bytes_at(pts, length, a.before, a.after)
    for n in rep.notes:
        print("aviso:", n)
    for lbl, row in rep.rows.items():
        print(f"{Path(lbl).name:<24} {row.hex(' ')}")
    print(f"offsets variáveis: {rep.variable}\nsugestão (região da assinatura): {rep.suggested_core}")
    print(f"sugestão (janela com contexto estável): {rep.suggested_extended}")


def cmd_sigctx(a) -> None:
    _need_cs()
    from .aobintel import analyze_context
    img = _load(a.file)
    c = analyze_context(img, _ctx(img, a), a.rva, a.before, a.after)
    for t in c["before"]:
        print("     " + t)
    if c["at"]:
        print("  ►  " + c["at"])
    for t in c["after"]:
        print("     " + t)
    print(f"({c['note']})")


def cmd_siginfo(a) -> None:
    try:
        sigs = load_sigs(a.sigs)
    except (OSError, ValueError) as e:
        sys.exit(f"erro nas assinaturas: {e}")
    print("== qualidade do padrão ==")
    for s in sigs:
        q = pattern_quality(s["pattern"])
        print(f"{s['name']:<28} score={q.score:>3}  fixos={q.fixed}/{q.length}  run={q.longest_run}  {q.flags or ''}")
    issues = analyze_set(sigs)
    print("== conjunto ==")
    print("\n".join(issues) if issues else "sem duplicações/redundâncias")
    if a.files:
        imgs = {p: _load(p) for p in a.files}
        print("== estabilidade entre builds ==")
        for st in stability(sigs, imgs, a.engine):
            print(f"{st.name:<28} {'; '.join(st.flags)}")
            for lbl, (stt, val, hits) in st.per_build.items():
                print(f"    {lbl}: {stt} {_h(val)} ({hits} match)")


# ---------------------------------------------------------------- estruturas / relatório
def cmd_structs(a) -> None:
    if a.from_db:
        db = _db(a, a.db or "l2ud.db")
        cands = db.load_structs(a.from_db)
        if not cands:
            sys.exit("nenhuma estrutura gravada para essa build/run")
    else:
        _need_cs()
        from .structs import discover
        img = _load(a.file)
        hints = json.load(open(a.hints, encoding="utf-8")) if a.hints else None
        cands = discover(img, Context(img, "capstone", not a.no_cfg), hints, a.min_fields, a.max_functions, a.function,
                         assume_x86_reg_args=not a.no_x86_reg_args)
        if a.db:
            db = _db(a, a.db)
            bid = db.register_build(img)
            rid = db.save_structs(bid, cands)
            print(f"estruturas salvas em {a.db}: build #{bid}, run #{rid}")
    if a.out:
        fmt = "md" if a.out.lower().endswith(".md") else "json"
        Path(a.out).write_text(export_structs(cands, fmt), encoding="utf-8")
        print(f"exportado: {a.out}")
    for c in cands[:a.limit]:
        print("\n" + c.render_text(a.fields))
    print(f"\n{len(cands)} candidato(s). Inferência estática, nunca confirmação.")


def cmd_report(a) -> None:
    from .intel import build_report, to_markdown
    img = _load(a.file)
    ctx = _ctx(img, a)
    try:
        sigs = load_sigs(a.sigs)
        results = run_all(img, sigs, ctx=ctx)
    except (OSError, ValueError) as e:
        sys.exit(f"erro nas assinaturas: {e}")
    structs = None
    if a.structs:
        _need_cs()
        from .structs import discover
        structs = discover(img, ctx, None, a.min_fields, a.max_functions, assume_x86_reg_args=not a.no_x86_reg_args)
    db = _db(a, a.db) if a.db else None
    rep = build_report(img, ctx, results, structs, db.history if db else None)
    text = json.dumps(rep.to_dict(), indent=2, ensure_ascii=False, default=str) if (a.out or "").endswith(".json") else to_markdown(rep)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"relatório gravado em {a.out}")
    else:
        print(text)


# ---------------------------------------------------------------- banco / builds
def cmd_builds(a) -> None:
    for b in _db(a, a.db).builds_info():
        print(f"#{b['id']:<3} {b['arch']:<4} {b['module'] or '-':<22} runs={b['runs']:<3} {b['created']}  {b['sha256']}")


def cmd_runs(a) -> None:
    for r in _db(a, a.db).runs(a.build):
        print(f"run #{r['run']:<4} build #{r['build']:<3} {r['started']}  v{r['tool_version']:<8} {r['engine'] or '-':<9} "
              f"{r['results']:>3} resultado(s)  sigs={r['sigs_digest'][:10] or '-'}  {r['note'] or ''}")


def cmd_events(a) -> None:
    for ts, kind, detail in _db(a, a.db).build_events(a.build):
        print(f"{ts}  {kind:<13} {detail}")


def cmd_export(a) -> None:
    db = _db(a, a.db)
    if a.structs:
        print(export_structs(db.load_structs(a.build), "md" if a.format == "md" else "json"), end="")
        return
    print(export(db.results(a.build), a.format, a.include_probable, a.all, db.image_base(a.build), str(a.build)), end="")


def cmd_diff(a) -> None:
    db = _db(a, a.db)
    d = diff(db.results(a.old), db.results(a.new))
    for name, o, n, delta in d["changed"]:
        dl = "" if delta is None else f" (Δ {'+' if delta >= 0 else '-'}{abs(delta):#x})"
        print(f"CHANGED  {name}: {_h(o)} -> {_h(n)}{dl}")
    for name, v in d["added"]:
        print(f"ADDED    {name}: {_h(v)}")
    for name, v in d["removed"]:
        print(f"REMOVED  {name}: {_h(v)}")
    for name, o, n in d["degraded"]:
        print(f"DEGRADED {name}: {o} -> {n}")
    for name, o, n in d["improved"]:
        print(f"IMPROVED {name}: {o} -> {n}")
    for name in d["pattern_changed"]:
        print(f"PATTERN  {name}: padrão diferente entre as execuções")
    print(f"{len(d['unchanged'])} inalterado(s)")


def cmd_history(a) -> None:
    rows = _db(a, a.db).history(a.name)
    if not rows:
        sys.exit("sem histórico para esse nome")
    for r in rows:
        print(f"build #{r['build']:<3} run #{r['run']:<4} {r['created']}  {r['status']:<20} {r['value_kind']:<13} "
              f"{_h(r['value']):<12} {r['sha256'][:12]}")


def cmd_similar(a) -> None:
    from .buildid import compute_profile, families, similarity
    if a.files:
        profs = {Path(f).name: compute_profile(_load(f)) for f in a.files}
    else:
        db = _db(a, a.db)
        profs = {f"#{b['id']} {b['module']}": p for b in db.builds_info() if (p := db.profile(b["id"]))}
    names = list(profs)
    for i, x in enumerate(names):
        for y in names[i + 1:]:
            s = similarity(profs[x], profs[y])
            parts = ", ".join(f"{k}={v}" for k, v in s["parts"].items() if v is not None)
            print(f"{x}  ~  {y}: {s['score']:.3f}  ({parts}){'  [mesma build]' if s['identical'] else ''}")
    from .buildid import family_report
    for g in families(profs, a.threshold):
        rep = family_report(profs, g)
        print(f"família (ligação completa ≥{a.threshold}): " + ", ".join(
            f"{r['build']} [mín {r['min']:.3f}, média {r['mean']:.3f}]" if len(g) > 1 else r["build"] for r in rep))
    print("(similaridade ≠ compatibilidade de assinaturas: valide por build)")


def cmd_buildinfo(a) -> None:
    from .buildid import identity
    for k, v in identity(_load(a.file)).items():
        print(f"{k:<12}: {v}")


def cmd_bundle(a) -> None:
    """Analisa uma pasta de módulos PE como CONJUNTO (arquitetura real, empacotamento, consistência de imports)."""
    from .bundle import analyze_bundle
    try:
        rep = analyze_bundle(a.folder, recursive=a.recursive)
    except NotADirectoryError as e:
        sys.exit(f"erro: {e}")
    print(f"bundle {rep.bundle_id[:16]}…  pasta={rep.root}  módulos={len(rep.modules)}  ignorados={len(rep.skipped)}")
    print(f"{'módulo':<24}{'arch':<6}{'machine':<8}{'timestamp':<12}{'imagebase':<12}{'imports':>8}{'exports':>8}  empacotamento")
    for m in rep.modules:
        print(f"{m.name:<24}{m.arch:<6}{m.machine:<#8x}{m.timestamp:<#12x}{m.image_base:<#12x}{m.n_imports:>8}{m.n_exports:>8}  "
              f"{m.packing_level} ({m.packing_score})" + ("" if m.arch_consistent else "  [Machine/Magic NÃO concordam]"))
        if m.packing_level != "none" or a.verbose:
            for ind in m.packing_indicators:
                print(f"      - {ind}")
    for path, why in rep.skipped:
        print(f"ignorado: {path}: {why}")
    for i in rep.issues:
        if i.level != "info" or a.verbose:
            print(f"[{i.level.upper():7}] {i.code}: {i.message}")
    if a.json:
        Path(a.json).write_text(json.dumps(rep.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"relatório gravado em {a.json}")


def cmd_funcs(a) -> None:
    """Catálogo de FUNÇÕES de um módulo (limites, chamadores/chamados, strings e imports), sem assinaturas manuais."""
    _need_cs()
    from .bundle import analyze_module
    from .catalog import Catalog
    from .evgraph import EvidenceGraph
    from .funcdisc import run as discover_functions
    from .modwork import DiscoverOptions, ModuleWork
    info = analyze_module(a.file)
    if info.packing_level == "likely" and not a.force:
        sys.exit(f"erro: {info.name} tem indicadores de empacotamento ({'; '.join(info.packing_indicators[:2])}). "
                 "A análise estática de um binário empacotado tende a ser inútil; use --force para analisar assim mesmo.")
    img = _load(a.file)
    catalog, graph = Catalog(info.sha256), EvidenceGraph()
    work = ModuleWork(img, info, info.sha256, graph, catalog, DiscoverOptions(max_functions=a.max_functions))
    items = discover_functions(work)
    catalog.finalize(graph)
    from collections import Counter
    cnt = Counter(i.status for i in items)
    print(f"{info.name} [{info.arch}] sha256={info.sha256[:16]}…  {len(items)} função(ões): {dict(cnt)}")
    ranked = sorted(items, key=lambda i: (-i.independence.get("observations", 0), i.value))
    for i in ranked[:a.limit]:
        at = i.attrs
        print(f"  {i.value:#010x} {i.name:<22} {i.status:<20} obs={i.independence.get('observations', 0):<3} "
              f"{at.get('bounds_source'):<9} insn={at.get('instructions')} chamadores={at.get('caller_count')} "
              f"chamados={at.get('callee_count')} strings={len(at.get('strings', []))} imports={len(at.get('imports', []))}")
    if a.out:
        catalog.export(a.out)
        print(f"exportado: {a.out}")


def cmd_autodiscover(a) -> None:
    """Pipeline AUTO DISCOVER OFFSETS completo para um bundle ou módulo."""
    _need_cs()
    from .modwork import DiscoverOptions
    from .pipeline import AutoDiscoverPipeline
    from .progress import Progress
    from .storage import Database

    opts = DiscoverOptions(
        max_functions=a.max_functions,
        max_globals=a.max_globals,
        max_vtables=a.max_vtables,
        generate_aob=not a.no_aob,
        include_packed=a.force,
    )
    pipe = AutoDiscoverPipeline(opts)
    db = Database(a.db) if a.db else None

    prog = Progress(lambda stage, done, total, msg: print(f"[{stage}] ({done}/{total}) {msg}")) if a.verbose else None
    try:
        catalog, graph, rep = pipe.run(a.target, progress=prog, db=db, db_note=a.note or "")
    finally:
        if db is not None:
            db.close()

    counts = catalog.counts()
    print(f"Descoberta concluída: bundle={catalog.bundle_id}")
    for cat, st_cnt in counts.items():
        total = sum(st_cnt.values())
        print(f"  {cat:<28} total={total:<4} {st_cnt}")

    if a.out:
        catalog.export(a.out, include_candidates=a.include_candidates)
        print(f"catálogo exportado: {a.out}")


def cmd_diff_catalog(a) -> None:
    """Compara dois catálogos entre builds (Cross-Build Diff)."""
    from .catalog import Catalog
    from .crossbuild import CrossBuildDiff

    cat1 = Catalog.from_dict(json.loads(Path(a.old).read_text(encoding="utf-8")))
    cat2 = Catalog.from_dict(json.loads(Path(a.new).read_text(encoding="utf-8")))
    cbd = CrossBuildDiff(cat1, cat2)
    diff = cbd.compare()
    print(cbd.to_markdown())
    if a.out:
        Path(a.out).write_text(cbd.to_markdown(), encoding="utf-8")
        print(f"diff exportado em: {a.out}")


def cmd_validate(a) -> None:
    """Aplica registros de validação externa a um catálogo."""
    from .catalog import Catalog
    from .validation import apply_validation

    cat = Catalog.from_dict(json.loads(Path(a.catalog).read_text(encoding="utf-8")))
    rep = apply_validation(cat, a.validation)
    print(rep.summary())
    if a.out:
        cat.export(a.out)
        print(f"catálogo atualizado gravado em: {a.out}")


def cmd_catalog_runs(a) -> None:
    """Lista execuções de catálogo salvas no banco."""
    from .storage import Database
    with Database(a.db) as db:
        runs = db.list_catalog_runs()
        if not runs:
            print("nenhuma execução de catálogo gravada")
            return
        print(f"{len(runs)} execução(ões) de catálogo:")
        for r in runs:
            print(f"  id={r['id']} bundle={r['bundle_id']} itens={r['item_count']} data={r['created']} nota={r['note']}")


def cmd_gui(a) -> None:
    from .gui import main
    main()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="l2ud", description="Análise estática de PEs: AOB, CFG, funções, estruturas, assinaturas.")
    sp = p.add_subparsers(dest="cmd", required=True)

    def eng(s):
        s.add_argument("--engine", choices=["auto", "lite", "capstone"], default="auto",
                       help="motor de xrefs (auto = capstone se instalado)")
        s.add_argument("--no-cfg", action="store_true", help="não usar CFG (volta ao modo 0.3: heurística/linear)")
        s.add_argument("--no-linear", action="store_true", help="sem varredura linear complementar")

    s = sp.add_parser("info", help="resumo do PE"); s.add_argument("file")
    s.add_argument("--exports", action="store_true"); s.add_argument("--imports", action="store_true"); s.set_defaults(f=cmd_info)

    s = sp.add_parser("scan", help="scan AOB"); s.add_argument("file"); s.add_argument("pattern")
    s.add_argument("--section", action="append"); s.add_argument("--exec-only", action="store_true")
    s.add_argument("--disp", type=_int); s.add_argument("--insn-len", type=_int); s.add_argument("--limit", type=int, default=200); s.set_defaults(f=cmd_scan)

    s = sp.add_parser("strings", help="strings ASCII/UTF-16 (+ xrefs)"); s.add_argument("file"); s.add_argument("query", nargs="?")
    s.add_argument("--min-len", type=int, default=5); s.add_argument("--xrefs", action="store_true")
    s.add_argument("--limit", type=int, default=100); eng(s); s.set_defaults(f=cmd_strings)

    s = sp.add_parser("xrefs", help="xrefs para um RVA"); s.add_argument("file"); s.add_argument("rva", type=_int)
    s.add_argument("--limit", type=int, default=100); eng(s); s.set_defaults(f=cmd_xrefs)

    s = sp.add_parser("func", help="análise de função (limites, CFG, callers/callees, strings, imports)")
    s.add_argument("file"); s.add_argument("rva", type=_int); eng(s); s.set_defaults(f=cmd_func)

    s = sp.add_parser("cfg", help="CFG: blocos básicos, arestas, regiões ambíguas (Capstone)")
    s.add_argument("file"); s.add_argument("rva", type=_int); s.add_argument("--insns", action="store_true")
    s.add_argument("--dot", help="grava Graphviz .dot"); eng(s); s.set_defaults(f=cmd_cfg)

    s = sp.add_parser("disasm", help="desmonta (Capstone)"); s.add_argument("file"); s.add_argument("rva", type=_int)
    s.add_argument("--count", type=int, default=32); s.set_defaults(f=cmd_disasm)

    s = sp.add_parser("hex", help="hexdump por RVA"); s.add_argument("file"); s.add_argument("rva", type=_int)
    s.add_argument("--length", type=_int, default=256); s.set_defaults(f=cmd_hex)

    s = sp.add_parser("sigs", help="roda assinaturas JSON"); s.add_argument("file"); s.add_argument("sigs")
    s.add_argument("--db"); s.add_argument("--note", help="nota da execução (AnalysisRun)")
    s.add_argument("--out", help="exporta (.json/.csv/.hpp)")
    s.add_argument("--include-probable", action="store_true"); s.add_argument("--all", action="store_true")
    eng(s); s.set_defaults(f=cmd_sigs)

    s = sp.add_parser("sigcheck", help="valida disp_offset/insn_len, genericidade e contexto (Capstone)")
    s.add_argument("file"); s.add_argument("sigs"); s.add_argument("--context", action="store_true"); eng(s); s.set_defaults(f=cmd_sigcheck)

    s = sp.add_parser("siggen", help="sugere padrão a partir das instruções em um RVA (Capstone)")
    s.add_argument("file"); s.add_argument("rva", type=_int); s.add_argument("--max-len", type=int, default=48)
    s.add_argument("--wild-fields", action="store_true", help="também wildcard em deslocamentos de campo")
    s.add_argument("--strict-boundary", action="store_true", help="recusa gerar se o RVA não for início de instrução alcançada")
    eng(s); s.set_defaults(f=cmd_siggen)

    s = sp.add_parser("sigvar", help="bytes que mudam entre builds + sugestão de wildcards")
    s.add_argument("files", nargs="*"); s.add_argument("--pattern"); s.add_argument("--at", action="append", help="ARQUIVO=RVA (repetir)")
    s.add_argument("--length", type=int); s.add_argument("--before", type=int, default=0); s.add_argument("--after", type=int, default=0)
    s.set_defaults(f=cmd_sigvar)

    s = sp.add_parser("sigctx", help="instruções antes/depois de um ponto"); s.add_argument("file"); s.add_argument("rva", type=_int)
    s.add_argument("--before", type=int, default=4); s.add_argument("--after", type=int, default=6); eng(s); s.set_defaults(f=cmd_sigctx)

    s = sp.add_parser("siginfo", help="qualidade/duplicação/estabilidade"); s.add_argument("sigs")
    s.add_argument("files", nargs="*"); eng(s); s.set_defaults(f=cmd_siginfo)

    s = sp.add_parser("structs", help="Structure Discovery v2 (Capstone)"); s.add_argument("file", nargs="?")
    s.add_argument("--hints"); s.add_argument("--min-fields", type=int, default=4); s.add_argument("--max-functions", type=int)
    s.add_argument("--function", type=_int); s.add_argument("--limit", type=int, default=20); s.add_argument("--fields", type=int, default=40)
    s.add_argument("--db", default=None); s.add_argument("--out", help=".json ou .md")
    s.add_argument("--from-db", help="lista estruturas gravadas (build, build@run, sha)"); s.add_argument("--no-cfg", action="store_true")
    s.add_argument("--no-x86-reg-args", action="store_true",
                   help="x86: NÃO assumir ecx/edx como argumentos (só argumentos de pilha comprovados por esp/ebp)")
    s.set_defaults(f=cmd_structs)

    s = sp.add_parser("report", help="Offset Intelligence: relatório explicativo"); s.add_argument("file"); s.add_argument("sigs")
    s.add_argument("--structs", action="store_true"); s.add_argument("--min-fields", type=int, default=4)
    s.add_argument("--max-functions", type=int); s.add_argument("--db"); s.add_argument("--out", help=".md ou .json")
    s.add_argument("--no-x86-reg-args", action="store_true"); eng(s); s.set_defaults(f=cmd_report)

    s = sp.add_parser("builds", help="lista builds"); s.add_argument("--db", default="l2ud.db"); s.set_defaults(f=cmd_builds)
    s = sp.add_parser("runs", help="lista execuções (AnalysisRun)"); s.add_argument("build", nargs="?"); s.add_argument("--db", default="l2ud.db"); s.set_defaults(f=cmd_runs)
    s = sp.add_parser("events", help="histórico de mudanças da build"); s.add_argument("build"); s.add_argument("--db", default="l2ud.db"); s.set_defaults(f=cmd_events)

    s = sp.add_parser("export", help="exporta resultados/estruturas do DB (build, build@run, @run)"); s.add_argument("build")
    s.add_argument("--db", default="l2ud.db"); s.add_argument("--format", choices=["json", "csv", "hpp", "md"], default="json")
    s.add_argument("--include-probable", action="store_true"); s.add_argument("--all", action="store_true")
    s.add_argument("--structs", action="store_true"); s.set_defaults(f=cmd_export)

    s = sp.add_parser("diff", help="compara duas execuções (build ou build@run)"); s.add_argument("old"); s.add_argument("new")
    s.add_argument("--db", default="l2ud.db"); s.set_defaults(f=cmd_diff)

    s = sp.add_parser("history", help="histórico de um resultado"); s.add_argument("name"); s.add_argument("--db", default="l2ud.db"); s.set_defaults(f=cmd_history)

    s = sp.add_parser("similar", help="similaridade/família entre builds (PEs ou DB)"); s.add_argument("files", nargs="*")
    s.add_argument("--db", default="l2ud.db"); s.add_argument("--threshold", type=float, default=0.8); s.set_defaults(f=cmd_similar)

    s = sp.add_parser("buildinfo", help="identidade da build (SHA-256, fingerprint, módulo…)"); s.add_argument("file"); s.set_defaults(f=cmd_buildinfo)

    s = sp.add_parser("bundle", help="analisa uma pasta de módulos PE como conjunto (arch real, empacotamento, imports)")
    s.add_argument("folder"); s.add_argument("--recursive", action="store_true"); s.add_argument("--json", help="grava o relatório em JSON")
    s.add_argument("-v", "--verbose", action="store_true", help="mostra também os avisos informativos e os indicadores de cada módulo")
    s.set_defaults(f=cmd_bundle)

    s = sp.add_parser("funcs", help="catálogo de funções de um módulo (Capstone)"); s.add_argument("file")
    s.add_argument("--max-functions", type=int); s.add_argument("--limit", type=int, default=30)
    s.add_argument("--out", help="exporta o catálogo (.json .csv .md .hpp)")
    s.add_argument("--force", action="store_true", help="analisa mesmo com indicadores de empacotamento"); s.set_defaults(f=cmd_funcs)

    s = sp.add_parser("autodiscover", help="descoberta automática completa em bundle ou módulo (Etapas 1-7)")
    s.add_argument("target", help="pasta do bundle ou arquivo de módulo PE")
    s.add_argument("--max-functions", type=int, help="máximo de funções a analisar por módulo")
    s.add_argument("--max-globals", type=int, help="máximo de globais a analisar por módulo")
    s.add_argument("--max-vtables", type=int, help="máximo de vtables a analisar por módulo")
    s.add_argument("--no-aob", action="store_true", help="desativa geração automática de assinaturas AOB")
    s.add_argument("--force", action="store_true", help="analisa módulos mesmo com indicadores de empacotamento likely")
    s.add_argument("--out", help="exporta o catálogo completo (.json, .csv, .hpp, .md)")
    s.add_argument("--include-candidates", action="store_true", help="no .hpp, inclui itens com status candidato")
    s.add_argument("--db", help="salva a execução e o catálogo no banco SQLite informado")
    s.add_argument("--note", help="anotação para a execução salva no banco")
    s.add_argument("-v", "--verbose", action="store_true", help="imprime progresso de cada etapa")
    s.set_defaults(f=cmd_autodiscover)

    s = sp.add_parser("diff-catalog", help="compara dois catálogos entre builds diferentes")
    s.add_argument("old", help="arquivo JSON do catálogo antigo")
    s.add_argument("new", help="arquivo JSON do catálogo novo")
    s.add_argument("--out", help="exporta o relatório de diff em Markdown (.md)")
    s.set_defaults(f=cmd_diff_catalog)

    s = sp.add_parser("validate", help="aplica registros de validação externa a um catálogo")
    s.add_argument("catalog", help="arquivo JSON do catálogo existente")
    s.add_argument("validation", help="arquivo JSON com os dados de validação externa")
    s.add_argument("--out", help="caminho para gravar o catálogo atualizado com as validações")
    s.set_defaults(f=cmd_validate)

    s = sp.add_parser("catalog-runs", help="lista execuções de catálogo salvas no SQLite")
    s.add_argument("--db", default="l2ud.db", help="caminho do arquivo SQLite (padrão: l2ud.db)")
    s.set_defaults(f=cmd_catalog_runs)

    s = sp.add_parser("gui", help="interface gráfica (tkinter)"); s.set_defaults(f=cmd_gui)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd == "structs" and not a.from_db and not a.file:
        sys.exit("erro: informe FILE ou --from-db")
    try:
        with contextlib.ExitStack() as stack:
            a._stack = stack
            a.f(a)
    except KeyError as e:                       # referência de build/run inexistente, ambígua ou de outra build
        sys.exit(f"erro: {e.args[0] if e.args else e}")
    return 0
