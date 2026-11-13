"""Testes da 0.5.0 (descoberta automática). Fixtures 100% sintéticos (nada é de jogo real), exceto os testes marcados
`RealPE`, que usam binários do Windows apenas como corpus de verificação quando existirem."""
import json
import os
import random
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import builders as B  # noqa: E402
from l2ud import disasm  # noqa: E402
from l2ud.analysis import Context  # noqa: E402
from l2ud.pe import PeImage  # noqa: E402
from l2ud.progress import Cancelled, CancelToken, Progress  # noqa: E402

CS = unittest.skipUnless(disasm.available(), "Capstone não instalado")
T0 = 0x3F000000


def write_bundle(folder: Path, mods: dict[str, bytes]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for name, data in mods.items():
        (folder / name).write_bytes(data)


def l2_like(unresolved=False, ts_engine=T0 + 100, machine=0x14C):
    """core.dll <- engine.dll <- L2.exe (nomes citados; conteúdo sintético)."""
    core = B.simple_module("core.dll", 0x10000000, T0, exports=[("CoreInit", 0x1000), ("CoreFree", 0x1010)])
    engine = B.simple_module("engine.dll", 0x11000000, ts_engine, exports=[("EngineMain", 0x1000)],
                             imports=[("core.dll", "CoreInit"), ("kernel32.dll", "Sleep")])
    l2 = B.simple_module("L2.exe", 0x400000, T0 + 200, dll=False,
                         imports=[("engine.dll", "EngineGone" if unresolved else "EngineMain"),
                                  ("core.dll", "CoreFree"), ("kernel32.dll", "GetTickCount")])
    mods = {"core.dll": core.build(), "engine.dll": engine.build(), "L2.exe": l2.build()}
    if machine != 0x14C:
        m = B.simple_module("odd.dll", 0x12000000, T0, exports=[("X", 0x1000)])
        m.machine = machine
        mods["odd.dll"] = m.build()
    return mods


def packed_module():
    b = B.Pe32Builder(0x400000, T0, dll=False, entry=0x1000, name="packed.exe")
    b.section(".text", 0x1000, 0x400, B.F_RDATA)                       # EP em seção NÃO executável
    b.section(".themida", 0x2000, 0x4000, B.F_CODE)                    # nome de protetor + exec + entropia alta
    b.put(0x2000, random.Random(7).randbytes(0x4000))
    b.add_import("kernel32.dll", "LoadLibraryA")
    b.add_import("kernel32.dll", "GetProcAddress")
    return b.build()


# ================================================================== Etapa 1 — Client Bundle Analyzer
class TestBundleAnalyzer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def analyze(self, mods, **kw):
        from l2ud.bundle import analyze_bundle
        write_bundle(self.root, mods)
        return analyze_bundle(self.root, **kw)

    def test_module_metadata_is_complete(self):
        rep = self.analyze(l2_like())
        eng = rep.module("ENGINE.DLL")
        self.assertEqual((eng.arch, eng.machine, eng.magic, eng.arch_consistent), ("x86", 0x14C, 0x10B, True))
        self.assertEqual((eng.timestamp, eng.image_base, eng.is_dll), (T0 + 100, 0x11000000, True))
        self.assertEqual((eng.n_exports, eng.n_imports, eng.export_name), (1, 2, "engine.dll"))
        self.assertEqual(eng.import_dlls, ["core.dll", "kernel32.dll"])
        self.assertEqual(len(eng.sha256), 64)
        self.assertEqual(len(eng.fingerprint), 32)
        self.assertIn(".text", [s.name for s in eng.sections])
        self.assertTrue(all(0.0 <= s.entropy <= 8.0 for s in eng.sections))
        self.assertFalse(rep.module("L2.exe").is_dll)
        self.assertEqual(eng.packing_level, "none")

    def test_modules_of_interest_come_first_and_bundle_id_is_order_independent(self):
        rep = self.analyze(l2_like())
        self.assertEqual([m.name for m in rep.modules][:3], ["core.dll", "engine.dll", "L2.exe"])   # interesse (ordem alfabética entre eles)
        from l2ud.bundle import analyze_bundle, bundle_identity
        self.assertEqual(rep.bundle_id, bundle_identity(list(reversed(rep.modules))))
        # mudar UM byte de um módulo muda a identidade do conjunto
        mods = l2_like()
        raw = bytearray(mods["core.dll"])
        raw[0x400] ^= 0xFF
        write_bundle(self.root, {"core.dll": bytes(raw)})
        self.assertNotEqual(analyze_bundle(self.root).bundle_id, rep.bundle_id)

    def test_consistent_imports_are_reported_and_dependencies_listed(self):
        rep = self.analyze(l2_like())
        codes = [i.code for i in rep.issues]
        self.assertNotIn("IMPORT_UNRESOLVED", codes)
        self.assertEqual(rep.dependencies["L2.exe"], ["core.dll", "engine.dll"])
        self.assertEqual(rep.dependencies["engine.dll"], ["core.dll"])
        self.assertEqual(rep.dependencies["core.dll"], [])

    def test_import_not_exported_by_sibling_signals_mixed_builds(self):
        rep = self.analyze(l2_like(unresolved=True))
        bad = [i for i in rep.issues if i.code == "IMPORT_UNRESOLVED"]
        self.assertEqual(len(bad), 1)
        self.assertEqual((bad[0].level, bad[0].modules), ("error", ["L2.exe", "engine.dll"]))
        self.assertIn("EngineGone", bad[0].message)

    def test_timestamp_spread_is_a_warning_not_a_verdict(self):
        far = T0 + 200 * 86400
        rep = self.analyze(l2_like(ts_engine=far))
        ts = [i for i in rep.issues if i.code == "TIMESTAMP_SPREAD"]
        self.assertEqual(len(ts), 1)
        self.assertEqual(ts[0].level, "warning")
        self.assertIn("não é prova", ts[0].message)
        self.assertFalse([i for i in self.analyze(l2_like(), max_ts_spread_days=45).issues if i.code == "TIMESTAMP_SPREAD"])

    def test_real_architecture_uses_machine_and_magic_and_flags_mismatch(self):
        rep = self.analyze(l2_like(machine=0x8664))
        odd = rep.module("odd.dll")
        self.assertEqual((odd.arch, odd.magic, odd.arch_consistent), ("x64", 0x10B, False))   # Machine=x64 mas Magic=PE32
        codes = {i.code: i for i in rep.issues}
        self.assertEqual(codes["ARCH_MISMATCH"].level, "error")
        self.assertIn("MIXED_ARCH", codes)
        self.assertNotIn("odd.dll", [m.name for m in __import__("l2ud.bundle", fromlist=["x"]).analyzable(rep)])

    def test_unknown_machine_is_not_guessed(self):
        rep = self.analyze(l2_like(machine=0x1234))
        odd = rep.module("odd.dll")
        self.assertEqual((odd.arch, odd.arch_consistent), ("unknown", True))
        self.assertTrue(any(i.code == "ARCH_UNKNOWN" for i in rep.issues))

    def test_packing_indicators_are_explained_and_packed_modules_are_not_analyzable_by_default(self):
        from l2ud.bundle import analyzable
        mods = l2_like()
        mods["packed.exe"] = packed_module()
        rep = self.analyze(mods)
        p = rep.module("packed.exe")
        self.assertEqual(p.packing_level, "likely")
        text = " | ".join(p.packing_indicators)
        self.assertIn("nome típico de packer", text)
        self.assertIn("entropia alta", text)
        self.assertIn("entry point na seção não executável", text)
        self.assertIn("imports de carregador", text)
        self.assertEqual(rep.module("engine.dll").packing_level, "none")
        self.assertTrue(any(i.code == "PACKING_LIKELY" and "dump desempacotado" in i.message for i in rep.issues))
        self.assertNotIn("packed.exe", [m.name for m in analyzable(rep)])
        self.assertIn("packed.exe", [m.name for m in analyzable(rep, include_packed=True)])

    def test_non_pe_files_are_skipped_with_reason(self):
        mods = l2_like()
        (self.root).mkdir(exist_ok=True)
        (self.root / "fake.dll").write_bytes(b"isto nao e um PE")
        (self.root / "readme.txt").write_text("ignorado pela extensão")
        rep = self.analyze(mods)
        self.assertEqual([Path(p).name for p, _ in rep.skipped], ["fake.dll"])
        self.assertIn("não é um PE válido", rep.skipped[0][1])
        self.assertEqual(len(rep.modules), 3)

    def test_duplicate_names_in_subfolders_when_recursive(self):
        mods = l2_like()
        self.analyze(mods)
        write_bundle(self.root / "sub", {"core.dll": mods["core.dll"]})
        from l2ud.bundle import analyze_bundle
        rep = analyze_bundle(self.root, recursive=True)
        self.assertTrue(any(i.code == "DUPLICATE_NAME" for i in rep.issues))
        self.assertEqual(len(analyze_bundle(self.root, recursive=False).modules), 3)

    def test_missing_folder_and_empty_folder(self):
        from l2ud.bundle import analyze_bundle
        with self.assertRaises(NotADirectoryError):
            analyze_bundle(self.root / "nao_existe")
        rep = analyze_bundle(self.root)
        self.assertEqual([i.code for i in rep.issues if i.level == "error"], ["NO_MODULES"])

    def test_progress_is_reported_per_stage_and_cancel_is_safe(self):
        from l2ud.bundle import analyze_bundle
        write_bundle(self.root, l2_like())
        events = []
        analyze_bundle(self.root, progress=Progress(lambda st, d, t, m: events.append((st, d, t))))
        stages = [e[0] for e in events]
        self.assertIn("bundle", stages)
        self.assertIn("bundle-imports", stages)
        self.assertEqual([e for e in events if e[0] == "bundle"][-1][1:], (3, 3))
        tok = CancelToken()
        tok.cancel()
        with self.assertRaises(Cancelled):
            analyze_bundle(self.root, progress=Progress(None, tok))
        tok2 = CancelToken()
        seen = []

        def cb(st, d, t, m):
            seen.append(m)
            if len(seen) == 2:
                tok2.cancel()
        with self.assertRaises(Cancelled):
            analyze_bundle(self.root, progress=Progress(cb, tok2))
        self.assertLess(len(seen), 6)                                        # parou no meio, não varreu tudo

    def test_report_is_json_serializable(self):
        rep = self.analyze(l2_like(unresolved=True))
        d = json.loads(json.dumps(rep.to_dict()))
        self.assertEqual(d["bundle_id"], rep.bundle_id)
        self.assertEqual(d["modules"][0]["machine"], "0x14c")
        self.assertTrue(any(i["code"] == "IMPORT_UNRESOLVED" for i in d["issues"]))


class TestPe32Builder(unittest.TestCase):
    """O próprio builder precisa ser confiável: os demais testes dependem dele."""

    def test_roundtrip_through_our_parser(self):
        b = B.simple_module("engine.dll", exports=[("B", 0x1010), ("A", 0x1000)],
                            imports=[("kernel32.dll", "Sleep"), ("kernel32.dll", "GetTickCount"), ("core.dll", "X")])
        b.reloc(0x1005)
        b.reloc(0x1100)
        img = PeImage.parse(b.build())
        self.assertEqual((img.machine, img.magic, img.is_dll, img.export_name), (0x14C, 0x10B, True, "engine.dll"))
        self.assertEqual(sorted((e.name, e.rva) for e in img.exports), [("A", 0x1000), ("B", 0x1010)])
        self.assertEqual([(i.dll, i.name, i.iat_rva) for i in img.imports],
                         [("kernel32.dll", "Sleep", b.iat_rva("kernel32.dll", "Sleep")),
                          ("kernel32.dll", "GetTickCount", b.iat_rva("kernel32.dll", "GetTickCount")),
                          ("core.dll", "X", b.iat_rva("core.dll", "X"))])
        self.assertEqual(sorted(r for r, t in img.relocs), [0x1005, 0x1100])


class TestRealBundle(unittest.TestCase):
    """Corpus REAL (binários do Windows): só verifica que o analisador aguenta PEs reais e produz metadados coerentes."""
    SYS = Path(r"C:\Windows\SysWOW64")

    @unittest.skipUnless(Path(r"C:\Windows\SysWOW64\kernel32.dll").exists(), "SysWOW64 ausente")
    def test_real_x86_modules(self):
        from l2ud.bundle import analyze_bundle
        with tempfile.TemporaryDirectory() as d:
            for n in ("kernel32.dll", "notepad.exe"):
                shutil.copy(self.SYS / n, Path(d) / n)
            rep = analyze_bundle(d)
        self.assertEqual({m.arch for m in rep.modules}, {"x86"})
        self.assertTrue(all(m.arch_consistent and m.packing_level == "none" for m in rep.modules))
        self.assertTrue(all(m.n_imports > 10 for m in rep.modules))


# ================================================================== Etapa 2 — Evidence Graph + Catalog
class TestEvidenceGraph(unittest.TestCase):
    def graph(self):
        from l2ud.evgraph import EvidenceGraph
        g = EvidenceGraph()
        g.add_node("item:A", "global", "g_A")
        g.add_node("fn:f1", "function", "f1")
        g.add_node("fn:f2", "function", "f2")
        return g

    def test_same_origin_evidence_is_one_observation(self):
        g = self.graph()
        g.add_evidence("code_xref", "insn:m:0x10", ["item:A"], "m:f1", True, "cfg")
        g.add_evidence("reloc", "insn:m:0x10", ["item:A"], "m:f1", True, "reloc")          # MESMA instrução
        ind = g.independence("item:A")
        self.assertEqual((ind["evidence"], ind["observations"], ind["collapsed"]), (2, 1, 1))
        self.assertEqual(g.assess("item:A")[0], "STATIC_CANDIDATE")                         # 2 tipos, mas 1 observação

    def test_many_references_of_one_type_do_not_corroborate(self):
        g = self.graph()
        for k in range(30):
            g.add_evidence("code_xref", f"insn:m:{k:#x}", ["item:A"], f"m:f{k}", True, "cfg")
        st, why = g.assess("item:A")
        self.assertEqual(st, "STATIC_CANDIDATE")
        self.assertIn("só o tipo ['code_xref']", why)
        self.assertEqual(g.independence("item:A")["observations"], 30)

    def test_two_independent_observations_of_two_types_corroborate(self):
        g = self.graph()
        g.add_evidence("export", "export:m:A", ["item:A"], None, True, "export")
        g.add_evidence("direct_call", "insn:m:0x20", ["item:A"], "m:f2", True, "cfg")
        st, why = g.assess("item:A")
        self.assertEqual(st, "STATIC_CORROBORATED")
        self.assertIn("2 observações independentes", why)

    def test_untrusted_evidence_never_corroborates(self):
        g = self.graph()
        g.add_evidence("code_xref", "insn:m:0x10", ["item:A"], "m:f1", True, "cfg")
        g.add_evidence("pointer_use", "insn:m:0x40", ["item:A"], "m:f2", False, "linear")   # só varredura linear
        self.assertEqual(g.assess("item:A")[0], "STATIC_CANDIDATE")
        self.assertEqual(g.independence("item:A")["trusted_observations"], 1)

    def test_assess_never_yields_validated_statuses(self):
        g = self.graph()
        for k in range(5):
            g.add_evidence("code_xref" if k % 2 else "export", f"o{k}", ["item:A"], f"f{k}", True, "cfg")
        self.assertNotIn(g.assess("item:A")[0], ("KNOWN_REFERENCE_VALIDATED", "RUNTIME_VALIDATED"))

    def test_evidence_is_idempotent_and_graph_roundtrips(self):
        from l2ud.evgraph import EvidenceGraph
        g = self.graph()
        a = g.add_evidence("code_xref", "insn:m:0x10", ["item:A"], "m:f1", True, "cfg", rw="r")
        b = g.add_evidence("code_xref", "insn:m:0x10", ["item:A"], "m:f1", True, "cfg", rw="r")
        self.assertEqual(a, b)
        self.assertEqual(len(g.evidence), 1)
        g.add_edge("fn:f1", "item:A", "references", a)
        g.add_edge("fn:f1", "item:A", "references", a)
        self.assertEqual(len(g.edges), 1)
        h = EvidenceGraph.from_dict(json.loads(json.dumps(g.to_dict())))
        self.assertEqual((len(h.nodes), len(h.edges), len(h.evidence)), (3, 1, 1))
        self.assertEqual(h.independence("item:A"), g.independence("item:A"))

    def test_neighborhood_and_dot(self):
        g = self.graph()
        g.add_node("item:B", "global", "g_B")
        g.add_node("far", "global", "far")
        g.add_edge("fn:f1", "item:A", "references")
        g.add_edge("item:A", "item:B", "points_to")
        g.add_edge("item:B", "far", "points_to")
        nodes, edges = g.neighborhood("item:A", depth=1)
        self.assertEqual({n.id for n in nodes}, {"item:A", "fn:f1", "item:B"})
        self.assertEqual(len(edges), 2)
        self.assertEqual({n.id for n in g.neighborhood("item:A", depth=2)[0]}, {"item:A", "fn:f1", "item:B", "far"})
        self.assertIn('"fn:f1" -> "item:A" [label="references"];', g.to_dot())


def make_item(cat="GLOBAL_VARIABLES", module="engine.dll", sha="a" * 64, value=0x1234, kind="RVA", name=None, **kw):
    from l2ud.catalog import CatalogItem, item_id
    iid = item_id(cat, sha, kind, value, kw.pop("extra", ""))
    extra = {}
    if kind == "RVA":
        extra = {"va_preferred": 0x10000000 + (value or 0), "file_offset": kw.pop("file_offset", None)}
    return CatalogItem(iid, cat, module, sha, "bundle1", "x86", name or f"g_{value:08X}", kind, value, 0x10000000,
                       **extra, **kw)


class TestCatalog(unittest.TestCase):
    def test_types_never_mix(self):
        from l2ud.catalog import Catalog, CatalogItem
        cat = Catalog("b")
        cat.add(make_item())                                                                  # RVA com va_preferred: ok
        bad = make_item("STRUCTURE_FIELDS", value=0x10, kind="STRUCT_MEMBER_OFFSET")
        bad.va_preferred = 0x10000010                                                          # offset de campo com VA: proibido
        with self.assertRaises(ValueError) as cm:
            cat.add(bad)
        self.assertIn("tipos não se misturam", str(cm.exception))
        with self.assertRaises(ValueError):
            cat.add(CatalogItem("x", "FUNCTION_RVAS", "m", "s", "b", "x86", "n", "BOGUS", 1))
        with self.assertRaises(ValueError):
            cat.add(CatalogItem("x", "NOPE", "m", "s", "b", "x86", "n", "RVA", 1))

    def test_ids_are_stable_and_distinguish_kinds(self):
        from l2ud.catalog import item_id
        a = item_id("GLOBAL_VARIABLES", "s" * 64, "RVA", 0x1234)
        self.assertEqual(a, item_id("GLOBAL_VARIABLES", "s" * 64, "RVA", 0x1234))
        self.assertNotEqual(a, item_id("GLOBAL_VARIABLES", "t" * 64, "RVA", 0x1234))            # outra build
        self.assertNotEqual(a, item_id("GLOBAL_VARIABLES", "s" * 64, "STRUCT_MEMBER_OFFSET", 0x1234))   # outro TIPO, mesmo número
        self.assertTrue(a.startswith("GV-"))

    def test_finalize_applies_graph_rule_without_downgrading_external_validation(self):
        from l2ud.catalog import Catalog
        from l2ud.evgraph import EvidenceGraph
        cat, g = Catalog("b"), EvidenceGraph()
        a = cat.add(make_item(value=0x10))
        b = cat.add(make_item(value=0x20))
        c = cat.add(make_item(value=0x30))
        c.status = "RUNTIME_VALIDATED"
        for it in (a, b, c):
            g.add_node(f"item:{it.id}", "global", it.name)
        g.add_evidence("export", "e1", [f"item:{a.id}"], None, True, "export")
        g.add_evidence("direct_call", "i1", [f"item:{a.id}"], "m:f", True, "cfg")
        g.add_evidence("code_xref", "i2", [f"item:{b.id}"], "m:f", True, "cfg")
        cat.finalize(g)
        self.assertEqual((a.status, b.status, c.status), ("STATIC_CORROBORATED", "STATIC_CANDIDATE", "RUNTIME_VALIDATED"))
        self.assertEqual(a.independence["observations"], 2)
        self.assertTrue(b.status_reason)

    def test_json_roundtrip_and_counts(self):
        from l2ud.catalog import Catalog
        cat = Catalog("b", {"engine.dll": {"sha256": "a" * 64, "arch": "x86", "image_base": 0x10000000}})
        cat.add(make_item(value=0x10, signature={"pattern": "A1 ?? ?? ?? ??", "roundtrip": {"ok": True}}, limitations=["x"]))
        cat.add(make_item("STRUCTURE_FIELDS", value=-8, kind="STRUCT_MEMBER_OFFSET", name="field_m8"))
        again = Catalog.from_dict(json.loads(cat.to_json()))
        self.assertEqual(sorted(again.items), sorted(cat.items))
        self.assertEqual(again.get(next(iter(cat.items))).value_kind, "RVA")
        self.assertEqual(again.counts(), {"GLOBAL_VARIABLES": {"STATIC_CANDIDATE": 1}, "STRUCTURE_FIELDS": {"STATIC_CANDIDATE": 1}})
        d = json.loads(cat.to_json())
        self.assertEqual(d["categories"]["GLOBAL_VARIABLES"][0]["typed"], {"kind": "RVA", "value": "0x10"})
        with self.assertRaises(ValueError):
            Catalog.from_dict({"schema": "outro"})

    def test_csv_hpp_markdown_exports(self):
        from l2ud.catalog import Catalog
        cat = Catalog("bundle-xyz", {"engine.dll": {"sha256": "a" * 64, "arch": "x86", "image_base": 0x10000000},
                                     "core.dll": {"sha256": "b" * 64, "arch": "x86", "image_base": 0x11000000}})
        good = cat.add(make_item("FUNCTION_RVAS", value=0x1000, name="EngineMain"))
        good.status = "STATIC_CORROBORATED"
        cat.add(make_item("GLOBAL_VARIABLES", value=0x3010))                                                  # candidato
        fld = cat.add(make_item("STRUCTURE_FIELDS", value=-4, kind="STRUCT_MEMBER_OFFSET", name="struct_1_field_m4"))
        fld.status = "STATIC_CORROBORATED"
        cat.add(make_item("FUNCTION_RVAS", module="core.dll", sha="b" * 64, value=0x1000, name="EngineMain")).status = "STATIC_CORROBORATED"
        hpp = cat.to_hpp()
        self.assertIn("namespace engine_dll {", hpp)
        self.assertIn("namespace core_dll {", hpp)
        self.assertIn("constexpr std::uint32_t ENGINEMAIN_RVA = 0x1000; // STATIC_CORROBORATED", hpp)
        self.assertIn("constexpr std::int32_t STRUCT_1_FIELD_M4_OFFSET = -4;", hpp)               # offset negativo: int32, sufixo _OFFSET
        self.assertNotIn("G_00003010", hpp)                                                        # candidato fora por padrão
        self.assertIn("G_00003010_RVA", cat.to_hpp(include_candidates=True))
        self.assertNotIn("constexpr std::uintptr_t", hpp)
        csv_text = cat.to_csv()
        self.assertTrue(csv_text.startswith("id,category,module,module_sha256"))
        self.assertIn("FUNCTION_RVAS,engine.dll", csv_text)
        md = cat.to_markdown()
        for needle in ("# Catálogo de descoberta automática", "## FUNCTION_RVAS (2)", "nunca se misturam", "Um slot global tem o ENDEREÇO"):
            self.assertIn(needle, md)
        with tempfile.TemporaryDirectory() as d:
            for ext in ("json", "csv", "md", "hpp"):
                cat.export(os.path.join(d, "out." + ext))
                self.assertTrue(os.path.getsize(os.path.join(d, "out." + ext)) > 20)
            with self.assertRaises(ValueError):
                cat.export(os.path.join(d, "out.xyz"))


# ================================================================== Etapa 3 — Function Discovery
PROLOG = b"\x55\x8B\xEC"                 # push ebp; mov ebp,esp
EPILOG = b"\x5D\xC3"                     # pop ebp; ret


def rel32(frm_end: int, target: int) -> bytes:
    return struct.pack("<i", target - frm_end)


def funcs_module(name="engine.dll", base=0x10000000, ts=T0):
    """F1(entry) chama F2 e F3; F2 (exportada 'Ex2') usa uma string e um import; F3 chama F2; F4 sem chamadores."""
    b = B.Pe32Builder(base, ts, dll=True, entry=0x1000, name=name)
    b.section(".text", 0x1000, 0x400, B.F_CODE)
    b.section(".rdata", 0x2000, 0x200, B.F_RDATA)
    b.section(".data", 0x3000, 0x200, B.F_DATA)
    b.add_import("kernel32.dll", "Sleep")
    b.add_export("Ex2", 0x1020)
    iat = b.va(b.iat_rva("kernel32.dll", "Sleep"))
    b.put(0x2000, b"Hello discovery\x00")
    b.put(0x1000, PROLOG + b"\xE8" + rel32(0x1008, 0x1020) + b"\xE8" + rel32(0x100D, 0x1040) + EPILOG)       # F1
    b.put(0x1020, PROLOG + b"\x68" + struct.pack("<I", b.va(0x2000)) + b"\xFF\x15" + struct.pack("<I", iat) + EPILOG)   # F2
    b.put(0x1040, PROLOG + b"\xE8" + rel32(0x1048, 0x1020) + EPILOG)                                          # F3
    b.put(0x1060, PROLOG + EPILOG)                                                                           # F4
    b.reloc(0x1024)
    b.reloc(0x102A)
    return b


def make_work(mod_bytes: bytes, name="engine.dll", opts=None, bundle="bundle-test"):
    from l2ud.bundle import analyze_module
    from l2ud.catalog import Catalog
    from l2ud.evgraph import EvidenceGraph
    from l2ud.modwork import DiscoverOptions, ModuleWork
    d = tempfile.mkdtemp()
    p = Path(d) / name
    p.write_bytes(mod_bytes)
    info = analyze_module(p)
    img = PeImage.load(str(p))
    shutil.rmtree(d, ignore_errors=True)
    return ModuleWork(img, info, bundle, EvidenceGraph(), Catalog(bundle), opts or DiscoverOptions())


@CS
class TestFunctionDiscovery(unittest.TestCase):
    def setUp(self):
        from l2ud import funcdisc
        self.work = make_work(funcs_module().build())
        self.items = {i.value: i for i in funcdisc.run(self.work)}
        self.work.catalog.finalize(self.work.graph)

    def test_functions_are_found_without_any_signature(self):
        self.assertEqual(sorted(self.items), [0x1000, 0x1020, 0x1040, 0x1060])
        self.assertEqual({v: i.name for v, i in self.items.items()},
                         {0x1000: "sub_00001000", 0x1020: "Ex2", 0x1040: "sub_00001040", 0x1060: "sub_00001060"})
        f = self.items[0x1020]
        self.assertEqual((f.category, f.value_kind, f.module, f.arch), ("FUNCTION_RVAS", "RVA", "engine.dll", "x86"))
        self.assertEqual(f.va_preferred, 0x10000000 + 0x1020)
        self.assertEqual(f.file_offset, 0x400 + 0x20)                       # RVA e file offset são campos DISTINTOS
        self.assertEqual(f.attrs["exported_name"], "Ex2")
        self.assertEqual(f.attrs["name_source"], "export")
        self.assertEqual(self.items[0x1060].attrs["name_source"], "neutral")

    def test_calls_strings_and_imports_are_associated(self):
        f1, f2, f3 = self.items[0x1000], self.items[0x1020], self.items[0x1040]
        self.assertEqual(f1.attrs["callees"], [0x1020, 0x1040])
        self.assertEqual((f2.attrs["callers"], f2.attrs["caller_count"]), ([0x1000, 0x1040], 2))
        self.assertEqual(f2.attrs["strings"], ["Hello discovery"])
        self.assertEqual(f2.attrs["imports"], ["kernel32.dll!Sleep"])
        self.assertEqual(f3.attrs["callers"], [0x1000])
        self.assertEqual({r["from_rva"] for r in f2.references}, {"0x1003", "0x1043"})
        self.assertGreater(f2.attrs["instructions"], 3)

    def test_status_comes_from_independent_evidence_only(self):
        st = {v: (i.status, i.independence["observations"], i.independence["types"]) for v, i in self.items.items()}
        self.assertEqual(st[0x1020][0], "STATIC_CORROBORATED")                       # export + 2 chamadores + string + import
        self.assertEqual(set(st[0x1020][2]), {"export", "direct_call", "string_ref", "import_ref"})
        self.assertEqual(st[0x1040][0], "STATIC_CANDIDATE")                          # 1 chamador só
        self.assertEqual(st[0x1000][0], "STATIC_CANDIDATE")                          # só entry point
        self.assertEqual(st[0x1060], ("STATIC_CANDIDATE", 0, []))                    # prólogo sem nenhuma evidência
        self.assertIn("só 0 observação independente", self.items[0x1060].status_reason)

    def test_bounds_quality_is_stated_as_a_limitation(self):
        lim = " ".join(self.items[0x1040].limitations)
        self.assertIn("derivados de alcançabilidade (CFG): não provados", lim)
        self.assertIn("nenhum significado semântico", lim)
        self.assertEqual(self.items[0x1040].attrs["bounds_source"], "cfg")
        self.assertIn("nome de export do binário", " ".join(self.items[0x1020].limitations))

    def test_graph_has_provenance(self):
        g = self.work.graph
        kinds = {(e.kind) for e in g.edges}
        self.assertTrue({"contains", "calls", "references_string", "references_import"} <= kinds)
        f1, f2 = self.items[0x1000], self.items[0x1020]
        self.assertTrue(any(e.src == f"item:{f1.id}" and e.dst == f"item:{f2.id}" and e.kind == "calls" for e in g.edges))
        self.assertIn("string:engine.dll:0x2000", g.nodes)
        self.assertIn("import:kernel32.dll!Sleep", g.nodes)
        for eid in f2.evidence:                                                       # toda evidência rastreia a instrução/fonte
            ev = g.evidence[eid]
            self.assertTrue(ev.origin.startswith(("insn:engine.dll:", "export:", "entry:", "pdata:")), ev.origin)
        origins = [g.evidence[e].origin for e in f2.evidence if g.evidence[e].type == "direct_call"]
        self.assertEqual(sorted(origins), ["insn:engine.dll:0x1003", "insn:engine.dll:0x1043"])

    def test_max_functions_and_progress_and_cancel(self):
        from l2ud import funcdisc
        from l2ud.modwork import DiscoverOptions
        w = make_work(funcs_module().build(), opts=DiscoverOptions(max_functions=2))
        ev = []
        its = funcdisc.run(w, Progress(lambda s, d, t, m: ev.append((s, d, t))))
        self.assertEqual(len(its), 2)
        self.assertEqual(ev[0], ("functions", 0, 2))
        self.assertEqual(ev[-1], ("functions", 2, 2))
        tok = CancelToken()
        tok.cancel()
        with self.assertRaises(Cancelled):
            funcdisc.run(make_work(funcs_module().build()), Progress(None, tok))


@CS
class TestFunctionDiscoveryX64(unittest.TestCase):
    def test_x64_pdata_bounds_are_exact_evidence(self):
        from l2ud import funcdisc
        work = make_work(B.build_pe(blobs=[(0x1100, B.CFG_BLOB)], pdata_extra=B.CFG_PDATA, text_size=0x400), "x64.exe")
        items = {i.value: i for i in funcdisc.run(work)}
        f = items[0x1100]
        self.assertTrue(f.attrs["bounds_source"] == "pdata" and not [x for x in f.limitations if "HEUR" in x])
        self.assertIn("pdata", {work.graph.evidence[e].type for e in f.evidence})
        self.assertEqual(f.attrs["external_edges"], 0)


# ================================================================== Etapa 4 — Global & Pointer Slot Discovery
@CS
class TestGlobalDiscovery(unittest.TestCase):
    def test_global_variables_and_pointer_slots_discovered(self):
        from l2ud import globaldisc
        b = B.Pe32Builder(0x10000000, T0, dll=True, entry=0x1000, name="globals.dll")
        b.section(".text", 0x1000, 0x200, B.F_CODE)
        b.section(".data", 0x3000, 0x200, B.F_DATA)
        b.put(0x1000, b"\xA1\x10\x30\x00\x10\x89\x0D\x10\x30\x00\x10\xC3")
        b.reloc(0x1001)
        b.reloc(0x1007)
        b.put(0x3020, struct.pack("<I", 0x10001000))
        b.reloc(0x3020)
        b.add_export("g_ExportedVar", 0x3010)

        work = make_work(b.build(), "globals.dll")
        items = {i.value: i for i in globaldisc.run(work)}
        work.catalog.finalize(work.graph)

        self.assertIn(0x3010, items)
        self.assertIn(0x3020, items)

        var = items[0x3010]
        self.assertEqual(var.category, "GLOBAL_VARIABLES")
        self.assertEqual(var.name, "g_ExportedVar")
        self.assertEqual(var.value_kind, "RVA")
        self.assertEqual(var.va_preferred, 0x10003010)
        self.assertEqual(var.attrs["access_count"], 2)
        self.assertEqual(var.status, "STATIC_CORROBORATED")

        ptr = items[0x3020]
        self.assertEqual(ptr.category, "GLOBAL_POINTER_CANDIDATES")
        self.assertTrue(ptr.name.startswith("g_ptr_"))
        self.assertEqual(ptr.attrs["static_target_rva"], 0x1000)
        self.assertTrue(any(e.kind == "points_to" for e in work.graph.edges))


# ================================================================== Etapa 5 — Vtables with MSVC RTTI
@CS
class TestVtableDiscovery(unittest.TestCase):
    def test_vtable_with_rtti_discovered_and_demangled(self):
        from l2ud import vtabledisc
        b = B.Pe32Builder(0x10000000, T0, dll=True, entry=0x1000, name="vtables.dll")
        b.section(".text", 0x1000, 0x200, B.F_CODE)
        b.section(".rdata", 0x2000, 0x200, B.F_RDATA)

        # Três métodos
        b.put(0x1000, b"\x55\x8B\xEC\x5D\xC3")  # M1
        b.put(0x1010, b"\x55\x8B\xEC\x5D\xC3")  # M2
        b.put(0x1020, b"\x55\x8B\xEC\x5D\xC3")  # M3

        # TypeDescriptor em 0x2000
        td_raw = struct.pack("<II", 0, 0) + b".?AVPlayer@@\x00"
        b.put(0x2000, td_raw)

        # CompleteObjectLocator em 0x2020
        col_raw = struct.pack("<IIIII", 0, 0, 0, 0x10002000, 0)
        b.put(0x2020, col_raw)

        # Ponteiro para CompleteObjectLocator em 0x2034 (imediatamente antes da vtable em 0x2038)
        b.put(0x2034, struct.pack("<I", 0x10002020))

        # Vtable em 0x2038 com 3 métodos
        vtbl_raw = struct.pack("<III", 0x10001000, 0x10001010, 0x10001020)
        b.put(0x2038, vtbl_raw)

        # Construtor em 0x1030 que referencia a vtable: mov dword ptr [ecx], 0x10002038; ret
        b.put(0x1030, b"\xC7\x01\x38\x20\x00\x10\xC3")
        b.reloc(0x1032)

        work = make_work(b.build(), "vtables.dll")
        items = {i.value: i for i in vtabledisc.run(work)}
        work.catalog.finalize(work.graph)

        self.assertIn(0x2038, items)
        vt = items[0x2038]
        self.assertEqual(vt.category, "VTABLE_CANDIDATES")
        self.assertEqual(vt.name, "vtbl_Player")
        self.assertEqual(vt.attrs["rtti_class"], "Player")
        self.assertEqual(vt.attrs["method_count"], 3)
        self.assertEqual(vt.attrs["methods"], [0x1000, 0x1010, 0x1020])
        self.assertTrue(any(e.kind == "contains_method" for e in work.graph.edges))
        self.assertTrue(any(e.kind == "has_rtti" for e in work.graph.edges))


# ================================================================== Etapa 6 — Collection Discovery
@CS
class TestCollectionDiscovery(unittest.TestCase):
    def test_std_vector_detected_in_static_data(self):
        from l2ud import collectiondisc
        b = B.Pe32Builder(0x10000000, T0, dll=True, entry=0x1000, name="colls.dll")
        b.section(".text", 0x1000, 0x200, B.F_CODE)
        b.section(".rdata", 0x2000, 0x200, B.F_RDATA)
        b.section(".data", 0x3000, 0x200, B.F_DATA)

        # Buffer de elementos em 0x2050 (16 bytes)
        b.put(0x2050, b"\x01\x02\x03\x04\x05\x06\x07\x08")

        # Static vector em 0x3010: [first=0x10002050, last=0x10002058, end=0x10002060]
        b.put(0x3010, struct.pack("<III", 0x10002050, 0x10002058, 0x10002060))
        b.reloc(0x3010)
        b.reloc(0x3014)
        b.reloc(0x3018)

        # Código em 0x1000 que lê o vetor: mov eax, [0x10003010]; ret
        b.put(0x1000, b"\xA1\x10\x30\x00\x10\xC3")
        b.reloc(0x1001)

        work = make_work(b.build(), "colls.dll")
        items = collectiondisc.run(work)

        colls = [i for i in items if i.category == "COLLECTION_CANDIDATES"]
        rels = [i for i in items if i.category == "POINTER_RELATIONSHIPS"]

        self.assertEqual(len(colls), 1)
        self.assertEqual(len(rels), 1)
        self.assertEqual(colls[0].attrs["collection_type"], "std::vector")
        self.assertEqual(colls[0].value, 0x3010)
        self.assertEqual(rels[0].value_kind, "RELATION")
        self.assertTrue(any(e.kind == "has_relation" for e in work.graph.edges))


# ================================================================== Etapa 7 — Auto Signature Generation
@CS
class TestAutoSignature(unittest.TestCase):
    def test_auto_signature_generates_and_validates_roundtrip(self):
        from l2ud import autosig, funcdisc
        work = make_work(funcs_module().build(), "engine.dll")
        funcdisc.run(work)
        autosig.run(work)

        # F2 (Ex2 em 0x1020) tem instruções distintas
        f2 = next(i for i in work.catalog.by_category("FUNCTION_RVAS") if i.value == 0x1020)
        self.assertIsNotNone(f2.signature)
        self.assertTrue(f2.signature["unique"])
        self.assertTrue(f2.signature["roundtrip"]["ok"])
        self.assertEqual(f2.signature["roundtrip"]["resolved_rva"], "0x1020")


# ================================================================== Etapa 8 — Auto Discovery Pipeline & SQLite
@CS
class TestPipelineAndDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pipeline_runs_all_stages_and_persists_to_database(self):
        from l2ud.pipeline import AutoDiscoverPipeline
        from l2ud.storage import Database
        mods = l2_like()
        mods["engine.dll"] = funcs_module().build()
        write_bundle(self.root, mods)

        db_path = str(self.root / "test.db")
        with Database(db_path) as db:
            pipe = AutoDiscoverPipeline()
            cat, graph, rep = pipe.run(str(self.root), db=db, db_note="test run")

            # Verifica categorias preenchidas
            counts = cat.counts()
            self.assertIn("FUNCTION_RVAS", counts)
            self.assertIn("GLOBAL_VARIABLES", counts)

            # Verifica persistência no SQLite
            runs = db.list_catalog_runs()
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["note"], "test run")
            self.assertGreater(runs[0]["item_count"], 0)

            # Roundtrip de carregamento do DB
            loaded_cat, loaded_graph = db.load_catalog(runs[0]["id"])
            self.assertEqual(loaded_cat.bundle_id, cat.bundle_id)
            self.assertEqual(len(loaded_cat.items), len(cat.items))
            self.assertEqual(len(loaded_graph.nodes), len(graph.nodes))


# ================================================================== Etapas 9 & 10 — CrossBuild & Validation
class TestCrossBuildAndValidation(unittest.TestCase):
    def test_cross_build_diff(self):
        from l2ud.catalog import Catalog
        from l2ud.crossbuild import CrossBuildDiff
        cat1 = Catalog("build1")
        cat2 = Catalog("build2")

        # Item estável
        cat1.add(make_item("FUNCTION_RVAS", value=0x1000, name="F_Unchanged"))
        cat2.add(make_item("FUNCTION_RVAS", value=0x1000, name="F_Unchanged"))

        # Item deslocado
        cat1.add(make_item("FUNCTION_RVAS", value=0x2000, name="F_Moved"))
        cat2.add(make_item("FUNCTION_RVAS", value=0x2050, name="F_Moved"))

        # Adicionado / Removido
        cat1.add(make_item("FUNCTION_RVAS", value=0x3000, name="F_OldOnly"))
        cat2.add(make_item("FUNCTION_RVAS", value=0x4000, name="F_NewOnly"))

        diff = CrossBuildDiff(cat1, cat2).compare()
        c = diff["counts"]
        self.assertEqual((c["unchanged"], c["moved"], c["added"], c["removed"]), (1, 1, 1, 1))
        self.assertEqual(diff["moved"][0]["delta"], 0x50)

    def test_external_validation_promotion_and_mismatch_check(self):
        from l2ud.catalog import Catalog
        from l2ud.validation import apply_validation
        cat = Catalog("test_val")
        it = cat.add(make_item("FUNCTION_RVAS", value=0x1500, name="TargetFunc"))

        # Divergência de valor
        bad_val = {"validation_type": "KNOWN_REFERENCE", "items": [{"name": "TargetFunc", "value": 0x9999}]}
        rep = apply_validation(cat, bad_val)
        self.assertEqual(len(rep.mismatched), 1)
        self.assertEqual(it.status, "STATIC_CANDIDATE")

        # Valor correto promovendo para RUNTIME_VALIDATED
        good_val = {"validation_type": "RUNTIME", "source": "frida", "items": [{"name": "TargetFunc", "value": 0x1500, "notes": "hook ok"}]}
        rep2 = apply_validation(cat, good_val)
        self.assertEqual(len(rep2.promoted), 1)
        self.assertEqual(it.status, "RUNTIME_VALIDATED")
        self.assertIn("frida", it.status_reason)








# ================================================================== CLI: bundle e funcs
class TestCliBundleAndFuncs(unittest.TestCase):
    def run_cli(self, *argv):
        import contextlib
        import io
        from l2ud.cli import main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(list(argv))
        return buf.getvalue()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_bundle_command_reports_modules_and_inconsistencies(self):
        write_bundle(self.root / "ok", l2_like())
        out = self.run_cli("bundle", str(self.root / "ok"))
        for name in ("core.dll", "engine.dll", "L2.exe"):
            self.assertIn(name, out)
        self.assertIn("módulos=3", out)
        self.assertNotIn("IMPORT_UNRESOLVED", out)
        write_bundle(self.root / "mix", l2_like(unresolved=True))
        out = self.run_cli("bundle", str(self.root / "mix"), "--json", str(self.root / "r.json"))
        self.assertIn("[ERROR  ] IMPORT_UNRESOLVED", out)
        data = json.loads((self.root / "r.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["modules"]), 3)
        self.assertTrue(any(i["code"] == "IMPORT_UNRESOLVED" for i in data["issues"]))

    def test_bundle_command_shows_packing_indicators_and_bad_folder(self):
        mods = l2_like()
        mods["packed.exe"] = packed_module()
        write_bundle(self.root / "p", mods)
        out = self.run_cli("bundle", str(self.root / "p"))
        self.assertIn("likely", out)
        self.assertIn("nome típico de packer", out)
        self.assertIn("PACKING_LIKELY", out)
        with self.assertRaises(SystemExit) as cm:
            self.run_cli("bundle", str(self.root / "nao_existe"))
        self.assertIn("erro:", str(cm.exception.code))

    @CS
    def test_funcs_command_lists_and_exports_catalog(self):
        p = self.root / "engine.dll"
        p.write_bytes(funcs_module().build())
        out = self.run_cli("funcs", str(p), "--out", str(self.root / "c.json"))
        self.assertIn("4 função(ões)", out)
        self.assertIn("Ex2", out)
        self.assertIn("STATIC_CORROBORATED", out)
        cat = json.loads((self.root / "c.json").read_text(encoding="utf-8"))
        fn = {i["value"]: i for i in cat["categories"]["FUNCTION_RVAS"]}
        self.assertEqual(sorted(fn), [0x1000, 0x1020, 0x1040, 0x1060])
        self.assertEqual(fn[0x1020]["typed"], {"kind": "RVA", "value": "0x1020"})
        for ext in ("csv", "md", "hpp"):
            self.run_cli("funcs", str(p), "--out", str(self.root / f"c.{ext}"))
            self.assertTrue((self.root / f"c.{ext}").stat().st_size > 20)
        hpp = (self.root / "c.hpp").read_text(encoding="utf-8")
        self.assertIn("namespace engine_dll {", hpp)
        self.assertIn("constexpr std::uint32_t EX2_RVA = 0x1020; // STATIC_CORROBORATED", hpp)   # corroborada (export + chamadores)
        self.assertNotIn("SUB_00001040", hpp)                                                  # candidata: fora do .hpp por padrão

    @CS
    def test_funcs_command_refuses_likely_packed_unless_forced(self):
        p = self.root / "packed.exe"
        p.write_bytes(packed_module())
        with self.assertRaises(SystemExit) as cm:
            self.run_cli("funcs", str(p))
        self.assertIn("indicadores de empacotamento", str(cm.exception.code))
        self.assertIn("--force", str(cm.exception.code))

    @CS
    def test_cli_autodiscover_diff_validate_runs(self):
        p = self.root / "engine.dll"
        p.write_bytes(funcs_module().build())
        cat_file = str(self.root / "auto_cat.json")
        db_file = str(self.root / "l2ud_cli.db")

        # 1. autodiscover
        out = self.run_cli("autodiscover", str(p), "--out", cat_file, "--db", db_file, "--note", "cli-test")
        self.assertIn("Descoberta concluída:", out)
        self.assertTrue(Path(cat_file).exists())

        # 2. catalog-runs
        out_runs = self.run_cli("catalog-runs", "--db", db_file)
        self.assertIn("1 execução(ões) de catálogo:", out_runs)
        self.assertIn("cli-test", out_runs)

        # 3. diff-catalog
        diff_file = str(self.root / "diff.md")
        out_diff = self.run_cli("diff-catalog", cat_file, cat_file, "--out", diff_file)
        self.assertIn("Relatório de Comparação", out_diff)
        self.assertTrue(Path(diff_file).exists())

        # 4. validate
        val_spec = str(self.root / "val.json")
        Path(val_spec).write_text(json.dumps([{"name": "Ex2", "value": 0x1020, "notes": "ok"}]), encoding="utf-8")
        val_out = str(self.root / "val_out.json")
        out_val = self.run_cli("validate", cat_file, val_spec, "--out", val_out)
        self.assertIn("1 promovido(s)", out_val)
        self.assertTrue(Path(val_out).exists())


if __name__ == "__main__":
    unittest.main()
