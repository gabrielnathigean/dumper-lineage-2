import contextlib
import io
import json
import os
import sqlite3
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import builders as B  # noqa: E402
from builders import BASE32, BASE64, build_pe, build_pe32  # noqa: E402
from l2ud import aob, disasm  # noqa: E402
from l2ud.analysis import Context, analyze_function, find_strings, get_xrefs, hexdump, hexdump_file, xrefs_to  # noqa: E402
from l2ud.buildid import BuildProfile, compute_profile, families, family_report, identity, similarity  # noqa: E402
from l2ud.functions import build_function_map  # noqa: E402
from l2ud.pe import PeError, PeImage  # noqa: E402
from l2ud.siginfo import analyze_set, pattern_quality, stability  # noqa: E402
from l2ud.sigs import Result, Status, load_sigs, run_all, run_signature, sigs_digest  # noqa: E402
from l2ud.storage import Database, diff, export, export_structs  # noqa: E402
from l2ud.structs import discover  # noqa: E402

CS = unittest.skipUnless(disasm.available(), "Capstone não instalado")
LONG = "48 8B 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 8B 87"     # >=5 bytes fixos: padrão não-frágil


def sig(name="G", **kw):
    d = {"name": name, "pattern": LONG, "kind": "rip", "disp_offset": 3, "insn_len": 7}
    d.update(kw)
    return d


def big(blobs=(), pdata=()):
    return PeImage.parse(build_pe(blobs=blobs, pdata_extra=pdata, text_size=0x400))


# ================================================================== PE / AOB / x64 (modo Lite)
class TestCore(unittest.TestCase):
    def setUp(self):
        self.img = PeImage.parse(build_pe())

    def test_parse_x64(self):
        i = self.img
        self.assertTrue(i.is64)
        self.assertEqual(i.image_base, BASE64)
        self.assertEqual(i.rva_to_file(0x1000), 0x400)
        self.assertIsNone(i.rva_to_file(0x3010))
        self.assertEqual(i.file_to_rva(0x600), 0x2000)
        self.assertEqual(i.functions, [(0x1000, 0x1020)])

    def test_reject_garbage(self):
        for bad in (b"", b"MZ" + b"\0" * 100, b"\x7fELF" + b"\0" * 100, build_pe()[:0x90]):
            with self.assertRaises(PeError):
                PeImage.parse(bad)

    def test_aob(self):
        self.assertEqual([h.rva for h in aob.scan(self.img, "48 8B 05 ?? ?? ?? ??")], [0x1000])
        self.assertEqual(len(aob.scan(self.img, "48 8B 05 ? ? ? ?")), 1)
        self.assertGreater(len(aob.scan(self.img, "00 00", [".text"])), 100)
        with self.assertRaises(aob.AobError):
            aob.compile_pattern("48 ZZ")

    def test_function_map_pdata_exact(self):
        f = build_function_map(self.img).containing(0x1005)
        self.assertEqual((f.start, f.end, f.source, f.exact, f.strength), (0x1000, 0x1020, "pdata", True, "exact"))
        self.assertIsNone(build_function_map(self.img).containing(0x1500))

    def test_lite_xrefs_and_strings(self):
        self.assertEqual(find_strings(self.img, "hello")[0].rva, 0x2000)
        ctx = Context(self.img, "lite")
        xs = xrefs_to(self.img, 0x2000, ctx.xrefs)
        self.assertEqual([(x.from_rva, x.kind, x.via) for x in xs], [(0x1007, "rip", "opcode")])
        self.assertEqual(xs[0].function.start, 0x1000)
        self.assertTrue(any(f.wide for f in find_strings(self.img, "Login")))

    def test_hexdump_rva_and_file(self):
        self.assertIn("48 8b 05", hexdump(self.img, 0x1000, 16))
        h = hexdump_file(self.img, 0x400, 16)
        self.assertIn("rva=0x1000", h)
        self.assertIn("fora do arquivo", hexdump_file(self.img, 0x100000, 16))


# ================================================================== Status honestos
class TestStatus(unittest.TestCase):
    def setUp(self):
        self.img = PeImage.parse(build_pe())
        self.ctx = Context(self.img, "lite")

    def run1(self, **kw):
        return run_signature(self.img, sig(**kw), self.ctx)

    def test_probable_only_aob(self):
        r = self.run1()
        self.assertEqual((r.status, r.value, r.value_kind), (Status.PROBABLE, 0x3010, "RVA"))
        self.assertEqual((r.va, r.file_offset, r.hits), (BASE64 + 0x3010, None, [0x1000]))

    def test_string_gives_static_corroborated_not_confirmed(self):
        r = self.run1(confirm_string="hello world")
        self.assertEqual(r.status, Status.STATIC_CORROBORATED)
        self.assertTrue(any("limites exatos" in e for e in r.evidence))

    def test_confirmed_needs_full_sha_known_value_of_same_build(self):
        k = {self.img.sha256: "0x3010"}
        self.assertEqual(self.run1(confirm_string="hello world", known_value=k).status, Status.CONFIRMED)
        self.assertNotEqual(self.run1(known_value=k).status, Status.CONFIRMED)        # sem corroboração
        other = {"de" * 32: "0x3010"}                                                  # SHA completo de OUTRA build
        self.assertEqual(self.run1(confirm_string="hello world", known_value=other).status, Status.STATIC_CORROBORATED)

    def test_known_value_rejects_prefix_and_fingerprint(self):
        for bad in ({self.img.sha256[:12]: "0x3010"}, {self.img.sha256[:32]: "0x3010"}, {"nope": "0x1"}):
            with self.assertRaises(ValueError) as cm:
                self.run1(confirm_string="hello world", known_value=bad)
            self.assertIn("SHA-256 COMPLETO", str(cm.exception))

    def test_divergent_known_value_downgrades(self):
        r = self.run1(confirm_string="hello world", known_value={self.img.sha256: "0x9999"})
        self.assertEqual(r.status, Status.CANDIDATE)
        self.assertIn("DIVERGE", r.notes)

    def test_uncorroborated_request_is_noted(self):
        r = self.run1(confirm_string="does not exist")
        self.assertEqual(r.status, Status.PROBABLE)
        self.assertIn("não corroborada", r.notes)

    def test_fragile_pattern_is_candidate(self):
        r = self.run1(pattern="48 8B 05 ?? ?? ?? ??")
        self.assertEqual(r.status, Status.CANDIDATE)
        self.assertIn("frágil", r.notes)

    def test_imm_field_offset_kind(self):
        r = self.run1(name="F", pattern="8B 87 ?? ?? 00 00 C3", kind="imm", disp_offset=2, size=2)
        self.assertEqual((r.value, r.value_kind, r.va), (0x1234, "FIELD_OFFSET", None))

    def test_not_found_and_ambiguous(self):
        self.assertEqual(self.run1(pattern="DE AD BE EF 12 34").status, Status.NOT_FOUND)
        self.assertEqual(self.run1(pattern="00 " * 22, kind="hit").status, Status.AMBIGUOUS)

    def test_ambiguity_with_different_targets(self):
        extra = b"\x48\x8B\x05" + struct.pack("<i", 0x3020 - (0x1100 + 7)) + b"\x48\x8D\x0D" + b"\0\0\0\0" + b"\x8B\x87"
        img = PeImage.parse(build_pe(extra_text=extra))
        r = run_all(img, [sig()], "lite")[0]
        self.assertEqual((r.status, r.candidates), (Status.AMBIGUOUS, [0x3010, 0x3020]))

    def test_bad_value_kind_and_known_value_shape(self):
        with self.assertRaises(ValueError):
            self.run1(value_kind="WHATEVER")
        with self.assertRaises(ValueError):
            self.run1(known_value="0x3010")

    def test_sigs_digest_is_stable_and_order_sensitive_to_content(self):
        a, b = [sig("A"), sig("B")], [sig("A"), sig("B", pattern="90 90 90")]
        self.assertEqual(sigs_digest(a), sigs_digest([sig("A"), sig("B")]))
        self.assertNotEqual(sigs_digest(a), sigs_digest(b))


# ================================================================== x86 (modo Lite)
class TestX86Lite(unittest.TestCase):
    def setUp(self):
        self.img = PeImage.parse(build_pe32())
        self.ctx = Context(self.img, "lite")

    def test_parse_x86(self):
        i = self.img
        self.assertFalse(i.is64)
        self.assertEqual((i.image_base, i.arch), (BASE32, "x86"))
        self.assertEqual(sorted(i.relocs), [(0x1006, 3), (0x100B, 3)])
        self.assertEqual(i.functions, [])

    def test_heuristic_function_map(self):
        fm = self.ctx.fmap
        self.assertEqual(fm.source, "heuristic")
        a, b = fm.containing(0x1008), fm.containing(0x1022)
        self.assertEqual((a.start, a.end, a.exact, a.strength), (0x1000, 0x101C, False, "weak"))
        self.assertEqual((b.start, b.end), (0x1020, 0x1027))

    def test_reloc_based_abs_xrefs(self):
        g = xrefs_to(self.img, 0x3010, self.ctx.xrefs)
        self.assertEqual([(x.from_rva, x.kind, x.via) for x in g], [(0x1006, "abs", "reloc")])
        s = xrefs_to(self.img, 0x2000, self.ctx.xrefs)
        self.assertEqual((s[0].from_rva, s[0].function.start), (0x100B, 0x1000))
        self.assertEqual([(x.from_rva, x.kind) for x in xrefs_to(self.img, 0x1020, self.ctx.xrefs)], [(0x100F, "call")])

    def test_weak_bounds_never_promote_status(self):
        s = {"name": "G86", "pattern": "A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8", "kind": "abs", "disp_offset": 1,
             "confirm_string": "hello x86"}
        r = run_signature(self.img, s, self.ctx)
        self.assertEqual((r.status, r.value, r.va), (Status.CANDIDATE, 0x3010, BASE32 + 0x3010))   # padrão frágil, sem promoção
        self.assertTrue(any("NÃO conta: limites heurísticos" in e for e in r.evidence))
        s2 = dict(s, pattern="A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 80 34 12 00 00 5D C3")
        r2 = run_signature(self.img, s2, self.ctx)
        self.assertEqual(r2.status, Status.PROBABLE)                  # corroboração fraca NÃO vira STATIC_CORROBORATED
        self.assertIn("não corroborada com limites confiáveis", r2.notes)

    def test_abs_outside_image_is_not_found(self):
        s = {"name": "bad", "pattern": "68 ?? ?? ?? ?? E8", "kind": "abs", "disp_offset": 1}
        raw = bytearray(self.img.raw)
        struct.pack_into("<I", raw, 0x400 + 0x0B, 0x10000000)
        self.assertEqual(run_signature(PeImage.parse(bytes(raw)), s).status, Status.NOT_FOUND)


# ================================================================== CFG / funções (Capstone)
@CS
class TestCfg(unittest.TestCase):
    def setUp(self):
        self.img = big([(0x1100, B.CFG_BLOB)], B.CFG_PDATA)
        self.ctx = Context(self.img, "capstone")

    def test_blocks_edges_and_loop(self):
        cfg = self.ctx.cfg(0x1100)
        self.assertEqual(sorted(cfg.blocks), [0x1100, 0x1102, 0x1107, 0x110B])
        edges = {(a, t, k) for a, b in cfg.blocks.items() for t, k in b.succs}
        self.assertEqual(edges, {(0x1100, 0x1102, "fall"), (0x1102, 0x110B, "jcc"), (0x1102, 0x1107, "fall"),
                                 (0x1107, 0x1102, "jmp")})
        self.assertEqual(cfg.blocks[0x110B].terminator, "ret")
        self.assertEqual(sorted(cfg.preds()[0x1102]), [0x1100, 0x1107])        # laço: volta ao cmp
        self.assertEqual(cfg.summary()["blocks"], 4)
        self.assertEqual(cfg.extent, (0x1100, 0x110C))

    def test_reachable_vs_ambiguous_vs_padding(self):
        cfg = self.ctx.cfg(0x1100)
        self.assertEqual(cfg.reachable, [(0x1100, 0x110C)])
        self.assertEqual(cfg.ambiguous, [(0x110C, 0x1113, "ambiguous"), (0x1113, 0x1118, "padding")])

    def test_linear_sweep_xref_is_marked_untrusted(self):
        xs = [x for x in self.ctx.xrefs if x.from_rva == 0x110C]          # dado que parece `lea rcx,[rip+str]`
        self.assertEqual([(x.via, x.trusted, x.target_rva) for x in xs], [("linear", False, 0x2000)])
        real = [x for x in self.ctx.xrefs if x.from_rva == 0x1007]
        self.assertEqual([(x.via, x.trusted) for x in real], [("cfg", True)])
        no_lin = Context(self.img, "capstone", include_linear=False)
        self.assertFalse([x for x in no_lin.xrefs if x.from_rva == 0x110C])

    def test_linear_only_evidence_does_not_corroborate(self):
        s = {"name": "H", "pattern": "33 C0 83 F9 0A 7D 04 FF C0 EB F7 C3", "kind": "hit", "confirm_string": "hello world"}
        r = run_signature(self.img, s, self.ctx)
        self.assertEqual(r.status, Status.PROBABLE)
        self.assertTrue(any("só varredura linear" in e for e in r.evidence))
        r2 = run_signature(self.img, s, Context(self.img, "capstone", include_linear=False))
        self.assertEqual(r2.status, Status.PROBABLE)
        self.assertFalse(any("hello world" in e for e in r2.evidence))

    def test_indirect_jump_x64_is_flagged_unresolved(self):
        img = big([(0x1280, b"\xFF\xE0\xCC\xCC")], ((0x1280, 0x1284, 0x2100),))
        cfg = Context(img, "capstone").cfg(0x1280)
        self.assertTrue(cfg.blocks[0x1280].indirect_unresolved)
        self.assertEqual(cfg.summary()["indirect_unresolved"], 1)

    def test_x86_function_map_derived_from_cfg(self):
        img = PeImage.parse(build_pe32())
        ctx = Context(img, "capstone")
        f = ctx.fmap.containing(0x1008)
        self.assertEqual((f.start, f.end, f.source, f.exact, f.strength), (0x1000, 0x101C, "cfg", False, "derived"))
        self.assertEqual(ctx.cfg(0x1000).calls, {0x1020})

    def test_cfg_on_real_binary(self):
        path = r"C:\Windows\System32\notepad.exe"
        if not os.path.exists(path):
            self.skipTest("notepad.exe ausente")
        ctx = Context(PeImage.load(path), "capstone")
        cfg = ctx.cfg(0x225a4)
        self.assertGreater(len(cfg.blocks), 20)
        self.assertEqual(cfg.summary()["indirect_unresolved"], 0)
        self.assertTrue(all(t in cfg.blocks for b in cfg.blocks.values() for t, _ in b.succs))


# ================================================================== Capstone: decodificação / xrefs
@CS
class TestCapstone(unittest.TestCase):
    def test_decode_x64(self):
        img = PeImage.parse(build_pe())
        ins = disasm.Disassembler(img).decode(0x1000, 4)
        self.assertEqual([i.mnemonic for i in ins], ["mov", "lea", "mov", "ret"])
        self.assertEqual((ins[0].mems[0].rip_target, ins[0].disp_offset, ins[0].size), (0x3010, 3, 7))
        self.assertEqual(ins[2].mems[0].disp, 0x1234)

    def test_canonical_registers_and_operands(self):
        img = PeImage.parse(build_pe())
        i = disasm.Disassembler(img).decode_one(0x1007)          # lea rcx,[rip+str]
        self.assertEqual((i.ops[0].kind, i.ops[0].reg, i.ops[0].bits, i.ops[1].kind), ("reg", "rcx", 64, "mem"))
        self.assertEqual(disasm.canon_reg("r10d"), ("r10", 32))
        self.assertEqual(disasm.canon_reg("ecx"), ("rcx", 32))
        self.assertEqual(disasm.canon_reg("xmm0")[1], 0)

    def test_x64_capstone_xrefs(self):
        xs, eng = get_xrefs(PeImage.parse(build_pe()), "capstone")
        self.assertEqual(eng, "capstone")
        rip = {(x.from_rva, x.target_rva, x.rw) for x in xs if x.kind == "rip"}
        self.assertEqual(rip, {(0x1000, 0x3010, "r"), (0x1007, 0x2000, "addr")})

    def test_x86_decode_and_xrefs(self):
        img = PeImage.parse(build_pe32())
        ins = disasm.Disassembler(img).decode(0x1000, 8)
        self.assertEqual([i.mnemonic for i in ins][:5], ["mov", "push", "mov", "mov", "push"])
        got = {(x.from_rva, x.kind, x.target_rva, x.via) for x in get_xrefs(img, "capstone")[0]}
        self.assertIn((0x1005, "abs", 0x3010, "cfg"), got)
        self.assertIn((0x100A, "imm", 0x2000, "cfg"), got)
        self.assertIn((0x100F, "call", 0x1020, "cfg"), got)

    def test_x86_signature_corroborated_by_cfg_bounds(self):
        img = PeImage.parse(build_pe32())
        s = {"name": "G86", "pattern": "A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 80", "kind": "abs", "disp_offset": 1,
             "confirm_string": "hello x86"}
        r = run_signature(img, s, Context(img, "capstone"))
        self.assertEqual(r.status, Status.STATIC_CORROBORATED)        # limites derivados de CFG + xref via CFG
        self.assertTrue(any("capstone/cfg" in e and "derivados de CFG" in e for e in r.evidence))
        self.assertTrue(any("validação Capstone: instrução confere" in e for e in r.evidence))

    def test_function_analysis_includes_cfg(self):
        img = PeImage.parse(build_pe32())
        ctx = Context(img, "capstone")
        r = analyze_function(img, ctx, 0x1008)
        self.assertFalse(r["exact_bounds"])
        self.assertEqual((r["callees"], r["cfg"]["blocks"]), ([0x1020], 1))
        self.assertIn("hello x86", r["strings"].values())
        self.assertEqual(analyze_function(img, ctx, 0x1020)["callers"], [0x100F])

    def test_data_bytes_not_misread_as_code(self):
        raw = bytearray(build_pe())
        raw[0x600 + 0x40:0x600 + 0x45] = b"\xE8\x00\x10\x00\x00"
        xs, _ = get_xrefs(PeImage.parse(bytes(raw)), "capstone")
        self.assertFalse(any(0x2040 <= x.from_rva < 0x2045 for x in xs))

    def test_engine_capstone_without_lib_message(self):
        # contrato: pedir 'capstone' explicitamente nunca cai em silêncio no Lite
        self.assertTrue(Context(PeImage.parse(build_pe()), "capstone").capstone)


# ================================================================== AOB Intelligence
@CS
class TestAobIntel(unittest.TestCase):
    def setUp(self):
        self.img = PeImage.parse(build_pe())
        self.ctx = Context(self.img, "capstone")

    def check(self, s, img=None, ctx=None):
        from l2ud.aobintel import check_resolution
        img, ctx = img or self.img, ctx or self.ctx
        return check_resolution(img, ctx, aob.scan(img, s["pattern"])[0].rva, s)

    def test_rip_fields_validated(self):
        self.assertTrue(self.check(sig()).ok)
        bad = self.check(sig(insn_len=6))
        self.assertFalse(bad.ok)
        self.assertIn("insn_len declarado 6 != tamanho real da instrução 7", bad.issues[0])
        self.assertEqual(bad.suggestion, {"disp_offset": 3, "insn_len": 7})
        self.assertIn("disp_offset declarado 2 != real 3", self.check(sig(disp_offset=2)).issues[0])

    def test_match_in_middle_of_instruction(self):
        c = self.check(sig(pattern="8B 05 ?? ?? ?? ?? 48 8D 0D", disp_offset=2, insn_len=6))
        self.assertFalse(c.ok)
        self.assertTrue(any("MEIO de uma instrução" in i for i in c.issues))

    def test_rel_abs_imm_validated_x86_x64(self):
        i86 = PeImage.parse(build_pe32())
        c86 = Context(i86, "capstone")
        rel = {"name": "r", "pattern": "E8 ?? ?? ?? ?? 8B 80", "kind": "rel", "disp_offset": 1, "insn_len": 5}
        self.assertTrue(self.check(rel, i86, c86).ok)
        self.assertFalse(self.check(dict(rel, disp_offset=2), i86, c86).ok)
        ab = {"name": "a", "pattern": "A1 ?? ?? ?? ?? 68", "kind": "abs", "disp_offset": 1}
        self.assertTrue(self.check(ab, i86, c86).ok)
        self.assertFalse(self.check(dict(ab, disp_offset=2), i86, c86).ok)
        imm = {"name": "f", "pattern": "48 8D 0D ?? ?? ?? ?? 8B 87 ?? ?? 00 00 C3", "kind": "imm", "disp_offset": 9, "size": 4}
        self.assertTrue(self.check(imm).ok)
        c = self.check(dict(imm, size=2))
        self.assertFalse(c.ok)
        self.assertEqual(c.suggestion, {"disp_offset": 9, "size": 4})

    def test_wrong_fields_downgrade_status_only_when_validated(self):
        wrong = sig(insn_len=6)
        r = run_signature(self.img, wrong, self.ctx)
        self.assertEqual((r.status, r.value), (Status.CANDIDATE, 0x300F))          # lê o lugar errado, mas a validação pegou
        self.assertIn("NÃO batem com a instrução real", r.notes)
        self.assertEqual(r.meta["validation"]["suggestion"], {"disp_offset": 3, "insn_len": 7})
        lite = run_signature(self.img, wrong, Context(self.img, "lite"))
        self.assertEqual(lite.status, Status.PROBABLE)                             # Lite não valida (e diz isso)
        self.assertTrue(any("indisponível" in e for e in lite.evidence))

    def test_generate_wildcards_addresses_and_is_unique(self):
        from l2ud.aobintel import generate
        s = generate(self.img, self.ctx, 0x1000)
        self.assertTrue(s.unique)
        self.assertTrue(s.pattern.startswith("48 8B 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 8B 87 34 12 00 00"))
        self.assertEqual([h.rva for h in aob.scan(self.img, s.pattern)], [0x1000])
        w = generate(self.img, self.ctx, 0x1000, wild_fields=True)
        self.assertIn("8B 87 ?? ?? ?? ??", w.pattern)
        i86 = PeImage.parse(build_pe32())
        g = generate(i86, Context(i86, "capstone"), 0x1005)
        self.assertTrue(g.pattern.startswith("A1 ?? ?? ?? ?? 68 ?? ?? ?? ??"))     # abs32 e imediato-VA relocáveis

    def test_variable_bytes_between_builds(self):
        from l2ud.aobintel import find_points, variable_bytes_at
        a, b = PeImage.parse(build_pe(0x3010)), PeImage.parse(build_pe(0x3040, field=0x99))
        pts, warn = find_points({"a": a, "b": b}, LONG)
        self.assertEqual((sorted(pts), warn), (["a", "b"], []))
        rep = variable_bytes_at(pts, 16, 0, 4)
        self.assertIn(3, rep.variable)           # byte baixo do disp32 rip-relativo mudou
        self.assertNotIn(4, rep.variable)        # byte seguinte é igual
        self.assertTrue(rep.suggested_core.startswith("48 8B 05 ?? 20 00 00"))
        self.assertTrue(rep.suggested_extended.startswith("48 8B 05"))
        self.assertIn("precisa de ≥2", variable_bytes_at({"a": pts["a"]}, 8).notes[-1])

    def test_context_before_after(self):
        from l2ud.aobintel import analyze_context
        c = analyze_context(self.img, self.ctx, 0x1007, 1, 2)
        self.assertEqual((len(c["before"]), len(c["after"])), (1, 2))
        self.assertIn("lea", c["at"])
        mid = analyze_context(self.img, self.ctx, 0x1001)
        self.assertIsNone(mid["at"])
        self.assertIn("não é início de instrução", mid["note"])

    def test_genericity(self):
        from l2ud.aobintel import analyze_signature, genericity
        g = genericity(self.img, self.ctx, "48 8B 05 ?? ?? ?? ??")
        self.assertEqual((g["hits"], g["covered_instructions"]), (1, 1))
        self.assertIn("fragile_pattern", g["flags"])
        z = genericity(self.img, self.ctx, "00 00")
        self.assertIn("generic", z["flags"])
        self.assertIn("too_many_matches", z["flags"])
        a = analyze_signature(self.img, self.ctx, sig())
        self.assertTrue(a["check"].ok)
        self.assertEqual(a["generic"]["flags"], [])


# ================================================================== Structure Discovery v2
@CS
class TestStructs(unittest.TestCase):
    @staticmethod
    def disc(blobs=(), pdata=(), **kw):
        from l2ud.structs import discover
        img = big(blobs, pdata)
        return discover(img, Context(img, "capstone"), **kw)

    @staticmethod
    def offs(c):
        return sorted(f["offset_int"] for f in c.fields)

    def test_similar_layout_is_never_merged(self):
        img = PeImage.parse(build_pe(extra_text=B.STRUCT_TEXT, pdata_extra=B.STRUCT_PDATA))
        from l2ud.structs import discover
        c = discover(img, Context(img, "capstone"), min_fields=4)
        self.assertEqual(len(c), 2)
        self.assertEqual([x.functions for x in c], [[0x1100], [0x1120]])
        self.assertEqual({f["offset"]: f["type_guess"] for f in c[0].fields},
                         {"0x10": "int32", "0x14": "int32", "0x18": "int32", "0x20": "float32", "0x28": "pointer"})
        self.assertTrue(all(x.status == "CANDIDATE" and x.confidence in ("low", "medium") for x in c))
        self.assertTrue(any(r["kind"] == "similar_layout" and "NÃO fundidas" in r["detail"] for r in c[0].relations))
        self.assertEqual(c[0].hints, [])

    def test_same_register_reused_for_two_objects(self):
        c = self.disc([(0x1140, B.REUSE)], B.REUSE_PDATA)
        self.assertEqual(sorted(self.offs(x) for x in c),
                         [[0x10, 0x14, 0x18, 0x1C], [0x20, 0x24, 0x28, 0x2C]])      # 0.3 teria fundido em 8 campos
        roots = sorted(x.roots[0] for x in c)
        self.assertTrue(roots[0].startswith("argumento 0") and roots[1].startswith("argumento 1"))

    def test_same_object_through_global_pointer_across_functions(self):
        blobs, pd = B.global_ident_blobs(0x3020)
        c = self.disc(blobs, pd)
        self.assertEqual(len(c), 1)                       # nenhuma função sozinha atinge 4 campos
        self.assertEqual(self.offs(c[0]), [0x10, 0x14, 0x18, 0x1C, 0x20, 0x24])
        self.assertEqual(c[0].functions, [0x1180, 0x11A0])
        self.assertIn("global 0x3020", c[0].roots[0])

    def test_merge_by_argument_passing_records_reason(self):
        c = self.disc(B.CALL_BLOBS, B.CALL_PDATA)
        self.assertEqual(len(c), 1)
        self.assertEqual(self.offs(c[0]), [0x10, 0x14, 0x18, 0x20, 0x24, 0x28, 0x2C])
        self.assertTrue(any("passado de 0x11c0 para 0x11e0 (arg0)" in r for r in c[0].evidence["merge_reasons"]))

    def test_type_conflict_refuses_merge(self):
        c = self.disc(B.CONF_BLOBS, B.CONF_PDATA)
        self.assertEqual(sorted(self.offs(x) for x in c), [[0x10, 0x14, 0x18, 0x1C], [0x10, 0x18, 0x1C, 0x20]])
        refused = [m for x in c for m in x.evidence["refused_merges"]]
        self.assertTrue(refused and "ponteiro num objeto e escalar" in refused[0])
        types = {f["offset"]: f["type_guess"] for x in c for f in x.fields if f["offset"] == "0x10"}
        self.assertEqual(sorted({f["type_guess"] for x in c for f in x.fields if f["offset"] == "0x10"}), ["float32", "pointer"])

    def test_array_index_and_negative_offsets(self):
        c = self.disc([(0x1240, B.ARRAY)], B.ARRAY_PDATA)
        self.assertEqual(len(c), 1)
        self.assertEqual(self.offs(c[0]), [-4, 8, 0xC, 0x10, 0x20])
        f10 = next(f for f in c[0].fields if f["offset_int"] == 0x10)
        self.assertIn("array(stride 4)", f10["notes"])
        self.assertTrue(any("NEGATIVOS" in x for x in c[0].evidence["conflicts"]))
        self.assertEqual(next(f for f in c[0].fields if f["offset_int"] == -4)["offset"], "-0x4")

    def test_nested_object_through_pointer_field(self):
        c = self.disc([(0x1260, B.NESTED)], B.NESTED_PDATA)
        self.assertEqual(sorted(self.offs(x) for x in c), [[4, 8, 0xC, 0x10], [8, 0x10, 0x14, 0x18]])
        parent = next(x for x in c if 8 in self.offs(x) and 0x14 in self.offs(x))
        child = next(x for x in c if x is not parent)
        self.assertEqual(next(f for f in parent.fields if f["offset_int"] == 8)["type_guess"], "pointer")
        rel = [r for r in parent.relations if r["kind"] == "pointer_field"]
        self.assertEqual([(r["offset"], r["target"]) for r in rel], [(8, child.id)])
        self.assertIn("campo +0x8", child.roots[0])

    def test_hints_are_unverified_correlation(self):
        from l2ud.structs import discover
        f2 = b"\x48\x8D\x0D" + struct.pack("<i", 0x2000 - (0x1120 + 7)) + B.STRUCT_TEXT[0x20:]
        img = PeImage.parse(build_pe(extra_text=B.STRUCT_TEXT[:0x20] + f2,
                                     pdata_extra=((0x1100, 0x1118, 0x2100), (0x1120, 0x1120 + len(f2), 0x2100))))
        c = discover(img, Context(img, "capstone"), {"Demo": ["hello world"]}, min_fields=4)
        self.assertTrue(any(h for x in c for h in x.hints if "NÃO verificado" in h))
        self.assertEqual({x.status for x in c}, {"CANDIDATE"})

    def test_roundtrip_export_and_db(self):
        from l2ud.structs import StructCandidate
        c = self.disc(B.CALL_BLOBS, B.CALL_PDATA)
        again = StructCandidate.from_dict(json.loads(json.dumps(c[0].to_dict())))
        self.assertEqual((again.fields, again.functions, again.roots), (c[0].fields, c[0].functions, c[0].roots))
        self.assertIn("inferência estática", export_structs(c, "json"))
        self.assertIn("| offset | tipo provável", export_structs(c, "md"))
        img = big(B.CALL_BLOBS, B.CALL_PDATA)
        with tempfile.TemporaryDirectory() as d:
            db = Database(os.path.join(d, "t.db"))
            bid = db.register_build(img)
            rid = db.save_structs(bid, c)
            back = db.load_structs(bid)
            self.assertEqual((rid, [x.to_dict() for x in back]), (rid, [x.to_dict() for x in c]))
            db.close()

    def test_function_option_and_limits(self):
        c = self.disc(B.CALL_BLOBS, B.CALL_PDATA, function=0x11E0)         # só a callee: 4 campos
        self.assertEqual([self.offs(x) for x in c], [[0x20, 0x24, 0x28, 0x2C]])
        self.assertEqual(self.disc(B.CALL_BLOBS, B.CALL_PDATA, min_fields=9), [])


# ================================================================== Signature Intelligence
class TestSigInfo(unittest.TestCase):
    def test_quality(self):
        good, bad = pattern_quality(LONG), pattern_quality("00 00 00 00 ?? ??")
        self.assertFalse(good.fragile)
        self.assertTrue(bad.fragile)
        self.assertIn("low_entropy", bad.flags)
        self.assertIn("too_short", pattern_quality("48 8B 05 ?? ?? ?? ??").flags)

    def test_set_analysis(self):
        sigs = [{"name": "A", "pattern": "48 8B 05 ?? 00"}, {"name": "B", "pattern": "48 8B 05 11 00"},
                {"name": "C", "pattern": "48 8B 05 ?? 00"}, {"name": "A", "pattern": "90 90"}]
        issues = " | ".join(analyze_set(sigs))
        self.assertIn("nome repetido: A", issues)
        self.assertIn("padrão idêntico: A == C", issues)
        self.assertIn("mais genérico", issues)

    def test_stability_across_builds(self):
        a, b = PeImage.parse(build_pe()), PeImage.parse(build_pe(field=0x99))
        raw = bytearray(PeImage.parse(build_pe()).raw)
        raw[0x400:0x420] = b"\x90" * 0x20
        st = {s.name: s for s in stability([sig("G")], {"a": a, "b": b, "c": PeImage.parse(bytes(raw))})}
        self.assertTrue(any("NOT_FOUND em c" in f for f in st["G"].flags))


# ================================================================== Identidade de builds
class TestBuildId(unittest.TestCase):
    @staticmethod
    def variant(text: bytes):
        raw = bytearray(build_pe())
        raw[0x600:0x600 + len(text)] = text
        return PeImage.parse(bytes(raw))

    def test_identity_fields(self):
        i = identity(PeImage.parse(build_pe()))
        self.assertEqual((len(i["sha256"]), i["arch"], i["machine"]), (64, "x64", "0x8664"))
        self.assertNotEqual(i["sha256"], i["fingerprint"])

    def test_similarity_family_and_identity(self):
        a = compute_profile(PeImage.parse(build_pe()))
        a2 = compute_profile(PeImage.parse(build_pe(field=0x99)))          # código diferente, mesmas strings/seções
        c = compute_profile(self.variant(b"another thing"))
        self.assertTrue(similarity(a, a)["identical"])
        self.assertEqual(similarity(a, a2)["score"], 1.0)
        self.assertFalse(similarity(a, a2)["identical"])
        sc = similarity(a, c)["score"]
        self.assertTrue(0 < sc < 0.5, sc)
        fam = families({"a": a, "a2": a2, "c": c}, 0.8)
        self.assertEqual(sorted(sorted(g) for g in fam), [["a", "a2"], ["c"]])
        self.assertEqual(compute_profile(PeImage.parse(build_pe())).to_json(), a.to_json())

    def test_arch_mismatch_penalized(self):
        a, x = compute_profile(PeImage.parse(build_pe())), compute_profile(PeImage.parse(build_pe32()))
        self.assertFalse(similarity(a, x)["same_arch"])
        self.assertLessEqual(similarity(a, x)["score"], 0.5)


# ================================================================== Export / DB / AnalysisRun / diff
class TestStorage(unittest.TestCase):
    def results(self):
        img = PeImage.parse(build_pe())
        ctx = Context(img, "lite")
        return img, [
            run_signature(img, sig("Player Base", confirm_string="hello world"), ctx),
            run_signature(img, sig("OnlyAob"), ctx),
            run_signature(img, sig("Field", pattern="48 8D 0D ?? ?? ?? ?? 8B 87 ?? ?? 00 00 C3", kind="imm", disp_offset=9, size=4), ctx),
            run_signature(img, sig("Missing", pattern="DE AD BE EF 12 34"), ctx),
        ]

    def test_export_defaults_exclude_probable(self):
        img, rs = self.results()
        names = [r["name"] for r in json.loads(export(rs, "json", image_base=img.image_base))["results"]]
        self.assertEqual(names, ["Player Base"])
        names = [r["name"] for r in json.loads(export(rs, "json", include_probable=True))["results"]]
        self.assertEqual(names, ["Player Base", "OnlyAob", "Field"])

    def test_hpp_is_explicit_about_rva(self):
        img, rs = self.results()
        h = export(rs, "hpp", include_probable=True, image_base=img.image_base, build="abc")
        self.assertIn("constexpr std::uint32_t PLAYER_BASE_RVA = 0x3010; // STATIC_CORROBORATED", h)
        self.assertIn(" FIELD_OFFSET = 0x1234;", h)
        self.assertIn("ONLYAOB_RVA", h)
        self.assertIn("va_from_rva(std::uintptr_t module_base", h)
        self.assertNotIn("constexpr std::uintptr_t", h)
        self.assertNotIn("MISSING", h)

    def test_json_has_rva_va_fileoffset_separately(self):
        img, rs = self.results()
        r = json.loads(export(rs, "json", include_all=True, image_base=img.image_base))["results"][0]
        self.assertEqual((r["rva"], r["va_preferred_base"]), ("0x3010", hex(BASE64 + 0x3010)))
        self.assertIn("file_offset", r)

    def test_identifier_collisions(self):
        h = export([Result("a b", Status.CONFIRMED, 1), Result("a-b", Status.CONFIRMED, 2)], "hpp")
        self.assertIn("A_B_RVA = 0x1;", h)
        self.assertIn("A_B_RVA_2 = 0x2;", h)

    def test_each_run_is_independent_no_stale_results(self):
        img, rs = self.results()
        s1 = [sig("Player Base", confirm_string="hello world"), sig("OnlyAob")]
        s2 = [sig("Player Base", confirm_string="hello world")]
        with tempfile.TemporaryDirectory() as d:
            db = Database(os.path.join(d, "t.db"))
            b1, r1 = db.save_run(img, rs[:2], s1, "lite", "primeira")
            b2, r2 = db.save_run(img, rs[:1], s2, "lite", "segunda (OnlyAob removida)")
            self.assertEqual((b1, b2, r1 != r2), (b1, b1, True))                      # mesma build, duas execuções
            self.assertEqual([r.name for r in db.results(b1)], ["Player Base"])        # última run: sem resíduo
            self.assertEqual([r.name for r in db.results(f"{b1}@{r1}")], ["OnlyAob", "Player Base"])
            self.assertEqual([r.name for r in db.results(f"@{r1}")], ["OnlyAob", "Player Base"])
            self.assertEqual([x["results"] for x in db.runs(b1)], [2, 1])
            self.assertEqual(db.run_sigs(r1), s1)
            d_ = diff(db.results(f"@{r1}"), db.results(f"@{r2}"))
            self.assertEqual(d_["removed"], [("OnlyAob", 0x3010)])
            self.assertNotEqual(db.runs(b1)[0]["sigs_digest"], db.runs(b1)[1]["sigs_digest"])
            ev = [k for _, k, _ in db.build_events(b1)]
            self.assertEqual(ev, ["registered", "analysis_run", "analysis_run"])
            with self.assertRaises(KeyError):
                db.resolve(f"{b1}@999")
            db.close()

    def test_structs_stay_reachable_after_later_runs(self):
        from l2ud.structs import StructCandidate
        img = PeImage.parse(build_pe())
        cand = StructCandidate(1, [{"offset": "0x10", "offset_int": 16, "type_guess": "int32", "sizes": [4], "reads": 1,
                                    "writes": 0, "functions": 1, "notes": ""}], 0x14, [0x1000], roots=["argumento 0 da função 0x1000"])
        with tempfile.TemporaryDirectory() as d:
            with Database(os.path.join(d, "t.db")) as db:
                bid = db.register_build(img)
                r_structs = db.save_structs(bid, [cand])
                _, r_sigs = db.save_run(img, [], [sig("G")], "lite")
                self.assertGreater(r_sigs, r_structs)
                self.assertEqual([c.to_dict() for c in db.load_structs(bid)], [cand.to_dict()])      # não some após nova run
                self.assertEqual(db.load_structs(f"{bid}@{r_sigs}"), [])                            # run explícita é literal
                self.assertEqual(len(db.load_structs(f"@{r_structs}")), 1)

    def test_build_identity_is_full_sha_and_path_change_is_logged(self):
        img = PeImage.parse(build_pe())
        other = PeImage.parse(build_pe())
        other.path = "C:/outro/caminho.exe"
        with tempfile.TemporaryDirectory() as d:
            db = Database(os.path.join(d, "t.db"))
            a, b = db.register_build(img), db.register_build(other)
            self.assertEqual(a, b)
            self.assertIn("path_changed", [k for _, k, _ in db.build_events(a)])
            self.assertEqual(db.resolve(img.sha256)[0], a)
            self.assertEqual(db.resolve(img.sha256[:10])[0], a)             # busca por prefixo continua válida (só consulta)
            info = db.builds_info()[0]
            self.assertEqual((info["sha256"], info["arch"]), (img.sha256, "x64"))
            self.assertIsNotNone(db.profile(a))
            db.close()

    def test_history_and_diff_across_runs(self):
        a, b = PeImage.parse(build_pe(0x3010)), PeImage.parse(build_pe(0x3040, field=0x99))
        s = [sig("G", confirm_string="hello world")]
        ra, rb = run_all(a, s, "lite"), run_all(b, s, "lite")
        with tempfile.TemporaryDirectory() as d:
            db = Database(os.path.join(d, "t.db"))
            ia, ib = db.save(a, ra), db.save(b, rb)
            self.assertNotEqual(ia, ib)
            self.assertEqual(db.results(ia)[0].status, Status.STATIC_CORROBORATED)
            dd = diff(db.results(ia), db.results(ib))
            h = db.history("G")
            db.save(b, run_all(b, [sig("G", pattern=LONG + " C3")], "lite"))
            dd2 = diff(db.results(ia), db.results(ib))
            db.close()
        self.assertEqual(dd["changed"], [("G", 0x3010, 0x3040, 0x30)])
        self.assertEqual([(x["build"], x["value"]) for x in h], [(1, 0x3010), (2, 0x3040)])
        self.assertEqual(dd2["pattern_changed"], ["G"])

    def test_diff_degraded_improved(self):
        d = diff([Result("x", Status.STATIC_CORROBORATED, 1), Result("y", Status.PROBABLE, 2)],
                 [Result("x", Status.CANDIDATE, 1), Result("y", Status.CONFIRMED, 2)])
        self.assertEqual(d["degraded"], [("x", "STATIC_CORROBORATED", "CANDIDATE")])
        self.assertEqual(d["improved"], [("y", "PROBABLE", "CONFIRMED")])

    def test_migrates_0_3_database_to_a_legacy_run(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "old.db")
            con = sqlite3.connect(p)
            con.executescript("""CREATE TABLE builds(id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE, path TEXT, arch TEXT,
              fingerprint TEXT, image_base INTEGER, created TEXT DEFAULT CURRENT_TIMESTAMP);
              CREATE TABLE results(id INTEGER PRIMARY KEY, build_id INTEGER, name TEXT, status TEXT, kind TEXT,
              value INTEGER, candidates TEXT, notes TEXT, evidence TEXT, value_kind TEXT, va TEXT, file_offset INTEGER,
              pattern TEXT, value_hex TEXT, UNIQUE(build_id,name));
              CREATE TABLE structs(id INTEGER PRIMARY KEY, build_id INTEGER, cand_id INTEGER, data TEXT, UNIQUE(build_id,cand_id));
              INSERT INTO builds(sha256,path,arch,fingerprint,image_base) VALUES('aa','p','x64','f',1);
              INSERT INTO results(build_id,name,status,kind,value,candidates,notes,evidence,value_kind,va,file_offset,pattern,value_hex)
                VALUES(1,'Old','PROBABLE','rip',4112,'["0x1010"]','','[]','RVA','0x1010',NULL,'48 8B','0x1010');""")
            con.commit()
            con.close()
            db = Database(p)
            r = db.results(1)[0]
            runs = db.runs(1)
            ev = db.build_events(1)
            db.close()
            db2 = Database(p)                                     # reabrir não duplica a migração
            self.assertEqual(len(db2.runs(1)), 1)
            db2.close()
        self.assertEqual((r.name, r.value, r.value_kind, r.candidates, r.pattern), ("Old", 4112, "RVA", [0x1010], "48 8B"))
        self.assertEqual((len(runs), runs[0]["tool_version"], runs[0]["results"]), (1, "legacy", 1))
        self.assertIn("migrated", [k for _, k, _ in ev])

    def test_migrates_0_2_database_without_extra_columns(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "old2.db")
            con = sqlite3.connect(p)
            con.executescript("""CREATE TABLE builds(id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE, path TEXT, arch TEXT,
              fingerprint TEXT, image_base INTEGER, created TEXT DEFAULT CURRENT_TIMESTAMP);
              CREATE TABLE results(id INTEGER PRIMARY KEY, build_id INTEGER, name TEXT, status TEXT, kind TEXT,
              value INTEGER, candidates TEXT, notes TEXT, evidence TEXT, UNIQUE(build_id,name));
              INSERT INTO builds(sha256,path,arch,fingerprint,image_base) VALUES('aa','p','x64','f',1);
              INSERT INTO results(build_id,name,status,kind,value,candidates,notes,evidence)
                VALUES(1,'Old','PROBABLE','rip',4112,'[4112]','','[]');""")
            con.commit()
            con.close()
            db = Database(p)
            r = db.results(1)[0]
            db.close()
        self.assertEqual((r.name, r.value, r.value_kind, r.candidates), ("Old", 4112, "RVA", [4112]))


# ================================================================== Offset Intelligence
class TestIntel(unittest.TestCase):
    def build(self, engine, structs=None):
        from l2ud.intel import build_report
        img = PeImage.parse(build_pe())
        ctx = Context(img, engine)
        rs = run_all(img, [sig("G", confirm_string="hello world"), sig("F", pattern="48 8D 0D ?? ?? ?? ?? 8B 87 ?? ?? 00 00 C3",
                                                                       kind="imm", disp_offset=9, size=4),
                           sig("Gone", pattern="DE AD BE EF 12 34 56")], ctx=ctx)
        return build_report(img, ctx, rs, structs)

    def test_lite_report_is_factual_and_states_limits(self):
        from l2ud.intel import to_markdown
        rep = self.build("lite")
        by = {o.name: o for o in rep.offsets}
        g = by["G"]
        self.assertEqual((g.status, g.value), ("STATIC_CORROBORATED", 0x3010))
        self.assertEqual(g.facts["referencias_ao_valor"]["total"], 1)
        self.assertEqual(g.facts["funcao_do_match"]["limites"], "limites exatos (.pdata)")
        self.assertTrue(any("significado semântico" in n for n in g.not_established))
        self.assertTrue(any("Capstone" in n for n in g.not_established))
        self.assertTrue(any("coocorrência" in n for n in g.not_established))
        self.assertGreater(g.interest, by["Gone"].interest)
        self.assertEqual(by["Gone"].interest, 0)
        self.assertTrue(rep.warnings and "Modo Lite" in rep.warnings[0])
        md = to_markdown(rep)
        self.assertIn("**O que NÃO foi estabelecido:**", md)
        self.assertIn("'Interesse' é triagem, não confiança", md)
        for forbidden in ("jogador", "player", "inventário"):
            self.assertNotIn(forbidden, md.lower())                      # nunca inventa significado

    @CS
    def test_capstone_report_links_structs_and_validation(self):
        from l2ud.intel import explain_struct, to_markdown
        from l2ud.structs import discover
        img = PeImage.parse(build_pe(extra_text=B.STRUCT_TEXT, pdata_extra=B.STRUCT_PDATA))
        ctx = Context(img, "capstone")
        cands = discover(img, ctx, min_fields=4)
        from l2ud.intel import build_report
        rs = run_all(img, [sig("F", pattern="48 8D 0D ?? ?? ?? ?? 8B 87 ?? ?? 00 00 C3", kind="imm", disp_offset=9, size=4)], ctx=ctx)
        rep = build_report(img, ctx, rs, cands)
        f = rep.offsets[0]
        self.assertTrue(f.facts["validacao_instrucao"]["ok"])
        self.assertEqual(f.facts["funcao_do_match"]["cfg"]["blocks"], 1)
        self.assertIn("NÃO foi estabelecida", explain_struct(cands[0]))
        md = to_markdown(rep)
        self.assertIn("# Candidatos a estrutura", md)
        self.assertIn("| Leituras |", md)
        self.assertEqual(rep.to_dict()["structs"][0]["status"], "CANDIDATE")


# ================================================================== Fiação da CLI
class TestCli(unittest.TestCase):
    def run_cli(self, *argv):
        from l2ud.cli import main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(list(argv))
        return buf.getvalue()

    def test_commands_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            p = lambda n: os.path.join(d, n)  # noqa: E731
            Path(p("a.exe")).write_bytes(build_pe())
            Path(p("b.exe")).write_bytes(build_pe(0x3040, field=0x99))
            Path(p("s.json")).write_text(json.dumps([sig("G", confirm_string="hello world"), sig("Only")]))
            db = p("t.db")
            self.assertIn("fingerprint", self.run_cli("info", p("a.exe")))
            self.assertIn("1 hit(s)", self.run_cli("scan", p("a.exe"), LONG))
            self.assertIn("-> target RVA 0x3010", self.run_cli("scan", p("a.exe"), LONG, "--disp", "3", "--insn-len", "7"))
            out = self.run_cli("sigs", p("a.exe"), p("s.json"), "--db", db, "--note", "n1", "--engine", "lite", "--out", p("o.hpp"))
            self.assertIn("STATIC_CORROBORATED", out)
            self.assertIn("run #1", out)
            self.assertIn("G_RVA", Path(p("o.hpp")).read_text(encoding="utf-8"))
            self.run_cli("sigs", p("b.exe"), p("s.json"), "--db", db, "--engine", "lite")
            self.assertIn("run #1", self.run_cli("runs", "--db", db))
            self.assertIn("a.exe", self.run_cli("builds", "--db", db))
            self.assertIn("registered", self.run_cli("events", "1", "--db", db))
            self.assertIn("CHANGED  G: 0x3010 -> 0x3040 (Δ +0x30)", self.run_cli("diff", "1", "2", "--db", db))
            self.assertIn("run #", self.run_cli("history", "G", "--db", db))
            self.assertEqual(json.loads(self.run_cli("export", "1", "--db", db, "--format", "json"))["results"][0]["name"], "G")
            self.assertIn("a.exe", self.run_cli("similar", "--db", db))
            self.assertIn("sha256", self.run_cli("buildinfo", p("a.exe")))
            self.assertIn("score=", self.run_cli("siginfo", p("s.json"), p("a.exe"), p("b.exe"), "--engine", "lite"))
            self.assertIn("48 8b 05", self.run_cli("hex", p("a.exe"), "0x1000", "--length", "16"))
            rep = self.run_cli("report", p("a.exe"), p("s.json"), "--engine", "lite")
            self.assertIn("Relatório de Offset Intelligence", rep)

    @CS
    def test_capstone_commands(self):
        with tempfile.TemporaryDirectory() as d:
            p = lambda n: os.path.join(d, n)  # noqa: E731
            Path(p("a.exe")).write_bytes(build_pe(extra_text=B.STRUCT_TEXT, pdata_extra=B.STRUCT_PDATA))
            Path(p("c.exe")).write_bytes(build_pe(blobs=[(0x1100, B.CFG_BLOB)], pdata_extra=B.CFG_PDATA, text_size=0x400))
            Path(p("s.json")).write_text(json.dumps([sig("G")]))
            db = p("t.db")
            self.assertIn("mov rax", self.run_cli("disasm", p("a.exe"), "0x1000", "--count", "2"))
            out = self.run_cli("cfg", p("c.exe"), "0x1100", "--dot", p("g.dot"))
            self.assertIn("bloco 0x1102", out)
            self.assertIn("região ambiguous: 0x110c-0x1113", out)
            self.assertIn("digraph cfg", Path(p("g.dot")).read_text(encoding="utf-8"))
            self.assertIn("CFG: 4 blocos", self.run_cli("func", p("c.exe"), "0x1100", "--engine", "capstone"))
            out = self.run_cli("structs", p("a.exe"), "--db", db, "--out", p("st.md"))
            self.assertIn("CANDIDATE", out)
            self.assertIn("# Candidatos a estrutura", Path(p("st.md")).read_text(encoding="utf-8"))
            self.assertIn("CANDIDATE", self.run_cli("structs", "--from-db", "1", "--db", db))
            self.assertIn("padrão:", self.run_cli("siggen", p("a.exe"), "0x1000"))
            self.assertIn("campos conferem", self.run_cli("sigcheck", p("a.exe"), p("s.json")))
            self.assertIn("►", self.run_cli("sigctx", p("a.exe"), "0x1007"))
            self.assertIn("offsets variáveis", self.run_cli("sigvar", p("a.exe"), p("c.exe"), "--pattern", "33 C0 83 F9 0A"))
            out = self.run_cli("report", p("a.exe"), p("s.json"), "--structs", "--out", p("r.md"))
            self.assertIn("relatório gravado", out)
            self.assertIn("# Candidatos a estrutura", Path(p("r.md")).read_text(encoding="utf-8"))


# ================================================================== 0.4.1 — regressões da auditoria
def bigs(blobs=(), pdata=(), size=0x800):
    return PeImage.parse(build_pe(blobs=blobs, pdata_extra=pdata, text_size=size))


class TestAudit041FunctionMap(unittest.TestCase):
    """Item 4: cobertura REAL por intervalos (não só menor/maior endereço)."""

    def test_discontiguous_function_covers_only_its_ranges(self):
        from l2ud.functions import Function, FunctionMap
        f = Function(0x1000, 0x1200, "cfg", None, ((0x1000, 0x1100), (0x1180, 0x1200)))
        g = Function(0x1100, 0x1110, "cfg")
        fm = FunctionMap([f, g])
        self.assertEqual(fm.containing(0x1050), f)
        self.assertEqual(fm.containing(0x1190), f)            # antes: None (a função g interceptava a busca)
        self.assertEqual(fm.containing(0x1105), g)
        self.assertIsNone(fm.containing(0x1150))              # vão entre blocos: nem dado, nem padding, nem outra função
        self.assertFalse(f.contiguous)
        self.assertEqual(fm.overlaps(), [])

    def test_overlap_is_ambiguous_and_reported(self):
        from l2ud.functions import Function, FunctionMap
        x = Function(0x1000, 0x1200, "cfg")
        y = Function(0x1080, 0x1100, "cfg")
        fm = FunctionMap([x, y])
        self.assertIsNone(fm.containing(0x1090))              # duas funções cobrem: NÃO atribui
        self.assertEqual(fm.containing(0x1090, strict=False), y)
        self.assertEqual({f.start for f in fm.covering(0x1090)}, {0x1000, 0x1080})
        self.assertEqual(fm.containing(0x1150), x)            # só x cobre (antes: None porque y.start <= 0x1150)
        self.assertEqual([(a.start, b.start, s, e) for a, b, s, e in fm.overlaps()], [(0x1000, 0x1080, 0x1080, 0x1100)])


@CS
class TestAudit041Cfg(unittest.TestCase):
    def test_branch_into_middle_of_instruction_creates_no_overlap(self):            # 1.1
        img = bigs([(0x1300, B.OVERLAP)], ((0x1300, 0x1308, 0x2100),))
        cfg = Context(img, "capstone").cfg(0x1300)
        ins = sorted((i for b in cfg.blocks.values() for i in b.insns), key=lambda i: i.rva)
        self.assertEqual([(i.rva, i.end) for i in ins], [(0x1300, 0x1305), (0x1305, 0x1307)])
        self.assertTrue(all(a.end <= b.rva for a, b in zip(ins, ins[1:])))
        blocks = sorted((b.start, b.end) for b in cfg.blocks.values())
        self.assertTrue(all(a[1] <= b[0] for a, b in zip(blocks, blocks[1:])))
        self.assertEqual(cfg.invalid_edges, [(0x1305, 0x1301, "inside_instruction")])
        self.assertEqual(cfg.summary()["invalid_edges"], 1)

    def test_external_branches_are_classified_not_dropped(self):                     # 1.2
        blobs = [(0x1330, B.EXT_JCC), (0x1340, B.EXT_TAIL_RDATA), (0x1350, B.EXT_TAIL_OUT)]
        pd = ((0x1330, 0x1335, 0x2100), (0x1340, 0x1345, 0x2100), (0x1350, 0x1355, 0x2100))
        ctx = Context(bigs(blobs, pd), "capstone")
        g = ctx.cfg(0x1330)
        self.assertEqual([(e.src, e.dst, e.kind, e.cls) for e in g.external], [(0x1332, 0x1354, "jcc", "tail_transfer")])
        self.assertEqual(g.tail_calls, {0x1354})
        self.assertIn((0x1334, "fall"), g.blocks[0x1330].succs)                    # o ramo de queda continua
        g = ctx.cfg(0x1340)
        self.assertEqual([(e.dst, e.cls) for e in g.external], [(0x2000, "not_executable")])
        self.assertEqual(g.tail_calls, set())                                       # destino não executável NÃO é tail call
        g = ctx.cfg(0x1350)
        self.assertEqual([(e.dst, e.cls) for e in g.external], [(0x70000000, "outside_image")])
        self.assertEqual(g.tail_calls, set())

    def test_jump_table_needs_proven_bound(self):                                    # 1.3
        from l2ud.cfg import build_cfg
        img = PeImage.parse(build_pe32(with_table=True))
        cfg = build_cfg(img, disasm.Disassembler(img), 0x1030)
        jt = cfg.jump_tables[0]
        self.assertEqual((jt.entry_format, jt.bound, jt.declared_count, jt.resolved), ("abs32_va", "index_check", 2, True))
        self.assertEqual((jt.entries, jt.rejected), ([(0, 0x1040), (1, 0x1050)], []))
        self.assertEqual(sorted(cfg.blocks), [0x1030, 0x1035, 0x103C, 0x1040, 0x1050])
        self.assertEqual((cfg.blocks[0x1030].terminator, cfg.blocks[0x1035].terminator), ("jcc", "indirect"))
        self.assertEqual(sorted(cfg.blocks[0x1035].succs), [(0x1040, "table"), (0x1050, "table")])
        self.assertEqual(cfg.summary()["jump_tables_resolved"], 1)

    def test_unbounded_jump_table_is_not_deduced(self):
        from l2ud.cfg import build_cfg
        img = PeImage.parse(B.pe32_patched([(0x1030, b"\x90" * 5)], with_table=True))     # remove cmp/ja
        cfg = build_cfg(img, disasm.Disassembler(img), 0x1030)
        jt = cfg.jump_tables[0]
        self.assertEqual((jt.bound, jt.declared_count, jt.resolved), ("none", None, False))
        self.assertEqual([t for _, t in jt.entries], [0x1040, 0x1050])                    # candidatas, só registradas
        self.assertEqual(sorted(cfg.blocks), [0x1030])                                    # NENHUMA aresta criada
        self.assertTrue(cfg.blocks[0x1030].indirect_unresolved)
        self.assertEqual(cfg.summary()["jump_tables_resolved"], 0)

    def test_valid_looking_entry_past_the_proven_bound_is_not_read(self):
        from l2ud.cfg import build_cfg
        extra = struct.pack("<I", B.BASE32 + 0x1000)                                      # 3ª entrada: parece endereço de código
        img = PeImage.parse(B.pe32_patched(rdata=[(0x48, extra)], with_table=True))
        jt = build_cfg(img, disasm.Disassembler(img), 0x1030).jump_tables[0]
        self.assertEqual([t for _, t in jt.entries], [0x1040, 0x1050])                    # antes: aceitava 0x1000 também

    def test_rejected_table_entries_are_recorded_individually(self):
        from l2ud.cfg import build_cfg
        img = PeImage.parse(B.pe32_patched(rdata=[(0x44, struct.pack("<I", 0x500000))], with_table=True))
        cfg = build_cfg(img, disasm.Disassembler(img), 0x1030)
        jt = cfg.jump_tables[0]
        self.assertEqual(jt.entries, [(0, 0x1040)])
        self.assertEqual([(i, r) for i, _, r in jt.rejected], [(1, "fora da imagem")])
        self.assertEqual(cfg.blocks[0x1035].succs, [(0x1040, "table")])

    def test_cfg_function_covers_only_reached_blocks(self):                           # 4 (integração)
        raw = B.pe32_patched([(0x1080, B.X86_COLD_F), (0x10A0, B.X86_COLD_G), (0x1100, B.X86_COLD_TAIL)], entry=0x1080)
        ctx = Context(PeImage.parse(raw), "capstone")
        f = ctx.fmap.containing(0x1080)
        self.assertEqual((f.start, f.source, f.cover), (0x1080, "cfg", ((0x1080, 0x1085), (0x1100, 0x1101))))
        self.assertEqual(ctx.fmap.containing(0x1100), f)                              # o cold chunk pertence a F
        self.assertEqual(ctx.fmap.containing(0x10A2).start, 0x10A0)                   # G dentro do envelope de F continua de G
        self.assertIsNone(ctx.fmap.containing(0x1090))                                # vão: sem dono


@CS
class TestAudit041Disasm(unittest.TestCase):
    def test_x64_absolute_moffs_is_not_truncated_to_32_bits(self):                   # item 5
        img = bigs([(0x1580, B.MOFFS64)], B.MOFFS64_PDATA)
        i = disasm.Disassembler(img).decode_one(0x1580)
        self.assertEqual(i.mems[0].abs_va, B.BASE64 + 0x3010)
        got = {(x.from_rva, x.kind, x.target_rva) for x in get_xrefs(img, "capstone")[0]}
        self.assertIn((0x1580, "abs", 0x3010), got)

    def test_constant_without_relocation_is_not_treated_as_address(self):
        img = PeImage.parse(B.pe32_patched([(0x1090, B.X86_UNRELOCATED)], entry=0x1090))
        got = {(x.from_rva, x.kind) for x in get_xrefs(img, "capstone")[0]}
        self.assertFalse([g for g in got if g[0] == 0x1090])                          # push 0x402000 sem reloc: constante
        self.assertIn((0x100A, "imm"), got)                                           # push offset COM reloc continua sendo xref


class TestAudit041SigsLite(unittest.TestCase):
    def test_rel8_is_not_resolved_as_rel32(self):                                    # 3.1 (também sem Capstone)
        img = bigs([(0x13C0, B.REL8)], B.REL8_PDATA)
        ctx = Context(img, "lite")
        pat = "74 05 02 00 00 90 90 C3"
        r = run_signature(img, {"name": "R", "pattern": pat, "kind": "rel", "disp_offset": 1, "insn_len": 2}, ctx)
        self.assertEqual(r.status, Status.NOT_FOUND)
        self.assertIn("REL32", r.notes)
        r8 = run_signature(img, {"name": "R8", "pattern": pat, "kind": "rel8", "disp_offset": 1, "insn_len": 2}, ctx)
        self.assertEqual((r8.value, r8.status), (0x13C7, Status.PROBABLE))            # alvo REAL do jz (antes: 0x15c7)
        rel32 = run_signature(img, {"name": "R32", "pattern": pat, "kind": "rel", "disp_offset": 1}, ctx)   # insn_len padrão (rel32)
        self.assertEqual(rel32.status, Status.NOT_FOUND)                               # Lite: o opcode 0x74 denuncia branch curto
        self.assertIn("branch CURTO (rel8)", rel32.notes)

    def test_rel32_is_not_accepted_as_rel8(self):
        blob = b"\xE8" + struct.pack("<i", 0x20) + b"\x90\x90\x90\xC3"            # call rel32
        img = bigs([(0x13E0, blob)], ((0x13E0, 0x13E0 + len(blob), 0x2100),))
        ctx = Context(img, "lite")
        pat = "E8 20 00 00 00 90 90 90 C3"
        bad = run_signature(img, {"name": "x", "pattern": pat, "kind": "rel8", "disp_offset": 1}, ctx)
        self.assertEqual(bad.status, Status.NOT_FOUND)
        self.assertIn("branch NEAR (rel32)", bad.notes)
        ok = run_signature(img, {"name": "y", "pattern": pat, "kind": "rel", "disp_offset": 1}, ctx)
        self.assertEqual(ok.value, 0x13E0 + 5 + 0x20)

    def test_unresolved_match_never_corroborates(self):                              # 3.3
        blobs, pd = B.unresolved_corroboration_blobs()
        img = bigs(blobs, pd)
        s = {"name": "C", "pattern": "48 8B 05 ?? ?? ?? ?? 90 C3", "kind": "rip", "disp_offset": 3, "insn_len": 7,
             "confirm_string": "hello world"}
        r = run_signature(img, s, Context(img, "lite"))
        self.assertEqual((r.value, r.hits), (0x3010, [0x1440]))
        self.assertNotIn(r.status, (Status.STATIC_CORROBORATED, Status.CONFIRMED))     # antes: STATIC_CORROBORATED
        self.assertFalse(any("hello world" in e for e in r.evidence))
        self.assertEqual(r.meta["hit_status"], {0x1440: "resolved", 0x1467: "unresolved"})
        self.assertIn("IGNORADOS", r.evidence[0])

    def test_duplicate_signature_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            p.write_text(json.dumps([sig("A"), sig("A", pattern="90 90")]))
            with self.assertRaises(ValueError) as cm:
                load_sigs(str(p))
            self.assertIn("repetido", str(cm.exception))


@CS
class TestAudit041Sigs(unittest.TestCase):
    def test_rel8_validated_and_wrong_kind_suggests_rel8(self):                      # 3.1 com Capstone
        from l2ud.aobintel import check_resolution
        img = bigs([(0x13C0, B.REL8)], B.REL8_PDATA)
        ctx = Context(img, "capstone")
        pat = "74 05 02 00 00 90 90 C3"
        r8 = run_signature(img, {"name": "R8", "pattern": pat, "kind": "rel8", "disp_offset": 1, "insn_len": 2}, ctx)
        self.assertEqual((r8.value, r8.status, r8.meta["validation"]["ok"]), (0x13C7, Status.PROBABLE, True))
        bad = check_resolution(img, ctx, 0x13C0, {"name": "x", "pattern": pat, "kind": "rel", "disp_offset": 1, "insn_len": 5})
        self.assertFalse(bad.ok)
        self.assertEqual(bad.suggestion["kind"], "rel8")
        self.assertTrue(any("rel8" in i and "rel32" in i for i in bad.issues))

    def test_every_match_is_validated_including_the_hidden_one(self):                # 3.2
        blob, pd, hidden = B.hidden_hit_blob(3)
        img = bigs([(0x1400, blob)], pd)
        ctx = Context(img, "capstone")
        s = {"name": "H", "pattern": "48 8B 05 ?? ?? ?? ?? 90", "kind": "rip", "disp_offset": 3, "insn_len": 7}
        r = run_signature(img, s, ctx)
        v = r.meta["validation"]
        self.assertEqual((v["checked"], v["total"], v["ok"], v["partial"]), (4, 4, False, False))   # antes: checked=3
        self.assertEqual(v["invalid"], [hex(hidden)])
        self.assertEqual(r.meta["hit_status"][hidden], "invalid")
        self.assertEqual(r.status, Status.CANDIDATE)
        self.assertIn("FALHOU em 1/4", " ".join(r.evidence))

    def test_partial_validation_is_declared_and_blocks_confirmed(self):
        import l2ud.sigs as S
        blobs, pd = B.multi_site_blob(3)
        img = bigs(blobs, pd)
        s = {"name": "M", "pattern": "48 8B 05 ?? ?? ?? ?? 90", "kind": "rip", "disp_offset": 3, "insn_len": 7,
             "confirm_string": "hello world", "known_value": {img.sha256: "0x3010"}}
        full = run_signature(img, s, Context(img, "capstone"))
        self.assertEqual(full.status, Status.CONFIRMED)
        self.assertFalse(full.meta["validation"]["partial"])
        old, S.VALIDATION_LIMIT = S.VALIDATION_LIMIT, 1
        try:
            part = run_signature(img, s, Context(img, "capstone"))
        finally:
            S.VALIDATION_LIMIT = old
        v = part.meta["validation"]
        self.assertEqual((v["checked"], v["total"], v["partial"]), (1, 3, True))
        self.assertEqual(part.status, Status.STATIC_CORROBORATED)                      # CONFIRMED bloqueado
        self.assertIn("PARCIAL", part.notes)
        self.assertIn("CONFIRMED bloqueado", part.notes)
        self.assertEqual(list(part.meta["hit_status"].values()).count("unvalidated"), 2)

    def test_evidence_from_same_source_is_not_counted_as_independent(self):         # item 8
        blobs, pd = B.multi_site_blob(1)
        img = bigs(blobs, pd)
        s = {"name": "I", "pattern": "48 8B 05 ?? ?? ?? ?? 90", "kind": "rip", "disp_offset": 3, "insn_len": 7,
             "confirm_string": "hello world"}
        r = run_signature(img, s, Context(img, "capstone"))
        items = r.meta["evidence_items"]
        self.assertGreaterEqual(len(items), 2)                                         # duas referências (dois `lea`) à string
        self.assertEqual({(e["source"], e["function"]) for e in items}, {("string", "0x1500")})
        self.assertEqual(r.meta["independent_sources"], 1)                             # ...mas UMA fonte independente
        self.assertIn("1 fonte(s) de evidência independente(s)", r.notes)
        self.assertEqual(r.status, Status.STATIC_CORROBORATED)

    def test_generate_warns_when_start_is_not_an_instruction_boundary(self):        # 3.4
        from l2ud.aobintel import generate
        img = PeImage.parse(build_pe())
        ctx = Context(img, "capstone")
        ok = generate(img, ctx, 0x1000)
        self.assertTrue(ok.start_reliable)
        mid = generate(img, ctx, 0x1001)
        self.assertIs(mid.start_reliable, False)
        self.assertTrue(any("NÃO é início de instrução" in n for n in mid.notes))
        refused = generate(img, ctx, 0x1001, require_boundary=True)
        self.assertEqual((refused.pattern, refused.start_reliable), ("", False))
        self.assertIn("recusada", " ".join(refused.notes))
        self.assertIsNone(generate(img, ctx, 0x1500).start_reliable)                    # sem função/CFG: não verificável


@CS
class TestAudit041Structs(unittest.TestCase):
    @staticmethod
    def disc(blobs=(), pdata=(), **kw):
        img = bigs(blobs, pdata)
        return discover(img, Context(img, "capstone"), **kw)

    @staticmethod
    def offs(c):
        return sorted(f["offset_int"] for f in c.fields)

    def test_congruence_cannot_merge_classes_with_conflicting_children(self):       # 2.1
        c = self.disc(B.CONG_BLOBS, B.CONG_PDATA, min_fields=1)
        t20 = sorted(f["type_guess"] for s in c for f in s.fields if f["offset"] == "0x20")
        self.assertEqual(t20, ["float32", "pointer"])                                  # dois campos distintos, NÃO um 'pointer'
        self.assertFalse(any("congruência" in m for s in c for m in s.evidence["merge_reasons"]))
        refused = [m for s in c for m in s.evidence["refused_merges"]]
        self.assertTrue(refused)
        self.assertIn("implicado pelo campo +0x10", refused[0])
        self.assertIn("ponteiro num objeto e escalar (float)", refused[0])

    def test_pointer_needs_use_as_base(self):                                        # 2.5
        c = self.disc(B.SIZE_T_BLOBS, B.SIZE_T_PDATA, min_fields=1, function=0x1480)
        f = [(x["offset"], x["type_guess"], x["pointer_evidence"]) for s in c for x in s.fields]
        self.assertEqual(f, [("0x20", "pointer_candidate", "argument_or_store")])
        self.assertFalse([r for s in c for r in s.relations if r["kind"] == "pointer_field"])
        base = self.disc([(0x1100, B.STRUCT_F1)], ((0x1100, 0x1118, 0x2100),), min_fields=4)
        f28 = next(x for s in base for x in s.fields if x["offset"] == "0x28")
        self.assertEqual((f28["type_guess"], f28["pointer_evidence"]), ("pointer", "base_use"))

    def test_nonconvergence_is_reported_and_lowers_confidence(self):                # 2.4
        import l2ud.structs as S
        ok = self.disc([(0x14C0, B.BRANCHY)], B.BRANCHY_PDATA, min_fields=4, function=0x14C0)
        self.assertEqual((len(ok), ok[0].evidence["dataflow_incomplete"]), (1, []))
        old = (S.DATAFLOW_ITER_FACTOR, S.DATAFLOW_ITER_BASE)
        S.DATAFLOW_ITER_FACTOR = S.DATAFLOW_ITER_BASE = 0
        try:
            bad = self.disc([(0x14C0, B.BRANCHY)], B.BRANCHY_PDATA, min_fields=4, function=0x14C0)
        finally:
            S.DATAFLOW_ITER_FACTOR, S.DATAFLOW_ITER_BASE = old
        self.assertEqual((len(bad), bad[0].confidence), (1, "low"))
        self.assertEqual(bad[0].evidence["dataflow_incomplete"], ["0x14c0"])
        self.assertIn("NÃO convergiu", __import__("l2ud.intel", fromlist=["x"]).explain_struct(bad[0]))

    def test_x86_register_args_are_hypotheses(self):                                 # 2.2
        img = PeImage.parse(build_pe32(with_struct=True))
        c = discover(img, Context(img, "capstone"), min_fields=4)
        self.assertEqual(len(c), 1)
        s = c[0]
        self.assertIn("HIPÓTESE", s.roots[0])
        self.assertIn("registrador ecx", s.roots[0])
        self.assertTrue(s.evidence["assumptions"] and "NÃO provada" in s.evidence["assumptions"][0])
        self.assertEqual(s.confidence, "low")
        self.assertEqual(s.evidence["x86_conventions"]["0x1060"]["entry_regs_read_before_write"], ["rcx"])
        off = discover(img, Context(img, "capstone"), min_fields=4, assume_x86_reg_args=False)
        self.assertEqual(off, [])                                                      # sem a hipótese: origem desconhecida

    def test_x86_fpo_argument_is_tracked_through_esp(self):                          # achado extra da verificação
        img = PeImage.parse(B.pe32_patched([(0x1080, B.X86_FPO)], entry=0x1080))
        c = discover(img, Context(img, "capstone"), min_fields=4)
        self.assertEqual([self.offs(x) for x in c], [[8, 0xC, 0x10, 0x14]])
        self.assertIn("argumento de pilha #0", c[0].roots[0])
        self.assertEqual(c[0].evidence["assumptions"], [])                             # pilha comprovada, não hipótese

    def test_x86_stack_args_merge_through_push_and_callee_ret_n(self):               # 2.3
        raw = B.pe32_patched([(0x10C0, B.X86_CALLEE), (0x10E0, B.X86_CALLER)], entry=0x10E0)
        img = PeImage.parse(raw)
        c = discover(img, Context(img, "capstone"), min_fields=4)
        merged = [s for s in c if len(s.fields) == 8]
        self.assertEqual(len(merged), 1)
        s = merged[0]
        self.assertEqual(self.offs(s), [8, 0xC, 0x10, 0x14, 0x20, 0x24, 0x28, 0x2C])
        self.assertTrue(any("passado de 0x10e0 para 0x10c0 (arg10)" in m for m in s.evidence["merge_reasons"]))
        self.assertEqual(s.evidence["assumptions"], [])

    def test_spilled_non_pointer_push_is_not_taken_as_argument(self):                # 2.3 (negativo)
        from l2ud.structs import _FnAnalyzer
        img = PeImage.parse(B.pe32_patched([(0x10E0, B.X86_CALLER)], entry=0x10E0))
        ctx = Context(img, "capstone")
        d = ctx.disassembler
        # `push 0` antes: um push de constante ocupa o slot e NÃO vira argumento ponteiro
        pushed = d.decode_one(0x10E0)
        self.assertEqual(pushed.mnemonic, "mov")
        an = _FnAnalyzer(d, 0x10E0, ctx)
        st = an.entry_state()
        an._stk_set(st, -4, None)
        self.assertIsNone(an._stack_load(st, -4))
        self.assertEqual(an._stack_load(dict(an.entry_state()), 4), (("arg", 0x10E0, 10), 0))


class TestAudit041Storage(unittest.TestCase):
    @staticmethod
    def structs():
        from l2ud.structs import StructCandidate
        return [StructCandidate(1, [{"offset": "0x0", "offset_int": 0, "type_guess": "int32", "sizes": [4], "reads": 1,
                                      "writes": 0, "functions": 1, "notes": ""}], 4, [0x1000])]

    def test_run_must_belong_to_build(self):                                         # 5.1
        a, b = PeImage.parse(build_pe()), PeImage.parse(build_pe(field=0x99))
        with tempfile.TemporaryDirectory() as d, Database(os.path.join(d, "t.db")) as db:
            b1, r1 = db.save_run(a, [Result("A", Status.PROBABLE, 1)], [], "lite")
            b2, r2 = db.save_run(b, [Result("B", Status.PROBABLE, 2)], [], "lite")
            db.save_structs(b2, self.structs(), r2)
            for call in (lambda: db.results(b1, run=r2), lambda: db.load_structs(b1, run=r2),
                         lambda: db.save_structs(b1, [], run_id=r2), lambda: db.resolve(f"{b1}@{r2}")):
                with self.assertRaises(KeyError) as cm:
                    call()
                self.assertIn("pertence", str(cm.exception))
            self.assertEqual(len(db.load_structs(f"@{r2}")), 1)                         # antes: save_structs(b1,[],r2) APAGAVA isto
            self.assertEqual([x.name for x in db.results(b2, run=r2)], ["B"])
            with self.assertRaises(KeyError):
                db.results(b1, run=999)

    def test_numeric_id_priority_and_unique_prefix_rules(self):                      # 5.2
        from l2ud.storage import AmbiguousBuild
        with tempfile.TemporaryDirectory() as d, Database(os.path.join(d, "t.db")) as db:
            for i, sha in ((1, "2" + "a" * 63), (2, "b" * 64), (3, "b" * 63 + "c")):
                db.con.execute("INSERT INTO builds(id,sha256,path,arch,fingerprint,image_base) VALUES(?,?, 'p','x64','f',0)", (i, sha))
            db.con.commit()
            self.assertEqual(db.resolve("2")[0], 2)                                      # id exato ganha do sha que começa com '2'
            self.assertEqual(db.resolve("2" + "a" * 7)[0], 1)                            # prefixo único de 8
            self.assertEqual(db.resolve("b" * 64)[0], 2)
            self.assertEqual(db.resolve("b" * 63 + "c")[0], 3)
            with self.assertRaises(AmbiguousBuild) as cm:
                db.resolve("b" * 10)
            self.assertIn("#2", str(cm.exception))
            self.assertIn("#3", str(cm.exception))
            for bad in ("bbb", "99", "zz" * 8, "b" * 8 + "d"):                             # curto demais / inexistente / não-hex
                with self.assertRaises(KeyError):
                    db.resolve(bad)

    def test_failed_save_run_rolls_back_everything(self):                            # transações
        img = PeImage.parse(build_pe())
        with tempfile.TemporaryDirectory() as d, Database(os.path.join(d, "t.db")) as db:
            with self.assertRaises(Exception):
                db.save_run(img, [Result("OK", Status.PROBABLE, 1), Result("BAD", Status.PROBABLE, 2, notes=object())], [], "lite")
            self.assertEqual((db.runs(), db.builds()), ([], []))                         # nem build, nem run, nem resultado parcial
            db.save_run(img, [Result("Z", Status.PROBABLE, 3)], [], "lite")
            self.assertEqual([r["results"] for r in db.runs()], [1])

    def test_duplicate_result_names_are_rejected(self):
        img = PeImage.parse(build_pe())
        with tempfile.TemporaryDirectory() as d, Database(os.path.join(d, "t.db")) as db:
            with self.assertRaises(ValueError) as cm:
                db.save_run(img, [Result("X", Status.PROBABLE, 1), Result("X", Status.PROBABLE, 2)], [], "lite")
            self.assertIn("repetidos", str(cm.exception))
            self.assertEqual(db.runs(), [])

    def test_cli_reports_ambiguous_reference_as_error_message(self):
        from l2ud.cli import main
        img = PeImage.parse(build_pe())
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.db")
            with Database(path) as db:
                db.save_run(img, [Result("A", Status.PROBABLE, 1)], [], "lite")
            with self.assertRaises(SystemExit) as cm, contextlib.redirect_stdout(io.StringIO()):
                main(["diff", "1", "999", "--db", path])
            self.assertTrue(str(cm.exception.code).startswith("erro: "))


class TestAudit041BuildId(unittest.TestCase):
    @staticmethod
    def prof(sha, minhash, arch="x64"):
        return BuildProfile(sha, sha, arch, 0x8664, 0, "m", 1, [[".text", 1], [".data", 1]], [], [], minhash)

    def test_families_do_not_chain_dissimilar_builds(self):                          # 5.3
        base = list(range(32))
        b = base[:]
        for i in range(0, 6):
            b[i] = 1000 + i
        c = b[:]
        for i in range(6, 12):
            c[i] = 2000 + i
        P = {"A": self.prof("a", base), "B": self.prof("b", b), "C": self.prof("c", c)}
        sab, sbc, sac = (similarity(P[x], P[y])["score"] for x, y in (("A", "B"), ("B", "C"), ("A", "C")))
        self.assertTrue(sab >= 0.8 and sbc >= 0.8 and sac < 0.8)                       # a cadeia que enganava a 0.4.0
        self.assertEqual(families(P, 0.8), [["A", "B"], ["C"]])
        rep = {r["build"]: r for r in family_report(P, ["A", "B"])}
        self.assertEqual(rep["A"]["min"], sab)

    def test_different_architectures_never_share_a_family(self):
        P = {"x64": self.prof("a", list(range(32))), "x86": self.prof("b", list(range(32)), "x86")}
        self.assertEqual(families(P, 0.5), [["x64"], ["x86"]])


@CS
class TestAudit041Cli(unittest.TestCase):
    def run_cli(self, *argv):
        buf = io.StringIO()
        from l2ud.cli import main
        with contextlib.redirect_stdout(buf):
            main(list(argv))
        return buf.getvalue()

    def test_cfg_command_shows_external_invalid_and_tables(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "e.exe").write_bytes(build_pe(blobs=[(0x1330, B.EXT_JCC), (0x1300, B.OVERLAP)], pdata_extra=(
                (0x1330, 0x1335, 0x2100), (0x1300, 0x1308, 0x2100)), text_size=0x800))
            out = self.run_cli("cfg", str(p / "e.exe"), "0x1330")
            self.assertIn("desvio EXTERNO jcc 0x1332 -> 0x1354: tail_transfer", out)
            out = self.run_cli("cfg", str(p / "e.exe"), "0x1300")
            self.assertIn("aresta INVÁLIDA 0x1305 -> 0x1301: inside_instruction", out)
            (p / "t.exe").write_bytes(B.pe32_patched(with_table=True, entry=0x1030))
            out = self.run_cli("cfg", str(p / "t.exe"), "0x1030")
            self.assertIn("RESOLVIDA", out)
            self.assertIn("limite=index_check (2 entradas)", out)

    def test_siggen_strict_boundary_and_x86_flag(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "a.exe").write_bytes(build_pe())
            out = self.run_cli("siggen", str(p / "a.exe"), "0x1001")
            self.assertIn("NÃO é início de instrução", out)
            out = self.run_cli("siggen", str(p / "a.exe"), "0x1001", "--strict-boundary")
            self.assertIn("recusada", out)
            (p / "x.exe").write_bytes(build_pe32(with_struct=True))
            self.assertIn("HIPÓTESES", self.run_cli("structs", str(p / "x.exe")))
            self.assertIn("0 candidato(s)", self.run_cli("structs", str(p / "x.exe"), "--no-x86-reg-args"))


# ================================================================== GUI (headless-friendly: pula se não houver display)
class TestGui(unittest.TestCase):
    def setUp(self):
        import tkinter
        from tkinter import messagebox
        try:
            from l2ud.gui import App
            self.app = App()
        except tkinter.TclError as e:      # sem display
            self.skipTest(f"sem display: {e}")
        self.msgs = []
        self._orig = {n: getattr(messagebox, n) for n in ("showinfo", "showwarning", "showerror")}
        for n in self._orig:
            setattr(messagebox, n, lambda *a, _n=n, **k: self.msgs.append((_n, a)))
        import l2ud.gui as G
        self._ask = G.App._ask
        G.App._ask = lambda self, p: "nota"
        self.G = G
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        from tkinter import messagebox
        for n, f in self._orig.items():
            setattr(messagebox, n, f)
        self.G.App._ask = self._ask
        self.app.destroy()
        self.tmp.cleanup()

    def pump(self, cond, t=20):
        import time
        end = time.time() + t
        while time.time() < end:
            self.app.update()
            time.sleep(0.02)
            if cond():
                return True
        return False

    def test_every_tab_works_without_errors(self):
        a, d = self.app, Path(self.tmp.name)
        exe = d / "a.exe"
        exe.write_bytes(build_pe(extra_text=B.STRUCT_TEXT, pdata_extra=B.STRUCT_PDATA))
        (d / "s.json").write_text(json.dumps([sig("G", confirm_string="hello world")]))
        a.dbpath.set(str(d / "t.db"))
        a.exe.set(str(exe))
        a.sigs.set(str(d / "s.json"))
        a.load_pe()
        self.assertTrue(self.pump(lambda: "funções" in a.status.cget("text")), self.msgs)
        a.run_sigs()                                   # regressão: Tk vars só na thread principal
        self.assertTrue(self.pump(lambda: a.results), self.msgs)
        self.assertEqual(a.results[0].status, Status.STATIC_CORROBORATED)
        a.tree.selection_set("0")
        a.update()
        self.assertIn("STATIC_CORROBORATED", a.detail.get("1.0", "end"))
        a.hex_pos.set("0x1000")
        a.do_hex()
        self.assertIn("48 8b 05", a.hex_t.get("1.0", "end"))
        a.hex_mode.set("file")
        a.hex_pos.set("0x400")
        a.do_hex()
        self.assertIn("rva=0x1000", a.hex_t.get("1.0", "end"))
        a.hex_pat.set("48 8B 05")
        a.hex_pos.set("0")
        a.hex_find()
        self.assertEqual(a.hex_pos.get(), "0x400")
        a.hex_page(1)
        self.assertEqual(a.hex_pos.get(), "0x500")
        if disasm.available():
            a.dis_rva.set("0x1000")
            a.dis_n.set("3")
            a.do_disasm()
            self.assertTrue(self.pump(lambda: "mov rax" in a.dis_t.get("1.0", "end")))
            a.cfg_rva.set("0x1000")
            a.do_cfg()
            self.assertTrue(self.pump(lambda: "bloco" in a.cfg_t.get("1.0", "end")))
            self.assertGreater(len(a.canvas.find_all()), 0)
            a.max_fn.set("0")
            a.do_structs()
            self.assertTrue(self.pump(lambda: a.cands))
            self.assertEqual(len(a.cands), 2)
            a.st_tree.selection_set("s0")
            a.update()
            self.assertIn("NÃO foi estabelecida", a.st_t.get("1.0", "end"))
            a.structs_save()
        a.xr_rva.set("0x2000")
        a.do_xrefs()
        self.assertTrue(self.pump(lambda: a.xr.get_children()))
        a.db_save_run()
        a.db_save_run()
        a.db_refresh()
        a.b_tree.selection_set(a.b_tree.get_children()[0])
        a.update()
        a.db_pick_build()
        runs = a.r_tree.get_children()
        self.assertEqual(len(runs), 3 if disasm.available() else 2)    # (com Capstone: +1 run das estruturas gravadas)
        a.r_tree.selection_set(runs[-2:])
        a.update()
        a.db_compare()
        self.assertIn("inalterado", a.db_t.get("1.0", "end"))
        a.db_events()
        self.assertIn("analysis_run", a.db_t.get("1.0", "end"))
        a.rep_db.set(True)                            # regressão: histórico do DB lido na thread principal
        a.do_report()
        self.assertTrue(self.pump(lambda: a.rep_md), self.msgs)
        self.assertIn("Histórico entre execuções", a.rep_md)
        self.assertEqual([m for m in self.msgs if m[0] == "showerror"], [])

    def test_missing_pe_warns_instead_of_crashing(self):
        self.app.do_hex()
        self.assertTrue(self.msgs and self.msgs[-1][0] == "showwarning")


# ================================================================== Smoke em PEs reais do Windows (se existirem)
class TestRealPE(unittest.TestCase):
    PATH = r"C:\Windows\System32\notepad.exe"

    @unittest.skipUnless(os.path.exists(PATH), "notepad.exe ausente")
    def test_notepad_lite(self):
        img = PeImage.load(self.PATH)
        self.assertTrue(img.is64 and img.imports and img.functions)
        ctx = Context(img, "lite")
        self.assertEqual(ctx.fmap.source, "pdata")
        self.assertGreater(len(ctx.xrefs), 1000)
        self.assertEqual(len(identity(img)["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
