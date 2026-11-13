"""Gera os PEs sintéticos de demonstração (nada aqui é de jogo) e os arquivos de assinaturas/hints.

    python demo/make_demos.py

Saídas (na pasta demo/): demo_x64.exe, demo_x86.exe, demo_cfg_x64.exe, sigs_demo.json, hints_demo.json
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tests"))
import builders as B  # noqa: E402

# --- x64 básico: função 0x1000 + duas funções com layout parecido (0x1100/0x1120) ---
(HERE / "demo_x64.exe").write_bytes(B.build_pe(extra_text=B.STRUCT_TEXT, pdata_extra=B.STRUCT_PDATA))

# --- x86: prólogo clássico, relocações, jump table (0x1030) e função thiscall (0x1060) ---
(HERE / "demo_x86.exe").write_bytes(B.build_pe32(with_table=True, with_struct=True))

# --- x64 com TODOS os cenários de CFG/estruturas ---
blobs = [(0x1100, B.CFG_BLOB), (0x1140, B.REUSE), (0x11C0, B.CALLER), (0x11E0, B.CALLEE),
         (0x1200, B.CONF_A), (0x1220, B.CONF_B), (0x1240, B.ARRAY), (0x1260, B.NESTED)]
gblobs, gpd = B.global_ident_blobs(0x3020)
pdata = (*B.CFG_PDATA, *B.REUSE_PDATA, *gpd, *B.CALL_PDATA, *B.CONF_PDATA, *B.ARRAY_PDATA, *B.NESTED_PDATA)
(HERE / "demo_cfg_x64.exe").write_bytes(B.build_pe(blobs=blobs + gblobs, pdata_extra=pdata, text_size=0x400))

LONG = "48 8B 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 8B 87"
sigs = [
    {"name": "DemoGlobal", "pattern": LONG, "kind": "rip", "disp_offset": 3, "insn_len": 7,
     "confirm_string": "hello world"},
    {"name": "DemoSoPadrao", "pattern": LONG.replace("8B 87", "8B 87 34 12 00 00 C3"), "kind": "rip",
     "disp_offset": 3, "insn_len": 7},
    {"name": "DemoCampo", "pattern": "48 8D 0D ?? ?? ?? ?? 8B 87 ?? ?? 00 00 C3", "kind": "imm", "disp_offset": 9, "size": 4},
    {"name": "DemoPadraoCurto", "pattern": "48 8B 05 ?? ?? ?? ??", "kind": "rip", "disp_offset": 3, "insn_len": 7},
    {"name": "DemoInsnLenErrado", "pattern": LONG, "kind": "rip", "disp_offset": 3, "insn_len": 6},
    {"name": "DemoNaoExiste", "pattern": "DE AD BE EF 12 34 56 78", "kind": "hit"},
    {"name": "DemoX86", "pattern": "A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 80 34 12 00 00 5D C3", "kind": "abs",
     "disp_offset": 1, "confirm_string": "hello x86"},
]
(HERE / "sigs_demo.json").write_text(json.dumps(sigs, indent=1, ensure_ascii=False), encoding="utf-8")
(HERE / "hints_demo.json").write_text(json.dumps({"Demo": ["hello world"]}, indent=1), encoding="utf-8")
print("gerado em", HERE)
