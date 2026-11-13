"""PEs sintéticos (x64 e x86) para os testes. Nada aqui é de nenhum jogo."""
import struct

BASE64 = 0x140000000
BASE32 = 0x400000


def _headers(raw, opt_size, magic, machine, nsec, entry, base, soi, soh, ndirs_off, dirs_off, dirs):
    lfanew = 0x80
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, lfanew)
    raw[lfanew:lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", raw, lfanew + 4, machine, nsec, 0, 0, 0, opt_size, 0x22)
    o = lfanew + 24
    struct.pack_into("<H", raw, o, magic)
    struct.pack_into("<I", raw, o + 16, entry)
    if magic == 0x20B:
        struct.pack_into("<Q", raw, o + 24, base)
    else:
        struct.pack_into("<I", raw, o + 28, base)
    struct.pack_into("<I", raw, o + 56, soi)
    struct.pack_into("<I", raw, o + 60, soh)
    struct.pack_into("<I", raw, o + ndirs_off, 16)
    for idx, (rva, size) in dirs.items():
        struct.pack_into("<II", raw, o + dirs_off + idx * 8, rva, size)
    return lfanew + 24 + opt_size


def _sections(raw, so, secs):
    for i, (n, va, vs, rp, rs, fl) in enumerate(secs):
        struct.pack_into("<8sIIIIIIHHI", raw, so + i * 40, n, vs, va, rs, rp, 0, 0, 0, 0, fl)


def build_pe(global_rva=0x3010, field=0x1234, extra_text=b"", pdata_extra=(), blobs=(), text_size=0x200) -> bytes:
    """PE32+: .text/.rdata/.data(bss)/.pdata. Função 0x1000: mov rax,[rip+G]; lea rcx,[rip+str]; mov eax,[rdi+field]; ret.
    blobs: [(rva, bytes)] gravados em .text (RVA 0x1000+). text_size > 0x200 desloca .rdata/.pdata no arquivo."""
    text = bytearray(text_size)
    code = bytearray()
    code += b"\x48\x8B\x05" + struct.pack("<i", global_rva - (0x1000 + 7))
    code += b"\x48\x8D\x0D" + struct.pack("<i", 0x2000 - (0x1007 + 7))
    code += b"\x8B\x87" + struct.pack("<I", field) + b"\xC3"
    text[:len(code)] = code
    text[0x100:0x100 + len(extra_text)] = extra_text
    for rva, blob in blobs:
        text[rva - 0x1000:rva - 0x1000 + len(blob)] = blob
    rdata = bytearray(0x200)
    rdata[0:12] = b"hello world\0"
    rdata[0x20:0x20 + 14] = b"L\0o\0g\0i\0n\0\0\0\0\0"
    entries = [(0x1000, 0x1020, 0x2100), *pdata_extra]
    pdata = b"".join(struct.pack("<III", *e) for e in entries)

    rd_off, pd_off = 0x400 + text_size, 0x400 + text_size + 0x200
    raw = bytearray(pd_off + 0x200)
    so = _headers(raw, 240, 0x20B, 0x8664, 4, 0x1000, BASE64, 0x5000, 0x400, 108, 112,
                  {3: (0x4000, len(pdata))})
    _sections(raw, so, [(b".text", 0x1000, text_size, 0x400, text_size, 0x60000020),
                        (b".rdata", 0x2000, 0x200, rd_off, 0x200, 0x40000040),
                        (b".data", 0x3000, 0x100, 0, 0, 0xC0000080),
                        (b".pdata", 0x4000, 0x80, pd_off, 0x200, 0x40000040)])
    raw[0x400:0x400 + text_size] = text
    raw[rd_off:rd_off + 0x200] = rdata
    raw[pd_off:pd_off + len(pdata)] = pdata
    return bytes(raw)


STRUCT_F1 = (b"\x8B\x41\x10" b"\x8B\x51\x14" b"\x44\x8B\x41\x18" b"\xF3\x0F\x10\x41\x20"
             b"\x48\x8B\x41\x28" b"\x44\x8B\x48\x04" b"\xC3")          # 24 bytes, base rcx, + deref de rax
STRUCT_F2 = b"\x8B\x42\x10" b"\x8B\x4A\x14" b"\x44\x8B\x42\x18" b"\xF3\x0F\x10\x42\x20" b"\xC3"  # base rdx
STRUCT_TEXT = STRUCT_F1 + b"\xCC" * (0x20 - len(STRUCT_F1)) + STRUCT_F2
STRUCT_PDATA = ((0x1100, 0x1100 + len(STRUCT_F1), 0x2100), (0x1120, 0x1120 + len(STRUCT_F2), 0x2100))


def build_pe32(global_rva=0x3010, field=0x1234, with_table=False, with_struct=False) -> bytes:
    """PE32 com relocações:
    0x1000 A: prólogo mov edi,edi/push ebp/mov ebp,esp | 0x1005 mov eax,[G abs] | 0x100A push offset str |
              0x100F call B | 0x1014 mov eax,[eax+field] | pop ebp; ret
    0x1020 B: push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret"""
    text = bytearray(0x200)
    code = bytearray(b"\x8B\xFF\x55\x8B\xEC")
    code += b"\xA1" + struct.pack("<I", BASE32 + global_rva)
    code += b"\x68" + struct.pack("<I", BASE32 + 0x2000)
    code += b"\xE8" + struct.pack("<i", 0x1020 - (0x100F + 5))
    code += b"\x8B\x80" + struct.pack("<I", field)
    code += b"\x5D\xC3"
    text[:len(code)] = code
    text[len(code):0x20] = b"\xCC" * (0x20 - len(code))
    text[0x20:0x27] = b"\x55\x8B\xEC\x33\xC0\x5D\xC3"
    rdata = bytearray(0x200)
    rdata[0:10] = b"hello x86\0"
    if with_table:   # 0x1030: cmp eax,1; ja default(0x103C); jmp [eax*4 + tabela@0x2040] -> 0x1040 | 0x1050; 0x103C: ret
        text[0x30:0x35] = b"\x83\xF8\x01" b"\x77\x07"
        text[0x35:0x3C] = b"\xFF\x24\x85" + struct.pack("<I", BASE32 + 0x2040)
        text[0x3C] = 0xC3
        text[0x40:0x43] = b"\x31\xC0\xC3"
        text[0x50:0x56] = b"\xB8\x01\x00\x00\x00\xC3"
        rdata[0x40:0x48] = struct.pack("<II", BASE32 + 0x1040, BASE32 + 0x1050)
    if with_struct:  # 0x1060: thiscall (ecx=this), prólogo clássico; campos 8/0xC/0x10/0x14
        text[0x60:0x71] = (b"\x55\x8B\xEC" b"\x8B\x41\x08" b"\x8B\x51\x0C" b"\x8B\x71\x10" b"\x8B\x79\x14"
                           b"\x5D\xC3")
    reloc = struct.pack("<IIHH", 0x1000, 12, (3 << 12) | 0x006, (3 << 12) | 0x00B)

    raw = bytearray(0x1000)
    so = _headers(raw, 224, 0x10B, 0x14C, 4, 0x1000, BASE32, 0x5000, 0x400, 92, 96, {5: (0x4000, len(reloc))})
    _sections(raw, so, [(b".text", 0x1000, 0x200, 0x400, 0x200, 0x60000020),
                        (b".rdata", 0x2000, 0x200, 0x600, 0x200, 0x40000040),
                        (b".data", 0x3000, 0x100, 0, 0, 0xC0000080),
                        (b".reloc", 0x4000, 0x0C, 0x800, 0x200, 0x42000040)])
    raw[0x400:0x600] = text
    raw[0x600:0x800] = rdata
    raw[0x800:0x800 + len(reloc)] = reloc
    return bytes(raw)


# ---------------------------------------------------------------------------------------------
# Fixtures x64 para CFG e estruturas (cada função tem entrada .pdata). Endereços = RVA em .text.
# ---------------------------------------------------------------------------------------------
def rip32(target: int, insn_end: int) -> bytes:
    return struct.pack("<i", target - insn_end)


# CFG: loop + jcc + dados no meio da função (0x1100-0x1118).
#   33C0 xor eax,eax | 83F90A cmp ecx,10 | 7D04 jge ret | FFC0 inc eax | EBF7 jmp cmp | C3 ret
#   depois do ret: 7 bytes de DADO que parecem `lea rcx,[rip+str]` (só a varredura linear os lê) + padding CC
CFG_CODE = b"\x33\xC0" b"\x83\xF9\x0A" b"\x7D\x04" b"\xFF\xC0" b"\xEB\xF7" b"\xC3"
CFG_DATA = b"\x48\x8D\x0D" + rip32(0x2000, 0x110C + 7)
CFG_BLOB = CFG_CODE + CFG_DATA + b"\xCC" * (0x18 - len(CFG_CODE) - len(CFG_DATA))
CFG_PDATA = ((0x1100, 0x1118, 0x2100),)

# 0x1140: o MESMO registrador (rcx) vira dois objetos: arg0 e depois arg1 (mov rcx, rdx)
REUSE = (b"\x8B\x41\x10" b"\x44\x8B\x51\x14" b"\x44\x8B\x59\x18" b"\x8B\x41\x1C"
         b"\x48\x89\xD1"
         b"\x8B\x41\x20" b"\x44\x8B\x51\x24" b"\x44\x8B\x59\x28" b"\x8B\x41\x2C" b"\xC3")
REUSE_PDATA = ((0x1140, 0x1140 + len(REUSE), 0x2100),)


def global_ident_blobs(g: int = 0x3020):
    """Duas funções leem o MESMO ponteiro global e acessam campos diferentes (3+3 campos; nenhuma sozinha atinge 4)."""
    f1 = b"\x48\x8B\x0D" + rip32(g, 0x1180 + 7) + b"\x8B\x41\x10" + b"\x44\x8B\x51\x14" + b"\x44\x8B\x59\x18" + b"\xC3"
    f2 = b"\x48\x8B\x0D" + rip32(g, 0x11A0 + 7) + b"\x8B\x41\x1C" + b"\x44\x8B\x51\x20" + b"\x44\x8B\x59\x24" + b"\xC3"
    return [(0x1180, f1), (0x11A0, f2)], ((0x1180, 0x1180 + len(f1), 0x2100), (0x11A0, 0x11A0 + len(f2), 0x2100))


# caller(arg0: campos 0x10,0x14,0x18) chama callee(arg0: campos 0x20,0x24,0x28,0x2C) passando o MESMO rcx
CALLER = b"\x8B\x41\x10" b"\x44\x8B\x51\x14" b"\x44\x8B\x59\x18" b"\xE8" + struct.pack("<i", 0x11E0 - (0x11C0 + 16)) + b"\xC3"
CALLEE = b"\x8B\x41\x20" b"\x44\x8B\x51\x24" b"\x44\x8B\x59\x28" b"\x8B\x41\x2C" b"\xC3"
CALL_BLOBS = [(0x11C0, CALLER), (0x11E0, CALLEE)]
CALL_PDATA = ((0x11C0, 0x11C0 + len(CALLER), 0x2100), (0x11E0, 0x11E0 + len(CALLEE), 0x2100))

# conflito: A.0x10 é ponteiro (lido e desreferenciado); B.0x10 é float -> A e B NÃO podem ser fundidos
CONF_A = (b"\x48\x8B\x41\x10" b"\x44\x8B\x10" b"\x44\x8B\x59\x18" b"\x8B\x51\x1C" b"\x44\x8B\x49\x20"
          b"\xE8" + struct.pack("<i", 0x1220 - (0x1200 + 23)) + b"\xC3")
CONF_B = b"\xF3\x0F\x10\x41\x10" b"\x44\x8B\x51\x14" b"\x44\x8B\x59\x18" b"\x8B\x41\x1C" b"\xC3"
CONF_BLOBS = [(0x1200, CONF_A), (0x1220, CONF_B)]
CONF_PDATA = ((0x1200, 0x1200 + len(CONF_A), 0x2100), (0x1220, 0x1220 + len(CONF_B), 0x2100))

# array indexado + offset NEGATIVO
ARRAY = (b"\x8B\x44\x91\x10" b"\x44\x8B\x51\x08" b"\x44\x8B\x59\x0C" b"\x44\x8B\x49\xFC" b"\x8B\x41\x20" b"\xC3")
ARRAY_PDATA = ((0x1240, 0x1240 + len(ARRAY), 0x2100),)

# cadeia de ponteiros: pai(arg0: 8*,0x10,0x14,0x18) -> filho(deref(arg0,8): 4,8,0xC,0x10)
NESTED = (b"\x48\x8B\x41\x08" b"\x44\x8B\x51\x10" b"\x44\x8B\x59\x14" b"\x44\x8B\x49\x18"
          b"\x8B\x50\x04" b"\x44\x8B\x50\x08" b"\x44\x8B\x58\x0C" b"\x44\x8B\x48\x10" b"\xC3")
NESTED_PDATA = ((0x1260, 0x1260 + len(NESTED), 0x2100),)


# ---------------------------------------------------------------------------------------------
# 0.4.1 — fixtures de regressão da auditoria (cada um reproduz uma falha real da 0.4.0)
# ---------------------------------------------------------------------------------------------
OVERLAP = b"\xB8\x90\x90\x90\x90" b"\xEB\xFA" b"\xC3"            # mov eax,imm32 | jmp 0x1301 (MEIO do mov) | ret   @0x1300
EXT_JCC = b"\x85\xC9" b"\x75\x20" b"\xC3"                        # test ecx,ecx | jne 0x1354 (fora da função) | ret  @0x1330
EXT_TAIL_RDATA = b"\xE9" + struct.pack("<i", 0x2000 - 0x1345)    # jmp 0x2000 (.rdata, NÃO executável)               @0x1340
EXT_TAIL_OUT = b"\xE9" + struct.pack("<i", 0x70000000 - 0x1355)  # jmp para fora da imagem                           @0x1350
# congruência: F(arg0.0x10 -> .0x20 PONTEIRO usado como base) chama G(arg0.0x10 -> .0x20 FLOAT)
CONG_F = (b"\x48\x8B\x41\x10" b"\x48\x8B\x50\x20" b"\x44\x8B\x02" b"\xE8" + struct.pack("<i", 0x10) + b"\xC3")   # @0x1380
CONG_G = b"\x48\x8B\x41\x10" b"\xF3\x0F\x10\x40\x20" b"\xC3"                                                    # @0x13A0
CONG_BLOBS = [(0x1380, CONG_F), (0x13A0, CONG_G)]
CONG_PDATA = ((0x1380, 0x1391, 0x2100), (0x13A0, 0x13AA, 0x2100))
# ponteiro fraco: mov rdx,[rcx+0x20]; call h  (rdx só é ARGUMENTO; pode ser um size_t)                             @0x1480
SIZE_T = b"\x48\x8B\x51\x20" b"\xE8" + struct.pack("<i", 0x14A0 - 0x1489) + b"\xC3"
SIZE_T_BLOBS = [(0x1480, SIZE_T), (0x14A0, b"\xC3")]
SIZE_T_PDATA = ((0x1480, 0x148A, 0x2100), (0x14A0, 0x14A1, 0x2100))
# dataflow com laço/desvio (3 blocos) e 4 campos no bloco de entrada                                               @0x14C0
BRANCHY = b"\x8B\x41\x10" b"\x44\x8B\x51\x14" b"\x44\x8B\x59\x18" b"\x44\x8B\x49\x1C" b"\x85\xD2" b"\x74\x01" b"\x90" b"\xC3"
BRANCHY_PDATA = ((0x14C0, 0x14C0 + len(BRANCHY), 0x2100),)
# rel8: jz curto cujos 4 bytes seguintes lidos como rel32 dariam 0x205                                              @0x13C0
REL8 = b"\x74\x05\x02\x00\x00\x90\x90\xC3"
REL8_PDATA = ((0x13C0, 0x13C8, 0x2100),)


def hidden_hit_blob(good=3):
    """`good` sites `mov rax,[rip+G]; nop` + 1 site ESCONDIDO dentro de `mov rax,imm64` (meio de instrução)  @0x1400"""
    sites = b""
    for k in range(good):
        a = 0x1400 + 8 * k
        sites += b"\x48\x8B\x05" + rip32(0x3010, a + 7) + b"\x90"
    hit = 0x1400 + 8 * good + 2
    sites += b"\x48\xB8" + b"\x48\x8B\x05" + rip32(0x3010, hit + 7) + b"\x90" + b"\xC3"
    return sites, ((0x1400, 0x1400 + len(sites), 0x2100),), hit


def unresolved_corroboration_blobs():
    """f1 resolve (0x3010) sem string; f2 referencia a string mas seu match aponta para FORA da imagem  @0x1440/0x1460"""
    f1 = b"\x48\x8B\x05" + rip32(0x3010, 0x1440 + 7) + b"\x90\xC3"
    f2 = b"\x48\x8D\x0D" + rip32(0x2000, 0x1460 + 7) + b"\x48\x8B\x05" + struct.pack("<i", 0x70000000) + b"\x90\xC3"
    return [(0x1440, f1), (0x1460, f2)], ((0x1440, 0x1449, 0x2100), (0x1460, 0x1470, 0x2100))


def multi_site_blob(sites=3):
    """função com 2 `lea` da MESMA string (evidências da mesma fonte) + `sites` matches bons         @0x1500"""
    code = b"\x48\x8D\x0D" + rip32(0x2000, 0x1500 + 7) + b"\x48\x8D\x15" + rip32(0x2000, 0x1507 + 7)
    for k in range(sites):
        a = 0x1500 + 14 + 8 * k
        code += b"\x48\x8B\x05" + rip32(0x3010, a + 7) + b"\x90"
    code += b"\xC3"
    return [(0x1500, code)], ((0x1500, 0x1500 + len(code), 0x2100),)


MOFFS64 = b"\x48\xA1" + struct.pack("<Q", BASE64 + 0x3010) + b"\xC3"            # mov rax,[abs64]; ret   @0x1580
MOFFS64_PDATA = ((0x1580, 0x1580 + len(MOFFS64), 0x2100),)


def pe32_patched(patches=(), entry=None, rdata=(), with_table=False, with_struct=False) -> bytes:
    """PE32 base + bytes arbitrários em .text (por RVA) e .rdata (por offset), e entry point opcional."""
    raw = bytearray(build_pe32(with_table=with_table, with_struct=with_struct))
    for rva, blob in patches:
        raw[0x400 + (rva - 0x1000):0x400 + (rva - 0x1000) + len(blob)] = blob
    for off, blob in rdata:
        raw[0x600 + off:0x600 + off + len(blob)] = blob
    if entry is not None:
        struct.pack_into("<I", raw, 0xA8, entry)
    return bytes(raw)


# x86: callee stdcall (ebp-frame, [ebp+8], ret 4) chamado por caller FPO ([esp+4]) com `push eax`
X86_CALLEE = (b"\x55\x8B\xEC" b"\x8B\x45\x08" b"\x8B\x50\x08" b"\x8B\x48\x0C" b"\x8B\x70\x10" b"\x8B\x78\x14"
              b"\x5D\xC2\x04\x00")                                                      # @0x10C0
X86_CALLER = (b"\x8B\x44\x24\x04" b"\x8B\x50\x20" b"\x8B\x48\x24" b"\x8B\x70\x28" b"\x8B\x78\x2C" b"\x50"
              b"\xE8" + struct.pack("<i", 0x10C0 - 0x10F6) + b"\xC3")                   # @0x10E0 (entry)
X86_FPO = b"\x8B\x44\x24\x04" b"\x8B\x48\x08" b"\x8B\x50\x0C" b"\x8B\x70\x10" b"\x8B\x78\x14" b"\xC3"   # @0x1080 (entry)
# x86: função F com cold chunk: jmp 0x1100 (descontínua) e função G (prólogo) dentro do envelope de F
X86_COLD_F = b"\xE9" + struct.pack("<i", 0x1100 - 0x1085)                              # @0x1080 (entry)
X86_COLD_G = b"\x55\x8B\xEC\x5D\xC3"                                                    # @0x10A0
X86_COLD_TAIL = b"\xC3"                                                                 # @0x1100
X86_UNRELOCATED = b"\x68\x00\x20\x40\x00\xC3"                                           # push 0x402000 (SEM reloc); ret  @0x1090


# =============================================================================================
# 0.5.0 — Pe32Builder: PE32 com imports (IAT), exports, relocações e seções livres
# =============================================================================================
F_CODE, F_RDATA, F_DATA, F_BSS, F_RELOC = 0x60000020, 0x40000040, 0xC0000040, 0xC0000080, 0x42000040
EDATA_RVA, IDATA_RVA, RELOC_RVA = 0x5000, 0x6000, 0x7000


class Pe32Builder:
    """Monta um PE32 (x86) completo. Seções do usuário devem ficar abaixo de 0x5000; .edata/.idata/.reloc são
    geradas em 0x5000/0x6000/0x7000. `iat_rva(dll, nome)` é determinístico depois que todos os imports foram declarados."""

    def __init__(self, image_base=0x10000000, timestamp=0x3F000000, dll=True, machine=0x14C, entry=0x1000,
                 name="mod.dll"):
        self.base, self.ts, self.dll, self.machine, self.entry, self.name = image_base, timestamp, dll, machine, entry, name
        self.secs: dict[str, dict] = {}
        self.exports: list[tuple[str, int]] = []
        self.imports: list[tuple[str, str]] = []
        self.relocs: list[int] = []
        self._iat_locked = False

    # ---- montagem ----
    def section(self, name, rva, size, flags, raw=True):
        self.secs[name] = {"rva": rva, "data": bytearray(size), "flags": flags, "raw": raw, "vsize": size}
        return self.secs[name]["data"]

    def put(self, rva, blob):
        for s in self.secs.values():
            if s["rva"] <= rva < s["rva"] + len(s["data"]):
                off = rva - s["rva"]
                assert off + len(blob) <= len(s["data"]), "blob excede a seção"
                s["data"][off:off + len(blob)] = blob
                return
        raise AssertionError(f"nenhuma seção contém o RVA {rva:#x}")

    def u32(self, rva, v):
        self.put(rva, struct.pack("<I", v & 0xFFFFFFFF))

    def va(self, rva):
        return self.base + rva

    def add_export(self, name, rva):
        self.exports.append((name, rva))

    def add_import(self, dll, name):
        assert not self._iat_locked, "declare todos os imports antes de pedir iat_rva()"
        self.imports.append((dll, name))

    def reloc(self, rva):
        self.relocs.append(rva)

    # ---- imports ----
    def _import_layout(self):
        dlls: dict[str, list[str]] = {}
        for d, n in self.imports:
            dlls.setdefault(d, []).append(n)
        pos = IDATA_RVA + 20 * (len(dlls) + 1)
        ilt, iat = {}, {}
        for d, names in dlls.items():
            ilt[d] = pos
            pos += 4 * (len(names) + 1)
        for d, names in dlls.items():
            iat[d] = pos
            pos += 4 * (len(names) + 1)
        hint, dname = {}, {}
        for d, names in dlls.items():
            for n in names:
                hint[(d, n)] = pos
                pos += 2 + len(n) + 1 + ((len(n) + 1) % 2)
        for d in dlls:
            dname[d] = pos
            pos += len(d) + 1
        return dlls, ilt, iat, hint, dname, pos

    def iat_rva(self, dll, name):
        self._iat_locked = True
        dlls, _, iat, _, _, _ = self._import_layout()
        return iat[dll] + 4 * dlls[dll].index(name)

    def _gen_idata(self):
        dlls, ilt, iat, hint, dname, end = self._import_layout()
        buf = bytearray(end - IDATA_RVA)
        for i, (d, names) in enumerate(dlls.items()):
            struct.pack_into("<IIIII", buf, 20 * i, ilt[d], 0, 0, dname[d], iat[d])
            for j, n in enumerate(names):
                struct.pack_into("<I", buf, ilt[d] - IDATA_RVA + 4 * j, hint[(d, n)])
                struct.pack_into("<I", buf, iat[d] - IDATA_RVA + 4 * j, hint[(d, n)])
                h = hint[(d, n)] - IDATA_RVA
                buf[h + 2:h + 2 + len(n)] = n.encode()
            buf[dname[d] - IDATA_RVA:dname[d] - IDATA_RVA + len(d)] = d.encode()
        return buf, (IDATA_RVA, 20 * (len(dlls) + 1))

    # ---- exports ----
    def _gen_edata(self):
        ex = sorted(self.exports)
        n = len(ex)
        funcs = EDATA_RVA + 40
        names = funcs + 4 * n
        ords = names + 4 * n
        strs = ords + 2 * n
        buf = bytearray(strs - EDATA_RVA)
        name_rvas, pos = [], strs
        for nm, _ in ex:
            name_rvas.append(pos)
            pos += len(nm) + 1
        dll_rva = pos
        pos += len(self.name) + 1
        buf += bytearray(pos - strs)
        struct.pack_into("<IIHHIIIIIII", buf, 0, 0, self.ts, 0, 0, dll_rva, 1, n, n, funcs, names, ords)
        for i, (nm, rva) in enumerate(ex):
            struct.pack_into("<I", buf, funcs - EDATA_RVA + 4 * i, rva)
            struct.pack_into("<I", buf, names - EDATA_RVA + 4 * i, name_rvas[i])
            struct.pack_into("<H", buf, ords - EDATA_RVA + 2 * i, i)
            buf[name_rvas[i] - EDATA_RVA:name_rvas[i] - EDATA_RVA + len(nm)] = nm.encode()
        buf[dll_rva - EDATA_RVA:dll_rva - EDATA_RVA + len(self.name)] = self.name.encode()
        return buf, (EDATA_RVA, len(buf))

    def _gen_reloc(self):
        pages: dict[int, list[int]] = {}
        for r in sorted(set(self.relocs)):
            pages.setdefault(r & ~0xFFF, []).append(r & 0xFFF)
        buf = bytearray()
        for page, offs in pages.items():
            ents = [(3 << 12) | o for o in offs]
            if len(ents) % 2:
                ents.append(0)
            buf += struct.pack("<II", page, 8 + 2 * len(ents)) + b"".join(struct.pack("<H", e) for e in ents)
        return buf, (RELOC_RVA, len(buf))

    # ---- arquivo ----
    def build(self) -> bytes:
        secs = {k: dict(v) for k, v in self.secs.items()}
        dirs: dict[int, tuple[int, int]] = {}
        if self.exports:
            d, dd = self._gen_edata()
            secs[".edata"] = {"rva": EDATA_RVA, "data": d, "flags": F_RDATA, "raw": True, "vsize": len(d)}
            dirs[0] = dd
        if self.imports:
            self._iat_locked = True
            d, dd = self._gen_idata()
            secs[".idata"] = {"rva": IDATA_RVA, "data": d, "flags": F_DATA, "raw": True, "vsize": len(d)}
            dirs[1] = dd
        if self.relocs:
            d, dd = self._gen_reloc()
            secs[".reloc"] = {"rva": RELOC_RVA, "data": d, "flags": F_RELOC, "raw": True, "vsize": len(d)}
            dirs[5] = dd
        order = sorted(secs.items(), key=lambda kv: kv[1]["rva"])
        hdr_end = 0x400
        raw_ptr, pos = {}, hdr_end
        for name, s in order:
            if s["raw"]:
                raw_ptr[name] = pos
                pos += (len(s["data"]) + 0x1FF) & ~0x1FF
        out = bytearray(pos)
        lfanew, optsz = 0x80, 224
        out[:2] = b"MZ"
        struct.pack_into("<I", out, 0x3C, lfanew)
        out[lfanew:lfanew + 4] = b"PE\0\0"
        chars = 0x0102 | (0x2000 if self.dll else 0)
        struct.pack_into("<HHIIIHH", out, lfanew + 4, self.machine, len(order), self.ts, 0, 0, optsz, chars)
        o = lfanew + 24
        last = order[-1][1]
        size_of_image = (last["rva"] + max(len(last["data"]), 1) + 0xFFF) & ~0xFFF
        struct.pack_into("<H", out, o, 0x10B)
        struct.pack_into("<I", out, o + 16, self.entry)
        struct.pack_into("<I", out, o + 28, self.base)
        struct.pack_into("<II", out, o + 32, 0x1000, 0x200)
        struct.pack_into("<I", out, o + 56, size_of_image)
        struct.pack_into("<I", out, o + 60, hdr_end)
        struct.pack_into("<H", out, o + 68, 2)
        struct.pack_into("<I", out, o + 92, 16)
        for idx, (rva, size) in dirs.items():
            struct.pack_into("<II", out, o + 96 + 8 * idx, rva, size)
        so = o + optsz
        for i, (name, s) in enumerate(order):
            rp = raw_ptr.get(name, 0)
            rs = ((len(s["data"]) + 0x1FF) & ~0x1FF) if s["raw"] else 0
            struct.pack_into("<8sIIIIIIHHI", out, so + 40 * i, name.encode(), s["vsize"], s["rva"], rs, rp, 0, 0, 0, 0, s["flags"])
            if s["raw"]:
                out[rp:rp + len(s["data"])] = s["data"]
        return bytes(out)


def simple_module(name="mod.dll", base=0x10000000, ts=0x3F000000, dll=True, exports=(), imports=(), code=b"\xC3", entry=0x1000):
    """Módulo mínimo: .text com `code`, .rdata e .data; exports [(nome, rva)]; imports [(dll, nome)]."""
    b = Pe32Builder(base, ts, dll, entry=entry, name=name)
    b.section(".text", 0x1000, 0x400, F_CODE)
    b.section(".rdata", 0x2000, 0x200, F_RDATA)
    b.section(".data", 0x3000, 0x200, F_DATA)
    b.put(0x1000, code)
    for n, r in exports:
        b.add_export(n, r)
    for d, n in imports:
        b.add_import(d, n)
    return b
