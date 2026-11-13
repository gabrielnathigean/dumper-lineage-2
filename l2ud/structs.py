"""Structure Discovery v2 (requer Capstone): proveniência de ponteiros + classes de objetos.

Ideia central (mudança em relação à 0.3): objetos NÃO são identificados por "função + registrador".
Cada função é analisada com um dataflow sobre o CFG; cada registrador carrega uma ORIGEM:

    Ptr(obj, off)        "este registrador aponta para `obj` + off"
    obj ::= ('arg', fn, i)          argumento i da função fn (reg: rcx/rdx/r8/r9; x86: ecx/edx; pilha: 10+k)
          | ('glob', rva)           objeto estático em um endereço global (lea reg,[rip+G])
          | ('ret', callee)         valor retornado por callee
          | ('deref', obj, off)     ponteiro lido do campo `off` de `obj`  (cadeia de ponteiros)
          | ('elem', obj, off)      ponteiro lido de um elemento de array em obj+off

Assim o MESMO objeto acessado por registradores diferentes cai na mesma classe, e o mesmo registrador
reutilizado para objetos diferentes vira origens diferentes. Classes só são FUNDIDAS por evidência concreta:
  • mesma origem global/retorno/cadeia de ponteiros (igualdade estrutural);
  • ponteiro passado como argumento a outra função (call-site);
  • ponteiro gravado em um campo (store).
Duas classes com offsets parecidos NÃO são fundidas (no máximo ganham uma relação informativa `similar_layout`).
Fusões são recusadas quando há conflito de tipos no mesmo offset ou quando a função é um "hub" (muitos objetos
distintos passados ao mesmo argumento).

0.4.1: nenhuma fusão ignora a checagem de conflito (a congruência é antecipada); 'pointer' exige uso como base
(só passado como argumento/gravado = 'pointer_candidate'); argumentos x86 em ecx/edx são HIPÓTESES e rebaixam a
confiança; ESP/pilha x86 são rastreados (argumentos em [esp+4]/[ebp+8]); se o dataflow não convergir, os
resultados derivados ficam com confiança baixa e `dataflow_incomplete`.

Todo resultado é CANDIDATE com confiança no máximo "medium". Nada aqui identifica o SIGNIFICADO de uma
estrutura (Player, NPC…): rótulos só existem como DICA se o usuário fornecer strings (hints), marcada
"NÃO verificado".
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import disasm
from .analysis import Context, find_strings, xrefs_to

ARG_REGS_X64 = ("rcx", "rdx", "r8", "r9")
ARG_REGS_X86 = ("rcx", "rdx")                 # ecx/edx: HIPÓTESE (thiscall/fastcall), nunca um fato — ver assume_x86_reg_args
VOLATILE_X64 = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
VOLATILE_X86 = {"rax", "rcx", "rdx"}
_SS = ("movss", "addss", "subss", "mulss", "divss", "comiss", "ucomiss", "cvtss2sd", "sqrtss", "maxss", "minss")
_SD = ("movsd", "addsd", "subsd", "mulsd", "divsd", "comisd", "ucomisd", "cvtsd2ss", "sqrtsd")
MAX_DISP = 0x10000
MAX_FIELDS = 4096
MAX_STACK_ARGS = 8
DATAFLOW_ITER_FACTOR = 64          # teto de iterações = fator × nº de blocos + BASE (o reticulado é finito: normalmente converge antes)
DATAFLOW_ITER_BASE = 64
FP = ("FP",)                       # obj marcador de endereços de pilha (x86: ebp/esp); `off` = endereço relativo à entrada
_UNK = ("unk",)                    # slot de pilha cujo conteúdo é conhecido-não-ponteiro/desconhecido

LIMITATIONS = ("Inferência estática por dataflow simples: não segue chamadas indiretas, vtables, ponteiros "
               "guardados fora da pilha/registradores nem aliasing por memória. Não identifica o significado da estrutura. "
               "Argumentos x86 em ecx/edx são HIPÓTESES (convenção não provada).")


# ------------------------------------------------------------------ coleta por função
@dataclass
class Access:
    obj: tuple
    off: int                  # offset com sinal em relação ao início de `obj`
    size: int
    rw: str                   # 'r' | 'w' | 'rw' | 'lea'
    hint: str                 # '' | 'float32' | 'float64' | 'call'
    indexed: bool
    scale: int
    fn: int
    rva: int


@dataclass
class CallSite:
    rva: int
    callee: int | None
    args: dict[int, tuple]    # índice de argumento (0..3 registrador; 10+k pilha) -> (obj, off)
    fn: int


@dataclass
class Store:
    dst_obj: tuple
    dst_off: int
    src: tuple                # (obj, off) do ponteiro gravado
    fn: int


class _Collector:
    def __init__(self) -> None:
        self.accesses: list[Access] = []
        self.calls: list[CallSite] = []
        self.stores: list[Store] = []
        self.nonconverged: dict[int, list[int]] = {}      # função -> blocos ainda pendentes quando o teto foi atingido
        self.convention: dict[int, dict] = {}             # função -> evidências de convenção de chamada (x86)


def _meet(a: dict, b: dict) -> dict:
    """Interseção de estados: só sobrevive o que é IGUAL nos dois caminhos."""
    out: dict = {}
    for k, v in a.items():
        w = b.get(k)
        if k == "_stk":
            w = w or {}
            out[k] = {o: x for o, x in v.items() if w.get(o) == x}
        elif k == "_sp":
            out[k] = v if w == v else None
        elif w == v:
            out[k] = v
    return out


class _FnAnalyzer:
    """Dataflow de ponteiros de UMA função sobre o seu CFG (ver docstring do módulo)."""

    def __init__(self, d: disasm.Disassembler, fn_start: int, ctx: Context | None = None,
                 assume_x86_reg_args: bool = True):
        self.d, self.fn, self.ctx = d, fn_start, ctx
        self.relocs = ctx.reloc_locs if ctx is not None else set()
        self.is64 = d.img.is64
        self.track_sp = not self.is64                       # rastreio de ESP/pilha só em x86
        self.pb, self.ps = d.ptr_bits, d.ptr_size
        self.assume_reg_args = assume_x86_reg_args
        self.argregs = ARG_REGS_X64 if self.is64 else (ARG_REGS_X86 if assume_x86_reg_args else ())
        self.volatile = VOLATILE_X64 if self.is64 else VOLATILE_X86
        self.entry_regs_used: set[str] = set()
        self.stack_args: set[int] = set()
        self._retcache: dict = {}

    # ---- estado inicial ----
    def entry_state(self) -> dict:
        st: dict = {r: (("arg", self.fn, i), 0) for i, r in enumerate(self.argregs)}
        if self.track_sp:
            st["_sp"] = 0                                    # endereço relativo à entrada: [esp+0] = endereço de retorno
            st["_stk"] = {}
        return st

    def _simm(self, v: int) -> int:
        return v - (1 << self.pb) if v >= (1 << (self.pb - 1)) else v

    def _val(self, st: dict, op) -> tuple | None:
        if op.kind == "reg" and op.bits == self.pb:
            return st.get(op.reg)
        return None

    def _imm_glob(self, ins, op) -> tuple | None:
        """x86: `mov reg, offset G` / `push offset G`. Um imediato que é VA da imagem (e, se a imagem tem relocações,
        está relocado) é o ENDEREÇO de G (objeto estático), não um valor lido do slot."""
        if self.is64 or op.kind != "imm":
            return None
        r = op.imm - self.d.img.image_base
        if r < 0 or self.d.img.section_for_rva(r) is None:
            return None
        if self.relocs and (ins.imm_offset == 0 or (ins.rva + ins.imm_offset) not in self.relocs):
            return None
        return (("glob", r), 0)

    @staticmethod
    def _stk_set(st: dict, slot: int, v: tuple | None) -> None:
        stk = dict(st.get("_stk", {}))                       # copia: estados compartilham o dict por referência
        stk[slot] = v if v is not None else _UNK
        st["_stk"] = stk

    def _stack_load(self, st: dict, a: int) -> tuple | None:
        stk = st.get("_stk", {})
        if a in stk:
            return None if stk[a] == _UNK else stk[a]
        if a >= 4 and (a - 4) % 4 == 0:                      # acima do endereço de retorno: argumento de pilha
            idx = (a - 4) // 4
            self.stack_args.add(idx)
            return (("arg", self.fn, 10 + idx), 0)
        return None

    def _ret_imm(self, callee: int) -> int | None:
        """Bytes que o callee remove da pilha (`ret N`); 0 se `ret` simples; None se o callee não é analisável."""
        if callee in self._retcache:
            return self._retcache[callee]
        n = None
        if self.ctx is not None:
            cfg = self.ctx.cfg(callee)
            if cfg is not None:
                for b in cfg.blocks.values():
                    last = b.insns[-1]
                    if last.kind == "ret":
                        n = last.ops[0].imm if last.ops and last.ops[0].kind == "imm" else 0
                        break
        self._retcache[callee] = n
        return n

    def _note_entry_use(self, st: dict, ins) -> None:
        for r in ins.regs_read:
            if r in self.argregs and st.get(r) == (("arg", self.fn, self.argregs.index(r)), 0):
                self.entry_regs_used.add(r)

    def _record_mem(self, rec, st, ins, op, kind_hint: str = "") -> tuple | None:
        """Registra acesso [base+disp] se a base for um ponteiro conhecido. Retorna (obj, off_efetivo) ou None."""
        m = op.mem
        if m is None or m.segment:
            return None
        if m.rip_target is not None:
            base = (("glob", m.rip_target), 0)
            disp = 0
        elif m.abs_va is not None and not m.base and not m.index:       # x86: acesso por endereço ABSOLUTO a um global
            r = m.abs_va - self.d.img.image_base
            if r < 0 or self.d.img.section_for_rva(r) is None:
                return None
            if self.relocs and (ins.disp_offset == 0 or (ins.rva + ins.disp_offset) not in self.relocs):
                return None                                               # constante, não endereço relocável
            base = (("glob", r), 0)
            disp = 0
        elif m.base:
            if m.base == "rsp" and self.track_sp:
                sp = st.get("_sp")
                base = (FP, sp) if sp is not None else None
            else:
                base = st.get(m.base)
            disp = m.disp
        else:
            return None
        if base is None:
            return None
        obj, off = base
        if obj == FP:
            return (obj, off + disp)          # endereços de pilha: não viram campos
        eff = off + disp
        if not (-MAX_DISP <= eff < MAX_DISP):
            return None
        if rec is not None:
            hint = kind_hint
            if not hint:
                if ins.mnemonic in _SS:
                    hint = "float32"
                elif ins.mnemonic in _SD and any(o.kind == "reg" and o.bits == 0 for o in ins.ops):
                    hint = "float64"
            if ins.mnemonic == "lea":
                rw = "lea"
            else:
                a = op.access
                rw = "rw" if a & 3 == 3 else "w" if a & 2 else "r"
            rec.accesses.append(Access(obj, eff, op.size, rw, hint, bool(m.index), m.scale, self.fn, ins.rva))
        return (obj, eff)

    # ---- transferência de uma instrução ----
    def step(self, st: dict, ins, rec) -> None:
        mn = ins.mnemonic
        if rec is not None:
            self._note_entry_use(st, ins)
        effs = []
        for o in (o for o in ins.ops if o.kind == "mem"):
            hint = "call" if ins.kind in ("call", "jmp", "jcc") else ""
            effs.append(self._record_mem(rec, st, ins, o, hint))
        written = list(ins.regs_written)

        def clear(regs) -> None:
            for r in regs:
                st.pop(r, None)

        sp = st.get("_sp") if self.track_sp else None
        # ---- pilha x86: ESP relativo à entrada, slots, frame pointer ----
        if self.track_sp:
            if mn == "push" and ins.ops:
                if sp is not None:
                    sp -= 4
                    st["_sp"] = sp
                    op0 = ins.ops[0]
                    self._stk_set(st, sp, self._val(st, op0) if op0.kind == "reg" else self._imm_glob(ins, op0))
                return
            if mn == "pop" and ins.ops and ins.ops[0].kind == "reg":
                dst = ins.ops[0]
                v = st.get("_stk", {}).get(sp) if sp is not None else None
                st["_sp"] = None if sp is None else sp + 4
                clear([dst.reg])
                if v is not None and v != _UNK and dst.bits == self.pb:
                    st[dst.reg] = v
                return
            if mn in ("add", "sub") and len(ins.ops) == 2 and ins.ops[0].kind == "reg" and ins.ops[0].reg == "rsp":
                if ins.ops[1].kind == "imm" and sp is not None:
                    imm = self._simm(ins.ops[1].imm)
                    st["_sp"] = sp + (imm if mn == "add" else -imm)
                else:
                    st["_sp"] = None
                return
            if mn == "leave":
                fp = st.get("rbp")
                st["_sp"] = fp[1] + 4 if fp and fp[0] == FP else None
                clear(["rbp"])
                return
            if mn == "mov" and len(ins.ops) == 2 and ins.ops[0].kind == "reg" and ins.ops[1].kind == "reg":
                d_, s_ = ins.ops
                if d_.reg == "rsp" and s_.reg == "rbp":
                    fp = st.get("rbp")
                    st["_sp"] = fp[1] if fp and fp[0] == FP else None
                    return
                if d_.reg == "rbp" and s_.reg == "rsp":
                    clear(["rbp"])
                    if sp is not None:
                        st["rbp"] = (FP, sp)
                    return
            if "rsp" in written and ins.kind not in ("call", "ret"):
                st["_sp"] = None                              # qualquer outra escrita em ESP: rastreio perdido

        # ---- casos que produzem origem ----
        if mn in ("mov", "movabs") and len(ins.ops) == 2:
            dst, src = ins.ops
            if dst.kind == "reg" and dst.bits == self.pb:
                clear([dst.reg])
                if src.kind == "reg":
                    v = self._val(st, src) if src.reg != dst.reg else st.get(dst.reg)
                    if src.reg == "rsp" and dst.reg == "rbp" and self.is64:
                        st["rbp"] = (FP, 0)
                    elif v is not None:
                        st[dst.reg] = v
                elif src.kind == "imm":
                    g = self._imm_glob(ins, src)
                    if g is not None:
                        st[dst.reg] = g
                elif src.kind == "mem" and src.size == self.ps:
                    eff = effs[0] if effs else None
                    if eff is not None and eff[0] == FP:
                        if self.track_sp:
                            v = self._stack_load(st, eff[1])
                            if v is not None:
                                st[dst.reg] = v
                    elif eff is not None:
                        kind = "elem" if src.mem.index else "deref"
                        st[dst.reg] = ((kind, eff[0], eff[1]), 0)
                return
            if dst.kind == "mem":
                eff = effs[0] if effs else None
                if eff is not None and eff[0] == FP:
                    if self.track_sp:
                        self._stk_set(st, eff[1], self._val(st, src) if src.kind == "reg" and dst.size == self.ps else None)
                elif rec is not None and eff is not None and src.kind == "reg":
                    v = self._val(st, src)
                    if v is not None and src.size == self.ps:
                        rec.stores.append(Store(eff[0], eff[1], v, self.fn))
                return
        if mn == "lea" and len(ins.ops) == 2 and ins.ops[0].kind == "reg":
            dst, src = ins.ops
            clear([dst.reg])
            if dst.bits == self.pb:
                m = src.mem
                eff = effs[0] if effs else None
                if m.rip_target is not None:
                    st[dst.reg] = (("glob", m.rip_target), 0)
                elif eff is not None and eff[0] != FP:
                    st[dst.reg] = (eff[0], eff[1]) if not m.index else (("elem", eff[0], eff[1]), 0)
            return
        if mn in ("add", "sub") and len(ins.ops) == 2 and ins.ops[0].kind == "reg" and ins.ops[1].kind == "imm":
            r = ins.ops[0]
            v = self._val(st, r)
            clear(written)
            if v is not None and v[0] != FP:
                imm = self._simm(ins.ops[1].imm)
                st[r.reg] = (v[0], v[1] + (imm if mn == "add" else -imm))
            return
        if ins.kind == "call":
            args: dict[int, tuple] = {}
            for i, r in enumerate(self.argregs):
                if st.get(r) is not None:
                    args[i] = st[r]
            if self.track_sp and sp is not None:              # argumentos de pilha: slots a partir do topo, não "últimos push"
                stk = st.get("_stk", {})
                for k in range(MAX_STACK_ARGS):
                    v = stk.get(sp + 4 * k)
                    if v is not None and v != _UNK:
                        args[10 + k] = v
            if rec is not None:
                rec.calls.append(CallSite(ins.rva, ins.target, args, self.fn))
            clear(self.volatile)
            if self.track_sp:
                if ins.target is None or sp is None:
                    st["_sp"] = None
                else:
                    n = self._ret_imm(ins.target)
                    st["_sp"] = None if n is None else sp + n   # callee desconhecido: perde o rastreio (honesto)
            if ins.target is not None:
                st["rax"] = (("ret", ins.target), 0)
            return
        # ---- padrão: toda escrita em registrador destrói a origem ----
        clear(written)

    # ---- dataflow sobre o CFG ----
    def run(self, cfg, rec: _Collector) -> bool:
        """Itera até o ponto fixo. Retorna False (e registra os blocos pendentes) se o teto de iterações for atingido."""
        if not cfg.blocks:
            return True
        ins_state: dict[int, dict] = {cfg.entry: self.entry_state()}
        work = [cfg.entry]
        iters, cap = 0, max(1, DATAFLOW_ITER_FACTOR * len(cfg.blocks) + DATAFLOW_ITER_BASE)
        while work and iters < cap:
            iters += 1
            b = cfg.blocks[work.pop()]
            st = dict(ins_state[b.start])
            for ins in b.insns:
                self.step(st, ins, None)
            for t, _ in b.succs:
                if t not in ins_state:
                    ins_state[t] = dict(st)
                    work.append(t)
                else:
                    new = _meet(ins_state[t], st)
                    if new != ins_state[t]:
                        ins_state[t] = new
                        work.append(t)
        converged = not work
        if not converged:
            rec.nonconverged[self.fn] = sorted(set(work))
        for b in cfg.blocks.values():
            st = dict(ins_state.get(b.start, {}))
            for ins in b.insns:
                self.step(st, ins, rec)
        if not self.is64:
            rec.convention[self.fn] = {"assumed_reg_args": self.assume_reg_args,
                                       "entry_regs_read_before_write": sorted(self.entry_regs_used),
                                       "stack_args_used": sorted(self.stack_args)}
        return converged


# ------------------------------------------------------------------ agregação
@dataclass
class FieldAcc:
    offset: int
    sizes: set[int] = field(default_factory=set)
    reads: int = 0
    writes: int = 0
    hints: set[str] = field(default_factory=set)       # float32 float64 call array embedded
    functions: set[int] = field(default_factory=set)
    scales: set[int] = field(default_factory=set)


class _Class:
    def __init__(self) -> None:
        self.fields: dict[int, FieldAcc] = {}
        self.keys: set[tuple] = set()
        self.funcs: set[int] = set()
        self.reasons: list[str] = []
        self.accesses = 0

    def add(self, a: Access) -> None:
        f = self.fields.setdefault(a.off, FieldAcc(a.off))
        f.functions.add(a.fn)
        self.funcs.add(a.fn)
        self.accesses += 1
        if a.rw == "lea":
            f.hints.add("embedded")
            return
        if a.size:
            f.sizes.add(a.size)
        if "r" in a.rw:
            f.reads += 1
        if "w" in a.rw:
            f.writes += 1
        if a.hint:
            f.hints.add(a.hint)
        if a.indexed:
            f.hints.add("array")
            f.scales.add(a.scale)


class _UF:
    def __init__(self) -> None:
        self.p: dict = {}

    def find(self, x):
        self.p.setdefault(x, x)
        r = x
        while self.p[r] != r:
            r = self.p[r]
        while self.p[x] != r:
            self.p[x], x = r, self.p[x]
        return r


def _root_key(k: tuple) -> tuple:
    while k[0] in ("deref", "elem"):
        k = k[1]
    return k


def describe_key(k: tuple, is64: bool = True) -> str:
    if k[0] == "arg":
        i = k[2]
        if i >= 10:
            return f"argumento de pilha #{i - 10} da função {k[1]:#x}"
        if not is64:
            return (f"registrador {'ecx' if i == 0 else 'edx'} na entrada da função {k[1]:#x} "
                    "(HIPÓTESE thiscall/fastcall, convenção não provada)")
        return f"argumento {i} da função {k[1]:#x}"
    if k[0] == "glob":
        return f"objeto estático no global {k[1]:#x}"
    if k[0] == "ret":
        return f"valor retornado por {k[1]:#x}"
    if k[0] == "deref" and k[1][0] == "glob" and k[2] == 0:
        return f"objeto apontado pelo valor guardado no slot global {k[1][1]:#x}"
    if k[0] == "deref":
        return f"objeto apontado pelo campo {k[2]:+#x} de [{describe_key(k[1], is64)}]"
    if k[0] == "elem":
        return f"elemento de array em {k[2]:+#x} de [{describe_key(k[1], is64)}]"
    return str(k)


@dataclass
class StructCandidate:
    id: int
    fields: list[dict]
    size_estimate: int
    functions: list[int]
    hints: list[str] = field(default_factory=list)
    confidence: str = "low"
    status: str = "CANDIDATE"
    roots: list[str] = field(default_factory=list)
    relations: list[dict] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    interest: int = 0
    notes: str = LIMITATIONS
    pointer_slots: list = field(default_factory=list)      # RVAs de slots globais cujo VALOR aponta para este objeto
    static_objects: list = field(default_factory=list)     # RVAs de globais que SÃO este objeto (estático)

    def to_dict(self) -> dict:
        return {"id": self.id, "status": self.status, "confidence": self.confidence, "interest": self.interest,
                "pointer_slots": [f"{x:#x}" for x in self.pointer_slots],
                "static_objects": [f"{x:#x}" for x in self.static_objects],
                "size_estimate_min": self.size_estimate, "fields": self.fields,
                "functions": [f"{x:#x}" for x in self.functions], "hints": self.hints, "roots": self.roots,
                "relations": self.relations, "evidence": self.evidence, "notes": self.notes}

    @staticmethod
    def from_dict(d: dict) -> "StructCandidate":
        return StructCandidate(d["id"], d["fields"], d["size_estimate_min"],
                               [int(x, 16) for x in d.get("functions", [])], d.get("hints", []),
                               d.get("confidence", "low"), d.get("status", "CANDIDATE"), d.get("roots", []),
                               d.get("relations", []), d.get("evidence", {}), d.get("interest", 0),
                               d.get("notes", LIMITATIONS), [int(x, 16) for x in d.get("pointer_slots", [])],
                               [int(x, 16) for x in d.get("static_objects", [])])

    def render_text(self, max_fields: int = 40) -> str:
        e = self.evidence
        out = [f"#{self.id} {self.status} confiança={self.confidence} interesse={self.interest}/100 "
               f"tamanho≥{self.size_estimate:#x} campos={len(self.fields)} funções={len(self.functions)}"]
        out += [f"   origem: {r}" for r in self.roots[:4]]
        out += [f"   {h}" for h in self.hints]
        for f in self.fields[:max_fields]:
            out.append(f"   {f['offset']:>8} {f['type_guess']:<24} r={f['reads']} w={f['writes']} fn={f['functions']}")
        for r in self.relations[:12]:
            out.append(f"   relação: {r['kind']} {r.get('detail', '')}")
        if e.get("merge_reasons"):
            out.append(f"   fusões: {'; '.join(e['merge_reasons'][:3])}")
        if e.get("refused_merges"):
            out.append(f"   FUSÕES RECUSADAS: {'; '.join(e['refused_merges'][:2])}")
        if e.get("assumptions"):
            out.append(f"   HIPÓTESES: {'; '.join(e['assumptions'][:2])}")
        if e.get("dataflow_incomplete"):
            out.append(f"   DATAFLOW INCOMPLETO em: {', '.join(e['dataflow_incomplete'][:4])}")
        if e.get("conflicts"):
            out.append(f"   RESSALVAS: {'; '.join(e['conflicts'][:3])}")
        return "\n".join(out)


def _ftype(f: FieldAcc, strong_ptr: bool, weak_ptr: bool, ptr: int) -> str:
    """'pointer' só com USO COMO BASE (o valor lido foi usado para acessar memória); ser apenas passado como
    argumento/gravado em campo dá 'pointer_candidate' (pode ser um inteiro do tamanho de um ponteiro)."""
    if strong_ptr:
        return "pointer"
    if "float64" in f.hints:
        return "float64"
    if "float32" in f.hints:
        return "float32"
    if weak_ptr:
        return "pointer_candidate"
    if "call" in f.hints:
        return "function_pointer(call)"
    if f.sizes:
        if len(f.sizes) > 1:
            return "mixed(" + "/".join(str(s) for s in sorted(f.sizes)) + ")"
        return {1: "int8", 2: "int16", 4: "int32", 8: "int64"}.get(next(iter(f.sizes)), f"bytes{next(iter(f.sizes))}")
    return "embedded_object_or_array" if "embedded" in f.hints else "unknown"


def discover(img, ctx: Context | None = None, hints: dict[str, list[str]] | None = None, min_fields: int = 4,
             max_functions: int | None = None, function: int | None = None, hub_limit: int = 6,
             assume_x86_reg_args: bool = True) -> list[StructCandidate]:
    """Descobre candidatos a estrutura. `assume_x86_reg_args=False` não trata ecx/edx como argumentos em x86."""
    if not disasm.available():
        raise disasm.DisasmUnavailable("Structure Discovery requer Capstone (pip install capstone)")
    ctx = ctx or Context(img, "capstone")
    d = ctx.disassembler
    ptr = d.ptr_size
    funcs = ctx.fmap.funcs
    if function is not None:
        f = ctx.fmap.containing(function)
        funcs = [f] if f else []
    if max_functions:
        funcs = funcs[:max_functions]

    rec = _Collector()
    for fn in funcs:
        cfg = ctx.cfg(fn)
        if cfg is not None:
            _FnAnalyzer(d, fn.start, ctx, assume_x86_reg_args).run(cfg, rec)

    # ---- classes iniciais: uma por chave de objeto ----
    uf = _UF()
    cls: dict[tuple, _Class] = {}
    deref_by_base: dict[tuple, set[int]] = {}
    all_keys: set[tuple] = set()

    def touch(k: tuple) -> None:
        if k == FP or k in cls:
            return
        c = cls[k] = _Class()
        c.keys.add(k)
        uf.find(k)
        all_keys.add(k)
        if k[0] in ("deref", "elem"):
            touch(k[1])
            if k[0] == "deref":
                deref_by_base.setdefault(k[1], set()).add(k[2])

    for a in rec.accesses:
        if a.obj != FP:
            touch(a.obj)
            cls[a.obj].add(a)
    for c in rec.calls:
        for o, _ in c.args.values():
            touch(o)
    for s in rec.stores:
        touch(s.dst_obj)
        touch(s.src[0])

    children_of: dict[tuple, dict[tuple, tuple]] = {}        # base -> {(tipo, off): chave filha}
    for kk in all_keys:
        if kk[0] in ("deref", "elem"):
            children_of.setdefault(kk[1], {})[(kk[0], kk[2])] = kk

    def ptr_offsets(c: _Class, weak: bool = False) -> set[int]:
        """Offsets-ponteiro da classe. Forte = o valor lido foi usado como BASE de acesso (a classe filha tem acessos);
        fraco = só foi passado como argumento ou gravado em campo."""
        out: set[int] = set()
        for key in c.keys:
            for off in deref_by_base.get(key, ()):
                strong = cls[uf.find(("deref", key, off))].accesses > 0
                if strong != weak:
                    out.add(off)
        return out

    def kind_at(c: _Class, off: int, pset: set[int]) -> str:
        if off in pset:
            return "ptr"
        f = c.fields.get(off)
        if f and ("float32" in f.hints or "float64" in f.hints):
            return "float"
        if f and f.sizes and max(f.sizes) < ptr:
            return "small"
        return ""

    def conflict(a: _Class, b: _Class) -> str | None:
        pa, pb = ptr_offsets(a), ptr_offsets(b)
        for off in set(a.fields) & set(b.fields):
            ka, kb = kind_at(a, off, pa), kind_at(b, off, pb)
            if {ka, kb} in ({"ptr", "float"}, {"ptr", "small"}):
                return f"offset {off:+#x} é ponteiro num objeto e escalar ({'float' if 'float' in (ka, kb) else 'int pequeno'}) no outro"
        if len(set(a.fields) | set(b.fields)) > MAX_FIELDS:
            return "união excede limite de campos"
        return None

    def child_map(c: _Class) -> dict[tuple, set[tuple]]:
        out: dict[tuple, set[tuple]] = {}
        for key in c.keys:
            for kk, child in children_of.get(key, {}).items():
                out.setdefault(kk, set()).add(child)
        return out

    def implied_conflict(ra: tuple, rb: tuple, seen: set) -> str | None:
        """Conflito da fusão ra≡rb OU de qualquer fusão que a congruência IMPLICA nos campos-ponteiro filhos."""
        if ra == rb or (ra, rb) in seen or (rb, ra) in seen:
            return None
        seen.add((ra, rb))
        why = conflict(cls[ra], cls[rb])
        if why:
            return why
        ca, cb = child_map(cls[ra]), child_map(cls[rb])
        for kk in ca.keys() & cb.keys():
            for x in ca[kk]:
                for y in cb[kk]:
                    rx, ry = uf.find(x), uf.find(y)
                    if rx != ry:
                        why = implied_conflict(rx, ry, seen)
                        if why:
                            return f"{why} (implicado pelo campo {kk[1]:+#x} dos dois objetos)"
        return None

    refused: list[tuple] = []

    def merge(ka: tuple, kb: tuple, reason: str) -> bool:
        """Funde as classes de ka e kb. NENHUMA fusão ignora a checagem de conflito, inclusive as implicadas por congruência."""
        ra, rb = uf.find(ka), uf.find(kb)
        if ra == rb:
            return False
        why = implied_conflict(ra, rb, set())
        if why:
            refused.append((ka, kb, f"fusão recusada ({reason}): {why}"))
            return False
        a, b = cls[ra], cls[rb]
        uf.p[rb] = ra
        for off, f in b.fields.items():
            m = a.fields.setdefault(off, FieldAcc(off))
            m.sizes |= f.sizes
            m.reads += f.reads
            m.writes += f.writes
            m.hints |= f.hints
            m.functions |= f.functions
            m.scales |= f.scales
        a.keys |= b.keys
        a.funcs |= b.funcs
        a.accesses += b.accesses
        a.reasons += b.reasons + [reason]
        del cls[rb]
        return True

    callee_args: dict[tuple, set[tuple]] = {}
    for c in rec.calls:
        if c.callee is None:
            continue
        for i, (o, off) in c.args.items():
            if off == 0:
                callee_args.setdefault((c.callee, i), set()).add(o)

    relations: list[tuple[tuple, int, str, str]] = []     # (obj origem, off, kind, detalhe)
    for _ in range(6):
        changed = False
        for c in rec.calls:
            if c.callee is None:
                continue
            for i, (o, off) in c.args.items():
                callee_key = ("arg", c.callee, i)
                if callee_key not in cls:
                    continue
                if off != 0:
                    relations.append((o, off, "embedded_subobject",
                                      f"ponteiro interior (+{off:#x}) passado a {c.callee:#x} arg{i}"))
                    continue
                if len(callee_args.get((c.callee, i), ())) > hub_limit:
                    relations.append((o, 0, "passed_to_hub", f"{c.callee:#x} arg{i} recebe >{hub_limit} objetos distintos"))
                    continue
                changed |= merge(o, callee_key, f"passado de {c.fn:#x} para {c.callee:#x} (arg{i})")
        for s in rec.stores:
            dk = ("deref", s.dst_obj, s.dst_off)
            if s.src[1] == 0 and dk in cls:
                changed |= merge(dk, s.src[0], f"ponteiro gravado em campo {s.dst_off:+#x} por {s.fn:#x}")
        # congruência: se A≡B então deref(A,f)≡deref(B,f) — também CHECADA (já foi antecipada em implied_conflict)
        groups: dict[tuple, list[tuple]] = {}
        for k in all_keys:
            if k[0] in ("deref", "elem"):
                groups.setdefault((k[0], uf.find(k[1]), k[2]), []).append(k)
        for g in groups.values():
            for k2 in g[1:]:
                changed |= merge(g[0], k2, "congruência (mesmo campo de objetos unificados)")
        if not changed:
            break

    # ---- classes finais ----
    final: dict[tuple, _Class] = {}
    for k in list(cls):
        if uf.find(k) == k:
            final[k] = cls[k]
    keyroot = {k: uf.find(k) for k in all_keys}
    ranked = sorted(((k, c) for k, c in final.items() if len(c.fields) >= min_fields),
                    key=lambda kc: (-len(kc[1].funcs), -len(kc[1].fields)))
    ids = {k: i for i, (k, _) in enumerate(ranked, 1)}
    hint_fns = _hint_functions(img, ctx, hints) if hints else {}
    children: dict[tuple, list[tuple]] = {}          # (obj base, off) -> chaves deref filhas
    for kk in all_keys:
        if kk[0] == "deref":
            children.setdefault((kk[1], kk[2]), []).append(kk)

    out: list[StructCandidate] = []
    for k, c in ranked:
        pset, wset = ptr_offsets(c), ptr_offsets(c, weak=True)
        fl = []
        for off in sorted(c.fields):
            f = c.fields[off]
            tg = _ftype(f, off in pset, off in wset, ptr)
            extra = []
            if "array" in f.hints:
                extra.append("array(stride " + "/".join(str(s) for s in sorted(f.scales)) + ")")
            if "embedded" in f.hints:
                extra.append("endereço tomado (subobjeto/array embutido)")
            fl.append({"offset": f"{off:+#x}" if off < 0 else f"{off:#x}", "offset_int": off, "type_guess": tg,
                       "pointer_evidence": "base_use" if off in pset else ("argument_or_store" if off in wset else ""),
                       "sizes": sorted(f.sizes), "reads": f.reads, "writes": f.writes,
                       "functions": len(f.functions), "notes": "; ".join(extra)})
        lo = min(c.fields)
        hi = max(o + (max(f.sizes) if f.sizes else 1) for o, f in c.fields.items())
        size = hi - min(lo, 0)
        rel: list[dict] = []
        seen_rel = set()
        for key in c.keys:                                   # ponteiros FORTES para outras classes
            for off in sorted(deref_by_base.get(key, ())):
                for child in children.get((key, off), []):
                    rc = keyroot.get(child)
                    if rc in ids and rc != k and off in pset and (off, rc) not in seen_rel:
                        seen_rel.add((off, rc))
                        rel.append({"kind": "pointer_field", "offset": off, "target": ids[rc],
                                    "detail": f"{off:+#x} -> #{ids[rc]}"})
        seen_det = set()
        for (o, off, kind, det) in relations:
            if keyroot.get(o) == k and (kind, det) not in seen_det:   # o mesmo ponteiro interior aparece em várias rodadas
                seen_det.add((kind, det))
                rel.append({"kind": kind, "offset": off, "detail": det})
        for off in sorted(pset):                             # coleções: dois ponteiros adjacentes + acesso indexado no apontado
            if off + ptr in pset:
                kids = [kk for key in c.keys for kk in children.get((key, off), [])]
                if any("array" in fa.hints for kk in kids for fa in cls.get(keyroot.get(kk), _Class()).fields.values()):
                    rel.append({"kind": "collection_hint", "offset": off,
                                "detail": f"ponteiros adjacentes em {off:+#x}/{off + ptr:+#x} e acesso indexado ao apontado: "
                                          "possível coleção (início/fim/capacidade) — hipótese fraca"})
        if sum(1 for f in c.fields.values() if "call" in f.hints) >= max(2, len(c.fields) // 2):
            rel.append({"kind": "vtable_like", "detail": "maioria dos campos é alvo de call/jmp indireto: possível tabela de funções"})
        conflicts = []
        kinds_bad = [f"offset {f['offset']}: {f['type_guess']}" for f in fl if f["type_guess"].startswith("mixed")]
        if kinds_bad:
            conflicts.append("tamanhos de acesso mistos em " + ", ".join(kinds_bad[:4]))
        if lo < 0:
            conflicts.append("campos em offsets NEGATIVOS: ponteiro interior (subobjeto/classe base) — "
                             "o início real do objeto é desconhecido")
        assumptions: list[str] = []
        if not img.is64:
            for key in c.keys:
                r = _root_key(key)
                if r[0] == "arg" and r[2] < 10:
                    assumptions.append(f"x86: {'ecx' if r[2] == 0 else 'edx'} assumido como argumento {r[2]} de {r[1]:#x} "
                                       "(thiscall/fastcall) — convenção NÃO provada")
        assumptions = list(dict.fromkeys(assumptions))
        incomplete = [f"{fn:#x}" for fn in sorted(c.funcs) if fn in rec.nonconverged]
        score = (min(len(c.funcs), 6) * 2 + min(len(c.fields), 12) + (3 if any(x[0] == "glob" for x in c.keys) else 0)
                 + min(len(c.reasons), 3))
        conf = "medium" if score >= 16 and not [x for x in conflicts if "mixed" in x] \
            and not assumptions and not incomplete else "low"
        interest = max(0, min(100, score * 4 - 8 * len(conflicts) - 10 * bool(assumptions) - 15 * bool(incomplete)))
        conv = {f"{fn:#x}": rec.convention[fn] for fn in sorted(c.funcs) if fn in rec.convention}
        ev = {"accesses": c.accesses, "reads": sum(f.reads for f in c.fields.values()),
              "writes": sum(f.writes for f in c.fields.values()), "functions": len(c.funcs),
              "merge_reasons": list(dict.fromkeys(c.reasons))[:20],
              "refused_merges": [t for a_, b_, t in refused if k in (keyroot.get(a_), keyroot.get(b_))][:10],
              "conflicts": conflicts, "keys": len(c.keys), "assumptions": assumptions,
              "dataflow_incomplete": incomplete, "pointer_strong": sorted(pset), "pointer_weak": sorted(wset),
              "x86_conventions": dict(list(conv.items())[:8])}
        roots = [describe_key(x, img.is64) for x in sorted(c.keys, key=lambda x: (len(str(x)), str(x)))[:6]]
        sc = StructCandidate(ids[k], fl, size, sorted(c.funcs), confidence=conf, roots=roots,
                             relations=rel, evidence=ev, interest=interest)
        sc.pointer_slots = sorted({x[1][1] for x in c.keys if x[0] == "deref" and x[1][0] == "glob" and x[2] == 0})
        sc.static_objects = sorted({x[1] for x in c.keys if x[0] == "glob"})
        for cat, hf in hint_fns.items():
            common = c.funcs & set(hf)
            if common:
                s = sorted(common)[0]
                sc.hints.append(f"hint:{cat} (NÃO verificado): função {s:#x} usa a estrutura e referencia {hf[s]!r}; "
                                f"{len(common)} função(ões) em comum")
        out.append(sc)

    # similaridade de layout: informativa, NUNCA funde
    for i, a in enumerate(out[:200]):
        for b in out[i + 1:200]:
            sa = {f["offset_int"] for f in a.fields}
            sb = {f["offset_int"] for f in b.fields}
            j = len(sa & sb) / len(sa | sb)
            if j >= 0.75:
                for x, y in ((a, b), (b, a)):
                    x.relations.append({"kind": "similar_layout", "target": y.id,
                                        "detail": f"layout {j:.0%} parecido com #{y.id} (NÃO fundidas: sem fluxo de dados em comum)"})
    return out


def _hint_functions(img, ctx: Context, hints: dict[str, list[str]]) -> dict[str, dict[int, str]]:
    res: dict[str, dict[int, str]] = {}
    for cat, texts in hints.items():
        m: dict[int, str] = {}
        for t in texts:
            for fs in find_strings(img, t, min_len=max(3, len(t))):
                for x in xrefs_to(img, fs.rva, ctx.xrefs):
                    if x.function and x.trusted:
                        m[x.function.start] = fs.text
        if m:
            res[cat] = m
    return res
