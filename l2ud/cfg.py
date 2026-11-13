"""Análise de fluxo de controle (requer Capstone): CFG, blocos básicos, descoberta de funções e xrefs.

Diferença para a varredura linear: aqui só é "código válido" o que é ALCANÇÁVEL a partir de uma entrada
(recursive descent). Bytes dentro de uma função que não são alcançados (dados, jump tables x64 não
resolvidas, padding) ficam em `ambiguous`/`padding`, nunca viram xref "confiável". A varredura linear
continua disponível como complemento (xrefs com via="linear"), marcada como menos confiável.

Limitações honestas:
- jump tables: só a forma x86 `jmp [reg*4 + tabela]` COM limite provado (`cmp reg,N; ja/jae`) vira aresta; sem o
  limite as entradas ficam só como candidatas; `jmp reg` (x64) fica "indirect_unresolved";
- chamadas indiretas não são seguidas; funções só alcançadas por ponteiro/vtable não são descobertas aqui;
- não há detecção de funções noreturn (o código depois de um `call` é tratado como alcançável).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import disasm
from .functions import Function, FunctionMap, build_function_map

MAX_INSNS = 20000          # teto por função (evita explosão em dados mal interpretados)
MAX_TABLE = 256            # teto de entradas por jump table


@dataclass
class Block:
    start: int
    end: int                                   # exclusivo
    insns: list = field(default_factory=list)
    succs: list[tuple[int, str]] = field(default_factory=list)   # (alvo, 'fall'|'jmp'|'jcc'|'table')
    terminator: str = "fall"                   # 'ret' | 'jmp' | 'jcc' | 'indirect' | 'fall' | 'invalid' | 'end'
    calls: list[int] = field(default_factory=list)
    indirect_calls: int = 0
    indirect_unresolved: bool = False


@dataclass
class ExternalEdge:
    """Desvio que sai da função (ou cai em outra função conhecida). Nunca some do relatório."""
    src: int
    dst: int
    kind: str                 # 'jmp' | 'jcc'
    cls: str                  # 'tail_transfer' | 'not_executable' | 'outside_image' | 'unmapped'
    known_function: bool = False   # o destino é o início de uma função conhecida


@dataclass
class JumpTable:
    """Tabela de saltos x86 `jmp [idx*4 + tabela]` (entradas = VA absolutos de 32 bits)."""
    jmp_rva: int
    table_rva: int
    entry_format: str                          # 'abs32_va'
    bound: str                                 # 'index_check' (cmp reg,N + ja/jae) | 'none'
    declared_count: int | None                 # nº de entradas provado pelo cmp/ja; None se sem limite
    entries: list = field(default_factory=list)     # [(índice, alvo_rva)] aceitas
    rejected: list = field(default_factory=list)    # [(índice, valor_bruto, motivo)]
    resolved: bool = False                     # True só se houver limite provado (viram arestas do CFG)

    @property
    def table_end(self) -> int:
        return self.table_rva + 4 * max(1, len(self.entries) + len(self.rejected))


@dataclass
class CFG:
    entry: int
    blocks: dict[int, Block]
    calls: set[int]                            # alvos diretos de call
    tail_calls: set[int]                       # alvos EXECUTÁVEIS de desvios que saem da função
    reachable: list[tuple[int, int]]           # faixas de código alcançado (mescladas)
    ambiguous: list[tuple[int, int, str]]      # (início, fim, 'padding'|'jump_table'|'ambiguous')
    bounds: tuple[int, int]
    truncated: bool = False
    invalid: list[int] = field(default_factory=list)
    invalid_edges: list[tuple[int, int, str]] = field(default_factory=list)   # (origem, destino, 'inside_instruction'|'overlap')
    external: list[ExternalEdge] = field(default_factory=list)
    jump_tables: list[JumpTable] = field(default_factory=list)

    @property
    def extent(self) -> tuple[int, int]:
        """Intervalo ENVOLVENTE (só para exibição). A cobertura real é `reachable`."""
        if not self.blocks:
            return self.entry, self.entry
        return min(self.blocks), max(b.end for b in self.blocks.values())

    def preds(self) -> dict[int, list[int]]:
        p: dict[int, list[int]] = {a: [] for a in self.blocks}
        for b in self.blocks.values():
            for t, _ in b.succs:
                if t in p:
                    p[t].append(b.start)
        return p

    def block_of(self, rva: int) -> Block | None:
        for b in self.blocks.values():
            if b.start <= rva < b.end:
                return b
        return None

    def instruction_count(self) -> int:
        return sum(len(b.insns) for b in self.blocks.values())

    def summary(self) -> dict:
        return {"entry": self.entry, "blocks": len(self.blocks),
                "edges": sum(len(b.succs) for b in self.blocks.values()),
                "instructions": self.instruction_count(), "calls": len(self.calls),
                "tail_calls": len(self.tail_calls), "external_edges": len(self.external),
                "invalid_edges": len(self.invalid_edges),
                "jump_tables": len(self.jump_tables),
                "jump_tables_resolved": sum(1 for j in self.jump_tables if j.resolved),
                "indirect_unresolved": sum(1 for b in self.blocks.values() if b.indirect_unresolved),
                "ambiguous_regions": sum(1 for a in self.ambiguous if a[2] != "padding"),
                "truncated": self.truncated}


_CMP_BOUND_JCC = {"ja": 1, "jae": 0, "jnb": 0, "jnbe": 1}     # nº de entradas = N + delta


def _index_bound(recent: list) -> int | None:
    """Procura, nas instruções imediatamente anteriores ao `jmp`, `cmp reg, N` seguido de `ja/jae default`.
    Retorna o nº de entradas PROVADO pelo limite do índice (N+1 para `ja`, N para `jae`); None se não houver."""
    for k in range(len(recent) - 1, 0, -1):
        j, c = recent[k], recent[k - 1]
        if j.kind == "jcc" and j.mnemonic in _CMP_BOUND_JCC and c.mnemonic == "cmp" \
                and len(c.ops) == 2 and c.ops[1].kind == "imm":
            n = c.ops[1].imm
            if 0 <= n <= MAX_TABLE:
                return n + _CMP_BOUND_JCC[j.mnemonic]
    return None


def resolve_jump_table(d: disasm.Disassembler, ins, limit, recent: list) -> JumpTable | None:
    """x86: `jmp dword ptr [idx*4 + tabela_abs]`. A tabela só vira ARESTAS do CFG quando o tamanho é PROVADO
    por `cmp reg,N; ja/jae default`. Sem esse limite o tamanho não é deduzido (parecer endereço não basta):
    as entradas candidatas ficam registradas, mas `resolved=False` e o salto continua 'indireto não resolvido'."""
    if d.img.is64 or not ins.mems:
        return None
    m = ins.mems[0]
    if m.base or not m.index or m.scale != 4 or m.segment:
        return None
    table = (m.disp & 0xFFFFFFFF) - d.img.image_base
    if table < 0 or d.img.section_for_rva(table) is None:
        return None
    declared = _index_bound(recent)
    jt = JumpTable(ins.rva, table, "abs32_va", "index_check" if declared is not None else "none", declared)
    count = min(declared, MAX_TABLE) if declared is not None else MAX_TABLE
    raw = d.read_ptr_table(table, count, 4)
    for idx, va in enumerate(raw):
        t = va - d.img.image_base
        if t < 0 or d.img.section_for_rva(t) is None:
            reason = "fora da imagem"
        elif not d.is_code(t):
            reason = "não é código executável mapeado"
        elif limit and not (limit[0] <= t < limit[1]):
            reason = "fora dos limites exatos da função"
        else:
            jt.entries.append((idx, t))
            continue
        jt.rejected.append((idx, va, reason))
        if declared is None:
            break                                   # sem limite: para na 1ª entrada que não parece alvo
    if declared is not None and len(raw) < declared:
        jt.rejected.append((len(raw), 0, "tabela termina antes do limite provado (fim dos dados)"))
    jt.resolved = declared is not None and bool(jt.entries)
    return jt


def _classify_external(d: disasm.Disassembler, t: int) -> str:
    sec = d.img.section_for_rva(t)
    if sec is None:
        return "outside_image"
    if not sec.executable:
        return "not_executable"
    return "tail_transfer" if d.is_code(t) else "unmapped"


def build_cfg(img, d: disasm.Disassembler, entry: int, limit: tuple[int, int] | None = None,
              known_starts: frozenset[int] | set[int] = frozenset(), max_insns: int = MAX_INSNS) -> CFG:
    """Recursive descent a partir de `entry`.
    limit        : (início, fim) EXATOS (.pdata) — nada fora é seguido.
    known_starts : inícios de outras funções (desvio direto para eles = transferência externa; queda neles = fim).
    Garantias: nenhuma instrução decodificada se sobrepõe a outra (um desvio para o MEIO de uma instrução já
    decodificada, ou uma instrução que invadiria bytes já decodificados, vira `invalid_edges`); todo desvio que
    sai da função é registrado em `external` com classificação."""
    insn_at: dict[int, disasm.Insn] = {}
    owner: dict[int, int] = {}                    # byte -> início da instrução que o contém
    leaders = {entry}
    tables: dict[int, list[int]] = {}
    jump_tables: list[JumpTable] = []
    unresolved: set[int] = set()
    calls: set[int] = set()
    tail: set[int] = set()
    external: list[ExternalEdge] = []
    invalid: list[int] = []
    invalid_edges: list[tuple[int, int, str]] = []
    work: list[tuple[int, int]] = [(entry, -1)]
    truncated = False

    def inside(a: int) -> bool:
        return (limit[0] <= a < limit[1]) if limit else True

    def leaves(t: int) -> bool:
        return not inside(t) or (t in known_starts and t != entry and not limit)

    def go_external(src: int, t: int, kind: str) -> None:
        cls = _classify_external(d, t)
        external.append(ExternalEdge(src, t, kind, cls, t in known_starts))
        if cls == "tail_transfer":
            tail.add(t)

    while work:
        a, src = work.pop()
        recent: list = []
        while True:
            if a in insn_at or not inside(a):
                break
            if a in owner:                                    # destino no MEIO de instrução já decodificada
                invalid_edges.append((src, a, "inside_instruction"))
                break
            if len(insn_at) >= max_insns:
                truncated = True
                break
            if a != entry and a in known_starts and not limit:
                break  # caiu no início de outra função
            ins = d.decode_one(a)
            if ins is None or not d.is_code(a):
                invalid.append(a)
                break
            if any(x in owner for x in range(a + 1, ins.end)):   # invadiria bytes já decodificados
                invalid_edges.append((src, a, "overlap"))
                break
            insn_at[a] = ins
            for x in range(a, ins.end):
                owner[x] = a
            recent = (recent + [ins])[-12:]
            nxt = ins.end
            k = ins.kind
            if k == "ret":
                break
            if k == "jmp":
                if ins.target is not None:
                    t = ins.target
                    if leaves(t):
                        go_external(a, t, "jmp")
                    else:
                        leaders.add(t)
                        work.append((t, a))
                else:
                    jt = resolve_jump_table(d, ins, limit, recent[:-1])
                    if jt is not None:
                        jump_tables.append(jt)
                    if jt is not None and jt.resolved:
                        tables[a] = [t for _, t in jt.entries]
                        for t in tables[a]:
                            leaders.add(t)
                            work.append((t, a))
                    else:
                        unresolved.add(a)
                break
            if k == "jcc":
                if ins.target is not None:
                    if leaves(ins.target):
                        go_external(a, ins.target, "jcc")
                    else:
                        leaders.add(ins.target)
                        work.append((ins.target, a))
                leaders.add(nxt)
            elif k == "call" and ins.target is not None:
                calls.add(ins.target)
            src = a
            a = nxt

    # ---- blocos ----
    blocks: dict[int, Block] = {}
    cur: Block | None = None
    prev_end = -1
    for a in sorted(insn_at):
        ins = insn_at[a]
        if cur is None or a in leaders or a != prev_end:
            cur = Block(a, a)
            blocks[a] = cur
        cur.insns.append(ins)
        cur.end = ins.end
        prev_end = ins.end
        if ins.kind == "call":
            if ins.target is not None:
                cur.calls.append(ins.target)
            else:
                cur.indirect_calls += 1
        if ins.kind in ("ret", "jmp"):
            cur = None
    for b in blocks.values():
        last = b.insns[-1]
        nxt = last.end
        if last.kind == "ret":
            b.terminator = "ret"
        elif last.kind == "jmp":
            if last.rva in tables:
                b.terminator = "indirect"
                b.succs = [(t, "table") for t in dict.fromkeys(tables[last.rva]) if t in insn_at]
            elif last.target is not None:
                b.terminator = "jmp"
                if last.target in insn_at:
                    b.succs = [(last.target, "jmp")]
            else:
                b.terminator = "indirect"
                b.indirect_unresolved = True
        elif last.kind == "jcc":
            b.terminator = "jcc"
            if last.target is not None and last.target in insn_at:
                b.succs.append((last.target, "jcc"))
            if nxt in insn_at:
                b.succs.append((nxt, "fall"))
        else:
            b.terminator = "fall"
            if nxt in insn_at:
                b.succs.append((nxt, "fall"))
            else:
                b.terminator = "invalid" if nxt in invalid else "end"

    # ---- regiões: alcançado × ambíguo ----
    reach: list[tuple[int, int]] = []
    for b in sorted(blocks.values(), key=lambda x: x.start):
        if reach and b.start <= reach[-1][1]:
            reach[-1] = (reach[-1][0], max(reach[-1][1], b.end))
        else:
            reach.append((b.start, b.end))
    ext = (min(blocks), max(b.end for b in blocks.values())) if blocks else (entry, entry)
    bounds = limit or ext
    table_ranges = [(j.table_rva, j.table_end) for j in jump_tables]
    amb: list[tuple[int, int, str]] = []
    pos = bounds[0]
    for a, b in reach + [(bounds[1], bounds[1])]:
        if a > pos:
            data = d._bytes(pos, a - pos)
            if data and all(x in (0xCC, 0x00, 0x90) for x in data):
                amb.append((pos, a, "padding"))
            else:
                # separa o padding de compilador (CC/90) nas pontas; zeros NÃO são aparados (podem ser dado)
                lo, hi = 0, len(data)
                while lo < hi and data[lo] in (0xCC, 0x90):
                    lo += 1
                while hi > lo and data[hi - 1] in (0xCC, 0x90):
                    hi -= 1
                if lo:
                    amb.append((pos, pos + lo, "padding"))
                tag = "jump_table" if any(r0 < pos + hi and r1 > pos + lo for r0, r1 in table_ranges) else "ambiguous"
                amb.append((pos + lo, pos + hi, tag))
                if hi < len(data):
                    amb.append((pos + hi, a, "padding"))
        pos = max(pos, b)
    return CFG(entry, blocks, calls, tail, reach, amb, bounds, truncated, invalid, invalid_edges, external, jump_tables)


# ---------------------------------------------------------------- função + xrefs
def build_function_map_cfg(img, d: disasm.Disassembler, seed_map: FunctionMap | None = None,
                           max_functions: int = 200000) -> tuple[FunctionMap, dict[int, CFG]]:
    """Descobre funções por alcançabilidade (recursive descent) a partir de sementes.
    - .pdata presente: mantém os limites EXATOS (source='pdata') e só constrói o CFG de cada um;
    - sem .pdata: sementes = heurística (entry/exports/prólogos/calls) + alvos de call encontrados no código
      alcançado; o fim da função é a extensão do CFG (source='cfg')."""
    seed_map = seed_map or build_function_map(img)
    cfgs: dict[int, CFG] = {}
    if img.functions:      # limites exatos: os CFGs são construídos sob demanda (Context.cfg)
        return seed_map, cfgs
    names = {f.start: f.name for f in seed_map.funcs}
    known: set[int] = {f.start for f in seed_map.funcs}
    queue = sorted(known)
    done: dict[int, CFG] = {}
    while queue and len(done) < max_functions:
        s = queue.pop(0)
        if s in done or not d.is_code(s):
            continue
        cfg = build_cfg(img, d, s, None, known)
        if not cfg.blocks:
            continue
        done[s] = cfg
        for t in cfg.calls | cfg.tail_calls:
            if t not in known and d.is_code(t):
                known.add(t)
                queue.append(t)
    funcs = []
    for s, cfg in done.items():
        a, b = cfg.extent
        funcs.append(Function(s, b, "cfg", names.get(s), tuple(cfg.reachable)))   # cobertura REAL = blocos alcançados
    return FunctionMap(funcs), done


def collect_xrefs(img, fmap: FunctionMap, cfg_of, include_linear: bool = True):
    """Xrefs por decodificação. `cfg_of(fn)` devolve o CFG da função (ou None).
    via='cfg'    : instruções ALCANÇÁVEIS (confiável);
    via='linear' : varredura linear de lacunas/regiões ambíguas (pode ser dado interpretado como código)."""
    from .analysis import Xref
    d = disasm.Disassembler(img)
    out: list[Xref] = []
    # Se a imagem tem relocações, um operando absoluto/imediato só é ENDEREÇO se houver relocação nele;
    # senão é uma constante que coincidiu com o intervalo da imagem (ex.: push 0x402000 sem reloc).
    reloc_locs = {rva for rva, typ in img.relocs if typ in (3, 10)}

    def is_address_field(ins_rva: int, off: int) -> bool:
        if not reloc_locs:
            return True                       # imagem sem relocs: não há como distinguir; aceita (comportamento 0.4.0)
        return off > 0 and (ins_rva + off) in reloc_locs

    def emit(ins, via: str) -> None:
        fn = fmap.containing(ins.rva)
        if ins.target is not None and ins.kind in ("call", "jmp"):
            t = img.section_for_rva(ins.target)
            if t is not None and t.executable:
                out.append(Xref(ins.rva, ins.kind, ins.target, fn, "capstone", via))
        for m in ins.mems:
            rw = "addr" if ins.mnemonic == "lea" else ("rw" if m.access & 3 == 3 else "w" if m.access & 2 else "r")
            if m.rip_target is not None and img.section_for_rva(m.rip_target):
                out.append(Xref(ins.rva, "rip", m.rip_target, fn, "capstone", via, rw))
            elif m.abs_va is not None:
                r = m.abs_va - img.image_base
                if r >= 0 and img.section_for_rva(r) and is_address_field(ins.rva, ins.disp_offset):
                    out.append(Xref(ins.rva, "abs", r, fn, "capstone", via, rw))
        if not img.is64:
            for v in ins.imms:
                r = v - img.image_base
                if r >= 0 and img.section_for_rva(r) and is_address_field(ins.rva, ins.imm_offset):
                    out.append(Xref(ins.rva, "imm", r, fn, "capstone", via))

    covered: list[tuple[int, int]] = []
    for f in fmap.funcs:
        cfg = cfg_of(f)
        if cfg is None:
            continue
        for b in cfg.blocks.values():
            for ins in b.insns:
                emit(ins, "cfg")
        covered.extend(cfg.reachable)
        covered.extend((a, b) for a, b, _ in cfg.ambiguous)     # já tratadas abaixo: não varrer de novo como "lacuna"
        if include_linear:
            for a, b, tag in cfg.ambiguous:
                if tag == "ambiguous":
                    for ins in d.sweep(a, b):
                        emit(ins, "linear")
    if include_linear:
        covered.sort()
        for s in img.sections:
            if not s.executable or not s.raw_size or s.discardable:
                continue
            cur, send = s.va, s.va + s.raw_size
            for a, b in covered:
                if b <= cur or a >= send:
                    continue
                if a > cur:
                    _sweep_gap(d, cur, a, emit)
                cur = max(cur, b)
            if cur < send:
                _sweep_gap(d, cur, send, emit)
    out.sort(key=lambda x: (x.from_rva, x.kind))
    return out


def _sweep_gap(d, a: int, b: int, emit) -> None:
    pad = d._bytes(a, b - a)
    if not pad or all(x in (0xCC, 0x00, 0x90) for x in pad):
        return
    for ins in d.sweep(a, b):
        emit(ins, "linear")


def to_dot(cfg: CFG) -> str:
    """Graphviz DOT do CFG (blocos com até 12 instruções; arestas rotuladas fall/jmp/jcc/table)."""
    lines = ["digraph cfg {", "  node [shape=box fontname=Consolas];"]
    for b in cfg.blocks.values():
        label = "\\l".join(f"{i.rva:#x} {i.mnemonic} {i.op_str}".replace('"', "'") for i in b.insns[:12])
        lines.append(f'  "{b.start:#x}" [label="{label}\\l"];')
        for t, k in b.succs:
            lines.append(f'  "{b.start:#x}" -> "{t:#x}" [label="{k}"];')
    lines.append("}")
    return "\n".join(lines)
