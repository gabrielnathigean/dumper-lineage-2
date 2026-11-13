"""Grafo de evidências: módulos, funções, globais, campos, ponteiros, strings, imports, vtables e coleções.

Toda descoberta tem PROVENIÊNCIA rastreável: cada `Evidence` diz de que observação veio (`origin`), de que função
(`function`), por qual via (`cfg`, `reloc`, `opcode`, `linear`…) e se é confiável. Duas evidências com a MESMA
`origin` (ex.: o mesmo operando de uma mesma instrução visto como "referência de código" e como "relocação") são UMA
observação — nunca duas confirmações independentes.

Regra de corroboração (`assess`): um nó só sobe para STATIC_CORROBORATED com
    ≥ 2 observações independentes (origens distintas)  E  ≥ 2 TIPOS de evidência distintos  E  ≥ 2 observações confiáveis.
Muitas referências do mesmo tipo (ex.: 30 `code_xref` a um endereço) NÃO corroboram a natureza do endereço.
"""
from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import asdict, dataclass, field

# famílias de tipo (documentação/diagnóstico): código x estrutura/dados
CODE_TYPES = {"code_xref", "direct_call", "struct_access", "index_access", "pointer_use", "ctor_store", "call_return_store",
              "cmp_bound", "string_ref", "import_ref", "dispatch_call", "object_base_use", "call_arg"}
STRUCTURAL_TYPES = {"reloc", "export", "pdata", "entry_point", "vtable_slot", "rtti", "static_data", "function_match",
                    "cfg_bounds"}


@dataclass
class Evidence:
    id: str
    type: str
    origin: str                      # chave da observação-fonte (ex.: 'insn:engine.dll:0x1234')
    function: str | None             # ex.: 'engine.dll:0x1230'
    trusted: bool
    via: str
    nodes: list[str]
    detail: dict = field(default_factory=dict)


@dataclass
class Node:
    id: str
    kind: str                        # module|function|global|pointer_slot|struct|field|string|import|vtable|collection|…
    label: str
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    evidence: str | None = None


class EvidenceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.evidence: dict[str, Evidence] = {}
        self._by_node: dict[str, list[str]] = {}
        self._edge_keys: set[tuple] = set()

    # ---- construção ----
    def add_node(self, id: str, kind: str, label: str = "", **attrs) -> str:
        n = self.nodes.get(id)
        if n is None:
            self.nodes[id] = Node(id, kind, label or id, dict(attrs))
        elif attrs:
            n.attrs.update(attrs)
        return id

    def add_edge(self, src: str, dst: str, kind: str, evidence: str | None = None) -> None:
        key = (src, dst, kind, evidence)
        if key not in self._edge_keys:
            self._edge_keys.add(key)
            self.edges.append(Edge(src, dst, kind, evidence))

    def add_evidence(self, type: str, origin: str, nodes: list[str], function: str | None = None, trusted: bool = True,
                     via: str = "", **detail) -> str:
        """Registra uma evidência ligada aos `nodes`. Idempotente para (tipo, origem, nós)."""
        key = f"{type}|{origin}|{'/'.join(sorted(nodes))}"
        eid = "ev-" + hashlib.sha1(key.encode()).hexdigest()[:12]
        if eid not in self.evidence:
            self.evidence[eid] = Evidence(eid, type, origin, function, trusted, via, sorted(nodes), detail)
            for n in nodes:
                self._by_node.setdefault(n, []).append(eid)
        return eid

    # ---- consulta ----
    def evidence_for(self, node_id: str) -> list[Evidence]:
        return [self.evidence[e] for e in self._by_node.get(node_id, [])]

    def independence(self, node_id: str) -> dict:
        """Observações INDEPENDENTES de um nó: evidências de mesma origem colapsam."""
        evs = self.evidence_for(node_id)
        by_origin: dict[str, list[Evidence]] = {}
        for e in evs:
            by_origin.setdefault(e.origin, []).append(e)
        trusted_origins = {o for o, es in by_origin.items() if any(e.trusted for e in es)}
        types = {e.type for e in evs if e.trusted}
        return {"evidence": len(evs), "observations": len(by_origin), "trusted_observations": len(trusted_origins),
                "types": sorted(types), "functions": len({e.function for e in evs if e.function}),
                "collapsed": len(evs) - len(by_origin)}

    def assess(self, node_id: str) -> tuple[str, str]:
        """(status, motivo). Nunca devolve KNOWN_REFERENCE_VALIDATED/RUNTIME_VALIDATED: isso só vem de validação externa."""
        ind = self.independence(node_id)
        if ind["observations"] >= 2 and len(ind["types"]) >= 2 and ind["trusted_observations"] >= 2:
            return "STATIC_CORROBORATED", (f"{ind['observations']} observações independentes e {len(ind['types'])} tipos "
                                           f"de evidência ({', '.join(ind['types'])})")
        why = []
        if ind["observations"] < 2:
            why.append(f"só {ind['observations']} observação independente")
        if len(ind["types"]) < 2:
            why.append(f"só o tipo {ind['types'] or 'nenhum'} de evidência")
        if ind["trusted_observations"] < 2:
            why.append(f"{ind['trusted_observations']} observação(ões) confiável(is)")
        return "STATIC_CANDIDATE", "; ".join(why)

    def neighborhood(self, node_id: str, depth: int = 2, limit: int = 60) -> tuple[list[Node], list[Edge]]:
        """Vizinhança (BFS) para visualização."""
        adj: dict[str, list[Edge]] = {}
        for e in self.edges:
            adj.setdefault(e.src, []).append(e)
            adj.setdefault(e.dst, []).append(e)
        seen, order, q = {node_id}, [node_id], deque([(node_id, 0)])
        while q and len(order) < limit:
            n, d = q.popleft()
            if d >= depth:
                continue
            for e in adj.get(n, []):
                other = e.dst if e.src == n else e.src
                if other not in seen and other in self.nodes:
                    seen.add(other)
                    order.append(other)
                    q.append((other, d + 1))
                    if len(order) >= limit:
                        break
        return ([self.nodes[i] for i in order if i in self.nodes],
                [e for e in self.edges if e.src in seen and e.dst in seen])

    # ---- serialização ----
    def to_dict(self) -> dict:
        return {"nodes": [asdict(n) for n in self.nodes.values()], "edges": [asdict(e) for e in self.edges],
                "evidence": [asdict(e) for e in self.evidence.values()]}

    @staticmethod
    def from_dict(d: dict) -> "EvidenceGraph":
        g = EvidenceGraph()
        for n in d.get("nodes", []):
            g.nodes[n["id"]] = Node(**n)
        for e in d.get("edges", []):
            g.add_edge(e["src"], e["dst"], e["kind"], e.get("evidence"))
        for e in d.get("evidence", []):
            ev = Evidence(**e)
            g.evidence[ev.id] = ev
            for n in ev.nodes:
                g._by_node.setdefault(n, []).append(ev.id)
        return g

    def to_dot(self, nodes: list[Node] | None = None, edges: list[Edge] | None = None) -> str:
        nodes = nodes if nodes is not None else list(self.nodes.values())
        edges = edges if edges is not None else self.edges
        ids = {n.id for n in nodes}
        lines = ["digraph evidence {", "  node [shape=box fontname=Consolas fontsize=10];"]
        for n in nodes:
            lines.append(f'  "{n.id}" [label="{n.kind}\\n{n.label}"];'.replace("\n", " "))
        for e in edges:
            if e.src in ids and e.dst in ids:
                lines.append(f'  "{e.src}" -> "{e.dst}" [label="{e.kind}"];')
        lines.append("}")
        return "\n".join(lines)
