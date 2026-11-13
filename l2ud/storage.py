"""SQLite: builds (identidade), AnalysisRun (execuções independentes), resultados, estruturas, eventos;
exportação explícita (RVA/VA/File Offset) e diff/histórico.

Modelo 0.4:
  builds       identidade por SHA-256 COMPLETO (+ fingerprint estrutural, módulo, arch, timestamp, perfil de similaridade)
  runs         uma linha por execução de `sigs`: engine, versão da ferramenta, hash e cópia do conjunto de assinaturas
  run_results  resultados DAQUELA execução (nada de misturar com execuções antigas)
  run_structs  candidatos a estrutura DAQUELA execução
  build_events trilha de mudanças (registro, mudança de caminho, execuções)
Bancos antigos (0.2/0.3: tabelas `results`/`structs` soltas por build) são migrados para uma run "legada".
"""
from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
from pathlib import Path

from . import __version__
from .analysis import fingerprint
from .buildid import BuildProfile, compute_profile
from .pe import PeImage
from .sigs import STATUS_ORDER, Result, Status, sigs_digest

SCHEMA = """
CREATE TABLE IF NOT EXISTS builds(
  id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE, path TEXT, arch TEXT, fingerprint TEXT,
  image_base INTEGER, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS build_events(
  id INTEGER PRIMARY KEY, build_id INTEGER REFERENCES builds(id) ON DELETE CASCADE,
  ts TEXT DEFAULT CURRENT_TIMESTAMP, kind TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY, build_id INTEGER REFERENCES builds(id) ON DELETE CASCADE,
  started TEXT DEFAULT CURRENT_TIMESTAMP, tool_version TEXT, engine TEXT,
  sigs_digest TEXT, sigs_json TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS run_results(
  id INTEGER PRIMARY KEY, run_id INTEGER REFERENCES runs(id) ON DELETE CASCADE,
  name TEXT, status TEXT, kind TEXT, value INTEGER, value_hex TEXT, value_kind TEXT, va TEXT, file_offset INTEGER,
  pattern TEXT, candidates TEXT, notes TEXT, evidence TEXT, UNIQUE(run_id, name));
CREATE TABLE IF NOT EXISTS run_structs(
  id INTEGER PRIMARY KEY, run_id INTEGER REFERENCES runs(id) ON DELETE CASCADE,
  cand_id INTEGER, data TEXT, UNIQUE(run_id, cand_id));
CREATE TABLE IF NOT EXISTS catalog_runs(
  id INTEGER PRIMARY KEY, bundle_id TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP,
  tool_version TEXT, note TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS catalog_items(
  id TEXT, run_id INTEGER REFERENCES catalog_runs(id) ON DELETE CASCADE,
  category TEXT, module TEXT, module_sha256 TEXT, name TEXT, value_kind TEXT,
  value INTEGER, va_preferred INTEGER, file_offset INTEGER, status TEXT,
  status_reason TEXT, data TEXT, PRIMARY KEY (run_id, id));
CREATE TABLE IF NOT EXISTS catalog_graphs(
  run_id INTEGER PRIMARY KEY REFERENCES catalog_runs(id) ON DELETE CASCADE,
  data TEXT);
"""
BUILD_NEW_COLS = {"machine": "INTEGER", "timestamp": "INTEGER", "module": "TEXT", "size": "INTEGER", "profile": "TEXT"}
_LEGACY_COLS = ["name", "status", "kind", "value", "candidates", "notes", "evidence", "value_kind", "va",
                "file_offset", "pattern", "value_hex"]

# Status exportados por padrão: só o que tem evidência além do AOB.
DEFAULT_EXPORT = {Status.CONFIRMED, Status.STATIC_CORROBORATED}
WITH_PROBABLE = DEFAULT_EXPORT | {Status.PROBABLE}


MIN_SHA_PREFIX = 8
_HEX = re.compile(r"^[0-9a-f]+$")


class AmbiguousBuild(KeyError):
    """Prefixo de SHA-256 que corresponde a mais de uma build."""


def _hex_list(vals) -> list:
    return [hex(v) if isinstance(v, int) else v for v in vals]


class Database:
    def __init__(self, path: str = "l2ud.db"):
        self.con = sqlite3.connect(path)
        self.con.execute("PRAGMA foreign_keys=ON")
        self.con.executescript(SCHEMA)
        have = {r[1] for r in self.con.execute("PRAGMA table_info(builds)")}
        for col, ddl in BUILD_NEW_COLS.items():
            if col not in have:
                self.con.execute(f"ALTER TABLE builds ADD COLUMN {col} {ddl}")
        self.con.commit()
        self._migrate_legacy()

    def close(self) -> None:
        self.con.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------ migração 0.2/0.3 -> runs
    def _table_cols(self, table: str) -> set[str]:
        return {r[1] for r in self.con.execute(f"PRAGMA table_info({table})")}

    def _migrate_legacy(self) -> None:
        if not self._table_cols("results"):
            return
        have = self._table_cols("results")
        sel = ", ".join(c if c in have else "NULL" for c in _LEGACY_COLS)
        with self.con:                                         # tudo ou nada
            for (bid,) in self.con.execute("SELECT DISTINCT build_id FROM results").fetchall():
                if self.con.execute("SELECT 1 FROM runs WHERE build_id=?", (bid,)).fetchone():
                    continue
                rid = self.con.execute(
                    "INSERT INTO runs(build_id,tool_version,engine,sigs_digest,sigs_json,note) VALUES(?,?,?,?,?,?) RETURNING id",
                    (bid, "legacy", "", "", "", "migrada de banco 0.2/0.3 (resultados soltos por build)")).fetchone()[0]
                for r in self.con.execute(f"SELECT {sel} FROM results WHERE build_id=?", (bid,)).fetchall():
                    n, st, k, v, c, no, ev, vk, va, fo, pat, vh = r
                    self.con.execute(
                        "INSERT OR REPLACE INTO run_results(run_id,name,status,kind,value,value_hex,value_kind,va,file_offset,"
                        "pattern,candidates,notes,evidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (rid, n, st, k, v, vh or (hex(v) if isinstance(v, int) else None), vk or "RVA", va, fo, pat or "",
                         c or "[]", no or "", ev or "[]"))
                if self._table_cols("structs"):
                    for cid, data in self.con.execute("SELECT cand_id,data FROM structs WHERE build_id=?", (bid,)).fetchall():
                        self.con.execute("INSERT OR REPLACE INTO run_structs(run_id,cand_id,data) VALUES(?,?,?)", (rid, cid, data))
                self._event(bid, "migrated", f"resultados legados convertidos na run {rid}")

    def _event(self, build_id: int, kind: str, detail: str = "") -> None:
        self.con.execute("INSERT INTO build_events(build_id,kind,detail) VALUES(?,?,?)", (build_id, kind, detail))

    # ------------------------------------------------------------ gravação
    def _register(self, img: PeImage, with_profile: bool = True) -> int:
        """Registra a build SEM commit (usar dentro de uma transação). Identidade = SHA-256 completo."""
        row = self.con.execute("SELECT id,path,profile FROM builds WHERE sha256=?", (img.sha256,)).fetchone()
        prof = compute_profile(img) if with_profile and (row is None or not row[2]) else None
        if row:
            bid = row[0]
            if row[1] != img.path:
                self._event(bid, "path_changed", f"{row[1]} -> {img.path}")
                self.con.execute("UPDATE builds SET path=? WHERE id=?", (img.path, bid))
            if prof:
                self.con.execute("UPDATE builds SET profile=? WHERE id=?", (prof.to_json(), bid))
            return bid
        module = prof.module if prof else (img.export_name or Path(img.path).name)
        bid = self.con.execute(
            "INSERT INTO builds(sha256,path,arch,fingerprint,image_base,machine,timestamp,module,size,profile) "
            "VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING id",
            (img.sha256, img.path, img.arch, fingerprint(img), img.image_base, img.machine, img.timestamp, module,
             len(img.raw), prof.to_json() if prof else None)).fetchone()[0]
        self._event(bid, "registered", f"{module} ({img.arch}) sha256={img.sha256[:16]}…")
        return bid

    def register_build(self, img: PeImage, with_profile: bool = True) -> int:
        with self.con:
            return self._register(img, with_profile)

    def save_run(self, img: PeImage, results: list[Result], sigs: list[dict] | None = None, engine: str = "",
                 note: str = "", with_profile: bool = True) -> tuple[int, int]:
        """Grava UMA execução completa e ATOMICAMENTE (build + run + resultados + evento: tudo ou nada).
        Retorna (build_id, run_id). Resultados de execuções anteriores permanecem nas suas próprias runs."""
        names = [r.name for r in results]
        dup = sorted({n for n in names if names.count(n) > 1})
        if dup:
            raise ValueError(f"nomes de resultado repetidos na mesma run: {dup} (a chave de um resultado é (run, nome))")
        with self.con:                                         # rollback automático em qualquer exceção
            bid = self._register(img, with_profile)
            rid = self.con.execute(
                "INSERT INTO runs(build_id,tool_version,engine,sigs_digest,sigs_json,note) VALUES(?,?,?,?,?,?) RETURNING id",
                (bid, __version__, engine, sigs_digest(sigs) if sigs is not None else "",
                 json.dumps(sigs, ensure_ascii=False) if sigs is not None else "", note)).fetchone()[0]
            for r in results:
                small = r.value is not None and r.value < 2**63
                self.con.execute(
                    "INSERT INTO run_results(run_id,name,status,kind,value,value_hex,value_kind,va,file_offset,"
                    "pattern,candidates,notes,evidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rid, r.name, r.status.value, r.kind, r.value if small else None,
                     None if r.value is None else hex(r.value), r.value_kind, None if r.va is None else hex(r.va),
                     r.file_offset, r.pattern, json.dumps(_hex_list(r.candidates)), r.notes, json.dumps(r.evidence)))
            self._event(bid, "analysis_run", f"run {rid}: {len(results)} resultado(s), engine={engine or '?'}")
        return bid, rid

    def save(self, img: PeImage, results: list[Result]) -> int:
        """Compat 0.3: grava como uma nova run e devolve o build_id."""
        return self.save_run(img, results)[0]

    def _run_build(self, run_id: int) -> int | None:
        r = self.con.execute("SELECT build_id FROM runs WHERE id=?", (run_id,)).fetchone()
        return r[0] if r else None

    def _check_run(self, build_id: int, run_id: int) -> None:
        """Toda leitura/gravação com run explícita exige que a run pertença à build."""
        owner = self._run_build(run_id)
        if owner is None:
            raise KeyError(f"run não encontrada: {run_id}")
        if owner != build_id:
            raise KeyError(f"run {run_id} pertence à build {owner}, não à build {build_id}")

    def save_structs(self, build_id: int, cands: list, run_id: int | None = None) -> int:
        """Grava candidatos de estrutura numa run DA build (a mais recente se não informada; cria uma vazia se não
        houver). Uma run de outra build é recusada (antes isto apagaria as estruturas dela)."""
        with self.con:
            if run_id is not None:
                self._check_run(build_id, run_id)
            else:
                run_id = self.latest_run(build_id)
            if run_id is None:
                run_id = self.con.execute(
                    "INSERT INTO runs(build_id,tool_version,engine,sigs_digest,sigs_json,note) VALUES(?,?,?,?,?,?) RETURNING id",
                    (build_id, __version__, "capstone", "", "", "run de estruturas")).fetchone()[0]
            self.con.execute("DELETE FROM run_structs WHERE run_id=?", (run_id,))
            for c in cands:
                self.con.execute("INSERT INTO run_structs(run_id,cand_id,data) VALUES(?,?,?)",
                                 (run_id, c.id, json.dumps(c.to_dict(), ensure_ascii=False)))
        return run_id

    def builds(self):
        return self.con.execute("SELECT id,sha256,path,arch,created FROM builds ORDER BY id").fetchall()

    def builds_info(self) -> list[dict]:
        rows = self.con.execute(
            "SELECT b.id,b.sha256,b.path,b.arch,b.created,b.module,b.timestamp,b.size,b.fingerprint,"
            "(SELECT COUNT(*) FROM runs r WHERE r.build_id=b.id) FROM builds b ORDER BY b.id").fetchall()
        keys = ["id", "sha256", "path", "arch", "created", "module", "timestamp", "size", "fingerprint", "runs"]
        return [dict(zip(keys, r)) for r in rows]

    def latest_run(self, build_id: int) -> int | None:
        r = self.con.execute("SELECT MAX(id) FROM runs WHERE build_id=?", (build_id,)).fetchone()
        return r[0] if r else None

    def _find_build(self, ref: str) -> int:
        """Regras: (1) id numérico EXATO tem prioridade; (2) SHA-256 completo; (3) prefixo de ≥8 hex, que precisa
        ser ÚNICO (ambíguo -> AmbiguousBuild listando as candidatas)."""
        s = ref.strip().lower()
        if s.isdigit():
            row = self.con.execute("SELECT id FROM builds WHERE id=?", (int(s),)).fetchone()
            if row:
                return row[0]
        if len(s) == 64 and _HEX.match(s):
            row = self.con.execute("SELECT id FROM builds WHERE sha256=?", (s,)).fetchone()
            if row:
                return row[0]
        elif MIN_SHA_PREFIX <= len(s) < 64 and _HEX.match(s):
            rows = self.con.execute("SELECT id,sha256 FROM builds WHERE sha256 LIKE ? ORDER BY id", (s + "%",)).fetchall()
            if len(rows) == 1:
                return rows[0][0]
            if len(rows) > 1:
                raise AmbiguousBuild(f"prefixo {ref!r} é ambíguo: " + ", ".join(f"#{i} ({h[:16]}…)" for i, h in rows))
        raise KeyError(f"build não encontrada: {ref!r} (use o id, o SHA-256 completo ou um prefixo único de ≥{MIN_SHA_PREFIX} hex)")

    def resolve(self, ref: int | str) -> tuple[int, int | None]:
        """Referências: `3` (build 3, run mais recente), `3@5` (build 3, run 5), `@5` (run 5), SHA-256 completo ou
        prefixo único (≥8 hex). Retorna (build_id, run_id|None)."""
        s = str(ref).strip()
        run = None
        if "@" in s:
            s, r = s.split("@", 1)
            if not r.isdigit():
                raise KeyError(f"referência de run inválida: {ref!r}")
            run = int(r)
            if not s:
                owner = self._run_build(run)
                if owner is None:
                    raise KeyError(f"run não encontrada: {run}")
                return owner, run
        bid = self._find_build(s)
        if run is not None:
            self._check_run(bid, run)
            return bid, run
        return bid, self.latest_run(bid)

    def _bid(self, build: int | str) -> int:
        return self.resolve(build)[0]

    def runs(self, build: int | str | None = None) -> list[dict]:
        q = ("SELECT r.id,r.build_id,r.started,r.tool_version,r.engine,r.sigs_digest,r.note,"
             "(SELECT COUNT(*) FROM run_results x WHERE x.run_id=r.id) FROM runs r")
        args: tuple = ()
        if build is not None:
            q += " WHERE r.build_id=?"
            args = (self._bid(build),)
        keys = ["run", "build", "started", "tool_version", "engine", "sigs_digest", "note", "results"]
        return [dict(zip(keys, r)) for r in self.con.execute(q + " ORDER BY r.id", args).fetchall()]

    def run_sigs(self, run_id: int) -> list[dict] | None:
        r = self.con.execute("SELECT sigs_json FROM runs WHERE id=?", (run_id,)).fetchone()
        return json.loads(r[0]) if r and r[0] else None

    @staticmethod
    def _row_to_result(row) -> Result:
        n, st, k, v, vh, c, no, ev, vk, va, fo, pat = row
        val = int(vh, 16) if vh else v
        cands = [int(x, 16) if isinstance(x, str) else x for x in json.loads(c or "[]")]
        return Result(n, Status(st), val, k, cands, no or "", json.loads(ev or "[]"), vk or "RVA",
                      int(va, 16) if va else None, fo, pat or "")

    def results(self, build: int | str, run: int | None = None) -> list[Result]:
        """Resultados de UMA run: a informada (ou a de `build@run`), senão a mais recente da build."""
        bid, rid = self.resolve(build)
        if run is not None:
            self._check_run(bid, run)
            rid = run
        if rid is None:
            return []
        rows = self.con.execute(
            "SELECT name,status,kind,value,value_hex,candidates,notes,evidence,value_kind,va,file_offset,pattern "
            "FROM run_results WHERE run_id=? ORDER BY name", (rid,)).fetchall()
        return [self._row_to_result(r) for r in rows]

    def image_base(self, build: int | str) -> int:
        return self.con.execute("SELECT image_base FROM builds WHERE id=?", (self._bid(build),)).fetchone()[0]

    def build_events(self, build: int | str) -> list[tuple]:
        return self.con.execute("SELECT ts,kind,detail FROM build_events WHERE build_id=? ORDER BY id",
                                (self._bid(build),)).fetchall()

    def profile(self, build: int | str) -> BuildProfile | None:
        r = self.con.execute("SELECT profile FROM builds WHERE id=?", (self._bid(build),)).fetchone()
        return BuildProfile.from_json(r[0]) if r and r[0] else None

    def history(self, name: str) -> list[dict]:
        rows = self.con.execute(
            "SELECT b.id,r.id,b.sha256,r.started,x.status,x.value,x.value_hex,x.value_kind,x.pattern "
            "FROM run_results x JOIN runs r ON r.id=x.run_id JOIN builds b ON b.id=r.build_id "
            "WHERE x.name=? ORDER BY r.id", (name,)).fetchall()
        return [{"build": b, "run": r, "sha256": s, "created": c, "status": st,
                 "value": int(vh, 16) if vh else v, "value_kind": vk or "RVA", "pattern": p or ""}
                for b, r, s, c, st, v, vh, vk, p in rows]

    def load_structs(self, build: int | str, run: int | None = None) -> list:
        """Estruturas de uma run. Sem run explícita (`build` simples), usa a execução MAIS RECENTE QUE TEM estruturas
        (uma run de assinaturas posterior não esconde as estruturas descobertas antes)."""
        from .structs import StructCandidate
        bid, rid = self.resolve(build)
        if run is None and "@" not in str(build):
            r = self.con.execute("SELECT MAX(s.run_id) FROM run_structs s JOIN runs r ON r.id=s.run_id "
                                 "WHERE r.build_id=?", (bid,)).fetchone()
            rid = r[0] or rid
        if run is not None:
            self._check_run(bid, run)
            rid = run
        if rid is None:
            return []
        return [StructCandidate.from_dict(json.loads(d)) for (d,) in self.con.execute(
            "SELECT data FROM run_structs WHERE run_id=? ORDER BY cand_id", (rid,)).fetchall()]

    def delete_run(self, run_id: int) -> None:
        with self.con:
            self.con.execute("DELETE FROM runs WHERE id=?", (run_id,))

    # ------------------------------------------------------------ Catálogo de Descoberta Automática
    def save_catalog(self, catalog, graph=None, note: str = "") -> int:
        """Salva uma execução do catálogo e opcionalmente o grafo de evidências."""
        from .catalog import Catalog
        with self.con:
            cur = self.con.execute(
                "INSERT INTO catalog_runs(bundle_id, tool_version, note, data) VALUES(?,?,?,?) RETURNING id",
                (catalog.bundle_id, __version__, note, catalog.to_json()))
            run_id = cur.fetchone()[0]
            for it in catalog.items.values():
                self.con.execute(
                    "INSERT INTO catalog_items(id, run_id, category, module, module_sha256, name, value_kind, "
                    "value, va_preferred, file_offset, status, status_reason, data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (it.id, run_id, it.category, it.module, it.module_sha256, it.name, it.value_kind,
                     it.value, it.va_preferred, it.file_offset, it.status, it.status_reason,
                     json.dumps(it.to_dict(), ensure_ascii=False)))
            if graph is not None:
                self.con.execute(
                    "INSERT INTO catalog_graphs(run_id, data) VALUES(?,?)",
                    (run_id, json.dumps(graph.to_dict(), ensure_ascii=False)))
        return run_id

    def load_catalog(self, run_id: int):
        """Carrega (Catalog, EvidenceGraph | None) para um run_id."""
        from .catalog import Catalog
        from .evgraph import EvidenceGraph
        row = self.con.execute("SELECT data FROM catalog_runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            raise KeyError(f"catalog_run {run_id} não encontrada")
        cat = Catalog.from_dict(json.loads(row[0]))
        graph_row = self.con.execute("SELECT data FROM catalog_graphs WHERE run_id=?", (run_id,)).fetchone()
        graph = EvidenceGraph.from_dict(json.loads(graph_row[0])) if graph_row else None
        return cat, graph

    def list_catalog_runs(self) -> list[dict]:
        """Lista todas as execuções de catálogo salvas."""
        rows = self.con.execute(
            "SELECT id, bundle_id, created, tool_version, note, "
            "(SELECT COUNT(*) FROM catalog_items i WHERE i.run_id = r.id) as item_count "
            "FROM catalog_runs r ORDER BY id DESC").fetchall()
        keys = ["id", "bundle_id", "created", "tool_version", "note", "item_count"]
        return [dict(zip(keys, r)) for r in rows]

    def delete_catalog_run(self, run_id: int) -> None:
        with self.con:
            self.con.execute("DELETE FROM catalog_runs WHERE id=?", (run_id,))

# ---------- exportação ----------
def _suffix(vk: str) -> str:
    return {"RVA": "_RVA", "FIELD_OFFSET": "_OFFSET"}.get(vk, "_VALUE")


def _ident(name: str, vk: str, used: set[str]) -> str:
    s = re.sub(r"\W", "_", name).upper()
    if s[:1].isdigit():
        s = "_" + s
    suf = _suffix(vk)
    if not s.endswith(suf):
        s += suf
    base, n = s, 2
    while s in used:
        s, n = f"{base}_{n}", n + 1
    used.add(s)
    return s


def select(results: list[Result], include_probable: bool = False, include_all: bool = False) -> list[Result]:
    if include_all:
        return list(results)
    allowed = WITH_PROBABLE if include_probable else DEFAULT_EXPORT
    return [r for r in results if r.status in allowed]


def export(results: list[Result], fmt: str, include_probable: bool = False, include_all: bool = False,
           image_base: int | None = None, build: str = "") -> str:
    rs = select(results, include_probable, include_all)
    if fmt == "json":
        def j(r: Result):
            d = {"name": r.name, "status": r.status.value, "kind": r.kind, "value_kind": r.value_kind,
                 "value": None if r.value is None else f"{r.value:#x}",
                 "candidates": [f"{c:#x}" for c in r.candidates], "notes": r.notes, "evidence": r.evidence}
            if r.value_kind == "RVA":
                d["rva"] = d["value"]
                va = r.va if r.va is not None else (None if r.value is None or image_base is None else image_base + r.value)
                d["va_preferred_base"] = None if va is None else f"{va:#x}"
                d["file_offset"] = None if r.file_offset is None else f"{r.file_offset:#x}"
            return d
        return json.dumps({"build": build, "image_base_preferred": None if image_base is None else f"{image_base:#x}",
                           "results": [j(r) for r in rs]}, indent=2, ensure_ascii=False)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["name", "status", "kind", "value_kind", "value", "va_preferred_base", "file_offset", "notes"])
        for r in rs:
            w.writerow([r.name, r.status.value, r.kind, r.value_kind, "" if r.value is None else f"{r.value:#x}",
                        "" if r.va is None else f"{r.va:#x}", "" if r.file_offset is None else f"{r.file_offset:#x}",
                        r.notes])
        return buf.getvalue()
    if fmt == "hpp":
        used: set[str] = set()
        lines = ["#pragma once", "#include <cstdint>", "",
                 "// Gerado por l2ud. *_RVA = offset relativo à BASE REAL do módulo carregado; *_OFFSET = deslocamento de campo.",
                 "// Nunca some o ImageBase preferido do PE: use a base real (ASLR/relocação) com va_from_rva().",
                 f"// build: {build}" if build else "// build: (não informada)", "namespace l2ud_offsets {"]
        if image_base is not None:
            lines.append(f"constexpr std::uint64_t PREFERRED_IMAGE_BASE = {image_base:#x}; // informativo")
        lines.append("inline std::uintptr_t va_from_rva(std::uintptr_t module_base, std::uint32_t rva) "
                     "{ return module_base + rva; }")
        for r in rs:
            if r.value is None:
                lines.append(f"// {r.name}: {r.status.value} (sem valor único) {r.notes}")
                continue
            ty = "std::uint32_t" if r.value <= 0xFFFFFFFF else "std::uint64_t"
            lines.append(f"constexpr {ty} {_ident(r.name, r.value_kind, used)} = {r.value:#x}; // {r.status.value}")
        lines.append("}")
        return "\n".join(lines) + "\n"
    raise ValueError(f"formato desconhecido: {fmt}")


def write_export(results: list[Result], path: str, include_probable: bool = False, include_all: bool = False,
                 image_base: int | None = None, build: str = "") -> None:
    fmt = Path(path).suffix.lstrip(".").lower()
    fmt = "hpp" if fmt in ("h", "hpp") else fmt
    Path(path).write_text(export(results, fmt, include_probable, include_all, image_base, build), encoding="utf-8")


def export_structs(cands: list, fmt: str = "json") -> str:
    """Estruturas candidatas -> json | md. Sempre rotuladas como inferência (CANDIDATE)."""
    if fmt == "json":
        return json.dumps({"disclaimer": "inferência estática; nada aqui confirma o significado de uma estrutura",
                           "structs": [c.to_dict() for c in cands]}, indent=2, ensure_ascii=False)
    if fmt == "md":
        out = ["# Candidatos a estrutura", "", "> Inferência estática (status sempre CANDIDATE). Não identifica significado.", ""]
        for c in cands:
            out += [f"## #{c.id} — confiança {c.confidence}, interesse {c.interest}/100, tamanho ≥ {c.size_estimate:#x}", ""]
            out += [f"- origem: {r}" for r in c.roots[:4]]
            out += [f"- {h}" for h in c.hints]
            out += ["", "| offset | tipo provável | leituras | escritas | funções |", "|---|---|---|---|---|"]
            out += [f"| {f['offset']} | {f['type_guess']} | {f['reads']} | {f['writes']} | {f['functions']} |" for f in c.fields]
            out += [""] + [f"- relação **{r['kind']}**: {r.get('detail', '')}" for r in c.relations] + [""]
        return "\n".join(out)
    raise ValueError(f"formato desconhecido: {fmt}")


# ---------- diff ----------
def diff(old: list[Result], new: list[Result]) -> dict[str, list]:
    o = {r.name: r for r in old}
    n = {r.name: r for r in new}
    d: dict[str, list] = {"changed": [], "unchanged": [], "added": [], "removed": [],
                          "degraded": [], "improved": [], "pattern_changed": []}
    for name, r in n.items():
        if name not in o:
            d["added"].append((name, r.value))
            continue
        a = o[name]
        if a.value != r.value:
            delta = None if a.value is None or r.value is None else r.value - a.value
            d["changed"].append((name, a.value, r.value, delta))
        else:
            d["unchanged"].append(name)
        if STATUS_ORDER.index(r.status) < STATUS_ORDER.index(a.status):
            d["degraded"].append((name, a.status.value, r.status.value))
        elif STATUS_ORDER.index(r.status) > STATUS_ORDER.index(a.status):
            d["improved"].append((name, a.status.value, r.status.value))
        if a.pattern and r.pattern and a.pattern != r.pattern:
            d["pattern_changed"].append(name)
    d["removed"] = [(k, o[k].value) for k in o if k not in n]
    return d
