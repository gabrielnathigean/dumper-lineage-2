"""Client Bundle Analyzer: analisa uma pasta (ex.: a pasta System de um cliente) como um CONJUNTO de módulos PE.

Para cada módulo: SHA-256, arquitetura REAL (Machine + OptionalHeader.Magic, com checagem de consistência),
timestamp, ImageBase, seções (com entropia), imports/exports, fingerprint e INDICADORES de empacotamento.

Nada aqui presume que os arquivos pertencem à mesma build: o relatório procura sinais de MISTURA (imports que
o módulo-irmão não exporta, datas muito distantes, arquiteturas diferentes) e diz o que encontrou. Indicadores de
empacotamento são heurísticas, nunca prova.
"""
from __future__ import annotations

import hashlib
import math
import os
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .analysis import fingerprint
from .pe import PeError, PeImage
from .progress import CancelToken, Progress

PE_EXTENSIONS = {".exe", ".dll", ".ocx", ".sys", ".drv", ".ax"}
INTEREST_MODULES = ("l2.exe", "engine.dll", "core.dll")        # prioridade de análise (nomes citados; não é lista completa)
ARCH_BY_MACHINE = {0x14C: "x86", 0x8664: "x64", 0x1C0: "arm", 0x1C4: "arm", 0xAA64: "arm64", 0x200: "ia64"}
MAGIC_BY_MACHINE = {0x14C: 0x10B, 0x8664: 0x20B, 0xAA64: 0x20B, 0x200: 0x20B, 0x1C0: 0x10B, 0x1C4: 0x10B}
PACKER_SECTION_HINTS = (".themida", ".winlice", ".vmp0", ".vmp1", ".vmp2", "upx0", "upx1", "upx2", ".aspack", ".adata",
                        ".petite", ".nsp0", ".nsp1", ".nsp2", ".enigma1", ".enigma2", ".mpress1", ".mpress2", ".rmnet",
                        ".perplex", ".pec", ".neolit", ".yp", ".packed", ".boom", ".svkp", "pebundle", ".shrink")
LOADER_IMPORTS = {"loadlibrarya", "loadlibraryw", "getprocaddress", "virtualalloc", "virtualprotect", "loadlibraryexa",
                  "loadlibraryexw"}
HIGH_ENTROPY = 7.2


@dataclass
class SectionInfo:
    name: str
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int
    flags: int
    entropy: float
    executable: bool
    writable: bool


@dataclass
class ModuleInfo:
    name: str
    path: str
    sha256: str
    size: int
    arch: str                       # 'x86' | 'x64' | ... (derivada de Machine)
    machine: int
    magic: int
    arch_consistent: bool           # Machine e OptionalHeader.Magic concordam
    timestamp: int
    image_base: int
    is_dll: bool
    entry_point: int
    entry_section: str
    export_name: str
    fingerprint: str
    n_imports: int
    n_exports: int
    import_dlls: list[str] = field(default_factory=list)
    sections: list[SectionInfo] = field(default_factory=list)
    overlay_size: int = 0
    packing_level: str = "none"     # 'none' | 'possible' | 'likely'
    packing_score: int = 0
    packing_indicators: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["image_base"] = f"{self.image_base:#x}"
        d["machine"] = f"{self.machine:#x}"
        d["magic"] = f"{self.magic:#x}"
        d["entry_point"] = f"{self.entry_point:#x}"
        return d


@dataclass
class BundleIssue:
    level: str                      # 'info' | 'warning' | 'error'
    code: str
    message: str
    modules: list[str] = field(default_factory=list)


@dataclass
class BundleReport:
    root: str
    modules: list[ModuleInfo]
    skipped: list[tuple[str, str]]
    issues: list[BundleIssue]
    bundle_id: str
    dependencies: dict[str, list[str]] = field(default_factory=dict)       # módulo -> módulos do bundle que ele importa

    def module(self, name: str) -> ModuleInfo | None:
        return next((m for m in self.modules if m.name.lower() == name.lower()), None)

    def to_dict(self) -> dict:
        return {"root": self.root, "bundle_id": self.bundle_id, "modules": [m.to_dict() for m in self.modules],
                "skipped": [{"path": p, "reason": r} for p, r in self.skipped],
                "issues": [asdict(i) for i in self.issues], "dependencies": self.dependencies}


# ------------------------------------------------------------------ entropia e empacotamento
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def section_infos(img: PeImage) -> list[SectionInfo]:
    out = []
    for s in img.sections:
        data = img.raw[s.raw_ptr:s.raw_ptr + s.raw_size]
        out.append(SectionInfo(s.name, s.va, s.vsize, s.raw_ptr, s.raw_size, s.flags,
                               round(shannon_entropy(data[:1 << 20]), 3), s.executable, bool(s.flags & 0x80000000)))
    return out


def packing_assessment(img: PeImage, secs: list[SectionInfo]) -> tuple[int, str, list[str]]:
    """Indicadores de empacotamento/proteção. Retorna (pontuação, nível, indicadores explicados)."""
    score, ind = 0, []
    for s in secs:
        low = s.name.lower()
        if any(low == h or low.startswith(h) for h in PACKER_SECTION_HINTS):
            score += 3
            ind.append(f"seção '{s.name}' tem nome típico de packer/protetor")
        if s.executable and s.raw_size >= 0x1000 and s.entropy >= HIGH_ENTROPY:
            score += 3 if s.entropy >= 7.6 else 2
            ind.append(f"seção executável '{s.name}' com entropia alta ({s.entropy}): conteúdo comprimido/cifrado?")
        if s.executable and s.writable:
            score += 1
            ind.append(f"seção '{s.name}' é executável E gravável")
        if s.executable and s.raw_size == 0 and s.vsize >= 0x10000:
            score += 2
            ind.append(f"seção executável '{s.name}' sem dados em disco e grande em memória (descompressão em runtime?)")
    ep = img.entry_section()
    if img.entry_point:
        if ep is None:
            score += 3
            ind.append("entry point fora de qualquer seção")
        elif not ep.executable:
            score += 3
            ind.append(f"entry point na seção não executável '{ep.name}'")
        else:
            execs = [s for s in img.sections if s.executable]
            if execs and ep.name != execs[0].name and len(img.sections) > 2:
                score += 2
                ind.append(f"entry point em '{ep.name}', não na primeira seção executável '{execs[0].name}'")
            if img.sections and ep.name == img.sections[-1].name and len(img.sections) > 2:
                score += 1
                ind.append("entry point na última seção")
    names = {i.name.lower() for i in img.imports}
    ndll = len({i.dll.lower() for i in img.imports})
    if len(img.raw) > 100_000 and len(img.imports) < 8:
        score += 2
        ind.append(f"poucos imports ({len(img.imports)}) para um arquivo de {len(img.raw)} bytes")
    if img.imports and names and names <= LOADER_IMPORTS | {"exitprocess", "getmodulehandlea", "getmodulehandlew"} and len(names) <= 6:
        score += 2
        ind.append("só imports de carregador (LoadLibrary/GetProcAddress/VirtualAlloc…): resolução dinâmica?")
    if img.overlay_size() > 0.5 * len(img.raw) and len(img.raw) > 100_000:
        score += 1
        ind.append(f"overlay grande ({img.overlay_size()} bytes, >50% do arquivo)")
    level = "likely" if score >= 6 else "possible" if score >= 3 else "none"
    del ndll
    return score, level, ind


# ------------------------------------------------------------------ módulo
def analyze_module(path: str | Path) -> ModuleInfo:
    """Metadados de UM módulo. Levanta PeError/OSError se não for um PE válido."""
    img = PeImage.load(str(path))
    secs = section_infos(img)
    score, level, ind = packing_assessment(img, secs)
    arch = ARCH_BY_MACHINE.get(img.machine, "unknown")
    expected_magic = MAGIC_BY_MACHINE.get(img.machine)
    consistent = expected_magic is None or expected_magic == img.magic
    notes = []
    if arch == "unknown":
        notes.append(f"Machine {img.machine:#x} desconhecida: arquitetura real indeterminada")
    if not consistent:
        notes.append(f"Machine ({img.machine:#x} = {arch}) e Magic ({img.magic:#x}) NÃO concordam: header suspeito/adulterado")
    es = img.entry_section()
    return ModuleInfo(
        name=Path(path).name, path=str(path), sha256=img.sha256, size=len(img.raw), arch=arch, machine=img.machine,
        magic=img.magic, arch_consistent=consistent, timestamp=img.timestamp, image_base=img.image_base,
        is_dll=img.is_dll, entry_point=img.entry_point, entry_section=es.name if es else "", export_name=img.export_name,
        fingerprint=fingerprint(img), n_imports=len(img.imports), n_exports=len(img.exports),
        import_dlls=sorted({i.dll for i in img.imports}, key=str.lower), sections=secs, overlay_size=img.overlay_size(),
        packing_level=level, packing_score=score, packing_indicators=ind, notes=notes)


def bundle_identity(modules: list[ModuleInfo]) -> str:
    """Identidade do CONJUNTO: SHA-256 de 'nome:sha256' ordenados (independe da ordem e de maiúsculas no nome)."""
    lines = sorted(f"{m.name.lower()}:{m.sha256}" for m in modules)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


# ------------------------------------------------------------------ conjunto
def find_pe_files(root: str | Path, recursive: bool = False) -> list[Path]:
    root = Path(root)
    it = root.rglob("*") if recursive else root.iterdir()
    return sorted((p for p in it if p.is_file() and p.suffix.lower() in PE_EXTENSIONS), key=lambda p: p.name.lower())


def _check_imports(modules: list[ModuleInfo]) -> tuple[list[BundleIssue], dict[str, list[str]]]:
    """Cada import de um módulo cujo DLL está no bundle TEM que ser exportado por esse DLL; se não for, os dois
    arquivos provavelmente não pertencem à mesma build."""
    issues: list[BundleIssue] = []
    by_name = {m.name.lower(): m for m in modules}
    deps: dict[str, list[str]] = {}
    exports: dict[str, tuple[set[str], set[int]]] = {}
    for m in modules:
        img = PeImage.load(m.path)
        exports[m.name.lower()] = ({e.name for e in img.exports if e.name}, {e.ordinal for e in img.exports})
    for m in modules:
        img = PeImage.load(m.path)
        used: dict[str, list[str]] = {}
        for imp in img.imports:
            d = imp.dll.lower()
            if d in by_name and d != m.name.lower():
                used.setdefault(d, []).append(imp.name)
        deps[m.name] = sorted(by_name[d].name for d in used)
        for d, names in used.items():
            en, eo = exports[d]
            missing = [n for n in names if (int(n[1:]) not in eo if n.startswith("#") and n[1:].isdigit() else n not in en)]
            if missing:
                issues.append(BundleIssue(
                    "error", "IMPORT_UNRESOLVED",
                    f"{m.name} importa {len(missing)} símbolo(s) que {by_name[d].name} (do próprio bundle) NÃO exporta "
                    f"(ex.: {', '.join(missing[:4])}): módulos de builds diferentes?", [m.name, by_name[d].name]))
            else:
                issues.append(BundleIssue("info", "IMPORTS_CONSISTENT",
                                          f"{m.name} → {by_name[d].name}: {len(names)} import(s) todos resolvidos", [m.name, by_name[d].name]))
    return issues, deps


def analyze_bundle(root: str | Path, recursive: bool = False, progress: Progress | None = None,
                   cancel: CancelToken | None = None, max_ts_spread_days: int = 45) -> BundleReport:
    """Analisa todos os PEs da pasta. `progress`/`cancel` são opcionais (cancelamento cooperativo)."""
    prog = progress or Progress(None, cancel)
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f"pasta não encontrada: {root}")
    files = find_pe_files(root, recursive)
    prog.stage("bundle", len(files), f"{len(files)} arquivo(s) PE candidato(s) em {root}")
    modules: list[ModuleInfo] = []
    skipped: list[tuple[str, str]] = []
    for p in files:
        try:
            modules.append(analyze_module(p))
        except (PeError, OSError, ValueError, MemoryError) as e:
            skipped.append((str(p), f"não é um PE válido: {e}"))
        prog.step(p.name)
    # prioridade: módulos de interesse primeiro, depois ordem alfabética
    modules.sort(key=lambda m: (m.name.lower() not in INTEREST_MODULES, m.name.lower()))
    issues: list[BundleIssue] = []
    if not modules:
        issues.append(BundleIssue("error", "NO_MODULES", "nenhum módulo PE válido encontrado na pasta"))
    names = [m.name.lower() for m in modules]
    for dup, c in Counter(names).items():
        if c > 1:
            issues.append(BundleIssue("warning", "DUPLICATE_NAME", f"nome de módulo repetido (subpastas?): {dup} ×{c}", [dup]))
    present = [n for n in INTEREST_MODULES if n in names]
    absent = [n for n in INTEREST_MODULES if n not in names]
    issues.append(BundleIssue("info", "INTEREST_MODULES", f"módulos de interesse presentes: {present or 'nenhum'}"
                              + (f"; ausentes: {absent}" if absent else "")))
    archs = Counter(m.arch for m in modules)
    if len([a for a in archs if a != "unknown"]) > 1:
        issues.append(BundleIssue("warning", "MIXED_ARCH", f"arquiteturas misturadas no bundle: {dict(archs)}"))
    for m in modules:
        if not m.arch_consistent:
            issues.append(BundleIssue("error", "ARCH_MISMATCH", m.notes[-1], [m.name]))
        if m.arch == "unknown":
            issues.append(BundleIssue("warning", "ARCH_UNKNOWN", m.notes[0], [m.name]))
        if m.packing_level != "none":
            issues.append(BundleIssue(
                "warning" if m.packing_level == "possible" else "error", "PACKING_" + m.packing_level.upper(),
                f"{m.name}: indicadores de empacotamento/proteção ({m.packing_level}, pontuação {m.packing_score}); "
                "a análise estática de um binário empacotado tende a ser inútil — use um dump desempacotado", [m.name]))
    ts = [(m.timestamp, m.name) for m in modules if m.timestamp not in (0, 0xFFFFFFFF)]
    if len(ts) >= 2:
        lo, hi = min(ts), max(ts)
        spread = (hi[0] - lo[0]) / 86400
        if spread > max_ts_spread_days:
            issues.append(BundleIssue("warning", "TIMESTAMP_SPREAD",
                                      f"timestamps separados por {spread:.0f} dias ({lo[1]} … {hi[1]}): podem ser de builds diferentes "
                                      "(ou timestamps reprodutíveis/alterados — não é prova)", [lo[1], hi[1]]))
    deps: dict[str, list[str]] = {}
    if modules:
        prog.stage("bundle-imports", len(modules), "conferindo imports entre os módulos do bundle")
        imp_issues, deps = _check_imports(modules)
        issues += imp_issues
        prog.done = len(modules)
    prog.finish()
    return BundleReport(str(root), modules, skipped, issues, bundle_identity(modules), deps)


def analyzable(report: BundleReport, include_packed: bool = False) -> list[ModuleInfo]:
    """Módulos que valem a análise automática: PE x86/x64 consistente e (por padrão) não 'likely' empacotado."""
    return [m for m in report.modules if m.arch in ("x86", "x64") and m.arch_consistent
            and (include_packed or m.packing_level != "likely")]
