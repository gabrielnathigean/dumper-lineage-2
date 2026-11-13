"""Parser de PE (PE32 / PE32+) conservador: valida limites e rejeita cedo."""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field


class PeError(Exception):
    pass


IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_CNT_CODE = 0x00000020

DIR_EXPORT, DIR_IMPORT, DIR_EXCEPTION, DIR_BASERELOC = 0, 1, 3, 5


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))

    @property
    def discardable(self) -> bool:
        return bool(self.flags & IMAGE_SCN_MEM_DISCARDABLE)

    @property
    def span(self) -> int:
        return max(self.vsize, self.raw_size)


@dataclass
class Export:
    name: str
    rva: int
    ordinal: int
    forwarder: str | None = None  # "DLL.Func" se a exportação é um forwarder (rva aponta p/ string)


@dataclass
class Import:
    dll: str
    name: str
    iat_rva: int


@dataclass
class PeImage:
    path: str
    raw: bytes
    is64: bool
    machine: int
    image_base: int
    entry_point: int
    size_of_headers: int
    size_of_image: int
    sections: list[Section] = field(default_factory=list)
    dirs: list[tuple[int, int]] = field(default_factory=list)
    exports: list[Export] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    relocs: list[tuple[int, int]] = field(default_factory=list)
    functions: list[tuple[int, int]] = field(default_factory=list)  # (begin_rva, end_rva) de .pdata
    timestamp: int = 0          # TimeDateStamp do COFF header (pode ser reprodutível/zerado)
    export_name: str = ""       # nome interno do módulo (Export Directory), ex.: "client.dll"
    magic: int = 0              # OptionalHeader.Magic (0x10B = PE32, 0x20B = PE32+)
    characteristics: int = 0    # FileHeader.Characteristics (0x2000 = DLL)

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & 0x2000)

    def overlay_size(self) -> int:
        """Bytes depois do fim dos dados das seções (instaladores/packers costumam anexar dados aqui)."""
        end = max((s.raw_ptr + s.raw_size for s in self.sections), default=0)
        return max(0, len(self.raw) - max(end, self.size_of_headers))

    def entry_section(self) -> "Section | None":
        return self.section_for_rva(self.entry_point) if self.entry_point else None

    # ---------- carga ----------
    @staticmethod
    def load(path: str) -> "PeImage":
        with open(path, "rb") as f:
            return PeImage.parse(f.read(), path)

    @staticmethod
    def parse(raw: bytes, path: str = "<memory>") -> "PeImage":
        n = len(raw)
        if n < 64 or raw[:2] != b"MZ":
            raise PeError("assinatura MZ ausente")
        lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
        if lfanew + 24 > n or raw[lfanew:lfanew + 4] != b"PE\0\0":
            raise PeError("assinatura PE ausente / e_lfanew inválido")
        machine, nsec = struct.unpack_from("<HH", raw, lfanew + 4)
        opt_size = struct.unpack_from("<H", raw, lfanew + 20)[0]
        if nsec == 0 or nsec > 96:
            raise PeError(f"numberOfSections fora do esperado: {nsec}")
        opt = lfanew + 24
        if opt_size < 96 or opt + opt_size > n:
            raise PeError("optional header truncado")
        magic = struct.unpack_from("<H", raw, opt)[0]
        if magic == 0x10B:
            is64 = False
            image_base = struct.unpack_from("<I", raw, opt + 28)[0]
            ndirs_off, dirs_off = opt + 92, opt + 96
        elif magic == 0x20B:
            is64 = True
            image_base = struct.unpack_from("<Q", raw, opt + 24)[0]
            ndirs_off, dirs_off = opt + 108, opt + 112
        else:
            raise PeError(f"magic de optional header desconhecido: {magic:#x}")
        entry = struct.unpack_from("<I", raw, opt + 16)[0]
        size_of_image = struct.unpack_from("<I", raw, opt + 56)[0]
        size_of_headers = struct.unpack_from("<I", raw, opt + 60)[0]
        ndirs = min(struct.unpack_from("<I", raw, ndirs_off)[0], 16)
        dirs = []
        for i in range(ndirs):
            o = dirs_off + i * 8
            if o + 8 > opt + opt_size:
                break
            dirs.append(struct.unpack_from("<II", raw, o))

        img = PeImage(path, raw, is64, machine, image_base, entry, size_of_headers, size_of_image, dirs=dirs)
        img.timestamp = struct.unpack_from("<I", raw, lfanew + 8)[0]
        img.magic = magic
        img.characteristics = struct.unpack_from("<H", raw, lfanew + 22)[0]

        so = opt + opt_size
        for i in range(nsec):
            o = so + i * 40
            if o + 40 > n:
                raise PeError("tabela de seções truncada")
            name = raw[o:o + 8].split(b"\0", 1)[0].decode("latin-1")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", raw, o + 8)
            flags = struct.unpack_from("<I", raw, o + 36)[0]
            if rsize and rptr + rsize > n:
                rsize = max(0, n - rptr)  # arquivo truncado: clampa em vez de ler fora
            img.sections.append(Section(name, va, vsize, rptr, rsize, flags))

        # diretórios são best-effort: falha num deles não derruba o resto
        for fn in (img._parse_exports, img._parse_imports, img._parse_relocs, img._parse_pdata):
            try:
                fn()
            except (PeError, struct.error, IndexError):
                pass
        return img

    # ---------- endereçamento ----------
    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()

    @property
    def arch(self) -> str:
        return "x64" if self.is64 else "x86"

    def section_for_rva(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.va <= rva < s.va + s.span:
                return s
        return None

    def rva_to_file(self, rva: int) -> int | None:
        if 0 <= rva < self.size_of_headers and rva < len(self.raw):
            return rva
        s = self.section_for_rva(rva)
        if s is None:
            return None
        d = rva - s.va
        if d >= s.raw_size:
            return None  # só existe em memória (bss)
        return s.raw_ptr + d

    def file_to_rva(self, off: int) -> int | None:
        for s in self.sections:
            if s.raw_ptr <= off < s.raw_ptr + s.raw_size:
                return s.va + off - s.raw_ptr
        return None

    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva

    def read_rva(self, rva: int, n: int) -> bytes | None:
        off = self.rva_to_file(rva)
        if off is None or off + n > len(self.raw):
            return None
        return self.raw[off:off + n]

    def read_cstr(self, rva: int, limit: int = 512) -> str | None:
        off = self.rva_to_file(rva)
        if off is None:
            return None
        end = self.raw.find(b"\0", off, off + limit)
        if end < 0:
            end = min(off + limit, len(self.raw))
        return self.raw[off:end].decode("latin-1")

    def u32(self, rva: int) -> int:
        b = self.read_rva(rva, 4)
        if b is None:
            raise PeError(f"RVA {rva:#x} não mapeado")
        return struct.unpack("<I", b)[0]

    def uptr(self, rva: int) -> int:
        sz = 8 if self.is64 else 4
        b = self.read_rva(rva, sz)
        if b is None:
            raise PeError(f"RVA {rva:#x} não mapeado")
        return struct.unpack("<Q" if self.is64 else "<I", b)[0]

    # ---------- diretórios ----------
    def _dir(self, idx: int) -> tuple[int, int]:
        return self.dirs[idx] if idx < len(self.dirs) else (0, 0)

    def _parse_exports(self) -> None:
        rva, size = self._dir(DIR_EXPORT)
        if not rva:
            return
        name_rva = struct.unpack("<I", self.read_rva(rva + 12, 4) or b"\x00\x00\x00\x00")[0]
        if name_rva:
            self.export_name = self.read_cstr(name_rva, 128) or ""
        base, nfuncs, nnames, aof, aon, aoo = struct.unpack("<IIIIII", self.read_rva(rva + 16, 24) or b"")
        nfuncs, nnames = min(nfuncs, 65536), min(nnames, 65536)
        by_ord: dict[int, str] = {}
        for i in range(nnames):
            name_rva = self.u32(aon + 4 * i)
            ordi = struct.unpack("<H", self.read_rva(aoo + 2 * i, 2) or b"")[0]
            by_ord[ordi] = self.read_cstr(name_rva) or ""
        for i in range(nfuncs):
            frva = self.u32(aof + 4 * i)
            if frva == 0:
                continue
            fwd = None
            if rva <= frva < rva + size:
                fwd = self.read_cstr(frva)
            self.exports.append(Export(by_ord.get(i, ""), frva, base + i, fwd))

    def _parse_imports(self) -> None:
        rva, _ = self._dir(DIR_IMPORT)
        if not rva:
            return
        ptr = 8 if self.is64 else 4
        flag = 1 << (63 if self.is64 else 31)
        for k in range(1024):
            d = self.read_rva(rva + 20 * k, 20)
            if not d or d == b"\0" * 20:
                break
            oft, _, _, name_rva, ft = struct.unpack("<IIIII", d)
            dll = self.read_cstr(name_rva) or "?"
            src = oft or ft
            for j in range(8192):
                ent = self.uptr(src + j * ptr)
                if ent == 0:
                    break
                iat = ft + j * ptr
                if ent & flag:
                    nm = f"#{ent & 0xFFFF}"
                else:
                    nm = self.read_cstr((ent & 0x7FFFFFFF) + 2) or "?"
                self.imports.append(Import(dll, nm, iat))

    def _parse_relocs(self) -> None:
        rva, size = self._dir(DIR_BASERELOC)
        if not rva or not size:
            return
        pos, end = rva, rva + size
        while pos + 8 <= end and len(self.relocs) < 5_000_000:
            page, bsize = struct.unpack("<II", self.read_rva(pos, 8) or b"")
            if bsize < 8:
                break
            for i in range((bsize - 8) // 2):
                e = struct.unpack("<H", self.read_rva(pos + 8 + 2 * i, 2) or b"")[0]
                if e >> 12:
                    self.relocs.append((page + (e & 0xFFF), e >> 12))
            pos += bsize

    def _parse_pdata(self) -> None:
        if not self.is64:
            return
        rva, size = self._dir(DIR_EXCEPTION)
        if not rva or not size:
            return
        off = self.rva_to_file(rva)
        if off is None:
            return
        data = self.raw[off:off + min(size, len(self.raw) - off)]
        for i in range(0, len(data) - 11, 12):
            b, e, _ = struct.unpack_from("<III", data, i)
            if b == 0 and e == 0:
                break
            if e > b:
                self.functions.append((b, e))
        self.functions.sort()

    def function_containing(self, rva: int) -> tuple[int, int] | None:
        """Limites exatos da função via .pdata (x64). None se indisponível."""
        import bisect
        i = bisect.bisect_right(self.functions, (rva, 1 << 62)) - 1
        if i >= 0 and self.functions[i][0] <= rva < self.functions[i][1]:
            return self.functions[i]
        return None
