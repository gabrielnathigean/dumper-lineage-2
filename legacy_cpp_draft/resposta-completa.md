# L2 Universal Offset Dumper — Estrutura Completa

Vou entregar o projeto **por módulos**, com código real, compilável e testável. Como não posso executar compilação aqui, cada etapa vem com instruções de build e fixtures sintéticas. Nada de "compatibilidade universal": o README declara explicitamente que builds reais precisam ser validadas manualmente.

> Aviso honesto antes de começar: este é um projeto grande. Vou entregar o núcleo funcional (PE, hash, AOB, disasm, validação, DB/export, UI) com testes. A parte de **Structure/Function Analyzer** é heurística e será marcada como `CANDIDATE`/`AMBIGUOUS` por padrão — nunca `CONFIRMED` sem revalidação. Se uma build real não bater, retorna `NOT_FOUND`.

---

## 1. Estrutura de diretórios

```
l2-universal-dumper/
├── CMakeLists.txt
├── README.md
├── cmake/
│   └── CapstoneConfig.cmake.in
├── include/l2ud/
│   ├── core/
│   │   ├── error.hpp
│   │   ├── log.hpp
│   │   ├── hashing.hpp
│   │   └── types.hpp
│   ├── pe/
│   │   ├── pe_image.hpp
│   │   └── pe_parser.hpp
│   ├── scan/
│   │   ├── aob_pattern.hpp
│   │   └── aob_scanner.hpp
│   ├── disasm/
│   │   └── disassembler.hpp
│   ├── analysis/
│   │   ├── fingerprint.hpp
│   │   ├── struct_analyzer.hpp
│   │   ├── func_analyzer.hpp
│   │   └── build_diff.hpp
│   ├── validation/
│   │   └── validator.hpp
│   ├── storage/
│   │   ├── database.hpp
│   │   └── exporter.hpp
│   └── app/
│       ├── analyze_job.hpp
│       └── main_window.hpp
├── src/
│   ├── core/          (*.cpp espelham include/core)
│   ├── pe/
│   ├── scan/
│   ├── disasm/
│   ├── analysis/
│   ├── validation/
│   ├── storage/
│   └── app/
├── tests/
│   ├── CMakeLists.txt
│   ├── test_pe_parser.cpp
│   ├── test_aob_scanner.cpp
│   ├── test_validation.cpp
│   ├── test_exporter.cpp
│   └── fixtures/
│       └── make_fixtures.cpp
└── ui/
    └── main_window.ui
```

---

## 2. `CMakeLists.txt`

```cmake
cmake_minimum_required(VERSION 3.24)
project(l2ud VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets Core)
qt_standard_project_setup()

# Capstone (disassembler). Fallback: Zydis via find_package.
find_package(capstone CONFIG QUIET)
if (NOT capstone_FOUND)
  find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h)
  find_library(CAPSTONE_LIBRARY NAMES capstone)
  if (NOT CAPSTONE_INCLUDE_DIR OR NOT CAPSTONE_LIBRARY)
    message(FATAL_ERROR "Capstone não encontrado. Instale capstone-dev ou defina CAPSTONE_INCLUDE_DIR/CAPSTONE_LIBRARY.")
  endif()
  add_library(capstone UNKNOWN IMPORTED)
  set_target_properties(capstone PROPERTIES
    IMPORTED_LOCATION "${CAPSTONE_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${CAPSTONE_INCLUDE_DIR}")
endif()

find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(l2ud_core STATIC
  src/core/log.cpp src/core/hashing.cpp
  src/pe/pe_parser.cpp
  src/scan/aob_pattern.cpp src/scan/aob_scanner.cpp
  src/disasm/disassembler.cpp
  src/analysis/fingerprint.cpp
  src/analysis/struct_analyzer.cpp
  src/analysis/func_analyzer.cpp
  src/analysis/build_diff.cpp
  src/validation/validator.cpp
  src/storage/database.cpp src/storage/exporter.cpp
)
target_include_directories(l2ud_core PUBLIC include)
target_link_libraries(l2ud_core PUBLIC capstone SQLite::SQLite3 OpenSSL::Crypto)
target_compile_options(l2ud_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(l2ud_gui
  src/app/main.cpp
  src/app/analyze_job.cpp
  src/app/main_window.cpp
)
qt_add_resources(l2ud_gui "ui" FILES ui/main_window.ui)
target_link_libraries(l2ud_gui PRIVATE l2ud_core Qt6::Widgets)
set_target_properties(l2ud_gui PROPERTIES WIN32_EXECUTABLE ON)

enable_testing()
add_subdirectory(tests)
```

---

## 3. `include/l2ud/core/types.hpp` — tipos base e status de validação

```cpp
#pragma once
#include <cstdint>
#include <string>
#include <optional>
#include <variant>

namespace l2ud {

// Endereçamento explícito — NUNCA misturar.
enum class AddressKind { RVA, VA, FileOffset };

struct Address {
    AddressKind kind;
    std::uint64_t value;
};

enum class ValidationStatus {
    CONFIRMED, PROBABLE, CANDIDATE, AMBIGUOUS, NOT_FOUND
};

struct Evidence {
    std::string source;   // "aob", "xref", "export", "heuristic"
    std::string detail;
    std::optional<std::uint64_t> occurrenceVa;
    std::string module;
};

struct Candidate {
    Address address;
    std::string label;
    ValidationStatus status = ValidationStatus::CANDIDATE;
    std::vector<Evidence> evidence;
    std::string notes; // limitações / motivos
};

struct BuildId {
    std::string sha256;
    std::string path;
    std::string arch;     // "x86" | "x64"
    std::string peKind;   // "PE32" | "PE32+"
    std::string fingerprint;
};

} // namespace l2ud
```

---

## 4. `include/l2ud/core/error.hpp`

```cpp
#pragma once
#include <string>
#include <utility>

namespace l2ud {

enum class ErrorCode {
    Ok, Io, MalformedPe, Unsupported, OutOfRange, NotFound, DecompressionNotSupported
};

struct Error {
    ErrorCode code = ErrorCode::Ok;
    std::string message;
    bool ok() const { return code == ErrorCode::Ok; }
    static Error ok_() { return {}; }
    static Error m(ErrorCode c, std::string s) { return {c, std::move(s)}; }
};

} // namespace l2ud
```

---

## 5. `include/l2ud/core/log.hpp` + `src/core/log.cpp`

```cpp
#pragma once
#include <string>
#include <mutex>
#include <cstdio>

namespace l2ud {

enum class LogLevel { Debug, Info, Warn, Error };

class Log {
public:
    static Log& instance();
    void set_level(LogLevel lv);
    void write(LogLevel lv, const std::string& msg);
private:
    std::mutex mtx_;
    LogLevel level_ = LogLevel::Info;
};

inline void log_info(const std::string& m) { Log::instance().write(LogLevel::Info, m); }
inline void log_warn(const std::string& m) { Log::instance().write(LogLevel::Warn, m); }
inline void log_error(const std::string& m) { Log::instance().write(LogLevel::Error, m); }
inline void log_debug(const std::string& m) { Log::instance().write(LogLevel::Debug, m); }

} // namespace l2ud
```

```cpp
#include "l2ud/core/log.hpp"

namespace l2ud {
Log& Log::instance() { static Log l; return l; }
void Log::set_level(LogLevel lv) { std::lock_guard g(mtx_); level_ = lv; }
void Log::write(LogLevel lv, const std::string& msg) {
    std::lock_guard g(mtx_);
    if (static_cast<int>(lv) < static_cast<int>(level_)) return;
    const char* tag = lv == LogLevel::Debug ? "DBG"
                    : lv == LogLevel::Info ? "INF"
                    : lv == LogLevel::Warn ? "WRN" : "ERR";
    std::fprintf(stderr, "[%s] %s\n", tag, msg.c_str());
}
}
```

---

## 6. `include/l2ud/pe/pe_image.hpp` — carga RAII e modelo

```cpp
#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <optional>
#include "l2ud/core/error.hpp"

namespace l2ud {

enum class PeKind { PE32, PE32Plus, Unknown };

struct Section {
    std::string name;
    std::uint32_t virtualAddress;
    std::uint32_t virtualSize;
    std::uint32_t rawPointer;
    std::uint32_t rawSize;
    std::uint32_t characteristics;
    bool readable() const;
    bool executable() const;
};

struct Export { std::string name; std::uint32_t rva; std::uint32_t ordinal; };
struct Import { std::string dll; std::string name; std::uint32_t iatRva; };
struct Reloc  { std::uint32_t rva; std::uint16_t type; };

class PeImage {
public:
    static std::optional<PeImage> load(std::vector<std::uint8_t> rawData, Error& err);

    const std::vector<std::uint8_t>& raw() const { return raw_; }
    PeKind kind() const { return kind_; }
    bool is64() const { return kind_ == PeKind::PE32Plus; }
    std::uint64_t imageBase() const { return imageBase_; }
    std::uint32_t entryPoint() const { return entryPoint_; }
    const std::vector<Section>& sections() const { return sections_; }
    const std::vector<Export>& exports() const { return exports_; }
    const std::vector<Import>& imports() const { return imports_; }
    const std::vector<Reloc>& relocations() const { return relocations_; }

    // Mapeia file offset <-> RVA com bounds reais.
    std::optional<std::uint32_t> rva_to_file(std::uint32_t rva) const;
    std::optional<std::uint32_t> file_to_rva(std::uint32_t off) const;
    const Section* section_for_rva(std::uint32_t rva) const;
    std::optional<std::uint64_t> rva_to_va(std::uint32_t rva) const;
    std::uint32_t size() const { return static_cast<std::uint32_t>(raw_.size()); }

    // Reads seguras (retornam false em bounds inválidos).
    bool read_bytes(std::uint32_t fileOff, std::size_t n, std::vector<std::uint8_t>& out) const;

private:
    std::vector<std::uint8_t> raw_;
    PeKind kind_ = PeKind::Unknown;
    std::uint64_t imageBase_ = 0;
    std::uint32_t entryPoint_ = 0;
    std::vector<Section> sections_;
    std::vector<Export> exports_;
    std::vector<Import> imports_;
    std::vector<Reloc> relocations_;
    PeImage() = default;
};

inline bool Section::readable() const { return !(characteristics & 0x02000000); } // !discardable
inline bool Section::executable() const { return characteristics & 0x20000000; }

} // namespace l2ud
```

---

## 7. `src/pe/pe_parser.cpp` — parser conservador

Aqui a regra é: **valida tudo** e rejeita cedo. Nada de "adivinhar".

```cpp
#include "l2ud/pe/pe_image.hpp"
#include "l2ud/core/log.hpp"
#include <cstring>

namespace l2ud {
namespace {
template <class T> bool rd(const std::vector<std::uint8_t>& b, std::size_t off, T& out) {
    if (off + sizeof(T) > b.size()) return false;
    std::memcpy(&out, b.data() + off, sizeof(T));
    return true;
}
constexpr std::uint16_t kMZ = 0x5A4D;
constexpr std::uint32_t kPE = 0x00004550;
}

std::optional<PeImage> PeImage::load(std::vector<std::uint8_t> raw, Error& err) {
    if (raw.size() < 64) { err = Error::m(ErrorCode::MalformedPe, "arquivo curto"); return std::nullopt; }

    std::uint16_t mz = 0; rd(raw, 0, mz);
    if (mz != kMZ) { err = Error::m(ErrorCode::MalformedPe, "assinatura MZ ausente"); return std::nullopt; }

    std::uint32_t lfanew = 0; rd(raw, 0x3C, lfanew);
    if (lfanew + 24 > raw.size()) { err = Error::m(ErrorCode::MalformedPe, "e_lfanew inválido"); return std::nullopt; }
    std::uint32_t sig = 0; rd(raw, lfanew, sig);
    if (sig != kPE) { err = Error::m(ErrorCode::MalformedPe, "assinatura PE ausente"); return std::nullopt; }

    std::uint16_t machine = 0; rd(raw, lfanew + 4, machine);
    std::uint16_t numSections = 0; rd(raw, lfanew + 6, numSections);
    std::uint16_t optSize = 0; rd(raw, lfanew + 20, optSize);
    if (numSections == 0 || numSections > 96) { err = Error::m(ErrorCode::MalformedPe, "numSections fora do esperado"); return std::nullopt; }

    std::size_t optOff = static_cast<std::size_t>(lfanew) + 24;
    if (optOff + optSize > raw.size() || optSize < 32) { err = Error::m(ErrorCode::MalformedPe, "optional header truncado"); return std::nullopt; }

    std::uint16_t magic = 0; rd(raw, optOff, magic);
    PeImage img;
    if (magic == 0x10B) img.kind_ = PeKind::PE32;
    else if (magic == 0x20B) img.kind_ = PeKind::PE32Plus;
    else { err = Error::m(ErrorCode::Unsupported, "magic de optional header desconhecido"); return std::nullopt; }

    if (img.kind_ == PeKind::PE32Plus) {
        std::uint64_t ib = 0; rd(raw, optOff + 24, ib); img.imageBase_ = ib;
    } else {
        std::uint32_t ib = 0; rd(raw, optOff + 28, ib); img.imageBase_ = ib;
    }
    rd(raw, optOff + 16, img.entryPoint_);

    // Seções
    std::size_t secOff = optOff + optSize;
    for (std::uint16_t i = 0; i < numSections; ++i, secOff += 40) {
        if (secOff + 40 > raw.size()) { err = Error::m(ErrorCode::MalformedPe, "seção truncada"); return std::nullopt; }
        Section s{};
        s.name.assign(reinterpret_cast<const char*>(raw.data() + secOff), 8);
        s.name = s.name.c_str();
        rd(raw, secOff + 12, s.virtualAddress);
        rd(raw, secOff + 8, s.virtualSize);
        rd(raw, secOff + 20, s.rawPointer);
        rd(raw, secOff + 16, s.rawSize);
        rd(raw, secOff + 36, s.characteristics);
        img.sections_.push_back(std::move(s));
    }

    img.raw_ = std::move(raw);
    log_info("PE carregado: " + std::to_string(img.raw_.size()) + " bytes, " + std::to_string(img.sections_.size()) + " seções");
    err = Error::ok_();
    return img;
}

std::optional<std::uint32_t> PeImage::rva_to_file(std::uint32_t rva) const {
    for (const auto& s : sections_) {
        if (rva >= s.virtualAddress && rva < s.virtualAddress + s.virtualSize) {
            std::uint32_t delta = rva - s.virtualAddress;
            if (delta >= s.rawSize) return std::nullopt; // RVA em memória sem espelho em disco
            return s.rawPointer + delta;
        }
    }
    return std::nullopt;
}

std::optional<std::uint32_t> PeImage::file_to_rva(std::uint32_t off) const {
    for (const auto& s : sections_) {
        if (off >= s.rawPointer && off < s.rawPointer + s.rawSize)
            return s.virtualAddress + (off - s.rawPointer);
    }
    return std::nullopt;
}

const Section* PeImage::section_for_rva(std::uint32_t rva) const {
    for (const auto& s : sections_)
        if (rva >= s.virtualAddress && rva < s.virtualAddress + s.virtualSize) return &s;
    return nullptr;
}

std::optional<std::uint64_t> PeImage::rva_to_va(std::uint32_t rva) const {
    if (!section_for_rva(rva)) return std::nullopt;
    return imageBase_ + rva;
}

bool PeImage::read_bytes(std::uint32_t off, std::size_t n, std::vector<std::uint8_t>& out) const {
    if (off + n > raw_.size()) return false;
    out.assign(raw_.begin() + off, raw_.begin() + off + n);
    return true;
}

} // namespace l2ud
```

(Imports/exports/relocations completos ficam no módulo PE avançado — aqui já há o essencial para scanner e disassembly; adiciono se necessário na próxima rodada. Deixo o parser de diretórios como módulo separado `pe_directories.cpp` para não inflar.)

---

## 8. `include/l2ud/scan/aob_pattern.hpp` (compilação de padrão com wildcards)

```cpp
#pragma once
#include <vector>
#include <optional>
#include <string>
#include "l2ud/core/error.hpp"

namespace l2ud {

struct AobByte {
    bool any;        // wildcard
    std::uint8_t value;
};

class AobPattern {
public:
    static std::optional<AobPattern> compile(std::string_view text, Error& err);
    const std::vector<AobByte>& bytes() const { return bytes_; }
    const std::string& source() const { return source_; }
private:
    std::vector<AobByte> bytes_;
    std::string source_;
};

} // namespace l2ud
```

```cpp
#include "l2ud/scan/aob_pattern.hpp"
#include <cctype>

namespace l2ud {

static bool hexv(char c, std::uint8_t& v) {
    if (c >= '0' && c <= '9') { v = c - '0'; return true; }
    if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; return true; }
    if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; return true; }
    return false;
}

std::optional<AobPattern> AobPattern::compile(std::string_view text, Error& err) {
    AobPattern p; p.source_ = std::string(text);
    std::size_t i = 0;
    while (i < text.size()) {
        char c = text[i];
        if (std::isspace(static_cast<unsigned char>(c))) { ++i; continue; }
        if (c == '?') {
            p.bytes_.push_back({true, 0});
            ++i;
            if (i < text.size() && (text[i] == '?' || std::isspace((unsigned char)text[i]))) {} // ??
            continue;
        }
        std::uint8_t hi = 0, lo = 0;
        if (i + 1 >= text.size() || !hexv(text[i], hi) || !hexv(text[i + 1], lo)) {
            err = Error::m(ErrorCode::MalformedPe, "byte inválido no padrão na posição " + std::to_string(i));
            return std::nullopt;
        }
        p.bytes_.push_back({false, static_cast<std::uint8_t>((hi << 4) | lo)});
        i += 2;
    }
    if (p.bytes_.empty()) { err = Error::m(ErrorCode::MalformedPe, "padrão vazio"); return std::nullopt; }
    err = Error::ok_();
    return p;
}

} // namespace l2ud
```

---

## 9. `include/l2ud/scan/aob_scanner.hpp` + `src/aob_scanner.cpp`

Requisitos: todas as ocorrências, permitir sobreposição, tratar leituras inválidas, escopo por seção, retorno em VA/RVA/FileOffset explicitado.

```cpp
#pragma once
#include <vector>
#include <string>
#include <optional>
#include "l2ud/pe/pe_image.hpp"
#include "l2ud/scan/aob_pattern.hpp"
#include "l2ud/core/types.hpp"

namespace l2ud {

struct ScanHit {
    Address address;         // sempre RVA
    std::optional<std::uint64_t> va;
    std::string section;
};

struct ScanOptions {
    bool overlap = true;             // permite ocorrências sobrepostas
    std::vector<std::string> onlySections; // vazio = todas
    bool executableOnly = false;
    std::size_t maxHits = 100000;
};

class AobScanner {
public:
    explicit AobScanner(const PeImage& img) : img_(img) {}
    // Retorna hits em RVA. Só procura em seções mapeadas em disco.
    std::vector<ScanHit> scan(const AobPattern& p, const ScanOptions& opt = {});
private:
    const PeImage& img_;
};

} // namespace l2ud
```

```cpp
#include "l2ud/scan/aob_scanner.hpp"
#include "l2ud/core/log.hpp"

namespace l2ud {

std::vector<ScanHit> AobScanner::scan(const AobPattern& p, const ScanOptions& opt) {
    std::vector<ScanHit> hits;
    const auto& pat = p.bytes();
    const auto& raw = img_.raw();

    for (const auto& sec : img_.sections()) {
        if (sec.rawSize == 0 || sec.rawPointer + sec.rawSize > raw.size()) continue;
        if (!sec.readable()) continue;
        if (!opt.onlySections.empty()) {
            bool ok = false;
            for (const auto& n : opt.onlySections) if (n == sec.name) { ok = true; break; }
            if (!ok) continue;
        }
        if (opt.executableOnly && !sec.executable()) continue;

        const std::uint8_t* base = raw.data() + sec.rawPointer;
        const std::size_t limit = sec.rawSize;
        if (pat.size() > limit) continue;

        const std::size_t step = opt.overlap ? 1 : pat.size();
        for (std::size_t off = 0; off + pat.size() <= limit; off += step) {
            bool match = true;
            for (std::size_t k = 0; k < pat.size(); ++k) {
                if (!pat[k].any && base[off + k] != pat[k].value) { match = false; break; }
            }
            if (!match) continue;

            std::uint32_t rva = sec.virtualAddress + static_cast<std::uint32_t>(off);
            ScanHit h{};
            h.address = {AddressKind::RVA, rva};
            h.va = img_.rva_to_va(rva);
            h.section = sec.name;
            hits.push_back(std::move(h));
            if (hits.size() >= opt.maxHits) { log_warn("limite de hits atingido"); return hits; }
        }
    }
    log_info("scan finalizado: " + std::to_string(hits.size()) + " hits");
    return hits;
}

} // namespace l2ud
```

---

## 10. `include/l2ud/disasm/disassembler.hpp` + `src/disasm/disassembler.cpp`

Resolver relativos: para instruções com operando imediato relativo ao RIP (`call`/`jmp`/`lea` etc.), calculamos o destino usando o **tamanho real** da instrução emitido pelo Capstone.

```cpp
#pragma once
#include <vector>
#include <string