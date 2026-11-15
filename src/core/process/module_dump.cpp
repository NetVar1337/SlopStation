#include "core/process/module_dump.hpp"

#include "core/disasm/pe_parser.hpp"
#include "core/memory/read_ahead.hpp"
#include "core/runtime/session.hpp"

#include "core/infra/paths.hpp"

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#else
#include <unistd.h>

// The PE structs module_dump walks come from <windows.h> on Windows. These are
// the same layouts, only the fields this file reads.
#pragma pack(push, 1)
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp;
    uint16_t e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid, e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};
struct IMAGE_FILE_HEADER {
    uint16_t Machine, NumberOfSections;
    uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    uint16_t SizeOfOptionalHeader, Characteristics;
};
struct IMAGE_SECTION_HEADER {
    uint8_t  Name[8];
    union { uint32_t VirtualSize; } Misc;
    uint32_t VirtualAddress, SizeOfRawData, PointerToRawData;
    uint32_t PointerToRelocations, PointerToLinenumbers;
    uint16_t NumberOfRelocations, NumberOfLinenumbers;
    uint32_t Characteristics;
};
struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode, BaseOfData;
    uint32_t ImageBase, SectionAlignment, FileAlignment;
    uint16_t MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint32_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
    uint8_t  DataDirectory[16 * 8];
};
struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint64_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
    uint8_t  DataDirectory[16 * 8];
};
#pragma pack(pop)

inline constexpr uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;
inline constexpr uint32_t IMAGE_NT_SIGNATURE = 0x00004550;
inline constexpr uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B;
inline constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;
#endif

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <system_error>
#include <unordered_map>

namespace slop::core::process {

namespace {

constexpr size_t kMaxHeaderBytes = 4u * 1024u * 1024u;
constexpr size_t kMaxOutputBytes = 512u * 1024u * 1024u;
constexpr uint16_t kMaxSections = 256;

bool add_fits(size_t a, size_t b, size_t limit, size_t& sum) {
    if (a > limit || b > limit - a) return false;
    sum = a + b;
    return true;
}

bool read_exact(const module_read_fn_t& read, uintptr_t address, void* dst,
                size_t size, size_t chunk_size) {
    auto* out = static_cast<uint8_t*>(dst);
    size_t done = 0;
    const size_t chunk = std::max<size_t>(chunk_size, 4096);
    while (done < size) {
        const size_t take = std::min(chunk, size - done);
        const auto io = read(address + done, out + done, take);
        if (!io.ok || io.bytes != take) return false;
        done += take;
    }
    return true;
}

bool write_atomic(const std::string& output_path,
                  const std::vector<uint8_t>& data, std::string& error) {
#ifndef _WIN32
    // same contract: temp file, flushed, renamed over the destination
    const std::string tmp = output_path + ".slop-tmp-" + std::to_string(::getpid());
    {
        std::FILE* f = std::fopen(tmp.c_str(), "wb");
        if (!f) {
            error = "failed to create temporary dump file";
            return false;
        }
        const size_t n = std::fwrite(data.data(), 1, data.size(), f);
        const bool flushed = std::fflush(f) == 0;
        std::fclose(f);
        if (n != data.size() || !flushed) {
            std::remove(tmp.c_str());
            error = "failed to write dump file";
            return false;
        }
    }
    if (std::rename(tmp.c_str(), output_path.c_str()) != 0) {
        std::remove(tmp.c_str());
        error = "failed to replace the dump file";
        return false;
    }
    return true;
#else
    const std::filesystem::path final_path{output_path};
    if (final_path.empty()) {
        error = "output path is empty";
        return false;
    }

    const auto temporary = final_path.wstring() + L".slop-tmp-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64());
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY |
                              FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = "failed to create temporary dump file (error " +
                std::to_string(GetLastError()) + ")";
        return false;
    }

    bool ok = true;
    size_t written_total = 0;
    while (written_total < data.size()) {
        const DWORD take = static_cast<DWORD>(std::min<size_t>(
            data.size() - written_total, 1u * 1024u * 1024u));
        DWORD written = 0;
        if (!WriteFile(file, data.data() + written_total, take, &written,
                       nullptr) || written != take) {
            ok = false;
            break;
        }
        written_total += written;
    }
    if (ok) ok = FlushFileBuffers(file) != FALSE;
    CloseHandle(file);

    if (ok) {
        ok = MoveFileExW(temporary.c_str(), final_path.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
    }
    if (!ok) {
        const DWORD code = GetLastError();
        DeleteFileW(temporary.c_str());
        error = "failed to write dump file (error " + std::to_string(code) + ")";
    }
    return ok;
#endif
}

uint32_t sane_align(uint32_t a, uint32_t fallback) {
    return (a != 0 && (a & (a - 1)) == 0 && a <= 0x10000000u) ? a : fallback;
}

uint64_t align_up(uint64_t v, uint64_t a) { return (v + a - 1) & ~(a - 1); }

bool in_buf(const std::vector<uint8_t>& b, uint64_t off, uint64_t n) {
    return off <= b.size() && n <= b.size() - off;
}

template <typename T>
T get_at(const std::vector<uint8_t>& b, size_t off) {
    T v{};
    std::memcpy(&v, b.data() + off, sizeof(T));
    return v;
}

template <typename T>
void put_at(std::vector<uint8_t>& b, size_t off, T v) {
    std::memcpy(b.data() + off, &v, sizeof(T));
}

uint32_t rd32p(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

std::string lower_ascii(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// "KERNEL32.DLL" -> "kernel32" (forwarder strings name the dll without extension)
std::string module_stem(const std::string& name) {
    auto l = lower_ascii(name);
    const auto dot = l.rfind('.');
    return dot == std::string::npos ? l : l.substr(0, dot);
}

struct export_ref_t {
    uint32_t module = 0;   // index into options.import_modules
    uint16_t ordinal = 0;
    std::string name;      // empty = ordinal only
};
using export_map_t = std::unordered_map<uint64_t, std::vector<export_ref_t>>;

struct forward_t {
    uint32_t module = 0;
    uint16_t ordinal = 0;
    std::string name;
    std::string target;    // "NTDLL.RtlAllocateHeap" or "DLL.#12"
    bool done = false;
};

constexpr uint32_t kMaxExports = 1u << 17;
constexpr size_t kMaxExportSpan = 32u * 1024u * 1024u;

// export table of a loaded module, read from target memory (untrusted)
void read_exports(uint32_t idx, const runtime::module_info_t& m,
                  const module_read_fn_t& read, size_t chunk, export_map_t& out,
                  std::unordered_map<std::string, uint64_t>& by_key,
                  std::vector<forward_t>& fwd) {
    if (m.base == 0 || m.size < 0x200) return;
    auto rd = [&](uint64_t rva, void* dst, uint64_t n) {
        return rva <= m.size && n <= m.size - rva &&
               read_exact(read, m.base + static_cast<uintptr_t>(rva), dst,
                          static_cast<size_t>(n), chunk);
    };
    IMAGE_DOS_HEADER dos{};
    if (!rd(0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x10000)
        return;
    uint8_t h[4 + 20 + 120];
    if (!rd(static_cast<uint32_t>(dos.e_lfanew), h, sizeof(h))) return;
    if (rd32p(h) != IMAGE_NT_SIGNATURE) return;
    const uint16_t optsz = static_cast<uint16_t>(h[4 + 16] | (h[4 + 17] << 8));
    const uint16_t magic = static_cast<uint16_t>(h[24] | (h[25] << 8));
    const bool p64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if (!p64 && magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return;
    if (optsz < (p64 ? 120 : 104)) return;
    if (rd32p(h + 24 + (p64 ? 108 : 92)) < 1) return;
    const uint32_t er = rd32p(h + 24 + (p64 ? 112 : 96));
    const uint32_t es = rd32p(h + 24 + (p64 ? 116 : 100));
    if (er == 0 || es < 40) return;
    uint8_t ed[40];
    if (!rd(er, ed, sizeof(ed))) return;
    const uint32_t ord_base = rd32p(ed + 16), nf = rd32p(ed + 20), nn = rd32p(ed + 24);
    const uint32_t af = rd32p(ed + 28), an = rd32p(ed + 32), ao = rd32p(ed + 36);
    if (nf == 0 || nf > kMaxExports || nn > nf) return;
    std::vector<uint32_t> funcs(nf);
    if (!rd(af, funcs.data(), uint64_t{nf} * 4)) return;

    std::vector<std::string> fname(nf);
    std::vector<uint32_t> names(nn);
    std::vector<uint16_t> ords(nn);
    if (nn && rd(an, names.data(), uint64_t{nn} * 4) && rd(ao, ords.data(), uint64_t{nn} * 2)) {
        uint32_t lo = UINT32_MAX, hi = 0;
        for (auto r : names)
            if (r != 0 && r < m.size) { lo = std::min(lo, r); hi = std::max(hi, r); }
        if (lo <= hi) {
            const uint64_t span = std::min<uint64_t>(uint64_t{hi} + 256, m.size) - lo;
            std::vector<char> buf(static_cast<size_t>(span));
            if (span <= kMaxExportSpan && rd(lo, buf.data(), span)) {
                for (uint32_t i = 0; i < nn; ++i) {
                    if (ords[i] >= nf || names[i] < lo || names[i] - lo >= span) continue;
                    const size_t off = names[i] - lo;
                    fname[ords[i]].assign(buf.data() + off,
                                          strnlen(buf.data() + off, std::min<size_t>(span - off, 255)));
                }
            }
        }
    }

    std::vector<char> dir;
    bool have_dir = false;
    if (es <= kMaxExportSpan) {
        dir.resize(es);
        have_dir = rd(er, dir.data(), es);
    }
    const std::string stem = module_stem(m.name);
    for (uint32_t i = 0; i < nf; ++i) {
        const uint32_t r = funcs[i];
        if (r == 0) continue;
        const auto ordinal = static_cast<uint16_t>(ord_base + i);
        if (r >= er && r - er < es) {
            if (have_dir) {
                const size_t off = r - er;
                std::string t(dir.data() + off, strnlen(dir.data() + off, std::min<size_t>(es - off, 255)));
                if (!t.empty()) fwd.push_back({idx, ordinal, fname[i], std::move(t)});
            }
            continue;
        }
        if (r >= m.size) continue;
        const uint64_t va = m.base + r;
        out[va].push_back({idx, ordinal, fname[i]});
        if (!fname[i].empty()) by_key[stem + "!" + fname[i]] = va;
        by_key[stem + "!#" + std::to_string(ordinal)] = va;
    }
}

// a forwarded export (kernel32!HeapAlloc -> ntdll!RtlAllocateHeap) lands in the
// IAT as the target's address; alias that address back to the forwarding name
void resolve_forwarders(const std::vector<runtime::module_info_t>& mods,
                        std::vector<forward_t>& fwd, export_map_t& out,
                        std::unordered_map<std::string, uint64_t>& by_key) {
    for (int pass = 0; pass < 2; ++pass) {   // two passes cover one level of chained forwarders
        for (auto& f : fwd) {
            if (f.done) continue;
            const auto dot = f.target.rfind('.');
            if (dot == std::string::npos || dot == 0 || dot + 1 >= f.target.size()) continue;
            const auto it = by_key.find(lower_ascii(f.target.substr(0, dot)) + "!" +
                                        f.target.substr(dot + 1));
            if (it == by_key.end()) continue;
            const uint64_t va = it->second;
            out[va].push_back({f.module, f.ordinal, f.name});
            const std::string stem = module_stem(mods[f.module].name);
            if (!f.name.empty()) by_key[stem + "!" + f.name] = va;
            by_key[stem + "!#" + std::to_string(f.ordinal)] = va;
            f.done = true;
        }
    }
}

struct import_entry_t {
    uint32_t slot_rva = 0;
    export_ref_t ref;
};
struct import_desc_t {
    uint32_t module = 0;
    std::vector<import_entry_t> entries;
};

// one contiguous run of IAT slots -> descriptors; each slot prefers the module
// most of the run resolves to (so forwarder aliases stay with their dll)
void resolve_run(const std::vector<std::pair<uint32_t, uint64_t>>& run, size_t ptr_size,
                 const export_map_t& ex, std::vector<import_desc_t>& out, size_t& unresolved) {
    std::unordered_map<uint32_t, size_t> votes;
    for (const auto& [slot, value] : run) {
        const auto it = ex.find(value);
        if (it == ex.end()) continue;
        std::vector<uint32_t> seen;
        for (const auto& r : it->second)
            if (std::find(seen.begin(), seen.end(), r.module) == seen.end()) {
                seen.push_back(r.module);
                ++votes[r.module];
            }
    }
    import_desc_t* cur = nullptr;
    uint32_t prev_slot = 0;
    for (const auto& [slot, value] : run) {
        const auto it = ex.find(value);
        if (it == ex.end()) {
            if (value != 0) ++unresolved;
            cur = nullptr;
            continue;
        }
        const export_ref_t* best = nullptr;
        size_t best_votes = 0;
        for (const auto& r : it->second) {
            const size_t v = votes[r.module];
            if (!best || v > best_votes ||
                (v == best_votes && r.module == best->module && best->name.empty() && !r.name.empty())) {
                best = &r;
                best_votes = v;
            }
        }
        if (!cur || cur->module != best->module || slot != prev_slot + ptr_size) {
            out.push_back({best->module, {}});
            cur = &out.back();
        }
        cur->entries.push_back({slot, *best});
        prev_slot = slot;
    }
}

} // namespace

module_dump_result_t reconstruct_mapped_pe(
    uintptr_t module_base, uint32_t module_size, const module_read_fn_t& read,
    std::vector<uint8_t>& output, const module_dump_options_t& options) {
    module_dump_result_t result;
    result.module_base = module_base;
    output.clear();

    if (module_base == 0 || module_size < sizeof(IMAGE_DOS_HEADER) || !read) {
        result.error = "invalid module range or reader";
        return result;
    }

    IMAGE_DOS_HEADER dos{};
    if (!read_exact(read, module_base, &dos, sizeof(dos), options.chunk_size)) {
        result.error = "failed to read DOS header";
        return result;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        static_cast<size_t>(dos.e_lfanew) > kMaxHeaderBytes) {
        result.error = "module does not contain a valid DOS header";
        return result;
    }

    const size_t nt_offset = static_cast<size_t>(dos.e_lfanew);
    size_t coff_end = 0;
    if (!add_fits(nt_offset, sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER),
                  kMaxHeaderBytes, coff_end)) {
        result.error = "PE header offset is out of range";
        return result;
    }
    std::vector<uint8_t> prefix(coff_end);
    if (!read_exact(read, module_base, prefix.data(), prefix.size(),
                    options.chunk_size)) {
        result.error = "failed to read PE header";
        return result;
    }
    uint32_t signature = 0;
    IMAGE_FILE_HEADER file_header{};
    std::memcpy(&signature, prefix.data() + nt_offset, sizeof(signature));
    std::memcpy(&file_header, prefix.data() + nt_offset + sizeof(signature),
                sizeof(file_header));
    if (signature != IMAGE_NT_SIGNATURE || file_header.NumberOfSections == 0 ||
        file_header.NumberOfSections > kMaxSections) {
        result.error = "module does not contain a valid PE header";
        return result;
    }
    if (file_header.SizeOfOptionalHeader < sizeof(uint16_t)) {
        result.error = "PE optional header is truncated";
        return result;
    }

    size_t optional_offset = coff_end;
    size_t section_table = 0;
    size_t section_table_end = 0;
    if (!add_fits(optional_offset, file_header.SizeOfOptionalHeader,
                  kMaxHeaderBytes, section_table) ||
        !add_fits(section_table,
                  static_cast<size_t>(file_header.NumberOfSections) *
                      sizeof(IMAGE_SECTION_HEADER),
                  kMaxHeaderBytes, section_table_end)) {
        result.error = "PE section table is out of range";
        return result;
    }

    std::vector<uint8_t> tables(section_table_end);
    if (!read_exact(read, module_base, tables.data(), tables.size(),
                    options.chunk_size)) {
        result.error = "failed to read PE section table";
        return result;
    }

    uint16_t optional_magic = 0;
    std::memcpy(&optional_magic, tables.data() + optional_offset,
                sizeof(optional_magic));
    const bool pe64 = optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    uint32_t file_alignment = 0;
    uint32_t section_alignment = 0;
    if (pe64) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
            result.error = "PE32+ optional header is truncated";
            return result;
        }
        IMAGE_OPTIONAL_HEADER64 optional{};
        std::memcpy(&optional, tables.data() + optional_offset, sizeof(optional));
        size_of_image = optional.SizeOfImage;
        size_of_headers = optional.SizeOfHeaders;
        file_alignment = optional.FileAlignment;
        section_alignment = optional.SectionAlignment;
    } else if (optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
            result.error = "PE32 optional header is truncated";
            return result;
        }
        IMAGE_OPTIONAL_HEADER32 optional{};
        std::memcpy(&optional, tables.data() + optional_offset, sizeof(optional));
        size_of_image = optional.SizeOfImage;
        size_of_headers = optional.SizeOfHeaders;
        file_alignment = optional.FileAlignment;
        section_alignment = optional.SectionAlignment;
    } else {
        result.error = "unsupported PE optional-header magic";
        return result;
    }

    if (size_of_image == 0 || size_of_headers < section_table_end ||
        size_of_headers > kMaxHeaderBytes || size_of_image > kMaxOutputBytes) {
        result.error = "PE image/header sizes are invalid";
        return result;
    }
    if (module_size < size_of_image) {
        result.warnings.push_back("enumerated module size is smaller than SizeOfImage");
    }

    const bool virt = options.layout == pe_layout_t::virtual_image;
    result.layout = virt ? "virtual" : "file";
    const uint32_t falign = sane_align(file_alignment, 0x200);
    const uint32_t salign = std::max(sane_align(section_alignment, 0x1000), falign);
    const size_t ptr_size = pe64 ? 8 : 4;
    // header field offsets inside the image (optional header layout)
    const size_t opt_off = optional_offset;
    const size_t dd_off = opt_off + (pe64 ? 112 : 96);
    const uint32_t rva_count = get_at<uint32_t>(tables, opt_off + (pe64 ? 108 : 92));
    auto dir_ok = [&](size_t index) {
        return rva_count > index &&
               file_header.SizeOfOptionalHeader >= (dd_off - opt_off) + (index + 1) * 8;
    };

    std::vector<IMAGE_SECTION_HEADER> sections(file_header.NumberOfSections);
    std::memcpy(sections.data(), tables.data() + section_table,
                sections.size() * sizeof(IMAGE_SECTION_HEADER));

    // the mapped image, rva-indexed; every layout is emitted from it
    std::vector<uint8_t> mapped(std::max(size_of_image, size_of_headers), 0);
    if (!read_exact(read, module_base, mapped.data(), size_of_headers,
                    options.chunk_size)) {
        result.error = "failed to read complete PE headers";
        return result;
    }

    bool complete = true;
    std::vector<uint32_t> extents(sections.size(), 0);   // bytes of each section taken from memory
    for (size_t i = 0; i < sections.size(); ++i) {
        const auto& section = sections[i];
        const uint32_t vsize = section.Misc.VirtualSize;
        const uint64_t want = virt ? std::max<uint64_t>(vsize, section.SizeOfRawData)
                                   : section.SizeOfRawData;
        if (want == 0) continue;
        uint64_t readable = 0;
        if (section.VirtualAddress < size_of_image)
            readable = std::min<uint64_t>(want, size_of_image - section.VirtualAddress);
        extents[i] = static_cast<uint32_t>(readable);
        if (readable != 0 && !read_exact(
                read, module_base + section.VirtualAddress,
                mapped.data() + section.VirtualAddress, static_cast<size_t>(readable),
                options.chunk_size)) {
            if (options.strict_reads) {
                result.error = "failed to read section " +
                    std::string(reinterpret_cast<const char*>(section.Name),
                                strnlen(reinterpret_cast<const char*>(section.Name), 8));
                return result;
            }
            std::fill_n(mapped.data() + section.VirtualAddress, static_cast<size_t>(readable), 0);
            complete = false;
        }
        if (!virt && readable < section.SizeOfRawData) {
            complete = false;
            result.warnings.push_back("section data extends beyond SizeOfImage and was zero-filled");
        }
    }

    // raw placement of the original sections
    std::vector<uint32_t> raw_ptr(sections.size()), raw_size(sections.size());
    size_t output_size = size_of_headers;
    for (size_t i = 0; i < sections.size(); ++i) {
        uint64_t ptr = sections[i].PointerToRawData, size = sections[i].SizeOfRawData;
        if (virt) {
            ptr = sections[i].VirtualAddress;
            size = align_up(extents[i], falign);
        }
        if (ptr + size > kMaxOutputBytes) {
            result.error = "PE section raw range is out of bounds";
            return result;
        }
        raw_ptr[i] = static_cast<uint32_t>(ptr);
        raw_size[i] = static_cast<uint32_t>(size);
        output_size = std::max<size_t>(output_size, static_cast<size_t>(ptr + size));
    }
    if (virt) output_size = std::max<size_t>(output_size, 1024);
    if (output_size < 1024 || output_size > kMaxOutputBytes) {
        result.error = "reconstructed PE size is invalid";
        return result;
    }

    // headers are patched in `mapped` and copied out with it
    if (virt) {
        for (size_t i = 0; i < sections.size(); ++i) {
            const size_t sh = section_table + i * sizeof(IMAGE_SECTION_HEADER);
            put_at<uint32_t>(mapped, sh + offsetof(IMAGE_SECTION_HEADER, SizeOfRawData), raw_size[i]);
            put_at<uint32_t>(mapped, sh + offsetof(IMAGE_SECTION_HEADER, PointerToRawData), raw_ptr[i]);
        }
    }
    if (options.rebase) {
        if (pe64) put_at<uint64_t>(mapped, opt_off + 24, static_cast<uint64_t>(module_base));
        else if (static_cast<uint64_t>(module_base) <= 0xFFFFFFFFull)
            put_at<uint32_t>(mapped, opt_off + 28, static_cast<uint32_t>(module_base));
        else result.warnings.push_back("rebase skipped: runtime base does not fit a PE32 ImageBase");
    }
    if (options.oep != 0) {
        uint64_t rva = options.oep;
        if (rva >= size_of_image) {
            if (options.oep < module_base || options.oep - module_base >= size_of_image) {
                result.error = "oep is outside the module (pass an RVA or a VA inside it)";
                return result;
            }
            rva = options.oep - module_base;
        }
        put_at<uint32_t>(mapped, opt_off + 16, static_cast<uint32_t>(rva));
    }
    result.oep_rva = get_at<uint32_t>(mapped, opt_off + 16);

    // IAT reconstruction into an appended .slopimp section
    std::vector<uint8_t> blob;
    uint32_t blob_rva = 0, blob_ptr = 0;
    bool added_section = false;
    if (options.rebuild_imports) {
        export_map_t exports;
        std::unordered_map<std::string, uint64_t> by_key;
        std::vector<forward_t> fwd;
        const auto& mods = options.import_modules;
        for (uint32_t i = 0; i < mods.size() && i < 4096; ++i) {
            if (mods[i].base == module_base) continue;   // own exports are not imports
            read_exports(i, mods[i], read, options.chunk_size, exports, by_key, fwd);
        }
        resolve_forwarders(mods, fwd, exports, by_key);
        // a pointer only counts if it targets another module's export
        auto own = [&](uint64_t v) { return v >= module_base && v - module_base < size_of_image; };
        auto ptr_at = [&](size_t off) {
            return pe64 ? get_at<uint64_t>(mapped, off) : uint64_t{get_at<uint32_t>(mapped, off)};
        };

        std::vector<import_desc_t> descs;
        size_t unresolved = 0;
        // 1) the in-memory import directory, when it survived
        if (dir_ok(1)) {
            const uint32_t imp = get_at<uint32_t>(mapped, dd_off + 8);
            for (uint32_t k = 0; imp != 0 && k < 4096; ++k) {
                const uint64_t d = uint64_t{imp} + uint64_t{k} * 20;
                if (!in_buf(mapped, d, 20)) break;
                const uint32_t oft = get_at<uint32_t>(mapped, static_cast<size_t>(d));
                const uint32_t name = get_at<uint32_t>(mapped, static_cast<size_t>(d + 12));
                const uint32_t ft = get_at<uint32_t>(mapped, static_cast<size_t>(d + 16));
                if (oft == 0 && name == 0 && ft == 0) break;
                std::vector<std::pair<uint32_t, uint64_t>> run;
                for (uint64_t s = ft; ft != 0 && in_buf(mapped, s, ptr_size) && run.size() < 65536;
                     s += ptr_size) {
                    const uint64_t v = ptr_at(static_cast<size_t>(s));
                    if (v == 0) break;
                    run.push_back({static_cast<uint32_t>(s), v});
                }
                resolve_run(run, ptr_size, exports, descs, unresolved);
            }
        }
        // 2) otherwise scan the image for runs of pointers into exports
        if (descs.empty()) {
            unresolved = 0;
            std::vector<std::pair<uint32_t, uint64_t>> run;
            for (size_t off = align_up(size_of_headers, ptr_size); off + ptr_size <= size_of_image;
                 off += ptr_size) {
                const uint64_t v = ptr_at(off);
                if (!own(v) && exports.count(v)) {
                    run.push_back({static_cast<uint32_t>(off), v});
                    continue;
                }
                if (run.size() >= 2 || (run.size() == 1 && v == 0))
                    resolve_run(run, ptr_size, exports, descs, unresolved);
                run.clear();
            }
            if (run.size() >= 2) resolve_run(run, ptr_size, exports, descs, unresolved);
        }

        uint64_t image_end = size_of_image;
        for (const auto& s : sections)
            image_end = std::max<uint64_t>(image_end, uint64_t{s.VirtualAddress} + s.Misc.VirtualSize);
        const size_t new_sh = section_table_end;
        result.import_unresolved = unresolved;
        const bool header_room = in_buf(mapped, new_sh, sizeof(IMAGE_SECTION_HEADER)) &&
                                 new_sh + sizeof(IMAGE_SECTION_HEADER) <= size_of_headers &&
                                 file_header.NumberOfSections < kMaxSections;
        // no header slot: grow the section with the highest RVA instead
        size_t last = 0;
        for (size_t i = 1; i < sections.size(); ++i)
            if (sections[i].VirtualAddress >= sections[last].VirtualAddress) last = i;
        const uint64_t last_end = uint64_t{sections[last].VirtualAddress} +
            std::max<uint64_t>(sections[last].Misc.VirtualSize, sections[last].SizeOfRawData);
        const uint64_t want_rva = header_room ? align_up(image_end, salign) : align_up(last_end, 16);
        if (descs.empty()) {
            result.warnings.push_back("no import thunks resolved to exports of loaded modules");
        } else if (!dir_ok(1)) {
            result.warnings.push_back("optional header has no import directory slot; imports not rebuilt");
        } else if (want_rva > kMaxOutputBytes) {
            result.warnings.push_back("import section would exceed the dump size cap; imports not rebuilt");
        } else {
            blob_rva = static_cast<uint32_t>(want_rva);
            const uint64_t ord_flag = pe64 ? (1ull << 63) : (1ull << 31);
            blob.assign((descs.size() + 1) * 20, 0);
            std::vector<size_t> ilt_at(descs.size()), dll_at(descs.size());
            for (size_t d = 0; d < descs.size(); ++d) {
                blob.resize(align_up(blob.size(), ptr_size), 0);
                ilt_at[d] = blob.size();
                blob.resize(blob.size() + (descs[d].entries.size() + 1) * ptr_size, 0);
            }
            for (size_t d = 0; d < descs.size(); ++d) {
                dll_at[d] = blob.size();
                const auto& n = mods[descs[d].module].name;
                blob.insert(blob.end(), n.begin(), n.end());
                blob.push_back(0);
            }
            std::vector<uint32_t> distinct;
            uint32_t iat_lo = UINT32_MAX, iat_hi = 0;
            std::vector<std::pair<uint32_t, uint64_t>> thunks;   // iat slot -> thunk value
            for (size_t d = 0; d < descs.size(); ++d) {
                const auto& desc = descs[d];
                if (std::find(distinct.begin(), distinct.end(), desc.module) == distinct.end())
                    distinct.push_back(desc.module);
                for (size_t e = 0; e < desc.entries.size(); ++e) {
                    const auto& ent = desc.entries[e];
                    uint64_t thunk = ord_flag | ent.ref.ordinal;
                    if (!ent.ref.name.empty()) {
                        blob.resize(align_up(blob.size(), 2), 0);
                        thunk = blob_rva + blob.size();
                        blob.push_back(0);   // hint
                        blob.push_back(0);
                        blob.insert(blob.end(), ent.ref.name.begin(), ent.ref.name.end());
                        blob.push_back(0);
                    }
                    const size_t slot = ilt_at[d] + e * ptr_size;
                    if (pe64) put_at<uint64_t>(blob, slot, thunk);
                    else put_at<uint32_t>(blob, slot, static_cast<uint32_t>(thunk));
                    thunks.push_back({ent.slot_rva, thunk});
                    iat_lo = std::min(iat_lo, ent.slot_rva);
                    iat_hi = std::max<uint32_t>(iat_hi, ent.slot_rva + static_cast<uint32_t>(ptr_size));
                }
                const size_t dd = d * 20;
                put_at<uint32_t>(blob, dd, blob_rva + static_cast<uint32_t>(ilt_at[d]));
                put_at<uint32_t>(blob, dd + 12, blob_rva + static_cast<uint32_t>(dll_at[d]));
                put_at<uint32_t>(blob, dd + 16, desc.entries.front().slot_rva);
                result.import_functions += desc.entries.size();
            }
            result.import_modules = distinct.size();
            const uint32_t last_va = sections[last].VirtualAddress;
            const uint64_t last_vsize = uint64_t{blob_rva} + blob.size() - last_va;
            const uint64_t blob_raw = align_up(blob.size(), falign);
            const uint64_t last_raw = align_up(last_vsize, falign);
            const uint64_t new_image = header_room
                ? uint64_t{blob_rva} + align_up(blob.size(), salign)
                : std::max<uint64_t>(align_up(size_of_image, salign), align_up(last_va + last_vsize, salign));
            blob_ptr = header_room
                ? (virt ? blob_rva : static_cast<uint32_t>(align_up(output_size, falign)))
                : raw_ptr[last] + (blob_rva - last_va);
            const uint64_t file_end = header_room ? uint64_t{blob_ptr} + blob_raw
                                                  : uint64_t{raw_ptr[last]} + last_raw;
            if (new_image > kMaxOutputBytes || file_end > kMaxOutputBytes) {
                result.warnings.push_back("import section would exceed the dump size cap; imports not rebuilt");
                blob.clear();
                result.import_modules = result.import_functions = 0;
            } else {
                // the loader rewrites the IAT; the file carries the thunks like a fresh link
                for (const auto& [slot, thunk] : thunks) {
                    if (pe64) put_at<uint64_t>(mapped, slot, thunk);
                    else put_at<uint32_t>(mapped, slot, static_cast<uint32_t>(thunk));
                }
                constexpr uint32_t kReadData = 0x40u | 0x40000000u;   // initialized data, read
                if (header_room) {
                    IMAGE_SECTION_HEADER sh{};
                    std::memcpy(sh.Name, ".slopimp", 8);
                    sh.Misc.VirtualSize = static_cast<uint32_t>(blob.size());
                    sh.VirtualAddress = blob_rva;
                    sh.SizeOfRawData = static_cast<uint32_t>(blob_raw);
                    sh.PointerToRawData = blob_ptr;
                    sh.Characteristics = kReadData | 0x80000000u;   // + write
                    std::memcpy(mapped.data() + new_sh, &sh, sizeof(sh));
                    put_at<uint16_t>(mapped, nt_offset + 4 + 2,
                                     static_cast<uint16_t>(file_header.NumberOfSections + 1));
                    added_section = true;
                } else {
                    const size_t sh = section_table + last * sizeof(IMAGE_SECTION_HEADER);
                    put_at<uint32_t>(mapped, sh + offsetof(IMAGE_SECTION_HEADER, Misc),
                                     static_cast<uint32_t>(last_vsize));
                    put_at<uint32_t>(mapped, sh + offsetof(IMAGE_SECTION_HEADER, SizeOfRawData),
                                     static_cast<uint32_t>(last_raw));
                    const size_t ch = sh + offsetof(IMAGE_SECTION_HEADER, Characteristics);
                    put_at<uint32_t>(mapped, ch, get_at<uint32_t>(mapped, ch) | kReadData);
                    raw_size[last] = static_cast<uint32_t>(last_raw);
                    result.warnings.push_back("no room for an extra section header; imports appended to the last section");
                }
                put_at<uint32_t>(mapped, opt_off + 56, static_cast<uint32_t>(new_image));
                put_at<uint32_t>(mapped, dd_off + 8, blob_rva);
                put_at<uint32_t>(mapped, dd_off + 12, static_cast<uint32_t>((descs.size() + 1) * 20));
                if (dir_ok(11)) {   // stale bound imports would short-circuit the loader
                    put_at<uint32_t>(mapped, dd_off + 11 * 8, 0);
                    put_at<uint32_t>(mapped, dd_off + 11 * 8 + 4, 0);
                }
                if (dir_ok(12)) {
                    put_at<uint32_t>(mapped, dd_off + 12 * 8, iat_lo);
                    put_at<uint32_t>(mapped, dd_off + 12 * 8 + 4, iat_hi - iat_lo);
                }
                if (header_room) blob.resize(static_cast<size_t>(blob_raw), 0);
                output_size = std::max<size_t>(output_size, static_cast<size_t>(file_end));
            }
        }
    }
    put_at<uint32_t>(mapped, opt_off + 64, 0);   // CheckSum no longer matches

    output.assign(output_size, 0);
    std::memcpy(output.data(), mapped.data(), size_of_headers);
    for (size_t i = 0; i < sections.size(); ++i) {
        const uint32_t va = sections[i].VirtualAddress;
        if (va >= mapped.size()) continue;
        const size_t take = std::min<size_t>(raw_size[i], mapped.size() - va);
        std::memcpy(output.data() + raw_ptr[i], mapped.data() + va, take);
    }
    if (!blob.empty()) std::memcpy(output.data() + blob_ptr, blob.data(), blob.size());

    const size_t want_sections = sections.size() + (added_section ? 1 : 0);
    const auto parsed = disasm::pe_parse(output.data(), output.size());
    if (!parsed.ok || parsed.sections.size() != want_sections) {
        result.error = "reconstructed image failed PE validation";
        output.clear();
        return result;
    }

    result.ok = true;
    result.complete = complete;
    result.bytes_written = output.size();
    result.section_count = want_sections;
    return result;
}

module_dump_result_t dump_module_pe(
    runtime::session_t& session, const runtime::module_info_t& module,
    const std::string& output_path, const module_dump_options_t& options) {
    std::vector<uint8_t> image;
    auto result = reconstruct_mapped_pe(
        module.base, module.size,
        [&session](uintptr_t address, void* destination, size_t size) {
            return session.read(address, destination, size);
        },
        image, options);
    result.output_path = output_path;
    if (!result.ok) return result;

    if (!write_atomic(output_path, image, result.error)) {
        result.ok = false;
        result.bytes_written = 0;
        return result;
    }
    return result;
}

bool write_minidump(uint32_t pid, const std::string& output_path, bool full,
                    uint64_t& bytes_written, std::string& error) {
    bytes_written = 0;
#ifndef _WIN32
    (void)pid; (void)output_path; (void)full;
    error = "minidump requires Windows";
    return false;
#else
    const std::filesystem::path final_path{output_path};
    if (final_path.empty()) {
        error = "output path is empty";
        return false;
    }
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
                                 FALSE, pid);
    if (!process) {
        error = "OpenProcess failed (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    const auto temporary = final_path.wstring() + L".slop-tmp-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = "failed to create temporary dump file (error " +
                std::to_string(GetLastError()) + ")";
        CloseHandle(process);
        return false;
    }
    const auto type = static_cast<MINIDUMP_TYPE>(
        (full ? MiniDumpWithFullMemory : MiniDumpNormal) | MiniDumpWithHandleData |
        MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules);
    bool ok = MiniDumpWriteDump(process, pid, file, type, nullptr, nullptr, nullptr) != FALSE;
    DWORD code = ok ? 0 : GetLastError();
    LARGE_INTEGER size{};
    if (ok && GetFileSizeEx(file, &size)) bytes_written = static_cast<uint64_t>(size.QuadPart);
    CloseHandle(file);
    CloseHandle(process);
    if (ok && !MoveFileExW(temporary.c_str(), final_path.c_str(),
                           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        ok = false;
        code = GetLastError();
    }
    if (!ok) {
        DeleteFileW(temporary.c_str());
        error = "MiniDumpWriteDump failed (error " + std::to_string(code) + ")";
        bytes_written = 0;
    }
    return ok;
#endif
}

namespace {

constexpr uint64_t kElfPage = 0x4000;   // PS4 page size; also a multiple of 4 KiB

#pragma pack(push, 1)
struct elf64_ehdr_t {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};
struct elf64_phdr_t {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};
#pragma pack(pop)
static_assert(sizeof(elf64_ehdr_t) == 64);
static_assert(sizeof(elf64_phdr_t) == 56);

// copy [start, end) through read into dst; unreadable parts zero-fill (non
// strict) or fail. Returns false only on a strict failure. Chunk reads are
// double-buffered (chunk k+1 streams in while chunk k is validated) and a
// failed chunk is salvaged page by page, so one protected page costs 4 KiB
// of zero-fill, not the whole chunk
bool read_segment(const module_read_fn_t& read, uint64_t start, uint64_t end, uint8_t* dst,
                  const module_dump_options_t& options, module_dump_result_t& result) {
    const size_t chunk = std::max<size_t>(options.chunk_size, 4096);
    uint64_t failed_from = 0, failed_bytes = 0;
    auto note_fail = [&](uint64_t a, size_t n) {
        std::memset(dst + (a - start), 0, n);
        result.complete = false;
        if (!failed_bytes) failed_from = a;
        failed_bytes += n;
    };
    auto flush_warning = [&] {
        if (!failed_bytes) return;
        char b[96];
        std::snprintf(b, sizeof(b), "unreadable 0x%llX..0x%llX zero-filled",
                      static_cast<unsigned long long>(failed_from),
                      static_cast<unsigned long long>(failed_from + failed_bytes));
        result.warnings.emplace_back(b);
        failed_bytes = 0;
    };

    const uint64_t total = end - start;
    const size_t nchunks = static_cast<size_t>((total + chunk - 1) / chunk);
    memory::read_ahead_t ra(read);
    auto cancelled = [&] {
        if (!options.cancel.cancelled()) return false;
        result.error = "cancelled";
        return true;
    };
    auto issue = [&](size_t k) {
        const uint64_t a = start + k * chunk;
        ra.prefetch(static_cast<uintptr_t>(a), dst + (a - start),
                    static_cast<size_t>(std::min<uint64_t>(chunk, end - a)));
    };
    issue(0);
    for (size_t k = 0; k < nchunks; ++k) {
        if (cancelled()) return false;
        if (k + 1 < nchunks) issue(k + 1);
        const uint64_t a = start + k * chunk;
        const size_t take = static_cast<size_t>(std::min<uint64_t>(chunk, end - a));
        const auto io = ra.reap();
        if (options.on_bytes) options.on_bytes(take);
        if (io.ok && io.bytes == take) {
            flush_warning();
            continue;
        }
        if (options.strict_reads) {
            char b[96];
            std::snprintf(b, sizeof(b), "read failed at 0x%llX (%zu bytes)",
                          static_cast<unsigned long long>(a), take);
            result.error = b;
            return false;
        }
        // salvage readable pages inside the failed chunk
        constexpr size_t kPage = 0x1000;
        for (size_t p = 0; p < take;) {
            const size_t step =
                std::min<size_t>(take - p, kPage - ((a + p) & (kPage - 1)));
            const auto pio = read(static_cast<uintptr_t>(a + p), dst + (a - start) + p, step);
            if (pio.ok && pio.bytes == step) flush_warning();
            else note_fail(a + p, step);
            p += step;
        }
    }
    flush_warning();
    return true;
}

bool validate_segments(const std::vector<mapped_segment_t>& segs, std::string& error) {
    if (segs.empty()) { error = "no segments to dump"; return false; }
    uint64_t total = 0;
    for (size_t i = 0; i < segs.size(); ++i) {
        const auto& s = segs[i];
        if (s.end <= s.start) { error = "empty or inverted segment"; return false; }
        if (i > 0 && s.start < segs[i - 1].end) { error = "segments overlap or are unsorted"; return false; }
        total += s.end - s.start;
        if (total > kMaxOutputBytes) { error = "module larger than the dump cap (512 MiB)"; return false; }
    }
    return true;
}

} // namespace

module_dump_result_t reconstruct_elf_from_segments(
    const std::vector<mapped_segment_t>& segments, const module_read_fn_t& read,
    std::vector<uint8_t>& output, const module_dump_options_t& options,
    elf_rebuild_info_t* info) {
    module_dump_result_t result;
    output.clear();
    elf_rebuild_info_t meta;
    if (!validate_segments(segments, result.error)) return result;
    if (segments.size() >= 0xFFFF) {
        result.error = "too many segments for one ELF program header table";
        return result;
    }
    const uint64_t base = segments.front().start;
    const uint64_t end  = segments.back().end;
    result.module_base = base;
    result.complete = true;

    // layout: ehdr, phdrs, then every segment at a page-aligned offset whose
    // residue matches its vaddr (p_offset % p_align == p_vaddr % p_align)
    const size_t n = segments.size();
    uint64_t off = align_up(sizeof(elf64_ehdr_t) + n * sizeof(elf64_phdr_t), kElfPage);
    std::vector<uint64_t> offsets(n);
    for (size_t i = 0; i < n; ++i) {
        off += (segments[i].start - off) & (kElfPage - 1);   // match the residue
        offsets[i] = off;
        off += segments[i].end - segments[i].start;
    }
    if (off > kMaxOutputBytes) {
        result.error = "reconstructed ELF larger than the dump cap (512 MiB)";
        return result;
    }
    output.assign(static_cast<size_t>(off), 0);

    for (size_t i = 0; i < n; ++i) {
        if (!read_segment(read, segments[i].start, segments[i].end,
                          output.data() + offsets[i], options, result)) {
            output.clear();
            result.complete = false;
            return result;
        }
    }

    // an in-memory ELF header (rare on PS4: the SELF loader maps only the
    // segments) tells us the entry point and the original type
    const uint8_t* first = output.data() + offsets[0];
    const uint64_t first_len = segments[0].end - segments[0].start;
    if (first_len >= sizeof(elf64_ehdr_t) && std::memcmp(first, "\x7f" "ELF", 4) == 0 &&
        first[4] == 2 /*ELFCLASS64*/) {
        elf64_ehdr_t src{};
        std::memcpy(&src, first, sizeof(src));
        meta.had_header = true;
        meta.source_type = src.e_type;
        const uint64_t span = end - base;
        if (src.e_entry >= base && src.e_entry < end) meta.entry = src.e_entry;          // absolute
        else if (src.e_entry != 0 && src.e_entry < span) meta.entry = base + src.e_entry; // PIE-relative
    }

    // PS4's SELF loader maps only the segments, so the header (and its entry)
    // is usually absent: without a start address the analyzer begins at VA 0
    // and finds almost nothing. The first executable segment is the code.
    if (meta.entry == 0) {
        std::vector<size_t> order(n);
        for (size_t i = 0; i < n; ++i) order[i] = i;
        std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
            return segments[a].start < segments[b].start;
        });
        for (size_t idx : order) {
            if ((segments[idx].prot & 4u) != 0) {   // execute, per the p_flags mapping below
                meta.entry = segments[idx].start;
                break;
            }
        }
    }

    elf64_ehdr_t eh{};
    const uint8_t ident[16] = {0x7F, 'E', 'L', 'F', 2 /*64-bit*/, 1 /*LE*/, 1 /*version*/,
                               9 /*FreeBSD*/, 0, 0, 0, 0, 0, 0, 0, 0};
    std::memcpy(eh.e_ident, ident, sizeof(ident));
    eh.e_type      = 2;      // ET_EXEC: p_vaddr are the runtime addresses
    eh.e_machine   = 62;     // EM_X86_64
    eh.e_version   = 1;
    eh.e_entry     = meta.entry;
    eh.e_phoff     = sizeof(elf64_ehdr_t);
    eh.e_shoff     = 0;
    eh.e_ehsize    = sizeof(elf64_ehdr_t);
    eh.e_phentsize = sizeof(elf64_phdr_t);
    eh.e_phnum     = static_cast<uint16_t>(n);
    eh.e_shentsize = 64;
    eh.e_shnum     = 0;
    eh.e_shstrndx  = 0;
    std::memcpy(output.data(), &eh, sizeof(eh));
    for (size_t i = 0; i < n; ++i) {
        const auto& s = segments[i];
        elf64_phdr_t ph{};
        ph.p_type   = 1;   // PT_LOAD
        ph.p_flags  = ((s.prot & 1) ? 4u : 0u) | ((s.prot & 2) ? 2u : 0u) | ((s.prot & 4) ? 1u : 0u);
        ph.p_offset = offsets[i];
        ph.p_vaddr  = s.start;
        ph.p_paddr  = s.start;
        ph.p_filesz = s.end - s.start;
        ph.p_memsz  = s.end - s.start;
        ph.p_align  = kElfPage;
        std::memcpy(output.data() + sizeof(eh) + i * sizeof(ph), &ph, sizeof(ph));
    }
    meta.segments = n;
    result.ok = true;
    result.bytes_written = output.size();
    result.section_count = n;
    if (!meta.had_header)
        result.warnings.emplace_back("no ELF header in memory: rebuilt one from the console maps "
                                     "(entry unknown, no section headers/symbols)");
    if (info) *info = meta;
    return result;
}

module_dump_result_t dump_raw_span(const std::vector<mapped_segment_t>& segments,
                                   const module_read_fn_t& read, std::vector<uint8_t>& output,
                                   const module_dump_options_t& options) {
    module_dump_result_t result;
    output.clear();
    if (!validate_segments(segments, result.error)) return result;
    const uint64_t base = segments.front().start;
    const uint64_t span = segments.back().end - base;
    if (span > kMaxOutputBytes) {
        result.error = "module span larger than the dump cap (512 MiB)";
        return result;
    }
    result.module_base = base;
    result.complete = true;
    output.assign(static_cast<size_t>(span), 0);   // gaps stay zero
    for (const auto& s : segments) {
        if (!read_segment(read, s.start, s.end, output.data() + (s.start - base), options, result)) {
            output.clear();
            result.complete = false;
            return result;
        }
    }
    result.ok = true;
    result.bytes_written = output.size();
    result.section_count = segments.size();
    return result;
}

bool write_dump_file(const std::string& output_path, const std::vector<uint8_t>& data,
                     std::string& error) {
    return write_atomic(output_path, data, error);
}

} // namespace slop::core::process
