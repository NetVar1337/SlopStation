#include "harness.hpp"

#include "core/disasm/pe_parser.hpp"
#include "core/memory/read_ahead.hpp"
#include "core/process/module_dump.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/session.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <thread>
#include <vector>

namespace {

constexpr uintptr_t kImageBase = 0x140000000ull;

std::vector<uint8_t> make_mapped_image() {
    std::vector<uint8_t> image(0x3000, 0);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 2;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE |
                                     IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt->OptionalHeader.BaseOfCode = 0x1000;
    nt->OptionalHeader.ImageBase = kImageBase;
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.SizeOfImage = 0x3000;
    nt->OptionalHeader.SizeOfHeaders = 0x200;
    nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    auto* sections = IMAGE_FIRST_SECTION(nt);
    std::memcpy(sections[0].Name, ".text", 5);
    sections[0].Misc.VirtualSize = 0x180;
    sections[0].VirtualAddress = 0x1000;
    sections[0].SizeOfRawData = 0x200;
    sections[0].PointerToRawData = 0x200;
    sections[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                                  IMAGE_SCN_MEM_READ;

    std::memcpy(sections[1].Name, ".data", 5);
    sections[1].Misc.VirtualSize = 0x100;
    sections[1].VirtualAddress = 0x2000;
    sections[1].SizeOfRawData = 0x200;
    sections[1].PointerToRawData = 0x400;
    sections[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                  IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    std::fill_n(image.begin() + 0x1000, 0x200, uint8_t{0x90});
    image[0x1000] = 0xCC;
    std::fill_n(image.begin() + 0x2000, 0x200, uint8_t{0x42});
    image[0x2000] = 0x7A;
    return image;
}

slop::core::process::module_read_fn_t reader_for(
    const std::vector<uint8_t>& image, uintptr_t fail_begin = 0,
    uintptr_t fail_end = 0) {
    return [&image, fail_begin, fail_end](uintptr_t address, void* output,
                                          size_t size) {
        slop::core::runtime::io_result_t result;
        if (address < kImageBase || size > image.size() ||
            address - kImageBase > image.size() - size ||
            (fail_begin < fail_end && address < fail_end &&
             address + size > fail_begin)) {
            result.error = ERROR_PARTIAL_COPY;
            return result;
        }
        std::memcpy(output, image.data() + (address - kImageBase), size);
        result.ok = true;
        result.bytes = size;
        return result;
    };
}

} // namespace

TEST_CASE(module_dump_reconstructs_file_layout) {
    const auto mapped = make_mapped_image();
    std::vector<uint8_t> output;
    const auto result = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), reader_for(mapped), output);

    REQUIRE(result.ok);
    REQUIRE(result.complete);
    REQUIRE_EQ(result.section_count, size_t{2});
    REQUIRE_EQ(output.size(), size_t{0x600});
    REQUIRE_EQ(output[0x200], uint8_t{0xCC});
    REQUIRE_EQ(output[0x201], uint8_t{0x90});
    REQUIRE_EQ(output[0x400], uint8_t{0x7A});
    REQUIRE_EQ(output[0x401], uint8_t{0x42});

    const auto pe = slop::core::disasm::pe_parse(output.data(), output.size());
    REQUIRE(pe.ok);
    REQUIRE_EQ(pe.sections.size(), size_t{2});
    REQUIRE_EQ(pe.sections[0].raw_offset, uint32_t{0x200});
    REQUIRE_EQ(pe.sections[1].raw_offset, uint32_t{0x400});
}

TEST_CASE(module_dump_rejects_invalid_headers) {
    auto mapped = make_mapped_image();
    mapped[0] = 0;
    std::vector<uint8_t> output;
    const auto result = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), reader_for(mapped), output);
    REQUIRE_FALSE(result.ok);
    REQUIRE(output.empty());
    REQUIRE_FALSE(result.error.empty());
}

TEST_CASE(module_dump_strict_and_best_effort_reads) {
    const auto mapped = make_mapped_image();
    const auto failing_reader = reader_for(mapped, kImageBase + 0x2000,
                                           kImageBase + 0x2200);
    std::vector<uint8_t> output;

    auto strict = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), failing_reader, output);
    REQUIRE_FALSE(strict.ok);
    REQUIRE(output.empty());

    slop::core::process::module_dump_options_t options;
    options.strict_reads = false;
    auto best_effort = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), failing_reader, output,
        options);
    REQUIRE(best_effort.ok);
    REQUIRE_FALSE(best_effort.complete);
    REQUIRE_EQ(output[0x400], uint8_t{0});
    REQUIRE_EQ(output[0x5FF], uint8_t{0});
}

TEST_CASE(module_dump_captures_live_test_process) {
    using namespace slop::core;
    if (runtime::active_kind() != runtime::backend_kind_t::user_mode) {
        std::printf("  [skip] live self-dump requires user-mode backend\n");
        return;
    }

    runtime::session_t session;
    REQUIRE(session.open(GetCurrentProcessId()));
    auto modules = runtime::active().enum_modules(session.handle());
    REQUIRE(modules.ok);
    REQUIRE_FALSE(modules.items.empty());
    if (!modules.ok || modules.items.empty()) return;

    const auto module = modules.items.front();
    const auto path = std::filesystem::temp_directory_path() /
                      L"reverse_slop_live_module_dump.exe";
    const auto result = process::dump_module_pe(session, module, path.string());
    REQUIRE(result.ok);
    REQUIRE(result.complete);
    REQUIRE(result.bytes_written >= 1024);

    std::ifstream file(path, std::ios::binary);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),
                                     std::istreambuf_iterator<char>{}};
    REQUIRE_EQ(bytes.size(), result.bytes_written);
    const auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);
    REQUIRE_FALSE(pe.sections.empty());

    std::error_code ec;
    std::filesystem::remove(path, ec);
    session.close();
}

namespace {

// a fake address space: three segments with an unmapped gap and a hole
struct fake_space_t {
    std::map<uint64_t, uint8_t> bytes;   // sparse; absent = 0
    uint64_t bad_lo = 0, bad_hi = 0;     // reads touching this range fail
    slop::core::runtime::io_result_t read(uintptr_t a, void* dst, size_t n) const {
        slop::core::runtime::io_result_t r;
        if (a < bad_hi && a + n > bad_lo) { r.error = 5; return r; }
        auto* out = static_cast<uint8_t*>(dst);
        for (size_t i = 0; i < n; ++i) {
            auto it = bytes.find(a + i);
            out[i] = it == bytes.end() ? 0 : it->second;
        }
        r.ok = true;
        r.bytes = n;
        return r;
    }
};

template <typename T>
T rd(const std::vector<uint8_t>& v, size_t off) {
    T x{};
    std::memcpy(&x, v.data() + off, sizeof(T));
    return x;
}

} // namespace

TEST_CASE(module_dump_rebuilds_elf_from_segments) {
    using namespace slop::core;
    fake_space_t mem;
    mem.bytes[0x400000] = 0xC3;
    mem.bytes[0x401234] = 0x90;
    mem.bytes[0x480010] = 0xAB;
    mem.bytes[0x4C8FFF] = 0xEE;
    const std::vector<process::mapped_segment_t> segs = {
        {0x400000, 0x480000, 5},    // r-x
        {0x480000, 0x4C0000, 1},    // r--
        {0x4C8000, 0x500000, 3},    // rw-
    };
    std::vector<uint8_t> out;
    process::elf_rebuild_info_t info;
    auto res = process::reconstruct_elf_from_segments(
        segs, [&](uintptr_t a, void* d, size_t n) { return mem.read(a, d, n); }, out, {}, &info);
    REQUIRE(res.ok);
    REQUIRE(res.complete);
    CHECK(res.module_base == 0x400000u);
    CHECK(info.segments == 3u);
    CHECK(!info.had_header);
    // no in-memory header: the entry falls back to the first executable segment,
    // so the analyzer starts at code instead of VA 0
    CHECK(info.entry == 0x400000u);
    CHECK(!res.warnings.empty());   // says the header was rebuilt
    REQUIRE(out.size() > 64u);
    CHECK(std::memcmp(out.data(), "\x7f" "ELF", 4) == 0);
    CHECK(out[4] == 2);
    CHECK(out[5] == 1);
    CHECK(rd<uint16_t>(out, 16) == 2);    // ET_EXEC
    CHECK(rd<uint16_t>(out, 18) == 62);   // EM_X86_64
    CHECK(rd<uint64_t>(out, 24) == 0x400000u);   // first executable segment
    CHECK(rd<uint64_t>(out, 32) == 64u);  // phoff
    CHECK(rd<uint16_t>(out, 54) == 56);   // phentsize
    REQUIRE(rd<uint16_t>(out, 56) == 3);  // phnum
    CHECK(rd<uint16_t>(out, 60) == 0);    // no section headers
    const uint32_t want_flags[3] = {5, 4, 6};
    uint64_t prev_end = 0;
    for (size_t i = 0; i < 3; ++i) {
        const size_t ph = 64 + i * 56;
        const uint64_t off = rd<uint64_t>(out, ph + 8);
        const uint64_t va = rd<uint64_t>(out, ph + 16);
        const uint64_t fsz = rd<uint64_t>(out, ph + 32);
        CHECK(rd<uint32_t>(out, ph) == 1u);   // PT_LOAD
        CHECK(rd<uint32_t>(out, ph + 4) == want_flags[i]);
        CHECK(va == segs[i].start);
        CHECK(fsz == segs[i].end - segs[i].start);
        CHECK(rd<uint64_t>(out, ph + 40) == fsz);
        CHECK(off % 0x4000 == va % 0x4000);
        CHECK(off >= prev_end);
        prev_end = off + fsz;
        REQUIRE(off + fsz <= out.size());
        // every byte sits at p_offset + (va - p_vaddr)
        for (const auto& [a, b] : mem.bytes)
            if (a >= va && a < va + fsz) CHECK(out[off + (a - va)] == b);
    }
}

TEST_CASE(module_dump_elf_keeps_in_memory_header_entry) {
    using namespace slop::core;
    fake_space_t mem;
    // an in-memory ELF header with a PIE-relative entry (ET_SCE_DYNEXEC style)
    const uint8_t ident[8] = {0x7F, 'E', 'L', 'F', 2, 1, 1, 9};
    for (size_t i = 0; i < sizeof(ident); ++i) mem.bytes[0x800000 + i] = ident[i];
    const uint16_t type = 0xFE10;
    mem.bytes[0x800010] = static_cast<uint8_t>(type & 0xFF);
    mem.bytes[0x800011] = static_cast<uint8_t>(type >> 8);
    const uint64_t entry = 0x1230;
    for (int i = 0; i < 8; ++i) mem.bytes[0x800018 + i] = static_cast<uint8_t>(entry >> (8 * i));
    const std::vector<process::mapped_segment_t> segs = {{0x800000, 0x810000, 5}};
    std::vector<uint8_t> out;
    process::elf_rebuild_info_t info;
    auto res = process::reconstruct_elf_from_segments(
        segs, [&](uintptr_t a, void* d, size_t n) { return mem.read(a, d, n); }, out, {}, &info);
    REQUIRE(res.ok);
    CHECK(info.had_header);
    CHECK(info.source_type == 0xFE10);
    CHECK(info.entry == 0x801230u);
    CHECK(rd<uint64_t>(out, 24) == 0x801230u);
}

TEST_CASE(module_dump_elf_unreadable_pages_strict_and_lenient) {
    using namespace slop::core;
    fake_space_t mem;
    mem.bytes[0x400000] = 0x11;
    mem.bad_lo = 0x404000;
    mem.bad_hi = 0x405000;
    const std::vector<process::mapped_segment_t> segs = {{0x400000, 0x410000, 5}};
    auto rf = [&](uintptr_t a, void* d, size_t n) { return mem.read(a, d, n); };
    std::vector<uint8_t> out;
    process::module_dump_options_t strict;
    strict.chunk_size = 0x1000;
    strict.strict_reads = true;
    auto res = process::reconstruct_elf_from_segments(segs, rf, out, strict);
    CHECK(!res.ok);
    CHECK(res.error.find("0x404000") != std::string::npos);
    CHECK(out.empty());

    process::module_dump_options_t lenient = strict;
    lenient.strict_reads = false;
    res = process::reconstruct_elf_from_segments(segs, rf, out, lenient);
    REQUIRE(res.ok);
    CHECK(!res.complete);
    bool named = false;
    for (const auto& w : res.warnings)
        if (w.find("0x404000..0x405000") != std::string::npos) named = true;
    CHECK(named);

    // bad layouts are refused
    std::vector<process::mapped_segment_t> overlap = {{0x400000, 0x402000, 1}, {0x401000, 0x403000, 1}};
    CHECK(!process::reconstruct_elf_from_segments(overlap, rf, out).ok);
    CHECK(!process::reconstruct_elf_from_segments({}, rf, out).ok);
}

TEST_CASE(module_dump_raw_span_zero_fills_gaps) {
    using namespace slop::core;
    fake_space_t mem;
    mem.bytes[0x400000] = 0x01;
    mem.bytes[0x401FFF] = 0x02;
    mem.bytes[0x403000] = 0x03;
    mem.bytes[0x402800] = 0x77;   // inside the gap: must not appear
    const std::vector<process::mapped_segment_t> segs = {{0x400000, 0x402000, 5}, {0x403000, 0x404000, 3}};
    std::vector<uint8_t> out;
    auto res = process::dump_raw_span(
        segs, [&](uintptr_t a, void* d, size_t n) { return mem.read(a, d, n); }, out);
    REQUIRE(res.ok);
    REQUIRE(out.size() == 0x4000u);
    CHECK(out[0] == 0x01);
    CHECK(out[0x1FFF] == 0x02);
    CHECK(out[0x2800] == 0x00);
    CHECK(out[0x3000] == 0x03);
    CHECK(res.section_count == 2u);
}

namespace {

// several mapped images at their own bases behind one reader
slop::core::process::module_read_fn_t multi_reader(
    const std::vector<std::pair<uintptr_t, const std::vector<uint8_t>*>>& images) {
    return [images](uintptr_t address, void* output, size_t size) {
        slop::core::runtime::io_result_t result;
        for (const auto& [base, img] : images) {
            if (address >= base && size <= img->size() && address - base <= img->size() - size) {
                std::memcpy(output, img->data() + (address - base), size);
                result.ok = true;
                result.bytes = size;
                return result;
            }
        }
        result.error = ERROR_PARTIAL_COPY;
        return result;
    };
}

struct fake_export_t {
    std::string name;        // empty = ordinal only
    uint32_t rva = 0;        // ignored when forward is set
    std::string forward;     // "dll.Func"
};

// a minimal PE32+ image with only an export directory
std::vector<uint8_t> make_export_dll(const std::vector<fake_export_t>& exports) {
    std::vector<uint8_t> image(0x2000, 0);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x80);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfImage = 0x2000;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.DataDirectory[0] = {0x1000, 0x400};

    auto* ed = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(image.data() + 0x1000);
    ed->Base = 1;
    ed->NumberOfFunctions = static_cast<DWORD>(exports.size());
    ed->AddressOfFunctions = 0x1040;
    ed->AddressOfNames = 0x1080;
    ed->AddressOfNameOrdinals = 0x10C0;
    uint32_t str = 0x1100, named = 0;
    for (size_t i = 0; i < exports.size(); ++i) {
        const auto& e = exports[i];
        uint32_t rva = e.rva;
        if (!e.forward.empty()) {   // forwarders point inside the export directory
            rva = str;
            std::memcpy(image.data() + str, e.forward.c_str(), e.forward.size() + 1);
            str += static_cast<uint32_t>(e.forward.size() + 1);
        }
        std::memcpy(image.data() + 0x1040 + i * 4, &rva, 4);
        if (e.name.empty()) continue;
        std::memcpy(image.data() + 0x1080 + named * 4, &str, 4);
        const auto ord = static_cast<uint16_t>(i);
        std::memcpy(image.data() + 0x10C0 + named * 2, &ord, 2);
        std::memcpy(image.data() + str, e.name.c_str(), e.name.size() + 1);
        str += static_cast<uint32_t>(e.name.size() + 1);
        ++named;
    }
    ed->NumberOfNames = named;
    return image;
}

} // namespace

TEST_CASE(module_dump_virtual_layout_keeps_data_past_raw_size) {
    using namespace slop::core;
    auto mapped = make_mapped_image();
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(mapped.data() + 0x80);
    IMAGE_FIRST_SECTION(nt)[1].Misc.VirtualSize = 0x1000;   // .data: bss past the 0x200 raw bytes
    mapped[0x2800] = 0x5A;
    process::module_dump_options_t options;
    options.layout = process::pe_layout_t::virtual_image;
    std::vector<uint8_t> output;
    const auto result = process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), reader_for(mapped), output, options);
    REQUIRE(result.ok);
    CHECK(result.layout == "virtual");
    REQUIRE(output.size() >= 0x3000u);
    CHECK(output[0x1000] == 0xCC);
    CHECK(output[0x2000] == 0x7A);
    CHECK(output[0x2800] == 0x5A);
    const auto pe = disasm::pe_parse(output.data(), output.size());
    REQUIRE(pe.ok);
    REQUIRE_EQ(pe.sections.size(), size_t{2});
    CHECK(pe.sections[1].raw_offset == 0x2000u);
    CHECK(pe.sections[1].raw_size == 0x1000u);
}

TEST_CASE(module_dump_rebase_and_oep_override) {
    using namespace slop::core;
    auto mapped = make_mapped_image();
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(mapped.data() + 0x80);
    nt->OptionalHeader.ImageBase = 0x180000000ull;   // linked base differs from the runtime one
    nt->OptionalHeader.CheckSum = 0x1234;
    process::module_dump_options_t options;
    options.rebase = true;
    options.oep = kImageBase + 0x1010;
    std::vector<uint8_t> output;
    const auto result = process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), reader_for(mapped), output, options);
    REQUIRE(result.ok);
    CHECK(result.oep_rva == 0x1010u);
    const auto pe = disasm::pe_parse(output.data(), output.size());
    REQUIRE(pe.ok);
    CHECK(pe.image_base == kImageBase);
    CHECK(pe.entry_rva == 0x1010u);
    const auto* out_nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(output.data() + 0x80);
    CHECK(out_nt->OptionalHeader.CheckSum == 0u);

    options.oep = 0x9000000;   // neither an RVA nor a VA inside the module
    CHECK(!process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), reader_for(mapped), output, options).ok);
}

TEST_CASE(module_dump_rebuilds_imports_from_iat_scan) {
    using namespace slop::core;
    constexpr uintptr_t kDllA = 0x7FF800000000ull, kDllB = 0x7FF810000000ull;
    const auto dll_a = make_export_dll({{"FuncA", 0x1800, ""},
                                        {"FuncB", 0x1810, ""},
                                        {"FwdC", 0, "dllb.Target"}});
    const auto dll_b = make_export_dll({{"Target", 0x1900, ""}, {"", 0x1910, ""}});

    auto mapped = make_mapped_image();
    std::fill_n(mapped.begin() + 0x2100, 0x40, uint8_t{0});
    const uint64_t slots[] = {kDllA + 0x1800, kDllA + 0x1810, kDllB + 0x1900, 0,
                              kDllB + 0x1910, 0};
    std::memcpy(mapped.data() + 0x2100, slots, sizeof(slots));

    std::vector<runtime::module_info_t> mods(3);
    mods[0] = {kImageBase, 0x3000, "main.exe", ""};
    mods[1] = {kDllA, 0x2000, "dlla.dll", ""};
    mods[2] = {kDllB, 0x2000, "dllb.dll", ""};
    process::module_dump_options_t options;
    options.layout = process::pe_layout_t::virtual_image;
    options.rebuild_imports = true;
    options.import_modules = mods;
    std::vector<uint8_t> output;
    const auto result = process::reconstruct_mapped_pe(
        kImageBase, 0x3000,
        multi_reader({{kImageBase, &mapped}, {kDllA, &dll_a}, {kDllB, &dll_b}}), output, options);
    REQUIRE(result.ok);
    CHECK(result.import_modules == 2u);
    CHECK(result.import_functions == 4u);
    CHECK(result.import_unresolved == 0u);
    CHECK(result.section_count == 3u);

    const auto pe = disasm::pe_parse(output.data(), output.size());
    REQUIRE(pe.ok);
    REQUIRE_EQ(pe.sections.size(), size_t{3});
    CHECK(std::string(pe.sections[2].name) == ".slopimp");
    CHECK(pe.data_dirs[12].rva == 0x2100u);
    REQUIRE_EQ(pe.imports.size(), size_t{2});
    CHECK(pe.imports[0].dll == "dlla.dll");
    REQUIRE_EQ(pe.imports[0].functions.size(), size_t{3});
    CHECK(pe.imports[0].functions[0].name == "FuncA");
    CHECK(pe.imports[0].functions[1].name == "FuncB");
    CHECK(pe.imports[0].functions[2].name == "FwdC");   // forwarder alias kept with its dll
    CHECK(pe.imports[0].functions[0].iat_rva == 0x2100u);
    CHECK(pe.imports[1].dll == "dllb.dll");
    REQUIRE_EQ(pe.imports[1].functions.size(), size_t{1});
    CHECK(pe.imports[1].functions[0].by_ordinal);
    CHECK(pe.imports[1].functions[0].ordinal == 2);
    CHECK(pe.imports[1].functions[0].iat_rva == 0x2120u);
}

TEST_CASE(module_dump_minidump_of_current_process) {
    const auto path = std::filesystem::temp_directory_path() / L"slop_selftest.dmp";
    uint64_t bytes = 0;
    std::string error;
    REQUIRE(slop::core::process::write_minidump(GetCurrentProcessId(), path.string(), false,
                                                bytes, error));
    CHECK(bytes > 4u);
    std::ifstream file(path, std::ios::binary);
    char magic[4] = {};
    file.read(magic, 4);
    CHECK(std::memcmp(magic, "MDMP", 4) == 0);
    file.close();
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

namespace {

constexpr uintptr_t kDllA2 = 0x7FF800000000ull, kDllB2 = 0x7FF810000000ull;

slop::core::process::module_dump_result_t rebuild_with_dlls(
    const std::vector<uint8_t>& mapped, slop::core::process::pe_layout_t layout,
    std::vector<uint8_t>& output) {
    using namespace slop::core;
    static const auto dll_a = make_export_dll({{"FuncA", 0x1800, ""}, {"FuncB", 0x1810, ""}});
    static const auto dll_b = make_export_dll({{"Target", 0x1900, ""}, {"Other", 0x1910, ""}});
    process::module_dump_options_t options;
    options.layout = layout;
    options.rebuild_imports = true;
    options.import_modules = {{kImageBase, 0x3000, "main.exe", ""},
                              {kDllA2, 0x2000, "dlla.dll", ""},
                              {kDllB2, 0x2000, "dllb.dll", ""}};
    return process::reconstruct_mapped_pe(
        kImageBase, 0x3000,
        multi_reader({{kImageBase, &mapped}, {kDllA2, &dll_a}, {kDllB2, &dll_b}}), output, options);
}

} // namespace

TEST_CASE(module_dump_imports_fall_back_to_last_section_without_header_room) {
    using namespace slop::core;
    auto mapped = make_mapped_image();
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(mapped.data() + 0x80);
    nt->OptionalHeader.SizeOfHeaders = 0x1D8;   // section table ends exactly here
    std::fill_n(mapped.begin() + 0x2100, 0x40, uint8_t{0});
    const uint64_t slots[] = {kDllA2 + 0x1800, kDllA2 + 0x1810, 0};
    std::memcpy(mapped.data() + 0x2100, slots, sizeof(slots));

    for (auto layout : {process::pe_layout_t::file, process::pe_layout_t::virtual_image}) {
        std::vector<uint8_t> output;
        const auto result = rebuild_with_dlls(mapped, layout, output);
        REQUIRE(result.ok);
        CHECK(result.section_count == 2u);
        CHECK(result.import_functions == 2u);
        bool warned = false;
        for (const auto& w : result.warnings)
            if (w.find("last section") != std::string::npos) warned = true;
        CHECK(warned);
        const auto pe = disasm::pe_parse(output.data(), output.size());
        REQUIRE(pe.ok);
        REQUIRE_EQ(pe.sections.size(), size_t{2});
        CHECK(pe.data_dirs[1].rva == 0x2200u);   // right after .data's raw bytes
        CHECK((pe.sections[1].characteristics & 0x40000040u) == 0x40000040u);
        REQUIRE_EQ(pe.imports.size(), size_t{1});
        CHECK(pe.imports[0].dll == "dlla.dll");
        REQUIRE_EQ(pe.imports[0].functions.size(), size_t{2});
        CHECK(pe.imports[0].functions[0].name == "FuncA");
        CHECK(pe.imports[0].functions[1].name == "FuncB");
    }
}

TEST_CASE(module_dump_imports_from_intact_import_directory) {
    using namespace slop::core;
    auto mapped = make_mapped_image();
    std::fill_n(mapped.begin() + 0x2100, 0x100, uint8_t{0});
    // the descriptor's IAT holds resolved dlla addresses
    const uint64_t iat[] = {kDllA2 + 0x1800, kDllA2 + 0x1810, 0};
    std::memcpy(mapped.data() + 0x2100, iat, sizeof(iat));
    // a stray dllb pointer run the scan would pick up but the directory does not name
    const uint64_t stray[] = {kDllB2 + 0x1900, kDllB2 + 0x1910, 0};
    std::memcpy(mapped.data() + 0x2140, stray, sizeof(stray));
    IMAGE_IMPORT_DESCRIPTOR desc{};
    desc.Name = 0x21C0;
    desc.FirstThunk = 0x2100;
    std::memcpy(mapped.data() + 0x2180, &desc, sizeof(desc));
    std::memcpy(mapped.data() + 0x21C0, "dlla.dll", 9);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(mapped.data() + 0x80);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {0x2180, 40};

    std::vector<uint8_t> output;
    const auto result = rebuild_with_dlls(mapped, process::pe_layout_t::virtual_image, output);
    REQUIRE(result.ok);
    CHECK(result.import_modules == 1u);
    CHECK(result.import_functions == 2u);
    const auto pe = disasm::pe_parse(output.data(), output.size());
    REQUIRE(pe.ok);
    REQUIRE_EQ(pe.imports.size(), size_t{1});   // only what the directory names
    CHECK(pe.imports[0].dll == "dlla.dll");
    REQUIRE_EQ(pe.imports[0].functions.size(), size_t{2});
    CHECK(pe.imports[0].functions[0].name == "FuncA");
    CHECK(pe.imports[0].functions[0].iat_rva == 0x2100u);
}

TEST_CASE(read_ahead_buffers_overlap_and_stay_ordered) {
    using namespace slop::core;
    std::atomic<int> in_flight{0}, max_in_flight{0};
    memory::read_ahead_t ra([&](uintptr_t a, void* d, size_t n) {
        const int now = ++in_flight;
        int prev = max_in_flight.load();
        while (now > prev && !max_in_flight.compare_exchange_weak(prev, now)) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        runtime::io_result_t r;
        if (a == 0x3000) {   // one deterministic failure for the reap checks
            --in_flight;
            r.error = 5;
            return r;
        }
        auto* out = static_cast<uint8_t*>(d);
        for (size_t i = 0; i < n; ++i) out[i] = static_cast<uint8_t>(a + i);
        --in_flight;
        r.ok = true;
        r.bytes = n;
        return r;
    });
    constexpr size_t kChunk = 64;
    std::vector<uint8_t> a(kChunk), b(kChunk);
    ra.prefetch(0x1000, a.data(), kChunk);
    ra.prefetch(0x2030, b.data(), kChunk);   // second slot: no wait on chunk 0
    const auto r0 = ra.reap();
    REQUIRE(r0.ok);
    REQUIRE(r0.bytes == kChunk);
    CHECK(a[0] == 0x00 && a[1] == 0x01);     // payload is the low address byte
    const auto r1 = ra.reap();
    REQUIRE(r1.ok);
    CHECK(b[0] == 0x30 && b[1] == 0x31);
    CHECK(max_in_flight.load() == 2);        // the two reads really overlapped

    // a failure surfaces at its own reap and does not poison the next chunk
    ra.prefetch(0x3000, a.data(), kChunk);   // fails by address above
    ra.prefetch(0x4000, b.data(), kChunk);
    const auto r2 = ra.reap();
    CHECK(!r2.ok);
    const auto r3 = ra.reap();
    CHECK(r3.ok);
    CHECK(b[0] == 0x00);
}

TEST_CASE(module_dump_failed_chunk_salvaged_page_by_page) {
    using namespace slop::core;
    fake_space_t mem;
    mem.bytes[0x400000] = 0x11;   // chunk 0, good page
    mem.bytes[0x408000] = 0x33;   // chunk 1 start
    mem.bad_lo = 0x401000;        // one protected page inside chunk 0
    mem.bad_hi = 0x402000;
    const std::vector<process::mapped_segment_t> segs = {{0x400000, 0x410000, 5}};
    std::vector<uint8_t> out;
    process::module_dump_options_t o;
    o.chunk_size = 0x8000;        // the bad page fails chunk 0 wholesale
    o.strict_reads = false;
    const auto res = process::dump_raw_span(
        segs, [&](uintptr_t a, void* d, size_t n) { return mem.read(a, d, n); }, out, o);
    REQUIRE(res.ok);
    REQUIRE(out.size() == 0x10000u);
    CHECK(!res.complete);
    CHECK(out[0] == 0x11);              // good page of the failed chunk survives
    CHECK(out[0x1000] == 0x00);         // the bad page itself is zero-filled
    CHECK(out[0x1FFF] == 0x00);
    CHECK(out[0x8000] == 0x33);         // chunk 1 (prefetched) intact
    bool named = false;
    for (const auto& w : res.warnings)
        if (w.find("0x401000..0x402000") != std::string::npos) named = true;
    CHECK(named);
}
