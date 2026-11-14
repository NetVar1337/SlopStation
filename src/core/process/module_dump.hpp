#pragma once

#include "core/runtime/backend.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace slop::core::runtime { class session_t; }

namespace slop::core::process {

using module_read_fn_t =
    std::function<runtime::io_result_t(uintptr_t, void*, size_t)>;

// file: sections at their PointerToRawData/SizeOfRawData as linked.
// virtual_image: PointerToRawData = VirtualAddress, SizeOfRawData = aligned
// VirtualSize, so bss and data unpacked at runtime survive.
enum class pe_layout_t { file, virtual_image };

struct module_dump_options_t {
    size_t chunk_size = 64u * 1024u;
    bool strict_reads = true;
    // PE only (reconstruct_mapped_pe / dump_module_pe)
    pe_layout_t layout = pe_layout_t::file;
    bool rebase = false;            // ImageBase := runtime base
    bool rebuild_imports = false;   // IAT reconstruction into a new .slopimp section
    uint64_t oep = 0;               // AddressOfEntryPoint override: RVA or VA, 0 = keep
    // modules whose in-memory export tables resolve IAT thunks (read through the same reader)
    std::vector<runtime::module_info_t> import_modules;
};

struct module_dump_result_t {
    bool ok = false;
    bool complete = false;
    std::string error;
    std::string output_path;
    uint64_t module_base = 0;
    size_t bytes_written = 0;
    size_t section_count = 0;
    std::vector<std::string> warnings;
    // PE only
    std::string layout;
    uint32_t oep_rva = 0;
    size_t import_modules = 0;
    size_t import_functions = 0;
    size_t import_unresolved = 0;
};

// rebuild a file layout pe from a mapped image, separated so it tests
// without a live process
module_dump_result_t reconstruct_mapped_pe(
    uintptr_t module_base,
    uint32_t module_size,
    const module_read_fn_t& read,
    std::vector<uint8_t>& output,
    const module_dump_options_t& options = {});

// dump one module through the active session, works with rpm and the
// driver alike
module_dump_result_t dump_module_pe(
    runtime::session_t& session,
    const runtime::module_info_t& module,
    const std::string& output_path,
    const module_dump_options_t& options = {});

// one mapped segment of a (console) module; prot uses FreeBSD VM_PROT bits
// (1 read, 2 write, 4 execute)
struct mapped_segment_t {
    uint64_t start = 0;
    uint64_t end   = 0;
    uint32_t prot  = 0;
};

struct elf_rebuild_info_t {
    bool     had_header = false;  // the first segment carried an in-memory ELF header
    uint16_t source_type = 0;     // that header's e_type (ET_SCE_* etc.), 0 if none
    uint64_t entry = 0;           // absolute entry point, 0 = unknown
    size_t   segments = 0;        // PT_LOAD headers written
};

// Build a loadable ELF64 (x86-64, ET_EXEC) from a module's mapped segments:
// one PT_LOAD per segment at its absolute VA (p_vaddr == runtime address, so
// loading with base_override = first segment start is a no-op rebase), data at
// page-aligned file offsets, no section headers. Memory images of PS4 modules
// usually lack the ELF header (the SELF loader does not map it); when the
// first segment does start with one, its e_entry/e_type are carried over.
// Unreadable chunks fail a strict dump, otherwise they are zero-filled with a
// warning and complete=false. Pure function over the read callback.
module_dump_result_t reconstruct_elf_from_segments(
    const std::vector<mapped_segment_t>& segments,
    const module_read_fn_t& read,
    std::vector<uint8_t>& output,
    const module_dump_options_t& options = {},
    elf_rebuild_info_t* info = nullptr);

// The raw mapped span [first.start, last.end): segment bytes at their
// offsets from the module base, gaps between segments zero-filled.
module_dump_result_t dump_raw_span(
    const std::vector<mapped_segment_t>& segments,
    const module_read_fn_t& read,
    std::vector<uint8_t>& output,
    const module_dump_options_t& options = {});

// write a buffer atomically (temp file + replace)
bool write_dump_file(const std::string& output_path, const std::vector<uint8_t>& data,
                     std::string& error);

// MiniDumpWriteDump of a local process (Windows only). full adds the whole
// address space; handle data, thread info and unloaded modules always.
bool write_minidump(uint32_t pid, const std::string& output_path, bool full,
                    uint64_t& bytes_written, std::string& error);

} // namespace slop::core::process
