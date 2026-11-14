#pragma once

// Unity IL2CPP metadata dumper. Parses global-metadata.dat (versions 24.0
// through 31), locates Il2CppCodeRegistration / Il2CppMetadataRegistration in
// the game binary by structural search (Il2CppDumper style: counts in the
// metadata must match the tables in the binary) and resolves field offsets and
// method addresses. Pure data code over untrusted input: every read is bounds
// checked, malformed files fail with an error instead of crashing.

#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::re::il2cpp {

// one mapped range of the binary: VAs [va, va+size) are bytes[off, off+size)
struct image_segment_t {
    uint64_t va   = 0;
    uint64_t off  = 0;
    uint64_t size = 0;
    bool     exec = false;
};

// the binary as the dumper sees it: bytes plus the VA map. Pointers stored in
// the bytes must already be absolute VAs (PE preferred base, relocated ELF or
// a live module read from memory)
struct binary_image_t {
    std::vector<uint8_t>         bytes;
    std::vector<image_segment_t> segs;
    uint64_t                     image_base = 0;   // RVAs in the output are VA - image_base
    bool                         file_layout = false; // offsets are file offsets (dump.cs prints them)
    std::string                  format;           // "pe", "elf" or "live"
};

// PE32+ or ELF64 (x86-64 / AArch64, PS4 PRX and dumped ELFs included) from a
// file on disk. ELF images whose lowest PT_LOAD sits at 0 get their
// R_*_RELATIVE relocations applied so pointer tables hold usable VAs
bool image_from_file(std::vector<uint8_t> file, binary_image_t& out, std::string& error,
                     std::vector<std::string>& warnings);

// a module span read from the live target (already relocated by the loader).
// segs are absolute VAs; empty segs = derive them from an in-memory PE header,
// else treat the whole span as one data+code segment
bool image_from_memory(std::vector<uint8_t> span, uint64_t base,
                       std::vector<image_segment_t> segs, binary_image_t& out,
                       std::string& error);

struct dump_options_t {
    bool cs     = true;   // dump.cs
    bool json   = true;   // il2cpp.json
    bool header = true;   // il2cpp.h
};

struct dump_result_t {
    bool        ok = false;
    std::string error;
    std::string version;            // "24.2", "29.1", ... (binary-side subversion when known)
    size_t      images = 0, types = 0, methods = 0, fields = 0;
    size_t      methods_with_address = 0, generic_instances = 0;
    uint64_t    code_registration = 0, metadata_registration = 0;
    std::vector<std::string> warnings;
    std::string dump_cs, il2cpp_json, il2cpp_h;
};

// image may be empty (no segments): the metadata is still dumped, without
// field offsets, type names of fields or method addresses
dump_result_t dump(const std::vector<uint8_t>& metadata, const binary_image_t& image,
                   const dump_options_t& options = {});

} // namespace slop::core::re::il2cpp
