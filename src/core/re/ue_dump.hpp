#pragma once

// Unreal Engine 4.20+ / 5.x SDK dumper over a live memory reader (native port
// of examples/ue5_dumper.lua). Locates the name table (FNamePool on 4.23+,
// TNameEntryArray on 4.20-4.22) and GUObjectArray by structural validation
// only (no game-specific signatures), detects the struct/property layout from
// the engine's own core classes, then walks every UClass / UScriptStruct /
// UEnum / UFunction. Reads go through a page cache so slow console readers
// see few round trips. x64 targets only.

#include "core/memory/reader.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace slop::core::re::ue {

struct range_t {
    uint64_t base = 0;
    uint64_t size = 0;
};

struct dump_options_t {
    uint64_t gnames   = 0;   // FNamePool / TNameEntryArray (or the pointer to it); 0 = locate
    uint64_t gobjects = 0;   // FUObjectArray (or its ObjObjects member); 0 = locate
    int      version_hint = 0;            // 0 auto, 4 or 5
    std::vector<range_t> scan;            // memory searched when locating (module data sections)
    size_t   max_objects = 4'000'000;
    bool     json = true;                 // ClassesInfo/StructsInfo/EnumsInfo/FunctionsInfo.json + FNames.txt
    bool     sdk  = true;                 // SDK.hpp
};

struct dump_result_t {
    bool        ok = false;
    std::string error;
    std::string version;                  // "4.20-4.22", "4.23-4.24", "4.25-4.27", "5.x"
    uint64_t    gnames = 0, gobjects = 0;  // located/used addresses (gobjects = ObjObjects)
    size_t      names = 0, objects = 0, classes = 0, structs = 0, enums = 0, functions = 0;
    std::vector<std::string> warnings;
    std::vector<std::pair<std::string, std::string>> files;   // file name -> contents
};

dump_result_t dump(memory::reader_t& reader, const dump_options_t& options);

} // namespace slop::core::re::ue
