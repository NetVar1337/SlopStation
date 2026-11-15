#pragma once

// Source engine (Titanfall-derived, e.g. Apex Legends) netvar dumper over a
// live memory reader. Locates the ClientClass linked list by structural
// validation only (no game-specific signatures), then walks every RecvTable /
// RecvProp and computes flat netvar offsets the way hazedumper does:
// DPT_DataTable props recurse into their table (a "0"-prefixed baseclass
// prop adds no offset), everything else records table->prop = base + offset.
// x64 targets only (PS4 Orbis, PC).

#include "core/memory/reader.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace slop::core::re::source {

struct range_t {
    uint64_t base = 0;
    uint64_t size = 0;
};

struct dump_options_t {
    uint64_t head = 0;                    // first ClientClass*; 0 = locate by scanning
    std::vector<range_t> scan;            // ranges searched when locating (module data sections)
    size_t max_classes = 4096;
    bool json = true;                     // netvars.json + recvtables.json
};

struct dump_result_t {
    bool        ok = false;
    std::string error;
    uint64_t    head = 0;                 // located/used first ClientClass
    size_t      classes = 0, tables = 0, props = 0, netvars = 0;
    std::vector<std::string> warnings;
    std::vector<std::pair<std::string, std::string>> files;   // file name -> contents
};

dump_result_t dump(memory::reader_t& reader, const dump_options_t& options);

} // namespace slop::core::re::source
