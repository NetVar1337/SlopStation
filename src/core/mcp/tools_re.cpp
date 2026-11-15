// src/core/mcp/tools_re.cpp
// tool: re (rtti, vtables, danger imports, libsig, symbols, il2cpp/unreal dumpers)

#include "core/mcp/tools_common.hpp"

#include "core/infra/paths.hpp"
#include "core/loader/elf_loader.h"
#include "core/memory/session_reader.hpp"
#include "core/re/il2cpp_dump.hpp"
#include "core/re/ue_dump.hpp"
#include "core/re/source_dump.hpp"

#include <cstring>

namespace slop::core::mcp::detail {


namespace {

namespace il2cpp = slop::core::re::il2cpp;
namespace ue = slop::core::re::ue;
namespace source = slop::core::re::source;

std::vector<uint8_t> read_host_file(const std::string& path, uint64_t cap, const char* what) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) fail(std::string("cannot open ") + what + ": " + path);
    const std::streamoff size = f.tellg();
    if (size <= 0 || static_cast<uint64_t>(size) > cap)
        fail(std::string(what) + " is empty or larger than " + std::to_string(cap >> 20) + " MiB: " + path);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    f.seekg(0);
    if (!f.read(reinterpret_cast<char*>(data.data()), size)) fail(std::string("short read on ") + what + ": " + path);
    return data;
}

// format: string or array of strings out of `allowed`; absent = all of them
std::unordered_set<std::string> parse_formats(const json& args, std::initializer_list<const char*> allowed,
                                              const char* action) {
    std::unordered_set<std::string> out;
    std::string list;
    for (const char* a : allowed) list += (list.empty() ? "" : "|") + std::string(a);
    if (!args.contains("format")) {
        for (const char* a : allowed) out.insert(a);
        return out;
    }
    const json& f = args.at("format");
    std::vector<std::string> items;
    if (f.is_string()) items.push_back(f.get<std::string>());
    else if (f.is_array()) {
        for (const auto& e : f) {
            if (!e.is_string()) fail(std::string(action) + ": format entries must be strings (" + list + ")");
            items.push_back(e.get<std::string>());
        }
    } else {
        fail(std::string(action) + ": format must be a string or an array of strings (" + list + ")");
    }
    for (const auto& it : items) {
        bool ok = false;
        for (const char* a : allowed) ok = ok || it == a;
        if (!ok) fail(std::string(action) + ": unknown format '" + it + "' (" + list + ")");
        out.insert(it);
    }
    if (out.empty()) fail(std::string(action) + ": format selects nothing (" + list + ")");
    return out;
}

std::string require_out_dir(const json& args, const char* action) {
    const std::string dir = args.value("out_dir", std::string{});
    if (dir.empty()) fail(std::string(action) + " requires 'out_dir' (host folder for the output files)");
    return dir;
}

std::string write_out(const std::string& dir, const std::string& name, const std::string& body) {
    const char last = dir.back();
    const std::string path = dir + (last == '/' || last == '\\' ? "" : "/") + name;
    if (!infra::paths::write_file_atomic(path, body)) fail("cannot write " + path);
    return path;
}

bool same_name(const std::string& a, const std::string& b) {
    return a.size() == b.size() && icontains(b, a);   // portable, case-insensitive
}

// a loaded module of the active target: its mapped span (gaps zero-filled)
// plus the segment map when the backend reports one (console modules)
struct live_module_t {
    uint64_t base = 0;
    std::string name;
    std::vector<process::mapped_segment_t> segs;
};

live_module_t find_live_module(runtime::session_t& s, const std::string& want) {
    live_module_t m;
    if (auto* p4 = dynamic_cast<runtime::backend_ps4_t*>(s.backend()); p4 && p4->connected()) {
        auto mods = p4->ps4_modules(s.handle());
        if (!mods.ok) fail("module enumeration failed on the console: " + runtime::ps4::io_error_str(mods.error));
        for (const auto& pm : mods.items) {
            if (!(want.empty() ? same_name(pm.name, "eboot.bin") : same_name(pm.name, want))) continue;
            m.base = pm.base;
            m.name = pm.name;
            for (const auto& sg : pm.segments) m.segs.push_back({sg.start, sg.end, sg.prot});
            return m;
        }
    } else {
        auto mods = runtime::active().enum_modules(s.handle());
        if (!mods.ok) fail("module enumeration failed");
        for (const auto& lm : mods.items) {
            if (!want.empty() && !same_name(lm.name, want)) continue;
            m.base = lm.base;
            m.name = lm.name;
            m.segs.push_back({lm.base, lm.base + lm.size, 7});
            return m;
        }
    }
    fail(want.empty() ? "no main module found on the target" : "module '" + want + "' is not loaded in the target");
}

std::vector<uint8_t> read_live_span(runtime::session_t& s, const live_module_t& m,
                                    std::vector<std::string>& warnings,
                                    const infra::cancel_token_t& cancel = {}) {
    process::module_dump_options_t o;
    // console reads are socket round trips: one 8 MiB read instead of 32x
    // 256 KiB; failed chunks are salvaged page by page inside read_segment
    o.chunk_size = s.backend()->kind() == runtime::backend_kind_t::user_mode
                       ? (64u << 20) : memory::kRemoteChunkBytes;
    o.strict_reads = false;
    o.cancel = cancel;
    o.on_bytes = [](uint64_t n) { dump_progress().add(n); };
    auto read = [&s](uintptr_t a, void* dst, size_t n) { return s.read(a, dst, n); };
    std::vector<uint8_t> span;
    const auto r = process::dump_raw_span(m.segs, read, span, o);
    if (!r.ok) fail("reading module " + m.name + " failed: " + r.error);
    warnings.insert(warnings.end(), r.warnings.begin(), r.warnings.end());
    return span;
}

json il2cpp_dump_action(const json& args, const infra::cancel_token_t& cancel) {
    const std::string meta_path = args.value("metadata", std::string{});
    if (meta_path.empty()) fail("il2cpp_dump requires 'metadata' (path to global-metadata.dat)");
    const std::string out_dir = require_out_dir(args, "il2cpp_dump");
    const auto formats = parse_formats(args, {"cs", "json", "header"}, "il2cpp_dump");
    const std::string bin_path = args.value("binary", std::string{});
    const std::string module = args.value("module", std::string{});
    if (bin_path.empty() == module.empty())
        fail("il2cpp_dump requires exactly one of 'binary' (GameAssembly.dll / libil2cpp.so / decrypted PRX "
             "or dumped ELF on disk) or 'module' (a module loaded in the active target)");

    const auto metadata = read_host_file(meta_path, 512ull << 20, "metadata");
    std::vector<std::string> pre_warnings;
    il2cpp::binary_image_t img;
    std::string err;
    json source;
    if (!bin_path.empty()) {
        if (!il2cpp::image_from_file(read_host_file(bin_path, 2048ull << 20, "binary"), img, err, pre_warnings))
            fail("il2cpp_dump: " + err);
        source = {{"binary", bin_path}, {"format", img.format}, {"image_base", img.image_base}};
    } else {
        const auto s_hold = need_session();
        auto& s = *s_hold;
        const live_module_t m = find_live_module(s, module);
        std::vector<il2cpp::image_segment_t> segs;
        if (m.segs.size() > 1 || dynamic_cast<runtime::backend_ps4_t*>(s.backend()))
            for (const auto& sg : m.segs) {
                il2cpp::image_segment_t is;
                is.va = sg.start;
                is.size = sg.end - sg.start;
                is.exec = (sg.prot & 4) != 0;
                segs.push_back(is);
            }
        if (!il2cpp::image_from_memory(read_live_span(s, m, pre_warnings, cancel), m.base, std::move(segs), img, err))
            fail("il2cpp_dump: " + err);
        source = {{"module", m.name}, {"base", m.base}, {"size", img.bytes.size()}};
    }

    il2cpp::dump_options_t o;
    o.cs = formats.count("cs") != 0;
    o.json = formats.count("json") != 0;
    o.header = formats.count("header") != 0;
    auto r = il2cpp::dump(metadata, img, o);
    if (!r.ok) fail("il2cpp_dump: " + r.error);
    json files = json::array();
    if (o.cs) files.push_back(write_out(out_dir, "dump.cs", r.dump_cs));
    if (o.json) files.push_back(write_out(out_dir, "il2cpp.json", r.il2cpp_json));
    if (o.header && !r.il2cpp_h.empty()) files.push_back(write_out(out_dir, "il2cpp.h", r.il2cpp_h));
    pre_warnings.insert(pre_warnings.end(), r.warnings.begin(), r.warnings.end());
    return {{"version", r.version}, {"images", r.images}, {"types", r.types}, {"methods", r.methods},
            {"fields", r.fields}, {"methods_with_address", r.methods_with_address},
            {"generic_instances", r.generic_instances}, {"code_registration", r.code_registration},
            {"metadata_registration", r.metadata_registration}, {"source", source},
            {"out_files", files}, {"warnings", pre_warnings}};
}

// writable sections of a module (where FNamePool / GUObjectArray live)
std::vector<ue::range_t> ue_scan_ranges(runtime::session_t& s, const live_module_t& m) {
    std::vector<ue::range_t> out;
    if (m.segs.size() > 1 || dynamic_cast<runtime::backend_ps4_t*>(s.backend())) {
        for (const auto& sg : m.segs)
            if ((sg.prot & 2) && sg.end > sg.start) out.push_back({sg.start, sg.end - sg.start});
    } else {
        uint8_t hdr[0x1000] = {};
        uint32_t lfanew = 0, sig = 0;
        uint16_t nsec = 0, opt = 0;
        if (s.read(m.base, hdr, sizeof hdr).ok && hdr[0] == 'M' && hdr[1] == 'Z') {
            std::memcpy(&lfanew, hdr + 0x3C, 4);
            if (lfanew < 0xF00) {
                std::memcpy(&sig, hdr + lfanew, 4);
                std::memcpy(&nsec, hdr + lfanew + 6, 2);
                std::memcpy(&opt, hdr + lfanew + 20, 2);
            }
        }
        const uint64_t sec0 = uint64_t{lfanew} + 24 + opt;
        for (uint32_t i = 0; sig == 0x00004550u && i < nsec && sec0 + 40ull * (i + 1) <= sizeof hdr; ++i) {
            uint32_t vsize = 0, rva = 0, chars = 0;
            std::memcpy(&vsize, hdr + sec0 + 40ull * i + 8, 4);
            std::memcpy(&rva, hdr + sec0 + 40ull * i + 12, 4);
            std::memcpy(&chars, hdr + sec0 + 40ull * i + 36, 4);
            if ((chars & 0x80000000u) && vsize) out.push_back({m.base + rva, vsize});   // IMAGE_SCN_MEM_WRITE
        }
        if (out.empty() && !m.segs.empty()) out.push_back({m.segs[0].start, m.segs[0].end - m.segs[0].start});
    }
    return out;
}

json ue_dump_action(const json& args, const infra::cancel_token_t& cancel) {
    // the module read (read_live_span) honours the token; the metadata walk
    // below does not, so a cancel cannot interrupt it mid-walk
    (void)cancel;
    const std::string out_dir = require_out_dir(args, "ue_dump");
    const auto formats = parse_formats(args, {"json", "sdk"}, "ue_dump");
    ue::dump_options_t o;
    const std::string ver = args.value("version", std::string("auto"));
    if (ver == "4.x" || ver == "4") o.version_hint = 4;
    else if (ver == "5.x" || ver == "5") o.version_hint = 5;
    else if (ver != "auto") fail("ue_dump: version must be auto, 4.x or 5.x");
    if (args.contains("gnames")) o.gnames = parse_addr(args, "gnames");
    if (args.contains("gobjects")) o.gobjects = parse_addr(args, "gobjects");
    if (args.contains("max_objects")) {
        const uint64_t mo = parse_addr(args, "max_objects");
        if (mo == 0 || mo > 20'000'000) fail("ue_dump: max_objects must be 1..20000000");
        o.max_objects = static_cast<size_t>(mo);
    }
    o.json = formats.count("json") != 0;
    o.sdk = formats.count("sdk") != 0;

    const auto s_hold = need_session();
    auto& s = *s_hold;
    json scanned = json::array();
    if (!o.gnames || !o.gobjects) {
        const live_module_t m = find_live_module(s, args.value("module", std::string{}));
        o.scan = ue_scan_ranges(s, m);
        for (const auto& r : o.scan) scanned.push_back({{"base", r.base}, {"size", r.size}});
        if (o.scan.empty()) fail("ue_dump: module " + m.name + " has no writable sections to search; pass gnames and gobjects");
    }
    memory::session_reader_t reader(s);
    auto r = ue::dump(reader, o);
    if (!r.ok) fail("ue_dump: " + r.error);
    json files = json::array();
    for (const auto& [name, body] : r.files) files.push_back(write_out(out_dir, name, body));
    return {{"version", r.version}, {"gnames", r.gnames}, {"gobjects", r.gobjects}, {"names", r.names},
            {"objects", r.objects}, {"classes", r.classes}, {"structs", r.structs}, {"enums", r.enums},
            {"functions", r.functions}, {"scanned", scanned}, {"out_files", files}, {"warnings", r.warnings}};
}

json source_dump_action(const json& args, const infra::cancel_token_t& cancel) {
    // the module read honours the token; the ClientClass/RecvTable walk does
    // not, so a cancel cannot interrupt it mid-walk
    (void)cancel;
    const std::string out_dir = require_out_dir(args, "source_dump");
    const auto formats = parse_formats(args, {"json", "header"}, "source_dump");
    source::dump_options_t o;
    if (args.contains("head")) o.head = parse_addr(args, "head");
    if (args.contains("max_classes")) {
        const uint64_t mc = parse_addr(args, "max_classes");
        if (mc == 0 || mc > 100'000) fail("source_dump: max_classes must be 1..100000");
        o.max_classes = static_cast<size_t>(mc);
    }
    o.json = formats.count("json") != 0;
    o.header = formats.count("header") != 0;
    o.datamaps = args.value("datamaps", false);
    if (args.contains("max_datamaps")) {
        const uint64_t md = parse_addr(args, "max_datamaps");
        if (md == 0 || md > 100'000) fail("source_dump: max_datamaps must be 1..100000");
        o.max_datamaps = static_cast<size_t>(md);
    }

    const auto s_hold = need_session();
    auto& s = *s_hold;
    json scanned = json::array();
    if (!o.head) {
        const live_module_t m = find_live_module(s, args.value("module", std::string{}));
        for (const auto& r : ue_scan_ranges(s, m)) {
            o.scan.push_back({r.base, r.size});
            scanned.push_back({{"base", r.base}, {"size", r.size}});
        }
        if (o.scan.empty())
            fail("source_dump: module " + m.name + " has no writable sections to search; pass head");
    }
    memory::session_reader_t reader(s);
    auto r = source::dump(reader, o);
    if (!r.ok) fail("source_dump: " + r.error);
    json files = json::array();
    for (const auto& [name, body] : r.files) files.push_back(write_out(out_dir, name, body));
    json out = {{"head", r.head}, {"classes", r.classes}, {"tables", r.tables}, {"props", r.props},
                {"netvars", r.netvars}, {"scanned", scanned}, {"out_files", files},
                {"warnings", r.warnings}};
    if (o.datamaps) {
        out["datamaps"] = r.datamaps;
        out["datamap_fields"] = r.datamap_fields;
    }
    return out;
}

} // namespace

// tool: re

json tool_re(const json& args, const infra::cancel_token_t& cancel) {
    const std::string action = require_action(args);
    // engine-metadata dumpers work on host files / the live target, not the shared image
    if (action == "il2cpp_dump") return il2cpp_dump_action(args, cancel);
    if (action == "ue_dump") return ue_dump_action(args, cancel);
    if (action == "source_dump") return source_dump_action(args, cancel);

    // app loaded binary unless a path is given
    std::optional<ds::binary_lock_t> shared_lock;
    disasm::pe_image_t const*   pe   = nullptr;
    std::vector<uint8_t> const* file = nullptr;
    disasm::function_index_t*   fidx = nullptr;
    disasm::xref_index_t*       xidx = nullptr;
    uint64_t                    session_base = 0;   // VA base of the source
    const hype::AnalysisDB*     hdb  = nullptr;     // hyperion DB when analyzed
    disasm::image_format_t format = disasm::image_format_t::pe;
    disasm::image_arch_t arch = disasm::image_arch_t::x64;
    const bool have_path = args.contains("path") && args.at("path").is_string();

    if (have_path) {
        auto& img = load_image(args.at("path").get<std::string>());
        format = img.format;
        arch = img.arch;
        if (action == "danger")
            require_x86_image(arch, format, "re.danger", true);
        pe = &img.pe; file = &img.file; fidx = &img.fidx; xidx = &img.xidx;
        session_base = pe->image_base;
        // signature matching needs bounds, not decoding; import callsites
        // need the legacy x86 xref index when there is no hyperion session
        if (action == "libsig" && !img.fidx_ok) {
            if (arch == disasm::image_arch_t::x86 || arch == disasm::image_arch_t::x64) {
                auto& eng = shared_engine();
                if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
                if (!fidx->build(*pe, *file, eng, session_base))
                    fail("function index build failed");
            } else if (!fidx->build_from_bounds(*pe, *file, session_base)) {
                fail("function bounds index build failed");
            }
            img.fidx_ok = true;
        }
        if (action == "danger" && !img.xidx_ok) {
            auto& eng = shared_engine();
            if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
            if (!xidx->build(*pe, *file, eng, session_base))
                fail("xref index build failed");
            img.xidx_ok = true;
        }
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop");
        format = bin.format;
        arch = bin.arch;
        if (bin.indexes_dirty && (action == "danger" || action == "libsig"))
            ds::rebuild_indexes_locked(bin);
        pe = &bin.pe; file = &bin.file; fidx = &bin.fns; xidx = &bin.xrefs;
        session_base = bin.base;
        if (bin.hype && bin.hype->ready()) hdb = &bin.hype->db();
    }
    const uint64_t base = args.contains("base")
        ? parse_addr(args, "base")
        : session_base;
    (void)base;

    if (action == "rtti_scan") {
        // MSVC RTTI on x86/x64 PE; Itanium (clang/gcc) RTTI on ELF/SELF of any
        // arch the hyperion loader maps
        const bool itanium = format == disasm::image_format_t::elf ||
                             format == disasm::image_format_t::self;
        if (!itanium) {
            require_x86_image(arch, format, "re.rtti_scan", have_path);
            require_pe_image(arch, format, "re.rtti_scan", have_path);
        }
        // Case-insensitive substring filter over mangled + demangled names,
        // plus limit/total so 600-class dumps stop truncating the session.
        const std::string filter = args.value("filter", std::string{});
        auto match_filter = [&](const std::string& a, const std::string& b) {
            return filter.empty() || icontains(a, filter) || icontains(b, filter);
        };
        const size_t rtti_limit =
            std::min<size_t>(args.value("limit", 500u), 10000u);
        const char* abi = itanium ? "itanium" : "msvc";
        // hyperion rtti beats the quick scanner when its ready
        // the lock above already pins the session
        if (!args.contains("path")) {
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                const auto& classes = bin.hype->rtti().classes();
                json arr = json::array();
                size_t matched = 0;
                for (const auto& c : classes) {
                    const std::string shown = c.demangled_name.empty()
                                                  ? c.mangled_name
                                                  : c.demangled_name;
                    if (!match_filter(shown, c.mangled_name)) continue;
                    ++matched;
                    if (arr.size() >= rtti_limit) continue;
                    json methods = json::array();
                    for (auto m : c.methods) methods.push_back(m);
                    json e = {{"name", shown},
                              {"mangled", c.mangled_name},
                              {"td_va", c.type_descriptor},
                              {"vtable_va", c.vtable},
                              {"methods", methods},
                              {"method_count", c.methods.size()}};
                    if (itanium) e["bases"] = c.bases;
                    arr.push_back(std::move(e));
                }
                json out = {{"engine", "hyperion"}, {"abi", abi}, {"classes", arr},
                            {"count", arr.size()}, {"total", matched}};
                if (!filter.empty()) out["filter"] = filter;
                if (matched > arr.size()) out["truncated"] = true;
                return out;
            }
        }
        re::rtti_result_t r;
        if (itanium) {
            const unsigned ptr_size = (arch == disasm::image_arch_t::x64 ||
                                       arch == disasm::image_arch_t::arm64) ? 8 : 4;
            if (have_path && file->size() >= 4 && std::memcmp(file->data(), "\x7F" "ELF", 4) == 0) {
                // the path cache holds the ELF as read (a SELF's extracted
                // ELF too); vtable and type_info pointers only exist once
                // its relocations are applied
                std::vector<uint8_t> relocated = *file;
                hype::ELFLoader::apply_relocations(relocated, pe->image_base);
                r = re::rtti_scan_itanium(*pe, relocated, ptr_size);
            } else {
                r = re::rtti_scan_itanium(*pe, *file, ptr_size);
            }
        } else {
            r = re::rtti_scan(*pe, *file);
        }
        json arr = json::array();
        size_t matched = 0;
        for (const auto& c : r.classes) {
            if (!match_filter(c.name, c.mangled.empty() ? c.name : c.mangled)) continue;
            ++matched;
            if (arr.size() >= rtti_limit) continue;
            json vfs = json::array();
            for (auto v : c.vftables) vfs.push_back(v);
            json e = {{"name", c.name}, {"td_va", c.td_va}, {"vftables", vfs}};
            if (itanium) {
                e["mangled"] = c.mangled;
                e["bases"] = c.bases;
                e["methods"] = c.methods;
                e["method_count"] = c.methods.size();
            }
            arr.push_back(std::move(e));
        }
        json rout = {{"abi", abi}, {"classes", arr}, {"count", arr.size()},
                     {"total", matched},
                     {"scanned_bytes", r.scanned_bytes}};
        if (!filter.empty()) rout["filter"] = filter;
        if (matched > arr.size()) rout["truncated"] = true;
        return rout;
    }
    if (action == "vftable") {
        if (!args.contains("path")) {
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                // serve from the db when the address is indexed
                const uint64_t vva = parse_addr(args, "addr");
                for (const auto& vt : bin.hype->db().vtables) {
                    if (vt.addr != vva) continue;
                    json arr = json::array();
                    for (auto e : vt.entries) arr.push_back(e);
                    return {{"engine", "hyperion"}, {"vftable_va", vva},
                            {"targets", arr}, {"count", arr.size()}};
                }
                // raw read for everything else
            }
        }
        if (!args.contains("addr")) fail("missing addr");
        const uint64_t va = parse_addr(args, "addr");
        auto slots = re::read_vftable(
            *pe, *file, va,
            static_cast<size_t>(std::min<uint64_t>(
                args.contains("slots") ? parse_addr(args, "slots") : 32,
                256)));
        if (!slots) fail("vftable not readable in image");
        json arr = json::array();
        for (auto v : *slots) arr.push_back(v);
        return {{"vftable_va", va}, {"targets", arr},
                {"count", arr.size()}};
    }
    if (action == "danger") {
        if (arch != disasm::image_arch_t::x86 && arch != disasm::image_arch_t::x64 && !hdb)
            fail("re.danger requires completed hyperion analysis for this image; "
                 "wait for disasm.loaded hype.ready");
        // hyperion knows the iat refs, the legacy index covers explicit paths
        auto hits = analysis::danger_scan(
            *pe,
            [xidx, hdb](uint64_t target_va) {
                std::vector<uint64_t> out;
                if (hdb) {
                    // one instruction can emit two records, dedupe by from
                    std::set<uint64_t> seen;
                    const auto it = hdb->xrefs_to.find(target_va);
                    if (it != hdb->xrefs_to.end())
                        for (const auto& x : it->second)
                            if (seen.insert(x.from).second)
                                out.push_back(x.from);
                    return out;
                }
                for (const auto& r : xidx->refs_to(target_va))
                    out.push_back(r.from);
                return out;
            },
            session_base);
        json arr = json::array();
        for (const auto& h : hits) {
            json cs = json::array();
            for (auto c : h.callsites) cs.push_back(c);
            arr.push_back({{"function", h.function},
                           {"category", h.category},
                           {"iat_va", h.iat_va},
                           {"callsites", cs},
                           {"count", cs.size()}});
        }
        return {{"hits", arr}, {"count", arr.size()}};
    }
    if (action == "libsig") {
        std::vector<analysis::libsig_t> sigs;
        json out = json::object();
        if (args.contains("sig_path") && args.at("sig_path").is_string()) {
            // IDA FLIRT .sig import: parsed into the same pattern matcher
            const std::string sig_path = args.at("sig_path").get<std::string>();
            std::ifstream f(sig_path, std::ios::binary);
            if (!f) fail("cannot open signature file " + sig_path);
            std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                                       std::istreambuf_iterator<char>{});
            std::string sig_err;
            auto parsed = analysis::parse_flirt_sig(bytes.data(), bytes.size(), &sig_err);
            if (!parsed) fail(sig_err.empty() ? "bad FLIRT signature file" : sig_err);
            sigs = std::move(parsed->sigs);
            out["library"]       = parsed->library;
            out["ctype"]         = parsed->ctype;
            out["flirt_version"] = parsed->version;
        } else {
            if (!args.contains("sigset")) fail("missing sigset JSON or sig_path");
            std::string sig_err;
            auto parsed = analysis::parse_sig_set(
                args.at("sigset").get<std::string>(), &sig_err);
            if (!parsed) fail(sig_err.empty() ? "bad sigset" : sig_err);
            sigs = std::move(*parsed);
        }
        auto hits = analysis::libsig_scan(*pe, *file, *fidx, sigs);
        json arr = json::array();
        for (const auto& h : hits) {
            json o = {{"name", h.sig_name}, {"va", h.va}};
            if (h.function_va) o["function_va"] = *h.function_va;
            arr.push_back(std::move(o));
        }
        out["hits"]      = arr;
        out["count"]     = arr.size();
        out["requested"] = sigs.size();
        return out;
    }

    fail("re: unknown action (rtti_scan|vftable|danger|libsig|il2cpp_dump|ue_dump|source_dump)");
}

} // namespace slop::core::mcp::detail
