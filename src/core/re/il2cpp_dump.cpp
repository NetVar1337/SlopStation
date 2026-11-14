// src/core/re/il2cpp_dump.cpp
// IL2CPP global-metadata.dat parser + registration search, see il2cpp_dump.hpp

#include "core/re/il2cpp_dump.hpp"

#include "core/loader/elf_loader.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <map>
#include <span>
#include <unordered_map>
#include <unordered_set>

namespace slop::core::re::il2cpp {

namespace {

using json = nlohmann::json;

template <class T>
bool rd(const std::vector<uint8_t>& b, uint64_t off, T& out) {
    if (off > b.size() || sizeof(T) > b.size() - off) return false;
    std::memcpy(&out, b.data() + off, sizeof(T));
    return true;
}

std::string hx(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

// ---------------------------------------------------------------- binary image

bool parse_pe(const std::vector<uint8_t>& b, bool mapped, uint64_t base_override,
              binary_image_t& out, std::string& error) {
    uint32_t lfanew = 0;
    uint32_t sig = 0;
    if (!rd(b, 0x3C, lfanew) || !rd(b, lfanew, sig) || sig != 0x00004550u) {
        error = "not a PE image (bad NT signature)";
        return false;
    }
    const uint64_t nt = lfanew;
    uint16_t nsec = 0, opt_size = 0, magic = 0;
    uint64_t image_base = 0;
    if (!rd(b, nt + 6, nsec) || !rd(b, nt + 20, opt_size) || !rd(b, nt + 24, magic)) {
        error = "truncated PE header";
        return false;
    }
    if (magic != 0x20B) {
        error = "only PE32+ (64-bit) binaries are supported";
        return false;
    }
    if (!rd(b, nt + 24 + 24, image_base)) {
        error = "truncated PE optional header";
        return false;
    }
    if (base_override) image_base = base_override;
    const uint64_t sec0 = nt + 24 + opt_size;
    out.segs.clear();
    for (uint32_t i = 0; i < nsec; ++i) {
        const uint64_t s = sec0 + 40ull * i;
        uint32_t vsize = 0, rva = 0, raw_size = 0, raw_ptr = 0, chars = 0;
        if (!rd(b, s + 8, vsize) || !rd(b, s + 12, rva) || !rd(b, s + 16, raw_size) ||
            !rd(b, s + 20, raw_ptr) || !rd(b, s + 36, chars)) {
            error = "truncated PE section table";
            return false;
        }
        image_segment_t seg;
        seg.va   = image_base + rva;
        seg.exec = (chars & 0x20000000u) != 0;
        if (mapped) {
            seg.off  = rva;
            seg.size = vsize ? vsize : raw_size;
        } else {
            seg.off  = raw_ptr;
            seg.size = vsize ? std::min(raw_size, vsize) : raw_size;
        }
        if (seg.off >= b.size()) continue;
        seg.size = std::min<uint64_t>(seg.size, b.size() - seg.off);
        if (seg.size) out.segs.push_back(seg);
    }
    if (out.segs.empty()) {
        error = "PE has no sections with data";
        return false;
    }
    out.image_base  = image_base;
    out.file_layout = !mapped;
    out.format      = mapped ? "live" : "pe";
    return true;
}

bool parse_elf(std::vector<uint8_t>& b, binary_image_t& out, std::string& error,
               std::vector<std::string>& warnings) {
    if (b.size() < 64 || b[4] != 2 || b[5] != 1) {
        error = "only little-endian ELF64 binaries are supported";
        return false;
    }
    uint64_t phoff = 0;
    uint16_t phentsize = 0, phnum = 0, machine = 0;
    rd(b, 18, machine);
    rd(b, 32, phoff);
    rd(b, 54, phentsize);
    rd(b, 56, phnum);
    if (phentsize < 56 || phnum == 0) {
        error = "ELF has no program headers";
        return false;
    }
    out.segs.clear();
    uint64_t lowest = ~0ull;
    for (uint32_t i = 0; i < phnum; ++i) {
        const uint64_t p = phoff + uint64_t{phentsize} * i;
        uint32_t type = 0, flags = 0;
        uint64_t off = 0, vaddr = 0, filesz = 0;
        if (!rd(b, p, type) || !rd(b, p + 4, flags) || !rd(b, p + 8, off) ||
            !rd(b, p + 16, vaddr) || !rd(b, p + 32, filesz)) {
            error = "truncated ELF program header table";
            return false;
        }
        if (type != 1 && type != 0x61000010u) continue;   // PT_LOAD, PT_SCE_RELRO
        if (off >= b.size() || filesz == 0) continue;
        image_segment_t seg;
        seg.va   = vaddr;
        seg.off  = off;
        seg.size = std::min<uint64_t>(filesz, b.size() - off);
        seg.exec = (flags & 1u) != 0;
        out.segs.push_back(seg);
        lowest = std::min(lowest, vaddr);
    }
    if (out.segs.empty()) {
        error = "ELF has no loadable segments with file data";
        return false;
    }
    if (machine != 62 && machine != 183)
        warnings.push_back("ELF machine " + std::to_string(machine) +
                           " is neither x86-64 nor AArch64; pointer tables may not resolve");
    // a file image is unrelocated: fill the pointer slots from R_*_RELATIVE.
    // A module dumped from memory (lowest segment at its runtime VA) already
    // carries the console's relocations and must not be touched
    if (lowest == 0) {
        const auto st = hype::ELFLoader::apply_relocations(std::span<uint8_t>(b.data(), b.size()), 0);
        if (st.applied == 0)
            warnings.push_back("no ELF relocations applied: pointer tables in an unrelocated "
                               "file read as zero (dump the module from memory if the search fails)");
    }
    out.image_base  = lowest;
    out.file_layout = true;
    out.format      = "elf";
    return true;
}

// ---------------------------------------------------------------- binary reader

struct bin_t {
    const binary_image_t& im;
    mutable size_t        last = 0;
    bool                  lax_exec = true;   // no segment flagged exec: anything mapped counts

    explicit bin_t(const binary_image_t& i) : im(i) {
        for (const auto& s : im.segs)
            if (s.exec) lax_exec = false;
    }
    bool has() const { return !im.segs.empty(); }

    const image_segment_t* seg_of(uint64_t va, uint64_t len) const {
        if (im.segs.empty()) return nullptr;
        auto hit = [&](const image_segment_t& s) {
            return va >= s.va && va - s.va < s.size && len <= s.size - (va - s.va);
        };
        if (last < im.segs.size() && hit(im.segs[last])) return &im.segs[last];
        for (size_t i = 0; i < im.segs.size(); ++i)
            if (hit(im.segs[i])) { last = i; return &im.segs[i]; }
        return nullptr;
    }
    bool mapped(uint64_t va, uint64_t len = 1) const { return va && seg_of(va, len) != nullptr; }
    bool exec(uint64_t va) const {
        const auto* s = seg_of(va, 1);
        return s && (s->exec || lax_exec);
    }
    template <class T>
    bool get(uint64_t va, T& out) const {
        const auto* s = seg_of(va, sizeof(T));
        if (!s) return false;
        return rd(im.bytes, s->off + (va - s->va), out);
    }
    uint64_t q(uint64_t va) const { uint64_t v = 0; get(va, v); return v; }
    bool cstr(uint64_t va, std::string& out, size_t max = 512) const {
        out.clear();
        const auto* s = seg_of(va, 1);
        if (!s) return false;
        const uint64_t off = s->off + (va - s->va);
        const uint64_t end = std::min<uint64_t>(s->off + s->size, off + max);
        for (uint64_t o = off; o < end && o < im.bytes.size(); ++o) {
            if (im.bytes[o] == 0) return true;
            out.push_back(static_cast<char>(im.bytes[o]));
        }
        return false;
    }
    // count*8 bytes of pointers at va, count sane
    bool array(uint64_t va, uint64_t count) const {
        return count < (1ull << 28) && mapped(va, count != 0 ? count * 8 : 1);
    }
    std::vector<const image_segment_t*> data_segs() const {
        std::vector<const image_segment_t*> d;
        for (const auto& s : im.segs)
            if (!s.exec) d.push_back(&s);
        if (d.empty())
            for (const auto& s : im.segs) d.push_back(&s);
        return d;
    }
    // walk every 8-aligned qword of the data segments; fn(va, pointer to the
    // bytes, bytes available from there) returns true to stop
    template <class F>
    uint64_t scan(F&& fn) const {
        for (const auto* s : data_segs()) {
            const uint64_t first = (8 - (s->va & 7)) & 7;
            for (uint64_t i = first; i + 8 <= s->size; i += 8) {
                const uint64_t off = s->off + i;
                if (off + 8 > im.bytes.size()) break;
                const uint64_t avail = std::min<uint64_t>(s->size - i, im.bytes.size() - off);
                if (fn(s->va + i, im.bytes.data() + off, avail)) return s->va + i;
            }
        }
        return 0;
    }
};

uint64_t le64(const uint8_t* p) { uint64_t v; std::memcpy(&v, p, 8); return v; }

// ---------------------------------------------------------------- metadata

struct td_t {
    uint32_t name = 0, ns = 0;
    int32_t  byval = -1, declaring = -1, parent = -1, element = -1, gcontainer = -1;
    uint32_t flags = 0;
    int32_t  field_start = 0, method_start = 0, property_start = 0, interfaces_start = 0;
    uint16_t method_count = 0, property_count = 0, field_count = 0, interfaces_count = 0;
    uint32_t bitfield = 0, token = 0;
    bool valuetype() const { return (bitfield & 1u) != 0; }
    bool is_enum() const { return (bitfield & 2u) != 0; }
};
struct md_t {
    uint32_t name = 0;
    int32_t  declaring = -1, ret = -1, param_start = 0, gcontainer = -1, method_index = -1;
    uint32_t token = 0;
    uint16_t flags = 0, iflags = 0, slot = 0, param_count = 0;
};
struct fd_t { uint32_t name = 0; int32_t type = -1; };
struct pd_t { uint32_t name = 0; int32_t type = -1; };
struct prop_t { uint32_t name = 0; int32_t get = -1, set = -1; uint32_t attrs = 0; };
struct img_t { uint32_t name = 0; int32_t type_start = 0; uint32_t type_count = 0; uint32_t token = 0; };
struct gc_t { int32_t argc = 0, gp_start = 0; };

struct meta_t {
    const std::vector<uint8_t>& b;
    int      major = 0;
    int      v = 0;            // version * 10 (240, 241, 242, 270, 290, 310)
    uint32_t str_off = 0, str_size = 0;
    std::vector<td_t>    tds;
    std::vector<md_t>    mds;
    std::vector<fd_t>    fds;
    std::vector<pd_t>    pds;
    std::vector<prop_t>  props;
    std::vector<img_t>   imgs;
    std::vector<uint32_t> gp_names;
    std::vector<gc_t>    gcs;
    std::vector<int32_t> ifaces;
    uint32_t td_off = 0, td_size = 0, gp_off = 0;
    size_t   td_rec = 0;
    std::string error;

    explicit meta_t(const std::vector<uint8_t>& bytes) : b(bytes) {}

    std::string str(uint32_t idx) const {
        if (idx >= str_size) return {};
        const uint64_t beg = uint64_t{str_off} + idx;
        const uint64_t end = uint64_t{str_off} + str_size;
        std::string s;
        for (uint64_t o = beg; o < end && o < b.size() && b[o]; ++o) s.push_back(static_cast<char>(b[o]));
        return s;
    }

    // header word at index i
    uint32_t hw(size_t i) const { uint32_t x = 0; rd(b, i * 4, x); return x; }

    // table [off, off+size) of rec-sized records, returns the record count
    bool table(size_t word, size_t rec, uint32_t& off, size_t& count, const char* what) {
        off = hw(word);
        const uint32_t size = hw(word + 1);
        if (uint64_t{off} + size > b.size()) {
            error = std::string("metadata table ") + what + " runs past the end of the file";
            return false;
        }
        if (rec == 0 || size % rec != 0) {
            error = std::string("metadata table ") + what + " size is not a multiple of its record size "
                    "(unsupported layout or corrupt file)";
            return false;
        }
        count = size / rec;
        return true;
    }

    bool parse(std::vector<std::string>& warnings) {
        if (b.size() < 0x100) { error = "metadata file too small"; return false; }
        if (hw(0) != 0xFAB11BAFu) { error = "bad metadata sanity (expected 0xFAB11BAF; encrypted or not global-metadata.dat)"; return false; }
        major = static_cast<int>(hw(1));
        if (major != 24 && major != 27 && major != 29 && major != 31) {
            error = "unsupported metadata version " + std::to_string(major) + " (24, 27, 29 and 31 are supported)";
            return false;
        }
        v = major * 10;
        if (major == 24) {
            if (hw(2) == 264) {
                v = 242;
            } else {
                // 24.0 images are 32 bytes with token == 1; a 24.1 file read
                // that way shows other values there
                v = 240;
                const uint32_t ioff = hw(44), isz = hw(45);
                if (uint64_t{ioff} + isz <= b.size()) {
                    for (uint64_t o = ioff; o + 32 <= uint64_t{ioff} + isz; o += 32) {
                        uint32_t tok = 0;
                        rd(b, o + 28, tok);
                        if (tok != 1) { v = 241; break; }
                    }
                }
            }
        }
        str_off  = hw(6);
        str_size = hw(7);
        if (uint64_t{str_off} + str_size > b.size()) { error = "metadata string table runs past the end of the file"; return false; }

        const bool ca = v <= 240;   // customAttributeIndex fields
        // Il2CppTypeDefinition
        {
            size_t o = 8;
            if (ca) o += 4;
            const size_t byval = o; o += 4;
            if (v <= 245) o += 4;           // byrefTypeIndex
            const size_t decl = o; o += 4;
            const size_t parent = o; o += 4;
            const size_t elem = o; o += 4;
            if (v <= 241) o += 8;           // rgctx
            const size_t gcont = o; o += 4;
            const size_t flags = o; o += 4;
            const size_t fstart = o; o += 4;
            const size_t mstart = o; o += 4;
            o += 4;                          // eventStart
            const size_t pstart = o; o += 4;
            o += 4;                          // nestedTypesStart
            const size_t istart = o; o += 4;
            o += 8;                          // vtableStart, interfaceOffsetsStart
            const size_t counts = o; o += 16;
            const size_t bits = o; o += 4;
            const size_t tok = o; o += 4;
            td_rec = o;
            size_t n = 0;
            if (!table(40, o, td_off, n, "typeDefinitions")) return false;
            td_size = hw(41);
            tds.resize(n);
            for (size_t i = 0; i < n; ++i) {
                const uint64_t r = td_off + i * o;
                td_t& t = tds[i];
                rd(b, r, t.name); rd(b, r + 4, t.ns);
                rd(b, r + byval, t.byval); rd(b, r + decl, t.declaring); rd(b, r + parent, t.parent);
                rd(b, r + elem, t.element); rd(b, r + gcont, t.gcontainer); rd(b, r + flags, t.flags);
                rd(b, r + fstart, t.field_start); rd(b, r + mstart, t.method_start);
                rd(b, r + pstart, t.property_start); rd(b, r + istart, t.interfaces_start);
                rd(b, r + counts, t.method_count); rd(b, r + counts + 2, t.property_count);
                rd(b, r + counts + 4, t.field_count); rd(b, r + counts + 12, t.interfaces_count);
                rd(b, r + bits, t.bitfield); rd(b, r + tok, t.token);
            }
        }
        // Il2CppMethodDefinition
        {
            size_t o = 12;
            if (v >= 310) o += 4;           // returnParameterToken
            const size_t pstart = o; o += 4;
            if (ca) o += 4;
            const size_t gcont = o; o += 4;
            const size_t midx = o;
            if (v <= 241) o += 20;          // methodIndex, invoker, delegateWrapper, rgctx x2
            const size_t tok = o; o += 4;
            const size_t fl = o; o += 8;
            uint32_t off = 0; size_t n = 0;
            if (!table(12, o, off, n, "methods")) return false;
            mds.resize(n);
            for (size_t i = 0; i < n; ++i) {
                const uint64_t r = off + i * o;
                md_t& m = mds[i];
                rd(b, r, m.name); rd(b, r + 4, m.declaring); rd(b, r + 8, m.ret);
                rd(b, r + pstart, m.param_start); rd(b, r + gcont, m.gcontainer);
                if (v <= 241) rd(b, r + midx, m.method_index);
                rd(b, r + tok, m.token); rd(b, r + fl, m.flags); rd(b, r + fl + 2, m.iflags);
                rd(b, r + fl + 4, m.slot); rd(b, r + fl + 6, m.param_count);
            }
        }
        // Il2CppFieldDefinition / Il2CppParameterDefinition / properties
        {
            const size_t frec = ca ? 16 : 12;
            uint32_t off = 0; size_t n = 0;
            if (!table(24, frec, off, n, "fields")) return false;
            fds.resize(n);
            for (size_t i = 0; i < n; ++i) { rd(b, off + i * frec, fds[i].name); rd(b, off + i * frec + 4, fds[i].type); }
            if (!table(22, frec, off, n, "parameters")) return false;
            pds.resize(n);
            for (size_t i = 0; i < n; ++i) { rd(b, off + i * frec, pds[i].name); rd(b, off + i * frec + (ca ? 12 : 8), pds[i].type); }
            const size_t prec = ca ? 24 : 20;
            if (!table(10, prec, off, n, "properties")) return false;
            props.resize(n);
            for (size_t i = 0; i < n; ++i) {
                const uint64_t r = off + i * prec;
                rd(b, r, props[i].name); rd(b, r + 4, props[i].get); rd(b, r + 8, props[i].set); rd(b, r + 12, props[i].attrs);
            }
        }
        // generic parameters / containers / interfaces
        {
            uint32_t off = 0; size_t n = 0;
            if (!table(26, 16, off, n, "genericParameters")) return false;
            gp_off = off;
            gp_names.resize(n);
            for (size_t i = 0; i < n; ++i) rd(b, off + i * 16 + 4, gp_names[i]);
            if (!table(30, 16, off, n, "genericContainers")) return false;
            gcs.resize(n);
            for (size_t i = 0; i < n; ++i) { rd(b, off + i * 16 + 4, gcs[i].argc); rd(b, off + i * 16 + 12, gcs[i].gp_start); }
            if (!table(34, 4, off, n, "interfaces")) return false;
            ifaces.resize(n);
            for (size_t i = 0; i < n; ++i) rd(b, off + i * 4, ifaces[i]);
        }
        // Il2CppImageDefinition
        {
            const size_t irec = v >= 241 ? 40 : 32;
            const size_t word = v <= 241 ? 44 : 42;
            uint32_t off = 0; size_t n = 0;
            if (!table(word, irec, off, n, "images")) return false;
            imgs.resize(n);
            for (size_t i = 0; i < n; ++i) {
                const uint64_t r = off + i * irec;
                rd(b, r, imgs[i].name); rd(b, r + 8, imgs[i].type_start);
                rd(b, r + 12, imgs[i].type_count); rd(b, r + 28, imgs[i].token);
            }
        }
        if (imgs.empty()) warnings.push_back("metadata lists no images");
        return true;
    }
};

// ---------------------------------------------------------------- registrations

// Il2CppCodeRegistration field presence by version*10 (Il2CppDumper's table)
struct creg_field_t { const char* name; bool (*present)(int); };
const creg_field_t kCodeReg[] = {
    {"methodPointersCount", [](int v) { return v <= 241; }},
    {"methodPointers", [](int v) { return v <= 241; }},
    {"reversePInvokeWrapperCount", [](int) { return true; }},
    {"reversePInvokeWrappers", [](int) { return true; }},
    {"genericMethodPointersCount", [](int) { return true; }},
    {"genericMethodPointers", [](int) { return true; }},
    {"genericAdjustorThunks", [](int v) { return v == 245 || v >= 271; }},
    {"invokerPointersCount", [](int) { return true; }},
    {"invokerPointers", [](int) { return true; }},
    {"customAttributeCount", [](int v) { return v <= 245; }},
    {"customAttributeGenerators", [](int v) { return v <= 245; }},
    {"unresolvedVirtualCallCount", [](int) { return true; }},
    {"unresolvedVirtualCallPointers", [](int) { return true; }},
    {"unresolvedInstanceCallPointers", [](int v) { return v >= 291; }},
    {"unresolvedStaticCallPointers", [](int v) { return v >= 291; }},
    {"interopDataCount", [](int) { return true; }},
    {"interopData", [](int) { return true; }},
    {"windowsRuntimeFactoryCount", [](int v) { return v >= 243; }},
    {"windowsRuntimeFactoryTable", [](int v) { return v >= 243; }},
    {"codeGenModulesCount", [](int v) { return v >= 242; }},
    {"codeGenModules", [](int v) { return v >= 242; }},
};

int creg_index(int v, const char* name) {
    int idx = 0;
    for (const auto& f : kCodeReg) {
        if (!f.present(v)) continue;
        if (std::strcmp(f.name, name) == 0) return idx;
        ++idx;
    }
    return -1;
}

// Il2CppMetadataRegistration (v >= 19): 8-byte count/pointer pairs
enum : uint64_t {
    MR_GENERIC_CLASSES_COUNT = 0x00, MR_GENERIC_INSTS_COUNT = 0x10, MR_GENERIC_INSTS = 0x18,
    MR_GENERIC_METHOD_TABLE_COUNT = 0x20, MR_GENERIC_METHOD_TABLE = 0x28,
    MR_TYPES_COUNT = 0x30, MR_TYPES = 0x38, MR_METHOD_SPECS_COUNT = 0x40, MR_METHOD_SPECS = 0x48,
    MR_FIELD_OFFSETS_COUNT = 0x50, MR_FIELD_OFFSETS = 0x58,
    MR_TYPE_SIZES_COUNT = 0x60, MR_TYPE_SIZES = 0x68,
};

uint64_t find_metadata_registration(const bin_t& bin, uint64_t tdc) {
    if (tdc == 0) return 0;
    // scan yields the matching fieldOffsetsCount slot; the struct starts 0x50 earlier
    const uint64_t at = bin.scan([&](uint64_t va, const uint8_t* p, uint64_t avail) {
        if (avail < 32 || le64(p) != tdc || le64(p + 16) != tdc) return false;
        const uint64_t offsets = le64(p + 8), sizes = le64(p + 24);
        if (va < MR_FIELD_OFFSETS_COUNT) return false;
        if (!bin.array(sizes, tdc) || !bin.array(offsets, tdc)) return false;
        for (uint64_t i = 0; i < tdc; ++i) {
            if (!bin.mapped(bin.q(sizes + i * 8), 16)) return false;
            const uint64_t fo = bin.q(offsets + i * 8);
            if (fo && !bin.mapped(fo, 4)) return false;
        }
        const uint64_t reg = va - MR_FIELD_OFFSETS_COUNT;
        const uint64_t types_count = bin.q(reg + MR_TYPES_COUNT);
        return types_count > 0 && bin.array(bin.q(reg + MR_TYPES), types_count);
    });
    return at ? at - MR_FIELD_OFFSETS_COUNT : 0;
}

// v24.2+: the codeGenModules count/pointer pair whose modules carry the
// metadata image names; returns the VA of codeGenModulesCount
uint64_t find_codegen_modules(const bin_t& bin, const meta_t& m) {
    const uint64_t n = m.imgs.size();
    if (n == 0) return 0;
    std::unordered_set<std::string> names;
    for (const auto& im : m.imgs) names.insert(m.str(im.name));
    std::string s;
    return bin.scan([&](uint64_t, const uint8_t* p, uint64_t avail) {
        if (avail < 16 || le64(p) != n) return false;
        const uint64_t arr = le64(p + 8);
        if (!bin.array(arr, n)) return false;
        bool corlib = false;
        for (uint64_t i = 0; i < n; ++i) {
            const uint64_t mod = bin.q(arr + i * 8);
            if (!bin.mapped(mod, 24) || !bin.cstr(bin.q(mod), s, 260) || !names.count(s)) return false;
            corlib = corlib || s == "mscorlib.dll";
        }
        return corlib || n == 1;
    });
}

// v24.0/24.1: methodPointersCount + methodPointers (all into code)
uint64_t find_method_pointers(const bin_t& bin, uint64_t count) {
    if (count == 0) return 0;
    return bin.scan([&](uint64_t, const uint8_t* p, uint64_t avail) {
        if (avail < 16 || le64(p) != count) return false;
        const uint64_t arr = le64(p + 8);
        if (!bin.array(arr, count)) return false;
        const uint64_t probe = std::min<uint64_t>(count, 256);
        uint64_t code = 0;
        for (uint64_t i = 0; i < probe; ++i) {
            const uint64_t f = bin.q(arr + i * 8);
            if (f && !bin.exec(f)) return false;
            code += f != 0;
        }
        return code * 2 >= probe;
    });
}

bool valid_ptr_table(const bin_t& bin, uint64_t count, uint64_t arr) {
    if (count == 0 || count >= (1ull << 24) || !bin.array(arr, count)) return false;
    const uint64_t probe = std::min<uint64_t>(count, 64);
    for (uint64_t i = 0; i < probe; ++i) {
        const uint64_t f = bin.q(arr + i * 8);
        if (f && !bin.exec(f)) return false;
    }
    return true;
}

// ---------------------------------------------------------------- types

enum : uint8_t {
    T_VOID = 1, T_BOOLEAN, T_CHAR, T_I1, T_U1, T_I2, T_U2, T_I4, T_U4, T_I8, T_U8, T_R4, T_R8,
    T_STRING, T_PTR, T_BYREF, T_VALUETYPE, T_CLASS, T_VAR, T_ARRAY, T_GENERICINST,
    T_TYPEDBYREF, T_I = 0x18, T_U = 0x19, T_FNPTR = 0x1B, T_OBJECT = 0x1C, T_SZARRAY = 0x1D,
    T_MVAR = 0x1E,
};

struct ity_t {
    uint64_t dp = 0;
    uint16_t attrs = 0;
    uint8_t  kind = 0;
    bool     byref = false;
};

const char* prim_name(uint8_t k) {
    switch (k) {
    case T_VOID: return "void"; case T_BOOLEAN: return "bool"; case T_CHAR: return "char";
    case T_I1: return "sbyte"; case T_U1: return "byte"; case T_I2: return "short";
    case T_U2: return "ushort"; case T_I4: return "int"; case T_U4: return "uint";
    case T_I8: return "long"; case T_U8: return "ulong"; case T_R4: return "float";
    case T_R8: return "double"; case T_STRING: return "string"; case T_I: return "IntPtr";
    case T_U: return "UIntPtr"; case T_OBJECT: return "object"; case T_TYPEDBYREF: return "TypedReference";
    default: return nullptr;
    }
}

const char* prim_c(uint8_t k, uint32_t& size) {
    switch (k) {
    case T_BOOLEAN: size = 1; return "uint8_t"; case T_CHAR: size = 2; return "uint16_t";
    case T_I1: size = 1; return "int8_t"; case T_U1: size = 1; return "uint8_t";
    case T_I2: size = 2; return "int16_t"; case T_U2: size = 2; return "uint16_t";
    case T_I4: size = 4; return "int32_t"; case T_U4: size = 4; return "uint32_t";
    case T_I8: size = 8; return "int64_t"; case T_U8: size = 8; return "uint64_t";
    case T_R4: size = 4; return "float"; case T_R8: size = 8; return "double";
    case T_I: size = 8; return "intptr_t"; case T_U: size = 8; return "uintptr_t";
    default: size = 0; return nullptr;
    }
}

struct ctx_t {
    const meta_t& m;
    const bin_t&  bin;
    int           bv = 0;            // binary-side version*10
    uint64_t      types = 0, ntypes = 0;
    uint64_t      meta_base = 0;     // live v27+: VA of the metadata blob (type handles)
    std::unordered_map<int32_t, int32_t> byval_td;   // type index -> typedef (no-binary fallback)

    ctx_t(const meta_t& meta, const bin_t& b) : m(meta), bin(b) {}

    bool type_ptr(int32_t idx, uint64_t& tp) const {
        if (idx < 0 || static_cast<uint64_t>(idx) >= ntypes) return false;
        tp = bin.q(types + static_cast<uint64_t>(idx) * 8);
        return bin.mapped(tp, 12);
    }
    bool read(uint64_t tp, ity_t& t) const {
        uint32_t bits = 0;
        if (!bin.get(tp, t.dp) || !bin.get(tp + 8, bits)) return false;
        t.attrs = static_cast<uint16_t>(bits & 0xFFFF);
        t.kind  = static_cast<uint8_t>((bits >> 16) & 0xFF);
        t.byref = ((bits >> (bv >= 272 ? 29 : 30)) & 1u) != 0;
        return true;
    }
    int32_t td_of(uint64_t dp) const {
        if (dp < m.tds.size()) return static_cast<int32_t>(dp);
        if (meta_base && m.td_rec && dp >= meta_base + m.td_off) {
            const uint64_t rel = dp - meta_base - m.td_off;
            if (rel % m.td_rec == 0 && rel / m.td_rec < m.tds.size()) return static_cast<int32_t>(rel / m.td_rec);
        }
        return -1;
    }
    int32_t gp_of(uint64_t dp) const {
        if (dp < m.gp_names.size()) return static_cast<int32_t>(dp);
        if (meta_base && dp >= meta_base + m.gp_off) {
            const uint64_t rel = dp - meta_base - m.gp_off;
            if (rel % 16 == 0 && rel / 16 < m.gp_names.size()) return static_cast<int32_t>(rel / 16);
        }
        return -1;
    }

    std::string gc_params(int32_t gc) const {
        if (gc < 0 || static_cast<size_t>(gc) >= m.gcs.size()) return {};
        const auto& c = m.gcs[static_cast<size_t>(gc)];
        std::string s = "<";
        for (int32_t i = 0; i < c.argc && i < 64; ++i) {
            const int64_t g = int64_t{c.gp_start} + i;
            if (i) s += ", ";
            s += (g >= 0 && static_cast<size_t>(g) < m.gp_names.size()) ? m.str(m.gp_names[static_cast<size_t>(g)]) : "T";
        }
        return s + ">";
    }

    std::string td_name(int32_t i, bool with_ns, bool generic, int depth = 0) const {
        if (i < 0 || static_cast<size_t>(i) >= m.tds.size()) return "?";
        const td_t& t = m.tds[static_cast<size_t>(i)];
        std::string nm = m.str(t.name);
        if (generic && t.gcontainer >= 0) {
            const size_t tick = nm.find('`');
            if (tick != std::string::npos) nm.resize(tick);
            nm += gc_params(t.gcontainer);
        }
        if (t.declaring >= 0 && depth < 16) {
            int32_t outer = -1;
            uint64_t tp = 0;
            ity_t ot;
            if (type_ptr(t.declaring, tp) && read(tp, ot)) outer = td_of(ot.dp);
            else if (auto it = byval_td.find(t.declaring); it != byval_td.end()) outer = it->second;
            if (outer >= 0 && outer != i) return td_name(outer, with_ns, generic, depth + 1) + "." + nm;
        }
        if (with_ns) {
            const std::string ns = m.str(t.ns);
            if (!ns.empty()) return ns + "." + nm;
        }
        return nm;
    }

    std::string inst_args(uint64_t inst, int depth) const {
        const uint64_t argc = bin.q(inst), argv = bin.q(inst + 8);
        if (argc == 0 || argc > 32 || !bin.array(argv, argc)) return "<?>";
        std::string s = "<";
        for (uint64_t i = 0; i < argc; ++i) {
            if (i) s += ", ";
            s += name(bin.q(argv + i * 8), depth + 1);
        }
        return s + ">";
    }

    int32_t generic_class_td(uint64_t gclass) const {
        if (bv < 270) {
            const uint64_t idx = bin.q(gclass);
            return idx < m.tds.size() ? static_cast<int32_t>(idx) : -1;
        }
        ity_t t;
        return read(bin.q(gclass), t) ? td_of(t.dp) : -1;
    }

    std::string name(uint64_t tp, int depth = 0) const {
        ity_t t;
        if (depth > 12 || !read(tp, t)) return "?";
        if (const char* p = prim_name(t.kind)) return p;
        switch (t.kind) {
        case T_CLASS: case T_VALUETYPE: {
            const int32_t td = td_of(t.dp);
            return td >= 0 ? td_name(td, false, true) : "?";
        }
        case T_GENERICINST: {
            const int32_t td = generic_class_td(t.dp);
            std::string n = td >= 0 ? td_name(td, false, false) : "?";
            const size_t tick = n.find('`');
            if (tick != std::string::npos) n.resize(tick);
            return n + inst_args(bin.q(t.dp + 8), depth);
        }
        case T_SZARRAY: return name(t.dp, depth + 1) + "[]";
        case T_PTR: return name(t.dp, depth + 1) + "*";
        case T_ARRAY: {
            uint8_t rank = 1;
            bin.get(t.dp + 8, rank);
            return name(bin.q(t.dp), depth + 1) + "[" +
                   std::string(static_cast<size_t>(rank > 1 && rank < 32 ? rank - 1 : 0), ',') + "]";
        }
        case T_VAR: case T_MVAR: {
            const int32_t g = gp_of(t.dp);
            return g >= 0 ? m.str(m.gp_names[static_cast<size_t>(g)]) : "T";
        }
        case T_FNPTR: return "IntPtr";
        default: return "?";
        }
    }

    std::string name_idx(int32_t idx) const {
        uint64_t tp = 0;
        if (type_ptr(idx, tp)) return name(tp);
        if (auto it = byval_td.find(idx); it != byval_td.end()) return td_name(it->second, false, true);
        return "type_" + std::to_string(idx);
    }

    bool attrs_idx(int32_t idx, ity_t& t) const {
        uint64_t tp = 0;
        return type_ptr(idx, tp) && read(tp, t);
    }

    // live v27+: the runtime replaced klassIndex with pointers into the
    // metadata blob; vote the blob base from each typedef's own byval type
    void detect_meta_base() {
        if (bv < 270 || !ntypes) return;
        std::map<uint64_t, size_t> votes;
        for (size_t i = 0; i < m.tds.size() && i < 4096; ++i) {
            ity_t t;
            if (!attrs_idx(m.tds[i].byval, t) || (t.kind != T_CLASS && t.kind != T_VALUETYPE)) continue;
            const uint64_t rel = m.td_off + i * m.td_rec;
            if (t.dp < m.tds.size() || t.dp < rel) continue;
            ++votes[t.dp - rel];
        }
        size_t best = 0;
        for (const auto& [base, n] : votes)
            if (n > best) { best = n; meta_base = base; }
    }
};

// ---------------------------------------------------------------- model

struct field_out { std::string name, type, access; int64_t offset = 0; bool has_offset = false, is_static = false, is_const = false, readonly = false, thread_static = false; uint8_t kind = 0; int32_t type_index = -1; };
struct param_out { std::string name, type; };
struct ginst_out { std::string name; uint64_t va = 0; };
struct method_out { std::string name, ret, mods; std::vector<param_out> params; uint64_t va = 0; uint16_t flags = 0; uint32_t token = 0; int32_t slot = -1; std::vector<ginst_out> ginsts; };
struct prop_out { std::string name, type, mods; bool get = false, set = false; };
struct type_out {
    int32_t index = 0;
    std::string ns, name, kind, mods, parent;
    std::vector<std::string> ifaces;
    std::vector<field_out> fields;
    std::vector<method_out> methods;
    std::vector<prop_out> props;
    uint32_t instance_size = 0, static_size = 0;
    bool have_size = false, generic_def = false, valuetype = false;
};
struct image_out { std::string name; int32_t type_start = 0; std::vector<type_out> types; };

const char* access_of(uint32_t flags) {
    switch (flags & 7) {
    case 1: return "private"; case 2: return "private protected"; case 3: return "internal";
    case 4: return "protected"; case 5: return "protected internal"; case 6: return "public";
    default: return "";
    }
}
const char* type_access(uint32_t flags) {
    switch (flags & 7) {
    case 1: case 2: return "public"; case 3: return "private"; case 4: return "protected";
    case 7: return "protected internal";
    default: return "internal";
    }
}

std::string method_mods(uint16_t f) {
    std::string s = access_of(f);
    if (f & 0x10) s += " static";
    if (f & 0x400) s += " abstract";
    else if ((f & 0x40) && (f & 0x20)) s += " sealed override";
    else if ((f & 0x40) && (f & 0x100)) s += " virtual";
    else if (f & 0x40) s += " override";
    if (f & 0x2000) s += " extern";
    return s;
}

std::string c_ident(const std::string& s) {
    std::string o;
    for (char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        o.push_back((std::isalnum(c) || c == '_') ? ch : '_');
    }
    if (o.empty() || std::isdigit(static_cast<unsigned char>(o[0]))) o.insert(o.begin(), '_');
    return o;
}

} // namespace

// ---------------------------------------------------------------- public

bool image_from_file(std::vector<uint8_t> file, binary_image_t& out, std::string& error,
                     std::vector<std::string>& warnings) {
    out = {};
    if (file.size() >= 4 && file[0] == 'M' && file[1] == 'Z') {
        if (!parse_pe(file, false, 0, out, error)) return false;
    } else if (file.size() >= 4 && file[0] == 0x7F && file[1] == 'E' && file[2] == 'L' && file[3] == 'F') {
        if (!parse_elf(file, out, error, warnings)) return false;
    } else if (file.size() >= 4 && file[0] == 0x4F && file[1] == 0x15 && file[2] == 0x3D && file[3] == 0x1D) {
        error = "encrypted PS4 SELF: dump the module from the console first (target.ps4_dump_module "
                "format=elf) or use module= on the live target";
        return false;
    } else {
        error = "unrecognized binary format (expected PE32+ or ELF64)";
        return false;
    }
    out.bytes = std::move(file);
    return true;
}

bool image_from_memory(std::vector<uint8_t> span, uint64_t base,
                       std::vector<image_segment_t> segs, binary_image_t& out,
                       std::string& error) {
    out = {};
    if (span.empty()) { error = "empty module span"; return false; }
    if (!segs.empty()) {
        for (auto s : segs) {
            if (s.va < base || s.va - base >= span.size()) continue;
            s.off  = s.va - base;
            s.size = std::min<uint64_t>(s.size, span.size() - s.off);
            if (s.size) out.segs.push_back(s);
        }
    } else if (span.size() >= 2 && span[0] == 'M' && span[1] == 'Z') {
        std::string perr;
        if (!parse_pe(span, true, base, out, perr)) out.segs.clear();
    }
    if (out.segs.empty()) {
        image_segment_t s;
        s.va = base; s.off = 0; s.size = span.size(); s.exec = false;
        out.segs.push_back(s);
    }
    out.image_base  = base;
    out.file_layout = false;
    out.format      = "live";
    out.bytes       = std::move(span);
    return true;
}

dump_result_t dump(const std::vector<uint8_t>& metadata, const binary_image_t& image,
                   const dump_options_t& options) {
    dump_result_t res;
    meta_t m(metadata);
    if (!m.parse(res.warnings)) { res.error = m.error; return res; }

    bin_t bin(image);
    ctx_t cx(m, bin);
    cx.bv = m.v;
    for (size_t i = 0; i < m.tds.size(); ++i)
        if (m.tds[i].byval >= 0) cx.byval_td.emplace(m.tds[i].byval, static_cast<int32_t>(i));

    // ---- registrations
    uint64_t mreg = 0, creg = 0, cgm_count_va = 0, old_mptrs = 0, old_mcount = 0;
    if (bin.has()) {
        mreg = find_metadata_registration(bin, m.tds.size());
        if (mreg) {
            cx.types  = bin.q(mreg + MR_TYPES);
            cx.ntypes = bin.q(mreg + MR_TYPES_COUNT);
        } else {
            res.warnings.push_back("Il2CppMetadataRegistration not found: no field offsets, type sizes or "
                                   "field/parameter type names from the binary");
        }
        if (m.v >= 242) {
            cgm_count_va = find_codegen_modules(bin, m);
            if (!cgm_count_va) {
                res.warnings.push_back("Il2CppCodeRegistration not found (no codeGenModules table matching the "
                                       "metadata images): method addresses omitted");
            } else {
                std::vector<int> cands;
                if (m.major == 24) cands = {242, 243, 245};
                else if (m.major == 27) cands = {270, 271};
                else if (m.major == 29) cands = {290, 291};
                else cands = {310};
                for (int c : cands) {
                    const uint64_t start = cgm_count_va - 8ull * static_cast<uint64_t>(creg_index(c, "codeGenModulesCount"));
                    const uint64_t gi = 8ull * static_cast<uint64_t>(creg_index(c, "genericMethodPointersCount"));
                    const uint64_t ii = 8ull * static_cast<uint64_t>(creg_index(c, "invokerPointersCount"));
                    if (valid_ptr_table(bin, bin.q(start + gi), bin.q(start + gi + 8)) &&
                        valid_ptr_table(bin, bin.q(start + ii), bin.q(start + ii + 8))) {
                        creg = start;
                        cx.bv = c;
                        break;
                    }
                }
                if (!creg) {
                    creg = cgm_count_va - 8ull * static_cast<uint64_t>(creg_index(cands.front(), "codeGenModulesCount"));
                    cx.bv = cands.front();
                    res.warnings.push_back("CodeRegistration subversion not confirmed (generic/invoker tables did "
                                           "not validate): generic instance addresses omitted");
                }
            }
        } else {
            int32_t maxi = -1;
            for (const auto& md : m.mds) maxi = std::max(maxi, md.method_index);
            old_mcount = static_cast<uint64_t>(maxi + 1);
            const uint64_t at = find_method_pointers(bin, old_mcount);
            if (at) { creg = at; old_mptrs = bin.q(at + 8); }
            else res.warnings.push_back("Il2CppCodeRegistration.methodPointers not found: method addresses omitted");
        }
    }
    // 27.x: the Il2CppType bit layout changed in 27.2 (valuetype bit 31)
    if (m.major == 27 && cx.ntypes && cx.bv >= 271) {
        for (uint64_t i = 0; i < cx.ntypes && i < 20000; ++i) {
            uint32_t bits = 0;
            const uint64_t tp = bin.q(cx.types + i * 8);
            if (bin.get(tp + 8, bits) && ((bits >> 16) & 0xFF) == T_VALUETYPE && (bits >> 31)) { cx.bv = 272; break; }
        }
    }
    if (image.format == "live") cx.detect_meta_base();
    res.code_registration     = creg;
    res.metadata_registration = mreg;
    {
        const int show = std::max(cx.bv, m.v);
        char vb[16];
        std::snprintf(vb, sizeof vb, "%d.%d", show / 10, show % 10);
        res.version = vb;
    }

    // ---- method pointers per image (v24.2+)
    struct cgm_t { uint64_t count = 0, ptrs = 0; };
    std::unordered_map<std::string, cgm_t> modules;
    if (cgm_count_va) {
        const uint64_t n = bin.q(cgm_count_va), arr = bin.q(cgm_count_va + 8);
        std::string s;
        for (uint64_t i = 0; i < n; ++i) {
            const uint64_t mod = bin.q(arr + i * 8);
            if (!bin.cstr(bin.q(mod), s, 260)) continue;
            cgm_t c{bin.q(mod + 8), bin.q(mod + 16)};
            if (!bin.array(c.ptrs, c.count)) {
                res.warnings.push_back("codegen module " + s + ": method pointer table out of range");
                continue;
            }
            modules[s] = c;
        }
    }

    // ---- field offsets / sizes
    const uint64_t fo_tab = mreg ? bin.q(mreg + MR_FIELD_OFFSETS) : 0;
    const uint64_t sz_tab = mreg ? bin.q(mreg + MR_TYPE_SIZES) : 0;

    // ---- generic method instances (best effort)
    std::unordered_map<int32_t, std::vector<ginst_out>> ginsts;
    if (mreg && creg && m.v >= 242 && res.warnings.end() == std::find_if(res.warnings.begin(), res.warnings.end(),
            [](const std::string& w) { return w.rfind("CodeRegistration subversion", 0) == 0; })) {
        const uint64_t gi = 8ull * static_cast<uint64_t>(creg_index(cx.bv, "genericMethodPointersCount"));
        const uint64_t gmp_n = bin.q(creg + gi), gmp = bin.q(creg + gi + 8);
        const uint64_t tab_n = bin.q(mreg + MR_GENERIC_METHOD_TABLE_COUNT), tab = bin.q(mreg + MR_GENERIC_METHOD_TABLE);
        const uint64_t spec_n = bin.q(mreg + MR_METHOD_SPECS_COUNT), specs = bin.q(mreg + MR_METHOD_SPECS);
        const uint64_t inst_n = bin.q(mreg + MR_GENERIC_INSTS_COUNT), insts = bin.q(mreg + MR_GENERIC_INSTS);
        const uint64_t rec = (cx.bv == 245 || cx.bv >= 271) ? 16 : 12;
        if (tab_n && tab_n < (1ull << 24) && spec_n < (1ull << 24) && bin.mapped(tab, tab_n * rec) &&
            bin.mapped(specs, spec_n != 0 ? spec_n * 12 : 1) && bin.array(insts, inst_n)) {
            for (uint64_t i = 0; i < tab_n; ++i) {
                int32_t spec_i = -1, ptr_i = -1;
                bin.get(tab + i * rec, spec_i);
                bin.get(tab + i * rec + 4, ptr_i);
                if (spec_i < 0 || static_cast<uint64_t>(spec_i) >= spec_n || ptr_i < 0 || static_cast<uint64_t>(ptr_i) >= gmp_n) continue;
                int32_t mdi = -1, cls = -1, mth = -1;
                const uint64_t sp = specs + static_cast<uint64_t>(spec_i) * 12;
                bin.get(sp, mdi); bin.get(sp + 4, cls); bin.get(sp + 8, mth);
                if (mdi < 0 || static_cast<size_t>(mdi) >= m.mds.size()) continue;
                const uint64_t va = bin.q(gmp + static_cast<uint64_t>(ptr_i) * 8);
                if (!va) continue;
                auto& list = ginsts[mdi];
                if (list.size() >= 64) continue;
                const md_t& md = m.mds[static_cast<size_t>(mdi)];
                std::string n = cx.td_name(md.declaring, false, false);
                if (const size_t tick = n.find('`'); tick != std::string::npos) n.resize(tick);
                if (cls >= 0 && static_cast<uint64_t>(cls) < inst_n) n += cx.inst_args(bin.q(insts + static_cast<uint64_t>(cls) * 8), 0);
                n += "." + m.str(md.name);
                if (mth >= 0 && static_cast<uint64_t>(mth) < inst_n) n += cx.inst_args(bin.q(insts + static_cast<uint64_t>(mth) * 8), 0);
                list.push_back({n, va});
                ++res.generic_instances;
            }
        } else if (tab_n) {
            res.warnings.push_back("generic method tables out of range: generic instance addresses omitted");
        }
    }

    // ---- build the model
    std::vector<image_out> images;
    images.reserve(m.imgs.size());
    for (const auto& im : m.imgs) {
        image_out io;
        io.name = m.str(im.name);
        io.type_start = im.type_start;
        const cgm_t* mod = nullptr;
        if (auto it = modules.find(io.name); it != modules.end()) mod = &it->second;
        for (uint64_t k = 0; k < im.type_count; ++k) {
            const int64_t ti = int64_t{im.type_start} + static_cast<int64_t>(k);
            if (ti < 0 || static_cast<size_t>(ti) >= m.tds.size()) break;
            const td_t& t = m.tds[static_cast<size_t>(ti)];
            type_out to;
            to.index = static_cast<int32_t>(ti);
            to.ns = m.str(t.ns);
            to.name = cx.td_name(to.index, false, true);
            to.valuetype = t.valuetype();
            to.generic_def = t.gcontainer >= 0;
            to.kind = (t.flags & 0x20) ? "interface" : t.is_enum() ? "enum" : t.valuetype() ? "struct" : "class";
            to.mods = type_access(t.flags);
            if ((t.flags & 0x80) && (t.flags & 0x100)) to.mods += " static";
            else if ((t.flags & 0x80) && !(t.flags & 0x20)) to.mods += " abstract";
            else if ((t.flags & 0x100) && !t.valuetype()) to.mods += " sealed";
            if (t.parent >= 0 && !t.valuetype()) {
                const std::string p = cx.name_idx(t.parent);
                if (p != "object" && p != "ValueType" && p != "Enum") to.parent = p;
            }
            if (t.is_enum() && t.element >= 0) to.parent = cx.name_idx(t.element);
            for (uint16_t j = 0; j < t.interfaces_count; ++j) {
                const int64_t ii = int64_t{t.interfaces_start} + j;
                if (ii < 0 || static_cast<size_t>(ii) >= m.ifaces.size()) break;
                to.ifaces.push_back(cx.name_idx(m.ifaces[static_cast<size_t>(ii)]));
            }
            if (sz_tab) {
                const uint64_t sp = bin.q(sz_tab + static_cast<uint64_t>(ti) * 8);
                if (bin.get(sp, to.instance_size) && bin.get(sp + 8, to.static_size)) to.have_size = true;
            }
            const uint64_t fo = fo_tab ? bin.q(fo_tab + static_cast<uint64_t>(ti) * 8) : 0;
            for (uint16_t j = 0; j < t.field_count; ++j) {
                const int64_t fi = int64_t{t.field_start} + j;
                if (fi < 0 || static_cast<size_t>(fi) >= m.fds.size()) break;
                const fd_t& f = m.fds[static_cast<size_t>(fi)];
                field_out fo_;
                fo_.name = m.str(f.name);
                fo_.type = cx.name_idx(f.type);
                fo_.type_index = f.type;
                ity_t ft;
                if (cx.attrs_idx(f.type, ft)) {
                    fo_.kind = ft.kind;
                    fo_.access = access_of(ft.attrs);
                    fo_.is_static = (ft.attrs & 0x10) != 0;
                    fo_.is_const = (ft.attrs & 0x40) != 0;
                    fo_.readonly = (ft.attrs & 0x20) != 0;
                }
                int32_t off = 0;
                if (fo && !fo_.is_const && bin.get(fo + 4ull * j, off)) {
                    if (off == -1 && fo_.is_static) {
                        fo_.thread_static = true;
                    } else {
                        if (off > 0 && t.valuetype() && !fo_.is_static) off -= 16;
                        fo_.offset = off;
                        fo_.has_offset = true;
                    }
                }
                to.fields.push_back(std::move(fo_));
                ++res.fields;
            }
            for (uint16_t j = 0; j < t.method_count; ++j) {
                const int64_t mi = int64_t{t.method_start} + j;
                if (mi < 0 || static_cast<size_t>(mi) >= m.mds.size()) break;
                const md_t& md = m.mds[static_cast<size_t>(mi)];
                method_out mo;
                mo.name = m.str(md.name);
                if (md.gcontainer >= 0) mo.name += cx.gc_params(md.gcontainer);
                mo.ret = cx.name_idx(md.ret);
                mo.flags = md.flags;
                mo.token = md.token;
                mo.slot = md.slot == 0xFFFF ? -1 : md.slot;
                mo.mods = method_mods(md.flags);
                for (uint16_t p = 0; p < md.param_count; ++p) {
                    const int64_t pi = int64_t{md.param_start} + p;
                    if (pi < 0 || static_cast<size_t>(pi) >= m.pds.size()) break;
                    const pd_t& pd = m.pds[static_cast<size_t>(pi)];
                    param_out po;
                    po.name = m.str(pd.name);
                    po.type = cx.name_idx(pd.type);
                    ity_t pt;
                    if (cx.attrs_idx(pd.type, pt) && pt.byref)
                        po.type = ((pt.attrs & 0x2) && !(pt.attrs & 0x1) ? "out " : "ref ") + po.type;
                    mo.params.push_back(std::move(po));
                }
                if (mod) {
                    const uint32_t row = md.token & 0x00FFFFFFu;
                    if (row && row <= mod->count) mo.va = bin.q(mod->ptrs + (row - 1ull) * 8);
                } else if (old_mptrs && md.method_index >= 0 && static_cast<uint64_t>(md.method_index) < old_mcount) {
                    mo.va = bin.q(old_mptrs + static_cast<uint64_t>(md.method_index) * 8);
                }
                if (mo.va) ++res.methods_with_address;
                if (auto it = ginsts.find(static_cast<int32_t>(mi)); it != ginsts.end()) mo.ginsts = it->second;
                to.methods.push_back(std::move(mo));
                ++res.methods;
            }
            for (uint16_t j = 0; j < t.property_count; ++j) {
                const int64_t pi = int64_t{t.property_start} + j;
                if (pi < 0 || static_cast<size_t>(pi) >= m.props.size()) break;
                const prop_t& p = m.props[static_cast<size_t>(pi)];
                prop_out po;
                po.name = m.str(p.name);
                const md_t* acc = nullptr;
                auto method_at = [&](int32_t rel) -> const md_t* {
                    if (rel < 0) return nullptr;
                    const int64_t g = int64_t{t.method_start} + rel;
                    return (g >= 0 && static_cast<size_t>(g) < m.mds.size()) ? &m.mds[static_cast<size_t>(g)] : nullptr;
                };
                if (const md_t* g = method_at(p.get)) { po.get = true; acc = g; po.type = cx.name_idx(g->ret); }
                if (const md_t* s = method_at(p.set)) {
                    po.set = true;
                    if (!acc) {
                        acc = s;
                        const int64_t last = int64_t{s->param_start} + s->param_count - 1;
                        if (s->param_count && last >= 0 && static_cast<size_t>(last) < m.pds.size())
                            po.type = cx.name_idx(m.pds[static_cast<size_t>(last)].type);
                    }
                }
                if (acc) po.mods = method_mods(acc->flags);
                to.props.push_back(std::move(po));
            }
            io.types.push_back(std::move(to));
            ++res.types;
        }
        images.push_back(std::move(io));
    }
    res.images = images.size();
    if (bin.has() && res.methods && !res.methods_with_address && creg)
        res.warnings.push_back("no method resolved to an address: the binary may not match this metadata");

    const uint64_t ib = image.image_base;
    auto addr_line = [&](uint64_t va) {
        std::string s = "// RVA: " + hx(va - ib);
        if (image.file_layout) {
            for (const auto& sg : image.segs)
                if (va >= sg.va && va - sg.va < sg.size) { s += " Offset: " + hx(sg.off + (va - sg.va)); break; }
        }
        return s + " VA: " + hx(va);
    };

    // ---- dump.cs
    if (options.cs) {
        std::string& o = res.dump_cs;
        o.reserve(res.methods * 96 + res.fields * 48);
        for (size_t i = 0; i < images.size(); ++i)
            o += "// Image " + std::to_string(i) + ": " + images[i].name + " - " + std::to_string(images[i].type_start) + "\n";
        for (const auto& io : images) {
            for (const auto& t : io.types) {
                o += "\n// Namespace: " + t.ns + "\n";
                o += t.mods + " " + t.kind + " " + t.name;
                std::vector<std::string> ext;
                if (!t.parent.empty()) ext.push_back(t.parent);
                for (const auto& f : t.ifaces) ext.push_back(f);
                for (size_t k = 0; k < ext.size(); ++k) o += (k ? ", " : " : ") + ext[k];
                o += " // TypeDefIndex: " + std::to_string(t.index) + "\n{\n";
                if (!t.fields.empty()) {
                    o += "\t// Fields\n";
                    for (const auto& f : t.fields) {
                        o += "\t" + f.access;
                        if (f.is_const) o += " const";
                        else {
                            if (f.is_static) o += " static";
                            if (f.readonly) o += " readonly";
                        }
                        o += " " + f.type + " " + f.name + ";";
                        if (f.thread_static) o += " // ThreadStatic";
                        else if (f.has_offset) o += " // " + hx(static_cast<uint64_t>(f.offset));
                        o += "\n";
                    }
                }
                if (!t.props.empty()) {
                    o += "\n\t// Properties\n";
                    for (const auto& p : t.props) {
                        o += "\t" + p.mods + " " + p.type + " " + p.name + " {";
                        if (p.get) o += " get;";
                        if (p.set) o += " set;";
                        o += " }\n";
                    }
                }
                if (!t.methods.empty()) {
                    o += "\n\t// Methods\n";
                    for (const auto& mo : t.methods) {
                        o += "\n\t" + (mo.va ? addr_line(mo.va) : std::string("// RVA: -1 Offset: -1"));
                        if (mo.slot >= 0) o += " Slot: " + std::to_string(mo.slot);
                        o += "\n\t" + mo.mods + " " + mo.ret + " " + mo.name + "(";
                        for (size_t k = 0; k < mo.params.size(); ++k)
                            o += (k ? ", " : "") + mo.params[k].type + " " + mo.params[k].name;
                        o += ") { }\n";
                        if (!mo.ginsts.empty()) {
                            o += "\t/* GenericInstMethod :\n";
                            for (const auto& g : mo.ginsts)
                                o += "\t|\n\t|-" + addr_line(g.va).substr(3) + "\n\t|-" + g.name + "\n";
                            o += "\t*/\n";
                        }
                    }
                }
                o += "}\n";
            }
        }
    }

    // ---- il2cpp.json
    if (options.json) {
        json j;
        j["version"] = res.version;
        j["image_base"] = ib;
        j["code_registration"] = creg;
        j["metadata_registration"] = mreg;
        json jimgs = json::array();
        for (const auto& io : images) {
            json jt = json::array();
            for (const auto& t : io.types) {
                json jf = json::array(), jm = json::array(), jp = json::array();
                for (const auto& f : t.fields)
                    jf.push_back({{"name", f.name}, {"type", f.type},
                                  {"offset", f.has_offset ? json(f.offset) : json(nullptr)},
                                  {"static", f.is_static}, {"const", f.is_const},
                                  {"thread_static", f.thread_static}});
                for (const auto& mo : t.methods) {
                    json params = json::array();
                    for (const auto& p : mo.params) params.push_back({{"name", p.name}, {"type", p.type}});
                    json e = {{"name", mo.name}, {"return_type", mo.ret}, {"params", params},
                              {"flags", mo.flags}, {"token", mo.token},
                              {"va", mo.va ? json(mo.va) : json(nullptr)},
                              {"rva", mo.va ? json(mo.va - ib) : json(nullptr)}};
                    if (!mo.ginsts.empty()) {
                        json g = json::array();
                        for (const auto& gi : mo.ginsts) g.push_back({{"name", gi.name}, {"va", gi.va}, {"rva", gi.va - ib}});
                        e["generic_instances"] = std::move(g);
                    }
                    jm.push_back(std::move(e));
                }
                for (const auto& p : t.props)
                    jp.push_back({{"name", p.name}, {"type", p.type}, {"get", p.get}, {"set", p.set}});
                json e = {{"index", t.index}, {"namespace", t.ns}, {"name", t.name}, {"kind", t.kind},
                          {"parent", t.parent}, {"interfaces", t.ifaces}, {"fields", std::move(jf)},
                          {"methods", std::move(jm)}, {"properties", std::move(jp)}};
                if (t.have_size) { e["instance_size"] = t.instance_size; e["static_fields_size"] = t.static_size; }
                jt.push_back(std::move(e));
            }
            jimgs.push_back({{"name", io.name}, {"type_start", io.type_start}, {"types", std::move(jt)}});
        }
        j["images"] = std::move(jimgs);
        res.il2cpp_json = j.dump(-1, ' ', false, json::error_handler_t::replace);
    }

    // ---- il2cpp.h: flat structs, explicit padding, exact sizes
    if (options.header) {
        if (!mreg) {
            res.warnings.push_back("il2cpp.h skipped: field offsets need the MetadataRegistration");
        } else {
            std::string& o = res.il2cpp_h;
            o += "// il2cpp.h generated by SlopStation re.il2cpp_dump (metadata " + res.version + ")\n"
                 "// value-type and generic fields are byte blobs sized from the field layout\n"
                 "#pragma once\n#include <stdint.h>\n#pragma pack(push, 1)\n";
            std::unordered_map<int32_t, const type_out*> by_index;
            for (const auto& io : images)
                for (const auto& t : io.types) by_index[t.index] = &t;
            std::unordered_set<std::string> used;
            auto emit = [&](const std::string& sname, std::vector<const field_out*> fs, uint64_t start,
                            uint64_t end, bool header_words) {
                std::sort(fs.begin(), fs.end(), [](const field_out* a, const field_out* b) { return a->offset < b->offset; });
                o += "struct " + sname + " {\n";
                uint64_t cur = start;
                if (header_words) { o += "    void* klass;    // 0x0\n    void* monitor;  // 0x8\n"; cur = 16; }
                std::unordered_set<std::string> names;
                for (size_t k = 0; k < fs.size(); ++k) {
                    const field_out& f = *fs[k];
                    const uint64_t off = static_cast<uint64_t>(f.offset);
                    if (off < cur) { o += "    // overlapping: " + f.type + " " + f.name + " @ " + hx(off) + "\n"; continue; }
                    if (off > cur) o += "    uint8_t _pad_" + hx(cur).substr(2) + "[" + std::to_string(off - cur) + "];\n";
                    uint64_t next = end;
                    for (size_t l = k + 1; l < fs.size(); ++l)
                        if (static_cast<uint64_t>(fs[l]->offset) > off) { next = static_cast<uint64_t>(fs[l]->offset); break; }
                    const uint64_t gap = next > off ? next - off : 0;
                    std::string id = c_ident(f.name);
                    while (!names.insert(id).second) id += "_";
                    uint32_t width = 0;
                    const char* ct = prim_c(f.kind, width);
                    if (f.kind == T_VALUETYPE) {
                        ity_t ft;
                        if (cx.attrs_idx(f.type_index, ft)) {
                            const int32_t td = cx.td_of(ft.dp);
                            if (td >= 0 && m.tds[static_cast<size_t>(td)].is_enum()) {
                                ity_t et;
                                if (cx.attrs_idx(m.tds[static_cast<size_t>(td)].element, et)) ct = prim_c(et.kind, width);
                            }
                        }
                    }
                    const bool pointer = f.kind == T_STRING || f.kind == T_CLASS || f.kind == T_OBJECT ||
                                         f.kind == T_SZARRAY || f.kind == T_ARRAY || f.kind == T_PTR ||
                                         f.kind == T_FNPTR || f.kind == T_BYREF ||
                                         (f.kind == T_GENERICINST && [&] {
                                             ity_t gt;
                                             if (!cx.attrs_idx(f.type_index, gt)) return false;
                                             const int32_t td = cx.generic_class_td(gt.dp);
                                             return td >= 0 && !m.tds[static_cast<size_t>(td)].valuetype();
                                         }());
                    if (pointer && gap >= 8) { ct = "void*"; width = 8; }
                    if (ct && width && width <= gap) {
                        o += "    " + std::string(ct) + " " + id + ";  // " + hx(off) + " " + f.type + "\n";
                        cur = off + width;
                    } else if (gap) {
                        o += "    uint8_t " + id + "[" + std::to_string(gap) + "];  // " + hx(off) + " " + f.type + "\n";
                        cur = off + gap;
                    } else {
                        o += "    // " + f.type + " " + f.name + " @ " + hx(off) + " (no room)\n";
                    }
                }
                if (end > cur) o += "    uint8_t _pad_" + hx(cur).substr(2) + "[" + std::to_string(end - cur) + "];\n";
                o += "};\n";
            };
            for (const auto& io : images) {
                for (const auto& t : io.types) {
                    if (t.generic_def || t.kind == "interface" || !t.have_size) continue;
                    std::string base = c_ident((t.ns.empty() ? "" : t.ns + "_") + t.name);
                    while (!used.insert(base).second) base += "_";
                    std::vector<const field_out*> inst, stat;
                    // inherited instance fields come first in the object
                    std::vector<const type_out*> chain;
                    for (const type_out* c = &t; c && chain.size() < 64;) {
                        chain.push_back(c);
                        const td_t& td = m.tds[static_cast<size_t>(c->index)];
                        ity_t pt;
                        int32_t pidx = -1;
                        if (td.parent >= 0 && cx.attrs_idx(td.parent, pt)) pidx = cx.td_of(pt.dp);
                        auto it = by_index.find(pidx);
                        c = (pidx >= 0 && it != by_index.end()) ? it->second : nullptr;
                    }
                    for (const type_out* c : chain)
                        for (const auto& f : c->fields) {
                            if (!f.has_offset || f.is_const || f.offset < 0) continue;
                            if (c == &t && f.is_static) stat.push_back(&f);
                            else if (!f.is_static) inst.push_back(&f);
                        }
                    o += "\n// " + (t.ns.empty() ? t.name : t.ns + "." + t.name) + " (TypeDefIndex: " + std::to_string(t.index) + ")\n";
                    if (t.valuetype) {
                        const uint64_t size = t.instance_size > 16 ? t.instance_size - 16 : 0;
                        emit(base + "_t", inst, 0, size, false);
                    } else {
                        emit(base + "_o", inst, 16, t.instance_size, true);
                    }
                    if (!stat.empty() && t.static_size) emit(base + "_StaticFields", stat, 0, t.static_size, false);
                }
            }
            o += "\n#pragma pack(pop)\n";
        }
    }
    res.ok = true;
    return res;
}

} // namespace slop::core::re::il2cpp
