// src/tests/test_engine_dumpers.cpp
// re.il2cpp_dump / re.ue_dump engines over synthetic fixtures built here:
// IL2CPP metadata (v24.2, v29) + a PE64 carrying the registration tables, and
// a fake UE5 process memory (FNamePool, chunked GUObjectArray, FField props)

#include "harness.hpp"

#include "core/memory/reader.hpp"
#include "core/re/il2cpp_dump.hpp"
#include "core/re/source_dump.hpp"
#include "core/re/ue_dump.hpp"

#include <nlohmann/json.hpp>

#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace il2cpp = slop::core::re::il2cpp;
namespace source = slop::core::re::source;
namespace ue = slop::core::re::ue;

namespace {

// ------------------------------------------------------------ byte helpers

struct bytes_t {
    std::vector<uint8_t> d;
    void i32(int32_t v) { put(&v, 4); }
    void u32(uint32_t v) { put(&v, 4); }
    void u16(uint16_t v) { put(&v, 2); }
    void put(const void* p, size_t n) {
        const auto* b = static_cast<const uint8_t*>(p);
        d.insert(d.end(), b, b + n);
    }
};

template <class T>
void poke(std::vector<uint8_t>& b, size_t off, T v) {
    if (off + sizeof(T) > b.size()) b.resize(off + sizeof(T));
    std::memcpy(b.data() + off, &v, sizeof(T));
}

// ------------------------------------------------------------ il2cpp fixture

// System.Object (0) and value type Vec (1) in mscorlib.dll, class Player (2)
// in Assembly-CSharp.dll with an instance int, a Vec, a static int, three
// methods and a property
std::vector<uint8_t> make_metadata(int ver) {
    const size_t hdr_words = ver == 242 ? 66 : 64;
    std::vector<uint8_t> b(hdr_words * 4, 0);
    auto hw = [&](size_t i, uint32_t v) { poke<uint32_t>(b, i * 4, v); };
    hw(0, 0xFAB11BAFu);
    hw(1, static_cast<uint32_t>(ver / 10));
    hw(2, static_cast<uint32_t>(hdr_words * 4));

    std::string strs;
    auto S = [&](const char* s) {
        const auto off = static_cast<uint32_t>(strs.size());
        strs += s;
        strs.push_back('\0');
        return off;
    };
    const uint32_t s_empty = S("");
    const uint32_t s_corlib = S("mscorlib.dll"), s_asm = S("Assembly-CSharp.dll"), s_sys = S("System");
    const uint32_t s_obj = S("Object"), s_vec = S("Vec"), s_player = S("Player");
    const uint32_t s_ctor = S(".ctor"), s_update = S("Update"), s_damage = S("Damage"), s_geth = S("get_Health");
    const uint32_t s_health = S("health"), s_pos = S("pos"), s_count = S("count"), s_x = S("x"), s_y = S("y");
    const uint32_t s_amount = S("amount"), s_Health = S("Health");

    auto table = [&](size_t word, const std::vector<uint8_t>& data) {
        hw(word, static_cast<uint32_t>(b.size()));
        hw(word + 1, static_cast<uint32_t>(data.size()));
        b.insert(b.end(), data.begin(), data.end());
    };
    table(6, std::vector<uint8_t>(strs.begin(), strs.end()));

    bytes_t td;
    auto typedef_rec = [&](uint32_t name, uint32_t ns, int32_t byval, int32_t parent, uint32_t flags,
                           int32_t fstart, int32_t mstart, int32_t pstart, uint16_t mc, uint16_t pc,
                           uint16_t fc, uint32_t bitfield) {
        td.u32(name); td.u32(ns); td.i32(byval);
        if (ver <= 245) td.i32(-1);                 // byrefTypeIndex
        td.i32(-1); td.i32(parent); td.i32(-1); td.i32(-1);   // declaring, parent, element, gcontainer
        td.u32(flags);
        td.i32(fstart); td.i32(mstart); td.i32(0); td.i32(pstart);
        td.i32(0); td.i32(0); td.i32(0); td.i32(0);
        td.u16(mc); td.u16(pc); td.u16(fc); td.u16(0); td.u16(0); td.u16(0); td.u16(0); td.u16(0);
        td.u32(bitfield); td.u32(0x02000001);
    };
    typedef_rec(s_obj, s_sys, 0, -1, 0x1, 0, 0, 0, 1, 0, 0, 0);
    typedef_rec(s_vec, s_sys, 1, -1, 0x1, 3, 1, 0, 0, 0, 2, 1);
    typedef_rec(s_player, s_empty, 2, 0, 0x1, 0, 1, 0, 3, 1, 3, 0);
    table(40, td.d);

    bytes_t md;
    auto method_rec = [&](uint32_t name, int32_t decl, int32_t ret, int32_t pstart, uint32_t token, uint16_t pcount) {
        md.u32(name); md.i32(decl); md.i32(ret);
        if (ver >= 310) md.i32(0);
        md.i32(pstart); md.i32(-1); md.u32(token);
        md.u16(0x0086); md.u16(0); md.u16(0xFFFF); md.u16(pcount);
    };
    method_rec(s_ctor, 0, 6, 0, 0x06000001, 0);
    method_rec(s_update, 2, 6, 0, 0x06000001, 0);
    method_rec(s_damage, 2, 6, 0, 0x06000002, 1);
    method_rec(s_geth, 2, 3, 0, 0x06000003, 0);
    table(12, md.d);

    bytes_t fd;
    auto field_rec = [&](uint32_t name, int32_t type) { fd.u32(name); fd.i32(type); fd.u32(0x04000001); };
    field_rec(s_health, 3); field_rec(s_pos, 4); field_rec(s_count, 5); field_rec(s_x, 7); field_rec(s_y, 7);
    table(24, fd.d);

    bytes_t pd;
    pd.u32(s_amount); pd.u32(0x08000001); pd.i32(8);
    table(22, pd.d);

    bytes_t pr;
    pr.u32(s_Health); pr.i32(2); pr.i32(-1); pr.u32(0); pr.u32(0x17000001);
    table(10, pr.d);

    table(26, {});   // generic parameters
    table(30, {});   // generic containers
    table(34, {});   // interfaces

    bytes_t im;
    auto image_rec = [&](uint32_t name, int32_t start, uint32_t count) {
        im.u32(name); im.i32(0); im.i32(start); im.u32(count); im.i32(0); im.u32(0); im.i32(-1); im.u32(1);
        im.i32(0); im.u32(0);
    };
    image_rec(s_corlib, 0, 2);
    image_rec(s_asm, 2, 1);
    table(42, im.d);
    return b;
}

constexpr uint64_t kBase = 0x180000000ull;

// a PE32+ with .text (RVA 0x1000) and .data (RVA 0x2000) holding the
// registration tables laid out for metadata version `ver`
std::vector<uint8_t> make_pe(int ver) {
    std::vector<uint8_t> f(0x4400, 0);
    poke<uint16_t>(f, 0, 0x5A4D);
    poke<uint32_t>(f, 0x3C, 0x40);
    poke<uint32_t>(f, 0x40, 0x00004550);
    poke<uint16_t>(f, 0x44, 0x8664);
    poke<uint16_t>(f, 0x46, 2);
    poke<uint16_t>(f, 0x54, 0xF0);
    poke<uint16_t>(f, 0x58, 0x20B);
    poke<uint64_t>(f, 0x58 + 24, kBase);
    auto section = [&](size_t at, const char* name, uint32_t vsize, uint32_t rva, uint32_t raw, uint32_t ptr, uint32_t chars) {
        std::memcpy(f.data() + at, name, std::strlen(name));
        poke(f, at + 8, vsize); poke(f, at + 12, rva); poke(f, at + 16, raw); poke(f, at + 20, ptr); poke(f, at + 36, chars);
    };
    section(0x148, ".text", 0x1000, 0x1000, 0x1000, 0x400, 0x60000020u);
    section(0x170, ".data", 0x3000, 0x2000, 0x3000, 0x1400, 0xC0000040u);
    auto off = [](uint64_t va) {
        const uint64_t rva = va - kBase;
        return static_cast<size_t>(rva < 0x2000 ? rva - 0x1000 + 0x400 : rva - 0x2000 + 0x1400);
    };
    auto q = [&](uint64_t va, uint64_t v) { poke<uint64_t>(f, off(va), v); };
    auto d = [&](uint64_t va, uint32_t v) { poke<uint32_t>(f, off(va), v); };
    auto str = [&](uint64_t va, const char* s) { std::memcpy(f.data() + off(va), s, std::strlen(s) + 1); };
    const uint64_t D = kBase + 0x2000;

    str(D + 0x000, "mscorlib.dll");
    str(D + 0x020, "Assembly-CSharp.dll");
    // Il2CppType: datapoint + attrs | type << 16
    const struct { uint64_t dp; uint32_t attrs; uint32_t kind; } types[] = {
        {0, 0, 0x1C},        // 0 System.Object (OBJECT)
        {1, 0, 0x11},        // 1 Vec byval
        {2, 0, 0x12},        // 2 Player byval
        {0, 0x6, 0x08},      // 3 public int
        {1, 0x6, 0x11},      // 4 public Vec
        {0, 0x16, 0x08},     // 5 public static int
        {0, 0, 0x01},        // 6 void
        {0, 0x6, 0x0C},      // 7 public float
        {0, 0, 0x08},        // 8 int (parameter)
    };
    for (size_t i = 0; i < 9; ++i) {
        q(D + 0x100 + i * 16, types[i].dp);
        d(D + 0x108 + i * 16, types[i].attrs | (types[i].kind << 16));
        q(D + 0x200 + i * 8, D + 0x100 + i * 16);
    }
    // field offsets: Object none, Vec {x,y}, Player {health, pos, count}
    q(D + 0x300, 0); q(D + 0x308, D + 0x340); q(D + 0x310, D + 0x350);
    d(D + 0x340, 0x10); d(D + 0x344, 0x14);
    d(D + 0x350, 0x10); d(D + 0x354, 0x18); d(D + 0x358, 0x0);
    // Il2CppTypeDefinitionSizes {instance, native, static, thread_static}
    const uint32_t sizes[3][2] = {{0x10, 0}, {0x18, 0}, {0x20, 4}};
    for (size_t i = 0; i < 3; ++i) {
        d(D + 0x380 + i * 16, sizes[i][0]);
        d(D + 0x388 + i * 16, sizes[i][1]);
        q(D + 0x400 + i * 8, D + 0x380 + i * 16);
    }
    // Il2CppMetadataRegistration
    const uint64_t mr = D + 0x500;
    q(mr + 0x30, 9); q(mr + 0x38, D + 0x200);
    q(mr + 0x50, 3); q(mr + 0x58, D + 0x300);
    q(mr + 0x60, 3); q(mr + 0x68, D + 0x400);
    // codegen modules {moduleName, methodPointerCount, methodPointers}
    q(D + 0x600, D + 0x000); q(D + 0x608, 1); q(D + 0x610, D + 0x700);
    q(D + 0x640, D + 0x020); q(D + 0x648, 3); q(D + 0x650, D + 0x710);
    q(D + 0x680, D + 0x600); q(D + 0x688, D + 0x640);
    q(D + 0x700, kBase + 0x1010);
    q(D + 0x710, kBase + 0x1020); q(D + 0x718, kBase + 0x1030); q(D + 0x720, kBase + 0x1040);
    q(D + 0x780, kBase + 0x1050);   // generic method pointers
    q(D + 0x788, kBase + 0x1060);   // invokers
    // Il2CppCodeRegistration: field slots per version
    const uint64_t cr = D + 0x800;
    const int gmp = 2, inv = ver == 242 ? 4 : 5, cgm = ver == 242 ? 12 : 13;
    q(cr + gmp * 8, 1); q(cr + gmp * 8 + 8, D + 0x780);
    q(cr + inv * 8, 1); q(cr + inv * 8 + 8, D + 0x788);
    q(cr + cgm * 8, 2); q(cr + cgm * 8 + 8, D + 0x680);
    return f;
}

bool has(const std::string& hay, const char* needle) { return hay.find(needle) != std::string::npos; }

void check_il2cpp(int ver, const char* expect_version) {
    il2cpp::binary_image_t img;
    std::string err;
    std::vector<std::string> warns;
    REQUIRE(il2cpp::image_from_file(make_pe(ver), img, err, warns));
    REQUIRE(img.segs.size() == 2);
    const auto r = il2cpp::dump(make_metadata(ver), img);
    if (!r.ok) std::printf("  il2cpp error: %s\n", r.error.c_str());
    REQUIRE(r.ok);
    for (const auto& w : r.warnings) std::printf("  warning: %s\n", w.c_str());
    REQUIRE_STR_EQ(r.version, expect_version);
    REQUIRE_EQ(r.images, 2u);
    REQUIRE_EQ(r.types, 3u);
    REQUIRE_EQ(r.methods, 4u);
    REQUIRE_EQ(r.fields, 5u);
    REQUIRE_EQ(r.methods_with_address, 4u);
    REQUIRE_EQ(r.metadata_registration, kBase + 0x2500);
    REQUIRE_EQ(r.code_registration, kBase + 0x2800);
    CHECK(r.warnings.empty());

    CHECK(has(r.dump_cs, "public class Player // TypeDefIndex: 2"));
    CHECK(has(r.dump_cs, "\tpublic int health; // 0x10\n"));
    CHECK(has(r.dump_cs, "\tpublic Vec pos; // 0x18\n"));
    CHECK(has(r.dump_cs, "\tpublic static int count; // 0x0\n"));
    CHECK(has(r.dump_cs, "\tpublic float x; // 0x0\n"));     // value type: object header removed
    CHECK(has(r.dump_cs, "\tpublic float y; // 0x4\n"));
    CHECK(has(r.dump_cs, "// RVA: 0x1020 Offset: 0x420 VA: 0x180001020"));
    CHECK(has(r.dump_cs, "public void Damage(int amount) { }"));
    CHECK(has(r.dump_cs, "public int Health { get; }"));
    CHECK(has(r.dump_cs, "// RVA: 0x1010 Offset: 0x410 VA: 0x180001010"));

    const auto j = nlohmann::json::parse(r.il2cpp_json);
    const auto& player = j["images"][1]["types"][0];
    CHECK(player["name"] == "Player");
    CHECK(player["fields"][0]["offset"] == 16);
    CHECK(player["fields"][2]["static"] == true);
    CHECK(player["methods"][0]["rva"] == 0x1020);
    CHECK(player["instance_size"] == 0x20);

    CHECK(has(r.il2cpp_h, "struct Player_o {"));
    CHECK(has(r.il2cpp_h, "int32_t health;"));
    CHECK(has(r.il2cpp_h, "uint8_t pos[8];"));
    CHECK(has(r.il2cpp_h, "struct Player_StaticFields {"));
    CHECK(has(r.il2cpp_h, "struct System_Vec_t {"));
    CHECK(has(r.il2cpp_h, "float y;"));
}

} // namespace

TEST_CASE(il2cpp_v24_2_metadata_and_pe_registrations) { check_il2cpp(242, "24.2"); }

TEST_CASE(il2cpp_v29_metadata_and_pe_registrations) { check_il2cpp(290, "29.0"); }

TEST_CASE(il2cpp_metadata_only_without_binary) {
    const auto r = il2cpp::dump(make_metadata(290), il2cpp::binary_image_t{});
    REQUIRE(r.ok);
    REQUIRE_EQ(r.types, 3u);
    REQUIRE_EQ(r.methods_with_address, 0u);
    CHECK(r.il2cpp_h.empty());
    // byval fallback still names fields whose type is a typedef's own type
    CHECK(has(r.dump_cs, "class Player"));
}

TEST_CASE(il2cpp_malformed_inputs_fail_cleanly) {
    const auto empty = il2cpp::binary_image_t{};
    auto meta = make_metadata(242);

    auto trunc = meta;
    trunc.resize(0x60);
    CHECK(!il2cpp::dump(trunc, empty).ok);

    auto bad = meta;
    poke<uint32_t>(bad, 0, 0x12345678u);
    CHECK(!il2cpp::dump(bad, empty).ok);

    auto ver = meta;
    poke<uint32_t>(ver, 4, 99);
    CHECK(!il2cpp::dump(ver, empty).ok);

    auto huge = meta;
    poke<uint32_t>(huge, 41 * 4, 0x7FFFFFF0u);   // typeDefinitionsSize
    const auto rh = il2cpp::dump(huge, empty);
    CHECK(!rh.ok);
    CHECK(has(rh.error, "runs past"));

    auto odd = meta;
    uint32_t tsz = 0;
    std::memcpy(&tsz, odd.data() + 41 * 4, 4);
    poke<uint32_t>(odd, 41 * 4, tsz - 4);
    CHECK(!il2cpp::dump(odd, empty).ok);

    // out-of-range record indices inside valid tables
    auto idx = meta;
    uint32_t td_off = 0;
    std::memcpy(&td_off, idx.data() + 40 * 4, 4);
    poke<int32_t>(idx, td_off + 2 * 92 + 36, 0x7FFFFFF0);   // Player.fieldStart
    poke<int32_t>(idx, td_off + 2 * 92 + 40, -50);          // Player.methodStart
    CHECK(il2cpp::dump(idx, empty).ok);

    // byte flips anywhere must never crash
    for (size_t i = 8; i < meta.size(); i += 3) {
        auto flip = meta;
        flip[i] ^= 0xA5;
        (void)il2cpp::dump(flip, empty);
    }

    // binaries
    il2cpp::binary_image_t img;
    std::string err;
    std::vector<std::string> warns;
    CHECK(!il2cpp::image_from_file(std::vector<uint8_t>(64, 0), img, err, warns));
    std::vector<uint8_t> mz(0x200, 0);
    poke<uint16_t>(mz, 0, 0x5A4D);
    poke<uint32_t>(mz, 0x3C, 0x40);
    poke<uint32_t>(mz, 0x40, 0x00004550);
    poke<uint16_t>(mz, 0x46, 0xFFFF);   // section count past the file
    poke<uint16_t>(mz, 0x58, 0x20B);
    CHECK(!il2cpp::image_from_file(mz, img, err, warns));
    std::vector<uint8_t> elf(0x40, 0);
    elf[0] = 0x7F; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F'; elf[4] = 2; elf[5] = 1;
    CHECK(!il2cpp::image_from_file(elf, img, err, warns));
    std::vector<uint8_t> self = {0x4F, 0x15, 0x3D, 0x1D, 0, 0, 0, 0};
    CHECK(!il2cpp::image_from_file(self, img, err, warns));

    // registration with a huge typesCount is rejected, the dump still runs
    auto pe = make_pe(242);
    poke<uint64_t>(pe, 0x2500 - 0x2000 + 0x1400 + 0x30, 0x7FFFFFFFFFFFull);
    REQUIRE(il2cpp::image_from_file(pe, img, err, warns));
    const auto rr = il2cpp::dump(meta, img);
    CHECK(rr.ok);
    CHECK(rr.metadata_registration == 0);
    CHECK(rr.methods_with_address == 4u);
}

// ------------------------------------------------------------ UE fixture

namespace {

class fake_mem_t final : public slop::core::memory::reader_t {
public:
    std::map<uint64_t, std::vector<uint8_t>> regions;
    bool read(uintptr_t addr, void* dst, size_t len) override {
        auto it = regions.upper_bound(addr);
        if (it == regions.begin()) return false;
        --it;
        const uint64_t off = addr - it->first;
        if (off > it->second.size() || len > it->second.size() - off) return false;
        std::memcpy(dst, it->second.data() + off, len);
        return true;
    }
    std::vector<uint8_t>& region(uint64_t base, size_t size) {
        auto& r = regions[base];
        r.assign(size, 0);
        return r;
    }
    template <class T>
    void w(uint64_t addr, T v) {
        auto it = regions.upper_bound(addr);
        --it;
        std::memcpy(it->second.data() + (addr - it->first), &v, sizeof(T));
    }
};

constexpr uint64_t kData = 0x140100000ull, kNames = 0x200000000ull, kHeap = 0x300000000ull;

struct ue_fixture_t {
    fake_mem_t mem;
    std::map<std::string, uint32_t> name_idx;
    uint32_t cursor = 0;
    uint64_t heap_next = kHeap + 0x1000;
    std::vector<uint64_t> objects;
    uint64_t pool = kData + 0x100, objarray = kData + 0x2010;

    uint32_t name(const std::string& s) {
        if (auto it = name_idx.find(s); it != name_idx.end()) return it->second;
        const uint32_t idx = cursor / 2;
        mem.w<uint16_t>(kNames + cursor, static_cast<uint16_t>(s.size() << 6));
        std::memcpy(mem.regions[kNames].data() + cursor + 2, s.data(), s.size());
        cursor += static_cast<uint32_t>((2 + s.size() + 1) & ~size_t{1});
        name_idx.emplace(s, idx);
        mem.w<uint32_t>(pool + 0xC, cursor);
        return idx;
    }
    uint64_t alloc(size_t n) {
        const uint64_t a = heap_next;
        heap_next += (n + 15) & ~size_t{15};
        return a;
    }
    uint64_t object(const std::string& nm, uint64_t cls, size_t size = 0xE0) {
        const uint64_t o = alloc(size);
        mem.w<uint64_t>(o + 0x10, cls ? cls : o);
        mem.w<uint32_t>(o + 0x18, name(nm));
        objects.push_back(o);
        return o;
    }
    uint64_t field_class(const std::string& nm) {
        const uint64_t fc = alloc(0x40);
        mem.w<uint32_t>(fc, name(nm));
        return fc;
    }
    uint64_t prop(const std::string& nm, uint64_t fclass, int32_t offset, int32_t size, uint64_t extra = 0,
                  uint64_t flags = 0) {
        const uint64_t p = alloc(0x90);
        mem.w<uint64_t>(p + 0x08, fclass);
        mem.w<uint32_t>(p + 0x28, name(nm));
        mem.w<int32_t>(p + 0x38, 1);
        mem.w<int32_t>(p + 0x3C, size);
        mem.w<uint64_t>(p + 0x40, flags);
        mem.w<int32_t>(p + 0x4C, offset);
        mem.w<uint64_t>(p + 0x78, extra);
        return p;
    }
    void chain(uint64_t owner, std::initializer_list<uint64_t> props) {
        uint64_t prev = 0;
        for (uint64_t p : props) {
            if (prev) mem.w<uint64_t>(prev + 0x20, p);
            else mem.w<uint64_t>(owner + 0x50, p);
            prev = p;
        }
    }

    uint64_t vector_struct = 0, player = 0, z_prop = 0, x_prop = 0;

    ue_fixture_t() {
        mem.region(kData, 0x10000);
        mem.region(kNames, 0x20000);
        mem.region(kHeap, 0x100000);
        mem.w<uint64_t>(pool + 0x10, kNames);   // Blocks[0]
        name("None");
        name("ByteProperty");

        const uint64_t cls = object("Class", 0);
        const uint64_t strct = object("Struct", cls);
        const uint64_t field = object("Field", cls);
        const uint64_t obj = object("Object", cls);
        const uint64_t sstruct = object("ScriptStruct", cls);
        const uint64_t enm = object("Enum", cls);
        const uint64_t fn = object("Function", cls);
        const uint64_t actor = object("Actor", cls);
        player = object("Player", cls);
        mem.w<uint64_t>(cls + 0x40, strct);
        mem.w<uint64_t>(strct + 0x40, field);
        mem.w<uint64_t>(field + 0x40, obj);
        mem.w<uint64_t>(sstruct + 0x40, strct);
        mem.w<uint64_t>(enm + 0x40, field);
        mem.w<uint64_t>(fn + 0x40, strct);
        mem.w<uint64_t>(actor + 0x40, obj);
        mem.w<uint64_t>(player + 0x40, actor);
        mem.w<int32_t>(obj + 0x58, 0x28);
        mem.w<int32_t>(actor + 0x58, 0x30);
        mem.w<int32_t>(player + 0x58, 0x58);

        const uint64_t fc_double = field_class("DoubleProperty"), fc_int = field_class("IntProperty");
        const uint64_t fc_struct = field_class("StructProperty"), fc_bool = field_class("BoolProperty");
        const uint64_t fc_byte = field_class("ByteProperty"), fc_float = field_class("FloatProperty");

        vector_struct = object("Vector", sstruct);
        mem.w<int32_t>(vector_struct + 0x58, 24);
        x_prop = prop("X", fc_double, 0, 8);
        const uint64_t y = prop("Y", fc_double, 8, 8);
        z_prop = prop("Z", fc_double, 16, 8);
        chain(vector_struct, {x_prop, y, z_prop});

        const uint64_t estate = object("EState", enm);
        const uint64_t pairs = alloc(0x20);
        mem.w<uint32_t>(pairs, name("EState::Idle"));
        mem.w<int64_t>(pairs + 8, 0);
        mem.w<uint32_t>(pairs + 0x10, name("EState::Run"));
        mem.w<int64_t>(pairs + 0x18, 1);
        mem.w<uint64_t>(estate + 0x40, pairs);
        mem.w<int32_t>(estate + 0x48, 2);
        mem.w<int32_t>(estate + 0x4C, 2);

        const uint64_t health = prop("Health", fc_int, 0x30, 4);
        const uint64_t pos = prop("Pos", fc_struct, 0x38, 24, vector_struct);
        const uint64_t alive = prop("bAlive", fc_bool, 0x50, 1);
        mem.w<uint32_t>(alive + 0x78, 0x02020001u);   // FieldSize 1, ByteOffset 0, ByteMask 2, FieldMask 2
        const uint64_t state = prop("State", fc_byte, 0x51, 1, estate);
        chain(player, {health, pos, alive, state});

        const uint64_t tick = object("Tick", fn);
        chain(tick, {prop("DeltaTime", fc_float, 0, 4, 0, 0x80)});
        mem.w<uint32_t>(tick + 0xB0, 0x00020400u);   // FunctionFlags
        mem.w<uint8_t>(tick + 0xB4, 1);              // NumParms
        mem.w<uint64_t>(tick + 0xD8, 0x140001000ull); // Func
        mem.w<uint64_t>(player + 0x48, tick);        // Children

        while (objects.size() < 48) object("None", obj, 0x30);   // plain instances

        // chunked TUObjectArray: one chunk of 24-byte FUObjectItems
        const uint64_t chunk_table = alloc(8), items = alloc(objects.size() * 24);
        mem.w<uint64_t>(chunk_table, items);
        for (size_t i = 0; i < objects.size(); ++i) mem.w<uint64_t>(items + i * 24, objects[i]);
        mem.w<uint64_t>(objarray, chunk_table);
        mem.w<int32_t>(objarray + 0x10, 1000);
        mem.w<int32_t>(objarray + 0x14, static_cast<int32_t>(objects.size()));
        mem.w<int32_t>(objarray + 0x18, 1);
        mem.w<int32_t>(objarray + 0x1C, 1);
    }

    ue::dump_options_t opts() const {
        ue::dump_options_t o;
        ue::range_t r;
        r.base = kData;
        r.size = 0x10000;
        o.scan.push_back(r);
        return o;
    }
};

const std::string* file_of(const ue::dump_result_t& r, const char* name) {
    for (const auto& [n, body] : r.files)
        if (n == name) return &body;
    return nullptr;
}

const std::string* file_of(const source::dump_result_t& r, const char* name) {
    for (const auto& [n, body] : r.files)
        if (n == name) return &body;
    return nullptr;
}

} // namespace

TEST_CASE(ue_auto_locate_and_walk_ue5_layout) {
    ue_fixture_t fx;
    const auto r = ue::dump(fx.mem, fx.opts());
    if (!r.ok) std::printf("  ue error: %s\n", r.error.c_str());
    REQUIRE(r.ok);
    for (const auto& w : r.warnings) std::printf("  warning: %s\n", w.c_str());
    REQUIRE_EQ(r.gnames, fx.pool + 0x10);
    REQUIRE_EQ(r.gobjects, fx.objarray);
    REQUIRE_STR_EQ(r.version, "5.x");
    REQUIRE_EQ(r.objects, fx.objects.size());
    REQUIRE_EQ(r.classes, 9u);
    REQUIRE_EQ(r.structs, 1u);
    REQUIRE_EQ(r.enums, 1u);
    REQUIRE_EQ(r.functions, 1u);
    CHECK(r.names >= fx.name_idx.size());
    CHECK(r.warnings.empty());

    const std::string* classes = file_of(r, "ClassesInfo.json");
    const std::string* structs = file_of(r, "StructsInfo.json");
    const std::string* enums = file_of(r, "EnumsInfo.json");
    const std::string* funcs = file_of(r, "FunctionsInfo.json");
    const std::string* names = file_of(r, "FNames.txt");
    const std::string* sdk = file_of(r, "SDK.hpp");
    REQUIRE(classes && structs && enums && funcs && names && sdk);

    const auto cj = nlohmann::json::parse(*classes);
    const nlohmann::json* player = nullptr;
    for (const auto& e : cj["data"])
        if (e.contains("APlayer")) player = &e["APlayer"];
    REQUIRE(player != nullptr);
    CHECK((*player)[0]["__InheritInfo"][0] == "AActor");
    CHECK((*player)[1]["__MDKClassSize"] == 0x58);
    CHECK((*player)[2]["Health"][0][0] == "int32");
    CHECK((*player)[2]["Health"][1] == 0x30);
    CHECK((*player)[3]["Pos"][0][0] == "FVector");
    CHECK((*player)[4]["bAlive : 1"][4] == 1);
    CHECK((*player)[5]["State"][0][0] == "EState");

    CHECK(has(*structs, "\"FVector\""));
    CHECK(has(*enums, "\"Idle\":0"));
    CHECK(has(*funcs, "\"Tick\""));
    CHECK(has(*names, "\tByteProperty\n"));
    CHECK(has(*sdk, "struct APlayer : public AActor {"));
    CHECK(has(*sdk, "    int32 Health;"));
    CHECK(has(*sdk, "    FVector Pos;"));
    CHECK(has(*sdk, "    uint8 bAlive : 1;"));
    CHECK(has(*sdk, "    EState State;"));
    CHECK(has(*sdk, "enum class EState : uint8 {"));
    CHECK(has(*sdk, "// fn Tick(float DeltaTime) -> 0x140001000"));

    // explicit addresses take the same path
    auto o = fx.opts();
    o.scan.clear();
    o.gnames = fx.pool;
    o.gobjects = fx.objarray - 0x10;
    const auto r2 = ue::dump(fx.mem, o);
    REQUIRE(r2.ok);
    CHECK(r2.classes == 9u);
}

TEST_CASE(ue_malformed_memory_fails_cleanly) {
    {
        fake_mem_t empty;
        ue::dump_options_t o;
        CHECK(!ue::dump(empty, o).ok);
        ue::range_t r;
        r.base = 0x1000;
        r.size = 0x10000;   // unreadable
        o.scan.push_back(r);
        CHECK(!ue::dump(empty, o).ok);
        o.gnames = 0xDEADBEEF;
        CHECK(!ue::dump(empty, o).ok);
    }
    {
        // names but no object array
        ue_fixture_t fx;
        fx.mem.w<uint64_t>(fx.objarray, 0);
        const auto r = ue::dump(fx.mem, fx.opts());
        CHECK(!r.ok);
        CHECK(has(r.error, "GUObjectArray"));
    }
    {
        // a property chain that loops back on itself, and a huge object count
        ue_fixture_t fx;
        fx.mem.w<uint64_t>(fx.z_prop + 0x20, fx.x_prop);
        fx.mem.w<int32_t>(fx.objarray + 0x10, 0x4000000);
        fx.mem.w<int32_t>(fx.objarray + 0x14, 0x3000000);
        fx.mem.w<int32_t>(fx.objarray + 0x18, 0x400);
        fx.mem.w<int32_t>(fx.objarray + 0x1C, 0x300);
        auto o = fx.opts();
        o.max_objects = 1000;
        const auto r = ue::dump(fx.mem, o);
        REQUIRE(r.ok);
        CHECK(r.structs == 1u);
        bool capped = false;
        for (const auto& w : r.warnings) capped = capped || has(w, "max_objects");
        CHECK(capped);
        const std::string* sdk = file_of(r, "SDK.hpp");
        REQUIRE(sdk != nullptr);
        CHECK(has(*sdk, "struct FVector {"));
    }
}

// ------------------------------------------------------------ source fixture
// Source engine (Apex Legends style): ClientClass nodes live in the module
// data section, RecvTables/RecvProps/strings in the heap. Prop structs are
// inline arrays (RecvTable.m_pProps points at n contiguous 0x58-byte RecvProp)

constexpr uint64_t kSrcData = 0x500000000ull, kSrcHeap = 0x600000000ull;

struct source_fixture_t {
    fake_mem_t mem;
    uint64_t heap_next = kSrcHeap + 0x100;

    uint64_t alloc(size_t n) {
        const uint64_t a = heap_next;
        heap_next += (n + 15) & ~size_t{15};
        return a;
    }
    uint64_t str(const std::string& s) {
        const uint64_t a = alloc(s.size() + 1);
        std::memcpy(mem.regions[kSrcHeap].data() + (a - kSrcHeap), s.data(), s.size() + 1);
        return a;
    }
    // returns the RecvTable address; *props_out (when given) receives the
    // inline RecvProp array address so tests can poke per-prop fields
    uint64_t table(const std::string& dt_name, const std::vector<std::pair<std::string, uint32_t>>& defs,
                   const std::vector<uint64_t>& extra_dt = {}, const std::vector<int32_t>& extra_off = {},
                   uint64_t* props_out = nullptr) {
        const uint64_t t = alloc(0x28);
        mem.w<uint64_t>(t + 0x18, str(dt_name));
        mem.w<int32_t>(t + 0x08, static_cast<int32_t>(defs.size()));
        const uint64_t props = alloc(defs.size() * 0x58);
        mem.w<uint64_t>(t + 0x00, props);
        if (props_out) *props_out = props;
        for (size_t i = 0; i < defs.size(); ++i) {
            const uint64_t p = props + i * 0x58;
            mem.w<uint64_t>(p + 0x00, str(defs[i].first));
            mem.w<uint32_t>(p + 0x08, defs[i].second);
            mem.w<int32_t>(p + 0x40, 0);
        }
        for (size_t i = 0; i < extra_dt.size(); ++i) {
            const uint64_t p = props + i * 0x58;
            mem.w<uint64_t>(p + 0x38, extra_dt[i]);
            mem.w<int32_t>(p + 0x40, extra_off[i]);
        }
        return t;
    }
    uint64_t klass(const std::string& net_name, uint64_t tbl, uint64_t next, int32_t id) {
        const uint64_t cc = alloc(0x30);
        mem.w<uint64_t>(cc + 0x10, str(net_name));
        mem.w<uint64_t>(cc + 0x18, tbl);
        mem.w<uint64_t>(cc + 0x20, next);
        mem.w<int32_t>(cc + 0x28, id);
        return cc;
    }

    uint64_t world_cc = 0, base_cc = 0, player_cc = 0, head_slot = kSrcData + 0x20;

    source_fixture_t() {
        mem.region(kSrcData, 0x10000);
        mem.region(kSrcHeap, 0x100000);

        uint64_t props_base = 0, props_player = 0, props_weapon = 0;
        const uint64_t dt_weapon = table("DT_Weapon", {{"m_clip", 0}}, {}, {}, &props_weapon);
        const uint64_t dt_base = table("DT_BaseEntity", {{"m_vecOrigin", 2}, {"m_iTeamNum", 0}}, {}, {}, &props_base);
        const uint64_t dt_player = table("DT_Player", {{"0", 6}, {"m_iHealth", 0}, {"m_hWeapons", 5}, {"m_weapon", 6}},
                                         {dt_base, 0, 0, dt_weapon}, {0, 0x30, 0x400, 0x500}, &props_player);
        mem.w<int32_t>(props_base + 0x40, 0x2B0);              // m_vecOrigin offset
        mem.w<int32_t>(props_base + 0x58 + 0x40, 0x44);        // m_iTeamNum offset
        mem.w<int32_t>(props_player + 2 * 0x58 + 0x48, 64);    // m_hWeapons elements
        mem.w<int32_t>(props_weapon + 0x40, 0x10);             // m_clip offset
        const uint64_t dt_world = table("DT_World", {{"m_bActive", 0}});

        world_cc = klass("CWorld", dt_world, 0, 0);
        base_cc = klass("CBaseEntity", dt_base, world_cc, 1);
        player_cc = klass("CPlayer", dt_player, base_cc, 2);
        mem.w<uint64_t>(head_slot, player_cc);   // the g_pClientClassHead-style root in .data
    }

    source::dump_options_t opts() const {
        source::dump_options_t o;
        o.scan.push_back({kSrcData, 0x10000});
        return o;
    }
};

TEST_CASE(source_auto_locate_and_netvar_offsets) {
    source_fixture_t fx;
    const auto r = source::dump(fx.mem, fx.opts());
    if (!r.ok) std::printf("  source error: %s\n", r.error.c_str());
    REQUIRE(r.ok);
    for (const auto& w : r.warnings) std::printf("  warning: %s\n", w.c_str());
    REQUIRE_EQ(r.head, fx.player_cc);
    REQUIRE_EQ(r.classes, 3u);
    REQUIRE_EQ(r.tables, 3u);
    REQUIRE_EQ(r.netvars, 6u);

    const std::string* nv = file_of(r, "netvars.json");
    const std::string* rt = file_of(r, "recvtables.json");
    REQUIRE(nv && rt);
    const auto nj = nlohmann::json::parse(*nv);
    const auto& n = nj["netvars"];
    CHECK(n["DT_World->m_bActive"] == 0);
    CHECK(n["DT_BaseEntity->m_vecOrigin"] == 0x2B0);   // baseclass adds no offset
    CHECK(n["DT_BaseEntity->m_iTeamNum"] == 0x44);
    CHECK(n["DT_Player->m_iHealth"] == 0x30);
    CHECK(n["DT_Player->m_hWeapons"] == 0x400);
    CHECK(n["DT_Weapon->m_clip"] == 0x510);            // nested table offset accumulates
    CHECK(nj["head"].get<std::string>().rfind("0x", 0) == 0);

    const auto rj = nlohmann::json::parse(*rt);
    REQUIRE_EQ(rj["data"].size(), 3u);
    const nlohmann::json* player_row = nullptr;
    for (const auto& e : rj["data"])
        if (e["class"] == "CPlayer") player_row = &e;
    REQUIRE(player_row != nullptr);
    CHECK((*player_row)["class_id"] == 2);
    CHECK((*player_row)["props"].size() > 0);

    // explicit head mid-list walks only what remains
    auto o = fx.opts();
    o.scan.clear();
    o.head = fx.base_cc;
    const auto r2 = source::dump(fx.mem, o);
    REQUIRE(r2.ok);
    CHECK(r2.classes == 2u);
    CHECK(r2.head == fx.base_cc);
}

TEST_CASE(source_malformed_memory_fails_cleanly) {
    {
        fake_mem_t empty;
        source::dump_options_t o;
        CHECK(!source::dump(empty, o).ok);
        o.scan.push_back({0x1000, 0x10000});   // unreadable
        CHECK(!source::dump(empty, o).ok);
    }
    {
        // garbage range: no ClientClass-shaped nodes
        fake_mem_t g;
        g.region(0x10000, 0x10000);
        for (auto& b : g.regions) std::fill(b.second.begin(), b.second.end(), 0xAA);
        source::dump_options_t o;
        o.scan.push_back({0x10000, 0x10000});
        const auto r = source::dump(g, o);
        CHECK(!r.ok);
        CHECK(has(r.error, "no ClientClass"));
    }
    {
        // explicit head pointing at nothing
        fake_mem_t empty;
        source::dump_options_t o;
        o.head = 0xDEADBEEF;
        CHECK(!source::dump(empty, o).ok);
    }
}
