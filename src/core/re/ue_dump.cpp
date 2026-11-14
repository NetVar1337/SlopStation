// src/core/re/ue_dump.cpp
// Unreal Engine SDK dumper over a memory reader, see ue_dump.hpp

#include "core/re/ue_dump.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace slop::core::re::ue {

namespace {

using json = nlohmann::json;

bool plausible(uint64_t p) { return p >= 0x10000 && p < 0x0000800000000000ull; }
bool plausible8(uint64_t p) { return plausible(p) && (p & 7) == 0; }
uint64_t align_up(uint64_t v, uint64_t a) { return (v + a - 1) & ~(a - 1); }

std::string hx(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

void utf8_push(std::string& s, uint32_t cp) {
    if (cp < 0x80) s.push_back(static_cast<char>(cp));
    else if (cp < 0x800) { s.push_back(static_cast<char>(0xC0 | (cp >> 6))); s.push_back(static_cast<char>(0x80 | (cp & 0x3F))); }
    else { s.push_back(static_cast<char>(0xE0 | (cp >> 12))); s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F))); s.push_back(static_cast<char>(0x80 | (cp & 0x3F))); }
}

// ---------------------------------------------------------------- page cache

class cache_t {
public:
    explicit cache_t(memory::reader_t& r) : r_(r) {
        page_ = r.hints().chunk_bytes ? 0x10000 : 0x1000;   // remote readers: fewer, bigger round trips
        max_pages_ = (256u << 20) / page_;
    }
    bool read(uint64_t a, void* dst, size_t n) {
        if (n == 0) return true;
        if (a + n < a || !a) return false;
        auto* out = static_cast<uint8_t*>(dst);
        uint64_t cur = a;
        size_t left = n;
        while (left) {
            const uint64_t pg = cur & ~static_cast<uint64_t>(page_ - 1);
            const std::vector<uint8_t>* p = page(pg);
            if (!p) return r_.read(static_cast<uintptr_t>(a), dst, n);   // page partly unreadable
            const size_t in = static_cast<size_t>(cur - pg);
            const size_t take = std::min(left, page_ - in);
            std::memcpy(out, p->data() + in, take);
            out += take;
            cur += take;
            left -= take;
        }
        return true;
    }
    template <class T>
    T get(uint64_t a) {
        T v{};
        if (!read(a, &v, sizeof v)) v = T{};
        return v;
    }
    uint64_t q(uint64_t a) { return get<uint64_t>(a); }
    uint32_t u32(uint64_t a) { return get<uint32_t>(a); }
    int32_t  i32(uint64_t a) { return get<int32_t>(a); }
    uint8_t  u8(uint64_t a) { return get<uint8_t>(a); }
    // bulk read that bypasses the cache (locate scans)
    bool raw(uint64_t a, void* dst, size_t n) { return r_.read(static_cast<uintptr_t>(a), dst, n); }

private:
    const std::vector<uint8_t>* page(uint64_t pg) {
        auto it = pages_.find(pg);
        if (it != pages_.end()) return it->second.empty() ? nullptr : &it->second;
        std::vector<uint8_t> buf(page_);
        if (!r_.read(static_cast<uintptr_t>(pg), buf.data(), page_)) buf.clear();
        if (pages_.size() >= max_pages_ && !order_.empty()) {
            pages_.erase(order_.front());
            order_.pop_front();
        }
        order_.push_back(pg);
        auto& slot = pages_[pg];
        slot = std::move(buf);
        return slot.empty() ? nullptr : &slot;
    }

    memory::reader_t& r_;
    size_t page_ = 0x1000;
    size_t max_pages_ = 0;
    std::unordered_map<uint64_t, std::vector<uint8_t>> pages_;
    std::deque<uint64_t> order_;
};

// ---------------------------------------------------------------- names

struct names_t {
    cache_t& c;
    bool     ok = false;
    bool     legacy = false;
    uint64_t blocks = 0;            // pool: &Blocks[0]; legacy: &Chunks[0]
    uint32_t cur_block = 0, cur_cursor = 0;
    int32_t  legacy_count = 0;
    uint32_t hdr_off = 0, stride = 2, mode = 0;
    uint32_t name_off = 0x10;       // legacy FNameEntry string offset
    std::unordered_map<uint32_t, std::string> cache;

    explicit names_t(cache_t& cc) : c(cc) {}

    // FNameEntry (pool) at addr; bytes = total entry size
    bool pool_entry(uint64_t addr, uint32_t h_off, uint32_t md, std::string& s, uint32_t* bytes = nullptr) {
        s.clear();
        const uint16_t h = c.get<uint16_t>(addr + h_off);
        uint32_t len = 0;
        bool wide = false;
        switch (md) {
        case 0: wide = (h & 1) != 0; len = h >> 6; break;
        case 1: wide = (h & 1) != 0; len = h >> 1; break;
        default: wide = (h >> 15) != 0; len = h & 0x3FF; break;
        }
        if (len == 0 || len > 1024) return false;
        const uint32_t n = wide ? len * 2 : len;
        std::vector<uint8_t> b(n);
        if (!c.read(addr + h_off + 2, b.data(), n)) return false;
        if (wide) {
            for (uint32_t i = 0; i + 1 < n; i += 2) utf8_push(s, static_cast<uint32_t>(b[i] | (b[i + 1] << 8)));
        } else {
            s.assign(reinterpret_cast<const char*>(b.data()), n);
        }
        if (bytes) *bytes = h_off + 2 + n;
        return true;
    }

    bool try_pool(uint64_t blocks_va, uint32_t cb, uint32_t cursor) {
        if (cb >= 8192) return false;
        const uint64_t p = c.q(blocks_va);
        if (!plausible(p)) return false;
        std::string s;
        for (uint32_t ho : {0u, 4u}) {
            for (uint32_t md : {0u, 1u, 2u}) {
                uint32_t sz = 0;
                if (!pool_entry(p, ho, md, s, &sz) || s != "None") continue;
                const uint32_t st = ho ? 4 : 2;
                if (!pool_entry(p + align_up(sz, st), ho, md, s) || s != "ByteProperty") continue;
                ok = true; legacy = false; blocks = blocks_va; cur_block = cb; cur_cursor = cursor;
                hdr_off = ho; mode = md; stride = st;
                cache.clear();
                return true;
            }
        }
        return false;
    }

    std::string cstr_at(uint64_t a, size_t max = 1024) {
        std::string s;
        char buf[64];
        while (s.size() < max) {
            if (!c.read(a + s.size(), buf, sizeof buf)) {
                // tail of a region: byte by byte
                const char ch = static_cast<char>(c.u8(a + s.size()));
                if (!ch) break;
                s.push_back(ch);
                continue;
            }
            const void* z = std::memchr(buf, 0, sizeof buf);
            if (z) { s.append(buf, static_cast<size_t>(static_cast<const char*>(z) - buf)); break; }
            s.append(buf, sizeof buf);
        }
        return s;
    }

    bool try_legacy(uint64_t arr) {
        if (!plausible8(arr)) return false;
        const uint64_t c0 = c.q(arr);
        if (!plausible8(c0)) return false;
        const uint64_t e0 = c.q(c0), e1 = c.q(c0 + 8);
        if (!plausible(e0) || !plausible(e1)) return false;
        for (uint32_t off : {0x10u, 0x0Cu, 0x08u, 0x14u, 0x18u}) {
            if (cstr_at(e0 + off, 8) != "None" || cstr_at(e1 + off, 16) != "ByteProperty") continue;
            ok = true; legacy = true; blocks = arr; name_off = off;
            legacy_count = c.i32(arr + 128 * 8);
            if (legacy_count <= 0 || legacy_count > (1 << 23)) legacy_count = 0;
            cache.clear();
            return true;
        }
        return false;
    }

    bool fetch(uint32_t idx, std::string& s) {
        if (legacy) {
            const uint64_t chunk = c.q(blocks + (idx / 16384) * 8ull);
            if (!plausible8(chunk) || idx / 16384 >= 128) return false;
            const uint64_t e = c.q(chunk + (idx % 16384) * 8ull);
            if (!plausible(e)) return false;
            const bool wide = name_off >= 8 && (c.i32(e) & 1) != 0;
            if (wide) {
                s.clear();
                for (uint32_t i = 0; i < 1024; ++i) {
                    const uint16_t ch = c.get<uint16_t>(e + name_off + i * 2ull);
                    if (!ch) break;
                    utf8_push(s, ch);
                }
            } else {
                s = cstr_at(e + name_off);
            }
            return !s.empty();
        }
        const uint32_t blk = idx >> 16;
        if (blk > cur_block) return false;
        const uint64_t bp = c.q(blocks + blk * 8ull);
        if (!plausible(bp)) return false;
        return pool_entry(bp + (idx & 0xFFFF) * uint64_t{stride}, hdr_off, mode, s);
    }

    const std::string& get(uint32_t idx) {
        auto it = cache.find(idx);
        if (it != cache.end()) return it->second;
        std::string s;
        if (!fetch(idx, s)) s = "<bad_name_" + std::to_string(idx) + ">";
        return cache.emplace(idx, std::move(s)).first->second;
    }

    // every name in the table, (index, string)
    std::vector<std::pair<uint32_t, std::string>> all(size_t cap) {
        std::vector<std::pair<uint32_t, std::string>> out;
        std::string s;
        if (legacy) {
            const uint32_t n = legacy_count > 0 ? static_cast<uint32_t>(legacy_count) : 128u * 16384u;
            uint32_t misses = 0;
            for (uint32_t i = 0; i < n && out.size() < cap; ++i) {
                if (fetch(i, s)) { out.emplace_back(i, s); misses = 0; }
                else if (legacy_count <= 0 && ++misses > 65536) break;
            }
            return out;
        }
        const uint64_t block_bytes = 0x10000ull * stride;
        for (uint32_t b = 0; b <= cur_block && out.size() < cap; ++b) {
            const uint64_t bp = c.q(blocks + b * 8ull);
            if (!plausible(bp)) continue;
            const uint64_t limit = b == cur_block ? std::min<uint64_t>(cur_cursor, block_bytes) : block_bytes;
            uint64_t cur = 0;
            while (cur + hdr_off + 2 <= limit && out.size() < cap) {
                uint32_t sz = 0;
                if (!pool_entry(bp + cur, hdr_off, mode, s, &sz)) break;
                out.emplace_back((b << 16) | static_cast<uint32_t>(cur / stride), s);
                cur += align_up(sz, stride);
            }
        }
        return out;
    }
};

// ---------------------------------------------------------------- scanning

// fn(va, slice, index of va in slice, slice size) -> true stops
template <class F>
bool scan_ranges(cache_t& c, const std::vector<range_t>& ranges, F&& fn) {
    constexpr uint64_t kSlice = 1u << 20, kPad = 256, kPage = 0x1000;
    std::vector<uint8_t> buf;
    for (const auto& r : ranges) {
        if (!r.size || r.base + r.size < r.base) continue;
        const uint64_t end = r.base + r.size;
        for (uint64_t s = align_up(r.base, 8); s < end; s += kSlice) {
            const uint64_t lo = s - std::min(kPad, s - r.base);
            const uint64_t hi = std::min(end, s + kSlice + kPad);
            buf.assign(static_cast<size_t>(hi - lo), 0);
            if (!c.raw(lo, buf.data(), buf.size())) {
                for (uint64_t p = lo; p < hi;) {
                    const uint64_t next = std::min(hi, (p & ~(kPage - 1)) + kPage);
                    if (!c.raw(p, buf.data() + (p - lo), static_cast<size_t>(next - p)))
                        std::memset(buf.data() + (p - lo), 0, static_cast<size_t>(next - p));
                    p = next;
                }
            }
            const uint64_t stop = std::min(end, s + kSlice);
            for (uint64_t va = s; va + 8 <= stop; va += 8)
                if (fn(va, buf.data(), static_cast<size_t>(va - lo), buf.size())) return true;
        }
    }
    return false;
}

uint64_t rq(const uint8_t* b, size_t i) { uint64_t v; std::memcpy(&v, b + i, 8); return v; }
uint32_t rd32(const uint8_t* b, size_t i) { uint32_t v; std::memcpy(&v, b + i, 4); return v; }

// ---------------------------------------------------------------- objects

struct objarr_t {
    uint64_t at = 0;       // ObjObjects
    uint64_t objs = 0;     // FUObjectItem** chunk table
    int32_t  num = 0;
    uint32_t stride = 0x18;
};

struct obj_t {
    uint64_t addr = 0, cls = 0, outer = 0;
    uint32_t name = 0, number = 0;
};

enum kind_t : uint8_t { K_OTHER = 0, K_CLASS, K_STRUCT, K_ENUM, K_FUNC };

struct ptype_t {
    std::string name;
    char cat = 'D';
    std::string ext;
    std::vector<ptype_t> sub;
};

std::string cpp_type(const ptype_t& t) {
    std::string s = t.name;
    if (!t.sub.empty()) {
        s += "<";
        for (size_t i = 0; i < t.sub.size(); ++i) s += (i ? ", " : "") + cpp_type(t.sub[i]);
        s += ">";
    }
    return s + t.ext;
}

json ds_type(const ptype_t& t) {
    json sub = json::array();
    for (const auto& s : t.sub) sub.push_back(ds_type(s));
    return json::array({t.name, std::string(1, t.cat), t.ext, sub});
}

struct prop_t {
    std::string name, cls;
    ptype_t     type;
    int32_t     offset = 0, size = 0, dim = 1;
    uint64_t    flags = 0;
    int         bit = -1;        // BoolProperty bit inside the byte at offset
    uint64_t    addr = 0;
};

struct func_t {
    std::string         name;
    uint32_t            flags = 0;
    uint64_t            func = 0;
    std::vector<prop_t> params;
};

struct ustruct_t {
    uint64_t addr = 0, super = 0;
    std::string name, cpp, super_cpp;
    kind_t   kind = K_STRUCT;
    int32_t  size = 0;
    std::vector<std::string> inherit;
    std::vector<prop_t> props;
    std::vector<func_t> funcs;
};

struct uenum_t {
    std::string name;
    std::vector<std::pair<std::string, int64_t>> values;
};

std::string c_ident(const std::string& s) {
    std::string o;
    for (char ch : s) {
        const unsigned char u = static_cast<unsigned char>(ch);
        o.push_back((u < 0x80 && (std::isalnum(u) || u == '_')) ? ch : '_');
    }
    if (o.empty() || std::isdigit(static_cast<unsigned char>(o[0]))) o.insert(o.begin(), '_');
    return o;
}

bool ends_with(const std::string& s, const char* suf) {
    const size_t n = std::strlen(suf);
    return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
}

struct dumper_t {
    cache_t&              c;
    names_t&              nm;
    const dump_options_t& opt;
    dump_result_t&        res;

    objarr_t oa;
    // layout
    uint32_t fname_size = 8, num_off = 4;
    uint64_t o_class = 0x10, o_name = 0x18, o_outer = 0x20, o_next = 0x28, field_end = 0x30;
    uint64_t o_super = 0x40, o_children = 0x48, o_childprops = 0x50, o_size = 0x58;
    bool     ffield = true;
    uint64_t ff_class = 0x08, ff_next = 0x20, ff_name = 0x28;
    uint64_t p_dim = 0x38, p_esize = 0x3C, p_flags = 0x40, p_off = 0x4C, p_size = 0x78;
    uint64_t e_names = 0x40;
    uint64_t fn_flags = 0;   // 0 = unknown

    std::vector<obj_t> objs;
    std::unordered_map<uint64_t, size_t> by_addr;
    std::unordered_map<uint64_t, kind_t> kinds;
    std::unordered_map<uint64_t, bool> actors;
    uint64_t cls_class = 0, cls_struct = 0, cls_sstruct = 0, cls_enum = 0, cls_function = 0;

    dumper_t(cache_t& cc, names_t& n, const dump_options_t& o, dump_result_t& r) : c(cc), nm(n), opt(o), res(r) {}

    std::string fname(uint64_t a) {
        const uint32_t idx = c.u32(a);
        const uint32_t num = c.u32(a + num_off);
        std::string s = nm.get(idx);
        if (num) s += "_" + std::to_string(num - 1);
        return s;
    }
    std::string obj_name(uint64_t o) {
        if (auto it = by_addr.find(o); it != by_addr.end()) {
            const obj_t& ob = objs[it->second];
            std::string s = nm.get(ob.name);
            if (ob.number) s += "_" + std::to_string(ob.number - 1);
            return s;
        }
        return fname(o + o_name);
    }

    // ---- GUObjectArray
    bool validate_objs(uint64_t chunks, int32_t num, uint64_t at) {
        const uint64_t c0 = c.q(chunks);
        if (!plausible8(c0) || num <= 0) return false;
        uint32_t best = 0, best_stride = 0;
        uint64_t meta = 0;   // a UClass "Class" candidate seen on the way
        for (uint32_t st : {0x18u, 0x10u, 0x20u}) {
            uint32_t score = 0;
            for (int32_t i = 0; i < 64 && i < num; ++i) {
                const uint64_t o = c.q(c0 + static_cast<uint64_t>(i) * st);
                if (!plausible8(o)) continue;
                const uint64_t cl = c.q(o + 0x10);
                if (!plausible8(cl)) continue;
                const uint64_t cc = c.q(cl + 0x10);
                if (plausible8(cc) && c.q(cc + 0x10) == cc) { ++score; meta = cc; }
            }
            if (score > best) { best = score; best_stride = st; }
        }
        const uint32_t need = static_cast<uint32_t>(std::min<int32_t>(16, std::max<int32_t>(1, num / 2)));
        if (best < need) return false;
        if (nm.ok && nm.get(c.u32(meta + 0x18)) != "Class") return false;   // the class of a class is "Class"
        oa.at = at; oa.objs = chunks; oa.num = num; oa.stride = best_stride;
        return true;
    }

    // TUObjectArray header at va (bytes b[i..]); with and without PreAllocatedObjects
    bool objarray_at(uint64_t va, const uint8_t* b, size_t i, size_t len) {
        for (size_t hdr : {16u, 8u}) {
            if (i + hdr + 16 > len) continue;
            const uint64_t chunks = rq(b, i);
            if (!plausible8(chunks)) return false;
            const int32_t mx = static_cast<int32_t>(rd32(b, i + hdr)), num = static_cast<int32_t>(rd32(b, i + hdr + 4));
            const int32_t mxc = static_cast<int32_t>(rd32(b, i + hdr + 8)), numc = static_cast<int32_t>(rd32(b, i + hdr + 12));
            if (num < 32 || mx < num || mx > 0x8000000) continue;
            if (mxc != (mx + 65535) / 65536 || numc < (num + 65535) / 65536 || numc > mxc) continue;
            if (validate_objs(chunks, num, va)) return true;
        }
        return false;
    }

    bool objarray_explicit(uint64_t a) {
        for (uint64_t off : {0x10ull, 0x0ull, 0x18ull, 0x20ull, 0x8ull}) {
            uint8_t b[32];
            if (!c.read(a + off, b, sizeof b)) continue;
            if (objarray_at(a + off, b, 0, sizeof b)) return true;
        }
        return false;
    }

    uint64_t object_at(int32_t i) {
        const uint64_t chunk = c.q(oa.objs + static_cast<uint64_t>(i / 65536) * 8);
        if (!plausible8(chunk)) return 0;
        return c.q(chunk + static_cast<uint64_t>(i % 65536) * oa.stride);
    }

    void index_objects() {
        const int32_t n = static_cast<int32_t>(std::min<uint64_t>(static_cast<uint64_t>(oa.num), opt.max_objects));
        if (static_cast<uint64_t>(oa.num) > opt.max_objects)
            res.warnings.push_back("object walk capped at max_objects=" + std::to_string(opt.max_objects));
        objs.reserve(static_cast<size_t>(n));
        uint8_t hdr[0x40];
        for (int32_t i = 0; i < n; ++i) {
            const uint64_t o = object_at(i);
            if (!plausible8(o) || !c.read(o, hdr, static_cast<size_t>(o_outer + 8))) continue;
            obj_t ob;
            ob.addr = o;
            std::memcpy(&ob.cls, hdr + o_class, 8);
            std::memcpy(&ob.name, hdr + o_name, 4);
            std::memcpy(&ob.number, hdr + o_name + num_off, 4);
            std::memcpy(&ob.outer, hdr + o_outer, 8);
            if (!plausible8(ob.cls)) continue;
            by_addr.emplace(o, objs.size());
            objs.push_back(ob);
        }
    }

    kind_t kind_of(uint64_t cls) {
        if (auto it = kinds.find(cls); it != kinds.end()) return it->second;
        kind_t k = K_OTHER;
        uint64_t cur = cls;
        for (int d = 0; d < 64 && plausible8(cur); ++d, cur = c.q(cur + o_super)) {
            if (cur == cls_class) { k = K_CLASS; break; }
            if (cur == cls_sstruct) { k = K_STRUCT; break; }
            if (cur == cls_enum) { k = K_ENUM; break; }
            if (cur == cls_function) { k = K_FUNC; break; }
            if (cur == cls_struct) break;
        }
        kinds.emplace(cls, k);
        return k;
    }

    bool is_actor(uint64_t cls) {
        if (auto it = actors.find(cls); it != actors.end()) return it->second;
        bool a = false;
        uint64_t cur = cls;
        for (int d = 0; d < 64 && plausible8(cur); ++d, cur = c.q(cur + o_super))
            if (obj_name(cur) == "Actor") { a = true; break; }
        actors.emplace(cls, a);
        return a;
    }
    std::string class_cpp(uint64_t cls) {
        if (!plausible8(cls)) return "UObject";
        return (is_actor(cls) ? "A" : "U") + obj_name(cls);
    }

    // ---- layout detection
    void find_core() {
        for (const auto& o : objs)
            if (o.cls == o.addr && nm.get(o.name) == "Class") { cls_class = o.addr; break; }
        if (!cls_class) return;
        for (const auto& o : objs) {
            if (o.cls != cls_class) continue;
            const std::string& n = nm.get(o.name);
            if (n == "Struct") cls_struct = o.addr;
            else if (n == "ScriptStruct") cls_sstruct = o.addr;
            else if (n == "Enum") cls_enum = o.addr;
            else if (n == "Function") cls_function = o.addr;
        }
    }

    bool detect_layout() {
        o_next = o_outer + 8;
        field_end = o_next + 8;
        bool super_ok = false;
        for (uint64_t cand : {field_end + 0x10, field_end, field_end + 0x08, field_end + 0x18}) {
            if (cls_struct && c.q(cls_class + cand) == cls_struct) { o_super = cand; super_ok = true; break; }
        }
        if (!super_ok) {
            o_super = field_end + 0x10;
            res.warnings.push_back("UStruct::SuperStruct offset not confirmed (UClass \"Class\" -> \"Struct\"); using " + hx(o_super));
        }
        o_children = o_super + 8;
        o_childprops = o_super + 0x10;

        // FField (4.25+) or UProperty (older) properties: vote over script structs
        int ff_votes = 0, up_votes = 0;
        int seen = 0;
        for (const auto& o : objs) {
            if (seen >= 300 || o.cls != cls_sstruct) continue;
            ++seen;
            const uint64_t p = c.q(o.addr + o_childprops);
            if (plausible8(p)) {
                const uint64_t fc = c.q(p + ff_class);
                if (plausible8(fc) && ends_with(fname(fc), "Property")) { ++ff_votes; continue; }
            }
            const uint64_t ch = c.q(o.addr + o_children);
            if (plausible8(ch) && ends_with(obj_name(c.q(ch + o_class)), "Property")) ++up_votes;
        }
        ffield = ff_votes >= up_votes;
        if (!ff_votes && !up_votes) res.warnings.push_back("no struct with properties found to confirm the property layout");

        if (ffield) {
            o_size = o_super + 0x18;
            // FField: Owner is a 16-byte FFieldVariant, or 8 bytes on 5.1+
            int best = -1;
            uint64_t best_next = 0x20, best_name = 0x28;
            for (const auto& cand : {std::pair<uint64_t, uint64_t>{0x20, 0x28}, std::pair<uint64_t, uint64_t>{0x18, 0x20}}) {
                int score = 0;
                int checked = 0;
                for (const auto& o : objs) {
                    if (checked >= 200 || o.cls != cls_sstruct) continue;
                    uint64_t p = c.q(o.addr + o_childprops);
                    for (int g = 0; g < 8 && plausible8(p); ++g) {
                        ++checked;
                        const std::string n = fname(p + cand.second);
                        if (n.empty() || n.rfind("<bad", 0) == 0) { --score; break; }
                        ++score;
                        const uint64_t nx = c.q(p + cand.first);
                        if (nx && !(plausible8(nx) && ends_with(fname(c.q(nx + ff_class)), "Property"))) { --score; break; }
                        p = nx;
                    }
                }
                if (score > best) { best = score; best_next = cand.first; best_name = cand.second; }
            }
            ff_next = best_next;
            ff_name = best_name;
            p_dim = align_up(ff_name + fname_size + 4, 8);
        } else {
            o_size = o_super + 0x10;
            p_dim = field_end;
        }
        p_esize = p_dim + 4;
        p_flags = p_dim + 8;
        p_off = p_dim + 0x14;
        p_size = align_up(p_off + 4 + fname_size, 8) + 32;
        e_names = field_end + 0x10;
        return true;
    }

    // ---- properties
    ptype_t describe(uint64_t p, int depth) {
        ptype_t t;
        if (depth > 6 || !plausible8(p)) { t.name = "void"; return t; }
        const std::string cls = ffield ? fname(c.q(p + ff_class)) : obj_name(c.q(p + o_class));
        const uint64_t x = p + p_size;
        auto prim = [&](const char* n) { t.name = n; return t; };
        auto tmpl = [&](const char* n, std::initializer_list<ptype_t> sub, char cat = 'C') {
            t.name = n; t.cat = cat; t.sub = sub; return t;
        };
        auto cls_t = [&](uint64_t k) { ptype_t r; r.name = class_cpp(k); r.cat = 'C'; r.ext = "*"; return r; };
        if (cls == "ByteProperty") {
            const uint64_t e = c.q(x);
            if (plausible8(e)) { t.name = obj_name(e); t.cat = 'E'; return t; }
            return prim("uint8");
        }
        if (cls == "Int8Property") return prim("int8");
        if (cls == "Int16Property") return prim("int16");
        if (cls == "IntProperty") return prim("int32");
        if (cls == "Int64Property") return prim("int64");
        if (cls == "UInt16Property") return prim("uint16");
        if (cls == "UInt32Property") return prim("uint32");
        if (cls == "UInt64Property") return prim("uint64");
        if (cls == "FloatProperty") return prim("float");
        if (cls == "DoubleProperty") return prim("double");
        if (cls == "BoolProperty") return prim("bool");
        if (cls == "NameProperty") { t.name = "FName"; t.cat = 'S'; return t; }
        if (cls == "StrProperty") { t.name = "FString"; t.cat = 'S'; return t; }
        if (cls == "TextProperty") { t.name = "FText"; t.cat = 'S'; return t; }
        if (cls == "ObjectProperty" || cls == "ObjectPtrProperty") return cls_t(c.q(x));
        if (cls == "ClassProperty" || cls == "ClassPtrProperty") return tmpl("TSubclassOf", {cls_t(c.q(x + 8))});
        if (cls == "WeakObjectProperty") return tmpl("TWeakObjectPtr", {cls_t(c.q(x))});
        if (cls == "LazyObjectProperty") return tmpl("TLazyObjectPtr", {cls_t(c.q(x))});
        if (cls == "SoftObjectProperty") return tmpl("TSoftObjectPtr", {cls_t(c.q(x))});
        if (cls == "SoftClassProperty") return tmpl("TSoftClassPtr", {cls_t(c.q(x + 8))});
        if (cls == "InterfaceProperty") return tmpl("TScriptInterface", {cls_t(c.q(x))});
        if (cls == "StructProperty") {
            const uint64_t s = c.q(x);
            t.name = plausible8(s) ? "F" + obj_name(s) : "FUnknownStruct";
            t.cat = 'S';
            return t;
        }
        if (cls == "ArrayProperty") return tmpl("TArray", {describe(c.q(x), depth + 1)});
        if (cls == "SetProperty") return tmpl("TSet", {describe(c.q(x), depth + 1)});
        if (cls == "MapProperty") return tmpl("TMap", {describe(c.q(x), depth + 1), describe(c.q(x + 8), depth + 1)});
        if (cls == "EnumProperty") {
            const uint64_t e = c.q(x + 8);
            if (plausible8(e)) { t.name = obj_name(e); t.cat = 'E'; return t; }
            return describe(c.q(x), depth + 1);
        }
        if (cls == "DelegateProperty") { t.name = "FScriptDelegate"; t.cat = 'S'; return t; }
        if (cls == "MulticastInlineDelegateProperty") { t.name = "FMulticastInlineDelegate"; t.cat = 'S'; return t; }
        if (cls == "MulticastSparseDelegateProperty") { t.name = "FMulticastSparseDelegate"; t.cat = 'S'; return t; }
        if (cls == "MulticastDelegateProperty") { t.name = "FMulticastScriptDelegate"; t.cat = 'S'; return t; }
        if (cls == "FieldPathProperty") { t.name = "FFieldPath"; t.cat = 'S'; return t; }
        t.name = cls.empty() ? "unknown" : cls;
        return t;
    }

    prop_t read_prop(uint64_t p) {
        prop_t r;
        r.addr = p;
        r.name = ffield ? fname(p + ff_name) : obj_name(p);
        r.cls = ffield ? fname(c.q(p + ff_class)) : obj_name(c.q(p + o_class));
        r.dim = c.i32(p + p_dim);
        r.size = c.i32(p + p_esize);
        r.flags = c.q(p + p_flags);
        r.offset = c.i32(p + p_off);
        r.type = describe(p, 0);
        if (r.cls == "BoolProperty") {
            const uint8_t byte_off = c.u8(p + p_size + 1), byte_mask = c.u8(p + p_size + 2), field_mask = c.u8(p + p_size + 3);
            if (field_mask != 0xFF && byte_mask) {
                r.offset += byte_off;
                r.size = 1;
                int b = 0;
                while (!((byte_mask >> b) & 1)) ++b;
                r.bit = b;
            }
        }
        return r;
    }

    bool prop_class_ok(uint64_t p) {
        const std::string k = ffield ? fname(c.q(p + ff_class)) : obj_name(c.q(p + o_class));
        return ends_with(k, "Property");
    }

    std::vector<prop_t> props_of(uint64_t s) {
        std::vector<prop_t> out;
        std::unordered_set<uint64_t> seen;
        uint64_t p = c.q(s + (ffield ? o_childprops : o_children));
        for (int g = 0; g < 4096 && plausible8(p) && seen.insert(p).second; ++g) {
            if (prop_class_ok(p)) out.push_back(read_prop(p));
            p = c.q(p + (ffield ? ff_next : o_next));
        }
        return out;
    }

    void detect_function_flags() {
        if (!cls_function) return;
        std::vector<std::pair<uint64_t, size_t>> sample;   // function, param count
        for (const auto& o : objs) {
            if (sample.size() >= 64) break;
            if (kind_of(o.cls) != K_FUNC) continue;
            const size_t n = props_of(o.addr).size();
            if (n) sample.emplace_back(o.addr, n);
        }
        if (sample.empty()) return;
        size_t best = 0;
        for (uint64_t cand = o_super + 0x20; cand <= o_super + 0x98; cand += 8) {
            size_t hits = 0;
            for (const auto& [f, n] : sample)
                if (static_cast<size_t>(c.u8(f + cand + 4)) == n && plausible(c.q(f + cand + 0x28))) ++hits;
            if (hits > best) { best = hits; fn_flags = cand; }
        }
        if (best * 10 < sample.size() * 6) {
            fn_flags = 0;
            res.warnings.push_back("UFunction::FunctionFlags offset not confirmed: function flags and addresses omitted");
        }
    }

    std::vector<func_t> funcs_of(uint64_t s) {
        std::vector<func_t> out;
        std::unordered_set<uint64_t> seen;
        uint64_t f = c.q(s + o_children);
        for (int g = 0; g < 4096 && plausible8(f) && seen.insert(f).second; ++g) {
            const uint64_t cls = c.q(f + o_class);
            if (plausible8(cls) && kind_of(cls) == K_FUNC) {
                func_t fn;
                fn.name = obj_name(f);
                if (fn_flags) { fn.flags = c.u32(f + fn_flags); fn.func = c.q(f + fn_flags + 0x28); }
                fn.params = props_of(f);
                out.push_back(std::move(fn));
            }
            f = c.q(f + o_next);
        }
        return out;
    }

    uenum_t enum_of(uint64_t e) {
        uenum_t r;
        r.name = obj_name(e);
        const uint64_t data = c.q(e + e_names);
        const int32_t num = c.i32(e + e_names + 8);
        const uint64_t pair = align_up(fname_size, 8) + 8;
        if (!plausible8(data) || num <= 0 || num > 65536) return r;
        for (int32_t i = 0; i < num; ++i) {
            const uint64_t a = data + static_cast<uint64_t>(i) * pair;
            std::string n = fname(a);
            if (const size_t sep = n.rfind("::"); sep != std::string::npos) n = n.substr(sep + 2);
            r.values.emplace_back(std::move(n), c.get<int64_t>(a + align_up(fname_size, 8)));
        }
        return r;
    }
};

std::string enum_underlying(const uenum_t& e) {
    int64_t mx = 0, mn = 0;
    for (const auto& v : e.values) { mx = std::max(mx, v.second); mn = std::min(mn, v.second); }
    if (mn < 0) return mx <= 0x7F && mn >= -0x80 ? "int8" : "int32";
    return mx <= 0xFF ? "uint8" : mx <= 0xFFFF ? "uint16" : mx <= 0xFFFFFFFFll ? "uint32" : "uint64";
}

} // namespace

dump_result_t dump(memory::reader_t& reader, const dump_options_t& opt) {
    dump_result_t res;
    cache_t c(reader);
    names_t nm(c);
    dumper_t d(c, nm, opt, res);

    // ---- names
    if (opt.gnames) {
        bool found = false;
        for (uint64_t k = 0; k <= 0x80 && !found; k += 8)
            found = nm.try_pool(opt.gnames + k, c.u32(opt.gnames + k - 8), c.u32(opt.gnames + k - 4));
        if (!found) found = nm.try_legacy(opt.gnames) || nm.try_legacy(c.q(opt.gnames));
        if (!found) { res.error = "gnames " + hx(opt.gnames) + ": no FNamePool or TNameEntryArray whose first names are None, ByteProperty"; return res; }
    } else {
        if (opt.scan.empty()) { res.error = "nothing to search: pass gnames/gobjects or scan ranges"; return res; }
        scan_ranges(c, opt.scan, [&](uint64_t va, const uint8_t* b, size_t i, size_t len) {
            if (i < 8 || i + 16 > len) return false;
            const uint64_t p = rq(b, i);
            if (!plausible(p) || (p & 1)) return false;
            const uint32_t cb = rd32(b, i - 8), cur = rd32(b, i - 4);
            if (cb >= 8192 || cur > 0x40000 || (cb == 0 && cur == 0)) return false;
            if (cb == 0) {
                if (rq(b, i + 8) != 0) return false;
            } else {
                const size_t j = i + 8ull * cb;
                if (j + 8 <= len && rq(b, j) == 0) return false;
                if (j + 16 <= len && rq(b, j + 8) != 0) return false;
            }
            return nm.try_pool(va, cb, cur);
        });
        if (!nm.ok && opt.version_hint != 5) {
            size_t checked = 0;
            scan_ranges(c, opt.scan, [&](uint64_t, const uint8_t* b, size_t i, size_t len) {
                if (i + 8 > len) return false;
                const uint64_t p = rq(b, i);
                if (!plausible8(p)) return false;
                if (++checked > 400000) return true;
                return nm.try_legacy(p);
            });
            if (!nm.ok && checked > 400000)
                res.warnings.push_back("legacy GNames search stopped after 400000 candidate pointers");
        }
        if (!nm.ok) { res.error = "name table not found (no FNamePool / TNameEntryArray in the scanned ranges); pass gnames explicitly"; return res; }
    }
    res.gnames = nm.blocks;
    if (nm.hdr_off == 4) { d.fname_size = 12; d.num_off = 8; }
    d.o_outer = align_up(d.o_name + d.fname_size, 8);

    // ---- objects
    if (opt.gobjects) {
        if (!d.objarray_explicit(opt.gobjects)) { res.error = "gobjects " + hx(opt.gobjects) + ": no chunked TUObjectArray with valid objects there"; return res; }
    } else {
        scan_ranges(c, opt.scan, [&](uint64_t va, const uint8_t* b, size_t i, size_t len) {
            return d.objarray_at(va, b, i, len);
        });
        if (!d.oa.objs) { res.error = "GUObjectArray not found in the scanned ranges; pass gobjects explicitly"; return res; }
    }
    res.gobjects = d.oa.at;
    d.index_objects();
    res.objects = d.objs.size();
    d.find_core();
    if (!d.cls_class || !d.cls_struct) { res.error = "core classes (UClass \"Class\", \"Struct\") not found among the objects: wrong GUObjectArray or unsupported layout"; return res; }
    d.detect_layout();
    d.detect_function_flags();

    // ---- version
    std::string ver;
    if (nm.legacy) ver = "4.20-4.22";
    else if (!d.ffield) ver = "4.23-4.24";
    else {
        ver = "4.25-4.27";
        for (const auto& o : d.objs)
            if (o.cls == d.cls_sstruct && nm.get(o.name) == "Vector") {
                if (c.i32(o.addr + d.o_size) == 24) ver = "5.x";
                break;
            }
    }
    res.version = ver;
    if (opt.version_hint && ver.front() - '0' != opt.version_hint)
        res.warnings.push_back("detected UE " + ver + " but version " + std::to_string(opt.version_hint) + ".x was requested");

    // ---- walk
    std::vector<ustruct_t> structs;
    std::vector<uenum_t> enums;
    std::unordered_map<uint64_t, size_t> struct_at;
    for (const auto& o : d.objs) {
        const kind_t k = d.kind_of(o.cls);
        if (k == K_CLASS || k == K_STRUCT) {
            ustruct_t s;
            s.addr = o.addr;
            s.kind = k;
            s.name = d.obj_name(o.addr);
            s.cpp = k == K_CLASS ? d.class_cpp(o.addr) : "F" + s.name;
            s.super = c.q(o.addr + d.o_super);
            if (!plausible8(s.super)) s.super = 0;
            s.size = c.i32(o.addr + d.o_size);
            uint64_t cur = s.super;
            for (int g = 0; g < 64 && cur; ++g) {
                s.inherit.push_back(k == K_CLASS ? d.class_cpp(cur) : "F" + d.obj_name(cur));
                const uint64_t nx = c.q(cur + d.o_super);
                cur = plausible8(nx) ? nx : 0;
            }
            if (!s.inherit.empty()) s.super_cpp = s.inherit.front();
            s.props = d.props_of(o.addr);
            if (k == K_CLASS) s.funcs = d.funcs_of(o.addr);
            res.functions += s.funcs.size();
            (k == K_CLASS ? res.classes : res.structs) += 1;
            struct_at.emplace(o.addr, structs.size());
            structs.push_back(std::move(s));
        } else if (k == K_ENUM) {
            enums.push_back(d.enum_of(o.addr));
        }
    }
    res.enums = enums.size();

    // ---- names table
    const auto all_names = nm.all(8u << 20);
    res.names = all_names.size();

    const std::string stamp = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    auto wrap = [&](json data) {
        json j;
        j["updated_at"] = stamp;
        j["data"] = std::move(data);
        j["version"] = 10202;
        return j.dump(-1, ' ', false, json::error_handler_t::replace);
    };

    if (opt.json) {
        json classes = json::array(), sts = json::array(), fns = json::array(), ens = json::array();
        for (const auto& s : structs) {
            json members = json::array();
            members.push_back({{"__InheritInfo", s.inherit}});
            members.push_back({{"__MDKClassSize", s.size}});
            for (const auto& p : s.props) {
                json v = json::array({ds_type(p.type), p.offset, p.size, p.dim});
                std::string key = p.name;
                if (p.bit >= 0) { key += " : 1"; v.push_back(p.bit); }
                members.push_back({{key, std::move(v)}});
            }
            (s.kind == K_CLASS ? classes : sts).push_back({{s.cpp, std::move(members)}});
            if (!s.funcs.empty()) {
                json list = json::array();
                for (const auto& f : s.funcs) {
                    ptype_t ret;
                    ret.name = "void";
                    json params = json::array();
                    for (const auto& p : f.params) {
                        if (p.flags & 0x400) { ret = p.type; continue; }   // CPF_ReturnParm
                        params.push_back(json::array({ds_type(p.type), (p.flags & 0x100) ? "&" : "", p.name}));
                    }
                    list.push_back({{f.name, json::array({ds_type(ret), params, f.func, f.flags})}});
                }
                fns.push_back({{s.cpp, std::move(list)}});
            }
        }
        for (const auto& e : enums) {
            json vals = json::array();
            for (const auto& [n, v] : e.values) vals.push_back({{n, v}});
            ens.push_back({{e.name, json::array({vals, enum_underlying(e)})}});
        }
        res.files.emplace_back("ClassesInfo.json", wrap(std::move(classes)));
        res.files.emplace_back("StructsInfo.json", wrap(std::move(sts)));
        res.files.emplace_back("FunctionsInfo.json", wrap(std::move(fns)));
        res.files.emplace_back("EnumsInfo.json", wrap(std::move(ens)));
        std::string txt;
        txt.reserve(all_names.size() * 24);
        for (const auto& [i, s] : all_names) txt += std::to_string(i) + "\t" + s + "\n";
        res.files.emplace_back("FNames.txt", std::move(txt));
    }

    if (opt.sdk) {
        std::string o = "// SDK.hpp generated by SlopStation re.ue_dump (UE " + ver + ")\n"
                        "// layout is exact (pack 1 + explicit padding); containers without a\n"
                        "// definition here are byte blobs annotated with their UE type\n"
                        "#pragma once\n#include <cstdint>\n\n"
                        "using int8 = int8_t; using int16 = int16_t; using int32 = int32_t; using int64 = int64_t;\n"
                        "using uint8 = uint8_t; using uint16 = uint16_t; using uint32 = uint32_t; using uint64 = uint64_t;\n"
                        "template <class T> struct TArray { T* Data; int32 Num; int32 Max; };\n"
                        "struct FString { TArray<wchar_t> Data; };\n";
        o += nm.hdr_off == 4 ? "struct FName { uint32 ComparisonIndex; uint32 DisplayIndex; uint32 Number; };\n"
                             : "struct FName { uint32 ComparisonIndex; uint32 Number; };\n";
        o += "\n#pragma pack(push, 1)\n\n";
        std::unordered_set<std::string> enum_done;
        for (const auto& e : enums) {
            if (!enum_done.insert(c_ident(e.name)).second) continue;
            o += "enum class " + c_ident(e.name) + " : " + enum_underlying(e) + " {\n";
            std::unordered_set<std::string> seen;
            for (const auto& [n, v] : e.values) {
                std::string id = c_ident(n);
                while (!seen.insert(id).second) id += "_";
                o += "    " + id + " = " + std::to_string(v) + ",\n";
            }
            o += "};\n\n";
        }
        // forward declarations so pointers always compile
        std::unordered_set<std::string> declared;
        for (const auto& s : structs)
            if (declared.insert(c_ident(s.cpp)).second) o += "struct " + c_ident(s.cpp) + ";\n";
        o += "\n";
        std::unordered_set<std::string> enum_names;
        for (const auto& e : enums) enum_names.insert(c_ident(e.name));
        std::unordered_map<std::string, size_t> by_cpp;
        for (size_t i = 0; i < structs.size(); ++i) by_cpp.emplace(c_ident(structs[i].cpp), i);
        // supers and by-value struct members first
        std::vector<uint8_t> state(structs.size(), 0);
        std::vector<size_t> order;
        std::function<void(size_t)> visit = [&](size_t i) {
            if (state[i]) return;
            state[i] = 1;
            auto dep = [&](const std::string& n) {
                auto it = by_cpp.find(c_ident(n));
                if (it != by_cpp.end() && it->second != i && state[it->second] == 0) visit(it->second);
            };
            if (!structs[i].super_cpp.empty()) dep(structs[i].super_cpp);
            for (const auto& p : structs[i].props)
                if (p.type.cat == 'S' && p.type.sub.empty() && p.type.ext.empty()) dep(p.type.name);
            state[i] = 2;
            order.push_back(i);
        };
        for (size_t i = 0; i < structs.size(); ++i) visit(i);
        std::unordered_set<std::string> emitted;
        for (size_t i : order) {
            const ustruct_t& s = structs[i];
            const std::string id = c_ident(s.cpp);
            if (!emitted.insert(id).second) continue;
            int32_t base = 0;
            std::string sup;
            if (!s.super_cpp.empty() && emitted.count(c_ident(s.super_cpp)) != 0) {
                sup = c_ident(s.super_cpp);
                if (auto it = struct_at.find(s.super); it != struct_at.end()) base = structs[it->second].size;
            }
            o += "// " + s.name + " size " + hx(static_cast<uint64_t>(std::max(s.size, 0))) + "\n";
            o += "struct " + id + (sup.empty() ? "" : " : public " + sup) + " {\n";
            std::vector<const prop_t*> ps;
            for (const auto& p : s.props) ps.push_back(&p);
            std::stable_sort(ps.begin(), ps.end(), [](const prop_t* a, const prop_t* b) {
                return a->offset != b->offset ? a->offset < b->offset : a->bit < b->bit;
            });
            int64_t cur = base;
            std::unordered_set<std::string> names;
            for (size_t k = 0; k < ps.size(); ++k) {
                const prop_t& p = *ps[k];
                std::string nmid = c_ident(p.name);
                while (!names.insert(nmid).second) nmid += "_";
                const int64_t width = static_cast<int64_t>(std::max(p.size, 0)) * std::max(p.dim, 1);
                if (p.bit >= 0) {
                    // a run of bool bitfields sharing one byte
                    if (p.offset < cur - 1 || (p.offset == cur - 1 && k && ps[k - 1]->bit < 0)) {
                        o += "    // " + p.name + " bit " + std::to_string(p.bit) + " @ " + hx(static_cast<uint64_t>(p.offset)) + " overlaps\n";
                        continue;
                    }
                    if (p.offset >= cur) {
                        if (p.offset > cur) o += "    uint8 _pad_" + hx(static_cast<uint64_t>(cur)).substr(2) + "[" + std::to_string(p.offset - cur) + "];\n";
                        int used_bits = 0;
                        for (size_t l = k; l < ps.size() && ps[l]->offset == p.offset && ps[l]->bit >= 0; ++l) {
                            std::string bid = l == k ? nmid : c_ident(ps[l]->name);
                            if (l != k) while (!names.insert(bid).second) bid += "_";
                            if (ps[l]->bit < used_bits) continue;
                            if (ps[l]->bit > used_bits) o += "    uint8 : " + std::to_string(ps[l]->bit - used_bits) + ";\n";
                            o += "    uint8 " + bid + " : 1;  // " + hx(static_cast<uint64_t>(p.offset)) + " bit " + std::to_string(ps[l]->bit) + "\n";
                            used_bits = ps[l]->bit + 1;
                        }
                        if (used_bits < 8) o += "    uint8 : " + std::to_string(8 - used_bits) + ";\n";
                        cur = p.offset + 1;
                    }
                    continue;
                }
                if (p.offset < cur) { o += "    // " + cpp_type(p.type) + " " + p.name + " @ " + hx(static_cast<uint64_t>(p.offset)) + " overlaps\n"; continue; }
                if (p.offset > cur) o += "    uint8 _pad_" + hx(static_cast<uint64_t>(cur)).substr(2) + "[" + std::to_string(p.offset - cur) + "];\n";
                const std::string ct = cpp_type(p.type);
                const bool typed = p.type.cat == 'D' ? p.type.name != "unknown" && p.type.name.find("Property") == std::string::npos
                                 : p.type.cat == 'E' ? enum_names.count(c_ident(p.type.name)) != 0
                                 : p.type.ext == "*" || p.type.name == "TArray" || p.type.name == "FString" || p.type.name == "FName" ||
                                   (p.type.cat == 'S' && p.type.sub.empty() && emitted.count(c_ident(p.type.name)) != 0);
                auto ptr_t = [&](const ptype_t& x) {
                    return declared.count(c_ident(x.name)) != 0 ? c_ident(x.name) + "*" : std::string("void*");
                };
                const ptype_t* in = p.type.sub.size() == 1 ? &p.type.sub[0] : nullptr;
                const bool arr_ok = p.type.name != "TArray" ||
                                    (in && (in->ext == "*" ||
                                            (in->cat == 'D' && in->name != "unknown" && in->name.find("Property") == std::string::npos) ||
                                            (in->cat == 'S' && in->sub.empty() && (in->name == "FName" || in->name == "FString" ||
                                                                                   declared.count(c_ident(in->name)) != 0))));
                std::string decl;
                if (typed && arr_ok && width > 0) {
                    std::string t = ct;
                    if (p.type.cat == 'E' || (p.type.cat == 'S' && p.type.sub.empty() && p.type.ext.empty() && p.type.name.front() == 'F' &&
                                              p.type.name != "FString" && p.type.name != "FName"))
                        t = c_ident(p.type.name);
                    if (p.type.ext == "*") t = ptr_t(p.type);
                    if (p.type.name == "TArray" && in)
                        t = "TArray<" + (in->ext == "*" ? ptr_t(*in) : in->cat == 'D' ? in->name : c_ident(in->name)) + ">";
                    decl = "    " + t + " " + nmid + (p.dim > 1 ? "[" + std::to_string(p.dim) + "]" : "") + ";";
                } else {
                    decl = "    uint8 " + nmid + "[" + std::to_string(std::max<int64_t>(width, 1)) + "];";
                }
                o += decl + "  // " + hx(static_cast<uint64_t>(p.offset)) + " " + hx(static_cast<uint64_t>(std::max<int64_t>(width, 0))) + " " + ct + "\n";
                cur = p.offset + std::max<int64_t>(width, 1);
            }
            if (s.size > cur) o += "    uint8 _pad_" + hx(static_cast<uint64_t>(cur)).substr(2) + "[" + std::to_string(s.size - cur) + "];\n";
            for (const auto& f : s.funcs) {
                std::string sig;
                for (const auto& p : f.params) sig += (sig.empty() ? "" : ", ") + cpp_type(p.type) + " " + p.name;
                o += "    // fn " + f.name + "(" + sig + ")";
                if (f.func) o += " -> " + hx(f.func);
                o += "\n";
            }
            o += "};\n\n";
        }
        o += "#pragma pack(pop)\n";
        res.files.emplace_back("SDK.hpp", std::move(o));
    }
    res.ok = true;
    return res;
}

} // namespace slop::core::re::ue
