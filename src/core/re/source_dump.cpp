// src/core/re/source_dump.cpp
// Source engine netvar dumper over a memory reader, see source_dump.hpp
// (Apex Legends PS4 eboot is a 64-bit Titanfall-derived Source build: the
// ClientClass / RecvTable / RecvProp layouts below are the stock Source SDK
// x64 layouts, and every table is found by structure, not by signature)

#include "core/re/source_dump.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace slop::core::re::source {

namespace {

using json = nlohmann::json;

// RecvProp::m_RecvType (SendPropType)
const char* kTypeNames[] = {"int", "float", "vector", "vectorxy", "string", "array", "datatable", "int64"};

bool plausible(uint64_t p) { return p >= 0x10000 && p < 0x0000800000000000ull; }
bool plausible8(uint64_t p) { return plausible(p) && (p & 7) == 0; }
uint64_t align_up(uint64_t v, uint64_t a) { return (v + a - 1) & ~(a - 1); }

std::string hx(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

// x64 layouts (bytes)
constexpr uint64_t kRecvPropSize    = 0x58;
constexpr uint32_t kRecvTypeNames   = 8;    // DPT_Int .. DPT_Int64
constexpr size_t   kMaxPropsPerTbl  = 512;
constexpr size_t   kMaxTables       = 4096;
constexpr size_t   kMaxDepth        = 32;

// ClientClass: CreateFn 0x00, CreateEventFn 0x08, NetworkName 0x10,
//              RecvTable 0x18, Next 0x20, ClassID 0x28
// RecvTable:   Props 0x00, NumProps 0x08, Decoder 0x10, Name 0x18, Bools 0x20
// RecvProp:    VarName 0x00, RecvType 0x08, Flags 0x0C, StringBufferSize 0x10,
//              InsideArray 0x14, ExtraDataTable 0x18, ArrayLengthProxy 0x20,
//              ProxyFn 0x28, DataTableProxyFn 0x30, DataTable 0x38,
//              Offset 0x40, ElementStride 0x44, NumElements 0x48, ParentArrayName 0x50

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

// ---------------------------------------------------------------- strings

// printable ASCII C string, len in [1, max]; false when unreadable
bool cstr(cache_t& c, uint64_t a, std::string& out, size_t max = 64) {
    out.clear();
    if (!plausible(a)) return false;
    uint8_t buf[72];
    if (!c.read(a, buf, max + 1)) return false;
    for (size_t i = 0; i < max; ++i) {
        const uint8_t ch = buf[i];
        if (ch == 0) return !out.empty();
        if (ch < 0x20 || ch > 0x7E) return false;
        out.push_back(static_cast<char>(ch));
    }
    return false;   // never terminated inside the window
}

bool ident_like(const std::string& s) {   // m_foo / DT_foo / _x / 0base style
    for (char ch : s)
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_') return false;
    return true;
}

// ---------------------------------------------------------------- structures

// table present + shape plausible; with check_props also validates the prop array
bool valid_table(cache_t& c, uint64_t t, bool check_props) {
    if (!plausible8(t)) return false;
    std::string name;
    if (!cstr(c, c.q(t + 0x18), name, 48) || name.rfind("DT_", 0) != 0 || !ident_like(name)) return false;
    const int32_t n = c.i32(t + 0x08);
    if (n < 1 || static_cast<size_t>(n) > kMaxPropsPerTbl) return false;
    const uint64_t props = c.q(t + 0x00);
    if (!plausible8(props)) return false;
    if (!check_props) return true;
    for (int32_t i = 0; i < n; ++i) {
        const uint64_t p = props + static_cast<uint64_t>(i) * kRecvPropSize;
        std::string pn;
        if (!cstr(c, c.q(p + 0x00), pn, 48) || !ident_like(pn)) return false;
        const uint32_t ty = c.u32(p + 0x08);
        if (ty > kRecvTypeNames) return false;
    }
    return true;
}

bool valid_class(cache_t& c, uint64_t cc, bool deep) {
    if (!plausible8(cc)) return false;
    std::string net_name;
    if (!cstr(c, c.q(cc + 0x10), net_name, 48) || !ident_like(net_name)) return false;
    const uint64_t next = c.q(cc + 0x20);
    if (next != 0 && !plausible8(next)) return false;
    return valid_table(c, c.q(cc + 0x18), deep);
}

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

// ---------------------------------------------------------------- dumper

class dumper_t {
public:
    dumper_t(cache_t& c, dump_result_t& res) : c_(c), res_(res) {}

    // follow the Next chain from `head`; returns the collected class addresses
    std::vector<uint64_t> chain(uint64_t head, size_t max_classes) {
        std::vector<uint64_t> out;
        std::unordered_set<uint64_t> seen;
        for (uint64_t cc = head; cc && seen.insert(cc).second && out.size() < max_classes;) {
            if (!valid_class(c_, cc, true)) break;
            out.push_back(cc);
            cc = c_.q(cc + 0x20);
        }
        return out;
    }

    void run(const std::vector<uint64_t>& classes, std::string stamp) {
        stamp_ = std::move(stamp);
        std::unordered_set<uint64_t> tables_seen;
        for (uint64_t cc : classes) {
            std::string cls_name, tbl_name;
            cstr(c_, c_.q(cc + 0x10), cls_name);
            const uint64_t tbl = c_.q(cc + 0x18);
            cstr(c_, c_.q(tbl + 0x18), tbl_name);
            const int32_t class_id = c_.i32(cc + 0x28);
            json jprops = json::array();
            walk_table(tbl, tbl_name, 0, 0, jprops);
            json e = {{"class", cls_name}, {"table", tbl_name}, {"class_id", class_id},
                      {"recv_table", hx(tbl)}, {"props", std::move(jprops)}};
            recv_tables_.push_back({tbl_name, std::move(e)});
            if (tables_seen.insert(tbl).second) ++res_.tables;
        }
        res_.classes = classes.size();
        res_.props = prop_count_;
        res_.netvars = netvars_.size();
    }

    void emit_files() {
        {
            json nv = json::object();
            for (const auto& [k, v] : netvars_) nv[k] = v;
            json j;
            j["head"] = hx(res_.head);
            j["updated_at"] = stamp_;
            j["netvars"] = std::move(nv);
            res_.files.emplace_back("netvars.json", j.dump(2, ' ', false, json::error_handler_t::replace));
        }
        {
            json data = json::array();
            for (auto& [_, e] : recv_tables_) data.push_back(std::move(e));
            json j;
            j["head"] = hx(res_.head);
            j["updated_at"] = stamp_;
            j["data"] = std::move(data);
            res_.files.emplace_back("recvtables.json", j.dump(2, ' ', false, json::error_handler_t::replace));
        }
    }

    std::map<std::string, int32_t> netvars_;   // sorted flat offsets

private:
    void walk_table(uint64_t tbl, const std::string& tbl_name, int32_t base, unsigned depth, json& jprops) {
        if (depth > kMaxDepth || walked_.size() >= kMaxTables ||
            !walked_.insert(tbl_name + "@" + hx(base)).second)
            return;
        const int32_t n = c_.i32(tbl + 0x08);
        const uint64_t props = c_.q(tbl + 0x00);
        for (int32_t i = 0; i < n; ++i) {
            if (++prop_count_ > 200000) { res_.warnings.push_back("prop walk stopped at 200000"); return; }
            const uint64_t p = props + static_cast<uint64_t>(i) * kRecvPropSize;
            std::string name;
            if (!cstr(c_, c_.q(p + 0x00), name, 48)) continue;
            const uint32_t ty = c_.u32(p + 0x08);
            if (ty > kRecvTypeNames) continue;
            const int32_t offset = c_.i32(p + 0x40);
            const uint64_t dt = c_.q(p + 0x38);
            json jp = {{"name", name}, {"type", kTypeNames[ty]}, {"offset", offset},
                       {"elements", c_.i32(p + 0x48)}, {"stride", c_.i32(p + 0x44)}};
            if (ty == 6) jp["data_table"] = hx(dt);
            jprops.push_back(std::move(jp));

            if (ty == 6 && plausible8(dt)) {                    // DPT_DataTable
                std::string dt_name;
                if (!cstr(c_, c_.q(dt + 0x18), dt_name, 48)) dt_name = tbl_name;
                if (name[0] == '0')                             // baseclass: no offset add
                    walk_table(dt, dt_name, base, depth + 1, jprops);
                else
                    walk_table(dt, dt_name, base + offset, depth + 1, jprops);
            } else {
                std::string key = tbl_name;                      // first table to define a name wins
                key += "->";
                key += name;
                if (netvars_.emplace(std::move(key), base + offset).second) ++res_.netvars;
            }
        }
    }

    cache_t& c_;
    dump_result_t& res_;
    std::string stamp_;
    size_t prop_count_ = 0;
    std::unordered_set<std::string> walked_;
    std::vector<std::pair<std::string, json>> recv_tables_;
};

} // namespace

dump_result_t dump(memory::reader_t& reader, const dump_options_t& opt) {
    dump_result_t res;
    cache_t c(reader);

    std::vector<uint64_t> classes;
    if (opt.head) {
        res.head = opt.head;
        classes = dumper_t(c, res).chain(opt.head, opt.max_classes);
        if (classes.empty()) { res.error = "head " + hx(opt.head) + ": no ClientClass chain there"; return res; }
    } else {
        if (opt.scan.empty()) { res.error = "nothing to search: pass head or scan ranges"; return res; }
        // pass 1: collect every qword in the ranges that looks like a ClientClass node
        std::unordered_set<uint64_t> nodes, nexts;
        scan_ranges(c, opt.scan, [&](uint64_t, const uint8_t* b, size_t i, size_t len) {
            if (i + 8 > len) return false;
            uint64_t v;
            std::memcpy(&v, b + i, 8);
            if (!plausible8(v)) return false;
            if (valid_class(c, v, false)) {
                nodes.insert(v);
                const uint64_t nx = c.q(v + 0x20);
                if (nx) nexts.insert(nx);
            }
            return false;
        });
        if (nodes.empty()) {
            res.error = "no ClientClass nodes in the scanned ranges; pass head explicitly "
                        "(the CHLClient class list pointer, e.g. from GetAllClasses)";
            return res;
        }
        // pass 2: heads are nodes nobody points at; keep the longest chain
        dumper_t probe(c, res);
        size_t best = 0;
        for (uint64_t n : nodes) {
            if (nexts.count(n)) continue;               // mid-list node
            auto ch = probe.chain(n, opt.max_classes);
            if (ch.size() > best) { best = ch.size(); res.head = n; classes = std::move(ch); }
        }
        if (classes.empty()) {                          // cyclic or single node: take any longest chain
            for (uint64_t n : nodes) {
                auto ch = probe.chain(n, opt.max_classes);
                if (ch.size() > best) { best = ch.size(); res.head = n; classes = std::move(ch); }
            }
        }
        if (classes.size() < 5)
            res.warnings.push_back("only " + std::to_string(classes.size()) +
                                   " ClientClass node(s) validated; chain may be partial, "
                                   "pass head for the true list head");
    }

    dumper_t d(c, res);
    d.run(classes, std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count()));
    d.emit_files();
    res.ok = true;
    return res;
}

} // namespace slop::core::re::source
