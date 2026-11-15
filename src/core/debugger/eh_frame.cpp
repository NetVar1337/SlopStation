// src/core/debugger/eh_frame.cpp
// DWARF CFI unwinding for ELF x86-64 (.eh_frame), see callstack.hpp
//
// A small interpreter for the subset of DWARF call-frame information that real
// eboots emit: CIE/FDE records, the common DW_EH_PE encodings, and the CFA /
// return-address rules. Expressions (DW_CFA_expression) are not evaluated; a
// frame that needs one ends the walk rather than producing a wrong address.

#include "core/debugger/callstack.hpp"

#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace slop::core::debugger::unwind {

namespace {

constexpr uint64_t kEhUserMax = 0x7FFFFFFEFFFFull;   // highest user VA

struct cfi_rule_t {
    bool    present = false;
    bool    same    = false;   // DW_CFA_same_value
    bool    undef   = false;   // DW_CFA_undefined
    int64_t offset  = 0;       // value lives at CFA + offset
};

struct cfi_state_t {
    uint32_t cfa_reg    = 7;   // rsp
    int64_t  cfa_offset = 8;
    bool     cfa_expr   = false;
    std::map<uint32_t, cfi_rule_t> rules;
    int      remember = 0;     // DW_CFA_remember_state nesting (rules not saved)
};

struct cfi_cursor_t {
    const uint8_t* p = nullptr;
    const uint8_t* end = nullptr;
    bool bad = false;
    bool ok() const { return !bad && p < end; }
    uint8_t u8() {
        if (p >= end) { bad = true; return 0; }
        return *p++;
    }
    uint64_t uleb() {
        uint64_t v = 0;
        unsigned shift = 0;
        while (ok() && shift < 64) {
            const uint8_t b = u8();
            v |= static_cast<uint64_t>(b & 0x7f) << shift;
            if (!(b & 0x80)) return v;
            shift += 7;
        }
        bad = true;
        return 0;
    }
    int64_t sleb() {
        int64_t v = 0;
        unsigned shift = 0;
        uint8_t b = 0;
        while (ok() && shift < 64) {
            b = u8();
            v |= static_cast<int64_t>(b & 0x7f) << shift;
            shift += 7;
            if (!(b & 0x80)) break;
        }
        if (shift < 64 && (b & 0x40)) v |= -(static_cast<int64_t>(1) << shift);
        return v;
    }
    uint64_t fixed(size_t n) {
        uint64_t v = 0;
        for (size_t i = 0; i < n; ++i) v |= static_cast<uint64_t>(u8()) << (8 * i);
        return v;
    }
    void skip(size_t n) {
        if (static_cast<size_t>(end - p) < n) { bad = true; return; }
        p += n;
    }
};

// DW_EH_PE_* value decoding; `here` is the VA the field sits at (pcrel base)
bool read_encoded(cfi_cursor_t& c, uint8_t enc, uint64_t here, uint64_t& out) {
    if (enc == 0xff) { out = 0; return false; }
    const uint8_t fmt = enc & 0x0f;
    const uint8_t app = enc & 0x70;
    int64_t v = 0;
    switch (fmt) {
    case 0x00: v = static_cast<int64_t>(c.fixed(8)); break;   // absptr
    case 0x01: v = static_cast<int64_t>(c.uleb());   break;
    case 0x02: v = static_cast<int64_t>(c.fixed(2)); break;
    case 0x03: v = static_cast<int64_t>(c.fixed(4)); break;
    case 0x04: v = static_cast<int64_t>(c.fixed(8)); break;
    case 0x09: v = c.sleb();                         break;
    case 0x0a: v = static_cast<int16_t>(c.fixed(2)); break;
    case 0x0b: v = static_cast<int32_t>(c.fixed(4)); break;
    case 0x0c: v = static_cast<int64_t>(c.fixed(8)); break;
    default: c.bad = true; return false;
    }
    if (c.bad) return false;
    switch (app) {
    case 0x00: break;                                     // absolute
    case 0x10: v += static_cast<int64_t>(here); break;    // pcrel
    case 0x30: v += static_cast<int64_t>(here); break;    // datarel: treated as pcrel
    default: c.bad = true; return false;                  // textrel/funcrel/aligned
    }
    out = static_cast<uint64_t>(v);
    return true;
}

struct cie_t {
    uint64_t code_align = 1;
    int64_t  data_align = -8;
    uint64_t ra_reg     = 16;
    uint8_t  fde_enc    = 0;
    const uint8_t* init = nullptr;      // initial instructions
    const uint8_t* init_end = nullptr;
};

// apply one CFI instruction stream; `loc` starts at pc_begin and advances per
// DW_CFA_advance_loc*, so the state reflects the rules in force at target_pc
void run_cfi(cfi_cursor_t& c, const cie_t& cie, cfi_state_t& st,
             uint64_t& loc, uint64_t target_pc, bool stop_at_target) {
    while (c.ok()) {
        if (stop_at_target && loc > target_pc) return;
        const uint8_t op = c.u8();
        if (c.bad) return;
        const uint8_t hi = op & 0xc0;
        const uint8_t lo = op & 0x3f;
        if (hi == 0x40) {                       // advance_loc
            loc += lo * cie.code_align;
            continue;
        }
        if (hi == 0x80) {                       // offset
            cfi_rule_t r;
            r.present = true;
            r.offset = static_cast<int64_t>(c.uleb()) * cie.data_align;
            st.rules[lo] = r;
            continue;
        }
        if (hi == 0xc0) {                       // restore
            st.rules.erase(lo);
            continue;
        }
        switch (op) {
        case 0x00: break;                       // nop
        case 0x01: {                            // set_loc
            uint64_t a = 0;
            read_encoded(c, cie.fde_enc, 0, a);
            loc = a;
            break;
        }
        case 0x02: loc += c.u8() * cie.code_align; break;
        case 0x03: loc += c.fixed(2) * cie.code_align; break;
        case 0x04: loc += c.fixed(4) * cie.code_align; break;
        case 0x05: {                            // offset_extended
            const uint32_t reg = static_cast<uint32_t>(c.uleb());
            cfi_rule_t r;
            r.present = true;
            r.offset = static_cast<int64_t>(c.uleb()) * cie.data_align;
            st.rules[reg] = r;
            break;
        }
        case 0x06: st.rules.erase(static_cast<uint32_t>(c.uleb())); break;
        case 0x07: {                            // undefined
            cfi_rule_t r;
            r.present = true;
            r.undef = true;
            st.rules[static_cast<uint32_t>(c.uleb())] = r;
            break;
        }
        case 0x08: {                            // same_value
            cfi_rule_t r;
            r.present = true;
            r.same = true;
            st.rules[static_cast<uint32_t>(c.uleb())] = r;
            break;
        }
        case 0x09: {                            // register (approx: same_value)
            const uint32_t a = static_cast<uint32_t>(c.uleb());
            (void)c.uleb();
            cfi_rule_t r;
            r.present = true;
            r.same = true;
            st.rules[a] = r;
            break;
        }
        case 0x0a: ++st.remember; break;        // remember_state
        case 0x0b: if (st.remember > 0) --st.remember; break;   // restore_state
        case 0x0c:                              // def_cfa
            st.cfa_reg = static_cast<uint32_t>(c.uleb());
            st.cfa_offset = static_cast<int64_t>(c.uleb());
            st.cfa_expr = false;
            break;
        case 0x0d: st.cfa_reg = static_cast<uint32_t>(c.uleb()); break;
        case 0x0e: st.cfa_offset = static_cast<int64_t>(c.uleb()); break;
        case 0x0f: st.cfa_expr = true; (void)c.uleb(); break;   // def_cfa_expression
        case 0x10: (void)c.uleb(); (void)c.uleb(); break;       // expression
        case 0x11: {                            // offset_extended_sf
            const uint32_t reg = static_cast<uint32_t>(c.uleb());
            cfi_rule_t r;
            r.present = true;
            r.offset = c.sleb() * cie.data_align;
            st.rules[reg] = r;
            break;
        }
        case 0x12: st.cfa_reg = static_cast<uint32_t>(c.uleb());
                   st.cfa_offset = c.sleb(); st.cfa_expr = false; break;
        case 0x13: st.cfa_offset = c.sleb(); break;
        case 0x14: case 0x15: {                 // val_offset / val_offset_sf
            const uint32_t reg = static_cast<uint32_t>(c.uleb());
            if (op == 0x14) (void)c.uleb(); else (void)c.sleb();
            cfi_rule_t r;
            r.present = true;
            r.undef = true;
            st.rules[reg] = r;
            break;
        }
        case 0x16: (void)c.uleb(); (void)c.uleb(); break;       // val_expression
        case 0x2e: (void)c.uleb(); break;                       // GNU_args_size
        case 0x2f: (void)c.uleb(); (void)c.uleb(); break;       // GNU_negative_offset
        default: return;                        // unknown: end this frame cleanly
        }
    }
}

// parse a CIE body (after its length and the 4-byte id) into cie_t
bool parse_cie(const uint8_t* body, const uint8_t* body_end, cie_t& out) {
    cfi_cursor_t c{body, body_end};
    if (c.fixed(4) != 0) return false;          // not a CIE
    const uint8_t ver = c.u8();
    std::string aug;
    while (c.ok()) {
        const char ch = static_cast<char>(c.u8());
        if (ch == 0) break;
        aug += ch;
    }
    if (c.bad) return false;
    out.code_align = c.uleb();
    out.data_align = c.sleb();
    out.ra_reg = (ver == 1) ? c.u8() : c.uleb();
    if (c.bad) return false;
    if (!aug.empty() && aug[0] == 'z') {
        const uint64_t alen = c.uleb();
        if (c.bad) return false;
        const uint8_t* aend = c.p + alen;
        if (aend > c.end) return false;
        for (size_t i = 1; i < aug.size() && c.p < aend; ++i) {
            if (aug[i] == 'R') out.fde_enc = c.u8();
            else if (aug[i] == 'P') {
                const uint8_t penc = c.u8();
                uint64_t dummy = 0;
                read_encoded(c, penc, 0, dummy);
            } else if (aug[i] == 'L') {
                (void)c.u8();
            }
        }
        c.p = aend;
    }
    out.init = c.p;
    out.init_end = body_end;
    return !c.bad;
}

// find the FDE covering pc; fills cie and the FDE instruction range
bool find_fde(const eh_frame_t& eh, uint64_t pc, cie_t& cie,
              const uint8_t*& fde_insn, const uint8_t*& fde_insn_end) {
    const uint8_t* base = eh.data;
    const uint8_t* p = base;
    const uint8_t* end = base + eh.size;
    while (p + 4 <= end) {
        cfi_cursor_t len_c{p, end};
        uint64_t len = len_c.fixed(4);
        const uint8_t* body = p + 4;
        if (len == 0) break;                       // terminator
        if (len == 0xffffffffull) {                // 64-bit length
            cfi_cursor_t l64{body, end};
            len = l64.fixed(8);
            body += 8;
        }
        if (len == 0 || static_cast<uint64_t>(end - body) < len) break;
        const uint8_t* body_end = body + len;
        cfi_cursor_t c{body, body_end};
        const uint64_t id = c.fixed(4);
        if (id == 0) { p = body_end; continue; }   // CIE: consumed on demand by its FDEs

        const uint8_t* cie_at = body - id;          // CIE_pointer is a back-offset
        if (cie_at < base || cie_at >= end) { p = body_end; continue; }
        cfi_cursor_t lc{cie_at, end};
        uint64_t clen = lc.fixed(4);
        const uint8_t* cbody = cie_at + 4;
        if (clen == 0xffffffffull) {
            cfi_cursor_t l64{cbody, end};
            clen = l64.fixed(8);
            cbody += 8;
        }
        if (clen == 0 || static_cast<uint64_t>(end - cbody) < clen) { p = body_end; continue; }
        cie_t local;
        if (!parse_cie(cbody, cbody + clen, local)) { p = body_end; continue; }

        // pc_begin / pc_range are pcrel to the field itself
        uint64_t pc_begin = 0, pc_range = 0;
        const uint64_t begin_va = eh.va + static_cast<uint64_t>(c.p - base);
        if (!read_encoded(c, local.fde_enc, begin_va, pc_begin)) { p = body_end; continue; }
        const uint64_t range_va = eh.va + static_cast<uint64_t>(c.p - base);
        if (!read_encoded(c, static_cast<uint8_t>(local.fde_enc & 0x0f), range_va, pc_range)) {
            p = body_end;
            continue;
        }
        if (!c.bad && pc >= pc_begin && pc < pc_begin + pc_range) {
            cie = local;
            fde_insn = c.p;
            fde_insn_end = body_end;
            return true;
        }
        p = body_end;
    }
    return false;
}

} // namespace

bool elf_unwind(reader_t& rdr, const eh_frame_t& eh, uint64_t rip, uint64_t rsp,
                uint64_t rbp, size_t max_frames, std::vector<frame_t>& out,
                std::string* note) {
    out.clear();
    if (!eh.data || eh.size == 0) {
        if (note) *note = "no .eh_frame section";
        return false;
    }
    if (max_frames == 0) return false;

    uint64_t pc = rip, sp = rsp, fp = rbp;
    bool first = true;
    for (size_t i = 0; i < max_frames; ++i) {
        cie_t cie;
        const uint8_t* insn = nullptr;
        const uint8_t* insn_end = nullptr;
        if (!find_fde(eh, pc, cie, insn, insn_end)) {
            if (note && out.empty()) *note = "no FDE covers this pc";
            break;
        }
        if (first) {
            frame_t f;
            f.ret_addr = pc;
            f.frame_ptr = fp;
            out.push_back(f);
            first = false;
        }

        // replay the CIE initial instructions, then the FDE's up to pc
        cfi_state_t st;
        uint64_t loc = 0;
        {
            cfi_cursor_t c{cie.init, cie.init_end};
            run_cfi(c, cie, st, loc, pc, false);
        }
        {
            cfi_cursor_t c{insn, insn_end};
            run_cfi(c, cie, st, loc, pc, true);
        }
        if (st.cfa_expr) {
            if (note) *note = "CFA is a DWARF expression (not evaluated)";
            break;
        }
        // CFA base register: only rsp (7) and rbp (6) have known values here;
        // any other base ends the walk rather than guessing
        uint64_t base_val = 0;
        if (st.cfa_reg == 7) base_val = sp;
        else if (st.cfa_reg == 6) base_val = fp;
        else {
            if (note) *note = "CFA uses a register whose value is unknown";
            break;
        }
        const uint64_t cfa = base_val + static_cast<uint64_t>(st.cfa_offset);

        // return-address column (16 on x86-64)
        const auto ra_it = st.rules.find(static_cast<uint32_t>(cie.ra_reg));
        uint64_t caller_rip = 0;
        if (ra_it != st.rules.end() && ra_it->second.present) {
            if (ra_it->second.undef || ra_it->second.same) {
                if (note) *note = "return address is not recoverable from CFI";
                break;
            }
            if (!rdr.read(cfa + static_cast<uint64_t>(ra_it->second.offset), &caller_rip, 8)) {
                if (note) *note = "cannot read the return address at CFA";
                break;
            }
        } else {
            // default x86-64 rule: the return address sits at CFA - 8
            if (!rdr.read(cfa - 8, &caller_rip, 8)) {
                if (note) *note = "cannot read the return address at CFA-8";
                break;
            }
        }
        if (caller_rip == 0 || caller_rip > kEhUserMax) break;

        // caller's frame pointer, when the CFI describes one
        uint64_t caller_fp = 0;
        const auto bp_it = st.rules.find(6);
        if (bp_it != st.rules.end() && bp_it->second.present && !bp_it->second.undef &&
            !bp_it->second.same)
            rdr.read(cfa + static_cast<uint64_t>(bp_it->second.offset), &caller_fp, 8);

        frame_t f;
        f.ret_addr = caller_rip;
        f.frame_ptr = caller_fp;
        out.push_back(f);

        pc = caller_rip;
        sp = cfa;
        fp = caller_fp;
    }
    return out.size() > 1;
}

} // namespace slop::core::debugger::unwind
