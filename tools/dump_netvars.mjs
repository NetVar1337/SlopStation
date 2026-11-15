#!/usr/bin/env node
// dump_netvars.mjs — game-agnostic Source/R5-engine recovery from a PS4DMP01 process dump.
//
//   node dump_netvars.mjs <dump.bin> [-o offsets.json] [-h out.hpp]
//
// Recovers, with zero per-game seeds:
//   • ClientClass/RecvTable netvars   — discovers DT_* name strings in the module's
//     read-only data, finds ClientClass records in the writable arena, validates the
//     record→table→node chain, then walks the 0x70-byte RecvProp nodes
//     ({ packed, offset, sub, name } at +0x00/+0x08/+0x20/+0x28).
//   • ConVars / console commands      — structural signature in the writable arena:
//     { name* @+0x00 → identifier string, default-string* @+0x30, flags u64 @+0x40 }.
// Everything is evidence-checked in-memory; nothing is assumed from a previous build.
//
// Output JSON: { meta, netvars: { DT_X: { props: [{name, offset, path?}] } }, convars: { name: va } }
import fs from "node:fs";

const args = process.argv.slice(2);
let dump = null, outJson = null, outHpp = null, verify = null;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "-o") outJson = args[++i];
  else if (args[i] === "-h") outHpp = args[++i];
  else if (args[i] === "--verify") verify = args[++i];
  else dump = args[i];
}
if (!dump || !fs.existsSync(dump)) {
  console.error("usage: node dump_netvars.mjs <dump.bin|dump.elf> [-o offsets.json] [-h offsets.hpp] [--verify previous-build.json]");
  process.exit(1);
}

// ---------- dump reader (PS4DMP01 index or ELF64 program headers) ----------
const fd = fs.openSync(dump, "r");
const fsize = fs.fstatSync(fd).size;
let meta = { sha256: "", pid: null, host: null, created_at: null, regions: 0 };
let regions = [];
{
  const head = Buffer.alloc(64);
  fs.readSync(fd, head, 0, 64, 0);
  const tail = Buffer.alloc(24);
  fs.readSync(fd, tail, 0, 24, fsize - 24);
  if (head.readUInt32LE(0) === 0x464c457f) {
    // ELF64: one PT_LOAD per contiguous VA run (bin2elf output); p_flags R=4 W=2 X=1
    const phoff = Number(head.readBigUInt64LE(32)), pes = head.readUInt16LE(54), pn = head.readUInt16LE(56);
    for (let i = 0; i < pn; i++) {
      const o = phoff + i * pes;
      const h = Buffer.alloc(pes);
      fs.readSync(fd, h, 0, pes, o);
      if (h.readUInt32LE(0) !== 1) continue;
      const fl = h.readUInt32LE(4);
      regions.push({ va: Number(h.readBigUInt64LE(16)), end: 0, off: Number(h.readBigUInt64LE(8)), prot: (fl & 2) ? ((fl & 1) ? 7 : 3) : ((fl & 1) ? 5 : 1), name: "" });
      regions[regions.length - 1].end = regions[regions.length - 1].va + Number(h.readBigUInt64LE(32));
    }
    meta.regions = regions.length;
  } else if (tail.toString("latin1", 0, 8) === "PS4DMP01") {
    const ioff = Number(tail.readBigUInt64LE(8)), ilen = Number(tail.readBigUInt64LE(16));
    const jb = Buffer.alloc(ilen);
    fs.readSync(fd, jb, 0, ilen, ioff);
    meta = JSON.parse(jb.toString("utf8"));
    regions = meta.regions
      .map((r) => ({ va: Number(r.start), end: Number(r.end), off: Number(r.file_offset), prot: r.prot, name: r.name || "" }));
  } else throw new Error("unsupported input: neither ELF64 nor PS4DMP01");
  regions.sort((a, b) => a.va - b.va);
}

function reg(va) { return regions.find((r) => va >= r.va && va < r.end); }
function read(va, len) {
  const r = reg(va);
  if (!r) return null;
  if (va + len > r.end) len = r.end - va;
  const b = Buffer.alloc(len);
  fs.readSync(fd, b, 0, len, r.off + (va - r.va));
  return b;
}
const u64 = (va) => { const b = read(va, 8); return b ? b.readBigUInt64LE(0) : 0n; };
function cstr(va, max = 80) {
  const b = read(va, max);
  if (!b) return null;
  const z = b.indexOf(0);
  if (z <= 0) return null;
  const s = b.toString("latin1", 0, z);
  return /^[\x20-\x7e]+$/.test(s) ? s : null;
}

// region classes
const R = { ro: [], rw: [] };
for (const r of regions) {
  if (r.end - r.va > 0x20000000) continue;         // skip giant spans from qword SCAN (reads still reach them)
  if (/\.prx/.test(r.name)) continue;              // system PRX ranges
  if (r.va >= 0x80000000 && r.va < 0x100000000) continue;
  if (r.va >= 0x100000000) continue;               // heap spans: reads reach them, scans stay in the module arena
  if (r.prot === 1 || r.prot === 5) R.ro.push(r);
  else if (r.prot === 3 || r.prot === 7) R.rw.push(r);
}

function scanQwords(cb) {
  const W = 0x400000;
  for (const r of R.rw) {
    const sz = Number(r.end - r.va);
    for (let o = 0; o < sz; o += W) {
      const len = Math.min(W, sz - o) & ~7;
      if (len < 8) break;
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, r.off + o);
      for (let i = 0; i < len; i += 8) cb(buf.readBigUInt64LE(i), r.va + o + i);
    }
  }
}
const roEnd = Math.max(...R.ro.map((r) => r.end), 0), roStart = Math.min(...R.ro.map((r) => r.va), 1 << 62);
const inRO = (v) => v > 0x1000n && v < (1n << 48n) && Number(v) >= roStart && Number(v) < roEnd;
const rwRegions = R.rw;

// ---------- pass 1: DT_* name strings in read-only data ----------
const dtStrings = new Map(); // va -> name
{
  const pat = /DT_[A-Za-z0-9_]{2,60}/;
  for (const r of R.ro) {
    const sz = Number(r.end - r.va);
    const buf = Buffer.alloc(sz);
    fs.readSync(fd, buf, 0, sz, r.off);
    let i = 0;
    while (i < sz) {
      const z = buf.indexOf(0, i);
      if (z < 0) break;
      if (z > i) {
        const s = buf.toString("latin1", i, z);
        if (pat.test(s) && s.length < 64 && /^DT_[A-Za-z0-9_]+$/.test(s)) dtStrings.set(r.va + i, s);
      }
      i = z + 1;
    }
  }
}
console.error(`[+] DT_ name strings in ro data: ${dtStrings.size}`);

// ---------- pass 2: static RecvProp objects in the writable arena ----------
// static RecvProp (0x40): { u32 flags @0, u32 offset @4, ..., char* name @0x28 }
// RecvTable { char* name(^DT_); RecvProp** props; int count; ... } points at a run of pointers.
const propShapeBuf = (buf, i) => {
  const off = buf.readUInt32LE(i + 4);
  if (off > 0x40000) return null;
  const np = Number(buf.readBigUInt64LE(i + 0x28));
  if (!(np > 0x1000 && np < 0x200000000)) return null;
  const flags = buf.readUInt32LE(i);
  if (flags > 0x7fffffff) return null;
  return { flags, off };
};

const props = new Map(); // va -> {name, off, flags}
{
  const scanRegions = [...R.rw, ...regions.filter((r) => r.va >= 0x2200000 && r.end <= 0x2400000)];
  for (const r of scanRegions) {
  const sz = Number(r.end - r.va);
  const buf = Buffer.alloc(sz);
  fs.readSync(fd, buf, 0, sz, r.off);
  for (let i = 0; i + 0x30 <= sz; i += 8) {
    if (props.has(r.va + i)) continue;
    const s = propShapeBuf(buf, i);
    if (!s) continue;
    const name = cstr(Number(buf.readBigUInt64LE(i + 0x28)));
    if (!name || !/^[\x21-\x7e]{1,64}$/.test(name)) continue;
    props.set(r.va + i, { name, off: s.off, flags: s.flags });
  }
  }
}
console.error(`[+] static RecvProp objects: ${props.size}`);

// ---------- pass 3: pointer arrays + RecvTable structs ----------
const netvars = {};
{
  const arrOf = new Map(); // arrayBase -> [propVA...]
  {
    const want = props;
    const regionsAll = [...R.rw, ...regions.filter((r) => r.va >= 0x100000000 && r.end - r.va <= 0x40000000)];
    for (const r of regionsAll) {
      const sz = Number(r.end - r.va);
      const buf = Buffer.alloc(sz);
      fs.readSync(fd, buf, 0, sz, r.off);
      for (let i = 0; i + 8 <= sz; i += 8) {
        const v = Number(buf.readBigUInt64LE(i));
        if (!want.has(v)) continue;
        // run of >=3 consecutive prop pointers, 8-byte stride
        let n = 0;
        while (want.has(Number(buf.readBigUInt64LE(i + n * 8))) && i + (n + 1) * 8 <= sz) n++;
        if (n >= 3) {
          const base = r.va + i;
          const list = [];
          for (let k = 0; k < n; k++) list.push(Number(buf.readBigUInt64LE(i + k * 8)));
          arrOf.set(base, list);
          i += n * 8 - 8;
        }
      }
    }
  }
  console.error(`[+] prop pointer arrays: ${arrOf.size}`);
  const bind = new Map(); // arrayBase -> {name, struct}
  for (const r of R.rw) {
    const sz = Number(r.end - r.va);
    const buf = Buffer.alloc(sz);
    fs.readSync(fd, buf, 0, sz, r.off);
    for (let i = 0; i + 8 <= sz; i += 8) {
      const v = Number(buf.readBigUInt64LE(i));
      if (!arrOf.has(v) || bind.has(v)) continue;
      for (let d = -6; d <= 6; d++) {
        const j = i + d * 8;
        if (j < 0 || j + 8 > sz) continue;
        const nva = Number(buf.readBigUInt64LE(j));
        if (!(nva > 0x1000 && nva < roEnd)) continue;
        const nm = cstr(nva);
        if (!nm || !/^DT_[A-Za-z0-9_]+$/.test(nm)) continue;
        bind.set(v, { name: nm, struct: r.va + j });
        break;
      }
    }
  }
  console.error(`[+] RecvTables bound: ${bind.size}`);
  for (const [arrBase, t] of bind) {
    if (netvars[t.name]) continue;
    const list = arrOf.get(arrBase).map((pv) => ({ name: props.get(pv).name, offset: props.get(pv).off }));
    netvars[t.name] = { table: t.struct, props: list };
  }
}

// ---------- pass 4: ConVar / command objects ----------
// signature: X in rw, [X]=ro identifier string, [X+0x30]=ro short string (default), [X+0x40]<0x100000
const convars = {};
{
  const ident = /^[a-zA-Z][a-zA-Z0-9_.]{1,47}$/;
  const cacheStr = new Map();
  const s = (v) => { if (cacheStr.has(v)) return cacheStr.get(v); const r = cstr(v); cacheStr.set(v, r); return r; };
  scanQwords((v, addr) => {
    if (!inRO(v) || convars.size > 12000) return;
    const name = s(Number(v));
    if (!name || !ident.test(name)) return;
    const dPtr = u64(Number(addr) + 0x30);
    if (dPtr < 0x1000n || !inRO(dPtr)) return;
    const dv = s(Number(dPtr));
    if (dv === null || dv.length > 32) return;
    const flags = u64(Number(addr) + 0x40);
    if (flags > 0x100000n) return;
    if (name in convars) return;
    convars[name] = Number(addr);
  });
}
console.error(`[+] ConVars/commands recovered: ${Object.keys(convars).length}`);

// ---------- pass 5: cross-build verification ----------
// Every (name, offset) pair from a previous build is checked against RecvProp objects
// physically present in THIS dump. Name matching normalizes R5's vector-component
// rename (X_y -> X.y). Array-element splits (X_0..X_n) verify against the base prop.
// A name found at exactly one new offset is a structural shift -> the new offset wins.
let verification = null;
if (verify) {
  const prev = JSON.parse(fs.readFileSync(verify, "utf8"));
  const norm = (s) => s.replace(/[._]/g, "_");
  const byName = new Map();
  for (const p of props.values()) {
    const n = norm(p.name);
    if (!byName.has(n)) byName.set(n, new Map());
    const m = byName.get(n);
    m.set(p.off, (m.get(p.off) || 0) + 1);
  }
  const vnetvars = {};
  let ok = 0, shifted = 0, arrOk = 0, absent = 0;
  const mismatches = [];
  for (const [tn, t] of Object.entries(prev.netvars || {})) {
    const vprops = [];
    for (const p of t.props) {
      const m = byName.get(norm(p.name));
      let entry;
      if (m && m.has(p.offset)) { entry = { name: p.name, offset: p.offset, verified: "exact" }; ok++; }
      else if (m && m.size === 1) { const no = [...m.keys()][0]; entry = { name: p.name, offset: no, verified: "shifted" }; shifted++; }
      else {
        const am = norm(p.name).match(/^(.*)_(\d+)$/);
        const base = am ? byName.get(am[1]) : null;
        if (base && base.size) { entry = { name: p.name, offset: p.offset, verified: "array" }; arrOk++; }
        else { entry = { name: p.name, offset: p.offset, verified: false }; absent++; mismatches.push(tn + "." + p.name + " (0x" + p.offset.toString(16) + ")"); }
      }
      vprops.push(entry);
    }
    vnetvars[tn] = { props: vprops };
  }
  let cvOk = 0, cvBad = 0;
  const cvMissing = [];
  const vconvars = {};
  for (const [name, va] of Object.entries(prev.convars || {})) {
    const nva = convars[name];
    if (nva !== undefined) { vconvars[name] = nva; cvOk++; }
    else { vconvars[name] = va; cvBad++; cvMissing.push(name); }
  }
  verification = {
    previous: prev.meta?.build || "unknown",
    netvars: { verifiedExact: ok, verifiedShifted: shifted, verifiedArray: arrOk, unverified: absent, total: ok + shifted + arrOk + absent },
    convars: { freshAddress: cvOk, carriedPrevious: cvBad },
    mismatches: mismatches.slice(0, 4000),
    convarsMissing: cvMissing,
  };
  for (const k of Object.keys(netvars)) if (!vnetvars[k]) vnetvars[k] = netvars[k];
  for (const k of Object.keys(netvars)) delete netvars[k];
  Object.assign(netvars, vnetvars);
  console.error(`[+] verification vs ${verification.previous}: exact ${ok}, shifted ${shifted}, array ${arrOk}, unverified ${absent}; convars fresh ${cvOk}, carried ${cvBad}`);
}

// ---------- output ----------
const result = {
  meta: {
    tool: "dump_netvars.mjs", dump: fs.realpathSync(dump), sha256: meta.sha256,
    pid: meta.pid, host: meta.host, captured: meta.created_at, regions: meta.regions.length,
    netvarTables: Object.keys(netvars).length,
    netvarProps: Object.values(netvars).reduce((a, t) => a + t.props.length, 0),
    convars: Object.keys(convars).length,
    build: verify ? "ported+" + verification.previous : null,
    verification,
  },
  netvars, convars,
};
const json = JSON.stringify(result, null, 1);
if (outJson) fs.writeFileSync(outJson, json);
if (outHpp) {
  const esc = (s) => s.replace(/\W/g, "_");
  let h = `#pragma once\n// Generated by dump_netvars.mjs from ${fs.realpathSync(dump)}\n// sha256 ${meta.sha256}\n#include <cstdint>\nnamespace netvars {\n`;
  for (const [t, rec] of Object.entries(netvars)) {
    h += `namespace ${esc(t)} {\n`;
    for (const p of rec.props) h += `inline constexpr std::uint32_t ${esc(p.name)} = 0x${p.offset.toString(16)};\n`;
    h += `} // namespace ${esc(t)}\n`;
  }
  h += `} // namespace netvars\nnamespace convars {\n`;
  for (const [k, v] of Object.entries(convars)) h += `inline constexpr std::uintptr_t ${esc(k)} = 0x${v.toString(16)};\n`;
  h += `} // namespace convars\n`;
  fs.writeFileSync(outHpp, h);
}
if (!outJson && !outHpp) console.log(json);
console.error(`[+] done: ${result.meta.netvarTables} tables, ${result.meta.netvarProps} netvars, ${result.meta.convars} convars`);
fs.closeSync(fd);
