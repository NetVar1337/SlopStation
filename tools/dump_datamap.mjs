// weapon-settings.mjs — walk the WeaponSettings script-datamap in a live dump.
// Field record (0x40 stride): { name*@0x00, type*@0x10, offset u32@0x1c, hash u32@0x20 }.
// Anchor: any known field name (default ammo_clip_size). Walks forward+backward.
import fs from "node:fs";
import path from "node:path";
const D = process.argv[2];
const ANCHOR = process.argv[3] || "ammo_clip_size";
const OUT = process.argv[4] || "reports/weapon-settings.json";
const fd = fs.openSync(D, "r");
const head = Buffer.alloc(64); fs.readSync(fd, head, 0, 64, 0);
const phoff = Number(head.readBigUInt64LE(32)), pes = head.readUInt16LE(54), pn = head.readUInt16LE(56);
const regions = [];
for (let i = 0; i < pn; i++) { const o = phoff + i * pes; const h = Buffer.alloc(pes); fs.readSync(fd, h, 0, pes, o);
  if (h.readUInt32LE(0) === 1) { const va = Number(h.readBigUInt64LE(16)), sz = Number(h.readBigUInt64LE(32)); regions.push({ va, end: va + sz, off: Number(h.readBigUInt64LE(8)) }); } }
function read(va, len) { const r = regions.find(r => va >= r.va && va < r.end); if (!r) return null; if (va + len > r.end) len = r.end - va; const b = Buffer.alloc(len); fs.readSync(fd, b, 0, len, r.off + (va - r.va)); return b; }
function cstr(va, max = 64) { const b = read(va, max); if (!b) return null; const z = b.indexOf(0); if (z <= 0) return null; const s = b.toString("latin1", 0, z); return /^[\x20-\x7e]+$/.test(s) ? s : null; }
// locate anchor string, then its field record (name*@+0), then walk
let anchorVA = null;
for (const r of regions) { const sz = r.end - r.va; if (sz > 0x40000000) continue;
  for (let o = 0; o < sz && !anchorVA; o += 0x400000) { const len = Math.min(0x400000, sz - o); if (len < 8) break;
    const buf = Buffer.alloc(len); fs.readSync(fd, buf, 0, len, r.off + o);
    const p = Buffer.from(ANCHOR + "\0"); let i = buf.indexOf(p);
    if (i !== -1 && (i === 0 || buf[i - 1] === 0)) anchorVA = r.va + o + i; } }
if (!anchorVA) { console.error("anchor string not found"); process.exit(1); }
const p8 = Buffer.alloc(8); p8.writeBigUInt64LE(BigInt(anchorVA));
let start = null;
for (const r of regions) { const sz = r.end - r.va; if (sz > 0x40000000) continue;
  for (let o = 0; o < sz && !start; o += 0x400000) { const len = Math.min(0x400000, sz - o) & ~7; if (len < 8) break;
    const buf = Buffer.alloc(len); fs.readSync(fd, buf, 0, len, r.off + o);
    let i = 0; while ((i = buf.indexOf(p8, i)) !== -1) { if ((o + i) % 8 === 0 && i >= 0x20) start = r.va + o + i; i += 8; if (start) break; } } }
if (!start) { console.error("anchor record not found"); process.exit(1); }
const walk = (from, dir) => { const out = [];
  for (let k = 0; k < 6000; k++) { const rec = from + dir * k * 0x40; const b = read(rec, 0x40); if (!b) break;
    const np = Number(b.readBigUInt64LE(0)); if (!(np > 0x1000 && np < 0x2200000)) break;
    const nm = cstr(np); if (!nm || !/^[A-Za-z_][A-Za-z0-9_.]{1,60}$/.test(nm)) break;
    const off = b.readUInt32LE(0x1c); if (off > 0x10000) break;
    out.push({ name: nm, offset: off }); } return out; };
const fwd = walk(start, 1), back = walk(start - 0x40, -1);
const fields = [...back.reverse(), ...fwd];
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify({ dump: D, table: "WeaponSettings", count: fields.length, fields }, null, 1));
console.log(`${fields.length} fields -> ${OUT}`);
fs.closeSync(fd);
