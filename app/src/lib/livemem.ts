// app/src/lib/livemem.ts
// pure helpers for the live-memory views: value text per scan width, typed
// writes, result paging, pointer-chain text and sparkline geometry. No stores
// and no rpc, so they are unit tested on their own

export type ParseError = "empty" | "syntax" | "float_for_int" | "negative_unsigned" | "range";
export type Parsed<T> = { ok: true; value: T } | { ok: false; error: ParseError };

const ok = <T>(value: T): Parsed<T> => ({ ok: true, value });
const fail = <T>(error: ParseError): Parsed<T> => ({ ok: false, error });

const kIntBits: Record<string, number> = {
  i8: 8,
  u8: 8,
  i16: 16,
  u16: 16,
  i32: 32,
  u32: 32,
  i64: 64,
  u64: 64,
};

const kHexRe = /^([+-]?)0x([0-9a-f]+)$/i;
const kDecRe = /^([+-]?)(\d+)$/;
const kFloatRe = /^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?$/i;

/** Integer text (decimal or 0x hex, optional sign) as a bigint, null otherwise. */
function intOf(text: string): bigint | null {
  const h = kHexRe.exec(text);
  if (h !== null) {
    const v = BigInt(`0x${h[2]}`);
    return h[1] === "-" ? -v : v;
  }
  const d = kDecRe.exec(text);
  if (d !== null) {
    // BigInt() keeps "010" decimal; the engine's strtoll(…, 0) would read octal
    const v = BigInt(d[2]);
    return d[1] === "-" ? -v : v;
  }
  return null;
}

/**
 * Normalize a typed value for the engine's parse_value_text(width): integers
 * go out as plain decimal (hex accepted, no octal surprise, signed widths
 * wrap an unsigned spelling to two's complement), floats as dot-decimal text
 * (a German comma is accepted). "all" takes either.
 */
export function parseScanValue(raw: string, width: string): Parsed<string> {
  const text = raw.trim().replace(/[\s_`']/g, "");
  if (text === "") return fail("empty");
  const int = intOf(text);
  if (width === "f32" || width === "f64" || width === "all") {
    if (int !== null) return ok(int.toString());
    const f = text.replace(",", ".");
    if (!kFloatRe.test(f) || !Number.isFinite(Number(f))) return fail("syntax");
    return ok(f);
  }
  const bits = kIntBits[width];
  if (bits === undefined) return fail("syntax");
  if (int === null) return fail(kFloatRe.test(text.replace(",", ".")) ? "float_for_int" : "syntax");
  const signed = width.startsWith("i");
  if (!signed && int < 0n) return fail("negative_unsigned");
  const span = 1n << BigInt(bits);
  const min = signed ? -(span >> 1n) : 0n;
  if (int < min || int >= span) return fail("range");
  // 0xFF for i8 means -1: strtoll would reject 2^63.. for i64 otherwise
  return ok((signed ? BigInt.asIntN(bits, int) : int).toString());
}

/** Kinds the hex view can write at the caret. */
export const kWriteKinds = [
  "u8",
  "u16",
  "u32",
  "u64",
  "i8",
  "i16",
  "i32",
  "i64",
  "f32",
  "f64",
  "string",
  "bytes",
] as const;
export type WriteKind = (typeof kWriteKinds)[number];

/** Encode `raw` as the little-endian bytes a typed write stores. */
export function encodeTyped(kind: WriteKind, raw: string): Parsed<Uint8Array> {
  if (kind === "string") {
    return raw === "" ? fail("empty") : ok(new TextEncoder().encode(raw));
  }
  if (kind === "bytes") {
    const clean = raw.replace(/[\s,]/g, "").replace(/^0x/i, "");
    if (clean === "") return fail("empty");
    if (!/^[0-9a-f]+$/i.test(clean) || clean.length % 2 !== 0) return fail("syntax");
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++)
      out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    return ok(out);
  }
  const parsed = parseScanValue(raw, kind);
  if (!parsed.ok) return parsed;
  if (kind === "f32" || kind === "f64") {
    const out = new Uint8Array(kind === "f32" ? 4 : 8);
    const view = new DataView(out.buffer);
    if (kind === "f32") view.setFloat32(0, Number(parsed.value), true);
    else view.setFloat64(0, Number(parsed.value), true);
    return ok(out);
  }
  const bits = kIntBits[kind];
  let v = BigInt.asUintN(bits, BigInt(parsed.value));
  const out = new Uint8Array(bits / 8);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return ok(out);
}

export type PageInfo = {
  /** 1-based index of the first row shown, 0 when there are none. */
  from: number;
  /** 1-based index of the last row shown. */
  to: number;
  page: number;
  pages: number;
  prevOffset: number | null;
  nextOffset: number | null;
  lastOffset: number;
};

/** Where a page of `count` rows starting at `offset` sits in `total`. */
export function pageInfo(offset: number, count: number, total: number, pageSize: number): PageInfo {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return {
    from: count === 0 ? 0 : offset + 1,
    to: offset + count,
    page: Math.floor(offset / pageSize) + 1,
    pages,
    prevOffset: offset > 0 ? Math.max(0, offset - pageSize) : null,
    nextOffset: offset + count < total ? offset + count : null,
    lastOffset: (pages - 1) * pageSize,
  };
}

/** One row of memory.pointerscan / pointerscan_verify. */
export type PointerChain = {
  /** [root-most holder, …, final holder]. */
  addresses: number[];
  /** offsets[i] is added to the qword read at addresses[i]. */
  offsets: number[];
  base_hex?: string;
  depth?: number;
  module?: string;
  module_offset?: number;
};

const hexU = (v: number): string => v.toString(16).toUpperCase();

/** "+0x10" / "-0x8". */
export function formatOffset(o: number): string {
  return `${o < 0 ? "-" : "+"}0x${hexU(Math.abs(o))}`;
}

/** The chain root: module-relative when the scan found one, absolute otherwise. */
export function chainRoot(c: PointerChain): string {
  if (c.module !== undefined && c.module !== "")
    return `${c.module}+0x${hexU(c.module_offset ?? 0)}`;
  return `0x${hexU(c.addresses[0] ?? 0)}`;
}

/** Cheat Engine reading order: root, then each offset added after a deref. */
export function formatChain(c: PointerChain): string {
  return [chainRoot(c), ...c.offsets.map(formatOffset)].join(" → ");
}

/** SVG polyline points scaling `values` into a w×h box (y grows down). */
export function sparkPoints(values: readonly number[], w: number, h: number): string {
  const vs = values.filter((v) => Number.isFinite(v));
  if (vs.length === 0) return "";
  const lo = Math.min(...vs);
  const hi = Math.max(...vs);
  const step = vs.length > 1 ? w / (vs.length - 1) : 0;
  const y = (v: number) => (hi === lo ? h / 2 : h - ((v - lo) / (hi - lo)) * h);
  const pts = vs.map((v, i) => `${(i * step).toFixed(1)},${y(v).toFixed(1)}`);
  // one sample draws a flat line across instead of a dot nobody sees
  return vs.length === 1 ? `0,${y(vs[0]).toFixed(1)} ${w},${y(vs[0]).toFixed(1)}` : pts.join(" ");
}

/** Watchpoint length for a value width: DR lengths are 1, 2, 4 or 8 ("all" and strings watch 4). */
export function accessLenFor(width: string): 1 | 2 | 4 | 8 {
  const bits = Number.parseInt(width.slice(1), 10);
  return bits === 8 ? 1 : bits === 16 ? 2 : bits === 64 ? 8 : 4;
}
