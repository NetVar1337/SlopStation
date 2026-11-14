// app/src/store/scanner.ts
// scanner parameters and the displayed page of hits, the result set itself
// lives in the engine and is paged with memory.scan_results

import { create } from "zustand";
import { t, type Key } from "@/i18n";
import { parseScanValue, type ParseError } from "@/lib/livemem";
import { call, errorText } from "@/lib/rpc";

export type Hit = {
  addr: number;
  bits: number;
  formatted: string;
  type: string;
};

/** Rows the engine pages with; scan_results caps limit at 10000. */
export const kPageSize = 1000;

/** Reason a typed value was refused, in words. */
export const kParseErrorKeys: Record<ParseError, Key> = {
  empty: "livemem.parse.empty",
  syntax: "livemem.parse.syntax",
  float_for_int: "livemem.parse.floatForInt",
  negative_unsigned: "livemem.parse.negativeUnsigned",
  range: "livemem.parse.range",
};

type RawHit = {
  addr?: number;
  address?: number;
  bits?: number;
  value?: number | string;
  formatted?: string;
  type?: string;
};

type Page = { hits?: RawHit[]; results?: RawHit[]; total?: number; next_offset?: number | null };

/** scan/rescan rows are {addr, formatted, type}; scan_results may name them {address, value}. */
function normalizeHits(page: Page, width: string): Hit[] {
  return (page.hits ?? page.results ?? []).map((r) => ({
    addr: r.addr ?? r.address ?? 0,
    bits: r.bits ?? (typeof r.value === "number" ? r.value : 0),
    formatted: r.formatted ?? String(r.value ?? ""),
    type: r.type ?? width,
  }));
}

export type ScanState = {
  active: boolean;
  pid: number;
  total: number;
  width: string;
  kind: string;
};

export const kWidths = [
  "i8",
  "u8",
  "i16",
  "u16",
  "i32",
  "u32",
  "i64",
  "u64",
  "f32",
  "f64",
  "all",
] as const;

/** First pass can only seed; the comparison kinds need a previous result set. */
export const kFirstKinds = ["exact", "unknown"] as const;
export const kNextKinds = [
  "exact",
  "between",
  "bigger",
  "smaller",
  "increased",
  "increased_by",
  "decreased",
  "decreased_by",
  "changed",
  "unchanged",
  "changed_by_more_than",
  "changed_by_less_than",
] as const;

/** Kinds that compare against previous values only; the engine refuses a value for none. */
const kNoValueKinds: Record<string, true> = {
  unknown: true,
  increased: true,
  decreased: true,
  changed: true,
  unchanged: true,
};
export const kindNeedsValue = (kind: string): boolean => kNoValueKinds[kind] !== true;

type ScannerStore = {
  width: string;
  kind: string;
  value: string;
  value2: string;
  hits: Hit[];
  total: number;
  /** Index of hits[0] in the engine's result set. */
  offset: number;
  hasState: boolean;
  busy: boolean;
  error: string | null;

  set: (patch: Partial<Pick<ScannerStore, "width" | "kind" | "value" | "value2">>) => void;
  refreshState: () => Promise<void>;
  scan: (rescan: boolean) => Promise<void>;
  /** Show the page of the current result set starting at `offset`. */
  page: (offset: number) => Promise<void>;
  /** Write the engine's full result set (not just this page) as CSV. */
  exportCsv: (path: string) => Promise<boolean>;
  reset: () => Promise<void>;
};

export const useScanner = create<ScannerStore>((set, get) => ({
  width: "u32",
  kind: "exact",
  value: "",
  value2: "",
  hits: [],
  total: 0,
  offset: 0,
  hasState: false,
  busy: false,
  error: null,

  set: (patch) => set(patch),

  refreshState: async () => {
    let st: ScanState;
    try {
      st = await call<ScanState>("memory", "scan_state");
    } catch {
      set({ hasState: false });
      return;
    }
    set({ hasState: st.active === true, total: st.total ?? 0 });
    // a scan an agent ran over mcp shows up here on first open
    if (st.active === true && (st.total ?? 0) > 0 && get().hits.length === 0) await get().page(0);
  },

  scan: async (rescan) => {
    const { width, value, value2 } = get();
    // the panel shows the list's first kind when the stored one is not offered
    // (a comparison kind left over from a reset, `unknown` after the first pass)
    const offered: readonly string[] = rescan ? kNextKinds : kFirstKinds;
    const kind = offered.includes(get().kind) ? get().kind : offered[0];
    const params: Record<string, unknown> = {
      width,
      kind,
      max_results: 100000,
      // limit defaults to 100 engine-side; the rest is paged with scan_results
      limit: kPageSize,
      offset: 0,
    };
    // The value-less kinds compare against the previous pass. Text keeps float
    // accuracy; the parse catches what the width cannot hold
    const comparands: [string, string][] = [["value", value]];
    if (kind === "between") comparands.push(["value2", value2]);
    if (kindNeedsValue(kind))
      for (const [name, text] of comparands) {
        const parsed = parseScanValue(text, width);
        if (!parsed.ok) {
          set({ error: t(kParseErrorKeys[parsed.error], { value: text, width }) });
          return;
        }
        params[name] = parsed.value;
      }
    set({ busy: true, error: null });
    try {
      const res = await call<Page>(
        "memory",
        rescan ? "rescan" : "scan",
        params,
        // a full first pass over a large process takes a while; it still ends
        { timeoutMs: 300_000 },
      );
      set({ hits: normalizeHits(res, width), total: res.total ?? 0, offset: 0, hasState: true });
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: false });
    }
  },

  page: async (offset) => {
    set({ busy: true });
    try {
      const res = await call<Page & { offset?: number }>("memory", "scan_results", {
        offset,
        limit: kPageSize,
      });
      set({
        hits: normalizeHits(res, get().width),
        total: res.total ?? get().total,
        offset: res.offset ?? offset,
        error: null,
      });
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: false });
    }
  },

  reset: async () => {
    await call("memory", "scan_reset").catch(() => undefined);
    set({ hits: [], total: 0, offset: 0, hasState: false, error: null });
  },

  exportCsv: async (path) => {
    try {
      await call("memory", "scan_export", { path });
      set({ error: null });
      return true;
    } catch (e) {
      set({ error: errorText(e) });
      return false;
    }
  },
}));
