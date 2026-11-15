// app/src/store/dumpers.ts
// Engine-metadata dumpers (re.ue_dump / re.il2cpp_dump / re.source_dump) and
// the offset-manifest helpers (memory.offsets_build / offsets_diff). These all
// write host files and return counts, so the store keeps the last reply plus a
// flat row list the panel renders

import { create } from "zustand";
import { call, errorText } from "@/lib/rpc";

export const kDumpers = ["ue_dump", "il2cpp_dump", "source_dump"] as const;
export type Dumper = (typeof kDumpers)[number];

export const kDumperLabels: Record<Dumper, string> = {
  ue_dump: "Unreal Engine 4/5",
  il2cpp_dump: "Unity IL2CPP",
  source_dump: "Source engine",
};

export type DumpRow = { cells: string[] };

export type DumperResult = {
  dumper: Dumper;
  summary: string;
  rows: DumpRow[];
  files: string[];
  warnings: string[];
  raw: unknown;
};

type DumpersState = {
  busy: boolean;
  error?: string;
  result?: DumperResult;
  /** run one dumper; `params` is passed straight through to the tool */
  run: (dumper: Dumper, params: Record<string, unknown>) => Promise<void>;
  /** build an offsets manifest from named addresses */
  buildOffsets: (params: Record<string, unknown>) => Promise<void>;
  /** diff two manifests / netvar dumps */
  diffOffsets: (oldPath: string, newPath: string) => Promise<void>;
  clear: () => void;
};

type Reply = Record<string, unknown>;

const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string =>
  typeof v === "string" ? v : v === null || v === undefined ? "" : String(v);

/** Flatten a dumper reply into the counters the panel shows. */
function summarise(dumper: Dumper, r: Reply): DumperResult {
  const files = asArray(r.out_files).map(str);
  const warnings = asArray(r.warnings).map(str);
  const rows: DumpRow[] = [];

  if (dumper === "source_dump") {
    rows.push({ cells: ["ClientClass head", str(r.head)] });
    rows.push({ cells: ["Classes", str(r.classes)] });
    rows.push({ cells: ["RecvTables", str(r.tables)] });
    rows.push({ cells: ["Props", str(r.props)] });
    rows.push({ cells: ["Netvars", str(r.netvars)] });
    if (r.datamaps !== undefined) rows.push({ cells: ["DataMaps", str(r.datamaps)] });
    if (r.datamap_fields !== undefined)
      rows.push({ cells: ["DataMap fields", str(r.datamap_fields)] });
  } else if (dumper === "ue_dump") {
    rows.push({ cells: ["Version", str(r.version)] });
    rows.push({ cells: ["GNames", str(r.gnames)] });
    rows.push({ cells: ["GObjects", str(r.gobjects)] });
    rows.push({ cells: ["Names", str(r.names)] });
    rows.push({ cells: ["Objects", str(r.objects)] });
    rows.push({ cells: ["Classes", str(r.classes)] });
    rows.push({ cells: ["Structs", str(r.structs)] });
    rows.push({ cells: ["Enums", str(r.enums)] });
    rows.push({ cells: ["Functions", str(r.functions)] });
  } else {
    rows.push({ cells: ["Version", str(r.version)] });
    rows.push({ cells: ["Images", str(r.images)] });
    rows.push({ cells: ["Types", str(r.types)] });
    rows.push({ cells: ["Methods", str(r.methods)] });
    rows.push({ cells: ["Fields", str(r.fields)] });
    rows.push({ cells: ["Methods with address", str(r.methods_with_address)] });
  }

  const summary =
    files.length === 0
      ? "no files written"
      : `${files.length} file${files.length === 1 ? "" : "s"} written`;
  return { dumper, summary, rows, files, warnings, raw: r };
}

export const useDumpers = create<DumpersState>((set) => ({
  busy: false,

  async run(dumper, params) {
    set({ busy: true, error: undefined });
    try {
      const r = await call<Reply>("re", dumper, params, { timeoutMs: 600_000 });
      set({ busy: false, result: summarise(dumper, r) });
    } catch (e) {
      set({ busy: false, error: errorText(e) });
    }
  },

  async buildOffsets(params) {
    set({ busy: true, error: undefined });
    try {
      const r = await call<Reply>("memory", "offsets_build", params, { timeoutMs: 600_000 });
      const rows: DumpRow[] = [];
      rows.push({ cells: ["Module", str(r.module)] });
      rows.push({ cells: ["Offsets built", str(r.offsets)] });
      const problems = asArray(r.problems).map(str);
      for (const p of problems) rows.push({ cells: ["problem", p] });
      const files = r.path ? [str(r.path)] : [];
      set({
        busy: false,
        result: {
          dumper: "source_dump",
          summary: `manifest: ${str(r.offsets)} offset(s)${problems.length ? `, ${problems.length} problem(s)` : ""}`,
          rows,
          files,
          warnings: problems,
          raw: r,
        },
      });
    } catch (e) {
      set({ busy: false, error: errorText(e) });
    }
  },

  async diffOffsets(oldPath, newPath) {
    set({ busy: true, error: undefined });
    try {
      const r = await call<Reply>("memory", "offsets_diff", { old: oldPath, new: newPath });
      const rows: DumpRow[] = [];
      rows.push({ cells: ["Verdict", str(r.verdict)] });
      rows.push({ cells: ["Stable", str(r.stable_count)] });
      rows.push({ cells: ["Moved", str(r.moved_count)] });
      rows.push({ cells: ["Missing", str(r.missing_count)] });
      rows.push({ cells: ["Added", str(r.added_count)] });
      for (const m of asArray(r.moved)) {
        const o = m as Reply;
        rows.push({
          cells: ["moved", str(o.name), str(o.old), str(o.new), str(o.delta)],
        });
      }
      for (const m of asArray(r.missing)) rows.push({ cells: ["missing", str(m)] });
      set({
        busy: false,
        result: {
          dumper: "source_dump",
          summary: `diff: ${str(r.verdict)}`,
          rows,
          files: [],
          warnings: [],
          raw: r,
        },
      });
    } catch (e) {
      set({ busy: false, error: errorText(e) });
    }
  },

  clear() {
    set({ result: undefined, error: undefined });
  },
}));
