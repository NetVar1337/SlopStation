// app/src/store/dump.ts
// raw dumps of the live target to disk: a span (memory.dump), every readable
// region (memory.dump_regions) or a Windows minidump (target.minidump). One
// note line reports the last result in the memory view

import { create } from "zustand";
import { t } from "@/i18n";
import { call, errorText } from "@/lib/rpc";

/** Dumps stream large files; the engine caps them at 4 GiB. */
const kDumpTimeoutMs = 900_000;

type DumpStore = {
  busy: boolean;
  note: string | null;
  error: string | null;
  dumpSpan: (addr: number, len: number, path: string) => Promise<void>;
  dumpRegions: (dir: string) => Promise<void>;
  minidump: (path: string) => Promise<void>;
};

export const useDump = create<DumpStore>((set) => {
  const run = async (fn: () => Promise<string>): Promise<void> => {
    set({ busy: true, error: null, note: null });
    try {
      set({ note: await fn() });
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: false });
    }
  };

  return {
    busy: false,
    note: null,
    error: null,

    dumpSpan: (addr, len, path) =>
      run(async () => {
        const r = await call<{ path: string; bytes_written: number; unreadable_bytes?: number }>(
          "memory",
          "dump",
          { addr, len, path },
          { timeoutMs: kDumpTimeoutMs },
        );
        return t("livemem.dump.spanDone", {
          bytes: r.bytes_written.toLocaleString(),
          unreadable: (r.unreadable_bytes ?? 0).toLocaleString(),
          path: r.path,
        });
      }),

    dumpRegions: (dir) =>
      run(async () => {
        const r = await call<{ dir: string; regions: number; bytes_written: number }>(
          "memory",
          "dump_regions",
          { dir },
          { timeoutMs: kDumpTimeoutMs },
        );
        return t("livemem.dump.regionsDone", {
          regions: r.regions,
          bytes: r.bytes_written.toLocaleString(),
          dir: r.dir,
        });
      }),

    minidump: (path) =>
      run(async () => {
        const r = await call<{ path: string; bytes_written: number }>(
          "target",
          "minidump",
          { path, full: true },
          { timeoutMs: kDumpTimeoutMs },
        );
        return t("livemem.dump.minidumpDone", {
          bytes: r.bytes_written.toLocaleString(),
          path: r.path,
        });
      }),
  };
});
