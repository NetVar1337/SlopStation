// app/src/store/pointers.ts
// pointer scan over the live target (memory.pointerscan) and the Cheat Engine
// follow-up: restart, find the value again, verify the chains against the new
// address (memory.pointerscan_verify keeps the survivors engine-side)

import { create } from "zustand";
import type { PointerChain } from "@/lib/livemem";
import { call, errorText } from "@/lib/rpc";

/** Chains listed per call; the engine caps the listing at 1000. */
const kListLimit = 1000;

export type PointerScanParams = {
  target: number;
  depth: number;
  maxOffset: number;
  /** Only roots inside a loaded module (static_roots). */
  staticRoots: boolean;
};

type PointerStore = {
  chains: PointerChain[];
  total: number;
  /** Address the listed chains land on. */
  target: number | null;
  truncated: boolean;
  /** Last verify summary, null before the first. */
  verified: { kept: number; checked: number } | null;
  busy: boolean;
  error: string | null;
  scan: (p: PointerScanParams) => Promise<void>;
  /** Re-resolve the last list; `target` is the value's new address after a restart. */
  verify: (target: number | null) => Promise<void>;
};

export const usePointers = create<PointerStore>((set) => ({
  chains: [],
  total: 0,
  target: null,
  truncated: false,
  verified: null,
  busy: false,
  error: null,

  scan: async ({ target, depth, maxOffset, staticRoots }) => {
    set({ busy: true, error: null, verified: null });
    try {
      const res = await call<{ chains?: PointerChain[]; total?: number; truncated?: boolean }>(
        "memory",
        "pointerscan",
        {
          target,
          depth,
          // forward offsets only, as Cheat Engine's default
          min_offset: 0,
          max_offset: maxOffset,
          static_roots: staticRoots,
          limit: kListLimit,
        },
        { timeoutMs: 600_000 },
      );
      set({
        chains: res.chains ?? [],
        total: res.total ?? 0,
        truncated: res.truncated === true,
        target,
      });
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: false });
    }
  },

  verify: async (target) => {
    set({ busy: true, error: null });
    try {
      const res = await call<{
        chains?: PointerChain[];
        kept?: number;
        checked?: number;
        target?: number;
      }>(
        "memory",
        "pointerscan_verify",
        { ...(target !== null ? { target } : {}), limit: kListLimit },
        { timeoutMs: 600_000 },
      );
      set((s) => ({
        chains: res.chains ?? [],
        total: res.kept ?? 0,
        target: res.target ?? target ?? s.target,
        verified: { kept: res.kept ?? 0, checked: res.checked ?? 0 },
      }));
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: false });
    }
  },
}));
