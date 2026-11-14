// app/src/store/access.ts
// "find out what writes/accesses this address": hardware-watchpoint sessions
// the engine keeps running (debugger.access_*), on local Windows targets and
// consoles alike. The view polls the selected session while it runs

import { create } from "zustand";
import { call, errorText } from "@/lib/rpc";

export type AccessKind = "write" | "access" | "exec";
export const kAccessKinds: readonly AccessKind[] = ["write", "access", "exec"];
export const kAccessLens = [1, 2, 4, 8] as const;

export type AccessSite = {
  rip: number;
  rip_hex?: string;
  rip_modoff?: string;
  count: number;
  first_ms?: number;
  last_ms?: number;
  disasm?: string;
  regs?: Record<string, number>;
};

export type AccessStatus = {
  id: number;
  running: boolean;
  hits: number;
  elapsed_ms: number;
  sites: AccessSite[];
};

export type AccessSession = {
  id: number;
  addr: number;
  len: number;
  kind: AccessKind;
  running: boolean;
  hits: number;
};

type AccessStore = {
  sessions: AccessSession[];
  selected: number | null;
  status: AccessStatus | null;
  error: string | null;
  busy: boolean;
  list: () => Promise<void>;
  start: (addr: number, len: number, kind: AccessKind) => Promise<void>;
  /** Refresh the selected session's site table. */
  poll: () => Promise<void>;
  stop: (id: number) => Promise<void>;
  select: (id: number) => Promise<void>;
};

export const useAccess = create<AccessStore>((set, get) => ({
  sessions: [],
  selected: null,
  status: null,
  error: null,
  busy: false,

  list: async () => {
    try {
      const res = await call<{ sessions?: AccessSession[] }>("debugger", "access_list");
      set({ sessions: res.sessions ?? [], error: null });
    } catch (e) {
      set({ error: errorText(e) });
    }
  },

  start: async (addr, len, kind) => {
    set({ busy: true });
    try {
      const res = await call<{ id: number }>("debugger", "access_start", { addr, len, kind });
      set({ selected: res.id, status: null, error: null });
      await get().list();
      await get().poll();
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: false });
    }
  },

  poll: async () => {
    const id = get().selected;
    if (id === null) return;
    try {
      const status = await call<AccessStatus>("debugger", "access_status", { id });
      if (get().selected !== id) return;
      set({ status, error: null });
      // a session that just ended (duration/max_hits) changes the list too
      if (!status.running && get().sessions.some((s) => s.id === id && s.running))
        await get().list();
    } catch (e) {
      set({ error: errorText(e) });
    }
  },

  stop: async (id) => {
    try {
      const status = await call<AccessStatus>("debugger", "access_stop", { id });
      if (get().selected === id) set({ status });
      set({ error: null });
      await get().list();
    } catch (e) {
      set({ error: errorText(e) });
    }
  },

  select: async (id) => {
    set({ selected: id, status: null });
    await get().poll();
  },
}));
