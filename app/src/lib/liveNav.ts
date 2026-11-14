// app/src/lib/liveNav.ts
// cross-links between the live-memory views: a scanner hit, watch row or hex
// caret opens the hex view or starts a "what writes/accesses this" session

import { useAccess, type AccessKind } from "@/store/access";
import { useMemory } from "@/store/memory";
import { useUi } from "@/store/ui";

export function showInMemory(addr: number): void {
  useUi.getState().setWorkspaceTab("memory");
  useMemory.getState().goto(addr);
}

/** Arm a watchpoint session on `addr` and show its live site table. */
export function traceAccess(addr: number, len: number, kind: AccessKind): void {
  useUi.getState().setWorkspaceTab("debugger");
  void useAccess.getState().start(addr, len, kind);
}
