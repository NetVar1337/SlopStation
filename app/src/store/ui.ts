// app/src/store/ui.ts
// Shell-level UI state more than one component needs: dialogs, which left
// panel the rail selected, the active tabs and the splitter sizes. The layout
// half is persisted so a reload (or the next launch) comes back the same

import { create } from "zustand";
import { kMotionOptions, useMotion, type MotionPref } from "@/store/motion";
import { kThemes, useTheme, type ThemeName } from "@/store/theme";

export type RailView = "targets" | "modules" | "scripts";
export type WorkspaceTab =
  | "disassembly"
  | "decomp"
  | "strings"
  | "memory"
  | "debugger"
  | "pe"
  | "structs"
  | "unpacker"
  | "xray"
  | "patch"
  | "network"
  | "emulate";
export type OutputTab = "output" | "log";

/** Splitter-driven CSS variables and their largest defaults (px), see app.css. */
export const kLayoutVars = {
  "--left-w": 300,
  "--scan-w": 316,
  "--bottom-h": 260,
  "--right-w": 320,
} as const;
export type LayoutVar = keyof typeof kLayoutVars;

/** Below this viewport width the inspector starts closed unless the user pinned it. */
export const kInspectorAutoWidth = 1400;

const clamp = (lo: number, v: number, hi: number) => Math.round(Math.min(hi, Math.max(lo, v)));

/**
 * Default size of a layout var for a viewport: panels shrink with the window
 * so the workspace keeps real width at 1100-1366px. A dragged size wins.
 */
export function defaultLayoutSize(key: LayoutVar, w: number, h: number): number {
  switch (key) {
    case "--left-w":
      return clamp(220, w * 0.2, kLayoutVars[key]);
    case "--scan-w":
      return clamp(250, w * 0.2, kLayoutVars[key]);
    case "--bottom-h":
      return clamp(140, h * 0.27, kLayoutVars[key]);
    case "--right-w":
      return clamp(240, w * 0.18, kLayoutVars[key]);
  }
}

const viewport = () =>
  typeof window === "undefined"
    ? { w: 1680, h: 980 }
    : { w: window.innerWidth, h: window.innerHeight };

type Layout = {
  rail: RailView;
  workspaceTab: WorkspaceTab;
  outputTab: OutputTab;
  /** Effective state; follows the viewport width until `inspectorPinned`. */
  inspectorOpen: boolean;
  /** The user opened or closed the inspector explicitly: auto-collapse stops. */
  inspectorPinned: boolean;
  scannerOpen: boolean;
  sizes: Partial<Record<LayoutVar, number>>;
};

const kStorageKey = "reverse-slop.layout";

const defaultLayout = (): Layout => ({
  rail: "targets",
  workspaceTab: "disassembly",
  outputTab: "output",
  inspectorOpen: viewport().w >= kInspectorAutoWidth,
  inspectorPinned: false,
  scannerOpen: true,
  sizes: {},
});

const kRails: readonly RailView[] = ["targets", "modules", "scripts"];
const kWorkspaceTabs: readonly WorkspaceTab[] = [
  "disassembly",
  "decomp",
  "strings",
  "memory",
  "debugger",
  "pe",
  "structs",
  "unpacker",
  "xray",
  "patch",
  "network",
  "emulate",
];

/** Parse persisted layout defensively: a hand-edited or stale blob must not break boot. */
export function parseLayout(raw: string | null): Layout {
  const def = defaultLayout();
  if (raw === null) return def;
  try {
    const v = JSON.parse(raw) as Partial<Layout>;
    // Older blobs always wrote inspectorOpen=true; only an explicit close counts as a choice
    const pinned = v.inspectorPinned === true || v.inspectorOpen === false;
    return {
      rail: kRails.includes(v.rail as RailView) ? (v.rail as RailView) : def.rail,
      workspaceTab: kWorkspaceTabs.includes(v.workspaceTab as WorkspaceTab)
        ? (v.workspaceTab as WorkspaceTab)
        : def.workspaceTab,
      outputTab: v.outputTab === "log" ? "log" : "output",
      inspectorOpen: pinned ? v.inspectorOpen !== false : def.inspectorOpen,
      inspectorPinned: pinned,
      scannerOpen: v.scannerOpen !== false,
      sizes: parseSizes(v.sizes),
    };
  } catch {
    return def;
  }
}

/** Splitter sizes that survive a round trip: finite, positive, sane pixels. */
function parseSizes(raw: unknown): Partial<Record<LayoutVar, number>> {
  const sizes: Partial<Record<LayoutVar, number>> = {};
  if (typeof raw !== "object" || raw === null) return sizes;
  for (const key of Object.keys(kLayoutVars) as LayoutVar[]) {
    const n = (raw as Record<string, unknown>)[key];
    if (typeof n === "number" && Number.isFinite(n) && n > 0 && n < 4000)
      sizes[key] = Math.round(n);
  }
  return sizes;
}

/** Bumped when the exported shape changes; an older file is refused, not guessed at. */
export const kLayoutFileVersion = 1;

/** What Settings writes: layout vars, rail, workspace tab, theme and motion. */
export type LayoutFile = {
  version: number;
  sizes: Partial<Record<LayoutVar, number>>;
  rail: RailView;
  workspaceTab: WorkspaceTab;
  theme: ThemeName;
  motion: MotionPref;
};

/** The live shell state as an export file. */
export function layoutFile(): LayoutFile {
  const s = useUi.getState();
  return {
    version: kLayoutFileVersion,
    sizes: s.sizes,
    rail: s.rail,
    workspaceTab: s.workspaceTab,
    theme: useTheme.getState().theme,
    motion: useMotion.getState().motion,
  };
}

/**
 * Validate an imported file. Throws naming the offending field: a support
 * hand-off must never half-apply a file that was meant for another build.
 */
export function parseLayoutFile(raw: string): LayoutFile {
  let v: Partial<LayoutFile>;
  try {
    v = JSON.parse(raw) as Partial<LayoutFile>;
  } catch {
    throw new Error("not a JSON file");
  }
  if (typeof v !== "object" || v === null) throw new Error("not a JSON object");
  if (v.version !== kLayoutFileVersion)
    throw new Error(
      `unsupported version ${JSON.stringify(v.version)} (expected ${kLayoutFileVersion})`,
    );
  if (!kRails.includes(v.rail as RailView))
    throw new Error(`unknown rail ${JSON.stringify(v.rail)}`);
  if (!kWorkspaceTabs.includes(v.workspaceTab as WorkspaceTab))
    throw new Error(`unknown workspace tab ${JSON.stringify(v.workspaceTab)}`);
  if (!kThemes.some((t) => t.id === v.theme))
    throw new Error(`unknown theme ${JSON.stringify(v.theme)}`);
  if (!kMotionOptions.some((o) => o.id === v.motion))
    throw new Error(`unknown motion ${JSON.stringify(v.motion)}`);
  return {
    version: kLayoutFileVersion,
    sizes: parseSizes(v.sizes),
    rail: v.rail as RailView,
    workspaceTab: v.workspaceTab as WorkspaceTab,
    theme: v.theme as ThemeName,
    motion: v.motion as MotionPref,
  };
}

/** One line per field an import changes; empty when the file matches the shell. */
export function layoutChanges(before: LayoutFile, after: LayoutFile): string[] {
  const out: string[] = [];
  if (before.theme !== after.theme) out.push(`theme ${before.theme} → ${after.theme}`);
  if (before.motion !== after.motion) out.push(`motion ${before.motion} → ${after.motion}`);
  if (before.rail !== after.rail) out.push(`rail ${before.rail} → ${after.rail}`);
  if (before.workspaceTab !== after.workspaceTab)
    out.push(`tab ${before.workspaceTab} → ${after.workspaceTab}`);
  for (const key of Object.keys(kLayoutVars) as LayoutVar[]) {
    const a = before.sizes[key];
    const b = after.sizes[key];
    if (a !== b) out.push(`${key} ${a ?? "default"} → ${b ?? "default"}`);
  }
  return out;
}

function load(): Layout {
  try {
    return parseLayout(localStorage.getItem(kStorageKey));
  } catch {
    return defaultLayout();
  }
}

function save(layout: Layout): void {
  try {
    localStorage.setItem(kStorageKey, JSON.stringify(layout));
  } catch {
    // storage unavailable: layout just does not persist
  }
}

type UiStore = Layout & {
  settingsOpen: boolean;
  paletteOpen: boolean;
  /** Live window size (not persisted); drives default panel sizes. */
  viewportW: number;
  viewportH: number;
  /** Guide topic shown in the guide modal, null when closed; "" lists topics. */
  guideTopic: string | null;
  setRail: (rail: RailView) => void;
  setWorkspaceTab: (tab: WorkspaceTab) => void;
  setOutputTab: (tab: OutputTab) => void;
  setInspectorOpen: (open: boolean) => void;
  setScannerOpen: (open: boolean) => void;
  setSize: (key: LayoutVar, px: number) => void;
  resetLayout: () => void;
  importLayout: (file: LayoutFile) => void;
  openSettings: () => void;
  closeSettings: () => void;
  setPaletteOpen: (open: boolean) => void;
  openGuide: (topic: string | null) => void;
  /** Window resized: refresh the viewport and the unpinned inspector. */
  onViewport: (w: number, h: number) => void;
};

export const useUi = create<UiStore>((set, get) => {
  const update = (patch: Partial<Layout>) => {
    set(patch);
    const s = get();
    save({
      rail: s.rail,
      workspaceTab: s.workspaceTab,
      outputTab: s.outputTab,
      inspectorOpen: s.inspectorOpen,
      inspectorPinned: s.inspectorPinned,
      scannerOpen: s.scannerOpen,
      sizes: s.sizes,
    });
  };
  const vp = viewport();

  return {
    ...load(),
    settingsOpen: false,
    paletteOpen: false,
    viewportW: vp.w,
    viewportH: vp.h,
    guideTopic: null,
    setRail: (rail) => update({ rail }),
    setWorkspaceTab: (workspaceTab) => update({ workspaceTab }),
    setOutputTab: (outputTab) => update({ outputTab }),
    setInspectorOpen: (inspectorOpen) => update({ inspectorOpen, inspectorPinned: true }),
    setScannerOpen: (scannerOpen) => update({ scannerOpen }),
    setSize: (key, px) => update({ sizes: { ...get().sizes, [key]: Math.round(px) } }),
    resetLayout: () => update(defaultLayout()),
    importLayout: (file) => {
      useTheme.getState().setTheme(file.theme);
      useMotion.getState().setMotion(file.motion);
      update({ rail: file.rail, workspaceTab: file.workspaceTab, sizes: file.sizes });
    },
    openSettings: () => set({ settingsOpen: true, paletteOpen: false }),
    closeSettings: () => set({ settingsOpen: false }),
    setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
    openGuide: (guideTopic) => set({ guideTopic, paletteOpen: false }),
    onViewport: (w, h) => {
      const s = get();
      const patch: Partial<UiStore> = { viewportW: w, viewportH: h };
      if (!s.inspectorPinned) patch.inspectorOpen = w >= kInspectorAutoWidth;
      set(patch);
    },
  };
});
