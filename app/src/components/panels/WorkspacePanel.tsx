// app/src/components/panels/WorkspacePanel.tsx
// The tabbed centre area, shared across ELF, PE, Mach-O and live-target views.

import { useEffect, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, FolderOpen, ScanSearch, X } from "lucide-react";
import IconButton from "@/components/IconButton";
import Tabs, { panelId, tabId } from "@/components/Tabs";
import DisassemblyView from "@/components/panels/DisassemblyView";
import DecompView from "@/components/panels/DecompView";
import DebuggerView from "@/components/panels/DebuggerView";
import EmulatorPanel from "@/components/panels/EmulatorPanel";
import MemoryView from "@/components/panels/MemoryView";
import NetworkPanel from "@/components/panels/NetworkPanel";
import PatchPanel from "@/components/panels/PatchPanel";
import PeView from "@/components/panels/PeView";
import StringsView from "@/components/panels/StringsView";
import StructEditor from "@/components/panels/StructEditor";
import UnpackerView from "@/components/panels/UnpackerView";
import XrayPanel from "@/components/panels/XrayPanel";
import { useT } from "@/i18n";
import type { Key } from "@/i18n/en";
import { browserLabel, formatLabel } from "@/lib/format";
import { openBinary } from "@/lib/openBinary";
import { useEngine } from "@/store/engine";
import { useDisasm } from "@/store/disasm";
import { useUi, type WorkspaceTab } from "@/store/ui";

// Which tabs read the static analysis session and which need a live process.
// Getting this wrong is what made Memory and Debugger look broken behind a
// "no binary loaded" wall they never needed. The debugger renders its own
// console / attach states.
const kTabs: readonly {
  id: WorkspaceTab;
  labelKey: Key;
  needs: "image" | "target" | "none";
}[] = [
  { id: "disassembly", labelKey: "workspace.disassembly", needs: "image" },
  { id: "decomp", labelKey: "workspace.decomp", needs: "image" },
  { id: "strings", labelKey: "workspace.strings", needs: "image" },
  { id: "memory", labelKey: "workspace.memory", needs: "target" },
  { id: "debugger", labelKey: "workspace.debugger", needs: "none" },
  { id: "pe", labelKey: "workspace.imageBrowser", needs: "image" },
  { id: "structs", labelKey: "workspace.structs", needs: "image" },
  { id: "unpacker", labelKey: "workspace.unpacker", needs: "image" },
  { id: "xray", labelKey: "workspace.xray", needs: "image" },
  { id: "patch", labelKey: "workspace.patches", needs: "image" },
  { id: "network", labelKey: "workspace.network", needs: "none" },
  { id: "emulate", labelKey: "workspace.emulate", needs: "none" },
];

export default function WorkspacePanel() {
  const t = useT();
  const active = useUi((s) => s.workspaceTab);
  const setActive = useUi((s) => s.setWorkspaceTab);
  const setRail = useUi((s) => s.setRail);
  const target = useEngine((s) => s.target);
  const hype = useEngine((s) => s.hype);
  // The session is shared with agents, so the image can change without this
  // window doing anything; the engine store refreshes the mirror on
  // image.changed / hype.progress and on every reconnect
  const { image, busy, error, unload } = useDisasm();
  const stripRef = useRef<HTMLDivElement>(null);
  const [edges, setEdges] = useState({ left: false, right: false });

  // Twelve tabs never fit a narrow workspace: the strip scrolls sideways and
  // shows arrows on the side that has hidden tabs
  useEffect(() => {
    const el = stripRef.current;
    if (el === null) return;
    const measure = () =>
      setEdges({
        left: el.scrollLeft > 1,
        right: el.scrollLeft + el.clientWidth < el.scrollWidth - 1,
      });
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    el.addEventListener("scroll", measure, { passive: true });
    return () => {
      observer.disconnect();
      el.removeEventListener("scroll", measure);
    };
  }, []);

  useEffect(() => {
    document
      .getElementById(tabId("workspace", active))
      ?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [active]);

  const scrollTabs = (dir: -1 | 1) =>
    stripRef.current?.scrollBy({ left: dir * 160, behavior: "smooth" });

  const tabLabel = (tab: (typeof kTabs)[number]) =>
    tab.id === "pe" ? browserLabel(image.format) : t(tab.labelKey);
  const meta = image.ready
    ? `${image.name ?? ""}${
        image.format !== undefined
          ? t("workspace.metaFormat", { format: formatLabel(image.format) })
          : ""
      }${image.arch !== undefined ? t("workspace.metaArch", { arch: image.arch }) : ""}${
        hype.running
          ? t("workspace.metaAnalyzing", { percent: Math.round(hype.progress * 100) })
          : ""
      }`
    : "";

  const body = () => {
    const tab = kTabs.find((item) => item.id === active);

    if (tab?.needs === "target" && !target.attached) {
      return (
        <div className="empty">
          <div className="empty-glyph">
            <ScanSearch size={28} strokeWidth={1.5} />
          </div>
          <div className="empty-title">{t("workspace.noTarget")}</div>
          <div className="empty-hint">{t("workspace.noTargetHint", { tab: t(tab.labelKey) })}</div>
          <button type="button" className="row-action" onClick={() => setRail("targets")}>
            {t("titlebar.attachToProcess")}
          </button>
        </div>
      );
    }

    if (tab?.needs === "image") {
      if (busy && !image.ready) {
        return (
          <div className="empty">
            <div className="empty-title">{t("common.loading")}</div>
          </div>
        );
      }
      if (!image.ready) {
        return (
          <div className="empty">
            <div className="empty-glyph">
              <ScanSearch size={28} strokeWidth={1.5} />
            </div>
            <div className="empty-title">{t("workspace.noBinary")}</div>
            <div className="empty-hint">
              {target.attached ? t("workspace.noBinaryHintTarget") : t("workspace.noBinaryHint")}
            </div>
            <button type="button" className="row-action" onClick={() => void openBinary()}>
              <FolderOpen size={12} style={{ marginRight: 6, verticalAlign: -2 }} aria-hidden />
              {t("common.openBinary")}
            </button>
            {error !== null && (
              <div className="empty-hint error-text" role="alert">
                {error}
              </div>
            )}
          </div>
        );
      }
    }

    switch (active) {
      case "disassembly":
        return <DisassemblyView />;
      case "decomp":
        return <DecompView />;
      case "strings":
        return <StringsView />;
      case "pe":
        return <PeView />;
      case "memory":
        return <MemoryView />;
      case "debugger":
        return <DebuggerView />;
      case "structs":
        return <StructEditor />;
      case "unpacker":
        return <UnpackerView />;
      case "xray":
        return <XrayPanel />;
      case "patch":
        return <PatchPanel />;
      case "network":
        return <NetworkPanel />;
      case "emulate":
        return <EmulatorPanel />;
    }
  };

  const warning =
    image.warning || (image.encrypted === true ? t("workspace.encrypted") : undefined);

  return (
    <div className="panel">
      <div className="tabs">
        {edges.left && (
          <IconButton
            tip={t("workspace.scrollLeft")}
            className="tabs-arrow"
            tabIndex={-1}
            onClick={() => scrollTabs(-1)}
          >
            <ChevronLeft size={14} />
          </IconButton>
        )}
        <div
          className="tabs-scroll"
          ref={stripRef}
          data-fade-left={edges.left}
          data-fade-right={edges.right}
        >
          <Tabs<WorkspaceTab>
            items={kTabs.map((tab) => ({ id: tab.id, label: tabLabel(tab) }))}
            active={active}
            onChange={setActive}
            label={t("workspace.views")}
            idPrefix="workspace"
          />
        </div>
        {edges.right && (
          <IconButton
            tip={t("workspace.scrollRight")}
            className="tabs-arrow"
            tabIndex={-1}
            onClick={() => scrollTabs(1)}
          >
            <ChevronRight size={14} />
          </IconButton>
        )}
        <div className="spacer" />
        {image.ready && (
          <span className="faint workspace-meta" data-tip={meta}>
            {meta}
          </span>
        )}
        <IconButton
          tip={image.ready ? t("workspace.closeBinary") : t("common.openBinary")}
          className="workspace-close"
          onClick={() => void (image.ready ? unload() : openBinary())}
        >
          {image.ready ? <X size={14} /> : <FolderOpen size={14} />}
        </IconButton>
      </div>
      <div className="workspace-body">
        {image.ready && warning !== undefined && (
          <div className="workspace-warning" role="alert">
            {warning}
          </div>
        )}
        <div
          className="panel-body"
          style={{ overflow: "hidden" }}
          role="tabpanel"
          id={panelId("workspace", active)}
          aria-labelledby={tabId("workspace", active)}
        >
          {/* Keyed on the active tab so the enter animation replays on every
              switch rather than only on first mount. */}
          <div className="view-swap" key={active}>
            {body()}
          </div>
        </div>
      </div>
    </div>
  );
}
