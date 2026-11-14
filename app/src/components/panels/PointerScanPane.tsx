// app/src/components/panels/PointerScanPane.tsx
// pointer scan pane under the hex grid: find chains that land on an address
// (memory.pointerscan), re-check them after a restart (pointerscan_verify),
// watch the address a chain resolves to

import { useState } from "react";
import { Copy, Eye, Search, ShieldCheck, X } from "lucide-react";
import IconButton from "@/components/IconButton";
import { useT } from "@/i18n";
import { copyText } from "@/lib/clipboard";
import { hex, parseAddress } from "@/lib/format";
import { formatChain } from "@/lib/livemem";
import { usePointers } from "@/store/pointers";
import { useScanner } from "@/store/scanner";
import { useWatch } from "@/store/watch";

const kDepths = [1, 2, 3, 4, 5, 6, 7];
/** Rows rendered; the engine lists at most 1000 anyway. */
const kShown = 500;

export default function PointerScanPane({ addr, onClose }: { addr: number; onClose: () => void }) {
  const t = useT();
  const { chains, total, target, truncated, verified, busy, error, scan, verify } = usePointers();
  const addWatch = useWatch((s) => s.add);
  const scanWidth = useScanner((s) => s.width);
  const [targetText, setTargetText] = useState(hex(addr, 1));
  const [depth, setDepth] = useState(3);
  const [maxOffText, setMaxOffText] = useState("1000");
  const [staticRoots, setStaticRoots] = useState(true);
  const [moduleFilter, setModuleFilter] = useState("");
  const [newAddrText, setNewAddrText] = useState("");
  const [inputError, setInputError] = useState<string | null>(null);

  const run = () => {
    const tgt = parseAddress(targetText);
    const maxOff = parseAddress(maxOffText);
    if (tgt === null || tgt === 0 || maxOff === null) {
      setInputError(t("livemem.ptr.badInput"));
      return;
    }
    setInputError(null);
    void scan({ target: tgt, depth, maxOffset: maxOff, staticRoots });
  };

  const recheck = () => {
    const text = newAddrText.trim();
    const moved = text === "" ? null : parseAddress(text);
    if (text !== "" && moved === null) {
      setInputError(t("livemem.ptr.badInput"));
      return;
    }
    setInputError(null);
    void verify(moved);
  };

  const filter = moduleFilter.trim().toLowerCase();
  const shown = (
    filter === "" ? chains : chains.filter((c) => (c.module ?? "").toLowerCase().includes(filter))
  ).slice(0, kShown);
  const watchWidth = scanWidth === "all" ? "u32" : scanWidth;

  return (
    <section className="lm-pane" aria-label={t("livemem.ptr.title")}>
      <div className="view-bar lm-wrap">
        <span className="panel-title">{t("livemem.ptr.title")}</span>
        <label className="view-label">
          {t("livemem.ptr.target")}
          <input
            className="addr-input mono lm-addr-input"
            value={targetText}
            onChange={(e) => setTargetText(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
          />
        </label>
        <label className="view-label">
          {t("livemem.ptr.depth")}
          <select
            className="select"
            value={depth}
            onChange={(e) => setDepth(Number(e.target.value))}
          >
            {kDepths.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </label>
        <label className="view-label" data-tip={t("livemem.ptr.maxOffsetTip")}>
          {t("livemem.ptr.maxOffset")}
          <input
            className="addr-input mono lm-short-input"
            value={maxOffText}
            onChange={(e) => setMaxOffText(e.target.value)}
          />
        </label>
        <label className="view-label" data-tip={t("livemem.ptr.staticTip")}>
          <input
            type="checkbox"
            checked={staticRoots}
            onChange={(e) => setStaticRoots(e.target.checked)}
          />
          {t("livemem.ptr.static")}
        </label>
        <button type="button" className="row-action" disabled={busy} onClick={run}>
          <Search size={11} aria-hidden /> {t("livemem.ptr.scan")}
        </button>
        <div className="spacer" />
        <IconButton tip={t("livemem.ptr.close")} onClick={onClose}>
          <X size={13} />
        </IconButton>
      </div>
      <div className="view-bar lm-wrap">
        <label className="view-label">
          {t("livemem.ptr.module")}
          <input
            className="addr-input lm-short-input"
            value={moduleFilter}
            placeholder={t("livemem.ptr.modulePlaceholder")}
            onChange={(e) => setModuleFilter(e.target.value)}
          />
        </label>
        <label className="view-label" data-tip={t("livemem.ptr.newAddressTip")}>
          {t("livemem.ptr.newAddress")}
          <input
            className="addr-input mono lm-addr-input"
            value={newAddrText}
            placeholder={t("livemem.ptr.sameAddress")}
            onChange={(e) => setNewAddrText(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && recheck()}
          />
        </label>
        <button
          type="button"
          className="row-action"
          disabled={busy || target === null}
          onClick={recheck}
        >
          <ShieldCheck size={11} aria-hidden /> {t("livemem.ptr.verify")}
        </button>
        <span className="faint lm-ellipsis lm-grow" role="status">
          {busy
            ? t("livemem.ptr.working")
            : verified !== null
              ? t("livemem.ptr.verified", { kept: verified.kept, checked: verified.checked })
              : target !== null
                ? t("livemem.ptr.found", {
                    total: total.toLocaleString(),
                    addr: hex(target, 1),
                  }) + (truncated ? t("livemem.ptr.truncated") : "")
                : ""}
        </span>
      </div>
      <div className="panel-body">
        {(error ?? inputError) !== null && (
          <div className="empty-hint error-text lm-note" role="alert">
            {error ?? inputError}
          </div>
        )}
        {target === null && !busy && (
          <div className="lm-note empty-hint">{t("livemem.ptr.hint")}</div>
        )}
        {target !== null && shown.length === 0 && !busy && (
          <div className="lm-note empty-hint">{t("livemem.ptr.none")}</div>
        )}
        {shown.length > 0 && target !== null && (
          <ol className="plain-list" aria-label={t("livemem.ptr.title")}>
            {shown.map((c, i) => {
              const text = formatChain(c);
              return (
                <li key={`${i}-${text}`} className="fn-row lm-chain">
                  <span className="lm-ellipsis lm-grow" data-tip={text}>
                    {text}
                  </span>
                  <span className="faint lm-fixed">{c.offsets.length}</span>
                  <IconButton
                    tip={t("livemem.ptr.watch", { addr: hex(target, 1) })}
                    onClick={() => void addWatch(target, watchWidth, text.slice(0, 120))}
                  >
                    <Eye size={11} />
                  </IconButton>
                  <IconButton tip={t("livemem.ptr.copy")} onClick={() => void copyText(text)}>
                    <Copy size={11} />
                  </IconButton>
                </li>
              );
            })}
          </ol>
        )}
      </div>
    </section>
  );
}
