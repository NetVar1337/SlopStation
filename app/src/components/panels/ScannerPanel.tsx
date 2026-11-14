// app/src/components/panels/ScannerPanel.tsx
// scanner config, results and watchlist, a scan started here is the scan an
// agent sees over mcp. Hits and watch rows link to the hex view and to the
// "what writes/accesses this" tracer

import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Download,
  Eye,
  Footprints,
  PenLine,
  Plus,
  RotateCcw,
  Search,
  Snowflake,
  Upload,
  X,
} from "lucide-react";
import IconButton from "@/components/IconButton";
import WatchHistory from "@/components/panels/WatchHistory";
import { useT } from "@/i18n";
import { hex, parseAddress } from "@/lib/format";
import { accessLenFor, pageInfo } from "@/lib/livemem";
import { showInMemory, traceAccess } from "@/lib/liveNav";
import { pickOpenPath, pickSavePath } from "@/lib/pickPath";
import { useEngine } from "@/store/engine";
import {
  kFirstKinds,
  kindNeedsValue,
  kNextKinds,
  kPageSize,
  kWidths,
  useScanner,
} from "@/store/scanner";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import "@/styles/livemem.css";

const kRow = 19;
/** Widths a watch can hold ("all" is a scan-only mode). */
const kWatchWidths = kWidths.filter((w) => w !== "all");

/** Inline add-watch row: validated address, width and optional label. */
function AddWatchRow({ onDone, defaultWidth }: { onDone: () => void; defaultWidth: string }) {
  const t = useT();
  const add = useWatch((s) => s.add);
  const [addr, setAddr] = useState("");
  const [width, setWidth] = useState(
    kWatchWidths.includes(defaultWidth as never) ? defaultWidth : "u32",
  );
  const [label, setLabel] = useState("");
  const [intervalMs, setIntervalMs] = useState("100");
  const [invalid, setInvalid] = useState(false);

  const submit = async () => {
    const parsed = parseAddress(addr);
    if (parsed === null) {
      setInvalid(true);
      return;
    }
    const rate = Number.parseInt(intervalMs, 10);
    if (await add(parsed, width, label.trim() || undefined, Number.isFinite(rate) ? rate : 100))
      onDone();
  };

  return (
    <form
      className="watch-add"
      aria-label={t("scanner.addWatch")}
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
      onKeyDown={(e) => e.key === "Escape" && onDone()}
    >
      <input
        className="addr-input mono lm-grow"
        autoFocus
        aria-label={t("scanner.watchAddress")}
        aria-invalid={invalid}
        placeholder={t("scanner.addressPlaceholder")}
        value={addr}
        onChange={(e) => {
          setAddr(e.target.value);
          setInvalid(false);
        }}
      />
      <select
        className="select"
        aria-label={t("scanner.watchWidth")}
        value={width}
        onChange={(e) => setWidth(e.target.value)}
      >
        {kWatchWidths.map((w) => (
          <option key={w} value={w}>
            {w}
          </option>
        ))}
      </select>
      <input
        className="addr-input lm-grow"
        aria-label={t("scanner.watchLabel")}
        placeholder={t("scanner.labelPlaceholder")}
        value={label}
        onChange={(e) => setLabel(e.target.value)}
      />
      <input
        className="addr-input mono"
        style={{ width: 52 }}
        aria-label={t("scanner.watchInterval")}
        title={t("scanner.watchIntervalTip")}
        inputMode="numeric"
        value={intervalMs}
        onChange={(e) => setIntervalMs(e.target.value)}
      />
      <button type="submit" className="row-action" disabled={addr.trim() === ""}>
        {t("common.add")}
      </button>
      <IconButton tip={t("common.cancel")} onClick={onDone}>
        <X size={12} />
      </IconButton>
    </form>
  );
}

/** Pager under the hit list: position in the engine's result set. */
function Pager() {
  const t = useT();
  const { offset, total, hits, busy, page } = useScanner();
  const info = pageInfo(offset, hits.length, total, kPageSize);
  // an empty slot keeps the body grid rows stable
  if (total <= hits.length && offset === 0) return <div />;
  return (
    <div className="lm-pager" role="navigation" aria-label={t("livemem.pager")}>
      <IconButton
        tip={t("livemem.firstPage")}
        disabled={busy || info.prevOffset === null}
        onClick={() => void page(0)}
      >
        <ChevronsLeft size={12} />
      </IconButton>
      <IconButton
        tip={t("livemem.prevPage")}
        disabled={busy || info.prevOffset === null}
        onClick={() => info.prevOffset !== null && void page(info.prevOffset)}
      >
        <ChevronLeft size={12} />
      </IconButton>
      <span className="lm-ellipsis lm-pager-text" aria-live="polite">
        {t("livemem.pageRange", {
          from: info.from.toLocaleString(),
          to: info.to.toLocaleString(),
          total: total.toLocaleString(),
        })}
      </span>
      <IconButton
        tip={t("livemem.nextPage")}
        disabled={busy || info.nextOffset === null}
        onClick={() => info.nextOffset !== null && void page(info.nextOffset)}
      >
        <ChevronRight size={12} />
      </IconButton>
      <IconButton
        tip={t("livemem.lastPage")}
        disabled={busy || info.nextOffset === null}
        onClick={() => void page(info.lastOffset)}
      >
        <ChevronsRight size={12} />
      </IconButton>
    </div>
  );
}

export default function ScannerPanel() {
  const t = useT();
  const attached = useEngine((s) => s.target.attached);
  const setRail = useUi((s) => s.setRail);
  const scanner = useScanner();
  const {
    entries,
    values,
    error: watchError,
    load,
    add,
    remove,
    setFreeze,
    poke,
    exportCt,
    importCt,
    clear,
  } = useWatch();
  const [editing, setEditing] = useState<number | null>(null);
  const [adding, setAdding] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const refreshState = useScanner((s) => s.refreshState);

  useEffect(() => {
    // Engine-state seeds; the watch list keeps itself current from
    // `watch.list` events afterwards
    void load();
    void refreshState();
  }, [load, refreshState]);

  const virtualizer = useVirtualizer({
    count: scanner.hits.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 15,
  });

  // a new page starts at its top
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: 0 });
  }, [scanner.offset, scanner.hits]);

  const kinds = scanner.hasState ? kNextKinds : kFirstKinds;
  const kind = kinds.includes(scanner.kind as never) ? scanner.kind : kinds[0];
  const needsValue = kindNeedsValue(kind);
  const watchWidth = scanner.width === "all" ? "u32" : scanner.width;
  const selectedEntry = entries.find((e) => e.id === selected);
  const runScan = () => void scanner.scan(scanner.hasState);

  return (
    <div className="panel">
      <div className="lm-scan-head">
        <div className="lm-row">
          <select
            className="select"
            aria-label={t("scanner.valueWidth")}
            value={scanner.width}
            onChange={(e) => scanner.set({ width: e.target.value })}
          >
            {kWidths.map((w) => (
              <option key={w} value={w}>
                {w}
              </option>
            ))}
          </select>
          <select
            className="select lm-grow"
            aria-label={t("scanner.scanKind")}
            value={kind}
            onChange={(e) => scanner.set({ kind: e.target.value })}
          >
            {kinds.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
        </div>
        <div className="lm-row">
          {needsValue && (
            <input
              className="addr-input mono lm-grow"
              aria-label={t("scanner.value")}
              value={scanner.value}
              placeholder={t("scanner.valuePlaceholder")}
              data-tip={t("livemem.valueTip")}
              onChange={(e) => scanner.set({ value: e.target.value })}
              onKeyDown={(e) => e.key === "Enter" && runScan()}
            />
          )}
          {needsValue && kind === "between" && (
            <input
              className="addr-input mono lm-grow"
              aria-label={t("scanner.upperBound")}
              value={scanner.value2}
              placeholder={t("scanner.toPlaceholder")}
              onChange={(e) => scanner.set({ value2: e.target.value })}
              onKeyDown={(e) => e.key === "Enter" && runScan()}
            />
          )}
          {!needsValue && <span className="faint lm-grow lm-ellipsis">{t("livemem.noValue")}</span>}
          <button
            type="button"
            className="row-action lm-fixed"
            disabled={!attached || scanner.busy}
            onClick={runScan}
          >
            <Search size={11} aria-hidden />{" "}
            {scanner.hasState ? t("scanner.next") : t("scanner.first")}
          </button>
          {scanner.hasState && (
            <IconButton tip={t("scanner.reset")} onClick={() => void scanner.reset()}>
              <RotateCcw size={13} />
            </IconButton>
          )}
        </div>
      </div>

      <div className="lm-scan-body">
        <div className="dbg-head">
          {t("scanner.results")}
          <div className="spacer" />
          <span className="faint" style={{ fontSize: 11 }} aria-live="polite">
            {scanner.busy ? t("scanner.scanning") : scanner.total.toLocaleString()}
          </span>
          <IconButton
            tip={t("scanner.exportCsvTip")}
            disabled={scanner.total === 0}
            onClick={() => {
              void (async () => {
                const path = await pickSavePath(t("scanner.exportCsvTitle"), "scan-results.csv");
                if (path) await scanner.exportCsv(path);
              })();
            }}
          >
            <Download size={12} />
          </IconButton>
        </div>

        <div className="panel-body" ref={scrollRef}>
          {scanner.error !== null && (
            <div className="empty-hint error-text lm-note" role="alert">
              {scanner.error}
            </div>
          )}
          {!attached ? (
            <div className="lm-empty">
              <div className="empty-hint">{t("livemem.attachHint")}</div>
              <button type="button" className="row-action" onClick={() => setRail("targets")}>
                {t("livemem.attachTarget")}
              </button>
            </div>
          ) : scanner.hits.length === 0 ? (
            <div className="lm-empty empty-hint">
              {scanner.busy
                ? ""
                : scanner.hasState
                  ? t("livemem.noMatches")
                  : t("livemem.firstScanHint")}
            </div>
          ) : (
            <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
              {virtualizer.getVirtualItems().map((v) => {
                const h = scanner.hits[v.index];
                const at = hex(h.addr, 12);
                return (
                  <div
                    key={`${h.addr}-${h.type}`}
                    className="hex-row mono lm-hit"
                    style={{ top: v.start, height: kRow }}
                  >
                    <button
                      type="button"
                      className="link mono lm-fixed"
                      data-tip={t("livemem.openInMemory")}
                      onClick={() => showInMemory(h.addr)}
                    >
                      {at}
                    </button>
                    <span className="insn-text lm-ellipsis lm-grow" data-tip={h.formatted}>
                      {h.formatted}
                    </span>
                    <span className="faint lm-fixed">{h.type}</span>
                    <span className="lm-actions">
                      <IconButton
                        tip={t("scanner.addToWatchlist")}
                        onClick={() => void add(h.addr, h.type === "all" ? "u32" : h.type)}
                      >
                        <Eye size={11} />
                      </IconButton>
                      <IconButton
                        tip={t("livemem.findWrites")}
                        onClick={() => traceAccess(h.addr, accessLenFor(h.type), "write")}
                      >
                        <PenLine size={11} />
                      </IconButton>
                      <IconButton
                        tip={t("livemem.findAccesses")}
                        onClick={() => traceAccess(h.addr, accessLenFor(h.type), "access")}
                      >
                        <Footprints size={11} />
                      </IconButton>
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <Pager />

        <div className="dbg-head lm-border-top">
          {t("scanner.watchlist")}
          <div className="spacer" />
          <IconButton
            tip={t("scanner.importCtTip")}
            onClick={() => {
              void (async () => {
                const path = await pickOpenPath(t("scanner.importCtTitle"), "table.CT");
                if (path) await importCt(path);
              })();
            }}
          >
            <Upload size={12} />
          </IconButton>
          <IconButton
            tip={t("scanner.exportCtTip")}
            disabled={entries.length === 0}
            onClick={() => {
              void (async () => {
                const path = await pickSavePath(t("scanner.exportCtTitle"), "watchlist.CT");
                if (path) await exportCt(path);
              })();
            }}
          >
            <Download size={12} />
          </IconButton>
          <IconButton
            tip={t("scanner.addAddress")}
            pressed={adding}
            disabled={!attached}
            onClick={() => setAdding((v) => !v)}
          >
            <Plus size={13} />
          </IconButton>
          {entries.length > 0 && (
            <IconButton tip={t("scanner.clearWatches")} onClick={() => void clear()}>
              <X size={13} />
            </IconButton>
          )}
        </div>

        <div className="panel-body">
          {adding && attached && (
            <AddWatchRow defaultWidth={watchWidth} onDone={() => setAdding(false)} />
          )}
          {watchError !== null && (
            <div className="empty-hint error-text lm-note" role="alert">
              {watchError}
            </div>
          )}
          {entries.length === 0 ? (
            <div className="lm-empty empty-hint">
              {attached ? t("livemem.noWatchesHint") : t("livemem.attachHint")}
            </div>
          ) : (
            <table className="table watch-table lm-watch-table">
              <caption className="sr-only">{t("scanner.watchedAddresses")}</caption>
              <colgroup>
                <col />
                <col className="lm-col-addr" />
                <col className="lm-col-width" />
                <col />
                <col className="lm-col-icon" />
                <col className="lm-col-icon" />
              </colgroup>
              <thead className="sr-only">
                <tr>
                  <th scope="col">{t("scanner.colLabel")}</th>
                  <th scope="col">{t("scanner.colAddress")}</th>
                  <th scope="col">{t("scanner.colWidth")}</th>
                  <th scope="col">{t("scanner.colValue")}</th>
                  <th scope="col">{t("scanner.colFreeze")}</th>
                  <th scope="col">{t("scanner.colRemove")}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => {
                  const v = values.get(e.id);
                  const at = hex(e.addr, 12);
                  return (
                    <tr
                      key={e.id}
                      data-selected={selected === e.id}
                      onClick={() => setSelected(selected === e.id ? null : e.id)}
                    >
                      <td data-tip={e.label || undefined}>
                        {e.label !== "" ? e.label : <span className="faint">-</span>}
                      </td>
                      <td className="mono" data-tip={at}>
                        <button
                          type="button"
                          className="link mono"
                          aria-label={t("livemem.watchDetails", { addr: at })}
                          aria-expanded={selected === e.id}
                          onClick={(ev) => {
                            ev.stopPropagation();
                            setSelected(selected === e.id ? null : e.id);
                          }}
                        >
                          {at}
                        </button>
                      </td>
                      <td className="faint">{e.width}</td>
                      <td
                        className="mono"
                        data-tip={v?.ok === true ? v.text : undefined}
                        onDoubleClick={() => setEditing(e.id)}
                      >
                        {editing === e.id ? (
                          <input
                            className="addr-input mono lm-fill"
                            aria-label={t("scanner.newValue", { label: e.label || at })}
                            autoFocus
                            defaultValue={v?.text ?? ""}
                            onClick={(e2) => e2.stopPropagation()}
                            onBlur={() => setEditing(null)}
                            onKeyDown={(e2) => {
                              if (e2.key === "Enter") {
                                void poke(e.id, e2.currentTarget.value);
                                setEditing(null);
                              }
                              if (e2.key === "Escape") setEditing(null);
                            }}
                          />
                        ) : (
                          <>
                            {v?.ok === true ? v.text : "-"}
                            {e.freeze && <span className="faint"> *</span>}
                          </>
                        )}
                      </td>
                      <td>
                        <IconButton
                          tip={e.freeze ? t("scanner.unfreeze") : t("scanner.freeze")}
                          pressed={e.freeze}
                          style={{ color: e.freeze ? "var(--accent)" : undefined }}
                          onClick={(ev) => {
                            ev.stopPropagation();
                            void setFreeze(e.id, !e.freeze);
                          }}
                        >
                          <Snowflake size={11} />
                        </IconButton>
                      </td>
                      <td>
                        <IconButton
                          tip={t("scanner.removeWatch")}
                          onClick={(ev) => {
                            ev.stopPropagation();
                            void remove(e.id);
                          }}
                        >
                          <X size={11} />
                        </IconButton>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          {entries.length > 0 && selectedEntry === undefined && (
            <div className="lm-note faint">{t("livemem.watchSelectHint")}</div>
          )}
        </div>

        {selectedEntry !== undefined && (
          <WatchHistory entry={selectedEntry} onClose={() => setSelected(null)} />
        )}
      </div>
    </div>
  );
}
