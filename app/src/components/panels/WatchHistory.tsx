// app/src/components/panels/WatchHistory.tsx
// detail strip under the watchlist: the selected entry's value history
// (memory.watch_history, polled while shown) as a sparkline and a table, plus
// links to the hex view and the write/access tracer

import { useEffect, useState } from "react";
import { Binary, Footprints, PenLine, X } from "lucide-react";
import IconButton from "@/components/IconButton";
import { useT } from "@/i18n";
import type { WatchEntry } from "@/lib/events";
import { hex } from "@/lib/format";
import { accessLenFor, sparkPoints } from "@/lib/livemem";
import { showInMemory, traceAccess } from "@/lib/liveNav";
import { useWatch, type WatchSample } from "@/store/watch";

const kPollMs = 1000;
const kSparkW = 200;
const kSparkH = 32;
/** Newest rows listed under the sparkline. */
const kTableRows = 40;

export default function WatchHistory({
  entry,
  onClose,
}: {
  entry: WatchEntry;
  onClose: () => void;
}) {
  const t = useT();
  const history = useWatch((s) => s.history);
  const [samples, setSamples] = useState<WatchSample[]>([]);

  useEffect(() => {
    let alive = true;
    setSamples([]);
    const tick = async () => {
      const got = await history(entry.id);
      if (alive && got !== null) setSamples(got);
    };
    void tick();
    const id = setInterval(() => void tick(), kPollMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [entry.id, history]);

  const at = hex(entry.addr, 12);
  const len = accessLenFor(entry.width);
  const latest = samples.at(-1)?.ms ?? 0;
  const points = sparkPoints(
    samples.map((s) => Number(s.value)),
    kSparkW,
    kSparkH,
  );

  return (
    <section className="lm-watch-detail" aria-label={t("livemem.historyOf", { addr: at })}>
      <div className="dbg-head">
        <span className="lm-ellipsis lm-grow" data-tip={entry.label || at}>
          {entry.label !== "" ? `${entry.label} · ${at}` : at}
        </span>
        <IconButton tip={t("livemem.openInMemory")} onClick={() => showInMemory(entry.addr)}>
          <Binary size={12} />
        </IconButton>
        <IconButton
          tip={t("livemem.findWrites")}
          onClick={() => traceAccess(entry.addr, len, "write")}
        >
          <PenLine size={12} />
        </IconButton>
        <IconButton
          tip={t("livemem.findAccesses")}
          onClick={() => traceAccess(entry.addr, len, "access")}
        >
          <Footprints size={12} />
        </IconButton>
        <IconButton tip={t("common.close")} onClick={onClose}>
          <X size={12} />
        </IconButton>
      </div>
      {samples.length === 0 ? (
        <div className="lm-note faint">{t("livemem.noHistory")}</div>
      ) : (
        <>
          <svg
            className="lm-spark"
            viewBox={`0 0 ${kSparkW} ${kSparkH}`}
            preserveAspectRatio="none"
            role="img"
            aria-label={t("livemem.sparkline", { count: samples.length })}
          >
            {points !== "" && <polyline points={points} />}
          </svg>
          <div className="lm-history-scroll">
            <table className="table">
              <caption className="sr-only">{t("livemem.historyOf", { addr: at })}</caption>
              <thead className="sr-only">
                <tr>
                  <th scope="col">{t("livemem.colAge")}</th>
                  <th scope="col">{t("scanner.colValue")}</th>
                </tr>
              </thead>
              <tbody>
                {samples
                  .slice(-kTableRows)
                  .reverse()
                  .map((s, i) => (
                    <tr key={`${s.ms}-${i}`}>
                      <td className="faint mono lm-col-age">
                        {t("livemem.age", { seconds: ((latest - s.ms) / 1000).toFixed(1) })}
                      </td>
                      <td className="mono" data-tip={String(s.value)}>
                        {String(s.value)}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}
