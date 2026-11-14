// app/src/components/panels/AccessTracer.tsx
// "find out what writes/accesses this address": arm a session, watch the
// instruction sites pile up (debugger.access_status, polled while it runs),
// click a site to open it in the disassembly

import { useEffect, useState } from "react";
import { Footprints, Play, Square } from "lucide-react";
import IconButton from "@/components/IconButton";
import { useT, type Key } from "@/i18n";
import { hex, parseAddress } from "@/lib/format";
import { showInDisassembly } from "@/lib/navigate";
import { kAccessKinds, kAccessLens, useAccess, type AccessKind } from "@/store/access";
import "@/styles/livemem.css";

const kPollMs = 500;
const kKindKeys: Record<AccessKind, Key> = {
  write: "livemem.access.kindWrite",
  access: "livemem.access.kindAccess",
  exec: "livemem.access.kindExec",
};

/** Last hit's registers as tooltip lines. */
function regsTip(regs: Record<string, number> | undefined): string | undefined {
  if (regs === undefined) return undefined;
  return Object.entries(regs)
    .map(([name, v]) => `${name} = ${hex(v)}`)
    .join("\n");
}

export default function AccessTracer() {
  const t = useT();
  const { sessions, selected, status, error, busy, list, start, poll, stop, select } = useAccess();
  const [addrText, setAddrText] = useState("");
  const [kind, setKind] = useState<AccessKind>("write");
  const [len, setLen] = useState<number>(4);
  const [badAddr, setBadAddr] = useState(false);

  useEffect(() => {
    void list();
  }, [list]);

  const running = status?.running ?? sessions.some((s) => s.id === selected && s.running);
  useEffect(() => {
    if (selected === null || !running) return;
    const id = setInterval(() => void poll(), kPollMs);
    return () => clearInterval(id);
  }, [selected, running, poll]);

  const session = sessions.find((s) => s.id === selected);

  const submit = () => {
    const a = parseAddress(addrText);
    setBadAddr(a === null || a === 0);
    if (a !== null && a !== 0) void start(a, len, kind);
  };

  return (
    <section className="lm-access" aria-label={t("livemem.access.title")}>
      <div className="dbg-head lm-wrap">
        <Footprints size={12} aria-hidden />
        {t("livemem.access.title")}
        <form
          className="lm-row lm-grow"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <input
            className="addr-input mono lm-grow"
            aria-label={t("livemem.access.address")}
            aria-invalid={badAddr}
            placeholder={t("scanner.addressPlaceholder")}
            value={addrText}
            onChange={(e) => {
              setAddrText(e.target.value);
              setBadAddr(false);
            }}
          />
          <select
            className="select"
            aria-label={t("livemem.access.kind")}
            value={kind}
            onChange={(e) => setKind(e.target.value as AccessKind)}
          >
            {kAccessKinds.map((k) => (
              <option key={k} value={k}>
                {t(kKindKeys[k])}
              </option>
            ))}
          </select>
          <select
            className="select"
            aria-label={t("livemem.access.len")}
            value={len}
            onChange={(e) => setLen(Number(e.target.value))}
          >
            {kAccessLens.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
          <IconButton
            tip={t("livemem.access.start")}
            type="submit"
            disabled={busy || addrText.trim() === ""}
          >
            <Play size={12} />
          </IconButton>
        </form>
        {sessions.length > 0 && (
          <select
            className="select lm-shrink"
            aria-label={t("livemem.access.sessions")}
            value={selected ?? ""}
            onChange={(e) => void select(Number(e.target.value))}
          >
            <option value="" disabled>
              {t("livemem.access.pick")}
            </option>
            {sessions.map((s) => (
              <option key={s.id} value={s.id}>
                {t("livemem.access.sessionLabel", {
                  id: s.id,
                  kind: t(kKindKeys[s.kind] ?? "livemem.access.kindAccess"),
                  addr: hex(s.addr, 1),
                  state: s.running ? t("livemem.access.running") : t("livemem.access.stopped"),
                })}
              </option>
            ))}
          </select>
        )}
        {selected !== null && running && (
          <IconButton tip={t("livemem.access.stop")} onClick={() => void stop(selected)}>
            <Square size={12} />
          </IconButton>
        )}
      </div>
      <div className="panel-body">
        {error !== null && (
          <div className="empty-hint error-text lm-note" role="alert">
            {error}
          </div>
        )}
        {selected === null ? (
          <div className="lm-note empty-hint">{t("livemem.access.hint")}</div>
        ) : (
          <>
            <div className="lm-note faint mono" role="status">
              {t("livemem.access.summary", {
                addr: session !== undefined ? hex(session.addr, 1) : "?",
                state: running ? t("livemem.access.running") : t("livemem.access.stopped"),
                hits: (status?.hits ?? 0).toLocaleString(),
                seconds: ((status?.elapsed_ms ?? 0) / 1000).toFixed(1),
                sites: status?.sites.length ?? 0,
              })}
            </div>
            {status !== null && status.sites.length === 0 && (
              <div className="lm-note empty-hint">{t("livemem.access.noSites")}</div>
            )}
            {status !== null && status.sites.length > 0 && (
              <table className="table lm-sites">
                <caption className="sr-only">{t("livemem.access.sitesCaption")}</caption>
                <colgroup>
                  <col className="lm-col-count" />
                  <col className="lm-col-site" />
                  <col />
                </colgroup>
                <thead>
                  <tr>
                    <th scope="col">{t("livemem.access.colCount")}</th>
                    <th scope="col">{t("livemem.access.colSite")}</th>
                    <th scope="col">{t("livemem.access.colInsn")}</th>
                  </tr>
                </thead>
                <tbody>
                  {status.sites.map((s) => {
                    const site = s.rip_modoff ?? s.rip_hex ?? hex(s.rip, 1);
                    return (
                      <tr key={s.rip} data-tip={regsTip(s.regs)}>
                        <td className="mono">{s.count.toLocaleString()}</td>
                        <td className="mono">
                          <button
                            type="button"
                            className="link mono lm-ellipsis lm-fill"
                            data-tip={`${site}\n${t("debugger.showInDisasm")}`}
                            onClick={() => showInDisassembly(s.rip)}
                          >
                            {site}
                          </button>
                        </td>
                        <td className="mono" data-tip={s.disasm}>
                          {s.disasm ?? ""}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </>
        )}
      </div>
    </section>
  );
}
