// app/src/components/panels/DumpersPanel.tsx
// Engine-metadata dumpers (Unreal / Unity IL2CPP / Source) plus the offset
// manifest helpers. Every dumper writes host files and returns counters, so
// the panel is a parameter form, a result table and the file list.

import { useState } from "react";
import { useDumpers, kDumpers, kDumperLabels, type Dumper } from "@/store/dumpers";

export default function DumpersPanel() {
  const { busy, error, result, run, buildOffsets, diffOffsets, clear } = useDumpers();
  const [dumper, setDumper] = useState<Dumper>("source_dump");
  const [outDir, setOutDir] = useState("");
  const [module, setModule] = useState("eboot.bin");
  const [head, setHead] = useState("");
  const [datamaps, setDatamaps] = useState(true);
  const [gnames, setGnames] = useState("");
  const [gobjects, setGobjects] = useState("");
  const [metadata, setMetadata] = useState("");
  const [offsetsText, setOffsetsText] = useState("");
  const [manifestOut, setManifestOut] = useState("");
  const [oldPath, setOldPath] = useState("");
  const [newPath, setNewPath] = useState("");

  const go = () => {
    if (outDir.trim() === "") return;
    const params: Record<string, unknown> = { out_dir: outDir.trim() };
    if (module.trim() !== "") params.module = module.trim();
    if (dumper === "source_dump") {
      if (head.trim() !== "") params.head = head.trim();
      params.datamaps = datamaps;
    }
    if (dumper === "ue_dump") {
      if (gnames.trim() !== "") params.gnames = gnames.trim();
      if (gobjects.trim() !== "") params.gobjects = gobjects.trim();
    }
    if (dumper === "il2cpp_dump" && metadata.trim() !== "") params.metadata = metadata.trim();
    void run(dumper, params);
  };

  // one "name addr" pair per line, optional third column = aob_offset
  const build = () => {
    const offsets: Record<string, unknown>[] = [];
    for (const line of offsetsText.split("\n")) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 2) continue;
      const entry: Record<string, unknown> = { name: parts[0], addr: parts[1] };
      const delta = Number.parseInt(parts[2] ?? "", 10);
      if (Number.isFinite(delta)) entry.aob_offset = delta;
      offsets.push(entry);
    }
    if (offsets.length === 0) return;
    const params: Record<string, unknown> = { offsets };
    if (module.trim() !== "") params.module = module.trim();
    if (manifestOut.trim() !== "") params.out = manifestOut.trim();
    void buildOffsets(params);
  };

  return (
    <div className="panel tool-panel">
      <div className="panel-head">
        <span className="panel-title">Dumpers</span>
        <div className="spacer" />
        <span className="faint" style={{ fontSize: "var(--type-small)" }}>
          writes host files
        </span>
      </div>
      <div className="panel-body tool-body">
        <div className="tool-form">
          <label className="faint tool-field">
            engine
            <select
              className="addr-input"
              aria-label="Dumper"
              value={dumper}
              onChange={(e) => setDumper(e.target.value as Dumper)}
            >
              {kDumpers.map((d) => (
                <option key={d} value={d}>
                  {kDumperLabels[d]}
                </option>
              ))}
            </select>
          </label>
          <label className="faint tool-field">
            module
            <input
              className="addr-input"
              style={{ width: 110 }}
              aria-label="Module name"
              value={module}
              onChange={(e) => setModule(e.target.value)}
            />
          </label>
          <input
            className="addr-input mono"
            style={{ minWidth: 220 }}
            aria-label="Output folder"
            placeholder="out_dir (host folder)"
            value={outDir}
            onChange={(e) => setOutDir(e.target.value)}
          />
          <button className="btn" disabled={busy || outDir.trim() === ""} onClick={go}>
            {busy ? "running…" : "dump"}
          </button>
          <button className="btn ghost" onClick={clear}>
            clear
          </button>
        </div>

        {dumper === "source_dump" && (
          <div className="tool-form">
            <input
              className="addr-input mono"
              style={{ width: 130 }}
              aria-label="ClientClass head"
              placeholder="head (optional)"
              value={head}
              onChange={(e) => setHead(e.target.value)}
            />
            <label className="faint tool-field">
              <input
                type="checkbox"
                checked={datamaps}
                onChange={(e) => setDatamaps(e.target.checked)}
              />
              datamaps
            </label>
          </div>
        )}

        {dumper === "ue_dump" && (
          <div className="tool-form">
            <input
              className="addr-input mono"
              style={{ width: 150 }}
              aria-label="GNames"
              placeholder="gnames (optional)"
              value={gnames}
              onChange={(e) => setGnames(e.target.value)}
            />
            <input
              className="addr-input mono"
              style={{ width: 150 }}
              aria-label="GObjects"
              placeholder="gobjects (optional)"
              value={gobjects}
              onChange={(e) => setGobjects(e.target.value)}
            />
          </div>
        )}

        {dumper === "il2cpp_dump" && (
          <div className="tool-form">
            <input
              className="addr-input mono"
              style={{ minWidth: 260 }}
              aria-label="global-metadata.dat"
              placeholder="global-metadata.dat (host path)"
              value={metadata}
              onChange={(e) => setMetadata(e.target.value)}
            />
          </div>
        )}

        <div className="panel-head" style={{ marginTop: 8 }}>
          <span className="panel-title">Offset manifest</span>
        </div>
        <div className="tool-form">
          <textarea
            className="addr-input mono"
            style={{ minWidth: 320, minHeight: 64 }}
            aria-label="Named addresses"
            placeholder={"cl_entitylist 0x14A2B3C40\nview_matrix 0x14A2B0010 -7"}
            value={offsetsText}
            onChange={(e) => setOffsetsText(e.target.value)}
          />
          <input
            className="addr-input mono"
            style={{ minWidth: 200 }}
            aria-label="Manifest output path"
            placeholder="manifest.json (optional)"
            value={manifestOut}
            onChange={(e) => setManifestOut(e.target.value)}
          />
          <button className="btn" disabled={busy || offsetsText.trim() === ""} onClick={build}>
            build
          </button>
        </div>
        <div className="tool-form">
          <input
            className="addr-input mono"
            style={{ minWidth: 170 }}
            aria-label="Old manifest"
            placeholder="old manifest / netvars.json"
            value={oldPath}
            onChange={(e) => setOldPath(e.target.value)}
          />
          <input
            className="addr-input mono"
            style={{ minWidth: 170 }}
            aria-label="New manifest"
            placeholder="new manifest / netvars.json"
            value={newPath}
            onChange={(e) => setNewPath(e.target.value)}
          />
          <button
            className="btn"
            disabled={busy || oldPath.trim() === "" || newPath.trim() === ""}
            onClick={() => void diffOffsets(oldPath.trim(), newPath.trim())}
          >
            diff
          </button>
        </div>

        {error !== undefined && <div className="tool-error">{error}</div>}

        {result !== undefined && (
          <div className="tool-results">
            <div className="faint" style={{ marginBottom: 4 }}>
              {result.summary}
            </div>
            <table className="tool-table">
              <tbody>
                {result.rows.map((row, i) => (
                  <tr key={i}>
                    {row.cells.map((cell, j) => (
                      <td key={j} className={j === 0 ? "faint" : "mono"}>
                        {cell}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            {result.files.length > 0 && (
              <div className="faint" style={{ marginTop: 6 }}>
                {result.files.map((f) => (
                  <div key={f} className="mono">
                    {f}
                  </div>
                ))}
              </div>
            )}
            {result.warnings.length > 0 && (
              <div className="faint" style={{ marginTop: 6 }}>
                {result.warnings.map((w, i) => (
                  <div key={i}>{w}</div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
