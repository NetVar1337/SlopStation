#!/usr/bin/env python3
"""Read-only PS4 feature sweep: process attach + memory/disasm/dump/scan reads.

Run: SLOP_API=http://127.0.0.1:8765 SLOP_TOKEN=<mcp token> python tools/ps4_readonly_test.py
(the engine must be connected to the console; the game must be running).

Nothing here stops the process, arms a debugger, writes memory or executes code:
no ps4_attach (debug), no bp/watch, no continue/wait/step/until/trace/call,
no write/protect/alloc/free, no emulate, no gdb.start, no access_start.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

import os
BASE = os.environ.get("SLOP_API", "http://127.0.0.1:8765") + "/api/v1"
TOKEN = os.environ.get("SLOP_TOKEN", "").strip()
if not TOKEN:
    raise SystemExit("setup: set SLOP_TOKEN to the engine MCP token (settings.json mcp_token)")
WORK = os.environ.get("SLOP_PS4_OUT", "ps4-readonly-out")
results: list[tuple[str, bool, str]] = []


def call(tool: str, action: str, params: dict | None = None, timeout: float = 180) -> dict:
    body = json.dumps({"tool": tool, "action": action, "params": params or {}}).encode()
    for attempt in range(5):
        req = urllib.request.Request(
            BASE, data=body,
            headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            if e.code == 429 or "-32002" in text:
                time.sleep(1.5)
                continue
            try:
                return json.loads(text)
            except Exception:
                return {"ok": False, "data": {"http": e.code, "body": text[:200]}}
        except Exception as e:
            if attempt == 4:
                return {"ok": False, "data": {"exception": str(e)[:200]}}
            time.sleep(1.0)
    return {"ok": False, "data": {"exception": "retries exhausted"}}


def case(label, tool, action, params=None, expect="ok", check=None, timeout=180) -> dict:
    r = call(tool, action, params, timeout)
    ok = {"ok": r.get("ok") is True, "error": r.get("ok") is not True, "any": True}[expect]
    note = ""
    if ok and check is not None:
        try:
            v = check(r.get("data") or {})
            if v is False:
                ok, note = False, "check failed"
            elif isinstance(v, str):
                note = v
        except Exception as e:
            ok, note = False, f"check threw: {e!s:.120}"
    results.append((label, ok, note))
    print(f"[{'PASS' if ok else 'FAIL'}] {label} {note}")
    if not ok:
        print("   ->", json.dumps(r.get("data"))[:280])
    return r


def main() -> int:
    st = call("target", "status").get("data") or {}
    if (st.get("backend") or "").upper() != "PS4" or not st.get("ps4", {}).get("connected"):
        print("setup: engine is not connected to the console:", json.dumps(st)[:200])
        return 2
    if st.get("attached"):
        print(f"already attached to {st.get('name')} pid {st.get('pid')}")
    else:
        procs = call("target", "list").get("data", {}).get("processes", [])
        game = next((p for p in procs if p.get("name") == "eboot.bin"), None)
        if not game:
            print("setup: eboot.bin is not running (start the game first)")
            return 2
        a = case("target.attach (read-only attach)", "target", "attach", {"pid": game["pid"]},
                 check=lambda p: p.get("attached") is True)
        if not a.get("ok"):
            return 2

    st = call("target", "status").get("data") or {}
    pid = st.get("pid")
    print(f"attached: {st.get('name')} pid {pid} fw {st.get('fw')} debug_attached={st.get('ps4_debug_attached')}")

    # ---- target surface ----
    case("target.status", "target", "status", check=lambda p: p.get("attached") is True)
    case("debugger.ps4_status", "debugger", "ps4_status",
         check=lambda p: p.get("connected") is True)
    case("target.list", "target", "list", check=lambda p: p.get("count", 0) > 10)
    mods = case("target.modules", "target", "modules",
                check=lambda p: p.get("count", 0) > 100 and p["modules"][0]["base"] == 0x400000)
    case("target.threads", "target", "threads", check=lambda p: p.get("count", 0) >= 1)
    regs = case("target.regions", "target", "regions", check=lambda p: p.get("count", 0) > 10)
    case("target.consoles_list", "target", "consoles_list", expect="any")

    modules = mods.get("data", {}).get("modules", [])
    game_mod = next((m for m in modules if m["name"] == "executable"), modules[0])
    small = next((m for m in modules if m["name"] == "libc.prx"), modules[1])
    gbase, gsize = game_mod["base"], game_mod["size"]
    sbase, ssize = small["base"], small["size"]
    print(f"game module: base {hex(gbase)} size {gsize}; small module: {small['name']} {hex(sbase)}")

    # ---- memory reads on the real image ----
    case("memory.read hex (module header)", "memory", "read", {"addr": gbase, "len": 64},
         check=lambda p: len(p.get("hex", "")) == 128)
    case("memory.read u32", "memory", "read", {"addr": gbase, "len": 32, "format": "u32"},
         check=lambda p: len(p.get("values", [])) == 8)
    case("memory.read f32", "memory", "read", {"addr": gbase + 0x1000, "len": 32, "format": "f32"},
         expect="any")
    case("memory.read utf8 (module path strings)", "memory", "read",
         {"addr": sbase, "len": 32, "format": "utf8"}, expect="any")
    case("memory.read unmapped (must fail)", "memory", "read",
         {"addr": "0xFFFFFFFFFF000000", "len": 16}, expect="error")
    case("memory.read past module end (must fail or partial)", "memory", "read",
         {"addr": sbase + ssize - 8, "len": 64}, expect="any")

    # ---- live disassembly ----
    case("disasm.disassemble live", "disasm", "disassemble", {"addr": gbase + 0x1000, "count": 8},
         check=lambda p: len(json.dumps(p)) > 50)
    case("debugger.ps4_disasm (payload zydis)", "debugger", "ps4_disasm",
         {"addr": gbase + 0x1000, "len": 64, "max": 16}, expect="any")

    # ---- structure / snapshot / diff (read-only) ----
    case("memory.dissect", "memory", "dissect", {"addr": sbase, "size": 256}, expect="any")
    snap_a = case("memory.snapshot A", "memory", "snapshot", {"addr": sbase, "len": 0x2000},
                  expect="any", timeout=300)
    snap_b = case("memory.snapshot B", "memory", "snapshot", {"addr": sbase, "len": 0x2000},
                  expect="any", timeout=300)
    ia = (snap_a.get("data") or {}).get("id")
    ib = (snap_b.get("data") or {}).get("id")
    case("memory.snapshots", "memory", "snapshots", expect="any")
    if ia is not None and ib is not None:
        case("memory.diff A/B", "memory", "diff", {"a": ia, "b": ib}, expect="any", timeout=300)
        case("memory.snapshot_free", "memory", "snapshot_free", {"id": ia}, expect="any")

    # ---- scans over console memory (payload + host, both read-only) ----
    case("debugger.ps4_scan (module range)", "debugger", "ps4_scan",
         {"addr": sbase, "len": min(ssize, 0x20000), "value_type": "u32", "compare": "unknown",
          "keep_first": True}, expect="any", timeout=300)
    case("debugger.ps4_scan_state", "debugger", "ps4_scan_state", expect="any")
    case("debugger.ps4_rescan", "debugger", "ps4_rescan", {"compare": "unchanged"}, expect="any")
    case("debugger.ps4_scan_aob", "debugger", "ps4_scan_aob",
         {"addr": gbase, "len": 0x20000, "pattern": "48 8B ?? ?? 90"}, expect="any", timeout=300)
    case("debugger.ps4_scan_reset", "debugger", "ps4_scan_reset", expect="any")
    case("debugger.ps4_turbo_caps", "debugger", "ps4_turbo_caps", expect="any")
    case("debugger.ps4_turbo_regions", "debugger", "ps4_turbo_regions", expect="any")
    case("debugger.ps4_turbo_config", "debugger", "ps4_turbo_config", expect="any")
    case("debugger.ps4_turbo_scan (small module)", "debugger", "ps4_turbo_scan",
         {"regions": "writable", "value_type": "u32", "compare": "unknown", "keep_first": True},
         expect="any", timeout=600)
    case("debugger.ps4_turbo_results", "debugger", "ps4_turbo_results",
         {"start": 0, "count": 5}, expect="any")
    case("debugger.ps4_turbo_end", "debugger", "ps4_turbo_end", expect="any")

    case("memory.scan exact u32 (module range)", "memory", "scan",
         {"kind": "exact", "width": "u32", "value": 0x464C457F, "begin": gbase,
          "end": gbase + 0x10000, "limit": 5}, expect="any", timeout=300)
    case("memory.scan_results", "memory", "scan_results", {"offset": 0, "limit": 5}, expect="any")
    case("memory.scan_state", "memory", "scan_state", expect="any")
    case("memory.aob (module range)", "memory", "aob",
         {"pattern": "7F 45 4C 46", "engine": "console", "begin": gbase,
          "end": gbase + 0x10000}, expect="any", timeout=300)
    case("memory.pointerscan (depth 2)", "memory", "pointerscan",
         {"target": sbase, "depth": 2, "max_results": 8}, expect="any", timeout=300)

    # ---- watch list (the service only reads) ----
    w = case("memory.watch_add", "memory", "watch_add",
             {"addr": sbase, "width": "u32", "label": "module_head"})
    wid = (w.get("data") or {}).get("id")
    case("memory.watch_list", "memory", "watch_list",
         check=lambda p: p.get("returned", len(p.get("entries", []))) >= 1)
    if wid is not None:
        time.sleep(1.2)
        case("memory.watch_history", "memory", "watch_history", {"id": wid, "limit": 16},
             check=lambda p: isinstance(p.get("samples"), list))
        case("memory.watch_remove", "memory", "watch_remove", {"id": wid})

    # ---- dumps (read the console, write host files) ----
    case("memory.dump span", "memory", "dump",
         {"addr": sbase, "len": 0x1000, "path": WORK + "/span.bin"},
         check=lambda p: p.get("bytes_written", 0) == 0x1000, timeout=300)
    case("memory.dump_regions (16 MiB cap)", "memory", "dump_regions",
         {"dir": WORK + "/regions", "writable_only": True, "max_total": 16 * 1024 * 1024},
         expect="any", timeout=900)
    case("target.ps4_dump_module elf", "target", "ps4_dump_module",
         {"name": small["name"], "path": WORK + "/" + small["name"] + ".elf", "format": "elf",
          "load": True}, check=lambda p: p.get("bytes_written", 0) > 0, timeout=900)
    case("target.ps4_dump_module raw", "target", "ps4_dump_module",
         {"base": sbase, "path": WORK + "/raw.bin", "format": "raw"}, expect="any", timeout=900)
    case("debugger.ps4_snapshot", "debugger", "ps4_snapshot",
         {"addr": sbase, "len": 0x800, "path": WORK + "/snap.bin"}, expect="any", timeout=300)
    case("debugger.ps4_modules", "debugger", "ps4_modules", expect="any")

    # ---- static analysis of the dump (local, no console) ----
    case("disasm.loaded", "disasm", "loaded", expect="any")
    case("disasm.functions", "disasm", "functions", {"limit": 20}, expect="any")
    case("disasm.strings", "disasm", "strings", {"limit": 20}, expect="any")
    case("analyze.packer (dumped elf)", "analyze", "packer",
         {"path": WORK + "/" + small["name"] + ".elf"}, expect="any")

    # ---- script read-only ----
    case("script.run slop.mem.read", "script", "run",
         {"code": f"local h = slop.mem.read({sbase}, 16); return h and #h or 'nil'"},
         expect="any")

    # ---- forbidden-in-read-only actions must be refused or unused: prove we did not
    case("no debug session was attached", "target", "status",
         check=lambda p: p.get("ps4_debug_attached") is not True)

    failed = [r for r in results if not r[1]]
    print(f"\n=== PS4 read-only sweep: {len(results) - len(failed)}/{len(results)} passed ===")
    for label, _, note in failed:
        print(f"  FAILED: {label} {note}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
