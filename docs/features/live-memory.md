# Live memory

The `memory` tool works on the console session and on a local Windows process alike.

- Read/write in hex, UTF-8, integer and float formats; allocate, free, change protection.
- Initial and refined numeric scans: exact/range/changed/unchanged, signed/unsigned/float
  widths, rounding, region/protection/alignment filters, worker/chunk/result caps.
- AOB wildcard search, pointer-chain scans and verification, signature generation, live
  crypto-constant search.
- Memory snapshots with compare/list/free; `scan_save`/`scan_load` persist an address-list
  scan across restarts, and `scan_export {path}` writes the current hit set as
  `address,type,value` CSV.
- `dissect {addr, size}` classifies what each 8-byte slot of an unknown object is: pointer
  to code, object or string, float, double, integer, or text.
- `watch_export_ct {path}` / `watch_import_ct {path}` move the watchlist to and from a
  Cheat Engine `.CT` table.
- `offsets_verify`: fingerprint-gated offset manifests. A manifest pins the build (title
  ID, app version, SHA-256 of the module's executable segment) and gives every offset an
  anchor signature that must match exactly once; any mismatch returns no addresses at all.
  Format in [`src/core/memory/offsets.hpp`](https://github.com/NetVar1337/SlopStation/blob/main/src/core/memory/offsets.hpp).
- Shared watchlist sampled about 10 Hz with freeze writes; UI and MCP edits appear in
  both. `watch_freeze_once` releases after the first write-back and `watch_undo` restores
  the captured value.

## Scans

```json
{ "tool": "memory", "action": "scan",
  "params": { "kind": "exact", "width": "u32", "value": 100 } }
{ "tool": "memory", "action": "rescan",
  "params": { "kind": "decreased", "width": "u32" } }
{ "tool": "memory", "action": "scan_state", "params": {} }
```

Kinds: `exact`, `between`, `bigger`, `smaller`, `unknown`, `increased`, `increased_by`,
`increased_percent`, `decreased`, `decreased_by`, `changed`, `unchanged`. Widths: `i8`,
`u8`, `i16`, `u16`, `i32`, `u32`, `i64`, `u64`, `f32`, `f64`, or `all`.

Useful extras on `scan`: `begin`/`end` to bound the range, `alignment` (fastscan),
`tail` (1–8 hex digits, "ends with" fastscan), `writable`/`executable` region filters,
`max_results`, `threads`, `chunk_bytes`.

`scan` and `rescan` list `limit` rows (default 100, max 10000) starting at `offset`, and
reply with `total`, `offset` and `next_offset` (`null` on the last page). Walk the stored
hits without touching the target again:

```json
{ "tool": "memory", "action": "scan_results", "params": { "offset": 1000, "limit": 1000 } }
```

## Watchlist and freeze

```json
{ "tool": "memory", "action": "watch_add",
  "params": { "addr": "0x200001000", "width": "u32", "label": "player.health" } }
{ "tool": "memory", "action": "watch_set", "params": { "id": 1, "freeze": true } }
```

`watch_add` latches the live value immediately, so a freeze has something to write back;
`freeze_armed` in the reply tells you whether it actually armed.

Every entry keeps a ring of its last 512 samples: one per service tick when the value
changed, plus one per second while it holds still. `ms` is wall-clock epoch milliseconds.

```json
{ "tool": "memory", "action": "watch_history", "params": { "id": 1, "limit": 256 } }
```

The reply is `{id, width, samples:[{ms, value, bits, text}]}`, oldest first; `value` is
numeric (floats decoded). Removing or clearing the entry drops its history.

## AOB and pointer chains

```json
{ "tool": "memory", "action": "aob", "params": { "pattern": "48 8B ?? ?? 89" } }
{ "tool": "memory", "action": "pointerscan",
  "params": { "target": "0x200001000", "depth": 5, "max_results": 32 } }
{ "tool": "memory", "action": "pointerscan_verify",
  "params": { "chains": [ { "base": "0x200000000", "offsets": [16, 32] } ] } }
```

`??` matches any byte. `pointerscan` walks static roots and reads pointer chains out of
live memory, returning the address path for each hit; `pointerscan_verify` re-checks
explicit chains (or the last pointerscan of this target) against the current session.

## Snapshots and diffs

```json
{ "tool": "memory", "action": "snapshot", "params": { "label": "before" } }
{ "tool": "memory", "action": "diff", "params": { "a": 1, "b": 2 } }
{ "tool": "memory", "action": "snapshots", "params": {} }
```

`diff` takes two snapshot ids and returns the changed `offset`/`length` ranges;
`snapshot_free {id}` releases one, and `snapshots` lists what is held.

## Dumping raw memory

```json
{ "tool": "memory", "action": "dump",
  "params": { "addr": "0x200000000", "len": 1048576, "path": "C:/tmp/span.bin" } }
{ "tool": "memory", "action": "dump_regions",
  "params": { "dir": "C:/tmp/regions", "writable_only": true } }
```

`dump` streams any span of the active target (local, PS4, PS5) to `path`. Unreadable pages
are zero-filled and counted in `unreadable_bytes`; `strict: true` fails instead. The cap is
4 GiB. The file is written to `<path>.part` and renamed, so a failed dump leaves no torn
file.

`dump_regions` writes every committed readable region to `<dir>/<base>-<size>.bin` (hex)
plus `index.json` with `{base, size, protect, type, module, file}` per region. Filter with
`writable_only` / `exec_only`; `max_total` (default 4 GiB) is a byte budget, and regions
that do not fit are skipped and counted in `skipped_over_budget`.

## Dissecting an unknown object

```json
{ "tool": "memory", "action": "dissect", "params": { "addr": "0x2004A0000", "size": 256 } }
```

`size` defaults to 256 bytes and is capped at 4096; the reply labels every 8-byte slot as a
pointer to code, object or string, a float, a double, an integer or text, so an unknown
structure can be mapped before `types.declare` describes it.

## Offsets that survive a game update

`offsets_verify` takes a manifest that pins the exact build and gives every offset an
anchor signature. If the game updated, the fingerprints or signatures stop matching and the
call returns no addresses instead of silently wrong ones.

## Walkthrough

[Find and freeze a value](../tutorials/local-process.md) — the scanner and watchlist on a
local process, and [Live debugging](live-debugging.md) for the "who writes this" flow.

## Retrying the holes in a dump

A dump of a live process is rarely complete: guard pages, regions the payload
cannot read, and pages that are not mapped yet all become zero-filled holes.
`memory.dump` reports them as spans instead of only a byte count:

```json
{ "tool": "memory", "action": "dump",
  "params": { "addr": "0x400000", "len": "0x10000000", "path": "C:/dumps/eboot.bin" } }
```

The reply carries `holes: [{addr, size, offset}]`. Once the game maps those
pages (or you change their protection), `memory.dump_holes` re-reads just those
spans and patches them into the existing file in place:

```json
{ "tool": "memory", "action": "dump_holes",
  "params": { "addr": "0x400000", "len": "0x10000000", "path": "C:/dumps/eboot.bin",
              "holes": [ { "addr": "0x41234000", "size": 4096 } ] } }
```

`bytes_filled` is what could now be read, `remaining` lists the spans that are
still unreadable, and `complete` is true when nothing is left. `addr`/`len` must
match the original dump so the offsets line up. `dump_regions` records the same
`holes` array per region in its `index.json`.

## Code that belongs to no module

JIT output, runtime-unpacked stubs and generated thunks live in executable pages
outside every loaded module, so a module dump structurally cannot see them.
`memory.dynamic_code` lists those regions and optionally dumps them:

```json
{ "tool": "memory", "action": "dynamic_code", "params": { "dir": "C:/dumps/dyn" } }
```

Each entry carries `base`, `size`, `protect` and `type`; with `dir` set, each
region is also written as `dyn-<base>-<size>.bin`. An empty result means nothing
is JIT'd at that moment, not that the target has no dynamic code.
