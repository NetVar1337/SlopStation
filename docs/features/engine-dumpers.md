# Engine dumpers

Two `re` actions turn a game engine's own metadata into an SDK: `il2cpp_dump` for Unity
IL2CPP builds and `ue_dump` for Unreal Engine 4/5. Both write files into `out_dir` on the
host and return counts plus any warnings. Neither uses game-specific signatures or
offsets: every table is found by checking its structure against the engine's own data.

## Unity IL2CPP: `re.il2cpp_dump`

```json
{ "tool": "re", "action": "il2cpp_dump",
  "params": { "metadata": "C:/game/Data/il2cpp_data/Metadata/global-metadata.dat",
              "binary": "C:/game/GameAssembly.dll", "out_dir": "C:/dumps/il2cpp" } }
```

| Parameter | Meaning |
| --- | --- |
| `metadata` | `global-metadata.dat`. Versions 24.0–24.5, 27.x, 29.x and 31 (sanity `0xFAB11BAF`). |
| `binary` | `GameAssembly.dll` (PE32+), `libil2cpp.so` (ELF64 x86-64/AArch64), a decrypted PS4 PRX, or an ELF from `target.ps4_dump_module`. |
| `module` | Instead of `binary`: a module loaded in the active target (local Windows, PS4, PS5). It is read from memory, so it is already relocated. |
| `out_dir` | Output folder. |
| `format` | Any of `cs`, `json`, `header`. Default: all three. |

Outputs:

- `dump.cs`: images, namespaces, classes with parents and interfaces, fields with offsets,
  properties, and methods with `RVA`/`Offset`/`VA` (Il2CppDumper layout). Generic method
  instances are listed under their definition when the tables resolve.
- `il2cpp.json`: the same data in machine-readable form, plus type sizes.
- `il2cpp.h`: one packed C struct per non-generic class (`_o`, with `klass`/`monitor`), value
  type (`_t`) and static field block (`_StaticFields`). Padding is explicit, so offsets
  and sizes match the runtime exactly. Value-type and generic members are byte blobs.

How it works: the metadata is parsed with bounds checks on every table. In the binary,
`Il2CppMetadataRegistration` is the table whose `fieldOffsetsCount` and
`typeDefinitionsSizesCount` both equal the metadata's type count. `Il2CppCodeRegistration`
is found through its `codeGenModules` array, whose modules carry the metadata's image names
(24.2+), or through the `methodPointers` table (24.0/24.1). The binary-side subversion
(24.2–24.5, 27.0–27.2, 29.0/29.1) is chosen by validating the generic and invoker pointer
tables. ELF files on disk get their `R_*_RELATIVE` relocations applied first. PS4
`PT_SCE_RELRO` segments are mapped like `PT_LOAD`.

Field offsets: value-type instance offsets have the 16-byte object header removed. A static
field with offset `-1` is thread-static. Literal (`const`) fields have no offset. If a
registration table is not found, the dump still runs and says what is missing in
`warnings`: no offsets, no method addresses, or names like `type_N` for fields whose type
lives only in the binary.

Encrypted retail SELFs cannot be read. Dump the module from the console first
(`target.ps4_dump_module {format:"elf"}`), or use `module` on the live target.

## Unreal Engine: `re.ue_dump`

```json
{ "tool": "re", "action": "ue_dump", "params": { "out_dir": "C:/dumps/ue" } }
{ "tool": "re", "action": "ue_dump",
  "params": { "gnames": "0x14A2B3C40", "gobjects": "0x14A2F0010", "out_dir": "C:/dumps/ue" } }
```

| Parameter | Meaning |
| --- | --- |
| `gnames` | Optional. An `FNamePool` address (4.23+; the address of its `Blocks` array works too), or a `TNameEntryArray` or the pointer to it (4.20–4.22). |
| `gobjects` | Optional. A `FUObjectArray` (or its `ObjObjects` member). |
| `module` | Optional. The module whose writable sections are searched. Default: the main module (`eboot.bin` on a PS4). |
| `version` | `auto` (default), `4.x` or `5.x`. A hint only: a mismatch with the detected layout adds a warning. |
| `max_objects` | Cap on the object array walk. Default 4,000,000. |
| `format` | `json`, `sdk`. Default: both. |

Outputs (Dumpspace-style): `ClassesInfo.json`, `StructsInfo.json`, `FunctionsInfo.json`,
`EnumsInfo.json`, `FNames.txt` (`index<TAB>name`) and `SDK.hpp`. `SDK.hpp` is packed with
explicit padding, so member offsets match the target. Containers without a definition in
the header (`TMap`, `TSet`, `FText`, delegates, soft/weak pointers) become byte blobs
annotated with their UE type.

How the tables are located:

- **Names.** An `FNamePool` is a `Blocks[]` array preceded by `CurrentBlock` and
  `CurrentByteCursor`. Its first entry must decode to `None` and the next to
  `ByteProperty`. Plain, wide, case-preserving and both header bit layouts are tried. On
  4.20–4.22 the same check runs against `TNameEntryArray` chunks.
- **Objects.** A chunked `TUObjectArray` must have consistent `Max`/`Num`/chunk counts. Its
  objects' `ClassPrivate` must chain to a UClass whose own class is itself, named `Class`.
  The item stride (0x18, 0x10 or 0x20) is detected.
- **Layout.** `SuperStruct` is the offset where UClass `Class` points to UClass `Struct`.
  FField-based (4.25+/5.x) properties are told apart from UProperty-based ones by voting
  over script structs. The `FField` `Next`/`Name` offsets (16- or 8-byte owner variant,
  5.1+) are validated along property chains. `FunctionFlags` is where `NumParms` matches
  the parameter count. The version is reported as `4.20-4.22`, `4.23-4.24`, `4.25-4.27` or
  `5.x` (`Vector` is 24 bytes on 5.x).

Reads go through a page cache: 4 KiB pages locally, 64 KiB pages on a console, so a PS4 or
PS5 dump costs far fewer round trips. If a layout guess cannot be confirmed, the dump keeps
going and names that guess in `warnings`. If auto-locate fails, pass `gnames`/`gobjects`
(from the returned values of an earlier run, an AOB match, or xrefs).

Not covered: 32-bit targets, `UE_FNAME_OUTLINE_NUMBER` builds (4-byte `FName`), and
engines with custom object layouts that move `ClassPrivate`/`NamePrivate`.

## Source engine (Titanfall-derived, e.g. Apex Legends): `re.source_dump`

```json
{ "tool": "re", "action": "source_dump", "params": { "out_dir": "C:/dumps/apex" } }
{ "tool": "re", "action": "source_dump",
  "params": { "head": "0x14A2B3C40", "out_dir": "C:/dumps/apex" } }
```

| Parameter | Meaning |
| --- | --- |
| `head` | Optional. The first `ClientClass*` of the game's class list (the `GetAllClasses` root). Skips the search. |
| `module` | Optional. The module whose writable sections are searched. Default: the main module (`eboot.bin` on a PS4). |
| `max_classes` | Cap on the ClientClass chain walk. Default 4096. |
| `format` | `json` (default). |

Attach to the game process first (`target.ps4_connect` + `target.attach`, or
`target.ps4_auto`). Apex Legends on PS4 is a 64-bit Titanfall-derived Source build, so the
stock Source SDK x64 `ClientClass`/`RecvTable`/`RecvProp` layouts apply and every table is
found by structure, not by game-specific signatures.

Outputs:

- `netvars.json`: flat `DT_Table->m_prop` → offset map (hazedumper layout) plus the
  located `head`. A `DPT_DataTable` prop contributes its own offset to its children; a
  `"0"`-prefixed baseclass prop contributes nothing. First table to define a name wins.
- `recvtables.json`: per-class entries (`class`, `table`, `class_id`, `recv_table`) with
  the raw `RecvProp` layout (name, type, offset, elements, stride, nested `data_table`).

How the list is located: every qword in the module's writable sections is checked as a
`ClientClass` candidate (printable `m_pNetworkName`, `m_pNext` null or aligned, and a
`m_pRecvTable` whose `DT_`-prefixed name, prop count and prop varnames validate). Nodes
nobody points at are chain heads; the longest validating chain wins. A chain shorter than
5 classes comes with a warning — the located node was probably mid-list, so pass the true
`head` (from xrefs on the engine's `GetAllClasses`, or the first run's return value).

Reads go through the same page cache as `ue_dump` (64 KiB pages on a console). Netvars
are the networked player/entity state (what PC offset sites list); statics like the
entity list or view matrix are not part of the RecvTable set — find those with
`memory.aob`/`debugger.ps4_xrefs_to` against the dumped module.

Not covered: 32-bit Source builds, and engines that renamed `DT_` tables or moved the
`RecvProp` fields (a wrong layout fails validation with `no ClientClass nodes`, not with
garbage offsets).

## Offsets that survive a patch

Three actions turn a one-off dump into a maintained offset set.

`memory.offsets_build` writes a manifest `memory.offsets_verify` accepts: each
named address gets an anchor pattern decoded in place, grown until it matches
exactly once inside the module's executable segment, plus that segment's
SHA-256 as the build fingerprint.

```json
{ "tool": "memory", "action": "offsets_build",
  "params": { "module": "eboot.bin", "out": "C:/dumps/apex/manifest.json",
              "offsets": [ { "name": "cl_entitylist", "addr": "0x14A2B3C40" },
                           { "name": "view_matrix", "addr": "0x14A2B0010", "aob_offset": -7 } ] } }
```

`aob_offset` shifts the anchor back from the target, for statics that are only
reachable through the instruction that loads them. Offsets with no unique
anchor come back in `problems[]` rather than silently producing a weak pattern.

`memory.offsets_diff` compares two manifests (or two `netvars.json` dumps) and
reports `stable` / `moved` / `missing` / `added`, with a `verdict` of
`compatible`, `moved` or `broken`. Run it after a game update, before touching
the console.

`memory.globals` finds the static globals a function touches: every RIP-relative
memory operand whose target lands in a module's data section. Scope it to a
function you already know (from a string xref or an RTTI vtable slot) and read
off what it loads — this is how `cl_entitylist` and view-matrix style statics are
located without a signature.

`re.source_dump` also writes `offsets.hpp` (one `constexpr` per netvar, grouped
by declaring table, in the shape a payload SDK consumes) and, with
`datamaps: true`, `datamaps.json` for the non-networked DataMap fields. The
DataMap layout drifts between engine branches, so a candidate is accepted only
when its own class-name string and every field record validate; nothing
validating is a warning, not a wrong dump.

## Long dumps

`memory.dump`, `memory.dump_regions`, `target.dump_module`,
`target.ps4_dump_module` and the engine dumpers' module reads are
double-buffered: chunk k+1 streams in while chunk k is validated or written to
disk. A failed chunk is salvaged page by page, so one unreadable page costs
4 KiB of zero-fill instead of the whole chunk. Console dumps use 8 MiB chunks
(one ps4debug/ps5debug command each). All of them honour the request's cancel
token and publish a byte counter to `notifications/progress`.
