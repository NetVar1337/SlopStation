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
