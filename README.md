# cs2-lks-dumper

A C++ memory dumper for Counter-Strike 2 that extracts offsets, interfaces, buttons, and Source 2 schemas from the running `cs2.exe` process, and exports them in multiple programming language formats.

**Author: [Leksa667](https://github.com/Leksa667)**

This project is a C++ port / adaptation of the Rust-based [a2x/cs2-dumper](https://github.com/a2x/cs2-dumper), reimplemented with a focus on Windows-native memory reading, IDA-style pattern scanning, and direct Source 2 structure parsing.

## Features

- **Process attachment** — attaches to `cs2.exe` via `ReadProcessMemory` (Toolhelp32 snapshot enumeration)
- **PE parsing** — built-in PE viewer with export directory lookup and section enumeration
- **IDA-style pattern scanning** — flexible pattern engine with support for byte literals, wildcards, relative offsets (`jmp`/`call`), indirection, alignment, and more
- **Offset dumping** — pre-defined patterns for `client.dll`, `engine2.dll`, `inputsystem.dll`, `matchmaking.dll`, `soundsystem.dll`
- **Interface enumeration** — walks the `InterfaceReg` linked list in each module
- **Button enumeration** — walks the `KeyButton` linked list in `client.dll`
- **Schema dumping** — parses the Source 2 Schema System (`SchemaSystemTypeScope` → `UtlTsHash<SchemaClassBinding>` / `UtlTsHash<SchemaEnumBinding>`) including class fields, metadata (`MNetworkChangeCallback`, `MNetworkVarNames`), base classes, and enum members
- **Multi-language output** — generates bindings in 5 formats:
  - `cs` — C#
  - `hpp` — C++
  - `json` — JSON
  - `rs` — Rust
  - `zig` — Zig
- **Metadata export** — writes `info.json` with build number and timestamp

## Requirements

- Windows 10 / 11
- CMake 3.20+
- C++20 compiler (MSVC 2022 recommended)
- Counter-Strike 2 running

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Or use the provided script:

```bash
.\build.bat
```

The executable will be at `build\Release\cs2-lks-dumper.exe`.

## Usage

```bash
cs2-lks-dumper.exe
cs2-lks-dumper.exe -o output -f hpp,json
cs2-lks-dumper.exe -p cs2.exe -v
```

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --file-types` | Output formats: `cs`, `hpp`, `json`, `rs`, `zig` | all |
| `-o, --output` | Output directory | `output` |
| `-p, --process-name` | Process name | `cs2.exe` |
| `-i, --indent-size` | Spaces per indentation level | `4` |
| `-v, --verbose` | Verbosity (repeatable) | errors only |
| `--no-log-file` | Do not create `cs2-lks-dumper.log` | |

## Output Example

```
output/
├── buttons.cs / .hpp / .json / .rs / .zig
├── client.cs / .hpp / .json / .rs / .zig
├── engine2.cs / .hpp / .json / .rs / .zig
├── inputsystem.cs / .hpp / .json / .rs / .zig
├── matchmaking.cs / .hpp / .json / .rs / .zig
├── soundsystem.cs / .hpp / .json / .rs / .zig
├── info.json
```

## Project Structure

```
include/cs2dumper/
├── project.hpp          — project metadata (name, version, author)
├── types.hpp            — core data types (Rva, ModuleInfo, Class, Enum, AnalysisResult)
├── memory/
│   ├── address.hpp      — RIP-relative address resolution
│   └── process.hpp      — process attachment + memory reading
├── pe/
│   ├── pe_view.hpp      — PE parser (DOS, NT, sections, exports)
│   └── pattern_scanner.hpp — IDA-style pattern scanning engine
├── source2/
│   ├── tier0.hpp        — low-level Source 2 types (TsList)
│   ├── tier1.hpp        — UtlVector, UtlTsHash, UtlMemoryPool
│   ├── schema.hpp       — SchemaSystem structures
│   ├── client.hpp       — InterfaceReg, KeyButton
│   └── utl_ts_hash.hpp  — UtlTsHash walker
├── analysis/
│   ├── analyze.hpp      — orchestration entry point
│   ├── buttons.hpp      — button scan
│   ├── interfaces.hpp   — interface scan
│   ├── offsets.hpp      — offset pattern definitions
│   └── schemas.hpp      — schema system parser
├── output/
│   ├── dumper.hpp       — output orchestrator
│   ├── formatter.hpp    — indented text formatter
│   └── writers.hpp      — multi-language code generators
└── utils/
    └── string.hpp       — string case conversion utilities
```

## Acknowledgements

- [a2x/cs2-dumper](https://github.com/a2x/cs2-dumper) — the original Rust implementation that served as the reference for this project

## License

MIT — see [LICENSE](LICENSE). © 2026 Leksa667.
