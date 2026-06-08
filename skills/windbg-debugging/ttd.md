# Playbook: Time Travel Debugging (`.run` traces)

**Goal:** record (or open) a deterministic user-mode trace, navigate it forward and
backward, and answer questions with the TTD data model (every call to a function, every
access to an address, the module/thread/exception timeline).

**Prerequisite:** the **WinDbg engine must be bundled** next to the binary — System32's
engine rejects `.run` files with `0x80070057`. See [setup.md](setup.md). Replay needs no
elevation; **recording does**.

TTD positions are `major:minor` (a sequencing point and a step within it), not wall-clock.

## 1. Get a trace

- **Record** (Administrator, `TTD.exe` on `PATH`):
  `record_trace { "out_dir": "C:\\traces", "target": "C:\\path\\app.exe arg" }`
- **Open** an existing trace:
  `open_trace { "path": "C:\\traces\\app01.run" }` — returns
  `@$curprocess.TTD.Lifetime` (e.g. `[C:0, 124:8C2]`), confirming replay is live and giving
  the position span. If the index is stale, `index_trace {}` (`!tt.index`).

## 2. Navigate — forward and backward

| Tool | cmd | UI |
|------|-----|----|
| `go` | `g` | F9 continue |
| `step_over` / `step_into` | `p` / `t` | F8 / F7 |
| `reverse_go` | `g-` | Shift+F9 reverse continue |
| `step_over_back` / `step_back` | `p-` / `t-` | Shift+F8 / Shift+F7 |
| `goto_position` | `!tt` | go to timestamp |

Typical loop: `set_breakpoint { "expression": "0x..." }` → `goto_position { "position": "0" }`
→ `go {}` (stops at the first hit, reporting `Time Travel Position`). From there `go` again
for the next hit forward, `reverse_go` to step back to the previous hit, or single-step in
either direction. Jump anywhere with `goto_position { "position": "25:508" }`.

> **Stepping needs a stop context.** Step *after* a `go`/breakpoint hit. Stepping straight
> off `goto_position 0` (before any thread is live) returns `0x80040205` — `go` somewhere
> first.

## 3. Analyze with the data model

- **Calls to a function (across the whole trace):**
  `ttd_calls { "function": "ucrtbase!__stdio_common_vfprintf" }` — each result carries
  time, thread, parameters, and return value. Wrap with `dx` LINQ to filter or project:
  `dx { "expression": "@$cursession.TTD.Calls(\"ntdll!NtCreateFile\").Where(c => c.ReturnValue != 0).Count()" }`
  Wildcards work: `ttd_calls { "function": "ntdll!Nt*" }`.
- **Accesses to a memory range:**
  `ttd_memory { "address": "0x...", "size": 14, "mode": "r" }` — every read/write/execute
  (`mode` = any combination of `r`/`w`/`e`/`c`; omit for all). Reports position, IP, and
  access type for each.
- **Event timeline (modules / threads / exceptions):** `ttd_events {}`
  (`dx -r2 @$curprocess.TTD.Events`). Note: `Events` and `Threads` hang off
  `@$curprocess.TTD`; `Calls` and `Memory` hang off `@$cursession.TTD`.
- **Anything else:** raw `dx { "expression": "..." }`, e.g.
  `-g @$curprocess.TTD.Threads` or
  `-g @$curprocess.TTD.Events.Where(e => e.Type == "ModuleLoaded")`.

## 4. Calls with symbols (the part that needs PDBs)

Symbol names like `ucrtbase!__stdio_common_vfprintf` only resolve after a settled context:

```text
execute { "command": ".sympath srv*C:\\ProgramData\\Dbg\\sym*https://msdl.microsoft.com/download/symbols" }
set_breakpoint { "expression": "0x..." }
goto_position  { "position": "0" }
go {}
execute { "command": ".reload /f" }
execute { "command": "lm m <mod>" }     # want "(pdb symbols)", not "(export symbols)"
```

Then `ttd_calls`/`dx` by name work. To inspect a specific call, travel to it
(`goto_position { "position": "25:508" }`) and read `registers {}` / arguments.

## Pitfalls

- **`.run` won't open / `0x80070057`** → System32 engine; bundle the WinDbg engine
  ([setup.md](setup.md)).
- **`module!name` won't resolve / `(export symbols)` only** → `msdia140.dll` not bundled,
  no `.sympath`, or you reloaded off a bare `!tt`. Bundle it, set the path, `go` to a stop,
  `.reload /f`.
- **`lm m <mod>` looks empty but full `lm` shows the module** → its symbols aren't loaded;
  `.reload` at a stopped position.
- The `__stdio_common_vfprintf` display alias has two underscores; `_stdio_common_vfprintf`
  is the alias — match the real symbol.
