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
  `record_trace { "out_dir": "C:\\traces", "target": "C:\\path\\app.exe arg" }`.
  If the target needs a specific environment or working directory to run — a Qt app's
  `QT_QPA_PLATFORM_PLUGIN_PATH`, or an anti-analysis "run me from here" guard — pass
  `"env": ["KEY=VALUE", …]` and/or `"working_dir": "C:\\path"`; they're applied to the
  recorded target (the recorder inherits the server's env otherwise).
- **Open** an existing trace:
  `open_trace { "path": "C:\\traces\\app01.run" }` — returns
  `@$curprocess.TTD.Lifetime` (e.g. `[C:0, 124:8C2]`), confirming replay is live. It also
  flags an **unindexed** `.run` (freshly recorded traces have no `.idx`): the first
  data-model query then builds an in-memory index and can run long — let it finish.
  `index_trace {}` builds a **persistent** `.idx` (`!ttdext.index`) so queries and re-opens
  are fast.

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
- **Never run an unbounded memory search on a trace.** A whole-address-space
  `execute { "command": "s -u 0 L?0x400000000000 …" }` sends the engine into a scan that can
  run for minutes — and it wedges the single engine thread, so every later tool call times
  out queued behind it. **Scope every search** to a real region: a module range (`lm`), a
  heap segment from the PEB (`dt ntdll!_PEB @$peb ProcessHeap`), or a stack window — and
  prefer the indexed data model (`ttd_calls`/`ttd_memory`) over raw `s`. If you do wedge it,
  the only recovery is to kill `windbg-mcp.exe` and reconnect (`/mcp`), then re-open the trace.
- **`registers {}` empty** → no thread context at this position (a module-load break, or a
  bare `goto_position 0`). Travel to a settled position after a `go`/breakpoint, or read one
  register with `execute { "command": "r rip" }`.

## Technique: tabulate a pure function for a solver

To recover "what input passes this check" when the check is a math function of the input
(a hash, a per-digit transform), **evaluate the function directly** instead of reversing it.
On a **live** target (`attach_process`), break at the function's call site, then loop:
set the argument registers, set `rip` to the call site, `go` to just past the call, read the
return — for every input you care about. A WinDbg `.for` script with `.logopen` dumps the
whole table to a file; feed it to an SMT solver (e.g. Z3). See the FlareAuthenticator TTD
walkthrough (`docs/flareauthenticator-ttd-walkthrough.md`) for a full worked example.
(Watch the `.for` **radix**: the default is 16, so `10` means `0x10` — write bounds as `0xa`.)
