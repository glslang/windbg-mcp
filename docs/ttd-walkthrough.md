# Walkthrough: analyzing a TTD trace with windbg-mcp

A hands-on tour of the Time Travel Debugging tools, using the
[`xusheng6/TTD_lab`](https://github.com/xusheng6/TTD_lab) `helloworld` sample. It mirrors that lab's
exercises (record → load → navigate forward/back → analyze with Calls/Memory/Events) but drives them
through this MCP server instead of a GUI.

Everything below is shown as a tool call (`tool_name { args }`) followed by the real output. An MCP
client/agent issues these as `tools/call`; the same flow works from any client.

## 0. Prerequisites

- A trace file, e.g. `C:\workspace\TTD_lab\helloworld01.run`. Record one with
  `record_trace` (needs Administrator) or the standalone `TTD.exe`.
- **The WinDbg engine bundled next to the binary** — System32's `dbgeng.dll` cannot replay `.run`
  traces. See the README's *TTD engine* section; the one-time copy brings in `dbgeng.dll`, the
  `ttd\` data-model/replay extensions, **`msdia140.dll`** (PDB parser) and `symsrv.dll`.
- For symbol *names* (e.g. counting `printf`): a symbol path with the PDBs available (below).

The target, `helloworld.c`:

```c
int main(int argc, char **argv)
{
    int i;
    printf("Hello, world!\n");
    printf("argc: %d\n", argc);
    for (i = 0; i < argc; ++i)
        printf("argv[%d]: %s\n", i, argv[i]);
    return 10;
}
```

It was recorded with no extra arguments (`argc == 1`), so it makes **3** `printf` calls and exits 10.

## 1. Open the trace

```text
open_trace { "path": "C:\\workspace\\TTD_lab\\helloworld01.run" }
```

```text
@$curprocess.TTD.Lifetime : [C:0, 124:8C2]
    MinPosition : C:0
    MaxPosition : 124:8C2
```

The reported `Lifetime` confirms TTD replay is live and gives the position span. TTD positions are
`major:minor` (a sequencing point and a step within it), not wall-clock time.

## 2. Survey the trace (the Events widget)

`ttd_events` lists module loads/unloads, thread create/exit and exceptions — it runs
`dx -r2 @$curprocess.TTD.Events`, so you get the full event objects. For just a tally:

```text
dx { "expression": "@$curprocess.TTD.Events.Count()" }
```

```text
@$curprocess.TTD.Events.Count() : 0x16        # 22 events
```

Module-load timeline (a raw `dx` with LINQ — `ttd_events` is the convenience wrapper):

```text
dx { "expression": "-g @$curprocess.TTD.Events.Where(e => e.Type == \"ModuleLoaded\").Select(e => new { Pos = e.Position, Mod = e.Module.Name })" }
```

```text
=          = Pos   = Mod
= [0x0]    - 2:0   - C:\workspace\TTD_lab\helloworld.exe
= [0x1]    - 3:0   - C:\Windows\SYSTEM32\VCRUNTIME140.dll
= [0x2]    - 4:0   - C:\Windows\SYSTEM32\apphelp.dll
= [0x3]    - 5:0   - C:\Windows\System32\ucrtbase.dll
= [0x4]    - 6:0   - C:\Windows\System32\KERNELBASE.dll
= [0x5]    - 7:0   - C:\Windows\System32\KERNEL32.DLL
= [0x6]    - 8:0   - C:\Windows\SYSTEM32\ntdll.dll
= [0x7]    - D3:0  - C:\Windows\System32\msvcrt.dll
= [0x8]    - D8:0  - C:\Windows\SYSTEM32\kernel.appcore.dll
```

Threads (`@$curprocess.TTD.Threads`) — the main thread plus a short-lived worker:

```text
dx { "expression": "-g @$curprocess.TTD.Threads" }
```

```text
= [0x0] UID:2 TID:0x1324 Lifetime [A:0, 125:0]  ActiveTime [C:0, 124:8C2]
= [0x1] UID:3 TID:0xFE4  Lifetime [0:0, ...]    ActiveTime [91:0, B3:0]
```

## 3. Navigate — forward and backward (the lab's Part 3)

The control tools map to a debugger UI's F-keys and their Shift (reverse) variants:

| Tool | cmd | UI |
|---|---|---|
| `go` | `g` | F9 continue |
| `step_over` / `step_into` | `p` / `t` | F8 / F7 |
| `reverse_go` | `g-` | Shift+F9 reverse continue |
| `step_over_back` / `step_back` | `p-` / `t-` | Shift+F8 / Shift+F7 |
| `goto_position` | `!tt` | Shift+G goto timestamp |

Set a code breakpoint, jump to the start, and continue forward to it — then reverse:

```text
set_breakpoint { "expression": "0x7ff887e453e4" }     # ucrtbase format-string read loop
goto_position  { "position": "0" }                    # start of trace
go {}
```

```text
Breakpoint 0 hit
Time Travel Position: 27:50E
```

```text
go {}            → Time Travel Position: 27:550       # next hit, forward
reverse_go {}    → Time Travel Position: 27:50E       # back to previous hit  ← time travel
step_into {}     → 27:50F   step_into {} → 27:510     # single-step forward
step_back {}     → 27:50F                             # single-step backward
```

> **Note:** single-stepping needs a real stop context. Step *after* a `go`/breakpoint hit. Stepping
> straight off a bare `goto_position` to the very start of a trace (before any thread is live)
> returns `0x80040205` — `go` somewhere first.

## 4. Memory analysis (the Memory widget)

`ttd_memory` reports every access to an address range across the whole trace. Find every read of the
`"Hello, world!"` string (its address comes from a memory search — see §5 for how, or just read it
with `execute { "command": "s -a helloworld L?0x7000 \"Hello\"" }`):

```text
ttd_memory { "address": "0x7ff629fe2210", "size": 14, "mode": "r" }
```

```text
# 14 read records — one per byte — all from the same instruction:
= Pos     = IP             = Acc
= 27:50E  - 0x7ff887e453e4 - Read
= 27:550  - 0x7ff887e453e4 - Read
  ... (14 total) ...
```

That single instruction reading the string 14 times *is* `printf` walking the format string — and
note the positions match the breakpoint hits from §3.

## 5. Call analysis with symbols (the Calls widget — lab Ex 4.3)

This is the only part that needs PDB symbols. Point at a symbol store, then **reload at a stopped
position** (after a `go`, not straight off a `!tt` — the settled context is what lets the module's
PDB load and `module!name` lookups resolve):

```text
execute { "command": ".sympath srv*C:\\ProgramData\\Dbg\\sym*https://msdl.microsoft.com/download/symbols" }
set_breakpoint { "expression": "0x7ff887e453e4" }
goto_position  { "position": "0" }
go {}
execute { "command": ".reload /f" }
execute { "command": "lm m ucrtbase" }
```

```text
ucrtbase   (pdb symbols)   ...\ucrtbase.pdb\ACEA08EF1B94F30576F5085FC95B3A841\ucrtbase.pdb
```

`(pdb symbols)` (not `(export symbols)`) means it worked. Now count the `printf` implementation:

```text
ttd_calls { "function": "ucrtbase!__stdio_common_vfprintf" }
dx        { "expression": "@$cursession.TTD.Calls(\"ucrtbase!__stdio_common_vfprintf\").Count()" }
```

```text
@$cursession.TTD.Calls("ucrtbase!__stdio_common_vfprintf").Count() : 0x3
```

**3 calls** — exactly the `printf`s in `main`. (The symbol is `__stdio_common_vfprintf`, two
underscores; the lab's `_stdio_common_vfprintf` is the display alias.) Pull the format string of
each call (3rd x64 argument → `r8` → `Parameters[2]`):

```text
dx { "expression": "-g @$cursession.TTD.Calls(\"ucrtbase!__stdio_common_vfprintf\").Select(c => new { Time = c.TimeStart, Format = ((char*)c.Parameters[2]) })" }
```

```text
= Time     = Format
= 25:508   - "Hello, world!."
= 29:12D   - "argc: %d."
= 2B:131   - "argv[%d]: %s."
```

Double-click equivalent — travel to the first call and inspect it:

```text
goto_position { "position": "25:508" }
registers {}                              # r8 holds the format pointer
```

## Lab exercise → tool cheat sheet

| Lab exercise | Tools |
|---|---|
| 3 — load + navigate | `open_trace`, `goto_position`, `go`/`reverse_go`, `step_into`/`step_back`, `set_breakpoint` |
| 4.1 — Events widget | `ttd_events` (threads / modules / exceptions); double-click ≈ `goto_position` on an event's `.Position` |
| 4.3 — Calls widget | `ttd_calls("mod!func")`, then `dx … .Count()` / `.Select(...)`; return-address filtering via `.Where(c => c.ReturnAddress …)` |
| 4.4 — Memory widget | `ttd_memory(addr, size, "rwec")` |
| anything else | `execute` (raw command) or `dx` (raw data-model/LINQ) |

## Gotchas

- **`.run` won't open / `0x80070057`** → System32 engine; bundle the WinDbg engine (README).
- **`module!name` won't resolve / `(export symbols)` only** → `msdia140.dll` not bundled, or no
  symbol path, or you reloaded off a bare `!tt`. Bundle it, set `.sympath`, `go` to a stop, `.reload /f`.
- **Offline / no PDB?** The data model, navigation, memory reads and `ln`/disassembly all work
  without symbols — query by address instead of by name.
- **`lm m <mod>` filter looks empty** but full `lm` shows the module → its symbols aren't loaded yet;
  `.reload` at a stopped position.
