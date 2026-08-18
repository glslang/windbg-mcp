# Playbook: crash-dump (`.dmp`) triage

**Goal:** open a crash dump and identify the faulting thread, the exception, and the
offending frame. No elevation needed; works on System32's engine.

## Steps

1. **Open the dump.** `open_dump { "path": "C:\\path\\to\\crash.dmp" }`
   — loads the dump, waits for it to settle, and returns the module list (`lm`).
   (`open_dump` also accepts a `.run` trace, but for TTD use `open_trace` — see
   [ttd.md](ttd.md).)

2. **Triage the bug check.** `crash_triage {}`
   — for a **kernel** dump (or a live kernel stopped at a bug check), this is the first call:
   the code and its four parameters, the crashing process, the stack with every frame as
   `module+RVA`, and the **faulting frame** — the innermost frame that could be a driver at all
   (not `nt`/`hal`, not a framework layer, not user-mode code past the system-call boundary).
   It runs `!analyze -v` for you (either spelling — see below) and reports the fields
   only `!analyze` computes (`pool_tag`, `failure_bucket_id`, the per-parameter explanations)
   under `analysis`, so you get them without reading ~150 lines. **Those fields need the bundled
   `winext\` extensions** ([setup.md](setup.md)) — without them `analysis.ran` is `false` and
   `analysis.note` says why, while everything read from the engine (code, parameters, process,
   frames, faulting frame) is unaffected. On such an engine, `crash_triage { "analyze": false }`
   asks for the engine-only answer deliberately instead of trying and reporting the failure.
   — **`faulting_frame` and `analysis.module_name` are two guesses; `frames` settles them.** Every
   frame's `module+RVA` is *computed* from the load base, so it is right even for a driver with no
   PDB — that part is not a guess. *Which* frame is the culprit is. The rule picks the innermost
   frame that could be a driver at all, so it is only as good as its list of what to skip: a crash
   routed through a framework layer this build does not recognise as one is blamed on that layer
   rather than on the driver behind it. `!analyze`'s attribution is a different heuristic, and is
   often wrong for a PDB-less driver. When the two differ the text says so; read the stack and
   decide.
   — `crash_triage { "analyze": false }` skips the `!analyze` and answers from engine reads alone —
   fast, and it still names the bug check. It walks **whichever context the session has selected**,
   which on a freshly opened dump is the crash: only run it on a session where you have moved the
   context yourself (`.thread`, `~Ns`, `.cxr`) if that is the stack you meant. The default
   `analyze: true` walks the **target's default** context instead — the `!analyze -v` it runs
   first resets the scope there — and your scope is put back before the call returns, so a triage
   costs you nothing either way and a later `registers` / `backtrace` reads as before. If the
   analysis did not run to completion (`ran: false` — no time left, no `ext.dll` — or
   `truncated: true`, cut short before the reset it does partway through its output), nothing
   reset anything and you get the selected context after all.
   — **`faulting_frame` is not always there, and `faulting_frame_note` says why.** It is *absent*
   (the key is omitted, as every optional field in this server's structured results is) for four
   different reasons, and only two of them are findings about the crash. **Read the note before
   concluding anything.**
   - *No frame could be a driver* — they are all `nt`/`hal`, a framework layer, or user-mode code
     past the system-call boundary. A real answer: a `0x9F` watchdog fires on an idle CPU's timer
     DPC, so the driver holding the IRP is not on that stack at all, and the culprit has to come
     from the bug check *arguments* instead (step 7).
   - *The walk hit its frame cap* (`frames_truncated: true`) — re-ask with
     `crash_triage { "frames": 64 }`.
   - *The call was interrupted*, so the reads were abandoned rather than started. Says nothing
     about the crash; triage again without interrupting.
   - *The stack could not be walked at all.* Also says nothing about the crash.

3. **Auto-analyze in full**, for the parts the triage summary leaves out (the exception record
   on a user-mode dump, the rendered stack, the hypervisor/blackbox detail):
   `execute { "command": "!ext.analyze -v" }`
   — **Use the module-qualified `!ext.analyze`, not bare `!analyze`.** `open_dump` auto-runs
   `.load ext`, but this engine only resolves the qualified form; bare `!analyze` returns
   *"No export analyze found"*. If even `!ext.analyze` says that, the `winext\` extensions
   aren't bundled — see [setup.md](setup.md). (`crash_triage` tries both spellings itself and
   reports which one worked.)
   — When `!ext.analyze` leaves `MODULE_NAME: Unknown_Module` (common for power/IRP bugchecks
   like `0x9F`), name the driver yourself from the bugcheck args by walking the device stack —
   see step 7.

4. **Locate the faulting context.** `threads {}` (`~`) to see all threads; `!ext.analyze -v`
   switches to the faulting thread on the bug checks that carry an exception context — not on all
   of them, so confirm with `registers {}` rather than assuming.

5. **Read the stack.** `backtrace {}` — typed frames, each carrying `module` + `rva` (the offset
   into the image, computed from its load base) as well as the `module!Symbol` the debugger
   resolves. A frame with **no `symbol`** is a module with no PDB rather than a lost frame, and
   `module+rva` still names it: to resolve the rest, set up symbols (see [setup.md](setup.md)),
   `execute { "command": ".reload /f" }`, then ask again. Default 32 frames — `frames_truncated`
   says when the stack went on past that, so raise `frames` rather than reading a capped stack as
   a short one. This is **not** `k`'s listing: it has no `Child-SP`/`RetAddr` columns and no
   `[Inline Frame]` rows, which a stack walk does not return. For those,
   `execute { "command": "k" }`.

6. **Inspect the crash site.**
   - `disassemble {}` at the current IP, or `disassemble { "address": "module!func" }` — typed
     instructions, each with its encoding and, where the engine can place the address in a loaded
     module, its offset into that image; 16 by default. Use
     `execute { "command": "uf module!func" }` to follow a whole function, which is the one shape
     a count cannot ask for.
   - `read_memory { "address": "0x...", "size": 64 }` for a hex dump (numeric/hex address
     only — for a register expression use `execute { "command": "db @rsp" }`).
   - `execute { "command": "dt module!_STRUCT <addr>" }` to format a structure.

7. **Name the driver by hand when `!ext.analyze` can't** (e.g. `0x9F`
   `DRIVER_POWER_STATE_FAILURE`). The bugcheck args hand you the device object and the blocked
   IRP; walk to the owning driver by *field*, not by dumping whole structs (see the pitfall
   below):
   - `dt nt!_IO_STACK_LOCATION poi(<IRP>+b8) MajorFunction MinorFunction DeviceObject`
     — the device object currently sitting on the IRP.
   - `dt nt!_DRIVER_OBJECT poi(<DeviceObject>+8) DriverName DriverStart`
     — the culprit driver's name, and a `DriverStart` you can match against `lm`.
   - Walk the stack with `dt nt!_DEVICE_OBJECT <devobj> AttachedDevice` (PDO → FDO → FiDO).
   The worked example is [docs/crash-dump-walkthrough.md](../../docs/crash-dump-walkthrough.md).

## Pitfalls

- **Symbols matter most here.** A stack of raw addresses tells you little — get
  `(pdb symbols)` working ([setup.md](setup.md)) before drawing conclusions.
- **Minidumps are partial.** `read_memory` can fail for pages not captured in the dump;
  that's the dump's limitation, not a tool error. A `dt`/`dq`/`dps` against an *uncaptured*
  page raises `An unexpected exception was raised (0x80040205)` (not a clean read error), and a
  full-struct `dt` can hit it just by following a pointer into a missing page — read the one
  field you need (`dt nt!_DRIVER_OBJECT <addr> DriverName`) and prefer the addresses
  `!ext.analyze` already resolved (PDO, IRP, DRIVER_OBJECT live in the triage data). To read the
  same field across many objects, use `walk_memory` rather than a `.for` loop: one uncaptured page
  aborts the whole loop, while the walk marks that node and reads the rest.
- For a kernel dump, `!ext.analyze -v` reports the **bugcheck code and arguments** — start
  there rather than from the raw stack.
