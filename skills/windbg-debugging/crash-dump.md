# Playbook: crash-dump (`.dmp`) triage

**Goal:** open a crash dump and identify the faulting thread, the exception, and the
offending frame. No elevation needed; works on System32's engine.

## Steps

1. **Open the dump.** `open_dump { "path": "C:\\path\\to\\crash.dmp" }`
   — loads the dump, waits for it to settle, and returns the module list (`lm`).
   (`open_dump` also accepts a `.run` trace, but for TTD use `open_trace` — see
   [ttd.md](ttd.md).)

2. **Auto-analyze.** `execute { "command": "!ext.analyze -v" }`
   — WinDbg's built-in triage: the exception record, the probable faulting frame, the
   bugcheck (for kernel dumps), and `FAILURE_BUCKET_ID`. Read this first; it usually names
   the culprit module and call.
   — **Use the module-qualified `!ext.analyze`, not bare `!analyze`.** `open_dump` auto-runs
   `.load ext`, but this engine only resolves the qualified form; bare `!analyze` returns
   *"No export analyze found"*. If even `!ext.analyze` says that, the `winext\` extensions
   aren't bundled — see [setup.md](setup.md).
   — When `!ext.analyze` leaves `MODULE_NAME: Unknown_Module` (common for power/IRP bugchecks
   like `0x9F`), name the driver yourself from the bugcheck args by walking the device stack —
   see step 6.

3. **Locate the faulting context.** `threads {}` (`~`) to see all threads; `!ext.analyze -v`
   already switches to the faulting thread. Confirm with `registers {}`.

4. **Read the stack.** `backtrace {}` (`k`). If frames show `module!name` you have symbols;
   if not, set up symbols (see [setup.md](setup.md)) and `execute { "command": ".reload /f" }`,
   then `backtrace {}` again.

5. **Inspect the crash site.**
   - `disassemble {}` at the current IP, or `disassemble { "address": "module!func" }`.
   - `read_memory { "address": "0x...", "size": 64 }` for a hex dump (numeric/hex address
     only — for a register expression use `execute { "command": "db @rsp" }`).
   - `execute { "command": "dt module!_STRUCT <addr>" }` to format a structure.

6. **Name the driver by hand when `!ext.analyze` can't** (e.g. `0x9F`
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
  `!ext.analyze` already resolved (PDO, IRP, DRIVER_OBJECT live in the triage data).
- For a kernel dump, `!ext.analyze -v` reports the **bugcheck code and arguments** — start
  there rather than from the raw stack.
