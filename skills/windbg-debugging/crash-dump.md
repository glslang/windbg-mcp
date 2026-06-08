# Playbook: crash-dump (`.dmp`) triage

**Goal:** open a crash dump and identify the faulting thread, the exception, and the
offending frame. No elevation needed; works on System32's engine.

## Steps

1. **Open the dump.** `open_dump { "path": "C:\\path\\to\\crash.dmp" }`
   — loads the dump, waits for it to settle, and returns the module list (`lm`).
   (`open_dump` also accepts a `.run` trace, but for TTD use `open_trace` — see
   [ttd.md](ttd.md).)

2. **Auto-analyze.** `execute { "command": "!analyze -v" }`
   — WinDbg's built-in triage: the exception record, the probable faulting frame, the
   bugcheck (for kernel dumps), and `FAILURE_BUCKET_ID`. Read this first; it usually names
   the culprit module and call.

3. **Locate the faulting context.** `threads {}` (`~`) to see all threads; `!analyze -v`
   already switches to the faulting thread. Confirm with `registers {}`.

4. **Read the stack.** `backtrace {}` (`k`). If frames show `module!name` you have symbols;
   if not, set up symbols (see [setup.md](setup.md)) and `execute { "command": ".reload /f" }`,
   then `backtrace {}` again.

5. **Inspect the crash site.**
   - `disassemble {}` at the current IP, or `disassemble { "address": "module!func" }`.
   - `read_memory { "address": "0x...", "size": 64 }` for a hex dump (numeric/hex address
     only — for a register expression use `execute { "command": "db @rsp" }`).
   - `execute { "command": "dt module!_STRUCT <addr>" }` to format a structure.

## Pitfalls

- **Symbols matter most here.** A stack of raw addresses tells you little — get
  `(pdb symbols)` working ([setup.md](setup.md)) before drawing conclusions.
- **Minidumps are partial.** `read_memory` can fail for pages not captured in the dump;
  that's the dump's limitation, not a tool error.
- For a kernel dump, `!analyze -v` reports the **bugcheck code and arguments** — start
  there rather than from the raw stack.
