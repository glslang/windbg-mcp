# Playbook: live user-mode & kernel debugging

**Goal:** drive a running target (or the kernel) — break in, set breakpoints, step, and
inspect state. Kernel debugging needs **Administrator** (see [setup.md](setup.md)).

## Start a session

Pick one entry point:

- **Launch a new process.** `launch { "command_line": "C:\\path\\app.exe arg1 arg2" }`
  — stops at the initial breakpoint with a live thread context (the binding enables the
  `sxe ibp` initial-breakpoint filter, which a bare host leaves off).
- **Attach to a running process.** `attach_process { "pid": 1234 }` — breaks in.
- **Local kernel.** `attach_kernel_local {}` (returns `vertarget`).
- **Remote kernel (KDNET).** `attach_kernel { "connection": "net:port=50000,key=..." }`.

End with `end_session {}` before opening another target (one session at a time).

## Inspect and control

1. **Survey.** `modules {}` (`lm`), `threads {}` (`~`), `registers {}`.
2. **Set a breakpoint.** `set_breakpoint { "expression": "kernelbase!CreateFileW" }`
   (symbol, address, or expression). For kernel, e.g. `nt!NtCreateFile`.
3. **Run to it.** `go {}` — continues and pumps to the next stop. On hit, inspect with
   `backtrace {}`, `registers {}`, `disassemble {}`, `read_memory {...}`.
4. **Step.** `step_over {}` (`p`) / `step_into {}` (`t`) — only valid once stopped with a
   real thread context (after a `go`/breakpoint).
5. **Anything else.** `execute { "command": "..." }` for raw commands (e.g. `!peb`,
   `dt nt!_EPROCESS`), or `dx {...}` for data-model queries.

## Pitfalls

- **Store-app PID gotcha:** on Windows 11 `notepad` is a Store app, so attaching to the PID
  that `Start-Process notepad` returns can hit `0xD000010A` (that PID is a transient
  launcher). Attach to a classic Win32 process instead.
- **`read_memory` is numeric/hex only.** Use `execute` → `db @rip` for register/symbol
  expressions.
- **`go` is bounded by the per-call timeout** (~60s). A long-running live target may not
  reach a breakpoint within one call.
- **TTD is user-mode only** — you cannot time-travel a kernel target. For reverse
  execution, record a user-mode trace instead (see [ttd.md](ttd.md)).
- Symbol names need the full setup (`msdia140.dll` + `.sympath` + `.reload /f` at a stop) —
  see [setup.md](setup.md).
