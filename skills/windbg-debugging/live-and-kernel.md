# Playbook: live user-mode & kernel debugging

**Goal:** drive a running target (or the kernel) — break in, set breakpoints, step, and
inspect state. Kernel debugging needs **Administrator** (see [setup.md](setup.md)).

## Start a session

Pick one entry point:

- **Launch a new process.** `launch { "command_line": "C:\\path\\app.exe arg1 arg2" }`
  — stops at the initial breakpoint with a live thread context (the binding enables the
  `sxe ibp` initial-breakpoint filter, which a bare host leaves off).
- **Attach to a running process.** `attach_process { "pid": 1234 }` — breaks in.
- **Local kernel.** `attach_kernel_local {}` — breaks in and returns `vertarget`.
- **Remote kernel (KDNET).** `attach_kernel { "connection": "net:port=<n>,key=<w.x.y.z>" }`
  — connects, breaks in, and returns `vertarget`. **Ask the user for the actual
  connection string**; the port and key are specific to the target's KDNET setup (from
  `bcdedit /dbgsettings` on the target, or the `windbgx -k` / `kd -k` command they use)
  and cannot be guessed — never invent a placeholder key.

Each of these opens a session of its own and returns a `session_id` — opening one does not close
another, so you can keep a kernel attach live while you look at a dump. Pass the id on later calls
to route them, and `end_session { "session_id": "<id>" }` when you are done with a target (up to
four at a time).

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
  reach a breakpoint within one call; on a live kernel it is force-broken at the cap.
- **Unreachable kernel target waits forever.** `attach_kernel` to a target that never
  establishes the KDNET link waits like `kd` does — a connecting link can't be cancelled
  mid-handshake — so the call reports a timeout while the attach keeps waiting. Confirm the
  target is up, booted with debugging enabled, and pointed at this host with the right
  port/key. Three things to know when it happens:
  - It costs **only that session**: other sessions and every other tool keep working.
  - **Do not re-attach.** The connection was already claimed, so a retry dials a second time.
  - `session_status` says how long it has been waiting, and whether that is past the point a
    healthy link takes (~25s for a KDNET resync). Past that, nothing on this side will end the
    wait — but the target still can: boot the guest with debugging enabled and the attach lands
    on its own. Use `end_session { "session_id": "<id>" }` when you choose to give up on it
    instead; that reclaims the session by terminating its engine process.

  A *connected* target that doesn't break in is bounded and returns an error.
- **TTD is user-mode only** — you cannot time-travel a kernel target. For reverse
  execution, record a user-mode trace instead (see [ttd.md](ttd.md)).
- Symbol names need the full setup (`msdia140.dll` + `.sympath` + `.reload /f` at a stop) —
  see [setup.md](setup.md).
