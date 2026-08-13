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
- **Remote kernel (KDNET).** `attach_kernel` — connects, breaks in, and returns `vertarget`.
  A connection string carries the target's **debug key**, and a key that arrives as a tool
  argument is in this conversation's transcript for good — copied on through context snapshots
  and summaries. So the order below is not a style preference; step 3 is the one to get right.
  1. **Know the profile name?** `attach_kernel { "profile": "<name>" }`. Done.
  2. **Don't?** Call `attach_kernel {}` with no arguments. The refusal lists the profiles this
     host has, so you never have to guess a name or ask the user for anything.
  3. **No profile covers the target?** **Ask the user to create one** — do not ask for a
     connection string. Ask for the **file**, which is the only route that works mid-session:

     ```jsonc
     // %USERPROFILE%\.windbg-mcp\profiles.json — create it if it isn't there
     { "ctf-vm": "net:port=50000,key=<w.x.y.z>" }
     ```

     The values come from the target's KDNET setup (`bcdedit /dbgsettings` on the target, or
     the `windbgx -k` / `kd -k` command they already use) — you cannot guess them, and must
     never invent a placeholder key. The file is re-read on **every** attach, so the moment
     they say it's saved, go to step 1; nothing needs restarting.

     Do **not** offer `$env:WINDBG_MCP_PROFILE_…` as the fix for right now. The server reads
     its *own* environment, fixed when it started, so a variable set in the user's shell after
     that changes nothing until the server restarts. It is worth mentioning only as the way to
     configure a profile permanently in the MCP client's server definition.
  4. **Only if the user declines** — a one-off target, or they'd rather not configure anything
     — fall back to `attach_kernel { "connection": "net:port=<n>,key=<w.x.y.z>" }`. Say plainly
     that the key will then be in the transcript, so it is their call, not a silent default.

  Passing both, or neither, is refused. So is a connection string put in `profile` by mistake —
  and it is not echoed back. Sessions report their connection with the key masked
  (`net:port=50000,key=<redacted>`), so `session_status` still tells two kernel targets apart.
  Full configuration details: [setup.md](setup.md).

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
- **Walk driver lists and handle tables with `walk_memory`, not a `.for` loop.** A freed node
  whose page has gone takes a MASM loop down with `0x80040205` and no partial output; the walk
  marks it and continues, and a chain reports the node whose link would not read. Fields of one
  structure cost a single read per node, which matters over KDNET.
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
