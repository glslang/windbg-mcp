---
paths:
  - "src/engine.rs"
---

## The console a spawned child is given (`engine::without_a_console_window`)

**A console-subsystem child of a console-*less* parent gets a brand-new, visible console**, and a
GUI MCP client starts a stdio server without a console — so until #273 every worker spawn put a
window on the desktop, titled with the exe's path, taking the foreground as it appeared. Measured
here, both halves: a plain child of a console-less parent comes back with a window handle and the
title `C:\WINDOWS\system32\cmd.exe`, and the same child under `CREATE_NO_WINDOW` comes back with
none.

**The flag is conditional, and that is the whole of the change rather than a nicety.**
`CREATE_NO_WINDOW` does not suppress a console — it suppresses the *window*, by giving the child a
console of its **own** — and a worker's stderr is inherited. A console handle handed to a process
attached to a different console is re-bound to that one: measured, the child's `WriteFile` reports
success with bytes written and no error, and the text lands in its own invisible console instead of
the terminal, while a child that inherits the console writes where the operator is looking.
Unconditional, the flag therefore deletes every worker log line from a terminal-run server —
silently, and against the workflow `.claude/rules/powershell-scripts.md` documents ("leave stderr inherited; it lands in your
terminal") — and makes `logbridge`'s "they are still on the server's stderr" untrue. So it goes on
exactly where it changes something.

Four things to know before touching it.

- **The flag gives the child a console, and the docs say otherwise.** `CREATE_NO_WINDOW`'s own
  documentation — "the console handle for the application is not set" — reads as *no console*, and
  a reviewer will read it that way. Measured against a probe that allocates none of its own (a
  reading taken through `powershell.exe` does not count; a console host may allocate one):
  `CREATE_NO_WINDOW` leaves the child alone in a console of its own with no window and console
  APIs working, while `DETACHED_PROCESS` is the flag that leaves it with none —
  `GetConsoleProcessList` failing `ERROR_INVALID_HANDLE`, `GetConsoleCP` zero, no standard
  handles. The four-flag table is in the dbgscope commit that added its `mode con` assertion,
  which is where the same doubt was raised as a P1 review finding.
- **`GetConsoleWindow` is the wrong question**, and it is the one everybody reaches for. A console
  with no window is ordinary: a ConPTY has none — Windows Terminal, and this repo's own test
  harness, where the call answers 0 for a process attached to a live console with three processes
  in it — and neither has a console created by `CREATE_NO_WINDOW` one level up. It would apply the
  flag to precisely the worker whose stderr would then be lost. `GetConsoleProcessList` answers the
  question actually being asked, and returns 0 with `ERROR_INVALID_HANDLE` where there is no
  console (measured from a GUI-subsystem process, which Windows gives none).
- **A test that only looks for a window waves the unconditional version through**, since it opens
  none either. So both tests assert the child **joined this process's console** —
  `engine::tests::a_worker_shares_this_processs_console_or_gets_a_windowless_one` on a stand-in
  spawned with a worker's flags, and `mcp_smoke`'s `a_session_worker_opens_no_console_window_of_its_own`
  on a real session's `engine_pid`. Both fail against the unconditional flag; that was checked by
  making the change and running them.
- **The host decides which branch runs, so test the one you are not on.** A host spawning the
  server with `CREATE_NO_WINDOW` (node's `windowsHide`) leaves it a *hidden console*, so the worker
  inherits and the bug never appears; one spawning it with `DETACHED_PROCESS` (node's `detached`)
  leaves it console-less, which is the reported case. A stand-in host for this is 30 lines and is
  the only way to see either from a terminal, where everything has a console and nothing reproduces.

**A `launch`ed debuggee's window comes from somewhere else** — dbgscope's `CreateProcessWide`, which
passed `CREATE_NEW_CONSOLE` and now passes `CREATE_NO_WINDOW`
([dbgscope#129](https://github.com/glslang/dbgscope/issues/129)). Unconditional there, and rightly:
the debuggee must *never* inherit this process's console, because its stdout would then be the MCP
channel — measured, with a `STARTUPINFO` carrying no `STARTF_USESTDHANDLES`, which is the shape
DbgEng uses. The only question there was whether that console is on the desktop.

**And a service is a third answer to the same problem, at the deployment layer.** A service runs in
**session 0** (measured on this host: every service process is `SessionId 0` against an interactive
shell's 2), which has no interactive window station — so nothing the server tree opens can reach the
desktop or take the foreground, including windows from processes this repo does not control: a GUI
debuggee, an extension DLL, `TTD.exe`'s target. It is not a substitute for the flags, since it also
means a launched debuggee cannot interact with the desktop and `--listen` moves the transport off
stdio; it is what to reach for when something *else* starts opening windows.

