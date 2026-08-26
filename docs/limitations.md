# Limitations & notes

- **TTD is user-mode only** (a Microsoft limitation): kernel debugging and TTD are distinct session
  types — you can't time-travel a kernel target.
- `launch` and `attach_process` stop the target at its initial/break-in point with a live
  process/thread context. (The binding enables the initial-breakpoint event filter — `sxe ibp` —
  which a bare `DebugCreate` host leaves off; without it the target would run free.) Note: on
  Windows 11 `notepad` is a Store app, so attaching by the PID that `Start-Process notepad` returns
  can hit `0xD000010A` (that PID is a transient launcher) — attach to a classic Win32 process.
- `read_memory` takes a numeric/`0x`-hex address only; for register/symbol expressions use
  `execute` with `db`/`dd` (e.g. `db @rip`).
- `reachable_from_dispatch` is a **static** call-graph walk over `uf` disassembly: it follows
  direct calls and cross-function tail jumps but **not** indirect calls through function pointers
  or unresolved compiler jump tables. So a `REACHABLE` verdict is sound (a concrete static path
  exists, and the path is reported), while `NOT REACHABLE` is best-effort within the explored
  bounds. If the dispatch uses a `switch(IoControlCode)` jump table (common), pass the specific
  handler VA as `from` to scope past it, or confirm dynamically with a breakpoint + `go`.
- The **kernel pool** tools (`pool_find_tag`, `pool_chunk`, `pool_census`, `pool_diagnostics`) walk the allocator's own
  descriptors through win-kexp rather than shelling out to `!pool`/`!poolused`, so all four read
  one snapshot and cannot disagree with each other. They need a **broken-in x64 kernel** target.
  Walking every pool page is expensive, so the snapshot is **cached per session** and reused; pass
  `refresh: true` after letting the target run, or you are reading a photograph of a target that has
  since moved. A walk that does happen is bounded by **what is left of the caller's own timeout**
  (`WINDBG_MCP_CALL_TIMEOUT_SECS`, less what the query waited its turn on the session), so it can
  neither outlive the call that asked for it nor stop early while that call is still waiting; a walk
  cut short still answers, and every result says how much of the pool it reached. `interrupt` ends
  one sooner. A query that reaches the engine with no time left to walk in — a call timeout at or
  under the 15s the reply itself reserves, or a long wait behind other work on the session — is
  *refused* rather than run, since a truncated walk is discarded rather than cached; without
  `refresh` it is still answered from the cached snapshot if there is one. Two semantics worth knowing: only *allocated* chunks are indexed by tag (a freed
  chunk's tag is not reliably preserved, so `pool_find_tag` never reports freed memory — ask about a
  specific address with `pool_chunk` instead), and `pool_chunk` reports three outcomes that are
  easy to conflate. A chunk in an explicitly free state (`ReusableFree` or `CachedFree`) is the
  one that means a pointer the target still holds is dangling. An address **not covered by the
  snapshot** is not the opposite finding: a region the walk never reached looks exactly like
  memory that was never pool, so read the coverage the tools print — and `pool_diagnostics` for
  what was missed — before concluding the pointer never pointed at pool. A span reported
  `Unreadable` is the walk's own limit (a Verifier guard page reads that way) and says nothing
  about whether the allocator freed anything. `pool_chunk` also
  reports the **neighbouring** chunks, which is what tells you what a reclaim would land next to. `pool_diagnostics` returns the walk's own diagnostics filtered by substring: a real walk emits tens of thousands across a hundred-plus categories, so any per-call summary truncates and the one line explaining a specific heap is never in the truncated head — filter by a heap address or a phrase to reach it.
- The **user Segment Heap** tools share that typed decoder but discover roots through the current
  process's PDB-resolved `_PEB.NumberOfHeaps` and `ProcessHeaps`. They require a stopped x64 user
  target (or a dump with sufficient memory) and the exact loaded `ntdll` PDB. `heap_list` reports
  every root and explicitly separates Segment Heaps walked from classic NT, unknown, and unreadable
  heaps skipped. V1 does not decode classic NT heaps, WOW64, or ARM64; use `!heap` for classic heaps.
  Snapshots are cached per target/PEB/`ntdll` image and invalidated when execution resumes; pass
  `refresh: true` for the final observation after target execution. Allocation `capacity` is always
  allocator-backed, while `requested_size` is optional and appears only when the selected schema
  validates exact unused-byte metadata. `heap_allocations` defaults to `state: allocated`; when
  investigating freed memory, pass `state: reusable_free` or `state: cached_free` explicitly. Read
  `layout`, `scope`, and `walk` before treating an absent allocation as evidence. The agent workflow is in
  [`skills/windbg-debugging/heap-walking.md`](../skills/windbg-debugging/heap-walking.md).
- **`crash_triage` reads a bug check two ways, and keeps them apart.** The code and its parameters
  (`ReadBugCheckData`), the stack, each frame's module, and the crashing process (out of the current
  `_EPROCESS`'s audit name — the full image name, not the 15-byte `ImageFileName` that turns
  `mm_exploit_v5.exe` into `mm_exploit_v5.`) are engine reads. The pool tag, the
  failure bucket, the blamed module and the per-parameter explanations exist nowhere but `!analyze`'s
  own output, so they are extracted from it and confined to the `analysis` object. **Prefer
  `faulting_frame` to `analysis.module_name`**: the frame's `module+RVA` is computed from the load
  base and is right for a driver with no PDB, which is exactly where `!analyze`'s attribution goes
  wrong. **Which frame is the culprit is still a guess, though — only the offset is computed.**
  `faulting_frame` is the innermost frame that *could* be a kernel driver: not `nt`/`hal`, not the
  framework layers that sit on a stack on somebody else's behalf (KMDF's `Wdf01000`, Driver
  Verifier), and not a user-mode module — a kernel stack that unwinds past the system call boundary
  runs on into `ntdll` and the caller's own `.exe`, and neither can be a driver. It is still
  positional, so a crash routed through a layer this build does not recognise names that layer
  instead of the driver behind it. The text
  prints `!analyze`'s attribution beside it whenever the two disagree and tells you to settle it
  from `frames`, where every `module+RVA` is sound whichever guess is right. `faulting_frame` is
  **absent** when the whole captured stack is in those images; `faulting_frame_note` then says
  whether that is the crash itself (a `0x9F` watchdog fires on an idle CPU — the culprit is not on
  that stack, and the bug check *arguments* are where to go next) or merely the 16-frame default
  cap, which `frames` raises to 128. `analyze: false` skips `!analyze` for a fast answer of
  everything else. **The call leaves the session exactly as it found it**, which running the same
  `!analyze -v` through `execute` does not: the analysis resets the selected scope to the target's
  default, so a `.frame`/`.cxr` a caller had chosen would be silently discarded — `crash_triage`
  saves that scope and restores it (`ScopeGuard`, [win-kexp#98](https://github.com/glslang/win-kexp/issues/98)),
  which is why the tool reports itself read-only. The stack it walks is the **default** context
  (the crash, on a crash dump) whenever the analysis ran to completion — running it is what resets
  the scope there — and whatever the session has selected when it did not: `analyze: false`, no
  time left, no `ext.dll`, or a run the deadline cut short before the reset it does partway
  through its output. `analysis.ran` and `analysis.truncated` distinguish them. Needs a kernel
  target
  *stopped at a bug check* — a live kernel that has not crashed yet, and a dump that is not a crash
  dump, are both **refused** with a message saying which of the two they are.
- **`crash_triage` tries `!analyze -v` and then `!ext.analyze -v`**, and reports which one worked
  under `analysis.command`. A **manual** `execute` has to pick, and on the bundled engine the
  answer is the module-qualified `!ext.analyze -v` — the unqualified form does not resolve there
  even after `.load ext` (see [*Bundling the WinDbg engine*](./install.md#bundling-the-windbg-engine)). On a **partial minidump**, reads of
  pages that weren't captured raise `An unexpected exception was raised (0x80040205)` rather than a
  clean "memory read error"; query the specific field you need (e.g.
  `dt nt!_DRIVER_OBJECT <addr> DriverName`) instead of dumping whole structures. See the
  [crash-dump walkthrough](crash-dump-walkthrough.md).
- **That failure is all-or-nothing inside a `.for` loop**, which is what `walk_memory` is for: one
  unmapped dereference takes the whole script down with no rows at all, and the node it happened on
  is usually the interesting one. Walk a list, an array or a chain with `walk_memory` and each hole
  is a marked value instead.
- Single-stepping is only valid once the target is stopped with a real thread context (after a
  `go`/step or a breakpoint hit). Stepping straight after a bare `goto_position` to the very start of
  a trace (before any thread is live) returns `0x80040205` — `go` to a breakpoint first.
- Symbol *names* (`module!func`) need (a) `msdia140.dll` bundled next to the binary, (b) a symbol
  path pointing at the PDBs (`.sympath …`), and (c) for TTD, reloading at a *stopped* position
  (after a `go`/breakpoint, not straight off a `!tt`) so the module's PDB is matched and loaded.
  With those, e.g. `ttd_calls("ucrtbase!__stdio_common_vfprintf")` returns the exact call count.
  Without symbols, the data model, navigation, and memory reads still work — query by address.
- **One command at a time per session.** Sessions run concurrently, but each one is a single engine
  processing operations serially, so a call against a busy session waits its turn. Issue tool calls
  for a given session **sequentially — await each result before sending the next**: the server does
  not order concurrent in-flight requests against each other, so pipelining them (firing several
  calls before their results return) can run a command before the one that establishes its state,
  and is meaningless for stateful, order-dependent debugger commands anyway. Standard MCP clients
  already serialize call→result, so this is only a concern for custom/batched callers.
- **Sessions are a bounded resource.** Each is a process holding a dump, a trace, or a live target,
  and at most `4` are open at once. `end_session` when you are done with one rather than relying on
  the oldest idle session being reclaimed.
- TTD **replay** (`open_trace`) needs `TTDReplay.dll` discoverable but **not** elevation; TTD
  **recording** (`record_trace`) needs `TTD.exe` **and** Administrator. `record_trace` captures the
  recorder's startup output to `<out_dir>\ttd_record.log` and watches it briefly, so a fast failure
  (e.g. running un-elevated → `0x80070005 Access is denied`) is reported as an error rather than a
  false "recording started". A target that *finishes* inside that watch is the other case, and is
  reported as a **complete** recording naming the finished `.run` — so `record_trace` answers one
  of two things on success, and only one of them has a trace ready to open.
- **Control-flow tools (`go`/`step*`/`reverse_*`) wait 60s for a stop, then break the target in.**
  The command is issued and the engine pumped to the next stop; if the target has not reached one
  by then the debugger raises a Ctrl+Break, so the call returns with the target *stopped where it
  happened to be* rather than left running. That case is reported rather than left to be inferred:
  `timed_out` is set in the structured result and the text says so. It is not an error and not an
  `interrupt` — nobody asked — and the next move is to run the target on, or to give it something
  to stop at.
- **A raw `execute` of an execution-control command works, and is not the same as the typed tool.**
  `g`, `p`, `t`, `bp X; g` and anything else that reaches execution moves the target: the server
  asks the engine whether a command left it running and pumps it if so, under the same 60s bound.
  What you get back is the debugger's output plus a line naming where the target ended up — there
  is no structured `stopped_at`, no typed `timed_out`, and a step prints nothing of its own, so
  that line is the only position in the answer. The typed tools are still the better call.
