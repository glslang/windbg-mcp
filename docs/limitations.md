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
  descriptors through dbgscope rather than shelling out to `!pool`/`!poolused`, so all four read
  one snapshot and cannot disagree with each other. They need a **broken-in x64 kernel** target.
  Walking every pool page is expensive, so the snapshot is **cached per session** and reused; pass
  `refresh: true` after letting the target run, or you are reading a photograph of a target that has
  since moved. A walk that does happen is bounded by **what is left of the caller's own timeout**
  (`WINDBG_MCP_CALL_TIMEOUT_SECS`, less what the query waited its turn on the session), so it can
  neither outlive the call that asked for it nor stop early while that call is still waiting; a walk
  cut short still answers, and every result says how much of the pool it reached. `interrupt` ends
  one sooner. `pool_find_tag` can also stop deliberately at a nonzero `stop_after_matches` count;
  that result reports `match_limit_reached`, is not cached as exhaustive, and keeps its counts as
  floors. A complete cached snapshot still answers exhaustively. This traversal threshold is
  independent of `limit`, which caps only the rows rendered. A query that reaches the engine with
  no time left to walk in — a call timeout at or under the 15s the reply itself reserves, or a
  long wait behind other work on the session — is
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
- **A 32-bit user-mode target is opened by a worker of its own architecture, and what that buys and
  costs is worth knowing before you reach for either.** An extension DLL is loaded into the
  debugger's own process, so SOS on a 32-bit .NET target is reachable only from a 32-bit host: the
  32-bit `sos.dll` will not load into an x64 engine (`Win32 error 0n193`) and the 64-bit one loads
  and then refuses the target (`Failed to load data access DLL, 0x80004005`), the CLR data access
  DLL being paired to the target's architecture as well as the host's. So a 32-bit dump, and an
  `attach_process` on a WoW64 process, are routed to an `x86\windbg-mcp.exe` worker. Nothing about
  that is visible to a client — one server, one handle, one tool surface — and where the worker or
  its 32-bit engine is absent the target **still opens**, on the x64 build, with an opener
  `limitation` saying SOS is unreachable rather than a failure: native analysis of such a target
  works and always has. Two things such a session does not have, and only one of them is about the
  worker. The `heap_*` tools refuse any non-x64 *target* (*"heap walking supports x64 targets
  only"*), so they are gone whichever worker holds it — SOS's own `!dumpheap`/`!eeheap` are the
  managed equivalent. The other **is** the 32-bit worker's own trade: a live WoW64 `attach_process`
  there sees only the 32-bit half of the process. The emulation layer above 4 GiB (`wow64.dll`,
  `wow64cpu.dll`, `wow64win.dll` and the 64-bit `ntdll`) is what the x64 engine reaches with
  `!wow64exts.sw` and this one cannot — measured on one process, 36 modules against 30. That is the
  right trade when you are here for SOS and the wrong one for debugging the thunk layer itself; for
  both halves, take a `procdump64.exe -ma` capture and open that, which routes to the x64 engine. A
  dump loses nothing, a 32-bit capture never having held the 64-bit side. The engine payload to copy
  is in [`setup.md`](../skills/windbg-debugging/setup.md).
- **`crash_triage` reads a bug check two ways, and keeps them apart.** The code and its parameters
  (`ReadBugCheckData`), the stack, each frame's module, and the crashing process (out of the current
  `_EPROCESS`'s audit name — the full image name, not the 15-byte `ImageFileName` that turns
  `mm_exploit_v5.exe` into `mm_exploit_v5.`) are engine reads. The pool tag, the
  failure bucket, the blamed module and the per-parameter explanations exist nowhere but `!analyze`'s
  own output, so they are extracted from it and confined to the `analysis` object. **Prefer
  `faulting_frame` to `analysis.module_name`**: the frame's `module+RVA` is computed from the load
  base, so it names the driver on any host that can read the dump, while `!analyze`'s attribution
  additionally needs `triage\triage.ini` beside the engine and reports `Unknown_Module` without it
  (`skills/windbg-debugging/setup.md` has the copy step). A missing PDB costs the *function* on
  both — neither answer names one. **Which frame is the culprit is still a guess, though — only the offset is computed.**
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
  saves that scope and restores it (`ScopeGuard`, [dbgscope#98](https://github.com/glslang/dbgscope/issues/98)),
  which is why the tool reports itself read-only. The stack it walks is the **default** context
  (the crash, on a crash dump) whenever the analysis ran to completion — running it is what resets
  the scope there — and whatever the session has selected when it did not: `analyze: false`, no
  time left, no `ext.dll`, or a run the deadline cut short before the reset it does partway
  through its output. `analysis.ran` and `analysis.truncated` distinguish them. Needs a kernel
  target
  *stopped at a bug check* — a live kernel that has not crashed yet, and a dump that is not a crash
  dump, are both **refused** with a message saying which of the two they are.
- **`exception_triage` reports three kinds of fact and labels the weakest.** The exception record,
  its decoded code and the stack are reads of the dump. The thrown C++ **type** is decoded from
  MSVC's own `ThrowInfo`/`CatchableType`/`TypeDescriptor` chain, whose layout the compiler fixes.
  The thrown **HRESULT** is located by the `0xAABBCCDD` sentinel a `winrt::hresult_error` carries,
  which no header states — so it comes with `hresult_confidence`, `corroborated` when the type name
  independently said `hresult_error` and `convention` when the sentinel stands alone.
- **The thrown type needs the throwing module's image, and a minidump does not contain it.**
  `ThrowInfo` and everything it points at live in the image's `.rdata`, which the debugger reads
  off the binary on disk — measured: the walk succeeds while the executable is at its recorded path
  and returns `????????` once it is moved aside. So a dump from another machine, or one whose
  binaries have moved, reports no `type_name` and says why in `type_note`, and the HRESULT still
  comes back, because the thrown object is on the *stack* and therefore captured. Neither route is
  a superset of the other; both are tried.
- **A minidump without the faulting module's image unwinds badly on x64, and that is a fact about
  dumps rather than about this server.** (x86 is not affected the same way — its unwind is
  frame-pointer based, and the 32-bit fixture walks its whole stack with the image moved aside.) The unwind data lives in the image's `.pdata`, which a
  minidump does not capture, so the engine reads it off the binary on disk. Measured on the
  checked-in fixture with its executable moved aside: frame 0 is right either way — it comes from
  the recorded context rather than from unwinding — and beyond it the frames alternate between
  resolved ones and frames attributed to no module at all. Every frame's `module`+`rva` is still
  computed rather than guessed, so a *hole* in the attribution is the signal: a walk with one is a
  walk this host could not do, not a stack with an unusual frame in it. Put the binaries where the
  debugger can find them (`.exepath`, or beside the dump) before reading a stack from a dump that
  came from another machine.
- **The buried-throw scan runs on one fault shape, and reports nothing on the others.** It is
  `abort`'s fail-fast — `0xc0000409` with subcode 7 and none of WIL's parameters — because that is
  the fault whose cause is somewhere other than its own record. It deliberately does *not* run on
  every fault that carries no throw: a C++ `EXCEPTION_RECORD` outlives the frames that held it, so
  an access violation deeper on the stack than an old `try`/`catch` would find that handled
  exception's object and report it as the cause. A specific wrong answer is worse than none, so on
  an access violation, a breakpoint or a WIL fail-fast there is no `thrown` and the record's own
  fields are the whole answer.
- **The C++ EH decode is laid out at the *target's* pointer width, which is not this build's.**
  A 32-bit throw raises **three** parameters where a 64-bit one raises four — the fourth is an image
  base, and a 32-bit graph's links are absolute pointers needing none — its `EXCEPTION_RECORD` is 80
  bytes rather than 152 with the parameter count and the parameters both earlier, and
  `TypeDescriptor::name` sits at `+8` rather than `+16`. All measured, by building one program twice
  and having it print its own record and walk its own graph. Every one of those differences makes a
  mismatched reader come back *empty* rather than fail, so the width is read from the engine
  (`GetActualProcessorType`) per target rather than assumed; `docs/samples/cppthrow-fastfail-x86.dmp`
  is the fixture that keeps it honest.
- **`exception_triage`'s stack comes from the stored crash context where the target has one.** That
  is what `.ecxr` adopts, walked without `.ecxr`'s effect on the session, so the caller's selected
  thread and frame are left alone — which is what lets the tool be read-only where `crash_triage`
  needed a scope guard. `frames_from_stored_context` says which happened: a **live** target stores
  no event, so there the stack is whatever thread is selected and is not promised to be a crash.
  A kernel session is **refused** — a kernel crash dump carries no stored event at all, measured,
  and its bug check is `crash_triage`'s.
- **`decode_error_reporting` reads the host's message tables, not the target's.** The structural
  fields — severity, facility, code, the customer bit — are arithmetic and cannot differ. The
  message text comes from this machine (`FormatMessageW`, plus `ntdll`'s table for an `NTSTATUS`),
  so a dump from a build that words an error differently is described in this host's words;
  `message_provenance` says so on every answer that carries one. It reports **both** readings
  rather than choosing, because a bare dword does not say which space it came from: severity is one
  bit as an HRESULT and two as an NTSTATUS, and `0x80670015` is a *failed* HRESULT whose top two
  bits read as an NTSTATUS *warning*.
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
- **A target that runs to completion ends the session, and that is not a failure.** A `go` (or a
  step, or a raw `g`) whose debuggee exits reports the ending — `target_gone` in the structured
  result, and a sentence beside it — carrying whatever the run printed on the way there, which is
  the only copy: the command prints its own echo, while module loads, a breakpoint banner and an
  embedded script's output all arrive during the wait. `.detach`, `q` and `qd` end it the same way.
  Afterwards every call on that session is refused with one message and the category
  `stale_session`; `end_session` releases it, and opening again gets a fresh target. There is no
  way to reopen a target inside an existing session, and `session_status` still reports such a
  session as `open`.
