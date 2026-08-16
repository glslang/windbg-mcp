# CLAUDE.md

Guidance for Claude Code working in this repo. See `README.md` for architecture and the full tool
surface; this file covers the non-obvious operational workflows.

## What this is

`windbg-mcp` is a Rust MCP server (stdio, `rmcp`) exposing **WinDbg/DbgEng** for live user-mode,
kernel, crash-dump, and Time Travel Debugging (TTD) work. The low-level DbgEng bindings come from
the sibling crate [`win-kexp`](https://github.com/glslang/win-kexp) (a **path/git dependency we grow
ourselves** — do not add third-party DbgEng crates).

**The binary has two roles.** Started normally it is the **supervisor**: MCP on stdio, no DbgEng.
Re-executed with `--engine-worker` it owns exactly one debug session, because dbgeng.dll holds one
debuggee session per process. Key source: `src/engine.rs` (the supervisor — session registry,
worker supervision, routing), `src/worker.rs` (the child process and the engine thread inside it),
`src/proto.rs` (the wire protocol between them), `src/server.rs` (the MCP tools),
`src/kdconn.rs` (KDNET connection profiles and the redacting `Connection` type), `src/ttd.rs`,
`src/main.rs` (role selection).

Practical consequences when debugging this server: a stack trace or log line can come from either
role (worker logs are untagged by target and inherit the supervisor's stderr), and killing the
supervisor leaves no workers behind — they exit when their request channel closes. That channel is
a pair of inherited anonymous pipes, *not* the worker's stdio: anything a worker prints to stdout
is drained into the log and cannot reach the protocol.

## Updating the running windbg MCP after code changes

The MCP server registered for this repo runs `target\release\windbg-mcp.exe`. **While that server is
connected in a Claude Code session, it holds an open handle to the exe**, so a plain
`cargo build --release` fails at the final replace step with `Access is denied (os error 5)` — but
only *after* compilation has already succeeded.

To rebuild and load the new code without stopping the session:

1. **Rename the locked exe out of the way** (Windows allows renaming a running image, just not
   deleting/overwriting it):
   ```
   mv target/release/windbg-mcp.exe target/release/windbg-mcp.exe.stale
   ```
2. **Build** into the now-free path:
   ```
   cargo build --release
   ```
   This builds the `win-kexp` revision pinned in `Cargo.lock` and writes a fresh
   `target\release\windbg-mcp.exe`. If this `windbg-mcp` change depends on a newly pushed
   `win-kexp` commit, run `cargo update -p win-kexp` first and commit the resulting `Cargo.lock`
   bump with the `windbg-mcp` change. The running server keeps executing the *old* code from the
   renamed `.stale` file until its connection is recycled.
3. **Load the new binary** by reconnecting the server: `/mcp` → reconnect `windbg` (or restart
   Claude Code). Only after this reconnect do the windbg tools run the new code.
4. Once reconnected (the old process is gone), delete `target/release/windbg-mcp.exe.stale`. Do
   **not** delete it while the old process is still alive — it demand-pages code from that file.

A worker is spawned by re-executing the supervisor's *own* image, so a supervisor running from the
renamed `.stale` file spawns workers from it too — old code stays consistently old, which is what
you want. It also means `.stale` can be held by more than one process: reconnecting ends the
supervisor, and its workers exit with it, so step 4 is still just "after the reconnect".

## Changing win-kexp (the DbgEng bindings)

`win-kexp` is a **git dependency pinned to `main`**, not a path dependency — a `windbg-mcp` build
pulls it from GitHub, so **local edits to `C:\workspace\win-kexp` are invisible to a `windbg-mcp`
build until they are pushed to `win-kexp` `main`** (then bump the pin / rebuild). Add new DbgEng
primitives as typed `win-kexp` methods (returning `Result<_, DbgEngError>`, not `panic!`/`.expect`),
not via the `execute` text hatch.

After pushing a required `win-kexp` change to `main`, run `cargo update -p win-kexp` in this repo and
commit the resulting `Cargo.lock` change before building or opening the dependent `windbg-mcp` PR.

To compile-check a `windbg-mcp` change that depends on un-pushed `win-kexp` edits, add a temporary
patch and `cargo check`, then revert it (do **not** commit it — it breaks CI/other contributors):

```toml
[patch.'https://github.com/glslang/win-kexp']
win-kexp = { path = "../win-kexp" }
```
`git checkout -- Cargo.toml Cargo.lock` afterwards.

## Local verification (no session restart needed)

For a compile/behavior check without touching the locked release exe, use the **dev profile**
(writes `target/debug`, never locked): `cargo test` and `cargo clippy --all-targets`. The release
build differs only in optimization and is exercised by CI on a fresh runner.

`cargo test` includes `tests/mcp_smoke.rs`, which spawns the **dev** binary (via
`CARGO_BIN_EXE_windbg-mcp`) and drives it over stdio — so it is also clear of the release lock.
After a dependency bump (`rmcp`, `schemars`, `tokio`, `cargo update -p win-kexp`) or an MCP spec
revision, run it and follow [`docs/smoke-test.md`](./docs/smoke-test.md). To include the tier that
opens the sample dump through DbgEng, set the gate first (PowerShell, not `VAR=1 cmd`):

```pwsh
$env:WINDBG_MCP_SMOKE_DUMP = "1"; cargo test --test mcp_smoke
```

That tier now also covers the process-per-session behaviour end to end: two sessions coexisting, a
kernel attach parked on a dead port being reclaimed by `end_session`, and no worker process
outliving the connection. A third tier is `#[ignore]`d because it runs commands out to a watchdog
deadline (minutes, not seconds) — run it by hand after a win-kexp watchdog change:

```pwsh
$env:WINDBG_MCP_SMOKE_DUMP = "1"
cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 bounded
```

A fourth tier drives a **real KDNET target** through a full session lifecycle — attach, work
alongside a second session, detach gracefully — separately checks that a client *disconnect*
releases a live kernel session rather than killing its worker, covers the **pool walk**
(`pool_find_tag`/`pool_census`), whose cost only exists over a live link, and runs a **`debug_batch`
that patches a byte of the running kernel** and has to put it back (through a failing assertion, a
clamped call budget, a disconnect and an `end_session`) — the one claim a crash dump cannot test,
because a byte patched in a dump is patched in a file nobody reads again. It is gated on the
connection string (which nobody can guess) *and* `#[ignore]`d, so a stale variable can never freeze
a VM during an ordinary `cargo test`. Run it last, on its own.

**Before deciding a live-kernel claim cannot be checked, read the profiles.** This host normally has
one configured, and a configured profile *is* a KDNET target — connection, port and key — so the
tier can be run. The failure this is here to stop is not asking the user for a key; it is concluding
"no KDNET target on this host" without looking, shipping the live claim as unverified, and saying so
in a PR. Two lines settle it:

```pwsh
Get-Content "$env:USERPROFILE\.windbg-mcp\profiles.json" -Raw | ConvertFrom-Json | Get-Member -MemberType NoteProperty | Select-Object Name
Get-ChildItem Env: | Where-Object Name -like 'WINDBG_MCP_PROFILE_*' | Select-Object Name
```

Then set the variable **from the profile, in one step**, so the key never lands in a command line, a
tool argument or this transcript:

```pwsh
$env:WINDBG_MCP_SMOKE_KERNEL = (Get-Content "$env:USERPROFILE\.windbg-mcp\profiles.json" -Raw | ConvertFrom-Json).'ctf-vm'
cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 live_kernel
```

The tier takes the *raw* string only because it has to exercise the explicit path — not because it
needs a second copy of the key. Print the profile **name** and the port when reporting what you are
attaching to, never the value; `attach_kernel {}` lists the configured names without disclosing any
of them. Only ask the user for a raw connection when no profile is configured at all.

`--test-threads=1` is not optional: the filter matches **eight** tests, and the KD transport is
single-owner, so in parallel the second attach fails and can leave the target halted.

**Check the target is reachable before starting the tier, not by starting it.** A KDNET attach that
finds nothing parks its worker in `WaitForEvent(INFINITE)` for the whole run and reports a timeout
that measures the environment rather than the code.

What settles it is not "can I reach the guest" but **does the guest's `bcdedit /dbgsettings hostip`
equal this debugger host's current IP**, on the port the profile names — that is what makes the
target dial in, and the host IP moves between sessions. Read it on the guest and compare the key by
*hash* rather than printing it. That check is the same everywhere; how you reach the guest to run it
is not.

*Finding* the guest is topology-specific, so what follows is one instance and not the procedure. On
the machine this was written for, the debugger host is itself a Hyper-V guest — `Get-VM` does not
exist and there is no local VM to start — so the target is a *sibling*: it appears in the neighbour
table (`Get-NetNeighbor | ? LinkLayerAddress -like '00-15-5D*'`) and answers **TCP 5985** and
nothing else, ICMP and 445 being closed, so a failed ping proves nothing there. Elsewhere it may be
a local VM, another hypervisor, or one of several neighbours — and with several, the neighbour table
alone will happily validate the wrong guest, which is what the `hostip` comparison above is for.

## Live kernel + driver IOCTL gotchas (learned driving HEVD over KDNET)

**Attach by `profile`, not by connection string — always, for any live target.** `attach_kernel
{ "profile": "<name>" }` resolves the connection inside the server (`src/kdconn.rs`), so the
target's debug key never lands in a tool argument — and therefore never in the *client's*
transcript, where one key previously ended up replicated across hundreds of records.
`attach_kernel {}` lists the profiles this host has. Configure one with
`WINDBG_MCP_PROFILE_<NAME>` or `%USERPROFILE%\.windbg-mcp\profiles.json`; raw `connection` still
works for a target nothing is configured for, and is the last resort rather than the quick option.

A raw `connection` now also reaches a second place: with recording on (below) it is written to the
server's own transcript file, scrubbed to `key=<redacted>`. That backstop is not a reason to pass
one. A profile keeps the key out of the request, so there is nothing for either transcript to
redact, and redaction is a thing that has to keep working while a key never sent cannot leak.

The live smoke tier below is the one sanctioned exception: `WINDBG_MCP_SMOKE_KERNEL` is a raw
connection string, passed straight to `attach_kernel { "connection": … }`, and is deliberately
*not* a profile — the tier has to exercise the explicit path, and it is a variable in a developer's
own shell rather than something a client ever sees.

A worker process does **not** inherit `WINDBG_MCP_PROFILE_*` (`engine::spawn_worker` strips them):
it is told the one connection it is opening over its private pipe, and a `launch`ed debuggee would
otherwise inherit every configured key on the host.

**KDNET attach is a blocking wait, by design.** A live kernel needs `WaitForEvent(INFINITE)` (a finite
timeout returns `E_NOTIMPL` and never drives the link). So if the target isn't reachable, the
`attach_kernel` MCP call reports a *timeout* while its **worker process** stays parked in the wait —
it self-heals and completes the attach the moment the target actually connects. Consequences:
- The park costs **that session only**. Other sessions and every other tool keep working, so an
  attach that is going nowhere is no longer a reason to restart the server. `session_status` says
  how long it has been waiting and whether that is past the point a healthy link takes;
  `end_session` reclaims it, terminating the worker process if the wait will not unwind (it won't —
  `SetInterrupt` cannot reach a wait that has not yet connected).
- **Do not re-run the attach while it is still waiting.** The connection was already claimed, so a
  retry dials a second time. End it first, or fix the target and let the original attach land.
- Diagnosing why nothing dialed in is still out-of-band work (PowerShell): check the debugger is
  listening (`Get-NetUDPEndpoint -LocalPort 50000` → owned by `windbg-mcp.exe`, which will be the
  *worker* process) and whether any VM is running.
- The **target must dial this host**: on the target, `bcdedit /dbgsettings net hostip:<debugger-ip>
  port:50000 key:<key>` — **colons, not `=`**. `hostip` must be the debugger host's current IP.
  Symbols are **not** pulled over the KD wire (see below).
- After a target reboot, the settling KD link shows repeated break-ins in **`kdnic.sys`** (the KD NIC
  transport: `nt!DbgBreakPointWithStatus` ← `kdnic!TXTransmitQueuedSends`). These are not real stops —
  `go` through them until boot proceeds.

**Walking a service-loaded driver's IOCTLs live.** `sxe ld:<drv>.sys` breaks on module load, which is
**before DriverEntry runs** — so the driver object's `MajorFunction` table is *not* populated yet
(`driver_object` shows defaults / "is not a driver object"). To let DriverEntry run and populate it:
1. Compute the PE entry point from the header: `? <base> + dwo(<base> + dwo(<base>+0x3c) + 0x28)`.
2. `bp` it, `go`. At entry, `@rcx` = `DriverObject`, `poi(@rsp)` = return addr (into
   `nt!PnpCallDriverEntry`). `bp` that return, `go` — now the table is populated.
3. `MajorFunction[0x0e]` (IRP_MJ_DEVICE_CONTROL, the IOCTL dispatch) is at **`DriverObject+0xe0`**.
   In the dispatch, the `IoControlCode` is `IO_STACK_LOCATION+0x18`; the current stack location is
   `IRP+0xB8`. `uf` the dispatch to read the (usually binary-search) IOCTL switch, `decode_ioctl`
   each code, and read each case's `DbgPrintEx` string (`da`) for the human name.

**Symbols must be on the debugger host.** PDBs are never fetched from the target over KD. Find the
exact PDB identity the engine wants with `!sym noisy; .reload /f <mod>` (it prints `<pdb>\<GUID>\...`),
then get that PDB onto this host. **Gotcha: `.sympath` / `.sympath+` swallow the *rest of the command
line* — they ignore `;`, so anything chained after them (`; .reload ...`) is parsed as path text.**
Issue `.sympath` alone, or use the **`set_symbol_path`** tool (goes through the DbgEng
`AppendSymbolPath`/`SetSymbolPath` API, immune to the quirk; appends + reloads). When a driver's
`module!Symbol` names don't resolve, **ask the user for the PDB folder** and apply it with that tool.

## Recording a session while debugging this server

`WINDBG_MCP_TRANSCRIPT=<path>` makes the supervisor write a JSONL record of every tool call, every
session transition, every timeout and every worker death (`src/record.rs`; the README has the
format). It is off unless the variable is set, and it is often the fastest way to answer "what
actually happened in that session" — the `tracing` stream on stderr is prose about the *server* and
interleaves both roles, while this is values about the *session*, keyed by session and request.

Two things worth knowing when using it here:

- **It records the supervisor's view.** A worker inherits the variable and ignores it (the role
  check in `main` runs first), so there is exactly one writer and no interleaving. A fact that
  exists only inside a worker reaches the transcript only if it crosses the pipe as a value — which
  is the same rule as everything else in `src/structured.rs`, and the reason `debug_batch` grew a
  typed report.
- **`windbg-mcp --render-cast <transcript.jsonl>`** turns one into an asciicast. That is the
  supported way to produce the recordings under `examples/` and `docs/` — the older ones are
  hand-reconstructed and say so, and a new walkthrough should not add another.

Recording a **live kernel** session is where this needs care, because a transcript of one is as
sensitive as the target: not the connection (attach by `profile` and there is no key in it), but
everything the debugger printed — stack frames, strings, whatever the guest holds. Nothing but
secrets is masked, so treat the file like a crash dump: keep it out of the repo, and delete it when
the investigation is done. It is **appended** to, so a path reused across runs accumulates.

## Plugin vs. dev build

This project is also installed as a user-scope Claude Code plugin (`windbg-mcp@windbg-mcp`), which is
a snapshot of the last *published* release and does **not** track working-tree edits. In this repo
the plugin is **disabled locally** (`.claude/settings.local.json`) so the dev build above is what
runs. Keep machine-specific server wiring (absolute paths) out of version control.
