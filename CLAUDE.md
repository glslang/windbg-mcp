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
role (both write to the supervisor's stderr, told apart by `tracing` target — `windbg_mcp::worker`
against `windbg_mcp::engine` and friends), and killing the supervisor leaves no workers behind —
they exit when their request channel closes.

The same records are also readable **through the tool surface**: `server_log` serves a bounded ring
of them (`src/logbridge.rs`), with a worker's tagged by session, which is the only way to see them
when the client is not on this machine (`--listen`). It is a copy of the stderr stream, not a
replacement — worker stderr is untouched — so it holds nothing below the level the server was
started with; `RUST_LOG` widens both together. The ring is bounded, so it holds the run-up to a
failure rather than a session's history — a transcript (below) is what keeps history.

The **supervisor↔worker protocol channel** is a pair of inherited anonymous pipes, *not* the
worker's stdio: anything a worker prints to stdout is drained into the log and cannot reach the
protocol.

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
   `win-kexp` commit, move the pin first — edit the `rev` in `Cargo.toml`, then
   `cargo update -p win-kexp` — and commit both with the `windbg-mcp` change (see below: the update
   command alone does **not** move a `rev` pin). The running server keeps executing the *old* code from the
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

`win-kexp` is a **git dependency pinned to an exact `rev`**, not a path dependency — a `windbg-mcp`
build pulls it from GitHub, so **local edits to a win-kexp checkout are invisible to a `windbg-mcp`
build until they are pushed** and the pin is moved. Add new DbgEng primitives as typed `win-kexp`
methods (returning `Result<_, DbgEngError>`, not `panic!`/`.expect`), not via the `execute` text
hatch.

**`cargo update -p win-kexp` does not move the pin.** `Cargo.toml` names a 40-character `rev`, so
the update command only re-resolves *that* revision; the pin is moved by editing the `rev` and then
running `cargo update -p win-kexp` to refresh `Cargo.lock`. Commit both. (This file used to say the
update command alone was enough, which silently leaves you building the old code.)

**Develop against the feature branch, not a `[patch]`.** Push the win-kexp branch and point
`Cargo.toml`'s `rev` at that branch commit while iterating: it needs no local checkout on the build
machine, it works identically on every machine, and it travels through git like everything else.
Repoint to the merge commit before the dependent PR merges. A `[patch]` section still works for a
quick local `cargo check` but must never be committed:

```toml
[patch.'https://github.com/glslang/win-kexp']
win-kexp = { path = "../win-kexp" }
```
`git checkout -- Cargo.toml Cargo.lock` afterwards.

**Both repos require an approving review**, and a solo maintainer cannot self-approve, so a green
PR still needs `gh pr merge --admin`. In this harness that call is refused by the permission
classifier — so **the human merges**, and an agent's job ends at "green and waiting". Plan the two
PRs around that: win-kexp first, then repoint and re-verify.

**win-kexp's `cargo clippy --all-targets -- -D warnings` fails on ARM64 with 4 pre-existing errors**
(`shellcode.rs`, `process.rs` — ARM64-only paths its x64 CI never lints). Check them against `main`
before assuming they are yours.

## Local verification (no session restart needed)

For a compile/behavior check without touching the locked release exe, use the **dev profile**
(writes `target/debug`, which the registered release server never holds): `cargo test` and
`cargo clippy --all-targets`. The release
build differs only in optimization and is exercised by CI on a fresh runner.

**The pass count does not say which tiers ran.** Each gate is inside its test, so
`cargo test` reports the same **64 passed** with the debugger tier off as with it on; what differs is
the runtime (~1.3s against ~52s) and the `SKIPPED` lines, which only `--nocapture` prints. Read one
of those two before believing a run covered a debugger claim.

**The dev exe can be locked too, and the failure is quiet.** A worker left running — a driver
script that died mid-session, a debugger tier killed partway — holds `target\debug\windbg-mcp.exe`,
and `cargo build` then fails at the final replace step with `Access is denied (os error 5)` while
everything before it succeeded. If you are driving the binary by hand rather than through
`cargo test`, the next run **silently executes the old code**, which reads as the change not
working. Kill it **by path, not by name**: the registered release server is the same image, and taking it
down with `/IM` drops every session it holds — which for a live kernel leaves the guest frozen (see
the KDNET notes below). Only the processes under `target\debug`:

```pwsh
Get-Process windbg-mcp -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -like '*\target\debug\*' } | Stop-Process -Force
```

Then re-read the build output before believing a behavioural result. Note `cargo clippy` and
`cargo test --bins` do *not* refresh that exe: clippy only checks, and the test harness is a
separate binary.

**Driving the server over stdio from a script: do not redirect stderr unless you drain it.** With
`RUST_LOG` widened the server fills the stderr pipe buffer and blocks mid-request, which looks
exactly like a hung debugger. Leave stderr inherited (it lands in your terminal, interleaved) or
read it on a second thread.

**Both review bots comment per commit**, and a round of findings can land *after* a reply to the
previous round. Before calling a review done, re-check with the head SHA:
`gh api --paginate repos/<owner>/<repo>/pulls/<n>/comments --jq '.[] |
select(.original_commit_id=="<sha>")'` — with `--paginate`, since a busy PR's comments span pages
and the first page is exactly where the older rounds are.

`cargo test` includes `tests/mcp_smoke.rs`, which spawns the **dev** binary (via
`CARGO_BIN_EXE_windbg-mcp`) and drives it over stdio — so it is also clear of the release lock.
After a dependency bump (`rmcp`, `schemars`, `tokio`, `cargo update -p win-kexp`) or an MCP spec
revision, run it and follow [`docs/smoke-test.md`](./docs/smoke-test.md).

Two of its tests budget **what this server costs the model driving it** — the tool surface, paid
once per conversation, and each result, paid every call. They are guarded differently, and the
difference matters when you change one:

- **The surface** is goldened, in `tests/golden/tool_budget.json`, re-recorded by the same
  `UPDATE_GOLDEN=1 cargo test --test mcp_smoke` as the shape golden beside it. Read that diff
  rather than rubber-stamping it: it is the only place the price of a reworded description or a
  widened schema shows up, and it reports per tool (`modules: modelVisible 2112 -> 4200`).
- **Results are not goldened** — their sizes move with what symbols a runner resolves, so exact
  bytes would be flaky. They are per-tool ceilings in the `budgets` slice of
  `tool_results_stay_within_their_budget`, with a table printed under `--nocapture`. So a result
  that grows *within* its ceiling produces no diff anywhere; if you need to see the movement, run
  the tier and read the table. Changing a ceiling is an edit to that slice, not a re-record.

`--nocapture` is what makes either print anything: libtest shows a passing test's output nowhere.
[`docs/token-budget.md`](./docs/token-budget.md) has the baseline and what it exposed — including
the two client behaviours it settled by measurement: `outputSchema` never reaches the model, and
`structuredContent` *replaces* the text block rather than accompanying it. To include the tier that
opens the sample dump through DbgEng, set the gate first (PowerShell, not `VAR=1 cmd`):

```pwsh
$env:WINDBG_MCP_SMOKE_DUMP = "1"; cargo test --test mcp_smoke
```

That tier now also covers the process-per-session behaviour end to end: two sessions coexisting, a
kernel attach parked on a dead port being reclaimed by `end_session`, and no worker process
outliving the connection. It opens the **dump matching this host's architecture** — an ARM64 one is
checked in beside the two x64 samples — and the four assertions that read a *target* rather than
the dump's structure check first that this host can: `nt`'s base has to read, plus a resolved PDB
for the two that walk `nt`'s types. Where it cannot they print `SKIPPED` and pass, so a green tier
on a machine without symbols is not the same claim as a green tier here; read the `SKIPPED` lines
(`--nocapture`) before concluding a change is covered. `docs/smoke-test.md` has the measurements
behind that gate, and the driver-attribution claim still has **no ARM64 fixture at all**
(issue #154). A third tier is `#[ignore]`d because it runs commands out to a watchdog
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
one configured, and a configured profile *is* a live kernel target, so the tier can be run. The
failure this is here to stop is not asking the user for a key; it is concluding "no kernel target on
this host" without looking, shipping the live claim as unverified, and saying so in a PR. Two lines
settle it:

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

**The transport does not have to be KDNET, and the target does not have to be x64.** The variable is
a DbgEng connection string, passed through untouched, so `com:port=COM1,baud=115200` is as valid as
a `net:` one. Three assertions gate themselves on what the target actually is rather than on the
tier: the KD endpoint being owned by the worker is a UDP claim, the key-redaction claim needs a key
to look for, and the two **pool** tests need an x64 target because the walker decodes x64 pool
descriptors. Each says so when it stands down; none of them passes quietly.

### Two ways a target is reached, and neither is "the" procedure

**KDNET.** Check the target is reachable *before* starting the tier, not by starting it — an attach
that finds nothing parks its worker in `WaitForEvent(INFINITE)` for the whole run and reports a
timeout that measures the environment rather than the code. What settles it is not "can I reach the
guest" but **does the guest's `bcdedit /dbgsettings hostip` equal this debugger host's current IP**,
on the port the profile names; the host IP moves between sessions. Compare the key by *hash* rather
than printing it.

*Finding* the guest is topology-specific. On the machine that paragraph was written for, the
debugger host is itself a Hyper-V guest — `Get-VM` does not exist and there is no local VM to start
— so the target is a *sibling*: it appears in the neighbour table (`Get-NetNeighbor | ?
LinkLayerAddress -like '00-15-5D*'`) and answers **TCP 5985** and nothing else, ICMP and 445 being
closed, so a failed ping proves nothing there. With several neighbours the table will happily
validate the wrong guest, which is what the `hostip` comparison is for.

**Serial, which is what the Parallels bench uses** — and there KDNET is not merely unconfigured but
*impossible*: guests get a `Parallels VirtIO Ethernet Adapter` (`PCI\VEN_1AF4`), and `1AF4` is not
in the Debugging Tools' `VerifiedNICList.xml`. `prlctl set <vm> --device-set net0 --adapter-type
e1000` is accepted and silently ignored on ARM, leaving the guest with no network at all. Do not
spend an afternoon on it. The wiring that works is a TCP socket between two guests:

- target `serial0` → `tcp://localhost:2020`, **client**; `bcdedit /dbgsettings serial debugport:1
  baudrate:115200`
- debugger `serial0` → `tcp://:2020`, **server** — then `prlctl set <vm> --device-connect serial0`,
  or it stays `state=disconnected` and nothing binds the port, and a **VM restart**, or the guest
  never sees a COM port
- `netstat -an | grep 2020` on the Mac: a LISTEN *and* an ESTABLISHED pair means the wire is up
- on the target, `ARM PL011 Serial Port Device (COM1)` in **`Error`** state with no name from
  `GetPortNames()` is correct — that is the kernel debugger owning the port

Three traps on that bench, each of which cost real time:

- **`kd -b` is no longer supported** — the docs say so in those words, and it is silently a no-op,
  so a `kd -k … -b` probe sits at `no_debuggee` against a *running* target and looks like a dead
  link. Use **`-bonc`**. windbg-mcp itself is unaffected; DbgEng issues a proper break-in.
- **Parallels `Pause idle` is on by default**, and a target broken into the debugger burns no CPU,
  so the hypervisor suspends the whole VM mid-run and every later call times out with nothing to
  explain it. `prlctl list` then shows it `paused`, which is *not* a kernel halt.
  `prlctl set "<vm>" --pause-idle off`.
- **A worker killed while holding a broken-in kernel leaves the guest frozen** — `prlctl exec` hangs
  on it. Attaching and detaching properly is the fix:
  `kd -k com:port=COM1,baud=115200 -c ".time;qd"`.

**A pool walk will not finish over 115200 baud.** It reads every committed pool page and times out
at 240s, so on a serial bench "x64-only" and "too slow over this wire" cannot be told apart.

## Live kernel + driver IOCTL gotchas (learned driving HEVD over KDNET)

**Loading HEVD on an ARM64 bench takes two things, and the error names neither.**
`StartService FAILED 577` ("cannot verify the digital signature") means both `bcdedit /set
testsigning on` (a reboot) *and* the driver's signing certificate imported into
`Cert:\LocalMachine\Root` — test signing has nothing to chain to otherwise, and an unexpired cert
that is simply untrusted looks identical to an expired one. `TrustedPublisher` refuses with
`E_ACCESSDENIED` and is not needed for `sc start` of a non-PnP driver. Check HVCI
(`(Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning`)
before blaming signing; `0` means it is not the cause.

**A crash out of an exploit client is usually not a driver bug.** HEVD's stack-overflow client on
this bench bug-checks `0xFC` with the kernel faulting at the *user-mode payload* — its ROP chain
never disables privileged execution of a user page — so the stack is `nt`-only and carries no
`HEVD` frame at all. A fixture that needs a driver frame wants a path that faults **inside** the
driver (issue #154), not a failed exploit.

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

**Nothing resolves at all without `msdia140.dll` beside the engine** — `symsrv.dll` finds a PDB and
that one *parses* it, so without it every module reports `Symbol Type: EXPORT - PDB not found` even
when the identity was known and the file was downloaded. **`symsrv.dll` is the other half, and
System32 does not ship it**: on a machine with neither, a `srv*` path downloads nothing. Worth
knowing because of how that presents on a *dump* — not as missing symbols but as a **memory read
failing** (`0x8007001E`), since a kernel dump's virtual addresses are translated through structures
the engine locates with `nt`'s symbols. That symptom was read as an ARM64 engine limitation for a
while (issue #142); it is not one, and an engine with symbols reads x64 and ARM64 dumps alike. It is **not** store-package-only, which
this repo believed for a while: Visual Studio Build Tools ships it, including an ARM64 build, at
`…\BuildTools\DIA SDK\bin\arm64\msdia140.dll`. Copy it next to the exe (`target\release`, and
`target\debug` for the smoke tiers). **Warm the cache once** afterwards — attach and `.reload /f nt`
— because the first fetch takes minutes and everything around it times out, which reads convincingly
as the parser having made things worse.

## Several clients on one listener (`src/client.rs`)

A `--listen` server holds **one bearer token per client**: `WINDBG_MCP_LISTEN_TOKEN_<NAME>` names
one, the unnamed variable names `local`, and a configured `WINDBG_MCP_LISTEN_TOKEN_FILE` shuts the
environment out entirely rather than merely outranking it. Under stdio everything runs as `local`,
so there is one set of rules and no transport exception. `docs/remote-listener.md` is the operator's
half; what follows is what bites while editing.

**Identity is ambient inside a call and by name outside one.** `crate::client::current()` reads a
task-local that `listen::gate` sets — with `client::as_client`, around the `mcp.handle(req)` that
is the whole MCP call — which is why no tool signature carries a caller. Anything running *outside*
that scope — the listener's own diagnostics, a sweep, a shutdown — gets the default `local` instead
of an error, so it must take the client as a parameter
(`Sessions::live_count_for` against `Sessions::snapshot`). The bug this rule is written from was a
log line reporting `local`'s session count to a named client on reconnect.

**A caller sees only its own sessions**, and that is not a fault to debug: routing, `session_status`,
`server_log`, the four-session cap, closed-session history and lease release are all per client, and
another client's handle is reported *unknown* rather than refused. Two tokens on one host are two
namespaces — if a session "vanished", check which token the request carried.

**There is no tenancy gate any more, and stale memory of it is the likeliest thing to mislead you
here.** Retired 2026-08-20 (`FOLLOWUPS.md` item 28, once #162's ownership had taken the boundary
over). What `Lease` is now: a clock, plus the two answers that were never tenancy. `admit` refuses an
`Mcp-Session-Id` **another client** records (`404`, *unknown* — never "someone else's") and a request
whose own credential is mid-release (`409`, ask again in a moment), and otherwise renews. Gone with
the gate: the reservation and its generation counter, `Occupied`/`409`, the in-flight count and its
epoch, the handover that waited on `Sessions::busy` (and `Sessions::busy` itself), `Arriving`, and
every read of `MCP-Protocol-Version` — the classification behind #168 is deleted rather than fixed,
so a request now presents an id or nothing and the revision does not enter into it. A credential may
hold **several** MCP sessions; they are kept in a set, because an id recorded for nobody is one any
credential may present.

**One lease rule survives, and forgetting it costs a client sessions it was using.** An **admitted**
request renews an existing deadline and creates none:

- *admitted*, because a refusal that renewed would let a stream of wrong session ids hold an
  abandoned client's live kernel target open for ever — the failure the sweep exists to prevent. Both
  refusals return before the renewal, and that ordering is the rule.
- *any* request, not any request of a shape: a credential holding a legacy session can go on to send
  `2026-07-28` ones (a client that upgraded, or restarted inside the grace), and the sweep reads
  `deadline` and nothing else.
- *creates none*, because a clock armed for a credential that holds nothing releases everything it
  opens one grace later. Only a settled MCP session arms one, which is what makes the trap that used
  to sit beside this — a reservation minting nothing and having to hand its deadline back —
  unreachable rather than handled.

The sweep zeroes nothing and waits for nothing, so what keeps it from releasing a session mid-call is
the startup floor in `Lease::new`: a grace longer than the longest a call can keep a client quiet
means **no request of that credential's can still be in flight when its lease expires**. That is the
property the epochs and claim generations were protecting one layer above, and it was already
enforced.

**What rmcp does with session ids, which the ownership answer now leans on.** Two facts, both in
`…/rmcp-3.1.2/src/transport/streamable_http_server/tower.rs`:

- a legacy `initialize` **always** mints one — `create_session()` then `spawn_session_worker`, with no
  check on who is asking — so nothing but this server ever refused a credential a second MCP session,
  and now nothing does. Hence a client's ids are a **set** (an id this server stops recording is one
  any credential may present) and an expiry closes **every** one of them (each abandoned handshake
  otherwise leaves a live service task behind).
- an id the service does not know — never issued, closed by a `DELETE`, or closed by the sweep —
  comes back `404 Not Found: Session not found`. That is deliberately the same status
  `Admission::NotYours` answers with: from the caller's side "not yours" and "not a session here"
  are indistinguishable, and splitting them into a distinguishable pair would confirm a session the
  caller may not touch.

**Driving the listener by hand on `2026-07-28` needs three things, and sending one gets a `400`
that looks like a broken server.** Every request *after the handshake* carries the
`MCP-Protocol-Version` header, `params._meta` with `io.modelcontextprotocol/protocolVersion` *and*
`…/clientCapabilities` (SEP-2567 moved them there when it removed the session that held them), and
SEP-2243's `Mcp-Method` — plus `Mcp-Name`, which is mapped **per method**: `params.name` for
`tools/call` and `prompts/get`, `params.uri` for `resources/read`, nothing for the rest.

`initialize` is the exception and is exempt from all three: it is the request that *establishes*
the revision, so it carries the version in its body, needs no `_meta` and no `Mcp-Method`, and may
omit the header as well. Sending the header anyway is legal and is what `Listener::stateless_opening`
does — which is precisely why the headerless handshake is untested (`FOLLOWUPS.md` item 30). Send
the recipe above on a handshake and you will take the ordinary path rather than the one that
carried the bug. `PowerShell`'s `Invoke-WebRequest` throws
on a 4xx and leaves the body on the exception, so those refusals read as empty when they in fact
name what is missing. Before believing any protocol-level claim about `--listen`, read the validator
that produced it: the rmcp source is on the Mac and needs no Windows build, at
`~/.cargo/registry/src/*/rmcp-<ver>/src/transport/streamable_http_server/tower.rs`.

**A listener test that needs a real engine worker belongs in the debugger tier**, however cheap it
looks — the protocol tier's contract is "no debugger target". An attach cannot *park* without
`dbgeng.dll`: it fails during initialisation instead, which turns a test about a call that does not
return into one about a call that failed fast. CI's Windows runner happens to have the DLL, so
getting this wrong does not show up as a red build.

**Credentials are built from variables handed in, not read from the environment**
(`Credentials::from_entries`), for the same reason as `kdconn::env_entries`: `set_var` is `unsafe` in
edition 2024 and mutates state the whole test binary shares. And they are **stripped from every
child process by prefix** (`client::strip_credentials`), so a token variable added later cannot
quietly reach an engine worker or a `launch`ed debuggee — but a credential under a *different*
prefix would need its own strip.

Two collisions are refused at startup rather than resolved, because the winner would be a `HashMap`
ordering detail: one token naming two clients, and two tokens naming one (names are folded, so
`…_TOKEN` and `…_TOKEN_LOCAL` collide, as do `…_CI` and `…__CI`). **Neither refusal may quote a
token** — they are printed to stderr and, under the service, to a log file.

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
