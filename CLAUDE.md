# CLAUDE.md

Guidance for Claude Code working in this repo. `README.md` is the map — it carries the tool table
and links out to one document per topic under `docs/` (`architecture.md`, `sessions.md`,
`tool-surface.md`, `structured-results.md`, …); this file covers the non-obvious operational
workflows.

**Most of that guidance is not in this file, and that is deliberate.** What every session needs is
here; what only a *part* of the tree needs is a path-scoped rule under `.claude/rules/`, loaded when
Claude reads a file it covers; what is a *procedure* is a skill under `.claude/skills/`, whose body
costs nothing until it is invoked. *Where the rest of it lives* below is the index of both. Add to
this file only what a session touching none of those files still has to know — it is loaded in
full, every time, and length here is paid for by every other instruction competing with it.

## What this is

`windbg-mcp` is a Rust MCP server (`rmcp`; stdio, or HTTP under `--listen`) exposing
**WinDbg/DbgEng** for live user-mode,
kernel, crash-dump, and Time Travel Debugging (TTD) work. The low-level DbgEng bindings come from
the sibling crate [`dbgscope`](https://github.com/glslang/dbgscope) (a **path/git dependency we grow
ourselves** — do not add third-party DbgEng crates).

**A new DbgEng primitive is a typed `dbgscope` method**, returning `Result<_, DbgEngError>` rather
than `panic!`/`.expect`, never the `execute` text hatch. It is here rather than in
`.claude/rules/cargo-and-dependencies.md` with the rest of the dbgscope material because it binds a
Rust-only change, which loads that rule never — it is scoped to the manifests and `build.rs`.

**The binary has two roles.** Started normally it is the **supervisor**: MCP on stdio — or over HTTP,
where `--listen` routes the same non-worker role to `serve_http` — and no DbgEng in either case.
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


## Where the rest of it lives

**Rules load themselves; skills you invoke.** A rule under `.claude/rules/` carries a `paths:` glob
and is pulled into context when Claude reads a file matching it. The three about something other
than this server's code are scoped to that thing — a `Cargo.toml`, a `.md`, a `.ps1`. The nine
about the code share **one** scope: `src/**/*.rs`, `tests/**/*.rs` and `build.rs` — which is
`build.rs`'s own `INPUTS` less the two manifests, those having a rule of their own. That trigger is
a **read**, not a grep, so if you are about to reason about a subsystem from search results alone,
open the rule first.

**They share a scope because per-rule scoping was measured and did not pay.** Review on
[#285](https://github.com/glslang/windbg-mcp/pull/285) filed **nine** findings that were one file
whose editor a rule binds and whose `paths:` did not name it, spread across rounds one to nine, and
six more were found by enumerating rather than waiting for the next round. There was no end to them
because this crate's files are entangled: every tool call crosses `server.rs`, `engine.rs`,
`proto.rs` and `worker.rs`, so most rules bind most of them. Measured at the restructure, against
the 72,396 bytes of all eight then, `engine.rs` already loaded
**89%**, `worker.rs` and `server.rs` 69%, `proto.rs` 62%. Eleven hand-maintained lists were buying
11–38% on the files anyone actually edits, at a review round for each one that was wrong. One scope
buys that back by leaving nothing to get wrong. Where the laziness still pays is the other axis, and
it is untouched: a session that touches no Rust never loads the code rules at all, and picks up at
most the three narrow ones. Measured after round twelve: **77,169 B** against **6,496 B** —
a measurement rather than an invariant, since any edit to a rule moves it, and the second of those
figures was already stale by 30 bytes when first written here. How many narrow rules fire is
deliberately not stated: the globs intersect (`examples/README.md` matches two rules, `build.rs` nine),
and two attempts to give the exact composition were both wrong, one in the commit that fixed the
other. `/handoff` carries the method and what went wrong with it.

So the *Covers* column is the index. The nine are split by **subject**, not by which files trip
them — read it to pick the one you want.

| Rule (`.claude/rules/`) | Loads when you touch | Covers |
|---|---|---|
| `cargo-and-dependencies.md` | `Cargo.toml`, `Cargo.lock`, `build.rs` | moving the `dbgscope` `rev` pin, why a `[patch]` is never committed, and why a green dbgscope PR says nothing about Miri |
| `cross-target-check.md` | any `src/` or `tests/` Rust, or `build.rs` | type-checking the whole crate from a Mac, `build.rs`'s PE version resource and its expected warning, reading a dependency's pinned source with `cargo fetch`/`metadata` |
| `markdown-and-docs.md` | `**/*.md` | CI's two non-Rust gates: `cargo fmt --all --check` and the markdownlint globs |
| `powershell-scripts.md` | `**/*.ps1`, `tools/**`, `examples/**` | the three ways a shipped `.ps1` fails only under PowerShell 5.1; draining stderr when driving the server from a script; handling a token so it stays out of the transcript |
| `measurement-provenance.md` | `tools/**`, `docs/**/*.md` | which build answered, why an exe's date is not evidence, and why a narrowed surface has to be captured from a narrowed listener |
| `execution-waits.md` | any `src/` or `tests/` Rust, or `build.rs` | the two waits, what a raw `execute` of execution-control text leaves behind, `settle`, the load-wait outcome, the session fuzz |
| `async-runs.md` | any `src/` or `tests/` Rust, or `build.rs` | `continue_async`: the slot, the filing task, the refusal, `submit_gate`, breaking the pump, bars, `break_in` against `interrupt` |
| `session-teardown.md` | any `src/` or `tests/` Rust, or `build.rs` | what `end_session` does to a dump, a live kernel, an attached process and a launched one — and the handle it still accepts |
| `spawned-console.md` | any `src/` or `tests/` Rust, or `build.rs` | `CREATE_NO_WINDOW` and why it is conditional; what a launched debuggee gets instead |
| `worker-architecture.md` | any `src/` or `tests/` Rust, or `build.rs` | the 32-bit worker image: deciding before the engine exists, `x86\`, the build-identity check, falling back |
| `tool-surface.md` | any `src/` or `tests/` Rust, or `build.rs` | adding a tool: the second file, output schemas carrying no prose, per-client surfaces, `TOOL_NOTES`/`SUMMARY_NOTES` |
| `listener-clients.md` | any `src/` or `tests/` Rust, or `build.rs` | several clients on one listener: credentials, per-client surfaces, ambient identity, the lease, driving `2026-07-28` by hand |
| `transcripts.md` | any `src/` or `tests/` Rust, or `build.rs` | `WINDBG_MCP_TRANSCRIPT`, what it records that stderr cannot, and `--render-cast` |

| Skill (`.claude/skills/`) | Invoke when |
|---|---|
| `/tiers` | before claiming a change is covered by a green run, or to turn on the dump, bounded, live-kernel, TTD or 32-bit tier |
| `/review-round` | working bot findings on a PR, or before calling a review done |
| `/live-kernel` | attaching to a kernel target, walking a driver's IOCTL dispatch, or diagnosing a parked attach or unresolved symbols |
| `/eval-bench` | running `tools/local_model_eval.py`, adding or re-grading a task, or writing up a benchmark result |
| `/handoff` | updating the handoff docs, closing a `FOLLOWUPS.md` item, or writing prose that states a rule about how this code behaves |

Two things about this layout that are easy to get wrong. **`skills/` at the repo root is not
`.claude/skills/`**: the first is the *shipped* plugin skill (`windbg-debugging`, published through
`.claude-plugin/plugin.json` to whoever installs this server), the second is this repo's own working
guidance and ships nowhere. Put nothing about editing this codebase in `skills/`. And **a rule's
prose is not linted** — CI's markdownlint globs cover `docs/**` and `skills/**`, and `.claude/**` is
in neither.

## Updating the running windbg MCP after code changes

**Two shapes, and which one you are in decides the whole procedure.** Both run
`target\release\windbg-mcp.exe` and both hold an open handle to it, so `cargo build --release`
fails either way at the final replace step with `Access is denied (os error 5)` — *after*
compilation has already succeeded. What differs is **who** holds the handle, and therefore whether
you can let go of it:

| | **stdio** | **service over `--listen`** |
|---|---|---|
| Started by | Claude Code, per session | the SCM, at boot (`AUTO_START`) |
| Holds the exe | the client's own child process | a service you can stop |
| Frees the exe by | renaming it (you cannot stop it without ending the session) | `sc.exe stop` |
| New code loads on | `/mcp` reconnect | `sc.exe start` |
| `/mcp` reconnect alone | **is** the fix | changes **nothing** — it reopens a socket to the same process |

**Read the registration to tell them apart, not the host.** `claude mcp list` prints each server's
transport — a URL marked `(HTTP)` is the second column, a command line is the first. A running
service proves nothing on its own: a host can serve HTTP clients from one *and* register a stdio
server for this project, and then `sc.exe query` picks the wrong column. That failure is worse than
guessing, because `session_status` answers for whichever server is **registered** — so you would
read the stdio supervisor's empty session list and then stop a service holding somebody else's live
targets.

**`(HTTP)` is still not enough on its own**, because a listener can also run in the *foreground*
(`docs/remote-listener.md`) — so the registered URL may be a process the SCM knows nothing about
while an unrelated service sits beside it. What settles it is which process holds the **guest-side**
socket.

**The registered URL gives the *local* port, which need not be the guest's.** A forward is
`-L <local>:<host>:<remote>` and `ssh` treats those as separate fields, so `-L 9000:127.0.0.1:8765`
is perfectly ordinary. Comparing the URL's port against the service would then reject a real
service — and worse, if some unrelated service on the guest happens to listen on the *local*
number, it would correlate the registration with that one and send you to stop it. So read the
remote port out of the forward rather than assuming it:

```console
$ ps -Ao args= | grep -oE '\-L [0-9]+:[^ ]+'        # on the client
-L 8765:127.0.0.1:8765                              # local 8765 -> guest 8765 (they can differ)
```

Then correlate **that** remote port on the guest:

```pwsh
$remote = 8765                                                          # from the forward, not the URL
(Get-NetTCPConnection -LocalPort $remote -State Listen).OwningProcess    # 5524
(Get-CimInstance Win32_Service -Filter "Name='windbg-mcp'").ProcessId    # 5524 -> it is the service
```

A mismatch means the endpoint you are talking to is *not* that service, and stopping it releases
somebody else's targets while changing nothing about yours. On this bench the two ports happen to
be equal and the pids match, so it is the second column — and the equal ports are a coincidence of
this setup, not something to build the check on.

### The stdio shape

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
   This builds the `dbgscope` revision pinned in `Cargo.lock` and writes a fresh
   `target\release\windbg-mcp.exe`. If this `windbg-mcp` change depends on a newly pushed
   `dbgscope` commit, move the pin first — edit the `rev` in `Cargo.toml`, then
   `cargo update -p dbgscope` — and commit both with the `windbg-mcp` change (see below: the update
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

### The service shape (this repo's ARM64 bench)

Measured 2026-09-18. The registered server is **not** a child of Claude Code: it is a Windows
service on the debugger guest, and the client reaches it over HTTP through an ssh port-forward from
the Mac. Ask the host rather than reading the wiring from here — it is per machine, and this is a
public repository, so the shapes are given with placeholders:

```console
$ sc.exe qc windbg-mcp     # on the guest
BINARY_PATH_NAME : <repo>\target\release\windbg-mcp.exe --service --listen 127.0.0.1:<port>
START_TYPE       : 2   AUTO_START          SERVICE_START_NAME : LocalSystem
$ ps aux | grep ssh        # on the client, to find the forward
ssh -f -N -L <local>:127.0.0.1:<remote> <user>@<guest>
```

**`sc.exe`, never bare `sc`.** In PowerShell — which is the shell `README.md`'s own install steps
use — `sc` is an alias for `Set-Content`, so `sc stop windbg-mcp` writes the text `windbg-mcp` to a
file called `stop` and reports nothing wrong. Over ssh into `cmd.exe` the bare name happens to
reach the real thing, which is how a runbook written from an ssh session ships a command that fails
silently for everyone reading it in a PowerShell window.

So **the rename dance is unnecessary and the `/mcp` reconnect is useless**: stopping the service
frees the exe outright, and reconnecting only reopens a socket to whatever process the SCM is
running. The procedure is:

1. **Check for live sessions first**, and **not with `session_status` alone.** Stopping the service
   kills the supervisor, and its workers exit with it, so every open target goes — including other
   people's. There is no `.stale` equivalent here: the old code does not survive the stop.

   `session_status` answers for **the calling client only** (`Sessions::snapshot` filters
   `s.owner == caller`, deliberately — another client's handles would be unusable and listing them
   would say how many clients this server has and what they are debugging). On a listener serving
   one credential that is the whole truth; on one serving several it is not, and a clean
   `session_status` is no evidence at all about the others. What settles what is open *right now* is
   the **worker count of the service you matched above** — a supervisor spawns one worker per live
   session, and a worker is a direct child of it:

   ```pwsh
   $svc = (Get-CimInstance Win32_Service -Filter "Name='windbg-mcp'").ProcessId
   @(Get-CimInstance Win32_Process -Filter "Name='windbg-mcp.exe' AND ParentProcessId=$svc").Count
   ```

   **Scoped to that pid on purpose.** A bare `Get-Process windbg-mcp` counts every supervisor on
   the guest and all of their workers — and this section's whole premise is that a stdio supervisor
   and a service can coexist there — so it reports an idle service as holding sessions. Measured
   here: the service is pid 5524 with parent 908 (`services.exe`), and one open session adds pid
   7228 whose parent is 5524.

   **Neither of those is a roster, and `--list-listen-clients` is not one either**: it reads the
   credential *file*, and the file and the running service can disagree — a `--remove` or
   `--rotate` whose reload failed leaves a token the service still accepts and the file no longer
   names, which is exactly the case you would run it to check. There is no way to ask the service
   what it has in force; its only channel carries a status code and no data
   (`docs/remote-listener.md`). And the process count is a reading *at an instant*: a client the
   file does not name can open a session between your check and your stop. So on a multi-client
   listener this is a maintenance window and out-of-band coordination, not a check — nothing in the
   server will do it for you, and nothing in it can.
2. **Put the guest's tree on the commit you mean to run** — *that* commit, named. A branch under
   review is not `main`, and fetching `main` here builds a different tree and then attributes
   everything you measure to the code you meant. So pass the ref and **check the head afterwards**
   rather than trusting the fetch:
   ```console
   git -C <repo> status --short
   ```
   **Read that first and stop if it prints anything.** `reset --hard` discards uncommitted tracked
   work without asking, and a shared bench's tree is dirty more often than not — this session put
   files there with `scp` repeatedly. Checking *after* the reset, which this step did until review
   caught it, cannot report what the reset destroyed: it shows a clean tree and calls it safe.
   Commit, stash or copy the work aside, then:
   ```console
   git -C <repo> fetch <url> <branch-or-sha>
   git -C <repo> reset --hard FETCH_HEAD
   git -C <repo> log --oneline -1
   ```
   `&&` is deliberately not used to chain these: it is a PowerShell 7 operator and a parse error in
   5.1, which is the shell this section's reader may well be in — the same trap as `sc` below.
   Fetch **over HTTPS by URL**: this guest's `origin` is an SSH remote with no key on it, so a plain
   `git fetch` fails with *"make sure you have the correct access rights"* — which reads as a
   permissions problem and is a missing key. Giving the URL avoids reconfiguring their remote
   (`dbgscope`'s remote there is already HTTPS and fetches fine).
3. **`sc.exe stop windbg-mcp`**, and *verify* — `sc.exe stop` prints the state at the moment of the
   request, which is still `RUNNING`. `sc.exe query windbg-mcp` is what says `STOPPED`, and the gap
   is not always brief: a stop ends the accept loop and *then* releases every target, which on a
   host holding a live kernel is minutes. `STOP_PENDING` is not stopped, and connections already
   accepted are served until the process exits. The name is fixed by
   `--install-service`, which is why `README.md`'s install ends `Start-Service windbg-mcp`; the
   *path* it was installed from is the machine-specific half, and `sc.exe qc` prints that.
4. **Check free space before building.** This guest fills up, and the failure names a compiler bug
   rather than a disk (`rustc-LLVM ERROR: IO failure on output stream`). Measured today:
   **2.0 GB** free against a 9.79 GB `target\debug\incremental`; deleting that one directory —
   regenerable, git-ignored, and *not* `target\release`, which is the service's image — gave
   11.0 GB back.
5. **`cd <repo>` first, then `cargo build --release`.** No rename: the path is free. 34.7s here.
   The `git -C <repo>` above updates that checkout **without changing the shell's directory**, so a
   bare `cargo build` run from anywhere else either finds no manifest or — worse — builds a
   different checkout and restarts the service on it. The staging paths below are relative to
   `<repo>` for the same reason.

   **This does not rebuild the 32-bit worker, and the identity check will reject the old one.**
   `x86\windbg-mcp.exe` is a second target triple Cargo does not build for you, and the build
   identity on `WorkerMessage::Ready` refuses a worker built from *any* other state of the tree —
   which **a commit moves**, not just a code change, since the identity digests the uncommitted
   diff of `build.rs`'s `INPUTS` and committing takes that diff to empty
   (`.claude/rules/worker-architecture.md`). So a documentation-only commit is enough to strand it,
   and the symptom reads as a *missing* file rather than a stale one: "this host could not give the
   target a 32-bit worker", with every 32-bit dump and WoW64 attach losing SOS. Rebuild and stage
   it with the supervisor:
   ```console
   cargo build --release --target i686-pc-windows-msvc
   mkdir target\release\x86
   copy target\i686-pc-windows-msvc\release\windbg-mcp.exe target\release\x86\
   ```
   It lands in the triple's own directory, not in the `x86\` subdirectory the loader rule needs, so
   the copy is the point — and the `mkdir` is not boilerplate, because **this guest deploys no
   `target\release\x86\` at all** (checked 2026-09-18). Nothing was stranded here by the rebuilds
   above, which is the reason to write the step down rather than rely on remembering it.

   **The worker also needs a 32-bit `dbgeng.dll` beside it, and without one the copy buys nothing.**
   `engine::x86_worker_image` returns `None` unless both files are in `x86\`, and that check is not
   caution: the engine is an import-table dependency the loader resolves *before `main`*, so a
   worker with no engine next to it does not fail to open a dump — it fails to **start**, as a
   loader error with no Rust in it. Staging the exe alone therefore leaves the fallback exactly
   where it was. That fallback is deliberate and not a failure: an x86 target opens fine in this
   build and only SOS is lost (`.claude/rules/worker-architecture.md`).
6. **`sc.exe start windbg-mcp`**, then verify the *process* rather than the service state — a new
   `Get-Process windbg-mcp` `Id` and `StartTime`, against the exe's `LastWriteTime`.
7. **Nothing to do on the client.** The tunnel survives the restart (it forwards a port; only the
   far end went away), and the next tool call reconnects on its own — measured: an `open_dump`
   straight after `sc.exe start` succeeded with no `/mcp` reconnect. And nothing to delete afterwards.

**Do not paste this bench's own wiring back into this file.** The hostname, account and port are
machine-specific, `AGENTS.md` keeps them out of version control, and the repository is public —
which is how a sandbox guest's name reached a tracked file once and had to be taken out again.

A worker is still re-executed from the supervisor's own image, so the consistency argument above
holds — but here the supervisor is gone the moment you stop it, so there is no window in which old
and new coexist.


## Local verification (no session restart needed)

For a compile/behavior check without touching the locked release exe, use the **dev profile**
(writes `target/debug`, which the registered release server never holds): `cargo test` and
`cargo clippy --all-targets`. The release
build differs only in optimization and is exercised by CI on a fresh runner.

The dev exe can be locked too — by a worker left running from a driver script or a killed tier —
and the failure is quiet: `cargo build` fails at the final replace step with
`Access is denied (os error 5)` after everything before it succeeded, and the next run silently
executes the old code. `.claude/skills/tiers/SKILL.md` has the kill-by-path recipe (never `/IM`,
which would drop every session the registered release server holds), what a pass count does and
does not say, and how to turn each tier on.

## Plugin vs. dev build

This project is also installable as a user-scope Claude Code plugin (`windbg-mcp@windbg-mcp`), which
is a snapshot of the last *published* release and does **not** track working-tree edits.

**What is registered here is neither that plugin nor a local build** (checked 2026-09-18, and this
paragraph used to say otherwise): this project has a single MCP server, and it is an **HTTP**
transport on a forwarded loopback port — the guest's service, which is the second column of the
table above. Its name and endpoint are machine-specific and deliberately not written down here; ask
the host, as that table says. There is no `.claude/settings.local.json` disabling anything; the
`.claude/` directory holds `rules/` and `skills/` and nothing else. So a change is live once the
**service** has been restarted, and never because a build finished on this Mac — which cannot
produce a Windows binary anyway.

Keep machine-specific server wiring out of version control. The registration lives in
`~/.claude.json` under this project, and it carries a **bearer token** for the listener, so treat
that file the way `.claude/rules/powershell-scripts.md` says to treat a token: do not print it, and
verify it by hash if you must check it at all.
