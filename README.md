# windbg-mcp

[![CI](https://github.com/glslang/windbg-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/glslang/windbg-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/glslang/windbg-mcp?utm_source=oss&utm_medium=github&utm_campaign=glslang%2Fwindbg-mcp&labelColor=171717&color=FF570A&label=CodeRabbit+Reviews)](https://coderabbit.ai)
[![Latest release](https://img.shields.io/badge/release-v0.10.0-blue)](https://github.com/glslang/windbg-mcp/releases/latest)
[![Platform: Windows x64](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](https://github.com/glslang/windbg-mcp#requirements)

An [MCP](https://modelcontextprotocol.io) server that exposes **WinDbg/DbgEng** to AI agents
(Claude Code, Claude Desktop, Cursor, …) over stdio. It drives a live debugger engine for
**user-mode**, **kernel-mode**, **crash-dump**, and **Time Travel Debugging (TTD)** workflows.

The low-level engine bindings live in [`win-kexp`](https://github.com/glslang/win-kexp)
(`src/dbgeng.rs`); this crate adds process-per-session engine supervision and the `rmcp` tool
surface on top.

## Architecture

**One debug session per process.** dbgeng.dll holds a single debuggee session per process — that is
why `.opendump` *replaces* the target rather than opening a second one — so this server runs the MCP
protocol in a **supervisor** process and each open target in its own **engine worker** child
process. Two things follow, and they are why it is built this way:

- **A session that cannot be unwound costs a process, not the server.** A live-kernel attach waits
  for its target with `WaitForEvent(INFINITE)`, and nothing can interrupt a wait that has not yet
  connected — so a guest that never dials in blocks forever. That blocks one worker, which
  `end_session` can terminate. It used to block the server's only engine thread, and the only
  recovery was restarting the server.
- **Sessions are concurrent.** Triage a crash dump while a kernel attach is live; keep a TTD trace
  open while you look at another. Up to four at once.

- **`engine.rs`** — the supervisor: the session registry, worker spawn/teardown, and the routing
  that turns a `session_id` into "which worker". Each session has one queue with one consumer, so
  calls against a session are *serialized* — one runs at a time, and the one running finishes
  before the next starts. Serialized is not ordered: two calls submitted before either has
  answered reach that queue in whichever order wins the race, so await each result before sending
  the next call that depends on it.
- **`worker.rs`** — the child process. The `DebugEngine` is created on, and confined to, one OS
  thread inside it (DbgEng requires serialized, single-thread access, and `WaitForEvent` must run on
  the session-owning thread). A `catch_unwind` guard turns a panic in one operation into a failed
  call rather than a dead session. The *request reader* is a second thread that only ever reads and
  hands on, so it is never blocked by the engine — which is what makes `interrupt` and the
  abandon-a-batch signal deliverable to a worker that is busy.
- **`proto.rs`** — the line-delimited JSON protocol between the two. A closure cannot cross a
  process boundary, so what used to be closures marshalled onto the engine thread are now
  serializable operations — deliberately *tool*-shaped rather than DbgEng-shaped, so a tool that is
  several engine calls (`reachable_from_dispatch`'s call-graph walk) stays one indivisible job. It
  travels on a pair of anonymous pipes the worker inherits, not on its standard handles: an
  extension DLL that prints to the console writes to the worker's stdout, which is drained into the
  log and carries nothing else.
- **`server.rs`** — the MCP tools (see below), built with `rmcp`'s `#[tool_router]`/`#[tool_handler]`.
- **`kdconn.rs`** — kernel connection strings, the one tool argument that is a secret: profile
  resolution, and the `Connection` type whose `Debug`/`Display` are redacted so a key can only be
  unwrapped deliberately (see [Kernel connection profiles](#kernel-connection-profiles-keeping-the-kdnet-key-out-of-the-transcript)).
- **`ttd.rs`** — locates `TTD.exe` and launches trace recording.
- **`main.rs`** — role selection (supervisor or worker), tokio + stdio transport. **Logs go to
  stderr** (stdout is the JSON-RPC channel); workers inherit the supervisor's stderr, so everything
  lands in the same place. Workers never outlive the connection: a disconnect asks every session
  to release its target — all of them concurrently — waits **five seconds**, and terminates only
  the workers that have not finished by then; a worker also exits on its own once its request
  channel closes. A session running a `debug_batch` is told to abandon it by that same request, and
  then gets as long as the batch says it still needs on top of the grace — the only case where a
  disconnect waits longer, and never longer than the batch's own budget allowed.
  Which of those two endings a session gets matters for a live kernel. DbgEng leaves a
  detached-but-halted kernel *frozen*, so a worker that releases its target leaves the machine
  running, while a worker that is terminated leaves it stopped. Five seconds is enough for an
  idle session and for most busy ones, but a session in the middle of long work may not make it,
  so end a live kernel session with `end_session` — which allows considerably longer — rather
  than relying on the disconnect.

**MCP protocol revision:** built on `rmcp` 3.x, this server accepts every revision that SDK knows —
`2026-07-28` and the `initialize`-handshake ("legacy") era before it (`2025-11-25`, `2025-06-18`,
`2025-03-26`, `2024-11-05`) — and serves whichever the client selects. A `2026-07-28` client gets the
stateless, per-request model (`server/discover`, `resultType`, per-request `_meta`) and may open with
`server/discover` instead of `initialize`; older clients keep the handshake, and a client that offers
an unknown revision is answered with `2025-11-25`. That revision also makes SEP-2549's cache fields
mandatory on a paginated result, so `tools/list` answers a `2026-07-28` client with `ttlMs: 0` and
`cacheScope: public`, and omits both for the older revisions, which never defined them. This is why
the `rmcp` dependency has a `3.1.1` floor: every 3.x before it omitted the fields on every revision,
and a client that validates against the spec schema then rejects the whole tool list.

## Requirements

- Windows x64 (host bitness must match the target).
- `dbgeng.dll` / `dbghelp.dll` — present in `System32` on modern Windows 11 (verified with
  `10.0.26100`). This is enough for live user-mode/kernel debugging and crash-dump analysis.
- **For crash-dump `!analyze`** (and any other `!`-extension command), the engine needs the
  WinDbg `winext\` extensions bundled next to the binary — System32's engine ships none, so
  `!analyze` would return *"No export analyze found"*. See *Bundling the WinDbg engine* below.
- **For the kernel driver tools** (`driver_object` / `device_object` / `irp_stack`), the engine
  needs `winxp\kdexts.dll` bundled next to the binary — it exports `!drvobj`/`!devobj`/`!irp`, which
  System32 doesn't ship, so without it those three return *"No export drvobj found"* even though the
  kernel attach itself succeeded. See *Bundling the WinDbg engine* below.
- **For Time Travel Debugging (`.run`) replay**, the System32 engine is *not* enough — it rejects
  `.run` traces (`0x80070057`). You need the **WinDbg engine** (which bundles the TTD replay
  components) loaded next to the binary — see *TTD engine* below.
- `TTD.exe` (the standalone Time Travel Debugging recorder) for `record_trace` — ships with the
  WinDbg / TTD store packages; put it on `PATH`.
- A reachable symbol server (e.g. `srv*https://msdl.microsoft.com/download/symbols`) for symbol-name
  queries like `ttd_calls("ucrtbase!_stdio_common_vfprintf")`. Offline, address-based queries and the
  data model still work; symbol *names* won't resolve.
- **Administrator** for live kernel debugging and TTD recording (not for replay).

## Build or download

Prebuilt Windows x64 binaries are attached to each
[GitHub release](https://github.com/glslang/windbg-mcp/releases) as
`windbg-mcp-vX.Y.Z-windows-x64.zip` (with a `SHA256SUMS.txt` to verify the download
against — the skill's `setup.md` snippet does this for you) — no Rust toolchain needed.
To build from source instead:

```pwsh
cargo build --release
```

`win-kexp` is fetched automatically as a git dependency from [`glslang/win-kexp`](https://github.com/glslang/win-kexp) — no sibling checkout needed.

`cargo test` covers the unit tests plus an end-to-end smoke test that drives the built binary over
stdio. Run it after a dependency bump or an MCP spec revision — see
[`docs/smoke-test.md`](docs/smoke-test.md). It also budgets what the tool surface and each result
cost the model driving them, which a schema change can move without breaking anything —
[`docs/token-budget.md`](docs/token-budget.md).

### Install with Scoop

A community-maintained [Scoop](https://scoop.sh) manifest lives in
[`gitfool/scoop-dungeon`](https://github.com/gitfool/scoop-dungeon)
([#109](https://github.com/glslang/windbg-mcp/issues/109)), which turns the download — and every
later update — into one command:

```pwsh
scoop bucket add dungeon https://github.com/gitfool/scoop-dungeon
scoop install windbg-mcp
scoop update windbg-mcp    # later; the manifest's checkver/autoupdate tracks releases here
```

It unpacks the release zip and — when the `Microsoft.WinDbg` store package is installed on your
machine — its `post_install` copies that package's engine DLLs and its `ttd\`, `winext\` and
`winxp\` subdirectories next to the binary: the whole
[*Bundling the WinDbg engine*](#bundling-the-windbg-engine) step below, done for you on install and
on every update. That copy is local, from a WinDbg you already installed; neither the release zip
nor the bucket redistributes Microsoft's engine. Without that package you get the in-box `System32`
engine: live and crash-dump debugging work, TTD `.run` replay, `!analyze` and the kernel driver
tools don't. The copy happens at install time, so if you add WinDbg afterwards, re-run
`post_install` with `scoop update --force windbg-mcp` (`scoop reset` won't — it only re-links) or
copy the files by hand as below, with `$dst` set to `…\scoop\apps\windbg-mcp\current`.

Point your MCP client at the `current` junction, so an update needs no config change:

```jsonc
{
  "mcpServers": {
    "windbg": { "command": "C:\\Users\\<you>\\scoop\\apps\\windbg-mcp\\current\\windbg-mcp.exe" }
  }
}
```

A connected client holds that binary open (and each engine worker re-executes the same image), so
disconnect the `windbg` server — `/mcp` in Claude Code — before `scoop update`, then reconnect to
actually run the new build.

**The bucket is community-maintained — not by this repo, and not audited by it.** A Scoop manifest
is code, not just a URL: `post_install` is arbitrary PowerShell, run against whatever download URL
and hash the manifest carries at the time, and autoupdate rewrites both on each new release. So
installing from it is a trust decision about that bucket, taken on your own judgement.

Scoop is not required either way. It installs the same
[release asset](https://github.com/glslang/windbg-mcp/releases) described above, which you can
download directly, check against the published `SHA256SUMS.txt`, and verify with
`gh attestation verify` — see [*Releasing*](#releasing) — none of which a third-party manifest can
promise on this project's behalf.

### Bundling the WinDbg engine

Basic live and crash-dump debugging works on the `dbgeng.dll` already in `System32`. These do not,
and each needs files that engine does not ship:

| Wanted | Needs |
| --- | --- |
| TTD `.run` replay | `ttd\` — System32's engine rejects traces with `0x80070057` |
| Crash-dump `!analyze` | `winext\` for the extension, `triage\` for its module attribution |
| `driver_object` / `device_object` / `irp_stack` | `winxp\kdexts.dll` |
| `module!name` symbols anywhere | `msdia140.dll` + `symsrv.dll`, plus a symbol path |

The fix is a one-time file copy: `DebugCreate` binds to whichever `dbgeng.dll` the loader finds
first and the app directory is searched before `System32`, so a WinDbg engine copied next to
`windbg-mcp.exe` wins. Note the kernel row — a live-kernel-only user needs this too, even though
the attach itself works on the System32 engine.

**The copy list, what each file buys, and what to do when the store package will not install are in
the skill's [`setup.md`](./skills/windbg-debugging/setup.md).**
It is one document rather than two so the list cannot drift; it is also where symbols, elevation,
kernel connection profiles and the differences an ARM64 host brings are written down.

Most of these fail *quietly* rather than loudly — a missing `triage\` turns `!analyze` into
`ANALYSIS_INCONCLUSIVE`, a missing `msdia140.dll` silently downgrades symbols to exports — so it is
worth doing deliberately rather than discovering later.

## Use with an MCP client

Point your client at the built binary, e.g. Claude Code:

```jsonc
// .mcp.json  (or claude_desktop_config.json under "mcpServers")
{
  "mcpServers": {
    "windbg": {
      "command": "C:\\workspace\\windbg-mcp\\target\\release\\windbg-mcp.exe"
    }
  }
}
```

### On another machine

The server has to run where DbgEng does, but the client and the model do not. `--listen <addr>`
serves the same tools over HTTP instead of stdio, so a Mac can drive a Windows VM:

```console
# Windows, with WINDBG_MCP_LISTEN_TOKEN set to a long random string
windbg-mcp.exe --listen 127.0.0.1:8765
# client machine — the same string, spelled out: the variable lives on the Windows
# host, and a shell without it sends an empty bearer and gets a 401 on every call
ssh -N -L 8765:127.0.0.1:8765 windbg-vm
claude mcp add windbg-vm --transport http http://127.0.0.1:8765/ \
  --header "Authorization: Bearer <the same string>"
```

Install it as a **Windows service** (`--install-service --listen <addr>`, elevated) and it survives
logout, starts at boot, and gets a defined `PATH` and working directory — which is what decides
whether the engine DLLs beside the exe are the ones that load. `Stop-Service` releases every debug
target before exiting, because a live kernel that is merely killed is left frozen.

**Bind loopback and forward over SSH.** This endpoint runs `execute`, `debug_batch` and `launch`
against a live kernel, and the token is sent in clear — a hypervisor's guest network is not private
when the machine being debugged shares it. [`docs/remote-listener.md`](./docs/remote-listener.md)
covers the tokens — **one per client**, each with its own sessions, so two people or two agents on
one listener cannot reach each other's targets — the session lease and its grace, and the one thing
a `409` means: this credential's own expired sessions are still being released, so ask again in a
moment. Nothing else is refused for contention — a credential may hold several MCP sessions, and
requests of one client never wait on another's. For a one-off, [`docs/remote-phase0.md`](./docs/remote-phase0.md) does the same
job over plain `ssh` with no listener; for driving it from a **local model** rather than a hosted
one, [`docs/local-model.md`](./docs/local-model.md) is the runbook and the numbers that decide
whether it fits.

### As a Claude Code plugin

This repo is also a single-plugin [Claude Code marketplace](https://code.claude.com/docs/en/plugin-marketplaces):
installing it registers the `windbg` MCP server **and** a `windbg-debugging` skill that
knows how to drive it (setup, crash-dump, live/kernel, and TTD playbooks).

```text
/plugin marketplace add glslang/windbg-mcp
/plugin install windbg-mcp@windbg-mcp
```

The plugin ships source, not a binary, so after installing you still put the server binary in
place — download a prebuilt release or build from source — and (for `.run` replay, crash-dump
`!analyze`, and the kernel driver tools) bundle the WinDbg engine — the skill's `setup.md`
walks through it, and it mirrors the [*Build or download*](#build-or-download) and
[*Bundling the WinDbg engine*](#bundling-the-windbg-engine) sections above. Then `/reload-plugins`
to connect the server. The plugin points at `${CLAUDE_PLUGIN_ROOT}/target/release/windbg-mcp.exe`.

### From the official MCP registry

The server is listed in the [official MCP registry](https://registry.modelcontextprotocol.io) as
**`io.github.glslang/windbg-mcp`**. Clients that support the registry — or that install
[MCPB](https://github.com/anthropics/mcpb) bundles directly — can add it by name: the client
downloads that release's `.mcpb` bundle, verifies its SHA-256, and wires up the `windbg-mcp.exe`
inside it as an stdio server, with no Rust build or manual binary placement.

The bundle is **Windows x64 only** and ships just the server binary, so the one-time engine setup
still applies — for TTD `.run` replay, crash-dump `!analyze`, and the
`driver_object`/`device_object`/`irp_stack` tools, drop the WinDbg engine DLLs next to the
client-extracted `windbg-mcp.exe` (the skill's `setup.md` covers it). Basic live and crash-dump
work runs on the in-box `System32` engine without them — a kernel attach included, but not those
three tools, which need `winxp\kdexts.dll`.

### Releasing

The plugin sets an explicit `version` in
[`.claude-plugin/plugin.json`](.claude-plugin/plugin.json), so users only receive an update
when that version changes — pushing commits alone does not trigger one. To cut a release, bump
`version` in `plugin.json` and `Cargo.toml`, bump the release badge near the top of this README,
add a matching entry to
[`CHANGELOG.md`](CHANGELOG.md), and tag the commit `vX.Y.Z`. Run
`claude plugin validate . --strict` before publishing. Pushing the tag runs
[`release.yml`](.github/workflows/release.yml), which verifies the tag matches both manifest
versions and the README badge, builds `windbg-mcp.exe`, and attaches the zip + SHA256 checksum to the GitHub release.
It also builds an [MCPB](https://github.com/anthropics/mcpb) bundle
(`windbg-mcp-vX.Y.Z-windows-x64.mcpb`, described by
[`packaging/mcpb/manifest.json`](packaging/mcpb/manifest.json)) and publishes a
[`server.json`](server.json) entry to the [official MCP Registry](https://registry.modelcontextprotocol.io)
(`io.github.glslang/windbg-mcp`) with the `mcp-publisher` CLI over GitHub OIDC — no secrets. CI
stamps the release version into both files and the bundle's SHA-256 into `server.json`, so
neither is part of the manual bump list above.
The zip also gets a signed
[build-provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
tying it to the workflow run that built it — verify with:

```pwsh
gh attestation verify <zip> --repo glslang/windbg-mcp `
   --signer-workflow glslang/windbg-mcp/.github/workflows/release.yml
```

(`--repo` alone only proves the attestation came from *some* workflow in this repo;
`--signer-workflow` pins it to the release workflow.)

## Walkthroughs

- [`docs/coordinates.md`](docs/coordinates.md) — pairing this server with a disassembler, which is a
  coordinate rather than an integration: `(module, image identity, RVA)`, the symbol-server key it
  builds, and a worked join of a `crash_triage` frame to a function in an image fetched on another
  machine from two integers.
- [`docs/crash-dump-walkthrough.md`](docs/crash-dump-walkthrough.md) — triaging a real kernel
  minidump ([`docs/samples/052126-34312-01.dmp`](docs/samples/052126-34312-01.dmp)): a
  `0x9F DRIVER_POWER_STATE_FAILURE` traced to `nvlddmkm.sys` — `crash_triage` for the bug check as
  fields, then `!ext.analyze -v` and a manual device-stack walk for the culprit it cannot name, with
  the real outputs and the partial-minidump (`0x80040205`) gotcha. Ends on a second sample, a
  `0x13A` in a **PDB-less driver**, where `!analyze` says `Unknown_Module` and the frame says
  `MessageManager+0x1654` — the same offset in five dumps that loaded the driver at five addresses.
- [`docs/ttd-walkthrough.md`](docs/ttd-walkthrough.md) — a hands-on tour of the TTD tools against the
  [`xusheng6/TTD_lab`](https://github.com/xusheng6/TTD_lab) `helloworld` sample: opening a `.run`,
  surveying events/threads, forward/reverse navigation, memory analysis, and counting `printf` calls
  with symbols (with the real outputs and the gotchas). It maps each tool to the lab's exercises.
- [`docs/flareauthenticator-ttd-walkthrough.md`](docs/flareauthenticator-ttd-walkthrough.md) — a full
  **TTD → Z3 solve** of an obfuscated Qt crackme (Flare-On 12 #8). Defeats an anti-analysis env guard,
  records a wrong-guess run, and uses `ttd_calls`/`ttd_memory`/reverse-navigation to peel control-flow
  flattening + computed calls + encrypted strings down to the exact check: a per-keystroke rolling hash
  that reduces to a pure weighted sum. The 25 weights come from the replay, the 250 `g` values from
  debugger function-evaluation, and Z3 finds a satisfying code — which reveals the flag (the code is
  intentionally non-unique). Runnable solver in [`examples/flareauthenticator/`](examples/flareauthenticator/);
  recorded terminal session in [`docs/flareauthenticator.cast`](docs/flareauthenticator.cast)
  (`asciinema play`) — [rendered as a GIF](docs/flareauthenticator.gif) in the walkthrough.
- [`docs/driver-ioctl-walkthrough.md`](docs/driver-ioctl-walkthrough.md) — enumerating a driver's IOCTL
  surface and deciding user-mode reachability on a live KDNET kernel: `driver_object`/`uf` to recover
  the `\Driver\mountmgr` dispatch switch, `decode_ioctl` for the access tiers, the device DACL parsed
  from memory, and an `ioctl_trace` sweep — ending with a reachability report (which codes a standard
  user can reach vs. what the I/O manager blocks).

## Tools

| Group | Tools |
|-------|-------|
| Session | `open_dump`, `open_trace`, `attach_kernel_local`, `attach_kernel`, `attach_process`, `launch`, `interrupt`, `end_session`, `session_status` |
| Server   | `server_log` — the server's own log, the supervisor's and every engine worker's, tagged with the session each record belongs to |
| State   | `registers`, `read_memory`, `walk_memory`, `backtrace` (the stack as typed frames, each carrying `module`+`RVA` where the engine can place it, as well as its symbol), `modules`, `threads`, `disassemble` (instructions as records, each with its encoding and, where the engine can place it, its `RVA`), `dx` |
| Crash   | `crash_triage` — a bug check as fields: code and parameters, crashing process, the stack as `module+RVA`, and the faulting driver frame |
| Control | `go`, `step_over`, `step_into`, `set_breakpoint`, `run_to_address` |
| Transaction | `debug_batch` — an ordered sequence with assertions and a rollback the engine process runs on every path |
| TTD nav | `step_back` (`t-`), `step_over_back` (`p-`), `reverse_go` (`g-`), `goto_position` (`!tt`) |
| TTD analysis | `ttd_calls`, `ttd_memory`, `ttd_events`, `index_trace`, `record_trace` |
| Driver IOCTL | `decode_ioctl`, `driver_object`, `device_object`, `irp_stack`, `ioctl_trace`, `reachable_from_dispatch` |
| Kernel pool | `pool_find_tag`, `pool_chunk`, `pool_census`, `pool_diagnostics` |
| User Segment Heap | `heap_list`, `heap_allocations`, `heap_chunk`, `heap_census`, `heap_diagnostics` |
| Raw     | `execute` — run any debugger command, returns full text output |

### Sessions and session handles

The six Session tools that open a target (`open_dump`, `open_trace`, `attach_kernel_local`,
`attach_kernel`, `attach_process`, `launch`) each create a **session** — one engine worker process
holding one target — and return a **`session_id`**. Every tool that touches a target accepts that id
as an optional argument, and it is what **routes** the call to the right worker.

Sessions are independent. Opening a second target does not disturb the first, a call against one
does not queue behind work in another, and ending one leaves the rest alone. Up to `4` at once; at
the limit a new open reclaims the oldest **idle** session, and if every session has a call in flight
the open is refused with the list rather than picking a victim. Sessions end when you `end_session`
them or when the client disconnects — a disconnect is treated as `end_session` on everything, so no
debugger process is left behind. It gives each session a shorter grace than `end_session` does,
though, so end a live kernel session explicitly if you can: one still busy at disconnect is
terminated, and a terminated kernel session leaves its target halted.

Omit `session_id` and a call goes to the **current** session: the most recently opened one that will
still accept work. That is the pre-handle behaviour and it still holds. What supplying the id buys
is that the call can never land on a target you did not open — it fails loudly instead.

The asymmetry is worth knowing, because it is where the guarantee earns its keep. A raw `execute`
that replaces or releases the target (`.opendump`, `.attach`, `.detach`) leaves the session
**retired**: a call naming its handle is refused, while a call naming nothing is still routed there,
because the worker is genuinely the server's current target and a caller who asked for no guarantee
gets what is in front of them. So omitting the id is not merely "whatever is current" — it is also
"whatever that target has since become".
`decode_ioctl` (pure) and `record_trace` (independent of any debug session) do not take one.

`session_status` lists every session — what it is, what state it is in, how long it has been there,
and which one is current — or reports on one you name. It never queues on any worker, so it answers
even while a session is parked.

**Stopping a call that is taking too long.** `interrupt` Ctrl+Breaks a session's engine, exactly as
Ctrl+Break does at a WinDbg prompt, and leaves the session and its target alone. Call it while the
slow call is still outstanding — it travels on the session's queue but is answered by the worker's
*request reader*, so it does not queue behind the operation it is meant to stop. That operation ends
at the debugger's next poll and returns whatever it had reached **to the call that started it**,
marked as cut short, and the session takes the next call immediately. It is bound to the job that
was running when it arrived, so it can never land on the one after it; with nothing running it says
so and does nothing. Two things it cannot reach, both properties of the debugger: an operation that
never polls for the break, and the parked kernel attach below.

A `debug_batch` is the one call that stops *itself*: it checks between steps and, when interrupted,
runs its `always` block and reports `BATCH: INTERRUPTED` — so no step after the interrupt is applied
and the session keeps its target, unlike `end_session`, which also stops a batch but takes the
session with it. Its **rollback is not interruptible**: cleanup runs as part of the same call, and a
restore cut short would come back `Ok` with partial output and be reported as a rollback that
completed while the target was still changed — so an `interrupt` aimed at a batch that is unwinding
says so and sends nothing, as does one repeated while a batch is still stopping.

**Watching a call that is taking a while.** Put a `progressToken` in a call's `_meta` and it reports
on itself with MCP progress notifications while it runs: the engine worker coming up, the target
being claimed, the target being open, a teardown unwinding a transaction — and, when there is
nothing new to say, that it is still running, every ten seconds. `progress` is seconds elapsed and
there is no `total`, since the budget differs per tool and an opener spends up to 30s bringing a
worker up before its own budget starts. Nothing is sent to a call that did not ask. This matters
most over `--listen`, where `session_status` and `server_log` are on the other machine and both are
pull — see [`docs/remote-listener.md`](./docs/remote-listener.md).

**Recovering a session that is stuck.** A per-call timeout abandons the *wait*, not the job, so a
call that reports a timeout may still be running. The case that matters is `attach_kernel`: it waits
for the target to dial in with no timeout, and DbgEng cannot interrupt a wait that has not yet
connected — so a guest that is powered off, not booted with debugging enabled, or pointed at the
wrong host/port/key never arrives, and that wait never ends. `session_status` distinguishes a link
that is still coming up (normal, ~25s for a KDNET resync) from one that has been waiting far longer
than a healthy attach ever takes. For the second, `end_session` is the recovery: it asks the worker
to let go, and terminates the worker process if it will not. Do **not** re-run the open while it is
still waiting — the target was already claimed, so that would attach a second time.

Two caveats, both in the command hatches, and both now confined to a single session. The typed tools
announce their own transitions, but `execute` can replace its session's target directly
(`.opendump`, `.attach`, `.detach`, `.kill`, `.restart`, `.abandon`, `.remote`, `q`/`qd`/`qq`), and
those commands **retire** that session's handle: calls passing it are refused, while calls that pass
no id still reach the worker. `dx` is the second hatch — the data model reaches
`Debugger.Utility.Control.ExecuteCommand`, which runs any command, so an expression that touches
command execution retires the handle too, conservatively, since the command it runs is a runtime
string this server never sees.

Both matches are deliberately biased toward retiring: over-matching costs one re-open,
under-matching would let a stale handle through. Neither can be exhaustive — DbgEng has more ways to
reach the target than a name list can enumerate, and the data model is extensible — so inside
`execute` and `dx` a handle is a strong hint rather than a guarantee. Everywhere else it is a
guarantee, and it is enforced at the front of that session's queue, after everything queued ahead of
it: checking on the caller's side would leave a window in which an `execute { ".opendump …" }`
already queued ahead retires the handle between a caller's check and its call.

### Kernel connection profiles (keeping the KDNET key out of the transcript)

A KDNET connection string carries the target's debug key — `net:port=50000,key=<w.x.y.z>` — and that
key is all anyone on the same network needs to take the debug link. Passing it as a tool argument
puts it somewhere this server does not control: an MCP client keeps a transcript, and a key handed
over once is then copied into messages, tool calls, context snapshots and compaction summaries. That
is what a transcript *is*, not a client misbehaving, so the fix is that the secret never enters the
request.

`attach_kernel` therefore takes **exactly one** of two selectors:

```jsonc
{ "profile": "ctf-vm" }                          // resolved on this host; no key in the request
{ "connection": "net:port=50000,key=1.2.3.4" }   // the raw string, still supported
```

Configure a profile either way — the environment is checked first, then the file:

```pwsh
# Per profile, in the environment the MCP server is launched with. The variable's own suffix is
# the profile name, lowercased: this defines `ctf_vm`, and `ctf-vm` finds it too.
$env:WINDBG_MCP_PROFILE_CTF_VM = "net:port=50000,key=1.2.3.4"
```

```jsonc
// %USERPROFILE%\.windbg-mcp\profiles.json  (override the path with WINDBG_MCP_PROFILES)
{
  "ctf-vm": "net:port=50000,key=1.2.3.4",
  "lab":    "net:port=50001,key=5.6.7.8"
}
```

Keep that file out of any repository — it holds keys, and it is deliberately machine-local. Names
are matched case-insensitively with `-`, `_` and `.` equivalent (as are the environment-variable
names themselves, since Windows matches those that way).

The two sources differ in **when a change lands**. The file is re-read on every attach, so adding a
profile to it works immediately with nothing restarted — that is the one to edit mid-session. An
environment variable is read from the server's own environment, fixed when the process started, so
it belongs in the MCP client's server definition and takes a server restart to change.
`attach_kernel` with **neither** selector answers with the names this host has, which is how an
agent discovers them without ever asking the user for a string.

Configured profiles stay in the supervisor: an engine worker is spawned **without** the
`WINDBG_MCP_PROFILE_*` variables, and is told only the one connection it is opening, over its
private pipe. A `launch`ed debuggee inherits its worker's environment, and a debuggee is exactly the
untrusted program that must not be handed every kernel key on the host.

Connection strings are redacted everywhere else on principle, whichever selector opened the session:
`session_status` reports `kernel target: profile "ctf-vm" (net:port=50000,key=<redacted>)`, and the
value is held in a type whose `Debug`/`Display` are the redacted form, so a log line or an error can
only ever carry the masked one ([`src/kdconn.rs`](./src/kdconn.rs)). The raw string is unwrapped at
exactly one call site, handing it to DbgEng inside the session's own worker process. Redaction
covers `key=` and `password=` values in any connection string, and masks nothing else — debugger
output is never rewritten.

It works off a **parse**, not a text scan: the string is split once into the structure DbgEng's
syntax has, and a secret parameter's value is simply never rendered. The parse is total — every
byte lands in exactly one field, so an unredacted render reproduces the input exactly — which is
what makes "the key cannot get out" checkable rather than a matter of having anticipated every
delimiter. Whitespace **between** parameters is refused rather than interpreted (it reads as either
a missing comma or a stray space, and each leaks the key under the other reading), so a connection
carrying any is rejected up front and reported as `<connection redacted>` in full; whitespace around
the whole string is trimmed as the paste artefact it is.

### Typed operands are operands, not commands

The typed tools build debugger commands by interpolation (`u {address}`, `bp {expression}`,
`!drvobj {name} 7`), so those parameters refuse `;`, line breaks, and `"` — the last everywhere
except `dx`, whose data-model expressions use quoted literals legitimately.

Two things go wrong without that. DbgEng treats `;` as a command separator, so
`disassemble { address: "rip; .opendump C:\other.dmp" }` would replace the debug target from a tool
that reports itself read-only. And `bp <location> "command"` is real WinDbg syntax — `ioctl_trace`
builds exactly that form — so a quote in a breakpoint location arms a command that runs on every
hit, replacing the target at some arbitrary later moment, outside any tool call and outside anything
that could retire the session handle.

Nothing legitimate is lost: these parameters were always single operands. Use `execute` to run a
command list — it is annotated destructive and retires the handle when a command changes the target.

### Walking a structure (`walk_memory`)

Walking a kernel list through `execute` is all-or-nothing. A single unmapped dereference inside a
MASM `.for` loop ends the whole script with `An unexpected exception was raised (0x80040205)` — no
rows, no iteration number, no indication of how many nodes were classified before it. In pool and
use-after-free work that is precisely backwards: "some of these nodes are freed" is the normal case,
and the pointer that will not read is usually the one worth looking at
([#103](https://github.com/glslang/windbg-mcp/issues/103)).

`walk_memory` reads each value on its own, so a hole is a row rather than an end. Three ways to name
the nodes, one of them required:

| | |
|---|---|
| `addresses` | walk these exactly — the bulk read |
| `start` + `stride` | an array: element *i* is `start + i * stride` |
| `start` + `next_offset` | a chain: the next node is the pointer at `node + next_offset` |

`fields` says what to read out of each node (`{name, offset, size}`, size 1/2/4/8, **offsets may be
negative** — a pool header sits 16 bytes before the address the allocator returned). `start` is any
expression `?` evaluates, so a symbol or `poi(<head>)` works; the addresses in a list are numbers, in
any form the debugger prints. Fields of one structure are fetched in a single read and fall back to
per-field reads only where there is a hole, so a node costs one round trip in the ordinary case —
which is what lets a 512-node walk finish over KDNET.

```jsonc
// Every message pointer in a 512-slot handle table, freed ones included.
{ "start": "MessageManager!g_Handles", "stride": 16, "count": 512,
  "fields": [{ "name": "msg", "offset": 8 }] }

// Then the refcount out of each of those pointers — one call, holes and all.
{ "addresses": ["0xffffc00f6ec02f90", "0xffffc00f6ec03000", …],
  "fields": [{ "name": "refs", "offset": 16, "size": 4 },
             { "name": "flink", "offset": 0 }] }
```

An unreadable value comes back as `null` in its own field (`0x????????????????` in the text), a node
where *nothing* read is counted, and the walk carries on — for a list or an array. A **chain** is the
exception, because the address of everything after an unreadable node lived in the bytes that would
not read: it stops and says which node. It also stops on a null link, on a **loop** (reporting where
the list closed — back at the head that is a healthy circular `_LIST_ENTRY`, anywhere else it is
corruption), and at `count`, where it hands back the address to resume from. `count` past the cap of
1024 is refused rather than clamped, so "every node asked for was visited" is never about a number
this server lowered.

### Transactional batches (`debug_batch`)

A sequence that *mutates* a target — patch a byte, arm a breakpoint, resume a thread — has to put
things back afterwards, and a client cannot be relied on to do it. The call that would have sent the
cleanup is exactly the call that times out, and a disconnect sends nothing at all. On a kernel target
that costs the VM: an un-restored patch, or a target left halted.

`debug_batch` submits the whole sequence as one op. It runs **inside the session's engine process**,
which owns the deadline, so the `always` block is reached on every path — success, a debugger error,
an assertion that did not hold, the deadline expiring, the session being torn down under it — before
the tool call returns. Part of the budget is reserved for it up front, because "what is left" after a
step that ran to its own deadline is nothing.

```jsonc
{
  "steps": [
    { "op": "eval", "expr": "poi(hevd!Guard)", "capture": "orig" },   // save
    { "op": "command", "command": "eq hevd!Guard 0" },                // patch
    { "op": "run_to", "address": "hevd!TriggerUaf",                   // confirm, with a verdict
      "expect": [{ "check": "contains", "text": "VERDICT: HIT" }] },
    { "op": "eval", "expr": "@rcx",
      "expect": [{ "check": "eval", "expr": "(@rcx > 0x1000)", "equals": "1" }] }
  ],
  "always": [
    { "op": "command", "command": "eq hevd!Guard {{orig}}" },         // restore, whatever happened
    { "op": "command", "command": "bc *" }
  ]
}
```

Eight step kinds. Five are the debugger itself: `command` (raw), `resume` (a command that moves the
target, plus the wait), `run_to` (a HIT/STOPPED ELSEWHERE/TIMEOUT verdict), `eval` (a MASM
expression's value), and `read_memory`. Three ask the kernel pool the questions the `pool_*` tools
ask — `pool_chunk`, `pool_find_tag`, `pool_census` — because those are walks over the allocator's own
descriptors rather than debugger commands, so no `command` step can stand in for them:

```jsonc
{ "op": "eval", "expr": "@$t1", "capture": "obj" },                    // what the target handed us
{ "op": "pool_chunk", "address": "{{obj}}", "refresh": true }          // what the allocator says it is
```

Inside a batch a walk is bounded by the *step's* share of the budget rather than by the whole call's,
so a `refresh` cannot spend the reserve the rollback lives on; a walk cut short still reports how
much of the pool it covered. Assertions are `contains`, `not_contains`, and `eval` — the
last compares two MASM expressions, so registers, memory and relations between them are all one
check. An `eval` step may `capture` its value under a name that later steps interpolate as
`{{name}}`; a reference that names no earlier capture is refused before anything runs.

**A field this tool does not know is an error, not something to ignore** — the one place in this
server where that is true. Serde drops unknown fields silently, so `"aways"` for `always` would be a
batch with no rollback block at all: mutations applied, nothing restored, `COMMITTED` reported. The
same goes for a misspelt `expect`, which is a step that asserts nothing and lets the batch commit.
Both fail *open*, so both are refused by name.

The report names every step that ran, the exact one that failed, what each step changed, whether the
rollback completed — reported *beside* the original failure, never instead of it — and whether the
session is left stopped, running, detached, or uncertain. A batch that did not commit comes back as a
tool error carrying that whole report.

It carries the same report as values (see [Structured results](#structured-results)), and the
pairing is worth reading once: a batch that **ran** answers `status: "ok"` — the report is the
answer — on a result flagged `isError` when the transaction did not commit or its rollback did not
finish. `status: "error"` is the batch that never ran at all: refused for a malformed step, a stale
handle, too little budget left to start. Reading only `isError` cannot tell those apart, and it is
the difference between "resubmit" and "check what the target is left holding".

Four honest limits, none of them hidden in the report:

- A raw command that prints an error and returns success is a step that *succeeded* with that text
  (DbgEng reports most failures that way), so assert on it if it matters.
- What a step "changed" is a best-effort classification of the command, biased toward reporting a
  change: it is a reporting aid, and the `always` block, not the classifier, is what makes a
  mutation recoverable.
- The reserve buys the rollback *time*, not a guarantee. A step that overruns far enough to consume
  the reserve as well leaves cleanup with no budget; the block is then skipped and the result says
  `rollback: INCOMPLETE`, naming each step that did not run.
- Against a **call timeout** the guarantee is arithmetic: the batch budget is clamped so the
  rollback finishes and the report is written before the caller gives up. Against a **teardown** —
  `end_session`, or a client disconnect, both of which release the target — it is a signal instead.
  The batch is told to stop, does so at its next step, runs `always`, and the teardown waits: the
  worker answers the signal with how long that batch may still need, so the wait covers the step in
  flight as well as the rollback. That figure is the batch's own remaining budget, which was already
  clamped to the caller's patience, so a teardown can never wait longer than the batch could have
  run anyway. What the signal cannot do is *shorten* a step already inside the debugger, so a batch
  of long steps stops at the end of the current one rather than where it stands — and it cannot undo
  what the batch never recorded, since `always` is still the only thing that puts anything back.

### Structured results

Every tool returns the same readable text it always has. The tools below **also** return MCP
[`structuredContent`](https://modelcontextprotocol.io/specification/2025-06-18/server/tools), with a
matching `outputSchema` in `tools/list`, so a program can read a field instead of parsing prose:

| Tool | Typed answer |
|------|--------------|
| `open_dump`, `open_trace`, `attach_kernel`, `attach_kernel_local`, `attach_process`, `launch` | `session_id`, `kind`, `target`, `report`, and a `summary` of the target — `kernel_mode`, `modules_loaded`, the `primary_module` (the kernel, or the process's own image) and, for a crash dump, the `bug_check`. On failure, whether a target was created (`target: no \| yes \| pending`), which is what decides whether opening again is a recovery or a second attach |
| `session_status` | each session's `state` (`opening`/`attaching`/`open`/`failed`/`retired`/`closed`), `engine_pid`, `in_state_for_ms`, and — for an attach — `waits_indefinitely` and `overdue` |
| `server_log` | `records[]` as `{seq, at, level, session_id, target, message}` — `session_id` absent for the supervisor's own — plus `matched`, the buffer's `held`/`capacity`/`oldest_seq`, and a `next_since` cursor that advances even on an empty page |
| `end_session` | `released`, `worker_terminated`, `waited_ms` |
| `registers` | `registers[]` as `{name, kind, …}` plus `instruction_pointer` — `kind: int` and `kind: float` carry `value`, `kind: bytes` carries `bytes` (an x87 or vector register, which no number holds), `kind: non_finite` names a NaN or infinity that JSON has no literal for and carries its bits, `kind: unavailable` carries neither; pass `all: true` for the x87/vector registers and subregister views |
| `modules` | `modules[]` with `start`/`end`, `size`, `timestamp` (the `TimeDateStamp`+`size` pair a symbol server is keyed by — see [`docs/coordinates.md`](docs/coordinates.md)), a typed `symbols` state (`deferred` is *not* `none`) and, for a module whose symbols resolved, the `pdb` identity (`guid`, `age`, and the `key` those two make) plus `unmatched` when the engine loaded a PDB that does not belong to the image; `unloaded[]` for the images that have since unloaded (listed by image name, since an unloaded module has none of its own); `loaded` (how many the target has in total) and the `filter` a narrowed listing was matched by. The listing text is rendered from these same records rather than pasted from `lm`, so the two halves cannot describe different sets of modules; the filter's grammar is this server's own — a name plus `*` (any run) and `?` (exactly one), **every other character literal** — and `execute { "command": "lm m <pattern>" }` is where WinDbg's fuller wildcard syntax lives |
| `set_breakpoint` | the ids this call `added`, and every breakpoint now set — a successful `bp` prints nothing at all |
| `run_to_address` | `verdict` (`hit`/`stopped_elsewhere`/`timeout`), `target`, `stopped_at` |
| `go`, `step_over`, `step_into`, `step_back`, `step_over_back`, `reverse_go` | `stopped_at` |
| `pool_find_tag`, `pool_chunk`, `pool_census`, `pool_diagnostics` | the chunks/totals/diagnostics as values, each carrying the `walk` behind them |
| `heap_list`, `heap_allocations`, `heap_chunk`, `heap_census`, `heap_diagnostics` | PEB heap roots and Segment Heap allocations/totals/diagnostics, each carrying exact `ntdll` layout provenance, skipped-heap scope, and walk coverage |
| `walk_memory` | `nodes[]` with each field's `value` — `null` where the debugger could not read it — plus `walked`/`unreadable` counts and a `stopped` reason (`complete`, `cap`, `null_link`, `loop`, `unreadable_link`, `deadline`, `interrupted`), each carrying the address it is about |
| `disassemble` | `instructions[]` in address order, each `{address, module, rva, bytes, text}` — `module`+`rva` travel together and are **absent when the address is in no loaded module**, with `attribution_failed` marking the different case of a lookup that failed; `address` and `bytes` are always there. Plus `start`, the call's `address` after the debugger evaluated it, and `stopped_early`, which means the code ran out before the count rather than the call being truncated. `bytes` is the engine's spelling of the encoding, which is what says whether a disassembler holds the same build |
| `backtrace` | `frames[]` as `{index, address, module, rva, symbol, displacement}`, innermost first, plus `frames_truncated` — whether the stack went on past the call's `frames` cap (32 by default, 256 at most). `address` is always there; `module`+`rva` travel together and are **absent when the engine places the address in no loaded module** (a freed pool page, an unloaded driver), and `symbol`+`displacement` are absent when nothing resolves, which is the ordinary case for a driver with no PDB. A frame whose module *lookup failed* — a different fact from being in no module, and the opposite kind of evidence — carries `attribution_failed: true`. The same records `crash_triage` reports, from the same walk |
| `crash_triage` | `bug_check` (`code`, `name`, four `parameters`), `process_name`, `frames[]` as `{module, rva, symbol}` — see `backtrace` above for when each is absent — the `faulting_frame` picked out of them, and `!analyze`'s own conclusions kept apart under `analysis` |
| `debug_batch` | `outcome` (`committed`/`failed`/`timed_out`/`abandoned`/`interrupted`), the position it stopped `at`, `committed`, `rollback_complete`, what the session holds `after`, and every step of both blocks with what it `changed` and whether an assertion was `unmet` |

Two conventions hold across all of them:

- **One address representation.** Every address, and every register-sized value, is a `0x`-prefixed,
  lowercase, 16-digit zero-padded hex **string** — `"0xfffff8031ab10000"`. A string because a `u64`
  past 2^53 does not survive a JSON parser that reads numbers as doubles; zero-padded so lexical
  order matches numeric order. The debugger's backtick form (``fffff803`1ab10000``) appears only in
  the text.
- **An allocator answer says what the walk covered.** `walk.coverage` is `complete`, `deadline_truncated`
  (the call's budget ran out — more time reaches more of the allocator) or `partial` (unreadable regions
  or a traversal cap — more time changes nothing). Counts from anything but `complete` are floors,
  not totals. A walk that failed outright, or was stopped by `interrupt`, is not a coverage state at
  all: it is the error branch below, with category `debugger` or `interrupted`.

One caveat about "also", measured rather than assumed: a client that understands
`structuredContent` generally forwards **it** to the model and drops the text block, rather than
sending both. So for the tools above, the typed answer is what a model reads and the rendering is
what a program-with-a-terminal reads — they are two audiences, not one audience twice.
[`docs/token-budget.md`](docs/token-budget.md) has the measurements, and what they cost.

### Error reporting

Anything scoped to a session comes back as a normal tool result with `isError: true` and the text
intact, so the model can read it and correct itself: a failed *debugger operation* (an unresolvable
symbol, an unreadable address, a target that never stopped), a refused handle, a timeout, a session
whose worker is gone. Each has a next move. The only JSON-RPC protocol error is the one failure that
is the server's rather than a session's — no engine worker could be started at all.

For the tools listed above, a failure also carries structured content — the `error` branch of the
same output schema — so a caller can branch on a stable category instead of on wording:
`invalid_argument`, `debugger`, `timeout`, `interrupted`, `not_run` (the work never started, so
nothing changed — unlike `timeout`, where it may still be running), `stale_session`, `worker_lost`,
`capacity`. Both branches carry a `status` discriminator (`"ok"` / `"error"`), which is what lets one
schema describe a result whichever way it went.

The forward (`go`/`step_over`/`step_into`) and reverse (`reverse_go`/`step_over_back`/`step_back`)
control tools mirror a debugger UI's F9/F8/F7 and Shift+F9/F8/F7, so an agent can drive a trace in
both directions and jump anywhere with `goto_position`. All of these issue the command **and pump the
engine to the next stop** (a plain `Execute` only sets the run state — it doesn't move the target),
which is what makes both live stepping and TTD forward/reverse navigation actually advance.

`ttd_calls`/`ttd_memory`/`ttd_events` are convenience wrappers over the TTD data model: `ttd_calls`
and `ttd_memory` query `@$cursession.TTD.{Calls,Memory}` (every call to a function / every access to
an address range), and `ttd_events` queries `@$curprocess.TTD.Events` (the module/thread/exception
timeline). For anything else, `dx` evaluates arbitrary data-model/LINQ expressions, e.g.
`@$cursession.TTD.Calls("ntdll!NtCreateFile").Where(c => c.ReturnValue != 0)`.

### Session transcripts (`WINDBG_MCP_TRANSCRIPT`)

Point `WINDBG_MCP_TRANSCRIPT` at a path and the server records what it was asked and what it did,
one JSON object per line. Unset — the default — nothing is written and nothing is spent.

```pwsh
$env:WINDBG_MCP_TRANSCRIPT = "$env:USERPROFILE\.windbg-mcp\session.jsonl"
```

```jsonc
{"v":1,"run":4158027124358305144,"seq":1,"at":"2026-08-16T12:05:20.549Z","mono_ms":1,"event":"tool_request","request":1,"tool":"open_dump","args":{"path":"C:\\dumps\\a.dmp"}}
{"v":1,"run":4158027124358305144,"seq":2,"at":"2026-08-16T12:05:20.672Z","mono_ms":125,"event":"session_open","session":"sess-18cc47a3b2779cc8-1","kind":"crash dump","target":{"text":"C:\\dumps\\a.dmp"},"engine_pid":832}
{"v":1,"run":4158027124358305144,"seq":11,"at":"2026-08-16T12:05:23.129Z","mono_ms":2582,"event":"batch","request":3,"session":"sess-18cc47a3b2779cc8-1","outcome":"failed","at_step":2,"committed":false,"rollback_complete":true,"after":"stopped","elapsed_ms":402}
```

Every record carries the format version, the run that wrote it, a sequence number, a wall clock
and a monotonic offset.
The events are the tool call and its result; a session opening, changing state and being released;
a wait abandoned, an `interrupt`, a worker process dying; and — derived from each result's *typed*
half, never scraped from the text beside it — where execution stopped, what a `run_to_address`
concluded, every breakpoint or memory mutation, each assertion that did not hold, and how a
`debug_batch` ended with whether its rollback completed. See [`src/record.rs`](./src/record.rs).

A record's `session` is the one the call was **routed** to, not the one it named: omitting
`session_id` accepts the current session rather than none, so the field answers "which target was
this?" even for the calls that did not say.

**It is not the log.** `RUST_LOG` output is prose about the server, on stderr; this is values about
the *session*, in a file of its own. Standard output stays JSON-RPC and nothing else.

Render one as a terminal recording with the same executable:

```pwsh
windbg-mcp --render-cast session.jsonl -o session.cast   # asciicast v2
asciinema play session.cast
```

The rendering is derived, so a cast can be made from a transcript recorded weeks ago and the
timings are the recorded ones. `--idle-limit <s>` tells a player how long to sit in a pause (`0`
plays at the speed it happened), `--max-lines <n>` caps how much of a long result is shown, and
`--title`/`--width`/`--height` shape the recording.

A file holding several runs renders as one recording with the runs laid end to end, separated by
however long the server was actually down — each run's own clock starts at zero, so playing those
offsets as they stand would step backwards at the join and no player would accept it. Two servers
pointed at the same path interleave their lines; they are grouped back into their own runs by the
`run` field every record carries, so neither session is read as part of the other.

**Redaction**, by two mechanisms that are not equally strong. Every secret this server has been
handed — from a profile or from a raw `connection` — is masked **by value**, wherever it appears
and in whatever syntax, so a key that reached this process cannot leave it in a transcript. Under
that sits a scan for `key=`/`password=` in text, which also catches a secret the server has never
seen (one a target printed itself); it has to guess a syntax and is best-effort by nature. An
argument member *named* like a secret is masked whole. Prefer a
[profile](#kernel-connection-profiles-keeping-the-kdnet-key-out-of-the-transcript) regardless: it
keeps the key out of the request in the first place, and all of this is the backstop.

**Retention.** Nothing else is masked, and that is the point to plan around: debugger output is the
contents of somebody's memory — stack frames, strings, registry paths, whatever the target holds —
so a transcript of a live session is as sensitive as the machine it was taken from. Treat one like
a crash dump. Keep it out of version control unless you have read it, put it somewhere with the
same access as the target, and delete it when the investigation is done. The file is **appended**
to, never truncated, so a path reused across runs accumulates until something removes it; each run
starts with a `start` record naming its pid, which is what separates them.

**Size.** Fields are capped at 16 KiB, and a record says how much it dropped rather than being
quietly short. `WINDBG_MCP_TRANSCRIPT_MAX_FIELD` moves the cap; `0` removes it, at the cost of a
file that grows with every module listing and pool census. A whole record is bounded too, well
above what a capped one reaches: a record past that ceiling is replaced by an `oversized` marker
naming its kind and size, which is a bug in the recorder rather than something a session did.

## Limitations & notes

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
  [`skills/windbg-debugging/heap-walking.md`](skills/windbg-debugging/heap-walking.md).
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
  even after `.load ext` (see *Bundling the WinDbg engine*). On a **partial minidump**, reads of
  pages that weren't captured raise `An unexpected exception was raised (0x80040205)` rather than a
  clean "memory read error"; query the specific field you need (e.g.
  `dt nt!_DRIVER_OBJECT <addr> DriverName`) instead of dumping whole structures. See the
  [crash-dump walkthrough](docs/crash-dump-walkthrough.md).
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
  false "recording started".
- Control-flow tools (`go`/`step*`) issue the corresponding debugger command; precise stop/wait
  semantics for long-running `go` against a live target are bounded by the per-call timeout.
