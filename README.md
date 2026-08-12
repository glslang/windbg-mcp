# windbg-mcp

[![CI](https://github.com/glslang/windbg-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/glslang/windbg-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/glslang/windbg-mcp?utm_source=oss&utm_medium=github&utm_campaign=glslang%2Fwindbg-mcp&labelColor=171717&color=FF570A&label=CodeRabbit+Reviews)](https://coderabbit.ai)
[![Latest release](https://img.shields.io/badge/release-v0.7.0-blue)](https://github.com/glslang/windbg-mcp/releases/latest)
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
[`docs/smoke-test.md`](docs/smoke-test.md).

### Bundling the WinDbg engine

Needed for three things: TTD `.run` replay (System32's engine rejects traces with `0x80070057`),
crash-dump `!analyze` (which lives in the `winext\` extensions that System32 doesn't ship), and the
kernel driver tools `driver_object`/`device_object`/`irp_stack` (which need `winxp\kdexts.dll`).
So a live-kernel-only user needs this section too, even though the attach itself works on the
System32 engine. `DebugCreate` binds to whichever `dbgeng.dll` the loader finds first, and the app directory is
searched before `System32`, so the copied **WinDbg** engine (which replays TTD traces and ships the
extensions) wins. One-time, from the installed WinDbg store package:

```pwsh
$wd  = (Get-AppxPackage Microsoft.WinDbg).InstallLocation + "\amd64"
$dst = "C:\workspace\windbg-mcp\target\release"
Copy-Item "$wd\dbgeng.dll","$wd\dbghelp.dll","$wd\dbgcore.dll","$wd\dbgmodel.dll",`
          "$wd\symsrv.dll","$wd\msdia140.dll" $dst -Force
Copy-Item "$wd\ttd"    "$dst\ttd"    -Recurse -Force   # TTDReplay*.dll, TtdExt.dll, TTDAnalyze.dll, ...
Copy-Item "$wd\winext" "$dst\winext" -Recurse -Force   # ext.dll (!analyze), kext.dll, … — crash-dump triage
New-Item   "$dst\winxp" -ItemType Directory -Force | Out-Null
Copy-Item "$wd\winxp\kdexts.dll" "$dst\winxp" -Force   # !drvobj/!devobj/!irp — the kernel driver tools
```

- The `ttd\` subdir provides the `@$cursession.TTD` / `@$curprocess.TTD` data model and the `!tt`
  time-travel commands.
- The `winext\` subdir provides `ext.dll` (which exports `!analyze`) and the other `!`-extensions.
  `open_dump` runs `.load ext` for you, but note the **unqualified `!analyze` does not resolve** on
  this minimal engine — use the module-qualified **`!ext.analyze -v`** for crash-dump triage. Without
  `winext\`, `!analyze` returns *"No export analyze found"*.
- `winxp\kdexts.dll` provides `!drvobj`/`!devobj`/`!irp`, behind the
  `driver_object`/`device_object`/`irp_stack` tools. `attach_kernel` / `attach_kernel_local`
  `.load kdexts` for you and nothing complains at attach time, so a missing file first surfaces as
  *"No export drvobj found"* from those three tools. It lives in `winxp\`, not `winext\` — the
  engine searches that subdir by name.
- **`msdia140.dll` is required for PDB symbols.** Without it, `dbghelp` can't parse any PDB
  (`dia error 0x8007007e`) and silently falls back to *export* symbols — which makes `module!name`
  lookups (and so `ttd_calls("ucrtbase!__stdio_common_vfprintf")`) fail even with the right PDB in
  the cache. `symsrv.dll` is needed to read a symbol-store cache.

(`cargo clean` wipes `target\`, so re-copy after one.) Live and dump debugging work with or without
the TTD engine; PDB symbol *names* need `msdia140.dll` + a symbol path
(`execute` → `.sympath srv*C:\ProgramData\Dbg\sym*https://msdl.microsoft.com/download/symbols`).

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

### As a Claude Code plugin

This repo is also a single-plugin [Claude Code marketplace](https://code.claude.com/docs/en/plugin-marketplaces):
installing it registers the `windbg` MCP server **and** a `windbg-debugging` skill that
knows how to drive it (setup, crash-dump, live/kernel, and TTD playbooks).

```text
/plugin marketplace add glslang/windbg-mcp
/plugin install windbg-mcp@windbg-mcp
```

The plugin ships source, not a binary, so after installing you still put the server binary in
place — download a prebuilt release or build from source — and (for `.run` replay and
crash-dump `!analyze`) bundle the WinDbg engine — the skill's `setup.md`
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
still applies — for TTD `.run` replay and crash-dump `!analyze`, drop the WinDbg engine DLLs next
to the client-extracted `windbg-mcp.exe` (the skill's `setup.md` covers it). Basic live and
crash-dump work runs on the in-box `System32` engine without them.

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

- [`docs/crash-dump-walkthrough.md`](docs/crash-dump-walkthrough.md) — triaging a real kernel
  minidump ([`docs/samples/052126-34312-01.dmp`](docs/samples/052126-34312-01.dmp)): a
  `0x9F DRIVER_POWER_STATE_FAILURE` traced to `nvlddmkm.sys` via `!ext.analyze -v` and a manual
  device-stack walk, with the real outputs and the partial-minidump (`0x80040205`) gotcha.
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
| State   | `registers`, `read_memory`, `backtrace`, `modules`, `threads`, `disassemble`, `dx` |
| Control | `go`, `step_over`, `step_into`, `set_breakpoint`, `run_to_address` |
| Transaction | `debug_batch` — an ordered sequence with assertions and a rollback the engine process runs on every path |
| TTD nav | `step_back` (`t-`), `step_over_back` (`p-`), `reverse_go` (`g-`), `goto_position` (`!tt`) |
| TTD analysis | `ttd_calls`, `ttd_memory`, `ttd_events`, `index_trace`, `record_trace` |
| Driver IOCTL | `decode_ioctl`, `driver_object`, `device_object`, `irp_stack`, `ioctl_trace`, `reachable_from_dispatch` |
| Kernel pool | `pool_find_tag`, `pool_chunk`, `pool_census`, `pool_diagnostics` |
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
| `open_dump`, `open_trace`, `attach_kernel`, `attach_kernel_local`, `attach_process`, `launch` | `session_id`, `kind`, `target`, `report` — and on failure, whether a target was created (`target: no \| yes \| pending`), which is what decides whether opening again is a recovery or a second attach |
| `session_status` | each session's `state` (`opening`/`attaching`/`open`/`failed`/`retired`/`closed`), `engine_pid`, `in_state_for_ms`, and — for an attach — `waits_indefinitely` and `overdue` |
| `end_session` | `released`, `worker_terminated`, `waited_ms` |
| `registers` | `registers[]` as `{name, kind, …}` plus `instruction_pointer` — `kind: int` and `kind: float` carry `value`, `kind: bytes` carries `bytes` (an x87 or vector register, which no number holds), `kind: non_finite` names a NaN or infinity that JSON has no literal for and carries its bits, `kind: unavailable` carries neither; pass `all: true` for the x87/vector registers and subregister views |
| `modules` | `modules[]` with `start`/`end`, `size` and a typed `symbols` state (`deferred` is *not* `none`) |
| `set_breakpoint` | the ids this call `added`, and every breakpoint now set — a successful `bp` prints nothing at all |
| `run_to_address` | `verdict` (`hit`/`stopped_elsewhere`/`timeout`), `target`, `stopped_at` |
| `go`, `step_over`, `step_into`, `step_back`, `step_over_back`, `reverse_go` | `stopped_at` |
| `pool_find_tag`, `pool_chunk`, `pool_census`, `pool_diagnostics` | the chunks/totals/diagnostics as values, each carrying the `walk` behind them |

Two conventions hold across all of them:

- **One address representation.** Every address, and every register-sized value, is a `0x`-prefixed,
  lowercase, 16-digit zero-padded hex **string** — `"0xfffff8031ab10000"`. A string because a `u64`
  past 2^53 does not survive a JSON parser that reads numbers as doubles; zero-padded so lexical
  order matches numeric order. The debugger's backtick form (``fffff803`1ab10000``) appears only in
  the text.
- **A pool answer says what the walk covered.** `walk.coverage` is `complete`, `deadline_truncated`
  (the call's budget ran out — more time reaches more of the pool) or `partial` (unreadable regions
  or a traversal cap — more time changes nothing). Counts from anything but `complete` are floors,
  not totals. A walk that failed outright, or was stopped by `interrupt`, is not a coverage state at
  all: it is the error branch below, with category `debugger` or `interrupted`.

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
- **Crash-dump triage uses `!ext.analyze -v`**, not `!analyze` — the bundled engine only resolves
  the module-qualified form (see *Bundling the WinDbg engine*). On a **partial minidump**, reads of
  pages that weren't captured raise `An unexpected exception was raised (0x80040205)` rather than a
  clean "memory read error"; query the specific field you need (e.g.
  `dt nt!_DRIVER_OBJECT <addr> DriverName`) instead of dumping whole structures. See the
  [crash-dump walkthrough](docs/crash-dump-walkthrough.md).
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
