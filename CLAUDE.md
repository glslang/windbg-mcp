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

`windbg-mcp` is a Rust MCP server (stdio, `rmcp`) exposing **WinDbg/DbgEng** for live user-mode,
kernel, crash-dump, and Time Travel Debugging (TTD) work. The low-level DbgEng bindings come from
the sibling crate [`dbgscope`](https://github.com/glslang/dbgscope) (a **path/git dependency we grow
ourselves** — do not add third-party DbgEng crates).

**A new DbgEng primitive is a typed `dbgscope` method**, returning `Result<_, DbgEngError>` rather
than `panic!`/`.expect`, never the `execute` text hatch. It is here rather than in
`.claude/rules/cargo-and-dependencies.md` with the rest of the dbgscope material because it binds a
Rust-only change, which loads that rule never — it is scoped to the manifests and `build.rs`.

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


## Where the rest of it lives

**Rules load themselves; skills you invoke.** A rule under `.claude/rules/` carries a `paths:` glob
and is pulled into context when Claude reads a file matching it. The three about something other
than this server's code are scoped to that thing — a `Cargo.toml`, a `.md`, a `.ps1`. The eight
about the code share **one** scope: `src/**/*.rs`, `tests/**/*.rs` and `build.rs` — which is
`build.rs`'s own `INPUTS` less the two manifests, those having a rule of their own. That trigger is
a **read**, not a grep, so if you are about to reason about a subsystem from search results alone,
open the rule first.

**They share a scope because per-rule scoping was measured and did not pay.** Six review rounds on
[#285](https://github.com/glslang/windbg-mcp/pull/285) filed ten findings, **eight** of them one
file whose editor a rule binds and whose `paths:` did not name it — and six more were found by
enumerating rather than waiting for the next round. There was no end to them because this crate's
files are entangled: every tool call crosses `server.rs`, `engine.rs`, `proto.rs` and `worker.rs`,
so most rules bind most of them. Against the 72,396 bytes of all eight, `engine.rs` already loaded
**89%**, `worker.rs` and `server.rs` 69%, `proto.rs` 62%. Eleven hand-maintained lists were buying
11–38% on the files anyone actually edits, at a review round for each one that was wrong. One scope
buys that back by leaving nothing to get wrong. Where the laziness still pays is the other axis, and
it is untouched: a session that touches no Rust never loads the **72,211 bytes** of code rules at
all. It loads this file plus whichever narrow rules its files match, which is at most 11,315 B if
all three somehow fired. How many fire is deliberately not stated more precisely than that — the
globs intersect (`examples/README.md` matches two, `build.rs` matches four), and two attempts to
give the exact composition here were both wrong, one of them in the commit that fixed the other.
The bound is the claim; the arithmetic below it is a Venn diagram, and `/handoff` has it.

So the *Covers* column is the index. The eight are split by **subject**, not by which files trip
them — read it to pick the one you want.

| Rule (`.claude/rules/`) | Loads when you touch | Covers |
|---|---|---|
| `cargo-and-dependencies.md` | `Cargo.toml`, `Cargo.lock`, `build.rs` | moving the `dbgscope` `rev` pin, the Mac `cargo check`/`fetch`/`metadata` workflow, `build.rs`'s PE version resource, why `[patch]` is never committed |
| `markdown-and-docs.md` | `**/*.md` | CI's two non-Rust gates: `cargo fmt --all --check` and the markdownlint globs |
| `powershell-scripts.md` | `**/*.ps1`, `tools/**`, `examples/**` | the three ways a shipped `.ps1` fails only under PowerShell 5.1; draining stderr when driving the server from a script |
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

This project is also installed as a user-scope Claude Code plugin (`windbg-mcp@windbg-mcp`), which is
a snapshot of the last *published* release and does **not** track working-tree edits. In this repo
the plugin is **disabled locally** (`.claude/settings.local.json`) so the dev build above is what
runs. Keep machine-specific server wiring (absolute paths) out of version control.
