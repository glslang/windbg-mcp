# Repository Guidelines

## Project Structure & Module Organization

`windbg-mcp` is a Rust MCP server for WinDbg/DbgEng. Core code lives in `src/`: `main.rs` selects the process role (supervisor or engine worker) and wires tokio and stdio transport, `server.rs` defines the MCP tool surface, `engine.rs` is the supervisor (session registry, worker processes, routing), `worker.rs` is the child process that owns serialized DbgEng access on a dedicated thread, `proto.rs` is the protocol between them, and `ttd.rs` handles Time Travel Debugging discovery and launch logic. Operational documentation is in `docs/`, agent playbooks are in `skills/windbg-debugging/`, and PowerShell examples live in `examples/`. Helper tooling such as IOCTL harness scripts is under `tools/`. Build output in `target/` is generated and should not be committed.

## Build, Test, and Development Commands

- `cargo fmt --all --check`: verify Rust formatting as CI does.
- `cargo clippy --all-targets -- -D warnings`: run lint checks for library, binary, and tests, as CI does — a warning fails the build there.
- `cargo test`: run the unit tests, including parser and tool-schema coverage in `src/server.rs` and `src/ttd.rs`.
- `cargo build --release`: build the Windows release binary at `target/release/windbg-mcp.exe`.

For local iteration while an MCP client may have the release executable locked, prefer `cargo test` or debug builds. See `CLAUDE.md` before replacing a running release binary.

## Coding Style & Naming Conventions

Use Rust 2024 idioms and `rustfmt` defaults. Keep DbgEng access inside the worker process and on its engine thread; do not add ad hoc cross-thread or cross-process calls. The supervisor must never touch a `DebugEngine`.

**The rule's constraint is one debuggee session per process, every call on the thread that made it, and no engine in the process that serves MCP** — and there is now a third process that meets all three without being a worker. `--sk-inspect --symbols` (`src/sksym.rs`, `FOLLOWUPS.md` item 103 gate S2) opens `securekernel.exe` as an image target to read its symbols: one target, and that target is a *file*, with no process behind it to resume, detach or kill. That role speaks no MCP, holds no session registry, has no clients, and returns from `main` before a tokio runtime exists, so there is no server for a wedged engine to take down and no other session to protect — which is what the worker boundary buys. Review raised this as a P1 on [#399](https://github.com/glslang/windbg-mcp/pull/399) against the prose above, correctly: the sentence said *worker or nothing* and this is neither. **Two files may construct a `DebugEngine` and `sksym::tests::only_the_worker_and_this_module_build_an_engine` fails if a third does**, so the next one is a decision taken deliberately rather than a review finding. Mentioning the type is not constructing it: the worker's analysis modules take `&DebugEngine` throughout and always have.

**And the tool surface for the same subsystem answered that question the other way, which is where the rule points from now on.** Gate S3 (`src/sksession.rs`) put the Secure Kernel capture tools in an ordinary **worker**, and not only because of the sentence above: the SDK provider those tools load `__fastfail`s on a capture it cannot decrypt (measured, S0 arm 4 — `docs/secure-kernel/vmsavedstatedumpprovider-crash.md`), so a vendor DLL that aborts the process on an input a *caller* supplies must not be loaded beside the session registry, whether or not an engine comes with it. The engine-free half of a subsystem is not automatically safe for the supervisor; what makes a worker the answer is that one session pays for whatever goes wrong in it. A capture session's engine holds at most the image, which is why the debugger tools are refused on it (`engine::refuse_op_on_kind`) rather than answering about the wrong target.

**There is exactly one approved exception, and it is not a precedent for a second.** `SetInterrupt` is the single DbgEng entry point Microsoft documents as safe to call from any thread, and it is the only call made off the engine thread: from `worker::interrupt_running` on the request reader, from the Secure Kernel KD reader while the engine thread is inside its explicitly scoped owned-event wait, and from dbgscope's two watchdog threads. It is unavoidable rather than convenient — an interrupt exists to stop an operation that is running, so the engine thread is busy by definition, and a request routed through it would be read only once there was nothing left to interrupt. The KD path exposes only an atomic `WaitActivity`; reset, disconnect, Ctrl+Break or idle expiry can interrupt that interval, and no transport thread can reach an engine, dispatcher or provider. Adding any *other* cross-thread DbgEng entry point or any unscoped `SetInterrupt` caller is a design change, not a local one: raise it before writing it. See the `DECISIONS.md` entry "An interrupt is bound to a job, not to a moment" and the `worker.rs` module docs. Prefer typed Rust APIs and structured JSON over parsing debugger text unless the command surface only exposes text. Use `snake_case` for functions, modules, fields, and tests; use `PascalCase` for types. Keep comments short and focused on non-obvious debugger behavior.

## Testing Guidelines

Add focused unit tests near the code they cover under `#[cfg(test)]`. Name tests after the behavior, for example `decode_ioctl_rejects_short_input`. Tests should run without a live debugger, kernel target, symbols, or network access unless explicitly documented. Run `cargo test` before opening a PR; run `cargo clippy --all-targets` for shared or tool-surface changes.

`tests/mcp_smoke.rs` is the end-to-end smoke test: it drives the built binary over stdio with hand-written JSON-RPC, covering transport hygiene, protocol-revision negotiation, and a golden snapshot of the `tools/list` wire surface (`tests/golden/tools_list.json`). Its protocol tier runs under plain `cargo test`; the debugger tier is opt-in via `WINDBG_MCP_SMOKE_DUMP=1` and opens the checked-in sample dump. Run it after a dependency bump (`rmcp`, `schemars`, `tokio`, `dbgscope`) or an MCP spec revision — see `docs/smoke-test.md` for the runbook and the manual checklist for live/TTD paths.

## Commit & Pull Request Guidelines

History uses short imperative subjects, sometimes scoped, such as `docs(hevd): make ...` or `Add set_symbol_path tool`. Keep commits focused and mention affected workflows when relevant. PRs should include a concise description, testing performed, linked issues or follow-ups, and updated docs/examples for user-visible tool changes. Include screenshots only when changing rendered documentation or workflow output.

## Security & Configuration Tips

Keep machine-specific MCP paths, symbol caches, kernel-debug keys, dumps, and credentials out of version control. Large sample dumps belong under documented sample paths only when intentionally added.
