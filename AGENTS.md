# Repository Guidelines

## Project Structure & Module Organization

`windbg-mcp` is a Rust MCP server for WinDbg/DbgEng. Core code lives in `src/`: `main.rs` selects the process role (supervisor or engine worker) and wires tokio and stdio transport, `server.rs` defines the MCP tool surface, `engine.rs` is the supervisor (session registry, worker processes, routing), `worker.rs` is the child process that owns serialized DbgEng access on a dedicated thread, `proto.rs` is the protocol between them, and `ttd.rs` handles Time Travel Debugging discovery and launch logic. Operational documentation is in `docs/`, agent playbooks are in `skills/windbg-debugging/`, and PowerShell examples live in `examples/`. Helper tooling such as IOCTL harness scripts is under `tools/`. Build output in `target/` is generated and should not be committed.

## Build, Test, and Development Commands

- `cargo fmt --all --check`: verify Rust formatting as CI does.
- `cargo clippy --all-targets`: run lint checks for library, binary, and tests.
- `cargo test`: run the unit tests, including parser and tool-schema coverage in `src/server.rs` and `src/ttd.rs`.
- `cargo build --release`: build the Windows release binary at `target/release/windbg-mcp.exe`.

For local iteration while an MCP client may have the release executable locked, prefer `cargo test` or debug builds. See `CLAUDE.md` before replacing a running release binary.

## Coding Style & Naming Conventions

Use Rust 2024 idioms and `rustfmt` defaults. Keep DbgEng access inside the worker process and on its engine thread; do not add ad hoc cross-thread or cross-process calls. The supervisor must never touch a `DebugEngine`.

**There is exactly one approved exception, and it is not a precedent for a second.** `SetInterrupt` is the single DbgEng entry point Microsoft documents as safe to call from any thread, and it is the only call made off the engine thread: from `worker::interrupt_running` on the request reader, and from win-kexp's two watchdog threads, which have always done it. It is unavoidable rather than convenient — an interrupt exists to stop an operation that is running, so the engine thread is busy by definition, and a request routed through it would be read only once there was nothing left to interrupt. Adding any *other* cross-thread DbgEng call is a design change, not a local one: raise it before writing it. See the `DECISIONS.md` entry "An interrupt is bound to a job, not to a moment" and the `worker.rs` module docs. Prefer typed Rust APIs and structured JSON over parsing debugger text unless the command surface only exposes text. Use `snake_case` for functions, modules, fields, and tests; use `PascalCase` for types. Keep comments short and focused on non-obvious debugger behavior.

## Testing Guidelines

Add focused unit tests near the code they cover under `#[cfg(test)]`. Name tests after the behavior, for example `decode_ioctl_rejects_short_input`. Tests should run without a live debugger, kernel target, symbols, or network access unless explicitly documented. Run `cargo test` before opening a PR; run `cargo clippy --all-targets` for shared or tool-surface changes.

`tests/mcp_smoke.rs` is the end-to-end smoke test: it drives the built binary over stdio with hand-written JSON-RPC, covering transport hygiene, protocol-revision negotiation, and a golden snapshot of the `tools/list` wire surface (`tests/golden/tools_list.json`). Its protocol tier runs under plain `cargo test`; the debugger tier is opt-in via `WINDBG_MCP_SMOKE_DUMP=1` and opens the checked-in sample dump. Run it after a dependency bump (`rmcp`, `schemars`, `tokio`, `win-kexp`) or an MCP spec revision — see `docs/smoke-test.md` for the runbook and the manual checklist for live/TTD paths.

## Commit & Pull Request Guidelines

History uses short imperative subjects, sometimes scoped, such as `docs(hevd): make ...` or `Add set_symbol_path tool`. Keep commits focused and mention affected workflows when relevant. PRs should include a concise description, testing performed, linked issues or follow-ups, and updated docs/examples for user-visible tool changes. Include screenshots only when changing rendered documentation or workflow output.

## Security & Configuration Tips

Keep machine-specific MCP paths, symbol caches, kernel-debug keys, dumps, and credentials out of version control. Large sample dumps belong under documented sample paths only when intentionally added.
