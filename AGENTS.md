# Repository Guidelines

## Project Structure & Module Organization

`windbg-mcp` is a Rust MCP server for WinDbg/DbgEng. Core code lives in `src/`: `main.rs` wires tokio and stdio transport, `server.rs` defines the MCP tool surface, `engine.rs` owns serialized DbgEng access on a worker thread, and `ttd.rs` handles Time Travel Debugging discovery and launch logic. Operational documentation is in `docs/`, agent playbooks are in `skills/windbg-debugging/`, and PowerShell examples live in `examples/`. Helper tooling such as IOCTL harness scripts is under `tools/`. Build output in `target/` is generated and should not be committed.

## Build, Test, and Development Commands

- `cargo fmt --all --check`: verify Rust formatting as CI does.
- `cargo clippy --all-targets`: run lint checks for library, binary, and tests.
- `cargo test`: run the unit tests, including parser and tool-schema coverage in `src/server.rs` and `src/ttd.rs`.
- `cargo build --release`: build the Windows release binary at `target/release/windbg-mcp.exe`.

For local iteration while an MCP client may have the release executable locked, prefer `cargo test` or debug builds. See `CLAUDE.md` before replacing a running release binary.

## Coding Style & Naming Conventions

Use Rust 2024 idioms and `rustfmt` defaults. Keep DbgEng access behind the engine-thread abstraction; do not add ad hoc cross-thread calls. Prefer typed Rust APIs and structured JSON over parsing debugger text unless the command surface only exposes text. Use `snake_case` for functions, modules, fields, and tests; use `PascalCase` for types. Keep comments short and focused on non-obvious debugger behavior.

## Testing Guidelines

Add focused unit tests near the code they cover under `#[cfg(test)]`. Name tests after the behavior, for example `decode_ioctl_rejects_short_input`. Tests should run without a live debugger, kernel target, symbols, or network access unless explicitly documented. Run `cargo test` before opening a PR; run `cargo clippy --all-targets` for shared or tool-surface changes.

## Commit & Pull Request Guidelines

History uses short imperative subjects, sometimes scoped, such as `docs(hevd): make ...` or `Add set_symbol_path tool`. Keep commits focused and mention affected workflows when relevant. PRs should include a concise description, testing performed, linked issues or follow-ups, and updated docs/examples for user-visible tool changes. Include screenshots only when changing rendered documentation or workflow output.

## Security & Configuration Tips

Keep machine-specific MCP paths, symbol caches, kernel-debug keys, dumps, and credentials out of version control. Large sample dumps belong under documented sample paths only when intentionally added.
