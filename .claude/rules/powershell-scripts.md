---
paths:
  - "**/*.ps1"
  - "tools/**"
  - "examples/**"
---

**A `.ps1` this repo ships has to parse under Windows PowerShell 5.1, and three ways of failing
that are invisible on the machine you write it on.** The scripts in `tools/` and `examples/` run on
*debuggees*, where 5.1 is the only PowerShell there is, and all three faults below abort before the
script does anything — `tools/ioctl_harness.ps1` had all three at once:

- **Non-ASCII in a BOM-less UTF-8 file.** 5.1 decodes such a file in the ANSI code page, so an em
  dash becomes three characters, the last of which is a quotation mark that *ends a string* — and
  the parse error is reported tens of lines later, pointing at a brace. Keep these files ASCII
  (`grep -P '[^\x00-\x7F]'`); PowerShell 7 hides this completely by assuming UTF-8.
- **A hex literal that does not fit `Int32`.** `0x80000000` is a *bit pattern* in 5.1, so it is
  negative and a `uint32` parameter refuses it; 7 widens the same literal to `Int64` and the call
  succeeds. `[Convert]::ToUInt32('80000000', 16)` reads the same on both — the `[uint32]` cast of
  either the literal or a `'0x…'` string fails on 5.1.
- **Returning an empty array.** `return [byte[]] @()` is unrolled by the pipeline into nothing, so
  the caller gets `$null` and every `.Length` on it fails under `Set-StrictMode`. `return , ([byte[]] @())`.

**Driving the server over stdio from a script: do not redirect stderr unless you drain it.** With
`RUST_LOG` widened the server fills the stderr pipe buffer and blocks mid-request, which looks
exactly like a hung debugger. Leave stderr inherited (it lands in your terminal, interleaved) or
read it on a second thread.

**A token in one of these scripts is never printed, never an argument, and verified by hash.** All
three of these have gone wrong here, and the first one twice:

- **Never read a token file to look at it.** `Get-Content …\token` and `cat` both put the value in
  the transcript, and a transcript is forever. Compare a **SHA-256 prefix** instead — that is how
  `%ProgramData%\windbg-mcp\token`, the VM's `WINDBG_MCP_LISTEN_TOKEN` and the `Authorization`
  header in `~/.claude.json` were confirmed to match without any of them being displayed.
- **An error message will read the file out for you.** `Get-Content …\token | ConvertFrom-Json`
  against a file that is a bare token — which it is, when the listener has one unnamed client —
  fails with `Invalid JSON primitive: <the entire token>`. The command that leaked it was a command
  written to *avoid* printing it, so "I did not ask for the contents" is not the test; assume any
  command touching the file can echo it on the failure path.
- **Never pass a token as a command-line argument.** Every process on the box can read a command
  line. Pipe it over **ssh stdin** into a script that reads one line (`[Console]::In.ReadLine()`),
  which is how `tools/…` launchers take one, and have the script print a fingerprint rather than
  the value.

If a token does reach a transcript, it is **rotated, not forgotten** — and *which* token decides
how, because the two are rotated by different means and `--rotate-listen-client` only reaches one
of them:

- **The service's**, in `%ProgramData%\windbg-mcp\token`. `--rotate-listen-client <name>` rewrites
  that file and the running service picks it up with nothing stopped; it keeps that client's
  sessions, where a remove-then-add does not. Then re-match every consumer of the old value — the
  guest's environment variable, the `windbg-vm` header in `~/.claude.json`.
- **A foreground listener's**, which nothing rewrites in place: the file command does not touch it,
  and the process holds what it started with until it is **relaunched**. A leaked bench token stays
  valid for as long as that listener runs, so rotating it means killing the listener (by the PID
  `netstat -ano` gives for its port) and starting it again — *with the right thing changed*, which
  depends on where its credentials came from:
  - **Environment-backed** (`WINDBG_MCP_LISTEN_TOKEN`, which is how the bench listener runs):
    relaunch with a new value.
  - **File-backed** (`WINDBG_MCP_LISTEN_TOKEN_FILE`): replace the file's token first. Changing the
    environment variable does nothing here — `Credentials::from_entries` does not read the
    environment *at all* when a file is configured (`src/client.rs`), so a relaunch with a new
    `WINDBG_MCP_LISTEN_TOKEN` beside an unchanged file keeps serving the leaked one and looks like
    a successful rotation.
