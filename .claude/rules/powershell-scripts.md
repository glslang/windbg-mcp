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
