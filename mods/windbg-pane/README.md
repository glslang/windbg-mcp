# windbg-pane

A Claude Code mod that draws a WinDbg-style pane from `windbg-mcp` tool calls as they happen:
disassembly with the stop marked, registers, stack, memory, breakpoints, and a command window
showing the WinDbg equivalent of each call. It watches; it never changes a call.

```text
/windbg-pane            open the pane
/windbg-pane close      close it
/windbg-pane clear      forget the session history
/windbg-pane shape      report what the last tool result actually looked like
```

Install it for development with `claude --plugin-dir mods/windbg-pane`, or copy the directory into
`~/.claude/mods/`.

## What it is for

A tool call's typed half says a great deal that prose does not, and a pane is the cheapest way to
see it: that `cr3` changed, that a register read is older than the last step, that a stop is in
VTL1 at CPL 0. The folding logic in `hooks/model.ts` is pure functions over one `View`, so it is
tested without an engine, a target, or a debugger.

## The thing to know before editing it

**Every fixture is a real recording, and that is the point.** `tests/recorded.ts` is a `cmd.exe`
launch breaking on `kernelbase!CreateFileW`; `recorded-kernel.ts` a live KDNET attach;
`recorded-dump.ts` an ARM64 kernel crash dump. They were captured through
`WINDBG_MCP_TRANSCRIPT`, not written by hand, because a hand-made fixture agrees with whatever the
code already does. Three defects found this way would not have been found otherwise:

- a kernel target reports `cr0/cr2/cr3/cr4/cr8`, `xcr0`, `gdtr/idtr/tr` and `kdr*`, and the pane
  drew none of them — so **`cr3`, the page-table root, was silently dropped**;
- `docs/samples/*.dmp` are ARM64, so their registers are `x0`..`x28`, `fp/lr/sp/pc`, `w0`..`w30`
  and `bvr/bcr/wvr/wcr` — **109 of them, not one matching an x64 name** — and the grid came up
  empty;
- a live Secure Kernel stop reports its registers as `registers.values[]` carrying `low`/`high`/
  `status` rather than flat `{ name, value }` rows, and its instruction as a byte *array*, so none
  of the ordinary branches saw any of it.

All three are the same mistake: a fixed list of names quietly drops whatever it does not enumerate.
The pane now picks a register bank per target, and **counts anything it leaves out on screen**
(`+n not shown: …`), so a missing class shows up as a number instead of vanishing. If you add a
target kind, add its bank — and check the count line rather than the grid.

Some fixtures are deliberately absent. `tests/recorded-sk.ts` and `tests/sk.test.tsx` hold a lab
VM's GUID and live VTL1 addresses from a private run and are gitignored; `windbg.test.tsx` covers
the same code paths with synthetic payloads, so a clone exercises them without the bench.

`claude plugin test mods/windbg-pane` runs it. `claude plugin validate mods/windbg-pane` checks the
manifest and that every `$.state` key the module names is in `types/index.d.ts`.
