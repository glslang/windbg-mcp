# The tool surface

The tools themselves are listed by group in the [README](../README.md#tools). This file covers
how much of that surface a run serves, and four behaviours the table has no room for.

## Serving fewer tools (`--tools`)

All seventy-five tools are served unless you say otherwise, and their definitions cost the model
**116,356 bytes — about 29k tokens — before it has asked anything**, once per conversation. Every
figure on this page is a measurement of 2026-10-05 rather than an invariant: any edit to a tool's
description moves it, so re-derive before quoting one. The tables below are checked against a
running server by `every_documented_surface_figure_matches_the_served_surface`; this sentence is
**not**, which is how it came to say 94,921 while the table beside it said 94,957. Seven
tenths of that is the prose that tells a model how to drive them, so it cannot be trimmed without
making the tools harder to use correctly (see
[`token-budget.md`](token-budget.md)). What *can* change is how many of them a given run
offers:

```pwsh
windbg-mcp.exe --tools session,inspect,crash
```

| `--tools` | Tools | Model context |
|---|---:|---:|
| *(absent)* — every tool | 75 | 116,356 B |
| `session,inspect,exec,crash` | 33 | 49,137 B |
| `session,inspect,crash` | 23 | 33,897 B |
| `crash` | 13 | 20,320 B |

The spec is a comma-separated list of the group names in the [tool table](../README.md#tools), of
individual tool names, or `all`.
Anything else is refused at startup, with the valid names — a surface that quietly serves something
other than what was asked for is worse than one that will not start.

Two things worth knowing:

- **`session` is always included**, whatever the spec says. Every other tool routes by a
  `session_id`, and this server is the only thing that issues one, so a surface with `registers`
  and no opener cannot be used at all. That is why `--tools crash` is thirteen tools rather than three.
  The startup log line names the surface it ended up with.
- **The prose narrows with the list.** A client is told about the tools it has and no others: the
  `instructions` sent at `initialize` are assembled from the surface, and a tool's description
  carries its cross-references to *other* tools only when those are served too — so `open_dump` on
  a `crash` surface no longer says the module table is what `modules` lists. That is most of why a
  narrowed surface is smaller than its groups' shares add up to.
- **`exec` carries two ways to run a target**, and they are not alternatives to be picked between
  once. `go`, `step_over`, `step_into` and `run_to_address` wait for the stop and answer with it,
  which is what almost every question wants. `continue_async`, `wait_for_stop` and `break_in` split
  that in two, for the sequence where something has to *happen* while the target runs — arm a
  breakpoint, resume, start the process on the guest that trips it, then collect the stop. See
  [Running a target asynchronously](sessions.md#running-a-target-asynchronously).
- **Calling a tool that exists but is not served** is refused by name — "not on the surface this
  run advertises" — rather than as an unknown tool, because the remedy is a flag on a command line
  the caller cannot see.

`--tools` goes on the stdio command line, on a `--listen` one, or on `--install-service` (where it
is written into the command line the SCM stores, and read back at every start). That is the
**run's** surface, and under stdio it is the whole story: one process, one client.

A `--listen` server names its clients, and **a client may be served a surface of its own** — which
is what lets one listener hold a local model that can fit twenty-three tools beside a hosted client
that can hold seventy-five, against the same debug sessions:

```pwsh
setx WINDBG_MCP_LISTEN_TOKEN_BENCH "<a long random string>"
setx WINDBG_MCP_TOOLS_BENCH        "session,inspect,crash"
```

A client with no spec of its own is served the run's, so the flag above is a **default rather than
a ceiling** — a client's own spec replaces it, wider or narrower. Under a Windows service the same
thing lives in the credential file, and `--set-listen-client-tools <name> --tools <spec>` changes it
without a reinstall or a restart; `--list-listen-clients` prints the whole set, name, fingerprint
and surface, and changes nothing. [`remote-listener.md`](remote-listener.md#a-tool-surface-per-client)
is the operator's half, including when a change reaches a client (the next time it is identified —
its next handshake, or its next request if it holds no session) and why nothing announces one.

## An argument a tool does not have is refused

Every tool's `inputSchema` says `additionalProperties: false`, and every tool refuses a call that
carries a key it does not know — with the names it *does* have in the refusal:

```text
failed to deserialize parameters: unknown field `target`, expected one of `address`, `count`, `session_id`
```

Both halves are the point. Serde ignores an unknown field by default, so `disassemble { "target":
"nt!Foo" }` used to disassemble at the current instruction pointer and answer `"status": "ok"` with
a `start` that was the image entry point — a wrong answer that reads as a right one, which cost a
gate a detour into `execute` + `uf` before anyone suspected the argument. And JSON Schema's default
is that an extra key *conforms*, so refusing one while advertising nothing would be this server
breaking its own published contract; the keyword is what makes the refusal honest. `FOLLOWUPS.md`
item 107.

Two things to expect from it. The refusal arrives as a **tool result** with `isError: true`, not as
a JSON-RPC `-32602` — that is where rmcp routes an argument fault, and it is the same channel every
other refusal here uses — and it carries no `structuredContent`, so a client branching on
`error.category` sees nothing for this one. And a **nested** object is held to the same rule: a
coordinate, a `walk_memory` field and a `set_breakpoint` `watch` each refuse a key of their own.
The one exception is a `debug_batch` **step**, which flattens its action and so cannot carry the
serde attribute; it collects its leftover keys and refuses them in a message of its own, naming them
and what a step takes.

A value that is well-formed JSON and still outside the contract is a different check, and there is
one of those: `sk_symbol`'s `name` is unqualified, because the module is the engine's spelling of
the captured image and this server applies it. A qualified name is refused rather than stripped —
`skci!Foo` is a module the capture does not hold, and a lenient engine answers
`securekernel!securekernel!Foo` with the right address under a doubled name.

## Typed operands are operands, not commands

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

## Control flow and the TTD wrappers

The forward (`go`/`step_over`/`step_into`) and reverse (`reverse_go`/`step_over_back`/`step_back`)
control tools mirror a debugger UI's F9/F8/F7 and Shift+F9/F8/F7, so an agent can drive a trace in
both directions and jump anywhere with `goto_position`. All of these issue the command **and pump the
engine to the next stop** (a plain `Execute` only sets the run state — it doesn't move the target),
which is what makes both live stepping and TTD forward/reverse navigation actually advance. A stop
that does not arrive within the wait is a **forced break at the bound**, not a failure: the result
says `timed_out`, and the position it reports is where the target happened to be.

A raw `execute` of the same commands works too, because the server asks the engine after every raw
command whether it was left running and pumps it if it was — which is a check on the *engine's*
state rather than on the command's text, so it covers `bp X; g`, an alias, and anything else that
reaches execution without announcing it. Prefer the typed tools anyway: they answer with a typed
position and stop reason, where `execute` answers with debugger text and one appended line.

`ttd_calls`/`ttd_memory`/`ttd_events` are convenience wrappers over the TTD data model: `ttd_calls`
and `ttd_memory` query `@$cursession.TTD.{Calls,Memory}` (every call to a function / every access to
an address range), and `ttd_events` queries `@$curprocess.TTD.Events` (the module/thread/exception
timeline). For anything else, `dx` evaluates arbitrary data-model/LINQ expressions, e.g.
`@$cursession.TTD.Calls("ntdll!NtCreateFile").Where(c => c.ReturnValue != 0)`.

`current_location` belongs to `inspect`. The optional identity-guarded `coordinate` input
on `read_memory`, `set_breakpoint`, and `run_to_address` requires an explicit session and
excludes the tool's traditional location argument. See [coordinates](coordinates.md).
