# The tool surface

The tools themselves are listed by group in the [README](../README.md#tools). This file covers
how much of that surface a run serves, and three behaviours the table has no room for.

## Serving fewer tools (`--tools`)

All fifty-one tools are served unless you say otherwise, and their definitions cost the model
**67,658 bytes — about 17k tokens — before it has asked anything**, once per conversation. Three
quarters of that is the prose that tells a model how to drive them, so it cannot be trimmed without
making the tools harder to use correctly (see
[`token-budget.md`](token-budget.md)). What *can* change is how many of them a given run
offers:

```pwsh
windbg-mcp.exe --tools session,inspect,crash
```

| `--tools` | Tools | Model context |
|---|---:|---:|
| *(absent)* — every tool | 51 | 67,658 B |
| `session,inspect,exec,crash` | 25 | 28,671 B |
| `session,inspect,crash` | 20 | 25,265 B |
| `crash` | 11 | 15,073 B |

The spec is a comma-separated list of the group names in the [tool table](../README.md#tools), of
individual tool names, or `all`.
Anything else is refused at startup, with the valid names — a surface that quietly serves something
other than what was asked for is worse than one that will not start.

Two things worth knowing:

- **`session` is always included**, whatever the spec says. Every other tool routes by a
  `session_id`, and this server is the only thing that issues one, so a surface with `registers`
  and no opener cannot be used at all. That is why `--tools crash` is eleven tools rather than one.
  The startup log line names the surface it ended up with.
- **Calling a tool that exists but is not served** is refused by name — "not on the surface this
  run advertises" — rather than as an unknown tool, because the remedy is a flag on a command line
  the caller cannot see.

`--tools` goes on the stdio command line, on a `--listen` one, or on `--install-service` (where it
is written into the command line the SCM stores, and read back at every start). That is the
**run's** surface, and under stdio it is the whole story: one process, one client.

A `--listen` server names its clients, and **a client may be served a surface of its own** — which
is what lets one listener hold a local model that can fit twenty tools beside a hosted client that
can hold fifty-one, against the same debug sessions:

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
which is what makes both live stepping and TTD forward/reverse navigation actually advance.

`ttd_calls`/`ttd_memory`/`ttd_events` are convenience wrappers over the TTD data model: `ttd_calls`
and `ttd_memory` query `@$cursession.TTD.{Calls,Memory}` (every call to a function / every access to
an address range), and `ttd_events` queries `@$curprocess.TTD.Events` (the module/thread/exception
timeline). For anything else, `dx` evaluates arbitrary data-model/LINQ expressions, e.g.
`@$cursession.TTD.Calls("ntdll!NtCreateFile").Where(c => c.ReturnValue != 0)`.
