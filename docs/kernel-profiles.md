# Kernel connection profiles

*Keeping the KDNET key out of the transcript.*

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
only ever carry the masked one ([`src/kdconn.rs`](../src/kdconn.rs)). The raw string is unwrapped at
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
