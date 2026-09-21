# Kernel connection profiles

*Keeping the KDNET key out of the transcript.*

Profiles also work for [Microsoft hypervisor debugging](hypervisor-debugging.md). Use a separate
profile for the hypervisor endpoint; an NT kernel connection does not select the hypervisor.

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

## Saying what an endpoint reaches

A name and a string cannot say **what** a profile reaches: that this one is the hypervisor rather
than the NT kernel, or that two of them are two endpoints of the *same* guest. That second fact is
what [debugging a hypervisor alongside its root partition](hypervisor-debugging.md) is built on —
the two sessions interact only through the guest underneath them, so a pair pointing at different
guests is two sessions that never interact, which reads as a bug for a long time.

Inferring it from the *names* is worse than not knowing. The wiring is machine-specific and
deliberately untracked, so any convention read off a name is a guess that looks like knowledge, and
a pair that looks matched need not be. So a profile's value may be an **object** instead of a
string, everywhere a string is accepted:

```jsonc
// %USERPROFILE%\.windbg-mcp\profiles.json
{
  "lab-nt": {
    "connection": "net:port=50000,key=1.2.3.4",
    "role": "windows",          // or "nt"; "hypervisor" or "hv" for the other kind
    "guest": "lab",             // shared by every endpoint of one machine
    "note": "root partition"    // free text, up to 200 characters
  },
  "lab-hv": { "connection": "net:port=50001,key=5.6.7.8", "role": "hv", "guest": "lab" },
  "ctf-vm": "net:port=50002,key=9.9.9.9"
}
```

```pwsh
# The same through the environment. A connection string never starts with `{`, so the two forms
# cannot be confused and every variable set before this existed keeps its meaning.
$env:WINDBG_MCP_PROFILE_LAB_HV =
  '{"connection":"net:port=50001,key=5.6.7.8","role":"hypervisor","guest":"lab"}'
```

Every field but `connection` is optional, and a profile that carries none of them renders exactly
what it always did. What they change is what a caller can see before and after an attach:

- `attach_kernel` with **neither** selector now describes what it lists —
  `Configured profiles: ctf-vm; lab-hv (hypervisor, guest "lab"); lab-nt (windows, guest "lab",
  "root partition").` — so an agent discovers the *pair* and not only the names.
- the session describes itself with them: `kernel target: profile "lab-hv" [hypervisor, guest
  "lab"] (net:port=50001,key=<redacted>)`.
- and they arrive as **values** too, in a `profile` object on the open's result and on every
  `session_status` row, beside the `kernel_target` the attach derived for itself. `guest` exists to
  be acted on — pairing two sessions as two endpoints of one machine is something a client does,
  not something it reads — and a structured-aware client forwards `structuredContent` and drops the
  text.

### What is checked, and what is only claimed

`role` is **checked**. An attach derives the same fact from the engine's primary module (`nt` or
`hv`), and a profile that says one and reaches the other is reported in the session's `limitation`,
in both halves of the result. Absent is not disagreement: a freshly attached kernel can have
nothing but `nt` in the engine's inventory yet, and "this server could not tell" must not be
reported as "your configuration is wrong". Nothing is refused either way — by the time there is
anything to compare, the session is open and the target is whatever it is; what is wrong is the
file.

`guest` and `note` are **claims and nothing more**. No debugger question asks two endpoints whether
they are the same machine, so these are the operator's word, reported as such. They are still worth
configuring — an asserted pairing is a fact somebody wrote down, where a pairing read off two names
is a guess — but do not read them as findings.

A field this server cannot take costs **that field** and never the profile: a `role` that is not
one of the four spellings, a `guest` that is not a name, a `note` with a line break in it or over
200 characters, or a member this server does not know is dropped with a note in the configuration
report, and the target still opens. The opposite would mean a typo in a description costs the
machine it describes. A `note` is scrubbed like everything else here, so a connection string pasted
into one does not leave this process either.

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
