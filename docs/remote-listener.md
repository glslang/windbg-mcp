# The listener — running the server on one machine and the client on another

`windbg-mcp --listen <addr>` serves the same tool surface over HTTP that the default stdio role
serves over standard handles. It exists so the client and the model can run somewhere other than
the machine DbgEng needs — a Mac driving a Windows VM, say.

If you only need that once, [`remote-phase0.md`](./remote-phase0.md) does it with no listener at
all: register the MCP server as an `ssh` command and stdio tunnels for you. The listener is for
what that arrangement cannot do — sessions that survive a client restart, several connections in
one session, and a server that is not tied to a login shell.

## Bind loopback, reach it over SSH

**This endpoint is patch-the-kernel-as-a-service.** `execute`, `debug_batch` and `launch` are all
on it, and the bearer token below is sent in clear. Bind `127.0.0.1` and forward:

```console
# on the Windows machine
setx WINDBG_MCP_LISTEN_TOKEN "<a long random string>"
windbg-mcp.exe --listen 127.0.0.1:8765

# on the client machine
ssh -N -L 8765:127.0.0.1:8765 windbg-vm
```

A hypervisor's guest network looks private and often is not: the machine being debugged is
frequently a sandbox on that same subnet, and it is the least trustworthy host you own. Binding
anything but loopback logs a warning on every start for that reason. If you do it anyway, put the
listener behind something that terminates TLS — the server does not.

The token comes from `WINDBG_MCP_LISTEN_TOKEN`, never an argument, because a command line is
readable by every process on the machine — including a debuggee you `launch`. It is stripped from
the environment of both processes this server creates (engine workers, and the TTD recorder), so a
recorded or launched target cannot read it and claim the server.

### Do not start it *through* ssh and then hang up

The two blocks above assume you are on the Windows machine for the first one. If instead you start
the listener from an `ssh` command and let that command finish, it dies with the session:

```console
# on the client machine — starts, binds, logs "listening on ...", and is gone seconds later
ssh windbg-vm 'powershell -Command "Start-Process windbg-mcp.exe -ArgumentList \"--listen\",\"127.0.0.1:8765\" -WindowStyle Hidden"'
```

**Windows OpenSSH terminates the session's process tree when the session ends**, and `Start-Process`
does not escape it. The symptom is confusing because the log looks like a healthy start: the bind
succeeds, `windbg-mcp listening on http://127.0.0.1:8765` is written, and nothing reports a failure
— the process is simply not there afterwards, and the port is not bound. Measured: alive at
`HasExited=False` three seconds in with the ssh session still open, and `Get-NetTCPConnection` on
the port empty once it closed.

**It is not stdin.** That is the intuitive explanation and it is wrong: the listener role never
reads stdin. Under stdio, a closed stdin *is* the disconnect and tears every session down; under
`--listen` there is no such signal, which is what the lease below exists to replace, and
`serve_http` is handed a shutdown future that never completes (`main.rs`). Worth knowing, because
"it lost its stdin" sends you looking at the wrong half of the server.

Two ways to keep it up:

**One ssh channel that both forwards and runs it.** Good for a session you are driving anyway — the
listener lives exactly as long as the tunnel, which is usually what you want, and there is nothing
left running when you are done:

```console
ssh -L 8765:127.0.0.1:8765 windbg-vm 'windbg-mcp.exe --listen 127.0.0.1:8765'
```

The token comes from the environment `setx` put it in, which an ssh session inherits.

**Know what that protects and what it does not.** This server strips `WINDBG_MCP_LISTEN_TOKEN` from
every child it creates (`engine::spawn_worker`, `ttd::record_launch`), so a debuggee you `launch` or
a target you `record_trace` does not *inherit* it — which is the accident worth preventing, and the
common one. It is not a defence against a target that goes looking: `setx` writes to
`HKCU\Environment`, and a process running as the same user can read that key, a file under that
user's profile, or the listener's own memory. Nothing the listener can read is hidden from a
program running as the listener's user.

So the account is the boundary, and **this server cannot put an untrusted target on the other side
of it**. `launch` creates the process through DbgEng and `record_trace` spawns TTD with `-launch`;
both run the target as the listener's own account, and there is no alternate-account path in this
server today. An untrusted binary passed to either can therefore read `HKCU\Environment`, recover
the token, and claim the listener — which is `execute`, `debug_batch` and `launch` on every session
it holds.

What that leaves:

- **Do not `launch` or `record_trace` an untrusted binary on a host whose listener token matters.**
  Record it on a machine that is not serving one, and bring the trace over.
- **Opening a dump or a trace executes nothing**, so it is unaffected.
- **`attach_process` is fine** when the target already runs as a **less-privileged** user — there
  the boundary exists, because this server did not create the process. A different account is not
  enough by itself: a target running as SYSTEM or as an administrator can read the listener's
  process memory or your registry hive whatever account it nominally has.
- **A remote kernel target** — `attach_kernel` over KDNET or serial — is a different machine
  entirely, which is what this endpoint is mostly used for. `attach_kernel_local` is **not** that:
  it debugs the machine the listener runs on, so an untrusted driver there is inside the boundary
  like anything else local.

**Or install it as a service**, which is what the service role is for and what survives a logout, a
reboot and a hung tunnel — see [Run it as a Windows service](#run-it-as-a-windows-service).

## Point a client at it

```console
claude mcp add windbg-vm --scope local --transport http http://127.0.0.1:8765/ \
  --header "Authorization: Bearer <the same string>"
```

`--scope local` rather than `project`: an address and a token are machine-specific in exactly the
way [`AGENTS.md`](../AGENTS.md) says to keep out of version control.

## The lease, and why the grace is what it is

Stdio gets one property free that the listener has to rebuild: when stdin closes, the client is
*definitively* gone, and every target is released — which for a live kernel is the difference
between a machine that comes back and one left frozen. Over HTTP there is no such moment. A client
that has stopped talking is indistinguishable from one that is thinking.

So a client holds a **lease**. Any request renews it; when it runs out, the sessions that client
opened are released exactly as a disconnect would have released them.

| | |
| --- | --- |
| Default grace | `WORKER_READY_TIMEOUT` (30 s) + the call timeout (300 s) + 60 s = **390 s** |
| Override | `WINDBG_MCP_LEASE_GRACE_SECS` |
| Floor | must exceed 30 s + `WINDBG_MCP_CALL_TIMEOUT_SECS`, or the server refuses to start |

That floor is not conservatism. A `crash_triage` or a pool walk sends **no HTTP request while it
runs**, so a grace shorter than the longest a call can keep a client quiet reads a working client
as an absent one — and releases the session the call is running against, out from under its own
caller. The bound is the sum because an opener spends up to 30 s bringing a worker up *before* the
call budget starts. If the server refuses to start, that message is why; raise the grace or lower
the call timeout.

**Saying goodbye starts the grace; it does not end it.** A `DELETE` closes the MCP session it
names, and the clock starts — but the debug sessions that client opened stay open for one more grace
period, and their engine worker processes with them. That is the adoption case below, reached
deliberately: a client that restarts is the common reason a client says goodbye, and making it pay a
fresh `attach_kernel` would defeat the property this whole arrangement is for. If you are really
done, end the sessions first: `end_session` releases **one** target — the one you name, or the
current one — so a client holding several has to call it for each, and `session_status` is what
lists them. That is the difference between a live kernel that is free and one still owned for the
next 390 seconds.

**A returning client adopts what it left.** Sessions are not released the moment a client goes
away, so reconnecting inside the grace finds them still open — which is better than stdio, where a
client restart costs a KDNET attach, and a KDNET attach costs a reboot of the target. The log says
how many sessions were inherited when that happens — or that nothing was open, since a credential
can also come back to find the MCP session it let go of had nothing open behind it.

## A session nobody is using is released

The lease answers "has this *client* gone away". There is a second question it cannot answer, and on
the revision most clients now negotiate it is the only one left: **has anyone touched this session
at all?**

`2026-07-28` removed the protocol-level MCP session ([SEP-2567]), and a lease is armed by one — so a
client on that revision is never given a clock. A client that vanishes there would leave its targets
held until this process exits, which for a live kernel means a machine owned by nobody. See
[#162](https://github.com/glslang/windbg-mcp/issues/162) for the whole of it; this is the half that
needs no client identity and so keeps working whatever the transport does.

**Not fixed by arming the lease from the credential instead**, which is now what identifies a
client and could perfectly well carry a clock. The two mechanisms answer different questions on
purpose. A lease releases *everything* that credential holds, busy sessions included, on the
reasoning that a client silent for a grace has gone; a `2026-07-28` client is legitimately silent
for far longer than 390 seconds — a model thinking between calls — and releasing a live kernel from
under a caller who is merely thinking is a worse failure than holding an abandoned one for half an
hour.

| | |
| --- | --- |
| Default | **30 minutes** since the last call that reached that session's engine. `session_status` and `server_log` are answered by the supervisor and never routed, so they name a session without touching its clock |
| Override | `WINDBG_MCP_SESSION_IDLE_SECS`, whole seconds; `0` disables it |
| Floor | must exceed the longest a single call can run, or the server refuses to start |

It is deliberately far longer than the lease grace. A lease is renewed by *any* request, so a
working client renews it constantly; this is per session, and reading a stack for twenty minutes
before asking the next question is ordinary work, not abandonment.

**A session with a call outstanding is never idle**, however old that call is. That is not a
detail: an `attach_kernel` parked in `WaitForEvent(INFINITE)` waiting for its target to dial in has
one call outstanding and nothing else for as long as it takes, and it is precisely the session that
must not be released. Nor is an opener that has not yet handed its handle back.

Each one is released through the same orderly `EndSession` an explicit `end_session` uses, one at a
time, because a live kernel that is merely killed is left halted.

[SEP-2567]: https://modelcontextprotocol.io/seps/2567-sessionless-mcp

## A client per token, and sessions that belong to it

A listener may hold several tokens, each naming a client, and **a session belongs to the client that
opened it**:

```console
setx WINDBG_MCP_LISTEN_TOKEN        "<a long random string>"   # the client named `local`
setx WINDBG_MCP_LISTEN_TOKEN_CI     "<another>"                # the client named `ci`
setx WINDBG_MCP_LISTEN_TOKEN_LAPTOP "<another>"                # `laptop`
```

The suffix is the name, lowercased — the same rule a kernel profile's variable follows. The unnamed
variable still works and names the client `local`, which is also who every stdio call runs as, so
one set of rules covers both transports. Configuring one token for two names is refused at startup:
the winner would be a hash-map ordering detail, and a boundary that moves between runs is not one.

What ownership buys, and it is the whole of it:

| | |
| --- | --- |
| Routing | a handle only routes for the client that opened it; omitting one finds *that* client's newest session |
| Refusal | another client's handle is reported **unknown**, not "someone else's" — the answer must not confirm a session the caller may not touch |
| Listing | `session_status` shows the caller's sessions and no others |
| Capacity | the four-session cap is per client, so a busy one cannot deny a quiet one |
| Reclamation | a session is only ever reclaimed to make room for **its own** client |
| History | a closed session ages out of `session_status` on its **own** client's churn, not the server's |
| The log | `server_log` shows the caller's sessions' records, plus the supervisor's own, which name no session — and the buffer counts it reports are over the records that caller can read |
| Lease expiry | releases the sessions of the client whose lease ran out, and no others — and refuses only that client's requests while the release runs |
| Session ids | an `Mcp-Session-Id` another client holds is reported **unknown**, before this caller's own lease is consulted at all |
| Contention | none — no client waits on another, and no client waits on itself |

**Why authentication is the identity.** `2026-07-28` removed the protocol-level MCP session
([SEP-2567]), so there is no session id to key on; requests arrive on whatever socket a client's
pool hands them, so there is no connection either; and `clientInfo` is not retained between
requests. The credential is what is left, and it is what every other stateless HTTP API uses. A name
a client presents for itself would be a label; a name only the holder of a token can present is a
boundary.

**Nothing queues behind anything.** Two clients never did after ownership landed, and since
`FOLLOWUPS.md` item 28 was settled a client does not queue behind *itself* either: the tenancy gate
is gone. It refused a credential a second **MCP session** — a fresh `initialize` while it held one,
or a request bearing an id that was not the one it held — with a `409`. That was the whole boundary
once, when handles were minted from one registry, the cap was shared and `end_session` ended
whatever it was handed. Ownership took the job over, and what the gate had left to arbitrate was one
credential racing itself, which inside its own namespace is not a boundary at all: both MCP sessions
reach the same debug sessions, because they are the same client.

So a credential may hold several MCP sessions, and each is recorded — an id owned by nobody is one
*any* credential may present, and the answer to another client's id is still **unknown**.

**What a `409` means now, and it is the only one left.** After a lease runs out, that credential's
sessions are released in the background, and a request arriving during the cleanup is refused while
it holds nothing at all — the body names the release, because the fix is to ask again in a moment
rather than to go looking for a session you do not have. Nothing else here answers `409`: an id
this server never issued is a `404` from the MCP service, and one another client holds is the same
`404`, deliberately — the answer must not confirm a session the caller may not touch.

**A client on a sessionless revision is refused less still.** `2026-07-28` sends no id, so it can
never present one that is not its own, and the only thing it can be told to wait for is its own
release. It used to be told far more: every request took the gate's *opening* path, so any two that
overlapped got a `409`, and a kernel attach whose target never dialled in locked its whole
credential out of `session_status` and `end_session` — the two calls that recover it. That was
[#168](https://github.com/glslang/windbg-mcp/issues/168), fixed by not reserving for a request that
could never become the holder, and the classification behind it is gone with the gate.

Such a client also never installs a lease at all, which is why abandonment on this revision is the
idle release's job rather than the grace's — see *A session nobody is using is released*, above.

**This does not authorise anything beyond separation.** Every client that can authenticate has the
whole tool surface, including `execute` and `launch`. Tokens separate clients from each other; they
do not rank them.

**One thing a client can still infer: that another one is busy.** `server_log`'s sequence numbers
are assigned across the whole server, and that is what makes a `since` cursor exact under eviction —
so a client reading two of its own records numbered a hundred apart can tell that *something* was
filed in between. It learns a count. The records, the sessions they belong to and their text stay
unreachable, and every number the tool reports — how full the buffer is, where the cursor is now,
what the oldest record is — is over that client's own stream. Numbering per client would close the
last of it and cost the cursor its stability, which is a bad trade for a shared debug host and a
worse one for a hostile tenant, who should not be sharing a listener at all.

**A token file is the only credential when one is configured, so it names its own clients.**
`WINDBG_MCP_LISTEN_TOKEN_FILE` shuts the environment out entirely — named tokens included — rather
than merely outranking the unnamed variable. That precedence is load-bearing: the service installer
ACLs that file to SYSTEM and Administrators *because* the machine environment is readable by
unprivileged processes, so a variable standing beside it would reintroduce exactly what the file was
written to avoid.

Which is why the file takes either shape. A **bare token**, which names `local` and is what this
file has always held:

```text
<a long random string>
```

Or a **JSON object of client name to token**, the same shape `WINDBG_MCP_PROFILES` uses for kernel
profiles:

```json
{
  "local":  "<a long random string>",
  "ci":     "<another>",
  "laptop": "<another>"
}
```

A leading `{` is what tells them apart, so a bare token may not begin with one — a file that does is
refused at startup, by name, rather than read as the other thing. Keys are client names, values are
their tokens: **written the other way round it configures a client named after your token**, and the
line this server logs at startup says who may connect. Nothing can detect that for you, since a
token is a valid name.

Everything else about the file is unchanged: one file, one ACL, and every rule above about what
owning a session means applies to the clients it names exactly as it does to tokens from the
environment.

**Every credential variable is stripped from the processes this server creates** — engine workers
and the TTD recorder — by prefix rather than by name, so a token added later cannot quietly reach a
debuggee. See the warning above about what that does and does not protect.

## Reading the server's log from the client machine

The listener's `tracing` output still goes to its own stderr, which is now on the *other* machine.
`server_log` is how it reaches you anyway: the supervisor keeps the last thousand records — its own
and every engine worker's — and serves them as a tool, so this works the same over stdio and HTTP.

```jsonc
server_log {}                                // the last 50, info and above
server_log { "session_id": "sess-…-1" }      // what that session's engine worker said
server_log { "level": "warn", "limit": 200 } // 50 records by default, 500 at most
server_log { "since": 412 }                  // only what is new, from the last `next_since`
```

A worker's records carry the session they belong to; the supervisor's — spawning a worker, timing
a call out, a worker dying — carry none, so **omit `session_id` when tracing an open that failed**,
since there was no session for those records to be tagged with.

Two things worth knowing. A healthy session is *quiet*: a worker logs when something goes wrong, not
as it works, so an empty page usually means nothing went wrong rather than that the bridge is
broken. And the buffer is the same stream as stderr, so it holds nothing below the level the server
was started with — widen with `RUST_LOG=windbg_mcp=debug` on the listener (and restart), not with
`level` on the call. `WINDBG_MCP_LOG_BUFFER` sets how many records are kept.

This is diagnostics about the *server*, not the target, and it is as sensitive as the server's
stderr — which for a live kernel session can name what the guest was doing. Under stdio those
records reached a log file; here they reach the client, and therefore the model. Treat a live-kernel
session accordingly.

## Watching a long call

`session_status` and `server_log` are both **pull**: they answer when asked, which means guessing
when to ask about a call that has not come back. A call can report on *itself* instead, with MCP's
progress notifications — opt in per call by putting a `progressToken` in its `_meta`:

```jsonc
{ "method": "tools/call",
  "params": { "name": "attach_kernel",
              "arguments": { "profile": "ctf-vm" },
              "_meta": { "progressToken": "attach-1" } } }
```

What comes back on that call's own stream, before its result:

```jsonc
{"method":"notifications/progress","params":{"progressToken":"attach-1","progress":1.4,
  "message":"engine worker started (pid 8124); opening the target"}}
{"method":"notifications/progress","params":{"progressToken":"attach-1","progress":2.1,
  "message":"the target has been created or claimed; waiting for it to break in"}}
{"method":"notifications/progress","params":{"progressToken":"attach-1","progress":12.1,
  "message":"still running (12.1s)"}}
```

Three things worth knowing. `progress` is **seconds elapsed** and there is no `total` — the budget
is a different constant per tool and an opener spends up to 30s bringing a worker up before its
budget even starts, so a denominator here would be a number the server cannot stand behind. A call
that has nothing new to say reports that it is **still running** every ten seconds, which is what
covers the two longest silences: a kernel attach whose last real milestone lands in the first second
and may never be followed, and a pool walk or `crash_triage`, which have no milestones at all. And
nothing at all is sent to a call that did not ask.

This is the same on stdio, where it is a convenience; here it is the only thing that arrives while a
call is outstanding.

## Run it as a Windows service

A foreground listener dies with the login session, inherits whatever `PATH` and working directory
that shell had — which is what decides whether the engine DLLs beside the exe are the ones that load
— and cannot start at boot. Installing it as a service fixes all three. From an **elevated** shell:

```pwsh
$env:WINDBG_MCP_LISTEN_TOKEN = "<a long random string>"   # this shell only
windbg-mcp.exe --install-service --listen 127.0.0.1:8765
Start-Service windbg-mcp        # or reboot; it is configured to start automatically
```

**Install from a protected directory.** The SCM stores an exact path for a `LocalSystem` auto-start
service, so whoever can write that directory — or drop an engine DLL beside the exe — gets their
code run as SYSTEM at the next start. `--install-service` refuses unless the exe is under
`%ProgramFiles%`, `%ProgramFiles(x86)%` or `%SystemRoot%`; for a development install on a machine
that is entirely yours, `--allow-unprotected-path` says so out loud.

The install copies that token into `%ProgramData%\windbg-mcp\token`, strips inheritance and grants
read to `SYSTEM` and `Administrators` only, and points the service at it. **Do not put the token in
the machine environment instead.** That would work, and it is a local privilege escalation: the
machine environment is readable by every local process, the listener is reachable on loopback by the
same, and `launch` takes an arbitrary command line and runs it from a worker this service spawned —
as `LocalSystem`. The token is the only thing in the way, so it has to stay unreadable by an
unprivileged process, which is the one property the foreground listener gets for free.

**Every credential in the installing shell is copied, not just the unnamed one.** A service reads
its file and nothing else, so the environment is only ever consulted *here*, at install — set
`WINDBG_MCP_LISTEN_TOKEN_CI` beside `WINDBG_MCP_LISTEN_TOKEN` before installing and the file it
writes names both. Afterwards the [client commands](#adding-revoking-and-rotating-a-client-without-stopping-anything)
are how that set changes, and they neither read the environment nor need a reinstall. One client called `local` is written as a bare token, as it always was; anything
else is the JSON object above. The install validates them the way the listener would, so a shell
that could not start a foreground listener cannot register a service either — which matters here,
because the SCM registers a service once and a bad credential then fails it at every start.

`windbg-mcp.exe --uninstall-service` removes it, stopping it first and waiting for it — a delete
issued against a running service only marks it, and this one has debug targets to let go of.

### Adding, revoking and rotating a client, without stopping anything

Three commands, from an **elevated** shell, and none of them costs you a session:

```pwsh
windbg-mcp.exe --add-listen-client    ci
windbg-mcp.exe --rotate-listen-client ci
windbg-mcp.exe --remove-listen-client ci
```

Each one rewrites `%ProgramData%\windbg-mcp\token` and then tells the running service to re-read
it — **waiting for it to have done so**, so the set in force when the command returns is the set it
wrote. Nothing is stopped and nothing is restarted, which is the whole point: a restart drops every
session the service holds, a parked kernel attach included.

Two commands cannot run at once. The second is refused rather than queued, because both would
compute a whole file from their own snapshot of it and the later write would silently discard the
earlier — an add and a revocation run together, both reporting success, and the revocation gone.

**A service reads the file its own commands write**, and nothing else. Setting
`WINDBG_MCP_LISTEN_TOKEN_FILE` in a service's environment does not repoint it: the installer writes
`%ProgramData%\windbg-mcp\token`, these commands edit it and `--uninstall-service` deletes it, so
a service reading somewhere else would be a configuration whose other three halves do not exist —
and the failure was silent, a revocation reporting success while the credential went on being
accepted. The variable is unchanged for a **foreground** listener, which is what it is for.

**The file is still not yours to edit.** It grants `SYSTEM` and `Administrators` *read*, so an
administrator who opens it in an editor is told `Access to the path is denied` — that is the ACL
working rather than something to route around, and taking ownership to write it anyway leaves a
credential owned by whoever did that. These commands are the writer instead: the same program,
running elevated, writing a fresh file with `create_new` in that protected directory, ACL'ing it
there, and renaming it over the old name. Never through a file it did not create, and atomic for a
service reading it at the same moment.

**They generate the token, and they will not print it.** What reaches your console is a fingerprint:

```text
added the client `ci` (sha256:076C14953E1DE5EF) — it gets the whole tool surface, as every client
here does — a token separates clients from each other, it does not limit one.
`windbg-mcp` now holds: `ci` (sha256:076C14953E1DE5EF), `local` (sha256:701E4CF334890225).

Its token is in C:\ProgramData\windbg-mcp\ci.token — the same SYSTEM-and-Administrators
directory the credential file is in, which is why it goes there and not somewhere you name. …

`windbg-mcp` re-read its clients; nothing was stopped.
```

Move that file to the client machine, set it there as `WINDBG_MCP_LISTEN_TOKEN`, and delete this
copy. The reason for all of it is one property: a token you typed has been through a shell history,
and on a machine being driven by an agent, through a transcript. One this server generated has been
through neither.

**You do not choose where it lands, and that is deliberate.** An earlier draft took a
`--token-out <path>`, which meant writing a live credential into a directory this program does not
control the protection of — so the file had to be created, ACL'd and reopened by name, and anyone
who could write that directory had a window to substitute a file of their own and keep a read handle
to it (a DACL change does not revoke access through a handle already open). The state directory is
already SYSTEM and Administrators only, with no traverse for anyone else, so there is no window to
race and nothing to substitute. An existing `<name>.token` there is never overwritten: it is a
credential an earlier command wrote and nobody has moved yet, and the fix is to move it — or, if it
belongs to a client you are done with, to remove that client, which deletes it.

Four behaviours worth knowing before you need them:

- **A rotation keeps the client's name, and so keeps its sessions.** Only the token moves: the old
  one starts answering `401` and the new one reaches the same debug sessions, because it is the same
  client. Rotating is the cheap operation — a lost token costs a rotation and nothing else.
- **A removal releases what that client still held**, down the path a lease expiry already uses, so
  a live kernel is let go rather than left frozen. It is not refused on their account: the command
  runs in another process and cannot see them, and blocking a revocation on the sessions it is
  revoking would be exactly backwards. It also deletes that client's `<name>.token` if the copy is
  still sitting there — from the moment the command returns, that file authenticates nothing.
- **Removing the last client is refused.** A listener with no credentials will not start, so that is
  not an incremental change but a decision to stop serving — which is `--uninstall-service`, and it
  takes the file with it rather than leaving a service that fails at every start.
- **A reload that cannot read the file changes nothing.** The set is only ever replaced by one that
  would have started this listener from cold, so a mangled file is a loud line in the service log
  and a service still serving the clients it had. The command that asked is told, and for a
  **revocation** it is told as a *failure*: a `--remove` or `--rotate` whose reload did not land
  means the credential you were taking out of service is still being accepted, which is not
  something to mention in passing. An `--add` in the same position is a warning — the new client
  simply cannot connect until the next start, and nothing that worked has stopped working.

If the service is not running, the file is written anyway and the command says it will be read at
the next start — a service that is still *starting* is asked all the same, because it has read its
credentials by then and is already serving the old set. If it is not *installed*, the commands refuse — a foreground listener takes its
clients from the environment it was started with, which is a set that cannot change without the
process changing too.

**A second foreground listener is still the right answer for a bench**, and it is a *development*
workflow rather than a way to operate a deployment — the commands above are what an operator uses.
A borrowed box with no administrator, a credential that should vanish with the process, a run that
must not share a process with the listener an editor depends on, a build that is not the installed
one: run a *second, foreground* listener on another port with its own token, which needs no
privileged write and disappears when you close it — [Driving it with a local model](#driving-it-with-a-local-model)
has the recipe. Two listeners on one host is a normal arrangement; sessions belong to a listener's
own process, so the two cannot see each other's.

**Stopping is graceful, and that is the point.** `Stop-Service` takes the same path a client
disconnect takes: every session is asked to release its target before the process exits, and the SCM
is given a wait hint that covers it rather than being left to assume the default and kill us
partway. DbgEng leaves a detached-but-halted kernel *frozen*, so a service that were merely killed
would hold someone's machine stopped until they noticed.

Three things that surprise people, all of them consequences of running as `LocalSystem`:

- **There is no console, so stderr goes nowhere.** The service writes to
  `%ProgramData%\windbg-mcp\service.log` (override with `WINDBG_MCP_SERVICE_LOG`). `server_log` is
  still the better channel once the listener is up; the file is for the case that matters most, a
  listener that refuses to start.
- **Kernel connection profiles are not read from your home directory.** `LocalSystem`'s
  `%USERPROFILE%` is `C:\Windows\system32\config\systemprofile`, so `attach_kernel {}` under the
  service lists nothing from *your* `profiles.json`. Configure them machine-wide instead:
  `WINDBG_MCP_PROFILE_<NAME>` in the machine environment, or `WINDBG_MCP_PROFILES` pointing at a
  file the service account can read.
- **It runs with more privilege than you did.** `--uninstall-service` deletes the token file with
  the service. If you want less privilege, `sc.exe config windbg-mcp obj= "NT AUTHORITY\LocalService"`
  and re-ACL the token file to match — at the cost of local kernel and process attach, which need
  privileges that account does not have.

## Driving it with a local model

Same listener, same registration — what changes is the budget, since the surface and every answer
now have to fit a window you are paying for in RAM rather than in tokens.
[`local-model.md`](./local-model.md) is the runbook: the three pieces, the measured cost of this
server's tool surface, and why the context your runtime *serves* is the number that matters rather
than the one on the model card.

## Not there yet

Nothing on this page is known-missing. `FOLLOWUPS.md` is where anything new lands.
