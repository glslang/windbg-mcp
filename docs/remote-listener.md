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

**Saying goodbye starts the grace; it does not end it.** A `DELETE` gives up the tenancy — the next
client is served once the departing one's work has drained, rather than after a whole grace period
(`Lease::try_give_up` holds it while a request is in flight or a worker is still busy, so a `409`
just after a `DELETE` is that, not a failure) — but the sessions that client opened stay open for
one more grace period, and its engine worker processes with them. That is the adoption case below,
reached deliberately: a client that restarts is the common reason a client says goodbye, and making
it pay a fresh `attach_kernel` would defeat the property this whole arrangement is for. If you are
really done, end the sessions first: `end_session` releases **one** target — the one you name, or the
current one — so a client holding several has to call it for each, and `session_status` is what
lists them. That is the difference between a live kernel that is free and one still owned for the
next 390 seconds.

**A returning client adopts what it left.** Sessions are not released the moment a client goes
away, so reconnecting inside the grace finds them still open — which is better than stdio, where a
client restart costs a KDNET attach, and a KDNET attach costs a reboot of the target. The log says
how many sessions were inherited when that happens — or that nothing was open, since a client can
also arrive to find the previous one had let go of an empty server.

## A session nobody is using is released

The lease answers "has this *client* gone away". There is a second question it cannot answer, and on
the revision most clients now negotiate it is the only one left: **has anyone touched this session
at all?**

`2026-07-28` removed the protocol-level MCP session ([SEP-2567]), so no `Mcp-Session-Id` is minted
and the lease — which
identifies a client by exactly that header — never takes a holder. A client that vanishes on that
revision leaves its targets held until this process exits, which for a live kernel means a machine
owned by nobody. See [#162](https://github.com/glslang/windbg-mcp/issues/162) for the whole of it;
this is the half that needs no client identity and so keeps working whatever the transport does.

| | |
| --- | --- |
| Default | **30 minutes** since the last call naming that session |
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
| Lease expiry | releases the sessions of the client whose lease ran out, and no others |
| Session ids | an `Mcp-Session-Id` another client holds is reported **unknown**, before this caller's own tenancy is consulted |
| Contention | **within** a client only — one client's long call does not make another wait |

**Why authentication is the identity.** `2026-07-28` removed the protocol-level MCP session
([SEP-2567]), so there is no session id to key on; requests arrive on whatever socket a client's
pool hands them, so there is no connection either; and `clientInfo` is not retained between
requests. The credential is what is left, and it is what every other stateless HTTP API uses. A name
a client presents for itself would be a label; a name only the holder of a token can present is a
boundary.

**Two clients do not queue behind each other.** The lease still arbitrates *within* a client — a
second **MCP session** for one token contends, and gets a `409` — because that is one credential
racing itself. Across clients there is nothing to arbitrate: a pool walk that keeps one client busy
for four minutes used to make every other client wait, for a boundary the registry now provides
properly.

A `409` is never about *connections*. Requests carrying the session a credential already holds are
served concurrently, which is what lets a `DELETE` arrive on one connection while a tool call runs
on another — the topology every streamable-HTTP client uses. What it refuses is a second MCP session
for one credential: a fresh `initialize` while a session is held or being opened, or a request
bearing an id that is not the one it holds. A request that arrives while another of the same
credential's is still *opening* one is refused on the same grounds, which is why the body names both.

**A client that sends no session id at all is the case to watch.** `2026-07-28` removed the session
([SEP-2567]), so every one of its requests takes the opening path, and two that overlap contend with
each other — measured on the bench, and recorded as `FOLLOWUPS.md` item 28, which is where the
question of retiring this gate lives. Measuring it also turned up
[#168](https://github.com/glslang/windbg-mcp/issues/168), which is the bigger question standing
behind it: this listener answers a `2026-07-28` handshake and then refuses the request after it, so
**use a client that negotiates a legacy revision until that is settled**.

**One `409` means the opposite of the others**, and says so: after a lease runs out, the sessions are
released in the background, and a request arriving during that cleanup is refused while the
credential holds nothing at all. Its body names the release rather than a session, because the fix
is to ask again in a moment rather than to go looking for a session you do not have.

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

**A token file is the only credential when one is configured.** `WINDBG_MCP_LISTEN_TOKEN_FILE` shuts
the environment out entirely — named tokens included — rather than merely outranking the unnamed
variable. That precedence is load-bearing: the service installer ACLs that file to SYSTEM and
Administrators *because* the machine environment is readable by unprivileged processes, so a
variable standing beside it would reintroduce exactly what the file was written to avoid.

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

`windbg-mcp.exe --uninstall-service` removes it, stopping it first and waiting for it — a delete
issued against a running service only marks it, and this one has debug targets to let go of.

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

## Not there yet

Nothing on this page is known-missing. `FOLLOWUPS.md` is where anything new lands.
