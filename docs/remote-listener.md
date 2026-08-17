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

**A returning client adopts what it left.** Sessions are not released the moment a client goes
away, so reconnecting inside the grace finds them still open — which is better than stdio, where a
client restart costs a KDNET attach, and a KDNET attach costs a reboot of the target. The log says
how many sessions were inherited when that happens — or that nothing was open, since a client can
also arrive to find the previous one had let go of an empty server.

## One client at a time

A second client is refused with `409`. This is forced by the registry rather than chosen: session
handles are minted globally, the four-session cap is shared, and `end_session` ends whatever it is
handed — so two clients would silently share, and one could end a target the other was using.

The token is the identity. There is one authorised client, so presenting the token *is* the proof,
and a reconnect needs nothing further.

A `409` therefore means one of:

- another client holds the server, and has not gone away or timed out yet;
- a client is mid-`initialize` and has not been given a session id yet;
- sessions are being released after a lease expired, which finishes within a sweep (5 s);
- your own request outlived its claim — open a new session.

Tenancy changes hands only when nothing is still using the server: no HTTP request admitted under
the holder is outstanding, **and** no debug session has work in flight. The second is the one worth
knowing about, because an engine job outlives the request that asked for it — a call whose client
gave up is still running against the target, and the server will not hand that target on until it
finishes.

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

## Not there yet

- **No service installation.** The listener runs in whatever shell you start it in. A Windows
  service would give it a defined `PATH` and working directory, boot start, and a life independent
  of a login session.
