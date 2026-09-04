---
paths:
  - "src/**/*.rs"
  - "build.rs"
---

## Several clients on one listener (`src/client.rs`)

A `--listen` server holds **one bearer token per client**: `WINDBG_MCP_LISTEN_TOKEN_<NAME>` names
one, the unnamed variable names `local`, and a configured `WINDBG_MCP_LISTEN_TOKEN_FILE` shuts the
environment out entirely rather than merely outranking it — so that file names its own clients (a
bare token is `local`; a JSON object of name to token is as many as it lists), which is the only way
a service-hosted listener holds more than one, and `--install-service` copies every credential
variable in the shell rather than the unnamed one alone. Under stdio everything runs as `local`,
so there is one set of rules and no transport exception. `docs/remote-listener.md` is the operator's
half; what follows is what bites while editing.

**A credential also carries a tool surface**, since item 36: `WINDBG_MCP_TOOLS_<NAME>` beside the
token, or a `tools` field in a file entry that is then an object rather than a string. That
follows the same precedence — a configured file is the whole configuration, so the variable is not
read on a host that has one — for a reason that is not secrecy but arithmetic: one file answering
who may connect and another answering what they get is two files to keep in step and a precedence
rule to remember.

**Five client commands, and the fifth only reads.** `--list-listen-clients` (item 37) prints the
same `roster` the four editors print, with no write and no reload — and **not under the credential
lock**, which is the trap: `lock_credentials` opens its file with `create(true)` and nothing else
creates it, so a reader that locked would write into `%ProgramData%` on any host where no edit had
yet run, which is exactly the property this command sells. It buys almost nothing either, since
`write_credentials` renames a finished file over the old one. Two more things bite when touching
it. It answers for **both** sources — a service's clients are in the credential
file, a foreground listener's are the environment it was started with — and the environment half
goes through `listen::named_token_file`, *not* `client::env_credentials` alone: a shell naming
`WINDBG_MCP_LISTEN_TOKEN_FILE` has its token variables ignored by the listener, so listing them
would be a roster of credentials nothing accepts. And a file it cannot read in full has to refuse
rather than print a shorter list — a dropped entry is a service that will not start, reported as a
service serving fewer people. And an unelevated caller is turned away by the *credential file's* own ACL rather
than by the lock, which is the object being protected rather than a thing beside it.

**All five warn when the SCM's image is not the one running the command** (item 38), and two things
about that bite. **`Service::query_config()` does not return a path**: the field is called
`executable_path` and `QueryServiceConfigW` fills it from `lpBinaryPathName`, which is the whole
line the SCM starts — exe *and* `--service --listen <addr>`. Compared as it comes it differs from
`current_exe()` on every host, correct ones included, so the warning would be a warning that is
always wrong. `image_in` reads the image back out of the line; a real service on this bench shows
both shapes it has to handle (`WinDefend`'s path is quoted, this service's is not). And the config
is read on a **handle of its own** rather than on the one `edit_client` already holds: adding
`QUERY_CONFIG` there would let a host with a narrowed service descriptor fail
`--remove-listen-client` because a warning wanted a right. It is a warning and never a refusal, for
the reason that is easy to try to "fix" — nothing carries a version between the two, so a second
copy of the *same* build is indistinguishable from a stale one.

**Identity is ambient inside a call, carried by the instance, and by name outside both.**
`crate::client::current()` reads a task-local, which is why no tool signature carries a caller. What
sets it around a tool call is **`call_tool`**, from the client its `WindbgServer` was built with —
*not* `listen::gate`'s `as_client` around `mcp.handle(req)`. The gate's scope covers the HTTP task;
rmcp serves a legacy MCP session from a task it `tokio::spawn`s at `initialize`
(`streamable_http_server::tower::spawn_session_worker`), and a task-local does not cross a spawn. So
the credential is captured where the instance is built — the listener's service factory, which does
run inside the gate's scope — and re-entered per call.

**Getting that wrong is invisible to everything but two real clients.** It was wrong from #162 until
the two-client smoke tier found it (`FOLLOWUPS.md` item 29): every call ran as the default `local`,
so both clients' sessions were owned by `local` and each could see, route to and end the other's,
while every unit test passed — each sets the identity itself, and the tier ran one client, for whom
`local` is the right answer.

**The factory now decides a second thing on that line, with the same failure mode**: which tools
this client is served (item 36). A client may carry a `Toolset` beside its name, so
`credentials.surface_for(&client)` is read there and nowhere later — a surface resolved after the
factory would be resolved for whichever task rmcp happened to serve the call from, which is exactly
the bug above wearing a different hat. It is covered the only way that shape can be:
`two_clients_on_one_listener_are_served_two_surfaces` puts two tokens on one port and asserts two
different `tools/list` answers, on the session-bearing route and the stateless one. One client
cannot state the claim — with one credential, "this client's spec" and "the run's spec" are the same
answer.

Anything running *outside* a call — the listener's own diagnostics, a sweep, a shutdown — gets the
default `local` instead of an error, so it must take the client as a parameter
(`Sessions::live_count_for` against `Sessions::snapshot`). The bug that rule is written from was a
log line reporting `local`'s session count to a named client on reconnect.

**A caller sees only its own sessions**, and that is not a fault to debug: routing, `session_status`,
`server_log`, the four-session cap, closed-session history and lease release are all per client, and
another client's handle is reported *unknown* rather than refused. Two tokens on one host are two
namespaces — if a session "vanished", check which token the request carried.

**There is no tenancy gate any more, and stale memory of it is the likeliest thing to mislead you
here.** Retired 2026-08-20 (`FOLLOWUPS.md` item 28, once #162's ownership had taken the boundary
over). What `Lease` is now: a clock, plus the two answers that were never tenancy. `admit` refuses an
`Mcp-Session-Id` **another client** records (`404`, *unknown* — never "someone else's") and a request
whose own credential is mid-release (`409`, ask again in a moment), and otherwise renews. Gone with
the gate: the reservation and its generation counter, `Occupied`/`409`, the in-flight count and its
epoch, the handover that waited on `Sessions::busy` (and `Sessions::busy` itself), `Arriving`, and
every read of `MCP-Protocol-Version` — the classification behind #168 is deleted rather than fixed,
so a request now presents an id or nothing and the revision does not enter into it. A credential may
hold **several** MCP sessions; they are kept in a set, because an id recorded for nobody is one any
credential may present.

**One lease rule survives, and forgetting it costs a client sessions it was using.** An **admitted**
request renews an existing deadline and creates none:

- *admitted*, because a refusal that renewed would let a stream of wrong session ids hold an
  abandoned client's live kernel target open for ever — the failure the sweep exists to prevent. Both
  refusals return before the renewal, and that ordering is the rule.
- *any* request, not any request of a shape: a credential holding a legacy session can go on to send
  `2026-07-28` ones (a client that upgraded, or restarted inside the grace), and the sweep reads
  `deadline` and nothing else.
- *creates none*, because a clock armed for a credential that holds nothing releases everything it
  opens one grace later. Only a settled MCP session arms one, which is what makes the trap that used
  to sit beside this — a reservation minting nothing and having to hand its deadline back —
  unreachable rather than handled.

The sweep zeroes nothing and waits for nothing, so what keeps it from releasing a session mid-call is
the startup floor in `Lease::new`: a grace longer than the longest a call can keep a client quiet
means **no request of that credential's can still be in flight when its lease expires**. That is the
property the epochs and claim generations were protecting one layer above, and it was already
enforced.

**What rmcp does with session ids, which the ownership answer now leans on.** Two facts, both in
`…/rmcp-3.1.2/src/transport/streamable_http_server/tower.rs`:

- a legacy `initialize` **always** mints one — `create_session()` then `spawn_session_worker`, with no
  check on who is asking — so nothing but this server ever refused a credential a second MCP session,
  and now nothing does. Hence a client's ids are a **set** (an id this server stops recording is one
  any credential may present) and an expiry closes **every** one of them (each abandoned handshake
  otherwise leaves a live service task behind).
- an id the service does not know — never issued, closed by a `DELETE`, or closed by the sweep —
  comes back `404 Not Found: Session not found`. That is deliberately the same status
  `Admission::NotYours` answers with: from the caller's side "not yours" and "not a session here"
  are indistinguishable, and splitting them into a distinguishable pair would confirm a session the
  caller may not touch.

**Driving the listener by hand on `2026-07-28` needs three things, and sending one gets a `400`
that looks like a broken server.** Every request *after the handshake* carries the
`MCP-Protocol-Version` header, `params._meta` with `io.modelcontextprotocol/protocolVersion` *and*
`…/clientCapabilities` (SEP-2567 moved them there when it removed the session that held them), and
SEP-2243's `Mcp-Method` — plus `Mcp-Name`, which is mapped **per method**: `params.name` for
`tools/call` and `prompts/get`, `params.uri` for `resources/read`, nothing for the rest.

`initialize` is the exception and is exempt from all three: it is the request that *establishes*
the revision, so it carries the version in its body, needs no `_meta` and no `Mcp-Method`, and may
omit the header as well. Sending the header anyway is legal and is what `Listener::stateless_opening`
does — which is precisely why the headerless handshake is untested (`FOLLOWUPS.md` item 30). Send
the recipe above on a handshake and you will take the ordinary path rather than the one that
carried the bug. `PowerShell`'s `Invoke-WebRequest` throws
on a 4xx and leaves the body on the exception, so those refusals read as empty when they in fact
name what is missing. Before believing any protocol-level claim about `--listen`, read the validator
that produced it: the rmcp source is on the Mac and needs no Windows build, at
`<rmcp>/src/transport/streamable_http_server/tower.rs`, where `<rmcp>` is the directory
`cargo metadata` reports for the pinned version rather than one assembled by hand — see *Local
verification* for why that distinction has teeth.

**A listener test that needs a real engine worker belongs in the debugger tier**, however cheap it
looks — the protocol tier's contract is "no debugger target". An attach cannot *park* without
`dbgeng.dll`: it fails during initialisation instead, which turns a test about a call that does not
return into one about a call that failed fast. CI's Windows runner happens to have the DLL, so
getting this wrong does not show up as a red build.

**Credentials are built from variables handed in, not read from the environment**
(`Credentials::from_entries`), for the same reason as `kdconn::env_entries`: `set_var` is `unsafe` in
edition 2024 and mutates state the whole test binary shares. And they are **stripped from every
child process by prefix** (`client::strip_credentials`), so a token variable added later cannot
quietly reach an engine worker or a `launch`ed debuggee — but a credential under a *different*
prefix would need its own strip.

Two collisions are refused at startup rather than resolved, because the winner would be a `HashMap`
ordering detail: one token naming two clients, and two tokens naming one (names are folded, so
`…_TOKEN` and `…_TOKEN_LOCAL` collide, as do `…_CI` and `…__CI`). **Neither refusal may quote a
token** — they are printed to stderr and, under the service, to a log file.

**That rule reaches inside an entry too, and getting there took two goes.** A file entry may be an
object (`{"token": …, "tools": …}`), and both ways its fields can be ambiguous were live in #196:
`serde_json::Map` collapsed an exact repeat before this module saw it — the very thing `Entries`
exists to stop one level up — and `entry_of` *folded* the field name, so `{"token": …, "TOKEN": …}`
was two spellings of one field with the later silently winning the credential. The fixes are worth
knowing apart, because only one of them is a check: the value type is now recursive (`Written`,
which takes every JSON type into a variant rather than letting serde raise a type error that would
quote a credential), and **a field name is matched exactly**. A client's *name* is folded because
the operator chose it and configures it in two places that have to agree; `token` is a keyword in a
file format, and being lenient about its case is what created the ambiguity rather than what
tolerated it.

