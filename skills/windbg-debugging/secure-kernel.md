# Playbook: the Secure Kernel (VTL1)

**Goal:** inspect or control a Windows guest's **Secure Kernel** — the VBS VTL1 side, memory a
running Windows cannot read about itself. Four capture tools read a Hyper-V saved state; seven
live-control tools stop, inspect, step and resume one selected VP in an exact disposable VBS VM.

**There are three routes.** A **capture** is a file, and its MCP tools read it with no driver, no
debuggee, and nothing running. A **live decode** uses the `--sk-live` command-line role and an
operator-supplied memory transport. **Live execution control** is a separate MCP session using
operator-supplied register and memory providers plus a build-matched `vmwp` adapter. This repository
ships no privileged provider. For a running guest, choose between
[live decode](#the-live-route-the-operator-supplies-the-transport) and
[live control](#live-execution-control-a-separate-mcp-session) according to whether the request
needs a snapshot or stop/step/resume.

## What the capture route needs on the host

- **A standard checkpoint of the guest, and an *unencrypted* one** — a `.vmrs`, or the older
  `.bin` + `.vsv` pair. It reads the same **copied off the Hyper-V host** as on it, so the machine
  running the server needs no Hyper-V role at all when the capture is named as a path. Naming it as
  a `vm` instead asks Hyper-V where that checkpoint lives, which does need the role installed there
  and an account that may ask about that VM. Encryption is the one prerequisite whose failure is
  not a refusal — see below.
- **The Windows SDK's `vmsavedstatedumpprovider.dll`**, which the tool loads out of an installed
  kit. `kit` and `kit_version` override the search when several are installed or the newest one has
  no provider.
- **The `securekernel.exe` the captured guest was running**, as a file on the host running the
  server — usually `C:\Windows\System32\securekernel.exe` when host and guest builds match.
  `image` is required and is not a formality: a mapping in VTL1 is **identified by comparing it with
  that file**, so there is nothing to identify against without one. A host on a different build is
  the wrong file; point `image` at the guest's own copy or the decode finds nothing and reports
  that it did.
- **The `securekernel` tool group.** It is in the default surface, so a server started plainly has
  all eleven capture and live-control tools. One started with a narrowed `--tools` has the capture
  tools if that spec names the `securekernel` group **or** names the tools it wants individually —
  `--tools` takes either, so a surface can carry `open_sk_capture` and `sk_read_memory` and not the
  other two capture readers.

No driver, no test-signing, and no debugger attached to anything. A checkpoint is the guest's whole
RAM in a file, so handle one like a full memory dump of that machine.

**An encrypted `.vmrs` will kill the session rather than be refused, and the error reads as
transient when it is not.** For a checkpoint of a VM with `EncryptStateAndVmMigrationTraffic` on,
the SDK provider does not return a failure: `LoadSavedStateFile` `__fastfail`s (`0xC0000409`) and
takes the calling process with it, which here is the worker holding that session — the provider is
loaded once per worker. So the open comes back *"the engine worker process holding session … is
gone"*, whose own advice is that opening again starts a fresh one. **For this cause that advice is
wrong**: the same capture kills the next worker too, so read that error on an `open_sk_capture` as
*check whether the VM encrypts its state* before retrying anything. Your other sessions are
untouched, one worker holding one session being the whole point of the shape.

**What that is measured on, because the scope is narrower than the warning sounds.** Provider
`10.0.26100.7705`, x64, a standard checkpoint, reproduced from two unrelated processes — one a Rust
binary calling the same export — so it is the provider's behaviour rather than this server's
handling of it. The older `bin` + `vsv` pair goes through a **different** export
(`LoadSavedStateFiles`) and is **untested**, encrypted or not: expect the same symptom, but if an
encrypted pair gives you an ordinary error instead, that is new information and not a contradiction
of this page. The ARM64 provider is untested too.

## Open a capture

Name it **exactly one way** — `vm` (with an optional `snapshot`; omit for the most recent),
`vmrs`, or `bin` with `vsv`. Two selectors is refused rather than one silently winning.

```jsonc
open_sk_capture {
  "vmrs":    "D:\\Hyper-V\\Virtual Machines\\Snapshots\\<id>.vmrs",
  "image":   "C:\\Windows\\System32\\securekernel.exe",
  "symbols": true          // opt-in: sk_symbol needs it; sk_read_memory names what it read with it
}
```

The rest are rarely needed and each has a sane default: `vp` (which virtual processor's saved
registers the VTL1 page-table root comes from, default 0), `vtl` (default 1, which is where the
Secure Kernel is), `symbol_path` (replaces the default for that engine rather than adding to it),
and `cross_check`, which reaches the loader list a **second** way — structurally, from the entry
whose base is the identified image's — and reports whether that agrees with the debugger data
block. One answer by two routes, at the cost of a scan of the mapped pages.

**The whole decode comes back with the open**: the page-table root read out of the capture, the
walk, `securekernel.exe`'s base, `KdDebuggerDataBlock`, `SkLoadedModuleList`, the loader list it
points at, and every count the decode made — **including the reads that failed**, which is what
separates "nothing is there" from "this run could not see". A capture is a fixed snapshot, so
nothing it says changes while the session is held and no later call re-reads it; `sk_modules`
renders the list the open already walked.

**A capture of a VBS-off guest opens and says so.** The provider refuses the VTL switch by name,
the session reports that refusal and the partition's VTLs, and every read against it is refused
with the same sentence. That is the answer to asking — and the control that makes a VBS guest's
figures mean something — not a failure to work around.

## A capture session is not a debugger session

Two consequences, both of them from the target being a file:

- **Only its own tools read it.** `sk_modules`, `sk_read_memory` and `sk_symbol` read the capture;
  every other tool that answers about a **debugger target** is **refused by name**. That is not
  tidiness: the engine in that worker holds the Secure Kernel **image on disk** — or nothing at
  all, when the session was opened without `symbols` — so `read_memory` there would read the file
  and report it as the guest's memory, and `registers` would answer about no thread. What is *not*
  refused is everything that is about the **session** rather than its target: `end_session` and
  `interrupt` are accepted on any session kind, and `session_status` and `server_log` never reach
  the worker at all. So a capture session is closed the ordinary way.
- **Nothing executes.** There is no thread, nothing to resume, step or break into, and no use for
  `go`, `set_breakpoint` or `continue_async`. The capture is opened read-only and never written;
  `end_session` closes a file.

## Read VTL1

```jsonc
sk_read_memory { "session_id": "sess-…", "address": "0xFFFFF80220D89000", "size": 4096 }
```

The address is a **guest virtual** address in the captured VTL1, translated through the page-table
walk the open made. The physical address comes back with the bytes — so a reading here can be
compared with one taken another way — and, where the session has symbols, what the image calls that
address.

**That `gpa` is where the range *starts*, and nothing more.** A read crossing a page boundary is
assembled page by page, each translated on its own, and two adjacent virtual pages need not be
adjacent physically — so the returned `gpa` is the first page's and the buffer is **not** a window
onto `gpa..gpa+size`. To line a reading up against a physical source, read a page at a time and
translate each one, rather than comparing a multi-page buffer against a contiguous physical range. `size` is 1 to 65536 and the read is **whole or nothing**: a range reaching a
page the capture does not carry is refused naming that page rather than answered short, which would
look like the end of a structure.

This is the only read that answers about the guest.

## Names, and the absence of types

```jsonc
sk_symbol { "session_id": "sess-…", "name": "SkLoadedModuleList" }   // or "address": "0x…"
```

Exactly one of `name` or `address`. A name is **unqualified** — the module name is the engine's and
is applied for you, so pass `SkLoadedModuleList` and not `securekernel!SkLoadedModuleList`. A
qualified one is **refused** as an invalid argument rather than stripped: `skci!Foo` names a module
the capture does not hold, and a lenient engine would otherwise answer
`securekernel!securekernel!Foo` — the right address under a doubled name — so the refusal is the
one answer that cannot mislead. A lookup by address answers with the nearest preceding name and how far past it
the address is, so **a displacement of zero is the only answer that says the address *is* the
symbol**. Every answer carries the guest address, the RVA and the engine's own address, so a figure
from here joins a disassembler loaded at either base.

Two limits to plan around:

- **It needs a session opened with `symbols`.** Without it the refusal says so and the remedy is to
  open the capture again — the decode is identical either way, so nothing is lost but the call.
- **There are no types — on every build anyone here has looked at.** Microsoft's public
  `securekernel.pdb` has carried **no type records**, so nothing in this session formats a
  structure over VTL1, and `dt` is not a way round it, the debugger tools being refused here in the
  first place. A structure is read with `sk_read_memory` and decoded by hand, from offsets you
  derive. Whether a public PDB ships types is Microsoft's to change, which is why the open **probes
  for them and reports what the engine answered** — read that rather than this sentence, and if it
  ever says otherwise, that is the build worth saying so about.

Symbols are loaded against the **image** with no debuggee, at its preferred base, rebased onto the
base the decode found. So what a session with `symbols` buys is the **names**; the types are what
the paragraph above is about, and the open's probes are what answer for the build in front of you.

## The live route: the operator supplies the transport

```console
windbg-mcp --sk-live --transport "<command line>" --image <securekernel.exe> [--cross-check]
```

That runs the same decode against a **running** guest. Three things about it decide how it can be
used, and all three matter:

1. **It is not a tool.** It is a role of the server's own binary, so there is no MCP call for it, no
   `session_id`, and `session_status` never lists it. This skill can describe it and read what it
   printed; running it needs a shell on the debugger host.
2. **This repository ships no transport, and the role will not start without one.** `--transport`
   is required. Reading another partition's VTL1 *live* needs a kernel component this project will
   not distribute — on the bench that has meant a test-signed driver issuing `HvCallReadGpa`, and
   `hvlib.dll` with its own driver — so the operator supplies the transport and accepts whatever
   posture **that** transport needs. Do not prescribe one here: which settings a host has to give
   up depends on the transport, this project has nothing to say about a transport it does not
   ship, and the one time that posture was guessed at on this bench it cost a protection for
   nothing (HVCI, turned off because a Code Integrity event was read as naming it when the policy
   id in it named something else, measured to change the failure not at all, and restored). What ships here is the **client** half: a
   line protocol, no privileged code, no unsafe FFI. It is the same arrangement as the live-kernel
   tier's KDNET wiring. **Without a transport there is no live route at all** — not a degraded one.
3. **It is deliberately not a fifth tool.** `open_sk_capture` can hand back a whole decode at the
   open because a capture cannot change. A live guest can: 2 bytes of `securekernel.exe`'s `.data`
   were measured changing inside twenty seconds (gate S5x), so a session whose figures were taken
   at the open would quietly describe a guest that has moved on, and two `sk_read_memory` calls
   could not be promised the same bytes.

A capture can also be read without MCP, by the sibling role —
`windbg-mcp --sk-inspect --image <path> (--vm <name> | --vmrs <path> | --bin <p> --vsv <p>)
[--symbols] [--cross-check] [--json <path>]` — which is the thing to suggest when the operator
wants the decode in a terminal or a file rather than in this conversation.

### What the transport has to be

A **child process speaking a line protocol on its stdio**: one ASCII line of request on stdin, one
status line on stdout, and for a successful read exactly the requested bytes after it.
`src/livesrc.rs` is the normative spec — this is the shape.

```text
<- (the provider's own startup lines; echoed to stderr, prefixed `transport:`, and bounded — see
    the table below, which is where every number in this protocol lives)
<- windbg-mcp-gpa/1        the ready sentinel — the lines before it are ignored, not unlimited
-> SHAPE
<- SHAPE cr3=0x1201000 vtl_enabled=1 paging=long max_read=4096
<- SHAPE max_read=16 switch_refused=VTL_switch_denied unreadable=efer:not_exposed
                           a VBS-off guest, and a register the source cannot get: both are
                           answers that travel, and both spell a space as `_`
-> READ 0xCD12DF 16
<- OK 16
<- <16 raw bytes>
<- REFUSED ReadIntercept   the hypervisor withheld that page
<- NOTPRESENT              no such mapping
<- ERROR the driver is not loaded
```

**Every bound the client enforces, in one place.** Three of these were found one review round at a
time, each as a provider that satisfied the protocol as written and failed anyway, so the list is
read off `src/livesrc.rs` rather than grown a row per bug report. None of them is negotiable from
the transport's side, and none is clamped — each refuses.

| what | bound | what a breach does |
|---|---|---|
| lines before the sentinel | **63** (64 are read in all) | rejected as "probably not a transport", with what it said quoted back |
| bytes in **any** one line | under **64 KiB**, newline included | 64 KiB with no newline is "not one line"; the exchange is refused and the transport poisoned |
| `max_read` declared | **`1..=1048576`** | the handshake is refused — declare the smaller of your real capacity and 1 MiB |
| `SHAPE` keys | the documented ones only | an unknown key is refused, not ignored |
| `vtl_enabled` | `0` or `1` | anything else is refused |
| `paging` | `long` | refused; this decode walks long mode only |
| `unreadable` names | `cr0`, `cr3`, `cr4`, `efer` | an unknown register name is refused |
| `OK <n>` | `n` **equal to** the bytes asked for | both directions poison: more is a source error, fewer is a short read, and a short read *is* a failed read rather than a partial answer |
| stdout | stays open until stdin closes | an EOF mid-exchange is "the transport closed its stdout" |
| teardown | **10s** after its stdin closes | the child is killed rather than waited for |

**And the grammar, which is the other half of the same contract.** Rounds of review found the
bounds one at a time and then found these the same way, so they are read off the source together:
nothing here is a shell, and no value is free text except where the table says it is.

| where | the rule | what ignoring it does |
|---|---|---|
| the `--transport` string | words split on whitespace, `"` toggling quoting; **no shell at all** — no expansion, no escapes, no single quotes | `$VAR`, `%VAR%`, `>`, `\|`, `'…'` and `\` reach the program **literally, as arguments**, so it usually fails to start or starts wrong |
| an **empty** argument | cannot be expressed: quoting groups whitespace, it does not create a word, so `""` contributes nothing | a provider needing an explicit empty positional gets it **dropped** and everything after it shifted — the one case that needs the wrapper script rather than merely preferring it |
| a `SHAPE` field | `key=value`, with whitespace in **neither** | the reply is split on whitespace first, so a value containing a space becomes a field that is not `key=value`, and the handshake fails |
| a `SHAPE` reason — `switch_refused`, `unreadable` | spaces written as `_`, which the client turns back into spaces | a reason with real spaces fails the handshake as above |
| `unreadable` | `unreadable=<register>:<reason>`, the register one of `cr0`, `cr3`, `cr4`, `efer` | an unknown register name is refused; no colon means the whole value is the register name |
| a status line's detail — `REFUSED`, `ERROR` | free text to the end of the line | **nothing**: these may contain spaces, and that asymmetry with `SHAPE` is the one to remember |

**If the provider needs shell features, put them in a script and name the script.** That is the
advice rather than a quoting recipe for invoking `cmd.exe` or `pwsh` inline, because this grammar
has no escape character: a `"` toggles quoting wherever it appears, so nested quotes do not nest.
Note also that the string reaches `--transport` only after **your own** shell has had it, so what
this grammar sees is whatever that shell passed on.

Things to know besides the numbers and the grammar:

- **After the sentinel, say nothing that was not asked for.** Every line the client reads from then
  on is read as the reply to the request it just sent, and there are only two requests ever sent:
  `SHAPE`, once, and then `READ <0xADDR> <len>` — the address in uppercase hex with an `0x` prefix.
  A progress line, a warning or a log written to stdout after the handshake is therefore consumed as
  a status line and desynchronises the stream. Diagnostics belong on **stderr**, which is never
  read as protocol and is the right place for them anyway: it reaches the operator's terminal
  directly.

- **The sentinel is not politeness.** A provider prints during its own setup, so without it the
  first line of a partition menu gets read as a `SHAPE` reply. A provider that prints per
  partition, per device or per loaded component is the one to check the line bound against — and a
  single long line is as fatal as too many, which is the easier one to hit with a provider that
  dumps a table or a JSON blob in one write.
- **`max_read` is the only required `SHAPE` field**, and it must be the real one — `HvCallReadGpa`
  moves at most **16** bytes, and a transport that claims more than it can do will be asked for it.
  Its ceiling above is a guard on the client's own buffer, which is sized from whatever you
  declare, rather than a statement about your source: a transport that reads more per request
  simply gets more requests. Every other field is optional because a source that cannot read a
  register must be able to say so rather than have a missing `EFER` decoded as a machine not in
  long mode. An unknown key is refused rather than ignored because a misspelled `cr3` would
  otherwise look like a guest with no page-table root, which is a far more plausible-looking wrong
  answer. One `SHAPE` field is **not** a failure: `switch_refused=<reason>` is how a transport says
  the VTL could not be selected, which on a VBS-off guest is the result and travels as one.
- **The four status words must stay distinct, and collapsing them fails in two different
  directions.** `REFUSED` is the hypervisor withholding a page, and over `HvCallReadGpa` on a VBS
  guest it is the **expected** answer. **Only `OK` with zero-filled bytes turns a protected guest
  into one with no Secure Kernel** — a zeroed buffer cannot tell data from silence, which is why
  refusals are counted on their own. Reporting a refusal as `ERROR` is a different mistake and
  still a mistake: it becomes a *failed* read, so the report withholds the negative instead of
  claiming one (*"identified nothing while N read(s) failed, so its negative has not been
  earned"*) — you lose the reason rather than receive a wrong answer — and an `ERROR` **poisons the
  transport**, that variant also covering an unparseable `OK`, which the client deliberately will
  not try to tell apart by reading the detail. On a guest that refuses per access, that ends the
  run at the first refusal instead of counting every one of them.
- **Every exchange has a deadline, and it is per response rather than per byte.** A transport that
  starts and then never emits a newline is refused after 60 seconds (`EXCHANGE_WAIT`), and the
  bound covers a whole banner, shape or read response, so one byte a minute does not keep the role
  alive either. It still runs in the foreground, where the person who wrote the transport sees the
  refusal.

## Live execution control: a separate MCP session

The `--sk-live` role above decodes a running guest once. It does not stop or resume anything. For a
controlled VTL1 kernel-mode stop, use the seven live-control tools. They create a dedicated worker
session whose DbgEng target is the host's `vmwp` and whose operator-supplied providers access the
selected VP's VTL1 registers and memory. The repository ships neither provider and ordinary debugger
tools are refused on this session so they cannot report `vmwp` state as guest state.

Use this route only for an exact, disposable VBS VM under an independent heartbeat, crash-record and
unchanged-text audit. Before opening, collect the current VM GUID, partition ID, selected VP, VTL1
CR3, `vmwp` PID and dispatcher VND; the exact-build `vmwp` profile or bounded profile directory; and
the register-control and live-memory provider commands. `open_sk_live_control` validates the input
shape, loads the profile and checks the register provider's declared identity and capabilities. It
does not pause, attach to or inspect the VM. The first `sk_live_arm` pauses the VM and validates the
live VM/`vmwp` binding, CR3, build and guarded instruction before it changes registers or breakpoints.

The sequence is:

1. `open_sk_live_control` with `profile`, `control_transport`, `live_transport`, `vmwp_pid`,
   `dispatcher_vnd`, `vm_id`, `partition_id`, `expected_cr3` and optional `vp`.
2. `sk_live_arm` with the exact instruction address and 1–15 guarded bytes. Natural mode leaves RIP
   untouched and may arm up to four distinct debug-register slots; redirect mode accepts one and
   deliberately moves RIP.
3. `sk_live_wait` to resume and collect the exact owned vector-1 event. Its answer includes the
   complete two-read register evidence, guarded instruction, expected next RIPs and a new opaque
   stopped epoch.
4. While that event is held, use `sk_live_registers` or `sk_live_read_memory`. Reads are bound to the
   stop and refused while running.
5. Pass the exact current epoch to `sk_live_step`, then call `sk_live_wait` for the next stop. For
   repeated steps, give the new current instruction and its bounded destinations.
6. Pass the final stopped epoch to `sk_live_continue`, then call `end_session`. Require the teardown
   to confirm release and that the target is running before the external health audit decides the
   run passed.

Every mutating stopped operation consumes one session-scoped epoch. Never reuse an epoch, guess an
instruction, or widen a branch beyond its decoded destinations. If teardown is unconfirmed,
`session_status` reports `live_control_unresolved` and retains the worker plus the exact VM/`vmwp`
reservation. Do not open a second controller; inspect or discard the disposable VM out of band.

### If the user wants live Secure Kernel

Offer the capture first: it answers the same landmarks, needs no driver and no weakened bench, and
a checkpoint can be read on a different machine from the one that made it. For a current decode of
a *running* guest, use `--sk-live`: the transport is theirs to supply, the server ships none, and the
role runs on the debugger host outside MCP. For a controlled stop, stopped-state inspection, step or
resume at a chosen address, use `open_sk_live_control` and the epoch-bound MCP sequence above, after
the operator supplies the exact disposable target and both providers. If they want **WinDbg itself**
on that stop, the `--sk-kd-target` role serves the serial KD protocol over a local named pipe to a
`kd -k com:pipe,port=\\.\pipe\<name>,resets=0`; it is a foreground role rather than a tool, and what
has been measured through it is one `t`, an `r` after it and `q` — the limits are in
[`docs/secure-kernel/kd-facade.md`](../../docs/secure-kernel/kd-facade.md).

## Where the rest of it is

- [`docs/sessions.md`](../../docs/sessions.md) — the caller's half: what capture and live-control
  sessions are, and what ending one does.
- [`docs/secure-kernel/kd-facade.md`](../../docs/secure-kernel/kd-facade.md) — WinDbg in front of
  the live controller: the connection string, what it can do today, and what it is told that the
  guest never held.
- [`docs/secure-kernel/README.md`](../../docs/secure-kernel/README.md) — the research record behind
  all of it: what is reachable from where, which landmarks survive a reboot and which do not, and
  what the lab needs. Several sections record what did **not** work, which is most of the value.
