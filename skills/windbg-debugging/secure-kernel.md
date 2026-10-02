# Playbook: the Secure Kernel (VTL1)

**Goal:** read a Windows guest's **Secure Kernel** — the VBS VTL1 side, memory a running Windows
cannot read about itself — out of a **Hyper-V saved state**. Four tools do it: `open_sk_capture`,
`sk_modules`, `sk_read_memory`, `sk_symbol`.

**There are two routes and only one of them is a tool.** A **capture** is a file, and the tools read
it with no driver, no debuggee, and nothing running. A **live** guest needs a transport the
**operator** supplies, is driven by a command-line role rather than by MCP, and this repository
ships no transport — so nothing in the tool list reaches a running Secure Kernel. If that is what
was asked for, read [the live route](#the-live-route-the-operator-supplies-the-transport) first;
it is the second half of this page.

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
  all four. One started with a narrowed `--tools` has them if that spec names the `securekernel`
  group **or** names the tools it wants individually — `--tools` takes either, so a surface can
  carry `open_sk_capture` and `sk_read_memory` and not the other two.

No driver, no test-signing, and no debugger attached to anything. A checkpoint is the guest's whole
RAM in a file, so handle one like a full memory dump of that machine.

**A checkpoint of a VM with `EncryptStateAndVmMigrationTraffic` on will kill the session rather
than be refused, and the error reads as transient when it is not.** The SDK provider does not
return a failure for one: `LoadSavedStateFile` `__fastfail`s (`0xC0000409`) and takes the calling
process with it, which here is the worker holding that session — the provider is loaded once per
worker. So the open comes back *"the engine worker process holding session … is gone"*, whose own
advice is that opening again starts a fresh one. **For this cause that advice is wrong**: the same
capture kills the next worker too, so read that error on an `open_sk_capture` as *check whether the
VM encrypts its state* before retrying anything. Your other sessions are untouched, one worker
holding one session being the whole point of the shape. Measured on provider `10.0.26100.7705`,
x64, and reproduced from two unrelated processes — one of them a Rust binary calling the same
export — so it is the provider's behaviour and not this server's handling of it.

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
walk the open made. The physical address it landed on comes back with the bytes — so a reading here
can be compared with one taken another way — and, where the session has symbols, what the image
calls that address. `size` is 1 to 65536 and the read is **whole or nothing**: a range reaching a
page the capture does not carry is refused naming that page rather than answered short, which would
look like the end of a structure.

This is the only read that answers about the guest.

## Names, and the absence of types

```jsonc
sk_symbol { "session_id": "sess-…", "name": "SkLoadedModuleList" }   // or "address": "0x…"
```

Exactly one of `name` or `address`. A name is **unqualified** — the module name is the engine's and
is applied for you, so pass `SkLoadedModuleList` and not `securekernel!SkLoadedModuleList`. A
qualified one is not refused: a lenient engine resolves it and the answer comes back rendered
`securekernel!securekernel!Sym`, the right address under a doubled name. A lookup by address answers with the nearest preceding name and how far past it
the address is, so **a displacement of zero is the only answer that says the address *is* the
symbol**. Every answer carries the guest address, the RVA and the engine's own address, so a figure
from here joins a disassembler loaded at either base.

Two limits to plan around:

- **It needs a session opened with `symbols`.** Without it the refusal says so and the remedy is to
  open the capture again — the decode is identical either way, so nothing is lost but the call.
- **There are no types.** Microsoft's public `securekernel.pdb` carries **no type records**, so
  nothing in this session formats a structure over VTL1 — and `dt` is not a way round it, the
  debugger tools being refused here in the first place. A structure is
  read with `sk_read_memory` and decoded by hand, from offsets you derive. The open's report says
  what the engine answered when asked, rather than leaving you to infer it.

Symbols are loaded against the **image** with no debuggee, at its preferred base, rebased onto the
base the decode found. What that gives is the **names**, completely; what it does not give is the
types, at all.

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
<- (up to 63 lines the provider prints while starting; echoed to stderr, prefixed `transport:`)
<- windbg-mcp-gpa/1        the ready sentinel — the lines before it are ignored, not unlimited
-> SHAPE
<- SHAPE cr3=0x1201000 vtl_enabled=1 paging=long max_read=4096
-> READ 0xCD12DF 16
<- OK 16
<- <16 raw bytes>
<- REFUSED ReadIntercept   the hypervisor withheld that page
<- NOTPRESENT              no such mapping
<- ERROR the driver is not loaded
```

Four things to know before writing one:

- **The sentinel is not politeness.** A provider prints during its own setup, so without it the
  first line of a partition menu gets read as a `SHAPE` reply. **It has to arrive within the first
  64 lines**, those being all the client will read looking for it, so at most **63** may precede
  it; a transport still talking about itself on line 65 is rejected as probably not a transport,
  with what it said quoted back. A provider that prints per partition, per device or per loaded
  component is the one to check this against.
- **`max_read` is the only required `SHAPE` field**, and it must be the real one — `HvCallReadGpa`
  moves at most **16** bytes, and a transport that claims more than it can do will be asked for it.
  **Declare the smaller of your real capacity and 1 MiB**: the accepted range is `1..=1048576`, and
  a declaration outside it refuses the handshake rather than being clamped. That ceiling is a guard
  on the client's own buffer, which is sized from whatever you declare — not a statement about what
  your source can do — so a transport that reads more per request simply gets more requests.
  Every other field is optional because a source that cannot read a
  register must be able to say so rather than have a missing `EFER` decoded as a machine not in
  long mode. An **unknown** key is refused rather than ignored: a misspelled `cr3` would otherwise
  look like a guest with no page-table root, which is a far more plausible-looking wrong answer.
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
- **Nothing in this role has a read deadline.** A transport that starts and then never emits a
  newline blocks it until the operator interrupts — acceptable in a foreground command run by the
  person who wrote the transport, and one of the reasons it is not reachable from the server.

### If the user wants live Secure Kernel

Offer the capture first: it answers the same landmarks, needs no driver and no weakened bench, and
a checkpoint can be read on a different machine from the one that made it. If they need a *running*
guest, say plainly that the transport is theirs to supply — this server ships none and `--sk-live`
refuses to start without `--transport` — and that the role runs on the debugger host, not through
these tools. Then ask them to paste what it printed.

## Where the rest of it is

- [`docs/sessions.md`](../../docs/sessions.md) — the caller's half: what a capture session is, and
  what ending one does.
- [`docs/secure-kernel/README.md`](../../docs/secure-kernel/README.md) — the research record behind
  all of it: what is reachable from where, which landmarks survive a reboot and which do not, and
  what the lab needs. Several sections record what did **not** work, which is most of the value.
