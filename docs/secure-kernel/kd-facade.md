# The Secure Kernel KD facade

`open_sk_kd` puts an installed WinDbg in front of the live Secure Kernel controller
that [`live-control-provider.md`](live-control-provider.md) describes. WinDbg is the **protocol
client**: a dedicated engine worker serves the serial KD packet stream over a generated local named
pipe and translates the
requests it understands into the same guarded operations the seven `sk_live_*` tools make. The
target is still one selected VTL1 VP behind the operator's providers, and the facade creates no
DbgEng instance of its own — `src/worker.rs` lends it the one engine, on the thread that built it.
It shipped in 0.22.0 ([#463](https://github.com/glslang/windbg-mcp/pull/463), merged 2026-10-06)
with no tracked record, which `FOLLOWUPS.md` item 115 filed and this page closes. The MCP-managed
session now owns the lifecycle, reservations and recovery state; the earlier `--sk-kd-target` role
remains as a compatibility and diagnostic entry point.

`open_sk_debugger` builds the ordinary MCP debugger on top of that facade. The supervisor keeps
the facade worker internal, attaches a second worker's DbgEng kernel session to its private pipe,
and returns only the DbgEng handle. Generic tools therefore operate on Secure Kernel directly:
symbols, modules, stacks, disassembly, breakpoints, execution control and raw commands need no
Secure-Kernel-specific duplicate. The two workers still obey the repository boundary — one
DbgEng session per process, and no engine in the MCP-serving process — while `session_status`,
capacity and teardown treat them as one composite session.

The public worker is a protocol peer, not a second target owner. On `end_session` it closes its
private pipe and exits without sending native KD's `qd`: the facade has no distinct detach packet,
so `qd` is indistinguishable from an ordinary continue. The supervisor then asks the hidden
controller worker to restore and release VTL1. Only that controller can claim target release.

**What it is not.** It is not KDNET: there is no UDP discovery, no key exchange and no encryption,
and the transport is a named pipe on the debugger host (`src/kdwire.rs` keeps the framing
transport-neutral for a network envelope nobody has attempted). It is not EXDI, which the research
record parked ([`README.md`](README.md)). It is not a KD
transport inside the guest. Secure Kernel still ships none — gate S5a's finding stands — so this is
a host-side facade over the root-driven controller, and nothing here changes what the guest can do.
MCP and WinDbg do not mutate one stop concurrently: WinDbg holds the execution lease, while MCP
admits status, logs and teardown. While stopped, WinDbg can inspect the target and issue the
supported execution commands. While running after a `g`, WinDbg's Ctrl+Break asks the controller
for its M2 break rendezvous and the next stop is where the VP was paused; MCP `end_session`
recovers and releases the controller from any state. MCP `interrupt` is not a route into the
KD lifecycle.

## What has been measured

The MCP-managed gate passed live repeatedly on 2026-10-07 on the disposable K3 VM. `kd` from WinDbg
**10.0.26100.6584** connected to the server-generated pipe, received the held stop at
`securekernel.exe+0xb12b`, and ran `t`, `r` and `q`. The `t` arrived as `Continue2` with the trace
flag; the controller removed its hardware arm, set TF and released the retained `vmwp` event in one
transition, then published the returned vector-1 stop at the five-byte NOP's successor. `r`
printed the real VTL1 general registers, selectors, flags and new RIP. `q` entered the bounded
reconnect state, after which `end_session` restored the saved baseline and released the retained
event.

That run exposed one protocol dependency that the earlier standalone run had hidden. DbgEng reads
the AMD64 control-space selector for `KSPECIAL_REGISTERS` after a successful `GetContextEx`; if the
target rejects the read, DbgEng reports `GetContextState failed` and discards the usable general
context. The facade now returns the measured CR3 and debug registers in that bounded `0xe0`-byte
record and zeroes fields the provider cannot report. The independent post-release audit kept the
same `vmwp` PID healthy at immediate, 30-second and 60-second samples, found DR0–DR3 zero, DR7 with
no local enable bits, TF/RF clear, and read the original guarded Secure Kernel bytes twice.

A later run added live debugger metadata without a preparatory cdb session. Before admitting the KD
peer, the worker combined provider-reported base with exact-build profile RVAs and validated the
`KdpDebuggerDataListHead` links, `KDBG` tag and size, `KernBase`, `PsLoadedModuleList`, and the
loader-head links in VTL1 memory. WinDbg accepted those addresses and `lm m securekernel`
enumerated `securekernel.exe`; the gate used an empty local symbol directory, so this proves module
discovery independently of a symbol server. It then completed the same `t`, `r`, `q` sequence and
post-release audit.

On 2026-10-11, the item 116 symbol gate used the same kd version and a prepared local PDB cache
against Secure Kernel 26100.9457. The worker verified the mapped PE and its version resource before
publishing the pipe. At a natural `KiTimerInterrupt` stop, `t` executed `sub rsp,8`, `lm` enumerated
the live image, and `x securekernel!KiTimerInterrupt` resolved inside that range. `k 4` unwound two
symbolized frames: `KiTimerInterrupt+0x4` and `SkpReturnFromNormalModeRaxSet+0xe`, using real stack
and code reads. A redirected stop did not establish an unwind: its borrowed stack produced a
bogus return address. This is a bounded natural-stop result, not a claim about arbitrary stacks.
The exact server build and release audit are recorded under item 116 in `DONE.md`.

That run also corrects the earlier wording that `r` simply succeeds. It prints real registers and
the stepped RIP, followed by `Unable to get program counter 'r'`. `t` prints a `SetContext failed`
diagnostic when WinDbg tries to clear the controller-owned DR7 enable bit through a refused
control-space write; the guarded step still completes. These diagnostics remain product limits.

Two things that run also measured, both load-bearing for anyone running it again. WinDbg's serial
reconnect window is a few seconds, and the arm-and-stop transition took about five, so the role
captures its initial stop **before** it creates the pipe. And `kd -c "r;t;t;r;q"` did not execute
five commands — it stranded kd at its prompt — so commands go in a `-cf` file, one per line.

The earlier standalone run on 2026-10-05 established the same `t`, `r`, `q` route but ended with
the now-fixed `GetContextState` error. At that point the `g`-to-breakpoint path was only coded and
unit-tested against a fake dispatcher; no external WinDbg run had installed a breakpoint and
continued to it. The review that
filed items 115–119 read the facade and did not run it; the managed gates above are the later
evidence against those findings.

On 2026-10-26 the server-owned DbgEng composite passed its first live M8 route probe on the K3
one-VP VBS bench. Through the ordinary MCP debugger tools it resolved the 26100.9457 PDB, enumerated
`securekernel.exe`, installed `securekernel!IumInvokeSecureService` in a hardware slot, continued
to a guest enclave call, read registers and a two-frame symbolized stack, disassembled the x64
entry, and single-stepped its first instruction. It then cleared the slot, performed a bounded
`g` with nothing armed, and stopped that run through `break_in` and M2's rendezvous. Composite
release restored the controller baseline before resuming the child. The independent audit found
DR0–DR3 zero, DR7 `0x400`, TF/RF clear, no engine workers, unchanged guarded text and a healthy
heartbeat. K3 remained on its original boot, the child remained running, exact trigger artifacts
were removed, both provider services were stopped, staging was removed, and the runner used no
forced recovery. On 2026-10-28 the final controller repeated the same generic assertions and 25
free-run/break-in cycles on each of three clean boots; all 75 stops, ordered releases and
60-second audits passed. The external WinDbg/WinDbgX compatibility matrix remains separate.

## Running the managed session

Live Secure Kernel openers are disabled until the operator sets `WINDBG_MCP_SK_LIVE_POLICY` before
the server starts. The JSON file fixes all authority that a client may select:

```json
{
  "disposable_vm_ids": ["51749a1f-f939-44f5-b251-1251ef5b64a3"],
  "transport_commands": [
    "\"C:\\Python313\\python.exe\" \"D:\\windbg-mcp-private\\control.py\" --vm-id 51749a1f-f939-44f5-b251-1251ef5b64a3 --partition-id {partition_id} --vp {vp}",
    "\"C:\\Python313\\python.exe\" \"D:\\windbg-mcp-private\\memory.py\" --vm-id 51749a1f-f939-44f5-b251-1251ef5b64a3 --partition-id {partition_id} --vp {vp} --cr3 {cr3} --vmwp-pid {vmwp_pid} --partition-handle {partition_handle}"
  ],
  "profile_roots": ["D:\\windbg-mcp-private\\profiles"],
  "kit_roots": ["C:\\Program Files (x86)\\Windows Kits\\10"],
  "max_pause_ms": 600000,
  "allow_memory_writes": false
}
```

Every executable path is canonicalized at startup, and the complete tokenized provider command
must equal an allow-listed template. This prevents an allowed interpreter from being reused with a
different script or `-c` payload. Profiles must be files below an allowed root, and the VM GUID
must be in the disposable allow-list. Windows Kit roots are canonicalized too; capture provider
loading is disabled when none is admitted. `max_pause_ms` is the absolute bound for each retained
ordinary live-control stop and each managed-KD stop. The request cannot choose or widen it. An
optional `allow_memory_writes` defaults false and gates the ordinary live session's guarded write
tool; the managed KD facade does not expose guest-memory writes. An
invalid or absent policy fails before a VM lookup, provider load or worker spawn.
A capture-only deployment may omit the three live-authority arrays and `max_pause_ms`; a live
deployment must provide all three arrays together and a pause bound of at least 60,000 ms. The
smallest window leaves 30 seconds for service and a 30-second controller-cleanup reserve: the
mandatory five-second unregister settle plus 25 seconds of headroom for the restoration, event
completion, attach, unregister and deferred-cleanup work that precedes it.

Call `open_sk_debugger` with the exact-build dispatcher profile, the two provider command
templates, VM GUID and selected VP when MCP is the debugger UI. It returns one ordinary kernel
session handle; pass that handle to the generic debugger tools. `end_session` detaches that DbgEng
peer first and only then restores and releases the hidden controller. Here "detaches" means closing
the managed private-pipe peer, not sending generic KD `qd`, whose wire form the facade cannot
distinguish from `g`. If the peer cannot be closed, the controller remains held for recovery rather
than having its pipe removed underneath an unresolved engine. A controller-side recovery failure
is surfaced on the same public handle.

Call `open_sk_kd` with the same arguments when an installed WinDbg is the client. The profile
carries the initial guarded instruction as a Secure Kernel RVA;
the same required section carries the build-specific debugger-data list, block and loaded-module
list RVAs. The worker resolves them from the provider-reported image base and validates their live
links and identities before creating the pipe. It also reads the live AMD64 PE header and version
resource at that base and requires the image's file-version build to equal the profile's build.
Missing, unreadable or malformed version metadata refuses the open; the profile is not a fallback
for guest evidence. The resource-directory read is bounded to 64 KiB and shares the held stop's
service deadline. `{partition_id}` and `{vp}` are expanded only
after the worker discovers them; `{cr3}` is expanded for the memory provider after the register
provider reports and validates it. A memory command may additionally use `{vmwp_pid}` and
`{partition_handle}`; those are expanded only from the same guarded vmwp discovery, allowing an
operator transport to duplicate the VID file object into its own process without exposing either
value as client authority. `vmwp_pid`, `dispatcher_vnd`, `partition_id` and `expected_cr3`
remain optional mismatch assertions. The server resolves the current `vmwp` PID itself, generates
the pipe name from the system RNG, reserves both the VM and PID, and returns a session id plus the
exact connection string:

```console
kd -k com:pipe,port=\\.\pipe\<generated-name>,resets=0 -cf <commands.txt>
```

The success result also carries that generated string as the typed `connection` field; clients do
not need to parse it back out of `target`. `open_sk_debugger` deliberately omits the field because
its pipe is private to the supervisor-owned composite.

For an interactive external debugger, build the release binary and use the checked-in launcher
from any working directory. Its JSON file is exactly the `open_sk_kd` argument object; the startup
policy remains in the inherited environment and neither it nor the provider commands are copied
onto a child command line:

```powershell
$env:WINDBG_MCP_SK_LIVE_POLICY = 'D:\private\sk-live-policy.json'
& 'C:\src\windbg-mcp\tools\launch_sk_kd.ps1' `
  -Frontend Classic `
  -ConfigPath 'D:\private\sk-kd-open.json'

& 'C:\src\windbg-mcp\tools\launch_sk_kd.ps1' `
  -Frontend WinDbgX `
  -ConfigPath 'D:\private\sk-kd-open.json'
```

Supply `-ServerPath` or `-DebuggerPath` for an unpacked build. The launcher initializes a private
stdio MCP client, opens the facade, starts the selected debugger with only the generated local pipe,
waits for it to exit, and sends `end_session` in a `finally`-equivalent lifecycle. It also attempts
that cleanup when debugger startup fails or an open failure carries a recovery handle. The JSON
must not include smoke-harness fields such as `kd`, `trigger` or `post_release_audit`.

`session_status` reports `discovering`, `arming`, `waiting_for_peer`, `stopped`, `running`,
`reconnecting`, `releasing`, `released` or `recovery_required`. A peer disconnect while stopped
enters a bounded reconnect window. `end_session` cancels a connect or active wait, then runs the
ordinary proved controller teardown. Expiry of the connect, idle or absolute-pause bound also runs
that teardown immediately; `released` means it completed. The worker is preserved only if it
cannot prove restoration and release. The absolute pause bound comes from startup policy, is
independent of KD traffic, and includes response I/O plus controller restoration and native-event release. Each
stop reserves the smaller of 30 seconds or half of that bound for deadline-aware cleanup; the KD
service stops accepting work at the start of that reserve. A peer that stops consuming output
therefore cannot consume the time needed to restore and release the stop. `end_session` is also
observed by the live-memory pipe's engine-thread poll, so a provider that stops answering a read
cannot occupy the worker until its 60-second exchange limit while teardown waits behind it. Once a
stop is retained, its cleanup deadline remains with the dispatcher even after native completion has
consumed the event record; it bounds unregister waits, cleanup settling, `vmwp` reattachment,
Hyper-V transition joins and the final VM resume. Connect and idle bounds default to 30 and 300
seconds.

## Standalone compatibility role

```console
windbg-mcp --sk-kd-target --pipe <name> --profile <json> \
  --control-transport "<command line>" --live-transport "<command line>" --vm-id <guid> \
  [--instruction-address <assertion> --instruction-bytes <assertion>] \
  [--vmwp-pid <assertion>] [--dispatcher-vnd <assertion>] \
  [--partition-id <assertion>] [--expected-cr3 <assertion>] [--kernel-base <assertion>] \
  [--arm-mode redirect|natural] [--vp <number>] [--build <number>] \
  [--connect-timeout-ms <milliseconds>] [--idle-timeout-ms <milliseconds>] \
  [--max-pause-ms <milliseconds>]
```

The standalone role now resolves PID, VND and partition in its worker and accepts provider-reported
CR3 and Secure Kernel base. The optional values above, including the paired initial address and
bytes, are assertions for migration and diagnosis. The pipe remains operator-named in this compatibility role; the managed opener is the
route that generates it and applies startup policy. The version build is read from the live image
and must match the exact-build profile; `--build` is only an optional mismatch assertion. The arm mode defaults to natural guest
execution; select redirect explicitly when intentionally moving RIP to the guard.

1. The role opens the controller session and runs the provider handshake, arms slot 0 on the initial
   instruction in the chosen mode, and waits for that stop. No pipe exists yet.
2. It creates the pipe and prints `Secure Kernel stop held at <rip>; waiting for WinDbg on
   \\.\pipe\<name>; KD processor 0 of 1 maps to guest VP <vp>` to stderr. The connect wait and the KD reset wait that follows are each bounded
   by `--connect-timeout-ms` (default 30 s; 1 ms to 1 h).
3. Start the debugger. WinDbg takes the same `-k` string as kd:

   ```console
   kd -k com:pipe,port=\\.\pipe\<name>,resets=0 -cf <commands.txt>
   ```

   The facade answers the reset and sends the held stop as a state-change packet.
4. While stopped, every manipulate request is answered as the limits below say, and silence longer
   than `--idle-timeout-ms` (default 300 s; 1 ms to 1 h) ends the session. While running — after a
   `t` or a `g` — the same idle bound covers the wait, and a KD reset, a disconnect, a Ctrl+Break or
   a transport failure cancels the controller's wait through the one cross-thread `SetInterrupt` the
   repository allows (`AGENTS.md`), which enters the controller's fail-closed recovery.
5. `q`, or a disconnect, runs the controller's normal close: the baseline is restored and the
   retained event released. A disconnect logs "WinDbg disconnected; restoring the held Secure Kernel
   stop" and exits 0 once the close succeeds.

## Known product limits

The private bench plan's limits, re-derived against `src/kdtarget.rs`, `src/kdapi.rs` and
`src/sklive.rs` on 2026-10-07 and updated by the 2026-10-11 symbol gate, plus two the code states and the plan did not —
which single steps are refused, and what every other request is answered with:

- **Named-pipe serial KD only.** No KDNET network transport.
- **One selected VTL1 VP, and at most four debugger breakpoint handles.** A `bp` arrives as
  `WriteBreakpoint`. The composite debugger and a read-only standalone policy map it to a DR slot;
  a write-authorized standalone facade maps it to M3's guarded one-shot INT3 path. A fifth handle
  is refused in either mode. `StateChange64` reports one processor
  at index 0. The pipe banner and every state-change audit record identify the guest VP represented
  by that index; `SwitchProcessor` remains refused.
- **The version record still says `NOMM`, but its module and debugger-data pointers are live.** The
  worker validates the exact-build `KdpDebuggerDataListHead`, `KdDebuggerDataBlock` and loaded-module
  list before serving them. `lm m securekernel` enumerated `securekernel.exe` with an empty local
  symbol path. A prepared PDB cache also passed symbol resolution and a bounded two-frame natural
  stack walk. NT process, thread and memory-manager extensions remain outside the current claim.
- **The measured command order starts with `lm m securekernel`, `t`, `r`.** The symbol gate adds
  `.reload`, `x` and `k 4` before `q` and MCP teardown. The AMD64 special-register control-space
  selector returns real CR3 and debug-register state, with unavailable fields zero. The debugger
  diagnostics described above remain. An execution command after `r` has not been
  measured, so the gate does not claim that ordering yet.
- **The version record advertises hardware stepping.** The facade translates the debugger's trace
  request into its guarded target-assisted step. Without `DBGKD_VERS_FLAG_HSS`, WinDbgX 10.0.26100
  tried to derive a software-step successor from NT compatibility state, truncated the redirected
  RIP to its 16-bit offset (`0x512b` on the measured stop), and failed `t` before sending a trace
  request. Classic KD had already selected the trace-enabled `Continue2` path without that flag.
- **`t` steps the linear successor only.** A branch, call, return, interrupt or exception is
  refused; so is a `rep`-prefixed string instruction, and anything that writes `ss` (`mov ss`,
  `pop ss`, `lss`), because the trap can land somewhere other than the successor. A decoded
  `mov cr3,r64` is carried to that successor with a temporary hardware breakpoint rather than TF;
  the controller binds the resulting root and removes the slot before reporting the stop.
  **`g` is routed since 2026-10-25 and passed the server-owned three-clean-boot gate on
  2026-10-28.** A non-trace
  continue (legacy or `Continue2`) with hardware breakpoints installed is M1's proved
  continue-to-breakpoints; with none installed it is a bounded free run in which every slot is
  released and only a Ctrl+Break, teardown or the wait's recovery deadline can stop the VP, never
  an infinite resume. Managed KD grants transition-CR3 authority to those natural arms: a stop in
  another VTL1 address space is accepted only after two stable snapshots, a nonzero page-aligned
  root, a rebound memory walker and fresh breakpoint-byte verification. The immediate redirected
  first stop remains pinned to the startup CR3. A transition the controller refuses resends the
  held stop, so the session survives it. The call-debugging roadmap's M8.2 gate owns the packet-race and recovery
  qualification of both routes; the repeated probe is the ignored test
  `a_managed_secure_kernel_kd_session_is_driven_by_this_servers_own_kernel_attach`, which drives
  them through `open_sk_debugger`'s supervisor-owned composite. Whatever WinDbg sends for `p` is
  handled by the trace arm.
- **The proven redirected step is one five-byte NOP.** On that bench the next instruction used the
  interrupted context's RBX, so the acceptance takes one step and quits.
- **`SetContext` succeeds only for WinDbg's unchanged compatibility write**; a changed byte is
  refused, as are all control-space writes. No guest memory is written and no general-purpose register is: the only writes are the
  controller's own — debug registers for a breakpoint, TF for a step — and the baseline restores
  them at release.
- **Break-in during a `g` is routed to M2 since 2026-10-25 and passed 75 server-owned live cycles
  across three clean boots on 2026-10-28.** The serial break-in byte binds to the exact running wait: the reader marks the
  wait's break request before it interrupts the owned DbgEng wait, the dispatcher answers that
  interruption as a break wake rather than a cancellation, and the engine thread runs the M2
  rendezvous, a proved VM pause, a transient execute breakpoint at the paused RIP and the ordinary
  owned wait for it. A natural breakpoint that wins the race arrives as itself and keeps its
  reason. While stopped, a break-in resends the retained stop. During a `t` it stays what it was,
  a cancellation of the bounded wait into fail-closed recovery, because a trace step's expected
  stop is its own successor and break-on-demand has no running arm to bind to.
- **Everything else answers `0xC0000001`**: `WriteVirtual`, `ReadPhysical`, `SearchMemory`, MSR
  reads and writes, `SwitchProcessor`, `QueryMemory`, `SetContextEx`, `Reboot`, `CauseBugCheck`,
  control-space writes and control-space selectors other than the bounded AMD64 special-register
  record. A short manipulate packet and an invalid
  `GetContextEx` range now receive failure without losing the stop. Framing errors request resend;
  three consecutive framing errors enter recovery.

The `g` route has a history worth knowing before running it. A 2026-10-18 live qualification had
WinDbg install `securekernel!KiTimerInterrupt`, send non-trace `Continue2`, and the controller
release its retained event, after which no VTL1 breakpoint stop returned, the disposable VM reset
and the managed call timed out; both continue packets were refused from then on. The direct
controller then passed M1's 300 run-to-breakpoint cycles across three boots and M2's break races
on 2026-10-20, at a deterministic site rather than the timer interrupt. On 2026-10-25 the refusal
was retired in favour of routing both packets onto those proved paths, with the qualification
left where M8.2 puts it: a reset, hang, ambiguous stop or unproved restoration in that gate fails
it and brings the refusal back.

## What WinDbg reads that the guest never held

Secure Kernel has no NT `KTHREAD`, and WinDbg dereferences the wait-state thread field before it
will issue `t`. The facade therefore reports a synthetic thread at `0xfffffffefffe0000` and serves
zeros for the page there, for the life of the connection. It also serves zeros **once each** for the
bookkeeping reads WinDbg makes while constructing an NT scope — two null-page probes and four
`KUSER_SHARED_DATA` probes. **Natural stops always read real stack and code.** Only the initial
redirected stop has one-shot probes for 0x80 bytes at RSP, 0x2b bytes ending at RIP and 0x80 bytes
after the instruction. A KD reset or reconnect renews the probes for the current stop; after
execution reaches a new stop, neither can restore redirected stack/code probes. Those bytes exist
only in the KD view. Every other read goes to guarded VTL1 memory through the live source, clamped
to 3,944 bytes a request. Every fabricated read is logged at `info` with its shape, address, count
and zero fill. The version and state-change records identify their fixed compatibility fields;
context and special-register replies identify which unavailable fields were zeroed. These tracing
records reach both stderr and MCP `server_log`. Native KD has no per-read provenance field, so
WinDbg still displays compatibility bytes as memory; the audit is where an operator distinguishes
those bytes from guest reads.

The compatibility view also contains a synthetic GDT at `0xfffffffefffe0800`. Its bounded
descriptors define the reported CS `0x10` as long-mode code, SS `0x18` as kernel data, DS/ES/GS
`0x2b` as data and FS `0x53` as data; the AMD64 special-register reply points GDTR at it with limit
`0x57`. These bytes carry no guest state. They tell DbgEng how to decode the real instruction
stream: before that table existed, a zero GDTR made the engine treat CS `0x10` as 16-bit and render
the real bytes `40 55` as `inc ax; push bp`. The 2026-10-26 gate rendered them correctly as
`push rbp` and continued with the live x64 prologue.

## Pipe and host safety

- **The pipe is local and identity checked.** It rejects remote clients and carries a protected DACL
  granting the creating account, LocalSystem and Administrators. Before answering reset, the server
  obtains the client PID from the pipe and requires that process token to be the creating account or
  LocalSystem. The managed opener generates an unguessable name; the standalone diagnostic role
  still accepts an operator name.
- **The 2026-10-05 run is the leading suspect for a Kernel-Power 41 host reset** with
  `BugcheckCode=0`, no dump and no WHEA record. Causation is not proven. The controller's log ended
  after a complete restore and release; what the failed runner had left behind was a kd in its
  reconnect loop — from the pre-fix reset timing and the mis-parsed `-c` string — which could
  outlive the runner's short wait and block VM cleanup. The mitigations live in the bench's private
  runner, not in the facade: one command per `-cf` line; kd and the target monitored together under
  a 60-second command bound; kd asked to quit twice with bounded waits before it is terminated; the
  facade never killed while it may own `vmwp` state — the disposable VM is powered off first; VM and
  service cleanup run even when teardown reports an error; `Stop-VM -TurnOff` only after controller
  cleanup, or as the emergency containment path; and the disposable VM's `AutomaticStartAction` set
  to `Nothing`.

## What is tested

Focused unit tests cover framing, short manipulate requests, both context APIs, the AMD64
special-register record, malformed mapped PE/version metadata and compatibility-memory shapes.
The ignored WINDBG_MCP_SMOKE_SK_KD gates open the managed session through MCP and launch installed
kd with command files. The lifecycle gate checks forced disconnect and reconnect separately from
the symbol gate, which requires a natural stop, cached symbols and an unwind beyond the current
frame. Both release through MCP and require `quit:` plus the bounded external health/register/text
audit. The 2026-10-11 forced-disconnect run failed: the terminated kd retained its pipe until idle
expiry. It does not establish a reconnect result. The symbol gate exercises MCP teardown without
forcing that disconnect. Private configs must omit boot addresses, VND, partition ID, CR3, kernel
base and vmwp PID. These gates require the disposable bench and are outside ordinary CI;
docs/smoke-test.md has the runbook.

| WinDbg operation | Current result | Source of the answer |
| --- | --- | --- |
| Connect and initial stop | Live measured | Real retained VTL1 vector-1 event; synthetic KD envelope |
| `r` | Values live measured; display diagnostic remains | Real stopped general, segment, flag, CR3 and debug-register values; unavailable special-register fields are zero |
| `t` over a fall-through instruction | Live measured | Real TF step and returned VTL1 vector-1 event |
| Virtual instruction reads/disassembly | Live measured | Real VTL1 virtual memory, plus narrowly scoped compatibility addresses |
| `bp`/`g`, hardware-slot mapping | One server-owned DbgEng composite pass; repeated M8.2 qualification remains | Guarded VTL1 DR state and retained dispatcher event |
| `bp`/`g`, guarded INT3 mapping | Implemented for a write-authorized standalone facade; M8.2 qualification remains | M3 byte guard, proved pause and restoration |
| `g` with no breakpoint | One bounded server-owned run stopped by `break_in`; repeated M8.2 qualification remains | Every slot released; ends only at a break-in, teardown or the recovery deadline |
| Arbitrary memory/register writes | Refused | The standalone write-authorized facade owns only M3's guarded breakpoint byte; `SetContext` accepts only an unchanged prefix |
| `lm m securekernel` module discovery | Live measured | Validated live debugger-data head, `KDBG` block and loaded-module list |
| PDB symbol resolution and bounded stack walking | Live measured at a natural timer stop | Prepared PDB cache, live module range, real stack/code; two Secure Kernel frames |
| Asynchronous break-in during a `g` | One server-owned DbgEng composite pass; repeated M8.2 qualification remains | A proved VM pause and a transient execute breakpoint at the paused RIP |
| `q` and MCP `end_session` | Live measured | Proved restore/release, followed by the external audit |

`windbg-mcp --sk-kd-wire-probe --pipe <name>` is the transport-only fixture: one pipe, no VM, no
DbgEng, no MCP. It answers a connected WinDbg's reset, optionally sends a supplied state-change
packet (`--state-change`) and context (`--context`) under a `--kernel-base`, answers reads with
zeros, can write the traffic to `--capture`, and exits at `--timeout-ms` (default 15 s). It is a
handshake fixture rather than a replay, and it is what isolated the 2026-10-05 failure to command
order rather than to the context encoding: replaying the full live context through it still
produced `Continue2` with the trace flag.

## Distance from a debugging session

The [item 119 capability record](../../DONE.md#119-windbg-mcp-what-a-vtl1-debugger-still-cannot-do--done-2026-10-07)
holds the ordered ladder. The version record now names validated live debugger and module
lists; module enumeration, PDB symbol resolution and one bounded natural stack walk have passed.
Debugger display/write diagnostics, forced-disconnect behavior, stepping over anything but a
fall-through, more than one VP and writes are left, each behind a guard or an explicit refusal in
`src/sklive.rs` and `src/kdtarget.rs`. Facade-routed `g` and break-in are coded against the
qualified direct M1/M2 paths and passed one server-owned composite run. M8.2 still owns the
three-boot repeated front-end and race qualification.
