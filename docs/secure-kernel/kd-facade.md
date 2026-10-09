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

**What it is not.** It is not KDNET: there is no UDP discovery, no key exchange and no encryption,
and the transport is a named pipe on the debugger host (`src/kdwire.rs` keeps the framing
transport-neutral for a network envelope nobody has attempted). It is not EXDI, which the research
record parked ([`README.md`](README.md)). It is not a KD
transport inside the guest. Secure Kernel still ships none — gate S5a's finding stands — so this is
a host-side facade over the root-driven controller, and nothing here changes what the guest can do.
MCP and WinDbg do not mutate one stop concurrently: WinDbg holds the execution lease, while MCP
admits status, logs and teardown. While stopped, WinDbg can inspect the target and issue the
supported execution commands. While running, use MCP `end_session` to recover and release the
controller: WinDbg Ctrl+Break and MCP `interrupt` cannot preserve the KD lifecycle and are
unavailable.

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

Two things that run also measured, both load-bearing for anyone running it again. WinDbg's serial
reconnect window is a few seconds, and the arm-and-stop transition took about five, so the role
captures its initial stop **before** it creates the pipe. And `kd -c "r;t;t;r;q"` did not execute
five commands — it stranded kd at its prompt — so commands go in a `-cf` file, one per line.

The earlier standalone run on 2026-10-05 established the same `t`, `r`, `q` route but ended with
the now-fixed `GetContextState` error. The `g`-to-breakpoint path is coded and unit-tested against a fake
dispatcher, and no run has installed a breakpoint from WinDbg and continued to it. The review that
filed items 115–119 read the facade and did not run it; the managed gates above are the later
evidence against those findings.

## Running the managed session

Live Secure Kernel openers are disabled until the operator sets `WINDBG_MCP_SK_LIVE_POLICY` before
the server starts. The JSON file fixes all authority that a client may select:

```json
{
  "disposable_vm_ids": ["51749a1f-f939-44f5-b251-1251ef5b64a3"],
  "transport_commands": [
    "\"C:\\Python313\\python.exe\" \"D:\\windbg-mcp-private\\control.py\" --vm-id 51749a1f-f939-44f5-b251-1251ef5b64a3 --partition-id {partition_id} --vp {vp}",
    "\"C:\\Python313\\python.exe\" \"D:\\windbg-mcp-private\\memory.py\" --vm-id 51749a1f-f939-44f5-b251-1251ef5b64a3 --partition-id {partition_id} --vp {vp} --cr3 {cr3}"
  ],
  "profile_roots": ["D:\\windbg-mcp-private\\profiles"],
  "kit_roots": ["C:\\Program Files (x86)\\Windows Kits\\10"],
  "max_pause_ms": 600000
}
```

Every executable path is canonicalized at startup, and the complete tokenized provider command
must equal an allow-listed template. This prevents an allowed interpreter from being reused with a
different script or `-c` payload. Profiles must be files below an allowed root, and the VM GUID
must be in the disposable allow-list. Windows Kit roots are canonicalized too; capture provider
loading is disabled when none is admitted. `max_pause_ms` is the absolute bound for each retained
ordinary live-control stop and each managed-KD stop. The request cannot choose or widen it. An
invalid or absent policy fails before a VM lookup, provider load or worker spawn.
A capture-only deployment may omit the three live-authority arrays and `max_pause_ms`; a live
deployment must provide all three arrays together and a pause bound.

Call `open_sk_kd` with the exact-build dispatcher profile, the two provider command templates, VM
GUID and selected VP. The profile carries the initial guarded instruction as a Secure Kernel RVA;
the same required section carries the build-specific debugger-data list, block and loaded-module
list RVAs. The worker resolves them from the provider-reported image base and validates their live
links and identities before creating the pipe. `{partition_id}` and `{vp}` are expanded only
after the worker discovers them; `{cr3}` is expanded for the memory provider after the register
provider reports and validates it. `vmwp_pid`, `dispatcher_vnd`, `partition_id` and `expected_cr3`
remain optional mismatch assertions. The server resolves the current `vmwp` PID itself, generates
the pipe name from the system RNG, reserves both the VM and PID, and returns a session id plus the
exact connection string:

```console
kd -k com:pipe,port=\\.\pipe\<generated-name>,resets=0 -cf <commands.txt>
```

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
route that generates it and applies startup policy. The version build comes from the exact-build
profile; `--build` is only an optional mismatch assertion. The arm mode defaults to natural guest
execution; select redirect explicitly when intentionally moving RIP to the guard.

1. The role opens the controller session and runs the provider handshake, arms slot 0 on the initial
   instruction in the chosen mode, and waits for that stop. No pipe exists yet.
2. It creates the pipe and prints `Secure Kernel stop held at <rip>; waiting for WinDbg on
   \\.\pipe\<name>` to stderr. The connect wait and the KD reset wait that follows are each bounded
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
`src/sklive.rs` on 2026-10-07 rather than copied, plus two the code states and the plan did not —
which single steps are refused, and what every other request is answered with:

- **Named-pipe serial KD only.** No KDNET network transport.
- **One selected VTL1 VP, and four hardware execute breakpoints.** A `bp` arrives as
  `WriteBreakpoint` and takes a DR slot; a fifth is refused. `StateChange64` reports one processor
  at index 0 whatever `--vp` named, so nothing on the wire says which guest VP that is (item 116).
- **The version record still says `NOMM`, but its module and debugger-data pointers are live.** The
  worker validates the exact-build `KdpDebuggerDataListHead`, `KdDebuggerDataBlock` and loaded-module
  list before serving them. `lm m securekernel` enumerated `securekernel.exe` with an empty local
  symbol path. Symbol loading, stack walking and NT process, thread and memory-manager extensions
  have not passed and remain outside the current claim.
- **The measured command order is `lm m securekernel`, `t`, `r`, `q`.** `r` now completes after
  `GetContextEx` because the AMD64 special-register control-space selector returns real CR3 and
  debug-register state, with unavailable fields zero. An execution command after `r` has not been
  measured, so the gate does not claim that ordering yet.
- **`t` steps the linear successor only.** A branch, call, return, interrupt or exception is
  refused; so is a `rep`-prefixed string instruction, and anything that writes `ss` (`mov ss`,
  `pop ss`, `lss`), because the trap can land somewhere other than the successor. `g` needs at least
  one hardware breakpoint installed and is refused otherwise. A refusal resends the held stop, so
  the session survives it. The facade reads one bit of `Continue2`, the trace flag; whatever WinDbg
  sends for `p` is handled by those same two arms.
- **The proven redirected step is one five-byte NOP.** On that bench the next instruction used the
  interrupted context's RBX, so the acceptance takes one step and quits.
- **`SetContext` succeeds only for WinDbg's unchanged compatibility write**; a changed byte is
  refused. No guest memory is written and no general-purpose register is: the only writes are the
  controller's own — debug registers for a breakpoint, TF for a step — and the baseline restores
  them at release.
- **Break-in is not implemented as a new stop.** While stopped it is logged as unsupported and the
  retained stop remains usable. While running it cancels the bounded wait into fail-closed recovery;
  it is not reported as a stop that did not occur.
- **Everything else answers `0xC0000001`**: `WriteVirtual`, `ReadPhysical`, `SearchMemory`, MSR
  reads and writes, `SwitchProcessor`, `QueryMemory`, `SetContextEx`, `Reboot`, `CauseBugCheck`,
  control-space writes and control-space selectors other than the bounded AMD64 special-register
  record. A short manipulate packet and an invalid
  `GetContextEx` range now receive failure without losing the stop. Framing errors request resend;
  three consecutive framing errors enter recovery.

## What WinDbg reads that the guest never held

Secure Kernel has no NT `KTHREAD`, and WinDbg dereferences the wait-state thread field before it
will issue `t`. The facade therefore reports a synthetic thread at `0xfffffffefffe0000` and serves
zeros for the page there, for the life of the connection. It also serves zeros **once each** for the
bookkeeping reads WinDbg makes while constructing an NT scope — two null-page probes, four
`KUSER_SHARED_DATA` probes, 0x80 bytes at RSP, 0x2b bytes ending at RIP and 0x80 bytes after the
instruction, and that once-only window resets for every reported stop. Those bytes exist
only in the KD view. Every other read goes to guarded VTL1 memory through the live source, clamped
to 3,944 bytes a request. The facade's stderr says which happened for every read, `served by
compatibility memory` against `served by Secure Kernel memory`; the synthesized version and state
change are logged too. That audit is the only place the two are told apart: item 116 is about WinDbg
having no way to tell them apart.

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

The four protocol modules retain focused unit tests over inline packet vectors, including malformed
framing, short manipulate requests, both context APIs and the AMD64 special-register record. The ignored WINDBG_MCP_SMOKE_SK_KD tier opens the managed
session over MCP, observes its phases, and launches installed kd with a t, r, q command file. Once
the transcript proves `q` completed, the harness closes a kd process that still retains its pipe,
then requires the managed session to enter reconnecting before releasing it through MCP and running
the bounded external health/register/text audit. Its private config is forbidden from carrying a boot address, VND, partition ID, CR3,
kernel base or vmwp PID. The tier still requires the disposable bench and is not part of ordinary
CI; docs/smoke-test.md has the runbook.

| WinDbg operation | Current result | Source of the answer |
| --- | --- | --- |
| Connect and initial stop | Live measured | Real retained VTL1 vector-1 event; synthetic KD envelope |
| `r` | Live measured | Real stopped general, segment, flag, CR3 and debug-register values; unavailable special-register fields are zero |
| `t` over a fall-through instruction | Live measured | Real TF step and returned VTL1 vector-1 event |
| Virtual instruction reads/disassembly | Live measured | Real VTL1 virtual memory, plus narrowly scoped compatibility addresses |
| `bp`/`g` to one of four hardware slots | Implemented, not live measured | Guarded VTL1 DR state and retained dispatcher event |
| Software breakpoints or memory/register writes | Refused | No safe patch owner; `SetContext` accepts only an unchanged prefix |
| `lm m securekernel` module discovery | Live measured | Validated live debugger-data head, `KDBG` block and loaded-module list |
| Symbol discovery and stack walking | Unavailable | No live symbol or stack gate has passed |
| Asynchronous break-in | Unavailable | No running-state interrupt route has passed item 117 |
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
lists, and the control-space record is sufficient for `r`; module enumeration therefore precedes
symbol and stack support as a measured rung. Symbol loading, a bounded stack walk, break-in,
stepping over anything but a fall-through, repeated run-break-run, more than one VP and writes are
left, each behind a guard or an explicit refusal in `src/sklive.rs` and `src/kdtarget.rs`.
