# Live VTL1 control provider contract

`src/skcontrol.rs` defines the repository-owned half of the live Secure Kernel control boundary.
The operator supplies the privileged provider as a child process. The repository ships no driver,
private VID layout, or provider DLL.

This is an implementation boundary, not an MCP session yet. `--sk-control-probe` validates a
provider's startup identity, epoch, and capabilities. `src/sklive.rs` supplies the worker-side
state machine over that contract, and `src/skdispatch.rs` supplies the build-guarded `vmwp` adapter.
The opt-in `--sk-live-control` role runs the complete narrow acceptance lifecycle through the same
engine constructor and thread ownership as an engine worker. The MCP tools remain a later gate.

## Process boundary

The provider owns exact-partition VTL1 register access. It does not receive or complete VID
messages. The debugger owner attaches to the existing `vmwp`, observes the dispatcher holding the
exception, and publishes that event to the provider. This keeps the private provider out
of the MCP supervisor and leaves Windows' existing VM process responsible for boot, devices,
message receipt, and native completion.

```mermaid
flowchart LR
    MCP[MCP supervisor] --> W[dedicated control worker]
    W -->|DbgEng, same thread| V[managed vmwp dispatcher]
    W -->|JSON lines| P[operator provider]
    P -->|guarded VP registers| H[exact child partition / VTL1]
    V --> H
```

The provider process starts with an exact target fixed by operator configuration. It prints:

```text
windbg-mcp-sk-control/1
{"protocol":1,"target":{...},"epoch":"running-..."}
```

The target object contains the VM GUID, hypervisor partition ID, VP, VTL, and expected CR3. Every
request and response repeats the full target and current opaque epoch. Addresses are fixed-width
hex strings so JSON implementations cannot round 64-bit values.

## Epoch state machine

```mermaid
stateDiagram-v2
    [*] --> Running
    Running --> Arming: begin_arm / rotate epoch
    Arming --> Running: finish_arm / rotate epoch
    Running --> Stopped: publish_stop / rotate epoch
    Stopped --> Running: release / rotate epoch
```

Register access is legal only in `Arming` or `Stopped`. `Arming` is entered while the debugger has
already paused the disposable VM and is installing or clearing DR state. `Stopped` requires a held
dispatcher event. A provider must refuse register access in `Running`, a stale epoch, a different
target, an unsupported register, and any compare guard which no longer matches.

The first revision has seven capabilities:

- `begin_arm` and `finish_arm` bracket debugger-paused breakpoint setup;
- `publish_stop` records the exact vector-1 event observed by the debugger worker;
- `held_event` reads that immutable event identity back;
- `read_registers` returns named values and per-register hypervisor status;
- `write_registers` compares every named register before applying any replacement;
- `release` consumes one held epoch immediately before the worker completes that event through
  `vmwp`'s native path.

The ordering on the last operation is load-bearing. Once native completion runs, the next vector-1
event may arrive immediately, so the provider must already accept a new `publish_stop`. The worker's
outer state machine remains in `releasing` between the provider transition and native completion;
failure in that interval faults the session and runs bounded recovery.

The readable bank is `rip`, `rsp`, `rflags`, `cr3`, `cs`, `dr0` through `dr3`, `dr6`, `dr7`, and
`vsm_vp_status`. `cr3`, `cs`, and `vsm_vp_status` are read-only. A held event records message type,
vector, VP, VTL, CPL, dispatcher context, advance flag, and either a hardware-breakpoint slot or a
single-step reason. Revision 1 accepts only mapped exception type `0x01000002`, vector 1, the bound
VP at VTL1 CPL0, a nonzero dispatcher context, and native advance clear.

## Probe

Run the non-mutating capability probe with an operator provider command:

```pwsh
windbg-mcp --sk-control-probe `
  --transport "python C:\private\provider.py ..." `
  --vm-id <VM-GUID> `
  --partition-id 0x85 `
  --expected-cr3 0x1201000
```

The optional `--vp` defaults to zero; VTL is fixed to 1 in this protocol revision. The command
starts before the MCP runtime and loads no DbgEng engine. It requires the operator's expected target
and rejects a provider hello for any other valid target. It prints the validated identity, current
epoch, and capabilities, then closes the provider's stdin and gives it ten seconds to exit before
terminating it.

Offline tests drive the complete running → arming → running → stopped → running sequence through a
fake provider, including guarded register reads and writes. They also pin fixed-width address
encoding, running-state refusal, target validation, and the rule that every state transition must
rotate the epoch. A live acceptance still requires the disposable Hyper-V target and the
operator-supplied provider.

## Worker state machine

`src/sklive.rs` joins one provider to one debugger-owned dispatcher. It contains no DbgEng engine
and no private VID layout; its production owner will be the existing engine worker, on the thread
which created that worker's engine. The dispatcher boundary must return the exact registered
callback context, a bounded observation of the held event, and a second read of the guarded guest
instruction.

The first revision deliberately implements the narrow gate that passed live:

1. pause the disposable target and enter the provider's arming epoch;
2. save RIP, RSP, RFLAGS, CR3, CS, DR0â€“DR3, DR6, DR7 and VSM VP status;
3. refuse an already-enabled hardware breakpoint, install one DR0 execution breakpoint, and
   redirect RIP to one guarded 1â€“15-byte instruction;
4. accept only the registered dispatcher context, VTL1 CPL0 vector 1, the bound CR3, the expected
   DR6 cause, and two identical held-state reads;
5. consume the stop epoch once to arm TF, then accept the single-step only at the guarded
   instruction's successor;
6. restore the complete writable baseline, verify the complete snapshot, rotate the provider to
   running, and complete only the exact owned native event.

Its outer phases are `running`, `arming`, `stopped`, `releasing`, `faulted`, and `closed`. A stale
epoch is a refusal with no mutation. A changed instruction, unexpected stop reason, changed
callback context, unstable held state, provider failure, or native-completion failure enters the
terminal `faulted` phase. Recovery first tries to restore the saved register state. It authorizes
native completion only when both restoration and event ownership are proven; otherwise the adapter
must leave the disposable target paused. Teardown does not erase the fault record.

The offline state-machine tests cover hardware stop to step to continue, stale epochs, instruction
guard failure, non-owned callback context, unstable held registers, completion failure, stopped
close, restoration, and idempotent close.

## Build-guarded dispatcher adapter

`src/skdispatch.rs` implements the concrete K4.2b boundary without constructing another engine.
The opt-in role calls the engine constructor in `worker.rs`; every adapter call then borrows that
engine on the same thread. Its retained state owns the provider child, live-memory transport,
breakpoint ids, callback scratch allocation, handler context, VM pause state, and delayed completion
helper.

The local dispatcher profile contains an absolute `vmwp.exe` image path, SHA-256 and SizeOfImage;
function and stop-site RVAs; original bytes for every software-breakpoint site; bounded scratch
offsets; and no debugger command text. The per-boot VND pointer is a separate session input. Before
mutation the adapter checks the VM GUID against the `vmwp` command line, the image identity, every
guarded site, the current VTL1 CR3, and the selected Secure Kernel instruction. It refuses an
existing mapping at the requested scratch base or a pre-existing breakpoint at an owned site.

All debugger commands are fixed internal operations with validated numeric substitutions. Software
breakpoints are created and removed through the typed DbgEng API, and their original bytes are read
back after removal. The adapter uses `.detach /h` at the pending native breakpoint, because the
measured unhandled detach terminates `vmwp`. The delayed `Suspend-VM` completion kick runs on a host
helper thread and makes no DbgEng call; the engine itself never leaves its owner thread.

The live acceptance role performs exactly one guarded hardware stop, one trap-flag step, continue,
handler unregister, deferred cleanup, scratch free, and handled detach. On 2026-10-03 it passed twice
against the allowlisted disposable K3 VM. Both runs stopped at the selected VTL1 CPL0 address with
DR6.B0, stepped five bytes to the exact successor with DR6.BS, restored the full saved state, and
closed. The recorded repeat kept the same `vmwp` PID and healthy heartbeat for 60 seconds, found no
scoped crash record, re-read unchanged Secure Kernel text, and left the VM Off. The exact profile,
provider, command and evidence remain ignored under `target/private/`.
