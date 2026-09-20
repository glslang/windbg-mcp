# Hypervisor demonstration, 2026-09-20

The merged server demonstrated hypervisor inspection, single-step, breakpoint creation/removal,
and an actual software-breakpoint hit. **The breakpoint-hit run failed its independent post-detach
guest-health check.** It is not a successful end-to-end recovery demonstration.

Open work is tracked in [windbg-mcp #355](https://github.com/glslang/windbg-mcp/issues/355)
and [FOLLOWUPS.md item 93](../FOLLOWUPS.md#93-windbg-mcp--dbgscope-multiprocessor-hypervisor-stops-after-a-temporary-breakpoint-and-detach).
The guest has since recovered. The owner's later one-vCPU change and successful demonstration
are recorded [separately](./hypervisor-demonstration-single-vcpu-20260920.md); they do not alter
the four-vCPU measurements or close the follow-up below.

## Measured artifacts

- Server source: `0ae564969822afa832fac2b39911c3b7c0f3247a` (merged windbg-mcp #350), unmodified.
- MCP `initialize` identity: `0.18.0+g0ae56496`.
- Development executable SHA-256:
  `150BE90567829D4C2F915B7A17A6F1C0A5E96D18A50C18BDEF9AAFDB7773B9D1`.
- Cargo-locked dbgscope revision: `1767cf2c151d8375aa447b854919edb9f9afd2b3`.
  The changes between that revision and #172's reviewed `b77ffe9` affect documentation and
  diagnostic examples, not the library source; no dependency override was used.
- Actual worker-loaded AMD64 DbgEng: `10.0.29617.1000`, SHA-256
  `4352756685E7325288E54ABB3281E768637987517BE8575EC4450E4B4421842F`.
- Target: Microsoft Hypervisor 29671, four processors, image `hvix64.exe`, module `hv`.
  Image size `6393856`, timestamp `3152137373`, checksum `2578329`; no hypervisor symbols.

Read-only preflight verified guest identity, hypervisor launch/debug settings, the debugger's
current address, and the endpoint key by hash. The endpoint was unowned before each attach.
All six MCP live runs used `experimental_break_on_connect: true` through a machine-local profile.
No configuration changes, reset/reboot, installed-server replacement, or forced process
termination were performed.

## Results

Times below are local debugger time (UTC+1). Raw logs remain local; they are not public attachments.

| Run | Result | Independent health |
|---|---|---|
| 10:54:11 | Inspection and single-step succeeded. Harness stopped on a stale `breakpoints` tool call, before creating any breakpoint. Explicit detach succeeded. | Same boot; post-detach uptime 75143.6991699 then 75146.0131737 seconds. |
| 10:54:59 | Corrected inspection, memory, disassembly, single-step, breakpoint creation/removal, and explicit detach all succeeded. | Same boot; post-detach uptime 75190.8051764 then 75193.1211778 seconds. |
| 10:56:20 | Repeated those operations, then hit the return-site software breakpoint at `hv+0x312024`. Explicit detach reported success. | WinRM failed after detach; a later bounded TCP check also failed. The owner subsequently confirmed a black/frozen Hyper-V console. |
| 11:27:25 | Packet-traced breakpoint hit on CPU 1, followed by one requested single-step that stopped on CPU 2 at the same address. Explicit detach reported success. | WinRM failed again; the owner confirmed a frozen console. Recovery at 12:00 failed; a separately authorized connection at 12:03 handled further stops and restored same-boot health. |
| 14:03:40 | Initial-event caller stack captured without adding a breakpoint or requesting a step. CPU 0 registers read successfully; its subsequent unqualified virtual stack read failed and ended the capture. | Same boot; post-detach uptime 86511.8907794 then 86514.2167716 seconds. |
| 14:05:20 | Narrowed capture obtained all four processor register snapshots and the initial event stack; no breakpoint or step added. | Same boot; post-detach uptime 86610.0358456 then 86612.3378266 seconds. |

The successful single-step moved PC from `hv+0x404a60` (`cc`, `int 3`) to `hv+0x404a61`
(`c3`, `ret`). The breakpoint-hit run read the return address from the stopped processor's stack,
checked it was inside the measured hypervisor image, and decoded that destination before resuming.
It did not use an address from another build or patch the instruction pointer.

`run_to_address` used a 5000 ms budget and returned `verdict: hit`, with `stopped_at` equal to
the selected `hv+0x312024` address. Its output said `Breakpoint 0 hit`; `.lastevent` independently
reported `Hit breakpoint 0`, and a register query confirmed PC. A subsequent `bl` was empty.
This is evidence of a breakpoint hit, not merely successful breakpoint installation.

The final `end_session` returned `released: true`, `target_left_running: true`, and
`worker_terminated: true`. The supervisor exited zero. Subsequent local checks found no debugger
process and no owner for the hypervisor UDP endpoint, but the guest management channel did not
respond. The owner's subsequent black/frozen-console confirmation establishes that the failure was
not merely an unavailable WinRM service. Thus debugger-reported release did not establish restored guest execution. No packet
trace was collected in this run. The recovery below subsequently established a pending stop,
but the mechanism that produced it remains unestablished.

## Native recovery after console confirmation

The owner authorized one native-KD recovery connection. At 11:08:44 local time, after checking
that no debugger owned the endpoint, KD 10.0.29617.1000 connected without `-bonc` and without an
explicit-target poke. The saved trace contains zero `Send Break in` lines. Initial state-packet
ID mismatches were followed by a target RESET; synchronization then reached a usable prompt.

The recovery prompt selected CPU 2 at `hv+0x312024`, the demonstration's breakpoint destination.
`.lastevent` reported a first-chance `0x80000003` breakpoint exception. The controller's `bl`
listing was empty, and memory decoded to the original `8a057e99dbff` instruction, not `int 3`.
The demonstration's earlier single-step report explicitly identified CPU 3; its `run_to_address`
report did not carry a processor field, so that earlier CPU number alone does not establish
which CPU reported the software-breakpoint hit.

One `qd` sent `DbgKdContinue(10002)`, received the correct ACK, and returned `00000000`.
KD exited zero. Independent WinRM readings then confirmed the expected guest, the same boot
as before the demonstration, and uptime advancing from `76060.8779815` to `76063.2470469`
seconds. The hypervisor endpoint was free afterward. No reset, reboot, forced termination,
additional recovery connection, or host configuration change was needed.

This confirms one pending stop at the software-breakpoint address after the original controller
had reported release. Another processor reaching shared patched code before breakpoint removal
is a plausible explanation, not an established root cause. A restored instruction and empty
breakpoint inventory did not exclude a pending breakpoint event. This is one successful manual
recovery, not validation of automatic recovery or dependable post-breakpoint detach.

## Packet-traced post-hit step

After the successful recovery, one further bounded diagnostic used the same unmodified server
and DbgEng binaries. The guest was healthy before attachment, with the same boot and uptime
`77133.6670753` seconds. Packet logging was enabled after attachment, so this trace cannot
establish whether the initial attachment sent break-in packets.

The packet trace records the following sequence:

1. `DbgKdWriteBreakPoint` installed the breakpoint at `hv+0x312024` with handle 1.
2. An acknowledged `DbgKdContinue(10001)` was followed by a `STATE_CHANGE64` event on CPU 1
   of 4. Context readback placed PC at the breakpoint destination.
3. `DbgKdRestoreBreakPoint(1)` returned success; `run_to_address` reported `hit`,
   `.lastevent` reported `Hit breakpoint 0`, and the subsequent breakpoint inventory was empty.
4. One requested `step_into` sent another acknowledged `DbgKdContinue(10001)` and received
   a second `STATE_CHANGE64` event, this time on CPU 2 of 4 at the same PC. The stack pointer
   differed from CPU 1's. The typed result reported `timed_out: false`, `interrupted: false`,
   and `target_gone: false`, but PC had not advanced. `.lastevent` then reported `<no event>`;
   the breakpoint inventory remained empty and disassembly showed the original instruction.
5. Final `qd` sent `DbgKdContinue(10002)`, received the correct ACK, and returned success.
   MCP reported release and the supervisor exited zero, but independent WinRM health failed.

There is an important confound: between the first breakpoint hit and the requested step, the
harness issued bare `~` as a processor-status query. DbgEng returned a syntax error and
`0x80040205`; the harness failed to check that query's `isError` before continuing. That query
has been removed from the local harness for any future controlled comparison; no repeat has
been performed. The failed query is retained in the evidence and prevents treating this as a
clean comparison of detach with and without an extra step.

The trace establishes that a state-change event from a different processor was delivered after
breakpoint restoration. It does not establish that the requested instruction step completed,
how many stops remained after `qd`, or the root cause of the unhealthy guest. In particular,
one extra step did not provide a successful recovery in this run. No automatic stepping loop
or production teardown change follows from this result.

## Second native recovery: single-step exception pending

After the owner confirmed the console was frozen and authorized one recovery, native KD connected
at 12:00:26 without `-bonc` or an explicit-target poke. The endpoint was unowned and no debugger
process was present beforehand. The saved trace contains zero `Send Break in` lines, although
the transport printed `Kd sync initial break: on`; absence of that packet-log message is not a
general guarantee about every effect of synchronization.

The recovered state was CPU 1 at `hv+0x31202a`, immediately after the six-byte instruction at
the original breakpoint address. Its stack pointer matched CPU 1's first breakpoint stop.
`.lastevent` reported `Single step exception - code 80000004 (!!! second chance !!!)`.
The breakpoint inventory was empty and disassembly started with `shr al,3`. Thus this recovery
found a pending single-step exception, whereas the previous recovery found a breakpoint exception.
This is consistent with the requested step's completion arriving after the CPU 2 stop; the
precise event ordering and the reason DbgEng labels it second-chance remain unresolved.

One `qd` sent `DbgKdContinue(10002)`, received the correct ACK, and returned success. KD exited
zero. Unlike the earlier recovery, WinRM then timed out; a bounded TCP 5985 check at 12:01:49
also failed. No debugger process or owner of the hypervisor endpoint remained. The owner then
confirmed the console was still frozen: this recovery failed. No additional connection was made
under that authorization, and no forced termination, reset, reboot, or host configuration change
was attempted.

## Third native recovery: further processor stops, then healthy

The owner separately authorized one connection to inspect the remaining exception before
choosing a resume command. At 12:03:45 KD connected without `-bonc` or an explicit-target poke,
after confirming no debugger process or endpoint owner remained. The trace again contains zero
`Send Break in` lines, with the same synchronization caveat as above.

This connection found CPU 0 at `hv+0x312024`, with a first-chance `0x80000003` breakpoint
exception, an empty breakpoint inventory, and the original six-byte instruction restored.
EFLAGS read `00000246`. One `gh` sent an acknowledged `DbgKdContinue(10001)` and stayed
attached. The next state-change event selected CPU 3 at the same address, also reporting a
first-chance breakpoint exception, empty breakpoint inventory, original instruction, and
EFLAGS `00000246`. No additional single-step was requested.

After inspecting that stop, one `qd` sent an acknowledged `DbgKdContinue(10002)` and KD exited
zero. Independent WinRM readings confirmed the expected guest, unchanged boot identity, and
uptime advancing from `79427.7787338` to `79430.1465458` seconds. The endpoint was free and
no debugger process remained. The owner also confirmed the guest was back. No reset, reboot,
forced termination, processor-count change, or host configuration change was needed.

Across the traced demonstration and its recovery connections, the observed event order was:

| Observation | Processor | Stop |
|---|---|---|
| Initial run-to hit | 1 | Breakpoint at `hv+0x312024` |
| Requested post-hit step returns | 2 | State-change at `hv+0x312024`; `.lastevent` subsequently empty |
| First recovery connection for this run | 1 | Second-chance single-step at `hv+0x31202a` |
| Second recovery connection for this run | 0 | First-chance breakpoint at `hv+0x312024` |
| Same connection after `gh` | 3 | First-chance breakpoint at `hv+0x312024` |

This is evidence for successive stops involving multiple processors, not a requirement
to issue one explicit per-processor resume command. No processor-selection resume commands were
used. It also does not prove that a fixed number of continues will drain all events, or that
reconnection is necessary. Event-aware continuation before detach remains an investigation,
not a production fix; packet ACKs and restored instruction bytes alone were insufficient.
The packet trace establishes event delivery order, not the time each processor originally
trapped. The owner proposed that another processor could encounter a new break after resume;
the observations do not exclude that alternative to previously raised exceptions.

A one-vCPU lab comparison would help isolate the multiprocessor contribution. Microsoft's
[breakpoint documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
states that kernel breakpoints apply to all processors. Avoiding multiple processors reaching
the patched instruction is therefore a reasonable experimental hypothesis, not a measured fix
for this hypervisor build. The VM's processor count has not been changed.

## Static follow-up: recurring callback and conditional debug check

The next investigation used the saved `hvix64.exe` and its existing disassembly only; no live
debugger connection was made. PE timestamp `3152137373`, image size `6393856`, checksum
`2578329`, and the instruction bytes at the breakpoint site match the earlier target readings.
This is metadata and sampled-byte agreement, not a whole-image hash comparison with live memory.
The saved file uses preferred image base `0x140000000`; addresses below are image-relative.

The PE exception directory places `hv+0x312024` inside the function
`[hv+0x311eec, hv+0x3120de)`. That function is registered as a callback, rather than reached
by a direct call to its entry point in the saved disassembly:

| Location | Static observation |
|---|---|
| `hv+0x2908b3` | Loads a context pointer from `gs:[0]`, then initializes an object at context offset `0x29100`. |
| `hv+0x290900` | Stores the address `hv+0x311eec` at context offset `0x29128`, the object's callback slot `+0x28`. |
| `hv+0x312170` | Selects an interval, obtains a time value, then passes the object, time plus interval, and interval to `hv+0x211310`. The time unit is not established. |
| `hv+0x211310` | Records deadline at object `+0x10` and interval at `+0x18`, and inserts the object into an ordered list at context offset `0x28f00`. |
| `hv+0x20fe33` | Compares the first object's deadline with the current time value and removes expired entries. |
| `hv+0x20fe66` | Loads the callback from object `+0x28`; `hv+0x20fe71` calls it with the context in RCX and object in RDX. |
| `hv+0x20fe7e` | Reads the interval after callback return and requeues at time plus interval when nonzero. |

This establishes a recurring deadline-driven callback mechanism, consistent with a per-processor
timer queue. The context is obtained through GS; the exact private structure and function names
are not known. The dispatch function is `[hv+0x20f9d0, hv+0x20ff45)` according to the PE
exception directory. A direct caller exists at `hv+0x2169b2`; its branch compares a dispatch
value against a global at `hv+0x34df0`. This is not yet a complete identification of the outer
interrupt/VM-exit path or evidence of a hypercall-resume path.

Inside the callback, the relevant control flow is:

```text
hv+0x312008  test global enable byte
             disabled -> hv+0x312024
hv+0x312011  call hv+0x29b7f8
             false -> hv+0x312024
hv+0x31201a  ecx = 1
hv+0x31201f  call hv+0x404a60        (int 3; ret)
hv+0x312024  mov al,[hv+0xcb9a8]     (our temporary breakpoint site)
```

The helper at `hv+0x29b7f8` first checks a global byte at `hv+0x34de4`; when set, it clears
the byte and returns true. Otherwise, after another helper succeeds, it calls `hv+0x29cdf8`.
That routine checks transport state and dispatches to `hv+0x29df00` or `hv+0x29f950`.
Both contain receive-result checks for byte `0x62`. Together with the conditional call to the
`int 3` routine, this supports a debug-break polling interpretation; these are inferred roles,
not recovered private symbol names or proof that either branch was taken in the live run.

The important correction to the experiment is that `hv+0x312024` is not reachable only after
the hypervisor requests a break. Both the disabled and false-result branches also reach it.
Our temporary software breakpoint therefore instrumented shared recurring callback code, not
an exclusive return path for the processor we initially stopped. Other processors traversing
that callback could encounter our breakpoint without issuing a new hypercall or a new native
debug-break request. This is a plausible source of the multi-processor stops, not proof of when
each trap occurred or how breakpoint restoration interacted with those processors.

The next discriminating capture should collect caller/return addresses and exception context
for each observed processor, checking for the callback dispatcher return at `hv+0x20fe73`.
That would test the static path against live execution without assuming reliable symbolic
unwinding. A controlled comparison should also avoid treating this recurring callback's return
site as a single-processor breakpoint fixture. Neither follow-up was run in this static pass.

## Live follow-up: initial break reaches the predicted callback

Two bounded captures used the same unmodified server and loaded DbgEng hashes recorded above.
Read-only preflight verified guest identity, launch/debug settings, current debugger address,
key fingerprint, and free endpoint. Neither capture installed a software breakpoint, requested
a single-step, or issued a continue before final detach. Packet logging began after attachment,
so it still does not establish the attach-time break-in packet count.

At 14:03:40, the initial event was a first-chance `0x80000003` at `hv+0x404a60`, with stack
pointer `0xffffe70000405828`. A 128-byte stack read placed `hv+0x312024` at `[rsp]` and
`hv+0x20fe73` at `[rsp+0x30]`. These are the two statically predicted return addresses:
the `int 3; ret` routine returns to the recurring callback, and that callback returns to the
deadline dispatcher. The `+0x30` offset accounts for the nested call's return address, the
callback's saved RBX, and its `0x20`-byte stack allocation; this is not merely a stack scan for
any word inside the image.

The harness next used the documented processor-qualified register command `0r`. It returned
CPU 0's PC and SP, but an ensuing unqualified `read_memory` of that SP failed with `0x8007001e`.
The trace includes a failed virtual-to-physical translation. The register command's processor
scope was not carried into the following memory RPC. A paging-context mismatch is a plausible
explanation, not a proven fault in the target's stack. The harness stopped and detached;
same-boot health passed. This run is a partial capture, not an all-processor success.

The 14:05:20 follow-up deliberately avoided those cross-processor virtual-memory reads. It used
`0r`, `1r`, `2r`, and `3r` for register snapshots and reused only the initial event's stack.
Microsoft documents processor-qualified register inspection in
[Multiprocessor Syntax](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/multiprocessor-syntax).
All four register commands succeeded:

| Processor | Saved PC | Stack captured |
|---|---|---|
| 0 | `hv+0x404c5e` | No |
| 1 | `hv+0x404c5e` | No |
| 2 | `hv+0x404a60` | Yes: callback return at `[rsp]`, dispatcher return at `[rsp+0x30]` |
| 3 | `hv+0x404c5e` | No |

The matching static image places `hv+0x404c5e` immediately after `sti; hlt`, in a short
conditional halt routine ending in `ret`. These are saved processor contexts, not three new
breakpoint events. CPU 2's two return addresses matched the earlier capture exactly. Final
detach advanced CPU 2's PC to `hv+0x404a61`, sent one acknowledged `DbgKdContinue(10002)`,
and exited zero. Independent health confirmed the same boot with advancing uptime and the
endpoint free. No recovery connection was needed for either capture.

The initial debug break is therefore dynamically tied to the recurring callback identified
statically. These observations do not support a requirement to resume every processor after
an ordinary initial break, nor do they establish a hypercall-resume origin. They narrow the
earlier multi-processor-stop investigation toward the temporary breakpoint/step experiment.
They do not determine when the previous CPUs trapped: capturing caller context at those
post-breakpoint stops remains future work. No VM processor-count or host configuration change
was made.

## Harness and remaining work

The existing broader smoke test could not be used unchanged: it selects the default attach path,
calls a nonexistent `breakpoints` tool, and passes `address` rather than `expression` to
`set_breakpoint`. The temporary PowerShell harness used the merged server's current surface,
`execute`/`bl` for the text-only listing, and the returned breakpoint ID for removal.
Its initial stale-call failure is retained above rather than counted as a passing test.

**Those three defects have since been repaired, and the tool the first one named now exists.**
The server grew `breakpoints` and `clear_breakpoints` -- a typed inventory and a typed removal, the
operations this harness could reach only through `execute`/`bl`/`bc` -- and the tier test takes its
attach shape from `WINDBG_MCP_SMOKE_HYPERVISOR_BREAK_ON_CONNECT`, sets its breakpoint by
`expression`, and clears through the typed tool. The breakpoint-hit sequence is behind
`WINDBG_MCP_SMOKE_HYPERVISOR_BREAKPOINT_HIT`, which
[`examples/hypervisor_detach_regression.ps1`](../examples/hypervisor_detach_regression.ps1) refuses
to pass to a guest reporting more than one logical processor. **Nothing above was re-measured**:
that is a repeatable way to run this sequence again, against the same open questions, and no run
of it is recorded in this file.

Both failed demonstrations have now been recovered, with independent same-boot health checks.
Next: investigate post-breakpoint pending-stop handling separately
from the already reported EXIT cancellation failure. Ordinary live-NT `qd` support remains tracked
in [dbgscope #173](https://github.com/glslang/dbgscope/issues/173).

## Local evidence identifiers

- `hypervisor-demonstration-20260920-105411.log`:
  `1EB5ECE58B3F73CD842D00BE8664D635A9B9744974CA213EAC8F29A8411EAF6E`.
- `hypervisor-demonstration-20260920-105459.log`:
  `707874C294C57B40C5980AB75430BA65DF67B251A435A228619058BB18324063`.
- `hypervisor-demonstration-20260920-105620.log`:
  `F716C8E8A1711A28DB53CD9F3CA2E58BB7F8D3E4579C5D61EBB2D52D773AE000`.
- `native-hv-recovery-20260920-110844.log`:
  `DBE73AD10E50B7140F2BF4775A73DC33B798FDEC24A535D606DF451B7B2106CD`.
- `hypervisor-demonstration-20260920-112725.log`:
  `4B41DF1BDE8D3EDFDEDD5FBC8CD4FE443649AD255FDD7CC279FF0F14EE99E5AB`.
- `hypervisor-demonstration-20260920-112725.log.kd.log`:
  `EBB0C5F52BFF152F7D887EF10C7704376CE1297B9E3FA82BD25AF24C3B0483A8`.
- `native-hv-recovery-20260920-120026.log`:
  `F508CA1082799888FCD45A78DDE52DCD1D148466E026F6D44D90791032B33018`.
- `native-hv-recovery-20260920-120345.log`:
  `1F8E0FC37C80CA6566D7345130DF44A794191C3E22DD0B2E909299A55ABF2977`.
- `hypervisor-demonstration-20260920-140340.log`:
  `0A57B1C30C77A0D4E60FC29F076FAAB2B5D7AE4062B2AE2661D84ECC2F6F12C5`.
- `hypervisor-demonstration-20260920-140340.log.kd.log`:
  `52F3484D3589CDE357A08EBE4407F1C43ADC3EFFDF12857FCF6230D44D7D1992`.
- `hypervisor-demonstration-20260920-140520.log`:
  `5FDE2C5D6CDF7A3D4237196E26401FB152742A242EB257BCF4953E58D3418548`.
- `hypervisor-demonstration-20260920-140520.log.kd.log`:
  `458B401A4CA72CCF1969CC21BACA17EE9FE321555F5C0CC3EF12DF9F901B7C9C`.
- Saved `sk-29671-static/hvix64.exe`:
  `AD601A867EA480988EC0B618EABDB6F5D242F00F75D2E6C4B4CD62CB886DBAB1`.
- Saved `sk-29671-static/hv-disasm.txt`:
  `DD72301A9F16394604F8D72FCB2D6CAD65027EC90EE5F7A01B41238BE0657D45`.

These are SHA-256 hashes of the saved local evidence at this checkpoint. The temporary runner is
`target/hypervisor-demo-run.ps1` in the debugger workspace; it contains lab-specific wiring and
is not a portable or committed example.
