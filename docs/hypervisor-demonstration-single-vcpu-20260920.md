# Hypervisor demonstration on one vCPU, 2026-09-20

**The server completed an end-to-end hypervisor debugging demonstration:** inspection, one
single-step, breakpoint creation/removal, an actual temporary-breakpoint hit, and detach followed
by independently healthy guest execution. This is one successful run on one vCPU, not validation
of general multiprocessor teardown or Secure Kernel debugging.

The owner changed the disposable VM from four virtual processors to one and started it before
this run. Both guest management and the attached hypervisor reported one processor. The earlier
[four-vCPU investigation](./hypervisor-demonstration-20260920.md) remains tracked in
[windbg-mcp #355](https://github.com/glslang/windbg-mcp/issues/355) and FOLLOWUPS.md item 93.

## Measured configuration

- Run began at 14:13:52 local debugger time (UTC+1).
- MCP initialize identity: `0.18.0+g0ae56496`, source
  `0ae564969822afa832fac2b39911c3b7c0f3247a`, unmodified.
- Executable SHA-256:
  `150BE90567829D4C2F915B7A17A6F1C0A5E96D18A50C18BDEF9AAFDB7773B9D1`.
- Locked dbgscope: `1767cf2c151d8375aa447b854919edb9f9afd2b3`.
- Worker-loaded AMD64 DbgEng: `10.0.29617.1000`, SHA-256
  `4352756685E7325288E54ABB3281E768637987517BE8575EC4450E4B4421842F`.
- Hypervisor 29671, one processor; `hvix64.exe`, image size `6393856`, timestamp `3152137373`,
  checksum `2578329`, no hypervisor symbols. The image base changed after the owner's restart;
  the harness derived addresses from the current module and stack, not a previous absolute address.

The documentation branch had advanced beyond the measured executable; the binary was not rebuilt
or replaced for this demonstration. Read-only preflight verified the guest identity, launch/debug
settings, current debugger address, key fingerprint, and unowned endpoint. Attachment used a
machine-local profile and `experimental_break_on_connect: true`.

## Demonstrated operations

| Operation | Observed result |
|---|---|
| `modules`, `registers`, `read_memory`, `disassemble` | Hypervisor image identified; registers and instruction bytes read; instructions decoded without symbols. |
| `step_into` | CPU 0 moved from `hv+0x404a60` (`int 3`) to `hv+0x404a61` (`ret`), without timeout or interruption. |
| `set_breakpoint` and explicit removal | Breakpoint ID returned, removed by that ID; `bl` confirmed an empty inventory. |
| `run_to_address` with a 5000 ms budget | Returned `verdict: hit` at the stack-derived return address `hv+0x312024`. |
| Hit verification | Packet trace selected CPU 0 of 1; debugger printed `Breakpoint 0 hit`; `.lastevent` reported `Hit breakpoint 0`; register PC matched. |
| Temporary breakpoint cleanup | `DbgKdRestoreBreakPoint(1)` returned success; subsequent `bl` was empty. |
| `end_session` | Returned `released: true`, `target_left_running: true`; acknowledged `DbgKdContinue(10002)`; supervisor exited zero. |

There was no extra post-hit single-step, manual recovery connection, fixed-count continue loop,
forced debugger termination, assistant-initiated reboot, or host configuration change.
Packet logging began after attachment, so this run does not establish the attach-time break-in
packet count.

## Independent guest health

Guest uptime before attachment was `219.6737893` seconds. After detach, two WinRM observations
reported `221.4133363` and `223.7673362` seconds, with the same boot identity and one logical
processor throughout. The hypervisor endpoint was free after release. Thus this result does not
rely only on the debugger's detach status.

This establishes that the measured server can inspect, step, hit a breakpoint, and detach from
this one-vCPU hypervisor lab with a healthy postcondition. It does not prove that one vCPU alone
caused the difference: the owner restarted the target to change its topology, and the earlier
extra-step run had additional differences. The multiprocessor follow-up remains open.

## Local evidence

Raw logs remain local and are not public attachments. SHA-256 identifiers:

- `hypervisor-demonstration-20260920-141352.log`:
  `0C341051ECC6678A16BD64BE7A50784512742F7659FE8A78731C58CFFA5510ED`.
- `hypervisor-demonstration-20260920-141352.log.kd.log`:
  `76220444AE31C45D5E68F64B9B72F87CCD308C6F2F52B8F40F1CBFEE74B568F9`.

The temporary local harness passed Windows PowerShell 5.1 parsing and ran with
`-BreakpointHit -ExpectedProcessors 1`, exiting zero. Its machine-specific wiring remains
uncommitted; this is a recorded demonstration, not a new portable regression test.

**The sequence is a committed one since 2026-09-20**, in the hypervisor tier behind
`WINDBG_MCP_SMOKE_HYPERVISOR_BREAKPOINT_HIT` and driven by
[`examples/hypervisor_detach_regression.ps1 -BreakpointHit`](../examples/hypervisor_detach_regression.ps1),
which reads the processor count over WinRM rather than taking it as a parameter and refuses the
gate above one. That makes this run repeatable; it does not make it a second measurement, and
nothing on this page was re-taken.
