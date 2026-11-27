# Secure Kernel sessions

The caller's half of the two Secure Kernel session kinds: what a capture session and a live-control
session are, what they admit, and what ending one does. Everything a session of any kind shares —
handles, routing, the four-session cap, reclamation, and the unresolved-controller retention a live
controller is subject to — is in [`docs/sessions.md`](../sessions.md); this page is only what is
particular to these two.

## Secure Kernel captures

`open_sk_capture` opens a **Hyper-V saved state** — a standard checkpoint — and decodes the Secure
Kernel in the guest's VTL1: the page-table root read out of the capture, `securekernel.exe`'s base,
`KdDebuggerDataBlock`, `SkLoadedModuleList` and the loader list it points at. The whole decode comes
back with the open, because a capture is a fixed snapshot: nothing in it changes while the session is
held, so there is nothing for a later call to re-read.

Three things about such a session differ from every other one here, and each is a consequence of the
target being a file:

- **Only its own tools work on it.** `sk_modules`, `sk_read_memory` and `sk_symbol` read the capture;
  every other debugger tool is refused by name. That is not a limitation being enforced for
  tidiness — the engine in that worker holds the Secure Kernel **image on disk** (or nothing at all,
  when the session was opened without `symbols`), so `read_memory` there would read the file and
  report it as the guest's memory, and `registers` would answer about no thread. A tool added to this
  server later is refused on a capture until somebody decides what it would mean for one.
- **Nothing executes**, so there is nothing to resume, step, or break into, and `end_session` closes
  a file. The capture is opened read-only and is never written.
- **A capture with no VTL1 opens and says so.** On a guest with VBS switched off the provider refuses
  the VTL switch by name, and that is the answer to asking rather than a failure: the session opens,
  reports the refusal and the partition's VTLs, and refuses every read against it with the same
  sentence.

`symbols: true` also opens that image in the debugger and loads its PDB, which is what gives
addresses in the session names — in both directions, and rebased onto the base the decode found.
There are no **types**: Microsoft's public `securekernel.pdb` carries no type records, so a structure
in VTL1 is read with `sk_read_memory` and decoded by hand rather than formatted.

What it needs on the host: the Windows SDK's `vmsavedstatedumpprovider.dll`, and the
`securekernel.exe` the guest was running. **No driver, no test-signing, and no Hyper-V role on the
machine reading the file** — a checkpoint copied off the host reads the same anywhere.
[`secure-kernel/README.md`](README.md) is the background, and the capabilities and
limits are recorded there rather than here.

## Live Secure Kernel control

`open_sk_live_control` opens a dedicated control session for selected VTL1 VPs in a running,
disposable VBS VM. The caller supplies a primary `vp` and may add distinct `additional_vps`; every
provider shares the exact VM GUID, discovered partition ID and VTL1 CR3. The caller also supplies
an exact-build adapter profile, a register-control provider command and a live memory transport
command, each of which the server's startup policy must admit. The `vmwp` PID is resolved by the
server from the VM id and CR3 is reported by the register provider, so `vmwp_pid` and
`expected_cr3` are mismatch assertions rather than inputs; the dispatcher address and partition ID
are discovered by the worker only when the profile carries a `discovery` section, which makes
`dispatcher_vnd` and `partition_id` assertions too — a profile without one still takes both as
required inputs. The repository supplies neither privileged provider.
Opening validates the request and the profile and takes the VM's reservation; it starts no
provider and does not change guest execution. The register provider is started, and its declared
identity and capabilities checked, when the first `sk_live_arm` prepares the session — so a
provider that is wrong is refused there, not at open. That arm also pauses the VM,
validates the VM-to-`vmwp` binding, live-memory CR3, guarded instructions and local `vmwp.exe`
build, and proceeds to register or breakpoint mutation only after those checks pass.

Ten tools drive that session after the open:

- `sk_live_arm` saves every selected VP's baseline and installs one to four guarded execution
  breakpoints on each. Each address carries the exact live instruction bytes expected there.
- `sk_live_wait` moves the VM and returns only after `vmwp` holds the exact owned vector-1 event. For
  several providers, it completes the winner's event and proves a VM-wide pause before restoring a
  loser; the returned stop remains pause-backed for the winning VP. Its
  stop record carries the target and event identity, two-read register evidence, guarded instruction,
  accepted next addresses, arm mode and a new opaque epoch.
- `sk_live_break` pauses one naturally armed VP, captures and guards its current instruction,
  installs a transient hardware breakpoint, and resumes into the same bounded event wait. If an
  ordinary `sk_live_wait` is already in DbgEng, the break request wakes only that job; all target
  mutation still runs on the engine thread, and both calls return the same retained stop epoch.
- `sk_live_registers` returns that retained stop record without changing it, and
  `sk_live_read_memory` reads VTL1 virtual memory only while the stop remains held. The memory answer
  is tied to the same epoch and includes its starting GPA.
- `sk_live_write_memory` optionally compares and replaces 1–64 bytes within one mapped page. It
  requires both startup-policy authority and a transport advertising bounded instruction-coherent
  writes. The stop epoch remains held, the original bytes remain rollback-owned, and every path
  which would resume, step, fault or tear down restores and verifies them first.
- `sk_live_step` consumes the current stop epoch, proves the current instruction and its bounded
  destinations, and arms the next trap. Collect that stop with `sk_live_wait`.
- `sk_live_continue_to_breakpoints` atomically replaces the guarded breakpoint set while consuming
  the held epoch, then resumes for another `sk_live_wait`.
- `sk_live_continue_to_software_breakpoints` verifies up to 64 exact instruction guards, patches
  their first bytes with one-shot `INT3`s under a VM-wide pause, and arms the owned event wait.
  The pause and its original absolute deadline remain in force until the immediately following
  `sk_live_wait` installs its `vmwp` breakpoint and starts Resume-VM. This first slice requires
  the processor count cached from Hyper-V during write-enabled target preparation to prove that
  the VM has exactly one virtual processor, preventing an unselected VP from consuming a patch.
  No Hyper-V management query runs while `vmwp` is debugger-stopped. The next vector-3 stop must
  name an owned patch or its exact successor and use the CR3 where that patch was guarded and
  installed. Adjacent patch addresses are refused so those two VID forms cannot be ambiguous.
  Before returning it, the controller treats that sole-VP event as an execution barrier, restores
  and verifies every patch, normalizes RIP to the patch, and converts the event to a VM-wide pause.
- `sk_live_continue` consumes the current epoch, restores the complete saved baseline, clears the
  execution breakpoints and resumes. The session stays open for another arm.

Ordinary debugger tools are refused on this session because its DbgEng target is the host's
`vmwp`, not the guest Secure Kernel. Public epochs are scoped to one controller and every mutating
stopped operation rejects a stale epoch. Reads, guarded memory writes and register writes are
refused while running.

Teardown is fail-closed. A confirmed `end_session` restores every selected VP, completes any owned
event through the native dispatcher, removes the temporary handler, detaches from `vmwp` and leaves
the VM running. If any of that is unconfirmed, `session_status` reports
`live_control_unresolved`, and the worker is never killed for it: not by idle or capacity
reclamation, lease expiry, shutdown or the loss of its supervisor. The worker holds the VM's
reservation itself, so that outlives the supervisor too. The session slot does not: it is the
supervisor's, kept through reclamation and lease expiry while that supervisor runs, and gone with
it — after a shutdown or supervisor loss no server lists the session, and recovery works from the
retained worker, out of band. The unresolved session refuses
further control work and cannot be treated as released. Inspect or discard the disposable VM out of
band before allowing another controller to own it.

The same controller can be driven by an installed WinDbg instead of these tools. `open_sk_kd` opens
it as a session of its own: a serial KD facade over a generated local named pipe, where WinDbg holds
the execution lease and MCP keeps `session_status`, `server_log` and `end_session`, which runs the
controller's normal close. The older `--sk-kd-target` command-line role remains for diagnosis and is
**not** a session — it speaks no MCP, appears nowhere in `session_status`, and ends when the
debugger disconnects or quits, running that same close.
[`docs/secure-kernel/kd-facade.md`](kd-facade.md) has what either can and cannot do.
