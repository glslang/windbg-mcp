# Plan: carry h3probe and its providers in this repository

## Objective

Make this repository the owner of the whole live VTL1 path: the source of `h3probe.sys`, the
register/control provider and the live-memory provider that drive it, and the qualification that
proves them. A client then needs an operator-installed driver, a startup policy and MCP calls, and
nothing else.

[`secure-kernel-lab`](https://github.com/glslang/secure-kernel-lab) (sklab) carries all three
today and becomes an ordinary client. It keeps the
lab: VM provisioning and disk reset, guest triggers, run orchestration, evidence audits and the
driver service's lifecycle. It stops opening `\\.\H3Probe` itself.

**Status, 2026-10-30: written; no phase started.** `FOLLOWUPS.md` item 133 tracks it.

## The decision this reverses, and what it keeps

Item 103 (in `DONE.md`) shipped the live reads as an opt-in feature on a standing decision: **the
repository distributes no driver and the operator supplies the transport.** It is restated
wherever the code and docs meet that boundary:

- `src/livesrc.rs`'s module comment, "Why a subprocess, and why this repository ships no
  transport";
- [`live-control-provider.md`](live-control-provider.md): "The repository ships no driver, private
  VID layout, or provider DLL", and a process boundary that "keeps the private provider out of the
  MCP supervisor";
- this directory's [README](README.md): "The privileged instruments remain outside this
  repository".

Two reasons stood behind it, and only one survives.

**Privacy no longer holds.** The provider, the VID layout and the driver were private because the
bench was. sklab was published on 2026-10-31 with `h3probe.c`, the derivation of its VID memory
operation, and both Python providers. Kept out of this repository now, they buy no secrecy and
cost three things:

- every change to the driver's ABI is two commits in two repositories;
- the startup policy allow-lists a Python interpreter and two scripts;
- the provider this server's documentation describes is one it can only link to.

**The posture still holds, and this plan keeps it.** The
[hypercall feasibility record](secure-kernel-hypercall-feasibility.md) settled that "where a driver
is unavoidable it is **ours, minimal, and test-signed** — the operator reconfigures their machine
either way, and only one of the two is auditable". Carrying the source is the auditable half of
that. Nothing here changes the rest:

- No driver **binary** is distributed, and nothing is signed for anyone. The operator builds,
  test-signs and installs it.
- `windbg-mcp` never installs or starts a driver ([`m8-debugger.md`](m8-debugger.md)).
- The `securekernel` tool group stays `extra`, and nothing live runs without
  `WINDBG_MCP_SK_LIVE_POLICY`.
- **The providers stay child processes.** That boundary was never only about privacy.
  `livesrc.rs` chose a subprocess over a DLL because "a child process that dies costs one read and
  reports why". Every provider line has a 10-second deadline, read off the engine thread
  ([`live-control-provider.md`](live-control-provider.md#process-boundary)), so a provider stuck
  in `DeviceIoControl` cannot pin a worker.
- The two protocols, `windbg-mcp-sk-control/2` and `windbg-mcp-gpa/1`, stay as they are. An
  operator's own provider still plugs in through `transport_commands`.

**One property does change in kind.** `livesrc.rs` says the client half "contains no privileged
code, links nothing". The built-in providers are user-mode code issuing IOCTLs to a kernel driver.
The privilege is in the driver, which the operator installs, but that sentence stops being true of
this binary. It is rewritten in the phase that makes it false, not left to drift.

## Where everything is today

sklab's driver use was inventoried on 2026-10-30 against sklab's tree at `f47aa35`. Every open of
the device in sklab's `src/` goes through one of three places:

| Opener | Control codes it issues |
|---|---|
| `h3_memory.Device` | MEMREAD `0x812`, MEMWRITE `0x813` |
| `bench/h3_vtl1_debug_control.Probe` | RUN `0x800`; CALL `0x804`, used only for `HvCallGetVpRegisters` (`0x50`) and `HvCallSetVpRegisters` (`0x51`) |
| `drivers.open_device` | none: it opens the device and closes it |

Through those handles, `backing.Hypervisor` and the hypercall mode of `bench/guest_physical.py`
add READGPA `0x801`, and `validate.h3-memory` adds VIDTRANSLATE `0x810`.

| What | In sklab today | Driver calls | End state |
|---|---|---|---|
| Register/control provider | `bench/k4_control_provider.py`, launched by this server | RUN, CALL | `windbg-mcp --sk-h3-control` ([Phase 4](#phase-4-the-control-provider)) |
| Live-memory provider, and `live.decode` | `bench/gpa_server.py` over `bench/guest_physical.py`, launched by this server | RUN, CALL, MEMREAD, MEMWRITE; READGPA in hypercall mode | `windbg-mcp --sk-h3-memory`, hypercall mode included ([Phase 3](#phase-3-the-memory-provider)) |
| Coordinates before an open | `bench/run_k3_sk_live.py`, `bench/run_k3_sk_syscall.py`, `_resolve_guard` in the `fault.*` modules | RUN, CALL, MEMREAD | the opener's own discovery, which is `FOLLOWUPS.md` item 129 |
| Post-release audit | `_post_kd_audit`, run by `kd.*`, `validate.kd-post-audit` and M8's `audit` callback; it starts a control provider of its own | RUN, CALL, MEMREAD | an audit entry point here ([Phase 5](#phase-5-name-them-and-give-clients-what-they-used-the-driver-for)) |
| Driver qualification | `validate.h3-memory`, `validate.memory-write` | all of the above, VIDTRANSLATE, and a service stop/start | a gated tier here ([Phase 6](#phase-6-the-drivers-qualification-moves-with-it)) |
| Readiness | `sklab doctor`'s device-open and memory-ABI rows | open, MEMREAD | a probe of the built-in provider (Phase 5); the service, file and hash rows stay in sklab |
| Register reads and writes outside a session | `live.registers` (snapshot, root check), `live.transition`'s VTL1 `LSTAR` and `RSP` force and restore, `validate.vtl-split` | RUN, CALL, MEMREAD | **undecided**: [open question 1](#open-questions) |
| Service lifecycle | `sklab driver start\|stop\|status` | SCM only, no device I/O | stays in sklab |

**The control provider sklab ships does not advertise `active_vtl`.** Without it, `ProviderTriage`
returns `Own` for every event at the dispatcher site (`src/sklive.rs`, `impl EventTriage for
ProviderTriage`), so the triage that carries another VTL's exception natively never runs under it.
The built-in provider answers it, which makes this the one behaviour the port is meant to change.

## Target boundary

### The driver

The driver lives under `drivers/h3probe/` here, as `h3probe.c`, `build.cmd` and a README. It is
moved byte-identical first, with its SHA-256 and sklab's commit recorded, the way sklab recorded
its own import from `exdi-rig`, so that the move and every change after it are separate commits.
The build stays the operator's: Visual Studio Build Tools and the WDK (`build.cmd` defaults to
Build Tools 18 and WDK `10.0.26100.0`), and an optional certificate thumbprint to test-sign.

What that means for packaging, read from the manifests rather than assumed:

- The Claude Code plugin's source is the repository root (`.claude-plugin/marketplace.json`), so
  the driver's **source** reaches every plugin install. It is inert until someone builds, signs
  and installs it.
- The MCPB bundle stages only `windbg-mcp.exe` and `LICENSE` (`.github/workflows/release.yml`), so
  it carries the provider roles and no driver.

The memory operation is pinned to one `Vid.sys` build (`H3_VID_TIMESTAMP`, `H3_VID_SIZEOFIMAGE`)
and answers `identity` on any other. That fail-closed behaviour moves with it, and so does its
cost: a Windows update that ships a new `Vid.sys` stops the live path until the pin is re-derived.
It is a build-bound fact like the `vmwp` dispatcher profile, and the driver's README says so.

### The providers

Two new roles of the same executable, beside `--engine-worker` and `--sk-discover-identity`:

- **`--sk-h3-control`** speaks `windbg-mcp-sk-control/2`.
  - At startup it checks RUN's enabled-VTL set, and reads CR3 when none was asserted.
  - It implements `capabilities`, `begin_arm`, `finish_arm`, `publish_stop`, `held_event`,
    `read_registers`, `release`, and `write_registers`, which is checked against the expected
    value, read back, and rolled back on a mismatch.
  - It adds `active_vtl`.
- **`--sk-h3-memory`** speaks `windbg-mcp-gpa/1`.
  - It implements `SHAPE`, `REFRESH`, `READ` and `WRITE` over MEMREAD and MEMWRITE.
  - At startup it does the identity check and Secure Kernel base discovery that `gpa_server.py`
    does today.
  - It keeps the `HvCallReadGpa` hypercall mode as the negative control.

The ABI is typed Rust beside the source it mirrors: request and answer structs of the sizes the
driver's `C_ASSERT`s pin (40 and 32 bytes for the memory operation), with a version check on every
answer, as `h3_memory.parse_answer` does today. It is not a `dbgscope` method, because nothing here
is DbgEng.

### Naming them in the policy

Today `control_transport` and `live_transport` are command lines matched exactly against
`transport_commands`, and their executable must be an absolute path (`canonical_transport` in
`src/skpolicy.rs`). A built-in provider could be admitted the same way, with the policy naming
`windbg-mcp.exe --sk-h3-control …`.

That is the wrong way, for a reason specific to this server: the provider would be whatever image
the policy names, not the image the worker is running. Under the stdio update procedure in
`.claude/CLAUDE.md`, the running supervisor is the renamed `.stale` file while
`target\release\windbg-mcp.exe` is a newer build. A provider spawned from the path would pair two
builds, and no check compares them: the build identity is checked on `WorkerMessage::Ready`, not on
providers.

**So the recommendation is a reserved name.**

- The policy admits `builtin:h3probe` in a list of its own.
- An opener may pass that name in place of a command line, and so may `--sk-kd-target` and
  `--sk-live --transport`. The field it is passed in selects the role: control or memory.
- The worker resolves it to its own `current_exe()` with the role flag and the discovered target,
  through the same placeholders `expand_target_command` fills today.
- A client still cannot select it unless the operator admitted it.

### What a client calls

Everything a client does goes through MCP tools or an existing CLI role. A role is used only where a
tool would hand a client something it must not hold, which is the rule `--sk-discover-identity`
already follows: it "is a role and not a tool: the session confines the handle to the live-memory
command, and a tool would hand it to an MCP client". No tool takes a raw hypercall code, a VID
handle or an IOCTL.

## Phases

Each phase states its pass condition, its control and when to stop, written before the work.

### Phase 0: freeze the contract

Record what the Python providers do. This is the oracle every later phase is compared against.

1. **A protocol transcript of both providers over one boot.**
   - For `k4_control_provider.py`: every `op` and reply through an M8 open, a stop, a step and a
     release.
   - For `gpa_server.py`: every `SHAPE`, `READ` and `WRITE`, including `NOTPRESENT`, `REFUSED` and
     `identity` answers.
2. **A memory corpus on the same boot, in both source modes.** It is the set `validate.h3-memory`
   already reads: mapped code and data, an all-zero page, RAM holes, the device gap, the end of RAM,
   and an address above 4 GiB.
3. **The `h3probe` image hash and service configuration** the corpus was taken against.

Live memory stays out of Git. The schema and synthetic fixtures go in.

### Phase 1: move the driver

1. Copy `drivers/h3probe/` from sklab byte-identical, and record its SHA-256 and sklab's commit.
2. Build it here.
3. Re-point the `h3probe` service's `ImagePath` at this tree's build.
4. Re-pin sklab's `[drivers] h3probe_sha256`.

- **Pass:** sklab's final acceptance from its `docs/h3probe-only-plan.md` passes against the driver
  built here, with sklab's Python providers unchanged.
- **Control:** the same run against the image built in sklab, so that a difference is the build
  and not the boot.
- **Stop:** if the two builds behave differently, find out why before anything is changed.

Measure here, rather than assume, whether CI can build the driver: try the build on the runner. If
it cannot, the build is an operator step and CI checks the source only.

### Phase 2: harden what is about to be a component of this repository

Four findings, read from the source on 2026-10-30. None of them has been measured.

- **The hypercall pages are shared and unlocked.** RUN and CALL go through one global input/output
  page pair (`g_InputVa`, `g_OutputVa`) with no lock around it. The driver's only locks are push
  locks in the gate-era WHVPART and CHAIN code, around a WinHv table walk. The built-in design runs
  one control provider per VP plus a memory provider, each a process with its own handle, so on a
  multi-VP target concurrent CALLs are the normal case. Add a lock, and a test: N processes reading
  distinct registers at once must agree with the same reads made one at a time.
- **CALL issues any hypercall.** Its doc comment says it "issues Control verbatim", while the
  providers need only `0x50` and `0x51`. Allow-list those two.
- **The device's DACL is whatever `IoCreateDevice` gives it.** There is no SDDL, and every code is
  `FILE_ANY_ACCESS`. Measure the effective descriptor first, then create the device with
  `IoCreateDeviceSecure`, restricted to SYSTEM and Administrators. sklab's checks already require
  an elevated administrator for most of the modules that open it, and Phase 2's acceptance run
  finds any that do not.
- **An unknown control code succeeds with zero bytes.** Answer `STATUS_INVALID_DEVICE_REQUEST`
  instead.

The gate-era codes nothing reaches (`0x802`, `0x803`, `0x805` to `0x80F`, `0x811`) are removed only
after [Phase 7](#phase-7-sklab-becomes-a-client). Until then, an sklab module could still reach one.

- **Pass:**
  - Phase 1's acceptance again;
  - the concurrency test;
  - an open by a non-administrator, refused.
- **Control:** run the concurrency test against the Phase 1 build first. A race that never shows
  there is not evidence that the lock works, so record it as unreproduced rather than as passed.
- **Stop:** if the lock changes timing enough to fail a live gate, measure before relaxing
  anything.

### Phase 3: the memory provider

Write `--sk-h3-memory` in Rust, and run it beside `gpa_server.py` on one boot.

- **Pass:**
  - byte-identical data over the Phase 0 corpus and a bounded random sample of guest RAM;
  - the same failure type for every `NOTPRESENT`, `REFUSED` and `identity`;
  - the same `SHAPE` line;
  - `live.decode` passing in both modes through `--sk-live --transport builtin:h3probe`;
  - with `allow_memory_writes`, a `WRITE` through each provider to the same guarded page, with the
    same readback and restoration.
- **Control:** the Python provider, unchanged, on the same boot. It is the untouched oracle; two new
  implementations that agree with each other prove nothing.
- **Stop:** any disagreement, in data or in failure type.

`livesrc.rs`'s "why this repository ships no transport" comment is rewritten in this phase.

### Phase 4: the control provider

Write `--sk-h3-control` in Rust, with `active_vtl`.

- **Pass:**
  1. The Phase 0 transcript, replayed op for op, gets the same replies, epochs aside.
  2. With both built-in providers, this repository's live tier
     (`a_live_secure_kernel_session_stops_steps_inspects_resumes_and_closes`) and the managed KD
     gate each pass on three fresh boots, every run followed by sklab's post-release audit.
- **Control:** the same runs with the Python providers, interleaved with the built-in runs rather
  than run before and after them.
- **Stop:** an event the Python provider would have held is carried, or the reverse. `active_vtl`
  is the one behaviour meant to differ, and its difference has to be the measured one.

### Phase 5: name them, and give clients what they used the driver for

1. `builtin:h3probe` in the policy, the openers and the two CLI roles, as described above.
2. **An audit entry point** replacing `_post_kd_audit`'s direct reads: the identity, a register
   snapshot, the sentinel reads and the guarded text, all taken through the built-in providers.
   Whether it is a role or a tool follows the rule above: the question is whether anything it
   returns is a handle.
3. **A readiness probe for `sklab doctor`.** `--sk-control-probe` already validates a provider's
   identity, epoch and capabilities. Pointed at `builtin:h3probe`, it answers whether the driver is
   loaded and speaks the expected ABI.
4. **Remove the Python command lines** from `m8-debugger.md`, this directory's README,
   `live-control-provider.md` and the shipped skill.

- **Pass:** sklab's M8 acceptance, run with a policy that names `builtin:h3probe` and no Python
  provider.

### Phase 6: the driver's qualification moves with it

`validate.h3-memory` and `validate.memory-write` test the driver, so they become a gated tier here,
on the same terms as the other live tiers in [`docs/smoke-test.md`](../smoke-test.md). The tier
covers:

- the refusal cases;
- the killed-reader case;
- a service stop and start under load;
- a stale identity after a VM restart;
- VIDTRANSLATE's range map;
- the bounded write and its restoration.

The tier stops and starts the service, not the server, which still never does.

- **Pass:** the tier passes on the same boot as sklab's two modules, so the two can be compared.

### Phase 7: sklab becomes a client

1. Delete from sklab the driver directory and:
   - `h3_memory.py`, `h3_memory_probe.py`, `backing.py`;
   - `bench/h3_vtl1_debug_control.py`, `bench/guest_physical.py`;
   - `bench/gpa_server.py`, `bench/k4_control_provider.py`.
2. Route each remaining use through the map above. What [open question 1](#open-questions) decides
   is ported or retired first.
3. sklab's README provenance points here.
4. Remove the gate-era control codes deferred from Phase 2.

- **Pass:** no `\\.\H3Probe` and no control code anywhere in sklab's `src/`, and its acceptance
  passes.

## Final acceptance

The move is done only when all of these hold, with sklab at its Phase 7 tree:

- the policy admits `builtin:h3probe` and names no interpreter;
- the live tier, the KD gate and sklab's M8 acceptance pass on three fresh boots, each run followed
  by a post-release audit;
- the driver tier passes;
- the `h3probe` service runs this repository's build, and sklab's pin matches it.

## Open questions

1. **Register reads and writes outside a stopped session.** `live.registers`, `validate.vtl-split`
   and `live.transition`'s `LSTAR` force and restore all read or write VP registers while the VM
   runs, outside any live session. This server has no such authority today: every register write
   it makes is inside a guarded session. Either it gains one, bounded by the startup policy as the
   session is, or those modules stay lab experiments and are retired rather than ported. Decide
   before Phase 7.
2. **Whether the plugin should carry the driver source at all.** The marketplace entry's source is
   the whole repository, so excluding `drivers/` is a packaging change of its own, not part of this
   plan.

Two `FOLLOWUPS.md` items meet this one. Item 129's private preps are the "coordinates before an
open" row above, and closing it removes that row's driver use outright. Item 122 (a live session
has no image to resolve against) is unaffected.
