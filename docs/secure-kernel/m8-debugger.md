# M8: an ordinary debugger for the Secure Kernel

M8 is complete for the product path. A live Secure Kernel session can now be exposed as an
ordinary DbgEng kernel session, either to the server's generic MCP debugger tools or to an
installed Classic WinDbg/WinDbgX client. The controller remains the owner of VTL1 state and the
debugger remains a KD protocol client; release is not successful until the controller has restored
the guest and the independent audit has passed.

This page is the cohesive operator and architecture guide. The packet-level behavior and bounded
compatibility memory are specified in [the KD facade](kd-facade.md), while the lower-level
provider state machine is specified in [the live-control contract](live-control-provider.md).

## What M8 changed

Before M8, the controller could already stop, inspect, step, resume, read, write, and trace one
VTL1 VP, but those were Secure-Kernel-specific operations. M8 closes the three user-facing gaps:

- `open_sk_debugger` makes the target an ordinary MCP DbgEng session. Generic tools such as
  `modules`, `registers`, `backtrace`, `disassemble`, `set_breakpoint`, `go`, `continue_async`,
  `wait_for_stop`, `break_in`, `step_into`, `dx`, and `execute` operate on the returned handle.
- The facade accepts ordinary non-trace KD continue packets. With breakpoints it uses the
  controller's proved run-to-breakpoint path; without breakpoints it performs a bounded free run.
- `open_sk_kd` and the checked-in launcher give Classic WinDbg and WinDbgX the same target through
  a generated, authenticated local named pipe.

The low-level `sk_live_*` tools remain useful for controller development and exact stop evidence.
They are no longer the normal way to debug the Secure Kernel.

## Process and ownership model

One public composite session represents two workers:

```text
MCP client
    |
    | generic debugger tools, one public session_id
    v
supervisor (no DbgEng)
    |                               |
    | public DbgEng worker          | hidden controller worker
    | one kernel session            | one vmwp debugger session
    v                               v
DbgEng -- private KD pipe --> Secure Kernel KD facade --> VTL1 controller/providers
```

The public worker is a protocol peer, not another target owner. It closes its private KD peer
first during `end_session`; the supervisor then asks the hidden worker to restore debug state,
complete the retained event, detach from `vmwp`, and resume the VM. Only the hidden controller can
report `released: true`.

The external route omits the public worker. `open_sk_kd` returns the same private-pipe connection
to an installed debugger, while MCP retains lifecycle, timeout, recovery, and audit ownership.

## Supported product surface

| Operation | Managed MCP debugger | Classic/WinDbgX | Controller route |
|---|---|---|---|
| Modules and PDB symbols | Yes | Yes | Validated live PE, debugger-data block, and loader list |
| Registers, stack, virtual reads, x64 disassembly | Yes | Yes | Stopped VTL1 context and guarded virtual-memory provider |
| Hardware execution breakpoints | Up to four handles | Up to four handles | DR slots on the selected VP |
| Guarded software breakpoints | Not exposed by the read-only composite | Write-authorized external facade | One-shot INT3 under a proved pause, with exact restoration |
| Fall-through single step | Yes | Yes | Target-assisted TF step |
| CR3-writing step | Yes | Yes | Temporary successor breakpoint and root rebind |
| `g` to a breakpoint | Yes | Yes | Qualified M1 run-to-breakpoint path |
| `g` with no breakpoint | Yes, bounded | Yes, bounded | All slots released; ends at break-in, teardown, or deadline |
| Running break-in | Typed `break_in` | Serial Ctrl+Break | Qualified M2 rendezvous |
| Arbitrary register or memory writes | Refused | Refused | Not part of M8 |
| Multiple processors | Refused | Refused | One selected VTL1 VP is exposed as KD processor 0 |

Branch, call, return, interrupt, exception, `rep` string, and SS-writing instructions are refused
by the single-step path when a trap at the linear successor cannot be proved. NT process and thread
extensions are also outside the facade: Secure Kernel has no NT process/thread model to report.

## Required bench state

M8 is a live target-control workflow. It requires all of the following before an open:

1. An explicitly disposable, running VBS guest with a healthy Hyper-V heartbeat. The qualified K3
   topology uses one VP. Guarded INT3 additionally requires the VM to have exactly one VP.
2. A host view in which the root provider can see that guest's VTL1. On the qualified K3 boot,
   `ExposeVirtualizationExtensions=false`; enabling K3's nested hypervisor removes K3's own VTL1
   from the outer provider view. A nested L2 target uses a different provider topology and is not
   an implicit fallback.
3. A register/control provider and a live-memory provider admitted by startup policy. This
   repository deliberately ships neither privileged provider.
4. An exact-build `vmwp` dispatcher profile, a matching `securekernel.exe`, and a symbol store
   containing the matching `securekernel.pdb` when names and stacks are required.
5. `WINDBG_MCP_SK_LIVE_POLICY` set before the MCP server starts. The `securekernel` tool group must
   also be enabled.
6. An independent trigger for a natural stop. M8 qualification creates and terminates a VBS
   enclave while the facade reports `running`, causing a secure service call through
   `securekernel!IumInvokeSecureService`.

The sibling `secure-kernel-lab` repository turns these requirements into checked configuration,
driver lifecycle, generated policy, trigger, release audit, and exact qualification modules. Its
`docs/m8-runbook.md` is the reproducible bench procedure.

## Exact-build profiles

The dispatcher profile is executable build knowledge, not a convenience file. The opener accepts
one JSON file or a bounded directory catalog and selects exactly one profile whose declared local
`vmwp.exe` path, SHA-256, and `SizeOfImage` match the running host image. Before mutation, the
worker repeats the identity check against DbgEng's loaded `vmwp` module and compares every guarded
site's original bytes.

An M8-capable profile contains:

- the schema, absolute `vmwp_image`, SHA-256, and image size;
- handler registration, unregister, callback, return, cleanup, and discovery RVAs;
- original bytes for every debugger breakpoint site;
- the exact `vid.dll` identity used by discovery;
- event, VP, software-flag, instruction-length, and native-advance layout offsets;
- scratch allocation bounds and handler/callback structure offsets;
- `secure_kernel_kd.build`, the initial guarded instruction RVA and bytes, and the three debugger
  metadata RVAs for the debugger-data list, `KDBG`, and loaded-module list.

This is not a normal `attach_kernel` connection profile from
[`docs/kernel-profiles.md`](../kernel-profiles.md). It contains no KDNET key or network endpoint and
is selected by the live Secure Kernel opener, under `WINDBG_MCP_SK_LIVE_POLICY`'s `profile_roots`.

The profile never supplies live identity. VM GUID, `vmwp` PID, VID partition handle, partition ID,
VTL1 CR3, Secure Kernel base, and boot identity are discovered and cross-checked on the current
boot. Optional values in an open request are mismatch assertions only.

After Windows servicing moves `vmwp`, do not edit RVAs by hand. In `secure-kernel-lab`, derive a
write-once candidate from the last validated profile and both old/new images:

```powershell
uv run sklab profile vmwp `
  --baseline profiles\vmwp-dispatcher-profile-26100.9457.json `
  --old-image C:\images\26100.9457\vmwp.exe `
  --new-image C:\Windows\System32\vmwp.exe `
  --output .state\profiles\vmwp-candidate.json
```

The offline report must show unique guarded-site and function-prefix mappings. Then run the
optional disposable-VM validation with `--live-validate --yes`, review its separate report, and
only then promote the candidate into the source-controlled profile catalog. This process derives a
serviced profile from an already proven baseline; it does not bootstrap an unknown first build.
The reprofiler preserves `secure_kernel_kd` unchanged. That is correct only while the target's
`securekernel.exe` identity/build is unchanged.

When the Secure Kernel image changes, first take a standard unencrypted checkpoint and run the
capture decoder with the new guest image and symbols:

```powershell
windbg-mcp --sk-inspect `
  --vmrs D:\captures\new-build.vmrs `
  --image D:\images\new-build\securekernel.exe `
  --symbols --cross-check --json D:\evidence\new-build-sk-inspect.json
```

Use that record to re-establish the live image identity, debugger-data block, loaded-module list,
symbol build, and image-relative coordinates before reviewing a new `secure_kernel_kd` section and
its initial guarded instruction. The current sklab `profile vmwp` command does not generate that
section. If the Secure Kernel build changes and no reviewed section exists, stop rather than
carrying old RVAs into a new image.

## Startup policy and provider setup

The startup policy fixes authority before a client can select anything:

```json
{
  "disposable_vm_ids": ["51749a1f-f939-44f5-b251-1251ef5b64a3"],
  "transport_commands": [
    "\"C:\\Python313\\python.exe\" \"D:\\sklab\\control.py\" --vm-id 51749a1f-f939-44f5-b251-1251ef5b64a3 --partition-id {partition_id} --vp {vp}",
    "\"C:\\Python313\\python.exe\" \"D:\\sklab\\memory.py\" --vm-id 51749a1f-f939-44f5-b251-1251ef5b64a3 --partition-id {partition_id} --vp {vp} --cr3 {cr3} --vmwp-pid {vmwp_pid} --partition-handle {partition_handle}"
  ],
  "profile_roots": ["D:\\sklab\\profiles"],
  "kit_roots": ["C:\\Program Files (x86)\\Windows Kits\\10"],
  "max_pause_ms": 600000,
  "allow_memory_writes": false
}
```

Paths and complete tokenized commands are canonicalized and compared with the allow-list. An
allowed Python executable cannot be reused with another script or `-c` payload. Provider
placeholders are expanded only from guarded discovery, after the corresponding identity exists.

The current reproducible sklab bench uses one demand-start host driver, `h3probe.sys`, built from
sklab's source. It supplies VTL1 register/control operations, boot-scoped identity, and the direct
guest-physical read/write path through the identity-bound VID partition handle. Sklab's migration
off LiveCloudKd's `hvmm.sys` completed on 2026-10-29, and its final acceptance ran with the `hvmm`
service uninstalled and no process holding `hvlib.dll`.

The service must already be installed and running before `open_sk_debugger` or `open_sk_kd`.
`windbg-mcp` never installs or starts a driver. The sklab runbook records build, signing, service,
hash pinning, and start/stop commands. [`h3probe-provider-plan.md`](h3probe-provider-plan.md)
moves the driver's source, and the providers that drive it, into this repository.

## Open a managed MCP debugger

Start the server with the policy and tool group in its environment, then call:

```jsonc
open_sk_debugger {
  "profile": "D:\\sklab\\profiles\\vmwp-dispatcher-profile-26100.9457.json",
  "control_transport": "\"C:\\Python313\\python.exe\" \"D:\\sklab\\control.py\" --vm-id 51749a1f-f939-44f5-b251-1251ef5b64a3 --partition-id {partition_id} --vp {vp}",
  "live_transport": "\"C:\\Python313\\python.exe\" \"D:\\sklab\\memory.py\" --vm-id 51749a1f-f939-44f5-b251-1251ef5b64a3 --partition-id {partition_id} --vp {vp} --cr3 {cr3} --vmwp-pid {vmwp_pid} --partition-handle {partition_handle}",
  "vm_id": "51749a1f-f939-44f5-b251-1251ef5b64a3",
  "vp": 0,
  "arm_mode": "redirect",
  "connect_timeout_ms": 60000,
  "idle_timeout_ms": 180000
}
```

The result is an ordinary debugger `session_id`. A representative generic-tool sequence is:

1. `set_symbol_path`, reloading only `securekernel.exe`.
2. `modules`; on a redirected initial stop, `registers` and one guarded `step_into`.
3. `set_breakpoint` at `securekernel!IumInvokeSecureService`.
4. `continue_async`; only after it reports running, trigger the guest enclave call.
5. `wait_for_stop`, then `registers`, `backtrace`, `disassemble`, and `step_into`.
6. `clear_breakpoints`, `continue_async`, typed `break_in`, and `wait_for_stop` to exercise the
   free-run rendezvous.
7. `end_session`; require `released: true`, then run the independent same-boot audit.

Issue calls sequentially for this session. Do not send a trigger while the VM is paused during
arming, and do not treat a closed public DbgEng worker as proof that the hidden controller released
VTL1.

## Open an external WinDbg client

`open_sk_kd` takes the same open arguments and returns a typed `connection` such as:

```console
com:pipe,port=\\.\pipe\<generated-name>,resets=0
```

The supported launcher owns open, debugger process lifetime, ordered teardown, and failure cleanup:

```powershell
$env:WINDBG_MCP_SK_LIVE_POLICY = 'D:\sklab\runs\current\sk-live-policy.json'

& C:\workspace\windbg-mcp\tools\launch_sk_kd.ps1 `
  -Frontend Classic `
  -ConfigPath D:\sklab\runs\current\open-sk-kd.json

& C:\workspace\windbg-mcp\tools\launch_sk_kd.ps1 `
  -Frontend WinDbgX `
  -ConfigPath D:\sklab\runs\current\open-sk-kd.json
```

For WinDbgX, name `DbgX.Shell.exe` inside the installed Microsoft.WinDbg package. Do not use the
WindowsApps execution alias: that process can exit while the UI remains alive. The launcher finds
the current package host before legacy `WinDbgX.exe` names when no explicit path is supplied.

A read-only policy maps `bp` handles to hardware slots. A policy with
`allow_memory_writes: true` maps external breakpoint handles to guarded one-shot INT3 patches and
is appropriate only for the one-VP qualification arm. It does not authorize arbitrary writes.

## Qualification

The ordinary CI suite uses fake providers and packet fixtures. Live M8 qualification is opt-in and
must run alone against the disposable target.

The product gate is:

```powershell
$env:WINDBG_MCP_SK_LIVE_POLICY = 'D:\private\sk-live-policy.json'
$env:WINDBG_MCP_SMOKE_SK_KD = 'D:\private\m8-composite-config.json'
cargo test --test mcp_smoke -- --ignored --exact `
  a_managed_secure_kernel_kd_session_is_driven_by_this_servers_own_kernel_attach `
  --nocapture --test-threads=1
```

Its config adds a matching symbol path, breakpoint, host-side trigger command, and post-release
audit command to the ordinary open arguments. Sklab generates this file and both policies; users do
not need the former private scripts.

The completed acceptance evidence is:

- three clean K3 boots;
- the complete generic-tool assertions on every boot;
- 25 bounded free-run/break-in cycles per boot, 75/75 total;
- same-boot, same-`vmwp`, unchanged-text, restored-register, healthy-heartbeat 60-second audits;
- Classic WinDbg and WinDbgX each completing 100 hardware-breakpoint hits;
- Classic WinDbg and WinDbgX each completing 100 guarded-INT3 hits.

External GUI/remote Ctrl+Break and reset-race automation remains non-gating compatibility research.
It is not required to claim M8 complete, and the unsafe automation is not a substitute for the
server-owned typed `break_in` gate.

## Failure and recovery

Every stop has an absolute policy deadline with cleanup time reserved. On timeout, disconnect,
provider failure, malformed packet, or teardown, the controller attempts the same guarded restore
and release path.

- `released: true` is authoritative success.
- A transient `live_control_unresolved` while release is in progress is not the final result.
- A final `recovery_required` or `released: false` retains the worker and exact VM/`vmwp`
  reservation. Do not open a second controller and do not kill the worker merely to make the
  process list clean.
- Preserve the server log and run directory, contain the disposable VM, and use the recorded exact
  identity for recovery or discard.

The post-release audit re-discovers the current boot and VTL1, checks the guarded image bytes,
DR0-DR3, DR7 local enables, TF/RF, recent `vmwp` failures, heartbeat, and process/service residue.
Qualification samples survival immediately, at 30 seconds, and at 60 seconds.

## Source map

- `src/kdtarget.rs`, `src/kdapi.rs`, and `src/kdwire.rs`: KD facade and packet translation.
- `src/sklive.rs`, `src/skdispatch.rs`, and `src/skcontrol.rs`: guarded VTL1 controller.
- `src/engine.rs` and `src/worker.rs`: composite ownership and worker boundaries.
- `tools/launch_sk_kd.ps1`: supported external debugger lifecycle.
- `tests/support/sk_m8.rs` and `tests/mcp_smoke.rs`: exact M8 qualification contracts.
- `docs/secure-kernel/skcall-debugging-roadmap.md`: chronological M8 engineering record.
