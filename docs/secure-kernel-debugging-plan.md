# Validate software-only Secure Kernel debugging, then integrate the working route

## Handoff status

- **First EXDI attempts; one reset this workspace, 2026-09-23:** the `Kd=` option set is now read
  out of `dbgeng.dll` 10.0.29617.1000: **six** kernel-discovery modes, of which
  **`Kd=VerAddr:<addr>`** takes an arbitrary `KdVersionBlock` address (parsed, range-checked,
  `E_INVALIDARG` on a bad one). That is the mechanism a Secure Kernel bind would use, and it is the
  finding worth keeping. **The `sk!KdVersionBlock` record reported in the entry below is weaker
  than that entry claimed**: mapping `.pdata` and classifying every function that touches its table
  found the readers reached only from EXDI-referencing functions, no KD-transport caller among 91
  such strings, and the `hv`-vs-`sk` selector at RVA `0x42EDE0` with **no callers and its address
  never taken**. So a hypervisor KD session cannot be steered to `sk`, and the record may be
  vestigial; the strong reading is corrected in place. **Registration of the EXDI COM server is a
  real prerequisite** — a plain elevated `kd -kx` with the CLSID absent returns
  `0x80040154 Class not registered` and registers nothing, so the earlier claim that the engine
  self-registers was wrong. **And `Inproc=`, which looks like the way to avoid registering, hung
  this host hard enough to need a reset**; DbgEng warns about exactly that before it happens, the
  60-second kill on the child did not save the machine, and a job object is the bound a retry
  needs. Nothing was left registered, no target was touched, and no BCD or host setting changed.
  For the rig: `ExdiGdbSrv.dll` ships in the WinDbg package, `EXDI_GDBSRV_XML_CONFIG_FILE` points
  the engine at a private config, and the preconfigured **`VMWare`** target is a better x64
  starting point than `QEMU` — but only in the copy of `exdiConfigData.xml` beside the debugger
  binaries (`X64`, 40 registers rather than 66). The `winext\` copy, which is the one this repo
  bundles, has that same entry as **`X86`** with no X64 register block; re-measured 2026-09-24 and
  tabulated in the [transport experiments](secure-kernel-debugging-validation.md#exdi-transport-experiments-and-the-host-reset-2026-09-23).
  This workspace cannot
  host the target — it is a Hyper-V guest with Hyper-V disabled and 10.3 GB free, and **Hyper-V
  exposes no gdbstub** in any case, so a Hyper-V guest cannot substitute for QEMU or VMware. The
  user elected to set up a VMware VM separately, and as of 2026-09-24 that guest exists on the box
  hosting this workspace. What it still needs before E0 can run is in
  [`docs/exdi-stub-plan.md`](exdi-stub-plan.md#where-each-component-runs) — the stub is not a guest
  service and does not listen off-host by default, and VMware sharing a box with Hyper-V raises a
  VBS question that decides whether E2 has a target at all. Working detail is in
  [`docs/exdi-stub-plan.md`](exdi-stub-plan.md); measurements in the
  [transport experiments](secure-kernel-debugging-validation.md#exdi-transport-experiments-and-the-host-reset-2026-09-23).
- **Dispatch identified and the EXDI prerequisite corrected, 2026-09-22:** an offline pass
  re-derived the stub finding from the retained samples and reproduced the recorded break-request
  RVAs in five of the six matrix images; the 29671 image is no longer on this workspace, so its
  row is carried over rather than re-measured. **No `IumpDebugBreakRequestedByVtl1` exists in any
  of the eight images inspected in this pass**, and the absence is structural rather than a gap to
  find in another build: the routine is the handler for **secure call `0x124`**, reached from
  `IumInvokeSecureService` and `IumpInvokeLimitedModeSecureService`, which are the only direct
  branches to it a cross-reference scan of the executable sections finds. A `…ByVtl1` counterpart
  would have no caller, because VTL1 asking itself to break is not a secure call. That scan reads
  direct branches and data references, so it does not exclude an indirect path, and 29671 was not
  re-checked. The body is identical-COMDAT-folded with three unrelated routines, so **a breakpoint
  on that address is ambiguous across four callers** — relevant before anyone arms one live. Of
  the eleven `Kd`-prefixed symbols in each of the six post-26100 images, none is a function; the
  two pre-26100 samples have no `Kd`-prefixed symbol at all. Against that,
  `SkdInitDebuggerDataBlock` populates the debugger data block in full, so SK ships the metadata a
  debugger keys off and no transport to deliver it. For Phase 4 this corrects step 2 below:
  `ExdiGdbSrv.dll` and `exdiConfigData.xml` ship **inside the installed WinDbg package**, so the
  EXDI adaptation layer needs no separate distribution and a backend implements a **GDB stub
  rather than a COM server**, which is what removes the LiveCloudKd dependency. Registration
  remains host setup exactly as that step says — the CLSID in the shipped DLL
  (`{29f9906e-9dbe-4d4b-b0fb-6acf7fb6d014}`) is absent from this workspace's `HKLM` and `HKCU`
  class registrations. `DEBUG_ATTACH_EXDI_DRIVER` is reachable with the features dbgscope already
  enables. *If EXDI is required* below stands, with one correction applied to it: its claim that
  `EngineOp::AttachKernel` carries only `connection` had gone stale, and the second field it now
  carries is precedent for that section’s own advice. One gap it still does not name is that
  `Connection::endpoint` returns `Endpoint::Unknown` for every non-`net:` prefix, which
  `Endpoint::conflicts` treats as conflicting with **every** other kernel endpoint, so
  `Sessions::admit` would refuse an EXDI attach alongside any live kernel session and refuse
  every later one alongside it. That is over-conservative rather than permissive, and it
  breaks the two-session NT-plus-hypervisor workflow already in use here. **Whether DbgEng's EXDI path can be pointed
  at `securekernel` rather than `nt` is still unproven and decides the design.** No live attach,
  reboot, BCD change, host change, EXDI installation or registration followed. See the
  [dispatch and EXDI reassessment](secure-kernel-debugging-validation.md#secure-call-dispatch-of-the-debug-break-request-and-exdi-reassessment-2026-09-22).
- **Publication and host boundary, 2026-09-19:** the user rules out configuration changes
  on the hardened outer host. The next lab direction is a separate nested lab, not a
  scheduler change on that host. Provisioning and capacity remain pending; do not start
  them during publication. Preserve the current investigations and publish an evidence-led
  blog post in `adorior.ai` first, with separate review branches/PRs for the article and
  investigation archive. Native VTL1 attachment remains unsuccessful; no Rust/MCP transport
  implementation or EXDI installation is claimed. Earlier handoff entries below are
  chronological records, not permission to resume their proposed mutations.
- **EXDI host preflight, 2026-09-19:** user-supplied outer-host output reports scheduler
  **0x4 (Root)**, target **4 vCPUs**, exposed virtualization extensions **True**, and
  dynamic memory **True** (startup/max **4 GiB**, minimum **2 GiB**). This conflicts
  with the LiveCloudKd recipe's Classic scheduler, fixed memory, and non-nested target;
  one vCPU is its preferred initial configuration. Microsoft documents Root as the only
  supported scheduler on Windows client hosts. Do not change this shared host's scheduler
  or reboot it implicitly. An isolated Windows Server Hyper-V lab would require a new
  topology/resource decision (nesting was previously deferred), while using this client
  host would require explicit acceptance of the unsupported scheduler configuration and
  host-wide impact. No settings changed. See the
  [host preflight decision](secure-kernel-debugging-validation.md#exdi-host-preflight-and-topology-decision-2026-09-19).
- **Current gate, 2026-09-19:** the offline comparison found the same three stub-like
  debugger routines in five additional exact x64 images: **26100.9457, 28000.2952,
  29617.1000, 29639.1000 and 29648.1000**, matching the 29671 target's behavior.
  A 19041 sample lacked the comparison symbol names and remains unclassified; mismatched
  downloads were excluded. No known-working native SK image was found. Close this native
  investigation as inconclusive for support and unsuccessful for attachment; assess the
  Phase 4 EXDI prerequisites next. The next dependency is a read-only outer-host scheduler,
  target CPU and memory check. No rollback, host installation, security change or reboot
  is authorized by this gate decision. Keep the working NT/HV lab intact until a concrete
  EXDI setup is agreed. See the
  [build comparison and gate](secure-kernel-debugging-validation.md#offline-build-comparison-and-native-route-gate-2026-09-19).
- **Latest target:** the user created a separate Windows 11 Insider **29671.1000** sibling VM.
  Its BCDEdit contains `vsmdebugtype`, Secure Boot is off, TPM is ready, and VBS/HVCI are running.
  The user confirmed a new VBS baseline checkpoint. Ordinary NT KDNET configuration and reboot
  succeeded. An initial two-client native KD attempt coincided with a workspace freeze requiring
  user-forced restart; its queued initial `g` also raced the second client's inspection commands.
  The whole-workspace freeze cause is unconfirmed. A later user-authorized single-MCP-worker
  retry passed attach, registers, disassembly, resume/detach, and advancing guest uptime.
  The negative control subsequently passed, and verified KDNET `-hks` configuration exited 0,
  setting `vsmdebugtype NET` and emitting a separate Secure Kernel endpoint. The target rebooted
  with VBS/HVCI still running. Two bounded post-restart Secure Kernel attach attempts did not
  connect. A subsequent single native KD listener was ready before reboot and also did not
  connect. Post-boot port-50012 packet counters stayed zero; a port-50010 NT positive control
  recorded traffic and passed attach/read/resume. Configuration now passes, but VTL1 attachment
  remains unproven. User-supplied outer-host output confirms build **26200**, extension exposure
  **True**, and VBS opt-out **False** for the new target. Those missing-setting hypotheses are
  ruled out; outer-host compatibility is not established as the cause. Guest VBS and extension
  exposure do not by themselves prove that a nested hypervisor was launched.
  A further pre-boot native attempt coordinated with a user-run capture on the outer host also
  remained unconnected; NT controls passed and all workspace test listeners exited. The supplied
  host trace contains 1,200 NT-only packet snapshots across the Default Switch and both VM
  interfaces, with no recorded hypervisor/Secure Kernel packets or drop events. Target/host
  transport initialization remains to investigate; this does not establish host incompatibility.
  Read-only follow-up found the target's `Microsoft-Hyper-V-Hypervisor` and
  `VirtualMachinePlatform` features disabled, with empty hypervisor Admin/Operational logs.
  Offline inspection found a root-VTL1 debugger initialization failure path in its hypervisor
  image, but no runtime evidence that this path executed. With user approval, the target's
  Hyper-V hypervisor was then enabled, launch policy set to `Auto`, and the target rebooted.
  Event ID 1 confirmed successful hypervisor startup; the separate hypervisor debugger connected,
  read registers, and resumed/detached successfully. NT debugging still passed and VBS remained
  running. Secure Kernel listeners before reboot and after hypervisor detach remained unconnected.
  All test listeners exited and guest uptime advanced. This proves hypervisor debugging on the
  current host/guest pairing, not Secure Kernel attachment; no additional VM was created and
  neither the workspace nor outer host was reconfigured.
  Subsequent read-only hypervisor inspection verified the loaded image identity and found the
  expected Secure Kernel port in runtime configuration. The root VTL1 debugger context existed
  but its active-port field was `0xFFFF`, unlike the initialized VTL0 context. Its internal port
  record contained the expected value. A user-approved early-boot trace then captured the
  activation returns directly: VTL0 **0**, VTL1 **0x1D**. The matching activation routine propagates
  that failure from debug-buffer allocation when its free-page list is exhausted. The temporary
  breakpoint was removed and the target resumed/detached; an NT control passed afterward.
  A subsequent approved experiment increased `hypervisordebugpages` from **1000** to **2000**
  and rebooted. Read-only hypervisor inspection then found the VTL1 active port initialized
  and both debug buffers allocated. This resolved the observed allocation failure, but neither
  the pre-boot Secure Kernel listener nor a post-boot retry connected. NT and hypervisor debugging
  still passed; WinRM responded with VBS/HVCI running. The increased reservation is retained.
  On 2026-09-19, a further boot trace reached the hypervisor's VTL-specific debug-session reset
  path twice for VTL0 and never for a nonzero VTL at the selected, post-guard trace point.
  The first VTL0 request used flags `0xF` and returned 0; its context flag became 1 while
  VTL1's remained 0, with the VTL1 port still active. Breakpoints were removed and both native
  sessions detached cleanly. Two NT controls passed with uptime advancing; the user confirmed
  a responsive console, and WinRM subsequently reported VBS **2**, running services **[2]**,
  and **245.087 seconds** uptime. No BCD setting changed during this trace.
  Next inspect the earlier handler guards and the guest/loader's decision to initiate VTL1
  debugging. The bounded post-guard trace does not prove absence of every VTL1 debug request,
  nor that this build lacks support. See the
  [session-path trace](secure-kernel-debugging-validation.md#vtl-specific-session-path-trace-2026-09-19).
  Offline loader tracing then mapped `vsmdebugtype` to BCD element `0x2500013A` and found
  later setup failures that can leave the loader's SK debugger-type field disabled while
  boot continues. This has not yet been observed live. SK's initialization routine only
  initializes debugger metadata, and its loader-block cleanup prevents treating post-boot
  zeros as the original handoff. That inspection proposed temporary **boot-loader
  debugging**, with BCD backup, one controller, exact-image trace points, and restoration
  of the original boot-debug element afterward; it had not yet been enabled. Final read-only
  checks found VBS **2**, services **[2]**, uptime **1006.203 seconds**, Secure Boot off,
  and BitLocker protection off on encrypted C:. No reboot or BCD change occurred in this
  offline pass. See the
  [loader gate record](secure-kernel-debugging-validation.md#loader-debugger-configuration-gates-2026-09-19).
  The user then approved one boot-loader experiment. It **connected to Windows Boot Debugger
  29671**, but the loader's module-load event continued automatically despite `sxe ibp`;
  no planned trace breakpoint was installed or gate value captured. NT subsequently passed,
  and the temporary `bootdebug` element was removed with the current BCD entry verified
  identical to its saved original. Final WinRM health showed VBS **2**, services **[2]**,
  uptime **174.684 seconds**, and no debugger listener remained. A proposed retry must arm
  an explicit loader module-load break before reboot; this revised filter is untested and
  a second reboot has not been performed. See the
  [boot-loader experiment](secure-kernel-debugging-validation.md#boot-loader-connection-experiment-2026-09-19).
  A subsequent user-approved retry armed both loader-specific and initial-module-load
  breaks, caught the loader, and verified the exact image before installing three
  one-shot trace points. The debug-type gate returned **3**, NET descriptor setup returned
  **0**, and the final configuration block contained type **3** and port **50012**.
  This rules out failure in that configuration block for the traced boot, not later
  initialization or handoff problems. All breakpoints were consumed, the debugger
  resumed/detached, and an NT control passed with advancing uptime. The original BCD entry
  was restored exactly; final WinRM health reported VBS **2**, services **[2]**, uptime
  **184.792 seconds**, and zero debugger listeners remained. Next trace downstream
  consumption/initialization and the earlier hypervisor session guards; no further BCD
  adjustment is indicated by these measurements. See the
  [live loader trace](secure-kernel-debugging-validation.md#live-loader-configuration-trace-2026-09-19).
  Downstream offline inspection then found that this exact SK image's debugger-info
  routine returns three constant zero bytes, its VTL0-requested break routine is
  `xor eax,eax; ret`, and its inspected debugger initialization only writes metadata.
  A read-only ordinary class-237 query returned `STATUS_NOT_SUPPORTED`; resolving NT's
  dispatch proves this status originates in NT without querying SK. The extended probe
  used invalid missing input and establishes no capability result. These findings
  strengthen an image-specific implementation-stub hypothesis, not a universal build
  support claim. The target hash still matches, VBS/HVCI run, and boot debugging stays
  off. No live attach, reboot, or BCD change occurred in this pass. Next compare the
  routines with a known-working image or survey builds offline; further BCD guessing
  is not indicated. See the
  [downstream inspection](secure-kernel-debugging-validation.md#downstream-debugger-implementation-inspection-2026-09-19).
  See the [configuration record](secure-kernel-debugging-validation.md#insider-secure-kernel-configuration-2026-09-18).
- Plan saved 2026-09-12. Implementation began 2026-09-14; the original bench snapshot below is
  historical. See [validation record](secure-kernel-debugging-validation.md) for current measurements.
- Phase 1's on-disk engine and syntax gate passed: WinDbg **1.2606.22001.0**, bundled engine
  **10.0.29617.1000**, and explicit `kdnet.exe -s` support. The release supervisor's loaded engine
  was also verified at **10.0.29617.1000** on 2026-09-18.
- No MCP API was changed. On the earlier Server target, ordinary NT debugging and the Secure
  Kernel negative control passed; native Secure Kernel configuration was attempted and refused.
  No VTL1 attach has succeeded.
  On 2026-09-16 the lab placement changed to a target VM directly on the outer Hyper-V host,
  with this workspace remaining the debugger VM. Hosting the target inside the workspace is
  deferred. The earlier 16 GiB RAM / 100 GiB free-space suggestion applied to that deferred layout.
  On 2026-09-18 the user identified an existing, separate Generation 2 VM to reuse. Verify that
  target's settings and guest VBS state before changing it; creating another VM is unnecessary.
  Initial WinRM inspection confirmed Windows Server 2025 build **26100.33438**, a ready TPM,
  Secure Boot off, and VBS status **0**. After the user exposed virtualization extensions and
  rebooted, VBS became **2**, with memory integrity running. The user confirmed the working-VBS
  checkpoint. Its ordinary KDNET settings match an existing profile. Reusing this
  target changes the original Windows 11 25H2 test baseline; Secure Kernel compatibility is unproven.
- `kdnet -ks` returned **0x80004005**, reporting failure to enable Secure Kernel debugging. It
  partially enabled `hypervisordebug`; that value was removed and the BCD verified identical to
  its backup. After explicit user approval, a direct diagnostic of the utility's
  `vsmdebugtype=3` operation exited 1: BCDEdit did not recognize the element type or consider it
  applicable to the entry. The BCD then matched its backup, VBS remained running, and no reboot
  occurred during that diagnostic. Initially this command was found only in binary strings,
  so treating it as the confirmed failure and moving to EXDI was premature.
  A subsequent standalone `kdnet -h` configuration succeeded, preserving ordinary NT settings.
  The target was then rebooted with a hypervisor debugger listener ready; NET settings persisted
  and VBS remained running, but no hypervisor connection was observed.
  A subsequent user-requested process trace of `-hs` now confirms the utility actually executes
  `bcdedit /set {default} vsmdebugtype 3`, which exits 1, followed by KDNET exiting **0x80004005**.
  Target KDNET matches the updated package by SHA-256; it is not an older copy. BCD was unchanged
  by the trace, and no further reboot occurred. The rejected target-side BCD setting is now an
  observed configuration blocker; minimum supported target builds remain unknown. No EXDI
  installation or MCP API change has begun.
  See the [native experiment record](secure-kernel-debugging-validation.md#native-controls-and-configuration-attempt-2026-09-18).
- A read-only binary survey found `vsmdebugtype` in BCDEdit **28000.1**, **28000.2336**, and
  sampled Insider **29553.1000 through 29667.1000**, but not **26100.1** or **26100.8737**.
  **28000.1 is the earliest positive sample inspected, not a proven minimum supported OS.**
  The original Windows 11 25H2 baseline is therefore not an evidence-backed fix for this failure.
  A different target OS requires a new lab decision; no guest upgrade or system-file replacement
  was performed. See the [build survey](secure-kernel-debugging-validation.md#bcdedit-build-survey-2026-09-18).
- The approach is **setup first**: prove a working lab, then make only the MCP changes the
  successful route requires.
- The preferred route is **native `kdnet.exe -s` against a Hyper-V Generation 2 guest**. EXDI is a
  fallback, entered only through a recorded gate decision, never by drift.
- The ordering is fixed: **update the debugger engine first, then verify.** The bench state below
  shows why that is a precondition rather than a preference.
- Success requires breakpoints, register and memory inspection, single-stepping, and resume inside
  Secure Kernel. Live memory inspection alone is insufficient.

## Bench state, measured 2026-09-13

Measured on the working host rather than recalled. Re-derive these before trusting them: the engine
version is what this plan now turns on, and it is the one fact most likely to have moved.

| Check | How it was read | Result |
|---|---|---|
| Host architecture | `$env:PROCESSOR_ARCHITECTURE`, `Win32_Processor` | x64, Intel Core i7-14700 |
| Installed WinDbg | package name under `C:\Program Files\WindowsApps` | 1.2603.20001.0 |
| Bundled engine | `(Get-Item target\release\dbgeng.dll).VersionInfo.FileVersion` | 10.0.29547.1002 |
| `kdnet.exe` switches | `kdnet.exe -?` from that package | `b`, `h`, `k`, `w`, `-SkipSecureBoot`. No `-s` |
| dbgscope pin | `Cargo.toml` | `59d48a008f87fe2f99370c2a4984117637d1f4a7` |
| `DEBUG_ATTACH_EXDI_DRIVER` | `windows` 0.62.2 sources | Present and reachable |
| Hyper-V | `Get-VM`, `Get-Service vmms` | Management tools not installed |
| Host VBS | `Win32_DeviceGuard` | Not configured, not running |

Three consequences follow, and they set the phase order.

1. **The native route cannot be attempted as the bench stands.** The only `kdnet.exe` present has no
   `-s` switch, and the bundled engine comes from that same release. Phase 1 is a precondition.
2. **x64 is available, but nesting prerequisites remain.** An earlier revision of this plan recorded the working host as ARM64
   and called for relocating to an x64 machine. That architecture objection does not hold here.
   ARM64 stays out of scope as a *support* question, not as a reason to
   move machines. The 2026-09-14 check additionally identified this x64 host as a VM; x64 alone
   does not establish that it can host the proposed nested lab.
3. **The lab does not exist yet.** Hyper-V is absent, so Phase 2 starts from an unprovisioned host.

## Findings

Live Secure Kernel debugging is reported viable without a dedicated hardware probe, and native KDNET
may now make it substantially simpler. This exploration established published capabilities only. It
did not exercise a live target, and nothing in this section has been reproduced on this bench.

Ordinary NT kernel debugging operates in VTL0. Secure Kernel runs in VTL1, whose memory protections
the hypervisor enforces against VTL0. Attaching to NT therefore does not by itself provide Secure
Kernel access.
[Microsoft's VSM architecture](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm)

| Route | Evidence and setup implications |
|---|---|
| **Native Secure Kernel KDNET** | The supplied release notes explicitly add `kdnet.exe -s` configuration support in **WinDbg 1.2606.22001.0**. This is the first route to test, and the switch was confirmed absent from 1.2603.20001.0 on this bench. The notes do not establish minimum target builds, retail-build restrictions, or VM compatibility. [Microsoft release notes](https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/debuggercmds/windbg-release-notes.md) |
| **Hyper-V + LiveCloudKd EXDI debugger** | A documented software-only route supporting Secure Kernel breakpoints and single-stepping. Requires the live debugger distribution, a registered EXDI COM server, symbols, and a compatible Hyper-V configuration. [Maintainer's instructions](https://github.com/gerhart01/LiveCloudKd/blob/master/ExdiKdSample/LiveDebugging.md) |
| **QEMU/KVM or VMware debugger** | Published research demonstrates Secure Kernel debugging through the outer virtual machine debugger. More manual work is involved in locating the image and handling address translation. [2025 research, chapter 4](https://www.cs.ru.nl/masters-theses/2025/J_Jagt___Analysis_of_Windows_Secure_Kernel_security_bugs.pdf) |
| **JTAG/SourcePoint** | An established physical-target alternative requiring compatible hardware. It is unnecessary for the VM routes above. [Vendor's setup guide](https://www.asset-intertech.com/wp-content/uploads/2024/03/SourcePoint-WinDbg-Getting-Started-Guide-for-the-UP-Xtreme-i11-v1.1.pdf) |

"Software-only" here means ordinary virtualization-capable x64 hardware with no specialized debug
probe. The debugger must run outside the Windows instance being stopped, and the two candidate
routes place it differently. Native KDNET puts a debugger process on the host, or on another
machine, talking to the guest over the KDNET transport. LiveCloudKd puts a debugger on the Hyper-V
host reading the guest's memory through EXDI. Say which machine is which when recording results.

### Two switch names that invite a wrong turn

`kdnet.exe` already carries a **`-SkipSecureBoot`** switch, which abbreviates uncomfortably close to
`-s` and has nothing to do with Secure Kernel. It suppresses the Secure Boot checks that otherwise
block enabling debug on a Secure Boot machine. It was present in 1.2603.20001.0, where `-s` was not.
Read the updated binary's own help before typing either one, and record the help verbatim.

The same help offers **`h`** for hypervisor debugging. That is the older hypervisor recipe, and it is
not the Secure Kernel route. Do not infer Secure Kernel ports or BCD switches from it.

## Phase 0: pre-flight, no lab required

Complete. The results are the bench-state table above. The two questions it closed were whether the
EXDI fallback rests on a reachable API, which it does, and which dbgscope revision is actually
pinned. Re-run it if the bench changes.

## Phase 1: update the engine, then read the real syntax

This phase is a **gate**. It needs no VM and should be finished before any lab work.

1. Install WinDbg 1.2606.22001.0 or newer.
2. Re-bundle the engine DLLs beside the server executable, following "Bundling the WinDbg engine" in
   [install.md](install.md). A connected MCP session holds those DLLs open through its workers, so
   replacing them needs the same rename-then-reconnect sequence that `CLAUDE.md` documents for the
   executable itself. Confirm the new `dbgeng.dll` file version afterwards.
3. Run `kdnet.exe -?` from the new package and record the actual `-s` syntax verbatim, along with
   any subcommands it introduces. Do not carry forward the syntax assumed in this document.
4. Record the new WinDbg version, the new engine file version, and the date.

**Gate.** If `-s` is still absent after updating, the native route is closed. Skip Phases 2 and 3
and go to Phase 4, because there is no value in building a VTL1 lab for a switch that does not
exist. Record which version was checked, so the next attempt starts from evidence.

## Phase 2: build the lab

Establish one reproducible lab and record exact OS, debugger, and binary versions throughout.

Before provisioning, follow the selected sibling-VM layout in the
[validation record](secure-kernel-debugging-validation.md#phase-2-entry-condition).
`tools/secure_kernel_preflight.ps1` repeats the package, engine, help, and host checks without
changing boot settings. Its `ready_for_lab` result covers the Phase 1 on-disk gate only.

1. **Verify the outer host.** Inspect its Hyper-V role, management tools, available RAM, storage,
   and virtual switches. It already hosts the workspace VM, but its configuration has not been
   inspected. Hyper-V being absent *inside the workspace* is no longer a provisioning blocker.
2. **Create the guest.** A Windows 11 25H2 x64 Generation 2 guest with fixed memory, Secure Boot, and
   a virtual TPM.
3. **Record the VM's virtualization configuration.** Check `Get-VMProcessor` and `Get-VMSecurity`
   on the outer host. Do not infer extension exposure from Generation 2, or infer a nested
   hypervisor from VBS status alone. Hyper-V can provide memory integrity to Generation 2 guests;
   Microsoft's guest requirements treat nested virtualization separately.
   [Memory integrity in VMs](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#memory-integrity-deployment-in-virtual-machines)
   If the selected experiment requires a nested hypervisor, explicitly expose extensions while
   that guest is off:

   ```powershell
   Set-VMProcessor -VMName <guest> -ExposeVirtualizationExtensions $true
   ```

   The original plan incorrectly described this as a universal prerequisite for guest VBS.
   The older Server target's observed improvement after exposure and reboot is a lab result,
   not proof of that universal requirement. Native Secure Kernel transport requirements on this
   sibling-VM topology still need to be established.
4. **Enable VBS in the guest, then prove it is running.** Configured is not running. Check
   `Win32_DeviceGuard` from inside the guest and record `SecurityServicesRunning` and
   `VirtualizationBasedSecurityStatus`, not merely the policy settings.
   [Microsoft's verification guidance](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
5. **Checkpoint the guest.** Take this checkpoint before any boot-configuration change. Secure-kernel
   debug settings combined with VBS can produce a guest that will not boot, and every later step in
   this plan assumes a baseline exists to restore.

## Phase 3: native route

This phase is a **gate**. Time-box it in bench sessions and record "inconclusive" as an outcome
distinct from "failed", because inconclusive is the result that silently consumes the milestone.

1. **Establish the positive control.** Configure ordinary NT KDNET and confirm a normal VTL0 kernel
   attach works. This proves transport, firewall, and key handling before Secure Kernel enters.
2. **Establish the negative control.** Before secure-kernel configuration, attempt to resolve a VTL1
   symbol and set a breakpoint inside `securekernel.exe`, and record how it fails. Without this, a
   later success cannot be attributed to the configuration change rather than to something
   unrelated that moved at the same time.
3. **Configure Secure Kernel debugging** using the `-s` syntax recorded in Phase 1 and the connection
   instructions the utility emits. Record every boot change it makes and any policy restriction it
   reports. Re-check `Win32_DeviceGuard` afterwards and confirm VBS is still running.
4. **Prove attachment in WinDbg before changing any MCP code.** Load matching Secure Kernel symbols
   and hit a breakpoint inside `securekernel.exe`. A connected debugger, or a loaded PDB, does not
   satisfy this milestone on its own.

**Gate.** On a pass, go to the acceptance criteria and then to integration. On a failure or a
time-box expiry, go to Phase 4 and record the evidence listed below.

**Failure evidence to capture.** A failed milestone is still a useful artifact if it records: the
exact WinDbg, engine, guest and host build numbers; the `kdnet.exe` help and the instructions it
emitted; boot configuration before and after; the `Win32_DeviceGuard` readout; and the debugger's
verbatim error text.

## Phase 4: EXDI fallback

Entered only by a gate decision from Phase 1 or Phase 3. **The working detail for this phase is
[`docs/exdi-stub-plan.md`](exdi-stub-plan.md)**, which carries the staged gates, the stub’s wire
contract and the integration edits; the steps below remain the summary.

1. Restore the guest to the Phase 2 checkpoint.
2. Register an EXDI COM server. **A separate distribution is not required for the GDB-server
   route**: `ExdiGdbSrv.dll` and `exdiConfigData.xml` ship inside the installed WinDbg package
   (measured 2026-09-22), and a backend then implements a GDB stub rather than a COM server.
   Registration is still host setup: the MCP server cannot perform it, and no code change
   removes the requirement. The shipped CLSID is not registered on this workspace.
3. Follow the published configuration: fixed guest memory, one vCPU for the first experiment, Secure
   Kernel scanning enabled, and matching symbols. Keep nested virtualization disabled on the target
   guest where the published Hyper-V recipe calls for that, and note the conflict with Phase 2 step
   3 if both are in play. Record the working host scheduler and EXDI versions.
   [LiveCloudKd instructions](https://github.com/gerhart01/LiveCloudKd/blob/master/ExdiKdSample/LiveDebugging.md),
   [independent reproduction](https://windows-internals.com/secure-kernel-research-with-livecloudkd/)

If neither route passes, finish with the captured failure conditions. QEMU and VMware remain
documented alternatives, and implementing another debugger backend is outside this first milestone.

## Minimum MCP integration

Only the successful route gets built. Locate the integration sites by the file and symbol names
below; re-read them and check the dbgscope pin in `Cargo.toml` before editing. The revision in the
bench-state table is the historical 2026-09-13 measurement, not the current dependency pin.

### If native KDNET works

Try the existing `attach_kernel` tool first, naming the target through a **connection profile**.
Profiles are the machine-local mechanism: the key is resolved on this host and never appears in the
request. See [kernel-profiles.md](kernel-profiles.md).

- `attach_kernel` in `src/server.rs` takes `ConnectionArgs` in the same file, whose
  `connection` and `profile` fields are mutually exclusive, enforced at runtime by `kdconn::select`
  (`src/kdconn.rs`). The `EngineOp::AttachKernel` dispatch arm in `src/worker.rs` already hands the
  resolved string to `attach_kernel_begin`, which reaches `AttachKernel(DEBUG_ATTACH_KERNEL_CONNECTION, ...)` in
  dbgscope. No new public API is planned for this route.
- **Do not use `attach_kernel_local`.** It takes no arguments (`src/server.rs`) and attaches to
  this host's own kernel through `DEBUG_ATTACH_LOCAL_KERNEL`. Local kernel debugging cannot set
  breakpoints, single-step, or control execution, so it can never satisfy the success criteria in
  this plan. The repo already excludes it from the live-kernel test tier on the related ground that a
  frozen local kernel is the host under test.
- Use the same engine build that passed Phase 3.

### If EXDI is required

Add an optional **`transport: "kdnet" | "exdi"`** argument to `attach_kernel`, defaulting to
`"kdnet"`, and preserve the existing connection and profile selectors.

- **Do not name it `backend`.** That term is already taken across this tool surface, where it means a
  heap or pool allocator backend such as LFH, VS, Segment or Large. "kernel" would also be a poor
  label for one arm, since EXDI is kernel debugging too.
- **Prefer a field on the existing op over a new variant.** `EngineOp::AttachKernel`
  (`src/proto.rs`) carries `connection` and `experimental_break_on_connect` (re-read
  2026-09-22), so the transport selection does not exist on the wire yet — and that second
  field is precedent for this advice rather than an argument against it. A new `EngineOp`
  variant would require reviewing three classification methods in that
  file: `is_opener`, `opening` and `target_origin`. `opening` deliberately returns `None` for
  kernel attaches; `is_opener` and `target_origin` explicitly match `AttachKernel`.
  **`target_origin` ends in a wildcard that returns `None`**, so a forgotten arm silently suppresses
  OS questions instead of failing the build. A field on the existing variant keeps all three correct
  by construction.
- The threading path either way is `ConnectionArgs` -> `kdconn::select` and `Selected`
  (`src/kdconn.rs`) -> `EngineOp` -> the `EngineOp::AttachKernel` dispatch arm (`src/worker.rs`)
  -> a new typed dbgscope method.
- Add that dbgscope method as a sibling of `attach_kernel_begin` and `attach_local_kernel_begin`,
  using `DEBUG_ATTACH_EXDI_DRIVER`. That constant was confirmed present in `windows` 0.62.2, the
  version dbgscope pins, so the binding is reachable rather than hypothetical. Follow the house rule
  that a new DbgEng primitive is a typed dbgscope method returning `Result<_, DbgEngError>`, never
  the `execute` text hatch.
  [AttachKernel API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugclient-attachkernel)
- **Less new work than it looks.** `SessionKind::waits_indefinitely` (`src/engine.rs`)
  already treats kernel sessions as indefinite, and dbgscope's `is_live_kernel`
  already counts EXDI as a live-kernel connection for wait-timeout purposes. Classification works
  once such a target exists; only construction is missing.
- **Preserve the redaction invariant.** `Connection` (`src/kdconn.rs`) renders redacted through
  both `Debug` and `Display`, and `expose()` has exactly one call site. An EXDI connection string
  must travel through the same type and must not introduce a second unguarded exposure.

### Either way

- Preserve one worker per session and engine-thread ownership. Reuse existing execution controls
  where the experiment proves they work.
- Check target summaries for NT-specific assumptions. EXDI in particular provides less OS
  information, so NT process, driver, and pool inspection cannot be assumed to transfer.
  [Microsoft's EXDI limitations](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/configuring-the-exdi-debugger-transport)

## Acceptance

In the debugger first, then through MCP.

- Hit a breakpoint such as `securekernel!IumInvokeSecureService`, and verify the stopped instruction
  belongs to the matching Secure Kernel image.
- Read registers and memory, disassemble, single-step, remove the breakpoint, and resume
  successfully.
- Repeat across three guest boots and ten breakpoint and resume cycles.
- Repeat the successful workflow through MCP. Verify that failed-attach cleanup and detach leave the
  server usable, and that a normal detach resumes the guest.
- **Interruption needs care, because part of it is architecturally impossible.** A live kernel attach
  cannot be interrupted; it waits indefinitely, and `end_session` reclaims that session alone. What
  to verify is that interrupting an *overrunning command* mid-session returns a partial result and
  leaves the session usable, and that `end_session` reclaims a parked attach. Model the wording on
  the existing live-kernel tests in `tests/mcp_smoke.rs`, which already pin attach, detach, and
  disconnect-releases-the-session behaviour.
- **A mutating `debug_batch` may be refused rather than broken.** Patching a byte of VTL0 kernel
  memory and restoring it is an existing tier test. The hypervisor may simply refuse the VTL1
  equivalent. Record that as a capability finding, not a test failure.
- For code changes, run formatting, Clippy, unit tests, and the MCP protocol smoke tests, plus a
  separate opt-in Secure Kernel test. Existing NT kernel tests do not establish VTL1 support.

## Deliverables

Each of these has an existing form in this repo. Follow it rather than inventing a new one.

- **Opt-in test.** Tiers live in `tests/mcp_smoke.rs` and are gated inside the test itself. The
  live-kernel tier is doubly gated by `#[ignore]` plus the `kernel_tier()` environment helper, and
  the MessageManager CTF tier is the precedent for stacking a *second* gate on top of the kernel
  gate so an ordinary live-kernel run never assumes the target is installed. Follow that shape, reuse
  the `with_live_kernel_session` helper, and name the new gate here once chosen.
- **Version-pinned setup runbook.** The pattern is `.claude/skills/live-kernel/SKILL.md` for KDNET
  wiring and symbol placement, plus [install.md](install.md) and [kernel-profiles.md](kernel-profiles.md),
  with operating prose added to [smoke-test.md](smoke-test.md) beside the live-kernel section.
- **Redacted validation transcript.** Record with `WINDBG_MCP_TRANSCRIPT` and render with
  `--render-cast`, committing the reviewed `.cast` as `docs/flareauthenticator.cast` does. The raw
  `.jsonl` is gitignored and is as sensitive as the machine it came from, so it is never the
  committed artifact. See [transcripts.md](transcripts.md).
- **Capability matrix.** Which tools are meaningful against a VTL1 target, and which silently answer
  for VTL0 instead. This is the finding most likely to affect users, and it belongs in the
  deliverables rather than in a footnote.
- **Recovery procedure**, derived from the Phase 2 checkpoint and the recorded boot changes.
- Keep keys and machine-specific configuration outside version control. The mechanism already
  exists: profiles resolved from `WINDBG_MCP_PROFILE_*` or `%USERPROFILE%\.windbg-mcp\profiles.json`,
  which lives outside the tree entirely, with redaction enforced by type in `src/kdconn.rs` and
  workers spawned with the profile environment stripped.

## Capability limits and security note

A debuggable Secure Kernel is a weakened VBS boundary by construction. That is the point of the
exercise, and it is also its cost: the configuration this plan produces is for a disposable lab
guest, not for a machine holding anything of value. Verifying that VBS still reports as running
after configuration, as Phase 3 does, confirms VTL1 is present to debug. It does not mean the
guest's protections are intact in the sense a user would assume.

Prior work on `securekernel.exe` in this repo is
[securekernel-export-followup.md](securekernel-export-followup.md), which is static export and CVE
diffing on ARM64. It is a naming neighbour rather than a functional precedent, and nothing in it
establishes any part of live VTL1 debugging.

Hardware purchases, ARM64 support, and general EXDI expansion are outside this initial milestone.
