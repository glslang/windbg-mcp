# Feasibility test plan: reading a guest's VTL1 from the root partition

The question this answers is narrow and falsifiable: **can a root-partition component read a
guest's Secure Kernel state well enough to drive a debugger?** It is not a plan to build one.
Every gate below can fail, each says how, and the stop conditions are written before the work
starts so that a sunk cost does not decide.

**Answer, as of 2026-09-26: probably yes, but not with the hypercall the plan was built around.**
The two halves of the route need different mechanisms, and only one of them is documented.

- **Registers: granted.** H3 passed — `HvCallGetVpRegisters` returns a child's **VTL1** `CR3` to the
  parent, on a documented, parent-callable hypercall.
- **Memory: refused by the hypercall, reachable by a driver.** H4 measured `HvCallReadGpa`
  (`0x0053`) refusing a VBS guest's VTL1-protected pages — 4608 protected pages against **0** in a
  VBS-off control — and it refuses them as `HV_STATUS_SUCCESS` with a per-access `ReadIntercept`
  and zeros, so a consumer checking only the status sees silent zeros exactly where the protected
  memory is. It is not a permission to be found: `HvCallReadGpa` has no VTL parameter to ask with.
  **But an independent oracle then read three of five of those same ranges** from the root by a
  direct-mapping route, so the withholding belongs to that hypercall rather than to the root's
  access. The VTL1 `CR3` page itself is not yet among the pages recovered.

Gates H0, H1 and H3 passed; H2 failed with a known cause; H4 is a negative **about the instrument**,
narrowed by the oracle in the revised section below; H5 was never reached.

This is a sibling of [`docs/exdi-stub-plan.md`](exdi-stub-plan.md) rather than a replacement. That
document's route reaches SK through a GDB stub and needs a hypervisor that exposes one; this route
reaches it through hypercalls and needs the Hyper-V already present. The two share E4's integration
work and share the EXDI activation problem E0 found.

## What is already established, and what is assumed

Carried in from work recorded elsewhere, so that no gate re-derives it and no gate rests on it
silently:

| Fact | Where from | Standing |
|---|---|---|
| SK ships no KD transport; every `Kd`-prefixed symbol in post-26100 `securekernel.exe` is data | exdi-stub-plan, 2026-09-22 | measured |
| `SkdInitDebuggerDataBlock` fills `KdDebuggerDataBlock` completely — `KDBG`, size `0x3A8`, `SkLoadedModuleList`, PTE swizzle bit | exdi-stub-plan, 2026-09-22 | measured |
| `Kd=VerAddr:<addr>` is parsed and range-checked, mode 3 of six | exdi-stub-plan E1, 2026-09-22 | measured |
| DbgEng's `sk` record is EXDI-gated and its selector unreferenced | exdi-stub-plan E1, 2026-09-23 | measured |
| The hypercall surface is VTL-parameterised — `HV_INPUT_VTL`, `HV_TRANSLATE_GVA_INPUT_VTL_MASK` | header survey, 2026-09-25 | measured |
| EXDI activation stalls on this bench; registration is surrogate-hosted | exdi-stub-plan E0, 2026-09-25 | measured |
| `HvCallGetVpRegisters` is documented as callable **by the parent** of the target partition, and carries a `TargetVtl` | TLFS, H0 2026-09-25 | measured |
| CR3 is **VTL-private** state, so a VTL1 CR3 is a real and distinct value to ask for | TLFS VSM, H0 2026-09-25 | measured |
| VBS defends a guest's VTL1 from that guest's VTL0, not from its host | architecture | **partly false** — H4 measured the hypervisor defending VTL1 *memory* from the host too |
| The hypervisor permits a parent to name a child's **VTL1** specifically | H3, 2026-09-26 | measured — **for registers**; `HvCallGetVpRegisters` returned a child's VTL1 `CR3` |
| The hypervisor **refuses** a parent a child's VTL1 **memory** | H4, 2026-09-26 | measured — `HvAccessGpaReadIntercept` and zeros, 4608 protected pages against 0 in a VBS-off control |
| `HvCallReadGpa` = `0x0053`, `HvCallWriteGpa` = `0x0054`; read/write pairs are **adjacent** call codes | `hvgdk.h` + H3/H4 behaviour | measured — corroborated on this build at four call codes |
| `HvCallReadGpa` moves at most **16 bytes** per call and carries **no VTL field** | H4, 2026-09-26 | measured |
| `HvCallTranslateVirtualAddress` is parent-callable and VTL-parameterised | — | **assumed, and less documented than the register read** |

## Two disciplines that apply throughout

**Clean-room.** LiveCloudKd is GPL-3.0. *Running* it is unrestricted and it is used below as an
oracle; **linking to or deriving from it is not**, and no gate's implementation may be written from
its headers or source. Implementation facts come from Microsoft's published TLFS and VSM
documentation. Keep that tree closed while writing code, and note in the commit which document a
structure came from.

**A gate without its control is not evidence.** An SK failure and a rig failure are
indistinguishable from the calling side — this is the lesson the EXDI plan already carries, and it
applies harder here because a wrong answer often looks like a plausible number rather than an
error. Every gate below names a control, and a control that has not passed invalidates the gate
above it rather than merely weakening it.

## H0 — does the specification permit it at all

Desk work. No hardware, no guest, no code. Hours rather than days, and it can kill the route.

Read the TLFS on `HvCallGetVpRegisters`, `HvCallTranslateVirtualAddress`, `HvCallReadGpa`, the
`HV_INPUT_VTL` input field, and the partition privileges gating them (`AccessVpRegisters`,
`AccessGpa` and neighbours). The question is whether a *parent* partition may name a **child's**
VTL1 in those calls, or whether VTL1 register access is reserved to the VP itself and to higher
VTLs.

- **Pass:** the specification describes a permitted path, and the privileges it requires are ones a
  root partition holds or can be granted.
- **Fail:** the specification reserves VTL1 state. The route is then not dead but is much more
  expensive — it falls back to physical-memory scanning plus reimplementing SK's swizzled
  page-table walk, and should be re-costed rather than continued into.
- **This gate cannot pass on its own.** A documented interface is evidence of a code path, not of
  what a given build permits at runtime — the same distinction that made an earlier revision of the
  EXDI plan claim DbgEng self-registers. H0 decides whether H3 is worth building for; only H3
  answers it.

### H0 result, 2026-09-25: pass, and H3 is worth building for

Read from the TLFS on Microsoft Learn — `tlfs/hypercalls/hvcallgetvpregisters`,
`tlfs/datatypes/hv_input_vtl`, `tlfs/vsm`, `tlfs/hypercalls/hvcalltranslatevirtualaddress`.

**The pivotal call is documented as parent-callable.** `HvCallGetVpRegisters`, call code `0x0050`,
states under *Restrictions*:

> The caller must either be the parent of the partition specified by PartitionId, or the partition
> specified must be "self" and the partition must have the AccessVpRegisters privilege.

Two things follow. A parent may read a child's VP registers at all, which is the premise the route
rests on. And **the `AccessVpRegisters` privilege is attached to the *self* case** — being the
parent is itself the authorization in this text, so the privilege is not obviously the gating
factor for our caller.

**It is VTL-parameterised, and the register we want is VTL-private.** The input carries `TargetVtl`
at offset 12, and `HV_INPUT_VTL` is `TargetVtl : 4` with `UseTargetVtl : 1`, documented as "allows
specifying a target virtual trust level for hypercall operations that operate across VTL
boundaries". The VSM page lists **CR3 among the private registers** each VTL maintains — so a VTL1
CR3 is a genuinely distinct value rather than the VTL0 one under another name, and H3's pass
condition is meaningful.

**The prohibition in the VSM page does not by its terms cover a parent.** It reads *"Software
running at a lower VTL cannot access the higher VTL's private virtual processor's register state"*
— a rule about software **within** a partition. A parent partition is not a VTL of its child, and
the hypercall's own restriction text contemplates exactly that caller.

**What H0 did not establish, and H3 must.** No TLFS text says a parent may name a child's **VTL1**
specifically; what was found is the absence of a prohibition, which is not permission. That
distinction is the whole reason H3 exists and it should not be softened on the strength of this
reading.

**And one design consequence, which is the useful part of a pass.**
`HvCallTranslateVirtualAddress`, call code `0x0052`, takes a `PartitionId` and `VpIndex` and an
opaque 8-byte `HV_TRANSLATE_GVA_CONTROL_FLAGS`, but its page documents **no Restrictions section at
all** and does not expand those flags — so parent-calling and VTL selection are *not* established
for it to the standard the register read reached. **H4 must therefore not assume the hypervisor
will perform the VTL1 translation**, and should carry the swizzled page-table walk as its expected
cost rather than its fallback. That raises H4's estimate and lowers the risk of discovering it
late.

## H1 — a target that actually has a Secure Kernel, and a control that does not

Build **two** guests, identical but for VBS. The second is not optional: it is the control for
every gate after H2, and without it a plausible-looking read cannot be told from a real one.

- **Pass:** in the VBS guest, `Win32_DeviceGuard.VirtualizationBasedSecurityStatus` is `2` from
  inside that guest, `SecurityServicesRunning` is non-empty, and `securekernel.exe` is present on
  disk with a build recorded.
- **Control:** the second guest reports `0` and runs no secure services.
- **Record the build of both**, because every later comparison against an on-disk image depends on
  knowing which image.

**Resolve one tension before building, not after.** The target needs VBS so that a Secure Kernel
exists, and LiveCloudKd — the H2 probe and the H4 second oracle — reports that it wants nested
virtualisation **disabled** on the guest. Whether those conflict depends on something the
validation record already flags and this plan should not assume either way: exposing
virtualisation extensions to a VM "enables the nested-hypervisor route, **not** a universal
prerequisite for Hyper-V guest VBS". So the two may be independent knobs, or enabling VBS may drag
nesting in with it. Settle it on the first guest, cheaply, before building the pair: turn VBS on
**without** `ExposeVirtualizationExtensions` and see whether
`VirtualizationBasedSecurityStatus` reaches `2` from inside. If it does, the knobs are independent
and the oracle stays usable. If it does not, the oracle and the target are in conflict on this
host, and H2 falls back to writing the driver rather than probing with someone else's.

Topology is decided by the constraint that the debugging component runs on the **Hyper-V host of
the target**: the host of these two guests is the machine the rest of this plan runs on.

### H1 result, 2026-09-25: the two knobs are independent, and the oracle survives

**VBS and nested virtualisation are separate settings on this host, which is the answer the tension
above needed.** A Generation 2 guest, configuration version 12.0, 2 vCPU, 4 GB static memory, vTPM
enabled and `VirtualizationBasedSecurityOptOut` false, was built with
**`ExposeVirtualizationExtensions = False`** — confirmed from the host, which is the authoritative
side — and reports from inside:

```text
VBS=2 Running=2
```

So VTL1 is active *and* HVCI is running in a guest whose nesting is off. LiveCloudKd's requirement
that the guest have nested virtualisation disabled therefore does not conflict with the target
having a Secure Kernel, and the oracle remains available to H2 and H4 on this host. Guest build
**10.0.26200**, x64, recorded because H4's comparison against the on-disk `securekernel.exe`
depends on knowing which image.

**Read the two fields as separate facts.** `VirtualizationBasedSecurityStatus = 2` says VTL1 is up
and `securekernel.exe` is loaded; `SecurityServicesRunning` says what is using it, and it read
**`0`** on the first pass — VBS running with no service behind it. That state passes every gate
here, since VTL1 exists and has a CR3 either way, but it is a thinner target than the subject of
study: HyperGuard and SKPG are what make VTL1 interesting and they arrive with HVCI. Turning on
Memory Integrity and rebooting moved it to `2`.

**Two traps this gate produced, both worth carrying forward.** The `Secure System` process is
present whenever VBS runs and says nothing about which services are active, so it cannot stand in
for the `SecurityServicesRunning` reading — it was sampled twice, identical but for a working set,
and neither sample distinguished the two states. And **both the guest and the host now report
`VBS=2`**, so a bare status reading cannot be attributed to a machine: every VBS reading in this
plan is taken with `$env:COMPUTERNAME` beside it, which is what caught the first one.

**An asymmetry that matters for H2.** The debugger host — the Hyper-V host of this guest — is
itself running VBS with **HVCI**, while the guest was not until it was turned on. HVCI blocks
drivers signed with revoked certificates, which is what LiveCloudKd's `hvmm.sys` is. So on this
host the oracle's default driver path is blocked by the very feature under study, and
`ReadInterfaceWinHv` moves from *preferred first probe* to *the only one that does not require
weakening the debugger host*. Disabling HVCI here remains possible and would become a condition of
every measurement taken afterwards, so it is recorded rather than assumed away.

**H1 complete, 2026-09-25.** The control twin was cloned from the target *after* pinning, so both
are on the same build by construction rather than by two separate acts of configuration:

```text
TARGET   DESKTOP-PR0QOQF   VBS=2  Running=2  Secure System present
CONTROL  LAB-VBSOFF        VBS=0  Running=0  Secure System absent
```

Both are Generation 2, Secure Boot on with the `MicrosoftWindows` template, vTPM enabled, 2 vCPU,
4 GB static, nesting off, build **26200.9457** with `securekernel.exe` and `ntoskrnl.exe` both
**10.0.26100.9457**, and both have `wuauserv` disabled with `NoAutoUpdate=1`. The single difference
is `VirtualizationBasedSecurityOptOut` on the VM. Each is checkpointed.

**The control's guest OS is still *configured* for HVCI**, reporting `Configured=2` while
`Running=0`, and that is deliberate. Turning HVCI off inside the control as well would have made
the twins differ in two ways, and a later failure could then be attributed to either. Leaving the
guest configuration identical means the only variable is whether the hypervisor grants VBS at all.

**Three procedural notes, each of which cost something to learn.** A clone reports its parent's
computer name, so the control was renamed before any reading was taken from it — without that,
`$env:COMPUTERNAME` attribution silently fails in exactly the situation it exists for. A live
export carries saved state, so the copy had to be cold-booted rather than resumed, since resuming
would have restored a VTL1 that the opt-out is supposed to prevent. And `Import-VM -GenerateNewId`
requires `-Copy`, which preserves the source VHDX filename — so the destination must be a folder
that does not already hold the original's disk, and the copy costs a second full-size allocation
rather than none.

## H2 — can the root read the guest's physical memory at all

Foundational, and independent of every VTL question. If GPA reads do not work, nothing after this
matters.

Two mechanisms, cheapest first:

1. **`winhvr.sys` as it stands**, which LiveCloudKd's `ReadInterfaceWinHv` suggests is sufficient
   for some operations. Probe with LiveCloudKd configured to that method — running it is licence-
   safe and answers whether the route exists on this Hyper-V build before any driver is written.

   The configuration is a registry key, read from the tool's own published schema
   (`cfg/HvlibSettingsEditor/config.json`, 2026-09-25) rather than inferred — under
   `HKLM\SOFTWARE\LiveCloudKd\Parameters`:

   | Value | Set to | Why |
   |---|---|---|
   | `ReadMethod` (dword) | **2** = `ReadInterfaceWinHv` | default is `1`, the driver; `2` needs none, so HVCI on the debugger host does not apply |
   | `WriteMethod` (dword) | **2** = `WriteInterfaceWinHv` | same, and the gate needs no writes — set it so a stray write cannot silently take the driver path |
   | `VSMScan` (bool) | `1` (its default) | "Virtual Secure Mode scan" — the VTL1 discovery this gate is about, already on by default |
   | `LogLevel` (dword) | `3` | maximum diagnostics; a probe's value is in what it says when it fails |

   **Set `ReloadDriver` to `0` and confirm no driver service was created**, because the pass
   condition for this step is *"read guest memory with no driver loaded"* and a tool that quietly
   falls back to loading one would satisfy the reading while destroying its meaning. Check for the
   service afterwards rather than trusting the setting.

   **Result, 2026-09-26: the driver-free path does not exist in this tool.**

   Probed through the release's own Python SDK over `hvlib.dll` — running it, not deriving from
   it — with `ReadMethod = WriteMethod = 2` (`ReadInterfaceWinHv`, confirmed from the shipped enum),
   `ReloadDriver = False`, `LogLevel = 3`. `hvlib.dll` loaded and `SdkGetDefaultConfig` answered, so
   the library itself works. Then:

   ```text
   SdkEnumPartitions        -> 0 partitions (with two guests running)
   hvmm service             -> ABSENT before, created during the call, failed to start
   CodeIntegrity 3077       -> hvmm.sys "did not meet the Authenticode signing level
                               requirements or violated code integrity policy"
   CodeIntegrity 3004       -> "unable to verify the image integrity ... file hash could
                               not be found on the system"
   SCM 7045 / 7000          -> service installed, then failed to start
   ```

   **`SdkEnumPartitions` installs the driver regardless of the read method and regardless of
   `ReloadDriver`.** So the WinHv setting selects how memory is *read* and does not make the tool
   driver-free: enumeration is gated on `hvmm.sys` loading, and on an HVCI host it does not. The
   zero partitions is a downstream symptom of the blocked load rather than an independent result,
   and `NestedScan` — false by default and plausible on a nested host — was never reached as a
   variable. `hvlib` removed the service after the failed start, leaving no residue.

   **What this does and does not establish.** It establishes that **the oracle is unusable on a
   host running HVCI**, which this debugger host is, and that the conflict predicted from the
   driver's revoked certificate is real rather than theoretical. It does **not** establish anything
   about whether `ReadInterfaceWinHv` can read guest memory once a partition handle exists — that
   path was never exercised, and cannot be without enumeration succeeding first. Treat "WinHv needs
   no driver" as untested rather than disproven.

   **A driver of our own has no distribution story, and that reorders the backends rather than
   just costing one.** Microsoft will not WHQL-sign a driver whose purpose is handing user mode a
   read of memory it could not otherwise reach; a driver that got signed anyway would be a
   candidate for the vulnerable-driver blocklist later. So any such driver is test-signed,
   self-signed, or admitted by an enterprise code-integrity policy — each of which means the
   operator reconfigures their machine, and none of which ships. **That makes it a research
   capability and not a feature**, however well it works.

   **The oracle ships both answers to that wall, and the second one is worth naming so it is not
   re-derived as a good idea.** Beside the revoked-certificate `hvmm.sys`, `MEMORY_ACCESS_TYPE`
   carries `MmAccessRtCore64`, and `hvlib.dll` contains the string `RTCore64` twice — MSI
   Afterburner's driver, whose CVE-2019-16098 gives arbitrary physical read and write to any caller
   that can reach it. That is the bring-your-own-vulnerable-driver route: if you cannot get signed,
   ride something that already is.

   **This plan does not take it**, for reasons that are practical before they are anything else.
   RTCore64 is on Microsoft's vulnerable-driver blocklist and HVCI refuses it by name, so it fails
   on exactly the hosts where a bypass would be wanted — the same wall as `hvmm.sys`, reached by
   another road. It is among the most closely monitored binaries in existence, so EDR flags it and
   a blocklist update breaks it. And the asymmetry runs the wrong way: a purpose-built driver needs
   to issue *specific hypercalls against a named partition*, where RTCore64 hands arbitrary
   physical memory to anyone who asks. Avoiding a driver of our own would produce the **larger**
   attack surface, not the smaller one.

   So where a driver is unavoidable it is **ours, minimal, and test-signed** — the operator
   reconfigures their machine either way, and only one of the two is auditable.

   What survives that constraint is being a **client of drivers Microsoft already signs**:
   `winhvr.sys` and `vid.sys`, or the documented user-mode **WHP** API. Those carry no signing
   problem at all, because we ship no driver. The backend table in
   [`exdi-stub-plan.md`](exdi-stub-plan.md) lists WHP with the caveat that it is "aimed at
   partitions the caller creates, so applicability to an existing VM's VTL1 is doubtful and should
   be checked before it is costed" — that check is now the highest-value unknown in this plan,
   because it is the only candidate that could both work and ship. And it is exactly what
   `ReadInterfaceWinHv` was going to exercise, which makes the untested status of that path the
   thing to resolve first rather than a loose end.

   **Correction, 2026-09-26: HVCI was never the blocker, and disabling it bought nothing.** The
   first diagnosis read "CodeIntegrity refused the driver" as "HVCI refused the driver". Those are
   different claims and the event named which policy all along. With HVCI disabled on the debugger
   host and the host rebooted, the probe produced the **identical** failure — `SdkEnumPartitions`
   returned 0, the service was installed and failed to start, and CodeIntegrity 3077 cited the same
   `{8f9cb695-5d48-48d6-a329-7202b44607e3}`, which event 3099 identifies as *"Microsoft Windows
   Cross Certificates for Code Integrity Exceptions Policy"*. That policy is refreshed and
   activated at boot independently of HVCI and refuses the revoked 2013 certificate regardless.
   The concession was made on a misdiagnosis and should be reverted; the lesson is that an event
   naming a policy ID is naming *which* gate, and reading past it to the gate one expected is how a
   security posture gets weakened for nothing.

   **Why weakening this particular host is acceptable, which is a separate question from whether a
   given change helps.** The debugger host is itself a Hyper-V guest, and its parent is hardened
   independently with kCET enabled. So the blast radius of test signing, Secure Boot off, or HVCI
   off is one rebuildable VM sitting behind a hardened boundary, not the lab's trust anchor. That
   makes the concessions route 1 needs defensible. It does **not** make a concession that buys
   nothing defensible, which is the distinction the HVCI misdiagnosis above failed: the question is
   never only *"can we afford to weaken this host"* but also *"does weakening it achieve the thing
   we are weakening it for"*, and the second question was not asked.

   HVCI was restored after that finding. Expect to disable it again if route 1 proceeds — a
   test-signed driver generally will not load with HVCI active even under `testsigning` — so the
   revert is correctness about *this* attempt rather than a permanent posture.

   **What actually gates a driver here**, measured after that reboot: Secure Boot is **on**, so
   `bcdedit /set testsigning on` is refused until it is turned off on the VM; the WDK is absent —
   `Include\10.0.26100.0\km` and `Lib\10.0.26100.0\km` do not exist, only the user-mode SDK — while
   VS Build Tools 18 with MSVC 14.50 and an x64 `cl.exe` **is** present, so the compiler is not the
   gap. `vid.sys` does publish a device interface (`ROOT#VID#0000#{7896e901-…}` and `VidExo` are
   present in `\GLOBAL??`), but a user-mode `CreateFileW` against them returns `FILE_NOT_FOUND`,
   so reaching that interface is the reverse-engineering effort the backend table already priced
   and not a shortcut.

   **So H2's cheap probe is spent, and the remaining options both require the same concession.**
   Disabling HVCI on the debugger host makes the oracle usable and becomes a recorded condition of
   every measurement taken afterwards. Writing our own driver — H2's stated fallback — needs either
   the same concession or a properly signed binary. The decision rule this gate was written with
   held: HVCI stayed on until a driver was *demonstrably* needed, and it now demonstrably is.
2. **A minimal root-partition driver** issuing `HvCallReadGpa`, written only if the above is
   insufficient. Signable by whoever runs it; the revoked-certificate driver that ships with
   LiveCloudKd is not a dependency of this plan and should not be loaded to satisfy it.

- **Pass:** a page whose contents are known is read from the root at the right GPA. *Make* it
  known — allocate a large non-paged buffer inside the guest, fill it with a random signature
  generated for the run, and find that signature from the root. A signature chosen at run time
  rather than a constant, so a stale match cannot be mistaken for a live one.
- **Control 1:** the same search against the *other* guest does not find it. Without this, a read
  that is actually hitting host memory passes.
- **Control 2:** a GPA the guest does not have backed must **fail** rather than return zeroes.
  A reader that returns zeroes for unmapped memory will later report SK as "all zeroes" and be
  believed.

## H3 — can the root read the guest's VTL1 registers (the pivotal gate)

Everything rests here. `HvCallGetVpRegisters` with `HV_INPUT_VTL` set to `Vtl1`, asking for `CR3`.

- **Pass:** the call succeeds and returns a CR3 that is **not** the guest's VTL0 CR3.
- **Control 1 — the positive control that makes a negative meaningful.** The same call with
  `HV_INPUT_VTL = Vtl0` must return a CR3 that matches what the guest's own kernel reports, checked
  by attaching an ordinary kernel debugger to that guest and reading it. If VTL0 succeeds and VTL1
  is refused, that is a clean answer about VTL1. If **both** are refused, the finding is about
  privileges or plumbing and says nothing about VTL1 — and the two failures must not be reported as
  one.
- **Control 2:** against the VBS-off guest, the VTL1 request must fail or report VTL1 not enabled.
  A VTL1 CR3 from a guest with no VTL1 means the value is being fabricated somewhere.
- **Control 3:** `HvRegisterVsmVpStatus` and `HvRegisterVsmPartitionStatus` should independently
  agree that VTL1 is enabled on that VP in the first guest and not in the second.
- **Stop condition:** refused for the VBS guest while the VTL0 control passes — the route as
  designed is closed, and what remains is the scanning fallback, which is a different plan with a
  different cost and should be re-decided rather than drifted into.

### H3 result, 2026-09-26: PASS — the hypervisor grants a parent a child's VTL1 registers

**This is the assumption the whole route rested on, and it holds.** H0 could establish only that the
TLFS does not prohibit a parent naming a child's VTL1; `h3probe.sys` converts that into a fact.
Both guests were enumerated as children of the root and probed identically:

```text
child partition 0x2                       child partition 0x3
  VTL0 CR3 : SUCCESS 0x00007D5000           VTL0 CR3 : SUCCESS 0x0001A75000
  VTL1 CR3 : 0x0015  (refused)              VTL1 CR3 : SUCCESS 0x0001201000
  VsmVpStatus       EnabledVtlSet=0x0001    VsmVpStatus       EnabledVtlSet=0x0003
  VsmPartitionStatus EnabledVtlSet=0x0001   VsmPartitionStatus EnabledVtlSet=0x0003
                     MaximumVtl=0                              MaximumVtl=1
```

**The control discriminated exactly as designed, which is what makes the positive readable.** On
partition 0x2 the VTL0 read succeeded while VTL1 was refused — so the refusal is a statement about
VTL1 and not about privilege or plumbing, which is the distinction the VTL0 control exists to draw.
On 0x3 the VTL1 read returned a CR3 **distinct from** that partition's VTL0 CR3, so it is not the
VTL0 value under another name.

**The interpretation does not depend on decoding the refusal.** `0x0015` is not enumerated on the
TLFS `HV_STATUS` page and is left unnamed here rather than guessed at. It does not need naming: the
two VSM status registers say independently that partition 0x2 has only VTL0 enabled and a maximum
VTL of 0, so there is no VTL1 there to read. Those registers were included as corroboration and are
now carrying the reading — which is the argument for gathering corroborating state even when the
primary measurement looks self-explanatory.

**Identification is by VSM state, not by partition number.** Partition 0x3 is the VBS guest because
its `EnabledVtlSet` is `0x0003`, not because 3 sorts after 2; the ids are the hypervisor's and carry
no ordering guarantee worth relying on.

**Confirmed incidentally: the inferred `HvlInvokeHypercall` signature is right.** It was flagged as
the one piece taken from convention rather than documentation — control word, input physical
address, output physical address — and four hypercalls per partition returning coherent, correct
values settles it.

**What this does not establish.** VTL1 **register** access is granted; VTL1 **memory** is untouched.
Whether `0x1201000` is Secure Kernel's CR3 and whether translating through it reaches readable SK
pages is H4, which now has a concrete input rather than an assumption.

### H3 instrument, as built

**`nt!HvlInvokeHypercall` is exported and resolvable at runtime**, which is what makes a small
driver sufficient: it issues arbitrary hypercalls without the driver building its own hypercall
page, and `MmGetSystemRoutineAddress` reaches it without depending on it being in the public
`ntoskrnl.lib`. `HvlInvokeFastExtendedHypercall` is exported beside it.

`h3probe.sys` enumerates child partitions with `HvCallGetNextChildPartition` (`0x0047`, Simple) and
for each child's VP 0 issues `HvCallGetVpRegisters` (`0x0050`, Rep, rep count 1) four times: CR3 at
`TargetVtl=0` — the control — CR3 at `TargetVtl=1` — the test — then `HvRegisterVsmVpStatus` and
`HvRegisterVsmPartitionStatus` as independent corroboration that VTL1 exists on that VP at all. The
register codes are `HvX64RegisterCr3 = 0x00040002`, `HvRegisterVsmVpStatus = 0x000D0003`,
`HvRegisterVsmPartitionStatus = 0x000D0004`, and `HV_INPUT_VTL` packs `TargetVtl:4` with
`UseTargetVtl:1` at input offset 12. **Every constant is from the TLFS**, not from the GPL headers,
which is the clean-room condition this plan set for itself.

The client refuses to over-read its own result: a VTL1 failure is reported as a negative *about
VTL1* only when the VTL0 control succeeded, a double failure is reported as being about privilege
or plumbing, and a VTL1 "success" returning the VTL0 value is flagged as suspect rather than
counted.

**Secure Boot had to come off first, from the parent.** `bcdedit /set testsigning on` was
refused with *"The value is protected by Secure Boot policy and cannot be modified or deleted."*
The debugger host is itself a Hyper-V guest, so Secure Boot is turned off from its parent with the
VM powered down (`Set-VMFirmware -EnableSecureBoot Off`), not from inside. The driver is built and
test-signed with a certificate trusted in `LocalMachine\Root` and `TrustedPublisher`, and HVCI is
staged off again for the same attempt.

**Three build traps, recorded because each cost a cycle.** `CL` and `LINK` are *reserved* MSVC
environment variables — setting them to tool paths makes `cl.exe` treat its own binary as a source
file. Kernel sources still need the **UCRT** include directory, or `ntdef.h` fails on `ctype.h`.
And taking the address of a member of a `#pragma pack(1)` struct is genuinely unsafe rather than
merely warned about, so results are gathered into locals and assigned afterwards.

## H4 — does what comes back look like Secure Kernel

### H4 result, 2026-09-26: FAIL, cleanly — the hypervisor withholds VTL1 memory from the parent

**The memory half of the route is refused, and the refusal is measured rather than inferred.** A
parent may read a VBS-enabled child's VTL0 memory freely; the pages VTL1 protects come back as
`HvAccessGpaReadIntercept` with actively-written zeros. Taken with H3 this gives the route's
governing asymmetry: **the hypervisor grants a parent a child's VTL1 *registers* and denies it that
child's VTL1 *memory*.** You can obtain VTL1's `CR3` and you cannot read the page it points at.

**Three corrections to what this section said before.**

**The call code was never in doubt, and the earlier hedging was mine.** `hvgdk.h` from the HDK — a
Microsoft-authored header, published under their academic licence — names `HvCallReadGpa = 0x0053`
and `HvCallWriteGpa = 0x0054`. Its numbering is confirmed correct *on this build* at three
independent points already measured here: `0x0047` GetNextChildPartition and `0x0050`
GetVpRegisters both worked in H3, and `/live-hypervisor` separately measured a running guest's
traffic at `0x005C`/`0x005D`, which this header names PostMessage and SignalEvent — exactly what a
live guest emits constantly. The header is old and the V1 block has not renumbered.

**That retires a near-miss worth stating plainly.** The secondary source proposing `0x0054` as "the
newer call code" was proposing the **write**. Firing it blind would have written into a child
partition's physical memory. And the hazard is structural rather than a one-off: **this ABI places
read/write pairs adjacently** — `0x0053`/`0x0054` ReadGpa/WriteGpa, `0x00CC`/`0x00CD`
QueryVtlProtectionMaskRange/**Modify**VtlProtectionMaskRange. An off-by-one on a call code in this
range mutates a partition where it meant to inspect one. No call code in this family is fired
without corroboration.

**The "wrong output layout" hypothesis was wrong, and it was wrong because of how I measured.** The
probe **zeroed** the hypercall output page before each call, so "the VTL1 page reads as all zeros"
could not be told apart from "the hypervisor wrote nothing" — and the instrument manufactured the
very ambiguity the section recorded as a finding. Filling the page with `0xAA` instead makes every
byte answer for itself:

| probe | written span | reading |
|---|---|---|
| `ReadGpa`, `ByteCount=16` | `+0 .. +23` | `AccessResult` at `+0`, `Data[16]` at `+8` |
| `ByteCount` = 1 / 2 / 4 / 8 | `+0 .. +23` | that many real bytes at `+8`, remainder zero-filled |
| bogus call code `0x0FFF` | **none** — page still pure poison | the control: a rejected call writes nothing |

The layout the driver already used was correct all along. The bogus-code row is what makes every
other row mean something: it demonstrates that "written" is a real observation and not an artefact
of the buffer.

**The refusal is a named result code that was on screen and undecoded.** The output's `AccessResult`
field is `HV_ACCESS_GPA_RESULT_CODE`, and `2` is `HvAccessGpaReadIntercept`. Every earlier run
printed `AccessResult=0x2` and no table existed to read it with, so it was recorded as "all zeros".

| read | `HV_STATUS` | `AccessResult` | data |
|---|---|---|---|
| partition 0x3 VTL0 `CR3` page | `SUCCESS` | `0` Success | real contents |
| partition 0x3 **VTL1** `CR3` page | `SUCCESS` | **`2` ReadIntercept** | zeros, actively written |
| partition 0x1 (root) | `ACCESS_DENIED` | — | — |

**`HV_STATUS` is SUCCESS on the refused read.** A consumer that checks only the status renders
zeros for exactly the memory it exists to inspect, with no error anywhere. That is the single most
important operational fact in this section, and it is a property of the interface rather than of
this probe.

**The effect tracks VBS, measured against a control partition at page granularity.** The same fixed
grid was walked in both guests, so the columns are comparable by construction:

| partition | pages scanned | `ReadIntercept` | contiguous runs |
|---|---|---|---|
| 0x2 — VBS **off** (control) | 32768 | **0** | 0 |
| 0x3 — VBS **on** | 32768 | **4608** (18 MiB) | 7 |

A sparser 4 GiB sweep agrees and extends it: 0 of 1984 mapped samples in the control against 11 in
the VBS guest, with two further protected regions above the 128 MiB the dense scan covered, so
18 MiB is a floor and not the footprint. Both partitions returned **identical** unmapped counts
(63/63), which is the check that the two guests' memory maps are comparable and the split is not an
artefact of different layouts.

**The shape carries more evidence than the rate.** Every run is 2 MiB-aligned and a whole multiple
of 2 MiB (512 and 1536 pages). That is large-page-granular protection. Scattered single pages would
have indicated device overlays instead, which is the reading the control was there to exclude.

**Why the call cannot be talked round: `HV_INPUT_READ_GPA` has no VTL field.** `PartitionId`,
`VpIndex`, `ByteCount`, `BaseGpa`, `ControlFlags` — and `ControlFlags` is `CacheType:8` and reserved
bits. There is no parameter with which to request VTL1, so the read is performed as a VTL0-class
access and VTL1-protected pages intercept it. This is not a permissions setting to be found.

**One hard throughput fact for any design built on this call:** `ByteCount` is capped at **16**.
`n = 17` and above return `INVALID_PARAMETER`. A 4 KiB page therefore costs 256 hypercalls.

**What this does to the route.** H3's pass must not be read as "the route works". The register half
is granted and documented; the memory half is refused by the hypervisor itself, through the only
guest-physical read this interface offers. A Secure Kernel debugger needs to read SK's memory, and
this call will not do it. The remaining avenues, none of them started:

- **`HvCallQueryVtlProtectionMaskRange` (`0x00CC`)** would turn this correlation into mechanism by
  asking the hypervisor directly which VTL protections cover the withheld runs. `hvgdk.h` carries
  the enum entry but **no input structure**, so its layout has to come from the dispatch table in
  `hvix64.exe` before it is fired — see the adjacency hazard above, since `0x00CD` modifies.
- **`HvCallReadSystemMemory` (`0x00F5`)**, likewise undocumented here, and unexamined.
- **The `vid.sys` route**, which is what LiveCloudKd carries a driver for, priced in the backend
  table as a large reverse-engineering effort.

**The instrument, and what it is worth reusing for.** `h3probe.sys` gained an
`IOCTL_H3_RAWGPA` that parameterises call code, partition, VP index, GPA, byte count, rep count and
control flags, poisons the output page, and returns the raw first 64 bytes with the full hypercall
return value. It is a general hypercall bench rather than a ReadGpa client, and the poisoning is
the part to keep: **a zeroed output buffer cannot distinguish data from silence.**

### H4 revised, 2026-09-26: the withholding is route-specific, and the route is not dead

**An independent oracle overturns the scope of the result above.** VTL1 memory is withheld from
`HvCallReadGpa`, **not** from the root partition. A root-partition driver reading guest physical
memory by direct mapping sees pages the hypercall refuses. H4's negative is a fact about the
instrument, and the earlier heading's "the hypervisor withholds VTL1 memory from the parent" was
true only of the call it was measured with.

**The oracle is LiveCloudKd's published SDK, and it is independent in the one way that matters:**
`SdkReadPhysicalMemory` takes the read route as a **parameter**, so the same library, the same
partition and the same addresses can be read both ways.

| `ReadMemoryMethod` | route |
|---|---|
| `2` `ReadInterfaceWinHv` | `winhvr.sys!WinHvReadGpa` — hypercall `0x0053`, i.e. exactly this plan's route |
| `1` `ReadInterfaceHvmmDrvInternal` | `hvmm.sys`'s own mapping — `MmMapIoSpaceEx`, `MmGetPhysicalMemoryRanges`, `ZwMapViewOfSection` |

That the two are one argument apart makes this a **within-instrument** differential rather than a
comparison of two tools that could differ for a hundred irrelevant reasons.

**The oracle validated itself against this plan's own instrument before being believed.** On method
2 it returned `008b4b2841b800100000489948c1e90c` at partition 0x3 GPA `0x1A75000` — byte-identical
to what `h3probe` returned for the same address — and "all zeros" on precisely the ranges the page
scan found intercepted. Two independently built instruments agreeing on both a positive and a
negative is what makes the next table evidence rather than an anecdote.

| GPA | method 2 (hypercall) | method 1 (direct) |
|---|---|---|
| `0x00C00000` | all zeros | `b03f641d02f8ffff…` — **read** |
| `0x01201000` (the VTL1 `CR3` page) | all zeros | all zeros |
| `0x03600000` | all zeros | all zeros |
| `0x03E00000` | all zeros | `ff01000000010000…` — **read** |
| `0x04800000` | all zeros | `0000000000000060…` — **read** |
| four control GPAs both routes can read | data | **identical** to method 2 |

The controls are what license the reading: where both routes work they agree byte for byte, so the
disagreement above is about the pages and not about the tools. `b03f641d02f8ffff` is
`0xfffff8021d643fb0`, a canonical kernel pointer — real content, not noise.

**What is established, and what is not.** Established: at least three of the five sampled withheld
ranges are readable from the root by a non-hypercall route, so the hypervisor's refusal is a
property of `HvCallReadGpa` rather than a property of the root's access to VTL1 memory. **Not**
established: that the direct route reaches *all* of VTL1. Two ranges — including the VTL1 `CR3`
page itself, which is the one a debugger would need first — still read as zeros by **both** routes.
Whether that is a limit of `hvmm.sys`'s mapping, a fallback to the hypercall inside method 1, or
genuinely zero memory is unmeasured, and it is the next thing to settle.

**What this does to the route.** The backend table's pricing stands and its conclusion changes: the
memory half needs the `vid.sys`/direct-mapping route that LiveCloudKd carries a driver for, and
that route demonstrably works against a VBS guest. The register half is already granted and
documented (H3). So the two halves can both be served — one by a documented hypercall, the other by
an undocumented driver route — which is a materially better position than the hypercall-only
finding suggested.

**Loading `hvmm.sys` needed one change, and the blocking policy was not the one it looks like.**
As shipped it is signed with a **revoked** certificate (`CN=Atheros Communications Inc.`, expired
2013), and `sc start` fails with *"An Application Control policy has blocked this file"*. The
CodeIntegrity log separates two policies, and only one of them blocked:

| policy | event | effect |
|---|---|---|
| `{8f9cb695-5d48-48d6-a329-7202b44607e3}` | 3077 | **blocked** — the same policy that blocked `h3probe` before it was test-signed |
| `{784c4414-79f4-4c32-a6a5-f0fb42a51d0d}` (vulnerable-driver blocklist) | 3076 | **audit only** — logged, did not block |

Re-signing the driver with this bench's own test certificate loads it, testsigning being on. Worth
stating plainly because the obvious guess — "the vulnerable driver blocklist stopped it" — is
wrong here, and acting on it would have meant disabling a protection that was not in the way. This
is the second time in this investigation that a CodeIntegrity refusal was nearly attributed to the
wrong policy; the log names the policy, so read it.

### H4 pass criteria, as written before the run

**Kept for comparison, and not reached.** These describe what a successful read of SK's memory
would have had to show. The run never got to test any of them: the memory could not be read at all,
so "does what comes back look like Secure Kernel" was answered one step earlier than this plan
expected. The controls below are still the right ones for any future instrument that *can* read it.

Only meaningful once H3 passes. **Budget for walking SK's page tables rather than for the
hypervisor doing it**: H0 found `HvCallTranslateVirtualAddress` documented without a Restrictions
section and without its control flags expanded, so parent-calling and VTL selection are unproven
there. Try the hypercall first, since it is cheap and would remove the swizzle problem outright —
but a design that only works if it succeeds is a design with an unmeasured dependency. The
`SkdInitDebuggerDataBlock` PTE swizzle bit is the fallback's key input and was already measured.

- **Pass, weak:** at the claimed SK base there is a valid PE header, and its section names and
  sizes match the `securekernel.exe` image on disk for that guest's build.
- **Pass, strong:** SK's `KdDebuggerDataBlock` is located — `KDBG` signature, size `0x3A8` — and
  `SkLoadedModuleList` points at a list whose first entries are plausible module records. Those
  three facts come from H0's table and were measured from the image, so this is a real test rather
  than a restatement.
- **Control 1:** the same procedure against the VBS-off guest finds **no** SK data block. This
  control is inherited from the EXDI plan's E2 and matters as much here.
- **Control 2 — an oracle that is not this mechanism.** Compare read-only sections against the
  on-disk image. Two readings produced by the same hypercall path can agree and both be wrong; the
  image on disk was produced by neither. LiveCloudKd may be used as a *second* oracle, with the
  caveat that if it turns out to use the same hypercall it is not independent — establish which
  route it takes before treating agreement as confirmation.
- **Note the expected mismatch:** a live image's IAT is populated and will not match the file. A
  comparison that demands whole-image equality will fail for the wrong reason.

## H5 — can DbgEng be driven off it

Two sub-paths, and the first is **blocked until E0's activation stall is resolved**, since it needs
a working EXDI server on the debugger host.

- **H5a, through DbgEng.** An EXDI server of our own, handed SK's `KdVersionBlock` address through
  `Kd=VerAddr:<addr>`. **Pass:** `lm` lists `securekernel`, symbols resolve against live memory, SK
  structures walk. **Partial pass is the likely outcome and is not a failure** — E1 found DbgEng's
  `sk` record EXDI-gated with its selector unreferenced, so SK-aware semantics may simply not
  materialise and what remains is a generic target with correct memory.
- **H5b, without DbgEng.** Expose the reads as windbg-mcp tools: SK base and size, structure walks,
  symbol resolution against the image. **This is the fallback that loses least**, precisely because
  of E1 — if DbgEng contributes no SK awareness, it is contributing only its memory plumbing, which
  is the part we would already have.

Deciding between them is a result of H4 and E1, not a preference to settle now.

## Explicitly out of scope

**Execution control.** Breakpoints and single-stepping in VTL1 are not part of this feasibility
question. Nothing seen so far demonstrates them: `SdkControlVmState` pauses and resumes a whole VM,
which is not VTL1 stepping, and LiveCloudKd's active CLSID is undemonstrated by its own write-up.
Read-only inspection is the deliverable being tested, and a plan that quietly grows execution
control will not finish.

**The host's own Secure Kernel.** This technique crosses a partition boundary, so it reaches a
*guest's* SK and never the host's. Debugging the physical host's SK needs an independent machine,
which the validation record already states.

## Stop conditions

Written here so they are not renegotiated later:

- **H0 says the specification reserves VTL1 state**, and H3 then refuses with its VTL0 control
  passing. The hypercall route is closed; re-cost the scanning fallback as a separate decision.
- **H2 cannot read guest physical memory** by either mechanism. Then the problem is below every
  VTL question and this plan has learned nothing about SK.
- **H3 passes but H4 finds nothing recognisable** at any candidate address. Either the translation
  is wrong or VTL1 memory is protected from the root in a way register access is not — and those
  are distinguishable, so say which before continuing.
- **H4 passes and H5a finds DbgEng contributes no SK awareness.** Not a failure: it selects H5b and
  retires the EXDI work for this route, which is a saving rather than a loss.
- **Any gate passes without its control having passed.** The result is withdrawn, not caveated.
