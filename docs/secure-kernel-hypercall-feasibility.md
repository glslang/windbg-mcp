# Feasibility test plan: reading a guest's VTL1 from the root partition

The question this answers is narrow and falsifiable: **can a root-partition component read a
guest's Secure Kernel state well enough to drive a debugger?** It is not a plan to build one.
Every gate below can fail, each says how, and the stop conditions are written before the work
starts so that a sunk cost does not decide.

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
| VBS defends a guest's VTL1 from that guest's VTL0, not from its host | architecture | **assumed** — H3 tests it |
| The hypervisor permits a parent to name a child's **VTL1** specifically | — | **assumed; H0 found no prohibition, which is not permission** |
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

## H4 — does what comes back look like Secure Kernel

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
