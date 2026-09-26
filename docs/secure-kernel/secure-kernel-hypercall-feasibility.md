# Feasibility test plan: reading a guest's VTL1 from the root partition

The question this answers is narrow and falsifiable: **can a root-partition component read a
guest's Secure Kernel state well enough to drive a debugger?** It is not a plan to build one.
Every gate below can fail, each says how, and the stop conditions are written before the work
starts so that a sunk cost does not decide.

**Answer, as of 2026-09-26: yes — `securekernel.exe` was located in a VBS guest's VTL1 address
space from the root partition and identified against the image on disk (18/18 section names,
timestamp and `SizeOfImage` all matching).** It takes two mechanisms rather than one, and only the
first is documented.

- **Registers: granted.** H3 passed — `HvCallGetVpRegisters` returns a child's **VTL1** `CR3` to the
  parent, on a documented, parent-callable hypercall.
- **Memory: refused by the hypercall, reachable by a driver.** H4 measured `HvCallReadGpa`
  (`0x0053`) refusing a VBS guest's VTL1-protected pages — 4608 protected pages against **0** in a
  VBS-off control — and it refuses them as `HV_STATUS_SUCCESS` with a per-access `ReadIntercept`
  and zeros, so a consumer checking only the status sees silent zeros exactly where the protected
  memory is. It is not a permission to be found: `HvCallReadGpa` has no VTL parameter to ask with.
  **But an independent oracle then read those same ranges** from the root by a direct-mapping
  route, so the withholding belongs to that hypercall rather than to the root's access. Read whole
  rather than 16 bytes at a time, the VTL1 `CR3`'s page is Secure Kernel's **PML4**, identified by
  its self-map entry — so the register half and the memory half join up, and SK's address space is
  walkable from the root.

- **Result: `securekernel.exe` at VA `0xFFFFF80220D89000`** in the VBS guest, walked from the root
  via SK's own page tables, matching the on-disk image on all 18 section names, timestamp and
  `SizeOfImage`. The identification is independent of the mechanism that produced it.

Gates H0, H1, H2, H3 and H4 passed. **H5 is not started, but its route is now decided**: of its two
sub-paths, H5a (drive DbgEng through EXDI) is blocked on E0's unresolved activation stall *and*
would contribute no Secure Kernel awareness if it were unblocked — E1 measured its `sk` record
unreachable — so H5 proceeds as **H5b**, exposing the reads directly. The decision, its evidence
and the two-part condition that would reverse it are recorded under H5. **H2's status is stated
carefully,
because an earlier draft of this line called the gate failed and that contradicted the two gates
built on it:** H2 asked whether the root can read the guest's physical memory *at all*, offering two
mechanisms. Mechanism 1, the driver-free probe, **failed** — and its cause is worth reading, since
the Code Integrity policy that blocks is not the one it looks like. Mechanism 2, H2's own stated
fallback of a minimal root-partition driver, **succeeded**, and every GPA measurement in H3 and H4
is taken through it. So the cheap probe failed and the gate passed. H4's sections
below are kept in the order they were measured — a negative, then its narrowing by an independent
oracle, then a correction about the sampling window, then the pass — because how the negative was
overturned is as much the result as the pass is.

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
| `SkdInitDebuggerDataBlock` fills `KdDebuggerDataBlock` — `KDBG`, `SkLoadedModuleList`, PTE swizzle bit | exdi-stub-plan, 2026-09-22 | measured **from the image** |
| That block's `Size` field reads **`0x3A0`** in a live guest, not the `0x3A8` read from the image | H4, 2026-09-26 | measured **live**; an exact-match search on `0x3A8` found nothing |
| `KdDebuggerDataBlock` at `securekernel.exe` **+0x1335E0**, `SkLoadedModuleList` at **+0x127770** | H4, 2026-09-26 | measured — each found independently, and they agree |
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

   **So H2's cheap probe is spent, and the remaining options both require a concession — but not
   the one written here at the time.** This paragraph said *"disabling HVCI on the debugger host
   makes the oracle usable"*. **It does not, and the sentence is left corrected rather than deleted
   because acting on it would weaken a host for nothing.** HVCI was disabled and the probe failed
   identically, with the same policy id; the blocker is the **Cross Certificates for Code Integrity
   Exceptions** policy `{8f9cb695-5d48-48d6-a329-7202b44607e3}`, which rejects the revoked
   certificate the oracle's driver ships with. What actually loads it, measured 2026-09-26, is
   **test-signing plus re-signing the driver** — and the vulnerable-driver blocklist
   `{784c4414-…}` only *audits*, so that is not the blocker either. HVCI was reverted. See the
   correction below, and the H4 record of which policy blocks what.

   Writing our own driver — H2's stated fallback — needs test-signing or a properly signed binary.
   The decision rule this gate was written with held: HVCI stayed on until a driver was
   *demonstrably* needed; what the gate got wrong was **which** setting was in the way.
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

### H2 result, 2026-09-26: mechanism 1 fails, mechanism 2 passes, so the gate passes

**The cheap probe failed and the gate did not.** Mechanism 1 — reading guest memory with no driver
loaded — does not exist in this tool, for the Code Integrity reason recorded above. Mechanism 2,
this gate's own stated fallback, was built as `h3probe` in H3 and **reads a child partition's
physical memory from the root**: single reads, a 22-address grid, and page-granular scans of 32768
pages in each of two guests. Every GPA measurement in H3 and H4 is taken through it, so reporting
H2 as failed would contradict the two gates that rest on it.

**The pass condition as written was not the procedure run**, and that is worth stating rather than
quietly counting it. It asked for a run-time random signature planted in a guest buffer and found
from the root, which needs a driver *inside* the guest; no such signature was planted. What was
used instead is a stronger oracle arriving later: `securekernel.exe` read out of the guest and
matched against the on-disk image on 18 section names, timestamp and `SizeOfImage` — contents known
independently, and known to a source that is neither the hypercall nor the driver.

**Both controls did run, and Control 2 is the one that earned its place.**

| control | outcome |
|---|---|
| 1 — the same read against the *other* guest differs | **passed** — the partition id is honoured: partitions 0x2 and 0x3 return different data at one GPA, and partition 0x1 is refused `ACCESS_DENIED` |
| 2 — an unbacked GPA must fail rather than return zeroes | **passed** — unmapped GPAs answer `HvAccessGpaUnmapped`, 63 of them per guest in the dense scan |

Control 2 was written against a reader that "returns zeroes for unmapped memory" and would later
"report SK as all zeroes and be believed". The real instrument does something one step subtler and
the control still caught it: a VTL1-protected page returns **`HV_STATUS_SUCCESS` with zeros**, and
only the per-access `AccessResult` distinguishes it — `HvAccessGpaReadIntercept` rather than
`Success`. A reader checking the status alone fails exactly as this control predicted. It was
nevertheless believed for a while, because the *data* was being read 16 bytes at a time; see the
H4 correction.

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

### H4 first finding, 2026-09-26: the *hypercall* withholds VTL1 memory — later narrowed, then passed

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

### H4 correction, 2026-09-26: the VTL1 CR3 page was never zero — the sample was 16 bytes

**`HvCallReadGpa` moves at most 16 bytes, so every probe in this investigation read bytes 0–15 of a
4096-byte page and judged the page on them.** Secure Kernel maps nothing in the low canonical half,
so its PML4's first entries are legitimately zero. **Every "all zeros" recorded above therefore
means "the first 16 bytes are zero" and nothing more.** The 16-byte cap is documented two sections
up as a throughput fact; it is also a *sampling* fact, and that was missed.

Read whole, GPA `0x1201000` is a page table root, and it identifies itself structurally:

| property | value |
|---|---|
| self-map entry | index **388** = `0x8000000001201063` → PFN `0x1201`, **its own** |
| present entries | 26 |
| non-zero bytes in the page | 123 of 4096 |
| first present entry's byte offset | `0x850` — past every probe's 16-byte window |

A self-referencing entry is decisive: it is the signature of an x64 paging root, it survives
relocation, and it needs no address known in advance. So the VTL1 `CR3` returned by
`HvCallGetVpRegisters` is correct, current and points where it says — **H3's result needed no
qualification after all.**

**Two neighbouring claims fall with it.** The "2 of 5 withheld ranges unreadable even directly" in
the section above was an artefact of sampling each run's **first** address only. Measured page by
page, the run holding the `CR3` is **424 of 512 pages readable** by the direct route, and
`0x1205000` in that run holds PTEs with consecutive PFNs (`0xd47, 0xd48, 0xd49, 0xd4a`, flags
`0x121` = Present|Accessed|Global). The direct route is reading Secure Kernel's page tables.

| run | pages | DATA | first-16-zero |
|---|---|---|---|
| `0x0C00000` | 512 | 455 | 57 |
| `0x1200000` (holds the `CR3`) | 512 | **424** | 88 |
| `0x3600000` | 512 | 13 | 499 |
| `0x3A00000` | 512 | 445 | 67 |
| `0x3E00000` | 1536 | 496 | 1040 |
| `0x4800000` | 512 | 396 | 116 |
| `0x4E00000` | 512 | 403 | 109 |

**The layout is deterministic across a reboot**, which was measured rather than assumed: after an
unrelated host reset the VBS guest came back with the **same seven runs at the same addresses**,
the same 4608 intercepted pages, the control partition still at 0, and the VTL1 `CR3` still
`0x1201000`. That makes these usable as landmarks rather than as one boot's accident.

**Why the poison discipline did not catch this one.** Poisoning separates *written* from
*unwritten*, and every one of these reads genuinely was written — with zeros, which were the real
contents of the bytes requested. The defect is one level up: **the window was too small to be
representative, and no control established that it was.** The check that would have caught it is
the same one that caught everything else here — read something whose shape is known independently,
in this case a whole page rather than a fixed prefix of one.

### H4 result, 2026-09-26: PASS — Secure Kernel located and identified from the root

**`securekernel.exe` was found in the VBS guest's VTL1 address space, walked from the root
partition, and positively identified against the image on disk.** This is the pass condition this
section was written to test, and it is met on the strong form rather than the weak one.

| | in the guest's VTL1 space | `C:\Windows\System32\securekernel.exe` |
|---|---|---|
| sections | 18 | 18 |
| timestamp | `0x94DED27F` | `0x94DED27F` |
| `SizeOfImage` | `0x175000` | `0x175000` |
| section names | *(all 18, below)* | **identical** |

```text
.text KVASCODE TRNS PAGELK fothk ZEROPAGE CACHEALI .rdata .data
.pdata TABLERO ALMOSTRO MIRRDATA nlsdata FUNCTBL CFGRO .rsrc .reloc
```

Found at **VA `0xFFFFF80220D89000`**, backed by **GPA `0x00CD0000`** — inside the `0x0C00000`
withheld run, one of the seven the hypercall refuses. The names carry the identification on their
own: `KVASCODE`, `TRNS`, `ALMOSTRO`, `MIRRDATA`, `CFGRO` and `FUNCTBL` are Secure Kernel's, and a
coincidental match on all eighteen plus timestamp plus image size is not a reading anyone has to
argue about. **The identification is also independent of the mechanism that produced it** — the
on-disk image was written by neither the hypercall nor the driver — which is the control this plan
required before believing any of it.

**The route, end to end, as measured.** Two primitives with different permission models, joined at
a physical address:

1. `HvCallGetVpRegisters`, `TargetVtl = 1` → the guest's **VTL1 `CR3`** (`0x1201000`). Documented,
   parent-callable, granted (H3).
2. That GPA holds SK's **PML4** — read whole, not 16 bytes at a time.
3. A four-level walk over SK's page tables, read by a **non-hypercall** memory route, since
   `HvCallReadGpa` refuses these pages.
4. Scan the walked leaves for a PE header; identify it against the on-disk image.

So the hypervisor guards one door and hands over the key to the building through another. **That
asymmetry is the finding**, and it is what makes the route viable: registers by documented
hypercall, memory by driver mapping.

**Cost, which decides whether this can drive a debugger.** The walk itself took **167 page reads**:
11 PDPTs, 24 PDs, 130 PTs, yielding **11,326 leaf pages** in 9,201 contiguous VA runs. Finding the
image cost more than the walk, because scanning leaves for `MZ` is one read per page. Six PE images
were found in total; the other five are SK-side modules and are not yet identified.

**Walking a page table is walking a cyclic graph, and the self-map is the cycle.** SK's PML4
self-maps at index 388, so an unguarded descent re-enters the table at every level — 512× per
level. The first attempt at this walk grew its leaf list until Python exhausted the machine's
memory, which starved every other process on the host: `msedge.exe` died with `0xe0000008`, an
allocation failure, and the bench needed a reboot. Twice. It was **not** a kernel fault, a driver
leak or a pool exhaustion — the pool and PTE counters were clean throughout — it was an unguarded
graph walk in a Python script. Three guards fix it and all three are load-bearing: skip any entry
whose target PFN is the table it came from, keep a visited set per level, and put hard budgets on
both reads and collected leaves so that exceeding them is *reported* rather than absorbed. With
them the same walk costs 167 reads.

**What this does to the plan.** H4's pass criteria below ask for SK's `KdDebuggerDataBlock` and
`SkLoadedModuleList` as the strong form; the image identification is achieved and those two are the
next step, both now reachable as ordinary reads of a known VA range. H5 — driving DbgEng off it —
remains untouched, and the EXDI activation problem E0 found is still the blocker there rather than
anything measured here.

### H4 strong pass, 2026-09-26: `KdDebuggerDataBlock` and `SkLoadedModuleList` located

**Both of the strong-form pass criteria are met, and each was found by a route that does not depend
on the other.** Addresses are given as offsets into `securekernel.exe` as well as VAs, because the
VA depends on the load base and the offset does not.

| what | VA | image offset |
|---|---|---|
| `securekernel.exe` base | `0xFFFFF80220D89000` | — |
| `KdDebuggerDataBlock` | `0xFFFFF80220EBC5E0` | **+0x1335E0** |
| `SkLoadedModuleList` | `0xFFFFF80220EB0770` | **+0x127770** |

**The two findings confirm each other.** The list head was found *structurally* — searching SK's
address space for a `KLDR_DATA_TABLE_ENTRY` whose `DllBase` is the SK base and whose `SizeOfImage`
is `0x175000` sixteen bytes later, then following that entry's `Blink` — while the data block was
found by its `KDBG` owner tag. The block's `PsLoadedModuleList` field equals the structurally-found
head exactly, and its `KernBase` equals the base the PE walk had already established. Three
independent agreements, none of them assumed.

**The loaded-module list, walked:**

| # | `DllBase` | `SizeOfImage` | name |
|---|---|---|---|
| 1 | `0xFFFFF80220D89000` | `0x175000` | `securekernel.exe` |
| 2 | `0xFFFFF80220F03000` | `0x54000` | `skci.dll` |
| 3 | `0xFFFFF8022104A000` | `0xD000` | `symcryptk.dll` |
| 4 | `0xFFFFF80220F5C000` | `0xE9000` | `cng.sys` |
| 5 | `0xFFFFF8022105C000` | `0x15000` | `vmsvc.dll` |
| 6 | `0xFFFFF8021C5B1000` | `0xA000` | `vmsvcext.sys` |

**That table is itself a cross-check.** The PE-header scan of the walked pages found six images and
could name only one; the module list names all six, and the two agree base for base and size for
size. Neither method was told about the other's results.

**Correction to this plan's established-facts table: the block's `Size` is `0x3A0`, not `0x3A8`.**
The table carries `0x3A8` as *measured*, from static analysis of `SkdInitDebuggerDataBlock` on
2026-09-22; read out of a live guest on 2026-09-26 the field holds `0x3A0`. The offset is not in
doubt — `OwnerTag` at +0x10 and `Size` at +0x14 are fixed by `DBGKD_DEBUG_DATA_HEADER64`, and
`KernBase` at +0x18 lands exactly on the SK base found independently, which pins the alignment. The
discrepancy cost a run: **a first scan searching the image for the eight bytes `KDBG` + `0x3A8`
reported zero occurrences**, and the tag was three pages away the whole time. An exact-match needle
built from a remembered constant fails silently; searching for the tag alone and *reporting* the
size found is what recovered it.

**The block is populated selectively, which is correct rather than partial.** 26 of its 116 qwords
are non-zero. `KernBase`, `PsLoadedModuleList` and `BreakpointWithStatus`
(`0xFFFFF80220DA8A70`) are filled; `PsActiveProcessHead`, `PspCidTable`, `KiCallUserMode`,
`KeUserCallbackDispatcher` and `MmLoadedUserImageList` are all zero. Those are NT concepts Secure
Kernel has no equivalent for, so their absence is the expected shape of an SK debugger block and
not evidence that the block is uninitialised. **This also retires a hypothesis raised when the
first scan failed** — that `SkdInitDebuggerDataBlock` might only run when secure debugging is
enabled. It has run: the fields that mean anything for SK carry live pointers.

**Cost:** the whole confirmation took **10 page reads**, against 13,769 for the structural search
that preceded it. Once the coordinates are known, this is cheap enough to do on every attach.

### H4 Control 1, 2026-09-26: run, and it passes

**This was the criterion still owed, and it is the one that decides whether anything above counts.**
The risk it guards is specific: **this host runs VBS itself** (`VirtualizationBasedSecurityStatus`
is `2`), so the root partition has its own Secure Kernel resident in memory. A read path that was
landing in *host* memory — or in any partition other than the one named — would find
`securekernel.exe` regardless, and the identification against the on-disk image would confirm it
just as happily. Nothing measured above distinguishes those two worlds. This does.

One procedure, two partitions, the same fixed GPA grid, in one process:

| | partition 0x3 — VBS **on** | partition 0x2 — VBS **off** |
|---|---|---|
| pages scanned | 32768 | 32768 |
| pages with content | 32768 | 32768 |
| PE image headers | 112 | **152** |
| matching `securekernel.exe` (sections + timestamp + `SizeOfImage`) | **1**, at GPA `0x00CD0000` | **0** |
| `KDBG` tags | 4 | **0** |
| `KDBG` with `Size` `0x3A0` | **1**, at GPA `0x03A035F0` | **0** |

**The positive arm is not decoration.** A scan that finds nothing anywhere is indistinguishable
from a broken scan, so the negative is worth nothing on its own — which is why both arms run
together and both are reported. The control guest yields **more** PE headers than the VBS guest
(152 against 112), so the procedure demonstrably works there. It simply finds no Secure Kernel, and
not one `KDBG` tag of any size.

**A second result falls out of it.** This scan reached `securekernel.exe` by walking raw physical
pages and testing PE headers — touching no page table and using none of the VTL1 `CR3`. It landed on
GPA `0x00CD0000`, **the same GPA the four-level walk reported** from an entirely different
direction. Two methods that share only the partition handle agreeing on one address is a stronger
statement than either made alone.

**What the control does not establish.** It shows the reads are scoped to the partition named and
that SK's presence tracks VBS. It says nothing about *which* mechanism reads VTL1 pages — that is
the hypercall-versus-direct-route question settled separately — and the two guests differ in more
than one respect besides VBS, so this is a control against a specific confusion rather than a
general one.

### H4 pass criteria, as written before the run

**Kept for comparison, and — unlike an earlier draft of this paragraph said — subsequently met.**
These describe what a successful read of SK's memory would have to show. They were written before
the run, and the sections above record them being reached out of order: the memory looked
unreadable first, which is why this paragraph once said the run "never got to test any of them".
It did.

| criterion, as written below | outcome |
|---|---|
| valid PE header at the claimed SK base, section names and sizes matching the on-disk image | **met** — 18/18 names, timestamp and `SizeOfImage` |
| `KdDebuggerDataBlock` located, `KDBG` signature | **met** — image +0x1335E0; its `Size` is `0x3A0`, not the `0x3A8` the criterion assumed |
| `SkLoadedModuleList` points at plausible module records | **met** — image +0x127770, six modules |
| Control 1: the same procedure finds no SK data block in the VBS-off guest | **met** — 0 SK images and 0 `KDBG` tags there, against 1 of each in the VBS guest, same grid |
| Control 2: an oracle that is not this mechanism | **met** — the on-disk image, written by neither the hypercall nor the driver |

Every criterion and both controls are now met. The criteria are left below in their original
wording so that what was asked for before the run can be read against what was found.

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

### H5 decision, 2026-09-26: take H5b, and H5a is blocked rather than merely harder

**The plan deferred this choice to "a result of H4 and E1". H4 is now done, so it is decidable, and
it decides for H5b.** The reasoning is three measurements, none of them new:

| question | measurement | where |
|---|---|---|
| Can an EXDI server be activated on this host at all? | **No, unresolved.** E0's transport half did not pass: the RSP responder logged no connection at 75 s or 60 s, the surrogate held no socket, and a bare `CreateInstance` reproduced the stall without `kd`, blocking past 17 s having launched no surrogate | E0, 2026-09-25 |
| If it were, would DbgEng contribute Secure Kernel *awareness*? | **Not reachably.** Only functions that also reference EXDI strings reach the `sk` table readers; **0 of 91** KD-transport strings appear in any function touching the table; the `hv`-vs-`sk` selector has no direct callers and its address is never taken | E1, 2026-09-23 |
| Do we already have the memory plumbing DbgEng would otherwise supply? | **Yes.** VTL1 registers by documented hypercall, SK's page tables walked, `securekernel.exe` identified against the on-disk image, `KdDebuggerDataBlock` and `SkLoadedModuleList` both located | H4, 2026-09-26 |

Put together: **DbgEng's marginal contribution on this path is close to nothing, and its price is an
activation stall that has already cost a host reset.** H5a's own text anticipated the first half —
"if DbgEng contributes no SK awareness, it is contributing only its memory plumbing, which is the
part we would already have" — and H4 is what turned *would* into *do*.

**This is not "EXDI is a dead end".** It is narrower: **for reaching Secure Kernel**, EXDI buys a
generic memory target we can already produce, at the cost of an unresolved stall. E0 remains worth
resolving on its own merits, and H5a becomes attractive again the moment two things change
together — which is the reversal condition, written here so it is checkable rather than remembered:

- **E0's activation stall is resolved**, by something other than the in-process load, which is
  materially what `Inproc=` arranges and is what the 2026-09-22 host reset points at; **and**
- **the `sk` record turns out reachable after all.** E1's own caveat is the place to look: absence
  of a direct caller is not proof of dead code, since a computed jump table would not show in that
  scan, and it was one engine build.

Either alone is not enough. Resolving E0 while the record stays unreachable buys a generic target;
a reachable record with no activation buys nothing at all.

**What H5b gives up, and how much of it is recoverable.** Dropping the live-target path through
DbgEng costs its symbol handling — `lm`, PDB type resolution, structure formatting against
`securekernel.pdb` — which is real value and the main thing H5a was for. It is **not** all lost:
symbol resolution against the *image* needs no live target, so the engine can still resolve
`securekernel.exe` statically and have the base applied from H4's walk. The part genuinely given up
is DbgEng driving a live SK session, which E1 says it would not have driven knowledgeably anyway.

**Consequence for the sibling plan, recorded but not yet applied.**
[`exdi-stub-plan.md`](exdi-stub-plan.md) is written around the H5a route and its hypercall section
predates H4. It is **not** superseded wholesale — E0's activation problem and E4's integration work
are shared with any route — but its read-side design should be re-derived against H4's result
rather than patched, and until that happens its hypercall-only assumptions should be read with this
decision beside them. That re-derivation is deliberately scoped to whatever H5b turns out to need,
so it is not done here.

**So H5 proceeds as H5b**: expose the reads as `windbg-mcp` tools — SK base and size, structure
walks, symbol resolution against the image — with H5a parked behind the two-part reversal condition
above.

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
