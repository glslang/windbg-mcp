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

> **Corrected 2026-09-28 by S5e: the `0x1201000` row above is an artifact of the sample size.**
> Every cell in this table is **16 bytes** from the start of the page, and a PML4's low entries
> describe user space. **The proof is this record's own data for that same boot**: the H4 landmark
> table below puts that page's first present entry at byte offset `0x850` and its self-map at index
> 388, so its first 16 bytes were zero whether or not the page was readable, and a 16-byte read
> could only ever have returned zeros. So the answer to "a limit of the mapping, a fallback, or
> genuinely zero" is *none of the three* — the window never covered the data. What the row says
> about `0x3600000` stands unretested.
>
> **The S5e census is a different boot and must not be read as a second opinion on this one.** That
> guest booted 2026-09-27 10:07, after these measurements; its VTL1 `CR3` is **also** `0x1201000`
> but its page table is not the same one. Both are internally consistent, each with a self-map
> pointing at its own root:
>
> | | H4 / S0, 2026-09-26 boot | S5e, 2026-09-27 boot |
> |---|---|---|
> | VTL1 `CR3` | `0x1201000` | `0x1201000` |
> | self-map index | 388 | **463** (`0x8000000001201063`) |
> | present entries | 26 | 26 |
> | non-zero bytes | 123 | 122 |
> | first present entry | offset `0x850` | offset `0x830` (index 262) |
>
> **And that is a landmark trap worth the line it costs**: this record already says the VTL1 `CR3`
> is not reboot-stable, citing a boot that used `0x107593000`. What it did not say is that the
> value can also **repeat** across boots — so `CR3` equality is not evidence of the same boot, and
> reading it as such is what made two correct censuses look like a contradiction.

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

### S4 result, 2026-09-26: the hypercall refuses VTL1 writes symmetrically; the direct route accepts them

**The hypercall half is settled and the refusal is exactly symmetric with the read.** The direct
half is strongly evidenced and deliberately stops short of proof, for a reason recorded below.

The input layout came from `winhvr.sys!WinHvWriteGpa`'s disassembly on this build rather than from
the header that agrees with it — `PartitionId` +0x00, `VpIndex` +0x08, `ByteCount` +0x0C,
`BaseGpa` +0x10, `ControlFlags` +0x18, **`Data[16]` at +0x20**, call code `0x54`, `ByteCount`
capped at 16 — because a wrong layout here writes the right bytes to the wrong address.

**The method was a round-trip that changes nothing: read 16 bytes, write the *identical* bytes
back, read again.** Every write issued in this gate wrote bytes that were already there.

| probe | result |
|---|---|
| `ByteCount = 0` | `INVALID_PARAMETER` — nothing written whatever the layout |
| unmapped GPA, hypercall **write** | `SUCCESS` / `AccessResult = 1 Unmapped` — **the address field is honoured on the write path**, and nothing was written |
| VTL0 page, hypercall write | `SUCCESS` / `AccessResult = 0 Success` — page unchanged |
| VTL1 page, hypercall **read** | `SUCCESS` / `AccessResult = 2 ReadIntercept` |
| VTL1 page, hypercall **write** | `SUCCESS` / **`AccessResult = 3 WriteIntercept`** — page unchanged |

**So `HvCallWriteGpa` is refused on VTL1 exactly as `HvCallReadGpa` is**, with the result code the
ABI defines for it. The prediction made from `HV_ACCESS_GPA_RESULT_CODE` — that
`HvAccessGpaWriteIntercept` existing meant symmetric refusal was the thing to expect — held. And
`HV_STATUS` is `SUCCESS` on the refused write too, so the trap that makes a read look like zeros
makes a *write* look like it landed.

**The VTL1 target was chosen to be the most stable memory in the guest**: `securekernel.exe`'s PE
header page at GPA `0x00CD0000`, never written after load, verified stable across two reads, and
independently known since it must match the on-disk image — it read `4d5a9000…`, `MZ`. It is also
read through the **direct** route, because the hypercall cannot read it, making that a cross-route
round trip.

**The direct route accepts a VTL1 write, and the return value was checked before being believed.**
`SdkWritePhysicalMemory` returned `True` on that page — but writing identical bytes makes
"unchanged afterwards" the expected outcome of both a real write and a silent no-op, so the safe
round trip is also the one that cannot tell them apart. That is the zeroed-buffer defect wearing
another hat, so the return value got its own control:

| target | `SdkWritePhysicalMemory` |
|---|---|
| unmapped `0xFEC00000` | **False** |
| unmapped `0xFFFFF000` | **False** |
| VTL0 `0x00001000` | True |
| VTL1 `0x00CD0000` | **True** |

It refuses unmapped memory and accepts VTL1, so `True` discriminates rather than rubber-stamping.

**What this first pass established, and the gap it left.** Established: the direct route *accepts*
a write to a VTL1-protected page that the hypercall refuses, and refuses one to memory that cannot
be written. **Not** established at that point: that the bytes land — every write so far having
written bytes that were already there, which makes "unchanged afterwards" the expected outcome of
both a real write and a silent no-op. Only a write of **differing** bytes shows it, and the first
pass excluded that deliberately rather than reach for it on a Secure Kernel image page.

**That gap was then closed, with a target chosen so the risk was small rather than accepted** —
see the completion below. The short version: it lands.

**S4 completed, 2026-09-26: VTL1 is writable from the root by the direct route.** The gap left
above — that "accepts a write" is not "the bytes land" — is closed, by writing **differing** bytes
and reading them back.

| test | route | result |
|---|---|---|
| ordinary scratch page, differing bytes | hypercall | **lands** — pattern read back, and read back *identically through the direct route* |
| ordinary scratch page, differing bytes | direct | **lands** — pattern read back, and read back identically through the hypercall |
| VTL1 (`securekernel.exe` `.text` padding) | hypercall | **refused**, `AccessResult = 3 WriteIntercept`, page unchanged |
| VTL1 (same address) | **direct** | **LANDS** — `deadbeef…` written and read back, then restored |

**The mechanism check came first and it mattered.** Every VTL1 write before this one wrote bytes
that were already there, so neither route had been shown to write *anything* — the hypercall's
`AccessResult = Success` on VTL0 was as unproven as the direct route's `True`. A scratch page —
4096 bytes of zero, stable across two reads, outside every withheld run and every image — settled
both, and incidentally showed the two routes addressing the same memory: each read back the other's
pattern.

**That scratch page was not *reserved*, and the difference matters if anyone repeats this.** Two
all-zero reads and exclusion from known images are evidence that a page looks unused; they do not
establish that the guest does not own it, and the guest can allocate it between the check and the
write. The identical-bytes probes that preceded this were forgiving of being wrong about that; a
**differing-bytes** pattern is not. Repeat this against a **paused** guest, a page the guest has
explicitly reserved, or a snapshot that is discarded afterwards — not against a live guest on the
strength of the page looking quiet.

**The VTL1 target was alignment padding inside Secure Kernel's own code**, chosen as the
**lowest-risk** VTL1 memory rather than as inert memory, which is a distinction worth keeping.
Compilers pad between functions with `0xCC`, and that padding is *not guaranteed* never to be
executed or read: control can reach it through a mispredicted or unusual path, and the paragraph
below says outright that SKPG/HyperGuard may checksum the region it sits in. So "never executed and
never read" would be an overstatement; "the least consequential VTL1 bytes available, and still SK's
code section" is the accurate description.

The cave was located in the **on-disk** `securekernel.exe` first — a run of at least 96 `0xCC`
bytes in `.text`, written to at its centre — so what belonged there was known independently, the
in-memory pre-state could be checked against it before writing, and the restore was exact rather
than remembered. VA `0xFFFFF80220E79280`, GPA `0x00DC0280`, restored and verified.

**Step 3 is a control worth keeping:** the hypercall was attempted on *that* address too and
refused there as well, so `WriteIntercept` is a per-page property and not an artefact of the
earlier PE-header target.

**What the guest surviving does and does not show.** It ran on, uptime advancing, with no bugcheck.
That is **not** evidence that SKPG/HyperGuard does not checksum SK's code — the modification existed
for milliseconds between two reads, and a periodic integrity check has no particular reason to fall
inside that window. A *persistent* modification is an entirely different experiment and this says
nothing about it.

**The consequence for the route.** A software breakpoint is a memory patch, and the patch half is
now solved: an `int 3` can be planted in Secure Kernel by the direct route. What is missing is the
other half — **catching the trap** — which is exactly S5, and which nothing here advances. The
asymmetry is now complete and symmetrical in an unexpected way:

| | hypercall | direct route |
|---|---|---|
| VTL0 read | yes | yes |
| VTL0 write | yes | yes |
| **VTL1 read** | **ReadIntercept** | yes |
| **VTL1 write** | **WriteIntercept** | **yes** |

The hypervisor refuses the parent both directions on VTL1 through its own interface, and the
root's direct mapping of the guest's memory is subject to neither refusal.

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

**Measured as gate S2, 2026-09-27, and the recoverable half is smaller than this paragraph promised.**
The *names* recover completely: DbgEng opens the image as a target of its own, loads
`securekernel.pdb` from the public store, and resolves in both directions at whatever base the walk
supplies. **The types do not recover at all** — that public PDB carries no type records, so "PDB type
resolution" and "structure formatting" were never available to be given up or kept, by this route or
by H5a's. The result is below; what stands in this paragraph is the first half of its last sentence.

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

**H5b is scoped as `FOLLOWUPS.md` item 103.** Two things the scoping got wrong on the first pass are
worth stating here, because both were overstatements in the direction of closing doors:

- **The driver is a setup cost, not a shipping blocker.** H2's conclusion — that such a driver is a
  research capability rather than a feature — is about *distribution*, and this repo already ships
  capabilities behind documented manual setup. H5b ships as an opt-in research feature where the
  operator supplies the transport, and once that is in place the rest is drivable from it. What
  item 103's first measurement decides is therefore **how much setup a user needs**, not whether
  anything ships: is there a **driver-free source containing VTL1 pages**? A guest kernel crash
  dump cannot be one, since the guest's own NT cannot read VTL1 memory and so cannot write it into
  a dump — the same refusal H4 measured from outside. A **Hyper-V saved state** is written by the
  host and is the candidate.
- **Execution control is unresolved, not impossible — and the hypervisor half of it already
  works.** What this plan established is narrower than it was first written: SK ships no KD
  transport *of its own*. The **hypervisor's** VTL1 debug machinery is a separate thing, and the
  validation record took it further than a first reading of that record suggests: the activation
  failure **was** captured (`0x1D`, the debug free-page list exhausted), raising
  `hypervisordebugpages` from 1000 to 2000 **resolved** it — active port `0xC35C`, both buffers
  allocated — and its conclusion is *"the allocation failure is resolved, but Secure Kernel
  attachment is not"*, naming the next boundary as **Secure Kernel-side debugger
  startup/transport beyond the initialized hypervisor port**. So there is a working port with
  nothing on the guest side connecting to it, which sits uncomfortably beside SK shipping no KD
  transport — plausibly the same wall, and unproven either way, the record explicitly declining
  *"they do not establish that this Windows build lacks Secure Kernel debugging support"*. Item 103
  carries that as S5, which starts there rather than by re-running the completed trace.
- **Whether VTL1 can be *written* was measured as S4 on 2026-09-26, and the answer is per route.**
  `HvCallWriteGpa` (`0x0054`) writes VTL0 from the parent and is **refused on VTL1 with
  `AccessResult = 3 WriteIntercept`** — symmetric with the read, and predicted from the ABI before
  it was run. **The direct route writes VTL1** — differing bytes landed in `securekernel.exe`'s
  `.text` alignment padding and read back, then were restored and verified, with the guest running
  on. So VTL1 is **fully read/write from the root** by that route and refused in both directions by
  the hypercall. For a debugger that means the **patch** half of a software breakpoint is solved —
  an `int 3` can be planted — and the **catch** half is not, which is S5. Planting one before S5 is
  answered bugchecks the guest. The full result is under H4 above.

### S0 result, 2026-09-26: PASS — a Hyper-V saved state carries VTL1, and hands over the root

**A capture written by the host reaches everything H4 reached, with no driver, no test-signing and
no hypercall — and the page-table root comes out of the capture rather than being carried in.**
That is the strong form of the gate, and it moves the audience for S1–S3 from "an operator who has
weakened their bench" to "an operator who can take a checkpoint".

**The instrument is Microsoft's own and was already on this machine.**
`vmsavedstatedumpprovider.dll`, from the Windows Kit's `bin\10.0.26100.0\x64`, declared in
`VmSavedStateDump.h` beside it. It is **VTL-aware by declaration** —
`GetGuestEnabledVirtualTrustLevels`, `GetEnabledVirtualTrustLevels`,
`ForceActiveVirtualTrustLevel`, `IsActiveVirtualTrustLevelEnabled` — and the whole of this result is
whether that declaration extends to VTL1's *memory* and its `CR3`. It does. The probe is
[`tools/sk_savedstate_probe.py`](../../tools/sk_savedstate_probe.py), which reads the `REGISTER_ID`
enum out of the SDK header rather than hand-counting to `X64_RegisterCr3` (it is 46), and reads
`CR0`/`CR4`/`EFER` beside `CR3` so that a long-mode-consistent control register set says the
indexing is right rather than off by one.

**The captures.** Standard checkpoints (`CheckpointType = Standard`, so memory is included) of both
running guests, taken 2026-09-26 19:28:13Z and 19:28:23Z, ~1.7 GB each. Both guests stayed
`Running` throughout and were still `Operating normally` afterwards; both checkpoints were removed
when the run finished, and the H1 pinned ones were left alone.

#### The same boot, two routes

Every H4 landmark reproduces. The left column is the live route — a test-signed driver plus
`HvCallGetVpRegisters` — and the right is a file.

| landmark | H4, live (driver + hypercall) | S0, saved state (neither) |
|---|---|---|
| VTL1 `CR3` | `0x1201000` | `0x1201000` |
| PML4 self-map index | 388 | 388 |
| present entries in the PML4 | 26 | 26 |
| non-zero bytes in that page | 123 | 123 |
| first present entry's byte offset | `0x850` | `0x850` |
| reads to walk the page tables | 167 | **166** |
| leaf pages | 11,326 | 11,326 |
| `securekernel.exe` | VA `0xFFFFF80220D89000`, GPA `0x00CD0000` | identical |
| identified against the on-disk image | 18 sections, `0x94DED27F`, `0x175000` | identical |
| `KdDebuggerDataBlock` | `+0x1335E0`, `Size` `0x3A0` | identical |
| `SkLoadedModuleList` | `+0x127770` | identical |
| VTL1 modules | 6, named | identical — same six, same bases, same sizes |
| `KDBG` tags in a 32768-page scan | 4, exactly one with `Size` `0x3A0` | 4, exactly one with `Size` `0x3A0` |

The one cell that is not a repeat is **166 against 167**, and it is not worth chasing: H4's own
breakdown — 11 PDPTs, 24 PDs, 130 PTs, plus the root — sums to 166.

**The provider's translator agrees with our walk.** `GuestVirtualAddressToPhysicalAddress` at the
forced VTL1, given SK's base VA, returns `0x00CD0000` — the GPA the four-level descent had already
reached from the `CR3`. Two translators sharing only the capture is what makes either believable,
and it gives S1's decode layer a differential oracle that costs nothing.

**The `KDBG` search found four tags and three of them are noise**, which is the argument for
reporting `Size` instead of matching it. The three carry a `Size` of `0x2C058948`, `0` and `0`, and
`KernBase` values that are plainly instruction bytes; the fourth carries `Size` `0x3A0` and a
`KernBase` equal to the base the PE walk established independently. Validation against the base is
the step that separates them, and an exact-match needle built from a remembered constant would have
returned the noise or nothing at all.

#### What the walk leaves out, and why enumerating every VA is the wrong target

**Secure Kernel's VTL1 page tables are recursively self-mapped, so one physical page is a PML4, a
PDPT, a PD *and* a PT depending on the route taken to it.** Two measurements, and they have
different provenance, which matters:

| | guarded walk, 2026-09-26 | guarded walk, 2026-09-25 | sweep that **follows** the self-map |
|---|---|---|---|
| table reads | 166 | 179 | 215 |
| tables decoded | 166 | **215** — 36 served at more than one level | — |
| alias prefixes skipped | **6,773** | 7,803 | — |
| leaf mappings / distinct pages | 11,326 / **~4,200** | 16,437 / 4,545 | — |
| worst-case fan-in | — | — | one PD referenced **1023×**, one PT **2300×**, the root present at all four levels |

The leaf/distinct-page ratio is a reading rather than a constant — 4,189, 4,194 and 4,217 on
three captures of the 2026-09-26 boot, the guest having run in between, while the 11,326
mappings and 166 table reads were identical on all three. The third column is a deliberate
diagnostic, not the production walk: it does **not** skip the
self-map entry, which is how it reaches the page tables *as* mapped data and shows why enumerating
every prefix is combinatorial rather than merely expensive. The first two are the walk as it runs,
and the middle column's 215 decodes against 179 reads is the same phenomenon seen from inside it —
36 tables genuinely serving at more than one level on that boot, and none on the other.

So the walk expands each table **once per level** and now **counts** what that skips — 6,773 alias
prefixes on the 2026-09-26 capture, reported beside the leaves rather than passed over in silence.
The distinction matters because the walk's own contract is that an incomplete answer says so;
before this round it did not, and a review finding said exactly that.

**The remedy that finding proposed was built and measured, and it does not work here.** Cutting
cycles by descent path instead — so an aliased table is walked again under each prefix — turned a
166-read, 11,326-leaf walk that identifies the image into one that **exhausted a 200,000-leaf
budget over 509 distinct pages and identified nothing**. Recorded because the finding's *fact* is
right and its remedy is not: on a self-mapped tree, the complete VA enumeration it asks for is the
thing that cannot terminate usefully. What the identification rests on instead is two independent
agreements — the provider's own translator on the GPA, and `KernBase` inside the data block — both
of which hold.

Two smaller readings from the same instrumentation. **No large-page mapping appears in SK's VTL1
tables on this build** (`malformed_entries` 0, every leaf 4 KiB), which is why an address-masking
defect in the large-page path stayed latent until review found it by reading: in a large PDPTE or
PDE bit 12 is the PAT flag rather than the low bit of the frame, so masking at 4 KiB granularity
lands a page high. And the physical scan's four `KDBG` tags are the same four the image search
finds, three of them coincidental byte sequences.

#### A different boot, and why the root has to come from the capture

The H1 checkpoint of the same guest, taken 2026-09-25 20:32Z, is a **different boot**, and reading
it is the control that says this is a file being read rather than a channel to the running guest.

| | capture of 2026-09-25 | capture of 2026-09-26 |
|---|---|---|
| VTL1 `CR3` | **`0x107593000`** | **`0x1201000`** |
| PML4 self-map index | **309** | **388** |
| present entries | **29** | **26** |
| `securekernel.exe` VA | **`0xFFFFF8070EDA9000`** | **`0xFFFFF80220D89000`** |
| `securekernel.exe` GPA | `0x00CD0000` | `0x00CD0000` |
| `KdDebuggerDataBlock` | `+0x1335E0`, `Size` `0x3A0` | same |
| `SkLoadedModuleList` | `+0x127770` | same |
| VTL1 modules | the same six | the same six |
| leaf pages from the walk | 16,437 | 11,326 |

**So the VTL1 `CR3` is not reboot-stable, and this plan's own landmark table said it was.** H4
measured it identical across the two boots it compared and recorded *"repeated across a reboot:
yes"*; a third boot has a different one. Nothing about H4 falls — it measured what it measured —
but the generalisation does, and it is the exact generalisation an implementer would have
hard-coded. The **image-relative offsets** are the coordinates that survive, as the README already
said; the GPA `0x00CD0000` survived these two boots as well, which was previously a single
observation and is now two.

**A seventh PE image appears on the earlier boot** — identity-identical to `symcryptk.dll`
(`0xD000`, `0x98293ECD`) at VA `0xFFFFB300199C3000`, outside the module list's range and not named
by it. Recorded rather than explained, and it is the counterexample that makes the identification
rule non-obvious: **matching the disk image says the bytes are that image, not that this VA is the
base it was loaded at.** A duplicate mapping matches on all three fields, and which of two
mappings the walk reaches first is prefix order. So the probe tries **every** matching candidate
until one is confirmed, and reports the attempt for each. One candidate on both captures here —
but the mechanism that would have produced two is in the table above.

**Confirmation is two independent things agreeing, not one.** A `KDBG` block whose `KernBase`
equals the candidate's base is necessary and is *not* sufficient: the block is populated
selectively — 26 of its 116 qwords — so a `PsLoadedModuleList` that is stale, zero or read at
the wrong alignment still yields plausible names and sizes rather than an error. A candidate is
accepted only when the list walked from that field has a **first entry whose `DllBase` is the
candidate's base**; a hit that fails it is recorded with its reason and the search moves to the
next hit, then the next candidate. On every capture taken here exactly one of the four `KDBG`
tags passes both.

#### It is a file, not a live channel

The capture was copied out of `D:\Hyper-V\Virtual Machines\Snapshots\` into a scratch directory and
read there with `--vmrs` and **no VM named**, so neither WMI nor Hyper-V was consulted. Same
`CR3` `0x107593000`, same SK, same six modules, same `KDBG`. Together with the different-boot
result above — the running guest's VTL1 `CR3` is `0x1201000`, and that copy insists on
`0x107593000` — the source is demonstrably the bytes on disk. **Capture on the Hyper-V host,
analyse anywhere.**

**And nothing was loaded to do it.** No `hvmm` or `h3probe` service exists on this host, and the
CodeIntegrity log's most recent entries are from boot with none during any of these runs — which is
worth checking rather than assuming, because H2's driver-free probe failed precisely by installing
a driver while configured not to.

#### The control: the VBS-off twin

H4's Control 1, repeated on the new source, one procedure against both captures.

| | VBS **on** | VBS **off** |
|---|---|---|
| `GetGuestEnabledVirtualTrustLevels` | `0b11` | **`0b1`** |
| `ForceActiveVirtualTrustLevel(vp0, 1)` | succeeds, VTL enabled | **refused**, `0xC0370509` |
| pages scanned physically | 32768 | 32768 |
| PE image headers | 86-101 | **100-143** |
| matching `securekernel.exe` | **1**, GPA `0x00CD0000` | **0** |
| `KDBG` tags | 4 | **0** |

**The two PE-header counts move and the other rows do not, which is worth saying rather than
picking one.** Those are three captures of the *same boot* across two hours, and a running guest's
physical memory changes between them — so a count of PE headers in a fixed 32768-page window is a
reading of what happened to be resident, not a property of the guest. What is stable across every
capture taken here is what the control actually rests on: **1 against 0** matching
`securekernel.exe`, **4 against 0** `KDBG` tags, and the direction of the header count, the
VBS-off guest yielding more every time.

**And the negatives are earned rather than assumed**, which is a separate claim and now a
measured one: every capture reports `reads.failed: 0` with no unreadable page in either
scan, so the control found no Secure Kernel in 32,768 pages it actually read. A scan that
had quietly skipped some fraction of them would have produced the same zero, and until this
round nothing in the output could tell the two apart.

**The `KDBG` half of that scan searches across page boundaries, and doing so found a tag that had
been invisible.** A PE image is page-aligned, so a per-page test for `MZ` cannot miss one; a
debugger data block sits at an arbitrary offset, and a page-local search cannot see a tag split
across the boundary or decode one whose fields continue into the next page — about 1.4% of
placements, silently absent from a negative the control rests on. Pairing each page with its
physical successor turned up a **fifth** tag on the 2026-09-25 capture, at GPA `0x39E3F90`, which
is another coincidental byte sequence with a junk `KernBase` rather than a block. The 2026-09-26
capture still has exactly four, and the control still has **none** — so nothing in the table above
moves, and the reason it does not is now something that was checked rather than something the
search was incapable of noticing.

**What the physical scan still cannot see is stated rather than fixed, and its size was
measured.** Two pages adjacent in *virtual* memory can sit in frames that are not adjacent, and
a record split across them cannot be joined without page tables — which is the one thing this
route is defined as not having, and which the VBS-off control does not possess at all. Making
the physical scan virtual would delete the independence that makes it a cross-check of the walk
rather than a second reading of it, so the scan carries the limit in a `limitation` field beside
its counts. The exposure on this build: `securekernel.exe` spans **373 pages with one physical
discontinuity**, in runs of 304 and 69, and the debugger data block sits at page 307 offset
`0x5E0` — inside a frame rather than across one, with an adjacent successor. The image-side
search reads by VA through the translator and has no such blind spot; it is the authoritative
one, and the control's own result rests first on `GetGuestEnabledVirtualTrustLevels` answering
`0b1` and the VTL1 switch being refused by name, with the scan as corroboration.

**The refusal is named, not silent.** `0xC0370509` is
`VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED` — the provider ships a typed error for exactly this
condition, and the probe keeps it apart from a *query* that fails after a switch that worked. That
separation is the whole of this arm: one handler over both would let a provider that cannot return
some register report a guest as having no Secure Kernel, which is the same collapse of *refused*
into *absent* the read seam is guarded against, one level up. That answers S1's third fixture requirement from the source side rather than from our
own code: this source does not collapse *refused*, *not captured* and *zeros* into an empty buffer.
Short reads are reported as a byte count too, so the seam can carry *why* rather than only
bytes-or-not.

**And the positive arm is load-bearing.** The control guest yields **more** PE headers than the VBS
guest, 143 against 101 and 100 against 86, so the scan demonstrably works there; it simply finds no Secure Kernel and
not one `KDBG` tag of any size. A scan that found nothing anywhere would be indistinguishable from
a broken one.

#### What this does not establish

- **It is a snapshot.** There is no execution control here and S5 is untouched by it — if anything
  a fixed capture makes the inspector-versus-debugger question sharper rather than answering it.
- **It says nothing about writes.** S4's result is about the two *live* routes; a capture is not
  the guest, and writing to a `.vmrs` would change a file, not VTL1.
- **It does not retire the driver.** The live route is still the only one that reads a guest as it
  runs. What this adds is a second source with a much lower setup cost, not a replacement.
- **Only the checkpoint form was run.** `Save-VM` also produces a `.vmrs`, and
  `LocateSavedStateFiles` answers with the older `.bin`/`.vsv` pair for a capture written by an
  earlier Hyper-V. The probe selects that pair and loads it through `LoadSavedStateFiles` — the
  **selection** is pinned by a test, and the **provider call** is unexercised, because this bench
  has never produced a capture of that form.
- **One host, one Hyper-V version, one guest build**, and a guest that is not hardware-isolated. A
  confidential VM's memory is not the host's to write into a capture, so nothing here should be
  read as reaching one.
- **The operator still needs the SDK** for the provider DLL — a download, not a posture change, and
  the interesting half of the comparison.

#### What it changes downstream

- **S1's source contract is confirmed and satisfied.** `read(gpa, len)` plus `root()` is exactly
  what this source offers, the root arriving as a register read rather than as a constant. The
  different-boot table above is the measured reason the root belongs in the contract.
- **S1 gains a differential oracle for free** in the provider's own VA→GPA translator, which is not
  our code and agreed on the one address it was asked about.
- **The audience widens.** An operator with no test-signing, no weakened Code Integrity and no
  loaded driver can run S1–S3 against a captured guest. The driver-backed live source remains for
  work a snapshot cannot do.
- **S3's design question gets a default.** A saved state is a fixed snapshot with no debuggee, which
  is the sessionless shape — so the awkward fit with this server's session model is now the common
  case rather than a hypothetical, and S5 remains the thing that could bring execution state back.

#### Is a capture carrying VTL1 a boundary crossing?

Asked directly, 2026-09-27, because the reasonable reaction to "a checkpoint hands over Secure
Kernel" is to wonder whether Microsoft should hear about it. **The evidence says this is documented
behaviour inside the boundary VBS claims, so there is nothing here to report about VTL1 reachability
itself.** Three cases that *would* be reportable are named below, and two of them have since been
measured: the encryption one came back negative (S0 arm 4), and the **file-ACL one is true on this
bench** — which is a configuration matter rather than a product defect, but it is also the reason the
third reading below no longer claims what it used to.

Three readings, the first two measured on this host:

1. **The SDK documents the capability in terms.**
   `C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\vmsavedstatedump.h`, at
   `ForceActiveVirtualTrustLevel`: *"Forces the current Virtual Trust Level of a given virtual
   processor. This is useful to force register state to and virtual address translation to come from
   a different VTL."* Beside it `GetGuestEnabledVirtualTrustLevels`, `GetEnabledVirtualTrustLevels`,
   `GetActiveVirtualTrustLevel`, and a `GetGuestOsInfo` that takes a VTL parameter. Reading a
   capture's VTL1 register state and translating its VTL1 addresses is an API surface Microsoft
   shipped, commented and versioned — which is what S0 used, as documented.
2. **The mitigation for the at-rest half exists and is switched off here.** `Get-VMSecurity` on both
   lab guests: `TpmEnabled True`, **`EncryptStateAndVmMigrationTraffic False`**, `Shielded False`.
   The knob whose job is to encrypt saved state is available and unset; a mitigation being offered
   is design intent stated out loud. **Whether it covers VTL1 in a capture was then measured — arm 4
   below — and it does.**
3. **The boundary VBS claims is VTL0 → VTL1 *inside the guest*.** For a guest that is not
   hardware-isolated the host partition is inside the TCB, which this document's own H3 and H4
   demonstrate from the other direction: the same pages were read from a *running* guest with a
   driver in the root partition. So a guest's VTL1 is **the host's to protect**, and reading it from
   the host is not a boundary being crossed — which is what makes the *setup cost* the thing S0 was
   run to measure.

   **This reading used to say "every route here needs Hyper-V Administrator", and that is false.**
   The live routes do — H3 and H4 need a driver loaded and the Hyper-V APIs need the role. A
   **capture is a file**, and the `--vmrs` route needs nothing but read access to it, so the file's
   ACL is the gate rather than the Hyper-V role. On this bench that ACL is inherited and permissive,
   which is measured below and is the second reportable case — so the sentence contradicted a
   measurement three paragraphs later in its own document. What survives is the claim above: the
   host's TCB contains the guest's VTL1 either way, and who on the host can reach a capture is the
   operator's ACL to set.

**What the Secure Kernel *base* is worth, separately**, since that is the landmark that prompted the
question: against the host it was never a secret, and it does not reach VTL0 by this route — a guest
kernel cannot read the host's checkpoint file. The content that would matter is VTL1 **data**: IUM
trustlet and LSA Isolated memory. **Whether those pages are in the capture is unmeasured here**;
nothing in S0 or S1 looked, and neither should be read as saying they are or are not.

**Three things that would be reportable, and the state of each:**

- **VTL1 out of a capture taken with `EncryptStateAndVmMigrationTraffic = $true`**, or from a
  Shielded VM. That would be encryption not covering what it claims. **Measured 2026-09-27 as S0 arm
  4, and it does not happen**: with the setting on, no VTL1 comes out, on the VBS guest as well as
  on the control. It does not come out because `LoadSavedStateFile` **never returns** — the provider
  fast-fails, `0xC0000409` (`STATUS_STACK_BUFFER_OVERRUN`), WER `BEX64`, faulting module
  `vmsavedstatedumpprovider.dll 10.0.26100.7705` at offset `0xD569`. A *fresh plaintext* capture of
  the same guest taken minutes later reads normally with the identical command, which is what
  attributes the failure to the setting rather than to the capture being new. So the mitigation
  holds and this verdict stands — **and the arm turned up a different defect worth reporting**: a
  documented SDK API crashing on an input Hyper-V itself wrote, which is a robustness and
  availability bug rather than a boundary bypass. It is written up in
  [`vmsavedstatedumpprovider-crash.md`](vmsavedstatedumpprovider-crash.md). `0xC0000409` is the
  status every `__fastfail` raises, so its legacy name (`STATUS_STACK_BUFFER_OVERRUN`) is not a
  diagnosis — this file said "the corruption being detected" for one commit, which is the trap
  `src/fault.rs` exists to stop. The subcode was then measured: **`0x7 FAST_FAIL_FATAL_APP_EXIT`**,
  from `gsl::details::terminate` under
  `PartitionStateParser::GetPartitionStateVirtualProcessors` — a GSL contract violation while
  parsing the partition state, which is a robustness bug and not a mitigation firing.

  **What the arm does and does not establish about the file.** The payload *was* measured, which an
  earlier version of this paragraph denied: the encrypted and plaintext captures share the container
  magic `14 20 28 01` and the field at `+0x08`, while payload entropy is **8.000** bits/byte against
  **7.246** — a well-formed container whose body is at maximal entropy. That reading matters more
  than the provider's behaviour, because the arm ran **on the owning host with the VM's key protector
  available**: in that context a *successful* read would have been authorized decryption and would
  have said nothing about how the bytes are stored, so provider-level reachability could never have
  been the evidence. Still unestablished: the encrypted checkpoint was never `Apply-VMSnapshot`ed, so
  Hyper-V reading what it wrote is an inference, and Shielded VMs and a capture read from a host
  *without* the guardian key are both untested.
- **A principal below Hyper-V Administrator.** Reading a checkpoint needs read access to a *file*,
  not the Hyper-V role — so the file's ACL is the boundary, and **on this bench it is wide open**:
  `D:\Hyper-V\Virtual Machines\Snapshots\<id>.vmrs` (1,984,630,784 bytes) grants
  `BUILTIN\Users: ReadAndExecute` and `NT AUTHORITY\Authenticated Users: Modify`. Measured
  2026-09-27, and **inherited rather than set by Hyper-V**: both ACEs carry the `ID` flag in the
  SDDL and match `D:\`'s root ACL, which is the Windows default for a non-system volume, while the
  two ACEs Hyper-V *does* add (the VM's own SID and a capability SID) are the non-inherited ones. So
  Hyper-V adds what it needs and does not strip what it inherited, and a VM whose storage sits on a
  default-ACL'd data volume has its guest RAM readable by any authenticated local user. That is a
  **configuration hazard rather than a product defect** — the storage path is the administrator's
  choice — but it is the one of these three that is true here today, and it is worth fixing on any
  bench that keeps VM files off the system volume.
- **A hardware-isolated guest** (SEV-SNP / TDX), where the host is outside the TCB by construction.
  Out of scope by this document's own "Explicitly out of scope", and nothing here reaches one.

**One measured fact about arm 4's cost**, since it decides how the arm is run:
`Set-VMSecurity -EncryptStateAndVmMigrationTraffic $true` on a running VM is refused —
*"The SecuritySettingData property cannot be modified because the virtual machine is running"* — so
the arm needs the guest powered off and is a scheduled lab mutation, not a probe.

### S1 result, 2026-09-27: the decode layer is Rust in this server, and it reproduces the probe

S0 answered *whether* a driver-free source carries VTL1. S1 is the decode over that source expressed
so the source is a parameter, and it is now `src/sk.rs` (the seam, the guarded walk, PE
identification, the `KdDebuggerDataBlock` decode, the `SkLoadedModuleList` walk),
`src/savedstate.rs` (the SDK provider bound from Rust) and `windbg-mcp --sk-inspect` (a
command-line role, **not** an MCP tool — that is S3). `FOLLOWUPS.md` item 103 carries the full
record; what belongs here is the measurement and what it does not cover.

**The run, 2026-09-27, against the `H1 pinned 26200.9457 VBS+HVCI` checkpoint of the VBS guest** —
the **third-boot** capture, the one whose root is not `0x1201000`. Every capture-derived landmark in
this document reproduced, from an independent implementation in a different language:

| landmark | S0's probe | `src/sk.rs` |
|---|---|---|
| VTL1 `CR3` | `0x107593000` | `0x107593000` |
| root page: present entries / self-map index | 29 / 309 | 29 / 309 |
| `securekernel.exe` GPA | `0x00CD0000` | `0xCD0000` |
| `securekernel.exe` base VA | `0xFFFFF8070EDA9000` | `0xFFFFF8070EDA9000` |
| `KdDebuggerDataBlock` | `+0x1335E0`, `Size` `0x3A0` | `+0x1335E0`, `Size` `0x3A0` |
| `SkLoadedModuleList` | `+0x127770` | `+0x127770` |
| VTL1 modules | the same six | the same six, same sizes |
| `KDBG` tags found / accepted | 4 / 1 | 4 / 1 |
| table reads / decodes | 179 / 215 | 179 / 215 |

**Two checks the probe did not run, and both are the reason this is worth more than a second
opinion.** The **structural route** — find a loader entry whose `DllBase` is the identified base with
`SizeOfImage` sixteen bytes later, then follow its `Blink` — found the list head
`0xFFFFF8070EED0770` at entry `0xFFFFB700022020C0`, which is **the same head the debugger data block
names**, reached without reading the block at all. And the **provider's own translator**
(`GuestVirtualAddressToPhysicalAddress`, which is Microsoft's code and not ours) agreed with the walk
on **373 of 373** pages of the image, with **0** pages mapped by one and not the other. The sample is
taken from the *image's* `SizeOfImage` rather than from the walk's own leaves, deliberately: comparing
on the addresses the walk found would only ask whether we agree about what we found, and a page the
walk missed would be invisible to it.

Figures the probe has no equivalent for, recorded so a later build can be compared: **16,437** leaf
mappings over **4,545** distinct pages, **7,803** alias prefixes counted as unexpanded, **0**
malformed entries, **0** unreadable tables, **18,253** physical reads of which **0** failed,
**74,764,288** bytes read.

**The control arm, same command against the VBS-off twin** (`H1 control 26200.9457 VBS off`):
partition VTLs `0x1` against the VBS guest's `0x3`, and `ForceActiveVirtualTrustLevel(vp0, vtl1)`
refused with `0xC0370509` (`VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED`). Reported as the **switch**
being refused, which is deliberately not the same answer as a register that did not come back — a
provider that cannot return one register must not read as a guest with no Secure Kernel.

#### What the S1 result does not establish

- **One capture, one build, one host.** The `0x1201000` capture is no longer on this bench, so the
  reboot-moved root remains pinned by S0's record rather than re-measured by this implementation.
- **The `.bin`/`.vsv` pair is selected and never called.** Same gap S0 recorded, for the same
  reason: no capture of that form has ever been produced here.
- **Nothing was read from a running guest.** A capture cannot refuse a read, so the refusal path
  through the seam is exercised by synthetic fixtures alone; the hypercall route that answers
  `HV_STATUS_SUCCESS` with a per-access `ReadIntercept` is not built.
- **No symbol was resolved.** That was S2's, and the base this produces is its input; S2 has since
  run, below.
- **34 synthetic tests are not a second capture.** They pin the rules — the self-map, the large-page
  frame mask, a tag straddling a page boundary, a stale list under a matching `KernBase`, poison
  against zeros — and six of them were mutation-verified. That is a guard against regression, not
  more evidence about Windows.

### S2 result, 2026-09-27: the PDB agrees with the scan, and there are no types to have

S1 found the landmarks by searching the capture. S2 asks a `securekernel.pdb` that has never seen
that capture where the same landmarks are, and the two agree to the byte. It is `src/sksym.rs`, and
`windbg-mcp --sk-inspect --symbols` drives it. `FOLLOWUPS.md` item 103 carries the full record;
what belongs here is the measurement, the mechanism, and the half that is not available.

**Image-only symbol resolution needs no live target and no new primitive.** DbgEng accepts a PE
image as a target in its own right — `OpenDumpFileWide` on `C:\Windows\System32\securekernel.exe`
gives a session with exactly **one** module, at the image's own `ImageBase` `0x140000000`, and
`.reload /f` against it fetches the PDB from the public store. So this uses `dbgscope` methods that
already existed and touches neither the `execute` text hatch nor a new engine call. Its own work is
the rebase from `0x140000000` onto the base the walk found.

**The agreement, against the same `H1 pinned 26200.9457 VBS+HVCI` capture S1 ran on.** Image
10.0.26100.9457, PDB key `C2C0D1A62E3269F40C69EA44FDB230C41`, `symbols: pdb`:

| landmark | found by searching the capture (S0, S1) | read out of the PDB (S2) |
|---|---|---|
| `KdDebuggerDataBlock` RVA | `+0x1335E0` | `+0x1335E0` |
| `SkLoadedModuleList` RVA | `+0x127770` | `+0x127770` |
| `KdDebuggerDataBlock` in the guest | `0xFFFFF8070EEDC5E0` | `0xFFFFF8070EEDC5E0` |
| `SkLoadedModuleList` in the guest | `0xFFFFF8070EED0770` | `0xFFFFF8070EED0770` |

Asked the other way round as well, which is a separate engine call and can fail differently: the
engine names each of those two guest addresses with displacement **0**. That matters because
`GetNameByOffset` answers with the nearest *preceding* symbol at any address in the module, so a
non-zero displacement is a miss dressed as a hit. Every S1 figure in the sections above reproduced
unchanged in the same run.

**So the module list now has a third route, and it is the only one that needs no debugger data
block.** The tag scan cannot find `SkLoadedModuleList` — it is a bare `LIST_ENTRY` with no signature
— which is why H4 read it out of the block and why the structural `Blink` walk exists as a
cross-check. A PDB names it directly. The scan stays primary: a host with no symbol store, or a build
whose PDB is not served, has only that route.

**The control arm keeps the two halves apart.** Same command against the VBS-off twin: the symbols
load and report normally while the capture refuses the VTL switch with `0xC0370509`. A run where the
engine had symbols and the capture had no VTL1 must not read like a run where neither half worked, so
the text report and the JSON carry them as separate answers.

#### What S2 does not establish

- **The public `securekernel.pdb` carries no type information.** `dt securekernel!_LIST_ENTRY` is
  *not found*, `dt securekernel!*` lists symbols rather than types, every data symbol prints
  `= <no type information>` under `x /t`, and four `GetTypeId` probes in the shipped code all come
  back **`E_NOINTERFACE` (`0x80004002`)** — *no such interface supported*, which is the engine
  declining to service type queries for this module at all rather than four names it searched for and
  did not find. Structure walks over VTL1 therefore stay hand-decoded the way `src/sk.rs` does them. A
  finite set of name probes cannot *prove* a PDB has no types, which is why the report prints the
  engine's own reason for each rather than a verdict — and that reason is what makes the four
  negatives worth more than a sample of four.
- **`SymbolKind::has_type_info` says otherwise and is wrong here.** It reads `DEBUG_SYMTYPE_PDB` as
  private type information, and this module is `symbols: pdb` with no types: the engine does not
  distinguish a stripped public PDB from a private one. Ask for a type; do not ask the kind.
- **Rebasing inside the engine is available and is a trap.** `.reload /i
  securekernel.exe=fffff8070eda9000,175000` with `.exepath` set does load the image a second time at
  the guest's base and does resolve the same PDB there — but the name collides, so the second module
  is `securekernel_exe` and **both** answer to `securekernel!`. With the pair loaded,
  `? securekernel!KdDebuggerDataBlock` answers `0x1401335E0`: the *preferred* base. Measured on this
  bench; it is why the rebase is arithmetic outside the engine.
- **Two symbols, one PDB, one build, one host.** The gate resolves the landmarks S1 already found. It
  does not enumerate the PDB, and it cannot name the other five VTL1 modules — their symbols are in
  their own images, which nothing here opens.
- **A host with no symbols is refused, and what that refusal reads is measured.** `Symbols::open`
  makes the engine issue a resolving query — one deliberately-failing lookup, which is what settles a
  deferred module — and then **requires** a symbol provider, naming the kind and the forced reload's
  own error when there is none, before the capture is read. Pointed at a symbol path that reaches no
  store, the module comes back **`Export`** rather than `Deferred`: DbgEng falls back to the image's
  export table, and the run reports *no symbols loaded (the module still reads Export after a
  resolving query)* while the decode carries on. Refusing that costs nothing here — with symbols
  failing to load, `x securekernel!KdDebuggerDataBlock` and `x securekernel!SkLoadedModuleList` both
  answer nothing against roughly 280 exported names, so neither landmark is reachable from exports.
  The first draft of this gate accepted a still-deferred module on the grounds that `Deferred` means
  "nothing has looked yet"; after the probe it does not, and three review rounds on
  [#399](https://github.com/glslang/windbg-mcp/pull/399) were the cost of that distinction — a module
  left deferred could load its PDB on the first *landmark* query, after the only check that the PDB
  belongs to this image. What is still unmeasured is a PDB that is served and **wrong**.

### S5a result, 2026-09-27: the hypervisor's VTL1 debug port has no sender in Secure Kernel

**The two facts are one fact.** The record held them separately and never joined them: the
hypervisor's root VTL1 debug context is live — active port `0xC35C` (50012), both buffers allocated
once `hypervisordebugpages` went 1000 → 2000 — and nothing ever connects to it; and post-26100
`securekernel.exe` ships no KD transport. S5's specification says to start by asking whether those
are the **same wall**. They are, for the route this scan covers: **Secure Kernel has no hypercall
or MSR route to that port.** Across ten builds it never writes a debug control code as an immediate
at any instruction boundary the scan recognises, never materialises a synthetic-debugger MSR number
at all, and contains no hypercall instruction of its own. That is a statement about those readings
over those ten images, not a proof that no mechanism of any kind exists — the limits are named
below, and S5 stays open.

Entirely offline. No VM queried, attached, reconfigured or rebooted; no BCD change; no driver; no
`int 3`; no reservation change; no re-capture of the activation return — the three "do not"s in the
S5 specification are untouched. The instrument is
[`tools/sk_hypercall_scan.py`](../../tools/sk_hypercall_scan.py), a pure PE parse plus capstone; it
needs no debugger, and symbols are used only to *name* what the scan already found structurally.

#### The mechanism, and the control that identifies it

A VTL1 debuggee cannot own the NIC — the hypervisor does, which is the whole point of
`hypervisordebug` multiplexing three ports on one wire — so a debuggee hands KD packets to the
hypervisor. **`kdhvcom.dll` is Windows' own implementation of exactly that**, and it is the positive
control: without it a negative on Secure Kernel would be indistinguishable from a broken scanner.

| reading | `C:\Windows\System32\kdhvcom.dll`, sha256 `CD4BD901326BBF31…` |
|---|---|
| exports | `KdInitialize`, `KdPower`, `KdReceivePacket`, `KdSendPacket`, `KdSetHiberRange` — the five-function KD transport contract, the same five `kdnet.dll` exports |
| imports | six `ntoskrnl.exe` symbols, none hypercall-related |
| hypercall instructions | **2** — `vmcall` at `+001FE0`, `vmmcall` at `+001FF0` (Intel and AMD) |
| control codes written | **3**, and only 3: `0x69` at `+001A6F`, `0x6B` at `+001B74`, `0x6A` at `+001C7F`, each `mov dword ptr [rsp+X], imm` |

**The code-to-name mapping is pinned by this binary's structure rather than by a cited table.** By
call-graph reachability from each export: `KdInitialize` reaches `0x6B` **only**, `KdSendPacket` and
`KdReceivePacket` reach all three, `KdPower` and `KdSetHiberRange` reach none. An initialize that
reaches only one code, and a send/receive pair that share it plus two others, is
`HvResetDebugSession` with `HvPostDebugData`/`HvRetrieveDebugData` beside it.

#### The subject: ten `securekernel.exe` builds, 19041.207 to 29667.1000

**No sample contains a `vmcall` or `vmmcall` instruction at all**, so every hypercall Secure Kernel
makes goes through the hypercall code page, which lives in two globals. That makes the set of
functions that can reach the hypervisor *derivable* rather than a list of names to keep up to date —
which matters, because the name moved: the generic invoker is `HvcallpInitiateHypercall` before
26100 and `HvcallInitiateHypercall` after, and a first pass that asked for the later spelling
resolved nothing on nine of ten samples and reported "0 hypercall sites" for every one of them.

**The scan makes two readings and only the first decides anything**, which is the shape the first
version of this gate got wrong by resting everything on one evaluator. **Reading A** — are the debug
codes and the SynDbg MSR numbers present as immediates, and are there hypercall instructions — is
taken over *every executable byte*, by passes chosen so that no one of them has to be trusted about
where instructions begin:

- **instruction boundaries from four seeds**, unioned: the functions the exception directory
  declares, a linear sweep of each executable section, a **recursive descent from every direct call
  and jump target** iterated to a fixpoint, and the **export table**. The last two are what reach
  **leaf functions**, which need no unwind data and are therefore absent from `.pdata` entirely —
  and which a linear sweep can stride straight past if it desynchronises on embedded data. A leaf
  is reached by being called, so its entry is a call target; one reachable *only* through an export
  is not, which is why the export table is seeded too. That last seed is measured as a **no-op on
  these images** — every exported entry is already reached by another seed, delta zero on the
  builds checked — so it closes a hole in the reasoning rather than in the result, and is recorded
  that way rather than as a finding.
- **a raw opcode byte search** for `vmcall`, `vmmcall`, `rdmsr` and `wrmsr`, which cannot
  desynchronise because it does not decode at all.
- **a byte-anchored search for the constants themselves.** An immediate is encoded little-endian,
  so the low bytes of the value appear verbatim whatever the operand width. Finding those bytes and
  decoding from all sixteen starts that could cover them locates any instruction carrying the value
  without knowing where instructions begin. For the SynDbg MSR numbers this is both sound and
  precise, because `0x400000Fx` cannot be encoded as an `imm8` or `imm16` — the full four-byte
  pattern must be present. For the three debug codes, whose low byte is one byte, it is sound but
  noisy, so it is reported as a **superset** rather than used as the reading.

**Reading B**, the hypercall repertoire, comes from an abstract evaluator that walks in address
order without following control flow; it is a heuristic lower bound whose job is to be the negative
control, and it is never allowed to produce the verdict.

| build | sha256[:16] | executable bytes | `0069/6A/6B` written | `vmcall` | SynDbg MSR | wrapper call sites | codes resolved |
|---|---|---|---|---|---|---|---|
| 19041.207 | `7F85188451EE4671` | 653,715 | **0** | 0 | 0 | 30 | 21 |
| 19041.7725 † | `8C7135D0E37E2943` | 660,803 | **0** | 0 | 0 | 30 | 21 |
| 22621.317 † | `49F6196295058CD4` | 752,348 | **0** | 0 | 0 | 29 | 19 |
| 22621.7582 † | `4FBF5EAD32F49A12` | 780,892 | **0** | 0 | 0 | 30 | 20 |
| 28000.2952 | `BA493451314B11A1` | 1,065,757 | **0** | 0 | 0 | 39 | 25 |
| 29617.1000 | `BB29E5EFCFEE50FD` | 1,083,601 | **0** | 0 | 0 | 39 | 25 |
| 29639.1000 | `28FAEB48277EE5F8` | 1,103,817 | **0** | 0 | 0 | 39 | 25 |
| 29648.1000 | `77DA0F3187B73655` | 1,017,801 | **0** | 0 | 0 | 32 | 25 |
| 29667.1000 † | `7CB598068319DAC7` | 1,036,777 | **0** | 0 | 0 | 32 | 25 |
| 26100.9457 | `A9CDE82E39794FB2` | 1,012,571 | **0** | 0 | 0 | 63 | 38 |

† identity unverified — these are the four downloads whose bytes did not match the requested index
record, flagged as such in
[the build survey](secure-kernel-debugging-validation.md#offline-build-comparison-and-native-route-gate-2026-09-19).
They agree with the six verified rows and are listed separately rather than counted with them.

**What the scan found, in the order the conclusion depends on it:**

- **No debug code is written at any instruction boundary the scan recognises.** Every occurrence of
  `0x0069`, `0x006A` or `0x006B` at such a boundary, in any of the ten images — 5 to 10 per build —
  is a `cmp`, in code unrelated to debugging. Against it, the control writes all three distinct
  values and compares none.
- **And the superset is decided rather than merely reported.** The byte-anchored pass also finds 40
  to 96 decodings per build at offsets *no* pass recognises as a boundary — forms like `in al, 0x6b`
  and `enter -0x6e18, 0x6b`. Listing them and acting on none was the previous shape and it left a
  real gap, because a candidate sitting in bytes no instruction covers is not a misreading of
  anything: it is unexamined code. So each is tested against a bitmap of bytes lying inside some
  instruction a decoder placed at a boundary. **Every one of them, on all ten builds, is a shadow
  of an instruction covering its bytes; none sits in unexamined code.** A candidate that did would
  make the scan inconclusive. The same discriminator settles the raw opcode pass, which is kept
  apart from the decoders for the same reason in reverse: `0F 01 C1` can sit inside an immediate,
  so a raw match is sound evidence of *absence* and must never be counted as a `vmcall` — 1 to 3
  raw-only matches per build, all shadowed.
  **And a dismissal only counts if the instruction doing it is at a boundary that cannot be
  wrong.** The linear sweep *does* desynchronise on these images: measured against `.pdata` as
  2,617 to 3,221 independent checkpoints per build, it decodes straight through 2 or 3 of them,
  always in one small region. Finding an instruction is safe from any pass, since a spurious one
  only gives the scan another place to look; dismissing a candidate as a shadow is not, because a
  shadow cast by a misaligned decode is worthless. So dismissal uses only the seeds that start at
  known function entries. Measured before the change: no candidate on any of the ten builds relied
  on the sweep for its dismissal, so this costs nothing and stops the question arising.
- **A control code does not have to be bare.** The ABI puts it in bits 0–15 of a hypercall input
  value, with the fast flag at bit 16 — so `0x00010069` is `HvPostDebugData` and an exact-equality
  test misses it, which this scan did while its repertoire reading masked with `& 0xFFFF`. Matching
  the field instead needs a bound, or it catches branch targets: measured across the ten samples, a
  bare mask adds 0 to 5 further immediates per build, nearly all of them addresses like
  `jmp 0x140060069`. The ABI supplies the bound — bits 27–30, 44–47 and 60–63 are reserved and zero
  in any real input value — and control-transfer operands are excluded outright. With both, the
  count of matches stays zero on every build while `0x00010069` and `0x0001000000010069` are
  caught.
- **The synthetic-debugger MSR numbers are never materialised at all.** Zero occurrences of
  `0x400000F0`–`0x400000FF` as an immediate anywhere in any build, at any alignment — and here the
  byte-anchored pass is precise as well as sound, since those values need a four-byte encoding.
  That is what carries this negative, because the other reading cannot: resolving each
  `rdmsr`/`wrmsr`'s index leaves **16 to 19 sites per build unresolved**, any of which could in
  principle be in the range. Those sites are reported, and the index reading is kept only as
  colour — it finds 22 to 30 *other* synthetic-MSR accesses per build, which is what shows the
  machinery works at all.
- **The repertoire is the negative control, and it is a lower bound.** 19 to 38 distinct control
  codes per build across 29 to 63 wrapper call sites, spanning `0x0002` to `0x0103`, growing as
  builds add capability — and never a debug code. A Secure Kernel that issued *no* hypercall would
  be a broken scan rather than a finding, which is the whole reason this reading exists.

#### Four traps, each of which produced a wrong reading first

- **A sample named after its version resolves no symbols, and the scan then reports the answer you
  were hoping for.** `cdb` names a module after its *file*, so
  `securekernel-10.0.29648.1000.exe` answers to `securekernel_10_0_29648_1000!` and every
  `x securekernel!...` silently returns nothing. Nine of ten samples reported *0 hypercall sites,
  no debug control codes* — a broken scan wearing the conclusion's clothes, caught only because the
  negative control says a Secure Kernel issuing no hypercalls is impossible. The instrument now
  stages each image under the real module name before asking.
- **The control code and the rep-count bound are the same number.** `mov ecx, 0xc` followed by
  `cmp r14d, ecx` is one constant serving as both: `0x000C` is the control code, and 12 is the
  extended-fast rep limit, because a 112-byte fast input is a 16-byte header plus twelve 8-byte
  elements. Read the `cmp` as the bound and the `mov` as the code and you are right; read either
  the other way and it still looks right.
- **Resting the whole negative on one approximate component.** The first version of this scan had a
  single straight-line evaluator carrying the conclusion, and review found **six independent ways
  it could invent a code or miss one** — partial-register writes (`mov ecx, 0x100; mov cl, 0x69` is
  `0x0169`, not `0x0069`), branch joins, `and reg, 0` against a tracked parameter, tail calls,
  an MSR index mutated between its load and the `rdmsr`, and a function that both forwards a
  parameter and calls with a literal. Each was individually fixable and fixing them one at a time
  was the wrong response: what generated them was a *negative* resting on a component that can only
  ever be approximately right. The split into a sound reading that decides and a heuristic reading
  that corroborates is the fix, and the six defects were repaired underneath it.
  **And the first version of that fix was itself half a rule**, which is the part worth keeping: it
  restarted the linear sweep only after an *undecodable* byte, so data that decoded successfully but
  desynchronised still carried the cursor past a leaf function's real entry — and a leaf is absent
  from `.pdata` too, so a genuine `mov ecx, 0x69` there would have been missed while every coverage
  figure read 100%. Recursive descent from call targets is what reaches those. The tell was that the
  remedy could not express the whole rule: a sweep that resynchronises on *failure* has nothing to
  say about a boundary it never noticed it had crossed.
- **Treating every function that calls the hypercall page as a wrapper reads bug check codes as
  hypercall codes.** `SkeBugCheckEx` calls the page directly, so an earlier pass enumerated *its*
  callers and took each `KeBugCheckEx(code, …)` argument for a control code — 271 call sites and 72
  "control codes" on 28000.2952, including `0x0000` and `0x01E6`. Bug check `0x69` exists
  (`IO1_INITIALIZATION_FAILED`), so this was a live route to a **false positive on the exact
  question being asked**. The fix is to evaluate rcx at the *page call*: `SkeBugCheckEx` reaches it
  with a literal `0x0087`, which is its own answer, and only a function that reaches the page with
  the code it was *handed* has callers worth enumerating.

#### What S5a does not establish

- **S5's pass condition is untouched.** *A VTL1 execution stop is delivered to a debugger* is not
  met by any outcome here. What is closed is one route — the hypercall and MSR route from Secure
  Kernel's side — and closing it is what makes the remaining candidate specific.
- **The receiver was not re-derived statically, and two attempts to do it failed instructively.**
  Confirming from `hvix64.exe` that the debug hypercalls reach the VTL1 debug context would have
  closed the loop from both ends. A stride scan for a dispatch table indexed past `0x6B` found a
  16-byte-record array at `.data+0x22000` whose entries *self-label* — each stub writes its own
  index into a per-processor ring — which looks exactly like proof that the index is a control code.
  It is the **IDT**: the stubs end in `iretq` and the second qword of each record is a gate
  attribute (`0x8E` interrupt, `0x8F` trap) with selector `0x0010`, so the index is a **vector**. A
  second attempt, looking for a bound check after a `movzx …, cx`, found one candidate and it was a
  512-entry page-table walk. The receiver therefore rests on the live trace already in the
  validation record — the session handler reached twice with VTL 0 and **zero** times with a
  nonzero VTL — and on the control binary, not on a static read of this build. The `hvix64.exe`
  read was of this workspace's `10.0.26100.9444`, which is not the lab guest's build.
- **It is static, and it reads *immediates*, which is narrower than "values".** Two ways a code
  could reach a register without appearing as one, and neither is closed here: *computed* —
  `mov ecx, 0x68` then `inc ecx` — and *loaded from data*, `mov ecx, dword ptr [rip+…]` against a
  constant sitting in `.rdata`, which the scan never looks at because a value in a data section is
  not an immediate in a code section. This is the residual gap in the conclusion and the repertoire
  does not close it, being only a lower bound. Both were found by auditing the tool's own claims
  against the checks behind them rather than by a reviewer, which is the cheaper order.
- **5 to 12 wrapper sites and 16 to 19 `rdmsr`/`wrmsr` sites per build have an operand the scan
  cannot recover**, and any of them could carry a value by one of the routes above — a constant in
  `.rdata` loaded into `ecx` is the concrete case a reviewer raised, and it is real. They do not
  block the verdict, which is a decision rather than an oversight: every sampled build has some, so
  blocking on them would make every run inconclusive and delete the reading instead of qualifying
  it. Both counts are printed on the verdict line so the qualifier travels with the result rather
  than living in this document.
- **The repertoire does not follow control flow, and is not sound on its own.** The evaluator walks
  in address order, so a code built across a branch can be missed and a block after an
  unconditional jump can contribute one no path reaches. Discarding state at every branch target
  was tried and is sound, but it took 26100.9457 from 38 codes to **1** — which destroys the
  negative control the repertoire exists to be. A CFG with a merge at each join is the real fix and
  is more machinery than a corroborating reading justifies, so the repertoire is labelled a
  heuristic lower bound and the verdict is taken from the immediate scan instead. The two compose:
  since no debug value appears as an immediate anywhere, no arrangement of branches can route one
  into a wrapper *as an immediate*.
- **Nothing here is about a route with no guest-side code**, which is now the only live candidate:
  a stop driven entirely from the hypervisor or the root, needing no cooperation from Secure Kernel
  at all. S5 continues there.

#### What it changes downstream

- **Breakpoints stay excluded, and now for a measured reason rather than an assumed one.** S4 solved
  the patch half — an `int 3` can be written into VTL1 by the direct route. S5a shows the catch half
  has no Secure Kernel-side transport to deliver it, which is why the S5 instruction *do not plant
  one to test this* stands unchanged and is better founded than when it was written.
- **The inspector-versus-debugger question narrows rather than closes.** A capture session is a
  fixed snapshot and stays one. What would change that is a route this gate did not test, not the
  one it closed.

### S5b result, 2026-09-28: a parent may install an exception intercept on a child, and may not aim one at VTL1

**Both halves are measured, and they point in opposite directions.** The install works: from the
root, `HvCallInstallIntercept` (`0x004D`) installs an exception intercept on a *child* partition
and removes it again, on both lab guests, with the negative controls refusing. And it cannot be
aimed: the input block has no field to name a VTL, and every byte this run put where one might
hide was accepted **identically on a child with no VTL1 at all**.

**What that closes is aiming, and not the route.** An earlier draft of this section said the
candidate S5a left standing was closed, and that does not follow from these arms: with no VTL
selector in the ABI, an intercept is either implicitly VTL0 or implicitly **every VTL**, and the
second of those needs no selector because it would already deliver a VTL1 exception to the parent.
This gate cannot tell those apart — it provoked no exception and holds no port to receive one. So
the route stands **unresolved on scope**, with its install half measured and available. S5's pass
condition is untouched and S5 stays open.

The instrument is `h3probe.sys` — the H3 driver — with one IOCTL added that issues a hypercall
whose input block the *client* composes byte for byte, so each arm is a different 24 or 32 bytes
rather than a different driver. Its client is `s5b.py`. Measured on the x64 bench: host
`10.0.26200`, `hvix64.exe` `10.0.26100.9444`, `winhvr.sys` `10.0.26100.8972`, `Vid.sys`
`10.0.26100.9278`, against child partitions `0x7` (`EnabledVtlSet` `0x0003`) and `0xB` (`0x0001`).
As in H3, the guests are identified by VSM state and never by partition number.

#### The block is documented, and three readings of it agree

The plan's clean-room condition is that constants come from the published TLFS, and the TLFS
documents this one completely — `PartitionId` (0, 8), `AccessType` (8, 4), `InterceptType` (12, 4),
`InterceptParameter` (16, 8), call code `0x004d`, Simple. `HV_INTERCEPT_PARAMETERS` is a union
whose exception member is a bare `UINT16 ExceptionVector`, and **neither structure has a VTL field
or a reserved one that could become one**. `HvInterceptTypeException` is `0x00000003`.

Both known callers build exactly that block, read twice each — once with capstone, once with
Ghidra, the second reading being there because the first was one tool's opinion about a field
layout this record then publishes. **They are two different images and neither is the lab guest's
running Secure Kernel**: the SK side is the 26100.9457 *sample* from the build survey, the root side
is this host's own `winhvr.sys`, and what the live arms below exercise is the hypervisor, which is
this host's `hvix64.exe`. The static half establishes the shape callers use, not what the guests
are running:

| | `securekernel.exe` 26100.9457 `ShvlInstallExceptionIntercept` (+`0x092C4C`) | `winhvr.sys` `WinHvInstallIntercept` (+`0x021BB0`) |
|---|---|---|
| `PartitionId` | `-1` — **SELF** | the caller's, and Vid.sys passes a *child's* |
| `AccessType` | `4` (execute) | the caller's; Vid.sys passes 4 to install, **0 to remove** |
| `InterceptType` | `3` — exception | the caller's; see below |
| `Parameters` | vector in the low word, six bytes zeroed explicitly | 8 bytes, caller's |
| input size | `0x18`, passed to the invoker | `0x18`, passed to the invoker |

**So `FOLLOWUPS.md`'s "intercept type 4" was the access mask.** Type 3 is the exception intercept
and 4 is `HV_INTERCEPT_ACCESS_MASK_EXECUTE`; the two fields are adjacent dwords and the earlier
reading took the first one it saw. Corrected there.

**The root side is not hypothetical either: Hyper-V's own `Vid.sys` calls it on children.** Eleven
call sites reach `WinHvInstallIntercept`. Seven carry a literal intercept type — `1`, `2`, `3` and
`0xC` — and four take it from a caller or a structure, which this pass did not resolve; one of those
four is a **VID IOCTL passthrough** that length-checks an input buffer at `0x18` and hands the
descriptor straight through, so user mode supplies the whole block. Four sites pass `AccessType`
`0`, which is how an intercept is removed and is where this run's removal arm comes from rather than
from a guess. So a parent installing an exception intercept on a child is ordinary, documented
behaviour — what S5b adds is that it cannot be pointed at a VTL.

Secure Kernel's own installer also refuses every vector but **#DB and #BP** — `(vector - 1) & 0xFFFD`
must be zero, unless a global is set — and sets `1 << vector` in a bitmask after the call succeeds.
That is SK installing intercepts *for itself*, at `PartitionId` SELF, which is what a higher VTL
does; it is not a parent naming a child.

#### What the hypervisor did, arm by arm

Every install is paired with its removal, and the removals ran again in a `finally`: the teardown
line reads `0 intercept(s) still standing`.

| arm | VTL1 child `0x7` | VTL0-only child `0xB` |
|---|---|---|
| **negative control** — intercept type `0xFFFFFFFF` | `0x0005 INVALID_PARAMETER` | — |
| **negative control** — access mask `0xFFFFFFFF` | `0x0005 INVALID_PARAMETER` | — |
| **negative control** — partition id 0 | `0x000D` | — |
| baseline — the ABI block, spare bytes zero, vector `0x05` | `SUCCESS`, removed `SUCCESS` | `SUCCESS`, removed `SUCCESS` |
| byte +`0x12` = `0x11` (`HV_INPUT_VTL(1)`) | `SUCCESS` | `SUCCESS` |
| byte +`0x12` = `0x01` (bare VTL 1) | `SUCCESS` | `SUCCESS` |
| dword +`0x14` = 1 | `SUCCESS` | `SUCCESS` |
| qword +`0x18` = `0x11`, eight bytes *past* the block | `SUCCESS` | `SUCCESS` |
| the same, declared as **variable header size 1** | `0x0003 INVALID_HYPERCALL_INPUT` | `0x0003 INVALID_HYPERCALL_INPUT` |
| vector `0x03` (#BP) — what SK installs for itself | `SUCCESS` | `SUCCESS` |
| vector `0x01` (#DB) — the other one | `SUCCESS` | `SUCCESS` |

**Arms on which the two guests disagree: zero.**

#### Why "accepted" reads as "not a VTL selector", which acceptance alone would not say

A hypercall that succeeds has not said what it did with the bytes, and an earlier draft of this
section read SUCCESS as *ignored* directly. It does not follow: the hypervisor could have read
them and installed something else. What carries the reading is the **control partition**, which has
no VTL1 — `EnabledVtlSet` `0x0001`, `MaximumVtl` 0. Naming VTL1 there must fail if the field is
read as a VTL, and the same run shows what that failure looks like, because a field the hypervisor
*does* read per VTL was exercised beside it: `HvCallGetVpRegisters` with `TargetVtl = 1` returns
`0x0015` on that partition and `SUCCESS` on the VTL1 one. So in one run, on one pair of guests, the
`TargetVtl` field discriminates and the intercept block's spare bytes do not. That is the
difference between a field and a gap.

The variable-header arm closes the other door the ABI leaves open. The TLFS says a non-zero
variable header size on a call not documented to accept one returns
`HV_STATUS_INVALID_HYPERCALL_INPUT`, and that is exactly what `0x004D` returns — so the call is
fixed-size on this hypervisor, there is no extended form of the block to carry a VTL, and the
hypervisor demonstrably parses the control word rather than ignoring it.

#### The trap: a vector chosen to be harmless made every arm unreadable

The first run of this gate picked exception vector `0x1F` because Intel reserves it and no hardware
raises it, so an install could intercept nothing and nothing could be delivered to a parent with no
port to receive it. **Every arm came back `0x0005 INVALID_PARAMETER`, including the baseline** — and
that reads exactly like a clean negative about VTL1 while being a statement about the vector: the
hypervisor validates it against the architectural set, which `0x1F` is not in. It is the same
failure H3 wrote its own discipline against — *if both are refused the finding is about privilege or
plumbing and says nothing about VTL1* — arriving in a different costume, and the only reason it was
caught is that the control was in the run rather than assumed. The fix is a **vector phase**: the
script discovers a vector this hypervisor accepts, on the guest with no VTL1, before any arm that
claims to be about VTL1 runs. `0x05` (#BR) is the first it takes, and it is the vector every arm
above was installed for.

**The second half of that choice — that the vector cannot fire — is retracted, and the reason is
the shape of the search rather than any one counterexample.** Two review rounds each named a way
that #BR reaches a running x64 Windows guest, both correct: **MPX**'s bound-check instructions raise
it on hardware that implements the feature, and the legacy `BOUND` still decodes in **32-bit
compatibility mode**, which is every WOW64 process on such a guest. A third exists without looking
far — an explicit `int 5` delivers the vector as a software interrupt, and whether the hypervisor's
*exception* intercept catches that is itself unmeasured here. Each round's fix was a longer
qualification, which is the tell: **"no code can raise this vector" is a claim about every
instruction every guest might execute, and no CPUID reading or decode rule settles it.** The
enumeration is not certified complete above and is not meant to be — that is the point.

So the record claims only what it can: `0x05` was chosen to make a fire *unlikely*, not impossible,
and **what actually protected the run is not the vector at all** — a pair of disposable lab guests,
and an install paired with its removal microseconds later, on a bench whose CPU happens to lack MPX
(`CPUID.7.0:EBX` bit 14 = `0` on the i7-14700, no MPX state component in `CPUID.D`; `FSGSBASE` and
`SMEP` read 1 in the same register, so that is a real reading rather than an all-zero answer). Both
guests came through with continuous uptime. **A re-run that needs a genuinely inert arm pauses the
target or uses one it is willing to lose, rather than hunting for an unraisable vector** — there is
no vector this method could have proved safe, and the hunt for one is what generated these rounds.

A second, smaller one: the client's `HV_STATUS` table was carried over from `h3client.py` and had
`0x000B` as `INVALID_PARTITION_ID`, which the invalid-partition arm contradicted by returning
`0x000D`. The TLFS's own `HV_STATUS` page carries no table to check it against, so the client now
names only the codes this record has a source for and prints the rest as numbers. `0x0015` is left
unnamed here for the same reason it was in H3.

#### What S5b does not establish

- **Delivery, which is the whole of S5's pass condition.** *A VTL1 execution stop is delivered to a
  debugger* needs an exception to occur in VTL1 and to arrive somewhere a debugger can see it.
  Neither was tested: no exception was provoked, and provoking one means planting an `int 3` in
  VTL1, which the plan excludes and S5a's result makes no safer.
- **Whether a partition-scoped exception intercept fires for VTL1 execution at all.** This gate
  shows there is no way to *ask* for VTL1; it does not show that an intercept installed without
  asking excludes it, and the absence of a selector is exactly as consistent with *covers every
  VTL* as with *means VTL0*. That question is now the interesting one, and answering it needs both
  a VTL1 exception and somewhere to observe delivery.
- **Where an intercept would be delivered.** The child's intercept messages are routed to the port
  Hyper-V's own `Vid.sys` created; this run holds no port and created none, so nothing here says
  what a parent-installed intercept would look like to a debugger rather than to the VM worker.
- **Anything beyond this hypervisor.** One host, one `hvix64.exe` build, one pair of guests, x64.
  The static half spans the ten `securekernel.exe` builds only for the caller's shape, not for what
  a hypervisor accepts.
- **That the spare bytes are unread rather than read-and-rejected-as-zero.** The control makes
  "not a VTL selector" sound; it does not make them provably inert.

#### What it changes downstream, and where S5 goes next

- **The intercept route is closed for aiming and unresolved on scope.** A parent *can* install and
  remove exception intercepts on a child, and cannot select a VTL while doing it. Whether what it
  installed covers VTL1 anyway is the open half, and it is now the *cheapest* question in S5:
  unlike the aiming question it needs no new primitive, only a VTL1 exception and somewhere to
  watch. S5a closed the guest-cooperating route; this one is narrowed rather than closed.
- **Breakpoints stay excluded**, unchanged and for the same reason: the catch half is unmeasured.
- **So S5 has two live candidates, not one, and the intercept one is first.** Settling scope means
  answering *does a parent-installed exception intercept fire for a VTL1 exception* — and the two
  ways in are a static read of `hvix64.exe`'s intercept dispatch, asking whether the check consults
  the active VTL (two attempts have already failed on that image, and Ghidra is on this bench now
  where it was not then), or a live test, which needs an intercept port of its own to receive on
  and a VTL1 exception that is not a planted `int 3`. Neither is free; both are cheaper than
  building a route that already exists.
- **The second candidate is named by a measurement rather than by a guess, and it is not an
  intercept.** In the read-only reconnaissance beside the arms above, `HvRegisterExplicitSuspend`
  (`0x00000000`), `HvRegisterInterceptSuspend` (`0x00000001`) and `HvRegisterDispatchSuspend`
  (`0x00000003`) are all **readable from the parent at both VTL0 and VTL1** on the VBS guest, and
  all three are refused at VTL1 on the twin with no VTL1 — the control discriminating exactly as it
  does for `CR3` in H3. So a stop that needs no exception, no intercept and no guest-side code is at
  least *nameable* per VTL. What is unmeasured is the **write**, and S4 is the reason not to read
  the read as an answer: `HvCallReadGpa` and `HvCallWriteGpa` disagreed about VTL1 in exactly that
  way. `HvCallSetVpRegisters` (`0x0051`) against a child's VTL1 suspend register, with the VTL0
  control beside it, is the gate for it — and note it *stops a running guest's VP*, which every arm
  in S5b was designed to avoid, so it needs a disposable guest and a written-down recovery before
  it runs rather than after. It is second because it is the more expensive of the two and because
  an intercept that already covers VTL1 would make it unnecessary.

### S5c result, 2026-09-28: the root can stop a child VP and read its VTL1 while it is stopped

**The stop works, it is not a VTL1 stop, and the distinction is measured rather than reasoned
about.** `HvCallSetVpRegisters` (`0x0051`) writing `HvRegisterExplicitSuspend` halts a running
child's virtual processor from the root partition — no guest-side code, no exception, no intercept,
no port — and while it is halted the child's **VTL1 `CR3` and VTL1 `RIP` read back as VTL1's own,
while the VTL0-labelled `RIP` and `RSP` do not read back as VTL0's**. That asymmetry is measured
over repeated halts below, and it is a caution on the *VTL0* read rather than on the VTL1 one.
What the run also shows is that the halt is **VP-wide**: naming VTL1 stops the whole processor, not
VTL1's execution, so this is an inspector's stop rather than the debugger's stop S5 asks for.

Instrument `s5c.py` on the same `h3probe.sys` IOCTL as S5b. Same bench and same children as that
gate: partitions `0x7` (`EnabledVtlSet` `0x0003`) and `0xB` (`0x0001`), VP 0, a 2000 ms hold.

#### A status is not a stop, so the stop is measured separately

`HV_STATUS_SUCCESS` says a register write was accepted. **`HvRegisterVpRuntime` (`0x00090000`) is
what says a processor stopped**: it counts executed time in 100ns units and is read-only, so a
working suspend shows as a counter that stops advancing. That mattered here rather than in theory —
a first run at a 60 ms window read `during` as 139 against a `before` of 105 and called it nothing,
because **an idle guest's VP and a suspended one are indistinguishable at that scale**. The window
went to 2000 ms and a **null model** went in beside it: three samples with no suspend at all, to
show what idle looks like when nothing is being done to it.

| arm | VP runtime over 2000 ms |
|---|---|
| null model, no suspend (three samples) | 84,075 / 53,293 / 60,149 |
| control 1 — VTL0 suspend on the VTL0-only child, before | 45,434 |
| control 1 — **while suspended** | **430** |
| control 1 — after release | 43,907 |
| test — VTL1 suspend on the VBS child, before | 41,291 |
| test — **while suspended** | **1,032** |
| test — after release | 61,453 |
| symmetric arm — VTL0 suspend on the **VBS** child, while suspended | 495 |

Against the lowest idle sample of the same run — 41,291 — the suspended arms are **40× to 106×**
below it: control 1 at `45,434 / 430` is 106×, the symmetric arm's 495 is 83×, and the VTL1 test at
`41,291 / 1,032` is **40×**. An earlier version of this sentence said "two orders of magnitude in
every suspended arm", which is true of the control and not of the test, and overstated the
narrowest arm by more than a factor of two. The separation is large and consistent in every arm;
the figure that carries it is 40×, not 100×. An earlier version of the *guard* looked for a
**catch-up burst** on release instead, and called a clean drop "weak" — an idle guest has no queued
work to catch up on, so the burst was never the discriminator. The `during` sample against the null
model is.

#### What the VTL parameter does, and what it does not

- **It is validated.** The same write naming VTL1 on the child with no VTL1 is **refused with
  `0x0015`** — the same code its VTL1 register *read* returns, which is the S5b recon result
  arriving from the write side.
- **It does not scope the stop.** With the suspend set by naming VTL1, `HvRegisterExplicitSuspend`
  reads **`1` at VTL0 as well**; the symmetric arm — setting it by naming VTL0 on the same VBS
  guest — reads `1` at VTL1 and stops the VP just as hard (495 against 1,032). So there is one
  VP-wide suspend behind a VTL parameter that decides *who may ask*, exactly as S5b found for the
  intercept block's missing selector, and not a per-VTL stop.

#### What is readable while it is stopped

|  | VTL0 | VTL1 |
|---|---|---|
| `CR3` | `0x00000000007D5000` | `0x0000000001201000` |
| `RIP` before the stop | `0xFFFFF8067A8BF8BD` | `0xFFFFF80609990035` |
| `RIP` **during** the stop | `0xFFFFF80609990035` | `0xFFFFF80609990035` |
| `RSP` **during** the stop | `0xFFFFBF003EA2DEC8` | `0xFFFFBF003EA2DEC8` |
| `RIP` after release | `0x00007FFFCDD94F2A` (user mode) | `0xFFFFF80609990003` |

That VTL1 `CR3` is `0x1201000`, which is the value S0 and H4 recorded **on the 2026-09-26 boot** —
and this guest restarted on 2026-09-27, so it is the same *value* on a different boot rather than a
third confirmation of one state. Worth having (the value recurs, and a halted read returns it) and
not worth more than that; the S5e correction below is where that distinction is worked out.

**The VTL1 context is real, and that needed its own control.** During the stop the VP's *own*
`RIP` and `RSP` become the VTL1 values, which on its own is equally consistent with the read being
mislabelled — so a separate read-only probe sampled the pair on a *running* guest: **40 of 40
samples on each of both VPs returned a VTL1 `RIP` distinct from the VTL0 one**, with the VTL1 `CR3`
distinct in every sample too. The VTL1 context is Secure Kernel's own, and it **moves** —
`0xFFFFF80609990035` to `0xFFFFF80609990003` across one suspend cycle — so it is live state rather
than a stale copy.

**But sampling while the guest runs validates only the running path, which is what a review round
pointed out**, so the halt itself was repeated. **Eight halt/read/release cycles**, each comparing
the pre-halt pair with the halted pair:

| reading over 8 cycles | result |
|---|---|
| halted VTL0 `RIP` == halted VTL1 `RIP` | **8/8** |
| halted VTL1 `RIP` == that cycle's **pre-halt** VTL1 `RIP` | **8/8** |
| `CR3` still distinct between the two VTLs while halted | **8/8** |
| distinct pre-halt VTL0 `RIP`s across the eight cycles | 2 — the guest was moving |

**So the coincidence is systematic, not a matter of where the guest happened to be**, and the two
halves fall on opposite sides. The VTL1 reading is *stable*: it equals its own pre-halt value in
every cycle, so halting does not disturb it and what comes back is the context that was there
before. The **VTL0** reading is the one to distrust: it returns the VTL1 value in every cycle
regardless of where VTL0 actually was, which the two distinct pre-halt VTL0 `RIP`s rule out as
coincidence. `CR3` staying distinct throughout also rules out the crude version of the mislabelling
story — the read path is not simply returning VTL1 for everything.

What is still *not* settled is which mechanism produces it: the VP parked at the VTL1 entry
context, or the register path substituting VTL1's `RIP`/`RSP` while suspended. Both fit all eight
cycles.

**This paragraph twice tried to end with a rule for consumers, and both attempts were findings**,
so it ends with the observation and its condition instead. Every reading above — the 40-sample
probe, the eight cycles, every suspended arm — was taken with **`VsmVpStatus.ActiveVtl = 0`**, and
that is not a detail to file under limitations: the labels could behave differently when the halt
catches a VP with Secure Kernel actually executing, and *nothing here says they do not*. So what is
established is narrow and conditional:

> **Measured, on this build, with `ActiveVtl = 0` at the halt:** the VTL1 `RIP` reads back its own
> pre-halt value and the VTL0-labelled `RIP`/`RSP` read back the VTL1 values, 8 cycles of 8, with
> `CR3` distinct throughout. **Unmeasured:** the same halt with `ActiveVtl = 1`.

**And `ActiveVtl = 1` is not merely unobserved, it could not be reached from here.** A sampler
took **4,000 reads per VP with no delay — 8,000 in ~214 ms of wall time — and every one returned
`ActiveVtl = 0`.** On an idle guest VTL1 runs too rarely to catch, and this bench cannot make it
run by any means this gate found: **corrected by S5f below** -- PowerShell Direct does reach both
guests, and driving twelve kernel image loads through it still caught `ActiveVtl = 1` zero times in
832,560 samples.

**A third attempt at telling a consumer what to do went the way of the first two, and there will
not be a fourth.** It said to read `ActiveVtl` and check it is zero, which sounds cheap and does
not establish the precondition: read *before* the suspend it races entry into VTL1, and read
*after* it, whether it still reports the VTL that was active at the instant of the stop is the very
thing the paragraph above leaves unresolved — the same suspension that makes the VTL0-labelled
`RIP` read as VTL1's could be doing something to this register too, and nothing here says
otherwise. **These primitives offer no atomic stop-and-observe**, so the condition this gate
measured under cannot be *enforced* by anything it demonstrated, only reported. That is the state:
the readings hold for `ActiveVtl = 0`, whether a given halt satisfies that is not decidable from
here, and an implementer needs a measurement this bench could not take rather than a check this
document invented.

#### What S5c does not establish

- **S5's pass condition is still not met**, and this is the honest reading rather than a modest
  one. *A VTL1 execution stop delivered to a debugger* wants a stop **of VTL1**, at a chosen point,
  **reported** as an event. This is a stop of the whole VP, at an arbitrary point, discovered by
  polling. Two of the three are missing.
- **Secure Kernel was never caught executing, and not for want of trying.** `VsmVpStatus.ActiveVtl`
  read `0` in every sample of every arm, and a dedicated sampler took **8,000 reads across the two
  VPs with no delay — ~214 ms of wall time — and caught `ActiveVtl = 1` exactly zero times.** On an
  idle guest VTL1 runs too rarely to catch, and this bench cannot make it run, so *every* reading
  in this gate is conditional on VTL1 being parked.
- **Nothing is delivered.** There is no event, no message and no port: the stop is something the
  root does and then observes. A debugger's stop arrives; this one is taken.
- **The suspend bit is measured, not documented.** No TLFS page this run could find publishes
  `HV_EXPLICIT_SUSPEND_REGISTER`'s layout, so the control *establishes* that writing `1` reads back
  `1` and stops the VP, and the run refuses to read any later arm if it does not.
- **This is Hyper-V's own pause primitive**, not a new capability: the root suspending a child's VP
  is how a VM pauses. What is new here is only that it is reachable from this probe and that VTL1
  state is readable across it.
- **One host, one pair of guests, idle.** A busy guest would sharpen the runtime evidence and was
  not available at the time: **corrected by S5f below** -- PowerShell Direct loads them over the
  VMBus, and the busy-guest figure is 23,854x rather than this section's 40x. Every arm but the all-VP one halts **VP 0 alone**, which is enough for a
  register reading and is *not* enough for a memory walk — see the inspector note below.
- **Why the VTL0-labelled `RIP`/`RSP` coincide with VTL1's while halted.** Measured as systematic
  over eight cycles; the mechanism behind it is not established.

#### What it changes downstream

- **A live VTL1 *inspector* reaches registers, page tables and page contents, and it has to halt
  every VP rather than one.** (*"End to end" was this bullet's original wording and is withdrawn —
  see the S5e result: the chain is measured on one virtual address, and each page needs a read
  route chosen for it.*)
  Stop the guest (S5c), read VTL1 registers (H3) and VTL1 memory by **whichever of the two routes
  serves each page** — the direct one alone returns a zero page for the very address S5e walked to
  — resume —
  on a running guest, with no capture. S3's tool surface was shaped for a fixed snapshot because S0
  said most users would have one; this says a *live* source can be given the same shape, with the
  stop bracketing the reads.

  **That sentence was a composition of two halves measured in different runs until review said
  so**, which is a fair thing to be caught by: S5c halted VPs and read *registers*, H4 read VTL1
  *memory* on a guest nobody had stopped, and "end to end" was an inference joining them. It is now
  one run. `s5d.py` drives both drivers in a single process — `h3probe.sys` for the halt,
  LiveCloudKd's `hvmm.sys` for the direct route, with the SDK's `ForceFreezeCPU` and
  `PausePartition` **off** so the only stop in the experiment is the measured one:

  - both VPs of partition `0x7` halted, `SUCCESS` each, and both runtimes froze — **11,149 → 379**
    and **32,119 → 188** over the same window, 2/2;
  - **3 of 3** VTL1 GPAs that H4 established the direct route reaches returned content *while both
    VPs were halted* — `0x0C00000`, `0x3E00000`, `0x4800000` — and `0x3E00000`'s
    `ff01000000010000` and `0x4800000`'s `0000000000000060` are byte-identical to what H4 recorded
    for them — **across two boots**, so that is a statement about those bytes recurring and not
    about the two runs seeing one state;
  - each address was read **twice inside the halt** and agreed both times, 3/3, which is what
    "fixed source" has to mean.

  **What the run does not show is that the halt was necessary**, and the instrument says so itself:
  the same double reads while the guest was *running* were stable too, 0 of 3 changing. An idle
  guest is not a demanding test of consistency, and this bench has no way to load these guests —
  they were thought unreachable. **S5f corrects the reachability and not the conclusion**: with the
  guest busy, 80,399 reads over a matched 3 s window return one distinct value per page, so these
  pages are static and the halt's *value* is still an argument from what a second VP can do rather
  than a measurement of it.

  **And those three GPAs were preselected from H4's table, which review pointed out is not the
  join**: reads of known-good addresses succeed whether or not the halted *register* context can
  drive the memory path. The join is data flow — `CR3` taken from the halted VP, used to walk, to
  reach a **virtual** address. That is the S5e result below, and it changes the claim again.

  **The "every VP" part is a correction from review, and it is the difference between a stop and a
  snapshot.** S5c's other arms halt VP 0 alone, and on a two-VP guest the second processor goes on
  executing Secure Kernel and mutating exactly the page tables and loader lists a VTL1 walk reads —
  so one halted VP brackets *per-VP register* reads and does not make memory internally consistent.
  The same S4 hazard the record already carries for writes ("identical only at the instant of the
  first read"), arriving on the read side. Measured rather than left as a caveat: halting **both**
  VPs of partition `0x7` succeeds on each (`SUCCESS`, `SUCCESS`) and **both** runtimes freeze —
  995 and 299 per 2000 ms against 45,005 and 23,046 before, and 229,059 and 30,687 after release,
  the first of those a catch-up burst from a guest that really had been stopped. Both released
  cleanly and read back `0`. So the inspector is available, and *halt every VP and verify each* is
  part of its contract rather than an optimisation.
- **The debugger half stays open**, and its remaining candidate is the one S5b left: whether a
  partition-scoped intercept fires for VTL1 execution. That is still the only route that could
  produce a stop *at a chosen point*, and it still needs a receiver.
- **Breakpoints stay excluded**, unchanged.

### S5e result, 2026-09-28: the halted `CR3` walks, the leaves are only partly readable

**The join review asked for runs the whole way, and it needs both read routes to do it.** Taking
`CR3` from the halted VP and walking it through the direct route reaches a physical address for a
VTL1 *virtual* address — the register half driving the memory half, in one run, by data flow rather
than by two experiments standing beside each other — and the page at the end of that walk reads
back the instruction the processor is parked on. **The direct route returns zeros for that leaf and
the hypercall returns 4,084 non-zero bytes of it**, which is the shape of the whole result: the two
routes are complementary and a reader who takes only the first will conclude the chain is broken
where it is not.

With both VPs halted (runtimes 10,927 → 833 and 15,279 → 212), `ActiveVtl = 0`, VTL1 `CR3`
`0x1201000` and VTL1 `RIP` `0xFFFFF80609990035`:

| step | result |
|---|---|
| `PML4E[496]` @ `0x1201000` | `0x0000000001204063` — present, `0x63` = P\|RW\|A\|D |
| `PDPTE[24]` @ `0x1204000` | `0x0000000001203063` — present |
| `PDE[76]` @ `0x1203000` | `0x0000000001208063` — present |
| `PTE[400]` @ `0x1208000` | `0x000000000081F121` — present, `0x121` = P\|A\|G |
| the leaf, PA `0x81F035` | **zeros** |

**A coherent four-level descent with sane flags is not something a broken read produces**, and the
page tables it walks are VTL1's own — so the direct route reads VTL1 page tables while every VP is
halted.

**The leaf is not withheld — it is readable by the *other* route, which the first version of this
section got backwards by reading 32 bytes and naming a cause.** Review caught that, and the census
that answers it reads each page **whole, 4096 bytes, through both routes**:

| page | direct (`hvmm`) | hypercall (`HvCallReadGpa`) |
|---|---|---|
| `PTE[400]` → PA `0x81F000` — the `RIP`'s own leaf | **0** non-zero bytes | **4,084** of 4,096 |
| `PTE[378]` → PA `0x3BE1000` — the other present leaf | **200** non-zero | 0 |
| PA `0x1208000` — the page table itself, as a control | **8** non-zero | 0 |

**Each of the three pages is readable by exactly one of the two routes, and which one differs per
page.** The complementarity is the finding: **neither route alone reads VTL1's address space**, and
H4's framing of the direct route as the one that "sees what the hypercall cannot" is true of the
pages H4 sampled and false as a general rule.

**And the bytes at the end of the chain are what settle that the chain is right.** At the halted
`RIP`'s own page offset, `0x035`, the leaf holds:

```text
c3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 …
```

`ret` followed by `nop` padding — a plausible instruction at a plausible place for a parked Secure
Kernel to be sitting. Nothing in the walk was checked against an oracle, so this is the check: had
any level of the descent been misread, the offset would hold arbitrary data rather than an
instruction that makes sense of `RIP` pointing at it. Halted VP → VTL1 `CR3` → four levels → the
right route for that page → the instruction the processor is parked on.

A hypothesis consistent with all of it, and **not** established here: the hypercall returns zeros
for VTL1-*protected* pages (H4's `ReadIntercept` result) while `hvmm`'s mapping returns zeros for
pages outside whatever physical ranges it maps, so a VTL1 address space — which maps both private
and shared pages — needs both. Three pages is not a rule, and nothing here identifies which
property decides.

#### The trap, which this gate walked into before walking out

The run's own step 3 read **64 bytes** of the `CR3` page, found them zero, and printed that the
walk could not start — and then step 4 walked it successfully out of entry 496. A PML4's low
entries describe user space; on this guest the first present entry is at index 262, byte offset
`0x830`. **H4's table has the same artifact at 16 bytes**, which is where its "the VTL1 `CR3` page
reads as zeros by both routes" came from, and that row has been corrected in place: read whole, the
page carries **122 non-zero bytes and 26 present entries**. S0 also counted 26 from the capture
side, on the **earlier boot** — the same guest and not the same page table, so that is two boots
agreeing on a count rather than one reading confirmed twice. What refutes the row needs neither:
H4's own table puts that boot's first present entry at offset `0x850`, so its 16-byte probe read
nothing but padding. A question H4 left open as "a limit of the mapping, a fallback, or genuinely
zero" turns out to have been none of the three.

The general form is worth stating because both instances were mine: **a prefix is not a page**, and
a structure whose interesting entries are index-addressed will read as empty from any window that
does not cover them.

**It then happened a third time, inside the fix for the second**, which is the part worth carrying.
The instrument gained a `census()` that reads whole pages by both routes — written precisely so no
page-level claim could rest on a window again — and it censused the address it was *handed*. For a
leaf reached by a walk that address is `…035`, so the read straddled two pages, counted 16 non-zero
bytes belonging to the *next* one, chose the route those bytes came from, and printed *"neither
route returned content"* about a page the other route reads 4,084 bytes of. **A census of the wrong
extent is the same defect as a prefix**, and writing the rule down is demonstrably not the same as
obeying it: the fix is one `& ~0xFFF` in the helper, where it is exercised on every run, rather than
a sentence in a document.

#### What this leaves the inspector claim as

- **Registers, halted: yes** (S5c). **Page tables, halted, from the halted `CR3`: yes** (here).
  **Leaf contents: yes for the one address walked**, with the route chosen per page.
- **What is measured is a chain, not a capability over the address space.** One virtual address —
  the halted `RIP` — walked once, and three pages censused, each of which returned content through
  one route or the other. That is a demonstration that the chain *can* complete; it is not evidence
  that an arbitrary VTL1 address will, and it must not be read as one. **An untested page could be
  unreadable by both routes**: `0x3600000` in H4's table is exactly such a page and remains
  unretested, and what decides which route serves a given page is unknown, so there is no rule here
  to predict from. Three pages, one page table, one guest, one boot.
- **What the gate adds to the design is therefore narrow and firm**: an inspector must try *both*
  routes per page, because on this sample either alone reads one page in three. What it must not
  assume is that trying both always succeeds.
- **"End to end" still should not be used**, for a different reason than round four thought: the
  chain is measured on a single virtual address, the pass condition for S5 is untouched, and the
  step that would make it a debugger — a stop at a chosen point — remains missing.

### S5f result, 2026-09-28: the guests can be driven after all, and what that changes

**"Neither lab guest answers ICMP or WinRM, so there is no way to load them from outside" was
wrong, and it is repeated three times in the sections above.** There is a way that needs no network
at all: **PowerShell Direct**, over the VMBus, which wants only a running Windows guest, Hyper-V
admin on the host, and guest credentials. `Invoke-Command -VMName` reaches both guests
(`DESKTOP-PR0QOQF`, VBS on; `LAB-VBSOFF`, VBS off; both 26200, 2 VPs). The error was equating *no
network path* with *no guest access* and never testing the second — the guests had been reachable
for the whole gate.

What that unlocks is measurement, so here is what it settled and what it did not.

#### The register interface is live, which nothing had checked

Every reading in S5c and S5e assumes a parent-side `HvCallGetVpRegisters` samples the *running*
processor. That had never been tested; on an idle guest a stale interface and a parked VP look
identical, and both would return the constant `0xFFFFF8067A8BF8BD` this record quotes. Under a
sustained user-mode spin driven through PowerShell Direct:

| | VP 0 | VP 1 |
|---|---|---|
| samples in ~6 s | 110,638 | 110,638 |
| distinct VTL0 `RIP` values | **6,675** | **6,603** |
| user-mode `RIP`s | **87.9%** | **88.2%** |

A read that returns ring-3 addresses 88% of the time while the guest spins in ring 3, across
thousands of distinct values, is sampling the processor and not a cached exit record — **for VTL0,
which is the only VTL this experiment varied.** The spin ran in VTL0 and every sample above is a
VTL0 `RIP`, so it establishes that the *VTL0* read is live and says nothing about the VTL1 one: a
live VTL0 read is perfectly compatible with an inactive VTL1 query returning saved context, which
is what the next section's `ActiveVtl = 0` result would predict. The only VTL1 movement this record
has seen is `RIP` going `…0035` → `…0003` across one suspend cycle, which fits both readings.
**So S5c's and S5e's VTL1 readings rest on an instrument validated for VTL0 and not for VTL1**, and
validating it there needs a workload that demonstrably moves VTL1. **Superseded by S5g below**,
which produced exactly that: with a VBS enclave spinning, the VTL1 `RIP` moves across halts and
lands inside code we wrote, so the VTL1 read is live as well. **The idle
constant was the idle loop, not a stale read** — and S5c's readings rest on an instrument that has
now been checked rather than assumed.

#### The stop, measured against a guest that is actually doing something

S5c's headline figure was taken on an idle guest, where the separation is 40× and the record had
to say so. Repeated with both VPs spinning:

| | per 2000 ms |
|---|---|
| before the suspend | **19,512,433** |
| **while VTL1-suspended** | **818** |
| after release | **19,447,557** |
| symmetric arm, named VTL0 | 472 |

**23,854×**, with before and after within 0.3% of each other — so the load was steady across the
window and the drop is the suspend rather than the guest losing interest. On the all-VP arm both
processors drop together, 7,290,238 → 319 and 7,300,560 → 269. This is what the idle measurement
was trying to show, and it is four orders of magnitude rather than one and a half.

#### What driving the guest did *not* settle

- **`ActiveVtl = 1` was still never observed**, and the sample count is now **832,560+** across
  three conditions: idle, a two-VP user-mode spin, and **twelve freshly loaded kernel driver
  images** — every one of them verified by HVCI, which is enforced on this guest
  (`SecurityServicesRunning = 2`, `CodeIntegrityPolicyEnforcement = 2`).

  **And the reason is now quantitative rather than a shrug, which is the useful part.** The thing
  that occupies a VP in VTL1 for a measurable span is a **trustlet** — an IUM process, which runs in
  VTL1 *user* mode — not an HVCI verification, which is a brief excursion into VTL1 kernel mode.
  This guest runs exactly one trustlet, `LsaIso`, and it is **inert**: `TotalProcessorTime`
  **0.3593750 s across 27.6 hours** of uptime, a duty cycle near 0.0004%, and **unchanged to the
  tick** across a burst of loopback logons. It is inert because Credential Guard is not configured
  — `LsaCfgFlags` unset, `RequiredSecurityProperties = 0`, `SecurityServicesRunning` listing HVCI
  alone — so `LsaIso` is loaded and does no work. At 0.36 s of VTL1 user-mode execution in 27 hours,
  832,560 samples would expect about **1.5** hits if that time were spread evenly -- that total is
  the *combined* figure across two VPs, which an earlier draft divided as though it were per-VP and
  called ~3 -- and under uniform sampling zero still carries roughly a **22%** probability. So the
  arithmetic shows this result is **compatible with rare `LsaIso` activity**, which is weaker than
  the validation of the sampler it was first written as: S5g's known VTL1 workloads produced zero
  hits too, and that points at `ActiveVtl` not reporting rather than at a sampler missing windows.
- **So the experiment that would settle it is to give the guest a trustlet that works.** That was
  then attempted, with the operator's authorisation, and is the S5g result below: both routes to a
  working trustlet are closed on this bench, one by edition and one by signing policy.
- **The halt's necessity is still not demonstrated.** S5d compared two back-to-back reads, which an
  idle guest passes trivially; the sharper test samples the same pages across a **matched
  wall-clock window** in both conditions. Over 3 s with the guest busy: **80,399 reads while
  running, one distinct value per page**, and the same one value while halted. Those three VTL1
  pages are simply static, which a user-mode spin would not change — nothing in that workload
  mutates Secure Kernel's memory. Showing the halt matters needs pages SK is actively writing, and
  finding those needs the VTL1 activity the point above could not catch.

#### What it cost the bench

Twelve inbox driver images were loaded in the VBS guest to try to provoke VTL1, of which eleven
will not stop (`sc stop` is unsupported for them) and remain loaded until it reboots. They are
inbox drivers for hardware the VM does not have, they failed to find devices, and a reboot clears
them — but the guest is not byte-for-byte as it was found, and a later gate reading its module list
should know why there is a FireWire controller in it.

### S5g result, 2026-09-28: the enclave route is open and measured; one route closed, one unresolved

**One door is shut, one is unresolved, and the third is open: our own code now runs in VTL1, and a halt taken
while it runs is the condition every earlier gate was qualified on.** The value is in both halves —
which routes are closed and why, and what the working one finally measured. S5f turned "VTL1 runs
too rarely to catch" into a number; this turns "we could make it run" into two specific refusals
and one success. Run with the operator's authorisation to reconfigure and reboot the VBS guest; see
*What it cost the bench* at the end, because this one changed the guest materially.

#### Route 1 — Credential Guard: unresolved, and the edition was the wrong answer

The cheapest workload is the trustlet already present. `LsaCfgFlags = 1` did nothing, so
`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled = 1` and
`EnableVirtualizationBasedSecurity = 1` went in beside it. **Two reboots, and
`SecurityServicesRunning` stayed `2`** — HVCI alone, no Credential Guard, and not one event in
`Microsoft-Windows-DeviceGuard/Operational` to explain it.

**The explanation is NOT the edition, and an earlier version of this section said it was.**
Microsoft's Credential Guard documentation carries an edition table reading *Windows Pro: **No***,
and that table was used here to decline a review finding which said the edition could not be the
cause. **The finding was right and the citation was wrong.** The operator produced a Windows 11 Pro
machine whose Security UI reports *"Credential Guard is protecting your account log-in from
attacks"*, and this bench's own host — `Windows 11 Pro`, build 26200 — is running `LsaIso` with
`VirtualizationBasedSecurityStatus = 2`. **Pro runs Credential Guard in practice**, whatever the
table says.

**Worse for the original reading, the test itself is suspect.** That host reports
`SecurityServicesConfigured = 0` and `SecurityServicesRunning = 0` while its own UI says Credential
Guard is protecting it — so `SecurityServicesRunning` staying `2` on the guest does not establish
that Credential Guard failed to start, which is the entire evidential basis the conclusion rested
on.

**So this route is recorded as unresolved rather than closed.** Why the guest did not report
Credential Guard after both documented switches and two reboots is unknown: candidates include the
in-VM requirements the same documentation lists (a Hyper-V host with an IOMMU, a generation 2 VM),
licensing entitlement, and the reporting field being unreliable. **It no longer blocks anything** —
route 3 below produced the VTL1 workload this gate wanted — but the reasoning that retired it was
unsound and is retracted here rather than left standing.

**Secure Boot was `On` for both of those reboots**, which matters because Secure Boot is a
documented Credential Guard prerequisite and this record later turns it **off** for the enclave
route. Raised in review as a confounder and it is not one: the ordering was two Credential Guard
reboots with Secure Boot on, *then* the enclave work that disabled it. The prerequisite was met and
the activation still did not happen.

**And the value used carries a UEFI lock, which a draft of this section called reversible.**
Microsoft documents `LsaCfgFlags` `1` as *enabled with UEFI lock* and `2` as *enabled without
lock*, with the locked form removable only through an `SecConfig.efi` boot-sequence procedure that
requires physical presence. `1` is what went onto this guest. Credential Guard never activated, so
and an earlier draft concluded from that that no lock can have been established — **which the
retraction above forbids**: the test that said it never activated is the one just discarded, so
**the lock state is unknown** and a later cleanup of this guest should assume it may need the
documented `SecConfig.efi` removal procedure until someone checks. **A repeat on an eligible
edition must use `2`**,
and the escape hatch for a VM is worth recording beside it: the same documentation says a virtual
machine's Credential Guard can be disabled from the host with
`Set-VMSecurity -VMName <n> -VirtualizationBasedSecurityOptOut $true`.

#### Route 2 — writing a trustlet: closed by signing policy

An IUM process must be signed with a **Microsoft** certificate carrying the Isolated User Mode EKU
*and* appear in Secure Kernel's trustlet identity list. Test-signing is not honoured for that path,
by design — arbitrary VTL1 user-mode code is precisely what VBS exists to prevent. There is no
local route, and this was not attempted.

**Patching SK's identity list from the root was raised and declined.** S4 established VTL1 is
writable by the direct route, so it is coherent rather than fanciful — and it is the wrong tool:
SKPG/HyperGuard monitors exactly that, the likely outcome is a bugcheck rather than a trustlet, and
it means modifying live policy state whose layout nothing here has mapped. If it is ever wanted it
is its own gate, against a throwaway checkpoint, with the bugcheck as the expected result.

#### Route 3 — a VBS enclave: **open**, once the official sample was used as the reference

**This route works, and the nine failures below were all one mistake: building from first
principles instead of from Microsoft's sample.** `windows-classic-samples/Samples/VbsEnclave` is
the reference; against it the image loads, initialises and runs, and *our own code executes in VTL1
user mode*:

```text
LoadEnclaveImage ok
InitializeEnclave ok
Spin at 000001CE77FE5030 -- calling 2 x 20000000 rounds IN VTL1
done: 2 calls in 78 ms
```

**Five differences mattered, and the first is the one that had been refusing the image.** The
sample sets `PolicyFlags = IMAGE_ENCLAVE_POLICY_DEBUGGABLE`; this build had `0`, while the *host*
creates the enclave with `ENCLAVE_VBS_FLAG_DEBUG` — a debug host and a non-debuggable image, which
the loader is entitled to refuse. Beside it: non-zero `FamilyID`/`ImageID` where this had zeros; an
`EnclaveSize` of `0x10000000` that the host's `CreateEnclave` must match, against 16 MiB here;
**no `/ENTRY` override**, so the enclave CRT's `_DllMainCRTStartup` runs rather than a raw
`DllMain`; and `/GUARD:MIXED` with `SubSystem CONSOLE`, exports through a `.def`, and the *enclave*
`libcmt`/`libvcruntime` kept rather than removed.

#### Route 3 — the eight attempts before the reference existed

An enclave is the documented way to run *your own* code in VTL1 user mode, and unlike a trustlet it
is a developer facility. The guest supports it — `IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS)` is
true, `vertdll.dll` is present — and `CreateEnclave` with `ENCLAVE_VBS_FLAG_DEBUG` **succeeds every
run**. `LoadEnclaveImage` did not, and nine suspects were eliminated one at a time — the ninth
being signature trust, which is the row most easily miscounted because it was cleared by an
operator action rather than a rebuild:

| suspect | what was done | result |
|---|---|---|
| no enclave config | `IMAGE_ENCLAVE_CONFIG` added, verified by `dumpbin /LOADCONFIG` | still 193 |
| no load-config directory | forced with `/INCLUDE:_load_config_used`, later an explicit one for `/NODEFAULTLIB` | still 193 |
| no page hashes | `signtool /ph` — which reports the file **as a VBS enclave image** | still 193 |
| no imports at all | a `vertdll` import added | still 193 |
| wrong EKU | signed with `szOID_ENCLAVE_SIGNING`, `1.3.6.1.4.1.311.10.3.42` (from `um/wincrypt.h`) | still 193 |
| TLS directory | checked — absent | not the cause |
| desktop CRT | relinked against `ucrt_enclave` and MSVC's `lib\x64\enclave` | still 193 |
| **missing `/INTEGRITYCHECK`** | added, with `/ENCLAVE /NODEFAULTLIB /INCREMENTAL:NO`; characteristics went `0x160` → **`0x1E0`**, *Check integrity* set | still 193 |
| signature not trusted | cert imported to the guest's `LocalMachine\Root`; in-guest status went `UnknownError` → **`Valid`** | **still 193** |

**Two of those moved the failure and neither fixed it**, which is the useful part: enabling
test-signing took the error from **577 `ERROR_INVALID_IMAGE_HASH`** to **193
`ERROR_BAD_EXE_FORMAT`**, and establishing chain trust left it at 193 with the signature verifying.
So the signature path is satisfied and what remains is a **shape** rule the loader applies and this
record has not identified. `veclient.lib`, named in the requirements this build followed, does not
exist in SDK `10.0.26100`; `vertdll.lib` is its equivalent here, and whether that substitution is
the defect is unmeasured.

**What the refusal does *not* stop is enclave creation, and that produced one more reading and one
more correction.** The guest's System log records a **`Secure Trustlet … started` / `stopped`** pair
for a run, so `CreateEnclave` really does instantiate a container in VTL1 even though the image
never loads — which looked like a usable VTL1 workload. A loop was built on it: **300
create/terminate cycles in 15 ms**, then 400,000 cycles while the sampler ran, for **326,468
further samples and still no `ActiveVtl = 1`**.

**Then the trustlet events were counted, and there were ten in three minutes rather than 400,000.**
So the creates after the first are not each instantiating a secure trustlet — at 50 µs a cycle they
are mostly VTL0 bookkeeping — and "a sustained VTL1 workload" was a claim made from a plausible
mechanism rather than from a count. It is recorded here as the fourth workload *with that
qualification*, not as the strong one it was briefly described as.

**Across four workloads — idle, a user-mode spin, twelve HVCI-verified kernel image loads, and the
enclave loop — `ActiveVtl` has now read `0` in more than 1.15 million samples.** Two readings fit
and this bench cannot separate them: VTL1 windows are consistently shorter than the ~55 µs sampling
interval, or **the parent-side `HvRegisterVsmVpStatus.ActiveVtl` does not report a VP that is
executing VTL1 at all**. The second has become the likelier of the two — a sampler at ~16,000 reads
per second per VP that never once lands in VTL1, across workloads that certainly enter it, is
easier to explain by the field than by the timing — but neither is established, and the
halted-register readings stay conditional either way.

#### With VTL1 running, the condition every earlier reading was qualified on is finally measured

**`ActiveVtl` still reads `0` while VTL1 is provably executing, so it is not a usable indicator.**
With the enclave spinning and the VPs measurably busy — VP 0 at **25.8%**, VP 1 at **52.4%** by
`HvRegisterVpRuntime` — `ActiveVtl` came back `0` in **274,566** samples, and VP 0's *VTL0* `RIP`
read the idle loop while that VP was a quarter busy. Whether the field cannot express VTL1 or the
parent-side read is served at a VTL0 boundary is not settled here; either way, **the parent cannot
use it to tell whether VTL1 is running**, which is what round nine of
[#409](https://github.com/glslang/windbg-mcp/pull/409) concluded on weaker grounds.

**A method error had to be corrected first, and it invalidated a reading this record nearly kept.**
An earlier "zero even while our code spins in VTL1" was taken against a spin launched with
`Invoke-Command -AsJob` — and each of this bench's PowerShell invocations is its own process, so
the job and its remote session died when the call returned. The VP runtime said so: **0.7% and
0.3% busy** while the "spin" was supposedly running. The workload only exists when the guest-side
process is **detached** with `Start-Process`, which is why the earlier CPU-load arms were real and
the enclave ones were not.

**Halt the VP while the enclave runs, and the VTL1 context is the enclave's own.** Six halts, all
with the spin confirmed running:

| | VP 0 | VP 1 |
|---|---|---|
| VTL1 `RIP` caught | `0xFFFFF80679FB0035` — Secure Kernel, parked | **`0x21456DE509B`–`0x21456DE50BC`** — *user mode, inside the enclave* |
| halts catching VTL1 executing | 0 of 6 | **6 of 6** |
| distinct addresses across halts | 1 | **5** |
| stable within one halt (10 reads) | yes | **yes** |

A ~34-byte span is what a tight loop looks like. **So the halt catches VTL1 mid-execution, freezes
it, and the VTL1 registers report the running context** — five distinct addresses across six halts
proves it is sampling live code, and the stability within each halt proves the halt stopped it.
VP 0 stayed parked at Secure Kernel's address throughout, so the two processors are distinguished
correctly.

**What this retires.** Every halted-register reading in S5c and S5e was conditional on
`ActiveVtl = 0` with VTL1 parked, and the record said repeatedly that the `ActiveVtl = 1` case was
unmeasured and unreachable. It is now measured — by a workload that puts VTL1 in user mode rather
than by catching `ActiveVtl`, which never reports it. The halted VTL1 context behaves the same way
it did parked: readable, stable under the halt, and its own rather than VTL0's.

**And it settles the liveness scope from the other direction.** #411's review correctly limited the
"the register interface is live" result to VTL0, because only VTL0 had been varied. The VTL1 `RIP`
now moves across halts and tracks code we wrote, so **the VTL1 read is live too** — established
here rather than assumed there.

**Where to start next, and what to avoid.** *(Superseded above: the image now loads. Kept because
the elimination order is what a reader repeating this needs.)* Diff the image against a
*known-good* enclave binary —
Microsoft's VBS enclave sample or the enclave SDK package — rather than forming another hypothesis.
An attempt to find one by scanning `System32` for images carrying an enclave configuration read the
wrong offset in `IMAGE_LOAD_CONFIG_DIRECTORY64` and returned 62 false positives including `mfc140`
and `libomp140`, which is this record's recurring defect (a structure guessed at rather than
sourced) arriving one more time.

#### What it cost the bench

The VBS guest is **not** as it was found, and a later gate reading it needs to know:

- **Secure Boot off** and **test-signing on** — both required to get as far as a trusted
  self-signed enclave image, both operator-authorised, both reversible.
- **VBS and HVCI survived both**, which was checked rather than assumed: `VBSStatus = 2`,
  `SecurityServicesRunning = 2`, `CodeIntegrityPolicyEnforcement = 2` after Secure Boot came off.
  So VTL1 is intact and the subject of every earlier gate still exists.
- A self-signed **`CN=VTL1 Enclave Test`** certificate sits in the guest's `LocalMachine\Root`.
- `LsaCfgFlags` and the DeviceGuard Credential Guard scenario keys are set and inert.
- `C:\encl\` holds the enclave, its host and the certificate.
- **Four reboots, and the new landmarks are *measured* rather than inferred from that count.**
  Inferring movement from a reboot is the same error in reverse as inferring sameness from an equal
  `CR3`, which this record corrects above — the value has repeated across boots before. As read
  after S5g: VTL1 `CR3` **`0x3BEF2000`** (it was `0x1201000` for S5c–S5f) and Secure Kernel parked at
  **`0xFFFFF80679FB0035`**. The self-map index was not re-read and is unknown rather than assumed to
  have moved.

### S5h result, 2026-09-28: a VTL1-raised exception is held and handed back, and which VTL takes it is not settled

**A parent-installed exception intercept stops a `#BP` raised in VTL1 user mode from ever reaching
the guest, and hands it back intact when the intercept comes down** — no guest-side cooperation, no
port, no patched byte. That is the first time anything in this record has stopped VTL1 execution at
a *chosen kind of event* rather than at an arbitrary polling point, which is what S5c's halt gives.

**What it does not settle is S5b's actual question.** That gate installed and removed an intercept
without provoking anything, so it could not tell an implicitly-VTL0 intercept from an
implicitly-every-VTL one, and recorded the route as *unresolved on scope*. **It stays unresolved.**
A first version of this section claimed the halt readings ruled out the alternative — that the
enclave's exception dispatch makes a VTL0 excursion and a VTL0-scoped intercept catches *that* — and
review showed they do not; see *Where the held thread sits* below, which now carries the retraction
and what would settle it.

So this section reports a **behaviour** that is measured and a **mechanism** that is not, and the
two matter differently: the behaviour is what a debugger would use, and the mechanism is what decides
whether it reaches Secure Kernel's own code. *What this does not establish*, at the end, is the part
to read before building on any of it.

**S5g is what made it runnable.** A VTL1 exception was needed that is not a planted `int 3` in
Secure Kernel, which the plan excludes and which would bugcheck the guest. S5g's enclave supplies
one: our own code, in VTL1 user mode, in a process we start and can lose.

#### The instrument

One guest-side binary raises the exception in **both** VTLs, so the two arms differ in the VTL and
in nothing else — `spin_host.exe BP0` runs the loop in VTL0, `BP1` runs the identical loop inside
the enclave through a new `RaiseBp` export, and each catches its own exception with `__try` /
`__except` and counts what came back. The count is the detector: an intercept that fires takes the
trap **before the guest dispatches it**, so `handled` tracking `rounds` says the guest saw every
exception and `handled` frozen says something else took them. **This probe holds no port of its
own**, so it receives nothing — and it does not need to in order to see the effect at the guest's
end. That is not the same as saying nothing received the message: the root's own virtualization
stack owns a port for every child it runs, and an exception intercept it never asked for arriving
there is the likeliest mechanism of the hold. Unmeasured either way; see the bullets at the end.

Beside it, from the parent: `HvRegisterVpRuntime` each second, a second PowerShell Direct
connection four seconds into every intercept arm to ask whether the *guest* is still alive or only
the raising thread is stuck, and S5c's halt to read `RIP` at both VTLs while the arm is stalled.
The client is `s5h.py`, on the same `h3probe.sys` IOCTL as S5b and S5c.

**Every arm is a null / intercept / null triple**, run back to back: a difference between readings
taken minutes apart is drift, and interleaving is what makes it the intercept.

#### What the guest did, arm by arm

Twenty thousand raises per arm. The null rate is what every intercept arm is read against, and the
two VTLs have different null rates — a VTL1 exception costs about eleven times a VTL0 one on this
guest, which is itself a measurement this gate did not have before:

| arm | null | with the intercept standing |
|---|---|---|
| **VTL0**, VTL0-only guest | 20,000/20,000, `0.86 us` each | **0 handled**, all 120 samples over 24.4 s |
| **VTL0**, VBS guest | 20,000/20,000, `0.82–0.96 us` each | **0 handled**, all 120 samples over 24.4 s |
| **VTL1**, VBS guest, in the enclave | 20,000/20,000, `9.47–9.97 us` each | **0 handled**, 120 samples over 24.4 s, the 121st taken after the release |

Every arm reports code `0x80000003` (`STATUS_BREAKPOINT`) in its null, so what the handler caught
is checkable as the exception that was raised rather than assumed.

**Released mid-arm, all three complete.** Removing the intercept at 25 s while the raiser is still
running lets every arm finish **20,000/20,000** — so the traps were **held, not discarded**, and
the hold is resumable. That is the difference between a stop a debugger could use and a swallowed
exception, and it is measured rather than inferred. Held for 24.4 s of a 24.6 s run, the arms
average `1224–1235 us` per exception against nulls of `0.86` and `9.7`.

Longer holds behave the same. Without the release the arm is killed at its timeout and the teardown
removes the intercept, so the zeroes are counted up to that point: **198, 218 and 291** consecutive
zero samples on the VTL0 arms of the 40 s, 45 s and 60 s runs, and **193, 218 and 291** on the VTL1
arms of the same three, each followed by the single post-release sample the next section is about.

#### The two controls, because either one alone leaves the finding unreadable

An intercept that is standing and an exception that is being taken are the same observation unless
both are varied. So both were:

| control | VTL0 | VTL1 |
|---|---|---|
| **install `#BR` (`0x05`), raise `#BP`** — an intercept nothing triggers | `0.94 us` against a `0.84` null, 20,000/20,000 | `9.71 us` against a `9.88` null, 20,000/20,000 |
| **install `#BP` (`0x03`), raise `#DE`** — an exception the intercept is not for | `1.23 us` against a `1.13` null, 20,000/20,000 | `9.36 us` against a `10.01` null, 20,000/20,000 |

Neither control moves either arm. The effect needs the installed vector to **be** the raised one,
which is what "this intercept fires for this exception" means. `#DE` is raised by an integer divide
by zero and reports `0xC0000094`, at a null cost within 15% of `#BP`'s in both VTLs, so it is a
matched substitute rather than a cheaper one.

The negative control from S5b ran first in every run and refused every time: intercept type
`0xFFFFFFFF` returns `0x0005 INVALID_PARAMETER`, so `SUCCESS` on the real installs means something.
`#BP` acceptance was re-derived on the VTL0-only child in each run rather than recalled from S5b's
table.

#### The retraction this gate had to make about its own first reading

**The first four runs reported the VTL1 arm as *advancing* under the intercept — 1,902 then 6,396
then 15,076 then 18,486 handled — and all four readings were wrong.** The monitor writes the live
count every 200 ms; the arm's teardown removes the intercept; the guest-side raiser then finishes
its remaining raises in under a second, and the monitor gets one more write in before it exits. The
figure being read was that write. Converted to a rate it looked like a credible partial effect —
"405x slower but advancing" — and it supported a whole reading in which the intercept reached VTL0
and VTL1 differently.

What caught it was the release arm, where the removal is explicit and the samples before it are
unambiguous. Re-reading the trace then settled it: **the count first moves at sample 121 of 121**,
and in the runs with no release, at sample 219 of 219. One hundred and twenty consecutive zeroes,
then a post-release burst.

The reading now comes from **where the count first moved**, not from what it ended at, and the
script says `ALL ZERO` or names the sample. *A prefix is not a page* has a sibling here: the last
sample is on the wrong side of the release.

#### Where the held thread sits, and what the halt says about which VTL

Six halts, five seconds apart, with the intercept standing (S5c's `HvRegisterExplicitSuspend`,
released in a `finally`; every halt reported `released: True`):

| | VTL0 arm | VTL1 arm |
|---|---|---|
| where the raiser was caught | VTL0 `RIP` **`0x00007FF7D5AF748D`**, user mode | VTL1 `RIP` **`0x000001D1009E500D`**, user mode inside the enclave |
| halts that caught it | **3 of 6** | **6 of 6** |
| the address, across those halts | one, with `RSP` `0x000000B3BF7DF968` every time | one, with `RSP` `0x000001D0F0B0FEB8` every time |
| the other VTL on that VP | VTL1 parked at Secure Kernel's `0xFFFFF80679FB0035` | VTL0 read `0xFFFFF80679FB001C`, `RSP` `0xFFFFB18F23D8A648` |

The **3 of 6** is a property of the halt, not of the hold: on the other three the read returned
Secure Kernel's parked address for both VTLs, which is the shape S5c recorded and means the halt did
not land on the raiser. The raiser was held throughout all six — the progress file says so
independently. Which VP carried it moved between halts in both arms, so the table is per-arm rather
than per-VP.

**These halts do not settle which VTL the interception happens in, and an earlier version of this
section claimed they did.** It argued that if the enclave's exception dispatch made a VTL0 excursion
and the intercept were catching *that*, the stall would surface as a VTL0 **user-mode** `RIP` the way
the VTL0 arm's does — and it does not, so the excursion was ruled out. Review was right that this
does not follow. A VTL1 exception reflected into VTL0 would leave the VTL1 register set **saved at
the faulting instruction**, which is `0x000001D1009E500D`, while VTL0 sits in *kernel* code
handling the reflection — which is `0xFFFFF80679FB001C`. **That is exactly the pair this table
shows**, so the reading is consistent with both hypotheses and discriminates neither.

**Two further things cut the same way**, and both were available before the claim was made:

- The VTL0-labelled read is `0xFFFFF80679FB001C`, in the **same page** as the
  `0xFFFFF80679FB0035` this record attributes to Secure Kernel. A "VTL0" `RIP` landing in Secure
  Kernel's page is the S5c anomaly's signature — over eight halts S5c's VTL0-labelled `RIP`/`RSP`
  came back as the VTL1 values 8/8 — so the earlier claim that *"the VTL0-labelled read is not
  echoing VTL1 here"* rested on the two values merely differing. They do differ, including in
  `RSP`; that is weaker than being a trustworthy VTL0 context and was written as though it were
  stronger.
- The **null costs argue the other way**: a VTL1 exception costs `~9.7 us` against VTL0's
  `~0.85 us` on the same guest, and an 11x gap is what a VTL1 → VTL0 → VTL1 round trip would look
  like. That is a reason to take the excursion seriously rather than to dismiss it.

**What still stands is the behaviour, not the mechanism.** A `#BP` raised in VTL1 user mode is held
and handed back; *where* the hypervisor takes it is unresolved. And this is not a separate worry
from the scope limit below — it is the same one, because an excursion-mediated hold would not extend
to Secure Kernel's own code, which handles its exceptions in VTL1 without one. **What would settle
it** is the route S5b named and this gate skipped: a static read of `hvix64.exe`'s intercept dispatch
for a check on the active VTL, two attempts having failed on that image before Ghidra was on this
bench — or delivery metadata from an actual receiver, which is the other next gate.

On halts where the VP was not running the raiser, both reads return Secure Kernel's parked address,
which is why the table says where the raiser was *caught* rather than what every read returned.

#### The blast radius, which is narrower than the first run suggested

**The guest keeps serving while an intercept stands.** A second PowerShell Direct connection opened
four seconds into every intercept arm answered with the guest's computer name every time, on both
guests — so a partition-wide `#BP` intercept does not wedge the partition.

**That is all it shows, and an earlier version of this section read it as "only the raising thread
is held".** It does not follow: the intercept is partition-scoped, so any *other* thread raising
`#BP` in that window would be held too, and no such thread was arranged as a control — the
connection that answered is one that raises no `#BP` at all. The claim is continued guest service,
not exclusive single-thread impact. **Treat a standing `#BP` intercept as freezing every thread in
the partition that raises that vector**, which is also why an install must be paired with its
removal in a `finally`.

**And the first run's runtime figures were read as a livelock, which per-second rates say they are
not.** The rates come from the timestamped sample series the later runs take once a second:
**`0.12–0.16`** and **`0.48–0.55`** CPU-seconds per second over windows of 25–44 s, one VP about an
eighth busy and one about half.

The first run took no such series, only a raw `HvRegisterVpRuntime` delta across the whole arm —
444 M and 664 M 100ns units, which is 44.5 and 66.4 CPU-seconds and looks like two processors
spinning. That arm's wall time was not recorded; against the ~190 s it must have been it works out
near **`0.23`** and **`0.35`** per second. An earlier version of this paragraph gave those deltas
and then quoted the sample-series rates as though they were the result of dividing them, which they
are not — they are different runs, and the split between the two VPs differs because the raiser
thread does not always land on the same one.

What both agree on is the only claim made here: **a fraction of one VP, never saturated.** There is
no matched-duration idle baseline to put beside either — the null arms last seconds and their wall
time is not recorded — so this does not quantify how much of that is the hold.

Both guests came through every run: teardown reported **0 intercepts still standing** each time, no
straggler processes, VBS and HVCI still `2` on the VBS guest, no reboot. **This gate cost the bench
nothing**, which is worth recording because S5g cost it four reboots.

#### What this does not establish, and the two scope limits are the important part

- **Which VTL the interception happens in.** The hold is measured at the guest's exception
  dispatch; whether the hypervisor takes the trap in VTL1, or takes a VTL0 event that dispatching
  the VTL1 exception produces, is open — see the retraction under *Where the held thread sits*. So
  S5b's "implicitly VTL0 or implicitly every VTL" is **not** answered here.
- **It is VTL1 *user* mode, not Secure Kernel**, and this is the same limit wearing different
  clothes. The enclave runs in VTL1 user mode (IUM); Secure Kernel is VTL1 kernel mode and handles
  its own exceptions without returning to VTL0. So if the hold turns out to be excursion-mediated,
  it would **not** extend to Secure Kernel — the mechanism question above governs this one rather
  than sitting beside it. The plan forbids planting an `int 3` in Secure Kernel to check, and that
  prohibition stands: treat *"a `#BP` in Secure Kernel would be held too"* as untested.
- **Nothing was delivered to *us*.** This probe has no port and read no intercept message. S5's pass
  condition wants a stop *delivered to a debugger*, and nothing here was. The gate does not pass.
- **The mechanism of the hold is unmeasured, and the obvious candidate is not this probe's
  absence.** Hyper-V's own stack owns a port for each child — S5b found eleven `Vid.sys` call sites
  reaching `WinHvInstallIntercept`, so intercepts on children are ordinary there — and an exception
  intercept nobody asked for arriving at that port, with `vmwp` never completing it, would produce
  exactly this: the trap held, the thread pending, the rest of the partition untouched. Whether that
  is what happens, or the hypervisor queues an undeliverable message some other way, is not
  established by anything here. What is established is the behaviour at the guest's exception
  dispatch. **S5k read that port's owner and found a third possibility**: the message does reach
  Hyper-V's own routine, which *discards* it rather than holding it whenever the vector is not
  claimed in a per-partition table an install hypercall does not touch. Whether this gate's own
  message met that branch turns on a runtime byte S5k did not read, and **the controls above cannot
  stand in for it**: they observe a hypervisor mask this probe's own raw removals also write, and
  S5l read those removals clearing it — so the implication a controls-based argument would need is
  false on a probed child. See S5k, which sets the argument out and retracts it.
- **`HvCallCreatePort` / `HvCallConnectPort` are untried**, and the bullet above is why the next
  gate has to establish *where the message goes* before assuming a port of our own would receive
  it. If intercepts are delivered to the partition's designated port, creating a second one is not
  the answer. **S5j ran that step and this is what it found**: the message is already addressed to
  the parent, and those two hypercalls are not the build — see the S5j result below.

#### What this gate leaves open, and what not to repeat

- **Do not** re-run the controls. The `#BR`-installed and `#DE`-raised arms are taken on both VTLs,
  and the negative control ran in every one of six runs.
- **Do not** read a progress count without checking which side of the release it is on. That is
  this gate's own retracted reading, and the script now refuses to make it.
- **Do not** plant an `int 3` in Secure Kernel to extend the result from VTL1 user mode to VTL1
  kernel mode. S5a's prohibition is unchanged and the guest would bugcheck.
- **Two questions were left open here, and both have since been carried forward** — the ordering
  lives in `FOLLOWUPS.md` item 103 rather than in this list, which is what kept it from going stale
  a fourth time.
  - **The receiver**, which is what S5's pass condition needs — but it starts one step earlier than
    "create a port": first establish **where an exception intercept message on a child is delivered
    today**, since the root's stack already owns a port for that child and is the likeliest
    recipient. `Vid.sys` and `winhvr.sys` were both read for S5b and are the same two images to read
    for this. **Run as S5j below, and it replaced the rest of this bullet**: the hand-rolled port
    and SynIC page are not the build, because `winhvr.sys` exports the API and `Vid.sys` already
    consumes it — and a registration may *displace* whatever entry Hyper-V holds, so the next
    step is identifying the table's key, which decides whether it displaces anything at all.
    **S5k ran that step too, and the exported API is not the build either**: the key is the
    partition id, the entry is Vid's, and the receiving path Vid already runs needs a *vector
    registration*, which is an IOCTL rather than anything built here.
  - **The dispatch read**, which is what decides whether any of this reaches Secure Kernel:
    `hvix64.exe`'s exception-intercept path, for a check on the active VTL. S5b named it, two
    attempts had failed on that image, and Ghidra is on this bench now. A receiver that works would
    also answer it from the other side, through the delivery metadata — so either experiment can go
    first, and neither makes the other unnecessary for the *other* question.

### S5i result, 2026-09-29: the intercept reaches VTL1 by design, and the hypervisor says so in five steps

**A parent-installed exception intercept is applied at every enabled VTL, and that is deliberate
rather than incidental.** S5b left the scope question open — with no VTL selector in the ABI, an
intercept is either implicitly VTL0 or implicitly every VTL — and S5h could not close it, because
its halt readings fit an excursion just as well as a VTL1 interception. Reading the hypervisor
settles it: the mask a parent installs is seeded at the child's VTL0 slot and **OR'd into every
VTL's effective mask** by a loop whose whole purpose is that propagation.

So S5b's question resolves in the second direction, and **S5h's hold was genuine VTL1
interception.** #412 was right to withdraw that claim from the halt evidence — the evidence did not
carry it — and the claim itself turns out to be true on different evidence.

**Why this read succeeded where two earlier ones failed.** Both earlier attempts went looking for a
*hypercall dispatch table* by structural heuristics and found the IDT and a 512-entry page-table
walk (recorded under S5a). This one asked an architectural question instead. On Intel VMX an
exception intercept **is** the VMCS exception bitmap, field encoding `0x4004`: the hypervisor must
`vmwrite` it, and an exception whose bit is clear never exits to the hypervisor at all. That is one
constant in one instruction, and it is reachable by scanning rather than by guessing at layout. The
instrument is [`tools/sk_vmcs_scan.py`](../../tools/sk_vmcs_scan.py).

**Measured against** `C:\Windows\System32\hvix64.exe`, **`10.0.26100.9444`**, SHA-256
`CF5AF317F300B7DA25F37D5DC6CA75BFF91B6B868D89F337D23EC1773340CE8A` — this host's own hypervisor,
which is the one S5b and S5h ran against. All RVAs below are image-relative; the image base is
`0xFFFFF80000000000` and there is no PDB for it. The exception directory yields 5,763 functions
covering **97.2%** of the executable bytes, and of 417 `vmwrite`/`vmread` sites **355** resolve to
an immediate field encoding.

**The tracker behind that number was unsound when this section was first written**, and review on
[#413](https://github.com/glslang/windbg-mcp/pull/413) found **sixteen** defects in it over six
rounds, and they are mostly one mistake wearing many costumes: **reading rendered text where
capstone had already decoded the thing itself**, plus two places that used a decoded field without
asking what it meant.

- *The constant tracker*, five ways to invent a resolved field: carrying a constant across a branch
  that skips its assignment; treating `mov ax, 0x4004` as defining all of `rax`; letting `vmread`
  leave its destination's old constant in place; invalidating only the first of two comma-separated
  operands, so `inc eax` and `pop rax` left a stale value; and an alias table with no
  `ah`/`bh`/`ch`/`dh` in it.
- *`--imm`*, five, and the last three are one equivalence corrected three times: a substring match
  over the printed operands; an equivalence that compared only the low 32 bits; counting a
  `call`/`jmp` destination as a data constant; applying the imm32 sign-extension equivalence to
  operands **not** encoded as imm32, so `--imm 0x80010003` matched
  `movabs rax, 0xffffffff80010003` (both bots reported that one independently); and then applying
  it **symmetrically**, so a query for a sign-extended value matched `mov eax, 0x80004004` — whose
  32-bit destination *zero*-extends, so the instruction does not carry it. The rule that survives
  is narrow: `encoding.imm_size == 4`, and only a decoded value normalised toward a 32-bit query,
  never the reverse.
- *`--offset`*, two: matching a rendered `0x…]`, which a small displacement never produces, and
  inferring "written" from operand position — which labels `call qword ptr [rax + 0x1a04]` a write.
- *`--range`*, two: no validation at all, then validating only the start, so a range running off
  the end of its section decoded whatever followed **in the file** and labelled it with RVAs it does
  not have.
- *Caller enumeration*, one: `branch_target()` accepted every `CS_GRP_JUMP` instruction, so a `jcc`
  landing on a function's entry counted as a direct caller. A conditional edge is not a call, and
  the counts here are what a reader walks the chain by. (Re-derived after the fix: unchanged, so
  nothing in this section was ever inflated by it — but that is a measurement, not the reason the
  bug was acceptable.)

All sixteen are fixed, each pinned by the counterexample it was named for, and the branch-target,
immediate and displacement decisions live in one helper apiece rather than at each call site.
`--self-test` runs 20 cases, one of which caught a mistake in another test's hand-assembled bytes
rather than in the code.

**Every figure in this section and in S5j was re-derived after each round, and none has moved:**
417 `vmwrite`/`vmread` sites with 355 resolved, the same two functions for field `0x4004`, caller
counts of 14, 2, 2 and 2 along the chain, `+0x1A04` at 9 sites with the same 2 writers, `+0x1A08`
9/2, `+0x1A0C` 4/2, `+0x6124` 6/3, and `0x80010003` at exactly one site. That stability is the
argument, not the fix list: **the conclusions never rested on the tracker.** Each anchor was read
instruction by instruction before it was used, and the chain past it is caller enumeration and
per-function disassembly, which no amount of constant tracking can bend. **The result below did not
move**: the same two sites, before and after. What moved is the resolved count, 373 to 355, which is
the conservative clearing losing real resolutions rather than inventing false ones — the direction
that cannot manufacture an anchor.

**And the anchor never rested on the tracker anyway.** The two functions it named were read
instruction by instruction, and in each the `mov` sits immediately before the `vmwrite`/`vmread`
inside a 48- and 46-byte function with no branch between them. Everything downstream — callers,
displacement scans, per-function disassembly — uses no register tracking at all.

#### The chain, in the five steps that carry it

| # | where | what it does |
|---|---|---|
| 1 | `+0x295800` | `HvCallInstallIntercept`: reads `PartitionId` at `+0`, `AccessType` at `+8`, `InterceptType` at `+0xC`, `InterceptParameter` at `+0x10`, and looks the partition up |
| 2 | `+0x295879` | **the VTL decision.** `cmp rdi, rax` against `gs:[0x360]`, the caller's own partition |
| 3 | `+0x2C9430` | `InterceptType == 3` lands here: `array[VTL].0x1A04 \|= 1 << vector`, indexed `[partition + VTL*8 + 0x63C8]` |
| 4 | `+0x2BECC8` | for every VTL in the set at `+0x63B8`, descending: `array[vtl].0x1A0C = accumulated 0x1A04 \| array[vtl].0x1A08`, **seeded with `array[0].0x1A04`** |
| 5 | `+0x331AA8` | programs the VMCS bitmap from `array[current VTL].0x1A0C`, through the `vmwrite 0x4004` accessor at `+0x32F3D8` |

**Step 2 is the answer to the question as asked.** There is a check on the VTL, and it is not in the
dispatch of a delivered exception — it is at *install* time, and it decides which VTL slot the
intercept is written to:

```text
0x295868  mov  rax, qword ptr gs:[0x360]     ; the calling partition
0x295871  mov  rdi, qword ptr [rbp + 0x20]   ; the target partition
0x295879  cmp  rdi, rax
0x29587C  je   0x295931                      ; target IS self -> use the caller's own VTL
0x295882  mov  cl, r14b                      ; target is a CHILD -> VTL := 0
```

`r14d` is zeroed on entry, so **a parent naming a child always installs at VTL 0** — which is
exactly why the ABI needs no VTL field, and why S5b found every byte it put where a VTL might hide
was ignored. The self branch instead takes the caller's own active VTL and *requires it to be
non-zero*, returning status `8` otherwise:

```text
0x295931  mov   rax, qword ptr gs:[0x358]    ; the current virtual processor
0x29593E  mov   rcx, qword ptr [rax + 0x3c0] ; its per-VTL context
0x295945  mov   cl, byte ptr [rcx + 0x14]    ; the active VTL
0x295948  test  cl, cl
0x29594A  jne   0x295885                     ; VTL 0 installing on itself is refused
```

That is Secure Kernel's own path — `ShvlInstallExceptionIntercept` issues `0x004D` with
`PartitionId` **SELF**, which S5b read from the 26100.9457 sample — and it explains why only a
higher VTL may use it.

**Step 4 is why VTL0's slot is not a VTL0-only slot.** The recompute descends the enabled-VTL set
and carries a mask down with it, starting from VTL0's:

```text
0x2BECD2  mov  r9d, dword ptr [rax + 0x1a04]        ; seed := array[0].1A04
0x2BECE7  movzx edx, cl                             ; loop: edx := this VTL
0x2BECED  mov  rcx, qword ptr [r8 + rdx*8 + 0x63c8]
0x2BECF5  or   eax, dword ptr [rcx + 0x1a08]
0x2BECFB  mov  dword ptr [rcx + 0x1a0c], eax        ; effective := seed | own
0x2BED0E  or   r9d, dword ptr [rax + 0x1a04]        ; seed |= this VTL's own
```

On a guest with VTLs `{0,1}` that is: `array[1].1A0C = array[0].1A04 | array[1].1A08`, then
`array[0].1A0C = array[0].1A04 | array[1].1A04 | array[0].1A08`. **The parent's mask is in VTL1's
effective mask**, and a higher VTL's own intercepts reach itself and every VTL below it.

**Step 5 is privilege-blind, which matters for Secure Kernel.** The bitmap is selected by
`byte ptr [r9 + 0x14]` — the same field step 2 reads as the caller's VTL, used in a second, independent
function, which is the strongest cross-check available without symbols — and a VMCS exception
bitmap does not distinguish CPL 0 from CPL 3. So nothing in this mechanism separates VTL1 *user*
mode from VTL1 *kernel* mode. That removes the specific reason S5h had to doubt that its result
extends to Secure Kernel's own code; it does not make that a measurement, and the prohibition on
planting an `int 3` in Secure Kernel is unchanged.

#### Four things S5b measured that this read independently explains

The read was done from the callee side and the live arms from the caller side, so these are
agreements rather than restatements:

| S5b measured | the code says |
|---|---|
| access mask `0xFFFFFFFF` → `0x0005 INVALID_PARAMETER` | `test r8d, 0xfffffffb` — `AccessType` may only be `0` or `4` |
| vector `0x1F` refused, `#BP` and `#BR` accepted | `cmp cx, 0x1f / ja` rejects above `0x1F`, then a per-partition permitted-vector mask at `+0x6124` gates the rest, with `or eax, 0x18` always permitting `#BP` and `#OF` |
| the block is `PartitionId`, `AccessType`, `InterceptType`, `InterceptParameter` | the handler reads exactly those at `+0`, `+8`, `+0xC`, `+0x10` |
| every byte put where a VTL might hide was ignored | nothing downstream of step 2 reads the block again for a VTL; the VTL comes from the self/child comparison |

#### What this does not establish

- **It is static, and hvix64 has no PDB.** Every field name here is inferred from use:
  `+0x14` as the VTL (two independent uses, both consistent), `+0x63B8 & 7` as the enabled-VTL set
  (three bits, matching the `EnabledVtlSet` of `0x3` and `0x1` the live arms read), `+0x63C8` as the
  per-VTL array (indexed by the same quantity in four functions). No symbol confirms any of them.
- **One build, one hypervisor, Intel only.** `10.0.26100.9444`, the host's own. `hvax64.exe` — the
  AMD hypervisor, which uses an SVM intercept vector rather than a VMCS bitmap — is not read here
  and nothing above transfers to it.
- **A loose end that is not a contradiction.** The VP-initialisation path at `+0x334223` programs
  the bitmap from `array[vtl].0x1A08` where the runtime path uses `+0x1A0C`. It cannot be what
  applies a *later* install, because an install recomputes `+0x1A0C` and then notifies the VPs
  (`+0x2BECC8` then `+0x2BED3C`), and `+0x1A08` has no writer but the type-16 installer and a
  zeroing at teardown. Why initialisation reads the other field is unestablished.
- **The scan reads immediates.** A field encoding arriving computed or loaded from data is invisible
  to it, which is the same limit `sk_hypercall_scan.py` records; 62 of 417 `vmwrite`/`vmread` sites
  did not resolve and were not chased.
- **It walks each function linearly**, so inline constants, padding or a jump table a branch skips
  over decode as though they were instructions — a data sequence could in principle be reported as
  a VMCS access, or a stray `E8` pair counted as a caller. Real instruction boundaries need a
  reachable-block traversal and this does not do one. **The mitigation is procedural**: every
  anchor above was then read as disassembly in full, and every call site was read in context, so a
  decode that was really data had to survive a human reading of the surrounding function to reach
  this page. That is weaker than a traversal and stronger than nothing, and it is stated here
  rather than left for a reader to discover.
- **It says nothing about delivery.** Where the resulting intercept *message* goes is untouched
  here, and remains S5's open half.

#### What it changes, and what to run next

- **S5b's scope question is closed**: implicitly every VTL. Do not re-open it and do not re-run the
  spare-byte arms.
- **S5h's mechanism question is closed**: the hold is VTL1 interception. The excursion hypothesis is
  retired.
- **The Secure Kernel limit narrows to an architectural inference** rather than an open mechanism,
  as step 5 explains — still not measured.
- **What is left for S5 is exactly one thing, the receiver**, and this read does not help with it:
  nothing above touches message delivery. That gate stands as written under S5h.

### S5j result, 2026-09-29: the message is already addressed to the parent, and binding to it may displace Hyper-V's handler

**One finding and one hazard, and the hazard is the one that changes what to build.** The intercept
message S5h's hold produces is routed to the **parent** — the hypervisor picks the recipient by asking which VTL
*installed* the vector, and for a parent-installed intercept that is VTL0 whatever VTL the exception
occurred in. And the root-side API for receiving it already exists, exported, so the hand-rolled
`HvCallCreatePort` / SynIC page this gate was specified around is **not** what it needs. What it
does need is a way in that does not take something already taken: `WinHvSetInterceptRoutine` stores
**one** routine per table entry, and `Vid.sys` imports it.

Same instrument and same image as S5i — [`tools/sk_vmcs_scan.py`](../../tools/sk_vmcs_scan.py)
against `hvix64.exe` `10.0.26100.9444` — plus `winhvr.sys` and `Vid.sys` read with symbols from the
Microsoft symbol server, which is what makes the root side legible where the hypervisor has no PDB.

#### Where the message goes, in the hypervisor

`HvMessageTypeX64ExceptionIntercept` is `0x80010003`, and like `0x4004` before it that is one
constant to look for rather than a structure to recognise. It appears **once** in the whole image,
at `+0x2C9A9E`, inside the builder at `+0x2C98A8` that fills a `0xF0`-byte payload with the
faulting context and hands it to `+0x2C5728`, which forwards to the post at `+0x2EB134`.

**The recipient is chosen at `+0x2C95B8`, and this is the part that matters:**

```text
0x2C9679  mov   dl, byte ptr [rcx + 0x14]        ; start at the ACTIVE VTL
0x2C967C  movzx r10d, byte ptr [rbx + 0x14]      ; the faulting vector
0x2C9681  mov   r8d, dword ptr [r9 + 0x63b8]     ; the enabled-VTL set
          ... next enabled VTL above the current one, else wrap to the lowest ...
0x2C96CC  mov   rax, qword ptr [r9 + rax*8 + 0x63c8]   ; array[candidate VTL]
0x2C96D4  mov   eax, dword ptr [rax + 0x1a04]          ; that VTL's OWN installed mask
0x2C96DD  bt    dword ptr [rcx], r10d                  ; does it contain this vector?
0x2C96E1  jae   0x2c9688                               ; no -> try the next VTL
0x2C96F1  call  0x2c98a8                               ; yes -> deliver, VTL = this one
```

So the scan starts at the VTL that faulted, tries **higher** VTLs first, then wraps to the lowest,
and delivers to the first whose *own* `+0x1A04` holds the vector. On a `{0,1}` guest, a `#BP` taken
in VTL1 whose vector the parent installed finds no higher VTL, wraps to **VTL0**, matches the mask
S5i showed the parent writes — and is delivered as a VTL0 intercept.

That the higher VTL is tried first is the VSM precedence one would want: Secure Kernel sees an
exception it intercepted for itself before VTL0 does.

**And the post forks on exactly that byte** (`+0x2EB134`): zero takes the parent-directed path,
stamping the message header from `partition + 0x4550` and posting through `+0x2EC204`; non-zero
posts to `[VP + VTL*8 + 0x148] + 0x80`, the higher VTL's own SynIC. **So nothing needs to be
redirected.** The message S5h's hold produced was already addressed to the parent.

**What that does *not* establish is what happened at the other end**, and an earlier version of this
section said the hold was explained by a message posted to a port with nobody listening. The static
read shows where the message is *sent*; nothing here observed its receipt — and this same section
records that `Vid.sys` has a handler for this exact message type. So "nothing was bound" and "the
existing handler received the unsolicited intercept and retained it" are **both** live explanations
of S5h's hold, and they are not the same gate: the first wants a binding built, the second wants
Hyper-V's handler understood. Distinguishing them is what comes next, so this record does not pick
one. **S5k, below, killed the first and added a third**: `Vid.sys` is bound, so nothing-was-bound is
out — and the handler *drops* a message whose vector is not claimed in a per-partition table of
Vid's own. Dropped and retained are separated by a runtime byte S5k did not read.

#### What the root side already has

`winhvr.sys` exports **201** functions, and the ones this gate needs are among them:

| for | exports |
|---|---|
| a port | `WinHvCreatePort`, `WinHvConnectPort`, `WinHvDeletePort`, `WinHvAllocatePortId`, `WinHvSetPortProperty` |
| a message stream | `WinHvAllocatePartitionSintIndex`, `WinHvGetSintMessage`, `WinHvSetEndOfMessage`, `WinHvSetSint` |
| intercepts | `WinHvInstallIntercept`, **`WinHvSetInterceptRoutine`**, `WinHvCompleteIntercept`, `WinHvRegisterInterceptResult` |

**So the build this gate was specified around is the wrong build.** The plan said
`HvCallCreatePort`/`HvCallConnectPort` and a SynIC message page hand-rolled into `h3probe.sys`;
none of that is necessary, because the root's own kernel API does it and a driver can import it.
`WinHvCompleteIntercept` matters as much as the receive half — it is the *resume*, which is what
separates a debugger from an observer.

`Vid.sys` is already a full consumer of it, with an intercept thread, a DPC, a preprocess/process
pair, and — named for this exact case — **`VidExceptionInterceptReturnCallback`**. The root does not
merely have the plumbing; it has a handler for this message type today.

#### The hazard, which is why this is a finding and not a green light

`WinHvSetInterceptRoutine` is three instructions of substance:

```text
0x8030  call  0x2b40                         ; look the entry up by the first argument
0x8038  jne   0x8041                         ; not found -> 0xC035000D
0x8044  mov   qword ptr [rax + 0x10], rdi    ; routine
0x8048  mov   qword ptr [rax + 0x18], rbx    ; context
```

and `+0x2B40` is a binary search over a sorted global table. **What is established is per entry:
one routine, one context, assigned rather than chained.** So *if* two callers select the same entry,
the second replaces the first.

**Whether they do is exactly what this read did not establish, and an earlier version of this
section asserted it anyway.** It reasoned that `Vid.sys` imports `WinHvSetInterceptRoutine`,
therefore the entry is held, therefore registering replaces Hyper-V's handler. The import proves
`Vid.sys` *calls* the function; it says nothing about which entry the call selects. Review was
right that the next paragraph then contradicts it — the key is unidentified, so a per-client or
allocated handle that lets another driver own a **separate** entry is not ruled out, and ruling it
out on this evidence would send the next gate looking for a way round a wall that may not be there.

So the honest shape is a **hazard, not a finding**: displacement is what to assume until the key is
known, because the cost of being wrong is asymmetric. If the key is per-partition the blast radius
is one child; if it is per-message-type or per-SINT it is every VM on the host, because the
displaced handler services IO-port, MSR and CPUID intercepts; and if it is an allocated handle there
is no displacement at all. All three are open. **Establishing which is the next thing to do** — from
`Vid.sys`'s own call sites, which pass the key, and from whatever creates the entries.

**Answered by S5k, below: the key is the partition id, so the blast radius is one child** — and the
prohibition hardens rather than lifts, because the routine a registration would displace is the one
that dispatches to Vid's own per-vector table. Do not call it.

#### What this settles and what it leaves

- **The routing question is answered**: a parent-installed intercept's message is delivered to the
  parent even when the exception occurred in VTL1. **So the route is not what is missing** — which
  is narrower than saying a binding is: what is missing is whatever stands between that delivery
  and a debugger seeing it, and this read cannot say whether that is an absent binding or Hyper-V's
  own handler consuming it.
- **The build is re-scoped**: exported kernel API rather than hand-rolled hypercalls and a SynIC
  page, with `WinHvCompleteIntercept` supplying the resume.
- **A hazard the plan did not anticipate**: a registration may displace the entry Hyper-V holds,
  and whether it does — and at what scope — turns on a key this read did not identify. **Do not
  call `WinHvSetInterceptRoutine` on this bench until it is known.**
- **Still not measured**: no message has been received. S5 does not pass, and nothing here changes
  the Secure Kernel scope limit, which stands as S5i left it.
- **Two reads come next, not one**, because the hold has two live explanations and they diverge:
  the **table key**, which says whether a registration collides at all and at what scope; and
  **Vid's own path for `0x80010003`** — preprocess, process, `VidExceptionInterceptReturnCallback`,
  completion — which is the only thing that says *why the intercept stays outstanding*. The key
  cannot answer that, and if Hyper-V's handler is receiving and retaining the message then a second
  receiver is the wrong build whatever the key turns out to be.

  **Both were run as S5k, below.** The first explanation is dead — Vid is bound, per partition, and
  recognises `0x80010003`. The second gains a competitor rather than a refutation: the handler
  *drops* a message whose vector is not claimed in a per-partition table that lives in `Vid.sys` and
  that the install hypercall knows nothing about, and which of those two S5h met turns on a runtime
  byte S5k did not read. A second receiver is the wrong build either way, for a third reason: the
  right one already exists.

### S5k result, 2026-09-29: an unclaimed vector is dropped inside `Vid.sys`, and the receiver is an IOCTL rather than a build

**Both reads S5j called for are done, and between them they move S5h's hold from "unexplained" to
"one branch of a path that is now read end to end".** `Vid.sys` *is* bound, per partition, and it
recognises `0x80010003` — so "nothing was bound" is dead on the static read alone. What the static
read then shows is a **third** possibility S5j did not have: a handler that receives the message and
**discards** it, in four instructions, because the vector is not registered in a second table that
lives in `Vid.sys` and that `HvCallInstallIntercept` knows nothing about. The hypervisor-level
install S5b built and S5h fired is **half** of what the root's own stack does to arm an exception
intercept, and the half it skipped is the half that makes anyone listen.

**Which branch S5h's own message took is a question about live state, and this gate did not read
it** — `[partition+0xB68][3]` is runtime, and a VID client that had already claimed `#BP` on that
child would have made the handler enqueue rather than drop. A section below sets out why S5h's own
controls cannot stand in for that read, and names the one live read that settles it. **So the drop
competes with S5j's retained explanation and does not replace it**, and nothing here should be read
as saying what S5h's message did.

So S5's missing piece is not a receiver to build. It is `Vid!VidHandlerIoctlExceptionRegister`, an
IOCTL that takes a vector, claims a per-partition slot for it, and *then* calls
`WinHvInstallIntercept` with the same type-3 descriptor S5b read — after which the delivery path
S5j traced ends in a message to whoever opened the handle, with an instruction-pointer advance and a
resume already written.

**Measured against** this host's own `C:\Windows\System32\drivers\winhvr.sys` **`10.0.26100.8972`**,
SHA-256 `7D407FC49711176E…ECA1CE`, and `Vid.sys` **`10.0.26100.9278`**, SHA-256
`6611BCD768EFCFF9…B06697` — the same two images and the same build pair as S5b and S5j, so this
read sits on the record those two left rather than beside it. Both were opened as DbgEng image
targets (`open_dump` on the `.sys` itself) with public PDBs from the Microsoft symbol server, which
is what makes every name below a name rather than an offset. Exhaustive reference scans over the
executable sections were done with two throwaway byte scanners rather than a disassembler — see the
limits at the end.

#### Read one: the table key is the partition id, and the slot belongs to whoever created the partition

`WinHvSetInterceptRoutine` (`winhvr+0x8020`) is four instructions once the prologue is off:

```text
0x8030  call  winhvr!WinHvpReferencePartition   ; look up by the FIRST argument
0x8038  jne   0x8041                            ; not found -> 0xC035000D
0x8044  mov   qword ptr [rax+0x10], rdi         ; routine
0x8048  mov   qword ptr [rax+0x18], rbx         ; context
```

and `WinHvpReferencePartition` (`+0x2B40`) takes `WinHvpPartitionArrayLock` shared, binary-searches
`WinHvpPartitionArray` — a count at `+0`, then 16-byte entries of `{ qword key, qword object }` — and
refcounts the object it finds. **The key is an `HV_PARTITION_ID`**, which the failure path states
outright: `0xC035000D` is `STATUS_HV_INVALID_PARTITION_ID`, *"a partition with the specified
partition Id does not exist"*. It is not a message type, not a SINT, and not an allocated per-client
handle.

`WinHvpOnInterception` (`+0x4438`) is the other end of the same array, and it settles that the two
agree:

```text
0x444C  mov   r11, qword ptr [rcx+8]            ; HV_MESSAGE_HEADER.Sender = sending partition
          ... the same binary search over WinHvpPartitionArray ...
0x4488  mov   rcx, qword ptr [r8+rcx*8+0x10]    ; the partition object
0x4492  mov   rax, qword ptr [rcx+0x10]         ; its routine
0x4499  mov   rcx, qword ptr [rcx+0x18]         ; its context
0x449D  call  winhvr!guard_dispatch_icall       ; routine(context, message)
```

**So the blast radius of a registration is exactly one partition, and displacement is real.** The
three outcomes S5j could not choose between resolve to the first: per-partition means one child, and
a second caller registering for a child Vid created replaces `VidInterceptIsrCallback` for that
child — taking its IO-port, MSR, CPUID, halt and memory intercepts with it, since one routine serves
all of them.

Vid's own two call sites confirm the shape from the other side, and they are the **only** two in the
image — an exhaustive scan for `call qword ptr [rip+disp32]` resolving to
`Vid!_imp_WinHvSetInterceptRoutine` (`+0x57CA0`) finds `+0x7CB21` and `+0xC2166` and nothing else:

| site | in | passes |
|---|---|---|
| `+0xC2166` | `VsmmPhuStoreHvPartitionRestore` | `rcx = [partition+0x288]`, routine `VidInterceptIsrCallback`, context = the Vid partition object |
| `+0x7CB21` | `VsmmPhuStoreHvPartitionTeardown` | the same id, routine `VsmmPhuStorepHvPartitionInactiveInterceptRoutine` |

An activate/deactivate pair on one field — **Vid itself relies on assignment replacing**, which is
the cleanest available proof that the slot is not chained. And `[Vid partition object + 0x288]` is
the partition id, since it is what Vid passes as the first argument to `WinHvSetVpRegisters`,
`WinHvInstallIntercept`, `WinHvCompleteIntercept` and `WinHvCancelVpDispatchLoop` as well.

The slot is also not first-come-first-served: `WinHvpCreatePartitionObject` (`+0x1D42C`) allocates
the `0x100`-byte object and writes the routine and context into that same `+0x10`/`+0x18` pair **at
creation**, from its third and fourth arguments, and its only caller is `WinHvCreatePartitionEx`.
Vid supplies them there too — `VsmmPhuStorepHvPartitionDeserialize` passes
`VsmmPhuStorepHvPartitionInactiveInterceptRoutine` straight into `WinHvCreatePartition`, and
`VidPartitionIoctlSetup` picks between `VidInterceptIsrCallback` and
`VidExoVpInterceptIsrCallback` and does the same. **To hold the slot without displacing anyone you
would have to be the partition's creator**, and for a Hyper-V guest that is Vid.

#### Read two: Vid receives `0x80010003`, recognises it, and drops it

`VidInterceptIsrCallback` (`+0x4170`) — the routine registered above — has **no filter that could
lose an exception intercept**. It special-cases three notification types (`0x80000071`,
`0x80000072`, `0x80000073`) and sends *everything else* into the VP path:

```text
0x4191  mov   eax, dword ptr [rdx+0x10]         ; the intercept header's VpIndex
0x4194  imul  rbx, rax, 0x980                   ; -> the VP object
0x419B  add   rbx, qword ptr [rcx+0xAB0]
0x41A5  call  Vid!VidInterceptPreprocess
```

`VidInterceptPreprocess` (`+0x4270`) marks the VP intercept-pending (`lock bts [vp+0x130], 0`),
`memcpy`s the whole message — header plus `[msg+4]` payload bytes — to `vp+0x30`, and switches on the
type to choose a handler for `[vp+0x158]` and an internal reason code for `[vp+0x200]`. For the
range `0x80010002 … 0x80010013` that switch is a jump table at RVA `0x3D137`, and **index 1 —
`0x80010003` — is a real entry**:

```text
0x4450  lea   rax, [Vid!VidHandleExceptionIntercept]
0x4457  mov   esi, 2
0x445C  jmp   back to the common tail
```

Its neighbours are `VidHandleCpuidIntercept`, `VidHandleApicEoiIntercept`,
`VidHandleRegisterIntercept`, `VidHandleHaltIntercept`, `VidHandleInterruptionDeliverableIntercept`,
`VidHandleSevCtrlRegIntercept`, `VidHandleSnpGuestRequestIntercept` and
`VidHandleTripleFaultIntercept`. An exhaustive scan for the address `Vid+0x11690` being taken finds
**one** site, this stub, so the preprocess switch is the only thing that selects the exception
handler.

**And `VidHandleExceptionIntercept` (`+0x11690`) gates on a table `HvCallInstallIntercept` has never
heard of:**

```text
0x116A4  movzx ebp, byte ptr [rcx+0x68]           ; the faulting vector, out of the copied message
0x116C2  mov   rax, qword ptr [r8+0xB68]          ; the partition's per-vector table
0x116C9  movzx ecx, byte ptr [rbp+rax]            ; its entry for this vector
0x116CE  cmp   cl, 0xFF
0x116D1  je    0x116EE                            ; 0xFF -> no registration -> return 0
0x116D3  imul  rcx, rcx, 0xB0                     ; else the handler entry that claimed it
0x116DA  add   rcx, qword ptr [r8+0xB58]
```

`VidPartitionInitialize` (`+0x9428`) allocates both: `[partition+0xB58]` is 255 handler entries of
`0xB0` bytes, and `[partition+0xB68]` is **`0x100` bytes filled with `0xFF`** — one byte per
exception vector, holding the index of the entry that owns it, `0xFF` meaning none. An exhaustive
scan for `0xB68` as a displacement finds eight sites and no others: that initialisation, the
teardown free, this read, and the register/unregister pair below.

With `0xFF` the function returns **0** having enqueued nothing, signalled nobody and woken no
thread. With a registration it builds a VID message carrying the vector, the error code, the
exception parameter and the software-exception flag, and enqueues it with
`VidExceptionInterceptReturnCallback` — whose address, again, is taken at exactly one site, inside
this enqueue. So **the return callback cannot run for an unregistered vector**, which is what makes
the drop silent: `VidInterceptAdvanceInstructionPointer` and `VidCompleteInterceptReturnCallback`
both sit behind it.

#### What arms it, and why our install could not

`VidHandlerpExceptionRegisterEntry` (`+0x63B80`) is the writer, and its order of operations is the
finding:

```text
0x63B9E  movzx ecx, byte ptr [rdx+0x74]           ; the vector, from the handler entry
0x63BAE  mov   r8, qword ptr [rbx+0xB68]
0x63BB5  cmp   byte ptr [r8+rcx], 0xFF
0x63BBA  je    0x63BC3
0x63BBC  mov   edx, 0xC0370001                    ; STATUS_VID_DUPLICATE_HANDLER
...
0x63BDB  mov   byte ptr [r8+rcx], dl              ; claim the slot for this entry
0x63BDF  lea   r8, [rsp+0x20]                     ; the descriptor
0x63BE4  mov   word ptr [rsp+0x28], cx            ;   .Vector
0x63BE9  mov   edx, 4                             ; AccessType = execute
0x63BEE  mov   rcx, qword ptr [rbx+0x288]         ; the child's partition id
0x63BF5  mov   dword ptr [rsp+0x20], 3            ;   .Type = 3 (exception)
0x63BFD  call  qword ptr [Vid!_imp_WinHvInstallIntercept]
0x63C20  ... on failure, restore 0xFF
```

**That descriptor is byte-for-byte the one S5b read and S5h installed** — type 3, `AccessType` 4,
the vector in the same field — which is the strongest possible statement that our install was not
wrong, merely incomplete. Vid does the identical hypercall; it just claims the slot first, and the
slot is what the delivery path consults.

Its single caller is `VidHandlerIoctlExceptionRegister` (`+0x63630`), which allocates a handler
entry (`VidHandlerpEntryAllocate`), stores the vector at `+0x74` and a caller-supplied context at
`+0x80`, calls the above, and returns a handle to the client. `VidHandlerpExceptionUnregisterEntry`
(`+0x63C4C`) restores `0xFF`; its single caller is `VidHandlerpUnregisterSingle`, the generic
handler-entry teardown.

So the root-side chain, end to end, is:

```text
IOCTL -> VidHandlerIoctlExceptionRegister -> VidHandlerpExceptionRegisterEntry
             -> claim [partition+0xB68][vector], then WinHvInstallIntercept(id, 4, {3, vector})
  ... the guest faults ...
hvix64 -> WinHvpOnInterception -> VidInterceptIsrCallback -> VidInterceptPreprocess
             -> VidHandleExceptionIntercept -> [partition+0xB68][vector] != 0xFF
             -> VidMessageBufferEnqueue(..., VidExceptionInterceptReturnCallback)
  ... the client answers ...
VidExceptionInterceptReturnCallback -> VidInterceptAdvanceInstructionPointer (software exceptions)
             -> VidCompleteInterceptReturnCallback
```

and S5h entered it at the third line with the first line never having run — **for its own install**.
Whether some *other* client had run the first line for `#BP` on that child, before S5h started, is
the next section.

#### Was the slot claimed? Not read, and the probe's own removals make S5h's controls silent on it

The whole application of this read to S5h turns on one runtime byte,
`[partition+0xB68][3]`, and **this gate did not read it.** A VID client holding `#BP` on that child
would have sent the handler down the enqueue branch instead, which is S5j's received-and-retained
explanation still standing.

**An earlier version of this section argued from S5h's controls that the slot was `0xFF`, and the
argument does not stand.** It ran: Vid's two register paths bracket the slot in both directions —
`VidHandlerpExceptionRegisterEntry` claims it and *then* installs, restoring `0xFF` if the hypercall
fails, and `VidHandlerpExceptionUnregisterEntry` (`+0x63C4C`) restores `0xFF` and calls
`WinHvInstallIntercept` with `AccessType` **`0`** and the same type-3 descriptor — so a claimed slot
implies an installed intercept; and S5h's null arms and its `#BR`-installed/`#BP`-raised control
each handled 20,000/20,000, so no `#BP` intercept stood; so the slot was `0xFF`.

**Both halves are true and the implication between them is not *established*, because Vid is not the
only writer of the hypervisor mask on these children — the probe is.** `h3probe.sys` calls
`WinHvInstallIntercept` directly, and **every install it makes is paired with a raw
`AccessType = 0` removal in a `finally`**, S5b onward, which touches nothing in `Vid.sys`. When this
section was written, whether that removal clears the shared bit outright was **not read** — S5i had
read the install as an unconditional `OR` of `1 << vector` and not the removal — and the argument
was retracted on that alone: the implication it needs, *"a claimed slot implies an installed
intercept"*, needs no other writer to be able to clear the bit, and one other writer existed whose
effect was unknown. **S5l then read it, and it clears the bit** — so the implication is not merely
unestablished but false on a probed child. `slot claimed` and `intercept installed` do
desynchronise there: a client's claim survives a probe removal that cleared its bit, the controls
pass in exactly that state, S5h's next raw install re-sets the bit, and the message enqueues to
that client.

**What settles the question itself is reading `[partition+0xB68][3]` inside a replicated intercept
arm**, not a bare read now. The slot is mutable runtime state and a client can claim or release it
at any time, so a read taken today reports today: it can say which branch *a reproduction* takes,
and it can only say what S5h's runs met to the extent the bench has not changed under it — which is
an assumption to state, not a result. Read it with the intercept standing and the raiser held, in
the same triple shape S5h used. Nothing should be built on the drop until that is done.

**And the same desynchronisation is a hazard rather than only a hole in an argument.** A VID client
holding a vector this probe installs *would* have its intercept stripped by the probe's teardown
while Vid went on believing it armed — silently, on the child under test, with no error anywhere.
**S5l confirms the mechanism**: install and remove are the same function acting on the same bit,
with no refcount and nowhere for one to live, so two parties holding one vector are one bit and the
**first** removal clears it for both. What is not established is whether any client ever held one:
six runs executed that teardown and none read the slot, so this is an exposure rather than a
recorded loss.

#### What the hold then is, stated as the inference it is

**What is read, not inferred:** with no registration the handler returns 0, no message is enqueued,
and the VP's intercept-pending bit is cleared by the common tail in `VidInterceptProcess`, which
also flushes a queued `WinHvSetVpRegisters` writing register name `1` — which the TLFS names
`HvRegisterInterceptSuspend`; the name is from the specification, the number is what was read — to
zero. Nothing on that path injects the exception into the guest and nothing advances `RIP`,
because both of those live behind the return callback that did not run.

**What follows, and is an inference this gate did not measure:** the faulting instruction is
re-entered and faults again, so a standing intercept on an unregistered vector is a *loop* rather
than a queue. It predicts S5h exactly — no progress past the trap while the intercept stands, and
all 20,000 traps intact the moment it is removed, because the very next execution takes the ordinary
path into the guest's dispatcher. It is also consistent with, but not proved by, S5h's runtime
figures: a fraction of one VP, never saturated, is what a loop whose period is a root-side round
trip looks like from `HvRegisterVpRuntime`, which counts only guest time. **Distinguishing a loop
from a single held trap needs a live arm** — a retired-instruction or intercept counter across the
window — and none was run here. The record should not carry "livelock" as established.

#### A hazard this read found that nothing had anticipated

`VidInterceptPreprocess` ends its switch at `+0x44E7` with a WPP trace and then `int 29h` with
`ecx = 5` — `__fastfail(FAST_FAIL_INVALID_ARG)`, in the **root** partition, which is a host bugcheck
rather than a guest one.

It is reached by any intercept message type the switch does not cover, and **the coverage is sparse
inside the ranges as well as outside them.** Two range checks bound it — `0x80000000`–`0x80000060`
and `0x80010000`–`0x80010013` — and within the first a byte index table at RVA `0x3D0D8` maps all
but **ten** of its ninety-five values to that same stub, while within the second the jump table's
holes do:
`0x80010005`, `0x80010009` through `0x8001000F`, and `0x80010012`.

So *"install an intercept type and see what happens"* is not a cheap experiment on a bench that
matters: an intercept whose message type Vid does not handle takes the machine down, not the VM.
Exception (`0x80010003`), CPUID, MSR and IO-port are safe by this table; the rest must be checked
against it first. It belongs beside this plan's two existing prohibitions — no `int 3` in Secure
Kernel (S5a), and no `WinHvSetInterceptRoutine` on this bench — and `FOLLOWUPS.md` carries all
three.

#### What this changes

- **The `WinHvSetInterceptRoutine` prohibition becomes permanent and gets a better reason.** It is
  not "do not call it until the key is known" — the key is known, and calling it would displace
  `VidInterceptIsrCallback` for one child partition, which is the very routine that would dispatch
  to a registration. It is the wrong call, not a risky one. Do not call it.
- **The build is re-scoped a second time, downward.** S5j retired the hand-rolled
  `HvCallCreatePort`/SynIC page in favour of `winhvr.sys`'s exported API. This retires the exported
  API too: the receiving side already exists, per partition and per vector, with completion and
  instruction-pointer advance written. What S5 needs is the IOCTL that reaches
  `VidHandlerIoctlExceptionRegister`.
- **"Nothing was bound" is dead, and a third candidate joins the other one.** `Vid.sys` is bound
  per partition and recognises the type, which the static read settles outright. What replaces it is
  "the handler received it and dropped it, the vector never having been claimed" — **which competes
  with S5j's retained explanation rather than retiring it**, because the two are separated by a
  runtime byte this gate did not read and nothing already measured can stand in for.
- **S5b's install is vindicated and re-scoped.** The descriptor Vid sends is identical. The gap was
  never the hypercall.
- **Still not measured**: no message has been received. **S5 does not pass.** Nothing here touches
  the Secure Kernel scope limit, which stands as S5i left it, and nothing here was run live — this
  is two static reads.

#### What this gate leaves open

**Questions, not a schedule** — the ordered plan lives in `FOLLOWUPS.md` item 103 and is maintained
in one place, because keeping a "run this next" list in every gate section is what produced a run of
review findings against lists a later gate had already invalidated.

- **The IOCTL code and the user-mode surface for `VidHandlerIoctlExceptionRegister`** — its
  dispatch entry in Vid's IOCTL table, the input layout, and whether a documented API reaches it.
  That is what decides whether S5's receiver is a supported call, a private one, or a driver.
  **Answered by S5m**: `0x221148`, wrapped by the exported `vid!VidRegisterExceptionHandler`, with
  attach, receive, complete and unregister exported beside it — not reached by WHP, so exported
  rather than documented, and not a driver.
- **`[partition+0xB68][3]` during an intercept arm**, which is the only thing that separates the
  drop from S5j's retained explanation. The slot is mutable, so any reading is about the arm that
  takes it rather than about S5h. **S5m answers half of this and leaves half open**: a registration
  reports whether the slot is claimed *at that call*, but it also *claims* it, so it cannot observe
  what an unregistered vector meets. That still wants a contemporaneous, non-mutating read.
- **Whether the hold is a loop**, per the inference above, since a loop and a held trap want
  different things from a debugger design.
- **Answered while this gate was in review**: `hvix64.exe`'s type-3 *removal* path, read as S5l —
  it clears the bit, so the hazard is real and the retracted argument cannot be rebuilt.
- **Ruled out, not open**: a second receiver, a port of our own, and `WinHvSetInterceptRoutine`.

#### Limits of this read, stated rather than left to be found

- **Two images, one build pair, no live arm.** Everything above is static, from `winhvr.sys`
  `10.0.26100.8972` and `Vid.sys` `10.0.26100.9278`. No registration was made and no message was
  received.
- **The one runtime byte the application to S5h turns on was not read**, and **nothing already
  measured stands in for it.** `[partition+0xB68][3]` is mutable live state; the attempt to
  substitute S5h's controls is retracted in its own section above, because the probe writes the
  hypervisor mask those controls observe and — S5l — desynchronises it from the slot.
  And because it is *mutable*, no later read recovers what it held during S5h — only a replicated
  arm reports the branch a reproduction takes. Every statement about *code paths* here is
  independent of that byte; every statement about *what S5h's message did* is not, and none is
  made.
- **The reference scans match an encoded displacement, so a computed one is invisible.** The
  "exactly one site" and "exactly two call sites" claims above are exhaustive over
  `call/jmp qword ptr [rip+disp32]`, `call/jmp rel32` and `lea reg, [rip+disp32]` in the executable
  sections, which is the same class of limit `sk_vmcs_scan.py` records for immediates: a target
  reached through a pointer in data, or a base held in a register, would not be found. Each claim is
  therefore "no other *direct* reference", and the ones that matter — the `0xB68` table's writers,
  and who selects `VidHandleExceptionIntercept` — were also read as disassembly in full.
- **`VidDeviceExtension+0x288` bit `0x40` forks several of these paths** and was not identified. It
  chooses between the DPC-and-message-slot shape and a dispatch-loop shape (`WinHvDispatchVp`,
  `WinHvCancelVpDispatchLoop`), which is almost certainly the root scheduler. The finding does not
  turn on it — the `0xFF` gate is ahead of the fork — but the resume detail in the inference section
  is read off the bit-clear path only.
- **The internal reason code is not the public one.** `[vp+0x200]` takes `2` for an exception, `1`
  for CPUID, `5` for IO port, `6` for MSR, `7` for unmapped GPA, `0x10` for halt, `0x15` for triple
  fault. Those are not `WHV_RUN_VP_EXIT_REASON` values and are not named here as anything else.
- **Intel and this hypervisor only**, as with S5i and S5j; `hvax64.exe` is not read.

### S5l result, 2026-09-29: the mask is one bit with no owner, so the probe's removal is a real hazard

**The removal clears the bit outright. There is no refcount, and there is nowhere for one to
live.** S5k left this unread and two things turned on it: whether the probe's paired
`AccessType = 0` teardown can strip an intercept another party installed, and whether the controls
argument S5k retracted could be rebuilt. Both are now answered, and in the same direction — **the
hazard is real and the argument cannot be rebuilt.**

What this does **not** do is say which branch S5h's message took. That still wants the replicated
arm S5k named; this read removes the alternative reading of the retraction, not the need for the
measurement.

**Measured against** the same `C:\Windows\System32\hvix64.exe` **`10.0.26100.9444`**, SHA-256
`CF5AF317…40CE8A`, with the same instrument — [`tools/sk_vmcs_scan.py`](../../tools/sk_vmcs_scan.py),
`--self-test` 20/20, and the ledger figures re-derived once more: `+0x1A04` at **9 sites with 2
writers**, `+0x6124` at **6 with 3**, both unchanged since S5i.

#### Install and remove are the same function, and the same bit

S5i named `+0x2C9430` as where `InterceptType == 3` lands and read the install. It is the removal
too — the direction is a single compare on `AccessType`:

```text
0x2C94A5  mov   rax, qword ptr [r10 + r11*8 + 0x63c8]   ; array[VTL]
0x2C94AD  mov   edx, dword ptr [rax + 0x1a04]           ; the current mask
0x2C94B3  cmp   r8d, 4                                  ; AccessType
0x2C94B7  jne   0x2c94be
0x2C94B9  or    edx, r9d                                ; 4  -> set 1 << vector
0x2C94BC  jmp   0x2c94c4
0x2C94BE  not   r9d                                     ; 0  -> clear it
0x2C94C1  and   edx, r9d
0x2C94C4  mov   rcx, qword ptr [r10 + r11*8 + 0x63c8]
0x2C94CC  mov   dword ptr [rcx + 0x1a04], edx           ; store back
0x2C94D2  mov   rcx, r10
0x2C94D5  call  0x2becc8                                ; recompute every VTL (S5i step 4)
0x2C94E8  call  0x2bed3c                                ; notify the VPs
```

**`or` to install, `and ~bit` to remove, one dword per VTL.** The whole update runs under a
per-partition lock — `lock bts qword ptr [r10 + 0x63f0], 0` on the way in, `lock and … , 0` on the
way out, `0x78` returned to a caller that finds it held — so it is serialised and still
last-writer-wins, which is a different thing.

**And there is no second structure carrying a count.** An exhaustive displacement scan puts
`+0x1A04` at nine sites with exactly **two writers** in the whole image: this store, and a zeroing
at `+0x2C0F84` in the partition-teardown path that clears `+0x1A04`, `+0x1A08` and `+0x1A0C`
together. Six of the seven readers are the recompute, the routing scan S5j read, and two siblings.
Nothing increments, nothing decrements, and a 32-bit bitmask has no room to.

#### What that settles

- **The *mechanism* of the hazard is confirmed and stops being conditional.** Two parties
  installing the same vector on one partition are not two installs — they are **the same bit**, and
  because removal is a plain `and ~bit`, **the first removal clears it for both**, whichever party
  makes it. There is no "my install" to take back. So a VID client that had claimed `#BP` through
  `VidHandlerpExceptionRegisterEntry` would lose its intercept to this probe's `finally` while
  `[partition+0xB68][3]` still said it was armed, with no error raised anywhere.
  **Whether that ever happened is still unknown**: six S5h runs executed that teardown, and no arm
  has read the slot, so what is established is the exposure rather than an occurrence.
- **It propagates.** The store is followed by the `+0x2BECC8` recompute S5i read, which rebuilds
  every enabled VTL's effective mask from the per-VTL `+0x1A04` values seeded with VTL 0's. So
  clearing the parent's bit clears it from every VTL's effective mask — *except* for a VTL that
  installed the vector into its own slot, which is Secure Kernel's `SELF` path and not a VID
  client's.
- **The retracted controls argument cannot be rebuilt.** S5k retracted it on the ground that the
  implication *"a claimed slot implies an installed intercept"* was unestablished, which held
  whichever way this read went. It goes the way that makes the desynchronisation real, so the
  implication is not merely unestablished but false on a probed child.
- **It does not say what S5h met.** Nothing here reads `[partition+0xB68]`. The replicated arm
  stands exactly as S5k left it.

#### Three more bounds, read from the same 215 bytes

They cost nothing extra and they bound what any future arm may ask for:

- **`AccessType` must be exactly `0` or `4`.** `test r8d, 0xfffffffb; jne` rejects everything else
  with status `5`, which is where S5b's `INVALID_PARAMETER` negative control was landing.
- **The vector is a `word` at `+8` of the `InterceptParameter`, and must be `<= 0x1F`.**
  `movzx ecx, word ptr [r9 + 8]; cmp cx, 0x1f; ja` — consistent with a 32-bit mask, and it explains
  why S5b found the neighbouring bytes inert.
- **There is a per-partition allowed-vector mask at `+0x6124`, with an exemption for `#BP` and
  `#OF` at VTL 0.** `test dword ptr [r10 + 0x6124], r9d` admits the vector directly; failing that,
  `lea eax, [r11 - 1]; cmp al, 1; jbe` refuses target VTLs 1 and 2, and `test r9b, 0x18; je`
  refuses every vector but **3** (`#BP`) and **4** (`#OF`). Since S5i established that a parent
  naming a child always installs at VTL 0, **`#BP` on a child is installable unconditionally** —
  which is why S5b's and S5h's installs never depended on the partition's configuration. It also
  predicts that S5h's `#BR` (`0x05`) control succeeded only because `+0x6124` carried bit 5 on
  those children; that is a prediction this read does not check, and `+0x6124`'s three writers
  (all in `0x32FEF0-0x3305D9`) are not read here.

#### What to do about the hazard

**The obvious remediation is to read the mask before installing, and it is not available.**
`array[0].0x1A04` lives in the hypervisor's own memory, which the root cannot read by any of this
plan's mechanisms — that is H2's whole question, one level further out. Nor is there a hypercall
that reports installed intercepts: the ABI has an install and a remove and no query, which is the
same asymmetry that leaves a caller unable to tell a fresh install from a redundant one.

**What is readable, in principle, is Vid's `[partition+0xB68][vector]`** — kernel memory in the
root, and the thing that actually matters, since it says whether a *VID client* holds the vector.
**On this bench it needs a capability nothing here has yet**: local kernel debugging is not enabled
(`bcdedit /dbgsettings` reports `debugtype Local`, which is the *global setting store* and not the
boot entry — `{current}` carries no `debug Yes`, and `attach_kernel_local` answers `0x80004001`
accordingly), so reading it means either a host reboot into debug mode or a kernel-read path added
to `h3probe.sys`. Both are bench work this repo does not ship.

**And a pre-read would not make the pair safe even if it were available**, which is worth stating
because it is the remedy that suggests itself and an earlier draft of this section proposed it.
The per-partition lock at `+0x63F0` serialises one update; it does not span read-then-install-then-
remove. A client registering between the read and the teardown still loses its bit, and a
comparison *after* removal cannot say who owned what was cleared. Making the pair safe needs
exclusive coordination with every other installer, or an ownership mechanism the bitmask does not
have — not a check.

So the honest statement is a constraint with no remedy attached: **treat *"an install/remove pair is
free"* as false.** It is free only if nobody else holds the vector; nothing in the ABI says whether
anybody does; on this bench nothing yet can look; and looking would not be enough.

**S5m then found a better call, and it is a remedy against one class of collision only.**
`vid!VidRegisterExceptionHandler` arms the same intercept through Vid, which refuses a claimed slot
with `STATUS_VID_DUPLICATE_HANDLER` before touching the hypervisor, and `VidUnregisterHandler`
clears the slot and the bit together. **That check reads `[partition+0xB68]`, so it sees only
parties that registered through Vid.** Against a raw `WinHvInstallIntercept` owner — which leaves
the slot `0xFF` — the registration succeeds beside them and the unregister still clears their
shared bit, exactly as this section describes. So the raw pair should be retired in favour of the
registration, and that is an improvement rather than a fix: the general collision hazard survives,
because the bitmask has no owner to consult. S5m states the qualification in full.

#### Limits

- **One build, Intel only, static.** `10.0.26100.9444`, the same image as S5i and S5j; `hvax64.exe`
  is not read and nothing here transfers to it.
- **The scan finds encoded displacements**, so a `+0x1A04` reached through a computed base is
  invisible to the "two writers" claim — the same bound S5i and S5k record. The two writers found
  were read as disassembly in full, as was the whole of `0x2C9430-0x2C9507`.
- **`+0x6124`'s writers are not read**, so what puts a vector in a child's allowed mask is open.
  The `#BP` exemption above does not depend on it.
- **Nothing was run live**, and no bench state was touched.

### S5m result, 2026-09-29: the receiver is a user-mode export, and there is no driver left to write

**`vid.dll` exports the whole thing.** The IOCTL S5k found is `0x221148`, and it has a thin
user-mode wrapper — `vid!VidRegisterExceptionHandler` — beside the attach, receive, complete and
unregister calls that go with it. So S5's receiver needs **no driver of our own, no port, and no
hypercall**: it is a sequence of exported calls from an ordinary user-mode process holding a
partition handle.

**That last clause carries the whole conclusion, and this gate does not test it.** Every call in
the sequence operates on a partition handle; finding the wrappers says they exist, not that a
second process can obtain one for a VM Hyper-V is running. Until an arm gets a handle, *"no driver
left to write"* is **conditional on that**, and if it cannot be obtained the sequence is
unavailable and a driver or another privileged route may be back on the table. Opening a partition
is the first item in `FOLLOWUPS.md` item 103's ordered plan, and is the test.

That is the third downward re-scope in a row, and it is worth seeing them together, because each
one deleted the build the previous gate had specified:

| gate | what it said to build | why the next one deleted it |
|---|---|---|
| plan → S5j | `HvCallCreatePort` + a hand-rolled SynIC page in `h3probe.sys` | `winhvr.sys` exports the whole kernel API |
| S5j → S5k | a `winhvr.sys` client in `h3probe.sys` | the receiving path exists in `Vid.sys`; it wants a *vector registration*, which is an IOCTL |
| S5k → S5m | an IOCTL client in `h3probe.sys` | the IOCTL has a user-mode export, and so does everything around it |

**Measured against** `C:\Windows\System32\drivers\Vid.sys` **`10.0.26100.9278`** (the same image as
S5k), `C:\Windows\System32\vid.dll` **`10.0.26100.8457`**, SHA-256 `9B538C07FA65C09D…`, and
`C:\Windows\System32\WinHvPlatform.dll` **`10.0.26100.9278`**, SHA-256 `07FEC05320E576C3…`. All
three read as DbgEng image targets with public PDBs, plus byte-level PE scans for the import,
export and reference tables. Nothing was called and nothing was run.

#### The IOCTL, read from the dispatcher rather than guessed

`VidIoControlPartition` (`+0x32980`) is a compare chain on the control code, and the exception case
has exactly one entry — an exhaustive scan for branches into `+0x33706` finds one:

```text
0x33602  mov  eax, r9d                ; the IoControlCode
0x33605  sub  eax, 0x221144
0x3360A  je   0x3373C                 ; 0x221144 -> VidHandlerIoctlCpuidRegister
0x33610  mov  edi, 4
0x33615  sub  eax, edi
0x33617  je   0x33706                 ; 0x221148 -> VidHandlerIoctlExceptionRegister
```

**`0x221148`** decodes as `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x452, METHOD_BUFFERED, FILE_ANY_ACCESS)` —
device type `0x22`, function `0x452`, method `0`, access `0`. **`FILE_ANY_ACCESS` is not the access
control here**: the code is dispatched by `VidIoControlPartition`, which is reached with a
*partition* in `rcx`, so what gates it is possession of a partition handle rather than a permission
on the device.

The case block states the buffer contract before it calls:

```text
0x33706  cmp   dword ptr [rbp+0x40], 0x10     ; input length  >= 0x10
0x33714  cmp   dword ptr [rbp+0x50], 8        ; output length >= 8
0x3371E  mov   r9,  qword ptr [r11 + 8]       ; Context
0x33726  mov   r8d, dword ptr [r11 + 4]       ; Parameter
0x3372A  mov   dl,  byte  ptr [r11]           ; Vector
0x3372D  mov   qword ptr [rsp+0x20], rax      ; &out handle
0x33732  call  Vid!VidHandlerIoctlExceptionRegister
```

so the input is `{ u8 Vector; u8 pad[3]; u32 Parameter; u64 Context; }` and the output is the
`8`-byte handle S5k read being taken from `[entry+0x60]`.

#### The user-mode side, which is the finding

`vid.dll` carries `0x221148` as an immediate at exactly one place, `+0x16C50`, inside
**`vid!VidRegisterExceptionHandler`** — one of the library's **215 exports**. It is a wrapper and
nothing more: an event, one `NtDeviceIoControlFile`, a `STATUS_PENDING` wait, and
`RtlNtStatusToDosError`/`SetLastError` on failure.

```text
0x16C25  mov   dword ptr [rsp+0x48], 8        ; OutputLength
0x16C39  mov   dword ptr [rsp+0x38], 0x10     ; InputLength
0x16C50  mov   dword ptr [rsp+0x28], 0x221148 ; IoControlCode
0x16C60  call  qword ptr [vid!_imp_NtDeviceIoControlFile]
```

Its arguments map straight onto the buffer above: `rcx` the partition handle, `dl` the vector,
`r8d` the parameter, `r9` the context, and the fifth argument the `8`-byte output. **And the rest
of the sequence is exported beside it:**

| for | exports |
|---|---|
| a partition handle | `VidAttachPartition`, `VidGetPartitionIds`, `VidGetHvPartitionId`, `VidDetachPartition` |
| arming a vector | **`VidRegisterExceptionHandler`**, and siblings for CPUID, MSR, IO port, APIC EOI and triple fault |
| receiving | `VidMessageSlotMap`, `VidSetupMessageQueue`, `VidMessageSlotHandleAndGetNext`, `VidHandleMessageAndGetNextMessage` |
| releasing | `VidUnregisterHandler` |

`VidGetPartitionIds` and `VidGetHvPartitionId` matter more than they look: they are the translation
between a VID partition handle and the `HV_PARTITION_ID` every gate from S5b onward has been
passing to hypercalls, so the two halves of this record address the same child by construction
rather than by the operator lining up numbers.

#### The public API does not reach it, and that is worth stating plainly

`WinHvPlatform.dll` — the documented WHP surface — **delay-imports 31 functions from `vid.dll`, and
`VidRegisterExceptionHandler` is not one of them.** What it imports is the *Exo* family:
`VidCreateExoPartition`, `VidReopenExoPartition`, `VidGetExoPartitionProperty`,
`VidSetPartitionProperty`, `VidDeletePartition`, `VidResetPartition`. So WHP's exception exits are
a mechanism for WHP's **own** partitions, and the path to a Hyper-V VM's exception intercept is
`vid.dll`'s export rather than anything public.

**So the answer to "is S5 one supported call from passing" is no, and the reason is narrower than
"no API exists".** The API exists, it is exported, and it is stable enough that Microsoft's own
`vmwp.exe` is built on it — it is simply not part of a documented contract, so anything built on it
is built on an observed interface. That is a materially different position from the hand-rolled
driver this plan carried three gates ago, and it should be recorded as such rather than as a pass.

#### What this does to S5l's hazard: it covers the VID-table owners, and only those

S5l established that an install/remove pair on the raw hypercall is destructive to whoever else
holds the vector, and that the pre-check it wanted — Vid's `[partition+0xB68][vector]` — needs root
kernel memory this bench cannot read. **Going through `VidRegisterExceptionHandler` makes that
pre-check unnecessary for one class of owner**, because the kernel side does it:
`VidHandlerpExceptionRegisterEntry` refuses a claimed slot with `0xC0370001`
`STATUS_VID_DUPLICATE_HANDLER` **before** touching the hypervisor, and `VidUnregisterHandler`
clears the slot and the hypervisor bit together.

**It does not remove the hazard in general, and an earlier draft of this section said it did.**
The duplicate check consults `[partition+0xB68]`, so it sees only parties that registered *through
Vid*. Anyone who installed the same vector with a raw `WinHvInstallIntercept` — which is exactly
what this plan's own probe has done since S5b, and the class S5l is about — leaves the slot at
`0xFF`. A Vid registration then succeeds beside it, and `VidUnregisterHandler` later clears the
shared, unrefcounted hypervisor bit out from under them. **So the supported path is safe against
supported clients and no safer than the raw one against raw installers**, and there is no check
that closes the second case: the bitmask has no owner field to consult. What follows is a rule for
this bench rather than a guarantee — **one installer per vector per partition at a time, and that
installer should be the Vid registration** — not "the collision hazard is solved".

So the registration's own return value is the measurement S5k has been waiting for — **provided it
is read precisely**, which takes one more fact than the paragraph above. `VidRegisterExceptionHandler`
returns a `BOOL` and puts the failure through `RtlNtStatusToDosError`/`SetLastError`, so the caller
sees a Win32 error rather than the `NTSTATUS`, and by default a duplicate would be
indistinguishable from an invalid handle or an allocation failure. **Measured here:**

| `NTSTATUS` | what `RtlNtStatusToDosError` returns |
|---|---|
| `0xC0370001` `STATUS_VID_DUPLICATE_HANDLER` | **`0xC0370001`, unchanged** |
| `0xC0370005` (the VID status a malformed partition name gives) | `0xC0370005`, unchanged |
| `0xC0000008` `STATUS_INVALID_HANDLE` | `6` |
| `0xC0000022` `STATUS_ACCESS_DENIED` | `5` |
| `0xC000009A` `STATUS_INSUFFICIENT_RESOURCES` | `1450` |

**VID-facility statuses have no Win32 mapping and pass through verbatim**, so `GetLastError()` after
a failed registration returns `0xC0370001` itself and is unambiguous against every ordinary failure.
The check is therefore on that exact value, and the arm must read `GetLastError()` rather than
inferring from the `BOOL` alone:

- **`GetLastError() == 0xC0370001`** ⇒ a VID client holds `#BP` on that child **at the moment of
  this call** ⇒ S5j's retained explanation is the live one.
- **Success** ⇒ the slot was `0xFF` **at that moment**, and the arm now holds the registration
  itself and can receive what the intercept produces.
- **Anything else** ⇒ classify nothing; it is a failure of the call, not a reading of the slot.

**It supersedes half of the replicated-arm plan and not the other half**, which an earlier draft of
this section did not separate. The half it answers is *"is the slot claimed"*, and it answers it
with no reboot and no kernel read. The half it cannot answer is *"what does an unregistered vector
meet"* — because **registering claims the slot**, so a `#BP` raised afterwards travels the
*registered* path and the drop is no longer what is being observed. Nor does a reading taken now
say what the slot held during S5h; the byte is mutable, as S5k recorded. Observing the drop still
wants a contemporaneous, **non-mutating** read inside a replicated arm, which is the kernel-memory
access this bench does not have.

So the registration is the better *next* move — it settles the current state and, on success, hands
over a receiver, which is S5's pass condition rather than its diagnosis — and it is not a
substitute for the diagnosis. It does replace the raw hypercall the probe has been using since S5b.

#### What this gate leaves open

Questions, not a schedule; the ordered plan is in `FOLLOWUPS.md` item 103.

- **Whether a second process can open a running VM's partition**, which every call in the sequence
  needs and this gate did not test. Everything above is conditional on it. **S5n tried and could
  not** — the open is refused at one integrity level, with an error matching a single-open rule that
  was not traced to its check. **Read that as "this arm could not obtain an open", not as a closed
  door**: S5n's limits keep privilege untested, duplication untried and the failing site unlocated,
  and its own plan keeps cheaper arms ahead of abandoning the route.
- **Whether the registration then receives**, through `VidSetupMessageQueue` / `VidMessageSlotMap` /
  `VidMessageSlotHandleAndGetNext`, with a `#BP` raised in the guest — VTL0 first, then the VTL1
  enclave, which is S5's pass condition. Not reached.
- **Settled here regardless**: the raw `WinHvInstallIntercept` pair should be retired in favour of
  the registration for exception vectors — better, though per S5l not safe against a raw installer.

#### Limits

- **Nothing was called.** This is three images read statically. Whether a second process can get a
  partition handle on a *running* Hyper-V VM at all, and at what privilege, is **not read here**;
  it is the first item in item 103's plan. **S5n ran it and could not get one** — and
  `VidAttachPartition` turned out not to be the call this bullet assumed: it starts the VPs rather
  than joining a partition.
- **`vid.dll`'s exports are not a documented contract.** They are stable entry points with public
  PDB names, which is not the same thing, and a build can move them.
- **The message-slot protocol is not read** — what `VidSetupMessageQueue` and `VidMessageSlotMap`
  expect, and the layout a client sees, belong to the receive item in item 103's plan rather than
  to this gate.
- **One build each**, named above, and Intel/this host only.

#### What the bench can and cannot debug, since two gates planned around getting this wrong

**No machine in this lab has kernel debugging enabled — not the host, and neither guest** — and the
setting that looks like it says otherwise says something else. Measured 2026-09-29, host directly
and both guests over PowerShell Direct:

| | `{current}` | `bcdedit /dbgsettings` |
|---|---|---|
| host | no `debug` entry | `debugtype Local` |
| Lab Guest Control | no `debug` entry | `debugtype Local` |
| Lab Guest Hyper-V | no `debug` entry (`testsigning Yes`) | `debugtype Local` |

`/dbgsettings` prints the **global debugger-settings store**, which is `debugtype Local` on a stock
image whether or not anything is debugged; only `debug Yes` in the boot entry enables it. Reading
the first as the second is what made S5k's and S5l's "just read the slot" plan look cheap, and
`attach_kernel_local` answering `0x80004001` is what corrected it. **Neither guest has KDNET
configured either**, so any plan wanting a kernel debugger *inside* a guest starts with a reboot
there too.

**None of that blocks what comes next**, and it is written down so nobody re-derives it: every S5
arm from S5b onward drives `h3probe.sys` on the **host** and a raiser in the guest over
**PowerShell Direct**, which needs no network, no KDNET and no guest debugger. S5m's steps are
host-side user-mode calls plus that same raiser.

### S5n result, 2026-09-29: a VID partition takes no second *open*, so the receiver has no reachable handle

**A VID partition name can be opened once at a time, globally, and Hyper-V holds that open for
every running VM.** S5m found the receiver exported in `vid.dll` and named the first thing to find
out: whether a second process can get a partition handle on a running VM by opening it. It cannot.

**Two precisions the first draft of this section did not make**, both from review. The measured
constraint is *no second **open***, not "one handle can exist": `DuplicateHandle` and handle
inheritance create further handles to the same file object without a create request, and neither
was attempted — so duplication is an **excluded route**, recorded below, rather than something this
gate closed. And the refusal's *cause* on a live VM is established less tightly than the refusal
itself; the controls below say what they rule out and what they do not.

So the sequence S5m laid out — **open** the partition, register `#BP`, receive (*not* "attach":
that call starts the virtual processors, as below) — **is structurally unavailable for a
VM run by Hyper-V.** It is available to whoever *created* the partition, which for a Hyper-V guest
is `vmwp.exe` and for nobody else.

This is a live result and it cost the bench nothing: no VM was touched, no intercept installed, no
reboot, and the only objects created were **six** transient VID partitions, under four names no VM
uses, every handle closed. The limits section lists the names and explains why the two counts differ.

#### The namespace, read rather than guessed

`VidCreatePartition` calls `VidpCreateVidObject`, which builds a path and opens it:

```text
prefix = the device interface path for GUID_DEVICEINTERFACE_VID  (or "\\?\VidExo" for Exo)
path   = StringCchPrintfW("%s\%s", prefix, name)
handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                     OPEN_EXISTING, 0x40100080, NULL)
```

`GUID_DEVICEINTERFACE_VID` is `{7896E901-FE60-446E-828D-D65920654A23}`, read out of `vid.dll` at
`+0x23B50`, and SetupAPI resolves it on this host to
`\\?\root#vid#0000#{7896e901-fe60-446e-828d-d65920654a23}`. The leaf is the partition name, which
for a Hyper-V guest is its **VM Id**. So the whole "open a partition" operation is one `CreateFileW`
— no IOCTL, no privilege beyond opening the device.

**`VidAttachPartition` is not the call its name suggests**, which is worth recording because the
plan briefly assumed it was. IOCTL `0x221014` reaches `Vid!VidPartitionIoctlAttach`, which loops
over the partition's VPs calling `VidVpAttach` — it is the VM-worker's *start the virtual
processors* operation, gated on the partition being in states `2`/`2` and a flag at `+0x3079`. It
has nothing to do with a second client joining, and calling it on a running VM would be disruptive
rather than useless. It was not called.

**Superseded in part by S5o, and the half that survives is the half that mattered here.** Reading
the flag at `+0x3079` rather than only noting it shows what this IOCTL is: it requires the
partition to be **detached**, which is the second half of an ownership handoff rather than a
start-up step — so "nothing to do with a second client joining" is wrong, and the correct statement
is *nothing to do with a second client joining* **alongside** *the first*. The operational reading
that follows from it is unchanged and was right: calling it on a running VM would be disruptive,
and it was not called.

#### What the opens actually do, with the controls that make the reading sound

Every row is one `CreateFileW` with the arguments above:

| name | result |
|---|---|
| `Lab Guest Control`'s VM Id, lower and upper case | **`ERROR_BAD_COMMAND` (22)** |
| `Lab Guest Hyper-V`'s VM Id, lower and upper case | **`ERROR_BAD_COMMAND` (22)** |
| either VM Id wrapped in braces | `0xC0370005`, a VID-facility status |
| `zzzz-not-a-partition` | `0xC0370005` |
| a well-formed GUID no VM uses | **opens** |
| the bare device path, no leaf | opens |

So a malformed name and a live VM's name fail *differently*, and a well-formed unused name
**succeeds** — which already says the VM's name was recognised and the open refused, rather than not
found.

**Two controls reproduce `22` with no VM involved at all.** Within one process:

| step | result |
|---|---|
| open a fresh unused name | **succeeds**, handle `0x1D8` |
| open the *same* name again, same process, `FILE_SHARE_READ` | **`ERROR_BAD_COMMAND` (22)** |
| open the same name again, `FILE_SHARE_READ \| FILE_SHARE_WRITE` | **`ERROR_BAD_COMMAND` (22)** |
| close both handles, open again | **succeeds**, handle `0x1D8` |

and across two processes, which is the shape a VM actually presents:

| step | result |
|---|---|
| a child process opens a fresh unused name and holds it | **succeeds** |
| the parent opens **that** name | **`ERROR_BAD_COMMAND` (22)** |
| the parent opens a **different** unused name, at the same moment | **succeeds** |
| the child exits; the parent opens the held name again | **succeeds** |

**So the rule is global rather than per-process, and per *name* rather than per device** — a
second name opens happily while the first is held, so `22` is not a busy device or a lock over the
whole interface. It is not share-mode negotiation either, since widening the mask changes nothing.
The name frees the moment the last handle closes.

**What that does and does not establish about a live VM.** A running Hyper-V VM's partition is held
open by `vmwp.exe` for the VM's lifetime, and its name refuses with the same error under the same
call. **That is a match, not a proof of common cause**: `STATUS_INVALID_DEVICE_STATE` — the status
that maps to Win32 `22`, confirmed by `RtlNtStatusToDosError` in the S5m measurement table — appears
at 62 sites in `Vid.sys`, and the create dispatcher was not located, so two different checks could
produce the same error. The controls rule out the two alternatives they can reach: it is not
per-process, and it is not the device being busy. **Not ruled out** are VM lifecycle state, caller
identity and partition-specific state. **Caller identity is the cheap one** — rerunning the same
opens under another token needs nothing this bench lacks, and the plan's next arm is exactly that,
as `SYSTEM`. The other two are what want a kernel debugger or a VM stop, and only the first of those
turns out to discriminate.

**S5o closed this paragraph from an angle it did not consider, and two of its cost estimates were
wrong.** The check is readable in the image — `Vid.sys` is KMDF, so the dispatcher this paragraph
could not find by name is a file-object callback reached *through* the framework's `MajorFunction`
entries rather than named in one — and reading
it settles all three residual causes at once: the refusal tests **partition-specific state** and
nothing else, consulting neither the caller's token nor the VM's lifecycle. So this paragraph had
both costs wrong. Caller identity needed no run at all — the static read made one unnecessary
rather than merely cheap — and the alternative filed here as wanting a kernel debugger wanted an
image and a PDB.

#### What this does to the plan

- **The exported receiver S5m found has no handle this gate could obtain.** Every call in that
  sequence — `VidRegisterExceptionHandler`, `VidMessageSlotMap`,
  `VidHandleMessageAndGetNextMessage`, `VidUnregisterHandler` — takes the partition handle, and
  opening one is refused.
- **Nothing here says privilege would help**, and nothing here says it would not. The controls were
  run at one integrity level with one token, so *"running as SYSTEM changes it"* is untested rather
  than excluded. What the controls do show is that the rule they exercise is indifferent to
  *which* process asks — which makes privilege an unlikely explanation for the VM case without
  ruling it out. Varying it is one cheap arm if this route is worth another look. **S5o ruled it
  out** by reading the check rather than by varying anything: the refusal consults no token, and
  the one token check on the create path is on *creating* a partition, where an administrator —
  which both this account and `SYSTEM` are — is admitted unconditionally.
- **Handle duplication and inheritance are excluded routes, not closed ones.** They would produce a
  second handle without a second open, so the measurement above does not reach them. They are not
  attempted: `vmwp.exe` runs protected, and taking a handle out of it would be an attack on the
  platform rather than an experiment on it.
- **The route with the clearest path is to own the partition**, which means running the guest under
  a VMM of our own rather than under Hyper-V's. `vid.dll` exports enough to consider it —
  `VidCreatePartition`, `VidVsmEnableVpVtl`, `VidVsmSetPartitionConfig`, `VidVsmGetPartitionConfig`
  — and that last group is the interesting part, because VSM configuration is what a VTL1 target
  needs. **That is a different and much larger rig than anything this plan has built**, and it
  should be costed as its own decision rather than slipped in as the next step. It is *the clearest*
  rather than *the only* route: **two** cheaper ones this gate could not reach — varying the caller
  upward, and locating the failing check — come before it in item 103's plan. A third, a stopped VM,
  was proposed and dropped because it moves two candidate causes together; the plan records why.
  **S5o ran the second cheap one and it answered the first as well** — so both of those are gone,
  and what stands between here and *"the only route"* is a third cheap one S5o opened rather than
  closed: a **writer census** of the two fields its refusal tests. Until that comes back empty this
  is the route with no *known* obstacle, which is a weaker claim and the right one. An earlier
  version of this sentence said *the only* route, which contradicted S5o's own limits two screens
  below and would have sent the work at the large rig before the cheap check that can make it
  unnecessary.
- **S5 does not pass**, and the obstacle has changed shape. It is no longer a missing mechanism:
  the mechanism exists and is exported. What blocks it is that opening the partition of a VM this
  host did not create is refused, for a reason consistent with a single-open rule and not yet traced
  to its check. **S5o traced it**, and the shape changed once more: the refusal is a partition-state
  test, and the branch behind it transfers ownership rather than admitting a second client.

#### Limits

- **The single-open rule is measured, not read, and the live VM's refusal is matched to it rather
  than traced.** Where Vid enforces it — presumably its `IRP_MJ_CREATE` handler — was **not**
  located: `0xC0000184`, the status that maps to `ERROR_BAD_COMMAND`, appears at 62 sites in
  `Vid.sys` and no create dispatcher was identifiable by symbol name. So two different checks could
  give the same error, and the eight arms above narrow the alternatives without eliminating them.
  **Lifted by S5o**, which located it — and the guess in this bullet is why it took a second gate:
  the driver is KMDF, so its `IRP_MJ_CREATE` entry is the framework's, and the handler to find is
  the file-object callback behind it.
- **Measured at one integrity level, with one token.** Nothing here varies the caller, so the
  refusal's independence from privilege is an inference from the rule's indifference to *which*
  process asks, not a measurement. **Still true of this gate** — S5o did not vary the caller
  either. It established the same conclusion by a different kind of evidence, reading the check
  instead of sampling its behaviour, which is why the plan records the `SYSTEM` arm as *not run*
  rather than as *refused*.
- **The constraint measured is "no second open", not "one handle".** `DuplicateHandle` and handle
  inheritance are untested and untried.
- **Two guests, one host, one build.** `vid.dll 10.0.26100.8457`, `Vid.sys 10.0.26100.9278`.
- **Stopped VMs were not tried.** Both lab guests are running, and stopping one is a bench change
  this gate did not need. Whether a stopped VM's partition object exists at all is untested.
- **The probe created six transient partition objects under four names**, and every handle was
  closed. The two counts differ because a name frees when its last handle closes and both controls
  then reopen it, which creates a *new* object: `11111111-…` was opened, refused twice, and reopened
  after closing (two objects), and `aaaaaaaa-…` likewise (two more). The names,
  because this is the audit record for the arm's host-side effects: `00000000-0000-0000-0000-000000000000`
  (the well-formed-unused-name arm), `11111111-2222-3333-4444-555566667777` (the same-process
  control), and `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee` plus
  `ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb` (the cross-process control's held name and its concurrent
  control). No VM uses any of them. Named here because a reader should know the probe is not purely
  passive — and because three earlier drafts of this section said "two", "three" and "four", the
  first two counting a subset of the names and the third counting names where the audit wants
  objects.

#### What this gate leaves open

- **Whether privilege lifts the refusal.** Nothing here varies the caller, so this section could
  only infer the refusal's independence from privilege out of the rule's indifference to *which*
  process asks. **Answered by S5o, and by reading rather than by running**: the refusing check
  consults no token, so a caller varied upward reaches the same instruction.
- **Where the refusal is enforced.** `0xC0000184` has 62 sites in `Vid.sys` and no create
  dispatcher was identifiable by symbol name, so two different checks could give the same error.
  **Answered by S5o**: the driver is KMDF, so its `MajorFunction` entries are the framework's and
  name nothing in `Vid.sys`, and the check reads statically out of the image once you follow the
  file-object callback instead. This bullet's predecessor costed the answer at a
  host reboot into kernel-debug mode; that was wrong, and wrong in a way worth keeping visible —
  it assumed locating a dispatcher meant catching it running.
- ~~**A stopped VM.**~~ **Dropped: it does not discriminate**, and an earlier draft proposed it as
  though it did. Stopping the guest moves *both* candidate causes at once — `vmwp.exe` releases its
  open **and** the VM's lifecycle state changes — so neither outcome separates them. Worse, if the
  partition object goes away with the VM, as the limits above allow, then the VM Id becomes just
  another well-formed unused name and a successful open says only what the unused-name arm already
  said. Making it discriminate would need an independent check of whether the object still exists,
  which is the same kernel visibility this gate does not have.
- **Owning the partition rather than opening one** — the VMM-of-our-own question, which is a rig to
  cost rather than an arm to run, and which `FOLLOWUPS.md` item 103 orders against everything else.

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

### S5o result, 2026-09-29: the refusal is a partition-state test with no token in it, and the branch behind it is an ownership handoff

**Two of the plan's open steps are answered by one read, and neither needed the arm it was waiting
for.** S5n left the live VM's refusal *matched* to a single-open rule rather than traced to a check,
and left privilege untested; the plan's next two steps were a run as `SYSTEM` and — expensively, as
a host reboot into kernel-debug mode — locating the check. The check is in `Vid.sys`'s create path
and reads out of the image with no debugger attached to anything, and having read it:

- **The refusing check consults no token at all.** It tests two fields of the partition object. So
  the `SYSTEM` run cannot change the outcome, and the plan's fork collapses onto its "refused too"
  branch **without being run** — which is the better evidence of the two, because a refusal under
  `SYSTEM` would have been one more match and this is the instruction.
- **The branch it guards is not a second client joining. It is the partition changing owner**, and
  the one route into it this gate located runs through the current owner asking to give the
  partition up. Whether any *other* writer can put the gating fields into the admitting state is
  **not** established — see the limits — so this closes the route as far as the located path goes,
  not as far as the driver goes.

So the **refusal** is now understood by cause rather than by match, and the route behind it is not
the room S5m was heading for: the door is locked, and the one key found unlocks it by emptying the
room. What this gate does **not** do is prove there is no second key — the writer census that would
settle that was not run, and the limits below say so.

This gate executed nothing. No VM was touched, no partition object created, no handle opened, no
intercept installed, no reboot — it is a static read of one image.

#### How it was read

`DbgEng` opens a PE image as a target of its own, which the repo already relies on for
`securekernel.exe` (S2) and is what makes this cheap: `open_dump` on
`C:\Windows\System32\drivers\Vid.sys` loads the image at `0x140000000` with its public PDB, and
`uf` walks the code with symbols. There is no debuggee, no live kernel and no VM in the picture, so
the kernel-debug reboot S5n costed for this step was never needed for the *static* half of the
question — a distinction that section did not draw, because it assumed locating the dispatcher
meant catching it running.

`Vid.sys` is a **KMDF** driver, which is why S5n looked for an `IRP_MJ_CREATE` dispatcher by name
and found none — though **not** because there is no `MajorFunction` table. There is one, and the
framework fills it: `Wdf01000!FxDriver::Initialize` runs a 28-entry loop (`0` through `0x1B`,
`IRP_MJ_MAXIMUM_FUNCTION_CODE + 1`) writing `Wdf01000!FxDevice::Dispatch` or
`FxDevice::DispatchWithLock` into every slot, picked per device by `FxDevice::_RequiresRemLock`.
So all 28 entries point into **`Wdf01000.sys`**, none into the client driver, and an `IRP_MJ_CREATE`
travels `FxDevice::Dispatch` → `FxPkgGeneral::OnCreate` → the callback the driver registered in its
file-object config. What the image lacks is a **VID-owned** create dispatcher, not the table — a
distinction worth keeping, because the first version of this paragraph gave the wrong model for
tracing any KMDF driver, and every in-box Hyper-V component here is one. (Read from
`Wdf01000.sys 1.35.26100.3323` the same way, as a PE target with its public PDB — the framework is
a separate image with its own version line, which is itself the point.)

The create callback is
`Vid!VidFileCreate` (RVA `0xe030`), a one-line forwarder to `Vid!VidFileObjectCreate`
(RVA `0x8d20`) passing a fourth argument of `0`. `Vid!VidExopFileCreate` (RVA `0x61dc0`) forwards to
the same function passing `1`, which is how that argument is identified as the **Exo** selector
rather than guessed. The device we open is the VID interface, so every reading below is the `0` arm.

The `FILE_OBJECT` is identified by two offsets rather than asserted: the function reads a
`UNICODE_STRING` at `+0x58` and writes its result to `+0x18`, which are `FileName` and `FsContext`.

#### The create path, and a cause for every row S5n measured

| what the caller asks for | what `VidFileObjectCreate` does |
|---|---|
| a name of length `0`, or of length `2` whose one character is `\` | returns success with no partition — the **bare device** open |
| a name `VidPartitionNameParse` (RVA `0x31990`) rejects | that function's own VID-facility status — the measured `0xC0370005` |
| a parsed name, device tag `!= 1` | `VidPartitionCreate` |
| a parsed name, tag `== 1`, `VidPartitionTableLookup` misses | `VidPartitionCreate` — which **creates**, and is why the probe left transient objects |
| a parsed name, tag `== 1`, found, `[p+0x3060] != 2` **or** `[p+0x3079] != 1` | **`STATUS_INVALID_DEVICE_STATE`** at RVA `0x8f6f`, which `RtlNtStatusToDosError` maps to `ERROR_BAD_COMMAND` (22) |
| a parsed name, tag `== 1`, found, both hold | `VidPartitionAttach`, and a handle |

**The two arms predict different errors, and the measurements pick one — so the branch is
identified rather than assumed.** If the VID device's context tag were `0`, the lookup would be
skipped and `VidPartitionCreate` would take its *other* arm, which looks a partition up instead of
allocating one and answers a miss with `0xC0370009`; an unused name would then have **failed**
rather than created anything. S5n measured an unused name creating an object and an existing name
answering `0xC0000184`, which is only the `tag == 1` path.

**S5n's "a match, not a proof of common cause" can now be upgraded to a common cause.** On this arm
there is exactly one `0xC0000184` site — the other in the function sits under `exo != 0`, and
`VidFileCreate` passes `0` — so the probe's own held name and a live guest's name are refused by the
**same instruction**. The 62 sites S5n counted are real and irrelevant: 61 of them are not on this
path.

#### Why privilege cannot lift it

**The only token check anywhere on the create path is on *creating*, not on the refusal.**
`VidPartitionCreate` calls `Vid!VidSidPartitionCheck` (RVA `0xbebec`), which is:

- `VidCurrentProcessIsAdmin` (RVA `0x5e468`) — `SeTokenIsAdmin` on the primary token — and an admin
  **returns success immediately, with no further check**;
- otherwise the caller's user SID must have exactly six sub-authorities beginning `S-1-5-83-1`, and
  its last four must `memcmp` equal against the partition name — the per-VM
  `NT VIRTUAL MACHINE\<vm id>` identity, which is how a `vmwp.exe` is confined to its own VM's
  partition. Anything else is `STATUS_INVALID_SID`.

**That our elevated token took the admin arm is measured, not assumed**: S5n's unused-name opens
created partitions under names that are not this account's SID, and the non-admin arm would have
rejected that account's five-sub-authority user SID outright. `SeTokenIsAdmin` is true for `SYSTEM`
as well, so the `SYSTEM` run reaches the **same instruction with the same two fields**, and that
instruction reads neither a token nor a process.

Identity *is* consulted before any of this, by the object manager against the device's own security
descriptor — and the probe passes it, which is why the error is `22` and not `ERROR_ACCESS_DENIED`.
`SYSTEM` cannot do better than passing.

#### What the guarded branch actually is, and why reaching it would not have helped

`Vid!VidPartitionAttach` (RVA `0x10b08`) rearms the two file-object counters, unblocks the
partition's op control, takes a reference, stores **`PsGetCurrentProcess()`** at `[p+0x3780]`,
references that process, and calls `VidThreadPoolSwitchProcess`. Its inverse
`Vid!VidPartitionDetach` (RVA `0xb06c`) returns immediately unless `[p+0x3079]` is set, and
otherwise unmaps the statistics page, calls **`VidHandlerUnregister`**, detaches every VP,
un-shares both client buffers per VP, uninitialises the dispatch interface, switches the thread pool
away and dereferences the stored process.

So `[p+0x3079]` is a **detached** flag, and the pair is a handoff protocol rather than a lock:

- `Vid!VidPartitionIoctlDetach` (RVA `0x66164`) requires `[p+0x3060] == 2`, `[p+0x3064] == 2` and
  `[p+0x3079] == 0`, then **sets `[p+0x3079] = 1`**;
- `Vid!VidPartitionIoctlAttach` (RVA `0xc1f4`) requires the same two states and `[p+0x3079] != 0`,
  then attaches every VP. **This corrects S5n's reading of that IOCTL** as merely "start the virtual
  processors": it is the second half of a handoff, and it refuses a partition nobody has detached;
- and the create path demands the same detached flag before it will hand a *new process* a handle.

**The consequence for S5 is stronger than a refusal, and it is bounded by what was enumerated.**
Even a successful open would not have produced a second receiver alongside Hyper-V's: it would have
taken the partition over, becoming the process the thread pool runs in. **On the route located
here** it could only have happened after `vmwp.exe` had already called `VidHandlerUnregister` and
detached the VPs — so that route dismantles the receive path S5m found by the very step that lets
us in.

**What is not established is that it is the only route in.** The limits below say the writers of
the two gating fields were not enumerated, and this paragraph must not quietly claim otherwise: if
some other path sets `[p+0x3079]` without running the detach sequence, a registration alongside
Hyper-V is not excluded by anything read here. Two reviewers caught that overreach independently,
and the correction is the reason it is spelled out rather than softened — **what would settle it is
a writer census or live confirmation**, and until one of those exists the honest statement is *no
admission that preserves the receive path has been found*, not *none exists*.

#### Limits

- **Nothing was executed, and no live partition object was read.** Which of the two fields a
  running guest's partition fails on is therefore not measured — only that at least one must.
- **The writers of these fields are not enumerated.** `VidPartitionIoctlDetach` is the writer this
  gate *located* for `[p+0x3079]`; it is not established to be the only one. A byte scan for either
  displacement cannot separate partition objects from the several other `Vid` structures with
  fields at the same offsets — most hits for both land in `Vsmm*` code on unrelated objects — so
  "only the owner can set it" is the shape of the protocol read from three functions, not a
  census. An earlier draft of this section claimed the census, from a `s -d` scan that was
  **dword-aligned** and silently missed unaligned displacements, including one in
  `VidPartitionDetach` itself.
- **`[p+0x3060]` and `[p+0x3064]` are read as "both must be 2", not decoded.** What state 2 *is*
  was not established, and it is not needed for the conclusion: entering the admitting state at all
  requires the owner's detach.
- **One build, read statically.** `Vid.sys 10.0.26100.9278`, the image on this host.
- **Exo partitions are out of scope.** The `exo != 0` arm has its own create path and its own
  `0xC0000184` site, and none of the above was read for it.
- **Handle duplication and inheritance are still excluded routes**, exactly as S5n left them.
  Nothing here reaches them.

#### What this gate leaves open

- **Whether owning the partition from creation reaches S5's pass condition** — the VMM-of-our-own
  question, unchanged by this gate except that it is now the route with no known obstacle rather
  than the clearest of several. It is a rig to cost, not an arm to run.
- **A writer census for `[p+0x3060]` and `[p+0x3079]`**, which is the cheaper of the two things
  that would decide whether the previous bullet is the *only* route. It wants a way to tell
  partition objects from the other `Vid` structures sharing those displacements — a type-aware
  cross-reference rather than a byte scan — and it is desk work on an image this gate already has
  open. The other is live confirmation on a running guest's partition.
- **The two arms blocked by the standing constraint** — the replicated slot read and whether the
  hold is a loop — which this gate does not touch and does not unblock.
- **Whether a guest's partition is ever momentarily in the admitting state** — answerable only with
  live kernel visibility. On the located path it would be worth little, since that state is entered
  by the owner detaching, which is not a window to race but a handoff to intercept; if the census
  above finds another writer, that changes.

### S5p result, 2026-09-29: the writer census, and S5o's retracted sentence comes back as a measurement

**Exactly one instruction in `Vid.sys` sets `[partition+0x3079]` to the value the create path
requires, and it is inside the detach IOCTL.** S5o read the create path's refusal and then claimed
more than it had measured — that the ownership handoff was the *only* way into the admitting state
— and two reviewers independently refused the claim, correctly, because the writers had never been
enumerated. This gate enumerates them. The claim is now true on evidence rather than on inference,
and the retraction was right to demand it: what was unestablished then is established now, by a
different kind of work.

Nothing was executed. This is a decoded read of one image.

#### The instrument, and why a byte scan could not do this

[`tools/vid_field_census.py`](../../tools/vid_field_census.py) walks the image's own `.pdata`
function table — exact on x86-64 and needing no symbols — disassembles every function with
capstone, and reports only instructions carrying a **real memory operand** at the displacement
asked for, classified read/write by capstone's own operand access rather than guessed from the
mnemonic. `--self-test` decodes six instructions whose bytes were read out of this image during
S5o, so a pass means it agrees with what the debugger showed for the same instructions; a seventh
case pins the thing that makes it necessary, that `mov eax,3060h` must **not** count. 7/7 here.

Three ways the obvious search is wrong, all of which bit:

- **It scans aligned.** S5o's first attempt used `s -d`, which walks dword-aligned, and a
  displacement sits after a variable-length opcode and ModRM — so it missed sites, including one in
  `VidPartitionDetach` itself. S5o recorded that it had, which is why it claimed no census.
- **It matches non-operands.** Immediates, relative offsets and data all contain those bytes.
- **It cannot see a write through a taken address**, which is not hypothetical here — see below.

#### `[p+0x3079]`: 19 accesses, 4 writers, **0 address-taken**

| site | writes |
|---|---|
| `VidPartitionIoctlDetach+0x43` | **`1`** |
| `VidPartitionIoctlAttach+0xca` | `0` |
| `VidPartitionUninitialize+0x413` | `0` — `mov byte ptr [rdi+3079h],sil`, and `sil` is `0` from the `xor esi,esi` at `+0x5b`, which is the function's null register: every other use of it in the function nulls a pointer field (`[+0xB58]`, `[+0xB68]`, `[+0x70]`, `[+0x3780]`, `[+0x3788]`, `[+0x3EB8]`) |
| `VsmmPhuIoctlEnd+0xbe` | `0` |

The other fifteen accesses are reads. **No site takes the field's address**, so for this field the
census is *complete*: there is no pointer through which some other function could write it, and the
four sites above are every instruction in the image that can change it.

**Three of the four clear it. One sets it, and that one is the detach IOCTL** — which itself
demands `[p+0x3060] == 2`, `[p+0x3064] == 2` and `[p+0x3079] == 0` before it will, so the caller
must already hold the partition.

#### Why that settles the question without a complete census of the other field

The create path requires **both** `[p+0x3060] == 2` **and** `[p+0x3079] == 1`. A conjunction is
gated by its weakest reachable term, and `[p+0x3079] == 1` is reachable from exactly one
instruction — so whatever else may write `[p+0x3060]`, **no admission can occur that the detach
IOCTL did not enable.** The `[p+0x3060]` census is therefore reported below for what it says about
the field's meaning, not because the conclusion needs it.

**So S5o's conclusion stands, and now with the evidence it was missing.** The route into
`VidPartitionAttach` runs through an owner who called detach, and detach calls
`VidHandlerUnregister` and detaches every VP before returning. There is no second client alongside
Hyper-V to be had on a VM Hyper-V runs.

#### `[p+0x3060]` / `[p+0x3064]`: what they are, and one write the displacement alone would have missed

47 and 38 accesses, 7 and 6 writers — and **2 address-taken sites on `0x3060`**, which is where the
instrument paid for itself. Following them:

- `VsmmPhuIoctlEnd+0x42` takes `lea rdi,[rbx+3060h]` and only ever reads through it.
- `VsmmPhuPartitionTeardown+0x16` takes `lea rsi,[rcx+3060h]` and later executes
  **`and dword ptr [rsi],0`** — a write to `[p+0x3060]` whose displacement is **zero**. No search
  for `0x3060`, byte or decoded, can see that instruction. It is only reachable by noticing the
  address was taken and following it, which is exactly what the `lea` column is for.

So the `[p+0x3060]` writer set is **bounded but not closed**, and is reported as such.

**What the fields are** is now much less anonymous. Every writer of the pair is in the `VsmmPhu*`
family — `PartitionInitialize` (zeroes both), `IoctlBegin`, `IoctlCommit`, `PartitionRestore`,
`PhupUncommit`, `PartitionTeardown` (zeroes both) — and the ETW events either side of
`VsmmPhuIoctlEnd` are literally `VID_PARTITION_UNPERSIST_START` / `_STOP`. So this is the
partition **persistence** state machine, not a general lifecycle counter, and the create path's
`== 2` names a state reached through the persist Begin/Commit sequence. **Which value 2 is
precisely, and which of Begin or Commit produces it, is not decoded here** — but the domain
answers the question S5o left hanging about why a running guest fails the test: its partition is
not in a committed-persist state, because nothing has persisted it.

That also makes the design read coherently for the first time. The second open is the reconnect
half of **persist-and-restore** — a worker process handing a partition on, or picking one back up —
which is why it demands a persisted, detached partition and why it re-owns rather than joins.

#### Limits

- **A bulk copy is outside this method.** The census covers instructions with an explicit
  displacement operand plus every `lea` of one. A `memcpy`-shaped restore whose length spans the
  field would write it without either, and `VsmmPhuPartitionRestore` is in the persistence family
  that would do such a thing. Nothing here excludes it, and it is the one residual on the
  `[p+0x3079]` result rather than a residual on the reasoning above it.
- **`[p+0x3060]`'s writers are not claimed complete**, per the taken address above.
- **Static, one build** — `Vid.sys 10.0.26100.9278`. No partition object was inspected live, so
  this says what the code can do, not what any particular partition's fields hold.
- **The fingerprint column is per `(function, base register)`**, so a function that reuses a
  register for two different objects shows their offsets merged. It is a reading aid for telling a
  partition from a memory block by hand, not a type recovery.

#### What this gate leaves open

- **The VMM-of-our-own question**, which is now the only remaining user-mode route **on evidence**
  rather than on assumption — the distinction this gate exists to supply. Still a rig to cost.
- **What persistence state `2` is**, if anyone needs to know whether a guest's partition can be
  driven into it deliberately. Note what that would mean: persisting a running guest's partition,
  which is a disruptive operation on somebody else's VM, not an observation.
- **The two arms blocked by the standing constraint**, untouched.
