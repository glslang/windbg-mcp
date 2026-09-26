# Secure Kernel debugging validation

## Current status, 2026-09-23

NT and hypervisor debugging passed; native Secure Kernel attachment did not. Loader
configuration and hypervisor VTL1 debug-buffer initialization were measured successfully
after resolving earlier failures. Offline comparison found the same three stub-like
debugger routines in six exact SK images; it does not establish universal build support.
See [the build comparison](#offline-build-comparison-and-native-route-gate-2026-09-19).

The stub finding was re-derived from the retained image samples on 2026-09-22, and the
routine was traced to its caller: it is the handler for **secure call `0x124`**, so there is
no `IumpDebugBreakRequestedByVtl1` to find and its absence is structural. The same pass found
that SK populates a complete debugger data block while shipping no KD transport, and that
Microsoft's own `ExdiGdbSrv.dll` ships with WinDbg — which makes the EXDI backend contract a
GDB stub rather than a COM server or a LiveCloudKd dependency. No live attach, host change or
EXDI installation followed. See
[the dispatch and EXDI reassessment](#secure-call-dispatch-of-the-debug-break-request-and-exdi-reassessment-2026-09-22).

The first EXDI attempts then ran on 2026-09-22/23 and **one of them reset this workspace**.
Offline reading established the `Kd=` option set — six discovery modes, of which
`Kd=VerAddr:<addr>` takes an arbitrary `KdVersionBlock` address and is the mechanism a Secure
Kernel bind would use. The `sk!KdVersionBlock` record found earlier turns out to be
**EXDI-gated and possibly vestigial**, so a hypervisor KD session cannot be steered to it;
that earlier reading was too strong and is corrected there. Registration of the EXDI COM
server is a real prerequisite, and the `Inproc` option that appears to avoid it is what took
the machine down. Nothing was left registered and no target was touched. See
[the transport experiments](#exdi-transport-experiments-and-the-host-reset-2026-09-23).

The user has ruled out configuration changes on the hardened outer host and selected a
separate nested lab as the future direction. Provisioning is deferred while the investigation
is archived and prepared as a blog post. No host changes, VM reconfiguration or additional
live debugging are authorized by this publication step. The entries below preserve the
investigation chronologically; their proposed next actions are historical unless reaffirmed.

The public [evidence bundle](../samples/secure-kernel-debugger-investigation/README.md) preserves
selected offline disassembly and exact-image identities without raw credentials or binaries.

## Initial status, 2026-09-14: Phase 1 on-disk gate passed, lab pending

Measured on 2026-09-14. WinDbg was upgraded with the exact-version command below; winget verified
the installer hash and reported a successful install. The new x64 engine was bundled into both
`target/release` and `target/debug`, following [engine setup](../install.md#bundling-the-windbg-engine).
The six top-level DLL signatures were valid before copying. The preflight compared `dbgeng.dll`
to the installed payload by SHA-256 and found an exact match in the release directory.

```powershell
winget upgrade --id Microsoft.WinDbg --exact --version 1.2606.22001.0 --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity
```

| Measurement | Result |
| --- | --- |
| WinDbg before / after | 1.2603.20001.0 / 1.2606.22001.0 |
| Bundled x64 engine before / after | 10.0.29547.1002 / 10.0.29617.1000 |
| New `kdnet.exe` file version | 10.0.29617.1000 |
| `kdnet.exe -?` exit code / stderr | 0 / empty |
| Dedicated Secure Kernel switch | Present: `s - enable securekernel debugging` |
| Workspace OS | Windows 11 Pro 25H2, 26200.9457, x64 |
| Computer manufacturer / model | Microsoft Corporation / Virtual Machine |
| Hypervisor present | True |
| Processor exposed to workspace | Intel Core i7-14700 |
| `VirtualizationFirmwareEnabled` / `SecondLevelAddressTranslationExtensions` | False / False |
| Hyper-V optional feature | Disabled |
| Hyper-V management command / `vmms` service | Absent / absent |
| Workspace VBS status / security services running | 0 / `[0]` |
| dbgscope pin | `59d48a008f87fe2f99370c2a4984117637d1f4a7` (unchanged) |

**Gate decision:** native KDNET remains the route to test. EXDI has not been selected. The switch
and new engine are present; no VTL1 connection, breakpoint, single-step, or resume has been tested.

The pre-existing release supervisor had the old DLLs mapped. Its engine was preserved by moving
the previous bundle into a timestamped `target/secure-kernel-engine-backup-*` directory before
copying the new files. Reconnect the MCP server before using the new engine through that client.
Keep the backup until the old process has exited. No running server was terminated, and the x86
engine bundle was not updated. The backup contains the old top-level DLLs, extension and TTD
directories, and `kdexts.dll` (restore the latter into `winxp/`).

## Verification

On 2026-09-14:

- `cargo fmt --all --check` and `cargo clippy --all-targets` passed.
- `WINDBG_MCP_SMOKE_DUMP=1` with `cargo test --quiet`, outside the restricted process sandbox:
  unit harness **947 passed**; MCP smoke harness **111 passed, 14 ignored**, in 64.47 seconds.
  The dump/debugger gate was enabled. TTD and live-kernel tiers were not enabled; the separate
  `WINDBG_MCP_X86_DUMP` unit fixture was not supplied. No Secure Kernel acceptance is implied.
- The first default test run exposed a stale `target/debug/x86/windbg-mcp.exe` with a different
  build identity. Rebuilt with `cargo build --target i686-pc-windows-msvc` and copied into the
  debug bundle, retaining the previous executable in the backup. Both development worker
  architectures then reported `0.17.0+g31ce4e58`. No Rust source or dependency pin changed.
- The debugger-enabled sandbox run failed three process-lifetime checks; those passed when
  rerun with host process visibility. These were distinct from the stale-worker failures above.
- The preflight executed under Windows PowerShell **5.1.26100.9444** against both refreshed x64
  bundles, returning `ready_for_lab` with matching engine hashes. Its parse/ASCII checks passed,
  and an old-help synopsis containing `-SkipSecureBoot` did not match the Secure Kernel check.
- `markdownlint-cli2@0.23.2` passed for the plan and this record; `git diff --check` passed.

## Repeat the preflight

Run in an elevated Windows PowerShell 5.1 or newer session from the repository root:

```powershell
.\tools\secure_kernel_preflight.ps1
# Check the development bundle instead:
.\tools\secure_kernel_preflight.ps1 -EngineDirectory .\target\debug
```

The script emits JSON with versions, host virtualization observations, memory and system-disk
capacity, SHA-256 equality for the
source and bundled engine, and separate verbatim stdout/stderr from `kdnet.exe -?`. It accepts
`-WinDbgDirectory` for an unpacked package root containing `AppxManifest.xml` and `amd64/`.
The output includes local paths; review it before sharing. It reads no connection profiles, keys,
or BCD settings and does not configure debugging. Missing files or inaccessible host metadata
fail the command rather than being reported as a successful preflight.

| `native_gate` | Meaning |
| --- | --- |
| `pending_update` | Package is below 1.2606.22001.0 |
| `inconclusive_help` | New package, but help exited unsuccessfully or lacked the recognized synopsis |
| `closed_missing_switch` | New package and recognized help, but no dedicated Secure Kernel switch description |
| `pending_engine_bundle` | Switch exists, but the bundled engine does not match the package |
| `ready_for_lab` | Phase 1 package/help/on-disk engine checks passed; lab and running-process checks remain |

## Exact help from the updated binary

Captured from the installed package's `amd64/kdnet.exe -?`. Leading/trailing blank lines are
omitted below; wording and indentation are retained. The utility's emitted connection instructions
must still be captured when configuring the disposable guest. In particular, this help does not
settle the secure port when only `-s` is selected, so do not hard-code a connection from it.

```text
kdnet.exe [host] [port] [-[b][h][k][s][w]] [-SkipSecureBoot]
  [host] is the name or IPv4 address of the host machine running the debugger.
  [port] is the network port number to use for debugging this machine.
     [-[b][h][k][s][w]] are the debug types to enable
      b - enables bootmgr debugging
      h - enables hypervisor debugging
      k - enables kernel debugging
      s - enable securekernel debugging
      w - enables winload debugging
  Note that any combination of debug types may be specified.
  If no debug types are specified then kernel debugging will be enabled.
  If both hypervisor and kernel debug are enabled the hypervisor port
  will be set to the value port+1.
    If securekernel debug is enabled then the securekernel port value will be
    hypervisorport+1.
  [SkipSecureBoot] skips enabling bootdebug/hypervisordebug/debug on a machine with Secure Boot enable

kdnet.exe /busparams [device] [host] [port] [-[b][h][k][s][w]] [-SkipSecureBoot]
  [device] specifies the busparams of the device to configure.
  additional parameters same as specified above

kdnet.exe /addpf [device] [host] [port] [-[b][h][k][s][w]] [-SkipSecureBoot]
  [device] specifies the busparams of the device to which the
      PCI physical function will be added
  additional parameters same as specified above

kdnet.exe /removepf [device] [host] [port] [-[b][h][k][s][w]] [-SkipSecureBoot]
  [device] specifies the original busparams of the device from
      which the PCI physical function will be removed
  additional parameters same as specified above

kdnet.exe /xml
  Outputs supported KDNET device data in XML format.

When run without parameters, kdnet.exe identifies the NICs and USB3
controllers which support network debugging. When run with parameters
kdnet.exe enables network debugging using the specified information.
If [port] is not specified then it will be set to a default
value of 5364.
```

## Phase 2 entry condition

**Selected on 2026-09-16:** place the disposable target directly on the outer Hyper-V host,
as a sibling of the existing workspace VM. WinDbg/MCP can remain in the workspace and connect
over KDNET. Hosting a target inside the workspace is deferred; the workspace does not need a
Hyper-V installation or a RAM/disk increase for that purpose.

**Updated on 2026-09-18:** the user identified an existing Generation 2 sibling VM as the target.
Reuse it after checking its configuration and taking the required baseline checkpoint. Its
host-side virtualization-extension setting still needs verification; guest-side measurements are
recorded below. Workspace measurements do not establish target properties.

The target's Hyper-V name did not resolve through DNS from the workspace; a VM display name need
not be its guest hostname. Neither resolved outer-host address accepted TCP connections on SSH
or WinRM ports (22, 5985, 5986). After the user supplied the target address, TCP 5985 was reachable
and WinRM authentication with the current Windows identity succeeded. Guest integration metadata
confirmed the expected target and outer host. A comparison of KDNET key hashes and ports also
identified the existing debugger profile as belonging to this target; no key was printed. No VM
settings or network trust settings were changed during those initial checks. Later changes and
their rollback are recorded in the native experiment below.

### Target preflight, measured 2026-09-18

This is the initial state before the user exposed virtualization extensions and rebooted.

| Check | Target result |
| --- | --- |
| OS | Windows Server 2025 Standard, 24H2, build 26100.33438 |
| Memory / logical processors | 4 GiB / 4 |
| Secure Boot | Off |
| TPM | Present and ready |
| VBS status | 0 |
| Security services configured / running | `[2]` / `[0]` (memory integrity configured, not running) |
| Processor virtualization / SLAT flags inside guest | False / False; host VM processor setting still unverified |
| HVCI registry `Enabled` | 1 |
| DeviceGuard root VBS policy values queried | `EnableVirtualizationBasedSecurity`, `RequirePlatformSecurityFeatures`, `Locked` not present |
| Boot settings | `testsigning Yes`, `debug Yes`, `isolatedcontext Yes` |
| Ordinary KDNET | NET transport; host address matches debugger; key hash and port match the existing profile |
| Existing lab drivers | MessageManager running with automatic start; HEVD stopped with manual start |

These are setup observations, not an attach or Secure Kernel acceptance result. The identified
target is Server 2025, which changes the plan's original Windows 11 25H2 baseline. Native Secure
Kernel compatibility with this target build remains to be measured.

Before changing the existing target, take a checkpoint on the outer host and inspect
`Get-VMProcessor -VMName '<target VM name>'`. The guest's current WinRM access cannot perform those
outer-host operations. Preserve the existing driver-lab configuration: Secure Boot and test-signing
policy interact, and enabling memory integrity can affect driver compatibility. See Microsoft's
[test-signing guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)
and [memory-integrity guidance](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity).
The target has not been rebooted, attached, or reconfigured during this preflight. A checkpoint of
the current driver lab is separate from the later checkpoint of a verified VBS baseline.

### Native controls and configuration attempt, 2026-09-18

The user reported `ExposeVirtualizationExtensions = False` on the outer host, followed the
shutdown/expose/start procedure, and confirmed the guest was back. Post-boot guest measurements:

| Check | Result |
| --- | --- |
| VBS status | **2: running** |
| Security services configured / running | `[2]` / `[2]`: memory integrity running |
| Guest processor virtualization / SLAT flags | False / True |
| Secure Boot | Still off |
| Hyper-V server role inside target | Available, not installed |
| Working-VBS checkpoint | User confirmed `VBS-Baseline-20260918` was created on the outer host |
| Loaded release-supervisor engine | 10.0.29617.1000 |

`VirtualizationFirmwareEnabled = False` is therefore not, by itself, a usable blocker: this
guest reports it while VBS is demonstrably running. No additional VBS policy changes were needed.
Secure Boot remains off, which is a deviation from the original lab recipe, alongside the already
recorded Server 2025 target. The experiment preserves the target's test-signing setting.

**Native positive control passed.** Microsoft's package-supplied x64 `kd.exe`, engine
10.0.29617.1000, attached to ordinary NT KDNET through the existing machine-local profile. It
stopped at `nt!DbgBreakPointWithStatus`, loaded the matching `ntkrnlmp.pdb`, read RIP, disassembled
the stopped instructions, and exited through `qd`. WinRM then answered with advancing guest time
and VBS still running.

**Negative control passed.** Before Secure Kernel configuration, `lm m securekernel` listed no
module and `x securekernel!IumInvokeSecureService` failed to resolve. The corrected breakpoint
attempt produced this native output:

```text
0: kd> bp0 securekernel!IumInvokeSecureService
Bp expression 'securekernel!IumInvokeSecureService' could not be resolved, adding deferred bp
0: kd> bl
     0 e Disable Clear u                      0001 (0001) (securekernel!IumInvokeSecureService)

0: kd> bc 0
0: kd> bl

0: kd> qd
quit:
```

The earlier `bp 31 ...` attempt incorrectly treated the spaced number as an address; that run
does not establish the breakpoint control. The corrected run above cleared its sole deferred
breakpoint and verified an empty list before detaching. Redacted native logs and temporary control
scripts are retained under ignored `target/`; these are not the eventual MCP acceptance cast.

The console automation needed a delayed break-in: start KD with a local named-pipe debug server,
wait for the KDNET transport connection, then connect a second KD client with `-remote ... -bonc`.
The server's `-cf` script ran the controls and detached; the client then reported a remote-session
closure error while the server exited 0. The initial single-process `-bonc` attempted a break before
the transport connected (`0n87`), and did not subsequently stop the target. Two such attempts were
closed only after WinRM confirmed the target was running. Adding `target=<address>` to the native
connection produced a debugger startup access violation (`0xc0000005`); that option was removed.
No target crash or reboot occurred during these attempts. Firewall rules for the new KD binary
initially showed Block and later Allow; the agent did not edit those rules.

**Secure Kernel setup failed before a VTL1 attach.** The signed `kdnet.exe` 10.0.29617.1000 and its
`VerifiedNICList.xml` were copied into a dedicated administrator/System-only folder on the target
and verified by SHA-256. Its non-configuring NIC check reported support for the Microsoft
Hypervisor VM. The target's `securekernel.exe` is 10.0.26100.33438. A BCD export was saved in that
folder before running:

```text
kdnet.exe <debugger-address> <existing-NT-port> -ks
```

The utility exited **0x80004005**. Verbatim stdout:

```text
The hypervisorlaunchtype setting is not present in {current} or {default}. This is expected on platforms where hypervisor launch policy is implicit.
```

Verbatim stderr:

```text
No current hypervisorlaunchtype setting was found in bcdedit output (0x80070490).
Failed to enable securekernel debugging.  Is secure boot enabled?
```

Secure Boot was independently measured off, so the question in that generic error is not a
diagnosis. The failure left `hypervisordebug Yes` on the current boot entry, without configuring
the Secure Kernel transport. Removed that newly added value with
`bcdedit /deletevalue {current} hypervisordebug`; a full `bcdedit /enum all /v` comparison against
the exported store then matched exactly. The original profile still applies, no reboot was
performed, and a final WinRM check confirmed VBS status 2 and services running `[2]`.

The utility contains the UTF-16 command string `%s /set {default} vsmdebugtype 3` at file offset
`0x1CF50`. This is binary-string evidence, not a trace proving the failed invocation executed it.
The target has `bcdedit.exe` 10.0.26100.1 and `bcd.dll`
10.0.26100.4202; its OS-loader help lists `VSMLAUNCHTYPE` but not `VSMDEBUGTYPE`. Automatic approval
review initially rejected a direct reproduction as a persistent security/boot change requiring
clearer authorization. After the user explicitly approved that exact command without a reboot,
it was executed and exited **1**, with this verbatim stdout and empty stderr:

```text
The element data type specified is not recognized, or does not apply to the
specified entry.
Run "bcdedit /?" for command line assistance.
Element not found.
```

The subsequent full BCD comparison against the export again found no differences. VBS remained
**2**, security services running remained `[2]`, and the boot timestamp was unchanged. No reboot
was performed. This establishes that the target's BCDEdit rejects the utility's named setting
on this entry; it does not establish a minimum supported Windows build or prove that every
Secure Kernel debugging route is unavailable on this OS. No private numeric BCD element was
forced and no system binary was replaced.

**Gate correction at this stage:** the `-ks` attempt failed before VTL1 attachment, but its fatal
step had not been traced. The separate BCDEdit rejection did not prove why KDNET failed. The initial
decision to move to EXDI was premature; continue native investigation, including explicit
hypervisor setup. EXDI has not been installed or validated. The user-confirmed VBS checkpoint
provides the recovery baseline; do not treat the BCD comparison as a full checkpoint restoration.

### Explicit hypervisor setup and reboot, 2026-09-18

The user requested hypervisor setup and noted that a reboot may be needed. Rechecked target
identity, debugger address, Secure Boot (off), and VBS (2, services `[2]`). BitLocker tooling was
absent and the server BitLocker feature was not installed. Exported another BCD backup in the
existing protected target-side lab directory, then ran the same verified KDNET binary:

```text
kdnet.exe <debugger-address> 50001 -h
```

It exited **0**, emitted a hypervisor NET connection on port **50001** with a generated key,
and instructed a reboot. The key was not printed in the transcript or copied into this document.
It emitted the same missing-`hypervisorlaunchtype` stdout and stderr messages recorded above,
despite succeeding. Those messages alone therefore do not establish a fatal configuration error.

The full BCD comparison showed `hypervisordebug Yes` added and the hypervisor transport changed
from Serial to NET. Hypervisor host address, port, key, debug pages (1000), and DHCP (Yes) were
configured; serial port and baud rate were removed. The ordinary NT `/dbgsettings` output was
unchanged. No explicit `hypervisorlaunchtype` was added.

Started the native debugger with the generated hypervisor connection resolved internally,
verified its UDP listener and existing Public-profile Allow firewall rules, and scheduled a
normal target restart. Boot time changed and WinRM returned. After reboot, the configured
hypervisor NET settings persisted, `hypervisordebug` remained Yes, and VBS remained **2** with
services running `[2]`. Guest uptime advanced across subsequent checks.

**Result:** hypervisor configuration and target reboot succeeded, but the debugger remained
waiting without an observed hypervisor connection. This is not a successful hypervisor attach,
nor Secure Kernel acceptance. At this point the `-hs` variant had not yet been run. No Secure Kernel setting
was changed during this standalone hypervisor setup; EXDI remains deferred.
After a final WinRM check showed 158 seconds of uptime and VBS still running, the unconnected
listener was stopped by its verified process ID and executable path. Hypervisor boot settings
remain applied; no debugger from this experiment remains attached or waiting.

### Traced Secure Kernel setup failure, 2026-09-18

The user subsequently ran `-hs` on the target and received the same failure, then requested a
trace and a check for an older target KDNET binary. Both source and target report version
**10.0.29617.1000**, with identical SHA-256:

```text
572E4607C9EA6E5E18CD01919B9C186FECA178E197720896C9A11AFEF52277CB
```

The target copy's Authenticode signature is valid. The explicit lab path was used, not PATH
lookup. Target `bcdedit.exe` remains **10.0.26100.1**, `bcd.dll` **10.0.26100.4202**, and
`securekernel.exe` **10.0.26100.33438**.

Staged matching Microsoft CDB and its DLLs in the protected target-side lab directory, verifying
each copy by hash. A harmless nested `cmd.exe /c exit 7` test verified child command-line capture
and exit-status reporting before rerunning any setup. Used CDB `-o` with `cpr` and `epr` event
commands to record child process command lines and `.lastevent` exit codes. Command lines were
read from the x64 PEB process parameters; environment variables were not dumped. Missing optional
extension DLL warnings did not prevent these built-in commands from working. The final
`No runnable debuggees` message followed the recorded parent exit and the script's final `g`;
it is not the configuration failure.

After a fresh BCD export, traced `kdnet.exe <debugger-address> 50001 -hs`. Observed sequence:

| Process / command | Exit code |
| --- | --- |
| `bcdedit.exe /set hypervisordebug on` | 0 |
| `bcdedit.exe /enum {current}` (via `cmd.exe`, output redirected to KDNET's temporary file) | 0; wrapper also 0 |
| `bcdedit.exe /set {default} vsmdebugtype 3` | **1** |
| Parent `kdnet.exe` | **0x80004005** |

The parent emitted the same missing-launch-setting and Secure Kernel failure messages. This is
now execution evidence of the failed BCD command, not an inference from embedded strings. The
earlier standalone reproduction supplies its underlying error: element type unrecognized or
inapplicable, followed by `Element not found`. It does not establish a minimum supported target
build or justify substituting a newer system BCDEdit binary or forcing a private numeric element.

Full BCD enumeration before and after the traced run matched exactly, including keys. VBS
remained **2**, services running `[2]`, and the boot timestamp was unchanged. The trace's CDB and
KDNET processes exited; no reboot or further boot modification was performed. Redacted traces
and temporary scripts are retained under ignored `target/`, separate from source control.

**Current gate:** the tested native Secure Kernel configuration is blocked at the target's
rejection of the setting used by the verified new KDNET. Hypervisor transport connectivity is a
separate unvalidated result, not the cause established by this trace. EXDI remains deferred;
target-build compatibility needs evidence before proposing another native target or OS change.

### BCDEdit build survey, 2026-09-18

Microsoft's [WinDbg release notes](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-release-notes)
announce `kdnet -s` in 1.2606.22001.0 but do not specify a minimum target build. An exact-name
search did not locate a Microsoft `vsmdebugtype` reference. Consequently, examined x64 binaries
directly, using the [Winbindex release index](https://winbindex.m417z.com/?file=bcdedit.exe) and
[Insider index](https://winbindex.m417z.com/?arch=insider&file=bcdedit.exe) only to locate files.
Downloaded the binaries from **Microsoft's public symbol server**, verified their SHA-256 hashes
against the index, and scanned them without executing or installing them.

| BCDEdit file version inspected | `vsmdebugtype` present | Evidence scope |
| --- | --- | --- |
| 10.0.26100.1 | No | Installed copies; target also rejects the actual command |
| 10.0.26100.8737 | No | Downloaded release sample, also indexed for 25H2 updates |
| 10.0.28000.1 | **Yes** | Earliest positive sample inspected |
| 10.0.28000.2336 | **Yes** | Downloaded release sample |
| 10.0.29553.1000 through 10.0.29667.1000 | **Yes in every sampled build** | Discrete Insider samples, not a claim about every intervening build |

Positive samples inspected were 28000.1, 28000.2336, 29553, 29558, 29560, 29565, 29570, 29576,
29580, 29585, 29591, 29595, 29599, 29610, 29613, 29617, 29634, 29639, 29648, 29661, and 29667;
the 295xx/296xx samples all have revision 1000. Requests for indexed 26100.8951 and 28000.2672
returned HTTP 404, so those versions are **unknown**, not negative findings.

The positive 28000.1 sample contains both `vsmdebugtype` (UTF-16 at file offset `0x4CB10`) and
`BCDE_OSLOADER_TYPE_VSM_DEBUGGER_TYPE` (`0x4CAC0`), plus the adjacent Secure Kernel network-port
type name. Its SHA-256 is
`cce14fdb38df7130e2e7d478de156af0bd4affad597682fa569d316e725dcad6`.
[Microsoft-hosted 28000.1 binary](https://msdl.microsoft.com/download/symbols/bcdedit.exe/5C64A7EC7f000/bcdedit.exe)
The 28000.2336 and 26100.8737 samples also passed local Authenticode validation. The checked
29553 and 29617 samples had Microsoft Windows signers but failed local chain construction;
their hashes matched the index and their downloads came directly from Microsoft's server.
No trust store was modified.

Microsoft identifies the 28000 family as [Windows 11 26H1](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information),
29553 as [Canary](https://blogs.windows.com/windows-insider/2026/03/20/announcing-windows-11-insider-preview-build-for-canary-channel-29553-1000/),
and 29617 as [Experimental (Future Platforms)](https://learn.microsoft.com/en-us/windows-insider/release-notes/experimental-future-platforms/preview-build-29617-1000).
Retail 26H1 is hardware-scoped and is not an ordinary in-place upgrade from 24H2/25H2; see
[Microsoft's deployment guidance](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-version-26h1).

**Conclusion:** 28000.1 is the earliest confirmed binary presence in this survey, not the exact
introduction build or a proven working Secure Kernel target. A compatible full target OS remains
to be tested for configuration, VBS, transport, breakpoint, step, and resume. Copying a newer
BCDEdit into Server 2025 would not prove that its loader and Secure Kernel implement the setting.
The workspace reports OS build 26200.9457 / 25H2 but its installed BCDEdit is also 26100.1;
changing the lab to 25H2 alone is not established as a remedy. Research scripts, downloaded
samples, source metadata, hashes, and per-sample results remain under ignored
`target/bcd-build-research/`. No live BCD, OS, or VM setting was changed during this survey.

### New Insider target and normal-kernel retry, 2026-09-18

The user created a separate Generation 2 sibling VM running Windows 11 Pro Insider Preview
**29671.1000**. After moving it from an isolated internal network to the reachable lab network,
WinRM confirmed the VM identity, build, and matching **29671.1000** versions of BCDEdit, BCD DLL,
and Secure Kernel. BCDEdit contains `vsmdebugtype`. Secure Boot is off, TPM is ready, and VBS is
**2** with memory integrity running (`[2]`). The user confirmed checkpoint
`VBS-Baseline-29671-20260918` on the outer host. BitLocker protection was off; encryption reported
85 percent and in progress. No encryption policy was changed.

Staged and hash-verified the same updated KDNET and NIC-list files in an administrator/System-only
target directory. Exported BCD before `kdnet <debugger-address> 50010 -k`. Configuration exited 0,
enabled ordinary NT debugging, and emitted port **50010**. The generated connection is stored in
a local DPAPI-encrypted credential artifact; no raw key entered the transcript. The earlier Server
VM and its separate debug ports were not changed. Restarted only the new target with native KD
listening; it connected and identified build 29671.

**Interrupted native attempt:** the primary KD process had a queued initial `-c "g"`. When a
second, named-pipe client requested a break at 20:36:12 workspace-local time, the primary ran that
initial `g` before the second client's inspection sequence. The log shows a break at
`nt!DbgBreakPointWithStatus`, then `Reading initial command 'g'`, no-current-thread warnings, and
`Non-primary client caused an implicit wait`. It does not show completion of the controls or
the planned `qd`. This establishes a debugger sequencing problem, not a negative-control pass.

The user reported that the **debugger workspace VM**, not the target, froze and required a forced
restart. Local events show service timeouts from 20:37, followed by Kernel-Power 41 at 20:41 with
bugcheck code 0. No new crash dump or resource-exhaustion event was found in the checks performed.
Those observations do not establish why the workspace froze. The PowerShell output loop used
`ReadLineAsync().Wait(1000)`, not an unbounded polling spin; DbgEng CPU usage at the incident was
not captured. Outer-host WinRM/SSH were unavailable, and an event-log RPC attempt failed despite
the endpoint mapper being reachable. Host Hyper-V/resource events therefore remain unchecked.

**User-authorized ordinary NT retry passed:** used the existing release MCP server
**0.17.0+g453ae2bc**, with one engine worker and one stdio controller, against the already-booted
target. The profile was supplied only in that supervisor's environment from the encrypted local
artifact; host address, port, and key hash were checked first. No second native client, queued
`g`, forced symbol reload, boot edit, or reboot was used. Calls were attach, registers,
`u @rip L3`, and explicit `end_session`, with bounded client waits and cleanup on failure.

Attach reported build 29671 with four processors and uptime 13 minutes 51 seconds. Registers and
disassembly identified `nt!DbgBreakPointWithStatus` at `0xfffff8067ab7be10` (`int 3`, `ret`).
`end_session` returned `target_left_running: true`; the dedicated supervisor and worker exited.
The whole retry finished in under two seconds, before its five-second CPU/memory reporting
interval. Subsequent WinRM checks showed uptime advancing from **865.7 to 867.7 seconds**,
VBS still **2**, and services running `[2]`. The workspace boot timestamp was unchanged.

The successful retry proves ordinary NT attach/read/resume/detach on the new target, not the
cause of the earlier freeze. At this point its Secure Kernel negative control, `-s` setup, and
VTL1 acceptance were still pending; the subsequent experiment follows. Logs and temporary scripts
remain under ignored `target/`; no MCP implementation was changed for this retry.

### Insider Secure Kernel configuration, 2026-09-18

**Configuration passed; VTL1 attachment remains unproven.** Before changing BCD, repeated the
ordinary NT attach through one MCP worker. `lm m securekernel` listed no matching module, and
`x securekernel!IumInvokeSecureService` returned **0x80040205**. That error stopped the first
transaction before its breakpoint step; its cleanup completed. A second transaction directly
attempted `bp0 securekernel!IumInvokeSecureService`: the expression could not resolve and became
a deferred breakpoint. `bl` showed it unresolved; the `always` block cleared it and confirmed an
empty breakpoint list. Both sessions explicitly resumed/detached successfully. Subsequent WinRM
showed the guest running with VBS status **2**.

With Secure Boot off and BitLocker protection off, exported a fresh target-side BCD backup and
ran the hash-verified **10.0.29617.1000** KDNET with `-hks`, requesting base port **50010**.
It exited **0** and emitted these separate connections (keys omitted):

| Target | Emitted UDP port |
| --- | --- |
| NT kernel | 50010 |
| Hypervisor | 50011 |
| Secure Kernel | 50012 |

The recorded BCD diff added `vsmdebugtype NET`, `hypervisordebug Yes`, the hypervisor network key,
`hypervisordebugtype NET`, the debugger host address, `hypervisorhostport 50011`,
`hypervisordebugpages 1000`, and `hypervisordhcp Yes`. It replaced the previous hypervisor Serial,
port 1, baud 115200 defaults. Ordinary NT settings were unchanged. KDNET still printed the absent
`hypervisorlaunchtype` warning, explicitly describing implicit policy as expected; that warning
did **not** prevent successful configuration on this build. Each emitted connection was stored in
a local DPAPI-encrypted artifact, separate from source control and redacted logs.

Restarted only the target. Its new boot time was **20:56:28 workspace-local time**. WinRM initially
timed out; the user reported the guest alive and Hyper-V console requesting reconnection, then
confirmed its unchanged address. WinRM subsequently returned, verifying VBS **2** and services
running `[2]`. The Secure Kernel BCD setting persisted, and the saved Secure Kernel key matched
the target's hypervisor key by hash.

Two single-worker Secure Kernel attach attempts, started after the restart was requested rather
than listening before boot, each reached the client harness's **50-second deadline** without a
completed attach. The first overlapped the WinRM-unavailable interval; the second followed the
successful health check. The workspace listener bound UDP 50012, loaded the intended bundled
DbgEng, and had an existing enabled Public-profile inbound UDP Allow rule for the release
executable. Sampled worker CPU stayed below **0.2 seconds total** per attempt, not a tight polling
loop. Guest uptime advanced from **169.4 to 268.6 seconds**, with VBS still running.

Neither attempt produced a connected-target summary, registers, or a breakpoint event. The
50-second timeout came from the harness, not an observed Hyper-V timeout. `end_session` reclaimed
the unconnected workers after its bounded grace period; that is not a successful target
resume/detach result. No evidence establishes that Hyper-V cancelled a break-in. A reconnecting
enhanced console alone cannot distinguish guest reboot or RDP disruption from a debugger stop.

A final ordinary NT control after both Secure Kernel attempts still passed attach, registers,
disassembly, and explicit resume/detach (`target_left_running: true`) in under one second.
It reported uptime **5 minutes 22 seconds**; subsequent WinRM showed **348.4 seconds** and VBS
still **2**. No listeners from these tests remained on ports 50010 through 50012. This separates
the unsuccessful Secure Kernel endpoint from an otherwise working NT debugging path.

The remaining question is transport/initialization, not BCDEdit recognition on build 29671.
The following experiment tests a native listener ready before boot. No Rust implementation,
public API, EXDI setup, or additional boot-setting workaround was added.

### Native listener before boot, 2026-09-18

Started one **10.0.29617.1000** native KD process on the emitted Secure Kernel endpoint with
`-bonc -t`, using the encrypted local connection artifact and a local symbol-cache path.
There was no debug server, secondary client, or initial `-c` execution command. One redirected
stdin controller could issue commands or native control keys, and timed asynchronous stdout
reads captured prompts without busy polling. The wrapper drained stderr separately and redacted
the key before logging. UDP 50012 was bound before requesting the target reboot.

Native output remained at `[no_debuggee]`, `Waiting to reconnect`, and a wait for a
`STATE_CHANGE64` packet. Its initial break-in send reported **Win32 error 87**, before the target
reboot. This is a pre-connection diagnostic, not evidence of a target breakpoint or its cause.
No connected-target summary or debugger prompt followed the reboot. Sampled native CPU remained
below one second total over approximately 280 seconds of listening; private memory was about
5 MiB. The target's new boot timestamp was **21:06:27 workspace-local time**.

Packet Monitor was initially idle with no filters. A header-limited capture for UDP 50010,
50011, and 50012 recorded aggregate NIC counters, but its ETL decoded to **zero packet events**.
Consequently, that file cannot establish which port received the counted boot traffic.
Stopped that capture and measured separate counters-only windows on the workspace NIC:

| Observation window | Received | Sent | Interpretation |
| --- | --- | --- | --- |
| UDP 50012 only, after boot while native KD was listening | 0 packets | 0 packets | No Secure Kernel traffic observed at this NIC in this window |
| UDP 50010 only, during a normal NT attach/read/detach control | 280 packets / 57,072 bytes | 280 packets / 43,856 bytes | Positive control for the same counter method |

These are separate observation windows, not a per-port breakdown of the unusable boot trace.
Zero received packets does not locate a drop upstream or prove the target never emitted one.
No packet-level handshake analysis is possible from the ETL captured in this run.

WinRM was temporarily unavailable after reboot. A separate NT endpoint control connected with
uptime **3 minutes 4 seconds**, read registers and disassembly, then explicitly resumed/detached.
WinRM subsequently showed uptime **209.5 seconds**, later **269.6 seconds**, and VBS **2** with
services running `[2]`. This does not prove the NT attach caused WinRM to recover. The user also
confirmed the console was back. The Secure Kernel listener remained unconnected throughout;
sent native Ctrl+B followed by Enter to end its wait, and KD exited **0** without a process kill.
The final NT counter control also resumed/detached successfully. No test listeners remained,
Packet Monitor was stopped, and only this experiment's filters were removed, restoring the
initial empty filter list.

Read-only target KDNET still reports Microsoft Hypervisor VM network-debug support. Both
Hyper-V-Hypervisor event channels were enabled but empty, so they supplied no initialization
failure. Kernel-Boot records included debug PCI-table warnings, but their timestamps included
future-dated records; they were not established as new to this experiment or causal. Do not
promote them to a diagnosis. Guest processor flags reported virtualization firmware **false**,
VM-monitor extensions **true**, and SLAT **true**. These are not a substitute for reading the VM
processor configuration on the outer host.

At the end of this run, requested the outer host's build, `ExposeVirtualizationExtensions`, and
`VirtualizationBasedSecurityOptOut` before another boot-setting change. The user subsequently
supplied those read-only results below; host management access remains unavailable from the
workspace. Guest VBS does not prove a nested hypervisor was launched. Microsoft's
[memory-integrity VM requirements](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#memory-integrity-deployment-in-virtual-machines)
separate guest VBS from nested virtualization; the original plan's universal extension-exposure
prerequisite was too strong and has been corrected. This does not yet identify the Secure Kernel
transport failure. No further BCD changes, EXDI setup, or MCP API changes were made.

Microsoft also explicitly warns that an enhanced VM console session can time out at a debugger
breakpoint and recommends disabling Enhanced session in VMConnect for debugging.
[KDNET VM setup](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-network-debugging-of-a-virtual-machine-host)
That console timeout is distinct from proof that Hyper-V cancelled a debugger break-in; this run
never observed a Secure Kernel connection or break-in to cancel.

### Outer-host checks supplied by the user, 2026-09-18

The user ran the requested commands on the outer host for the new Insider target:

| Check | Reported value |
| --- | --- |
| `Get-VMProcessor`: `ExposeVirtualizationExtensions` | **True** |
| `Get-VMSecurity`: `VirtualizationBasedSecurityOptOut` | **False** |
| `Get-ComputerInfo`: `OsVersion` | **10.0.26200** |
| `Get-ComputerInfo`: `OsBuildNumber` | **26200** |
| `Get-ComputerInfo`: `WindowsProductName` | Windows 10 Pro N |

These are user-supplied host measurements, not guest-inferred values. They rule out disabled
extension exposure and an enabled VBS opt-out for this VM. They do not prove a nested hypervisor
was actually launched or establish the native Secure Kernel transport's host compatibility.
The reported product-name string is retained verbatim; do not infer the precise marketing
version or update revision from it. The host's update revision was not included.

Microsoft's checked [WinDbg release notes](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-release-notes)
announce Secure Kernel configuration support but give no minimum outer Hyper-V host build for
this route. The earlier BCDEdit survey concerned the **target's** ability to accept a BCD setting;
it does not establish that a build-26200 **outer host** cannot forward this debug connection.
Do not recommend an outer-host upgrade as a confirmed fix on this evidence.

**Next diagnostic:** coordinate a scoped port-50012 observation on the outer host during target
startup, with an NT transport positive control. The workspace-only zero counter cannot distinguish
target/host initialization from an upstream routing or filtering issue. Host-side observations
must account for the virtual-switch path; a negative counter at an unrelated physical NIC is
not sufficient. If no Secure Kernel traffic is observed on the relevant path, investigate target
debug-transport initialization before selecting another boot-setting or OS experiment.
No VM settings, BCD, debugger session, or reboot was changed while recording these host checks.

### Coordinated outer-host capture, 2026-09-18

The user confirmed Packet Monitor was capturing on the outer host, following the supplied
procedure: UDP filters for ports 50010, 50011, and 50012, all components, 64-byte packet snapshots,
and a 32 MiB circular ETL. The user subsequently supplied the artifacts; analysis follows below.

Workspace preflight verified the target identity, VBS **2** with services `[2]`, unchanged
debugger address, and free debug ports. Started one native **10.0.29617.1000** KD listener at
**21:32:22 workspace-local time**, verified its UDP 50012 binding and the saved key against the
target by hash, then requested a normal restart of only the target. No BCD changes were made.
The same one-client `-bonc -t` procedure had no debug server or queued execution command.

The Secure Kernel session remained unconnected, including the same pre-connection Win32 error
87 on its initial break-in send. At approximately 140 seconds its sampled cumulative CPU was
**0.36 seconds** and private memory approximately **5 MiB**. Native Ctrl+B/Enter ended the wait;
KD exited **0** without forced termination.

The NT positive control at **21:34:02** reported uptime **25.535 seconds** and passed register
and disassembly reads, followed by `released: true` and `target_left_running: true`. A final
health control at **21:35:11** reported **94.555 seconds** and the same successful resume/detach.
Both supervisors and workers exited. WinRM health requests still timed out during this window;
the user confirmed the guest was already up and responsive. The advancing NT uptime supports
guest progress, but post-reboot VBS was not independently re-read during this run.

No test listener remained on ports 50010 through 50012. The user was asked to save outer-host
counters and stop capture after the primary control. The supplied ETL confirms capture stopped
before the final NT health check. Host filter cleanup still requires user confirmation.

### Outer-host capture analysis, 2026-09-18

Read the user-supplied ETL, decoded text, counter JSON, and component JSON without modifying
them. ETL SHA-256:

```text
220F0F761E6FF83A49DA534D22617A9F622190CBF6DB0182E61855FD5A2ACDC1
```

The ETL spans **21:31:11.298 through 21:35:04.386 workspace-local time**: it covers listener
startup, the target reboot, and the first successful NT control. Its header reports zero lost
events and buffers. Unlike the previous workspace ETL, it contains useful packet events:
**1,200 packet snapshots**, all decoded as IPv4 UDP on port **50010**. No captured packet uses
50011 or 50012, and no packet-drop event was recorded. The prescribed capture filters covered
all three ports; the supplied component and counter JSON files are not an independent export
of the configured filter list.

| Captured endpoint pair | Packet snapshots |
| --- | --- |
| NT target to debugger, UDP 50010 | 440 |
| Debugger to NT target, UDP 50010 | 760 |
| Either direction, UDP 50011 or 50012 | 0 |

These counts are **snapshots at instrumented components, not unique wire packets**. The counter
JSON reports larger aggregate component counts; do not equate logged snapshots with all counted
traffic or turn a zero-loss header into a guarantee of complete visibility.

The component inventory maps IDs **98**, **38**, and **212** (secondary ID **11**) to the
**Default Switch** protocol, filter, and miniport. VM NIC **215** is the debugger workspace;
**216** is the target before reboot. An ETL component-removal event at **21:33:31** names the
target's old ID **216**, and the post-reboot counter JSON maps **243** to the target. Packet
snapshots include these VM interfaces and switch components. Thus, this is not merely a capture
at a physical NIC that sibling-VM traffic might bypass. NT traffic is visible in both directions
through the relevant path, including the **21:34:02** positive control.

**Interpretation:** there is no observed Secure Kernel UDP stream arriving at these host-side
capture points to follow toward the debugger VM, and no observed drop explaining the failure.
The evidence points investigation toward target/host debug-transport initialization or forwarding
before that visible path. It does not distinguish those alternatives, prove a build-26200 host
incompatibility, or prove no packet could have been emitted outside the captured scope. Inspect
Secure Kernel debugger initialization next rather than repeating identical attaches, changing
firewall rules without drop evidence, or presenting an outer-host upgrade as a known fix.
No live debugger session, reboot, BCD change, or host configuration change was performed during
this artifact analysis. Raw captures remain machine-local, outside source control.

### Offline initialization inspection and guest feature check, 2026-09-18

WinRM became reachable again. A read-only identity check confirmed the intended Insider target;
VBS remained **2**, with security services running **[2]**. Current-loader settings still included
`vsmdebugtype NET`, `debug Yes`, and `hypervisordebug Yes`; `hypervisorlaunchtype` remained implicit.

Guest images were copied into ignored local analysis storage and verified against source SHA-256
hashes. Offline CDB inspection used `-z` on those PE files, not a live attach. The inspected images
were build **10.0.29671.1000**. Matching public Secure Kernel symbols resolved; matching hypervisor
and loader symbols did not resolve in this attempt.

- `securekernel!SkdInitSystem` calls `SkdInitDebuggerDataBlock` when its phase argument is zero,
  then returns zero. That routine does not initialize a network transport.
- `IumpReadSecureKernelDebuggerInfo` returns a three-byte zero-filled result for a sufficiently
  sized buffer, and `IumpDebugBreakRequestedByVtl0` returns zero. These individual routines do not
  establish that all Secure Kernel debugging is unsupported.
- The copied hypervisor contains a code reference to the event metadata for
  `Root VTL1 debugger init failed`. At image RVA `0x2A049B`, an initialization call is followed by
  status checking; the nonzero-status path for loop index 1 can emit this diagnostic through the
  metadata reference at RVA `0x2A04E8`. This is static control-flow evidence only, **not an observed
  failure message**, and does not show that this guest executed the copied hypervisor at boot.

The subsequent guest feature query returned:

| Check | Result |
|---|---|
| `Microsoft-Hyper-V-Hypervisor` optional feature | Disabled |
| `VirtualMachinePlatform` optional feature | Disabled |
| Hyper-V-Hypervisor Admin and Operational logs | Enabled, zero records in each |

This leaves an important setup distinction unresolved: a VBS-enabled child partition is not proof
that the guest launched its own nested hypervisor. Microsoft's
[Hyper-V debugging setup](https://www.microsoft.com/en-us/msrc/blog/2018/12/first-steps-in-hyper-v-research)
explicitly enables Hyper-V inside the guest whose hypervisor is being debugged. That older guide
does not establish the requirements of the new Secure Kernel `-s` route, but supplies a concrete
next experiment: enable Hyper-V in the target, verify its launch after reboot, and retest the
configured debug endpoints with a single controller. Extension exposure is already enabled.
This would leave the target as a sibling of the workspace and create no additional Windows VM.

**Decision at this point:** obtain approval for that target feature/boot change before applying it.
Feature state and empty logs alone are not conclusive proof of the current runtime topology or
the reason for missing Secure Kernel traffic. No BCD setting, optional feature, firewall rule,
or VM configuration was changed, and no reboot or live debugger attach occurred in this follow-up.
The native route remains inconclusive; no MCP API changes are justified yet.

### Approved target hypervisor enablement and retry, 2026-09-18

The user approved enabling Hyper-V inside the existing Insider target, rebooting it, verifying
launch, and retrying. No new VM was created, and the workspace and outer host were not reconfigured.

After checking target identity, current debugger destination and unoccupied listener ports:

1. Exported the target BCD to its protected lab directory as
   `before-enable-hyperv-20260918-215921.bcd`.
2. Ran `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor -All -NoRestart`.
   The feature subsequently reported **Enabled**. Set `{current}` `hypervisorlaunchtype Auto`;
   `vsmdebugtype NET`, `debug Yes`, and `hypervisordebug Yes` remained configured.
3. Compared the saved NT and hypervisor/Secure Kernel connection keys with the target by hash;
   all matched. An initial hypervisor comparison used the wrong field name and was corrected to
   the actual `hypervisorusekey` field before reboot. No keys were printed or regenerated.
4. Started one native Secure Kernel listener before scheduling the target restart. That listener
   remained unconnected for approximately 130 seconds and exited normally via Ctrl+B.
5. Started a single listener on the distinct hypervisor endpoint. This time the transport
   synchronized with the target. A break request reached an `hv+0x404a60` breakpoint, and `r;lm`
   returned registers and the hypervisor image. Matching hypervisor symbols were not loaded.
   `.time` reported uptime unavailable for that target. `qd` received a successful continue
   acknowledgement and the debugger exited 0.
6. Retried the Secure Kernel endpoint after hypervisor detach. It remained unconnected for
   approximately 60 seconds and exited normally via Ctrl+B. These listeners ran sequentially,
   never as two controllers of one target session.
7. Repeated the NT positive control through MCP: attach, registers, three-instruction disassembly,
   and `end_session` all passed. Teardown reported `released=true` and `target_left_running=true`.

Post-reboot guest verification provided independent runtime evidence:

| Check | Result |
|---|---|
| Hyper-V-Hypervisor System event 1 | `Hypervisor successfully started.` |
| Hypervisor feature / launch policy | Enabled / Auto |
| VBS / services running | 2 / [2] |
| Guest boot time | 2026-09-18 21:01:53 UTC |
| Guest uptime after hypervisor detach | 161.042 seconds |
| NT debugger uptime at positive control | 197.269 seconds |
| Final guest uptime | 220.807 seconds, same boot |
| Remaining test listeners | None on the three configured ports |

The setup change establishes a working nested-hypervisor debugger on this host/guest pairing.
Both feature enablement and explicit launch policy changed, so this experiment does not isolate
which was sufficient. It also does **not** establish a working Secure Kernel endpoint or explain
its remaining failure. The guest is responsive with VBS/HVCI running; no forced reset was used.

The next investigation can use the now-working hypervisor debugger to inspect Secure Kernel
debugger initialization state, with brief, read-only stops and explicit resume/detach. Do not
equate the hypervisor breakpoint with the plan's required breakpoint inside `securekernel.exe`.
The Phase 3 VTL1 gate remains unpassed and no MCP API was changed. Redacted debugger logs remain
under ignored local `target/` storage.

### Read-only live hypervisor initialization state, 2026-09-18

The user approved brief read-only inspection through the working hypervisor debugger, without
another boot change or reboot. Two sequential native sessions read the identified fields and
each ended with `qd`, a successful continue acknowledgement, and exit 0. Before attachment, the
target identity, debugger destination, private key hash agreement, and on-disk hypervisor hash
were verified. No target-memory patches or diagnostic breakpoints were installed.

The loaded `hvix64.exe` matched the copied image by reproducible-build stamp **BBE1CC9D**,
checksum **00275799**, image size **00619000**, and its live CodeView record:
PDB GUID **91E90DB1-A7E8-488B-2FE2-4212838EC6F0**, age **1**. Matching hypervisor symbols remained
unavailable; field interpretations below come from that exact image's disassembly, not public
type definitions. Offsets are build-specific and are not a supported debugger interface.

| Read | Observed value | Interpretation from inspected code |
|---|---|---|
| Image RVA `0x7C040` / `0x7C044` | 1 / 3 | Enabled flag / transport selector used by initialization |
| Image RVA `0x7C0A8` | 7 | Transport flags; initialization's bit-0 condition is satisfied |
| Words at image RVA `0x7C0AC` | `C35B C35A C35C` | Configured hypervisor, VTL0 and VTL1 ports match the saved endpoints |
| Root partition context array at `+0x68C8` | Three non-null pointers | Contexts were allocated |
| VTL0 context `+0x12` | `C35A` | Expected active NT port |
| VTL1 context `+0x12` | `FFFF` | Inactive/uninitialized port sentinel |
| VTL1 context `+0x2960` | 1 | Matches context index 1 |
| VTL1 context `+0x18` | `C35C` | Internal port-tree node key contains the expected Secure Kernel port |
| VTL1 context `+0x28E0` / `+0x28E4` | 0 / `FFFFFFFF` | Same values written by context initialization; not a captured error code |

The pointer chain was derived offline: image RVA `0xAA5B8` points to the root VTL0 context;
context `+0x2958` points back to its partition; partition `+0x68D0` selects context 1.
Only debugger pseudo-registers were assigned while following this chain.

At image RVA `0x29C858`, the port activation routine attempts tree registration and buffer
allocation before assigning the active port at context `+0x12` (instruction RVA `0x29C957`).
The helper at RVA `0x3EBB0C` writes the node key at `+0x18` before trying insertion. Thus seeing
`C35C` there does not prove insertion succeeded. The activation routine can return **5** on
registration failure; the buffer helper at RVA `0x29EAA4` can return **0x1D** when its free-page
list is exhausted. These are inspected failure paths, **not observed return values**. The reads
do not establish buffer exhaustion, a duplicate port, or that the embedded failure event fired.

**Result:** the Secure Kernel configuration reached the live hypervisor, but its root VTL1 debug
context was not active at inspection time. This is stronger evidence than the earlier absence
of packets, while still insufficient to name the specific initialization failure or a fix.
Do not change `hypervisordebugpages` speculatively. A separate early-boot tracing experiment would
be needed to capture the activation return directly; no such reboot or breakpoint was attempted.

Guest uptime advanced from **636.483** seconds before attachment to **698.303** after the first
session and **763.996** after the second. WinRM responded and VBS remained **2**. The native
inspection logs remain in ignored `target/` storage. No MCP API or runtime code was changed.

### Early-boot activation return captured, 2026-09-18

The user approved the early-boot trace and target reboot. A single native hypervisor controller
was attached before a normal guest restart; initial-break handling was enabled with `sxe ibp`.
No BCD setting changed. On reconnect, the root debugger-context pointer at image RVA `0xAA5B8`
was still null, establishing that this stop preceded the initialization under investigation.
The loaded image stamp, checksum and size still matched the offline image; the call and return
instructions at RVAs `0x2A049B` and `0x2A04A0` were verified live.

One temporary breakpoint at `hv+0x2A04A0` stopped immediately after the activation call:

| Stop | Loop index (`BL`) | Activation return (`AX`) |
|---|---|---|
| Root VTL0 | 0 | 0 |
| Root VTL1 | 1 | `0x1D` |

At the VTL1 stop, its active port was still `0xFFFF`, and both buffer descriptors' size/count
fields had been cleared. **The error is now a directly observed return**, not a conclusion from
an embedded message. In the matching activation routine, `0x1D` is propagated from its buffer
allocator; that allocator returns it when the debug free-page list is exhausted. Cleanup returns
pages to that list, so the observed non-null list head after the call does not contradict the
allocation failure. The trace does not determine which of the two buffer allocations failed or
the minimum sufficient reservation.

Removed breakpoint 0, verified an empty breakpoint list, and used `qd`; continue was acknowledged
successfully and native KD exited 0. The subsequent MCP NT control passed attach, registers,
disassembly and explicit resume/detach at **55.789 seconds** uptime. WinRM checks immediately
afterward timed out, so post-trace VBS and desktop health were not yet reverified at that point.
Another NT control passed at **139.818 seconds** uptime, establishing continued guest execution
across the detach interval; it too explicitly resumed/detached successfully.
No listener remained on any of the three configured debugger ports.

**Next experiment:** back up BCD, increase the existing `hypervisordebugpages` reservation, reboot,
then verify the VTL1 activation return and Secure Kernel attachment. This is a targeted hypothesis,
not yet a demonstrated fix. The setting still displayed **1000** before this trace and was not
changed. Do not substitute an outer-host upgrade, firewall change, or additional VM RAM for the
specific debug-pool reservation without further evidence. Raw debugger logs remain local and
ignored; no MCP code changed.

### Increased debug-page reservation, 2026-09-18

The user confirmed all machines were responsive and approved the reservation experiment.
WinRM identity matched the target VM. Exported BCD to the protected target lab folder as
`before-debugpages-2000-20260918-222916.bcd`, then changed only:

```powershell
bcdedit /set '{hypervisorsettings}' hypervisordebugpages 2000
```

The previous displayed value was **1000**. Comparing hypervisor settings before and after,
with this one line normalized, found no other change; keys were not printed. No VM RAM,
outer-host configuration, debug endpoint, or workspace boot setting changed. Started one
native Secure Kernel listener before a normal target reboot. WinRM later reported boot time
**22:30:42 local**, VBS **2**, and running security services **[2]**. The reservation displayed
**2000**, and `vsmdebugtype NET`, `debug Yes`, `hypervisordebug Yes`, and
`hypervisorlaunchtype Auto` persisted.

That listener remained unconnected and exited 0 after about 200 seconds. A separate native
hypervisor session then connected and read the same root VTL1 context fields as before:

| Field | At reservation 1000 | At reservation 2000 |
|---|---|---|
| Active port, context `+0x12` | `0xFFFF` | `0xC35C` (50012) |
| First buffer size/count, `+0x60` | 0 / 0 | `0x1000` / 2 |
| Second buffer size/count, `+0x1488` | 0 / 0 | `0x1000` / `0xA0` (160) |

The matching activation routine assigns the active port only after both allocation calls
succeed. These post-boot fields establish that the previously failing allocations completed;
this experiment did not directly recapture the activation return. Native hypervisor `qd`
received a successful continue acknowledgement and the client exited 0.

A fresh Secure Kernel listener still remained unconnected for about 60 seconds, including
an explicit break request, and exited 0. **The allocation failure is resolved, but Secure
Kernel attachment is not.** The increased reservation is retained, with the BCD backup available.
The next diagnostic boundary is Secure Kernel-side debugger startup/transport beyond the
initialized hypervisor port, not another unsupported increase in reservation or VM RAM.

The subsequent MCP NT control passed attach, register reads, disassembly, and explicit
resume/detach at **268.268 seconds** uptime, reporting `target_left_running: true` and exiting 0.
WinRM subsequently reported **324.369 seconds** uptime, VBS **2**, and running services **[2]**,
confirming continued execution after detach. No temporary breakpoint was installed during this
experiment. Local ignored logs:

- `29671-native-boot-50012-20260918-222938.log`: pre-boot listener.
- `29671-native-boot-50011-20260918-223321.log`: initialized VTL1 buffers and active port.
- `29671-native-boot-50012-20260918-223405.log`: post-boot retry.
- `29671-single-controller-20260918-223509.log`: passing NT control.

No Rust implementation or MCP API changed; the plan's live Secure Kernel acceptance gate
remains open.

### VTL-specific session-path trace, 2026-09-19

The user requested continued tracing. Before attaching, WinRM confirmed the target VM identity,
build **29671**, VBS **2**, running services **[2]**, and the previous boot time. The debugger
host address still matched the target configuration, and `hypervisordebugpages` remained **2000**.
No lab UDP listener was already present.

A read-only native hypervisor session compared the root VTL0 and VTL1 debug contexts. Both
had initialized active ports and context/list flags `01 01` at `+0x10`. The byte at `+0x2970`
was **1 for VTL0** and **0 for VTL1**. In the matching offline image, the routine beginning at
RVA `0x2DFFF4` resets transport buffers, selects a context using the caller's VTL, and writes
that byte according to request flag `0x8` at RVAs `0x2E00EE`/`0x2E00F9`. This is a session
configuration flag, not proof of a connected debugger. The read-only session used `qd` and
exited 0.

For the boot trace, one native hypervisor controller remained attached across one normal
target restart. No BCD, VM memory, outer-host, firewall, or workspace boot configuration changed.
At the initial hypervisor break, the root context pointer was still null. The loaded image's
stamp **BBE1CC9D**, checksum **00275799**, and size **00619000** matched the offline image,
and the instructions at the selected trace point were verified live.

Breakpoint 0 at `hv+0x2E00A8` stopped after the handler's initial guards, immediately before
it reads the VTL byte and selects its debug context. The first stop showed VTL **0** and
request flags **0xF**. A one-shot breakpoint at the return epilogue, `hv+0x2E0125`, captured
**AX = 0** and **EDI = 0**; the VTL0 context's `+0x2970` byte was then **1**.

The trace subsequently counted VTL0 stops in debugger pseudo-register `$t0`, starting at 1
for the first observed call, and automatically continued them. A nonzero-VTL stop would
increment `$t1` and remain stopped for inspection. At the final manual break:

| Measurement | Result |
|---|---|
| Calls reaching the trace point with VTL 0 | 2 |
| Calls reaching it with nonzero VTL | 0 |
| VTL0 context byte `+0x2970` | 1 |
| VTL1 context byte `+0x2970` | 0 |
| VTL1 active port | `0xC35C` (50012) |

**Scope of the result:** no VTL1 call reached this particular post-guard point during the
bounded boot trace. This does not rule out a request rejected by earlier guards, a different
debugger path, or a later request. The flag difference and trace narrow the next inspection
to earlier handler checks and the guest/loader decision to initiate VTL1 debugging. They do
not establish that this Windows build lacks Secure Kernel debugging support. No Secure Kernel
listener was active during this hypervisor-only trace; it is not another attachment test.

Removed breakpoint 0 and verified the empty list; the return breakpoint was one-shot and
already removed. `qd` received a successful continue acknowledgement and native KD exited 0.
Two subsequent MCP NT controls passed attach, register reads, disassembly and explicit
resume/detach, with uptime advancing from **103.580** to **178.605 seconds**. Both reported
`target_left_running: true` and exited 0. Initial WinRM checks after reboot timed out. The user
then confirmed a responsive desktop/sign-in console; a subsequent WinRM check verified the
target identity, **245.087 seconds** uptime, VBS **2**, and running services **[2]**. No listener
remained on the three lab debugger ports. No Rust or MCP API change was made.

Local ignored evidence under `target/`:

- `29671-native-boot-50011-20260919-071803.log`: read-only context comparison.
- `29671-native-boot-50011-20260919-071956.log`: boot trace and breakpoint cleanup.
- `29671-single-controller-20260919-072257.log` and
  `29671-single-controller-20260919-072410.log`: passing NT controls.
- `sk-29671-static/sk-transport-20260919.log`, `sk-shvl-init-20260919.log`, and
  `sk-disasm.txt` in that directory: offline Secure Kernel symbol/disassembly inspection.

### Loader debugger-configuration gates, 2026-09-19

Continued upstream inspection offline, using the target's copied **29671.1000** images.
BCDEdit's element table associates `vsmdebugtype` with **0x2500013A** and the internal name
`BCDE_OSLOADER_TYPE_VSM_DEBUGGER_TYPE`. The matching loader reads that numeric element;
this is a code-path observation, not an inferred setting from a diagnostic message.

The routine at `winload+0x28860` checks Secure Boot state using the helper at `+0x277800`
(which reads the `SetupMode` and `SecureBoot` firmware variables). If Secure Boot is active,
it additionally requires a successful, true read of boolean element `0x260000A0`. It then
reads `0x2500013A`, returning the configured integer or `0xFFFFFFFF` on the disabled/error
path. The current target's Secure Boot state is **False**; this static branch alone does
not identify the runtime failure.

The loader subsequently builds the Secure Kernel debugger descriptor. It initializes the
loader-block DWORD at `+0x740` to `0xFFFFFFFF`, accepts serial type 0 or NET type 3, and
only stores NET type 3 after the later configuration steps succeed. Missing required
configuration or a failing descriptor-setup call can leave that field disabled while
execution continues past this block. Therefore, successful BCD configuration and an
active hypervisor-side VTL1 port do not prove that the loader enabled the SK debugger.

Candidate live trace points, **specific to the inspected loader image**:

| Loader RVA | Measurement |
|---|---|
| `0x2B508` | EAX returned by the debug-type gate |
| `0x2B5CB` / `0x2B5E6` | Explicit-port / fallback-port lookup status |
| `0x2B609` | Key lookup status only; do not print the key or its buffer |
| `0x2B6C1` | EAX returned by descriptor setup at `+0x28718` |
| `0x2B71E` | Final debugger-type DWORD at `poi(winload+0x3A2AB8)+0x740` |

The port WORD is at loader-block `+0x738`. Any live inspection must verify the loaded image
identity and instructions first, and read only the selected fields: the nearby descriptor
contains the debug key. The loader SHA-256 is
`B24C5B501077621524530A8C4DB719655D7A21108B5245F3A5BC83F367FDCC8C`.

Matching Secure Kernel symbols show `SkInitBootProcessor` calling `SkdInitSystem(0)` at
RVA `0xA680E`. That function only calls `SkdInitDebuggerDataBlock` for phase zero and
returns zero; it does not itself initialize a transport. This remains a separate lead,
not proof that no other debugger path exists. `SkScrubLoaderBlock` explicitly zeroes
`0x920` bytes of the loader block, so a zero read after cleanup cannot reconstruct the
debugger type originally handed over at boot.

**Proposed at the end of this offline inspection:** temporarily enable boot-loader debugging
for the target's current OS entry and capture these decisions during one normal reboot.
Microsoft documents [BCDEdit /bootdebug](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--bootdebug)
separately from ordinary kernel debugging; it uses the configured debugger connection.
Before the experiment, preserve the original element state and export BCD to the protected
target lab directory. Use one controller, verify the loader before setting temporary
breakpoints, remove those breakpoints before leaving the loader, resume/detach explicitly,
and restore the original boot-debug element state afterward. Do not enable boot-manager
debugging, alter keys, or change workspace/outer-host configuration. Boot may pause at
the debugger until continued; retain the existing console/checkpoint recovery path.

The final read-only preflight found no explicit `bootdebug` line in `{current}`. WinRM
verified the target identity, uptime **1006.203 seconds**, VBS **2**, running services
**[2]**, and Secure Boot **False**. C: was **FullyEncrypted** with BitLocker protection
**Off**; no protector or encryption setting changed. No native KD/CDB process or listener
on the three lab debugger ports remained. No reboot, BCD change, or Rust/MCP API change
was made during this inspection.

Ignored local evidence under `target/sk-29671-static/`:

- `bcdedit.exe` and `inspect-bcd-element.ps1`: element-table inspection.
- `loader-disasm.txt` and `loader-gates-20260919.log`: loader control flow and trace points.
- `sk-loader-lifetime-20260919.log`: SK initialization call and loader-block cleanup.

### Boot-loader connection experiment, 2026-09-19

With user approval, enabled `bootdebug` on the target's current OS entry for **one normal
reboot**. Preflight verified the target identity, unchanged loader SHA-256, Secure Boot off,
BitLocker protection off, the debugger host address, and the NT connection key by hash.
The original entry had no explicit `bootdebug` element. Exported BCD and saved the original
entry in the existing protected target lab directory before enabling it. No boot-manager,
workspace, outer-host, debugger-key, or port setting changed.

One native KD controller attached to the existing NT endpoint. Before reboot it enabled
`sxe ibp` and resumed. The transport log then recorded:

- `BD: Boot Debugger Initialized` and a connection to **Windows Boot Debugger 29671**.
- A `winload.efi` module-load state-change event (`0x3031`), with primary image base
  `0x0107F000` in this boot.
- A successful debugger continue, subsequent loader module/file activity, and transition
  to NT. There was **no interactive loader stop** at which to install the planned trace
  breakpoints. No loader trace breakpoint was installed and none of the proposed return
  values or the final SK debugger-type field was captured.

Thus boot-loader KDNET **connectivity** is demonstrated, but the SK configuration gate
remains unmeasured. The initial-break filter used here was insufficient for this observed
loader transition. The next proposed retry should additionally arm and verify an explicit
loader module-load break, such as `sxe ld:winload*`, before restarting. Microsoft documents
[`ld[:Module]` separately from initial-break events](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/controlling-exceptions-and-events).
That revised filter has not yet been tested here; no second reboot was performed.

Continued the early NT stop, then explicitly detached with `qd` at **59.081 seconds**
uptime. `bl` was empty; native KD received a successful continue acknowledgement and
exited 0. A subsequent single-controller MCP NT control passed attach, register reads,
disassembly, and explicit resume/detach at **101.137 seconds** uptime, reporting
`target_left_running: true` and exiting 0.

The first two WinRM restoration attempts timed out during guest startup. The next succeeded:
removed the temporary `bootdebug` element, verified its absence, and compared the current
entry's enumeration to the saved original with **no differences**. Final WinRM health
reported uptime **174.684 seconds**, VBS **2**, and running services **[2]**. No native
KD/CDB process or listener on the three lab debugger ports remained. No forced reset,
additional reboot, or Rust/MCP API change occurred.

Machine-local evidence:

- Protected target backup: `before-bootdebug-20260919-074314.bcd` in the existing lab directory.
- Protected original-state record: `loader-trace-original-20260919.clixml`; retain it with
  the backup, and do not print or commit its BCD contents.
- Ignored `target/29671-loader-setup.ps1`: identity-checked preparation and restoration.
  It deliberately refuses another preparation when the original-state record exists;
  a future trial needs a fresh record, not an overwrite of this one.
- Ignored `target/29671-native-boot-50010-20260919-074340.log`: native connection,
  loader auto-continue, NT stops and detach.
- Ignored `target/29671-single-controller-20260919-074724.log`: passing NT control.

### Live loader configuration trace, 2026-09-19

The user approved one retry with a loader module-load break. Created a fresh protected
BCD backup and original-state record, checked the target identity and loader SHA-256,
verified the existing NT connection key by hash, and enabled only current-entry
`bootdebug`. One native controller owned the NT/loader endpoint throughout the trace.

Armed `sxe ibp`, `sxe ld:winload*`, and `sxe iml`, verifying the filters with `sx`.
Enabling initial-module-load breaks first stopped the existing NT session; a WinRM restart
attempt timed out without connecting. After continuing that stop, the normal target
restart was successfully scheduled. Only one restart was scheduled in this retry.

The debugger stopped on the `winload.efi` module-load event. Live image identity matched
the inspected loader: stamp **0B4F4B09**, checksum **0038DCCD**, size **003C0000**, version
**10.0.29671.1000**. Verified the instructions around all three selected trace points
before installing breakpoints. This combination of event filters caught the loader;
the test does not isolate whether `ld` or `iml` alone would have sufficed.

After returning module-load events to notify and initial-module-load events to ignore,
installed three one-shot breakpoints:

| Measurement | Trace point | Observed value |
|---|---|---|
| Debug-type gate return | `winload+0x2B508` | EAX **3** (NET) |
| NET descriptor setup return | `winload+0x2B6C1` | EAX **0** (success) |
| Final debugger-type field at this stage | `winload+0x2B71E`, loader block `+0x740` | **3** |
| Configured SK port | Same stop, loader block `+0x738` | **0xC35C** (50012) |
| Adjacent loader flags, raw observation only | Same stop, loader block `+0x744` | **0x21E** |

The first two breakpoint commands recorded only EAX and continued; the third stopped
for the selected field reads. No key buffer was printed. All three one-shot breakpoints
had been consumed, and `bl` was empty before continuing out of the loader.

**Result:** the suspected failure in this loader configuration block did not occur in
the traced boot. NET was selected, descriptor setup succeeded, and the block ended with
debugger type 3 and the expected SK port. This is not proof that those fields remained
unchanged through every later boot stage, nor that Secure Kernel initialized or connected
its debugger. No SK listener was active during this single-controller loader trace.
The next investigation is downstream consumption/initialization and the earlier
hypervisor session-handler guards, not another change to these working BCD settings.

Protected target evidence in the existing lab directory:

- `before-bootdebug-20260919-102117.bcd`.
- `loader-trace-original-20260919-02.clixml` (contains BCD data; do not print or commit).

Ignored native trace: `target/29671-native-boot-50010-20260919-102129.log`.

Continued the early NT startup stop, then used `qd` at **56.538 seconds** uptime. The
native debugger acknowledged the continue and exited 0, with an empty breakpoint list.
The subsequent MCP NT control passed attach, register reads, disassembly and explicit
resume/detach at **95.593 seconds** uptime, reporting `target_left_running: true` and
exiting 0. Its ignored log is `target/29671-single-controller-20260919-102643.log`.

Three WinRM restoration attempts timed out during startup. After a TCP check found the
WinRM endpoint reachable, restoration succeeded: the temporary `bootdebug` element was
removed, and the current BCD entry matched its saved original exactly. Final WinRM health
reported uptime **184.792 seconds**, VBS **2**, running services **[2]**, and no explicit
`bootdebug` element. The workspace had **zero** lab-port listeners and **zero** native
KD/CDB processes. No additional reboot, forced reset, Rust change, or MCP API change was
made during the retry.

### Downstream debugger implementation inspection, 2026-09-19

Continued with offline inspection of the target's copied SK and NT images and matching
symbols, plus a read-only user-mode system-information query over WinRM. No debugger
attached to the guest, no break request was issued, and no reboot or BCD change occurred.
The guest's SK SHA-256 was reconfirmed as
`F6112AEEA8D5306D401D9D8779A40BD67667CD67A323C3BF1E27BFA59086AAEA`.
VBS remained **2**, running services **[2]**, and `bootdebug` remained absent.

The exact SK image contains these implementations (addresses are image-relative):

| Routine | RVA | Observed implementation |
|---|---|---|
| `SkdInitSystem` | `0xA387C` | Phase zero initializes debugger metadata; returns zero |
| `SkdInitDebuggerDataBlock` | `0xA363C` | Writes metadata, lists and offsets; no calls or transport initialization in its inspected body |
| `IumpReadSecureKernelDebuggerInfo` | `0x2C464` | Constructs three constant zero bytes, reports length 3, then copies them to a sufficiently large caller buffer |
| `IumpDebugBreakRequestedByVtl0` | `0x2ED60` | Only `xor eax,eax; ret` |

The status routine does not read runtime debugger flags or loader configuration. Its
user/kernel copy branches do not change those three bytes. `SkInitBootProcessor` calls
`SkdInitSystem(0)` and ignores its return. Inspection of startup and exception dispatch
did not identify a SK KDNET transport initialization or packet-processing loop; that
negative search is not proof that no alternative path exists. Debug metadata, debug
service traps and trustlet exception forwarding are not themselves proof of SK KDNET.

For an independent runtime check, queried class **149** as the NT control and class
**237** as `SystemSecureKernelDebuggerInformation`, using the class identifiers in the
[PHNT header](https://github.com/winsiderss/phnt/blob/master/ntexapi.h).
These are undocumented interfaces, not a Microsoft-supported capability contract.
Each probe supplied a three-byte output buffer and read it only on success:

| Query | NTSTATUS | Returned length | Output bytes |
|---|---|---|---|
| `NtQuerySystemInformation(149)` | `0x00000000` | 3 | `[1, 1, 1]` |
| `NtQuerySystemInformation(237)` | `0xC00000BB` (`STATUS_NOT_SUPPORTED`) | 0 | Not read |
| `NtQuerySystemInformationEx(237)`, null/zero-length input | `0xC000000D` (`STATUS_INVALID_PARAMETER`) | 0 | Not read |

Resolved the NT image's switch tables for class `0xED` rather than relying on incomplete
automatic function disassembly. The ordinary query reaches `ExpQuerySystemInformation`
and dispatches directly to NT RVA **0x9BAD96**, which sets `STATUS_NOT_SUPPORTED` and
branches to cleanup. It does **not** call SK to obtain debugger state. The extended
query rejects missing input before class-specific handling, at NT RVA **0x9B6F1D**;
that invalid probe form says nothing about a correctly formed extended query. Neither
failed probe establishes live SK debugger flags. The NT control bytes also do not
establish that a controller is currently attached.

**Interpretation:** together with successful loader configuration and the initialized
hypervisor VTL1 buffers, the constant-output/no-op SK routines strengthen an
**implementation-stub hypothesis for this exact SK image**. They do not establish a
minimum supported Windows build or exclude every alternative debugger path. No additional
BCD adjustment or forced break follows from these results. The next useful comparison
is these routines in a known-working SK KDNET image, or an offline build survey before
selecting another target. A bounded trace at the earlier hypervisor session-handler
guards remains possible, but would not supply missing code in these inspected routines.
Native VTL1 attachment and the MCP integration acceptance criteria remain unmet.

Ignored local evidence:

- `target/29671-query-sk-debug-status.ps1`: identity-checked read-only query helper.
- `target/sk-29671-static/sk-downstream-20260919.log`: startup and metadata initialization.
- `target/sk-29671-static/sk-debug-status-20260919.log`: complete status and break routines.
  Its separate raw disassembly beginning at `0x82C60` was not instruction-aligned and is
  not evidence for exception control flow.
- `target/sk-29671-static/sk-debug-dispatch-20260919.log`: instruction-aligned function
  disassembly of exception dispatch and boot-processor initialization.
- `target/sk-29671-static/nt-query-dispatch-20260919.log` and
  `nt-exp-query-20260919.log`: NT query entry points and common dispatch.
- `target/sk-29671-static/nt-sk-query-handlers-20260919.log` and
  `nt-sk-query-return-20260919.log`: explicitly resolved class-237 handlers and cleanup.

### Offline build comparison and native-route gate, 2026-09-19

Compared five additional x64 SK images with the inspected 29671 target. Copied the local
26100 image and acquired the others from Microsoft's public symbol server, using the
[Winbindex release and Insider indexes](https://github.com/m417z/winbindex) for discovery.
Accepted comparison images matched the indexed SHA-256 and used matching Microsoft PDBs.
All were opened as offline image data, not launched or installed. Neither VM was queried,
attached, reconfigured or rebooted during this pass.

The three routines have the same behavior in all six rows below: phase-zero initialization
calls `SkdInitDebuggerDataBlock` and returns zero; the information routine constructs three
constant zero bytes; the VTL0-requested break routine is `xor eax,eax; ret`. RVAs identify
the exact inspected entry points, not portable breakpoint addresses.

| SK file version | `SkdInitSystem` RVA | Information routine RVA | Break-request routine RVA |
|---|---|---|---|
| 10.0.26100.9457 | `0xAC3BC` | `0x25BE4` | `0x27CDC` |
| 10.0.28000.2952 | `0xB2BB4` | `0x2939C` | `0x2BA6C` |
| 10.0.29617.1000 | `0xB6720` | `0x41108` | `0x439EC` |
| 10.0.29639.1000 | `0xB8C00` | `0x3FF44` | `0x42840` |
| 10.0.29648.1000 | `0xA3A54` | `0x2D194` | `0x2FA90` |
| 10.0.29671.1000, prior target inspection | `0xA387C` | `0x2C464` | `0x2ED60` |

This includes samples on both sides of the indexed image-size reduction between 29639
and 29648; these debugger routines did not change from implemented to stubbed across
that sampled boundary. The survey does not inspect every intervening build or every
alternative debugger path.

An additional hash-verified **10.0.19041.207** sample loaded matching symbols, but those
symbols did not expose the three comparison names. It is **unclassified** by this test,
not evidence of either working or absent native debugging. Its `SkdpStub` contains
exception-handling logic: the name alone does not make it equivalent to the later
two-instruction break-request routine.

The symbol server returned bytes different from the requested index record for
19041.7725, 22621.7582, 22621.317 and 29667.1000. The helper rejected each SHA-256 mismatch;
none contributes a row above. The first three also had different embedded versions
(19041.7722, 22621.7581 and 22621.675 respectively). Retained their original download
filenames as acquisition evidence, but do not treat those names as image identities.

Accepted new comparison hashes:

```text
26100.9457 A9CDE82E39794FB2910BD53A7DDA3DF750C443222F898C49092D5E51F8B2095E
28000.2952 BA493451314B11A139088BE95AC6B8A1413560958618B1ACBB279922526D4969
29617.1000 BB29E5EFCFEE50FD82975FCA45535B2C6A01D430F5A86B4F235DB33848B951AA
29639.1000 28FAEB48277EE5F85D97300B5B992C9482AD2EFB3AFA8BA885EA0551E9A301EE
29648.1000 77DA0F3187B736554070DCB812A6AEB94BEFDDA48818BFE471CAFF3BD5DE390D
```

**Gate decision:** native SK attachment remains unproven, and this bounded survey found
no better image candidate. End the current native-route investigation as **inconclusive
for support, unsuccessful for attachment** and assess Phase 4 prerequisites before any
more native boot experiments. Reopen native testing when there is a known-working image,
a documented target-build requirement, or another concrete implementation lead. The
[WinDbg release note](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-release-notes#12606220010)
announces configuration-tool support; it does not identify a working target build.

Re-read the [LiveCloudKd maintainer's EXDI procedure](https://github.com/gerhart01/LiveCloudKd/blob/master/ExdiKdSample/LiveDebugging.md).
That route requires setup on the outer Hyper-V host, not this sibling workspace. Its
fixed-memory and non-nested-target recipe conflicts with parts of the present target
configuration. Host scheduler requirements must also be checked before proposing changes.
Compatibility with this exact host/guest combination remains unverified. No checkpoint
was restored, host component installed, scheduler changed, security setting disabled,
or EXDI attachment attempted. Host-side changes need separate approval because the outer host
also runs the workspace; a host reboot would interrupt it.

The immediate external dependency at this stage was a read-only outer-host preflight: current Hyper-V scheduler
event (provider `Microsoft-Windows-Hyper-V-Hypervisor`, ID 2), target processor count and
extension exposure, and target dynamic-memory configuration. Do not reset the target or
restore its checkpoint merely to collect those values. Native lab settings and evidence
remain intact, and all offline CDB processes exited. MCP changes remain deferred until
a native or EXDI VTL1 control actually passes.

Ignored evidence is in `target/sk-build-survey-20260919/`: compressed index snapshots,
`fetch-samples.ps1`, `audit-samples.ps1`, image copies, matching symbol cache,
`*-resolved.log` function disassembly, `*-metadata.log` initialization bodies, and the
separate 19041 symbol/stub logs. The initial 26100 log lacked a usable symbol-store path;
use `26100.9457-resolved.log`, not that failed first attempt.

### EXDI host preflight and topology decision, 2026-09-19

The user supplied the requested read-only outer-host measurements:

| Item | Observed value |
|---|---|
| Latest returned Hyper-V scheduler event | 2026-09-14 20:54:19, scheduler `0x4` |
| Target virtual processors | 4 |
| Target `ExposeVirtualizationExtensions` | True |
| Target `DynamicMemoryEnabled` | True |
| Target startup / minimum / maximum memory | 4 / 2 / 4 GiB |

Microsoft maps scheduler **4** to **Root**. Its current documentation also states that
Root is the only supported scheduler configuration on Windows client systems and that
scheduler changes require a host restart. This is a host-wide setting, not a per-target
adjustment. See [Microsoft's scheduler guidance](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-scheduler-types).

The [LiveCloudKd maintainer's recipe](https://github.com/gerhart01/LiveCloudKd/blob/master/ExdiKdSample/LiveDebugging.md)
instead calls for Classic on Windows 11 (event value 1 or 2), fixed guest memory and no
exposed nested virtualization on the target. One vCPU is preferred for initial testing;
the procedure describes experimental multi-CPU debugging, so four vCPUs alone are not
proof of incompatibility. These recipe differences are an EXDI setup finding, not a new
explanation for the earlier native-KDNET failure.

**Decision required before setup:** do not silently change the shared client host to
an unsupported scheduler configuration. Prefer an isolated Windows Server Hyper-V lab,
either on a separate host or in a new nested lab VM if the user elects to revisit nesting
and confirms capacity. That alternative has not been provisioned or validated. Direct
use of the existing outer client host would require explicit acceptance of the scheduler
support limitation, host-wide scheduling impact, a coordinated reboot affecting the
workspace, and separately reviewed host debugger installation. Neither route is approved
by the supplied read-only output. No VM was stopped, checkpoint restored, host setting
changed, or debugger component installed in response to it.

### Secure-call dispatch of the debug-break request and EXDI reassessment, 2026-09-22

Re-derived the stub finding from the retained image samples rather than recalling it, then
established what *calls* the stub. Entirely offline: no VM was queried, attached, reconfigured
or rebooted, no MCP server was involved, no live attach or break request was issued, and no BCD
or host setting changed. The debugger was `cdb` **10.0.29617.1000 AMD64** from WinDbg package
**1.2606.22001.0**, opening each image with `-z` against the existing local symbol cache. Images
came from `target/sk-build-survey-20260919/`; every SHA-256 was recomputed before use.

**The 29671 target image is no longer on this workspace** — `target/sk-29671-static/` is gone, and
only its archived excerpt survives. So five of the six matrix rows below were re-measured, and the
29671 row is carried over from
[the earlier comparison](#offline-build-comparison-and-native-route-gate-2026-09-19)
rather than reproduced.

#### Replication

| SK file version | Image SHA-256 status | Break-request RVA | Body | `…ByVtl1` |
|---|---|---|---|---|
| 10.0.26100.9457 | matches accepted matrix | `0x27CDC` | `xor eax,eax; ret` | absent |
| 10.0.28000.2952 | matches accepted matrix | `0x2BA6C` | `xor eax,eax; ret` | absent |
| 10.0.29617.1000 | matches accepted matrix | `0x439EC` | `xor eax,eax; ret` | absent |
| 10.0.29639.1000 | matches accepted matrix | `0x42840` | `xor eax,eax; ret` | absent |
| 10.0.29648.1000 | matches accepted matrix | `0x2FA90` | `xor eax,eax; ret` | absent |
| 10.0.29671.1000 | not re-measured; archived excerpt | `0x2ED60` | `xor eax,eax; ret` | absent |
| 10.0.29667.1000 | **index mismatch, identity unverified** | `0x2ED60` | `xor eax,eax; ret` | absent |
| 10.0.19041.207 | hash-verified, unclassified | symbol absent | — | absent |
| 10.0.22621.7581 | **index mismatch, identity unverified** | symbol absent | — | absent |

The five re-measured RVAs reproduce the recorded values exactly. The 29667 sample remains one of
the rejected downloads and is listed separately; **its matching the 29671 RVA is a coincidence of
layout and not evidence that the two files are the same** — their hashes differ
(`7CB59806…` against `F6112AEE…`).

`x securekernel!*DebugBreakRequested*` returns exactly one symbol in every image, so
`IumpDebugBreakRequestedByVtl1` is not a spelling to keep hunting for. It does not exist in any
sample inspected here, including the two pre-26100 ones.

#### There is no VTL1 counterpart because the routine is a secure-call handler

The name records a *direction of request*, not a debugger role. In 29648,
`IumpInvokeLimitedModeSecureService` (`0x2FA9C`) switches on the secure call number read from
`[rcx+2]`, and **call number `0x124`** dispatches straight into the stub:

```text
4002fad1 b824010000      mov     eax,124h
4002fad6 663bc8          cmp     cx,ax
4002fad9 0f87f6000000    ja      IumpInvokeLimitedModeSecureService+0x139
4002fadf 0f84e6000000    je      IumpInvokeLimitedModeSecureService+0x12f
...
4002fbcb e8c0feffff      call    securekernel!IumpDebugBreakRequestedByVtl0 (00000001`4002fa90)
```

A rel32 scan of every executable section finds **exactly two** call sites in each of the six
images that have the symbol, and both are dispatch sites — there is no internal use:

| SK file version | `IumInvokeSecureService` site | `IumpInvokeLimitedModeSecureService` site |
|---|---|---|
| 10.0.26100.9457 | `0x199D2` | `0x27E15` |
| 10.0.28000.2952 | `0x1C02E` | `0x2BBA9` |
| 10.0.29617.1000 | `0x1AA80` | `0x43B27` |
| 10.0.29639.1000 | `0x1B48D` | `0x4297B` |
| 10.0.29648.1000 | `0x14BA9` | `0x2FBCB` |
| 10.0.29667.1000 | `0x14BA9` | `0x2EE9B` |

VTL0 asking VTL1 to break is a secure call; VTL1 asking itself is not a secure call at all, so a
symmetric `…ByVtl1` entry point would have nothing to dispatch it. **The absence is structural,
not a missing feature to look for in another build.** That is an argument about this dispatch
shape in these images, and it does not exclude some other VTL1 debug entry reached by a mechanism
not inspected here.

#### Four details the first pass did not record

- **The body is identical-COMDAT-folded.** In 29648, four symbols share `0x14002FA90`:
  `IumpDebugBreakRequestedByVtl0`, `SkIsSecureKernel`, `SkhalpPciAccessAtsCapability` and
  `SkpnppSwdValidateTrustlet`. This cuts both ways. The linker folds only byte-identical bodies,
  so `return 0` is genuinely what the routine compiles to; but **a breakpoint at that address is
  ambiguous across four unrelated callers**, which matters to anyone planning to arm one live.
- **`.pdata` confirms the extent without the symbol.** The `RUNTIME_FUNCTION` at `0x14DD28` reads
  `Begin=0x2FA90, End=0x2FA94, UnwindData=0x112FA0` — a four-byte function, independent of whether
  the PDB named it correctly.
- **`SkiSecureServiceTable` does not contain it.** The table sits at `0x156000` with
  `SkiSecureServiceLimit` immediately after it at `0x1560D0` holding `0x1A`, so it has 26 entries,
  all `Ium*` device/enclave services. The debug break is switch-dispatched, not table-dispatched,
  which is why a table walk alone would miss it.
- **`SkdpStub` disappears after 26100.** Present in 19041.207, 22621.7581 and 26100.9457; absent
  from 28000.2952, 29617, 29639, 29648 and 29667. The earlier note that 19041's `SkdpStub`
  contains exception-handling logic still stands, and this says only when the symbol stopped being
  emitted, not what replaced it.

#### No transport, but a complete self-description

`x securekernel!*Kd*` returns `KdDebuggerDataBlock`, `KdVersionBlock`, `KdpDebuggerDataListHead`
and the `KdpSearch*` globals — **all data**. There is no `KdSendPacket`, `KdReceivePacket`,
`KdpTrap` or `KdInitSystem` in any inspected image. `SkdIsThisAKdTrap` exists in all of them and
is a classifier, not a servicer: it tests the exception code for `0x80000003` or `0x4000001F`,
requires a non-zero parameter count and a non-null `ExceptionInformation[0]`, and returns a
boolean. Nothing consumes that verdict over a wire.

Against that, `SkdInitDebuggerDataBlock` populates the block fully: the `KDBG` signature
(`0x4742444B`), size `0x3A8`, `SkLoadedModuleList` into the loaded-module-list slot,
`SkeProcessorBlock`, `SkiBugCheckData`, `SkmmHighestUserAddress`, `SkmmSystemRangeStart`,
`SkmmUserProbeAddress`, `DbgBreakPointWithStatus` and the PTE swizzle bit.

**So the split is: SK ships the metadata a debugger needs to describe it, and ships no transport
to deliver it.** That is a statement about these images' inspected routines, not a proof that no
alternative path exists — but it is the same split across every sample, and it is what decides
which integration route is worth pursuing.

#### EXDI reassessment: the backend contract is GDB RSP, not COM

Re-examined the Phase 4 prerequisites in light of the above, and of the requirement that no
LiveCloudKd component be taken as a dependency. Read-only inspection of the installed WinDbg
package found that **Microsoft already ships the EXDI adaptation layer**:

| Item | Observed |
|---|---|
| `ExdiGdbSrv.dll` | present for `amd64` (1,455,416 B) and `arm64` (1,523,512 B) |
| `exdiConfigData.xml` | present beside it and under `winext\`; `CurrentTarget = "QEMU"` in both. The two copies are **not the same file** - see the 2026-09-24 re-measurement below |
| Preconfigured targets | Trace32, BMC-OpenOCD, QEMU, VMWare, BMC-SMM, UEFI - this is the **top-level** copy's set; the `winext\` copy ends VMWare, gdbserver |
| Memory-command flags | `SupervisorMemory`, `HypervisorMemory`, `requirePAMemoryAccess` |
| CLSID in the DLL's strings | `{29f9906e-9dbe-4d4b-b0fb-6acf7fb6d014}` |
| That CLSID registered on this workspace | **no** — absent from `HKLM` and `HKCU` `\SOFTWARE\Classes\CLSID` |

`ExdiGdbSrv.dll` is a generic EXDI COM server that speaks the GDB remote serial protocol, so a
backend implements a **GDB stub over TCP** rather than an EXDI COM interface. That removes both
the LiveCloudKd dependency and the COM surface from the design. The last row matters and is easy
to skip past: **shipping is not registration**, so a working route still requires a registration
step that has not been taken or reviewed here.

The engine-side plumbing is two changes, both in existing shapes:

- **dbgscope.** `attach_kernel_begin` (`src/dbgeng.rs:4174`) passes
  `DEBUG_ATTACH_KERNEL_CONNECTION`; an EXDI attach is the same call with
  `DEBUG_ATTACH_EXDI_DRIVER`. That constant is reachable today — `windows` 0.62.2,
  `Windows/Win32/System/Diagnostics/Debug/Extensions/mod.rs:323`, value `2`.
- **windbg-mcp.** `Connection::endpoint` (`src/kdconn.rs:133`) already returns `Endpoint::Unknown`
  for any prefix other than `net:`, so an EXDI connection string flows through the profile and
  redaction machinery without a gate change. **It is still a blocker, and in the opposite
  direction to the one this entry first recorded.** `Endpoint::conflicts` (`src/kdconn.rs:99`)
  treats `Unknown` as conflicting with *everything*, and `Sessions::admit`
  (`src/engine.rs:3200`) refuses the open on a conflict. So an EXDI attach would be refused
  whenever any live kernel session exists, and once admitted would block every later kernel
  attach whatever its port — which breaks the two-session NT-plus-hypervisor workflow this
  bench already runs on non-conflicting `net:` ports. The guard is over-conservative rather
  than permissive; a new `Endpoint` variant carrying the stub’s host and port is still the
  fix, for coexistence rather than for safety. The first reading of this was taken from the
  variant’s name without opening `conflicts`, which is the failure
  [`measurement-provenance.md`](../../.claude/rules/measurement-provenance.md) opens with.

Neither code change has been made, and no EXDI component was installed or registered. **An
attach was attempted on 2026-09-22 and it reset this workspace** — see
[the transport experiments](#exdi-transport-experiments-and-the-host-reset-2026-09-23).

#### What this does not settle, and the two cheapest experiments

**Whether DbgEng's EXDI kernel path can be pointed at `securekernel` rather than `nt` is
unproven, and it decides the whole design.** `Kd=Guess` scans for NT's debugger data block, and
whatever assumptions sit below that were not inspected. Everything above establishes that SK
*has* a block worth keying off, not that DbgEng can be made to use it.

Two steps answer that without provisioning a lab or changing the outer host:

1. **Use the hypervisor session that already works.** The hypervisor KD route passed on this
   bench, so SK's `KdDebuggerDataBlock` can be located and parsed at runtime from there. That
   confirms the block is populated *live* rather than merely written by a routine whose execution
   was inferred, and it costs one session. **It will not reach SK through DbgEng's own `sk`
   record**, which the follow-up below measured as EXDI-gated — this step reads memory, it does
   not bind a target.
2. **Then test DbgEng-over-EXDI against QEMU**, which `exdiConfigData.xml` already targets. The
   assumption to be tested is that a nested-VBS guest's SK pages are readable through QEMU's
   gdbstub beneath the nested hypervisor's SLAT; that assumption is **not** established here and
   is the point of the experiment.

Neither step needs a Hyper-V-side stub, and step 2 is what a custom hypervisor would have to beat
before it could be justified. Note also that the Root-scheduler, fixed-memory and single-vCPU
constraints recorded in
[the host preflight](#exdi-host-preflight-and-topology-decision-2026-09-19) are the LiveCloudKd
recipe's, not EXDI's — a stub written here is not bound by them, though whatever supplies
VTL-qualified register state still needs privileged Hyper-V access, and that requirement does not
go away.

#### Evidence

Published: `secure-call-dispatch-29648.1000.txt` in the
[evidence bundle](../samples/secure-kernel-debugger-investigation/README.md), recorded under
`supplementary` in `images.json`. The six pre-existing `evidence_sha256` values were re-verified
before that file was added and all still match, so the earlier excerpts are unchanged.

Ignored local evidence, under the session scratchpad rather than `target/`: per-image
`x securekernel!*` symbol dumps, `uf` output for the routines above, the rel32 cross-reference
scan (`xrefscan.py`, a pure PE parse with no debugger involved), and the resolved
`SkiSecureServiceTable` listing.

### EXDI transport experiments and the host reset, 2026-09-23

First attempts to drive DbgEng's EXDI path on this workspace, plus an offline read of the engine's
option parser. **One attempt reset this machine**; that is the most important line here. No VM was
queried, attached or reconfigured, no BCD or host security setting changed, and nothing was left
registered. The engine throughout was `dbgeng.dll` **10.0.29617.1000** with `kd.exe` from WinDbg
package **1.2606.22001.0**; no PDB is served for that engine build, so all offline readings are
from string cross-references, `.pdata` and imports rather than symbols.

#### The `Kd=` option set, read offline

The connection string is a list of `Name=Value` pairs, and `Kd=` selects one of **six**
kernel-discovery modes. The parser spans image RVA `0x2FC810`-`0x2FCB46`; each option is a string
compare followed by a mode number stored at `ctx+0x20`:

| `Kd=` value | Mode | Compared with | Carries an address |
|---|---|---|---|
| `Ioctl` | 1 | `_wcsicmp` | no |
| `GsPcr` | 2 | `_wcsicmp` | no |
| `VerAddr:<addr>` | 3 | `_wcsnicmp`, length 8 | **yes** - `%I64i` into `ctx+0x28` |
| `Guess` | 4 | `_wcsicmp` | no |
| `NTBaseAddr` | 5 | `_wcsicmp` | no |
| `HwDbgBlock` | 6 | `_wcsicmp` | no; also sets `ctx+0x44` |

A malformed address returns `0x80070057` and the conversion is checked for exactly one field, so
`VerAddr:` is parsed rather than merely recognised. Remaining option names: `CLSID`, `DataBreaks`,
`Desc`, `EBC`, `Exdi`, `ForceX86`, `Args`, `Linux`, `Inproc`, `PathToSrvCfgFiles`.

**`Kd=VerAddr:<address>` is the load-bearing find.** It lets a caller name the version block
instead of letting the engine hunt for NT's, which is the mechanism a Secure Kernel bind would
need.

#### An `sk` record exists; its reachability does not

A table of 40-byte records at `.data` RVA `0xA1F718` maps an EXDI memory space to a kernel module
and its version-block symbol: `nt`/User Mode, `nt`/Supervisor-Kernel, `hv`/Hypervisor, and
**`sk`/Hypervisor with `sk!KdVersionBlock`**. Those space names are the ones `exdiConfigData.xml`
gates with `SupervisorMemory` and `HypervisorMemory`.

That looked like a built-in Secure Kernel bootstrap and was first recorded here as one. A follow-up
on 2026-09-23 mapped `.pdata` (18,091 functions) and classified every function that touches the
table, which does not support the stronger reading:

| Question | Measurement |
|---|---|
| Who reaches the three table readers? | Only functions that also reference **EXDI** strings (`0x3042F4`, `0x305900`, `0x42EE70`) |
| Any KD-transport caller? | **None** - 0 of 91 KD-transport strings appear in any function touching the table |
| The `hv`-vs-`sk` selector at `0x42EDE0` | **No direct callers; its address is never taken** |

So the path is EXDI-gated and the one function distinguishing the `sk` record from the `hv` record
is unreferenced in this build. **A hypervisor KD session cannot be steered to `sk` by this
machinery.** The record is real; whether it is reachable at all is unproven, and it may be
vestigial. Absence of a direct caller is not proof of dead code - a computed jump table would not
show in that scan - and this is one engine build.

**One string is a red herring, recorded so it is not re-read as evidence.** The only `securekernel`
occurrence with a code reference (RVA `0x814178`) sits in a partially-mapped-image diagnostic, not
a bootstrap. The `securekernel.exe` and `securekernella57.exe` names at `0x813E60`/`0x813EC0` have
no code reference; they live in a name table.

#### Registration is a real prerequisite

With the CLSID `{29f9906e-9dbe-4d4b-b0fb-6acf7fb6d014}` absent from `HKLM` and `HKCU`, and the
shell elevated, `kd -kx exdi:CLSID={29f9906e-...},Kd=Guess,DataBreaks=Exdi` fails with
`0x80040154 Class not registered` and **registers nothing**. An earlier entry read the engine's
registration strings as proof it self-registers; it has that code and did not run it there. The
strings were evidence of a code path, not of when it executes.

Also measured: **`cdb.exe` has no `-k` switch at all** - kernel work needs `kd.exe`, whose
`-kx <options>` is the EXDI connection.

#### The `Inproc` attempt reset the workspace

`Inproc=<value>` resolves `<debugger module directory>\<value>` and calls `LoadLibraryExW`, so the
value is a **bare filename**: `Inproc=1` tried `...\amd64\1`, and an absolute path was concatenated
onto the debugger directory and failed with error 126. With `Inproc=ExdiGdbSrv.dll` the engine
printed its own warning and nothing further:

```text
EXDI WARNING! The /Inproc option is not compatible with connecting remote clients.
              Consider removing it if you encounter hangs or strange behavior.
```

**That attempt hung the host hard enough to require a reset.** The box returned with a 2-minute
uptime and no surviving debugger processes. A private GDB-RSP responder on the far end
(`localhost:12345`) logged **no connection at all**, so nothing reached the transport: neither a
runaway `Kd=Guess` scan nor the responder's replies were involved, and `heuristicScanSize` was
already `0xffe`. The hang was not observed directly - the session was interrupted and the machine
reset - so *in-process COM load* is where the evidence points rather than a proven cause. What is
established is that the warning is the last output and the machine did not recover.

The attempt carried a 60-second kill on the child and **the kill did not save the machine**, so a
job object is the bound a retry needs, not a `WaitForExit` timeout. Nothing was left registered, so
there was no cleanup. This is the hazard class of a `cdb -server` spinning on a broken pipe.

#### Rig findings for a future attempt

`ExdiGdbSrv.dll` and `exdiConfigData.xml` ship inside the WinDbg package for `amd64` and `arm64`,
so the EXDI adaptation layer needs no separate distribution and a backend implements a **GDB stub
rather than a COM server**. The engine can be pointed at a private copy of the config with the
`EXDI_GDBSRV_XML_CONFIG_FILE` environment variable, which worked here. The shipped `CurrentTarget`
is `QEMU` with `targetArchitecture` **ARM64**, wrong for this x64 workspace; retargeting it to
`X64` selects a 66-entry register block totalling **608 bytes** (1,216 hex characters for a `g`
reply). The preconfigured **`VMWare`** entry looked like a better starting point on x64, and
**which of the two `exdiConfigData.xml` copies you read decides whether it is** - the row above
records the file as present in two places and the rest of this section then treated it as one.
Re-measured 2026-09-24 against the same package (`Microsoft.WinDbg_1.2606.22001.0_x64`), the two
are different files:

| | `<arch>\exdiConfigData.xml` | `<arch>\winext\exdiConfigData.xml` |
|---|---|---|
| sha256, first 16 | `ee64b9e18e6f6343` | `983f9e9d014b7beb` |
| Targets | Trace32, BMC-OpenOCD, QEMU, VMWare, BMC-SMM, UEFI | Trace32, BMC-OpenOCD, QEMU, VMWare, gdbserver |
| `VMWare` `targetArchitecture` | `X64` | **`X86`** |
| `VMWare` register blocks | X64 (40 entries, `rax`..`fop`) and x86 (40, `Eax`..`xmm7`) | x86 only (40, `Eax`..`xmm7`) |
| `VMWare` `forceLegacyResumeStepCommands` | `yes` | **absent** |
| `VMWare` `HostNameAndPort` | `localhost:1234` | `localhost:15360` |

So *"already `X64`, 40 register entries ... `forceLegacyResumeStepCommands=yes`"* describes the
**top-level** copy, and the *Preconfigured targets* row above lists that copy's six. In the
`winext\` copy the same entry is `X86` with no X64 block at all. `heuristicScanSize=0xffe` and all
seven memory-command flags `no` - plain `m`/`M` with virtual addresses - hold in both.

**This repo bundles the `winext\` copy**: `target\release\winext\exdiConfigData.xml` is
byte-identical to it, sha256 `983f9e9d014b7beb`. Taken as it ships, that entry offers DbgEng a
32-bit register contract, so it is a starting point for a 64-bit guest only after the X64 block is
put back. Which copy the engine loads when neither `EXDI_GDBSRV_XML_CONFIG_FILE` nor
`PathToSrvCfgFiles` is set was **not** established here. The `QEMU` entry is identical in both
copies, and its 66-entry X64 block is 66 live `<Entry>` elements of 69, three being commented out.

This workspace cannot host the target itself: it is a Hyper-V guest, `Microsoft-Hyper-V-All` and
`VirtualMachinePlatform` are **Disabled**, no VMware or VirtualBox is installed, and 10.3 GB is
free. **Hyper-V exposes no gdbstub in any case**, so a Hyper-V guest cannot stand in for QEMU or
VMware as an EXDI target - that gap is the backend work itself, not a way around it. The user
elected to set up a VMware VM separately. As of 2026-09-24 that guest exists, on the same box that
hosts this workspace; what it still needs before E0 can run, and the VBS question that VMware and
Hyper-V sharing a box raises for E2, are in
[`docs/exdi-stub-plan.md`](exdi-stub-plan.md#where-each-component-runs).

Ignored local evidence, under the session scratchpad rather than `target/`: the option-parser and
`.pdata` classification scripts, per-image string and cross-reference dumps, the private
`exdiConfigData.xml`, the GDB-RSP responder and its log, and the `kd` attach logs.

### Selected layout and resources

```text
Outer Hyper-V host
  +-- Workspace VM: WinDbg / MCP
  +-- New Windows 11 Insider 29671 target VM: VBS / NT KDNET verified
        ^ KDNET from the workspace over a reachable virtual network
  +-- Existing Server 2025 VM: retained; native Secure Kernel setup rejected
```

The target uses resources on the outer host. For a fresh target, a starting budget would be
8 GiB fixed target RAM and a 64 GiB or larger virtual disk, with additional physical free space
for its installed contents, installation media, and checkpoints. These are proposed lab settings;
the outer host's capacity has not been checked. The previous 16 GiB workspace recommendation
covered both Windows instances inside one VM. The previous 100 GiB free-space suggestion allowed
for the target and its artifacts; storing them on the outer host relocates that storage cost.

### Current route: target on the outer host

1. On the outer host, inspect the existing target's generation, processor settings, fixed memory,
   Secure Boot, virtual TPM, network addresses, and checkpoints. Inside the target, record its
   Windows version and VBS state. Compare these with the Windows 11 25H2 x64 lab plan before
   changing configuration; do not replace an existing VM or assume its OS build.
2. Check `Get-VMProcessor -VMName '<target VM name>'` and `Get-VMSecurity` first. Record extension
   exposure and the VBS opt-out setting. If a nested hypervisor is required for the selected
   experiment and extensions are not exposed, enable them while the **target VM** is off:

   ```powershell
   Set-VMProcessor -VMName '<target VM name>' -ExposeVirtualizationExtensions $true
   ```

   This enables the nested-hypervisor route, not a universal prerequisite for Hyper-V guest VBS.
   It does not require hosting another Windows guest there, and it is not a request to enable
   nesting on the workspace. Microsoft's
   [nested virtualization procedure](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization)
   describes the extension-exposure step.
3. Connect the target and debugger to a virtual network where KDNET UDP traffic can pass between
   them. Use the debugger's reachable address in the target's KDNET setup and open only the actual
   emitted debugger ports on the debugger VM. Select addresses after inspecting the network.
4. Enable VBS in the target, restart it, and verify `VirtualizationBasedSecurityStatus = 2` with
   `Win32_DeviceGuard` inside that VM. Record `SecurityServicesRunning` as well. Follow Microsoft's
   [VBS verification guidance](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity).
5. Take the baseline checkpoint, then perform the plan's ordinary NT KDNET positive control,
   Secure Kernel negative control, and `kdnet -s` experiment. Configure only the disposable target.
   The physical host's own Secure Kernel is not the target in this layout.

If the intended target is instead the physical host's own Secure Kernel, use a debugger on an
independent machine: a debugger VM running on the machine being stopped is not an independent
control path. That would require a separate physical-target setup decision.

### Deferred route: target inside the workspace

The 2026-09-14 measurements below describe the deferred layout. The workspace is itself a virtual machine. Its processor flags reported no virtualization extensions;
this is an observation inside the VM, not a measurement of the physical machine's firmware or
proof of the outer VM configuration. The outer Hyper-V host and this VM's settings on it have not
been inspected. Installing Hyper-V here alone does not establish the proposed lab prerequisites.

**Originally selected on 2026-09-14, deferred on 2026-09-16:** the target would run inside this workspace VM, after the outer host
exposes virtualization extensions. The workspace will run WinDbg/MCP and the nested Hyper-V role;
the inner Generation 2 Windows guest will be the disposable Secure Kernel target. Running VBS
inside that target adds another virtualization layer whose suitability remains to be demonstrated.

The follow-up resource check found **4 GiB RAM and 37.5 GiB free on C:** in the workspace, with
Hyper-V still disabled and the same false virtualization flags. No `.iso` was found in the user's
Downloads directory; other installation-media locations have not been inventoried. Before guest
creation, budget memory for both Windows instances and storage for installation media, the guest
disk, and checkpoints. A proposed starting allocation is **16 GiB fixed RAM for the workspace**
(8 GiB for the target) and **100 GiB free guest-storage space**; these are lab sizing choices, not
measured requirements or an allocation already made. Check outer-host capacity before applying them.

Microsoft's [nested virtualization procedure](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization)
requires running `Set-VMProcessor -VMName <VMName> -ExposeVirtualizationExtensions $true` on the
outer host while the affected VM is off. Turning off the workspace ends this working session, so
that transition requires coordination outside the guest. No host role, firmware, guest, or boot
configuration was changed during Phase 1.

### Deferred outer-host preparation and resume

Save work and shut down the workspace normally. From elevated PowerShell on the outer host,
identify the workspace VM, inspect its current CPU and memory configuration, then enable nesting
while it is off. Use the VM object so the mutation is scoped to the inspected machine:

```powershell
$workspaceVm = Get-VM -Name '<workspace VM name>' -ErrorAction Stop
$workspaceVm | Select-Object Name, State, Version
$workspaceVm | Get-VMProcessor | Select-Object Count, ExposeVirtualizationExtensions
$workspaceVm | Get-VMMemory | Select-Object DynamicMemoryEnabled, Startup, Minimum, Maximum
if ($workspaceVm.State -ne 'Off') { throw 'Shut down the workspace VM normally first.' }
$workspaceVm | Set-VMProcessor -ExposeVirtualizationExtensions $true
# After checking the outer host has room for the proposed allocation:
# $workspaceVm | Set-VMMemory -DynamicMemoryEnabled $false -StartupBytes 16GB
$workspaceVm | Get-VMProcessor | Select-Object Count, ExposeVirtualizationExtensions
$workspaceVm | Start-VM
```

Keep the inspected original values with the machine-local lab notes. Host and VM names are omitted
from this committed runbook. Increase or add guest-storage capacity on the outer host as needed;
resizing a virtual disk alone does not expand the partition inside the workspace.

After restarting and reconnecting, rerun `tools/secure_kernel_preflight.ps1` inside the workspace
and verify the outer host reports `ExposeVirtualizationExtensions = True`. Then install Hyper-V
and its management tools here, recording any requested restart before creating the inner guest.
Expose virtualization extensions to the inner guest too, and verify VBS **inside that guest**;
the workspace's own VBS status does not establish the target's VTL1 state.

Continue with the plan's Generation 2 guest, fixed memory, Secure Boot,
vTPM, verified running VBS, and baseline checkpoint. The positive and negative controls still
precede Secure Kernel configuration. The capability matrix, opt-in VTL1 test, recovery procedure
for actual BCD changes, and redacted MCP validation cast remain pending a working route.
