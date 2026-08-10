# Kernel address disclosure probe

`kernel_address_probe.c` is a standalone, read-only reproducer for checking whether a Windows
caller can obtain kernel virtual addresses from system-information APIs. It does not load or open
the MessageManager challenge driver, issue IOCTLs, modify memory, or use the kernel debugger.

The probe checks four information classes:

| Class | Probe | Address material |
|---|---|---|
| 11 | `SystemModuleInformation` | kernel and driver image bases |
| 16 | `SystemHandleInformation` | legacy, truncated handle records with object pointers |
| 64 | `SystemExtendedHandleInformation` | full-width handle records with object pointers |
| 66 | `SystemBigPoolInformation` | kernel pool allocation addresses and tags |

It also calls the documented `EnumDeviceDrivers` path for comparison. On Windows 11 24H2 and
later, Microsoft documents that this API returns valid image bases only when `SeDebugPrivilege` is
enabled.

## Build

From `examples\messagemanager` in an x64 Developer Command Prompt:

```bat
build.cmd kernel_address_probe.c
```

The output is `kernel_address_probe.exe`. The existing build helper locates the repository's MSVC
Build Tools installation and returns the compiler exit status.

## Run a valid standard-user test

Use a clean, fully updated retail VM. Kernel debugging and test-signing should be disabled for the
reportable run. Sign in as a newly created local user that has never been added to Administrators;
do not launch the process through an administrator's WinRM session.

Capture the OS and token context before running:

```powershell
whoami /all
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber
.\kernel_address_probe.exe --require-standard *>&1 |
    Tee-Object -FilePath .\kernel-address-probe.txt
```

`--require-standard` exits before issuing the address queries when the token contains the local
Administrators SID, is an elevated/filtered administrator token, or contains `SeDebugPrivilege`.
This prevents an administrator result from being mistaken for a non-administrator disclosure.

Exit codes are:

- `0`: the probe ran; inspect the final `overall` assessment;
- `1`: invalid arguments or an operational failure;
- `2`: `--require-standard` rejected a privileged or filtered-administrator token.

## Interpret the result

A hardened result has zero kernel pointers, for example:

```text
[assessment] caller_class=standard-non-admin
[documented-modules] count=... kernel_pointers=0 first=0000000000000000
[direct-modules] count=... kernel_pointers=0
[extended-handles] ... object=0000000000000000 kernel_pointer=no
[big-pool] count=... kernel_pointers=0
[assessment] overall=NO_KERNEL_POINTERS_OBSERVED
```

The result is worth validating for disclosure when all of these are true:

1. `caller_class=standard-non-admin`;
2. the VM is a current supported build with all security updates installed;
3. one or more `kernel_pointers` counts are nonzero;
4. the result reproduces after a clean reboot with KD and test-signing disabled.

On build 26100 or later, nonzero class-11 addresses also produce
`candidate_24h2_module_base_disclosure=yes`. That label is a triage hint, not a claim that Microsoft
has confirmed a vulnerability. Handle and big-pool pointer observations must be assessed separately
from module-base hardening.

For an MSRC submission, include the source, compiler architecture, complete probe output, token
output, exact servicing build, and clean-install reproduction steps. Do not attach an entire Codex or
debugger session transcript: it may contain KDNET keys, remoting credentials, or unrelated target
data.
