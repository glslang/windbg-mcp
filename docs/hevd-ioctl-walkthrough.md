# Driver IOCTL walkthrough: HEVD — service-loaded driver, user PDB, static→live reachability

A companion to the [`\Driver\mountmgr` walkthrough](driver-ioctl-walkthrough.md), run against
**HEVD** (the [HackSys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver),
`win10-klfh` build) on a **live KDNET kernel** (Windows 26100). Where the mountmgr tour covered the
four reachability *gates* on a built-in driver with public symbols, this one covers the pieces that
differ for a **third-party, service-loaded** driver you have a **PDB** for, and closes the loop with
the `reachable_from_dispatch` / `run_to_address` tools. It mirrors the
[`driver-ioctl.md`](../skills/windbg-debugging/driver-ioctl.md) playbook.

> **Verdict up front:** HEVD exposes **28 IOCTLs**, `0x222003`–`0x22206F` (function codes
> `0x800`–`0x81b`), **every one** `CTL_CODE(FILE_DEVICE_UNKNOWN, …, METHOD_NEITHER, FILE_ANY_ACCESS)`.
> METHOD_NEITHER hands the driver raw user-mode pointers and FILE_ANY_ACCESS means the I/O manager
> delivers on any handle; the device is openable by anyone — so all 28 are reachable from an
> unprivileged user. That is the entire point of HEVD: no gates, maximum bug surface. The write-
> what-where handler (`HEVD!ArbitraryWriteIoctlHandler`, IOCTL `0x22200B`) is confirmed reachable
> from the dispatch entry by a concrete static path.

## 1. Attach over KDNET (and let the link settle)

```jsonc
attach_kernel { "connection": "net:port=50000,key=<w.x.y.z>" }   // ask the user for the real string
```

> **Gotcha — the attach *blocks*.** A live kernel needs `WaitForEvent(INFINITE)`, so if the target
> isn't reachable the tool reports a *timeout* while the engine stays parked, waiting — it completes
> the moment the target connects. Don't fire more windbg tools into a parked attach; **diagnose
> out-of-band** (`Get-NetUDPEndpoint -LocalPort 50000` → owned by `windbg-mcp.exe`; is a VM running?).
> The target must dial this host: `bcdedit /dbgsettings net hostip:<debugger-ip> port:50000 key:<key>`
> (**colons**, not `=`). After a target reboot the settling KD link throws repeated break-ins in
> `kdnic.sys` (`nt!DbgBreakPointWithStatus` ← `kdnic!TXTransmitQueuedSends`) — just `go` through them.

## 2. Wait for the driver to load — it loads *after* boot

HEVD is a service, not a boot driver, so at attach it isn't present (`lm m HEVD` is empty). Break on
its load:

```jsonc
execute { "command": "sxe ld:HEVD.sys" }
go {}     // continues boot; breaks when HEVD maps in
```

```text
Last event: Load module HEVD.sys at fffff800`11820000
```

> **Gotcha — the load event fires *before* `DriverEntry` runs.** So the driver object's dispatch
> table isn't populated yet: `driver_object { "name": "HEVD" }` reports *"is not a driver object"*.
> Let `DriverEntry` run first by breaking on its return:

```jsonc
// PE entry point = base + AddressOfEntryPoint (read straight from the header):
execute { "command": "? 0xfffff80011820000 + dwo(0xfffff80011820000 + dwo(0xfffff80011820000+0x3c) + 0x28)" }
//   → fffff800`118aa140
set_breakpoint { "expression": "0xfffff800118aa140" }
go {}   // at entry: @rcx = DriverObject, poi(@rsp) = return into nt!PnpCallDriverEntry
set_breakpoint { "expression": "<poi(@rsp)>" }   // e.g. 0xfffff8007cab3ff0
go {}   // DriverEntry has now run; the MajorFunction table is populated
```

(A driver already loaded when you attach needs none of this — go straight to §4.)

## 3. Resolve symbols from the user's PDB

Third-party drivers ship no public symbols, but HEVD is built by the user, so the **PDB exists**.
Find exactly which one the engine wants, then ask the user for it:

```jsonc
execute { "command": "!sym noisy; .reload /f HEVD.sys" }
//   → wants HEVD.pdb, GUID 0971DD2656BD43C49F6B1BE314AB3F8C1
```

The PDB must be reachable from **this** (debugger) host — symbols are never pulled from the target
over the KD wire. Ask the user for the folder, then apply it with the `set_symbol_path` tool (it uses
the DbgEng `AppendSymbolPath` API, so it's immune to the `.sympath` line-eating quirk below):

```jsonc
set_symbol_path { "path": "C:\\HEVD\\bin", "reload": "/f HEVD.sys" }
//   → HEVD (private pdb symbols)  c:\hevd\bin\HEVD.pdb
```

> **Gotcha:** the raw `.sympath` / `.sympath+` commands swallow the *rest of the line* — they ignore
> `;`, so anything chained after (`; .reload …`) is parsed as path text. Use `set_symbol_path`, or
> issue `.sympath` alone. Names now resolve: `HEVD!IrpDeviceIoCtlHandler`,
> `HEVD!ArbitraryWriteIoctlHandler`, etc.

## 4. Find the dispatch routine

```jsonc
driver_object { "name": "HEVD" }
```

```text
Device object … \Driver\HEVD   DeviceObject ffff930f1af3ee10
MajorFunction[0x0e]  fffff800`118a5074   HEVD!IrpDeviceIoCtlHandler
```

Index **`0x0e`** (`IRP_MJ_DEVICE_CONTROL`) at `DriverObject+0xe0` is the IOCTL dispatch.

## 5. Static enumeration — recover the switch

```jsonc
execute { "command": "uf HEVD!IrpDeviceIoCtlHandler" }
```

The prologue loads the control code (`r9d = [IRP_SP+0x18]`, `IRP_SP = [Irp+0xb8]`), then a compiler
**binary-search** chain of `cmp`/`sub`+`je` on the code — 28 cases, each `DbgPrintEx`-ing a name
string and calling its trigger handler, with a `default:` returning `STATUS_INVALID_DEVICE_REQUEST`:

```text
sub ecx, 222003h ; je → ArbitraryWrite path is +8 codes up …
0x222003 BUFFER_OVERFLOW_STACK          0x22200B ARBITRARY_WRITE (write-what-where)
0x222007 BUFFER_OVERFLOW_STACK_GS       0x22200F BUFFER_OVERFLOW_NON_PAGED_POOL
… (function codes 0x800..0x81b, step 4) …
0x22206F DELETE_ARW_HELPER_OBJECT_NON_PAGED_POOL_NX
default  → STATUS_INVALID_DEVICE_REQUEST (0xC0000010)
```

Names come from each case's `DbgPrintEx` string (read with `da`); the trigger handler is the second
`call` in each case block.

## 6. Decode — the tier is uniform

```jsonc
decode_ioctl { "code": "0x22200B" }   // ARBITRARY_WRITE
decode_ioctl { "code": "0x22206F" }   // the last code
```

```text
0x0022200b  CTL_CODE(0x0022, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
0x0022206f  CTL_CODE(0x0022, 0x81b, METHOD_NEITHER, FILE_ANY_ACCESS)
  [!] METHOD_NEITHER: driver receives raw user-mode pointers — classic bug surface.
  [!] FILE_ANY_ACCESS: no access gate — delivered on any handle.
```

All 28 are identical in method/access; only the function code differs. Unlike mountmgr's tiered
`FILE_ANY_ACCESS`/`READ`/`READ|WRITE` codes, HEVD gates **nothing**.

## 7. Openable gate

```jsonc
device_object { "device": "0xffff930f1af3ee10" }
```

```text
HackSysExtremeVulnerableDriver \Driver\HEVD   Type 0x22
Characteristics (0x100) FILE_DEVICE_SECURE_OPEN   ExtensionFlags DOE_DEFAULT_SD_PRESENT
```

`FILE_DEVICE_SECURE_OPEN` with the **default** device SD (`!sd` isn't in the bundled engine; the SD
pointer is surfaced). Combined with `FILE_ANY_ACCESS`, an unprivileged process opens
`\Device\HackSysExtremeVulnerableDriver` and reaches every IOCTL — no `RequiredAccess` gate to fail.

## 8. Static reachability → live confirm (the new tools)

Prove a specific bug block is reachable from the dispatch entry, and read the input that routes there:

```jsonc
reachable_from_dispatch {
  "from": "HEVD!IrpDeviceIoCtlHandler",
  "address": "HEVD!ArbitraryWriteIoctlHandler",
  "recipe": true
}
```

```text
VERDICT: REACHABLE
  Call path (1 hops):  fffff800`118a51ea  call -> HEVD!ArbitraryWriteIoctlHandler
Path recipe (input that keeps control on the path):
  … sub ecx,222003h  (tests != 0x222003) … je — must take   ; sub ecx,eax
```

The recipe's compare chain pins the gating input to **`IoControlCode == 0x22200B`** — the write-
what-where IOCTL. Then confirm it live (needs KDNET/VM), once a user-mode client sends that code:

```jsonc
run_to_address { "address": "HEVD!ArbitraryWriteIoctlHandler" }   // → HIT / STOPPED-ELSEWHERE / TIMEOUT
```

> `reachable_from_dispatch` doesn't follow indirect `call [ptr]`/`call reg` or unresolved jump
> tables — REACHABLE is sound, NOT-REACHABLE only means "not found within bounds". HEVD's dispatch
> is a direct compare chain, so the walk follows it and decodes the gate. (The tool prints a generic
> "indirect jump table" caveat even here, where it doesn't apply.)

## Gotchas recap

- **Attach blocks on an INFINITE wait** — diagnose a hung attach out-of-band, don't hammer tools.
- **Target dials the debugger:** `bcdedit /dbgsettings net hostip:… port: key:` (colons).
- **`sxe ld` stops before `DriverEntry`** — the dispatch table isn't populated; run DriverEntry via
  the PE-entry + return-address breakpoint (§2) before `driver_object`.
- **Symbols live on the debugger host, not the target** — find the PDB GUID with `!sym noisy`, ask
  the user for the folder, apply with `set_symbol_path`.
- **`.sympath` swallows the rest of the line** — use `set_symbol_path`, or run `.sympath` alone.
- **While broken in the whole guest is frozen** — start any user-mode client, then `go`.
