# Driver IOCTL walkthrough: enumerating & gating `\Driver\mountmgr`

A hands-on tour of the driver-IOCTL tools against a **live KDNET kernel** (Windows
26100.32995), mirroring the skill's
[`driver-ioctl.md`](../skills/windbg-debugging/driver-ioctl.md) playbook. It shows the real
`windbg` MCP tool calls, their output, and the gotchas — ending with a **reachability report**:
which IOCTLs the Mount Point Manager exposes and which a normal user can actually reach. The
target is a built-in driver (no test driver needed); the same flow applies to a third-party
`.sys`.

> **Verdict up front:** `\Device\MountPointManager` exposes IOCTLs in three access tiers. A
> **standard user** can reach **only the four `FILE_ANY_ACCESS` query codes** (`0x6d0008`,
> `0x6d0030`, `0x6d0034`, `0x6d003c`), and only by opening the device with *minimal* access.
> Every read-gated (`0x6d40xx`) and mutating (`0x6dc0xx`) IOCTL is rejected by the I/O manager's
> `RequiredAccess` check **before** the IRP reaches the driver, because the device DACL grants
> normal users neither `FILE_READ_DATA` nor `FILE_WRITE_DATA`. Admin/SYSTEM reach everything.

## 1. Attach (kernel extensions auto-load)

```jsonc
attach_kernel { "connection": "net:port=<n>,key=<w.x.y.z>" }
```

Breaks in and returns `vertarget`. `attach_kernel` also `.load`s `kdexts.dll` for you, so the
`!drvobj`/`!devobj`/`!irp` commands behind the next tools resolve. (Without it they fail
*"No export drvobj found"* — see [setup.md](../skills/windbg-debugging/setup.md) for bundling.)

For readable analysis, point at symbols once stopped:

```jsonc
execute { "command": ".sympath srv*C:\\ProgramData\\Dbg\\sym*https://msdl.microsoft.com/download/symbols" }
execute { "command": ".reload /f mountmgr.sys" }   // → mountmgr (pdb symbols)
```

> **Gotcha:** `.sympath` consumes the rest of the line, so run it on its own — don't `;`-chain
> other commands after it.

## 2. Find the IOCTL dispatch routine

```jsonc
driver_object { "name": "\\Driver\\mountmgr" }
```

The `MajorFunction` table's index **`0x0e`** (`IRP_MJ_DEVICE_CONTROL`) is the IOCTL dispatch:

```text
[0e] IRP_MJ_DEVICE_CONTROL   fffff803`3e254750   mountmgr!MountMgrDeviceControl
```

(On a live target these are already the rebased VAs — no ASLR math needed. For a third-party
driver with no PDB, you'd rebase an RVA to `lm m <driver>`.)

## 3. Static enumeration — recover the switch

```jsonc
execute { "command": "uf mountmgr!MountMgrDeviceControl" }
```

The prologue loads the control code (`r13d = [IRP_SP+0x18]`, `IRP_SP = [Irp+0xb8]`), then a chain
of comparisons + a jump table — the authoritative candidate set:

```text
cmp r13d, 6D0030h  → MountMgrQueryDosVolumePath
cmp r13d, 6D0008h  → MountMgrQueryPoints
cmp r13d, 6D4020h  → MountMgrChangeNotify
sub eax, 6D0034h   → MountMgrQueryDosVolumePaths
...
cmp r13d, 6DC000h  → MountMgrCreatePoint        ; + jump table 0x6dc004..0x6dc054
default            → STATUS_INVALID_DEVICE_REQUEST (0xC0000010)
```

The three **prefixes** — `0x6d00xx`, `0x6d40xx`, `0x6dc0xx` — are the whole story, because the
bits 14–15 of the code (`RequiredAccess`) are exactly what the I/O manager gates on.

## 4. Decode the access tiers

```jsonc
decode_ioctl { "code": "0x6d0008" }   // FILE_ANY_ACCESS
decode_ioctl { "code": "0x6d4020" }   // FILE_READ_DATA
decode_ioctl { "code": "0x6dc000" }   // FILE_READ_DATA | FILE_WRITE_DATA
```

```text
0x006d0008  CTL_CODE(0x006d, 0x002, METHOD_BUFFERED, FILE_ANY_ACCESS)
0x006d4020  CTL_CODE(0x006d, 0x008, METHOD_BUFFERED, FILE_READ_DATA)
0x006dc000  CTL_CODE(0x006d, 0x000, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
```

All `METHOD_BUFFERED` (no `METHOD_NEITHER` raw-pointer surface).

## 5. Openable gate — the device DACL

```jsonc
device_object { "device": "\\Device\\MountPointManager" }
```

```text
SecurityDescriptor ffff8680fc6912a0   Characteristics (0x100) FILE_DEVICE_SECURE_OPEN
```

> **Gotcha:** `!sd` is **not** in the bundled engine, so `device_object` surfaces the SD pointer
> and you decode the DACL by reading the structure:

```jsonc
execute { "command": "dt nt!_SECURITY_DESCRIPTOR_RELATIVE ffff8680fc6912a0" }  // Control 0x8004, Dacl +0x14
execute { "command": "dt nt!_ACL ffff8680fc6912b4" }                            // 4 ACEs
execute { "command": "db ffff8680fc6912b4 L5c" }                                // raw ACEs → parse
```

Parsed DACL:

| Principal | SID | Granted access |
|---|---|---|
| Everyone | `S-1-1-0` | `0x001200a0` (`READ_CONTROL\|SYNCHRONIZE\|READ_ATTRIBUTES\|EXECUTE`) — **no** `READ_DATA`/`WRITE_DATA` |
| RESTRICTED | `S-1-5-12` | `0x001200a0` |
| SYSTEM | `S-1-5-18` | `0x001f01ff` (`FILE_ALL_ACCESS`) |
| Administrators | `S-1-5-32-544` | `0x001f01ff` |

A standard user matches only the *Everyone* ACE → the handle has neither `FILE_READ_DATA` (0x1)
nor `FILE_WRITE_DATA` (0x2). It must open with `DesiredAccess = 0` / `FILE_READ_ATTRIBUTES`;
asking for `GENERIC_READ` is itself access-denied.

## 6. Namespace gate

```jsonc
execute { "command": "!object \\GLOBAL??\\MountPointManager" }
```

```text
SymbolicLink … Target String is '\Device\MountPointManager'
```

A global symbolic link → `CreateFile("\\.\MountPointManager")` resolves from any session. Not a
barrier for normal users here.

## 7. Dynamic confirmation

```jsonc
ioctl_trace { "dispatch": "fffff8033e254750" }   // logging bp: prints code + in/out, then gc
go {}                                            // run mountvol in the guest during the window
```

```text
IOCTL 006d0030 in=200 out=8
IOCTL 006d0008 in=46 out=20
IOCTL 006d0034 in=208 out=8
```

`mountvol` (run as admin here) drove three `FILE_ANY_ACCESS` queries; `in=200 out=8` for
`0x6d0030` matches what `irp_stack {}` decodes at a normal breakpoint on the dispatch
(`IRP_MJ_DEVICE_CONTROL`, `IoControlCode 0x6d0030`). No `0x6d40xx`/`0x6dc0xx` appeared — `mountvol`
only queries.

## 8. The report — discovered IOCTLs & reachability

DeviceType `0x6d`, all `METHOD_BUFFERED`. **Std user** = reachable by a non-admin token.

### `FILE_ANY_ACCESS` — reachable by a standard user

| Code | Handler | Meaning |
|---|---|---|
| `0x6d0008` | `MountMgrQueryPoints` | QUERY_POINTS |
| `0x6d0030` | `MountMgrQueryDosVolumePath` | QUERY_DOS_VOLUME_PATH |
| `0x6d0034` | `MountMgrQueryDosVolumePaths` | QUERY_DOS_VOLUME_PATHS |
| `0x6d003c` | `MountMgrQueryAutoMount` | QUERY_AUTO_MOUNT |

### `FILE_READ_DATA` — blocked for a standard user (handle lacks READ_DATA)

`0x6d4008` (QueryPoints, read variant), `0x6d4020` (ChangeNotify), `0x6d4028`, `0x6d402c`
(VolumeArrival), `0x6d4048` (TracelogCache), `0x6d4058` (VolumeRemoval).

### `FILE_READ_DATA | FILE_WRITE_DATA` — blocked for a standard user (no WRITE_DATA)

`0x6dc000` (CreatePoint) and the `0x6dc004`–`0x6dc054` jump-table group (DeletePoints,
NextDriveLetter, SetAutoMount, ScrubRegistry, …). Exact membership is a compiler jump table
(`mountmgr+0x5b80`/`+0x5b90`); unused slots route to the default. Doesn't change the verdict —
every `0x6dc0xx` carries `RequiredAccess = READ|WRITE`.

### Verdict

- **Standard user:** `0x6d0008`, `0x6d0030`, `0x6d0034`, `0x6d003c` only (opened with minimal
  access). All read-gated and mutating codes are rejected at the I/O-manager `RequiredAccess`
  check before reaching `mountmgr`.
- **Admin / SYSTEM:** all reachable (`FILE_ALL_ACCESS` on the device).
- **Hygiene:** no `METHOD_NEITHER` codes; no `FILE_ANY_ACCESS` *mutators* — the privileged ops
  are correctly gated behind write access.

### Confirm empirically (optional)

Run [`examples/send_ioctls_target.ps1`](../examples/send_ioctls_target.ps1) in the guest **as a
standard user**:

```text
.\send_ioctls_target.ps1 -DeviceName "\\.\MountPointManager" -DesiredAccess 0 `
    -Codes 0x6d0008,0x6d0030,0x6d4020,0x6dc000
```

Expect `0x6d0008`/`0x6d0030` to succeed and `0x6d4020`/`0x6dc000` to fail with
`ERROR_ACCESS_DENIED (5)` — and confirm on the host that the denied codes never reach an
`ioctl_trace` breakpoint.

## Gotchas recap

- `attach_kernel` auto-loads `kdexts.dll`; it must be bundled (`winxp\kdexts.dll`).
- `!sd` isn't in the bundled engine — parse the DACL from the SD pointer (§5).
- `.sympath` swallows the rest of the line — run it alone.
- While broken in, the **whole guest is frozen**: start the trigger (`mountvol`, the sender),
  then `go`. The logging bp continues with `gc`, so `go` returns its log at the ~60s cap.
- Local kernel (`attach_kernel_local`) is read-only — the `ioctl_trace`/`irp_stack` sweep needs a
  KDNET/VM target.
