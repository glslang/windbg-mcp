# Playbook: driver IOCTL discovery & user-mode reachability

**Goal:** enumerate the IOCTLs a kernel driver exposes through its
`IRP_MJ_DEVICE_CONTROL` dispatch routine, and decide — per caller token — whether each
one is actually **reachable from user mode**. This is **static-first, dynamic-confirm**:
static analysis produces the candidate IOCTL map; live debugging confirms delivery and
observes the taken case + return status. Kernel debugging needs **Administrator** (see
[setup.md](setup.md)).

> **Breakpoints confirm; they do not enumerate.** A breakpoint on the dispatch routine only
> fires for IOCTLs you actually *send*. The set of *available* IOCTLs is defined statically by
> the `switch (IoControlCode)` in the dispatch routine — recover it with `uf` or Binary Ninja,
> not with a breakpoint.

## Reachability is a multi-layer gate

"Reachable from user mode" is not one yes/no — it is four gates, evaluated for a specific
caller token. An IOCTL is only useful to a user if it passes all four:

| Gate | Question | How to answer |
|------|----------|---------------|
| **Openable** | Can this token open the device at all? | `device_object` → device DACL (`!sd` on its `SecurityDescriptor`); `FILE_DEVICE_SECURE_OPEN` |
| **Namespace-visible** | Does `CreateFile(\\.\Foo)` resolve in the caller's session? | symbolic-link scope (`\GLOBAL??\Foo` vs. session-local) via `execute` → `!object \GLOBAL??` |
| **Deliverable** | Does the I/O manager forward the IRP to the driver? | `decode_ioctl` → `RequiredAccess` (bits 14–15) checked against the handle's *granted* access **before** the IRP reaches the driver |
| **Handled** | Does the driver do something, or reject it? | `irp_stack` at the break + `Irp->IoStatus.Status` on return (a `default:` case returns `STATUS_INVALID_DEVICE_REQUEST` / `STATUS_NOT_SUPPORTED`) |

A dispatch breakpoint firing means **delivered**, not **useful** — the *deliverable* gate
already passed, and you still have to watch the return path for the *handled* gate.

## IOCTL decode reference

A control code is a packed 32-bit value:

```text
 31              16 15 14 13            2 1  0
+------------------+-----+---------------+----+
|   DeviceType     | Acc |  FunctionCode | Mth|
+------------------+-----+---------------+----+
  CTL_CODE(DeviceType, FunctionCode, Method, RequiredAccess)
```

`decode_ioctl { "code": "0x70000" }` renders all four fields and flags two that matter:
**`METHOD_NEITHER`** (the driver gets raw user-mode pointers — classic bug surface) and
**`FILE_ANY_ACCESS`** (no access gate — the *deliverable* gate is wide open).

## Static enumeration — WinDbg-native (default)

Works on a **local** kernel (`attach_kernel_local`) — it is read-only, but enumeration only
reads.

1. **Find the dispatch routine.** `driver_object { "name": "mydriver" }` (`!drvobj <name> 7`)
   dumps the `MajorFunction` table. Index **`0x0e`** (`IRP_MJ_DEVICE_CONTROL`) is the IOCTL
   dispatch handler's address.
2. **Recover the switch.** `disassemble { "address": "<dispatchVA>" }` or `execute { "command":
   "uf <dispatchVA>" }` to read the `IoControlCode` comparisons / jump-table constants. Each
   `cmp`/case constant is a candidate IOCTL.
3. **Decode each candidate** with `decode_ioctl` to get its method + required access (and the
   `METHOD_NEITHER`/`FILE_ANY_ACCESS` flags).
4. **Device surface.** `device_object { "device": "\\Device\\MyDevice" }` (`!devobj`) for the
   device type and characteristics; then `execute { "command": "!sd <SecurityDescriptor> 1" }`
   on the pointer it prints to decode the DACL (the *openable* gate). Inspect the symbolic link
   with `execute { "command": "!object \\GLOBAL??" }` for the *namespace* gate.

> **No PDBs.** Third-party drivers ship no symbols, so `module!Dispatch` won't resolve —
> everything is **address-based**. RVAs from static analysis must be **rebased to the live load
> base** (`modules {}` / `lm m <driver>`) before use, because of ASLR.

## Static enumeration — Binary Ninja (optional escalation)

When `uf` can't recover the switch (optimized/obfuscated dispatch, a computed sub-dispatch
table), load the `.sys` in Binary Ninja:

1. Find the dispatch routine (cross-reference the `MajorFunction[0x0e]` store near
   `DriverEntry`) and the `IoCreateDevice`/`IoCreateDeviceSecure` + `IoCreateSymbolicLink`
   calls.
2. Recover the `IoControlCode` switch constants, the expected input/output sizes per case, and
   the SDDL string passed to `IoCreateDeviceSecure`.
3. **Pin the `IO_STACK_LOCATION` offsets exactly.** With NT types applied (the wdm/ntddk type
   library, or the platform PDB), Binary Ninja shows the precise layout — and the dispatch
   routine's own prologue *reads* it, so you can lift the exact offsets from the disassembly
   instead of trusting a generic constant: `Irp->Tail.Overlay.CurrentStackLocation`
   (`Irp+0xb8` on x64), then within the `IO_STACK_LOCATION` `IoControlCode` (`+0x18`),
   `InputBufferLength` (`+0x10`), `OutputBufferLength` (`+0x08`), `Type3InputBuffer`/`UserBuffer`
   (`+0x20`). These confirm the `poi(@rdx+0xb8)+…` chain `ioctl_trace` uses — no runtime
   guesswork.
4. Emit a **JSON IOCTL map** for the dynamic step to join against. Suggested schema (one object
   per code):

   ```json
   {
     "code": "0x0022e004",
     "device_type": "0x0022",
     "function": "0x801",
     "method": "METHOD_BUFFERED",
     "required_access": "FILE_ANY_ACCESS",
     "case_rva": "0x14c0",
     "in_size": 8,
     "out_size": 4,
     "predicted_reachable": true
   }
   ```

   RVAs (`case_rva`) rebase to the live load base (`lm m <driver>`).

## Dynamic confirm (needs KDNET/VM)

A **local** kernel session is read-only — you cannot set code breakpoints or single-step. The
sweep requires a real **KDNET/VM** target via `attach_kernel`.

1. **Attach.** `attach_kernel { "connection": "net:port=<n>,key=<w.x.y.z>" }` — **ask the user
   for the real connection string** (see [live-and-kernel.md](live-and-kernel.md)).
2. **Install the sweep.** `ioctl_trace { "dispatch": "<dispatchVA-rebased>" }` installs a
   conditional logging breakpoint that prints `IOCTL <code> in=<n> out=<n>` and continues
   (`gc`) for every delivered IOCTL. It reads the current `IO_STACK_LOCATION` via
   `poi(@rdx+0xb8)` on x64. These offsets are the standard x64 layout — confirm them exactly
   from the Binary Ninja analysis above (the dispatch routine dereferences them directly), or
   at runtime with `execute { "command": "dt nt!_IRP" }` / `dt nt!_IO_STACK_LOCATION`.
3. **Drive the harness as the target token.** `go {}`, then from user mode run a sender (see
   `examples/sweep_ioctls.ps1`) that issues each candidate code **once as a low-priv token and
   again as admin**. Reachability is answered *as that user*: a code whose `RequiredAccess`
   exceeds the handle's granted access is rejected by the I/O manager and the breakpoint
   **never fires**.
4. **Classify.** For codes that do break in, `irp_stack {}` (defaults to `@rdx`) shows the
   `IoControlCode` + buffer lengths; let `go {}` return and read `Irp->IoStatus.Status` to tell
   a real handler (success / pending) from a `default:` rejection. Join the log against the
   static candidate map → label each code **delivered / taken-case / return-status /
   reachable-as-whom**.

## Pitfalls

- **Local kernel = read-only.** `attach_kernel_local` cannot set code breakpoints or step — the
  `ioctl_trace`/`irp_stack` sweep needs `attach_kernel` (KDNET/VM). The static walk
  (`driver_object`/`device_object`/`uf`/`decode_ioctl`) works fine locally.
- **The dispatch bp fires for *every* delivered IOCTL**, handled or not — it is noisy by design.
  The `default:` case still fires the bp; distinguish it by the return status, not the entry.
- **An IOCTL rejected by the I/O manager's `RequiredAccess` check never reaches the driver**, so
  the dispatch bp never fires for it. "bp didn't fire" can mean *not deliverable as this token*,
  not *not implemented* — that's why you run the harness under more than one token.
- **`@rdx` holds the PIRP only at the dispatch *entry*** (x64 fastcall arg2). After any
  `step_over`/`step_into` the register is clobbered; read `irp_stack` before stepping, or pass an
  explicit IRP address.
- **No PDBs → rebase.** Static RVAs are ASLR-relative; rebase to `lm m <driver>` before setting
  any breakpoint. See the symbol/elevation notes in [setup.md](setup.md) and
  [live-and-kernel.md](live-and-kernel.md).
