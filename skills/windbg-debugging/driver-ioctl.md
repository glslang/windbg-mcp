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
| **Openable** | Can this token open the device at all? | `device_object` → `SecurityDescriptor` pointer + `FILE_DEVICE_SECURE_OPEN` (decode the DACL with `!sd <ptr>` where that extension is present) |
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
   device type, characteristics, and `SecurityDescriptor` pointer (the *openable* gate). Where the
   `!sd` extension is present, `execute { "command": "!sd <SecurityDescriptor> 1" }` decodes the
   DACL; it is not in the bundled engine, so otherwise inspect the SD by address. Inspect the
   symbolic link with `execute { "command": "!object \\GLOBAL??" }` for the *namespace* gate.

> **Symbols — ask for the PDB when it exists.** Production/third-party drivers usually ship no
> PDB, so `module!Dispatch` won't resolve and you work **address-based** (rebase static RVAs to the
> live load base — `modules {}` / `lm m <driver>` — because of ASLR). **But if the user built the
> driver or has its PDB, symbols are available** and make everything readable. Find the exact PDB
> the engine wants with `execute { "command": "!sym noisy; .reload /f <driver>.sys" }` (it prints
> `<pdb>\<GUID>\…`), then **ask the user for the folder holding that PDB** — it must be on *this*
> debugger host (symbols are never pulled from the target over the KD wire) — and apply it with
> `set_symbol_path { "path": "<folder>", "reload": "/f <driver>.sys" }`. Names like
> `HEVD!IrpDeviceIoCtlHandler` / `HEVD!ArbitraryWriteIoctlHandler` then resolve.

## Static reachability — dispatch → handler (`reachable_from_dispatch`)

Once you have the dispatch VA and a handler VA of interest, `reachable_from_dispatch { "from":
"<dispatchVA-or-symbol>", "address": "<handlerVA>" }` runs a bounded control-flow walk and returns
**REACHABLE** (with the call path) or **NOT REACHABLE** (within bounds). With `recipe: true`
(default) it also emits the **on-path branch directions and the compare that gates each** — for the
common MSVC binary-search `switch (IoControlCode)`, that recipe pins the **exact `IoControlCode`**
routing to that handler. This is the fast way to answer "which IOCTL triggers handler X" and to
prove a bug block is reachable from the dispatch entry.

Then **confirm it live** (needs KDNET/VM): `run_to_address { "address": "<handlerVA>" }` runs the
target and reports **HIT / STOPPED-ELSEWHERE / TIMEOUT** once a user-mode client sends that IOCTL —
closing the static→dynamic loop without a scripted breakpoint.

> `reachable_from_dispatch` does **not** follow indirect `call [ptr]`/`call reg` or unresolved jump
> tables — REACHABLE is sound; NOT-REACHABLE only means "not found within bounds". For a jump-table
> dispatch, pass the specific handler VA as `from` to scope past the switch. (Its boilerplate
> "indirect jump table" note prints even when the dispatch is actually a direct compare chain it
> *did* follow.)

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

## Write the report

Close the workflow with a written report so the result is reviewable. Keep it grounded in the
tool output you gathered (cite the live addresses / DACL / codes — don't assert from memory). A
worked end-to-end examples are
[`docs/driver-ioctl-walkthrough.md`](../../docs/driver-ioctl-walkthrough.md) (Mount Point Manager —
the four reachability gates on a built-in driver) and
[`docs/hevd-ioctl-walkthrough.md`](../../docs/hevd-ioctl-walkthrough.md) (HEVD — a *service-loaded*
third-party driver with a user PDB, `set_symbol_path`, and the `reachable_from_dispatch` /
`run_to_address` loop). Structure:

1. **Verdict up front** — one paragraph: which IOCTLs a standard user can reach, which are
   blocked and by which gate. State the target driver/device + build.
2. **Openable gate** — the device DACL (principal → granted access) and `FILE_DEVICE_SECURE_OPEN`;
   note the access a normal user's handle actually gets.
3. **Discovered IOCTLs** — the full static set from `uf`, grouped by `RequiredAccess` tier
   (`FILE_ANY_ACCESS` / `READ` / `READ|WRITE`), each row: code, handler/name, function, method.
   Flag any `METHOD_NEITHER` or `FILE_ANY_ACCESS` *mutators*.
4. **Reachability** — per tier, the verdict for **standard user** vs **admin/SYSTEM**, with the
   reason (DACL grant vs `RequiredAccess`, plus any in-dispatch privilege check).
5. **Dynamic confirmation** — what `ioctl_trace`/`irp_stack` actually observed, and the token it
   ran under (note: a sweep run as admin does *not* prove standard-user reachability). Reachable
   means **delivered** (the dispatch bp fires), *not* that `DeviceIoControl` returned success — a
   dummy/short buffer often makes the call fail (`ERROR_INSUFFICIENT_BUFFER`/`INVALID_PARAMETER`)
   while the IRP still reached the driver. The blocked signal is `ERROR_ACCESS_DENIED (5)` with no
   bp hit (rejected at the I/O-manager gate).
6. **Caveats** — anything not fully expanded (e.g. a jump-table group), and the optional
   empirical check: run `examples/send_ioctls_target.ps1` as a non-admin token in the guest.

Save it under `docs/` (the repo's walkthrough convention) or hand it back inline.

## Pitfalls

- **Local kernel = read-only.** `attach_kernel_local` cannot set code breakpoints or step — the
  `ioctl_trace`/`irp_stack` sweep needs `attach_kernel` (KDNET/VM). The static walk
  (`driver_object`/`device_object`/`uf`/`decode_ioctl`) works fine locally.
- **Kernel-object commands need `kdexts.dll`.** `!drvobj`/`!devobj`/`!irp` (behind
  `driver_object`/`device_object`/`irp_stack`) come from `kdexts.dll`. `attach_kernel` /
  `attach_kernel_local` `.load` it automatically, but it must be bundled (`winxp\kdexts.dll`,
  see [setup.md](setup.md)); without it the tools return *"No export drvobj found"*.
- **The dispatch bp fires for *every* delivered IOCTL**, handled or not — it is noisy by design.
  The `default:` case still fires the bp; distinguish it by the return status, not the entry.
- **An IOCTL rejected by the I/O manager's `RequiredAccess` check never reaches the driver**, so
  the dispatch bp never fires for it. "bp didn't fire" can mean *not deliverable as this token*,
  not *not implemented* — that's why you run the harness under more than one token.
- **`@rdx` holds the PIRP only at the dispatch *entry*** (x64 fastcall arg2). After any
  `step_over`/`step_into` the register is clobbered; read `irp_stack` before stepping, or pass an
  explicit IRP address.
- **Caught the driver at *load*? Its dispatch table isn't populated yet.** For a driver that loads
  after boot, `sxe ld:<drv>.sys` + `go` stops *before* `DriverEntry` runs, so `driver_object` shows
  default handlers (or "is not a driver object"). Let `DriverEntry` finish first: compute the PE
  entry point `? <base> + dwo(<base> + dwo(<base>+0x3c) + 0x28)`, `set_breakpoint` it and `go`; at
  entry `@rcx` is the `DriverObject` and `poi(@rsp)` the return into `nt!PnpCallDriverEntry` —
  breakpoint that return, `go`, and now `MajorFunction[0x0e]` (at `DriverObject+0xe0`) is the real
  dispatch. (A driver already loaded when you attach needs none of this — just `driver_object`.)
- **No PDBs → rebase.** Static RVAs are ASLR-relative; rebase to `lm m <driver>` before setting
  any breakpoint. See the symbol/elevation notes in [setup.md](setup.md) and
  [live-and-kernel.md](live-and-kernel.md).
