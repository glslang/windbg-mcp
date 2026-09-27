# `vmsavedstatedumpprovider.dll` fast-fails on an encrypted Hyper-V saved state

A defect in a Microsoft-shipped SDK component, found while running gate S0 arm 4 of
[`FOLLOWUPS.md`](../../FOLLOWUPS.md) item 103. It is **not** the Secure Kernel question that work was
about, and it is not a VBS boundary bypass — that question was asked separately and answered *no*, in
[the feasibility record](secure-kernel-hypercall-feasibility.md). This file is the report, written so
it can be sent as it stands.

## Summary

`LoadSavedStateFile` terminates the calling process when handed a saved state captured from a VM with
`EncryptStateAndVmMigrationTraffic` enabled. It does not return a failure `HRESULT`: the process dies
inside the call with `0xC0000409` (`STATUS_STACK_BUFFER_OVERRUN`), which is a **fast-fail** and
therefore uncatchable — no `try`/`except`, no SEH handler and no `catch_unwind` in the caller sees it.

The same function **refuses corrupt, truncated and random input cleanly**, with
`0x80070570` (`ERROR_FILE_CORRUPT`). So this is not a parser that gives up loudly on anything it
dislikes; the encrypted-capture path specifically is the one that is not handled.

## Impact

Availability and robustness, in a component whose whole job is parsing files:

- **A caller cannot defend against it.** A fast-fail bypasses exception handling by design, so any
  tool built on this API — memory-forensics tooling, a debugger front end, anything that enumerates
  a host's checkpoints — is killed by one encrypted capture and cannot degrade gracefully or report
  which file did it.
- **The input is ordinary and legitimate.** Nothing crafted it. Hyper-V wrote it, from a supported
  configuration, using the setting Microsoft documents for protecting saved state.
- **Not demonstrated to be more than that.** `0xC0000409` means a corruption check *fired*, so the
  mitigation did its job; nothing here shows memory corruption that escaped it, and no crafted input
  was tried. This is reported as a crash, not as a memory-safety vulnerability.

Worth one factual note on who can supply the input, without a claim attached: a `.vmrs` is a file, so
its ACL is the boundary. On the bench this was found on, the checkpoint files inherited the data
volume's permissive ACL (`BUILTIN\Users: ReadAndExecute`, `Authenticated Users: Modify`) because
Hyper-V adds its own ACEs without removing inherited ones. That is a storage-path configuration
matter rather than a product defect, and it is mentioned only because it bears on who could put a
file in front of this parser.

## Environment

| | |
|---|---|
| Host OS | Windows 11 Pro, 10.0.26200, x64 (Intel Core i7-14700) |
| SDK component | `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\vmsavedstatedumpprovider.dll` |
| Component version | **10.0.26100.7705**, timestamp `0xFDF113F8` |
| Header | `Include\10.0.26100.0\um\VmSavedStateDump.h` (function), `…\VmSavedStateDumpDefs.h` (`REGISTER_ID`) |
| Guest | Generation 2 (configuration version 12.0), 4 GiB RAM, vTPM enabled; its `securekernel.exe` identifies as the host's 10.0.26100.9457 build |
| Reproduced on | two different VMs — one with VBS/HVCI on, one with it off — and from two unrelated host processes |
| Date | 2026-09-27 |

## Minimal reproduction

1. On a Hyper-V host, take any Generation 2 VM with a key protector (a vTPM is enough), **shut it
   down**, and enable encrypted saved state:

   ```powershell
   Stop-VM -Name 'Some VM'
   Set-VMSecurity -VMName 'Some VM' -EncryptStateAndVmMigrationTraffic $true
   Start-VM -Name 'Some VM'
   ```

   The setting cannot be changed while the VM runs — *"The SecuritySettingData property cannot be
   modified because the virtual machine is running"* — which is why this needs a power cycle.

2. Take a **standard** checkpoint of the running VM, which is what writes a `.vmrs` containing saved
   memory and register state:

   ```powershell
   Checkpoint-VM -Name 'Some VM' -SnapshotName 'repro'
   ```

3. Call `LoadSavedStateFile` on that `.vmrs`. The whole repro is one call;
   [`tools/vmsavedstate_load_probe.py`](../../tools/vmsavedstate_load_probe.py) in this repository is
   twelve lines of `ctypes` that does nothing else:

   ```console
   python tools/vmsavedstate_load_probe.py "D:\...\Snapshots\<id>.vmrs"
   provider C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\vmsavedstatedumpprovider.dll
   capture  D:\...\Snapshots\<id>.vmrs (<size> bytes)
   calling LoadSavedStateFile
   ```

   — and there is no fourth line. The process is gone, exit code `0xC0000409`.

The equivalent C is `LoadSavedStateFile(path, &handle)` with nothing before it but the `LoadLibrary`.
The crash is in the call, before any other entry point is reached: no handle exists yet, no VTL has
been selected and no memory has been read.

## What the OS records

```text
Faulting application name: python.exe, version: 3.13.14150.1013
Faulting module name:      vmsavedstatedumpprovider.dll, version: 10.0.26100.7705, timestamp 0xfdf113f8
Exception code:            0xc0000409
Fault offset:              0x000000000000d569
WER event name:            BEX64
```

**The same fault offset appears from an unrelated host process** — a Rust binary calling the same
export through its own FFI produced `0xC0000409` at `0xD569` as well. Two hosts with nothing in
common but this DLL, one offset: the fault is in the provider and is deterministic, not a property of
either caller.

## The control matrix, which is what makes the trigger specific

One call, one file, four inputs, same provider and same session:

| input | result |
|---|---|
| plaintext `.vmrs` from the same VM | `hr=0x00000000`, handle returned, released cleanly |
| **encrypted `.vmrs`** | **process terminated, `0xC0000409` at `+0xD569`** |
| 4 MiB of random bytes named `.vmrs` | `hr=0x80070570` (`ERROR_FILE_CORRUPT`) |
| first 64 MiB of a real plaintext capture (truncated) | `hr=0x80070570` |
| the same 64 MiB with its first 512 bytes zeroed | `hr=0x80070570` |

So the parser already has a clean rejection path and uses it for malformed input. The encrypted case
is not taking that path.

## The input is a well-formed container with an encrypted payload

Measured on the two captures above, so that "encrypted" is a reading rather than an assumption:

| | first 16 bytes | entropy of 1 MiB at offset 16 MiB |
|---|---|---|
| plaintext | `14 20 28 01 B3 89 7E 1E 11 00 00 04 00 00 00 00` | 7.246 bits/byte |
| encrypted | `14 20 28 01 04 01 3E 40 11 00 00 04 00 00 00 00` | **8.000 bits/byte** |

The container magic and the field at `+0x08` are identical; the payload is at maximal entropy. The
provider is therefore being handed a file it can recognise, whose contents it has no key for — which
is the case one would expect to be a clean `E_ACCESSDENIED`-shaped refusal.

## Expected behaviour

A failure `HRESULT`. The API already has a vocabulary for this — the `VM_SAVED_STATE_DUMP_E_*` family
in `VmSavedStateDumpDefs.h`, of which this work has seen `0xC0370509`
(`VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED`) returned cleanly for another unsupported request — and
`ERROR_FILE_CORRUPT` is already returned for input it cannot parse. Anything in that shape lets a
caller say *"this capture is encrypted and I cannot read it"* and carry on to the next file.

## What was not tested

Stated so the report is not read as broader than it is:

- **No crafted input.** Nothing here fabricated or mutated an encrypted capture to probe the fault
  further, and no attempt was made to determine whether the corruption check can be avoided.
- **One SDK version, one architecture.** 10.0.26100.7705, x64 provider in an x64 process. The ARM64
  provider ships beside it and was not exercised; no other kit version is installed on this host.
- **Shielded VMs and `Save-VM`.** Only the checkpoint form was produced. A shielded VM, and the
  older `.bin`/`.vsv` pair that `LoadSavedStateFiles` takes, are untested.
- **Whether Hyper-V itself can read the same file.** Presumably yes, but `Apply-VMSnapshot` was not
  run against it, so the container's well-formedness rests on the header and entropy readings above
  rather than on a successful restore.
- **Live saved state.** `Save-VM` output was not tried; only a standard checkpoint of a running VM.

## How this was found

Not by fuzzing. Item 103's gate S0 established that a Hyper-V checkpoint carries a VBS guest's VTL1
memory and its page-table root, readable through this provider as documented. Arm 4 of that gate
asked the obvious follow-up — *does `EncryptStateAndVmMigrationTraffic` cover it?* — and the answer
is yes: with the setting on, nothing comes out. It does not come out because the provider crashes
before returning, which is how this defect surfaced. The security question that prompted arm 4 is
answered in [the feasibility record](secure-kernel-hypercall-feasibility.md), and its answer is that
reading a guest's VTL1 from a host-side capture is documented behaviour inside the boundary VBS
claims, not a bypass.
