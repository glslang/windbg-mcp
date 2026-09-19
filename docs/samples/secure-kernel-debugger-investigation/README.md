# Secure Kernel debugger investigation evidence

Collected 2026-09-18 through 2026-09-19. This is a sanitized research archive, not a
successful VTL1 debugging transcript. See the [chronological validation record](../../secure-kernel-debugging-validation.md)
and [current plan](../../secure-kernel-debugging-plan.md).

## What is preserved

- `images.json`: SHA-256, exact version and size of each of the six compared x64 SK images;
  hashes of the local source logs and the published excerpts.
- `<version>.txt`: offline disassembly of `SkdInitSystem`, `SkdInitDebuggerDataBlock`,
  `IumpReadSecureKernelDebuggerInfo`, and `IumpDebugBreakRequestedByVtl0` from matching-symbol
  sessions. Headers, local paths, prompts and unrelated disassembly are omitted; instruction
  text is retained. Addresses use the offline preferred image base, not live load addresses.
  Excerpts use UTF-8 without a BOM and LF line endings, pinned by the local `.gitattributes`;
  their recorded hashes cover these published bytes.
- `observations.json`: selected live observations and query results transcribed from the
  validation record. This is a structured summary, not raw debugger output. Static explanations
  and experiment limitations remain explicit in the Markdown record.

The extraction deliberately excludes a misaligned raw-disassembly segment in the original
29671 status log. Source-log hashes establish which local artifacts supplied the excerpts;
they do not make those private artifacts publicly retrievable. Image identity does not, on
its own, attest to every experimental step.

## Findings and limits

All six compared images had a phase-zero metadata initialization call with zero return,
three constant zero information bytes, and a two-instruction zero-return break-request
routine. The 29671 live target never passed native SK attachment. Other matrix images were
not installed or tested live. A hash-verified 19041.207 sample lacked the three comparison
symbol names and remains unclassified. Mismatched downloads are excluded from the matrix.

The successful loader measurements and initialized hypervisor VTL1 buffers establish those
particular steps, not an uninterrupted end-to-end trace or a working SK transport session.
The ordinary system-information query's unsupported status originated in NT, not SK. Its
extended counterpart was an invalid missing-input probe, not a valid capability test.

## Repeat only the offline inspection

Obtain your own matching Windows image, record its SHA-256, and copy it into an analysis
directory. Do not replace a system binary. Download symbols through Microsoft's symbol
server into a local cache. For a file named `securekernel.exe`, open it as offline data:

```powershell
# Illustrative local paths; -z opens the image as data, not as a launched process.
& '<debugger-directory>\cdb.exe' -z '<analysis-directory>\securekernel.exe' `
    -y 'srv*<existing-symbol-cache>*https://msdl.microsoft.com/download/symbols'
```

Then inspect:

```text
lmvm securekernel
uf securekernel!SkdInitSystem
uf securekernel!SkdInitDebuggerDataBlock
uf securekernel!IumpReadSecureKernelDebuggerInfo
uf securekernel!IumpDebugBreakRequestedByVtl0
q
```

Check that `lmvm` reports matching PDB symbols, the intended image version and identity.
Renaming the image changes its debugger module name; adjust the commands accordingly.
Missing symbols are not a negative implementation result. Do not use these RVAs as live
breakpoints on another image. The live experiments required separate image verification,
BCD backups, console/checkpoint recovery, one controller, cleanup and explicit resume.

## Deliberately not published

No Windows binaries or PDBs, packet traces, raw BCD exports, DPAPI credentials, debugger
connection keys, memory dumps, or full native/MCP logs are included. They remain in the
existing local ignored/protected storage. No broad directory from `target/` is staged.
Machine-specific control helpers remain local; this archive is not an unattended reboot
or debugger-configuration harness.

The hardened outer host must remain unchanged. A separate nested lab is the selected next
direction, pending capacity and setup. This archive does not claim EXDI has been installed,
a checkpoint restored, or the future lab validated.
