# Provider-crash walkthrough: turning a crash in somebody else's component into a report

The other walkthroughs here debug a target: a dump, a trace, a driver, a dying shell. This one
debugs **a Microsoft SDK component** — `vmsavedstatedumpprovider.dll`, the Windows SDK's reader for
Hyper-V saved states — and the deliverable is not a fix, because the code is not ours. It is a
**report someone else can act on**, which needs different evidence from a diagnosis: a repro small
enough to hand over, a trigger isolated by controls, and a list of the things it would be wrong to
claim.

It needs a Hyper-V host, the Windows SDK, and a VM you may power-cycle twice, so it is not
reproducible from the repo alone — but unlike
[`explorer-crash-walkthrough.md`](explorer-crash-walkthrough.md) the repro *is* checked in:
[`tools/vmsavedstate_load_probe.py`](../tools/vmsavedstate_load_probe.py), twelve lines calling one
export. Every output below is verbatim from the session of 2026-09-27 on this bench. There is no
recorded cast; if you want one, `WINDBG_MCP_TRANSCRIPT` plus `--render-cast` is the supported route
(see [`transcripts.md`](transcripts.md)).

> **Verdict up front:** `LoadSavedStateFile` **terminates the calling process** when handed a saved
> state captured from a VM with `EncryptStateAndVmMigrationTraffic` enabled. It is a **Guidelines
> Support Library contract violation** in
> `PartitionStateParser::GetPartitionStateVirtualProcessors`, whose handler calls `std::terminate`
> → `abort` → `__fastfail`. Not a corruption check, and not a parser that dies on anything it
> dislikes: random, truncated and header-corrupted input are all refused cleanly with
> `ERROR_FILE_CORRUPT`. The full report is
> [`secure-kernel/vmsavedstatedumpprovider-crash.md`](secure-kernel/vmsavedstatedumpprovider-crash.md).

**What this walkthrough is not.** It does not teach reading a `__fastfail` — the
[explorer walkthrough](explorer-crash-walkthrough.md) already does, at length, and
`src/fault.rs`'s decoder exists because of it. That knowledge is a *step* here, cited rather than
re-derived. What is new is everything around it.

## 1. The crash arrived while measuring something else

It was not hunted. `FOLLOWUPS.md` item 103's gate S0 established that a Hyper-V checkpoint carries a
VBS guest's VTL1 memory, and **arm 4** asked the follow-up: does
`EncryptStateAndVmMigrationTraffic` — the setting whose job is to protect saved state — cover it?
The answer is yes, and the way it announced itself was this:

```console
$ windbg-mcp --sk-inspect --vm "Lab Guest Control" --snapshot "…" --image C:\Windows\System32\securekernel.exe
kit        10.0.26100.0 (…\bin\10.0.26100.0\x64\vmsavedstatedumpprovider.dll)
image      C:\Windows\System32\securekernel.exe (1385944 bytes, 18 sections, …)
capture    D:\…\Snapshots\<id>.vmrs
exit=-1073740791
```

Three lines and then nothing. `-1073740791` is `0xC0000409`. **The gate's own answer was already in
hand** — no VTL1 came out — so the crash was a second, unrelated finding, and the discipline that
matters at this point is not to let it contaminate the first: the arm's conclusion rests on the
file, not on the provider's behaviour (§4).

## 2. What the OS says, and what it does not

```text
Faulting application name: windbg-mcp.exe, version: 0.20.0.0
Faulting module name:      vmsavedstatedumpprovider.dll, version: 10.0.26100.7705
Exception code:            0xc0000409
Fault offset:              0x000000000000d569
WER event name:            BEX64
```

Two things this is good for and one it is not. It **names the faulting module**, which is the whole
reason this is somebody else's bug rather than ours, and it gives an **offset** that later becomes a
cross-check. What it does not carry is the `FAST_FAIL_*` **subcode**, which is the first exception
parameter — and `0xc0000409` without it says almost nothing, its legacy name
(`STATUS_STACK_BUFFER_OVERRUN`) being a leftover rather than a diagnosis. The explorer walkthrough
dug the subcode out of `Report.wer`; §5 here takes it from the debugger instead.

**The trap worth naming.** A first draft of the report said *"`0xC0000409` means the corruption was
detected, so the mitigation did its job"*. That is the exact misreading this repo ships a decoder to
prevent, and it survived into a document intended for Microsoft until review cited
`src/fault.rs`'s own comment back at it. A status code's name is not evidence.

## 3. Isolate the trigger before diagnosing it

The most useful hour of this was not the debugger. It was building four files and calling one
function on each — because "it crashes on my capture" is not a report, and "it crashes on *this
class* of input and refuses these others" is.

```console
$ python tools/vmsavedstate_load_probe.py <plaintext capture>.vmrs
returned hr=0x00000000 handle=2460471302544
released

$ python tools/vmsavedstate_load_probe.py random.vmrs           # 4 MiB of RNG output
returned hr=0x80070570 handle=None

$ python tools/vmsavedstate_load_probe.py truncated.vmrs        # first 64 MiB of a real capture
returned hr=0x80070570 handle=None

$ python tools/vmsavedstate_load_probe.py corrupt-header.vmrs   # the same, first 512 bytes zeroed
returned hr=0x80070570 handle=None

$ python tools/vmsavedstate_load_probe.py <encrypted capture>.vmrs
calling LoadSavedStateFile
<no further output; exit 0xC0000409>
```

`0x80070570` is `ERROR_FILE_CORRUPT`. So the parser **has** a clean rejection path and uses it for
malformed input; the encrypted case is the one that is not on it. That single table changed what the
report claims — without it the honest framing would have been "this parser dies on bad input", which
is both weaker and, as the middle three rows show, false.

Two mechanical gotchas in building those files:

- **A running VM holds its `.vmrs` open.** `[IO.File]::OpenRead` fails with *"being used by another
  process"*; copying a slice needs
  `[IO.File]::Open($p,'Open','Read',[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)`. Copy,
  never truncate in place — the original is the evidence.
- **The probe must match the process, not the machine.** Picking the provider by
  `PROCESSOR_ARCHITECTURE` hands 32-bit Python the x64 DLL, and `ctypes.WinDLL` then refuses the
  image *before* the call under test — an unrelated loader error wearing the shape of the repro. The
  checked-in probe derives it from `sys.maxsize`.

## 4. Establish that the input is what you think it is

The report's claim is about *encrypted* captures, so "encrypted" has to be a reading rather than
Hyper-V's word for it. Two numbers, taken from the two captures:

| | first 16 bytes | entropy of 1 MiB at offset 16 MiB |
|---|---|---|
| plaintext | `14 20 28 01 B3 89 7E 1E 11 00 00 04 00 00 00 00` | 7.246 bits/byte |
| encrypted | `14 20 28 01 04 01 3E 40 11 00 00 04 00 00 00 00` | **8.000 bits/byte** |

Same container magic, same field at `+0x08`, payload at maximal entropy: a **well-formed file whose
body the provider has no key for**. That is the case a reader should refuse politely, and it is why
the crash is a defect rather than a garbage-in result.

**This measurement is also what rescues the gate it came from.** Arm 4 ran on the owning host with
the VM's key protector available — so had the provider *succeeded*, that would have been authorized
decryption and would have said nothing about how the bytes are stored on disk. Review raised exactly
that, and the answer was already here: the conclusion rests on the entropy reading, not on
provider-level reachability. If you take one transferable habit from this file, take that one — ask
what your instrument would have shown in the *other* outcome.

## 5. The subcode, through this server's own tools

The provider is a DLL in a process we can start under a debugger, so the fastest route to the
exception parameter is to launch the repro:

```text
launch { "command_line": "…\\python.exe …\\vmsavedstate_load_probe.py \"D:\\…\\<id>.VMRS\"" }
→ ntdll!LdrpDoDebuggerBreak+0x35, 14 modules, session sess-…-1

go { "session_id": "sess-…-1" }
→ ModLoad: …\vmsavedstatedumpprovider.dll
  ModLoad: …\dbghelp.dll
  (32b0.1634): Security check failure or stack buffer overrun - code c0000409 (!!! second chance !!!)
  Subcode: 0x7 FAST_FAIL_FATAL_APP_EXIT
```

`exception_triage` then gives the record and the stack, and the stack is the answer:

```text
kind: fail_fast     code: 0xc0000409     parameters: [0x7]     noncontinuable: true

vmsavedstatedumpprovider!abort                                                     +0xD569
vmsavedstatedumpprovider!terminate                                                 +0x19716
vmsavedstatedumpprovider!gsl::details::terminate                                   +0x40235
vmsavedstatedumpprovider!PartitionStateParser::GetPartitionStateVirtualProcessors  +0x3F294
vmsavedstatedumpprovider!VmSavedStateDumpContentProvider::…ctor                    +0x3AFCC
vmsavedstatedumpprovider!std::_Ref_count_obj2<VmSavedStateDumpContentProvider>…    +0x2A59B
vmsavedstatedumpprovider!LoadSavedStateFile                                        +0x35FFA
  libffi_8!ffi_call → _ctypes → python313!PyEval_EvalFrameDefault
```

Read bottom-up: `LoadSavedStateFile` constructs the content provider, the constructor parses the
partition state, and `GetPartitionStateVirtualProcessors` trips a **GSL contract**. GSL's
contract-violation handler terminates. The frame at `+0xD569` is the `abort` itself — which is the
offset WER reported in §2, and the debugger stopped at `0x7FFCEFBDD569` against a module base of
`0x7FFCEFBD0000`, so the two independent measurements agree to the byte.

**Note what the tool refused to say.** `exception_triage`'s summary reads: *"subcode 7 is the CRT's
`abort()`: an uncaught C++ exception ends here, but so does a direct `abort()`, a failed assert and
every other `terminate()` — and no throw record was found on this stack, so the record does not say
which."* It is the `gsl::details::terminate` frame, not the subcode, that identifies the mechanism.
A decoder that had guessed "uncaught exception" from subcode 7 would have been right about the
family and wrong about this instance.

## 6. What the report deliberately does not claim

A report is judged on its weakest sentence, so these are enumerated in it rather than left to a
reader:

- **No memory corruption.** A `__fastfail` is a deliberate exit and the failing frame is a contract
  check. No exploitability claim, and no crafted input was ever fed to it.
- **Which precondition, and on what value, is unknown.** The frame is named; the contract is not,
  and there are no private symbols to say.
- **Two processes, not two hosts.** The same fault offset came from CPython and from a Rust binary —
  which is what makes it the DLL's rather than a caller's — but both ran on this one machine, so it
  says nothing about other builds or other hardware.
- **One SDK version, x64 only.** 10.0.26100.7705. The ARM64 provider ships beside it, untried.
- **Hyper-V's own ability to read the file is an inference.** `Apply-VMSnapshot` was never run
  against the encrypted capture.

## 7. What to ask for

`LoadSavedStateFile` should return a failure `HRESULT`. The API already has the vocabulary — the
`VM_SAVED_STATE_DUMP_E_*` family, and this same parser already answers `ERROR_FILE_CORRUPT` for
input it cannot parse. The narrow version, given §5: **a contract check is the wrong instrument for
parsed input.** An encrypted payload is a legitimate way for a precondition about virtual-processor
state not to hold, so that path wants validation returning an error rather than a `terminate` — and
the fact that the malformed-input path already does the right thing is what makes this look like one
case that was missed rather than a design choice.

## 8. Lab gotchas, if you reproduce it

- **`Checkpoint-VM` honours the VM's *configured* checkpoint type.** The current default is
  *Production*, which uses VSS in the guest and saves **no memory state** — so the `.vmrs` will not
  contain what triggers this and you will reproduce nothing. `Set-VM -CheckpointType Standard`
  first. This was the finding that turned the repro from "works on my bench" into a procedure.
- **The encryption setting cannot be changed while the VM runs** (*"The SecuritySettingData property
  cannot be modified because the virtual machine is running"*), and reverting it hits the same
  refusal — so it is **two** stop/start cycles per guest, not one.
- **Use a guest whose in-guest state is expendable**, and put the setting back. Each arm also costs
  a checkpoint a good fraction of the guest's RAM.
