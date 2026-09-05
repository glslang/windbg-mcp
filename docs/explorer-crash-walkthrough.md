# Explorer walkthrough: debugging the machine the server runs on

Every other walkthrough here opens a checked-in sample. This one does not: the target was
**this server's own host**, a Windows 11 26200 VM whose shell had stopped starting, and the
dumps were captured, read and deleted in one sitting. So it is not reproducible from the repo —
what it offers instead is the shape of a user-mode investigation driven entirely through the
`windbg` MCP tools, and three faults in a row where the answer was a **thrown HRESULT that no
typed tool returns**.

It is also the only walkthrough where the debugger and the debuggee were the same machine. That
works because a session lives in its own worker process (see
[`architecture.md`](architecture.md)) — the engine holding a 345 MB dump of `Explorer.EXE` is not
the process serving MCP, and neither is the shell that keeps dying.

> **Verdict up front:** the AppModel **State Repository** database
> (`StateRepository-Machine.srd`, SQLite) was malformed. Explorer's tray initialisation calls a
> WinRT API that reads it, the failing HRESULT propagates through `winrt::check_hresult` as a C++
> exception, nothing catches it, and `terminate` → `abort` → `__fastfail` kills the shell before a
> desktop exists. Repairing the database exposed two more faults behind it, each found the same
> way.

## 1. Cheap evidence first — the debugger is not the first move

`Get-Process explorer` returned nothing, and Windows Error Reporting had 42 crashes that day, all
one bucket:

```text
Faulting application name: explorer.exe, version: 10.0.26100.9168
Faulting module name: ucrtbase.dll, version: 10.0.26100.8875
Exception code: 0xc0000409
Fault offset: 0x00000000000a527e
```

`0xc0000409` is `STATUS_STACK_BUFFER_OVERRUN`, which on a modern build almost never means a stack
buffer overrun — it is the code `__fastfail` raises. WER's own `Report.wer` carries the subcode:

```text
Sig[7].Value=c0000409          ← Exception Code
Sig[8].Value=0000000000000007  ← Exception Data
```

Subcode **7** is `FAST_FAIL_FATAL_APP_EXIT`, and in `ucrtbase` that is `abort()`. So before
opening a debugger the shape was already known: not corruption, not a bad pointer — a *deliberate*
process exit, which for C++ means an exception nobody caught.

Two more things the report settled for free. `LoadedModule[0..87]` were **all** under
`C:\Windows` — no third-party DLL in the process, so no shell extension to hunt. And 88 modules is
early: a healthy Explorer carries a couple of hundred.

The image itself was ruled out separately — `Get-FileHash` matched the WinSxS copy and
`Get-AuthenticodeSignature` returned `Valid`, so nothing had been tampered with.

## 2. Capturing a dump on demand

WER archives a `Report.wer` but no dump by default. Arming `LocalDumps` for one executable, with
a full dump, is three registry values:

```pwsh
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\explorer.exe'
New-Item -Path $k -Force | Out-Null
New-ItemProperty -Path $k -Name DumpFolder -Value $dumpDir -PropertyType ExpandString -Force
New-ItemProperty -Path $k -Name DumpType   -Value 2 -PropertyType DWord -Force   # 2 = full
New-ItemProperty -Path $k -Name DumpCount  -Value 2 -PropertyType DWord -Force
```

Then `Start-Process C:\Windows\explorer.exe`, wait, and there is a 122 MB `.dmp`. The crash
reproduced in about two seconds every time, which is the luxury this investigation had and most do
not.

> **Cap `DumpCount`.** Later on, with the shell auto-restarting, Explorer was crashing ~27 times a
> minute and each dump was 345 MB. Left at its default the loop would have written the volume full;
> at 2 it merely churned. `AutoRestartShell=0` under `Winlogon` is the switch that stops the loop
> itself while you work.

## 3. Opening it

```jsonc
open_dump { "path": "…/scratchpad/dumps/explorer.exe.4664.dmp" }
```

```text
Windows 10 Version 26200 MP (4 procs) Free x64
Debug session time: Wed Aug 26 23:16:20.000 2026 (UTC + 1:00)
System Uptime: 0 days 0:14:43.360
Process Uptime: 0 days 0:00:02.000

88 module(s) loaded, `explorer` at 0x00007ff6bbb50000.
```

Nothing about the surface changes for a user-mode dump — same opener, same `session_id`, same
`end_session`. `Process Uptime: 2 seconds` corroborates WER: it dies during startup, not in use.

> **Gotcha, and it cost a call:** with `DumpCount` set, WER *rotates* files. A dump opened by
> path a minute after it was written can already be gone — `open_dump` answered
> `The system cannot find the file specified. (0x80070002)`. Copy the dump to a stable path
> before opening it.

## 4. Reading a fail-fast

The engine's own exception record is what you want, not the current thread's registers:

```jsonc
execute { "command": ".exr -1" }
```

```text
ExceptionAddress: 00007ffd98c5527e (ucrtbase!abort+0x000000000000004e)
   ExceptionCode: c0000409 (Security check failure or stack buffer overrun)
NumberParameters: 1
   Parameter[0]: 0000000000000007
Subcode: 0x7 FAST_FAIL_FATAL_APP_EXIT
```

Then `.ecxr` to adopt the crash context, and the stack:

```jsonc
execute { "command": ".ecxr; k 40" }
```

```text
ucrtbase!abort+0x4e
ucrtbase!terminate+0x1e
ucrtbase!__crt_state_management::wrapped_invoke<...>
explorer!_scrt_unhandled_exception_filter+0x5a
KERNELBASE!UnhandledExceptionFilter+0x1f3
ntdll!RtlUserThreadStart$filt$0+0x3f
...
KERNELBASE!RaiseException+0x8a
ucrtbase!CxxThrowException+0x96
explorer!winrt::throw_hresult+0x223
explorer!winrt::check_hresult+0x1f
explorer!winrt::impl::consume_Windows_UI_Internal_Input_IShellGesturesControllerStatics<…>::CreateForInputSite+0x4c
explorer!CTray::Init+0xe8
explorer!CreateDesktopAndTray+0x92
explorer!wWinMain+0x92e
```

Read it bottom-up and the whole story is there: the tray is being built, it calls a WinRT method,
`check_hresult` did not like the answer and threw, the throw reached the top of the thread
unhandled, and the CRT killed the process. `backtrace` returns the same frames as typed records
with `module` + `rva`; `k` was used here because the C++ and WinRT template frames are the
interesting part and `k` prints them verbatim.

What the stack does **not** say is *which* HRESULT. That is the whole question, and it is in the
thrown object.

## 5. Digging the HRESULT out of a C++/WinRT throw

A C++ exception on Windows is a real SEH exception with code `0xE06D7363` (`"msc"` with a byte
on the front), and its `ExceptionInformation` carries a pointer to the thrown object. The record
is on the stack, between the throw site and `RaiseException`, so search for it:

```jsonc
execute { "command": "s -d 0x87ef00 L400 e06d7363" }
```

```text
00000000`0087f058  e06d7363 00000000 e06d7363 00000081  csm.....csm.....
```

Rather than trusting a fixed offset into `EXCEPTION_RECORD` — which is easy to get off by one slot,
and was, first time — use **two landmarks**:

- `0x19930520` is the C++ EH magic. The pointer that follows it is the **thrown object**.
- A `winrt::hresult_error` carries a `0xAABBCCDD` sentinel immediately before its `m_code`.

```jsonc
execute { "command": "dd 0x87f1d0+8 L2" }
```

```text
00000000`0087f1d8  aabbccdd 80670015
```

The sentinel is the confirmation you have the right object, and the dword after it is the code.
Then let the debugger name it:

```jsonc
execute { "command": "!error 0x80670015" }
```

```text
Error code: (HRESULT) 0x80670015 (2154233877) - The StateRepository cache is not initialized.
```

That is the answer, from a public-symbols dump, with no private types and no source.

> **Be honest about what that layout is.** The `0xAABBCCDD`-then-`m_code` adjacency is read off
> the bytes, not off a PDB — C++/WinRT's own header is the authority and no symbol here confirms
> the offset. It is trustworthy *because* it was cross-checked: the same shape appeared in three
> unrelated dumps, and each time `!error` turned the dword into a sentence that matched the
> failing subsystem. A number that decodes to a plausible message is evidence; a number at an
> assumed offset is not.

## 6. Corroborating outside the debugger

A single dump can mislead. Two checks confirmed it independently and took seconds:

```pwsh
Get-AppxPackage
# The StateRepository cache is not initialized. (Exception from HRESULT: 0x80670015)
```

The same HRESULT from an unrelated caller — so it is the repository, not something explorer does
to it. And the service's own log names the real damage:

```text
CriticalError 0x87AF000B: [sqlite3_step] Database N: database disk image is malformed
  : SQL SELECT p.PackageFullName FROM Package AS p INNER JOIN PackageFamily …
Error 0x87AF000B: Database corruption detected in partition 1
Error 0x87AF000B: SRCache initialization encountered an error
```

390 critical events, first at 17:53 that afternoon. Six unclean shutdowns the same day
(`Kernel-Power 41`) with **no** minidumps and no `MEMORY.DMP` — hypervisor resets rather than bug
checks, which is exactly what tears a SQLite file mid-write. The debugger found the failing call;
the event log found the cause.

## 7. Round two — same tray, a different fail-fast

Renaming the corrupt databases (via `PendingFileRenameOperations`, which `smss.exe` applies before
any service can open the files) got a clean repository — and a *new* crash, this time with the
faulting module reported as `explorer.exe` itself:

```text
ExceptionAddress: 00007ff7aae5a72b (explorer!CTray::Init+0x00000000000002d7)
   ExceptionCode: c0000409
NumberParameters: 3
   Parameter[0]: 0000000000000007
   Parameter[1]: ffffffff8000ffff
   Parameter[2]: 000000000000028f
```

A different shape of the same code. This is not the CRT's `abort` — it is **WIL**:

```text
explorer!wil::details::WilRaiseFailFastException+0x17
explorer!wil::details::ReportFailure_Hr<3>+0x4b
explorer!wil::details::in1diag3::FailFast_Unexpected+0x1b
explorer!CTray::Init+0x2d7
```

and here the HRESULT needs no object walk at all: `Parameter[1]` is it, sign-extended —
`0x8000FFFF`, `E_UNEXPECTED`. `Parameter[2]` is `0x28F` = 655, a line number. `ub` back from the
fail-fast shows WIL's call being set up, and the string it is handed is worth reading:

```jsonc
execute { "command": "da 0x7ff7aaf9f9b0" }
```

```text
00007ff7`aaf9f9b0  "pcshell\shell\explorer\tray.cpp"
```

So: `tray.cpp` line 655. Two fail-fast shapes, two entirely different retrieval routes for the
same fact — read the record's parameter count first and it tells you which one you have.

## 8. Round three — the taskbar, and an HRESULT that named the remaining work

With the shell's packages partly re-registered, Explorer got much further — **197** modules
against 88 — and died inside `Taskbar.dll`:

```text
Taskbar!winrt::throw_hresult+0x223
Taskbar!winrt::check_hresult+0x1e
Taskbar!…consume_WindowsUdk_System_IKnownActivationPropertiesStatics<…>::ActivationType+0x56
Taskbar!…XamlExplorerHost::XamlApplication::Current+0x66
Taskbar!TrayUI::TryLoadTaskbarFromXamlExtension+0x4c
Taskbar!TrayUI::TryInitializeUndockedComponents+0x31
Taskbar!TrayUI::StartTaskbar+0x93
explorer!CTray::_StartTaskbarApiSurface+0x8f
```

Same technique as §5 — search, sentinel, `!error`:

```text
00000000`0466ead8  aabbccdd 80073d54
Error code: (HRESULT) 0x80073d54 - The process has no package identity.
```

Which pointed at the remaining work: the rebuilt repository had come back **empty**, and at that
moment 23 of the 44 `C:\Windows\SystemApps` packages were registered — `Microsoft.UI.Xaml.CBS`,
the WinUI framework this XAML host loads, among the missing. Re-registering that directory —
**twice**, because a package whose framework is not yet registered fails on the first pass and
succeeds on the second — took registrations from 23 to 44 and the shell came up.

Note what is *not* claimed there. `0x80073D54` says the process had no package identity at that
call; it does not by itself prove that registering the XAML framework is what granted it. The
four identity-bearing shell packages were already registered and still the call failed, so the
mechanism was never pinned down — what is established is the fix, not the chain. Saying which is
which costs a sentence and saves the next reader an afternoon.

## 9. What this exercised, and the gap it found — since closed

Three faults, three dumps, and the useful part is what each one needed:

| Fault | What answered it, in 2026-08 |
| --- | --- |
| `abort` in `ucrtbase` | `.exr -1` for the subcode, `k` for the throw path, object walk for the HRESULT |
| WIL `FailFast_Unexpected` | `.exr -1` alone — the HRESULT is a fail-fast parameter |
| `abort` in `Taskbar.dll` | identical to the first, in a different module |

**The typed surface got to the frame and stopped there.** `open_dump` and `backtrace` were enough
to say *where* a C++/WinRT process died, and in all three cases the fact that mattered — the
HRESULT — came out of `execute`: `.exr`, `.ecxr`, `s -d`, `dd`, `!error`, `ub`, `da`. That was the
escape hatch doing its job, and it was a legible argument for a primitive this server did not have:
*given a user-mode dump that died on an unhandled C++ exception, return the thrown HRESULT and its
message*. The routine is mechanical — find the `0xE06D7363` record, take the object after the EH
magic, decode — and it was performed by hand three times in one evening.

**It is `exception_triage` now**, on the primitives [dbgscope#144] added: `last_event` and
`stored_event` for the record, and `stack_frames_from` for the crash stack — which is what `.ecxr`
adopts, walked without `.ecxr`'s effect on the session, so the caller's selected thread stays where
they left it. §4 and §5 are one call:

```text
EXCEPTION: 0xc0000409 at 0x00007ff79e442989
  The system detected an overrun of a stack-based buffer in this application. […]
  second chance — nothing in the target handled it, noncontinuable
  Parameter[0]: 0x0000000000000007
WHAT THIS IS: a __fastfail — a deliberate process exit, not a stack buffer overrun, whatever the
  code's name and the system's message text for it say. FAST_FAIL_FATAL_APP_EXIT (subcode 0x7) is
  what says why. Subcode 7 is the CRT's abort(): an uncaught C++ exception ends here, but so does a
  direct abort(), a failed assert and every other terminate(). A C++ throw record was found on this
  stack — THROWN below — and such a record outlives the frames that held it, so confirm the throw
  site is on the stack above before calling it the cause.
THROWN: hresult_error at 0x00000054f7cff950
  carries 0x80670015 — The StateRepository cache is not initialized.
  the thrown type named winrt::hresult_error and the sentinel then matched inside the object: two
  routes agreeing, so the offset was expected rather than assumed.
  CAUTION: found by scanning the stack rather than reported by the debugger. Such a record outlives
  the frames that held it, so this may be from an exception the program caught earlier rather than
  the cause of this fault.
```

**That block is real output**, captured from `docs/samples/cppthrow-fastfail.dmp` — the fixture
built to reproduce this crash's shape, which is why the HRESULT is the same and the addresses are
not. Pasting it rather than paraphrasing is deliberate: an earlier revision of this section showed a
sample ending *"subcode 7 is the CRT's abort(), which means a C++ exception nobody caught"*, and the
tool had stopped saying that — so a reader following the walkthrough was pointed at a C++ exception
in exactly the cases where there may not have been one.

Note the second and third lines together, because that pairing is the point rather than a
flourish: the tool prints the system's own message for `0xc0000409` — the misleading one §10's
first gotcha is about — and then says what the code actually means. Suppressing it would leave a
reader who has met that sentence in an event log unable to place it.

**And note what it does not say.** Subcode 7 is `abort`, and `abort` is reached by a direct call, a
failed `assert`, the invalid-parameter handler and every other `terminate()` as well as by an
uncaught throw — so the summary names the throw only because the scan actually found a record, and
then calls it a candidate rather than the cause. A record found that way outlives the frames that
held it, which is what the `CAUTION` line and the `scanned` provenance are for. Where no search runs
— `scan_stack` off, or a fault shape that never buries one — the summary says *that*, rather than
reporting an empty result for a hunt that never happened.

**Three things about the version that shipped differ from the recipe above, and each is a
correction rather than a refinement.**

*The type is decoded, not assumed.* MSVC's throw passes four parameters — magic, thrown object,
`ThrowInfo`, image base — and `ThrowInfo → CatchableTypeArray → CatchableType → TypeDescriptor`
yields the mangled type name from a layout the compiler fixes. So the `0xAABBCCDD` sentinel is no
longer the thing that *finds* the code; it is the thing that confirms an offset the type name
already predicted, which is the cross-check §5 argued for, made mechanical. The result says which
it got: `corroborated` when both routes agree, `convention` when only the sentinel does.

*Both routes are needed, because neither is a superset.* `ThrowInfo` and everything it points at
live in the **image**, and a `MiniDumpNormal` does not capture that — the debugger reads it off the
binary on disk. Measured: the walk succeeds on a WER minidump while the executable is at its
recorded path, and returns `????????` once it is moved aside. So on a dump from another machine the
sentinel scan of the thrown object — which is on the *stack*, and therefore captured — is the only
route there is.

*The throw's record is searched for, not read.* When a C++ exception goes unhandled the event the
debugger sees is `abort`'s fail-fast; the throw's own record is a local of a frame between the
throw site and `RaiseException`, and no engine call returns it. `exception_triage` scans the
crashing thread's stack for it, bounded by the frames it has already walked — which is §5's
`s -d` with the range derived rather than eyeballed.

The other note on that list is closed too. **`!error` earned its place** — three times it turned a
bare dword into the sentence that redirected the whole investigation — and it is
`decode_error_reporting` now, which is a **pure host call** rather than a scrape of the extension's
output: `FormatMessageW` was measured to answer for both of this investigation's exotic codes
verbatim, `0x80670015` and `0x80073D54`, and an `NTSTATUS` resolves from `ntdll`'s table beside it.
It takes a sign-extended 64-bit value because that is the shape §7's HRESULT arrives in —
`0xffffffff8000ffff` decodes to `E_UNEXPECTED`.

And **nothing about a user-mode dump of a live process needed special handling**: same opener, same
routing, same `end_session`, on a machine where the debuggee was the shell of the box running the
server.

[dbgscope#144]: https://github.com/glslang/dbgscope/pull/144

## 10. Gotchas worth keeping

- **`0xc0000409` is a fail-fast, not a buffer overrun.** Read the subcode: `7` is
  `FAST_FAIL_FATAL_APP_EXIT`, i.e. `abort()`, i.e. an unhandled C++ exception. The instinct to go
  looking for stack corruption is wrong and expensive.
- **WER rotates dumps.** Copy to a stable path before `open_dump`, or race it and lose.
- **Cap `DumpCount` before reproducing a crash loop.** 345 MB × an unbounded count fills a volume.
- **`FileVersionInfo` reads the localised MUI.** `explorer.exe` reported `10.0.26100.8875` from its
  string block while the binary's fixed version — and WER's — was `10.0.26100.9168`. That looked
  briefly like a tampered image and was nothing. `VersionInfo.FileVersionRaw` is the honest field.
- **An empty error collection is not success.** A registration sweep run with
  `-ErrorAction SilentlyContinue` reported no failures while 21 of 44 packages had silently not
  registered. What settled it was counting what was *there*, by install path — not the absence of
  a complaint. The same rule the rest of this repo keeps repeating.
- **A checked-in sample would have made this reproducible.** It has none, deliberately: the dumps
  were 122–345 MB and carried the contents of a live desktop session.

## See also

- [`crash-dump-walkthrough.md`](crash-dump-walkthrough.md) — the kernel-side counterpart, on
  samples you can actually open.
- [`architecture.md`](architecture.md) — why the session holding the dump is a separate process
  from the one serving MCP, which is what makes debugging your own host unremarkable.
- [`tool-surface.md`](tool-surface.md) — where `execute` sits relative to the typed tools.
