---
name: live-kernel
description: Reach and drive a live kernel target from this bench - KDNET and serial wiring and their traps, loading and walking a driver's IOCTL dispatch (HEVD), what `.reload` does to the module inventory, and where symbols must live. Use when attaching to a kernel target, debugging a driver over KD, or diagnosing an attach that parked or symbols that will not resolve.
---

# Live kernel and driver IOCTL work

## Two ways a target is reached, and neither is "the" procedure

**KDNET.** Check the target is reachable *before* starting the tier, not by starting it — an attach
that finds nothing parks its worker in `WaitForEvent(INFINITE)` for the whole run and reports a
timeout that measures the environment rather than the code. What settles it is not "can I reach the
guest" but **does the guest's `bcdedit /dbgsettings hostip` equal this debugger host's current IP**,
on the port the profile names; the host IP moves between sessions. Compare the key by *hash* rather
than printing it.

*Finding* the guest is topology-specific. On the machine that paragraph was written for, the
debugger host is itself a Hyper-V guest — `Get-VM` does not exist and there is no local VM to start
— so the target is a *sibling*: it appears in the neighbour table (`Get-NetNeighbor | ?
LinkLayerAddress -like '00-15-5D*'`) and answers **TCP 5985** and nothing else, ICMP and 445 being
closed, so a failed ping proves nothing there. With several neighbours the table will happily
validate the wrong guest, which is what the `hostip` comparison is for.

**Serial, which is what the Parallels bench uses** — and there KDNET is not merely unconfigured but
*impossible*: guests get a `Parallels VirtIO Ethernet Adapter` (`PCI\VEN_1AF4`), and `1AF4` is not
in the Debugging Tools' `VerifiedNICList.xml`. `prlctl set <vm> --device-set net0 --adapter-type
e1000` is accepted and silently ignored on ARM, leaving the guest with no network at all. Do not
spend an afternoon on it. The wiring that works is a TCP socket between two guests:

- target `serial0` → `tcp://localhost:2020`, **client**; `bcdedit /dbgsettings serial debugport:1
  baudrate:115200`
- debugger `serial0` → `tcp://:2020`, **server** — then `prlctl set <vm> --device-connect serial0`,
  or it stays `state=disconnected` and nothing binds the port, and a **VM restart**, or the guest
  never sees a COM port
- `netstat -an | grep 2020` on the Mac: a LISTEN *and* an ESTABLISHED pair means the wire is up
- on the target, `ARM PL011 Serial Port Device (COM1)` in **`Error`** state with no name from
  `GetPortNames()` is correct — that is the kernel debugger owning the port

Three traps on that bench, each of which cost real time:

- **`kd -b` is no longer supported** — the docs say so in those words, and it is silently a no-op,
  so a `kd -k … -b` probe sits at `no_debuggee` against a *running* target and looks like a dead
  link. Use **`-bonc`**. windbg-mcp itself is unaffected; DbgEng issues a proper break-in.
- **Parallels `Pause idle` is on by default**, and a target broken into the debugger burns no CPU,
  so the hypervisor suspends the whole VM mid-run and every later call times out with nothing to
  explain it. `prlctl list` then shows it `paused`, which is *not* a kernel halt.
  `prlctl set "<vm>" --pause-idle off`.
- **A worker killed while holding a broken-in kernel leaves the guest frozen** — `prlctl exec` hangs
  on it. Attaching and detaching properly is the fix:
  `kd -k com:port=COM1,baud=115200 -c ".time;qd"`.
- **Do not hard-reset the debuggee to clear a corrupted kernel pool.** Two `prlctl reset`s in a row
  put it into WinRE ("Your device ran into a problem and couldn't be repaired"), which wants console
  input `prlctl` cannot send and `prlctl exec` cannot see past — a third reset happened to boot
  through it, but nothing guarantees that. Let a bug check reboot the machine itself
  (`AutoReboot=1` is already set there), and expect a file written just before a reset to come back
  whitespace-filled.

**A pool walk will not finish over 115200 baud.** It reads every committed pool page and times out
at 240s, so on a serial bench "x64-only" and "too slow over this wire" cannot be told apart.

## Live kernel + driver IOCTL gotchas (learned driving HEVD over KDNET)

**Loading HEVD on an ARM64 bench takes two things, and the error names neither.**
`StartService FAILED 577` ("cannot verify the digital signature") means both `bcdedit /set
testsigning on` (a reboot) *and* the driver's signing certificate imported into
`Cert:\LocalMachine\Root` — test signing has nothing to chain to otherwise, and an unexpired cert
that is simply untrusted looks identical to an expired one. `TrustedPublisher` refuses with
`E_ACCESSDENIED` and is not needed for `sc start` of a non-PnP driver. Check HVCI
(`(Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning`)
before blaming signing; `0` means it is not the cause.

**A crash out of an exploit client is usually not a driver bug.** HEVD's stack-overflow client on
this bench bug-checks `0xFC` with the kernel faulting at the *user-mode payload* — its ROP chain
never disables privileged execution of a user page — so the stack is `nt`-only and carries no
`HEVD` frame at all. A fixture that needs a driver frame wants a path that faults **inside** the
driver, not a failed exploit.

**Getting HEVD to bug-check at all is harder than it looks, because it is written to survive.**
Every trigger is wrapped in `__try/__except`, so a kernel-mode access violation is caught and
returned as a status: the null dereference answers `STATUS_ACCESS_VIOLATION` with the machine still
running, the non-paged pool overflow answers *success* and quietly corrupts the pool, and the UAF
double free answers success twice and surfaces minutes later on a heap-maintenance worker thread as
a `0x13A` whose stack is `nt`-only — the one shape a driver-attribution fixture must not have.
What SEH cannot catch is a **fail fast**. `HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS` compiles its trigger
with `/GS`, so overrunning the buffer corrupts the cookie and the driver's own `__report_gsfailure`
runs `mov w0, #2; brk #0xf003` — `0x139 KERNEL_SECURITY_CHECK_FAILURE`, raised inside the driver.
That is how `docs/samples/082126-7015-01.dmp` was made (issue #154); `docs/smoke-test.md` has the
one-line recipe.

**DbgEng's module inventory is the debugger's, not the target's, and `.reload` is two operations
wearing one name.** A kernel attach starts from what it can read at connect time, so a driver
loaded before the debugger dialled in is in the target and absent from `lm` — which is
[#85](https://github.com/glslang/windbg-mcp/issues/85), where a running challenge driver read as
"not loaded". The gap is not small: measured on the CTF guest 2026-08-30, a fresh attach held
**1** module and a refresh found **158**. `IDebugSymbols::Reload("")` resynchronises the list and leaves symbols deferred;
`/f` additionally fetches every PDB. `modules { "refresh": true }` is the first half on its own
(`worker::resynchronise`). Three things bite when editing it:

- **The refresh costs the symbol state, on a live target and not on a dump.** Measured both ways
  (2026-08-30, engine DLLs bundled): a launched `cmd.exe` goes all-five-`pdb` after a `.reload /f`
  and comes back with four `deferred` and `ntdll` still `pdb`, while the checked-in kernel dump
  keeps `nt` at `pdb` across a refresh and discards nothing. A live reload re-reads the module
  list and the entries are rebuilt; a dump's list is its own header. So the note says *on a live
  target* and *most* modules, and anything that refreshes after a live symbol load has undone it.
  **The first attempt at this measurement was taken on a host whose engine had no `symsrv.dll` or
  `msdia140.dll`** — the five modules could only reach `export` fallback, so the effect read as
  smaller than it is and the dump half was never asked. Check the engine is bundled before
  measuring anything symbol-shaped here.
- **Order is the whole of the CTF tier's claim.** `a_messagemanager_ctf_fixture_is_visible_through_mcp`
  asks `modules { "refresh": true }` **before** `load_kernel_symbols`, deliberately: that helper's
  unqualified `.reload /f` resynchronises the inventory as a side effect, so a `modules` call after
  it passes whether or not `refresh` does anything at all. Moving it back below the symbol setup
  keeps the test green and deletes what it is for.
- **A failed refresh is reported, not raised**, and the note goes *above* the tables. A caveat
  under a listing arrives after the conclusion it was there to prevent, which is the exact failure
  the issue is about.

**Read a driver's IOCTL codes out of its own dispatch — do not take them from a published list.**
This build's are not the ones HEVD's widely-quoted table gives, and the code that table calls the
null dereference is `FREE_UAF_OBJECT` here. Sending the wrong one is not always harmless: several
of them corrupt the kernel silently. The dispatch walk earlier in this section and `decode_ioctl`
are how to read them; on ARM64 the switch is a chain of `sub wN, wM, #0x222, lsl #12` against a
literal, and each case block's `DbgPrintEx` format string names the handler.

**Also: HEVD returns `STATUS_UNSUCCESSFUL` from handlers that succeeded.** `AllocateUaFObject*`
initialises its status to `0xC0000001` and never sets it on the success path, so `sc`-style error 31
out of the harness means nothing. Trust the resulting state, not the status.

**Attach by `profile`, not by connection string — always, for any live target.** `attach_kernel
{ "profile": "<name>" }` resolves the connection inside the server (`src/kdconn.rs`), so the
target's debug key never lands in a tool argument — and therefore never in the *client's*
transcript, where one key previously ended up replicated across hundreds of records.
`attach_kernel {}` lists the profiles this host has. Configure one with
`WINDBG_MCP_PROFILE_<NAME>` or `%USERPROFILE%\.windbg-mcp\profiles.json`; raw `connection` still
works for a target nothing is configured for, and is the last resort rather than the quick option.

A raw `connection` now also reaches a second place: with recording on (`.claude/rules/transcripts.md`) it is written to the
server's own transcript file, scrubbed to `key=<redacted>`. That backstop is not a reason to pass
one. A profile keeps the key out of the request, so there is nothing for either transcript to
redact, and redaction is a thing that has to keep working while a key never sent cannot leak.

The live smoke tier (`.claude/skills/tiers/SKILL.md`) is the one sanctioned exception: `WINDBG_MCP_SMOKE_KERNEL` is a raw
connection string, passed straight to `attach_kernel { "connection": … }`, and is deliberately
*not* a profile — the tier has to exercise the explicit path, and it is a variable in a developer's
own shell rather than something a client ever sees.

A worker process does **not** inherit `WINDBG_MCP_PROFILE_*` (`engine::spawn_worker` strips them):
it is told the one connection it is opening over its private pipe, and a `launch`ed debuggee would
otherwise inherit every configured key on the host.

**KDNET attach is a blocking wait, by design.** A live kernel needs `WaitForEvent(INFINITE)` (a finite
timeout returns `E_NOTIMPL` and never drives the link). So if the target isn't reachable, the
`attach_kernel` MCP call reports a *timeout* while its **worker process** stays parked in the wait —
it self-heals and completes the attach the moment the target actually connects. Consequences:
- The park costs **that session only**. Other sessions and every other tool keep working, so an
  attach that is going nowhere is no longer a reason to restart the server. `session_status` says
  how long it has been waiting and whether that is past the point a healthy link takes;
  `end_session` reclaims it, terminating the worker process if the wait will not unwind (it won't —
  `SetInterrupt` cannot reach a wait that has not yet connected).
- **Do not re-run the attach while it is still waiting.** The connection was already claimed, so a
  retry dials a second time. End it first, or fix the target and let the original attach land.
- Diagnosing why nothing dialed in is still out-of-band work (PowerShell): check the debugger is
  listening (`Get-NetUDPEndpoint -LocalPort 50000` → owned by `windbg-mcp.exe`, which will be the
  *worker* process) and whether any VM is running.
- The **target must dial this host**: on the target, `bcdedit /dbgsettings net hostip:<debugger-ip>
  port:50000 key:<key>` — **colons, not `=`**. `hostip` must be the debugger host's current IP.
  Symbols are **not** pulled over the KD wire (see below).
- After a target reboot, the settling KD link shows repeated break-ins in **`kdnic.sys`** (the KD NIC
  transport: `nt!DbgBreakPointWithStatus` ← `kdnic!TXTransmitQueuedSends`). These are not real stops —
  `go` through them until boot proceeds.

**Walking a service-loaded driver's IOCTLs live.** `sxe ld:<drv>.sys` breaks on module load, which is
**before DriverEntry runs** — so the driver object's `MajorFunction` table is *not* populated yet
(`driver_object` shows defaults / "is not a driver object"). To let DriverEntry run and populate it:
1. Compute the PE entry point from the header: `? <base> + dwo(<base> + dwo(<base>+0x3c) + 0x28)`.
2. `bp` it, `go`. At entry, `@rcx` = `DriverObject`, `poi(@rsp)` = return addr (into
   `nt!PnpCallDriverEntry`). `bp` that return, `go` — now the table is populated.
3. `MajorFunction[0x0e]` (IRP_MJ_DEVICE_CONTROL, the IOCTL dispatch) is at **`DriverObject+0xe0`**.
   In the dispatch, the `IoControlCode` is `IO_STACK_LOCATION+0x18`; the current stack location is
   `IRP+0xB8`. `uf` the dispatch to read the (usually binary-search) IOCTL switch, `decode_ioctl`
   each code, and read each case's `DbgPrintEx` string (`da`) for the human name.

**Symbols must be on the debugger host.** PDBs are never fetched from the target over KD. Find the
exact PDB identity the engine wants with `!sym noisy; .reload /f <mod>` (it prints `<pdb>\<GUID>\...`),
then get that PDB onto this host. **Gotcha: `.sympath` / `.sympath+` swallow the *rest of the command
line* — they ignore `;`, so anything chained after them (`; .reload ...`) is parsed as path text.**
Issue `.sympath` alone, or use the **`set_symbol_path`** tool (goes through the DbgEng
`AppendSymbolPath`/`SetSymbolPath` API, immune to the quirk; appends + reloads). When a driver's
`module!Symbol` names don't resolve, **ask the user for the PDB folder** and apply it with that tool.

**Nothing resolves at all without `msdia140.dll` beside the engine** — `symsrv.dll` finds a PDB and
that one *parses* it, so without it every module reports `Symbol Type: EXPORT - PDB not found` even
when the identity was known and the file was downloaded. **`symsrv.dll` is the other half, and
System32 usually does not ship it**: on a machine with neither, a `srv*` path downloads nothing.
*Usually*, because it is not a constant and this repo believed it was — probing both CI runners
(issue #153) found one in `windows-latest`'s System32 and none in `windows-11-arm`'s, so check the host in
front of you (`where.exe symsrv.dll`) rather than assuming either way. Worth
knowing because of how that presents on a *dump* — not as missing symbols but as a **memory read
failing** (`0x8007001E`), since a kernel dump's virtual addresses are translated through structures
the engine locates with `nt`'s symbols. That symptom was read as an ARM64 engine limitation for a
while (issue #142); it is not one, and an engine with symbols reads x64 and ARM64 dumps alike. It is **not** store-package-only, which
this repo believed for a while: Visual Studio Build Tools ships it, including an ARM64 build, at
`…\BuildTools\DIA SDK\bin\arm64\msdia140.dll`. Copy it next to the exe (`target\release`, and
`target\debug` for the smoke tiers — **and `target\debug\deps` if a *unit* test loads the engine**,
which is where libtest's binaries actually run from; this guidance said `target\debug` alone until a
2026-08-26 test met System32's engine and failed with an error about something else entirely).
**Warm the cache once** afterwards — attach and `.reload /f nt`
— because the first fetch takes minutes and everything around it times out, which reads convincingly
as the parser having made things worse.

