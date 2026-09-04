---
paths:
  - "src/**/*.rs"
  - "build.rs"
---

## A worker of the target's architecture (`src/target.rs`, `engine::worker_images`)

A 32-bit .NET target cannot be read from this server's own process, and the reason is not a missing
DLL. An extension is loaded into the debugger's process, so its architecture is the *host's*: the
32-bit `sos.dll` will not load into an x64 host (`0n193`), and the 64-bit one loads and then fails
on the target (`Failed to load data access DLL, 0x80004005`) because `mscordacwks` is paired to the
**target's** architecture as well as the host's. Measured both ways — there is no in-process
arrangement, which is why the process moves rather than the extension
([#234](https://github.com/glslang/windbg-mcp/issues/234)).

**It is a second worker image, not a second server.** The supervisor normally re-executes itself;
for a 32-bit user-mode target it spawns `x86\windbg-mcp.exe` instead (`engine::worker_images`,
`engine::x86_worker_image`). A worker has never spoken MCP — it speaks `src/proto.rs` down a pair
of inherited anonymous pipes and has never heard of a client — so the client still sees one server,
one `tools/list`, one session registry, one four-session cap and one transcript, and cannot tell
which architecture served a session. **The wire is architecture-neutral because it is JSON**: no
pointer width, no alignment, and nothing in `src/` types a target address as `usize` (DbgEng's are
`ULONG64`). The `usize` fields in `proto.rs` are row limits, clamped. That was not
luck — process-per-session imposed serializability, which is the same property.

**The decision has to precede the engine, not follow it.** `GetEffectiveProcessorType` answers
authoritatively but only once a session exists, in a process whose architecture is by then fixed —
the very thing being chosen. So `src/target.rs` answers without one, **in the supervisor**, which
is the only place a read can still change which process is started. The same constraint rules out
swapping the engine later: `worker.rs` takes `INTERRUPT` from the engine once, into a `OnceLock`,
so an engine replaced mid-session leaves `interrupt` pointing at a dead one.

**Two target kinds can be asked without an engine, and they are asked differently.** A dump carries
its architecture in its own header; a live process answers `IsWow64Process2`. `target::Opening` is
the pair — one value, built from the opener in `EngineOp::opening`, consumed by `worker_images` to
pick the image and by `worker::limitation_for` to report. Three things about the live half. Read
**`ProcessMachine`, falling back to `NativeMachine`**, never the native one alone: the native
machine is the *host's*, so reading it would report an ARM64 box's x86 processes as ARM64 — the
exact case this exists for. The two enumerations are **not one table** (`Arch::of` against
`Arch::of_machine`): 9 is x64 to a minidump and nothing at all as a PE machine type, and 332 is the
other way round, so a shared mapping is how a value gets a plausible wrong answer.
`PROCESS_QUERY_LIMITED_INFORMATION` and not more — asking what a process *is* should need no more
right than naming it, and the attach that follows is where DbgEng asks for debug privilege.

**`IsWow64Process2` lives behind a feature gated by module path, not by subject.** The call is in
`Win32_System_Threading`, its `IMAGE_FILE_MACHINE` out-parameters are in
`Win32_System_SystemInformation`, and without the second feature the import does not resolve —
the same trap `.claude/rules/cargo-and-dependencies.md` records for `IMAGE_NT_HEADERS64`.

**The dump half answers for `MDMP` only, and that is the whole format.** Every user-mode capture on
Windows goes through `MiniDumpWriteDump` — procdump, WER, Task Manager, DebugDiag, VS,
`dotnet-dump` — verified against three independent writers. A kernel dump is `PAGEDU64` and reads
as `Other`, which is right: there is no CLR in one, and the x64 engine reads x86 and ARM64 kernel
dumps alike. `MiniDumpReadDumpStream` is the documented API for this and was considered; it needs a
mapping and `unsafe` to read two bytes at a fixed ABI offset, and it still cannot distinguish "not
a minidump" from "no such stream", so the signature check stays hand-written either way. Reach for
it if this ever needs the module list.

**The flag between the two processes is tagged, and that is not decoration.** `--engine-target=`
carries `dump:<path>` or `process:<pid>` (`Opening::flag_value`/`parse`), because a bare value
would have to be told apart by guessing — is `1234` a pid or a file called `1234`? — in the one
process that cannot ask anyone. A value that does not parse is logged and ignored rather than
fatal; what actually catches a supervisor and a worker disagreeing is the build identity on
`WorkerMessage::Ready`.

**Which is also the trap while editing this on a bench.** That check refuses an
`x86\windbg-mcp.exe` built from *any* other state of the tree, and on a dirty tree the identity
carries a digest over the uncommitted diff of `build.rs`'s `INPUTS` — `src`, `tests`, `build.rs`
and the two manifests — so `cargo fmt` moves it as surely as a code change does. **And so does
`git commit`**, in the direction nobody expects: committing takes the diff to empty, so the
identity goes from `<commit>-dirty.<digest>` to a clean `<commit>` and the worker built minutes
earlier under the digest is refused. Measured on
[#285](https://github.com/glslang/windbg-mcp/pull/285) — the tier passed, the commit landed, and
the same tier failed on the next run with nothing in `src` changed. A stale 32-bit worker is
therefore turned away, the session falls back to this build, and the smoke tier fails saying *this
host could not give the target a 32-bit worker* — which reads as a missing file rather than a stale
one. After every edit **and after every commit**, before running that tier:

```pwsh
cargo build --target i686-pc-windows-msvc
Copy-Item target\i686-pc-windows-msvc\debug\windbg-mcp.exe target\debug\x86 -Force
```

**`x86\` is a subdirectory because the loader makes it one.** An executable's own directory is
searched first, so a 32-bit `dbgeng.dll` dropped beside the 64-bit one would be found by the wrong
process — and putting the 32-bit *worker* inside `x86\` turns that same rule into the mechanism:
it loads the engine sitting next to it, with no code to make it happen. It is also the layout a
debugger package ships (`amd64\`, `x86\`).

**Both halves are probed before spawning**, and this is the one that is easy to leave out: the
engine is an import-table dependency resolved by the loader *before `main`*, so an
`x86\windbg-mcp.exe` with no `dbgeng.dll` beside it does not fail to open a dump — it fails to
start, as a loader error with no Rust in it. `x86_worker_image` returns `None` unless both are
there.

**Falling back is deliberate and the limitation is computed twice on purpose.** An x86 target opens
perfectly well in the x64 build and native analysis of it works; only SOS is lost. So a missing or
unstartable 32-bit worker degrades to this build rather than failing the open, and the *worker*
that ends up with the target asks the same question again and reports the limitation itself
(`worker::limitation_for`). Two reads of one fact rather than a field on the wire — they cannot
disagree, and the worker needs no new protocol to say what it is. Why the 32-bit worker did not
start is a **server** fact and is logged by the supervisor that tried it, not put in the caller's
summary.

**The tier for it makes its own target**, which is why it now covers anything: it was gated on a
supplied dump for as long as it existed, so CI never ran it. `csc.exe` ships with every stock
Windows, so the two tests compile a `-platform:x86` C# program that dumps *itself* — a 32-bit
process loads the 32-bit `dbghelp.dll`, where a 64-bit writer aimed at the same target produces a
dump reporting the host's architecture — and the other test attaches to that same program running.
Two things the tier learned the hard way: assert the dump's **size**, because
`comsvcs.dll MiniDump` was measured writing a near-empty file and reporting nothing wrong; and read
`summary.limitation`, not `limitation`, or the assertion is against JSON null and passes whatever
happened. Its gate is the **engine** (`x86\dbgeng.dll`) and not the worker, so a half-populated
`x86\` fails loudly rather than skipping, and so the gate is not a second copy of
`x86_worker_image`'s renamed-image fallback.

**What this replaced, and why it is worth knowing.** Until 2026-08-27 the engine moved into an
`x86\cdb.exe` run as a debugging server and driven over DbgEng's `npipe:` transport. That worked,
and three things about it did not: `IDebugAdvanced2::GetSymbolInformation` does not cross the remote
transport, so `modules` rows carried no PDB identity; teardown had to be a **kill**, because a
`cdb -server` whose peer has gone spins on the broken pipe without bound (32,089 lines of
`cdb: Could not write to pipe, 1450` in one measured run, which hung the VM and needed a hypervisor
reset); and the pipe `cdb` creates grants **Everyone `FULL ACCESS`** — measured
`D:(D;;WDWO;;;WD)(A;;FA;;;WD)`, with no `SYSTEM` or `Administrators` ACE at all — which made the
transport password the only barrier, and made the name a squat target both ways (pre-create is a
denial of service; adding an instance to a live name hands the *next* client's connection, and the
password, to the squatter). All three are gone with the transport. `FOLLOWUPS.md` item 49 has the
measurements and the options that were weighed.


