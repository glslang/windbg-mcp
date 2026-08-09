# MessageManager: from a pool UAF to KD-assisted RIP control

A tour of the **MessageManager** CTF driver on a **live KDNET kernel** (Windows Server 26100),
driven end to end with windbg-mcp. Unlike the [HEVD](hevd-ioctl-walkthrough.md) and
[mountmgr](driver-ioctl-walkthrough.md) tours — which are about *reaching* an IOCTL — this one is
about a **use-after-free in the kernel pool**, measuring candidate reclaims, and proving controlled
kernel RIP with a debugger-assisted handoff when natural grooming misses. There is **no PDB**, so
everything is `module+RVA`.

> **The thesis.** The bug is a garden-variety locking mistake. The interesting parts are proving
> what the allocator actually did on Windows 26100, extending the tiny refcount race without losing
> the target object, and separating a natural reclaim from a debugger-assisted control-flow proof.
> A pool walker that silently returns "empty" is worse than no walker at all, so this also records
> the four fixes needed before the 26100 measurements could be trusted.

The four kernel-pool tools this walkthrough leans on (`pool_find_tag`, `pool_chunk`, `pool_census`,
`pool_diagnostics`) were built for exactly this target; see the
[README's tool list](../README.md#tools).

## 1. Attach over KDNET

```jsonc
attach_kernel { "connection": "net:port=50000,key=<w.x.y.z>" }   // ask the user for the real string
```

```text
Windows 10 Kernel Version 26100 MP (4 procs) Free x64
Kernel base = 0xfffff806`76800000   PsLoadedModuleList = 0xfffff806`776f4fd0
```

> **Gotcha — the attach *blocks* on an INFINITE wait.** If the target isn't dialed in, the tool
> reports a *timeout* while the engine stays parked and completes the moment the guest connects.
> Don't fire more tools into a parked attach; `session_status` says how long it has waited, and
> `end_session` reclaims it. The target must dial this host:
> `bcdedit /dbgsettings net hostip:<debugger-ip> port:50000 key:<key>` (**colons**, not `=`).

## 2. Reverse the driver with no symbols

`\Driver\MessageManager` ships no PDB, so start from the driver object and read the dispatch table
straight off it:

```jsonc
execute { "command": "!drvobj \\Driver\\MessageManager 2" }
```

```text
[0e] IRP_MJ_DEVICE_CONTROL   fffff806`0c881230
```

Disassembling the dispatch (`uf fffff8060c881230`) shows a plain `sub`/`je` compare chain over
`IoControlCode` (read from `IO_STACK_LOCATION+0x18`), which pins the four handlers. The image base is
`0xfffff8060c880000`, so the RVAs are stable across boots even without symbols:

| IOCTL       | Op       | Handler RVA |
|-------------|----------|-------------|
| `0x222000`  | Create   | `+0x10d4`   |
| `0x222004`  | Delete   | `+0x1000`   |
| `0x222008`  | SetData  | `+0x1560`   |
| `0x22200C`  | Flush    | `+0x1478`   |

`uf`-ing each handler reconstructs the object model. **Create** calls
`ExAllocatePool2(0x40, 0x68, 'Tgsm')` — the `0x40` is `POOL_FLAG_NON_PAGED`, encoded cutely as
`lea ecx,[rdi-28h]` off the `0x68` size — so a **MESSAGE is a 0x68 NonPaged chunk**:

```text
+0x00  RefCount              (init 1)
+0x08  LIST_ENTRY            small/large list linkage
+0x18  Buffer                paged 'Tfub' allocation
+0x20  Length
+0x28  FAST_MUTEX            (Count=+0x28, Event=+0x40)
+0x60  Linked                on-a-list flag
```

A **global handle list** (head at image `+0x30a0`, lock `+0x3060`, id counter `+0x3000`) maps each
returned `id` to its MESSAGE through 0x20-byte `Tdnh` nodes `{id, MESSAGE*, LINKS}`. Messages link
into a **small** or **large** list (split at `Length == 0x200`) by their own `+0x08` LIST_ENTRY.

## 3. The vulnerability: locking, not arithmetic

Single-threaded, the refcounting is balanced. The defect is that the four operations disagree about
which lock guards a MESSAGE:

- **SetData** looks a message up in the handle list and does `lock inc [msg]` — **without** holding
  that message's `+0x28` FAST_MUTEX.
- **Delete** and **Flush** drop the refcount and, when it hits zero,
  `ExFreePoolWithTag(msg, 'Tgsm')` — also without that per-message mutex.

So SetData can `lock inc` a message whose refcount another thread has already driven to zero and is
about to free — a classic revive-after-free — and the cross-list move in SetData unlinks the message
holding only its own mutex, never the *source* list's lock. The payoff is a **premature free of the
0x68 `Tgsm` chunk while a live reference still points at it**.

Under Driver Verifier this is an instant, unambiguous crash. A 6-thread SetData/Flush race
(`mm_client.ps1 -Op Race`) bugchecks on the first run:

```text
BugCheck 50, PAGE_FAULT_IN_NONPAGED_AREA
faulting IP: MessageManager+0x14de   (the Flush list-walk: mov rax,[rcx+8])
FAILURE_BUCKET_ID: AV_VRF
```

> **Gotcha — `!analyze` misnames the module.** `Failure.Exception.IP.Module` came back `mpsdrv`;
> the bugcheck banner and `IP_IN_PAGED_CODE` are trustworthy, the "friendly" attribution is not.

`MessageManager+0x14de` is inside Flush (`+0x1478`), at the `[Blink]=Flink; [Flink+8]=Blink` unlink
of a freed node — which is exactly the write-what-where an exploit wants (more on that in §6).

## 4. Watching the chunk — and why the walker had to be fixed four times

To exploit a UAF you have to *see* the freed chunk and what reclaims it. That is what the pool tools
are for:

```jsonc
pool_find_tag { "tag": "Tgsm" }
```

```text
tag `Tgsm`: 1 allocation(s), 0x68 bytes total
ffff8c8f`13a02f90  0x68  SpecialNonPagedNx  Allocated
```

```jsonc
pool_chunk { "address": "ffff8c8f13a02f90" }
```

`pool_chunk` reports the chunk **and its neighbours**, which is what tells you what a reclaim would
land next to — and under Verifier it correctly shows the adjacent **guard page** as an `Unreadable`
neighbour rather than guessing.

Getting these two calls to tell the truth on 26100 took **four** fixes in the underlying walker
(`win-kexp`), each one a place where the OS had moved something and the walk failed *silently*:

1. **VS free-chunk state moved out of `_HEAP_VS_CONTEXT`.** On 26100 that struct is 0x60 bytes and
   carries none of `FreeChunkTree`/`SubsegmentList`/`DelayFreeContext`; they live in a new
   `_HEAP_VS_AFFINITY_SLOT`, reached by a self-relative, ×64-scaled slot-map arithmetic off the
   context. Any walker that reads `_HEAP_VS_CONTEXT.FreeChunkTree` reads garbage.
2. **The page-segment signature dropped its constant.** `_HEAP_PAGE_SEGMENT.Signature` used to be
   `segment ^ context ^ heap_key ^ 0xa2e64ead…`; on 26100 the constant is gone. Every segment
   failed authentication, so **every chunk vanished** — and the walk returned an *empty pool*, not
   an error. (This is the breakage that motivated surfacing walk diagnostics everywhere: "I saw
   nothing" and "there is nothing" must never render the same.)
3. **Verifier special pool was discovered but not decoded.** A driver under `verifier /flags 0x1`
   gets page-per-allocation special pool, whose range descriptors carry `DESCRIPTOR_FLAG_LFH` — so
   the range was misparsed as an LFH subsegment, judged "implausible", and discarded before any
   walking. The chunk above (`SpecialNonPagedNx`) is only visible because that path was fixed to
   decode special pool page-granularly (data at `page + 0x1000 - align_up(size,16)`).
4. **Page-straddling LFH slots.** LFH slots whose data crossed a page boundary were mis-read; the
   fix stopped reporting the straddlers as corruption.

When the walk *is* incomplete, the tools say so rather than pretending — the whole point of the
`complete` flag threaded through `pool_census`/`pool_diagnostics`:

```jsonc
pool_diagnostics { "filter": "13a0" }   // a plain case-insensitive substring, not a pattern
```

> **Method note.** A real walk emits ~18k diagnostics across 100+ categories, so every summary
> truncates and the one line explaining a specific heap is never in the head. `pool_diagnostics`
> with a substring filter found the special-pool cause in **one** call, after three rounds of
> guessing had failed. Build the filter before theorising.

## 5. Defeating ASLR from outside the driver

There is **no read-back IOCTL**, so the exploit cannot leak addresses through the driver. Everything
it needs comes from `NtQuerySystemInformation`, all available at medium IL
(`examples/messagemanager/mm_exploit.c`, `leak` mode):

```text
[leaks]
  ntoskrnl base            : 0xfffff80676800000
  PsInitialSystemProcess   : 0xfffff806777c5ab0   (ntos + 0xFC5AB0)
  MessageManager base      : 0xfffff8060c880000
  this _EPROCESS           : 0xffffe6091811a080
  this _KTHREAD (+0x232 PreviousMode)
  big pool                 : 6420 entries, NonPaged addresses returned
```

- `SystemModuleInformation` → the kernel and driver bases (the driver base matches the one reversed
  in §2 to the byte).
- `SystemExtendedHandleInformation` → this process's `_EPROCESS` and this thread's `_KTHREAD`, found
  by matching a real handle to self against the system-wide handle table.
- `SystemBigPoolInformation` → real NonPaged pool addresses, which the reclaim spray will need.

Each value cross-checks against the debugger: `x nt!PsInitialSystemProcess` prints exactly
`0xfffff806777c5ab0`, and `lm` gives the same driver base — so the leak plumbing is sound before a
single byte of the driver is corrupted.

## 6. Measure grooming before trusting it

Create asks `ExAllocatePool2` for `0x68` bytes with `POOL_FLAG_NON_PAGED` (`0x40`) and tag `Tgsm`.
On this build `!pool` shows an `0x80` physical LFH block; the structured walker reports `0x70`
usable bytes. That distinction matters: matching the requested length is not proof that two call
sites draw from the same LFH allocation context.

The `rip` harness in `examples/messagemanager/mm_exploit.c` creates the race target on CPU 0, keeps
candidate allocations alive, and lets the pool tools answer the only useful grooming question:
**did this exact address change from `ReusableFree` to attacker-controlled?** The measurements on
Windows Server 26100.32995 were:

| Candidate | Live measurement | Result |
|---|---|---|
| NPFS write-data (`NpFr`) | physical blocks were `0xa0`; payload followed an NPFS header | wrong bucket and offset |
| Pending METHOD_BUFFERED requests (`IoSB`) | 784/1024 exact-`0x68` SystemBuffers stayed parked | target remained `ReusableFree` |
| Event objects | requested `0x68` and appeared in mixed `0x80` LFH blocks near `Tgsm` | useful density groom, unreliable reclaim |
| Retained SetData buffers (`Tfub`) | 1024 exact-`0x68` driver copies | target remained free: SetData uses `POOL_FLAG_PAGED` (`0x100`) |
| SetData with KD-patched tag and flags | `Tgsm` plus `POOL_FLAG_NON_PAGED` (`0x40`) | still missed; call-site/subsegment selection remained different |

`pool_census` established the population, `pool_find_tag` found the candidate classes, and
`pool_chunk(refresh=true)` gave the final per-address verdict. The tools do not mutate or groom
pool state; they prevent a plausible-looking spray count from being mistaken for a reclaim.

The [SSTIC 2020 pool-overflow work](https://www.sstic.org/2020/presentation/pool_overflow_exploitation_since_windows_10_19h1/)
is applicable to the allocator model: LFH subsegments, affinity slots, and free-bitmap randomisation
explain why density and CPU placement matter. Its aligned-chunk-confusion overflow is not this
driver's UAF primitive, though, and the live address checks above disprove a size-only translation
of that technique. For short race windows, the reschedule/TLB-pressure ideas are closer to
[Project Zero's tiny-race work](https://googleprojectzero.blogspot.com/2022/03/racing-against-clock-hitting-tiny.html)
and [ExpRace](https://www.usenix.org/system/files/sec21-lee-yoochan.pdf); here KD makes the final
experiment deterministic instead of pretending the scheduler trick is reliable.

## 7. Deterministic UAF and debugger-assisted handoff

The reliable race uses one target MESSAGE and four CPUs. `run_to_address` stops only when the
register holding the candidate equals the saved target; an assertion aborts and restores every
temporary byte if a different list node hits first.

Before opening the driver, the harness verifies that the calling thread's primary processor group
and the process, system, and thread affinity masks all expose CPUs 0–3. Each race, window-extension,
and CREATE-trigger worker must then be pinned successfully before its start gate is released; an
affinity-restricted launch fails instead of silently running the experiment with co-scheduled threads.

1. Stop the SetData caller at the unlink (`MessageManager+0x16e4`), set the target refcount to 3,
   and replace the first four unlink bytes with `jmp $`.
2. Let Flush reach `+0x1502`. Its `lock xadd -1` changes the same object from 3 to 2.
3. Restore the unlink and let SetData reach `+0x1706`; its final decrement leaves 1.
4. Let Flush reach `+0x151b`, immediately before it frees that exact object; continuing toward the
   first post-free allocation performs the free. In the successful run the target was
   `ffff9a04'94a74010`; `!pool` showed the physical `0x80` `Tgsm` block.

Natural grooming still did not return that address. To validate the downstream UAF and control-flow
chain independently of allocator luck, KD stopped after the first post-free `ExAllocatePool2` at
`SetData+0x1668`. The real return was `ffff9a04'94895f10`; KD deliberately changed `RAX` to the
freed target before the driver stored the pointer and copied the `0x68`-byte fake MESSAGE.

That is a **debugger-assisted handoff, not a standalone reclaim**. It leaks the real allocation and
does not mark the target allocated in LFH metadata, so the VM must be rebooted after the experiment.
Keeping this boundary explicit is important: the handoff proves the object layout, stale lookup,
unlink primitive, and final indirect call; it does not claim a production-quality pool spray.

## 8. Direct RIP control without `PreviousMode`

The first post-UAF attempt used the usual data-only bootstrap: set fake `Flink` to a writable kernel
anchor ending in `0x0800`, set fake `Blink` to `KTHREAD.PreviousMode`, and let the unlink's second
store make the low byte zero. Windows 26100.32995 immediately bugchecked with `0x1F9`,
`PREVIOUS_MODE_MISMATCH`, on return to user mode. The installed 26100 WDK names that stop code in
`bugcodes.h`; this route is mitigated on the tested build and is not a SYSTEM primitive here.

RIP control can instead be proved before the vulnerable syscall returns. The unlink at
`MessageManager+0x16e4` is:

```text
+0x16ef  mov qword ptr [rax],rcx       ; [Blink]   = Flink
+0x16f2  mov qword ptr [rcx+8],rax     ; [Flink+8] = Blink
```

At the synchronization `IRP_MJ_CREATE`, KD derives
`&DriverObject->MajorFunction[IRP_MJ_CREATE]` from `DeviceObject` and rewrites the fake:

```text
fake.Flink = nt!DbgBreakPointWithStatus
fake.Blink = &DriverObject->MajorFunction[IRP_MJ_CREATE]
```

The first unlink store therefore installs a kCFG-valid kernel export in the dispatch slot. The
reciprocal store would try to write into read-only kernel code, so KD temporarily changes `+0x16f2`
to `jmp $`. A second harness thread, pinned to CPU 3, continuously opens `\\.\MessageDevice`; the
stale SetData caller remains on CPU 0. Once the dispatch pointer changes, the trigger thread reaches
the selected target through the normal I/O manager indirect call.

The captured proof was:

The [curated MCP proof record](../examples/messagemanager/rip-proof-transcript.txt) identifies the
live binary and distinguishes transcribed output from canonicalized commands and post-run annotations.
A reconstructed [asciicast v2 recording](../examples/messagemanager/rip-proof.cast) animates the same
captured events; its timing is illustrative because live recording was not enabled for the original run.

```text
rip=fffff803`aa6fa240  nt!DbgBreakPointWithStatus
THREAD ffff9a04`93426080  Cid 0da0.0a2c  RUNNING on processor 3
Owning Process ffff9a04`93d4b440  Image: mm_exploit.exe

nt!DbgBreakPointWithStatus
nt!IopfCallDriver+0x5b
nt!IofCallDriver+0x13
nt!IopParseDevice+0x73b
nt!NtCreateFile+0x79

MM_PROOF_PROCESS_OK
MM_PROOF_CONCURRENT_THREAD_OK
```

The stale caller was a different thread (`ffff9a04'94017080`) in the same process, stopped at
`MessageManager+0x1560` on CPU 0. After capture, KD restored the CREATE slot to
`MessageManager+0x1210`, changed the reciprocal store to NOPs so the parked caller could pass it,
redirected the trigger to the original CREATE handler, and finally restored the original
`48 89 41 08` bytes. A final read verified both the dispatch pointer and instruction bytes before a
clean reboot discarded the intentionally corrupted free chunk.

This establishes controlled kernel RIP on the challenge build. It remains a debugger-assisted CTF
proof because the exact LFH reclaim is not natural; it makes no claim of privilege escalation or a
debugger-free exploit.

## 9. Streamlining the next kernel CTF

This run exposed several improvements that would remove orchestration risk without hiding the
debugger mechanics.

### MCP server

1. **Nonblocking continue with an execution handle.** `go` currently waits for the next stop. Add
   `continue_async`, `wait_for_stop`, and `break_in` so an agent can arm KD, launch the guest process,
   and then await a stop without relying on guest `Sleep` or a second ad-hoc client.
2. **Transactional breakpoint scripts.** A tool should accept ordered steps such as “run here,
   assert `rbx == target`, patch these bytes, run there” plus a rollback block. The worker can restore
   code, clear breakpoints, and report the last completed step even if a command, transport, or client
   fails. This is safer than cleanup hidden in PowerShell conditionals.
3. **Named debugger variables.** Keep host-side names (`target_message`, `create_slot`,
   `original_create`) and materialise them only when issuing a command. WinDbg `$tN` registers are a
   scarce global namespace; the first proof cleanup failed because an assertion helper reused
   `$t2`–`$t4`.
4. **Streamed, sanitized transcripts.** Emit each tool request, verdict, stop reason, register delta,
   and rollback action as JSONL while the batch is running, with connection strings redacted. An
   optional asciicast sink would make the recording in this directory live rather than reconstructed.
5. **Structured conditional breakpoints.** Extend `run_to_address` with register/memory predicates
   and on-hit reads. Returning `wrong-object` as a normal verdict would replace the current pattern
   of stopping first and running a separate assertion command.
6. **Pool-address watch mode.** After one full walk, track a selected chunk across stops and report
   state/tag/subsegment changes without refreshing the entire pool. Include requested size, usable
   size, physical block size, pool flags, LFH subsegment, affinity slot, and whether the allocation
   context changed. That data is exactly what distinguished `Tgsm`, `IoSB`, `Even`, and `Tfub` here.
7. **Command-level error attribution.** Split semicolon command batches internally and return the
   failing subcommand plus completed mutations. DbgEng's `0x80040205` otherwise hides whether a
   preceding restore happened.
8. **Explicit resume-and-detach verification.** `end_session` should report the final target state
   and, for live KD, optionally verify that the guest clock advances. A `continue_and_detach` tool
   would make WinRM handoffs predictable.

### Target VM

1. **Guest coordinator service.** Bake in a minimal authenticated lab service that can create the
   harness suspended, return PID/TID and image hash, then resume it on a host command. It should also
   expose log-tail and clean reboot operations. This replaces timing guesses without weakening the
   challenge driver.
2. **Checkpoint lifecycle.** Keep a named clean snapshot and automate
   `revert → boot → health check → run → collect dump/log → revert`. The forced handoff deliberately
   violates LFH metadata, so snapshot rollback is the correct cleanup boundary.
3. **Stable debug/remoting network.** Use a dedicated KDNET adapter, fixed guest address or DHCP
   reservation, baked-in WinRM firewall rules, and a health probe that compares the guest's leaked
   kernel base with KD's `vertarget` before a run.
4. **Two verifier profiles.** Maintain a fast exploit profile with Driver Verifier off and a triage
   profile with Special Pool/pool tracking enabled. Record the active profile in every transcript;
   verifier changes both allocator behaviour and crash timing.
5. **Deterministic topology.** Pin the VM to four fixed vCPUs, disable CPU hot-add/dynamic topology,
   and keep memory size constant. The harness assumes CPUs 0/1 for the victim race and 2/3 for
   pressure/trigger threads.
6. **Crash artefact collection.** Configure kernel or active-memory dumps, retain the most recent
   dump across reboot, and copy the bugcheck code/parameters plus harness hash into a small manifest.
   The `0x1F9` result was much easier to classify once it could be tied to the exact build.
7. **Build identity and secret hygiene.** Print the driver/harness SHA-256 and OS build at launch,
   but keep KD keys and credentials in host credential storage rather than scripts, logs, snapshots,
   or the repository.

## Gotchas recap

- **Attach blocks on an INFINITE wait** — diagnose a hung attach out-of-band, don't hammer tools.
- **The whole guest freezes while broken in** — the KD link only runs the target in bursts between
  break-ins, too short for a WinRM round-trip. For guest-side work, `end_session` to detach fully,
  then re-attach to observe. Release with `end_session`, never a process kill (it wedges the KD stub).
- **Guest `Sleep` is not a reliable host-side launch delay under KD** — interrupt time barely
  advances while the guest is stopped. Arm `run_to_address` first and launch the harness through a
  separate remoting call instead of guessing a delay.
- **`PREVIOUS_MODE_MISMATCH` is enforced on this build** — zeroing `KTHREAD.PreviousMode` and
  returning through the syscall boundary bugchecks with `0x1F9`; do not present that legacy
  bootstrap as a working 26100 privilege-escalation primitive.
- **Debugger pseudo-registers are scratch state** — assertion helpers use `$t2` through `$t4`.
  Derive cleanup pointers again from live registers or reserve pseudo-registers the helper cannot
  clobber.
- **A forced allocation return is not pool metadata** — after the KD-assisted handoff, restore code
  and dispatch pointers, capture the proof, and reboot the disposable VM before LFH reuses the
  intentionally corrupted free chunk.
- **A pool walker that "sees nothing" is not proof of an empty pool** — treat "rejected everything"
  as an error; the tools surface walk coverage (`complete`) and diagnostics for exactly this.
- **`!analyze` can misname the faulting module** — trust the bugcheck banner and `IP_IN_PAGED_CODE`.
- **Verifier special pool hides a driver from naive walkers** — it needs a page-granular decoder;
  `pool_find_tag` handles it, and shows the guard page as an `Unreadable` neighbour.
- **A full pool walk is expensive on a *live* KDNET target** — `pool_find_tag`/`pool_census`
  traverse every free tree node-by-node over the wire, and a live target mutates the lists under
  the walk (stale pointers get chased, diagnostics balloon), so the call can exceed the engine
  timeout and stall follow-ups. On a dump it's cheap. To find one object on a live target, prefer
  the targeted route (`!handle`/FILE_OBJECT/`dps`) over a tag walk; the snapshot is cached per
  session, so pay the walk once.
