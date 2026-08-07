# MessageManager: a pool UAF, and what it takes to see it

A tour of the **MessageManager** CTF driver on a **live KDNET kernel** (Windows Server 26100),
driven end to end with windbg-mcp. Unlike the [HEVD](hevd-ioctl-walkthrough.md) and
[mountmgr](driver-ioctl-walkthrough.md) tours — which are about *reaching* an IOCTL — this one is
about a **use-after-free in the kernel pool**, and the tooling you need to watch a freed chunk get
reclaimed. There is **no PDB**, so everything is `module+RVA`.

> **The thesis.** The bug is a garden-variety locking mistake. The interesting part is that
> *observing* it on Windows 26100 meant fixing the pool walker in four separate places where a new
> OS release had quietly moved the furniture — because a pool walker that silently returns "empty"
> is worse than no walker at all. This is the story of both: the driver's UAF, and the four
> breakages between a walker that worked on 22H2 and one that tells the truth on 26100.

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

## 6. From UAF to SYSTEM — how far the primitives reach

The intended payoff is **data-only** — the mitigations rule out anything else. CR4 on this box is
`0xb50ef8`: **SMEP, SMAP, and CET all on**. So a ROP chain to clear CR4 is a dead end (CET faults
the `ret`s, and there's no instruction-pointer control to begin with — the bug yields *data* writes,
and kCFG guards indirect calls). The only viable model is to never execute attacker code:

1. **Write-what-where** via the `+0x08` LIST_ENTRY unlink in Flush/SetData: `[Blink]=Flink` with
   collateral `[Flink+8]=Blink` — it writes a *pointer* to an attacker address, so both operands
   must be writable kernel addresses.
2. **Bootstrap R/W** by writing `KTHREAD.PreviousMode` (`+0x232`) to 0, which makes
   `Nt{Read,Write}VirtualMemory` operate on kernel addresses.
3. **Token steal:** read the System process's token via `PsInitialSystemProcess` (ntos + 0xFC5AB0)
   and write it into this process's `_EPROCESS.Token` (`+0x248`).

Every step of that is worked out and the addresses are all in hand (§5). **What is *not* solved is
step 0 — the reclaim**, and it turns out to be the whole game:

> The MESSAGE keeps its exploitable fields **low**: RefCount `+0x00`, the unlink LIST_ENTRY
> `+0x08`/`+0x10`, the arbitrary-free Buffer `+0x18`. To weaponise the freed chunk, an attacker
> has to reclaim it with a NonPaged (`NonPagedPoolNx`, 0x70 bucket) spray whose **attacker bytes
> land at those offsets**. Every standard medium-IL primitive fails, and it fails *systemically*:

| Reclaim spray | Measured with the pool tools | Verdict |
|---|---|---|
| Pipe write-data (`NpFr`) | `DATA_QUEUE_ENTRY` header is **0x30**; payload begins at chunk +0x30 | misses every field |
| I/O ring registered buffers | bytes are read as `{Address, Length}`, and `Address` is **validated as user memory** | can't carry a kernel target |
| Mailslot (MSFS) | FILE_OBJECT → FCB data queue is **empty**; msfs keeps no separate message chunk | no chunk to reclaim |

The pattern is the point: every list-managed NonPaged object carries a `LIST_ENTRY`/header of ≥0x10
before its first attacker-controlled byte — *above* exactly where this bug needs control. So the
exploit's difficulty isn't the driver bug (a textbook locking UAF) or the mitigations (data-only
sidesteps them); it's finding a **verbatim NonPaged reclaim** at this size. That is a genuine,
open research question.

**What this walkthrough establishes, then, is exploit*ability*, not a shell:** the UAF is confirmed
and reproducible (§3), control of the freed chunk is *demonstrated* (the pipe reclaim lands
attacker bytes in it — just at the wrong offset), and the two forward primitives — the unlink
write-what-where and an **unconditional** arbitrary-free (`SetData` frees `msg+0x18` before it
reallocates) — are pinned to exact instructions (§3). The reclaim, and the double-free →
type-confusion route that would sidestep the offset problem, are where the work continues.

## Gotchas recap

- **Attach blocks on an INFINITE wait** — diagnose a hung attach out-of-band, don't hammer tools.
- **The whole guest freezes while broken in** — the KD link only runs the target in bursts between
  break-ins, too short for a WinRM round-trip. For guest-side work, `end_session` to detach fully,
  then re-attach to observe. Release with `end_session`, never a process kill (it wedges the KD stub).
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
