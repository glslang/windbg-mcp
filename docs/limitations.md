# Limitations & notes

- **TTD is user-mode only** (a Microsoft limitation): kernel debugging and TTD are distinct session
  types — you can't time-travel a kernel target.
- `launch` and `attach_process` stop the target at its initial/break-in point with a live
  process/thread context. (The binding enables the initial-breakpoint event filter — `sxe ibp` —
  which a bare `DebugCreate` host leaves off; without it the target would run free.) Note: on
  Windows 11 `notepad` is a Store app, so attaching by the PID that `Start-Process notepad` returns
  can hit `0xD000010A` (that PID is a transient launcher) — attach to a classic Win32 process.
- `read_memory` takes a numeric/`0x`-hex address only; for register/symbol expressions use
  `execute` with `db`/`dd` (e.g. `db @rip`).
- `reachable_from_dispatch` is **x86, x64 and ARM64**, and refuses anything else by name. It
  follows an instruction's control flow, which this build decodes from the encoding for those
  three sets and for no other — so on a target outside them every instruction's flow is unknown
  and any verdict would be about what could not be read rather than about the target. The refusal
  names the machine type and the tools that do work on that target, and deliberately **not** the
  list above: a reader cannot change their target's architecture, and a list repeated into a
  message is one that goes stale the first time a gate moves. Analysis that needs no control flow is unaffected there: `modules`,
  `read_memory`, `backtrace` and `disassemble` all work. **ARM64 answers on all three of these now**, which it did
  not until dbgscope decoded A64's operands: the walk needed only the flow, and `ioctl_map` and
  `driver_hazards` read what an instruction *is* — so those two declined for as long as the
  operands went unread. The gate is still there and still refuses a set whose operands this build
  cannot read; ARM64 is no longer such a set. Measured on `docs/samples/082126-7015-01.dmp`
  (26100, effective machine `0xaa64`): three `nt` routines of 30, 127 and 272 instructions walk
  with **zero** unknown flows, the engine's own rendered branch targets are reproduced from the
  encoding, and `function_extent` reports the same regions `.fnent` prints for both ARM64 unwind
  record forms.
- `reachable_from_dispatch` is a **static** call-graph walk: it follows direct calls and
  cross-function tail jumps but **not** indirect calls through function pointers or unresolved
  compiler jump tables, and it stops at any instruction whose flow it could not decode. So a
  `REACHABLE` verdict is sound (a concrete static path exists, and the path is reported), while
  `NOT REACHABLE` is best-effort within the explored bounds. **A `switch(IoControlCode)` jump table
  is crossed where it resolves**, through the same resolver `ioctl_map` publishes its tables from,
  so the two tools no longer disagree about a handler the switch selects (`FOLLOWUPS.md` item 83):
  an edge admitted there is one that resolver proved, which is what keeps `REACHABLE` sound. Where
  the table does **not** resolve the walk still ends at the jump — pass the specific handler VA as
  `from` to scope past it, or confirm dynamically with a breakpoint + `go`. That scoping narrows
  the **walk** and not the **resolver**, which reads a whole function at a time — but it still
  escapes a resolver bound in the ordinary case, because the walk probes with no tables first and
  asks the resolver only where a path from the scoped start reaches an indirect jump: a handler
  past the dispatch reaches none, so nothing is resolved and no bound of the resolver's can fire.
  Where the handler holds a switch of **its own** the resolver runs over the whole routine again, so
  a cap the *dispatch's* tables spend is reported against the scoped walk — but it no longer takes
  the handler's own switch with it: a pass that hit a cap hands over the edges it proved and says the
  set is short, rather than discarding all of them (`FOLLOWUPS.md` item 90). A `from` in another
  function does not pay this routine's tables at all. **A walk scoped that way says so**, in
  both channels, because the verdict depends on where it began: from one case block a sibling case
  is not reachable, so the same question asked from the function's entry is a different question.
- That walk is bounded by **what is left of the caller's own timeout**
  (`WINDBG_MCP_CALL_TIMEOUT_SECS`, less what it waited its turn on the session) as well as by
  `max_functions` and `max_depth`. The three are different bounds and the report says which one
  stopped it: a walk that ran out of time did *not* explore the graph it was bounded to, so it
  says so rather than reporting that the reachable call graph was fully explored. A recipe cut
  short the same way is labelled `INCOMPLETE`, because a prefix of a recipe is not a weaker
  version of one — satisfying it does not put control on the target. Each disassembly the walk
  runs carries that remaining time as its own bound, so one blocked on a deferred symbol load
  aborts rather than outliving the call that asked for it and pinning the session behind it. So do
  the commands that run *before* the walk: evaluating the address expressions and reading a
  module's base are where a cold symbol server is reached, and a deadline first consulted inside
  the walk is one the caller can outlive before it starts. The
  typed instruction decodes underneath it are bounded by their *number* rather than by their time,
  because the debugger bindings have no bounded form of that call yet
  ([dbgscope#149](https://github.com/glslang/dbgscope/issues/149)).
- A `NOT REACHABLE` also says when part of the graph it explored **could not be seen**. An
  instruction whose bytes will not read, or whose encoding this build does not decode, stops the
  walk where it is; the report counts those, withholds the claim that the reachable call graph was
  fully explored, and names the remedy. Such an instruction is a **barrier** and is never stepped
  over — skipping it would join the instruction before it to whatever follows and invent an edge,
  which is the one thing a sound `REACHABLE` verdict must never rest on. **A switch it could not
  follow is counted the same way** (`FOLLOWUPS.md` item 89): an indirect jump whose targets the walk
  did not have ends that path where it is, and whatever it reaches — a switch's case blocks, or a
  callee a tail jump goes to — is missing from the graph the verdict is about, so the report counts
  the jumps and withholds the same claim. Not all of them are switches: measured on the ARM64 kernel
  dump, ordinary `nt` routines end at indirect jumps that are tail calls through a register —
  **11** on `nt!ObpLookupObjectName` inside 24 explored functions — so the dispatch switch is the
  case this was filed for rather than the only thing it counts. **The remedies are therefore given
  per case, and the report does not say which case a jump is.** For a jump table that would not
  read they are the resolver cap's own — a specific handler VA as `from`, and on a live kernel a
  module refresh first. For a destination computed at run time neither reaches it and nothing
  static will, so that one is a breakpoint and `go`. Separating the two is not available rather
  than unbuilt: the resolver answers per listing, and per site it has targets or nothing, so
  deciding that a jump *was* a switch is the analysis that did not answer. The count is of **jumps** rather
  than of functions, and it is the walk's rather than the probe's: a switch the resolver answered
  is not among them, and neither is one on a `REACHABLE` proved with no tables at all — those were
  never offered to a resolver, which is the ordinary success inside a dispatch routine. It is
  deliberately one count for three causes, because none of them is a difference a caller can act
  on: a table read and not recovered, an instruction set whose operands this build does not decode
  (so the resolver answers nothing), and a listing in no loaded module (so there is nothing to
  bound a table's reads to) all leave the graph short of the same edges.
- **One kind of unseen edge is not counted, and on ARM64 it is reachable in principle.** The counts
  above are of instructions that stopped the walk and of jumps it ended at. A *branch class the
  decoder does not know* does not stop it: it reads as an ordinary instruction and the walk
  continues along the fall-through,
  which is a real edge, having silently lost the taken one. A64's six branch classes are the Armv8
  baseline, and Armv9.6's FEAT_CMPBR adds a seventh that
  [dbgscope](https://github.com/glslang/dbgscope) does not decode — so on a target using it the
  walk is **incomplete rather than wrong**, and the difference from the bullet above is that
  nothing in the report says so. It never costs a sound `REACHABLE`, which is what the guarantee
  rests on; it weakens a `NOT REACHABLE`, which is best-effort by contract. No target on this bench
  has one, which is also why it is not decoded — masks for an encoding nothing can render would put
  a computed branch destination behind a recollection rather than a measurement.
- `device_security` reads the descriptor a device object **keeps in itself**, which is the one the kernel checks. Every other object in the namespace keeps its descriptor in its `_OBJECT_HEADER`, and a device's header field is **null** -- measured on Windows Server 26100, where `\Device\MountPointManager`'s header says nothing and `!devobj` reports the descriptor that holds the four published ACEs. The reason is the object type's own security method: `Device` carries `TypeInfo.SecurityProcedure = nt!IopGetSetSecurityObject`, which keeps the descriptor in the device object. A tool reading the header's would report every device on that build as carrying none, which is the most permissive answer there is.
- **A device that carries no descriptor is a branch nothing measured has reached, and its advice is unverified.** Where the field is empty this tool reports **only that**, and says in as many words that *whether anything guards the object in its place* is not something it read -- hedged deliberately, since a sentence naming no mechanism can still presuppose one, and a reader who takes "protected by something I cannot see" from it has been misled in the most permissive direction there is. It used to name the holding directory; that is the ordinary account of the mechanism, it has never been measured here, and the tool has no business asserting it while reading nothing to support it. Nor has the branch been reached: on a Windows Server 26100 guest every one of the **231** device objects on every driver chain carries a descriptor, including the **66** that have no name and so cannot be looked up by path at all. So *that* outcome is one whose sentence is owed a measurement rather than a case to plan around -- but do not read this as a licence to ignore the field it arrives in. `security_absent` carries **two** outcomes and the reason string is what separates them: the other is a device that **does** carry a descriptor whose bytes would not read or parse, which is reachable, names the address, and wants that address inspected rather than any directory. A caller branches on the reason, never on the field being present. `FOLLOWUPS.md` item 68 is what settling the unreached half would take.
- `device_security` answers about the **object manager's** gate and not the driver's. An access mask is what the kernel grants on an `IRP_MJ_CREATE`; a driver is free to refuse a caller the descriptor admitted, and many do, so an ACE granting `FILE_WRITE_DATA` says a handle can be opened rather than that a control code will be honoured. The descriptor it reads is the **device object's**, which is what an open **by name** is checked against: without `FILE_DEVICE_SECURE_OPEN` the kernel does not check it when a path *beneath* the device is opened, so a driver that parses its own paths is reachable through a relative open by a caller that descriptor would have refused -- the tool says so where the characteristic is clear rather than leaving it to be inferred. Two counts say what the link search could not check, and they are **not** summable into one: `links_unnamed` counts directory entries the namespace could not name, which were never examined, while `links_unread` counts links that were examined and whose target would not read. What the directory holds is `links_examined + links_unnamed`; a single combined figure satisfies no identity and double-counts. The links it lists are the ones in `\GLOBAL??`, the system-wide DOS device directory; a link in a session's own `\Sessions\<n>\DosDevices` is not searched, those being per-logon with no one answer to give, so a device reachable only that way has an empty list here and is still reachable. A link is matched to a device by its **target path**, case-insensitively and ignoring a trailing separator, which means a link reached through a *chain* of links is not matched -- and that a link to `\Device\HarddiskVolume1\dir` is correctly not a link to the volume. The directory enumeration runs under the call's own deadline rather than only inside it: the walk is polled per entry and per chain link, so a large directory over a slow wire is cut short and reported as a partial search instead of running on after the caller has stopped waiting. It needs a **live kernel target**: a kernel minidump carries no object namespace at all -- the root directory pointer, the type table and the header cookie all read as unavailable -- so there is nothing to walk, and the refusal says that rather than sending someone to check a device name that was correct.
- `ioctl_map` recovers what it can **follow**, and what it could not is in the answer rather than missing from it. It reads compare chains, the `sub`-and-compare form a compiler emits for a rebased switch, and a jump table -- the last only when the bounds check and the table's base were both recovered, the index is the control code itself, and every entry lands in one of the image's **executable sections** (the loader's extent is not that question: `.rdata`, `.data` and the headers are all inside it, so a table matched by accident would otherwise have data addresses published as cases), because a table read at a guessed address or a guessed length is a list of plausible addresses reported as codes the driver accepts, and a switch whose index is the code **shifted** (`shr eax,2`) has several codes reaching each slot with nothing in the walk saying which of them the driver takes, so that jump is left unresolved rather than answered with one of them. **A64 sizes a table's entries to the routine and scales them in the fold**, which is two more things to get right and neither of them fails safe: the ARM64 `mountmgr`'s own dispatch routine has a four-byte `ldrsw` table and a single-signed-byte `ldrsb` one feeding two different `br`s in the same function, and the `add x8,x9,x8,lsl #2` that folds the base in is saying the entries are *instruction* counts rather than displacements. An entry read at the wrong width, read unsigned where the load sign-extends, or added unscaled lands inside the image as readily as the right one -- so each is a rule here rather than something the executable-section check below catches, and a modifier the walk cannot read refuses the table instead of being dropped. The index steps one entry at a time, which is what makes the load's scale and its width the same number and a load where they differ some other array. Every indirect **jump** it did not follow is listed, so a map with entries there is a **lower bound** on what the driver accepts; an indirect call is not listed, for the reason below. A code computed at run time, or compared inside a callee, is not there at all, and neither is one tested only in **part** -- `cmp r13w,2003h` constrains sixteen bits of a `ULONG` and matches every code sharing them, so it is not reported as a code at all rather than as the wrong one. The control code itself is `[[Irp+0xb8]+0x18]`, traced from the dispatch routine's second argument where the code allows -- which takes a **whole** pointer, so a byte of one read out of `+0xb8` ends the chain rather than continuing it, and a field at a displacement, so `[rax+rcx*4+18h]` is an array element rather than the code -- and taken from the bare `+0x18` displacement where it does not -- `code_proved` says which, and a `+0x18` off an arbitrary register is an ordinary thing for code to do, so an unproved map may be about another structure. A case says where control goes when a code matches; whether the driver **accepts** it is a separate question, answered only where the landing block gives evidence and left open otherwise. A block that sets an NTSTATUS error and returns is a rejection -- including the ordinary shape that stores the status into `Irp->IoStatus.Status` and calls a completion routine first, which is why a call alone is never read as acceptance and a rejection reports no handler, and including one written before the unconditional tail jump a shared epilogue is reached through, that being one path continuing rather than a fact established before the routine chose. A status the case block merely **arrived** with is evidence and not a verdict: storing a default failure into the IRP before deciding and letting each case overwrite it is an ordinary shape, so reading that as every case refusing would take the handler away from every code the driver accepts -- such a case comes back `accepted` absent, which is this saying it cannot tell. What matters is what the routine returns rather than what it loaded: an error overwritten before the `ret` is not a refusal, and neither is one left in the **return register** across a call -- a call returns its own status there, so a driver that means to return one reloads it, which is a thing this can see. A tail **jump out of the routine** ends it the same way, the callee supplying what the routine returns, so a dispatcher that loads a default error before its compare chain and reaches a case through `jmp handler` is accepting that code; a jump that lands back in the same listing is one path continuing and carries the status with it. The IRP's copy is untouched by a call, which is where the ordinary rejection puts it. **That field**, off a register the walk watched the IRP reach, rather than any store: an error-looking constant put in a stack local would otherwise come back as a code the driver refuses, with its handler taken away. Sizes are proven exact or absent, and five things have to hold before a compare counts as an exact length at all: it must be **at the field's width**, since `cmp cx,20h` accepts every length whose low sixteen bits are 32 and requiring 32 of a caller is not what that driver does, its base must be a register this walk watched the IO stack location reach (a displacement is not a type -- `cmp [rsp+10h],20h` is a stack slot), it must be inside the case's own region (`uf` prints regions in sequence, so a case that returns early would otherwise inherit the next one's compare), **exact** means the path continues on equality, which is `jne` -- `cmp length,0` / `je failure` rejects zero rather than requiring it -- and the branch that leaves must be the one that *fails*, since `cmp length,20h` / `jne handler` has the success on the other edge. Everything short of that is still reported, as evidence rather than as a size. A case recovered through a **jump table** has no size at all and no evidence either, whatever its landing block checks: the walk settles what a block knows over the edges the instruction encoding gives it, an indirect jump gives none, and the table that says where it goes is read after the facts have stopped moving -- so the registers on the way into that block are the ones some *other* path left there. `mountmgr` has a landing five table entries and one compare all reach, and lending that compare's registers to the five would publish its length check as the required size of codes whose own path overwrote the register it reads. It answers on **x86, x64 and ARM64**, and refuses an instruction set whose operands this build cannot read -- this needs the immediate a compare holds and the register it is compared against, and without operands a routine's whole compare chain is invisible, so the map would report a driver accepting no codes rather than a question it could not ask. The refusal says so and points at `reachable_from_dispatch`. ARM64 was such a set until dbgscope#170, and three things had to arrive with the operands for the answer there to be worth having: a **layout of its own**, since the structure offsets are x64's but none of the register names are; `movk`, because A64 cannot state a control code in a compare and builds anything above `0xfff` across two instructions; and the rule that operand zero is the destination only where the decoder says it is **written**, since A64 names a store's source first and a store read as a load invents cases out of writes to the field. The structure offsets follow the target's bitness, and on x86 both arguments arrive on the stack, so a code comes from the bare displacement and every case says so.
- `ioctl_map` forgets whatever an instruction **writes**, which the decoder answers rather than this inferring it from a first operand: `xchg eax,r13d` writes both, and `mul ecx` writes `eax` and `edx` while naming neither, so a control code that survived either would be published as a code the driver accepts. A status in the return register is one of those facts and dies with the register, so a block that loads an error and then returns something it computed is not refusing. `ioctl_map` walks a dispatch routine's **blocks and edges** rather than its listing, so a fact reaches a block only along a path that carries it: what a block knows is what every path into it agrees on, and a bounds check holds on the path it admits rather than on the one it rejects. That agreement is reached by sweeping the routine until nothing changes, and the sweeps are **bounded**: a routine that exhausts them leaves beliefs a later path would have taken away, so every case and table resting on one is discarded and `unsettled` says so. A code read off the bare `+0x18` displacement survives that, because it is something a block says on its own rather than something a path carried, and it is already marked unproved. Two things it still decides rather than proves. A slot of a jump table that goes to the switch's **default** is not reported as a code, the default being the bounds check's own branch target: a dense table covers every index in its range and a compiler fills the ones it has no case for, so `mountmgr`'s two 81-entry tables hold 13 codes each. And an indirect **call** is not a dispatch decision and is not listed as unresolved -- a driver reaches its imports that way, so every dispatch routine is full of them. A block no edge reaches -- a listing that begins mid-function -- is read with nothing believed about any register, which is why a code compared only there is not recovered rather than recovered wrongly. And **both** edges of a conditional branch it cannot decide are taken as live, which is what makes an undecided branch a lower bound rather than a guess -- except where the condition is a **constant**. A flag write between a compare and its branch makes that branch unconditional and its fall-through unreachable, and a code compared along the dead edge is then reported as one the driver accepts. No compiler emits that shape, its own branch being what it would break; `FOLLOWUPS.md` item 67 says what closing it would take.
- **Every name in a rendered answer is escaped, and that is because the target chose it.** A driver's `DriverName`, an object path, a module name, and the library and import names in an image's import table are all strings somebody being *analysed* wrote. Printed raw into a line-oriented result they can add lines to it — a heading, a finding, an ANSI escape — so each goes through `structured::renderable`, which escapes anything that could leave the row it was printed in. Escaped rather than refused: a driver named something hostile still has to be describable. The structured half was never affected, since a JSON string carries a newline without it meaning anything; this is about what a client *shows*.
- `driver_surface` **stops where a device chain leaves its driver**, rather than following it. Each `_DEVICE_OBJECT` says which driver owns it, and a `NextDevice` that points at a device owned by somebody else — corruption, or a driver object written to on purpose — would otherwise have that device's fields and its **security descriptor** reported as this driver's, along with everything after it on that chain. The foreign device is named in the halt and is not listed among this driver's, because it exists and only its membership here is false.
- **On a live kernel, run `modules` with `refresh: true` before surveying a driver.** The debugger's module inventory holds the loads it *saw*, so a fresh attach holds `nt` and little else — measured on a KDNET target: **1** module at attach against **156** after a refresh. Every driver loaded before the attach is then absent from the inventory rather than from the target, and a tool that needs a module extent has nothing to resolve against. `driver_surface` and `ioctl_map` still answer, and answer *worse*: measured on mountmgr, **19** control codes instead of **45**, with both 81-entry jump tables unresolved, because following a table requires the image's executable ranges. The map says so — the tables are listed under `unresolved`, which is what makes a short map read as a lower bound — and the hazard section names the refresh as the remedy. It is not done automatically: resynchronising has no wall-clock bound of its own (`FOLLOWUPS.md` item 54), and starting one inside a deadline-bounded composite is a way to spend a caller's budget on an unbounded call.
- `driver_surface` is the other three tools' answers joined at one driver object, and **every way each of them can be wrong it is wrong here too** -- the bullets above are its limits as much as theirs, because the IOCTL and hazard sections are `ioctl_map`'s and `driver_hazards`' own results carried whole rather than re-derived. What it adds is a **per-section status**, and the reason it is per-section rather than one verdict is that the four are read from different things and fail independently: a dispatch routine that will not disassemble says nothing about whether the import table read. So `ok`, `partial`, `unavailable` and `error` are four answers and not two, and `error` itself carries two -- a section that tried and failed, and one the survey's shared clock never reached -- which `not_started` above the sections tells apart by naming the first section that did not begin. And `unavailable` is deliberately not folded into `error` -- a target that cannot answer a section is not a failure of the call, and reporting it as one sends a reader to debug the server. Three specific boundaries. It needs a **live kernel target** for the same reason `device_security` does and no other: a driver object is in pool and is reached by walking the object namespace, and a kernel minidump captures neither -- but note that the two sections read from the *image* would answer perfectly well on a dump, which is what `driver_hazards` and `ioctl_map` are for, and the refusal names them. The per-section rule **stops at the driver object**: every section is read from something the driver object points at, so a driver object that will not resolve is the whole call failing rather than four empty sections — because three empty sections is exactly what a driver with no devices, no control codes and no sensitive imports looks like, and the fourth -- an empty dispatch table -- is not something any driver has at all, which is a tell a reader should not have to notice. And a device here carries its descriptor but **not the symbolic links that reach it**: that search lists a whole directory per device, so running it down a chain would multiply the most expensive part of `device_security` by the device count -- `device_security` on one device's path is where the links are, and nothing here should be read as saying a device is unreachable from user mode.
- `driver_surface` gives a device a **path** by listing `\Device` and matching addresses, which answers a narrower question than it looks like. A device with no path is one *that directory* does not hold, and that covers both a device the object manager filed under no name at all and one filed somewhere else -- a directory listing cannot tell them apart, which is why the result names the directory it searched and the rendering says "not in this directory" rather than "unnamed". The distinction is not academic: of the **231** device objects measured on a Windows Server 26100 guest, **66** carry no name in their object header, and that measurement counted headers where this counts a directory, so the two numbers are not interchangeable. Reading the gates is a second pass over the chain, and it runs on the **call's own clock** rather than only inside it: it is several target reads per device on top of the one that discovered the device, so it is polled per device and a survey that runs out reports the devices it did not reach rather than reading on after its caller has stopped waiting. A chain that ended at a **null `DeviceObject`** has established that the driver created no devices, and the directory listing is then beside the point -- so that section is `ok` even where `\\Device` would not list in full, and the rendering says the driver created none rather than that none were read. With devices present the listing matters again, because each of them has a path to be missing. A device the gate pass did not reach keeps the fields the chain walk read and loses only its descriptor's **contents**: that it carries one, and at what address, were read off the device object before the halt, and the third `security_absent` reason states both rather than reporting the question as open -- an open question there reads as the permissive case, which is the opposite of what was established. The device **chain** itself is bounded twice, and the two catch different shapes -- a visited set catches a `NextDevice` ring, and a cap catches a chain whose every link is a fresh address and so never repeats. A device that will not read is reported as **on** the chain and ends it: it is a device this driver created, and what is missing is what it says about itself, so dropping it would report a shorter chain rather than a hole in one.
- `driver_surface` maps the IOCTL handler **only when it is inside the driver's own image**, and says so rather than mapping it otherwise. A `MajorFunction[0x0e]` pointing outside the image is the kernel's stub for a major this driver does not handle, or a filter forwarding into the driver below it; mapping either would report another image's control codes as this driver's. `ioctl_map` takes that address directly if it is wanted anyway. The dispatch table is reported **grouped by handler** with every major function accounted for, the null entries included -- the I/O manager fills an unhandled major with its own stub rather than leaving it empty, so a null entry is a driver object that has been written to. How many major functions the table holds is read off the target rather than taken as `wdm.h`'s 28, because the cost of being wrong is reading past the object and reporting whatever follows it as a dispatch routine.
- `driver_hazards` is **evidence, not a verdict**, and each of its three limits is a way to reach a
  wrong conclusion from a right answer. An **import is not a call**: the tool reports the call sites
  it found in the code it scanned, and a call through a pointer stored earlier leaves none. An
  **absent import excludes nothing**, because a driver can resolve an export at run time through
  `MmGetSystemRoutineAddress` and leave no import-table entry at all. And a **call site is not a
  reachable one** -- whether the dispatch routine gets there is a separate question, with its own
  tool. There is no decompiler here, so "this driver copies a user buffer without probing it" is not
  a question it answers; what it answers is that the driver imports both, and where each is called.
  What counts as sensitive is a curated judgement rather than a fact about Windows, which is why the
  result carries the version of the list it was scanned with. It answers on **x86, x64 and ARM64**, and refuses an
  instruction set whose operands this build cannot read -- the same operand gate `ioctl_map` has
  and not the reachability walk's flow gate. ARM64 was refused until dbgscope#170; what had to
  arrive with the operands is a family table **per architecture** (x86's `str` is the task register
  and A64's is an ordinary store, so one table reported every store in an ARM64 image as a
  descriptor-table access) and a pass that follows `adrp`/`ldr`/`blr`, A64 having no pc-relative
  memory operand for an import call to name its slot in. `privileged` is the decoder's own answer about an instruction, and
  a sensitive call is named by the import slot inside a memory operand; neither is a question about
  control flow, so on a set whose operands are unread this would report a driver with no privileged
  instructions and no call sites, which is what a clean driver looks like.
- On a **dump**, whether a driver's code reads at all depends on whether the engine can obtain its
  image, and the dump's type does not predict it — probe rather than assume. Measured on the
  x64 kernel minidump under `docs/samples/`, with no executable image path set: every code RVA
  probed across `mountmgr` read and the walk returned a complete answer. What a dump never yields
  is a driver's **writable** pages, so the import address table reads as `????` however the code is
  obtained — which is why imports are named from the read-only import lookup table and no slot is
  ever dereferenced. When code will not read, the remedies are a symbol path that can serve the
  image binary (the Microsoft symbol server serves images as well as symbols) or `.exepath` plus
  `.reload /f` for a driver it does not have.
- The **kernel pool** tools (`pool_find_tag`, `pool_chunk`, `pool_census`, `pool_diagnostics`) walk the allocator's own
  descriptors through dbgscope rather than shelling out to `!pool`/`!poolused`, so all four read
  one snapshot and cannot disagree with each other. They need a **broken-in x64 or ARM64 kernel**
  target — ARM64 since dbgscope#179, which lifted the gate after the walk was checked against
  `!pool` block for block on a live ARM64 kernel (`FOLLOWUPS.md` item 96).
  Walking every pool page is expensive, so the snapshot is **cached per session** and reused; pass
  `refresh: true` after letting the target run, or you are reading a photograph of a target that has
  since moved. A walk that does happen is bounded by **what is left of the caller's own timeout**
  (`WINDBG_MCP_CALL_TIMEOUT_SECS`, less what the query waited its turn on the session), so it can
  neither outlive the call that asked for it nor stop early while that call is still waiting; a walk
  cut short still answers, and every result says how much of the pool it reached. `interrupt` ends
  one sooner. `pool_find_tag` can also stop deliberately at a nonzero `stop_after_matches` count;
  that result reports `match_limit_reached`, is not cached as exhaustive, and keeps its counts as
  floors. A complete cached snapshot still answers exhaustively. This traversal threshold is
  independent of `limit`, which caps only the rows rendered. A query that reaches the engine with
  no time left to walk in — a call timeout at or under the 15s the reply itself reserves, or a
  long wait behind other work on the session — is
  *refused* rather than run, since a truncated walk is discarded rather than cached; without
  `refresh` it is still answered from the cached snapshot if there is one. Two semantics worth knowing: only *allocated* chunks are indexed by tag (a freed
  chunk's tag is not reliably preserved, so `pool_find_tag` never reports freed memory — ask about a
  specific address with `pool_chunk` instead), and `pool_chunk` reports three outcomes that are
  easy to conflate. A chunk in an explicitly free state (`ReusableFree` or `CachedFree`) is the
  one that means a pointer the target still holds is dangling. An address **not covered by the
  snapshot** is not the opposite finding: a region the walk never reached looks exactly like
  memory that was never pool, so read the coverage the tools print — and `pool_diagnostics` for
  what was missed — before concluding the pointer never pointed at pool. A span reported
  `Unreadable` is the walk's own limit (a Verifier guard page reads that way) and says nothing
  about whether the allocator freed anything. `pool_chunk` also
  reports the **neighbouring** chunks, which is what tells you what a reclaim would land next to. `pool_diagnostics` returns the walk's own diagnostics filtered by substring: a real walk emits tens of thousands across a hundred-plus categories, so any per-call summary truncates and the one line explaining a specific heap is never in the truncated head — filter by a heap address or a phrase to reach it.
- The **user Segment Heap** tools share that typed decoder. They discover roots by following
  `ntdll`'s process heap list, which is what `GetProcessHeaps` walks. They reach it through the
  process heap's PDB-typed `UserContext`, and check every entry against the heap it names. They do
  not trust the PEB for this. On current Windows `_PEB.ProcessHeaps` names the process heap alone,
  and it is the answer only on a build that keeps no list. A list that cannot be followed makes the
  walk `partial`, with a diagnostic naming where it stopped. They require a stopped x64 user
  target (or a dump with sufficient memory) and the exact loaded `ntdll` PDB. `heap_list` reports
  every root and explicitly separates Segment Heaps walked from classic NT, unknown, and unreadable
  heaps skipped. V1 does not decode classic NT heaps, WOW64, or ARM64; use `!heap` for classic heaps.
  Snapshots are cached per target/PEB/`ntdll` image and invalidated when execution resumes; pass
  `refresh: true` for the final observation after target execution. Allocation `capacity` is always
  allocator-backed, while `requested_size` is optional and appears only when the selected schema
  validates exact unused-byte metadata. `heap_allocations` defaults to `state: allocated`; when
  investigating freed memory, pass `state: reusable_free` or `state: cached_free` explicitly. Two
  further states are gaps rather than chunks: `uncommitted` is address space with no pages behind
  it, confirmed against the memory manager (`QueryVirtual`) rather than inferred from where the
  span lies, and `unreadable` is everything else the walk could not read — memory the process
  does have, *and* memory nothing could be asked about. It is the conservative bucket rather than
  a claim, so only it makes the walk `partial`; `walk.uncommitted_gaps` counts the second. A kernel pool walk cannot be
  asked that question and counts every span it could not read. Read
  `layout`, `scope`, and `walk` before treating an absent allocation as evidence. The agent workflow is in
  [`skills/windbg-debugging/heap-walking.md`](../skills/windbg-debugging/heap-walking.md).
- **A 32-bit user-mode target is opened by a worker of its own architecture, and what that buys and
  costs is worth knowing before you reach for either.** An extension DLL is loaded into the
  debugger's own process, so SOS on a 32-bit .NET target is reachable only from a 32-bit host: the
  32-bit `sos.dll` will not load into an x64 engine (`Win32 error 0n193`) and the 64-bit one loads
  and then refuses the target (`Failed to load data access DLL, 0x80004005`), the CLR data access
  DLL being paired to the target's architecture as well as the host's. So a 32-bit dump, and an
  `attach_process` on a WoW64 process, are routed to an `x86\windbg-mcp.exe` worker. Nothing about
  that is visible to a client — one server, one handle, one tool surface — and where the worker or
  its 32-bit engine is absent the target **still opens**, on the x64 build, with an opener
  `limitation` saying SOS is unreachable rather than a failure: native analysis of such a target
  works and always has. Two things such a session does not have, and only one of them is about the
  worker. The `heap_*` tools refuse a 32-bit process whichever worker holds it — a 32-bit worker
  sees an x86 machine (*"heap walking supports x64 and ARM64 targets only (machine 0x14c)"*), and
  a 64-bit one sees WoW64, whose 64-bit heaps are the emulation layer's rather than the
  program's — so SOS's own `!dumpheap`/`!eeheap` are the managed equivalent. The other **is** the 32-bit worker's own trade: a live WoW64 `attach_process`
  there sees only the 32-bit half of the process. The emulation layer above 4 GiB (`wow64.dll`,
  `wow64cpu.dll`, `wow64win.dll` and the 64-bit `ntdll`) is what the x64 engine reaches with
  `!wow64exts.sw` and this one cannot — measured on one process, 36 modules against 30. That is the
  right trade when you are here for SOS and the wrong one for debugging the thunk layer itself; for
  both halves, take a `procdump64.exe -ma` capture and open that, which routes to the x64 engine. A
  dump loses nothing, a 32-bit capture never having held the 64-bit side. The engine payload to copy
  is in [`setup.md`](../skills/windbg-debugging/setup.md).
- **`crash_triage` reads a bug check two ways, and keeps them apart.** The code and its parameters
  (`ReadBugCheckData`), the stack, each frame's module, and the crashing process (out of the current
  `_EPROCESS`'s audit name — the full image name, not the 15-byte `ImageFileName` that turns
  `mm_exploit_v5.exe` into `mm_exploit_v5.`) are engine reads. The pool tag, the
  failure bucket, the blamed module and the per-parameter explanations exist nowhere but `!analyze`'s
  own output, so they are extracted from it and confined to the `analysis` object. **Prefer
  `faulting_frame` to `analysis.module_name`**: the frame's `module+RVA` is computed from the load
  base, so it names the driver on any host that can read the dump, while `!analyze`'s attribution
  additionally needs `triage\triage.ini` beside the engine and reports `Unknown_Module` without it
  (`skills/windbg-debugging/setup.md` has the copy step). A missing PDB costs the *function* on
  both — neither answer names one. **Which frame is the culprit is still a guess, though — only the offset is computed.**
  `faulting_frame` is the innermost frame that *could* be a kernel driver: not `nt`/`hal`, not the
  framework layers that sit on a stack on somebody else's behalf (KMDF's `Wdf01000`, Driver
  Verifier), and not a user-mode module — a kernel stack that unwinds past the system call boundary
  runs on into `ntdll` and the caller's own `.exe`, and neither can be a driver. It is still
  positional, so a crash routed through a layer this build does not recognise names that layer
  instead of the driver behind it. The text
  prints `!analyze`'s attribution beside it whenever the two disagree and tells you to settle it
  from `frames`, where every `module+RVA` is sound whichever guess is right. `faulting_frame` is
  **absent** when the whole captured stack is in those images; `faulting_frame_note` then says
  whether that is the crash itself (a `0x9F` watchdog fires on an idle CPU — the culprit is not on
  that stack, and the bug check *arguments* are where to go next) or merely the 16-frame default
  cap, which `frames` raises to 128. `analyze: false` skips `!analyze` for a fast answer of
  everything else. **The call leaves the session exactly as it found it**, which running the same
  `!analyze -v` through `execute` does not: the analysis resets the selected scope to the target's
  default, so a `.frame`/`.cxr` a caller had chosen would be silently discarded — `crash_triage`
  saves that scope and restores it (`ScopeGuard`, [dbgscope#98](https://github.com/glslang/dbgscope/issues/98)),
  which is why the tool reports itself read-only. The stack it walks is the **default** context
  (the crash, on a crash dump) whenever the analysis ran to completion — running it is what resets
  the scope there — and whatever the session has selected when it did not: `analyze: false`, no
  time left, no `ext.dll`, or a run the deadline cut short before the reset it does partway
  through its output. `analysis.ran` and `analysis.truncated` distinguish them. Needs a kernel
  target
  *stopped at a bug check* — a live kernel that has not crashed yet, and a dump that is not a crash
  dump, are both **refused** with a message saying which of the two they are.
- **`exception_triage` reports three kinds of fact and labels the weakest.** The exception record,
  its decoded code and the stack are reads of the dump. The thrown C++ **type** is decoded from
  MSVC's own `ThrowInfo`/`CatchableType`/`TypeDescriptor` chain, whose layout the compiler fixes.
  The thrown **HRESULT** is located by the `0xAABBCCDD` sentinel a `winrt::hresult_error` carries,
  which no header states — so it comes with `hresult_confidence`, `corroborated` when the type name
  independently said `hresult_error` and `convention` when the sentinel stands alone.
- **The thrown type needs the throwing module's image, and a minidump does not contain it.**
  `ThrowInfo` and everything it points at live in the image's `.rdata`, which the debugger reads
  off the binary on disk — measured: the walk succeeds while the executable is at its recorded path
  and returns `????????` once it is moved aside. So a dump from another machine, or one whose
  binaries have moved, reports no `type_name` and says why in `type_note`, and the HRESULT still
  comes back, because the thrown object is on the *stack* and therefore captured. Neither route is
  a superset of the other; both are tried.
- **A minidump without the faulting module's image unwinds badly on x64, and that is a fact about
  dumps rather than about this server.** (x86 is not affected the same way — its unwind is
  frame-pointer based, and the 32-bit fixture walks its whole stack with the image moved aside.) The unwind data lives in the image's `.pdata`, which a
  minidump does not capture, so the engine reads it off the binary on disk. Measured on the
  checked-in fixture with its executable moved aside: frame 0 is right either way — it comes from
  the recorded context rather than from unwinding — and beyond it the frames alternate between
  resolved ones and frames attributed to no module at all. Every frame's `module`+`rva` is still
  computed rather than guessed, so a *hole* in the attribution is the signal: a walk with one is a
  walk this host could not do, not a stack with an unusual frame in it. Put the binaries where the
  debugger can find them (`.exepath`, or beside the dump) before reading a stack from a dump that
  came from another machine.
- **`0xc0000409`'s dismissal is conditional, because for two subcodes the code's name is the
  literal truth.** `FAST_FAIL_LEGACY_GS_VIOLATION` (0) and `FAST_FAIL_STACK_COOKIE_CHECK_FAILURE`
  (2) are the compiler reporting that a `/GS` guard between a local buffer and the return address
  was overwritten — so stack corruption *is* the finding there, and the summary says so instead of
  leading with "not a stack buffer overrun".
- **The value after the `0xAABBCCDD` sentinel must be a failed `HRESULT`.** The sentinel is four
  bytes with no header behind it, so it occurs by chance; the claim about a hit has always been
  that the number after it decodes, and now that is tested rather than asserted. A
  `winrt::hresult_error` exists to carry a failure, so bit 31 is set in every one — a success code
  or a small member value there means the object is not one and the match was a coincidence. The
  check is structural rather than "resolves to a message", so a failed `HRESULT` from a component
  whose table this host lacks is still reported.
- **The `0xAABBCCDD` sentinel is not read when the thrown type was read and is not an
  `hresult_error`.** Those four bytes have no header behind them, so they occur inside objects that
  have nothing to do with `winrt`; what makes a hit believable is the *type* saying to expect one.
  A type that was read and disagrees is contrary evidence rather than absent evidence, so no
  `hresult` is reported and `type_note` says why — reporting the dword after a coincidental match
  would invent a failure code out of some unrelated member's value. The sentinel still answers when
  the type could not be read at all, which is the ordinary minidump case.
- **A `0xc0000409` with no parameters reports no subcode**, rather than the zero an absent field
  would default to — zero is `FAST_FAIL_LEGACY_GS_VIOLATION`, so defaulting named a specific
  security check that the record never mentioned. Every real `__fastfail` supplies a subcode; one
  that does not is truncated or synthetic, and the summary says so.
- **A search that did not run reports no result.** The buried-throw scan is skipped when the
  caller passes `scan_stack: false`, when the fault shape never buries a throw, and when the walk
  gave no frame to anchor on — and the summary used to tell all three that *no throw record was
  found on this stack*, which is the result of a search none of them performed. A caller who turned
  the scan off was being handed the outcome of the search they had just declined. The state that
  means "nothing was looked for" is now its own and carries which of the four reasons applied, so
  the summary says the stack was not searched instead of what searching it found.
- **And it draws no conclusion from the subcode it has not got.** Preserving the field was half of
  that: the summary went on giving such a record the dismissal above — "not a stack buffer
  overrun" — which is the *other* thing only a subcode can support, since the two `/GS` subcodes
  are exactly that. So there are three answers rather than two, and a record with no parameters
  gets the one that says nothing has been established. A negative finding read off an absent field
  is the same mistake as a positive one, and reads more convincingly.
- **A scanned throw record is never this fault's cause, only a candidate for it.** A C++
  `EXCEPTION_RECORD` outlives the frames that held it: a `try`/`catch` unwinds past one without
  erasing it, so a later direct `abort()` running deeper than the old throw site finds a valid
  record above its stack pointer. Measured, on `docs/samples/stale-throw-abort.dmp` — the scan
  really does promote a candidate there, so "the scan will not find one" is not the guard. And
  **no property of the stack separates the two**: in both cases the record sits above the stack
  pointer inside a live caller's frame. So `thrown.provenance` says `scanned` for anything the scan
  produced and `reported` only when the debugger stopped on the throw itself, and the summary never
  names an uncaught exception on the strength of a scan. What settles it is whether the throw site
  is on the stack above, which the frames are there for a reader to check.

  What *is* checked is the candidate rather than the stack: a thrown object is copied onto the
  stack by `_CxxThrowException`, so a record whose `object` points outside the scanned range
  belongs to no throw on this thread. On the stale-abort fixture that rejects the only candidate —
  its `object` is a code address in the faulting image — and the tool reports no throw at all,
  which is right. It is necessary rather than sufficient: a genuinely stale record has its object
  on the stack too.
- **An exception code is decoded as an `NTSTATUS`, and a bare code is decoded as both.** The two
  namespaces overlap and the system message table answers for the wrong one where they do:
  `0x80000003` is `STATUS_BREAKPOINT`, and `FormatMessage` reads it as `E_INVALIDARG` — "One or
  more arguments are invalid". So `exception_triage` decodes the record's code as a status, while
  `decode_error_reporting`, which is given a number of unknown provenance, reports every reading
  and leads with the `HRESULT` one. Both tools carry `system_message` and `ntstatus_message`
  side by side regardless; the difference is only which leads.
- **The buried-throw scan runs on one fault shape, and reports nothing on the others.** It is
  `abort`'s fail-fast — `0xc0000409` with subcode 7 and **exactly one** parameter — because that is
  the fault whose cause is somewhere other than its own record. It deliberately does *not* run on
  every fault that carries no throw: a C++ `EXCEPTION_RECORD` outlives the frames that held it, so
  an access violation deeper on the stack than an old `try`/`catch` would find that handled
  exception's object and report it as the cause. A specific wrong answer is worse than none, so on
  an access violation, a breakpoint or a WIL fail-fast there is no `thrown` and the record's own
  fields are the whole answer.
- **The C++ EH decode is laid out at the *target's* pointer width, which is not this build's.**
  A 32-bit throw raises **three** parameters where a 64-bit one raises four — the fourth is an image
  base, and a 32-bit graph's links are absolute pointers needing none — its `EXCEPTION_RECORD` is 80
  bytes rather than 152 with the parameter count and the parameters both earlier, and
  `TypeDescriptor::name` sits at `+8` rather than `+16`. All measured, by building one program twice
  and having it print its own record and walk its own graph. Every one of those differences makes a
  mismatched reader come back *empty* rather than fail, so the width is asked per target rather
  than assumed; `docs/samples/cppthrow-fastfail-x86.dmp` is the fixture that keeps it honest.
- **Asking takes two questions, and one of them cannot be asked about a dump.** The engine's
  `GetActualProcessorType` answers for the **physical processor**, so a WoW64 process on an x64 box
  comes back `0x8664` — measured, by launching `C:\Windows\SysWOW64\cmd.exe` under a 64-bit
  worker. It is nonetheless the right answer for a dump, whose header records the machine it was
  written for, so a process **running on this machine** is asked about a second way:
  `IsWow64Process2` on the process id, which is what the worker routing already uses to pick an
  image. Nothing else is: a dump's and a TTD trace's recorded process ids name a process that had
  exited before the file was written, and some unrelated live process may have inherited the number
  since — which is not a query that fails but one that succeeds about the wrong process, so it would
  be a confident wrong width on a target whose own file already says the right one. A kernel's
  belong to the debugged machine and were never this host's at all. What neither source tracks is
  the engine's *effective*
  machine (`GetEffectiveProcessorType`), which follows a WoW64 target across the transition and is
  not in the pinned `dbgscope`; `FOLLOWUPS.md` item 58 carries it, with the measurement of where
  the approximation and the authoritative answer differ.
- **`exception_triage`'s stack comes from the stored crash context where the target has one.** That
  is what `.ecxr` adopts, walked without `.ecxr`'s effect on the session, so the caller's selected
  thread and frame are left alone — which is what lets the tool be read-only where `crash_triage`
  needed a scope guard. A kernel session is **refused** — a kernel crash dump carries no stored
  event at all, measured, and its bug check is `crash_triage`'s.
- **Two fields, because "not from the stored context" has two causes and they are not the same
  news.** `stored_crash_context` is what the target *had*; `frames_from_stored_context` is what the
  walk got. Both true is the crash. Both false is a **live** target, where the stack is whatever
  thread is selected and is not promised to be a crash. The pair that matters is
  `stored_crash_context` true with `frames_from_stored_context` false: a dump written *for* a fault
  whose own crash context would not walk, which on a dump usually means the faulting module's image
  — and so its unwind data — is not where the debugger can read it. The walk is best-effort by
  design, since the record and the thrown object are the answer and a triage that could not walk
  still carries both; what it must not do is describe that failure as a target that had nothing to
  walk from.
- **`decode_error_reporting` reads the host's message tables, not the target's.** The structural
  fields — severity, facility, code, the customer bit — are arithmetic and cannot differ between
  hosts. They can differ between *readings*, and the facility is where: an HRESULT's is eleven bits
  and an NTSTATUS's is twelve, so a value with bit 27 set has two, and both are reported. The
  message text comes from this machine (`FormatMessageW`, plus `ntdll`'s table for an `NTSTATUS`),
  so a dump from a build that words an error differently is described in this host's words;
  `message_provenance` says so on every answer that carries one — and says only that, since this
  tool is pure and the value it decoded came from its own argument rather than from any target. It
  reports **both** readings
  rather than choosing, because a bare dword does not say which space it came from: severity is one
  bit as an HRESULT and two as an NTSTATUS, and `0x80670015` is a *failed* HRESULT whose top two
  bits read as an NTSTATUS *warning*.
- **`crash_triage` tries `!analyze -v` and then `!ext.analyze -v`**, and reports which one worked
  under `analysis.command`. A **manual** `execute` has to pick, and on the bundled engine the
  answer is the module-qualified `!ext.analyze -v` — the unqualified form does not resolve there
  even after `.load ext` (see [*Bundling the WinDbg engine*](./install.md#bundling-the-windbg-engine)). On a **partial minidump**, reads of
  pages that weren't captured raise `An unexpected exception was raised (0x80040205)` rather than a
  clean "memory read error"; query the specific field you need (e.g.
  `dt nt!_DRIVER_OBJECT <addr> DriverName`) instead of dumping whole structures. See the
  [crash-dump walkthrough](crash-dump-walkthrough.md).
- **That failure is all-or-nothing inside a `.for` loop**, which is what `walk_memory` is for: one
  unmapped dereference takes the whole script down with no rows at all, and the node it happened on
  is usually the interesting one. Walk a list, an array or a chain with `walk_memory` and each hole
  is a marked value instead.
- Single-stepping is only valid once the target is stopped with a real thread context (after a
  `go`/step or a breakpoint hit). Stepping straight after a bare `goto_position` to the very start of
  a trace (before any thread is live) returns `0x80040205` — `go` to a breakpoint first.
- Symbol *names* (`module!func`) need (a) `msdia140.dll` bundled next to the binary, (b) a symbol
  path pointing at the PDBs (`.sympath …`), and (c) for TTD, reloading at a *stopped* position
  (after a `go`/breakpoint, not straight off a `!tt`) so the module's PDB is matched and loaded.
  With those, e.g. `ttd_calls("ucrtbase!__stdio_common_vfprintf")` returns the exact call count.
  Without symbols, the data model, navigation, and memory reads still work — query by address.
- **One command at a time per session.** Sessions run concurrently, but each one is a single engine
  processing operations serially, so a call against a busy session waits its turn. Issue tool calls
  for a given session **sequentially — await each result before sending the next**: the server does
  not order concurrent in-flight requests against each other, so pipelining them (firing several
  calls before their results return) can run a command before the one that establishes its state,
  and is meaningless for stateful, order-dependent debugger commands anyway. Standard MCP clients
  already serialize call→result, so this is only a concern for custom/batched callers.
- **Sessions are a bounded resource.** Each is a process holding a dump, a trace, or a live target,
  and at most `4` are open at once. `end_session` when you are done with one rather than relying on
  the oldest idle session being reclaimed.
- TTD **replay** (`open_trace`) needs `TTDReplay.dll` discoverable but **not** elevation; TTD
  **recording** (`record_trace`) needs `TTD.exe` **and** Administrator. `record_trace` captures the
  recorder's startup output to `<out_dir>\ttd_record.log` and watches it briefly, so a fast failure
  (e.g. running un-elevated → `0x80070005 Access is denied`) is reported as an error rather than a
  false "recording started". A target that *finishes* inside that watch is the other case, and is
  reported as a **complete** recording naming the finished `.run` — so `record_trace` answers one
  of two things on success, and only one of them has a trace ready to open.
- **Control-flow tools (`go`/`step*`/`reverse_*`) wait 60s for a stop, then break the target in.**
  The command is issued and the engine pumped to the next stop; if the target has not reached one
  by then the debugger raises a Ctrl+Break, so the call returns with the target *stopped where it
  happened to be* rather than left running. That case is reported rather than left to be inferred:
  `timed_out` is set in the structured result and the text says so. It is not an error and not an
  `interrupt` — nobody asked — and the next move is to run the target on, or to give it something
  to stop at.
- **A raw `execute` of an execution-control command works, and is not the same as the typed tool.**
  `g`, `p`, `t`, `bp X; g` and anything else that reaches execution moves the target: the server
  asks the engine whether a command left it running and pumps it if so, under the same 60s bound.
  What you get back is the debugger's output plus a line naming where the target ended up — there
  is no structured `stopped_at`, no typed `timed_out`, and a step prints nothing of its own, so
  that line is the only position in the answer. The typed tools are still the better call.
- **A target that runs to completion ends the session, and that is not a failure.** A `go` (or a
  step, or a raw `g`) whose debuggee exits reports the ending — `target_gone` in the structured
  result, and a sentence beside it — carrying whatever the run printed on the way there, which is
  the only copy: the command prints its own echo, while module loads, a breakpoint banner and an
  embedded script's output all arrive during the wait. `.detach`, `q` and `qd` end it the same way.
  Afterwards every call on that session is refused with one message and the category
  `stale_session`; `end_session` releases it, and opening again gets a fresh target. There is no
  way to reopen a target inside an existing session, and `session_status` still reports such a
  session as `open`.
