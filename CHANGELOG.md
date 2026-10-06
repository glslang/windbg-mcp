# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **A single failed PDB fetch turned a required check red** (issue
  [#457](https://github.com/glslang/windbg-mcp/issues/457)). The debugger tier's four
  target-reading assertions ask the host what it can do before they assert anything, and print
  `SKIPPED` where they cannot; `ci.yml`'s guard step then fails the job if any of those messages is
  in the log, because a skip otherwise passes and a broken symbol copy reads exactly like a green
  run. That step carries no `if:`, and the unsuffixed **x64** entry it judges is a *required status
  check* in the repository ruleset — so on 2026-10-05 it blocked a `rmcp` 3.4.1 -> 3.5.0 bump with
  `137 passed; 0 failed`. Measuring the job rather than taking the report is what moved the fix:
  the log holds **one** stand-down, not four, from the driver-crash test, while
  `a_dump_session_opens_reads_and_closes` resolved `nt`'s PDB in the same run and no read gate stood
  down at all — so `symsrv.dll` was being read the whole time and a single round trip to the symbol
  store had failed. Re-running the job unchanged passed. That rules out the direction the issue
  offered first, running the ARM64 symbol-half copy on x64 too: the entry's symbol half was there,
  and copying it again prevents nothing. So the **gates** ask three times
  (`mcp_smoke::SYMBOL_FETCH_ATTEMPTS`), and the asks in between *change the configuration* rather
  than repeating it — `symbol_path()` appended and `.reload /f nt` forced, which is the expression
  every other symbol-needing test on this bench already shares, `WINDBG_MCP_SMOKE_SYMBOLS` override
  included. Appending it is not ceremony: the engine's ambient default expands to a `cache*` naming
  no directory, a store element that is skipped and reads as an absent PDB, which four runs of the
  pool tier were once spent on. Only the last ask waits (`SYMBOL_FETCH_BACKOFF`), the first refetch
  being a different configuration rather than a retry of one. **Both** gates retry, not just the
  PDB one: they stand down for a single cause and the guard greps for their two messages alike, so
  retrying one would have left the same blip able to fail the same check through the other, a moment
  earlier in the same dump. What this does not soften is the regression the guard exists for — an
  image with no `symsrv.dll` has nothing to retry with, every attempt fails, and #153 is red there
  exactly as before; a retried blip is the only cause of a stand-down that re-running ever cured.
  The two skip messages also lost their `(issue #142)`, the other half of the report: they are
  printed into a CI log, where a parenthesised closed issue about a *stack walk* reads as a live
  tracker for the *symbol* failure in front of you. The pointer stays in the doc comments above
  them, which link it as the history it is. `tools/local_model_eval.py`'s `kernel_symbols` gate
  loses the same parenthetical, for the first of those reasons and not the second: the symptom it
  names — a stack walk giving back the bug check's own parameters — *is* #142's, so that citation was
  pointed at the right thing, and what it shared with the other two is a closed issue sitting in
  output a reader is invited to go and open, under a title ("an ARM64 engine cannot read virtual
  memory from an x64 kernel dump") the repo has since recorded as the wrong reading of it. **And the retry is asserted somewhere a green tier run
  can reach**, because the tier itself cannot: symbols resolve on the first ask on both CI entries,
  so every claim about the second and third would have rested on nothing having run — the same
  vacuity the `!analyze` assertions were found in. `before_ask` returns the schedule as a value, and
  `the_symbol_retry_schedule_refetches_before_every_ask_but_the_first` asserts it with no engine,
  dump or network, under plain `cargo test`. Mutation-verified in four directions, on the Mac — pure
  Rust lifts out of this Windows-only crate into a `rustc --test` of its own. The one shape it
  cannot see is the refetch moving to *after* the ask that failed, which spends two fetches and asks
  nothing again; that is prevented structurally, the ask being the last statement of the loop body.

- **`ioctl_map` recovered control codes from blocks execution never enters** (`FOLLOWUPS.md`
  item 67, in `DONE.md`). The walk swept both edges of every conditional branch, which is right
  wherever the condition depends on anything and wrong where it is a constant: `xor ecx,ecx` before
  a `je` sets the zero flag, so the branch is taken for every request and its fall-through is
  unreachable -- and every compare along that fall-through was reported with a landing, a handler
  and sizes, with nothing saying the path was hypothetical. `decides_zero` now folds the six
  self-cancelling idioms into a known zero flag -- `cmp r,r`, `sub r,r` and `xor r,r`, whose result
  is zero whatever the register held, plus `test r,r`, `and r,r` and `or r,r` over a register this
  pass watched a literal into -- an equality branch reading one takes a single edge, and a settled
  branch records no `untracked` site either, there being no test to name. What that removes is the
  **proved** fabricated case: a compare through a register recovers nothing along a dead edge,
  while the bare `+0x18` fallback needs no fact and still publishes its code there, marked unproved
  and taking `code_proved` off the map with it -- item 5's heuristic answering as it does in any
  block no edge reaches, and pinned by a test of its own. A flag write whose result
  depends on the **code** is still swept both ways: `sub r13w,8` leaves a zero for exactly the codes
  ending in 8, which is decided per request rather than once, and that is path sensitivity. Nor is
  a branch reading a register beside the flags -- `loope` is `ZF` and a counter both, and the fold
  asks `Instruction::reads` rather than a mnemonic list, so `jrcxz` and `loop` are out by
  construction. And the test for *whether the flags were replaced* is
  `writes_flags || settles.is_some()`, not the field alone: x86 reports `rflags_written()` of
  nothing for `xor r,r`, the outcome being statically known, so reading the field alone sent the
  two idioms the fold exists for down the no-flag-write path and made it inert on a real target. That
  stand-in is gated on `Layout::static_outcome_hides_flag_write`, because A64's non-`S` `sub` writes
  no flags at all and standing in for it would drop the compare a following `b.eq` is really
  reading. **No
  compiler emits any of this** -- its own branch is what it would break -- so the answer for a
  compiled driver should not move, and does not: `rdyboost+0xf6a0` (21 codes) and
  `mountmgr+0x17880` (48 codes) are byte-identical across the two builds. What it is measured by is
  the generated differential, whose `noise` could not put a flag write between a compare and its
  branch while the walk could not settle one and now can: backing the edge drop out fails its sweep
  on seed 29.

- **`ioctl_map`'s documented entry width said `DWORD` where the code admits one, two or four bytes**
  (`docs/structured-results.md`). `entry_width` takes any of those so long as the load's scale
  equals the width, because A64 picks the narrowest that reaches every case --
  `mountmgr!MountMgrDeviceControl` has a four-byte `ldrsw` table and a single-byte `ldrsb` one,
  feeding two different `br`s -- so that clause described a rule this tool stopped having when the
  A64 widths landed, and a reader checking an answer against it would have expected a byte table to
  be refused. It states both halves now: one whole entry for a table read through a register, and
  four bytes for the 32-bit form that jumps through its own table, where nothing is folded in and an
  entry **is** the address. Found while closing item 66, whose rewrite does not touch it.

- **The differential oracle kept its chain's codes and its switch's apart in a comment and nowhere
  else** (`src/ioctl/tests/differential.rs`). A chain code is drawn as `BASE + offset` with
  `offset` under `0x2_0000` while the switch's own base is `BASE + 0xc000`, so four draws in
  131,072 land on codes the switch's bounds check admits -- a routine whose `cmp`/`je` recognises a
  code the table below also routes. Execution leaves at the `je`; the map reports a case per
  **site**, which is the answer it documents; and the property fails on a map that is right. **It
  was never a flake**: a routine is a function of its seed, so the committed sweep builds the same
  1,024 routines every run -- seed **623** draws into the window and emits no switch, so the
  property holds on it, and seed **8099**, the first where both happen, is eight times past where
  any committed run looks. It was found by running the sweep at 65,536 seeds for item 66, where it
  failed identically on the resolver *before* that rewrite, which is what said the defect was the
  generator's. `SWITCH_CODES` now bounds both the
  switch's limit and the window the chain draws outside, from one constant so the two cannot
  disagree. The committed sweep measures **1,097 cases over 262 tables** where the figure beside it
  said 1,098: the one case is a compare in that window whose routine emits no switch at all, the
  rejection being unconditional.

- **A jump-table base the compiler built in two instructions survives the second one**
  (`FOLLOWUPS.md` item 84, in `DONE.md`). A64 materialises a page-relative address as
  `adrp x8,<page>` / `add x8,x8,#<offset>`, and `ioctl::update` modelled `Effect::Add` only as
  `Value::Code + immediate` -- so the `add` cleared the register, `follow_table` found no base, and
  the dispatch `br` went back `unresolved`: the safe direction, and silent about which part was
  lost. **It is a codegen choice rather than a reach one**, which is why it is not a large-driver
  edge: `adr` covers ±1 MB, and `mountmgr` emits the pair at **139 KB**
  (`mountmgr+0x19450` is `adrp x8,mountmgr!QueryPointsFromMemory+0x610` / `add x22,x8,#0x4E8`, four
  instructions past one of its two jump tables). The arm is in the fact walk, so it serves all three
  places a switch takes an address from -- the table's base, the base its signed entries are
  measured from, and an MSVC byte map's. **Gated on the destination's width**, which the item did
  not ask for and is the half that decides the direction: `add w8,w8,#K` writes four bytes of a
  64-bit base and zeroes the rest, and a model computing at the pointer's width would resolve the
  switch from bytes at an address execution never formed -- the question `Value::carried_by` already
  asks of `mov ecx,edx`, asked of arithmetic. No driver on this bench uses the pair for a table
  *base* -- `mountmgr`'s instance is past a table rather than under one -- so both halves are pinned
  by fixtures built from that driver's real offset, each mutation-verified against the state before
  the change: without the arm the switch recovers **no cases at all**, and without the guard it
  publishes **two** from a truncated base.

- **An image target's memory reads on the first call** (`FOLLOWUPS.md` item 111, in `DONE.md`). A
  PE opened with `open_dump` and no debuggee answered a virtual read with `0x8007001E` — *the
  system cannot read from the specified device* — until something made the engine load the module
  behind it, and `read_memory` was never that something: 16 bytes, 4 KiB and 64 KiB at `.text`, a
  second identical call, the same read at the image base, and a read taken 25 seconds after the
  open all failed, on `securekernel.exe` (ARM64) and `ACPI.sys` (x64) alike, while
  `modules { refresh: true }`, `disassemble`, `xrefs_to` and `reachable_from_dispatch` all made the
  next read work. What they have in common is a module load, so `worker::load_an_image_targets_module`
  does one at the open. **Gated on the target kind** — `GetDebuggeeType` answers
  `DEBUG_CLASS_IMAGE_FILE` / `DEBUG_DUMP_IMAGE_FILE`, measured 3 / 1027 — because
  `modules { refresh: true }`, which is that `.reload` plus an enumeration, took 2,159 ms on the
  checked-in x64 kernel dump against 11 ms on the image. A fresh
  session's first memory call now answers `kernel32!.text`'s own bytes, checked against the file.
  **The item's second claim is withdrawn**: no walk reported a scan it had not taken. A cold
  `xrefs_to` is byte-for-byte a warm one on both images, and `driver_hazards` refuses at the PE
  header rather than scanning — so `xrefs_to`'s *ask this on a dump or a live target* caveat is
  gone from its description rather than reworded.

- **An A64 conditional-compare chain is a compare chain, and `ioctl_map` reads it** (`FOLLOWUPS.md`
  item 92). A64 has `ccmp`, so a compiler writes `code == A || code == B || code == C` as **one**
  branch fed by several compares; this walk read the instruction before the branch, filed the rest in
  `untracked`, and every other code in such a chain was lost. `ioctl::chained_compare` and `absorb`
  (`src/ioctl.rs`) are the fold: a flag write replaces the set of live compares and **a conditional
  compare continues it**, with the `nzcv` immediate deciding whether it does. `ccmpne …,#4` forces
  `ZF` **set** where the link before it matched, so a match at any link reaches the `b.eq` and every
  readable link is a case at its own site; `ccmpne …,#0` forces it **clear**, so an earlier match
  takes the `b.ne` *away* from the case and only this compare's own operand can be one. Reading the
  first shape onto the second publishes the arm the routine **rejects** -- `0x00000000`, which is
  what the Binary Ninja companion's map carries for this driver
  ([binja-windbg-mcp#14](https://github.com/glslang/binja-windbg-mcp/issues/14)) -- so each shape is
  pinned by its own test. Measured end to end against the debugger guest's own `rdyboost.sys`
  (`10.0.26100.1`, SHA-256 `D872CFF7…`, opened as an image target, dispatch `rdyboost+0xf6a0`,
  2026-10-03): **17 codes with two `untracked` sites before, 21 with none after**, the four gained
  being exactly `0x0056c008`, `0x00070000`, `0x000700a0` and `0x00224194`, with nothing lost. Both
  readings are from **named, clean** builds one change apart -- `0.21.0+gdaa11a3d` against
  `0.21.0+gc02152aa` -- which is a re-take: the first pair was measured across `0.20.0+g3b8d6fee`
  and a `-dirty` tree, and by the time this merged, `main` had moved seventeen commits and item 108
  had touched `ioctl_map`'s own `render`. The baseline is unchanged across that, so the four codes
  are this change's and not the release's. That is **not** the build the item was filed against -- its
  chains are at `rdyboost+0xef00` and `+0xf00c`, this build's at `+0xf708` and `+0xf800` -- and on
  this one the link whose register the live-target reading could not resolve *is* readable, so the
  fold recovered four codes where the item named three. **A kept reading is good for an equality and
  nothing else**: the forced flags are not the flags that compare would have left (`#4` leaves `C`
  clear on A64, which is borrow, so `b.lo` is taken where the comparison it stands in for would not
  have been), so a chained reading founds no table bound and crosses no edge, and a chain read by
  anything but an equality branch -- or split across a block boundary -- reports its site in
  `untracked` instead of its codes. That costs a real code on the `b.lo` shape and is the right way
  round. `ccmn`, and a `ccmp` conditioned on `eq`, are deliberately not read: the first compares
  against a negation no control code is written as, the second chains a conjunction in which two
  distinct codes cannot both hold. **And the fold needs a predecessor the walk read**: `ccmpne …,#4`
  defers to the comparison before it, so where that comparison is not one of the walk's readings --
  `cmp w2,#0` / `ccmpne w9,w10,#4` / `b.eq` -- the forced arm sends every code to the handler, and a
  case list naming only `w10`'s code with an empty `untracked` would read as the whole set. Such a
  link is dropped and its site becomes the loss, which is what this module answered for that shape
  before a chain could be read at all. **And a link whose own comparison could not be read marks the
  chain it continues** -- with `ZF` forced set the links that *were* read stay cases and the site is
  a loss beside them, and with it forced clear nothing survives but the site, where a predecessor had
  established the code. Those three arms came from enumerating the fold's six cases in one pass
  rather than patching the findings that named two of them, which is also how the third was found.
  **A dropped chain is recorded at the branch that consumes it**, since leaving the site on the
  outgoing edges made the answer depend on a later equality branch arriving at all. All three P1s
  were Codex's, on [#439](https://github.com/glslang/windbg-mcp/pull/439); CodeRabbit reviewed the
  same head and filed nothing. **And the chain is a fact the block keeps in its own right** -- the
  site of the conditional compare whose flags are live, cleared by an ordinary flag write and by a
  call as the readings are -- because the check above was written searching the readings that
  survive a chain, and the forced-clear blind arm leaves *only* a loss, so `cmp code,A` /
  `ccmpne w2,w3,#0` / `b.lo` was still a complete-looking map with an accepted code in it (Codex
  again, against its own round's fix). The boundary is pinned as well: an ordinary flag write after
  a chain ends it, and the loss it leaves is reported the way this walk has always reported one, so
  no `ja` over a lost code anywhere grows an `untracked` entry it did not have. Eleven rules, eleven
  tests, each mutation-verified against the rule it is for; the `rdyboost` figures above were
  re-measured after the last of them and are unchanged. **And a forced-clear link's predecessors
  decide whether its case exists at all**: one that matched the same code makes the case
  unreachable, so it is dropped (`cmp code,A` / `ccmpne code,A,#0` / `b.ne` rejects every value),
  and one whose code could not be read leaves that unknown, so the code is published with the
  unread site recorded beside it -- the marker the fold had dropped, which `note_loss` used to
  leave. **And a chain needs a predecessor on every path into its block**, not on one of them: `Facts::join`
  unions `pending` by design, so a carried-in reading is one edge's comparison and says nothing about
  the others -- `cmp code,A` on one and `cmp w2,#0` on another lets a `ZF`-forcing link admit every
  code on the second. The fold therefore asks for flags the block itself wrote, which costs a chain
  whose first link is in another block the codes it used to name and gives it the site instead.
  **And a case is dropped only where every path excludes it**: a join unions the readings, so this
  link's code appearing on one predecessor leaves it accepted along another, which costs a real code
  rather than inventing one. The guard beside that rule -- *"and there were readings at all"* -- was
  found unpinned by the matrix and now has its own test, vacuous truth over an empty set having been
  enough to drop a forced-clear link's only case. Nineteen tests, sixteen of them mutation-verified
  against the mutation they are for, the other three controls against a later round *fixing*
  something already right. **And the two kinds of loss are separated**, which is what three findings on one line
  were about: *a loss about the control code* and *a forced arm admitting every code* shared one
  slot, and a forced-clear link treats them oppositely -- it resolves the second, an earlier match
  then taking the branch away from the case, and resolves nothing about a code nobody could name. So
  `tst code,#1` / `ccmpne code,B,#0` / `b.eq`, which admits only an odd code, no longer publishes an
  even `B` as definitive, and neither does a chain through a `ccmn`. Each direction is pinned by its
  own mutation, and all **four** sites that write either slot were then enumerated rather than
  fixed one at a time, and two sharper readings followed: within one chain **any** earlier link
  matching a code excludes it (*every path* being a test for readings that arrived from other
  paths), and the site reported for a dropped chain is the link that made it incomplete rather than
  the comparison that was understood -- the first separation had corrected only the arm the finding named, leaving a
  forced-set link to drop an incoming loss and a readable link to erase a blind one's site, both of
  which published an invented case as definitive -- and the first draft of the one that keeps a dropped chain visible keyed on the
  terminator's *condition* alone, which a `ccmp` carries, so a block ending in one left no case
  and no site; the block-boundary test caught it.

- **A narrowed surface no longer reads argument prose pointing at tools it cannot call**
  (`FOLLOWUPS.md` item 52, in `DONE.md`). An argument's doc comment lands in a tool's
  **`inputSchema`**, which is model-visible on exactly the terms its description is -- counted
  inside `modelVisible`, with a column of its own in `tool_budget.json` -- and the invariant that
  keeps a cross-reference out of a description walked only the description. So a
  `--tools run_to_address` client read "typically a block from `reachable_from_dispatch`", a
  pointer to a tool it is refused, which is what item 41 exists to prevent on the one channel item
  41 did not look at. **Eleven sentence/tool pairs across seven tools were leaking**, where the
  item recorded one: four were pointers at what to call next and are now `TOOL_NOTES` entries,
  which ship only where every tool they name is served; two were already in `TOOL_NOTES` and the
  argument had a second copy; and five were `debug_batch` prose pointing out of the batch when its
  own step is the thing -- four calling a step "the `X` tool", one offering `go` for what a
  `resume` step does. `no_input_schema_names_a_tool_the_client_cannot_call` walks the served
  schema, reports every leak rather than the first, and reads `input_schema` rather than the source
  because the two are not the same set: `schemars` attaches a whole doc comment, rationale
  paragraphs and all, but attaches none of a `#[serde(flatten)]`'d type's -- every one of
  `StepAction`'s *variant* docs reaches a client and not a word of the enum's own. **There is no
  third notes table**, which is the decision this closes: `annotate` rewrites a description per
  surface and nothing rewrites a schema, so a cross-reference belongs in `TOOL_NOTES` rather than
  in a second mechanism built for the same job. **And no exemption either**, though two were
  tried: `debug_batch`'s step vocabulary is spelled with four of the tool table's own words and
  `set_breakpoint` declares the *value* `execute`, so the walk first exempted a name the served
  schema declares and then only the occurrences written as JSON values -- and review escaped both.
  What the mechanism bought was one description, `debug_batch`'s `steps`, and four names in it, so
  the prose gave them up and the schema kept them in each variant's `op` `const`, which is the
  channel a client validates against. The model-visible surface moves 116,707 -> **116,318** B and
  `debug_batch`, still the worst single tool, 10,842 -> **10,308** -- the step catalogue the
  variants already carried being 426 B of it.

### Changed

- **The IOCTL switch resolver matches what a compiler emits instead of refusing what it trips
  over** (`FOLLOWUPS.md` item 66, in `DONE.md`). `ioctl::follow_table` walked **backwards** from an
  indirect jump and refused when something stopped it, so every instruction nobody had anticipated
  was a hole that failed toward a *resolved* table and the rule list grew a review round at a time
  -- one fold and not two, no `call` in the chain, no second byte map, a pointer-width copy. The
  stages a switch is made of are matched **forwards** now, in one pass over the block
  (`ioctl::stages_in`): a register holds either nothing or a value one of the stages left there,
  the **decoder's write set** is what takes it out again, and `switch_at` asks one question at the
  jump -- does the register it reads hold an entry this watched being loaded. The refusals are gone
  rather than restated: an `xchg` into the register, a copy that narrows it, a helper call that
  returns over it and a second fold are none of them named, and all of them leave the jump reading
  a register the pass did not compute. **Behaviour is unchanged, which is the claim that needed the
  evidence**: the generated differential in `src/ioctl/tests/differential.rs`, run at **65,536
  seeds** -- 64x its committed sweep -- against both resolvers in one clone, reports **74,189 cases
  over 15,954 tables with no mismatches** on each, the same figures rather than two green runs.
  **And the three idioms turned out to be two questions**: whether a byte map stands in front of
  the load, and whether an image base is folded into each entry. Three of the four answers are the
  shapes the item named; the fourth is a dense switch over *absolute* entries, which MSVC emits in
  a 32-bit image and which three hand-written matchers would have met as a shape nobody had
  anticipated. `a_dense_switch_over_absolute_entries_is_followed` pins it, mutation-verified
  against the map lookup it needs, and nothing in the suite reached it before.

### Added

- **`xrefs_to` — which sites in an image call or branch to one address** (`FOLLOWUPS.md` item 109).
  The reverse of `reachable_from_dispatch`'s forward walk, and about an **internal** address rather
  than an import, which is the question you have when a symbol is absent, a PDB is public and
  typeless, or the interesting thing is a callback body rather than a named routine. It had been
  hand-rolled in Python twice before this, once per image it was needed for. Each site carries
  module+RVA, the transfer kind, the mnemonic and its section — a reference from a discardable
  section such as `INIT` is dead code once the driver has loaded, which an address alone cannot
  say. Calls, unconditional jumps and conditional branches are counted apart, and those three
  counts are exact where the list is capped, so *is it called at all* survives a target reached by
  four thousand branches.

  **Decoded, never pattern-matched.** The destination is a field on the decoded instruction, so a
  coincidental call-opcode byte inside an immediate or inside data is not a hit, and the `Flow`
  match is exhaustive so a variant added upstream is a compile error rather than a silently missed
  reference. The Python this replaces matched `E8`/`E9` displacements over raw bytes, which is sound
  enough to generate a lead and not sound enough to be a tool.

  **An empty list is evidence about the scan, not the target**, and the prose says so on every
  answer rather than when asked: an indirect transfer (`call rax`) carries no destination to
  compare, an address merely *stored* in a dispatch table or callback slot is never branched to,
  only the one image is read, and code that did not decode is reported. It shipped with a fifth
  clause — *ask it on a dump or a live target*, an image target answering nothing — which item 111
  below withdrew two days later: the scan was never the thing misreading such a target, and the
  read underneath it is fixed at the open.

  Verified as a round trip, because nothing else tests a search: the dump tier reads a direct call
  out of the disassembler first and requires that site back with its kind, module and RVA, with an
  address one byte inside an instruction as the control. Measured by hand on both samples first —
  391 sites for `nt!KeBugCheck2` on the ARM64 dump, 383 call and 8 jump.

  Built on the hazard scan's walk rather than beside it, which took an extraction first:
  `src/codewalk.rs` now owns the bounded section walk, the window boundaries that resume after the
  last *whole* instruction, the clamped overrunning section, the unreadable-window accounting and
  the two budgets. `driver_hazards` moved onto it unchanged and its own 16 tests still cover those
  behaviours — breaking the extracted hex-pair instruction length fails two of them, which is what
  says the behaviour moved rather than being copied. A second copy of that loop would have been a
  copy of the defects fourteen rounds of review on
  [#305](https://github.com/glslang/windbg-mcp/pull/305) and
  [#307](https://github.com/glslang/windbg-mcp/pull/307) took out of it.

  The model-visible tool surface went **116,520 B** across **75** tools, from 113,516 across 74
  — 2,930 B of it this tool and 74 B `reachable_from_dispatch`'s rewritten `module` argument;
  its ceiling moves 114,000 → 118,000, with the arithmetic and the reason the description is the
  larger half recorded above `MODEL_VISIBLE_CEILING`. The wire ceiling is untouched at 330,000.
  Item 111 below then took 146 B of this tool's description back off again, so the figures this
  release ships are **116,374 B** and 327,543 on the wire.

- **Live Secure Kernel control is available as an isolated MCP session.** Seven typed tools bind an
  exact disposable VBS VM and selected VTL1 VP, arm one to four guarded hardware breakpoints, wait
  for the owned vector-1 event, inspect stopped registers and memory, step with bounded decoded
  destinations, restore the baseline and continue. The worker owns the operator-supplied register
  and memory providers plus the exact-build `vmwp` adapter; ordinary debugger tools are refused on
  the session, and uncertain teardown retains the worker and target reservation for recovery.

- **The immutable minimum Windows/VBS boot inputs pass (`FOLLOWUPS.md` item
  110, K1.0).** Private flattened bases from the VBS and VBS-off sources each
  cold-boot three times through disposable differencing children with one VP,
  fixed 4 GiB RAM, Secure Boot off, no TPM, network, DVD, or Guest Service
  Interface. Paired saved-state reads distinguish them directly: the positive
  clone exposes VTL masks `3`, a readable long-mode VTL1 root, and a validated
  Secure Kernel module list containing `skci.dll`; the control exposes masks
  `1` and refuses VTL1. This also measures the common two-span physical memory
  map used by K1.2.
- **The fatal inbox-device initialization spike for an owned Windows/VBS boot
  passed for all six minimum devices (`FOLLOWUPS.md` item 110, K1.1).**
  `tools/vdev_initialization_probe.py` runs guest emulation, BIOS, RTC, IOAPIC,
  VMBus, and SynthStor in separate bounded children; guards the exact device
  and VID binaries; and asserts their recovered `IVirtualDevice` vtables,
  required and optional dependencies, minimum XML, repository reads, and
  service callbacks. Each independently returns `S_OK` from initialization and
  teardown. RTC needs no partition; the other five children each create and
  delete a fresh process-local direct-VID partition. VMBus still proves the
  ownership link by opening its endpoint after the optional handle broker
  returns `E_NOTIMPL`. The generated, build-bound contract is committed as
  `docs/secure-kernel/vdev-contract-26100.8457.json`. This rules out `vmwp`
  process identity, VMMS-managed repository state, and a second VID receive
  loop as requirements for all six independent initialization paths. That
  result opened the composition work recorded in the next entry.
- **The six-device composition and lifecycle subgate passes three times in one
  owner partition (`FOLLOWUPS.md` item 110, K1.2).**
  `tools/vdev_graph_probe.py` supplies the real `IVmbusServices`, `IVmIoApic`,
  and `IVmBios` interfaces between the inbox objects, initializes in dependency
  order, mirrors `vmwp`'s recovered `IID_IVirtualDeviceMemoryInfo` notification
  loop, tears down in reverse, verifies repository release after COM object
  destruction, and deletes the partition. It now also configures VSM and installs
  the managed one-VP Windows layout: `0xF8000000` bytes of low RAM, a 128 MiB
  PCI/MMIO hole, and 128 MiB of high RAM at `0x100000000`. Both VSM-capable
  memory blocks pass mapped-page readback and are destroyed during unwind. The
  probe now follows the recovered pre-power sequence: initialize; call slots 6
  through 8 as `StartReservingResources`, `FinishReservingResources`, and
  `FreeReservedResources`; then tear down. The final three live runs used fresh
  partitions `0x1A` through `0x1C`, and every resource call returned `S_OK`.
  None of the six devices implements the optional memory-info interface, so the
  RAM-complete phase is an asserted no-op. K1.2 is closed; firmware execution,
  storage I/O, and VP start remain open.
- **The owner-partition probe can redirect and restore VTL1 execution state
  while an exception message is pending (`FOLLOWUPS.md` item 110 arm 1).** The
  new `--pending-vtl1-state-write` mode receives its marked VTL1 CPL0 `#BP`,
  writes and reads back `RIP=0x10180`, completes with instruction advance
  cleared, and receives the next marked trap at exactly that address with the
  same stack. It then writes the original continuation `RIP=0x10009` while the
  second message is pending, again completes without advance, and requires the
  original loop's resume witness. The guarded live run passed on 2026-10-02.
  Exact-build Ghidra analysis explains the result:
  `VidExceptionInterceptReturnCallback` calls
  `VidInterceptAdvanceInstructionPointer` only when exchange-buffer byte
  `+0x148` is nonzero. An initialized Secure Kernel stop can therefore redirect
  to its published `DbgBreakPointWithStatus` address and restore the interrupted
  `RIP` without patching Secure Kernel text.

## [0.21.0] - 2026-10-02

### Added

- **The driver tools say when a dispatch table is a *framework's* rather than the driver's, which is
  the reading that was silently useless (`FOLLOWUPS.md` item 108 step 1).** The driver tools that read
  `_DRIVER_OBJECT->MajorFunction` expected its entries to be the driver's own routines, and the two
  handed one of those entries as an address — `ioctl_map` and `reachable_from_dispatch` — inherited
  the expectation; a
  **KMDF** driver's 28 entries are all `Wdf01000!FxDevice::Dispatch` or `FxDevice::DispatchWithLock`,
  so `driver_surface` reported a driver dispatching nothing of its own and `ioctl_map` started at one
  of those entries reported a routine accepting no control codes — both correct about the table and
  neither an answer to the question asked, the same failure as item 107. `src/framework.rs`
  recognises the case and `driver_surface`, `driver_hazards`, `ioctl_map` and
  `reachable_from_dispatch` each carry a `framework` field saying so — and each **renders** it as well, since `structuredContent` replaces the text block rather than accompanying it, so a qualification on one half reaches none of the callers served the other. `reachable_from_dispatch` had it on one side only until review round 2. **Two tells, because neither
  implies the other**: a `WdfVersionBind` import from `WdfLdr.sys`, which is a fact about the *image*
  and so answers with no debuggee, and every `MajorFunction` entry read being in the framework's
  image, which is a fact about the *driver object*. A client passing
  `WdfDriverInitNoDispatchOverride` keeps a table of its own — measured:
  `FxDriver::Initialize+0x1b8` is a `test cl,2` on the driver config's flags with a `jne` over the
  whole fill loop at `+0x200`, which writes `DRIVER_OBJECT+0x70` onwards with `cl` running `0`
  through `0x1B` and asks `FxDevice::_RequiresRemLock(cl, 0)` per **major function**, not per device.
  So the dispatch tell requires *every* entry, which also keeps a WDM filter forwarding one major
  function into a framework image from being reported as a framework driver. **And the bind tell is the import's name *and* its
  library, both.** Either alone is wrong in its own direction, which took a review round to get
  right: a library-only rule reports the framework as its own client, `Wdf01000.sys` importing
  `WdfRegisterLibrary` and `WdfLdrDiagnosticsValueByNameAsULONG` from `WdfLdr.sys` and neither bind
  routine — the one image a reader of this field is most likely to be pointing a tool at — while a
  name-only rule reports any image that imports something *called* `WdfVersionBind` from anywhere,
  which an untrusted driver can arrange and which is not the evidence `bind_import` says it carries.
  **And each tell licenses only its own sentence**: the note is assembled from the tells that fired,
  so the clause about what the `MajorFunction` entries hold is there only where the dispatch tell read
  them — on the import alone, which is every `driver_hazards` answer, the note says instead that it
  made no such claim and names `WdfDriverInitNoDispatchOverride` as why that matters. `driver_surface`'s IOCTL section now names the framework as the **third** reason a handler
  sits outside the driver's image, beside the kernel's stub and a filter; that sentence enumerated two
  and explained a KMDF table as one of them, which is the wrong sentence item 108 records this
  repository shipping. Measured through the dev build against real images on 2026-10-02:
  `driver_hazards` on `Vid.sys` answers `kmdf`/`bind_import`, `ioctl_map` at `Wdf01000+0x51c90`
  answers `kmdf`/`framework_image` beside `case_count: 0`, and `Wdf01000.sys` and `mountmgr.sys`
  answer with no framework at all. **The absence of the field is deliberately not a claim**: it is
  added when a tell fires and nothing is added when none does, so an image whose import names could
  not be read is a driver nothing said anything about rather than a WDM one. What this does **not**
  do is resolve the driver's own handler, and it does not guess at where that is: a client's
  control-code comparison may be in a callback the framework holds — whose layout moves with
  `Wdf01000.sys`'s own version line, independently of the OS build — or in a routine that was
  registered as nothing at all, a manual queue's consumer being pulled by the driver's own worker or
  timer. Which it is, is item 108's remaining step, and is why the field tells a reader where *not*
  to look. UMDF (`WUDFx02000.dll`, user mode) is recognised nowhere and the note says so. Two gaps
  stated rather than left implied: the `MajorFunction`-entry tell is **unit-tested and
  mutation-verified but has not been run against a live kernel**, `driver_surface` needing one —
  what corroborates it is that the module name it matches is the name a kernel target's own
  inventory gives, measured on the checked-in ARM64 kernel dump (`Wdf01000`, with an address inside
  it attributed to that module); and the census behind "most in-box Hyper-V drivers are KMDF" is
  **132 of 445** driver images on this host, 13 of 25 Hyper-V-ish ones, `vmswitch`, `winhv`,
  `winhvr`, `hvsocket` and `vmbkmcl` among those that are not — item 108's title claimed all of them
  and is corrected in its own entry.
- **Secure Kernel reads can now come from a *live* guest, through a transport the operator supplies —
  and the first `ReadFailure::Refused` ever raised by a real source (gates S5w and S5x, 2026-10-01).**
  `src/sk.rs`'s source seam said *"a future driver-backed live source joins here and changes nothing
  above it"* and had only ever been driven by capture files. `src/livesrc.rs` is that source, and what
  this repository gains is the **client** half of a line protocol spoken by a **child process**: it
  ships no transport, links nothing privileged and contains no unsafe FFI, because reading another
  partition's VTL1 live needs a kernel component this project will not distribute — the same standing
  decision as the live-kernel tier's KDNET wiring. `windbg-mcp --sk-live --transport "<command>"
  --image <path>` drives gate S1's whole decode through it. Measured against the running VBS lab
  guest (run of 2026-10-01): root `0x1201000`, a **complete** walk of **11,819 leaf mappings over
  4,229 distinct pages**,
  `securekernel.exe` identified at `0xFFFFF8024278A000` with 4 `KDBG` hits and three other PE headers
  rejected on `KernBase`, `KdDebuggerDataBlock` at base `+0x1335E0`, `SkLoadedModuleList` at base
  `+0x127770`, and **six VTL1 modules** (`securekernel.exe`, `skci.dll`, `symcryptk.dll`, `cng.sys`,
  `vmsvc.dll`, `vmsvcext.sys`) — over **12,375 reads and 50,688,000 bytes with nothing failed**.
  **The walk counts are a reading of a running guest and move between runs**: the same command on
  2026-10-02 reported 11,820 leaves over **4,318** distinct pages and 12,376 reads, with every
  landmark, the identified base and the module list byte-identical. That is the first consequence
  below, visible in the headline figures rather than only in the churn arm.
  A second transport drives `HvCallReadGpa` instead, at its real `max_read` of **16** — the width
  `RawSource::max_read` exists because of — and answers
  **`Refused { detail: "ReadIntercept(2)" }`**, so `ReadStats::refused` is above zero outside a
  fixture for the first time and the decode declines to claim the negative: *"this run identified
  nothing while 2 read(s) failed, so its negative has not been earned."* That is the one mistake the
  seam was shaped to prevent — a refusal collapsing into **success**, zeros handed back as bytes,
  would have produced the VBS-off control's answer from a VBS-on guest — now demonstrated rather
  than argued. **Collapsing it into a plain failure is a different and lesser mistake**, and this
  sentence said it was the same one until review on
  [#435](https://github.com/glslang/windbg-mcp/pull/435) read it against the message quoted two
  lines above it: a failed read is exactly what makes the decode withhold the negative, so what
  that loses is the *classification* naming the cause, not the verdict. **It is a command-line
  role and deliberately not a fifth MCP tool**, because the two consequences a live source has for a
  capture *session* are now measured instead of assumed: one of `securekernel.exe`'s 373 pages changed
  in 20 seconds — 2 bytes, in **`.data`** — while 1,200 sampled non-image pages and every landmark
  stayed byte-identical. So decode-on-open is unsound in principle for a live source and
  `sk_read_memory`'s bytes are not guaranteed between two reads, while the churn is small enough to
  say what it would cost. Fifteen unit tests pin the framing against in-memory pipes, including a
  provider banner being skipped to a sentinel, a misspelled `SHAPE` key being refused rather than read
  as a guest with no page-table root, and a transport announcing more bytes than were asked for.
  **The shipped plugin skill now covers both routes**, which it had said nothing about in either
  direction: `skills/windbg-debugging/secure-kernel.md` is a new playbook for the four capture tools
  — what the host needs, the three ways of naming a capture, why `image` is required, that a capture
  session refuses the tools that answer about a debugger target while `end_session` and `interrupt`
  go on working, and that a VBS-off guest's capture opening with no VTL1 is the answer rather than a
  failure, and that the public PDB's missing type records mean structures
  are hand-decoded — and it states the live route as what it is: **the operator supplies the
  transport**, this repository ships none, `--sk-live` refuses to start without `--transport`, and
  there is no MCP call for it, so a request to debug a *running* Secure Kernel is answered with a
  checkpoint or handed back. `SKILL.md` indexes it in both tables and carries the limit as a
  cross-cutting one. **And the five places that enumerate what this project debugs now name this as
  one of them**, which none of them did — not since the four tools shipped: the skill's
  `description` (the only part of it in context before it is loaded, so the playbook was
  unreachable for the request it exists for), the skill's own opening sentence, `README.md`'s, and
  the `description` plus `keywords` of both `.claude-plugin/plugin.json` and
  `.claude-plugin/marketplace.json`. `setup.md`'s elevation matrix gains the row — no elevation, but the SDK
  provider and read access to the checkpoint, and naming a `vm` rather than a path asks Hyper-V on
  that host.

- **Retracted: `SdkWriteVirtualMemory` does not segfault on VTL1, and the fault blamed on it was an
  8-byte struct overrun in the bench's own Python binding (gate S5u, 2026-10-01).** This project has
  carried the claim since gate S5r that *"the virtual read path handles the Secure Kernel context and
  the virtual write path does not"*. Both halves are wrong. Four arms — {VTL0 NT kernel, VTL1 Secure
  Kernel} × {PE header page, executable `.text` page} — each **mutate** a byte and read it back
  through the physical route at a GPA walked from Secure Kernel's own `CR3`, validated against the
  virtual read first and restored through that route in a `finally`; all four land, three runs, 12 of
  12. The VTL0 arms are the control the original lacked, and the VTL1 `.text` arm is the patched
  gate's own page class. A null or stale partition handle — the other candidate — returns `False`
  cleanly in both directions with no fault. The access violation that *did* end those runs comes from
  `hvlib.py`, whose `CfgParameters` declares **12 fields and 48 bytes** where the SDK header's
  `VM_OPERATIONS_CONFIG` has **17 and 56**: every `SdkGetDefaultConfig` through that binding writes
  **8 bytes past a Python allocation**, and the process dies wherever the garbage collector next walks
  it, which `python -X faulthandler` reports as `Garbage-collecting` at a different place in every
  script. Three things recorded with it: **a `0xC0000005` exit from any of these probes says nothing
  about what the probe was doing**, which is how the claim arose; *"every run ends in an hvlib unload
  segfault"* is false in both directions; and five flags, `VSMScan` among them, have never been
  settable from this bench. **Gate S5t is unaffected** — it patched physically and verified by
  read-back — and what changes is only the reason recorded for that choice.

- **The Hyper-V device model activates outside `vmwp.exe`: 20 of its 24 COM classes, for an ordinary
  user (gate S5v, 2026-10-01).** Step 8's costing of a VID/VSM rig rested on an activation probe
  recorded as unrun — *"registered rather than shown to activate. No call was made"* — and
  `tools/devmodel_activation_probe.py` makes the call. The registry census reproduces exactly: 24
  CLSIDs backed by the seven `vm*` DLLs, all `ThreadingModel=Free`.
  `CoCreateInstance(CLSCTX_INPROC_SERVER, IID_IUnknown)` from an ordinary elevated process, one child
  process per CLSID so a faulting device model costs one result rather than 23: **20 `S_OK`, 4
  `CLASS_E_CLASSNOTAVAILABLE`, no faults**, with `msxml3` XMLHTTP activating as the positive control
  and an unregistered CLSID giving `REGDB_E_CLASSNOTREG` as the negative. The 4 refusals are a
  registration artefact rather than a policy: their backing DLL loads into the process before
  refusing, and their GUID bytes appear in **none** of the 45 `vm*.dll`s in System32. Each object
  refcounts `AddRef`→2, `Release`→1, `Release`→0 and answers `E_NOINTERFACE` with a nulled
  out-pointer for an IID nothing implements, so it is live rather than merely constructed; the
  out-pointer is poisoned with `0xAA` first, so writing nothing cannot read as writing null. **And it
  is not admin-gated** — `BiosVdev` activates under a restricted token and again at genuine **medium**
  integrity with no `Administrators` membership — so *process context can decide it* is answered **no**
  for construction. It removes the next obstacle and does not establish tier B: these objects
  implement private interfaces whose IIDs this record has never read.

- **The published IUM-debugging capability is now reproduced in full except single-stepping: a
  breakpoint we planted fired inside a trustlet, and its registers read and wrote (gate S5t,
  2026-10-01).** Gate S5r had replicated only the *access*, and its own record said so — the
  `EXCEPTION_BREAKPOINT` it caught was the break Windows **injects** on attach, so breakpoints at a
  chosen address, register read and register write were all unexercised. All three now run. The gate
  is the one S5r located, `securekernel.exe+0x1434E`, patched **in memory** by guest-physical write
  (`SdkWritePhysicalMemory` at GPA `0xCE534E`, derived per run by walking Secure Kernel's own page
  tables) and restored, each write verified by read-back; the on-disk image is never touched.
  Against `LsaIso.exe` pid 924 on the VBS guest: `ReadProcessMemory` walked the **trustlet's own** PE
  export directory to resolve `ntdll!DbgUiRemoteBreakin` = `0x7FF888215B90`; `VirtualProtectEx`
  reported old protection `0x20` and `WriteProcessMemory` planted one `0xCC` there, **read back
  `0xCC`** — the permission nothing had tested, and it is granted; `GetThreadContext` read `RIP` =
  `0x7FF888203AB1`; `SetThreadContext` redirected it to the planted address; and the next event was
  `EXCEPTION_BREAKPOINT` `0x80000003` at **`0x7FF888215B90`**, *our* address, with `RIP` =
  `0x7FF888215B91` — exactly address + 1. Byte and `RIP` restored and verified, detached, trustlet
  alive, guest uptime monotonic at 1d 00:21 with `Secure System` still running. **A-B-A**:
  `ERROR_ACCESS_DENIED (5)` with the gate closed, before and after.
  **A second arm the same day added single-stepping, so every clause of the published capability is
  reproduced**: `EFLAGS.TF` armed `0x246`→`0x346`, two `EXCEPTION_SINGLE_STEP` (`0x80000004`) events
  at `0x7FF888215B94` then `0x7FF888215B9D` — advances of 4 and 9 bytes, matching `sub rsp,0x28` and
  `mov rax,gs:[0x60]` as read from this host's `ntdll` — with `TF` self-cleared by each trap, and
  `EFLAGS` moving `0x246`→`0x206` across the first step, which a replayed breakpoint would not do.
  **That arm also crashed the trustlet, and the cause is this harness rather than the technique**: it
  restored `RIP` without `RSP` after stepping that `sub rsp,0x28`, so `DbgBreakPoint`'s `ret` popped a
  value that was never a return address, and WER logged `IUMTrustletCrash` for `lsaiso.exe`
  10.0.26100.9444 twice. The guest survived — uptime monotonic at 1d 00:47, `lsass` alive, `Secure
  System` running, nothing in the System log — but `LsaIso` did not restart, so **the single-step arm
  had no post-restore control. **Re-run on a rebooted guest the same day with all three defects fixed,
  and it is clean**: `LsaIso` pid 908, every address re-derived (Secure Kernel rebased to
  `0xFFFFF8024278A000`, the target to `0x7FF8EC595B90`, while `InfoHvddGetCr3Securekernel` read
  `0x1201000` for a third boot — which is why that value is not an identity), `VirtualProtectEx`
  reading the correct original `0x20` where the leak had shown `0x40`, `RESTORE_FULL_CONTEXT` verified
  by read-back, protection restored, the trustlet **alive at 1, 3 and 6 seconds**, Arm C refusing with
  `ERROR_ACCESS_DENIED (5)` on that **same pid**, and **zero `IUMTrustletCrash` events since that
  boot** — counted from `LastBootUpTime`, because a 20-minute window spans the reboot and returns the
  previous run's crashes, which is how that check first read as a failure. Three harness defects are
  fixed rather than noted: the full 1,232-byte `CONTEXT` is now snapshotted and restored wholesale with
  a read-back check, the original page protection is restored (the first run left the page RWX, which
  the second saw as `OLD=0x40` where the first read `0x20`), and liveness is sampled at 1, 3 and 6
  seconds instead of 400 ms — that early sample reported `TRUSTLET_ALIVE=True` moments before the
  crash surfaced. Still VTL1 **user** mode only, one build, one trustlet; nothing here is a property
  of VBS. Two incidental corrections: the probe's
  `TARGET_PARTITION_ID = 3` was stale because partition ids turn over (the VBS guest is now 5, the
  twin 8), so it selects on `InfoSecureKernelBase` being non-zero and prints the rejected partition
  as the control; and the `ERR=203` values in the probe output follow *successful* calls, Windows not
  clearing last-error on success.

- **Item 103's capture route is verified end to end, and the item stays open on attempts not yet
  made.** H5b's shipped half — Secure Kernel modules, symbols and memory off a Hyper-V checkpoint with
  no driver and no debuggee, DbgEng appearing only as gate S2's image-symbol server and never in the
  path of a read — was **re-verified on 2026-10-01 through the registered stdio server**, against three
  checkpoints rather than against the entry's own figures. Positive arm, the pinned VBS+HVCI
  checkpoint: VTL1 root `0x107593000` read *from the capture*, self-map at [309], a complete walk over
  4,545 distinct pages from 179 table reads, 1 of 7 PE headers matching this host's `securekernel.exe`
  10.0.26100.9457, `KdDebuggerDataBlock` at `0xfffff8070eedc5e0` `Size` `0x3a0`, `SkLoadedModuleList`
  with 6 entries, the structural cross-check agreeing with the block, and 18,253 reads with 0 failed
  and 0 refused — with `sk_modules` naming all six VTL1 modules and `sk_read_memory` returning the `MZ`
  header at the SK base. Control arm, the VBS-off twin: partition VTLs `0x1`,
  `ForceActiveVirtualTrustLevel(vp0, vtl1)` refused as `0xC0370509`, and the session reporting the
  limitation instead of answering, so the positive arm is **discriminated**. Symbols, on a third
  checkpoint: the PDB loads against the image and both landmarks agree with the decode in both
  directions, type probes still 0 of 4 as gate S2 measured. Green the same day: 1,101 unit tests, 130
  `mcp_smoke` tests, clippy clean under `-D warnings`, `sksym` 7/7 with the engine, and the capture
  tier against a real `.vmrs` in 16.67s. **That third checkpoint also sharpened S0's warning**: it
  carries the same `CR3` *value* as S0's first capture with a different self-map index (434 against
  388) and a different SK GPA, so the root is not merely un-stable across reboots but not even
  distinguishing — reading it from the capture every time is the contract, not a precaution.
  **The item does not close**, because part of what it is for is closing the remaining gaps and several
  attempts its own plan names have not been made: a `sk::RawSource` implementation against the
  operator-supplied live transport (`src/sk.rs:312` — the seam is built, `savedstate` implements it for
  a capture, and the trait's doc already says a driver-backed live source "joins here and changes
  nothing above it", so this is an unwritten implementation rather than an open question, and
  `ReadFailure::Refused` has therefore never been produced by a real source); the three operations the
  IUM write-up claims *on top of* attach — breakpoints, single-stepping and register access — where
  S5r **did** replicate the access itself, and from the Hyper-V root with no nesting against the
  published route's three hypervisor levels, but exercised none of `WriteProcessMemory`,
  `GetThreadContext` or `SetThreadContext` against the trustlet, so whether VTL0 may *write* a
  trustlet's memory is still untested and is a different permission from being admitted to attach;
  and an `SdkWriteVirtualMemory` segfault on a VTL1 virtual address that was
  recorded as unexplained and is **retracted above**: the call writes VTL1 fine. EXDI (E3, E4) stays out on **E2's
  lab condition** — a custom EXDI setup rests on a completely different type of lab, a host whose
  hypervisor slot is free, and *"the answer is a second host rather than a redesign"* — with H5a's
  two-part reversal condition unchanged and the measurement of the stub's three inputs (H3, H4, E1)
  explicitly **not** being it. **Two wrong drafts of that status are recorded in the entry rather than
  deleted**, because each inverted something already decided: the first closed the item on the strength
  of the four tools and filed the remainder as a new follow-up item; the second recast the
  operator-supplied transport as a refusal, when the entry's own first constraint had already settled
  it in favour — this repo distributes no driver, the operator supplies the transport, and the rest is
  drivable from it. One wart is recorded rather than fixed: `sk_symbol` resolves a *qualified* name a
  lenient engine accepts and renders it `securekernel!securekernel!…`, the right address with a doubled
  display string, which is item 107's family and whose remedy turns on what a *foreign* qualifier is
  owed.
- **Item 103's route is reassessed against the 2026-10-01 probe results, and the part the probe
  does *not* reach is now item 110.** The probe paragraph was headed *"a separate goal… rather than
  about Microsoft's Secure Kernel"*, which the `--securekernel-breakpoint` follow-on makes wrong: it
  is off the **inspection** route, not off Secure Kernel. Four claims are narrowed to what was
  measured. Step 7's *"the route is closed from user mode"* holds **against a partition another
  process owns** — the gate it located (`PsGetCurrentProcess()` against `[partition+0x3780]`) is
  satisfied by construction for whoever called `VidCreatePartition`, so on an owned partition the
  whole receive path runs from user mode with no driver. Step 8's costing **splits**: the VID/VSM
  half is built and passed at tier A, and only the guest OS and device model are unpaid. Route step
  1 no longer bears on whether a receive loop can be owned, only on chaining against a **managed**
  VM. And route step 3's *"which the observation half of E3 would rest on"* was simply wrong — H3
  reads VTL1 registers by hypercall keyed on a partition **id** and H4 reads VTL1 memory by direct
  mapping, so neither takes a VID handle and observation does not rest on it; the arm is about the
  control half. E3 then E4 was left standing here as *item 103's* critical path, with all three of
  that stub's inputs measured; the entry above corrects that half — it is a critical path for a stub
  **this bench cannot host**, E2's lab condition being the blocker, and measuring the inputs is not
  what would reopen it. **Item 110**
  carries the other terminal result — a stop inside an
  *initialized* Secure Kernel — filed as a decision rather than a schedule, with the cheap arms
  first (a VTL1 state write with a message pending; a one-shot non-resumable observation on a
  disposable guest) and the owned-boot programme behind the one falsification that decides whether
  it exists. **That falsification's own evidence line is corrected 2026-10-01**: it read *"the device
  classes **activate** out of process, which proves a registered class factory"*, which states a
  measurement that was never taken — the step-8 costing says *"Nothing here activated anything"* and
  records the activation probe as unrun, *"registered rather than shown to activate. No call was
  made."* What is measured is registration only: seven device DLLs exporting `DllGetClassObject`,
  `DllCanUnloadNow`, `DllRegisterServer`, `DllUnregisterServer` and nothing else, backing **24** in-proc
  CLSIDs on this host. The private plan had it right as a conditional — activation returning `S_OK` for
  `IID_IUnknown` *would* prove a class factory and nothing about `IVirtualDevice::Initialize` outside
  `vmwp`/VMMS — and flattening that conditional into a result is the defect. The arm is now two steps,
  the first being to actually `CoCreateInstance` one of the 24 and record the `HRESULT`.
- **The VTL1 kernel-mode control plan now has a build-locked owner-partition probe.**
  [`tools/vtl1_control_probe.c`](tools/vtl1_control_probe.c) creates only its own one-VP VID
  partition, enables partition and VP VTL1, enters it with a VTL1-targeted fixed interrupt, and
  holds on the selected `int3` until the exact marked exception message is completed. It includes
  a complete unwind path, refuses mismatched inbox VID builds and unexpected messages, and has an
  offline self-test for every private layout and the long-mode guest image. The high-integrity
  live run stopped at the marked VTL1 vector-3 instruction and verified the execution witness. It
  held the intercept for 266 ms, completed it, stopped the VP, deleted the disposable partition,
  and exited zero. The required memory pairing is now explicit: a VSM-capable VA memory block and
  a GPA range that applies default VTL protections. The `/W4 /WX` build and self-test also pass.
  The runbook and evidence are in
  [`docs/secure-kernel/vtl1-control-probe.md`](docs/secure-kernel/vtl1-control-probe.md).
  The probe now also has a guarded `--securekernel-breakpoint` mode. It maps the matching shipping
  `securekernel.exe` at its preferred VA, calls `DbgBreakPointWithStatus` from a VTL1 CPL0 interrupt
  trampoline, validates the pending stop's VTL, CPL and `RIP`, and re-enters the VID dispatch loop
  after completion. The live run held the image-backed stop for 250 ms, retired the real
  `int3; ret`, observed the handler's post-return witness, and deleted the owned partition. This is
  an image-backed execution proof; it does not claim a normally initialized Windows/VBS runtime.
- **Item 103 carries an ordered route to the actual goal, and two of today's claims are narrowed to
  what was measured.** The route, in `FOLLOWUPS.md` item 103 so it lives in **one** place: DbgEng
  inspecting `securekernel` is what `docs/secure-kernel/exdi-stub-plan.md` owns, and **all three of
  that stub's inputs are already measured** — VTL1 **registers** by H3, VTL1 **memory** by H4 plus
  the direct-mapping oracle that read the same ranges the hypercall withheld (with SK's **PML4**
  identified from the VTL1 `CR3`), and **kernel awareness** by E1. So the critical path is **E3 then
  E4**, E2 being unrunnable on this bench, and **steps 6–9 plus everything measured today are a
  different axis** — control rather than inspection, which an EXDI stub wants for breakpoints and
  not for reading. **Two corrections from review.** The all-zero VTL1 entry context was called a
  safety measure and is **not** one: on a partition whose ordering gate passes, the call may enable
  the VTL and start it at the context given, so an invalid one is a fault or a reset — it was
  harmless here only because the state gate refused first, which is a property of those partitions.
  And *"the VSM capability bit is fixed at creation"* was an inference, not a measurement: the one
  candidate review named has since been read — `VsmmVsmSetPartitionConfig` writes
  `[partition+0x30f0]`, `[partition+0x30f4]` and the per-VTL info, and **does not touch
  `[partition+0x10]`**, incidentally writing VID's enabled-VTL bookkeeping with no hypercall at all
  — but **where that bit is written is still untraced**, a name-filtered scan finding nothing being
  the same weak instrument that earlier read as *"no VID handle"*. Until
  `tools/vid_field_census.py` runs against it, "VTL cannot be retrofitted" is an inference and the
  claim that step 8 is *required* rests on it.
- **The hypervisor's gate on a VTL1 entry context is VTL *state*, not the context and not policy —
  so running our own code in VTL1 kernel mode is not blocked where it was assumed to be.** A VBS
  enclave is VTL1 *user* mode; a partition whose VTL1 we enable with an entry context of our
  choosing would put our code at VTL1 kernel privilege instead. **VID imposes nothing on that
  context**: `VidVsmEnableVpVtl` sends IOCTL **`0x221214`**, `METHOD_BUFFERED`, `0xE8` bytes
  (`{ULONG VpIndex; UCHAR TargetVtl; pad; UCHAR Context[0xE0]}` — 224 bytes, the size shape of
  `HV_INITIAL_VP_CONTEXT`), and `Vid.sys`'s handler, decompiled, checks **only the buffer length**
  before handing the caller's context straight to `WinHvEnableVpVtl`. So the probe driver called
  that wrapper **directly**, needing no partition of its own, with VP 0, target VTL 1 and an
  **all-zero context** — chosen for **discrimination, not safety**: a later round established that
  on a partition whose ordering gate passes the context may be *used*, so zero is a fault or a reset
  there rather than a refusal, and it was harmless here only because the state gate refused first.
  Both partitions were probed and **identified themselves by their own VTL state**:
  `STATUS_HV_VTL_ALREADY_ENABLED` (`0xC0350086`) for the VBS guest and
  `STATUS_HV_INVALID_VTL_STATE` (`0xC0350051`) for the one with `MaximumVtl=0`. **Neither refusal
  names the context** — no `INVALID_PARAMETER`, no `ACCESS_DENIED`, no measurement or policy — the
  hypervisor checks VTL state and returns before examining the 224 bytes. **Non-destructive**: both
  guests ran monotonically through a 60 s uptime watch. Partition ids had **moved** since H3 read
  `0x2`/`0x3`, so they were enumerated rather than recalled. **Still open**: whether the context is
  validated at all, since no run has got past the state check to present one — and reaching it may
  not need step 8's rig, because `WinHvEnablePartitionVtl` has no user-mode export but the driver
  can call it directly, and H3 already established the parent relationship suffices for the
  hypervisor to hand over a child's VTL1 registers. **Tested, and it cannot**:
  `WinHvEnablePartitionVtl` on the non-VBS guest returns `STATUS_HV_INVALID_PARAMETER`
  (`0xC0350005`) **invariantly** across `flags` of 0–7, `0x100`, `0x101` and both VTL 1 and 2, while
  the **same call on the VBS guest's partition answers differently** (`INVALID_VTL_STATE`) — a
  discriminating control, so the parameters reach the hypervisor and the refusal is about *that
  partition*. It mirrors `Vid.sys`'s own check, which refuses `STATUS_NOT_SUPPORTED` unless
  `[partition+0x10]` carries `0x10`. **Calling that bit "fixed at creation" was an inference and is
  withdrawn** — see the entry above: `VsmmVsmSetPartitionConfig` has since been read and does not
  write it, but where it *is* written remains untraced, so "VTL cannot be retrofitted" is not
  measured. What is: these two partitions cannot have partition VTL enabled by this call, and the
  VBS guest has no usable window because both levels are already enabled. **This prices the route rather than blocking it**: our
  own code at VTL1 kernel privilege needs a partition created VSM-capable, its partition VTL
  enabled, then the VP enabled with our context — **step 8's tier A plus configuration, and
  emphatically not tier B or C.** The 19-module, ~10 MB device-and-firmware cliff is the price of
  booting *Windows* in the partition; running our own code there needs no guest OS, no firmware and
  no vTPM. A much smaller project than "write a VMM", producing the one thing the enclave rig cannot
  give at any price. Every arm was refused before it could act and both guests ran monotonically
  throughout.
- **Item 103's consume loop runs, eats the partition owner's messages, and resets the guest — so
  step 8 is now the route on measurement rather than inference.** Two mechanical facts first:
  `0x221107` is the **only `METHOD_NEITHER`** code of the four in use, so its input must be
  allocated in the *attached* process's user space — a kernel buffer draws
  `STATUS_ACCESS_VIOLATION` and consumes nothing — and its `Flags` must be **`4`**, every other
  value of `0,1,2,3,4,7,0x10,0x100` returning `STATUS_INVALID_PARAMETER`. Both were found by a
  `SkipArm` probe mode that maps and completes **without arming**, which left the guest's uptime
  unchanged across the whole sweep: arming is what kills a guest, so separating the probe from it
  made the sweep free. Armed and consuming, the loop then works end to end — map `SUCCESS`,
  register `SUCCESS`, **64 messages consumed, every completion `SUCCESS`**, unregister `SUCCESS`.
  **But every message was type `0x01000010`** — exactly what the slot already held *before*
  anything was armed, and **not** the `0x80010003` of an exception intercept — so those were the
  **owner's** messages, 64 of `vmwp`'s, acknowledged by us, and **the guest reset inside ten
  seconds**. That closes the chain by measurement at every link: the gate admits one process per
  partition, on a Hyper-V VM that is `vmwp`, satisfying it means *being* `vmwp` and sharing its
  client state and slot, consuming from that slot takes the owner's traffic, and the guest does not
  survive it. **A usable receive loop therefore needs a partition with one client**, which is step
  8's own-from-creation rig — the justification its costing could not supply. **Not established**:
  that our own intercept was ever delivered (no `0x80010003` seen, the slot saturated at 64 messages
  with zero empty polls), and the reset is now **over-determined** between arming and stealing
  rather than pinned, because on this partition the second is the only way to attempt the first.
  Incidentally, the VP sweep gives the guest exactly **two** VPs (`vp` 2–3 refuse), agreeing with the
  loop question's counter result, and VP 1's slot carries a different type (`0x01000004`).
- **Item 103 step 7's `VidMessageSlot*` half: the map runs through the gate and the guest survives;
  the completion is not runnable on a live VM.** Decoded first, and the decode decided how much to
  run: `VidMessageSlotMap` is IOCTL **`0x221108`** (in 4 B `{u32 Vp}`, out 8 B — a VA **in the
  calling process**), `VidMessageSlotHandleAndGetNext` is **`0x221107`** (in 8 B `{u32 Vp; u32
  Flags}`, out 0), and the message is read from the mapped VA rather than returned. **Only the map
  was run.** The second call is the *completion* — its name is literal, and it is how `Vid.sys`
  reaches `WinHvCompleteIntercept`, which it imports from `winhvr.sys` — and **`vmwp` is already
  the consumer on these VPs**, so a second completer races it on a VM somebody is using. That needs
  a partition with one client, which makes it **a concrete reason for step 8's rig** rather than the
  general one its costing could not settle. The map **succeeded on exactly the handle whose
  `[partition+0x3780]` matched** and on no other — a **third** independent confirmation of the gate,
  after `VidGetHvPartitionId` and the register — returning slot VA `0x2059A811000`, whose first 64
  bytes parse as an `HV_MESSAGE_HEADER` with `MessageType` `0x01000010` and `PayloadSize` `0x30`;
  **not a type this record has named**, and left unread. **The guest survived**, and the watch was
  built to notice if it had not: uptime sampled every 10 s for a minute, monotonic throughout,
  because the previous arm's liveness probe answered cheerfully seconds before the guest went.
  **Mapping does not destabilise the guest — the arming did.** One cost: the map is one-way, there
  being no `VidMessageSlotUnmap`, so a slot mapped while attached stays mapped in `vmwp`.
- **Item 103 step 7's route WORKS from kernel mode, and using it hard-reset both lab guests.** Two
  results, and the second is not a footnote. `h3probe` gained `IOCTL_H3_VIDREG`, which attaches to
  the owning process with `KeStackAttachProcess` — the gate reads `PsGetCurrentProcess()`, so that
  is precisely what it wants — and, before issuing anything, resolves the handle to its file
  object and **reads `[partition+0x3780]` back: it holds the attached `EPROCESS` on both workers**,
  confirming the decompiled gate by direct measurement. The same control code `0x221148`, the same
  16-byte input, the same handle value that returned `ACCESS_DENIED` from user mode, then returns
  **`STATUS_SUCCESS`** with a registration handle, and the unregister succeeds. **The only
  difference between the refused and accepted calls is which process
  `PsGetCurrentProcess()` returns** — as controlled as a pair gets. So duplication gets the handle
  and only kernel mode can be the process the gate wants. **And each arm hard-reset the guest it
  touched** — `Kernel-Power` 41, **no** guest bug-check record, so a partition reset rather than a
  crash from inside — seconds after that arm's own health check had reported the guest responsive.
  Candidate mechanism, offered as that: the registration arms vector 3 with no message slot mapped
  or drained, and the **variable** delay (~1–2 s on one guest, ~20–30 s on the other) is what
  waiting for the next `#BP` looks like. **The rule this changes**: pairing an install with its
  removal is necessary and **not sufficient**, because the arming does the damage — map and drain
  the slot first or expect to lose the guest. Also: a post-arm liveness probe measures nothing on
  this path. Host untouched, both guests back up, `LsaIso` alive on the VBS one.
- **Item 103 step 7's deciding arm is run, and the route is closed from *user mode*: duplication
  is possible and insufficient.** (**It is open from kernel mode** — see the entry above, which
  passes the gate by attaching to the owner.) The named next arm — invoke the receiver through a duplicated handle
  rather than infer from a neighbouring call — was invoked on **both** workers, with the IOCTL
  issued directly rather than through `VidRegisterExceptionHandler`, because the wrapper runs its
  `NTSTATUS` through `RtlNtStatusToDosError` and that would collapse
  `STATUS_VID_DUPLICATE_HANDLER` — the one result meaning the handle *reached* the receiver. Three
  handles per worker return `STATUS_NOT_IMPLEMENTED` (the shared file object is not a partition) and
  the fourth **`STATUS_ACCESS_DENIED`**, against `STATUS_OBJECT_TYPE_MISMATCH` for a non-VID
  control — the same 3-and-1 split as `VidGetHvPartitionId`, on the same two file objects, in each
  worker independently. **Nothing was mutated**: the 8-byte output was poisoned and survived every
  arm, so no registration handed back a handle, no slot was claimed, and the rollback had nothing to
  release — a stronger statement than a rollback that ran. **And why it refuses is read out of the
  driver, not inferred**: a draft recorded it as an unresolvable limit, which it was only
  dynamically — from outside, the driver's ownership check and the driver wanting an access right
  predict the same result, because the security descriptor refuses a wider duplicate. Decompiled
  (Ghidra headless, cached PDB), `VidIoControlPreProcess` compares **`PsGetCurrentProcess()`
  against the owning process at `[partition+0x3780]`** and returns `ACCESS_DENIED` **before any
  dispatch**, exempting only control codes `0x2210ef` and `0x2211e3` — both new to this record, and
  the only two a non-owner may call. The driver's own ETW name for the check is
  **`VidIoControlPartitionIsAllowed`**. So it is a process-identity gate: **no handle could have
  passed it**, the escalation experiment was aimed at the wrong thing, and the receiver
  `VidHandlerpExceptionRegisterEntry` has **no access check at all** — its only refusal is
  `STATUS_VID_DUPLICATE_HANDLER`. It is also the check that consumes what S5o found
  `VidPartitionAttach` writing. **LiveCloudKd's driver stops being a guess**: kernel code can make
  `PsGetCurrentProcess()` match and handle manipulation never can, though its source is still
  unread. Both guests responsive across both arms, no bug check.
- **Item 103 step 7 is attempted: the handle is takeable, and the first read through it is
  refused.** S5n declined handle duplication because `vmwp.exe` runs protected; measured against
  positive controls (`csrss` 0x61, `lsass` 0x41, `MsMpEng` 0x31) with a poisoned output buffer,
  **`vmwp.exe` reads 0x00 — not protected** — and `PROCESS_ALL_ACCESS` succeeds from an elevated
  admin, so that ground is not there. Each worker holds **four** handles to the VID device and
  **all four duplicate out** with an ordinary `DuplicateHandle`; the refusals resolve by
  object-type index to `EtwRegistration` and `PcwObject` **in both workers** (120+13 and 121+13),
  with **no `File` object among them**, which is what makes four exhaustive rather than a floor.
  **Inheritance of a VID handle a worker still holds is excluded** on object identity: the
  children's tables, compared by object pointer, hold none of the workers' four current VID objects.
  **Not excluded** — and two drafts claimed otherwise — is one inherited and since closed in the
  parent, which a snapshot cannot see; the children's own single `File` object is unidentified
  (duplication refused three ways, sole holder, module list unavailable), so that case is
  unfalsifiable with these instruments and closing it needs handle lifetimes across a child
  creation — two weaker arguments for this (a bare count, then the
  parents' current `OBJ_INHERIT` flags) were both insufficient, the second because a flag cleared
  after child creation leaves the child's copy invisible in the parent. The same comparison shows
  the four VID handles are **two** file objects, three sharing one and one separate, mapping
  exactly onto the `INVALID_FUNCTION`/`ACCESS_DENIED` split. **And an instrument fault of our own
  is fixed rather than recorded**: an earlier reading of 53 handles for each `vmmem` was a stale
  uninitialised buffer — the call returns `STATUS_SUCCESS` and writes nothing — where the truth is
  zero, corroborated by a perf-counter `HandleCount` of 0. Poisoning the buffer is what found it,
  for the third time in this work.
  `VidGetHvPartitionId` through all **eight** then returns `ERROR_INVALID_FUNCTION` on six and
  **`ERROR_ACCESS_DENIED`** on two — the same 3-and-1 split in each worker independently — against
  `ERROR_INVALID_HANDLE` for a non-VID control, so they reach `Vid.sys` and are turned away. **A draft of this nearly shipped the opposite**: it
  searched handle names for *"Vid"*, found none, and concluded there was nothing to duplicate —
  but `Vid.sys` is PnP root-enumerated, so
  `\GLOBAL??\ROOT#VID#0000#{7896e901-…}` resolves to **`\Device\00000006`**, and this record
  already wrote the prefix as the device interface path. **Not established**: that the route
  reaches the receiver, which *this* arm does not test — the receiver arm above does, and closes
  it. A draft inferred that read-only duplicated
  access is insufficient; **withdrawn as the wrong axis, and S5m had already written the answer** —
  the receiver is IOCTL `0x221148` with `FILE_ANY_ACCESS`, gated on *holding a partition handle*,
  not on an access mask. Invoking it means `VidRegisterExceptionHandler`, and a draft justified
  skipping that with the wrong hazard: the call **refuses** a claimed slot with
  `STATUS_VID_DUPLICATE_HANDLER` **before** touching the hypervisor rather than displacing a
  handler, and the documented hazard is collision with a **raw** installer the duplicate check
  cannot see. The test is therefore more available than claimed and still a decision — an unclaimed
  slot would be claimed by us on a running VM — and it was step 7's next arm, **since run: see the
  receiver-arm entry above**. Controls, errors and
  limits in the **Step 7** section of
  [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).
- **Item 103 step 8 is costed, and the costing does not yield the decision — which a first draft
  of it claimed anyway.** The solid result is a negative: the **documented** partition API
  (`WinHvPlatform.dll`) has **66 exports and none naming VTL, VSM or secure**, so a rig rests
  entirely on the undocumented VID surface and private COM contracts. The entry point is decoded
  — `VidCreatePartition`'s three parameters and four gates, the create/open-existing boolean, and
  `VidpSetupPartition`'s `NtDeviceIoControlFile` control code **`0x2211A0`** with its length
  arithmetic — and the capability is present there (`VidVsmEnableVpVtl`, `VidMessageSlot*`).
  **Both numbers the draft decided on are retracted**: its 51,936-byte IOCTL buffer is an extent,
  not a field count, and reading the whole function shows `vid.dll` interprets **two** fields of
  it, both for length; and its 19 modules / ~9.9 MB of `vmwp.exe` device model are **COM in-proc
  servers with 24 registered CLSIDs**, so that is where the implementation lives rather than a
  bound on code to rewrite — though nothing here activated one, so they are **registered**, which
  names the mechanism rather than proving it works. Two probes would **narrow** it, neither run
  and neither sufficient: a census of `Vid.sys`'s `0x2211A0` handler, and an activation probe on
  one of those CLSIDs. Static throughout, and
  **no call was made**. Full record, including both retractions, in the **Step 8** section of
  [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).
- **The hold is a loop — supported, on Hyper-V's per-VP `Total Messages/sec` — and its sibling
  `Other Intercepts/sec` correlates the raising thread with both VPs.** They are two counters,
  not one: the first carries the loop evidence and the second the per-VP correlation, and this
  record says elsewhere that their tracking each other does not prove one message per intercept.
  Under *both* surviving readings **the raiser** makes no progress, because nothing advances
  `RIP` past the faulting instruction either way, so no counter the raiser keeps could
  discriminate them — *the guest* meanwhile executes throughout, which is a distinction a draft
  lost twice. The discriminator is on the **exit** side and Hyper-V publishes it per VM and per
  VP.
  `Total Messages/sec` reads **0** idle, **0** under guest churn, **0** with the raiser storming
  `#BP`s at **201,956** hypervisor intercepts a second *unarmed*, **0** with the vector armed and
  no raiser — and **65,676 across both VPs** with the intercept standing, sustained for 16 s
  while the raiser completes **zero** rounds. A pending intercept
  re-processed on the root side produces no hypervisor message at all, so those are **new
  deliveries**: the faulting instruction is re-executed tens of thousands of times a second with
  nothing retiring it. S5k's inference holds and step 6's arm 2 is answered.
  **Every figure in this entry is from the one six-phase run**, earlier drafts having mixed three
  into one table — caught by an `Other Intercepts/sec` exceeding the `Total Intercepts/sec`
  beside it, impossible within a run. **A finding fell out of the control, with a matched VTL0
  arm**: normalised per round, a VTL0
  `#BP` costs **at most 0.0027** hypervisor exits and a VTL1 one **at least 2.078** — bounds, not
  point estimates, and the VTL0 side subtracts no baseline at all: 0.0027 is *every* exit that
  occurred on either VP during that arm over its rounds, which an arm cannot exceed whatever the
  background did. A draft reported 0.0017 and 2.09 by subtracting a **three-sample** idle mean
  whose samples read 558, 2,389 and 360, with the VTL0 arm falling *below* it on VP 0; review
  round 6 pointed out that negative drift can cancel a positive contribution, so "under the
  drift" bounds nothing. **The ratio of the two bounds is 775×** and is itself a bound. Same
  guest and binary and counter with only the VTL differing, and the round-rate gap in that run
  is **9.45×** against the
  recorded 9.7 µs / 0.85 µs. That is a difference in kind and **not** a decomposition of the
  timing, which a draft claimed. The first attempt at that control was worthless and looked fine —
  the VTL0 raiser finished its rounds in 1.7 s, before the first sample — so round counts are per
  mode now and both arms print the rounds they retired. It is also what got
  the first run's verdict backwards: `Total Intercepts/sec` is *lower* armed (65 k) than unarmed
  (219 k), and comparing against it read "fewer exits" as "no new exits". **And the two-VP question
  is answered too**: `Other Intercepts/sec` — the bucket the exception lands in — is zero on both
  VPs in all **four** unarmed phases and nonzero on **both** armed, and that counter moves because
  an instruction trapped *on that VP*. Re-preprocessing of a pending message cannot produce
  per-VP hypervisor intercepts on a VP the thread is not on, so migration is the supported
  reading. **Supported rather than proven**, and the limit is the counters': they are aggregate
  rates carrying no vector and no `RIP`, so they attribute no individual sample to our `#BP` and
  do not exclude another armed-only source. What carries it is those rates plus the controlled
  comparison plus the VP markers' event-level naming of type `0x80010003`, vector `3` and the
  enclave `Rip` — and the stated assumption that nothing else in this guest raises `#BP` at a
  measurable rate — which now rests on a control that could have broken it, the vector **armed
  with the raiser absent**, reading zero on both VPs. The other four controls all ran with no
  intercept installed, so an unrelated `#BP` source would have been invisible to them; review
  round 4 named that and the control shares the armed phase's own install.
- **Item 103 step 6's two blocked arms both run, and the VPs turn out to be resumed.** They had been
  held by the standing constraint on installing a vector on a child and by root kernel-memory
  access; the first lifted for guests this bench owns and the second is what S5q's read IOCTL
  supplies. Everything here is a **pure read** apart from the intercept install. **The slot read**:
  `[P+0xB68]` is `FF FF FF FF FF FF FF FF` at **all twelve** samples across 24 s of a standing
  intercept, plus before the install and after the removal — unclaimed *at every sample*, not
  "throughout", since sampling cannot see a claim-and-release inside a gap. It is the
  contemporaneous, **non-mutating**
  read S5k has wanted since it was written and which S5m could only half-answer, because
  registering to ask whether the slot is claimed *claims* it. It narrows S5j's retained explanation
  without closing it: a claimant would have had to claim and release inside one 2-second gap and
  coincide with the raise. **The loop arm ran and did not answer its question, which the counters
  in the entry above later did**: `handled = 0` at
  all twelve samples shows the guest's `__except` never ran, which one trap held for the window
  gives too, and the frozen-or-slowed run's **20 fresh stamps** are twenty calls to
  `VidInterceptPreprocess` rather than twenty executions of the instruction — one pending
  intercept re-preprocessed gives the same series. S5k's re-entry inference stood as an
  inference at this arm, needing a count tied to new hypervisor deliveries or retired guest
  instructions — **and the loop-question entry above is that count**, so this arm's
  *did not answer* is superseded there rather than still open. **And a third reading came free**: per-VP
  `HvRegisterInterceptSuspend` is **transient** — seen on both VPs at different instants, and `0` at
  every sample of a control that raised **1.87 million** `#BP`s with no intercept standing — while
  both VPs keep accumulating `VpRuntime` and the **raiser** completes no rounds. **The VPs are being
  resumed**, which removes the necessary-condition objection review round 3 on #428 raised against
  the ping-pong reading of the two-VP markers — and removing an objection to one explanation is not
  evidence for it over another, so that question stayed open **at this arm**: nothing here
  correlates the single raising thread with either VP, and one pending intercept being
  re-preprocessed remains equally consistent. **The loop-question entry above supplies that
  correlation** and is where the two-VP status now reads. What *performs* the resumption is
  still unmeasured.
  One reading withdrawn because the control killed it: `RIP`
  `…4001C` appears on intercept-suspended VPs **and on running ones in the control**, so it is a
  common parked kernel address and not a signature of the trap.
- **A VTL1 `#BP` reaches VID too, and the message names the enclave's own instruction — which
  settles the fork S5h left open.** Same instrument as the VTL0 arm, same partition, same session,
  with `spin_host.exe BP1` raising inside a VBS enclave: both VPs read `0x80010003` / vector `3` /
  reason `2`, and the interleaved backed-out VTL1 arms on either side read nothing while completing
  2,000 rounds at **7.63** and **7.49 µs** each. **The intercept message's `Rip` is the enclave's
  `int3`** — `0x00000243071E500D`, `0x123` bytes from the routine the raiser named in that same run.
  S5h could not say whether the hypervisor takes the VTL1 trap in VTL1 or whether the enclave's
  dispatch makes a VTL0 excursion a VTL0-scoped intercept catches, because its register halts were
  consistent with both; a message reporting the **VTL1** instruction is not, because an intercept
  fired on an excursion would name the VTL0 one. **And it agrees with S5h across gates**: both arms'
  message `Rip`s match S5h's halted `RIP`s in their low 16 bits — `500D` and `748D` — on different
  boots with different ASLR bases, a VP halt and an intercept message naming the same two
  instructions. **`ExecutionState` bits 7–10 track the VTL, measured across two vectors**: `0x0097`
  in VTL1 and `0x001F` in VTL0 for **both** `#BP` (vector 3) and `#DE` (vector 0), which separates
  *the active VTL* from *something about `#BP` raised in an enclave* the way one vector could not —
  an identification from behaviour rather than from a header. Bit 3 (`Cr0Am`) tracks it too, so the
  delta is two bits and neither is about the exception, and the `Rip` moves with the *vector* in the
  same runs. A draft said that check was unrunnable because the hypervisor accepts exception
  intercepts only for vectors 3 and 4; that is **false** — S5i read a per-partition allowed-vector
  mask at `+0x6124` with an unconditional *exemption* for 3 and 4, `#BR` had already installed
  through the mask, and the vector-0 install was then tried and **succeeded**, adding a vector to
  what this child's mask is known to admit. **The raiser column says "did not finish" and nothing
  more**, so the freeze was measured separately — the guest's progress counter read **while the
  intercept stands**, which is the side of the release S5h's retracted "advancing" reading got
  wrong: `handled = 0` at ten samples over 30 s, against **2,282** the moment teardown releases it,
  reproducing S5h's artefact one line below the correct reading. **Interceptions kept arriving
  throughout** — 20 new stamps on both VPs at **one** `Rip` with nothing retiring, a re-delivery
  loop. **Where the second VP's events come from is left UNRESOLVED *by this arm*** — see below —
  after two drafts got it wrong in turn: the first called the two VPs "consistent with one held
  raise", which review refused
  because the raise loop is one thread; the second called it that thread ping-ponging between
  vCPUs, which review refused again because migrating needs the VP resumed and
  `WinHvCompleteIntercept` — the thing that resumes an intercepted VP — is exactly what nothing is
  calling. Settling it means measuring the delivery mechanism, which is an arm rather than a
  paragraph — **that arm has since run: the loop-question entry at the top of this section is
  where this question's status now reads**, and step 6's arm found the VPs *are* resumed,
  removing the objection recorded here. `UNRESOLVED` describes this entry's own arm, not the
  current state. The first draft also wrote the unarmed loop's **15.3 ms**
  as "15 s", three orders out. Scope unchanged: VTL1 **user** mode is not Secure Kernel. Bench intact — 0 intercepts
  standing at teardown on all three runs, `LsaIso` alive, both guests up **4h29m**, no bug check
  since boot.
- **The message IS delivered: item 103 step 9's arm, and S5q's third explanation is eliminated.** A
  `#BP` raised in a guest under a standing raw `HvCallInstallIntercept` reaches the root's
  `Vid!VidInterceptPreprocess`, which copies the message, stamps the VP and selects
  `VidHandleExceptionIntercept` — read on **both** VPs of the partition, every marker as the static
  read of the jump table at `Vid+0x3D137` predicted, with stamps **+27,772,140** and
  **+32,260,001** past baselines taken immediately before the raise. The copied message decodes as
  itself: `Sender` = the partition id, `VpIndex` `0` on VP 0 and `1` on VP 1 — so the message's own
  view of which processor raised agrees with the slot it was read from — `InstructionLength` `1`,
  `InterceptAccessType` `2`. The raiser was **held**, which is S5h's signature, and the
  **interleaved** backed-out arms on both sides show no exception markers and a raiser that
  completes. So `forwarded = 0` in S5q arm 1 was the chained slot being bypassed rather than nothing
  arriving, and the correction that section took in review — two dispatch-loop paths never read
  `[partition+0x10]` — is measured **in one run** rather than paired across two: a **combined arm**
  chains the callback, installs the intercept and reads the markers and `forwarded` at the same
  samples, giving `forwarded = 0` while both VPs read `0x80010003` at stamps ~1.08 × 10⁹ ticks past
  baselines taken *after* chaining. That arm's own first run was **vacuous and the driver's guard
  caught it** — while chained the registered pair is the probe's own, so the read was refused and
  the client reported "no arrival observed" from a zeroed buffer it never status-checked; the driver
  now takes the saved pair from its chain record and the client raises on a refusal. What is
  measured is reception **at preprocess** and nothing about retention: a held trap is produced by
  *both* branches of `VidHandleExceptionIntercept`. **Not settled**: which branch the
  handler took (`[P+0xB68][3]` read `0xFF` on both sides, consistent with the unclaimed-vector arm
  and corroborated by the trap staying held, but a claim-and-restore between samples reads as
  unchanged); and the raise was in **VTL0**, so a VTL1 raise was the next arm rather than something
  this one covered — **run, and it is the entry above**. The Secure Kernel scope limit stands as S5i
  left it. **And one defect worth the
  line**: run 1 called the arm confounded because the interleaved backed-out arm *after* the armed
  one showed a **stale** marker — the hit test compared type and vector and ignored the timestamp,
  which is exactly the defect review round 3 had filed against this plan, reproduced in the code
  written to honour it. Bench intact: teardown reported 0 intercepts standing every time, raiser
  killed after every arm across three unchained runs and two combined ones, the combined arm's
  `unchain` returning `SUCCESS` with the saved pair restored, both guests up **3h26m** unbroken, no
  bug check since boot.
- **The step 9 read is built, and the walk holds at run time.** Steps 1–2 of item 103 step 9:
  `h3probe.sys` gains `IOCTL_H3_VIDVP`, which takes a partition **id** rather than a pointer,
  resolves the VID partition object through Hyper-V's own locked table, refuses unless the
  registered routine lands inside the loaded `Vid.sys`, and reads every field through a
  kernel-canonical + `MmIsAddressValid` + SEH helper at `APC_LEVEL` or below. Nothing is written
  anywhere and no intercept is installed. On both lab partitions the static walk survives contact:
  `[V+0x00]` equals the partition for all four VPs, `[P+0xAA8]` reads **2** against Hyper-V's own
  report of 2 vCPUs per guest — an oracle with nothing to do with these offsets — and `[P+0xB68]`
  reads `FF` across vectors 0–7, so **`[P+0xB68][3]` is unclaimed**, the byte S5k named and nobody
  had read. **The reading worth more than the back-pointer check is a differential**: the live
  markers reproduce the type switch read statically out of `Vid+0x3D137`, on two message types and
  two partitions — `0x80000000` → `VsmmHandleMemoryIntercept` with reason `7`, `0x80010000` →
  `VidHandleIoPortIntercept` with reason `5`, each matching the `lea`/`mov esi` pair beside the
  jump table. The copied message's own sender field carries the partition id as a third
  corroboration. One caveat the output made plain and the record now states: `[V+0x68]` is the
  exception vector **only** for message type `0x80010003`; on the IO-port message it is payload.
  Bench untouched — driver stopped after, host uptime continuous, no bug check, both guests up
  throughout. **Nothing was raised** in this step, so what it retires is the risk in the arm rather
  than the arm — which the entry above then ran and answered.
- **The convergence point records its own arrivals, so the instrument is a read.** Item 103 step 9
  asked how the **root** partition's `Vid.sys` could be instrumented — *"a patch, a breakpoint on a
  host kernel this bench cannot freeze, or neither"* — and said to cost that before scheduling the
  arm. It is the third, and the reason is in the function: `VidInterceptPreprocess` runs straight
  from its entry to `+0x4f` with no branch, copying the whole `HV_MESSAGE` to `[VP+0x30]` and
  timestamping `[VP+0x208]`, and the type switch then leaves the selected handler at `[VP+0x158]`
  and its reason index at `[VP+0x200]`. A delivered `#BP` is therefore four values that name each
  other, readable from the partition context gate S5q already reads live — `[P+0xAB0] +
  VpIndex*0x980`, checked against the back-pointer at `[VP+0]` that `VidHandleExceptionIntercept`
  itself relies on — and `[P+0xB68]`, the per-vector claim table the step also requires, hangs off
  the same object, so the two readings the arm has to take together cost one request rather than
  two mechanisms — one *request*, not one instant, since an IOCTL reading several fields is not an
  atomic snapshot of them. **Sound because of two censuses, not because the code looks that way**:
  `[VP+0x208]` has one writer whose base carries this structure's fingerprint and **0
  address-taken** sites in the image, and `VidHandleExceptionIntercept` has **exactly one reference
  anywhere in `Vid.sys`** — the `lea` inside `VidInterceptPreprocess`. That is a statement about
  what is visible in one image, not a proof that every invocation goes through preprocess, and the
  instrument reports one thing — *an arrival was or was not observed at `VidInterceptPreprocess` for
  this VP* — and the record now scopes that **once**, in a table of what each inference rests on,
  rather than re-hedging it per paragraph: three review rounds landed on one sentence because every
  rewrite reclaimed coverage from a new angle. A positive is strong; a negative means "not observed
  at the convergence point" and **not** "not delivered", and the positive control shows the
  *instrument* works rather than that a raw-installed delivery shares VID's own route. The read
  being inside the callee retires the worry the step was written around: it does not depend on
  having enumerated the callers. Arms 1 and 2 are **not** separable by it — a claim-and-restore of
  `[P+0xB68][3]` between two samples reads as unchanged, so sampling cannot name the branch at any
  cadence, and the remedies that would are the patch route this gate declined.
  **New instrument**: `tools/pe_xref.py`, which answers *what can reach this RVA* by decoding
  rather than searching — a branch encodes a displacement that depends on where it sits, so there
  is no byte pattern to find, and the bytes of a function's address appear in immediates that
  transfer control nowhere. It attributes hits inside `.pdata` entries by name, decodes the
  executable bytes `.pdata` does not claim as a **detector** over every candidate start (reported
  apart and labelled, because a gap carries no boundary information), and searches **every** section
  for the two encodings a dispatch table uses, labelling the image's own `RUNTIME_FUNCTION` and
  `GFIDS` rows as the structure they are rather than filtering them out of sight. Which sections
  hold code is read from `IMAGE_SCN_MEM_EXECUTE` and not from a name list — `Vid.sys` alone ships
  five executable sections beside `.text`, and a name the list had not heard of would have had its
  gap bytes skipped in silence, which is the one way a negative here can be badly wrong. Scanning
  code sections for stored addresses closes the other: an indirect call through a RIP-relative slot
  names the slot, so a dispatch table in `.text` was invisible to the decoder *and* to the byte
  scan at once. And a byte capstone refuses no longer ends a `.pdata` function's decode: it steps
  over it, labels everything past the stop as possibly mis-framed and prints the refused count —
  without which a single byte of inline data would leave every later call in that function
  unexamined while the range still counted as claimed, so the gap detector would not pick it up
  either. Both images read here report **0 decode stops and 0 refused bytes** — a diagnostic, and
  *not* the reason their negatives are sound: a sweep that consumes inline data at the wrong
  framing refuses nothing at all, so what widens coverage is the candidate-start pass over every
  executable byte, below. The PE headers are scanned as a region of their own
  and `AddressOfEntryPoint` is reported by name, because a driver's `DriverEntry` has **no caller
  in its own image**: `Vid.sys`'s own entry point draws zero code references and one loader route,
  which is what the earlier version would have printed as a clean negative. And it refuses an image
  whose COFF `Machine` is not AMD64 rather than trusting the PE32+ magic, which ARM64 shares: read
  this host's own `arm64\breakin.exe` without that check and it reports **nine invented functions,
  all nine with a decode stop and 3,300 refused bytes** — a confident answer about nothing, on a
  bench whose guest is ARM64. And the candidate-start detector runs over **every executable byte**
  rather than only over what `.pdata` leaves unclaimed, because a linear sweep is one framing of a
  function and not coverage of it: `EB 01 B8 E8 F8 FF FF FF C3` sweeps as `jmp` / `mov
  eax,0xfffff8e8` / `inc ebx` and refuses **no byte**, while the `call` at offset 3 — the `jmp`'s
  own destination — is never decoded. So "0 refused" is about rejection and not about coverage, and
  the sentence that read it as coverage is corrected. On `Vid.sys` the wider pass is 652,268
  candidate starts and finds no route the sweep missed, with one re-framing of a swept hit dropped
  and counted. A reference found *after* a decode stop is a **detection** rather than a swept
  attribution — resynchronising one byte past a refusal is a guess, and calling it exact also seeded
  the suppression set the detector consults, silencing it at the one address whose framing was in
  doubt — and a detection is no longer labelled a "gap hit", because the detector covers claimed
  bytes too and sending a reader to look for a gap that does not exist is worse than saying nothing.
  `--self-test` **26/26,
  mutation-verified on sixteen edits**, every one applied and every one caught — and three of those
  earn a note. The byte-scan case's first version passed under
  the very mutation it existed for, because the immediate it used was a neighbouring number rather
  than the target's address; and `report` is now rendered into a sink for every case, because the
  counts come from `scan` and the printing path was otherwise never executed — which is exactly
  where the first version of this round's own fix crashed, on a tuple that had grown a field, with
  15/15 still on the screen. The third: widening the re-framing rule to drop *every* detection
  scored a clean sheet, because no case held an exact hit and a real detection at the same time —
  the control that pins it from the other side was written only after the mutation run said so. The
  linear decode replaced a quadratic one and was kept on a
  **differential** against the version it replaced rather than on the argument for it: identical
  references for nine targets in `Vid.sys` and five in `winhvr.sys`, **49.5 s down to 1.8 s**.
  **Costed against the alternatives**: the patch route fits mechanically
  (a 5-byte first instruction an `E9 rel32` replaces on an instruction boundary, ten bytes of
  padding ahead of it, `rel32` in range) but buys a PatchGuard exposure this gate did not measure,
  whose failure arrives later and names nothing; the host-breakpoint route needs a boot-config
  change this bench has not made and is read-only when it arrives. **Nothing ran live** — the
  IOCTL does not exist, and the arm's first act is the runtime confirmation a static reading
  cannot give.
- **The writer census, and a retracted claim comes back as a measurement.** Gate S5p, answering the
  step review added to the plan when it refused S5o's overreach. `[partition+0x3079]` — one of the
  two fields the VID create path tests before handing a second process a partition handle — has
  **19 accesses and 4 writers**, with no site taking its address in one step or two and nothing
  touching it in the 52 bytes of code outside `.pdata`: three
  writers clear it and **exactly one sets it**, inside the detach IOCTL, which itself requires the
  caller to hold the partition. Since the create path needs that field **and** the other one, and
  the first has exactly one located producer, **every admission this census can account for** was
  enabled by an owner's detach — a claim about located writes rather than a proof, because the
  method sees neither a pointer handed to another function nor a bulk copy spanning the field. So
  S5o's conclusion holds within that scope, with the evidence it was missing, and the retraction was
  right to demand it rather than wrong about the answer.
  **New instrument**: `tools/vid_field_census.py`, which walks a PE's own `.pdata` function table,
  disassembles with capstone and reports only real memory operands at a given displacement,
  classified read/write by operand access rather than by mnemonic. `--self-test` decodes six
  instructions whose bytes were read out of the image under study, plus three cases pinning what
  makes it necessary — that `mov eax,3060h` must not count, that a two-step address resolves, and
  that a two-step address to a *neighbouring* field does not; 9/9. **Review found two holes in the
  instrument itself and both are now closed or measured**, which matters because a census's whole
  value is the negative it licenses: `.pdata` omits leaf functions, so the tool now also decodes the
  executable bytes the table does not claim and reports them (20,622 bytes here, 20,570 of them
  padding, leaving 52 across ten runs, none touching the field); and a displacement is not the only
  way to form an address, so it now carries an intra-procedural alias table that resolves
  `lea rax,[rbx+3000h]` plus `mov byte ptr [rax+79h],1` to the field it really writes. **A second
  round then found three ways that alias table could *overcount*** — invalidating from capstone's
  `regs_write`, which carries only implicit writes, so `mov rax,[rbx]` left the overwritten pointer
  looking live; keeping a 64-bit alias through a 32-bit `lea`, which zero-extends and cannot hold a
  kernel pointer; and skipping alias resolution when the encoded displacement already matched, so
  `[rax+0x3079]` on an aliased base was reported as the field rather than as `+0x6079`. All three
  are fixed and each is now a self-test, alias state is dropped at basic-block boundaries rather
  than carried across joins in decode order, unexamined bytes after a decode stop are counted (`0`
  here), and each gap is decoded from every start after padding instead of once from a raw
  boundary. **A further round found the undercount that mattered more than any of those**:
  `add r,imm` updated the alias table only for a register already tracked, so
  `add rbx,0x3000` then `[rbx+0x79]` recorded nothing — while the tool's own docstring claimed
  `add` was covered. It now seeds from the pre-`add` value. That round also corrected a piece of
  reasoning in the write-up that had the failure directions backwards: for a census whose product
  is *"nothing else writes this"*, a **missed** writer silently falsifies the claim while a
  spurious one is only a row a reader dismisses. None of it changed the result. The instrument
  exists because the obvious search is wrong three ways, all
  of which bit here: a `s -d` scan walks **dword-aligned** and a displacement does not, so it misses
  sites silently; a byte scan matches immediates and data; and neither can see a write through a
  **taken address** — of which this census found a real one, `VsmmPhuPartitionTeardown` executing
  `and dword ptr [rsi],0` after `lea rsi,[rcx+3060h]`, a write with displacement zero that no search
  for the displacement can reach. Also identified: both gating fields belong to the `VsmmPhu*`
  **persistence** state machine, with `VID_PARTITION_UNPERSIST_START`/`_STOP` either side of one of
  them — so the second open is the reconnect half of persist-and-restore, which is why it demands a
  persisted, detached partition and re-owns rather than joins. **Residuals**, all named: a pointer
  to the field formed in one function and written through in another, since the alias table stops
  at a call boundary; one formed in a different basic block, since it stops there too by design;
  a bulk copy spanning the field; and the second field's writers being bounded rather than closed —
  the conclusion does not rest on that last one, because a conjunction is gated by its weakest
  reachable term. Also corrected: this gate does **not** establish that a running guest's refusal
  comes from the persistence field. The create path refuses when either gating field is wrong, no
  live partition was inspected, and the simpler reading is the other field — a guest that was never
  detached.
- **The refusal is a partition-state test with no token in it, and the branch behind it is an
  ownership handoff.** Gate S5o, a static read of `Vid.sys` — DbgEng opening the image as a target
  of its own, no debuggee, nothing executed, no VM touched — which answered the **two** steps the
  plan had left, neither by the arm it was waiting for. `Vid.sys` is a KMDF driver, which is why
  the previous gate could find no `IRP_MJ_CREATE` dispatcher to read — **not** because there is no
  `MajorFunction` table, as this entry first said, but because `Wdf01000!FxDriver::Initialize`
  fills all 28 entries with the framework's own `FxDevice::Dispatch`/`DispatchWithLock` and routes
  a create through `FxPkgGeneral::OnCreate` to the callback the driver registered. What the image
  lacks is a VID-owned dispatcher, not the table. The create callback is
  `VidFileCreate` → `VidFileObjectCreate`, and the refusal is a single site testing
  `[partition+0x3060] == 2` and `[partition+0x3079] == 1`. **It reads no token**, so the planned run
  as `SYSTEM` cannot change the outcome and was not performed — recorded as *not run* rather than
  as *refused*, since only the second would have been a measurement. The only token check on the
  path gates *creating* a partition, where an administrator is admitted outright and anyone else
  must present the `NT VIRTUAL MACHINE` SID matching the name; that the elevated account took the
  admin arm is measured rather than assumed, because the previous gate's unused-name opens created
  partitions the other arm would have rejected. The error that gate could only *match* is now a
  **common cause**: on the non-Exo arm there is exactly one such site, so its own held name and a
  live guest's name are refused by the same instruction, and the 62 candidate sites it counted are
  real and irrelevant. **And the branch the refusal guards is not a second client joining** —
  `VidPartitionAttach` makes the opener the partition's owning process, and the one way in this
  gate located runs through the current owner's detach IOCTL, which first unregisters the handlers
  and detaches every virtual processor. So on that route the step that would let us in dismantles
  what the previous gate found. Also corrected: `VidPartitionIoctlAttach` is the second half of that
  handoff and refuses a partition nobody has detached, not merely "start the virtual processors".
  **What this does not establish** — and the first draft of this entry claimed it: that the located
  handoff is the *only* way into the admitting state. No writers of either field are enumerated
  (the displacements are shared with unrelated `Vid` structures, and the first attempt to census
  them used a dword-aligned scan that missed unaligned sites), so another writer would leave
  registration alongside Hyper-V open; settling it needs a writer census or live confirmation.
  Neither state value is decoded, one build was read, and Exo partitions and handle duplication are
  untouched. **S5 does not pass**: the refusal is understood by cause rather than by match, and the
  route behind it empties the room it opens — with the writer census, not the VMM-of-our-own
  question, as the next cheap thing that could change either reading. **Both have since run**: the
  census as S5p, and the VMM-of-our-own question as step 8's costing — which did not settle the
  build either way.
- **Two gate sections still carried a "what to run next" list, and both had gone stale.** The class
  fix recorded against the previous round — one ordered plan in `FOLLOWUPS.md`, result sections
  stating what they leave *open* rather than what to run — was applied to two of the four sections
  that needed it. The remaining two are converted here, and the stale content is the reason it
  matters: one scheduled an arm this gate answered without running, and costed another at a host
  reboot into kernel-debug mode when it needed an image and a PDB.
- **A VID partition takes no second *open*, so the receiver has no reachable handle.** Gate S5n, the
  first live arm since S5h, and it cost the bench nothing: no VM touched, no intercept installed, no
  reboot. Opening a VID partition is a single `CreateFileW` on the VID device interface path plus
  the VM's Id, with `OPEN_EXISTING` — the path the library builds internally. Both running guests
  refuse with `ERROR_BAD_COMMAND`, while a well-formed unused name **opens** and a malformed one
  fails differently, so the name is recognised and the open refused. Two controls reproduce that
  error with no VM in them: a second open of the same name fails under either share mask and frees
  when the handle closes, and **across two processes** a name a child holds refuses the parent while
  a *different* unused name opens at the same moment — so the rule is global rather than
  per-process, and per name rather than per device. **What is not established** is that the live
  VM's failure has the same cause: the underlying status has 62 sites in the driver and the create
  dispatcher was not located, so the controls narrow the alternatives without eliminating them. The
  constraint measured is *no second open* rather than *one handle* — duplication and inheritance are
  untested and untried — and the caller was never varied, so privilege is unlikely rather than
  excluded. The exported receiving sequence the previous gate found therefore has no handle this
  arm could obtain. Also corrected: the library's "attach partition" call is the VM worker's *start
  the virtual processors* operation, not a second client joining; it was not called. **S5's
  obstacle has changed shape** — the mechanism exists and is exported, and what blocks it is a
  refused open — with two arms left before the VMM-of-our-own question, which is a rig
  rather than an arm. **That rig is now costed — see the step 8 entry above — and the costing did
  not settle the build: it found no documented route, and two numbers a draft decided on are
  retracted.**
- **The receiver is a user-mode export, and there is no driver left to write.** Gate S5m, the IOCTL
  read S5k named, against `Vid.sys`, `vid.dll` and `WinHvPlatform.dll`. The control code is
  `0x221148` — read from the dispatcher's compare chain, with a `0x10`-byte input carrying the
  vector and a caller context and an `8`-byte handle out — and `vid.dll` **exports a wrapper for
  it**, `VidRegisterExceptionHandler`, with attach, receive, complete and unregister exported
  beside it. So S5's receiver needs **no driver, no port and no hypercall**: it is a sequence of
  exported calls from a process holding a partition handle, which is the third downward re-scope in
  a row and deletes the build the previous gate specified — **conditional on obtaining such a
  handle**, which every call in the sequence takes and which this gate does not test. **It is not,
  however, a documented call**: the public WHP library delay-imports 31 `vid.dll` functions and
  this is not one of them — what it imports is the *Exo* family, a mechanism for WHP's own
  partitions. So S5 is one *observed, exported* call from passing rather than one supported call.
  Two consequences: the registration refuses a claimed vector with `STATUS_VID_DUPLICATE_HANDLER`
  **before** touching the hypervisor, which covers gate S5l's hazard **against clients that
  registered through the same path** and not against a raw installer, which leaves the table entry
  clear and is still exposed; and that same return value replaces **half** of the kernel-memory read
  the previous two gates wanted — it says whether the slot is claimed *at the moment of the call*,
  read as `GetLastError()`, since the wrapper maps failures through `RtlNtStatusToDosError` and
  VID-facility statuses pass through it verbatim. It does not replace the other half: registering
  *claims* the slot, so a fault raised afterwards travels the registered path and no longer observes
  the drop, and a reading taken now says nothing about a mutable byte's value during the earlier
  runs.
- **The hypervisor's exception mask is one bit with no owner, so an install/remove pair is not
  free.** Gate S5l, the removal read S5k left open, against the same `hvix64.exe`
  `10.0.26100.9444` and the same instrument. Install and remove are **the same function and the
  same bit**: one compare on `AccessType` picks `or` or `and ~`, the store goes to that VTL's mask,
  and the per-VTL recompute follows. There is **no refcount and nowhere for one** — two writers in
  the whole image, the other a partition-teardown zeroing, and a 32-bit bitmask has no room to
  count. So two parties holding one vector are one bit, and since removal is a plain `and ~bit` the
  **first** removal clears it for both, whichever party makes it — so this probe's `finally` *would*
  strip a VID client's intercept while Vid's own per-vector table still said armed. That confirms
  the *mechanism* of the hazard S5k left conditional, though not that it ever fired: no arm has read
  the slot, so what is established is the exposure. It also makes the controls argument S5k
  retracted false on a probed child rather than merely unestablished; it says nothing about which
  branch the earlier hold took, which still wants a replicated arm. Three bounds came free from the
  same function: `AccessType` must be exactly `0` or `4`, the vector is a `word` at `+8` of the
  intercept parameter bounded to `0x1F`, and a per-partition allowed-vector mask gates installs
  **except** that target VTL 0 admits `#BP` and `#OF` unconditionally — which is why a `#BP`
  install on a child never depended on the partition's configuration.
- **An unclaimed vector is dropped inside `Vid.sys`, and the receiver is an IOCTL rather than a
  build.** Gate S5k, both reads S5j called for, against `winhvr.sys` `10.0.26100.8972` and `Vid.sys`
  `10.0.26100.9278` opened as DbgEng image targets with public PDBs. **The table key** is the
  partition id — `WinHvSetInterceptRoutine` binary-searches a global partition array and fails with
  *"a partition with the specified partition Id does not exist"*, and the dispatcher looks the same
  array up by the message header's sender — so a registration's blast radius is one child, and
  displacement is real: Vid's only two call sites are an activate/deactivate pair on that one field.
  **Vid's path**: nothing filters an exception intercept out, the preprocess switch recognises the
  message type and selects a handler for it, and that handler then gates on a **second, per-vector
  table inside `Vid.sys`** which the install hypercall knows nothing about. Unclaimed vector means
  the handler returns having enqueued nothing, signalled nobody and woken no thread. What claims a
  vector is an IOCTL that reserves the slot and *then* issues the byte-for-byte descriptor gate S5b
  read — **so that install was not wrong, it was half of the arming sequence**, and the half it
  skipped is the half that makes anyone listen. Of S5j's two explanations of the hold the first is
  dead and the second gains a **competitor rather than a refutation**: which branch S5h's own
  message took turns on a **mutable** runtime byte this gate did not read, and nothing already
  measured stands in for it — the probe writes the same hypervisor mask the earlier arms observe,
  through a raw removal that touches nothing in `Vid.sys` and that S5l then read clearing the
  shared bit. Being mutable, the byte also cannot be recovered later: only a
  replicated intercept arm reports which branch is taken. The desynchronisation is a hazard of its
  own — a probe teardown would strip a vector a VID client holds while Vid went on believing it
  armed, an exposure rather than an observed loss.
  The receiver is nonetheless not
  something to build — the message path, the completion and the instruction-pointer advance already
  exist per partition and per vector — and the `WinHvSetInterceptRoutine` prohibition hardens into a
  permanent one, because the routine a registration would displace is the one that would dispatch to
  it. **New hazard**: an intercept message type Vid does not handle reaches `__fastfail` in the
  **root**, which is a host bugcheck rather than a guest one, and the unhandled set includes holes
  inside the range it otherwise covers.
- **The intercept message is already addressed to the parent, and the receiver is a displacement
  rather than an addition.** Gate S5j, the first half of the receiver work. **Routing**:
  `HvMessageTypeX64ExceptionIntercept` (`0x80010003`) appears once in `hvix64.exe`, and the
  recipient is chosen by scanning VTLs from the active one upward, wrapping to the lowest, and
  delivering to the first whose **own** installed mask holds the faulting vector. A `#BP` raised in
  VTL1 whose vector the parent installed therefore wraps to VTL0 and is delivered as a VTL0
  intercept, down the parent-directed path. **So the route is not what is missing** —
  nothing needs redirecting, and the hold S5h measured is explained as a message posted to a port
  whose owner never asked for an exception intercept — though what happened at the other end is not
  established, `Vid.sys` having a handler for this type, so that and "nothing was bound" are both
  live explanations the next gate must separate — **S5k above killed the first and added a third**.
  **Build**: the hand-rolled `HvCallCreatePort` and SynIC message page this gate was specified
  around are unnecessary. `winhvr.sys` exports the whole API — ports, SINT message retrieval,
  `WinHvSetInterceptRoutine`, and `WinHvCompleteIntercept`, which is the *resume* that separates a
  debugger from an observer — and `Vid.sys` already consumes it, including a
  `VidExceptionInterceptReturnCallback` for this message type.
  **Hazard**: `WinHvSetInterceptRoutine` stores one routine per table entry, assigned rather than
  chained, and `Vid.sys` imports it. That the import proves `Vid.sys` *calls* the function and not
  that its call selects the same entry is a distinction an earlier draft of this entry skipped:
  whether a registration displaces anything turns on the table's key, which this read did not
  identify — per-partition means one child, per-message-type means every VM on the host, an
  allocated handle means no displacement at all. Assume displacement, since the cost of being wrong
  is asymmetric, and call nothing here until it is known. **Two reads come next, not one**: that
  key, and Vid's own path for `0x80010003` through to completion — the key says whether a
  registration collides, and only the path says why the intercept stays outstanding, which is the
  other live explanation of the hold and the one a second receiver would not fix. **Both were run as
  S5k above**: the key is the partition id, and no second receiver is wanted at all.
- **The hypervisor applies a parent-installed exception intercept at every enabled VTL, by design.**
  Gate S5i, the dispatch read S5b named and S5h skipped, against this host's own `hvix64.exe`
  `10.0.26100.9444`. **It worked where two earlier attempts on that image failed because it asked an
  architectural question instead of a structural one**: those went looking for a hypercall dispatch
  table by shape and found the IDT and a page-table walk, while on Intel VMX an exception intercept
  *is* the VMCS exception bitmap, field `0x4004` — one constant in one instruction. New tool
  `tools/sk_vmcs_scan.py` finds it and walks outward from it.
  Five steps carry the result: `HvCallInstallIntercept` at `+0x295800`; **the VTL decision at
  `+0x295879`**, which compares the target partition against the caller's own and sets **VTL := 0
  for any child**, while the self branch takes the caller's active VTL and refuses VTL 0 — which is
  why the ABI needs no VTL field and why S5b found every byte it put where one might hide was
  ignored; `InterceptType == 3` landing at `+0x2C9430`, which ORs `1 << vector` into
  `array[VTL].0x1A04`; the recompute at `+0x2BECC8`, which descends the enabled-VTL set **seeded
  with `array[0].0x1A04`**, so a parent's mask lands in *every* VTL's effective mask; and
  `+0x331AA8`, which programs the bitmap for whichever VTL the VP is running.
  **So S5b's scope question closes in the second direction — implicitly every VTL — and S5h's hold
  was genuine VTL1 interception.** The retraction in #412 was right about what the halt evidence
  could carry and wrong about the conclusion, which is true on other evidence.
  The read also independently explains four things S5b measured from the other side: the
  `AccessType` 0-or-4 rule, the vector ceiling and the per-partition permitted-vector mask that
  refused `0x1F`, the block layout, and the ignored spare bytes.
  **And the Secure Kernel limit narrows**: a VMCS exception bitmap does not distinguish CPL 0 from
  CPL 3 and the bitmap is selected by VTL alone, so nothing in the mechanism separates VTL1 user
  mode from VTL1 kernel mode. That retires the specific reason to doubt it without making it a
  measurement.
- **A VTL1-raised exception is held by a parent-installed intercept and handed back intact — and
  which VTL takes it was settled separately.** Gate S5h. S5b installed and removed an intercept
  without provoking anything, so it could not tell an implicitly-VTL0 intercept from an
  implicitly-every-VTL one and recorded the route as *unresolved on scope*; this gate measures the
  **behaviour** and leaves that scope question to S5i above, which answers it. S5g's enclave supplies
  the missing piece — a VTL1 exception raised by code we wrote, rather than a planted `int 3` in
  Secure Kernel, which the plan excludes. One guest-side binary raises `#BP` in both VTLs and counts
  what its own `__except` catches, so the arms differ in the VTL and in nothing else, and the count
  is the detector: an intercept that fires takes the trap before the guest dispatches it, which
  needs no port to observe. **With the intercept standing the guest handled 0 of 20,000** in every
  arm — 120 consecutive zero samples over 24.4 s in VTL0, in VTL1 inside the enclave, and on the
  VTL0-only twin. **Removing it mid-arm lets all three finish 20,000/20,000**, so the traps are held
  and handed back rather than discarded: a resumable stop, not a swallowed exception. Both controls
  hold — an intercept on `#BR` that nothing raises, and a `#DE` raised against a `#BP` intercept,
  each leave both VTLs at their null rates — and either one alone would have left "an intercept is
  standing" and "this exception was taken" as the same observation. The guest keeps serving while an
  intercept stands, and no guest needed a reboot.
  **Two claims in the first draft of this entry are retracted, both found by review.** *"Six halts
  catch the VTL1 arm inside the enclave, which rules out a VTL0 excursion being what is
  intercepted"* — it does not, because a VTL1 exception reflected into VTL0 leaves VTL1 saved at the
  faulting instruction while VTL0 sits in kernel code, which is exactly the pair measured; the
  VTL0-labelled read lands in Secure Kernel's own page, which is the S5c anomaly's signature, and
  the 11x cost of a VTL1 exception over a VTL0 one is a reason to take the excursion seriously
  rather than to dismiss it. And *"only the raising thread is held"* was inferred from a connection
  that raises no `#BP` at all — the intercept is partition-scoped, so treat it as freezing every
  thread that raises that vector.
  **S5 still does not pass, and there are two next gates rather than one.** Nothing was delivered to
  *us*, because this probe holds no port — though the root's own stack owns one for each child, and
  an exception intercept it never asked for landing there uncompleted is the likeliest mechanism of
  the hold, so **the receiver gate** establishes where that message goes before building one — run
  as S5j, above, which found it already addressed to the parent. The dispatch-read gate that stood
  beside it was run as S5i, also above.
  **A working receiver would still leave Secure Kernel's own code untested**: the enclave is VTL1
  *user* mode and Secure Kernel is VTL1 *kernel* mode. Before S5i that gap was a mechanism question,
  since an excursion-mediated hold would not have reached Secure Kernel at all; S5i retires that and
  leaves an architectural inference.
- **The first four runs of that gate read the VTL1 arm as *advancing*, and it is retracted here.**
  The counts — 1,902, 6,396, 15,076, 18,486 — were all the monitor's final sample, written *after*
  teardown removed the intercept and the raiser finished, and one of them became a "405x slower but
  advancing" rate supporting a reading in which the two VTLs were reached differently. The trace
  says the count first moves at sample 121 of 121, and 219 of 219 in the runs with no release: 120
  consecutive zeroes, then a post-release burst. The reading now comes from where a count first
  moved rather than what it ended at.
- **Three routes to making Secure Kernel execute were tried and the third one works: our own code
  now runs in VTL1, and a halt taken while it runs is the condition every earlier gate was
  qualified on.** One route is closed, one unresolved, one open. Gate S5g, run with the
  operator's authorisation to reconfigure and reboot the VBS guest.
  **Credential Guard: unresolved, and the edition was the wrong answer** — an earlier version of this
  entry closed the route on Microsoft's edition table (*Windows Pro: No*) and used it to decline a
  review finding that said the edition could not be the cause. The finding was right: a Windows 11
  Pro machine reports Credential Guard protecting it, and this bench's own Pro host runs `LsaIso`
  while reading `SecurityServicesRunning = 0` — so Pro runs CG, and the field the guest was judged
  by is not a sound test either. What was actually seen: `LsaCfgFlags`, the DeviceGuard scenario key and
  `EnableVirtualizationBasedSecurity` all set, **Secure Boot `On` for both reboots** (it is a
  documented CG prerequisite, and this gate turns it off only later), `SecurityServicesRunning` still
  `2` and no DeviceGuard events — and **why** it never activated is unknown, the candidates being the
  in-VM requirements the same documentation lists, licensing entitlement, and the reporting field
  itself being unreliable. Note also that `LsaCfgFlags = 1`, which is what was set, is *enabled **with**
  UEFI lock* and `2` is without: a repeat on an eligible edition should use `2`, and a VM's CG is
  disableable from the host with `Set-VMSecurity -VirtualizationBasedSecurityOptOut $true`.
  **Writing a trustlet: closed by signing policy** — IUM wants a Microsoft certificate with the IUM
  EKU plus membership in Secure Kernel's identity list, and test-signing is deliberately not
  honoured there; patching that list from the root was raised and declined, being a HyperGuard
  bugcheck rather than a trustlet. **A VBS enclave: it works, and our own code now runs in VTL1** — once Microsoft's
  `windows-classic-samples/Samples/VbsEnclave` was used as the reference rather than building from
  first principles. The decisive difference is `PolicyFlags = IMAGE_ENCLAVE_POLICY_DEBUGGABLE`
  against the `0` this build used while the host passes `ENCLAVE_VBS_FLAG_DEBUG`; beside it
  non-zero Family/Image IDs, a `0x10000000` size the host must match, **no `/ENTRY` override** so
  the enclave CRT starts, plus `/GUARD:MIXED`, `SubSystem CONSOLE` and a `.def`. **With it
  spinning, the condition every halted-register reading was qualified on is measured**: `ActiveVtl`
  still reads `0` in 274,566 samples while the VPs are 25.8% and 52.4% busy — so the parent cannot
  use that field to tell whether VTL1 runs — yet halting anyway caught VTL1 **mid-execution in 6 of
  6 halts**, VP 1's VTL1 `RIP` landing in user mode inside the enclave across five distinct
  addresses, each frozen within its halt, while VP 0 stayed parked at Secure Kernel's. The halted
  VTL1 context is readable, stopped and its own, exactly as it was when parked — and the VTL1 read
  is therefore live, which supersedes this PR's earlier scoping of that result to VTL0. Before the
  reference existed the image was refused —
  `CreateEnclave` with `ENCLAVE_VBS_FLAG_DEBUG` succeeds every run while `LoadEnclaveImage` returns
  **193 `ERROR_BAD_EXE_FORMAT`** through nine eliminated suspects: enclave config, load config, page
  hashes, a `vertdll` import, `szOID_ENCLAVE_SIGNING`, TLS, the enclave CRT, `/INTEGRITYCHECK`
  (characteristics `0x160` → `0x1E0`) and chain trust (in-guest signature `UnknownError` →
  **`Valid`**). Two of those moved the failure and neither fixed it — test-signing took it from 577
  to 193, trust left it at 193 — so the signature path is satisfied and an unidentified image-shape
  rule remains. That diff against a known-good enclave binary is **done** and is what opened the route; an attempt to find one by scanning `System32` misread
  `IMAGE_LOAD_CONFIG_DIRECTORY64` and returned 62 false positives including `mfc140`.
- **That gate changed the lab guest**, recorded because a later one will read it: Secure Boot
  **off**, test-signing **on** (VBS and HVCI verified still running after both), a self-signed
  `CN=VTL1 Enclave Test` certificate in `LocalMachine\Root`, Credential Guard keys set and inert,
  and **four reboots**. The post-S5g landmarks are *measured* rather than inferred from that
  count — inferring movement from a reboot is the same error in reverse as inferring sameness
  from an equal `CR3`, which this record documents happening: VTL1 `CR3` is **`0x3BEF2000`**
  (it was `0x1201000` for S5c–S5f) and Secure Kernel is parked at **`0xFFFFF80679FB0035`**.
  **The self-map index was not re-read and is unknown**, not assumed to have moved.
- **The lab guests were reachable the whole time, which retires a limitation stated three times and
  turns the stop's evidence from 40× into 23,854×.** Gate S5f. *"Neither guest answers ICMP or
  WinRM, so there is no way to load them from outside"* equated **no network path** with **no guest
  access**; **PowerShell Direct** needs no network path and no WinRM — it wants a running Windows
  guest, Hyper-V administration on the host, the VMBus and guest credentials — and reaches
  both. Two results follow. **The register interface is live for VTL0** — under a user-mode spin, 110,638
  samples per VP return **6,675 / 6,603 distinct** VTL0 `RIP` values, **88%** of them ring-3, so the
  parent-side reads sample the running processor rather than a cached exit record; the idle constant
  was the idle loop. **That validation is VTL0-only**, since the spin ran there and every sample is a
  VTL0 `RIP`: a live VTL0 read is compatible with an inactive VTL1 query returning saved context, so
  S5c's and S5e's *VTL1* readings rest on an instrument checked for the other VTL — raised in review,
  and it needs a workload that demonstrably moves VTL1, which S5g could not produce. And **the stop measured against a busy guest** reads
  19,512,433 → **818** → 19,447,557 per 2000 ms, before and after within 0.3% of each other, with
  both VPs dropping together on the all-VP arm (7,290,238 → 319, 7,300,560 → 269). What driving the
  guests did **not** settle: `ActiveVtl = 1` is still unobserved across **832,560+** samples now
  including **twelve freshly loaded HVCI-verified kernel images**, and the halt's necessity is still
  unshown — 80,399 reads over a matched 3 s window give one distinct value per page, those pages
  being static under a workload that does not touch Secure Kernel's memory.
- **The root can halt a running guest's virtual processor and read that guest's VTL1 while it is
  halted — registers, page tables and page contents, with no capture.** The phrase this entry
  first used, *"a live Secure Kernel inspector is feasible end to end"*, is **withdrawn**: S5e
  measured the chain on a single virtual address, each page needed a route chosen for it, and S5's
  pass condition — a stop at a chosen point, delivered — is untouched.
  `FOLLOWUPS.md` item 103's gate S5c: `HvCallSetVpRegisters` (`0x0051`) writing
  `HvRegisterExplicitSuspend`, from the root partition, with no guest-side code, no exception, no
  intercept and no port. Stop every VP (S5c), read VTL1 registers (H3) and VTL1 memory by
  **whichever of H4's two routes serves each page** — the direct one alone returns an all-zero page
  for the address S5e walked to — resume. **A status is not a stop, so the stop is measured
  separately**:
  `HvRegisterVpRuntime` counts executed time and is read-only, and it reads **430** (VTL0 control)
  and **1,032** (VTL1 test) per 2000 ms while suspended against an idle band of **41,291–84,075**,
  with a three-sample no-suspend null model beside it — because a first attempt at a 60 ms window
  could not tell a suspended VP from an idle one, and an earlier guard looked for a catch-up burst
  on release that an idle guest never produces. While halted the VTL1 context is readable and
  distinct: `CR3` `0x1201000` — the value S0 and H4 recorded on the **2026-09-26 boot**, where this
  ran on the 2026-09-27 one, so a recurring value rather than a third confirmation of one state —
  with `RIP` `0xFFFFF80609990035`, and a separate read-only probe found the VTL1 `RIP`
  distinct from VTL0's in **40 of 40 samples on each of both VPs**, moving across a suspend cycle,
  so it is Secure Kernel's own live state rather than a mislabelled read. **Sampling a running
  guest validates only the running path**, so the halt was repeated eight times: the halted VTL1
  `RIP` equals its own pre-halt value **8/8** while the VTL0-labelled `RIP`/`RSP` come back as the
  VTL1 values **8/8** regardless of where VTL0 was — systematic, not coincidence, since the
  pre-halt VTL0 `RIP` took two distinct values across those cycles, and `CR3` stayed distinct 8/8.
  **Every one of those readings was taken with `VsmVpStatus.ActiveVtl = 0`**, so the record states
  them as an observation with that condition attached rather than as a rule for consumers — two
  drafts that phrased it as a rule were two review findings, because a rule invites a counterexample
  per unmeasured condition. `ActiveVtl = 1` is not merely unobserved: a sampler took **8,000 reads
  across both VPs with no delay and caught it zero times**, and at the time of that gate no way was
  known to make either lab guest run VTL1 from the host. **Superseded by S5g**: a VBS enclave does
  run guest code in VTL1, `ActiveVtl` still never reports it, and a halt taken during that
  workload catches VTL1 mid-execution. And the condition cannot be **enforced** with these primitives: reading
  `ActiveVtl` before the suspend races entry into VTL1, and reading it after depends on the
  suspension preserving it, which is the same unresolved question as the VTL0-labelled `RIP`
  reading as VTL1's. Reportable, not checkable — so the entry gives no consumer rule, three
  attempts at one having drawn three review findings.
- **A live inspector has to halt every VP, not one, and that is now the contract rather than a
  caveat.** One halted VP brackets per-VP *register* reads; it does not make *memory* consistent,
  because a second processor goes on running Secure Kernel and mutating the page tables and loader
  lists a VTL1 walk reads — S4's "identical only at the instant of the first read", arriving on the
  read side. Halting both VPs of the VBS guest was measured: `SUCCESS` on each, both runtimes
  frozen (995 and 299 per 2000 ms against 45,005 and 23,046 before, and 229,059 and 30,687 after,
  the first a catch-up burst from a guest that really had stopped), both released clean.
- **The halted `CR3` walks VTL1's page tables, the leaves are only partly readable, and "end to
  end" was wrong twice before that was measured.** Gate S5e: reading three GPAs preselected from
  H4's table never tested whether the halted *register* context can drive the memory path, so `CR3`
  was taken from the halted VP and walked through the direct route — `PML4E[496]` → `PDPTE[24]` →
  `PDE[76]` → `PTE[400]`, every level present with sane flags (`0x63` = P\|RW\|A\|D, `0x121` =
  P\|A\|G) — which reaches a physical address for a VTL1 **virtual** address. **The leaf reads
  too, through the other route.** Censusing each page whole — 4,096 bytes, both routes — gives
  PA `0x81F000` (the `RIP`'s leaf) **0** non-zero bytes by the direct route and **4,084** by the
  hypercall, PA `0x3BE1000` **200** by the direct route and 0 by the hypercall, and the page table
  itself 8 by the direct route and 0 by the hypercall. **Each page is readable by exactly one of
  the two routes and which one differs per page**, so neither alone reads VTL1's address space and
  a live inspector must try both per page — on **one** walked address and three censused pages,
  which shows the chain can complete and not that an arbitrary VTL1 address will, since what
  decides the serving route is unknown and H4's `0x3600000` remains unretested by either.
  An earlier draft of this entry called the leaf
  *withheld* on the strength of a 32-byte zero window — the same prefix mistake the entry below
  documents, made one paragraph after documenting it.
- **That run also corrected H4 and closed a question it had left open.** H4's table records the
  VTL1 `CR3` page as reading "all zeros by both routes", flagged as "a limit of the mapping, a
  fallback, or genuinely zero" and left unmeasured. It is none of the three: every cell in that
  table is **16 bytes** from the start of a page whose first present entry sits at offset `0x830`,
  because a PML4's low entries describe user space. **H4's own landmark table proves it for its own
  boot**: it records that page's first present entry at offset `0x850`, so its first 16 bytes were
  zero whether or not the page was readable. Read whole on a *later* boot — the guest restarted
  2026-09-27, and its `CR3` is `0x1201000` again with a self-map at index **463** rather than 388 —
  the page carries 122 non-zero bytes and 26 present entries. Two boots, two consistent censuses,
  and a trap worth naming: a VTL1 `CR3` value can **repeat** across boots, so `CR3` equality is not
  evidence of the same boot. The row is corrected in place. The same trap caught S5e's own precheck at 64 bytes before
  the next step walked the page successfully: **a prefix is not a page.**
- **And the inspector has now run as one thing rather than as two halves joined by an inference.**
  "End to end" originally composed S5c (halt the VPs, read *registers*) with H4 (read VTL1 *memory*
  on a guest nobody stopped), measured in different runs — which review caught. One process now
  drives both drivers, with the LiveCloudKd SDK's own freeze and pause **off** so the only stop is
  the measured one: both VPs halted (runtimes 11,149 → 379 and 32,119 → 188), **3 of 3** VTL1 GPAs
  returning content while halted, each read **twice inside the halt** and agreeing 3/3, two of them
  byte-identical to H4's recorded values — across two boots, so a statement about those bytes
  recurring rather than about one state read twice. What it does **not** show is that the halt was
  necessary:
  the same double reads while running were stable too, since an idle guest changes nothing and
  neither lab guest can be loaded from this host.
- **S5 still does not pass, and the gap is stated rather than rounded off.** Its condition is *a
  VTL1 execution stop delivered to a debugger*: this is the **whole VP**, at an arbitrary point,
  found by polling. Set by naming VTL1, `HvRegisterExplicitSuspend` reads `1` at VTL0 too, and the
  symmetric arm — naming VTL0 on the same VBS guest — reads `1` at VTL1 and stops the VP just as
  hard (495 against 1,032), so there is one VP-wide suspend behind a VTL parameter that decides who
  may ask, the same shape S5b found on the intercept block. The parameter *is* validated: naming
  VTL1 on the twin with no VTL1 is refused with `0x0015`, the code its VTL1 register read returns.
  `VsmVpStatus.ActiveVtl` read `0` in all 80 read-only samples and every arm, so Secure Kernel was
  never caught executing. The debugger half is back to S5b's leftover — whether a partition-scoped
  intercept fires for VTL1 execution — which is the only remaining candidate that could stop at a
  chosen point, and still needs a receiver.
- **A parent may install an exception intercept on a child partition, and may not aim one at that
  child's VTL1.** `FOLLOWUPS.md` item 103's gate S5b, which is the candidate S5a left standing: a
  VTL1 stop driven from the root through `HvCallInstallIntercept` (`0x004D`), the primitive Secure
  Kernel itself issues from `ShvlInstallExceptionIntercept`. The install half works — from the root
  partition an exception intercept goes onto a running child and comes off again, `SUCCESS` both
  ways on both lab guests, with the negative controls refusing (`INVALID_PARAMETER` for a bad
  intercept type or access mask) so that success means something. The aiming half does not exist:
  the TLFS documents the whole 0x18-byte input block — `PartitionId`, `AccessType`, `InterceptType`,
  `InterceptParameter` — and `HV_INTERCEPT_PARAMETERS`' exception member is a bare `UINT16
  ExceptionVector`, with no VTL field and no reserved one; both known callers write exactly those
  bytes — the 26100.9457 Secure Kernel sample and the host's own `winhvr.sys`, neither of them the
  guests' running SK — read once with capstone and once with Ghidra because a published field layout
  should not rest on one tool. Live, the union's six spare bytes and eight bytes appended past the block
  are accepted **identically on the child with no VTL1 at all**, and declaring them as a
  variable-sized header is refused with `INVALID_HYPERCALL_INPUT`, so there is no extended form
  either. **S5's pass condition is untouched** — a VTL1 execution stop delivered to a debugger — and
  what this closes is *aiming*, not the route: with no selector in the ABI, an intercept is either
  implicitly VTL0 or implicitly every VTL, and the second needs no selector because it would already
  deliver a VTL1 exception to the parent. Which of those it is stays open and is now the cheapest
  question in S5, needing no new primitive. It also corrects the plan: SK issues
  intercept type **3** (`HvInterceptTypeException`) with access mask 4, not "intercept type 4"; the
  two are adjacent dwords.
- **What makes that a reading rather than a hopeful one is a control that failed first.** The gate's
  first run chose exception vector `0x1F` so that an install could intercept nothing — Intel reserves
  it and no hardware raises it — and every arm came back `INVALID_PARAMETER`, baseline included,
  which reads exactly like a clean negative about VTL1 and is a statement about the vector. The
  script now *discovers* a vector the hypervisor accepts, on the guest with no VTL1, before any arm
  that claims to be about VTL1 runs; `0x05` (#BR) is the vector it takes. **What is retracted is the
  other half of that choice** — that the vector cannot fire. Two review rounds each named a way #BR
  reaches a running x64 guest (MPX's bound-check instructions; the legacy `BOUND`, which still
  decodes in 32-bit compatibility mode and so in every WOW64 process), an `int 5` is a third, and no
  CPUID reading settles a claim about every instruction a guest might execute. What protected the
  run was disposable guests and an install paired with its removal microseconds later — not the
  vector. And "accepted" reads as "not a VTL selector" only because
  the same run shows what a field the hypervisor *does* read per VTL does on that control guest:
  `HvCallGetVpRegisters` with `TargetVtl = 1` is refused there and succeeds on the VTL1 guest. That
  contrast also names the *second* of S5's two remaining candidates — the three suspend registers
  (`HvRegisterExplicitSuspend`, `HvRegisterInterceptSuspend`, `HvRegisterDispatchSuspend`) are
  readable from the parent at VTL1 on the VBS guest and refused at VTL1 on its twin, so a stop
  needing no exception and no guest-side code is at least nameable per VTL. Whether it is
  *writeable* is the open question, and S4 is why the read does not answer it.
- **The hypervisor's VTL1 debug port and Secure Kernel shipping no KD transport turn out to be one
  fact, and `tools/sk_hypercall_scan.py` is how that was established.** `FOLLOWUPS.md` item 103's
  gate S5a. The record held the two apart: the hypervisor's root VTL1 debug context is live — active
  port `0xC35C`, both buffers allocated once `hypervisordebugpages` went 1000 → 2000 — and nothing
  ever connects to it, while post-26100 `securekernel.exe` has every `Kd`-prefixed symbol as data.
  Joining them needed the question *what would speak to that port*, and the answer is on the same
  machine: `kdhvcom.dll` is Windows' own KD transport over the hypervisor, exporting the five-function
  contract (`KdInitialize`, `KdPower`, `KdReceivePacket`, `KdSendPacket`, `KdSetHiberRange` — the same
  five as `kdnet.dll`) over `vmcall`/`vmmcall` and exactly three control codes. Which code is which is
  pinned by that binary's own call graph rather than by citing a table: `KdInitialize` reaches `0x6B`
  alone, send and receive reach all three, `KdPower` and `KdSetHiberRange` reach none. **Across ten
  `securekernel.exe` builds from 19041.207 to 29667.1000, none of the three appears as an immediate at
  any instruction boundary the scan recognises** — every occurrence at one is a `cmp` in unrelated
  code — **no sample materialises a synthetic-debugger MSR number `0x400000F0`–`0x400000FF` at all,
  and no sample contains a `vmcall` or `vmmcall`**. So the port is a receiver with no sender. S5 itself
  is *not* closed: its pass condition is a VTL1 execution stop delivered to a debugger, and what this
  closes is one route, leaving the one needing no guest-side code — `HvCallInstallIntercept`
  (`0x004D`), which SK itself issues at VTL0 through `ShvlInstallExceptionIntercept`, aimed instead at
  a child's VTL1.
- **That scan decides from a sound reading and corroborates with an unsound one, because the first
  version rested everything on the unsound one.** Reading A — the immediates and the privileged
  instructions — is taken over every executable byte from four seeds unioned (`.pdata`, a linear sweep,
  a recursive descent from direct call and jump targets to a fixpoint, and the export table), plus a
  raw opcode byte search and a search anchored on the constants' own little-endian bytes. Reading B,
  the hypercall repertoire, walks in address order without following control flow and is a heuristic
  lower bound — 19 to 38 control codes per build, `0x0002`–`0x0103` — whose job is to be the negative
  control, a Secure Kernel issuing *no* hypercall being a broken scan rather than a finding. It never
  produces the verdict. Five review rounds and 28 findings did not move the answer and did move that
  structure. Four proposed remedies were declined, three of them because each would have deleted the
  reading it defended: clearing state at branch joins takes 26100.9457 from 38 codes to **1**, and
  invalidating on unresolved MSR indices or unresolved repertoire sites makes every build
  inconclusive, all ten having some. The fourth was declined for a different reason — seeding the
  Guard CF function table is not available at all, `securekernel.exe` having none (table 0, count 0,
  against 8,756 entries in `ntoskrnl.exe`, 1,535 in `kernel32.dll` and 13 in `kdhvcom.dll`, which is
  how that probe was validated before its negative was believed). **What the limits are is printed with the
  result rather than left in a document**: 5 to 12 repertoire sites and 16 to 19 `rdmsr`/`wrmsr` sites
  per build whose operand does not resolve, the scan reading *immediates* rather than values — a
  constant in `.rdata` is neither — and a verdict that says "no debug hypercall route **visible to
  this scan**". `--control` is not optional: a run without one prints UNVALIDATED and exits non-zero,
  since the file's own claim is that a failing control voids every negative. Four traps are recorded
  with it, each of which produced a wrong reading first — a sample whose *filename* silently defeats
  `cdb` symbol resolution, so nine of ten images reported "0 hypercall sites" with the conclusion's
  shape; `0x0C` being both a control code and the rep-count bound beside it; bug check codes read as
  hypercall codes, `SkeBugCheckEx` reaching the hypercall page with a literal `0x0087` and bug check
  `0x69` existing; and the linear sweep genuinely desynchronising, measured against `.pdata` as 2 or 3
  of 2,617–3,221 checkpoints per build, which is why dismissing a candidate now rests only on seeds
  that start at a known function entry.
- **A Hyper-V checkpoint now opens as a debug session, and four tools read the Secure Kernel out of
  it.** `FOLLOWUPS.md` item 103's gate S3: `open_sk_capture`, `sk_modules`, `sk_read_memory` and
  `sk_symbol`, in a `--tools securekernel` group, over `src/sksession.rs`. Gates S1 and S2 were
  reachable only from `windbg-mcp --sk-inspect`; this is the same two halves behind the tool surface,
  and the three questions the gate was deferred to answer are answered by where it puts things.
  **The engine lives in a worker, and the decisive argument is measured rather than architectural.**
  `AGENTS.md` already keeps DbgEng out of the process serving MCP, which settles the symbol half and
  says nothing about the decode, which needs no engine at all — what settles *that* is S0 arm 4:
  `vmsavedstatedumpprovider.dll` `__fastfail`s (`0xC0000409`, `FAST_FAIL_FATAL_APP_EXIT`, from a GSL
  contract violation inside `LoadSavedStateFile`) on a capture it has no key for, so a vendor DLL
  that aborts the process on an input a caller supplies cannot be loaded beside the session registry.
  In a worker it costs the one session that named the capture. **One session handle carries both
  halves**, `symbols` opt-in on it, because the symbols are the capture's only through the image the
  mapping was identified against and the rebase needs the base the decode found — two handles would
  be two halves of a join nothing checks. **And a "structure walk" is the decoders `src/sk.rs`
  already has**: the public `securekernel.pdb` carries no type records, so there is no `dt` over VTL1
  on offer and the four type probes travel with the session, which tells a caller *why* rather than
  letting them find out one failed call at a time. What follows from a capture being a file is that
  **the debugger tools are refused on such a session** — by an allow-list, in both directions, in the
  one funnel every call passes — because the engine in that worker holds `securekernel.exe` **as an
  image** and `read_memory` there would read the file and answer as though it had read the guest,
  which does not fail. The refusal names what the engine is holding. That refusal is also what keeps
  the answers stable: nothing in the session can run a command, so the target cannot be replaced
  under the symbols, and the capture does not change — which is why the **whole decode travels with
  the open** rather than being re-read, counters included, for the structured-aware client that drops
  the text. Measured over MCP against the same `H1 pinned 26200.9457 VBS+HVCI` checkpoint gates S0,
  S1 and S2 ran on: **every one of their figures came back unchanged** — root `0x107593000`, 29
  present entries with the self-map at 309, 16,437 leaves over 4,545 pages from 179 table reads and
  215 decodes, `securekernel.exe` at `0xFFFFF8070EDA9000`, `KdDebuggerDataBlock` at `+0x1335E0` with
  `Size` `0x3A0`, `SkLoadedModuleList` at `+0x127770`, the same six modules, the structural
  cross-check agreeing with the block, 18,253 reads and **0** failed, both landmarks agreeing in both
  directions, all four type probes `E_NOINTERFACE`. And one thing the command-line role could not
  show: `sk_read_memory` at the block's own address returns the self-pointing `LIST_ENTRY`, then
  **`KDBG`**, then `0x3A0`, then `0xFFFFF8070EDA9000` — three of the decode's conclusions read back
  as bytes through a different path, with the engine naming that address beside them. The control arm
  is the other half: the VBS-off twin's capture reports partition VTLs `0x1` against `0x3`, the
  provider refusing the VTL switch by name (`0xC0370509`), and the session **opens** carrying that as
  its reason and refuses every read with the same sentence — while its symbols load normally, which
  is the pair that had to stay distinguishable. Thirteen new unit tests (1,101 now, from 1,088) and
  four in the smoke harness (130, from 126), all eighteen guards **mutation-verified**: the
  kind gate three ways — accept every debugger op on a capture, accept every capture op elsewhere, and replace
  the allow-list with a deny-list, where the row that then goes through is the one that was not
  thought of — and five renderers, including a landmark that disagrees rendering as agreement and a
  failed type probe being dropped beside one that answered, which is review round 8 of #399's finding
  one level up. The capture tier's gate is a **file** (`WINDBG_MCP_SMOKE_SK_CAPTURE`), so it needs the
  Hyper-V role on no machine, and it asserts the *shape* of the answer — a decode, or the reason there
  is none, never neither — because whether a capture has VTL1 in it is a property of somebody's guest.
  **What it costs is recorded rather than absorbed**: the surface grew 7,501 B of model-visible
  context across 63 → 67 tools, paid by every caller because the default surface is every tool, and
  whether a group should be able to sit outside that default is now item 106 rather than a decision
  this made quietly. The `tools/list` payload found a **multiplication** on the way, which is the
  first time that ceiling has caught one: holding the report in `TargetSummary` inlined its schema
  into all seven openers' `$defs` and measured 341,057 B, and moving it into an outcome of its own
  took **50,844 B** back off the wire for a change no client can observe. Two review rounds found
  nine defects, eight of them taken: four were a **value asserting something nothing had compared** —
  the structural cross-check reporting agreement it never checked, an interrupt marking a job it could
  not stop, an opener's refusal answering in the wrong shape, a tier's prose claiming a tool its body
  never called — and two more were the same thing in a **sentence**: a `limitation` giving the VBS-off
  reading for all six reasons a capture can have no VTL1, and a page's headline byte figure left
  behind by its own table. The eighth is declined with its fact recorded: an open that exceeds the
  call timeout loses its decode, and both remedies would put another copy of a ten-kilobyte schema on
  the wire for every caller. Round 3's single finding is the one worth carrying forward: a read
  whose last byte was past the top of the address space wrapped to zero, because `Gva::offset` wraps
  deliberately — refused in the reader every part of the decode goes through rather than at the one
  call site, and with its own failure, since reporting it as the low page it wrapped onto is what made
  it worth filing. `sksym::Rebase` has refused the same thing since gate S2, which makes three
  findings in three rounds where the rule already existed in a sibling and this code was the outlier.
- **`securekernel.exe`'s symbols now resolve against the base gate S1 found in a capture, with no
  debuggee anywhere — and the PDB agrees with the capture scan to the byte.** `FOLLOWUPS.md` item
  103's gate S2, `src/sksym.rs`, driven by `windbg-mcp --sk-inspect --symbols`. The unknown the gate
  was written to settle was whether image-only resolution is available at all, since every
  `dbgscope` symbol method assumes a session with a target; the answer is that **DbgEng opens a PE
  image as a target in its own right**. `OpenDumpFileWide` on
  `C:\Windows\System32\securekernel.exe` gives a session with exactly one module at the image's own
  `ImageBase` `0x140000000`, and `.reload /f` fetches `securekernel.pdb` from the public store — so
  this needed **no new typed `dbgscope` primitive** and no `execute` text hatch, and the whole of its
  own work is the rebase from that base onto the guest's. Measured 2026-09-27 against the same
  `H1 pinned 26200.9457 VBS+HVCI` checkpoint S1 ran on: the PDB puts `KdDebuggerDataBlock` at RVA
  `0x1335E0` and `SkLoadedModuleList` at `0x127770`, **the same two offsets S0's tag scan and S1's
  decode found inside the capture**, rebasing onto the decode's own `0xFFFFF8070EEDC5E0` and
  `0xFFFFF8070EED0770` — and asked the other way round, a separate engine call, the engine names both
  of those guest addresses with displacement **0**, which is the only value that says an address *is*
  a symbol rather than being somewhere after one. Every S1 figure reproduced unchanged in the same
  run. So the module list is now reachable **three** ways and one of them needs no debugger data
  block at all: the tag scan cannot find `SkLoadedModuleList`, a bare `LIST_ENTRY` with no signature
  to search for, and a PDB names it directly. The scan stays primary, because a host with no symbol
  store or a build whose PDB is not served has only that route. **Three things this settles in the
  negative.** The public `securekernel.pdb` carries **no type information** — `dt securekernel!*`
  lists symbols rather than types, every global prints `= <no type information>`, and four
  `GetTypeId` probes in the shipped code all answer `E_NOINTERFACE`, *no such interface supported*,
  which is the engine declining type queries for this module rather than four names being absent — so the plan's "symbols **and** types"
  is one of the two, and structure walks over VTL1 stay hand-decoded. `SymbolKind::has_type_info`
  must not be the test for that, reading `DEBUG_SYMTYPE_PDB` as private type information where this
  module is `symbols: pdb` with none: the engine does not distinguish a stripped public PDB from a
  private one. And **rebasing inside the engine is a trap that was measured being one** — a second
  `.reload /i securekernel.exe=<base>,<size>` with `.exepath` set does load the image at the guest's
  base and resolve the same PDB there, but the module name collides, so it comes up
  `securekernel_exe` and *both* answer to `securekernel!`: with the pair loaded,
  `? securekernel!KdDebuggerDataBlock` answers the **preferred** base. One module plus arithmetic has
  no such ambiguity and is testable with no engine, which seven of the eight new tests are (1,088 unit
  tests now, from 1,080). Five
  pin the rebase against literals — the two landmark offsets, the half-open end of the image, an
  address below the base refused rather than wrapped, both bases checked for overflow, and an
  unresolved symbol reading as *unknown* rather than as a disagreement, because a host that cannot
  reach a symbol server must not read as a decode that is wrong — and all four guards were
  mutation-verified, each failing the one test it belongs to and no other. The sixth reads the
  crate's own source and pins which files may construct an engine. Only the seventh needs an engine,
  a symbol store and a real image, and is gated on the image path so the gate and the input are one
  thing (`WINDBG_MCP_SMOKE_SKSYM`); it deliberately asserts **nothing** about the type probes, since
  whether a Microsoft public PDB carries type records is Microsoft's to change and pinning today's
  answer would fail on exactly the build worth hearing about. The symbol half is **opt-in** because
  it is the only part of `--sk-inspect` that loads an engine, it opens before the SDK provider
  because the two would otherwise fight over whose `dbghelp.dll` the process has, and a failure is
  reported in place rather than ending the run — the control arm is what that is for: against the
  VBS-off twin the symbols load and report normally while the capture refuses the VTL switch with
  `0xC0370509`, and the report and the JSON keep those apart. **Symbols are made to load and then
  required**, with one deliberately-failing lookup after the forced `.reload /f`: a module left
  `Deferred` would otherwise load its PDB on the first *landmark* query, after the only `unmatched`
  check had run — printing another build's names as this build's — and would report `kind Deferred`
  and "no PDB signature" above addresses that PDB had just resolved. A probe alone only narrows that
  window, so after it a module without a symbol provider is refused, which is honest in a way it was
  not before: a probe *is* a first use, so `Deferred` after one is the engine having looked and not
  resolved them. Measured throughout — a deferred module moves to `pdb` with its key on a single
  failing lookup; the probe alone loads it with the reload not issued at all, so the two are
  independent and the reload stays for its *named* error; a symbol path reaching no store leaves the
  module reading `Export`, which is what the refusal actually fires on; and neither landmark is among
  that module's ~280 exports, so refusing `Export` costs the gate nothing. **And the PDB the engine
  selected is an input** — on the failure arms too, since a refusal can have read one — added where it
  is first known so `--json`
  cannot name it; the mutation is what says why it is worth having rather than what the finding
  claimed — backing it out fails with `os error 32` because DbgEng still holds the file, so the
  protection was incidental and the guard is what turns a sharing violation into *you named an
  input*. **And a PDB nothing vouched for is a refusal either way round**, whether the engine reports
  it does not belong to this image or cannot be asked which one it loaded: `.ok().flatten()` had made
  the second read as "there is no signature", publishing provenance nothing had checked — and a module
  the engine calls PDB-backed while having no signature for it is the third and closing way that check
  can fail to happen, so it is a requirement on the kind rather than a fourth enumerated failure. The
  engine
  ratchet likewise fails on a *rename* of the type, since `use … DebugEngine as E; E::new()` would
  otherwise walk past a check that reads the name. And **a flag where a value belongs is refused** on
  all twelve flags that take one, not just the reported `--sympath`: `--symbols --sympath
  --cross-check` had taken `--cross-check` as the symbol path and left cross-checking silently off,
  and `--json` would have written the report to a file named `--cross-check`. The test that should
  have caught it was named for exactly that property and put the flag last, where there is no next
  flag to eat. `--sk-inspect` also **names the build
  that produced its report** now, as its first line and in the JSON, because a figure taken from this
  role is a reading of the binary that answered and the tree beside it moves independently; the runs
  above were taken from this change's own working tree, a `-dirty` build over `3552d867`, and
  re-measured unchanged after the rebase onto `44428f5`. **It is a
  third process in this crate that loads DbgEng**, which review raised as a P1 against `AGENTS.md`'s
  *worker or nothing* wording: the rule's constraint is one debuggee session per process, every call
  on the thread that made it, and no engine in the process that serves MCP, and this role meets all
  three — one target, and that target is a *file*, on a single thread, speaking no MCP and returning
  from `main` before a runtime exists. `AGENTS.md` now states the constraint rather than the shape,
  and a test fails if a **third** file constructs an engine, so the next one is a decision rather
  than a review finding. Still **no MCP tool and no
  `tools/list` change**; the surface is gate S3, which this moves rather than answers, since the
  decode is engine-free and the symbols are not.

- **A guest's Secure Kernel can now be decoded by this server, from a Hyper-V capture, through a
  command-line role rather than a tool.** `FOLLOWUPS.md` item 103's gate S1. `src/sk.rs` is
  everything gates H0–H4 and S0 measured, expressed so the byte source is a parameter: a guarded
  four-level page-table walk, PE identification against an on-disk image, the `KdDebuggerDataBlock`
  decode and the `SkLoadedModuleList` walk. `src/savedstate.rs` is the one source it ships with — a
  Hyper-V saved state read through the Windows SDK's `vmsavedstatedumpprovider.dll` — and
  `windbg-mcp --sk-inspect` drives the two and prints a report, a fourth non-server role beside
  `--render-cast` that touches neither DbgEng nor MCP. **No MCP tool and no `tools/list` change**:
  the surface is gate S3 and its shape is an open question, and a capture is a fixed snapshot with
  no debuggee, which fits this server's one-worker-per-target session model awkwardly enough to
  deserve its own decision. **The seam is the design.** A source answers `root()` as well as
  `read(gpa, len)`, because the decode starts from the VTL1 page-table root and three captures of
  one guest carry three different ones — an implementation hard-coding the first would have walked
  from the wrong root on the third and not been told. Every read answers *whole or not at all*, so a
  16-byte-wide source cannot make a decode judge a 4096-byte page on its first sixteen bytes; every
  failure says **why**, because `HvCallReadGpa` refuses with `HV_STATUS_SUCCESS`, a per-access
  `ReadIntercept` and zeros, and a seam carrying bytes-or-nothing turns protected memory into
  plausible data; and the failure **count lives inside the read primitive**, where no consumer can
  bypass it, after four review rounds on S0's probe each found another `if reason { continue }`
  reporting a clean negative. Acceptance is two independent structures agreeing — `KernBase` inside
  the block, *and* the first `DllBase` of the list that block points at — enforced in the one
  function that can accept a candidate rather than left to whoever remembers to check, since a
  duplicate mapping of one image matches every header field and a stale `PsLoadedModuleList` yields
  plausible names rather than an error. Measured against the VBS guest's checkpoint on 2026-09-27
  and reproducing S0's Python probe landmark for landmark on that capture — `CR3` `0x107593000`,
  self-map index 309, `securekernel.exe` at GPA `0xCD0000`, the block at `+0x1335E0` with `Size`
  `0x3A0`, the module list at `+0x127770`, the same six VTL1 modules, 179 table reads and 215
  decodes — plus two checks the probe did not run: a structural route to the list head that agrees
  with the block, and the provider's own address translator agreeing with the walk on 373 of 373
  pages of the image. The VBS-off twin refuses the VTL switch by name (`0xC0370509`), reported as a
  refused **switch** rather than as a guest with no Secure Kernel. 34 tests, all fixtures rather
  than captured pages, six of them mutation-verified — one of which caught a test asserting against
  the same constant the code fills with, so changing the poison to zero had moved both sides of the
  assertion. `docs/secure-kernel/` carries the record.

### Changed

- **A tool argument this server does not have is refused, and the published schema says so
  (`FOLLOWUPS.md` item 107).** Serde ignores an unknown field by default, which for a tool argument
  fails *open*: three `disassemble` calls passing `target` — the parameter is `address` — were each
  served as though they had asked for nothing, disassembling at the current instruction pointer and
  answering `"status": "ok"` with a `start` that was the image entry point. All 52 `*Args` structs
  now carry `#[serde(deny_unknown_fields)]` (three did), so the call is refused with the offending
  key named and the tool's own parameter names listed beside it, and `schemars` emits the matching
  **`additionalProperties: false`** into every served `inputSchema` from the same attribute — which
  is the half that makes refusing it honest, JSON Schema's default being that an extra key conforms.
  Two places the struct list does not reach are closed with it: a **nested** object a caller fills in
  (`walk_memory`'s field list, `set_breakpoint`'s `watch`; the coordinate types already denied), and
  `attach_kernel_local`, which was declared with no parameters at all and so dropped *every*
  argument — `attach_kernel_local { "connection": "net:…" }` attached to the local kernel and
  reported success. A `debug_batch` **step** keeps the hand-rolled check `src/batch.rs` already had,
  serde making the attribute and `#[serde(flatten)]` mutually exclusive.
  `mcp_smoke::every_tool_refuses_an_unknown_argument` enumerates the served surface and holds both
  halves per tool, so a tool added later cannot opt out; the schema pass deliberately runs before any
  tool is called, since the one tool with no arguments of its own is the local-kernel attach. The
  refusal arrives as a tool result with `isError: true` rather than as JSON-RPC `-32602` — rmcp routes
  an argument fault there, which is the channel every other refusal here uses — and carries no
  structured error category. **It cost +1,955 B of model context** (103,321 → 105,276 across the same
  67 tools; the payload moves by the same amount), every byte of it one 29-byte keyword per schema:
  64 roots, two nested types, and 70 for `attach_kernel_local`, which also gains the `2020-12`
  declaration and loses rmcp's empty `properties`. The model ceiling moves 105,000 → 108,000 B;
  nothing else moved and no `outputSchema` changed. Turning it on broke four of this repository's own
  calls, which is the evidence the keys were doing nothing: `registers { "filter": "pc" }` in four
  places in the smoke suite, and an invented `timeout_ms` on `attach_kernel` in the Binary Ninja and
  Ghidra oracles and on `execute` in the Secure Kernel handoff probe.

- **`sk_symbol` refuses a qualified `name` rather than doubling it (the second shape of item 107).**
  That parameter is documented unqualified, because the module is the engine's spelling of the
  captured image and the tool applies it — but a lenient engine resolves
  `securekernel!securekernel!SkdInitDebuggerDataBlock` anyway, so the call answered `status: ok` with
  the right address, identifier fields byte-identical to the unqualified call, and a doubled name in
  `symbol`: the one field a caller quotes back. It is **refused rather than stripped**, and that is a
  decision about the surface rather than about one tool — telling a redundant qualifier from a foreign
  one needs the qualifier itself, which lives in the worker's capture, and `skci!Foo` is plainly
  foreign. `server::reject_module_qualifier` states the rule once, beside
  `reject_command_breakers`, for the next parameter whose module this server owns; the refusal happens
  before a session is looked for, like the `name`/`address` exclusivity check it sits next to.

- **The debugger tier's ARM64 half is one entry again, and it names an image rather than a moving label.** It was a pair -- `windows-11-arm` beside `windows-11-vs2026-arm` -- run side by side through the window GitHub announced for migrating the older label onto the Visual Studio 2026 ARM64 image, so that a break arriving with the new image would be attributable to the image rather than to the change under review. Nothing broke and the two converged: this workflow's own runs report `Image: windows-11-arm64` at 2026-09-23T06:22Z and `windows-11-vs2026-arm64` at 12:57Z the same day, then the new image on every run since -- eleven sampled over the following 47 hours, ending with both entries reporting `windows-11-vs2026-arm64`, `Version: 20260920.164.1` on the same run. Same image, same version, same inbox `dbgeng.dll`, which is the one thing that job exists to load, so the pair had stopped buying attribution and started buying a duplicate twenty-minute run on every PR. What survives is `windows-11-vs2026-arm` under the suffix `, arm64`: the **label pins the image and the name says which tier it is**, since carrying `vs2026` in a job name would rot one image later exactly as `windows-11-arm` did. The convention the pair established is now written where the next migration will be read -- add the new image as a second entry naming it in its suffix, keep both while they differ, drop the older when they do not. Checked rather than assumed: the repository ruleset requires `Build & test`, `Documentation lint` and `Smoke test (debugger tier)` and **neither ARM64 name**, so renaming one could not strand a required context on a job that will never report again. And the migration invalidated a measurement, which is the part worth carrying forward: issue #153's finding that `windows-11-arm`'s System32 ships no `symsrv.dll` is now about an image that label no longer names, and nobody has probed the new one. It cost nothing only because the symbol-half copy step was deliberately written to be independent of that answer -- a prediction made at the time, tested by this migration, and held. `docs/smoke-test.md` and `.claude/skills/live-kernel/SKILL.md` now say which image the probe was taken on rather than which label. `FOLLOWUPS.md` item 32, now in `DONE.md`.

### Fixed

- **A batch that could not certify its target told the caller their handle was safe, which it had no way to know.** The `BATCH: TARGET UNCERTAIN` headline said *"this session's handle is not being retired"* and then sent the caller to ask what the session holds -- but `debug_batch` reads `batch::retires_handle` over **every** step including `always` *before* anything runs, and the supervisor's pump retires the session at the front of its queue, so a batch that stops at step 2 with a `.opendump` waiting at step 4 has a retired handle and an unreached command, and the handle-bound query the report recommends would be refused. Raised by Codex on [#392](https://github.com/glslang/windbg-mcp/pull/392) after it had merged. The report is written in the worker, which cannot see the supervisor's session state at all, so the fix is to stop claiming and to name the one thing that answers: it now says to ask `session_status` whether the handle still answers, and why this report cannot. `structured::BatchOutcomeName::TargetUncertain` said the same thing to structured clients and says the same correction. **Third round on one question** -- who may claim what about a retirement -- after the interrupt refusal that claimed one two of its three causes do not do, and the report that claimed a retirement the replaced path does not reach; the pattern is a claim about the *supervisor's* state made from inside the worker, and the remedy each time is to state what the worker saw. **And two shipped prose sites used a wrapped `.opendump` as the example of a replacement**, which item 102 measured and disproved -- it adds a system and leaves the original current -- so `docs/debug-batch.md` and the plugin skill name the measured reproduction instead: a wrapped `.create`, whose change lands at the **`g`** after it, the command itself only arming the creation (*"Create will proceed with next execution"*). Raised by CodeRabbit on the same PR -- and the first version of that fix had the two halves the wrong way round in both files, which Codex caught on the follow-up: `docs/debug-batch.md` called the `g` the thing that arms it, and the plugin skill listed `.create` beside `.attach` as though either alone leaves the debugger somewhere else, which for an agent is worse than the example it replaced, since a wrapped `.create` as a batch's last step changes nothing and the expected stop never comes. Both now state the rule the reversal hid: the step a report names is the one the *change* happened at, not the one carrying the command. The same claim is repeated in about a dozen further places, including the sentence this server's one-worker-per-session shape is introduced with, and that is `FOLLOWUPS.md` item 105 rather than part of this change: it wants a per-target-kind measurement on a named engine build, not a rewrite. No tool description changes, no output schema changes and no golden moves -- both corrected sentences are rendered report text and stripped rustdoc.

- **A `debug_batch` ran its rollback against whatever target it ended up holding.** `batch::run` watched one thing between steps -- `done.target_gone` -- so a target that had been *replaced* rather than released read as an ordinary step: every remaining step ran against the replacement, and so did the `always` block, whose whole job is to put a mutation back. A restore applied to a target that never had the mutation writes into whatever that address means there, which on a live kernel is a write into somebody else's machine. Item 81's fingerprint retires the session's *handles* when an op ends holding a different target and does not stop a batch that is already running; nothing else was on the road either, `changes_debug_target` matching the first token of each `;`-separated segment and so seeing neither a `.if` nor an alias, and `retires_handle` retiring a handle rather than halting anything. Reached independently by Codex on [#389](https://github.com/glslang/windbg-mcp/pull/389) with the same remedy, which is what this is: `batch::Debuggee::replaced` is asked after **every** step -- including the last, which is the half that matters, a batch whose second act is its rollback having no later step for a top-of-loop check to catch it at -- and on a `Some` the batch stops as `BATCH: TARGET REPLACED`, lists the remaining steps as skipped, and **drops the `always` block**, each of its steps listed as skipped carrying the reason. From that point it issues no engine call at all: the rollback is not announced (that announcement exists to protect cleanup commands from a break, and there are none) and the state probe is not run, because `? @$ip` would answer perfectly well about the *replacement*; `session after` reads `DETACHED/REPLACED` naming the step instead. **The baseline is the batch's own**, taken before its first step (`worker::batch_baseline`), not the session's `OPENED_AS`: a call naming no `session_id` is deliberately served by whatever the worker now holds, so measuring against the session's would have refused to roll back every such batch for the life of the worker -- the same over-reach `refuse_when_the_target_was_replaced` was narrowed to avoid on #389, arrived at from the other direction. **`rollback_complete` stays and gains a disposition beside it**, `not_supplied`/`complete`/`incomplete`/`not_attempted`, because a bare `false` is now two pieces of news that send a caller to opposite places -- and because that flag is what `server::batch_settled` branches on to decide `isError`, so removing it would have moved that decision as a side effect of a reporting change. An `always` step that replaces the target stops the rest of the cleanup too, which is deliberately *not* the same news: the steps committed, so the outcome stands and the disposition is `incomplete`. **And measuring it disproved the item's own example.** Driven live against the dev build over stdio (dbgeng 10.0.26100.1742, ARM64, 2026-09-26), `.if (1) { .opendump C:\other.dmp }` replaces nothing: `||` afterwards lists two systems with the original still current, `? @$ip`, `version` and `lm` all still answer from it, and the fingerprint reads the current system -- so it *adds* a target, and switching to it is what would replace one (`||1s` through `ExecuteWide` fails here with `0x80040205`). What reproduces it end to end is a wrapped `.create` on a launched process, caught at the **`g`** rather than at the `.create`, the command only arming the creation: `TARGET REPLACED at step 3`, `rollback: NOT ATTEMPTED`, the cleanup skipped with its reason, and item 81's supervisor retirement firing at the end of the same op -- the two halves agreeing about one event. **Review found the reading itself too coarse, which is the part worth carrying forward.** `has_target` failing came back as `None` from a function returning `Option`, and the executor could not tell that from *nothing has changed* -- so a step that swapped the target while the engine went quiet would have had its cleanup run against the replacement anyway, and a batch whose *baseline* could not be read checked nothing for its whole length. Raised by Codex on [#392](https://github.com/glslang/windbg-mcp/pull/392), and it is dbgscope's own instruction from the other end, written on `has_target`: *"an unreadable status is not an answer, and this does not collapse one into `true`: what to do when the engine cannot be asked differs by caller, and each one below decides."* So the reading is a three-valued `batch::Held`; `Held::Unknown` withholds the cleanup under its own outcome, `BATCH: TARGET UNCERTAIN`, which claims no second target because none was identified; and a batch that cannot read a baseline before its first step is **refused outright** -- nothing run, nothing changed, resubmitting safe. The two halves of the mechanism now decide that reading differently on purpose: the handle half retires nothing on an engine that will not answer, and the batch withholds, because a wrong retirement costs a re-open and a wrong restore costs whatever that address means in somebody else's target. Mutation-verified, including a first claim about the mutation that was wrong: moving the check to the top of the loop fails **both** replacement tests rather than one, and differently -- the two-step batch commits with its restore written into the new target, the three-step batch stops at the wrong step and names `lm` as what took it. Collapsing `Held::Unknown` back into `Same` fails exactly the test that pins it, and with `Committed`. **A second round found the same hole one block along**: when the *last* `always` step is the one the target changes under, there is nothing left to mark skipped, so every cleanup step reads `Ok`, `rollback_complete` stayed true and `server::batch_settled` told the caller nothing was owed. That predicate now asks both halves — every step completed **and** the batch could still say what they ran against — and the rendering gained a line for a block where nought of the steps failed and the rollback is still not complete, since "0 of 1 step(s) did not complete" would send a reader looking for one that does not exist. The same round found the transcript rendering keying on `outcome == "target_replaced"` to spot a withheld cleanup, which is a list that grows with every outcome that learns to withhold one and had already fallen a round behind: `Event::Batch` carries the `rollback` disposition now, as an `Option` so a transcript written before it still reads as what it said — which also retires a second thing the flag could not say, a batch with **no** `always` block having completed one vacuously and read as `rollback complete` in a cast for as long as that line has existed, on a batch that undid nothing. The tool description owes two more sentences, so `debug_batch` goes 10,021 -> 10,507 model-visible bytes (+486, against an 11,200 ceiling) and its output schema 3,223 -> 3,566; the surface is 94,971 -> 95,457, one golden moves and the group tables in `src/toolset.rs`, `docs/tool-surface.md` and `docs/token-budget.md` move with it, four shares rounding differently. Those tables' *prose* totals were already 50 B behind before this change (94,921 against 94,971), which is what "prose is not swept" buys and costs. **One more window is closed and one is declined, and the difference is what the critical section would have to hold.** Asking the host whether a break is pending and then sealing the job were two transitions, so a break arriving between them was recorded, drained by the seal, and reported when the job was released -- beside a verdict decided before it. `Debuggee::sealing` answers both now, read under the lock that already seals and drains, adding no DbgEng call to that critical section. The window between the identity probe and the seal it may trigger is left open on purpose: closing it means holding the worker's interrupt lock across four DbgEng queries, so the request reader blocks on the engine thread -- the thing `AGENTS.md`'s single approved cross-thread exception exists to avoid -- and it would buy nothing, since that reading runs immediately after the call that changed the target and a break that could land in it could have landed a moment earlier inside that call, where nothing has observed anything yet. Strictly contained in a window that cannot be closed at all. **The promise lived in five places and a `head` hid two of them**: the sweep meant to be the enumeration was piped through `head`, which stopped at ten matches and cut off `src/server.rs` — so two later rounds arrived one copy at a time, the `always` field's own description (served in the *input* schema), the shipped plugin skill, and `GROUP_INSTRUCTIONS`, which is assembled separately from both and is budget-bound: a client truncates the instructions at 2,048 characters and they were at 2,003, so the exception fits as nineteen characters of qualifier ("on every path *it can be aimed at*") with the contract left to the tool's own description. **And the same false claim turned up one channel over**: the refusal an `interrupt` racing a stopped batch reads said "this session's handle is being retired with it", which is true when the target was replaced and false for the other two ways of losing it — so a caller could have thrown away a session that was about to come back usable. One seal reason covers three causes, so its message may claim only what all three share. **Six rounds asked one question — how soon does the batch find out — and what settled it was where the probe sits rather than how many places repeat it.** It began after the loop, moved to after each step, then to the detection point so the seal could be taken there, and finally to between a step's *action* and that step's own assertions: `Check::Eval` is engine calls, so a probe after them has its `? (…)` answered by the replacement and reported as this step's verdict, about a target the caller never named — and leaves the interrupt window open across them. `run_step` takes the reading and the seal and hands the reading back, so there is one probe per step rather than two and nothing between them; an engine-backed assertion on a step whose target changed is refused the way one on a step that *ended* the target already was. What is left is a change made inside a single engine call, which nothing in this process observes until that call returns -- the residual `refuse_a_break_for_a_replaced_target` already documents, and the bound. **And a moved selection is not a replacement**, which the first version of that check said it was: a replaced target retires this session's handle through the post-op fingerprint comparison, a moved selection leaves it good, and reporting the second as the first told a caller their session was finished when it was not. `BatchTarget::moved` answers a `Held` rather than a sentence, and `Held::Uncertain` now means *"cannot certify, and the session is not going away"* — the engine refusing to say, or the selection having moved — with the sentence saying which. The same round caught the seal still sitting a loop away from the detection that needed it (it is taken at detection now, in both blocks), and two model-facing promises the earlier sweep missed: the `always` field's own description, which is **served in the input schema**, and `skills/windbg-debugging/SKILL.md`, the shipped plugin skill, both still saying cleanup runs on every path. **Two more rounds were about what "the same target" means to something that *writes*.** The identity probe was the one call into the host outside `guarded`, so a panic in any of its four engine queries would unwind past the `always` block and the seal -- the rollback loss `guarded` exists to prevent, arriving through the check added to prevent a worse one; it answers `Held::Unknown` now, which withholds the cleanup and reports it. And the fingerprint is the wrong granularity for this caller: it carries the process **set** and deliberately not the selection, which is right for a handle and wrong for a batch, since `eb <addr>` writes into DbgEng's current process -- so on a session holding two user-mode processes a step that moved the selection would have had its restore applied in the other address space with the session holding exactly the target it always did. `worker::BatchTarget` is the batch's own baseline, and the line it stops at is worth stating: the current **thread** is not in it, because a thread moves at every stop and moving it is what a `resume` step is for. **And a batch that stops still has to close itself to breaks**, which the first version of this stopped doing: skipping the seal on the replaced path looked free, cleanup being what a seal protects and there being none — but what it left open is the *engine*, since `SetInterrupt` acts on whatever that is holding and the worker's own latch is not published until the op ends, so in between an `interrupt` passed `refuse_a_break_for_a_replaced_target` and reached somebody else's target. Raised by Codex on the same PR. The seal is unconditional now with its reason as an argument, and the refusal a caller reads says which of the two it is; deleting the `if` is the fix rather than adding a second call, since the call being conditional at all was the defect. One thing this **does not** close, and it is now `FOLLOWUPS.md` item 104: the fingerprint under it maps every query's error to `None`, which is also what a field holds when the question does not apply to that target kind — so two failures of one query compare equal and a recovery reads as a replacement. Raised by Codex on the same PR and half-closed here, a batch refusing to start against a reading with no `kind` (the field that decides which others are asked for); the rest needs a per-target-kind table of required fields, since DbgEng answers `E_UNEXPECTED` both to a question that does not apply and to one asked at the wrong time, and that table is the claim `TargetFingerprint`'s doc records as having been wrong three review rounds running. **The same reading, one field out, is closed rather than filed** — and it is the field this change added: the current process a batch measures its writes against was read with that same `.ok()`, so a refused query and a question that does not apply were one `None` again, two refusals compared equal, and a step that moved the selection between two held processes while the query was failing read as nothing having happened, which is the hazard `BatchTarget` was added for arriving through how `BatchTarget` was read. Raised by Codex against the rebased head. `worker::Selection` is three-valued — `NotAsked`/`Process`/`Refused` — a refused baseline will not start a batch, and one that arrives mid-batch answers *"would not say which process"* rather than the sentence for a selection that moved, which would be a claim about the target with no evidence for it. It is closable where the fingerprint's four fields are not because both obstructions are absent: whether the question applies is a **gate in the code** (`fingerprints_the_process`) rather than an inference from an `E_UNEXPECTED` that spells two things, and the refusal is narrowed to the only shape that can misdirect a write — a session holding more than one process — since one holding a single process has nowhere else for a write to land, so its refusal is accepted and costs nothing, which is also what keeps this affordable on a TTD trace, the one user-mode kind this bench cannot replay (#132). `FOLLOWUPS.md` item 102, now in `DONE.md`.

- **A command could replace the debug target without ever naming a command that does, and every handle to the old target went on reading as live.** `changes_debug_target` decides whether a raw `execute` retires its session's handles by matching the first token of each `;`-separated segment against a list -- `.opendump`, `.attach`, `.detach`, `q` and the rest -- and a wrapper says none of those: `.if (1) { .opendump C:\other.dmp }` presents `.if`, and so do `.foreach`, `.block`, `j`, `z` and an alias defined with `as`, which resolves at **execution** time, so no reading of the text before it runs can be complete. A breakpoint's command is the sharper case, because it runs at a **hit**, which is not a moment this server observes at all. Raised by Codex on [#341](https://github.com/glslang/windbg-mcp/pull/341) and reached independently by CodeRabbit on the same PR, both proposing the same remedy -- keep the text scan as the early defence, reconcile the target's identity afterwards -- and that is what this is. The engine process takes a **fingerprint** of what it is holding once the target is open and compares it after every op: `GetDebuggeeType`'s `(class, qualifier)` pair, the files the session is open on, and -- user-mode only -- the process it is on. A difference sends `WorkerMessage::TargetReplaced` *before* that op's `Done`, so the retirement is applied ahead of the answer reaching its caller and ahead of anything queued behind it; one pipe read in order is what makes "before" mean anything. It is the move `worker::pump_a_resume` already made for the running state, whose comment had said for months that a name list deciding this "would be wrong in both directions". **Both dbgscope queries were unreachable and one of them was unread**: `GetDebuggeeType` was called privately in two places with the qualifier discarded in both, and `GetNumberDumpFiles` nowhere -- so [dbgscope#188](https://github.com/glslang/dbgscope/pull/188) adds `DebuggeeType`, `debuggee_type()` and `dump_files()`, and the pin moves to it. **And the guard that reads `has_target` before any of them is load-bearing rather than tidy**, which the debugger tier said rather than anyone predicting: `GetNumberDumpFiles` on an engine with no debuggee is a `STATUS_ACCESS_VIOLATION` *inside* DbgEng -- a structured exception `catch_unwind` cannot trap -- so the first run of this change killed the engine worker on the two tests where a launched program runs to completion, reported as *the engine worker process holding session `sess-…` is gone*. `debuggee_type` in the same state answers `DEBUG_CLASS_UNINITIALIZED` without complaint, which is how two queries beside each other come to be read in one place; dbgscope guards `dump_files` now as well, and `examples/held_target_probe.rs` there is the record of what each query answers per target kind. The file list is not redundant with the other two: **two dumps of one process**, taken five minutes apart, share their class, their qualifier and their pid, and are the ordinary way a `.opendump` swap looks. The pid is the field that had to be left out of a *kernel* fingerprint -- there "the current process" is whatever the machine was running at the last break, so it moves across every `g` and would retire a live handle each time a kernel stopped somewhere else; the rule is its own function so it can be mutation-verified rather than inferred from a call site. And a target that has **gone** is deliberately not reported this way: there is no second target for a handle to wrongly certify, the ending is already carried by `StopReport::target_gone` and refused by `worker::refuse_when_the_target_is_gone` naming the same recovery -- and retiring on it would break the ordinary ending of a launched program, whose `continue_async` would have its session retired between the stop and the `wait_for_stop` that collects it. `set_breakpoint` still **refuses** a command the scan can see, which is the shape both reviewers proposed and is not redundant either: the backstop undoes at the next stop what refusing declines up front. What this does not do is make `changes_debug_target` complete, and the two assertions in `a_breakpoint_command_that_changes_the_target_is_refused` that pin its blind spot stay `!` for that reason -- the item's own closing instruction said to flip them, which was written for the *parser* option it also weighed. One message a caller sees moves: a retired handle no longer claims "the worker still holds a target", which was already untrue for `.detach`, `q` and `qd`. **In all three places that word it** -- `engine::stale_handle`, `server::describe_session` and the `SessionState::Retired` variant in `src/structured.rs`; the first was corrected and the other two were not until CodeRabbit pointed at the second, which is how a claim comes to be true in a changelog and false on the wire. No tool description changes and no golden moves. **Two P1s from review moved it**, both correct against the tree and both about *when* the fingerprint is consulted. A job is written into the worker's pipe as soon as it clears the session gate, without waiting for the job ahead of it to answer -- so a call already queued when the target is replaced is past every check the supervisor has, and retiring the handle afterwards cannot reach it; the worker now asks the same question **before** each op as well as after, with one `Watch` value deciding both ends. And the baseline was conditioned on the opener having *succeeded*, where `Sessions::open` deliberately answers `OpenError::PostCommit { report_only: true }` with a usable handle when only the follow-up diagnostic failed -- which would have left exactly those live sessions unwatched for good. It is read off the engine now, which the guard above already had to ask anyway. A third found that the worker-side refusal, keyed on the replacement alone, swallowed the **handle-less** flow with it: a retired session goes on serving calls that name no `session_id`, deliberately, and those would have been refused for the life of the worker -- so the refusal is now scoped to calls that named a handle, which is the only kind that was ever given a guarantee, and the supervisor tells the worker which it has (`WorkerRequest::handle_bound`). A fourth was the only regression this change *introduced* rather than a gap it failed to close: retiring the session at the stop made that stop uncollectible, because `wait_for_stop` resolved through the ordinary handle check — so a `continue_async` whose breakpoint command replaced the target lost the one result its caller most needed. `SessionState::accepts_execution_read` is a third widened predicate beside `accepts_default` and `accepts_teardown`, drawing the line at **reading a record** rather than at "an execution handle is involved" — `break_in` and `interrupt` reach the engine and stay refused — and needing no queue-side twin, since `wait_for_stop` submits no job. And a fifth turned the process half of the fingerprint from the **selection** into the **set**: DbgEng moves the current process by itself when a child process starts and by hand on `|Ns`, neither of which changes what the session is debugging, so `current_process_system_id` would have retired a live handle the first time the debugger pointed somewhere else -- permanently, with nobody having asked for anything. It reads `DebugEngine::session_processes` now (made public upstream for it), sorted and pids only, which still catches what the field is for, since the replacements in question change the *composition*: `.attach` and `.create` add a process and `.restart` swaps one for a new pid. Later rounds found the fingerprint blind to a whole target kind -- **every live kernel looks alike**, same class and qualifier with no files and no process set, so one swapped for another was invisible -- which `dbgscope`'s new `kernel_connection_options` closes, kept as a **hash** because a KDNET connection string carries the target machine's debug `key=` and the fingerprint derives `Debug`. That was the third round in a row to find a gap by naming one, so the answer was to stop and enumerate: `TargetFingerprint`'s doc now carries a row per opener saying which field identifies that kind of target, written as *what is covered* rather than as *what the gaps are*. And a handle-bound `interrupt`/`break_in` is refused after a replacement on its own path -- those are answered on the request reader, ahead of the engine thread, so neither the pre-op nor the post-op check was on their road and `SetInterrupt` would have stopped the replacement; the check reads the latch rather than the engine, since a second cross-thread DbgEng call is a design change rather than a local one. `FOLLOWUPS.md` item 81, now in `DONE.md`.

- **A run's identity block claimed more than its log said, in three places, because the grader worked out what a record contributes by testing the backend once per field.** `local_model_eval.identity()` had two such tests and they did not agree in shape -- a three-way `if/elif/else` covering `harness` and `reasoning`, and an unrelated inline ternary choosing `os_build` over `model_digest` for `weights` -- each added reactively, one per review round on the PR that introduced the third backend, each after a run had already reported something false: an fm run comparing across a macOS update as though the model had not moved (`09aa279`), and `think: false` on a backend with no reasoning arm printing `on, off` for a run in which every backend *with* the knob ran with it on (`faa147a`). Both were fixed; the shape that produced them was not, and it produced three more. Each driver now emits the resolved value under one agreed key: `IDENTITY_FIELDS` is the closed list (`weights`, `reasoning`, `harness`), each of `local_model_drive.py`, `claude_code_drive.py` and `fm_drive.py` has an `identity_block()` answering **all three** on every record -- `None` where the row has no answer -- and `identity()` reads that one key and tests no backend at all. Re-grading the six logs in `eval-out/` moved **only** the identity block, every cell score and `--matrix` distribution being byte-identical, and every line that moved was an overclaim: a mixed run's `harness 2.1.270 (Claude Code)` belonged to the Claude rows alone and now carries `, unavailable`; `reasoning unrecorded` on the pre-axis logs is `unavailable, unrecorded`, the Claude rows never having had an arm to record; and arm A of the reasoning A/B read `off` where it is `off, unavailable`, while arm B gains a `harness unavailable` line it had printed **not at all** -- so the one composition difference between the two arms, that arm A had Claude rows and arm B did not, was invisible in the field the A/B is about. `docs/eval-runs.json` is regenerated from the same logs. The old rendering had two spellings of "no answer" and chose between them per backend -- fm stated `reasoning unavailable` where claude-code, in the same position, contributed nothing -- which was itself the bug: two backend tests, a round apart, not agreeing. The dispatch survives in exactly one place, `legacy_identity()`, for records written before the drivers stated a block, and that function is closed by construction rather than by discipline: a record without the key predates it, so a new backend's records always carry the block and a new field is absent from every legacy record and correctly reads `unrecorded`. `tools/test_local_model_eval.py` is new -- twelve tests, run with `python3 -m unittest discover -s tools -p 'test_*.py'` -- and two of them are the ratchet: one fails when a name is added to `IDENTITY_FIELDS` that a driver has no opinion about, one when the grader defaults a field instead of saying so. Each is mutation-verified against the mutation it is for, and the two hold the seam from opposite sides: adding a field to `IDENTITY_FIELDS` fails the first on all three backends and leaves the second green, while making `stated()` read an absent key as `unavailable` fails the second and leaves the first green. Re-introducing the `faa147a` inference fails three of the twelve. `FOLLOWUPS.md` item 80, now in `DONE.md`.

### Documentation

- **A Hyper-V checkpoint handing over a guest's Secure Kernel is expected, and the one case that
  could have overturned that was measured rather than argued.** `FOLLOWUPS.md` item 103. The verdict
  rests on three things: the Windows SDK documents VTL selection in a capture as a feature
  (`ForceActiveVirtualTrustLevel` is commented *"useful to force register state to and virtual
  address translation to come from a different VTL"*), VBS claims a VTL0-to-VTL1 boundary **inside**
  the guest rather than one against the host — which gates H3 and H4 already demonstrated from the
  other side, reading the same pages out of a *running* guest — and every route needs Hyper-V
  Administrator, which can already read a live guest's RAM and attach a kernel debugger to it. So a
  capture lowers the setup cost for a principal already inside the boundary. Three cases would be
  reportable and none is asserted away. **S0 arm 4 ran the interesting one**: with
  `EncryptStateAndVmMigrationTraffic` on, no VTL1 comes out, on the VBS guest as well as on the
  VBS-off control — and it does not come out because `LoadSavedStateFile` never returns. The provider
  **fast-fails**: `0xC0000409` — the status every `__fastfail` raises, whose legacy name
  `STATUS_STACK_BUFFER_OVERRUN` is not a diagnosis — WER `BEX64`, faulting module
  `vmsavedstatedumpprovider.dll 10.0.26100.7705` at offset `0xD569`. A *fresh plaintext* capture of
  the same guest, read minutes later with the identical command, loads normally — which is what
  attributes the failure to the setting rather than to the capture being new, and is the whole rigour
  of the arm. So the mitigation holds and the verdict stands, **and the arm turned up a different
  defect worth reporting**: a documented SDK API crashing on an input Hyper-V itself wrote, which is
  a robustness and availability bug rather than a boundary bypass. Reported with a named cause, measured
  under this server's own debugger: subcode **`0x7 FAST_FAIL_FATAL_APP_EXIT`** — the CRT's `abort` —
  reached from `gsl::details::terminate` under
  `PartitionStateParser::GetPartitionStateVirtualProcessors`, so it is a Guidelines Support Library
  contract violation while parsing the partition state rather than a corruption check. Limits
  stated rather than glossed: the capture is unreadable *by this provider*, which is not the same as measured
  ciphertext, and the encrypted checkpoint was never applied, so Hyper-V reading what it wrote is an
  inference. Shielded VMs are untested. The third reportable case needs nobody's involvement and is
  true on this bench now: the checkpoint files inherit the data volume's ACL — `BUILTIN\Users:
  ReadAndExecute`, `Authenticated Users: Modify` — so any authenticated local user can read a file
  holding a guest's whole RAM, which is a storage-path hazard rather than a product defect. The lab
  was left as found: both settings reverted, the two pinned checkpoints intact, the three this work
  created removed, and the pinned VBS capture re-read afterwards to the same landmarks.

- **A walkthrough where the bug is somebody else's code**,
  `docs/provider-crash-walkthrough.md`. The other walkthroughs here debug a target and end in an
  answer; this one ends in a **report**, which needs different evidence — so it is about the evidence
  rather than about the crash. It deliberately does not re-teach the `__fastfail` decode
  `explorer-crash-walkthrough.md` already owns, and cites it instead. What it adds: a twelve-line
  checked-in repro; a control matrix that isolates the trigger by showing what does *not* crash
  (random, truncated and header-corrupted input all refused with `ERROR_FILE_CORRUPT`, so the parser
  has a rejection path and the encrypted case is not on it); a container-magic and entropy reading
  establishing the input is well-formed ciphertext rather than garbage — and the note that this is
  also what rescues the gate it came from, since a *successful* read on the owning host would have
  been authorized decryption and evidence of nothing; the subcode and stack from
  `launch`/`go`/`exception_triage`, naming a GSL contract violation; and an enumerated list of what
  the report refuses to claim. It records its own correction too: a first draft read `0xC0000409`'s
  legacy name as its meaning, in a repository that ships a decoder for that exact trap, and review
  caught it by citing `src/fault.rs` back at it.

- **The provider crash that arm 4 turned up is now a report that can be sent as it stands**, in
  `docs/secure-kernel/vmsavedstatedumpprovider-crash.md`, with
  `tools/vmsavedstate_load_probe.py` as a twelve-line repro that calls one export and names no VM.
  Writing it up moved three things the arm had left open. The repro crashes at the **same fault
  offset** `0xD569` from CPython as from this server's Rust binary — two processes on this host sharing
  nothing but the DLL, which is what makes the fault the provider's and deterministic rather than a
  property of either caller, and says nothing about other machines. The trigger is **specific**, and a control matrix is what says so: the same call
  *refuses* 4 MiB of random bytes, a truncated real capture, and one with its first 512 bytes zeroed,
  all three with a clean `0x80070570` (`ERROR_FILE_CORRUPT`) — so the parser has a rejection path and
  the encrypted case is simply not on it. And **"encrypted" is now a measurement** rather than
  Hyper-V's claim, which the arm's own caveat admitted it was not: the encrypted and plaintext
  captures share the container magic `14 20 28 01` and the field at `+0x08`, while payload entropy is
  **8.000** bits/byte against **7.246** — a well-formed container whose contents the provider has no
  key for, which is the case that should have produced a refusal. Reported as a crash and not as a
  memory-safety vulnerability: `0xC0000409` is the corruption check firing, and nothing here fed it a
  crafted capture. What remains untested is written down too — no crafted input, one SDK version and
  architecture, Shielded VMs and the `.bin`/`.vsv` pair untried, and `Apply-VMSnapshot` never run
  against the encrypted capture.

- **A guest's Secure Kernel is readable from a Hyper-V checkpoint, with no driver and nothing
  signed.** `FOLLOWUPS.md` item 103's first gate, S0, asked whether a driver-free memory source
  contains VTL1 pages -- a question about *how much setup a user needs*, since the live route H0-H4
  established needs test-signing off, Secure Boot off and a kernel driver loaded. It does, and the
  reader is Microsoft's own: `vmsavedstatedumpprovider.dll` from the Windows SDK, declared in
  `VmSavedStateDump.h`, which is VTL-aware by declaration (`GetGuestEnabledVirtualTrustLevels`,
  `ForceActiveVirtualTrustLevel`) and turns out to be VTL-aware in fact. A standard checkpoint of
  the running VBS guest reproduces **every** landmark the driver route measured on the same boot:
  VTL1 `CR3` `0x1201000` read back out of the capture, a PML4 self-mapping at index 388 with 26
  present entries and 123 non-zero bytes, 11,326 leaf pages from 166 table reads,
  `securekernel.exe` at GPA `0x00CD0000` identified against the on-disk image on 18 section names
  plus timestamp plus `SizeOfImage`, `KdDebuggerDataBlock` at `+0x1335E0` with `Size` `0x3A0`,
  `SkLoadedModuleList` at `+0x127770`, and the same six VTL1 modules. The **control** is the
  VBS-off twin, whose partition reports VTL0 only and refuses `ForceActiveVirtualTrustLevel(vp0, 1)`
  **by name** -- `VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED` -- while the same 32768-page physical
  scan finds more PE images than the VBS guest -- 143 against 101, and 100 against 86 on a
  second capture of the same boot, those counts being a reading of what was resident rather
  than a property -- and not one `KDBG` tag either time, so the scan demonstrably works there
  and simply finds no Secure Kernel. The capture was also copied out of
  Hyper-V's directory and read with no VM named, which makes it **a file rather than a channel**:
  capture on the host, analyse anywhere. And an older capture of the same guest **broke a landmark
  this work had believed** -- it carries VTL1 `CR3` `0x107593000` and SK based at
  `0xFFFFF8070EDA9000`, with the image-relative offsets and the GPA unchanged -- so the `CR3` is not
  reboot-stable, `docs/secure-kernel/README.md`'s "repeated across a reboot: yes" was a
  generalisation from two boots, and an implementation carrying `0x1201000` forward would have
  walked from the wrong root and not been told. That is the measured case for item 103's source
  contract, which requires the page-table root to come from the capture. The probe is
  `tools/sk_savedstate_probe.py`: it reads the `REGISTER_ID` enum out of the SDK header rather than
  hand-counting to `X64_RegisterCr3`, checks `CR0`/`CR4`/`EFER` for long-mode consistency so the
  register indexing is verified rather than assumed, judges a page-table root on all 4096 bytes
  rather than a 16-byte prefix, poisons what it cannot read with `0xAA` so a missing page cannot
  read as zeros, and guards the descent three ways -- skip an entry whose target is the table it
  came from, a visited set per level, and budgets on reads and leaves that *report* a truncation --
  because an unguarded walk of a self-mapping PML4 took this bench down twice. **Review moved
  three things and declined one remedy.** A large-page PDPTE or PDE carries the PAT flag in bit
  12 rather than the low bit of its frame, so masking at 4 KiB granularity lands a page high --
  latent here, since SK's VTL1 tables contain no large mapping on this build, and now held with
  the reserved-bit check in one `decode_entry` rather than spread across the descent. The older
  `.bin`/`.vsv` capture form is selected and loaded instead of being refused; the selection is
  pinned by a test and the provider call is unexercised, this bench producing only `.vmrs`. And
  a finding that the per-level visited set drops aliased prefixes *silently* was right about the
  silence and wrong about the fix: replacing it with path-based cycle cutting was built and
  measured, and on a recursively self-mapped tree -- 36 tables appearing at more than one level,
  one PD referenced 1023 times -- it exhausted a 200,000-leaf budget over 509 distinct pages and
  identified nothing, against 166 reads and a positive identification for the walk it replaced.
  So the guard stays and the omission is now counted: **6,773 alias prefixes** reported beside
  11,326 leaf mappings over 4,189 distinct pages. **A second round found the two remaining
  places the report collapsed several inputs into one answer**, which is the same shape as the
  alias: identification stopped at the first mapping that matched the disk image, where
  matching says the bytes *are* that image and not that this VA is the base it was loaded at --
  a duplicate mapping matches all three fields, and one is in the 2026-09-25 capture -- so every
  candidate is now tried until one carries a block whose `KernBase` names it, with the attempt
  reported for each; and one exception handler covered both the VTL1 switch and the register
  reads after it, so a provider that could not return one register would have reported `forced:
  false` beside a `cr3` it had already read -- the control arm's entire result is that
  distinction, and the two now have separate fields. Enumerating the report's other fields
  found no third case -- but a third round found two more in a place that enumeration had not
  looked: the **provider seam** rather than the report. An older provider rejecting one optional
  diagnostic took the VTL1 `CR3` down with it, because the queries shared one `try`; and the
  count-only `GetGuestPhysicalMemoryChunks` call had its HRESULT discarded, so a provider
  failure would have arrived as `memory_pages: 0` and `--scan-pages` would have turned it into
  a clean-looking negative. Both are fixed by enumerating every entry point into the DLL and
  putting each under one of four named contracts, written into the module docstring so a new
  call joins a row instead of getting a decision of its own: **fatal** (nothing downstream means
  anything without it), **diagnostic** (recorded per field by `probed()`, never fatal),
  **bulk** (never raises; returns a reason), and **sized** (a failure HRESULT is part of the
  protocol). That last one had to be measured rather than reasoned about: the sizing call
  answers `0x8007000E` by design with the count filled in, so the finding's literal remedy --
  check it -- would have rejected every healthy capture, and the rule is that a failure **with
  no count** propagates. Two tests hold that seam from opposite sides. **A fourth round landed on
  the same theme again, which was the signal the contract was prose rather than code**: the VTL0
  register block was a second copy of the VTL1 one that had never been made per-field, so a
  provider rejecting one VTL0 diagnostic still aborted before the VTL1 `CR3` was read; and both
  PE-header scans wrote `if reason: continue`, so a refused page arrived as a page with no image
  and an incomplete scan wore the shape of a clean negative -- under the **control arm**, whose
  entire result is that negative. Both VTLs are now read by one `read_vtl`, so there is no second
  copy to drift; `long_mode_consistent` answers *unknown* rather than *false* when a register is
  missing, since answering false would invert the control for the register indexing; each scan
  carries its own `unreadable` count; and `read()` counts every failure at the source in
  `reads.failed`, which no consumer can suppress -- a run reporting nothing found with a non-zero
  `reads.failed` is a run whose negative has not been earned. Measured on the captures taken here
  that number is **0**, so the control's zero is over 32,768 pages it actually read. Two more
  published figures become readings rather than properties: the PE-header counts span 86-101 and
  100-143 over three captures of one boot, and the walk's distinct leaf pages 4,189 and 4,194,
  while the 11,326 mappings and 166 table reads were identical every time. **A fifth round found
  four more, and the theme had moved**: from a failure reading as a result to prose asserting a
  property the code did not enforce. `walk_module_list`'s docstring said the first `DllBase` had
  to equal the independently identified base; the code only decoded, so a stale or coincidental
  pointer yielded plausible names and sizes instead of an error. It now returns `valid` and the
  candidate search takes it as the last word -- `KernBase` matching is necessary and was being
  treated as sufficient, and a rejected hit is recorded and the next one tried. Auditing every
  docstring in the file for invariants it claims found that one and no other. Beside it:
  `distinct_leaf_gpas` counted a 2 MiB leaf as one page where `leaf_pages` counted 512, and the
  obvious repair -- a set of every frame -- would allocate 262,144 entries per 1 GiB leaf against
  a 200,000-leaf budget, which is the memory explosion the walk's guards exist for, so the spans
  are merged instead; and `--apply-replay-log` mutates the `.vmrs` *after* its size and mtime
  were recorded, so the provenance described the input rather than the analysed bytes. That last
  one is also the round's own lesson about tests: the first attempt pinned `describe_file`, which
  was never where the defect was, and backing the re-stat out of `main` left it green -- so the
  ordering moved into `capture_provenance`, a function a test can drive. **A sixth round found
  one more, caused by the fifth**: with confirmation now able to reject every hit, the branch
  that handles "no candidate accepted" still wrote `hits: []`, so a run that found four `KDBG`
  tags and refused all four reported none -- and threw away the `confirmed`/`rejected_by`
  annotations that are the only thing distinguishing a coincidental tag from a stale module
  list. The tags now travel inside each candidate's attempt record, one home whether or not a
  candidate was accepted. **A seventh round found the `KDBG` half of the control scan searching
  page by page**, so a tag split across a 4 KiB boundary was invisible and one whose fields
  continued into the next page was rejected -- roughly 1.4% of placements, absent from a
  negative the control rests on, while the image-side search had read a contiguous buffer since
  the first commit. Pairing each page with its physical successor, and attributing a record to
  the page its header starts in so no pairing reports it twice, turned up a **fifth** tag on the
  2026-09-25 capture that no previous run could see -- another coincidental byte sequence, so
  the conclusion is unchanged and the control still finds none, but it is now a negative the
  search was capable of falsifying. A header at the end of the scanned range is counted in
  `boundary_incomplete` rather than dropped, and a chunk granularity other than 4 KiB is
  refused rather than strided over. **An eighth round found the last of that class**, exposed by
  the sixth's own change: `walk_module_list`'s unreadable-head exit reported under `error` while
  the caller reads `invalid_reason`, so a hit rejected for an unreadable list was retained with
  `rejected_by: null` -- a rejection indistinguishable from an unexplained one, in the field
  added two rounds earlier to explain rejections. Every exit now states `valid` and every
  failing one its reason in one field, across all four ways it can fail: unreadable head, empty
  list, unreadable first entry (which previously fell through to a confusing `DllBase 0x0`
  message), and a first `DllBase` that is not the identified base. **A ninth round asked for a
  list that never closes to be rejected outright, and that half is declined**: `valid` answers
  "is this the right block", which two independent structures agreeing on one address already
  settles, while closing cleanly answers "is this the whole enumeration". Conflating them would
  reject a genuine block and report *no debugger data block* for a capture that has one --
  the round-2 defect from the other side, and a build with more than the walk's entry limit of
  VTL1 modules would trigger it unaided. The finding's own second option is taken instead: a
  separate `complete`, with `incomplete_reason` naming which of the four ways it stopped --
  unreadable entry, entry limit, null forward link, or a walk that left the list. The declined
  remedy is pinned as a mutation, so applying it fails three tests. **A tenth round asked the
  physical scan to follow page tables, and that is declined on what the scan is**: it is the
  route defined as needing no `CR3`, which is why the VBS-off control -- whose VTL1 is refused
  outright, so there is no mapping to follow even in principle -- can run it at all, and making
  it virtual would delete the independence that makes it a cross-check of the walk rather than a
  second reading of it. The finding's second option is taken: the scan states in a `limitation`
  field, beside its counts, that it joins physically adjacent frames only. The exposure was then
  measured rather than left as a worry -- `securekernel.exe` spans 373 pages with **one**
  physical discontinuity, and the debugger data block sits at page 307 offset `0x5E0`, inside a
  frame with an adjacent successor -- and the image-side search, which reads by VA through the
  translator, has no such blind spot and is the authoritative one. **An eleventh round found the
  successor pairing reset at every chunk boundary**, so two chunks the provider reports
  separately but which are physically adjacent would have the last page of one flushed before
  the first page of the next could join it -- a split record missed at a boundary the stated
  limitation does not cover, those frames being adjacent. `pending` now lives across the chunk
  loop and the GPA-adjacency check, which was already there, is the only thing deciding
  join-or-flush. Measured on this bench the case does not arise -- the two chunks are
  `0x0..0xF8000000` and `0x100000000..0x108000000`, the PCI hole between them -- so no reported
  number moves; the structure no longer depends on that. **A twelfth round found the same
  counter one step short**: `boundary_incomplete` counted a complete four-byte tag whose fields
  were truncated, but a page ending in `K`, `KD` or `KDB` with no successor to join cannot be
  recognised at all, so nothing-found read as nothing-there at exactly the boundaries the
  counter exists for. A trailing prefix at an unpaired boundary is now counted, and the
  measured captures still report **0** of them with the control's zero tags intact. **A
  thirteenth round found the same shape in a module entry's name**: a `BaseDllName` whose
  buffer could not be read fell through to `""`, which reads as a loader entry with no name,
  and the enumeration could still be reported complete while omitting one. `read_module_name`
  now answers the name or `None` with the reason, naming the implausible cases -- a length above
  512, a null buffer -- rather than letting them reach the same empty string, and the list
  carries `names_unreadable` beside its entries. `complete` deliberately stays true when only a
  name is missing: every link was followed, and a name is an attribute rather than a link. The
  measured list still names all six modules with the count at 0. **Four findings were then
  found to have been missed rather than answered**: the review posts its comments over a minute
  or two and the watcher used here read the head on the *first* one to appear, so a second or
  third arriving later was never read — twenty-five comments against twenty-one worked. Of the
  four, one was already fixed and one partly so; the two that were live are now closed. The
  walk is gated on the **paging shape** rather than only on having a root, since its four
  levels, nine-bit indices and 48-bit canonical form would traverse any other mode with the
  wrong strides and invent or lose leaves instead of erroring — a non-`Long` mode or `CR4.LA57`
  now refuses by name, while a paging mode that could not be *read* does not block it, unknown
  not being wrong. And the walk answers `complete` in the module list's vocabulary, because
  `truncated` named a budget and a reader checking that one flag would have read a walk with an
  omitted subtree as whole. The third finding claimed `GuestVirtualAddressToPhysicalAddress`
  can succeed while reporting an unmapped span, which would have page 0's bytes read as a
  mapping: **measured false on this provider** — an unmapped VA fails outright with
  `0xC0370505` and a mapped one reports a span of zero, over five cases — and the check is in
  anyway, pinned by a fake provider, because the alternative is depending on that. **And
  CodeRabbit, rate-limited for this PR's whole life until now, ran once and found two** -- one
  of them a claim in this repository's own prose: `docs/secure-kernel/README.md` said every
  landmark in its table reproduces from a checkpoint, and one row is a measurement **of**
  `HvCallReadGpa`, which a capture involves no hypercall to perform. The row is marked *live
  route* and the sentence scoped to capture-derived landmarks. The other: `--image` was read
  after the capture had loaded and, with `--apply-replay-log`, after the `.vmrs` had been
  rewritten, so a typo raised `FileNotFoundError` rather than a refusal, discarded a report
  that already held the VTL1 `CR3`, and had mutated the one file this tool writes to before
  noticing. Inputs are resolved in one step that runs first and does nothing else. Codex added
  the register-level half of the paging gate: `GetPagingMode` is the provider's reading, and
  when `CR0.PG`/`PE`, `CR4.PAE` or `EFER.LMA` disagree with it the registers win, since a
  four-level walk of tables that are not four-level yields leaves rather than an error.
  **A fifteenth round found the worst defect of the set, and it was in the output path rather
  than anything the provider does**: `--json` naming one of the capture files truncated that
  saved state and wrote the report over it, destroying it -- under a module docstring whose
  first paragraph says nothing here writes to the capture. The output is now compared against
  every input before the analysis begins, by `samefile` where both exist and by the normcased
  absolute path where the output does not yet, and the docstring records that the sentence was
  once false. Beside it, a missing `--vmrs` or a stale path from `LocateSavedStateFiles` raised
  `FileNotFoundError` from `stat()` rather than a refusal -- the sibling of the `--image` case
  fixed the round before, which should have been found by enumerating the inputs then. And
  `complete` on the walk no longer reads as exhaustive: alias pruning is deliberate and happens
  on every capture, so rather than a flag that is never true, the walk states what it excludes
  with the count in the sentence. **A sixteenth round found that guard's own list incomplete**:
  it held the capture and the on-disk image and not the SDK header or provider, which are read
  early and closed and are therefore just as truncatable -- a function promising *every* input
  and given a subset, which is the shape it was written to fix. All four are in it now, and a
  test reads the labels back out of `main` so dropping any one of them fails. The same round
  caught a test of mine that would fail on a case-sensitive filesystem: an uppercase path names
  a different, nonexistent file there, and the assertion was ungated -- in the file whose
  offline discovery command this repository documents, edited from a Mac. No Rust and no MCP
  transport changed. The full record, both arms and what it does not establish, is the **S0 result**
  section of [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).

- **Secure Kernel: why the native route is dead, and what an EXDI route would actually cost.** The
  stub finding was re-derived from the retained `securekernel.exe` samples rather than recalled, and
  the routine was traced to its caller: `IumpDebugBreakRequestedByVtl0` is the handler for **secure
  call `0x124`**, reached from `IumInvokeSecureService` and `IumpInvokeLimitedModeSecureService` and
  from no other direct branch in the image. So **there is no `IumpDebugBreakRequestedByVtl1` to
  look for** -- VTL1 asking itself to break is not a secure call, and the absence is structural
  rather than a gap another build might fill. Its body is identical-COMDAT-folded with three
  unrelated routines, so a breakpoint on that address is ambiguous across four callers, which
  matters before anyone arms one live. Of the eleven `Kd`-prefixed symbols in each post-26100
  image **none is a function**, while `SkdInitDebuggerDataBlock` fills the block completely: SK
  ships the metadata a debugger keys off and no transport to deliver it. That split is what makes
  EXDI the interesting route and is written up as [`docs/exdi-stub-plan.md`](docs/secure-kernel/exdi-stub-plan.md),
  which Phase 4 of the Secure Kernel plan now defers to.

  **The EXDI reading is measured, including where it was first wrong.** `ExdiGdbSrv.dll` ships
  inside the WinDbg package, so a backend implements a **GDB stub rather than a COM server** and
  needs no LiveCloudKd dependency. `Kd=` turns out to select one of **six** kernel-discovery modes,
  of which `Kd=VerAddr:<addr>` takes an arbitrary `KdVersionBlock` address -- the mechanism a
  Secure Kernel bind would use. Three claims made from static reading did not survive being run,
  and each is corrected in place rather than quietly replaced: DbgEng does **not** self-register the
  EXDI COM server (a plain elevated `kd -kx` returns `0x80040154` and registers nothing); an `sk`
  record in DbgEng's memory-space table is **EXDI-gated and possibly vestigial**, its `hv`-vs-`sk`
  selector having no callers at all, so a hypervisor KD session cannot be steered to it; and
  `Endpoint::conflicts` treats `Endpoint::Unknown` as conflicting with **everything**, so an EXDI
  attach would be *refused* alongside any live kernel session rather than escaping the check -- the
  guard is over-conservative, not permissive, and it would break the two-session
  NT-plus-hypervisor workflow already in use.

  **And one attempt reset the bench, which the record says plainly.** `Inproc=`, which looks like a
  way to avoid registering, hung this workspace hard enough to need a reset; DbgEng warns about
  exactly that first, the far-end responder logged no connection so nothing reached the transport,
  and a 60-second kill on the child did not save the machine. A job object is the bound a retry
  needs. Nothing was left registered, no target was attached, and no BCD or host setting changed.
  The evidence bundle gains `secure-call-dispatch-29648.1000.txt` under `supplementary` in
  `images.json`; the six pre-existing `evidence_sha256` values were re-verified before it was added
  and all still match.

- **The WinDbg package ships two different `exdiConfigData.xml`, and the EXDI rig notes described
  one while citing the other.** Re-measured 2026-09-24 against
  `Microsoft.WinDbg_1.2606.22001.0_x64`: the copy beside the debugger binaries (sha256
  `ee64b9e18e6f6343`) carries targets Trace32, BMC-OpenOCD, QEMU, VMWare, BMC-SMM and UEFI, with
  `VMWare` as `targetArchitecture` **`X64`** — a 40-entry X64 register block plus a 40-entry x86
  one, `forceLegacyResumeStepCommands=yes`, `localhost:1234`. The `winext\` copy (sha256
  `983f9e9d014b7beb`) ends Trace32, BMC-OpenOCD, QEMU, VMWare, gdbserver, and its `VMWare` entry is
  **`X86`** with the x86 block only, no `forceLegacyResumeStepCommands`, `localhost:15360`. The
  claim that the preconfigured `VMWare` target is "already `X64`, 40 registers" therefore held for
  the top-level copy alone, while **this repo bundles the `winext\` one** —
  `target\release\winext\exdiConfigData.xml` is byte-identical to it — so taken as it ships that
  entry offers DbgEng a 32-bit register contract for a 64-bit guest. `heuristicScanSize=0xffe` and
  all seven memory-command flags `no` hold in both, and the `QEMU` entry is identical in both, its
  66-entry X64 block being 66 live `<Entry>` elements of 69 with three commented out. Which copy
  the engine loads when neither `EXDI_GDBSRV_XML_CONFIG_FILE` nor `PathToSrvCfgFiles` is set was
  not established. `docs/exdi-stub-plan.md` also gains **where each component runs**: the GDB stub
  belongs to the VMware host's `vmware-vmx` process rather than to the guest, so the guest's NAT
  address is a KDNET/WinRM address and never the debugger's endpoint, and `ExdiGdbSrv.dll` is a
  client that loads in the debugger process and may sit on a different machine.

- **Gate E2 has no reachable target on a Hyper-V-locked host, which is a stop condition the plan
  had not written.** Reported from the host 2026-09-25: VMware there runs on the Windows Hypervisor
  Platform because Hyper-V owns the box, so `vhv.enable` is unavailable, the Windows guest's
  `msinfo32` gives VBS as not enabled, and it cannot acquire VBS while Hyper-V stays on — which it
  must, the Hyper-V guests being the rest of the lab. No backend on that box both exposes a gdbstub
  and can host a VBS guest: Hyper-V hosts one and has no gdbstub, VMware has the gdbstub and no
  nested virtualisation to give, and QEMU meets the same wall through WHPX while its TCG mode
  implements no VMX/SVM for a guest hypervisor to use. The plan's existing stop conditions all
  assume E2 *ran*; this one fires a step earlier, so it is recorded beside them. **E0 and E1 are
  unaffected** — they need a plain NT guest, which that host still provides — and a second
  bare-metal Linux host restores E2 without moving the debugger, VMware Workstation there using its
  own kernel modules rather than the platform's hypervisor. Measured on this bench the same day:
  outbound TCP and DNS leave the Hyper-V NAT segment, so a debugger host behind that NAT can reach
  such a box, which is the opposite direction from the inbound path E0 itself needs.

- **The oracle was read from its own release, and what it needs for VTL1 is eleven functions and
  four values.** Static inspection 2026-09-25 of `v3.3.2.20260720` (zip sha256 `c8dff9409ad896ec…`),
  nothing registered or run. The server is `ExdiHvSrv.dll`, not the `ExdiKdSample.dll` the write-up
  names. It **registers exactly as `ExdiGdbSrv.dll` does** — identical exports, and `DllSurrogate`,
  `AppID`, `InprocServer32`, `ThreadingModel` in the binary — so E0's activation stall is a shared
  risk rather than a separate problem; its own installer script sweeps `dllhost` processes holding
  the DLL and says it derives from Microsoft's `WinDbg-Samples` script, which makes the
  surrogate-outlives-the-debugger behaviour upstream-known and the job object insufficient by
  design rather than by our error. It ships `hvmm.sys` signed `CN=Atheros Communications Inc.`,
  expired 2013, no timestamp, and Windows reports the certificate *explicitly revoked* — so it
  implies test signing or weakened code integrity on whichever host runs it, though
  `READ_MEMORY_METHOD`/`WRITE_MEMORY_METHOD` name `WinHv` beside `HvmmDrvInternal`, making the
  driver one of three pluggable backends rather than a requirement. **Why a VTL0 driver reaches
  VTL1 at all** is that the boundary crossed is partition-to-partition, not VTL-to-VTL: the tool
  runs in the root partition and reads a *guest's* memory, and VBS defends a guest's VTL1 from that
  guest's VTL0 rather than from its host — so no IUM trustlet is involved, and the technique
  reaches a guest's Secure Kernel and never the host's own. The public SDK is `SdkEnumPartitions`,
  `SdkSelectPartition`, `SdkCloseAllPartitions`, `SdkGetDefaultConfig`, `SdkGetData`,
  `SdkControlVmState` and four memory read/write entry points, with the secure-kernel-specific part
  being `InfoSecureKernelBase`, `InfoSecureKernelSize`, `InfoHvddGetCr3Securekernel` and
  `Cr3SecureKernel`. **That reopens the choice that produced the hardware problem**: the stub route
  exists to avoid implementing an EXDI COM interface, and that is what forces a gdbstub-exposing
  hypervisor, which Hyper-V is not. Recorded with two cautions rather than as a decided re-plan —
  `SdkControlVmState` pauses a VM and is not VTL1 stepping, the active CLSID's breakpoints are
  undemonstrated, EXDI's value here was DbgEng's SK awareness which E1 found EXDI-gated with an
  unreferenced selector, and the licence has not been checked.

- **E2 is reordered oracle-first, because an EXDI route into VTL1 is reported to exist already.**
  LiveCloudKd registers its own EXDI servers — `ExdiKdSample.dll`, CLSIDs
  `{53838F70-0936-44A9-AB4E-ABB568401508}` passive and `{67030926-1754-4FDA-9788-7F731CBDAE42}`
  active — **with no gdbstub in it at all**, and reports live read access to secure-kernel memory
  (windows-internals.com, read 2026-09-25). Read access is the solid claim; breakpoints and
  single-stepping are described there but not demonstrated, so the active mode is recorded as
  untested. The stub plan's exclusion of LiveCloudKd stands for what this server would **ship** and
  is now stated as not extending to what may be used to **answer a question**: E2 splits into E2a,
  the oracle, and E2b, the existing stub path, whose purpose becomes a shippable backend rather
  than the answer. A negative from the oracle would retire the stub programme rather than reorder
  it, which is why it goes first. Its constraints also decide the lab's shape — it runs on the
  Hyper-V host **of the target**, with the guest's VBS on and nested virtualisation off — so a
  debugger that is to drive it must be the machine hosting that target's hypervisor, which is the
  nested layout rather than the sibling one. And both routes ride the same dbgeng plumbing, so E2
  now says to check EXDI activation first: E0 found it stalling here, with registration writing an
  `AppID` whose `DllSurrogate` is empty and a bare `CreateInstance` blocking past 17 s having
  launched no surrogate. Whether `ExdiKdSample.dll` registers the same way is unestablished and
  cheap to read off its registration.

- **A VBS target was never what this hardware lacked — a gdbstub-backed one was.** The E2 entry
  above closed with "why the single-box arrangement cannot work", which overstates its own
  evidence and is the failure mode `.claude/skills/handoff` names: the tidy sentence at the end of
  an accurate paragraph. Hyper-V is the box's primary hypervisor, so
  `Set-VMProcessor -ExposeVirtualizationExtensions` on one of its own guests is the documented
  feature rather than the second-hypervisor-on-WHP case that defeats VMware there, and the
  validation record's sibling layout already writes that procedure down — the flag goes on the
  *target* VM, KDNET runs between it and the debugger, and the debugger host is asked for no
  nesting, memory or reboot. Separately, the deferred nested layout was recorded as adding "another
  virtualization layer whose suitability remains to be demonstrated": a published VTL1 write-up
  runs that shape, a Hyper-V guest as debugger passing Hyper-V through to a Windows 11 25H2 target
  inside it, so nesting depth is not the objection to either layout. **What neither supplies is a
  transport**, which is the whole of the gap: both give `securekernel` running with its NT side
  reachable over KDNET, neither exposes a gdbstub, and the native KD route into SK is dead. That
  write-up does not close it either — its setup section is deferred to a later post and its
  commands are ordinary kernel-debugger commands against `nt`.

- **The EXDI server registers as an out-of-process surrogate, so the job object that gate E0 relies
  on never contained it.** Run 2026-09-25: `regsvr32` writes the CLSID with `InprocServer32` and
  `ThreadingModel = Apartment` **and** an `AppID` (`ExdiTestServer1`) whose `DllSurrogate` is the
  empty string, which hosts the server in `dllhost.exe`. Across two bounded `kd` runs the surrogate
  had **svchost (RPCSS) as its parent**, not `kd`, so a job carrying
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` could not reach it and both runs left one alive after the
  job was torn down — E0 step 4 now says the harness needs the job *and* a sweep by `AppID`. Two
  more consequences of the same fact: the DLL cannot be registered where it ships, because
  `LoadLibraryExW` on the package copy returns error 5 under three flag sets (WindowsApps ACLs) and
  `regsvr32` then exits 3 having written nothing, visible only in the registry rather than the exit
  code; and `EXDI_GDBSRV_XML_CONFIG_FILE` cannot configure a surrogate at all, since RPCSS spawns
  it with the service's environment, leaving `PathToSrvCfgFiles` — which travels in the connection
  string — as the only one of the two that reaches it. Step 2 had presented them as equivalent.
  **The transport half of E0 did not pass**: against a minimal RSP responder on loopback the
  responder logged no connection at either 75 s or 60 s, the surrogate held no socket, and a bare
  `CreateInstance` reproduced the stall without `kd`, blocking past 17 s having launched no
  surrogate, with no DCOM `10010` logged in that window. What the run does pin is the register
  block the gate depends on — **66 entries, 608 bytes, 1216 hex characters** for a `g` reply, with
  `Size` decimal and `Order` hex in that file — matching the validation record independently. E0 is
  now written as two halves, the first of which needs no guest, and the step that would drop the
  surrogate for an in-process load is left untried on purpose: it is materially what `Inproc=`
  arranges, and that is what the 2026-09-22 host reset points at.
- **Secure Kernel is reachable from the root partition, measured gate by gate.** A falsifiable plan
  — H0 to H5, each gate with a pass condition, a control and a stop condition written before the
  work — establishes that **the hypervisor grants a parent a child's VTL1 registers and refuses it
  that child's VTL1 memory through `HvCallReadGpa`**, and that the refusal belongs to that one
  hypercall rather than to the root's access. `HvCallGetVpRegisters` at `TargetVtl=1` returns the
  guest's VTL1 `CR3`; that GPA holds Secure Kernel's PML4; walking SK's own page tables by a
  non-hypercall memory route reaches **`securekernel.exe`**, identified against the on-disk image on
  all 18 section names, timestamp and `SizeOfImage`, together with its `KdDebuggerDataBlock`
  (`+0x1335E0`, `Size` `0x3A0`) and `SkLoadedModuleList` (`+0x127770`), each found by a route that
  does not depend on the other and agreeing exactly. The memory refusal is `HV_STATUS_SUCCESS` with
  a per-access `ReadIntercept`, so a consumer checking only the status renders zeros for precisely
  the memory it exists to inspect — 4608 protected pages in the VBS guest against **0** in a VBS-off
  control, every protected run 2 MiB-aligned. Call codes were confirmed from `winhvr.sys`'s own
  wrappers on the bench build rather than from a header, which also showed `0x0054` to be
  `WriteGpa`: in this ABI read/write pairs are **adjacent** call codes, so an off-by-one mutates
  where it meant to inspect. H0 to H4 pass. **H5 is not started and its route is now decided —
  against the one this work set out to build.** Driving a live Secure Kernel target through
  DbgEng/EXDI is parked for two independent measured reasons: EXDI activation does not work on this
  bench and is unresolved, and DbgEng's own `sk` record is unreachable — only EXDI-referencing
  functions reach its table readers, **0 of 91** KD-transport strings appear in any function
  touching it, and its `hv`-vs-`sk` selector has no callers and its address is never taken. So a
  working EXDI would have supplied a generic memory target rather than Secure Kernel awareness, and
  H4 already supplies the memory. The reversal condition is written down as two things that must
  change together, so it stays checkable. **H2 passes on its second mechanism**: its cheap
  driver-free probe failed — and the Code Integrity policy that blocked it is not the one it looks
  like, which matters because acting on the obvious guess means disabling a protection that was not
  in the way — while the minimal root-partition driver it named as its own fallback reads a child
  partition's physical memory and carries every GPA measurement in H3 and H4. The six VTL1
  documents now live under
  [`docs/secure-kernel/`](docs/secure-kernel/README.md) with an index.

## [0.20.0] - 2026-09-24

### Added

- **The `heap_*` tools walk ARM64 processes.** They refused any processor but AMD64 (*"heap walking supports x64 targets only (machine 0xaa64)"*), which on an ARM64 debugger host is every target there is — native processes and x64 processes emulated there alike. They take both now, through [dbgscope#177](https://github.com/glslang/dbgscope/pull/177), and the pin moves to it. What they refuse on either machine is a **WoW64** process: under a 64-bit engine the PEB and `ntdll` a walk reads are the emulation layer's, so it would list those heaps as the program's and call the answer complete. No processor type says so at a WoW64 launch's first break, so it is read from `_TEB.WowTebOffset`; `a_wow64_process_is_refused_by_the_heap_tools_rather_than_walked` holds it, whichever worker the process lands on. `a_user_mode_heap_query_names_the_vs_shape_it_decoded_with` no longer stands down on ARM64, so the ARM64 runners' live tier walks a heap for the first time.

- **The `pool_*` tools walk ARM64 kernels.** They refused any processor but AMD64 (*"pool walking supports x64 targets only (machine 0xaa64)"*), the sibling of the `heap_*` gate above and all that was left of `FOLLOWUPS.md` item 96. They take both now, through [dbgscope#179](https://github.com/glslang/dbgscope/pull/179), and the pin moves to it. The gate was waiting on a **walk** rather than an argument, and the entry was explicit that matching structures answered the investigation and were "not a substitute for walking an ARM64 pool" — so one was walked, on 2026-09-23, against a live ARM64 kernel (26100, AArch64) over a serial link, which is a different bench from the x64 guest the rest of item 96 was measured on. Before touching the gate: that build's own `nt!ExpAddTagForBigPages` computes the big-page index 64 bits wide (`lsr x9,x21,#0xC` / `mul` / `eor x25,x8,x8,lsr #0x20`, then `add x8,x9,x8,lsl #5`, which also pins the `0x20` entry stride), and over the 17 in-use entries in the first 128 slots of the live `PoolBigPageTable` that hash lands on the entry's own slot **15/17** — the two others one and two slots on, their home slots now free, which is linear probing — where the truncating one lands on **none**; over 18 live LFH subsegments, `ceil(n/64)*8` matched the real bitmap **18/18**, `nt`'s count reproduced `BlockCount - FreeCount` **18/18**, and per slot `ContiguousBits` reproduced `FreeCount` exactly **18/18** against `AdjacentPairs` being wrong on 271 of 974 slots, 256 of them live blocks called free. Then the walk itself, run **both ways against the same guest**, sampling from `!pool`'s allocated rows and asking the walk about each: 59/59 and 7/7 allocated blocks agreed on the fixed decoder, against 37/59 and 4/7 on the revision then pinned, and in aggregate 7,055 allocated chunks against 6,238 over near-identical ground. What that run did **not** produce is a complete walk: every one ended `coverage: deadline_truncated`, at ~285s a query over 115200 baud — four runs at 285.0/285.1/285.2/285.4s, within 15s of the 300s default `WINDBG_MCP_CALL_TIMEOUT_SECS`. So the live tier's gate turned inside out rather than going away: `target_is_x64` and `NOT_X64_SKIP` are gone, `pool_walk_is_affordable` reads the transport out of the connection string, and the two pool tests skip a serial link **on cost** with `WINDBG_MCP_SMOKE_POOL_SLOW_LINK=1` to run them anyway — a transport nobody has measured counting as affordable on purpose, since the safe default is running a test that may be slow rather than skipping one silently. The four `pool_*` descriptions say "x64 or ARM64" now, which is why the goldens moved.

- **A connection profile could name a target and say nothing about it.** `profiles.json` and `WINDBG_MCP_PROFILE_<NAME>` mapped a name to a connection string, so nothing could record that an endpoint is a hypervisor rather than an NT kernel, or that two of them are two endpoints of the **same guest** -- the fact debugging a hypervisor alongside its root partition rests on, since those two sessions interact only through the guest underneath them and a mismatched pair reads as a bug for a long time. A profile's value may now be an object -- `{ "connection": …, "role": "windows"|"hypervisor", "guest": "<machine>", "note": … }` -- wherever the string was taken, the environment included: a connection string never starts with `{`, so every file and variable that predates this keeps its meaning. The claims reach the listing `attach_kernel {}` answers with (`ctf-vm; lab-hv (hypervisor, guest "lab"); lab-nt (windows, guest "lab", "root partition")`), the session's label, and -- as values -- a `profile` object on the open and on every `session_status` row. **`role` is checked and the rest are claims**, which is the line the item was filed doubting: `worker::kernel_target` already derives `nt` against `hv` from the engine's primary module, so a profile that says one and reaches the other has that claim **withdrawn** and the reason reported beside the profile, in both halves of the result -- not in `summary.limitation`, which is what a session cannot *do* rather than what its configuration got wrong, while `guest` and `note` are the operator's word and no debugger question can check them. Absent is **not** disagreement -- a fresh kernel attach can have nothing but `nt` in the inventory yet, and "this server could not tell" must not be reported as "your configuration is wrong" -- and a mismatch is said rather than refused, the session being open by the time there is anything to compare. A field this server cannot take costs **that field**: a bad `role`, a `guest` that is not a name, a `note` carrying a control character or a member it does not know is dropped with a note in the configuration report and the target still opens, where a malformed value used to fail the whole file and take every other profile with it. A `note` and a `guest` are both scrubbed at render rather than at parse, `KNOWN_SECRETS` being complete only once every profile has been admitted -- and `guest` needs it as much as the note does, which is not obvious: the name charset that validates it stops a connection string and a forged report line, and admits a bare KDNET key, since a key is dotted decimal. The text of every refusal is scrubbed too, since a refusal quotes the member name it is about and a member name is admitted by the same charset. Masking is by value, so an ordinary guest or member name is untouched. A `role` the attach **contradicts** is withdrawn from what the session reports rather than annotated, so a later `session_status` -- or another client -- cannot go on advertising it; both halves of every result render the claims from the one typed copy that withdrawal corrects, rather than from the session label, which is built at the open and never changes. And a connection is remembered as a secret when it is **read** rather than when it is admitted, so an entry the environment shadows still has its key masked in the complaints that quote the operator's own text. A field this server refused is reported by the profile that **resolves**, as `ignored` beside its claims and as a line in the text of both the open and `session_status` -- the notes are rendered only on the refusal paths, so a typo'd `role` was otherwise silently absent from an attach that looked entirely ordinary. And two spellings of one name that reach the **same** target but describe it differently have that field **dropped** rather than settled as whichever was read first, held as an absorbing `Claim` so a third spelling cannot bring a contradicted field back -- the file becomes a `BTreeMap`, so `-` sorts before `_`, and a `guest` nothing vouches for is the failure the field exists to prevent; the profile stays dialable, since which target was meant was never in doubt, and one spelling saying less than the other is not a disagreement. It costs the model **nothing** -- `modelVisible` is 94,879 B before and after -- since the facts travel in `outputSchema`, which never reaches it; seven tools' output schemas grew 2,529 B of wire between them, which is why `tests/golden/tool_budget.json` moved. **Exercised end to end against the hypervisor lab on 2026-09-22** -- the listing naming the pair, the withdrawal of a wrong `role` surviving into a later `session_status`, two spellings dropping the field they disagree about, and a malformed entry costing itself alone -- which turned up the one thing to know before describing a file: **the compatibility runs one way.** A server built before this refuses a described file *whole*, plain-string entries included, since its parser required every value to be a string; measured on `0.19.0+gb22a2583`, which answered `No profiles are configured on this host.` The window is exactly v0.6.0, where profiles arrived, to v0.19.0 -- older servers ignore the file entirely, which is why the plugin snapshot on this bench is unaffected -- so it bites two servers in that range sharing one file, and `docs/kernel-profiles.md` now says so with the way out. `FOLLOWUPS.md` item 95.

- **A breakpoint could be armed on a live kernel and not listed or removed, on any surface without `execute`.** `set_breakpoint` is in the `exec` group and `execute` is in `inspect`, so a client served `session,exec` -- which is how a small-context model is given execution control -- could patch an `int 3` into a hypervisor or a live kernel and had no typed way to find it again, let alone take it off. `breakpoints` answers what the session holds, as the same records `set_breakpoint` reports one of; `clear_breakpoints` removes them by `ids` or `all: true`, refusing a call that names **neither** rather than reading an omitted field as "everything". Each removal is reported on its own: `removed` is what the engine confirmed it took, `not_removed` the ids whose removal failed with the engine's reason for each, and `remaining` is what is left -- **`null`** rather than empty where that listing could not be read, because after clearing everything an empty list is the success state and the two must not collapse into one value. A call whose every named id failed is an error; one that removed some of them is not, since the engine reuses the ids of removed breakpoints and a retry by id can reach a different breakpoint. An explicitly empty `ids` asked for nothing and is neither. `ids` names breakpoints rather than operations, so duplicates are removed before anything is attempted and each id is tried once. And a failed removal is **not** read as a breakpoint left armed: an id that names nothing fails exactly like one the engine refused, so `still_set` on each row answers that from the inventory taken afterwards -- `null` where it could not be read -- and only `true` is the `int 3` to act on before a detach. `ids` is capped at 256 per call and the cap is a **refusal**, not a clamp: each id is one request to the engine — a packet to the target on a live kernel — and a call that outruns its caller is not cancelled, while a removal silently truncated is a caller told a target is clean while it is armed. It costs no capability, since `all: true` reads its ids from the session's own inventory. They cost 2,214 B of model context, which is why both ceilings in `tests/mcp_smoke.rs` moved and say so. dbgscope needed no change: `breakpoints()` and `remove_breakpoint()` have been there since its typed breakpoint API. Filed [`FOLLOWUPS.md` item 94](FOLLOWUPS.md) for the half deliberately left out -- `bd`/`be` has no consumer and `execute` still reaches it.

- **A live-kernel detach can now be checked from outside the debugger, and was.** `end_session` answers `released: true` and `target_left_running: true` from the debugger's own side of the wire, which a hypervisor target did on 2026-09-20 while its guest was frozen. `examples/kernel_detach_regression.ps1` reads the guest's boot identity and uptime over WinRM around the test and, crucially, **proves the target was halted at all**: a background probe knocks on its WinRM port every 50 ms and the run fails unless it was refused on *consecutive* knocks spanning half a second, because one refusal is a network blip and without the control a run where the attach never landed passes trivially. Measured against a disposable four-processor NT guest (build 26100, DbgEng `10.0.29617.1000`): two pool-walk cycles held it unreachable for 209 consecutive samples over 117.7 s and 212 over 119.5 s, and it resumed on the same boot after each; three shorter detach-only cycles agreed. The probe's resolution is part of the result -- an unanswered knock costs its timeout, so a warm detach-only run's few hundred milliseconds of halt is under it, and the script says so rather than passing on a single sample. That is the NT half of [dbgscope #173](https://github.com/glslang/dbgscope/issues/173)'s shared `qd` validation -- the teardown branches on `is_live_kernel()` rather than on which kernel, so NT takes the same `clear_all_breakpoints` then `qd` path the hypervisor does. It does not generalise beyond that guest, engine and transport, and says nothing about `FOLLOWUPS.md` item 93's four-processor hypervisor question.

### Fixed

- **A user heap walk called reserved address space a hole in its own coverage, so every healthy live process came back `partial`.** The tails of subsegments and page ranges -- address space the allocator reserved and never committed -- read exactly the way a paged-out page does, and *would not read* was the only thing the walk could observe. A signal that fires on everything says nothing, so this cost the tools the one signal they have for *we could not see something*. Three states hide behind one failed read: no pages behind it (nothing was missed), committed and paged out or absent from a dump (a real gap), and committed and present (not a gap at all). The allocator's own records answer only the first split, and from three structures that each move between builds -- a page range descriptor's `CommittedPageCount`, a VS subsegment's `CommitBitmap`, and an LFH subsegment's commit state at `CommitStateOffset`, which the item that filed this did not know about and which is needed because `CommittedPageCount` reads **1** for a 33-page LFH range with two committed pages. The **memory manager** answers all of it in one call and answers about the target rather than about what one allocator believes, so [dbgscope#183](https://github.com/glslang/dbgscope/pull/183) adds `DebugEngine::virtual_region` (`IDebugDataSpaces2::QueryVirtual`) and a `PoolState::Uncommitted` beside `Unreadable`, with `is_coverage_gap` the single definition of which one costs a walk its `complete`; the pin moves to it. **Only a positive `MEM_RESERVE`/`MEM_FREE` excuses a gap** -- a failed query, a run that cannot advance, a state the crate does not name and a source that cannot be asked are each conservative, so the excuse is never granted by an absence of evidence -- and **a kernel session is not asked at all**, `QueryVirtual` being a user-mode question, so the `pool_*` tools classify exactly as before and go on counting every span they could not read. One thing there does change, and it is the silent site rather than the classification: `walk_vs` now names the chunks it drops. Measured on a live 26100 kernel (`ctf-vm`, 2026-09-24, 633,665 chunks walked) that is a new diagnostic shape with **2,768** occurrences — incompleteness that was always there and always cleared `complete`, with nothing in the answer saying so, which is why `diagnostics_emitted` on a kernel walk rises. A second mechanism was holding the same walks short and the item had not named it: a free chunk whose middle the allocator decommitted runs past the committed extent it starts in, and `walk_vs` emitted no span for it and cleared `complete` **silently**. A span is geometry and state, both known there, so where the tail is confirmed to hold nothing the chunk is now reported, and where it is not -- memory the process has, or memory nothing could be asked about -- it is still refused, with the walk naming the chunk it dropped. Measured through dbgscope's new `examples/heap_coverage.rs`, which puts every gap a walk filed back to the memory manager with an allocated and a free chunk as controls: `sihost` live on 26200 (four Segment Heaps, 20,426 chunks) went from `partial` with 45--47 unreadable gaps to **`complete`** with 33 uncommitted gaps of 0x3fd0a0 bytes, every one `MEM_RESERVE` and both controls `MEM_COMMIT`; a `.dump /ma` of `RuntimeBroker` the same way, 22 gaps of 0x335000 bytes. And the case this must **not** sweep up was checked from the other end, on a thin dump of that same process: an address whose page the dump does not carry still answers `Committed`, reading it still fails `0x8007001E`, and the walk still counts it. `heap_*` results gain `uncommitted_gaps` beside `unreadable_gaps` and an `uncommitted` chunk state on the wire, which is why the goldens and the surface figures moved (+14 B of model context). `FOLLOWUPS.md` item 98, now in `DONE.md`.

- **Every big-pool allocation was reported with a tag read out of the caller's own data.** `ExAllocatePoolWithTag` sends anything that will not fit inside a page to `ExpAllocateBigPool`, which records the tag and length in `nt!PoolBigPageTable` **instead of** in a `_POOL_HEADER`. Nothing in the page range descriptor separates one from a plain page-range allocation -- both are `RangeFlags` `0x03` -- so the walker decoded the page as though a header were there, reading the caller's first sixteen bytes as `PreviousSize`/`BlockSize`/`PoolType`/`PoolTag` and reporting the block as starting 0x10 in and 0x10 short. Measured on a live 26100.33438 kernel: `!pool` calls `ffffac09dd0f5000` a 0x1000-byte `CM25` allocation and the walk called it a 4080-byte block at `+0x10` tagged `..N.`, those being the bytes of a registry hive bin's own `hbin` header; where they happened to be zero the tag came out `0x00000000`, which is how this presented -- as tens of thousands of untagged allocations. Two more defects in the same lookup went with it, both read out of `nt` rather than inferred: bit 0 of `Va` is `POOL_BIG_TABLE_ENTRY_FREE` and the address stays behind it (`ExpRemoveTagForBigPages` frees with `lock inc qword ptr [rax]`), so matching on `Va & !1` answered for freed pool with the tag it used to have -- **2,300** of that kernel's 32,768 slots were in that state -- while `nt`'s own comparison is `cmp rcx,rdi`; and the probe's stop test for `Va == 0` never fired, a never-used slot reading `1`, so every miss scanned all 32,768 entries. The fix is [dbgscope#180](https://github.com/glslang/dbgscope/pull/180) and the pin moves to it. Measured on `ctf-vm` (26100.33438, 12h uptime), the same census minutes apart: distinct tags **5,665 -> 1,501**, the `....` bulk 79,166,848 -> 51,216,352 bytes, and `CM25` (19.0 MB), `CM16`, `EtwB`, `Gpbm`, `Obtb`, `ClfI`, `CM29`, `DxgK` and `Pool` -- the big-page table's own 1 MB allocation -- correctly tagged where they had been scattered across bogus tags, one of which was `0x838bffff`, the top half of a kernel pointer. The live-kernel tier now puts every `large page allocation` line `!pool` prints back to the walk, sampled from the engine rather than from `pool_find_tag` for the reason that half of `FOLLOWUPS.md` item 96 was invisible for months. And the same tag was lost a second way, which item 99 had filed as probably a different fault and which is the same one: `nt` puts big-pool allocations inside **VS subsegments** too, where the page range descriptor says `0x0f`. What separates them is the *size*, structurally rather than by measurement -- `_POOL_HEADER.BlockSize` is eight bits of sixteen-byte units, so `0xff * 16` is the most it can describe and an allocation needing a page has nowhere to record its own length, which is why all 7,639 live entries recorded `NumberOfBytes` of `0x1000` or more. A chunk past that limit is matched against the table by containment and length ([dbgscope#181](https://github.com/glslang/dbgscope/pull/181)), which assumes nothing about the 0x10 between a VS chunk's header and its data that is measured and not yet explained -- now `FOLLOWUPS.md` item 101. Measured two hours later against a pool that had itself grown 5%: the `....` bulk fell again to 42,785,104 bytes and `0xffffac09da29f000` matched `!pool` exactly, `MiRr` and 57,792 bytes. `FOLLOWUPS.md` item 99, now in `DONE.md`.

- **The heap tools reported the wrong LFH blocks as allocated — on x64 as much as on ARM64.** `dbgscope` read an LFH subsegment's block bitmap as two adjacent bits per block, and `ntdll` packs 32 blocks to a 64-bit word with the busy bits in its low half. Measured on a live 62-block subsegment, `heap_allocations` reported fifteen busy blocks, eight of which were free, and missed nine that were busy. Running the walker on ARM64 for the first time, against the target's own `HeapWalk`, found that and three more, none of them ARM64's: a segment list walked one entry past its 8-aligned head, every free range in a segment's free-page tree dropped for a signature its tree links overwrite, and the VS free tree walked from each chunk's encoded header instead of its node. A walk of `user_heap_smoke`'s heap now matches `HeapWalk` block for block with no diagnostics, where it had twelve. The pool tools share the last three fixes and keep their LFH reading, which is not `nt`'s either — `FOLLOWUPS.md` item 96.

- **`heap_list` saw one heap in processes that have several, and called the answer complete.** The heap tools took their roots from the PEB's `ProcessHeaps`. On current Windows that array names the process heap and nothing else: `ntdll!RtlpProcessHeapsInsert` writes it for the first heap only, and links every heap onto a list in `ntdll`'s data, which is what `GetProcessHeaps` walks. So a `HeapCreate` return value was never a root. Measured 2026-09-22 on a live ARM64 26100.1 process holding three heaps, among them the one it had just created, against a PEB naming one. Also measured on this repo's two x64 26200 user dumps, whose list head links two entries against a PEB naming one. **The fix is [dbgscope#176](https://github.com/glslang/dbgscope/pull/176)**, and the pin moves to it here. Roots now come from that list, in its order, reached through the process heap's typed `UserContext`. Every entry is checked against the heap it names. An entry that fails ends the walk as unseen rather than absent: the walk reports `partial`, and a diagnostic names the entry. A build that keeps no list gets the PEB answer as before. `heap_list`'s description and text header no longer say "PEB", and each listed heap's `index` is now its position in the list. The user-mode `layout.fingerprint` moves on builds carrying `UserContext`, because the schema now reads it. No pool fingerprint moves. `FOLLOWUPS.md` item 79.

- **A warning is a red build now.** CI's clippy step runs `cargo clippy --all-targets -- -D warnings`, and the two it had been printing under every run -- `rmcp::model::ServerInfo`, deprecated in favour of `ServerConfig` because the old name collides with the protocol's own `serverInfo` field -- are gone: both are aliases of `InitializeResult`, so the swap is a rename. The cost is taken deliberately and is named at the step: the toolchain is `stable`, so a lint added by a future release can fail the job with nothing changed here, and the answer then is to fix the lint or `#[allow]` it with a reason at the site rather than weaken the flag. `AGENTS.md`, `CLAUDE.md` and the dependency rule now quote the flag too, since a local run without it passes over exactly what the job will fail on.

- **A clock nudge read as a reboot in both detach regressions.** `Read-GuestHealth` compared the guest's `LastBootUpTime` ticks for **equality** across a cycle, and that value is derived rather than fixed: measured on the hypervisor lab, it drifted **333 microseconds across ten hours with no reboot**, which the comparison would report as *"The guest rebooted; this is not a successful detach"* against a detach that worked. Both scripts now allow two seconds, which no reboot can fit inside -- a guest that has restarted cannot answer WinRM for tens of seconds afterwards and its new boot time is a whole uptime away -- so the tolerance separates the two cases completely rather than trading one error for the other. Checked both ways: the measured 3,330-tick drift is admitted, a 30-second move is refused.

- **A kernel attach left break-ins owing, and the teardown paid one with the target's only continue.** `DEBUG_ENGOPT_INITIAL_BREAK` leaves a pending host break-in; dbgscope's `absorb_initial_break_artifact` consumes exactly one, which is right for NT and one short on a Microsoft hypervisor. Nothing in the attach's result shows the leftover -- the session looks ordinary -- and `end_session` then spends it: `qd` sends one `DbgKdContinue`, the pending break-in takes it, and the target stops again with **no debugger attached**. The guest is frozen while this server reports `released: true` and `target_left_running: true`, which is [`FOLLOWUPS.md` item 93](FOLLOWUPS.md)'s whole shape. Measured on a one-vCPU lab, plain attach and detach: frozen **2 of 2** before, healthy **5 of 5** after, each confirmed by WinRM showing the same boot and advancing uptime; NT is unaffected, checked by two pool-walk cycles against a four-processor guest. Two readings pinned the cause, the first ruling out the obvious answer: stepping past the hypervisor's own `int 3` before detaching does *not* help, so it is not where the instruction pointer sits; and the first `go` after a completed attach returns at once with DbgEng's CTRL+BREAK banner while every later one runs to its bound.

  **The fix is [dbgscope#174](https://github.com/glslang/dbgscope/pull/174), not this server**, and the pin moves to it here. `quit_and_detach_target` spends the leftovers between `clear_all_breakpoints` and `qd` -- resuming with a 500 ms bound until **two consecutive** resumes run free, one free run being no evidence since a break-in merely slow to arrive reads the same way. That placement is the whole of it: the clear has succeeded, so no breakpoint remains for a resume to stop at and be mistaken for the break-in it is hunting, and the quit has not yet spent the target's one continue. It first lived here, where neither neighbour was guaranteed, and every review finding it drew was another consequence of that distance -- a teardown path it missed, an interrupt it could not tell from a free resume, an ordering against the clear, and the clear's own retry racing it. Both of this server's teardown paths now get it by construction, since both reach it through `end_session`.

  What stays here is the **seal**: an `end_session` is closed to interrupts by the same lock that claims it, the way a `debug_batch`'s rollback already was. A resume cut short by a host's interrupt is indistinguishable from one that found nothing pending, so a client interrupting its own teardown could end that drain early and hand the leftover straight back to `qd`. Sealing at the claim rather than inside the op leaves no window: a break is either raised before the job exists, binding to nothing, or refused with an answer written for a teardown rather than the rollback's -- whose advice is to run `end_session`, which there is what is already running. The worker's abrupt-exit grace also grows to 8s, since a live-kernel release now resumes up to five times before it quits and a wait expiring mid-drain would leave exactly the halted target that grace exists to prevent.

- **A breakpoint in code every processor runs owes a stop to each of the others, which is what froze the four-processor lab.** Item 93's guest was rebuilt with four virtual processors and the mechanism measured directly on 2026-09-21: a `run_to_address` that returned `verdict: hit` with an **empty** breakpoint inventory left **three** further stops behind it -- processors 2, 3 and 1 where the hit was reported on 0, each a first-chance `0x80000003` at the breakpoint's own address, each on that processor's own stack, delivered one per resume in 1-3 ms, after which the target ran free. The others reach the patched instruction before the debugger removes it. `qd` has one `DbgKdContinue` to spend, the first queued stop takes it, and the target stops again with no debugger attached -- the frozen guest reported as a clean release, in **2 of 4** runs, because it races the quit. One processor owes nothing, which is why every one-vCPU run of the same sequence was clean and why the earlier drain validation could not see this. The remedy is one attach and one detach *in this server* -- a plain `attach_kernel` finds the target stopped at the breakpoint's own address and `end_session` spends what is owed -- which replaces "a separately authorised native-KD connection" for this freeze; it worked twice, same boot, no reset. The fix itself is [dbgscope#175](https://github.com/glslang/dbgscope/pull/175), where the teardown drain stops asking how the session was opened (the gate left it unrun on exactly the `experimental_break_on_connect` attach a running hypervisor needs) and sizes its attempts from `GetNumberProcessors` rather than the fixed five that fitted four processors by coincidence. **20 of 20** four-processor cycles then detached cleanly, each with an independent WinRM boot-identity and advancing-uptime check, against 2 of 4 freezing with the drain backed out on the same guest and boot. Ten of those were a local `[patch]` and ten the merged pin, of which five answered as `0.19.0+g1ac1abc0` from a clean tree -- a measurement being a reading of the binary that answered rather than of the checkout beside it. `examples/hypervisor_detach_regression.ps1`'s one-vCPU refusal is now `-AllowMultiprocessor`, and names the recovery route. [`DONE.md` item 93](DONE.md).

- **The hypervisor tier's broader test called a tool that did not exist.** It asked for `breakpoints`, passed `address` where `set_breakpoint` takes `expression` -- refused outright, since those arguments deny unknown fields -- and attached on the default path, which has nothing to break into on a hypervisor that is running. All three are why the 2026-09-20 demonstrations were driven by a temporary uncommitted harness reading `bl` text, and why the one thing 0.19.0 led with had no committed regression. The test now uses the two tools above, takes its attach shape from `WINDBG_MCP_SMOKE_HYPERVISOR_BREAK_ON_CONNECT`, and carries the breakpoint-hit half -- a return address read off the stopped processor's stack, checked to be inside the `hv` image this session attached to, run to, and asserted `hit` with an empty inventory afterwards -- behind `WINDBG_MCP_SMOKE_HYPERVISOR_BREAKPOINT_HIT`. That gate is opt-in because it halts somebody's hypervisor and, on a multiprocessor guest, leaves a stop owing per other processor (below). `examples/hypervisor_detach_regression.ps1` gained `-Session`, `-BreakpointHit`, and a refusal to pass the latter to a multiprocessor guest without `-AllowMultiprocessor` -- read over WinRM before **every** cycle, since a VM's processor count changes with a restart.

## [0.19.0] - 2026-09-20

### Fixed

- Remote-kernel cleanup now reconciles late confirmed releases and does not preserve returned
  pre-commit attach failures. Preserved orphan workers no longer hold the MCP client's stderr
  open. Live-test cleanup requires an explicit successful release without recovery being required.
- Preserved remote-kernel open failures report `recovery_required` and unknown target ownership,
  without ordinary timeout advice promising later usability or automatic termination. An orphan
  also observes a confirmed end of ownership that arrives after supervisor loss.

- **A switch the walk could not follow was the one incompleteness the report did not count.** `reachable_from_dispatch` named four ways a `NOT REACHABLE` can be short of the graph -- a halt, a work bound, bytes that would not read, and the jump-table resolver's own caps -- and computed a fifth without reporting it. The walk records where it ended at an indirect jump the tables said nothing about, which is what decides whether resolving is worth an engine round trip at all; the *final* walk's copy was discarded. So a walk that ran the resolver over a dispatch switch and got nothing back carried no signal in either channel, and the report printed **"Bound hit: no -- the reachable call graph was fully explored"** over a graph missing that switch's every case. Those jumps are now counted, per **site** rather than per function -- a routine entered at two boundaries is walked twice and the two walks overlap, so summing them reports one switch as two -- and the count withholds the "fully explored" claim exactly as the blind-instruction count already does, names the remedies **per case** -- for a jump table that would not read, a specific handler VA as `from` and, on a live kernel, a module refresh first, a table's entries being checked against the image's executable ranges; for a destination computed at run time, a breakpoint, nothing static reaching one -- and travels as `unresolved_jumps` in the typed answer. It does not say which case a jump is, that being the analysis that did not answer: the resolver reports per listing, and per site it has targets or nothing. It is deliberately one count for three causes: a table read and not recovered, an instruction set whose operands this build does not decode, and a listing in no loaded module all leave the graph short of the same edges, and no caller can act on the difference. The sentence says *whatever they reach* rather than *a switch*, which a real target settled: on the ARM64 kernel dump ordinary `nt` routines end at indirect jumps that are tail calls through a register -- 11 of them on `nt!ObpLookupObjectName` inside 24 explored functions -- so the dispatch switch is the case this was filed for rather than the only thing counted. The one thing it does **not** count is the probe: the walk runs each function once with no tables to decide whether to resolve, and a path proved on that pass never offered its jumps to a resolver -- counting those would have reported every `REACHABLE` found inside a dispatch routine as one that met a switch it could not follow. `FOLLOWUPS.md` item 89.

- **A resolver cap threw away the edges it had already proved.** `reachable_from_dispatch` resolves a listing's switch tables in one pass, so a `from` scoped past a large dispatch switch into a handler holding a switch of its own still pays for the dispatch's literal pool and tables -- and when those spent `MAX_POOL_READS`, `MAX_CASES`, `MAX_TABLES` or `MAX_TABLE_ENTRIES`, every target was discarded, taking the handler's own resolvable switch with it. That made the tool's advice to scope `from` past a dispatch no escape from a resolver bound. A capped pass now hands over the targets it recovered and reports `bounded` beside them, which is what it already meant: each retained case was recorded from settled facts, and each cap shortens the answer rather than skewing it -- three of them stop a list growing, `MAX_TABLE_ENTRIES` refuses a whole table rather than shortening one, and `MAX_POOL_READS` leaves later literals unfolded, which makes the facts *weaker* so the table resolver refuses rather than invents. A cap is also deterministic, so the retry that would recover those edges does not exist. The other two ways the pass can be partial still contribute nothing, and for different reasons: a **halt** is the caller's rather than the routine's, and the poll that saw an interrupt consumed it, so more edges there mean more functions enqueued and more engine round trips after somebody asked it to stop; while a pass whose facts never **settled** has nothing to hand over at all, a bound being left only on a branch's outgoing edge and that arm clearing every block's entry facts before the table is read. The report's advice is unchanged and still carries its condition -- a handler holding a switch of its own still pays this routine's tables, and a cap can still cost it edges. `FOLLOWUPS.md` item 90.

- **A64 spells a constant it cannot encode as a PC-relative load, and `ioctl_map` never read one.** No single A64 instruction can materialise an arbitrary 32-bit constant, so a compiler emits `movz`/`movk` -- folded since #343 -- or `ldr w20,<pool>`, which reads four bytes of the image the fact walk did not look at. MSVC prefers the second, being one instruction against two. Measured on the live ARM64 target over seven drivers and 235 recovered control codes: **0** carried a proven size and **not one** case reported `accepted: false`, both from the same unread bytes. `rdyboost!SmdDispatchDeviceControl+0x1b8` is `ldr w20,<pool>` / `b <epilogue>` with `0xc000000d` in the pool, so `error_status` found a memory operand where it wanted a constant; and it reaches the **codes** rather than only the evidence, HEVD's dispatch comparing against a pool entry that is itself a control code. The pool is resolved **once, before the walk**, rather than read inside it: the walk sweeps to settle each block's facts and then records from them, and a literal visible only to the recording pass would produce a case the sweeps never admitted. So each readable literal load becomes the immediate it stands for and every existing consumer -- `source_value`, `scalar_of`, `status_after` -- folds it through the arm it already had. Gated two ways, because the operand's shape proves neither: on the **target**, since the identical operand is a *global read* on x86 and x64; and on the address's **storage class**, since a base-less `ldr` can legally name writable module memory and folding that would publish whatever the driver last wrote there as a control code. The second is readable-and-not-writable image storage -- `.text` and `.rdata` -- and deliberately not the executable-sections predicate a jump-table entry has to satisfy, a pool being data. `ldrsw` and eight-byte literals are excluded for value reasons, and the caller's own reader bounds every address to the module. `FOLLOWUPS.md` item 82.

- **`reachable_from_dispatch` and `ioctl_map` disagreed about the same driver.** Since #345 the map resolves A64 switch tables and the reachability walk did not, so the map named a handler the walk called NOT REACHABLE -- with the tool's own advice being to pass that handler's address by hand to scope past the switch. The walk now crosses a table through `ioctl::jump_targets`, which runs the map's own walk and returns what its tables select, so a target the walk admits is one `ioctl_map` publishes and neither tool can contradict the other. Every bound comes with it, and a table that does not resolve contributes no edges -- the walk ends at the jump exactly as before, which is what keeps REACHABLE sound and leaves NOT REACHABLE the best-effort verdict it already was. The path recipe follows the same edges, because a verdict the recipe cannot reconstruct is rendered as a segment with *no conditions at all* presented as the complete set of them -- the defect its `Flow::Call` arm already records. Two rules the review rounds added, both about an address the walk did not compute itself. A **discovered** edge -- a call target, a tail jump, or now a table slot -- is entered at its own address or dropped: one that is not an instruction boundary used to widen to the containing function's entry and explore code no execution reaches, which is the single direction a REACHABLE verdict may not be wrong in. And the resolver's module lookup **propagates** a failed enumeration instead of reading it as a target with no modules -- the second degrades correctly, ending the walk at each indirect jump as it did before, while the first left every switch unresolved and the report saying the graph had been fully explored. And a table slot going to the switch's **default** is an edge although it is not a case -- `Map::cases` is a list of codes, and exporting it unchanged as a list of edges inherited an exclusion that was never about control flow, so a walk beginning past the bounds check (which carries the indices the switch *refused*) could not reach the default block at all. `FOLLOWUPS.md` item 83.

- **A correct map the server's own schema refused.** `#[serde(skip_serializing_if = "Vec::is_empty")]` and `#[serde(default)]` are read by different crates and nothing makes them agree: serde omits the key, `schemars` marks it required. Five fields across three of `ioctl_map`'s output types carried the first and neither of the others, so a dispatch routine that is a pure compare chain -- no tables, nothing unresolved, no length checks on a case -- produced a result that a client validating `structuredContent` against the `outputSchema` this same server handed it rejected **whole**, not by the field. Measured on HEVD over a live ARM64 kernel: 29 correctly recovered control codes thrown away as `data must have required property 'tables', … 'unresolved', … 'evidence'`. `AccessEntry::rights` and `DeviceSecurity::links` are the same defect two tools away, found by enumerating the class rather than by tripping over them. The guard is a scan of `structured.rs`'s own source (`a_field_serde_may_skip_is_never_required_by_the_schema`), because runtime cannot answer it: a skipped field is *absent*, and no value proves that some other value would not have skipped it. A client that cached `tools/list` before this still holds the schema requiring those keys and still rejects the result -- a reconnect is the fix, and nothing in the server can push one. #345.

- **A64 folds the compare into the branch, and a dispatch chain written that way read as empty.** `cbz`/`cbnz` are a `cmp` and a `b.eq` in one instruction -- `condition: None`, `writes_flags: false`, and they *are* the block's terminator -- so nothing in the loop over a block's body ever saw them and the branch had no flags to read. A `sub w9,w9,w10` / `cbz w9,handler` chain, the ARM64 spelling of the `sub ecx,222003h` / `je` this module cites HEVD for, came back `cases=[] proved=true unresolved=0`: no case, not even an unresolved transfer, and `code_proved: true` over an empty list -- which reads as a driver that accepts no control codes, the answer this whole module is arranged against. `folded_compare` derives the comparison from the terminator by asking `compare` through a `cmp reg,#0` probe rather than rebuilding it, so the width guard, the shifted-index rule and the `Value::Code` arithmetic are the ones every other compare gets. `tbz`/`tbnz` are deliberately **not** cases -- one bit of a `ULONG` is a statement about part of a value, which is what `test ecx,3` / `je` gets on x86 -- and land in `untracked` along with any conditional branch over a register holding the code that this cannot read, so the next A64 form to appear shortens the list visibly instead of silently. Underneath both: A64's arithmetic is three-operand and `Effect::Subtract`, `Add` and `ShiftRight` read it as x86's destructive two-operand form, taking the amount from operand one and the source from the destination -- so on `sub w9,w8,w10` the arm matched nothing and cleared the register, which is how the chain lost the code before ever reaching the `cbz`. Every chain the test for it first used was `sub w9,w9,w10`, where the destination *is* the source and either reading gives the same answer: the accident that hid the bug, reproduced inside its own test, and named by the mutation coming back MISSED. #344.

- **`set_breakpoint` took a `command` it did not have, and answered `ok`.** `EngineOp::SetBreakpoint` has carried a command since dbgscope#126 and `ioctl_trace` uses it, but `BreakpointArgs` had no such field -- and serde drops an unknown field silently, so a caller asking for a breakpoint that logs and continues got one that **stops**, with `"status":"ok"` back. On a live kernel that halts the machine and leaves it halted. It had already manufactured evidence for a defect that did not exist: three attempts to set `command` through this tool produced three stopping breakpoints and a merged PR concluding that `gc` does not resume under this server, when none of those breakpoints carried a command at all. The field is passed through now, and deliberately *not* screened the way the location is -- the engine takes it through `SetCommand`, where nothing is parsed, and a command is the one argument whose whole purpose is to be debugger text, so refusing `;` or `"` would reject the documented `.printf …; gc` form `ioctl_trace` itself uses. The struct refuses unknown fields instead -- the second tool-argument struct to do so, beside `DebugBatchArgs` -- on that struct's own criterion: every other tool's typo costs a wrong answer, this one's costs the target. What it *is* screened for is a command that **changes** the target -- `.opendump`, `.attach`, `.detach`, `.kill`, `.restart`, `q`/`qd`/`qq` and their neighbours -- which `execute` allows and this refuses, the difference being *when* it runs: `execute` knows the command is about to run and retires the handle first, while a breakpoint's command runs at hit time, which may be never, may be minutes later, and is not a moment this server observes, so there is no point at which it could stop every outstanding handle reading as live over a replaced target. The screen splits on `;`, `\r` and `\n` outside quotes, a line break ending the command and any quote open inside it, so `.echo "banner\r\n.kill"` cannot carry one past it. The same hole through raw text -- `execute` with `bp nt!Foo ".detach"` -- is untouched and has been open all along, since finding it there means parsing `bp`'s own quoted argument rather than reading a field. #341.

- **The IRP a dispatch routine was entered with is not always in `@rdx`.** `ioctl_trace` and `irp_stack` both read the `PIRP` from `@rdx`, hardcoded in the **supervisor** -- which holds no engine and so cannot know what the target is. That is the x64 calling convention's answer to where the second argument of `DRIVER_DISPATCH(PDEVICE_OBJECT, PIRP)` lives, and it is wrong everywhere else. On ARM64 it does not read a wrong value, it halts the machine: `? @rdx` fails with `An unexpected exception was raised (0x80040205)`, so the trace's `.printf …; gc` dies at its **first** statement and the trailing `gc` never runs. Confirmed by arming exactly the old command on `nt!IofCallDriver` over the live ARM64 kernel -- the breakpoint hits and the target stays halted, while `ioctl_trace` had answered `"status":"ok"`. The choice moves to the worker, where the engine can be asked: `@rdx` on x64 and `@x1` on ARM64, both measured against a routine carrying the dispatch's own signature (`x1` the IRP, `poi(@x1+0xb8)` its current `_IO_STACK_LOCATION`); `poi(@esp+8)` on x86, derived from the documented `__stdcall` frame and **unmeasured**, this bench serving no 32-bit kernel; and a refusal naming the machine for anything else. `ioctl_trace` refuses x86 outright, because it dereferences the IRP at fixed 64-bit offsets and a 32-bit `_IRP`/`_IO_STACK_LOCATION` would read the wrong words and print a plausible control code; `irp_stack` does not have to, handing the address to `!irp`, which knows the layout itself -- and it takes an `irp` now, for an address that came from somewhere other than the dispatch entry. #340.

- **A 1 MiB read was the one operation in this worker that could outlast every clock.** `read_memory` allows a mebibyte in one call, and until dbgscope#95 that was a single `ReadVirtual` with nothing between its start and its return -- over a KD link, the one operation that could outrun both the caller's clock and the deadline a `debug_batch` advertises to its teardown, which is the difference between a patch restored and a live kernel left patched and halted. `OVERRUN_ALLOWANCE`'s doc presumed every operation a step can start is armed with at least the watchdog floor; one was not. `EngineOp::ReadMemory` carries a `patience_ms` now -- floored the way a command's is, because zero is no bound rather than a small one -- and `BatchEngine::read_memory` passes the step's own budget, as its `command` and `pool` steps do. A read that stops short **says so**: `structured::MemoryRead` gains `stopped: Option<WalkHalt>`, since `read_size` cannot say whether the bytes ran out for want of time or because the caller asked and the next move differs, and the text half names where the dump stops -- without which a short dump reads as a short *range*, and a caller decoding a structure takes its tail from bytes that were never fetched. The doctrine goes with it: the question to ask of a new op is not whether it runs an `Execute` but whether anything can stop the call underneath it. And the budget is sized from what the caller's clock has **left** rather than from the queue wait alone, which is a class rather than a site -- `SetBreakpoint` has had the same shape since it began resolving eagerly -- pinned by a source scan, because both quantities are a `Duration`, both are plausible at every site, and the two numbers agree on any host where the work before the bound is fast. #332.

### Added

- **The ARM64 second opinion is diffed rather than read out of two documents by hand.** `tools/binja_oracle/` diffs `ioctl_map` against the [`binja-windbg-mcp`](https://github.com/glslang/binja-windbg-mcp) companion, by code and by route, exiting non-zero when they diverge -- which is what `tools/ghidra_oracle/` does for x64 and what nothing did for ARM64. It is two halves on the machines that can run them: `oracle.py` replays a companion capture and takes this server's answer over stdio, locally on Windows or through `ssh` from a Mac, in about eight seconds a driver; `capture.py` makes the captures, because Binary Ninja **Personal has no headless API** -- it starts the real GUI in a disposable `BN_USER_DIRECTORY` with a generated plugin, the mechanism `tools/bn_followup_probe.py` already used, whose process-group handling it imports rather than copies. Three differences would otherwise be reported as disagreement and each is handled where it can be seen: the **build**, compared as `timestamp`+`size`+PDB before anything else and stopping the lane when it differs; the **case address convention**, the companion naming the first source-mapped statement and this walk the block the branch enters, paired inside a stated forward window rather than a constant fitted to whichever value lines the most records up; and the **default-rejection table slots**, which the companion publishes and this walk drops, accounted for by `entries` minus `followed`, a count this side already gives, so no arm has to be guessed to be the default. `--selftest` pins all three against the cases where the lane must still fail. Capturing needed three things the plan did not have: the NT types declared in the probe with every offset checked against the live kernel, the entry **register** typed as well as the prototype -- `__security_push_cookie` preserves the argument registers without being declared to, so the typed parameter dies at the first call and a table fill still reads `*(x0 + 0x70) = ...` -- and the recovered `MajorFunction[14]` checked against the live driver object's, so a mistyped variable is a refusal rather than a published reading. Measured 2026-09-20 against `0.18.0+g30c4af94` and the live ARM64 target: HEVD agrees outright (29 codes, every route `+0x18`), `mountmgr` agrees once recaptured (24 codes, 48 routes, and its 45 surplus records are exactly the 45 table slots dropped here) -- and the published agreement for that driver turns out to have been between **two different builds**, the capture's `timestamp 2826447139`/`0x21000` against the target's `1169727331`/`0x22000`, both calling themselves `10.0.26100.1`. `rdyboost` **differs**: two codes only the companion has, at exactly the two sites `ioctl_map` reports in `untracked`, which the target resolves to an A64 conditional-compare chain neither implementation reads. `FOLLOWUPS.md` item 85, and item 92 for the chain.

- **Microsoft hypervisor debugging, through the `attach_kernel` that was already there.** Point it at a profile for the **hypervisor's** KDNET endpoint and the existing DbgEng kernel transport handles it: no EXDI backend, no second attach tool, no Secure Kernel debug setting -- and what is debugged is the Microsoft hypervisor, not the NT kernel and not VTL1. The attach summary says which it got in `kernel_target`, inferred from the engine's **primary module**: `nt` is `windows`, `hv` is `hypervisor`, and anything else is *absent* rather than guessed, as it is for a user-mode target and for a kernel whose module inventory names neither. A hypervisor target also carries a `limitation` -- NT process, driver, object and pool inspection do not apply here; symbols may be unavailable, so image identity and module-relative addresses are what to work in; and **stopping this hypervisor pauses the guests it runs**. That is a *field* on the summary rather than a sentence in the rendered text, because a structured-aware client forwards `structuredContent` and drops the text block, so a limitation stated only in prose is one half the clients never see (`FOLLOWUPS.md` item 43). Beside it, opt-in and default false, `attach_kernel.experimental_break_on_connect` asks for **one** break on DbgEng's English connection announcement, with no `INITIAL_BREAK` and none of the default attach's additional resume -- a separate typed attach in the worker rather than a flag threaded through the ordinary one, and refused unless the connection is KDNET (`net:`), the announcement being the whole mechanism. It is text-dependent and for a known-running disposable lab: not a readiness guarantee, and the **default attach path is unchanged**, that one having previously left a guest unusable. Three detach-only MCP cycles passed independent guest-health checks on the measured build. The live tier is opt-in, gated on `WINDBG_MCP_SMOKE_HYPERVISOR_PROFILE` and `#[ignore]`d because it halts a hypervisor (`a_live_hypervisor_detaches_at_the_initial_break`, `a_live_hypervisor_announcement_attach_detaches_at_the_first_stop`), and it is paired with `examples/hypervisor_detach_regression.ps1`, which checks guest identity, a stable boot time and advancing uptime after **each** cycle -- because "the debugger reported a successful resume and detach" is exactly what the first probe said over a guest that was unresponsive. [`docs/hypervisor-debugging.md`](docs/hypervisor-debugging.md) is the runbook and keeps the failed experiments beside the passing ones. #350.

- **The hypervisor demonstrations, including the one that failed its health check.** On a **one-vCPU** lab (2026-09-20, server `0.18.0+g0ae56496`, DbgEng `10.0.29617.1000`, hypervisor 29671, no hypervisor symbols) the server ran an end-to-end session: `modules`, `registers`, `read_memory` and `disassemble` against the `hv` image, a `step_into` from `hv+0x404a60` to `hv+0x404a61`, a breakpoint set and removed by its id with `bl` confirming an empty inventory, a `run_to_address` answering `verdict: hit` at the stack-derived `hv+0x312024`, and an `end_session` reporting `released: true` and `target_left_running: true`. The postcondition is **independent** rather than the debugger's own word: WinRM uptime `219.67` s before the attach against `221.41` and `223.77` after the detach, the same boot identity throughout and the endpoint free. On the **four-processor** lab the same operations reached a real breakpoint hit and the run **failed** its post-detach guest health check -- WinRM unreachable, a frozen console confirmed by the owner, and recovery needing a separately authorized connection to release further stops. That is `FOLLOWUPS.md` item 93 and [#355](https://github.com/glslang/windbg-mcp/issues/355): further processor stops arrive after a successful breakpoint removal and a reported detach, delivery order does not settle whether they were raised before or after the resume, and neither a fixed number of continues nor explicit per-processor resumes is a validated remedy. One vCPU is **not** established as the cause -- the topology change came with a restart, and the earlier run had other differences. Two investigation records land with them. [`docs/hypervisor-detach-trace.md`](docs/hypervisor-detach-trace.md): the teardown **does** send a continue packet and the hypervisor acknowledges it, while the guest stays unavailable until additional stops are released -- which is what moved the hypothesis to repeated break-in stops rather than an omitted continue. And [`docs/dbgeng-exit-report.md`](docs/dbgeng-exit-report.md), a Microsoft report **draft that is not submitted**, on accepted `DEBUG_INTERRUPT_EXIT` requests that do not unwind a KDNET `WaitForEvent`: 150 EXIT calls all returning `S_OK` with no wait return before a 100-second external deadline, reproduced without dbgscope on `10.0.29617.1000` and on `10.0.26100.1`. #350, #356.

- **The Secure Kernel debugger investigation, recorded where its evidence can be audited.** `docs/secure-kernel-debugging-plan.md` carries the chronological experiments, the corrections and the gate the work is currently behind; `docs/secure-kernel-debugging-validation.md` carries the record -- a traced BCDEdit rejection, a target hypervisor launch, a captured VTL1 buffer-allocation failure and the successful reservation that followed it, a bounded session-path trace, a successful loader configuration, SK stub inspection, NT query dispatch, and an exact-image build comparison -- with sanitized offline disassembly for six SK images, image and evidence hashes and structured measurement summaries beside them under `docs/samples/secure-kernel-debugger-investigation/`, pinned to LF bytes so those hashes survive a cross-platform checkout. `tools/secure_kernel_preflight.ps1` is the read-only package/engine preflight the investigation was driven with. **Native VTL1 attachment remains unsuccessful**, and the routines inspected support a scoped implementation-stub hypothesis rather than a universal claim about Windows support. The operator's boundary is part of the record: the hardened outer host must not be reconfigured, so a nested lab is the next direction rather than something this validated. No Rust and no MCP transport changed. #346.

- **A64 switch tables, and `ioctl_map`'s first run against a real ARM64 driver.** Everything before this was fixtures; this is HEVD on the live 26100 debuggee with the built-in `mountmgr` beside it. Measured on `mountmgr!MountMgrDeviceControl`: **three** indirect jumps, all three `unresolved`, none of their codes recovered -- because A64 writes a switch three ways x86 does not. The fold is **three-operand and carries the scale** (`add x8,x9,x8,lsl #2`, the table holding an instruction count), and the decoder drops `Effect::Add` when it folds a modifier in, so the arm that recognised x86's `add rcx,rdx` never fired. The entry is **sized to the routine** rather than to `TABLE_ENTRY`'s constant 4, which was a constant because x86 emits a `DWORD` table and nothing else -- the *same* function here has a four-byte `ldrsw` table and a single-byte `ldrsb` one. And a byte table is **signed**, where at that width it matters most: `0xa2` is 94 entries back, not 162 forward. **None of the three fails safe** -- read unscaled, unsigned or at the wrong width, the targets land inside the image as readily as the right ones, so the executable-section check does not catch them and what comes out is a list of plausible addresses published as codes the driver accepts; the fixtures are built that way on purpose, so each test discriminates the rule rather than the guard. A modifier the walk cannot read (`lsr`, `asr`, an extension) refuses the table instead of being dropped. Hand-computed from the raw table bytes **before** the code was written and then compared: `mountmgr` goes **34 → 48** cases with `unresolved` **3 → 0**, its recovered codes being function codes 4-9 and 16-21 of `MOUNTMGRCONTROLTYPE`, which is independent corroboration rather than a self-check. Then surveyed rather than rested on one driver -- 24 drivers on the live ARM64 target, each one's `MajorFunction[0x0e]` mapped: **235 codes, 48 of them from 9 jump tables** that were unresolved indirect jumps before this, **0** tables left unresolved, 4 indirect jumps still unresolved and 33 `untracked`. Three of those four are refused on the **index** rather than the shape -- `fltmgr!FltpDispatch` switches on a major-function byte, and following it would publish major-function numbers as IOCTLs -- so the count of switch dispatches left unread on that target is zero. HEVD: **29** codes, `0x222003`-`0x222073` step 4, every one `METHOD_NEITHER`/`FILE_ANY_ACCESS` and every one `accepted`, matching `docs/hevd-ioctl-walkthrough.md`'s x64 verdict one handler wider in this build. #345.

- **`ioctl_map` and `driver_hazards` answer on ARM64.** Both were gated on `InstructionSet::operands_are_read`, which ARM64 passes once the pin moves to dbgscope#170 -- so the pin alone turns a refusal into an answer, and **neither tool was correct on ARM64 for as long as the refusal stood in front of it**. Two defects came out from behind it. `ioctl_map` matched layouts `X86 => X86, _ => X64`, a pair whose comment called it exhaustive *because the gate above had refused everything else*: an ARM64 target got the IRP seeded into `rdx`, refusals checked against `rax`, and a volatile list naming nothing an A64 decoder produces -- so a `call` invalidated nothing and a literal surviving one would be published as a control code the driver accepts. The offsets genuinely are shared, which is what made the wildcard look right; the register names are not. And `driver_hazards` called every store a descriptor-table access: measured by the debugger tier against a real ARM64 `nt`, **59,450** privileged instructions with **897** of the listed sample `descriptor_table`, every one mnemonic `str` -- x86's `str` stores the task register, A64's stores a register and is among the commonest instructions in any image. The tool was not unhelpful there, it was actively misleading: a hazard report that is really a disassembly, the shape `hazards`' own docs warn about. The two mnemonic namespaces are *mostly* disjoint, which is the worst way for them to be -- one collision rather than a wholesale mismatch obvious on the first run. A family table is one architecture's vocabulary now and is chosen by the target (`x86_family`/`arm64_family`), an architecture with no table keeping `PrivilegeKind::Other` for anything the decoder calls privileged: it loses family names and loses no findings. Three things had to arrive with it. **`movk`**, because an A64 compare immediate is twelve bits, so any code above `0xfff` is built `mov`/`movk` and compared register to register, and `Effect::Other` on the `movk` cleared the register at the second instruction of every chain (855 `movk` on the ARM64 kernel, 58 immediately before a compare). **Operand zero is the destination only where the decoder says it is written**, A64 naming a store's *source* first, so `str w11,[x8,#18h]` was modelled as a load **into** `w11` and invented a case from an instruction that stored to the field -- which corrects a pre-existing x86 reading too, `mul ecx` naming `ecx` first and writing `rax`/`rdx`. And **`hazards::Formed`**, because A64 has no pc-relative memory operand, so an import call is `adrp`/`ldr`/`blr` and without it the scan reports a driver calling no sensitive imports -- the clean-driver shape again. It cannot invent a call site: an address is reported only where the import table already holds that exact slot. Its positive path is fixture-tested only, the suite's one readable ARM64 image being `nt`, which *defines* the curated sink APIs rather than importing them. #343.

- **`reachable_from_dispatch` answers on ARM64.** The walk refused any target whose instructions this build does not decode, which meant ARM64 -- a target type this server otherwise supports fully -- and the refusal was right while it stood: every A64 instruction came back `Flow::Unknown`, the walk stops at those, so a verdict would have been a `NOT REACHABLE` about what could not be read rather than about the target. dbgscope#169 decodes A64's six branch classes, so the walk answers, and **nothing in the walk changed**: it reads `Instruction::flow` and has never known which architecture produced one. What [#297](https://github.com/glslang/windbg-mcp/issues/297) expected and did not hold is that the sibling tools would come along in the same pass because they share the traversal. They do share it, and that is not what gates them -- they read what an instruction **is**: the immediate a compare holds, the decoder's own privilege answer, the import slot inside a memory operand. So `flow_is_read` and `operands_are_read` came apart, and reading them as one gate would have had `ioctl_map` and `driver_hazards` report a driver with no control codes and no privileged instructions, which is what a clean driver looks like. Each refusal now says which of the two questions it is about and points at the tools that *do* work on that target, that last sentence being conditional on the gate rather than fixed. Two smaller things fell out: `machine_label` replaces a `{other:?}` fallback with `0xaa64`, which is what `!dh` and `lm v` print and is searchable; and no refusal enumerates the sets that do work any more, that having been a hand-written list beside a `matches!` in another crate, already stale, and not the actionable half -- nobody changes their dump's architecture. #338.

- **The eval drives the model that ships with macOS.** Apple's on-device model cannot be reached through ollama, and not for want of a feature: the weights ship as a SIP-protected MobileAsset in no format ollama loads, the `ollama` binary references `FoundationModels` nowhere, and inference runs in Apple's own daemon -- so the Swift framework is the only way in (`tools/fm_chat.swift`, `fm_probe.swift`, `fm_schema.swift`, driven from `tools/fm_drive.py`; the write-up is `docs/apple-foundation-models.md`, every figure in it re-derivable from the probe). It is a **drop-in**, which was not obvious: `LanguageModelSession.respond()` runs the tool-calling loop internally, the opposite of what this bench needs -- but a tool that **throws** yields its call instead of running it, the framework wrapping the refusal in a `ToolCallError` with the name and arguments surviving on `underlyingError`. So every tool refuses, the call travels back to the harness, and `local_model_drive` keeps its loop, the read-only fence, `call_tool()`'s three verdicts, the lease keepalive and the records. The grader needs no changes. **The constraint is the window, not tool calling**: `contextSize: 8192`, read off a real `contextSizeExceeded` rather than a model card, against **4,456** tokens for the 13-tool `crash` surface and **21,109** for all 61 -- Apple's own `SystemLanguageModel.tokenCount(for:)` over four real `tools/list` captures, one per `--tools` spec, from a listener answering `0.18.0+g2345a169`. So the tool-surface axis collapses to one cell, the only one that leaves usable room, and this backend varies **none** of the grid's three axes. That is the finding rather than a defect, and the backend refuses a plan asking for another model, for a `contexts` entry or for `think` instead of ignoring it: a cell is keyed against what the *records* carry, so an unkeyable cell would never count as already done and the plan would go on claiming an axis nobody varied. First graded run, two draws of the `short` subset on `--tools crash`: **4 of the 4 answerable task-runs right, both draws**, one tool call each. It also corrects `docs/token-budget.md`'s ≈4 B/token rule, which holds for the surface and breaks for results -- Apple's tokenizer reads structured results at 2.0-2.3 B/token and a `read_memory` hex dump at **1.24**, so a debugger's output costs about twice the tokens per byte that its documentation does. The live path is exercised rather than modelled: against the listener on the Windows VM, `--tools crash` and a kernel dump from `docs/samples`, revision `2025-06-18` negotiated and the read-only fence admitting 8 of the 13 served tools from the server's own `readOnlyHint`, the model opened the dump and ran `crash_triage` at 4,486 prompt tokens, read the bug check as `0x9f DRIVER_POWER_STATE_FAILURE`, declined to name a faulting driver on frames that carried none, and released the session. #335, #336.

- **`set_breakpoint` takes a `watch`, so a data breakpoint is a parameter rather than a reason to reach for `execute`.** `{"access": "write", "size": 4}` over the location the tool was already given -- `ba` as parameters, and one object rather than two optional fields, so a data breakpoint with nothing to watch is unspellable rather than refused, for the same reason `BreakpointSpec` has no kind field of its own. The **read** side has reported `kind: "data"` beside a `watch` the whole time, so a caller could see a data breakpoint it had no way to set. The access is an enum going **in** where `DataWatch::access` is a string coming **back**, deliberately: reading a breakpoint back has to cope with engine bits this build does not name and reports them rather than folding them into a plausible neighbour, while a request has no such case, so the schema refuses a sixth spelling before the call is made -- and both serialize to the same strings, so what a caller sends is what the result reports. Two smaller things fall out: a `coordinate` resolves against the **watched region's** size rather than one byte, since a four-byte watch one byte from the end of a module does not fit the image it was aimed at; and the rendering says which kind it set and what it watches, "Breakpoint N set at X" having been the same sentence for both kinds. The transcript's `Mutation` line carries the access and size too -- a `ba` and a `bp` at one address leave *different* state in the target, a programmed debug register against a patched byte, and a transcript is read after the session it describes has gone, so a fact missing from that line is recoverable from nowhere. Closes dbgscope#126; `FOLLOWUPS.md` item 2 **narrows rather than closes**, `write_virtual` and a typed register write being what is left of it. #334.

### Changed

- Remote kernel timeouts and unconfirmed releases now retain their worker and endpoint reservation
  in `kernel_unresolved`, including across automatic cleanup and supervisor loss. Ordinary
  `end_session` reports `recovery_required`; explicit session ID plus `kernel_handoff_pid` permits
  verified worker termination without claiming resume/detach. Reservations are supervisor-local.
  See [recovery handoff](docs/sessions.md#unresolved-remote-kernel-controllers).

- Experimental live-kernel teardown uses dbgscope's guarded quit-and-detach path before passive
  cleanup, checks breakpoint-removal errors, and requires the engine to release its target before
  reporting resume. Local regressions pass; live NT/hypervisor validation is still pending.

## [0.18.0] - 2026-09-17

### Fixed

- **Every pool and heap query refused current Windows, over one renamed field.** `_HEAP_VS_AFFINITY_SLOT::VsContext` -- the back-pointer a per-affinity VS slot uses to name the `_HEAP_VS_CONTEXT` it belongs to -- is spelled `VsContextOffset` on 26100.33438 and 26200, and holds `slot - context` rather than an address. The old name sat in a *required* field list, so `resolve_type` dropped the whole type and the family's other fields with it, and every pool and heap tool answered `unsupported allocator layout ... no recognized VS structural family is complete` -- a message that reads as a symbol problem, which is where the first day of diagnosis went. It is a third structural family rather than an alias, because the two affinity shapes are *checked* differently: an address against the context, a displacement against `slot - context`. Aliased, the newer build is decoded by the older rule, matches no context, and rejects every slot while reporting the older family's name -- confirmed live, where the displacement `0xa80` read as an address produced `claims context 0xa80`. Measured before either fix was written: `RtlpHpVsSlotCreate` stores `sub rax,rdi` against the context the slot was created for, and the slot-map arithmetic in `RtlpHpVsContextGetSlotInfo` is unchanged. Selection stays structural -- the fields a target's own PDB carries, never a build number, since `10.0.26100.1742` is the inline shape while later 26100s are not -- and both older shapes are pinned by schema fingerprints recorded before this change. Answers now carry `affinity_slot_vs_offset` beside `inline_vs` and `affinity_slot_vs`. `FOLLOWUPS.md` item 78, dbgscope#167.

- **`end_session` could not say whether a live kernel was left running or halted.** `target_left_running` was absent for every kernel target, because the worker filled it from `attached_to_a_live_process()` -- the attached-*process* table -- so a resumed kernel and a closed dump answered identically, and the teardown that needs somebody to walk over to a machine was the one that said nothing. "A kernel is not a process" is true of the word and wrong about the question: running or halted is exactly what the field asks, and for a kernel it is the only fact about a teardown worth acting on. It answers from the engine's own `TargetLeft` now, through a named `ending` rather than from a table about something else -- `true` where the target was resumed and actively detached, `false` where the resume did not take, which leaves it at a break with one processor stopped and the rest spinning, and the text names `qd` as the way out. The same disposition reaches the **supervisor's** teardowns, which had been logging `released its target` for a kernel left at a break: `lease expired`, `shutting down`, `idle reclamation` and `capacity reclamation` all render through one `note_release`, and a halted kernel is an `error!` carrying the remedy. Pinned at the call sites rather than at the renderer, because two of them awaited a `release` and dropped its answer on the floor -- a renderer test cannot see a caller that never calls it, which is how those two came to be written alongside the first. `every_supervisor_release_reports_what_it_did_to_the_target` reads this file's own source and fails on any `.release(` that hands its outcome to neither `note_release` nor a caller, naming `Sessions::end` as the one exception because it *is* `end_session`'s reply. What the answer still cannot separate is a target that ran on from one that resumed and re-broke, since both resumed; the uptime across the gap is what tells those apart. windbg-mcp#327.

- **The fold read the debugger host's NLS table, and the object manager reads the target's.** `RtlUpcaseUnicodeChar` folds through whichever machine calls it, so folding a *target's* object names by calling it here was right exactly as far as the two machines' NLS data agrees -- all 65,536 code units on this bench, both ends being 26100-era Windows. Nothing detected a disagreement, and a host several Windows versions from its target could differ exactly as Unicode's table differs from Windows': the `U+A7xx` additions moved most recently, and they are 40 of the 224 code units the *previous* fold was wrong about. `dbgscope`'s `Upcase` now walks the target's own `RtlNlsState.UnicodeUpcaseTable844` -- the 8-4-4 trie transcribed instruction for instruction from the routine, reached through `nt!PspHostSiloGlobals` by symbol and type rather than by literal offsets -- and falls back to the host's call only where the target will not say where its table is, reporting through `source()` which one answered. `device_security`'s link matching folds on the walk's own table, since it compares a link target the namespace read against a path the namespace resolved. It costs the ordinary walk nothing: the two bands below `U+00C0` consult no table, so an ASCII name -- nearly every name in the namespace -- makes no target read at all. Three things the routine does that a description of it loses are each pinned by a test: every index is an index of `u16` elements from the base, the leaf is a delta *added* to the code unit, and a table pointer that reads as null is the target's own answer -- it folds the ASCII bands and nothing else -- rather than a reason to reach for the host's table. `FOLLOWUPS.md` item 77, dbgscope#162.

- **The flags a branch reads can be computed from a register nothing named.** The loss check in `ioctl_map` asked an *operand list* which registers an instruction reads, and an operand list names the reads an instruction was written with: `cmp dword ptr [rcx+8],5` names `rcx` only inside a memory operand, `mul ecx` reads `eax`, `cmpxchg` reads `rax`. It asks `Instruction::reads` now -- the decoder's own answer, added upstream beside `writes` under the same two contracts -- and keeps the memory probe for the control-code field, which is a register on neither list. Measured rather than assumed, and the measurement moved the argument: over every flag-writing instruction the decoder handles in 64-bit mode, what `reads` adds over the operand list *and* `writes` together is, for every mnemonic a compiler emits, the registers that form a memory address. The shapes `FOLLOWUPS.md` item 75 named are read without being named and are also **written**, so the carried-and-gone half had them already. Conservative in the one direction that is safe: a pass that believes a control code is being dereferenced has lost the value either way, and the answer to give then is a case list that says it is short.

- **An object name was folded by an approximation of the object manager's table, and the approximation was wrong 326 ways.** Upstream, `Namespace::object_at` matched each component with `eq_ignore_ascii_case`; this server's `device_security` had a three-band reproduction of `nt!ObpLookupDirectoryEntry`'s fold instead, arrived at over three review rounds, which answered *undecided* wherever Rust's full Unicode mapping could not show a one-unit answer. Checked against a live 26100 kernel's own `UnicodeUpcaseTable844`, dumped over KD: it declined 102 code units, which was the known limit, and was **confidently wrong about 224 more** -- folding where Windows does not, so `\Device\ı` and `\Device\I`, two objects to the object manager, compared equal. Windows' table is not Unicode's. Both repositories now **call** the `RtlUpcaseUnicodeChar` the lookup itself calls rather than reproducing it, so there is one fold and no comparison it declines to make -- and the third answer that existed to contain the approximation is gone with it, along with `device_security`'s `links_unfolded`, which could only ever have been zero. What that left is that the call read the debugger host's table rather than the target's -- measured identical across all 65,536 code units on this bench, which is the easy case rather than the general one. `FOLLOWUPS.md` item 77 was what would close it, and it is closed in this same release -- by the first entry above, which reads the target's table and keeps this call only as the fallback for a target that will not say where its own is.

## [0.17.0] - 2026-09-14

### Fixed

- **Flags computed from the control code, with the code still where it was.** The loss check asked whether a register that *carried* the code had stopped carrying it, and the `test` clause beside it asked about operand **zero** -- two shape questions, each answering for the shapes somebody enumerated and answering *nothing* for the rest. `and eax,ecx` with the mask in `eax` leaves `ecx` holding the code and the `je` below reading a bit of it, and `test eax,ecx` is the same gap one operand along: no case, no `untracked`, a map reported complete. It is one question now -- does this flag write read the code, asked of every operand against the snapshot taken before the instruction ran -- which subsumes the `test` clause outright and with it every shape that clause was widened for. Its own boundary is stated rather than papered over: an operand list is not every *read* (`mul ecx` reads `eax` and names it nowhere), which is `FOLLOWUPS.md` item 75 and the same argument `Instruction::writes` was added under.

- **A pending compare is a claim about the path that left it, so a join unions them.** It intersected them, on the argument that a comparison is a fact like a register's value -- and they are not the same kind of fact. A register has to hold its value *here*; a comparison says what the branch below decides **on the path that made it**, and an execution taking that path reaches the case whatever the other edges did. `cmp code,K` / `jb other` / `je handler` reaches that `je` by falling through with the equality still live, so an IRP carrying `K` takes it; intersecting dropped that case outright as soon as anything else reached the same `je`, with no `untracked` either, because nothing had been lost. The live compares are a **set** now -- two paths meeting at one branch are two cases at their own two `case_rva`s -- and each answers the branch with **its own** flags, since one reached by a `sub` and one by an `add` admit the equality on opposite edges of a `jb`.

- **A block's last instruction was stepped by rules the rest of the block did not use.** A block ends where the next address is a branch target, which is a fact about the compiler's labels rather than about the instruction -- so the same `cmp`, `and` or `call` goes through the walk's loop in one routine and through the arm below its terminator match in the next, and that arm applied none of the loop's state transition. Three silent wrong answers came out of one omission: a compare ending a block left nothing for the `je` starting the next one, so the case was dropped with no case and no `untracked`; a loss ending a block left no `untracked` either; and a loss from earlier in the block outlived a **call** that had overwritten the flags it was about, reporting a branch on a callee's flags as a test of the control code. The compare and the loss now cross that boundary as they cross every other, and an unconditional jump's destination -- which is neither the fall-through nor a branch's target -- is given them too.

- **The oracle lane asks Ghidra about the function the tool walks.** `getFunctionContaining` answers with whatever body covers the dispatch address, so a `MajorFunction[0x0e]` landing inside a function Ghidra has already defined -- a shared interior entry, or an `--image` from a different build than the target's -- had the whole enclosing routine decompiled, and every comparison and table in it reported as the oracle's answer to a question about a different function. It refuses now, naming both RVAs; and because headless logs a post-script's exception and still exits `0`, the Python side reads Ghidra's own last words instead of failing on the file that was never written.

- **One flag was not the state.** An `add` reaching zero differs from a `cmp` reaching zero in **two** flags, not one: `0x80000000 + 0x80000000` is zero with `CF=1` and `OF=1`, both operands being `INT_MIN` and the sum not negative. So `jno`, `jge` and `jl` flip as well as `jae` and `jb`, and modelling the carry alone left them reading a state nobody had recorded. The comparison carries the flags an equality against it would leave, and every condition is derived from them -- which is what the rule's own doc comment already claimed, and is the arrangement that stopped it being wrong about the next instruction each round.

- **A loss joins by union, not by agreement**, which reverses a rule argued for badly. `pending` asserts a fact -- this comparison is live -- so every path into a block has to agree on it. A loss asserts **doubt**, and doubt on any path in is doubt at that block: the branch below is code-dependent on that path whatever the others did. Dropping it unless the paths agreed cleared the loss whenever two arms lost the code at different instructions, and the map read as complete.

- **The oracle lane checks switches the tool found and Ghidra did not.** It iterated Ghidra's tables alone, so a switch `ioctl_map` resolved and Ghidra missed had none of its cases cross-checked -- the promised same-switch comparison skipped in silence rather than reported.
- **Three more ways the control code went missing in silence.** The loss check asked one question -- "does the first operand's register still hold a code?" -- at one place, after the instruction's other writes had been cleared and after two early returns, so it missed a register written without being named (`xadd eax,ecx`, `mul ecx`), a narrow write over one (`sub cx,1` on a code in `rcx`), and a test of the field itself (`test dword ptr [stack_location+18h],3`) rather than of a register holding it. It is a **snapshot** now: which registers carried the code before the instruction ran, against what they hold after, asked at every exit. And the loss crosses block edges the way a pending compare does -- `and ecx,mask` / `ja next` / `je handler` put the loss in one block and the branch that makes it matter in the next -- surviving on **both** edges, because nothing is known about what an unmodelled operation did and so neither edge has ruled anything out.

- **The oracle lane reports candidates, never findings.** Ghidra admits a value because it came from memory and Driver Buddy because it looks like a control code, so an unrelated loaded field compared against a device-type-matching constant satisfies both: their agreement is two opinions rather than provenance, and the tool excluding it may be the one that is right. Neither traces the IRP's control-code field, and doing so here would be the lane adopting the assumption of the pass it exists to check -- so candidates are ranked by how many implementations saw them and the decompiled C decides, which is how `0x6dc000` was settled in the first place.
- **An `add` that reaches zero carried, and a `cmp` that reaches zero did not.** `equality_survives` is derived from the flags an equality leaves, and those were derived from a **subtraction**: for `add ecx,K` to be zero the operands must sum to exactly 2^32, so `CF=1` where a `cmp` leaves `CF=0`. `jae` and `jb` read carry alone, so their feasible edge flips -- `add ...; jae t; je h` put the case at `t`, where it cannot be, and lost the one on the fall-through, where it is. The carry travels **with** the comparison now rather than being assumed by whoever reads it, which is the same arrangement `proved` has with `Value::Code` and for the same reason: how a value was arrived at is a fact about that value.

- **The oracle lane's HEVD command could not have worked.** Its tool half opens `--dump`, which the documented invocation left at the checked-in `mountmgr` crash -- so an HEVD dispatch resolved nothing there and the run ended before either oracle was asked. `--profile` attaches a live kernel by name instead, which is how the rest of this repo reaches one and keeps the debug key out of an argument; the README's command is now the one that was actually run. Measured with it: HEVD 28 records over 28 codes, Ghidra 28 equality codes, Driver Buddy 24, nothing missing and no candidates.
- **`add ecx,K` / `je` produced no case and no sign of one.** The arm rebased the value and returned no comparison fact, so the pending compare was cleared -- and the loss went unrecorded too, because the register still held a control code and nothing had destroyed it. An `add` is how a compiler writes a subtraction of a negative, so this is an ordinary dispatch shape, and it was the silent kind of miss. It leaves a comparison now, exactly as the `sub` does.

- **`test ecx,3` / `je` was silent in the same way.** A test writes only flags, so the walk returned early and produced neither a case nor a record -- while the branch reading it takes a path whose codes cannot be enumerated. A test of a register holding the control code is a pending loss now, committed by the branch that reads its flags; a test of anything else is not.

- **The step wrapped at the field's width whatever the destination's was.** A control code is a `ULONG` and the ordinary chain steps a 32-bit register, but `sub rcx,rax` executes modulo 2^64 -- and wrapping at 32 can bring an offset back to zero where the machine does not, so a following `je` reports code `0`, a case no execution reaches.

- **Three more against the oracle lane.** A Ghidra run that could not decompile emitted `"decompiled": false` with empty lists and was consumed as a valid answer, so a failed oracle read as "found no codes". Its provenance check establishes that a compared value came from **memory**, not that it came from the IRP's control-code field -- a length, a status and a structure member are loads too -- and tracing it to that field would be the lane adopting the assumption of the pass it exists to check, so a value is reported as a **candidate** either way, ranked by how many implementations saw it -- two heuristics agreeing is two opinions rather than provenance, and the decompiled C is what settles it. And the README called a destination with many labels and no cases "a default" one paragraph after saying the default is not inferred; it is a candidate for one, or a group of labels `ioctl_map` did not take, and which is a question the grouping poses rather than answers.
- **Parity and overflow are decidable too, and were the two conditions this got wrong.** `equality_survives` gave `jo`, `jno`, `jp` and `jnp` both edges on the grounds that they "say nothing about equality" -- but `cmp a,b` with `a == b` computes zero, which fixes `OF=0` and `PF=1` as surely as it fixes `ZF=1`. So equality survives the fall-through of `jo`/`jnp` and the taken edge of `jno`/`jp`, and carrying the compare onto the other one lets a later `je` fabricate a case execution never reaches. The rule is derived from the flag state an equality leaves rather than written as a list of families, which is what let a wrong answer sit in two arms; the fixture's mnemonic table was missing `js`/`jo`/`jp` entirely, so a test using one silently became a branch with no condition at all.

- **Two more against the oracle lane** (`tools/ghidra_oracle/`). Its table cross-check compared only whether a code appeared among a switch's labels, never where the case **lands** -- so a map that recovers the right label and routes it to the wrong block passed clean, which is the failure the check was written for and which its README already claimed it caught. And its equality constants were filtered by device type alone, so an equality against a status, a length or a magic number whose top sixteen bits match would have been reported as a code `ioctl_map` missed. The Java side now walks the compared varnode back toward a `LOAD` and says whether it got there; constants that did not are reported apart rather than dropped, because deciding which displacement counts would be the oracle adopting the assumption of the pass it exists to check.
- **A pending compare was carried down the wrong edge for half the branch conditions.** The rule shipped as "the fall-through of anything that is not `je`/`jne`", which is right for the **strict** conditions and backwards for the **inclusive** ones: `cmp code,K` / `jbe L` admits equality where it *branches* (`code <= K`) and forbids it where it falls through (`code > K`). So a `je` at `L` was a case the walk dropped, and a `je` after the fall-through was one it would have **invented** -- reported and never reached, which is worse than missing because nothing about it says so. `jae`, `jge`, `jle` are the same shape, and `js`/`jns` fall either side of it. The edge is chosen per condition now, by asking which edges the branch has not ruled equality out on -- a question with an answer for every condition the decoder has, rather than a list of the ones somebody thought of. The earlier boundary tests used `ja` and `jb`, both strict, so a fixture built from them agreed with the wrong rule as readily as with the right one.

- **A step a register carries is a `ULONG` and wraps like one.** `mov eax,0FFFFFFFCh` is how a compiler puts `-4` in a register; widened to `i64` the offset ran past `u32::MAX` and `push_case` dropped the code **silently**. The arithmetic is modulo 2^32 now, as the machine's is. The immediate path had the same latent hole; carrying the step in a register is what made it reachable.

- **A lost control code is reported where a branch reads it, not where it is lost.** `untracked` was appended the moment a flag-writing instruction destroyed a tracked code, so an `and ecx,3` nothing branched on marked an otherwise complete map `partial` and claimed a missing case. The conservative direction, and still wrong: this is the one signal whose worth is that it is quiet.

- **Three corrections to the oracle lane itself** (`tools/ghidra_oracle/`), each of it lying quietly. It promoted Ghidra's **relational** bounds to control codes, so the diff reported `0x6d4021` and `0x6dc001` as missing from `ioctl_map` while the README beside it called them range checks; only equality comparisons count now. It inferred a switch's **default** as the most frequent destination, which discards real labels on a switch whose labels share a handler and drops one at random on a table of unique destinations; the labels are reported grouped by destination instead, and the table check is the subset question that needs no default. And it read Driver Buddy's output whatever the exit code, so a crashed run came back as "found no codes" and the comparison ran as though one of the two promised oracles had answered.

- **A driver's import directory can be in a section the loader freed, and the advice for that was wrong twice over.** `driver_hazards` cannot answer for **HEVD** on a live kernel: its import directory is at RVA `0x8a4a0`, inside `INIT`, which carries `IMAGE_SCN_MEM_DISCARDABLE` -- Windows frees those pages once `DriverEntry` returns, so the bytes are gone rather than paged out. The message said "a driver's pageable sections may simply not be resident, in which case this is the target's state rather than a missing image and there is nothing to reload", which is neither the cause nor the remedy. It now names the section, says what discardable means, and says what was **measured**: an executable image path plus `.reload /f` leaves those bytes unreadable on a live target -- the engine substitutes a file's bytes where a *capture* has none, and a live target's freed pages are mapped-and-invalid instead -- while the same driver in a dump scans fine. Reading the image file directly is `FOLLOWUPS.md` item 73.

- **`IoCreateSymbolicLink2` was not on the sink list**, so a current driver creating a symbolic link went unflagged: `mountmgr` on 26100 imports only the numbered form, and the list held only the original even though it already carries `ExAllocatePool2` and `ExAllocatePool3`. `SINK_LIST_VERSION` is `2`; the scan of `mountmgr` goes from three sinks to four.

- **`ioctl_map` recovered 4 of HEVD's 28 control codes and reported the map complete.** HEVD steps its dispatch chain with a register -- `sub ecx,222003h` / `je` / `sub ecx,eax` / `je` / ... with `eax` holding 4, each group ending `cmp ecx,eax` / `jne default`. Both the subtract and the compare paths read only **immediates**, so the walk followed the first code and lost the rest. They resolve an operand to a constant now whether it is written down or carried in a register a literal was moved into, which is the same "the literal, wherever it came from" the status path already did. Against the live driver: **4 codes -> 28**, which is every code its own header defines, with no false positives. `mountmgr` is unchanged at 48 records over 24 codes.

  **The worse half was that nothing said the list was short.** `unresolved[]` is documented as what stops a short case list reading as a complete one, and it only ever fired for an indirect *jump* -- so a chain the walk could not follow produced neither cases nor any sign of them: `unresolved` empty, nothing stopped, nothing capped, `code_proved: true`, and `driver_surface` calling the section `ok`. Nothing about four codes said they were four of twenty-eight. `untracked[]` now records where the control code stopped being followable -- an instruction that carried it somewhere unmodelled with a branch reading its flags, and a test on a register holding the code against a value that could not be resolved -- and feeds `IoctlMap::shortfall`, so such a map is `partial` with a note. Both measured drivers report it empty, correctly, which is why the tests for it are constructed.

- **`ioctl_map` missed a control code `mountmgr` accepts, and every check in this repo agreed it was absent.** `cmp r13d,6DC000h` / `ja default` / `je handler` is one compare feeding two conditional branches -- the three-way test a compiler emits for a binary-search dispatch. The walk is per basic block and a conditional branch ends one, so the `cmp` sat in one block and the `je` was the terminator of the next with no compare of its own. The equality was dropped with nothing saying so: no unresolved transfer, no blind instruction, no stop, just a code the driver accepts and the map does not list. On `mountmgr` that cost `0x6dc000` (`IOCTL_MOUNTMGR_CREATE_POINT`, with a name string and a handler) outright and one of `0x6d4020`'s two sites -- **45 records over 23 codes where the answer is 48 over 24**.

  A pending compare is now a fact that crosses edges, joined at merges the way a register's value and a bounds check already are. **Which edges it crosses is the rule and it is narrow**: the fall-through of a branch that is not `je`/`jne`, and nothing else. Past `ja K` *taken* the code is above `K` so an equality against that compare cannot hold, past `je K` not taken it is not `K`, and a case built on either would be invented -- worse than a missing one, because nothing about a fabricated case says it is fabricated.

### Added

- **A second shipped skill, and this is the release that delivers it** (`skills/msrc-patch-diff/`). The plugin has shipped one skill until now, and `skills/` reaches a machine only when the plugin version moves -- so a skill merged to `main` is not yet a skill anybody has. It turns a CVE number or an MSRC URL into a reproducible comparison: the CVRF record retrieved and kept as evidence, an explicit current-and-previous-stable release pair, verified downloads, paginated similarity results from Binary Ninja Personal driving an external BinDiff, and a report that separates observed changes from CVE attribution. What it refuses to infer is written into the skill rather than left to whoever runs it -- a blank JavaScript page is not evidence that a CVE is absent, file-version ordering and PE timestamps do not establish release order, MSRC's `Supercedence` is a candidate predecessor rather than proof of adjacency, and the changes in a cumulative update do not by themselves identify the fix. `scripts/evidence.py` is pinned by `scripts/test_evidence.py` rather than by having been run once.

- **The BN6 similarity work, recorded where its decisions can be audited** (`docs/binja6-similarity-plan.md`, with five investigation and acceptance notes beside it). The implementation is the companion's rather than this repo's -- `binja-windbg-mcp` PR #4, 2026-09-12 -- and what lands here is the plan it was built to and the evidence it was accepted on: a GUI export driving an external BinDiff across synthetic identical, relocated and changed PE fixtures, with the changed fixture's extra function reported unmatched and names, types, comments, bytes, generations, identities and modification flags all unchanged; and a live ARM64 handoff passing runtime-byte comparison, run-to, breakpoint and wrong-build refusal. **Native similarity needs Ultimate and is unvalidated**, which is stated rather than left to be discovered later: Ultimate was not bought, so Personal is the only path with evidence behind it. The investigations still open are `FOLLOWUPS.md` items 61-65.

- **A second opinion on the driver tools** (`tools/ghidra_oracle/`), which is what found the above. The four driver tools are a native port of Driver Buddy Revolutions, and until now everything checking them came from my own reading of the same drivers: the dump-tier oracle is derived from `docs/driver-ioctl-walkthrough.md`, a hand recovery, and `src/ioctl/tests/differential.rs` runs an interpreter over fixtures written beside the pass it checks. Both are worth having and neither is independent -- a model wrong the same way twice agrees with itself, which is exactly what happened: the walkthrough's published figure had the same miss, so the assertion derived from it passed. The lane runs Ghidra's own decompiler and Driver Buddy itself over the same cached image and diffs by code. Manual, about a minute per driver, and it needs Ghidra on the host; `tools/ghidra_oracle/README.md` has the bench requirements and the three traps.

  Worth recording from the first run: on `mountmgr` the native tool is **more accurate than the program it was ported from**. Driver Buddy missed `0x6d4008` and `0x6d4028`, and reported `0x80000005`, `0x8000002d` and `0xc0000004` as control codes -- NTSTATUS values its heuristic accepts. `ioctl_map` reports neither kind, because it traces the value from the IRP and says so in `code_proved`.

- **A hazard scan reads two things, and one note said a gap in either weakened both.** `driver_surface`'s hazard note claimed the scan "did not cover the whole image" and qualified `sinks` and `privileged` together, whichever field had actually fallen short -- so a driver with one bound library was reported as having an uncertain `privileged` list when the code had been decoded in full, and a scan the clock stopped was reported as having an uncertain set of `sinks` when the import table behind it was whole. The two do not travel together: the sink **set** is built from the import table before any code is decoded (`src/hazards.rs`), and the code walk only adds each sink's `call_sites`; an import walk that is stopped refuses rather than truncating, so a scan that exists at all has a complete import table behind it. The note is now chosen by a value (`Shortfall::Imports`/`Code`/`Both`) and names the fields its own cause is about, saying in as many words that the other side is not qualified by it.

- **`error` was two facts with opposite remedies, and only prose told them apart.** `driver_surface`'s four sections run in a fixed order on one shared deadline, so a clock spent before a section is reached leaves it `error` with a null payload -- identical on the wire to a section that tried and failed. The remedies are opposite: one says go and look at the driver, the other says this call had no budget left. A caller branching on `status` could tell which only by reading the `note`'s wording. The survey now carries `not_started` (`{section, why}`) naming the **first** section its clock did not reach, and every section after it is in the same state for the same reason -- which is why it is one field rather than a flag on each. `why` separates a deadline from a caller's interrupt, again because the remedies differ.

  Found as the third review round on one block of the live-kernel differential, all three the same mistake: the test branched on the standalone tool's outcome and then asserted about the composite, whose state its own clock decides -- so each round was a valid run failing the tier in a state the branch had not allowed for. The differential is restructured around what the composite says about itself (a section with no payload is never `ok` and never silent; a section with one is complete exactly when that payload covers its subject), with the two-call comparison layered on top and saying out loud when it is not comparing.

  **Measured, and the scenario does not arise on this bench**: the budget gate refuses a survey with under a second of its caller's clock left, and `mountmgr`'s survey fits inside a second, so call timeouts from 4 s to 19 s against `ctf-vm` either refused the call outright or ran every section. It is reachable on a slower transport, and the shape is asserted rather than observed.

- **A `driver_surface` section said it was complete when its own answer said otherwise.** Each section's status was decided at the composite from a hand-picked subset of the payload's fields, and both lists had gone stale. The hazard section read `stopped` alone — so a scan its **byte cap** ended, a scan over **pages that would not read**, and one whose **bound imports were never named** all came back `ok`, which means "everything this section reports was read", while `driver_hazards`' own renderer printed INCOMPLETE for each of them. The IOCTL section read `stopped`, `cap_hit` and `unsettled`; `blind` was added afterwards documented as making a map "incomplete in a way no other field says", and `unresolved` — an indirect transfer nobody followed — was never in the list at all. Measured on a live kernel against `mountmgr` before a module refresh: the section reported **`ok`** over **19** control codes with two jump tables unresolved, where the whole answer is **45**.

  Both now ask the answer instead of deciding for it (`DriverHazards::shortfall`, `IoctlMap::shortfall`), and each **destructures its struct exhaustively**, so a field added later is a compile error at the predicate rather than a silent omission at a caller. `unproved` is deliberately not a shortfall: those cases were read and are reported, each saying of itself that it is unproved — weaker evidence about what is here is not the same fact as something missing.

- **Two pieces of advice that were wrong for a live kernel**, found by running `driver_surface`'s live-kernel tier. A fresh kernel attach leaves the debugger's module inventory holding `nt` and little else — measured, **1** module at attach against **156** after a refresh — so a driver loaded beforehand is absent from the inventory rather than from the target. The hazard section said "is in no module the engine could name… `modules` lists what is loaded", which in that state lists nothing and sends a reader to confirm a wrong conclusion; it now reports the inventory's own size, says what a fresh attach looks like, and names `refresh: true`. And the PE-read failure named only the **dump** remedy (set an image path and `.reload /f`), which on a live kernel points at bytes that are on the machine in front of you, merely paged out; both targets are named now, because `is_kernel_target` does not separate a live kernel from a kernel dump and dbgscope's `is_live_kernel` is private.

  What the stale inventory costs is not cosmetic: on `mountmgr` it was **19** control codes instead of **45**, with both 81-entry jump tables unresolved, because following a table needs the image's executable ranges. The map says so — the tables are listed under `unresolved` — so a short map still reads as the lower bound it is. Running the refresh automatically is `FOLLOWUPS.md` item 72, deferred because resynchronising has no wall-clock bound of its own (item 54).

- **The four driver tools' rendered text is fenced, which is the other half of escaping it.** `renderable` escapes a backtick *precisely* so a target-chosen string cannot close the code block it is printed inside, and every one of the nine call sites in `src/worker.rs` puts its text in one. The renderers extracted to be engine-free fenced nothing, so escaped-but-bare text was still HTML to a Markdown-rendering client: `<br>Hazards<br>` in a driver's name or an image's import table changed the visible shape of the report without adding a single newline. Escaping `<` instead would have been wrong -- inside a fence it is inert, and `&lt;` would display literally in the nine listings that are already correct. The fence is also what these renderers' column padding always needed: bare, a Markdown client reflows the rows into a paragraph.

- **Every renderer that reads a target now escapes what the target chose.** `renderable` — which turns a line break, an ANSI escape, a `U+2028` or a backtick into something that cannot leave the row it was printed in — lived in `src/worker.rs` and was applied at nine sites there. The four renderers this crate had extracted to be **engine-free** (`device`, `ioctl`, `hazards`, `surface`) left that module and lost reach of it on the way out, and every one of them prints strings the target chose: a driver's `DriverName`, an object path out of the namespace, a module name, and — sharpest, because `src/pe.rs` exists to distrust exactly these bytes — the library and import names read out of a hostile image's own import table. A driver named with a newline could write a section heading of its own into the human-readable result, with `structuredContent` staying correct beside it. The helper now lives in `src/structured.rs` next to `addr`, where those modules already look for formatting.

- **`driver_surface` stops where a device chain leaves its driver.** `_DEVICE_OBJECT::DriverObject` is the authoritative answer to who owns a device and the chain walk reads it on every device anyway; nothing compared it with the driver object the survey had resolved. A corrupted or hostile `NextDevice` pointing at a readable device owned by somebody else was followed, and that device's fields, **its security descriptor** and the rest of *its* chain came back attributed to the driver that was asked about. The walk now stops at the boundary and says which driver claimed it — and the foreign device is not listed, because it is real and only the claim that it belongs here is false.

- **`driver_surface` no longer says a device is absent from a directory it did not finish reading.** Where the `\Device` listing was partial or failed, a device with no path was rendered as "not in this directory" — an absence, from a search that did not complete. It reports "no path found" instead, which is the rule this renderer already applied to "this driver created no devices" and `device_security` applies to its link search.

- **`driver_surface` — one driver, in one call.** Its dispatch table, every device it created with the gate on each, the control codes its IOCTL handler accepts, and what its image can do. The fourth and last of the native Driver Buddy Revolutions tools, and the one the other three were built toward: it joins them at the driver object's own fields rather than leaving a caller to match a module name to a device path by hand. 60 → 61 tools.

  **Four sections, each answering for itself.** They are read from different things — a dispatch table and a device chain out of pool, a control-code map out of the driver's code, an import table out of its image — and they fail independently, so there is no overall "did this work". Each carries `ok`, `partial`, `unavailable` or `error` with a note, and `unavailable` is kept apart from `error` because a target that cannot answer a section is not a failure of the call. The rule that shape exists to enforce: **a failed dispatch recovery must not discard the import or security evidence**, the fragile analysis being the code one and the two that still answer being the two a reader most often wants.

  The IOCTL and hazard sections are `ioctl_map`'s and `driver_hazards`' own answers **whole**, rendered by their own renderers — a digest would be a second shape restating what the map already says, and a composite whose caller has to go back for the detail has not composed anything.

  **The per-section rule stops at the driver object**, and that boundary is the point rather than an omission: every section is read from something the driver object points at, so a driver object that will not resolve is the whole call failing — because three empty sections is exactly what a driver with no devices, no control codes and no sensitive imports looks like, and the fourth -- an empty dispatch table -- is not something any driver has at all, which is a tell a reader should not have to notice.

  **A bare name resolves under `\Driver` then `\FileSystem`, and one that resolves in neither is refused** — not evaluated as an expression, which is what `!drvobj` does, and how `!drvobj mountmgr 7` comes to answer with mountmgr's image base reported as `is not a driver object`.

  The dispatch table is **grouped by handler** with every major accounted for, the null entries included; how many majors the table holds is read off the target rather than taken as `wdm.h`'s 28. A device carries its descriptor but **not** the symbolic links that reach it — that search lists a whole directory per device — and `device_security` on one path is where the links are.

  **What a short answer looks like**, which is the half worth knowing before relying on one. A device whose `_DEVICE_OBJECT` would not read carries `unread` and none of the five fields after it — absent rather than empty, so a caller parsing `device_type` as hex can act on a missing field and cannot act on `""` — and it is still listed, because it is on the chain and what is missing is what it says about itself. A device the call's clock did not reach keeps every field the chain walk had already read and loses only its descriptor, which `security_absent` says: that field carries **three** reasons here against `device_security`'s two, the third being a survey that stopped before asking. A chain that ended at a null `DeviceObject` is `ok` whatever the `\Device` listing managed, that chain having established the driver created none. And "this driver created no devices" is printed only for a section that read everything — the rule `device_security` already applies to its link search.

  Needs a **live kernel target**, for the reason `device_security` does and no other: a driver object is in pool and is reached through the object namespace. On a dump the whole call is refused rather than answered in part, and the refusal names the two tools that *do* read the image there: `driver_hazards` on a module name, and `ioctl_map` given a dispatch address from somewhere other than the driver object.

- **`device_security` — who may open a device.** The security descriptor the device object keeps, as principals and access masks, the two device words that qualify it, and the symbolic links in `\GLOBAL??` that reach it from user mode. It resolves an object path through the kernel's own namespace, so the name a user-mode caller knows works as well as the device's: a symbolic link is followed once, and the answer says which one it followed.

  Each ACE comes back as its SID **and** the account that SID reads as, with the mask named as a **device's** rights -- `FILE_READ_DATA` rather than the same bit's meaning on a registry key -- and the two the I/O manager checks a control code's `RequiredAccess` against picked out as `reads`/`writes`. That is the join to `ioctl_map`: a code requiring `FILE_WRITE_DATA` cannot be sent through a handle whose ACE grants neither.

  **The descriptor it reads is the device object's own, not its object header's.** Every other object in the namespace keeps one in the header; a device's is null there, because the `Device` object type's `SecurityProcedure` is `nt!IopGetSetSecurityObject` and that routine keeps the descriptor in the device. Reading the header's -- the natural thing, since the namespace walk hands it over ready-masked -- reports every device on such a build as carrying no descriptor at all, which is the most permissive answer there is.

  **Three pairs of facts are kept apart that a renderer would collapse.** A NULL DACL grants every caller everything and is read off the control bit, so it is never confused with a DACL that could not be read. An object carrying no descriptor is not a descriptor that would not read -- the second is what a kernel minidump answers for every object in it. And an empty list of symbolic links means "nothing reaches this device" only when the search saw the whole directory, which `link_search` says.

  `FILE_DEVICE_SECURE_OPEN` is called out where it is **missing**: without it the descriptor is checked when the device is opened by name and not when a path beneath it is opened, so a driver that parses its own paths is reachable through a relative open by a caller the descriptor would have refused.

  Needs a **live kernel target**. A kernel minidump carries no object namespace -- the root directory pointer, the type table and the header cookie all read as unavailable -- and the refusal says so rather than sending someone to check a device name that was correct.

- **The refusal for a namespace a dump cannot supply stopped offering two tools that fail the same way.** It ended "`driver_object` and `device_object` work on a dump"; measured against the checked-in sample, both answer `Unable to get value of ObpRootDirectoryObject`, because both resolve their argument through the very namespace the refusal is about. `!drvobj` given a name it cannot resolve is worse than a refusal — it evaluates the name as an expression, so `!drvobj mountmgr 7` answers with mountmgr's image base described as not being a driver object. The advice now names what a minidump does still serve: the image, through `driver_hazards` and `ioctl_map`.

- **`ioctl_map` — which control codes a dispatch routine accepts.** Recovered from the driver's own code and decoded: device type, function code, method and required access, with the site that recognises each code and the routine it reaches. It follows compare chains, the `sub`-and-compare form a rebased switch compiles to, and a jump table when the bounds check and the table's base were both recovered and the switch is indexed by the code itself.

  **A value is followed only while it is whole.** A control code is a `ULONG`, so a two-byte read or copy of one carries part of it and is not reported as a code -- the register's width is the decoder's answer, as is whether a table's entries were sign-extended, which decides whether a case sits before its base or four gigabytes past the image.

    **The recovery is a walk over the routine's blocks and edges**, not down its listing. `uf` prints basic blocks in sequence, so reading them in order carries register facts across seams control flow never crosses -- a shared epilogue's `pop r13`, a block entered from a branch elsewhere. What a block knows is what every path into it agrees on, a bounds check holds on the path it admits, and a case block is read with the facts of the path that reaches it.

    **A dense switch is two tables, and reading it as one invents codes.** MSVC emits a byte per
  index saying which case it is and a dword per case holding its RVA, reusing one register for
  both — so a table's entries are reached through the byte map, and a slot that goes to the
  switch's default is not a code the driver accepts. On `mountmgr` that is the difference between
  43 case records and 179, three quarters of which would have been wrong. Every resolved entry has
  to be code inside the driver's own image, or the table is refused as not being one.

  **An edge is not a verdict.** A compare and a branch say where control goes when a code matches, not that the driver accepts it, so each case carries what the landing block shows: an NTSTATUS error returned is a rejection, a routine reached is a handler, and neither is left open. An exact size needs the same evidence on the other edge.

  **Provenance belongs to the value, not to the routine.** Each case says whether the value it tested was traced from the IRP or read off a bare displacement, because a dispatch routine that compares some other structure's `+0x18` field before reading the real control code has one of each -- and the guessed case is the one a reader needs warning about. The offsets follow the target's bitness rather than being x64 constants.

  **What it could not follow is in the answer.** Every indirect transfer it did not resolve is listed, so a map that is a lower bound says so rather than reading as a complete set; a table is never read at a guessed length; and `code_proved` says whether the control code was traced from the IRP or taken from a bare `+0x18` displacement, which is what an empty case list turns on. Sizes are proven-exact or absent, with floors kept separately as evidence. The case fields are the shared IOCTL-case shape a Binary Ninja or Ghidra companion answers in, so the same driver recovered on either side is the same record. See [`docs/structured-results.md`](docs/structured-results.md) and [`docs/limitations.md`](docs/limitations.md).

- **`driver_hazards` — what a driver's image says it can do.** The sensitive APIs it imports with
  the call sites that reach them, and the privileged instructions in its code (`rdmsr`, `out`,
  `mov cr3`). Imports are named from the driver's own import table, so a stripped third-party
  binary answers as well as one with symbols, and a call site is matched by the **slot** it goes
  through rather than by a name.

  Whether an instruction is privileged is the **decoder's** answer, carried beside the flow by
  `dbgscope` and generated from the instruction set, so `cli`, `clts`, `lmsw` and the
  virtualisation families are found without anyone maintaining a list -- a list is wrong by
  construction, and a driver holding only the instructions nobody remembered was reported as
  holding none. The `kind` beside each finding names the family and nothing more; one no family
  names is `other`, with its mnemonic.

  Evidence rather than a verdict, and the result says so: an import is not a call, an absent import
  excludes nothing since a driver can resolve an export at run time, and a call site is not a
  reachable one. What counts as sensitive is a curated judgement, so the result carries the version
  of the list it was scanned with.

- **`reachable_from_dispatch` answers with values as well as prose**, with a matching
  `outputSchema` — the text is unchanged and both halves are built from the same walk, so they
  cannot disagree. The verdict, the call path as `{site, kind, callee}` hops, and the branch recipe
  as a segment per function with the compare feeding each branch decoded. Every address carries the
  `module` + `rva` coordinate that survives a reboot, and each image's identity is carried **once**
  in an `images[]` beside them rather than repeated on every address — a real driver's path names
  the same image a dozen times, and an identity is 150-odd bytes of GUID, timestamp and size.
  `FOLLOWUPS.md` item 60. See [`docs/coordinates.md`](docs/coordinates.md).

  The verdict is not a boolean, and the typed answer says so in three separate fields: `reachable`
  is sound, while `not_reachable` may be incomplete because a work bound stopped it (`bound_hit`),
  because the clock or an interrupt did (`stopped`), or because instructions in the graph could not
  be read or decoded (`blind_stops`). The three have different remedies, which is why they are three
  fields and not one.

### Changed

- **The dispatch walk is bounded in time, and its work bounds are capped** (`FOLLOWUPS.md` item 13).
  `max_functions` and `max_depth` came from the caller uncapped and nothing was polled between
  functions, so a large enough pair pinned that session's engine for as long as the walk took. The
  walk now carries what is left of the caller's own timeout, each `uf` it runs is bounded by the
  remainder rather than merely polled around, and the bounds are clamped at 4,096 functions and 256
  depth — far above the defaults of 256 and 32.

  Half of that is the rendering. A walk that ran out of time did not explore the graph it was
  *bounded* to either, so a halt outranks the bound in the report and "the reachable call graph was
  fully explored" is a sentence a halted walk no longer produces. A recipe cut short is labelled
  `INCOMPLETE`, because a prefix of a recipe is not a weaker version of one — satisfying it does not
  put control on the target.

- **The walk reads decoded control flow instead of parsing a disassembly listing**, which deletes a
  class of wrong answer rather than fixing instances of it: a symbol containing a comma, a
  parenthesis or a bracket used to turn a direct call into an indirect one, and a dropped direct
  edge is a `NOT REACHABLE` that should have been `REACHABLE`.

- **`reachable_from_dispatch` refuses a target whose instruction set this build does not decode**,
  naming the machine type, rather than returning a verdict about what could not be read. On ARM64
  every instruction's flow is unknown, so the walk would have reported everything as reachable.
  Lifting the refusal is [#297](https://github.com/glslang/windbg-mcp/issues/297).

- **A `NOT REACHABLE` says when part of the graph it explored could not be seen.** An instruction
  whose bytes will not read, or whose encoding is not decoded, stops the walk where it is and is
  counted; such an instruction is a barrier and is never stepped over, since skipping one would
  join the instruction before it to whatever follows and invent an edge.

## [0.16.0] - 2026-09-07

### Added

- **`exception_triage` — a user-mode fault as fields**, which is `crash_triage`'s counterpart for a
  process rather than a machine. The exception record with its code decoded, what kind of fault it
  is, the thrown C++ object and the `HRESULT` it carries, and the crashing stack. It closes the gap
  [`docs/explorer-crash-walkthrough.md`](docs/explorer-crash-walkthrough.md) §9 argued for: three
  faults in one evening whose answer came out of `execute` — `.exr`, `.ecxr`, `s -d`, `dd`,
  `!error` — are now one call.

  Three things it does that the hand recipe did not. The thrown **type** is decoded from MSVC's own
  `ThrowInfo` → `CatchableTypeArray` → `CatchableType` → `TypeDescriptor` chain rather than assumed,
  so the `0xAABBCCDD` sentinel confirms an offset the type name already predicted instead of being
  the thing that finds it — reported as `hresult_confidence: corroborated`, against `convention`
  when the sentinel stands alone. Both routes are tried, because neither is a superset: `ThrowInfo`
  lives in the throwing module's image, which a minidump does **not** capture (measured — the walk
  succeeds while the binary is at its recorded path and returns `????????` once it is moved aside),
  while the thrown object is on the stack and always is. And the throw's own record is **searched
  for**: when a C++ exception goes unhandled the event the debugger sees is `abort`'s fail-fast, so
  the crashing thread's stack is scanned for the `0xe06d7363` record, anchored on the innermost
  frame — whose stack pointer comes from the recorded context rather than from unwinding — and
  bounded by a fixed span.

  That scan runs on **that fault shape alone**: `abort`'s fail-fast, carrying none of WIL's
  parameters. Not on every fault whose own record holds no throw, which is every access violation
  and every breakpoint — a C++ `EXCEPTION_RECORD` outlives the frames that held it, so a fault
  deeper than an old `try`/`catch` would find that handled exception's object and report it as the
  root cause. And the summary for subcode 7 no longer says an `abort` *means* an uncaught C++
  exception: it is one of its causes, alongside a direct `abort()`, a failed `assert` and every
  other `terminate()`, and the sentence names the throw only when the scan actually found one.

  **A scan that did not run reports no result.** The hunt is skipped for three reasons a caller
  can meet — `scan_stack: false`, a fault shape that never buries a throw, a walk with no frame to
  anchor on — and the summary told all of them that no throw record was found on this stack, which
  is the outcome of a search none of them made. The evidence type said so itself ("No record was
  found, or none was looked for") and the sentence beneath it picked one. "Nothing was looked for"
  is its own state now, carrying which reason applied.

  A recovered record carries **`provenance`**, because finding one does not make it this fault's:
  a C++ `EXCEPTION_RECORD` outlives the frames that held it, so a direct `abort()` deeper than an
  earlier `try`/`catch` finds a valid record above its stack pointer — measured, on
  `docs/samples/stale-throw-abort.dmp`, which is checked in as the negative case. It is `scanned`
  for anything the scan produced and `reported` only when the debugger stopped on the throw itself,
  and the summary never names an uncaught exception on the strength of a scan.

  Two smaller refusals to invent a field. A `0xc0000409` carrying **no parameters** reports no
  subcode rather than defaulting to zero, which is `FAST_FAIL_LEGACY_GS_VIOLATION` and would name a
  security check the record never mentioned — and its summary draws no conclusion either, where it
  had gone on saying "not a stack buffer overrun". That dismissal is what a *known* non-`/GS`
  subcode earns; asserting it from an absent field is the same invention in the other direction,
  and the `/GS` subcodes it would have to exclude are the ones that really are stack corruption.
  And the `0xAABBCCDD` sentinel is **not** read when the
  thrown type was read and is not an `hresult_error`: those four bytes occur inside unrelated
  objects, and what makes a hit believable is the type expecting one, so a type that disagrees is
  contrary evidence rather than absent evidence. That is asked of the **whole** catchable-type
  array rather than of the entry whose name is displayed — C++/WinRT throws `hresult_access_denied`
  and a dozen siblings, one-line derivations that mangle to a name containing no `hresult_error`
  while carrying the base's `m_code` in the object exactly where it has always been. Only a
  complete walk of the bases counts as a disagreement; one that could not be finished leaves the
  sentinel to answer, as it does on a dump with no image at all.

  `decode_error_reporting` also stopped accepting `0xffffffff00000005` as a sign extension — an
  all-ones upper half is only one when the low half's sign bit is set — and its two validation
  refusals are typed, since it declares an `outputSchema`.

  Each **candidate** is checked against what it points at, which is the part that is about the
  record rather than about the stack: a thrown object is copied onto the stack, so one whose
  `object` lies outside the scanned range belongs to no throw on this thread. That rejects the
  stale-abort fixture's only candidate — its `object` is a code address in the faulting image — so
  the tool reports no throw there at all.

  **An exception record's code is decoded as an `NTSTATUS`.** The namespaces overlap and the system
  message table answers for the wrong one where they do: `0x80000003` is `STATUS_BREAKPOINT`, and
  `FormatMessage` reads it as `E_INVALIDARG` — so every breakpoint used to report "One or more
  arguments are invalid". `decode_error_reporting`, given a number of unknown provenance, still
  reports every reading. Relatedly the symbolic-name table had carried `winerror.h`'s **non-Win32**
  `E_*` block (`0x80000001`–`0x80000009`, behind the `#else` of `#if defined(_WIN32)`), whose nine
  values each shadow a defined `NTSTATUS`; they are gone, `0x8000000e` is `E_ILLEGAL_METHOD_CALL`
  rather than `E_STRING_NOT_NULL_TERMINATED`, and a test keeps the two namespaces apart.

  The whole C++ EH decode is laid out at the **target's** pointer width rather than this build's.
  A 32-bit throw raises three parameters where a 64-bit one raises four, its `EXCEPTION_RECORD` is
  80 bytes rather than 152, and `TypeDescriptor::name` is at `+8` rather than `+16` — each of which
  makes a mismatched reader come back empty rather than fail, so a 32-bit fault previously reported
  no thrown object at all. `docs/samples/cppthrow-fastfail-x86.dmp` is the second checked-in
  fixture, and it is where those numbers were measured.

  The width is **two questions**, because a WoW64 process is a 32-bit target that no single call
  will admit is one. `GetActualProcessorType` answers for the physical processor — measured, by
  launching `C:\Windows\SysWOW64\cmd.exe`: `0x8664`, under a 64-bit worker — and it is right for a
  dump, whose header records the machine it was written for. So for a process **running on this
  machine** the OS is asked about it as well, which is the `IsWow64Process2` the worker routing
  already uses; and only for one of those, since a dump's and a TTD trace's recorded process ids
  name a process that exited before the file was written and may since have been inherited by an
  unrelated one — not a query that fails, but one that succeeds about the wrong process. It is not
  a case the routing prevents: a `launch` has no image to parse and no process to ask about until
  after the worker exists, so the supervisor cannot preselect the 32-bit worker for it.

  The stack comes from the **stored crash context** ([dbgscope#144]), so it is the crash whatever
  thread the session has selected, and the selection is left where it was — which is why this is
  annotated read-only where `crash_triage` needed a scope guard. A kernel session is refused, since
  a kernel crash dump carries no stored event at all and its bug check is `crash_triage`'s.

  Two fields report that, not one, because the walk is best-effort and "not from the stored
  context" therefore has two causes. `stored_crash_context` is what the target had;
  `frames_from_stored_context` is what the walk got. Both false is a live target with nothing to
  walk from but the selected thread. The first true and the second false is the case worth seeing:
  a dump written *for* a fault whose own crash context would not walk, which usually means the
  faulting module's image — and so its unwind data — is not where the debugger can read it. One
  bool described that as a target that had no context at all.

- **`decode_error_reporting` — an HRESULT, NTSTATUS or Win32 error as fields**, with the message the
  system's own tables give it: `!error` as a typed call rather than a scrape of an extension's
  output. `FormatMessageW` was measured to answer for both of that investigation's exotic codes
  verbatim — `0x80670015` "The StateRepository cache is not initialized." and `0x80073D54` "The
  process has no package identity." — with `ntdll`'s table beside it for an `NTSTATUS`. Pure: no
  session, no `session_id`.

  It reports every **reading** rather than choosing one, because a bare dword does not say which
  space it came from: severity is one bit as an HRESULT and two as an NTSTATUS, so `0x80670015` is a
  failed HRESULT whose top two bits read as an NTSTATUS *warning*. It takes a sign-extended 64-bit
  value, because that is the shape a WIL fail-fast's HRESULT arrives in — `0xffffffff8000ffff`
  decodes to `E_UNEXPECTED`.

  **An `HRESULT_FROM_NT` value is decoded as the status it wraps.** Bit 28 is `FACILITY_NT_BIT`, so
  `0xd0000005` is `STATUS_ACCESS_VIOLATION` carried inside an HRESULT — and `ntdll`'s table knows
  the status, not the wrapper. Measured: before this, `0xd0000005` resolved to nothing at all while
  `0xc0000005` gave "The instruction at 0x%p referenced memory at 0x%p...", so the whole class came
  back an unexplained number. The bit is reported as `nt_mapped`, the message is the wrapped
  status's, and the text names which value it belongs to. Unwrapped only for a value of unknown
  provenance: bit 28 is `N` in the HRESULT layout and reserved in the NTSTATUS one, so a caller that
  has said "this is an NTSTATUS" has said this bit is not a wrapper — the same gate the well-known
  name is behind.

  **The facility is two fields for the same reason.** An HRESULT's is bits 16..=26 and an
  NTSTATUS's is 16..=27, so bit 27 — an HRESULT's reserved `X` — is inside one and outside the
  other: `0x88070005` is NTSTATUS facility `0x807` and HRESULT facility `0x7`, `FACILITY_WIN32`
  with a reserved bit set that says it is not a well-formed HRESULT at all. A single `facility`
  documented as "where the two layouts agree" was the one place this tool quietly picked a reading,
  and it picked the twelve-bit one for both. `ntstatus_facility` and `hresult_facility` now sit
  beside `ntstatus_severity` and `hresult_failed`, which had the naming right already.

- **`current_location` — the instruction pointer as a coordinate**, and `coordinate` accepted as an
  input by `set_breakpoint`, `run_to_address` and `read_memory`. It answers with the selected
  address, the thread and kernel processor where the target has them, and the containing
  `(module, image identity, RVA)` — the form [`docs/coordinates.md`](docs/coordinates.md) already
  documented on `crash_triage`, `backtrace` and `disassemble` frames, now readable for the current
  position and accepted back as a place to act on.

  **`location_state` names which of four answers this is** — `mapped`, `unmapped`,
  `attribution_failed` or `context_unavailable` — rather than leaving an absent coordinate to be
  read as any of them: a module lookup that *failed* is not the same fact as an address in no
  loaded image, and neither is a position with no thread context at all. A running target is
  refused as a typed `target_running` error, so polling this does not interrupt one.

  Acting on a coordinate resolves it **inside the same serialized engine job that acts on it**: the
  worker finds the unique loaded module, validates its identity and the whole requested range, and
  refuses a missing, ambiguous, unloaded, replaced or out-of-range image. No address cached from an
  earlier pairing is reused. Timestamp and `SizeOfImage` are matching metadata rather than
  cryptographic identity, which is why a SHA-256 the caller has is kept beside them rather than
  folded into them. The Binary Ninja companion that consumes this is maintained in its own
  `binja-windbg-mcp` repository.

### Changed

- `exception_triage` and `decode_error_reporting` join the **`crash`** group (`current_location`
  joins `inspect`), which is why `crash_triage`'s refusal on a user-mode
  session stopped pointing at `backtrace` and `execute`. Those are `inspect`, so a `--tools crash`
  caller — the surface most likely to hit that refusal — was guaranteed to get no pointer with it.
  It names `exception_triage` now, which that caller has.
- The tool surface is **57 tools and 84,506 B** of model context, from 54 tools and 76,386 B at
  v0.15.0 (measured 2026-09-07). `--tools crash` is 13 tools and 19,078 B.
- **A client that offers `2026-07-28` to `initialize` is now answered with `2025-11-25`**, which is
  the SDK's rule rather than this server's. SEP-2567 abolished the handshake in `2026-07-28` — the
  revision travels in per-request `_meta`, and a client on it opens with `server/discover` — so
  `rmcp` 3.2.0 settles every `initialize` on a revision that still has one
  ([upstream #1228](https://github.com/modelcontextprotocol/rust-sdk/pull/1228)). Earlier 3.x echoed
  the offer back, so one client saw two different answers depending on which patch release a
  resolver happened to pick; the dependency floor moves to `rmcp = "3.2.0"` for that reason.

  **Nothing changed for a client that opens the way `2026-07-28` prescribes.** `server/discover` and
  per-request `_meta` are served exactly as before, and so are `tools/list` and `tools/call` on that
  path over `--listen`. What changed is the answer to a *handshake*, and two things follow from it.
  SEP-2549's `ttlMs`/`cacheScope` accompany the revision actually in force, so they no longer appear
  after a handshake that negotiated down — the `tools/list` payload is 216,839 B against 216,895,
  which is those three fields' 56 bytes and nothing else. And on `--listen` such a handshake now
  mints an `Mcp-Session-Id` and is leased like the legacy client it is. So "a client on
  `2026-07-28`" means one that opens the way that revision prescribes, never one that merely names
  it somewhere.

[dbgscope#144]: https://github.com/glslang/dbgscope/pull/144

## [0.15.0] - 2026-09-04

### Fixed

- **A dump or trace that had not finished loading is no longer reported as an open that worked.**
  `open_dump` and `open_trace` defer the real work to the next `WaitForEvent`, so
  `wait_for_event(LOAD_WAIT_MS)` *is* the load — and dbgscope's finite wait used to answer
  `Result<(), _>`, flattening `S_FALSE` (the 60-second bound passing with the load still going) into
  the same `Ok` a completed load gets. A dump too large, or a symbol path too cold, to finish inside
  that bound therefore came back as a successful open, and whatever the caller did next failed for a
  reason nothing connected to it. Nothing here could have caught it: the fact was discarded inside
  the wait.

  dbgscope now returns a `WaitOutcome` ([dbgscope#136](https://github.com/glslang/dbgscope/issues/136)
  stage 1) and `worker::load_completed` reads it — only `Stopped` is a load that finished. The
  failure is reported **post-commit**, which is what the `commit()` already sitting above the wait
  was for: the caller is told the session holds the target, so `end_session` is the recovery and
  opening again would claim a second one. A host interrupting the load reports the same way. The
  `Expired` arm is **unmeasured against a real engine** — holding a dump load past sixty seconds is
  not something a test can arrange — so `a_load_that_did_not_finish_is_not_an_open_that_worked`
  asserts the mapping, and nothing claims how often it fires.

- **A session no longer opens a console window on the desktop.** Windows gives a console-subsystem
  child of a console-*less* parent a brand-new, *visible* console — and a GUI MCP client starts a
  stdio server without one — so every engine worker this server spawned put a window on the desktop,
  titled with the exe's path and taking the foreground as it appeared. At the rate a model opens and
  ends sessions (`MAX_SESSIONS` is 4, so a fifth open reclaims one) that is a machine nobody can
  work at, which is [#273](https://github.com/glslang/windbg-mcp/issues/273). The worker and the
  `TTD.exe` recorder are now spawned with `CREATE_NO_WINDOW`.

  **Only when this process has no console of its own**, which is not a refinement but the whole of
  it. The flag does not suppress a console — it suppresses the *window*, by giving the child a
  console of its own — and a worker's stderr is *inherited*. A console handle passed to a process
  attached to a different console is re-bound to that one: measured here, such a child's write
  reports success, bytes written and no error, and the text lands in its own invisible console
  rather than in the terminal. Applied unconditionally the flag would therefore delete every worker
  log line from a terminal-run server, silently, and make the log ring's "they are still on the
  server's stderr" untrue. So it goes on exactly where it changes something: with no console there
  is nothing to inherit and nothing for stderr to lose (a pipe or a file is inherited unchanged),
  and with one the worker shares it and opens no window anyway. `attached_to_a_console` asks
  `GetConsoleProcessList` rather than `GetConsoleWindow`, which answers "no console" for a ConPTY —
  Windows Terminal, and this repo's own harness — and would apply the flag to a worker holding a
  live console handle.

  Two assertions, and the unconditional version fails both: `engine.rs` checks that a child spawned
  with a worker's flags **joins this process's console**, and the debugger tier checks the same of a
  real session's engine pid, read from `session_status`. A *debuggee* launched by `launch` gets its
  window from DbgEng rather than from here; that is
  [dbgscope#129](https://github.com/glslang/dbgscope/issues/129), fixed there.

- **The rule that no process is created without the spawn lock was checked by a marker that could
  not see half of them.** `Command` spawns and waits in one call through `output()` and `status()`
  as well as through `spawn()`, and `service::icacls` used the first of those — so
  `every_process_spawn_in_this_crate_takes_the_spawn_lock` reported no unguarded spawns over a
  source tree that created a process it could not see. Its own name was half of why that stayed
  invisible — the rule is about a *process being created*, and `spawn` is only the spelling that
  says so — so it is now `every_process_created_in_this_crate_takes_the_spawn_lock`.

  Harmless where it stood — `icacls` runs from the install and client-editing commands, in a
  process that serves no session and spawns no worker — but that is a property of today's call
  sites rather than of the rule, and the lock exists because a handle is inheritable **process-wide**
  from the moment it is marked: a child started inside a worker's spawn window inherits that
  worker's protocol channel and keeps the pipe from ever reporting EOF, so the session never
  settles. `icacls` now takes the guard, and the marker counts the two fused calls.

  They are matched **only inside a function that also constructs a `Command`**, because
  `response.status()` is an HTTP status in `listen::gate` and an unanchored marker demands the
  spawn lock there — verified by removing the anchor, which lights up both lines. `spawn()` stays
  unanchored: it is specific enough alone, and anchoring it would open that same hole in the half
  that is load-bearing today. Each half is counted and asserted separately, since a marker that
  matches nothing passes.

- **A session handle that a raw `execute` retired can still end its own session.** `qd`, `q`,
  `.detach`, `.kill` and `.opendump` release or replace the target, which *retires* the handle
  naming that session: every later call supplying it is refused, while the worker stays live and
  reachable by a call supplying none. `end_session` was not exempt, and two things did not line
  up. The `execute` that retires the handle appends "`end_session` releases it", and `end_session`
  with that handle was refused one call later — the server contradicting its own instruction. And
  the recovery the refusal named, omitting `session_id`, routes to whichever session is *current*,
  so with anything newer open it reached a different one. The retired session could then not be
  released by its owner at all: it held one of the four sessions and a live engine process with a
  live target until everything newer had gone, or a client disconnect, or a lease expiry.

  A teardown does not touch the target retirement is about — it releases the **session**, which
  the handle still names exactly — so it is now admitted, through a
  `SessionState::accepts_teardown` of its own rather than a second caller of `accepts_default`,
  whose set is the same today but whose question is different. Both places a handle is checked had
  to widen together, the caller-side `Sessions::resolve` and the `Gate` at the front of the
  session's queue; backing either half out alone was tried and fails the same way, because
  widening one only moves the refusal to a place with no caller to explain it to.

  The refusal's own text changed with it: it names `end_session` **with the handle in it** as the
  recovery that always works, and mentions omitting `session_id` second and qualified — "only
  while this is still your current session" — since unqualified it reads as a way back to this
  target and is a way to act on another.

  Found by the session fuzz added below, on the second seed it ran under, and covered by
  `a_handle_a_raw_command_retired_can_still_end_its_own_session`. The second launch in that test
  is the test rather than scenery: with one session open the retired one is still current, so an
  un-handled `end_session` reaches it and the defect is invisible — which is why no
  single-session test had ever seen it.

### Changed

- **An abandoned launch no longer leaves its process to the next one.** dbgscope
  [#141](https://github.com/glslang/dbgscope/issues/141): dropping a launch guard before anything
  pumps does not un-queue its `CreateProcessWide`, so that process still arrived and was claimed by
  whichever launch asked next — whose `wait()` then returned for a target it never asked for. The
  entry now stays until its own create is accounted for, and a launch whose wait timed out is
  discarded rather than kept.

  **Unreachable from here, and that is a property rather than luck**: each opener in `worker.rs`
  creates one `PendingTarget` and waits on it inside the same closure, so this server never abandons
  a launch guard and never has two launches pending at once. The bump is the pin alone. What is
  still open upstream is *identification* — which of two simultaneous launches gets which process —
  declined there for the same reason it cannot arise here.

- **The debug engine no longer claims to cross threads.** dbgscope
  [#136](https://github.com/glslang/dbgscope/issues/136) stage 4, the last of that refactor, deletes
  `unsafe impl Send` and `unsafe impl Sync for DebugEngine`. Both asserted the opposite of what that
  crate says about itself — `SetInterrupt` is the one DbgEng call documented as safe from any thread
  *because the rest of the engine is single-thread-affine* — and neither carried a safety comment,
  because neither could have been given a true one. `InterruptHandle` is now its only `Send + Sync`
  type: one `SetInterrupt`, from anywhere, and nothing else.

  **A breaking change upstream that this server does not feel**, which is worth separating from "no
  behaviour changed": a worker builds its engine in `worker::build_engine`, on the engine thread
  that then uses it for the whole of that worker's life, so it never needed either bound. That was
  measured before the change rather than after — removing each and building leaves this crate
  compiling unchanged.

- **The engine's arrival bookkeeping is a delivery register rather than an engine-wide record.**
  dbgscope [#136](https://github.com/glslang/dbgscope/issues/136) stage 3: an open registers what it
  is waiting for, a stop is routed to the first open that wants it and has nothing yet, and the
  entry dies with the guard that made it. That deletes the three lifecycle rules the record it
  replaces needed — pruned at both openers for pid reuse, cleared where a session is replaced and
  cleared again where one is ended — because nothing outlives its reader any more. It also makes two
  opens pending at once exact where they were ambiguous, which the type it replaces had documented
  as an accepted cost.

  **No behaviour of this server moves**, which is worth stating rather than leaving to be inferred
  from a green suite: a worker holds one target for its whole life and `EngineOp` has no second
  opener, so every case the register newly tells apart is one this server cannot reach. What the
  bump buys is the correctness of the layer underneath, and the shapes it makes safe to add. No
  public API changed either, so this is the pin alone.

- **A break this server asks for is now scoped to the engine operation it will stop.** dbgscope's
  interrupt was an engine-wide flag that each bounded operation cleared as it opened, so a request
  lodged between that clear and the wait it was meant for was erased while its `SetInterrupt` was
  still on the way — and the synthetic Ctrl+Break that then arrived was reported as the target's
  own stop. This server reaches that path: `interrupt`/`break_in` raise the break from the request
  reader, off the engine thread, while a live open runs on it.

  Closed upstream by [dbgscope#135](https://github.com/glslang/dbgscope/issues/135) /
  [#136](https://github.com/glslang/dbgscope/issues/136) stage 2: the request is filed against the
  operation running at that instant, under the same lock that delivers `SetInterrupt`, and there is
  no clear anywhere. Nothing about this server's tool surface changes —
  `worker::interrupt_running` now logs which operation the break was filed against, and
  deliberately does **not** turn that into a different answer for the caller: `NothingRunning`
  means the *engine* had no bounded operation to file against (a typed getter, a plain
  `execute_command`), not that the session is idle, and the break is delivered either way.

- **`set_breakpoint` no longer runs `bp` as text**, and its result is a different shape as a result.
  It now goes through dbgscope's typed breakpoint API
  ([dbgscope#126](https://github.com/glslang/dbgscope/issues/126)), which hands back the breakpoint
  it created — so `breakpoint` carries the id, the address, whether it is `deferred` and the command
  it runs, all read off the engine rather than inferred. What that replaces is an `added` list
  recovered by **diffing `bl` either side of the `bp`**, since a successful `bp` prints nothing at
  all, plus the two fields (`listed`, `listing_error`) whose whole job was to say the diff might be
  unavailable and an empty `added` therefore *unknown* rather than empty. None of that can arise
  now. `replaced` is new: setting a breakpoint where one already is removes it — what `bp` has
  always done, previously visible only as a `breakpoint N redefined` line in debugger text — and the
  ids it took are now a value a caller can act on.
- **`ioctl_trace` returns a structured result**, having previously answered with whatever its `bp`
  printed, which on success was nothing at all (`FOLLOWUPS.md` item 57). It installs its logging
  breakpoint through the same typed op and reports the same `BreakpointSet`, with an `outputSchema`
  to match — a structured-aware client replaces the text block with `structuredContent`, so sending
  one without declaring a schema would have handed those clients an undeclared shape and taken their
  text away.
- Both tools' **command strings stopped being escaped by hand**. `ioctl_trace` built
  `bp <dispatch> ".printf \"IOCTL %08x …\", …; gc"` as one string, so every quote was `\\\"` and the
  newline `\\\\n` inside a Rust format string, and the `dispatch` operand had to be screened for `;`
  and `"` because either would have closed the quote and appended a command of the caller's
  choosing. A command reaches the engine as a parameter now, where a `;` separates nothing and a `"`
  opens nothing. `reject_command_breakers` stays on `set_breakpoint`'s expression as defence in
  depth rather than as the only defence.
- A breakpoint's **watched region** is reported where it has one — `watch: {access, size}` for a
  data breakpoint, which the read side could previously say only that a breakpoint *was*.
- `set_breakpoint` takes **`one_shot`**, which removes the breakpoint the first time it is hit.
  This was reachable before by putting `/1` in `expression`, and only because the expression was
  interpolated into `bp {expression}`: `/1` is not a location, so it could not survive the move to a
  typed setter and has a parameter of its own.
- `set_breakpoint` also takes **`pass_count`**, `bp`'s trailing `Passes` argument, reachable
  through `expression` before for the same reason. Its remaining options have no typed equivalent
  and are not added: `/p`, `/c` and `/C` have no setter on the engine's breakpoint interface at
  all, and `/t` takes an ETHREAD pointer where the engine's thread filter takes its own thread id —
  a different thing rather than a spelling of it. A raw `bp` still reaches those. Together the two
  parameters cost 839 B of model-visible surface, which is all the model pays for this change.

- **Every raw command this server runs is now bounded, except `index_trace`** (`FOLLOWUPS.md`
  item 14). `threads`, `goto_position`, `driver_object`, `device_object`, `irp_stack` and
  `ioctl_trace` moved from `EngineOp::Command` to `EngineOp::BoundedCommand`, so a command that
  runs away — `!drvobj` against a live kernel whose symbols are being fetched one frame at a time,
  a `!tt` seek into a trace with no index — now Ctrl+Breaks itself ahead of the caller's timeout
  and answers with the output it had, instead of holding its session's engine until it finishes.

  The split those six were on the other side of was decided on cost, not on principle: dbgscope's
  watchdog polled a `done` flag on a 200ms sleep, so the join waited out the rest of the nap and
  arming one rounded a command up to `ceil(d / 200ms) * 200ms` — a 30ms `k` became a 200ms `k`, and
  a session issues those by the dozen. That was worth a stated criterion and a list either side of
  it. It is not worth anything now: the `Watchdog` in the pinned revision parks on a `Condvar`, so
  the disarm is immediate and the bound costs nothing until it is reached. Re-measured through the
  tool surface before deciding, twice (x64 bench, sample dump, 20 rounds): a bounded `lm` medians
  3.0ms and 3.3ms against the unbounded `modules` beside it at 4.1ms and 4.2ms, and a ~170ms `.for`
  loop costs ~171ms and ~185ms rather than 200ms. The old second mode — where `lm` raced the
  watchdog's first poll and landed on either ~0.3ms or ~200.7ms run to run — did not appear.

  It arrived through the [#226](https://github.com/glslang/windbg-mcp/issues/226) work rather than
  through anything aimed at this entry: the sleep was what made a *finite* `WaitForEvent` look
  attractive, so fixing that defect retired this trade-off as a side effect and nothing here was
  revisited when it landed.

  `index_trace` stays out, and is now the only op that is. `!ttdext.index -force` deletes an
  unloadable `.idx` before rebuilding it, so a break part-way through can leave a trace with no
  usable index at all — the one case where the abort is worse than the wedge, and one whose long
  run is productive work that frees the session when it finishes. What was the general "raw
  command" op is renamed **`EngineOp::UnboundedCommand`** to say so at the call site, and
  `server::tests::only_index_trace_runs_a_command_unbounded` holds it to its single caller by
  reading the source — because the way a collapsed split comes back is a tool added by copy-paste
  taking the unbounded path with nobody deciding to, and that tool works perfectly until the day
  its command runs away.

- **`set_breakpoint` runs its `bp` on the caller's clock too.** `EngineOp::SetBreakpoint` carries a
  `patience_ms` and the command goes through `execute_command_bounded`. The address is the caller's
  text and `bp` makes the MASM evaluator resolve it, so `bp nt!Foo+0x10` against a deferred module
  with a `srv*` path is a symbol-server fetch with this session's engine held for all of it — the
  wedge the bounded path exists to stop, reached through a **typed** op where nothing in the name
  said there was a command inside. The `bl` reads either side of it stay unbounded, being direct
  engine calls with no `Execute` to break.

  It survived the first draft of the change above, whose rule was stated over ops and whose test
  certified ops, so both missed it. `worker::tests::every_unbounded_execute_in_this_worker_is_accounted_for`
  is the correction: it reads the source for `Execute` calls rather than for enum variants, and
  enumerates the five functions that legitimately run one unbounded — the two openers' fixed
  strings, the resume pump's own `Execute`, and the two that are deferred with items against them.
  Verified by backing the fix out, which names `set_breakpoint`.

  Enumerating rather than reasoning about it turned up a second instance the review did not:
  `worker::resolve`'s `? <expr>`, also caller text, filed as `FOLLOWUPS.md` item 56 rather than
  fixed here because its three callers sit on three different clocks and one of them is item 13.

  **And bounding it added a third state the result had no way to say**, which is
  `structured::BreakpointSet::cut_short`. An interrupted command comes back as an `Ok` run, so a
  `bp` that never finished looked from the caller's side exactly like one that ran and matched
  nothing — the same empty `added`, the same successful result, rendered as "(this call added
  none)". The two have opposite next moves. The listing is a real engine read taken afterwards, so
  `added` settles which happened — non-empty is a breakpoint that landed before the break and must
  **not** be re-requested. Empty settles nothing on its own: without a listing, which of the
  session's breakpoints is new is unknown, and *with* one it is still not evidence the expression
  is unset, because a `bp` at an address that already carries a breakpoint adds no id either. So
  the result says what the diff says and sends the caller to the listing for the rest. Reported in
  both channels — a structured-aware client drops the text — and it stays a success rather than an
  error, because an error is the shape a caller retries.

  That last point turned up a fact this module states as a universal and which is only half true.
  Measured on a live target: `bp ntdll!NtCreateFile` three times leaves **one** breakpoint, and
  `ntdll!NtClose+0x2` twice leaves one, because a resolved breakpoint is keyed by address — while
  `bp nosuchmod!Sym` twice leaves **two**, since a deferred one has no address to key on. `bp`
  duplicates exactly when its expression does not resolve, which is the same condition that makes
  one slow enough to be cut short in the first place. The warnings stay; what changed is that they
  are accurate about why, and no longer claim a retry is safe when the diff cannot know it.

  **One field for both causes**, unlike a stop's `interrupted`/`timed_out` pair: the `interrupt`
  tool reaches this command as readily as the deadline does and leaves the session in the same
  state, so reading only the deadline reported an interrupted `bp` as a completed one — and on the
  branch where the listing had also failed, as a breakpoint positively "set". A stop keeps the two
  apart because the next move differs there; here it does not, and `added` answers what the cause
  would only hint at.

### Added

- **`arming_the_watchdog_does_not_round_a_quick_command_up`**, in the debugger tier, guarding the
  assumption the rule above now rests on. The measurement it was extracted from
  (`measure_what_the_bounded_path_costs_a_quick_command`) is `#[ignore]`d, so it went on passing
  across the very change it exists to catch — the quantization it describes had been gone for six
  days. This one is in the debugger tier — it opens the sample dump, so a plain `cargo test`
  stands it down — and is *not* `#[ignore]`d, which is the difference: CI runs it on all three
  runners. Its oracle is a **ratio between two bounded commands of very different natural cost**,
  an `execute` of `lm` against an `execute` of a ~170ms `.for` loop, failing if they come within
  5x. That is what a fixed quantum destroys — rounding both up to a multiple of the nap makes them
  equal, where without one they stay ~50x apart — and it scales with the host, unlike the first
  version's bounded-against-unbounded margin, which a slow enough baseline grows into. The
  measurement keeps the numbers and its comment now records them.

- **A session fuzz in the debugger tier** — dbgscope's `examples/session_fuzz.rs` brought up to
  this server's surface. That example drives randomised command sequences straight at a
  `DebugEngine` and checks, after every one of them, that the session either still holds a target
  and answers or says it holds none; it exists because the three defects behind
  [#242](https://github.com/glslang/windbg-mcp/issues/242) were each found by hand, one sequence at
  a time, and none of them is about a *command* — they are about the state the previous command
  left behind, and there are more ways to reach a given state than anyone enumerates.

  What the port adds is everything between that engine and a caller. A **third state**, since
  `continue_async` leaves a target moving with nobody waiting and reads are then refused
  `target_running` — the supervisor's state machine
  ([#83](https://github.com/glslang/windbg-mcp/issues/83)), which the example cannot reach. The
  **category** a refusal carries rather than merely that it refused. A **bystander session** on the
  same server, never named by a step and asked after every round, which is the process-per-session
  claim no in-process test can make. And reclamation of whatever the sequence left.

  Its oracle is a **scale rather than an agreement**: a bounded run can stop between one road into
  the session and the next, so what is forbidden is a road moving back down
  `Moving → Holding → Gone` — `stale_session` and then an answer is the half-dead session, while an
  answer and then `stale_session` is a program that finished a millisecond ago. The seed is fixed,
  so CI walks one short deterministic sequence on all three of its `dbgeng.dll`s; the fuzz proper
  is a soak of the same test, and the run prints the states it reached and asserts it reached the
  terminal one, because a walk that never left `Holding` would pass without asking the question.
  `docs/smoke-test.md` has the soak command and what it does and does not assert.

  It found one thing on the second seed it ran under, left standing as `FOLLOWUPS.md` item 55: a
  handle that a raw `execute` has **retired** cannot release its own session, while the `execute`
  that retires it appends "`end_session` releases it" — and the recovery its refusal names, omitting
  the handle, routes to the *newest* session instead. Measured on the release build with two
  launches, the older retired by `qd`.

### Documentation

- **`FOLLOWUPS.md` holds only what is still open; what has landed moved to `DONE.md`.** Thirty-three
  of its fifty-five entries were finished work, so two thirds of a file read for "what is left" was
  answering a different question. The entries move **in full and under the numbers they were filed
  with** — `CLAUDE.md`, `CHANGELOG.md`, `docs/*.md`, `ci.yml` and `build.rs` all cite them as
  "`FOLLOWUPS.md` item N", and those are prose references that renumbering would break without
  failing anything — so `FOLLOWUPS.md`'s numbering is now sparse and its header is what answers
  *which file*, above every entry. Neither file is in the markdownlint globs, so neither is checked
  by CI.

  **Citations are deliberately not retargeted**, and `every_followups_citation_names_an_item_that_exists`
  is what makes that safe: it reads every text file in the repository and fails if a cited number is
  in neither file, if a number is in both, or if `DONE.md`'s index has fallen out of step with its
  entries. Some twenty files carry that string — doc comments in eleven modules and in `tests/`,
  `DECISIONS.md`, every `docs/*.md`, `build.rs`, `ci.yml` and the eval tooling — so a citation whose
  file half followed the entry would make every close a sweep of source comments, unchecked, and one
  that had to be repeated on the next close. The number is the name; which file holds it is the
  landing page's answer. Proved by breaking it three ways: an entry renumbered, an index line
  dropped, and an anchor corrupted.

  Two shapes deliberately stayed: an item **measured and declined** (27, 35), where nothing was
  built and the reopening condition is the content, and one that **half** landed (50), whose entry
  narrows to the half that is left rather than splitting across two files.

- **`DECISIONS.md`'s bounded-command entry (2026-08-02) is superseded by its own revisit trigger**,
  and says so above the criterion rather than only in its Status line. The criterion stays as the
  record of what the tax bought while it stood; `FOLLOWUPS.md` item 14 moves to `DONE.md`. Two
  boundaries the entry now states explicitly, because both have been mistaken for the split before:
  the typed ops carry no `patience_ms` because there is no *command* for a watchdog to break, and
  `reachable_from_dispatch` is a job-level deadline and still item 13.

## [0.14.0] - 2026-08-30

### Added

- **`modules { "refresh": true }` resynchronises the debugger's module inventory before it lists
  it** ([#85](https://github.com/glslang/windbg-mcp/issues/85)). DbgEng's inventory is the
  *debugger's*, not the target's: it is built from the module-load events the debugger saw, so it
  is complete for a dump and for a process the debugger launched, and it is not complete for a
  live kernel — an attach starts from what it can read at connect time, and a driver loaded before
  the debugger dialled in is in the target and missing from the list. On the MessageManager
  regression target that meant `nt` and little else, and a `modules` call straight after the attach
  read as "the challenge driver is not loaded" while the driver was open and serving IOCTLs.
  Measured on that target on 2026-08-30, across one attach: the engine held **1** module, a
  `modules { "filter": "MessageManager" }` matched **0**, and the same call with `refresh: true`
  reported `before: 1` against **158** loaded and matched the driver at `0xfffff80343970000` —
  `deferred`, so it was found without a byte of PDB being fetched.

  The resynchronisation was always available — it is what an unqualified `.reload /f` was doing as
  a side effect of fetching every module's PDB — and nothing said so, so finding a loaded image
  meant guessing that a force symbol reload was the missing step. This is that half on its own, and
  the tool says which half it is: it discovers modules and **fetches no symbols**, so what it finds
  comes back `deferred` with no symbol-server round trip.

  The result carries `refresh` — `synchronized`, the `before` count against `loaded` after it, and
  the engine's own `error` where it failed. Three things worth knowing. **Absent means it was not
  asked for**, which is not the same as one that found nothing, so a default call is unchanged in
  both channels and still cheap. **A failure is reported, not raised**: the listing beside it may
  well be the right one, so the answer stands and the text says so *above* the tables — a caveat
  printed under a listing arrives after the conclusion it was there to prevent — and withdraws the
  only inference the listing supports, that a module absent from it is absent from the target. And
  **on a live target it costs the symbol state**: a reload discards what the engine had loaded
  and reloads it as needed, so most modules come back `deferred` — measured on a launched
  `cmd.exe` either side of a `.reload /f`, where four of its five modules went `pdb` → `deferred`
  and `ntdll` kept its PDB. A **dump** pays none of it: its module list comes from its own header,
  so there is nothing to re-read, and `nt`'s PDB survives a refresh with the other 226 modules
  `deferred` either way. So refresh first and load symbols afterwards on anything live —
  [`docs/structured-results.md`](docs/structured-results.md) has the two reloads side by side and
  both measurements.

- **Asynchronous execution control: `continue_async`, `wait_for_stop` and `break_in`**
  ([#83](https://github.com/glslang/windbg-mcp/issues/83)). `go` waits for the next stop and answers
  with it, which leaves no room for the sequence a live target usually needs — arm a breakpoint,
  resume, *make the thing happen that trips it*, then collect the stop. `continue_async` resumes and
  returns at once with an execution handle; `wait_for_stop` collects the stop whenever it comes; and
  `break_in` ends a run that is not going to reach anything. A guest-side `Sleep` was the only way to
  express the middle step before, and it is not a sound one: a kernel halted in the debugger has a
  halted clock.

  The wait that goes away is the **caller's**, not the debugger's. DbgEng moves a target only from
  inside `WaitForEvent`, so the engine thread stays in the pump for the whole run — what changed is
  that the worker reports the target moving as a milestone, and the reply that follows is the stop,
  filed against the handle by a task that does not care whether the caller is still there. So there
  is no hidden wait anywhere: the run is recorded on the session before the job is queued,
  `session_status` reports it, and `max_run_ms` says when the debugger will end it itself.

  Consequences worth reading before using it. **One run per session**, because a second could not
  start until the first ended. **While the target is moving, every tool that reads it is refused**,
  with a new `target_running` category and the handle to wait on — refused rather than queued, since
  a queued `registers` would be answered whenever the target next stopped and would describe
  wherever it happened to be. **A wait that runs out is a poll**: no stop, nothing cancelled, the
  handle still good. **A stop is read rather than taken**, so a client that disconnected mid-run can
  reconnect and read it. **A break is bound to the run it was asked about**, so one aimed at a run
  that has since stopped is refused rather than landing on whatever the engine started next — and
  one aimed at a run that has not *started*, because something else is still on the engine, bars it
  from ever setting the target going. `requested` then answers the wide question — *is this run
  going to stop* — so a break raised, one already lodged and a barred run are all `true`, as is one
  whose run finished on its way to the engine. `false` means the run had already stopped **when the
  call looked**, which is the ordinary race; a break that could not be *delivered* is an error
  rather than a `false`. **A run's clock starts when the target
  moves**, not when it was asked for, so one waiting its turn reports no elapsed time and its whole
  bound rather than a bound already counted down. And `end_session` reaches the target whether the run is pumping or still
  queued — it breaks the pump in as it arrives, and bars a resume that has not started — rather than
  queueing behind a run that has no reason to end, which is the same path a client disconnect takes.
  [`docs/sessions.md`](docs/sessions.md#running-a-target-asynchronously) has the whole of it.
- **A stop says which thread, and which processor.** `StopReport` — what `go`, the stepping tools
  and `wait_for_stop` all answer with — now carries `thread` (the operating-system thread id the
  position belongs to) and `processor` (which of a kernel target's processors it is on, absent where
  no processor number applies, which every user-mode target is). A position on its own does not
  identify a stop on a multi-threaded target, and the alternative was parsing `~.`, whose text is
  one shape for a thread and another for a processor. Both come from new typed `dbgscope` readers.
- **`pool_find_tag` can answer existence and bounded-cardinality questions without walking the
  entire kernel pool** ([#86](https://github.com/glslang/windbg-mcp/issues/86)). Pass the nonzero
  `stop_after_matches` threshold to stop a newly started walk as soon as that many matching
  allocated chunks are decoded. The result reports `walk.coverage: "match_limit_reached"` and
  echoes the threshold in `walk.stop_after_matches`; its counts and byte total are explicitly
  floors. These deliberately partial snapshots are never cached as exhaustive. A complete cached
  snapshot is still reused and stays complete, while `limit` remains the independent rendering
  cap. The `debug_batch` `pool_find_tag` step accepts the same field.

- **The per-call result budget is charged against every channel a result carries, not only the
  half this client forwards** ([#150](https://github.com/glslang/windbg-mcp/issues/150)).
  `tool_results_stay_within_their_budget` now asserts a tool's model ceiling against
  `content[].text` and against `structuredContent` separately, so a typed tool is checked twice
  and the failure names which channel moved; the `wire` ceiling that landed with #149 still covers
  the result taken together. The printed table gains a `worst` column — the larger of the two
  halves — beside the ceiling it is compared against.

  This closes the half of #150 that was deferred for want of a second client to measure. The
  deferral had the wrong shape: a second client would say what one more implementation happens to
  do, which is a sample and not a rule, and inferring a server's budget from a client's forwarding
  policy is the same step that left the rendering unwatched in the first place. The text-forwarding
  client was also already in this repo's own compatibility matrix — `structuredContent` arrived
  with `2025-06-18`, this server serves `2025-03-26` and `2024-11-05` beneath it, and the channel
  is not gated on the negotiated revision, so for those two the rendering is not the half a client
  happens to forward but the only half it can read.

  No ceiling moved. `session_status` is the one budgeted typed tool whose rendering is larger than
  its typed answer (423 B against 301 B, identical on both CI runners), so it is the only row now
  measured against a number the old assertion never saw; elsewhere the typed half is the larger one
  and the new check restates the old. Which is what a floor under a channel nothing has yet grown
  looks like.

### Fixed

- **Documentation: `!analyze`'s module attribution is a fact about the debugging host, not about
  the dump.** Four documents and a smoke-test fixture said the two checked-in driver crashes
  disagree about it — that `MessageManager` has no PDB so `!analyze` reports `Unknown_Module`,
  while `HEVD` ships one so `!analyze` blames it by name. Measured on one engine against both
  dumps, they behave identically, and what decides it is whether `triage\triage.ini` is beside the
  engine (`skills/windbg-debugging/setup.md` copies it as a step of its own): with it, each crash
  is attributed to its driver; without it, both report `Unknown_Module`; with no `winext\` either,
  `!analyze` does not run at all. A missing PDB costs the *function* — both failure buckets end
  `!unknown_function` whichever way that falls.

  The same correction reaches the `0x9F` walkthrough, where it changes the reading rather than just
  the wording: with `triage\` bundled that dump is attributed to `pci` —
  `0x9F_3_ACPI_IMAGE_pci.sys` — which is the **bus driver** the walkthrough's own device-stack walk
  identifies as *not* the culprit. So the manual walk is required either way, and what a bundled
  engine changes is whether `!analyze` declines to answer or answers with the wrong layer.

  `a_driver_crash_names_the_driver_frame_an_all_kernel_walk_would_miss` now asks the host
  (`triage\triage.ini` beside the server) instead of carrying a per-fixture flag, and asserts on
  both sides of that rather than skipping either. It had never run: `ci.yml` copies no extension
  directory, so `analysis.ran` is false on both runners and every `!analyze` assertion in that tier
  is skipped there.

- **A transcript no longer records an interrupt that reached nothing as one that was delivered.**
  `WINDBG_MCP_TRANSCRIPT`'s `interrupt` event took `delivered` from whether the request succeeded,
  and four of the five things an interrupt can do succeed while raising nothing — there was no
  operation running, a `debug_batch` was sealed for its rollback, or a break was already pending.
  The worker now says which it was, so the transcript records a cause that happened. This matters
  because that event exists precisely to explain a *later* truncated result; one logged against a
  break that was never raised attributes a short answer to a request that did nothing.
- **`record_trace` finds the recorder the engine copy already delivered.** `setup.md`'s one-time
  engine bundle takes the whole `ttd\` directory, and that directory carries `TTD.exe` as well as
  the replay DLLs — but `find_ttd` probed `PATH`, the SDK layout and `WindowsApps` and never its
  own directory, so the one layout this project's own documentation tells people to create was the
  one it did not know. A host bundled exactly as documented could replay a trace and not record
  one, unless the recorder was *also* put on `PATH`. It now probes the bundle beside the
  executable, ranked below `PATH` so that override still wins
  ([#131](https://github.com/glslang/windbg-mcp/issues/131)) and above the machine-wide installs,
  since the payload next to the binary is the pair to the engine the loader actually gives this
  process.
- **A symbol path can now seed later sessions without coupling running workers
  ([#66](https://github.com/glslang/windbg-mcp/issues/66)).** `set_symbol_path` accepts
  `for_new_sessions`: `true` remembers the successful `path`/`append` setting for this client's
  future opens, `false` clears it, and omission keeps the existing session-only behavior. The
  supervisor applies that starting state on the new worker's engine thread before its opener; it
  never broadcasts a reload or path mutation to sessions already running, and listener clients
  cannot inherit one another's host paths.
- **`end_session` stops accepting work when its teardown reaches the front of the session queue
  ([#64](https://github.com/glslang/windbg-mcp/issues/64)).** The pump now marks the session closed
  immediately before forwarding `EndSession`: calls already ahead of it still run, while calls
  submitted behind it are refused as `stale_session` instead of reaching a target that has been
  released or creating a replacement target in a worker that is about to exit. Once teardown
  finishes, the provisional closed reason is refined with whether the target was released, the
  worker was parked, or it was already gone.

### Documentation

- **The WinDbg engine payload has three sources, not one, and the two that need no interactive
  install are now first-class** (issue
  [#132](https://github.com/glslang/windbg-mcp/issues/132)). TTD `.run` replay needs a `ttd\`
  directory beside `windbg-mcp.exe`; System32's `dbgeng.dll` ships none of it, the SDK Debugging
  Tools do not either, and MSIX registration fails from a non-interactive session
  (`Add-AppxPackage` → `0x80070005`, even elevated) — so a host reached over SSH could record
  traces and not replay them. `setup.md` had carried the way through since #133, as an appendix
  headed *when the store package will not install*; it is now source (b) of three named up front,
  because the store package's `InstallLocation\<arch>` and the unpacked `.msixbundle`'s `<arch>\`
  are the **same layout** — so the three sources differ only in how they set `$wd` and the copy
  after them is one block rather than two. What decided it was that this repository's own TTD smoke
  tier already runs against an engine bundled that way, so the route the documentation held at
  arm's length was the one its coverage stood on.
- **That recipe did not work, and had not since the day it was written** (`8bd98a5`, 2026-08-16).
  Its first line read the `.appinstaller` with `(Invoke-WebRequest …).Content` and cast it to
  `[xml]`; under Windows PowerShell 5.1 that property is a `Byte[]` for this content type, so the
  cast threw and nothing was downloaded at all. It now fetches to a file and reads it back with
  `Get-Content -Raw`, which is version-proof. Found by running it end to end for the first time, on
  the ARM64 host the issue was filed from — which also measured what the endorsement rests on: the
  bundle verifies as `Valid` / `Authenticode` / `CN=Microsoft Corporation`, is 1,188,564,441 bytes,
  and **all three** payload trees inside it (`amd64\`, `arm64\`, `x86\`) hold the entire copy
  list, `msdia140.dll` included — plus `ttd\TTD.exe`, so the engine copy already brings the
  *recorder* and not just the replay engine, which `setup.md` and `docs/install.md` now say. The
  recipe gains a publisher check before it unpacks anything, `setup.md` states what that settles
  (provenance) and what it does not (that an unregistered payload is a supported Microsoft
  configuration), and the update advice now says to clear the four wholesale-copied directories
  first — `Expand-Archive -Force` and `Copy-Item -Force` overwrite collisions and delete nothing,
  so re-running merges a new payload into the old one rather than replacing it. That bench was then bundled from the payload and **replays**: a 40 MB trace
  recorded with the bundled `ttd\TTD.exe`, opened by `open_trace` reporting its lifetime rather
  than the missing-`ttd\` diagnostic, and stepped backward with `step_back`. The issue is closed
  on the host it was filed from, and `FOLLOWUPS.md` item 47's blocker — TTD replay being
  unavailable on that bench — goes with it.

## [0.13.2] - 2026-08-28

### Documentation

- **Driving this server with ollama was supported in fact and written down nowhere a reader would
  look.** `skills/windbg-debugging/setup.md` explained at length how to put the server on another
  machine and never said what could drive it from there; its only mention of a local model was a
  half-sentence about `--tools` inside the service bullet, and it linked to none of the three
  documents that carry the subject. It now ends with *What drives the server — there is a choice*:
  the three arrangements, and the four things that decide whether the ollama route works — a
  credential of its own, the `tools` capability being necessary and not sufficient, the lease a
  quiet client loses its sessions to, and the surface being the fixed cost where a single
  `read_memory` is the variable one. The depth stays in `docs/local-model.md` rather than being
  copied, so there is one place for each rule to be wrong.
- **The benchmark's driver was being offered as the way to use a local model, and it is not.**
  `tools/local_model_drive.py` ships in no release — the zip is `windbg-mcp.exe`, the `x86\` worker
  and `LICENSE` — wants a checkout and Python 3, has no interactive mode, and exists to measure a
  model rather than to debug with one. Driving this server with an ollama model is the **client's**
  job: an MCP client that drives one holds the listener exactly as an editor does, ollama ships
  integrations for several of them, and nothing from this repository is involved. `README.md`, the
  skill and `docs/local-model.md` now say so, and name
  [`agent-sandbox-vm`](https://github.com/glslang/agent-sandbox-vm) as the environment the grid is
  actually run in.
- **`README.md` presented driving this with a local model as a benchmark result rather than as
  something a reader can do.** Its single section on the subject was the eval — the grid, the
  axes, the findings — so someone asking whether a local model is supported at all, how the
  listener is configured, or whether a Mac can drive a Windows host over ssh found none of it, and
  the answer to all three is yes. That section is now two. *Driving it* leads with a table of the
  five configurations — an MCP client or ollama, local weights or ollama's cloud, one machine or
  two — then the commands that install **and start** the listener as a service, the ssh forward,
  why the token is not optional, and the one line that points ollama at it. The benchmark follows
  as its own section, backing those claims instead of standing in for them. The service install is
  stated with the prerequisite that makes it work: `--install-service` **refuses** an exe outside
  `%ProgramFiles%`, `%ProgramFiles(x86)%` or `%SystemRoot%`, which a downloaded zip, a Scoop shim
  and a `target\release` build all are, so the whole deployment moves first — engine DLLs and
  `x86\` included — and `--allow-unprotected-path` is named as the development install it is. The
  skill and `docs/mcp-clients.md` both said "elevated" as though elevation were the only
  requirement, and now do not. Its context-window
  finding now carries the qualifier it always needed: it is a fact about that bench's runtime, and
  `ollama ps` is how a reader learns what theirs serves.
- **The tool-surface figures were stale in eight files and disagreed with each other in two.**
  Every current claim now comes from one re-derivation, none of which needs the eval run: the whole
  surface is `tests/golden/tool_budget.json`'s `modelVisible` total, which `cargo test` re-records
  (**68,322** — not the 67,766 five documents carried, and not the 67,873 in `README.md` and
  `CLAUDE.md`); each group's share is that golden summed over `src/toolset.rs`'s membership, which
  reconciles to the total across all 51 tools; and what a `--tools` spec actually *serves* is the
  same sum over a `tools/list` from a listener started with it. So `session,inspect,crash` is
  24,894 rather than 24,445, `crash` 14,587 rather than 14,138, the `session` floor 11,714 rather
  than 11,265, `debug_batch` 9,798 rather than 9,746, and the gap item 41 opened between a group's
  share and what a spec serves is 15,542 against 14,587. `docs/local-model.md` also says how to
  re-derive its own table, because this is the second time these numbers have gone quietly stale.
  The developer-facing copies moved with them — `src/toolset.rs`'s module table and floor,
  `tests/mcp_smoke.rs`'s note on why `--tools` exists, and `CLAUDE.md` — since a figure in a doc
  comment is a current claim like any other.
  The **historical** figures are deliberately untouched: `token-budget.md`'s `67,076 → 67,766`
  before-and-after column, `local-model-eval.md`'s statement of the conditions its grid ran under,
  and this file's earlier entries each record a measured moment and would be falsified by a refresh.
- **That page described one arrangement as though it were the only one — the bench's.** Where the
  weights run and where the listener runs are independent choices, and `docs/local-model.md` opened
  on *the three pieces* with the ssh forward baked in as piece 2, because the bench that produced
  its numbers had the model on a Mac and the engine on a Windows VM. It now opens on the four
  arrangements those two choices make, says that only the listener is pinned and why, labels which
  row each measurement came from, and says outright that on a single machine piece 2 is not a step.
  The driver is also described for what it is — a batch task runner with six tool-calling turns a
  task, no interactive mode, and four environment variables that exist only so the grid can be
  graded — so that a reader stops looking for the conversation it does not have.
- **`docs/local-model.md` is about ollama, not about local weights.** A cloud tag and a local one
  are the same route — the same endpoint, the same script, a different model name — so the page
  says so from its title down, and `ollama launch` is now explicitly not needed rather than merely
  "not a prerequisite". Three facts measured on 2026-08-28 are new, and a local bench could not
  have produced any of them. A pulled cloud tag is a registered *name*: `glm-5.3:cloud` declared
  `capabilities: ['completion', 'thinking', 'tools']`, passed the driver's model gate, and answered
  the first real call with *"currently being rolled out and is not yet available to you"* — so the
  gate is necessary and not sufficient, and one token is the probe. `/api/ps` is empty for a cloud
  model even straight after a successful run, so `served_context` and `model_digest` are recorded
  null and the served-window rule has no instrument at all — the position `claude_code_drive.py`'s
  rows are already in. And the keepalive stays on despite turns of 4 to 10 seconds, because what
  the lease measures is silence, and a queued request is silent the same way a thinking one is.

## [0.13.1] - 2026-08-28

### Documentation

- **The 32-bit .NET worker shipped with a setup page nothing routed to.**
  `skills/windbg-debugging/setup.md` gained its *32-bit .NET targets need a 32-bit server* section
  with the feature in 0.13.0 and is complete — both measured failure codes, the `x86\` copy block,
  the build line, the three ways to get the layout wrong. Nothing that would send a reader there
  moved with it, which is why this is a release and not a merge: the skill reaches an installed
  plugin only when `.claude-plugin/plugin.json`'s version changes, so until this bump the routing
  fix existed on GitHub and on nobody's machine. `skills/windbg-debugging/SKILL.md` said nothing at
  all — a model holding a 32-bit dump had no reason to open `setup.md` from the routing table, and
  nothing told it that a host with no 32-bit worker answers with a summary `limitation` rather than
  an error, so the one signal the fallback exists to send read as a broken SOS. `docs/install.md`'s
  *Wanted / Needs* table — the index of what fails quietly without which files, which is this
  failure's exact shape — had no row for it. `docs/limitations.md` recorded neither the fallback nor
  what such a session gives up. And `README.md` did not mention the second worker image at all; it
  does now, under *How it works*, where the process-per-session model this follows from is stated.
  Two facts that had been stated loosely are also separated wherever they appear: the `heap_*` tools
  refuse on the **target's** processor type, so they are gone whichever worker owns the session,
  while losing the WoW64 process's 64-bit half is the 32-bit worker's **own** trade and does not
  apply to the x64 fallback.

## [0.13.0] - 2026-08-28

### Added

- **The binary carries a PE version resource** — `FileVersion`, `ProductVersion`, `CompanyName`,
  `ProductName`, `FileDescription`, `LegalCopyright`, `OriginalFilename`, `InternalName` and
  `Comments`, where a Rust binary carries none of them by default. Explorer's properties dialog is
  the visible half; the reason is the other one. Windows Defender quarantined a freshly built
  `windbg-mcp.exe` as `Trojan:Win32/Bearfoos.B!ml`, and an absent version resource is one of the two
  causes Microsoft names for that same detection on its own shipped binaries — an `!ml` verdict is a
  machine-learning score rather than a signature match, so a binary with no metadata is scored on
  what little there is. `ProductVersion` carries the git-stamped identity (`0.12.1+g1a2b3c4`) while
  `FileVersion` stays the bare release, so the dialog answers the same question `serverInfo.version`
  does. This does not make the binary signed, and signing is what the reputation systems above
  Defender actually read: [`FOLLOWUPS.md`](./FOLLOWUPS.md) item 50 is what remains.
- **A 32-bit .NET target is opened by an engine that can load its SOS** (issue #234) — a 32-bit
  dump, and a 32-bit (WoW64) process reached with `attach_process`. An extension DLL is loaded into
  the debugger's own process, so its architecture is the *host's*: the 32-bit `sos.dll` will not
  load into this server's x64 engine (`Win32 error 0n193`) and the 64-bit one loads and then fails
  on the target (`Failed to load data access DLL, 0x80004005`), because the CLR data access DLL is
  paired to the target's architecture as well as the host's. Both measured — there is no in-process
  arrangement, and a process's architecture is fixed when its image loads — so the *process* moves.
  The release now ships a 32-bit build of this same server at `x86\windbg-mcp.exe`, and a 32-bit
  user-mode target is opened by that worker rather than by a re-execution of the 64-bit one;
  `!sos.threads`, `!clrstack` and the rest answer. None of it is visible to a client — one server,
  one handle, one tool surface, one session registry — because a worker has never spoken MCP: it
  talks to the supervisor over the same pair of inherited anonymous pipes every other session uses.
  The architecture is settled before anything opens the target, which is what makes the choice
  possible at all — asking the engine would need a session in a process whose architecture is by
  then already fixed — and the two kinds answer differently: a dump carries it in its own header,
  and a live process answers `IsWow64Process2`. `skills/windbg-debugging/setup.md` has the one-time
  copy block for the 32-bit engine payload that worker loads.
- **An opener's summary carries a `limitation`** when the session cannot do something a caller would
  otherwise assume it can. Today that is the case above on a host with no 32-bit worker available:
  rather than failing the open — native analysis of such a target works and always has — it opens
  here and the result says SOS is unreachable and what to copy. Present on both the text and
  the structured halves, so a client that forwards `structuredContent` and drops the text still
  sees it.
- **The smoke test builds its own 32-bit target** rather than waiting to be handed one, so the tier
  covering the above runs unattended and in CI. It compiles a small 32-bit C# program with the
  `csc.exe` every stock Windows ships; one test opens the full-memory dump that program writes of
  itself, and the other attaches to it running. `WINDBG_MCP_X86_DUMP` still overrides the made dump
  with a real capture. The tier stands down where there is no 32-bit engine to run it against.
- **The 32-bit worker's PE version resource is asserted too.** The existing check reads the binary
  built for the host, so `x86\windbg-mcp.exe` — shipped in both the `.zip` and the `.mcpb` — carried
  its resource unchecked on every host and in CI. `build.rs` will not fail a build whose resource it
  could not embed, so a worker that quietly lost one would ship with nothing saying so, and an
  absent version resource is one of the two causes Microsoft names for the `Bearfoos.B!ml` verdict
  that motivated the resource in the first place. Its fields are asserted equal to this build's
  rather than pinned again, because the two binaries are one product from one build.

### Fixed

- **Ending a session no longer kills a process this server only attached to**
  ([`FOLLOWUPS.md`](./FOLLOWUPS.md) item 51). `attach_process` on a running process and then
  `end_session`, and the process was *gone* — not suspended, not detached, terminated. Two defaults
  meeting: the engine ended every non-kernel session passively, which destroys the debug port rather
  than detaching, and a debuggee whose port is destroyed is killed by the kernel, because
  `DebugSetProcessKillOnExit` defaults to true. That is the honest end for a `launch`, which created
  the process, and it still is; it was never right for an attach, and it was worse here than in a
  plain debugger, because the same release runs when a client **disconnects** or its lease expires —
  so a client that simply went away took the service it was looking at with it. A session whose
  target this server attached to is now actively detached and left running, and `end_session`'s
  result says which of the two endings it was. The engine-side half is
  [glslang/dbgscope#121](https://github.com/glslang/dbgscope/pull/121); `end_session`,
  `attach_process` and `launch` now each say in their own description what ending a session will do
  to that kind of target, which is what none of them said before. `end_session`'s structured result
  carries `target_left_running` beside the sentence, because a client that forwards
  `structuredContent` drops the text and this is the one fact about a teardown that cannot be
  recovered afterwards.

## [0.12.1] - 2026-08-26

### Fixed

- **A target that ends during a resume is an ending, not a catastrophe** (issue #242, and
  [`FOLLOWUPS.md`](./FOLLOWUPS.md) item 48, which had held the question open since #226). A `go`, a
  step or a raw `execute 'g'` whose debuggee ran to completion came back
  `Debug command failed: Catastrophic failure (0x8000FFFF)` — the raw `E_UNEXPECTED` DbgEng answers
  once the wait ends with no debuggee left — reported unchanged for a program exiting normally, and
  the output the run had captured was discarded with it. That output is the only copy there will be:
  the command prints its own echo, while the module loads, the breakpoint banner and anything an
  embedded `bp X "…; g"` script printed all arrive during the wait. The ending is now an outcome
  carrying its text, on both halves of the result — `target_gone` on the stop report, a sentence
  beside it, and `run_to_address` gaining a `target_gone` verdict that is deliberately not a
  timeout, since the address was never ruled out.

  The session then said so, where before it half-answered: `.echo` and `.lastevent` kept working
  while `k`, `r` and `registers` failed `0x80040205`, which from a caller's side is
  indistinguishable from #226's wedged session and needs the opposite response. Every tool now
  answers one refusal naming `end_session`, categorised `stale_session` rather than `debugger`
  because no change to what is asked will help. `.detach`, `q` and `qd` take the target away
  themselves and are reported the same way — read from the engine rather than from the command's
  name, since `.kill` is measured *not* to be in that group: it leaves a target that still reads a
  stack and goes away on the next resume.

  A `debug_batch` stops there rather than running on: a resume that ends the target **succeeds**,
  so nothing about the step's result would otherwise halt the batch, and one whose last step ended
  the target would have reported `committed` with its mutations no longer standing in anything and
  its `always` block unable to execute. The outcome is `target_gone` naming the step, the steps
  after it are not attempted, the `always` block is still attempted (the fail-safe direction: a
  misread ending must not drop cleanup that could have run), and `after` is `ended` rather than
  `detached` — a detached process is still running somewhere, and on a live kernel that is the
  difference between a machine that is up and one that is not. A step's `eval` assertions are not
  checked against an engine that has no target either: they are engine calls, and a refused
  `? (...)` used to read back as a *failed assertion* on a step whose action did exactly what it
  was asked.

  The ending reaches the two channels beside the result as well: `run_to_address`'s tool
  description now names the fourth verdict (an output schema never reaches the model, so a
  description that enumerates three when there are four is the only place a model could learn
  otherwise), and a session transcript's `stop` event carries `target_gone` — without it an ending
  is a locationless stop with both other flags false, which is what an ordinary stop looks like,
  followed by every later call being refused with nothing joining the two.

- **Execution control with no debuggee no longer takes the worker down**, which is the same defect's
  other half and was a `STATUS_ACCESS_VIOLATION` inside DbgEng — a structured exception, so no
  `catch_unwind` traps it. `execute 'g'` on a session whose target had exited hit it; so does a raw
  `g` on an engine that never had a target, which is what says the trigger is the missing debuggee
  rather than the departure. dbgscope now refuses every road into `Execute` when the engine holds
  none. It cannot be narrowed to text that looks like execution control — an alias, a `.if` branch
  and `dx …ExecuteCommand("g")` all reach it — so the few engine-level commands that do work without
  a target (`version`, `.echo`, `.sympath`) are refused too.

- **`ttd_calls` and `ttd_memory` return the fields their descriptions promise** (issue #231). Both
  ran `dx` without a recursion depth, and `dx` renders one level unless told otherwise:
  `TTD.Calls` and `TTD.Memory` return *containers of records*, so `-r1` was exactly one level short
  and every result came back as a bare index. The count was right and the payload absent, which
  reads as "three calls, details unavailable" rather than as a defect — and there was no error to
  go on. Not a regression: all three query commands are in the initial commit and only `ttd_events`
  ever carried `-r2`, so two of the three TTD query tools had never returned usable output.
  Measured after the fix against a trace recorded on this host: `ttd_calls` carries `TimeStart`,
  `TimeEnd`, `Function`, `FunctionAddress`, `ReturnAddress`, `ReturnValue` and `Parameters`, and
  `ttd_memory` carries `AccessType`, `IP`, `Address`, `Size` and `Value`. The depth is now one
  constant the three share rather than three literals, and a test asserts that every TTD query asks
  for it — what went wrong was one of them being written differently from its siblings, which no
  test could see while each built its own command line.

- **`record_trace` passes arguments to the target, which its schema always said it could**
  (issue #232). `target` is documented as "Program (with optional arguments)", and the whole string
  went to `TTD.exe` as a **single** argv entry — so the recorder looked for a file named
  `cmd.exe /c dir C:\Windows\System32\ntdll.dll` and answered `0x80004005` with "cannot find the
  file specified", a message pointing at the program rather than at the quoting. TTD's own help
  requires the opposite ("`-launch` … must be the last option in the command-line, followed by the
  program + `<arguments>`"), and `-launch` was already last, so the only thing wrong was that the
  tail was one token instead of several. It is now split by `CommandLineToArgvW`'s rules — the ones
  that will parse the line at the other end — so a quoted path holding spaces stays one argument
  and a backslash run before a quote halves the way Windows says it does. An **unquoted** path that
  exists exactly as written is still one program: that is what handing the whole string over got
  right, `C:\Program Files\…` is where programs live, and splitting it on whitespace would have
  taken the case away from callers relying on it without an error to show for it. That check asks
  the directory the *recorder* will run in — `working_dir` when the caller set one, since the
  recorder resolves a relative program against its own cwd and this process's is a different
  directory. Asking the wrong one is not a refusal: measured on `TTD.exe` 1.01.11, a target of
  `.\a program.exe` under a `working_dir` holding that file split into `.\a` and `program.exe` and
  recorded **`a.exe`** — a different program — into a 29 MB trace reported as a complete recording.
  An empty `target` is refused before the output directory and log are created, beside the existing
  `env` validation.
  Measured: `record_trace { "target": "cmd.exe /c dir C:\\Windows\\System32\\ntdll.dll" }` records
  and the recorder's own echo is now `Launching 'cmd.exe /c dir …'` rather than the quoted single
  token it used to be.

- **`record_trace` reports a recording that already finished as a success, naming the trace**
  (issue #233). The recorder is watched for 2.5s for a fast failure — the un-elevated refusal is
  what that was built to surface — and **any** exit inside the window was treated as one. A target
  that runs to completion faster than that exits inside it, so `hostname.exe` produced a 46 MB
  trace that opened and replayed correctly and was reported as `TTD recording failed to start
  (exit code: 0)`, with the quoted reason being TTD's `Launching '<target>'` banner: a line that
  says nothing was wrong. An early exit means the recorder is no longer running, not why, and "the
  target already finished" is an ordinary reason. The decision is now on the recorder's exit
  *status* and on what it left behind: a successful exit with a finished `.run` is a **complete
  recording**, and the message says so and names the trace — which is the more useful of the two
  success answers, since only one of them has a file ready to open. A successful exit with no trace
  is still an error, and a distinct one. A non-zero exit takes the path it always did, except that
  the reason is now read past the launch banner to the line that reports the failure. The trace is
  identified from the log's own `Full trace dumped to <path>`, falling back to a `.run` in
  `out_dir` written since the recorder was spawned — restricted that way so a trace an earlier
  recording left in the same directory cannot be reported as this one's.

## [0.12.0] - 2026-08-25

### Changed

- **The engine bindings are now `dbgscope`, and `win-kexp` keeps only what its name meant.**
  The dependency had two halves with exactly one reference between them: the debugger side
  (`dbgeng` plus the pool and heap walkers built on it), which is everything this server consumes
  and 117 of the dependency's last 135 commits, and an exploitation side (shellcode, ROP, process
  injection, win32k wrappers) with zero commits in three months. The debugger half keeps the
  repository and its history under the new name; the dormant half was extracted with `git
  filter-repo` and keeps the `win-kexp` name, which now describes all of it. Nothing this server
  used has moved or changed shape — the update is `use win_kexp::` becoming `use dbgscope::` — but
  the crate can now carry a version rather than a git revision, and it sheds `goblin`,
  `byte-strings`, its build script and nine `windows` features on the way. The WinDbg extension
  command it exposes is renamed with it: `!win_kexp.poolmap` is `!dbgscope.poolmap`, since that
  name comes from the cdylib's filename. Both crates are also **relicensed from GPL-3.0 to MIT**,
  which removes a conflict that predates the split and was never deliberate: a GPL library
  linked into this MIT-distributed binary made the combined work GPL. Entries above this one
  name `win-kexp` because that is what the crate was called when they were written.

- **The server reports the git revision it was built from**, as semver build metadata on the
  version it already reported: `0.11.0+g1a2b3c4`, and `-dirty.<digest>` where the build inputs
  differ from that commit — the digest, over the working-tree diff, so that two uncommitted
  iterations on one `HEAD` are not one identity. It reaches both places that carried the crate version alone and are the two a reader
  reaches for when asking *which* build did something — MCP `serverInfo.version`, and a
  transcript's `start` record. A crate version moves only on release, so every build between two of
  them was indistinguishable, including the pairs that matter most: the behaviour a bug report or a
  bench turns on is often a changed *result* rather than a changed API. Absent git, the reported
  version is the bare crate version, and nothing that compares versions is affected — build
  metadata is ignored for precedence.

- **The eval records what a run ran against, so two runs can be compared** (`FOLLOWUPS.md` item 46,
  which closes it). A record identified the question and the surface and neither of the two things
  that change over time: which model weights answered — `qwen3.8:27b-mlx` is a mutable tag that can
  be re-pulled onto different ones — and which server build was asked. Both facts were already on
  the wire and both were thrown away, so every record now carries `server`, `model_digest`, `suite`
  and, for the Claude rows that can have no digest, `harness_version`. A surface is fingerprinted
  by a **digest** of what went over the wire rather than by its byte length, and a field that is
  deliberately null (`unavailable`) is kept apart from one nobody recorded (`unrecorded`). `--compare` reads two logs
  with two rules that are not one rule: a **changed question blocks** a pairing, and a changed
  build, model or window is **named above the table**. `--series` reduces logs to one row per run
  in `docs/eval-runs.json`. The three runs already recorded read `unrecorded` throughout, which is
  the part of this that expires: a run recorded without identity cannot have it added later.

- **The eval's answer key is re-read off the dumps rather than trusted** (`FOLLOWUPS.md` item 45,
  which closes it). Its six tasks are graded against facts read off the checked-in samples with
  this server's own tools, and nothing re-checked them — so a fact that stopped being what the
  server reports would leave the suite grading, every model scoring, and a rotted key looking
  exactly like a model that got worse. Each task now carries a **`verify` binding** of
  `(tool, arguments)` steps to the values expected back, and
  `local_model_eval.py --verify-key` drives the server and checks the lot through the same
  `present()` that grades. It catches a moved fact, a renamed field, a prompt repointed at another
  sample, an `expect` group nothing fetches, an `expect` group edited to something the server does
  not say, an `expect` group widened to also accept something else, a relation whose supporting
  pin was deleted, a gated step ordered before its opener, and a stale text pin — all nine
  verified against deliberately rotted copies of the suite, with the real one green. It is a command rather than a CI
  gate because a Rust test would need a second copy of `present()`, whose three rules were each
  learned from a wrong verdict; run it after a `win-kexp` bump, a symbol-path change or a new
  sample. Nothing was wrong when it landed.

- **The eval's `arm64_pc` task asks a question with one reading** (`FOLLOWUPS.md` item 44, which
  closes it). It asked for "the value of the `pc` register at the point of the crash", which reads
  as the address whose execution faulted — bug check parameter 1 — rather than as the register's
  value: across the 35 runs of it in the three logs on disk, **none** gave the key and **32** gave
  parameter 1. Both are defensible on that dump (`pc` is `nt!KeBugCheck2+0x2e8`, inside the
  bug-check path the machine reached *after* the fault), so the fix is the question and not the
  key — widening `expect` to accept parameter 1 would let the task pass off `open_dump`'s summary,
  where the parameters already are, without the route it exists to check being taken at all. The
  other five prompts were re-read against their keys at the same time and none has the same
  defect; `driver_blame`'s `0x1654` is the nearest thing and is recorded in that task's `note`
  rather than changed, since 33 of its 35 runs give the key. **Scores published before this**
  — `docs/local-model-eval.md`, three tables over — were graded against the old wording and say so
  now.

- **A run's identity includes the question it asked**, so the suite the published runs used is
  frozen as `tools/eval_tasks_v1.json` and both checked-in plans name it; the live
  `tools/eval_tasks.json` is `v2`. `usable()` drops any record whose stored prompt is not the one
  the suite asks now — right for a resume, and it meant rewording `arm64_pc` in place took that
  task out of every historical plan: `after-217.jsonl` graded 15 possible per cell instead of 20,
  with 25 of 150 records `UNCOUNTED`, and a *resumed* plan would have appended new-wording answers
  under the same `(cell, draw, task)` key as the old ones. Pinned, it grades to 20 again and
  resume counts 150 of 150 done. The grader now also names that reason under the table when it
  fires, because it is the one uncounted reason a reader can act on — a served window that was not
  the one requested is unrecoverable, a changed question is only the wrong suite.

- **The eval's `unserved` column is two numbers, because it was two measurements** (`FOLLOWUPS.md`
  item 43, which closes it). A call naming a tool the client is not served is either `taught` — the
  task *was* answerable on this surface, so nothing about the question required a name off it — or
  `wanted`, where it was not and the model reached for the capability that would answer it. Summed,
  they hide each other: re-graded over the two logs on disk, item 41's fix is **4+10 -> 0+6**, an
  elimination of the half it was aimed at rather than a 57% improvement in a total. `taught` prints
  its offenders by name and `--grade --assert-no-taught` exits non-zero on one; `wanted` is not
  assertable, being a property of the task list rather than of this server.

### Fixed

- **Every tool's `outputSchema` is rooted at `type: "object"`, which is what keeps a strict client
  holding any tools at all** (issue #223). The structured results are internally-tagged enums, and
  `schemars` renders one as `{ $schema, oneOf, $defs }` — object-ness stated on each branch of the
  union and nowhere at the root. rmcp passes that through deliberately, because SEP-2106
  (`2026-07-28`) relaxed the requirement for output schemas. But that relaxation says what a server
  *may* emit, not what clients accept: every released `@modelcontextprotocol/sdk` 1.x — 1.30.0
  included — parses `Tool.outputSchema` as `z.object({ type: z.literal("object"), … })` and
  `tools/list` as `z.array(ToolSchema)`, so the array fails on the first non-conforming tool and the
  client registers **none** of them. Measured against 1.30.0 on this server's own captured
  `tools/list`: **0 of 51 tools before, 51 of 51 after**. It reached a real client as zero tools
  registered, a reconnect loop exhausted and the server deregistered.

  Supplying the keyword is not a concession to old clients — it is *true*, since MCP types
  `structuredContent` as a JSON object in every revision — and it changes nothing about what
  validates: each branch of the `oneOf` already carried `"type": "object"`, and `ajv` gives success,
  failure, a payload missing its required fields and an unknown discriminator the same verdict
  either way. Emitting the relaxed shape only to peers that negotiated `2026-07-28` was considered
  and rejected for the same reason: the object-rooted form is legal under both revisions, so the
  version-aware branch would exist only to send a worse schema to half the population. It costs
  16 bytes per tool — 528 across the surface, none of it model-visible.

- **A raw `execute` of `g`/`p`/`t` moves the target instead of wedging the session**
  ([#226](https://github.com/glslang/windbg-mcp/issues/226)). `execute` runs a plain
  `IDebugControl::Execute`, and DbgEng's execution-control commands only *set the run state*
  there — nothing moves until a `WaitForEvent` pumps it. So the call answered with its own echoed
  command, the target had not moved, and from then on every `go`/`step_*` on that session failed
  with `0x80040205` while `bl`, `r` and `.lastevent` kept working, which reads as half alive. There
  was no way back short of `end_session`. The same door was open through `debug_batch`'s
  `{"op": "command"}` step, which reported `committed`, `rollback_complete: true` and
  `after: stopped` on a session it had just wedged.

  The fix asks the **engine** rather than the command text: after any raw `Execute`, win-kexp's new
  `settle` reads the execution status and pumps a target that was left running. That is why no list
  of command names appears anywhere in it — `bp X; g`, an alias, `.if (1) { g }` and the data
  model all reach execution without saying so, and a list would have to enumerate them. The result
  carries what the pump printed plus a line naming where the target ended up, since a step prints
  nothing at all; `debug_batch` now asks the same question before reporting what its session holds.

- **A `go`, step or `resume` that reaches no stop no longer destroys its session**, and says what
  happened. Underneath #226 and reachable with no `execute` at all: win-kexp's `execute_and_wait`
  used a *finite* `WaitForEvent` for every target that was not a live kernel, and on expiry that
  returns `S_FALSE` with the target still running and the engine holding no current process/thread
  — unrecoverable, while the call reported success. Measured: one `go` on a launched process with
  nothing to stop it, and every later `registers`, `bl` and `? @$ip` failed with `0x80040205` for
  the life of the session, with `session_status` still calling it open and live. The wait is now
  the bounded INFINITE one `run_to_address` has always used, so the target is broken in at the
  bound and the session survives, and `go`/`step_*`/`reverse_*` answer with a new
  `timed_out` beside `interrupted` — two different reasons the position is real but is not a stop
  the target reached. Nothing caught this because the only tier that drove execution was the
  live-kernel one, which was already on the bounded wait; the debugger tier now launches a process
  and drives it. A session **transcript** records which of the two reasons a stop was not one the
  target reached, and `--render-cast` says so, rather than showing a forced break as an ordinary
  stop. And where the recovery itself fails, the answer depends on what the engine then says: still
  running is an error carrying the command's output, stopped is the command's answer, and an engine
  that cannot be asked is reported as not known instead of guessed at.

- **And no *result* names one either, which was the channel nobody had scanned** (`FOLLOWUPS.md`
  item 43). Items 40 and 41 below closed the `instructions` string and the descriptions; an
  opener's summary went on ending with "`modules` lists a page of the table and `modules
  { \"filter\": \"<name>\" }` answers for one", because `summary_text` runs in the **worker**,
  which owns one session and has never heard of a client, let alone its surface. `modules` is
  `inspect`, so on an eleven-tool `crash` surface the first result a client ever saw handed it the
  exact name together with its real argument — which is where the local-model bench's "invented"
  `modules` calls were coming from. `crash_triage` rode along the same way, and a post-commit
  failure sent any caller to `execute`. The summary now crosses the pipe as facts and the pointers
  are appended where the surface is (`SUMMARY_NOTES`, `annotated_report`), on both halves of the
  result, since a structured-aware client forwards `structuredContent` and drops the text. Two
  more sentences went the same way: a post-commit failure keeps its advice on every surface and
  drops only the `execute` example, and `crash_triage`'s user-mode refusal — which named
  `backtrace` and `execute` to the one caller that has neither, `crash_triage` being `crash` while
  both of those are `inspect`.

- **A client is told about the tools it is served, and no others** (`FOLLOWUPS.md` item 40, which
  closes it). `--tools` narrowed the router per client — `tools/list` answers with that client's
  set, and anything else is refused by name — while the `instructions` string sent at `initialize`
  stayed one literal naming twenty-one tools, sent to everybody. A `--tools crash` client could
  call eleven tools and was told about twenty-one, so it would ask for `modules`, `execute` or
  `debug_batch` and be refused; driving this server with local models measured every one of those
  wasted calls (`docs/local-model-eval.md`) and read them as models inventing tool names. They were
  reading this server — through this string where the client injects it into its prompt, and
  through the descriptions of tools they *are* served where it does not (`FOLLOWUPS.md` item 41).
  The string is now a base plus a fragment per group, assembled for the client's own surface:
  1,983 characters for the whole surface against the constant's 1,990, 1,220 for
  `session,inspect,crash`, and **927 for `crash`** — a 53% cut, worth ~265 tokens to a client that
  reads it, on the surface that exists to be small.

- **And no served tool's description advertises one the client cannot call** (`FOLLOWUPS.md` item
  41, which closes it). Item 40 fixed one of the two channels above; this is the other and the
  larger. A tool's description cross-references other tools — `open_dump` said the module table is
  "what `modules` lists", `interrupt` and `end_session` both named `debug_batch`, `crash_triage`
  named `backtrace` — and on `--tools crash` those five sentences named four tools the client is
  refused. The eval measured them: with item 40 live, 13 of 61 calls on that surface still asked
  for `modules` or `debug_batch`, three times what the instructions were costing. Re-running those
  five cells afterwards took unserved calls **14 to 6** and `debug_batch` to **zero**; the three
  `modules` calls did not move, so a description naming it is not what a model needs in order to
  ask for it, though one sample per cell cannot say it never contributed. Every such
  sentence now lives in `TOOL_NOTES` beside the tools it names and is appended only to a client
  served all of them, so `--tools crash` reads **14,138 B instead of 15,073** (−6.2%) and names
  nothing it cannot call, `session` alone 11,265 instead of 12,161, and the fifty-one-tool client
  keeps every pointer for 108 bytes more (67,766). Twenty-two (tool, tool-it-names) pairs across
  sixteen descriptions, not the five one surface showed: a spec may name a single tool, and six of
  the pairs — four pointing at `execute`, the three pool tools at each other — are inside one group
  where no group spec reaches them.

- **`--list-listen-clients` sorts both halves of what it prints.** A credential file's entries
  already came back sorted; the environment's arrived in the order the variables were scanned,
  which on Windows is by *variable* name — so `WINDBG_MCP_LISTEN_TOKEN` came before
  `…_TOKEN_BENCH` and `local` led a roster whose other half was alphabetical. The same command
  formatted its two answers differently, and neither could be diffed against the other.

### Added

- **The eval can repeat a cell, which is the only way it can answer "how often"** (`FOLLOWUPS.md`
  item 42, which closes it). The grid runs one draw per (model, context, surface, task) — enough
  for failure *modes* and for whether a surface fits, and not enough for any sentence of the form
  "X caused Y". Three write-ups reached past that anyway and review took two of them back, each
  time because the cell's *composition* had changed too: an aggregate holding across two runs of
  different models is a coincidence, not a rate. A cell group now takes `draws: n` and the draw
  index is part of a record's identity, so repeats **accumulate** — `already_done` resumes per
  draw, the grader counts over draws instead of keeping the last, and `--matrix` prints a
  distribution (`3Y2n` is five draws, three correct) where one draw still prints `Y`. A record
  written before this is draw 1, so the three published runs grade to exactly what they graded to.

  **The seed rides along and does not replay a draw here.** Each draw asks for `seed: <draw index>`
  and records it, which where a seed reproduces a sample makes draws repeatable and pairs the two
  arms of an A/B. It does not here: four identical requests to `qwen3.8:27b-mlx` under
  `seed: 7` returned four different answers (ollama 0.32.15, MLX). Measured after the code comment
  claiming the opposite had been written — the column is what was *asked for*, and the distribution
  over draws is the measurement.

- **The local-model eval: a grid where there were two sightings**
  ([`docs/local-model-eval.md`](./docs/local-model-eval.md), `FOLLOWUPS.md` item 39). Three ~30B
  local models against three tool surfaces and three context windows, with Claude Code as the
  control, scored against an answer key read off the checked-in sample dumps with this server's own
  tools before any model saw them. `tools/local_model_eval.py` runs the grid and grades it,
  `tools/claude_code_drive.py` is the control row, `tools/bench_listener.ps1` stands up the one
  listener that serves all three surfaces — which is 0.11.0's per-client `--tools` doing the
  narrowing, rather than a test double.

  It also found a defect in this server, filed as `FOLLOWUPS.md` item 40: **`--tools` narrows
  `tools/list` and not the `instructions` string**, which is one compile-time constant naming
  twenty-one tools and is sent to every client whatever its surface. A `crash`-surface client is
  served 11 tools and told about 21, of which 17 it cannot call - which is where every "invented"
  tool call in the grid came from, and 59% of a 497-token string that client pays for in full.

  Three findings worth the run. **The window was not the binding constraint**: at a *served*
  8,192-token window a 17,300-token surface answered all six tasks correctly, multi-turn tasks with
  10,000-character results included, so the "will it fit" arithmetic in `docs/local-model.md`
  predicted a failure that does not happen on this runtime. **The surface axis costs fewer answers
  than tools** — 51 tools down to 11 removes 40 tools and 2 of 6 answers, because `open_dump`'s
  summary and `crash_triage`'s frames carry facts that `modules` and `registers` also carry. And
  **a narrowed surface makes every model call tools that are not there**, the control included, so
  the refusal that names the client's own surface is load-bearing rather than cosmetic.

- **The client commands warn when the SCM starts a different copy of this program than the one you
  ran** (`FOLLOWUPS.md` item 38, which closes it). 0.11.0 gave the credential file a shape earlier
  builds refuse — an entry that is an object, carrying a client's `--tools` beside its token — so
  `--add-listen-client <name> --tools …` or `--set-listen-client-tools`, run from a newer copy than
  the one the SCM starts, writes a file the running service cannot read. **Nothing breaks at the
  time, which is the problem**: a reload only ever swaps in a set that would have started this
  listener from cold, so the service goes on serving the clients it had and says so in its log. It
  is the *next start* that fails, a reboot away from the cause. A fresh install cannot reach this
  and neither can an ordinary upgrade, since Windows will not overwrite a running image — a
  development tree with two builds in it is the case that does.

  All five commands print it, with both paths: the four that edit the file, and
  `--list-listen-clients`, which is where an operator goes when a service did not come back after a
  reboot and which was otherwise printing one build's reading of a file another build has to read.
  **A warning and never a refusal** — a path is all there is to compare, since nothing carries a
  version between the two, and running a client command from a second copy of the *same* build is
  legitimate and looks identical from here.

- **`--list-listen-clients`, the one client command that changes nothing** (`FOLLOWUPS.md` item 37,
  which closes it). The four commands that edit a service's credential file each print the whole
  roster afterwards — name, token fingerprint, and the `--tools` spec where one is set — and until
  now that roster could only be had by making a change you may not have wanted. That was survivable
  while every client was served the same surface, because "who may connect" had one other answer in
  the listener's startup line; a client's own spec has no such second answer.

  It reads the same file through the same parser as the edits and prints the same fingerprints,
  and it writes nothing whatever: no token minted, no reload asked for, and not even the credential
  lock the four editors take — that lock is a file this program creates, and creating one is a
  write. **A file it cannot read in full refuses rather than printing a shorter roster** — one entry this server would
  refuse at startup is a file that will not start the service, and a list that quietly dropped the
  client it could not parse would be the most misleading thing this command could print.

  **It says which of the two sources it answered for.** A service's clients are in the credential
  file; a foreground listener's are the environment it was started with, and no command edits
  those — so where no service is installed this answers for the environment instead of refusing,
  and where both are configured it prints both. A `--tools` beside it is refused rather than
  ignored, on the same rule as `--rotate-` and `--remove-listen-client`: it reads exactly like a
  filter over the list it is about to print.

  **And it says it is reading the file rather than the service**, with the state that service is in
  beside it, because the two differ in two unrelated ways. A credential's: a `--remove` or
  `--rotate` whose reload failed leaves a token authenticating that the file no longer names, which
  is the case an operator would run this to check. A surface's: a reload that *succeeded* still
  does not reach a client holding an MCP session, which goes on being served what it had when it
  connected — including when the change was to *clear* the last spec, so the caveat is
  unconditional rather than gated on the file still holding one. The running service
  cannot be asked what it holds: its only channel carries a status code and no data, so what is
  reported beside the roster is the state that service is in, across every state it can reach —
  including **stopping**, which is not stopped: a stop ends the accept loop and then releases every
  target, and the connections already accepted are served until the process exits.

### Documentation

- **`README.md` is now a map rather than the manual.** It had grown to 986 lines carrying twelve
  topics end to end, so a reader looking for one of them scrolled past the other eleven, and every
  topic's prose was in the one file a newcomer opens first. Each topic is now its own document
  under `docs/` — [`architecture.md`](docs/architecture.md), [`install.md`](docs/install.md),
  [`mcp-clients.md`](docs/mcp-clients.md), [`releasing.md`](docs/releasing.md),
  [`tool-surface.md`](docs/tool-surface.md), [`sessions.md`](docs/sessions.md),
  [`kernel-profiles.md`](docs/kernel-profiles.md), [`structured-results.md`](docs/structured-results.md),
  [`debug-batch.md`](docs/debug-batch.md), [`walk-memory.md`](docs/walk-memory.md),
  [`transcripts.md`](docs/transcripts.md), [`limitations.md`](docs/limitations.md) and
  [`walkthroughs.md`](docs/walkthroughs.md) — and the README keeps an index, a quick start, the
  tool table, and a summary of each topic that links to it. **The prose moved verbatim**; what
  changed is where it lives.

  The **`## Tools` table stays in the README**, because `docs/messagemanager-walkthrough.md` and
  two of the new documents link to `README.md#tools`, and because it is the one thing a reader
  wants before deciding to read anything else.

  Three references were wrong before the move and are fixed rather than carried over: the
  *Requirements* section pointed at a *"TTD engine"* section that has never existed (it meant
  *Bundling the WinDbg engine*), the platform badge linked to `#requirements` on a README that no
  longer has that heading, and `crash_triage`'s "no `!analyze`" error told the reader to see "the
  README's engine setup". Source comments in `src/schema.rs`, `src/structured.rs`, `src/worker.rs`
  and `tests/mcp_smoke.rs` that cited a README section now cite the document holding it.

## [0.11.0] - 2026-08-23

### Added

- **A tool surface per client, not just per server** (`FOLLOWUPS.md` item 36, which closes it). A
  `--listen` server names its clients already, and they do not have one budget between them: the
  arrangement this listener exists for is a local model that can hold twenty tools beside a hosted
  client that can hold fifty-one, on the same box and against the same debug sessions. So a client
  may be configured with a `--tools` spec of its own — `WINDBG_MCP_TOOLS_<NAME>` beside its token,
  or a `tools` field in the credential file — and two credentials on one port get two `tools/list`
  answers.

  **The run's `--tools` is the default rather than a ceiling.** A client with no spec of its own is
  served whatever the run serves; a client with one is served that instead, wider or narrower,
  because an intersection would produce a surface neither the operator nor the client ever named.
  `session` is added to a client's spec exactly as it is to a run's.

  The credential file's entries may now be objects — `{"bench": {"token": "…", "tools": "crash"}}` —
  beside the bare tokens they always were, which keep meaning what they meant. A spec naming a
  client nothing configures a token for is **refused at startup**, on the precedent of the two
  collisions that file already refuses: a surface no credential can reach is a setting that would
  never take effect, and the way to write one is the typo that makes the two variables disagree.

  **`--set-listen-client-tools <name> --tools <spec>`** changes a service-hosted listener's client
  surface without a reinstall or a restart, the way item 34's three commands change a token; with
  no `--tools` at all it puts the client back on the service's own surface. It mints no credential
  and revokes none. A `--tools` beside `--rotate-` or `--remove-listen-client` is refused rather
  than ignored, because it reads exactly like a command that had narrowed that client.

  **A surface change reaches a client the next time it is identified**, and nothing announces one.
  The surface is fixed at that moment — `initialize` for a client holding an MCP session, every
  request for one on `2026-07-28`, which therefore picks the change up with nothing done to it —
  and no `notifications/tools/list_changed` is
  sent: this server keeps no handle to notify a session through, and the sessionless revision has
  no session to notify, so it would be a guarantee on one revision and silence on the other. The
  command that changes a surface says so.

  A tool that exists and is not served is still refused by name rather than as an unknown tool, and
  the message now names **which** configuration to widen — the run's flag, or that client's own
  entry — since the caller can see neither.

- **`--tools` serves a named subset of the tool surface** (`FOLLOWUPS.md` item 24's last finding,
  which closes that item). All 51 tools cost a model **67,658 B — about 17k tokens — once per
  conversation, before it has asked anything**. `--tools session,inspect,crash` makes that 20 tools
  and 25,265 B; `--tools crash` is 11 and 15,073 B. Nothing is reworded: the tools that remain are
  the tools they were.

  Fewer tools rather than smaller ones, because measuring settled it: **74% of the model-visible
  surface is prose** - 24,794 B of tool descriptions and 25,333 B inside the input schemas - and
  input-schema prose is most of what tells a model how to drive a tool. `debug_batch` is where
  getting that wrong leaves a patched byte in a running kernel. The structural remainder is
  ~1,744 B, 2.6%, since `$schema` is how a client picks a validator dialect and `minimum`/`format`
  are constraints. There was no strip here worth the risk.

  A spec names groups (`session`, `inspect`, `exec`, `ttd`, `ioctl`, `allocator`, `crash`, `batch`),
  individual tools, or `all`; anything else is refused at startup with the valid names. **`session`
  is always included** - every other tool routes by a `session_id` this server is the only issuer
  of, so a surface with `registers` and no opener is not a smaller surface but a broken one, and
  `--tools crash` is eleven tools rather than one. A tool that exists and is *not* served is refused
  by name ("not on the surface this run advertises") rather than as an unknown tool, because the
  remedy is a flag on a command line the caller cannot see.

  On the stdio command line, on a `--listen` one, or on `--install-service`, where it is written
  into the command line the SCM stores and read back at every start - the only place an install's
  choice survives to. It was server-wide when it landed; the entry above makes it a run's default
  that a named client may replace.

- **A service-hosted listener's clients can be changed without a reinstall**
  (`FOLLOWUPS.md` item 34). `--add-listen-client <name>`, `--remove-listen-client <name>` and
  `--rotate-listen-client <name>`, from an elevated shell, edit the credential file the service
  reads and then tell the running service to re-read it — so a client is added, revoked or rotated
  **without stopping anything**. Before this, `--install-service` was the file's only writer and the
  SCM refuses a second registration, so adding a client meant uninstall, set every credential
  variable again, install, start — which drops every session the service holds, a parked kernel
  attach included.

  Each command **generates the token itself** and never prints one: standard output carries a
  fingerprint (`sha256:701E4CF334890225`) and the token goes to `<name>.token` beside the credential
  file, in the same SYSTEM-and-Administrators directory — not to a path the operator names, because
  writing a live credential into a directory this program does not control the protection of means
  creating, ACL'ing and reopening it by name, which is a window to substitute a file and keep a read
  handle to it. Keeping a working credential out of a shell history and out of an agent's transcript
  is what makes these commands narrow enough to allow-list in a permission rule where "let this
  write `%ProgramData%`" would not be.

  The two properties the installer was hardened for are unchanged: only *this program*, running
  elevated, writes that file, and it still never writes through a file it did not create — the
  content goes to a fresh sibling created with `create_new` in the protected directory, is ACL'd
  there, and is renamed over the old name, which also makes the replacement atomic for a service
  reading it concurrently. `--install-service` now shares that writer, so an install and an
  `--add-listen-client` leave the file to one standard.

  A **rotation keeps the client's name**, and so keeps the debug sessions it has open — only the
  token moves. A **removal releases** what that client still held, down the path a lease expiry
  already uses (an orderly release, not a worker killed and a live kernel left frozen); the command
  could not have refused on their account, since it runs in another process and cannot see them, and
  blocking a revocation on the sessions it is revoking is the wrong way round. Removing the *last*
  client is refused: a listener with no credentials will not start, and `--uninstall-service` is the
  command that means "stop serving".

  The command **waits for the reload**, so the set in force when it returns is the set it wrote — the
  control handler blocks on the reload task's answer and reports a failed re-read as a failed
  control code. A reload that cannot read the file **changes nothing**: the set is only ever
  replaced by one that would have started this listener from cold, so a typo is a loud log line and
  a service still serving, rather than every client locked out of a live kernel target. That failure
  is reported as an **error** for a `--remove` or `--rotate`, whose whole point is that a credential
  stops being accepted, and as a warning for an `--add`.

  Two of these commands cannot run at once (a `token.lock` in the state directory, opened with no
  sharing): both would compute a whole file from their own snapshot and the later write would
  silently discard the earlier.

  A removal also **deletes that client's token copy** if it is still sitting there: the credential
  file is written by then, so the file authenticates nothing from the moment the command returns.

  **A revocation is an expiry that does not wait.** It sets that client's lease clock to now and
  closes an admission gate (`Sessions::revoke`); the sweeper — which already releases an expired
  client's debug sessions, closes the MCP sessions it left resident and clears its state — does the
  teardown on its next pass, and lifts the gate when it is done. So nothing an operator waits on is
  behind a live kernel letting go, and there is no second teardown path to keep in step with the
  first. The gate is what a lease expiry does not need: an expiry fires only after the client has
  been silent for longer than any call can keep it quiet, so nothing of that credential's can still
  be in flight, whereas here an opener that authenticated a moment earlier can be seconds from
  registering — and a session admitted behind the sweep would belong to a client nothing can
  authenticate as and nothing will ever come back for.

  **A name given back is a different client**
  ([#190](https://github.com/glslang/windbg-mcp/issues/190)). A client used to *be* its name, so
  `--remove-listen-client ci` followed by `--add-listen-client ci` produced two credentials that
  nothing keyed on identity could tell apart, and the second reached the debug sessions, MCP session
  ids and lease of the first. Identity is now `(name, incarnation)`: the name is still the whole of
  what is rendered — log lines, refusals and `session_status` say exactly what they did — and the
  incarnation is minted in one place, when a set of credentials is swapped in, which is the only
  code that can tell a name *carrying on* from a name *being given back*. So a
  `--rotate-listen-client` keeps the client and therefore its sessions, which is what it is for, and
  a removal-and-re-add keeps only the name.

  A request already inside the MCP service when the set was swapped still settles against the client
  that is going, and records its MCP session so the sweep closes it — but does not renew the clock,
  since a renewal would push the revocation a whole grace out and the sweep that was to run on its
  next pass would not. A request of that credential's which authenticated a moment before the swap
  and reaches the lease after it is refused, so a revoked client cannot route to its sessions once
  more; one already *inside* the service runs to completion, as it must, because a call against a
  live kernel cannot be abandoned half way.

  The registry gate a revocation closes is **never lifted**, and no longer needs to be. It marks the
  incarnation rather than the name, so a client configured under that name afterwards is simply not
  the one it gates — which deleted the question of *when* to take a gate off, where two separate
  findings had lived. It exists because the release is one pass over the sessions that exist, so an
  opener which authenticated before the revocation and has not registered yet — an `attach_kernel`
  is a worker spawn away — is invisible to it. What it leaves behind is a name and a `u64` per
  revocation.

### Changed

- **An `outputSchema` carries constraints now, not prose** (`FOLLOWUPS.md` item 24's finding 1).
  The whole `tools/list` payload went **394,883 B -> 177,460 B, a 55% cut**, and what a model reads
  did not move by a byte. `schemars` emits each output schema self-contained, so every type
  reachable from a tool's answer is inlined into that tool's `$defs`: `ErrorCategory`'s doc comment
  shipped 33 times, `ModuleInfo`'s seven, the allocator subtree's nine - 222,579 B of duplication.
  That duplication cannot be removed, because MCP gives each tool one schema and no document above
  it for a `$ref` to reach. What could be removed is what was being multiplied: **68% of every
  `outputSchema` byte was a `description`**, and `ErrorCategory` is 2,089 B with its prose and 324 B
  without.

  Nothing read it there. No model is given an output schema - the measurement
  `docs/token-budget.md` opens with - and `description` is an annotation keyword, so every instance
  that validated before validates now. The prose stays where it is read: the rustdoc it is generated
  from, `README.md`'s structured-results table, and each tool's own model-visible `description`.

  The strip is **structural, not textual** (`src/schema.rs`): a field named `description` is a
  property name, so removing every `"description"` key would delete the field rather than its
  documentation. No structured type has such a field, which is precisely why nothing would have
  reported it - there is a unit test for the case, and a smoke assertion reading `tools/list` off
  the wire, because the change comes undone by one import line. `WIRE_CEILING` 460,000 -> 205,000.

- **A default `registers` answer stopped carrying the vector bank** (`FOLLOWUPS.md` item 24's
  finding 7). The `all` argument documents the default as excluding the x87 and vector registers,
  and it did not: DbgEng exposes `xmm0` twice - as 128 bits of `bytes`, and as `xmm0/0` … `xmm0/3`,
  four 32-bit pseudo-registers that carry no subregister flag - so 64 of the x64 sample's 123 rows
  were the vector bank. Excluding them, and skipping `"subregister":false` on the rows that remain,
  takes the answer from **9,804 B to 3,480 B** and its ratio against its own text from 15.9x to
  5.6x; the result ceiling moved 13,500 -> 5,000 with it. `kind` was left alone - it earns its place
  on the `float`, `non_finite` and `unavailable` rows.

  Two things the measurement corrected rather than confirmed. The scaffolding this was filed against
  was 41% of the payload, not the bulk of it. And the text was never "the same thing better": `r`
  prints 17 registers where the values carried 123, so the ratio compared two different sets - it is
  59 against 17 now. The ARM64 half is untouched and filed as item 35: there the same class of row
  is `w0`-`w30`, which DbgEng declines to flag as views either.

- **A `modules` page names the `limit` that would return everything.** Driving the capped tool with
  a local model found the trap the cap had introduced: the obvious value to raise `limit` to is the
  count the note above the rows just gave (`227 module(s) loaded`), and that one is *guaranteed* to
  fall short, because the budget is shared with the unloaded half - the model asked for 227, got 177
  loaded rows and 50 unloaded ones, and had to fetch the table a second time. The note now reads
  ``Showing the first 64 loaded row(s) - `limit: 277` returns all of them, or narrow with `filter`
  to ask about one driver.`` Both halves' match counts are known where the note is built, so the sum
  is too. Above the 2000-row ceiling there is no such value and the note says so rather than naming
  one that would still be short. A re-run halved that task's cost, 146,359 characters to 70,929.

- **`tools/local_model_drive.py` keeps its lease alive while the model thinks.** The same run found
  something that is not about tokens at all: a lease is renewed by requests and its grace is derived
  from how long a *call* may take, so it assumes the server is the slow party. A local model
  inverts that - one turn took 440s against a 390s grace - and the sweep released the client's
  sessions mid-investigation, after which every call returned `404 Session not found`, which reads
  exactly like a broken server. The script now pings after 120s of silence
  (`WINDBG_MCP_KEEPALIVE`, `0` disables). Whether the listener should also be more patient with a
  still-connected client is [`FOLLOWUPS.md`](./FOLLOWUPS.md) item 33.

- **`modules` answers with a page of the table rather than all of it** ([`FOLLOWUPS.md`](./FOLLOWUPS.md)
  item 24). It was the largest single answer this server gives - 53,933 B of model-visible JSON for
  227 modules, a fifth of a whole tool surface for one question, and on a local model a turn of
  prefill measured in minutes as well as the window it fills. A new `limit` (default 64, maximum
  2000) bounds the whole listing, the loaded and unloaded halves sharing it through the same
  `split_row_budget` the heap diagnostics use, so neither can crowd the other out. Measured against
  the same checked-in dump `docs/token-budget.md` records its baseline on: **12,268 B model /
  16,871 B wire for the default page against 53,933 B / 74,052 B for all 227 modules**, for 383 B
  of tool surface paid once a conversation.

  The counts are what keep it honest, and they are values rather than prose: `loaded` is the
  target's inventory as before, and the new `matched` / `unloaded_matched` say how many rows each
  half would have had - so a page is never mistaken for the whole table. The text says the same
  thing and names the argument that undoes it. Every existing cap in this codebase is a worker
  out-of-memory guard; this is the first one whose constraint is the **caller's** context.

- **Driver-frame attribution is now asserted on an ARM64 stack as well**
  ([#154](https://github.com/glslang/windbg-mcp/issues/154)). A `0x139` crash raised inside HEVD by
  its own stack-cookie fail fast is checked in as `docs/samples/082126-7015-01.dmp`, and the smoke
  tier's driver-crash test became a table run over every checked-in driver crash on every host.
  The pair also covers `!analyze` both ways round: it cannot name the PDB-less `MessageManager`,
  and does name `HEVD`.

- **CI runs the debugger tier on the new ARM64 runner image as well.** GitHub's Visual Studio 2026
  ARM64 image went generally available on 2026-08-20 as `windows-11-vs2026-arm`, and the
  `windows-11-arm` label migrates onto it between 21 and 30 September 2026. The tier's ARM64 half
  is now a pair of entries, one per label, because what this job exercises that nothing else does
  is a real inbox `dbgeng.dll` and the two labels are - until the migration completes - two
  different OS builds carrying two different ones. Running both is what makes a break attributable
  to the image rather than to the change under review; the older entry is meant to be dropped once
  the labels converge ([`FOLLOWUPS.md`](./FOLLOWUPS.md) item 32). The cargo cache is now keyed by
  runner label rather than by architecture, or the two ARM64 entries would share one. The x64 entry
  needs no pairing: `windows-latest` has been the Visual Studio 2026 image since its own migration.

- **The ARM64 CI entry resolves symbols, so its target-reading assertions run**
  ([#153](https://github.com/glslang/windbg-mcp/issues/153)). Both runner images carry the
  Debugging Tools; what differs is System32. `windows-latest` ships a `symsrv.dll` there beside
  the `dbghelp.dll` that is always present, so its stock engine reaches the symbol server;
  `windows-11-arm` has none, so a `srv*` path downloaded nothing, `nt` resolved no PDB, and all
  four assertions that read a *target* stood down. That entry now copies the kit's `dbghelp.dll`
  and `symsrv.dll` beside the binary under test - `dbgeng.dll` is deliberately left alone, so it
  goes on loading the image's own engine - and the job fails if either stand-down appears in the
  output, since a skip otherwise reads exactly like a green run.

  This also retires the claim that Windows ships no `symsrv.dll` outside the Debugging Tools. It
  holds on ARM64 and does not hold on the x64 runner image.

### Fixed

- **Two ways a client command could report a revocation that had not happened** (found reviewing
  [#189](https://github.com/glslang/windbg-mcp/pull/189), after it merged). Both ended the same way:
  `--remove-listen-client` or `--rotate-listen-client` printing success while the credential it took
  out of service went on being accepted, which is the worst thing these commands can do.

  A service now reads **the credential file its own commands write**, unconditionally. It used to
  defer to a `WINDBG_MCP_LISTEN_TOKEN_FILE` already in its environment, which left it serving one
  file while the commands edited another — and the reload then succeeded, re-reading the unchanged
  override. `%ProgramData%\windbg-mcp\token` is what the installer writes, the commands edit and
  `--uninstall-service` deletes, so a service reading elsewhere is a configuration whose other three
  halves do not exist. An inherited override is ignored with a warning; the variable is unchanged
  for a foreground listener, which is what it is documented for.

  And a **starting** service is no longer treated as a stopped one. Credentials are read before the
  bind, so a `StartPending` listener is already serving the old set — and a non-loopback bind at boot
  can hold it there for `BIND_PATIENCE`, a minute and a half — while "it will read this at its next
  start" was true only of a start that had not happened. It cannot be told either: the SCM refuses a
  control code to a service in that state (`ERROR_SERVICE_CANNOT_ACCEPT_CTRL`, measured against a
  real service held there by an address not on the host). So the command says the change was not
  handed over, says that whether the start picked it up by itself cannot be told from outside, and
  points at the `clients: …` line the listener logs when it comes up. A `--remove` or `--rotate`
  exits non-zero, because "may still authenticate" is the same thing to act on as "does".

- **`tools/ioctl_harness.ps1` could not run under Windows PowerShell 5.1**, which is the only
  PowerShell a stock debuggee has. Three faults, each fatal before an IOCTL was sent: em dashes in
  a BOM-less UTF-8 file (5.1 decodes such a file in the ANSI code page, so `—` became a string
  terminator and the parse failed tens of lines later), `0x80000000` read as a negative `Int32` so
  the access mask was refused by `CreateFileW`, and the default empty `-InputHex` returning `$null`
  because the pipeline unrolls an empty array - so an IOCTL taking no input buffer could not be
  sent at all.

## [0.10.0] - 2026-08-20

### Added

- **`--listen`: the same tool surface over HTTP, so the client and the model need not be on the
  debugger host** ([#135](https://github.com/glslang/windbg-mcp/pull/135)). DbgEng is Windows-only
  and holds one debuggee per process; nothing about the *client* has to be. `windbg-mcp.exe --listen
  127.0.0.1:8765` serves every tool over streamable HTTP, with the process tree below it unchanged —
  same supervisor, same private pipes to each engine worker, same teardown.

  - **A bearer token is required, and the server refuses to start without one.** The surface
    includes `execute` and `launch`, so a port with no lock on it is arbitrary code on the machine
    holding your kernel debugger. `WINDBG_MCP_LISTEN_TOKEN` names it.
  - **Bind loopback and forward with `ssh -L`.** The listener binds what it is told and *warns* on
    every start when that is not loopback, because the argument for skipping a tunnel — a
    hypervisor network that does not route off the host — is exactly wrong on a debugger host: the
    guest being debugged is on that network, and is a sandbox by design.
  - **A session lease stands in for "stdio closed" — for the clients that can have one.** Under
    stdio the disconnect *is* the teardown signal, and it drives a real `EndSession` through every
    worker rather than killing it, because a live kernel that is merely killed is left frozen. HTTP
    has no such event, so a credential that holds a settled MCP session holds a deadline with it,
    renewed by every admitted request, and a sweep releases what an absent client left. **A
    `2026-07-28` client has no such session and is therefore never given a clock** — SEP-2567
    removed the id a lease is armed by — so what covers an abandoned target there is the per-session
    idle release under **Changed** below, which is a different question deliberately answered
    differently: it is far longer, it is per session rather than per credential, and it spares a
    session with a call still outstanding. A parked `attach_kernel` is exactly that, so it is held
    until somebody ends it rather than until a timer notices.
  - **Silence is not departure and a goodbye is** — both of them session-id behaviours, so both
    belong to the client above that has one. Every request is its own connection, so quiet is the
    resting state; a `DELETE` is the client saying it is done. One that comes back inside the grace
    **adopts what it left**, which is what makes a client restart cost nothing where under stdio it
    costs a KDNET attach — and a KDNET attach costs a reboot of the target.
  - **The grace has a floor and the floor is derived, not chosen**: the longest a single call can
    keep a client quiet is `WORKER_READY_TIMEOUT` plus the call timeout, since an opener spends up
    to 30s bringing a worker up before its budget starts. A shorter grace would release a session
    underneath the request that opened it, so it is refused at startup rather than truncated.
    `WINDBG_MCP_LEASE_GRACE_SECS` overrides it.

  [`docs/remote-listener.md`](./docs/remote-listener.md) is the operator's half.

- **The listener installs as a Windows service** ([#151](https://github.com/glslang/windbg-mcp/pull/151)).
  `--install-service --listen <addr>`, elevated, registers it with the SCM as `windbg-mcp`,
  auto-start, `LocalSystem`; `--uninstall-service` stops and removes it. That is what gives it
  `PATH`, boot start and a life independent of a login shell. Elevation is *not* among the reasons:
  Windows OpenSSH already hands an Administrators member a full token.

  - **The stop is the whole of the difficulty.** A service killed rather than asked leaves a
    detached-but-halted kernel frozen, so `listen::serve` grew a shutdown future for this one case —
    nothing else in this server needs one — and the SCM is told a preshutdown wait sized from what
    releasing every worker can actually take, refreshed at every start rather than left on the
    default.
  - **The token moves out of the environment**, because `launch` under `LocalSystem` would make a
    machine-scope variable a local privilege escalation. `install` writes it to
    `%ProgramData%\windbg-mcp\token`, ACL'd to SYSTEM and Administrators, and refuses to install
    from a user-writable directory unless `--allow-unprotected-path` says the machine is yours.
  - **`LocalSystem` does not read your `profiles.json`** — its `%USERPROFILE%` is the system
    profile — so kernel profiles have to be configured machine-wide or the service sees none.
    Verified rather than assumed, and `install` says so where an operator will read it.
  - A service has no console, so the role also writes to `%ProgramData%\windbg-mcp\service.log`.
    `server_log` is the better channel and is only reachable once the listener is up, which is
    exactly the case that file is for.

- **A long call says how it is going** ([#147](https://github.com/glslang/windbg-mcp/pull/147),
  `src/progress.rs`). A caller that puts a `progressToken` in a call's `_meta` gets
  `notifications/progress` while the call runs. The worker already emitted the milestones; what was
  missing was a route out to the client — and two decisions that are the difference between a
  progress bar and a liveness signal.

  - **Seconds elapsed, with no `total`.** A denominator would have to be a per-tool budget, and in
    an opener's case that budget does not even cover the 30s worker handshake before it starts.
  - **Ten seconds without a word is itself reported.** The milestones alone would have left the two
    longest silences exactly as they were: a parked kernel attach reports once in the first second
    and may never report again, and a pool walk or a `crash_triage` has no milestones at all.
    Incidentally this makes progress something a client can extend its own request timeout on.

  It matters most over `--listen`, where a quiet five-minute call and a dead link look identical
  from the other machine.

- **Per-client session namespaces, so two clients on one listener cannot reach each other's
  targets** ([#162](https://github.com/glslang/windbg-mcp/issues/162), slices 2 and 3). A listener
  may now hold several bearer tokens — `WINDBG_MCP_LISTEN_TOKEN_<NAME>` names a client, the unnamed
  variable names `local` — and a session belongs to whichever client opened it.

  - **Routing** is per client: a handle only routes for its owner, and omitting one finds that
    client's newest session.
  - **Another client's handle is reported unknown**, not "someone else's". The answer must not
    confirm a session the caller may not touch, and there is nothing they could do with the
    distinction.
  - **`session_status` lists only the caller's**, and the four-session **cap is per client**, so a
    busy client cannot deny a quiet one. A session is only ever reclaimed to make room for its own
    client — reclaiming another's is the precise harm a shared registry did.
  - **Closed-session history is per client too**, so a handle still answers after its target is gone
    however busy the rest of the server has been. A shared bound is a shared fate: one client's
    churn would age out another's record of a session that failed, and the answer that client then
    gets for a handle it is still holding is "unknown" — which reads as "never existed".
  - **`server_log`** shows the caller's sessions' records and the supervisor's own — one ring serves
    the whole server, so without this a client could read what another's worker printed. **Its
    counts are the caller's too**: how full the buffer is, where the cursor is now and what the
    oldest record is are all over that client's stream, since numbers about records nobody may read
    still report another client's activity.
  - **A lease expiry releases the sessions of the client whose lease ran out**, not every session.
    Before ownership those were the same set, because the gate served one client at a time.
  - **An `Mcp-Session-Id` another client holds is reported unknown**, and the check runs before the
    caller's own lease is consulted. The MCP service keeps one session table for the server, so on
    a legacy revision the id was the only thing between a client and another's MCP session — and a
    `DELETE` on it closed that session while the lease that minted it still held the id, leaving its
    owner failing every request and refused its own re-`initialize` for a grace period.
  - The rule for identity is **ambient inside a call, by name outside one**. A tool body reads the
    caller from the task-local, which is who is asking; the listener's own diagnostics run after
    that scope has closed and take the client as a parameter, so the one that reports an adoption on
    reconnect counts the reconnecting client's sessions rather than `local`'s.
  - **The tenancy itself became per client** — the gate serialised the server when the registry was
    global and one client could end another's targets, and keeping it shared would have meant one
    client's four-minute pool walk making every other client wait for a boundary the registry now
    provides properly. It has since been retired outright (see **Changed**, below): with sessions
    owned, the contention it had left to arbitrate was one credential racing itself, which inside a
    namespace is not a boundary at all. The `409` it answered with is gone; the one that remains is
    a request arriving while the sweeper releases this credential's own expired sessions.
  - Under **stdio** everything runs as `local`, so one set of registry rules serves both transports
    rather than one rule and an exception.
  - **Every credential variable is stripped from the processes this server creates** — by prefix,
    so a token added later cannot quietly reach a debuggee — and a configured token *file* shuts the
    environment out entirely, which is the precedence a LocalSystem service depends on. That file
    names its own clients (below), because a service reads nothing else.

  **Why authentication is the identity.** `2026-07-28` removed the protocol-level MCP session, so
  there is no session id to key on; requests arrive on whatever socket a client's pool hands them,
  so there is no connection either; `clientInfo` is not retained. The credential is what is left,
  and a name only the holder of a token can present is a boundary — where a name a client picks for
  itself would be a label. Configuring one token for two names is refused at startup rather than
  resolved, because the winner would be a hash-map ordering detail. Both refusals name the
  *variables* to change and never the token: they are printed to stderr, and under the service to a
  log file, so quoting the credential would leave a working one there.

  This separates clients; it does not rank them. Everyone who can authenticate still has the whole
  tool surface.

- **The token file can name more than one client, so a service-hosted listener can hold more than
  one.** A configured `WINDBG_MCP_LISTEN_TOKEN_FILE` is the *only* credential — deliberately, since
  the service installer ACLs it to SYSTEM and Administrators precisely because the machine
  environment is readable by unprivileged processes. The consequence was that the per-client work
  above could not be had in the deployment `docs/remote-listener.md` recommends: a foreground
  listener could hold `local`, `ci` and `laptop`; the service could hold one, so two agents on one
  host shared a namespace, and one of them going over the four-session cap could evict the other's
  target with nothing naming it.

  The file now takes either shape: a **bare token**, which names `local` and is what it has always
  held, or a **JSON object of client name to token** — the shape `WINDBG_MCP_PROFILES` already uses
  for kernel profiles. A leading `{` is what tells them apart, so a bare token may not begin with
  one; a file that does is refused at startup by name rather than read as the other thing. The ACL
  story is unchanged, since it is one file either way.

  `--install-service` copies **every** `WINDBG_MCP_LISTEN_TOKEN*` variable in the installing shell
  rather than the unnamed one alone, and writes the shape that fits — a bare token for a single
  `local`, the object otherwise — so an existing single-client install keeps a file nobody has to
  rewrite. It validates them the way the listener would, because the SCM registers a service once
  and a credential it refuses then fails it at every start.

  **Upgrading with a token that begins with `{`:** an install predating this wrote whatever the
  shell held, so such a file is now read as the JSON shape and the service refuses to start rather
  than authenticating. Write it as `{"local": "<that token>"}` — the refusal in the service log says
  so too — and it works exactly as it did. Any other token is unaffected. The rule is not softened
  to a fallback on purpose: reading a file whose JSON does not parse as one long token would turn a
  hand-written object with a typo in it into a credential that authenticates nobody and explains
  nothing, which is the likelier file by far.

  Its refusals name the file and the key and never a value, for the same reason the environment's
  name the variable: they are printed at startup, and under the service into a log file. A client
  name is now held to one rule wherever it was configured — a variable whose suffix is not a name is
  refused rather than skipped, since an install copies those names into the file — and a name
  written twice in the file is refused rather than collapsed to the last of them. One thing none of
  it can catch is an entry written back to front, since a token is a valid client name, so the
  documentation says which way round it goes.

- **`server_log` — the server's own log, readable from wherever the client is.** The supervisor
  keeps a bounded ring of the most recent records, its own and every engine worker's, and serves a
  caller its own share of them — the supervisor's, which name no session, plus those of the sessions
  that caller opened (under stdio, one client by construction, that is all of them): filterable by session and level, paged with a `since` cursor, answered without
  ever touching a session's engine — so it still answers while the session it is about is wedged,
  like `session_status`.

  This closes a regression the listener introduced. Under stdio the log needs no plumbing: a
  worker's stderr is inherited by the supervisor, the supervisor's is captured by the MCP client,
  and the whole stream lands in a file the operator already has. `--listen` moves the server to
  another machine and the stream stops there.

  - **Records cross the pipe as values.** A worker's `tracing` output is mirrored up the existing
    protocol channel (`WorkerMessage::Log`) and filed by the supervisor **tagged with the session
    id** — the one thing the worker itself cannot stamp them with, and the thing that makes two
    processes' interleaved records readable.
  - **Worker stderr is untouched.** The bridge is a second copy, not a redirection, so the stdio
    behaviour it exists to restore is preserved by not touching it — and the local operator's view
    on the server machine is unchanged.
  - **It cannot block the debugger.** The worker's queue is bounded and dropped when full, never
    blocked on: it is fed from the engine thread, inside DbgEng, where a log line must never wait
    on a pipe. Drops are counted and filed as a record of their own, because a gap in a log that
    reads as a quiet stretch is worse than no log at all.
  - **Not built on MCP's logging capability.** rmcp marks `notifications/message` and its whole
    API `#[deprecated]` for removal (SEP-2577), and this repo asserts that capability is not
    advertised. See [`DECISIONS.md`](./DECISIONS.md) for the trade — pull rather than push — and
    for what a tool reaches that stderr never did: the model holding the session.

  `WINDBG_MCP_LOG_BUFFER` sets how many records are kept (1000 by default). The ring is the same
  stream as stderr, so `RUST_LOG` widens both together.

- **A smoke tier for the listener's lease.** The lease is the only part of this server whose
  failures cost a *target* rather than a call, and it was the only part checked by hand. It is now
  driven over real HTTP against a listener on a loopback port, with a hand-written client — a
  library that normalised a `409` into an exception, or hid the `Mcp-Session-Id` header, would be
  asserting on the server's behalf.

  Four assertions need no debugger, because none of them needs a session to be open: the listener
  refuses to start without a token and says which variable is missing; an unauthenticated request is
  refused, told nothing about what is here, and **costs the server nothing** (the bearer check runs
  before the lease is touched); a credential's second MCP session is served alongside its first,
  while an id this server never issued is not; and going quiet is not leaving while a `DELETE` is. The fifth is in the debugger tier and waits
  out a real grace against a **parked kernel attach** — a session that exists, holds a worker, and
  cannot be interrupted, so releasing it means terminating a process. See
  [`docs/smoke-test.md`](./docs/smoke-test.md).

- **A token budget for the tool surface and for every result.** Two smoke tests measure what this
  server costs the model driving it — a cost nothing here had ever measured, and one a dependency
  bump or a widened schema can move without breaking a single assertion.

  `tool_surface_stays_within_its_token_budget` records a per-tool size table in
  `tests/golden/tool_budget.json` (re-recorded with the same `UPDATE_GOLDEN=1` as the shape golden
  beside it) and enforces three ceilings, because a golden re-recorded on every diff is a rubber
  stamp against slow growth. `tool_results_stay_within_their_budget` runs the debugger tier's dump
  through a fixed set of calls and budgets each answer, plus one rule: a typed answer may not
  exceed the rendering it replaces by more than 20x.

  The baseline it recorded is in [`docs/token-budget.md`](./docs/token-budget.md), along with two
  client behaviours it settled by measurement rather than assumption — `outputSchema` never reaches
  the model (it is ~80% of the `tools/list` payload), and `structuredContent` *replaces* the text
  block rather than accompanying it. The second qualifies `DECISIONS.md`'s "a second channel, not a
  replacement": true for a program reading fields, not for the model. What that costs today is
  itemised as follow-up 24.

- **An ARM64 kernel dump, so the debugger tier reads a *target* on both architectures.**
  [`docs/samples/121524-4703-01.dmp`](docs/samples/121524-4703-01.dmp) is a `0xFC
  ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY` off this project's own ARM64 debuggee — a user-mode
  process jumped into memory that is not executable — captured the way the two x64 samples were, a
  real crash on a real machine, and the smallest of the five that machine had at 440 KB.

  Three of the four tier assertions that read a target now open the sample paired with the
  architecture they are running on, rather than naming one file; the fourth is the driver crash,
  which stays with its own x64 dump on every architecture because what it asserts is a property of
  that crash. What that buys is an ARM64
  `_EPROCESS`, an ARM64 image's headers and an ARM64 stack's frames, read through claims that were
  previously asserted only against x64: the ARM64 CI entry proved the protocol, the session
  machinery and a module list, and nothing at all about reading a target
  ([#143](https://github.com/glslang/windbg-mcp/issues/143)). It also pins the branch of the
  process read nothing else reaches — this dump does not capture the page
  `SeAuditProcessCreationInfo` points at, so the answer comes from the 15-byte
  `_EPROCESS::ImageFileName` and is the truncated `stack_buffer_o`.

- **The gate those assertions used to carry was measuring the wrong thing, and is gone.** Four of
  them were `ignore`d on anything but `x86_64`, on the reading that an engine cannot follow a
  pointer into a dump of another architecture
  ([#142](https://github.com/glslang/windbg-mcp/issues/142)). It can: on an ARM64 host with the
  SDK's `dbghelp.dll` and `symsrv.dll` beside the binary, one engine reads both x64 samples
  completely — the `EPROCESS`, the disassembly, and the driver frame at its literal RVA — and the
  ARM64 sample too, for a 60-of-60 tier. What no engine can do is follow a pointer into a kernel
  dump without `nt`'s **symbols**: strip the symbol path from that same engine and the reads stop.
  System32 ships `dbghelp.dll` and **no** `symsrv.dll`, so a machine with nothing beside the binary
  downloads no PDB — and running *that* configuration by hand reproduces the ARM64 runner's
  reported failure down to the address and the `0x8007001E`, which is the evidence for what state
  it is in.

  So they ask the host instead, each for the premise it has: `walk_memory` and the batch work on
  numeric addresses and need only that `nt`'s base reads, asked with a `dq` through `execute`
  rather than through the tools under test, so that a regression in `walk_memory` cannot silence
  the test that exists to catch it; `crash_triage` and the driver attribution walk `nt`'s *types*,
  so those two also require it to have resolved a PDB. Either way the test prints `SKIPPED` with
  the reason and what still holds.

  The two conditions are separate because they fail apart, which this branch's own CI proved twice
  over. A version that asked only for the read let the driver-crash test through on a runner that
  reads a module base and resolves nothing, where it walked a stack made of the bug check's own
  parameters and failed an attribution assertion for an environmental reason. Asking both of all
  four would stand `walk_memory` and the batch down where they are perfectly testable. And the
  worry that a symbol condition silences assertions passing today is settled rather than assumed:
  the x64 entry reads `mm_exploit_v5.exe` out of `SeAuditProcessCreationInfo`, which is a walk
  through `nt`'s types, and its run shows all four running rather than skipping.

### Fixed

- **The pool's heaviest tag could not be queried, and asking for it answered about a different
  one.** `pool_census` and `pool_chunk` named a tag only by how it *prints*, and that rendering
  maps every unprintable byte to `.` — and a literal `.` to the same thing. So a tag with a
  binary byte came back as `....`, several distinct tags shared that one rendering in the same
  table, and handing it back to `pool_find_tag` was not an error: `....` is four valid ASCII
  bytes, so the query silently asked about a tag nobody had allocated and reported no matches.
  A tag with a byte outside ASCII could not be named at all.

  This is not a corner case. On a live kernel the two heaviest tags by bytes are routinely binary
  — on the bench this was found on, ~66 MB and ~15 MB, both rendering `....` — so the single
  largest pool consumer was the one thing the tool could not be asked about.

  Every census entry and chunk now carries **`raw_tag`** beside the printed form: `0x` and the
  four bytes as hex, in memory order, so it reads in the same direction as the rendering
  (`Tgsm` is `0x5467736d`). `pool_find_tag` accepts either form — the two cannot collide, since
  the raw form is exactly 10 characters and a printed tag is at most 4, so `0x2e` still means the
  four-byte tag it always did. The tables print the raw form wherever the rendering is ambiguous,
  and querying a rendering now says what it really searched for instead of just finding nothing.

  Found by the live-kernel smoke tier, which had been standing down on exactly this — its
  census/`find_tag` cross-check skipped itself whenever the heaviest tag was binary, which on a
  real target was most of the time. It now runs.

- **Two clients on one listener shared a namespace after all**
  ([#162](https://github.com/glslang/windbg-mcp/issues/162), found while closing `FOLLOWUPS.md`
  item 29). Ownership was decided correctly everywhere it is decided — and the identity it was
  decided from never reached a tool call. `listen::gate` scopes the caller around
  `mcp.handle(req)`, which is the HTTP task; rmcp serves a legacy MCP session from a task it spawns
  at `initialize`, and a task-local does not cross a spawn. So every call ran as the default
  `local`: both clients' sessions were owned by `local`, both clients saw both, and either could
  route to or end the other's — the precise harm per-client namespaces were built to stop, in the
  transport they were built for.

  Nothing in the suite could see it. Every rule is unit-tested where it is decided, and those tests
  set the identity themselves; the smoke tier ran one client, for whom `local` is the right answer.
  It took two credentials on one port with a session each.

  The service instance now **carries** its client — captured in the listener's service factory,
  which does run inside the gate's scope, and re-entered in `call_tool`, the one place every tool
  passes. Stdio is unaffected: it has one client and no way to authenticate a second.

- **A listener client on `2026-07-28` can use more than one request at a time**
  ([#168](https://github.com/glslang/windbg-mcp/issues/168)). [SEP-2567] removed the MCP session id
  from the revision current clients negotiate, and the listener's tenancy gate read the absence of
  that id as "a client opening a session" — the one moment it reserves the server. On a revision
  where the id never comes, that made *every* request a reservation: two that overlapped got a
  `409`, and `server_log` while a pool walk ran — the workflow this server documents for a wedged
  session — was exactly that overlap.

  At its sharpest it cost the recovery path: a kernel attach whose target never dials in parks by
  design, and a parked call held its reservation for as long as it parked, so the client could
  reach neither `session_status` nor `end_session`. For that revision, a going-nowhere attach was
  once again a reason to restart the server — the property
  [#61](https://github.com/glslang/windbg-mcp/issues/61) established, quietly lost to a revision
  rather than to a change.

  The fix was for the gate to distinguish the two kinds of nothing: a request on a revision that
  mints no session can never become the holder a reservation arbitrates, so it reserved nothing and
  was served alongside its client's other work. The gate has since been retired altogether (see
  **Changed**), which deletes that classification rather than refining it — a request now presents a
  session id or nothing, and the revision does not enter into it. The one refusal such a client still
  meets is a teardown of its own credential's expired sessions, told to ask again once the release is
  done, which was always the sweep's rule and not the gate's.

  Two lease bugs on the same path came out of review and are fixed here too, both of which end with
  a client losing sessions it was using. A stateless request now **renews** a lease its credential
  already has, since the sweep reads the deadline alone — a credential holding a legacy session and
  since sending stateless requests would otherwise have had those sessions released while it was
  working; that rule outlived the gate, and is now simply what every admitted request does. And a
  reservation that minted no session gave its **deadline** back along with its claim: a `2026-07-28`
  `initialize` may omit the `MCP-Protocol-Version` header, so it was classified as an opener,
  reserved, and took nothing — leaving a clock running against a tenancy that held nothing, which one
  grace later released whatever that client had since opened. With reserving gone, nothing arms a
  deadline before an MCP session exists, so there is no longer a clock to hand back.

  The same issue reported that the listener answered a `2026-07-28` handshake and then `400`d the
  request after it. **It does not** — that was measured with a hand-rolled probe that sent the body
  and none of the transport contract the revision adds, and the `400`s were the server enforcing
  the spec. A request on this revision carries three things: the `MCP-Protocol-Version` header,
  `params._meta` with `io.modelcontextprotocol/protocolVersion` and `…/clientCapabilities`
  ([SEP-2567] moved them there when it removed the session that used to hold them), and SEP-2243's
  `Mcp-Method` header naming the body's method. The smoke tier now drives the revision properly and
  asserts both halves: a handshake and the calls after it are served, and each under-specified
  shape is refused with a body naming the part that is missing.

[SEP-2567]: https://modelcontextprotocol.io/seps/2567-sessionless-mcp

### Changed

- **The listener's single-tenancy gate is retired; the lease is now a clock and nothing else**
  ([#162](https://github.com/glslang/windbg-mcp/issues/162) slice 3b, `FOLLOWUPS.md` item 28). A
  credential may open a second MCP session, and two of its requests never wait on each other. The
  `409` that refused one is gone.

  The gate was the boundary between two clients when the registry was one map for the whole server —
  handles minted from it, the four-session cap shared, `end_session` ending whatever it was handed.
  Ownership took that job over in the slices above, and what the gate had left to arbitrate was one
  credential racing *itself*: a fresh `initialize` while it held one, or a request bearing an id that
  was not the one it held. Inside a namespace neither is a boundary — both MCP sessions reach the
  same debug sessions, because they are the same client — so what the refusal cost was a client's own
  concurrency, and what it bought was nothing.

  - **The clock stays, and it is the whole of what the lease was kept for.** Any request renews it;
    when it runs out, that client's sessions are released exactly as a disconnect would have released
    them, its MCP sessions are closed in the service, and its requests are refused until the release
    is done. Idle release (`WINDBG_MCP_SESSION_IDLE_SECS`) does **not** subsume it: it spares a
    session with a call outstanding, which is precisely the parked `attach_kernel` a vanished client
    leaves behind, and it knows nothing about MCP sessions.
  - **The lease is still armed by an MCP session, so a `2026-07-28` client still has no clock** —
    deliberately, now that it could have one. A lease releases everything that credential holds,
    busy or not, on the reasoning that a client silent for a grace has gone; a stateless client is
    legitimately silent for far longer, and releasing a live kernel from under a caller who is
    thinking is worse than holding an abandoned one for the idle window.
  - **A credential's MCP sessions are recorded as a set**, not as one holder. An id recorded for
    nobody is one any credential may present, so tracking only the newest would have handed a client
    another's older id the moment that client opened a second — the harm the ownership check exists
    to stop, arriving through the removal of the refusal in front of it.
  - **Two refusals remain, and neither was ever tenancy.** An `Mcp-Session-Id` another client holds
    is reported *unknown* (`404`); a request arriving while its own credential's expired sessions are
    still being released is told to ask again (`409`) — the sweep's refusal, and now the only `409`
    this server has.
  - **What went with the gate:** the reservation and its generation counter, the in-flight count and
    its epoch, the handover that waited on `Sessions::busy` (and `Sessions::busy` itself), the
    `Stale` settlement that had to close a session minted by a claim that had expired, and every
    read of `MCP-Protocol-Version`. A request now presents a session id or nothing, and the revision
    does not enter into it — so the classification behind
    [#168](https://github.com/glslang/windbg-mcp/issues/168) is deleted rather than fixed, and the
    trap beside it (a reservation that minted nothing having to hand its deadline back) is
    unreachable rather than handled: only a settled MCP session arms a deadline.
  - **The one lease rule that survives is the one that loses sessions if forgotten.** An *admitted*
    request renews an existing deadline and creates none. A refused one renews nothing, or a stream
    of wrong session ids would hold an abandoned client's live kernel open for ever. What keeps the
    sweep from releasing a session mid-call is the startup floor that was always there: a grace
    longer than the longest a call can keep a client quiet means no request of that credential's can
    still be in flight when its lease expires — which is what the epochs and claim generations were
    protecting one layer above.

- **The last progress milestone is no longer dropped when it races the answer**
  ([#163](https://github.com/glslang/windbg-mcp/issues/163)). A client watching a long call would
  intermittently miss the milestone it most wants — "the target is open", "the rollback finished" —
  because that is the one arriving beside the result.

  `relay` takes a step out of the channel and then sends it. If the send was not ready on its first
  poll, which is ordinary for a write to a peer, and the answer was ready beside it, the loop broke
  and **that message was gone**: the flush at the end re-sends what is still queued, and this one had
  already been taken. It now finishes the send on the same bounded terms the flush uses, so a client
  that has stopped reading still loses the courtesy after a second — it just no longer loses it to a
  scheduling coin toss.

  The result was never affected; it always carried the truth. What was affected is a client that
  watches progress and sees a long unwind stop at "rolling it back (up to 2m03s)" with no closing
  word.

  It surfaced as roughly one debugger-tier run in five failing on one of two tests, which is what
  made it worth chasing: every test in `src/progress.rs` used a notification that completes on its
  first poll, so the losing arm was unreachable and the bug lived entirely in the gap between the
  test double and a real write.

- **A session nobody is using is released, whatever the transport did.** The lease answers "has this
  *client* gone away" by identifying it from `Mcp-Session-Id` — and `2026-07-28` removed the protocol-level
  MCP session (SEP-2567), so on the revision most clients now negotiate no holder is ever installed and
  no lease ever expires. A client that vanished left its targets held until the process exited,
  which for a live kernel is a machine owned by nobody
  ([#162](https://github.com/glslang/windbg-mcp/issues/162)).

  The listener now also releases any session that has gone unused for **30 minutes** (
  `WINDBG_MCP_SESSION_IDLE_SECS`, `0` disables), through the same orderly `EndSession` an explicit
  `end_session` uses. It needs no notion of a client, which is the point: it is the half of the
  lease's job that survives a protocol with no sessions in it.

  - **Far longer than the lease grace, deliberately.** A lease is renewed by any request; this is
    per session, and twenty minutes of reading a stack before the next question is ordinary work.
  - **A session with a call outstanding is never idle**, however old the call — which is exactly an
    `attach_kernel` parked in `WaitForEvent(INFINITE)` waiting for its target to dial in, the one
    session that must never be released. Nor is an opener that has not yet handed back its handle.
  - The floor is the same one the lease refuses to start below: longer than a single call can run,
    or a session is released underneath its own caller.

  This is the first of the slices in #162. It does not make two clients safe from each other — that
  needs a client identity, which a stateless protocol only gets from authentication — but it stops
  the leak that has no workaround today.

- **The server instructions now fit what the client reads.** They were 3,147 characters against a
  measured 2,048-character limit, so 1,099 were paid for on every connection and discarded — and
  what fell off the end was the `debug_batch` paragraph, the one instruction there that stops a
  mutation being left half-applied. Rewritten to 1,990 characters with that guidance inside the
  budget, kept ASCII so the character and byte counts cannot diverge, and asserted in the protocol
  tier so it cannot grow back unnoticed.

- **One wording for `session_id`, on every tool that takes one.** It was documented three different
  ways across 26 tools and not at all on five (`heap_list`, `heap_allocations`, `heap_chunk`,
  `heap_census`, `heap_diagnostics`), where a caller had no way to know what to pass.
  `server_log`'s keeps its own wording, because there the field filters records rather than routing
  a call — a different question that deserves a different sentence.

  The wording also now says what the field *does*. All three originals described only the staleness
  guard — "pass it to refuse the call if the target has been replaced" — which is the consequence,
  not the behaviour: the field is a **router**, and omitting it sends the call to the current
  session, which with several open is not necessarily the one you were last using. That makes this
  half close to byte-neutral, and the instructions are where the surface actually moves: 67,613 B to
  **67,076 B** model-visible, plus 1,167 B of instruction text that was being sent and discarded. That is smaller
  than [`FOLLOWUPS.md`](./FOLLOWUPS.md) item 24 predicted for the `session_id` half, and the reason
  is worth recording: the 9,514 B that bullet claimed had counted the copies inside `outputSchema`,
  which the same document establishes no model reads. The real model-visible figure was 4,695 B.
  Both the item and [`docs/token-budget.md`](./docs/token-budget.md) are corrected, and the doc
  gains the finding that measurement actually supports — five tools carry a third of the surface,
  in their *input* schemas, `debug_batch` alone being 15% of it. The `session_id` wording also gained
  back what an earlier draft of it dropped: a handle is refused when the target was **replaced** by a
  raw command, not only when the session closed, and the README explains the asymmetry that makes
  that guarantee worth having — a retired session refuses its handle while still answering a call
  that names none.

- **`modules` reports which PDB the engine has for a module** — `guid`, `age`, and the `key` those
  two make, which is the middle element of a symbol server's `<pdb>/<key>/<pdb>` path. It completes
  the coordinate work: the image was already identified by `timestamp` + `size`, and its *symbols*
  are identified by a different pair that nothing reported.

  - **`key` is carried already-built** rather than left to the caller, because the age goes in
    **hex** and getting it wrong produces a URL that 404s — a hard failure to read backwards.
  - **Absent for a module whose symbols are `deferred`**, which on a freshly opened dump is nearly
    all of them. This reports the PDB the engine *has*, not one it could find; that is not the same
    as "this module has no PDB", and the `symbols` state beside it says which.
  - **`unmatched`** says the engine loaded a PDB that does not belong to the image, which makes
    every symbol on that module another build's names. Absent when false.
  - It saves a download rather than enabling something otherwise impossible — the same identity is
    in the image's own debug directory, and [`docs/coordinates.md`](./docs/coordinates.md) walks
    the whole chain, including the part where an 11 MB image is selected out of a symbol server by
    two integers.

- **`disassemble` answers with typed instructions carrying `RVA` and encoding, not just `u`'s
  text.** The second half of the same coordinate work, and the last tool that could only answer
  "what is the code here" as a rendering. Each instruction is now
  `{address, module, rva, bytes, text}`, on the same terms a stack frame is: `module` and `rva`
  travel together and are absent when the address is in no loaded module, `attribution_failed`
  marks the different case of a lookup that failed, and `address` and `bytes` are always there.

  - **The addresses are the engine's arithmetic, not a re-parse.** The new
    `win-kexp` primitive (`DebugEngine::disassemble`) walks `IDebugControl::Disassemble`, whose
    every instruction reports where the next one starts; reading an address back out of the
    rendering would make the record depend on the format it exists to replace.
  - **`bytes` is what identifies a build.** Two images that disassemble differently are different
    builds whatever their names say — the "stale image in the analyser" risk, checkable now without
    trusting a file name. It is the engine's spelling (`d503237f` on ARM64 is the instruction word,
    not memory order), so it compares against another disassembly rather than against a file.
  - **`stopped_early` is the code ending, not the call being cut.** Disassembly runs forward into
    whatever follows a function, which may be unmapped or not code; asking again with a larger
    count returns the same instructions. A count the caller set is not that, and does not set it.
  - **The debugger's backtick address form is normalised out of operands** — ``fffff801`3c677ef0``
    becomes `fffff8013c677ef0` — because this server spells an address one way, and that tick is
    also the delimiter of the code span the listing prints in. Only where it is an address: MSVC
    decorates real symbols with backticks (`` `anonymous namespace' ``, `` `vftable' ``) and those
    survive.
  - Default 16 instructions, maximum 128. `execute { "command": "uf module!func" }` still follows a
    whole function, which is the one shape a count cannot ask for, and `execute { "command": "u" }`
    is the engine's listing with its `module!Symbol+0x1c:` labels.

- **`backtrace` answers with typed frames carrying `module` + `RVA`, not just `k`'s text.** The
  tool ran `k` and handed back whatever DbgEng printed, which names a frame as
  `module!Symbol+0x1c` — a form that is unusable the moment the symbol does not resolve, and on a
  driver with no PDB it never does. A frame now carries the offset into its image as well,
  computed from the load base the engine reports, which is the half that survives an unsymbolised
  driver and stays comparable across reboots — and across machines, for **the same image and
  build**, which is what an RVA is relative to. That is what lets a frame be joined to a function
  in a disassembler without either side knowing the other exists.

  Neither half is promised: `module` and `rva` travel together and are absent when the engine
  places the address in no loaded module — a freed pool page, an unloaded driver, a corrupted
  return address, which is what a driver bug tends to leave behind — and `symbol` is absent
  whenever nothing resolves. `address` is the only field always there. A frame whose module
  **lookup failed** now says so (`attribution_failed`), because that is the opposite kind of
  evidence from being in no module and the two were indistinguishable on the wire: the walk has
  always kept the three states apart internally, since picking a faulting frame needs them, and
  the distinction stopped at the serializer. It reaches `crash_triage`'s frames too, they being the
  same records. Confirming the image a
  frame's RVA is against is the *other* half of this phase (`TimeDateStamp`/`SizeOfImage` are on
  `ModuleInfo` already; the PDB GUID and age are not yet), and until it lands the join is on the
  caller to make against a build they know.

  - **The same records as `crash_triage`, from the same walk.** Both tools go through one helper
    (`worker::walk_attributed`) and render through one function (`triage::describe`), so a
    coordinate carried between them names the same place by construction rather than by
    inspection. The debugger tier asserts it from outside: the two stacks are compared field by
    field.
  - **A cap, which `k` did not have** — 32 frames by default, 256 at most, with `frames_truncated`
    saying when the stack went on. The frames are values now, and an uncapped typed answer is an
    uncapped bill for whoever reads it; the flag is what keeps the cap from being read as a short
    stack. `crash_triage`'s own cap comment points here for the deep stack, which is why this one
    is twice as deep.
  - **The listing is rendered from those same values**, as `modules` is
    ([#120](https://github.com/glslang/windbg-mcp/issues/120)), so the text and the records cannot
    disagree. The cost is stated rather than hidden: this is not `k`'s output — it has no
    `Child-SP`/`RetAddr` columns and no `[Inline Frame]` rows, since a stack walk does not return
    them — and `execute { "command": "k" }` is that listing verbatim for anyone who wants it.
  - Under the client behaviour measured in [`docs/token-budget.md`](./docs/token-budget.md),
    `structuredContent` **replaces** the text block rather than accompanying it, so a model driving
    this tool now reads the frames and not the listing. That is the point — the coordinate is in
    the frames — but it is the same trade `FOLLOWUPS.md` item 24 records for every other typed
    tool, and the result budget moved with it.

- The listener no longer claims a reconnecting client **adopted sessions** when there were none to
  adopt. The flag behind that line says a previous tenancy ended inside the grace, which is true
  whether or not that client had opened anything — so an ordinary reconnect logged an adoption that
  had not happened. It now says how many sessions were inherited, or that nothing was open.

- **Opt-in session transcripts, and an asciicast renderer for them**
  ([#87](https://github.com/glslang/windbg-mcp/issues/87)). Point `WINDBG_MCP_TRANSCRIPT` at a path
  and the supervisor records what it was asked and what it did, one JSON object per line: the tool
  call and its result; a session opening, changing state and being released; a wait abandoned, an
  `interrupt`, a worker process dying; and — derived from each result's *typed* half — where
  execution stopped, what a `run_to_address` concluded, every breakpoint or memory mutation, each
  assertion that did not hold, and how a `debug_batch` ended with whether its rollback completed.
  Unset, which is the default, nothing is written.

  What existed before had opposite problems. A client's own log is tens of megabytes of prompts
  with the debugger operations buried inside shell-command source; the curated proof records under
  `examples/` are readable and are written afterwards from memory — one of them says so on its
  face, captioning its own timing as *"illustrative because live recording was not enabled for the
  original run"*. The server is the only party that sees the whole of a session, and it was
  recording none of it.

  - **Written by the supervisor, from values.** One writer, so no locking and no interleaving
    between processes — and a worker's facts still arrive as facts, because they cross the pipe as
    the typed half of its reply and are read back through [`structured`](./src/structured.rs)
    types. Nothing in a transcript is scraped out of a rendering, which is the rule
    [#77](https://github.com/glslang/windbg-mcp/issues/77) was fixed by. A tool this server cannot
    type — an arbitrary `execute` — contributes its call and its result and no derived event, which
    is the honest answer rather than a guess about what the command did.
  - **Redacted, and by the same rule as everywhere else.** `kdconn` grew a scan for arbitrary text
    beside its connection parser, sharing the one list of secret parameter names, so a raw
    `connection` passed to `attach_kernel` is recorded as `key=<redacted>`; an argument member
    *named* like a secret is masked whole, before any tool has one. Profiles still keep the key out
    of the request in the first place — this is the backstop for the caller who passed a raw string
    anyway.
  - **Bounded, and it says so.** Fields are capped (`WINDBG_MCP_TRANSCRIPT_MAX_FIELD`, 16 KiB by
    default) and a record reports how much it dropped. A transcript that quietly truncated would
    read as complete, which is worse than not having one.
  - **Never the transport.** Standard output stays JSON-RPC: the transcript is a file this module
    opens, and a test reads the source to keep it that way.
  - **`windbg-mcp --render-cast <transcript.jsonl>`** renders one as an [asciicast v2] recording —
    each call as a prompt line, its output beneath, and the derived facts marked between them. It
    is derived offline from the same JSONL, so a cast can be made from a transcript recorded weeks
    ago and its timings are the recorded ones, measured on a monotonic clock. `--idle-limit`,
    `--max-lines`, `--title`, `--width`/`--height` shape it.

  Retention is the operator's: nothing but secrets is masked, and debugger output is the contents of
  somebody's memory. The README says what to do with one.

  [asciicast v2]: https://docs.asciinema.org/manual/asciicast/v2/

- **`debug_batch` answers with its report as values**, not only as prose — the last tool whose
  whole answer was a rendering, and the one with the most at stake in being readable by a program.
  `outcome`, the position it stopped `at`, `committed`, `rollback_complete`, what the session holds
  `after`, and every step of both blocks with what it changed and whether an assertion was `unmet`.
  It is built in the worker from the executor's own `BatchReport`, which is what lets a transcript
  record a transaction's verdict as a fact.

  **Visible change for existing clients**: `debug_batch` now declares an `outputSchema` and returns
  `structuredContent`. The text is unchanged and so is `isError` — a batch that did not commit is
  still a tool error carrying the whole report. Note the pairing this tool alone has: a batch that
  *ran* answers `status: "ok"` (the report is the answer) on a result flagged `isError`, while
  `status: "error"` means the batch never ran. Reading only `isError` cannot tell those apart.

## [0.9.0] - 2026-08-14

### Changed

- **`modules` renders its listing from its own values, and no longer runs `lm`**
  ([#120](https://github.com/glslang/windbg-mcp/issues/120)). It was the one tool whose text was
  the *debugger's* rendering rather than a rendering of its own records: the text came from
  `lm` / `lm m <pattern>` inside DbgEng and the values from `IDebugSymbols3` records matched in
  this process, so one answer had two independent implementations of one filter. They disagreed in
  five measured ways — character sets (`lm m nt[fd]*` prints `Ntfs`; matched literally, nothing),
  the `\` escape (`lm m n\t*` prints `nt`, `Ntfs`, `ntosext`), whitespace (`lm m nt v` matches `nt`
  and prints lm's *verbose* listing, a different command rather than a different filter), case
  folding, and the unloaded tail `lm` appends to a filtered listing — and four of them were being
  held shut by **refusing input**, which is a strange thing to have to tell a caller about a
  listing tool.

  The enumeration was already there (win-kexp's `modules()` and `unloaded_modules()`); only the
  command had to go. The listing is now printed from those records, one table for the loaded
  modules and one for the unloaded ones, each with the symbol state as a column of its own
  (`deferred` is still not `none`) and addresses in this server's one representation — so `lm`'s
  backtick form (``fffff803`89200000``) is gone from this tool's output. `execute { "command":
  "lm" }` runs the engine's own listing verbatim for anyone who wants it.

  Consequences worth having:

  - **The filter is matched exactly once**, so its syntax is this server's to define rather than
    something that has to track DbgEng's: a name plus `*` (any run of characters) and `?` (exactly
    one), **every other character literal**. The three refusals that existed only to keep the two
    matchers in step are gone — `nt[fd]*`, `n\t*`, `nt v`, `nté` and `nt; .detach` are now patterns
    that match whatever is actually named that, which on a real target is nothing, answered as an
    empty listing rather than as an error. (The `;` refusal went with them: the filter reaches no
    command any more. The one refusal left is an *empty* filter, which is a caller who meant to
    narrow and sent nothing to narrow by.) Case now folds beyond ASCII too, since there is no
    second fold to stay in step with.
  - **Nothing from outside can add a line to the listing.** The listing is line-oriented and its
    rows begin with an address, so a string carrying a line break prints as two lines — and the
    second can be shaped exactly like a row, putting a module in the text that the values beside it
    do not have, which is the one property this change is for. Both strings that come from outside
    this server are escaped rather than acted on: the caller's `filter`, quoted into the note (until
    now it was command text, and the `;` check refused line breaks along with the separator — the
    command went, and that refusal with it), and the **module and image names**, which are the
    target's to choose. Windows file names exclude the characters below `0x20` and nothing else, so
    a driver may legally be named with a `U+2028`, and a server pointed at malware on purpose is the
    last place to assume none is.

    Escaped, not refused: "nothing matches this" is a good answer to a pattern nothing is named, and
    a module named something hostile still has to be listable — its row is still its row, and the
    name column is measured on what is printed so it still lines up. The guard is Unicode's whole
    line-break set rather than `char::is_control` (`U+2028`/`U+2029` are `Zl`/`Zp`, not `Cc`, break
    a line in a renderer that knows Unicode, and are invisible to `str::lines` — so to a test
    written around it), the other control characters (an ANSI escape is a thing a terminal acts on),
    and the backtick, which is the delimiter the note quotes with: a pattern containing one closes
    the code span, handing what follows to a Markdown-rendering client as markup.
  - **Case-insensitive means both directions.** The filter compares Unicode's simple case mappings
    per character, upward as well as down: `Σ` lowercases to `σ` while final sigma `ς` lowercases
    to itself, so lowercasing alone would have missed a name spelled with `ς` — case-insensitive
    right up until the first name that needed it. It is not full case folding (no dependency for
    that), and where the two differ it errs toward matching, which for a listing filter is the
    right direction: a caller sees a row that names itself rather than missing one.
  - **The unloaded half is rendered the same way**, from `unloaded[]`, under its own heading that
    says what its addresses mean — where an image *was* — instead of a note explaining the
    relationship between the values and a tail `lm` had printed.
  - The smoke tier's claim gets stronger with them: it parses the listing's rows back as records
    and asserts they are **exactly** the values, row for row, rather than "every value appears
    somewhere in the text" — which could never have caught a row the text had and the values did
    not, the direction every one of those five divergences ran in.

  **Visible change for existing clients**: the listing text has a different shape (it is within
  contract — the module docs have always said the text is a rendering that exists to be reworded,
  and `tools_list`'s golden records input schemas only — but it is a change a client reading the
  prose will see). The `symbols` **value** is unchanged. One thing deliberately not carried over:
  `lm`'s symbol-*file* column (the loaded PDB's path), which is not in the typed record;
  `execute { "command": "lmv m <module>" }` and `!lmi` still print it.

- **An opener summarises its target instead of printing the module table**
  ([#105](https://github.com/glslang/windbg-mcp/issues/105)). `open_dump` answered with `lm` —
  the whole inventory, ~230 lines on a kernel dump, unprompted — when what a caller reads off an
  open is three things: which build, where the target's own image is, and (for a crash dump)
  which bug check. Triaging five minidumps in one session meant paying for that table five times
  to answer them.

  Every opener now returns those facts instead, as text and as a typed `summary`:
  `kernel_mode`, `modules_loaded`, the `primary_module` (the kernel on a kernel target, the
  process's own image otherwise — a base to compute `module+RVA` against), and the `bug_check`
  the target stopped on, read from the engine's `ReadBugCheckData` and rendered by the same code
  `crash_triage` uses, so the two spell one value one way. `open_dump`'s own diagnostic is
  `vertarget` rather than `lm`; the kernel openers already ran it.

  The inventory itself is unchanged and one call away — `modules`, which is where it belongs, and
  which the report names. Every summary field is best-effort and independently optional: the
  target is open by the time they are read, and a field that could not be read costs its own
  field rather than a session that exists. That also makes the summary honest about the case in
  [#85](https://github.com/glslang/windbg-mcp/issues/85), where a fresh kernel attach has nothing
  but `nt` in the engine's inventory yet — it says one module, rather than implying a complete
  list.

- **An allocator answer says what decoded it, and sizes what a partial walk missed**
  ([#121](https://github.com/glslang/windbg-mcp/pull/121),
  [#126](https://github.com/glslang/windbg-mcp/pull/126),
  [win-kexp#102](https://github.com/glslang/win-kexp/pull/102),
  [win-kexp#103](https://github.com/glslang/win-kexp/issues/103)). Every `pool_*` answer — and every
  `heap_*` answer added below — now carries `layout`: the image the decoder read, its PDB, a
  fingerprint, and the validated structural family. A walk is only as trustworthy as the types
  behind it, and until now the answer named none of them.

  Beside it, `walk.gaps` turns `coverage: partial` into a quantity. `partial` said a walk did not
  cover the allocator; it could not say by how much, and `pool_diagnostics` could not either — it
  collapses messages by shape, so the count beside a category counts occurrences of that shape, not
  bytes and not chunks. One unreadable page and a third of the pool read identically. The five
  figures are `stalled_pages` (pages a valid-region query could not advance over), `skipped_bytes`
  (what those steps wrote off), `recovered_bytes` (committed memory read *past* them in the same
  regions — the number the walker's stall handling is judged by, and meaningless except next to
  `skipped_bytes`, which is why they travel together rather than as one "how bad was it" score),
  `refused_chunks`, and `unplaced_bytes`.

  The last two are a pair, and both had to be reported for either to be honest. `refused_chunks`
  counts headers a decoder refused and resynchronised past — the first live 26100 walk to report it
  returned 106,516 refusals across 542 extents, which is not a population of 106,516 bad chunks: a
  refusal resynchronises sixteen bytes along and tries again, so one lost sync bills a refusal per
  sixteen bytes until it recovers, about 3 KB of brute-force scanning per affected extent. It sizes
  the disruption, and how far to discount the chunks reported from those extents.
  `unplaced_bytes` is its counterpart: committed bytes of a variable-size subsegment the walk
  declined to decode at all because it could not say where a chunk began in them. A walk that stops
  guessing has to report what stopping cost, or a clean refusal count reads as a walk that saw
  everything.

  `gaps` is **absent** when a walk met none of it, which is the ordinary case — five zeroes on every
  healthy answer are noise on the answers that are fine.

### Added

- **User Segment Heap walking, as five typed tools**: `heap_list`, `heap_allocations`, `heap_chunk`,
  `heap_census` and `heap_diagnostics` ([#122](https://github.com/glslang/windbg-mcp/pull/122),
  [win-kexp#105](https://github.com/glslang/win-kexp/pull/105)). 0.7.0 gave the kernel pool a
  decoder that answers in values; a *user* heap was still `!heap` text to scrape. These are the same
  decoder pointed at the other allocator, and they ride the same worker path the `pool_*` tools do —
  queue budgeting, the caller's deadline, `interrupt`, partial coverage and the per-session snapshot
  all behave as they do there.

  The roots come from the current process's PEB, resolved through `ntdll`'s own PDB types
  (`NumberOfHeaps`, `ProcessHeaps`) rather than an offset table. `heap_list` reports every one of
  them and, more usefully, says which it did *not* walk and why: Segment Heaps walked, classic NT
  heaps listed and skipped, roots whose signature was unrecognised, roots whose signature could not
  be read. Then `heap_allocations` filters chunks by heap, backend (`lfh`, `vs`, `segment`, `large`),
  state and capacity; `heap_chunk` names the allocation containing an address, the offset into it,
  and its contiguous neighbours in the same heap, backend and subsegment; `heap_census` groups the
  heaviest heap/backend/state/size-class combinations; and `heap_diagnostics` filters the walk's own
  diagnostic categories and kept examples, optionally scoped to one heap root.

  What the answers carry beyond the chunks is the point of having them typed:

  - **`layout` says what decoded this** — the exact loaded image, its PDB, a fingerprint, and the
    structurally validated VS family (`inline_vs` or `affinity_slot_vs`). That last field is why
    these are described as version-aware: the variable-size metadata moved *out* of
    `_HEAP_VS_CONTEXT` in current builds, so a decoder keyed to a build number is correct until the
    build it was not tried on, and reports plausible chunks rather than failing. The family is
    chosen by validating the structure the PDB describes, and an ambiguous or unfamiliar one is
    refused rather than guessed at.
  - **`capacity` is allocator-backed; `requested_size` is not always there.** Capacity is what the
    allocation occupies. The size originally asked for is reported only when the selected schema
    validates the exact unused-byte metadata — its absence means *unknown*, and specifically not
    "equal to capacity".
  - **`scope` and `walk`** say which roots were in the answer and how much of them was covered, on
    the same `complete`/`deadline_truncated`/`partial` terms as a pool answer. An address the walk
    never reached is not an address that was freed.
  - **`state` defaults to `allocated`**, so a question about freed memory has to ask for
    `reusable_free` or `cached_free` by name — the alternative is a caller reasoning about
    use-after-free from a listing that quietly omitted the frees.

  V1 covers x64 Segment Heaps in a stopped live target or a dump with the memory to walk. Classic NT
  heaps, WOW64 and ARM64 are out of scope and say so; `execute { "command": "!heap ..." }` remains
  the answer for a classic heap, and is what `heap_list` points at. The agent-facing workflow is
  [`skills/windbg-debugging/heap-walking.md`](skills/windbg-debugging/heap-walking.md).

- **`modules` takes a `filter`**, so "where is that driver loaded?" costs one row rather than the
  whole table ([#105](https://github.com/glslang/windbg-mcp/issues/105)). A plain name matches
  anywhere in a module name — `{"filter": "MessageManager"}` — and `*` (any run of characters) and
  `?` (exactly one) are there for the caller who means to anchor: `nt*` is the names beginning with
  `nt`, `nt` is the names containing it. Every other character is literal. The answer still carries
  `loaded`, the size of the whole inventory, and echoes the `filter` as applied rather than as
  typed.

  A filter that matches nothing is an answer rather than an error, and says so in words — a listing
  with no rows in it otherwise reads as a target with no modules — naming the mistake callers
  actually make: the pattern matches the name symbols are qualified by (`nt`), not the image file
  (`ntkrnlmp.exe`), which is measured, since a dump whose kernel image is `ntkrnlmp.exe` has no
  module of that name. An **empty** filter is the one thing refused: it is a caller who meant to
  narrow and sent nothing to narrow by, and answering with the whole table would look like the
  filter had been applied and matched everything.

  The modules that have **unloaded** come back in their own `unloaded` list, narrowed by the same
  pattern ([win-kexp#101](https://github.com/glslang/win-kexp/pull/101)) — the only thing that can
  name an address in a driver that is no longer there. `{"filter": "nvhda"}` on this repo's sample
  matches no loaded module and twenty-six unloaded `nvhda64v.sys` rows, and is reported as what it
  is: *"no loaded module matches `*nvhda*`, but 26 that have since unloaded do"*. They are matched
  and rendered by **image** name, since an unloaded module has no module name at all (there is
  nothing left to qualify a symbol with), and each row carries the engine's own `unloaded` flag.

  The filter was originally matched twice — once by this server for the values, once by `lm m` for
  the text — which is what the wildcard grammar, whitespace and case-folding refusals in earlier
  builds of this release were for. See the `modules` entry under **Changed** above: one rendering,
  one matcher, and `execute { "command": "lm m <pattern>" }` for WinDbg's own.

- **`walk_memory`: a structure traversal where an unreadable node is a row, not an end**
  ([#103](https://github.com/glslang/windbg-mcp/issues/103)). Walking a kernel list through
  `execute` was all-or-nothing — one unmapped dereference inside a MASM `.for` loop ended the
  whole script with `An unexpected exception was raised (0x80040205)`, leaving no rows, no
  iteration number, and no way to tell which node faulted. Driving the MessageManager
  use-after-free that meant bisecting a 512-entry handle table by hand to find the one bad
  pointer, which was of course the pointer the walk existed to find.

  The new tool names its nodes three ways — an explicit `addresses` list (the bulk read),
  `start` + `stride` (an array), or `start` + `next_offset` (a pointer chain) — and reads named
  `fields` out of each. Offsets may be negative, so a pool header 16 bytes before the address
  the allocator returned is one argument rather than arithmetic per node. A value the debugger
  cannot read comes back as `null` in its own field, a node where nothing read is counted, and
  the walk carries on.

  A **chain** is the one traversal a hole really does stop, because the address of everything
  after it lived in the bytes that would not read — so it stops and says *which node*. It also
  stops on a null link, on a loop (reporting where the list closed: back at the head that is a
  healthy circular `_LIST_ENTRY`, anywhere else it is corruption), and at `count`, where it hands
  back the address to resume from.

  Fields of one structure are fetched in a single read, falling back to per-field reads only
  where there is a hole — one round trip per node in the ordinary case, which is what lets a
  512-node walk finish over KDNET. The walk checks its deadline and the session's interrupt
  between nodes: there is no *command* behind it, so win-kexp's watchdog has nothing to bound,
  and a walk cut short answers with what it really read rather than failing. The one part that
  *is* a command — the `?` resolving a symbolic `start`, which can block on a symbol server —
  takes the watchdog with what is left of the walk's budget.

### Fixed

- **An allocator snapshot is retired when the target could have moved under it**, instead of waiting
  for a caller to remember `refresh: true`. The pool snapshot has been cached per session since
  0.7.0, and the contract was that a caller who let the target run said so on the next query — which
  makes a stale answer the default outcome of forgetting, and a stale pool answer is not obviously
  wrong to the person reading it. Anything that resumes or steps the target now invalidates it
  (`go`, the steps, `reverse_go`, `run_to_address`, and a `debug_batch`'s resume steps), and so does
  any raw command — `execute` and a batch's command steps — because DbgEng offers no reliable way to
  classify what arbitrary debugger text did, and `eb`, `.reload` and `g` are all just text. The
  invalidation happens even when the command *failed*: a command list can change memory before
  reaching the token it fails on. `refresh: true` still exists and is still worth passing at the
  observation an argument rests on, but it is now a statement of intent rather than the only thing
  standing between a caller and a snapshot of a target that has since moved.

## [0.8.1] - 2026-08-13

### Fixed

- A `profiles.json` with a **UTF-8 BOM** is read rather than refused. Windows PowerShell
  5.1's `Set-Content -Encoding utf8` — the obvious way to write the one config file this
  server asks a Windows user to write by hand — puts a BOM in front, and `serde_json`
  rejected the whole file with `expected value at line 1 column 1`: a message that reads as
  "your JSON is malformed" about a file whose JSON is perfect. Found by configuring a real
  KDNET profile and having the first attempt refused.

## [0.8.0] - 2026-08-13

### Changed

- **`crash_triage` is read-only again, and now earns it**
  ([win-kexp#98](https://github.com/glslang/win-kexp/issues/98)). It ran `!analyze -v` for the
  fields no API returns — the pool tag, the failure bucket, the per-parameter notes — and paid for
  them with the session's selected scope, which is why the tool was annotated
  `read_only_hint = false` despite never writing to the debuggee. It now saves the scope and
  restores it (win-kexp's new `ScopeGuard`), on every path out including the interrupt one, so a
  `.frame` or `.cxr` a caller had chosen survives a triage.

  The measurement that made this possible also **corrected the reason**, which had been wrong in
  this repo's comments, its README and its `crash-dump` skill. `!analyze -v` does not select a
  faulting context and leave it selected: it ends with the scope at the target's **default**,
  discarding whatever the caller had chosen — measured on four targets (`0x13A`, `0xD1`, `0x9F`
  and a user-mode access violation). The implicit *thread* it does move — visibly, on the `0x9F`,
  where the thread it blames is not the one the dump opens on — and does put back.

  So the stack `crash_triage` reports is the target's default context (the crash, on a crash dump)
  rather than "the thread the analysis blamed", regardless of where the caller had navigated —
  which is what makes two triages of one session agree. That normalisation is the analysis's own
  side effect, so it holds exactly when the analysis *completed*: with `analyze: false`, when it is
  skipped for want of time or an `ext.dll`, or when the deadline cut it short before the reset it
  does partway through its output, the walk describes the selected context instead — `analysis.ran`
  and `analysis.truncated` are what tell those apart. The
  smoke tier checks the promise from a scope the analysis would otherwise discard — frame 3, since
  a check starting at the default would pass whether the scope was restored or merely reset.

### Documentation

- README documents installing with [Scoop](https://scoop.sh) from the community
  [`gitfool/scoop-dungeon`](https://github.com/gitfool/scoop-dungeon) bucket
  ([#109](https://github.com/glslang/windbg-mcp/issues/109)), whose `post_install` also does the
  engine bundling — copying from the machine's own `Microsoft.WinDbg` store package, when one is
  installed — so `scoop install` covers the manual setup this README otherwise walks through.
  Nothing about that path redistributes Microsoft's engine. Includes the client config to use (the
  version-independent `current` junction), the disconnect-before-`scoop update` caveat (a connected
  client holds the binary open), and how to bundle after the fact if WinDbg arrives later.
  Documented with the trust boundary stated: the bucket is community-maintained and unaudited by
  this project, and a manifest is code — `post_install` is arbitrary PowerShell over a URL and hash
  that autoupdate rewrites — so the skill's `setup.md` tells an agent never to run `scoop install`
  on the user's behalf, and points at the release zip's checksum and build attestation as the paths
  this project can actually vouch for.
- README's engine-bundling section now copies **`winxp\kdexts.dll`**, which it had never listed
  even though `attach_kernel` auto-`.load`s it: without that file `driver_object` /
  `device_object` / `irp_stack` fail with *"No export drvobj found"*. The skill's `setup.md` and
  the driver-IOCTL docs already had it, so the README was the odd one out.

## [0.7.0] - 2026-08-12

### Added

- **Typed results: `structuredContent` and `outputSchema` for the session, execution, register,
  module, breakpoint and pool tools** ([#84](https://github.com/glslang/windbg-mcp/issues/84)).

  Every tool answered in prose, so anything driving this server programmatically had to parse it.
  The MessageManager batch client and its regression test matched on `VERDICT: HIT`, on
  `allocation(s)`, on module-name substrings and on the exact spelling of the `session_id:` line —
  which means a rewording here broke automation there without any debugger behaviour changing at
  all. Twenty-two tools now return the same text **and** a typed result beside it, with a schema in
  `tools/list` describing it. The text is unchanged with one exception, which is an improvement
  rather than a break: a successful `bp` prints nothing at all, so `set_breakpoint` used to answer
  with an empty string and now renders the breakpoints the session holds beneath the command's own
  (usually empty) output.

  What is typed, and why each one earns it: an opener's `session_id` (previously recoverable only
  by finding a line in the report) and, when an open fails, **whether a target was created** — the
  field that decides whether opening again is a recovery or a second attach; `session_status`'s
  per-session `state`, with `waits_indefinitely` and `overdue` for the attach that can park for
  ever; `end_session`'s `released` / `worker_terminated`; `run_to_address`'s verdict; where a
  `go`/step left the target; the register set and the module list as records; the breakpoint a
  `bp` just set, which prints *nothing at all* on success; and the four pool answers.

  **One address representation**, documented once and used everywhere: a `0x`-prefixed, lowercase,
  16-digit zero-padded hex string. A string because a `u64` past 2^53 does not survive a JSON
  parser that reads numbers as doubles, and zero-padded so lexical order matches numeric order.

  **A pool answer now says what its walk covered** — `complete`, `deadline_truncated` or `partial`
  — because those need opposite responses and "incomplete" alone cannot tell them apart: more time
  reaches more of the pool in the first case and changes nothing in the second. A walk that failed
  or was interrupted is not a coverage state but an error, and an *interrupted* one no longer
  reports itself as a debugger failure.

  **Failures carry a category** (`invalid_argument`, `debugger`, `timeout`, `interrupted`,
  `not_run`, `stale_session`, `worker_lost`, `capacity`) in the error branch of the same schema, so
  a caller branches on a value rather than on wording. `not_run` is new information rather than a
  renaming: a pool query refused for want of budget never touched the target, which is the opposite
  of `timeout`, where the work may well still be running.

  Nothing here is parsed out of debugger output. Each value is built from a value — which is why
  `win-kexp` grew typed `register_values`, `modules` and `breakpoints` readers, why its pool walk
  now reports *why* it stopped rather than only that it did, and why its pool queries hand back
  the walk their answer came from (`PoolAnswer`) instead of leaving a caller to ask separately:
  an incomplete walk is deliberately not cached, so the second question could be answered by a
  *different* walk, and the count and the coverage beside it would then describe two things.
  Where the answer is the supervisor's rather than the engine's, it is built from the session
  registry, not from the sentence describing it.

- **`interrupt`: stop the operation a session is running, keeping the session and its target**
  (FOLLOWUPS item 7).

  A runaway call used to have exactly one way out: `end_session`, which ends it by throwing away
  the target it was running against. On a live kernel that is a machine to re-attach, and often a
  guest to reboot. `interrupt` is the graceful one — a Ctrl+Break, exactly as at a WinDbg prompt.
  The interrupted operation ends at the debugger's next poll and returns **whatever it had reached
  to the call that started it**, marked as cut short, and the session takes the next call
  immediately. Partial output is preserved rather than discarded: `SetInterrupt` makes `Execute`
  fail, so an aborted search used to be indistinguishable from a failed one and lost every line it
  had already produced.

  The primitive existed but was only ever *timeout-driven* — win-kexp's watchdog threads
  Ctrl+Break when a deadline passes, and no caller could ask for the same. `SetInterrupt` is now a
  public win-kexp method on a `Send` handle taken from a `&DebugEngine`, which needs no new
  threading model: it is the one DbgEng call documented as safe from another thread, so the engine
  stays confined to its own.

  **Bound to a job, not to a moment.** `SetInterrupt` addresses an *engine*, so raised a moment
  late it stops whatever started next — a caller's `go` aborted by a cancel meant for the search
  before it. The worker tracks which job its engine thread is running, and the request reader reads
  that job and raises the interrupt under one lock, while the engine thread claims and releases the
  job under the same one. So an interrupt reaches the job that was running when it arrived or
  nothing at all, and the job it reached spends it: a pending break left over is drained before the
  next job starts, and only the interrupted caller is told their result was cut short.

  Like the abandon-a-batch signal, the request is **answered by the worker's request reader** rather
  than queued for its engine thread — queued, it could only be read once the operation it means to
  stop had ended. So it does not wait behind the busy session: issue it while the slow call is still
  outstanding. With nothing running it says so and does nothing. Two limits carry over from DbgEng:
  an operation that never polls for the break is not reached, and neither is an `attach_kernel`
  whose target has not connected — `end_session` remains the only end to that one.

  A `debug_batch` interrupted this way stops and runs its `always` block, reporting
  `BATCH: INTERRUPTED` at the step the break reached — a distinct outcome from `ABANDONED`, because
  the session is still open and still holds its target, so the same batch can be resubmitted against
  it. It has to be told rather than left to infer it, and that is not a detail: **an interrupted
  command succeeds**. Preserving the output reached up to the break is the whole point, so a step
  whose assertions still hold is indistinguishable from one that ran, and the batch would carry on
  applying later mutations for a caller who had just asked it to stop.

  So the debugger reports *both* facts. `execute_command_bounded` returns the output **and** whether
  the command finished (`CommandRun { output, cut_short }`), the shape `run_to_address` already had,
  rather than a bare `String` that cannot say "this did not finish" — every place that reads a result
  gets the fact with the value instead of having to remember to ask for it. That is the difference
  between a step that reports itself cut short and a batch that has to guess: the last step of a
  batch, and a step whose assertion stops holding *because* the output was truncated, are both just
  "the step says so" rather than two more special cases.

  **A batch's rollback is not interruptible.** Cleanup runs as part of the same call and is reached
  on every path, so a break landing there hits a restore command — which returns `Ok` with partial
  output like any interrupted command, and would be recorded as a step that worked: `rollback:
  COMPLETE` with the target still changed. The executor announces the block before running it, and
  the worker then refuses breaks for that call and drains any already pending, both under the lock a
  raise has to take. An `interrupt` aimed at a batch that is unwinding says so and sends nothing.
  Two readings that were wrong in the same direction come right for free once the step carries the
  fact. A break landing during the **last** step has no next step to be caught before, so the batch
  reported `COMMITTED` of a transaction whose final step was cut short — directly above the note
  saying it had been. And a step that *fails* because the break truncated its output — a `contains`
  that stops holding, an `eval` that stops parsing, the likeliest shape of an interrupted step —
  reported `FAILED`, sending the caller to debug a step that was fine. Both are now `INTERRUPTED`,
  named at the step the break actually reached.

  Every op now keeps the output an interrupted command reached, not only the bounded ones. The plain
  path (`modules`, `index_trace` and the other typed commands) went through `execute_command`, where
  a break makes `Execute` fail and the captured buffer is discarded with the error — a bare failure
  plus a note promising partial output that was not there. They take `execute_command_bounded` with
  a zero deadline instead, which is the same call plus that recovery: zero spawns no watchdog, so
  they stay unbounded, as `index_trace` in particular must.

### Changed

- **The pool tools take the caller's own deadline instead of win-kexp's default walk budget**
  ([#75](https://github.com/glslang/windbg-mcp/issues/75)).

  A pool walk enforces a wall-clock ceiling of its own, so `pool_find_tag` and friends can no
  longer run for minutes after their caller has given up and leave every later call to that session
  queued behind them. But they took the walker's **default** — 120s — which knows nothing about
  this server's deadline, and was wrong in both directions. A host configured with
  `WINDBG_MCP_CALL_TIMEOUT_SECS=60` got a 120s walk against a 60s budget: the call timed out and
  the engine kept walking, which is precisely the wedge the walk budget was added to fix, arriving
  from this side. And with the 300s default the walk stopped at 120s and handed back a partial
  snapshot with three minutes still to spend.

  `EngineOp::Pool` now carries the caller's remaining patience exactly as a bounded command and a
  batch do — filled in by the supervisor's pump as the request is written, with the worker deriving
  the deadline, because only the worker knows how long the request then sat in *its* queue. The
  arithmetic is the bounded command's, so the invariant is the same: queue wait plus walk budget
  never exceeds the caller's patience. A walk cut short still answers, and every pool result already
  reports how much of the pool it reached.

  Where it parts company with a bounded command is at the bottom of the range: that one *floors* its
  budget, because zero disables its watchdog and an unbounded command is the worse outcome. A walk
  has no such cliff — zero simply stops it at the first check — so there is no floor here, and a
  query that reaches the engine with nothing left to spend is refused rather than run. Flooring it
  would reintroduce the bug at the small end (a 10s call budget yielding a 15s walk) and buy nothing
  for it, since win-kexp caches complete snapshots only: a budget-truncated walk is discarded, so the
  work would be spent for a caller who has gone and the next query would walk from scratch anyway.
  Only a query that *must* walk is refused; one that can be served from the session's cached snapshot
  is still answered, because a cache read costs nothing that even an exhausted caller cannot afford.

  Which slot the pump fills is now named on `EngineOp` itself rather than matched inside the pump,
  because the failure it prevents is silent — that is exactly how `Pool` came to carry no patience
  at all — and is checked against the serialized form, so an op with a `patience_ms` that does not
  hand it out fails a test rather than shipping with an unset deadline.

### Fixed

- **A `2026-07-28` client got a server with no tools at all**
  ([`rmcp` #1114](https://github.com/modelcontextprotocol/rust-sdk/issues/1114)).

  SEP-2549 added `ttlMs` and `cacheScope` to every paginated result, and the `2026-07-28` schema
  makes both **required**. Every `rmcp` before 3.1.1 generated a `list_tools` that hardcoded the
  pair to `None` and then skipped serializing them, so a client that validates responses against
  the spec schema refused the entire reply: the process starts, `initialize` succeeds, the
  capabilities advertise tools — and not one of the 43 is reachable. Neither side reports an
  error, because the response is a well-formed JSON-RPC result; it is only invalid against the
  schema. Clients on the handshake-era revisions were never affected, which is why this reached
  a release: those revisions do not define the fields, and the server is correct without them.

  The dependency now has an `rmcp = "3.1.1"` floor rather than `"3"`, because the fix lives in the
  SDK's macro and a version requirement is the only part of this a downstream resolver reads. The
  smoke test pins the resulting wire shape — the fields present on `2026-07-28`, absent on the
  revisions that predate them, over both the `initialize` handshake and the stateless
  `server/discover` opener — so an older 3.x fails the suite rather than shipping a server that
  looks empty to the newest clients.

## [0.6.0] - 2026-08-10

### Added

- **`debug_batch`: an ordered sequence of debugger steps as one transaction, with assertions and a
  rollback the engine process owns** ([#82](https://github.com/glslang/windbg-mcp/issues/82)).

  A tool call is a request/response, so a client driving a multi-step debugger transaction decides
  what to do next *after* each answer — and the case that matters is the one where no answer
  arrives. A call that times out, or a client that disconnects, leaves whatever the earlier calls
  changed in place: a patched instruction, an armed breakpoint, a target left running. On a kernel
  target that is not an inconvenience. The MessageManager CTF session grew a private JSON-RPC
  client for exactly this (`target/mcp_batch.ps1`, referenced 204 times and revised 18); the shape
  it converged on is what this tool is.

  A batch is submitted as one op and executed inside the session's worker process. Steps are
  `command` (raw), `resume` (a command that moves the target, plus the wait), `run_to` (a
  HIT/STOPPED ELSEWHERE/TIMEOUT verdict), `eval` (a MASM expression's value) and `read_memory`,
  plus `pool_chunk`, `pool_find_tag` and `pool_census`, which ask the kernel pool exactly what the
  tools of those names ask. Those three are here because they are the only typed tools that are
  *not* debugger commands — they are win-kexp walks over the allocator's descriptors, so no
  `command` step can stand in for them, and a transaction that needed one had to be split around
  it. Inside a batch their walk is bounded by the step's share of the budget rather than by the
  walker's own 120s default, so a `refresh` cannot spend the reserve the rollback lives on; a walk
  cut short still reports the coverage it reached.
  Each step may carry assertions — `contains`, `not_contains`, or `eval`, which compares two MASM
  expressions and so covers registers, memory and any relation between them — and an `eval` step
  may `capture` its value under a name later steps interpolate as `{{name}}`.

  **The `always` block is reached on every path**: success, a debugger error, an assertion that did
  not hold, the deadline expiring, a panic out of the debugger (win-kexp methods do panic — several
  use `.expect` — and the worker's own `catch_unwind` is around the whole op, so each engine call a
  step makes is guarded individually). Part of the budget is reserved for it before the first step
  runs, because what is left after a step that ran to its own deadline is nothing, and cleanup
  continues past its own failures. The worker owns that deadline, sized from the caller's remaining patience
  the same way a bounded command's watchdog is, so the rollback has finished and the report has been
  written before the tool call gives up — which is the only reason the report is worth anything.

  A batch whose caller has already given up is **not started at all**: a job stays queued after
  its waiter times out, so the worker checks what patience is left before the first step and
  refuses outright rather than applying mutations nobody is waiting to hear about. That is where a
  batch parts company with a bounded command, which floors its watchdog instead — that one is
  already running and the job left is to free the worker; this one has not started, and not
  starting is what leaves the target as the caller last saw it.

  **A teardown while the batch is running is answered too**, and it is a different problem from a
  timeout: `end_session` and a client disconnect both release the target, and the op that does so
  queues *behind* the batch, so the grace used to expire with the transaction still open and the
  worker was terminated mid-patch. The worker's *request reader* now acts on that release as it
  reads it, rather than only when the engine thread reaches it: the batch stops at its next step,
  runs `always`, and reports `BATCH: ABANDONED`, while the reader answers with **how long that batch
  may still need** — so the teardown's wait covers the step already inside DbgEng as well as the
  rollback behind it. That figure is the batch's own remaining budget plus the overrun its executor
  is allowed, already clamped to the caller's patience, so a teardown never waits longer than the
  batch could have run anyway; it is re-read as the wait goes on, so a batch that finishes early can
  hand the rest back and leave only what the release itself still needs. A session with nothing to
  unwind says nothing and costs exactly what it always did. A batch that
  reaches the engine *after* the release does not start at all, which is the same "nothing ran,
  resubmitting is safe" answer as an unaffordable budget.

  Two edges are reported rather than papered over. The reserve buys the rollback *time*, not a
  guarantee: a step that overruns far enough to consume the reserve as well leaves cleanup with no
  budget, and the result then says `rollback: INCOMPLETE` and names each step that never started.
  And no signal *shortens* a step already inside DbgEng, so a batch built from long steps unwinds
  only once the current step ends — the teardown waits that out rather than cutting it off, but a
  step that ignores its own watchdog is still terminated mid-transaction.

  The result names every step that ran, the exact failing one, what each step changed, whether the
  rollback completed (reported *beside* the original failure, never instead of it), and whether the
  session is left stopped, running, detached or uncertain. A batch that did not commit comes back as
  a tool error carrying that whole report.

  Validation is up front and engine-free: a forward capture reference, a capture on a step that has
  no value, a duplicate name, a `;` in a typed operand, an empty or oversized batch, a deadline too
  short to seat a step and its reserve, and — uniquely among this server's tools — any field the
  schema does not name are all refused before a single step runs. The last is there because those
  typos fail *open*: `"aways"` for `always` is a batch with no rollback that then reports
  `COMMITTED`, and a misspelt `expect` is a step that asserts nothing and commits anyway. A batch containing a target-changing command retires the session handle
  ahead of running, as `execute` does. The executor drives a `Debuggee` trait rather than DbgEng, so
  assertion failure, a command failure after a mutation, deadline expiry and a rollback that itself
  fails are unit-tested without a debugger; the dump tier drives a real engine to both outcomes, and
  to both teardowns — a real disconnect mid-batch, whose rollback has to leave a mark on the machine
  because there is no client left to report to, and an `end_session` mid-batch, where there is.

  The claim itself — *a write that is then restored* — is settled where it can be false, on a live
  KDNET kernel: a byte of the running kernel is patched inside a batch and read back afterwards,
  through a failing assertion, through a call budget shorter than the batch asked for, through a
  disconnect (read back by a **new server process** over a fresh attach) and through an
  `end_session`. A crash dump cannot make that claim at all — a byte patched in a dump is patched in
  a file nobody reads again, so a rollback that silently did nothing passes every assertion the dump
  tier can make. Each of those tests probes the byte before it starts, because a guest with memory
  integrity enabled accepts a debugger write to an image page and drops it, which would otherwise
  leave the whole tier passing for the wrong reason.

  Two limits are documented rather than papered over. DbgEng reports most command failures by
  printing them and returning success, so a raw step that prints an error is a step that
  *succeeded* — assert on its output if that matters. And what a step "changed" is a best-effort
  classification of the command text, biased toward reporting a change: a reporting aid, not what
  makes a mutation recoverable. The `always` block is.

  Validated against the workflow it was filed for, not against a guess at it: the CTF session's own
  transcript records all 18 revisions of the throwaway client and all 188 of its invocations — 1,681
  steps, every one of them a shape the step language covers. The 9 that motivated the pool steps are
  the reason those exist: the client's `@chunkt1` read a pseudo-register with `execute`,
  regex-scraped the value out of the debugger's prose and handed it to `pool_chunk`, and it sat
  *inside* the 32-step transaction, between a code patch and its restore — so a batch without it
  would have had to drop the query or split the transaction. It is now a `capture` and a step.
  Two of the client's revisions exist only to work around gaps this closes — a compound
  assertion rewritten as three pseudo-register assignments and three regexes, and a duplicate of its
  run-to verb whose only difference was restoring a patch "on both hit and timeout". The longest
  single invocation, 32 steps, is transcribed as a regression test.

  `tools/list` gains one tool and its first nested schema, so the recorded wire surface now has
  `$defs` (`usesDefs` flips to `true`); the refs stay internal and single-dialect.

- **`attach_kernel` can name its target by `profile`**, so a KDNET debug key never has to travel in
  an MCP request ([#81](https://github.com/glslang/windbg-mcp/issues/81)).

  A connection string carries the target's key, and a key passed as a tool argument does not stay in
  the tool call: an MCP client keeps a transcript, and the one key handed over during the
  MessageManager CTF session ended up replicated across 524 records of it — through messages, tool
  calls, context snapshots and compaction summaries. That is what a transcript *is*, not a client
  misbehaving, so the server had to offer a way for the secret never to enter the request at all.

  `attach_kernel` now takes **exactly one** of `connection` (unchanged, still supported for a target
  nothing is configured for) or `profile`, a non-secret name this process resolves from
  `WINDBG_MCP_PROFILE_<NAME>` in its environment or from `%USERPROFILE%\.windbg-mcp\profiles.json`
  (`WINDBG_MCP_PROFILES` overrides the path; environment-variable names are matched
  case-insensitively, as Windows matches them). The **file** is re-read on every attach, so adding
  a profile to it takes effect immediately — an environment variable is read from the server's own
  environment at startup, so it belongs in the client's server definition and needs a restart to
  change. Passing both selectors, or neither, is a tool error naming the alternative, and the
  "neither" case lists the profiles this host has — which is what lets an agent find one instead of
  asking the user for a string it would then have to keep.

  The exclusivity is enforced at runtime rather than in the schema: an untagged `oneOf` renders as a
  schema composition clients handle unevenly, the same reason `session_id` is repeated per tool
  struct rather than flattened. Both fields are therefore optional on the wire (`tools/list` golden
  updated).

### Changed

- **Connection strings are redacted everywhere but the one call that dials them.** `key=` and
  `password=` values are masked in session reports, errors and logs, whichever selector opened the
  session: `session_status` now shows
  `kernel target: profile "ctf-vm" (net:port=50000,key=<redacted>)`.

  The guarantee is structural rather than a discipline. The value lives in a `kdconn::Connection`
  whose `Debug` and `Display` are the redacted form, so a log line, a `{:?}` on `EngineOp`, or a
  session label cannot carry the raw string; it is unwrapped at exactly one call site, handing it to
  DbgEng inside the session's own worker process. Redaction masks *values inside connection strings*
  only — debugger output is never rewritten, which on a CTF target would be its own kind of damage.

  Redaction works off a **parse** rather than a scan: the string is split once into the structure
  DbgEng's syntax has (transport prefix, separator-delimited `name=value` items) and rendered from
  that, with a secret parameter's value never emitted. The parse is total — every byte lands in
  exactly one field, so an unredacted render reproduces the input exactly — which is what makes
  the guarantee checkable rather than a matter of having anticipated every delimiter. A repeated
  separator, an empty item or an `=` inside a value changes which field text lands in and cannot
  change which parameter owns it.

  **Whitespace between parameters is refused** rather than interpreted, on both the explicit and
  the configured path: it reads as either a separator (a missing comma) or as filler (a stray
  space), each of those leaks the key under the other reading, and nothing in the string says which
  was meant. A connection carrying any is reported as `<connection redacted>` in full. Whitespace
  *around* the whole string is still trimmed, so a pasted value is fine.

  Errors on the profile path never echo a value either. A connection string typed into `profile` —
  the one mistake that would defeat the whole feature — is refused by naming the shape a profile
  name has, not by quoting back what it was handed. The same applies to a *configured* name: an
  entry whose name is not a name is skipped and located, never quoted, because the way that happens
  is an entry written the wrong way round.

- **Neither process this server creates inherits the profile variables.** An engine worker is told
  the one connection it is opening over its private pipe and resolves nothing itself, and the TTD
  recorder needs no connection at all — so `WINDBG_MCP_PROFILE_*` and `WINDBG_MCP_PROFILES` are
  stripped from both. What each of them then launches is the reason: a `launch`ed debuggee inherits
  its worker's environment, and `TTD.exe` hands its own to the recorded target. Those are precisely
  the untrusted programs that must not receive every configured kernel key.

## [0.5.0] - 2026-08-08

### Added

- **Four tools that read the kernel pool from the allocator's own descriptors** —
  `pool_find_tag`, `pool_chunk`, `pool_census` and `pool_diagnostics`, on a broken-in x64 kernel
  target (38 → 42 tools).

  They go through win-kexp's descriptor walk rather than shelling out to `!pool`/`!poolused` and
  parsing the text back, so the answers are structured and all four read **one** snapshot — they
  cannot disagree with each other. Walking every committed pool page is expensive, so that
  snapshot is cached per session and reused; pass `refresh: true` after letting the target run, or
  you are reading a photograph of a target that has since moved.

  Two distinctions the tools keep deliberately, each of them the difference between an answer and
  a guess:

  - **`pool_find_tag` reports only *allocated* chunks.** A freed chunk's tag is not reliably
    preserved by the allocator, so listing freed ones would be inventing data. To ask whether one
    specific address has been freed, ask `pool_chunk` about it.
  - **`pool_chunk` separates a free hole inside a walked region from an address the snapshot never
    covered.** The first — an explicitly free state, `ReusableFree` or `CachedFree` — is the
    finding that a pointer the target still holds is dangling. The second is not its opposite: a
    region the walk never reached looks exactly like memory that was never pool, so the coverage
    the result prints has to be read before concluding anything from it. A third outcome,
    `Unreadable`, is neither — a Verifier guard page reads exactly that way — and says nothing
    about whether the allocator freed anything. `pool_chunk` also reports the **neighbouring**
    chunks, which is what tells you what a reclaim would land next to.

  `pool_diagnostics` exists because a real walk emits tens of thousands of diagnostics across a
  hundred-plus categories: any per-call summary necessarily truncates, and the one line explaining
  a specific heap is reliably not in the truncated head. A plain substring filter located a
  special-pool misclassification in one call, and disproved a wrong hypothesis in another — which
  is the part that saved the most time.

  What holds the set together is that **a walk states its own coverage**, and every result carries
  the walk's own state — chunks seen, diagnostics grouped by category — whenever it comes back
  empty. An incomplete walk is the ordinary outcome on a live kernel rather than a defect (paged
  pool is partly on disk, so `sparse virtual range` diagnostics are physics), which is exactly why
  "the pool holds no such chunk" and "the walk reached almost none of the pool" must not render
  identically. Letting them hid a real bug for three rounds. The walk is also bounded and gives
  the session back at its ceiling, so a query cannot leave every later call to that session queued
  behind it.

  Measured against Server 26100 over KDNET by the live-kernel smoke tier
  ([`docs/smoke-test.md`](./docs/smoke-test.md)): a forced walk returns in ~52s of its 120s
  budget, indexes 530,680 chunks of which 306,227 are allocated, and reports INCOMPLETE. Those
  figures are what they are because of glslang/win-kexp#92, which corrected the reading of
  `_HEAP_PAGE_RANGE_DESCRIPTOR.RangeFlags`: bit `0x01` is ALLOCATED, set on every unit of every
  allocated range, not "this is an LFH subsegment". Read as LFH it sent VS subsegments, plain
  page-range and large allocations, and Verifier special pool through the LFH decoder, which
  refused them and dropped each range at region creation — so a walk quietly omitted about a fifth
  of the pool. The same fix accounts for the walk now costing twice as long: those regions are
  decoded rather than discarded.

  Known limitation: a pool call takes win-kexp's default 120s walk budget rather than the caller's
  own deadline ([#75](https://github.com/glslang/windbg-mcp/issues/75)). With the default 300s
  call timeout the walk finishes well inside it, but a server run with
  `WINDBG_MCP_CALL_TIMEOUT_SECS` set below the walk's cost will time the call out while the engine
  keeps walking.

- **A walkthrough for those tools on a real bug**: MessageManager, a CTF driver's pool
  use-after-free, driven end to end over a live KDNET kernel with no PDB
  ([`docs/messagemanager-walkthrough.md`](./docs/messagemanager-walkthrough.md)). Unlike the HEVD
  and mountmgr tours it is not about *reaching* an IOCTL but about watching a freed chunk get
  reclaimed — and about the four places a new OS release had moved the furniture under the pool
  walker, because a walker that silently returns "empty" is worse than no walker at all. It claims
  what it demonstrates and no more: a confirmed UAF, freed-chunk control, and two pinned forward
  primitives, with SMEP/SMAP/CET ruling out anything but a data-only payoff and the reclaim left
  as where the work continues. `examples/messagemanager/` holds the client that drives the
  driver's IOCTLs from the target VM, since the server cannot issue `DeviceIoControl` itself.

## [0.4.2] - 2026-08-05

### Fixed

- **The supervisor↔worker protocol has a channel of its own, so nothing a worker prints can cost a
  session** ([#65](https://github.com/glslang/windbg-mcp/issues/65)).

  The protocol used to ride the worker's stdin and stdout — the same stdout any code in that
  process can write to. DbgEng's own output never lands there (it is captured through
  `IDebugOutputCallbacks`), but an extension DLL that prints to the console directly does, and an
  *unterminated* stray line swallowed the message written after it. The supervisor drops what it
  cannot parse, and only a `Done` removes a waiter, so the cost of one stray `printf` was not a
  lost line but a lost session: the call timed out, its waiter stayed, and the session counted as
  busy — and so could never be reclaimed — for the life of the server. 0.4.1 mitigated this by
  opening each message with a newline; the property was still a convention about who prints where.

  Each worker now gets a pair of anonymous pipes, created by the supervisor and inherited across
  the spawn: requests down one, messages up the other. An anonymous pipe has no name to open and
  is reachable only through an inherited handle, so nothing outside that pair of processes can
  write on it — "stray output cannot corrupt a reply" is a property of the plumbing rather than of
  what happens to be loaded. The worker's stdout is now only a log: it is drained into the
  server's stderr with the session it came from, which is also the first time an extension's
  console output has been visible at all. Its stdin is `NUL` — never inherited, since the
  supervisor's stdin is the MCP transport.

  What the channel cannot make impossible is a `Done` that is never written, and that is the half
  that strands a waiter, so it is answered directly: a result that cannot be encoded is replaced
  by one that says so, and a channel that cannot be written to means the supervisor is gone — its
  exit fails every outstanding call out. Teardown is unchanged in substance: EOF on the request
  channel now means what EOF on stdin meant, and a worker still releases its target before it
  exits.

## [0.4.1] - 2026-08-04

### Fixed

- **A worker the server never got round to releasing now lets go by itself, rather than being
  killed with its target still attached** ([#67](https://github.com/glslang/windbg-mcp/issues/67)).

  Workers were spawned with tokio's `kill_on_drop`, so the last act of a supervisor on its way out
  was to `TerminateProcess` every worker handle it still held. For a session shutdown had already
  released that is harmless. For one it *missed* it is the whole failure: the worker is killed
  before it can detach, and a live kernel left attached-but-halted is a target machine stopped
  until someone reboots it. Belt-and-braces that cut the braces.

  A worker has handled this on its own since 0.4.0 — its stdin reaching EOF means "the supervisor
  is gone", and it asks its engine to release the target before exiting, bounded at five seconds —
  so the fix is to stop pre-empting it. `kill_on_drop` is gone; EOF is the teardown on every route
  out, including a Ctrl+C or a crash where there is no supervisor left to do anything. Killing is
  now only ever deliberate: after a release was asked for and refused, or on a worker known to
  hold nothing.

  Workers are also spawned into their **own process group**, without which EOF could not be the
  teardown at all on one route: an interactive Ctrl+C goes to every process sharing the console,
  and a child inherits its parent's group, so a worker took the default console handler and died
  where it stood — no stdin close, no release. It is the route where the server can help least,
  since its own default handler ends it before it can run any shutdown, and it is the one a
  developer driving this from a terminal hits by reflex. Driven rather than argued:
  `examples/ctrl_c_teardown.ps1` fires a real Ctrl+C into a console of its own — Ctrl+C cannot be
  aimed, so a test that sends one from `cargo test` takes the runner with it — and checks the
  worker logged its release before exiting. It fails against a build with that one flag removed.

  The way shutdown could miss a worker is closed too. An open that was admitted before the client
  disconnected, and whose worker finished its handshake after shutdown had walked the registry,
  used to register anyway and be handed its opener — starting an attach nobody was left to end.
  Registration now re-checks, under the same lock that closes the gate, so such an open is refused
  and its (target-less) worker ended. That makes the set of workers to release one that cannot
  grow behind shutdown's snapshot, so the timed drain that used to approximate the same guarantee
  is gone with it.

- **A teardown now says what became of each target, instead of claiming more than it knows.**

  Every release outcome was discarded by whoever was its only witness. At shutdown the client has
  already disconnected, so the log is the only place one can land — and the outcome most worth
  hearing, a worker terminated without ever unwinding, was exactly the silent one. The worker
  discarded as much on its side: its engine's error releasing the target, whether the release
  finished at all, and whether it was even asked.

  All of them are reported now, and read by a single rule: a successful release **anywhere**
  outranks this attempt's failure. Two teardowns can race for one session — a reclamation
  releasing in the background, a disconnect collecting it mid-flight — and only the winner is told
  it worked. The loser sees a timeout, a lost worker, or a debugger error, none of which mean the
  target is still attached. Without that rule the new warning would have fired at the very moment
  another teardown cleanly detached, which is how the next real one gets ignored.

  `end_session` also stops telling a caller "nothing is left attached" when the debugger *refused*
  to release. DbgEng resumes and detaches a live kernel as part of releasing it, and that is the
  step that just failed — so terminating the worker afterwards leaves the guest halted, and the
  one caller who most needed to go and check was told there was nothing to check. Dumps and traces
  are named separately, since for those the old sentence was true.

## [0.4.0] - 2026-08-03

### Changed

- **Each debug session now runs in its own engine process, and a session that cannot be unwound
  can be reclaimed** ([#61](https://github.com/glslang/windbg-mcp/issues/61)).

  A live kernel attach waits for its target with `WaitForEvent(INFINITE)`, and DbgEng cannot
  interrupt a wait that has not yet connected. So a guest that is powered off, not booted with
  debugging enabled, or pointed at the wrong host/port/key parked the attach forever — measured on
  hardware at 300s with no bound and no cancellation path. With one engine thread that park owned
  the server: every later tool call queued behind it, `end_session` included, and the only recovery
  was restarting the process. Since the most common mistake in kernel debugging is exactly "the
  guest is not in debug mode", an agent driving this server hit it routinely.

  The server now runs MCP in a supervisor process and each open target in its own engine worker
  child process. The park costs one worker, and **`end_session` terminates it** — asking the worker
  to let go first, killing it if it will not. That is the in-band recovery that did not exist.

  What this changes for callers:

  - **Sessions are concurrent and no longer replace each other.** Triage a crash dump while a kernel
    attach is live; keep two traces open at once. Up to four; at the limit a new open reclaims the
    oldest *idle* session, and refuses with the list if every session is busy. The opener tools no
    longer say "replaces any session already open", because they do not.
  - **`session_id` routes rather than merely detects.** It names the worker holding your target, so
    another caller's open cannot invalidate your handle — the accident the handle was built to
    report is now largely impossible rather than merely visible.
  - **`session_status` lists every session**, with what state each is in and how long it has been
    there. For an attach that has not landed, that duration is the whole signal: a KDNET link
    still coming up (~25s) and one that will never come up were previously indistinguishable, and
    they need opposite responses. Past the point a healthy attach takes it says so, and names the
    recovery. It still never queues on any worker, so it answers while a session is parked.
  - **Nothing outlives the connection.** A disconnect ends every session the way `end_session`
    does: each is asked to release its target, and terminated only if it will not let go within a
    few seconds. So it cannot leak a debugger process or a debuggee.

    Releasing rather than killing matters most for a live kernel, because DbgEng leaves a
    detached-but-*halted* kernel stopped — a worker killed outright takes the target machine down
    with the connection. A disconnect asks every session to release concurrently, waits five
    seconds, and terminates only those that have not finished; the live-kernel tier checks against
    the target's own uptime that the release is what normally happens. The residual risk is a
    session that cannot let go inside that grace — one busy in a long `go`, say — which is
    terminated, and for a live kernel that does leave the target halted. Ending such a session
    with `end_session` first (it allows considerably longer) is the way to avoid it.
  - Failures scoped to a session (a debugger error, a timeout, a refused handle, a worker that
    died) are all tool errors with their text intact. The only JSON-RPC protocol error left is
    "no engine worker could be started at all".

  Reasoning, and why the two cheaper mitigations were not the fix, in
  [`DECISIONS.md`](./DECISIONS.md). The smoke test's debugger tier covers the reported case end to
  end — an attach parked on a dead port, another session opened alongside it, and `end_session`
  reclaiming it — and a new live-kernel tier drives a real KDNET target through attach, coexistence
  and detach, checking against the target's own uptime that a disconnect leaves it *running*.

- **The bounded-command path now has a stated coverage rule, and tests that prove it works.**
  0.3.0 routed `execute`, `dx` and the `ttd_*` tools through a watchdog that Ctrl+Breaks a
  runaway command before it can pin the engine thread, but nothing exercised that interrupt
  end to end, and "why these five?" had no written answer.

  It gains both. The queue-aware budget arithmetic is a pure function with unit tests that ride
  `cargo test` (`src/worker.rs`, next to the watchdog it arms); three `#[ignore]`d tests drive a
  real engine through the shipped binary, proving a runaway command self-aborts and leaves its
  session usable — including from behind a queued job, which is the half win-kexp's own tests
  cannot cover because the queue belongs to this crate. See
  [`docs/smoke-test.md`](./docs/smoke-test.md).

  The coverage rule, recorded in [`DECISIONS.md`](./DECISIONS.md): bound a command when its
  cost scales with the target's size or with an arbitrary caller-supplied expression; leave
  point queries (`k`, `lm`, `u`, `!irp`, …) unbounded. Arming the watchdog measurably rounds a
  command's duration up to a multiple of 200ms, so bounding a 30ms query would make it a 200ms
  one for a runaway case it does not have. `index_trace` is a deliberate exception and
  now says so: it is O(trace), but `-force` deletes before it rebuilds, so an abort can leave no
  usable index at all — its tool description now tells callers to wait rather than re-issue it.

### Fixed

- **Every opener now commits its session handle, including the four that attach or launch.**
  0.3.0 shipped this guarantee for `open_dump` and `open_trace` only, and documented the gap
  for the rest: win-kexp fused the target-creating call and the wait for the initial break
  into one `Result`, so a failure could mean "nothing happened" or "the process started /
  the attach succeeded, then the wait failed" — indistinguishable from here, and needing
  opposite recovery. Those four tools hedged accordingly, telling callers to check
  `vertarget` before opening again instead of claiming a retry was safe.

  win-kexp split them (glslang/win-kexp#71): each opener is now a `x_begin()` returning a
  `PendingTarget` guard, plus a `wait()` on that guard. The guard cannot exist unless the
  side effect succeeded, so there is finally a seam to commit at. `opened_result` hands its
  `transition` a `commit` callback to invoke at that seam, and every opener reads the same
  way — side effect, `commit()`, wait.

  So a failed break-in wait on `attach_process`, `attach_kernel`, `attach_kernel_local` or
  `launch` now returns the error *with* a usable `session_id`, exactly as a failed load wait
  on a dump already did. The hedge is gone: the server knows which side of the seam a failure
  fell on, and says so — re-open when nothing was created, never re-open when the target is
  already there. For `launch` that is the difference between one process and two.

## [0.3.0] - 2026-08-01

### Added

- **Explicit session handles.** The tools that open a target (`open_dump`, `open_trace`,
  `attach_kernel_local`, `attach_kernel`, `attach_process`, `launch`) now return a
  `session_id`, and every tool that touches the debug target accepts it as an optional
  argument, refusing to run when it no longer matches the session the engine holds. One
  process drives one DbgEng session, but an MCP connection is not a session — a client may
  interleave unrelated requests over the same stdio process — so without a handle a call
  could silently act on a target it never opened. Omitting the argument keeps the previous
  behaviour, so existing callers are unaffected. `decode_ioctl` (pure) and `record_trace`
  (independent of the session) do not take it.

  The check and the session transition both run **on the engine thread**, in the same
  queued job as the debugger call, so they are ordered by the queue that already serialises
  DbgEng access. Validating on the caller side would leave a time-of-check/time-of-use
  window: with session A current, an `open_dump` for B can be in flight while the session
  still reads A, so an `end_session(session_id=A)` would pass, queue behind the open, and
  close B. The guarantee is detection rather than exclusion — the opening tools take no
  handle, so holding one does not prevent a replacement, it makes any later call of yours
  that supplies the handle fail instead of acting on the wrong target.

  The opening tools commit the handle as soon as the target transition succeeds — the
  transition being exactly the one DbgEng call that replaces the target, and nothing else.
  Everything after it (the load wait, and the `lm` / `vertarget` / `r` / TTD lifetime
  diagnostic) runs post-commit, so a failure there reports the error *with* the `session_id`
  rather than swallowing it. The target is genuinely open at that point, and the only other
  way to obtain a handle is to open again, which for `launch` means spawning a second
  process. A `wait_for_event` that times out counts: the dump or trace is loaded either way.
  So does a *panic* in the report — several win-kexp methods use `.expect`, and an unwind
  would otherwise skip straight past the code that attaches the handle.

  One limit is documented rather than fixed: win-kexp bundles the wait for the initial
  break into `launch_process`, `attach_process` and the kernel attaches, so from this server
  a failure there can mean "nothing happened" or "the process started / the attach
  succeeded, then the wait failed", and the two are indistinguishable. Those tools therefore
  say so on failure and point at `vertarget` rather than advising a blind retry, which for
  `launch` would start a second process. Splitting them properly is a win-kexp change.

  `execute` and `dx` are the two paths that can swap the target without going through a
  typed tool. For `execute` the session-control commands (`.opendump`, `.attach`, `.detach`,
  `.kill`, `.restart`, `.abandon`, `.remote`, `q`/`qd`/`qq`) retire the current handle,
  matched per command across every DbgEng command boundary — `;` and line breaks alike,
  since `r\n.opendump other.dmp` is two commands and a scanner that split only on `;` would
  see nothing but `r`. `dx`
  reaches command execution through the data model's
  `Debugger.Utility.Control.ExecuteCommand`, which runs any command string, so an expression
  touching command execution retires the handle too — conservatively, because the command is
  a runtime string this server never sees. Both matches are biased toward retiring —
  over-matching costs a re-open, under-matching would let a stale handle through — and
  neither can be exhaustive, so inside `execute` and `dx` a handle is a strong hint rather
  than a guarantee. Everywhere else it is a guarantee.
- **`session_status`.** Reports the handle of the session the server currently holds, or
  that none is open. It exists to recover a `session_id` a caller never received: the
  per-call timeout can fire while the engine thread is still working, and if that job then
  succeeds it commits a handle no reply ever carried. A live `attach_kernel` is the case
  that matters — it waits indefinitely by design, so the call reporting a timeout while the
  attach completes later is normal, not exceptional. Recovering the handle beats the
  alternative of retrying an attach or launch that would connect or spawn a second time.
  Deliberately does not queue on the engine thread, since the situation it addresses is
  that thread being parked.

  It reports *the current* handle, not *your* handle, so recovery is a two-step check. A
  timed-out open now names the handle it would commit — the id is minted before the job is
  queued, so it can be stated up front — and the caller adopts the session only if
  `session_status` reports that same id. Without that correlation, "ask for the current
  handle" would quietly hand the wrong target to a caller following the documented recovery
  flow, with every later session check passing.

  The current handle alone cannot say *which* of those a mismatch means — "not yours" is
  equally true while an open is still queued and after it has permanently failed — and the
  two need opposite responses: a pending open must not be re-run (that attaches or launches
  a second time), while a failed one must be, since nothing else will produce a target. So
  each opener's outcome is recorded (pending / landed / failed) and `session_status` takes
  an optional `session_id` to ask about one. Outcomes are written from inside the job, under
  `catch_unwind`, so a panicking transition cannot leave an open recorded as pending
  forever; a job that never reaches the engine is recorded as failed on the caller side.

  Only *settled* outcomes are evicted when the history fills. Forgetting a pending open
  would be worse than remembering it indefinitely: `session_status` would report it as
  unknown, which tells the caller to open again — duplicating an attach or a launch, and
  letting the original land afterwards and replace the target underneath them. The history
  can therefore exceed its bound while opens are in flight, which is self-limiting, since
  the engine runs jobs one at a time and every job settles.
- **Tool behaviour annotations.** All 37 tools now declare a title and the
  read-only / destructive / idempotent / open-world hints, so a client can tell
  `read_memory` apart from `execute` before prompting the user. `openWorldHint` is true for
  everything that touches a debug target and false only for `decode_ioctl` and
  `session_status`, which never reach the engine. Two reasons put the rest over the line: a
  symbol server on the path
  means almost any command can pull a PDB (`r` symbolizes the current instruction, `k`
  symbolizes every frame, `bp module!Symbol` resolves a name), and a KDNET session puts the
  target itself across a network link, so even a raw `read_memory` is remote traffic. A
  client may be gating network consent on that hint.
- **End-to-end smoke test** (`tests/mcp_smoke.rs`), for the two events the in-process tests
  cannot see: a dependency moving, and the MCP spec revving. Both change the bytes on the wire
  while the Rust API this crate compiles against stays identical, so the existing tests keep
  passing and clients break. It spawns the built binary and speaks hand-written JSON-RPC to it,
  asserting that stdout carries only JSON-RPC (a dependency logging there corrupts the
  transport), that closing stdin exits the process, that every protocol revision the README
  promises is served — including `2026-07-28`'s handshake-free `server/discover` and its rule
  that *every* request, not just the opener, carries the `_meta` protocol keys — and that no
  capability is advertised that this server does not implement. A golden snapshot
  (`tests/golden/tools_list.json`) records the structural `tools/list` surface (schema dialect,
  hints, parameter types) so a `schemars` or `rmcp` bump lands as a readable diff rather than a
  silent client-visible change; re-record with `UPDATE_GOLDEN=1`. The protocol tier needs no
  debugger, target, or network and runs under plain `cargo test`; a second tier
  (`WINDBG_MCP_SMOKE_DUMP=1`) opens the checked-in sample dump through DbgEng and is the
  automated check for a `win-kexp` regression, available in CI on manual dispatch. Runbook,
  including the manual checklist for the live/TTD paths no runner can host, in
  [`docs/smoke-test.md`](docs/smoke-test.md).

### Changed

- **Upgraded the `rmcp` SDK from 1.x to 3.x**, now that the 3.x line is released rather than beta.
  The practical gain is protocol coverage: 3.x knows the `2026-07-28` revision, so the server now
  answers `server/discover` and the stateless per-request lifecycle in addition to the
  `initialize` handshake, and a client that speaks *only* `2026-07-28` can now talk to it. Both
  come from the SDK's defaults (`supported_protocol_versions` covers every known revision, and
  `serve` dispatches a non-`initialize` opening request through the inline lifecycle), so no
  handler code was needed. The only source change the bump required is the `Content` →
  `ContentBlock` rename in `rmcp::model`; the tool surface, its schemas, and the tool-call wire
  format are unchanged.

- **Debugger failures are now tool-execution errors, not protocol errors.** An unresolvable
  symbol, an unreadable address, a target that never stopped, or a recorder that won't
  start now comes back as a normal tool result with `isError: true` and the debugger's text
  intact, which is what lets the model see the failure and correct itself. Previously every
  such failure became a JSON-RPC `-32603`, which clients surface as a transport-level fault
  and models largely cannot act on. Only a dead engine thread remains a protocol error.
  Semantic input validation (`decode_ioctl`'s code, `ttd_memory`'s address) moved the same
  way — the request satisfies the schema, so the complaint belongs in the result.

  The classification is made by the engine worker, which is the only place that can tell a
  failed operation apart from an engine that never came up: a `DebugEngine::new()` failure
  (missing or unusable `dbgeng.dll`) is permanent and now reports as a protocol error, not
  as a retryable tool error that invites the model to try again forever.

- **`index_trace` is now annotated destructive.** It runs `!ttdext.index -force`, which
  deletes and rebuilds an unloadable `.idx` — replacing an on-disk artifact, whatever the
  intent. `destructiveHint: false` told clients otherwise and could bypass confirmation.
- **Typed tools reject operands that would end the command they build.** They interpolate
  their arguments — `u {address}`, `bp {expression}`, `!drvobj {name} 7` — and DbgEng reads
  `;` as a command separator, so `disassemble { address: "rip; .opendump C:\other.dmp" }`
  ran a target swap from a tool advertising `readOnlyHint: true`, and did it without going
  through the check that retires session handles. Quotes are the same problem deferred:
  `bp <location> "command"` is real WinDbg syntax — `ioctl_trace` builds exactly that form —
  so a quote in a breakpoint location arms a target swap that fires on the next hit, outside
  any tool call. `;`, line breaks, and `"` are now refused with a tool error, the last
  everywhere except `dx`, whose data-model expressions use quoted literals legitimately.
  These parameters were always documented as single operands, so nothing legitimate is
  lost: `execute` remains available for command lists, and is annotated destructive and
  handle-checked accordingly.

### Fixed

- **The server no longer introduces itself as the SDK.** `serverInfo` reported
  `{"name": "rmcp", "version": "<sdk version>"}` to every client, on both the `initialize`
  handshake and the `2026-07-28` `server/discover` response — so anything that names or
  keys off the connected server (client UIs, logs, per-server config) saw "rmcp" rather
  than "windbg-mcp", and saw the SDK's version where it wanted this crate's. The
  `#[tool_handler]` macro defaults to `Implementation::from_build_env()`, whose
  `env!("CARGO_CRATE_NAME")` / `env!("CARGO_PKG_VERSION")` resolve inside `rmcp` rather
  than here; naming the server on the attribute takes both from this crate instead. The
  bug predates the `rmcp` 3.x upgrade — 1.x reported the same — so this is the first
  release in which clients see the right identity.

### Documentation

- README now states which MCP protocol revisions the server speaks — `2026-07-28` and the
  `initialize`-handshake era before it — and what a client gets from each.

## [0.2.1] - 2026-07-23

### Added

- **Discoverable via the official MCP Registry.** Each release now also builds an
  `.mcpb` bundle (`windbg-mcp-vX.Y.Z-windows-x64.mcpb`) next to the existing zip and
  publishes a [`server.json`](server.json) entry (`io.github.glslang/windbg-mcp`) to
  [registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io) via the
  `mcp-publisher` CLI, authenticated with GitHub OIDC (no secrets). The bundle's
  descriptor is [`packaging/mcpb/manifest.json`](packaging/mcpb/manifest.json); CI stamps
  the release version into both files and the bundle's SHA-256 into `server.json`, so a
  release keeps the same manual bump list as before — Cargo.toml, plugin.json, the README
  badge, and CHANGELOG.

## [0.2.0] - 2026-07-22

### Added

- **Static IOCTL dispatch reachability.** A new `reachable_from_dispatch` tool answers
  whether a code block — given as an absolute address or `module`+`rva` — is reachable from
  a driver's IOCTL dispatch routine, via a bounded breadth-first walk over the call graph
  built from repeated `uf` disassembly. It follows direct calls and cross-function tail
  jumps; it does **not** follow indirect calls through function pointers or unresolved
  compiler jump tables, so a `REACHABLE` verdict is sound (and reports the call path) while
  `NOT REACHABLE` is a best-effort within-bounds result. The `uf`-parsing and graph-walk
  logic is pure and unit-tested (no debugger needed).
- **Driver IOCTL discovery & user-mode reachability.** A new
  [`driver-ioctl.md`](skills/windbg-debugging/driver-ioctl.md) playbook documents a
  static-first, dynamic-confirm workflow for enumerating a driver's IOCTL surface and
  testing whether each code is reachable from user mode (the openable → namespace →
  deliverable → handled gate model), with WinDbg-native (`uf`) static enumeration by
  default and Binary Ninja as an optional escalation. Five supporting tools:
  - `decode_ioctl` — decode a 32-bit control code into its `CTL_CODE` fields and flag
    `METHOD_NEITHER` / `FILE_ANY_ACCESS` (pure; no session needed).
  - `driver_object` — dump a driver's dispatch table + devices (`!drvobj <name> 7`).
  - `device_object` — inspect a device object's type/characteristics/SecurityDescriptor
    (`!devobj`) to answer the *openable* gate.
  - `irp_stack` — dump an IRP's current `IO_STACK_LOCATION` (`!irp`), defaulting the IRP
    to `@rdx` at a dispatch break.
  - `ioctl_trace` — install a conditional logging breakpoint at the IOCTL dispatch
    routine that prints each `IoControlCode` + buffer lengths and continues.
  - An `examples/sweep_ioctls.ps1` harness (host) + `examples/send_ioctls_target.ps1`
    (target-side `DeviceIoControl` sender) driving the dynamic confirm sweep.
  - `attach_kernel` / `attach_kernel_local` now `.load kdexts` automatically so the
    `!drvobj`/`!devobj`/`!irp` commands behind `driver_object`/`device_object`/`irp_stack`
    resolve; `setup.md` bundles `winxp\kdexts.dll`. Verified end-to-end against a live
    KDNET kernel (the tools captured real mountmgr IOCTLs).
  - [`docs/driver-ioctl-walkthrough.md`](docs/driver-ioctl-walkthrough.md): a worked
    `\Driver\mountmgr` enumeration + reachability report against a live kernel. The
    playbook now ends with a "Write the report" step + template.
- **`record_trace` `env` and `working_dir` options** — pass extra `KEY=VALUE` environment
  entries and a working directory to the recorded target, for programs that refuse to run
  without a specific environment (e.g. a Qt app's `QT_QPA_PLATFORM_PLUGIN_PATH`, or an
  anti-analysis "run me from here" guard). Previously the recorder only inherited the
  server's environment.

### Fixed

- **`index_trace` now works.** It invoked `!tt.index`, which fails with `LoadLibrary(tt)` —
  there is no `tt` extension. The bundled engine exposes trace indexing through `TtdExt.dll`,
  so `index_trace` now runs `!ttdext.index` (building a persistent `.idx` next to the `.run`).
- **`open_trace` flags an unindexed trace.** A freshly recorded `.run` has no `.idx`, so the
  first data-model query silently builds an in-memory index and can run long; `open_trace`
  now says so up front (via `!ttdext.index -status`) and points at `index_trace`.
- **`registers` no longer returns a blank result** when there is no thread context (a
  module-load break or a bare `goto_position 0`); it explains why and how to get a context.
- **A runaway debugger command no longer wedges the session.** `execute`, `dx`, and the
  `ttd_*` query tools now run through a bounded path
  ([`win-kexp`](https://github.com/glslang/win-kexp)'s `execute_command_bounded`) that
  `SetInterrupt`s the engine shortly before the per-call timeout. Previously an unbounded
  command — most importantly a broad `s` memory search — could pin the single engine thread
  indefinitely, so every later tool call timed out behind it and the only recovery was to
  kill and reconnect the server. Now such a command self-aborts (with a note) and the engine
  stays usable. (win-kexp pin bumped to include `execute_command_bounded` + its interrupt drain.)

## [0.1.3] - 2026-06-14

### Fixed

- Ending a live-kernel session (`end_session`) no longer leaves the target
  **frozen**. It was a passive detach, which never tells the target to run, so
  detaching while halted at a break left the guest frozen — one CPU halted, the
  rest spinning — with the breakpoint `int3` still patched. `end_session` now
  clears breakpoints, resumes the target, and does an active detach, leaving the
  kernel running. (win-kexp `777b5c2`.)

## [0.1.2] - 2026-06-14

### Fixed

- **Live kernel debugging now works.** `attach_kernel` / `attach_kernel_local`
  connect, request an initial break-in, and wait with the INFINITE timeout a live
  kernel requires — a finite timeout returned `E_NOTIMPL` and never drove the
  connection — so the engine breaks in, breakpoints resolve, and `go` runs to them.
  The wait is bounded by a watchdog (`SetInterrupt`) so the single engine thread
  can't hang on an unresponsive target; a forced timeout is reported as an error.
- A failed kernel attach now returns a clean error instead of panicking the
  debugger worker thread.
- `go`/step with no active debuggee now returns a clear "No active debuggee" error
  instead of crashing the server (a previously uncatchable engine fault).

### Added

- Example stdio JSON-RPC drivers under `examples/` (live-kernel attach, user-mode
  launch, and robustness regression checks).

### Changed

- The live/kernel skill now instructs asking the user for the target's actual KDNET
  connection string (the port and key can't be guessed).
- CI auto-approves and auto-merges Dependabot PRs.

## [0.1.1] - 2026-06-12

### Added

- Prebuilt Windows x64 binary releases: pushing a `vX.Y.Z` tag now builds
  `windbg-mcp.exe` and attaches `windbg-mcp-vX.Y.Z-windows-x64.zip` (plus a SHA256
  checksum) to the GitHub release, and the setup docs gained a no-Rust install path
  that downloads it into `target\release\`.
- Signed build-provenance attestations for release zips, verifiable with
  `gh attestation verify` (see the README's *Releasing* section).

### Security

- GitHub Actions in the CI and release workflows are pinned to immutable
  commit SHAs, with Dependabot configured to keep the pins (and their
  version comments) up to date.

## [0.1.0]

Initial release, packaged as a single-plugin Claude Code marketplace.

### Added

- **`windbg` MCP server** (Rust, stdio) exposing DbgEng-backed debugging tools:
  session management (open dump/trace, attach to process/kernel, launch, end),
  state queries (registers, memory read, backtrace, modules, threads,
  disassemble, `dx`), execution control (go, step over/into, breakpoints), Time
  Travel Debugging navigation (step back, reverse go, goto position) and
  analysis (`ttd_calls`, `ttd_memory`, `ttd_events`, index), TTD trace recording,
  and a raw `execute` command passthrough.
- **`windbg-debugging` skill** with task playbooks: setup, crash-dump triage,
  live/kernel debugging, and TTD recording/replay/analysis.
- Crash-dump `!analyze` support via automatic WinDbg extension DLL loading.
- Windows CI (format, clippy, build, test) and walkthrough docs with sample dumps.

[Unreleased]: https://github.com/glslang/windbg-mcp/compare/v0.21.0...HEAD
[0.21.0]: https://github.com/glslang/windbg-mcp/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/glslang/windbg-mcp/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/glslang/windbg-mcp/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/glslang/windbg-mcp/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/glslang/windbg-mcp/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/glslang/windbg-mcp/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/glslang/windbg-mcp/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/glslang/windbg-mcp/compare/v0.13.2...v0.14.0
[0.13.2]: https://github.com/glslang/windbg-mcp/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/glslang/windbg-mcp/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/glslang/windbg-mcp/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/glslang/windbg-mcp/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/glslang/windbg-mcp/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/glslang/windbg-mcp/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/glslang/windbg-mcp/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/glslang/windbg-mcp/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/glslang/windbg-mcp/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/glslang/windbg-mcp/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/glslang/windbg-mcp/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/glslang/windbg-mcp/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/glslang/windbg-mcp/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/glslang/windbg-mcp/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/glslang/windbg-mcp/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/glslang/windbg-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/glslang/windbg-mcp/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/glslang/windbg-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/glslang/windbg-mcp/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/glslang/windbg-mcp/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/glslang/windbg-mcp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/glslang/windbg-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/glslang/windbg-mcp/releases/tag/v0.1.0
