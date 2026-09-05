# Coordinates — joining a frame to an image somewhere else

A debugger answers in addresses. An address is the least portable thing it knows: it is a fact
about one boot of one machine, and the same function is somewhere else after a reboot, on another
host, or in the disassembler you have the image open in. This is what to use instead, and a worked
example of the join it makes possible.

The tools that emit it are `crash_triage`, `backtrace` and `disassemble`. None of them knows that a
disassembler exists, and that is the design: the coordinate is a form anything can join against,
not an integration with something in particular.

## The coordinate

**`(module, image identity, RVA)`** — never a bare virtual address.

- **`module` + `rva`** come back on every frame and every instruction. The RVA is the offset from
  the image's load base, computed from what the engine reports, and it survives the reboot the
  address does not.
- **The image identity** is the PE `TimeDateStamp` + `SizeOfImage` pair, on every `modules` row as
  `timestamp` and `size`. It is what a symbol server is keyed by, which is not a coincidence: it is
  the industry's existing answer to "is this the same binary".

Both halves are needed. The RVA says *where*; the identity says *in which build*, and a
decompilation of the wrong build is a silent wrong answer rather than an error.

**Neither half is promised.** `module` and `rva` travel together and are absent when the engine
places the address in no loaded module — a freed pool page, an unloaded driver, a corrupted return
address, which is exactly what a driver bug leaves behind. A frame or instruction whose module
*lookup failed* says so separately (`attribution_failed`), because that is an absence of
information rather than a finding about the target.

## The worked example

Every number below is real, from `docs/samples/121524-4703-01.dmp` — an ARM64
`0xFC ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY`. The debugger ran on a Windows VM; the join ran on a
Mac that had never seen the image.

**1. Ask the debugger.** `crash_triage` gives the frames:

```json
{ "index": 1, "address": "0xfffff8013c65c6a4", "module": "nt",
  "rva": "0x25c6a4", "symbol": "nt!KeBugCheckEx", "displacement": "0x14" }
```

and `modules { "filter": "nt" }` gives that module's identity:

```json
{ "name": "nt", "image_name": "ntkrnlmp.exe", "start": "0xfffff8013c400000",
  "timestamp": 1265362548, "size": 19173376, "symbols": "pdb" }
```

**2. Build the symbol-server key.** `TimeDateStamp` as eight uppercase hex digits, then
`SizeOfImage` in hex, unpadded, concatenated:

```text
1265362548 -> 4B6BE674      19173376 -> 1249000      key: 4B6BE6741249000
https://msdl.microsoft.com/download/symbols/ntkrnlmp.exe/4B6BE6741249000/ntkrnlmp.exe
```

**3. Check the image you got is the image you asked for.** Read `TimeDateStamp` and `SizeOfImage`
back out of the PE header and compare. Both matched here. A mismatch is a refusal, not a warning:
the whole point of the identity is that it is checkable.

**4. Resolve the coordinate.** The frame is `rva 0x25c6a4` with displacement `0x14`, so its
function begins at `0x25c690`. That image's export table has `KeBugCheckEx` at exactly `0x25c690`.

The image's own `ImageBase` is `0x140000000`, while the dump had it loaded at `0xfffff8013c400000`.
Nothing about the address survived; everything about the offset did.

**5. Check the code, not just the name.** `disassemble` at that entry reported four instruction
encodings, and all four match the file byte-for-byte:

```text
0x25c690  d503237f  pacibsp
0x25c694  a9bf7bfd  stp fp,lr,[sp,#-0x10]!
0x25c698  910003fd  mov fp,sp
0x25c69c  d2800005  mov x5,#0
```

That is what `bytes` is for. Two images that disassemble differently are different builds whatever
their names say — and this check needs no symbols at all.

## What resolves, and what needs a PDB

Of the six frames on that stack, **one** resolved from the image alone: `KeBugCheckEx`, which is
exported. `KeBugCheck2`, `MiCheckSystemNxFault`, `MiValidFault`, `MiUserFault` and `MmAccessFault`
are internal, so an export table cannot name them and a disassembler will show them as
`sub_25b9c0` until it has the PDB.

The PDB is keyed the same way, but by **GUID + age** rather than timestamp and size. `modules`
reports it as `pdb`, for the modules whose symbols the engine has actually resolved:

```json
{ "name": "nt", "symbols": "pdb",
  "pdb": { "guid": "FE3F58BDA39D2FC13C370618D1DBDF22", "age": 1,
           "key": "FE3F58BDA39D2FC13C370618D1DBDF221" } }
```

`key` is the path segment already assembled — `<pdb>/<key>/<pdb>` — because the age goes in **hex**
and getting that wrong produces a URL that 404s, which is a hard failure to read backwards:

```text
https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/FE3F58BDA39D2FC13C370618D1DBDF221/ntkrnlmp.pdb
```

Put the `.pdb` beside the `.exe` and a disassembler that reads PDBs picks it up.

**It is absent for a module whose symbols are `deferred`**, which on a freshly opened dump is
almost all of them: this reports the PDB the engine *has*, and a deferred module has none until
something makes it look. That is not "this module has no PDB". Nor is it a dead end — the identity
also lives in the image's own debug directory (the CodeView `RSDS` record), so a client that has
fetched the image by the pair above can read it from there. Reporting it here saves that download,
and lets a caller check the PDB it already holds is the right one, which the image cannot do.

`pdb.unmatched` is the field to check before trusting any symbol: it means the engine loaded a PDB
that does not belong to this image, so every name it produces is another build's.

## Four things that will trip you up

**An RVA is per image *and build*.** It is comparable across reboots and across machines for the
same binary, and means nothing against a different one. This is why step 3 is not optional.

**`bytes` is the engine's spelling, not memory order.** On ARM64 `d503237f` is the instruction
word; the four bytes in the file are `7f 23 03 d5`. Compare it against another *disassembly*, or
byte-swap deliberately — do not memcmp it against a file.

**Never reconstruct an image from target memory.** It is relocated, partly paged out, and quite
possibly patched by the thing you are investigating — three ways to hand a decompiler a lie. Fetch
the image by identity, as above.

**The engine's own address form has a backtick in it** — ``fffff801`3c677ef0``. `disassemble`
normalises it out of instruction text, but `execute { "command": "u" }` and everything else raw
still carries it.

## Where this came from

This is section 06 of the split-plane plan — the reason the correlation layer needs no proxy.
Converting an address to an RVA and back requires nothing but this server's own module map, so a
model holding both this server and an analysis server can do the join itself, with no component in
between knowing about both.

The example above is that claim being tested rather than argued: two machines, one coordinate, and
an 11 MB image selected out of a symbol server by two integers.

## Guarded bridge coordinates

The Binary Ninja bridge and host-orchestrated workflows share this location form:

```json
{
  "module": "driver",
  "image_name": "driver.sys",
  "identity": { "timestamp": 1234567890, "size": 65536 },
  "rva": "0x1234"
}
```

`size` is PE `SizeOfImage`. Timestamp and size are matching metadata, not cryptographic
identity. Preserve available original-file SHA-256 and architecture separately for
reproducibility. An unavailable hash is not a match. Paths describe provenance and are
not used to resolve an image across machines. When both sides have a PDB identity, its
GUID and age must match and neither identity may be marked unmatched.

`current_location` reads the instruction pointer, available system thread ID and kernel
processor, and containing coordinate in one worker job. `location_state` distinguishes
`mapped`, `unmapped`, `attribution_failed`, and `context_unavailable`. A running target
is a typed `target_running` error; polling never interrupts it.

`set_breakpoint`, `run_to_address`, and `read_memory` accept `coordinate` instead of their
existing `expression`/`address`. Supply exactly one form and an explicit `session_id` for
coordinates. The worker resolves the unique loaded module and validates its identity and
entire requested range immediately before acting, in the same serialized engine job.
Missing, ambiguous, unloaded, replaced, and out-of-range images are refused. No cached
address from pairing is used for an action.

See [the bridge plan](binja-windbg-mcp-plan.md) and
[validation record](binja-windbg-mcp-validation.md). The independently usable Binary Ninja
plugin is maintained in the separate `binja-windbg-mcp` repository.
