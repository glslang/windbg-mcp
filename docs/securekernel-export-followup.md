# Securekernel ARM64 export follow-up — 2026-09-11

## Diagnosis

The eight unresolved matches in the earlier securekernel comparison came from
undecoded instructions, rather than missing input files or failed BinDiff matching.
BN 6.0.10601 Personal exposes each affected function as a single four-byte basic
block but returns no instructions when that block is iterated. All sixteen
endpoints contain the same bytes, `df2203d5`, encoding AArch64 `CLRBHB`.
Arm documents this instruction as AArch64 `HINT #22` in its
[Spectre-BHB white paper, page 7](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Security%20Update%2008%20March%202022/Spectre-BHB%20White%20Paper%20v1.6.pdf).

The pinned SDK BinDiff processor stops instruction collection when
`GetInstructionInfo` fails. Its empty basic block does not produce an exported
flow graph. BinDiff still creates address/call-graph matches for those functions,
but the companion correctly refuses to import them as covered function matches.

The functions are the eight `FrontendBhbClrKiUser*Handler` entries at reference
RVAs `0x10fc00`–`0x10ff80` and target RVAs `0x11ac00`–`0x11af80`, spaced by `0x80`.
This observation does not associate those entries with the CVE fix. The same
instruction bytes occur on both sides.

The [diagnostic capture](samples/securekernel-export-diagnostic-20260911.json)
records each function's name, bounds, bytes, empty instruction list, and absent
exported flow graph, together with the input hashes and normal GUI exit. Its
binary-list snapshot precedes analysis completion; the per-function and export
observations were collected after `update_analysis_and_wait`. The
[executed probe](samples/securekernel-export-diagnostic-20260911.py) is retained
with its source hash. The earlier full comparison remains preserved in the
[ARM64 acceptance record](cve-patch-diff-acceptance.md#arm64-generation-follow-up--2026-09-10).

## Validation scope

Full export coverage means that every function in the captured BN inventory has
an instruction-bearing exported flow graph. It does not establish that BN has
decoded every instruction or discovered every function in the executable.
An export-only workaround must preserve BN's names, types, comments, function
inventory, bytes, identities, and generations. Unknown encodings must continue
to produce honest omissions, and address-only BinDiff rows must remain unresolved.

The exporter now includes a narrow fallback for this exact four-byte encoding
when BN instruction decoding fails. It requires AArch64, a four-byte-aligned
address, enough bytes, and enough space within the existing BN basic block.
It exports a `clrbhb` instruction with its actual bytes and fallthrough behavior.
Other decode failures retain their original handling. The helper's flow-graph
coverage check and the Python importer's identity/generation checks are unchanged.

This does not change BN's instruction-text decoder. In this BN version,
`similarity_diff` can still return zero instruction-text rows for these four-byte
functions; that is unavailable disassembly, not proof of semantic equivalence.
Their exported instruction bytes are available in the separate graph evidence.

## Full comparison recapture

The same reference and target files passed the full capture with the rebuilt
helper and external BinDiff. Target preparation at RVA `0xc0860` completed before
the baseline, and all existing acceptance checks remained enabled.

| Check | Earlier capture | Fixed helper |
| --- | --- | --- |
| Imported matches | 3,109 | 3,117 |
| Omitted functions, reference / target | 8 / 8 | 0 / 0 |
| Unresolved result rows | 8 | 0 |
| Unmatched functions, reference / target | 3 / 26 | 3 / 26 |
| Coverage | Partial | Complete for the captured BN inventory |
| Names, types, comments, function counts and mapped bytes | Unchanged | Unchanged |
| Identities, original hashes, generations and modification flags | Unchanged | Unchanged |
| Guarded target navigation | Passed | Passed |
| Overall capture | `ok: false` | `ok: true` |

All eight previously unresolved pairs are now imported with their original build
identities and RVAs. The [complete capture](samples/securekernel-export-capture-20260911.json.gz)
preserves every match, both unmatched lists, sampled textual diffs, target
navigation, and before/after state. Cleanup reported no errors; the disposable
GUI exited 0 without forced termination.

The [follow-up manifest](samples/securekernel-export-followup-20260911.json) records
the recovered pairs, source/helper/export hashes, fixed diagnostic, validation
results, and separate process exits. Earlier partial captures remain unchanged.
An independent [protobuf inspection](samples/securekernel-export-graph-inspection-20260911.py)
followed each graph's entry block and instruction index in the retained BinExport
files. All sixteen entries have the expected addresses, raw bytes `df2203d5`, and
mnemonic `clrbhb`; there are 3,120 reference graphs and 3,143 target graphs.
The manifest retains those observations and export hashes. No BN or BinDiff
process remained after the final diagnostic.

The native helper build and its CTest regression passed, including rejection of
wrong architectures, unaligned addresses, short input, null input, and a nearby
hint encoding. The test uses explicit failures so release builds execute its
checks. All 181 companion tests passed, including the existing omission and
unresolved-row guards; Ruff, formatting, and documentation checks also passed.

To reproduce, rebuild the companion's helper, restart the disposable BN GUI, and
use the shipped capture helper with the existing verified pair and
`prepare_target_rva=0xc0860`. Native validation is available with:

```console
cmake --build build/binexport --target binja_binexport binja_binexport_clrbhb_test
ctest --test-dir build/binexport -R binja_binexport_clrbhb --output-on-failure
```

This closes the securekernel export-coverage follow-up. Native Ultimate execution
remains tentative; live securekernel execution and CVE attribution are outside
this capture.
