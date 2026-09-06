# Binary Ninja 6 native MCP test drive

Measured on 2026-09-06 against the installed **6.0.10601 Personal** GUI on Apple Silicon
macOS. Connected with the official MCP Python SDK `2.1.1` to the user-started native
listener at `127.0.0.1:24642/mcp`, with authentication disabled as configured by the user.
The server identifies itself as `binaryninja_ui_mcp` version `0.1.0` and advertises protocol
`2025-11-25`. This exercises the native server, not our Python plugin's compatibility with 6.0.

## Result

The probe exercised 32 distinct native tools. Native MCP covers the general inspection and
editing work our plugin duplicates. Keep the
companion focused on driver analysis, evidence, explicit binary selection, and WinDbg pairing.
The native server's text IL and shared active-view selection prevent it from directly replacing
our structured-IL adapter and pinned-view operations.

## Fixtures and method

The workspace initially contained no open items. Two disposable fixtures were opened through
MCP; no existing user binary or database was edited.

| Fixture | Purpose | SHA-256 |
|---|---|---|
| ARM64 Mach-O compiled from a short C program with `clang -g -O1 -fno-inline` | Known control-code branches, size checks, a call, a string, and editable symbols/types | `d4fe791949fa2f14c3de72baca199135eb30f82af641dc335a5bf50e262b5b7c` |
| Hand-built x64 PE with native subsystem | Known PE headers and a second independent view | `d49bf95e9cbef15b832021dedd3827968186de3d17f9be30fad3c17e3dbc93f2` |

Sources, binaries, full tool schemas, call results, and probe scripts were captured locally under
`/tmp/binja6-mcp-drive/`. These are synthetic fixtures, not HEVD/mountmgr captures or evidence
that real-driver dispatch recovery is accepted.

## Observed behavior

| Check | Observation |
|---|---|
| Discovery | 75 tools; 41 declare output schemas, 34 do not. No tool annotations were advertised. |
| Analysis | Open, analyze-and-wait, view metadata, triage, and function search/listing worked. |
| Code | Pseudo C, lifted IL, LLIL, MLIL, HLIL, and MLIL SSA rendered successfully. |
| Source check | Decompilation recovered `0x222008` with `in_size == 8`, `0x22e004` with `in_size < 4` or `out_size < 4`, and the call to `copy_value`. |
| Control flow | Returned eight basic blocks and the matching caller/callee site at `0x1000004d0`. |
| Memory | A 32-byte read at `0x10000047c` matched the original file; hex and base64 decoded identically. Integer `32` and string `"0n32"` requested the same bytes. |
| Pagination | Three one-function pages covered the three functions once, with advancing `nextOffset` and a terminal `truncated: false`. |
| Comments | Set/readback worked; a second set replaced the first comment. |
| Symbols and types | Renamed a function, defined a four-byte typedef, applied it to a function prototype, and verified readback. |
| Local variables | Renamed parameter `code` to `control_code`; the new name appeared in decompilation and variable listing after analysis. |
| Mutation records | Tested edits returned before/after records and `undoable: true`. Actual UI undo was not exercised; no MCP undo tool is advertised. |
| Read limits | 65,537 bytes was refused. An unmapped read returned zero bytes with a `partial_read` warning; a read across the view end returned eight of 32 bytes with the same warning. |
| Errors | Missing symbols, invalid/closed view handles, and unsupported IL form returned structured tool errors; the connection stayed usable. A list limit of 1,001 was clamped to 1,000. |
| Transport | Loopback-only listener confirmed. A foreign Origin was refused with HTTP 403; a foreign Host with no Origin was accepted for initialization. Bearer enforcement was not tested. |

Across the 23 analysis calls on the small, warm Mach-O fixture, median latency was 1.50 ms and
maximum latency was 14.99 ms. Opening the fixture took 635.59 ms. These measurements do not
predict large-driver analysis or concurrent-session performance.

## Differences that affect the bridge

### IL and inspection results are rendered text

Function metadata, CFG, references, listings, Pseudo C, and IL came back as Markdown tables or
fenced text, without `structuredContent`. IL lines retain addresses in their text, but expose no
typed operation/operand tree. `bn_function_il` advertises only `form: "text"`; requesting
`form: "json"` returned `invalid_params` with `Only text IL form is currently supported`.

This works for interactive agent inspection. Our deterministic IOCTL-case recovery still needs
the Binary Ninja API adapter to consume structured IL directly.

### Active selection is shared across clients

With two simultaneous SDK clients, A initially saw the Mach-O view. B opened and selected the PE;
A then saw the PE. A selected the Mach-O; B then saw the Mach-O. Only
`bn_binary_view_set_active` accepts a `binaryView` input among the 75 advertised tools.

Selecting a view and subsequently inspecting or editing it are separate calls. They do not
provide the explicit binary selection and identity validation our paired operations require.
The server's own initialization instructions also require explicitly selecting files opened
through the GUI before using them through MCP.

### PE identity requires parsing headers

PE view metadata included architecture, platform, start, end, and entry point, but no PE
timestamp, `SizeOfImage`, PDB identity, or original-file hash. Reading 512 header bytes worked;
independent parsing recovered timestamp `0x6a9b0001` and `SizeOfImage` `0x3000`.

The reported view span was **`0x2230`**, so `end - start` is not a substitute for `SizeOfImage`.
Our WinDbg coordinate guard and PE-header extraction remain useful.

### Focused bridge operations are additional functionality

The installed tool list has no cursor/navigation, WinDbg pairing, breakpoint/run-to,
driver/IOCTL-map, or provenance-evidence tools. It also advertises no script execution or custom
tool registration tool. This establishes the exposed MCP surface, not whether an undocumented
native extension API exists.

### Closing a modified GUI item requires user interaction

Closing the unmodified PE succeeded, and its old view handle was subsequently refused. Closing
the edited Mach-O with `save: "discard"` returned `requires_user_choice`:
`The UI adapter cannot discard modified data without the existing close prompt`.
Native MCP required user cleanup of the edited fixture. The user subsequently confirmed it
was closed and discarded. Both original fixture files retained their hashes after
the tests. The native listener remains running as the user started it.

## Remaining scope

This run does not validate our plugin on Python 3.13/Binary Ninja 6, actual UI undo, headless MCP,
real-driver analysis, rebasing, or direct WinDbg pairing. The earlier
[bridge acceptance gates](binja-windbg-mcp-validation.md) remain open.
