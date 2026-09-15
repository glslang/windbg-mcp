# CLRBHB native validation and proposed upstream correction

## Companion-maintained replacement — accepted

Follow-up 63 is closed locally on 2026-09-15. The user chose to maintain the native
architecture patch in `binja-windbg-mcp` and submit it upstream afterward.
`native/arm64/README.md` in that repository documents the pinned SDK build,
packaging and reversible installation. `tools/capture_arm64.py` validates a new
user profile without changing the normal profile or application bundle.

The [acceptance summary](samples/clrbhb-replacement-acceptance-20260915.json)
records the replacement library hash and loaded-image proof, native text and
`SystemHintOp_CLRBHB` IL, all sixteen complete 12-byte endpoint functions and all
eight complete endpoint diffs. External BinDiff completed with 3,101 matches,
3 reference and 26 target unmatched functions, zero omitted functions, and
unchanged input bytes, function/type/comment hashes and generations. The GUI
exited zero without forced termination or a crash report.

The companion retains the complete compressed capture in
`docs/samples/clrbhb-native-acceptance-20260915.json.gz`, alongside a readable summary
and upstream PR draft. Its 197 Python tests pass, including ten new package tests;
the pinned stable C decoder regression passes CLRBHB, NOP and CSDB. The replacement
supports **Binary Ninja 6.0.10601 / SDK ABI 187 on Apple Silicon macOS**. Other builds
need their own compatibility pin and acceptance. The exporter fallback remains.

## Initial stock-build result — 2026-09-15

Binary Ninja 6.0.10601 Personal still rejects native decoding of `df2203d5`.
The synthetic `CLRBHB; ADD; RET` fixture becomes a four-byte function with no
instruction text and undefined IL. All sixteen retained ARM64 Secure Kernel
endpoints have the same native decoding failure. The disposable GUI exited zero
without forced termination. Follow-up 63 was still open at this initial capture.

The [capture and source-level validation](samples/clrbhb-native-validation-20260915.json)
include verified input hashes, function bounds, instruction/IL observations,
versions, source hashes and normal GUI exit. The installed SDK revision is
`2ddf304b3275aa184e95570404539cbc4beb64c6`; the upstream source checked separately is
`905a5a98d769bb832ba85674b004fec7ac5a224e`.

## Cause and patch

The current upstream generated decoder recognizes the encoding, but the operand
conversion switch omits `ENC_CLRBHB_HI_HINTS`. A standalone call to
`aarch64_decompose(0xd50322df, ...)` returns `-9`. Adding that encoding to the
zero-operand cases makes decomposition and formatting succeed as `clrbhb`.
See the pinned [generated decoder](https://github.com/Vector35/binaryninja-api/blob/905a5a98d769bb832ba85674b004fec7ac5a224e/arch/arm64/disassembler/decode2.c)
and [operand conversion](https://github.com/Vector35/binaryninja-api/blob/905a5a98d769bb832ba85674b004fec7ac5a224e/arch/arm64/disassembler/decode_scratchpad.c).

The [proposed upstream patch](samples/clrbhb-upstream-proposed.patch) adds the
missing operand case and proposes a named `SystemHintOp_CLRBHB` IL intrinsic,
following nearby hint instructions. **At this initial checkpoint, only the standalone decoder change had
been compiled and executed.** The IL/API changes require an upstream plugin build
and GUI analysis validation before acceptance. The intrinsic names an effect;
it does not model the branch predictor's security properties.

The patch is prepared locally for review. The installed Binary Ninja application
and companion exporter were not patched. The exact-encoding exporter fallback
remains necessary for supported older builds.

## Regression evidence

The new [C regression](samples/clrbhb-native-regression.c) fails before the patch
and passes afterward. It also checks NOP and CSDB controls. The existing companion
`native/binexport/clrbhb_test.cpp` passes its exact-encoding, architecture,
alignment and short-input checks. Inspection of `processor.cpp` confirms that
successful native instruction decoding bypasses the fallback.

The [corpus comparison tool](../tools/clrbhb_decoder_compare.py) compares return
codes and text from independently built baseline/patched decoder libraries.
All **42,639** existing corpus entries produce unchanged results. CLRBHB, tested
separately, changes from decode failure to successful `clrbhb` text.

The upstream `disasm_test.py` suite is **not green** on either source tree: both
stop at the same existing `D50049BF` formatting mismatch, line 22,420 of 46,060
(`msr pstate_spsel, #0x9` versus `msr spsel, #0x9`). The differential corpus check
does not replace that suite or claim to fix its expected text.

## Reproduce

Use separate baseline and patched checkouts of the pinned upstream revision.
Apply the patch only to the patched checkout. In each `arch/arm64/disassembler`
directory, build the standalone libraries and test wrapper:

```console
make -f Makefile-local -j4 libdecode.a libformat.a
make -f Makefile-local gofer.so
```

From this repository, substitute the checkout paths:

```console
cc -I /path/to/patched/arch/arm64/disassembler \
  docs/samples/clrbhb-native-regression.c \
  /path/to/patched/arch/arm64/disassembler/libdecode.a \
  /path/to/patched/arch/arm64/disassembler/libformat.a -o /tmp/clrbhb-regression
/tmp/clrbhb-regression
python3 tools/clrbhb_decoder_compare.py \
  --before /path/to/baseline/arch/arm64/disassembler/gofer.so \
  --after /path/to/patched/arch/arm64/disassembler/gofer.so \
  --corpus /path/to/patched/arch/arm64/disassembler/test_cases.txt \
  --output /tmp/clrbhb-corpus.json
```

Use the [GUI launcher](../tools/bn_followup_probe.py) with `--case decode`, as
documented in [the validation runbook](followups-validation.md). The endpoint
probe is hash-gated to the recorded ARM64 pair. It records native instruction
information, synthetic/real function analysis, and provider availability. If
native decoding and analysis succeed, it runs a complete external comparison,
pages all results and the eight affected diffs, and checks unchanged input state.
On the tested build those prerequisites fail, so the new comparison is `not_run`.

Closing 63 requires a supported upstream build that passes the real GUI decoder,
function-analysis and comparison checks. A successful standalone decoder patch
does not establish those results.
