# Driving this server from Apple's on-device model

Whether the model that ships with macOS can drive `windbg-mcp`, what it costs, and — since it
cannot be reached the way the [ollama bench](local-model.md) reaches its models — what the
interface would have to be.

Every figure here was measured on **macOS 27.0 (build 26A428), Apple M4 Max, 64 GB** on
2026-09-17, with a probe built against the `FoundationModels.swiftinterface` in the 27.0 SDK. They
are a reading of one machine on one day, not invariants: Apple moves the model with the OS, and
this server's surface moves with every tool description.

## The short answer

1. **Not through ollama.** Nothing bridges the two, and the reason is structural rather than a
   missing feature.
2. **Directly through `FoundationModels`, yes.** It is not a maybe — the on-device model opened a
   dump, threaded the returned `session_id` into a second call and answered correctly, in 7.4 s.
3. **Tool-calling is not the constraint; the context window is.** At 8,192 tokens, the full
   61-tool surface does not fit in the window *twice over*, and the choice of `--tools` spec stops
   being a tuning knob and becomes the thing that decides whether a run is possible at all.

## What the machine actually reports

```text
availability            : available
capability toolCalling  : true
capability guidedGeneration : true
capability vision       : true
capability reasoning    : false
contextSize             : 8192
```

Two of those deserve calling out.

**`reasoning: false`.** The eval's `OLLAMA_THINK` axis
([`local-model-eval.md`](local-model-eval.md)) has no counterpart here. A Foundation Models cell
would always be a no-think cell, and a grid that puts it beside a thinking ollama row is comparing
across an axis it did not control.

**`contextSize: 8192`**, read off a real `LanguageModelError.contextSizeExceeded` rather than a
model card — the probe grew a prompt until the framework refused it and reported
`contextSize=8192, tokenCount=32056`. This is the whole budget: instructions, tool surface,
transcript, every tool result and the answer.

## What the surface costs against that window

Token counts are `SystemLanguageModel.tokenCount(for: [any Tool])` — Apple's own tokenizer, not a
rule of thumb. They were measured against a **reconstruction** of the tool surface (descriptions
lifted from the doc comments in `src/server.rs`, input schemas rebuilt from the `JsonSchema`
structs), because this crate does not build on a Mac and no captured `tools/list` with prose exists
in the tree. The reconstruction lands at **83%** of the model-visible bytes
[`tool-surface.md`](tool-surface.md) records on each narrowed surface and 80% on the full one, so
the *scaled* column is each measured count divided by its own fidelity:

| `--tools` | Tools | Real bytes | Measured | Scaled | Share of the 8,192 window |
|---|---:|---:|---:|---:|---:|
| `crash` | 13 | 19,078 | 3,984 | ~4,795 | **59%** |
| `session,inspect,crash` | 23 | 32,322 | 6,795 | ~8,164 | **100%** |
| `session,inspect,exec,crash` | 31 | 43,784 | 9,106 | ~11,007 | **134%** |
| *(absent)* — every tool | 61 | 90,274 | 16,735 | ~21,012 | **256%** |

The `instructions` add **95 tokens**, which is the only line here that is cheap.

**Read the last column as a hard fence, not a warning.** Only `--tools crash` leaves usable room.
`session,inspect,crash` — the bench's `lean` client — consumes the entire window before the first
question is asked.

### The ≈4 B/token rule of thumb does not survive contact with this tokenizer

[`token-budget.md`](token-budget.md) converts bytes to tokens at ≈4 B/token and is careful to call
it an approximation for "JSON of this shape". Measured against Apple's tokenizer, the shape matters
more than that allows — by a factor of three across the things this server actually emits:

| Content | B/token |
|---|---:|
| Documentation prose (`docs/coordinates.md`) | 3.48 |
| This server's tool surface (descriptions + schemas) | 3.93 |
| A `crash_triage`-shaped structured result | 2.32 |
| A `modules`-page-shaped structured result | 2.27 |
| A `disassemble`-shaped structured result | 2.02 |
| A `read_memory` hex dump | **1.24** |

The rule holds for the **surface**, which is mostly English, and breaks for **results**, which are
mostly hex. Addresses, GUIDs, byte strings and JSON punctuation are close to the tokenizer's worst
case, so a debugger's output costs roughly **twice the tokens per byte that its documentation
does**. Anything converting result bytes to tokens for this model should use ~2.2, and ~1.3 for raw
memory.

### And then the results have to fit

Surface plus instructions leaves roughly **3,300 tokens** on the `crash` surface, and that is what
the whole investigation gets. Against the result sizes in [`token-budget.md`](token-budget.md),
converted at the 2.2 B/token measured above:

| Result | Model-visible bytes | ≈ tokens | Against the 3,300 left |
|---|---:|---:|---|
| `session_status` | 297 | 135 | fine |
| `open_dump` | 1,347 | 612 | fine |
| `crash_triage` | 1,855 | 843 | fine |
| `disassemble` | 2,018 | 917 | fine |
| `registers` | 3,480 | 1,582 | half the budget |
| `modules` (one page) | 12,268 | 5,576 | **over the remainder outright** |
| `execute` (`lm`) | 19,420 | 8,827 | **larger than the whole window** |

That is a two-call budget, which is exactly what the live drive below spent: `open_dump` plus
`crash_triage` is ~1,455 tokens and leaves room for one or two more.

`modules` and `execute` are both `inspect`, so on a `crash` surface neither is reachable — the
accidental good news being that the tools which would not fit in this window are the ones the only
fitting surface does not serve.

## The live drive

The proof, on `--tools crash` with stubbed replies standing in for a Windows host:

```text
task: "Open the crash dump at C:\dumps\MEMORY.DMP and tell me the bug check
       code and which driver is at fault."

-> open_dump    {"path": "C:\\dumps\\MEMORY.DMP"}
-> crash_triage {"analyze": false, "session_id": "s1", "frames": 16}

"The bug check code is 0xD1, which corresponds to DRIVER_IRQL_NOT_LESS_OR_EQUAL.
 The faulting driver is HEVD.sys, specifically in HEVD!TriggerArbitraryWrite."

elapsed: 6.5–7.5 s
```

Both calls are well-formed, the order is right, and **the `session_id` from the opener's result was
threaded into the second call** — the one piece of protocol discipline this server needs from every
client, and the thing narrow models most often get wrong.

**Five draws, five identical runs**: two calls, same arguments (only their key order varies), the
right answer every time. That is a rate rather than a sighting, which is the distinction
[`local-model-eval.md`](local-model-eval.md) exists to enforce — but it is one easy task on the
smallest surface with canned replies, and it says nothing about the six-task grid. What it
establishes is that the mechanism works, not that the model is good at this.

## Why not ollama

Ollama runs weights it can load — GGUF through llama.cpp, or MLX. Apple's model is neither
available as weights nor loadable by anything but Apple's own runtime:

- The `ollama` binary (0.34.1) contains no reference to `FoundationModels`, `SystemLanguageModel`
  or Apple Intelligence. There is no backend to select.
- The weights ship as a SIP-protected MobileAsset,
  `/System/Library/AssetsV2/com_apple_MobileAsset_UAF_FM_GenerativeModels`, unreadable without
  privilege and in no format ollama consumes. There is no `.gguf` or `.safetensors` anywhere under
  `AssetsV2`.
- Inference runs in Apple's on-device daemon. The `FoundationModels` framework is the only
  supported way in, and it is Swift-only.

So the question is not "which ollama tag" but "what replaces ollama", and the answer has to be a
Swift process.

An honest alternative worth naming: **macOS 27 added `LanguageModelExecutor`**, which lets a custom
model back a `LanguageModelSession`. That runs the arrow the wrong way — it puts *another* model
behind Apple's session API — so it does not help here, but it is the reason not to assume the
framework is a closed box.

## The interface

A third backend for the bench, beside `ollama` and `claude`. The shape is already carved out:
`local_model_eval.py` dispatches on a `backend` field, refuses a Claude group that asks for an
ollama-only arm, and `tools/claude_code_drive.py` is the precedent for a driver that is not ollama.

**It drives the server exactly the way ollama does, and nothing about the harness changes.** That
was not obvious and is the result of the measurements below: `LanguageModelSession.respond()` runs
the tool-calling loop *internally*, calling tools itself and returning only a final answer, which is
the opposite of what this bench needs — Python owns the loop, applies the read-only fence, and
records a verdict per call. Making Foundation Models behave like `POST /api/chat` instead — hand it
history and tools, get the next tool call back *without* it being executed — turns out to be
possible, so the model half is a drop-in and the transport half is untouched:

```text
tools/local_model_drive.py   the loop, the fence, MCP, the lease keepalive, the records
  |                          UNCHANGED - it already dispatches on a backend
  '-- chat(messages, tools) ------------------------.
        ollama : POST /api/chat                     |
        fm     : tools/fm_chat.swift  <-------------'  one process, one turn
                   rebuild a Transcript from `messages`
                   register tools that REFUSE to run
                   return the tool call in ollama's shape
```

So `tools/fm_drive.py` is a thin module in the shape of `claude_code_drive.py`: it imports
`local_model_drive` for the MCP plumbing and replaces **`chat()` alone**. The keepalive against the
listener's lease, a bearer token of the run's own, `permitted()`, `call_tool()`'s three failure
verdicts, scenario mode and the `WINDBG_MCP_EVAL_OUT` records all stay exactly as they are, which
also means the grader needs no changes at all.

### Making a tool call come back instead of being executed

Three facts, each measured rather than assumed, and the third is a landmine:

- **A tool that throws yields its call.** Foundation Models wraps the error in `ToolCallError` with
  the thrown value as `underlyingError`, and the tool's `name` and `arguments.jsonString` survive
  intact — which is the whole trick. `GenerationOptions.ToolCallingMode` is only
  `allowed`/`required`/`disallowed`, so there is no supported "report, do not run"; this is it.
- **The transcript is reverted when a tool throws** (the default `TranscriptErrorHandlingPolicy`),
  so after the throw the session holds only its instructions. That is *convenient* here rather than
  a problem, because the history has to be rebuilt from the harness's `messages` every turn anyway —
  Python is the one source of truth, exactly as it is for ollama.
- **`Transcript.ToolOutput.id` must equal the `id` of the `ToolCall` it answers.** Pair them and a
  hand-built transcript is accepted; leave them as independent UUIDs and generation fails with
  `InferenceError::inferenceFailed::Unable to tokenize prompt`, which names neither ids nor tool
  outputs and reads like a corrupt prompt. Ollama's messages carry no call ids at all, so the
  pairing is by order, oldest first. This cost the experiment one round and will cost the
  implementation one too if it is not written down.
- **An oversized *surface* does not raise `contextSizeExceeded`.** An oversized *prompt* does, with
  `contextSize` and `tokenCount` on the error — which is how the 8,192 above was read. Hand the
  same session 61 tools instead and it fails much deeper, as
  `InferenceError::inferenceFailed` carrying *"Provided 16,757 tokens, but the maximum allowed is
  8,192."* — untyped, with the two numbers only in prose. The case this backend exists to
  measure is the one the framework does not type, so `fm_chat.swift` reads them out of the message
  and records the overflow as an overflow. Without that it lands in the generic error bucket and a
  grid cannot tell "the surface did not fit" from "something broke".
- **The continuation prompt is the empty string.** Mid-loop the history ends in a tool result with
  no new user turn, and `respond(to:)` always wants a prompt. `respond(to: "")` continues correctly
  — it called `crash_triage` with the `session_id` threaded from the previous result, then
  answered. `respond(to: " ")` does **not**: a single space is read as a real user turn and gets
  "I'm here to help with crash-dump work. What else do you need?". Inventing a sentence like "now
  answer using what the tools returned" works too, and is worse than either — it puts words in the
  conversation that the ollama rows never see, so the cells stop being comparable.

`Transcript` is `Codable`, so the rebuilt history round-trips through JSON (~2.4 KB for a two-call
task). Note `==` on the decoded transcript is **false** while the model accepts it and answers
correctly, so do not assert equality as a health check.

**A subprocess per turn is affordable**, which is what makes the stateless shape practical: the
on-device daemon's prefix cache survives process exit. A cold process answering from a rebuilt
six-entry transcript reported **408 of 409 input tokens cached** and took 1.4 s; two further fresh
processes took 0.82 s each. Prefill is not re-paid per turn, so there is no argument for a
long-lived bridge.

### The one piece of real work: JSON Schema to `GenerationSchema`

Foundation Models does not take JSON Schema. A `Tool` carries a `GenerationSchema`, and the runtime
path to one is `DynamicGenerationSchema` → `GenerationSchema(root:dependencies:)`. The generic tool
is short, because `GeneratedContent` satisfies the `Arguments` constraint on its own and carries
`jsonString` both ways:

```swift
struct DynamicTool: Tool {
    typealias Arguments = GeneratedContent
    typealias Output = String
    let name: String
    let description: String
    let parameters: GenerationSchema          // built from the MCP inputSchema
    func call(arguments: GeneratedContent) async throws -> String {
        try await mcp.callTool(name, arguments.jsonString)   // straight through
    }
}
```

The converter is where the work is. Against this server's actual surface, **60 of 61 tools
translate** with a converter of about 50 lines. What it has to handle, in the order the surface
forces it to:

- **`$ref` / `$defs`.** `usesDefs` is true in
  [`tests/golden/tools_list.json`](../tests/golden/tools_list.json): seven tools carry them, and
  **the definitions nest** — ten distinct types, because `ImageCoordinate` pulls in `CoordinatePdb`
  and `ImageIdentity`, and `BatchStep` pulls in `StepAction` and `Check`.
  `DynamicGenerationSchema(referenceTo:)` plus the `dependencies:` array is the exact match, but
  **a missed dependency fails when the schema is built, not when the tool is called**, with
  `undefinedReferences`. Resolve `$defs` transitively; the first version of the probe did not, and
  eight tools failed to construct.
- **Nullable types.** `string|null` is `isOptional: true` on the `Property`, not a union. Every
  `Option<T>` in `src/server.rs` arrives this way, so this is most of the surface.
- **Enums.** `DynamicGenerationSchema(name:anyOf: [String])` takes a string enum directly —
  `server_log`'s `Level`, `heap_allocations`'s two.
- **Objectless tools.** `attach_kernel_local` takes no arguments, and an empty `properties` is
  rejected. A single optional ignored field is the workaround.
- **Tagged unions — the one that failed.** `debug_batch`'s `StepAction` is an externally-tagged
  Rust enum with struct variants, which `schemars` renders as an `anyOf` of single-key objects.
  `DynamicGenerationSchema(name:anyOf: [DynamicGenerationSchema])` can express exactly that shape,
  so this is a converter that needs writing rather than a wall — but note that `debug_batch` is
  **10,021 model-visible bytes on its own**, roughly 2,550 tokens, or **31% of this model's entire
  window for one tool**. On any surface this model can run, `--tools` has already excluded it.

### Context discipline is the feature, not a nicety

With 3,300 tokens of working room, a driver that appends turns until it dies is not a driver.
Because the history lives in Python's `messages`, compaction is a *harness* concern here rather
than a Swift one — the same list ollama's loop already appends to:

- Have `fm_chat.swift` report `tokenCount` for the transcript it was handed, so the driver learns
  the cost before the turn that would exceed it rather than after.
- When the budget is short, drop older tool *results* from `messages` and keep their calls — a
  debugger transcript is mostly superseded output, and the last result is usually the only one
  still load-bearing. Foundation Models also offers `historyTransform` on a session profile, but
  doing it in Python keeps one implementation of history for both backends.
- `RESULT_LIMIT`, which the ollama driver already has and defaults to off, should default to *on*
  here. It is the difference between one `modules` page ending the run and not.
- Catch `contextSizeExceeded` and record it as an outcome. It is a distinct failure mode from a
  wrong answer, and a grid that scores them the same is measuring the wrong thing — the same
  lesson [`local-model-eval.md`](local-model-eval.md) records about failure modes not being
  visible in scores.

### What a grid would be allowed to claim

Only the `crash` surface fits, so **the tool-surface axis collapses to one cell** for this model.
That is not a defect in the bench; it is the finding. A Foundation Models row can answer "can the
model that ships with the OS drive a 13-tool debugging surface", and it cannot be extended to the
other two surfaces without a smaller server rather than a bigger model. `reasoning: false` removes
the think axis too, and the window is fixed, so of the eval's three axes this backend varies
**none** of them.

The honest experiment is therefore narrow and still worth running: the six existing tasks, on
`--tools crash`, several draws, against the same answer key — reported as its own row and never
folded into an aggregate with the ollama cells, which is the misreading
[`local-model-eval.md`](local-model-eval.md) already warns about.

## If this is pursued

1. ~~**`tools/fm_chat.swift`**~~ — **built.** Reads `{instructions, tools, messages}` on stdin,
   rebuilds the transcript, registers refusing tools, and writes ollama's response shape on stdout.
   The translation it shares with the probe is [`tools/fm_schema.swift`](../tools/fm_schema.swift),
   so there is one converter rather than two:

   ```console
   swiftc -swift-version 6 -O tools/fm_schema.swift tools/fm_chat.swift -o /tmp/fm_chat
   ```

   Driven through a loop shaped like `local_model_drive.run()`, on `--tools crash` with fixtures
   in place of a Windows host, it completes the dump-triage task in **three turns and 13.4 s**:

   | Turn | Prompt tokens | What came back |
   |---|---:|---|
   | 1 | 4,014 | `open_dump {"path": "C:\\dumps\\MEMORY.DMP"}` |
   | 2 | 4,115 | `crash_triage {"session_id": "s1", "analyze": false, "frames": 16}` |
   | 3 | 4,274 (4,273 cached) | the answer: `0xD1`, `HEVD.sys` |

   Note what the middle column says about the shape of this problem: the whole investigation added
   **260 tokens** to a prompt that started at 4,014. On this model the surface *is* the context
   budget, and what an investigation spends is rounding error beside it — until one `modules` page
   arrives and ends the run.

2. ~~**`tools/fm_drive.py`**~~ — **built**, and smaller than expected: it imports
   `local_model_drive`, assigns `drive.chat = chat`, and that is the whole substitution. `run()`
   resolves `chat` from its module globals at call time, so the loop, the fence, `call_tool`'s
   verdicts, the keepalive and the records are all the ollama ones, untouched. It builds
   `fm_chat` on demand (3.1 s) unless `FM_CHAT_BIN` points at one.

   Exercised offline against a fixture, with no listener: the surface measured through
   `drive.as_ollama()` at 16,998 B, a turn returning `open_dump` in ollama's shape, a second
   turn threading the `session_id`, and both axis refusals firing. The full 61-tool surface comes
   back as `ChatFailed: context size exceeded: 16757 tokens against a window of 8192` — the
   overflow arriving as a recorded result rather than a crash, which is what the grid needs.

   **What is still untested is the live path**: every MCP call in that run was a fixture, so the
   handshake, the lease keepalive and session cleanup have not been exercised against a real
   `--listen`. That is the first thing to do when the VM is reachable.
3. **`backend: "fm"` in `local_model_eval.py`**, beside the two refusals that already key on
   backend, so a cell asking for `think` or a `num_ctx` is refused rather than silently ignored —
   this model has neither, and a silently ignored axis is how a grid fakes a controlled result.
4. Re-measure the surface costs against a **real** `tools/list` captured from a Windows host rather
   than the reconstruction above, which is the one number in this document that is inferred.

Step 1 carries no dependency on the VM; steps 2 and 4 need the listener reachable.
