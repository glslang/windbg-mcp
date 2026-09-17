// One turn of Apple's on-device model, in the shape ollama's `POST /api/chat` answers in.
//
// This is the model half of the Foundation Models backend and nothing else: it owns no MCP
// connection, executes no tool, and keeps no state between runs. `tools/local_model_drive.py`
// keeps the loop, the read-only fence, the lease keepalive and the eval records exactly as it has
// them for ollama, and swaps only `chat()` for a run of this program. See
// `docs/apple-foundation-models.md`.
//
//     swiftc -swift-version 6 -O tools/fm_schema.swift tools/fm_chat.swift -o /tmp/fm_chat
//     /tmp/fm_chat < request.json
//
// **stdin** is one request:
//
//     {"tools": [ <MCP tools/list entries> ],
//      "messages": [ {"role":"system"|"user"|"assistant"|"tool", ...} ]}
//
// **stdout** is one response in ollama's shape, so the Python side can hand it straight to the
// loop it already has:
//
//     {"message": {"role":"assistant","content":"","tool_calls":[{"function":{"name":…,"arguments":{…}}}]},
//      "prompt_eval_count": 4201, "eval_count": 18, "done": true}
//
// Three things about this were measured rather than assumed, and each one is load-bearing:
//
//   1. **A tool that throws yields its call instead of running it.** Foundation Models drives the
//      tool-calling loop itself and returns only a final answer, which is the opposite of what the
//      bench needs. Every tool here refuses, the framework wraps the refusal in a
//      `ToolCallError`, and the call is recovered from `underlyingError` — this is what makes the
//      model half a drop-in. `ToolCallingMode` offers no supported "report, do not run".
//   2. **A tool output's id must equal the id of the call it answers.** Otherwise generation fails
//      with `InferenceError::inferenceFailed::Unable to tokenize prompt`, which names neither ids
//      nor tool outputs. Ollama messages carry no call ids, so they are paired here by order
//      through `pending`.
//   3. **The continuation prompt is the empty string, not a space and not a nudge.** Mid-loop the
//      history ends in a tool result with no new user turn. `respond(to: "")` continues correctly;
//      `respond(to: " ")` is read as a real user turn and answers "what else do you need?", and an
//      invented sentence would put words in the conversation the ollama rows never see.

import Foundation
import FoundationModels

// MARK: - Every tool refuses, so the call travels back to the harness

struct ToolCallRequested: Error {
    let name: String
    let argumentsJSON: String
}

struct RefusingTool: Tool {
    typealias Arguments = GeneratedContent
    typealias Output = String
    let name: String
    let description: String
    let parameters: GenerationSchema
    func call(arguments: GeneratedContent) async throws -> String {
        throw ToolCallRequested(name: name, argumentsJSON: arguments.jsonString)
    }
}

/// Foundation Models wraps whatever a tool threw; the call is inside.
func requestedCall(_ error: any Error) -> ToolCallRequested? {
    if let direct = error as? ToolCallRequested { return direct }
    if let wrapped = error as? LanguageModelSession.ToolCallError {
        return requestedCall(wrapped.underlyingError)
    }
    return nil
}

/// An overflow that arrives as prose rather than as `LanguageModelError.contextSizeExceeded`.
///
/// **The case this backend exists to measure takes the untyped path.** An oversized *prompt*
/// raises `contextSizeExceeded` with `contextSize` and `tokenCount` on it; an oversized *tool
/// surface* — 61 tools against an 8,192-token window — fails deeper, as
/// `InferenceError::inferenceFailed` carrying "Provided 16,757 tokens, but the maximum allowed is
/// 8,192." So the numbers are read out of the message, because there is nowhere else to read them
/// from, and a surface that does not fit is recorded as the overflow it is rather than as an
/// unexplained error. If a future release types this properly the typed branch already catches it
/// and this one stops matching.
func overflowFromMessage(_ error: any Error) -> (provided: Int, maximum: Int)? {
    let text = "\(error)"
    guard let match = text.firstMatch(of: /Provided ([\d,]+) tokens, but the maximum allowed is ([\d,]+)/)
    else { return nil }
    let digits = { (s: Substring) in Int(s.replacingOccurrences(of: ",", with: "")) }
    guard let provided = digits(match.1), let maximum = digits(match.2) else { return nil }
    return (provided, maximum)
}

// MARK: - Output

func emit(_ object: [String: Any]) -> Never {
    let data = (try? JSONSerialization.data(withJSONObject: object)) ?? Data("{}".utf8)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
    exit(0)
}

/// Errors travel as JSON on stdout rather than as an exit code, because the Python side treats a
/// refusal as a *result* — a window too small for the surface is the measurement, not a crash.
func fail(_ message: String, kind: String, extra: [String: Any] = [:]) -> Never {
    var out: [String: Any] = ["error": message, "error_kind": kind, "done": true]
    out.merge(extra) { a, _ in a }
    emit(out)
}

// MARK: - Rebuild the transcript from the harness's message list

func text(_ message: [String: Any]) -> String { (message["content"] as? String) ?? "" }

/// `{"function": {"name": …, "arguments": {…}}}`, ollama's shape, which is also what this program
/// emits — so a call it reports comes back to it unchanged on the next turn.
func toolCalls(of message: [String: Any]) -> [(String, Any)] {
    guard let raw = message["tool_calls"] as? [[String: Any]] else { return [] }
    return raw.compactMap { call in
        let function = (call["function"] as? [String: Any]) ?? call
        guard let name = function["name"] as? String else { return nil }
        return (name, function["arguments"] ?? [String: Any]())
    }
}

func generated(_ arguments: Any) throws -> GeneratedContent {
    if let string = arguments as? String {
        return try GeneratedContent(json: string.isEmpty ? "{}" : string)
    }
    let data = try JSONSerialization.data(withJSONObject: arguments)
    return try GeneratedContent(json: String(decoding: data, as: UTF8.self))
}

// MARK: - Request

@main
struct FMChat {
    static func main() async {
        setbuf(stdout, nil)

        let input = FileHandle.standardInput.readDataToEndOfFile()
        guard !input.isEmpty,
              let request = (try? JSONSerialization.jsonObject(with: input)) as? [String: Any] else {
            fail("stdin was not a JSON object", kind: "bad_request")
        }

        let model = SystemLanguageModel.default
        guard model.isAvailable else {
            fail("the on-device model is unavailable: \(model.availability)", kind: "model_unavailable")
        }

        // **`{"probe": "window"}` reads the enforced context window from the running system.**
        // There is no API that reports it, so the only honest way to learn it is to exceed it and
        // read `contextSize` off the refusal. The driver asks once per run rather than recording a
        // figure measured on some other OS build as if it were this run's runtime identity - the
        // window is a property of the model the OS ships, and both move.
        if (request["probe"] as? String) == "window" {
            let oversized = String(repeating: "windbg kernel debugger crash dump analysis. ", count: 4000)
            do {
                _ = try await LanguageModelSession(model: model).respond(to: oversized)
                fail("the probe prompt did not exceed the window", kind: "window_not_reached")
            } catch let error as LanguageModelError {
                if case .contextSizeExceeded(let exceeded) = error {
                    emit(["context_size": exceeded.contextSize, "probed_with": exceeded.tokenCount])
                }
                if let overflow = overflowFromMessage(error) {
                    emit(["context_size": overflow.maximum, "probed_with": overflow.provided])
                }
                fail("\(error)", kind: "window_probe_failed")
            } catch {
                if let overflow = overflowFromMessage(error) {
                    emit(["context_size": overflow.maximum, "probed_with": overflow.provided])
                }
                fail("\(error)", kind: "window_probe_failed")
            }
        }

        let messages = (request["messages"] as? [[String: Any]]) ?? []
        guard !messages.isEmpty else { fail("no messages", kind: "bad_request") }

        let surface: [[String: Any]]
        do {
            surface = try parseSurface(request["tools"] ?? [])
        } catch {
            fail("\(error)", kind: "bad_request")
        }

        let (specs, problems) = buildSpecs(surface)
        let tools: [any Tool] = specs.map { RefusingTool(name: $0.name, description: $0.description, parameters: $0.parameters) }
        let definitions = specs.map {
            Transcript.ToolDefinition(name: $0.name, description: $0.description, parameters: $0.parameters)
        }
        for problem in problems where problem.contains("FAILED TO BUILD") {
            FileHandle.standardError.write(Data("fm_chat: \(problem)\n".utf8))
        }

        // A trailing user message is the *new* prompt for this turn rather than history; anything else
        // means the turn continues from a tool result and the prompt is empty (see note 3 above).
        var history = messages
        var prompt = ""
        if let last = history.last, (last["role"] as? String) == "user" {
            prompt = text(last)
            history.removeLast()
        }

        var instructionText: [String] = []
        var entries: [Transcript.Entry] = []
        var pending: [String] = []          // call ids awaiting their output, oldest first
        var callCounter = 0

        for message in history {
            let role = (message["role"] as? String) ?? ""
            switch role {
            case "system":
                instructionText.append(text(message))

            case "user":
                entries.append(.prompt(.init(segments: [.text(.init(content: text(message)))])))

            case "assistant":
                let calls = toolCalls(of: message)
                if calls.isEmpty {
                    let content = text(message)
                    if !content.isEmpty {
                        entries.append(.response(.init(assetIDs: [], segments: [.text(.init(content: content))])))
                    }
                } else {
                    var built: [Transcript.ToolCall] = []
                    for (name, arguments) in calls {
                        callCounter += 1
                        let id = "call-\(callCounter)"
                        pending.append(id)
                        do {
                            built.append(.init(id: id, toolName: name, arguments: try generated(arguments)))
                        } catch {
                            fail("tool call arguments were not JSON: \(error)", kind: "bad_request")
                        }
                    }
                    entries.append(.toolCalls(.init(built)))
                }

            case "tool":
                // Paired by order: ollama's tool messages carry no call id, and an id that does not match
                // its call is what produces "Unable to tokenize prompt".
                let name = (message["tool_name"] as? String) ?? (message["name"] as? String) ?? "tool"
                guard !pending.isEmpty else {
                    fail("a tool result arrived with no outstanding call (\(name))", kind: "bad_request")
                }
                let id = pending.removeFirst()
                entries.append(.toolOutput(.init(id: id, toolName: name, segments: [.text(.init(content: text(message)))])))

            default:
                continue
            }
        }

        if !pending.isEmpty {
            fail("\(pending.count) tool call(s) have no result in the message list", kind: "bad_request")
        }

        var instructionParts: [String] = []
        if let supplied = request["instructions"] as? String { instructionParts.append(supplied) }
        instructionParts.append(contentsOf: instructionText)
        let instructions = instructionParts.filter { !$0.isEmpty }.joined(separator: "\n\n")

        // Instructions must be the first entry, and they are what carries the tool definitions.
        entries.insert(.instructions(.init(segments: [.text(.init(content: instructions))],
                                           toolDefinitions: definitions)), at: 0)

        // MARK: - The turn

        let transcript = Transcript(entries: entries)
        let session = LanguageModelSession(model: model, tools: tools, transcript: transcript)
        let started = Date()

        /// What the prompt cost, for the eval's token columns. `Response.usage` carries it on a turn that
        /// answered; a turn that stopped at a tool call has no `Response`, so it is measured instead and
        /// said to be measured.
        func measuredPromptTokens() async -> Int? {
            try? await model.tokenCount(for: transcript)
        }

        do {
            let response = try await session.respond(to: prompt)
            var out: [String: Any] = [
                "message": ["role": "assistant", "content": response.content],
                "done": true,
                "total_duration": Int(Date().timeIntervalSince(started) * 1e9),
            ]
            if #available(macOS 27.0, *) {
                out["prompt_eval_count"] = response.usage.input.totalTokenCount
                out["eval_count"] = response.usage.output.totalTokenCount
                out["fm"] = ["cached_token_count": response.usage.input.cachedTokenCount,
                             "tools_translated": specs.count,
                             "tools_dropped": problems.filter { $0.contains("FAILED TO BUILD") }.count]
            } else if let measured = await measuredPromptTokens() {
                out["prompt_eval_count"] = measured
                out["fm"] = ["prompt_tokens_measured": true, "tools_translated": specs.count]
            }
            emit(out)
        } catch let error where requestedCall(error) != nil {
            let call = requestedCall(error)!
            let arguments = (try? JSONSerialization.jsonObject(with: Data(call.argumentsJSON.utf8)))
                ?? [String: Any]()
            var out: [String: Any] = [
                "message": ["role": "assistant", "content": "",
                            "tool_calls": [["function": ["name": call.name, "arguments": arguments]]]],
                "done": true,
                "total_duration": Int(Date().timeIntervalSince(started) * 1e9),
            ]
            var fm: [String: Any] = ["tools_translated": specs.count,
                                     "tools_dropped": problems.filter { $0.contains("FAILED TO BUILD") }.count]
            if let measured = await measuredPromptTokens() {
                out["prompt_eval_count"] = measured
                fm["prompt_tokens_measured"] = true
            }
            out["fm"] = fm
            emit(out)
        } catch let error as LanguageModelError {
            if case .contextSizeExceeded(let exceeded) = error {
                // The measurement this backend exists to make, not an accident: the window is 8,192 and
                // most of this server's surfaces do not fit in it.
                fail("context size exceeded", kind: "context_size_exceeded",
                     extra: ["context_size": exceeded.contextSize, "token_count": exceeded.tokenCount])
            }
            if let overflow = overflowFromMessage(error) {
                fail("context size exceeded", kind: "context_size_exceeded",
                     extra: ["context_size": overflow.maximum, "token_count": overflow.provided])
            }
            fail("\(error)", kind: "language_model_error")
        } catch {
            if let overflow = overflowFromMessage(error) {
                fail("context size exceeded", kind: "context_size_exceeded",
                     extra: ["context_size": overflow.maximum, "token_count": overflow.provided])
            }
            fail("\(error)", kind: "error")
        }
    }
}
