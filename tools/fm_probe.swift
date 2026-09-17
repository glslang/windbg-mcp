// Measure Apple's on-device model against this server's tool surface.
//
// `docs/apple-foundation-models.md` is the write-up; this is what produced every figure in it, and
// re-running it is how those figures are re-derived rather than recalled. It needs macOS 26+ and
// Apple Intelligence switched on:
//
//     /tmp/fm_probe surface <capture.json> [more.json ...]   # window, and what each costs
//     /tmp/fm_probe drive   <capture.json>                   # one canned task, no Windows host
//     /tmp/fm_probe tokens  <file> [file ...]                # bytes per token, by content kind
//
// It compiles together with `fm_schema.swift`, which holds the translation:
//
//     swiftc -swift-version 6 -O tools/fm_schema.swift tools/fm_probe.swift -o /tmp/fm_probe
//
// A capture is an MCP `tools/list` result (`{"tools":[...]}`), the bare array, or ollama's
// function-calling shape, with `name`, `description` and `inputSchema` on each entry.
//
// **One capture per `--tools` spec, each taken from a listener serving that spec.** `surface`
// measures every capture it is given exactly as given and never subsets one, because a narrowed
// surface is not the full surface filtered by name: the server drops a tool's cross-references to
// tools the client cannot see, which is 1,155 B on `crash` alone. An earlier version of this file
// did subset, and published numbers inflated by that much for all three narrowed surfaces.
//
// The translation itself lives in `fm_schema.swift`, shared with `fm_chat.swift` so there is one
// implementation of it rather than two.

import Foundation
import FoundationModels

// MARK: - A tool built at runtime

/// The generic tool. `GeneratedContent` satisfies `Arguments` on its own and carries `jsonString`
/// in both directions, so no per-tool Swift type is needed and the arguments pass through to MCP
/// exactly as the model generated them.
struct DynamicTool: Tool {
    typealias Arguments = GeneratedContent
    typealias Output = String
    let name: String
    let description: String
    let parameters: GenerationSchema
    let invoke: @Sendable (String, String) -> String

    func call(arguments: GeneratedContent) async throws -> String {
        invoke(name, arguments.jsonString)
    }
}

func buildTools(_ surface: [[String: Any]],
                invoke: @escaping @Sendable (String, String) -> String) -> ([any Tool], [String]) {
    let (specs, problems) = buildSpecs(surface)
    return (specs.map { DynamicTool(name: $0.name, description: $0.description,
                                    parameters: $0.parameters, invoke: invoke) }, problems)
}

let INSTRUCTIONS = """
Drive WinDbg/DbgEng for live user-mode, kernel, crash-dump and Time Travel Debugging (TTD) work. \
Open a target first; every other tool routes by the session_id an opener returns.
"""

func pad(_ s: String, _ n: Int) -> String {
    s.count >= n ? s : s + String(repeating: " ", count: n - s.count)
}
func rpad(_ s: String, _ n: Int) -> String {
    s.count >= n ? s : String(repeating: " ", count: n - s.count) + s
}

// MARK: - Subcommands

func reportAvailability(_ model: SystemLanguageModel) {
    print("== availability ==")
    print("availability        : \(model.availability)")
    if #available(macOS 27.0, *) {
        let caps = model.capabilities
        for (label, capability) in [("toolCalling", LanguageModelCapabilities.Capability.toolCalling),
                                    ("guidedGeneration", .guidedGeneration),
                                    ("reasoning", .reasoning),
                                    ("vision", .vision)] {
            print("capability \(pad(label, 9)): \(caps.contains(capability))")
        }
    }
}

/// The context window, read off a refusal rather than a model card.
///
/// There is no API that reports it, so the only honest way to learn it is to exceed it and read
/// `contextSize` out of the error the framework raises.
func reportWindow(_ model: SystemLanguageModel) async -> Int {
    let oversized = String(repeating: "windbg kernel debugger crash dump analysis. ", count: 4000)
    do {
        _ = try await LanguageModelSession(model: model).respond(to: oversized)
        print("contextSize         : not reached by this probe")
        return 0
    } catch let error as LanguageModelError {
        if case .contextSizeExceeded(let exceeded) = error {
            print("contextSize         : \(exceeded.contextSize) (refused \(exceeded.tokenCount))")
            return exceeded.contextSize
        }
        print("contextSize         : unknown - \(error)")
    } catch {
        print("contextSize         : unknown - \(error)")
    }
    return 0
}

func surfaceCommand(_ model: SystemLanguageModel, _ paths: [String]) async throws {
    reportAvailability(model)
    let window = await reportWindow(model)

    print("\n== what each surface costs ==")
    print(pad("capture", 34) + rpad("tools", 6) + rpad("bytes", 9) + rpad("tokens", 9)
          + (window > 0 ? rpad("% window", 10) : ""))
    var allProblems: [String] = []
    for path in paths {
        let surface = try loadSurface(path)
        let (specs, problems) = buildSpecs(surface)
        let tools: [any Tool] = specs.map {
            DynamicTool(name: $0.name, description: $0.description, parameters: $0.parameters,
                        invoke: { _, _ in "{}" })
        }
        let tokens = try await model.tokenCount(for: tools)
        // The same measure `docs/tool-surface.md` calls "model context": name, description and
        // input schema as MCP serialises them. Not the ollama function-calling shape the driver
        // measures its `surface.bytes` in, which wraps each entry and runs about 3% larger.
        let bytes = surface.reduce(0) { total, entry in
            let name = (entry["name"] as? String) ?? ""
            let desc = (entry["description"] as? String) ?? ""
            let schema = entry["inputSchema"].flatMap {
                try? JSONSerialization.data(withJSONObject: $0, options: [.sortedKeys, .withoutEscapingSlashes])
            }
            return total + name.utf8.count + desc.utf8.count + (schema?.count ?? 0)
        }
        let share = window > 0 ? String(format: "%.0f%%", 100.0 * Double(tokens) / Double(window)) : ""
        print(pad((path as NSString).lastPathComponent, 34) + rpad("\(tools.count)", 6)
              + rpad("\(bytes)", 9) + rpad("\(tokens)", 9) + rpad(share, 10))
        allProblems.append(contentsOf: problems)
    }

    if !allProblems.isEmpty {
        print("\n== schema translation ==")
        for problem in allProblems { print("  - \(problem)") }
    }

    print("\ninstructions: \(try await model.tokenCount(for: Instructions(INSTRUCTIONS))) tokens")
}

/// One task end to end, with canned replies standing in for a Windows host.
///
/// It proves the mechanism and nothing else: the answers below are fixtures, so a correct final
/// sentence says the model read the fixture and threaded the `session_id` from the opener into the
/// next call. It is not a score. `tools/local_model_eval.py` is where scores come from.
func driveCommand(_ model: SystemLanguageModel, _ path: String) async throws {
    let replies: [String: String] = [
        "open_dump": #"{"status":"ok","session_id":"s1","kind":"dump","target":"MEMORY.DMP"}"#,
        "crash_triage": #"""
        {"status":"ok","bugcheck":{"code":"0xD1","name":"DRIVER_IRQL_NOT_LESS_OR_EQUAL",\
        "parameters":["0x0000000000000008","0x0000000000000002","0x0000000000000000",\
        "0xfffff80412ab34c0"]},"culprit_module":"HEVD.sys","frames":[{"module":"HEVD",\
        "rva":"0x34c0","symbol":"HEVD!TriggerArbitraryWrite"}]}
        """#,
        "session_status": #"{"status":"ok","sessions":[],"max_sessions":4}"#,
    ]

    final class CallLog: @unchecked Sendable {
        private let lock = NSLock()
        private var lines: [String] = []
        func add(_ line: String) { lock.lock(); lines.append(line); lock.unlock() }
        var all: [String] { lock.lock(); defer { lock.unlock() }; return lines }
    }
    let log = CallLog()

    let surface = try loadSurface(path)
    let (tools, _) = buildTools(surface) { name, arguments in
        log.add("\(name) \(arguments)")
        return replies[name] ?? #"{"status":"ok"}"#
    }

    let session = LanguageModelSession(model: model, tools: tools, instructions: INSTRUCTIONS)
    let task = "Open the crash dump at C:\\dumps\\MEMORY.DMP and tell me the bug check code "
             + "and which driver is at fault."

    print("== live drive: --tools crash, \(tools.count) tools ==")
    let started = Date()
    do {
        let response = try await session.respond(to: task)
        print(String(format: "elapsed: %.1fs", Date().timeIntervalSince(started)))
        for call in log.all { print("  -> \(call)") }
        print("answer: \(response.content)")
    } catch let error as LanguageModelError {
        if case .contextSizeExceeded(let exceeded) = error {
            print("CONTEXT EXCEEDED: contextSize=\(exceeded.contextSize) tokenCount=\(exceeded.tokenCount)")
        } else {
            print("LanguageModelError: \(error)")
        }
        for call in log.all { print("  -> \(call)") }
    }
}

/// Bytes per token, per kind of content.
///
/// The reason this subcommand exists: `docs/token-budget.md` converts at ~4 B/token, which holds
/// for the surface (mostly English) and breaks for results (mostly hex). Point it at a file of
/// each kind rather than trusting one ratio for both.
func tokensCommand(_ model: SystemLanguageModel, _ paths: [String]) async throws {
    for path in paths {
        let text = try String(contentsOfFile: path, encoding: .utf8)
        let tokens = try await model.tokenCount(for: text)
        let bytes = text.utf8.count
        let ratio = tokens > 0 ? Double(bytes) / Double(tokens) : 0
        print("\(pad(path, 28)) \(rpad("\(bytes)", 9)) bytes  \(rpad("\(tokens)", 8)) tokens"
              + String(format: "  %.2f B/token", ratio))
    }
}

// MARK: - main

@main
struct FMProbe {
    static func main() async throws {
        setbuf(stdout, nil)

        let arguments = CommandLine.arguments
        guard arguments.count > 2 else {
            print("usage: fm_probe surface|drive <tools-list.json>")
            print("       fm_probe tokens <file> [file ...]")
            exit(2)
        }

        let model = SystemLanguageModel.default
        guard model.isAvailable else {
            print("the on-device model is not available here: \(model.availability)")
            exit(1)
        }

        switch arguments[1] {
        case "surface": try await surfaceCommand(model, Array(arguments.dropFirst(2)))
        case "drive":   try await driveCommand(model, arguments[2])
        case "tokens":  try await tokensCommand(model, Array(arguments.dropFirst(2)))
        default:
            print("unknown subcommand \(arguments[1])")
            exit(2)
        }
    }
}
