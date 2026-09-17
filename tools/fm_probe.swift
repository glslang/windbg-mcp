// Measure Apple's on-device model against this server's tool surface.
//
// `docs/apple-foundation-models.md` is the write-up; this is what produced every figure in it, and
// re-running it is how those figures are re-derived rather than recalled. It needs macOS 26+ and
// Apple Intelligence switched on:
//
//     /tmp/fm_probe surface <tools-list.json>   # availability, window, what the surface costs
//     /tmp/fm_probe drive   <tools-list.json>   # one canned dump-triage task, no Windows host
//     /tmp/fm_probe tokens  <file> [file ...]   # bytes per token, per kind of content
//
// It compiles together with `fm_schema.swift`, which holds the translation:
//
//     swiftc -swift-version 6 -O tools/fm_schema.swift tools/fm_probe.swift -o /tmp/fm_probe
//
// `<tools-list.json>` is either an MCP `tools/list` result (`{"tools":[...]}`) or the bare array,
// with `name`, `description` and `inputSchema` on each entry. **Capture a real one from a Windows
// host.** The numbers in the doc came from a reconstruction of the surface (descriptions from the
// doc comments in `src/server.rs`, schemas rebuilt from the `JsonSchema` structs), which lands at
// 80-83% of the bytes `docs/tool-surface.md` records, and that gap is the one inferred figure in
// the whole write-up.
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

func buildTools(_ surface: [[String: Any]], only: Set<String>?,
                invoke: @escaping @Sendable (String, String) -> String) -> ([any Tool], [String]) {
    let (specs, problems) = buildSpecs(surface, only: only)
    return (specs.map { DynamicTool(name: $0.name, description: $0.description,
                                    parameters: $0.parameters, invoke: invoke) }, problems)
}

// MARK: - The surfaces, mirroring src/toolset.rs

// Hardcoded rather than derived, because this probe runs on a Mac and `--tools` is resolved inside
// a binary that only builds on Windows. **If `GROUPS` in `src/toolset.rs` moves, this goes stale
// silently** - the tool counts printed below are the check: 13 / 23 / 31 against
// `docs/tool-surface.md`.
let ALWAYS = ["open_dump", "open_trace", "attach_kernel", "attach_kernel_local", "attach_process",
              "launch", "end_session", "session_status", "server_log", "interrupt"]
let INSPECT = ["registers", "current_location", "backtrace", "disassemble", "read_memory",
               "modules", "threads", "execute", "dx", "set_symbol_path"]
let EXEC = ["go", "step_over", "step_into", "run_to_address", "set_breakpoint",
            "continue_async", "wait_for_stop", "break_in"]
let CRASH = ["crash_triage", "exception_triage", "decode_error_reporting"]

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

func surfaceCommand(_ model: SystemLanguageModel, _ path: String) async throws {
    reportAvailability(model)
    let window = await reportWindow(model)

    let surface = try loadSurface(path)
    let stub: @Sendable (String, String) -> String = { _, _ in "{}" }

    print("\n== what the surface costs ==")
    print(pad("--tools", 32) + rpad("tools", 6) + rpad("tokens", 9)
          + (window > 0 ? rpad("% window", 10) : ""))
    let surfaces: [(String, Set<String>?)] = [
        ("crash", Set(ALWAYS + CRASH)),
        ("session,inspect,crash", Set(ALWAYS + INSPECT + CRASH)),
        ("session,inspect,exec,crash", Set(ALWAYS + INSPECT + EXEC + CRASH)),
        ("(absent) - every tool", nil),
    ]
    for (label, only) in surfaces {
        let (tools, problems) = buildTools(surface, only: only, invoke: stub)
        let tokens = try await model.tokenCount(for: tools)
        let share = window > 0 ? String(format: "%.0f%%", 100.0 * Double(tokens) / Double(window)) : ""
        let failed = problems.filter { $0.contains("FAILED TO BUILD") }.count
        print(pad(label, 32) + rpad("\(tools.count)", 6) + rpad("\(tokens)", 9) + rpad(share, 10)
              + (failed > 0 ? "  (\(failed) untranslatable)" : ""))
    }

    let (_, problems) = buildTools(surface, only: nil, invoke: stub)
    if !problems.isEmpty {
        print("\n== schema translation ==")
        for problem in problems { print("  - \(problem)") }
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
    let (tools, _) = buildTools(surface, only: Set(ALWAYS + CRASH)) { name, arguments in
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
        case "surface": try await surfaceCommand(model, arguments[2])
        case "drive":   try await driveCommand(model, arguments[2])
        case "tokens":  try await tokensCommand(model, Array(arguments.dropFirst(2)))
        default:
            print("unknown subcommand \(arguments[1])")
            exit(2)
        }
    }
}
