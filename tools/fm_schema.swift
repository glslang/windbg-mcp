// MCP tool definitions translated into what Apple's Foundation Models generates against.
//
// Shared by `fm_probe.swift` (which measures) and `fm_chat.swift` (which drives), because there
// must be exactly one translation of this server's schemas — a second copy is a second set of
// behaviours to keep in step. It carries no top-level code, so it compiles into either:
//
//     swiftc -swift-version 6 -O tools/fm_schema.swift tools/fm_probe.swift -o /tmp/fm_probe
//     swiftc -swift-version 6 -O tools/fm_schema.swift tools/fm_chat.swift  -o /tmp/fm_chat
//
// See `docs/apple-foundation-models.md` for what this is for and what it cost to find out.

import Foundation
import FoundationModels

struct ConversionFailed: Error, CustomStringConvertible {
    let why: String
    var description: String { why }
}

/// One tool's `inputSchema` translated into the shape Foundation Models generates against.
///
/// Stateful because `$defs` are not inlined: a `$ref` becomes `DynamicGenerationSchema(referenceTo:)`
/// and the type it names has to travel separately in `dependencies:`. **A missed dependency fails
/// when the schema is built, not when the tool is called** (`undefinedReferences`), so `emitted`
/// accumulates every definition reached transitively — `ImageCoordinate` pulls in `CoordinatePdb`
/// and `ImageIdentity`, `BatchStep` pulls in `StepAction` and `Check`.
final class SchemaConverter {
    var defs: [String: Any] = [:]
    var emitted: [String: DynamicGenerationSchema] = [:]
    var notes: [String] = []

    func convert(_ node: Any, name: String, path: String) throws -> DynamicGenerationSchema {
        guard let d = node as? [String: Any] else { throw ConversionFailed(why: "\(path): not an object") }

        if let ref = d["$ref"] as? String {
            let key = String(ref.split(separator: "/").last ?? "")
            if emitted[key] == nil, let target = defs[key] {
                // Seeded before the recursive call, so a self-referential type resolves by name
                // instead of recursing forever.
                emitted[key] = DynamicGenerationSchema(referenceTo: key)
                emitted[key] = try convert(target, name: key, path: "$defs/\(key)")
            }
            if emitted[key] == nil { notes.append("\(path): $ref to undefined \(key)") }
            return DynamicGenerationSchema(referenceTo: key)
        }

        let desc = d["description"] as? String

        if let cases = d["enum"] as? [Any] {
            let strings = cases.compactMap { $0 as? String }
            if strings.count == cases.count, !strings.isEmpty {
                return DynamicGenerationSchema(name: name, description: desc, anyOf: strings)
            }
            notes.append("\(path): non-string enum, widened to its base type")
        }

        // **`Option<T>` usually arrives as an `anyOf`, not as a type array.** `schemars` renders
        // an optional enum or struct as `{"anyOf": [{"$ref": …}, {"type": "null"}]}`, and six of
        // this server's tools use it - `read_memory`/`set_breakpoint`/`run_to_address`'s
        // `coordinate`, `server_log`'s `level`, `heap_allocations`'s `backend` and `state`. Left
        // to the fallthrough these become a bare `string`, which builds and then generates
        // arguments the server rejects, so the reconstruction this converter was first written
        // against - which used type arrays - hid the bug entirely.
        //
        // Dropping the null branch is right rather than lossy: nullability travels on the
        // Property's `isOptional`, never on the type.
        if let branches = (d["anyOf"] ?? d["oneOf"]) as? [[String: Any]] {
            let concrete = branches.filter { ($0["type"] as? String) != "null" }
            if concrete.count == 1 {
                return try convert(concrete[0], name: name, path: path)
            }
            if concrete.count > 1 {
                // A real union. Traversing the branches also *defines* anything they `$ref`,
                // which is the other half of the bug: an untraversed branch leaves a reference
                // with no definition and the whole tool fails to build.
                let converted = try concrete.enumerated().map {
                    try convert($1, name: "\(name)_\($0)", path: "\(path)|\($0)")
                }
                return DynamicGenerationSchema(name: name, description: desc, anyOf: converted)
            }
            notes.append("\(path): anyOf with no concrete branch")
        }

        // `Option<T>` can also arrive as ["T", "null"] in a type array; same reasoning.
        let type = (d["type"] as? String) ?? ((d["type"] as? [String])?.first { $0 != "null" })

        switch type {
        case "string":  return DynamicGenerationSchema(type: String.self)
        case "integer": return DynamicGenerationSchema(type: Int.self)
        case "number":  return DynamicGenerationSchema(type: Double.self)
        case "boolean": return DynamicGenerationSchema(type: Bool.self)

        case "array":
            guard let items = d["items"] else {
                notes.append("\(path): array without items, assumed array of string")
                return DynamicGenerationSchema(arrayOf: DynamicGenerationSchema(type: String.self))
            }
            return DynamicGenerationSchema(arrayOf: try convert(items, name: name + "Item", path: path + "[]"))

        case "object":
            let props = (d["properties"] as? [String: Any]) ?? [:]
            let required = Set((d["required"] as? [String]) ?? [])
            guard !props.isEmpty else {
                // An empty `properties` is rejected outright, and `attach_kernel_local` has one.
                // A single optional field nothing reads is the cheapest way through.
                return DynamicGenerationSchema(name: name, description: desc, properties: [
                    .init(name: "_", description: "unused",
                          schema: DynamicGenerationSchema(type: String.self), isOptional: true),
                ])
            }
            var out: [DynamicGenerationSchema.Property] = []
            for (key, value) in props.sorted(by: { $0.key < $1.key }) {
                out.append(.init(name: key,
                                 description: (value as? [String: Any])?["description"] as? String,
                                 schema: try convert(value, name: name + "_" + key, path: path + "." + key),
                                 isOptional: !required.contains(key)))
            }
            return DynamicGenerationSchema(name: name, description: desc, properties: out)

        default:
            // `debug_batch`'s `StepAction` is the real one: an externally-tagged Rust enum rendered
            // by `schemars` as an `anyOf` of single-key objects, which
            // `DynamicGenerationSchema(name:anyOf:)` can express once something walks the branches.
            notes.append("\(path): untyped, treated as string")
            return DynamicGenerationSchema(type: String.self)
        }
    }
}

/// A tool as both programs need it: identity, prose, and a schema the runtime will generate against.
/// What a *call* does is left to each program — `fm_probe` answers from a fixture, `fm_chat` refuses
/// so the call travels back to the harness.
struct ToolSpec {
    let name: String
    let description: String
    let parameters: GenerationSchema
}

/// An MCP `tools/list` result (`{"tools":[...]}`), the bare array, or ollama's function-calling
/// shape — `{"type":"function","function":{"name","description","parameters"}}`.
///
/// **Both shapes, because the bench hands over the ollama one.** `claude_code_drive.py` measures
/// its surface through `as_ollama()` so the backends' surface bytes are comparable rather than
/// merely similar, and this backend does the same; accepting the wrapper here is what lets the
/// driver keep that property instead of measuring one shape and sending another.
func parseSurface(_ raw: Any) throws -> [[String: Any]] {
    var array: [[String: Any]]
    if let wrapped = raw as? [String: Any] {
        if let tools = wrapped["tools"] as? [[String: Any]] {
            array = tools
        } else if let result = wrapped["result"] as? [String: Any],
                  let tools = result["tools"] as? [[String: Any]] {
            array = tools
        } else {
            throw ConversionFailed(why: "object carried no \"tools\" array")
        }
    } else if let bare = raw as? [[String: Any]] {
        array = bare
    } else {
        throw ConversionFailed(why: "expected {\"tools\":[...]}, a bare array, or ollama functions")
    }
    return array.map { entry in
        guard let function = entry["function"] as? [String: Any] else { return entry }
        var unwrapped = function
        if unwrapped["inputSchema"] == nil, let parameters = function["parameters"] {
            unwrapped["inputSchema"] = parameters
        }
        return unwrapped
    }
}

func loadSurface(_ path: String) throws -> [[String: Any]] {
    try parseSurface(try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))))
}

/// Translate a surface, keeping the tools that survive and naming the ones that do not.
///
/// A tool that cannot be translated is **dropped rather than fatal**: a surface is worth driving
/// with 60 of its 61 tools, and the caller decides whether the missing one matters.
func buildSpecs(_ surface: [[String: Any]], only: Set<String>? = nil) -> ([ToolSpec], [String]) {
    var specs: [ToolSpec] = []
    var problems: [String] = []
    for entry in surface {
        guard let name = entry["name"] as? String else { continue }
        if let only, !only.contains(name) { continue }
        let schema = (entry["inputSchema"] as? [String: Any]) ?? ["type": "object", "properties": [String: Any]()]
        let converter = SchemaConverter()
        converter.defs = (schema["$defs"] as? [String: Any]) ?? [:]
        do {
            let root = try converter.convert(schema, name: name + "_args", path: name)
            let generation = try GenerationSchema(root: root, dependencies: Array(converter.emitted.values))
            problems.append(contentsOf: converter.notes.map { "\(name): \($0)" })
            specs.append(ToolSpec(name: name,
                                  description: (entry["description"] as? String) ?? "",
                                  parameters: generation))
        } catch {
            problems.append("\(name): FAILED TO BUILD - \(error)")
        }
    }
    return (specs, problems)
}
