//! What a tool's `outputSchema` carries: the constraints, and not the prose.
//!
//! Every typed tool declares an output schema generated from the [`crate::structured`] types, and
//! `schemars` emits each one as a self-contained document — so every type reachable from a tool's
//! answer is inlined into that tool's `$defs`, doc comments and all. That is fine once. It is
//! [`ErrorCategory`](crate::structured::ErrorCategory) thirty-three times, because every tool that
//! can fail answers with an [`Outcome`](crate::structured::Outcome).
//!
//! Measured on the payload rather than reasoned about: **68% of every `outputSchema` byte this
//! server emits was a `description`** — 217,423 B of 320,365 B, which is 55% of the whole
//! `tools/list` answer. [`strip_descriptions`] removes them, and the payload goes 394,883 B →
//! 177,460 B with **not one byte** of change to what a model reads.
//!
//! The reason that trade is one-sided is that `description` has no reader here:
//!
//! * A model never sees an `outputSchema` at all. That is the measurement
//!   [`docs/token-budget.md`](../docs/token-budget.md) opens with, taken against a real client:
//!   a tool definition reaches a model as name, description and *input* schema.
//! * A validator does not read it either. `description` is an annotation keyword in JSON Schema —
//!   it constrains nothing, so an instance that validated before validates now.
//! * A human has three better copies: the rustdoc these strings are generated from, the
//!   structured-results table in `docs/structured-results.md`, and the tool's own model-visible
//!   `description`.
//!
//! So the prose stays where it is written and is charged for where it is read. What the schema
//! keeps is the part that is *load-bearing* — the `status` discriminator, the `const` vocabularies,
//! `required`, the types — which is what `DECISIONS.md`'s "A typed result is a second channel"
//! entry was actually arguing for when it made one schema cover both branches of a result.
//!
//! This also ends the compounding, which is the half that matters going forward. Adding `PdbInfo`
//! — one optional four-field type on one field of `ModuleInfo` — cost 15,610 B of wire and 0 B of
//! model context, because `ModuleInfo` is embedded in six output shapes. The same type costs
//! roughly a seventh of that now: the multiplier is unchanged, but what is being multiplied is a
//! handful of keywords rather than a paragraph.
//!
//! The other thing this module does is **add** one keyword, for the opposite reason: a root
//! `type: "object"` that `schemars` does not emit for a discriminated union and rmcp does not
//! supply, without which every released TypeScript-SDK client rejects the whole `tools/list` and
//! is left with no tools at all. [`object_rooted`] has the measurements.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};

use rmcp::model::JsonObject;
use schemars::JsonSchema;
use serde_json::Value;

/// The `outputSchema` a tool declares, with the prose taken out.
///
/// A drop-in for `rmcp`'s `schema_for_output`, and the only thing `src/server.rs` should call —
/// deliberately *not* named after it, because the point of the module docs above is lost the
/// moment one tool declares its schema the other way round, and a name one import line away from
/// the original is a name that will come back.
///
/// Cached by type, like the function it wraps, because `tools/list` rebuilds the whole router and
/// there are thirty-three of these to walk.
pub fn constraints_of<T: JsonSchema + Any>() -> Arc<JsonObject> {
    static CACHE: LazyLock<RwLock<HashMap<TypeId, Arc<JsonObject>>>> =
        LazyLock::new(Default::default);

    if let Some(cached) = CACHE
        .read()
        .expect("output schema cache poisoned")
        .get(&TypeId::of::<T>())
    {
        return cached.clone();
    }

    let lean = Arc::new(object_rooted(strip_descriptions(
        &rmcp::handler::server::tool::schema_for_output::<T>(),
    )));
    // **The stored one wins, always.** Two callers can miss the read above at once — the lock is
    // dropped before the walk, deliberately, so a walk cannot block every other type's lookup —
    // and then both arrive here with a document of their own. A plain `insert` lets the second
    // overwrite the first, so one type has two `Arc`s alive and a caller that asked twice can be
    // handed two different ones. `or_insert` keeps whichever landed first and hands it back, at
    // the cost of the loser's wasted walk, which happens once per type at most.
    //
    // Observed as `the_same_type_is_walked_once` failing on an x64 CI runner and nowhere else:
    // three tests in this file ask for `OpenOutcome`, plus every test that builds a `router()`,
    // so the window is real and only ever needed the scheduling to hit it.
    CACHE
        .write()
        .expect("output schema cache poisoned")
        .entry(TypeId::of::<T>())
        .or_insert(lean)
        .clone()
}

/// The root's `"type": "object"`, supplied where the generator emitted no `type` at all.
///
/// Every structured result here is an [`Outcome`](crate::structured::Outcome) — a serde
/// internally-tagged enum — and `schemars` renders one as `{ $schema, oneOf, $defs }` with the
/// object-ness stated on each branch and nowhere at the root. rmcp does not fill it in: its
/// `schema_for_input` requires a root `type: "object"` and refuses anything else, while
/// `schema_for_output` deliberately does not, because SEP-2106 (`2026-07-28`) relaxed the
/// requirement for output schemas.
///
/// The relaxation is what a *server* may emit, not what clients accept. Every released
/// `@modelcontextprotocol/sdk` 1.x — through 1.30.0 — parses `Tool.outputSchema` as
/// `z.object({ type: z.literal("object"), … })`, and `tools/list` as `z.array(ToolSchema)`, so a
/// single non-conforming tool fails the array and the client is left with **no tools at all** —
/// not 50 of 51 (issue #223). Such a client negotiates `2025-11-25`, which rmcp knows and echoes,
/// so the session runs under the revision that requires the keyword anyway.
///
/// Supplying it is not a concession to old clients, because the keyword is *true*: MCP types
/// `structuredContent` as a JSON object in every revision, so a tool result can be nothing else.
/// Nor does it change what validates — measured, with `ajv` on both shapes: each branch of the
/// `oneOf` already carries `"type": "object"`, so success, failure, a payload missing its required
/// fields and an unknown discriminator all get the same verdict either way.
///
/// A root that *does* declare a type is left alone rather than corrected. Nothing produces one
/// today; if something ever does, the type it declares is either `object` already or a bug worth
/// seeing, and this function runs on every `router()` build — so the invariant is asserted in the
/// tests below and on the wire in `mcp_smoke`, where a failure can be read rather than crashed on.
fn object_rooted(mut schema: JsonObject) -> JsonObject {
    schema
        .entry("type")
        .or_insert_with(|| Value::String("object".into()));
    schema
}

/// Every `description` in a JSON Schema document, removed.
///
/// **Structurally, not by key name.** The obvious implementation — walk the whole JSON and drop
/// every `"description"` wherever it appears — is wrong in a way nothing would report: a struct
/// with a field *called* `description` renders as `properties: { "description": { … } }`, and
/// blind removal deletes that field from the schema rather than its documentation. No structured
/// type has such a field today; the one that does is the one this would break.
///
/// So the walk only descends where a JSON Schema keyword says a subschema lives, and only removes
/// `description` from a position that is itself a schema.
fn strip_descriptions(schema: &JsonObject) -> JsonObject {
    let mut lean = schema.clone();
    strip_in_place(&mut lean);
    lean
}

/// Keywords whose value is one subschema. `items` is here rather than below because 2020-12 gives
/// it a single schema; an array form from an older dialect is handled by the walk anyway.
const SUBSCHEMA: &[&str] = &[
    "items",
    "additionalProperties",
    "additionalItems",
    "unevaluatedItems",
    "unevaluatedProperties",
    "propertyNames",
    "contains",
    "not",
    "if",
    "then",
    "else",
];

/// Keywords whose value is an **array** of subschemas.
const SUBSCHEMA_LIST: &[&str] = &["oneOf", "anyOf", "allOf", "prefixItems"];

/// Keywords whose value is a **map** of name to subschema. The names are the caller's — a field
/// name, a definition name — which is exactly why the walk has to know they are not keywords.
const SUBSCHEMA_MAP: &[&str] = &["properties", "patternProperties", "$defs", "definitions"];

fn strip_in_place(schema: &mut JsonObject) {
    schema.remove("description");

    for key in SUBSCHEMA {
        if let Some(value) = schema.get_mut(*key) {
            strip_value(value);
        }
    }
    for key in SUBSCHEMA_LIST {
        if let Some(Value::Array(items)) = schema.get_mut(*key) {
            for item in items {
                strip_value(item);
            }
        }
    }
    for key in SUBSCHEMA_MAP {
        if let Some(Value::Object(members)) = schema.get_mut(*key) {
            for (_, member) in members.iter_mut() {
                strip_value(member);
            }
        }
    }
}

/// A position that holds a subschema: an object is one, an array is a list of them (the older
/// `items` form), and `true`/`false` are the two schemas that carry nothing to strip.
fn strip_value(value: &mut Value) {
    match value {
        Value::Object(object) => strip_in_place(object),
        Value::Array(items) => items.iter_mut().for_each(strip_value),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn strip(value: serde_json::Value) -> serde_json::Value {
        let object = value.as_object().expect("a schema is an object").clone();
        Value::Object(strip_descriptions(&object))
    }

    #[test]
    fn the_root_description_goes() {
        assert_eq!(
            strip(json!({ "description": "why", "type": "object" })),
            json!({ "type": "object" })
        );
    }

    #[test]
    fn descriptions_go_from_every_schema_position() {
        let stripped = strip(json!({
            "description": "root",
            "type": "object",
            "properties": {
                "one": { "description": "a field", "type": "string" },
                "many": {
                    "type": "array",
                    "items": { "description": "an element", "type": "integer" }
                }
            },
            "oneOf": [
                { "description": "a branch", "const": "ok" },
                { "description": "the other", "const": "error" }
            ],
            "$defs": {
                "Shared": { "description": "a shared type", "type": "string" }
            }
        }));

        assert_eq!(
            stripped,
            json!({
                "type": "object",
                "properties": {
                    "one": { "type": "string" },
                    "many": { "type": "array", "items": { "type": "integer" } }
                },
                "oneOf": [{ "const": "ok" }, { "const": "error" }],
                "$defs": { "Shared": { "type": "string" } }
            })
        );
    }

    /// The failure mode the structural walk exists for: a *field* named `description` is a
    /// property name, not a keyword, and a walk that removed it by name would delete the field.
    #[test]
    fn a_field_called_description_survives() {
        let stripped = strip(json!({
            "description": "the type's own doc, which goes",
            "type": "object",
            "properties": {
                "description": { "description": "the field's doc, which goes", "type": "string" }
            },
            "required": ["description"]
        }));

        assert_eq!(
            stripped,
            json!({
                "type": "object",
                "properties": { "description": { "type": "string" } },
                "required": ["description"]
            })
        );
    }

    /// A `$defs` entry may be named after a keyword too — the map's keys are type names, and
    /// nothing stops a type being called `Items` or, in some other generator, `oneOf`.
    #[test]
    fn a_definition_named_after_a_keyword_survives() {
        let stripped = strip(json!({
            "$defs": {
                "oneOf": { "description": "a type with an awkward name", "type": "string" }
            },
            "$ref": "#/$defs/oneOf"
        }));

        assert_eq!(
            stripped,
            json!({
                "$defs": { "oneOf": { "type": "string" } },
                "$ref": "#/$defs/oneOf"
            })
        );
    }

    /// `additionalProperties: false` is a schema, and a boolean one has nothing to walk into.
    #[test]
    fn a_boolean_schema_is_left_alone() {
        let stripped = strip(json!({
            "type": "object",
            "additionalProperties": false,
            "description": "gone"
        }));

        assert_eq!(
            stripped,
            json!({ "type": "object", "additionalProperties": false })
        );
    }

    /// Nothing but `description` moves: `default`, `const` and `enum` are values a client acts on,
    /// and `format`/`minimum` are constraints. Stripping any of them would change what validates.
    #[test]
    fn every_other_keyword_stays() {
        let schema = json!({
            "type": "integer",
            "format": "uint64",
            "minimum": 0,
            "default": 64,
            "enum": [1, 2, 3]
        });

        assert_eq!(strip(schema.clone()), schema);
    }

    /// The real thing, end to end: a tool's declared schema keeps its shape and loses its prose.
    #[test]
    fn a_real_output_schema_keeps_its_discriminator() {
        let schema =
            constraints_of::<crate::structured::Outcome<crate::structured::SessionEnded>>();
        let rendered = serde_json::to_string(&schema).expect("a schema serializes");

        assert!(
            !rendered.contains("\"description\""),
            "a declared output schema still carries prose: {rendered}"
        );
        assert!(
            rendered.contains("\"status\""),
            "the branch discriminator is what the schema is for: {rendered}"
        );
        assert!(
            rendered.contains("\"stale_session\""),
            "the ErrorCategory vocabulary is a constraint, not prose: {rendered}"
        );
    }

    /// The root keyword that decides whether a strict client keeps *any* of this server's tools.
    ///
    /// `schemars` states the object-ness of an internally-tagged enum on each branch of the
    /// `oneOf` and nowhere at the root, and rmcp's `schema_for_output` passes that through. A
    /// TypeScript-SDK 1.x client parses `tools/list` as an array of tools whose `outputSchema`
    /// must be root-`object`, so one such schema costs the client the whole list (issue #223).
    #[test]
    fn a_declared_output_schema_is_object_rooted() {
        for schema in [
            constraints_of::<crate::structured::Outcome<crate::structured::SessionEnded>>(),
            constraints_of::<crate::structured::OpenOutcome>(),
        ] {
            assert_eq!(
                schema.get("type"),
                Some(&json!("object")),
                "an output schema with no root `type: \"object\"` is dropped by every released \
                 TypeScript-SDK client, and it takes the other fifty tools with it: {schema:?}"
            );
        }
    }

    /// The keyword is supplied, not asserted: the branches already carry it, so what is added at
    /// the root states what the union could only ever have meant.
    #[test]
    fn every_branch_was_already_an_object() {
        let schema = constraints_of::<crate::structured::OpenOutcome>();
        let branches = schema["oneOf"].as_array().expect("an outcome is a union");
        assert!(!branches.is_empty(), "the union has branches: {schema:?}");
        for branch in branches {
            assert_eq!(
                branch["type"], "object",
                "a branch that is not an object would make the root keyword a lie: {branch}"
            );
        }
    }

    /// A root that already declares a type is left as it is. Nothing generates one today, and a
    /// future one is either `object` already or a bug — and this runs on every `router()` build,
    /// so it is the wire assertion in `mcp_smoke` that has to report it, not a panic in a live
    /// server.
    #[test]
    fn a_root_that_declares_a_type_is_left_alone() {
        let declared = json!({ "type": "array", "items": true });
        let object = declared.as_object().expect("a schema is an object").clone();
        assert_eq!(Value::Object(object_rooted(object)), declared);
    }

    /// Two calls hand back the same cached document rather than two walks of the same one.
    ///
    /// **And that has to hold against the other tests in this binary**, which is what it did not.
    /// Three tests here ask for `OpenOutcome` and every test that builds a `router()` asks for it
    /// again, all in parallel; a caller that misses the read lock walks the type outside the lock
    /// and then inserts. With a plain `insert` the second arrival overwrote the first, so this
    /// test's two calls could straddle another test's insert and get two different `Arc`s — seen
    /// once on an x64 CI runner, and green on every other run of the same commit.
    ///
    /// The fix is in `constraints_of` rather than here: a test made serial would have hidden a
    /// cache that really can hand one type two documents.
    #[test]
    fn the_same_type_is_walked_once() {
        let first = constraints_of::<crate::structured::OpenOutcome>();
        let second = constraints_of::<crate::structured::OpenOutcome>();
        assert!(Arc::ptr_eq(&first, &second));
    }
}
