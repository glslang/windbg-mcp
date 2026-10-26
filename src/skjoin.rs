//! Pure M7.2 deterministic join over the three layers' serialized traces.
//!
//! Like `skcorrelate`, this module owns no debugger, session or provider. The coordinator hands
//! it the public trace reads of the VTL0 call trace (M4), the hypervisor transition trace (M5)
//! and the VTL1 service trace (M6), together with the capture identity and the clock admission
//! the transaction established, and it answers with versioned JSON that keeps every original
//! event, every decision, and every reason a decision was not made. The table is rendered from
//! that JSON and is never a second source.
//!
//! What a decision rests on. Each layer orders its own events by its sequence numbers and
//! nothing about arrival order is trusted, which is what makes the join invariant under input
//! permutation. Across layers a point order is used only when the capture's clock admission is
//! `point` and both events carry a sample on the admitted frequency; equal ticks prove nothing
//! and leave both candidates in place. Everything else is an interval argument from the
//! coordinator's arm and drain brackets, which can prove two recording windows disjoint, prove
//! one contained in the other, and nothing finer. A stage with one surviving candidate is matched
//! and names the rule that selected it; zero is unmatched and more than one is ambiguous, with
//! the candidates retained as sequence ranges. The nearest candidate is never chosen.
//!
//! The chain's first stage. M4 and M6 cannot share a VP in one window with what exists
//! (`docs/secure-kernel/skcall-debugging-roadmap.md`, M7.1a), so a capture may arrive without
//! M4. Its chains then start from M6's entry phase, and every such chain is at most
//! `provisional`: the VTL0 fields M4 measures are either VTL1-observed copies whose equality to
//! the NT values has not been shown on one call, coordinator-envelope values, or unavailable.
//! [`first_stage_fields`] is that table, field by field, and travels in the output. When both
//! layers are present and a chain's M4 entry is matched, the join compares the fields the two
//! layers both carry and reports each comparison, which is the measurement that table is
//! waiting for.

use std::collections::BTreeSet;
use std::io::Write as _;

use anyhow::{Context as _, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::skcorrelate::{
    CaptureIdentity, ClockAdmission, ClockMode, Layer, RestorationAudit, RpcClockBracket,
};
use crate::structured::HostQpcSample;

pub(crate) const JOIN_FLAG: &str = "--m7-join";
pub(crate) const JOIN_TABLE_FLAG: &str = "--m7-join-table";
pub(crate) const JOIN_INPUT_SCHEMA: &str = "windbg-mcp.sk-correlation-join-input.v1";
pub(crate) const JOIN_SCHEMA: &str = "windbg-mcp.sk-correlation-join.v1";

/// The value of CL at `nt!VslpEnterIumSecureMode` for a secure-service call on the measured
/// build, and the value of the request's `dispatch_mode` byte at `IumInvokeSecureService`.
/// Measured on K3 (10.0.26100.9457): 255 of the 256 entries in the M4 record of 2026-10-21
/// carried 2, the one exception being the `nt!VslCallEnclave` entry with kind 1 and service 0,
/// and every one of the 100 service-47 requests in the M6 record of 2026-10-23 carried 2 at
/// offset 0. It is an input default rather than a constant so a different build can state its
/// own and have the record say so.
pub(crate) const DEFAULT_SECURE_CALL_KIND: u8 = 2;

/// Rows a rendered table shows before eliding the rest. The JSON is the record; the table is a
/// bounded view of it.
pub(crate) const TABLE_ROWS: usize = 64;

fn default_secure_call_kind() -> u8 {
    DEFAULT_SECURE_CALL_KIND
}

/// One layer's contribution: the public trace read exactly as the worker answered it, and the
/// coordinator's own brackets around its arm and drain, which bound when it was recording.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayerSource {
    pub(crate) trace: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) arm: Option<RpcClockBracket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) drain: Option<RpcClockBracket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) restoration: Option<RestorationAudit>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JoinLayers {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) m4_vtl0: Option<LayerSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) m5_hypervisor: Option<LayerSource>,
    pub(crate) m6_vtl1: LayerSource,
}

/// Everything the join consumes. The coordinator assembles it from the transaction report: the
/// validated preflight identity, the clock admission, each layer's drained trace with its arm and
/// drain brackets, and the two values only the coordinator knows: how many selected calls the
/// workload was asked for, and the workload process it launched.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JoinInput {
    pub(crate) schema: String,
    pub(crate) identity: CaptureIdentity,
    pub(crate) clock: ClockAdmission,
    pub(crate) selected_service: u16,
    #[serde(default = "default_secure_call_kind")]
    pub(crate) secure_call_kind: u8,
    /// The manifest's selected calls per positive ordinal times the ordinals the workload ran.
    /// Coordinator-observed; a chain count that differs is a reason, never a correction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expected_selected_calls: Option<u64>,
    /// The guest process the coordinator launched the workload in. A coordinator-envelope value:
    /// it stands in for M4's `process_id` only as the envelope says, never as a measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) workload_process_id: Option<u32>,
    pub(crate) layers: JoinLayers,
}

// ---- lenient views of the three public trace shapes -------------------------------------

#[derive(Deserialize)]
struct ProvenanceView {
    #[serde(default)]
    read_failures: Vec<String>,
}

#[derive(Deserialize)]
struct M4Trace {
    trace_id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    calls: Vec<M4Call>,
    #[serde(default)]
    dropped: u64,
    #[serde(default)]
    full: bool,
    #[serde(default)]
    unreadable_hits: u64,
    #[serde(default)]
    missing_breakpoint: bool,
    #[serde(default)]
    armed: bool,
}

#[derive(Deserialize)]
struct M4Call {
    sequence: u64,
    #[serde(default)]
    host_qpc: Option<HostQpcSample>,
    #[serde(default)]
    host_monotonic_us: u64,
    #[serde(default)]
    transition_kind: Option<u8>,
    #[serde(default)]
    service: Option<u16>,
    #[serde(default)]
    argument_block: Option<String>,
    #[serde(default)]
    caller_symbol: Option<String>,
    #[serde(default)]
    process_id: Option<u32>,
    #[serde(default)]
    thread: Option<String>,
    #[serde(default)]
    provenance: Option<ProvenanceView>,
}

#[derive(Deserialize)]
struct M5Trace {
    trace_id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    transitions: Vec<M5Transition>,
    #[serde(default)]
    dropped: u64,
    #[serde(default)]
    full: bool,
    #[serde(default)]
    unreadable_hits: u64,
    #[serde(default)]
    missing_breakpoints: u64,
    #[serde(default)]
    armed: bool,
}

#[derive(Deserialize)]
struct M5Transition {
    sequence: u64,
    #[serde(default)]
    host_qpc: Option<HostQpcSample>,
    #[serde(default)]
    host_monotonic_us: u64,
    kind: String,
    #[serde(default)]
    vp_index: Option<u8>,
    #[serde(default)]
    source_vtl: Option<u8>,
    #[serde(default)]
    target_vtl: Option<u8>,
    #[serde(default)]
    provenance: Option<ProvenanceView>,
}

#[derive(Deserialize)]
struct M6Trace {
    trace_id: String,
    #[serde(default)]
    label: Option<String>,
    selected_service: u16,
    #[serde(default)]
    records: Vec<M6Record>,
    #[serde(default)]
    dropped_records: u64,
    #[serde(default)]
    dropped_capture_bytes: u64,
    #[serde(default)]
    unreadable_fields: u64,
    #[serde(default)]
    full: bool,
    #[serde(default)]
    armed: bool,
    #[serde(default)]
    pending_phase: Option<String>,
}

#[derive(Deserialize)]
struct M6Record {
    sequence: u64,
    #[serde(default)]
    complete: bool,
    #[serde(default)]
    incomplete_reason: Option<String>,
    #[serde(default)]
    entry: Option<M6Entry>,
    #[serde(default)]
    dispatch: Option<M6Dispatch>,
    #[serde(default)]
    returned: Option<M6Return>,
}

#[derive(Deserialize)]
struct M6Site {
    #[serde(default)]
    epoch: String,
    #[serde(default)]
    host_qpc: Option<HostQpcSample>,
    #[serde(default)]
    host_monotonic_us: u64,
}

#[derive(Deserialize)]
struct M6Provenance {
    #[serde(default)]
    unavailable: Vec<Value>,
}

#[derive(Deserialize)]
struct M6Entry {
    site: M6Site,
    service: u16,
    #[serde(default)]
    provenance: Option<M6Provenance>,
}

#[derive(Deserialize)]
struct M6Field {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct M6Buffer {
    name: String,
    #[serde(default)]
    bytes: Value,
}

#[derive(Deserialize)]
struct M6Dispatch {
    site: M6Site,
    #[serde(default)]
    fields: Vec<M6Field>,
    #[serde(default)]
    buffers_before: Vec<M6Buffer>,
    #[serde(default)]
    provenance: Option<M6Provenance>,
}

#[derive(Deserialize)]
struct M6Return {
    site: M6Site,
    #[serde(default)]
    status: Option<u32>,
    #[serde(default)]
    provenance: Option<M6Provenance>,
}

// ---- normalized events, by identity ------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    M4Entry,
    M5VtlCall,
    M6Entry,
    M6Dispatch,
    M6Return,
    M5VtlReturn,
}

impl Stage {
    fn layer(self) -> Layer {
        match self {
            Self::M4Entry => Layer::M4Vtl0,
            Self::M5VtlCall | Self::M5VtlReturn => Layer::M5Hypervisor,
            Self::M6Entry | Self::M6Dispatch | Self::M6Return => Layer::M6Vtl1,
        }
    }
}

/// The identity of one original event: the layer, its own sequence number and the stage it
/// stands for. An M6 record contributes three stages under one sequence number.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventId {
    pub(crate) layer: Layer,
    pub(crate) sequence: u64,
    pub(crate) stage: Stage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct M4Event {
    pub(crate) sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) host_qpc: Option<HostQpcSample>,
    pub(crate) host_monotonic_us: u64,
    pub(crate) transition_kind: Option<u8>,
    pub(crate) service: Option<u16>,
    /// A fully classified secure-service entry of the selected service.
    pub(crate) selected: bool,
    /// Whether unreadable classification fields leave this hit able to be the selected service.
    #[serde(skip)]
    candidate: bool,
    pub(crate) process_id: Option<u32>,
    pub(crate) thread: Option<String>,
    pub(crate) caller_symbol: Option<String>,
    pub(crate) read_failures: u64,
    #[serde(skip)]
    argument_block: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransitionKind {
    VtlCall,
    VtlReturn,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct M5Event {
    pub(crate) sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) host_qpc: Option<HostQpcSample>,
    pub(crate) host_monotonic_us: u64,
    pub(crate) kind: TransitionKind,
    pub(crate) vp_index: Option<u8>,
    pub(crate) source_vtl: Option<u8>,
    pub(crate) target_vtl: Option<u8>,
    pub(crate) read_failures: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhaseStamp {
    pub(crate) epoch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) host_qpc: Option<HostQpcSample>,
    pub(crate) host_monotonic_us: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct M6Event {
    pub(crate) sequence: u64,
    pub(crate) complete: bool,
    pub(crate) incomplete_reason: Option<String>,
    pub(crate) service: Option<u16>,
    pub(crate) entry: Option<PhaseStamp>,
    pub(crate) dispatch: Option<PhaseStamp>,
    pub(crate) returned: Option<PhaseStamp>,
    pub(crate) status: Option<u32>,
    pub(crate) read_failures: u64,
    #[serde(skip)]
    dispatch_mode: Option<u64>,
    #[serde(skip)]
    request_service: Option<u64>,
    #[serde(skip)]
    request_before: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct Events {
    pub(crate) m4_vtl0: Vec<M4Event>,
    pub(crate) m5_hypervisor: Vec<M5Event>,
    pub(crate) m6_vtl1: Vec<M6Event>,
}

// ---- decisions ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SequenceRange {
    pub(crate) first: u64,
    pub(crate) last: u64,
}

/// Candidates retained for an ambiguous stage, as the sequence numbers of that layer's events
/// compressed into contiguous ranges. Lossless, and bounded by the layer rather than by prose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Candidates {
    pub(crate) layer: Layer,
    pub(crate) stage: Stage,
    pub(crate) count: u64,
    pub(crate) sequence_ranges: Vec<SequenceRange>,
}

impl Candidates {
    fn new(stage: Stage, sequences: impl IntoIterator<Item = u64>) -> Self {
        let sorted: BTreeSet<u64> = sequences.into_iter().collect();
        let mut ranges: Vec<SequenceRange> = Vec::new();
        for sequence in &sorted {
            match ranges.last_mut() {
                Some(range) if range.last + 1 == *sequence => range.last = *sequence,
                _ => ranges.push(SequenceRange {
                    first: *sequence,
                    last: *sequence,
                }),
            }
        }
        Self {
            layer: stage.layer(),
            stage,
            count: sorted.len() as u64,
            sequence_ranges: ranges,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub(crate) enum Decision {
    Matched {
        event: EventId,
        rule: String,
    },
    Ambiguous {
        candidates: Candidates,
        reason: String,
    },
    Unmatched {
        reason: String,
    },
    /// The layer was not part of the capture, so the stage was never observed.
    Unobserved {
        reason: String,
    },
}

impl Decision {
    fn matched(&self) -> Option<&EventId> {
        match self {
            Self::Matched { event, .. } => Some(event),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Stages {
    pub(crate) m4_entry: Decision,
    pub(crate) m5_vtl_call: Decision,
    pub(crate) m6_entry: Decision,
    pub(crate) m6_dispatch: Decision,
    pub(crate) m6_return: Decision,
    pub(crate) m5_vtl_return: Decision,
}

impl Stages {
    fn each(&self) -> [(Stage, &Decision); 6] {
        [
            (Stage::M4Entry, &self.m4_entry),
            (Stage::M5VtlCall, &self.m5_vtl_call),
            (Stage::M6Entry, &self.m6_entry),
            (Stage::M6Dispatch, &self.m6_dispatch),
            (Stage::M6Return, &self.m6_return),
            (Stage::M5VtlReturn, &self.m5_vtl_return),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub(crate) enum CrossCheckResult {
    Equal { value: String },
    Differs { m4: String, m6: String },
    NotComparable { reason: String },
}

/// One field both layers carry for a matched chain, compared. These are the measurements the
/// first-stage table is waiting for; they are reported, never folded into a verdict of equality
/// for the field in general.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CrossCheck {
    pub(crate) field: String,
    pub(crate) result: CrossCheckResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChainVerdict {
    /// All six stages matched from an M4 entry, and every cross-check agreed.
    Complete,
    /// All stages the capture could observe matched, but the first stage is M6's entry phase
    /// standing in for an M4 entry the capture did not record.
    Provisional,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Chain {
    /// Assigned only when the six-stage order was observed (`complete`) or observed from M6's
    /// entry (`provisional`).
    pub(crate) call_id: Option<String>,
    pub(crate) m6_sequence: u64,
    pub(crate) service: Option<u16>,
    pub(crate) status: Option<u32>,
    pub(crate) stages: Stages,
    /// Round trips the hypervisor closed between the one that delivered the VTL1 entry and the one
    /// that carried the VTL1 return back: zero when both lie in one round trip, otherwise the
    /// number of times the VP left VTL1 inside the service, for the Secure Kernel's normal-mode
    /// calls and for any secure call VTL0 made during them, as the hypervisor saw them.
    pub(crate) nested_round_trips: Option<u64>,
    /// Complete M5 round trips between the matched M4 entry and the round trip that delivered the
    /// VTL1 entry. Zero is the expected reading; anything else is a finding to look at.
    pub(crate) round_trips_before_entry: Option<u64>,
    pub(crate) cross_checks: Vec<CrossCheck>,
    pub(crate) verdict: ChainVerdict,
    pub(crate) reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FirstStageSource {
    M4Vtl0Entry,
    M6EntryCopy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FieldStatus {
    /// M4 measured it in VTL0.
    Measured,
    /// M6 carries a VTL1-observed copy whose equality to the VTL0 value has not been shown on
    /// one call.
    Copied,
    /// M6 carries a value of the same role in a different address space; never equal.
    Replaced,
    /// Supplied by the coordinator's envelope, never by a target.
    CoordinatorEnvelope,
    /// Nothing in VTL1 or the envelope stands in for it.
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FieldProvenance {
    pub(crate) field: String,
    pub(crate) m4_source: String,
    pub(crate) m6_source: Option<String>,
    pub(crate) status: FieldStatus,
    pub(crate) note: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FirstStage {
    pub(crate) source: FirstStageSource,
    pub(crate) fields: Vec<FieldProvenance>,
}

/// The M4 fields read at `nt!VslpEnterIumSecureMode`, against what M6's entry and dispatch
/// phases carry for the same call. The layout rows rest on two K3 records of service 47 taken
/// two days apart (M4 `target/codex-m4/live-qualification/20261021T202417`, M6
/// `target/codex-m6/live-qualification/20261023T223744`): from offset 8 the VTL0 block and the
/// VTL1 request agree in shape, and the request's first four bytes hold what M4 reads from CL
/// and DX. That is a layout correspondence across runs, not an identity on one call, which is why
/// the rows say `copied` and the per-chain cross-checks exist.
pub(crate) fn first_stage_fields(
    source: FirstStageSource,
    workload_process_id: Option<u32>,
) -> Vec<FieldProvenance> {
    let measured = source == FirstStageSource::M4Vtl0Entry;
    let status = |copy: FieldStatus| {
        if measured {
            FieldStatus::Measured
        } else {
            copy
        }
    };
    let row =
        |field: &str, m4: &str, m6: Option<&str>, copy: FieldStatus, note: &str| FieldProvenance {
            field: field.into(),
            m4_source: m4.into(),
            m6_source: m6.map(str::to_string),
            status: status(copy),
            note: note.into(),
        };
    vec![
        row(
            "transition_kind",
            "CL at entry",
            Some("dispatch.fields.dispatch_mode (request+0, 1 byte)"),
            FieldStatus::Copied,
            "the request header's first byte read 2 in every measured service-47 request, as CL did at every secure-service entry; same-call equality is a cross-check, not a given",
        ),
        row(
            "service",
            "DX at entry",
            Some("entry.service and dispatch.fields.service_number (request+2, 2 bytes)"),
            FieldStatus::Copied,
            "the number space is one; same-call equality is a cross-check",
        ),
        row(
            "call_context",
            "R8D at entry",
            None,
            FieldStatus::Unavailable,
            "read as 0 in all 256 entries of the 2026-10-21 record; no VTL1 field carries it",
        ),
        row(
            "argument_block",
            "0x68 bytes at R9",
            Some("dispatch.buffers_before[request.before] bytes 8..64 at rcx"),
            FieldStatus::Copied,
            "bytes 8..64 agree in layout across the two records (image address, allocation, 0x10000000, two kernel pointers, a count); bytes 0..8 differ by construction and 64..104 are not captured by M6; same-call byte equality is a cross-check",
        ),
        row(
            "argument_block_pointer",
            "R9 at entry",
            Some("entry.raw_arguments.rcx"),
            FieldStatus::Replaced,
            "a VTL1 virtual address of the request, not the VTL0 block's address",
        ),
        row(
            "caller",
            "return address on the VTL0 stack, with its nt symbol",
            None,
            FieldStatus::Unavailable,
            "VTL1 sees no VTL0 stack; the manifest's caller_symbol is an exact-build expectation, not a reading",
        ),
        FieldProvenance {
            field: "process_id".into(),
            m4_source: "_ETHREAD.Cid.UniqueProcess of the entering thread".into(),
            m6_source: None,
            status: if measured {
                FieldStatus::Measured
            } else if workload_process_id.is_some() {
                FieldStatus::CoordinatorEnvelope
            } else {
                FieldStatus::Unavailable
            },
            note: "no VTL1 object names the VTL0 caller of a secure service; the coordinator's workload process id is an envelope value for the workload's own calls".into(),
        },
        row(
            "thread",
            "KTHREAD of the entering thread",
            None,
            FieldStatus::Unavailable,
            "no VTL1 object names the VTL0 thread of a secure service call",
        ),
        row(
            "processor",
            "KPRCB number",
            Some("target.vp"),
            FieldStatus::Copied,
            "one runnable processor is an admission condition of the capture",
        ),
        row(
            "target_rip",
            "VTL0 RIP at entry",
            Some("entry.site.coordinate (VTL1)"),
            FieldStatus::Replaced,
            "a VTL1 coordinate; the VTL0 one is the entry M4 guards",
        ),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MarkKind {
    DroppedRecords,
    MissingBreakpoints,
    CapacityReached,
    StillArmed,
    PendingPhase,
    UnreadableFields,
    SequenceGap,
    DuplicateSequence,
    IncompleteRecord,
    ForeignService,
    UnmatchedReturn,
    UnmatchedCall,
    UnexpectedTransition,
    SeveralVps,
    OrderContradiction,
    CountMismatch,
    WindowInvalid,
}

/// Something that stops a verdict being `complete` across the interval it names. A drop or a cap
/// marks the layer's tail; a gap, an incomplete record or an unmatched transition marks the place
/// it was seen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mark {
    pub(crate) layer: Option<Layer>,
    pub(crate) kind: MarkKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) after_sequence: Option<u64>,
    pub(crate) detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Unmatched {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) m6_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stage: Option<Stage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) event: Option<EventId>,
    pub(crate) reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ambiguity {
    pub(crate) m6_sequence: u64,
    pub(crate) stage: Stage,
    pub(crate) candidates: Candidates,
    pub(crate) reason: String,
}

/// When a layer was recording, in coordinator ticks. `certain` is the span it was recording
/// throughout (after its arm returned, before its drain was asked); `outer` is the span outside
/// which it cannot have recorded (before its arm was asked, after its drain returned).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Window {
    pub(crate) frequency: u64,
    pub(crate) outer_from: u64,
    pub(crate) certain_from: u64,
    pub(crate) certain_to: u64,
    pub(crate) outer_to: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WindowRelation {
    /// No instant lies in both outer spans.
    Disjoint,
    /// The first was certainly recording throughout the second's outer span.
    Contains,
    ContainedBy,
    Overlap,
    Unknown,
}

impl Window {
    fn from_brackets(arm: &RpcClockBracket, drain: &RpcClockBracket) -> Result<Self, String> {
        let frequency = arm.coordinator_before.frequency;
        if [
            arm.coordinator_after.frequency,
            drain.coordinator_before.frequency,
            drain.coordinator_after.frequency,
        ]
        .iter()
        .any(|other| *other != frequency)
            || frequency == 0
        {
            return Err("arm and drain brackets do not share one nonzero frequency".into());
        }
        if arm.coordinator_before.tick > arm.coordinator_after.tick
            || drain.coordinator_before.tick > drain.coordinator_after.tick
            || arm.coordinator_after.tick > drain.coordinator_after.tick
        {
            return Err("arm and drain brackets are not in order".into());
        }
        Ok(Self {
            frequency,
            outer_from: arm.coordinator_before.tick,
            certain_from: arm.coordinator_after.tick,
            certain_to: drain.coordinator_before.tick,
            outer_to: drain.coordinator_after.tick,
        })
    }

    fn relation(&self, other: &Self) -> WindowRelation {
        if self.frequency != other.frequency {
            return WindowRelation::Unknown;
        }
        if self.outer_to < other.outer_from || other.outer_to < self.outer_from {
            return WindowRelation::Disjoint;
        }
        let certain = |window: &Self| window.certain_from <= window.certain_to;
        if certain(self)
            && self.certain_from <= other.outer_from
            && other.outer_to <= self.certain_to
        {
            return WindowRelation::Contains;
        }
        if certain(other)
            && other.certain_from <= self.outer_from
            && self.outer_to <= other.certain_to
        {
            return WindowRelation::ContainedBy;
        }
        WindowRelation::Overlap
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayerSummary {
    pub(crate) trace_id: String,
    pub(crate) label: Option<String>,
    pub(crate) events: u64,
    pub(crate) first_sequence: Option<u64>,
    pub(crate) last_sequence: Option<u64>,
    pub(crate) contiguous: bool,
    pub(crate) dropped: u64,
    pub(crate) full: bool,
    pub(crate) unreadable: u64,
    #[serde(default)]
    pub(crate) missing_breakpoints: u64,
    pub(crate) armed_at_read: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) window: Option<Window>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) restoration: Option<RestorationAudit>,
    /// SHA-256 of the layer's trace as given, so a decision can be traced to the bytes it read.
    pub(crate) source_sha256: String,
}

impl LayerSummary {
    /// Whether rank pairing may treat this layer's events as the complete run of what happened
    /// while it recorded.
    fn complete_run(&self) -> bool {
        self.contiguous
            && self.dropped == 0
            && self.missing_breakpoints == 0
            && !self.full
            && !self.armed_at_read
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayerSummaries {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) m4_vtl0: Option<LayerSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) m5_hypervisor: Option<LayerSummary>,
    pub(crate) m6_vtl1: Option<LayerSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowPair {
    pub(crate) first: Layer,
    pub(crate) second: Layer,
    pub(crate) relation: WindowRelation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoundTrip {
    pub(crate) call_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) return_sequence: Option<u64>,
    #[serde(skip)]
    call_tick: Option<u64>,
    #[serde(skip)]
    return_tick: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClockSummary {
    pub(crate) mode: ClockMode,
    pub(crate) frequency: Option<u64>,
    pub(crate) resolution_ns: Option<u64>,
    pub(crate) reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CrossCheckSummary {
    pub(crate) field: String,
    pub(crate) equal: u64,
    pub(crate) differs: u64,
    pub(crate) not_comparable: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JoinVerdict {
    Complete,
    Provisional,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Sources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) m4_vtl0: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) m5_hypervisor: Option<Value>,
    pub(crate) m6_vtl1: Value,
}

/// The versioned result. `sources` are the three traces exactly as given; `events` are the same
/// events normalized and ordered by sequence; everything after them is a decision about those
/// events by identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JoinedCapture {
    pub(crate) schema: String,
    pub(crate) identity: CaptureIdentity,
    pub(crate) clock: ClockSummary,
    pub(crate) selected_service: u16,
    pub(crate) secure_call_kind: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expected_selected_calls: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) workload_process_id: Option<u32>,
    pub(crate) first_stage: FirstStage,
    pub(crate) layers: LayerSummaries,
    pub(crate) windows: Vec<WindowPair>,
    pub(crate) events: Events,
    pub(crate) round_trips: Vec<RoundTrip>,
    pub(crate) chains: Vec<Chain>,
    pub(crate) unmatched: Vec<Unmatched>,
    pub(crate) ambiguous: Vec<Ambiguity>,
    pub(crate) marks: Vec<Mark>,
    pub(crate) cross_check_summary: Vec<CrossCheckSummary>,
    pub(crate) verdict: JoinVerdict,
    pub(crate) reasons: Vec<String>,
    pub(crate) sources: Sources,
}

impl JoinedCapture {
    /// The decisions alone: what two joins of the same evidence in different arrival orders must
    /// agree on. `sources` are deliberately left out, being the inputs as given.
    #[cfg(test)]
    fn decisions(&self) -> Decisions<'_> {
        (
            &self.chains,
            &self.unmatched,
            &self.ambiguous,
            &self.marks,
            &self.round_trips,
            self.verdict,
            &self.reasons,
        )
    }
}

#[cfg(test)]
type Decisions<'a> = (
    &'a Vec<Chain>,
    &'a Vec<Unmatched>,
    &'a Vec<Ambiguity>,
    &'a Vec<Mark>,
    &'a Vec<RoundTrip>,
    JoinVerdict,
    &'a Vec<String>,
);

// ---- the join ----------------------------------------------------------------------------

struct Clock {
    point: bool,
    frequency: Option<u64>,
}

impl Clock {
    /// A tick comparable across layers, or nothing: outside point mode no sample is, and inside it
    /// only a sample on the admitted frequency is.
    fn tick(&self, sample: Option<HostQpcSample>) -> Option<u64> {
        if !self.point {
            return None;
        }
        sample
            .filter(|sample| Some(sample.frequency) == self.frequency)
            .map(|sample| sample.tick)
    }
}

fn parse_hex(text: &str) -> Option<u64> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    u64::from_str_radix(digits, 16).ok()
}

fn sha256_hex(value: &Value) -> String {
    // `serde_json` without `preserve_order` keeps object keys in a `BTreeMap`, so this encoding
    // is canonical in key order and the digest names the content rather than one spelling of it.
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    crate::client::sha256(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_layer<T: serde::de::DeserializeOwned>(layer: Layer, value: &Value) -> anyhow::Result<T> {
    serde_json::from_value(value.clone())
        .with_context(|| format!("{} trace is not a readable trace read", layer.wire_name()))
}

/// Check a layer's sequence numbers are one contiguous run without repeats, marking what is not.
fn check_sequences(layer: Layer, sequences: &[u64], marks: &mut Vec<Mark>) -> bool {
    let mut contiguous = true;
    for pair in sequences.windows(2) {
        if pair[1] == pair[0] {
            contiguous = false;
            marks.push(Mark {
                layer: Some(layer),
                kind: MarkKind::DuplicateSequence,
                sequence: Some(pair[0]),
                after_sequence: None,
                detail: format!("sequence {} appears more than once", pair[0]),
            });
        } else if pair[1] != pair[0] + 1 {
            contiguous = false;
            marks.push(Mark {
                layer: Some(layer),
                kind: MarkKind::SequenceGap,
                sequence: None,
                after_sequence: Some(pair[0]),
                detail: format!(
                    "sequences {} through {} are missing",
                    pair[0] + 1,
                    pair[1] - 1
                ),
            });
        }
    }
    contiguous
}

struct Counters {
    dropped: u64,
    missing_breakpoints: u64,
    full: bool,
    unreadable: u64,
    armed: bool,
    pending_phase: Option<String>,
}

fn summarize(
    layer: Layer,
    trace_id: String,
    label: Option<String>,
    sequences: &[u64],
    counters: Counters,
    source: &LayerSource,
    marks: &mut Vec<Mark>,
) -> LayerSummary {
    let contiguous = check_sequences(layer, sequences, marks);
    let last = sequences.last().copied();
    if counters.dropped > 0 {
        marks.push(Mark {
            layer: Some(layer),
            kind: MarkKind::DroppedRecords,
            sequence: None,
            after_sequence: last,
            detail: format!(
                "{} events were dropped after the retained ones",
                counters.dropped
            ),
        });
    }
    if counters.missing_breakpoints > 0 {
        marks.push(Mark {
            layer: Some(layer),
            kind: MarkKind::MissingBreakpoints,
            sequence: None,
            after_sequence: last,
            detail: format!(
                "{} trace breakpoint{} {} no longer held when read",
                counters.missing_breakpoints,
                if counters.missing_breakpoints == 1 {
                    ""
                } else {
                    "s"
                },
                if counters.missing_breakpoints == 1 {
                    "was"
                } else {
                    "were"
                },
            ),
        });
    }
    if counters.full {
        marks.push(Mark {
            layer: Some(layer),
            kind: MarkKind::CapacityReached,
            sequence: None,
            after_sequence: last,
            detail: "the trace reached its capacity; later events were not retained".into(),
        });
    }
    if counters.armed {
        marks.push(Mark {
            layer: Some(layer),
            kind: MarkKind::StillArmed,
            sequence: None,
            after_sequence: last,
            detail: "the trace was still armed when read, so the read is a prefix".into(),
        });
    }
    if let Some(phase) = &counters.pending_phase {
        marks.push(Mark {
            layer: Some(layer),
            kind: MarkKind::PendingPhase,
            sequence: None,
            after_sequence: last,
            detail: format!("a call was in flight at the read, last observed at its {phase} phase"),
        });
    }
    if counters.unreadable > 0 {
        marks.push(Mark {
            layer: Some(layer),
            kind: MarkKind::UnreadableFields,
            sequence: None,
            after_sequence: None,
            detail: format!("{} typed reads did not answer", counters.unreadable),
        });
    }
    let window = match (&source.arm, &source.drain) {
        (Some(arm), Some(drain)) => match Window::from_brackets(arm, drain) {
            Ok(window) => Some(window),
            Err(message) => {
                marks.push(Mark {
                    layer: Some(layer),
                    kind: MarkKind::WindowInvalid,
                    sequence: None,
                    after_sequence: None,
                    detail: message,
                });
                None
            }
        },
        _ => None,
    };
    LayerSummary {
        trace_id,
        label,
        events: sequences.len() as u64,
        first_sequence: sequences.first().copied(),
        last_sequence: last,
        contiguous,
        dropped: counters.dropped,
        full: counters.full,
        unreadable: counters.unreadable,
        missing_breakpoints: counters.missing_breakpoints,
        armed_at_read: counters.armed,
        window,
        restoration: source.restoration.clone(),
        source_sha256: sha256_hex(&source.trace),
    }
}

fn normalize_m4(
    trace: M4Trace,
    selected_service: u16,
    secure_call_kind: u8,
    source: &LayerSource,
    marks: &mut Vec<Mark>,
) -> (LayerSummary, Vec<M4Event>) {
    let mut events: Vec<M4Event> = trace
        .calls
        .into_iter()
        .map(|call| M4Event {
            sequence: call.sequence,
            host_qpc: call.host_qpc,
            host_monotonic_us: call.host_monotonic_us,
            transition_kind: call.transition_kind,
            service: call.service,
            selected: call.transition_kind == Some(secure_call_kind)
                && call.service == Some(selected_service),
            candidate: call
                .transition_kind
                .is_none_or(|kind| kind == secure_call_kind)
                && call
                    .service
                    .is_none_or(|service| service == selected_service),
            process_id: call.process_id,
            thread: call.thread,
            caller_symbol: call.caller_symbol,
            read_failures: call
                .provenance
                .map_or(0, |provenance| provenance.read_failures.len() as u64),
            argument_block: call.argument_block,
        })
        .collect();
    events.sort_by_key(|event| event.sequence);
    let sequences: Vec<u64> = events.iter().map(|event| event.sequence).collect();
    let summary = summarize(
        Layer::M4Vtl0,
        trace.trace_id,
        trace.label,
        &sequences,
        Counters {
            dropped: trace.dropped,
            missing_breakpoints: u64::from(trace.missing_breakpoint),
            full: trace.full,
            unreadable: trace.unreadable_hits,
            armed: trace.armed,
            pending_phase: None,
        },
        source,
        marks,
    );
    (summary, events)
}

fn normalize_m5(
    trace: M5Trace,
    source: &LayerSource,
    marks: &mut Vec<Mark>,
) -> (LayerSummary, Vec<M5Event>) {
    let mut events: Vec<M5Event> = trace
        .transitions
        .into_iter()
        .map(|transition| M5Event {
            sequence: transition.sequence,
            host_qpc: transition.host_qpc,
            host_monotonic_us: transition.host_monotonic_us,
            kind: match transition.kind.as_str() {
                "vtl_call" => TransitionKind::VtlCall,
                "vtl_return" => TransitionKind::VtlReturn,
                _ => TransitionKind::Other,
            },
            vp_index: transition.vp_index,
            source_vtl: transition.source_vtl,
            target_vtl: transition.target_vtl,
            read_failures: transition
                .provenance
                .map_or(0, |provenance| provenance.read_failures.len() as u64),
        })
        .collect();
    events.sort_by_key(|event| event.sequence);
    let sequences: Vec<u64> = events.iter().map(|event| event.sequence).collect();
    let summary = summarize(
        Layer::M5Hypervisor,
        trace.trace_id,
        trace.label,
        &sequences,
        Counters {
            dropped: trace.dropped,
            missing_breakpoints: trace.missing_breakpoints,
            full: trace.full,
            unreadable: trace.unreadable_hits,
            armed: trace.armed,
            pending_phase: None,
        },
        source,
        marks,
    );
    (summary, events)
}

fn stamp(site: &M6Site) -> PhaseStamp {
    PhaseStamp {
        epoch: site.epoch.clone(),
        host_qpc: site.host_qpc,
        host_monotonic_us: site.host_monotonic_us,
    }
}

fn normalize_m6(
    trace: M6Trace,
    selected_service: u16,
    source: &LayerSource,
    marks: &mut Vec<Mark>,
) -> (LayerSummary, Vec<M6Event>) {
    let mut events: Vec<M6Event> = trace
        .records
        .into_iter()
        .map(|record| {
            let read_failures = record
                .entry
                .as_ref()
                .and_then(|phase| phase.provenance.as_ref())
                .map_or(0, |provenance| provenance.unavailable.len() as u64)
                + record
                    .dispatch
                    .as_ref()
                    .and_then(|phase| phase.provenance.as_ref())
                    .map_or(0, |provenance| provenance.unavailable.len() as u64)
                + record
                    .returned
                    .as_ref()
                    .and_then(|phase| phase.provenance.as_ref())
                    .map_or(0, |provenance| provenance.unavailable.len() as u64);
            let field = |name: &str| {
                record.dispatch.as_ref().and_then(|dispatch| {
                    dispatch
                        .fields
                        .iter()
                        .find(|field| field.name == name)
                        .and_then(|field| parse_hex(&field.value))
                })
            };
            let request_before = record.dispatch.as_ref().and_then(|dispatch| {
                dispatch
                    .buffers_before
                    .iter()
                    .find(|buffer| buffer.name == "request.before")
                    .and_then(|buffer| {
                        (buffer.bytes.get("state")? == "measured")
                            .then(|| buffer.bytes.get("data")?.as_str().map(str::to_string))
                            .flatten()
                    })
            });
            M6Event {
                sequence: record.sequence,
                complete: record.complete,
                incomplete_reason: record.incomplete_reason,
                service: record.entry.as_ref().map(|entry| entry.service),
                entry: record.entry.as_ref().map(|entry| stamp(&entry.site)),
                dispatch: record
                    .dispatch
                    .as_ref()
                    .map(|dispatch| stamp(&dispatch.site)),
                returned: record
                    .returned
                    .as_ref()
                    .map(|returned| stamp(&returned.site)),
                status: record
                    .returned
                    .as_ref()
                    .and_then(|returned| returned.status),
                read_failures,
                dispatch_mode: field("dispatch_mode"),
                request_service: field("service_number"),
                request_before,
            }
        })
        .collect();
    events.sort_by_key(|event| event.sequence);
    let sequences: Vec<u64> = events.iter().map(|event| event.sequence).collect();
    let summary = summarize(
        Layer::M6Vtl1,
        trace.trace_id,
        trace.label,
        &sequences,
        Counters {
            dropped: trace.dropped_records,
            missing_breakpoints: 0,
            full: trace.full,
            unreadable: trace.unreadable_fields,
            armed: trace.armed,
            pending_phase: trace.pending_phase,
        },
        source,
        marks,
    );
    if trace.dropped_capture_bytes > 0 {
        marks.push(Mark {
            layer: Some(Layer::M6Vtl1),
            kind: MarkKind::DroppedRecords,
            sequence: None,
            after_sequence: summary.last_sequence,
            detail: format!(
                "{} captured bytes were dropped",
                trace.dropped_capture_bytes
            ),
        });
    }
    for event in &events {
        if !event.complete {
            marks.push(Mark {
                layer: Some(Layer::M6Vtl1),
                kind: MarkKind::IncompleteRecord,
                sequence: Some(event.sequence),
                after_sequence: None,
                detail: format!(
                    "record {} is incomplete ({})",
                    event.sequence,
                    event.incomplete_reason.as_deref().unwrap_or("unstated")
                ),
            });
        }
        if event
            .service
            .is_some_and(|service| service != selected_service)
        {
            marks.push(Mark {
                layer: Some(Layer::M6Vtl1),
                kind: MarkKind::ForeignService,
                sequence: Some(event.sequence),
                after_sequence: None,
                detail: format!(
                    "record {} carries service {:?}, not the selected {selected_service}",
                    event.sequence, event.service
                ),
            });
        }
    }
    (summary, events)
}

/// Pair the hypervisor's transitions with a stack per the one admitted VP. On one VP the calls
/// and returns alternate, so the stack never grows past one; it is a stack rather than an
/// alternation check so that what arrives decides, not what was expected.
fn pair_round_trips(
    events: &[M5Event],
    clock: &Clock,
    marks: &mut Vec<Mark>,
    unmatched: &mut Vec<Unmatched>,
) -> Vec<RoundTrip> {
    let mut open: Vec<RoundTrip> = Vec::new();
    let mut trips: Vec<RoundTrip> = Vec::new();
    let mut vp: Option<Option<u8>> = None;
    for event in events {
        match vp {
            None => vp = Some(event.vp_index),
            Some(first) if first != event.vp_index => marks.push(Mark {
                layer: Some(Layer::M5Hypervisor),
                kind: MarkKind::SeveralVps,
                sequence: Some(event.sequence),
                after_sequence: None,
                detail: format!(
                    "transition {} is on VP {:?} where the first was on VP {:?}",
                    event.sequence, event.vp_index, first
                ),
            }),
            Some(_) => {}
        }
        match (event.kind, event.source_vtl, event.target_vtl) {
            (TransitionKind::VtlCall, Some(0), Some(1)) => open.push(RoundTrip {
                call_sequence: event.sequence,
                return_sequence: None,
                call_tick: clock.tick(event.host_qpc),
                return_tick: None,
            }),
            (TransitionKind::VtlReturn, Some(1), Some(0)) => match open.pop() {
                Some(mut trip) => {
                    trip.return_sequence = Some(event.sequence);
                    trip.return_tick = clock.tick(event.host_qpc);
                    trips.push(trip);
                }
                None => {
                    marks.push(Mark {
                        layer: Some(Layer::M5Hypervisor),
                        kind: MarkKind::UnmatchedReturn,
                        sequence: Some(event.sequence),
                        after_sequence: None,
                        detail: format!(
                            "VTL return {} has no recorded VTL call before it",
                            event.sequence
                        ),
                    });
                    unmatched.push(Unmatched {
                        m6_sequence: None,
                        stage: Some(Stage::M5VtlReturn),
                        event: Some(EventId {
                            layer: Layer::M5Hypervisor,
                            sequence: event.sequence,
                            stage: Stage::M5VtlReturn,
                        }),
                        reason: "a VTL return with no recorded VTL call before it".into(),
                    });
                }
            },
            _ => marks.push(Mark {
                layer: Some(Layer::M5Hypervisor),
                kind: MarkKind::UnexpectedTransition,
                sequence: Some(event.sequence),
                after_sequence: None,
                detail: format!(
                    "transition {} is {:?} from VTL {:?} to VTL {:?}, neither a VTL0 call nor a VTL1 return",
                    event.sequence, event.kind, event.source_vtl, event.target_vtl
                ),
            }),
        }
    }
    for trip in open {
        marks.push(Mark {
            layer: Some(Layer::M5Hypervisor),
            kind: MarkKind::UnmatchedCall,
            sequence: Some(trip.call_sequence),
            after_sequence: None,
            detail: format!(
                "VTL call {} has no recorded VTL return after it",
                trip.call_sequence
            ),
        });
        unmatched.push(Unmatched {
            m6_sequence: None,
            stage: Some(Stage::M5VtlCall),
            event: Some(EventId {
                layer: Layer::M5Hypervisor,
                sequence: trip.call_sequence,
                stage: Stage::M5VtlCall,
            }),
            reason: "a VTL call with no recorded VTL return after it".into(),
        });
        trips.push(trip);
    }
    trips.sort_by_key(|trip| trip.call_sequence);
    trips
}

/// Which round trips could hold an instant: the one that strictly encloses it, plus any whose
/// boundary equals it and any whose boundary is unknown. One strict and nothing else is a match.
enum Placement {
    One(usize),
    None,
    Several(Vec<usize>),
}

/// What a round trip with no recorded return bounds. A trace that ran to a clean end left the VP
/// in VTL1 when it stopped, so its open trip encloses everything after its call up to the end of
/// the layer's window; a trace that was capped, dropped events, lost a breakpoint or was still
/// armed stopped recording, which says nothing about where the VP was, so its open trip decides
/// nothing.
#[derive(Clone, Copy)]
enum OpenBound {
    Until(Option<u64>),
    Undecided,
}

fn enclosing(trips: &[RoundTrip], tick: Option<u64>, open: OpenBound) -> Placement {
    let Some(tick) = tick else {
        return if trips.is_empty() {
            Placement::None
        } else {
            Placement::Several((0..trips.len()).collect())
        };
    };
    let mut strict = Vec::new();
    let mut undecided = Vec::new();
    for (index, trip) in trips.iter().enumerate() {
        let Some(call) = trip.call_tick else {
            undecided.push(index);
            continue;
        };
        if call > tick {
            continue;
        }
        if call == tick {
            undecided.push(index);
            continue;
        }
        match (trip.return_sequence, trip.return_tick) {
            (None, _) => match open {
                OpenBound::Undecided => undecided.push(index),
                OpenBound::Until(None) => strict.push(index),
                OpenBound::Until(Some(bound)) if tick <= bound => strict.push(index),
                OpenBound::Until(Some(_)) => {}
            },
            (Some(_), None) => undecided.push(index),
            (Some(_), Some(ret)) if ret > tick => strict.push(index),
            (Some(_), Some(ret)) if ret == tick => undecided.push(index),
            (Some(_), Some(_)) => {}
        }
    }
    match (strict.len(), undecided.is_empty()) {
        (1, true) => Placement::One(strict[0]),
        (0, true) => Placement::None,
        _ => {
            strict.extend(undecided);
            strict.sort_unstable();
            strict.dedup();
            Placement::Several(strict)
        }
    }
}

struct Ctx<'a> {
    clock: Clock,
    m4: Option<(&'a LayerSummary, &'a [M4Event])>,
    m5: Option<(&'a LayerSummary, &'a [RoundTrip])>,
    m6: &'a LayerSummary,
    m6_entries: usize,
    m4_candidates: Vec<usize>,
}

impl Ctx<'_> {
    fn m4_m6_relation(&self) -> WindowRelation {
        match (
            self.m4.and_then(|(summary, _)| summary.window),
            self.m6.window,
        ) {
            (Some(m4), Some(m6)) => m4.relation(&m6),
            _ => WindowRelation::Unknown,
        }
    }

    fn m5_m6_relation(&self) -> WindowRelation {
        match (
            self.m5.and_then(|(summary, _)| summary.window),
            self.m6.window,
        ) {
            (Some(m5), Some(m6)) => m5.relation(&m6),
            _ => WindowRelation::Unknown,
        }
    }
}

fn m4_event_id(sequence: u64) -> EventId {
    EventId {
        layer: Layer::M4Vtl0,
        sequence,
        stage: Stage::M4Entry,
    }
}

/// Decide the M4 entry of the chain whose M6 record is `record`, the `entry_rank`-th record with
/// an entry phase. `lower` is the latest comparable tick of the previous record, before which no
/// candidate for this chain can lie; `claimed` holds M4 entries earlier chains matched.
fn decide_m4(
    ctx: &Ctx<'_>,
    record: &M6Event,
    entry_rank: usize,
    lower: Option<u64>,
    claimed: &BTreeSet<u64>,
    marks: &mut Vec<Mark>,
) -> Decision {
    let Some((summary, events)) = ctx.m4 else {
        return Decision::Unobserved {
            reason: "the VTL0 call trace was not part of this capture".into(),
        };
    };
    let pool: Vec<&M4Event> = ctx
        .m4_candidates
        .iter()
        .map(|index| &events[*index])
        .filter(|event| !claimed.contains(&event.sequence))
        .collect();
    if pool.is_empty() {
        return Decision::Unmatched {
            reason:
                "the VTL0 trace holds no unclaimed secure-service entry of the selected service"
                    .into(),
        };
    }
    if ctx.clock.point {
        let entry_tick = ctx
            .clock
            .tick(record.entry.as_ref().and_then(|entry| entry.host_qpc));
        let Some(entry_tick) = entry_tick else {
            return Decision::Ambiguous {
                candidates: Candidates::new(
                    Stage::M4Entry,
                    pool.iter().map(|event| event.sequence),
                ),
                reason: "the VTL1 entry carries no clock sample on the admitted frequency".into(),
            };
        };
        let mut strict: Vec<&M4Event> = Vec::new();
        let mut undecided: Vec<&M4Event> = Vec::new();
        for event in &pool {
            match ctx.clock.tick(event.host_qpc) {
                None => undecided.push(event),
                Some(tick) if tick < entry_tick && lower.is_none_or(|lower| tick > lower) => {
                    strict.push(event)
                }
                Some(tick) if tick == entry_tick || lower == Some(tick) => undecided.push(event),
                Some(_) => {}
            }
        }
        return match (strict.as_slice(), undecided.is_empty()) {
            ([event], true) if event.selected => Decision::Matched {
                event: m4_event_id(event.sequence),
                rule: "the one selected VTL0 entry after the previous VTL1 record and before this VTL1 entry".into(),
            },
            ([], true) => Decision::Unmatched {
                reason: "no selected VTL0 entry lies after the previous VTL1 record and before this VTL1 entry".into(),
            },
            _ => Decision::Ambiguous {
                candidates: Candidates::new(
                    Stage::M4Entry,
                    strict.iter().chain(&undecided).map(|event| event.sequence),
                ),
                reason: if strict.iter().chain(&undecided).any(|event| !event.selected) {
                    "a time-compatible VTL0 hit has unreadable classification fields, so it cannot be excluded or uniquely matched".into()
                } else if strict.len() > 1 {
                    "several selected VTL0 entries lie between the previous VTL1 record and this VTL1 entry".into()
                } else {
                    "a candidate's tick equals a boundary or carries no comparable sample, so its order is unproved".into()
                },
            },
        };
    }

    // Interval-only: the coordinator's brackets can relate the two recording windows, and when
    // one contains the other and both are complete runs of equal length, the k-th selected entry
    // is the k-th record. Anything less leaves a range.
    let relation = ctx.m4_m6_relation();
    let n4 = ctx.m4_candidates.len();
    let n6 = ctx.m6_entries;
    let all = || Candidates::new(Stage::M4Entry, pool.iter().map(|event| event.sequence));
    match relation {
        WindowRelation::Disjoint => Decision::Unmatched {
            reason: "the VTL0 and VTL1 traces recorded disjoint windows, so no call was seen by both".into(),
        },
        _ if pool.iter().any(|event| !event.selected) => Decision::Ambiguous {
            candidates: all(),
            reason: "a potentially selected VTL0 hit has unreadable classification fields, so interval-only rank matching is not proved".into(),
        },
        WindowRelation::Contains | WindowRelation::ContainedBy
            if summary.complete_run() && ctx.m6.complete_run() =>
        {
            let (container_count, contained_count) = if relation == WindowRelation::Contains {
                (n4, n6)
            } else {
                (n6, n4)
            };
            if container_count < contained_count {
                marks.push(Mark {
                    layer: None,
                    kind: MarkKind::CountMismatch,
                    sequence: Some(record.sequence),
                    after_sequence: None,
                    detail: format!(
                        "the contained window recorded {contained_count} selected calls where the containing one recorded {container_count}"
                    ),
                });
                return Decision::Ambiguous {
                    candidates: all(),
                    reason: "the contained window recorded more selected calls than the window containing it".into(),
                };
            }
            let slack = container_count - contained_count;
            if slack == 0 {
                let sequence = events[ctx.m4_candidates[entry_rank]].sequence;
                return Decision::Matched {
                    event: m4_event_id(sequence),
                    rule: "rank: one complete run contains the other and both recorded the same number of selected calls".into(),
                };
            }
            // The contained run is a contiguous sub-run of the container at an unknown offset
            // of at most `slack`.
            let (first, last) = if relation == WindowRelation::Contains {
                (entry_rank, (entry_rank + slack).min(n4.saturating_sub(1)))
            } else {
                (entry_rank.saturating_sub(slack), entry_rank.min(n4.saturating_sub(1)))
            };
            let candidates = (first..=last)
                .filter(|rank| *rank < n4)
                .map(|rank| events[ctx.m4_candidates[rank]].sequence)
                .filter(|sequence| !claimed.contains(sequence));
            Decision::Ambiguous {
                candidates: Candidates::new(Stage::M4Entry, candidates),
                reason: format!(
                    "the containing window recorded {slack} more selected calls than the contained one; the offset is unknown"
                ),
            }
        }
        WindowRelation::Contains | WindowRelation::ContainedBy => Decision::Ambiguous {
            candidates: all(),
            reason: "one window contains the other but a trace is not a complete run (dropped, capped, gapped, missing a breakpoint or still armed)".into(),
        },
        WindowRelation::Overlap => Decision::Ambiguous {
            candidates: all(),
            reason: "the recording windows overlap without one containing the other, and the clock admits no point order".into(),
        },
        WindowRelation::Unknown => Decision::Ambiguous {
            candidates: all(),
            reason: "no arm and drain brackets relate the two windows, and the clock admits no point order".into(),
        },
    }
}

fn m5_event_id(sequence: u64, stage: Stage) -> EventId {
    EventId {
        layer: Layer::M5Hypervisor,
        sequence,
        stage,
    }
}

/// Decide the round trip holding a VTL1 phase observed at `tick`; `stage` says whether the chain
/// wants its call or its return.
fn decide_m5(ctx: &Ctx<'_>, tick: Option<u64>, stage: Stage) -> (Decision, Option<usize>) {
    let Some((summary, trips)) = ctx.m5 else {
        return (
            Decision::Unobserved {
                reason: "the hypervisor transition trace was not part of this capture".into(),
            },
            None,
        );
    };
    if trips.is_empty() {
        return (
            Decision::Unmatched {
                reason: "the hypervisor trace holds no VTL0 call".into(),
            },
            None,
        );
    }
    let sequence_of = |trip: &RoundTrip| match stage {
        Stage::M5VtlCall => Some(trip.call_sequence),
        _ => trip.return_sequence,
    };
    if !ctx.clock.point {
        return match ctx.m5_m6_relation() {
            WindowRelation::Disjoint => (
                Decision::Unmatched {
                    reason: "the hypervisor and VTL1 traces recorded disjoint windows".into(),
                },
                None,
            ),
            _ => (
                Decision::Ambiguous {
                    candidates: Candidates::new(stage, trips.iter().filter_map(sequence_of)),
                    reason:
                        "the clock admits no point order between the hypervisor and VTL1 workers"
                            .into(),
                },
                None,
            ),
        };
    }
    let open = if summary.complete_run() {
        OpenBound::Until(summary.window.map(|window| window.outer_to))
    } else {
        OpenBound::Undecided
    };
    match enclosing(trips, tick, open) {
        Placement::One(index) => {
            let trip = &trips[index];
            match sequence_of(trip) {
                Some(sequence) => (
                    Decision::Matched {
                        event: m5_event_id(sequence, stage),
                        rule: "the one round trip enclosing the VTL1 phase".into(),
                    },
                    Some(index),
                ),
                None => (
                    Decision::Unmatched {
                        reason:
                            "the round trip enclosing the VTL1 phase has no recorded VTL return"
                                .into(),
                    },
                    Some(index),
                ),
            }
        }
        Placement::None => (
            Decision::Unmatched {
                reason: "no recorded round trip encloses the VTL1 phase".into(),
            },
            None,
        ),
        Placement::Several(indices) => {
            let candidates = Candidates::new(
                stage,
                indices
                    .iter()
                    .filter_map(|index| sequence_of(&trips[*index])),
            );
            if candidates.count == 0 {
                return (
                    Decision::Unmatched {
                        reason: "every round trip that could hold the VTL1 phase has no recorded VTL return".into(),
                    },
                    None,
                );
            }
            (
                Decision::Ambiguous {
                    candidates,
                    reason: if tick.is_none() {
                        "the VTL1 phase carries no clock sample on the admitted frequency".into()
                    } else {
                        "a round-trip boundary equals the phase's tick, is unknown or carries no comparable sample, so the enclosure is unproved".into()
                    },
                },
                None,
            )
        }
    }
}

fn cross_checks(m4: &M4Event, m6: &M6Event) -> Vec<CrossCheck> {
    let mut checks = Vec::new();
    checks.push(CrossCheck {
        field: "service".into(),
        result: match (m4.service, m6.service) {
            (Some(left), Some(right)) if left == right => CrossCheckResult::Equal {
                value: left.to_string(),
            },
            (Some(left), Some(right)) => CrossCheckResult::Differs {
                m4: left.to_string(),
                m6: right.to_string(),
            },
            _ => CrossCheckResult::NotComparable {
                reason: "a side did not read the service".into(),
            },
        },
    });
    checks.push(CrossCheck {
        field: "transition_kind".into(),
        result: match (m4.transition_kind, m6.dispatch_mode) {
            (Some(left), Some(right)) if u64::from(left) == right => CrossCheckResult::Equal {
                value: left.to_string(),
            },
            (Some(left), Some(right)) => CrossCheckResult::Differs {
                m4: left.to_string(),
                m6: right.to_string(),
            },
            _ => CrossCheckResult::NotComparable {
                reason: "the dispatch phase carries no dispatch_mode field or M4 did not read CL"
                    .into(),
            },
        },
    });
    checks.push(CrossCheck {
        field: "argument_block[8..64]".into(),
        result: match (&m4.argument_block, &m6.request_before) {
            (Some(block), Some(request)) if block.len() >= 128 && request.len() >= 128 => {
                let left = block[16..128].to_ascii_lowercase();
                let right = request[16..128].to_ascii_lowercase();
                if left == right {
                    CrossCheckResult::Equal { value: left }
                } else {
                    CrossCheckResult::Differs {
                        m4: left,
                        m6: right,
                    }
                }
            }
            _ => CrossCheckResult::NotComparable {
                reason: "a side did not retain 64 bytes of the block".into(),
            },
        },
    });
    checks
}

/// Run the join. Errors are for input that cannot be joined at all (a schema this module does
/// not know, an identity that fails admission, a trace that is not a trace); everything about the
/// evidence itself comes back inside the result as decisions, marks and reasons.
pub(crate) fn join(input: &JoinInput) -> anyhow::Result<JoinedCapture> {
    if input.schema != JOIN_INPUT_SCHEMA {
        bail!("unsupported join input schema {}", input.schema);
    }
    input
        .identity
        .validate()
        .map_err(|message| anyhow!("capture identity: {message}"))?;
    let m6_trace: M6Trace = parse_layer(Layer::M6Vtl1, &input.layers.m6_vtl1.trace)?;
    if m6_trace.selected_service != input.selected_service {
        bail!(
            "the VTL1 trace selected service {} where the join was asked about {}",
            m6_trace.selected_service,
            input.selected_service
        );
    }
    let m4_trace = input
        .layers
        .m4_vtl0
        .as_ref()
        .map(|source| parse_layer::<M4Trace>(Layer::M4Vtl0, &source.trace))
        .transpose()?;
    let m5_trace = input
        .layers
        .m5_hypervisor
        .as_ref()
        .map(|source| parse_layer::<M5Trace>(Layer::M5Hypervisor, &source.trace))
        .transpose()?;

    let clock = Clock {
        point: input.clock.mode == ClockMode::Point,
        frequency: input.clock.frequency,
    };
    let mut marks = Vec::new();
    let mut unmatched = Vec::new();
    let mut ambiguous = Vec::new();

    let (m6_summary, m6_events) = normalize_m6(
        m6_trace,
        input.selected_service,
        &input.layers.m6_vtl1,
        &mut marks,
    );
    let m4 = m4_trace.map(|trace| {
        normalize_m4(
            trace,
            input.selected_service,
            input.secure_call_kind,
            input
                .layers
                .m4_vtl0
                .as_ref()
                .expect("parsed from the source"),
            &mut marks,
        )
    });
    let m5 = m5_trace.map(|trace| {
        normalize_m5(
            trace,
            input
                .layers
                .m5_hypervisor
                .as_ref()
                .expect("parsed from the source"),
            &mut marks,
        )
    });
    let round_trips = m5
        .as_ref()
        .map(|(_, events)| pair_round_trips(events, &clock, &mut marks, &mut unmatched))
        .unwrap_or_default();

    let m4_candidates: Vec<usize> = m4
        .as_ref()
        .map(|(_, events)| {
            events
                .iter()
                .enumerate()
                .filter(|(_, event)| event.candidate)
                .map(|(index, _)| index)
                .collect()
        })
        .unwrap_or_default();
    let ctx = Ctx {
        clock,
        m4: m4
            .as_ref()
            .map(|(summary, events)| (summary, events.as_slice())),
        m5: m5
            .as_ref()
            .map(|(summary, _)| (summary, round_trips.as_slice())),
        m6: &m6_summary,
        m6_entries: m6_events
            .iter()
            .filter(|event| event.entry.is_some())
            .count(),
        m4_candidates,
    };

    let mut windows = Vec::new();
    if ctx.m4.is_some() {
        windows.push(WindowPair {
            first: Layer::M4Vtl0,
            second: Layer::M6Vtl1,
            relation: ctx.m4_m6_relation(),
        });
    }
    if ctx.m5.is_some() {
        windows.push(WindowPair {
            first: Layer::M5Hypervisor,
            second: Layer::M6Vtl1,
            relation: ctx.m5_m6_relation(),
        });
    }
    if let (Some((m4_summary, _)), Some((m5_summary, _))) = (ctx.m4, ctx.m5) {
        windows.push(WindowPair {
            first: Layer::M4Vtl0,
            second: Layer::M5Hypervisor,
            relation: match (m4_summary.window, m5_summary.window) {
                (Some(m4), Some(m5)) => m4.relation(&m5),
                _ => WindowRelation::Unknown,
            },
        });
    }

    let source = if ctx.m4.is_some() {
        FirstStageSource::M4Vtl0Entry
    } else {
        FirstStageSource::M6EntryCopy
    };
    let first_stage = FirstStage {
        source,
        fields: first_stage_fields(source, input.workload_process_id),
    };

    let mut chains = Vec::new();
    let mut claimed: BTreeSet<u64> = BTreeSet::new();
    let mut entry_rank = 0usize;
    let mut lower: Option<u64> = ctx
        .m6
        .window
        .map(|window| window.outer_from)
        .filter(|_| ctx.clock.point);
    for record in &m6_events {
        let m6_stage = |phase: &Option<PhaseStamp>, stage: Stage| match phase {
            Some(_) => Decision::Matched {
                event: EventId {
                    layer: Layer::M6Vtl1,
                    sequence: record.sequence,
                    stage,
                },
                rule: "observed by the VTL1 service trace in this record".into(),
            },
            None => Decision::Unmatched {
                reason: format!(
                    "the record ends at its {:?} phase ({})",
                    record
                        .returned
                        .as_ref()
                        .map(|_| Stage::M6Return)
                        .or(record.dispatch.as_ref().map(|_| Stage::M6Dispatch))
                        .or(record.entry.as_ref().map(|_| Stage::M6Entry)),
                    record.incomplete_reason.as_deref().unwrap_or("unstated")
                ),
            },
        };
        let mut reasons = Vec::new();
        let this_rank = entry_rank;
        if record.entry.is_some() {
            entry_rank += 1;
        }

        let (m4_entry, m5_vtl_call, m5_vtl_return, nested, before_entry, checks) = if record
            .complete
        {
            let m4_entry = decide_m4(&ctx, record, this_rank, lower, &claimed, &mut marks);
            if let Some(event) = m4_entry.matched() {
                claimed.insert(event.sequence);
            }
            let entry_tick = ctx
                .clock
                .tick(record.entry.as_ref().and_then(|phase| phase.host_qpc));
            let return_tick = ctx
                .clock
                .tick(record.returned.as_ref().and_then(|phase| phase.host_qpc));
            let (call, call_index) = decide_m5(&ctx, entry_tick, Stage::M5VtlCall);
            let (ret, return_index) = decide_m5(&ctx, return_tick, Stage::M5VtlReturn);
            let (mut call, mut ret) = (call, ret);
            let mut nested = None;
            let mut before_entry = None;
            if let (Some(call_index), Some(return_index)) = (call_index, return_index) {
                if return_index < call_index {
                    marks.push(Mark {
                        layer: Some(Layer::M5Hypervisor),
                        kind: MarkKind::OrderContradiction,
                        sequence: Some(record.sequence),
                        after_sequence: None,
                        detail: "the round trip enclosing the VTL1 return precedes the one enclosing its entry".into(),
                    });
                    reasons
                        .push("the hypervisor round trips contradict the VTL1 phase order".into());
                    call = Decision::Unmatched {
                        reason: "withdrawn: the enclosing round trips are out of order".into(),
                    };
                    ret = Decision::Unmatched {
                        reason: "withdrawn: the enclosing round trips are out of order".into(),
                    };
                } else {
                    nested = Some((return_index - call_index) as u64);
                }
            }
            if let (Some(call_index), Some(event), Some((_, events)), Some((_, trips))) =
                (call_index, m4_entry.matched(), ctx.m4, ctx.m5)
            {
                let m4_tick = events
                    .iter()
                    .find(|candidate| candidate.sequence == event.sequence)
                    .and_then(|candidate| ctx.clock.tick(candidate.host_qpc));
                if let Some(m4_tick) = m4_tick {
                    let delivering = &trips[call_index];
                    if delivering.call_tick.is_some_and(|tick| tick < m4_tick) {
                        marks.push(Mark {
                            layer: None,
                            kind: MarkKind::OrderContradiction,
                            sequence: Some(record.sequence),
                            after_sequence: None,
                            detail: "the round trip delivering the VTL1 entry precedes the matched VTL0 entry".into(),
                        });
                        reasons.push(
                            "the VTL0 entry follows the round trip that delivered its VTL1 entry"
                                .into(),
                        );
                    } else {
                        before_entry = Some(
                            trips[..call_index]
                                .iter()
                                .filter(|trip| trip.call_tick.is_some_and(|tick| tick > m4_tick))
                                .count() as u64,
                        );
                    }
                }
            }
            let checks = match (m4_entry.matched(), ctx.m4) {
                (Some(event), Some((_, events))) => events
                    .iter()
                    .find(|candidate| candidate.sequence == event.sequence)
                    .map(|candidate| cross_checks(candidate, record))
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            (m4_entry, call, ret, nested, before_entry, checks)
        } else {
            let withheld = |what: &str| Decision::Unmatched {
                reason: format!(
                    "not decided: the VTL1 record is incomplete, so {what} has no proved bound"
                ),
            };
            reasons.push(format!(
                "the VTL1 record is incomplete ({})",
                record.incomplete_reason.as_deref().unwrap_or("unstated")
            ));
            (
                if ctx.m4.is_some() {
                    withheld("the VTL0 entry")
                } else {
                    Decision::Unobserved {
                        reason: "the VTL0 call trace was not part of this capture".into(),
                    }
                },
                if ctx.m5.is_some() {
                    withheld("the VTL call")
                } else {
                    Decision::Unobserved {
                        reason: "the hypervisor transition trace was not part of this capture"
                            .into(),
                    }
                },
                if ctx.m5.is_some() {
                    withheld("the VTL return")
                } else {
                    Decision::Unobserved {
                        reason: "the hypervisor transition trace was not part of this capture"
                            .into(),
                    }
                },
                None,
                None,
                Vec::new(),
            )
        };

        let stages = Stages {
            m4_entry,
            m5_vtl_call,
            m6_entry: m6_stage(&record.entry, Stage::M6Entry),
            m6_dispatch: m6_stage(&record.dispatch, Stage::M6Dispatch),
            m6_return: m6_stage(&record.returned, Stage::M6Return),
            m5_vtl_return,
        };
        for (stage, decision) in stages.each() {
            match decision {
                Decision::Matched { .. } => {}
                Decision::Ambiguous { candidates, reason } => {
                    reasons.push(format!("{stage:?} is ambiguous: {reason}"));
                    ambiguous.push(Ambiguity {
                        m6_sequence: record.sequence,
                        stage,
                        candidates: candidates.clone(),
                        reason: reason.clone(),
                    });
                }
                Decision::Unmatched { reason } => {
                    reasons.push(format!("{stage:?} is unmatched: {reason}"));
                    unmatched.push(Unmatched {
                        m6_sequence: Some(record.sequence),
                        stage: Some(stage),
                        event: None,
                        reason: reason.clone(),
                    });
                }
                Decision::Unobserved { reason } => {
                    if stage != Stage::M4Entry {
                        reasons.push(format!("{stage:?} was not observed: {reason}"));
                    }
                }
            }
        }
        for check in &checks {
            if let CrossCheckResult::Differs { m4, m6 } = &check.result {
                reasons.push(format!(
                    "cross-check {} differs: VTL0 read {m4}, VTL1 read {m6}",
                    check.field
                ));
            }
        }
        let m4_unobserved = matches!(stages.m4_entry, Decision::Unobserved { .. });
        let verdict = if !reasons.is_empty() {
            ChainVerdict::Incomplete
        } else if m4_unobserved {
            ChainVerdict::Provisional
        } else {
            ChainVerdict::Complete
        };
        let call_id = (verdict != ChainVerdict::Incomplete)
            .then(|| format!("{}:call:{}", input.identity.capture_id, record.sequence));
        chains.push(Chain {
            call_id,
            m6_sequence: record.sequence,
            service: record.service,
            status: record.status,
            stages,
            nested_round_trips: nested,
            round_trips_before_entry: before_entry,
            cross_checks: checks,
            verdict,
            reasons,
        });

        if ctx.clock.point {
            let latest = [&record.returned, &record.dispatch, &record.entry]
                .into_iter()
                .flatten()
                .find_map(|phase| ctx.clock.tick(phase.host_qpc));
            lower = latest.or(lower);
        }
    }

    if let Some((_, events)) = ctx.m4 {
        for index in &ctx.m4_candidates {
            let event = &events[*index];
            if !claimed.contains(&event.sequence) {
                unmatched.push(Unmatched {
                    m6_sequence: None,
                    stage: Some(Stage::M4Entry),
                    event: Some(m4_event_id(event.sequence)),
                    reason: if event.selected {
                        "no VTL1 record claimed this selected VTL0 entry".into()
                    } else {
                        "no VTL1 record claimed this potentially selected VTL0 entry whose classification was unreadable".into()
                    },
                });
            }
        }
    }

    let mut cross_check_summary: Vec<CrossCheckSummary> = Vec::new();
    for check in chains.iter().flat_map(|chain| &chain.cross_checks) {
        let entry = match cross_check_summary
            .iter_mut()
            .find(|summary| summary.field == check.field)
        {
            Some(entry) => entry,
            None => {
                cross_check_summary.push(CrossCheckSummary {
                    field: check.field.clone(),
                    equal: 0,
                    differs: 0,
                    not_comparable: 0,
                });
                cross_check_summary.last_mut().expect("just pushed")
            }
        };
        match check.result {
            CrossCheckResult::Equal { .. } => entry.equal += 1,
            CrossCheckResult::Differs { .. } => entry.differs += 1,
            CrossCheckResult::NotComparable { .. } => entry.not_comparable += 1,
        }
    }

    let mut reasons = Vec::new();
    if chains.is_empty() {
        reasons.push("no VTL1 record of the selected service: nothing to join".into());
    }
    if let Some(expected) = input.expected_selected_calls
        && chains.len() as u64 != expected
    {
        reasons.push(format!(
            "{} VTL1 records where the workload was expected to produce {expected} selected calls",
            chains.len()
        ));
        marks.push(Mark {
            layer: Some(Layer::M6Vtl1),
            kind: MarkKind::CountMismatch,
            sequence: None,
            after_sequence: None,
            detail: format!(
                "{} records against {expected} expected selected calls",
                chains.len()
            ),
        });
    }
    for mark in &marks {
        reasons.push(format!(
            "{} {:?}: {}",
            mark.layer.map_or("capture", Layer::wire_name),
            mark.kind,
            mark.detail
        ));
    }
    let incomplete = chains
        .iter()
        .filter(|chain| chain.verdict == ChainVerdict::Incomplete)
        .count();
    if incomplete > 0 {
        reasons.push(format!("{incomplete} chains are incomplete"));
    }
    let verdict = if !reasons.is_empty() {
        JoinVerdict::Incomplete
    } else if chains
        .iter()
        .any(|chain| chain.verdict == ChainVerdict::Provisional)
    {
        reasons.push(
            "chains start from M6's entry phase; the VTL0 fields are copies, envelope values or unavailable (first_stage.fields)".into(),
        );
        JoinVerdict::Provisional
    } else {
        JoinVerdict::Complete
    };

    Ok(JoinedCapture {
        schema: JOIN_SCHEMA.into(),
        identity: input.identity.clone(),
        clock: ClockSummary {
            mode: input.clock.mode,
            frequency: input.clock.frequency,
            resolution_ns: input.clock.resolution_ns,
            reasons: input.clock.reasons.clone(),
        },
        selected_service: input.selected_service,
        secure_call_kind: input.secure_call_kind,
        expected_selected_calls: input.expected_selected_calls,
        workload_process_id: input.workload_process_id,
        first_stage,
        layers: LayerSummaries {
            m4_vtl0: m4.as_ref().map(|(summary, _)| summary.clone()),
            m5_hypervisor: m5.as_ref().map(|(summary, _)| summary.clone()),
            m6_vtl1: Some(m6_summary.clone()),
        },
        windows,
        events: Events {
            m4_vtl0: m4.map(|(_, events)| events).unwrap_or_default(),
            m5_hypervisor: m5.map(|(_, events)| events).unwrap_or_default(),
            m6_vtl1: m6_events,
        },
        round_trips,
        chains,
        unmatched,
        ambiguous,
        marks,
        cross_check_summary,
        verdict,
        reasons,
        sources: Sources {
            m4_vtl0: input
                .layers
                .m4_vtl0
                .as_ref()
                .map(|source| source.trace.clone()),
            m5_hypervisor: input
                .layers
                .m5_hypervisor
                .as_ref()
                .map(|source| source.trace.clone()),
            m6_vtl1: input.layers.m6_vtl1.trace.clone(),
        },
    })
}

// ---- rendering ---------------------------------------------------------------------------

fn cell(decision: &Decision) -> String {
    match decision {
        Decision::Matched { event, .. } => event.sequence.to_string(),
        Decision::Ambiguous { candidates, .. } => format!("?{}", candidates.count),
        Decision::Unmatched { .. } => "-".into(),
        Decision::Unobserved { .. } => "n/a".into(),
    }
}

/// A bounded table of the joined capture, computed from the JSON record alone. The first rows
/// summarize, one row follows per chain up to `max_rows`, and the tail counts what was elided and
/// lists the marks, unmatched and ambiguous entries up to the same bound each.
pub(crate) fn render_table(joined: &JoinedCapture, max_rows: usize) -> String {
    let mut out = String::new();
    let count = |verdict: ChainVerdict| {
        joined
            .chains
            .iter()
            .filter(|chain| chain.verdict == verdict)
            .count()
    };
    out.push_str(&format!(
        "M7.2 join {} ({}): {:?}; {} chains ({} complete, {} provisional, {} incomplete); clock {:?}; first stage {:?}\n",
        joined.identity.capture_id,
        joined.schema,
        joined.verdict,
        joined.chains.len(),
        count(ChainVerdict::Complete),
        count(ChainVerdict::Provisional),
        count(ChainVerdict::Incomplete),
        joined.clock.mode,
        joined.first_stage.source,
    ));
    let layer_line = |name: &str, summary: Option<&LayerSummary>| match summary {
        Some(summary) => format!(
            "  {name}: {} events (seq {:?}..{:?}), dropped {}, full {}, unreadable {}, contiguous {}\n",
            summary.events,
            summary.first_sequence,
            summary.last_sequence,
            summary.dropped,
            summary.full,
            summary.unreadable,
            summary.contiguous
        ),
        None => format!("  {name}: not in this capture\n"),
    };
    out.push_str(&layer_line("m4_vtl0", joined.layers.m4_vtl0.as_ref()));
    out.push_str(&layer_line(
        "m5_hypervisor",
        joined.layers.m5_hypervisor.as_ref(),
    ));
    out.push_str(&layer_line("m6_vtl1", joined.layers.m6_vtl1.as_ref()));
    for pair in &joined.windows {
        out.push_str(&format!(
            "  windows {} / {}: {:?}\n",
            pair.first.wire_name(),
            pair.second.wire_name(),
            pair.relation
        ));
    }
    out.push_str(
        "call_id | m6 | m4 | vtl_call | entry | dispatch | return | vtl_return | nested | status | verdict\n",
    );
    for chain in joined.chains.iter().take(max_rows) {
        let phase = |decision: &Decision, phase: &Option<PhaseStamp>| match (decision, phase) {
            (Decision::Matched { .. }, Some(stamp)) => stamp.host_monotonic_us.to_string(),
            _ => "-".into(),
        };
        let record = joined
            .events
            .m6_vtl1
            .iter()
            .find(|event| event.sequence == chain.m6_sequence);
        let (entry, dispatch, returned) = match record {
            Some(record) => (
                phase(&chain.stages.m6_entry, &record.entry),
                phase(&chain.stages.m6_dispatch, &record.dispatch),
                phase(&chain.stages.m6_return, &record.returned),
            ),
            None => ("-".into(), "-".into(), "-".into()),
        };
        out.push_str(&format!(
            "{} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {:?}\n",
            chain.call_id.as_deref().unwrap_or("-"),
            chain.m6_sequence,
            cell(&chain.stages.m4_entry),
            cell(&chain.stages.m5_vtl_call),
            entry,
            dispatch,
            returned,
            cell(&chain.stages.m5_vtl_return),
            chain
                .nested_round_trips
                .map_or("-".to_string(), |nested| nested.to_string()),
            chain
                .status
                .map_or("-".to_string(), |status| format!("{status:#x}")),
            chain.verdict,
        ));
    }
    if joined.chains.len() > max_rows {
        out.push_str(&format!(
            "... {} more chains in the JSON\n",
            joined.chains.len() - max_rows
        ));
    }
    out.push_str(&format!(
        "unmatched {}, ambiguous {}, marks {}\n",
        joined.unmatched.len(),
        joined.ambiguous.len(),
        joined.marks.len()
    ));
    for mark in joined.marks.iter().take(max_rows) {
        out.push_str(&format!(
            "  mark {} {:?}: {}\n",
            mark.layer.map_or("capture", Layer::wire_name),
            mark.kind,
            mark.detail
        ));
    }
    for entry in joined.ambiguous.iter().take(max_rows) {
        out.push_str(&format!(
            "  ambiguous m6 {} {:?}: {} candidates {:?}: {}\n",
            entry.m6_sequence,
            entry.stage,
            entry.candidates.count,
            entry
                .candidates
                .sequence_ranges
                .iter()
                .map(|range| format!("{}..={}", range.first, range.last))
                .collect::<Vec<_>>(),
            entry.reason
        ));
    }
    for entry in joined.unmatched.iter().take(max_rows) {
        out.push_str(&format!(
            "  unmatched m6 {:?} {:?} {:?}: {}\n",
            entry.m6_sequence,
            entry.stage,
            entry.event.as_ref().map(|event| event.sequence),
            entry.reason
        ));
    }
    for summary in &joined.cross_check_summary {
        out.push_str(&format!(
            "  cross-check {}: equal {}, differs {}, not comparable {}\n",
            summary.field, summary.equal, summary.differs, summary.not_comparable
        ));
    }
    out
}

/// The engine-free `--m7-join <input.json>` role: read a [`JoinInput`], print the joined capture
/// as one JSON document, or the table rendered from it under `--m7-join-table`. It exits before
/// the MCP runtime like the other M7 roles.
pub(crate) fn run_join(args: &[String]) -> anyhow::Result<()> {
    let at = args
        .iter()
        .position(|argument| argument == JOIN_FLAG)
        .ok_or_else(|| anyhow!("{JOIN_FLAG} is required"))?;
    let path = args
        .get(at + 1)
        .filter(|path| !path.starts_with("--"))
        .ok_or_else(|| anyhow!("{JOIN_FLAG} takes the input file path"))?;
    let text = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    let input: JoinInput =
        serde_json::from_str(&text).with_context(|| format!("{path} is not a join input"))?;
    let joined = join(&input)?;
    let mut stdout = std::io::stdout().lock();
    if args.iter().any(|argument| argument == JOIN_TABLE_FLAG) {
        stdout.write_all(render_table(&joined, TABLE_ROWS).as_bytes())?;
    } else {
        serde_json::to_writer(&mut stdout, &joined)?;
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skcorrelate::{
        CAPTURE_SCHEMA, LayerBinding, LayerBindings, M5HypervisorProvider, M6Vtl1Provider,
        ParentIdentity, TargetShape, WorkloadPlacement, admit_clock,
    };
    use serde_json::json;

    const FREQUENCY: u64 = 10_000_000;
    const SELECTED: u16 = 47;

    /// xorshift64*, as `tests/mcp_smoke.rs` uses it: a seed replays a run, and zero is the one
    /// state the generator cannot be given.
    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Self {
            Self(if seed == 0 {
                0x243F_6A88_85A3_08D3
            } else {
                seed
            })
        }

        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound.max(1)
        }

        fn shuffle<T>(&mut self, items: &mut [T]) {
            for index in (1..items.len()).rev() {
                let other = self.below(index as u64 + 1) as usize;
                items.swap(index, other);
            }
        }
    }

    fn binding(profile: &str, digit: char) -> LayerBinding {
        LayerBinding {
            profile: profile.into(),
            image_identity_sha256: std::iter::repeat_n(digit, 64).collect(),
        }
    }

    fn identity() -> CaptureIdentity {
        CaptureIdentity {
            schema: CAPTURE_SCHEMA.into(),
            capture_id: "m7-join-test".into(),
            vm_id: "child-vm".into(),
            guest_boot_identity: "2026-10-25T13:13:00Z".into(),
            vmwp_pid: 7964,
            parent: Some(ParentIdentity {
                vm_id: "parent-vm".into(),
                guest_boot_identity: "2026-10-24T18:28:16Z".into(),
                vmwp_pid: 10308,
            }),
            workload_label: "join-test".into(),
            processor_count: 1,
            target_shape: TargetShape {
                nested_virtualization: true,
                guest_hypervisor_started: true,
                workload_placement: WorkloadPlacement::ChildPartition,
                outer_partition_vtl1: false,
                nested_child_vtl1: true,
                m5_provider: M5HypervisorProvider::GuestNested,
                m6_provider: M6Vtl1Provider::NestedParent,
            },
            layers: LayerBindings {
                m4_vtl0: binding("l2-nt", 'a'),
                m5_hypervisor: binding("k3-hypervisor", 'b'),
                m6_vtl1: binding("nested-vmwp-profile", 'c'),
            },
        }
    }

    fn sample(tick: u64) -> HostQpcSample {
        HostQpcSample {
            tick,
            frequency: FREQUENCY,
        }
    }

    fn bracket(layer: Layer, operation: &str, at: u64, worker_frequency: u64) -> RpcClockBracket {
        RpcClockBracket {
            layer: layer.wire_name().into(),
            operation: operation.into(),
            coordinator_before: sample(at),
            worker: Some(HostQpcSample {
                tick: at + 5,
                frequency: worker_frequency,
            }),
            coordinator_after: sample(at + 10),
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TruthChain {
        m6_sequence: u64,
        m4_sequence: u64,
        call_sequence: u64,
        return_sequence: u64,
        nested: u64,
        before_entry: u64,
    }

    /// A ground-truth timeline on one VP, emitted in the three layers' public shapes. Outer
    /// calls are secure-service entries (selected or ambient) or an enclave call; inside a
    /// selected service the Secure Kernel makes normal-mode calls, during which VTL0 may make
    /// an ambient secure call of its own, so the three layers nest the way the lab does.
    struct Timeline {
        tick: u64,
        m4: Vec<Value>,
        m5: Vec<Value>,
        m6: Vec<Value>,
        trips: Vec<(u64, u64)>,
        truth: Vec<TruthChain>,
        block: String,
    }

    impl Timeline {
        fn new(start: u64) -> Self {
            Self {
                tick: start,
                m4: Vec::new(),
                m5: Vec::new(),
                m6: Vec::new(),
                trips: Vec::new(),
                truth: Vec::new(),
                block: format!("{:0>208}", "8402004001000000"),
            }
        }

        fn step(&mut self, rng: &mut Rng) -> u64 {
            self.tick += 1 + rng.below(40);
            self.tick
        }

        fn m4_entry(&mut self, rng: &mut Rng, kind: u8, service: u16, pid: u32) -> u64 {
            let tick = self.step(rng);
            let sequence = self.m4.len() as u64;
            self.m4.push(json!({
                "sequence": sequence,
                "host_qpc": {"tick": tick, "frequency": FREQUENCY},
                "host_monotonic_us": tick / 10,
                "host_elapsed_us": tick,
                "transition_kind": kind,
                "service": service,
                "call_context": 0,
                "argument_block": self.block,
                "caller_symbol": if service == SELECTED { "nt!VslCreateEnclave" } else { "nt!VslApplySecureImageFixups" },
                "process_id": pid,
                "thread": "0xffffdb07dd4f2080",
                "processor": 0,
                "provenance": {"measured": ["service"], "symbol_derived": [], "inferred": [], "read_failures": []}
            }));
            sequence
        }

        fn transition(&mut self, rng: &mut Rng, call: bool) -> u64 {
            let tick = self.step(rng);
            let sequence = self.m5.len() as u64;
            self.m5.push(json!({
                "sequence": sequence,
                "host_qpc": {"tick": tick, "frequency": FREQUENCY},
                "host_monotonic_us": tick / 10,
                "host_elapsed_us": tick,
                "kind": if call { "vtl_call" } else { "vtl_return" },
                "processor": 0,
                "vp_index": 3,
                "source_vtl": if call { 0 } else { 1 },
                "target_vtl": if call { 1 } else { 0 },
                "control": if call { "0x0" } else { "0x1" },
                "provenance": {"measured": ["kind"], "exact_build_derived": [], "architectural": [], "inferred": [], "read_failures": []}
            }));
            sequence
        }

        fn round_trip(&mut self, rng: &mut Rng) -> (u64, u64) {
            let call = self.transition(rng, true);
            let ret = self.transition(rng, false);
            self.trips.push((call, ret));
            (call, ret)
        }

        fn site(&mut self, rng: &mut Rng, epoch: u64) -> Value {
            let tick = self.step(rng);
            json!({
                "epoch": format!("control-test-stopped-{epoch:016x}"),
                "host_qpc": {"tick": tick, "frequency": FREQUENCY},
                "host_monotonic_us": tick / 10,
                "host_elapsed_us": tick,
                "coordinate": {"address": "0xfffff803876cd7f0", "rva": 79856, "symbol": "securekernel!IumInvokeSecureService"}
            })
        }

        fn outer_call(&mut self, rng: &mut Rng, selected: bool, pid: u32) {
            let (kind, service) = if selected {
                (DEFAULT_SECURE_CALL_KIND, SELECTED)
            } else if rng.below(8) == 0 {
                (1, 0)
            } else {
                (
                    DEFAULT_SECURE_CALL_KIND,
                    [45, 46, 48][rng.below(3) as usize],
                )
            };
            let m4_sequence = self.m4_entry(rng, kind, service, pid);
            let first_call = self.transition(rng, true);
            if !selected {
                let ret = self.transition(rng, false);
                self.trips.push((first_call, ret));
                return;
            }
            let mut before_entry = 0;
            let mut delivering = first_call;
            if rng.below(6) == 0 {
                let ret = self.transition(rng, false);
                self.trips.push((first_call, ret));
                delivering = self.transition(rng, true);
                before_entry = 1;
            }
            let m6_sequence = self.m6.len() as u64 + 1;
            let entry = self.site(rng, m6_sequence * 16);
            let mut nested = 0;
            let mut last_call = delivering;
            let mut inner_rets = Vec::new();
            for _ in 0..rng.below(3) {
                let ret = self.transition(rng, false);
                if rng.below(3) == 0 {
                    self.m4_entry(rng, DEFAULT_SECURE_CALL_KIND, 241, 4);
                    self.round_trip(rng);
                }
                let call = self.transition(rng, true);
                inner_rets.push((last_call, ret));
                last_call = call;
                nested += 1;
            }
            let dispatch = self.site(rng, m6_sequence * 16 + 4);
            for _ in 0..rng.below(2) {
                let ret = self.transition(rng, false);
                let call = self.transition(rng, true);
                inner_rets.push((last_call, ret));
                last_call = call;
                nested += 1;
            }
            let returned = self.site(rng, m6_sequence * 16 + 8);
            let final_return = self.transition(rng, false);
            inner_rets.push((last_call, final_return));
            // Every inner round trip, including nested ambient ones, counts toward `nested`
            // only through the enclosing-trip arithmetic the join does; the truth records the
            // index distance the join will compute.
            self.trips.extend(inner_rets);
            self.m6.push(json!({
                "schema": "windbg-mcp.sk-service-call.v1",
                "trace_id": "sktrace-test",
                "label": "join-test",
                "sequence": m6_sequence,
                "manifest_id": "securekernel-10.0.26100.9457-service-47",
                "complete": true,
                "incomplete_reason": null,
                "last_phase": "return",
                "entry": {
                    "site": entry,
                    "service": SELECTED,
                    "caller": {"address": "0xfffff8038779f406", "rva": 939014, "symbol": "securekernel+0xe5406"},
                    "raw_arguments": {"rcx": "0xffff898075215e68", "rdx": "0xffff898075215ed0", "r8": "0xffff898075215ed0", "r9": "0xffffe787d7847080"},
                    "provenance": {"measured": ["entry.raw_arguments"], "exact_build_layout_derived": [], "inferred": [], "unavailable": []}
                },
                "dispatch": {
                    "site": dispatch,
                    "handler": {"address": "0xfffff80387713990", "rva": 366992, "symbol": "securekernel!SkmmCreateEnclave"},
                    "request": "0xffff898075215e68",
                    "fields": [
                        {"name": "dispatch_mode", "offset": 0, "width": 1, "value": "0x0000000000000002"},
                        {"name": "completion", "offset": 1, "width": 1, "value": "0x0000000000000000"},
                        {"name": "service_number", "offset": 2, "width": 2, "value": "0x000000000000002f"}
                    ],
                    "buffers_before": [{"name": "request.before", "address": "0xffff898075215e68", "available_size": 64, "requested_size": 64,
                        "bytes": {"state": "measured", "data": format!("02002F0000000000{}", &self.block[16..128])}}],
                    "provenance": {"measured": ["dispatch.fields"], "exact_build_layout_derived": [], "inferred": [], "unavailable": []}
                },
                "returned": {
                    "site": returned,
                    "status": 0,
                    "buffers_after": [],
                    "provenance": {"measured": ["returned.status"], "exact_build_layout_derived": [], "inferred": [], "unavailable": []}
                }
            }));
            self.truth.push(TruthChain {
                m6_sequence,
                m4_sequence,
                call_sequence: delivering,
                return_sequence: final_return,
                nested,
                before_entry,
            });
        }
    }

    struct Fixture {
        input: JoinInput,
        truth: Vec<TruthChain>,
        start: u64,
    }

    fn fixture(seed: u64, outer_calls: usize, with_m4: bool) -> Fixture {
        let mut rng = Rng::new(seed);
        let start = 1_000_000;
        let mut timeline = Timeline::new(start);
        let mut any_selected = false;
        for index in 0..outer_calls {
            let selected = rng.below(2) == 0 || (index + 1 == outer_calls && !any_selected);
            any_selected |= selected;
            timeline.outer_call(&mut rng, selected, if selected { 4680 } else { 4 });
        }
        // What the join counts as nested: the round trips closed between the delivering one and
        // the returning one, in call order, the Secure Kernel's normal-mode calls and the ambient
        // secure calls VTL0 made during them alike.
        let mut trips = timeline.trips.clone();
        trips.sort_unstable();
        for truth in &mut timeline.truth {
            let delivering = trips
                .iter()
                .position(|(call, _)| *call == truth.call_sequence)
                .expect("the delivering call closed a round trip");
            let returning = trips
                .iter()
                .position(|(_, ret)| *ret == truth.return_sequence)
                .expect("the final return closed a round trip");
            truth.nested = (returning - delivering) as u64;
        }
        let end = timeline.tick + 1_000;
        let layer = |layer: Layer, trace: Value| LayerSource {
            trace,
            arm: Some(bracket(layer, "arm", start - 500, FREQUENCY)),
            drain: Some(bracket(layer, "drain", end, FREQUENCY)),
            restoration: Some(RestorationAudit {
                restored: true,
                running: false,
                held: false,
                dropped_records: 0,
                dropped_bytes: 0,
                unreadable_fields: 0,
            }),
        };
        let m4 = layer(
            Layer::M4Vtl0,
            json!({
                "schema": "windbg-mcp.sk-call-trace.v1",
                "status": "ok",
                "trace_id": "skcall-1",
                "label": "join-test",
                "calls": timeline.m4,
                "limit": 1024, "full": false, "dropped": 0, "unreadable_hits": 0,
                "missing_breakpoint": false, "armed": false, "source_vtl": 0, "machine": "0x8664",
                "identity_gaps": []
            }),
        );
        let m5 = layer(
            Layer::M5Hypervisor,
            json!({
                "schema": "windbg-mcp.hv-transition-trace.v1",
                "status": "ok",
                "trace_id": "hvtransition-1",
                "label": "join-test",
                "transitions": timeline.m5,
                "limit": 1024, "full": false, "dropped": 0, "unreadable_hits": 0,
                "missing_breakpoints": 0, "armed": false
            }),
        );
        let m6 = layer(
            Layer::M6Vtl1,
            json!({
                "schema": "windbg-mcp.sk-service-trace.v1",
                "status": "ok",
                "trace_id": "sktrace-test",
                "label": "join-test",
                "manifest_id": "securekernel-10.0.26100.9457-service-47",
                "selected_service": SELECTED,
                "records": timeline.m6,
                "full": false, "dropped_records": 0, "dropped_capture_bytes": 0,
                "unreadable_fields": 0, "armed": false, "pending_phase": null
            }),
        );
        let mut brackets = vec![
            m6.arm.clone().unwrap(),
            m5.arm.clone().unwrap(),
            m5.drain.clone().unwrap(),
            m6.drain.clone().unwrap(),
        ];
        if with_m4 {
            brackets.insert(1, m4.arm.clone().unwrap());
            brackets.insert(3, m4.drain.clone().unwrap());
        }
        let clock = admit_clock(brackets, 1_000).expect("brackets are ordered");
        assert_eq!(clock.mode, ClockMode::Point);
        Fixture {
            input: JoinInput {
                schema: JOIN_INPUT_SCHEMA.into(),
                identity: identity(),
                clock,
                selected_service: SELECTED,
                secure_call_kind: DEFAULT_SECURE_CALL_KIND,
                expected_selected_calls: Some(timeline.truth.len() as u64),
                workload_process_id: Some(4680),
                layers: JoinLayers {
                    m4_vtl0: with_m4.then_some(m4),
                    m5_hypervisor: Some(m5),
                    m6_vtl1: m6,
                },
            },
            truth: timeline.truth,
            start,
        }
    }

    fn matched_sequence(decision: &Decision) -> Option<u64> {
        decision.matched().map(|event| event.sequence)
    }

    fn chain_for(joined: &JoinedCapture, m6_sequence: u64) -> &Chain {
        joined
            .chains
            .iter()
            .find(|chain| chain.m6_sequence == m6_sequence)
            .expect("every M6 record yields a chain")
    }

    fn records_mut(input: &mut JoinInput) -> &mut Vec<Value> {
        input.layers.m6_vtl1.trace["records"]
            .as_array_mut()
            .unwrap()
    }

    fn transitions_mut(input: &mut JoinInput) -> &mut Vec<Value> {
        input.layers.m5_hypervisor.as_mut().unwrap().trace["transitions"]
            .as_array_mut()
            .unwrap()
    }

    fn calls_mut(input: &mut JoinInput) -> &mut Vec<Value> {
        input.layers.m4_vtl0.as_mut().unwrap().trace["calls"]
            .as_array_mut()
            .unwrap()
    }

    #[test]
    fn a_clean_point_capture_joins_every_selected_call_to_its_six_stages() {
        for seed in 1..=40 {
            let fixture = fixture(seed, 12, true);
            let joined = join(&fixture.input).unwrap();
            assert_eq!(
                joined.verdict,
                JoinVerdict::Complete,
                "seed {seed}: {:?}",
                joined.reasons
            );
            assert_eq!(joined.chains.len(), fixture.truth.len());
            for truth in &fixture.truth {
                let chain = chain_for(&joined, truth.m6_sequence);
                assert_eq!(
                    chain.verdict,
                    ChainVerdict::Complete,
                    "seed {seed}: {chain:#?}"
                );
                assert_eq!(
                    chain.call_id.as_deref(),
                    Some(format!("m7-join-test:call:{}", truth.m6_sequence).as_str())
                );
                assert_eq!(
                    matched_sequence(&chain.stages.m4_entry),
                    Some(truth.m4_sequence)
                );
                assert_eq!(
                    matched_sequence(&chain.stages.m5_vtl_call),
                    Some(truth.call_sequence)
                );
                assert_eq!(
                    matched_sequence(&chain.stages.m5_vtl_return),
                    Some(truth.return_sequence)
                );
                assert_eq!(chain.nested_round_trips, Some(truth.nested), "seed {seed}");
                assert_eq!(chain.round_trips_before_entry, Some(truth.before_entry));
                assert!(
                    chain
                        .cross_checks
                        .iter()
                        .all(|check| matches!(check.result, CrossCheckResult::Equal { .. }))
                );
            }
            assert!(
                joined.unmatched.is_empty(),
                "seed {seed}: {:?}",
                joined.unmatched
            );
            assert!(joined.ambiguous.is_empty());
            assert!(joined.marks.is_empty());
            assert_eq!(joined.first_stage.source, FirstStageSource::M4Vtl0Entry);
        }
    }

    #[test]
    fn missing_m5_breakpoints_keep_an_open_round_trip_ambiguous() {
        let fixture = fixture(9, 1, true);
        let truth = fixture.truth[0].clone();
        let mut open = fixture.input;
        transitions_mut(&mut open)
            .retain(|transition| transition["sequence"] != json!(truth.return_sequence));

        let clean = join(&open).unwrap();
        assert_eq!(
            matched_sequence(&chain_for(&clean, truth.m6_sequence).stages.m5_vtl_call),
            Some(truth.call_sequence),
            "a cleanly read open trip is bounded by the trace window"
        );

        open.layers.m5_hypervisor.as_mut().unwrap().trace["missing_breakpoints"] = json!(1);
        let joined = join(&open).unwrap();
        let summary = joined.layers.m5_hypervisor.as_ref().unwrap();
        assert_eq!(summary.missing_breakpoints, 1);
        assert!(!summary.complete_run());
        assert!(joined.marks.iter().any(|mark| {
            mark.layer == Some(Layer::M5Hypervisor) && mark.kind == MarkKind::MissingBreakpoints
        }));
        assert!(matches!(
            chain_for(&joined, truth.m6_sequence).stages.m5_vtl_call,
            Decision::Ambiguous { .. }
        ));
    }

    #[test]
    fn decisions_do_not_depend_on_arrival_order() {
        for seed in 1..=30 {
            let fixture = fixture(seed, 10, true);
            let reference = join(&fixture.input).unwrap();
            let mut shuffled = fixture.input.clone();
            let mut rng = Rng::new(seed * 7919);
            rng.shuffle(calls_mut(&mut shuffled));
            rng.shuffle(transitions_mut(&mut shuffled));
            rng.shuffle(records_mut(&mut shuffled));
            let permuted = join(&shuffled).unwrap();
            assert_eq!(reference.decisions(), permuted.decisions(), "seed {seed}");
            assert_eq!(reference.events, permuted.events);
            // The sources are the inputs as given, so they differ; nothing else may.
            assert_ne!(reference.sources, permuted.sources);
        }
    }

    #[test]
    fn a_capture_without_m4_is_provisional_and_names_what_the_first_stage_lacks() {
        let fixture = fixture(5, 10, false);
        let joined = join(&fixture.input).unwrap();
        assert_eq!(
            joined.verdict,
            JoinVerdict::Provisional,
            "{:?}",
            joined.reasons
        );
        assert_eq!(joined.first_stage.source, FirstStageSource::M6EntryCopy);
        let status = |field: &str| {
            joined
                .first_stage
                .fields
                .iter()
                .find(|row| row.field == field)
                .unwrap_or_else(|| panic!("row {field}"))
                .status
        };
        assert_eq!(status("service"), FieldStatus::Copied);
        assert_eq!(status("argument_block"), FieldStatus::Copied);
        assert_eq!(status("caller"), FieldStatus::Unavailable);
        assert_eq!(status("thread"), FieldStatus::Unavailable);
        assert_eq!(status("call_context"), FieldStatus::Unavailable);
        assert_eq!(status("process_id"), FieldStatus::CoordinatorEnvelope);
        assert_eq!(status("argument_block_pointer"), FieldStatus::Replaced);
        for truth in &fixture.truth {
            let chain = chain_for(&joined, truth.m6_sequence);
            assert_eq!(chain.verdict, ChainVerdict::Provisional, "{chain:#?}");
            assert!(chain.call_id.is_some());
            assert!(matches!(chain.stages.m4_entry, Decision::Unobserved { .. }));
            assert_eq!(
                matched_sequence(&chain.stages.m5_vtl_call),
                Some(truth.call_sequence)
            );
            assert_eq!(
                matched_sequence(&chain.stages.m5_vtl_return),
                Some(truth.return_sequence)
            );
            assert!(chain.cross_checks.is_empty());
        }
        // Without a workload process the envelope has nothing to offer either.
        let mut without = fixture.input.clone();
        without.workload_process_id = None;
        let joined = join(&without).unwrap();
        assert_eq!(
            joined
                .first_stage
                .fields
                .iter()
                .find(|row| row.field == "process_id")
                .unwrap()
                .status,
            FieldStatus::Unavailable
        );
        // With M4 every row is measured.
        let joined = join(&self::fixture(5, 10, true).input).unwrap();
        assert!(
            joined
                .first_stage
                .fields
                .iter()
                .all(|row| row.status == FieldStatus::Measured)
        );
    }

    #[test]
    fn a_capped_hypervisor_trace_leaves_later_chains_unmatched_rather_than_mismatched() {
        for seed in 1..=20 {
            let fixture = fixture(seed, 10, true);
            let reference = join(&fixture.input).unwrap();
            let mut capped = fixture.input.clone();
            let transitions = transitions_mut(&mut capped);
            let cut = transitions.len() / 2;
            transitions.truncate(cut);
            let trace = &mut capped.layers.m5_hypervisor.as_mut().unwrap().trace;
            trace["full"] = json!(true);
            trace["dropped"] = json!(3);
            let joined = join(&capped).unwrap();
            assert_eq!(joined.verdict, JoinVerdict::Incomplete);
            assert!(
                joined
                    .marks
                    .iter()
                    .any(|mark| mark.kind == MarkKind::CapacityReached
                        && mark.layer == Some(Layer::M5Hypervisor))
            );
            assert!(
                joined
                    .marks
                    .iter()
                    .any(|mark| mark.kind == MarkKind::DroppedRecords)
            );
            for truth in &fixture.truth {
                let chain = chain_for(&joined, truth.m6_sequence);
                let before = chain_for(&reference, truth.m6_sequence);
                // A stage the cut kept decides as before; a stage past the cut is never matched
                // to a transition that is still there.
                for (stage, decision) in chain.stages.each() {
                    let kept = before
                        .stages
                        .each()
                        .into_iter()
                        .find(|(other, _)| *other == stage)
                        .unwrap()
                        .1;
                    let (Stage::M5VtlCall | Stage::M5VtlReturn, Some(sequence)) =
                        (stage, matched_sequence(kept))
                    else {
                        continue;
                    };
                    if sequence < cut as u64 {
                        // Still recorded: the same match, or ambiguity that keeps it when the
                        // cut left a neighbouring round trip open. Never a different transition.
                        match decision {
                            Decision::Matched { event, .. } => {
                                assert_eq!(
                                    event.sequence, sequence,
                                    "seed {seed} m6 {} {stage:?}",
                                    truth.m6_sequence
                                )
                            }
                            Decision::Ambiguous { candidates, .. } => assert!(
                                candidates
                                    .sequence_ranges
                                    .iter()
                                    .any(|range| (range.first..=range.last).contains(&sequence)),
                                "seed {seed} m6 {} {stage:?}: {candidates:?} lost {sequence}",
                                truth.m6_sequence
                            ),
                            other => panic!(
                                "seed {seed} m6 {} {stage:?}: {other:?} where {sequence} is still recorded",
                                truth.m6_sequence
                            ),
                        }
                    } else {
                        assert!(
                            decision.matched().is_none(),
                            "seed {seed}: {stage:?} matched {decision:?} past the cut at {cut}"
                        );
                    }
                }
                if truth.return_sequence >= cut as u64 {
                    assert_eq!(chain.verdict, ChainVerdict::Incomplete);
                    assert!(chain.call_id.is_none());
                }
            }
        }
    }

    #[test]
    fn an_incomplete_vtl1_record_yields_no_call_id_and_leaves_its_neighbours_alone() {
        let fixture = fixture(9, 12, true);
        let reference = join(&fixture.input).unwrap();
        let victim = fixture.truth[fixture.truth.len() / 2].m6_sequence;
        let mut broken = fixture.input.clone();
        for record in records_mut(&mut broken) {
            if record["sequence"] == json!(victim) {
                record["returned"] = Value::Null;
                record["complete"] = json!(false);
                record["incomplete_reason"] = json!("stopped");
                record["last_phase"] = json!("dispatch");
            }
        }
        let joined = join(&broken).unwrap();
        assert_eq!(joined.verdict, JoinVerdict::Incomplete);
        let chain = chain_for(&joined, victim);
        assert_eq!(chain.verdict, ChainVerdict::Incomplete);
        assert!(chain.call_id.is_none());
        assert!(matches!(chain.stages.m6_return, Decision::Unmatched { .. }));
        assert!(matches!(
            chain.stages.m5_vtl_return,
            Decision::Unmatched { .. }
        ));
        assert!(
            joined.marks.iter().any(
                |mark| mark.kind == MarkKind::IncompleteRecord && mark.sequence == Some(victim)
            )
        );
        for truth in &fixture.truth {
            if truth.m6_sequence == victim {
                continue;
            }
            assert_eq!(
                chain_for(&joined, truth.m6_sequence).stages,
                chain_for(&reference, truth.m6_sequence).stages,
                "m6 {}",
                truth.m6_sequence
            );
        }
        // The victim's own VTL0 entry is now claimed by nobody and says so.
        assert!(joined.unmatched.iter().any(|entry| {
            entry.stage == Some(Stage::M4Entry)
                && entry.event.as_ref().map(|event| event.sequence)
                    == Some(
                        fixture
                            .truth
                            .iter()
                            .find(|t| t.m6_sequence == victim)
                            .unwrap()
                            .m4_sequence,
                    )
        }));
    }

    #[test]
    fn a_return_with_no_call_before_it_is_marked_and_changes_no_decision() {
        let fixture = fixture(3, 8, true);
        let reference = join(&fixture.input).unwrap();
        let mut stray = fixture.input.clone();
        let transitions = transitions_mut(&mut stray);
        for transition in transitions.iter_mut() {
            transition["sequence"] = json!(transition["sequence"].as_u64().unwrap() + 1);
        }
        transitions.insert(
            0,
            json!({
                "sequence": 0,
                "host_qpc": {"tick": fixture.start - 100, "frequency": FREQUENCY},
                "host_monotonic_us": 1, "host_elapsed_us": 1,
                "kind": "vtl_return", "vp_index": 3, "source_vtl": 1, "target_vtl": 0,
                "provenance": {"read_failures": []}
            }),
        );
        let joined = join(&stray).unwrap();
        assert!(
            joined
                .marks
                .iter()
                .any(|mark| mark.kind == MarkKind::UnmatchedReturn && mark.sequence == Some(0))
        );
        assert!(joined.unmatched.iter().any(|entry| {
            entry.stage == Some(Stage::M5VtlReturn)
                && entry.event.as_ref().map(|event| event.sequence) == Some(0)
        }));
        assert_eq!(joined.verdict, JoinVerdict::Incomplete);
        for truth in &fixture.truth {
            let chain = chain_for(&joined, truth.m6_sequence);
            let before = chain_for(&reference, truth.m6_sequence);
            assert_eq!(chain.verdict, ChainVerdict::Complete);
            assert_eq!(
                matched_sequence(&chain.stages.m5_vtl_call),
                matched_sequence(&before.stages.m5_vtl_call).map(|sequence| sequence + 1)
            );
            assert_eq!(
                matched_sequence(&chain.stages.m5_vtl_return),
                matched_sequence(&before.stages.m5_vtl_return).map(|sequence| sequence + 1)
            );
            assert_eq!(chain.stages.m4_entry, before.stages.m4_entry);
        }
    }

    #[test]
    fn an_equal_tick_is_ambiguous_and_the_nearer_candidate_is_not_chosen() {
        let fixture = fixture(11, 10, true);
        let truth = fixture.truth.last().unwrap().clone();
        let mut equal = fixture.input.clone();
        let entry_tick = records_mut(&mut equal)
            .iter()
            .find(|record| record["sequence"] == json!(truth.m6_sequence))
            .unwrap()["entry"]["site"]["host_qpc"]["tick"]
            .as_u64()
            .unwrap();
        for call in calls_mut(&mut equal) {
            if call["sequence"] == json!(truth.m4_sequence) {
                call["host_qpc"]["tick"] = json!(entry_tick);
            }
        }
        let joined = join(&equal).unwrap();
        let chain = chain_for(&joined, truth.m6_sequence);
        match &chain.stages.m4_entry {
            Decision::Ambiguous { candidates, .. } => {
                assert_eq!(candidates.count, 1);
                assert_eq!(candidates.sequence_ranges[0].first, truth.m4_sequence);
            }
            other => panic!("an equal tick must not decide: {other:?}"),
        }
        assert_eq!(chain.verdict, ChainVerdict::Incomplete);
        assert!(chain.call_id.is_none());
        assert!(
            joined
                .ambiguous
                .iter()
                .any(|entry| entry.m6_sequence == truth.m6_sequence)
        );

        // Two selected VTL0 entries before one VTL1 entry, with the record between them gone:
        // both stay, neither is picked for being nearer. The record removed is an interior one,
        // so the run also shows the gap; a missing first record would read as a shorter run.
        let fixture = self::fixture(13, 14, true);
        assert!(fixture.truth.len() >= 3);
        let (first, second) = (fixture.truth[1].clone(), fixture.truth[2].clone());
        let mut hole = fixture.input.clone();
        records_mut(&mut hole).retain(|record| record["sequence"] != json!(first.m6_sequence));
        hole.expected_selected_calls = Some(fixture.truth.len() as u64 - 1);
        let joined = join(&hole).unwrap();
        let chain = chain_for(&joined, second.m6_sequence);
        match &chain.stages.m4_entry {
            Decision::Ambiguous { candidates, .. } => {
                assert_eq!(candidates.count, 2);
                let listed: Vec<u64> = candidates
                    .sequence_ranges
                    .iter()
                    .flat_map(|range| range.first..=range.last)
                    .collect();
                assert!(listed.contains(&first.m4_sequence));
                assert!(listed.contains(&second.m4_sequence));
            }
            other => panic!("two candidates must stay two: {other:?}"),
        }
        // The hole is a sequence gap and is marked as one.
        assert!(joined
            .marks
            .iter()
            .any(|mark| mark.kind == MarkKind::SequenceGap && mark.layer == Some(Layer::M6Vtl1)));
    }

    #[test]
    fn unclassified_m4_hits_remain_candidates_but_never_become_unique_matches() {
        let base = fixture(31, 8, true);
        let truth = base.truth.last().unwrap().clone();
        let mut alongside = base.input.clone();
        let unknown_sequence = {
            let calls = calls_mut(&mut alongside);
            let mut unknown = calls
                .iter()
                .find(|call| call["sequence"] == json!(truth.m4_sequence))
                .unwrap()
                .clone();
            let sequence = calls
                .iter()
                .filter_map(|call| call["sequence"].as_u64())
                .max()
                .unwrap()
                + 1;
            unknown["sequence"] = json!(sequence);
            unknown["transition_kind"] = Value::Null;
            unknown["service"] = Value::Null;
            unknown["provenance"]["read_failures"] = json!(["transition_kind", "service"]);
            calls.push(unknown);
            sequence
        };
        alongside.layers.m4_vtl0.as_mut().unwrap().trace["unreadable_hits"] = json!(1);

        let joined = join(&alongside).unwrap();
        let chain = chain_for(&joined, truth.m6_sequence);
        match &chain.stages.m4_entry {
            Decision::Ambiguous { candidates, reason } => {
                assert_eq!(candidates.count, 2);
                let listed: Vec<u64> = candidates
                    .sequence_ranges
                    .iter()
                    .flat_map(|range| range.first..=range.last)
                    .collect();
                assert!(listed.contains(&truth.m4_sequence));
                assert!(listed.contains(&unknown_sequence));
                assert!(reason.contains("unreadable classification"), "{reason}");
            }
            other => panic!("an unclassified time-compatible hit must stay ambiguous: {other:?}"),
        }

        let mut unknown_only = fixture(9, 1, true).input;
        let only_sequence = calls_mut(&mut unknown_only)[0]["sequence"]
            .as_u64()
            .unwrap();
        calls_mut(&mut unknown_only)[0]["service"] = Value::Null;
        let point = join(&unknown_only).unwrap();
        assert!(matches!(
            &point.chains[0].stages.m4_entry,
            Decision::Ambiguous { candidates, .. }
                if candidates.count == 1
                    && candidates.sequence_ranges[0].first == only_sequence
        ));

        unknown_only.clock.mode = ClockMode::IntervalOnly;
        unknown_only.clock.frequency = None;
        let m4 = unknown_only.layers.m4_vtl0.as_mut().unwrap();
        m4.arm = Some(bracket(Layer::M4Vtl0, "arm", base.start - 400, FREQUENCY));
        let end = m4.drain.as_ref().unwrap().coordinator_after.tick;
        m4.drain = Some(bracket(Layer::M4Vtl0, "drain", end - 200, FREQUENCY));
        let interval = join(&unknown_only).unwrap();
        match &interval.chains[0].stages.m4_entry {
            Decision::Ambiguous { candidates, reason } => {
                assert_eq!(candidates.count, 1);
                assert!(reason.contains("rank matching is not proved"), "{reason}");
            }
            other => panic!("an unclassified hit must not be rank-matched: {other:?}"),
        }
    }

    #[test]
    fn interval_only_clocks_match_by_rank_only_under_containment_and_equal_counts() {
        let fixture = fixture(21, 10, true);
        let mut interval = fixture.input.clone();
        // A worker sample off the common frequency degrades the capture to intervals, as M6's
        // K3 clock does in the nested lab.
        let m6 = &mut interval.layers.m6_vtl1;
        m6.arm = Some(bracket(
            Layer::M6Vtl1,
            "arm",
            fixture.start - 500,
            1_000_000,
        ));
        let brackets = vec![
            m6.arm.clone().unwrap(),
            interval
                .layers
                .m4_vtl0
                .as_ref()
                .unwrap()
                .arm
                .clone()
                .unwrap(),
            interval
                .layers
                .m5_hypervisor
                .as_ref()
                .unwrap()
                .arm
                .clone()
                .unwrap(),
            interval
                .layers
                .m5_hypervisor
                .as_ref()
                .unwrap()
                .drain
                .clone()
                .unwrap(),
            interval
                .layers
                .m4_vtl0
                .as_ref()
                .unwrap()
                .drain
                .clone()
                .unwrap(),
            m6.drain.clone().unwrap(),
        ];
        interval.clock = admit_clock(brackets, 1_000).unwrap();
        assert_eq!(interval.clock.mode, ClockMode::IntervalOnly);

        // M6 certainly recording throughout M4's outer window: rank pairing.
        let m4 = interval.layers.m4_vtl0.as_mut().unwrap();
        m4.arm = Some(bracket(
            Layer::M4Vtl0,
            "arm",
            fixture.start - 400,
            FREQUENCY,
        ));
        let end = m4.drain.as_ref().unwrap().coordinator_after.tick;
        m4.drain = Some(bracket(Layer::M4Vtl0, "drain", end - 200, FREQUENCY));
        let joined = join(&interval).unwrap();
        assert_eq!(
            joined
                .windows
                .iter()
                .find(|pair| pair.first == Layer::M4Vtl0 && pair.second == Layer::M6Vtl1)
                .unwrap()
                .relation,
            WindowRelation::ContainedBy
        );
        for truth in &fixture.truth {
            let chain = chain_for(&joined, truth.m6_sequence);
            assert_eq!(
                matched_sequence(&chain.stages.m4_entry),
                Some(truth.m4_sequence),
                "{chain:#?}"
            );
            match &chain.stages.m4_entry {
                Decision::Matched { rule, .. } => assert!(rule.starts_with("rank:")),
                other => panic!("{other:?}"),
            }
            // M5 against M6 has no point order and no containment argument: every round trip
            // stays a candidate, and the chain is not complete.
            assert!(matches!(
                chain.stages.m5_vtl_call,
                Decision::Ambiguous { .. }
            ));
            assert!(matches!(
                chain.stages.m5_vtl_return,
                Decision::Ambiguous { .. }
            ));
            assert_eq!(chain.verdict, ChainVerdict::Incomplete);
        }
        assert_eq!(joined.verdict, JoinVerdict::Incomplete);

        // One selected call fewer in M4 than in M6: a range of two per record, never a pick.
        let mut fewer = interval.clone();
        let drop = fixture.truth[0].m4_sequence;
        calls_mut(&mut fewer).retain(|call| call["sequence"] != json!(drop));
        for call in calls_mut(&mut fewer) {
            let sequence = call["sequence"].as_u64().unwrap();
            if sequence > drop {
                call["sequence"] = json!(sequence - 1);
            }
        }
        let joined = join(&fewer).unwrap();
        for chain in &joined.chains {
            match &chain.stages.m4_entry {
                Decision::Ambiguous { candidates, .. } => {
                    assert!(candidates.count <= 2 && candidates.count >= 1)
                }
                other => panic!("{other:?}"),
            }
        }

        // M4 capped: no rank argument at all.
        let mut capped = interval.clone();
        capped.layers.m4_vtl0.as_mut().unwrap().trace["full"] = json!(true);
        let joined = join(&capped).unwrap();
        for chain in &joined.chains {
            assert!(matches!(chain.stages.m4_entry, Decision::Ambiguous { .. }));
        }

        // A missing M4 breakpoint makes the retained events a prefix, not a complete run, even
        // when its sequences and recording window otherwise support rank pairing.
        let mut missing = interval.clone();
        missing.layers.m4_vtl0.as_mut().unwrap().trace["missing_breakpoint"] = json!(true);
        let joined = join(&missing).unwrap();
        let summary = joined.layers.m4_vtl0.as_ref().unwrap();
        assert_eq!(summary.missing_breakpoints, 1);
        assert!(!summary.complete_run());
        assert!(joined.marks.iter().any(|mark| {
            mark.layer == Some(Layer::M4Vtl0) && mark.kind == MarkKind::MissingBreakpoints
        }));
        for chain in &joined.chains {
            assert!(matches!(chain.stages.m4_entry, Decision::Ambiguous { .. }));
        }

        // Disjoint windows, as the alternating plan produces: unmatched, not ambiguous.
        let mut disjoint = interval.clone();
        let m4 = disjoint.layers.m4_vtl0.as_mut().unwrap();
        let m6_end = disjoint
            .layers
            .m6_vtl1
            .drain
            .as_ref()
            .unwrap()
            .coordinator_after
            .tick;
        m4.arm = Some(bracket(Layer::M4Vtl0, "arm", m6_end + 100, FREQUENCY));
        m4.drain = Some(bracket(Layer::M4Vtl0, "drain", m6_end + 1_000, FREQUENCY));
        let joined = join(&disjoint).unwrap();
        for chain in &joined.chains {
            assert!(
                matches!(chain.stages.m4_entry, Decision::Unmatched { .. }),
                "{chain:#?}"
            );
        }
        assert!(
            joined
                .unmatched
                .iter()
                .any(|entry| entry.stage == Some(Stage::M4Entry) && entry.event.is_some())
        );
    }

    #[test]
    fn a_differing_cross_check_refuses_the_chain() {
        let fixture = fixture(17, 8, true);
        let truth = fixture.truth[0].clone();
        let mut differs = fixture.input.clone();
        for call in calls_mut(&mut differs) {
            if call["sequence"] == json!(truth.m4_sequence) {
                let mut block = call["argument_block"].as_str().unwrap().to_string();
                block.replace_range(20..22, "ff");
                call["argument_block"] = json!(block);
            }
        }
        let joined = join(&differs).unwrap();
        let chain = chain_for(&joined, truth.m6_sequence);
        assert_eq!(chain.verdict, ChainVerdict::Incomplete);
        assert!(chain.cross_checks.iter().any(|check| {
            check.field == "argument_block[8..64]"
                && matches!(check.result, CrossCheckResult::Differs { .. })
        }));
        assert_eq!(
            joined
                .cross_check_summary
                .iter()
                .find(|summary| summary.field == "argument_block[8..64]")
                .unwrap()
                .differs,
            1
        );
    }

    #[test]
    fn the_expected_call_count_is_a_reason_never_a_correction() {
        let fixture = fixture(2, 6, true);
        let mut short = fixture.input.clone();
        short.expected_selected_calls = Some(fixture.truth.len() as u64 + 1);
        let joined = join(&short).unwrap();
        assert_eq!(joined.verdict, JoinVerdict::Incomplete);
        assert_eq!(joined.chains.len(), fixture.truth.len());
        assert!(
            joined
                .marks
                .iter()
                .any(|mark| mark.kind == MarkKind::CountMismatch)
        );
        // Nothing captured is nothing joined, not a vacuous pass: the idle gate's runs read
        // zero records and must not come back complete.
        let mut idle = fixture.input.clone();
        idle.expected_selected_calls = None;
        records_mut(&mut idle).clear();
        let joined = join(&idle).unwrap();
        assert_eq!(joined.verdict, JoinVerdict::Incomplete);
        assert!(joined.chains.is_empty());
        assert!(
            joined
                .reasons
                .iter()
                .any(|reason| reason.contains("nothing to join"))
        );
    }

    #[test]
    fn the_table_is_a_projection_of_the_json() {
        let fixture = fixture(4, 9, true);
        let joined = join(&fixture.input).unwrap();
        let text = serde_json::to_string(&joined).unwrap();
        let reparsed: JoinedCapture = serde_json::from_str(&text).unwrap();
        // Private working fields are skipped on the wire, so the comparison is of the record.
        assert_eq!(serde_json::to_string(&reparsed).unwrap(), text);
        assert_eq!(render_table(&reparsed, 3), render_table(&joined, 3));
        let table = render_table(&joined, 3);
        assert!(table.contains("M7.2 join m7-join-test"));
        assert!(
            table.contains(&format!(
                "... {} more chains",
                joined.chains.len().saturating_sub(3)
            )) || joined.chains.len() <= 3
        );
        assert!(table.contains("m7-join-test:call:"));
        // The join is a function of its input.
        assert_eq!(join(&fixture.input).unwrap(), joined);
    }

    #[test]
    fn input_that_cannot_be_joined_is_an_error_rather_than_a_verdict() {
        let fixture = fixture(1, 4, true);
        let mut wrong_schema = fixture.input.clone();
        wrong_schema.schema = "windbg-mcp.sk-correlation-join-input.v0".into();
        assert!(join(&wrong_schema).is_err());
        let mut wrong_service = fixture.input.clone();
        wrong_service.selected_service = 45;
        assert!(join(&wrong_service).is_err());
        let mut not_a_trace = fixture.input.clone();
        not_a_trace.layers.m6_vtl1.trace = json!({"records": "none"});
        assert!(join(&not_a_trace).is_err());
        let mut bad_identity = fixture.input.clone();
        bad_identity.identity.processor_count = 2;
        assert!(join(&bad_identity).is_err());
    }

    #[test]
    fn candidate_ranges_compress_contiguous_sequences_losslessly() {
        let candidates = Candidates::new(Stage::M5VtlCall, [9, 3, 4, 5, 1, 7, 7]);
        assert_eq!(candidates.count, 6);
        assert_eq!(
            candidates.sequence_ranges,
            vec![
                SequenceRange { first: 1, last: 1 },
                SequenceRange { first: 3, last: 5 },
                SequenceRange { first: 7, last: 7 },
                SequenceRange { first: 9, last: 9 },
            ]
        );
        assert_eq!(candidates.layer, Layer::M5Hypervisor);
    }

    #[test]
    fn windows_relate_conservatively() {
        let window = |outer_from, certain_from, certain_to, outer_to| Window {
            frequency: FREQUENCY,
            outer_from,
            certain_from,
            certain_to,
            outer_to,
        };
        let wide = window(0, 10, 90, 100);
        let inside = window(20, 25, 70, 80);
        assert_eq!(wide.relation(&inside), WindowRelation::Contains);
        assert_eq!(inside.relation(&wide), WindowRelation::ContainedBy);
        // Touching outer spans are not disjoint: an instant may lie in both.
        assert_eq!(
            window(0, 1, 2, 50).relation(&window(50, 51, 60, 70)),
            WindowRelation::Overlap
        );
        assert_eq!(
            window(0, 1, 2, 49).relation(&window(50, 51, 60, 70)),
            WindowRelation::Disjoint
        );
        // Containment needs the certain span, not the outer one.
        assert_eq!(
            window(0, 30, 60, 100).relation(&inside),
            WindowRelation::Overlap
        );
        // An empty certain span contains nothing.
        assert_eq!(
            window(0, 60, 40, 100).relation(&inside),
            WindowRelation::Overlap
        );
        let mut other = inside;
        other.frequency = 1;
        assert_eq!(wide.relation(&other), WindowRelation::Unknown);
    }
}
