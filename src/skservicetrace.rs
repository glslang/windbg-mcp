//! Versioned records and bounded recorder for the M6 Secure Kernel service trace.
//!
//! This module is deliberately engine-free. The live loop added by M6.2 owns the controller on
//! the existing `secure_kernel_live` worker's engine thread; it feeds already-validated phase
//! observations into this state machine. A concurrent read can therefore clone only
//! [`Recorder::completed_prefix`] and its counters without reaching DbgEng, a provider, or a
//! mutable in-flight record.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use crate::skcontrol::{HexU64, RegisterName, StopEpoch, StopReason, TargetIdentity};
use crate::sklive::StopRecord;
use crate::skservice::{ImageIdentity, ServiceManifest};

pub(crate) const ARMED_SCHEMA: &str = "windbg-mcp.sk-service-trace-armed.v1";
pub(crate) const TRACE_SCHEMA: &str = "windbg-mcp.sk-service-trace.v1";
pub(crate) const RECORD_SCHEMA: &str = "windbg-mcp.sk-service-call.v1";
pub(crate) const MAX_RECORDS: u32 = 1_024;
pub(crate) const MAX_BUFFER_BYTES: u32 = 4_096;
pub(crate) const MAX_CAPTURE_BYTES: u32 = 8 * 1_024 * 1_024;
const PAGE_BYTES: u64 = 4_096;
/// Generic dispatcher entries are private candidates until the selected handler site proves one.
/// Bound them independently of the public record budget so ambient traffic cannot grow the job.
const MAX_ENTRY_CANDIDATES: usize = 1_024;

#[cfg(test)]
pub(crate) const ARM_TOOL_DESCRIPTION: &str = "Trace one manifest-pinned Secure Kernel service on an existing secure_kernel_live session. Verifies the exact image, complete instruction guards and all three hardware slots before starting the worker-owned bounded job. The label is copied into every record; limits bound records, each buffer and total captured bytes.";
#[cfg(test)]
pub(crate) const READ_TOOL_DESCRIPTION: &str = "Read an immutable completed prefix from a Secure Kernel service trace. Without stop this touches no engine or provider. With stop it binds to the exact trace job, wakes only its scoped wait, restores the complete debug-register baseline on the engine thread, and returns after restoration.";

/// Drafted before the public tool is registered, so its model-visible cost and refusal rules are
/// reviewable independently of the M6.2 run loop.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraceArgs {
    /// Exact retained epoch for the currently held live-control stop.
    pub(crate) epoch: StopEpoch,
    /// Workload label copied into every record (1-128 UTF-8 bytes).
    #[serde(default)]
    pub(crate) label: Option<String>,
    /// Complete or incomplete selected-service records to retain (default 64, maximum 1024).
    #[serde(default)]
    pub(crate) max_calls: Option<u32>,
    /// Bytes retained from each manifest buffer (default 64, range 0-4096).
    #[serde(default)]
    pub(crate) per_buffer_bytes: Option<u32>,
    /// Bytes retained across all records (default 524288, maximum 8388608).
    #[serde(default)]
    pub(crate) total_capture_bytes: Option<u32>,
    /// A session opened by open_secure_kernel_live.
    #[serde(default)]
    pub(crate) session_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraceReadArgs {
    /// Trace id returned when the service trace was armed; stale or replaced ids are refused.
    pub(crate) trace_id: String,
    /// Stop this exact trace and wait for engine-thread restoration before returning.
    #[serde(default)]
    pub(crate) stop: Option<bool>,
    /// The secure_kernel_live session holding the trace.
    #[serde(default)]
    pub(crate) session_id: Option<String>,
}

impl TraceArgs {
    pub(crate) fn checked(&self) -> Result<(Option<String>, TraceLimits), String> {
        if self
            .label
            .as_ref()
            .is_some_and(|label| label.is_empty() || label.len() > 128)
        {
            return Err("trace label must contain 1 through 128 UTF-8 bytes".into());
        }
        let limits = TraceLimits::checked(
            self.max_calls.unwrap_or(64),
            self.per_buffer_bytes.unwrap_or(64),
            self.total_capture_bytes.unwrap_or(512 * 1_024),
        )?;
        Ok((self.label.clone(), limits))
    }
}

impl TraceReadArgs {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.trace_id.len() < 16
            || self.trace_id.len() > 128
            || !self.trace_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err("trace_id must contain 16 through 128 visible ASCII bytes".into());
        }
        Ok(())
    }
}

/// Caller-selected bounds, validated before a live guard or debug register is touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraceLimits {
    pub(crate) records: u32,
    pub(crate) per_buffer_bytes: u32,
    pub(crate) total_capture_bytes: u32,
}

impl TraceLimits {
    pub(crate) fn checked(
        records: u32,
        per_buffer_bytes: u32,
        total_capture_bytes: u32,
    ) -> Result<Self, String> {
        if records == 0 || records > MAX_RECORDS {
            return Err(format!("record limit must be in 1..={MAX_RECORDS}"));
        }
        if per_buffer_bytes > MAX_BUFFER_BYTES {
            return Err(format!(
                "per-buffer limit must be in 0..={MAX_BUFFER_BYTES}"
            ));
        }
        if total_capture_bytes > MAX_CAPTURE_BYTES {
            return Err(format!(
                "total capture limit must be in 0..={MAX_CAPTURE_BYTES}"
            ));
        }
        Ok(Self {
            records,
            per_buffer_bytes,
            total_capture_bytes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CodeCoordinate {
    pub(crate) address: HexU64,
    pub(crate) rva: u32,
    pub(crate) symbol: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhaseSite {
    pub(crate) epoch: StopEpoch,
    pub(crate) host_monotonic_us: u64,
    pub(crate) host_elapsed_us: u64,
    pub(crate) coordinate: CodeCoordinate,
}

/// Stable field paths partitioned by how their values were obtained.
///
/// A field must occur in exactly one list. The first selected service admits no inferred value;
/// its list is retained (and required to be empty) so a later schema cannot silently introduce
/// one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Provenance {
    pub(crate) measured: Vec<String>,
    pub(crate) exact_build_layout_derived: Vec<String>,
    pub(crate) inferred: Vec<String>,
    pub(crate) unavailable: Vec<ReadFailure>,
}

impl Provenance {
    fn unreadable_fields(&self) -> u64 {
        self.unavailable.len() as u64
    }

    fn validate(&self) -> Result<(), String> {
        if !self.inferred.is_empty() {
            return Err("the first M6 service does not permit inferred values".into());
        }
        let mut names = std::collections::HashSet::new();
        for name in self
            .measured
            .iter()
            .chain(&self.exact_build_layout_derived)
            .chain(self.unavailable.iter().map(|failure| &failure.field))
        {
            if name.is_empty() || !names.insert(name) {
                return Err("provenance field paths must be nonempty and disjoint".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadFailure {
    pub(crate) field: String,
    pub(crate) message: String,
}

/// A whole bounded read, or one named reason no bytes from it were retained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BufferState {
    Measured {
        /// Uppercase hexadecimal bytes with no separators.
        data: String,
    },
    Unavailable {
        failure: ReadFailure,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BufferCapture {
    pub(crate) name: String,
    pub(crate) address: HexU64,
    /// The manifest-defined extent before the caller's cap is applied.
    pub(crate) available_size: u32,
    /// Bytes requested after the per-buffer cap. Zero is a valid deliberate capture.
    pub(crate) requested_size: u32,
    pub(crate) bytes: BufferState,
}

impl BufferCapture {
    fn captured_bytes(&self) -> u64 {
        match &self.bytes {
            BufferState::Measured { data } => (data.len() / 2) as u64,
            BufferState::Unavailable { .. } => 0,
        }
    }

    fn unreadable_fields(&self) -> u64 {
        u64::from(matches!(self.bytes, BufferState::Unavailable { .. }))
    }

    fn validate(&self, limit: u32) -> Result<(), String> {
        if self.name.is_empty()
            || self.requested_size > self.available_size
            || self.requested_size > limit
        {
            return Err("buffer name or size exceeds its declared bound".into());
        }
        match &self.bytes {
            BufferState::Measured { data } => {
                if data.len() != self.requested_size as usize * 2
                    || !data.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err("measured buffer is not one complete hexadecimal read".into());
                }
            }
            BufferState::Unavailable { failure } => {
                if failure.field.is_empty() || failure.message.is_empty() {
                    return Err("unavailable buffer needs a named failure".into());
                }
            }
        }
        Ok(())
    }
}

/// Read a bounded capture page by page. A short page or any error discards the partial prefix.
pub(crate) fn capture_buffer<F>(
    name: impl Into<String>,
    address: u64,
    available_size: u32,
    limit: u32,
    mut read: F,
) -> Result<BufferCapture, String>
where
    F: FnMut(u64, u32) -> Result<Vec<u8>, String>,
{
    if limit > MAX_BUFFER_BYTES {
        return Err(format!("per-buffer limit exceeds {MAX_BUFFER_BYTES}"));
    }
    let name = name.into();
    if name.is_empty() {
        return Err("buffer name must not be empty".into());
    }
    let requested_size = available_size.min(limit);
    address
        .checked_add(u64::from(requested_size))
        .ok_or_else(|| "buffer capture crosses the address-space limit".to_string())?;

    let mut bytes = Vec::with_capacity(requested_size as usize);
    let mut cursor = address;
    while bytes.len() < requested_size as usize {
        let page_left = PAGE_BYTES - cursor % PAGE_BYTES;
        let remaining = requested_size as usize - bytes.len();
        let count = remaining.min(page_left as usize) as u32;
        let chunk = match read(cursor, count) {
            Ok(chunk) => chunk,
            Err(message) => {
                return Ok(BufferCapture {
                    name: name.clone(),
                    address: HexU64(address),
                    available_size,
                    requested_size,
                    bytes: BufferState::Unavailable {
                        failure: ReadFailure {
                            field: name,
                            message,
                        },
                    },
                });
            }
        };
        if chunk.len() != count as usize {
            return Ok(BufferCapture {
                name: name.clone(),
                address: HexU64(address),
                available_size,
                requested_size,
                bytes: BufferState::Unavailable {
                    failure: ReadFailure {
                        field: name,
                        message: format!(
                            "short read at {cursor:#x}: requested {count}, received {}",
                            chunk.len()
                        ),
                    },
                },
            });
        }
        bytes.extend(chunk);
        cursor += u64::from(count);
    }

    Ok(BufferCapture {
        name,
        address: HexU64(address),
        available_size,
        requested_size,
        bytes: BufferState::Measured {
            data: bytes.iter().map(|byte| format!("{byte:02X}")).collect(),
        },
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawArguments {
    pub(crate) rcx: HexU64,
    pub(crate) rdx: HexU64,
    pub(crate) r8: HexU64,
    pub(crate) r9: HexU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayoutValue {
    pub(crate) name: String,
    pub(crate) offset: u32,
    pub(crate) width: u8,
    pub(crate) value: HexU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EntryPhase {
    pub(crate) site: PhaseSite,
    /// The measured dispatch field, associated back to this entry only after the selected dispatch
    /// is observed.
    pub(crate) service: u16,
    pub(crate) caller: Option<CodeCoordinate>,
    pub(crate) raw_arguments: RawArguments,
    pub(crate) provenance: Provenance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispatchPhase {
    pub(crate) site: PhaseSite,
    pub(crate) handler: CodeCoordinate,
    pub(crate) request: HexU64,
    pub(crate) fields: Vec<LayoutValue>,
    pub(crate) buffers_before: Vec<BufferCapture>,
    pub(crate) provenance: Provenance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReturnPhase {
    pub(crate) site: PhaseSite,
    pub(crate) status: u32,
    pub(crate) buffers_after: Vec<BufferCapture>,
    pub(crate) provenance: Provenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ServicePhase {
    Entry,
    Dispatch,
    Return,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IncompleteReason {
    NestedEntry,
    RepeatedDispatch,
    MissingEntry,
    MissingDispatch,
    UnexpectedReturn,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceCallRecord {
    pub(crate) schema: String,
    pub(crate) trace_id: String,
    pub(crate) label: Option<String>,
    pub(crate) sequence: u64,
    pub(crate) manifest_id: String,
    pub(crate) target: TargetIdentity,
    pub(crate) image: ImageIdentity,
    pub(crate) image_base: HexU64,
    pub(crate) cr3: HexU64,
    pub(crate) last_phase: ServicePhase,
    pub(crate) complete: bool,
    pub(crate) incomplete_reason: Option<IncompleteReason>,
    pub(crate) entry: Option<EntryPhase>,
    pub(crate) dispatch: Option<DispatchPhase>,
    pub(crate) returned: Option<ReturnPhase>,
}

impl ServiceCallRecord {
    fn captured_bytes(&self) -> u64 {
        self.dispatch
            .iter()
            .flat_map(|phase| &phase.buffers_before)
            .chain(self.returned.iter().flat_map(|phase| &phase.buffers_after))
            .map(BufferCapture::captured_bytes)
            .sum()
    }

    fn unreadable_fields(&self) -> u64 {
        let phase = self
            .entry
            .iter()
            .map(|phase| phase.provenance.unreadable_fields())
            .chain(
                self.dispatch
                    .iter()
                    .map(|phase| phase.provenance.unreadable_fields()),
            )
            .chain(
                self.returned
                    .iter()
                    .map(|phase| phase.provenance.unreadable_fields()),
            )
            .sum::<u64>();
        let buffers = self
            .dispatch
            .iter()
            .flat_map(|phase| &phase.buffers_before)
            .chain(self.returned.iter().flat_map(|phase| &phase.buffers_after))
            .map(BufferCapture::unreadable_fields)
            .sum::<u64>();
        phase + buffers
    }

    fn validate(&self, manifest: &ServiceManifest, limits: TraceLimits) -> Result<(), String> {
        if self.schema != RECORD_SCHEMA
            || self.trace_id.is_empty()
            || self.manifest_id.is_empty()
            || self.image_base.0 == 0
            || self.cr3.0 == 0
            || self.cr3.0 & 0xfff != 0
        {
            return Err("service record identity is incomplete".into());
        }
        if self.complete
            != (self.entry.is_some() && self.dispatch.is_some() && self.returned.is_some())
            || self.complete == self.incomplete_reason.is_some()
        {
            return Err("service record completion fields disagree".into());
        }
        if self
            .entry
            .as_ref()
            .is_some_and(|phase| u32::from(phase.service) != manifest.service.number)
        {
            return Err("record carries a service other than the selected service".into());
        }
        let expected_last = if self.returned.is_some() {
            ServicePhase::Return
        } else if self.dispatch.is_some() {
            ServicePhase::Dispatch
        } else {
            ServicePhase::Entry
        };
        if self.last_phase != expected_last {
            return Err("record last_phase does not name its last observation".into());
        }
        let times = [
            self.entry
                .as_ref()
                .map(|phase| phase.site.host_monotonic_us),
            self.dispatch
                .as_ref()
                .map(|phase| phase.site.host_monotonic_us),
            self.returned
                .as_ref()
                .map(|phase| phase.site.host_monotonic_us),
        ];
        if times
            .into_iter()
            .flatten()
            .try_fold(None, |previous, next| match previous {
                Some(previous) if next < previous => Err(()),
                _ => Ok(Some(next)),
            })
            .is_err()
        {
            return Err("service phases are not in monotonic observation order".into());
        }
        if let Some(dispatch) = &self.dispatch {
            if dispatch.handler.rva != manifest.service.handler_rva
                || dispatch.handler.address.0
                    != self.image_base.0 + u64::from(manifest.service.handler_rva)
            {
                return Err("dispatch handler does not match the manifest".into());
            }
            if dispatch.fields.len() != manifest.request_layout.fields.len() {
                return Err("dispatch does not carry the complete checked request layout".into());
            }
            for (value, field) in dispatch.fields.iter().zip(&manifest.request_layout.fields) {
                if value.name != field.name
                    || value.offset != field.offset
                    || u32::from(value.width) != field.width
                    || (field.width < 8 && value.value.0 >= 1_u64 << (field.width * 8))
                {
                    return Err(format!(
                        "dispatch field {} does not match its checked layout",
                        field.name
                    ));
                }
            }
            let service = dispatch
                .fields
                .iter()
                .find(|field| field.name == "service_number")
                .ok_or_else(|| "dispatch omitted service_number".to_string())?;
            if service.value.0 != u64::from(manifest.service.number) {
                return Err("dispatch service_number is not the selected service".into());
            }
        }
        for provenance in self
            .entry
            .iter()
            .map(|phase| &phase.provenance)
            .chain(self.dispatch.iter().map(|phase| &phase.provenance))
            .chain(self.returned.iter().map(|phase| &phase.provenance))
        {
            provenance.validate()?;
        }
        for buffer in self
            .dispatch
            .iter()
            .flat_map(|phase| &phase.buffers_before)
            .chain(self.returned.iter().flat_map(|phase| &phase.buffers_after))
        {
            buffer.validate(limits.per_buffer_bytes)?;
        }
        self.validate_capture_set(manifest, true)?;
        self.validate_capture_set(manifest, false)?;
        Ok(())
    }

    fn validate_capture_set(&self, manifest: &ServiceManifest, before: bool) -> Result<(), String> {
        let captures: &[BufferCapture] = if before {
            self.dispatch
                .as_ref()
                .map(|phase| phase.buffers_before.as_slice())
                .unwrap_or_default()
        } else {
            self.returned
                .as_ref()
                .map(|phase| phase.buffers_after.as_slice())
                .unwrap_or_default()
        };
        let regions = manifest
            .capture
            .regions
            .iter()
            .filter(|region| if before { region.before } else { region.after })
            .collect::<Vec<_>>();
        // Without a dispatch there is no checked request coordinate from which post-call bytes
        // can be read. An out-of-order return is still recorded, but it cannot invent a capture.
        if self.dispatch.is_none() {
            if !captures.is_empty() {
                return Err("a record without dispatch cannot carry request-buffer bytes".into());
            }
            return Ok(());
        }
        if (before || self.returned.is_some()) && captures.len() != regions.len() {
            return Err("record does not carry the complete manifest capture set".into());
        }
        let request = self.dispatch.as_ref().map(|phase| phase.request.0).unwrap();
        for (capture, region) in captures.iter().zip(regions) {
            let suffix = if before { "before" } else { "after" };
            if capture.name != format!("{}.{suffix}", region.name)
                || capture.address.0 != request + u64::from(region.offset)
                || capture.available_size != region.length
            {
                return Err(format!(
                    "capture {} does not match manifest region {}",
                    capture.name, region.name
                ));
            }
        }
        Ok(())
    }
}

/// Entry data retained privately until a dispatch proves which service it belongs to.
#[derive(Clone, Debug)]
pub(crate) struct EntryObservation {
    pub(crate) site: PhaseSite,
    pub(crate) caller: Option<CodeCoordinate>,
    pub(crate) raw_arguments: RawArguments,
    pub(crate) provenance: Provenance,
}

#[derive(Clone, Debug)]
struct PendingCall {
    entry: Option<EntryObservation>,
    dispatch: Option<DispatchPhase>,
    cr3: HexU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceTraceArmed {
    pub(crate) schema: String,
    pub(crate) trace_id: String,
    pub(crate) label: Option<String>,
    pub(crate) manifest_id: String,
    pub(crate) target: TargetIdentity,
    pub(crate) image: ImageIdentity,
    pub(crate) image_base: HexU64,
    pub(crate) selected_service: u16,
    pub(crate) limits: TraceLimits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceTrace {
    pub(crate) schema: String,
    pub(crate) trace_id: String,
    pub(crate) label: Option<String>,
    pub(crate) manifest_id: String,
    pub(crate) target: TargetIdentity,
    pub(crate) image: ImageIdentity,
    pub(crate) image_base: HexU64,
    pub(crate) selected_service: u16,
    pub(crate) records: Vec<ServiceCallRecord>,
    pub(crate) limits: TraceLimits,
    pub(crate) full: bool,
    pub(crate) dropped_records: u64,
    pub(crate) dropped_capture_bytes: u64,
    pub(crate) unreadable_fields: u64,
    pub(crate) armed: bool,
    pub(crate) pending_phase: Option<ServicePhase>,
}

#[derive(Clone, Debug)]
pub(crate) struct Recorder {
    trace_id: String,
    label: Option<String>,
    manifest: ServiceManifest,
    target: TargetIdentity,
    image_base: HexU64,
    limits: TraceLimits,
    records: Vec<ServiceCallRecord>,
    pending: Option<PendingCall>,
    retained_capture_bytes: u64,
    dropped_records: u64,
    dropped_capture_bytes: u64,
    unreadable_fields: u64,
    sealed: bool,
    seen_epochs: std::collections::HashSet<StopEpoch>,
}

impl Recorder {
    pub(crate) fn new(
        trace_id: String,
        label: Option<String>,
        manifest: ServiceManifest,
        target: TargetIdentity,
        image_base: HexU64,
        limits: TraceLimits,
    ) -> Result<Self, String> {
        manifest.validate()?;
        target.validate().map_err(|error| format!("{error:#}"))?;
        if trace_id.is_empty() || image_base.0 == 0 {
            return Err("trace identity or selected VTL1 service is invalid".into());
        }
        if label
            .as_ref()
            .is_some_and(|label| label.is_empty() || label.len() > 128)
        {
            return Err("trace label must contain 1 through 128 UTF-8 bytes".into());
        }
        Ok(Self {
            trace_id,
            label,
            manifest,
            target,
            image_base,
            limits,
            records: Vec::new(),
            pending: None,
            retained_capture_bytes: 0,
            dropped_records: 0,
            dropped_capture_bytes: 0,
            unreadable_fields: 0,
            sealed: false,
            seen_epochs: std::collections::HashSet::new(),
        })
    }

    pub(crate) fn armed(&self) -> ServiceTraceArmed {
        ServiceTraceArmed {
            schema: ARMED_SCHEMA.into(),
            trace_id: self.trace_id.clone(),
            label: self.label.clone(),
            manifest_id: self.manifest.manifest_id.clone(),
            target: self.target.clone(),
            image: self.manifest.image.clone(),
            image_base: self.image_base,
            selected_service: self.manifest.service.number as u16,
            limits: self.limits,
        }
    }

    /// Clone only records that have reached a terminal state. The mutable pending call is exposed
    /// as a phase name, never as fields being filled concurrently.
    pub(crate) fn completed_prefix(&self) -> ServiceTrace {
        ServiceTrace {
            schema: TRACE_SCHEMA.into(),
            trace_id: self.trace_id.clone(),
            label: self.label.clone(),
            manifest_id: self.manifest.manifest_id.clone(),
            target: self.target.clone(),
            image: self.manifest.image.clone(),
            image_base: self.image_base,
            selected_service: self.manifest.service.number as u16,
            records: self.records.clone(),
            limits: self.limits,
            full: self.full(),
            dropped_records: self.dropped_records,
            dropped_capture_bytes: self.dropped_capture_bytes,
            unreadable_fields: self.unreadable_fields,
            armed: !self.sealed,
            pending_phase: self.pending.as_ref().map(|pending| {
                if pending.dispatch.is_some() {
                    ServicePhase::Dispatch
                } else {
                    ServicePhase::Entry
                }
            }),
        }
    }

    pub(crate) fn observe_entry(
        &mut self,
        cr3: HexU64,
        entry: EntryObservation,
    ) -> Result<(), String> {
        self.validate_observation(cr3, &entry.site, "entry")?;
        if self.sealed {
            return Ok(());
        }
        // Entry is common to every service and therefore is only a candidate until the checked
        // dispatch reads the selected number. Replacing an entry-only candidate cannot create an
        // incomplete *selected* record. Once dispatch has proved selection, however, a new entry
        // really does truncate that selected call and is retained as such.
        if let Some(pending) = self
            .pending
            .take()
            .filter(|pending| pending.dispatch.is_some())
        {
            self.seal_pending(pending, None, IncompleteReason::NestedEntry)?;
        }
        if !self.sealed {
            self.pending = Some(PendingCall {
                entry: Some(entry),
                dispatch: None,
                cr3,
            });
        }
        Ok(())
    }

    pub(crate) fn observe_dispatch(
        &mut self,
        cr3: HexU64,
        service: u16,
        dispatch: DispatchPhase,
    ) -> Result<(), String> {
        if service == self.manifest.service.number as u16 {
            let field = dispatch
                .fields
                .iter()
                .find(|field| field.name == "service_number")
                .ok_or_else(|| "dispatch observation omitted service_number".to_string())?;
            if field.value.0 != u64::from(service) {
                return Err("dispatch service argument and checked field disagree".into());
            }
        }
        self.validate_observation(cr3, &dispatch.site, "dispatch")?;
        if self.sealed {
            self.dropped_records += u64::from(service == self.manifest.service.number as u16);
            return Ok(());
        }
        if service != self.manifest.service.number as u16 {
            // The generic entry belonged to another service and is not an M6 record.
            self.pending = None;
            return Ok(());
        }
        match self.pending.take() {
            Some(mut pending) if pending.dispatch.is_none() => {
                if pending.cr3 != cr3 {
                    // The prior generic entry belonged to another transition address space and
                    // never proved the selected service. Start the selected record at dispatch;
                    // its eventual return will name the missing entry explicitly.
                    self.pending = Some(PendingCall {
                        entry: None,
                        dispatch: Some(dispatch),
                        cr3,
                    });
                } else {
                    pending.dispatch = Some(dispatch);
                    self.pending = Some(pending);
                }
            }
            Some(pending) => {
                self.seal_pending(pending, None, IncompleteReason::RepeatedDispatch)?;
                if !self.sealed {
                    self.pending = Some(PendingCall {
                        entry: None,
                        dispatch: Some(dispatch),
                        cr3,
                    });
                }
            }
            None => {
                self.pending = Some(PendingCall {
                    entry: None,
                    dispatch: Some(dispatch),
                    cr3,
                });
            }
        }
        Ok(())
    }

    pub(crate) fn observe_return(
        &mut self,
        cr3: HexU64,
        returned: ReturnPhase,
    ) -> Result<(), String> {
        self.validate_observation(cr3, &returned.site, "return")?;
        if self.sealed {
            self.dropped_records += 1;
            return Ok(());
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.dispatch.is_some() && pending.cr3 != cr3)
        {
            return Err("selected service return changed CR3 within one call".into());
        }
        match self.pending.take() {
            Some(pending) if pending.cr3 == cr3 && pending.dispatch.is_some() => {
                let reason = if pending.entry.is_some() {
                    None
                } else {
                    Some(IncompleteReason::MissingEntry)
                };
                self.push_record(self.record(pending, Some(returned), reason))?;
            }
            // A return with no selected dispatch is common non-selected traffic, not evidence
            // for an incomplete selected call. The decoder normally filters it; keep the
            // recorder boundary equally fail-closed for direct/offline callers.
            Some(_) | None => {}
        }
        Ok(())
    }

    fn validate_observation(
        &mut self,
        cr3: HexU64,
        site: &PhaseSite,
        phase: &str,
    ) -> Result<(), String> {
        if cr3.0 == 0 || cr3.0 & 0xfff != 0 {
            return Err("service observation used an invalid transition CR3".into());
        }
        let expected = self
            .manifest
            .sites
            .iter()
            .find(|site| site.phase == phase)
            .ok_or_else(|| format!("manifest has no {phase} site"))?;
        if site.coordinate.rva != expected.rva
            || site.coordinate.address.0 != self.image_base.0 + u64::from(expected.rva)
        {
            return Err(format!(
                "{phase} observation does not match its guarded site"
            ));
        }
        if !self.seen_epochs.insert(site.epoch.clone()) {
            return Err("service observation reused a stale stop epoch".into());
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<(), String> {
        if let Some(pending) = self
            .pending
            .take()
            .filter(|pending| pending.dispatch.is_some())
        {
            self.seal_pending(pending, None, IncompleteReason::Stopped)?;
        }
        self.sealed = true;
        Ok(())
    }

    fn seal_pending(
        &mut self,
        pending: PendingCall,
        returned: Option<ReturnPhase>,
        reason: IncompleteReason,
    ) -> Result<(), String> {
        let record = self.record(pending, returned, Some(reason));
        self.push_record(record)
    }

    fn record(
        &self,
        pending: PendingCall,
        returned: Option<ReturnPhase>,
        incomplete_reason: Option<IncompleteReason>,
    ) -> ServiceCallRecord {
        let entry = pending.entry.map(|entry| EntryPhase {
            site: entry.site,
            service: self.manifest.service.number as u16,
            caller: entry.caller,
            raw_arguments: entry.raw_arguments,
            provenance: entry.provenance,
        });
        let last_phase = if returned.is_some() {
            ServicePhase::Return
        } else if pending.dispatch.is_some() {
            ServicePhase::Dispatch
        } else {
            ServicePhase::Entry
        };
        ServiceCallRecord {
            schema: RECORD_SCHEMA.into(),
            trace_id: self.trace_id.clone(),
            label: self.label.clone(),
            sequence: self.records.len() as u64 + self.dropped_records + 1,
            manifest_id: self.manifest.manifest_id.clone(),
            target: self.target.clone(),
            image: self.manifest.image.clone(),
            image_base: self.image_base,
            cr3: pending.cr3,
            last_phase,
            complete: entry.is_some() && pending.dispatch.is_some() && returned.is_some(),
            incomplete_reason,
            entry,
            dispatch: pending.dispatch,
            returned,
        }
    }

    fn push_record(&mut self, record: ServiceCallRecord) -> Result<(), String> {
        record.validate(&self.manifest, self.limits)?;
        let bytes = record.captured_bytes();
        let event_full = self.records.len() >= self.limits.records as usize;
        let byte_full = self
            .retained_capture_bytes
            .checked_add(bytes)
            .is_none_or(|total| total > u64::from(self.limits.total_capture_bytes));
        if event_full || byte_full {
            self.dropped_records += 1;
            self.dropped_capture_bytes += bytes;
            self.sealed = true;
            return Ok(());
        }
        self.unreadable_fields += record.unreadable_fields();
        self.retained_capture_bytes += bytes;
        self.records.push(record);
        if self.records.len() == self.limits.records as usize
            || (self.limits.total_capture_bytes > 0
                && self.retained_capture_bytes == u64::from(self.limits.total_capture_bytes))
        {
            self.sealed = true;
        }
        Ok(())
    }

    fn full(&self) -> bool {
        self.records.len() == self.limits.records as usize
            || (self.limits.total_capture_bytes > 0
                && self.retained_capture_bytes == u64::from(self.limits.total_capture_bytes))
            || self.dropped_records > 0
    }
}

/// Engine-free state shared by the trace job and the worker request reader.
///
/// The engine thread is the only writer of observations. A reader can clone the immutable
/// completed prefix or set one stop bit, but cannot reach the live controller, provider or
/// decoder. Keeping both operations under this one lock gives stop-vs-completion one explicit
/// linearization point.
#[derive(Clone)]
pub(crate) struct SharedTrace {
    inner: Arc<Mutex<SharedTraceState>>,
}

struct SharedTraceState {
    recorder: Recorder,
    stop_requested: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopRequest {
    First,
    AlreadyRequested,
    Finished,
}

impl SharedTrace {
    pub(crate) fn new(recorder: Recorder) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SharedTraceState {
                recorder,
                stop_requested: false,
            })),
        }
    }

    pub(crate) fn armed(&self) -> ServiceTraceArmed {
        self.state().recorder.armed()
    }

    pub(crate) fn snapshot(&self, trace_id: &str) -> Result<ServiceTrace, String> {
        let state = self.state();
        require_trace_id(&state.recorder, trace_id)?;
        Ok(state.recorder.completed_prefix())
    }

    pub(crate) fn request_stop(&self, trace_id: &str) -> Result<StopRequest, String> {
        let mut state = self.state();
        require_trace_id(&state.recorder, trace_id)?;
        if state.recorder.sealed {
            return Ok(StopRequest::Finished);
        }
        if std::mem::replace(&mut state.stop_requested, true) {
            Ok(StopRequest::AlreadyRequested)
        } else {
            Ok(StopRequest::First)
        }
    }

    pub(crate) fn stop_requested(&self) -> bool {
        self.state().stop_requested
    }

    pub(crate) fn observe<T>(
        &self,
        observe: impl FnOnce(&mut Recorder) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut state = self.state();
        if state.stop_requested {
            return Err("service trace stop was linearized before this observation".into());
        }
        if state.recorder.sealed {
            return Err("service trace is already sealed".into());
        }
        observe(&mut state.recorder)
    }

    pub(crate) fn capacity_reached(&self) -> bool {
        self.state().recorder.full()
    }

    pub(crate) fn finish(&self) -> Result<ServiceTrace, String> {
        let mut state = self.state();
        state.recorder.finish()?;
        Ok(state.recorder.completed_prefix())
    }

    fn state(&self) -> std::sync::MutexGuard<'_, SharedTraceState> {
        self.inner.lock().unwrap_or_else(|error| error.into_inner())
    }
}

fn require_trace_id(recorder: &Recorder, trace_id: &str) -> Result<(), String> {
    if recorder.trace_id == trace_id {
        Ok(())
    } else {
        Err("trace_id is stale or belongs to a different trace".into())
    }
}

pub(crate) fn render_trace(trace: &ServiceTrace) -> String {
    let complete = trace
        .records
        .iter()
        .filter(|record| record.complete)
        .count();
    let incomplete = trace.records.len() - complete;
    let pending = trace
        .pending_phase
        .map(|phase| format!("; one {phase:?} phase is still pending"))
        .unwrap_or_default();
    let dropped = (trace.dropped_records > 0).then(|| {
        format!(
            "; {} record(s) and {} captured byte(s) were dropped",
            trace.dropped_records, trace.dropped_capture_bytes
        )
    });
    format!(
        "Secure Kernel service trace {} holds {} complete and {} incomplete record(s){}{}. It is {}.",
        trace.trace_id,
        complete,
        incomplete,
        pending,
        dropped.unwrap_or_default(),
        if trace.armed { "armed" } else { "stopped" },
    )
}

pub(crate) fn render_armed(armed: &ServiceTraceArmed) -> String {
    format!(
        "Secure Kernel service trace {} is armed for manifest {} service {} on VP {}.",
        armed.trace_id, armed.manifest_id, armed.selected_service, armed.target.vp
    )
}

/// One retained hardware-breakpoint stop after it has been decoded against the exact manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DecodedStop {
    pub(crate) phase: ServicePhase,
    /// False only for a dispatch whose measured service number is not the selected service.
    pub(crate) selected: bool,
}

/// A fully decoded stop that has not yet crossed the recorder's stop linearization point.
///
/// Live-memory reads happen while constructing this value, outside [`SharedTrace`]'s lock. The
/// engine thread then applies it atomically with respect to a reader-side stop request. If the
/// stop won while those reads were in flight, the observation is discarded and restoration wins.
pub(crate) struct DecodedObservation {
    stop: DecodedStop,
    event: Option<DecodedEvent>,
}

enum DecodedEvent {
    Dispatch {
        cr3: HexU64,
        service: u16,
        dispatch: Box<DispatchPhase>,
        matched_entry: Option<Box<(HexU64, EntryObservation)>>,
    },
    Return {
        cr3: HexU64,
        returned: ReturnPhase,
    },
}

impl DecodedObservation {
    pub(crate) fn apply(self, recorder: &mut Recorder) -> Result<DecodedStop, String> {
        match self.event {
            Some(DecodedEvent::Dispatch {
                cr3,
                service,
                dispatch,
                matched_entry,
            }) => {
                if let Some(matched_entry) = matched_entry {
                    let (entry_cr3, entry) = *matched_entry;
                    recorder.observe_entry(entry_cr3, entry)?;
                }
                recorder.observe_dispatch(cr3, service, *dispatch)?;
            }
            Some(DecodedEvent::Return { cr3, returned }) => {
                recorder.observe_return(cr3, returned)?
            }
            None => {}
        }
        Ok(self.stop)
    }
}

/// Converts retained live-control stops into the recorder's semantic observations.
///
/// It owns no engine or provider. The worker supplies a bounded read callback while it holds the
/// exact stop; tests supply an in-memory fake. This keeps the build-specific register and layout
/// interpretation in the same module as the record contract and makes it independently testable.
pub(crate) struct ObservationDecoder {
    manifest: ServiceManifest,
    target: TargetIdentity,
    image_base: HexU64,
    started: Instant,
    entry_captures: std::collections::VecDeque<PendingEntryCapture>,
    selected_requests: Vec<u64>,
    seen_epochs: std::collections::HashSet<StopEpoch>,
}

struct PendingEntryCapture {
    request: u64,
    cr3: HexU64,
    entry: EntryObservation,
    buffers: Vec<BufferCapture>,
}

#[derive(Clone, Copy)]
enum CapturePoint {
    Entry,
    Dispatch,
}

impl ObservationDecoder {
    pub(crate) fn new(
        manifest: ServiceManifest,
        target: TargetIdentity,
        image_base: HexU64,
    ) -> Result<Self, String> {
        manifest.validate()?;
        target.validate().map_err(|error| format!("{error:#}"))?;
        if image_base.0 == 0 {
            return Err("service-trace image base must be nonzero".into());
        }
        Ok(Self {
            manifest,
            target,
            image_base,
            started: Instant::now(),
            entry_captures: std::collections::VecDeque::new(),
            selected_requests: Vec::new(),
            seen_epochs: std::collections::HashSet::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn observe<F>(
        &mut self,
        recorder: &mut Recorder,
        stop: &StopRecord,
        read: F,
    ) -> Result<DecodedStop, String>
    where
        F: FnMut(u64, u32) -> Result<Vec<u8>, String>,
    {
        self.decode(stop, recorder.limits.per_buffer_bytes, read)?
            .apply(recorder)
    }

    pub(crate) fn decode<F>(
        &mut self,
        stop: &StopRecord,
        buffer_limit: u32,
        mut read: F,
    ) -> Result<DecodedObservation, String>
    where
        F: FnMut(u64, u32) -> Result<Vec<u8>, String>,
    {
        if stop.target != self.target {
            return Err("service stop does not belong to the trace target".into());
        }
        if !self.seen_epochs.insert(stop.epoch.clone()) {
            return Err("service observation reused a stale stop epoch".into());
        }
        let slot = match stop.event.reason {
            StopReason::HardwareBreakpoint { slot } => slot,
            _ => return Err("service trace observed a stop it does not own".into()),
        };
        let site = self
            .manifest
            .sites
            .iter()
            .find(|site| site.slot == slot)
            .cloned()
            .ok_or_else(|| format!("service trace observed unowned hardware slot {slot}"))?;
        let expected = self
            .manifest
            .breakpoints(self.image_base.0)?
            .into_iter()
            .find(|breakpoint| breakpoint.slot == slot)
            .ok_or_else(|| format!("manifest has no breakpoint for slot {slot}"))?;
        if stop.instruction != expected.instruction {
            return Err(format!(
                "{} stop instruction no longer matches its manifest guard",
                site.phase
            ));
        }
        let cr3 = HexU64(self.register(stop, RegisterName::Cr3)?);
        let phase_site = self.phase_site(stop, &site);

        match site.phase.as_str() {
            "entry" => {
                let rsp = self.register(stop, RegisterName::Rsp)?;
                let rcx = self.register(stop, RegisterName::Rcx)?;
                let buffers =
                    self.capture_regions(rcx, true, buffer_limit, CapturePoint::Entry, &mut read)?;
                let caller_result =
                    read_required("entry caller", rsp, 8, &mut read).and_then(|bytes| {
                        let address = little_u64(&bytes)?;
                        let rva = address
                            .checked_sub(self.image_base.0)
                            .and_then(|rva| u32::try_from(rva).ok())
                            .filter(|rva| *rva < self.manifest.image.pe.size_of_image)
                            .ok_or_else(|| {
                                "entry return address is outside the proved Secure Kernel image"
                                    .to_string()
                            })?;
                        Ok(CodeCoordinate {
                            address: HexU64(address),
                            rva,
                            symbol: format!("securekernel+0x{rva:x}"),
                        })
                    });
                let (caller, caller_failure) = match caller_result {
                    Ok(caller) => (Some(caller), None),
                    Err(message) => (None, Some(message)),
                };
                let mut provenance = Provenance {
                    measured: vec![
                        "entry.site.epoch".into(),
                        "entry.site.host_monotonic_us".into(),
                        "entry.site.host_elapsed_us".into(),
                        "entry.raw_arguments".into(),
                    ],
                    exact_build_layout_derived: vec!["entry.site.coordinate".into()],
                    inferred: Vec::new(),
                    unavailable: Vec::new(),
                };
                if caller.is_some() {
                    provenance.measured.push("entry.caller.address".into());
                    provenance
                        .exact_build_layout_derived
                        .push("entry.caller.coordinate".into());
                } else if let Some(message) = caller_failure {
                    provenance.unavailable.push(ReadFailure {
                        field: "entry.caller".into(),
                        message,
                    });
                }
                let entry = EntryObservation {
                    site: phase_site,
                    caller,
                    raw_arguments: RawArguments {
                        rcx: HexU64(rcx),
                        rdx: HexU64(self.register(stop, RegisterName::Rdx)?),
                        r8: HexU64(self.register(stop, RegisterName::R8)?),
                        r9: HexU64(self.register(stop, RegisterName::R9)?),
                    },
                    provenance,
                };
                if let Some(index) = self
                    .entry_captures
                    .iter()
                    .position(|candidate| candidate.request == rcx)
                {
                    self.entry_captures.remove(index);
                }
                if self.entry_captures.len() == MAX_ENTRY_CANDIDATES {
                    self.entry_captures.pop_front();
                }
                self.entry_captures.push_back(PendingEntryCapture {
                    request: rcx,
                    cr3,
                    entry,
                    buffers,
                });
                Ok(DecodedObservation {
                    stop: DecodedStop {
                        phase: ServicePhase::Entry,
                        selected: false,
                    },
                    event: None,
                })
            }
            "dispatch" => {
                let request =
                    self.register_named(stop, &self.manifest.service.number_source.base_register)?;
                if request == 0
                    || !request.is_multiple_of(u64::from(self.manifest.request_layout.alignment))
                {
                    return Err("dispatch request pointer is null or misaligned".into());
                }
                let service_field = self
                    .manifest
                    .request_layout
                    .fields
                    .iter()
                    .find(|field| field.name == "service_number")
                    .ok_or_else(|| "manifest has no service_number field".to_string())?;
                let service_address = request
                    .checked_add(u64::from(service_field.offset))
                    .ok_or_else(|| "service-number address wraps".to_string())?;
                let service = u16::try_from(little_u64(&read_required(
                    "service_number",
                    service_address,
                    service_field.width,
                    &mut read,
                )?)?)
                .map_err(|_| "service_number does not fit 16 bits".to_string())?;
                let selected = u32::from(service) == self.manifest.service.number;
                let mut matched_entry = None;
                let (fields, buffers_before) = if selected {
                    let layout = read_required(
                        "service request layout",
                        request,
                        self.manifest.request_layout.size,
                        &mut read,
                    )?;
                    let fields = self
                        .manifest
                        .request_layout
                        .fields
                        .iter()
                        .map(|field| {
                            let start = field.offset as usize;
                            let end = start + field.width as usize;
                            Ok(LayoutValue {
                                name: field.name.clone(),
                                offset: field.offset,
                                width: field.width as u8,
                                value: HexU64(little_u64(&layout[start..end])?),
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()?;
                    let buffers = match self
                        .entry_captures
                        .iter()
                        .rposition(|entry| entry.request == request)
                        .and_then(|index| self.entry_captures.remove(index))
                    {
                        Some(entry) => {
                            matched_entry = Some(Box::new((entry.cr3, entry.entry)));
                            entry.buffers
                        }
                        None => self.capture_regions(
                            request,
                            true,
                            buffer_limit,
                            CapturePoint::Entry,
                            &mut |_, _| Err("entry phase was not observed".into()),
                        )?,
                    };
                    (fields, buffers)
                } else {
                    if let Some(index) = self
                        .entry_captures
                        .iter()
                        .rposition(|entry| entry.request == request)
                    {
                        self.entry_captures.remove(index);
                    }
                    (Vec::new(), Vec::new())
                };
                let dispatch = DispatchPhase {
                    site: phase_site,
                    handler: CodeCoordinate {
                        address: HexU64(
                            self.image_base.0 + u64::from(self.manifest.service.handler_rva),
                        ),
                        rva: self.manifest.service.handler_rva,
                        symbol: self.manifest.service.handler_symbol.clone(),
                    },
                    request: HexU64(request),
                    fields,
                    buffers_before,
                    provenance: Provenance {
                        measured: vec![
                            "dispatch.site.epoch".into(),
                            "dispatch.site.host_monotonic_us".into(),
                            "dispatch.site.host_elapsed_us".into(),
                            "dispatch.request".into(),
                            "dispatch.fields".into(),
                        ],
                        exact_build_layout_derived: vec![
                            "dispatch.site.coordinate".into(),
                            "dispatch.handler".into(),
                        ],
                        inferred: Vec::new(),
                        unavailable: Vec::new(),
                    },
                };
                if selected {
                    self.selected_requests.push(request);
                }
                Ok(DecodedObservation {
                    stop: DecodedStop {
                        phase: ServicePhase::Dispatch,
                        selected,
                    },
                    event: Some(DecodedEvent::Dispatch {
                        cr3,
                        service,
                        dispatch: Box::new(dispatch),
                        matched_entry,
                    }),
                })
            }
            "return" => {
                let Some(request) = self.selected_requests.pop() else {
                    return Ok(DecodedObservation {
                        stop: DecodedStop {
                            phase: ServicePhase::Return,
                            selected: false,
                        },
                        event: None,
                    });
                };
                let buffers_after = self.capture_regions(
                    request,
                    false,
                    buffer_limit,
                    CapturePoint::Dispatch,
                    &mut read,
                )?;
                let returned = ReturnPhase {
                    site: phase_site,
                    status: self.register(stop, RegisterName::Rax)? as u32,
                    buffers_after,
                    provenance: Provenance {
                        measured: vec![
                            "returned.site.epoch".into(),
                            "returned.site.host_monotonic_us".into(),
                            "returned.site.host_elapsed_us".into(),
                            "returned.status".into(),
                        ],
                        exact_build_layout_derived: vec!["returned.site.coordinate".into()],
                        inferred: Vec::new(),
                        unavailable: Vec::new(),
                    },
                };
                Ok(DecodedObservation {
                    stop: DecodedStop {
                        phase: ServicePhase::Return,
                        selected: true,
                    },
                    event: Some(DecodedEvent::Return { cr3, returned }),
                })
            }
            other => Err(format!("manifest exposed unknown service phase {other}")),
        }
    }

    fn phase_site(&self, stop: &StopRecord, site: &crate::skservice::Site) -> PhaseSite {
        let origin = MONOTONIC_ORIGIN.get_or_init(Instant::now);
        PhaseSite {
            epoch: stop.epoch.clone(),
            host_monotonic_us: duration_us(origin.elapsed()),
            host_elapsed_us: duration_us(self.started.elapsed()),
            coordinate: CodeCoordinate {
                address: HexU64(self.image_base.0 + u64::from(site.rva)),
                rva: site.rva,
                symbol: site.symbol.clone(),
            },
        }
    }

    fn register(&self, stop: &StopRecord, register: RegisterName) -> Result<u64, String> {
        stop.registers
            .low(register)
            .map_err(|error| format!("{error:#}"))
    }

    fn register_named(&self, stop: &StopRecord, name: &str) -> Result<u64, String> {
        let register = match name {
            "rax" | "eax" => RegisterName::Rax,
            "rcx" => RegisterName::Rcx,
            "rdx" => RegisterName::Rdx,
            "r8" => RegisterName::R8,
            "r9" => RegisterName::R9,
            "r14" => RegisterName::R14,
            other => return Err(format!("manifest names unsupported register {other}")),
        };
        self.register(stop, register)
    }

    fn capture_regions<F>(
        &self,
        request: u64,
        before: bool,
        buffer_limit: u32,
        point: CapturePoint,
        read: &mut F,
    ) -> Result<Vec<BufferCapture>, String>
    where
        F: FnMut(u64, u32) -> Result<Vec<u8>, String>,
    {
        self.manifest
            .capture
            .regions
            .iter()
            .filter(|region| if before { region.before } else { region.after })
            .map(|region| {
                let (configured_base, expected_base) = match point {
                    CapturePoint::Entry => (&region.entry_base_register, "rcx"),
                    CapturePoint::Dispatch => (&region.dispatch_base_register, "r14"),
                };
                if configured_base != expected_base {
                    return Err(format!(
                        "manifest capture {} uses unsupported base register {configured_base}",
                        region.name,
                    ));
                }
                let address = request
                    .checked_add(u64::from(region.offset))
                    .ok_or_else(|| format!("capture {} address wraps", region.name))?;
                capture_buffer(
                    format!(
                        "{}.{}",
                        region.name,
                        if before { "before" } else { "after" }
                    ),
                    address,
                    region.length,
                    self.manifest.capture.per_buffer_limit_max.min(buffer_limit),
                    &mut *read,
                )
            })
            .collect()
    }
}

static MONOTONIC_ORIGIN: OnceLock<Instant> = OnceLock::new();

fn duration_us(duration: std::time::Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn little_u64(bytes: &[u8]) -> Result<u64, String> {
    if !matches!(bytes.len(), 1 | 2 | 4 | 8) {
        return Err("typed layout value must contain 1, 2, 4 or 8 bytes".into());
    }
    let mut word = [0_u8; 8];
    word[..bytes.len()].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(word))
}

fn read_required<F>(name: &str, address: u64, size: u32, read: &mut F) -> Result<Vec<u8>, String>
where
    F: FnMut(u64, u32) -> Result<Vec<u8>, String>,
{
    let mut bytes = Vec::with_capacity(size as usize);
    let mut cursor = address;
    while bytes.len() < size as usize {
        let page_left = PAGE_BYTES - cursor % PAGE_BYTES;
        let remaining = size as usize - bytes.len();
        let count = remaining.min(page_left as usize) as u32;
        let chunk = read(cursor, count).map_err(|error| format!("{name}: {error}"))?;
        if chunk.len() != count as usize {
            return Err(format!(
                "{name}: short read at {cursor:#x}: requested {count}, received {}",
                chunk.len()
            ));
        }
        bytes.extend(chunk);
        cursor += u64::from(count);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skcontrol::{HeldEvent, RegisterValue};
    use crate::sklive::{ArmMode, RegisterSnapshot};
    use crate::skservice::service_manifest;
    use std::collections::HashMap;

    fn target() -> TargetIdentity {
        TargetIdentity {
            vm_id: "00000000-0000-0000-0000-000000000001".into(),
            partition_id: HexU64(0x1b),
            vp: 0,
            vtl: 1,
            expected_cr3: HexU64(0x1234_5000),
        }
    }

    fn limits(records: u32, total: u32) -> TraceLimits {
        TraceLimits::checked(records, 64, total).unwrap()
    }

    fn recorder(records: u32, total: u32) -> Recorder {
        let manifest = service_manifest().unwrap();
        Recorder::new(
            "sktrace-1".into(),
            Some("capture-1".into()),
            manifest,
            target(),
            HexU64(0xffff_f807_0000_0000),
            limits(records, total),
        )
        .unwrap()
    }

    fn site(rva: u32, elapsed: u64) -> PhaseSite {
        PhaseSite {
            epoch: StopEpoch::new(format!("epoch-{elapsed:016x}")).unwrap(),
            host_monotonic_us: 1_000_000 + elapsed,
            host_elapsed_us: elapsed,
            coordinate: CodeCoordinate {
                address: HexU64(0xffff_f807_0000_0000 + u64::from(rva)),
                rva,
                symbol: format!("securekernel+0x{rva:x}"),
            },
        }
    }

    fn provenance(fields: &[&str]) -> Provenance {
        Provenance {
            measured: fields.iter().map(|field| (*field).into()).collect(),
            exact_build_layout_derived: Vec::new(),
            inferred: Vec::new(),
            unavailable: Vec::new(),
        }
    }

    fn entry_at(elapsed: u64) -> EntryObservation {
        EntryObservation {
            site: site(0x137f0, elapsed),
            caller: Some(CodeCoordinate {
                address: HexU64(0xffff_f800_0000_1000),
                rva: 0x1000,
                symbol: "nt!VslCreateEnclave".into(),
            }),
            raw_arguments: RawArguments {
                rcx: HexU64(1),
                rdx: HexU64(2),
                r8: HexU64(3),
                r9: HexU64(4),
            },
            provenance: provenance(&["entry.site", "entry.caller", "entry.raw_arguments"]),
        }
    }

    fn entry() -> EntryObservation {
        entry_at(10)
    }

    fn buffer(name: &str, byte: u8) -> BufferCapture {
        capture_buffer(name, 0xffff_8000_0000_2000, 64, 64, |_, count| {
            Ok(vec![byte; count as usize])
        })
        .unwrap()
    }

    fn dispatch_at(elapsed: u64, service: u16) -> DispatchPhase {
        let manifest = service_manifest().unwrap();
        DispatchPhase {
            site: site(0x14bd8, elapsed),
            handler: CodeCoordinate {
                address: HexU64(0xffff_f807_0005_9990),
                rva: 0x59990,
                symbol: "securekernel!SkmmCreateEnclave".into(),
            },
            request: HexU64(0xffff_8000_0000_2000),
            fields: manifest
                .request_layout
                .fields
                .iter()
                .map(|field| LayoutValue {
                    name: field.name.clone(),
                    offset: field.offset,
                    width: field.width as u8,
                    value: HexU64(if field.name == "service_number" {
                        u64::from(service)
                    } else {
                        0
                    }),
                })
                .collect(),
            buffers_before: vec![buffer("request.before", 0x11)],
            provenance: provenance(&[
                "dispatch.site",
                "dispatch.handler",
                "dispatch.request",
                "dispatch.fields",
            ]),
        }
    }

    fn dispatch() -> DispatchPhase {
        dispatch_at(20, 47)
    }

    fn returned_at(elapsed: u64) -> ReturnPhase {
        ReturnPhase {
            site: site(0x14c10, elapsed),
            status: 0,
            buffers_after: vec![buffer("request.after", 0x22)],
            provenance: provenance(&["returned.site", "returned.status"]),
        }
    }

    fn returned() -> ReturnPhase {
        returned_at(30)
    }

    fn bare_returned_at(elapsed: u64) -> ReturnPhase {
        let mut returned = returned_at(elapsed);
        returned.buffers_after.clear();
        returned
    }

    fn complete(recorder: &mut Recorder) {
        let cr3 = target().expected_cr3;
        recorder.observe_entry(cr3, entry()).unwrap();
        recorder.observe_dispatch(cr3, 47, dispatch()).unwrap();
        recorder.observe_return(cr3, returned()).unwrap();
    }

    #[derive(Default)]
    struct FakeMemory {
        bytes: HashMap<u64, u8>,
    }

    impl FakeMemory {
        fn put(&mut self, address: u64, bytes: &[u8]) {
            for (offset, byte) in bytes.iter().copied().enumerate() {
                self.bytes.insert(address + offset as u64, byte);
            }
        }

        fn read(&self, address: u64, size: u32) -> Result<Vec<u8>, String> {
            (0..u64::from(size))
                .map(|offset| {
                    self.bytes
                        .get(&(address + offset))
                        .copied()
                        .ok_or_else(|| format!("unreadable {:#x}", address + offset))
                })
                .collect()
        }
    }

    fn live_stop(
        manifest: &ServiceManifest,
        image_base: u64,
        phase: &str,
        epoch: u64,
        registers: &[(RegisterName, u64)],
    ) -> StopRecord {
        let site = manifest
            .sites
            .iter()
            .find(|site| site.phase == phase)
            .unwrap();
        let instruction = manifest
            .breakpoints(image_base)
            .unwrap()
            .into_iter()
            .find(|breakpoint| breakpoint.slot == site.slot)
            .unwrap()
            .instruction;
        let mut values = registers
            .iter()
            .map(|(name, value)| RegisterValue {
                name: *name,
                status: 0,
                low: HexU64(*value),
                high: HexU64(0),
            })
            .collect::<Vec<_>>();
        if !values.iter().any(|value| value.name == RegisterName::Cr3) {
            values.push(RegisterValue {
                name: RegisterName::Cr3,
                status: 0,
                low: target().expected_cr3,
                high: HexU64(0),
            });
        }
        StopRecord {
            epoch: StopEpoch::new(format!("live-epoch-{epoch:016x}")).unwrap(),
            target: target(),
            event: HeldEvent {
                message_type: HexU64(1),
                vector: 1,
                vp: 0,
                vtl: 1,
                cpl: 0,
                dispatcher_context: HexU64(0x2000),
                advance_instruction_pointer: false,
                reason: StopReason::HardwareBreakpoint { slot: site.slot },
            },
            registers: RegisterSnapshot { values },
            instruction,
            expected_rips: vec![HexU64(image_base + u64::from(site.rva))],
            arm_mode: ArmMode::Natural,
        }
    }

    #[test]
    fn trace_records_round_trip_with_exact_integer_widths() {
        let mut recorder = recorder(4, 1_024);
        complete(&mut recorder);
        recorder.finish().unwrap();
        let trace = recorder.completed_prefix();
        let encoded = serde_json::to_string(&trace).unwrap();
        let decoded: ServiceTrace = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, trace);
        assert_eq!(trace.records[0].entry.as_ref().unwrap().service, 47_u16);
        assert_eq!(trace.records[0].returned.as_ref().unwrap().status, 0_u32);
        let schema = schemars::schema_for!(ServiceTrace);
        let schema = serde_json::to_value(schema).unwrap().to_string();
        assert!(schema.contains("windbg-mcp.sk-service-call.v1") || schema.contains("records"));
    }

    #[test]
    fn page_boundary_reads_are_joined_but_a_short_page_is_all_unavailable() {
        let mut calls = Vec::new();
        let captured = capture_buffer("request.before", 0x1ffe, 6, 6, |address, count| {
            calls.push((address, count));
            Ok(vec![address as u8; count as usize])
        })
        .unwrap();
        assert_eq!(calls, [(0x1ffe, 2), (0x2000, 4)]);
        assert!(matches!(captured.bytes, BufferState::Measured { .. }));

        let short = capture_buffer("request.before", 0x1ffe, 6, 6, |_, count| {
            Ok(vec![0; count.saturating_sub(1) as usize])
        })
        .unwrap();
        assert!(matches!(
            short.bytes,
            BufferState::Unavailable {
                failure: ReadFailure { ref field, .. }
            } if field == "request.before"
        ));
    }

    #[test]
    fn zero_and_maximum_buffer_limits_are_exact() {
        let mut called = false;
        let zero = capture_buffer("request.before", 0x1000, 64, 0, |_, _| {
            called = true;
            Ok(Vec::new())
        })
        .unwrap();
        assert!(!called);
        assert_eq!(zero.requested_size, 0);
        assert!(matches!(zero.bytes, BufferState::Measured { ref data } if data.is_empty()));

        let maximum = capture_buffer(
            "request.before",
            0x1000,
            MAX_BUFFER_BYTES,
            MAX_BUFFER_BYTES,
            |_, count| Ok(vec![0xaa; count as usize]),
        )
        .unwrap();
        assert_eq!(maximum.captured_bytes(), u64::from(MAX_BUFFER_BYTES));
        assert!(TraceLimits::checked(1, MAX_BUFFER_BYTES + 1, 0).is_err());
    }

    #[test]
    fn completed_prefix_never_exposes_the_mutable_record() {
        let mut recorder = recorder(4, 1_024);
        recorder
            .observe_entry(target().expected_cr3, entry())
            .unwrap();
        let snapshot = recorder.completed_prefix();
        assert!(snapshot.records.is_empty());
        assert_eq!(snapshot.pending_phase, Some(ServicePhase::Entry));
        recorder
            .observe_dispatch(target().expected_cr3, 47, dispatch())
            .unwrap();
        let snapshot = recorder.completed_prefix();
        assert!(snapshot.records.is_empty());
        assert_eq!(snapshot.pending_phase, Some(ServicePhase::Dispatch));
    }

    #[test]
    fn a_nonselected_service_does_not_create_a_record() {
        let mut recorder = recorder(4, 1_024);
        recorder
            .observe_entry(target().expected_cr3, entry())
            .unwrap();
        recorder
            .observe_dispatch(target().expected_cr3, 46, dispatch_at(20, 46))
            .unwrap();
        recorder.finish().unwrap();
        let trace = recorder.completed_prefix();
        assert!(trace.records.is_empty());
        assert_eq!(trace.dropped_records, 0);
    }

    #[test]
    fn unproved_entries_and_returns_do_not_claim_the_selected_service() {
        let mut recorder = recorder(8, 1_024);
        recorder
            .observe_entry(target().expected_cr3, entry())
            .unwrap();
        recorder
            .observe_entry(target().expected_cr3, entry_at(11))
            .unwrap();
        recorder
            .observe_return(target().expected_cr3, bare_returned_at(30))
            .unwrap();
        recorder.finish().unwrap();
        let trace = recorder.completed_prefix();
        assert!(trace.records.is_empty());
        assert_eq!(trace.dropped_records, 0);
    }

    #[test]
    fn nested_entry_after_selected_dispatch_is_an_incomplete_selected_record() {
        let mut recorder = recorder(8, 1_024);
        recorder
            .observe_entry(target().expected_cr3, entry())
            .unwrap();
        recorder
            .observe_dispatch(target().expected_cr3, 47, dispatch())
            .unwrap();
        recorder
            .observe_entry(target().expected_cr3, entry_at(11))
            .unwrap();
        recorder.finish().unwrap();
        let trace = recorder.completed_prefix();
        assert_eq!(trace.records.len(), 1);
        assert_eq!(
            trace.records[0].incomplete_reason,
            Some(IncompleteReason::NestedEntry)
        );
        assert!(!trace.records[0].complete);
    }

    #[test]
    fn repeated_dispatch_and_stale_cr3_are_not_spliced_into_a_complete_call() {
        let mut recorder = recorder(8, 1_024);
        let cr3 = target().expected_cr3;
        recorder.observe_entry(cr3, entry()).unwrap();
        recorder.observe_dispatch(cr3, 47, dispatch()).unwrap();
        recorder
            .observe_dispatch(cr3, 47, dispatch_at(21, 47))
            .unwrap();
        let error = recorder
            .observe_return(HexU64(cr3.0 + 0x1000), returned())
            .unwrap_err();
        assert!(error.contains("CR3"), "{error}");
        recorder.finish().unwrap();
        let trace = recorder.completed_prefix();
        assert!(trace.records.iter().all(|record| !record.complete));
        assert_eq!(
            trace.records[0].incomplete_reason,
            Some(IncompleteReason::RepeatedDispatch)
        );
        assert!(
            trace
                .records
                .iter()
                .any(|record| { record.incomplete_reason == Some(IncompleteReason::Stopped) })
        );
    }

    #[test]
    fn a_controller_validated_transition_cr3_is_retained_on_the_complete_call() {
        let transition_cr3 = HexU64(0x5678_9000);
        let mut recorder = Recorder::new(
            "sktrace-transition-cr3".into(),
            None,
            service_manifest().unwrap(),
            target(),
            HexU64(0xffff_f807_0000_0000),
            limits(2, 1_024),
        )
        .unwrap();

        recorder.observe_entry(transition_cr3, entry()).unwrap();
        recorder
            .observe_dispatch(transition_cr3, 47, dispatch())
            .unwrap();
        recorder.observe_return(transition_cr3, returned()).unwrap();
        let trace = recorder.completed_prefix();
        assert_eq!(trace.records.len(), 1);
        assert!(trace.records[0].complete);
        assert_eq!(trace.records[0].cr3, transition_cr3);
    }

    #[test]
    fn event_and_byte_capacity_account_for_whole_dropped_records() {
        let mut event_full = recorder(1, 1_024);
        complete(&mut event_full);
        assert!(event_full.completed_prefix().full);
        event_full
            .observe_return(target().expected_cr3, returned_at(40))
            .unwrap();
        let trace = event_full.completed_prefix();
        assert_eq!(trace.records.len(), 1);
        assert_eq!(trace.dropped_records, 1);

        let mut byte_full = recorder(4, 7);
        complete(&mut byte_full);
        let trace = byte_full.completed_prefix();
        assert!(trace.records.is_empty());
        assert_eq!(trace.dropped_records, 1);
        assert_eq!(trace.dropped_capture_bytes, 128);
        assert!(trace.full);
    }

    #[test]
    fn unreadable_buffers_are_named_and_counted_without_partial_bytes() {
        let unavailable =
            capture_buffer("request.before", 0xffff_8000_0000_2000, 64, 64, |_, _| {
                Err("page absent".into())
            })
            .unwrap();
        let mut dispatch = dispatch();
        dispatch.buffers_before = vec![unavailable];
        let mut recorder = recorder(4, 1_024);
        let cr3 = target().expected_cr3;
        recorder.observe_entry(cr3, entry()).unwrap();
        recorder.observe_dispatch(cr3, 47, dispatch).unwrap();
        recorder.observe_return(cr3, returned()).unwrap();
        let trace = recorder.completed_prefix();
        assert_eq!(trace.unreadable_fields, 1);
        assert!(matches!(
            trace.records[0].dispatch.as_ref().unwrap().buffers_before[0].bytes,
            BufferState::Unavailable { .. }
        ));
    }

    #[test]
    fn every_incomplete_state_renders_without_claiming_completion() {
        for reason in [
            IncompleteReason::NestedEntry,
            IncompleteReason::RepeatedDispatch,
            IncompleteReason::MissingEntry,
            IncompleteReason::MissingDispatch,
            IncompleteReason::UnexpectedReturn,
            IncompleteReason::Stopped,
        ] {
            let mut recorder = recorder(4, 1_024);
            let pending = PendingCall {
                entry: Some(entry()),
                dispatch: None,
                cr3: target().expected_cr3,
            };
            let record = recorder.record(pending, None, Some(reason));
            recorder.push_record(record).unwrap();
            recorder.finish().unwrap();
            let text = render_trace(&recorder.completed_prefix());
            assert!(
                text.contains("0 complete and 1 incomplete"),
                "{reason:?}: {text}"
            );
        }
    }

    #[test]
    fn inferred_values_and_overlapping_provenance_are_refused() {
        let mut provenance = provenance(&["entry.site"]);
        provenance.inferred.push("entry.service".into());
        assert!(provenance.validate().unwrap_err().contains("inferred"));
        provenance.inferred.clear();
        provenance
            .exact_build_layout_derived
            .push("entry.site".into());
        assert!(provenance.validate().unwrap_err().contains("disjoint"));
    }

    #[test]
    fn a_stale_epoch_is_refused_without_consuming_the_pending_call() {
        let mut recorder = recorder(4, 1_024);
        let cr3 = target().expected_cr3;
        recorder.observe_entry(cr3, entry()).unwrap();
        let mut dispatch = dispatch();
        dispatch.site.epoch = entry().site.epoch;
        let error = recorder.observe_dispatch(cr3, 47, dispatch).unwrap_err();
        assert!(error.contains("stale stop epoch"), "{error}");
        let snapshot = recorder.completed_prefix();
        assert!(snapshot.records.is_empty());
        assert_eq!(snapshot.pending_phase, Some(ServicePhase::Entry));
    }

    #[test]
    fn a_zero_total_byte_limit_still_retains_zero_byte_records() {
        let manifest = service_manifest().unwrap();
        let mut recorder = Recorder::new(
            "sktrace-zero-bytes".into(),
            None,
            manifest,
            target(),
            HexU64(0xffff_f807_0000_0000),
            TraceLimits::checked(2, 0, 0).unwrap(),
        )
        .unwrap();
        let cr3 = target().expected_cr3;
        let mut dispatch = dispatch();
        dispatch.buffers_before = vec![
            capture_buffer(
                "request.before",
                0xffff_8000_0000_2000,
                64,
                0,
                |_, _| unreachable!(),
            )
            .unwrap(),
        ];
        let mut returned = returned();
        returned.buffers_after = vec![
            capture_buffer(
                "request.after",
                0xffff_8000_0000_2000,
                64,
                0,
                |_, _| unreachable!(),
            )
            .unwrap(),
        ];
        recorder.observe_entry(cr3, entry()).unwrap();
        recorder.observe_dispatch(cr3, 47, dispatch).unwrap();
        recorder.observe_return(cr3, returned).unwrap();
        let trace = recorder.completed_prefix();
        assert_eq!(trace.records.len(), 1);
        assert!(!trace.full);
        assert!(trace.armed);
    }

    #[test]
    fn a_changed_or_removed_typed_layout_value_is_refused() {
        let recorder = recorder(4, 1_024);
        let pending = PendingCall {
            entry: Some(entry()),
            dispatch: Some(dispatch()),
            cr3: target().expected_cr3,
        };
        let record = recorder.record(pending, Some(returned()), None);

        let mut changed = record.clone();
        changed.dispatch.as_mut().unwrap().fields[2].offset += 1;
        let error = changed
            .validate(&recorder.manifest, recorder.limits)
            .unwrap_err();
        assert!(error.contains("checked layout"), "{error}");

        let mut removed = record;
        removed.dispatch.as_mut().unwrap().fields.pop();
        let error = removed
            .validate(&recorder.manifest, recorder.limits)
            .unwrap_err();
        assert!(error.contains("complete checked request layout"), "{error}");
    }

    #[test]
    fn live_stops_decode_one_exact_entry_dispatch_return_record() {
        let manifest = service_manifest().unwrap();
        let image_base = 0xffff_f807_0000_0000_u64;
        let request = 0xffff_8000_0000_2000;
        let stack = 0xffff_8000_0000_3000;
        let caller = image_base + 0x2200;
        let mut memory = FakeMemory::default();
        memory.put(stack, &caller.to_le_bytes());
        let mut request_bytes = vec![0x11_u8; manifest.request_layout.size as usize];
        request_bytes[2..4].copy_from_slice(&47_u16.to_le_bytes());
        memory.put(request, &request_bytes);

        let mut recorder = Recorder::new(
            "sktrace-live-decoder".into(),
            Some("create-0".into()),
            manifest.clone(),
            target(),
            HexU64(image_base),
            TraceLimits::checked(4, 16, 1_024).unwrap(),
        )
        .unwrap();
        let mut decoder =
            ObservationDecoder::new(manifest.clone(), target(), HexU64(image_base)).unwrap();

        let entry = live_stop(
            &manifest,
            image_base,
            "entry",
            1,
            &[
                (RegisterName::Rsp, stack),
                (RegisterName::Rcx, request),
                (RegisterName::Rdx, 2),
                (RegisterName::R8, 3),
                (RegisterName::R9, 4),
            ],
        );
        assert_eq!(
            decoder
                .observe(&mut recorder, &entry, |address, size| {
                    memory.read(address, size)
                })
                .unwrap(),
            DecodedStop {
                phase: ServicePhase::Entry,
                selected: false,
            }
        );
        assert_eq!(recorder.completed_prefix().pending_phase, None);
        assert!(recorder.completed_prefix().records.is_empty());

        // The manifest calls this the before-capture at entry. Change the request before the
        // dispatch stop so a decoder that samples it late cannot pass this test by coincidence.
        request_bytes[..16].fill(0x22);
        request_bytes[2..4].copy_from_slice(&47_u16.to_le_bytes());
        memory.put(request, &request_bytes);

        let dispatch = live_stop(
            &manifest,
            image_base,
            "dispatch",
            2,
            &[(RegisterName::R14, request)],
        );
        assert!(
            decoder
                .observe(&mut recorder, &dispatch, |address, size| {
                    memory.read(address, size)
                })
                .unwrap()
                .selected
        );

        // A generic nested call while the selected handler is in flight stays a private
        // candidate; it cannot truncate the already proved selected call.
        let ambient_request = request + 0x2000;
        let mut ambient_bytes = vec![0_u8; manifest.request_layout.size as usize];
        ambient_bytes[2..4].copy_from_slice(&11_u16.to_le_bytes());
        memory.put(ambient_request, &ambient_bytes);
        decoder
            .observe(
                &mut recorder,
                &live_stop(
                    &manifest,
                    image_base,
                    "entry",
                    3,
                    &[
                        (RegisterName::Rsp, stack),
                        (RegisterName::Rcx, ambient_request),
                        (RegisterName::Rdx, 0),
                        (RegisterName::R8, 0),
                        (RegisterName::R9, 0),
                    ],
                ),
                |address, size| memory.read(address, size),
            )
            .unwrap();

        request_bytes[..16].fill(0x33);
        request_bytes[2..4].copy_from_slice(&47_u16.to_le_bytes());
        memory.put(request, &request_bytes);
        let returned = live_stop(
            &manifest,
            image_base,
            "return",
            4,
            &[(RegisterName::Rax, 0xc000_0001)],
        );
        decoder
            .observe(&mut recorder, &returned, |address, size| {
                memory.read(address, size)
            })
            .unwrap();
        recorder.finish().unwrap();

        let trace = recorder.completed_prefix();
        assert_eq!(trace.records.len(), 1);
        let record = &trace.records[0];
        assert!(record.complete);
        assert_eq!(
            record.entry.as_ref().unwrap().caller.as_ref().unwrap().rva,
            0x2200
        );
        assert_eq!(record.entry.as_ref().unwrap().raw_arguments.r9.0, 4);
        assert_eq!(record.entry.as_ref().unwrap().raw_arguments.rcx.0, request);
        assert_eq!(record.dispatch.as_ref().unwrap().request.0, request);
        assert_eq!(
            record
                .dispatch
                .as_ref()
                .unwrap()
                .fields
                .iter()
                .find(|field| field.name == "service_number")
                .unwrap()
                .value
                .0,
            47
        );
        assert_eq!(record.returned.as_ref().unwrap().status, 0xc000_0001);
        assert_eq!(
            record.dispatch.as_ref().unwrap().buffers_before[0].requested_size,
            16
        );
        assert!(matches!(
            &record.dispatch.as_ref().unwrap().buffers_before[0].bytes,
            BufferState::Measured { data } if data.starts_with("1111")
        ));
        assert!(matches!(
            &record.returned.as_ref().unwrap().buffers_after[0].bytes,
            BufferState::Measured { data } if data.starts_with("3333")
        ));
        assert_ne!(
            record.dispatch.as_ref().unwrap().buffers_before[0].bytes,
            record.returned.as_ref().unwrap().buffers_after[0].bytes
        );
    }

    #[test]
    fn live_decoder_discards_a_nonselected_dispatch_and_its_return() {
        let manifest = service_manifest().unwrap();
        let image_base = 0xffff_f807_0000_0000_u64;
        let request = 0xffff_8000_0000_2000;
        let stack = 0xffff_8000_0000_3000;
        let mut memory = FakeMemory::default();
        memory.put(stack, &(image_base + 0x2200).to_le_bytes());
        let mut request_bytes = vec![0_u8; manifest.request_layout.size as usize];
        request_bytes[2..4].copy_from_slice(&48_u16.to_le_bytes());
        memory.put(request, &request_bytes);
        let mut recorder = Recorder::new(
            "sktrace-nonselected".into(),
            None,
            manifest.clone(),
            target(),
            HexU64(image_base),
            limits(4, 1_024),
        )
        .unwrap();
        let mut decoder =
            ObservationDecoder::new(manifest.clone(), target(), HexU64(image_base)).unwrap();

        for stop in [
            live_stop(
                &manifest,
                image_base,
                "entry",
                10,
                &[
                    (RegisterName::Rsp, stack),
                    (RegisterName::Rcx, request),
                    (RegisterName::Rdx, 0),
                    (RegisterName::R8, 0),
                    (RegisterName::R9, 0),
                ],
            ),
            live_stop(
                &manifest,
                image_base,
                "dispatch",
                11,
                &[(RegisterName::R14, request)],
            ),
            live_stop(
                &manifest,
                image_base,
                "return",
                12,
                &[(RegisterName::Rax, 0)],
            ),
        ] {
            decoder
                .observe(&mut recorder, &stop, |address, size| {
                    memory.read(address, size)
                })
                .unwrap();
        }
        recorder.finish().unwrap();
        let trace = recorder.completed_prefix();
        assert!(trace.records.is_empty());
        assert_eq!(trace.pending_phase, None);
    }

    #[test]
    fn live_decoder_does_not_splice_a_different_entry_request_into_selected_dispatch() {
        let manifest = service_manifest().unwrap();
        let image_base = 0xffff_f807_0000_0000_u64;
        let entry_request = 0xffff_8000_0000_2000;
        let dispatch_request = 0xffff_8000_0000_4000;
        let stack = 0xffff_8000_0000_3000;
        let mut memory = FakeMemory::default();
        memory.put(stack, &(image_base + 0x2200).to_le_bytes());
        for request in [entry_request, dispatch_request] {
            let mut bytes = vec![0_u8; manifest.request_layout.size as usize];
            bytes[2..4].copy_from_slice(&47_u16.to_le_bytes());
            memory.put(request, &bytes);
        }
        let mut recorder = Recorder::new(
            "sktrace-request-change".into(),
            None,
            manifest.clone(),
            target(),
            HexU64(image_base),
            limits(4, 1_024),
        )
        .unwrap();
        let mut decoder =
            ObservationDecoder::new(manifest.clone(), target(), HexU64(image_base)).unwrap();

        decoder
            .observe(
                &mut recorder,
                &live_stop(
                    &manifest,
                    image_base,
                    "entry",
                    15,
                    &[
                        (RegisterName::Rsp, stack),
                        (RegisterName::Rcx, entry_request),
                        (RegisterName::Rdx, 0),
                        (RegisterName::R8, 0),
                        (RegisterName::R9, 0),
                    ],
                ),
                |address, size| memory.read(address, size),
            )
            .unwrap();
        let decoded = decoder
            .observe(
                &mut recorder,
                &live_stop(
                    &manifest,
                    image_base,
                    "dispatch",
                    16,
                    &[(RegisterName::R14, dispatch_request)],
                ),
                |address, size| memory.read(address, size),
            )
            .unwrap();
        assert_eq!(
            decoded,
            DecodedStop {
                phase: ServicePhase::Dispatch,
                selected: true,
            }
        );
        decoder
            .observe(
                &mut recorder,
                &live_stop(
                    &manifest,
                    image_base,
                    "return",
                    17,
                    &[(RegisterName::Rax, 0)],
                ),
                |address, size| memory.read(address, size),
            )
            .unwrap();
        let trace = recorder.completed_prefix();
        assert_eq!(trace.records.len(), 1);
        assert_eq!(
            trace.records[0].incomplete_reason,
            Some(IncompleteReason::MissingEntry)
        );
    }

    #[test]
    fn live_decoder_matches_selected_dispatch_to_an_earlier_private_entry_candidate() {
        let manifest = service_manifest().unwrap();
        let image_base = 0xffff_f807_0000_0000_u64;
        let selected_request = 0xffff_8000_0000_2000;
        let newer_request = 0xffff_8000_0000_4000;
        let stack = 0xffff_8000_0000_3000;
        let mut memory = FakeMemory::default();
        memory.put(stack, &(image_base + 0x2200).to_le_bytes());
        for (request, service) in [(selected_request, 47_u16), (newer_request, 11_u16)] {
            let mut bytes = vec![0_u8; manifest.request_layout.size as usize];
            bytes[2..4].copy_from_slice(&service.to_le_bytes());
            memory.put(request, &bytes);
        }
        let mut recorder = Recorder::new(
            "sktrace-nested-entry-candidates".into(),
            None,
            manifest.clone(),
            target(),
            HexU64(image_base),
            limits(4, 1_024),
        )
        .unwrap();
        let mut decoder =
            ObservationDecoder::new(manifest.clone(), target(), HexU64(image_base)).unwrap();

        for (epoch, request) in [(30, selected_request), (31, newer_request)] {
            decoder
                .observe(
                    &mut recorder,
                    &live_stop(
                        &manifest,
                        image_base,
                        "entry",
                        epoch,
                        &[
                            (RegisterName::Rsp, stack),
                            (RegisterName::Rcx, request),
                            (RegisterName::Rdx, 0),
                            (RegisterName::R8, 0),
                            (RegisterName::R9, 0),
                        ],
                    ),
                    |address, size| memory.read(address, size),
                )
                .unwrap();
        }
        for stop in [
            live_stop(
                &manifest,
                image_base,
                "dispatch",
                32,
                &[(RegisterName::R14, selected_request)],
            ),
            live_stop(
                &manifest,
                image_base,
                "return",
                33,
                &[(RegisterName::Rax, 0)],
            ),
        ] {
            decoder
                .observe(&mut recorder, &stop, |address, size| {
                    memory.read(address, size)
                })
                .unwrap();
        }

        let trace = recorder.completed_prefix();
        assert_eq!(trace.records.len(), 1);
        assert!(trace.records[0].complete);
        assert_eq!(
            trace.records[0].entry.as_ref().unwrap().raw_arguments.rcx,
            HexU64(selected_request)
        );
    }

    #[test]
    fn live_decoder_names_entry_capture_unavailable_for_an_out_of_order_dispatch() {
        let manifest = service_manifest().unwrap();
        let image_base = 0xffff_f807_0000_0000_u64;
        let request = 0xffff_8000_0000_2000;
        let mut memory = FakeMemory::default();
        let mut bytes = vec![0_u8; manifest.request_layout.size as usize];
        bytes[2..4].copy_from_slice(&47_u16.to_le_bytes());
        memory.put(request, &bytes);
        let mut recorder = Recorder::new(
            "sktrace-missing-entry".into(),
            None,
            manifest.clone(),
            target(),
            HexU64(image_base),
            limits(4, 1_024),
        )
        .unwrap();
        let mut decoder =
            ObservationDecoder::new(manifest.clone(), target(), HexU64(image_base)).unwrap();

        decoder
            .observe(
                &mut recorder,
                &live_stop(
                    &manifest,
                    image_base,
                    "dispatch",
                    17,
                    &[(RegisterName::R14, request)],
                ),
                |address, size| memory.read(address, size),
            )
            .unwrap();
        decoder
            .observe(
                &mut recorder,
                &live_stop(
                    &manifest,
                    image_base,
                    "return",
                    18,
                    &[(RegisterName::Rax, 0)],
                ),
                |address, size| memory.read(address, size),
            )
            .unwrap();
        let trace = recorder.completed_prefix();
        assert_eq!(trace.records.len(), 1);
        assert_eq!(
            trace.records[0].incomplete_reason,
            Some(IncompleteReason::MissingEntry)
        );
        assert!(matches!(
            &trace.records[0].dispatch.as_ref().unwrap().buffers_before[0].bytes,
            BufferState::Unavailable { failure }
                if failure.message.contains("entry phase was not observed")
        ));
    }

    #[test]
    fn live_decoder_refuses_a_changed_stop_guard_before_recording_it() {
        let manifest = service_manifest().unwrap();
        let image_base = 0xffff_f807_0000_0000_u64;
        let mut stop = live_stop(
            &manifest,
            image_base,
            "entry",
            20,
            &[
                (RegisterName::Rsp, 0xffff_8000_0000_3000),
                (RegisterName::Rcx, 0),
                (RegisterName::Rdx, 0),
                (RegisterName::R8, 0),
                (RegisterName::R9, 0),
            ],
        );
        stop.instruction.bytes[0] ^= 1;
        let mut recorder = recorder(4, 1_024);
        let mut decoder = ObservationDecoder::new(manifest, target(), HexU64(image_base)).unwrap();
        let error = decoder
            .observe(&mut recorder, &stop, |_, _| Ok(Vec::new()))
            .unwrap_err();
        assert!(error.contains("no longer matches"), "{error}");
        assert!(recorder.completed_prefix().records.is_empty());
        assert_eq!(recorder.completed_prefix().pending_phase, None);
    }

    #[test]
    fn shared_trace_stop_has_one_linearization_point_and_finishes_idempotently() {
        use std::sync::{Arc, Barrier};

        let shared = SharedTrace::new(recorder(4, 1_024));
        let trace_id = shared.armed().trace_id;
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let shared = shared.clone();
            let trace_id = trace_id.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                shared.request_stop(&trace_id).unwrap()
            }));
        }
        barrier.wait();
        let mut outcomes = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        outcomes.sort_by_key(|outcome| match outcome {
            StopRequest::First => 0,
            StopRequest::AlreadyRequested => 1,
            StopRequest::Finished => 2,
        });
        assert_eq!(
            outcomes,
            vec![StopRequest::First, StopRequest::AlreadyRequested]
        );
        assert!(shared.stop_requested());

        let first = shared.finish().unwrap();
        let second = shared.finish().unwrap();
        assert_eq!(first, second);
        assert!(!first.armed);
        assert_eq!(
            shared.request_stop(&trace_id).unwrap(),
            StopRequest::Finished
        );
    }

    #[test]
    fn shared_trace_read_refuses_a_stale_id_without_changing_the_trace() {
        let shared = SharedTrace::new(recorder(4, 1_024));
        let before = shared.armed();
        assert!(shared.snapshot("sktrace-stale").is_err());
        assert!(shared.request_stop("sktrace-stale").is_err());
        let after = shared.snapshot(&before.trace_id).unwrap();
        assert!(after.armed);
        assert!(!shared.stop_requested());
    }

    #[test]
    fn a_stop_linearized_before_an_observation_consumes_no_epoch() {
        let shared = SharedTrace::new(recorder(4, 1_024));
        let trace_id = shared.armed().trace_id;
        assert_eq!(shared.request_stop(&trace_id).unwrap(), StopRequest::First);
        let error = shared
            .observe(|recorder| recorder.observe_entry(target().expected_cr3, entry()))
            .unwrap_err();
        assert!(error.contains("linearized before"), "{error}");
        let trace = shared.finish().unwrap();
        assert!(trace.records.is_empty());
        assert_eq!(trace.pending_phase, None);
    }

    #[test]
    fn a_stop_arriving_after_decode_but_before_apply_discards_the_observation() {
        let shared = SharedTrace::new(recorder(4, 1_024));
        let trace_id = shared.armed().trace_id;
        let decoded = DecodedObservation {
            stop: DecodedStop {
                phase: ServicePhase::Dispatch,
                selected: true,
            },
            event: Some(DecodedEvent::Dispatch {
                cr3: target().expected_cr3,
                service: 47,
                dispatch: Box::new(dispatch()),
                matched_entry: Some(Box::new((target().expected_cr3, entry()))),
            }),
        };

        assert_eq!(shared.request_stop(&trace_id).unwrap(), StopRequest::First);
        let error = shared
            .observe(|recorder| decoded.apply(recorder))
            .unwrap_err();
        assert!(error.contains("linearized before"), "{error}");
        let trace = shared.finish().unwrap();
        assert!(trace.records.is_empty());
        assert_eq!(trace.pending_phase, None);
    }

    #[test]
    fn drafted_arguments_enforce_every_documented_bound() {
        let defaults = TraceArgs {
            epoch: StopEpoch::new("epoch-0000000000000000").unwrap(),
            label: None,
            max_calls: None,
            per_buffer_bytes: None,
            total_capture_bytes: None,
            session_id: None,
        };
        let (_, limits) = defaults.checked().unwrap();
        assert_eq!(limits.records, 64);
        assert_eq!(limits.per_buffer_bytes, 64);
        assert_eq!(limits.total_capture_bytes, 512 * 1_024);

        for invalid in [
            TraceArgs {
                max_calls: Some(0),
                ..defaults.clone()
            },
            TraceArgs {
                per_buffer_bytes: Some(MAX_BUFFER_BYTES + 1),
                ..defaults.clone()
            },
            TraceArgs {
                total_capture_bytes: Some(MAX_CAPTURE_BYTES + 1),
                ..defaults.clone()
            },
            TraceArgs {
                label: Some("x".repeat(129)),
                ..defaults.clone()
            },
        ] {
            assert!(invalid.checked().is_err(), "{invalid:?}");
        }
        assert!(
            TraceReadArgs {
                trace_id: "short".into(),
                stop: None,
                session_id: None,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn standalone_tool_schemas_have_a_pinned_budget() {
        use crate::structured::Outcome;
        use serde_json::json;

        fn bytes(value: &serde_json::Value) -> usize {
            serde_json::to_vec(value).unwrap().len()
        }

        let arm_input = serde_json::to_value(schemars::schema_for!(TraceArgs)).unwrap();
        let read_input = serde_json::to_value(schemars::schema_for!(TraceReadArgs)).unwrap();
        let arm_output =
            serde_json::to_value(crate::schema::constraints_of::<Outcome<ServiceTraceArmed>>())
                .unwrap();
        let read_output =
            serde_json::to_value(crate::schema::constraints_of::<Outcome<ServiceTrace>>()).unwrap();
        let arm_model = json!({
            "name": "sk_service_trace",
            "description": ARM_TOOL_DESCRIPTION,
            "inputSchema": arm_input,
            "annotations": {
                "title": "Trace a Secure Kernel service",
                "readOnlyHint": false,
                "destructiveHint": true,
                "idempotentHint": false,
                "openWorldHint": true
            }
        });
        let read_model = json!({
            "name": "sk_service_trace_read",
            "description": READ_TOOL_DESCRIPTION,
            "inputSchema": read_input,
            "annotations": {
                "title": "Read a Secure Kernel service trace",
                "readOnlyHint": false,
                "destructiveHint": true,
                "idempotentHint": false,
                "openWorldHint": true
            }
        });
        let model = bytes(&arm_model) + bytes(&read_model) + 1;
        let wire = model + bytes(&arm_output) + bytes(&read_output);
        eprintln!("M6 draft surface: model={model} wire={wire}");

        // This conservative standalone measurement remains a ratchet beside the registered
        // tools/list golden, whose shared schema definitions make its exact delta smaller.
        assert_eq!(model, 2_937);
        assert_eq!(wire, 15_124);
    }
}
