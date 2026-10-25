//! Pure M7 cross-layer admission and correlation primitives.
//!
//! This module owns no debugger, session or provider. The live coordinator feeds it serialized
//! records from the three existing workers; keeping identity and clock decisions here makes them
//! exhaustively testable without a target and prevents a fourth engine role from appearing.

#![allow(dead_code)] // M7 is driven through a hidden role; some join types land before M7.2 uses them.

use std::io::Write as _;

use anyhow::{Context as _, anyhow};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::structured::HostQpcSample;

pub(crate) const CAPTURE_SCHEMA: &str = "windbg-mcp.sk-correlation-capture.v1";
pub(crate) const TRANSACTION_PROTOCOL_FLAG: &str = "--m7-transaction-protocol";
const TRANSACTION_PROTOCOL_SCHEMA: &str = "windbg-mcp.m7-transaction-protocol.v1";
const TRANSACTION_PROTOCOL_RESPONSE_SCHEMA: &str = "windbg-mcp.m7-transaction-protocol-response.v1";

/// Profile and exact-image binding for one independently owned trace layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayerBinding {
    pub(crate) profile: String,
    /// SHA-256 of the canonical exact-image identity carried by that layer's arm response.
    pub(crate) image_identity_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayerBindings {
    pub(crate) m4_vtl0: LayerBinding,
    pub(crate) m5_hypervisor: LayerBinding,
    pub(crate) m6_vtl1: LayerBinding,
}

/// Where the M4 workload and M6 Secure Kernel execute relative to the hypervisor observed by M5.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WorkloadPlacement {
    HypervisorRoot,
    ChildPartition,
}

/// The boundary from which M5 observes the hypervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum M5HypervisorProvider {
    GuestNested,
    ExternalL0,
}

/// The boundary from which M6 controls the workload's VTL1 state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum M6Vtl1Provider {
    OuterVmwp,
    NestedParent,
}

/// Measured target shape that determines whether all three M7 layers refer to one live topology.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetShape {
    pub(crate) nested_virtualization: bool,
    pub(crate) guest_hypervisor_started: bool,
    pub(crate) workload_placement: WorkloadPlacement,
    pub(crate) outer_partition_vtl1: bool,
    pub(crate) nested_child_vtl1: bool,
    pub(crate) m5_provider: M5HypervisorProvider,
    pub(crate) m6_provider: M6Vtl1Provider,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LayerUnavailableReason {
    M5GuestProviderNeedsNestedHypervisor,
    M5ExternalProviderNeedsRootWorkload,
    M5ExternalProviderCannotObserveNestedHypervisor,
    M6OuterProviderNeedsRootWorkload,
    M6OuterPartitionHasNoVtl1,
    M6NestedProviderNeedsNestedHypervisor,
    M6NestedProviderNeedsChildWorkload,
    M6NestedChildHasNoVtl1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LayerUnavailability {
    pub(crate) layer: Layer,
    pub(crate) reason: LayerUnavailableReason,
}

impl TargetShape {
    /// Return every layer unavailable in this exact live topology. M4 remains available at either
    /// workload placement, so only M5 and M6 need provider-boundary admission here.
    pub(crate) fn unavailable_layers(&self) -> Vec<LayerUnavailability> {
        let mut unavailable = Vec::new();
        match self.m5_provider {
            M5HypervisorProvider::GuestNested
                if !self.nested_virtualization || !self.guest_hypervisor_started =>
            {
                unavailable.push(LayerUnavailability {
                    layer: Layer::M5Hypervisor,
                    reason: LayerUnavailableReason::M5GuestProviderNeedsNestedHypervisor,
                });
            }
            M5HypervisorProvider::ExternalL0
                if self.workload_placement != WorkloadPlacement::HypervisorRoot =>
            {
                unavailable.push(LayerUnavailability {
                    layer: Layer::M5Hypervisor,
                    reason: LayerUnavailableReason::M5ExternalProviderNeedsRootWorkload,
                });
            }
            M5HypervisorProvider::ExternalL0 if self.nested_virtualization => {
                unavailable.push(LayerUnavailability {
                    layer: Layer::M5Hypervisor,
                    reason: LayerUnavailableReason::M5ExternalProviderCannotObserveNestedHypervisor,
                });
            }
            M5HypervisorProvider::GuestNested | M5HypervisorProvider::ExternalL0 => {}
        }
        match self.m6_provider {
            M6Vtl1Provider::OuterVmwp
                if self.workload_placement != WorkloadPlacement::HypervisorRoot =>
            {
                unavailable.push(LayerUnavailability {
                    layer: Layer::M6Vtl1,
                    reason: LayerUnavailableReason::M6OuterProviderNeedsRootWorkload,
                });
            }
            M6Vtl1Provider::OuterVmwp if !self.outer_partition_vtl1 => {
                unavailable.push(LayerUnavailability {
                    layer: Layer::M6Vtl1,
                    reason: LayerUnavailableReason::M6OuterPartitionHasNoVtl1,
                });
            }
            M6Vtl1Provider::NestedParent
                if !self.nested_virtualization || !self.guest_hypervisor_started =>
            {
                unavailable.push(LayerUnavailability {
                    layer: Layer::M6Vtl1,
                    reason: LayerUnavailableReason::M6NestedProviderNeedsNestedHypervisor,
                });
            }
            M6Vtl1Provider::NestedParent
                if self.workload_placement != WorkloadPlacement::ChildPartition =>
            {
                unavailable.push(LayerUnavailability {
                    layer: Layer::M6Vtl1,
                    reason: LayerUnavailableReason::M6NestedProviderNeedsChildWorkload,
                });
            }
            M6Vtl1Provider::NestedParent if !self.nested_child_vtl1 => {
                unavailable.push(LayerUnavailability {
                    layer: Layer::M6Vtl1,
                    reason: LayerUnavailableReason::M6NestedChildHasNoVtl1,
                });
            }
            M6Vtl1Provider::OuterVmwp | M6Vtl1Provider::NestedParent => {}
        }
        unavailable
    }
}

/// Identity of the L1 parent that owns a child workload's `vmwp` and provider boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ParentIdentity {
    pub(crate) vm_id: String,
    pub(crate) guest_boot_identity: String,
    pub(crate) vmwp_pid: u32,
}

/// Coordinator-owned capture identity. None of these fields is presented as target-measured by
/// an individual layer; the coordinator observes and freezes them before opening the transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureIdentity {
    pub(crate) schema: String,
    pub(crate) capture_id: String,
    pub(crate) vm_id: String,
    pub(crate) guest_boot_identity: String,
    pub(crate) vmwp_pid: u32,
    pub(crate) parent: Option<ParentIdentity>,
    pub(crate) workload_label: String,
    pub(crate) processor_count: u32,
    pub(crate) target_shape: TargetShape,
    pub(crate) layers: LayerBindings,
}

impl CaptureIdentity {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema != CAPTURE_SCHEMA {
            return Err(format!("unsupported M7 capture schema {}", self.schema));
        }
        for (name, value) in [
            ("capture_id", self.capture_id.as_str()),
            ("vm_id", self.vm_id.as_str()),
            ("guest_boot_identity", self.guest_boot_identity.as_str()),
            ("workload_label", self.workload_label.as_str()),
        ] {
            if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                return Err(format!("{name} must contain 1 through 128 printable bytes"));
            }
        }
        if self.vmwp_pid == 0 {
            return Err("vmwp_pid must be nonzero".into());
        }
        match (&self.target_shape.workload_placement, &self.parent) {
            (WorkloadPlacement::ChildPartition, Some(parent)) => {
                for (name, value) in [
                    ("parent.vm_id", parent.vm_id.as_str()),
                    (
                        "parent.guest_boot_identity",
                        parent.guest_boot_identity.as_str(),
                    ),
                ] {
                    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
                    {
                        return Err(format!("{name} must contain 1 through 128 printable bytes"));
                    }
                }
                if parent.vmwp_pid == 0 {
                    return Err("parent.vmwp_pid must be nonzero".into());
                }
                if parent.vm_id == self.vm_id {
                    return Err("parent.vm_id must differ from the child workload vm_id".into());
                }
            }
            (WorkloadPlacement::ChildPartition, None) => {
                return Err("a child-partition workload requires its parent identity".into());
            }
            (WorkloadPlacement::HypervisorRoot, Some(_)) => {
                return Err("a hypervisor-root workload must not carry a parent identity".into());
            }
            (WorkloadPlacement::HypervisorRoot, None) => {}
        }
        if self.processor_count != 1 {
            return Err(format!(
                "M7 admits exactly one runnable processor, observed {}",
                self.processor_count
            ));
        }
        let unavailable = self.target_shape.unavailable_layers();
        if !unavailable.is_empty() {
            return Err(format!(
                "M7 target shape does not expose all three layers in one live topology: {unavailable:?}"
            ));
        }
        for (name, layer) in [
            ("m4_vtl0", &self.layers.m4_vtl0),
            ("m5_hypervisor", &self.layers.m5_hypervisor),
            ("m6_vtl1", &self.layers.m6_vtl1),
        ] {
            if layer.profile.is_empty()
                || layer.profile.len() > 128
                || layer.profile.chars().any(char::is_control)
            {
                return Err(format!(
                    "{name} profile is not a printable bounded identity"
                ));
            }
            if layer.image_identity_sha256.len() != 64
                || !layer
                    .image_identity_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(format!(
                    "{name} image identity must be one lowercase SHA-256 digest"
                ));
            }
        }
        Ok(())
    }
}

/// Every identity field that changed between preflight and the last arm acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityDrift {
    pub(crate) fields: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IdentityAdmissionError {
    Drift(IdentityDrift),
    Invalid(String),
}

/// Freeze the preflight identity only if the arm-time observation is exactly the same capture.
pub(crate) fn admit_identity(
    preflight: &CaptureIdentity,
    armed: &CaptureIdentity,
) -> Result<(), IdentityAdmissionError> {
    let mut fields = Vec::new();
    macro_rules! changed {
        ($field:literal, $left:expr, $right:expr) => {
            if $left != $right {
                fields.push($field.to_string());
            }
        };
    }
    changed!("schema", preflight.schema, armed.schema);
    changed!("capture_id", preflight.capture_id, armed.capture_id);
    changed!("vm_id", preflight.vm_id, armed.vm_id);
    changed!(
        "guest_boot_identity",
        preflight.guest_boot_identity,
        armed.guest_boot_identity
    );
    changed!("vmwp_pid", preflight.vmwp_pid, armed.vmwp_pid);
    if preflight.parent.is_some() != armed.parent.is_some() {
        fields.push("parent".to_string());
    } else {
        changed!(
            "parent.vm_id",
            preflight.parent.as_ref().map(|parent| &parent.vm_id),
            armed.parent.as_ref().map(|parent| &parent.vm_id)
        );
        changed!(
            "parent.guest_boot_identity",
            preflight
                .parent
                .as_ref()
                .map(|parent| &parent.guest_boot_identity),
            armed
                .parent
                .as_ref()
                .map(|parent| &parent.guest_boot_identity)
        );
        changed!(
            "parent.vmwp_pid",
            preflight.parent.as_ref().map(|parent| parent.vmwp_pid),
            armed.parent.as_ref().map(|parent| parent.vmwp_pid)
        );
    }
    changed!(
        "workload_label",
        preflight.workload_label,
        armed.workload_label
    );
    changed!(
        "processor_count",
        preflight.processor_count,
        armed.processor_count
    );
    changed!(
        "target_shape.nested_virtualization",
        preflight.target_shape.nested_virtualization,
        armed.target_shape.nested_virtualization
    );
    changed!(
        "target_shape.guest_hypervisor_started",
        preflight.target_shape.guest_hypervisor_started,
        armed.target_shape.guest_hypervisor_started
    );
    changed!(
        "target_shape.workload_placement",
        preflight.target_shape.workload_placement,
        armed.target_shape.workload_placement
    );
    changed!(
        "target_shape.outer_partition_vtl1",
        preflight.target_shape.outer_partition_vtl1,
        armed.target_shape.outer_partition_vtl1
    );
    changed!(
        "target_shape.nested_child_vtl1",
        preflight.target_shape.nested_child_vtl1,
        armed.target_shape.nested_child_vtl1
    );
    changed!(
        "target_shape.m5_provider",
        preflight.target_shape.m5_provider,
        armed.target_shape.m5_provider
    );
    changed!(
        "target_shape.m6_provider",
        preflight.target_shape.m6_provider,
        armed.target_shape.m6_provider
    );
    changed!(
        "layers.m4_vtl0.profile",
        preflight.layers.m4_vtl0.profile,
        armed.layers.m4_vtl0.profile
    );
    changed!(
        "layers.m4_vtl0.image_identity_sha256",
        preflight.layers.m4_vtl0.image_identity_sha256,
        armed.layers.m4_vtl0.image_identity_sha256
    );
    changed!(
        "layers.m5_hypervisor.profile",
        preflight.layers.m5_hypervisor.profile,
        armed.layers.m5_hypervisor.profile
    );
    changed!(
        "layers.m5_hypervisor.image_identity_sha256",
        preflight.layers.m5_hypervisor.image_identity_sha256,
        armed.layers.m5_hypervisor.image_identity_sha256
    );
    changed!(
        "layers.m6_vtl1.profile",
        preflight.layers.m6_vtl1.profile,
        armed.layers.m6_vtl1.profile
    );
    changed!(
        "layers.m6_vtl1.image_identity_sha256",
        preflight.layers.m6_vtl1.image_identity_sha256,
        armed.layers.m6_vtl1.image_identity_sha256
    );
    if !fields.is_empty() {
        return Err(IdentityAdmissionError::Drift(IdentityDrift { fields }));
    }
    preflight
        .validate()
        .map_err(IdentityAdmissionError::Invalid)?;
    armed.validate().map_err(IdentityAdmissionError::Invalid)
}

/// Coordinator samples bracketing one arm or read RPC, plus the sample the worker returned from
/// inside that call. `worker = None` is how an old record or unavailable QPC remains explicit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RpcClockBracket {
    pub(crate) layer: String,
    pub(crate) operation: String,
    pub(crate) coordinator_before: HostQpcSample,
    pub(crate) worker: Option<HostQpcSample>,
    pub(crate) coordinator_after: HostQpcSample,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClockMode {
    Point,
    IntervalOnly,
}

/// The clock authority retained in an M7 capture. A degraded result still carries every measured
/// interval and why point ordering was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClockAdmission {
    pub(crate) mode: ClockMode,
    pub(crate) frequency: Option<u64>,
    pub(crate) resolution_ns: Option<u64>,
    pub(crate) max_skew_ticks: u64,
    pub(crate) reasons: Vec<String>,
    pub(crate) brackets: Vec<RpcClockBracket>,
}

/// Check whether raw QPC points are authoritative for this capture.
///
/// Invalid coordinator intervals are rejected outright. Missing worker samples, frequency drift,
/// samples outside their RPC bracket, or a bracket wider than the declared skew bound retain an
/// interval-only result rather than manufacturing a point order.
pub(crate) fn admit_clock(
    brackets: Vec<RpcClockBracket>,
    max_skew_ticks: u64,
) -> Result<ClockAdmission, String> {
    if brackets.is_empty() {
        return Err("M7 clock admission needs at least one bracketed RPC".into());
    }
    let mut frequency = None;
    let mut reasons = Vec::new();
    for bracket in &brackets {
        if bracket.layer.is_empty() || bracket.operation.is_empty() {
            return Err("clock brackets need a layer and operation".into());
        }
        if bracket.coordinator_before.tick > bracket.coordinator_after.tick {
            return Err(format!(
                "{}.{} coordinator clock moved backwards",
                bracket.layer, bracket.operation
            ));
        }
        let expected = *frequency.get_or_insert(bracket.coordinator_before.frequency);
        for (source, sample) in [
            ("coordinator_before", Some(bracket.coordinator_before)),
            ("worker", bracket.worker),
            ("coordinator_after", Some(bracket.coordinator_after)),
        ] {
            match sample {
                Some(sample) if sample.frequency == expected && sample.frequency != 0 => {}
                Some(_) => reasons.push(format!(
                    "{}.{}.{source}: frequency_mismatch",
                    bracket.layer, bracket.operation
                )),
                None => reasons.push(format!(
                    "{}.{}.{source}: unavailable",
                    bracket.layer, bracket.operation
                )),
            }
        }
        let width = bracket
            .coordinator_after
            .tick
            .saturating_sub(bracket.coordinator_before.tick);
        if width > max_skew_ticks {
            reasons.push(format!(
                "{}.{}: bracket_exceeds_skew",
                bracket.layer, bracket.operation
            ));
        }
        if let Some(worker) = bracket.worker
            && (worker.tick < bracket.coordinator_before.tick
                || worker.tick > bracket.coordinator_after.tick)
        {
            reasons.push(format!(
                "{}.{}: worker_outside_bracket",
                bracket.layer, bracket.operation
            ));
        }
    }
    reasons.sort();
    reasons.dedup();
    let point = reasons.is_empty();
    let frequency = point.then_some(frequency.expect("a nonempty bracket set has a frequency"));
    let resolution_ns = frequency.map(|frequency| 1_000_000_000_u64.div_ceil(frequency));
    Ok(ClockAdmission {
        mode: if point {
            ClockMode::Point
        } else {
            ClockMode::IntervalOnly
        },
        frequency,
        resolution_ns,
        max_skew_ticks,
        reasons,
        brackets,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntervalOrder {
    Before,
    After,
    Overlap,
}

/// Conservative order for coordinator-measured intervals. Touching intervals overlap: they do
/// not prove which operation occurred first.
pub(crate) fn interval_order(
    left: &RpcClockBracket,
    right: &RpcClockBracket,
) -> Result<IntervalOrder, String> {
    if left.coordinator_before.frequency != right.coordinator_before.frequency
        || left.coordinator_before.frequency != left.coordinator_after.frequency
        || right.coordinator_before.frequency != right.coordinator_after.frequency
    {
        return Err("cannot compare RPC intervals with different QPC frequencies".into());
    }
    Ok(
        if left.coordinator_after.tick < right.coordinator_before.tick {
            IntervalOrder::Before
        } else if right.coordinator_after.tick < left.coordinator_before.tick {
            IntervalOrder::After
        } else {
            IntervalOrder::Overlap
        },
    )
}

pub(crate) const TRANSACTION_SCHEMA: &str = "windbg-mcp.sk-correlation-transaction.v1";

/// The three independently owned debugger layers in one M7 capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Layer {
    M4Vtl0,
    M5Hypervisor,
    M6Vtl1,
}

impl Layer {
    const ALL: [Self; 3] = [Self::M4Vtl0, Self::M5Hypervisor, Self::M6Vtl1];

    fn wire_name(self) -> &'static str {
        match self {
            Self::M4Vtl0 => "m4_vtl0",
            Self::M5Hypervisor => "m5_hypervisor",
            Self::M6Vtl1 => "m6_vtl1",
        }
    }
}

/// The hypervisor is armed last and drained first. A hypervisor held by its debugger holds every
/// partition beneath it, so nothing under M5 can be opened, armed, drained or ended while M5 is
/// stopped: M4 and M6 are put in place while the hypervisor runs, M5 is armed immediately before
/// the workload, and the reverse order drains and releases M5 first, which is what makes the
/// hypervisor run again for the drains and ends beneath it. Measured 2026-10-24 with the order the
/// other way round: M5's trace reached its cap two seconds after arming and froze the parent and
/// child before M6 could register its trigger or M4 could break in.
///
/// M6 is armed before M4 and drained after it. The child VP's DR0-DR3 are one set shared across
/// VTLs and only DR7 is per VTL (measured 2026-10-24), so the two layers partition the slots: M4's
/// VTL0 debugger holds slot 0 and M6 reserves it (`reserved_hardware_slots: [0]`), arming its
/// sites in slots 1-3. The kernel debugger writes the whole debug-register block back from its
/// cache at every stop, so M6's slot writes must never overlap a VTL0 debugger stop: M6 arms while
/// M4 is not yet armed and disarms after M4 has been drained, and its per-event writes happen while
/// the VP is held in VTL1, where no VTL0 stop can be in progress.
pub(crate) const ARM_ORDER: [Layer; 3] = [Layer::M6Vtl1, Layer::M4Vtl0, Layer::M5Hypervisor];

/// The windows of the alternating plan, M7.1's idle gate as revised 2026-10-25. The VTL1
/// dispatcher's exception intercept is per partition, not per VTL, so a VTL0 kernel debugger's
/// break-in, breakpoint hit or single step raises through M6's handler while it is registered,
/// and no root-side way to hand the exception back has been demonstrated: M4 and M6 cannot share
/// a VP in one window. So M6 is armed, drained and closed on its own, M4 then opens with M5 after
/// it (M5 keeps its place last, as [`ARM_ORDER`] says why), and M6 reopens once M4 has closed.
/// Each switch is a [`TransactionDriver::transition`] the next window waits on.
pub(crate) const ALTERNATING_WINDOWS: [&[Layer]; 3] = [
    &[Layer::M6Vtl1],
    &[Layer::M4Vtl0, Layer::M5Hypervisor],
    &[Layer::M6Vtl1],
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransactionState {
    Preflight,
    Opening,
    Armed,
    Workload,
    Draining,
    Restoring,
    /// Between two windows of an alternating plan: the closed window's instruments are proved
    /// gone before the next window opens.
    Transition,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransactionVerdict {
    Pass,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum Attempt<T> {
    Succeeded {
        value: T,
    },
    Failed {
        message: String,
        /// An opener can fail after the supervisor has minted the only handle that can reach its
        /// worker. Other operations leave this absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery: Option<RecoveryHandle>,
    },
    TimedOut {
        timeout_ms: u64,
        /// A caller-side timeout must retain a session handle if the public opener returned one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery: Option<RecoveryHandle>,
    },
}

impl<T> Attempt<T> {
    fn succeeded(&self) -> Option<&T> {
        match self {
            Self::Succeeded { value } => Some(value),
            Self::Failed { .. } | Self::TimedOut { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryHandle {
    pub(crate) session_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpenAck {
    pub(crate) session_id: String,
}

impl Attempt<OpenAck> {
    fn cleanup_session(&self) -> Option<OpenAck> {
        match self {
            Self::Succeeded { value } => Some(value.clone()),
            Self::Failed {
                recovery: Some(handle),
                ..
            }
            | Self::TimedOut {
                recovery: Some(handle),
                ..
            } => Some(OpenAck {
                session_id: handle.session_id.clone(),
            }),
            Self::Failed { recovery: None, .. } | Self::TimedOut { recovery: None, .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArmAck {
    pub(crate) trace_id: String,
    /// The instrument is armed and its worker has completed the layer-specific transition needed
    /// before a guest workload may start (for example, resuming a stopped KD target).
    pub(crate) workload_ready: bool,
    pub(crate) identity: CaptureIdentity,
    pub(crate) clock: RpcClockBracket,
}

/// Final child state returned by a stopping trace read. A clean result proves both that capture
/// has stopped and that the layer-specific patch/event/register baseline has been restored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestorationAudit {
    pub(crate) restored: bool,
    pub(crate) running: bool,
    pub(crate) held: bool,
    pub(crate) dropped_records: u64,
    pub(crate) dropped_bytes: u64,
    pub(crate) unreadable_fields: u64,
}

impl RestorationAudit {
    fn clean(&self) -> bool {
        self.restored
            && !self.running
            && !self.held
            && self.dropped_records == 0
            && self.dropped_bytes == 0
            && self.unreadable_fields == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DrainAck {
    pub(crate) audit: RestorationAudit,
    pub(crate) clock: RpcClockBracket,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EndAck {
    pub(crate) ended: bool,
    pub(crate) retained_processes: u32,
}

/// What the adapter read between two windows of an alternating plan, after the closed window's
/// sessions ended and before the next window's open. Every field is a reading, not a promise:
/// the handler state comes from `vmwp`, the slots, pending state and trap flag from the
/// hypervisor through the parent, and the worker count from the host's process table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransitionAck {
    /// The VTL1 session's exception handler is gone from `vmwp`: its unregister returned and
    /// the deferred cleanup freed its scratch. `None` when the closed window held no VTL1
    /// session; a closed VTL1 window needs `Some(true)`.
    pub(crate) handler_unregistered: Option<bool>,
    /// Slots VTL1's DR7 enables on the child's VP. Must be empty.
    pub(crate) vtl1_enabled_slots: Vec<u8>,
    /// Slots VTL0's DR7 enables on the child's VP. Must be empty.
    pub(crate) vtl0_enabled_slots: Vec<u8>,
    /// No exception event and no interruption is pending on the VP.
    pub(crate) pending_clear: bool,
    /// The trap flag is clear in both VTLs.
    pub(crate) trap_flag_clear: bool,
    /// Engine workers still running for the child on the layers' host. Must be zero.
    pub(crate) engine_workers: u32,
}

impl TransitionAck {
    /// Everything the next window needs gone, named together so one reading reports every
    /// leftover rather than the first. `closed_vtl1` says whether the window that closed held
    /// the VTL1 session, whose handler must then have been read as unregistered.
    fn clean(&self, closed_vtl1: bool) -> Result<(), String> {
        let mut leftover = Vec::new();
        match self.handler_unregistered {
            Some(true) => {}
            Some(false) => {
                leftover.push("the VTL1 exception handler is still registered".to_string())
            }
            None if closed_vtl1 => {
                leftover.push("the VTL1 exception handler's state was not read".to_string())
            }
            None => {}
        }
        if !self.vtl1_enabled_slots.is_empty() {
            leftover.push(format!(
                "VTL1 DR7 enables slots {:?}",
                self.vtl1_enabled_slots
            ));
        }
        if !self.vtl0_enabled_slots.is_empty() {
            leftover.push(format!(
                "VTL0 DR7 enables slots {:?}",
                self.vtl0_enabled_slots
            ));
        }
        if !self.pending_clear {
            leftover.push("an exception event or interruption is pending on the VP".to_string());
        }
        if !self.trap_flag_clear {
            leftover.push("the trap flag is set in a VTL".to_string());
        }
        if self.engine_workers != 0 {
            leftover.push(format!(
                "{} engine workers still run for the child",
                self.engine_workers
            ));
        }
        if leftover.is_empty() {
            Ok(())
        } else {
            Err(leftover.join("; "))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkloadAck {
    pub(crate) label: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub(crate) enum WorkloadResult {
    SkippedIdle,
    Launched { attempt: Attempt<WorkloadAck> },
    Withheld,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IssueKind {
    Failed,
    TimedOut,
    Invalid,
    UnsafeChild,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransactionIssue {
    pub(crate) state: TransactionState,
    pub(crate) layer: Option<Layer>,
    pub(crate) operation: String,
    pub(crate) kind: IssueKind,
    pub(crate) message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayerReport {
    pub(crate) open: Option<Attempt<OpenAck>>,
    pub(crate) arm: Option<Attempt<ArmAck>>,
    pub(crate) restoration: Option<Attempt<DrainAck>>,
    pub(crate) end: Option<Attempt<EndAck>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayerReports {
    pub(crate) m4_vtl0: LayerReport,
    pub(crate) m5_hypervisor: LayerReport,
    pub(crate) m6_vtl1: LayerReport,
}

impl LayerReports {
    fn get(&self, layer: Layer) -> &LayerReport {
        match layer {
            Layer::M4Vtl0 => &self.m4_vtl0,
            Layer::M5Hypervisor => &self.m5_hypervisor,
            Layer::M6Vtl1 => &self.m6_vtl1,
        }
    }

    fn get_mut(&mut self, layer: Layer) -> &mut LayerReport {
        match layer {
            Layer::M4Vtl0 => &mut self.m4_vtl0,
            Layer::M5Hypervisor => &mut self.m5_hypervisor,
            Layer::M6Vtl1 => &mut self.m6_vtl1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransactionReport {
    pub(crate) schema: String,
    pub(crate) state: TransactionState,
    pub(crate) states: Vec<TransactionState>,
    pub(crate) verdict: TransactionVerdict,
    pub(crate) preflight: Attempt<CaptureIdentity>,
    /// Every layer the plan arms, window by window: [`ARM_ORDER`] for one window, the
    /// concatenation of [`ALTERNATING_WINDOWS`] for the alternating plan, where M6 appears twice.
    pub(crate) arm_order: Vec<Layer>,
    pub(crate) successful_arm_order: Vec<Layer>,
    pub(crate) cleanup_order: Vec<Layer>,
    /// The plan's windows in order.
    pub(crate) windows: Vec<Vec<Layer>>,
    /// One entry per window that ran, holding only that window's layers; `layers` below keeps
    /// each layer's most recent window.
    pub(crate) window_reports: Vec<LayerReports>,
    /// One per switch between windows, in order; absent for a one-window plan.
    pub(crate) transitions: Vec<Attempt<TransitionAck>>,
    pub(crate) workload: WorkloadResult,
    pub(crate) clock: Option<Attempt<ClockAdmission>>,
    pub(crate) layers: LayerReports,
    pub(crate) issues: Vec<TransactionIssue>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TransactionPlan {
    pub(crate) launch_workload: bool,
    pub(crate) max_skew_ticks: u64,
    /// Arm the layers in [`ALTERNATING_WINDOWS`] rather than together in [`ARM_ORDER`]. No
    /// window then holds every layer, so the plan cannot launch a workload.
    pub(crate) alternate: bool,
}

/// The live adapter may call only public MCP operations. In particular, there is deliberately no
/// force-kill callback: a failed stopping read is followed by the public session teardown, whose
/// worker-owned recovery contract remains authoritative.
pub(crate) trait TransactionDriver {
    fn preflight(&mut self) -> Attempt<CaptureIdentity>;
    fn open(&mut self, layer: Layer) -> Attempt<OpenAck>;
    fn arm(
        &mut self,
        layer: Layer,
        session: &OpenAck,
        preflight: &CaptureIdentity,
    ) -> Attempt<ArmAck>;
    fn launch_workload(&mut self, preflight: &CaptureIdentity) -> Attempt<WorkloadAck>;
    fn drain(&mut self, layer: Layer, session: &OpenAck, arm: &ArmAck) -> Attempt<DrainAck>;
    fn end_session(&mut self, layer: Layer, session: &OpenAck) -> Attempt<EndAck>;
    /// Between two windows of an alternating plan, after `closed`'s sessions have ended and
    /// before `opening`'s first open: read what the closed window must have left behind.
    fn transition(&mut self, closed: &[Layer], opening: &[Layer]) -> Attempt<TransitionAck>;
}

#[derive(Serialize)]
struct ProtocolRequest {
    schema: &'static str,
    sequence: u64,
    operation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    layer: Option<Layer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<OpenAck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arm: Option<ArmAck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preflight: Option<CaptureIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_closed: Option<Vec<Layer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_opening: Option<Vec<Layer>>,
}

impl ProtocolRequest {
    fn new(operation: &'static str) -> Self {
        Self {
            schema: TRANSACTION_PROTOCOL_SCHEMA,
            sequence: 0,
            operation,
            layer: None,
            session: None,
            arm: None,
            preflight: None,
            window_closed: None,
            window_opening: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolResponse<T> {
    schema: String,
    sequence: u64,
    attempt: Attempt<T>,
}

struct StdioTransactionDriver {
    sequence: u64,
}

impl StdioTransactionDriver {
    fn exchange<T: DeserializeOwned>(&mut self, mut request: ProtocolRequest) -> Attempt<T> {
        self.sequence += 1;
        request.sequence = self.sequence;
        let exchanged = (|| -> Result<Attempt<T>, String> {
            let encoded = serde_json::to_string(&request).map_err(|error| error.to_string())?;
            println!("{encoded}");
            std::io::stdout()
                .flush()
                .map_err(|error| format!("could not flush M7 request: {error}"))?;
            let mut line = String::new();
            let read = std::io::stdin()
                .read_line(&mut line)
                .map_err(|error| format!("could not read M7 response: {error}"))?;
            if read == 0 {
                return Err("the M7 adapter closed its response stream".into());
            }
            let response: ProtocolResponse<T> = serde_json::from_str(&line)
                .map_err(|error| format!("invalid M7 response: {error}"))?;
            if response.schema != TRANSACTION_PROTOCOL_RESPONSE_SCHEMA {
                return Err(format!(
                    "unsupported M7 response schema {}",
                    response.schema
                ));
            }
            if response.sequence != self.sequence {
                return Err(format!(
                    "M7 response sequence {} did not match request {}",
                    response.sequence, self.sequence
                ));
            }
            Ok(response.attempt)
        })();
        exchanged.unwrap_or_else(|message| Attempt::Failed {
            message,
            recovery: None,
        })
    }
}

impl TransactionDriver for StdioTransactionDriver {
    fn preflight(&mut self) -> Attempt<CaptureIdentity> {
        self.exchange(ProtocolRequest::new("preflight"))
    }

    fn open(&mut self, layer: Layer) -> Attempt<OpenAck> {
        self.exchange(ProtocolRequest {
            layer: Some(layer),
            ..ProtocolRequest::new("open")
        })
    }

    fn arm(
        &mut self,
        layer: Layer,
        session: &OpenAck,
        preflight: &CaptureIdentity,
    ) -> Attempt<ArmAck> {
        self.exchange(ProtocolRequest {
            layer: Some(layer),
            session: Some(session.clone()),
            preflight: Some(preflight.clone()),
            ..ProtocolRequest::new("arm")
        })
    }

    fn launch_workload(&mut self, preflight: &CaptureIdentity) -> Attempt<WorkloadAck> {
        self.exchange(ProtocolRequest {
            preflight: Some(preflight.clone()),
            ..ProtocolRequest::new("workload")
        })
    }

    fn drain(&mut self, layer: Layer, session: &OpenAck, arm: &ArmAck) -> Attempt<DrainAck> {
        self.exchange(ProtocolRequest {
            layer: Some(layer),
            session: Some(session.clone()),
            arm: Some(arm.clone()),
            ..ProtocolRequest::new("drain")
        })
    }

    fn end_session(&mut self, layer: Layer, session: &OpenAck) -> Attempt<EndAck> {
        self.exchange(ProtocolRequest {
            layer: Some(layer),
            session: Some(session.clone()),
            ..ProtocolRequest::new("end_session")
        })
    }

    fn transition(&mut self, closed: &[Layer], opening: &[Layer]) -> Attempt<TransitionAck> {
        self.exchange(ProtocolRequest {
            window_closed: Some(closed.to_vec()),
            window_opening: Some(opening.to_vec()),
            ..ProtocolRequest::new("transition")
        })
    }
}

/// Run the engine-free half of the repository-owned M7 live driver. Each emitted request must be
/// answered by the adapter with one matching JSON line; the final emitted line is the complete
/// transaction report rather than another request.
pub(crate) fn run_transaction_protocol(args: &[String]) -> anyhow::Result<()> {
    let launch_workload = args.iter().any(|argument| argument == "--m7-workload");
    let alternate = args.iter().any(|argument| argument == "--m7-alternate");
    let skew = args
        .iter()
        .find_map(|argument| argument.strip_prefix("--m7-max-skew-ticks="))
        .ok_or_else(|| anyhow!("--m7-max-skew-ticks is required"))?
        .parse::<u64>()
        .context("--m7-max-skew-ticks must be an unsigned integer")?;
    let mut driver = StdioTransactionDriver { sequence: 0 };
    let report = run_transaction(
        TransactionPlan {
            launch_workload,
            max_skew_ticks: skew,
            alternate,
        },
        &mut driver,
    );
    println!("{}", serde_json::to_string(&report)?);
    std::io::stdout().flush()?;
    Ok(())
}

/// Run one M7 transaction. The runner continues every reachable cleanup after a failure and keeps
/// the result of each call in the report, so a serializer never has to reconstruct safety from a
/// log line. A one-window plan opens, arms, drains and ends [`ARM_ORDER`] once; the alternating
/// plan runs [`ALTERNATING_WINDOWS`] one after another with a transition between them, and a
/// window that leaves an issue or a transition that reads anything left behind ends the plan
/// there, after that window's own cleanup.
pub(crate) fn run_transaction<D: TransactionDriver>(
    plan: TransactionPlan,
    driver: &mut D,
) -> TransactionReport {
    let windows: Vec<Vec<Layer>> = if plan.alternate {
        ALTERNATING_WINDOWS
            .iter()
            .map(|window| window.to_vec())
            .collect()
    } else {
        vec![ARM_ORDER.to_vec()]
    };
    let preflight = driver.preflight();
    let mut report = TransactionReport {
        schema: TRANSACTION_SCHEMA.into(),
        state: TransactionState::Preflight,
        states: vec![TransactionState::Preflight],
        verdict: TransactionVerdict::Incomplete,
        preflight,
        arm_order: windows.concat(),
        successful_arm_order: Vec::new(),
        cleanup_order: Vec::new(),
        windows: windows.clone(),
        window_reports: Vec::new(),
        transitions: Vec::new(),
        workload: WorkloadResult::Withheld,
        clock: None,
        layers: LayerReports::default(),
        issues: Vec::new(),
    };

    let identity = match report.preflight.succeeded().cloned() {
        Some(identity) => match identity.validate() {
            Ok(()) => Some(identity),
            Err(message) => {
                report.issue(
                    TransactionState::Preflight,
                    None,
                    "preflight",
                    IssueKind::Invalid,
                    message,
                );
                None
            }
        },
        None => {
            report.issue_from_attempt(
                TransactionState::Preflight,
                None,
                "preflight",
                &report.preflight.clone(),
            );
            None
        }
    };
    if plan.alternate && plan.launch_workload {
        report.issue(
            TransactionState::Preflight,
            None,
            "preflight",
            IssueKind::Invalid,
            "an alternating plan never has every layer armed at once, so it cannot launch a workload"
                .into(),
        );
    }

    let mut brackets = Vec::new();
    let mut opened_total = 0;
    let mut armed_total = 0;
    for (index, window) in windows.iter().enumerate() {
        if index > 0 {
            report.enter(TransactionState::Transition);
            let closed = &windows[index - 1];
            let attempt = driver.transition(closed, window);
            match attempt.succeeded() {
                Some(ack) => {
                    if let Err(message) = ack.clean(closed.contains(&Layer::M6Vtl1)) {
                        report.issue(
                            TransactionState::Transition,
                            None,
                            "transition",
                            IssueKind::UnsafeChild,
                            message,
                        );
                    }
                }
                None => report.issue_from_attempt(
                    TransactionState::Transition,
                    None,
                    "transition",
                    &attempt,
                ),
            }
            report.transitions.push(attempt);
            if !report.issues.is_empty() {
                break;
            }
        }
        let mut layers = LayerReports::default();
        let (opened, armed) = run_window(
            &mut report,
            &mut layers,
            driver,
            &plan,
            window,
            identity.as_ref(),
            &mut brackets,
        );
        opened_total += opened;
        armed_total += armed;
        for layer in window {
            *report.layers.get_mut(*layer) = layers.get(*layer).clone();
        }
        report.window_reports.push(layers);
        if !report.issues.is_empty() {
            break;
        }
    }
    if plan.alternate && report.issues.is_empty() && armed_total == report.arm_order.len() {
        report.workload = WorkloadResult::SkippedIdle;
    }

    if !brackets.is_empty() {
        match admit_clock(brackets, plan.max_skew_ticks) {
            Ok(clock) => report.clock = Some(Attempt::Succeeded { value: clock }),
            Err(message) => {
                report.issue(
                    TransactionState::Restoring,
                    None,
                    "clock_admission",
                    IssueKind::Invalid,
                    message.clone(),
                );
                report.clock = Some(Attempt::Failed {
                    message,
                    recovery: None,
                });
            }
        }
    }

    report.enter(TransactionState::Closed);
    if report.issues.is_empty()
        && opened_total == report.arm_order.len()
        && armed_total == report.arm_order.len()
        && report.transitions.len() + 1 == windows.len()
    {
        report.verdict = TransactionVerdict::Pass;
    }
    report
}

/// One window: open its layers in order, arm them in order, launch the workload if this is the
/// one window of a plan that asked for one, then drain the successful arms in reverse and end
/// every reachable session. Returns how many layers opened and how many armed. `layers` receives
/// this window's results alone; the report's running orders and issues are appended to.
fn run_window<D: TransactionDriver>(
    report: &mut TransactionReport,
    layers: &mut LayerReports,
    driver: &mut D,
    plan: &TransactionPlan,
    window: &[Layer],
    identity: Option<&CaptureIdentity>,
    brackets: &mut Vec<RpcClockBracket>,
) -> (usize, usize) {
    let mut opened = Vec::new();
    let mut armed = Vec::new();
    report.enter(TransactionState::Opening);
    if identity.is_some() && report.issues.is_empty() {
        for layer in window.iter().copied() {
            let attempt = driver.open(layer);
            let succeeded = attempt.succeeded().is_some();
            let cleanup_session = attempt.cleanup_session();
            if cleanup_session
                .as_ref()
                .is_some_and(|open| open.session_id.is_empty())
            {
                report.issue(
                    TransactionState::Opening,
                    Some(layer),
                    "open",
                    IssueKind::Invalid,
                    "the opened layer returned an empty session id".into(),
                );
            }
            if !succeeded {
                report.issue_from_attempt(TransactionState::Opening, Some(layer), "open", &attempt);
            }
            layers.get_mut(layer).open = Some(attempt);
            if cleanup_session.is_some() {
                opened.push(layer);
            }
            if !succeeded || !report.issues.is_empty() {
                break;
            }
        }
    }

    report.enter(TransactionState::Armed);
    if report.issues.is_empty() && opened.len() == window.len() {
        let identity = identity.expect("validated preflight exists");
        for layer in window.iter().copied() {
            let session = layers
                .get(layer)
                .open
                .as_ref()
                .and_then(Attempt::succeeded)
                .expect("all layers opened before arming")
                .clone();
            let attempt = driver.arm(layer, &session, identity);
            let succeeded = attempt.succeeded().is_some();
            if let Some(arm) = attempt.succeeded() {
                // A successful arm owns an instrument even if its acknowledgement is malformed;
                // retain it in cleanup order before rejecting the transaction.
                report.successful_arm_order.push(layer);
                armed.push(layer);
                brackets.push(arm.clock.clone());
                if arm.trace_id.is_empty() {
                    report.issue(
                        TransactionState::Armed,
                        Some(layer),
                        "arm",
                        IssueKind::Invalid,
                        "the armed layer returned an empty trace id".into(),
                    );
                }
                if !arm.workload_ready {
                    report.issue(
                        TransactionState::Armed,
                        Some(layer),
                        "arm",
                        IssueKind::Invalid,
                        "the armed layer did not acknowledge workload readiness".into(),
                    );
                }
                if arm.clock.layer != layer.wire_name() || arm.clock.operation != "arm" {
                    report.issue(
                        TransactionState::Armed,
                        Some(layer),
                        "arm",
                        IssueKind::Invalid,
                        "the arm clock bracket names a different layer or operation".into(),
                    );
                }
                if let Err(error) = admit_identity(identity, &arm.identity) {
                    report.issue(
                        TransactionState::Armed,
                        Some(layer),
                        "arm_identity",
                        IssueKind::Invalid,
                        format!("{error:?}"),
                    );
                }
            } else {
                report.issue_from_attempt(TransactionState::Armed, Some(layer), "arm", &attempt);
            }
            layers.get_mut(layer).arm = Some(attempt);
            if !succeeded || !report.issues.is_empty() {
                break;
            }
        }
    }

    if !plan.alternate {
        report.enter(TransactionState::Workload);
        if report.issues.is_empty() && armed.len() == window.len() {
            if plan.launch_workload {
                let identity = identity.expect("validated preflight exists");
                let attempt = driver.launch_workload(identity);
                if let Some(workload) = attempt.succeeded()
                    && workload.label != identity.workload_label
                {
                    report.issue(
                        TransactionState::Workload,
                        None,
                        "workload",
                        IssueKind::Invalid,
                        "the workload acknowledgement changed its capture label".into(),
                    );
                } else if attempt.succeeded().is_none() {
                    report.issue_from_attempt(
                        TransactionState::Workload,
                        None,
                        "workload",
                        &attempt,
                    );
                }
                report.workload = WorkloadResult::Launched { attempt };
            } else {
                report.workload = WorkloadResult::SkippedIdle;
            }
        }
    }

    let cleanup = cleanup_order(&armed, &opened);
    report.cleanup_order.extend(cleanup.iter().copied());
    report.enter(TransactionState::Draining);
    for layer in armed.iter().rev().copied() {
        let layer_report = layers.get(layer);
        let session = layer_report
            .open
            .as_ref()
            .and_then(Attempt::succeeded)
            .expect("an armed layer was opened")
            .clone();
        let arm = layer_report
            .arm
            .as_ref()
            .and_then(Attempt::succeeded)
            .expect("successful arm order contains only acknowledgements")
            .clone();
        let attempt = driver.drain(layer, &session, &arm);
        if let Some(drain) = attempt.succeeded() {
            brackets.push(drain.clock.clone());
            if drain.clock.layer != layer.wire_name() || drain.clock.operation != "drain" {
                report.issue(
                    TransactionState::Draining,
                    Some(layer),
                    "drain",
                    IssueKind::Invalid,
                    "the drain clock bracket names a different layer or operation".into(),
                );
            }
            if !drain.audit.clean() {
                report.issue(
                    TransactionState::Draining,
                    Some(layer),
                    "drain",
                    IssueKind::UnsafeChild,
                    "the child remained running, held, dropped, unreadable or unrestored".into(),
                );
            }
        } else {
            report.issue_from_attempt(TransactionState::Draining, Some(layer), "drain", &attempt);
        }
        layers.get_mut(layer).restoration = Some(attempt);
    }

    report.enter(TransactionState::Restoring);
    for layer in cleanup {
        let session = layers
            .get(layer)
            .open
            .as_ref()
            .and_then(Attempt::cleanup_session)
            .expect("cleanup order contains only opened layers");
        let attempt = driver.end_session(layer, &session);
        if let Some(end) = attempt.succeeded() {
            if !end.ended || end.retained_processes != 0 {
                report.issue(
                    TransactionState::Restoring,
                    Some(layer),
                    "end_session",
                    IssueKind::UnsafeChild,
                    "the opened layer did not end cleanly with zero retained processes".into(),
                );
            }
        } else {
            report.issue_from_attempt(
                TransactionState::Restoring,
                Some(layer),
                "end_session",
                &attempt,
            );
        }
        layers.get_mut(layer).end = Some(attempt);
    }
    (opened.len(), armed.len())
}

fn cleanup_order(successful_arms: &[Layer], opened: &[Layer]) -> Vec<Layer> {
    let mut order = successful_arms.iter().rev().copied().collect::<Vec<_>>();
    order.extend(
        opened
            .iter()
            .rev()
            .copied()
            .filter(|layer| !successful_arms.contains(layer)),
    );
    order
}

impl TransactionReport {
    fn enter(&mut self, state: TransactionState) {
        self.state = state;
        self.states.push(state);
    }

    fn issue(
        &mut self,
        state: TransactionState,
        layer: Option<Layer>,
        operation: &str,
        kind: IssueKind,
        message: String,
    ) {
        self.issues.push(TransactionIssue {
            state,
            layer,
            operation: operation.into(),
            kind,
            message,
        });
    }

    fn issue_from_attempt<T>(
        &mut self,
        state: TransactionState,
        layer: Option<Layer>,
        operation: &str,
        attempt: &Attempt<T>,
    ) {
        match attempt {
            Attempt::Succeeded { .. } => {}
            Attempt::Failed { message, .. } => {
                self.issue(state, layer, operation, IssueKind::Failed, message.clone())
            }
            Attempt::TimedOut { timeout_ms, .. } => self.issue(
                state,
                layer,
                operation,
                IssueKind::TimedOut,
                format!("operation exceeded {timeout_ms} ms"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FREQUENCY: u64 = 10_000_000;
    type IdentityMutation = (&'static str, Box<dyn Fn(&mut CaptureIdentity)>);

    fn sample(tick: u64) -> HostQpcSample {
        HostQpcSample {
            tick,
            frequency: FREQUENCY,
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
            capture_id: "capture-00000001".into(),
            vm_id: "e35248f3-d779-44c1-8f69-8a8cc27bc11b".into(),
            guest_boot_identity: "2026-10-24T09:32:31.5773667Z".into(),
            vmwp_pid: 4124,
            parent: Some(ParentIdentity {
                vm_id: "6b1ed0f6-137e-469f-aeab-a3f4cfee398d".into(),
                guest_boot_identity: "2026-10-24T09:08:18.5667664Z".into(),
                vmwp_pid: 4242,
            }),
            workload_label: "m7-create-0001".into(),
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
                m4_vtl0: binding("k3-nt", 'a'),
                m5_hypervisor: binding("k3-hypervisor", 'b'),
                m6_vtl1: binding("k3-vtl1", 'c'),
            },
        }
    }

    fn bracket(layer: &str, start: u64, worker: u64, end: u64) -> RpcClockBracket {
        RpcClockBracket {
            layer: layer.into(),
            operation: "arm".into(),
            coordinator_before: sample(start),
            worker: Some(sample(worker)),
            coordinator_after: sample(end),
        }
    }

    #[test]
    fn one_vp_capture_identity_is_well_formed() {
        identity().validate().unwrap();
        let mut many = identity();
        many.processor_count = 2;
        assert!(many.validate().unwrap_err().contains("exactly one"));

        let mut missing_parent = identity();
        missing_parent.parent = None;
        assert!(
            missing_parent
                .validate()
                .unwrap_err()
                .contains("requires its parent identity")
        );

        let mut same_vm = identity();
        same_vm.parent.as_mut().unwrap().vm_id = same_vm.vm_id.clone();
        assert!(same_vm.validate().unwrap_err().contains("must differ"));

        let mut root_with_parent = identity();
        root_with_parent.target_shape.workload_placement = WorkloadPlacement::HypervisorRoot;
        assert!(
            root_with_parent
                .validate()
                .unwrap_err()
                .contains("must not carry a parent")
        );
    }

    #[test]
    fn target_shape_matrix_selects_the_nested_child_topology() {
        let non_nested = TargetShape {
            nested_virtualization: false,
            guest_hypervisor_started: false,
            workload_placement: WorkloadPlacement::HypervisorRoot,
            outer_partition_vtl1: true,
            nested_child_vtl1: false,
            m5_provider: M5HypervisorProvider::GuestNested,
            m6_provider: M6Vtl1Provider::OuterVmwp,
        };
        assert_eq!(
            non_nested.unavailable_layers(),
            [LayerUnavailability {
                layer: Layer::M5Hypervisor,
                reason: LayerUnavailableReason::M5GuestProviderNeedsNestedHypervisor,
            }]
        );

        let nested_root_with_outer_provider = TargetShape {
            nested_virtualization: true,
            guest_hypervisor_started: true,
            workload_placement: WorkloadPlacement::HypervisorRoot,
            outer_partition_vtl1: false,
            nested_child_vtl1: false,
            m5_provider: M5HypervisorProvider::GuestNested,
            m6_provider: M6Vtl1Provider::OuterVmwp,
        };
        assert_eq!(
            nested_root_with_outer_provider.unavailable_layers(),
            [LayerUnavailability {
                layer: Layer::M6Vtl1,
                reason: LayerUnavailableReason::M6OuterPartitionHasNoVtl1,
            }]
        );

        let rejected_self_provider = TargetShape {
            m6_provider: M6Vtl1Provider::NestedParent,
            ..nested_root_with_outer_provider
        };
        assert_eq!(
            rejected_self_provider.unavailable_layers(),
            [LayerUnavailability {
                layer: Layer::M6Vtl1,
                reason: LayerUnavailableReason::M6NestedProviderNeedsChildWorkload,
            }]
        );

        let selected_nested_child = TargetShape {
            workload_placement: WorkloadPlacement::ChildPartition,
            nested_child_vtl1: true,
            ..rejected_self_provider
        };
        assert!(selected_nested_child.unavailable_layers().is_empty());

        let external_l0_fallback = TargetShape {
            m5_provider: M5HypervisorProvider::ExternalL0,
            ..non_nested
        };
        assert!(external_l0_fallback.unavailable_layers().is_empty());
    }

    #[test]
    fn every_provider_boundary_has_a_typed_refusal() {
        let selected = identity().target_shape;
        let has = |shape: &TargetShape, layer, reason| {
            shape
                .unavailable_layers()
                .contains(&LayerUnavailability { layer, reason })
        };

        let guest_without_nested = TargetShape {
            nested_virtualization: false,
            guest_hypervisor_started: false,
            ..selected.clone()
        };
        assert!(has(
            &guest_without_nested,
            Layer::M5Hypervisor,
            LayerUnavailableReason::M5GuestProviderNeedsNestedHypervisor
        ));
        assert!(has(
            &guest_without_nested,
            Layer::M6Vtl1,
            LayerUnavailableReason::M6NestedProviderNeedsNestedHypervisor
        ));

        let external_for_child = TargetShape {
            m5_provider: M5HypervisorProvider::ExternalL0,
            ..selected.clone()
        };
        assert!(has(
            &external_for_child,
            Layer::M5Hypervisor,
            LayerUnavailableReason::M5ExternalProviderNeedsRootWorkload
        ));

        let external_for_nested_root = TargetShape {
            workload_placement: WorkloadPlacement::HypervisorRoot,
            m5_provider: M5HypervisorProvider::ExternalL0,
            ..selected.clone()
        };
        assert!(has(
            &external_for_nested_root,
            Layer::M5Hypervisor,
            LayerUnavailableReason::M5ExternalProviderCannotObserveNestedHypervisor
        ));

        let outer_for_child = TargetShape {
            m6_provider: M6Vtl1Provider::OuterVmwp,
            ..selected.clone()
        };
        assert!(has(
            &outer_for_child,
            Layer::M6Vtl1,
            LayerUnavailableReason::M6OuterProviderNeedsRootWorkload
        ));

        let outer_without_vtl1 = TargetShape {
            workload_placement: WorkloadPlacement::HypervisorRoot,
            m6_provider: M6Vtl1Provider::OuterVmwp,
            ..selected.clone()
        };
        assert!(has(
            &outer_without_vtl1,
            Layer::M6Vtl1,
            LayerUnavailableReason::M6OuterPartitionHasNoVtl1
        ));

        let nested_for_root = TargetShape {
            workload_placement: WorkloadPlacement::HypervisorRoot,
            ..selected.clone()
        };
        assert!(has(
            &nested_for_root,
            Layer::M6Vtl1,
            LayerUnavailableReason::M6NestedProviderNeedsChildWorkload
        ));

        let child_without_vtl1 = TargetShape {
            nested_child_vtl1: false,
            ..selected
        };
        assert!(has(
            &child_without_vtl1,
            Layer::M6Vtl1,
            LayerUnavailableReason::M6NestedChildHasNoVtl1
        ));
    }

    #[test]
    fn transaction_refuses_an_incompatible_shape_before_opening_a_worker() {
        let mut driver = MockDriver::new();
        driver.identity.target_shape.m6_provider = M6Vtl1Provider::OuterVmwp;
        let report = run_transaction(plan(false), &mut driver);
        assert_eq!(report.verdict, TransactionVerdict::Incomplete);
        assert_eq!(driver.calls, [Operation::Preflight]);
        assert!(report.issues.iter().any(|issue| {
            issue.state == TransactionState::Preflight
                && issue.operation == "preflight"
                && issue.message.contains("M6OuterProviderNeedsRootWorkload")
        }));
    }

    #[test]
    fn every_identity_field_is_frozen_between_preflight_and_arm() {
        let original = identity();
        let mutations: Vec<IdentityMutation> = vec![
            ("schema", Box::new(|v| v.schema.push_str("-changed"))),
            (
                "capture_id",
                Box::new(|v| v.capture_id.push_str("-changed")),
            ),
            ("vm_id", Box::new(|v| v.vm_id.push_str("-changed"))),
            (
                "guest_boot_identity",
                Box::new(|v| v.guest_boot_identity.push_str("-changed")),
            ),
            ("vmwp_pid", Box::new(|v| v.vmwp_pid += 1)),
            ("parent", Box::new(|v| v.parent = None)),
            (
                "parent.vm_id",
                Box::new(|v| v.parent.as_mut().unwrap().vm_id.push_str("-changed")),
            ),
            (
                "parent.guest_boot_identity",
                Box::new(|v| {
                    v.parent
                        .as_mut()
                        .unwrap()
                        .guest_boot_identity
                        .push_str("-changed")
                }),
            ),
            (
                "parent.vmwp_pid",
                Box::new(|v| v.parent.as_mut().unwrap().vmwp_pid += 1),
            ),
            (
                "workload_label",
                Box::new(|v| v.workload_label.push_str("-changed")),
            ),
            ("processor_count", Box::new(|v| v.processor_count += 1)),
            (
                "target_shape.nested_virtualization",
                Box::new(|v| v.target_shape.nested_virtualization = false),
            ),
            (
                "target_shape.guest_hypervisor_started",
                Box::new(|v| v.target_shape.guest_hypervisor_started = false),
            ),
            (
                "target_shape.workload_placement",
                Box::new(|v| v.target_shape.workload_placement = WorkloadPlacement::HypervisorRoot),
            ),
            (
                "target_shape.outer_partition_vtl1",
                Box::new(|v| v.target_shape.outer_partition_vtl1 = true),
            ),
            (
                "target_shape.nested_child_vtl1",
                Box::new(|v| v.target_shape.nested_child_vtl1 = false),
            ),
            (
                "target_shape.m5_provider",
                Box::new(|v| v.target_shape.m5_provider = M5HypervisorProvider::ExternalL0),
            ),
            (
                "target_shape.m6_provider",
                Box::new(|v| v.target_shape.m6_provider = M6Vtl1Provider::OuterVmwp),
            ),
            (
                "layers.m4_vtl0.profile",
                Box::new(|v| v.layers.m4_vtl0.profile.push_str("-changed")),
            ),
            (
                "layers.m4_vtl0.image_identity_sha256",
                Box::new(|v| {
                    v.layers
                        .m4_vtl0
                        .image_identity_sha256
                        .replace_range(0..1, "d")
                }),
            ),
            (
                "layers.m5_hypervisor.profile",
                Box::new(|v| v.layers.m5_hypervisor.profile.push_str("-changed")),
            ),
            (
                "layers.m5_hypervisor.image_identity_sha256",
                Box::new(|v| {
                    v.layers
                        .m5_hypervisor
                        .image_identity_sha256
                        .replace_range(0..1, "d")
                }),
            ),
            (
                "layers.m6_vtl1.profile",
                Box::new(|v| v.layers.m6_vtl1.profile.push_str("-changed")),
            ),
            (
                "layers.m6_vtl1.image_identity_sha256",
                Box::new(|v| {
                    v.layers
                        .m6_vtl1
                        .image_identity_sha256
                        .replace_range(0..1, "d")
                }),
            ),
        ];
        for (field, mutate) in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            let IdentityAdmissionError::Drift(drift) =
                admit_identity(&original, &changed).unwrap_err()
            else {
                panic!("{field} was not reported as identity drift")
            };
            assert_eq!(drift.fields, [field], "wrong drift for {field}");
        }
        admit_identity(&original, &original).unwrap();

        let mut invalid = original.clone();
        invalid.processor_count = 2;
        assert!(matches!(
            admit_identity(&invalid, &invalid),
            Err(IdentityAdmissionError::Invalid(message)) if message.contains("exactly one")
        ));
    }

    #[test]
    fn independent_process_ticks_order_events_even_when_old_timestamps_collide() {
        // These worker ticks model two independent processes. Both legacy millisecond-derived
        // timestamps would be 50_000 us; the QPC points retain their measured order.
        let m4_old_us = 50_000;
        let m5_old_us = 50_000;
        assert_eq!(m4_old_us, m5_old_us);
        let admitted = admit_clock(
            vec![
                bracket("m4_vtl0", 500_000, 500_100, 500_200),
                bracket("m5_hypervisor", 500_300, 500_350, 500_400),
                bracket("m6_vtl1", 500_500, 500_525, 500_600),
            ],
            1_000,
        )
        .unwrap();
        assert_eq!(admitted.mode, ClockMode::Point);
        assert_eq!(admitted.frequency, Some(FREQUENCY));
        assert_eq!(admitted.resolution_ns, Some(100));
        assert!(admitted.reasons.is_empty());
    }

    #[test]
    fn missing_mismatched_or_excessively_skewed_samples_keep_only_intervals() {
        let mut missing = bracket("m4_vtl0", 100, 150, 200);
        missing.worker = None;
        let mut mismatch = bracket("m5_hypervisor", 300, 350, 400);
        mismatch.worker.as_mut().unwrap().frequency += 1;
        let wide = bracket("m6_vtl1", 500, 550, 2_000);
        let admitted = admit_clock(vec![missing, mismatch, wide], 1_000).unwrap();
        assert_eq!(admitted.mode, ClockMode::IntervalOnly);
        assert_eq!(admitted.frequency, None);
        assert_eq!(admitted.resolution_ns, None);
        assert!(
            admitted
                .reasons
                .iter()
                .any(|reason| reason.contains("unavailable"))
        );
        assert!(
            admitted
                .reasons
                .iter()
                .any(|reason| reason.contains("frequency_mismatch"))
        );
        assert!(
            admitted
                .reasons
                .iter()
                .any(|reason| reason.contains("bracket_exceeds_skew"))
        );
    }

    #[test]
    fn overlapping_intervals_never_become_a_causal_order() {
        let first = bracket("m4_vtl0", 100, 150, 200);
        let separate = bracket("m5_hypervisor", 201, 225, 250);
        let touching = bracket("m6_vtl1", 200, 220, 240);
        assert_eq!(
            interval_order(&first, &separate).unwrap(),
            IntervalOrder::Before
        );
        assert_eq!(
            interval_order(&first, &touching).unwrap(),
            IntervalOrder::Overlap
        );
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Operation {
        Preflight,
        Open(Layer),
        Arm(Layer),
        Workload,
        Drain(Layer),
        End(Layer),
        Transition,
    }

    /// One leftover a transition can read, each the single field it dirties.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Leftover {
        HandlerUnread,
        HandlerRegistered,
        Vtl1Slot,
        Vtl0Slot,
        Pending,
        TrapFlag,
        EngineWorker,
    }

    impl Leftover {
        const ALL: [Self; 7] = [
            Self::HandlerUnread,
            Self::HandlerRegistered,
            Self::Vtl1Slot,
            Self::Vtl0Slot,
            Self::Pending,
            Self::TrapFlag,
            Self::EngineWorker,
        ];
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum InjectedFailure {
        Failed,
        TimedOut,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum UnsafeAudit {
        Unrestored,
        Running,
        Held,
        Dropped,
        Unreadable,
    }

    struct MockDriver {
        identity: CaptureIdentity,
        fault: Option<(Operation, InjectedFailure)>,
        recovery_at_open: Option<Layer>,
        unsafe_audit: Option<(Layer, UnsafeAudit)>,
        drift_at_arm: Option<Layer>,
        /// Which transition (by index) reads which leftover.
        leftover_at_transition: Option<(usize, Leftover)>,
        transitions: usize,
        calls: Vec<Operation>,
        next_tick: u64,
    }

    impl MockDriver {
        fn new() -> Self {
            Self {
                identity: identity(),
                fault: None,
                recovery_at_open: None,
                unsafe_audit: None,
                drift_at_arm: None,
                leftover_at_transition: None,
                transitions: 0,
                calls: Vec::new(),
                next_tick: 1_000,
            }
        }

        fn attempt<T>(&mut self, operation: Operation, value: T) -> Attempt<T> {
            self.calls.push(operation);
            match self.fault.filter(|(at, _)| *at == operation) {
                Some((_, InjectedFailure::Failed)) => Attempt::Failed {
                    message: format!("injected {operation:?} failure"),
                    recovery: None,
                },
                Some((_, InjectedFailure::TimedOut)) => Attempt::TimedOut {
                    timeout_ms: 37,
                    recovery: None,
                },
                None => Attempt::Succeeded { value },
            }
        }

        fn rpc_clock(&mut self, layer: Layer, operation: &str) -> RpcClockBracket {
            let start = self.next_tick;
            self.next_tick += 100;
            RpcClockBracket {
                layer: layer.wire_name().into(),
                operation: operation.into(),
                coordinator_before: sample(start),
                worker: Some(sample(start + 10)),
                coordinator_after: sample(start + 20),
            }
        }
    }

    impl TransactionDriver for MockDriver {
        fn preflight(&mut self) -> Attempt<CaptureIdentity> {
            self.attempt(Operation::Preflight, self.identity.clone())
        }

        fn open(&mut self, layer: Layer) -> Attempt<OpenAck> {
            let mut attempt = self.attempt(
                Operation::Open(layer),
                OpenAck {
                    session_id: format!("sess-{}", layer.wire_name()),
                },
            );
            let recovery = (self.recovery_at_open == Some(layer)).then(|| RecoveryHandle {
                session_id: format!("sess-{}", layer.wire_name()),
            });
            match &mut attempt {
                Attempt::Failed {
                    recovery: retained, ..
                }
                | Attempt::TimedOut {
                    recovery: retained, ..
                } => *retained = recovery,
                Attempt::Succeeded { .. } => {}
            }
            attempt
        }

        fn arm(
            &mut self,
            layer: Layer,
            _session: &OpenAck,
            _preflight: &CaptureIdentity,
        ) -> Attempt<ArmAck> {
            let mut identity = self.identity.clone();
            if self.drift_at_arm == Some(layer) {
                identity.guest_boot_identity.push_str("-changed");
            }
            let clock = self.rpc_clock(layer, "arm");
            self.attempt(
                Operation::Arm(layer),
                ArmAck {
                    trace_id: format!("trace-{}", layer.wire_name()),
                    workload_ready: true,
                    identity,
                    clock,
                },
            )
        }

        fn launch_workload(&mut self, _preflight: &CaptureIdentity) -> Attempt<WorkloadAck> {
            self.attempt(
                Operation::Workload,
                WorkloadAck {
                    label: self.identity.workload_label.clone(),
                },
            )
        }

        fn drain(&mut self, layer: Layer, _session: &OpenAck, _arm: &ArmAck) -> Attempt<DrainAck> {
            let mut audit = RestorationAudit {
                restored: true,
                running: false,
                held: false,
                dropped_records: 0,
                dropped_bytes: 0,
                unreadable_fields: 0,
            };
            if let Some((_, unsafe_audit)) = self
                .unsafe_audit
                .filter(|(unsafe_layer, _)| *unsafe_layer == layer)
            {
                match unsafe_audit {
                    UnsafeAudit::Unrestored => audit.restored = false,
                    UnsafeAudit::Running => audit.running = true,
                    UnsafeAudit::Held => audit.held = true,
                    UnsafeAudit::Dropped => audit.dropped_records = 1,
                    UnsafeAudit::Unreadable => audit.unreadable_fields = 1,
                }
            }
            let clock = self.rpc_clock(layer, "drain");
            self.attempt(Operation::Drain(layer), DrainAck { audit, clock })
        }

        fn end_session(&mut self, layer: Layer, _session: &OpenAck) -> Attempt<EndAck> {
            self.attempt(
                Operation::End(layer),
                EndAck {
                    ended: true,
                    retained_processes: 0,
                },
            )
        }

        fn transition(&mut self, closed: &[Layer], _opening: &[Layer]) -> Attempt<TransitionAck> {
            let index = self.transitions;
            self.transitions += 1;
            let mut ack = TransitionAck {
                handler_unregistered: closed.contains(&Layer::M6Vtl1).then_some(true),
                vtl1_enabled_slots: Vec::new(),
                vtl0_enabled_slots: Vec::new(),
                pending_clear: true,
                trap_flag_clear: true,
                engine_workers: 0,
            };
            if let Some((_, leftover)) = self.leftover_at_transition.filter(|(at, _)| *at == index)
            {
                match leftover {
                    Leftover::HandlerUnread => ack.handler_unregistered = None,
                    Leftover::HandlerRegistered => ack.handler_unregistered = Some(false),
                    Leftover::Vtl1Slot => ack.vtl1_enabled_slots = vec![1],
                    Leftover::Vtl0Slot => ack.vtl0_enabled_slots = vec![0],
                    Leftover::Pending => ack.pending_clear = false,
                    Leftover::TrapFlag => ack.trap_flag_clear = false,
                    Leftover::EngineWorker => ack.engine_workers = 1,
                }
            }
            self.attempt(Operation::Transition, ack)
        }
    }

    fn plan(launch_workload: bool) -> TransactionPlan {
        TransactionPlan {
            launch_workload,
            max_skew_ticks: 1_000,
            alternate: false,
        }
    }

    fn alternating_plan() -> TransactionPlan {
        TransactionPlan {
            launch_workload: false,
            max_skew_ticks: 1_000,
            alternate: true,
        }
    }

    /// The calls an alternating idle plan makes when nothing goes wrong.
    fn alternating_operation_points() -> Vec<Operation> {
        use Layer::{M4Vtl0 as M4, M5Hypervisor as M5, M6Vtl1 as M6};
        use Operation::{Arm, Drain, End, Open, Preflight, Transition};
        vec![
            Preflight,
            Open(M6),
            Arm(M6),
            Drain(M6),
            End(M6),
            Transition,
            Open(M4),
            Open(M5),
            Arm(M4),
            Arm(M5),
            Drain(M5),
            Drain(M4),
            End(M5),
            End(M4),
            Transition,
            Open(M6),
            Arm(M6),
            Drain(M6),
            End(M6),
        ]
    }

    fn operation_points() -> Vec<Operation> {
        let mut operations = vec![Operation::Preflight];
        for layer in ARM_ORDER {
            operations.push(Operation::Open(layer));
        }
        for layer in ARM_ORDER {
            operations.push(Operation::Arm(layer));
        }
        operations.push(Operation::Workload);
        for layer in ARM_ORDER.into_iter().rev() {
            operations.push(Operation::Drain(layer));
        }
        for layer in ARM_ORDER.into_iter().rev() {
            operations.push(Operation::End(layer));
        }
        operations
    }

    #[test]
    fn alternating_plan_closes_each_window_and_proves_the_switch_before_the_next_opens() {
        let mut driver = MockDriver::new();
        let report = run_transaction(alternating_plan(), &mut driver);
        assert_eq!(
            report.verdict,
            TransactionVerdict::Pass,
            "{:?}",
            report.issues
        );
        assert_eq!(driver.calls, alternating_operation_points());
        assert_eq!(
            report.states,
            [
                TransactionState::Preflight,
                TransactionState::Opening,
                TransactionState::Armed,
                TransactionState::Draining,
                TransactionState::Restoring,
                TransactionState::Transition,
                TransactionState::Opening,
                TransactionState::Armed,
                TransactionState::Draining,
                TransactionState::Restoring,
                TransactionState::Transition,
                TransactionState::Opening,
                TransactionState::Armed,
                TransactionState::Draining,
                TransactionState::Restoring,
                TransactionState::Closed,
            ]
        );
        assert_eq!(
            report.arm_order,
            [
                Layer::M6Vtl1,
                Layer::M4Vtl0,
                Layer::M5Hypervisor,
                Layer::M6Vtl1
            ]
        );
        assert_eq!(report.successful_arm_order, report.arm_order);
        assert_eq!(
            report.cleanup_order,
            [
                Layer::M6Vtl1,
                Layer::M5Hypervisor,
                Layer::M4Vtl0,
                Layer::M6Vtl1
            ]
        );
        assert_eq!(report.workload, WorkloadResult::SkippedIdle);
        assert_eq!(report.transitions.len(), 2);
        assert_eq!(report.window_reports.len(), 3);
        // The first window's record survives the second M6 window, which `layers` reflects.
        assert!(report.window_reports[0].m6_vtl1.end.is_some());
        assert!(report.window_reports[0].m4_vtl0.open.is_none());
        assert!(report.window_reports[1].m6_vtl1.open.is_none());
        assert!(report.window_reports[2].m6_vtl1.end.is_some());
        assert!(matches!(
            report.clock,
            Some(Attempt::Succeeded {
                value: ClockAdmission {
                    mode: ClockMode::Point,
                    ..
                }
            })
        ));
    }

    #[test]
    fn a_switch_that_reads_anything_left_behind_opens_no_further_window() {
        for at in 0..2 {
            for leftover in Leftover::ALL {
                let mut driver = MockDriver::new();
                driver.leftover_at_transition = Some((at, leftover));
                let report = run_transaction(alternating_plan(), &mut driver);
                let opens_after = driver
                    .calls
                    .iter()
                    .skip_while(|call| **call != Operation::Transition)
                    .skip(1)
                    .filter(|call| matches!(call, Operation::Open(_)))
                    .count();
                if at == 1 && leftover == Leftover::HandlerUnread {
                    // The window that closed held no VTL1 session; there was no handler to read.
                    assert_eq!(report.verdict, TransactionVerdict::Pass, "{leftover:?}");
                    continue;
                }
                assert_eq!(
                    report.verdict,
                    TransactionVerdict::Incomplete,
                    "{leftover:?} at {at}"
                );
                let issue = report
                    .issues
                    .iter()
                    .find(|issue| issue.operation == "transition")
                    .unwrap_or_else(|| panic!("no transition issue for {leftover:?} at {at}"));
                assert_eq!(issue.kind, IssueKind::UnsafeChild);
                assert_eq!(issue.state, TransactionState::Transition);
                assert_eq!(driver.transitions, at + 1, "{leftover:?} at {at}");
                let expected_opens_after_first_switch = if at == 0 { 0 } else { 2 };
                assert_eq!(
                    opens_after, expected_opens_after_first_switch,
                    "{leftover:?} at {at}"
                );
                assert_eq!(report.window_reports.len(), at + 1);
                assert_eq!(report.workload, WorkloadResult::Withheld);
            }
        }
    }

    #[test]
    fn a_window_that_leaves_an_issue_ends_the_alternation_after_its_own_cleanup() {
        let mut driver = MockDriver::new();
        driver.fault = Some((Operation::Arm(Layer::M4Vtl0), InjectedFailure::Failed));
        let report = run_transaction(alternating_plan(), &mut driver);
        assert_eq!(report.verdict, TransactionVerdict::Incomplete);
        assert_eq!(driver.transitions, 1);
        assert_eq!(
            driver
                .calls
                .iter()
                .filter(|call| **call == Operation::Open(Layer::M6Vtl1))
                .count(),
            1
        );
        // The failed window still ends both of its opened sessions, M5 first.
        assert_eq!(
            report.cleanup_order,
            [Layer::M6Vtl1, Layer::M5Hypervisor, Layer::M4Vtl0]
        );
        assert!(!driver.calls.contains(&Operation::Arm(Layer::M5Hypervisor)));
        assert_eq!(report.window_reports.len(), 2);
        assert_eq!(report.state, TransactionState::Closed);
    }

    #[test]
    fn an_alternating_plan_cannot_launch_a_workload() {
        let mut driver = MockDriver::new();
        let report = run_transaction(
            TransactionPlan {
                launch_workload: true,
                ..alternating_plan()
            },
            &mut driver,
        );
        assert_eq!(report.verdict, TransactionVerdict::Incomplete);
        assert_eq!(report.workload, WorkloadResult::Withheld);
        assert_eq!(driver.calls, [Operation::Preflight]);
        assert!(
            report.issues.iter().any(|issue| {
                issue.operation == "preflight" && issue.kind == IssueKind::Invalid
            })
        );
    }

    #[test]
    fn idle_transaction_arms_every_worker_and_restores_in_reverse_order() {
        let mut driver = MockDriver::new();
        let report = run_transaction(plan(false), &mut driver);
        assert_eq!(report.verdict, TransactionVerdict::Pass);
        assert_eq!(
            report.states,
            [
                TransactionState::Preflight,
                TransactionState::Opening,
                TransactionState::Armed,
                TransactionState::Workload,
                TransactionState::Draining,
                TransactionState::Restoring,
                TransactionState::Closed,
            ]
        );
        assert_eq!(report.successful_arm_order, ARM_ORDER);
        assert_eq!(
            report.cleanup_order,
            [Layer::M5Hypervisor, Layer::M4Vtl0, Layer::M6Vtl1]
        );
        assert_eq!(report.workload, WorkloadResult::SkippedIdle);
        assert!(report.transitions.is_empty());
        assert_eq!(
            report.window_reports.as_slice(),
            std::slice::from_ref(&report.layers)
        );
        assert!(!driver.calls.contains(&Operation::Transition));
        assert!(!driver.calls.contains(&Operation::Workload));
        assert!(matches!(
            report.clock,
            Some(Attempt::Succeeded {
                value: ClockAdmission {
                    mode: ClockMode::Point,
                    ..
                }
            })
        ));
        let drains = driver
            .calls
            .iter()
            .filter_map(|operation| match operation {
                Operation::Drain(layer) => Some(*layer),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(drains, report.cleanup_order);
    }

    #[test]
    fn workload_is_launched_only_after_all_three_arm_acknowledgements() {
        let mut driver = MockDriver::new();
        let report = run_transaction(plan(true), &mut driver);
        assert_eq!(report.verdict, TransactionVerdict::Pass);
        let workload = driver
            .calls
            .iter()
            .position(|operation| *operation == Operation::Workload)
            .unwrap();
        assert!(ARM_ORDER.into_iter().all(|layer| {
            driver
                .calls
                .iter()
                .position(|operation| *operation == Operation::Arm(layer))
                .is_some_and(|armed| armed < workload)
        }));

        let mut failed = MockDriver::new();
        failed.fault = Some((Operation::Arm(Layer::M4Vtl0), InjectedFailure::Failed));
        let report = run_transaction(plan(true), &mut failed);
        assert_eq!(report.verdict, TransactionVerdict::Incomplete);
        assert!(!failed.calls.contains(&Operation::Workload));
        assert_eq!(report.workload, WorkloadResult::Withheld);
    }

    #[test]
    fn every_failure_and_timeout_keeps_reachable_cleanup_and_a_complete_audit() {
        for failure in [InjectedFailure::Failed, InjectedFailure::TimedOut] {
            for operation in operation_points() {
                let mut driver = MockDriver::new();
                driver.fault = Some((operation, failure));
                let report = run_transaction(plan(true), &mut driver);
                assert_eq!(
                    report.verdict,
                    TransactionVerdict::Incomplete,
                    "{failure:?} at {operation:?} passed"
                );
                assert_eq!(report.state, TransactionState::Closed);
                assert!(!report.issues.is_empty());

                for layer in Layer::ALL {
                    let layer_report = report.layers.get(layer);
                    let opened = layer_report
                        .open
                        .as_ref()
                        .and_then(Attempt::succeeded)
                        .is_some();
                    let end_calls = driver
                        .calls
                        .iter()
                        .filter(|call| **call == Operation::End(layer))
                        .count();
                    assert_eq!(
                        end_calls,
                        usize::from(opened),
                        "opened-layer cleanup mismatch for {layer:?}, {failure:?} at {operation:?}"
                    );
                    if !opened {
                        assert!(!driver.calls.iter().any(|call| matches!(
                            call,
                            Operation::Arm(at) | Operation::Drain(at) | Operation::End(at)
                                if *at == layer
                        )));
                    }
                    if layer_report
                        .arm
                        .as_ref()
                        .and_then(Attempt::succeeded)
                        .is_some()
                    {
                        assert!(
                            layer_report.restoration.is_some(),
                            "armed layer lost its restoration result for {failure:?} at {operation:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_failed_or_timed_out_open_with_a_handle_is_ended_exactly_once() {
        for failure in [InjectedFailure::Failed, InjectedFailure::TimedOut] {
            for layer in ARM_ORDER {
                let mut driver = MockDriver::new();
                driver.fault = Some((Operation::Open(layer), failure));
                driver.recovery_at_open = Some(layer);
                let report = run_transaction(plan(true), &mut driver);

                assert_eq!(report.verdict, TransactionVerdict::Incomplete);
                let failed_at = ARM_ORDER
                    .iter()
                    .position(|candidate| *candidate == layer)
                    .unwrap();
                let expected_cleanup = ARM_ORDER[..=failed_at]
                    .iter()
                    .rev()
                    .copied()
                    .collect::<Vec<_>>();
                assert_eq!(report.cleanup_order, expected_cleanup);
                for opened in &ARM_ORDER[..=failed_at] {
                    assert_eq!(
                        driver
                            .calls
                            .iter()
                            .filter(|call| **call == Operation::End(*opened))
                            .count(),
                        1
                    );
                }
                for untouched in &ARM_ORDER[failed_at + 1..] {
                    assert!(!driver.calls.iter().any(|call| matches!(
                        call,
                        Operation::Open(at) | Operation::Arm(at) | Operation::Drain(at)
                            if at == untouched
                    )));
                }
            }
        }
    }

    #[test]
    fn no_child_hazard_can_be_reported_as_a_pass() {
        for layer in Layer::ALL {
            for unsafe_audit in [
                UnsafeAudit::Unrestored,
                UnsafeAudit::Running,
                UnsafeAudit::Held,
                UnsafeAudit::Dropped,
                UnsafeAudit::Unreadable,
            ] {
                let mut driver = MockDriver::new();
                driver.unsafe_audit = Some((layer, unsafe_audit));
                let report = run_transaction(plan(false), &mut driver);
                assert_eq!(
                    report.verdict,
                    TransactionVerdict::Incomplete,
                    "{unsafe_audit:?} on {layer:?} passed"
                );
                assert!(report.issues.iter().any(|issue| {
                    issue.layer == Some(layer) && issue.kind == IssueKind::UnsafeChild
                }));
                assert_eq!(
                    driver
                        .calls
                        .iter()
                        .filter(|call| **call == Operation::End(layer))
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn arm_time_identity_drift_still_restores_every_instrument_that_was_acknowledged() {
        // Drift at the second layer: the one before it armed cleanly and the one after it must
        // stay untouched, so both halves of "every acknowledged instrument" are exercised.
        let mut driver = MockDriver::new();
        driver.drift_at_arm = Some(Layer::M4Vtl0);
        let report = run_transaction(plan(true), &mut driver);
        assert_eq!(report.verdict, TransactionVerdict::Incomplete);
        assert_eq!(report.successful_arm_order, [Layer::M6Vtl1, Layer::M4Vtl0]);
        assert_eq!(
            report.cleanup_order,
            [Layer::M4Vtl0, Layer::M6Vtl1, Layer::M5Hypervisor]
        );
        assert!(report.layers.m4_vtl0.restoration.is_some());
        assert!(report.layers.m6_vtl1.restoration.is_some());
        assert!(report.layers.m5_hypervisor.arm.is_none());
        assert!(!driver.calls.contains(&Operation::Workload));
    }
}
