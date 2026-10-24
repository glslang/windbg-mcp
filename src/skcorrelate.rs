//! Pure M7 cross-layer admission and correlation primitives.
//!
//! This module owns no debugger, session or provider. The live coordinator feeds it serialized
//! records from the three existing workers; keeping identity and clock decisions here makes them
//! exhaustively testable without a target and prevents a fourth engine role from appearing.

#![allow(dead_code)] // M7.0 lands the pure admission gate before M7.1 wires the live coordinator.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::structured::HostQpcSample;

pub(crate) const CAPTURE_SCHEMA: &str = "windbg-mcp.sk-correlation-capture.v1";

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
    pub(crate) workload_label: String,
    pub(crate) processor_count: u32,
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
        if self.processor_count != 1 {
            return Err(format!(
                "M7 admits exactly one runnable processor, observed {}",
                self.processor_count
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
            vm_id: "6b1ed0f6-137e-469f-aeab-a3f4cfee398d".into(),
            guest_boot_identity: "2026-10-24T08:00:00.0000000Z".into(),
            vmwp_pid: 4242,
            workload_label: "m7-create-0001".into(),
            processor_count: 1,
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
            (
                "workload_label",
                Box::new(|v| v.workload_label.push_str("-changed")),
            ),
            ("processor_count", Box::new(|v| v.processor_count += 1)),
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
}
