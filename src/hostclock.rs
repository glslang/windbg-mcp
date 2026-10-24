//! Host-wide high-resolution clock samples used by the M7 cross-worker correlation gate.
//!
//! `Instant` has deliberately unspecified epochs and cannot cross a process boundary.
//! `GetTickCount64` does cross that boundary, but its millisecond resolution collides at the M5
//! transition rate. Windows' performance counter is host-wide, monotonic and high resolution;
//! every sample carries its frequency so the coordinator can refuse a machine or capture whose
//! processes do not agree instead of assuming compatible ticks.

use std::sync::OnceLock;

use anyhow::{Result, anyhow};
use serde::Serialize;

use crate::structured::HostQpcSample;

pub(crate) const CLOCK_PROBE_FLAG: &str = "--m7-clock-probe";
const CLOCK_PROBE_SCHEMA: &str = "windbg-mcp.m7-clock-probe.v1";
const PROBE_SAMPLES: usize = 256;
static FREQUENCY: OnceLock<Option<u64>> = OnceLock::new();

fn frequency() -> Option<u64> {
    *FREQUENCY.get_or_init(|| {
        let mut value = 0_i64;
        // SAFETY: `value` is a valid writable i64 for the duration of this one-shot Win32 call.
        let ok = unsafe {
            windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut value)
        };
        (ok != 0 && value > 0).then_some(value as u64)
    })
}

/// Sample the Windows performance counter without making clock availability a worker panic.
///
/// Modern supported Windows versions provide QPC, but absence is represented explicitly so M7
/// can refuse point ordering and retain only RPC intervals as its contract requires.
pub(crate) fn sample() -> Option<HostQpcSample> {
    let frequency = frequency()?;
    let mut tick = 0_i64;
    // SAFETY: `tick` is a valid writable i64 for the duration of this one-shot Win32 call.
    let ok = unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut tick) };
    (ok != 0 && tick >= 0).then_some(HostQpcSample {
        tick: tick as u64,
        frequency,
    })
}

#[derive(Serialize)]
struct ProbePoint {
    host_monotonic_us: u64,
    qpc: HostQpcSample,
}

#[derive(Serialize)]
struct ProbeReport {
    schema: &'static str,
    process_id: u32,
    samples: Vec<ProbePoint>,
}

/// Emit a tight clock vector from a standalone process and exit before the MCP runtime starts.
pub(crate) fn run_probe() -> Result<()> {
    let mut samples = Vec::with_capacity(PROBE_SAMPLES);
    for _ in 0..PROBE_SAMPLES {
        let qpc = sample().ok_or_else(|| anyhow!("QueryPerformanceCounter is unavailable"))?;
        // SAFETY: GetTickCount64 and GetCurrentProcessId take no pointers and have no failure
        // result. They are sampled here only to prove the old millisecond coordinate collides.
        let host_monotonic_us = unsafe {
            windows_sys::Win32::System::SystemInformation::GetTickCount64().saturating_mul(1_000)
        };
        samples.push(ProbePoint {
            host_monotonic_us,
            qpc,
        });
    }
    let report = ProbeReport {
        schema: CLOCK_PROBE_SCHEMA,
        // SAFETY: GetCurrentProcessId has no preconditions or failure result.
        process_id: unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() },
        samples,
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_are_ordered_and_report_one_frequency() {
        let first = sample().expect("supported Windows provides QPC");
        let second = sample().expect("supported Windows keeps QPC available");
        assert!(first.frequency > 0);
        assert_eq!(second.frequency, first.frequency);
        assert!(second.tick >= first.tick);
    }
}
