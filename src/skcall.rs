//! Engine-free state for the VTL0 Secure Kernel call trace.
//!
//! The ordinary kernel worker owns one breakpoint at the exact-build entry to
//! `nt!VslpEnterIumSecureMode`. Its breakpoint callback reads the x64 calling context and hands a
//! [`Hit`] here. This module decides only ownership, bounds and whether execution should continue,
//! so those decisions are testable without DbgEng or a live kernel.

use dbgscope::dbgeng::BreakpointAction;

/// Calls retained when the caller names no bound.
pub const DEFAULT_CALLS: usize = 64;

/// Maximum calls one trace retains. Each call is a kernel-debugger round trip and carries a
/// bounded copy of its argument block, so a larger trace would be expensive in both target time
/// and worker memory.
pub const MAX_CALLS: usize = 1024;

/// Size of the call block this build family prepares before entering VTL1.
///
/// This is not used to interpret fields. The raw bytes are evidence for a later service-specific
/// decoder; the entry arguments themselves remain the authoritative kind, service and context.
pub const ARGUMENT_BLOCK_BYTES: usize = 0x68;

/// Exact 10.0.26100.9457 entry prefix through the instructions that consume CL, DX, R8D and R9.
///
/// This makes the internal calling convention an executable guard, not an assumption carried
/// from one build to another. A different kernel must be measured before this table is extended.
pub const ENTRY_GUARD: &[u8] = &[
    0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x70,
    0x48, 0x8b, 0x05, 0x79, 0xb8, 0xb1, 0x00, 0x48, 0x33, 0xc4, 0x48, 0x89, 0x44, 0x24, 0x68, 0x40,
    0x32, 0xf6, 0x66, 0x89, 0x54, 0x24, 0x32, 0x40, 0x32, 0xff, 0x44, 0x0f, 0xb6, 0xf1, 0x48, 0x83,
    0x3d, 0x7a, 0x29, 0xf1, 0x00, 0x00, 0x41, 0xb5, 0x0f, 0x49, 0x8b, 0xd9, 0x40, 0x88, 0x74, 0x24,
    0x30, 0x45, 0x8b, 0xe0, 0x4c, 0x89, 0x6c, 0x24, 0x40, 0x44, 0x0f, 0xb7, 0xfa,
];

/// Decode the fixed-width entry arguments from their x64 register containers.
pub fn entry_arguments(rcx: u64, rdx: u64, r8: u64) -> (u8, u16, u32) {
    (rcx as u8, rdx as u16, r8 as u32)
}

/// Decode the pointer-sized `_CLIENT_ID.UniqueProcess` value read from the stopped thread.
///
/// The field is a `HANDLE`: four bytes on x86 and eight on x64. M4 currently admits only x64,
/// but keeping the width check here makes a corrupt or unexpectedly typed field a failed read
/// rather than a truncated process id.
pub fn decode_process_id(bytes: &[u8]) -> Option<u32> {
    match bytes {
        [a, b, c, d] => Some(u32::from_le_bytes([*a, *b, *c, *d])),
        [a, b, c, d, e, f, g, h] => {
            u32::try_from(u64::from_le_bytes([*a, *b, *c, *d, *e, *f, *g, *h])).ok()
        }
        _ => None,
    }
}

/// One breakpoint hit after the worker has attempted every typed read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// High-resolution host-wide sample at the hit.
    pub host_qpc: Option<crate::structured::HostQpcSample>,
    /// Host uptime at the hit, comparable across worker processes on this host.
    pub host_monotonic_us: u64,
    /// Monotonic time since the trace was armed.
    pub elapsed_us: u64,
    pub rip: Option<u64>,
    pub rsp: Option<u64>,
    /// Low byte of RCX at entry.
    pub transition_kind: Option<u8>,
    /// Low word of RDX at entry.
    pub service: Option<u16>,
    /// Low dword of R8 at entry.
    pub call_context: Option<u32>,
    /// R9 at entry.
    pub argument_block_pointer: Option<u64>,
    /// Up to [`ARGUMENT_BLOCK_BYTES`] read from R9.
    pub argument_block: Option<Vec<u8>>,
    /// Return address read from the x64 stack.
    pub caller: Option<u64>,
    pub process_id: Option<u32>,
    /// The kernel thread object, not a debugger thread index.
    pub thread: Option<u64>,
    pub processor: Option<u32>,
    /// Stable field names for reads that did not answer.
    pub read_failures: Vec<String>,
}

/// A retained call, ordered by breakpoint arrival.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub sequence: u64,
    pub hit: Hit,
}

/// Bounded state shared with the breakpoint callback on the engine thread.
#[derive(Debug)]
pub struct Recorder {
    marker: String,
    breakpoint: Option<u32>,
    calls: Vec<Call>,
    limit: usize,
    next_sequence: u64,
    dropped: u64,
    unreadable: u64,
    full: bool,
}

impl Recorder {
    pub fn new(limit: usize, marker: String) -> Self {
        Self {
            marker,
            breakpoint: None,
            calls: Vec::new(),
            limit: limit.clamp(1, MAX_CALLS),
            next_sequence: 0,
            dropped: 0,
            unreadable: 0,
            full: false,
        }
    }

    pub fn arm(&mut self, id: u32) {
        self.breakpoint = Some(id);
    }

    pub fn marker(&self) -> &str {
        &self.marker
    }

    pub fn breakpoint(&self) -> Option<u32> {
        self.breakpoint
    }

    /// Whether this is still the breakpoint this trace armed.
    ///
    /// The marker is as important as the id: DbgEng reuses ids after removal, so an id alone can
    /// turn somebody else's later breakpoint into one this callback automatically continues.
    pub fn owns(&self, id: u32, command: Option<&str>) -> bool {
        self.breakpoint == Some(id) && command == Some(self.marker.as_str())
    }

    /// Retains a hit and lets the target run, except for the hit that fills the trace.
    pub fn hit(&mut self, hit: Hit) -> BreakpointAction {
        if self.full {
            self.dropped += 1;
            return BreakpointAction::Go;
        }
        if !hit.read_failures.is_empty() {
            self.unreadable += 1;
        }
        self.calls.push(Call {
            sequence: self.next_sequence,
            hit,
        });
        self.next_sequence += 1;
        if self.calls.len() >= self.limit {
            self.full = true;
            BreakpointAction::Break
        } else {
            BreakpointAction::Go
        }
    }

    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn full(&self) -> bool {
        self.full
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn unreadable_hits(&self) -> u64 {
        self.unreadable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(failures: &[&str]) -> Hit {
        Hit {
            host_qpc: Some(crate::structured::HostQpcSample {
                tick: 110_000,
                frequency: 10_000_000,
            }),
            host_monotonic_us: 11_000,
            elapsed_us: 7,
            rip: Some(0xffff_f800_0000_1000),
            rsp: Some(0xffff_f000_0000_2000),
            transition_kind: Some(2),
            service: Some(0x10a),
            call_context: Some(0),
            argument_block_pointer: Some(0xffff_f000_0000_3000),
            argument_block: Some(vec![0; ARGUMENT_BLOCK_BYTES]),
            caller: Some(0xffff_f800_0000_2000),
            process_id: Some(4),
            thread: Some(0xffff_a000_0000_1000),
            processor: Some(0),
            read_failures: failures.iter().map(|failure| (*failure).into()).collect(),
        }
    }

    #[test]
    fn ownership_needs_the_id_and_the_marker() {
        let mut recorder = Recorder::new(4, "$$ sk_call_trace 7".into());
        recorder.arm(3);
        assert!(recorder.owns(3, Some("$$ sk_call_trace 7")));
        assert!(!recorder.owns(4, Some("$$ sk_call_trace 7")));
        assert!(!recorder.owns(3, Some("$$ somebody else")));
        assert!(!recorder.owns(3, None));
    }

    #[test]
    fn the_hit_that_fills_the_trace_stops_and_later_hits_run_on() {
        let mut recorder = Recorder::new(2, "marker".into());
        assert_eq!(recorder.hit(hit(&[])), BreakpointAction::Go);
        assert_eq!(
            recorder.hit(hit(&["argument_block"])),
            BreakpointAction::Break
        );
        assert_eq!(recorder.hit(hit(&[])), BreakpointAction::Go);
        assert_eq!(recorder.calls().len(), 2);
        assert_eq!(recorder.calls()[1].sequence, 1);
        assert_eq!(recorder.unreadable_hits(), 1);
        assert_eq!(recorder.dropped(), 1);
        assert!(recorder.full());
    }

    #[test]
    fn limits_are_never_zero_or_unbounded() {
        assert_eq!(Recorder::new(0, "m".into()).limit(), 1);
        assert_eq!(Recorder::new(usize::MAX, "m".into()).limit(), MAX_CALLS);
    }

    #[test]
    fn entry_arguments_use_only_the_width_the_exact_build_consumes() {
        assert_eq!(ENTRY_GUARD.len(), 77);
        assert_eq!(&ENTRY_GUARD[34..39], &[0x66, 0x89, 0x54, 0x24, 0x32]);
        assert_eq!(&ENTRY_GUARD[42..46], &[0x44, 0x0f, 0xb6, 0xf1]);
        assert_eq!(&ENTRY_GUARD[57..60], &[0x49, 0x8b, 0xd9]);
        assert_eq!(&ENTRY_GUARD[65..68], &[0x45, 0x8b, 0xe0]);
        assert_eq!(&ENTRY_GUARD[73..77], &[0x44, 0x0f, 0xb7, 0xfa]);
        assert_eq!(
            entry_arguments(
                0xaaaa_bbbb_cccc_dd02,
                0xaaaa_bbbb_cccc_010a,
                0xaaaa_bbbb_1234_5678,
            ),
            (2, 0x010a, 0x1234_5678)
        );
    }

    #[test]
    fn process_id_decode_accepts_pointer_widths_without_truncating() {
        assert_eq!(decode_process_id(&4u32.to_le_bytes()), Some(4));
        assert_eq!(decode_process_id(&3740u64.to_le_bytes()), Some(3740));
        assert_eq!(decode_process_id(&0x1_0000_0000u64.to_le_bytes()), None);
        assert_eq!(decode_process_id(&[4, 0]), None);
    }
}
