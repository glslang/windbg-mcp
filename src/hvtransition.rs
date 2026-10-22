//! Engine-free state for the exact-build hypervisor VTL transition trace.
//!
//! The hypervisor worker owns two software breakpoints in the measured `hvix64.exe`:
//! one after `HvCallVtlCall` has selected its target VTL and one after `HvCallVtlReturn` has
//! selected its return VTL. The callback performs typed register and memory reads; this module
//! owns only the fixed build profile and the bounded recorder, so its decisions need no live KD.

use dbgscope::dbgeng::BreakpointAction;

pub const DEFAULT_TRANSITIONS: usize = 64;
pub const MAX_TRANSITIONS: usize = 1024;

/// Identity of the measured Intel hypervisor image copied from K3.
pub const IMAGE_SIZE: u32 = 4_280_320;
pub const IMAGE_TIMESTAMP: u32 = 0x1525_065d;
pub const IMAGE_CHECKSUM: u32 = 0x001f_700b;

pub const CALL_HANDLER_RVA: u64 = 0x2931a0;
pub const CALL_BREAK_RVA: u64 = 0x2931f5;
pub const CALL_DESCRIPTOR_RVA: u64 = 0x2198;
pub const RETURN_HANDLER_RVA: u64 = 0x293230;
pub const RETURN_BREAK_RVA: u64 = 0x2932a1;
pub const RETURN_DESCRIPTOR_RVA: u64 = 0x21b0;

/// The handler descriptors are 24-byte entries. Their first qword is relocated at load time; the
/// remainder is fixed and includes the hypercall code (0x11 or 0x12).
pub const CALL_DESCRIPTOR_TAIL: &[u8] = &[
    0x11, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00,
];
pub const RETURN_DESCRIPTOR_TAIL: &[u8] = &[
    0x12, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00,
];

/// Prefix through the call-handler instruction immediately before the selected target VTL is
/// consumed. `CALL_BREAK_RVA` is byte 0x55 of this profile.
pub const CALL_GUARD: &[u8] = &[
    0x48, 0x89, 0x5c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48,
    0x8b, 0xf9, 0x33, 0xdb, 0x48, 0x8b, 0x89, 0xc0, 0x03, 0x00, 0x00, 0x8d, 0x43, 0x01, 0x8a, 0x49,
    0x14, 0xd3, 0xe0, 0x44, 0x8d, 0x48, 0xff, 0x44, 0x0b, 0xc8, 0x41, 0xf7, 0xd1, 0x44, 0x23, 0x8f,
    0xb0, 0x01, 0x00, 0x00, 0x41, 0x0f, 0xbc, 0xf1, 0x0f, 0x95, 0xc0, 0x84, 0xc0, 0x75, 0x07, 0xbb,
    0x0a, 0x10, 0x00, 0x00, 0xeb, 0x2b, 0x4d, 0x85, 0xc0, 0x75, 0xf4, 0x44, 0x0f, 0xb6, 0x47, 0x08,
    0xe8, 0x53, 0x8c, 0xfe, 0xff, 0x40, 0x8a, 0xd6, 0x48, 0x8b, 0xcf, 0xe8, 0xc4, 0xc9, 0x01, 0x00,
];

/// Prefix through the return-handler instruction immediately after the lower target VTL has been
/// selected. `RETURN_BREAK_RVA` is byte 0x71 of this profile.
pub const RETURN_GUARD: &[u8] = &[
    0x48, 0x89, 0x5c, 0x24, 0x10, 0x48, 0x89, 0x6c, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57,
    0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xb1, 0xc0, 0x03, 0x00, 0x00, 0x33,
    0xff, 0x4d, 0x8b, 0xf0, 0x8b, 0xea, 0x48, 0x8b, 0xd9, 0x44, 0x0f, 0xb6, 0x7e, 0x14, 0x45, 0x84,
    0xff, 0x75, 0x0a, 0xbf, 0x0a, 0x10, 0x00, 0x00, 0xe9, 0x1c, 0x01, 0x00, 0x00, 0x49, 0x83, 0xfe,
    0x02, 0x73, 0xf0, 0xe8, 0x3c, 0x1f, 0xf9, 0xff, 0x4a, 0x8b, 0x94, 0xfb, 0x48, 0x01, 0x00, 0x00,
    0x41, 0x8a, 0xcf, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xd3, 0xe0, 0xf7, 0xd0, 0x21, 0x83, 0xc8, 0x03,
    0x00, 0x00, 0x8b, 0x83, 0xc8, 0x03, 0x00, 0x00, 0x0f, 0xbd, 0xc8, 0x88, 0x8b, 0xcc, 0x03, 0x00,
    0x00, 0x8b, 0x82, 0x60, 0x07, 0x00,
];

pub const VP_INDEX_OFFSET: u64 = 0x8;
pub const VTL_STATE_ARRAY_OFFSET: u64 = 0x148;
pub const CURRENT_VTL_STATE_OFFSET: u64 = 0x3c0;
pub const ACTIVE_VTL_OFFSET: u64 = 0x14;
pub const GUEST_REGISTERS_OFFSET: u64 = 0xec0;
pub const VMCS_DESCRIPTOR_OFFSET: u64 = 0x13e8;
pub const VMCS_PHYSICAL_OFFSET: u64 = 0x188;
pub const GUEST_RIP_FIELD: u32 = 0x681e;
pub const GUEST_CR3_FIELD: u32 = 0x6802;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Call,
    Return,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmcsCoordinate {
    pub state: u64,
    pub descriptor: Option<u64>,
    pub physical_address: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub host_monotonic_us: u64,
    pub elapsed_us: u64,
    pub kind: Kind,
    pub rip: Option<u64>,
    pub rsp: Option<u64>,
    pub processor: Option<u32>,
    pub vp: Option<u64>,
    pub vp_index: Option<u8>,
    pub source_vtl: Option<u8>,
    pub target_vtl: Option<u8>,
    pub control: Option<u64>,
    pub guest_registers: Option<u64>,
    pub source_vmcs: Option<VmcsCoordinate>,
    pub target_vmcs: Option<VmcsCoordinate>,
    pub read_failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub sequence: u64,
    pub hit: Hit,
}

#[derive(Debug)]
pub struct Recorder {
    marker: String,
    call_breakpoint: Option<u32>,
    return_breakpoint: Option<u32>,
    transitions: Vec<Transition>,
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
            call_breakpoint: None,
            return_breakpoint: None,
            transitions: Vec::new(),
            limit: limit.clamp(1, MAX_TRANSITIONS),
            next_sequence: 0,
            dropped: 0,
            unreadable: 0,
            full: false,
        }
    }

    pub fn arm(&mut self, call: u32, ret: u32) {
        self.call_breakpoint = Some(call);
        self.return_breakpoint = Some(ret);
    }

    pub fn marker(&self) -> &str {
        &self.marker
    }

    pub fn breakpoints(&self) -> [Option<u32>; 2] {
        [self.call_breakpoint, self.return_breakpoint]
    }

    pub fn owns(&self, id: u32, command: Option<&str>) -> Option<Kind> {
        if command != Some(self.marker.as_str()) {
            return None;
        }
        if self.call_breakpoint == Some(id) {
            Some(Kind::Call)
        } else if self.return_breakpoint == Some(id) {
            Some(Kind::Return)
        } else {
            None
        }
    }

    pub fn hit(&mut self, hit: Hit) -> BreakpointAction {
        if self.full {
            self.dropped += 1;
            return BreakpointAction::Go;
        }
        if !hit.read_failures.is_empty() {
            self.unreadable += 1;
        }
        self.transitions.push(Transition {
            sequence: self.next_sequence,
            hit,
        });
        self.next_sequence += 1;
        if self.transitions.len() >= self.limit {
            self.full = true;
            BreakpointAction::Break
        } else {
            BreakpointAction::Go
        }
    }

    pub fn transitions(&self) -> &[Transition] {
        &self.transitions
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

    fn hit(kind: Kind, failures: &[&str]) -> Hit {
        Hit {
            host_monotonic_us: 20_000,
            elapsed_us: 7,
            kind,
            rip: Some(0xffff_f800_0029_31f5),
            rsp: Some(0xffff_f000_0000_1000),
            processor: Some(0),
            vp: Some(0xffff_f800_0040_0000),
            vp_index: Some(0),
            source_vtl: Some(0),
            target_vtl: Some(1),
            control: Some(0),
            guest_registers: Some(0xffff_f800_0050_0000),
            source_vmcs: None,
            target_vmcs: None,
            read_failures: failures.iter().map(|failure| (*failure).into()).collect(),
        }
    }

    #[test]
    fn ownership_requires_marker_and_distinguishes_handlers() {
        let mut recorder = Recorder::new(4, "$$ hv_transition_trace 3".into());
        recorder.arm(7, 8);
        assert_eq!(
            recorder.owns(7, Some("$$ hv_transition_trace 3")),
            Some(Kind::Call)
        );
        assert_eq!(
            recorder.owns(8, Some("$$ hv_transition_trace 3")),
            Some(Kind::Return)
        );
        assert_eq!(recorder.owns(7, Some("$$ somebody else")), None);
        assert_eq!(recorder.owns(9, Some("$$ hv_transition_trace 3")), None);
    }

    #[test]
    fn the_transition_that_fills_the_trace_stops() {
        let mut recorder = Recorder::new(2, "marker".into());
        assert_eq!(recorder.hit(hit(Kind::Call, &[])), BreakpointAction::Go);
        assert_eq!(
            recorder.hit(hit(Kind::Return, &["target_vmcs"])),
            BreakpointAction::Break
        );
        assert_eq!(recorder.hit(hit(Kind::Call, &[])), BreakpointAction::Go);
        assert_eq!(recorder.transitions().len(), 2);
        assert_eq!(recorder.transitions()[1].sequence, 1);
        assert_eq!(recorder.unreadable_hits(), 1);
        assert_eq!(recorder.dropped(), 1);
        assert!(recorder.full());
    }

    #[test]
    fn exact_profile_contains_both_breakpoint_instructions() {
        assert_eq!(CALL_GUARD.len(), 0x60);
        assert_eq!(CALL_BREAK_RVA - CALL_HANDLER_RVA, 0x55);
        assert_eq!(RETURN_GUARD.len(), 0x76);
        assert_eq!(RETURN_BREAK_RVA - RETURN_HANDLER_RVA, 0x71);
        assert_eq!(
            &RETURN_GUARD[0x6b..0x71],
            &[0x88, 0x8b, 0xcc, 0x03, 0x00, 0x00]
        );
        assert_eq!(&RETURN_GUARD[0x71..], &[0x8b, 0x82, 0x60, 0x07, 0x00]);
        assert_eq!(CALL_DESCRIPTOR_TAIL[0], 0x11);
        assert_eq!(RETURN_DESCRIPTOR_TAIL[0], 0x12);
    }

    #[test]
    fn limits_are_never_zero_or_unbounded() {
        assert_eq!(Recorder::new(0, "m".into()).limit(), 1);
        assert_eq!(
            Recorder::new(usize::MAX, "m".into()).limit(),
            MAX_TRANSITIONS
        );
    }
}
