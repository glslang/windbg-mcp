//! A live trace of the pool allocations one driver makes: the engine-free half.
//!
//! The worker arms two breakpoints per allocator call site in a driver -- one **on the call**, where
//! the arguments are in their registers, and one **after it**, where the returned pointer is -- and
//! registers a breakpoint callback that hands each hit here and answers the engine with what this
//! decides: [`BreakpointAction::Go`] so the target runs on, or [`BreakpointAction::Break`] once the
//! trace is full, so it stops rather than trapping on every allocation after the last one it can
//! record.
//!
//! **Why this is a state machine of its own.** Everything that decides what a hit means -- which
//! breakpoint is whose, which call a return belongs to, when the trace is full -- is here, behind
//! plain values, so it is tested without an engine. The callback in the worker reads registers and
//! calls in; it decides nothing.
//!
//! **What a hit costs, which is why the trace is scoped to one driver's call sites.** Every hit is
//! a trap: on a live kernel, a round trip over the KD link before the target runs on, measured at
//! about 25 ms over 115200-baud serial (`dbgscope`'s `examples/breakpoint_status_probe.rs`). A
//! breakpoint on the allocator itself would trap every allocation the system makes, whatever a
//! condition then decided; a breakpoint on one driver's call sites traps only that driver's.

use std::collections::HashMap;

use dbgscope::dbgeng::BreakpointAction;

/// The most allocations one trace holds when the caller names no limit.
pub const DEFAULT_ALLOCATIONS: usize = 64;

/// The most allocations one trace may hold. Each is two traps, so a thousand is a minute of
/// serial-link round trips and far more than a trace read by a person needs.
pub const MAX_ALLOCATIONS: usize = 1024;

/// What the allocator's first argument is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindArgument {
    /// `POOL_FLAGS`, a 64-bit mask: `ExAllocatePool2` and `ExAllocatePool3`.
    Flags,
    /// `POOL_TYPE`, an enumeration: the older allocators.
    Type,
}

/// Where a pool allocator's arguments are, by position in the calling convention.
///
/// The first three integer arguments arrive in registers on both architectures this traces --
/// `rcx`, `rdx`, `r8` on x64 and `x0`, `x1`, `x2` on ARM64 -- so a position is a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// The flags or pool type, always the first argument.
    pub kind: KindArgument,
    /// The byte count, always the second.
    pub size: usize,
    /// The tag, where the allocator takes one: always the third.
    pub tag: Option<usize>,
}

/// The layout of a pool allocator's arguments, or `None` for a name that is not one.
///
/// **The pool allocators only.** The hazard scan's allocation sinks also include
/// `MmAllocateContiguousMemory` and `MmAllocateNonCachedMemory`, which allocate memory but not
/// from the pool -- and a pool trace that reported them would hand `pool_chunk` addresses no pool
/// walk can place.
pub fn layout_of(allocator: &str) -> Option<Layout> {
    match allocator {
        "ExAllocatePool2" | "ExAllocatePool3" => Some(Layout {
            kind: KindArgument::Flags,
            size: 1,
            tag: Some(2),
        }),
        "ExAllocatePoolWithTag" | "ExAllocatePoolWithQuotaTag" => Some(Layout {
            kind: KindArgument::Type,
            size: 1,
            tag: Some(2),
        }),
        "ExAllocatePool" => Some(Layout {
            kind: KindArgument::Type,
            size: 1,
            tag: None,
        }),
        _ => None,
    }
}

/// One armed call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// The allocator the call reaches, as the driver imported it.
    pub allocator: String,
    /// The call instruction's address, where the entry breakpoint is.
    pub call: u64,
    /// The instruction after the call, where the return breakpoint is -- or `None` for a site that
    /// **jumps** to the allocator (a tail call), which never returns there and so is traced at
    /// entry only, with no address.
    pub returns_to: Option<u64>,
}

/// What a breakpoint of this trace is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// On the call, before it runs: the arguments are readable.
    Entry(usize),
    /// After it returns: the result is readable.
    Return(usize),
}

/// One traced allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    /// Order of arrival at the call, from zero, across the trace.
    pub sequence: u64,
    /// Index into the trace's sites.
    pub site: usize,
    /// The thread that made it, as the engine's thread data offset: the `KTHREAD` on a kernel.
    pub thread: u64,
    /// The first three integer arguments, as they were at the call.
    pub arguments: [u64; 3],
    /// What the allocator returned, or `None` for a site traced at entry only.
    pub address: Option<u64>,
}

/// A call seen at entry and not yet at its return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pending {
    sequence: u64,
    arguments: [u64; 3],
}

/// The trace: its sites, what each breakpoint is, and what has been recorded.
#[derive(Debug)]
pub struct Recorder {
    sites: Vec<Site>,
    breakpoints: HashMap<u32, Phase>,
    /// Calls in flight, by the thread that made them and the site they were made at. A call
    /// returns on the thread that made it, to the instruction after it -- so this pair names the
    /// one call a return belongs to.
    pending: HashMap<(u64, usize), Pending>,
    allocations: Vec<Allocation>,
    limit: usize,
    next_sequence: u64,
    /// Allocations seen after the trace filled, counted rather than recorded.
    dropped: u64,
    /// Hits whose registers could not be read, counted rather than recorded.
    unreadable: u64,
    /// Whether the limit has been reached. The hit that reaches it answers `Break`; every later one
    /// answers `Go`, so a caller who resumes a full trace is not stopped on each allocation.
    full: bool,
}

impl Recorder {
    /// A trace of `sites`, recording up to `limit` allocations.
    pub fn new(sites: Vec<Site>, limit: usize) -> Self {
        Self {
            sites,
            breakpoints: HashMap::new(),
            pending: HashMap::new(),
            allocations: Vec::new(),
            limit: limit.clamp(1, MAX_ALLOCATIONS),
            next_sequence: 0,
            dropped: 0,
            unreadable: 0,
            full: false,
        }
    }

    /// Records that breakpoint `id` is `phase`.
    pub fn arm(&mut self, id: u32, phase: Phase) {
        self.breakpoints.insert(id, phase);
    }

    /// What breakpoint `id` is to this trace, or `None` for one it did not set -- which the
    /// callback answers [`BreakpointAction::Default`], leaving it exactly as it was.
    pub fn phase_of(&self, id: u32) -> Option<Phase> {
        self.breakpoints.get(&id).copied()
    }

    /// The breakpoints this trace set, with what each is.
    pub fn armed(&self) -> impl Iterator<Item = (u32, Phase)> + '_ {
        self.breakpoints.iter().map(|(&id, &phase)| (id, phase))
    }

    pub fn sites(&self) -> &[Site] {
        &self.sites
    }

    /// A call at `site`, on `thread`, with `arguments`.
    pub fn entry(&mut self, site: usize, thread: u64, arguments: [u64; 3]) -> BreakpointAction {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        let returns = self
            .sites
            .get(site)
            .is_some_and(|site| site.returns_to.is_some());
        if !returns {
            // Traced at entry only: this is the whole allocation.
            return self.record(Allocation {
                sequence,
                site,
                thread,
                arguments,
                address: None,
            });
        }
        // The pending slot is taken whether or not the trace is full, so the return finds its
        // call either way and is counted rather than mistaken for an orphan.
        self.pending.insert(
            (thread, site),
            Pending {
                sequence,
                arguments,
            },
        );
        BreakpointAction::Go
    }

    /// A return from `site` on `thread`, with `value` in the return register.
    ///
    /// A return with no call pending -- the trace armed while a call was already in flight -- is
    /// not an allocation this trace saw made, so it records nothing.
    pub fn returned(&mut self, site: usize, thread: u64, value: u64) -> BreakpointAction {
        let Some(pending) = self.pending.remove(&(thread, site)) else {
            return BreakpointAction::Go;
        };
        self.record(Allocation {
            sequence: pending.sequence,
            site,
            thread,
            arguments: pending.arguments,
            address: Some(value),
        })
    }

    /// A hit whose registers could not be read.
    pub fn unreadable(&mut self) -> BreakpointAction {
        self.unreadable += 1;
        BreakpointAction::Go
    }

    fn record(&mut self, allocation: Allocation) -> BreakpointAction {
        if self.full {
            self.dropped += 1;
            return BreakpointAction::Go;
        }
        self.allocations.push(allocation);
        if self.allocations.len() >= self.limit {
            self.full = true;
            return BreakpointAction::Break;
        }
        BreakpointAction::Go
    }

    /// The allocations recorded so far, in the order they completed.
    pub fn allocations(&self) -> &[Allocation] {
        &self.allocations
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

    /// Calls seen at entry and not yet at their return.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(limit: usize) -> Recorder {
        let mut recorder = Recorder::new(
            vec![
                Site {
                    allocator: "ExAllocatePoolWithTag".into(),
                    call: 0x1000,
                    returns_to: Some(0x1004),
                },
                Site {
                    allocator: "ExAllocatePool2".into(),
                    call: 0x2000,
                    returns_to: None,
                },
            ],
            limit,
        );
        recorder.arm(10, Phase::Entry(0));
        recorder.arm(11, Phase::Return(0));
        recorder.arm(12, Phase::Entry(1));
        recorder
    }

    /// A breakpoint the trace did not set is not the trace's, so the callback leaves it alone.
    #[test]
    fn a_breakpoint_the_trace_did_not_set_is_not_its_own() {
        let recorder = trace(8);
        assert_eq!(recorder.phase_of(10), Some(Phase::Entry(0)));
        assert_eq!(recorder.phase_of(11), Some(Phase::Return(0)));
        assert_eq!(recorder.phase_of(99), None);
    }

    /// A return is paired with the call its thread made at that site, whatever ran in between.
    #[test]
    fn a_return_is_paired_with_its_own_threads_call() {
        let mut recorder = trace(8);
        assert_eq!(
            recorder.entry(0, 0xa, [0x200, 0x40, 0x6b636148]),
            BreakpointAction::Go
        );
        assert_eq!(
            recorder.entry(0, 0xb, [0x200, 0x80, 0x6b636148]),
            BreakpointAction::Go
        );
        assert_eq!(recorder.pending(), 2);
        // Thread b returns first.
        assert_eq!(
            recorder.returned(0, 0xb, 0xffff_0000_0000_2000),
            BreakpointAction::Go
        );
        assert_eq!(
            recorder.returned(0, 0xa, 0xffff_0000_0000_1000),
            BreakpointAction::Go
        );
        assert_eq!(recorder.pending(), 0);
        let allocations = recorder.allocations();
        assert_eq!(allocations.len(), 2);
        assert_eq!(
            (
                allocations[0].thread,
                allocations[0].arguments[1],
                allocations[0].address
            ),
            (0xb, 0x80, Some(0xffff_0000_0000_2000)),
            "thread b's call was the 0x80-byte one, and it is the one that returned first"
        );
        assert_eq!(
            (
                allocations[1].thread,
                allocations[1].arguments[1],
                allocations[1].address
            ),
            (0xa, 0x40, Some(0xffff_0000_0000_1000))
        );
        assert_eq!(
            (allocations[0].sequence, allocations[1].sequence),
            (1, 0),
            "sequence is the order of the calls, not of the returns"
        );
    }

    /// A return with no call pending was not seen made, and is not recorded.
    #[test]
    fn a_return_with_no_call_pending_records_nothing() {
        let mut recorder = trace(8);
        assert_eq!(recorder.returned(0, 0xa, 0x1234), BreakpointAction::Go);
        assert!(recorder.allocations().is_empty());
    }

    /// A site the allocator is jumped to is traced at entry: an allocation with no address.
    #[test]
    fn a_tail_called_site_is_an_allocation_at_entry_with_no_address() {
        let mut recorder = trace(8);
        assert_eq!(
            recorder.entry(1, 0xa, [0x40, 0x100, 0]),
            BreakpointAction::Go
        );
        assert_eq!(recorder.pending(), 0);
        assert_eq!(recorder.allocations()[0].address, None);
    }

    /// The allocation that fills the trace stops the target, once; later ones are counted and let
    /// through, so a full trace that is resumed does not stop on every allocation.
    #[test]
    fn a_full_trace_breaks_once_and_then_counts() {
        let mut recorder = trace(2);
        recorder.entry(0, 0xa, [0; 3]);
        assert_eq!(recorder.returned(0, 0xa, 1), BreakpointAction::Go);
        recorder.entry(0, 0xa, [0; 3]);
        assert_eq!(
            recorder.returned(0, 0xa, 2),
            BreakpointAction::Break,
            "the second of two fills the trace"
        );
        assert!(recorder.full());
        recorder.entry(0, 0xa, [0; 3]);
        assert_eq!(recorder.returned(0, 0xa, 3), BreakpointAction::Go);
        assert_eq!(recorder.entry(1, 0xa, [0; 3]), BreakpointAction::Go);
        assert_eq!(recorder.allocations().len(), 2);
        assert_eq!(recorder.dropped(), 2);
    }

    /// The limit is clamped to what a trace may hold, and to at least one.
    #[test]
    fn the_limit_is_clamped() {
        assert_eq!(Recorder::new(Vec::new(), 0).limit(), 1);
        assert_eq!(
            Recorder::new(Vec::new(), MAX_ALLOCATIONS + 1).limit(),
            MAX_ALLOCATIONS
        );
    }

    /// The pool allocators are the ones with layouts, and the `Mm` allocators are not pool.
    #[test]
    fn only_the_pool_allocators_have_layouts() {
        assert_eq!(
            layout_of("ExAllocatePool2").map(|layout| layout.kind),
            Some(KindArgument::Flags)
        );
        assert_eq!(
            layout_of("ExAllocatePoolWithTag").map(|layout| (layout.kind, layout.tag)),
            Some((KindArgument::Type, Some(2)))
        );
        assert_eq!(
            layout_of("ExAllocatePool").map(|layout| layout.tag),
            Some(None)
        );
        assert_eq!(layout_of("MmAllocateContiguousMemory"), None);
        assert_eq!(layout_of("MmAllocateNonCachedMemory"), None);
    }
}
