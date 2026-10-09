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
    /// `None` for a call whose argument registers would not read. It holds its place all the
    /// same, so the return that belongs to it pairs with it rather than with the call beneath.
    arguments: Option<[u64; 3]>,
}

/// The most calls the trace holds waiting on their return.
///
/// **A bound, because not every call returns to where the trace is waiting.** One whose return
/// breakpoint was cleared never pops, and neither does one an exception unwound past -- an
/// allocator asked to raise on failure does exactly that. Unbounded, a hot site in either state
/// grows the worker's memory for as long as the target runs. At the bound the **oldest** waiting
/// call is given up on: a call that returns does so within microseconds of target time, so the
/// oldest are the ones that will not, and the calls still in flight are the newest.
pub const MAX_PENDING: usize = 256;

/// The trace: its sites, what each breakpoint is, and what has been recorded.
#[derive(Debug)]
pub struct Recorder {
    sites: Vec<Site>,
    /// The command every breakpoint of this trace carries, and the only thing that makes one this
    /// trace's -- see [`Self::phase_of`].
    marker: String,
    breakpoints: HashMap<u32, Phase>,
    /// Calls in flight, by the thread that made them and the site they were made at. A call
    /// returns on the thread that made it, to the instruction after it -- so this pair names the
    /// calls a return can belong to, and of those it is the **latest**: a second call at one site
    /// on one thread is one an interrupt or a DPC made while the first was still inside the
    /// allocator, and it returns first. So each pair holds a stack rather than a slot, which would
    /// let the inner call overwrite the outer and leave the outer's return with nothing to pair.
    pending: HashMap<(u64, usize), Vec<Pending>>,
    allocations: Vec<Allocation>,
    limit: usize,
    next_sequence: u64,
    /// Allocations seen after the trace filled, counted rather than recorded.
    dropped: u64,
    /// Hits whose registers could not be read, counted rather than recorded.
    unreadable: u64,
    /// Calls given up on while waiting for their return -- past [`MAX_PENDING`], or abandoned when
    /// a hit at their site could not say which thread it was on.
    unpaired: u64,
    /// Whether the limit has been reached. The hit that reaches it answers `Break`; every later one
    /// answers `Go`, so a caller who resumes a full trace is not stopped on each allocation.
    full: bool,
}

impl Recorder {
    /// A trace of `sites`, recording up to `limit` allocations, whose breakpoints carry `marker`.
    pub fn new(sites: Vec<Site>, limit: usize, marker: String) -> Self {
        Self {
            sites,
            marker,
            breakpoints: HashMap::new(),
            pending: HashMap::new(),
            allocations: Vec::new(),
            limit: limit.clamp(1, MAX_ALLOCATIONS),
            next_sequence: 0,
            dropped: 0,
            unreadable: 0,
            unpaired: 0,
            full: false,
        }
    }

    /// Records that breakpoint `id` is `phase`.
    pub fn arm(&mut self, id: u32, phase: Phase) {
        self.breakpoints.insert(id, phase);
    }

    /// The command this trace's breakpoints carry.
    pub fn marker(&self) -> &str {
        &self.marker
    }

    /// What a hit on breakpoint `id`, whose command is `command`, is to this trace -- or `None`
    /// for one it did not set, which the callback answers [`BreakpointAction::Default`], leaving
    /// it exactly as it was.
    ///
    /// **The breakpoint's own command, because its id is not the trace's to keep.** The engine
    /// hands a removed breakpoint's id to the next one set, so one of the trace's that something
    /// else cleared comes back as the caller's own, at any address including the same one -- and a
    /// hit on it taken for an allocation would be answered *go* rather than stopping where the
    /// caller asked. The marker is written into the breakpoint when the trace sets it, so it leaves
    /// with the breakpoint, whatever happens to the id. Review on #473 found the id alone, then the
    /// id and the address, short of this in successive rounds.
    pub fn phase_of(&self, id: u32, command: Option<&str>) -> Option<Phase> {
        if command != Some(self.marker.as_str()) {
            return None;
        }
        self.breakpoints.get(&id).copied()
    }

    /// The breakpoints this trace set, with what each is.
    pub fn armed(&self) -> impl Iterator<Item = (u32, Phase)> + '_ {
        self.breakpoints.iter().map(|(&id, &phase)| (id, phase))
    }

    pub fn sites(&self) -> &[Site] {
        &self.sites
    }

    /// A call at `site`, on `thread`, with `arguments` -- `None` where they would not read.
    pub fn entry(
        &mut self,
        site: usize,
        thread: u64,
        arguments: Option<[u64; 3]>,
    ) -> BreakpointAction {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        if arguments.is_none() {
            self.unreadable += 1;
        }
        let returns = self
            .sites
            .get(site)
            .is_some_and(|site| site.returns_to.is_some());
        if !returns {
            // Traced at entry only: this is the whole allocation.
            return match arguments {
                Some(arguments) => self.record(Allocation {
                    sequence,
                    site,
                    thread,
                    arguments,
                    address: None,
                }),
                None => BreakpointAction::Go,
            };
        }
        // Pending whether or not the trace is full, so the return finds its call either way and is
        // counted rather than mistaken for an orphan.
        self.hold(
            (thread, site),
            Pending {
                sequence,
                arguments,
            },
        );
        BreakpointAction::Go
    }

    /// A return from `site` on `thread`, with `value` in the return register -- `None` where it
    /// would not read.
    ///
    /// A return with no call pending -- the trace armed while a call was already in flight -- is
    /// not an allocation this trace saw made, so it records nothing. One whose call or value would
    /// not read still takes its call off the stack, so the next return pairs with the right one.
    pub fn returned(&mut self, site: usize, thread: u64, value: Option<u64>) -> BreakpointAction {
        // A hit of its own, counted as one whatever became of the call it belongs to.
        if value.is_none() {
            self.unreadable += 1;
        }
        let Some(calls) = self.pending.get_mut(&(thread, site)) else {
            return BreakpointAction::Go;
        };
        let Some(pending) = calls.pop() else {
            return BreakpointAction::Go;
        };
        if calls.is_empty() {
            self.pending.remove(&(thread, site));
        }
        match (pending.arguments, value) {
            (Some(arguments), Some(value)) => self.record(Allocation {
                sequence: pending.sequence,
                site,
                thread,
                arguments,
                address: Some(value),
            }),
            // Each unreadable hit is counted where it happened.
            _ => BreakpointAction::Go,
        }
    }

    /// A hit at `site` that could not say which thread it was on. Nothing at that site can be
    /// paired after it -- the call it was, or the return, belongs to a thread it cannot name -- so
    /// every call waiting there is given up on rather than left for a later return to take.
    pub fn threadless(&mut self, site: usize) -> BreakpointAction {
        self.unreadable += 1;
        let keys: Vec<(u64, usize)> = self
            .pending
            .keys()
            .filter(|&&(_, at)| at == site)
            .copied()
            .collect();
        for key in keys {
            if let Some(calls) = self.pending.remove(&key) {
                self.unpaired += calls.len() as u64;
            }
        }
        BreakpointAction::Go
    }

    /// Holds a call until its return, giving up on the oldest waiting call at the bound.
    fn hold(&mut self, key: (u64, usize), call: Pending) {
        if self.pending() >= MAX_PENDING {
            // The bottom of each stack is its oldest call, since calls are pushed in order.
            let oldest = self
                .pending
                .iter()
                .filter_map(|(&key, calls)| calls.first().map(|call| (call.sequence, key)))
                .min()
                .map(|(_, key)| key);
            if let Some(oldest) = oldest
                && let Some(calls) = self.pending.get_mut(&oldest)
            {
                calls.remove(0);
                if calls.is_empty() {
                    self.pending.remove(&oldest);
                }
                self.unpaired += 1;
            }
        }
        self.pending.entry(key).or_default().push(call);
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

    pub fn unpaired(&self) -> u64 {
        self.unpaired
    }

    /// Calls seen at entry and not yet at their return.
    pub fn pending(&self) -> usize {
        self.pending.values().map(Vec::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = "$$ pool_trace 7";

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
            MARKER.to_string(),
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
        assert_eq!(recorder.phase_of(10, Some(MARKER)), Some(Phase::Entry(0)));
        assert_eq!(recorder.phase_of(11, Some(MARKER)), Some(Phase::Return(0)));
        assert_eq!(recorder.phase_of(99, None), None);
    }

    /// **An id the trace was given is not the trace's once the breakpoint is somebody else's**,
    /// wherever it is -- the same instruction included. The engine reuses a removed breakpoint's
    /// id for the next one set, so the caller clearing the trace's breakpoint and setting their own
    /// on that instruction, in one command, gets the trace's id at the trace's address. Only the
    /// marker the trace wrote into its own breakpoint tells the two apart, and a hit on the
    /// caller's taken for an allocation would be answered *go* instead of stopping.
    #[test]
    fn a_reused_id_carrying_no_marker_is_not_the_traces() {
        let recorder = trace(8);
        assert_eq!(
            recorder.phase_of(10, None),
            None,
            "id 10 was the trace's; with no command it is the caller's breakpoint"
        );
        assert_eq!(
            recorder.phase_of(10, Some(".echo hit")),
            None,
            "nor with a command of their own"
        );
        assert_eq!(
            recorder.phase_of(10, Some("$$ pool_trace 6")),
            None,
            "nor with an earlier trace's marker"
        );
    }

    /// A return is paired with the call its thread made at that site, whatever ran in between.
    #[test]
    fn a_return_is_paired_with_its_own_threads_call() {
        let mut recorder = trace(8);
        assert_eq!(
            recorder.entry(0, 0xa, Some([0x200, 0x40, 0x6b636148])),
            BreakpointAction::Go
        );
        assert_eq!(
            recorder.entry(0, 0xb, Some([0x200, 0x80, 0x6b636148])),
            BreakpointAction::Go
        );
        assert_eq!(recorder.pending(), 2);
        // Thread b returns first.
        assert_eq!(
            recorder.returned(0, 0xb, Some(0xffff_0000_0000_2000)),
            BreakpointAction::Go
        );
        assert_eq!(
            recorder.returned(0, 0xa, Some(0xffff_0000_0000_1000)),
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

    /// **Calls nested at one site on one thread unwind innermost first.** The second is one an
    /// interrupt or a DPC made while the first was still in the allocator; it returns first, and
    /// the outer return must still find the outer call.
    #[test]
    fn calls_nested_at_one_site_on_one_thread_pair_innermost_first() {
        let mut recorder = trace(8);
        recorder.entry(0, 0xa, Some([0x200, 0x40, 0]));
        recorder.entry(0, 0xa, Some([0x200, 0x80, 0]));
        assert_eq!(recorder.pending(), 2);
        recorder.returned(0, 0xa, Some(0x2000));
        recorder.returned(0, 0xa, Some(0x1000));
        assert_eq!(recorder.pending(), 0);
        let allocations = recorder.allocations();
        assert_eq!(
            (allocations[0].arguments[1], allocations[0].address),
            (0x80, Some(0x2000)),
            "the inner call returned first, with its own address"
        );
        assert_eq!(
            (allocations[1].arguments[1], allocations[1].address),
            (0x40, Some(0x1000)),
            "and the outer one was not lost to it"
        );
    }

    /// **A call whose registers would not read still holds its place.** Nested inside a readable
    /// one, its return takes it off the stack -- recording nothing -- and the outer return still
    /// finds the outer call, rather than the inner return pairing the outer call's arguments with
    /// the inner call's address.
    #[test]
    fn an_unreadable_call_holds_its_place_in_the_pairing() {
        let mut recorder = trace(8);
        recorder.entry(0, 0xa, Some([0x200, 0x40, 0]));
        recorder.entry(0, 0xa, None);
        recorder.returned(0, 0xa, Some(0x2000));
        assert!(
            recorder.allocations().is_empty(),
            "the inner return belongs to the unreadable call, not the outer one"
        );
        recorder.returned(0, 0xa, Some(0x1000));
        assert_eq!(
            recorder
                .allocations()
                .iter()
                .map(|allocation| (allocation.arguments[1], allocation.address))
                .collect::<Vec<_>>(),
            [(0x40, Some(0x1000))]
        );
        assert_eq!(recorder.unreadable_hits(), 1);
    }

    /// A return whose value would not read takes its call with it and records nothing.
    #[test]
    fn an_unreadable_return_takes_its_call_with_it() {
        let mut recorder = trace(8);
        recorder.entry(0, 0xa, Some([0x200, 0x40, 0]));
        recorder.entry(0, 0xa, Some([0x200, 0x80, 0]));
        recorder.returned(0, 0xa, None);
        recorder.returned(0, 0xa, Some(0x1000));
        assert_eq!(
            recorder
                .allocations()
                .iter()
                .map(|allocation| allocation.arguments[1])
                .collect::<Vec<_>>(),
            [0x40],
            "the outer return pairs with the outer call"
        );
        assert_eq!(recorder.unreadable_hits(), 1);
    }

    /// **Each unreadable hit is counted once**: a call whose arguments would not read and whose
    /// return value would not either is two hits that read nothing, not one.
    #[test]
    fn an_unreadable_call_and_its_unreadable_return_are_two_hits() {
        let mut recorder = trace(8);
        recorder.entry(0, 0xa, None);
        recorder.returned(0, 0xa, None);
        assert_eq!(recorder.unreadable_hits(), 2);
        assert_eq!(recorder.pending(), 0);
    }

    /// A hit that cannot say which thread it was on gives up on every call waiting at its site,
    /// since any of them might be the one it was, and leaves other sites alone.
    #[test]
    fn a_threadless_hit_gives_up_on_its_sites_waiting_calls() {
        let mut recorder = Recorder::new(
            vec![
                Site {
                    allocator: "ExAllocatePoolWithTag".into(),
                    call: 0x1000,
                    returns_to: Some(0x1004),
                },
                Site {
                    allocator: "ExAllocatePoolWithTag".into(),
                    call: 0x3000,
                    returns_to: Some(0x3004),
                },
            ],
            8,
            MARKER.to_string(),
        );
        recorder.entry(0, 0xa, Some([0; 3]));
        recorder.entry(0, 0xb, Some([0; 3]));
        recorder.entry(1, 0xa, Some([0; 3]));
        recorder.threadless(0);
        assert_eq!((recorder.pending(), recorder.unpaired()), (1, 2));
        assert_eq!(
            recorder.returned(0, 0xa, Some(0x1000)),
            BreakpointAction::Go
        );
        assert!(recorder.allocations().is_empty());
        recorder.returned(1, 0xa, Some(0x3000));
        assert_eq!(
            recorder.allocations().len(),
            1,
            "the other site still pairs"
        );
    }

    /// **Waiting calls are bounded, and the oldest are given up first.** A site whose return
    /// breakpoint is gone, or whose calls an exception unwinds past, never pops; unbounded, it
    /// grows for as long as the target runs. A call that does return is a recent one, so the
    /// eviction lands on the ones that will not.
    #[test]
    fn waiting_calls_are_bounded_and_the_oldest_go_first() {
        let mut recorder = trace(8);
        for thread in 0..MAX_PENDING as u64 {
            recorder.entry(0, thread, Some([0, thread, 0]));
        }
        assert_eq!(recorder.pending(), MAX_PENDING);
        recorder.entry(0, 0xffff, Some([0, 0xffff, 0]));
        assert_eq!((recorder.pending(), recorder.unpaired()), (MAX_PENDING, 1));
        recorder.returned(0, 0, Some(0x1000));
        assert!(
            recorder.allocations().is_empty(),
            "thread 0's call was the oldest, and was the one given up on"
        );
        recorder.returned(0, 0xffff, Some(0x2000));
        assert_eq!(recorder.allocations()[0].arguments[1], 0xffff);
    }

    /// A return with no call pending was not seen made, and is not recorded.
    #[test]
    fn a_return_with_no_call_pending_records_nothing() {
        let mut recorder = trace(8);
        assert_eq!(
            recorder.returned(0, 0xa, Some(0x1234)),
            BreakpointAction::Go
        );
        assert!(recorder.allocations().is_empty());
    }

    /// A site the allocator is jumped to is traced at entry: an allocation with no address.
    #[test]
    fn a_tail_called_site_is_an_allocation_at_entry_with_no_address() {
        let mut recorder = trace(8);
        assert_eq!(
            recorder.entry(1, 0xa, Some([0x40, 0x100, 0])),
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
        recorder.entry(0, 0xa, Some([0; 3]));
        assert_eq!(recorder.returned(0, 0xa, Some(1)), BreakpointAction::Go);
        recorder.entry(0, 0xa, Some([0; 3]));
        assert_eq!(
            recorder.returned(0, 0xa, Some(2)),
            BreakpointAction::Break,
            "the second of two fills the trace"
        );
        assert!(recorder.full());
        recorder.entry(0, 0xa, Some([0; 3]));
        assert_eq!(recorder.returned(0, 0xa, Some(3)), BreakpointAction::Go);
        assert_eq!(recorder.entry(1, 0xa, Some([0; 3])), BreakpointAction::Go);
        assert_eq!(recorder.allocations().len(), 2);
        assert_eq!(recorder.dropped(), 2);
    }

    /// The limit is clamped to what a trace may hold, and to at least one.
    #[test]
    fn the_limit_is_clamped() {
        assert_eq!(Recorder::new(Vec::new(), 0, MARKER.into()).limit(), 1);
        assert_eq!(
            Recorder::new(Vec::new(), MAX_ALLOCATIONS + 1, MARKER.into()).limit(),
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
