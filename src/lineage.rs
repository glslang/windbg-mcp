//! Whether a call stack could have been produced by calls — `stack_lineage`'s judgement.
//!
//! **Engine-free, so every rule is a unit test.** The worker observes — the walk, which module
//! holds each frame, whether the engine has unwind data for it, the bytes before each return
//! address, the shadow stack — and hands this module values; [`judge`] decides. Nothing here
//! touches a target, which is the [`crate::walk`] shape and for the same reason: the rules are
//! where this tool can be wrong, and a fake stack is the only place they can be pinned.
//!
//! `docs/stack-lineage-plan.md` is the design and the measurements it rests on. Three of them
//! decide most of what follows, and each is the reason for one rule:
//!
//! - **A walk the engine guessed looks exactly like a spoofed one.** A dump whose image is not on
//!   the host gives the walker no unwind data, and the frames it then reads off `[rsp]` are stack
//!   addresses and small integers — in no module, preceded by no call. Judged, two ordinary
//!   checked-in crash dumps read as spoofed. So a frame is judged only when the walk can vouch for
//!   how it got there ([`ReachedBy`]), and the first frame it cannot vouch for ends the judging.
//! - **A zero shadow-stack pointer is not a clean shadow stack.** The x64 samples record no CET
//!   state at all and still read `ssp=0`, exactly as a thread with shadow stacks off does. Zero is
//!   therefore an absence of evidence, and only the shadow stack's *presence* can earn
//!   `consistent`.
//! - **The call-site test holds on real stacks**: every return address on the clean x64 and ARM64
//!   kernel walks in `docs/samples/` follows an `e8 rel32` or a `bl`, and the exceptions are the
//!   frame under a trap dispatcher, which is what [`CallSite::ResumedContext`] is for.

use crate::structured::{
    CallSite, FindingKind, FrameInfo, FrameLineage, LineageFinding, LineageVerdict, ReachedBy,
    ShadowAbsence, ShadowMatch, ShadowReadStop, ShadowStack, ShadowStatus, StackLineage, addr,
};
use dbgscope::dbgeng::{Flow, InstructionSet, decode_instruction};

/// How many shadow-stack entries past the walk's own need are read.
///
/// The walk needs one entry per return address. The margin is what lets an unmatched frame be
/// called `missing` rather than `not_checked` when it is the last one: the read went on past where
/// it would have been. It also absorbs a handful of hidden calls before the frame that follows
/// them, which is the case a desynchronising spoof produces.
pub const SHADOW_MARGIN: usize = 16;

/// The longest x86/x64 instruction, and so the most bytes before a return address that can belong
/// to the call ending there.
pub const MAX_CALL_BYTES: usize = 15;

/// Everything the worker observed, before anything is judged.
pub struct Observed {
    /// Innermost first, as the walk returned them.
    pub frames: Vec<ObservedFrame>,
    pub frames_truncated: bool,
    pub shadow: ShadowObservation,
}

/// One frame, and the three readings the worker took of it.
pub struct ObservedFrame {
    /// The record `backtrace` returns for the same frame.
    pub info: FrameInfo,
    /// [`FrameInfo::address`] as a number.
    pub address: u64,
    pub placed: Placed,
    /// Whether the engine holds unwind data for **this** frame's code — which decides how the frame
    /// *under* it was found.
    pub unwind: Unwind,
    /// What ends at [`Self::address`]. Meaningless for frame 0, whose address is no return address.
    pub preceding: Preceding,
}

/// Which module holds a frame: the three answers `triage::Attribution` keeps apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placed {
    InModule,
    /// The engine established that no loaded module holds it — a positive finding.
    NoModule,
    /// The lookup failed, which is no finding at all.
    Unknown,
}

/// What the engine said about a frame's unwind entry (`DebugEngine::function_extent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unwind {
    Entry,
    /// The engine answered that there is none. **For frame 0 it means the engine also holds the
    /// image's unwind table**, so the absence is a fact about the code — a leaf — and not about a
    /// capture that left the image behind; the worker establishes that before saying so, and says
    /// [`Self::Unknown`] otherwise. Deeper frames are not checked, since nothing turns on it there.
    NoEntry,
    /// The lookup failed, or answered "no entry" for a frame 0 whose image's table the engine does
    /// not hold.
    Unknown,
    /// An instruction set with no unwind tables (x86), where the walker never had any.
    NotApplicable,
}

/// What ends at a return address, read from the bytes before it ([`preceding`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preceding {
    Call,
    SystemCall,
    /// Every byte that could have belonged to a call was read, and none of them ends in one.
    Other,
    /// Not enough could be read to rule a call out.
    Unreadable,
    /// An instruction set this does not decode.
    NotDecoded,
}

/// The shadow stack, as the worker found it.
pub enum ShadowObservation {
    /// Nothing to compare against, and why. `pointer`/`msr` are whatever was read on the way to
    /// finding that out, reported so a zero is visible as a zero.
    Unavailable {
        reason: ShadowAbsence,
        pointer: Option<u64>,
        msr: Option<u64>,
    },
    /// The pointer was real; these are the entries read up from it ([`shadow_entries`]).
    Read {
        pointer: u64,
        msr: u64,
        entries: Vec<u64>,
        /// Why the read ended before it had everything it asked for, if it did.
        stopped: Option<ShadowReadStop>,
    },
}

/// Classifies the bytes immediately before `end` — `bytes.last()` is the byte at `end - 1`.
///
/// **Every start that would end exactly at `end` is tried**, because x86 cannot be decoded
/// backwards: the instruction before a return address is whichever one, decoded from its own
/// first byte, is exactly as long as the distance to the address. A call of that length is a call;
/// anything else is not. The usual shapes are `e8 rel32` (five bytes) and `ff 15 disp32` (six), but
/// a prefixed indirect call (`3e ff d0`, CET's `notrack`) or a long `ff /2` through a SIB byte is
/// a call just the same, so the search does not stop at the common lengths.
///
/// **Fewer than [`MAX_CALL_BYTES`] bytes and no call is [`Preceding::Unreadable`]**, not
/// [`Preceding::Other`]: a longer call starting in the bytes that would not read has not been ruled
/// out, and saying "no call" about bytes nobody saw would be a finding made of a failed read.
///
/// ARM64 is fixed-width, so there is one candidate: the word before the address, which a `bl` or
/// a `blr` (and their authenticating forms) is. `svc` is the system call there; `syscall`,
/// `sysenter`, `int 2eh` and the hypercalls on x86/x64.
pub fn preceding(bytes: &[u8], end: u64, set: InstructionSet) -> Preceding {
    match set {
        InstructionSet::Arm64 => {
            let Some(word) = bytes.len().checked_sub(4).map(|start| &bytes[start..]) else {
                return Preceding::Unreadable;
            };
            // Memory holds the word little-endian and `decode_instruction` takes it most
            // significant byte first (its own doc comment), so reverse.
            let word = [word[3], word[2], word[1], word[0]];
            let instruction = decode_instruction(&word, end.wrapping_sub(4), set);
            match instruction.flow {
                Flow::Call(_) => Preceding::Call,
                _ if instruction.mnemonic == "svc" => Preceding::SystemCall,
                _ => Preceding::Other,
            }
        }
        InstructionSet::X86 | InstructionSet::Amd64 => {
            let available = bytes.len().min(MAX_CALL_BYTES);
            let mut system_call = false;
            for length in 1..=available {
                let start = bytes.len() - length;
                let candidate = &bytes[start..];
                let instruction =
                    decode_instruction(candidate, end.wrapping_sub(length as u64), set);
                // `bytes` is the hex of what the instruction occupies, so its length says whether it
                // ends exactly at `end`. An instruction that did not decode reports the whole
                // candidate, but with `Flow::Unknown`, which is no call.
                if instruction.bytes.len() != length * 2 {
                    continue;
                }
                // **Asked before the flow**, because iced's `FlowControl::Call` includes
                // `SYSCALL`, `SYSENTER`, `VMCALL` and `VMMCALL` and dbgscope maps it to
                // `Flow::Call` — so a syscall's return read as an ordinary call's until a test
                // said otherwise. Both are non-findings; the distinction is for the reader.
                if matches!(
                    instruction.mnemonic.as_str(),
                    "syscall" | "sysenter" | "vmcall" | "vmmcall"
                ) || candidate == [0xcd, 0x2e]
                {
                    system_call = true;
                    continue;
                }
                if matches!(instruction.flow, Flow::Call(_)) {
                    return Preceding::Call;
                }
            }
            if system_call {
                Preceding::SystemCall
            } else if available < MAX_CALL_BYTES {
                Preceding::Unreadable
            } else {
                Preceding::Other
            }
        }
        InstructionSet::Other(_) => Preceding::NotDecoded,
    }
}

/// Splits a read of the shadow stack, taken upward from `pointer`, into its entries.
///
/// **A restore token ends it.** A token is the one value a shadow stack holds that is not a return
/// address — it is written where a stack was switched away from, and its value, with the two flag
/// bits masked, is its own address plus eight. Past it lies another stack's entries, which a frame
/// of this walk could match only by accident. No return address can satisfy the test, since it
/// names a location in the shadow stack itself.
///
/// Trailing bytes short of a whole entry are dropped: a read is asked for in whole entries, so
/// they can only be the end of a page the caller cut.
pub fn shadow_entries(bytes: &[u8], pointer: u64) -> (Vec<u64>, Option<ShadowReadStop>) {
    let mut entries = Vec::with_capacity(bytes.len() / 8);
    let (whole, _) = bytes.as_chunks::<8>();
    for (slot, chunk) in whole.iter().enumerate() {
        let value = u64::from_le_bytes(*chunk);
        let at = pointer.wrapping_add(8 * slot as u64);
        if value & !0b11 == at.wrapping_add(8) {
            return (entries, Some(ShadowReadStop::Token));
        }
        entries.push(value);
    }
    (entries, None)
}

/// Whether a frame resumes a saved context rather than returning — the exception, APC and callback
/// dispatchers of `ntdll` and the kernel's trap and exception entries, all of which are `Ki*`
/// routines of `ntdll` or `nt`.
///
/// **A curated rule, not a reading of the unwind record**, and the plan says so: the fact is in the
/// unwind codes (`UWOP_PUSH_MACHFRAME` on x64, ARM64's trap-frame code `E8` — measured on
/// `nt!KiArm64ExceptionVectors`), and reading them needs a primitive dbgscope does not have. It is
/// applied only where the bytes have already failed to show a call, so a `Ki*` routine that calls
/// normally — `nt!KiDispatchException` — changes nothing, and what a missed dispatcher costs is a
/// `not_preceded_by_call` with the frame above it named.
fn resumes_context(above: &FrameInfo) -> bool {
    let Some((module, name)) = above.symbol.as_deref().and_then(|s| s.split_once('!')) else {
        return false;
    };
    matches!(module, "nt" | "ntdll") && name.starts_with("Ki")
}

/// Judges what was observed. See the module docs and `docs/stack-lineage-plan.md` §3.
pub fn judge(observed: Observed) -> StackLineage {
    let Observed {
        frames,
        frames_truncated,
        shadow,
    } = observed;
    let count = frames.len();

    let call_sites: Vec<CallSite> = (0..count)
        .map(|i| {
            if i == 0 {
                return CallSite::NotAReturnAddress;
            }
            match frames[i].preceding {
                Preceding::Call => CallSite::Call,
                Preceding::SystemCall => CallSite::SystemCall,
                Preceding::NotDecoded => CallSite::NotDecoded,
                // Asked only once the bytes have failed to show a call — so a dispatcher's
                // ordinary calls are still calls — and whether or not they could be read: the
                // address under a dispatcher is the interrupted instruction, which no call test
                // applies to.
                Preceding::Other | Preceding::Unreadable
                    if resumes_context(&frames[i - 1].info) =>
                {
                    CallSite::ResumedContext
                }
                Preceding::Unreadable => CallSite::Unreadable,
                Preceding::Other => CallSite::NotACall,
            }
        })
        .collect();

    let (reached, walk_lost_at) = reach(&frames, &call_sites);
    let compared = align(&frames, &call_sites, &reached, &shadow);

    let mut findings = Vec::new();
    for i in 0..count {
        if !judged(reached[i]) {
            continue;
        }
        let index = frames[i].info.index;
        let mut found = |kind| findings.push(LineageFinding { frame: index, kind });
        if frames[i].placed == Placed::NoModule {
            found(FindingKind::UnbackedCode);
        }
        if call_sites[i] == CallSite::NotACall {
            found(FindingKind::NotPrecededByCall);
        }
        if compared.matches[i] == ShadowMatch::Missing {
            found(FindingKind::MissingFromShadowStack);
        }
        if compared.hidden[i] > 0 {
            found(FindingKind::HiddenCalls);
        }
    }

    let verdict = if !findings.is_empty() {
        LineageVerdict::Suspicious
    } else if compared.status == ShadowStatus::Compared
        && walk_lost_at.is_none()
        && !frames_truncated
        && compared.matches.contains(&ShadowMatch::Matched)
        // A call the CPU recorded and the walk does not show is a disagreement whoever it is
        // about, even where it is no finding (an inferred frame's).
        && compared.hidden.iter().all(|&hidden| hidden == 0)
        && (1..count).all(|i| {
            compared.matches[i] == ShadowMatch::Matched || exempt_from_shadow(call_sites[i])
        })
    {
        LineageVerdict::Consistent
    } else {
        LineageVerdict::Unknown
    };

    let shadow_stack = compared.report(&shadow);
    let frames = frames
        .into_iter()
        .enumerate()
        .map(|(i, frame)| FrameLineage {
            frame: frame.info,
            reached_by: reached[i],
            call_site: call_sites[i],
            shadow: compared.matches[i],
            shadow_slot: compared.slots[i],
        })
        .collect();
    StackLineage {
        verdict,
        frames,
        frames_truncated,
        walk_lost_at,
        shadow_stack,
        findings,
    }
}

/// Whether what was found at a frame reached this way is evidence about the target.
fn judged(reached: ReachedBy) -> bool {
    matches!(
        reached,
        ReachedBy::Context | ReachedBy::UnwindData | ReachedBy::LeafRule
    )
}

/// Frames the CPU pushed nothing for, which are not looked for on the shadow stack.
fn exempt_from_shadow(call_site: CallSite) -> bool {
    matches!(call_site, CallSite::ResumedContext | CallSite::SystemCall)
}

/// How the walk reached each frame, and the first frame it could not vouch for.
///
/// **A frame is judged when the walk can say how it got there.** Through the frame above's unwind
/// data from a frame that was itself judged; or, for frame 1 alone, through the leaf rule when
/// frame 0 has no unwind entry — which the x64 and ARM64 ABIs make exact for a function that calls
/// nothing (a syscall stub, the commonest frame 0 there is), and which is kept only when it checks
/// out. Anything else is the walker's inference: kept if it checks out, and judged by nothing
/// either way, since a garbage walk produces a stale return address that checks out by chance.
///
/// **The first frame that does not check out ends the walk, permanently.** Re-anchoring on a later
/// plausible frame would turn the rest of a garbage walk back into evidence.
fn reach(frames: &[ObservedFrame], call_sites: &[CallSite]) -> (Vec<ReachedBy>, Option<u32>) {
    let mut reached = vec![ReachedBy::BeyondWalk; frames.len()];
    let Some(first) = reached.first_mut() else {
        return (reached, None);
    };
    *first = ReachedBy::Context;
    let checks_out = |i: usize| {
        frames[i].placed == Placed::InModule
            && matches!(
                call_sites[i],
                CallSite::Call | CallSite::SystemCall | CallSite::ResumedContext
            )
    };
    for i in 1..frames.len() {
        let above_judged = judged(reached[i - 1]);
        let next = match frames[i - 1].unwind {
            Unwind::Entry if above_judged => ReachedBy::UnwindData,
            Unwind::NoEntry if above_judged && i == 1 && checks_out(i) => ReachedBy::LeafRule,
            _ if checks_out(i) => ReachedBy::Inferred,
            _ => return (reached, Some(frames[i].info.index)),
        };
        reached[i] = next;
    }
    (reached, None)
}

/// The walk laid against the shadow stack.
struct Compared {
    status: ShadowStatus,
    matches: Vec<ShadowMatch>,
    slots: Vec<Option<u32>>,
    /// Per frame: entries passed over to reach it.
    hidden: Vec<u32>,
    entries_read: u32,
}

impl Compared {
    fn report(&self, shadow: &ShadowObservation) -> ShadowStack {
        let skipped_entries = self.hidden.iter().sum();
        match shadow {
            ShadowObservation::Unavailable {
                reason,
                pointer,
                msr,
            } => ShadowStack {
                status: ShadowStatus::Unavailable,
                unavailable: Some(*reason),
                pointer: pointer.map(addr),
                cet_msr: msr.map(addr),
                entries_read: 0,
                read_stopped: None,
                skipped_entries,
            },
            ShadowObservation::Read {
                pointer,
                msr,
                stopped,
                ..
            } => ShadowStack {
                status: self.status,
                unavailable: None,
                pointer: Some(addr(*pointer)),
                cet_msr: Some(addr(*msr)),
                entries_read: self.entries_read,
                read_stopped: *stopped,
                skipped_entries,
            },
        }
    }
}

/// Looks each frame's return address up on the shadow stack, from a cursor that only moves on.
///
/// Found at the cursor is the ordinary case. Found further on means the entries passed over are
/// calls the CPU recorded and the walk does not show. Not found is `missing` only when the shadow
/// stack demonstrably went past where the address would be — a later frame matched, or the read
/// reached its margin without stopping — and `not_checked` when the read stopped first, since the
/// address may sit in what was not read.
///
/// Every frame the walk reached is looked for, the inferred ones included: the shadow stack is the
/// CPU's record and vouches for a frame however the walker found it. Whether a mismatch is a
/// *finding* is [`judge`]'s question, not this one's.
fn align(
    frames: &[ObservedFrame],
    call_sites: &[CallSite],
    reached: &[ReachedBy],
    shadow: &ShadowObservation,
) -> Compared {
    let count = frames.len();
    let mut compared = Compared {
        status: ShadowStatus::Unavailable,
        matches: vec![ShadowMatch::NotChecked; count],
        slots: vec![None; count],
        hidden: vec![0; count],
        entries_read: 0,
    };
    let ShadowObservation::Read {
        entries, stopped, ..
    } = shadow
    else {
        return compared;
    };
    compared.entries_read = u32::try_from(entries.len()).unwrap_or(u32::MAX);
    compared.status = if entries.is_empty() && *stopped == Some(ShadowReadStop::Unreadable) {
        ShadowStatus::Unreadable
    } else {
        ShadowStatus::Compared
    };
    let mut cursor = 0;
    let mut unmatched = Vec::new();
    for i in 1..count {
        if reached[i] == ReachedBy::BeyondWalk || exempt_from_shadow(call_sites[i]) {
            continue;
        }
        match entries[cursor..]
            .iter()
            .position(|&entry| entry == frames[i].address)
        {
            Some(offset) => {
                compared.matches[i] = ShadowMatch::Matched;
                compared.slots[i] = u32::try_from(cursor + offset).ok();
                compared.hidden[i] = u32::try_from(offset).unwrap_or(u32::MAX);
                cursor += offset + 1;
                // Everything unmatched before this frame is now known to be absent: the shadow
                // stack went on past where it would have been.
                for &earlier in &unmatched {
                    compared.matches[earlier] = ShadowMatch::Missing;
                }
                unmatched.clear();
            }
            None => unmatched.push(i),
        }
    }
    if stopped.is_none() {
        for &late in &unmatched {
            compared.matches[late] = ShadowMatch::Missing;
        }
    }
    compared
}

/// The listing a person reads, built from the same values a program does.
pub fn render(lineage: &StackLineage) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let verdict = match lineage.verdict {
        LineageVerdict::Consistent => "CONSISTENT",
        LineageVerdict::Suspicious => "SUSPICIOUS",
        LineageVerdict::Unknown => "UNKNOWN",
    };
    let _ = writeln!(out, "LINEAGE: {verdict}");
    if lineage.frames.is_empty() {
        out.push_str(
            "\nNo frames: the engine walked no stack from the current context, so there is nothing \
             to judge.\n",
        );
        return out;
    }
    let mut listing = String::new();
    for row in &lineage.frames {
        let reached = match row.reached_by {
            ReachedBy::Context => "context",
            ReachedBy::UnwindData => "unwind",
            ReachedBy::LeafRule => "leaf",
            ReachedBy::Inferred => "inferred",
            ReachedBy::BeyondWalk => "beyond",
        };
        let call = match row.call_site {
            CallSite::NotAReturnAddress => "-",
            CallSite::Call => "call",
            CallSite::SystemCall => "syscall",
            CallSite::ResumedContext => "resumed",
            CallSite::NotACall => "NO CALL",
            CallSite::Unreadable => "unreadable",
            CallSite::NotDecoded => "not decoded",
        };
        let shadow = match (row.shadow, row.shadow_slot) {
            (ShadowMatch::Matched, Some(slot)) => format!("ssp[{slot}]"),
            (ShadowMatch::Matched, None) => "matched".to_string(),
            (ShadowMatch::Missing, _) => "MISSING".to_string(),
            (ShadowMatch::NotChecked, _) => "-".to_string(),
        };
        let line = format!(
            "{:02} {reached:<8} {call:<11} {shadow:<8} {}",
            row.frame.index,
            crate::triage::describe(&row.frame),
        );
        let _ = writeln!(listing, "{}", crate::structured::renderable(&line));
    }
    out.push_str("```\n");
    out.push_str(&listing);
    out.push_str("```\n");

    for finding in &lineage.findings {
        let what = match finding.kind {
            FindingKind::UnbackedCode => {
                "executes in memory no loaded module holds. A JIT compiler puts code there \
                 legitimately; injected code does too."
            }
            FindingKind::NotPrecededByCall => {
                "is a return address no call ends at, so no call returns there."
            }
            FindingKind::MissingFromShadowStack => {
                "is not on the shadow stack: the CPU recorded no call returning there."
            }
            FindingKind::HiddenCalls => {
                "was reached only by passing over shadow-stack entries: calls the CPU recorded \
                 that the walk does not show."
            }
        };
        let _ = writeln!(out, "Frame {:02} {what}", finding.frame);
    }

    let _ = writeln!(out, "\n{}", shadow_sentence(&lineage.shadow_stack));
    if let Some(lost) = lineage.walk_lost_at {
        let _ = writeln!(
            out,
            "The walk lost its footing at frame {lost:02}: the frame above it had no unwind data \
             the engine could read, and this one does not check out as a return address. It and \
             every frame under it are the walker's guess, so nothing found there is judged — a \
             dump whose image is not on this host reads exactly this way."
        );
    }
    if lineage.frames_truncated {
        let _ = writeln!(
            out,
            "The stack goes on past the frames examined; raise `frames` to judge the rest."
        );
    }
    let closing = match lineage.verdict {
        LineageVerdict::Consistent => {
            "Every return address the walk reached is on the CPU's own record of the calls this \
             thread made."
        }
        LineageVerdict::Suspicious => {
            "Each finding is about a frame the walk reached through its own registers or unwind \
             data, so it is a fact about the stack and not about the walk."
        }
        LineageVerdict::Unknown => {
            "Nothing was found, and that is not the same as the stack being clean: only the shadow \
             stack can vouch for every frame, and it was not available to compare against."
        }
    };
    let _ = writeln!(out, "{closing}");
    out
}

/// One sentence about the shadow stack, saying what was or was not compared.
fn shadow_sentence(shadow: &ShadowStack) -> String {
    let pointer = shadow.pointer.as_deref().unwrap_or("none");
    match (shadow.status, shadow.unavailable) {
        (ShadowStatus::Compared, _) => {
            let stopped = match shadow.read_stopped {
                Some(ShadowReadStop::Token) => " up to a restore token, where another stack begins",
                Some(ShadowReadStop::Unreadable) => " before the memory past them would not read",
                None => "",
            };
            format!(
                "Shadow stack at {pointer}: {} entries read{stopped}, {} passed over.",
                shadow.entries_read, shadow.skipped_entries
            )
        }
        (ShadowStatus::Unreadable, _) => format!(
            "Shadow stack at {pointer}: not compared, because its memory would not read — a dump \
             captures thread stacks and not shadow stacks."
        ),
        (ShadowStatus::Unavailable, Some(ShadowAbsence::NoRegister)) => {
            "No shadow stack: the engine has no shadow-stack register for this target's \
             architecture."
                .to_string()
        }
        (ShadowStatus::Unavailable, Some(ShadowAbsence::KernelTarget)) => {
            "No shadow stack compared: this is a kernel target, and the kernel's shadow stack is \
             not read."
                .to_string()
        }
        (ShadowStatus::Unavailable, Some(ShadowAbsence::PointerZero)) => {
            "No shadow stack: the shadow-stack pointer reads zero, which is a thread without one \
             in force or a capture that recorded none — the two read the same."
                .to_string()
        }
        (ShadowStatus::Unavailable, Some(ShadowAbsence::NotEnabled)) => format!(
            "No shadow stack compared: the pointer reads {pointer} but the thread's CET MSR does \
             not enable shadow stacks."
        ),
        (ShadowStatus::Unavailable, Some(ShadowAbsence::MsrUnreadable)) => format!(
            "No shadow stack compared: the pointer reads {pointer} but the thread's CET MSR would \
             not read."
        ),
        (ShadowStatus::Unavailable, None) => "No shadow stack compared.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x7ffc_9b72_0000;

    /// A frame in a module, with unwind data, preceded by a call — the ordinary case.
    fn frame(index: u32, address: u64, symbol: Option<&str>) -> ObservedFrame {
        ObservedFrame {
            info: FrameInfo {
                index,
                address: addr(address),
                module: Some("ntdll".into()),
                rva: Some(format!("{:#x}", address - BASE)),
                symbol: symbol.map(str::to_string),
                displacement: symbol.map(|_| "0x10".to_string()),
                attribution_failed: false,
            },
            address,
            placed: Placed::InModule,
            unwind: Unwind::Entry,
            preceding: Preceding::Call,
        }
    }

    fn chain(len: u32) -> Vec<ObservedFrame> {
        (0..len)
            .map(|i| frame(i, BASE + 0x1000 + u64::from(i) * 0x100, None))
            .collect()
    }

    fn read(entries: Vec<u64>, stopped: Option<ShadowReadStop>) -> ShadowObservation {
        ShadowObservation::Read {
            pointer: 0x54_f7af_8f00,
            msr: 1,
            entries,
            stopped,
        }
    }

    /// The shadow stack an honest walk of `frames` would have: frame `i`'s address is entry `i-1`.
    fn honest(frames: &[ObservedFrame]) -> Vec<u64> {
        frames.iter().skip(1).map(|frame| frame.address).collect()
    }

    fn zero() -> ShadowObservation {
        ShadowObservation::Unavailable {
            reason: ShadowAbsence::PointerZero,
            pointer: Some(0),
            msr: Some(0),
        }
    }

    fn judged_with(frames: Vec<ObservedFrame>, shadow: ShadowObservation) -> StackLineage {
        judge(Observed {
            frames,
            frames_truncated: false,
            shadow,
        })
    }

    fn kinds(lineage: &StackLineage) -> Vec<(u32, FindingKind)> {
        lineage
            .findings
            .iter()
            .map(|finding| (finding.frame, finding.kind))
            .collect()
    }

    #[test]
    fn a_chain_the_shadow_stack_vouches_for_is_consistent() {
        let frames = chain(6);
        let entries = honest(&frames);
        let lineage = judged_with(frames, read(entries, None));
        assert_eq!(lineage.verdict, LineageVerdict::Consistent);
        assert!(lineage.findings.is_empty());
        let slots: Vec<_> = lineage.frames.iter().map(|row| row.shadow_slot).collect();
        assert_eq!(slots, [None, Some(0), Some(1), Some(2), Some(3), Some(4)]);
        assert_eq!(lineage.shadow_stack.status, ShadowStatus::Compared);
    }

    /// The case every other rule exists to keep honest: nothing found, nothing to compare against.
    #[test]
    fn a_zero_shadow_stack_pointer_is_unknown_and_never_consistent() {
        let lineage = judged_with(chain(6), zero());
        assert_eq!(lineage.verdict, LineageVerdict::Unknown);
        assert_eq!(lineage.shadow_stack.status, ShadowStatus::Unavailable);
        assert_eq!(
            lineage.shadow_stack.unavailable,
            Some(ShadowAbsence::PointerZero)
        );
        assert_eq!(
            lineage.shadow_stack.pointer.as_deref(),
            Some("0x0000000000000000")
        );
        assert!(
            lineage
                .frames
                .iter()
                .all(|row| row.shadow == ShadowMatch::NotChecked)
        );
    }

    #[test]
    fn a_planted_return_address_is_missing_from_the_shadow_stack() {
        let mut frames = chain(5);
        // Frame 2 is a return address no call pushed: the shadow stack holds every other one.
        let planted = frames[2].address;
        let entries: Vec<u64> = honest(&frames)
            .into_iter()
            .filter(|&entry| entry != planted)
            .collect();
        frames[2].preceding = Preceding::Call; // chosen to sit after a call, as a careful one is
        let lineage = judged_with(frames, read(entries, None));
        assert_eq!(lineage.verdict, LineageVerdict::Suspicious);
        assert_eq!(kinds(&lineage), [(2, FindingKind::MissingFromShadowStack)]);
        assert_eq!(lineage.frames[3].shadow_slot, Some(1));
    }

    #[test]
    fn shadow_entries_the_walk_skipped_are_hidden_calls() {
        let frames = chain(4);
        let mut entries = honest(&frames);
        // Two calls between frame 1 and frame 2 that the walk does not show.
        entries.splice(1..1, [0x1111, 0x2222]);
        let lineage = judged_with(frames, read(entries, None));
        assert_eq!(lineage.verdict, LineageVerdict::Suspicious);
        assert_eq!(kinds(&lineage), [(2, FindingKind::HiddenCalls)]);
        assert_eq!(lineage.shadow_stack.skipped_entries, 2);
        assert_eq!(lineage.frames[2].shadow_slot, Some(3));
    }

    #[test]
    fn a_return_address_no_call_ends_at_is_a_finding_without_a_shadow_stack() {
        let mut frames = chain(4);
        frames[2].preceding = Preceding::Other;
        let lineage = judged_with(frames, zero());
        assert_eq!(lineage.verdict, LineageVerdict::Suspicious);
        assert_eq!(kinds(&lineage), [(2, FindingKind::NotPrecededByCall)]);
    }

    #[test]
    fn code_in_no_module_is_a_finding_at_frame_zero() {
        let mut frames = chain(3);
        frames[0].placed = Placed::NoModule;
        let lineage = judged_with(frames, zero());
        assert_eq!(kinds(&lineage), [(0, FindingKind::UnbackedCode)]);
    }

    #[test]
    fn a_failed_module_lookup_is_not_a_finding() {
        let mut frames = chain(3);
        frames[1].placed = Placed::Unknown;
        let lineage = judged_with(frames, zero());
        assert!(lineage.findings.is_empty(), "{:?}", kinds(&lineage));
        assert_eq!(lineage.verdict, LineageVerdict::Unknown);
    }

    /// `cppthrow-fastfail.dmp`, measured: frame 0 has no unwind entry because the image is not on
    /// this host, and the walker read a stack address off `[rsp]` as frame 1.
    #[test]
    fn a_walk_lost_under_a_frame_with_no_unwind_data_judges_nothing_beneath_it() {
        let mut frames = chain(5);
        frames[0].unwind = Unwind::NoEntry;
        for garbage in &mut frames[1..] {
            garbage.placed = Placed::NoModule;
            garbage.preceding = Preceding::Other;
        }
        let lineage = judged_with(frames, zero());
        assert_eq!(lineage.walk_lost_at, Some(1));
        assert!(lineage.findings.is_empty(), "{:?}", kinds(&lineage));
        assert_eq!(lineage.verdict, LineageVerdict::Unknown);
        assert!(
            lineage.frames[1..]
                .iter()
                .all(|row| row.reached_by == ReachedBy::BeyondWalk)
        );
    }

    /// `081226-2187-01.dmp`, measured: deep in the walk, a driver with no image and no entry.
    #[test]
    fn a_walk_lost_deep_in_the_stack_keeps_what_it_judged_above() {
        let mut frames = chain(6);
        frames[3].unwind = Unwind::NoEntry;
        frames[3].preceding = Preceding::Unreadable;
        frames[4].placed = Placed::NoModule;
        frames[4].preceding = Preceding::Unreadable;
        frames[2].preceding = Preceding::Other; // above the loss, so still a finding
        let lineage = judged_with(frames, zero());
        assert_eq!(lineage.walk_lost_at, Some(4));
        assert_eq!(kinds(&lineage), [(2, FindingKind::NotPrecededByCall)]);
        assert_eq!(lineage.frames[3].call_site, CallSite::Unreadable);
        assert_eq!(lineage.frames[3].reached_by, ReachedBy::UnwindData);
    }

    /// A syscall stub at frame 0 has no unwind entry because it is a leaf, and the frame under it
    /// is exact. That is the commonest frame 0 on a live process, so it must not end the judging.
    #[test]
    fn a_leaf_at_frame_zero_is_followed_by_the_leaf_rule_and_judging_goes_on() {
        let mut frames = chain(4);
        frames[0].unwind = Unwind::NoEntry;
        frames[3].preceding = Preceding::Other;
        let lineage = judged_with(frames, zero());
        assert_eq!(lineage.frames[1].reached_by, ReachedBy::LeafRule);
        assert_eq!(lineage.frames[2].reached_by, ReachedBy::UnwindData);
        assert_eq!(kinds(&lineage), [(3, FindingKind::NotPrecededByCall)]);
    }

    /// x86 has no unwind tables, so every frame past the first is the walker's inference — kept
    /// while it checks out, and never evidence.
    #[test]
    fn an_x86_walk_is_inferred_and_never_suspicious_past_frame_zero() {
        let mut frames = chain(4);
        for frame in &mut frames {
            frame.unwind = Unwind::NotApplicable;
        }
        let lineage = judged_with(frames, zero());
        assert!(
            lineage.frames[1..]
                .iter()
                .all(|row| row.reached_by == ReachedBy::Inferred)
        );
        assert_eq!(lineage.walk_lost_at, None);
        assert_eq!(lineage.verdict, LineageVerdict::Unknown);
    }

    /// Entries passed over to reach an inferred frame are no finding — the walker's inference is
    /// no evidence — but they are a disagreement, and a disagreement is not `consistent`.
    #[test]
    fn hidden_calls_before_an_inferred_frame_keep_the_stack_from_consistent() {
        let mut frames = chain(4);
        frames[1].unwind = Unwind::Unknown;
        let mut entries = honest(&frames);
        entries.insert(1, 0x1111);
        let lineage = judged_with(frames, read(entries, None));
        assert_eq!(lineage.frames[2].reached_by, ReachedBy::Inferred);
        assert!(lineage.findings.is_empty(), "{:?}", kinds(&lineage));
        assert_eq!(lineage.shadow_stack.skipped_entries, 1);
        assert_eq!(lineage.verdict, LineageVerdict::Unknown);
    }

    /// A frame 0 whose "no entry" could not be shown to be real gets no leaf rule: the frame under
    /// it is the walker's inference, however well it checks out.
    #[test]
    fn a_frame_zero_of_unknown_unwind_state_gets_no_leaf_rule() {
        let mut frames = chain(4);
        frames[0].unwind = Unwind::Unknown;
        frames[3].preceding = Preceding::Other;
        let lineage = judged_with(frames, zero());
        assert_eq!(lineage.frames[1].reached_by, ReachedBy::Inferred);
        assert_eq!(lineage.walk_lost_at, Some(3));
        assert!(lineage.findings.is_empty(), "{:?}", kinds(&lineage));
    }

    /// An inferred frame is still looked for on the shadow stack, which vouches for it.
    #[test]
    fn the_shadow_stack_vouches_for_an_inferred_frame() {
        let mut frames = chain(4);
        frames[1].unwind = Unwind::Unknown;
        let entries = honest(&frames);
        let lineage = judged_with(frames, read(entries, None));
        assert_eq!(lineage.frames[2].reached_by, ReachedBy::Inferred);
        assert_eq!(lineage.frames[2].shadow, ShadowMatch::Matched);
        assert_eq!(lineage.verdict, LineageVerdict::Consistent);
    }

    /// `082126-7015-01.dmp`, measured: under `nt!KiArm64ExceptionVectors` the address is the
    /// interrupted PC, and HEVD's code is not in the dump.
    #[test]
    fn the_frame_under_a_dispatcher_resumes_a_context_and_is_exempt() {
        let mut frames = chain(4);
        frames[1].info.symbol = Some("nt!KiArm64ExceptionVectors".into());
        frames[2].preceding = Preceding::Unreadable;
        let mut entries = honest(&frames);
        entries.retain(|&entry| entry != frames[2].address);
        let lineage = judged_with(frames, read(entries, None));
        assert_eq!(lineage.frames[2].call_site, CallSite::ResumedContext);
        assert_eq!(lineage.frames[2].shadow, ShadowMatch::NotChecked);
        assert_eq!(lineage.verdict, LineageVerdict::Consistent);
    }

    /// A dispatcher that calls normally is not a dispatcher for this purpose: the rule only explains
    /// bytes that failed to show a call.
    #[test]
    fn a_call_under_a_ki_routine_is_still_a_call() {
        let mut frames = chain(3);
        frames[1].info.symbol = Some("nt!KiDispatchException".into());
        let lineage = judged_with(frames, zero());
        assert_eq!(lineage.frames[2].call_site, CallSite::Call);
    }

    /// `121524-4703-01.dmp`, measured: a kernel trap under `KiArm64ExceptionVectors` at a PC in
    /// user memory. The CPU really was executing there, so the frame is a finding — the dump is of
    /// exactly that.
    #[test]
    fn a_trapped_pc_in_no_module_is_unbacked_code() {
        let mut frames = chain(3);
        frames[1].info.symbol = Some("nt!KiArm64ExceptionVectors".into());
        frames[2].placed = Placed::NoModule;
        frames[2].preceding = Preceding::Unreadable;
        let lineage = judged_with(frames, zero());
        assert_eq!(lineage.frames[2].call_site, CallSite::ResumedContext);
        assert_eq!(kinds(&lineage), [(2, FindingKind::UnbackedCode)]);
    }

    #[test]
    fn a_read_that_stopped_leaves_later_frames_unchecked_rather_than_missing() {
        let frames = chain(6);
        let mut entries = honest(&frames);
        entries.truncate(2);
        let lineage = judged_with(frames, read(entries, Some(ShadowReadStop::Unreadable)));
        let matches: Vec<_> = lineage.frames.iter().map(|row| row.shadow).collect();
        assert_eq!(
            matches,
            [
                ShadowMatch::NotChecked,
                ShadowMatch::Matched,
                ShadowMatch::Matched,
                ShadowMatch::NotChecked,
                ShadowMatch::NotChecked,
                ShadowMatch::NotChecked,
            ]
        );
        assert!(lineage.findings.is_empty());
        assert_eq!(lineage.verdict, LineageVerdict::Unknown);
    }

    /// The other half of the rule above: a frame is missing once a later one matched, whether or
    /// not the read stopped afterwards.
    #[test]
    fn a_frame_is_missing_once_a_later_frame_matched_even_if_the_read_then_stopped() {
        let frames = chain(5);
        let planted = frames[2].address;
        let mut entries = honest(&frames);
        entries.retain(|&entry| entry != planted);
        entries.truncate(2); // frame 1 and frame 3, then the read stops
        let lineage = judged_with(frames, read(entries, Some(ShadowReadStop::Unreadable)));
        assert_eq!(lineage.frames[2].shadow, ShadowMatch::Missing);
        assert_eq!(lineage.frames[4].shadow, ShadowMatch::NotChecked);
        assert_eq!(kinds(&lineage), [(2, FindingKind::MissingFromShadowStack)]);
    }

    #[test]
    fn a_pointer_whose_memory_would_not_read_is_unreadable_and_unknown() {
        let lineage = judged_with(chain(4), read(Vec::new(), Some(ShadowReadStop::Unreadable)));
        assert_eq!(lineage.shadow_stack.status, ShadowStatus::Unreadable);
        assert_eq!(lineage.verdict, LineageVerdict::Unknown);
    }

    /// Zero records is incomplete, never a vacuous pass.
    #[test]
    fn a_lone_frame_is_never_a_vacuous_consistent() {
        let lineage = judged_with(chain(1), read(vec![0x1234], None));
        assert_eq!(lineage.verdict, LineageVerdict::Unknown);
    }

    #[test]
    fn a_truncated_walk_is_never_consistent() {
        let frames = chain(4);
        let entries = honest(&frames);
        let lineage = judge(Observed {
            frames,
            frames_truncated: true,
            shadow: read(entries, None),
        });
        assert_eq!(lineage.verdict, LineageVerdict::Unknown);
    }

    #[test]
    fn a_restore_token_ends_the_shadow_stack() {
        let pointer = 0x1000;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x7ff6_0000_1234u64.to_le_bytes());
        // Slot 1 is at 0x1008, so a token there holds 0x1010 with the mode bit set.
        bytes.extend_from_slice(&0x1011u64.to_le_bytes());
        bytes.extend_from_slice(&0x7ff6_0000_5678u64.to_le_bytes());
        let (entries, stopped) = shadow_entries(&bytes, pointer);
        assert_eq!(entries, [0x7ff6_0000_1234]);
        assert_eq!(stopped, Some(ShadowReadStop::Token));
        let (entries, stopped) = shadow_entries(&bytes[..8], pointer);
        assert_eq!(entries.len(), 1);
        assert_eq!(stopped, None);
    }

    /// The encodings measured on the checked-in samples, and the ones they stand for.
    #[test]
    fn the_bytes_before_a_return_address_say_whether_a_call_ends_there() {
        let pad = |tail: &[u8]| {
            let mut bytes = vec![0xcc; MAX_CALL_BYTES - tail.len()];
            bytes.extend_from_slice(tail);
            bytes
        };
        let x64 = InstructionSet::Amd64;
        // `nt!PopIrpWatchdogBugcheck+0x1f5`'s `e8 rel32`, from `052126-34312-01.dmp`.
        assert_eq!(
            preceding(&pad(&[0x20, 0xe8, 0x53, 0xdc, 0xf2, 0xff]), 0x1000, x64),
            Preceding::Call
        );
        // `call qword ptr [rip+disp32]`, the import call.
        assert_eq!(
            preceding(&pad(&[0xff, 0x15, 0x10, 0x20, 0x00, 0x00]), 0x1000, x64),
            Preceding::Call
        );
        // `notrack call rax`, CET's prefixed indirect call.
        assert_eq!(
            preceding(&pad(&[0x3e, 0xff, 0xd0]), 0x1000, x64),
            Preceding::Call
        );
        // `syscall`, which iced files under `FlowControl::Call` — the case that has to be asked
        // first — and `vmcall`, which it files there too.
        assert_eq!(
            preceding(&pad(&[0x0f, 0x05]), 0x1000, x64),
            Preceding::SystemCall
        );
        assert_eq!(
            preceding(&pad(&[0x0f, 0x01, 0xc1]), 0x1000, x64),
            Preceding::SystemCall
        );
        // `mov eax, 1` then `ret`: no call ends at the address.
        assert_eq!(
            preceding(&pad(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]), 0x1000, x64),
            Preceding::Other
        );
        // A short read with no call in it has not ruled out a longer one.
        assert_eq!(
            preceding(&[0x90, 0x90, 0xc3], 0x1000, x64),
            Preceding::Unreadable
        );
        assert_eq!(preceding(&[], 0x1000, x64), Preceding::Unreadable);

        let arm64 = InstructionSet::Arm64;
        // `0x97fffcc4` and `0x940004f9`, the `bl` words measured on `082126-7015-01.dmp`, as
        // memory holds them.
        assert_eq!(
            preceding(&0x97ff_fcc4u32.to_le_bytes(), 0x1000, arm64),
            Preceding::Call
        );
        assert_eq!(
            preceding(&0x9400_04f9u32.to_le_bytes(), 0x1000, arm64),
            Preceding::Call
        );
        // `blr x8`.
        assert_eq!(
            preceding(&0xd63f_0100u32.to_le_bytes(), 0x1000, arm64),
            Preceding::Call
        );
        // `svc #0`.
        assert_eq!(
            preceding(&0xd400_0001u32.to_le_bytes(), 0x1000, arm64),
            Preceding::SystemCall
        );
        // `ret`.
        assert_eq!(
            preceding(&0xd65f_03c0u32.to_le_bytes(), 0x1000, arm64),
            Preceding::Other
        );
        assert_eq!(
            preceding(&[0x01, 0x02], 0x1000, arm64),
            Preceding::Unreadable
        );
        assert_eq!(
            preceding(&[0xe8, 0, 0, 0, 0], 0x1000, InstructionSet::Other(0x1c4)),
            Preceding::NotDecoded
        );
    }

    #[test]
    fn the_listing_names_the_verdict_and_every_finding() {
        let mut frames = chain(3);
        frames[2].preceding = Preceding::Other;
        let text = render(&judged_with(frames, zero()));
        assert!(text.starts_with("LINEAGE: SUSPICIOUS\n"), "{text}");
        assert!(
            text.contains("Frame 02 is a return address no call ends at"),
            "{text}"
        );
        assert!(text.contains("reads zero"), "{text}");
        let text = render(&judged_with(Vec::new(), zero()));
        assert!(text.contains("No frames"), "{text}");
    }
}
