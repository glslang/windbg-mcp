//! The bounded decode of an image's executable sections, which more than one analysis needs.
//!
//! This is the loop [`crate::hazards`] grew and fourteen rounds of review on
//! [#305](https://github.com/glslang/windbg-mcp/pull/305) and
//! [#307](https://github.com/glslang/windbg-mcp/pull/307) corrected: sections sorted and clamped
//! so no byte is decoded twice, a window boundary that resumes after the last *whole* instruction
//! rather than at a fixed stride, a span whose declared size runs past the image clamped and
//! recorded, an unreadable window recorded rather than skipped in silence, and two separate
//! budgets — one bounding the work and one bounding the answer.
//!
//! **It is here rather than in `hazards.rs` because none of that is about hazards.** The second
//! caller ([`crate::xrefs`]) needs every one of those corrections and nothing about sinks or
//! privileged instructions, and a copy of this loop beside the original would be a copy of the
//! defects it no longer has. What stays with each analysis is what it does per instruction; what
//! is shared is where the instructions come from and what the answer has to admit it did not read.
//!
//! # Engine-free
//!
//! Like [`dbgscope::pe`] and [`crate::hazards`], the entry point takes closures rather than a
//! `DebugEngine`: one to decode a range, one to ask whether to stop. The worker supplies the two
//! that touch DbgEng; the tests supply fixtures.

use dbgscope::dbgeng::Instruction;
use dbgscope::pe;

use crate::walk::Halt;

/// One executable range a walk covered, so a caller can see what it did *not*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    pub section: String,
    pub start: u64,
    /// Bytes decoded. Less than the section's size means the walk stopped inside it — the byte cap
    /// or a halt — and the report says which.
    pub bytes: u64,
}

/// How much of the image a walk actually read, and why it stopped if it did.
///
/// **Every analysis built on this walk carries these four**, because they are the difference
/// between "the driver does not do that" and "this did not look there". Left out, a dump missing
/// one page reports a clean driver and nothing anywhere says a page was missing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Covered {
    /// The contiguous runs that decoded, one entry per run rather than one per section: a section
    /// with a hole in it cannot be described by a single range whose `start` is the section's.
    pub scanned: Vec<Scanned>,
    /// Executable ranges that were **not** decoded, and therefore say nothing: bytes that would
    /// not read, a window that decoded to no instruction, and any part of a section whose declared
    /// span ran past the image.
    ///
    /// Separate from [`Self::halted`] and [`Self::cap_hit`] because it is a different fact with a
    /// different remedy — the walk ran to the end and part of the code was simply not there.
    pub unreadable: Vec<Scanned>,
    /// Why the walk stopped early, when it did.
    pub halted: Option<Halt>,
    /// True when a cap stopped it rather than the code running out.
    pub cap_hit: bool,
}

/// What the walk hands a visitor, in address order.
#[derive(Debug)]
pub enum Step<'a> {
    /// One decoded instruction, and the section it is in.
    At(&'a Instruction, &'a str),
    /// **Control is not continuous across this point.** A section began, or a window that would
    /// not read or decoded to nothing was stepped over. A visitor carrying state across adjacent
    /// instructions — a register's watched value, a partial sequence — has to drop it here: what
    /// is on the far side of an unreadable page is not the next instruction of anything.
    ///
    /// A visitor that keeps no such state ignores this, which is the tell that the seam is in the
    /// right place: [`crate::xrefs`] does, and [`crate::hazards`] does not.
    Break,
}

/// The most code one walk will decode, in bytes.
///
/// A driver's executable sections are tens to hundreds of kilobytes; this is well past that and is
/// there to bound the absurd — a caller pointing an analysis at `nt`, whose `.text` is megabytes.
/// It is a **cap that reports itself** rather than a refusal, because a partial walk of a huge
/// image still answers for what it read, and [`Covered::cap_hit`] says the rest was not looked at.
pub const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;

/// The most range rows one answer carries, across both lists.
///
/// Both lists are bounded by the byte cap and the section count already; this keeps a pathological
/// section table from turning that into thousands of rows.
pub const MAX_RANGES: usize = 256;

/// How much is decoded between two halt polls.
///
/// The decode is one call per window, so this is also the largest read a walk makes at once. Small
/// enough that a cancelled walk stops promptly, large enough that a 100 KB section is a handful of
/// calls rather than hundreds.
const WINDOW: u64 = 64 * 1024;

/// Decodes an image's executable sections in address order, handing each instruction to `visit`.
///
/// `decode` takes an address and a length and answers the instructions in it, or `None` where the
/// bytes could not be read — which is a fact about the image rather than an error, and leaves that
/// window out of [`Covered::scanned`]. `halt` is polled between windows.
///
/// **There is no early-out for a visitor whose answer has filled up, deliberately.** Both callers
/// report a capped list beside an *exact* count, and a count is only exact if the walk saw every
/// instruction — so stopping when the list fills would turn the one number that is a fact into a
/// second sample of itself. What bounds the work is the byte cap, which is a different budget.
///
/// **Windows overlap by nothing and that is deliberate.** A window boundary can fall inside an
/// instruction, so the last instruction of a window may be decoded from a truncated tail and the
/// next window would start mid-instruction. Both are handled by decoding from the *instruction
/// after* the last complete one rather than from a fixed offset, which is what `next` below
/// carries.
pub fn walk_code(
    image: &pe::Image,
    mut decode: impl FnMut(u64, usize) -> Option<Vec<Instruction>>,
    mut halt: impl FnMut() -> Option<Halt>,
    mut visit: impl FnMut(Step<'_>),
) -> Covered {
    let mut covered = Covered::default();
    let mut budget = MAX_SCAN_BYTES;

    // **Sorted, and each range clamped past the last**, so every byte is decoded at most once. A
    // malformed header can declare two executable sections covering the same addresses, and
    // walking both counts every finding in the overlap twice — which would make counts documented
    // as exact quietly inflated. Clamping rather than refusing, because the bytes are real and
    // reading them once is the right answer; what is dropped is the second visit, not the code.
    let mut code: Vec<&pe::Section> = image.code_sections().collect();
    code.sort_by_key(|section| section.rva);
    let mut past = 0u64;

    'sections: for section in code {
        // **The row cap is checked here as well as inside the decode loop**, because the two
        // paths below that record a malformed span never reach that loop: a section beginning
        // outside the image `continue`s, so a cap enforced only in the loop bounded every image
        // except the one it was written for (review on
        // [#446](https://github.com/glslang/windbg-mcp/pull/446)).
        //
        // **It bounds this walk rather than closing a hole**, and the difference is worth stating
        // because the finding claimed the second. `dbgscope::pe::read_image` refuses an image
        // declaring more than 96 sections outright — `PeError::Malformed`, not a truncation — so
        // no image it hands over can produce more than 96 rows here, and 96 is under this cap.
        // What this check buys is that [`MAX_RANGES`] is a property of *this* function, true for
        // any caller and any fixture, rather than one that has to be re-derived from a bound in
        // another crate that nothing at this seam mentions.
        if covered.scanned.len() + covered.unreadable.len() >= MAX_RANGES {
            covered.cap_hit = true;
            break 'sections;
        }
        // **The whole span, not just its start.** `checked_va(rva, 0)` asks only whether the
        // section begins inside the image, and a header claiming a `virtual_size` that runs past
        // `SizeOfImage` would then have this decode straight out of the module and into whatever
        // is mapped next — on a live target, the next driver — reporting its instructions as this
        // one's. A span that does not fit is **clamped to the image and recorded as a gap**,
        // rather than skipped: what is genuinely inside is still worth reading, and what was cut
        // has to be visible for the same reason every other shortfall here does.
        let Ok(start) = image.checked_va(section.rva, 0) else {
            // A section that begins **outside** the image is recorded, not skipped. Skipped, its
            // whole declared range vanished from both lists and the report read as a complete
            // clean walk of an image whose headers do not hold together. There is no address to
            // record it at -- that is the point of it -- so it is reported at the image's end,
            // which is the last address this walk can speak for.
            covered.unreadable.push(Scanned {
                section: section.name.clone(),
                start: image.base.saturating_add(u64::from(image.size_of_image)),
                bytes: u64::from(section.virtual_size),
            });
            continue;
        };
        let declared = u64::from(section.virtual_size);
        let end = match image.checked_va(section.rva, section.virtual_size as usize) {
            Ok(_) => start.saturating_add(declared),
            Err(_) => {
                let inside = u64::from(image.size_of_image.saturating_sub(section.rva));
                covered.unreadable.push(Scanned {
                    section: section.name.clone(),
                    start: start.saturating_add(inside),
                    bytes: declared.saturating_sub(inside),
                });
                start.saturating_add(inside)
            }
        };

        // The overlap with everything already walked is skipped rather than decoded again.
        let mut at = start.max(past);
        past = past.max(end);
        // One entry per **contiguous** decoded run rather than one per section. A section with a
        // hole in it used to come back as a single range starting where the section starts and
        // counting only the bytes that read — a shape that cannot say where the hole was, and
        // whose `start` is wrong for everything after it.
        let mut run: Option<(u64, u64)> = None;
        // A section's first instruction follows nothing: whatever a visitor was carrying belongs
        // to the previous section's code and must not cross into this one.
        visit(Step::Break);
        let close = |run: &mut Option<(u64, u64)>, scanned: &mut Vec<Scanned>| {
            if let Some((from, bytes)) = run.take()
                && bytes > 0
            {
                scanned.push(Scanned {
                    section: section.name.clone(),
                    start: from,
                    bytes,
                });
            }
        };
        while at < end {
            if let Some(why) = halt() {
                covered.halted = Some(why);
                close(&mut run, &mut covered.scanned);
                break 'sections;
            }
            if budget == 0 {
                covered.cap_hit = true;
                close(&mut run, &mut covered.scanned);
                break 'sections;
            }
            // The two range lists are bounded like everything else an answer carries. A section
            // table that is plausible produces a handful of entries; one that is not can produce a
            // row per window per section, and a bounded answer is still an answer where thousands
            // of rows is a reply nobody reads.
            if covered.scanned.len() + covered.unreadable.len() >= MAX_RANGES {
                covered.cap_hit = true;
                close(&mut run, &mut covered.scanned);
                break 'sections;
            }
            let want = WINDOW.min(end - at).min(budget);
            let Some(block) = decode(at, want as usize) else {
                // A window that would not read is skipped rather than ending the walk — a driver
                // whose `.text` is partly absent still answers for the rest of it — but it is
                // **recorded**. Left silent, a dump missing one page reports a driver with no
                // findings, and nothing anywhere says a page was missing.
                //
                // Nothing a visitor held survives the gap.
                visit(Step::Break);
                close(&mut run, &mut covered.scanned);
                covered.unreadable.push(Scanned {
                    section: section.name.clone(),
                    start: at,
                    bytes: want,
                });
                at = at.saturating_add(want);
                budget = budget.saturating_sub(want);
                continue;
            };
            // **An empty answer is not an answer**, and neither is one that advances nothing.
            // The decoder can succeed and return nothing — bytes that are there and decode to no
            // instruction — and a zero-length instruction would loop for ever, so both end the
            // section. What each has to do first is say what it is leaving: without that, a window
            // that decoded to nothing ends a section silently and the rest of it is missing from
            // both lists, which is the same silence an unreadable window used to keep.
            if block.is_empty() {
                visit(Step::Break);
                close(&mut run, &mut covered.scanned);
                covered.unreadable.push(Scanned {
                    section: section.name.clone(),
                    start: at,
                    bytes: end.saturating_sub(at),
                });
                break;
            }
            for instruction in &block {
                visit(Step::At(instruction, &section.name));
            }
            // Resume after the last instruction that decoded whole, not at a fixed stride: a
            // window's tail is usually a partial instruction, and restarting at `at + want` would
            // decode the next window from the middle of one.
            let last = block.last().expect("the block is not empty");
            let next = last.address.saturating_add(instruction_len(last));
            let consumed = next.saturating_sub(at);
            if consumed == 0 {
                close(&mut run, &mut covered.scanned);
                covered.unreadable.push(Scanned {
                    section: section.name.clone(),
                    start: at,
                    bytes: end.saturating_sub(at),
                });
                break;
            }
            let taken = consumed.min(want);
            match &mut run {
                Some((_, bytes)) => *bytes += taken,
                None => run = Some((at, taken)),
            }
            budget = budget.saturating_sub(taken);
            at = next;
        }
        close(&mut run, &mut covered.scanned);
    }

    covered
}

/// The encoded length of an instruction, from the bytes the decoder reported.
///
/// **The engine prints the encoding as hex pairs, so the length is half the digits.** Reading
/// `bytes.len()` directly doubles every instruction, which does not fail — it skips the rest of
/// each window and reports the bytes it skipped as scanned. Zero for an instruction that carried
/// none, which is what ends a section rather than looping on it.
fn instruction_len(instruction: &Instruction) -> u64 {
    (instruction.bytes.len() / 2) as u64
}

/// One covered range as the wire type, shared by every analysis built on this walk.
pub fn range_report(range: &Scanned) -> crate::structured::ScannedRange {
    crate::structured::ScannedRange {
        section: range.section.clone(),
        start: crate::structured::addr(range.start),
        bytes: range.bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbgscope::dbgeng::{Effect, Flow};

    const BASE: u64 = 0xffff_f800_0000_0000;

    /// An image whose `count` executable sections all begin **outside** `SizeOfImage`, which is
    /// the one shape that records a range and never reaches the decode loop.
    fn sections_outside_the_image(count: usize) -> pe::Image {
        pe::Image {
            base: BASE,
            bitness: pe::Bitness::Bits64,
            machine: 0x8664,
            size_of_image: 0x1000,
            section_alignment: 0x1000,
            sections: (0..count)
                .map(|i| pe::Section {
                    name: format!(".text{i}"),
                    // Past `size_of_image`, so `checked_va` refuses the start.
                    rva: 0x2000 + (i as u32) * 0x1000,
                    virtual_size: 0x100,
                    characteristics: 0x6000_0020,
                })
                .collect(),
            export_directory: (0, 0),
            import_directory: (0, 0),
        }
    }

    /// **[`MAX_RANGES`] is this function's bound, not its caller's.**
    ///
    /// The row cap used to be checked only inside the decode loop, and a section beginning outside
    /// the image records a range and `continue`s without entering it — so an image made of nothing
    /// but those was unbounded here. It was not *reachable*: `dbgscope::pe::read_image` refuses an
    /// image declaring more than 96 sections, so the real worst case was 96 rows against a cap of
    /// 256. This asserts the property anyway, with a fixture that bypasses that parser exactly as
    /// any other caller could.
    #[test]
    fn the_range_rows_are_bounded_even_when_no_section_decodes() {
        let covered = walk_code(
            &sections_outside_the_image(MAX_RANGES * 2),
            |_, _| panic!("no section begins inside the image, so nothing should be decoded"),
            || None,
            |_| {},
        );

        assert_eq!(
            covered.scanned.len() + covered.unreadable.len(),
            MAX_RANGES,
            "the two range lists share one bound"
        );
        assert!(covered.cap_hit, "a bounded answer says it was bounded");
        assert!(
            covered.halted.is_none(),
            "a cap is not a halt, and the two have different remedies"
        );
    }

    /// And the ordinary case is unaffected: a sane section table produces a row per contiguous
    /// run, nowhere near the cap.
    #[test]
    fn a_plausible_section_table_is_not_capped() {
        let image = pe::Image {
            base: BASE,
            bitness: pe::Bitness::Bits64,
            machine: 0x8664,
            size_of_image: 0x4000,
            section_alignment: 0x1000,
            sections: vec![pe::Section {
                name: ".text".to_string(),
                rva: 0x1000,
                virtual_size: 0x20,
                characteristics: 0x6000_0020,
            }],
            export_directory: (0, 0),
            import_directory: (0, 0),
        };
        let mut seen = 0usize;
        let covered = walk_code(
            &image,
            |at, _| {
                Some(vec![Instruction {
                    address: at,
                    // Four hex pairs: a four-byte instruction, so eight of them cover the section.
                    bytes: "d503237f".to_string(),
                    text: String::new(),
                    mnemonic: "nop".to_string(),
                    operands: Vec::new(),
                    flow: Flow::Fallthrough,
                    privileged: false,
                    privilege: None,
                    effect: Effect::Other,
                    condition: None,
                    writes_flags: false,
                    writes: Vec::new(),
                    reads: Vec::new(),
                }])
            },
            || None,
            |step| {
                if matches!(step, Step::At(..)) {
                    seen += 1;
                }
            },
        );

        assert!(!covered.cap_hit, "{covered:?}");
        assert!(covered.unreadable.is_empty(), "{covered:?}");
        assert_eq!(covered.scanned.len(), 1, "one contiguous run: {covered:?}");
        assert_eq!(covered.scanned[0].bytes, 0x20, "{covered:?}");
        assert_eq!(seen, 8, "0x20 bytes of four-byte instructions");
    }
}
