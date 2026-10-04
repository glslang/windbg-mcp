//! Who reaches one address, read off the image's own decoded control flow.
//!
//! The server could already walk a call graph **forward** — `reachable_from_dispatch` asks whether
//! a block is reachable from a known root, and [`crate::hazards`] finds the call sites of an
//! *import* by its IAT slot. Neither answers the reverse question about an **internal** address,
//! which is the one you have when a symbol is absent, a PDB is public and typeless, or the
//! interesting thing is a callback slot rather than a named routine (`FOLLOWUPS.md` item 109).
//!
//! # Decoded, never pattern-matched
//!
//! The ad-hoc Python this replaced matched `E8`/`E9` displacements over raw bytes, computing for
//! each offset whether `i + 5 + rel32` hit the target. That is cheap and **unsound**: a
//! coincidental `0xE8` inside another instruction's immediate, or inside data, matches exactly as
//! well. It was adequate as a *lead generator* because both of its hits were then verified by
//! disassembling them, and it is not adequate as a tool. Here the destination is a field on
//! [`Flow`] — the decoder's own answer — so no byte pattern and no rendered text is involved, and
//! an architecture whose branch encoding nobody here has thought about answers as well as x64.
//!
//! # What an empty answer does not mean
//!
//! Four ways a real caller is not in this list, and all four are ordinary rather than exotic:
//!
//! - **An indirect call finds nothing.** `call rax` and `call qword ptr [rbx+8]` decode to
//!   [`Flow::Call(None)`][Flow::Call] — there is no destination on the instruction to compare, and
//!   resolving one would need to know what the register held. A callback reached through a stored
//!   pointer is invisible here, which for driver work is the *common* case rather than the corner.
//! - **A pointer in data is not a reference.** A dispatch table, a `DRIVER_OBJECT`'s
//!   `MajorFunction` array, a KMDF config block: the address is *stored*, never branched to, so
//!   nothing in an executable section names it. That is a census of a field rather than a scan of
//!   code, and is deliberately not this tool — `FOLLOWUPS.md` item 109 records why shipping the
//!   second without the first repeats gate S5p's review rounds.
//! - **Only the named image is read.** A caller in another module is not found unless that module
//!   is the one scanned, because scanning every loaded image is unbounded work.
//! - **And code that did not decode says nothing**, which is what [`Found::covered`] is for.
//!
//! # Not on an image target
//!
//! **Ask this on a dump or a live target.** On a PE image opened with no debuggee the answer is
//! wrong and does not say so: measured on `securekernel.exe` (2026-10-04), the scan reports its
//! four code sections covered with **no** unreadable range and finds **nothing**, while
//! `reachable_from_dispatch` proves on the same session that `SkmiInitializePool+0x27` calls
//! `SkmiInitializePoolDescriptor`. The cause is below this module: `read_memory` on such a target
//! fails with `0x8007001E` on first use and succeeds once other calls have run, so the walk is
//! fed bytes it did not read and counts them scanned. It is not this analysis' defect and not this
//! analysis' to fix — `driver_hazards` reports 1,182 privileged instructions on the same image off
//! the same path — and it is recorded as `FOLLOWUPS.md` item 111 rather than left for a reader to
//! discover from an empty list.
//!
//! So a site here is evidence that something reaches the address; an empty list is evidence about
//! this scan, never about the target.
//!
//! # Engine-free
//!
//! Like [`crate::codewalk`] and [`crate::hazards`], the entry point takes closures rather than a
//! `DebugEngine`: one to decode a range, one to ask whether to stop.

use dbgscope::dbgeng::{Flow, Instruction};
use dbgscope::pe;

use crate::codewalk;
use crate::walk::Halt;

/// How control would reach the target from a site.
///
/// **Three, because the distinction is what tells a function from a basic block.** An address that
/// is only ever branched to is a label inside somebody else's routine; one that is `call`ed is a
/// routine of its own; one that is `jmp`ed to unconditionally is usually a tail call, and is how a
/// thunk or a hot-patched routine reaches its real body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum XrefKind {
    /// A `call`: the site expects to be returned to.
    Call,
    /// An unconditional `jmp`. A tail call, a thunk, or the far side of a hot-patch.
    Jump,
    /// A conditional branch: this site reaches the target **or** falls through.
    Branch,
}

impl XrefKind {
    /// A short label for a rendering, and the `snake_case` a typed result carries.
    pub fn name(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Jump => "jump",
            Self::Branch => "branch",
        }
    }
}

/// One site whose decoded control flow names the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xref {
    /// The address of the referencing instruction — not of the target.
    pub address: u64,
    pub kind: XrefKind,
    /// The mnemonic, for a reader who wants to know which branch it was.
    pub mnemonic: String,
    /// The section the site is in.
    ///
    /// **Carried because a reference from a discardable section is dead code at run time.** A
    /// driver's `INIT` section is freed once it has run, so a call from there says what happened
    /// during load and nothing about what the driver does to a caller's buffer afterwards — and a
    /// reader with only an address cannot tell the two apart.
    pub section: String,
}

/// What a scan found, and how much of the image it looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The address that was asked about.
    pub target: u64,
    /// The sites found, in address order, **up to [`MAX_SITES`]**. A sample rather than the list
    /// when [`Self::site_count`] is larger.
    pub sites: Vec<Xref>,
    /// How many sites the scan found, exact however many are listed above.
    pub site_count: usize,
    /// How many of each kind were found, each exact however many of that kind are listed.
    ///
    /// **Not derivable from a capped list, which is the whole reason they are here.** The list is
    /// in address order, so a target with four thousand branches and two calls lists branches and
    /// nothing else — and *is it called at all* is the question a reader came with. These three
    /// answer it whatever the cap did. They sum to [`Self::site_count`].
    pub calls: usize,
    pub jumps: usize,
    pub branches: usize,
    /// What was read, and what was not.
    pub covered: codewalk::Covered,
}

/// The most sites listed. The exact count travels beside the list, so a capped answer says how much
/// of a sample it is.
///
/// **A list is capped and a count is not**, which is [`crate::hazards`]' rule arrived at there over
/// three separate findings. Four megabytes of `jmp` to one address is inside the byte cap and would
/// be a million rows, each attributed through an engine call and serialized into the reply. Real
/// numbers are nowhere near it: the two hand-rolled censuses this tool replaces found two callers
/// and five.
pub const MAX_SITES: usize = 512;

/// Finds every site in `image` whose decoded control flow names `target`.
///
/// `decode` and `halt` are [`codewalk::walk_code`]'s, which owns the section walk and the two
/// budgets. What is here is the per-instruction reading, and it keeps no state across instructions
/// — so [`codewalk::Step::Break`] needs no handling, which is the tell that the seam is in the
/// right place.
pub fn find(
    image: &pe::Image,
    target: u64,
    decode: impl FnMut(u64, usize) -> Option<Vec<Instruction>>,
    halt: impl FnMut() -> Option<Halt>,
) -> Found {
    let mut sites = Vec::new();
    let mut site_count = 0usize;
    let mut calls = 0usize;
    let mut jumps = 0usize;
    let mut branches = 0usize;

    let covered = codewalk::walk_code(image, decode, halt, |step| {
        let codewalk::Step::At(instruction, section) = step else {
            // Nothing is carried across instructions, so a discontinuity costs this nothing.
            return;
        };
        let Some(kind) = reaches(instruction, target) else {
            return;
        };
        site_count += 1;
        match kind {
            XrefKind::Call => calls += 1,
            XrefKind::Jump => jumps += 1,
            XrefKind::Branch => branches += 1,
        }
        // Counted always, listed up to the cap: the count is the fact and the list is a sample.
        if sites.len() < MAX_SITES {
            sites.push(Xref {
                address: instruction.address,
                kind,
                mnemonic: instruction.mnemonic.clone(),
                section: section.to_string(),
            });
        }
    });

    Found {
        target,
        sites,
        site_count,
        calls,
        jumps,
        branches,
        covered,
    }
}

/// How this instruction reaches `target`, or `None` where it does not reach it.
///
/// **A field read, not a rendering matched.** The destination is on [`Flow`], which the decoder
/// filled in; `None` inside a variant is an *indirect* transfer, whose destination is a register's
/// value rather than anything on the instruction, and is therefore not a match rather than a match
/// that could not be checked. A `Fallthrough` to the next instruction is not a reference either,
/// even where that next instruction happens to be the target: every instruction has a successor,
/// so counting those would report the whole image.
///
/// [`Flow::Return`], [`Flow::Trap`], [`Flow::Unknown`] and [`Flow::Unreadable`] name no
/// destination and are exhaustive arms rather than a `_`, so a variant added upstream is a compile
/// error here instead of a silently missed reference.
fn reaches(instruction: &Instruction, target: u64) -> Option<XrefKind> {
    match instruction.flow {
        Flow::Call(Some(to)) if to == target => Some(XrefKind::Call),
        Flow::Jmp(Some(to)) if to == target => Some(XrefKind::Jump),
        Flow::Branch(Some(to)) if to == target => Some(XrefKind::Branch),
        Flow::Call(_)
        | Flow::Jmp(_)
        | Flow::Branch(_)
        | Flow::Fallthrough
        | Flow::Return
        | Flow::Trap
        | Flow::Unknown
        | Flow::Unreadable => None,
    }
}

/// The scan as values, with every address turned into a coordinate by `locate`.
///
/// A closure for the same reason [`crate::hazards`] takes one: attributing an address is an engine
/// call and this file has never seen an engine. The worker supplies one that caches per module; a
/// test supplies one that invents them.
pub fn structured_report(
    module: &str,
    base: u64,
    found: &Found,
    mut locate: impl FnMut(u64) -> crate::structured::CodeLocation,
) -> crate::structured::Xrefs {
    use crate::structured;
    structured::Xrefs {
        module: module.to_string(),
        base: structured::addr(base),
        target: locate(found.target),
        sites: found
            .sites
            .iter()
            .map(|site| structured::XrefSite {
                at: locate(site.address),
                kind: site.kind.name().to_string(),
                mnemonic: site.mnemonic.clone(),
                section: site.section.clone(),
            })
            .collect(),
        site_count: found.site_count,
        calls: found.calls,
        jumps: found.jumps,
        branches: found.branches,
        scanned: found
            .covered
            .scanned
            .iter()
            .map(codewalk::range_report)
            .collect(),
        unreadable: found
            .covered
            .unreadable
            .iter()
            .map(codewalk::range_report)
            .collect(),
        stopped: found.covered.halted.map(|halt| match halt {
            Halt::Deadline => structured::WalkHalt::Deadline,
            Halt::Interrupted => structured::WalkHalt::Interrupted,
        }),
        cap_hit: found.covered.cap_hit,
    }
}

/// The report as text, for a client that reads the text block rather than `structuredContent`.
///
/// **Says what it did not read, every time.** An empty site list is the answer this tool gives most
/// often and is the one most easily misread, so the qualification is not conditional on anybody
/// asking for it.
pub fn render(report: &crate::structured::Xrefs) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let target = &report.target;
    let _ = writeln!(
        out,
        "References to {}{} in {} (base {})",
        target.address,
        match (&target.module, &target.rva) {
            (Some(module), Some(rva)) => format!("  [{module}+{rva}]"),
            _ => String::new(),
        },
        report.module,
        report.base,
    );
    let _ = writeln!(
        out,
        "{} site(s): {} call, {} jump, {} branch",
        report.site_count, report.calls, report.jumps, report.branches,
    );
    if report.sites.len() < report.site_count {
        let _ = writeln!(
            out,
            "Listing the first {} in address order; the counts above are exact.",
            report.sites.len(),
        );
    }
    if !report.sites.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "{:<18} {:<8} {:<10} INSTRUCTION",
            "SITE", "KIND", "SECTION"
        );
        for site in &report.sites {
            let _ = writeln!(
                out,
                "{:<18} {:<8} {:<10} {}",
                match (&site.at.module, &site.at.rva) {
                    (Some(module), Some(rva)) => format!("{module}+{rva}"),
                    _ => site.at.address.clone(),
                },
                site.kind,
                site.section,
                site.mnemonic,
            );
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Scanned {} range(s){}.",
        report.scanned.len(),
        match (report.stopped, report.cap_hit) {
            (Some(crate::structured::WalkHalt::Deadline), _) => ", stopped by its deadline",
            (Some(crate::structured::WalkHalt::Interrupted), _) => ", interrupted",
            (None, true) => ", stopped by its own cap",
            (None, false) => "",
        }
    );
    if !report.unreadable.is_empty() {
        let _ = writeln!(
            out,
            "{} executable range(s) did not decode and say nothing; the first begins at {}.",
            report.unreadable.len(),
            report.unreadable[0].start,
        );
    }
    // Unconditional, and the one sentence this renderer will not make conditional. The list is
    // empty on most questions, and "nothing calls this" is what a reader takes from it unless
    // told that an indirect call and a pointer in a table are both outside what was looked at.
    let _ = writeln!(
        out,
        "Only direct, decoded transfers in this image are matched: an indirect call, an address \
         stored in a dispatch table or callback slot, and a caller in another module are each not \
         looked for, so an empty list is not evidence that nothing reaches this address."
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbgscope::dbgeng::Effect;

    const BASE: u64 = 0xffff_f800_0000_0000;
    /// The address every fixture below asks about. Inside `.text`, so a site reaching it is a
    /// reference rather than a transfer out of the image.
    const TARGET: u64 = BASE + 0x1080;

    /// One executable section and one that is not, so a test can show that only code is read.
    fn image() -> pe::Image {
        pe::Image {
            base: BASE,
            bitness: pe::Bitness::Bits64,
            machine: 0x8664,
            size_of_image: 0x4000,
            section_alignment: 0x1000,
            sections: vec![
                pe::Section {
                    name: ".text".to_string(),
                    rva: 0x1000,
                    virtual_size: 0x100,
                    characteristics: 0x6000_0020,
                },
                pe::Section {
                    name: "INIT".to_string(),
                    rva: 0x2000,
                    virtual_size: 0x100,
                    // Executable **and** discardable, which is the pair the `section` field is
                    // carried for: a reference from here is dead once the driver has loaded.
                    characteristics: 0x6200_0020,
                },
                pe::Section {
                    name: ".data".to_string(),
                    rva: 0x3000,
                    virtual_size: 0x100,
                    characteristics: 0xc000_0040,
                },
            ],
            export_directory: (0, 0),
            import_directory: (0, 0),
        }
    }

    /// One instruction. `bytes` is hex pairs, as the engine prints them, and its length is what
    /// the walk resumes on.
    fn insn(address: u64, bytes: &str, mnemonic: &str, flow: Flow) -> Instruction {
        Instruction {
            address,
            bytes: bytes.to_string(),
            text: String::new(),
            mnemonic: mnemonic.to_string(),
            operands: Vec::new(),
            flow,
            privileged: false,
            effect: Effect::Other,
            condition: None,
            writes_flags: false,
            writes: Vec::new(),
            reads: Vec::new(),
        }
    }

    fn never() -> Option<Halt> {
        None
    }

    /// Decodes `block` for the first window of `.text` and nothing anywhere else, so a test says
    /// exactly which instructions exist.
    fn only_text(block: Vec<Instruction>) -> impl FnMut(u64, usize) -> Option<Vec<Instruction>> {
        move |at, _| {
            (at == BASE + 0x1000)
                .then(|| block.clone())
                .or(Some(Vec::new()))
        }
    }

    #[test]
    fn a_call_a_jump_and_a_branch_to_the_target_are_each_found_and_told_apart() {
        let found = find(
            &image(),
            TARGET,
            only_text(vec![
                insn(
                    BASE + 0x1000,
                    "e87b000000",
                    "call",
                    Flow::Call(Some(TARGET)),
                ),
                insn(BASE + 0x1005, "eb79", "jmp", Flow::Jmp(Some(TARGET))),
                insn(BASE + 0x1007, "7477", "je", Flow::Branch(Some(TARGET))),
            ]),
            never,
        );

        assert_eq!(found.site_count, 3);
        assert_eq!((found.calls, found.jumps, found.branches), (1, 1, 1));
        assert_eq!(
            found
                .sites
                .iter()
                .map(|site| (site.address, site.kind, site.mnemonic.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (BASE + 0x1000, XrefKind::Call, "call"),
                (BASE + 0x1005, XrefKind::Jump, "jmp"),
                (BASE + 0x1007, XrefKind::Branch, "je"),
            ],
        );
    }

    /// **The headline negative, and the one a byte scanner gets wrong.** An indirect transfer
    /// carries no destination, so it is not a match rather than a match that could not be checked
    /// — and a caller reached this way is genuinely absent from the answer, which is why the tool's
    /// prose says so rather than leaving an empty list to be read as "nothing calls this".
    #[test]
    fn an_indirect_transfer_is_not_a_reference_however_the_bytes_read() {
        let found = find(
            &image(),
            TARGET,
            only_text(vec![
                // `call rax`, and the encoding deliberately contains no displacement at all.
                insn(BASE + 0x1000, "ffd0", "call", Flow::Call(None)),
                insn(BASE + 0x1002, "ffe0", "jmp", Flow::Jmp(None)),
            ]),
            never,
        );

        assert_eq!(
            found.site_count, 0,
            "an indirect transfer names no destination"
        );
        assert!(found.sites.is_empty());
    }

    /// A `jmp` whose destination is the instruction *after* the target, and a `call` one byte
    /// short of it: neither is a reference, and a scan that compared ranges rather than the
    /// decoded destination would report both.
    #[test]
    fn a_transfer_to_a_neighbouring_address_is_not_a_reference() {
        let found = find(
            &image(),
            TARGET,
            only_text(vec![
                insn(
                    BASE + 0x1000,
                    "e87a000000",
                    "call",
                    Flow::Call(Some(TARGET - 1)),
                ),
                insn(BASE + 0x1005, "eb7a", "jmp", Flow::Jmp(Some(TARGET + 1))),
            ]),
            never,
        );

        assert_eq!(found.site_count, 0);
    }

    /// **Falling into the target is not referencing it.** Every instruction has a successor, so
    /// counting a `Fallthrough` whose next address happens to be the target would report a site
    /// for the instruction immediately above every address anyone ever asked about.
    #[test]
    fn falling_through_to_the_target_is_not_a_reference() {
        let found = find(
            &image(),
            TARGET,
            only_text(vec![
                // Ends exactly at the target.
                insn(TARGET - 2, "6690", "xchg", Flow::Fallthrough),
                insn(TARGET, "c3", "ret", Flow::Return),
            ]),
            never,
        );

        assert_eq!(found.site_count, 0);
    }

    /// The section travels with the site, because a reference from a discardable section is dead
    /// code once the driver has loaded and an address alone cannot say so.
    #[test]
    fn a_site_carries_the_section_it_is_in() {
        let mut found = find(
            &image(),
            TARGET,
            |at, _| match at {
                a if a == BASE + 0x1000 => Some(vec![insn(
                    BASE + 0x1000,
                    "e87b000000",
                    "call",
                    Flow::Call(Some(TARGET)),
                )]),
                a if a == BASE + 0x2000 => Some(vec![insn(
                    BASE + 0x2000,
                    "e87b000000",
                    "call",
                    Flow::Call(Some(TARGET)),
                )]),
                _ => Some(Vec::new()),
            },
            never,
        );

        found.sites.sort_by_key(|site| site.address);
        assert_eq!(
            found
                .sites
                .iter()
                .map(|site| site.section.as_str())
                .collect::<Vec<_>>(),
            vec![".text", "INIT"],
            "both sections are executable, and which one a site is in is the answer"
        );
    }

    /// A list is capped and a count is not, and the **per-kind** counts are what survive the cap:
    /// a target reached by many branches and one call lists branches alone, and *is it called* is
    /// the question a reader arrived with.
    #[test]
    fn the_sites_are_capped_and_every_count_stays_exact() {
        // One call first, then enough branches to overrun the cap several times over. Two bytes
        // each, so they fit inside the section the fixture declares.
        let mut block = vec![insn(
            BASE + 0x1000,
            "e87b000000",
            "call",
            Flow::Call(Some(TARGET)),
        )];
        let extra = MAX_SITES + 64;
        for i in 0..extra {
            block.push(insn(
                BASE + 0x1005 + (i as u64) * 2,
                "7477",
                "je",
                Flow::Branch(Some(TARGET)),
            ));
        }

        let found = find(&image(), TARGET, only_text(block), never);

        assert_eq!(found.sites.len(), MAX_SITES, "the list is bounded");
        assert_eq!(
            found.site_count,
            extra + 1,
            "the total is exact past the cap"
        );
        assert_eq!(
            found.calls, 1,
            "the one call is counted though it is listed"
        );
        assert_eq!(found.branches, extra);
        assert_eq!(found.jumps, 0);
        assert_eq!(
            found.calls + found.jumps + found.branches,
            found.site_count,
            "the three kinds account for every site"
        );
    }

    /// A halt stops the scan and the answer says so, rather than coming back as an address
    /// nothing references.
    #[test]
    fn a_halt_stops_the_scan_and_says_so() {
        let found = find(
            &image(),
            TARGET,
            only_text(vec![insn(
                BASE + 0x1000,
                "e87b000000",
                "call",
                Flow::Call(Some(TARGET)),
            )]),
            || Some(Halt::Interrupted),
        );

        assert_eq!(found.covered.halted, Some(Halt::Interrupted));
        assert_eq!(found.site_count, 0, "it stopped before reading anything");
    }

    /// An unreadable window is reported rather than skipped in silence: without it, a dump missing
    /// one page answers with an address nothing calls and nothing says a page was missing.
    #[test]
    fn an_unreadable_window_is_reported_beside_an_empty_answer() {
        let found = find(&image(), TARGET, |_, _| None, never);

        assert_eq!(found.site_count, 0);
        assert!(
            !found.covered.unreadable.is_empty(),
            "nothing decoded, and the answer has to say which ranges those were"
        );
        assert!(
            found.covered.scanned.is_empty(),
            "a window that would not read is not a window that was scanned"
        );
    }

    /// The renderer says what was not looked at **whatever** the answer was, because the empty
    /// answer is the one most easily misread.
    #[test]
    fn the_rendering_qualifies_even_an_empty_answer() {
        let found = find(&image(), TARGET, only_text(Vec::new()), never);
        let report = structured_report("mydriver", BASE, &found, |address| {
            crate::structured::CodeLocation {
                address: crate::structured::addr(address),
                module: Some("mydriver".to_string()),
                rva: Some(crate::structured::addr(address - BASE)),
                attribution_failed: false,
            }
        });
        let text = render(&report);

        assert!(text.contains("0 site(s)"), "{text}");
        assert!(
            text.contains("indirect call") && text.contains("dispatch table"),
            "an empty answer has to carry what was not looked for: {text}"
        );
    }
}
