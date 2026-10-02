//! Which driver framework a driver was written against, recognised from facts the driver tools
//! already read.
//!
//! # Why this exists
//!
//! The driver tools that read `_DRIVER_OBJECT::MajorFunction` -- `driver_object` and
//! `driver_surface` -- expect its entries to name routines **in the driver whose object it is**, and
//! the two that are *handed* one of those entries as an address -- `ioctl_map` and
//! `reachable_from_dispatch` -- inherit the expectation from whoever read the table. (The other
//! driver tools do not come near it: `device_security` and `device_object` read a device,
//! `driver_hazards` an image, `decode_ioctl` one code.) For a WDM driver the entries are the
//! driver's. For a KMDF driver they name the *framework*, and nothing in the answer said so -- so
//! `driver_surface` reported a driver dispatching nothing of its own, `ioctl_map` started from code
//! that is not the driver's and found no control codes, and both readings were true about the table
//! and about nothing a caller had asked.
//!
//! This answers the one question that turns those into true answers: **is this a framework
//! driver**. It is deliberately not the question *where are its real callbacks*, which is
//! structure-walking against the framework's own types and a version of it
//! (`FOLLOWUPS.md` item 108 step 2).
//!
//! # The two tells, and why both
//!
//! They are available in different places and neither subsumes the other.
//!
//! * **The bind import.** A KMDF client imports `WdfVersionBind` from `WdfLdr.sys`. This is a fact
//!   about the **image**, so it answers with no driver object, no debuggee and no live kernel --
//!   which is the mode `driver_hazards` and `ioctl_map` run in.
//! * **The dispatch table's image.** Every `MajorFunction` entry read is in the framework's own
//!   image. This is a fact about the **driver object**, so it answers only where one was read --
//!   and it is the one a caller staring at 28 identical pointers actually needs.
//!
//! **The second does not follow from the first**, which is the measured reason they are two: a KMDF
//! client that asks the framework not to take its table over keeps one of its own, so a tool that
//! inferred the table's contents from the import would be wrong in the direction that matters.
//!
//! Measured on this bench (`Wdf01000.sys 1.35.26100.3323`, opened as a PE image target with its
//! public PDB) rather than recalled from the WDF headers, which is the whole of why it is written
//! out here:
//!
//! * the fill is `FxDriver::Initialize+0x200`, writing `[r9+r8]` from `r8 = 0x70` --
//!   `MajorFunction` on x64 -- with `cl` running `0` through `0x1B` inclusive, 28 entries, each
//!   `Wdf01000!FxDevice::Dispatch` or `FxDevice::DispatchWithLock` as
//!   `FxDevice::_RequiresRemLock(major, 0)` decides. **Per major function, not per device**, which
//!   is what the call in the loop body says;
//! * it is reached only by falling through `+0x1b8`'s `test cl,2` / `jne`, where `ecx` was loaded
//!   from `[rsi+0x18]` and `rsi` is the `_WDF_DRIVER_CONFIG *` this function's third argument;
//! * `dt Wdf01000!_WDF_DRIVER_CONFIG` puts `DriverInitFlags` at `+0x18` as a `Uint4B`, and the
//!   PDB's own `_WDF_DRIVER_INIT_FLAGS` gives `WdfDriverInitNoDispatchOverride = 2`.
//!
//! So that flag is the bit, read from the image that tests it rather than from a header.
//!
//! # Where a client's control codes are, which is **not** one place
//!
//! The notes below name `EvtIoDeviceControl` as the usual destination and not the required one, and
//! that correction is measured here rather than taken from the documentation link review cited.
//! `dt Wdf01000!_WDF_IO_QUEUE_CONFIG` on this bench's framework holds **eight** callback slots --
//! `EvtIoDefault` at `+0x10`, then `EvtIoRead`, `EvtIoWrite`, `EvtIoDeviceControl` at `+0x28`,
//! `EvtIoInternalDeviceControl` at `+0x30`, `EvtIoStop`, `EvtIoResume`, `EvtIoCanceledOnQueue` -- so
//! a device-control request reaches `EvtIoDefault` in a queue that configures no specific handler,
//! and an internal one reaches its own slot.
//!
//! A request can also reach the driver before any queue does. Registrations exported by this build,
//! as **names to look for** rather than a model of what each does:
//! `WdfDeviceInitSetIoInCallerContextCallback` and its class-extension twin (the framework invokes it
//! inside its own dispatch -- `FxPkgIo::DispatchStep1` and `DispatchStep2` reach
//! `GetIoInCallerContextCallback` then `FxIoInCallerContext::Invoke`),
//! `WdfDeviceInitAssignWdmIrpPreprocessCallback`, and
//! `WdfDeviceConfigureWdmIrpDispatchCallback`. What any of them *does* with a request -- complete it,
//! pend it, hand it to a queue through `WdfDeviceWdmDispatchPreprocessedIrp` or
//! `WdfDeviceWdmDispatchIrpToIoQueue`, or something else -- is the driver's choice and is step 2's
//! question (`FOLLOWUPS.md` item 108), not a claim this file makes.
//!
//! **And the answer is not even necessarily in a callback.** `_WDF_IO_QUEUE_DISPATCH_TYPE` on this
//! build is `Invalid`, `Sequential`, `Parallel`, `Manual`, `Max`: a driver whose queue is **manual**
//! takes requests out of it with `WdfIoQueueRetrieveNextRequest` whenever it likes -- a worker thread,
//! a timer -- so the control-code comparison need be in no registered callback at all. Which is why
//! the notes this file builds assert nothing about where a client's comparison is, only that this
//! build cannot say.
//!
//! **That is the deliberate end of a run of five review findings, and the shape of this section is
//! the remedy rather than its wording.** Each round corrected a claim here and the correction was the
//! next round's finding: a closed list missing the WDM hooks, a closed list missing the
//! in-caller-context callback, then that callback called *the* `METHOD_NEITHER` route -- inferred from
//! two unsafe-buffer helpers requiring caller context, which says nothing about a driver reading
//! `Type3InputBuffer` straight off the IRP in a preprocess callback, having made no WDF request --
//! then "none of these replaces the queue" written as a headline above its own qualifier, and finally
//! "compared in a callback the framework holds", which manual queues falsify outright. Every one was
//! me characterising a framework this crate does not own, from partial evidence, in prose no code here
//! depends on. So the characterisation is gone: what stays is what was *measured on this build* -- the
//! queue slots, the dispatch types, the registration names, the call path -- as names to look for, and
//! the taxonomy belongs to WDF's own documentation.
//! Naming one slot as *the* place was the overclaim the rest of this file's history is about, in the
//! one sentence that looked like architecture rather than evidence -- and it is the one that would
//! send a reader to the wrong callback.
//!
//! # Engine-free
//!
//! Like [`crate::surface`], [`crate::device`] and [`crate::hazards`], nothing here takes a
//! `DebugEngine`: one entry point takes an import table, the other a module name, and the worker
//! supplies both from what it has already read.

use dbgscope::pe;

/// A driver framework this build recognises.
///
/// One variant, and the enum is still an enum: UMDF is a different image in a different mode
/// (`WUDFx02000.dll`, user mode) and is **out of scope** rather than covered -- see
/// [`Framework::note`], which says so in the answer rather than leaving a caller to assume a
/// recognised `None` ruled it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framework {
    /// Kernel-Mode Driver Framework: the client driver binds to `Wdf01000.sys`, which owns the
    /// dispatch table and calls the driver's own code as callbacks.
    Kmdf,
}

/// The import that says a driver bound to KMDF: **this name, from this library, and both.**
///
/// Neither half is sufficient and they fail in opposite directions, which is why the first version
/// of this took one of them and was wrong.
///
/// * **The library alone** reports the framework as its own client: `Wdf01000.sys` imports
///   `WdfRegisterLibrary` and `WdfLdrDiagnosticsValueByNameAsULONG` from `WdfLdr.sys` and neither
///   bind routine -- measured on this bench, and the one image a reader of this field is most likely
///   to be pointing a tool at.
/// * **The name alone** reports an image that imports something *called* `WdfVersionBind` from any
///   library at all, which an untrusted driver can arrange and which is not the evidence
///   [`crate::structured::FrameworkTell::BindImport`] says it carries.
///
/// Both are compared case-insensitively, because the case is the image's own: every one of the 132
/// KMDF clients in `System32\drivers` on this bench spells the library `WDFLDR.SYS`, which is the
/// only spelling observed and not a constant to rely on.
const KMDF_BIND: &str = "WdfVersionBind";
/// See [`KMDF_BIND`]: the library the bind routines have to come from.
const KMDF_BIND_LIBRARY: &str = "WdfLdr.sys";

/// The class-extension form, which a client importing [`KMDF_BIND`] also imports.
///
/// Listed because it is the same statement and costs one comparison, **not** because a client
/// carrying it alone was observed: across the 445 driver images in `System32\drivers` on this
/// bench, 132 import `WdfVersionBind` and none imports `WdfVersionBindClass` without it.
const KMDF_BIND_CLASS: &str = "WdfVersionBindClass";

/// The framework's own image, as the module inventory names it.
///
/// **A name, and a name is not an identity** -- the rule this repo states for anything it keys on.
/// Nothing is keyed on it: it decides whether an answer carries a *qualification*, and the
/// qualification names the module it matched so a reader can check it. A second image called
/// `Wdf01000` would be qualified as the framework and a reader would see which module that was.
///
/// **This repo already names this image once, and the two lists are deliberately not one.**
/// `triage::PASS_THROUGH_IMAGES` holds `wdf01000` beside `wdfldr`, `verifier` and `vrfcore`, and it
/// answers a different question: *is this frame on the stack on somebody else's behalf*, for picking
/// a bug check's culprit. `wdfldr` belongs there and must not be here -- it is the loader that binds
/// a client to the framework and owns no dispatch table, so qualifying an answer about it as "the
/// framework that owns this driver's dispatch" would be false. Merging the lists would make one of
/// the two questions wrong, so they cross-reference instead.
const KMDF_IMAGE: &str = "Wdf01000";

impl Framework {
    /// The `snake_case` a structured result carries.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Kmdf => "kmdf",
        }
    }

    /// What the framework means for the answer it is attached to, **assembled from the tells that
    /// fired** rather than chosen from fixed sentences.
    ///
    /// This was two fixed sentences picked by a `Subject`, and review on
    /// [#437](https://github.com/glslang/windbg-mcp/pull/437) found the shape wrong rather than the
    /// wording: the client sentence said the framework *"installs its own dispatcher in every
    /// `MajorFunction` slot"*, which only [`crate::structured::FrameworkTell::DispatchTable`]
    /// establishes. On the import tell alone -- which is every `driver_hazards` answer, since that
    /// end never reads a driver object -- it was a claim about a table nothing had read, and in a
    /// `driver_surface` answer carrying `bind_import` *without* `dispatch_table` it contradicted the
    /// answer it sat in, that tell having been tried and failed.
    ///
    /// Assembling it from what was read is what makes the half-version unexpressible: there is no way
    /// to say anything about the table without a [`Table`] value saying it was read.
    ///
    /// **The input is [`Table`] rather than the tells, which is review round 5's correction.** The
    /// tells have two states where the answer has three, so the import-only sentence -- "nothing here
    /// read this driver's `MajorFunction` entries ... read the table" -- was being served by
    /// `driver_surface` *after* it had read the table and printed it, because the tell list for that
    /// case and for `driver_hazards`' is the same list. [`Table::NotEstablished`] is the state that
    /// had nowhere to go.
    fn note(self, table: Table) -> String {
        let Self::Kmdf = self;
        // **The base says only what *binding* establishes, which is that this driver is a client of a
        // framework that can take a dispatch table over -- never that it took this one.** Every
        // consequence of that having happened is in the clause below, because reading the table is
        // what licenses it. The base carried them for three rounds and each round found one:
        // "installs its own dispatcher in every slot", and then "calls the driver's code as callbacks
        // rather than through dispatch routines of its own -- control codes are compared in an
        // `EvtIoDeviceControl`", which contradicted the clause under it and sent a reader *away* from
        // an override client's real IOCTL handler. Keeping consequences out of the base is what ends
        // that rather than wording them more carefully.
        let mut note = "this is a KMDF driver: it binds to `Wdf01000.sys`, the framework that can \
                        take a client's dispatch table over and call its code as callbacks instead."
            .to_string();
        // **What this answer read about the table, and only that.** Each clause is a statement about
        // its own answer's evidence, so none can outrun it -- and each tells the reader where to go
        // next *within what was read*, since a reader sent nowhere and a reader sent somewhere
        // unverified were rounds 3 and 4.
        note.push_str(match table {
            Table::Frameworks(_) => {
                " Every `MajorFunction` entry read here is in the framework's image, so a dispatch \
                 entry is the framework's code rather than this driver's and holds no IOCTL compare \
                 chain. Where this driver's own control-code comparison is, this build cannot say."
            }
            Table::NotEstablished => {
                " This driver's `MajorFunction` entries **were** read and are in this answer, and \
                 they were not established as wholly the framework's -- an entry in another image, \
                 or one that could not be attributed -- so part of its dispatch may be its own. Read \
                 the table below rather than assuming either; a client passing \
                 `WdfDriverInitNoDispatchOverride` keeps a dispatch table of its own."
            }
            Table::Unread => {
                " Nothing in this answer read this driver's `MajorFunction` entries, so whether the \
                 framework took its dispatch table over is not something it says -- a client passing \
                 `WdfDriverInitNoDispatchOverride` keeps one of its own. Read the table to find out \
                 which this is."
            }
        });
        note.push_str(
            " UMDF (`WUDFx02000.dll`, user mode) is a different framework and is not recognised at \
             all.",
        );
        note
    }

    /// The framework as a **clause** inside somebody else's sentence, for a dispatch table that was
    /// read and found to be the framework's **whole**.
    ///
    /// A second spelling for the same fact, which the repo already does once
    /// (`structured::SurveySection::in_prose`) and for the same reason: a note that reads "outside
    /// its own image -- `<this>`" wants a clause, a structured field wants a standalone paragraph,
    /// and keeping both here is what stops a correction landing in one of them.
    ///
    /// **Only where the whole table was read as the framework's**, which is the condition review
    /// added: this clause claims the driver dispatches its whole table through the framework and
    /// points at a `framework` field, and on one forwarded entry alone both are wrong -- the field
    /// may not be there at all. [`Self::one_entry_clause`] is that case.
    pub(crate) fn table_clause(self) -> &'static str {
        match self {
            Self::Kmdf => {
                "the KMDF framework image `Wdf01000.sys` this driver dispatches its whole table \
                 through -- the `framework` field says what that means for this answer"
            }
        }
    }

    /// The same clause for a table where **this entry** is the framework's and the table as a whole
    /// was not read as one.
    ///
    /// The case a WDM filter forwarding one major function into a KMDF driver below it produces, and
    /// the one [`Self::table_clause`] must not be used for.
    ///
    /// **It says the table was not *read* as the framework's, not that it is not**, which is the same
    /// correction as the round that produced this clause, one level down. `dispatch_framework`
    /// refuses a table for two reasons -- an entry in another image, and an entry in **no** image it
    /// could name -- and only the first licenses "another entry is not the framework's". An
    /// unattributed entry may well be.
    pub(crate) fn one_entry_clause(self) -> &'static str {
        match self {
            Self::Kmdf => {
                "the KMDF framework image `Wdf01000.sys` -- this entry dispatches into it, while \
                 this driver's table as a whole was not read as the framework's, so nothing here \
                 says that it is"
            }
        }
    }
}

/// Whether an image is a **client** of a framework, from its import table.
///
/// **Absence is not a negative and is never reported as one.** A caller adds a qualification when
/// this answers `Some` and adds nothing when it answers `None`, so there is no "this is not a
/// framework driver" claim anywhere to be wrong: an image whose import names could not be read at
/// all -- `dbgscope`'s `ImportTable::unnamed_libraries`, a bound import table whose names live
/// only in the IAT -- answers `None` here and is reported as a driver nothing said anything about.
/// (No driver image on this bench is bound: 444 of 445 carry an import directory and every one of
/// them has a lookup table.)
pub(crate) fn client_of(imports: &[pe::Import]) -> Option<Framework> {
    imports
        .iter()
        .any(|import| {
            import.library.eq_ignore_ascii_case(KMDF_BIND_LIBRARY)
                && match &import.name {
                    pe::ImportName::Named(name) => {
                        name.eq_ignore_ascii_case(KMDF_BIND)
                            || name.eq_ignore_ascii_case(KMDF_BIND_CLASS)
                    }
                    pe::ImportName::Ordinal(_) => false,
                }
        })
        .then_some(Framework::Kmdf)
}

/// What an answer established about a driver's `MajorFunction` table.
///
/// **Three states, because the answer has three and the tells have two.** A report carrying
/// `bind_import` alone is `driver_hazards`, which read no table, *or* `driver_surface` having read
/// one and not recognised it as wholly the framework's -- and until review round 5 those two were
/// served the same sentence, so a survey that had printed the table directly below was told nothing
/// had read it and instructed to go and read it. The tells stay as they are, being evidence *for the
/// framework*; this is evidence about the **table**, which is a different axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Table {
    /// Nothing in this answer read it.
    Unread,
    /// Read, and every entry is in the framework's image, named here.
    Frameworks(String),
    /// Read, and **not** established as wholly the framework's: an entry in another image, or one
    /// this answer could not attribute. The two are not told apart, because
    /// `surface::dispatch_framework` cannot and a fourth state would be the same overclaim one
    /// level down.
    NotEstablished,
}

/// The structured answer about a **driver** that binds to a framework.
///
/// Three tools report one and the wording is the whole of what step 1 of `FOLLOWUPS.md` item 108
/// buys, so it is built here rather than at each of them: a helper the callers route through, with
/// nothing left for a caller to word differently.
///
/// **Both the note and the tells are derived from the same two inputs**, so a caller cannot hand in
/// a sentence its evidence does not support, nor a tell list the sentence disagrees with. Review
/// found both halves of that: the note was two fixed sentences picked by a subject argument, and
/// then a note built for one tool was cloned into another whose evidence differed.
pub(crate) fn client_report(
    framework: Framework,
    bind_import: bool,
    table: Table,
) -> crate::structured::DriverFramework {
    use crate::structured::FrameworkTell as Tell;
    debug_assert!(
        bind_import || matches!(table, Table::Frameworks(_)),
        "a framework is reported because something said so, and these are what can say so"
    );
    let mut tells = Vec::new();
    if bind_import {
        tells.push(Tell::BindImport);
    }
    if matches!(table, Table::Frameworks(_)) {
        tells.push(Tell::DispatchTable);
    }
    crate::structured::DriverFramework {
        note: framework.note(table.clone()),
        framework: framework.name().to_string(),
        tells,
        dispatch_image: match table {
            Table::Frameworks(image) => Some(image),
            _ => None,
        },
    }
}

/// The structured answer about **code inside the framework's own image**.
///
/// Its own constructor rather than a variant of [`client_report`], because the two subjects must
/// never be mixed and a shared one made that a list a caller could get wrong: this is about an
/// *address*, nothing here has read a driver object, and the sentence is not a clause of the
/// others. A `debug_assert` kept them apart for one round; two functions make it unexpressible.
pub(crate) fn code_report(framework: Framework) -> crate::structured::DriverFramework {
    let Framework::Kmdf = framework;
    crate::structured::DriverFramework {
        note: "this routine is in `Wdf01000.sys`, the KMDF framework, rather than in a driver that \
               binds to it -- so this answers about code every KMDF driver on the target shares, and \
               about none of them in particular. Where a client driver's own control-code comparison \
               is, this build cannot say."
            .to_string(),
        framework: framework.name().to_string(),
        tells: vec![crate::structured::FrameworkTell::FrameworkImage],
        dispatch_image: None,
    }
}

/// Whether a module **is** a framework's own image, by the name the inventory gave it.
///
/// Compared case-insensitively against the base name, with any extension taken off, because the
/// two spellings in play are the inventory's `Wdf01000` and a file name's `Wdf01000.sys` and a
/// caller holds whichever its own lookup produced.
///
/// **The extension is stripped case-insensitively too**, which the first version of this did not:
/// `strip_suffix` is exact, so `WDF01000.SYS` kept its suffix and failed the comparison that was
/// already case-insensitive. Caught by the test below, which is there because the case a module name
/// arrives in is the inventory's choice rather than ours.
pub(crate) fn image_is(module: &str) -> Option<Framework> {
    let stem = module.rsplit('\\').next().unwrap_or(module);
    // **Indexed through `get`, not `[]`.** A module name is the target's own string, so a cut four
    // bytes from the end can land inside a multi-byte character -- which slicing panics on, and a
    // panic here is a session. There is no such name in a real inventory and that is not the
    // standard this applies to one.
    let stem = match stem.len().checked_sub(4).filter(|cut| {
        stem.get(*cut..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(".sys"))
    }) {
        Some(cut) => stem.get(..cut).unwrap_or(stem),
        None => stem,
    };
    stem.eq_ignore_ascii_case(KMDF_IMAGE)
        .then_some(Framework::Kmdf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(library: &str, name: &str) -> pe::Import {
        pe::Import {
            library: library.to_string(),
            name: pe::ImportName::Named(name.to_string()),
            slot: 0x1000,
        }
    }

    /// The tell itself, in the spelling an image actually carries: `WDFLDR.SYS` uppercase, which is
    /// how every one of the 132 KMDF clients on this bench spells the library.
    #[test]
    fn a_driver_importing_the_bind_routine_is_a_kmdf_client() {
        let imports = vec![
            named("ntoskrnl.exe", "ExAllocatePool2"),
            named("WDFLDR.SYS", "WdfVersionBind"),
        ];
        assert_eq!(client_of(&imports), Some(Framework::Kmdf));
    }

    /// **The framework is not its own client**, which a library-only rule would get wrong and is
    /// the case a reader is most likely to be pointing a tool at. These are `Wdf01000.sys`'s own
    /// two imports from `WdfLdr.sys`, read off this bench's copy.
    #[test]
    fn the_framework_image_importing_from_wdfldr_is_not_a_client() {
        let imports = vec![
            named("ntoskrnl.exe", "ExAllocatePool2"),
            named("WDFLDR.SYS", "WdfRegisterLibrary"),
            named("WDFLDR.SYS", "WdfLdrDiagnosticsValueByNameAsULONG"),
        ];
        assert_eq!(client_of(&imports), None);
        // And it *is* recognised -- as the framework, by the other tell.
        assert_eq!(image_is("Wdf01000"), Some(Framework::Kmdf));
    }

    /// A WDM driver answers nothing, which the caller reports as nothing rather than as a negative.
    #[test]
    fn a_wdm_driver_matches_no_framework() {
        let imports = vec![named("ntoskrnl.exe", "IoCreateDevice")];
        assert_eq!(client_of(&imports), None);
    }

    /// **The name alone is not the tell either**, which is the other half of [`KMDF_BIND`]'s rule and
    /// the one review found missing: an untrusted image can import a routine *called* `WdfVersionBind`
    /// from anywhere, and `bind_import` says it came from the framework's loader.
    #[test]
    fn the_bind_routine_from_another_library_is_not_the_tell() {
        for library in ["evil.sys", "ntoskrnl.exe", "WdfLdrr.sys", "Wdf01000.sys"] {
            assert_eq!(
                client_of(&[named(library, "WdfVersionBind")]),
                None,
                "{library}"
            );
        }
        // And the library is still the image's own spelling, so the match is case-insensitive.
        for library in ["WDFLDR.SYS", "wdfldr.sys", "WdfLdr.sys"] {
            assert_eq!(
                client_of(&[named(library, "WdfVersionBind")]),
                Some(Framework::Kmdf),
                "{library}"
            );
        }
    }

    /// **A note says only what its answer read about the table, and the three readings are three
    /// sentences.** Two of them were one sentence until review round 5: a survey that had read the
    /// table and not recognised it was served `driver_hazards`' wording, which says nothing read it
    /// and tells the reader to go and read it -- printed directly above the table it says nobody read.
    #[test]
    fn a_note_claims_the_dispatch_table_only_as_far_as_the_answer_read_it() {
        let unread = Framework::Kmdf.note(Table::Unread);
        assert!(
            unread.contains("Nothing in this answer read")
                && unread.contains("WdfDriverInitNoDispatchOverride"),
            "says what it did not read, and the case that makes it matter: {unread}"
        );
        assert!(
            unread.contains("Read the table"),
            "and gives the reader a direction, rather than leaving them nowhere: {unread}"
        );
        assert!(
            !unread.contains("in this image"),
            "without naming a destination nothing read -- an override client may leave the kernel's              stub in the slot, or handle no IOCTL at all: {unread}"
        );

        let read_but_not = Framework::Kmdf.note(Table::NotEstablished);
        let whole = Framework::Kmdf.note(Table::Frameworks("Wdf01000".to_string()));
        assert!(
            whole.contains("Every `MajorFunction` entry read here")
                && whole.contains("holds no IOCTL compare chain"),
            "a table read as the framework's licenses the claim about the entry: {whole}"
        );
        assert!(
            whole.contains("this build cannot say"),
            "and declines to locate the driver's own comparison rather than guessing: {whole}"
        );
        // **A claim about the table's contents belongs only to the reading that read them**, which the
        // base sentence carried for three rounds -- the last of those contradicting the clause printed
        // underneath it. Asserted across the note as a whole, since that is the only form that catches
        // one moving back up into the base.
        for forbidden in ["no IOCTL compare chain", "callbacks it holds"] {
            for (reading, note) in [("an unread", &unread), ("an unrecognised", &read_but_not)] {
                assert!(
                    !note.contains(forbidden),
                    "{reading} table licenses no claim about the entries ({forbidden}): {note}"
                );
            }
        }
        // **And no reading names a callback at all**, which is where five consecutive review findings
        // landed: every attempt to say where a client's control codes *are* was wrong, the last of
        // them because a manual queue's consumer need be no registered callback. The rule now is that
        // these notes locate nothing, so the assertion is the absence of every name they used to
        // offer -- non-vacuous because each string was in one of them one commit ago.
        for named in [
            "EvtIoDeviceControl",
            "EvtIoDefault",
            "EvtIoInternalDeviceControl",
            "in-caller-context",
            "preprocess",
        ] {
            for note in [&unread, &read_but_not, &whole] {
                assert!(
                    !note.contains(named),
                    "a note locates no callback ({named}): {note}"
                );
            }
        }

        // **The state that had nowhere to go.** It has to say the entries *were* read -- the opposite
        // of the `Unread` sentence it used to borrow -- and must claim neither that the framework
        // owns them nor that nobody looked.
        assert!(
            read_but_not.contains("**were** read and are in this answer")
                && read_but_not.contains("Read the table below"),
            "says the table is here and points at it: {read_but_not}"
        );
        assert!(
            !read_but_not.contains("Nothing in this answer read"),
            "and does not borrow the sentence for a table nobody read: {read_but_not}"
        );

        // All three are distinct, which is the property the two-state version could not have.
        assert_eq!(
            [&unread, &whole, &read_but_not]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3,
            "three readings, three sentences"
        );

        // The framework's own code is a different subject with its own constructor -- it must not
        // tell a reader their *driver* is KMDF.
        let in_framework = code_report(Framework::Kmdf).note;
        assert!(
            in_framework.contains("rather than in a driver that binds to it")
                && !in_framework.contains("this is a KMDF driver"),
            "{in_framework}"
        );
    }

    /// An ordinal import cannot be the tell, and must not panic the match either.
    #[test]
    fn an_ordinal_import_is_not_the_tell() {
        let imports = vec![pe::Import {
            library: "WDFLDR.SYS".to_string(),
            name: pe::ImportName::Ordinal(3),
            slot: 0x1000,
        }];
        assert_eq!(client_of(&imports), None);
    }

    /// Both spellings a caller may hold, and nothing that merely starts the same way. `WdfLdr`
    /// is the loader, not the framework, and reporting it as the framework would put a
    /// qualification on the wrong module.
    #[test]
    fn the_framework_image_is_recognised_in_either_spelling_and_not_by_prefix() {
        for spelling in ["Wdf01000", "wdf01000", "WDF01000.SYS", "Wdf01000.sys"] {
            assert_eq!(image_is(spelling), Some(Framework::Kmdf), "{spelling}");
        }
        for other in ["WdfLdr", "Wdf01000x", "wdf", "mountmgr", "WUDFx02000"] {
            assert_eq!(image_is(other), None, "{other}");
        }
    }
}
