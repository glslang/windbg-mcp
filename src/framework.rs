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
    /// Assembling it from the tells is what makes the half-version unexpressible: there is no way to
    /// say anything about the table without `DispatchTable` being in the list. Which is the same
    /// correction, in the same round, as the clause [`Self::table_clause`] replaced.
    pub(crate) fn note(self, tells: &[crate::structured::FrameworkTell]) -> String {
        use crate::structured::FrameworkTell as Tell;
        let Self::Kmdf = self;
        // **The two subjects are never mixed**, which the early return below would silently resolve
        // in favour of one: a report is either about an address inside the framework or about a
        // driver that binds to it, and no caller builds both. Pinned here because the sentence
        // chosen is what a caller reads, and a wrong one would read as a true statement about the
        // other subject.
        debug_assert!(
            !tells.contains(&Tell::FrameworkImage)
                || tells.iter().all(|tell| *tell == Tell::FrameworkImage),
            "being framework code and binding to the framework are different subjects: {tells:?}"
        );
        // Its own sentence and not a clause of the others: this is about an *address*, where the two
        // below are about a driver, and nothing is known here about any driver object.
        if tells.contains(&Tell::FrameworkImage) {
            return "this routine is in `Wdf01000.sys`, the KMDF framework, rather than in a driver \
                    that binds to it -- so this answers about code every KMDF driver on the target \
                    shares, and about none of them in particular. A KMDF driver's own control codes \
                    are compared in an I/O queue's `EvtIoDeviceControl`, which this build cannot \
                    resolve."
                .to_string();
        }
        let mut note = "this is a KMDF driver: it binds to `Wdf01000.sys`, which calls the driver's \
                        code as callbacks it holds rather than through dispatch routines of its own \
                        -- control codes are compared in an I/O queue's `EvtIoDeviceControl`, which \
                        this build cannot resolve."
            .to_string();
        // **What was read about the table, and only that.** Either clause is a statement about this
        // answer's own evidence, so neither can outrun it.
        note.push_str(match tells.contains(&Tell::DispatchTable) {
            true => {
                " Every `MajorFunction` entry read here is in the framework's image, so a dispatch \
                 entry is the framework's code rather than this driver's and holds no IOCTL compare \
                 chain."
            }
            false => {
                " Nothing here read this driver's `MajorFunction` entries as the framework's, so \
                 what that table holds is not a claim this answer makes -- a client passing \
                 `WdfDriverInitNoDispatchOverride` keeps a dispatch table of its own."
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

/// The structured answer the tools carry, assembled in **one** place.
///
/// Four tools report this and the wording is the whole of what step 1 of `FOLLOWUPS.md` item 108
/// buys, so it is built here rather than at each of them: a helper the callers route through, with
/// nothing left for a caller to word differently.
///
/// **The note is written from the tells, not beside them**, so a caller cannot hand in a sentence
/// its evidence does not support -- which is the defect review found when the note was two fixed
/// sentences picked by a subject argument. [`Framework::note`] says what each tell licenses.
pub(crate) fn report(
    framework: Framework,
    tells: Vec<crate::structured::FrameworkTell>,
    dispatch_image: Option<String>,
) -> crate::structured::DriverFramework {
    debug_assert!(
        !tells.is_empty(),
        "a framework is reported because something said so, and `tells` is what said so"
    );
    crate::structured::DriverFramework {
        note: framework.note(&tells),
        framework: framework.name().to_string(),
        tells,
        dispatch_image,
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

    /// **A note says only what its tells establish.** The import tell is a fact about an image and
    /// licenses nothing about a dispatch table -- which is every `driver_hazards` answer, and is a
    /// `driver_surface` answer whose dispatch tell was tried and failed, where the old fixed sentence
    /// contradicted the result it sat in.
    #[test]
    fn a_note_claims_the_dispatch_table_only_where_a_tell_read_it() {
        use crate::structured::FrameworkTell as Tell;
        let import_only = Framework::Kmdf.note(&[Tell::BindImport]);
        assert!(
            import_only.contains("not a claim this answer makes")
                && import_only.contains("WdfDriverInitNoDispatchOverride"),
            "says what it did not read, and the case that makes it matter: {import_only}"
        );
        assert!(
            !import_only.contains("Every `MajorFunction` entry"),
            "and claims nothing about the table: {import_only}"
        );

        let with_table = Framework::Kmdf.note(&[Tell::BindImport, Tell::DispatchTable]);
        assert!(
            with_table.contains("Every `MajorFunction` entry read here"),
            "the table tell licenses the table claim: {with_table}"
        );
        assert!(
            !with_table.contains("not a claim this answer makes"),
            "and the two clauses are exclusive: {with_table}"
        );

        // The framework's own code is a different subject and keeps its own sentence -- it must not
        // tell a reader their *driver* is KMDF.
        let in_framework = Framework::Kmdf.note(&[Tell::FrameworkImage]);
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
