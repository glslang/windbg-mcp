//! Which driver framework a driver was written against, recognised from facts the driver tools
//! already read.
//!
//! # Why this exists
//!
//! Every driver tool here starts from `_DRIVER_OBJECT::MajorFunction` and expects the entries to
//! name routines **in the driver whose object it is**. For a WDM driver they do. For a KMDF driver
//! they name the *framework*, and nothing in the answer said so -- so `driver_surface` reported a
//! driver dispatching nothing of its own, `ioctl_map` started from code that is not the driver's
//! and found no control codes, and both readings were true about the table and about nothing a
//! caller had asked.
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

/// The import that says a driver bound to KMDF.
///
/// **Matched by name, not by library.** `Wdf01000.sys` itself imports from `WdfLdr.sys` --
/// `WdfRegisterLibrary` and `WdfLdrDiagnosticsValueByNameAsULONG`, measured on this bench -- so a
/// rule that read the library alone would report the framework as its own client, which is the one
/// image a reader of this field is most likely to be looking at.
const KMDF_BIND: &str = "WdfVersionBind";

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

    /// What the framework means for the answer it is attached to.
    ///
    /// **One sentence per subject, in one place.** Four tools want it, and four copies is how a
    /// correction lands in three of them. The two subjects need different sentences and are not
    /// interchangeable: one is about a driver whose table points elsewhere, the other is about
    /// being *at* the code it points to.
    pub(crate) fn note(self, subject: Subject) -> &'static str {
        match (self, subject) {
            (Self::Kmdf, Subject::Client) => {
                "this is a KMDF driver: it binds to `Wdf01000.sys`, which installs its own \
                 dispatcher in every `MajorFunction` slot and calls the driver's code as callbacks \
                 it holds. So a dispatch entry is the framework's code rather than this driver's, \
                 and holds no IOCTL compare chain -- a KMDF driver's control codes are compared in \
                 an I/O queue's `EvtIoDeviceControl`, which this build cannot resolve. UMDF \
                 (`WUDFx02000.dll`, user mode) is a different framework and is not recognised at \
                 all."
            }
            (Self::Kmdf, Subject::FrameworkCode) => {
                "this routine is in `Wdf01000.sys`, the KMDF framework, rather than in a driver \
                 that binds to it -- so this answers about code every KMDF driver on the target \
                 shares, and about none of them in particular. A KMDF driver's own control codes \
                 are compared in an I/O queue's `EvtIoDeviceControl`, which this build cannot \
                 resolve."
            }
        }
    }

    /// The framework as a **clause** inside somebody else's sentence, pointing at the field that
    /// explains it rather than explaining it again.
    ///
    /// A second spelling for the same fact, which the repo already does once
    /// (`structured::SurveySection::in_prose`) and for the same reason: a note that reads "outside
    /// its own image -- `<this>`" wants a clause, a structured field wants a standalone paragraph,
    /// and keeping both here is what stops a correction landing in one of them.
    pub(crate) fn as_clause(self) -> &'static str {
        match self {
            Self::Kmdf => {
                "the KMDF framework image `Wdf01000.sys` this driver binds to, which owns its whole \
                 dispatch table -- the `framework` field says what that means for this answer"
            }
        }
    }
}

/// What a [`Framework::note`] is about, which decides which sentence it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subject {
    /// A driver that binds to the framework. Its dispatch entries point into the framework.
    Client,
    /// Code inside the framework's own image, which is where those entries point.
    FrameworkCode,
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
        .any(|import| match &import.name {
            pe::ImportName::Named(name) => {
                name.eq_ignore_ascii_case(KMDF_BIND) || name.eq_ignore_ascii_case(KMDF_BIND_CLASS)
            }
            pe::ImportName::Ordinal(_) => false,
        })
        .then_some(Framework::Kmdf)
}

/// The structured answer the tools carry, assembled in **one** place.
///
/// Four tools report this and the wording is the whole of what step 1 of `FOLLOWUPS.md` item 108
/// buys, so it is built here rather than at each of them: a helper the callers route through, with
/// nothing left for a caller to word differently. The [`Subject`] is **derived** from the tells
/// rather than passed beside them, because the pair that must not be mixed up -- a driver that
/// dispatches into the framework, and code inside the framework -- is exactly the pair a second
/// argument lets a caller mix up.
pub(crate) fn report(
    framework: Framework,
    tells: Vec<crate::structured::FrameworkTell>,
    dispatch_image: Option<String>,
) -> crate::structured::DriverFramework {
    use crate::structured::FrameworkTell as Tell;
    debug_assert!(
        !tells.is_empty(),
        "a framework is reported because something said so, and `tells` is what said so"
    );
    let subject = match tells.contains(&Tell::FrameworkImage) {
        true => Subject::FrameworkCode,
        false => Subject::Client,
    };
    crate::structured::DriverFramework {
        framework: framework.name().to_string(),
        tells,
        dispatch_image,
        note: framework.note(subject).to_string(),
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
