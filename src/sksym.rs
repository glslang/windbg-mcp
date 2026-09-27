//! Symbols for a Secure Kernel image, resolved with **no process to debug**.
//!
//! `FOLLOWUPS.md` item 103 gate **S2**. Gate S1 ([`crate::sk`]) finds `securekernel.exe` in a
//! guest's VTL1 and says where its base is; this names what is at an address in it, and says where
//! a name is. It is the one place in H5b that DbgEng earns its keep — the reads are already
//! [`crate::sk`]'s, and routing those through an engine that could not read the guest anyway would
//! buy nothing.
//!
//! # This is the third process in this crate that loads DbgEng, and why that is allowed
//!
//! `AGENTS.md`'s rule is *keep DbgEng access inside the worker process and on its engine thread*,
//! and **the supervisor must never touch a `DebugEngine`**. Raised against this module by review on
//! [#399](https://github.com/glslang/windbg-mcp/pull/399) as a P1, asking for image resolution to be
//! routed through a worker. The fact is right — an engine here is a new thing — and the remedy is
//! declined, because the rule's *purpose* is met by construction and its letter is about a role this
//! is not:
//!
//! - **It is not the supervisor.** [`crate::skinspect`] speaks no MCP, holds no session registry, has
//!   no clients and routes nothing, and `main` returns into it *before* a tokio runtime is built.
//!   There is no server for a wedged engine to take down and no other session to protect — which is
//!   what the worker boundary exists to buy.
//! - **One target per process, which is the rule's actual constraint.** dbgeng.dll holds one debuggee
//!   session per process; this opens exactly one, and the thing it opens is a **file**. There is no
//!   live process behind it, nothing to resume, detach or kill, and no second opener in this role.
//! - **One thread.** This process spawns none — not [`crate::sk`], [`crate::savedstate`],
//!   [`crate::skinspect`] or this module — so every engine call is on the thread that made it, which
//!   is the other half of the rule.
//!
//! **What the remedy would cost is the thing S3 is deferred to decide.** There is no worker to route
//! to here: a worker is spawned by `crate::engine::Sessions`, which lives in the supervisor. Routing
//! would mean building a session registry and a `crate::proto` channel inside a command-line report
//! writer — and it would pre-decide, for a research CLI, where the *tool surface*'s engine lives,
//! which item 103's S3 lists as one of its three open questions. So the decision is recorded as a
//! test instead of as prose:
//! [`tests::only_the_worker_and_this_module_build_an_engine`] fails if a third file constructs one,
//! which is where a future `DebugEngine` in the supervisor stops rather than in a review round.
//!
//! # The unknown this gate was written to settle, and the answer
//!
//! The plan recorded it as an open question: `dbgscope`'s symbol methods all assume a session with
//! a target, so *image-only* resolution — load `securekernel.exe` at a base with nothing running and
//! resolve against it — was "not obviously available", and if it needed an engine call it would be
//! a new typed `dbgscope` method rather than an `execute` of text.
//!
//! **It needs no new primitive.** DbgEng opens a PE image as a target in its own right:
//! `OpenDumpFileWide` on `C:\Windows\System32\securekernel.exe` produces a session with exactly one
//! module, at the image's own `ImageBase`, and `.reload /f` against it downloads and loads
//! `securekernel.pdb` from the public symbol server. Measured on this bench 2026-09-27 against
//! 10.0.26100.9457: one module `securekernel` at `0x140000000`, `symbols: pdb`, PDB key
//! `C2C0D1A62E3269F40C69EA44FDB230C41`, and `KdDebuggerDataBlock` and `SkLoadedModuleList`
//! resolving at RVA `0x1335E0` and `0x127770` — **the same two offsets gate S0's tag scan and gate
//! S1's decode found in the capture**, derived from a file rather than from a search.
//!
//! So everything here is [`dbgscope::dbgeng`] methods that already existed, and the whole of this
//! module's own work is the **rebase**: a symbol resolves at the image's preferred base and the
//! guest loaded it somewhere else.
//!
//! # Why the rebase is arithmetic here rather than a second module in the engine
//!
//! DbgEng will load the image a second time at an arbitrary base —
//! `.reload /i securekernel.exe=fffff8070eda9000,175000`, with `.exepath` set so the file is
//! findable — and it resolves the same PDB there, giving correct addresses at the guest's base.
//! **That route is a trap, and it was measured being one.** The engine cannot reuse the module name
//! it already has, so the second module comes up as `securekernel_exe`, and *both* answer to the
//! `securekernel!` qualifier: with the pair loaded, `? securekernel!KdDebuggerDataBlock` answers
//! `0x1401335E0` — the **preferred** base — and only `securekernel_exe!` reaches the guest one. A
//! name-based lookup would therefore silently return an address in the wrong space, which is the
//! defect this whole gate exists to avoid one level down. One module at its own base plus
//! [`Rebase`] has no such ambiguity, and the arithmetic is testable with no engine at all.
//!
//! # What this gate does **not** deliver, measured rather than assumed
//!
//! The plan asked for symbols *and types*. **The public `securekernel.pdb` carries no type
//! information.** `dt securekernel!_LIST_ENTRY` is *not found*, `dt securekernel!*` lists symbols
//! rather than types, and every data symbol prints `= <no type information>` under `x /t`. So
//! structure walks over VTL1 stay hand-decoded the way [`crate::sk`] already does them, and this
//! module reports what a small [`TYPE_PROBES`] set answered rather than claiming either way.
//!
//! **And what the engine says when asked is more specific than "absent", which only showed once the
//! answer stopped being a `bool`:** every one of the four comes back `E_NOINTERFACE`
//! (`0x80004002`), *no such interface supported* — the engine declining to service type queries for
//! this module at all, rather than four names it looked for and did not find. That is a better
//! corroboration of the claim than a sample of four could be, and it was what the collapsed boolean
//! was hiding.
//!
//! **And `SymbolKind::has_type_info` must not be used to decide it.** That helper reads
//! `DEBUG_SYMTYPE_PDB` as "exposes private type information", and this image is `symbols: pdb`
//! with no types at all — the engine does not distinguish a stripped public PDB from a private
//! one. Asking for a type and seeing what comes back is the only answer.
//!
//! # Every engine answer this module turns into a value, and what each does with a failure
//!
//! **An engine call that failed is not a negative answer**, and three review rounds on #399 each
//! found one place that treated it as one — `module_pdb`'s `.ok().flatten()`, `type_id`'s
//! `is_ok_and`, and `module_symbol_file`'s `unwrap_or_default`. Two were reported and the third came
//! out of counting, so the list is here rather than the discipline:
//!
//! | call | a failure becomes |
//! |---|---|
//! | `DebugEngine::new` (panics) | [`SymbolFailure::EngineUnavailable`] |
//! | `set_symbol_path`, `open_dump`, `modules`, `module`, `module_symbol_file` | [`SymbolFailure::Engine`], naming the step |
//! | `wait_for_event` | [`SymbolFailure::LoadWait`], or [`SymbolFailure::LoadIncomplete`] for a wait that ended without a stop |
//! | `module_pdb` | [`SymbolFailure::PdbUnvouched`] with [`Unvouched::NotAsked`] — never "no signature" |
//! | `reload_symbols` | kept as [`Symbols::reload_error`] and reported; it is not fatal because the probe below may still load symbols |
//! | `symbol_offset` for [`FORCE_LOAD_PROBE`] | discarded **deliberately**: the call is made for its side effect and no answer is wanted |
//! | `type_id` | the engine's own message, per probe ([`Symbols::type_probes`]) — never `false` |
//! | `symbol_offset` for a caller's name | [`ResolveFailure::Unknown`], carrying the engine's message; the name says *did not resolve* rather than *does not exist*, because the two are one failed call to DbgEng |
//! | `symbol_for` | `None`, which is `dbgscope`'s own contract: an address with no name is the ordinary case and is not a failure |
//!
//! Two of those are answers rather than omissions and are the ones to check against before adding a
//! tenth row: the discarded probe, and `symbol_for`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use dbgscope::dbgeng::{DebugEngine, PdbIdentity, SymbolKind, WaitOutcome};

use crate::sk::{DiskImage, Gva};

/// How long the engine is given to finish opening the image target.
///
/// Generous for what it covers — an image file is opened from local disk and there is no debuggee
/// to arrive — and deliberately not the budget for the *symbol* load, which happens afterwards in
/// [`Symbols::open`] and is unbounded because a cold symbol server is minutes and refusing it would
/// be refusing the gate.
///
/// The same sixty seconds `crate::worker` gives a dump load, and independently so: the two are
/// separate roles with separate budgets, and nothing here needs them to agree.
const LOAD_WAIT_MS: u32 = 60_000;

/// A symbol name no image has, asked for once to make the engine load symbols.
///
/// The *answer* is discarded — what the call is for is the side effect, since a deferred module
/// resolves on first use and a lookup that finds nothing is a first use like any other. Deliberately
/// not a plausible name: one that happened to exist would still force the load, but it would make
/// this read like a query whose result mattered.
const FORCE_LOAD_PROBE: &str = "__windbg_mcp_force_symbol_load__";

/// Type names asked for, to report whether this PDB answers with a type at all.
///
/// **A finite list cannot prove a PDB carries no types**, and this one is not offered as proof: it
/// is four names a Secure Kernel PDB with type records would be expected to carry, so that all four
/// coming back empty is evidence rather than an assumption. The inference limit is stated where the
/// result is printed, not hidden behind a boolean.
pub(crate) const TYPE_PROBES: [&str; 4] = [
    "_LIST_ENTRY",
    "_KLDR_DATA_TABLE_ENTRY",
    "_KDDEBUGGER_DATA64",
    "_UNICODE_STRING",
];

/// Why an image's symbols could not be opened at all.
///
/// Each variant is a *different* thing to do about it, which is why none of them is a string: an
/// engine that would not start is a host missing `dbgeng.dll`, a PDB that did not load is a symbol
/// path or a build with none served, and an identity mismatch is the operator having handed a
/// different image than the capture holds.
#[derive(Debug)]
pub(crate) enum SymbolFailure {
    /// `DebugEngine::new` panicked — on this bench that means `dbgeng.dll` was not discoverable.
    EngineUnavailable,
    /// An engine call failed, naming **which** one.
    ///
    /// One variant with a step rather than one per call, and the step is the whole point. This was
    /// `Open(String)` whose message said *the engine refused the image as a target*, which was true
    /// of one of its four uses: review on #399 caught it for `--sympath`, where the sentence sends an
    /// operator to look at their image for a symbol-path problem and `open_dump` has not run yet.
    /// Enumerating rather than fixing that one found the same wrong sentence on the module listing and
    /// on the re-read. A symbol failure is non-fatal here, so this text is the operator's only
    /// account of why a report has no symbols in it.
    Engine { step: &'static str, detail: String },
    /// The load wait itself failed.
    LoadWait(String),
    /// The wait returned without the target having stopped, so nothing is loaded.
    LoadIncomplete(WaitOutcome),
    /// The engine did not answer with exactly one module. An image target has one; anything else
    /// means this is not the session this module thinks it is, and guessing which module to
    /// qualify symbols with is how the wrong image gets read.
    NotOneModule(usize),
    /// The engine and [`DiskImage`] read one file and disagree about what is in it.
    ///
    /// **Not the operator having named the wrong image** — that is gate S1's `matches_disk`, which
    /// compares the *capture's* mapping against the same file. This closes the other half of the
    /// chain: the mapping was identified against this file, so these symbols are the mapping's only
    /// if the engine opened this file too. Reachable when the file changes under the run, or when
    /// the two PE readers disagree, and refused rather than reported because symbols from a
    /// neighbouring build name real routines at wrong offsets.
    Identity {
        engine: (u32, u32),
        disk: (u32, u32),
    },
    /// The module has no symbol **provider** after a resolving query has been made — `Deferred` and
    /// `Export` included, since after that query neither means "nobody has looked yet".
    ///
    /// `reload` carries the `.reload /f` error where there was one, because "no PDB was served for
    /// this build" and "the symbol path is unreachable" look identical from the [`SymbolKind`] alone.
    NoSymbols {
        kind: SymbolKind,
        reload: Option<String>,
        /// Whatever the engine named as this module's symbol file — the image's own name, usually.
        /// Carried so a failure can still say what it read; see [`SymbolFailure::file_read`].
        symbol_file: String,
    },
    /// Symbols loaded and nothing vouched for the PDB they came from.
    ///
    /// **One refusal for one rule, either way round.** A *mismatch* — the engine having matched a PDB
    /// it then found does not belong to this image — was its own refusal from the start, because it is
    /// the one failure where symbols did load and reading them is worse than having none. Review on
    /// #399 found the other half: asking the engine *which* PDB it has could fail, and
    /// `.ok().flatten()` turned that into "there is no signature" — so *could not ask* was reported as
    /// a fact, and the mismatch check was skipped with nothing saying so. That is exactly the
    /// conflation [`crate::sk::ReadFailure`] exists to prevent one level down, committed one level up.
    ///
    /// Both are *this PDB is not vouched for*, so they are one variant rather than two cases a later
    /// round can find a third of.
    PdbUnvouched {
        why: Unvouched,
        /// The PDB's path. **A file this run read**, and the reason this field exists: without it the
        /// only route to the path was the success arm, so a run refused here left a PDB a `--json`
        /// could be pointed at once the engine let go of it. Review on #399.
        symbol_file: String,
    },
}

/// Why a loaded PDB could not be vouched for.
///
/// **Three arms, and they are the whole set**: an identity that says the wrong thing, one the engine
/// would not give, and one it does not have. Every way the check can fail to happen is one of those,
/// which is the answer to four review rounds each finding another — stated here so a fifth has
/// somewhere to land rather than something to add.
#[derive(Debug)]
pub(crate) enum Unvouched {
    /// The engine reports the PDB it matched does not belong to this image.
    Mismatch { guid: String, age: u32 },
    /// The engine could not be asked which PDB it loaded. **Not "there is none"**: the module reads
    /// as having a symbol provider, so there is one — what is missing is the answer that would let it
    /// be checked.
    NotAsked(String),
    /// The engine answered, and has no signature for a module it reports as PDB-backed. Carries the
    /// kind, because that is the half that makes it a contradiction rather than an ordinary absence —
    /// `CodeView` and `Sym` have no signature and are accepted.
    NoIdentity(SymbolKind),
}

impl SymbolFailure {
    /// A file this failure **read**, where it read one.
    ///
    /// The single place that question is answered, so a new variant that reads a file has one
    /// function to come to rather than a caller to remember. `Identity` and the image-opening step
    /// read the image, which is already an input by the time this is asked, so they answer `None`
    /// rather than repeating it.
    pub(crate) fn file_read(&self) -> Option<&str> {
        let file = match self {
            SymbolFailure::NoSymbols { symbol_file, .. }
            | SymbolFailure::PdbUnvouched { symbol_file, .. } => symbol_file.as_str(),
            _ => return None,
        };
        (!file.is_empty()).then_some(file)
    }
}

impl std::fmt::Display for SymbolFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SymbolFailure::EngineUnavailable => write!(
                f,
                "DbgEng could not be initialised (is dbgeng.dll on the search path?)"
            ),
            SymbolFailure::Engine { step, detail } => write!(f, "{step}: {detail}"),
            SymbolFailure::LoadWait(why) => write!(f, "waiting for the image to load: {why}"),
            SymbolFailure::LoadIncomplete(outcome) => write!(
                f,
                "the image never finished loading (the wait ended {outcome:?})"
            ),
            SymbolFailure::NotOneModule(count) => write!(
                f,
                "an image target carries one module and the engine reported {count}"
            ),
            SymbolFailure::Identity { engine, disk } => write!(
                f,
                "the engine opened an image with timestamp {:#010X} and SizeOfImage {:#X}, and the \
                 decode identified against timestamp {:#010X} and SizeOfImage {:#X}",
                engine.0, engine.1, disk.0, disk.1
            ),
            SymbolFailure::NoSymbols { kind, reload, .. } => match reload {
                Some(why) => write!(
                    f,
                    "no symbols loaded (the module still reads {kind:?} after a resolving query): \
                     {why}"
                ),
                None => write!(
                    f,
                    "no symbols loaded (the module still reads {kind:?} after a resolving query); \
                     check the symbol path and that a PDB is served for this build"
                ),
            },
            SymbolFailure::PdbUnvouched { why, .. } => match why {
                Unvouched::Mismatch { guid, age } => write!(
                    f,
                    "the engine loaded {guid}{age:X}, which it reports does not match this image — \
                     its names would be another build's"
                ),
                Unvouched::NotAsked(detail) => write!(
                    f,
                    "the engine would not say which PDB it loaded, so nothing checked that the \
                     symbols belong to this image: {detail}"
                ),
                Unvouched::NoIdentity(kind) => write!(
                    f,
                    "the engine reports the module's symbols as {kind:?} and has no PDB signature \
                     for them, so nothing could check that they belong to this image"
                ),
            },
        }
    }
}

/// One image, opened as a target, with symbols loaded and nothing else in the session.
pub(crate) struct Symbols {
    /// Held for the life of the resolver: dropping it ends the session.
    engine: DebugEngine,
    /// The name symbols are qualified by, as the engine named it — never derived from the file
    /// name, because the engine is what decides and it mangles on collision.
    qualifier: String,
    preferred_base: u64,
    size_of_image: u32,
    kind: SymbolKind,
    /// The PDB the engine actually selected, which is the provenance a figure taken from these
    /// symbols has to travel with.
    pdb: Option<PdbIdentity>,
    symbol_file: String,
    /// What `.reload /f` said, when it failed and the module still came back with a kind worth
    /// keeping. Reported rather than absorbed: it is the only thing that tells a reader why a kind
    /// they can see is not the one they expected.
    reload_error: Option<String>,
}

impl Symbols {
    /// Open `image` as a target and load its symbols, or say why not.
    ///
    /// `disk` is gate S1's own reading of the same file, and the two are compared: the symbols are
    /// the capture's only because the mapping was identified against *this* image, so an engine
    /// that read something else out of it breaks the chain and has to be a refusal rather than a
    /// footnote.
    pub(crate) fn open(
        image: &Path,
        disk: &DiskImage,
        symbol_path: Option<&str>,
    ) -> Result<Symbols, SymbolFailure> {
        // `DebugEngine::new` panics rather than erroring when the engine cannot be created, the
        // same way `crate::worker` has to handle it.
        let engine = catch_unwind(AssertUnwindSafe(DebugEngine::new))
            .map_err(|_| SymbolFailure::EngineUnavailable)?;
        if let Some(path) = symbol_path {
            // A path the caller gave replaces the engine's default rather than appending to it: an
            // operator naming a store means that store, and silently keeping `srv*` beside it is
            // how a run downloads from the internet when it was told not to.
            engine
                .set_symbol_path(path)
                .map_err(|e| SymbolFailure::Engine {
                    step: "configuring the symbol path given with --sympath",
                    detail: e.to_string(),
                })?;
        }
        engine
            .open_dump(&image.display().to_string())
            .map_err(|e| SymbolFailure::Engine {
                step: "opening the image as a target",
                detail: e.to_string(),
            })?;
        match engine.wait_for_event(LOAD_WAIT_MS) {
            Ok(WaitOutcome::Stopped { .. }) => {}
            Ok(other) => return Err(SymbolFailure::LoadIncomplete(other)),
            Err(e) => return Err(SymbolFailure::LoadWait(e.to_string())),
        }
        let modules = engine.modules().map_err(|e| SymbolFailure::Engine {
            step: "listing the target's modules",
            detail: e.to_string(),
        })?;
        let [module] = modules.as_slice() else {
            return Err(SymbolFailure::NotOneModule(modules.len()));
        };
        // Before the symbol load, so a mismatched image is refused without spending a download on
        // it — and so the refusal names the image rather than the symbols.
        if module.timestamp != disk.identity.timestamp || module.size != disk.identity.size_of_image
        {
            return Err(SymbolFailure::Identity {
                engine: (module.timestamp, module.size),
                disk: (disk.identity.timestamp, disk.identity.size_of_image),
            });
        }
        // Forced rather than left deferred, so the kind read below is a fact rather than "nobody has
        // looked yet" — and so a host with no `symsrv.dll` shows up on the first line of the report
        // instead of as whichever symbol happened to be asked for first appearing to be absent.
        let reload = engine
            .reload_symbols(&format!("/f {}", module.image_name))
            .err()
            .map(|e| e.to_string());
        // **And then make the engine look, whatever the reload said.** A *resolving query* is what
        // settles a deferred module, and one that finds nothing settles it just as well: measured
        // 2026-09-27, a module reading `symbols: deferred` straight after the open moved to
        // `symbols: pdb` with its PDB key on a single failing lookup
        // (`? securekernel!ThisSymbolDoesNotExistAnywhere`, itself `0x80040205`).
        //
        // Which is load-bearing rather than tidy, and review found it: narrowing the refusal below
        // to `None` — round 1 of #399 — left `Deferred` free to load its PDB on the first *landmark*
        // query, which is after the only `unmatched` check has run. `unmatched` is the one failure
        // where symbols did load and reading them is worse than having none, so bypassing it would
        // print another build's names as this build's. And the same window made the reported
        // provenance a lie in the ordinary case: `kind Deferred` and "no PDB signature" printed
        // above landmarks that a PDB had just resolved. Forcing the look **collapses** that state
        // instead of reporting it, which needs no second read and no field saying which one is
        // current.
        //
        // **And the probe is not riding on the reload**, which is the half worth measuring rather
        // than assuming: with `reload_symbols` not issued at all, the gated test below still reports
        // `symbols Pdb` with the PDB key and resolves both landmarks. So either alone suffices on
        // this bench and the pair is what covers a host where one of them does not — the reload
        // staying because it is the half that yields a *named* error for [`Symbols::reload_error`].
        let _ = engine.symbol_offset(&format!("{}!{FORCE_LOAD_PROBE}", module.name));
        // Re-read: the kind before the reload and the probe is `deferred`, which says nothing.
        let module = engine
            .module(&module.name)
            .map_err(|e| SymbolFailure::Engine {
                step: "re-reading the module after its symbols were made to load",
                detail: e.to_string(),
            })?;
        // Read **before** any refusal, so a failure that read a PDB can still name it: gate S1's
        // `Inputs` learns what a run read from wherever it is first known, and a path known only on
        // the success path is a path a `--json` can be pointed at. `unmatched` is the case review
        // named ([`SymbolFailure::file_read`]); enumerating rather than fixing the one arm found
        // `NoSymbols` in the same position.
        // **Not `unwrap_or_default()`**, which is what this was, and the enumeration that followed
        // review's `type_id` finding is what found it: an error became `""`, which reads as *the
        // engine named no symbol file* — and an empty path silently disables the `--json` protection
        // built on it, so the guard would have been off for the one reason nothing reported.
        let symbol_file =
            engine
                .module_symbol_file(module.base)
                .map_err(|e| SymbolFailure::Engine {
                    step: "reading the symbol file the engine selected for the module",
                    detail: e.to_string(),
                })?;
        // **A symbol provider is required, and the probe above is what makes that honest.** Round 1
        // of #399's review narrowed this to [`SymbolKind::None`] alone, reasoning that dbgscope
        // documents `Deferred` as *not* a statement that symbols are missing — a deferred module
        // usually resolves on first use — so refusing it would turn away a host where names would
        // have resolved.
        //
        // **That argument died the moment the probe was added, and rounds 2 and 3 of the same review
        // are what it cost.** The probe *is* a first use, so a module still `Deferred` after one is
        // not "nobody has looked": it is the engine having looked and not resolved them. Accepting it
        // left the PDB free to load on the first *landmark* query — after the `unmatched` check
        // below, which is the one failure where symbols did load and reading them is worse than
        // having none — and left the reported provenance able to say `Deferred` and "no PDB
        // signature" above addresses a PDB had just resolved. Round 2 answered that with the probe;
        // round 3 pointed out the probe can *fail* to settle it, and the same hole is back.
        //
        // So the generating choice goes rather than the symptom: after a resolving query the kind is
        // a fact, a refusal here is justified by measurement instead of by a guess, and **nothing
        // downstream can move it** — which is what lets the provenance below be read once and kept.
        //
        // Both halves are measured rather than reasoned. A symbol path reaching no store
        // (`--sympath C:\nonexistent-symbol-store`) leaves this module reading **`Export`**, not
        // `Deferred` — the engine falls back to the image's export table — so that is the value this
        // refusal actually fires on. And `Export` costs the gate nothing: with symbols failing to
        // load, `x securekernel!KdDebuggerDataBlock` and `x securekernel!SkLoadedModuleList` both
        // answer **nothing** against roughly 280 exported names, neither landmark being exported. The
        // residual assumption is stated rather than hidden: a provider does not change without
        // another `.reload`, and this issues none after this point.
        if !matches!(
            module.symbols,
            SymbolKind::Pdb | SymbolKind::Dia | SymbolKind::CodeView | SymbolKind::Sym
        ) {
            return Err(SymbolFailure::NoSymbols {
                kind: module.symbols,
                reload,
                symbol_file,
            });
        }
        // Kept rather than dropped once the refusal above has not fired: a forced load that errored
        // while the probe succeeded is exactly the case the reader needs told.
        let reload_error = reload;
        // **Not `.ok().flatten()`**, which is what this was: it made *the engine could not be asked*
        // indistinguishable from *the module has no PDB signature*, and the mismatch check below is
        // skipped in both cases — so an unanswered query published provenance nothing had validated.
        let pdb = match engine.module_pdb(module.base) {
            Ok(pdb) => pdb,
            Err(e) => {
                return Err(SymbolFailure::PdbUnvouched {
                    why: Unvouched::NotAsked(e.to_string()),
                    symbol_file,
                });
            }
        };
        // **A PDB-backed provider must have an identity, and this is the arm that closes the set.**
        // Four review rounds on #399 landed on this one seam, each on another way the identity could
        // fail to vouch for the symbols, so it is worth saying what the set *is* rather than adding a
        // fourth later: the engine says the wrong thing ([`Unvouched::Mismatch`]), will not say
        // ([`Unvouched::NotAsked`]), or says nothing (here). Those are every way a check can fail to
        // happen, which is why this is a **requirement on the kind** rather than another enumerated
        // failure — any future shape of "no identity" lands in this arm without a new one.
        //
        // `CodeView` and `Sym` keep `None`, because those providers genuinely have no PDB signature to
        // report and refusing them would be refusing what they are. Unmeasured, like the other
        // refusals: this bench has only produced `Pdb` with an identity, which is what the gated test
        // asserts.
        if matches!(module.symbols, SymbolKind::Pdb | SymbolKind::Dia) && pdb.is_none() {
            return Err(SymbolFailure::PdbUnvouched {
                why: Unvouched::NoIdentity(module.symbols),
                symbol_file,
            });
        }
        if let Some(identity) = &pdb
            && identity.unmatched
        {
            return Err(SymbolFailure::PdbUnvouched {
                why: Unvouched::Mismatch {
                    guid: identity.guid.clone(),
                    age: identity.age,
                },
                symbol_file,
            });
        }
        Ok(Symbols {
            engine,
            qualifier: module.name.clone(),
            preferred_base: module.base,
            size_of_image: module.size,
            kind: module.symbols,
            pdb,
            symbol_file,
            reload_error,
        })
    }

    pub(crate) fn qualifier(&self) -> &str {
        &self.qualifier
    }

    /// What the forced symbol load said, where it failed and the kind was still worth keeping.
    pub(crate) fn reload_error(&self) -> Option<&str> {
        self.reload_error.as_deref()
    }

    pub(crate) fn preferred_base(&self) -> u64 {
        self.preferred_base
    }

    pub(crate) fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    pub(crate) fn kind(&self) -> SymbolKind {
        self.kind
    }

    pub(crate) fn pdb(&self) -> Option<&PdbIdentity> {
        self.pdb.as_ref()
    }

    pub(crate) fn symbol_file(&self) -> &str {
        &self.symbol_file
    }

    /// Ask the engine for each of [`TYPE_PROBES`]: the type id it answered, or **what it said
    /// instead**.
    ///
    /// Reported as the list rather than as a verdict, because four names answering nothing is
    /// evidence that this PDB carries no types and is not a proof of it.
    ///
    /// **`Result` rather than `bool`, which is the third round of one class.** `is_ok_and` collapsed
    /// every failure into *absent*, so a DIA that could not service the query produced the same four
    /// negatives as a stripped PDB — and those four negatives are what this gate offers as evidence
    /// for its headline finding. DbgEng signals *no such type* as a failed call too, so the two
    /// cannot be told apart from the `Result` alone; what this does is stop **claiming** the
    /// distinction and hand the engine's own reason to the reader, who can see whether it says the
    /// type was not found or something operational. Review on #399 raised it for this call after
    /// raising it for `module_pdb`, which is why the module docs now enumerate every site.
    pub(crate) fn type_probes(&self) -> Vec<(&'static str, Result<u32, String>)> {
        TYPE_PROBES
            .iter()
            .map(|name| {
                let answer = self
                    .engine
                    .type_id(self.preferred_base, name)
                    .map_err(|e| e.to_string());
                (*name, answer)
            })
            .collect()
    }

    /// A resolver for this image as the guest loaded it, at `guest_base`.
    pub(crate) fn at(&self, guest_base: Gva) -> Result<Resolver<'_>, RebaseRefused> {
        Ok(Resolver {
            symbols: self,
            rebase: Rebase::new(self.preferred_base, guest_base.0, self.size_of_image)?,
        })
    }
}

/// Why a base cannot be rebased onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RebaseRefused {
    /// `SizeOfImage` is zero, so the image covers nothing and every address is outside it.
    EmptyImage,
    /// One of the two ranges runs off the top of the address space. Refused rather than wrapped:
    /// a `SizeOfImage` is read out of a guest and a wrapped range would make an address at the top
    /// of memory look like one near the bottom.
    RangeOverflows { base: u64, size: u32 },
}

/// Two bases for one image: where the engine has it, and where the guest loaded it.
///
/// A value rather than a pair of arguments, so a translation cannot be done with the base
/// forgotten — which on an upper-half kernel address produces a plausible-looking number rather
/// than an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rebase {
    preferred_base: u64,
    guest_base: u64,
    size_of_image: u32,
}

/// An address that is not in the image, and which end it fell off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutsideImage {
    /// Below the base it would be measured from.
    Below { address: u64, base: u64 },
    /// At or past the last byte. `SizeOfImage` bytes starting at the base is the whole of it, so
    /// `base + size` is already outside — the half-open end is the boundary that has to be right.
    Past { address: u64, base: u64, size: u32 },
}

impl Rebase {
    pub(crate) fn new(
        preferred_base: u64,
        guest_base: u64,
        size_of_image: u32,
    ) -> Result<Rebase, RebaseRefused> {
        if size_of_image == 0 {
            return Err(RebaseRefused::EmptyImage);
        }
        for base in [preferred_base, guest_base] {
            if base.checked_add(u64::from(size_of_image)).is_none() {
                return Err(RebaseRefused::RangeOverflows {
                    base,
                    size: size_of_image,
                });
            }
        }
        Ok(Rebase {
            preferred_base,
            guest_base,
            size_of_image,
        })
    }

    /// `address`'s offset into an image based at `base`, or which end it fell off.
    fn rva_from(self, address: u64, base: u64) -> Result<u32, OutsideImage> {
        let offset = address
            .checked_sub(base)
            .ok_or(OutsideImage::Below { address, base })?;
        if offset >= u64::from(self.size_of_image) {
            return Err(OutsideImage::Past {
                address,
                base,
                size: self.size_of_image,
            });
        }
        // The bound above is what makes this fit: an offset below a `u32` size is a `u32`.
        Ok(offset as u32)
    }

    /// Where an engine address is, in all three coordinates at once.
    ///
    /// **The one place an engine address becomes a guest one.** Two call sites each doing the
    /// subtraction is two chances to do it against the wrong base, and the wrong base here does not
    /// fail — it answers with an address in the other space that looks exactly like an answer.
    pub(crate) fn place(self, engine: u64) -> Result<Resolved, OutsideImage> {
        let rva = self.rva_from(engine, self.preferred_base)?;
        Ok(Resolved {
            rva,
            guest: Gva(self.guest_base + u64::from(rva)),
            engine,
        })
    }

    /// A guest address as the engine's.
    pub(crate) fn to_engine(self, guest: Gva) -> Result<u64, OutsideImage> {
        let rva = self.rva_from(guest.0, self.guest_base)?;
        Ok(self.preferred_base + u64::from(rva))
    }

    /// A guest address's offset into the image.
    pub(crate) fn rva_in_guest(self, guest: Gva) -> Result<u32, OutsideImage> {
        self.rva_from(guest.0, self.guest_base)
    }
}

/// Where a symbol is, in all three coordinates a reader needs.
///
/// The RVA is carried beside the two addresses rather than left to be recomputed: it is the one of
/// the three that survives a reboot and joins a disassembler, and a figure recounted downstream
/// measures the recount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub(crate) rva: u32,
    pub(crate) guest: Gva,
    pub(crate) engine: u64,
}

/// What an address resolved to, and how far past it the address is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Named {
    /// As the engine spells it, qualifier included. Kept whole: the qualifier is the engine's own
    /// and a caller comparing bare names has to say so.
    pub(crate) symbol: String,
    /// Bytes past the symbol. **Zero is the only value that says the address *is* the symbol** —
    /// the engine answers with the nearest preceding name at any address in the module, so a
    /// non-zero displacement on a landmark lookup is a miss dressed as a hit.
    pub(crate) displacement: u64,
}

/// Why a name did not resolve to an address in the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolveFailure {
    /// The engine has no such symbol.
    Unknown { name: String, detail: String },
    /// The engine answered with an address that is not in this module. Its own failure because the
    /// answer is not wrong so much as not about this image — an absolute symbol, or a name that
    /// matched in something else — and treating it as an offset would invent an RVA.
    Outside { name: String, why: OutsideImage },
}

impl std::fmt::Display for ResolveFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveFailure::Unknown { name, detail } => {
                write!(f, "{name} did not resolve: {detail}")
            }
            ResolveFailure::Outside { name, why } => {
                write!(f, "{name} resolved outside the image: {why:?}")
            }
        }
    }
}

/// One image's symbols, read in the guest's coordinates.
pub(crate) struct Resolver<'a> {
    symbols: &'a Symbols,
    rebase: Rebase,
}

impl Resolver<'_> {
    pub(crate) fn rebase(&self) -> Rebase {
        self.rebase
    }

    /// Where `name` is. Unqualified — the module the engine named is applied here, so a caller
    /// cannot accidentally qualify it with a name this session does not have.
    pub(crate) fn resolve(&self, name: &str) -> Result<Resolved, ResolveFailure> {
        let qualified = format!("{}!{}", self.symbols.qualifier, name);
        let engine =
            self.symbols
                .engine
                .symbol_offset(&qualified)
                .map_err(|e| ResolveFailure::Unknown {
                    name: qualified.clone(),
                    detail: e.to_string(),
                })?;
        self.rebase
            .place(engine)
            .map_err(|why| ResolveFailure::Outside {
                name: qualified,
                why,
            })
    }

    /// What is at a guest address, or `None` where the engine has no name for it.
    ///
    /// `Err` is the address not being in the image at all, which is a different answer from the
    /// image having no name there — and the one a caller has to fix rather than report.
    pub(crate) fn describe(&self, at: Gva) -> Result<Option<Named>, OutsideImage> {
        let engine = self.rebase.to_engine(at)?;
        Ok(self
            .symbols
            .engine
            .symbol_for(engine)
            .map(|(symbol, displacement)| Named {
                symbol,
                displacement,
            }))
    }
}

/// One address the PDB and gate S1's decode both have an answer for.
///
/// Built rather than checked inline so the comparison is one place and the report cannot disagree
/// with it — the same reason [`crate::skinspect`]'s oracle has a single classifier.
#[derive(Debug)]
pub(crate) struct Agreement {
    /// The symbol, unqualified, as it was asked for.
    pub(crate) name: &'static str,
    /// What the PDB says, or why it could not say.
    pub(crate) from_symbols: Result<Resolved, ResolveFailure>,
    /// What the decode found in the guest, and its offset into the identified image.
    pub(crate) from_decode: Gva,
    pub(crate) decode_rva: Result<u32, OutsideImage>,
    /// What the engine answers for the decode's own address, which is the same question asked in
    /// the other direction and can fail differently.
    pub(crate) named_by_decode: Result<Option<Named>, OutsideImage>,
}

impl Agreement {
    /// Whether the two routes name the same address.
    ///
    /// `None` when the PDB had nothing to say, which is **not** a disagreement: unknown is not
    /// wrong, and reporting a missing symbol as a mismatch would make a host with no symbol server
    /// look like a decode that is broken.
    pub(crate) fn agrees(&self) -> Option<bool> {
        let resolved = self.from_symbols.as_ref().ok()?;
        Some(resolved.guest == self.from_decode)
    }
}

/// Ask both routes for one landmark.
pub(crate) fn compare(resolver: &Resolver<'_>, name: &'static str, from_decode: Gva) -> Agreement {
    Agreement {
        name,
        from_symbols: resolver.resolve(name),
        from_decode,
        decode_rva: resolver.rebase().rva_in_guest(from_decode),
        named_by_decode: resolver.describe(from_decode),
    }
}

#[cfg(test)]
mod tests {
    //! The rebase, with no engine.
    //!
    //! Everything here is the arithmetic, which is this module's own work — the resolution itself
    //! is `dbgscope`'s and is exercised by the gated test at the bottom, which needs an engine, a
    //! symbol server and a real `securekernel.exe`. Plus one that is about neither, and reads the
    //! crate's own source: where an engine may be built.

    use super::*;

    /// **Exactly two files in this crate may construct a `DebugEngine`**, and this is the ratchet.
    ///
    /// `AGENTS.md` says the supervisor must never touch one, and until this module there was nothing
    /// to state that against but prose — which is how the P1 on
    /// [#399](https://github.com/glslang/windbg-mcp/pull/399) came to be a review finding rather than
    /// a failing test. The rule is a **construction** rule and not a mention rule: half the worker's
    /// analysis modules take a `&DebugEngine` quite properly, and it is *building* one that decides
    /// which process owns a debuggee session.
    ///
    /// A third entry is a design change and has to argue for itself — the argument this module's own
    /// entry rests on is in its module docs, and none of it (no MCP, no registry, one file-backed
    /// target, one thread) is true of `engine.rs`, `server.rs`, `listen.rs` or `service.rs`.
    ///
    /// Comment lines are stripped before matching, so naming `DebugEngine::new` in prose elsewhere
    /// does not trip it; a block comment would, and this crate writes none.
    ///
    /// **What it covers**, stated as the inclusion rather than as a boast: a literal construction, a
    /// `use … DebugEngine as …` rename, and a `type … = … DebugEngine` rename. A call generated inside
    /// a macro body is not covered, and neither is a rename split across lines.
    #[test]
    fn only_the_worker_and_this_module_build_an_engine() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut builders: Vec<String> = Vec::new();
        let mut walked = 0usize;
        let mut pending = vec![src.clone()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("src/ is readable") {
                let path = entry.expect("a readable directory entry").path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                walked += 1;
                let text = std::fs::read_to_string(&path).expect("a readable Rust file");
                let builds = text.lines().any(|line| {
                    let line = line.trim_start();
                    if line.starts_with("//") {
                        return false;
                    }
                    // The construction itself, however the path to the type is spelled...
                    line.contains("DebugEngine::new")
                        // ...and either way of **renaming** the type, which is how `E::new()` would
                        // walk past the line above. Raised by review on #399, which proposed tracking
                        // aliases and matching calls through them: a parser in a test is more
                        // machinery than this rule is worth, and a name that cannot be renamed cannot
                        // be constructed through a rename. Failing on the *rename* is also what keeps
                        // this from flagging a `&DebugEngine` parameter — only these two forms
                        // introduce one, and no file in the crate has either today.
                        || line.contains("DebugEngine as ")
                        || (line.starts_with("type ") && line.contains("DebugEngine"))
                });
                if builds {
                    builders.push(
                        path.strip_prefix(&src)
                            .unwrap_or(&path)
                            .display()
                            .to_string()
                            .replace('\\', "/"),
                    );
                }
            }
        }
        // A walk that read nothing would agree with an empty expectation, which is the one way this
        // test could pass by doing nothing at all.
        assert!(walked > 20, "only {walked} Rust files were walked");
        builders.sort();
        assert_eq!(
            builders,
            vec!["sksym.rs".to_string(), "worker.rs".to_string()],
            "a `DebugEngine` is constructed outside the engine worker and `sksym`. That decides \
             which process owns a debuggee session, so it is a design change rather than a local \
             one: see `AGENTS.md`, this module's docs, and `FOLLOWUPS.md` item 103 gate S3, which \
             is where the tool surface's engine is still to be placed."
        );
    }

    /// The three figures the bench measured, as literals.
    ///
    /// **Literals rather than constants shared with the code**, so this pins the arithmetic
    /// instead of restating it: a fixture and a parser reading one constant are blind to it. The
    /// preferred base and `SizeOfImage` are what the engine reported for
    /// `C:\Windows\System32\securekernel.exe` 10.0.26100.9457 on 2026-09-27, and the guest base is
    /// the one gate S1's decode found in the `H1 pinned 26200.9457 VBS+HVCI` capture.
    const PREFERRED: u64 = 0x1_4000_0000;
    const GUEST: u64 = 0xFFFF_F807_0EDA_9000;
    const SIZE: u32 = 0x175000;

    fn measured() -> Rebase {
        Rebase::new(PREFERRED, GUEST, SIZE).expect("the measured figures rebase")
    }

    #[test]
    fn the_two_landmarks_land_where_the_capture_found_them() {
        let rebase = measured();
        // `KdDebuggerDataBlock` at RVA 0x1335E0 and `SkLoadedModuleList` at 0x127770 — the PDB's
        // offsets for this build. The guest addresses are gate S1's: the block's own address in
        // the capture, and the list head its structural cross-check reached by following a loader
        // entry's `Blink`. Two derivations, one address each.
        assert_eq!(
            rebase.place(PREFERRED + 0x1335E0).unwrap().guest,
            Gva(0xFFFF_F807_0EED_C5E0)
        );
        assert_eq!(
            rebase.place(PREFERRED + 0x127770).unwrap().guest,
            Gva(0xFFFF_F807_0EED_0770)
        );
        // And back, because a one-way translation is half of what a resolver needs.
        assert_eq!(
            rebase.to_engine(Gva(0xFFFF_F807_0EED_C5E0)).unwrap(),
            PREFERRED + 0x1335E0
        );
        assert_eq!(
            rebase.rva_in_guest(Gva(0xFFFF_F807_0EED_0770)).unwrap(),
            0x127770
        );
    }

    #[test]
    fn the_ends_of_the_image_are_where_they_should_be() {
        let rebase = measured();
        // The base itself is in.
        assert_eq!(rebase.place(PREFERRED).unwrap().guest, Gva(GUEST));
        // The last byte is in, and the byte after it is not: `SizeOfImage` bytes from the base is
        // the whole image, so the end is half-open. An off-by-one here would name a symbol in
        // whatever the guest mapped next.
        assert_eq!(
            rebase.place(PREFERRED + u64::from(SIZE) - 1).unwrap().guest,
            Gva(GUEST + u64::from(SIZE) - 1)
        );
        assert_eq!(
            rebase.place(PREFERRED + u64::from(SIZE)),
            Err(OutsideImage::Past {
                address: PREFERRED + u64::from(SIZE),
                base: PREFERRED,
                size: SIZE,
            })
        );
    }

    #[test]
    fn an_address_below_the_base_is_refused_rather_than_wrapped() {
        let rebase = measured();
        // The case a `wrapping_sub` would turn into an enormous RVA that passes no bound check and
        // resolves to a plausible name near the end of the image.
        assert_eq!(
            rebase.place(PREFERRED - 1),
            Err(OutsideImage::Below {
                address: PREFERRED - 1,
                base: PREFERRED,
            })
        );
        // And in the guest's direction, where the base is upper-half and the address below it is
        // an ordinary-looking kernel address.
        assert_eq!(
            rebase.to_engine(Gva(GUEST - 0x1000)),
            Err(OutsideImage::Below {
                address: GUEST - 0x1000,
                base: GUEST,
            })
        );
    }

    #[test]
    fn a_range_that_runs_off_the_top_is_refused() {
        // `SizeOfImage` comes out of a guest's own header, so a crafted or corrupt one puts the end
        // of the image past the top of the address space. Both bases are checked, not just the
        // guest's: the engine's is read from the engine and is no more trusted than the other.
        assert_eq!(
            Rebase::new(u64::MAX - 0x10, GUEST, SIZE),
            Err(RebaseRefused::RangeOverflows {
                base: u64::MAX - 0x10,
                size: SIZE,
            })
        );
        assert_eq!(
            Rebase::new(PREFERRED, u64::MAX - 0x10, SIZE),
            Err(RebaseRefused::RangeOverflows {
                base: u64::MAX - 0x10,
                size: SIZE,
            })
        );
        assert_eq!(
            Rebase::new(PREFERRED, GUEST, 0),
            Err(RebaseRefused::EmptyImage)
        );
    }

    #[test]
    fn an_unresolved_symbol_is_not_a_disagreement() {
        // The distinction the whole report turns on: a host with no symbol server produces no
        // `Resolved`, and that must read as *unknown* rather than as the decode being wrong.
        let unresolved = Agreement {
            name: "SkLoadedModuleList",
            from_symbols: Err(ResolveFailure::Unknown {
                name: "securekernel!SkLoadedModuleList".into(),
                detail: "no symbol server".into(),
            }),
            from_decode: Gva(0xFFFF_F807_0EED_0770),
            decode_rva: Ok(0x127770),
            named_by_decode: Ok(None),
        };
        assert_eq!(unresolved.agrees(), None);

        let rebase = measured();
        let agreeing = Agreement {
            name: "SkLoadedModuleList",
            from_symbols: Ok(Resolved {
                rva: 0x127770,
                guest: Gva(0xFFFF_F807_0EED_0770),
                engine: PREFERRED + 0x127770,
            }),
            from_decode: Gva(0xFFFF_F807_0EED_0770),
            decode_rva: rebase.rva_in_guest(Gva(0xFFFF_F807_0EED_0770)),
            named_by_decode: Ok(Some(Named {
                symbol: "securekernel!SkLoadedModuleList".into(),
                displacement: 0,
            })),
        };
        assert_eq!(agreeing.agrees(), Some(true));

        // One page out is a disagreement and not a near miss. The decode's address is what would
        // be wrong here, and the report has to say so rather than round it off.
        let disagreeing = Agreement {
            from_decode: Gva(0xFFFF_F807_0EED_1770),
            ..agreeing
        };
        assert_eq!(disagreeing.agrees(), Some(false));
    }

    /// The whole route, against a real image: open, load, resolve both directions, rebase.
    ///
    /// Gated on the **image path**, so the gate and the input are one thing and a stale variable
    /// cannot point the test at a file that is not there. It needs an engine bundle beside the test
    /// binary (or an engine on the search path), a symbol path that reaches a store with this
    /// build's PDB, and a few seconds to download it.
    ///
    ///     $env:WINDBG_MCP_SMOKE_SKSYM = "C:\Windows\System32\securekernel.exe"
    ///     cargo test --nocapture sksym
    ///
    /// **It asserts nothing about the type probes.** Whether a Microsoft public PDB carries type
    /// records is Microsoft's to change, and a test that pinned today's answer would fail on a
    /// build that started shipping them — which is the opposite of what this gate wants to hear
    /// about. The result is printed instead.
    #[test]
    fn an_image_resolves_its_own_symbols_with_no_debuggee() {
        let Ok(path) = std::env::var("WINDBG_MCP_SMOKE_SKSYM") else {
            println!(
                "SKIPPED: set WINDBG_MCP_SMOKE_SKSYM=<path to securekernel.exe> to resolve \
                 symbols against a real image"
            );
            return;
        };
        let path = std::path::PathBuf::from(path);
        let disk = DiskImage::open(&path).expect("the image parses as PE64");
        let symbols = Symbols::open(&path, &disk, None).expect("the image opens with symbols");
        println!(
            "module {} at {:#X}, SizeOfImage {:#X}, symbols {:?}, pdb {:?}, file {}",
            symbols.qualifier(),
            symbols.preferred_base(),
            symbols.size_of_image(),
            symbols.kind(),
            symbols.pdb().map(|p| format!("{}{:X}", p.guid, p.age)),
            symbols.symbol_file()
        );
        println!("type probes: {:?}", symbols.type_probes());
        // **`open`'s post-condition, and it is a ratchet rather than a discovery.** Since round 3 the
        // refusal makes a `Deferred` kind unreachable here — `open` would have returned `Err` — so
        // this cannot fail while that refusal stands, and that is the point: it fails if the refusal
        // is ever narrowed again, which is what rounds 1 to 3 of #399 did once already. The PDB half
        // is the same claim from the other side: a provider that loaded and a PDB the engine can name
        // are the state the cached provenance is only safe in — and since round 7 that half is a
        // ratchet too, `Unvouched::NoIdentity` having made a PDB-backed module with no signature a
        // refusal. Both assertions now fail only if a refusal is narrowed, which is what they are for.
        assert_ne!(
            symbols.kind(),
            SymbolKind::Deferred,
            "open left the module deferred, so the provenance it reports is not yet a fact"
        );
        assert!(
            symbols.pdb().is_some(),
            "symbols loaded and the engine named no PDB for them"
        );

        // A base the image was certainly not built for, so a resolution that ignored the rebase
        // could not accidentally agree with one that applied it.
        let guest_base = Gva(0xFFFF_F807_0EDA_9000);
        let resolver = symbols.at(guest_base).expect("the measured base rebases");
        for name in ["KdDebuggerDataBlock", "SkLoadedModuleList"] {
            let resolved = resolver
                .resolve(name)
                .unwrap_or_else(|why| panic!("{name}: {why}"));
            assert_eq!(
                resolved.guest,
                Gva(guest_base.0 + u64::from(resolved.rva)),
                "{name}'s guest address is its RVA past the base it was given"
            );
            assert_eq!(
                resolved.engine,
                symbols.preferred_base() + u64::from(resolved.rva),
                "{name}'s engine address is its RVA past the preferred base"
            );
            // The other direction, at the address the rebase produced: the engine has to name the
            // same symbol there, exactly, with nothing between.
            let named = resolver
                .describe(resolved.guest)
                .expect("the resolved address is in the image")
                .unwrap_or_else(|| panic!("{name} resolved and then named nothing"));
            assert!(
                named.symbol.ends_with(name),
                "{:?} is not {name}",
                named.symbol
            );
            assert_eq!(named.displacement, 0, "{name} is not at {:?}", named.symbol);
            println!("{name}: rva {:#X} -> {:#X}", resolved.rva, resolved.guest.0);
        }
    }
}
