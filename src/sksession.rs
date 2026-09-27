//! A Secure Kernel capture, held open as a **session** — `FOLLOWUPS.md` item 103, gate **S3**.
//!
//! Gate S1 ([`crate::sk`]) decodes a guest's VTL1 out of a byte source, gate S2 ([`crate::sksym`])
//! names what is in it, and both were reachable only from `--sk-inspect`, a command-line role that
//! reads a capture and prints a report. This is the same two halves behind the tool surface: one
//! session per capture, opened once, answering questions about it until it is ended.
//!
//! # The three questions S3 was deferred to answer
//!
//! The plan left the shape open on purpose, because two of the three are about **where an engine
//! lives**, which is this repository's oldest architectural line.
//!
//! **1. Where does it live? In a worker, and the decisive half of that is measured rather than
//! argued.** The rule (`AGENTS.md`) is that the process serving MCP never loads DbgEng, which
//! already rules the supervisor out for the symbol half. What rules it out for the *engine-free*
//! half is gate S0 arm 4: `vmsavedstatedumpprovider.dll` **`__fastfail`s** on a capture it has no
//! key for — `0xC0000409`, subcode `FAST_FAIL_FATAL_APP_EXIT`, measured on two different hosts and
//! from two different callers (`docs/secure-kernel/vmsavedstatedumpprovider-crash.md`). A vendor
//! DLL that aborts the process on an input a caller supplies cannot be loaded into the supervisor:
//! there it would take every other client's session with it. In a worker it costs the one session
//! that named the capture, which is the property process-per-session exists for.
//!
//! **2. One session handle or two? One.** The symbols are the capture's *only because* the mapping
//! was identified against the same image on disk, and the rebase needs the base the decode found —
//! so a symbol handle without a capture handle can answer nothing in guest coordinates, and two
//! handles would be two halves of a join that nothing checks. Symbols stay **opt-in per session**
//! (`symbols: true`), because they are the only part that needs a debugger bundle and a reachable
//! symbol store, and the decode stands without them.
//!
//! **3. What is a "structure walk" with no types? The decoders [`crate::sk`] already has.** The
//! public `securekernel.pdb` carries no type information — four `GetTypeId` probes answer
//! `E_NOINTERFACE`, the engine declining to service type queries for this module at all — so there
//! is no `dt` over VTL1 to offer. What this surface exposes is what was hand-decoded: the root
//! page, the walk, the identified image, the debugger data block, and the loader list. The type
//! probes travel with the session so a caller is told *why* there is no type-driven walk rather
//! than finding out one failed call at a time.
//!
//! # The engine's target is the image, and that is why the debugger tools are refused
//!
//! A worker holding this session has at most **one** DbgEng target open, and it is
//! `securekernel.exe` **as a file**, at the image's own preferred base. `read_memory` against it
//! would read the file rather than the guest; `registers` would answer about no thread at all. So
//! the supervisor refuses every op that is not one of this session's own
//! ([`crate::engine::refuse_op_on_kind`]), by an **allow-list** — a tool added later is refused
//! here until somebody decides what it means for a capture, rather than quietly answering about
//! the wrong target.
//!
//! That refusal is also what makes the session's answers stable: nothing in it can execute a
//! command, so the engine's target cannot be replaced under the symbols, and the capture is a file
//! that does not change. Every figure this module reports is therefore as true at the end of the
//! session as at the open, which is why the whole decode travels with the opener.

use std::path::PathBuf;

use dbgscope::dbgeng::DebugEngine;

use crate::savedstate::{Capture, CaptureFiles, CaptureForm, CaptureSpec, Kit, Provider};
use crate::sk::{self, Gva, Landmarks, NotWalkable, VaFailure};
use crate::sksym::{self, Loaded, OutsideImage, RebaseRefused, SymbolFailure};
use crate::structured::{self, addr};

/// The most a single read may ask for.
///
/// A capture is a file and the read itself is cheap; what is not cheap is the answer, which is hex
/// and so twice the size again in a result a model pays for. A caller that wants a megabyte of
/// VTL1 wants a different tool than this one.
pub(crate) const MAX_READ: u32 = 64 * 1024;

/// What `open_sk_capture` was asked for, resolved.
///
/// The capture is **one** value by the time it reaches here ([`CaptureSpec`]) — the supervisor
/// resolves the three ways of naming one and refuses anything but exactly one, so this side has no
/// preference to get wrong.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Request {
    pub capture: CaptureSpec,
    /// The image the mapping is identified against. Required: identification compares the bytes in
    /// the guest with a file on disk, and there is nothing to compare without one.
    pub image: PathBuf,
    pub kit: Option<PathBuf>,
    pub kit_version: Option<String>,
    pub vp: u32,
    pub vtl: u8,
    pub cross_check: bool,
    pub symbols: bool,
    pub symbol_path: Option<String>,
}

/// What became of the symbol half.
enum SymbolHalf {
    /// The session was opened without `symbols`, so no engine was pointed at the image.
    NotRequested,
    Loaded(Loaded),
    /// Asked for and unavailable. **Not fatal**: the decode is gate S1's and stands without
    /// symbols, so the reason travels as a value and is reported in its place.
    Refused(SymbolFailure),
}

/// One open capture, and everything decoded out of it.
pub(crate) struct Session {
    files: CaptureFiles,
    /// Which SDK provider read the capture. Reported rather than forgotten: a figure from this
    /// session was produced by that DLL and not by another one.
    kit: Kit,
    vp: u32,
    vtl: u8,
    /// Borrows the provider, which is leaked for the life of the process — see [`provider`].
    capture: Capture<'static>,
    disk: sk::DiskImage,
    /// The decode, or why there was nothing to decode. A capture of a guest with Secure Kernel
    /// switched off lands in `Err`, and that is an **answer**: the session opens and says so.
    landmarks: Result<Landmarks, NotWalkable>,
    symbols: SymbolHalf,
}

/// The provider DLL, loaded once per worker process and never freed.
///
/// **Leaked deliberately, and it is the sound direction rather than the lazy one.** A [`Capture`]
/// borrows the provider's resolved entry points and calls them in its own `Drop`; a provider freed
/// first would leave the capture calling into an unmapped DLL. The process holds one session for
/// its whole life and exits with it, so the alternative — a self-referential pair, or ordering two
/// drops by hand — buys nothing this does not already have.
fn provider(kit: &Kit) -> Result<&'static Provider, String> {
    Ok(Box::leak(Box::new(Provider::load(kit)?)))
}

impl Session {
    /// Open the capture, decode it, and — if asked — load the image's symbols into `engine`.
    ///
    /// The order is not a preference. The **image on disk** is read first, so a mistyped path is a
    /// refusal rather than a failure three minutes into a capture read. The **engine** comes next,
    /// because the debugger bundle carries its own `dbghelp.dll` and whichever of DbgEng and the
    /// SDK provider loads first is the one the other inherits by name: the engine needs its own,
    /// and that the provider still reads a capture afterwards is measured rather than assumed
    /// (gate S2). The **provider** and the capture come last, which is also the expensive part.
    pub(crate) fn open(request: &Request, engine: &DebugEngine) -> Result<Session, String> {
        let disk = sk::DiskImage::open(&request.image)?;
        let kit = Kit::find(request.kit.as_deref(), request.kit_version.as_deref())?;
        let symbols = if request.symbols {
            match Loaded::on(
                engine,
                &request.image,
                &disk,
                request.symbol_path.as_deref(),
            ) {
                Ok(loaded) => SymbolHalf::Loaded(loaded),
                Err(why) => SymbolHalf::Refused(why),
            }
        } else {
            SymbolHalf::NotRequested
        };
        let provider = provider(&kit)?;
        let files = request.capture.files(provider)?;
        let capture = provider.open(&files, request.vp, request.vtl)?;
        // Scoped rather than dropped: `reader` borrows `capture`, and `landmarks` owns
        // everything the decode produced — including the address space later reads are served from
        // — so the borrow ends with the block and the capture moves into the session.
        let landmarks = {
            let reader = sk::Reader::new(&capture);
            sk::locate(&reader, &disk, request.cross_check)
        };
        Ok(Session {
            files,
            kit,
            vp: request.vp,
            vtl: request.vtl,
            capture,
            disk,
            landmarks,
            symbols,
        })
    }

    /// The whole decode, as values, for the opener's typed answer.
    pub(crate) fn report(&self) -> structured::SecureKernelReport {
        let facts = &self.capture.facts;
        structured::SecureKernelReport {
            capture: self
                .files
                .paths()
                .iter()
                .map(|p| (*p).to_string())
                .collect(),
            provider: structured::SkProvider {
                kit_version: self.kit.version.clone(),
                dll: self.kit.dll.display().to_string(),
            },
            identified_against: structured::SkImageOnDisk {
                path: self.disk.path.clone(),
                file_size: self.disk.file_size,
                sections: self.disk.identity.sections,
                timestamp: self.disk.identity.timestamp,
                size_of_image: self.disk.identity.size_of_image,
            },
            form: match self.capture.form {
                CaptureForm::Vmrs => structured::SkCaptureForm::Vmrs,
                CaptureForm::BinVsv => structured::SkCaptureForm::BinVsv,
            },
            vp: self.vp,
            vtl: self.vtl,
            guest: structured::SkGuest {
                vp_count: facts.vp_count,
                partition_vtls: facts.guest_vtls.map(|vtls| format!("{vtls:#x}")),
                vp_vtls: facts.vp_vtls.map(|vtls| format!("{vtls:#x}")),
                active_vtl: facts.active_vtl,
                architecture: facts.architecture,
                unanswered: facts
                    .unreadable
                    .iter()
                    .map(|(question, detail)| structured::SkUnanswered {
                        question: (*question).to_string(),
                        detail: detail.clone(),
                    })
                    .collect(),
            },
            not_walkable: self.landmarks.as_ref().err().map(refusal),
            decode: self.landmarks.as_ref().ok().map(decoded),
            symbols: self.symbol_half(),
        }
    }

    /// The symbol half, with the landmarks resolved in both directions where there are any.
    ///
    /// Takes no engine, so the type probes and the landmark comparison are **read at the open** and
    /// reported from what was recorded. That is not a shortcut: the same two answers asked later
    /// would be the same answers, because nothing in this session can move the engine's target.
    fn symbol_half(&self) -> structured::SkSymbolHalf {
        let empty = structured::SkSymbolHalf {
            state: structured::SkSymbolState::NotRequested,
            refusal: None,
            qualifier: None,
            preferred_base: None,
            kind: None,
            pdb: None,
            symbol_file: None,
            reload_error: None,
            type_probes: Vec::new(),
            landmarks: Vec::new(),
        };
        match &self.symbols {
            SymbolHalf::NotRequested => empty,
            SymbolHalf::Refused(why) => structured::SkSymbolHalf {
                state: structured::SkSymbolState::Refused,
                refusal: Some(why.to_string()),
                symbol_file: why.file_read().map(str::to_string),
                ..empty
            },
            SymbolHalf::Loaded(loaded) => structured::SkSymbolHalf {
                state: structured::SkSymbolState::Loaded,
                qualifier: Some(loaded.qualifier().to_string()),
                preferred_base: Some(addr(loaded.preferred_base())),
                kind: Some(loaded.kind().into()),
                pdb: loaded.pdb().map(|pdb| structured::CoordinatePdb {
                    guid: pdb.guid.clone(),
                    age: pdb.age,
                    unmatched: pdb.unmatched,
                }),
                symbol_file: Some(loaded.symbol_file().to_string()).filter(|f| !f.is_empty()),
                reload_error: loaded.reload_error().map(str::to_string),
                ..empty
            },
        }
    }

    /// The type probes and the landmark agreement, which need the engine the symbols were loaded
    /// into.
    ///
    /// Folded into [`Self::report`]'s answer by the caller that has the engine, rather than read
    /// here, so this module never has to hold one.
    pub(crate) fn symbol_evidence(
        &self,
        engine: &DebugEngine,
    ) -> (Vec<structured::SkTypeProbe>, Vec<structured::SkLandmark>) {
        let SymbolHalf::Loaded(loaded) = &self.symbols else {
            return (Vec::new(), Vec::new());
        };
        let probes = loaded
            .type_probes(engine)
            .into_iter()
            .map(|(name, answer)| structured::SkTypeProbe {
                name: name.to_string(),
                type_id: answer.as_ref().ok().copied(),
                refused: answer.err(),
            })
            .collect();
        let Some(found) = self
            .landmarks
            .as_ref()
            .ok()
            .and_then(|l| l.identified.as_ref())
        else {
            return (probes, Vec::new());
        };
        let resolver = match loaded.at(engine, found.candidate.va) {
            Ok(resolver) => resolver,
            Err(why) => {
                return (
                    probes,
                    vec![structured::SkLandmark {
                        name: "(the image)".into(),
                        from_decode: addr(found.candidate.va.0),
                        from_symbols: None,
                        rva: None,
                        agrees: None,
                        named_by_decode: None,
                        detail: Some(rebase_refused(why)),
                    }],
                );
            }
        };
        let landmarks = [
            ("KdDebuggerDataBlock", found.block.va),
            ("SkLoadedModuleList", Gva(found.block.ps_loaded_module_list)),
        ]
        .into_iter()
        .map(|(name, from_decode)| {
            let agreement = sksym::compare(&resolver, name, from_decode);
            structured::SkLandmark {
                name: name.to_string(),
                from_decode: addr(from_decode.0),
                from_symbols: agreement
                    .from_symbols
                    .as_ref()
                    .ok()
                    .map(|resolved| addr(resolved.guest.0)),
                rva: agreement
                    .decode_rva
                    .as_ref()
                    .ok()
                    .map(|rva| format!("{rva:#x}")),
                agrees: agreement.agrees(),
                named_by_decode: match &agreement.named_by_decode {
                    Ok(Some(named)) => Some(named.symbol.clone()),
                    _ => None,
                },
                // Whichever direction had no answer says so with the engine's own reason: a PDB
                // with nothing to say is a host without symbols for this build, and reporting that
                // as a disagreement would make it look like a broken decode.
                detail: match (&agreement.from_symbols, &agreement.named_by_decode) {
                    (Err(why), _) => Some(why.to_string()),
                    (_, Err(why)) => Some(outside(why)),
                    (Ok(_), Ok(None)) => {
                        Some("the engine has no name for the decode's address".into())
                    }
                    _ => None,
                },
            }
        })
        .collect();
        (probes, landmarks)
    }

    /// The VTL1 loader list, as the walk at the open read it.
    pub(crate) fn modules(&self) -> Result<structured::SecureKernelModules, String> {
        let found = self.identified()?;
        let list = &found.modules;
        Ok(structured::SecureKernelModules {
            head: addr(list.head.0),
            modules: list
                .entries
                .iter()
                .map(|entry| match &entry.record {
                    None => structured::SkModule {
                        entry: addr(entry.va.0),
                        name: None,
                        name_unreadable: None,
                        base: None,
                        size_of_image: None,
                        unreadable: Some("the loader record itself could not be read".into()),
                    },
                    Some(record) => structured::SkModule {
                        entry: addr(entry.va.0),
                        name: record.name.as_ref().ok().cloned(),
                        name_unreadable: record.name.as_ref().err().map(name_failure),
                        base: Some(addr(record.dll_base)),
                        size_of_image: Some(record.size_of_image),
                        unreadable: None,
                    },
                })
                .collect(),
            complete: list.complete(),
            incomplete: list.incomplete.as_ref().map(list_incomplete),
            names_unreadable: list.names_unreadable,
        })
    }

    /// `size` bytes of VTL1 at `address`, through the address space the walk found.
    pub(crate) fn read(
        &self,
        engine: &DebugEngine,
        address: u64,
        size: u32,
    ) -> Result<structured::SecureKernelRead, String> {
        readable(size)?;
        let landmarks = self.walkable()?;
        let at = Gva(address);
        // The physical address the range starts at, which is the coordinate the source was actually
        // asked for: a reader comparing this reading with one taken another way needs it.
        //
        // **Looked up before the read, so one unmapped page is refused once.** Taken afterwards it
        // could only fail on a page the read had just answered for, and the branch would be a second
        // sentence for a condition `read_span` already reports — which for any page *after* the
        // first is still the one that reports it.
        let Some(gpa) = landmarks.space.translate(at) else {
            return Err(format!("nothing in this capture's VTL1 maps {address:#x}"));
        };
        let reader = sk::Reader::new(&self.capture);
        let space = sk::Space::new(&reader, &landmarks.space);
        let bytes = space
            .read_span(at, size as usize)
            .map_err(|why| va_failure(&why))?;
        Ok(structured::SecureKernelRead {
            address: addr(address),
            gpa: addr(gpa.0),
            requested_size: size,
            read_size: bytes.len() as u32,
            data: bytes.iter().map(|b| format!("{b:02X}")).collect(),
            symbol: self.name_of(engine, at),
        })
    }

    /// Where a name is, or what is at an address.
    pub(crate) fn symbol(
        &self,
        engine: &DebugEngine,
        name: Option<&str>,
        address: Option<u64>,
    ) -> Result<structured::SecureKernelSymbol, String> {
        let resolver = self.resolver(engine)?;
        match (name, address) {
            (Some(name), None) => {
                let resolved = resolver.resolve(name).map_err(|why| why.to_string())?;
                Ok(structured::SecureKernelSymbol {
                    symbol: format!("{}!{}", resolver.qualifier(), name),
                    address: addr(resolved.guest.0),
                    rva: format!("{:#x}", resolved.rva),
                    engine_address: addr(resolved.engine),
                    displacement: None,
                })
            }
            (None, Some(address)) => {
                let at = Gva(address);
                let named = resolver
                    .describe(at)
                    .map_err(|why| outside(&why))?
                    .ok_or_else(|| {
                        format!("the image's symbols name nothing at or before {address:#x}")
                    })?;
                let rva = resolver
                    .rebase()
                    .rva_in_guest(at)
                    .map_err(|why| outside(&why))?;
                Ok(structured::SecureKernelSymbol {
                    symbol: named.symbol,
                    address: addr(address),
                    rva: format!("{rva:#x}"),
                    engine_address: addr(
                        resolver
                            .rebase()
                            .to_engine(at)
                            .map_err(|why| outside(&why))?,
                    ),
                    displacement: Some(named.displacement),
                })
            }
            _ => Err("give exactly one of `name` or `address`".into()),
        }
    }

    /// What the symbols call `at`, for a read to carry. Best-effort: an address outside the image,
    /// a session with no symbols and an image with no name there are all simply *nothing to say*.
    fn name_of(&self, engine: &DebugEngine, at: Gva) -> Option<String> {
        let resolver = self.resolver(engine).ok()?;
        let named = resolver.describe(at).ok()??;
        Some(match named.displacement {
            0 => named.symbol,
            by => format!("{}+{by:#x}", named.symbol),
        })
    }

    fn resolver<'a>(&'a self, engine: &'a DebugEngine) -> Result<sksym::Resolver<'a>, String> {
        let loaded = match &self.symbols {
            SymbolHalf::Loaded(loaded) => loaded,
            SymbolHalf::NotRequested => {
                return Err(
                    "this session was opened without symbols; open it again with \
                            `symbols` to resolve names against the image"
                        .into(),
                );
            }
            SymbolHalf::Refused(why) => {
                return Err(format!("this session has no symbols: {why}"));
            }
        };
        let found = self.identified()?;
        loaded
            .at(engine, found.candidate.va)
            .map_err(rebase_refused)
    }

    /// The decode, or the reason there is none — the same sentence the opener reported.
    fn walkable(&self) -> Result<&Landmarks, String> {
        self.landmarks.as_ref().map_err(|why| {
            format!(
                "this capture has no VTL1 address space to read: {}",
                refusal(why)
            )
        })
    }

    fn identified(&self) -> Result<&sk::Identified, String> {
        self.walkable()?.identified.as_ref().ok_or_else(|| {
            "the decode found no Secure Kernel image in this capture's VTL1, so there is nothing \
             to name: the open's report says which candidates were examined and why each was \
             refused"
                .to_string()
        })
    }

    /// Whether the decode found a Secure Kernel at all, for the session's one-line limitation.
    pub(crate) fn limitation(&self) -> Option<String> {
        match &self.landmarks {
            Err(why) => Some(format!(
                "This capture carries no VTL1 to read ({}), so every read against this session is \
                 refused. The guest it was taken from had Secure Kernel switched off, or the \
                 provider would not switch the virtual processor to VTL1.",
                refusal(why)
            )),
            Ok(landmarks) if landmarks.identified.is_none() => Some(
                "The walk found no mapping of this image in the capture's VTL1, so nothing here \
                 can be named or listed; the report says which candidates were examined."
                    .to_string(),
            ),
            Ok(_) => match &self.symbols {
                SymbolHalf::Refused(why) => Some(format!(
                    "The decode is complete and no symbols loaded ({why}), so addresses in this \
                     session have no names."
                )),
                _ => None,
            },
        }
    }
}

/// Whether a read of this size is one this tool will do.
///
/// A free function rather than two lines inside the read, so the bound is testable without a
/// capture, a provider or an SDK — which is the only way it gets tested at all.
fn readable(size: u32) -> Result<(), String> {
    if size == 0 {
        return Err("size must be at least one byte".into());
    }
    if size > MAX_READ {
        return Err(format!(
            "{size} bytes is more than this tool will read at once ({MAX_READ}); ask for a \
             narrower range"
        ));
    }
    Ok(())
}

/// The decode as values.
fn decoded(landmarks: &Landmarks) -> structured::SkDecode {
    structured::SkDecode {
        root: addr(landmarks.root.0),
        root_page: landmarks
            .root_page
            .as_ref()
            .ok()
            .map(|page| structured::SkRootPage {
                present_entries: page.present_entries,
                non_zero_bytes: page.nonzero_bytes,
                self_map_indexes: page.self_map_indexes.clone(),
                first_present_index: page.first_present_index,
                upper_half_present: page.upper_half_present,
            }),
        root_page_unreadable: landmarks
            .root_page
            .as_ref()
            .err()
            .map(|why| format!("{why:?}")),
        walk: structured::SkWalk {
            leaf_mappings: landmarks.walk.leaves,
            mapped_pages: landmarks.mapped_pages,
            table_reads: landmarks.walk.table_reads,
            tables_decoded: landmarks.walk.tables_decoded,
            alias_prefixes_skipped: landmarks.walk.alias_prefixes_skipped,
            malformed_entries: landmarks.walk.malformed_entries,
            unreadable_tables: landmarks.walk.unreadable_tables,
            complete: landmarks.walk.complete(),
            incomplete: landmarks.walk.incomplete.map(walk_incomplete),
        },
        scan: structured::SkScan {
            pages_scanned: landmarks.scan.scanned,
            pages_unreadable: landmarks.scan.unreadable,
            pe_headers_found: landmarks.candidates.len(),
            matching_the_image: landmarks
                .candidates
                .iter()
                .filter(|candidate| candidate.matches_disk)
                .count(),
            capped: landmarks.scan.capped,
        },
        image: landmarks
            .identified
            .as_ref()
            .map(|found| structured::SkImage {
                base: addr(found.candidate.va.0),
                gpa: addr(found.candidate.gpa.0),
                size_of_image: found.candidate.identity.size_of_image,
                timestamp: found.candidate.identity.timestamp,
                gathered_bytes: found.image.bytes.len(),
                pages_unreadable: found.image.missing.len(),
                block: addr(found.block.va.0),
                block_size: found.block.size,
                module_list: addr(found.block.ps_loaded_module_list),
                modules: found.modules.entries.len(),
            }),
        rejected: landmarks
            .attempts
            .iter()
            .flat_map(|attempt| attempt.rejected.iter())
            .map(|(at, why)| structured::SkRejection {
                at: addr(at.0),
                why: format!("{why:?}"),
            })
            .collect(),
        cross_check: landmarks.cross_check.as_ref().map(|result| match result {
            Ok(found) => structured::SkCrossCheck {
                // **Compared, not assumed.** Finding the entry and reading its `Blink` is what this
                // route *does*; whether that head is the one the block names is the question it was
                // run to answer, and reporting `Ok` as agreement answers it without asking.
                agrees: landmarks
                    .identified
                    .as_ref()
                    .map(|found_image| found.agrees_with(&found_image.block)),
                entry: Some(addr(found.entry.0)),
                head: Some(addr(found.head.0)),
                pages_scanned: found.pages_scanned,
                pages_unreadable: found.pages_unreadable,
                detail: None,
            },
            Err(miss) => structured::SkCrossCheck {
                // A miss is not a disagreement: nothing was found to compare, which is what the
                // detail below says and what `None` means here.
                agrees: None,
                entry: None,
                head: None,
                pages_scanned: miss.pages_scanned,
                pages_unreadable: miss.pages_unreadable,
                detail: Some(format!(
                    "the structural route found no loader entry for this base{}",
                    if miss.capped {
                        ", and stopped at its own budget"
                    } else {
                        ""
                    }
                )),
            },
        }),
        reads: structured::SkReads {
            attempted: landmarks.reads.attempted,
            failed: landmarks.reads.failed,
            refused: landmarks.reads.refused,
            bytes: landmarks.reads.bytes,
        },
    }
}

/// Why there is no VTL1 address space, as one sentence.
///
/// **A refused switch and a guest with no Secure Kernel are different answers** and stay different
/// here: the first is the provider declining, which is what a VBS-off capture does by name, and the
/// second would be a walk that found nothing.
pub(crate) fn refusal(why: &NotWalkable) -> String {
    match why {
        NotWalkable::SwitchRefused(detail) => detail.clone(),
        NotWalkable::VtlNotEnabled => {
            "the provider reports this VTL is not enabled on the VP".into()
        }
        NotWalkable::NoRoot { unreadable } => format!(
            "no page-table root came back from the capture ({})",
            if unreadable.is_empty() {
                "no register failed, so the capture simply carries none".to_string()
            } else {
                unreadable
                    .iter()
                    .map(|(name, detail)| format!("{name}: {detail}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ),
        NotWalkable::PagingMode(mode) => {
            format!("paging mode {mode:?} is not the four-level long mode this walk decodes")
        }
        NotWalkable::FiveLevel => "CR4.LA57 is set: five-level paging is not decoded".into(),
        NotWalkable::NotLongMode => {
            "the control registers do not describe long mode (CR0.PG/PE, CR4.PAE, EFER.LMA)".into()
        }
    }
}

/// Why a descent is not the whole tree.
///
/// **Two ways, kept apart**: a budget is this walk's own limit, and an unreadable table is a
/// subtree the *source* did not answer for. Pruned aliases are neither and are counted on their
/// own — a self-mapped tree is combinatorial to enumerate, so a walk that called itself incomplete
/// for skipping them would never be complete.
fn walk_incomplete(why: sk::Incomplete) -> String {
    match why {
        sk::Incomplete::Budget(sk::Budget::TableReads(reads)) => {
            format!("the walk stopped at its budget of {reads} table read(s)")
        }
        sk::Incomplete::Budget(sk::Budget::Leaves(leaves)) => {
            format!("the walk stopped at its budget of {leaves} leaf mapping(s)")
        }
        sk::Incomplete::UnreadableTables(count) => format!(
            "{count} page table(s) could not be read, so the subtrees below them are missing \
             rather than empty"
        ),
    }
}

fn rebase_refused(why: RebaseRefused) -> String {
    match why {
        RebaseRefused::EmptyImage => {
            "the identified image has a zero SizeOfImage, so no address is inside it".into()
        }
        RebaseRefused::RangeOverflows { base, size } => format!(
            "an image of {size:#x} bytes based at {base:#x} runs off the top of the address space"
        ),
    }
}

fn outside(why: &OutsideImage) -> String {
    match why {
        OutsideImage::Below { address, base } => {
            format!("{address:#x} is below the image's base {base:#x}")
        }
        OutsideImage::Past {
            address,
            base,
            size,
        } => format!("{address:#x} is past the end of the image at {base:#x} + {size:#x}"),
    }
}

fn va_failure(why: &VaFailure) -> String {
    match why {
        VaFailure::Unmapped(va) => format!("nothing in this capture's VTL1 maps {:#x}", va.0),
        VaFailure::Read { va, gpa, failure } => format!(
            "reading {:#x} (physical {:#x}) failed: {}",
            va.0,
            gpa.0,
            read_failure(failure)
        ),
    }
}

/// Why one physical read did not answer.
///
/// **A refusal and a failure are different answers** and the seam carries both, which is the whole
/// of `ReadFailure`'s reason for existing: a source that answered success-with-`ReadIntercept` and
/// zeros has refused, and a report that folded that into "the read failed" would put silent zeros
/// exactly where the protected memory is.
fn read_failure(why: &sk::ReadFailure) -> String {
    match why {
        sk::ReadFailure::Refused { detail } => format!("the source refused it ({detail})"),
        sk::ReadFailure::NotPresent => "this capture does not cover that physical address".into(),
        sk::ReadFailure::SourceError { detail } => detail.clone(),
        sk::ReadFailure::Short { got, want } => {
            format!("the source answered {got} of {want} bytes")
        }
    }
}

fn name_failure(why: &sk::NameFailure) -> String {
    match why {
        sk::NameFailure::ImplausibleLength(length) => {
            format!("its BaseDllName has a Length of {length}, which no module name has")
        }
        sk::NameFailure::NullBuffer { length } => {
            format!("its BaseDllName has a Length of {length} and a null Buffer")
        }
        sk::NameFailure::Unreadable { buffer, failure } => format!(
            "its BaseDllName buffer at {:#x} could not be read: {}",
            buffer.0,
            va_failure(failure)
        ),
    }
}

fn list_incomplete(why: &sk::ListIncomplete) -> String {
    match why {
        sk::ListIncomplete::EntryUnreadable(at) => {
            format!("the entry at {:#x} could not be read", at.0)
        }
        sk::ListIncomplete::Limit(limit) => {
            format!("the walk stopped at its {limit}-entry limit")
        }
        sk::ListIncomplete::NullForwardLink => "an entry's forward link is null".into(),
        sk::ListIncomplete::LeftTheList(at) => format!(
            "the walk left the list at {:#x}, which is neither the head nor null",
            at.0
        ),
    }
}

/// The opener's report, rendered **from the typed answer** rather than beside it.
///
/// One source for both halves of the result, which is the property that matters here: a text
/// assembled from the decode and a value assembled from the decode are two counts of one thing, and
/// the one that drifts is the one a reader quotes. Everything below is a rendering of
/// [`structured::SecureKernelReport`] and nothing in it reads the capture.
pub(crate) fn render(report: &structured::SecureKernelReport) -> String {
    let mut out = String::new();
    for path in &report.capture {
        out.push_str(&format!("capture    {path}\n"));
    }
    let guest = &report.guest;
    out.push_str(&format!(
        "guest      form {:?}, {} vp(s), partition VTLs {}, vp VTLs {}, active VTL {}, arch {}\n",
        report.form,
        show(guest.vp_count),
        show(guest.partition_vtls.as_deref()),
        show(guest.vp_vtls.as_deref()),
        show(guest.active_vtl),
        show(guest.architecture),
    ));
    for unanswered in &guest.unanswered {
        out.push_str(&format!(
            "           the provider would not answer {}: {}\n",
            unanswered.question, unanswered.detail
        ));
    }
    if let Some(why) = &report.not_walkable {
        out.push_str(&format!("\nnot walkable: {why}\n"));
    }
    if let Some(decode) = &report.decode {
        out.push_str(&format!(
            "\nroot       {} (read from the capture, never remembered)\n",
            decode.root
        ));
        if let Some(page) = &decode.root_page {
            out.push_str(&format!(
                "rootpage   {} present entr(ies), {} non-zero byte(s), self-map at {:?}, first \
                 present index {}, {} in the upper half\n",
                page.present_entries,
                page.non_zero_bytes,
                page.self_map_indexes,
                show(page.first_present_index),
                page.upper_half_present,
            ));
        }
        if let Some(why) = &decode.root_page_unreadable {
            out.push_str(&format!("rootpage   unreadable: {why}\n"));
        }
        let walk = &decode.walk;
        out.push_str(&format!(
            "walk       {} leaf mapping(s) over {} distinct page(s); {} table read(s), {} \
             decode(s), {} alias prefix(es) not expanded, {} malformed entr(ies), {} unreadable \
             table(s), complete {}{}\n",
            walk.leaf_mappings,
            walk.mapped_pages,
            walk.table_reads,
            walk.tables_decoded,
            walk.alias_prefixes_skipped,
            walk.malformed_entries,
            walk.unreadable_tables,
            walk.complete,
            walk.incomplete
                .as_deref()
                .map(|why| format!(" — {why}"))
                .unwrap_or_default(),
        ));
        let scan = &decode.scan;
        out.push_str(&format!(
            "scan       {} page(s) scanned, {} unreadable, {} PE header(s) found, {} matching the \
             image on disk{}\n",
            scan.pages_scanned,
            scan.pages_unreadable,
            scan.pe_headers_found,
            scan.matching_the_image,
            if scan.capped {
                " (the scan stopped at its own budget)"
            } else {
                ""
            },
        ));
        for rejected in &decode.rejected {
            out.push_str(&format!(
                "           rejected {}: {}\n",
                rejected.at, rejected.why
            ));
        }
        match &decode.image {
            Some(image) => {
                out.push_str(&format!(
                    "image      {} (gpa {}), SizeOfImage {:#x}, timestamp {:#010x}, {} byte(s) \
                     gathered, {} page(s) unreadable\n",
                    image.base,
                    image.gpa,
                    image.size_of_image,
                    image.timestamp,
                    image.gathered_bytes,
                    image.pages_unreadable,
                ));
                out.push_str(&format!(
                    "block      {} Size {:#x}\nmodulelist {} ({} entr(ies))\n",
                    image.block, image.block_size, image.module_list, image.modules,
                ));
            }
            None => out.push_str(
                "image      no mapping of this image was identified in the capture's VTL1\n",
            ),
        }
        if let Some(cross) = &decode.cross_check {
            out.push_str(&format!(
                "crosscheck {} ({} page(s) scanned, {} unreadable)\n",
                match (cross.agrees, &cross.entry, &cross.head) {
                    (Some(true), Some(entry), Some(head)) => format!(
                        "entry {entry} -> head {head}: the structural route agrees with the block"
                    ),
                    // **Loud, because this is the one line that says the decode's two independent
                    // witnesses are about the same structure.** A disagreement here means one of
                    // them is reading something else, and a reader who skims must not read it as
                    // the agreeing case with different numbers in it.
                    (Some(false), Some(entry), Some(head)) => format!(
                        "entry {entry} -> head {head}: DISAGREES with the block, which names a \
                         different list head"
                    ),
                    _ => cross
                        .detail
                        .clone()
                        .unwrap_or_else(|| "the structural route found nothing".into()),
                },
                cross.pages_scanned,
                cross.pages_unreadable,
            ));
        }
        let reads = &decode.reads;
        out.push_str(&format!(
            "reads      {} attempted, {} failed ({} refused), {} byte(s)\n",
            reads.attempted, reads.failed, reads.refused, reads.bytes
        ));
    }
    out.push_str(&render_symbols(&report.symbols));
    out
}

fn render_symbols(symbols: &structured::SkSymbolHalf) -> String {
    let mut out = String::new();
    match symbols.state {
        structured::SkSymbolState::NotRequested => {
            out.push_str(
                "\nsymbols    not requested: this session resolves no names, and every address \
                 below is the decode's own\n",
            );
            return out;
        }
        structured::SkSymbolState::Refused => {
            out.push_str(&format!(
                "\nsymbols    none loaded: {}\n",
                symbols.refusal.as_deref().unwrap_or("no reason recorded")
            ));
            return out;
        }
        structured::SkSymbolState::Loaded => {}
    }
    out.push_str(&format!(
        "\nsymbols    {} at {}, kind {}\n",
        symbols.qualifier.as_deref().unwrap_or("?"),
        symbols.preferred_base.as_deref().unwrap_or("?"),
        // The kind itself, never the `Option` around it: `kind Some(Pdb)` is what a `{:?}` of
        // the field prints, and it reads as a value somebody is unsure of rather than as the
        // provider the engine reported.
        symbols
            .kind
            .as_ref()
            .map_or_else(|| "unread".to_string(), |kind| format!("{kind:?}")),
    ));
    if let Some(pdb) = &symbols.pdb {
        out.push_str(&format!(
            "           pdb {}{:X}{}\n",
            pdb.guid,
            pdb.age,
            symbols
                .symbol_file
                .as_deref()
                .map(|file| format!(" ({file})"))
                .unwrap_or_default(),
        ));
    }
    if let Some(why) = &symbols.reload_error {
        out.push_str(&format!("           the forced symbol load said: {why}\n"));
    }
    // **Every probe's own reason, not only when they all failed.** A mixed result — one type
    // answered, another query broken — showed the successes and dropped the error for as long as
    // this was inside a "did any answer" branch, which is the shape review round 8 of #399 found on
    // the same report one level up.
    let answered = symbols
        .type_probes
        .iter()
        .filter(|probe| probe.type_id.is_some())
        .count();
    if !symbols.type_probes.is_empty() {
        out.push_str(&format!(
            "           {} of {} type probe(s) answered; a public PDB carrying no type records is \
             what this gate measured, and a reason that is not 'type not found' is a query that \
             could not run rather than a PDB without types\n",
            answered,
            symbols.type_probes.len()
        ));
        for probe in &symbols.type_probes {
            match (&probe.type_id, &probe.refused) {
                (Some(id), _) => {
                    out.push_str(&format!("           {}: type id {id}\n", probe.name))
                }
                (None, Some(why)) => out.push_str(&format!("           {}: {why}\n", probe.name)),
                (None, None) => out.push_str(&format!(
                    "           {}: no answer and no reason recorded\n",
                    probe.name
                )),
            }
        }
    }
    for landmark in &symbols.landmarks {
        out.push_str(&format!(
            "landmark   {} {} -> {}{}\n",
            landmark.name,
            landmark.rva.as_deref().unwrap_or("rva unknown"),
            landmark.from_symbols.as_deref().unwrap_or("unresolved"),
            match landmark.agrees {
                Some(true) => format!(": agrees with the decode's {}", landmark.from_decode),
                Some(false) => format!(
                    ": DISAGREES with the decode's {} — the names and the walk are not about the \
                     same image",
                    landmark.from_decode
                ),
                None => String::new(),
            },
        ));
        if let Some(named) = &landmark.named_by_decode {
            out.push_str(&format!(
                "           the engine names {} {named}\n",
                landmark.from_decode
            ));
        }
        if let Some(detail) = &landmark.detail {
            out.push_str(&format!("           {detail}\n"));
        }
    }
    out
}

fn show<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "unread".to_string(), |v| v.to_string())
}

/// The loader list, rendered from the value for [`render`]'s reason.
pub(crate) fn render_modules(modules: &structured::SecureKernelModules) -> String {
    let mut out = format!(
        "{} entr(ies) from SkLoadedModuleList at {}, complete {}, {} name(s) unreadable\n",
        modules.modules.len(),
        modules.head,
        modules.complete,
        modules.names_unreadable
    );
    if let Some(why) = &modules.incomplete {
        out.push_str(&format!("this is not the whole list: {why}\n"));
    }
    for module in &modules.modules {
        out.push_str(&format!(
            "{}  {:>10}  {}\n",
            module.base.as_deref().unwrap_or("                 ?"),
            module
                .size_of_image
                .map(|size| format!("{size:#x}"))
                .unwrap_or_else(|| "?".into()),
            match (&module.name, &module.name_unreadable, &module.unreadable) {
                (Some(name), _, _) if !name.is_empty() => structured::renderable(name).into_owned(),
                (_, Some(why), _) => format!("<name unreadable: {why}>"),
                (_, _, Some(why)) => format!("<{why}>"),
                _ => "<unnamed>".to_string(),
            }
        ));
    }
    out
}

/// One read, rendered from the value.
pub(crate) fn render_read(read: &structured::SecureKernelRead) -> String {
    format!(
        "{} byte(s) of VTL1 at {} (physical {}){}\n{}\n",
        read.read_size,
        read.address,
        read.gpa,
        read.symbol
            .as_deref()
            .map(|symbol| format!(", {symbol}"))
            .unwrap_or_default(),
        read.data
    )
}

/// One symbol, rendered from the value.
pub(crate) fn render_symbol(symbol: &structured::SecureKernelSymbol) -> String {
    format!(
        "{} at {} (rva {}, {} at the image's own base){}\n",
        symbol.symbol,
        symbol.address,
        symbol.rva,
        symbol.engine_address,
        match symbol.displacement {
            // Zero is the only displacement that says the address *is* the symbol: the engine
            // answers with the nearest preceding name at any address in the module, so saying so
            // is the difference between a hit and a miss dressed as one.
            Some(0) => ", which is exactly that address".to_string(),
            Some(by) => format!(", {by:#x} byte(s) past the symbol's own address"),
            None => String::new(),
        }
    )
}

#[cfg(test)]
mod tests {
    //! Everything here is a **value**, and none of it opens a capture or an engine.
    //!
    //! That is the point rather than a convenience: the two halves this module renders — the decode
    //! and the symbols — are produced on a bench with a VBS guest, an SDK and a symbol store, so a
    //! test that needed one would run nowhere. What is testable without them is the part that has
    //! actually been wrong before: whether a rendering says what the value says.

    use super::*;

    /// A report with nothing in it, to be filled in by each test with the one thing it is about.
    fn report() -> structured::SecureKernelReport {
        structured::SecureKernelReport {
            capture: vec![r"D:\Hyper-V\Snapshots\test.vmrs".into()],
            provider: structured::SkProvider {
                kit_version: "10.0.26100.0".into(),
                dll: r"C:\kits\vmsavedstatedumpprovider.dll".into(),
            },
            identified_against: structured::SkImageOnDisk {
                path: r"C:\Windows\System32\securekernel.exe".into(),
                file_size: 1_385_944,
                sections: 18,
                timestamp: 0x94DE_D27F,
                size_of_image: 0x175000,
            },
            form: structured::SkCaptureForm::Vmrs,
            vp: 0,
            vtl: 1,
            guest: structured::SkGuest {
                vp_count: Some(2),
                partition_vtls: Some("0x3".into()),
                vp_vtls: Some("0x3".into()),
                active_vtl: Some(0),
                architecture: Some(2),
                unanswered: Vec::new(),
            },
            not_walkable: None,
            decode: None,
            symbols: structured::SkSymbolHalf {
                state: structured::SkSymbolState::NotRequested,
                refusal: None,
                qualifier: None,
                preferred_base: None,
                kind: None,
                pdb: None,
                symbol_file: None,
                reload_error: None,
                type_probes: Vec::new(),
                landmarks: Vec::new(),
            },
        }
    }

    fn decode() -> structured::SkDecode {
        structured::SkDecode {
            root: structured::addr(0x1_0759_3000),
            root_page: Some(structured::SkRootPage {
                present_entries: 29,
                non_zero_bytes: 139,
                self_map_indexes: vec![309],
                first_present_index: Some(1),
                upper_half_present: 27,
            }),
            root_page_unreadable: None,
            walk: structured::SkWalk {
                leaf_mappings: 16_437,
                mapped_pages: 4_545,
                table_reads: 179,
                tables_decoded: 215,
                alias_prefixes_skipped: 7_803,
                malformed_entries: 0,
                unreadable_tables: 0,
                complete: true,
                incomplete: None,
            },
            scan: structured::SkScan {
                pages_scanned: 16_437,
                pages_unreadable: 0,
                pe_headers_found: 7,
                matching_the_image: 1,
                capped: false,
            },
            image: Some(structured::SkImage {
                base: structured::addr(0xFFFF_F807_0EDA_9000),
                gpa: structured::addr(0xCD0000),
                size_of_image: 0x175000,
                timestamp: 0x94DE_D27F,
                gathered_bytes: 1_527_808,
                pages_unreadable: 0,
                block: structured::addr(0xFFFF_F807_0EED_C5E0),
                block_size: 0x3A0,
                module_list: structured::addr(0xFFFF_F807_0EED_0770),
                modules: 6,
            }),
            rejected: Vec::new(),
            cross_check: None,
            reads: structured::SkReads {
                attempted: 18_253,
                failed: 0,
                refused: 0,
                bytes: 74_764_288,
            },
        }
    }

    /// The text is rendered **from** the typed answer, so a figure in one is the figure in the
    /// other — which is the property that stops a reader quoting a number the values disagree with.
    #[test]
    fn the_report_prints_the_values_it_was_built_from() {
        let mut report = report();
        report.decode = Some(decode());
        let text = render(&report);
        let decode = report.decode.as_ref().expect("the decode is there");
        for figure in [
            decode.root.as_str(),
            decode.image.as_ref().unwrap().base.as_str(),
            decode.image.as_ref().unwrap().block.as_str(),
            decode.image.as_ref().unwrap().module_list.as_str(),
        ] {
            assert!(
                text.contains(figure),
                "the report does not print {figure}:\n{text}"
            );
        }
        assert!(text.contains("18253 attempted, 0 failed"), "{text}");
        assert!(text.contains("16437 leaf mapping(s)"), "{text}");
    }

    /// A capture with no VTL1 is the **answer** on a VBS-off guest, so it reads as one rather than
    /// as a decode with everything zero — and the reason the provider gave is in it.
    #[test]
    fn a_capture_with_no_vtl1_reports_the_refusal_rather_than_an_empty_decode() {
        let mut report = report();
        report.not_walkable = Some(
            "ForceActiveVirtualTrustLevel(vp0, vtl1) failed: 0xC0370509 \
             (VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED)"
                .into(),
        );
        let text = render(&report);
        assert!(text.contains("not walkable: "), "{text}");
        assert!(text.contains("0xC0370509"), "{text}");
        assert!(
            !text.contains("leaf mapping(s)"),
            "a refusal must not print a walk it never did:\n{text}"
        );
    }

    /// An incomplete walk says **why**, because the two ways it can be incomplete need different
    /// answers: a budget is ours to raise, and unreadable tables are the source's.
    #[test]
    fn an_incomplete_walk_says_which_of_the_two_reasons_it_was() {
        for (why, expected) in [
            (
                sk::Incomplete::Budget(sk::Budget::TableReads(200_000)),
                "budget of 200000 table read(s)",
            ),
            (
                sk::Incomplete::UnreadableTables(4),
                "4 page table(s) could not be read",
            ),
        ] {
            let mut decode = decode();
            decode.walk.complete = false;
            decode.walk.incomplete = Some(walk_incomplete(why));
            let mut report = report();
            report.decode = Some(decode);
            let text = render(&report);
            assert!(
                text.contains(expected),
                "an incomplete walk did not say {expected}:\n{text}"
            );
        }
    }

    /// **A probe that failed is reported even when another answered.** Round 8 of #399's review
    /// found this exact shape one level up, in `--sk-inspect`: the reasons were printed only when
    /// *every* probe failed, so a mixed result — one type answered, another query broken — showed
    /// the successes and dropped the error. Every probe against this bench's PDB fails, so the
    /// mixed branch is the one no run here reaches.
    #[test]
    fn a_failed_type_probe_is_reported_beside_one_that_answered() {
        let mut report = report();
        report.symbols.state = structured::SkSymbolState::Loaded;
        report.symbols.qualifier = Some("securekernel".into());
        report.symbols.preferred_base = Some(structured::addr(0x1_4000_0000));
        report.symbols.type_probes = vec![
            structured::SkTypeProbe {
                name: "_LIST_ENTRY".into(),
                type_id: Some(42),
                refused: None,
            },
            structured::SkTypeProbe {
                name: "_KLDR_DATA_TABLE_ENTRY".into(),
                type_id: None,
                refused: Some("No such interface supported (0x80004002)".into()),
            },
        ];
        let text = render(&report);
        assert!(text.contains("type id 42"), "{text}");
        assert!(
            text.contains("No such interface supported (0x80004002)"),
            "a probe that failed beside one that answered was dropped:\n{text}"
        );
    }

    /// A landmark the two routes disagree about must not read like one they agree on — this is the
    /// one line of this report that says the decode and the symbols are about the same image.
    #[test]
    fn a_landmark_that_disagrees_is_not_rendered_as_agreement() {
        let mut report = report();
        report.symbols.state = structured::SkSymbolState::Loaded;
        report.symbols.landmarks = vec![structured::SkLandmark {
            name: "KdDebuggerDataBlock".into(),
            from_decode: structured::addr(0xFFFF_F807_0EED_C5E0),
            from_symbols: Some(structured::addr(0xFFFF_F807_0EED_C000)),
            rva: Some("0x1335e0".into()),
            agrees: Some(false),
            named_by_decode: None,
            detail: None,
        }];
        let text = render(&report);
        assert!(text.contains("DISAGREES"), "{text}");
        assert!(
            !text.contains(": agrees with"),
            "a disagreement rendered as agreement:\n{text}"
        );
    }

    /// A symbol resolved **at** an address and one resolved near it are different answers, and the
    /// displacement is the only thing that separates them.
    #[test]
    fn a_displacement_says_whether_the_address_is_the_symbol() {
        let at = structured::SecureKernelSymbol {
            symbol: "securekernel!SkLoadedModuleList".into(),
            address: structured::addr(0xFFFF_F807_0EED_0770),
            rva: "0x127770".into(),
            engine_address: structured::addr(0x1_4012_7770),
            displacement: Some(0),
        };
        let near = structured::SecureKernelSymbol {
            displacement: Some(0x18),
            ..at.clone()
        };
        assert!(render_symbol(&at).contains("is exactly that address"));
        assert!(render_symbol(&near).contains("0x18 byte(s) past"));
        assert!(!render_symbol(&near).contains("is exactly that address"));
    }

    /// **The cross-check has three answers and the report must not render two of them alike.**
    ///
    /// The one that matters is the middle: two routes naming different heads says the decode's own
    /// witnesses are not about one structure, and until review it was rendered as agreement — the
    /// value said `true` for any successful search (CodeRabbit, #401). `None` is neither: nothing
    /// was found to compare.
    #[test]
    fn the_cross_check_renders_agreement_disagreement_and_neither_apart() {
        let cross = |agrees| structured::SkCrossCheck {
            agrees,
            entry: Some(structured::addr(0xFFFF_B700_0220_20C0)),
            head: Some(structured::addr(0xFFFF_F807_0EED_0770)),
            pages_scanned: 1249,
            pages_unreadable: 0,
            detail: agrees
                .is_none()
                .then(|| "the structural route found no loader entry for this base".to_string()),
        };
        let rendered = |agrees| {
            let mut decode = decode();
            decode.cross_check = Some(cross(agrees));
            let mut report = report();
            report.decode = Some(decode);
            render(&report)
        };

        let agrees = rendered(Some(true));
        assert!(agrees.contains("agrees with the block"), "{agrees}");
        assert!(!agrees.contains("DISAGREES"), "{agrees}");

        let disagrees = rendered(Some(false));
        assert!(
            disagrees.contains("DISAGREES with the block"),
            "a disagreement rendered as anything softer is the one reading this line exists to \
             prevent:\n{disagrees}"
        );
        assert!(
            !disagrees.contains("route agrees"),
            "one line must not say both:\n{disagrees}"
        );

        let neither = rendered(None);
        assert!(neither.contains("no loader entry"), "{neither}");
        assert!(
            !neither.contains("agrees with the block") && !neither.contains("DISAGREES"),
            "a search that found nothing is not a verdict either way:\n{neither}"
        );
    }

    /// The read bound, which is about the **answer** rather than the read: a capture is a file and
    /// the bytes are cheap, where the hex a caller pays for is twice the size again.
    #[test]
    fn a_read_is_bounded_and_says_so() {
        assert!(readable(1).is_ok());
        assert!(readable(MAX_READ).is_ok());
        let refused = readable(MAX_READ + 1).expect_err("a read past the cap is refused");
        assert!(refused.contains(&MAX_READ.to_string()), "{refused}");
        assert!(
            readable(0).is_err(),
            "a zero-byte read is a caller who meant something else"
        );
    }

    /// An entry whose **name** could not be read and one whose **record** could not be read are
    /// different failures, and neither may print as an entry with no name — a list that quietly
    /// dropped names could be called complete while omitting them.
    #[test]
    fn an_unreadable_module_says_which_half_it_could_not_read() {
        let modules = structured::SecureKernelModules {
            head: structured::addr(0xFFFF_F807_0EED_0770),
            modules: vec![
                structured::SkModule {
                    entry: structured::addr(0xFFFF_B700_0202_00C0),
                    name: None,
                    name_unreadable: Some("its BaseDllName buffer could not be read".into()),
                    base: Some(structured::addr(0xFFFF_F807_0EDA_9000)),
                    size_of_image: Some(0x175000),
                    unreadable: None,
                },
                structured::SkModule {
                    entry: structured::addr(0xFFFF_B700_0202_0100),
                    name: None,
                    name_unreadable: None,
                    base: None,
                    size_of_image: None,
                    unreadable: Some("the loader record itself could not be read".into()),
                },
            ],
            complete: false,
            incomplete: Some("the walk stopped at its 32-entry limit".into()),
            names_unreadable: 1,
        };
        let text = render_modules(&modules);
        assert!(text.contains("name unreadable"), "{text}");
        assert!(text.contains("the loader record itself"), "{text}");
        assert!(
            text.contains("this is not the whole list"),
            "an incomplete list read as a short one:\n{text}"
        );
    }
}
