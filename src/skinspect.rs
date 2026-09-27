//! `--sk-inspect`: read a Hyper-V capture's VTL1 and report what is in it.
//!
//! `FOLLOWUPS.md` item 103 gate **S1**'s entry point. Not a server and not an MCP tool — it reads
//! files and writes a report, like [`crate::cast`]'s renderer, and it exists before the tool
//! surface does because the surface is gate **S3** and its shape is still an open question.
//!
//! What it is *for* is the measurement: [`crate::sk`] decodes a source, and this drives it against
//! a real capture so the decode can be compared with the numbers S0's Python probe recorded for the
//! same guest. A decode layer that has only ever read its own fixtures is self-consistent and
//! unmeasured.
//!
//! # The differential, and which side the samples come from
//!
//! The provider ships its own virtual-to-physical translator
//! ([`crate::savedstate::Capture::translate`]), which is not our code. Comparing it against our
//! walk on the addresses **our walk found** would only ask whether we agree about what we found —
//! a page the walk missed is invisible to that comparison. So the sample is taken from the
//! *image's* own range instead, which comes from the PE header rather than from the walk: every
//! page of `securekernel.exe` is offered to both, and a page the provider maps that the walk does
//! not is counted as a miss on our side.

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::savedstate::{Capture, CaptureFiles, Kit, Provider, TranslateFailure};
use crate::sk::{self, Gva, Landmarks, NotWalkable, PAGE, Reader};

pub(crate) const INSPECT_FLAG: &str = "--sk-inspect";

/// Which capture to read, as **one** value.
///
/// Three independent `Option`s were the shape that let `--vm` and `--vmrs` both be given and one of
/// them silently win, which is what the two matches on them disagreeing would eventually have cost:
/// a report about a different capture than the caller named. Parsing resolves the choice once, and
/// nothing downstream has a preference to get wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CaptureSpec {
    Vm {
        name: String,
        snapshot: Option<String>,
    },
    Vmrs(PathBuf),
    /// The older pair, which is selected here and — on this bench — called by nothing.
    Pair {
        bin: PathBuf,
        vsv: PathBuf,
    },
}

/// What to read, and what to compare it against.
#[derive(Debug)]
struct Request {
    capture: CaptureSpec,
    image: PathBuf,
    kit: Option<PathBuf>,
    kit_version: Option<String>,
    vp: u32,
    vtl: u8,
    cross_check: bool,
    json: Option<PathBuf>,
}

/// Every file this run reads, and the only way to write the report.
///
/// **The write goes through the thing that holds the inputs**, so a report cannot be written without
/// the check having been made — the half-version is not expressible. That shape is the lesson from
/// S0's probe rather than caution: `--json` naming the capture truncated it and wrote the report
/// over it (round 15 there), and the guard added for it was then found to have been handed four of
/// the six input paths (round 16). Here a path becomes an input by being *added*, and additions
/// happen where the path is first known.
struct Inputs {
    paths: Vec<PathBuf>,
}

impl Inputs {
    fn new() -> Inputs {
        Inputs { paths: Vec::new() }
    }

    fn add(&mut self, path: &Path) {
        self.paths.push(path.to_path_buf());
    }

    /// Refuse an output that names any input, before anything is written.
    ///
    /// Compared by *identity* rather than by spelling: a relative path, a different case and a
    /// trailing `.\` all name the same file on Windows and would each pass a string comparison.
    fn refuse_if_output_is_an_input(&self, output: &Path) -> Result<()> {
        let target = identity(output);
        for input in &self.paths {
            // File identity first, for the hard link a path comparison cannot see; the name
            // comparison second, because the output usually does not exist yet and has no identity
            // to read. Either saying "the same file" is a refusal.
            if same_file(input, output) == Some(true) || identity(input) == target {
                bail!(
                    "--json {} names an input this run reads ({}); writing the report there would \
                     destroy it",
                    output.display(),
                    input.display()
                );
            }
        }
        Ok(())
    }

    /// Write the report, having refused every aliasing output first.
    fn write_report(&self, output: &Path, bytes: &[u8]) -> Result<()> {
        self.refuse_if_output_is_an_input(output)?;
        std::fs::write(output, bytes).with_context(|| format!("writing {}", output.display()))
    }
}

/// The file two paths share, when they both exist: NTFS's own identity for it.
///
/// **A hard link is one file under two names**, and `canonicalize` keeps both — so a `--json` naming
/// a link to the capture compares unequal to it by every path-shaped test and the write truncates
/// the shared file record. `volume_serial_number` and `file_index` are what NTFS uses to answer
/// *same file*, and `std::fs::metadata` on Windows fills both.
///
/// `None` when either path does not exist, or the platform did not supply the pair — in which case
/// [`identity`] below is the answer instead. The output usually does not exist yet, which is why
/// this cannot be the only comparison.
fn same_file(left: &Path, right: &Path) -> Option<bool> {
    Some(file_identity(left)? == file_identity(right)?)
}

/// `(volume serial, file index)` for a path that exists, which is NTFS's answer to *which file*.
///
/// Opened with no access rights at all — `CreateFileW(0, …)` is a query-only open, so this needs no
/// read permission on the file and cannot disturb whoever else has it open. `std` exposes these same
/// two numbers behind the unstable `windows_by_handle` feature, which is the only reason this is
/// FFI rather than four lines of safe code.
fn file_identity(path: &Path) -> Option<(u32, u64)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            // So a directory can be opened too: a `--json` naming one fails later anyway, but it
            // must not fail *here* and leave the comparison unanswered.
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return None;
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return None;
    }
    Some((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

/// A path reduced to something two spellings of one file agree on.
///
/// `canonicalize` for a file that exists; for one that does not — which the output usually is — the
/// parent is canonicalized and the file name appended, so a not-yet-created report in the same
/// directory as an input still compares equal to it. Falls back to the path as given, lowercased,
/// when even the parent cannot be resolved: a comparison that cannot be made must not silently
/// answer "different".
///
/// This is the **weaker** of the two tests and runs when [`same_file`] cannot answer. It compares
/// names, so it cannot see a hard link.
fn identity(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).ok().or_else(|| {
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty())?;
        let name = path.file_name()?;
        Some(std::fs::canonicalize(parent).ok()?.join(name))
    });
    resolved
        .unwrap_or_else(|| path.to_path_buf())
        .display()
        .to_string()
        .to_lowercase()
}

fn usage() -> String {
    format!(
        "usage: windbg-mcp {INSPECT_FLAG} --image <securekernel.exe> \
         (--vm <name> [--snapshot <name>] | --vmrs <path> | --bin <path> --vsv <path>) \
         [--vp <n>] [--vtl <n>] [--kit <root>] [--kit-version <ver>] [--cross-check] \
         [--json <path>]"
    )
}

fn parse(args: &[String]) -> Result<Request> {
    let (mut vm, mut snapshot, mut vmrs, mut bin, mut vsv) = (None, None, None, None, None);
    let mut request = Request {
        capture: CaptureSpec::Vmrs(PathBuf::new()),
        image: PathBuf::new(),
        kit: None,
        kit_version: None,
        vp: 0,
        vtl: 1,
        cross_check: false,
        json: None,
    };
    let mut at = 0;
    while at < args.len() {
        let flag = args[at].as_str();
        // Every flag but `--cross-check` takes a value, and a missing one must be a usage error
        // rather than the next flag being swallowed as a filename.
        let mut value = || -> Result<String> {
            at += 1;
            args.get(at)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("{flag} needs a value\n{}", usage()))
        };
        match flag {
            "--vm" => vm = Some(value()?),
            "--snapshot" => snapshot = Some(value()?),
            "--vmrs" => vmrs = Some(PathBuf::from(value()?)),
            "--bin" => bin = Some(PathBuf::from(value()?)),
            "--vsv" => vsv = Some(PathBuf::from(value()?)),
            "--image" => request.image = PathBuf::from(value()?),
            "--kit" => request.kit = Some(PathBuf::from(value()?)),
            "--kit-version" => request.kit_version = Some(value()?),
            "--vp" => request.vp = value()?.parse().context("--vp")?,
            "--vtl" => request.vtl = value()?.parse().context("--vtl")?,
            "--json" => request.json = Some(PathBuf::from(value()?)),
            "--cross-check" => {}
            other => bail!("unknown argument `{other}`\n{}", usage()),
        }
        if flag == "--cross-check" {
            request.cross_check = true;
        }
        at += 1;
    }
    if request.image.as_os_str().is_empty() {
        bail!(
            "--image is required: the decode identifies a mapping against the image on disk\n{}",
            usage()
        );
    }
    // **Exactly one** capture form, named as a set rather than resolved by precedence: giving two
    // is a caller who means something this cannot do, and picking one of them would analyse a
    // capture they did not ask for.
    let mut forms: Vec<&str> = Vec::new();
    if vm.is_some() {
        forms.push("--vm");
    }
    if vmrs.is_some() {
        forms.push("--vmrs");
    }
    if bin.is_some() || vsv.is_some() {
        forms.push("--bin/--vsv");
    }
    match forms.as_slice() {
        [] => bail!(
            "name a capture: --vm, --vmrs, or --bin with --vsv\n{}",
            usage()
        ),
        [_] => {}
        several => bail!(
            "name one capture, not {}: {}\n{}",
            several.len(),
            several.join(" and "),
            usage()
        ),
    }
    request.capture = match (vm, vmrs, bin, vsv) {
        (Some(name), _, _, _) => CaptureSpec::Vm { name, snapshot },
        (None, Some(path), _, _) => CaptureSpec::Vmrs(path),
        (None, None, Some(bin), Some(vsv)) => CaptureSpec::Pair { bin, vsv },
        // The pair is two files and one of them alone is a usage error, not a capture that fails to
        // load inside the provider.
        (None, None, bin, _) => bail!(
            "--bin and --vsv go together; {} was given without the other\n{}",
            if bin.is_some() { "--bin" } else { "--vsv" },
            usage()
        ),
    };
    if !matches!(request.capture, CaptureSpec::Vm { .. }) && request.snapshot_was_given(args) {
        bail!(
            "--snapshot names a checkpoint of a --vm, and no --vm was given\n{}",
            usage()
        );
    }
    Ok(request)
}

impl Request {
    /// Whether `--snapshot` appeared, which only means something beside `--vm`.
    ///
    /// Read off the arguments rather than kept in a field: once the capture is one value, a snapshot
    /// belonging to no VM has nowhere to live, and silently ignoring it would be the same class of
    /// defect as preferring one selector over another.
    fn snapshot_was_given(&self, args: &[String]) -> bool {
        args.iter().any(|arg| arg == "--snapshot")
    }
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let request = parse(args)?;
    let mut inputs = Inputs::new();
    inputs.add(&request.image);
    // Named before they are read, so a `--json` aliasing one is refused before the analysis rather
    // than after it — the file a `--vmrs` names is the caller's capture, and it is irreplaceable.
    match &request.capture {
        CaptureSpec::Vm { .. } => {}
        CaptureSpec::Vmrs(path) => inputs.add(path),
        CaptureSpec::Pair { bin, vsv } => {
            inputs.add(bin);
            inputs.add(vsv);
        }
    }
    if let Some(json) = &request.json {
        inputs.refuse_if_output_is_an_input(json)?;
    }
    // Before the provider is touched: a typo in `--image` must be a refusal rather than a failure
    // three minutes into a decode that has already read a capture.
    let disk = sk::DiskImage::open(&request.image).map_err(|e| anyhow::anyhow!(e))?;
    let kit = Kit::find(request.kit.as_deref(), request.kit_version.as_deref())
        .map_err(|e| anyhow::anyhow!(e))?;
    inputs.add(&kit.dll);
    inputs.add(&kit.header);
    if let Some(json) = &request.json {
        inputs.refuse_if_output_is_an_input(json)?;
    }
    println!("kit        {} ({})", kit.version, kit.dll.display());
    println!(
        "image      {} ({} bytes, {} sections, timestamp {:#010X}, SizeOfImage {:#X})",
        disk.path,
        disk.file_size,
        disk.identity.sections,
        disk.identity.timestamp,
        disk.identity.size_of_image
    );
    let provider = Provider::load(&kit).map_err(|e| anyhow::anyhow!(e))?;
    let files = match &request.capture {
        CaptureSpec::Vm { name, snapshot } => provider
            .locate(name, snapshot.as_deref())
            .map_err(|e| anyhow::anyhow!(e))?,
        CaptureSpec::Vmrs(vmrs) => CaptureFiles::vmrs(vmrs),
        CaptureSpec::Pair { bin, vsv } => CaptureFiles::pair(bin, vsv),
    };
    for path in files.paths() {
        println!("capture    {path}");
        // Hyper-V answered with these, so they were not in the list above. A `--json` naming one is
        // still a report written over a capture.
        inputs.add(Path::new(path));
    }
    if let Some(json) = &request.json {
        inputs.refuse_if_output_is_an_input(json)?;
    }
    let capture = provider
        .open(&files, request.vp, request.vtl)
        .map_err(|e| anyhow::anyhow!(e))?;
    report_capture(&capture);
    let reader = Reader::new(&capture);
    let landmarks = match sk::locate(&reader, &disk, request.cross_check) {
        Ok(landmarks) => landmarks,
        Err(why) => {
            // A refusal is an answer, and on a VBS-off guest it is *the* answer, so it prints as
            // one rather than as an error with a backtrace.
            println!("\nnot walkable: {}", refusal(&why));
            if let Some(path) = &request.json {
                inputs.write_report(
                    path,
                    &serde_json::to_vec_pretty(&serde_json::json!({
                        "capture": files.paths(),
                        "walkable": false,
                        "reason": refusal(&why),
                    }))?,
                )?;
                println!("json       {}", path.display());
            }
            return Ok(());
        }
    };
    report_landmarks(&landmarks);
    let differential = differential(|va| capture.translate(va), &landmarks);
    if let Some(sampled) = &differential {
        println!(
            "\noracle     {} page(s) of the image offered to both: {} agree, {} disagree, {} the \
             provider maps and the walk does not, {} the walk maps and the provider says nothing \
             maps, {} the provider could not answer for",
            sampled.offered,
            sampled.agree,
            sampled.disagree,
            sampled.provider_only,
            sampled.walk_only,
            sampled.provider_failed
        );
        // Every outcome, so the categories add up to `offered`. A text report that recorded a failed
        // oracle and did not print it would leave the reader subtracting — and this line shipped
        // that way once, because the edit that was supposed to add these fields silently did not
        // apply and the check was of the script's own report rather than of the file.
        if let Some((va, ours, theirs)) = sampled.disagreement {
            println!(
                "           first disagreement at {va:#X}: walk {ours:#X}, provider {theirs:#X}"
            );
        }
        if let Some((va, why)) = &sampled.first_provider_error {
            println!("           the oracle first failed at {va:#X}: {why}");
        }
    }
    if let Some(path) = &request.json {
        let json = as_json(&files, &landmarks, differential.as_ref());
        inputs.write_report(path, &serde_json::to_vec_pretty(&json)?)?;
        println!("json       {}", path.display());
    }
    Ok(())
}

fn refusal(why: &NotWalkable) -> String {
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

fn report_capture(capture: &Capture) {
    let facts = &capture.facts;
    println!(
        "capture    form {:?}, {} vp(s), partition VTLs {}, vp VTLs {}, active VTL {}, arch {}",
        capture.form,
        show(facts.vp_count),
        show_hex(facts.guest_vtls),
        show_hex(facts.vp_vtls),
        show(facts.active_vtl),
        show(facts.architecture)
    );
    for (field, detail) in &facts.unreadable {
        println!("           unreadable: {field} ({detail})");
    }
}

fn report_landmarks(landmarks: &Landmarks) {
    let walk = &landmarks.walk;
    println!(
        "\nroot       {:#X} (read from the capture, never remembered)",
        landmarks.root.0
    );
    match &landmarks.root_page {
        Ok(page) => println!(
            "rootpage   {} present entr(ies), {} non-zero byte(s), self-map at {:?}, first present \
             index {}, {} in the upper half",
            page.present_entries,
            page.nonzero_bytes,
            page.self_map_indexes,
            page.first_present_index
                .map_or("none".to_string(), |index| index.to_string()),
            page.upper_half_present
        ),
        // Not folded into the walk's own result: a root page that could not be read and a walk that
        // found nothing are different facts, and only one of them is about the guest.
        Err(why) => println!("rootpage   unreadable: {why:?}"),
    }
    println!(
        "walk       {} leaf mapping(s) over {} distinct page(s); {} table read(s), {} decode(s), \
         {} alias prefix(es) not expanded, {} malformed entr(ies), {} unreadable table(s)",
        walk.leaves,
        landmarks.mapped_pages,
        walk.table_reads,
        walk.tables_decoded,
        walk.alias_prefixes_skipped,
        walk.malformed_entries,
        walk.unreadable_tables
    );
    println!(
        "           complete: {}{}",
        walk.complete(),
        match &walk.incomplete {
            Some(why) => format!(" ({why:?})"),
            None => String::new(),
        }
    );
    println!(
        "scan       {} page(s) scanned, {} unreadable, {} PE header(s) found, {} matching the \
         image on disk{}",
        landmarks.scan.scanned,
        landmarks.scan.unreadable,
        landmarks.candidates.len(),
        landmarks
            .candidates
            .iter()
            .filter(|c| c.matches_disk)
            .count(),
        if landmarks.scan.capped {
            " (capped)"
        } else {
            ""
        }
    );
    for attempt in &landmarks.attempts {
        println!(
            "candidate  {:#X} (gpa {:#X}): {} KDBG hit(s), {} image page(s) unreadable, accepted {}",
            attempt.candidate.va.0,
            attempt.candidate.gpa.0,
            attempt.hits.len(),
            attempt.image_pages_unreadable,
            attempt.accepted
        );
        for (va, why) in &attempt.rejected {
            println!("           rejected {va:#X}: {why:?}");
        }
    }
    match &landmarks.identified {
        None => println!("\nidentified none"),
        Some(found) => {
            let base = found.candidate.va.0;
            println!(
                "\nidentified {:#X} (gpa {:#X})",
                base, found.candidate.gpa.0
            );
            println!(
                "block      {:#X}  = base +{:#X}, Size {:#X}, KernBase {:#X}",
                found.block.va.0, found.block.image_offset, found.block.size, found.block.kern_base
            );
            println!(
                "modulelist {:#X}  = base +{:#X}",
                found.modules.head,
                found.modules.head.0.wrapping_sub(base)
            );
            println!(
                "image      {} byte(s) gathered, {} page(s) unreadable",
                found.image.bytes.len(),
                found.image.missing.len()
            );
            println!(
                "modules    {} entr(ies), complete {}, {} name(s) unreadable: {}",
                found.modules.entries.len(),
                found.modules.complete(),
                found.modules.names_unreadable,
                found.modules.names().join(", ")
            );
            for entry in &found.modules.entries {
                match &entry.record {
                    None => println!("           {:#X}: unreadable", entry.va.0),
                    Some(record) => println!(
                        "           {:#X} size {:#X}  {}",
                        record.dll_base,
                        record.size_of_image,
                        match &record.name {
                            Ok(name) if name.is_empty() => "(no name)".to_string(),
                            Ok(name) => name.clone(),
                            Err(why) => format!("(name unreadable: {why:?})"),
                        }
                    ),
                }
            }
            match &landmarks.cross_check {
                Some(Ok(cross)) => {
                    let agrees = cross.head.0 == found.block.ps_loaded_module_list;
                    println!(
                        "crosscheck entry {:#X} -> head {:#X}: {} the block ({} page(s) scanned, {} \
                         unreadable)",
                        cross.entry.0,
                        cross.head.0,
                        if agrees {
                            "agrees with"
                        } else {
                            "DISAGREES with"
                        },
                        cross.pages_scanned,
                        cross.pages_unreadable
                    );
                }
                // A miss is not a disagreement, and a **capped** miss is not even a search: saying
                // which is why the budget is reported rather than absorbed.
                Some(Err(miss)) => println!(
                    "crosscheck found no loader entry naming the base ({} page(s) scanned, {} \
                     unreadable{})",
                    miss.pages_scanned,
                    miss.pages_unreadable,
                    if miss.capped {
                        ", stopped at the page budget — this is not a search that looked everywhere"
                    } else {
                        ""
                    }
                ),
                None => {}
            }
        }
    }
    let reads = &landmarks.reads;
    println!(
        "\nreads      {} attempted, {} failed ({} refused), {} byte(s)",
        reads.attempted, reads.failed, reads.refused, reads.bytes
    );
    if landmarks.identified.is_none() && reads.failed > 0 {
        println!(
            "           this run identified nothing while {} read(s) failed, so its negative has \
             not been earned",
            reads.failed
        );
    }
}

/// The walk against the provider's own translator, sampled from the image's range.
struct Differential {
    offered: u64,
    agree: u64,
    disagree: u64,
    provider_only: u64,
    walk_only: u64,
    /// Addresses the oracle could not answer for **at all**, which is not a mapping difference and
    /// must never be counted as one: an unavailable oracle produces no evidence about the walk.
    provider_failed: u64,
    first_provider_error: Option<(u64, String)>,
    disagreement: Option<(u64, u64, u64)>,
}

/// What one address says about the walk and the oracle together.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Agree,
    Disagree {
        ours: u64,
        theirs: u64,
    },
    ProviderOnly,
    WalkOnly,
    /// The oracle could not answer. **Its own outcome**, because an oracle that failed is not a
    /// walk that was wrong — this arm is what the two `None`s used to be folded into.
    ProviderFailed(String),
    NeitherMaps,
}

/// Classify one address. The **only** place the two answers are compared.
///
/// Extracted so the rule is testable on its own line: the defect this replaced was in the
/// comparison itself, and a test that drove a whole capture could not reach it.
fn classify(ours: Option<u64>, theirs: Result<sk::Gpa, TranslateFailure>) -> Outcome {
    match (ours, theirs) {
        (_, Err(TranslateFailure::Failed(why))) => Outcome::ProviderFailed(why),
        (Some(ours), Ok(theirs)) if ours == theirs.0 => Outcome::Agree,
        (Some(ours), Ok(theirs)) => Outcome::Disagree {
            ours,
            theirs: theirs.0,
        },
        (None, Ok(_)) => Outcome::ProviderOnly,
        (Some(_), Err(TranslateFailure::NotMapped)) => Outcome::WalkOnly,
        (None, Err(TranslateFailure::NotMapped)) => Outcome::NeitherMaps,
    }
}

/// The walk against a translator, page by page over the identified image's own range.
///
/// Takes the translator as a parameter rather than a [`Capture`] so the accounting can be tested
/// with no capture, no provider and no VM — including the case that matters most here, an oracle
/// that fails.
fn differential(
    translate: impl Fn(u64) -> Result<sk::Gpa, TranslateFailure>,
    landmarks: &Landmarks,
) -> Option<Differential> {
    let found = landmarks.identified.as_ref()?;
    let base = found.candidate.va.0;
    let size = found.candidate.identity.size_of_image as u64;
    let mut result = Differential {
        offered: 0,
        agree: 0,
        disagree: 0,
        provider_only: 0,
        walk_only: 0,
        provider_failed: 0,
        first_provider_error: None,
        disagreement: None,
    };
    let mut offset = 0u64;
    while offset < size {
        // `wrapping_add`, like `Gva::offset` and for the same reason: `base` is an upper-half
        // canonical address and `size` is a `SizeOfImage` read out of the guest, so a crafted header
        // puts this over the top of the address space and panics a debug build.
        let va = base.wrapping_add(offset);
        offset += PAGE;
        result.offered += 1;
        let ours = landmarks.space.translate(Gva(va)).map(|gpa| gpa.0);
        // One classification site, so the counting below cannot disagree with the rule above.
        match classify(ours, translate(va)) {
            Outcome::Agree => result.agree += 1,
            Outcome::Disagree { ours, theirs } => {
                result.disagree += 1;
                result.disagreement = result.disagreement.or(Some((va, ours, theirs)));
            }
            Outcome::ProviderOnly => result.provider_only += 1,
            Outcome::WalkOnly => result.walk_only += 1,
            Outcome::ProviderFailed(why) => {
                result.provider_failed += 1;
                result.first_provider_error =
                    result.first_provider_error.take().or(Some((va, why)));
            }
            Outcome::NeitherMaps => {}
        }
    }
    Some(result)
}

fn as_json(
    files: &CaptureFiles,
    landmarks: &Landmarks,
    differential: Option<&Differential>,
) -> serde_json::Value {
    let identified = landmarks.identified.as_ref().map(|found| {
        let base = found.candidate.va.0;
        serde_json::json!({
            "base_va": format!("{base:#X}"),
            "base_gpa": format!("{:#X}", found.candidate.gpa.0),
            "kdbg_va": format!("{:#X}", found.block.va.0),
            "kdbg_image_offset": format!("{:#X}", found.block.image_offset),
            "kdbg_size": format!("{:#X}", found.block.size),
            "module_list_va": format!("{:#X}", found.block.ps_loaded_module_list),
            "module_list_image_offset":
                format!("{:#X}", found.block.ps_loaded_module_list.wrapping_sub(base)),
            "modules": found.modules.entries.iter().map(|entry| match &entry.record {
                None => serde_json::json!({ "entry_va": format!("{:#X}", entry.va.0),
                                            "unreadable": true }),
                Some(record) => serde_json::json!({
                    "entry_va": format!("{:#X}", entry.va.0),
                    "dll_base": format!("{:#X}", record.dll_base),
                    "size_of_image": format!("{:#X}", record.size_of_image),
                    "name": record.name.as_ref().ok(),
                    "name_error": record.name.as_ref().err().map(|why| format!("{why:?}")),
                }),
            }).collect::<Vec<_>>(),
            "module_list_complete": found.modules.complete(),
            "names_unreadable": found.modules.names_unreadable,
        })
    });
    serde_json::json!({
        "capture": files.paths(),
        "walkable": true,
        "root": format!("{:#X}", landmarks.root.0),
        "root_page": landmarks.root_page.as_ref().ok().map(|page| serde_json::json!({
            "present_entries": page.present_entries,
            "nonzero_bytes": page.nonzero_bytes,
            "self_map_indexes": page.self_map_indexes,
            "first_present_index": page.first_present_index,
            "upper_half_present": page.upper_half_present,
        })),
        "walk": {
            "leaves": landmarks.walk.leaves,
            "mapped_pages": landmarks.mapped_pages,
            "table_reads": landmarks.walk.table_reads,
            "tables_decoded": landmarks.walk.tables_decoded,
            "alias_prefixes_skipped": landmarks.walk.alias_prefixes_skipped,
            "malformed_entries": landmarks.walk.malformed_entries,
            "unreadable_tables": landmarks.walk.unreadable_tables,
            "complete": landmarks.walk.complete(),
            "incomplete": landmarks.walk.incomplete.map(|why| format!("{why:?}")),
        },
        "scan": {
            "scanned": landmarks.scan.scanned,
            "unreadable": landmarks.scan.unreadable,
            "capped": landmarks.scan.capped,
            "pe_headers": landmarks.candidates.len(),
            "matching_disk": landmarks.candidates.iter().filter(|c| c.matches_disk).count(),
        },
        "identified": identified,
        "cross_check": landmarks.cross_check.as_ref().map(|cross| match cross {
            Ok(cross) => serde_json::json!({
                "found": true,
                "entry_va": format!("{:#X}", cross.entry.0),
                "head_va": format!("{:#X}", cross.head.0),
                "pages_scanned": cross.pages_scanned,
                "pages_unreadable": cross.pages_unreadable,
            }),
            Err(miss) => serde_json::json!({
                "found": false,
                "pages_scanned": miss.pages_scanned,
                "pages_unreadable": miss.pages_unreadable,
                "capped": miss.capped,
            }),
        }),
        "oracle": differential.map(|d| serde_json::json!({
            "offered": d.offered,
            "agree": d.agree,
            "disagree": d.disagree,
            "provider_only": d.provider_only,
            "walk_only": d.walk_only,
            "provider_failed": d.provider_failed,
            "first_provider_error": d.first_provider_error.as_ref().map(|(va, why)| {
                serde_json::json!({ "va": format!("{va:#X}"), "reason": why })
            }),
            "first_disagreement": d.disagreement.map(|(va, ours, theirs)| serde_json::json!({
                "va": format!("{va:#X}"),
                "walk": format!("{ours:#X}"),
                "provider": format!("{theirs:#X}"),
            })),
        })),
        "reads": {
            "attempted": landmarks.reads.attempted,
            "failed": landmarks.reads.failed,
            "refused": landmarks.reads.refused,
            "bytes": landmarks.reads.bytes,
        },
    })
}

fn show<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "?".into())
}

fn show_hex(value: Option<u32>) -> String {
    value
        .map(|v| format!("{v:#X}"))
        .unwrap_or_else(|| "?".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flag_with_no_value_is_a_usage_error_rather_than_eating_the_next_flag() {
        let args: Vec<String> = ["--image", "sk.exe", "--vm"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let error = parse(&args).expect_err("--vm has no value");
        assert!(error.to_string().contains("--vm needs a value"), "{error}");
    }

    #[test]
    fn a_capture_has_to_be_named() {
        let args: Vec<String> = ["--image", "sk.exe"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let error = parse(&args).expect_err("no capture named");
        assert!(error.to_string().contains("name a capture"), "{error}");
    }

    #[test]
    fn the_image_is_required_because_identification_is_against_it() {
        let args: Vec<String> = ["--vm", "Lab"].iter().map(|s| (*s).to_string()).collect();
        let error = parse(&args).expect_err("no image named");
        assert!(error.to_string().contains("--image is required"), "{error}");
    }

    #[test]
    fn two_capture_selectors_are_a_usage_error_rather_than_one_of_them_winning() {
        // `--vm` and `--vmrs` together used to resolve by the order of a match arm, so the caller
        // got a report about a capture they had not named.
        let args: Vec<String> = ["--image", "sk.exe", "--vm", "Lab", "--vmrs", "c.vmrs"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let error = parse(&args).expect_err("two forms");
        assert!(
            error.to_string().contains("name one capture, not 2"),
            "{error}"
        );
        assert!(error.to_string().contains("--vm and --vmrs"), "{error}");
    }

    #[test]
    fn a_snapshot_with_no_vm_is_refused_rather_than_ignored() {
        let args: Vec<String> = ["--image", "sk.exe", "--vmrs", "c.vmrs", "--snapshot", "S0"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let error = parse(&args).expect_err("a snapshot belongs to a vm");
        assert!(
            error.to_string().contains("--snapshot names a checkpoint"),
            "{error}"
        );
    }

    #[test]
    fn a_report_refuses_to_be_written_over_an_input_however_the_path_is_spelled() {
        // S0's probe truncated a capture this way and wrote the report over it, and the guard added
        // for it was then found to have been given four of the six input paths.
        let dir = std::env::temp_dir().join("windbg-mcp-sk-inspect-alias");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let capture = dir.join("capture.vmrs");
        std::fs::write(&capture, b"not really a capture").expect("write input");
        let mut inputs = Inputs::new();
        inputs.add(&capture);

        assert!(
            inputs.refuse_if_output_is_an_input(&capture).is_err(),
            "the same path"
        );
        // The same file under a different spelling: case, and a `.\` hop through the directory.
        let shouty = dir.join("CAPTURE.VMRS");
        assert!(
            inputs.refuse_if_output_is_an_input(&shouty).is_err(),
            "case"
        );
        let hopped = dir.join(".").join("capture.vmrs");
        assert!(
            inputs.refuse_if_output_is_an_input(&hopped).is_err(),
            "a . component"
        );
        // And the **write** refuses it too, which is the line the shipped defect was on: a guard
        // that exists and is not called is the same file destroyed.
        assert!(
            inputs.write_report(&capture, b"{}").is_err(),
            "the write must refuse it"
        );
        assert_eq!(
            std::fs::read(&capture).expect("input survives the refused write"),
            b"not really a capture"
        );
        // And a report beside it is fine, including one that does not exist yet.
        let report = dir.join("report.json");
        inputs
            .refuse_if_output_is_an_input(&report)
            .expect("a new file beside the input");
        inputs.write_report(&report, b"{}").expect("write");
        assert_eq!(
            std::fs::read(&capture).expect("input survives"),
            b"not really a capture",
            "the input was modified"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_hard_link_to_an_input_is_the_input() {
        // `canonicalize` keeps both names of one file, so every path-shaped comparison says
        // "different" and the write truncates the shared file record. NTFS's own identity —
        // volume serial plus file index — is what answers this.
        let dir = std::env::temp_dir().join("windbg-mcp-sk-inspect-hardlink");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let capture = dir.join("capture.vmrs");
        let link = dir.join("report.json");
        std::fs::write(&capture, b"not really a capture").expect("write input");
        let _ = std::fs::remove_file(&link);
        if std::fs::hard_link(&capture, &link).is_err() {
            // A volume without hard links, or a sandbox that refuses one. Skipped rather than
            // passed: a test that silently proves nothing is worse than one that says so.
            eprintln!("SKIPPED: this filesystem would not make a hard link");
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        assert_eq!(
            same_file(&capture, &link),
            Some(true),
            "the two names are one file"
        );
        let mut inputs = Inputs::new();
        inputs.add(&capture);
        assert!(
            inputs.write_report(&link, b"{}").is_err(),
            "a hard link to the capture is the capture"
        );
        assert_eq!(
            std::fs::read(&capture).expect("input survives"),
            b"not really a capture"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_oracle_that_could_not_answer_is_not_a_mapping_disagreement() {
        // The defect: `.ok()` turned a failed `GuestVirtualAddressToPhysicalAddress` into "no
        // mapping", so a page the walk *did* map was counted as the walk and the provider
        // disagreeing — evidence manufactured out of a call that produced none.
        let failed = classify(
            Some(0x1000),
            Err(TranslateFailure::Failed("hresult 0x80070057".into())),
        );
        assert_eq!(failed, Outcome::ProviderFailed("hresult 0x80070057".into()));
        // And it must not become one when the walk has no mapping either.
        assert!(matches!(
            classify(
                None,
                Err(TranslateFailure::Failed("hresult 0x80004005".into()))
            ),
            Outcome::ProviderFailed(_)
        ));
        // The oracle answering "nothing maps that" is a different outcome and stays one.
        assert_eq!(
            classify(Some(0x1000), Err(TranslateFailure::NotMapped)),
            Outcome::WalkOnly
        );
        assert_eq!(
            classify(None, Err(TranslateFailure::NotMapped)),
            Outcome::NeitherMaps
        );
        assert_eq!(classify(Some(0x2000), Ok(sk::Gpa(0x2000))), Outcome::Agree);
        assert_eq!(
            classify(Some(0x2000), Ok(sk::Gpa(0x3000))),
            Outcome::Disagree {
                ours: 0x2000,
                theirs: 0x3000
            }
        );
        assert_eq!(classify(None, Ok(sk::Gpa(0x4000))), Outcome::ProviderOnly);
    }

    #[test]
    fn a_bin_without_a_vsv_is_not_a_capture() {
        // The older pair is two files, and one of them alone is a usage error rather than a load
        // that fails inside the provider.
        let args: Vec<String> = ["--image", "sk.exe", "--bin"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert!(parse(&args).is_err());
        let args: Vec<String> = ["--image", "sk.exe", "--bin", "a.bin"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let error = parse(&args).expect_err("--vsv missing");
        // It names the missing half rather than the generic "name a capture" it used to: with the
        // capture resolved to one value, half a pair is a distinguishable mistake.
        assert!(
            error.to_string().contains("--bin and --vsv go together")
                && error.to_string().contains("--bin was given"),
            "{error}"
        );
        // And the same the other way round.
        let args: Vec<String> = ["--image", "sk.exe", "--vsv", "a.vsv"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let error = parse(&args).expect_err("--bin missing");
        assert!(error.to_string().contains("--vsv was given"), "{error}");
    }
}
