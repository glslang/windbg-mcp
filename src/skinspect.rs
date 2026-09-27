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

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::savedstate::{Capture, CaptureFiles, Kit, Provider};
use crate::sk::{self, Gva, Landmarks, NotWalkable, PAGE, Reader};

pub(crate) const INSPECT_FLAG: &str = "--sk-inspect";

/// What to read, and what to compare it against.
#[derive(Debug)]
struct Request {
    vm: Option<String>,
    snapshot: Option<String>,
    vmrs: Option<PathBuf>,
    bin: Option<PathBuf>,
    vsv: Option<PathBuf>,
    image: PathBuf,
    kit: Option<PathBuf>,
    kit_version: Option<String>,
    vp: u32,
    vtl: u8,
    cross_check: bool,
    json: Option<PathBuf>,
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
    let mut request = Request {
        vm: None,
        snapshot: None,
        vmrs: None,
        bin: None,
        vsv: None,
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
            "--vm" => request.vm = Some(value()?),
            "--snapshot" => request.snapshot = Some(value()?),
            "--vmrs" => request.vmrs = Some(PathBuf::from(value()?)),
            "--bin" => request.bin = Some(PathBuf::from(value()?)),
            "--vsv" => request.vsv = Some(PathBuf::from(value()?)),
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
    if request.vm.is_none()
        && request.vmrs.is_none()
        && (request.bin.is_none() || request.vsv.is_none())
    {
        bail!(
            "name a capture: --vm, --vmrs, or --bin with --vsv\n{}",
            usage()
        );
    }
    Ok(request)
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let request = parse(args)?;
    // Before the provider is touched: a typo in `--image` must be a refusal rather than a failure
    // three minutes into a decode that has already read a capture.
    let disk = sk::DiskImage::open(&request.image).map_err(|e| anyhow::anyhow!(e))?;
    let kit = Kit::find(request.kit.as_deref(), request.kit_version.as_deref())
        .map_err(|e| anyhow::anyhow!(e))?;
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
    let files = match (&request.vm, &request.vmrs, &request.bin, &request.vsv) {
        (Some(vm), _, _, _) => provider
            .locate(vm, request.snapshot.as_deref())
            .map_err(|e| anyhow::anyhow!(e))?,
        (None, Some(vmrs), _, _) => CaptureFiles::vmrs(vmrs),
        (None, None, Some(bin), Some(vsv)) => CaptureFiles::pair(bin, vsv),
        _ => bail!("no capture files"),
    };
    for path in files.paths() {
        println!("capture    {path}");
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
                std::fs::write(
                    path,
                    serde_json::to_vec_pretty(&serde_json::json!({
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
    let differential = differential(&capture, &landmarks);
    if let Some(sampled) = &differential {
        println!(
            "\noracle     {} page(s) of the image offered to both: {} agree, {} the provider maps \
             and the walk does not, {} the walk maps and the provider does not",
            sampled.offered, sampled.agree, sampled.provider_only, sampled.walk_only
        );
        if let Some((va, ours, theirs)) = sampled.disagreement {
            println!(
                "           first disagreement at {va:#X}: walk {ours:#X}, provider {theirs:#X}"
            );
        }
    }
    if let Some(path) = &request.json {
        let json = as_json(&files, &landmarks, differential.as_ref());
        std::fs::write(path, serde_json::to_vec_pretty(&json)?)
            .with_context(|| format!("writing {}", path.display()))?;
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
            if let Some(cross) = &landmarks.cross_check {
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
    provider_only: u64,
    walk_only: u64,
    disagreement: Option<(u64, u64, u64)>,
}

fn differential(capture: &Capture, landmarks: &Landmarks) -> Option<Differential> {
    let found = landmarks.identified.as_ref()?;
    let base = found.candidate.va.0;
    let size = found.candidate.identity.size_of_image as u64;
    let mut result = Differential {
        offered: 0,
        agree: 0,
        provider_only: 0,
        walk_only: 0,
        disagreement: None,
    };
    let mut offset = 0u64;
    while offset < size {
        let va = base + offset;
        offset += PAGE;
        result.offered += 1;
        let theirs = capture.translate(va).ok().map(|gpa| gpa.0);
        let ours = landmarks.space.translate(Gva(va)).map(|gpa| gpa.0);
        match (ours, theirs) {
            (Some(ours), Some(theirs)) if ours == theirs => result.agree += 1,
            (Some(ours), Some(theirs)) => {
                result.disagreement = result.disagreement.or(Some((va, ours, theirs)));
            }
            (None, Some(_)) => result.provider_only += 1,
            (Some(_), None) => result.walk_only += 1,
            (None, None) => {}
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
        "cross_check": landmarks.cross_check.as_ref().map(|cross| serde_json::json!({
            "entry_va": format!("{:#X}", cross.entry.0),
            "head_va": format!("{:#X}", cross.head.0),
            "pages_scanned": cross.pages_scanned,
            "pages_unreadable": cross.pages_unreadable,
        })),
        "oracle": differential.map(|d| serde_json::json!({
            "offered": d.offered,
            "agree": d.agree,
            "provider_only": d.provider_only,
            "walk_only": d.walk_only,
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
        assert!(error.to_string().contains("name a capture"), "{error}");
    }
}
