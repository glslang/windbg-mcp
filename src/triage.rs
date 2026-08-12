//! Turning a bug check into the four or five facts a crash-triage loop actually reads.
//!
//! The workflow this exists for is a loop: fire a bug from user mode, let the machine bug check
//! and reboot, classify the minidump, change one thing, repeat
//! ([#104](https://github.com/glslang/windbg-mcp/issues/104)). Classifying used to mean running
//! `!analyze -v` and reading ~150 lines of it to find four — the code and its parameters, the
//! driver frame, the pool tag, the process — which is fine once and unreadable on the tenth pass.
//!
//! # Two provenances, and why they are kept apart
//!
//! **The engine's values.** The bug check code and parameters come from `ReadBugCheckData`, the
//! stack from a stack walk, each frame's module from the engine's own containment test, and the
//! process from the current `_EPROCESS`. These are reads of the dump.
//!
//! **`!analyze`'s conclusions.** The pool tag, the failure bucket, the culprit module, and the
//! per-parameter explanations exist nowhere else: they are the extension's analysis, and there is
//! no API that returns them. So they are extracted from its output — the one place in this server
//! where a structured field is scraped from debugger text — and they are confined to
//! [`structured::AnalysisInfo`] so that a consumer can tell which half it is reading.
//!
//! That split is not tidiness. `!analyze` attributes a crash to a module by heuristic, and on a
//! driver with no PDB it is often wrong — it named `mpsdrv` for a crash in `MessageManager` in the
//! run this tool came out of. So the frames here are attributed **independently**, from the load
//! bases the engine reports, and `module+RVA` computed that way is the field to trust. `!analyze`'s
//! own answer travels beside it, under `analysis.module_name`, precisely so the two can be
//! compared rather than confused.

use win_kexp::dbgeng::{BugCheck, Module, StackFrame};

use crate::structured;

/// One stack frame with the module the engine placed it in.
///
/// Paired here rather than inside win-kexp's own frame because "which module holds this address"
/// is a second question asked of the engine, and a stack walk that answers only the first is
/// still a good stack walk.
pub struct AttributedFrame {
    pub frame: StackFrame,
    pub module: Option<Module>,
}

/// The modules a bug check passes *through* on its way to being one.
///
/// Frames in these are skipped when picking the faulting frame: `nt!KeBugCheckEx` is on top of
/// every single crash, so it is never the answer. The list is exact rather than a prefix match, so
/// a driver called `halcyon.sys` is not mistaken for the HAL — the cost of a kernel image this
/// list does not name is that its frame gets picked as the culprit, which shows a caller something
/// slightly wrong rather than hiding something right.
const KERNEL_IMAGES: &[&str] = &[
    "nt", "ntoskrnl", "ntkrnlmp", "ntkrnlpa", "ntkrpamp", "hal", "halmacpi", "halacpi", "halaacpi",
    "halx86",
];

fn is_kernel_image(name: &str) -> bool {
    KERNEL_IMAGES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

/// Renders an offset within a module: `0x`-prefixed, lowercase, **unpadded**.
///
/// Deliberately not [`structured::addr`]. That form exists so addresses sort lexically and
/// round-trip a full 64-bit value; an RVA is neither an address nor register-sized, it is the
/// number you paste after `module+`, and `MessageManager+0x0000000000001654` is not a form
/// anything else in the debugger uses.
fn offset(value: u64) -> String {
    format!("{value:#x}")
}

/// Assembles the report from values already read off the engine.
///
/// Takes values rather than an engine so the whole shape of the answer — which frame is the
/// faulting one, what the text says when there isn't one, how `!analyze`'s fields land beside the
/// engine's — is testable without a debugger.
pub fn report(
    bug_check: BugCheck,
    frames: &[AttributedFrame],
    truncated: bool,
    process_name: Option<String>,
    analysis: Analysis,
) -> structured::CrashTriage {
    let extracted = analysis.extracted();
    let frames: Vec<structured::FrameInfo> = frames.iter().map(frame_info).collect();

    // The topmost frame outside the kernel image and the HAL. A frame whose module is unknown
    // counts as outside: an address in no loaded module is exactly the kind of thing a driver bug
    // produces (a freed pool page, an unloaded driver), and it is never the bug check machinery.
    let faulting = frames
        .iter()
        .find(|frame| {
            frame
                .module
                .as_deref()
                .is_none_or(|name| !is_kernel_image(name))
        })
        .cloned();
    let faulting_note = match (&faulting, frames.first()) {
        (Some(_), _) => None,
        (None, None) => Some(
            "the stack walk returned no frames, so there is no faulting frame to name".to_string(),
        ),
        (None, Some(top)) => Some(format!(
            "every one of the {} captured frames is in the kernel image or the HAL, so no driver \
             frame can be named: the bug check is either in the kernel's own path or the stack \
             did not reach the culprit. The innermost frame is {}.{}",
            frames.len(),
            top.symbol
                .clone()
                .or_else(|| module_offset(top))
                .unwrap_or_else(|| top.address.clone()),
            // Said only here, where it changes the reading of the answer above: a walk that hit
            // its cap may well have a driver frame one past it, so "no driver frame" would be a
            // conclusion about the cap rather than about the crash.
            if truncated {
                " The walk stopped at its frame cap, so a driver frame may lie past it — re-run \
                 with a larger `frames`."
            } else {
                ""
            }
        )),
    };

    structured::CrashTriage {
        bug_check: structured::BugCheckInfo {
            code: offset(u64::from(bug_check.code)),
            // This build's table first, `!analyze`'s header line second. The table is the reason
            // a name survives `analyze: false` and an engine with no extensions at all; the
            // header line is the reason a code newer than this build still gets named.
            name: bug_check_name(bug_check.code)
                .map(str::to_string)
                .or_else(|| extracted.bug_check_name.clone()),
            parameters: bug_check
                .parameters
                .iter()
                .map(|value| structured::addr(*value))
                .collect(),
        },
        process_name,
        faulting_frame: faulting,
        faulting_frame_note: faulting_note,
        frames,
        frames_truncated: truncated,
        analysis: extracted,
    }
}

fn frame_info(attributed: &AttributedFrame) -> structured::FrameInfo {
    let address = attributed.frame.instruction_offset;
    let module = attributed
        .module
        .as_ref()
        .filter(|module| !module.name.is_empty());
    structured::FrameInfo {
        index: attributed.frame.index,
        address: structured::addr(address),
        module: module.map(|module| module.name.clone()),
        // `saturating_sub` rather than a bare subtraction: the base comes from the engine and the
        // address from a stack walk, and an underflow here would print a 16-exabyte RVA rather
        // than fail, which is the sort of number nobody double-checks.
        rva: module.map(|module| offset(address.saturating_sub(module.base))),
        symbol: attributed.frame.symbol.clone(),
        displacement: attributed
            .frame
            .symbol
            .as_ref()
            .map(|_| offset(attributed.frame.displacement)),
    }
}

/// `module+0xrva`, where the frame has a module.
fn module_offset(frame: &structured::FrameInfo) -> Option<String> {
    Some(format!(
        "{}+{}",
        frame.module.as_ref()?,
        frame.rva.as_ref()?
    ))
}

/// The `!analyze -v` half of a triage: what ran, and what it printed.
pub enum Analysis {
    /// It was not asked for.
    NotRequested,
    /// It was asked for and could not be run; the string says why.
    Unavailable(String),
    /// It ran. Carries the command that worked and its full output, to be extracted below.
    Ran { command: String, output: String },
}

impl Analysis {
    fn extracted(&self) -> structured::AnalysisInfo {
        match self {
            Self::NotRequested => structured::AnalysisInfo {
                ran: false,
                note: Some(
                    "`!analyze -v` was not run (analyze: false). The pool tag and failure bucket \
                     come from it and are therefore missing; everything else here is read from \
                     the engine and is unaffected."
                        .to_string(),
                ),
                ..empty_analysis()
            },
            Self::Unavailable(why) => structured::AnalysisInfo {
                ran: false,
                note: Some(why.clone()),
                ..empty_analysis()
            },
            Self::Ran { command, output } => {
                let mut info = extract(output);
                info.ran = true;
                info.command = Some(command.clone());
                info
            }
        }
    }
}

fn empty_analysis() -> structured::AnalysisInfo {
    structured::AnalysisInfo {
        ran: false,
        command: None,
        bug_check_name: None,
        pool_tag: None,
        failure_bucket_id: None,
        module_name: None,
        image_name: None,
        process_name: None,
        parameter_notes: Vec::new(),
        note: None,
    }
}

/// The bug check's name, as `!analyze` prints it on its own summary line, and the fields from its
/// `KEY:  value` block.
///
/// Scoped deliberately narrowly. `!analyze -v` prints a great deal — timing, hypervisor state,
/// blackbox flags, a stack render — and none of it is read here: only the keys below, plus the
/// `Arg1:`..`Arg4:` explanations and the `NAME (code)` header. Anything it does not print is
/// simply absent, which is why every field is an `Option`.
fn extract(output: &str) -> structured::AnalysisInfo {
    let mut info = empty_analysis();
    let mut notes: [Option<String>; 4] = [None, None, None, None];

    for line in output.lines() {
        // The header line, `DRIVER_POWER_STATE_FAILURE (9f)`. Taken only if nothing has claimed
        // it yet: `!analyze` prints the name again inside the details, and the first one is the
        // summary.
        if info.bug_check_name.is_none()
            && let Some(name) = header_name(line)
        {
            info.bug_check_name = Some(name);
            continue;
        }
        // `Arg2: ffffe284ffe59060, Physical Device Object of the stack`
        if let Some((index, note)) = argument_note(line) {
            notes[index] = Some(note);
            continue;
        }
        let Some((key, value)) = key_value(line) else {
            continue;
        };
        // First writer wins throughout: `!analyze` can repeat a key (a second `IMAGE_NAME` in the
        // "additional information" tail), and its summary block is the authoritative one.
        let field = match key {
            // `FREED_POOL_TAG` is the pool bug checks' own; `POOL_TAG` is what the special-pool
            // and verifier paths print. Both land in the one field because a caller asking
            // "which tag?" does not care which bug check spelled it which way.
            "FREED_POOL_TAG" | "POOL_TAG" => &mut info.pool_tag,
            "FAILURE_BUCKET_ID" => &mut info.failure_bucket_id,
            "MODULE_NAME" => &mut info.module_name,
            "IMAGE_NAME" => &mut info.image_name,
            "PROCESS_NAME" => &mut info.process_name,
            _ => continue,
        };
        if field.is_none() {
            *field = Some(value.to_string());
        }
    }

    // Kept in `Arg1`..`Arg4` order and truncated at the first gap, so the position of a note in
    // the list is always the parameter it explains. `!analyze` prints all four or none, so a gap
    // means the output was cut short rather than that `Arg3` has no explanation.
    info.parameter_notes = notes
        .into_iter()
        .take_while(Option::is_some)
        .flatten()
        .collect();
    info
}

/// `DRIVER_POWER_STATE_FAILURE (9f)` → `DRIVER_POWER_STATE_FAILURE`.
fn header_name(line: &str) -> Option<String> {
    let (name, rest) = line.trim_end().split_once(" (")?;
    let code = rest.strip_suffix(')')?;
    // A bug check name is SCREAMING_SNAKE and the code is bare hex — checked rather than assumed,
    // because plenty of `!analyze` prose contains a parenthesised aside.
    let named = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    let coded = !code.is_empty() && code.chars().all(|c| c.is_ascii_hexdigit());
    (named && coded).then(|| name.to_string())
}

/// `Arg2: ffffe284ffe59060, Physical Device Object of the stack` → `(1, "Physical Device …")`.
fn argument_note(line: &str) -> Option<(usize, String)> {
    let rest = line.strip_prefix("Arg")?;
    let (index, rest) = rest.split_once(':')?;
    let index = index.parse::<usize>().ok()?.checked_sub(1)?;
    if index > 3 {
        return None;
    }
    // The value is echoed as bare hex; everything past the comma is the explanation. A parameter
    // `!analyze` has nothing to say about is printed without one, and is skipped.
    let (_, note) = rest.split_once(',')?;
    let note = note.trim();
    (!note.is_empty()).then(|| (index, note.to_string()))
}

/// `FAILURE_BUCKET_ID:  0x9F_3` → `("FAILURE_BUCKET_ID", "0x9F_3")`.
///
/// Column-anchored: `!analyze`'s summary keys start at column zero, while the `Key  : …` pairs of
/// its `KEY_VALUES_STRING` block and its rendered stack are indented. That is what keeps a stack
/// frame like `nt!KeBugCheckEx` — which also contains no space before a colon — out of this.
fn key_value(line: &str) -> Option<(&str, &str)> {
    if line.starts_with(char::is_whitespace) {
        return None;
    }
    let (key, value) = line.split_once(':')?;
    let is_key = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    let value = value.trim();
    (is_key && !value.is_empty()).then_some((key, value))
}

/// Renders a triage for a person, in the order a person reads one: what happened, to whom, where.
pub fn render(triage: &structured::CrashTriage) -> String {
    let mut text = String::new();
    let name = triage.bug_check.name.as_deref().unwrap_or("<unnamed>");
    text.push_str(&format!("BUG CHECK: {} {name}\n", triage.bug_check.code));
    for (index, value) in triage.bug_check.parameters.iter().enumerate() {
        let note = triage
            .analysis
            .parameter_notes
            .get(index)
            .map(|note| format!("  {note}"))
            .unwrap_or_default();
        text.push_str(&format!("  Arg{}: {value}{note}\n", index + 1));
    }
    if let Some(process) = &triage.process_name {
        text.push_str(&format!("PROCESS: {process}\n"));
    }
    if let Some(tag) = &triage.analysis.pool_tag {
        text.push_str(&format!("POOL TAG: {tag}\n"));
    }
    match (&triage.faulting_frame, &triage.faulting_frame_note) {
        (Some(frame), _) => text.push_str(&format!(
            "FAULTING FRAME: {} (frame {:02})\n",
            describe(frame),
            frame.index
        )),
        (None, Some(note)) => text.push_str(&format!("FAULTING FRAME: none — {note}\n")),
        (None, None) => {}
    }
    if let Some(bucket) = &triage.analysis.failure_bucket_id {
        text.push_str(&format!("FAILURE BUCKET: {bucket}\n"));
    }
    // `!analyze`'s own attribution. Shown when it adds something: a *disagreement* with the frame
    // above, which is the whole reason this field is reported — or, where no frame could be named,
    // the attribution on its own, since then it is the only guess there is. Agreement is not news.
    if let Some(module) = &triage.analysis.module_name {
        match triage
            .faulting_frame
            .as_ref()
            .and_then(|frame| frame.module.as_deref())
        {
            Some(named) if named == module => {}
            Some(_) => text.push_str(&format!(
                "!analyze blamed: {module} (differs from the faulting frame above, which is \
                 computed from the module's load base — prefer it)\n"
            )),
            None => text.push_str(&format!("!analyze blamed: {module}\n")),
        }
    }

    text.push_str(&format!("\nSTACK ({} frames):\n", triage.frames.len()));
    for frame in &triage.frames {
        text.push_str(&format!("  {:02} {}\n", frame.index, describe(frame)));
    }
    if let Some(note) = &triage.analysis.note {
        text.push_str(&format!("\nNote: {note}\n"));
    }
    text
}

/// A frame in one line: the symbol where there is one, and always the `module+RVA` — which is the
/// form that survives a driver with no PDB and is comparable across reboots.
///
/// The symbol carries its displacement, as the debugger's own stack renders it. Printing the bare
/// name would say the frame is *at* the function's first instruction, which it is for the
/// innermost frame and for nothing else on the stack.
fn describe(frame: &structured::FrameInfo) -> String {
    let symbol = frame
        .symbol
        .as_ref()
        .map(|symbol| match frame.displacement.as_deref() {
            Some("0x0") | None => symbol.clone(),
            Some(displacement) => format!("{symbol}+{displacement}"),
        });
    match (symbol, module_offset(frame)) {
        (Some(symbol), Some(offset)) => format!("{symbol}  [{offset}]"),
        (Some(symbol), None) => symbol,
        (None, Some(offset)) => offset,
        (None, None) => frame.address.clone(),
    }
}

/// The name of a bug check code.
///
/// A table rather than a lookup because there is no API for it: the engine reports the code, and
/// only `!analyze`'s own tables turn it into a name. Keeping one here is what lets `analyze:
/// false` — and an engine with no extension DLLs at all — still answer "which bug check was it?".
///
/// Not exhaustive, and not meant to be. It covers the bug checks a driver or exploitation
/// workflow actually meets; a code it does not know is reported by number, with `!analyze`'s
/// header line filling the name in whenever that ran.
pub fn bug_check_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x01 => "APC_INDEX_MISMATCH",
        0x02 => "DEVICE_QUEUE_NOT_BUSY",
        0x03 => "INVALID_AFFINITY_SET",
        0x04 => "INVALID_DATA_ACCESS_TRAP",
        0x05 => "INVALID_PROCESS_ATTACH_ATTEMPT",
        0x06 => "INVALID_PROCESS_DETACH_ATTEMPT",
        0x07 => "INVALID_SOFTWARE_INTERRUPT",
        0x08 => "IRQL_NOT_DISPATCH_LEVEL",
        0x09 => "IRQL_NOT_GREATER_OR_EQUAL",
        0x0A => "IRQL_NOT_LESS_OR_EQUAL",
        0x0B => "NO_EXCEPTION_HANDLING_SUPPORT",
        0x0C => "MAXIMUM_WAIT_OBJECTS_EXCEEDED",
        0x0D => "MUTEX_LEVEL_NUMBER_VIOLATION",
        0x0E => "NO_USER_MODE_CONTEXT",
        0x0F => "SPIN_LOCK_ALREADY_OWNED",
        0x10 => "SPIN_LOCK_NOT_OWNED",
        0x11 => "THREAD_NOT_MUTEX_OWNER",
        0x12 => "TRAP_CAUSE_UNKNOWN",
        0x18 => "REFERENCE_BY_POINTER",
        0x19 => "BAD_POOL_HEADER",
        0x1A => "MEMORY_MANAGEMENT",
        0x1E => "KMODE_EXCEPTION_NOT_HANDLED",
        0x20 => "KERNEL_APC_PENDING_DURING_EXIT",
        0x21 => "QUOTA_UNDERFLOW",
        0x22 => "FILE_SYSTEM",
        0x24 => "NTFS_FILE_SYSTEM",
        0x2E => "DATA_BUS_ERROR",
        0x35 => "NO_MORE_IRP_STACK_LOCATIONS",
        0x36 => "DEVICE_REFERENCE_COUNT_NOT_ZERO",
        0x3B => "SYSTEM_SERVICE_EXCEPTION",
        0x3D => "INTERRUPT_EXCEPTION_NOT_HANDLED",
        0x3F => "NO_MORE_SYSTEM_PTES",
        0x44 => "MULTIPLE_IRP_COMPLETE_REQUESTS",
        0x48 => "CANCEL_STATE_IN_COMPLETED_IRP",
        0x4A => "IRQL_GT_ZERO_AT_SYSTEM_SERVICE",
        0x4E => "PFN_LIST_CORRUPT",
        0x50 => "PAGE_FAULT_IN_NONPAGED_AREA",
        0x51 => "REGISTRY_ERROR",
        0x76 => "PROCESS_HAS_LOCKED_PAGES",
        0x77 => "KERNEL_STACK_INPAGE_ERROR",
        0x7A => "KERNEL_DATA_INPAGE_ERROR",
        0x7B => "INACCESSIBLE_BOOT_DEVICE",
        0x7E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0x7F => "UNEXPECTED_KERNEL_MODE_TRAP",
        0x8E => "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
        0x93 => "INVALID_KERNEL_HANDLE",
        0x94 => "KERNEL_STACK_LOCKED_AT_EXIT",
        0x9C => "MACHINE_CHECK_EXCEPTION",
        0x9F => "DRIVER_POWER_STATE_FAILURE",
        0xA0 => "INTERNAL_POWER_ERROR",
        0xA5 => "ACPI_BIOS_ERROR",
        0xAB => "SESSION_HAS_VALID_POOL_ON_EXIT",
        0xB8 => "ATTEMPTED_SWITCH_FROM_DPC",
        0xBE => "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
        0xC1 => "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION",
        0xC2 => "BAD_POOL_CALLER",
        0xC4 => "DRIVER_VERIFIER_DETECTED_VIOLATION",
        0xC5 => "DRIVER_CORRUPTED_EXPOOL",
        0xC6 => "DRIVER_CAUGHT_MODIFYING_FREED_POOL",
        0xC7 => "TIMER_OR_DPC_INVALID",
        0xC9 => "DRIVER_VERIFIER_IOMANAGER_VIOLATION",
        0xCA => "PNP_DETECTED_FATAL_ERROR",
        0xCB => "DRIVER_LEFT_LOCKED_PAGES_IN_PROCESS",
        0xCE => "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS",
        0xD1 => "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        0xD3 => "DRIVER_PORTION_MUST_BE_NONPAGED",
        0xD5 => "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL",
        0xD6 => "DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION",
        0xD8 => "DRIVER_USED_EXCESSIVE_PTES",
        0xDA => "SYSTEM_PTE_MISUSE",
        0xDB => "DRIVER_CORRUPTED_SYSPTES",
        0xE1 => "WORKER_THREAD_RETURNED_AT_BAD_IRQL",
        0xE2 => "MANUALLY_INITIATED_CRASH",
        0xE3 => "RESOURCE_NOT_OWNED",
        0xE4 => "WORKER_INVALID",
        0xE6 => "DRIVER_VERIFIER_DMA_VIOLATION",
        0xEA => "THREAD_STUCK_IN_DEVICE_DRIVER",
        0xEF => "CRITICAL_PROCESS_DIED",
        0xF4 => "CRITICAL_OBJECT_TERMINATION",
        0xF5 => "FLTMGR_FILE_SYSTEM",
        0xF7 => "DRIVER_OVERRAN_STACK_BUFFER",
        0xFC => "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
        0x101 => "CLOCK_WATCHDOG_TIMEOUT",
        0x109 => "CRITICAL_STRUCTURE_CORRUPTION",
        0x10D => "WDF_VIOLATION",
        0x116 => "VIDEO_TDR_FAILURE",
        0x117 => "VIDEO_TDR_TIMEOUT_DETECTED",
        0x119 => "VIDEO_SCHEDULER_INTERNAL_ERROR",
        0x11C => "ATTEMPTED_WRITE_TO_CM_PROTECTED_STORAGE",
        0x124 => "WHEA_UNCORRECTABLE_ERROR",
        0x133 => "DPC_WATCHDOG_VIOLATION",
        0x139 => "KERNEL_SECURITY_CHECK_FAILURE",
        0x13A => "KERNEL_MODE_HEAP_CORRUPTION",
        0x144 => "BUGCODE_USB3_DRIVER",
        0x1CA => "SYNTHETIC_WATCHDOG_TIMEOUT",
        0xDEADDEAD => "MANUALLY_INITIATED_CRASH1",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(index: u32, address: u64, symbol: Option<&str>, displacement: u64) -> StackFrame {
        StackFrame {
            index,
            instruction_offset: address,
            return_offset: 0,
            frame_offset: 0,
            stack_offset: 0,
            symbol: symbol.map(str::to_string),
            displacement,
        }
    }

    fn module(name: &str, base: u64) -> Module {
        Module {
            base,
            size: 0x10000,
            name: name.to_string(),
            image_name: format!("{name}.sys"),
            loaded_image_name: String::new(),
            timestamp: 0,
            checksum: 0,
            symbols: win_kexp::dbgeng::SymbolKind::None,
            user_mode: false,
        }
    }

    const NT_BASE: u64 = 0xfffff803_1a000000;
    const DRIVER_BASE: u64 = 0xfffff803_2b000000;

    /// The stack of the crash this tool was written for: three frames of kernel allocator on top
    /// of the driver that called into it, and the driver has no PDB.
    fn heap_corruption_frames() -> Vec<AttributedFrame> {
        vec![
            AttributedFrame {
                frame: frame(0, NT_BASE + 0x1000, Some("nt!KeBugCheckEx"), 0),
                module: Some(module("nt", NT_BASE)),
            },
            AttributedFrame {
                frame: frame(1, NT_BASE + 0x2040, Some("nt!RtlpHpVsContextFree"), 0x40),
                module: Some(module("nt", NT_BASE)),
            },
            AttributedFrame {
                frame: frame(2, NT_BASE + 0x3010, Some("nt!ExFreePoolWithTag"), 0x10),
                module: Some(module("nt", NT_BASE)),
            },
            AttributedFrame {
                frame: frame(3, DRIVER_BASE + 0x1654, None, 0),
                module: Some(module("MessageManager", DRIVER_BASE)),
            },
        ]
    }

    /// The whole point of the tool: the driver frame is named by `module+RVA` computed from the
    /// load base, and it is picked past the kernel frames that top every bug check.
    #[test]
    fn the_faulting_frame_is_the_first_one_outside_the_kernel() {
        let triage = report(
            BugCheck {
                code: 0x13A,
                parameters: [0x11, 0xdead, 0xbeef, 0],
            },
            &heap_corruption_frames(),
            false,
            Some("mm_exploit.exe".into()),
            Analysis::NotRequested,
        );
        let faulting = triage
            .faulting_frame
            .expect("a driver frame was on the stack");
        assert_eq!(faulting.index, 3);
        assert_eq!(faulting.module.as_deref(), Some("MessageManager"));
        // Unpadded, and computed from the base rather than taken from `!analyze`.
        assert_eq!(faulting.rva.as_deref(), Some("0x1654"));
        // No PDB, so no symbol — and that is reported as absent rather than guessed at.
        assert_eq!(faulting.symbol, None);
        assert_eq!(triage.faulting_frame_note, None);
        assert_eq!(triage.bug_check.code, "0x13a");
        assert_eq!(
            triage.bug_check.name.as_deref(),
            Some("KERNEL_MODE_HEAP_CORRUPTION")
        );
        // Parameters are register-sized values, so they take the padded address form.
        assert_eq!(triage.bug_check.parameters[0], "0x0000000000000011");
        assert_eq!(triage.bug_check.parameters.len(), 4);
        assert_eq!(triage.process_name.as_deref(), Some("mm_exploit.exe"));
    }

    /// Two intended fires of the same bug differ only by RVA — which is the comparison the whole
    /// crash/reboot loop is made of, and it must not depend on the load base being the same.
    #[test]
    fn the_rva_is_stable_when_the_driver_loads_somewhere_else() {
        let at = |base: u64, offset: u64| {
            let frames = vec![AttributedFrame {
                frame: frame(0, base + offset, None, 0),
                module: Some(module("MessageManager", base)),
            }];
            report(
                BugCheck {
                    code: 0x13A,
                    parameters: [0; 4],
                },
                &frames,
                false,
                None,
                Analysis::NotRequested,
            )
            .faulting_frame
            .expect("a frame")
            .rva
        };
        assert_eq!(at(DRIVER_BASE, 0x1654), Some("0x1654".to_string()));
        assert_eq!(at(0xfffff801_00000000, 0x1654), Some("0x1654".to_string()));
        // A different site in the same driver is a different RVA — this is the signal that tells
        // an intended fire from an incidental one.
        assert_eq!(at(DRIVER_BASE, 0x14e9), Some("0x14e9".to_string()));
    }

    /// A crash entirely inside the kernel has no driver frame, and says so rather than blaming
    /// `nt!KeBugCheckEx` — which is on top of every crash ever written.
    #[test]
    fn an_all_kernel_stack_names_no_faulting_frame() {
        let frames = vec![
            AttributedFrame {
                frame: frame(0, NT_BASE + 0x1000, Some("nt!KeBugCheckEx"), 0),
                module: Some(module("nt", NT_BASE)),
            },
            AttributedFrame {
                frame: frame(1, NT_BASE + 0x2000, Some("nt!KiPageFault"), 0),
                module: Some(module("HAL", NT_BASE)),
            },
        ];
        let triage = report(
            BugCheck {
                code: 0x1A,
                parameters: [0; 4],
            },
            &frames,
            false,
            None,
            Analysis::NotRequested,
        );
        assert!(triage.faulting_frame.is_none());
        let note = triage.faulting_frame_note.expect("a note explaining why");
        assert!(note.contains("nt!KeBugCheckEx"), "{note}");
        // The whole walk is still there to read.
        assert_eq!(triage.frames.len(), 2);
    }

    /// An address in no loaded module — a freed page, an unloaded driver — is a culprit, not a
    /// kernel frame to skip past.
    #[test]
    fn a_frame_in_no_module_can_be_the_faulting_one() {
        let frames = vec![
            AttributedFrame {
                frame: frame(0, NT_BASE + 0x1000, Some("nt!KeBugCheckEx"), 0),
                module: Some(module("nt", NT_BASE)),
            },
            AttributedFrame {
                frame: frame(1, 0xffffc000_12340000, None, 0),
                module: None,
            },
        ];
        let triage = report(
            BugCheck {
                code: 0xFC,
                parameters: [0; 4],
            },
            &frames,
            false,
            None,
            Analysis::NotRequested,
        );
        let faulting = triage.faulting_frame.expect("the unattributed frame");
        assert_eq!(faulting.index, 1);
        assert_eq!(faulting.module, None);
        assert_eq!(faulting.rva, None);
        assert_eq!(faulting.address, "0xffffc00012340000");
    }

    /// The `!analyze -v` of the checked-in sample dump, trimmed to the shapes this extracts from.
    const SAMPLE_ANALYZE: &str = "\
*******************************************************************************
*                        Bugcheck Analysis                                    *
*******************************************************************************

DRIVER_POWER_STATE_FAILURE (9f)
A driver has failed to complete a power IRP within a specific time.
Arguments:
Arg1: 0000000000000003, A device object has been blocking an IRP for too long a time
Arg2: ffffe284ffe59060, Physical Device Object of the stack
Arg3: ffffd38c2d84f580, nt!TRIAGE_9F_POWER on Win7 and higher
Arg4: ffffe2850787bc20, The blocked IRP

Debugging Details:
------------------

KEY_VALUES_STRING: 1

    Key  : Analysis.CPU.mSec
    Value: 1234

    Key  : Failure.Bucket
    Value: 0x9F_3

BUGCHECK_CODE:  9f

BUGCHECK_P1: 3

DRVPOWERSTATE_SUBCODE:  3

FREED_POOL_TAG:  Tfub

PROCESS_NAME:  System

STACK_TEXT:
ffffd38c`2d84f4a8 fffff803`1a1c1234 : nt!KeBugCheckEx
ffffd38c`2d84f4b0 fffff803`1a1c5678 : nt!PopIrpWatchdogBugcheck

MODULE_NAME: Unknown_Module

IMAGE_NAME:  Unknown_Image

FAILURE_BUCKET_ID:  0x9F_3
";

    /// The four fields the loop reads, out of the ~150 lines it used to mean reading by hand.
    #[test]
    fn the_analyze_extraction_takes_the_fields_and_nothing_else() {
        let info = extract(SAMPLE_ANALYZE);
        assert_eq!(
            info.bug_check_name.as_deref(),
            Some("DRIVER_POWER_STATE_FAILURE")
        );
        assert_eq!(info.pool_tag.as_deref(), Some("Tfub"));
        assert_eq!(info.failure_bucket_id.as_deref(), Some("0x9F_3"));
        assert_eq!(info.module_name.as_deref(), Some("Unknown_Module"));
        assert_eq!(info.image_name.as_deref(), Some("Unknown_Image"));
        assert_eq!(info.process_name.as_deref(), Some("System"));
        assert_eq!(info.parameter_notes.len(), 4);
        assert_eq!(
            info.parameter_notes[1],
            "Physical Device Object of the stack"
        );
        assert_eq!(info.parameter_notes[3], "The blocked IRP");
    }

    /// The two shapes that look like keys and are not: the indented `Key  : Value` pairs of the
    /// `KEY_VALUES_STRING` block, and the rendered stack — whose `nt!KeBugCheckEx` would otherwise
    /// be read as a key. Both are excluded by the column-zero anchor, which is why it exists.
    #[test]
    fn the_extraction_ignores_the_blocks_that_look_like_keys() {
        let info = extract(SAMPLE_ANALYZE);
        // "Analysis.CPU.mSec" and "Failure.Bucket" are indented, so the bucket that survives is
        // the summary block's `FAILURE_BUCKET_ID`, not the indented `Failure.Bucket`.
        assert_eq!(info.failure_bucket_id.as_deref(), Some("0x9F_3"));
        // A stack line is not a key/value pair.
        assert_eq!(
            key_value("ffffd38c`2d84f4a8 fffff803`1a1c1234 : nt!Ke"),
            None
        );
        assert_eq!(key_value("    Key  : Analysis.CPU.mSec"), None);
        // A key with nothing after it (`STACK_TEXT:`) has no value to take.
        assert_eq!(key_value("STACK_TEXT:"), None);
        // Prose with a parenthesised aside is not a bug check header.
        assert_eq!(header_name("A driver has failed (see below)"), None);
        assert_eq!(
            header_name("KERNEL_MODE_HEAP_CORRUPTION (13a)").as_deref(),
            Some("KERNEL_MODE_HEAP_CORRUPTION")
        );
    }

    /// A code this build's table does not know is still named, from `!analyze`'s header line —
    /// and the code itself is reported either way.
    #[test]
    fn an_unknown_code_takes_its_name_from_the_analysis() {
        let triage = report(
            BugCheck {
                code: 0x1F0,
                parameters: [0; 4],
            },
            &[],
            false,
            None,
            Analysis::Ran {
                command: "!analyze -v".into(),
                output: "SOME_FUTURE_BUGCHECK (1f0)\nArg1: 0000000000000001, why\n".into(),
            },
        );
        assert_eq!(bug_check_name(0x1F0), None);
        assert_eq!(triage.bug_check.code, "0x1f0");
        assert_eq!(
            triage.bug_check.name.as_deref(),
            Some("SOME_FUTURE_BUGCHECK")
        );
        assert!(triage.analysis.ran);
        assert_eq!(triage.analysis.command.as_deref(), Some("!analyze -v"));
    }

    /// This build's table wins over `!analyze`'s header for a code it knows, so the name a caller
    /// branches on does not change with the extension DLL that happens to be loaded.
    #[test]
    fn a_known_code_keeps_this_builds_name() {
        let triage = report(
            BugCheck {
                code: 0x9F,
                parameters: [0; 4],
            },
            &[],
            false,
            None,
            Analysis::Ran {
                command: "!ext.analyze -v".into(),
                output: "DRIVER_POWER_STATE_FAILURE_XYZ (9f)\n".into(),
            },
        );
        assert_eq!(
            triage.bug_check.name.as_deref(),
            Some("DRIVER_POWER_STATE_FAILURE")
        );
    }

    /// Skipping `!analyze` costs the analysis fields and nothing else, and the report says so
    /// rather than leaving a caller to wonder why the pool tag is missing.
    #[test]
    fn a_report_without_analysis_says_what_is_missing_and_why() {
        let triage = report(
            BugCheck {
                code: 0x13A,
                parameters: [0; 4],
            },
            &heap_corruption_frames(),
            false,
            Some("mm_exploit.exe".into()),
            Analysis::NotRequested,
        );
        assert!(!triage.analysis.ran);
        assert!(triage.analysis.pool_tag.is_none());
        assert!(
            triage
                .analysis
                .note
                .as_deref()
                .is_some_and(|note| note.contains("analyze: false"))
        );
        // Everything read from the engine is unaffected.
        assert_eq!(
            triage.faulting_frame.and_then(|frame| frame.rva).as_deref(),
            Some("0x1654")
        );
    }

    /// The text says the same things as the values, including the disagreement that is the reason
    /// `!analyze`'s attribution is reported at all.
    #[test]
    fn the_text_names_the_frame_the_tag_and_the_disagreement() {
        let triage = report(
            BugCheck {
                code: 0x13A,
                parameters: [0x11, 0, 0, 0],
            },
            &heap_corruption_frames(),
            false,
            Some("mm_exploit.exe".into()),
            Analysis::Ran {
                command: "!ext.analyze -v".into(),
                output: "KERNEL_MODE_HEAP_CORRUPTION (13a)\n\
                         Arg1: 0000000000000011, corrupted chunk\n\
                         FREED_POOL_TAG:  Tfub\n\
                         MODULE_NAME: mpsdrv\n"
                    .into(),
            },
        );
        let text = render(&triage);
        assert!(
            text.contains("BUG CHECK: 0x13a KERNEL_MODE_HEAP_CORRUPTION"),
            "{text}"
        );
        assert!(
            text.contains("Arg1: 0x0000000000000011  corrupted chunk"),
            "{text}"
        );
        assert!(text.contains("PROCESS: mm_exploit.exe"), "{text}");
        assert!(text.contains("POOL TAG: Tfub"), "{text}");
        assert!(
            text.contains("FAULTING FRAME: MessageManager+0x1654"),
            "{text}"
        );
        assert!(text.contains("!analyze blamed: mpsdrv"), "{text}");
        // The kernel frames keep their symbols and gain their module offsets.
        assert!(text.contains("nt!ExFreePoolWithTag"), "{text}");
    }

    /// A walk that stopped at its cap cannot conclude "no driver frame" — the driver may be the
    /// frame after the last one it took. So the note says so and points at the argument that
    /// fixes it, rather than reporting a cap as a finding about the crash.
    #[test]
    fn a_truncated_walk_says_the_answer_may_be_the_caps_fault() {
        let all_kernel = vec![AttributedFrame {
            frame: frame(0, NT_BASE + 0x1000, Some("nt!KeBugCheckEx"), 0),
            module: Some(module("nt", NT_BASE)),
        }];
        let stopped_short = report(
            BugCheck {
                code: 0x1A,
                parameters: [0; 4],
            },
            &all_kernel,
            true,
            None,
            Analysis::NotRequested,
        );
        assert!(stopped_short.frames_truncated);
        let note = stopped_short.faulting_frame_note.expect("a note");
        assert!(note.contains("frame cap"), "{note}");
        assert!(note.contains("`frames`"), "{note}");

        // The same stack walked to its end says nothing about a cap: there is no more stack.
        let complete = report(
            BugCheck {
                code: 0x1A,
                parameters: [0; 4],
            },
            &all_kernel,
            false,
            None,
            Analysis::NotRequested,
        );
        assert!(!complete.frames_truncated);
        assert!(
            !complete
                .faulting_frame_note
                .expect("a note")
                .contains("frame cap")
        );
    }

    /// A frame is not at its function's first instruction just because it has a symbol — every
    /// frame but the innermost is at a return address partway in, and the text has to say so.
    #[test]
    fn the_text_carries_each_frames_displacement() {
        let triage = report(
            BugCheck {
                code: 0x13A,
                parameters: [0; 4],
            },
            &heap_corruption_frames(),
            false,
            None,
            Analysis::NotRequested,
        );
        let text = render(&triage);
        assert!(text.contains("nt!ExFreePoolWithTag+0x10"), "{text}");
        assert!(text.contains("nt!RtlpHpVsContextFree+0x40"), "{text}");
        // The innermost frame is at the entry, so it takes no `+0x0`.
        assert!(text.contains("nt!KeBugCheckEx  ["), "{text}");
    }

    /// Agreement is not news: `!analyze`'s attribution is only printed when it differs from the
    /// frame, or the line would appear on every crash it got right.
    #[test]
    fn the_text_stays_quiet_when_analyze_agrees() {
        let triage = report(
            BugCheck {
                code: 0x13A,
                parameters: [0; 4],
            },
            &heap_corruption_frames(),
            false,
            None,
            Analysis::Ran {
                command: "!analyze -v".into(),
                output: "MODULE_NAME: MessageManager\n".into(),
            },
        );
        assert!(!render(&triage).contains("!analyze blamed"));
    }

    /// With no frame to disagree with, `!analyze`'s attribution is the only guess there is — so it
    /// is printed, and *without* the clause claiming it differs from a frame that isn't there.
    #[test]
    fn the_text_reports_the_lone_attribution_when_no_frame_was_named() {
        let all_kernel = vec![AttributedFrame {
            frame: frame(0, NT_BASE + 0x1000, Some("nt!KeBugCheckEx"), 0),
            module: Some(module("nt", NT_BASE)),
        }];
        let triage = report(
            BugCheck {
                code: 0x9F,
                parameters: [0; 4],
            },
            &all_kernel,
            false,
            None,
            Analysis::Ran {
                command: "!analyze -v".into(),
                output: "MODULE_NAME: Unknown_Module\n".into(),
            },
        );
        let text = render(&triage);
        assert!(text.contains("!analyze blamed: Unknown_Module\n"), "{text}");
        assert!(!text.contains("differs from the faulting frame"), "{text}");
    }
}
