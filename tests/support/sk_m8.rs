//! M8.2's qualification contract, kept beside the live smoke harness that will execute it.
//!
//! This first slice is deliberately offline. It fixes the private config, debugger script,
//! transcript grammar and evidence artifact before a command can reach the disposable bench.

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub(crate) const CONFIG_SCHEMA: &str = "windbg-mcp.sk-kd-m8.2a-config/v1";
pub(crate) const ARTIFACT_SCHEMA: &str = "windbg-mcp.sk-kd-m8.2a-arm/v1";
pub(crate) const FREE_RUN_ARTIFACT_SCHEMA: &str = "windbg-mcp.sk-kd-m8.2a-free-run/v1";
pub(crate) const RACE_ARTIFACT_SCHEMA: &str = "windbg-mcp.sk-kd-m8.2a-race/v1";
pub(crate) const BREAKPOINT_CYCLES: usize = 100;
pub(crate) const FREE_RUN_CYCLES: usize = 25;
// WinDbgX's UI-mediated guarded INT3 path measured just over 30 minutes for 100 cycles on the
// one-VP qualification guest. This is a whole-arm harness bound, not a target pause bound; each
// stop still has the policy's independent ten-minute absolute recovery deadline.
const BREAKPOINT_ARM_TIMEOUT: Duration = Duration::from_secs(45 * 60);

const FORBIDDEN_OPEN_FIELDS: &[&str] = &[
    "vmwp_pid",
    "dispatcher_vnd",
    "partition_id",
    "expected_cr3",
    "kernel_base",
];
const ALLOWED_OPEN_FIELDS: &[&str] = &[
    "profile",
    "control_transport",
    "live_transport",
    "vm_id",
    "vp",
    "arm_mode",
    "connect_timeout_ms",
    "idle_timeout_ms",
];
const REQUIRED_OPEN_STRING_FIELDS: &[&str] = &[
    "profile",
    "control_transport",
    "live_transport",
    "vm_id",
    "arm_mode",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    schema: String,
    disposable: bool,
    open: Map<String, Value>,
    frontends: Frontends,
    windbgx_script: Vec<String>,
    interrupts: Interrupts,
    resets: Interrupts,
    policies: Policies,
    breakpoint: String,
    symbol_path: String,
    trigger: Vec<String>,
    boot_probe: Vec<String>,
    post_release_audit: Vec<String>,
    artifact_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frontends {
    classic: String,
    windbgx: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Interrupts {
    classic: Vec<String>,
    windbgx: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policies {
    hardware: String,
    int3: String,
}

impl Config {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let config: Self = serde_json::from_str(text)
            .map_err(|error| format!("invalid M8.2a qualification config: {error}"))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != CONFIG_SCHEMA {
            return Err(format!(
                "M8.2a config schema must be `{CONFIG_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        if !self.disposable {
            return Err("M8.2a requires `disposable: true`".into());
        }
        for required in REQUIRED_OPEN_STRING_FIELDS {
            let Some(value) = self.open.get(*required).and_then(Value::as_str) else {
                return Err(format!("M8.2a open config requires string `{required}`"));
            };
            if value.trim().is_empty() {
                return Err(format!("M8.2a open config has empty `{required}`"));
            }
        }
        for forbidden in FORBIDDEN_OPEN_FIELDS {
            if self.open.contains_key(*forbidden) {
                return Err(format!(
                    "M8.2a must discover `{forbidden}` rather than accept a per-boot assertion"
                ));
            }
        }
        let allowed: BTreeSet<_> = ALLOWED_OPEN_FIELDS.iter().copied().collect();
        if let Some(unknown) = self
            .open
            .keys()
            .find(|name| !allowed.contains(name.as_str()))
        {
            return Err(format!(
                "M8.2a open config contains unknown field `{unknown}`"
            ));
        }
        if self.open.get("arm_mode").and_then(Value::as_str) != Some("redirect") {
            return Err("M8.2a requires `open.arm_mode` to be `redirect`".into());
        }
        for (name, expected) in [
            ("vp", 0),
            ("connect_timeout_ms", 60_000),
            ("idle_timeout_ms", 60_000),
        ] {
            if self.open.get(name).and_then(Value::as_u64) != Some(expected) {
                return Err(format!(
                    "M8.2a requires `open.{name}` to be the fixed value {expected}"
                ));
            }
        }
        for (name, value) in [
            ("frontends.classic", &self.frontends.classic),
            ("frontends.windbgx", &self.frontends.windbgx),
            ("policies.hardware", &self.policies.hardware),
            ("policies.int3", &self.policies.int3),
            ("symbol_path", &self.symbol_path),
            ("artifact_dir", &self.artifact_dir),
        ] {
            if value.trim().is_empty() {
                return Err(format!("M8.2a config has empty `{name}`"));
            }
        }
        if self
            .frontends
            .classic
            .eq_ignore_ascii_case(&self.frontends.windbgx)
        {
            return Err("classic WinDbg and WinDbgX must name distinct executables".into());
        }
        if self
            .policies
            .hardware
            .eq_ignore_ascii_case(&self.policies.int3)
        {
            return Err("hardware and INT3 arms must name distinct startup policies".into());
        }
        validate_command("trigger", &self.trigger)?;
        validate_command("boot_probe", &self.boot_probe)?;
        validate_command("post_release_audit", &self.post_release_audit)?;
        validate_command("windbgx_script", &self.windbgx_script)?;
        validate_command("interrupts.classic", &self.interrupts.classic)?;
        validate_command("interrupts.windbgx", &self.interrupts.windbgx)?;
        validate_command("resets.classic", &self.resets.classic)?;
        validate_command("resets.windbgx", &self.resets.windbgx)?;
        let placeholders = self
            .trigger
            .iter()
            .map(|argument| argument.matches("{count}").count())
            .sum::<usize>();
        if placeholders != 1 {
            return Err(format!(
                "M8.2a trigger must contain exactly one `{{count}}` placeholder, found {placeholders}"
            ));
        }
        for (name, command) in [
            ("windbgx_script", &self.windbgx_script),
            ("interrupts.classic", &self.interrupts.classic),
            ("interrupts.windbgx", &self.interrupts.windbgx),
            ("resets.classic", &self.resets.classic),
            ("resets.windbgx", &self.resets.windbgx),
        ] {
            let pid_placeholders = command
                .iter()
                .map(|argument| argument.matches("{pid}").count())
                .sum::<usize>();
            if pid_placeholders != 1 {
                return Err(format!(
                    "M8.2a `{name}` must contain exactly one `{{pid}}` placeholder, found {pid_placeholders}"
                ));
            }
            if name == "windbgx_script" {
                let command_placeholders = command
                    .iter()
                    .map(|argument| argument.matches("{command}").count())
                    .sum::<usize>();
                if command_placeholders != 1 {
                    return Err(format!(
                        "M8.2a `windbgx_script` must contain exactly one `{{command}}` placeholder, found {command_placeholders}"
                    ));
                }
            }
        }
        validate_debugger_atom("breakpoint", &self.breakpoint)?;
        Ok(())
    }

    pub(crate) fn counted_trigger(&self) -> Vec<String> {
        self.trigger_command(BREAKPOINT_CYCLES)
    }

    fn trigger_command(&self, count: usize) -> Vec<String> {
        self.trigger
            .iter()
            .map(|argument| argument.replace("{count}", &count.to_string()))
            .collect()
    }

    fn preflight_files(&self) -> Result<(), String> {
        for (name, path, directory) in [
            ("frontends.classic", self.frontends.classic.as_str(), false),
            ("frontends.windbgx", self.frontends.windbgx.as_str(), false),
            ("policies.hardware", self.policies.hardware.as_str(), false),
            ("policies.int3", self.policies.int3.as_str(), false),
            ("symbol_path", self.symbol_path.as_str(), true),
            (
                "open.profile",
                self.open["profile"].as_str().expect("validated profile"),
                false,
            ),
        ] {
            let metadata = fs::metadata(path)
                .map_err(|error| format!("M8.2a `{name}` is not readable at {path}: {error}"))?;
            if metadata.is_dir() != directory {
                let expected = if directory { "directory" } else { "file" };
                return Err(format!("M8.2a `{name}` must name a {expected}: {path}"));
            }
        }
        let read_policy = |name: &str, path: &str| -> Result<Value, String> {
            let text = fs::read_to_string(path)
                .map_err(|error| format!("reading M8.2a {name} policy {path}: {error}"))?;
            serde_json::from_str(&text)
                .map_err(|error| format!("parsing M8.2a {name} policy {path}: {error}"))
        };
        let hardware = read_policy("hardware", &self.policies.hardware)?;
        let int3 = read_policy("INT3", &self.policies.int3)?;
        validate_policy_pair(&hardware, &int3)?;
        for (name, command) in [
            ("trigger", &self.trigger),
            ("boot_probe", &self.boot_probe),
            ("post_release_audit", &self.post_release_audit),
            ("windbgx_script", &self.windbgx_script),
            ("interrupts.classic", &self.interrupts.classic),
            ("interrupts.windbgx", &self.interrupts.windbgx),
            ("resets.classic", &self.resets.classic),
            ("resets.windbgx", &self.resets.windbgx),
        ] {
            preflight_command_program(name, command)?;
        }
        Ok(())
    }

    fn expected_vm_id(&self) -> &str {
        self.open["vm_id"].as_str().expect("validated vm id")
    }

    fn open_arguments(&self) -> Value {
        Value::Object(self.open.clone())
    }

    fn frontend_path(&self, frontend: Frontend) -> &str {
        match frontend {
            Frontend::Classic => &self.frontends.classic,
            Frontend::WinDbgX => &self.frontends.windbgx,
        }
    }

    fn policy_path(&self, backend: BreakpointBackend) -> &str {
        match backend {
            BreakpointBackend::Hardware => &self.policies.hardware,
            BreakpointBackend::Int3 => &self.policies.int3,
        }
    }

    fn interrupt_command(&self, frontend: Frontend, pid: u32) -> Vec<String> {
        let template = match frontend {
            Frontend::Classic => &self.interrupts.classic,
            Frontend::WinDbgX => &self.interrupts.windbgx,
        };
        template
            .iter()
            .map(|argument| argument.replace("{pid}", &pid.to_string()))
            .collect()
    }

    fn windbgx_script_command(&self, pid: u32, command: &str) -> Vec<String> {
        self.windbgx_script
            .iter()
            .map(|argument| {
                argument
                    .replace("{pid}", &pid.to_string())
                    .replace("{command}", command)
            })
            .collect()
    }

    fn reset_command(&self, frontend: Frontend, pid: u32) -> Vec<String> {
        let template = match frontend {
            Frontend::Classic => &self.resets.classic,
            Frontend::WinDbgX => &self.resets.windbgx,
        };
        template
            .iter()
            .map(|argument| argument.replace("{pid}", &pid.to_string()))
            .collect()
    }

    fn artifact_directory(&self) -> &Path {
        Path::new(&self.artifact_dir)
    }
}

fn preflight_command_program(name: &str, command: &[String]) -> Result<(), String> {
    let program = command.first().expect("validated command is nonempty");
    if program.contains(['\\', '/']) || Path::new(program).is_absolute() {
        if Path::new(program).is_file() {
            return Ok(());
        }
        return Err(format!(
            "M8.2a `{name}` command program is not a file: {program}"
        ));
    }
    let located = Command::new("where.exe")
        .arg(program)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("locating M8.2a `{name}` command program {program}: {error}"))?;
    if located.success() {
        Ok(())
    } else {
        Err(format!(
            "M8.2a `{name}` command program is not on PATH: {program}"
        ))
    }
}

fn validate_command(name: &str, command: &[String]) -> Result<(), String> {
    if command.is_empty() || command.iter().any(|part| part.trim().is_empty()) {
        return Err(format!(
            "M8.2a `{name}` must be a nonempty command array with no empty element"
        ));
    }
    Ok(())
}

fn validate_debugger_atom(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.contains('!')
        || value
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, ';' | '\r' | '\n'))
    {
        return Err(format!(
            "M8.2a `{name}` must be one qualified debugger expression with no command separator"
        ));
    }
    Ok(())
}

pub(crate) fn validate_policy_pair(hardware: &Value, int3: &Value) -> Result<(), String> {
    let allows_writes = |name: &str, document: &Value| -> Result<bool, String> {
        let object = document
            .as_object()
            .ok_or_else(|| format!("M8.2a {name} policy is not a JSON object"))?;
        match object.get("allow_memory_writes") {
            None => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            Some(_) => Err(format!(
                "M8.2a {name} policy has non-boolean `allow_memory_writes`"
            )),
        }
    };
    if allows_writes("hardware", hardware)? {
        return Err("M8.2a hardware policy must not allow memory writes".into());
    }
    if !allows_writes("INT3", int3)? {
        return Err("M8.2a INT3 policy must set `allow_memory_writes: true`".into());
    }
    let disposable = hardware
        .get("disposable_vm_ids")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| "M8.2a policies must admit a nonempty disposable VM set".to_string())?;
    if disposable
        .iter()
        .any(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err("M8.2a disposable VM ids must be nonempty strings".into());
    }
    let mut hardware_without_write = hardware.as_object().expect("validated object").clone();
    let mut int3_without_write = int3.as_object().expect("validated object").clone();
    hardware_without_write.remove("allow_memory_writes");
    int3_without_write.remove("allow_memory_writes");
    if hardware_without_write != int3_without_write {
        return Err(
            "M8.2a policies may differ only in the INT3 policy's `allow_memory_writes: true`"
                .into(),
        );
    }
    Ok(())
}

fn validate_run_id(run_id: &str) -> Result<(), String> {
    if run_id.is_empty()
        || run_id.len() > 80
        || run_id
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_')))
    {
        return Err("M8.2a run id must use 1..=80 ASCII letters, digits, `-` or `_`".into());
    }
    Ok(())
}

pub(crate) fn breakpoint_script(
    run_id: &str,
    breakpoint: &str,
    backend: BreakpointBackend,
    cycles: usize,
) -> Result<String, String> {
    validate_run_id(run_id)?;
    validate_debugger_atom("breakpoint", breakpoint)?;
    if cycles != BREAKPOINT_CYCLES {
        return Err(format!(
            "M8.2a breakpoint qualification is fixed at {BREAKPOINT_CYCLES} cycles, got {cycles}"
        ));
    }
    let mut script = format!(".echo WINDBG_MCP_M8_READY {run_id}\n");
    append_debugger_probe(&mut script, run_id, "before", breakpoint);
    script.push_str(&format!(
        ".for (r @$t0=0; @$t0 < 0n{cycles}; r @$t0=@$t0+1) {{\n\
         bp {breakpoint}\n\
         bl\n\
         .printf \"WINDBG_MCP_M8_ARM {run_id} %03d\\n\", @$t0\n\
         g\n\
         .printf \"WINDBG_MCP_M8_HIT {run_id} %03d\\n\", @$t0\n\
         bc *\n\
         }}\n"
    ));
    if backend == BreakpointBackend::Hardware {
        // Materialize five target breakpoints while the last counted hardware stop still owns its
        // displaced-instruction proof. The fifth is refused, the first four continue, and +3
        // stops the command program again before the ordinary after-probe runs.
        script.push_str(&format!(
            "bp {breakpoint}+3\n\
             bp {breakpoint}+5\n\
             bp {breakpoint}+7\n\
             bp {breakpoint}+9\n\
             bl\n\
             .echo WINDBG_MCP_EXPECT_FIFTH_BREAKPOINT_REFUSAL {run_id}\n\
             bp {breakpoint}+17\n\
             g\n\
             .echo WINDBG_MCP_FIFTH_BREAKPOINT_RESUMED {run_id}\n\
             bc *\n"
        ));
    }
    append_debugger_probe(&mut script, run_id, "after", breakpoint);
    script.push_str(&format!(".echo WINDBG_MCP_M8_COMPLETE {run_id}\n"));
    // A refused arbitrary write is terminal in a `$><` command program. The runner waits for the
    // facade log after the complete marker, so the marker cannot race session teardown.
    if backend == BreakpointBackend::Int3 {
        script.push_str(&format!(
            ".echo WINDBG_MCP_EXPECT_WRITE_REFUSAL {run_id}\n\
             eb {breakpoint} 90\n"
        ));
    }
    Ok(script)
}

fn append_debugger_probe(script: &mut String, run_id: &str, phase: &str, breakpoint: &str) {
    script.push_str(&format!(
        ".echo WINDBG_MCP_PROBE_{phase}_BEGIN {run_id}\n\
         r\n\
         db {breakpoint} L10\n\
         lm m securekernel\n\
         x {breakpoint}\n\
         k 4\n\
         u {breakpoint} L4\n\
         t\n\
         .echo WINDBG_MCP_PROBE_{phase}_STEPPED {run_id}\n\
         .echo WINDBG_MCP_PROBE_{phase}_END {run_id}\n"
    ));
}

fn validate_debugger_probes(transcript: &str, run_id: &str) -> Result<(), String> {
    let mut expected = Vec::new();
    for phase in ["before", "after"] {
        for marker in ["BEGIN", "STEPPED", "END"] {
            expected.push(format!("WINDBG_MCP_PROBE_{phase}_{marker} {run_id}"));
        }
    }
    let observed = transcript
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("WINDBG_MCP_PROBE_"))
        .collect::<Vec<_>>();
    if observed.len() != expected.len()
        || observed
            .iter()
            .zip(&expected)
            .any(|(observed, expected)| *observed != expected)
    {
        return Err(format!(
            "debugger probe markers were missing, duplicated or reordered: observed {observed:?}"
        ));
    }
    if !transcript.contains("rax=") {
        return Err("debugger probes produced no register bank".into());
    }
    let module = transcript.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next().is_some_and(debugger_hex)
            && fields.next().is_some_and(debugger_hex)
            && fields.next() == Some("securekernel")
    });
    if !module {
        return Err("debugger probes did not enumerate the Secure Kernel module".into());
    }
    let symbolized = transcript
        .lines()
        .filter(|line| {
            line.contains("securekernel!")
                && line.split_whitespace().any(debugger_hex)
                && !line.trim_start().starts_with(['x', 'u', 'b', 'd'])
        })
        .count();
    if symbolized < 2 {
        return Err(format!(
            "debugger probes produced only {symbolized} symbolized Secure Kernel rows"
        ));
    }
    Ok(())
}

fn debugger_hex(value: &str) -> bool {
    let value = value
        .trim_start_matches("0x")
        .trim_end_matches(':')
        .replace('`', "");
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_facade_evidence(facade_log: &str, backend: BreakpointBackend) -> Result<(), String> {
    let kind = match backend {
        BreakpointBackend::Hardware => "hardware",
        BreakpointBackend::Int3 => "software",
    };
    let goes = facade_log
        .matches(&format!("KD go to 1 {kind} breakpoint(s)"))
        .count();
    let restores = facade_log
        .matches(&format!("KD restored the hit {kind}-breakpoint handle"))
        .count();
    if goes < BREAKPOINT_CYCLES || restores < BREAKPOINT_CYCLES {
        return Err(format!(
            "facade log proves {goes} {kind} breakpoint runs and {restores} restorations, expected at least {BREAKPOINT_CYCLES}"
        ));
    }
    let expected_refusal = match backend {
        BreakpointBackend::Hardware => "all four VTL1 hardware-breakpoint slots are in use",
        BreakpointBackend::Int3 => "KD API 0x3131 is not implemented",
    };
    let refusals = facade_log.matches(expected_refusal).count();
    if refusals != 1 {
        return Err(format!(
            "facade log proves {refusals} terminal `{expected_refusal}` refusals, expected 1"
        ));
    }
    let traces = facade_log.matches("trace=true").count();
    if traces < 2 {
        return Err(format!(
            "facade log proves {traces} generic single steps, expected at least 2"
        ));
    }
    if !facade_log.contains("KD virtual read ") {
        return Err("facade log proves no live virtual memory read".into());
    }
    if facade_log.contains("KD go refused") {
        return Err("facade refused a debugger go during the breakpoint arm".into());
    }
    if backend == BreakpointBackend::Hardware {
        let restored_capacity_handles = (1..=4)
            .filter(|handle| {
                facade_log.contains(&format!("KD restored breakpoint handle {handle} at"))
            })
            .count();
        if restored_capacity_handles != 4 {
            return Err(format!(
                "facade log proves {restored_capacity_handles} restored capacity handles, expected 4"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TranscriptProgress {
    pub(crate) ready: bool,
    pub(crate) armed_cycle: Option<usize>,
    pub(crate) completed_cycles: usize,
    pub(crate) complete: bool,
}

pub(crate) fn transcript_progress(
    transcript: &str,
    run_id: &str,
    cycles: usize,
) -> Result<TranscriptProgress, String> {
    cycle_progress(transcript, run_id, cycles, "WINDBG_MCP_M8", "breakpoint")
}

pub(crate) fn free_run_script(run_id: &str, cycles: usize) -> Result<String, String> {
    validate_run_id(run_id)?;
    if cycles != FREE_RUN_CYCLES {
        return Err(format!(
            "M8.2a free-run qualification is fixed at {FREE_RUN_CYCLES} cycles, got {cycles}"
        ));
    }
    // The managed facade opens on a redirected hardware-breakpoint stop. Its slot-0
    // KSPECIAL disarm is intentionally trace-only, so consume that retained stop before
    // asking an ordinary `g` to enter the free-run loop.
    let mut script = format!(
        ".echo WINDBG_MCP_INITIAL_TRACE_FREE_BEGIN {run_id}\n\
         t\n\
         .echo WINDBG_MCP_INITIAL_TRACE_FREE_END {run_id}\n\
         .echo WINDBG_MCP_M8_FREE_READY {run_id}\n"
    );
    script.push_str(&format!(
        ".for (r @$t0=0; @$t0 < 0n{cycles}; r @$t0=@$t0+1) {{\n\
         .printf \"WINDBG_MCP_M8_FREE_ARM {run_id} %03d\\n\", @$t0\n\
         g\n\
         .printf \"WINDBG_MCP_M8_FREE_HIT {run_id} %03d\\n\", @$t0\n\
         }}\n"
    ));
    script.push_str(&format!(".echo WINDBG_MCP_M8_FREE_COMPLETE {run_id}\n"));
    Ok(script)
}

pub(crate) fn free_run_progress(
    transcript: &str,
    run_id: &str,
    cycles: usize,
) -> Result<TranscriptProgress, String> {
    cycle_progress(transcript, run_id, cycles, "WINDBG_MCP_M8_FREE", "free-run")
}

fn cycle_progress(
    transcript: &str,
    run_id: &str,
    cycles: usize,
    prefix: &str,
    kind_name: &str,
) -> Result<TranscriptProgress, String> {
    validate_run_id(run_id)?;
    let ready = format!("{prefix}_READY {run_id}");
    let complete = format!("{prefix}_COMPLETE {run_id}");
    let arm_prefix = format!("{prefix}_ARM {run_id} ");
    let hit_prefix = format!("{prefix}_HIT {run_id} ");
    let mut progress = TranscriptProgress {
        ready: false,
        armed_cycle: None,
        completed_cycles: 0,
        complete: false,
    };
    // WinDbg writes `.printf` output to its log incrementally. A concurrent read can therefore
    // end after the marker text but before its numeric suffix or newline. Only newline-terminated
    // records are evidence; the next poll will see the completed final line.
    for line in transcript
        .split_inclusive('\n')
        .filter_map(|line| line.strip_suffix('\n'))
        .map(str::trim)
    {
        if !line.starts_with(&format!("{prefix}_")) {
            continue;
        }
        if line == ready {
            if progress.ready
                || progress.armed_cycle.is_some()
                || progress.completed_cycles != 0
                || progress.complete
            {
                return Err(format!(
                    "M8.2a {kind_name} transcript repeated or reordered its ready marker"
                ));
            }
            progress.ready = true;
            continue;
        }
        if line == complete {
            if !progress.ready
                || progress.armed_cycle.is_some()
                || progress.completed_cycles != cycles
                || progress.complete
            {
                return Err(format!(
                    "M8.2a {kind_name} transcript completed before every ordered hit"
                ));
            }
            progress.complete = true;
            continue;
        }
        let (kind, suffix) = if let Some(suffix) = line.strip_prefix(&arm_prefix) {
            ("arm", suffix)
        } else if let Some(suffix) = line.strip_prefix(&hit_prefix) {
            ("hit", suffix)
        } else {
            return Err(format!(
                "M8.2a {kind_name} transcript contains a marker from another or malformed run: `{line}`"
            ));
        };
        let cycle = suffix.parse::<usize>().map_err(|_| {
            format!("M8.2a {kind_name} transcript has malformed {kind} cycle `{suffix}`")
        })?;
        if !progress.ready || progress.complete || cycle >= cycles {
            return Err(format!(
                "M8.2a {kind_name} transcript has out-of-range or out-of-phase {kind} cycle {cycle}"
            ));
        }
        match kind {
            "arm" if progress.armed_cycle.is_none() && cycle == progress.completed_cycles => {
                progress.armed_cycle = Some(cycle);
            }
            "hit" if progress.armed_cycle == Some(cycle) => {
                progress.armed_cycle = None;
                progress.completed_cycles += 1;
            }
            _ => {
                return Err(format!(
                    "M8.2a {kind_name} transcript reordered or duplicated {kind} cycle {cycle}"
                ));
            }
        }
    }
    Ok(progress)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Frontend {
    Classic,
    WinDbgX,
}

impl Frontend {
    fn slug(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::WinDbgX => "windbgx",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BreakpointBackend {
    Hardware,
    Int3,
}

impl BreakpointBackend {
    fn slug(self) -> &'static str {
        match self {
            Self::Hardware => "hardware",
            Self::Int3 => "int3",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RaceScenario {
    NaturalStopWins,
    CtrlBreakWins,
    AlreadyStopped,
    NoHitTimeout,
    Reset,
    Disconnect,
    Reconnect,
    McpTeardown,
}

impl RaceScenario {
    fn slug(self) -> &'static str {
        match self {
            Self::NaturalStopWins => "natural-stop-wins",
            Self::CtrlBreakWins => "ctrl-break-wins",
            Self::AlreadyStopped => "already-stopped",
            Self::NoHitTimeout => "no-hit-timeout",
            Self::Reset => "reset",
            Self::Disconnect => "disconnect",
            Self::Reconnect => "reconnect",
            Self::McpTeardown => "mcp-teardown",
        }
    }

    fn starts_running(self) -> bool {
        matches!(
            self,
            Self::NaturalStopWins | Self::CtrlBreakWins | Self::NoHitTimeout | Self::McpTeardown
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RaceControl {
    TriggerAndInterrupt,
    InterruptWhileRunning,
    InterruptWhileStopped,
    AwaitIdleTimeout,
    ReconnectForReset,
    DisconnectWhileRunning,
    ReconnectAfterDisconnect,
    EndSessionWhileRunning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RaceOutcome {
    NaturalBreakpointRetained,
    RequestedBreakRetained,
    RetainedStopResent,
    IdleTimeoutReleased,
    ResetStopResent,
    ReconnectPending,
    ReconnectedStopRetained,
    TeardownReleased,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RacePlan {
    scenario: RaceScenario,
    control: RaceControl,
    expected: RaceOutcome,
}

fn race_plans() -> [RacePlan; 8] {
    [
        RacePlan {
            scenario: RaceScenario::NaturalStopWins,
            control: RaceControl::TriggerAndInterrupt,
            expected: RaceOutcome::NaturalBreakpointRetained,
        },
        RacePlan {
            scenario: RaceScenario::CtrlBreakWins,
            control: RaceControl::InterruptWhileRunning,
            expected: RaceOutcome::RequestedBreakRetained,
        },
        RacePlan {
            scenario: RaceScenario::AlreadyStopped,
            control: RaceControl::InterruptWhileStopped,
            expected: RaceOutcome::RetainedStopResent,
        },
        RacePlan {
            scenario: RaceScenario::NoHitTimeout,
            control: RaceControl::AwaitIdleTimeout,
            expected: RaceOutcome::IdleTimeoutReleased,
        },
        RacePlan {
            scenario: RaceScenario::Reset,
            control: RaceControl::ReconnectForReset,
            expected: RaceOutcome::ResetStopResent,
        },
        RacePlan {
            scenario: RaceScenario::Disconnect,
            control: RaceControl::DisconnectWhileRunning,
            expected: RaceOutcome::ReconnectPending,
        },
        RacePlan {
            scenario: RaceScenario::Reconnect,
            control: RaceControl::ReconnectAfterDisconnect,
            expected: RaceOutcome::ReconnectedStopRetained,
        },
        RacePlan {
            scenario: RaceScenario::McpTeardown,
            control: RaceControl::EndSessionWhileRunning,
            expected: RaceOutcome::TeardownReleased,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BootIdentity {
    pub(crate) vm_id: String,
    pub(crate) boot_id: String,
    pub(crate) vmwp_pid: u32,
    pub(crate) vp_count: u32,
    pub(crate) heartbeat_ok: bool,
}

impl BootIdentity {
    fn validate_for(&self, vm_id: &str) -> Result<(), String> {
        if !self.vm_id.eq_ignore_ascii_case(vm_id) {
            return Err(format!(
                "M8.2a boot probe answered for VM {}, expected {vm_id}",
                self.vm_id
            ));
        }
        if self.boot_id.trim().is_empty() || self.vmwp_pid == 0 {
            return Err("M8.2a boot probe omitted its boot id or vmwp PID".into());
        }
        if self.vp_count != 1 {
            return Err(format!(
                "M8.2a qualification requires one VP, probe reported {}",
                self.vp_count
            ));
        }
        if !self.heartbeat_ok {
            return Err("M8.2a boot probe did not report a healthy heartbeat".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ArmArtifact {
    pub(crate) schema: String,
    pub(crate) run_id: String,
    pub(crate) frontend: Frontend,
    pub(crate) backend: BreakpointBackend,
    pub(crate) requested_cycles: usize,
    pub(crate) completed_cycles: usize,
    pub(crate) boot_before: BootIdentity,
    pub(crate) boot_after: Option<BootIdentity>,
    pub(crate) transcript: String,
    pub(crate) facade_log: String,
    pub(crate) trigger: Option<TriggerOutcome>,
    pub(crate) audit: Option<Value>,
    pub(crate) failures: Vec<String>,
    pub(crate) verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TriggerOutcome {
    pub(crate) status: String,
    pub(crate) success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Verdict {
    Incomplete,
    Pass,
    Fail,
}

impl ArmArtifact {
    pub(crate) fn new(
        run_id: String,
        frontend: Frontend,
        backend: BreakpointBackend,
        boot_before: BootIdentity,
        transcript: String,
    ) -> Result<Self, String> {
        validate_run_id(&run_id)?;
        Ok(Self {
            schema: ARTIFACT_SCHEMA.into(),
            run_id,
            frontend,
            backend,
            requested_cycles: BREAKPOINT_CYCLES,
            completed_cycles: 0,
            boot_before,
            boot_after: None,
            transcript,
            facade_log: String::new(),
            trigger: None,
            audit: None,
            failures: Vec::new(),
            verdict: Verdict::Incomplete,
        })
    }

    pub(crate) fn settle(&mut self) {
        let same_boot = self.boot_after.as_ref().is_some_and(|after| {
            after == &self.boot_before
                && after.heartbeat_ok
                && after.vp_count == 1
                && after.vmwp_pid != 0
                && !after.boot_id.is_empty()
        }) && self.boot_before.heartbeat_ok
            && self.boot_before.vp_count == 1
            && self.boot_before.vmwp_pid != 0
            && !self.boot_before.boot_id.is_empty();
        let audit_passed = self
            .audit
            .as_ref()
            .and_then(|audit| audit.get("result"))
            .and_then(Value::as_str)
            == Some("pass");
        let trigger_recorded = self.trigger.is_some();
        if self.completed_cycles == self.requested_cycles
            && same_boot
            && audit_passed
            && trigger_recorded
            && self.failures.is_empty()
        {
            self.verdict = Verdict::Pass;
        } else {
            if self.completed_cycles != self.requested_cycles {
                self.failures.push(format!(
                    "completed {} of {} breakpoint cycles",
                    self.completed_cycles, self.requested_cycles
                ));
            }
            if !same_boot {
                self.failures
                    .push("boot identity changed or was not recorded after the arm".into());
            }
            if !audit_passed {
                self.failures
                    .push("post-release audit did not report `result: pass`".into());
            }
            if !trigger_recorded {
                self.failures
                    .push("counted trigger outcome was not recorded".into());
            }
            self.verdict = Verdict::Fail;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FreeRunArtifact {
    pub(crate) schema: String,
    pub(crate) run_id: String,
    pub(crate) frontend: Frontend,
    pub(crate) requested_cycles: usize,
    pub(crate) completed_cycles: usize,
    pub(crate) interrupts_requested: usize,
    pub(crate) boot_before: BootIdentity,
    pub(crate) boot_after: Option<BootIdentity>,
    pub(crate) transcript: String,
    pub(crate) facade_log: String,
    pub(crate) audit: Option<Value>,
    pub(crate) failures: Vec<String>,
    pub(crate) verdict: Verdict,
}

impl FreeRunArtifact {
    fn new(run_id: String, frontend: Frontend, boot_before: BootIdentity) -> Result<Self, String> {
        validate_run_id(&run_id)?;
        Ok(Self {
            schema: FREE_RUN_ARTIFACT_SCHEMA.into(),
            run_id,
            frontend,
            requested_cycles: FREE_RUN_CYCLES,
            completed_cycles: 0,
            interrupts_requested: 0,
            boot_before,
            boot_after: None,
            transcript: String::new(),
            facade_log: String::new(),
            audit: None,
            failures: Vec::new(),
            verdict: Verdict::Incomplete,
        })
    }

    fn settle(&mut self) {
        let same_boot = self.boot_after.as_ref().is_some_and(|after| {
            after == &self.boot_before
                && after.heartbeat_ok
                && after.vp_count == 1
                && after.vmwp_pid != 0
                && !after.boot_id.is_empty()
        }) && self.boot_before.heartbeat_ok
            && self.boot_before.vp_count == 1
            && self.boot_before.vmwp_pid != 0
            && !self.boot_before.boot_id.is_empty();
        let audit_passed = self
            .audit
            .as_ref()
            .and_then(|audit| audit.get("result"))
            .and_then(Value::as_str)
            == Some("pass");
        if self.completed_cycles == self.requested_cycles
            && self.interrupts_requested == self.requested_cycles
            && same_boot
            && audit_passed
            && self.failures.is_empty()
        {
            self.verdict = Verdict::Pass;
        } else {
            if self.completed_cycles != self.requested_cycles {
                self.failures.push(format!(
                    "completed {} of {} free-run cycles",
                    self.completed_cycles, self.requested_cycles
                ));
            }
            if self.interrupts_requested != self.requested_cycles {
                self.failures.push(format!(
                    "requested {} of {} debugger interrupts",
                    self.interrupts_requested, self.requested_cycles
                ));
            }
            if !same_boot {
                self.failures.push(
                    "boot identity changed or was not recorded after the free-run arm".into(),
                );
            }
            if !audit_passed {
                self.failures
                    .push("post-release audit did not report `result: pass`".into());
            }
            self.verdict = Verdict::Fail;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RaceArtifact {
    schema: String,
    run_id: String,
    frontend: Frontend,
    scenario: RaceScenario,
    control: RaceControl,
    expected: RaceOutcome,
    observed: Option<RaceOutcome>,
    boot_before: BootIdentity,
    boot_after: Option<BootIdentity>,
    transcript: String,
    reconnect_transcript: String,
    facade_log: String,
    audit: Option<Value>,
    failures: Vec<String>,
    verdict: Verdict,
}

impl RaceArtifact {
    fn new(
        run_id: String,
        frontend: Frontend,
        plan: RacePlan,
        boot_before: BootIdentity,
    ) -> Result<Self, String> {
        validate_run_id(&run_id)?;
        Ok(Self {
            schema: RACE_ARTIFACT_SCHEMA.into(),
            run_id,
            frontend,
            scenario: plan.scenario,
            control: plan.control,
            expected: plan.expected,
            observed: None,
            boot_before,
            boot_after: None,
            transcript: String::new(),
            reconnect_transcript: String::new(),
            facade_log: String::new(),
            audit: None,
            failures: Vec::new(),
            verdict: Verdict::Incomplete,
        })
    }

    fn settle(&mut self) {
        let same_boot = self.boot_after.as_ref().is_some_and(|after| {
            after == &self.boot_before
                && after.heartbeat_ok
                && after.vp_count == 1
                && after.vmwp_pid != 0
                && !after.boot_id.is_empty()
        }) && self.boot_before.heartbeat_ok
            && self.boot_before.vp_count == 1
            && self.boot_before.vmwp_pid != 0
            && !self.boot_before.boot_id.is_empty();
        let audit_passed = self
            .audit
            .as_ref()
            .and_then(|audit| audit.get("result"))
            .and_then(Value::as_str)
            == Some("pass");
        if self.observed == Some(self.expected)
            && same_boot
            && audit_passed
            && self.failures.is_empty()
        {
            self.verdict = Verdict::Pass;
        } else {
            if self.observed != Some(self.expected) {
                self.failures.push(format!(
                    "observed race outcome {:?}, expected {:?}",
                    self.observed, self.expected
                ));
            }
            if !same_boot {
                self.failures
                    .push("boot identity changed or was not recorded after the race row".into());
            }
            if !audit_passed {
                self.failures
                    .push("post-release audit did not report `result: pass`".into());
            }
            self.verdict = Verdict::Fail;
        }
    }
}

pub(crate) fn persist_artifact(
    directory: &Path,
    artifact: &ArmArtifact,
) -> Result<PathBuf, String> {
    persist_json_artifact(directory, &artifact.run_id, artifact)
}

fn persist_free_run_artifact(
    directory: &Path,
    artifact: &FreeRunArtifact,
) -> Result<PathBuf, String> {
    persist_json_artifact(directory, &artifact.run_id, artifact)
}

fn persist_race_artifact(directory: &Path, artifact: &RaceArtifact) -> Result<PathBuf, String> {
    persist_json_artifact(directory, &artifact.run_id, artifact)
}

fn persist_json_artifact(
    directory: &Path,
    run_id: &str,
    artifact: &impl Serialize,
) -> Result<PathBuf, String> {
    validate_run_id(run_id)?;
    fs::create_dir_all(directory).map_err(|error| {
        format!(
            "creating M8.2a artifact directory {}: {error}",
            directory.display()
        )
    })?;
    let final_path = directory.join(format!("{run_id}.json"));
    let staging_path = directory.join(format!("{run_id}.json.partial"));
    if final_path.exists() {
        return Err(format!(
            "refusing to overwrite M8.2a artifact {}",
            final_path.display()
        ));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging_path)
        .map_err(|error| {
            format!(
                "creating M8.2a staging artifact {}: {error}",
                staging_path.display()
            )
        })?;
    serde_json::to_writer_pretty(&mut file, artifact)
        .map_err(|error| format!("serializing M8.2a artifact: {error}"))?;
    file.write_all(b"\n")
        .map_err(|error| format!("finishing M8.2a artifact: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("flushing M8.2a artifact: {error}"))?;
    drop(file);
    fs::rename(&staging_path, &final_path).map_err(|error| {
        format!(
            "publishing M8.2a artifact {} from {}: {error}",
            final_path.display(),
            staging_path.display()
        )
    })?;
    Ok(final_path)
}

fn decode_boot_probe(output: &[u8], expected_vm_id: &str) -> Result<BootIdentity, String> {
    let text = std::str::from_utf8(output)
        .map_err(|error| format!("M8.2a boot probe output is not UTF-8: {error}"))?;
    let json = text
        .find('{')
        .map(|offset| &text[offset..])
        .ok_or_else(|| "M8.2a boot probe output contains no JSON object".to_string())?;
    let identity: BootIdentity = serde_json::from_str(json)
        .map_err(|error| format!("invalid M8.2a boot probe JSON: {error}"))?;
    identity.validate_for(expected_vm_id)?;
    Ok(identity)
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|message| (*message).into())
        })
        .unwrap_or_else(|| "operation panicked without a string diagnostic".into())
}

fn caught<T>(operation: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(operation)).map_err(panic_text)
}

fn run_host_command(
    command: &[String],
    what: &str,
    within: Duration,
) -> Result<std::process::Output, String> {
    let command = serde_json::to_value(command)
        .map_err(|error| format!("serializing {what} command: {error}"))?;
    caught(|| super::run_configured_command(&command, what, within))
}

fn probe_boot(config: &Config, what: &str) -> Result<BootIdentity, String> {
    let output = run_host_command(&config.boot_probe, what, Duration::from_secs(60))?;
    if !output.status.success() {
        return Err(format!(
            "{what} exited {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    decode_boot_probe(&output.stdout, config.expected_vm_id())
}

fn decode_json_output(output: &[u8], what: &str) -> Result<Value, String> {
    let text = std::str::from_utf8(output)
        .map_err(|error| format!("{what} output is not UTF-8: {error}"))?;
    let json = text
        .find('{')
        .map(|offset| &text[offset..])
        .ok_or_else(|| format!("{what} output contains no JSON object"))?;
    serde_json::from_str(json).map_err(|error| format!("invalid {what} JSON: {error}\n{json}"))
}

fn run_id(frontend: Frontend, backend: BreakpointBackend) -> String {
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!(
        "{}-{}-{}-{unique:x}",
        frontend.slug(),
        backend.slug(),
        std::process::id()
    )
}

fn free_run_id(frontend: Frontend) -> String {
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!(
        "{}-free-run-{}-{unique:x}",
        frontend.slug(),
        std::process::id()
    )
}

fn race_run_id(frontend: Frontend, scenario: RaceScenario) -> String {
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!(
        "{}-race-{}-{}-{unique:x}",
        frontend.slug(),
        scenario.slug(),
        std::process::id()
    )
}

fn connected_debugger_pid(server_log: &str) -> Option<u32> {
    const PREFIX: &str = "accepted Secure Kernel KD client PID ";
    server_log
        .lines()
        .rev()
        .find_map(|line| line.split_once(PREFIX).map(|(_, after)| after))
        .and_then(|after| after.split_whitespace().next())
        .and_then(|pid| pid.parse().ok())
}

fn wait_for_connected_debugger_pid(
    server: &super::Server,
    within: Duration,
) -> Result<u32, String> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(pid) = connected_debugger_pid(&server.stderr()) {
            return Ok(pid);
        }
        if Instant::now() >= deadline {
            return Err(
                "facade did not record the authenticated debugger PID before its control deadline"
                    .into(),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_new_connected_debugger_pid(
    server: &super::Server,
    previous: u32,
    within: Duration,
) -> Result<u32, String> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(pid) = connected_debugger_pid(&server.stderr())
            && pid != previous
        {
            return Ok(pid);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "facade did not authenticate a reconnecting debugger distinct from PID {previous}"
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn structured_tool_result(response: &Value, tool: &str) -> Result<Value, String> {
    if !response["error"].is_null() {
        return Err(format!(
            "MCP protocol error from `{tool}`: {}",
            response["error"]
        ));
    }
    let result = &response["result"];
    let structured = result["structuredContent"].clone();
    if structured.is_null() {
        return Err(format!(
            "`{tool}` returned no structured result: {}",
            result["content"]
        ));
    }
    Ok(structured)
}

fn open_managed_kd(
    server: &mut super::Server,
    config: &Config,
    session_id: &mut Option<String>,
) -> Result<String, String> {
    let response = server.call_tool(
        "open_sk_kd",
        config.open_arguments(),
        Duration::from_secs(240),
    );
    let opened = structured_tool_result(&response, "open_sk_kd")?;
    *session_id = opened["session_id"]
        .as_str()
        .or_else(|| opened["error"]["session_id"].as_str())
        .map(str::to_string);
    if opened["status"] != "ok" {
        return Err(format!("`open_sk_kd` failed: {opened}"));
    }
    let session = session_id
        .as_deref()
        .ok_or_else(|| "`open_sk_kd` succeeded without a session id".to_string())?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let phase = session_phase(server, session)?;
        match phase.as_str() {
            "waiting_for_peer" => break,
            phase if managed_kd_terminal_phase(phase) => {
                return Err(format!(
                    "managed KD entered terminal phase `{phase}` while waiting for its initial natural stop"
                ));
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "managed KD stayed in phase `{phase}` while waiting 60s for `waiting_for_peer`"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    opened["connection"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "`open_sk_kd` succeeded without its generated connection".into())
}

fn spawn_debugger(
    frontend: Frontend,
    executable: &str,
    connection: &str,
    commands: Option<&Path>,
    symbols: &str,
    transcript: &Path,
) -> Result<Child, String> {
    let mut command = Command::new(executable);
    command.args(["-k", connection]);
    if frontend == Frontend::Classic
        && let Some(commands) = commands
    {
        command.arg("-c").arg(debugger_script_command(commands));
    }
    command
        .arg("-y")
        .arg(symbols)
        .arg("-logo")
        .arg(transcript)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("launching debugger {executable}: {error}"))
}

fn debugger_script_command(commands: &Path) -> String {
    // A plain `$<` executes each source line as a separate command, so `t` or `g` ends the
    // script with "Command file caused an implicit wait". `$><` condenses the file into one
    // command block; WinDbg then defers the remaining commands until the target stops again.
    format!("$><{}", commands.display())
}

fn prepare_windbgx(
    server: &mut super::Server,
    session_id: &str,
    previous_pid: Option<u32>,
) -> Result<u32, String> {
    let pid = match previous_pid {
        Some(previous) => {
            wait_for_new_connected_debugger_pid(server, previous, Duration::from_secs(60))?
        }
        None => wait_for_connected_debugger_pid(server, Duration::from_secs(60))?,
    };
    wait_for_session_phase(server, session_id, "stopped", Duration::from_secs(60))?;
    Ok(pid)
}

fn consume_windbgx_initial_redirected_stop(
    config: &Config,
    pid: u32,
    server: &mut super::Server,
    session_id: &str,
    what: &str,
) -> Result<(), String> {
    let log_offset = server.stderr().len();
    deliver_windbgx_command(config, pid, "t", what)?;
    wait_for_server_log(
        server,
        log_offset,
        &["KD Continue api=0x313c trace=true"],
        Duration::from_secs(120),
    )?;
    wait_for_session_phase(server, session_id, "stopped", Duration::from_secs(120))?;
    Ok(())
}

fn deliver_windbgx_command(
    config: &Config,
    pid: u32,
    debugger_command: &str,
    what: &str,
) -> Result<(), String> {
    let command = config.windbgx_script_command(pid, debugger_command);
    let output = run_host_command(&command, what, Duration::from_secs(30))?;
    if !output.status.success() {
        return Err(format!(
            "{what} exited {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn write_new_file(path: &Path, contents: &str, what: &str) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .map_err(|error| format!("writing {what} {}: {error}", path.display()))
}

fn race_script(run_id: &str, scenario: RaceScenario, breakpoint: &str) -> Result<String, String> {
    validate_run_id(run_id)?;
    validate_debugger_atom("breakpoint", breakpoint)?;
    let initial_trace = scenario.starts_running().then(|| {
        format!(
            ".echo WINDBG_MCP_INITIAL_TRACE_RACE_BEGIN {run_id}\n\
             t\n\
             .echo WINDBG_MCP_INITIAL_TRACE_RACE_END {run_id}\n"
        )
    });
    let body = match scenario {
        RaceScenario::NaturalStopWins | RaceScenario::CtrlBreakWins => format!(
            "bp {breakpoint}\n.echo WINDBG_MCP_RACE_ARMED {run_id}\ng\n\
             .echo WINDBG_MCP_RACE_STOP {run_id}\nbc *\n"
        ),
        RaceScenario::NoHitTimeout => format!(
            "bp {breakpoint}\n.echo WINDBG_MCP_RACE_ARMED {run_id}\ng\n\
             .echo WINDBG_MCP_RACE_UNEXPECTED_STOP {run_id}\nbc *\n"
        ),
        RaceScenario::McpTeardown => {
            format!(".echo WINDBG_MCP_RACE_ARMED {run_id}\ng\n")
        }
        RaceScenario::AlreadyStopped
        | RaceScenario::Reset
        | RaceScenario::Disconnect
        | RaceScenario::Reconnect => {
            format!(".echo WINDBG_MCP_RACE_READY {run_id}\n")
        }
    };
    let script = format!("{}{body}", initial_trace.unwrap_or_default());
    if script.contains(".sleep") || script.lines().any(|line| line.trim() == "q") {
        return Err("M8.2a race scripts may contain neither sleeps nor debugger quit".into());
    }
    Ok(script)
}

#[allow(clippy::too_many_arguments)]
fn start_race_debugger(
    config: &Config,
    frontend: Frontend,
    server: &mut super::Server,
    session_id: &str,
    commands: &Path,
    previous_pid: Option<u32>,
    scenario: RaceScenario,
    run_id: &str,
) -> Result<Option<u32>, String> {
    if frontend == Frontend::Classic {
        return Ok(None);
    }
    let pid = prepare_windbgx(server, session_id, previous_pid)?;
    if scenario.starts_running() {
        consume_windbgx_initial_redirected_stop(
            config,
            pid,
            server,
            session_id,
            "M8.2a WinDbgX initial redirected-stop trace",
        )?;
    }
    let command = match scenario {
        RaceScenario::NaturalStopWins | RaceScenario::CtrlBreakWins => format!(
            "bp {}; .echo WINDBG_MCP_RACE_ARMED {run_id}; g",
            config.breakpoint
        ),
        RaceScenario::NoHitTimeout => format!(
            "bp {}; .echo WINDBG_MCP_RACE_ARMED {run_id}; g",
            config.breakpoint
        ),
        RaceScenario::McpTeardown => {
            format!(".echo WINDBG_MCP_RACE_ARMED {run_id}; g")
        }
        RaceScenario::AlreadyStopped
        | RaceScenario::Reset
        | RaceScenario::Disconnect
        | RaceScenario::Reconnect => debugger_script_command(commands),
    };
    deliver_windbgx_command(config, pid, &command, "M8.2a WinDbgX race command delivery")?;
    Ok(Some(pid))
}

fn wait_for_transcript_marker(
    path: &Path,
    marker: &str,
    within: Duration,
) -> Result<String, String> {
    let deadline = Instant::now() + within;
    loop {
        let transcript = fs::read_to_string(path).unwrap_or_default();
        if transcript.lines().any(|line| line.trim() == marker) {
            return Ok(transcript);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "debugger did not publish marker `{marker}` within {within:?}\n--- transcript ---\n{transcript}"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_server_log(
    server: &super::Server,
    after: usize,
    alternatives: &[&str],
    within: Duration,
) -> Result<String, String> {
    let deadline = Instant::now() + within;
    loop {
        let log = server.stderr();
        let fresh = log.get(after..).unwrap_or(&log);
        if alternatives.iter().any(|needle| fresh.contains(needle)) {
            return Ok(fresh.to_string());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "facade did not publish any of {alternatives:?} within {within:?}\n--- facade ---\n{log}"
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn session_phase(server: &mut super::Server, session_id: &str) -> Result<String, String> {
    let response = server.call_tool(
        "session_status",
        serde_json::json!({ "session_id": session_id }),
        Duration::from_secs(30),
    );
    let status = structured_tool_result(&response, "session_status")?;
    let session = status["sessions"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|session| session["session_id"] == session_id)
        .ok_or_else(|| format!("session status omitted {session_id}: {status}"))?;
    let state = &session["state"];
    if state["state"] == "secure_kernel_kd" {
        state["phase"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("managed KD state omitted its phase: {status}"))
    } else {
        state["state"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("session status omitted its state: {status}"))
    }
}

fn managed_kd_terminal_phase(phase: &str) -> bool {
    matches!(
        phase,
        "recovery_required" | "live_control_unresolved" | "released" | "failed" | "closed"
    )
}

fn wait_for_session_phase(
    server: &mut super::Server,
    session_id: &str,
    expected: &str,
    within: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + within;
    loop {
        let phase = session_phase(server, session_id)?;
        if phase == expected {
            return Ok(());
        }
        if managed_kd_terminal_phase(&phase) {
            return Err(format!(
                "managed KD entered terminal phase `{phase}` while waiting for `{expected}`"
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "managed KD stayed in phase `{phase}` while waiting {within:?} for `{expected}`"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn spawn_host_command(command: &[String], what: &str) -> Result<super::ConfiguredCommand, String> {
    let command = serde_json::to_value(command)
        .map_err(|error| format!("serializing {what} command: {error}"))?;
    caught(|| super::spawn_configured_command(&command, what))
}

fn successful_command(
    command: super::ConfiguredCommand,
    what: &str,
    within: Duration,
) -> Result<(), String> {
    let output = caught(|| command.wait(within))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{what} exited {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn disconnect_debugger(
    server: &super::Server,
    debugger: &mut Option<Child>,
) -> Result<u32, String> {
    let client_pid = wait_for_connected_debugger_pid(server, Duration::from_secs(5))?;
    caught(|| {
        super::terminate_process_tree(client_pid, "the M8.2a race debugger client");
        if let Some(child) = debugger.as_mut() {
            if super::still_running(child) {
                super::kill_process_tree(child, "the M8.2a race debugger launcher");
            } else {
                child.wait().expect("reap M8.2a race debugger launcher");
            }
        }
    })?;
    *debugger = None;
    Ok(client_pid)
}

fn wait_for_no_hit_timeout(
    server: &super::Server,
    transcript_path: &Path,
    unexpected_marker: &str,
    after: usize,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let transcript = fs::read_to_string(transcript_path).unwrap_or_default();
        if transcript
            .lines()
            .any(|line| line.trim() == unexpected_marker)
        {
            return Err(format!(
                "the no-hit row stopped naturally instead of reaching its running idle timeout\n--- transcript ---\n{transcript}"
            ));
        }
        let log = server.stderr();
        let fresh = log.get(after..).unwrap_or(&log);
        if fresh.contains("WinDbg sent no KD traffic before the running idle timeout") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the no-hit row produced neither a stop nor its 60-second running idle timeout\n--- facade ---\n{log}\n--- transcript ---\n{transcript}"
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[allow(clippy::too_many_arguments)]
fn drive_breakpoint_cycles(
    config: &Config,
    run_id: &str,
    transcript_path: &Path,
    artifact: &mut ArmArtifact,
    debugger: &Child,
    server: &mut super::Server,
    session_id: &str,
    backend: BreakpointBackend,
) -> Result<(), String> {
    let deadline = Instant::now() + BREAKPOINT_ARM_TIMEOUT;
    let mut trigger = None;
    let mut next_phase_check = Instant::now();
    loop {
        let transcript = fs::read_to_string(transcript_path).unwrap_or_default();
        artifact.transcript.clone_from(&transcript);
        let progress = transcript_progress(&transcript, run_id, BREAKPOINT_CYCLES)?;
        artifact.completed_cycles = progress.completed_cycles;
        if trigger.is_none() && progress.armed_cycle == Some(0) {
            let command = serde_json::to_value(config.counted_trigger())
                .map_err(|error| format!("serializing counted trigger: {error}"))?;
            trigger = Some(super::spawn_configured_command(
                &command,
                "M8.2a counted trigger",
            ));
        }
        if progress.complete {
            validate_debugger_probes(&transcript, run_id)?;
            let expected_refusal = match backend {
                BreakpointBackend::Hardware => "all four VTL1 hardware-breakpoint slots are in use",
                BreakpointBackend::Int3 => "KD API 0x3131 is not implemented",
            };
            wait_for_server_log(server, 0, &[expected_refusal], Duration::from_secs(30))?;
            break;
        }
        if transcript.contains("Command file execution failed") {
            return Err(format!(
                "debugger command file failed before completing the breakpoint arm\n--- transcript ---\n{transcript}"
            ));
        }
        if !super::still_running(debugger) {
            return Err(format!(
                "debugger exited before completing the breakpoint arm\n--- transcript ---\n{transcript}"
            ));
        }
        if Instant::now() >= next_phase_check {
            let phase = session_phase(server, session_id)?;
            if managed_kd_terminal_phase(&phase) {
                return Err(format!(
                    "managed KD entered terminal phase `{phase}` after {} of {BREAKPOINT_CYCLES} breakpoint cycles",
                    artifact.completed_cycles
                ));
            }
            next_phase_check = Instant::now() + Duration::from_secs(1);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "debugger did not complete {BREAKPOINT_CYCLES} breakpoint cycles within {} minutes",
                BREAKPOINT_ARM_TIMEOUT.as_secs() / 60
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let trigger =
        trigger.ok_or_else(|| "debugger completed without arming cycle zero".to_string())?;
    let output = caught(|| trigger.wait(Duration::from_secs(120)))?;
    artifact.trigger = Some(TriggerOutcome {
        status: output.status.to_string(),
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    });
    eprintln!(
        "--- M8.2a counted trigger ({}, 100 ordered target hits observed) ---\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn qualification_wait(
    deadline: Instant,
    ceiling: Duration,
    what: &str,
) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(ceiling))
        .ok_or_else(|| {
            format!(
                "M8.2a WinDbgX qualification exceeded {} minutes while waiting for {what}",
                BREAKPOINT_ARM_TIMEOUT.as_secs() / 60
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn run_windbgx_probe(
    config: &Config,
    pid: u32,
    run_id: &str,
    phase: &str,
    breakpoint: &str,
    ready: bool,
    transcript_path: &Path,
    server: &mut super::Server,
    session_id: &str,
    deadline: Instant,
) -> Result<(), String> {
    let ready = if ready {
        format!(".echo WINDBG_MCP_M8_READY {run_id}; ")
    } else {
        String::new()
    };
    let command = format!(
        "{ready}.echo WINDBG_MCP_PROBE_{phase}_BEGIN {run_id}; r; db {breakpoint} L10; lm m securekernel; x {breakpoint}; k 4; u {breakpoint} L4; t"
    );
    let log_offset = server.stderr().len();
    deliver_windbgx_command(
        config,
        pid,
        &command,
        &format!("M8.2a WinDbgX {phase} probe and terminal single-step"),
    )?;
    wait_for_server_log(
        server,
        log_offset,
        &["KD Continue api=0x313c trace=true"],
        qualification_wait(deadline, Duration::from_secs(120), "a generic single-step")?,
    )?;
    wait_for_session_phase(
        server,
        session_id,
        "stopped",
        qualification_wait(deadline, Duration::from_secs(120), "the single-step stop")?,
    )?;
    let end_marker = format!("WINDBG_MCP_PROBE_{phase}_END {run_id}");
    deliver_windbgx_command(
        config,
        pid,
        &format!(".echo WINDBG_MCP_PROBE_{phase}_STEPPED {run_id}; .echo {end_marker}"),
        &format!("M8.2a WinDbgX {phase} post-step markers"),
    )?;
    wait_for_transcript_marker(
        transcript_path,
        &end_marker,
        qualification_wait(deadline, Duration::from_secs(30), "the post-step marker")?,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn drive_windbgx_breakpoint_cycles(
    config: &Config,
    pid: u32,
    run_id: &str,
    transcript_path: &Path,
    artifact: &mut ArmArtifact,
    debugger: &Child,
    server: &mut super::Server,
    session_id: &str,
    backend: BreakpointBackend,
) -> Result<(), String> {
    let deadline = Instant::now() + BREAKPOINT_ARM_TIMEOUT;
    run_windbgx_probe(
        config,
        pid,
        run_id,
        "before",
        &config.breakpoint,
        true,
        transcript_path,
        server,
        session_id,
        deadline,
    )?;

    let kind = match backend {
        BreakpointBackend::Hardware => "hardware",
        BreakpointBackend::Int3 => "software",
    };
    let mut trigger = None;
    for cycle in 0..BREAKPOINT_CYCLES {
        if !super::still_running(debugger) {
            return Err(format!(
                "WinDbgX exited before breakpoint cycle {cycle} of {BREAKPOINT_CYCLES}"
            ));
        }
        let armed = format!("WINDBG_MCP_M8_ARM {run_id} {cycle:03}");
        let hit = format!("WINDBG_MCP_M8_HIT {run_id} {cycle:03}");
        let log_offset = server.stderr().len();
        deliver_windbgx_command(
            config,
            pid,
            &format!("bc *; bp {}; bl; .echo {armed}; g", config.breakpoint),
            &format!("M8.2a WinDbgX breakpoint arm {cycle:03}"),
        )?;
        wait_for_transcript_marker(
            transcript_path,
            &armed,
            qualification_wait(deadline, Duration::from_secs(30), "an arm marker")?,
        )?;
        wait_for_server_log(
            server,
            log_offset,
            &[&format!("KD go to 1 {kind} breakpoint(s)")],
            qualification_wait(deadline, Duration::from_secs(30), "the breakpoint go")?,
        )?;
        if trigger.is_none() {
            let command = serde_json::to_value(config.counted_trigger())
                .map_err(|error| format!("serializing counted trigger: {error}"))?;
            trigger = Some(super::spawn_configured_command(
                &command,
                "M8.2a counted trigger",
            ));
        }
        wait_for_server_log(
            server,
            log_offset,
            &[&format!("KD restored the hit {kind}-breakpoint handle")],
            qualification_wait(deadline, Duration::from_secs(120), "the breakpoint hit")?,
        )?;
        wait_for_session_phase(
            server,
            session_id,
            "stopped",
            qualification_wait(
                deadline,
                Duration::from_secs(30),
                "the retained breakpoint stop",
            )?,
        )?;
        deliver_windbgx_command(
            config,
            pid,
            &format!(".echo {hit}"),
            &format!("M8.2a WinDbgX breakpoint hit marker {cycle:03}"),
        )?;
        let transcript = wait_for_transcript_marker(
            transcript_path,
            &hit,
            qualification_wait(deadline, Duration::from_secs(30), "a hit marker")?,
        )?;
        artifact.transcript = transcript;
        artifact.completed_cycles = cycle + 1;
    }

    let expected_refusal = match backend {
        BreakpointBackend::Hardware => "all four VTL1 hardware-breakpoint slots are in use",
        BreakpointBackend::Int3 => "KD API 0x3131 is not implemented",
    };
    if backend == BreakpointBackend::Hardware {
        let log_offset = server.stderr().len();
        let capacity_marker = format!("WINDBG_MCP_EXPECT_FIFTH_BREAKPOINT_REFUSAL {run_id}");
        deliver_windbgx_command(
            config,
            pid,
            &format!(
                "bc *; bp {}+3; bp {}+5; bp {}+7; bp {}+9; bl; .echo {capacity_marker}; bp {}+17",
                config.breakpoint,
                config.breakpoint,
                config.breakpoint,
                config.breakpoint,
                config.breakpoint,
            ),
            "M8.2a WinDbgX hardware-breakpoint capacity probe",
        )?;
        wait_for_transcript_marker(
            transcript_path,
            &capacity_marker,
            qualification_wait(deadline, Duration::from_secs(30), "the capacity marker")?,
        )?;
        let resume_offset = server.stderr().len();
        deliver_windbgx_command(config, pid, "g", "M8.2a WinDbgX terminal capacity-probe go")?;
        wait_for_server_log(
            server,
            log_offset,
            &[expected_refusal],
            qualification_wait(deadline, Duration::from_secs(30), "the fifth-slot refusal")?,
        )?;
        wait_for_server_log(
            server,
            resume_offset,
            &["reason=SingleStep"],
            qualification_wait(
                deadline,
                Duration::from_secs(120),
                "the displaced-instruction stop",
            )?,
        )?;
        wait_for_session_phase(
            server,
            session_id,
            "stopped",
            qualification_wait(
                deadline,
                Duration::from_secs(30),
                "the displaced-instruction stop",
            )?,
        )?;
        deliver_windbgx_command(
            config,
            pid,
            &format!(".echo WINDBG_MCP_FIFTH_BREAKPOINT_RESUMED {run_id}; bc *"),
            "M8.2a WinDbgX capacity-probe cleanup",
        )?;
    }

    run_windbgx_probe(
        config,
        pid,
        run_id,
        "after",
        &config.breakpoint,
        false,
        transcript_path,
        server,
        session_id,
        deadline,
    )?;
    let complete = format!("WINDBG_MCP_M8_COMPLETE {run_id}");
    let log_offset = server.stderr().len();
    let final_command = if backend == BreakpointBackend::Int3 {
        format!(
            ".echo {complete}; .echo WINDBG_MCP_EXPECT_WRITE_REFUSAL {run_id}; eb {} 90",
            config.breakpoint
        )
    } else {
        format!(".echo {complete}")
    };
    deliver_windbgx_command(
        config,
        pid,
        &final_command,
        "M8.2a WinDbgX qualification completion",
    )?;
    let transcript = wait_for_transcript_marker(
        transcript_path,
        &complete,
        qualification_wait(deadline, Duration::from_secs(30), "the complete marker")?,
    )?;
    if backend == BreakpointBackend::Int3 {
        wait_for_server_log(
            server,
            log_offset,
            &[expected_refusal],
            qualification_wait(deadline, Duration::from_secs(30), "the terminal refusal")?,
        )?;
    }
    artifact.transcript = transcript.clone();
    let progress = transcript_progress(&transcript, run_id, BREAKPOINT_CYCLES)?;
    artifact.completed_cycles = progress.completed_cycles;
    if !progress.complete {
        return Err("WinDbgX did not publish the breakpoint-arm completion marker".into());
    }
    validate_debugger_probes(&transcript, run_id)?;

    let trigger =
        trigger.ok_or_else(|| "WinDbgX completed without arming cycle zero".to_string())?;
    let output = caught(|| trigger.wait(Duration::from_secs(120)))?;
    artifact.trigger = Some(TriggerOutcome {
        status: output.status.to_string(),
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    });
    eprintln!(
        "--- M8.2a counted trigger ({}, 100 ordered target hits observed) ---\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn drive_interactive_free_run_cycles(
    config: &Config,
    frontend: Frontend,
    pid: u32,
    run_id: &str,
    transcript_path: &Path,
    server: &mut super::Server,
    session_id: &str,
    artifact: &mut FreeRunArtifact,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10 * 60);
    consume_windbgx_initial_redirected_stop(
        config,
        pid,
        server,
        session_id,
        "M8.2a WinDbgX free-run initial redirected-stop trace",
    )?;
    let ready = format!("WINDBG_MCP_M8_FREE_READY {run_id}");
    deliver_windbgx_command(
        config,
        pid,
        &format!(".echo {ready}"),
        "M8.2a WinDbgX free-run ready marker",
    )?;
    wait_for_transcript_marker(transcript_path, &ready, Duration::from_secs(30))?;

    for cycle in 0..FREE_RUN_CYCLES {
        if Instant::now() >= deadline {
            return Err(format!(
                "WinDbgX did not complete {FREE_RUN_CYCLES} free-run/Ctrl+Break cycles within 10 minutes"
            ));
        }
        let armed = format!("WINDBG_MCP_M8_FREE_ARM {run_id} {cycle:03}");
        let hit = format!("WINDBG_MCP_M8_FREE_HIT {run_id} {cycle:03}");
        let log_offset = server.stderr().len();
        deliver_windbgx_command(
            config,
            pid,
            &format!(".echo {armed}; g"),
            &format!("M8.2a WinDbgX free-run arm {cycle:03}"),
        )?;
        wait_for_transcript_marker(transcript_path, &armed, Duration::from_secs(30))?;
        wait_for_server_log(
            server,
            log_offset,
            &["KD go with no breakpoint"],
            Duration::from_secs(30),
        )?;
        let output = run_host_command(
            &config.interrupt_command(frontend, pid),
            "M8.2a debugger interrupt",
            Duration::from_secs(30),
        )?;
        if !output.status.success() {
            return Err(format!(
                "{:?} interrupt for cycle {cycle} exited {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                frontend,
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        artifact.interrupts_requested += 1;
        wait_for_server_log(
            server,
            log_offset,
            &["KD break-in woke the running wait"],
            Duration::from_secs(30),
        )?;
        wait_for_session_phase(server, session_id, "stopped", Duration::from_secs(30))?;
        deliver_windbgx_command(
            config,
            pid,
            &format!(".echo {hit}"),
            &format!("M8.2a WinDbgX free-run hit marker {cycle:03}"),
        )?;
        artifact.transcript =
            wait_for_transcript_marker(transcript_path, &hit, Duration::from_secs(30))?;
        artifact.completed_cycles = cycle + 1;
    }

    let complete = format!("WINDBG_MCP_M8_FREE_COMPLETE {run_id}");
    deliver_windbgx_command(
        config,
        pid,
        &format!(".echo {complete}"),
        "M8.2a WinDbgX free-run completion",
    )?;
    let transcript =
        wait_for_transcript_marker(transcript_path, &complete, Duration::from_secs(30))?;
    let progress = free_run_progress(&transcript, run_id, FREE_RUN_CYCLES)?;
    if !progress.complete {
        return Err("WinDbgX did not publish the free-run completion marker".into());
    }
    artifact.transcript = transcript;
    artifact.completed_cycles = progress.completed_cycles;
    Ok(())
}

fn validate_free_run_facade_evidence(facade_log: &str) -> Result<(), String> {
    let runs = facade_log.matches("KD go with no breakpoint").count();
    let breaks = facade_log
        .matches("KD break-in woke the running wait")
        .count();
    if runs < FREE_RUN_CYCLES || breaks < FREE_RUN_CYCLES {
        return Err(format!(
            "facade log proves {runs} free runs and {breaks} running break-ins, expected at least {FREE_RUN_CYCLES}"
        ));
    }
    Ok(())
}

fn end_managed_kd(server: &mut super::Server, session_id: &str) -> Result<(), String> {
    let response = server.call_tool(
        "end_session",
        serde_json::json!({ "session_id": session_id }),
        Duration::from_secs(240),
    );
    let ended = structured_tool_result(&response, "end_session")?;
    if ended["status"] != "ok" || ended["released"] != true {
        return Err(format!("`end_session` did not prove release: {ended}"));
    }
    Ok(())
}

fn clean_up_debugger(debugger: &mut Option<Child>, client_pid: Option<u32>) -> Result<(), String> {
    let Some(child) = debugger.as_mut() else {
        return Ok(());
    };
    caught(|| {
        if let Some(pid) = client_pid {
            super::terminate_process_tree(pid, "the M8.2a debugger client");
        }
        if super::still_running(child) {
            super::kill_process_tree(child, "the M8.2a debugger launcher");
        } else {
            child.wait().expect("reap the M8.2a debugger launcher");
        }
    })
}

fn run_breakpoint_arm(
    config: &Config,
    frontend: Frontend,
    backend: BreakpointBackend,
    boot_before: BootIdentity,
) -> ArmArtifact {
    let run_id = run_id(frontend, backend);
    let commands_path = config
        .artifact_directory()
        .join(format!("{run_id}.commands.txt"));
    let transcript_path = config
        .artifact_directory()
        .join(format!("{run_id}.windbg.log"));
    let mut artifact = ArmArtifact::new(
        run_id.clone(),
        frontend,
        backend,
        boot_before,
        String::new(),
    )
    .expect("the generated run id is valid");
    let mut server = None;
    let mut session_id = None;
    let mut debugger = None;

    let body = caught(|| {
        fs::create_dir_all(config.artifact_directory()).map_err(|error| {
            format!(
                "creating M8.2a artifact directory {}: {error}",
                config.artifact_directory().display()
            )
        })?;
        let script = breakpoint_script(&run_id, &config.breakpoint, backend, BREAKPOINT_CYCLES)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&commands_path)
            .and_then(|mut file| file.write_all(script.as_bytes()))
            .map_err(|error| {
                format!(
                    "writing M8.2a debugger commands {}: {error}",
                    commands_path.display()
                )
            })?;

        let policy = config.policy_path(backend);
        server = Some(super::Server::started_with_args(
            &[("WINDBG_MCP_SK_LIVE_POLICY", policy)],
            &["--tools", "securekernel"],
        ));
        let connection = open_managed_kd(
            server.as_mut().expect("M8.2a server was started"),
            config,
            &mut session_id,
        )?;
        debugger = Some(spawn_debugger(
            frontend,
            config.frontend_path(frontend),
            &connection,
            Some(&commands_path),
            &config.symbol_path,
            &transcript_path,
        )?);
        let server = server.as_mut().expect("M8.2a server was started");
        let session = session_id
            .as_deref()
            .expect("the M8.2a managed session was opened");
        if frontend == Frontend::Classic {
            drive_breakpoint_cycles(
                config,
                &run_id,
                &transcript_path,
                &mut artifact,
                debugger.as_ref().expect("the M8.2a debugger was started"),
                server,
                session,
                backend,
            )
        } else {
            let pid = prepare_windbgx(server, session, None)?;
            drive_windbgx_breakpoint_cycles(
                config,
                pid,
                &run_id,
                &transcript_path,
                &mut artifact,
                debugger.as_ref().expect("the M8.2a debugger was started"),
                server,
                session,
                backend,
            )
        }
    })
    .and_then(|result| result);
    if let Err(error) = body {
        artifact.failures.push(error);
    }

    let client_pid = server
        .as_ref()
        .and_then(|server| connected_debugger_pid(&server.stderr()));
    if let (Some(server), Some(session_id)) = (server.as_mut(), session_id.as_deref())
        && let Err(error) = caught(|| end_managed_kd(server, session_id)).and_then(|result| result)
    {
        artifact
            .failures
            .push(format!("MCP teardown failed: {error}"));
    }
    if let Err(error) = clean_up_debugger(&mut debugger, client_pid) {
        artifact
            .failures
            .push(format!("debugger cleanup failed: {error}"));
    }
    if let Ok(transcript) = fs::read_to_string(&transcript_path) {
        artifact.transcript = transcript;
    }
    if let Some(server) = &server {
        artifact.facade_log = server.stderr();
        eprintln!(
            "--- M8.2a facade log ({run_id}) ---\n{}",
            artifact.facade_log
        );
        if let Err(error) = validate_facade_evidence(&artifact.facade_log, backend) {
            artifact.failures.push(error);
        }
    }

    match run_host_command(
        &config.post_release_audit,
        "M8.2a post-release audit",
        Duration::from_secs(120),
    ) {
        Ok(output) => {
            if !output.status.success() {
                artifact.failures.push(format!(
                    "post-release audit exited {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            match decode_json_output(&output.stdout, "M8.2a post-release audit") {
                Ok(audit) => artifact.audit = Some(audit),
                Err(error) => artifact.failures.push(error),
            }
        }
        Err(error) => artifact
            .failures
            .push(format!("post-release audit did not run: {error}")),
    }
    match probe_boot(config, "M8.2a post-arm boot probe") {
        Ok(identity) => artifact.boot_after = Some(identity),
        Err(error) => artifact
            .failures
            .push(format!("post-arm boot probe failed: {error}")),
    }
    artifact.settle();
    artifact
}

fn run_free_run_arm(
    config: &Config,
    frontend: Frontend,
    boot_before: BootIdentity,
) -> FreeRunArtifact {
    let run_id = free_run_id(frontend);
    let commands_path = config
        .artifact_directory()
        .join(format!("{run_id}.commands.txt"));
    let transcript_path = config
        .artifact_directory()
        .join(format!("{run_id}.windbg.log"));
    let mut artifact = FreeRunArtifact::new(run_id.clone(), frontend, boot_before)
        .expect("the generated free-run id is valid");
    let mut server = None;
    let mut session_id = None;
    let mut debugger = None;

    let body = caught(|| {
        fs::create_dir_all(config.artifact_directory()).map_err(|error| {
            format!(
                "creating M8.2a artifact directory {}: {error}",
                config.artifact_directory().display()
            )
        })?;
        let script = free_run_script(&run_id, FREE_RUN_CYCLES)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&commands_path)
            .and_then(|mut file| file.write_all(script.as_bytes()))
            .map_err(|error| {
                format!(
                    "writing M8.2a free-run commands {}: {error}",
                    commands_path.display()
                )
            })?;

        server = Some(super::Server::started_with_args(
            &[(
                "WINDBG_MCP_SK_LIVE_POLICY",
                config.policy_path(BreakpointBackend::Hardware),
            )],
            &["--tools", "securekernel"],
        ));
        let connection = open_managed_kd(
            server.as_mut().expect("M8.2a free-run server was started"),
            config,
            &mut session_id,
        )?;
        debugger = Some(spawn_debugger(
            frontend,
            config.frontend_path(frontend),
            &connection,
            None,
            &config.symbol_path,
            &transcript_path,
        )?);
        let server = server.as_mut().expect("M8.2a free-run server was started");
        let session = session_id
            .as_deref()
            .expect("the M8.2a free-run session was opened");
        // A condensed `$><file` command block leaves Classic WinDbg's Break command disabled
        // while its embedded `g` is outstanding. Drive both frontends one command at a time so
        // Ctrl+Break is delivered to an ordinary interactive run.
        let pid = prepare_windbgx(server, session, None)?;
        drive_interactive_free_run_cycles(
            config,
            frontend,
            pid,
            &run_id,
            &transcript_path,
            server,
            session,
            &mut artifact,
        )
    })
    .and_then(|result| result);
    if let Err(error) = body {
        artifact.failures.push(error);
    }

    let client_pid = server
        .as_ref()
        .and_then(|server| connected_debugger_pid(&server.stderr()));
    if let (Some(server), Some(session_id)) = (server.as_mut(), session_id.as_deref())
        && let Err(error) = caught(|| end_managed_kd(server, session_id)).and_then(|result| result)
    {
        artifact
            .failures
            .push(format!("MCP teardown failed: {error}"));
    }
    if let Err(error) = clean_up_debugger(&mut debugger, client_pid) {
        artifact
            .failures
            .push(format!("debugger cleanup failed: {error}"));
    }
    if let Ok(transcript) = fs::read_to_string(&transcript_path) {
        artifact.transcript = transcript;
    }
    if let Some(server) = &server {
        artifact.facade_log = server.stderr();
        eprintln!(
            "--- M8.2a free-run facade log ({run_id}) ---\n{}",
            artifact.facade_log
        );
        if let Err(error) = validate_free_run_facade_evidence(&artifact.facade_log) {
            artifact.failures.push(error);
        }
    }

    match run_host_command(
        &config.post_release_audit,
        "M8.2a free-run post-release audit",
        Duration::from_secs(120),
    ) {
        Ok(output) => {
            if !output.status.success() {
                artifact.failures.push(format!(
                    "free-run post-release audit exited {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            match decode_json_output(&output.stdout, "M8.2a free-run post-release audit") {
                Ok(audit) => artifact.audit = Some(audit),
                Err(error) => artifact.failures.push(error),
            }
        }
        Err(error) => artifact
            .failures
            .push(format!("free-run post-release audit did not run: {error}")),
    }
    match probe_boot(config, "M8.2a post-free-run boot probe") {
        Ok(identity) => artifact.boot_after = Some(identity),
        Err(error) => artifact
            .failures
            .push(format!("post-free-run boot probe failed: {error}")),
    }
    artifact.settle();
    artifact
}

fn run_race_arm(
    config: &Config,
    frontend: Frontend,
    plan: RacePlan,
    boot_before: BootIdentity,
) -> RaceArtifact {
    let run_id = race_run_id(frontend, plan.scenario);
    let commands_path = config
        .artifact_directory()
        .join(format!("{run_id}.commands.txt"));
    let transcript_path = config
        .artifact_directory()
        .join(format!("{run_id}.windbg.log"));
    let reconnect_commands_path = config
        .artifact_directory()
        .join(format!("{run_id}.reconnect.commands.txt"));
    let reconnect_transcript_path = config
        .artifact_directory()
        .join(format!("{run_id}.reconnect.windbg.log"));
    let mut artifact = RaceArtifact::new(run_id.clone(), frontend, plan, boot_before)
        .expect("the generated race id is valid");
    let mut server = None;
    let mut session_id = None;
    let mut debugger = None;
    let mut session_ended = false;
    let mut pending_commands = Vec::<(super::ConfiguredCommand, &'static str)>::new();

    let body = caught(|| {
        fs::create_dir_all(config.artifact_directory()).map_err(|error| {
            format!(
                "creating M8.2a artifact directory {}: {error}",
                config.artifact_directory().display()
            )
        })?;
        let script = race_script(&run_id, plan.scenario, &config.breakpoint)?;
        write_new_file(&commands_path, &script, "M8.2a race commands")?;
        server = Some(super::Server::started_with_args(
            &[(
                "WINDBG_MCP_SK_LIVE_POLICY",
                config.policy_path(BreakpointBackend::Hardware),
            )],
            &["--tools", "securekernel"],
        ));
        let server = server.as_mut().expect("M8.2a race server was started");
        let connection = open_managed_kd(server, config, &mut session_id)?;
        let session = session_id
            .as_deref()
            .ok_or_else(|| "race opener returned no session id".to_string())?;
        // Classic can execute its command file as soon as the process starts, and WinDbgX can do
        // the same as soon as start_race_debugger delivers it. Bound running evidence before
        // either frontend gets that opportunity.
        let execution_log_offset = server.stderr().len();
        debugger = Some(spawn_debugger(
            frontend,
            config.frontend_path(frontend),
            &connection,
            Some(&commands_path),
            &config.symbol_path,
            &transcript_path,
        )?);
        start_race_debugger(
            config,
            frontend,
            server,
            session,
            &commands_path,
            None,
            plan.scenario,
            &run_id,
        )?;

        match plan.scenario {
            RaceScenario::NaturalStopWins | RaceScenario::CtrlBreakWins => {
                let armed = format!("WINDBG_MCP_RACE_ARMED {run_id}");
                wait_for_transcript_marker(&transcript_path, &armed, Duration::from_secs(60))?;
                let pid = wait_for_connected_debugger_pid(server, Duration::from_secs(5))?;
                let trigger = config.trigger_command(1);
                let interrupt = config.interrupt_command(frontend, pid);
                wait_for_server_log(
                    server,
                    execution_log_offset,
                    &["KD go to 1 hardware breakpoint(s)"],
                    Duration::from_secs(10),
                )?;
                if plan.scenario == RaceScenario::NaturalStopWins {
                    pending_commands.push((
                        spawn_host_command(&trigger, "M8.2a natural-wins trigger")?,
                        "M8.2a natural-wins trigger",
                    ));
                    wait_for_session_phase(server, session, "stopped", Duration::from_secs(120))?;
                    pending_commands.push((
                        spawn_host_command(&interrupt, "M8.2a natural-wins Ctrl+Break")?,
                        "M8.2a natural-wins Ctrl+Break",
                    ));
                } else {
                    pending_commands.push((
                        spawn_host_command(&interrupt, "M8.2a Ctrl+Break-wins interrupt")?,
                        "M8.2a Ctrl+Break-wins interrupt",
                    ));
                    wait_for_server_log(
                        server,
                        execution_log_offset,
                        &["KD break-in woke the running wait"],
                        Duration::from_secs(10),
                    )?;
                    wait_for_session_phase(server, session, "stopped", Duration::from_secs(30))?;
                    pending_commands.push((
                        spawn_host_command(&trigger, "M8.2a Ctrl+Break-wins trigger")?,
                        "M8.2a Ctrl+Break-wins trigger",
                    ));
                }
                let stopped = format!("WINDBG_MCP_RACE_STOP {run_id}");
                if frontend == Frontend::WinDbgX {
                    deliver_windbgx_command(
                        config,
                        pid,
                        &format!(".echo {stopped}; bc *"),
                        "M8.2a WinDbgX race stop marker and cleanup",
                    )?;
                }
                artifact.transcript = wait_for_transcript_marker(
                    &transcript_path,
                    &stopped,
                    Duration::from_secs(120),
                )?;
                if plan.scenario == RaceScenario::CtrlBreakWins {
                    artifact.observed = Some(RaceOutcome::RequestedBreakRetained);
                } else {
                    let fresh = wait_for_server_log(
                        server,
                        execution_log_offset,
                        &[
                            "target is already stopped; resending the retained stop",
                            "stop is awaiting acknowledgement; deferring it until continue",
                            "break-in already served while running",
                        ],
                        Duration::from_secs(5),
                    )?;
                    if fresh.contains("KD break-in woke the running wait") {
                        return Err(
                            "Ctrl+Break won the row reserved for the natural-stop winner".into(),
                        );
                    }
                    artifact.observed = Some(RaceOutcome::NaturalBreakpointRetained);
                }
            }
            RaceScenario::AlreadyStopped => {
                let ready = format!("WINDBG_MCP_RACE_READY {run_id}");
                artifact.transcript =
                    wait_for_transcript_marker(&transcript_path, &ready, Duration::from_secs(60))?;
                let pid = wait_for_connected_debugger_pid(server, Duration::from_secs(5))?;
                let log_offset = server.stderr().len();
                let output = run_host_command(
                    &config.interrupt_command(frontend, pid),
                    "M8.2a stopped Ctrl+Break",
                    Duration::from_secs(30),
                )?;
                if !output.status.success() {
                    return Err(format!("stopped Ctrl+Break exited {}", output.status));
                }
                wait_for_server_log(
                    server,
                    log_offset,
                    &["target is already stopped; resending the retained stop"],
                    Duration::from_secs(5),
                )?;
                artifact.observed = Some(RaceOutcome::RetainedStopResent);
            }
            RaceScenario::NoHitTimeout => {
                let armed = format!("WINDBG_MCP_RACE_ARMED {run_id}");
                wait_for_transcript_marker(&transcript_path, &armed, Duration::from_secs(60))?;
                let unexpected = format!("WINDBG_MCP_RACE_UNEXPECTED_STOP {run_id}");
                wait_for_no_hit_timeout(
                    server,
                    &transcript_path,
                    &unexpected,
                    execution_log_offset,
                )?;
                artifact.transcript = fs::read_to_string(&transcript_path).unwrap_or_default();
                artifact.observed = Some(RaceOutcome::IdleTimeoutReleased);
            }
            RaceScenario::Reset => {
                let ready = format!("WINDBG_MCP_RACE_READY {run_id}");
                artifact.transcript =
                    wait_for_transcript_marker(&transcript_path, &ready, Duration::from_secs(60))?;
                let pid = wait_for_connected_debugger_pid(server, Duration::from_secs(5))?;
                let log_offset = server.stderr().len();
                let output = run_host_command(
                    &config.reset_command(frontend, pid),
                    "M8.2a debugger reset",
                    Duration::from_secs(30),
                )?;
                if !output.status.success() {
                    return Err(format!("debugger reset exited {}", output.status));
                }
                wait_for_server_log(
                    server,
                    log_offset,
                    &["KD peer reset; current held stop resent"],
                    Duration::from_secs(10),
                )?;
                artifact.observed = Some(RaceOutcome::ResetStopResent);
            }
            RaceScenario::Disconnect => {
                let ready = format!("WINDBG_MCP_RACE_READY {run_id}");
                artifact.transcript =
                    wait_for_transcript_marker(&transcript_path, &ready, Duration::from_secs(60))?;
                disconnect_debugger(server, &mut debugger)?;
                wait_for_session_phase(server, session, "reconnecting", Duration::from_secs(15))?;
                artifact.observed = Some(RaceOutcome::ReconnectPending);
            }
            RaceScenario::Reconnect => {
                let ready = format!("WINDBG_MCP_RACE_READY {run_id}");
                artifact.transcript =
                    wait_for_transcript_marker(&transcript_path, &ready, Duration::from_secs(60))?;
                let first_pid = disconnect_debugger(server, &mut debugger)?;
                wait_for_session_phase(server, session, "reconnecting", Duration::from_secs(15))?;
                let reconnect_marker = format!("WINDBG_MCP_RACE_RECONNECTED {run_id}");
                write_new_file(
                    &reconnect_commands_path,
                    &format!(".echo {reconnect_marker}\n"),
                    "M8.2a reconnect commands",
                )?;
                debugger = Some(spawn_debugger(
                    frontend,
                    config.frontend_path(frontend),
                    &connection,
                    Some(&reconnect_commands_path),
                    &config.symbol_path,
                    &reconnect_transcript_path,
                )?);
                start_race_debugger(
                    config,
                    frontend,
                    server,
                    session,
                    &reconnect_commands_path,
                    Some(first_pid),
                    RaceScenario::Reconnect,
                    &run_id,
                )?;
                artifact.reconnect_transcript = wait_for_transcript_marker(
                    &reconnect_transcript_path,
                    &reconnect_marker,
                    Duration::from_secs(60),
                )?;
                wait_for_session_phase(server, session, "stopped", Duration::from_secs(5))?;
                artifact.observed = Some(RaceOutcome::ReconnectedStopRetained);
            }
            RaceScenario::McpTeardown => {
                let armed = format!("WINDBG_MCP_RACE_ARMED {run_id}");
                wait_for_transcript_marker(&transcript_path, &armed, Duration::from_secs(60))?;
                wait_for_server_log(
                    server,
                    execution_log_offset,
                    &["KD go with no breakpoint"],
                    Duration::from_secs(10),
                )?;
                end_managed_kd(server, session)?;
                session_ended = true;
                artifact.transcript = fs::read_to_string(&transcript_path).unwrap_or_default();
                artifact.observed = Some(RaceOutcome::TeardownReleased);
            }
        }
        Ok::<(), String>(())
    })
    .and_then(|result| result);
    if let Err(error) = body {
        artifact.failures.push(error);
    }

    if !session_ended
        && let (Some(server), Some(session_id)) = (server.as_mut(), session_id.as_deref())
        && let Err(error) = caught(|| end_managed_kd(server, session_id)).and_then(|result| result)
    {
        artifact
            .failures
            .push(format!("MCP teardown failed: {error}"));
    }
    let client_pid = server
        .as_ref()
        .and_then(|server| connected_debugger_pid(&server.stderr()));
    if let Err(error) = clean_up_debugger(&mut debugger, client_pid) {
        artifact
            .failures
            .push(format!("debugger cleanup failed: {error}"));
    }
    for (command, what) in pending_commands {
        if let Err(error) = successful_command(command, what, Duration::from_secs(120)) {
            artifact.failures.push(error);
        }
    }
    if let Ok(transcript) = fs::read_to_string(&transcript_path) {
        artifact.transcript = transcript;
    }
    if let Ok(transcript) = fs::read_to_string(&reconnect_transcript_path) {
        artifact.reconnect_transcript = transcript;
    }
    if let Some(server) = &server {
        artifact.facade_log = server.stderr();
        eprintln!(
            "--- M8.2a race facade log ({run_id}) ---\n{}",
            artifact.facade_log
        );
    }

    match run_host_command(
        &config.post_release_audit,
        "M8.2a race post-release audit",
        Duration::from_secs(120),
    ) {
        Ok(output) => {
            if !output.status.success() {
                artifact.failures.push(format!(
                    "race post-release audit exited {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            match decode_json_output(&output.stdout, "M8.2a race post-release audit") {
                Ok(audit) => artifact.audit = Some(audit),
                Err(error) => artifact.failures.push(error),
            }
        }
        Err(error) => artifact
            .failures
            .push(format!("race post-release audit did not run: {error}")),
    }
    match probe_boot(config, "M8.2a post-race boot probe") {
        Ok(identity) => artifact.boot_after = Some(identity),
        Err(error) => artifact
            .failures
            .push(format!("post-race boot probe failed: {error}")),
    }
    artifact.settle();
    artifact
}

#[test]
#[ignore = "reads the explicitly configured disposable M8 bench; set WINDBG_MCP_SMOKE_SK_KD_M8 and run alone"]
fn qualification_preflight_reads_one_healthy_static_boot() {
    let Some(path) = std::env::var_os("WINDBG_MCP_SMOKE_SK_KD_M8") else {
        eprintln!(
            "SKIPPED: set WINDBG_MCP_SMOKE_SK_KD_M8=<private M8.2a config> to preflight the qualification bench"
        );
        return;
    };
    let path = PathBuf::from(path);
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read M8.2a qualification config {}: {error}",
            path.display()
        )
    });
    let config = Config::parse(&text).unwrap_or_else(|error| panic!("{error}"));
    config
        .preflight_files()
        .unwrap_or_else(|error| panic!("{error}"));
    let command = serde_json::to_value(&config.boot_probe).expect("serialize boot probe command");
    let output =
        super::run_configured_command(&command, "M8.2a boot preflight", Duration::from_secs(60));
    assert!(
        output.status.success(),
        "M8.2a boot preflight exited {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let identity = decode_boot_probe(&output.stdout, config.expected_vm_id())
        .unwrap_or_else(|error| panic!("{error}"));
    eprintln!(
        "M8.2a preflight: VM {} boot {} vmwp {} VP count {} heartbeat OK",
        identity.vm_id, identity.boot_id, identity.vmwp_pid, identity.vp_count
    );
}

#[test]
#[ignore = "runs one destructive WinDbgX/hardware arm; set WINDBG_MCP_SMOKE_SK_KD_M8 and run alone"]
fn qualification_probe_executes_one_winbgx_hardware_arm() {
    let Some(path) = std::env::var_os("WINDBG_MCP_SMOKE_SK_KD_M8") else {
        eprintln!("SKIPPED: set WINDBG_MCP_SMOKE_SK_KD_M8=<private M8.2a config> to probe WinDbgX");
        return;
    };
    let path = PathBuf::from(path);
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read M8.2a qualification config {}: {error}",
            path.display()
        )
    });
    let config = Config::parse(&text).unwrap_or_else(|error| panic!("{error}"));
    config
        .preflight_files()
        .unwrap_or_else(|error| panic!("{error}"));
    let boot_before =
        probe_boot(&config, "M8.2a WinDbgX probe boot").unwrap_or_else(|error| panic!("{error}"));
    let artifact = run_breakpoint_arm(
        &config,
        Frontend::WinDbgX,
        BreakpointBackend::Hardware,
        boot_before,
    );
    let published = persist_artifact(config.artifact_directory(), &artifact)
        .unwrap_or_else(|error| panic!("{error}"));
    eprintln!(
        "M8.2a WinDbgX/Hardware probe: {:?}; artifact {}",
        artifact.verdict,
        published.display()
    );
    assert_eq!(
        artifact.verdict,
        Verdict::Pass,
        "M8.2a WinDbgX/Hardware probe failed: {:#?}",
        artifact.failures
    );
}

#[test]
#[ignore = "runs one destructive WinDbgX/INT3 arm; set WINDBG_MCP_SMOKE_SK_KD_M8 and run alone"]
fn qualification_probe_executes_one_winbgx_int3_arm() {
    let Some(path) = std::env::var_os("WINDBG_MCP_SMOKE_SK_KD_M8") else {
        eprintln!(
            "SKIPPED: set WINDBG_MCP_SMOKE_SK_KD_M8=<private M8.2a config> to probe WinDbgX INT3"
        );
        return;
    };
    let path = PathBuf::from(path);
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read M8.2a qualification config {}: {error}",
            path.display()
        )
    });
    let config = Config::parse(&text).unwrap_or_else(|error| panic!("{error}"));
    config
        .preflight_files()
        .unwrap_or_else(|error| panic!("{error}"));
    let boot_before = probe_boot(&config, "M8.2a WinDbgX INT3 probe boot")
        .unwrap_or_else(|error| panic!("{error}"));
    let artifact = run_breakpoint_arm(
        &config,
        Frontend::WinDbgX,
        BreakpointBackend::Int3,
        boot_before,
    );
    let published = persist_artifact(config.artifact_directory(), &artifact)
        .unwrap_or_else(|error| panic!("{error}"));
    eprintln!(
        "M8.2a WinDbgX/Int3 probe: {:?}; artifact {}",
        artifact.verdict,
        published.display()
    );
    assert_eq!(
        artifact.verdict,
        Verdict::Pass,
        "M8.2a WinDbgX/Int3 probe failed: {:#?}",
        artifact.failures
    );
}

#[test]
#[ignore = "runs one destructive Classic free-run arm; set WINDBG_MCP_SMOKE_SK_KD_M8 and run alone"]
fn qualification_probe_executes_one_classic_free_run_arm() {
    let Some(path) = std::env::var_os("WINDBG_MCP_SMOKE_SK_KD_M8") else {
        eprintln!(
            "SKIPPED: set WINDBG_MCP_SMOKE_SK_KD_M8=<private M8.2a config> to probe Classic free-run"
        );
        return;
    };
    let path = PathBuf::from(path);
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read M8.2a qualification config {}: {error}",
            path.display()
        )
    });
    let config = Config::parse(&text).unwrap_or_else(|error| panic!("{error}"));
    config
        .preflight_files()
        .unwrap_or_else(|error| panic!("{error}"));
    let boot_before = probe_boot(&config, "M8.2a Classic free-run probe boot")
        .unwrap_or_else(|error| panic!("{error}"));
    let artifact = run_free_run_arm(&config, Frontend::Classic, boot_before);
    let published = persist_free_run_artifact(config.artifact_directory(), &artifact)
        .unwrap_or_else(|error| panic!("{error}"));
    eprintln!(
        "M8.2a Classic/free-run probe: {:?}; artifact {}",
        artifact.verdict,
        published.display()
    );
    assert_eq!(
        artifact.verdict,
        Verdict::Pass,
        "M8.2a Classic/free-run probe failed: {:#?}",
        artifact.failures
    );
}

#[test]
#[ignore = "runs the destructive M8.2a free-run and race matrix; set WINDBG_MCP_SMOKE_SK_KD_M8 and run alone"]
fn qualification_runner_executes_post_breakpoint_matrix_on_one_boot() {
    let Some(path) = std::env::var_os("WINDBG_MCP_SMOKE_SK_KD_M8") else {
        eprintln!(
            "SKIPPED: set WINDBG_MCP_SMOKE_SK_KD_M8=<private M8.2a config> to run the post-breakpoint matrix"
        );
        return;
    };
    let path = PathBuf::from(path);
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read M8.2a qualification config {}: {error}",
            path.display()
        )
    });
    let config = Config::parse(&text).unwrap_or_else(|error| panic!("{error}"));
    config
        .preflight_files()
        .unwrap_or_else(|error| panic!("{error}"));
    let baseline = probe_boot(&config, "M8.2a post-breakpoint initial boot probe")
        .unwrap_or_else(|error| panic!("{error}"));

    for frontend in [Frontend::Classic, Frontend::WinDbgX] {
        let boot_before = probe_boot(&config, "M8.2a pre-free-run boot probe")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            boot_before, baseline,
            "the M8.2a boot changed before the {:?} free-run arm",
            frontend
        );
        let artifact = run_free_run_arm(&config, frontend, boot_before);
        let published = persist_free_run_artifact(config.artifact_directory(), &artifact)
            .unwrap_or_else(|error| panic!("{error}"));
        eprintln!(
            "M8.2a {:?}/free-run: {:?}; artifact {}",
            frontend,
            artifact.verdict,
            published.display()
        );
        assert_eq!(
            artifact.verdict,
            Verdict::Pass,
            "M8.2a {:?}/free-run failed: {:#?}",
            frontend,
            artifact.failures
        );
        assert_eq!(
            artifact.boot_after.as_ref(),
            Some(&baseline),
            "the M8.2a boot changed during the {:?} free-run arm",
            frontend
        );
    }

    for frontend in [Frontend::Classic, Frontend::WinDbgX] {
        for plan in race_plans() {
            let boot_before = probe_boot(&config, "M8.2a pre-race boot probe")
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(
                boot_before, baseline,
                "the M8.2a boot changed before the {:?}/{:?} race",
                frontend, plan.scenario
            );
            let artifact = run_race_arm(&config, frontend, plan, boot_before);
            let published = persist_race_artifact(config.artifact_directory(), &artifact)
                .unwrap_or_else(|error| panic!("{error}"));
            eprintln!(
                "M8.2a {:?}/{:?}: {:?}; artifact {}",
                frontend,
                plan.scenario,
                artifact.verdict,
                published.display()
            );
            assert_eq!(
                artifact.verdict,
                Verdict::Pass,
                "M8.2a {:?}/{:?} failed: {:#?}",
                frontend,
                plan.scenario,
                artifact.failures
            );
            assert_eq!(
                artifact.boot_after.as_ref(),
                Some(&baseline),
                "the M8.2a boot changed during the {:?}/{:?} race",
                frontend,
                plan.scenario
            );
        }
    }
}

fn run_breakpoint_matrix(config: &Config, baseline: &BootIdentity) {
    for (frontend, backend) in [
        (Frontend::Classic, BreakpointBackend::Hardware),
        (Frontend::Classic, BreakpointBackend::Int3),
        (Frontend::WinDbgX, BreakpointBackend::Hardware),
        (Frontend::WinDbgX, BreakpointBackend::Int3),
    ] {
        let boot_before = probe_boot(config, "M8.2a pre-arm boot probe")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            &boot_before, baseline,
            "the M8.2a boot changed before the {:?}/{:?} arm",
            frontend, backend
        );
        let artifact = run_breakpoint_arm(config, frontend, backend, boot_before);
        let published = persist_artifact(config.artifact_directory(), &artifact)
            .unwrap_or_else(|error| panic!("{error}"));
        eprintln!(
            "M8.2a {:?}/{:?}: {:?}; artifact {}",
            frontend,
            backend,
            artifact.verdict,
            published.display()
        );
        assert_eq!(
            artifact.verdict,
            Verdict::Pass,
            "M8.2a {:?}/{:?} failed: {:#?}",
            frontend,
            backend,
            artifact.failures
        );
        assert_eq!(
            artifact.boot_after.as_ref(),
            Some(baseline),
            "the M8.2a boot changed during the {:?}/{:?} arm",
            frontend,
            backend
        );
    }
}

#[test]
#[ignore = "runs the destructive M8.2a breakpoint matrix; set WINDBG_MCP_SMOKE_SK_KD_M8 and run alone"]
fn qualification_runner_executes_breakpoint_matrix_on_one_boot() {
    let Some(path) = std::env::var_os("WINDBG_MCP_SMOKE_SK_KD_M8") else {
        eprintln!(
            "SKIPPED: set WINDBG_MCP_SMOKE_SK_KD_M8=<private M8.2a config> to run the breakpoint matrix"
        );
        return;
    };
    let path = PathBuf::from(path);
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read M8.2a qualification config {}: {error}",
            path.display()
        )
    });
    let config = Config::parse(&text).unwrap_or_else(|error| panic!("{error}"));
    config
        .preflight_files()
        .unwrap_or_else(|error| panic!("{error}"));
    let baseline =
        probe_boot(&config, "M8.2a initial boot probe").unwrap_or_else(|error| panic!("{error}"));
    run_breakpoint_matrix(&config, &baseline);
}

#[test]
#[ignore = "runs the destructive M8.2a debugger matrix; set WINDBG_MCP_SMOKE_SK_KD_M8 and run alone"]
fn qualification_runner_executes_full_m8_2a_matrix_on_one_boot() {
    let Some(path) = std::env::var_os("WINDBG_MCP_SMOKE_SK_KD_M8") else {
        eprintln!(
            "SKIPPED: set WINDBG_MCP_SMOKE_SK_KD_M8=<private M8.2a config> to run qualification"
        );
        return;
    };
    let path = PathBuf::from(path);
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read M8.2a qualification config {}: {error}",
            path.display()
        )
    });
    let config = Config::parse(&text).unwrap_or_else(|error| panic!("{error}"));
    config
        .preflight_files()
        .unwrap_or_else(|error| panic!("{error}"));
    let baseline =
        probe_boot(&config, "M8.2a initial boot probe").unwrap_or_else(|error| panic!("{error}"));

    run_breakpoint_matrix(&config, &baseline);

    for frontend in [Frontend::Classic, Frontend::WinDbgX] {
        let boot_before = probe_boot(&config, "M8.2a pre-free-run boot probe")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            boot_before, baseline,
            "the M8.2a boot changed before the {:?} free-run arm",
            frontend
        );
        let artifact = run_free_run_arm(&config, frontend, boot_before);
        let published = persist_free_run_artifact(config.artifact_directory(), &artifact)
            .unwrap_or_else(|error| panic!("{error}"));
        eprintln!(
            "M8.2a {:?}/free-run: {:?}; artifact {}",
            frontend,
            artifact.verdict,
            published.display()
        );
        assert_eq!(
            artifact.verdict,
            Verdict::Pass,
            "M8.2a {:?}/free-run failed: {:#?}",
            frontend,
            artifact.failures
        );
        assert_eq!(
            artifact.boot_after.as_ref(),
            Some(&baseline),
            "the M8.2a boot changed during the {:?} free-run arm",
            frontend
        );
    }

    for frontend in [Frontend::Classic, Frontend::WinDbgX] {
        for plan in race_plans() {
            let boot_before = probe_boot(&config, "M8.2a pre-race boot probe")
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(
                boot_before, baseline,
                "the M8.2a boot changed before the {:?}/{:?} race",
                frontend, plan.scenario
            );
            let artifact = run_race_arm(&config, frontend, plan, boot_before);
            let published = persist_race_artifact(config.artifact_directory(), &artifact)
                .unwrap_or_else(|error| panic!("{error}"));
            eprintln!(
                "M8.2a {:?}/{:?}: {:?}; artifact {}",
                frontend,
                plan.scenario,
                artifact.verdict,
                published.display()
            );
            assert_eq!(
                artifact.verdict,
                Verdict::Pass,
                "M8.2a {:?}/{:?} failed: {:#?}",
                frontend,
                plan.scenario,
                artifact.failures
            );
            assert_eq!(
                artifact.boot_after.as_ref(),
                Some(&baseline),
                "the M8.2a boot changed during the {:?}/{:?} race",
                frontend,
                plan.scenario
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(mut open: Value) -> String {
        if open.get("arm_mode").is_none() {
            open["arm_mode"] = json!("redirect");
        }
        json!({
            "schema": CONFIG_SCHEMA,
            "disposable": true,
            "open": open,
            "frontends": {
                "classic": "C:\\Debuggers\\windbg.exe",
                "windbgx": "C:\\WinDbg\\WinDbgX.exe"
            },
            "windbgx_script": [
                "C:\\rig\\send-command.exe", "--pid", "{pid}", "--command", "{command}"
            ],
            "interrupts": {
                "classic": ["C:\\rig\\ctrl-break.exe", "--pid", "{pid}"],
                "windbgx": ["C:\\rig\\ctrl-break.exe", "--pid", "{pid}"]
            },
            "resets": {
                "classic": ["C:\\rig\\reset-debugger.exe", "--pid", "{pid}"],
                "windbgx": ["C:\\rig\\reset-debugger.exe", "--pid", "{pid}"]
            },
            "policies": {
                "hardware": "D:\\private\\read-only.json",
                "int3": "D:\\private\\write.json"
            },
            "breakpoint": "securekernel!IumInvokeSecureService",
            "symbol_path": "D:\\symbols",
            "trigger": ["trigger.exe", "--count", "{count}"],
            "boot_probe": ["probe.exe", "boot"],
            "post_release_audit": ["probe.exe", "audit"],
            "artifact_dir": "D:\\evidence\\m8"
        })
        .to_string()
    }

    fn open() -> Value {
        json!({
            "profile": "D:\\private\\vmwp.json",
            "control_transport": "control --vp {vp}",
            "live_transport": "memory --cr3 {cr3}",
            "vm_id": "51749a1f-f939-44f5-b251-1251ef5b64a3",
            "vp": 0,
            "arm_mode": "redirect",
            "connect_timeout_ms": 60000,
            "idle_timeout_ms": 60000
        })
    }

    #[test]
    fn qualification_config_is_static_and_cannot_shrink_the_gate() {
        let parsed = Config::parse(&config(open())).unwrap();
        assert_eq!(parsed.breakpoint, "securekernel!IumInvokeSecureService");
        assert_eq!(parsed.counted_trigger(), ["trigger.exe", "--count", "100"]);
        assert_eq!(
            parsed.interrupt_command(Frontend::Classic, 4242),
            ["C:\\rig\\ctrl-break.exe", "--pid", "4242"]
        );
        assert_eq!(
            parsed.reset_command(Frontend::WinDbgX, 4242),
            ["C:\\rig\\reset-debugger.exe", "--pid", "4242"]
        );
        assert_eq!(
            parsed.windbgx_script_command(4242, "$><C:\\rig\\arm.txt"),
            [
                "C:\\rig\\send-command.exe",
                "--pid",
                "4242",
                "--command",
                "$><C:\\rig\\arm.txt"
            ]
        );
        assert_eq!(BREAKPOINT_CYCLES, 100);
        assert_eq!(FREE_RUN_CYCLES, 25);
        assert_eq!(BREAKPOINT_ARM_TIMEOUT, Duration::from_secs(45 * 60));

        let mut per_boot = open();
        per_boot["expected_cr3"] = json!("0x12345000");
        let error = Config::parse(&config(per_boot)).unwrap_err();
        assert!(error.contains("discover `expected_cr3`"), "{error}");

        let mut shortened = open();
        shortened["idle_timeout_ms"] = json!(1);
        let error = Config::parse(&config(shortened)).unwrap_err();
        assert!(error.contains("fixed value 60000"), "{error}");

        let lowered = config(open()).replace(
            "\"artifact_dir\":\"D:\\\\evidence\\\\m8\"",
            "\"cycles\":1,\"artifact_dir\":\"D:\\\\evidence\\\\m8\"",
        );
        let error = Config::parse(&lowered).unwrap_err();
        assert!(error.contains("unknown field `cycles`"), "{error}");

        let no_pid = config(open()).replace("{pid}", "4242");
        let error = Config::parse(&no_pid).unwrap_err();
        assert!(error.contains("exactly one `{pid}`"), "{error}");

        let no_command = config(open()).replace("{command}", "r");
        let error = Config::parse(&no_command).unwrap_err();
        assert!(error.contains("exactly one `{command}`"), "{error}");
    }

    #[test]
    fn gui_debuggers_receive_the_script_through_the_windbg_command_surface() {
        let path = Path::new(r"C:\qualification evidence\arm.commands.txt");
        assert_eq!(
            debugger_script_command(path),
            r"$><C:\qualification evidence\arm.commands.txt"
        );
    }

    #[test]
    fn preflight_resolves_every_command_before_the_vm_is_touched() {
        preflight_command_program("fixture", &["cmd.exe".into()]).unwrap();
        let error = preflight_command_program(
            "fixture",
            &["windbg-mcp-m8-command-that-does-not-exist.exe".into()],
        )
        .unwrap_err();
        assert!(error.contains("not on PATH"), "{error}");
    }

    #[test]
    fn configuration_preflight_reaches_every_command_array() {
        fn command_mut(config: &mut Config, index: usize) -> &mut Vec<String> {
            match index {
                0 => &mut config.trigger,
                1 => &mut config.boot_probe,
                2 => &mut config.post_release_audit,
                3 => &mut config.windbgx_script,
                4 => &mut config.interrupts.classic,
                5 => &mut config.interrupts.windbgx,
                6 => &mut config.resets.classic,
                7 => &mut config.resets.windbgx,
                _ => panic!("unknown command fixture"),
            }
        }

        let serial = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "windbg-mcp-m8-preflight-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let profile = root.join("vmwp.json");
        let hardware = root.join("hardware.json");
        let int3 = root.join("int3.json");
        fs::write(&profile, "{}").unwrap();
        fs::write(
            &hardware,
            r#"{"disposable_vm_ids":["51749a1f-f939-44f5-b251-1251ef5b64a3"]}"#,
        )
        .unwrap();
        fs::write(
            &int3,
            r#"{"disposable_vm_ids":["51749a1f-f939-44f5-b251-1251ef5b64a3"],"allow_memory_writes":true}"#,
        )
        .unwrap();

        let executable = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let mut parsed = Config::parse(&config(open())).unwrap();
        parsed.frontends.classic.clone_from(&executable);
        parsed.frontends.windbgx.clone_from(&executable);
        parsed.policies.hardware = hardware.to_string_lossy().into_owned();
        parsed.policies.int3 = int3.to_string_lossy().into_owned();
        parsed.symbol_path = root.to_string_lossy().into_owned();
        parsed.open.insert(
            "profile".into(),
            Value::String(profile.to_string_lossy().into_owned()),
        );
        for index in 0..8 {
            command_mut(&mut parsed, index)[0].clone_from(&executable);
        }
        parsed.preflight_files().unwrap();

        let missing = root
            .join("missing-command.exe")
            .to_string_lossy()
            .into_owned();
        for (index, name) in [
            "trigger",
            "boot_probe",
            "post_release_audit",
            "windbgx_script",
            "interrupts.classic",
            "interrupts.windbgx",
            "resets.classic",
            "resets.windbgx",
        ]
        .into_iter()
        .enumerate()
        {
            let original =
                std::mem::replace(&mut command_mut(&mut parsed, index)[0], missing.clone());
            let error = parsed.preflight_files().unwrap_err();
            command_mut(&mut parsed, index)[0] = original;
            assert!(error.contains(name), "{name}: {error}");
            assert!(error.contains("is not a file"), "{name}: {error}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn policy_pair_selects_one_hardware_and_one_int3_backend() {
        let vm = json!(["51749a1f-f939-44f5-b251-1251ef5b64a3"]);
        let hardware = json!({ "disposable_vm_ids": vm });
        let int3 = json!({
            "disposable_vm_ids": vm,
            "allow_memory_writes": true
        });
        validate_policy_pair(&hardware, &int3).unwrap();
        assert!(
            validate_policy_pair(&int3, &hardware)
                .unwrap_err()
                .contains("hardware policy")
        );
        let different_vm = json!({
            "disposable_vm_ids": ["11111111-1111-1111-1111-111111111111"],
            "allow_memory_writes": true
        });
        assert!(
            validate_policy_pair(&hardware, &different_vm)
                .unwrap_err()
                .contains("may differ only")
        );
    }

    #[test]
    fn breakpoint_script_and_transcript_have_one_ordered_hundred_cycle_grammar() {
        let run = "classic-hardware-boot1";
        let script = breakpoint_script(
            run,
            "securekernel!IumInvokeSecureService",
            BreakpointBackend::Hardware,
            BREAKPOINT_CYCLES,
        )
        .unwrap();
        assert_eq!(script.matches("bp securekernel!").count(), 6);
        assert_eq!(script.matches("\nbl\n").count(), 2);
        assert_eq!(script.matches("\ng\n").count(), 2);
        assert_eq!(script.matches("\nbc *\n").count(), 2);
        assert!(script.contains("@$t0 < 0n100"));
        assert!(script.contains("WINDBG_MCP_EXPECT_FIFTH_BREAKPOINT_REFUSAL"));
        assert!(script.contains("WINDBG_MCP_FIFTH_BREAKPOINT_RESUMED"));
        assert!(!script.contains("bp securekernel!IumInvokeSecureService+2\n"));
        assert!(script.contains("bp securekernel!IumInvokeSecureService+17\n"));
        assert!(
            script.len() < 4096,
            "command block is {} bytes",
            script.len()
        );
        assert_eq!(script.matches("WINDBG_MCP_PROBE_before_BEGIN").count(), 1);
        assert_eq!(script.matches("WINDBG_MCP_PROBE_after_END").count(), 1);
        assert!(!script.contains(".sleep"));
        assert!(!script.lines().any(|line| line.trim() == "q"));
        let int3 = breakpoint_script(
            run,
            "securekernel!IumInvokeSecureService",
            BreakpointBackend::Int3,
            BREAKPOINT_CYCLES,
        )
        .unwrap();
        assert!(int3.contains("WINDBG_MCP_EXPECT_WRITE_REFUSAL"));
        assert_eq!(int3.matches("\neb ").count(), 1);
        assert!(int3.len() < 4096, "command block is {} bytes", int3.len());
        assert!(
            breakpoint_script(
                run,
                "securekernel!Entry",
                BreakpointBackend::Hardware,
                BREAKPOINT_CYCLES - 1,
            )
            .unwrap_err()
            .contains("fixed at 100")
        );

        let mut transcript = format!("WINDBG_MCP_M8_READY {run}\n");
        for cycle in 0..BREAKPOINT_CYCLES {
            transcript.push_str(&format!(
                "WINDBG_MCP_M8_ARM {run} {cycle:03}\nWINDBG_MCP_M8_HIT {run} {cycle:03}\n"
            ));
        }
        transcript.push_str(&format!("WINDBG_MCP_M8_COMPLETE {run}\n"));
        let progress = transcript_progress(&transcript, run, BREAKPOINT_CYCLES).unwrap();
        assert_eq!(
            progress,
            TranscriptProgress {
                ready: true,
                armed_cycle: None,
                completed_cycles: BREAKPOINT_CYCLES,
                complete: true,
            }
        );

        let partial = format!(
            "0: kd> .echo WINDBG_MCP_M8_READY {run}\n\
             WINDBG_MCP_M8_READY {run}\n\
             WINDBG_MCP_M8_ARM {run} 000\n"
        );
        let progress = transcript_progress(&partial, run, BREAKPOINT_CYCLES).unwrap();
        assert_eq!(progress.armed_cycle, Some(0));
        assert_eq!(progress.completed_cycles, 0);
        assert!(!progress.complete);
    }

    #[test]
    fn generic_probe_and_facade_evidence_are_both_required() {
        let run = "classic-hardware-boot1";
        let mut transcript = String::from(
            "rax=0000000000000001\nfffff80000000000 fffff80000100000 securekernel\n\
             00 ffff800000001000 securekernel!First\n\
             01 ffff800000002000 securekernel!Second\n",
        );
        for phase in ["before", "after"] {
            for marker in ["BEGIN", "STEPPED", "END"] {
                transcript.push_str(&format!("WINDBG_MCP_PROBE_{phase}_{marker} {run}\n"));
            }
        }
        validate_debugger_probes(&transcript, run).unwrap();
        assert!(
            validate_debugger_probes(&transcript.replace("rax=", "eax:"), run)
                .unwrap_err()
                .contains("register bank")
        );

        let mut facade = String::new();
        for _ in 0..BREAKPOINT_CYCLES {
            facade.push_str("KD go to 1 hardware breakpoint(s)\n");
            facade.push_str("KD restored the hit hardware-breakpoint handle 1\n");
        }
        facade.push_str(
            "all four VTL1 hardware-breakpoint slots are in use\n\
             KD restored breakpoint handle 1 at 0xfffff80000000003\n\
             KD restored breakpoint handle 2 at 0xfffff80000000005\n\
             KD restored breakpoint handle 3 at 0xfffff80000000007\n\
             KD restored breakpoint handle 4 at 0xfffff80000000009\n\
             KD Continue api=0x3136 trace=true\n\
             KD Continue api=0x3136 trace=true\n\
             KD virtual read 0xfffff80000000000+0x10 served by Secure Kernel memory\n",
        );
        validate_facade_evidence(&facade, BreakpointBackend::Hardware).unwrap();
        assert!(
            validate_facade_evidence(
                &facade.replace("hardware-breakpoint", "missing-breakpoint"),
                BreakpointBackend::Hardware,
            )
            .unwrap_err()
            .contains("restorations")
        );
        assert!(
            validate_facade_evidence(
                &format!("{facade}KD go refused; current held stop preserved\n"),
                BreakpointBackend::Hardware,
            )
            .unwrap_err()
            .contains("refused a debugger go")
        );
    }

    #[test]
    fn transcript_rejects_duplicate_reordered_and_stale_markers() {
        let run = "windbgx-int3-boot2";
        for transcript in [
            format!(
                "WINDBG_MCP_M8_READY {run}\nWINDBG_MCP_M8_ARM {run} 000\n\
                 WINDBG_MCP_M8_ARM {run} 000\n"
            ),
            format!("WINDBG_MCP_M8_READY {run}\nWINDBG_MCP_M8_HIT {run} 000\n"),
            "WINDBG_MCP_M8_READY another-run\n".to_string(),
        ] {
            assert!(
                transcript_progress(&transcript, run, BREAKPOINT_CYCLES).is_err(),
                "accepted malformed transcript:\n{transcript}"
            );
        }
        let partial = format!(
            "WINDBG_MCP_M8_READY {run}\nWINDBG_MCP_M8_ARM {run} 000\n\
             WINDBG_MCP_M8_HIT {run}"
        );
        assert_eq!(
            transcript_progress(&partial, run, BREAKPOINT_CYCLES).unwrap(),
            TranscriptProgress {
                ready: true,
                armed_cycle: Some(0),
                completed_cycles: 0,
                complete: false,
            }
        );
    }

    #[test]
    fn free_run_script_requires_twenty_five_ordered_external_interrupts() {
        let run = "windbgx-free-run-boot1";
        let script = free_run_script(run, FREE_RUN_CYCLES).unwrap();
        assert_eq!(script.matches("\ng\n").count(), 1);
        assert_eq!(script.matches("\nt\n").count(), 1);
        assert_eq!(script.matches("WINDBG_MCP_M8_FREE_ARM").count(), 1);
        assert!(script.contains("@$t0 < 0n25"));
        let trace = script.find("\nt\n").unwrap();
        let ready = script.find("WINDBG_MCP_M8_FREE_READY").unwrap();
        let go = script.find("\ng\n").unwrap();
        assert!(trace < ready && ready < go, "{script}");
        assert!(
            script.len() < 4096,
            "command block is {} bytes",
            script.len()
        );
        assert!(!script.contains("bp "));
        assert!(!script.contains(".sleep"));
        assert!(!script.lines().any(|line| line.trim() == "q"));
        assert!(
            free_run_script(run, FREE_RUN_CYCLES - 1)
                .unwrap_err()
                .contains("fixed at 25")
        );

        let mut transcript = format!("WINDBG_MCP_M8_FREE_READY {run}\n");
        for cycle in 0..FREE_RUN_CYCLES {
            transcript.push_str(&format!(
                "WINDBG_MCP_M8_FREE_ARM {run} {cycle:03}\n\
                 WINDBG_MCP_M8_FREE_HIT {run} {cycle:03}\n"
            ));
        }
        transcript.push_str(&format!("WINDBG_MCP_M8_FREE_COMPLETE {run}\n"));
        assert_eq!(
            free_run_progress(&transcript, run, FREE_RUN_CYCLES).unwrap(),
            TranscriptProgress {
                ready: true,
                armed_cycle: None,
                completed_cycles: FREE_RUN_CYCLES,
                complete: true,
            }
        );
        assert!(
            free_run_progress(
                &transcript.replace(&format!("WINDBG_MCP_M8_FREE_HIT {run} 000\n"), ""),
                run,
                FREE_RUN_CYCLES,
            )
            .is_err()
        );
    }

    fn boot() -> BootIdentity {
        BootIdentity {
            vm_id: "51749a1f-f939-44f5-b251-1251ef5b64a3".into(),
            boot_id: "boot-1".into(),
            vmwp_pid: 4242,
            vp_count: 1,
            heartbeat_ok: true,
        }
    }

    fn successful_trigger() -> TriggerOutcome {
        TriggerOutcome {
            status: "exit code: 0".into(),
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn artifact_pass_requires_all_cycles_same_boot_and_a_passing_audit() {
        let mut artifact = ArmArtifact::new(
            "classic-hardware-boot1".into(),
            Frontend::Classic,
            BreakpointBackend::Hardware,
            boot(),
            "classic-hardware-boot1.log".into(),
        )
        .unwrap();
        artifact.completed_cycles = BREAKPOINT_CYCLES;
        artifact.boot_after = Some(boot());
        artifact.trigger = Some(successful_trigger());
        artifact.audit = Some(json!({ "result": "pass" }));
        artifact.settle();
        assert_eq!(artifact.verdict, Verdict::Pass);
        assert!(artifact.failures.is_empty());

        let encoded = serde_json::to_value(&artifact).unwrap();
        assert_eq!(encoded["schema"], ARTIFACT_SCHEMA);
        assert_eq!(encoded["backend"], "hardware");

        let mut failed = ArmArtifact::new(
            "windbgx-int3-boot1".into(),
            Frontend::WinDbgX,
            BreakpointBackend::Int3,
            boot(),
            "windbgx-int3-boot1.log".into(),
        )
        .unwrap();
        failed.completed_cycles = BREAKPOINT_CYCLES - 1;
        failed.trigger = Some(successful_trigger());
        failed.boot_after = Some(BootIdentity {
            boot_id: "boot-2".into(),
            ..boot()
        });
        failed.audit = Some(json!({ "result": "fail" }));
        failed.settle();
        assert_eq!(failed.verdict, Verdict::Fail);
        assert_eq!(failed.failures.len(), 3);

        let mut unhealthy = ArmArtifact::new(
            "classic-int3-boot1".into(),
            Frontend::Classic,
            BreakpointBackend::Int3,
            BootIdentity {
                heartbeat_ok: false,
                ..boot()
            },
            "classic-int3-boot1.log".into(),
        )
        .unwrap();
        unhealthy.completed_cycles = BREAKPOINT_CYCLES;
        unhealthy.trigger = Some(successful_trigger());
        unhealthy.boot_after = Some(BootIdentity {
            heartbeat_ok: false,
            ..boot()
        });
        unhealthy.audit = Some(json!({ "result": "pass" }));
        unhealthy.settle();
        assert_eq!(unhealthy.verdict, Verdict::Fail);
        assert!(
            unhealthy
                .failures
                .iter()
                .any(|failure| failure.contains("boot identity"))
        );
    }

    #[test]
    fn free_run_artifact_requires_every_ctrl_break_and_facade_wake() {
        let mut artifact =
            FreeRunArtifact::new("classic-free-run-boot1".into(), Frontend::Classic, boot())
                .unwrap();
        artifact.completed_cycles = FREE_RUN_CYCLES;
        artifact.interrupts_requested = FREE_RUN_CYCLES;
        artifact.boot_after = Some(boot());
        artifact.audit = Some(json!({ "result": "pass" }));
        artifact.settle();
        assert_eq!(artifact.verdict, Verdict::Pass);

        let mut facade = String::new();
        for _ in 0..FREE_RUN_CYCLES {
            facade.push_str("KD go with no breakpoint\n");
            facade.push_str("KD break-in woke the running wait\n");
        }
        validate_free_run_facade_evidence(&facade).unwrap();
        assert!(
            validate_free_run_facade_evidence(&facade.replacen(
                "KD break-in woke the running wait\n",
                "",
                1
            ))
            .unwrap_err()
            .contains("24 running break-ins")
        );

        artifact.interrupts_requested -= 1;
        artifact.failures.clear();
        artifact.settle();
        assert_eq!(artifact.verdict, Verdict::Fail);
        assert!(
            artifact
                .failures
                .iter()
                .any(|failure| failure.contains("24 of 25 debugger interrupts"))
        );
    }

    #[test]
    fn boot_probe_is_bound_to_the_vm_one_vp_and_heartbeat() {
        let expected = "51749a1f-f939-44f5-b251-1251ef5b64a3";
        let output = format!(
            "bench status follows\n{}",
            serde_json::to_string(&boot()).unwrap()
        );
        assert_eq!(
            decode_boot_probe(output.as_bytes(), expected).unwrap(),
            boot()
        );
        for (field, value, expected_error) in [
            ("vp_count", json!(2), "requires one VP"),
            ("heartbeat_ok", json!(false), "healthy heartbeat"),
            (
                "vm_id",
                json!("11111111-1111-1111-1111-111111111111"),
                "answered for VM",
            ),
        ] {
            let mut identity = serde_json::to_value(boot()).unwrap();
            identity[field] = value;
            let error = decode_boot_probe(identity.to_string().as_bytes(), expected).unwrap_err();
            assert!(error.contains(expected_error), "{field}: {error}");
        }
    }

    #[test]
    fn every_frontend_backend_arm_has_a_unique_run_key() {
        let mut keys = HashMap::new();
        for frontend in [Frontend::Classic, Frontend::WinDbgX] {
            for backend in [BreakpointBackend::Hardware, BreakpointBackend::Int3] {
                let key = format!("{frontend:?}-{backend:?}").to_ascii_lowercase();
                assert!(keys.insert(key, (frontend, backend)).is_none());
            }
        }
        assert_eq!(keys.len(), 4);
    }

    #[test]
    fn every_race_has_one_distinct_control_and_outcome() {
        let plans = race_plans();
        assert_eq!(
            plans.map(|plan| plan.scenario),
            [
                RaceScenario::NaturalStopWins,
                RaceScenario::CtrlBreakWins,
                RaceScenario::AlreadyStopped,
                RaceScenario::NoHitTimeout,
                RaceScenario::Reset,
                RaceScenario::Disconnect,
                RaceScenario::Reconnect,
                RaceScenario::McpTeardown,
            ]
        );
        assert_eq!(
            plans
                .iter()
                .map(|plan| plan.control)
                .collect::<BTreeSet<_>>()
                .len(),
            plans.len()
        );
        assert_eq!(
            plans
                .iter()
                .map(|plan| plan.expected)
                .collect::<BTreeSet<_>>()
                .len(),
            plans.len()
        );
    }

    #[test]
    fn race_scripts_expose_only_the_marker_the_host_control_needs() {
        for plan in race_plans() {
            let run = format!("classic-race-{}-boot1", plan.scenario.slug());
            let script =
                race_script(&run, plan.scenario, "securekernel!IumInvokeSecureService").unwrap();
            assert!(!script.contains(".sleep"), "{script}");
            assert!(!script.lines().any(|line| line.trim() == "q"), "{script}");
            match plan.scenario {
                RaceScenario::NaturalStopWins | RaceScenario::CtrlBreakWins => {
                    assert_eq!(script.matches("\nt\n").count(), 1, "{script}");
                    assert!(script.contains("WINDBG_MCP_RACE_ARMED"), "{script}");
                    assert!(script.contains("WINDBG_MCP_RACE_STOP"), "{script}");
                    assert!(script.contains("bp securekernel!"), "{script}");
                }
                RaceScenario::NoHitTimeout => {
                    assert_eq!(script.matches("\nt\n").count(), 1, "{script}");
                    assert!(script.contains("WINDBG_MCP_RACE_UNEXPECTED_STOP"));
                }
                RaceScenario::McpTeardown => {
                    assert_eq!(script.matches("\nt\n").count(), 1, "{script}");
                    assert!(script.contains("WINDBG_MCP_RACE_ARMED"));
                    assert!(!script.contains("bp securekernel!"));
                }
                RaceScenario::AlreadyStopped
                | RaceScenario::Reset
                | RaceScenario::Disconnect
                | RaceScenario::Reconnect => {
                    assert_eq!(script.lines().count(), 1, "{script}");
                    assert!(!script.contains("\nt\n"), "{script}");
                    assert!(script.contains("WINDBG_MCP_RACE_READY"), "{script}");
                }
            }
        }
    }

    #[test]
    fn race_execution_log_window_precedes_debugger_launch() {
        let source = include_str!("sk_m8.rs");
        let arm = source
            .split_once("fn run_race_arm(")
            .unwrap()
            .1
            .split_once("#[test]")
            .unwrap()
            .0;
        let offset = arm
            .find("let execution_log_offset = server.stderr().len();")
            .unwrap();
        let launch = arm.find("debugger = Some(spawn_debugger(").unwrap();
        assert!(offset < launch);
        assert_eq!(arm.matches("execution_log_offset,").count(), 5);
    }

    #[test]
    fn race_artifact_passes_only_its_own_outcome_on_the_same_boot() {
        for plan in race_plans() {
            let mut artifact = RaceArtifact::new(
                format!("classic-race-{}-boot1", plan.scenario.slug()),
                Frontend::Classic,
                plan,
                boot(),
            )
            .unwrap();
            artifact.observed = Some(plan.expected);
            artifact.boot_after = Some(boot());
            artifact.audit = Some(json!({ "result": "pass" }));
            artifact.settle();
            assert_eq!(artifact.verdict, Verdict::Pass, "{plan:?}");
            assert_eq!(
                serde_json::to_value(&artifact).unwrap()["schema"],
                RACE_ARTIFACT_SCHEMA
            );
        }

        let plan = race_plans()[0];
        let mut wrong = RaceArtifact::new(
            "classic-race-wrong-boot1".into(),
            Frontend::Classic,
            plan,
            boot(),
        )
        .unwrap();
        wrong.observed = Some(RaceOutcome::RequestedBreakRetained);
        wrong.boot_after = Some(boot());
        wrong.audit = Some(json!({ "result": "pass" }));
        wrong.settle();
        assert_eq!(wrong.verdict, Verdict::Fail);
        assert!(wrong.failures[0].contains("expected NaturalBreakpointRetained"));
    }

    #[test]
    fn runner_uses_the_latest_authenticated_debugger_and_typed_tool_result() {
        let log = "accepted Secure Kernel KD client PID 101 from local pipe\n\
                   another record\n\
                   accepted Secure Kernel KD client PID 202 from local pipe\n";
        assert_eq!(connected_debugger_pid(log), Some(202));
        assert_eq!(connected_debugger_pid("no client"), None);

        let structured = json!({ "status": "ok", "session_id": "sess-1" });
        let response = json!({ "result": { "structuredContent": structured } });
        assert_eq!(
            structured_tool_result(&response, "open_sk_kd").unwrap(),
            structured
        );
        let error = structured_tool_result(
            &json!({ "error": { "code": -32603, "message": "failed" } }),
            "open_sk_kd",
        )
        .unwrap_err();
        assert!(error.contains("protocol error"), "{error}");
    }

    #[test]
    fn generated_arm_ids_are_safe_artifact_names() {
        for (frontend, backend) in [
            (Frontend::Classic, BreakpointBackend::Hardware),
            (Frontend::Classic, BreakpointBackend::Int3),
            (Frontend::WinDbgX, BreakpointBackend::Hardware),
            (Frontend::WinDbgX, BreakpointBackend::Int3),
        ] {
            let id = run_id(frontend, backend);
            validate_run_id(&id).unwrap();
            assert!(
                id.starts_with(&format!("{}-{}-", frontend.slug(), backend.slug())),
                "{id}"
            );
        }
    }

    #[test]
    fn artifact_is_published_once_without_overwriting_evidence() {
        let root = std::env::temp_dir().join(format!(
            "windbg-mcp-m8-artifact-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut artifact = ArmArtifact::new(
            "classic-hardware-boot3".into(),
            Frontend::Classic,
            BreakpointBackend::Hardware,
            boot(),
            "classic-hardware-boot3.log".into(),
        )
        .unwrap();
        artifact.completed_cycles = BREAKPOINT_CYCLES;
        artifact.boot_after = Some(boot());
        artifact.trigger = Some(successful_trigger());
        artifact.audit = Some(json!({ "result": "pass" }));
        artifact.settle();

        let path = persist_artifact(&root, &artifact).unwrap();
        let decoded: ArmArtifact = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(decoded, artifact);
        assert_eq!(decoded.facade_log, "");
        assert!(
            persist_artifact(&root, &artifact)
                .unwrap_err()
                .contains("refusing to overwrite")
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
