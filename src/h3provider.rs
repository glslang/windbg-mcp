//! Built-in `h3probe` control and live-memory provider roles.
//!
//! They speak the same subprocess protocols as operator-supplied providers. Keeping the process
//! boundary means a stuck or failed `DeviceIoControl` costs one session/provider, never the MCP
//! supervisor or an engine worker.

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::h3probe::{
    GuestVirtual, Ioctl, MemoryResult, MemoryTarget, Probe, RegisterWord, find_secure_kernel_base,
};
use crate::skcontrol::{
    Capabilities, Capability, ErrorCode, HexU64, Operation, Outcome, ProviderError, RegisterName,
    RegisterValue, ReplyValue, Request, Response, StopEpoch, TargetIdentity,
};

pub(crate) const BUILTIN: &str = "builtin:h3probe";
pub(crate) const CONTROL_FLAG: &str = "--sk-h3-control";
pub(crate) const MEMORY_FLAG: &str = "--sk-h3-memory";
pub(crate) const AUDIT_FLAG: &str = "--sk-h3-audit";
pub(crate) const QUALIFY_FLAG: &str = "--sk-h3-qualify";
const CONTROL_PROTOCOL: u32 = 2;
const MEMORY_READY: &str = "windbg-mcp-gpa/1";
const PAGE: usize = 0x1000;

pub(crate) fn builtin_command(
    target: &TargetIdentity,
    cr3_known: bool,
    memory_handle: Option<(u32, u64)>,
    allow_transition_cr3: bool,
) -> Result<String> {
    let exe = std::env::current_exe().context("finding this provider's executable")?;
    let mut words = vec![exe.to_string_lossy().into_owned()];
    match memory_handle {
        None => {
            words.extend([
                CONTROL_FLAG.into(),
                "--vm-id".into(),
                target.vm_id.clone(),
                "--partition-id".into(),
                format!("{:#x}", target.partition_id.0),
                "--vp".into(),
                target.vp.to_string(),
            ]);
            if cr3_known {
                words.extend([
                    "--expected-cr3".into(),
                    format!("{:#x}", target.expected_cr3.0),
                ]);
            }
            if allow_transition_cr3 {
                words.push("--allow-transition-cr3".into());
            }
        }
        Some((vmwp_pid, partition_handle)) => {
            if vmwp_pid == 0 || partition_handle == 0 {
                bail!("the built-in memory provider needs worker-discovered vmwp coordinates");
            }
            words.extend([
                MEMORY_FLAG.into(),
                "--vmwp-pid".into(),
                vmwp_pid.to_string(),
                "--partition-handle".into(),
                format!("{partition_handle:#x}"),
                "--partition-id".into(),
                format!("{:#x}", target.partition_id.0),
                "--vp".into(),
                target.vp.to_string(),
                "--writes".into(),
            ]);
            if cr3_known {
                words.extend([
                    "--expected-cr3".into(),
                    format!("{:#x}", target.expected_cr3.0),
                ]);
            }
        }
    }
    Ok(crate::skpolicy::render_transport(&words))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Running,
    Arming,
    Stopped,
}

struct ControlProvider {
    probe: Probe,
    target: TargetIdentity,
    epoch: StopEpoch,
    partition: u64,
    vp: u32,
    allow_transition_cr3: bool,
    phase: Phase,
    event: Option<crate::skcontrol::HeldEvent>,
}

impl ControlProvider {
    fn open(args: ControlArgs) -> Result<Self> {
        let probe = Probe::open()?;
        let expected_cr3 = match args.expected_cr3 {
            Some(value) => value,
            None => probe
                .read_named(args.partition, args.vp, RegisterName::Cr3)?
                .low(RegisterName::Cr3)?,
        };
        probe.guard(args.partition, args.vp, expected_cr3)?;
        let target = TargetIdentity {
            vm_id: args.vm_id.to_ascii_lowercase(),
            partition_id: HexU64(args.partition),
            vp: args.vp,
            vtl: 1,
            expected_cr3: HexU64(expected_cr3),
        };
        target.validate()?;
        Ok(Self {
            probe,
            target,
            epoch: epoch("running")?,
            partition: args.partition,
            vp: args.vp,
            allow_transition_cr3: args.allow_transition_cr3,
            phase: Phase::Running,
            event: None,
        })
    }

    fn response(&self, id: u64, value: ReplyValue) -> Response {
        Response {
            protocol: CONTROL_PROTOCOL,
            id,
            target: self.target.clone(),
            epoch: self.epoch.clone(),
            outcome: Outcome::Ok { value },
        }
    }

    fn error(&self, id: u64, code: ErrorCode, detail: impl Into<String>) -> Response {
        Response {
            protocol: CONTROL_PROTOCOL,
            id,
            target: self.target.clone(),
            epoch: self.epoch.clone(),
            outcome: Outcome::Error {
                error: ProviderError {
                    code,
                    detail: detail.into(),
                },
            },
        }
    }

    fn handle(&mut self, request: Request) -> Response {
        let id = request.id;
        if request.protocol != CONTROL_PROTOCOL {
            return self.error(id, ErrorCode::Provider, "protocol must be 2");
        }
        if request.target != self.target {
            return self.error(id, ErrorCode::WrongTarget, "target identity mismatch");
        }
        if request.epoch != self.epoch {
            return self.error(id, ErrorCode::StaleEpoch, "stop epoch mismatch");
        }
        match request.operation {
            Operation::Capabilities => self.response(
                id,
                ReplyValue::Capabilities {
                    value: capabilities(),
                },
            ),
            Operation::BeginArm => {
                if self.phase != Phase::Running {
                    return self.error(id, ErrorCode::Running, "begin_arm requires running state");
                }
                self.phase = Phase::Arming;
                match epoch("arming") {
                    Ok(epoch) => self.epoch = epoch,
                    Err(error) => return self.error(id, ErrorCode::Provider, format!("{error:#}")),
                }
                self.response(id, ReplyValue::ArmBegun)
            }
            Operation::FinishArm => {
                if self.phase != Phase::Arming {
                    return self.error(id, ErrorCode::Running, "finish_arm requires arming state");
                }
                self.phase = Phase::Running;
                match epoch("running") {
                    Ok(epoch) => self.epoch = epoch,
                    Err(error) => return self.error(id, ErrorCode::Provider, format!("{error:#}")),
                }
                self.response(id, ReplyValue::ArmFinished)
            }
            Operation::PublishStop { event } => {
                if self.phase != Phase::Running {
                    return self.error(
                        id,
                        ErrorCode::Running,
                        "publish_stop requires running state",
                    );
                }
                if let Err(error) = event.validate(&self.target) {
                    return self.error(id, ErrorCode::Provider, format!("{error:#}"));
                }
                let cr3 = match self
                    .probe
                    .read_named(self.partition, self.vp, RegisterName::Cr3)
                    .and_then(|value| value.low(RegisterName::Cr3))
                {
                    Ok(value) => value,
                    Err(error) => return self.error(id, ErrorCode::Provider, format!("{error:#}")),
                };
                if cr3 == 0 || cr3 & 0xfff != 0 {
                    return self.error(
                        id,
                        ErrorCode::WrongTarget,
                        "stop CR3 is zero or not page aligned",
                    );
                }
                if cr3 != self.target.expected_cr3.0 && !self.allow_transition_cr3 {
                    return self.error(
                        id,
                        ErrorCode::WrongTarget,
                        "CR3 changed before stop publication",
                    );
                }
                self.event = Some(event.clone());
                self.phase = Phase::Stopped;
                match epoch("stopped") {
                    Ok(epoch) => self.epoch = epoch,
                    Err(error) => return self.error(id, ErrorCode::Provider, format!("{error:#}")),
                }
                self.response(id, ReplyValue::StopPublished { event })
            }
            Operation::HeldEvent => match (self.phase, self.event.clone()) {
                (Phase::Stopped, Some(event)) => self.response(id, ReplyValue::HeldEvent { event }),
                _ => self.error(id, ErrorCode::NotStopped, "there is no held event"),
            },
            Operation::ReadRegisters { registers } => {
                if self.phase == Phase::Running {
                    return self.error(
                        id,
                        ErrorCode::Running,
                        "register reads are refused while running",
                    );
                }
                if registers.is_empty()
                    || registers.len() > 32
                    || has_duplicates(&registers)
                    || registers.iter().any(|name| !readable().contains(name))
                {
                    return self.error(
                        id,
                        ErrorCode::UnsupportedRegister,
                        "invalid register request",
                    );
                }
                match registers
                    .iter()
                    .map(|name| self.read_value(*name))
                    .collect::<Result<Vec<_>>>()
                {
                    Ok(values) => self.response(id, ReplyValue::Registers { values }),
                    Err(error) => self.error(id, ErrorCode::Provider, format!("{error:#}")),
                }
            }
            Operation::WriteRegisters { writes } => {
                if self.phase == Phase::Running {
                    return self.error(
                        id,
                        ErrorCode::Running,
                        "register writes are refused while running",
                    );
                }
                if writes.is_empty()
                    || writes.len() > 32
                    || has_duplicates(&writes.iter().map(|write| write.name).collect::<Vec<_>>())
                    || writes.iter().any(|write| !writable(write.name))
                {
                    return self.error(
                        id,
                        ErrorCode::UnsupportedRegister,
                        "invalid register write request",
                    );
                }
                let mut before = Vec::with_capacity(writes.len());
                for write in &writes {
                    let current = match self
                        .probe
                        .read_named(self.partition, self.vp, write.name)
                        .and_then(|value| value.low(write.name))
                    {
                        Ok(value) => value,
                        Err(error) => {
                            return self.error(id, ErrorCode::Provider, format!("{error:#}"));
                        }
                    };
                    if current != write.expected.0 {
                        return self.error(
                            id,
                            ErrorCode::GuardMismatch,
                            format!("{:?} changed before write", write.name),
                        );
                    }
                    before.push((write.name, current));
                }
                for (applied, write) in writes.iter().enumerate() {
                    if let Err(primary) = self.probe.write_register(
                        self.partition,
                        self.vp,
                        write.name,
                        write.value.0,
                        0,
                    ) {
                        let mut rollback = Vec::new();
                        for (name, value) in before[..applied].iter().rev() {
                            if let Err(error) =
                                self.probe
                                    .write_register(self.partition, self.vp, *name, *value, 0)
                            {
                                rollback.push(format!("{name:?}: {error:#}"));
                            }
                        }
                        let detail = if rollback.is_empty() {
                            format!("register write failed and was rolled back: {primary:#}")
                        } else {
                            format!(
                                "register write failed: {primary:#}; rollback also failed: {}",
                                rollback.join("; ")
                            )
                        };
                        return self.error(id, ErrorCode::Provider, detail);
                    }
                }
                match writes
                    .iter()
                    .map(|write| self.read_value(write.name))
                    .collect::<Result<Vec<_>>>()
                {
                    Ok(values) => self.response(id, ReplyValue::RegistersWritten { values }),
                    Err(error) => self.error(id, ErrorCode::Provider, format!("{error:#}")),
                }
            }
            Operation::ActiveVtl => {
                if self.phase != Phase::Running {
                    return self.error(id, ErrorCode::Running, "active_vtl requires running state");
                }
                match self
                    .probe
                    .read_active_vtl(self.partition, self.vp)
                    .and_then(|value| value.low(RegisterName::VsmVpStatus))
                {
                    Ok(value) => self.response(
                        id,
                        ReplyValue::ActiveVtl {
                            vtl: (value & 0xf) as u8,
                        },
                    ),
                    Err(error) => self.error(id, ErrorCode::Provider, format!("{error:#}")),
                }
            }
            Operation::Release => {
                if self.phase != Phase::Stopped {
                    return self.error(id, ErrorCode::NotStopped, "release requires a held event");
                }
                self.event = None;
                self.phase = Phase::Running;
                match epoch("running") {
                    Ok(epoch) => self.epoch = epoch,
                    Err(error) => return self.error(id, ErrorCode::Provider, format!("{error:#}")),
                }
                self.response(id, ReplyValue::Released)
            }
        }
    }

    fn read_value(&self, name: RegisterName) -> Result<RegisterValue> {
        let RegisterWord { status, low, high } =
            self.probe.read_named(self.partition, self.vp, name)?;
        Ok(RegisterValue {
            name,
            status,
            low: HexU64(low),
            high: HexU64(high),
        })
    }
}

pub(crate) fn run_control(args: &[String]) -> Result<()> {
    let mut provider = ControlProvider::open(ControlArgs::parse(args)?)?;
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    writeln!(out, "{}", crate::skcontrol::READY_LINE)?;
    serde_json::to_writer(
        &mut out,
        &serde_json::json!({
            "protocol": CONTROL_PROTOCOL,
            "target": provider.target,
            "epoch": provider.epoch,
        }),
    )?;
    writeln!(out)?;
    out.flush()?;

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.context("reading control-provider request")?;
        let request: Request = serde_json::from_str(&line)
            .with_context(|| format!("invalid control-provider request: {line:?}"))?;
        let response = provider.handle(request);
        serde_json::to_writer(&mut out, &response)?;
        writeln!(out)?;
        out.flush()?;
    }
    Ok(())
}

#[derive(Debug)]
struct ControlArgs {
    vm_id: String,
    partition: u64,
    expected_cr3: Option<u64>,
    vp: u32,
    allow_transition_cr3: bool,
}

impl ControlArgs {
    fn parse(args: &[String]) -> Result<Self> {
        let mut vm_id = None;
        let mut partition = None;
        let mut expected_cr3 = None;
        let mut vp = 0;
        let mut allow_transition_cr3 = false;
        let mut at = 0;
        while at < args.len() {
            let value = |at: &mut usize| -> Result<&String> {
                *at += 1;
                args.get(*at)
                    .with_context(|| format!("{} requires a value", args[*at - 1]))
            };
            match args[at].as_str() {
                "--vm-id" => vm_id = Some(value(&mut at)?.clone()),
                "--partition-id" => partition = Some(parse_u64(value(&mut at)?)?),
                "--expected-cr3" => expected_cr3 = Some(parse_u64(value(&mut at)?)?),
                "--vp" => vp = value(&mut at)?.parse().context("invalid --vp")?,
                "--allow-transition-cr3" => allow_transition_cr3 = true,
                other => bail!("unknown {CONTROL_FLAG} argument {other:?}"),
            }
            at += 1;
        }
        Ok(Self {
            vm_id: vm_id.context("--vm-id is required")?,
            partition: partition.context("--partition-id is required")?,
            expected_cr3,
            vp,
            allow_transition_cr3,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pages {
    H3,
    Hypercall,
}

#[derive(Debug)]
struct MemoryArgs {
    pages: Pages,
    target: Option<MemoryTarget>,
    partition: u64,
    vp: u32,
    expected_cr3: Option<u64>,
    image: Option<PathBuf>,
    writes: bool,
}

impl MemoryArgs {
    fn parse(args: &[String]) -> Result<Self> {
        let mut pages = Pages::H3;
        let mut vmwp_pid = None;
        let mut partition_handle = None;
        let mut partition = None;
        let mut vp = 0;
        let mut expected_cr3 = None;
        let mut image = None;
        let mut writes = false;
        let mut at = 0;
        while at < args.len() {
            let value = |at: &mut usize| -> Result<&String> {
                *at += 1;
                args.get(*at)
                    .with_context(|| format!("{} requires a value", args[*at - 1]))
            };
            match args[at].as_str() {
                "--pages" => {
                    pages = match value(&mut at)?.as_str() {
                        "h3" => Pages::H3,
                        "hypercall" => Pages::Hypercall,
                        other => bail!("invalid --pages {other:?}; expected h3 or hypercall"),
                    }
                }
                "--vmwp-pid" => {
                    vmwp_pid = Some(value(&mut at)?.parse().context("invalid --vmwp-pid")?)
                }
                "--partition-handle" => partition_handle = Some(parse_u64(value(&mut at)?)?),
                "--partition-id" => partition = Some(parse_u64(value(&mut at)?)?),
                "--vp" => vp = value(&mut at)?.parse().context("invalid --vp")?,
                "--expected-cr3" => expected_cr3 = Some(parse_u64(value(&mut at)?)?),
                "--image" => image = Some(PathBuf::from(value(&mut at)?)),
                "--writes" => writes = true,
                other => bail!("unknown {MEMORY_FLAG} argument {other:?}"),
            }
            at += 1;
        }
        let partition = partition.context("--partition-id is required")?;
        if pages == Pages::Hypercall && writes {
            bail!("the hypercall source refuses writes as it refuses VTL1 reads");
        }
        let target = match pages {
            Pages::H3 => Some(MemoryTarget {
                owner_pid: vmwp_pid.context("--pages h3 requires --vmwp-pid")?,
                partition_handle: partition_handle
                    .context("--pages h3 requires --partition-handle")?,
                partition_id: partition,
            }),
            Pages::Hypercall => None,
        };
        Ok(Self {
            pages,
            target,
            partition,
            vp,
            expected_cr3,
            image,
            writes,
        })
    }
}

pub(crate) fn run_memory(args: &[String]) -> Result<()> {
    let args = MemoryArgs::parse(args)?;
    let probe = Probe::open()?;
    let identity = probe.identity(args.partition, args.vp)?;
    if let Some(expected) = args.expected_cr3
        && identity.cr3 != expected
    {
        bail!(
            "VTL1 CR3 {:#x} does not match expected {expected:#x}",
            identity.cr3
        );
    }
    let kernel_base = match args.target {
        Some(target) => {
            let mut guest = GuestVirtual::new(&probe, target, identity.cr3)?;
            Some(find_secure_kernel_base(
                &mut guest,
                identity.idtr_base,
                identity.idtr_limit,
                args.image.as_deref(),
            )?)
        }
        None => None,
    };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut output = BufWriter::new(stdout.lock());
    writeln!(output, "{MEMORY_READY}")?;
    output.flush()?;
    serve_memory(
        &probe,
        &args,
        identity.cr3,
        kernel_base,
        &mut input,
        &mut output,
    )
}

/// Run the post-release half of the Secure Kernel audit without exposing a VID handle or a raw
/// IOCTL to the caller. The orchestrator remains responsible for checking VM identity and health,
/// pausing it before this role starts, and resuming it after this role exits.
pub(crate) fn run_audit(args: &[String]) -> Result<()> {
    let args = AuditArgs::parse(args)?;
    let probe = Probe::open()?;
    let identity = probe.identity(args.partition, args.vp)?;
    if let Some(expected) = args.expected_cr3
        && identity.cr3 != expected
    {
        bail!(
            "VTL1 CR3 {:#x} does not match expected {expected:#x}",
            identity.cr3
        );
    }
    let target = MemoryTarget {
        owner_pid: args.vmwp_pid,
        partition_handle: args.partition_handle,
        partition_id: args.partition,
    };
    let mut guest = GuestVirtual::new(&probe, target, identity.cr3)?;
    let kernel_base = find_secure_kernel_base(
        &mut guest,
        identity.idtr_base,
        identity.idtr_limit,
        Some(&args.image),
    )?;
    let address = kernel_base
        .checked_add(args.target_rva)
        .context("the guarded address overflowed")?;
    let read_size = args.expected.len().max(16);
    let guarded_text = guest.read(address, read_size)?;
    if !guarded_text.starts_with(&args.expected) {
        bail!(
            "guarded text at {address:#x} is {}, expected prefix {}",
            hex_bytes(&guarded_text),
            hex_bytes(&args.expected)
        );
    }

    let mut registers = serde_json::Map::new();
    for (name, register) in [
        ("dr0", RegisterName::Dr0),
        ("dr1", RegisterName::Dr1),
        ("dr2", RegisterName::Dr2),
        ("dr3", RegisterName::Dr3),
        ("dr6", RegisterName::Dr6),
        ("dr7", RegisterName::Dr7),
        ("rflags", RegisterName::Rflags),
    ] {
        let word = probe.read_named(args.partition, args.vp, register)?;
        if word.status != 0 {
            bail!("reading {name} failed with HV_STATUS {:#06x}", word.status);
        }
        registers.insert(
            name.into(),
            serde_json::json!({
                "status": word.status,
                "low": format!("{:#018x}", word.low),
                "high": format!("{:#018x}", word.high),
            }),
        );
    }
    let dr7 = probe
        .read_named(args.partition, args.vp, RegisterName::Dr7)?
        .low(RegisterName::Dr7)?;
    if dr7 & 0xff != 0 {
        bail!("an active debug breakpoint remained after release: DR7={dr7:#018x}");
    }
    let rflags = probe
        .read_named(args.partition, args.vp, RegisterName::Rflags)?
        .low(RegisterName::Rflags)?;
    if rflags & ((1 << 8) | (1 << 16)) != 0 {
        bail!("TF or RF remained set after release: RFLAGS={rflags:#018x}");
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "windbg-mcp.sk-h3-audit.v1",
            "result": "pass",
            "vmwp_pid": args.vmwp_pid,
            "partition_handle": format!("{:#x}", args.partition_handle),
            "partition_id": format!("{:#x}", args.partition),
            "vp": args.vp,
            "cr3": format!("{:#x}", identity.cr3),
            "rip": format!("{:#x}", identity.rip),
            "idtr_base": format!("{:#x}", identity.idtr_base),
            "idtr_limit": format!("{:#x}", identity.idtr_limit),
            "secure_kernel_base": format!("{:#x}", kernel_base),
            "guarded_address": format!("{:#x}", address),
            "guarded_text": hex_bytes(&guarded_text),
            "debug_registers": {
                "dr0": registers["dr0"].clone(),
                "dr1": registers["dr1"].clone(),
                "dr2": registers["dr2"].clone(),
                "dr3": registers["dr3"].clone(),
                "dr6": registers["dr6"].clone(),
                "dr7": registers["dr7"].clone(),
            },
            "rflags": registers["rflags"].clone(),
        }))?
    );
    Ok(())
}

#[derive(Debug)]
struct AuditArgs {
    vmwp_pid: u32,
    partition_handle: u64,
    partition: u64,
    vp: u32,
    expected_cr3: Option<u64>,
    image: PathBuf,
    target_rva: u64,
    expected: Vec<u8>,
}

impl AuditArgs {
    fn parse(args: &[String]) -> Result<Self> {
        let mut vmwp_pid = None;
        let mut partition_handle = None;
        let mut partition = None;
        let mut vp = 0;
        let mut expected_cr3 = None;
        let mut image = None;
        let mut target_rva = None;
        let mut expected = None;
        let mut at = 0;
        while at < args.len() {
            let value = |at: &mut usize| -> Result<&String> {
                *at += 1;
                args.get(*at)
                    .with_context(|| format!("{} requires a value", args[*at - 1]))
            };
            match args[at].as_str() {
                "--vmwp-pid" => {
                    vmwp_pid = Some(value(&mut at)?.parse().context("invalid --vmwp-pid")?)
                }
                "--partition-handle" => partition_handle = Some(parse_u64(value(&mut at)?)?),
                "--partition-id" => partition = Some(parse_u64(value(&mut at)?)?),
                "--vp" => vp = value(&mut at)?.parse().context("invalid --vp")?,
                "--expected-cr3" => expected_cr3 = Some(parse_u64(value(&mut at)?)?),
                "--image" => image = Some(PathBuf::from(value(&mut at)?)),
                "--target-rva" => target_rva = Some(parse_u64(value(&mut at)?)?),
                "--expected-bytes" => expected = Some(parse_hex(value(&mut at)?)?),
                other => bail!("unknown {AUDIT_FLAG} argument {other:?}"),
            }
            at += 1;
        }
        let vmwp_pid = vmwp_pid.context("--vmwp-pid is required")?;
        let partition_handle = partition_handle.context("--partition-handle is required")?;
        let partition = partition.context("--partition-id is required")?;
        let image = image.context("--image is required")?;
        let target_rva = target_rva.context("--target-rva is required")?;
        let expected = expected.context("--expected-bytes is required")?;
        if vmwp_pid == 0 || partition_handle == 0 || partition == 0 {
            bail!("vmwp PID, partition handle and partition id must be nonzero");
        }
        if !image.is_file() {
            bail!("--image is not a file: {}", image.display());
        }
        if expected.is_empty() || expected.len() > 15 {
            bail!("--expected-bytes must contain 1..=15 bytes");
        }
        Ok(Self {
            vmwp_pid,
            partition_handle,
            partition,
            vp,
            expected_cr3,
            image,
            target_rva,
            expected,
        })
    }
}

fn parse_hex(value: &str) -> Result<Vec<u8>> {
    let compact = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .collect::<String>();
    if compact.is_empty()
        || !compact.len().is_multiple_of(2)
        || !compact.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("expected an even, nonempty hexadecimal byte string");
    }
    (0..compact.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&compact[at..at + 2], 16).context("invalid hexadecimal byte"))
        .collect()
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

/// Exercise the operator-installed driver's product ABI without starting or stopping its service.
/// The ignored live tier wraps this role with killed-reader and service-lifecycle controls.
fn qualify_write<D: Ioctl>(
    probe: &Probe<D>,
    target: MemoryTarget,
    gpa: u64,
    offset: u16,
) -> Result<serde_json::Value> {
    let address = gpa
        .checked_add(u64::from(offset))
        .context("qualification write address overflowed")?;
    let (before_answer, before) = probe.read_memory(target, address, 1)?;
    if before_answer.result != MemoryResult::Ok || before.len() != 1 {
        bail!("qualification write source byte was not readable: {before_answer:?}");
    }
    let changed = [before[0] ^ 1];
    let write_answer = probe.write_memory(target, address, &changed);
    if !matches!(&write_answer, Ok(answer) if answer.result == MemoryResult::Ok) {
        let restore_answer = probe.write_memory(target, address, &before);
        let restored_read = probe.read_memory(target, address, 1);
        let restoration = if matches!(
            (&restore_answer, &restored_read),
            (Ok(answer), Ok((read_answer, bytes)))
                if answer.result == MemoryResult::Ok
                    && read_answer.result == MemoryResult::Ok
                    && bytes.as_slice() == before.as_slice()
        ) {
            "verified".into()
        } else {
            format!("write={restore_answer:?}, read={restored_read:?}")
        };
        bail!("qualification write failed ({write_answer:?}); restoration: {restoration}");
    }

    let changed_read = probe.read_memory(target, address, 1);
    let restore_answer = probe.write_memory(target, address, &before);
    let restored_read = probe.read_memory(target, address, 1);
    if !matches!(
        (&restore_answer, &restored_read),
        (Ok(answer), Ok((read_answer, bytes)))
            if answer.result == MemoryResult::Ok
                && read_answer.result == MemoryResult::Ok
                && bytes.as_slice() == before.as_slice()
    ) {
        bail!(
            "qualification write could not prove restoration: write={restore_answer:?}, read={restored_read:?}"
        );
    }
    let (changed_answer, changed_bytes) = changed_read?;
    if changed_answer.result != MemoryResult::Ok || changed_bytes != changed {
        bail!("qualification write did not read back before restoration");
    }
    Ok(serde_json::json!({
        "gpa": format!("{gpa:#x}"),
        "offset": offset,
        "before": hex_bytes(&before),
        "changed": hex_bytes(&changed),
        "restored": true,
    }))
}

pub(crate) fn run_qualify(args: &[String]) -> Result<()> {
    let args = QualifyArgs::parse(args)?;
    let probe = Probe::open()?;
    let identity = probe.identity(args.partition, args.vp)?;
    let target = MemoryTarget {
        owner_pid: args.vmwp_pid,
        partition_handle: args.partition_handle,
        partition_id: args.partition,
    };
    let unknown_ioctl_rejected = probe.unknown_ioctl_is_rejected();
    if !unknown_ioctl_rejected {
        bail!("h3probe accepted an unknown IOCTL");
    }

    let mut corpus = Vec::new();
    for gpa in args.gpas {
        let translation = probe.translate_gpa(target, gpa)?;
        let (answer, data) = probe.read_memory(target, gpa, 16)?;
        corpus.push(serde_json::json!({
            "gpa": format!("{gpa:#x}"),
            "translation": translation,
            "memory": answer,
            "data": hex_bytes(&data),
        }));
    }

    let expected_cr3 = identity.cr3;
    std::thread::scope(|scope| -> Result<()> {
        let mut threads = Vec::new();
        for _ in 0..args.concurrency {
            let probe = &probe;
            threads.push(scope.spawn(move || -> Result<()> {
                for _ in 0..args.iterations {
                    let cr3 = probe
                        .read_named(args.partition, args.vp, RegisterName::Cr3)?
                        .low(RegisterName::Cr3)?;
                    if cr3 != expected_cr3 {
                        bail!("concurrent CR3 read returned {cr3:#x}, expected {expected_cr3:#x}");
                    }
                }
                Ok(())
            }));
        }
        for thread in threads {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("a qualification reader panicked"))??;
        }
        Ok(())
    })?;

    let write = match args.write {
        None => serde_json::Value::Null,
        Some((gpa, offset)) => qualify_write(&probe, target, gpa, offset)?,
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "windbg-mcp.h3probe-qualification.v1",
            "result": "pass",
            "identity": {
                "cr3": format!("{:#x}", identity.cr3),
                "rip": format!("{:#x}", identity.rip),
                "idtr_base": format!("{:#x}", identity.idtr_base),
                "idtr_limit": format!("{:#x}", identity.idtr_limit),
            },
            "unknown_ioctl_rejected": unknown_ioctl_rejected,
            "concurrency": {
                "readers": args.concurrency,
                "iterations_per_reader": args.iterations,
            },
            "corpus": corpus,
            "write": write,
        }))?
    );
    Ok(())
}

#[derive(Debug)]
struct QualifyArgs {
    vmwp_pid: u32,
    partition_handle: u64,
    partition: u64,
    vp: u32,
    gpas: Vec<u64>,
    concurrency: usize,
    iterations: usize,
    write: Option<(u64, u16)>,
}

impl QualifyArgs {
    fn parse(args: &[String]) -> Result<Self> {
        let mut vmwp_pid = None;
        let mut partition_handle = None;
        let mut partition = None;
        let mut vp = 0;
        let mut gpas = Vec::new();
        let mut concurrency = 8;
        let mut iterations = 100;
        let mut write_gpa = None;
        let mut write_offset = 0;
        let mut at = 0;
        while at < args.len() {
            let value = |at: &mut usize| -> Result<&String> {
                *at += 1;
                args.get(*at)
                    .with_context(|| format!("{} requires a value", args[*at - 1]))
            };
            match args[at].as_str() {
                "--vmwp-pid" => {
                    vmwp_pid = Some(value(&mut at)?.parse().context("invalid --vmwp-pid")?)
                }
                "--partition-handle" => partition_handle = Some(parse_u64(value(&mut at)?)?),
                "--partition-id" => partition = Some(parse_u64(value(&mut at)?)?),
                "--vp" => vp = value(&mut at)?.parse().context("invalid --vp")?,
                "--gpa" => gpas.push(parse_u64(value(&mut at)?)?),
                "--concurrency" => {
                    concurrency = value(&mut at)?.parse().context("invalid --concurrency")?
                }
                "--iterations" => {
                    iterations = value(&mut at)?.parse().context("invalid --iterations")?
                }
                "--write-gpa" => write_gpa = Some(parse_u64(value(&mut at)?)?),
                "--write-offset" => {
                    write_offset = value(&mut at)?.parse().context("invalid --write-offset")?
                }
                other => bail!("unknown {QUALIFY_FLAG} argument {other:?}"),
            }
            at += 1;
        }
        let vmwp_pid = vmwp_pid.context("--vmwp-pid is required")?;
        let partition_handle = partition_handle.context("--partition-handle is required")?;
        let partition = partition.context("--partition-id is required")?;
        if vmwp_pid == 0 || partition_handle == 0 || partition == 0 {
            bail!("vmwp PID, partition handle and partition id must be nonzero");
        }
        if gpas.is_empty() {
            bail!("at least one --gpa is required");
        }
        if !(1..=64).contains(&concurrency) || !(1..=10_000).contains(&iterations) {
            bail!("concurrency must be 1..=64 and iterations 1..=10000");
        }
        if write_offset >= PAGE as u16 {
            bail!("--write-offset must be within one page");
        }
        Ok(Self {
            vmwp_pid,
            partition_handle,
            partition,
            vp,
            gpas,
            concurrency,
            iterations,
            write: write_gpa.map(|gpa| (gpa, write_offset)),
        })
    }
}

fn serve_memory<D: Ioctl, R: BufRead, W: Write>(
    probe: &Probe<D>,
    args: &MemoryArgs,
    cr3: u64,
    kernel_base: Option<u64>,
    input: &mut R,
    output: &mut W,
) -> Result<()> {
    let max_read = if args.pages == Pages::H3 { PAGE } else { 16 };
    loop {
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let request = line.trim();
        if request == "SHAPE" {
            write!(output, "SHAPE cr3={cr3:#X}")?;
            if let Some(kernel_base) = kernel_base {
                write!(output, " kernel_base={kernel_base:#X}")?;
            }
            write!(output, " vtl_enabled=1 paging=long max_read={max_read}")?;
            if args.writes {
                write!(
                    output,
                    " max_write={PAGE} write_coherency=instruction_coherent"
                )?;
            }
            writeln!(
                output,
                " read_coherency=explicit_refresh unreadable=cr0:h3probe_not_asked \
                 unreadable=cr4:h3probe_not_asked unreadable=efer:h3probe_not_asked"
            )?;
        } else if request == "REFRESH" {
            writeln!(output, "OK 0")?;
        } else if let Some(rest) = request.strip_prefix("READ ") {
            let fields = rest.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 2 {
                writeln!(output, "ERROR malformed request {request:?}")?;
                output.flush()?;
                continue;
            }
            let parsed = parse_u64(fields[0]).and_then(|gpa| {
                parse_u64(fields[1]).and_then(|size| Ok((gpa, usize::try_from(size)?)))
            });
            let (gpa, size) = match parsed {
                Ok(value) => value,
                Err(_) => {
                    writeln!(output, "ERROR malformed request {request:?}")?;
                    output.flush()?;
                    continue;
                }
            };
            if size > max_read {
                writeln!(
                    output,
                    "ERROR {size} exceeds the declared max_read {max_read}"
                )?;
                output.flush()?;
                continue;
            }
            match read_physical(probe, args, gpa, size) {
                Ok(data) => {
                    writeln!(output, "OK {}", data.len())?;
                    output.write_all(&data)?;
                }
                Err(failure) => writeln!(output, "{failure}")?,
            }
        } else if let Some(rest) = request.strip_prefix("WRITE ") {
            let fields = rest.split_whitespace().collect::<Vec<_>>();
            let parsed = if fields.len() == 2 {
                parse_u64(fields[0]).and_then(|gpa| {
                    parse_u64(fields[1]).and_then(|size| Ok((gpa, usize::try_from(size)?)))
                })
            } else {
                Err(anyhow::anyhow!("malformed"))
            };
            let (gpa, size) = match parsed {
                Ok(value) if (1..=PAGE).contains(&value.1) => value,
                _ => {
                    writeln!(output, "ERROR malformed write request {request:?}")?;
                    output.flush()?;
                    return Ok(());
                }
            };
            let mut data = vec![0u8; size];
            if let Err(error) = input.read_exact(&mut data) {
                writeln!(
                    output,
                    "ERROR write payload ended before {size} bytes: {error}"
                )?;
                output.flush()?;
                return Ok(());
            }
            if !args.writes {
                writeln!(output, "ERROR this transport was started without --writes")?;
            } else if (gpa as usize & (PAGE - 1)) + size > PAGE {
                writeln!(output, "ERROR write must remain within one physical page")?;
            } else {
                let target = args.target.expect("writes exist only for h3 pages");
                match probe.write_memory(target, gpa, &data) {
                    Ok(answer) if answer.result == MemoryResult::Ok => {
                        writeln!(output, "OK {size}")?
                    }
                    Ok(answer) => writeln!(output, "{}", answer.protocol_failure())?,
                    Err(error) => writeln!(output, "ERROR h3 memory: {error:#}")?,
                }
            }
        } else if !request.is_empty() {
            writeln!(output, "ERROR unknown request {request:?}")?;
        }
        output.flush()?;
    }
}

fn read_physical<D: Ioctl>(
    probe: &Probe<D>,
    args: &MemoryArgs,
    mut gpa: u64,
    mut size: usize,
) -> Result<Vec<u8>, String> {
    if size == 0 {
        return Ok(Vec::new());
    }
    if args.pages == Pages::Hypercall {
        return probe
            .read_gpa_hypercall(args.partition, gpa, size)
            .map_err(|error| {
                let detail = format!("{error:#}");
                if detail.starts_with("REFUSED ") {
                    detail
                } else {
                    format!("ERROR {detail}")
                }
            });
    }
    let target = args.target.expect("h3 pages have a memory target");
    let mut data = Vec::with_capacity(size);
    while size > 0 {
        let take = size.min(PAGE - (gpa as usize & (PAGE - 1)));
        match probe.read_memory(target, gpa, take) {
            Ok((answer, bytes)) if answer.result == MemoryResult::Ok => data.extend(bytes),
            Ok((answer, _)) => return Err(answer.protocol_failure()),
            Err(error) => return Err(format!("ERROR h3 memory: {error:#}")),
        }
        gpa += take as u64;
        size -= take;
    }
    Ok(data)
}

fn capabilities() -> Capabilities {
    Capabilities {
        capabilities: vec![
            Capability::BeginArm,
            Capability::FinishArm,
            Capability::PublishStop,
            Capability::HeldEvent,
            Capability::ReadRegisters,
            Capability::WriteRegisters,
            Capability::Release,
            Capability::BreakpointEvents,
            Capability::ActiveVtl,
        ],
        readable_registers: readable(),
        writable_registers: readable()
            .into_iter()
            .filter(|name| writable(*name))
            .collect(),
        max_registers_per_request: 32,
        requires_stop_epoch: true,
        writes_while_running: false,
    }
}

fn readable() -> Vec<RegisterName> {
    vec![
        RegisterName::Rax,
        RegisterName::Rcx,
        RegisterName::Rdx,
        RegisterName::Rbx,
        RegisterName::Rbp,
        RegisterName::Rsi,
        RegisterName::Rdi,
        RegisterName::R8,
        RegisterName::R9,
        RegisterName::R10,
        RegisterName::R11,
        RegisterName::R12,
        RegisterName::R13,
        RegisterName::R14,
        RegisterName::R15,
        RegisterName::Rip,
        RegisterName::Rsp,
        RegisterName::Rflags,
        RegisterName::Cr3,
        RegisterName::Cs,
        RegisterName::Dr0,
        RegisterName::Dr1,
        RegisterName::Dr2,
        RegisterName::Dr3,
        RegisterName::Dr6,
        RegisterName::Dr7,
        RegisterName::Ds,
        RegisterName::Es,
        RegisterName::Fs,
        RegisterName::Gs,
        RegisterName::Ss,
        RegisterName::VsmVpStatus,
    ]
}

fn writable(name: RegisterName) -> bool {
    matches!(
        name,
        RegisterName::Rip
            | RegisterName::Rsp
            | RegisterName::Rflags
            | RegisterName::Dr0
            | RegisterName::Dr1
            | RegisterName::Dr2
            | RegisterName::Dr3
            | RegisterName::Dr6
            | RegisterName::Dr7
    )
}

fn has_duplicates<T: Eq + std::hash::Hash + Copy>(values: &[T]) -> bool {
    let mut unique = std::collections::HashSet::new();
    values.iter().any(|value| !unique.insert(*value))
}

fn epoch(phase: &str) -> Result<StopEpoch> {
    StopEpoch::new(format!("{phase}-{}", crate::client::generate_token()?))
}

fn parse_u64(value: &str) -> Result<u64> {
    value
        .strip_prefix("0x")
        .map(|digits| u64::from_str_radix(digits, 16))
        .unwrap_or_else(|| value.parse())
        .with_context(|| format!("invalid unsigned value {value:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Cursor;
    use std::rc::Rc;

    struct FixedIoctl(Vec<u8>);

    impl Ioctl for FixedIoctl {
        fn ioctl(&self, _code: u32, _input: &[u8], _output_size: usize) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    struct AmbiguousWriteIoctl {
        byte: Rc<Cell<u8>>,
        writes: Rc<Cell<usize>>,
    }

    impl Ioctl for AmbiguousWriteIoctl {
        fn ioctl(&self, _code: u32, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
            let mut answer = vec![0u8; output_size];
            answer[0..4].copy_from_slice(&1u32.to_le_bytes());
            answer[16..20].copy_from_slice(&1u32.to_le_bytes());
            if output_size == 32 {
                self.byte.set(input[40]);
                let attempt = self.writes.get();
                self.writes.set(attempt + 1);
                if attempt == 0 {
                    bail!("the first write reply was lost");
                }
            } else {
                assert_eq!(output_size, 32 + PAGE);
                answer[32] = self.byte.get();
            }
            Ok(answer)
        }
    }

    #[test]
    fn built_in_commands_reexecute_the_current_image_in_the_selected_role() {
        let target = TargetIdentity {
            vm_id: "51749a1f-f939-44f5-b251-1251ef5b64a3".into(),
            partition_id: HexU64(0x85),
            vp: 2,
            vtl: 1,
            expected_cr3: HexU64(0x1201000),
        };
        let control =
            crate::livesrc::split_command(&builtin_command(&target, true, None, true).unwrap());
        assert_eq!(control[1], CONTROL_FLAG);
        assert!(control.contains(&"--allow-transition-cr3".into()));
        assert!(control.contains(&"0x1201000".into()));

        let memory = crate::livesrc::split_command(
            &builtin_command(&target, true, Some((4242, 0x2e0)), false).unwrap(),
        );
        assert_eq!(memory[1], MEMORY_FLAG);
        assert!(memory.contains(&"4242".into()));
        assert!(memory.contains(&"0x2e0".into()));
        assert!(memory.contains(&"--writes".into()));
    }

    #[test]
    fn provider_capabilities_include_active_vtl_and_only_guarded_writes() {
        let capabilities = capabilities();
        assert!(capabilities.capabilities.contains(&Capability::ActiveVtl));
        assert!(
            capabilities
                .writable_registers
                .iter()
                .all(|name| writable(*name))
        );
        assert!(!capabilities.writable_registers.contains(&RegisterName::Cr3));
    }

    #[test]
    fn role_arguments_accept_hex_coordinates_and_reject_missing_identity() {
        let control = ControlArgs::parse(&[
            "--vm-id".into(),
            "51749a1f-f939-44f5-b251-1251ef5b64a3".into(),
            "--partition-id".into(),
            "0x85".into(),
        ])
        .unwrap();
        assert_eq!(control.partition, 0x85);
        assert!(MemoryArgs::parse(&["--partition-id".into(), "0x85".into()]).is_err());
        assert_eq!(parse_hex("cc-90 0f").unwrap(), [0xcc, 0x90, 0x0f]);
        assert_eq!(hex_bytes(&[0xcc, 0x90, 0x0f]), "cc900f");
        assert!(parse_hex("abc").is_err());

        let qualification = QualifyArgs::parse(&[
            "--vmwp-pid".into(),
            "4242".into(),
            "--partition-handle".into(),
            "0x2e0".into(),
            "--partition-id".into(),
            "0x85".into(),
            "--gpa".into(),
            "0x1000".into(),
            "--write-gpa".into(),
            "0x2000".into(),
            "--write-offset".into(),
            "15".into(),
        ])
        .unwrap();
        assert_eq!(qualification.gpas, [0x1000]);
        assert_eq!(qualification.write, Some((0x2000, 15)));
    }

    #[test]
    fn memory_protocol_preserves_typed_absence() {
        let mut answer = vec![0u8; 32 + PAGE];
        answer[0..4].copy_from_slice(&1u32.to_le_bytes());
        answer[4..8].copy_from_slice(&1u32.to_le_bytes());
        answer[8..12].copy_from_slice(&8u32.to_le_bytes());
        answer[24..32].copy_from_slice(&1u64.to_le_bytes());
        let probe = Probe::from_ioctl(FixedIoctl(answer));
        let args = MemoryArgs {
            pages: Pages::H3,
            target: Some(MemoryTarget {
                owner_pid: 4242,
                partition_handle: 0x2e0,
                partition_id: 0x85,
            }),
            partition: 0x85,
            vp: 0,
            expected_cr3: None,
            image: None,
            writes: false,
        };
        let mut input = Cursor::new(b"SHAPE\nREAD 0x1000 8\n".to_vec());
        let mut output = Vec::new();
        serve_memory(
            &probe,
            &args,
            0x1201000,
            Some(0xffff_f807_2000_0000),
            &mut input,
            &mut output,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.starts_with("SHAPE cr3=0x1201000 kernel_base=0xFFFFF80720000000"));
        assert!(output.ends_with("NOTPRESENT\n"), "{output:?}");
    }

    #[test]
    fn an_ambiguous_qualification_write_is_restored_before_it_fails() {
        let byte = Rc::new(Cell::new(0x42));
        let writes = Rc::new(Cell::new(0));
        let probe = Probe::from_ioctl(AmbiguousWriteIoctl {
            byte: Rc::clone(&byte),
            writes: Rc::clone(&writes),
        });
        let error = qualify_write(
            &probe,
            MemoryTarget {
                owner_pid: 4242,
                partition_handle: 0x2e0,
                partition_id: 0x85,
            },
            0x2000,
            15,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("restoration: verified"));
        assert_eq!(writes.get(), 2);
        assert_eq!(byte.get(), 0x42);
    }
}
