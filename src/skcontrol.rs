//! Versioned protocol for an operator-supplied VTL1 execution-control provider.
//!
//! This is the control counterpart to [`crate::livesrc`]. The repository owns the client and the
//! validation rules, while the operator owns the privileged provider. The provider never consumes
//! a VID message queue: a future dedicated debugger worker observes the existing `vmwp` dispatcher,
//! then publishes that exact held event here. The provider supplies guarded VTL1 register access.
//!
//! The provider prints [`READY_LINE`], followed by one JSON [`Hello`] line. Every request and reply
//! after that is one JSON line and names the exact VM, partition, VP, VTL, expected CR3 and epoch.
//! `BeginArm` first moves a debugger-paused target into an arming epoch; register access is legal
//! there until `FinishArm` returns a running epoch. `PublishStop` consumes that running epoch and
//! returns a held-event epoch; `Release` consumes it and returns the next running epoch. Reads and
//! writes are refused while running. A write carries both the expected and replacement value, so a
//! changed register is a refusal rather than a blind overwrite.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub(crate) const CONTROL_PROBE_FLAG: &str = "--sk-control-probe";
pub(crate) const READY_LINE: &str = "windbg-mcp-sk-control/2";

const PROTOCOL_VERSION: u32 = 2;
const MAX_BANNER_LINES: usize = 64;
const MAX_LINE_BYTES: u64 = 64 * 1024;
const MAX_REGISTERS: usize = 32;
const TEARDOWN_GRACE: Duration = Duration::from_secs(10);
const PROVIDER_REPLY_GRACE: Duration = Duration::from_secs(10);

/// A 64-bit word encoded as a hexadecimal string, so JSON consumers never lose address bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, JsonSchema)]
pub(crate) struct HexU64(#[schemars(with = "String")] pub(crate) u64);

impl Serialize for HexU64 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("0x{:016x}", self.0))
    }
}

impl<'de> Deserialize<'de> for HexU64 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let digits = text
            .strip_prefix("0x")
            .ok_or_else(|| serde::de::Error::custom("a 64-bit word must start with 0x"))?;
        if digits.len() != 16 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(serde::de::Error::custom(
                "a 64-bit word must contain exactly 16 hexadecimal digits",
            ));
        }
        u64::from_str_radix(digits, 16)
            .map(HexU64)
            .map_err(serde::de::Error::custom)
    }
}

/// Exact guest coordinate bound to one provider process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetIdentity {
    pub(crate) vm_id: String,
    pub(crate) partition_id: HexU64,
    pub(crate) vp: u32,
    pub(crate) vtl: u8,
    pub(crate) expected_cr3: HexU64,
}

/// Coordinates proved before a register provider starts. The provider's hello supplies the CR3;
/// an operator value, when present, is only an assertion over that provider-reported value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TargetSelector {
    pub(crate) vm_id: String,
    pub(crate) partition_id: HexU64,
    pub(crate) vp: u32,
    pub(crate) expected_cr3: Option<HexU64>,
}

impl TargetSelector {
    fn validate(&self) -> Result<()> {
        let probe = TargetIdentity {
            vm_id: self.vm_id.clone(),
            partition_id: self.partition_id,
            vp: self.vp,
            vtl: 1,
            expected_cr3: self.expected_cr3.unwrap_or(HexU64(0x1000)),
        };
        probe.validate()
    }

    fn require(&self, actual: &TargetIdentity) -> Result<()> {
        self.validate()?;
        actual.validate()?;
        if !actual.vm_id.eq_ignore_ascii_case(&self.vm_id)
            || actual.partition_id != self.partition_id
            || actual.vp != self.vp
            || actual.vtl != 1
        {
            bail!(
                "provider hello does not name the target requested by the operator or discovered \
                 by the worker"
            );
        }
        if let Some(expected_cr3) = self.expected_cr3
            && actual.expected_cr3 != expected_cr3
        {
            bail!(
                "provider hello CR3 {:#x} does not match asserted CR3 {:#x}",
                actual.expected_cr3.0,
                expected_cr3.0
            );
        }
        Ok(())
    }
}

impl TargetIdentity {
    pub(crate) fn validate(&self) -> Result<()> {
        let bytes = self.vm_id.as_bytes();
        if bytes.len() != 36
            || !bytes.iter().enumerate().all(|(index, byte)| {
                matches!(index, 8 | 13 | 18 | 23) && *byte == b'-'
                    || !matches!(index, 8 | 13 | 18 | 23) && byte.is_ascii_hexdigit()
            })
        {
            bail!("vm_id must be a canonical 36-character GUID");
        }
        if self.partition_id.0 == 0 {
            bail!("partition_id must be nonzero");
        }
        if self.vtl != 1 {
            bail!("this protocol revision controls VTL1, not VTL{}", self.vtl);
        }
        if self.expected_cr3.0 == 0 || self.expected_cr3.0 & 0xfff != 0 {
            bail!("expected_cr3 must be a nonzero page-aligned address");
        }
        Ok(())
    }
}

/// Opaque, bounded token which changes at every running/stopped transition.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub(crate) struct StopEpoch(String);

impl StopEpoch {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() < 16
            || value.len() > 128
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            bail!("a stop epoch must contain 16..=128 visible ASCII bytes");
        }
        Ok(Self(value))
    }
}

impl fmt::Display for StopEpoch {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RegisterName {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rip,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rflags,
    Cr3,
    Cs,
    Ds,
    Es,
    Fs,
    Gs,
    Ss,
    Dr0,
    Dr1,
    Dr2,
    Dr3,
    Dr6,
    Dr7,
    VsmVpStatus,
}

impl RegisterName {
    fn writable(self) -> bool {
        matches!(
            self,
            Self::Rip
                | Self::Rsp
                | Self::Rflags
                | Self::Dr0
                | Self::Dr1
                | Self::Dr2
                | Self::Dr3
                | Self::Dr6
                | Self::Dr7
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisterValue {
    pub(crate) name: RegisterName,
    pub(crate) status: u16,
    pub(crate) low: HexU64,
    pub(crate) high: HexU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisterWrite {
    pub(crate) name: RegisterName,
    pub(crate) expected: HexU64,
    pub(crate) value: HexU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Capability {
    BeginArm,
    FinishArm,
    PublishStop,
    HeldEvent,
    ReadRegisters,
    WriteRegisters,
    Release,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Capabilities {
    pub(crate) capabilities: Vec<Capability>,
    pub(crate) readable_registers: Vec<RegisterName>,
    pub(crate) writable_registers: Vec<RegisterName>,
    pub(crate) max_registers_per_request: u16,
    pub(crate) requires_stop_epoch: bool,
    pub(crate) writes_while_running: bool,
}

impl Capabilities {
    fn validate(&self) -> Result<()> {
        for required in [
            Capability::BeginArm,
            Capability::FinishArm,
            Capability::PublishStop,
            Capability::HeldEvent,
            Capability::ReadRegisters,
            Capability::WriteRegisters,
            Capability::Release,
        ] {
            if !self.capabilities.contains(&required) {
                bail!("provider does not advertise required capability {required:?}");
            }
        }
        if self.max_registers_per_request == 0
            || usize::from(self.max_registers_per_request) > MAX_REGISTERS
        {
            bail!(
                "max_registers_per_request must be in 1..={MAX_REGISTERS}, got {}",
                self.max_registers_per_request
            );
        }
        if !self.requires_stop_epoch || self.writes_while_running {
            bail!("provider must require epochs and refuse writes while running");
        }
        if self
            .writable_registers
            .iter()
            .any(|register| !register.writable())
        {
            bail!("provider advertised a read-only register as writable");
        }
        unique(&self.readable_registers, "readable register")?;
        unique(&self.writable_registers, "writable register")?;
        if self
            .writable_registers
            .iter()
            .any(|register| !self.readable_registers.contains(register))
        {
            bail!("every writable register must also be readable");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum StopReason {
    /// Raw vector-1 event as observed by the dispatcher. The worker replaces this with the exact
    /// architectural cause after it has published the held event and can read the VP's DR6.
    DebugException,
    HardwareBreakpoint {
        slot: u8,
    },
    SingleStep,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeldEvent {
    pub(crate) message_type: HexU64,
    pub(crate) vector: u8,
    pub(crate) vp: u32,
    pub(crate) vtl: u8,
    pub(crate) cpl: u8,
    pub(crate) dispatcher_context: HexU64,
    pub(crate) advance_instruction_pointer: bool,
    pub(crate) reason: StopReason,
}

impl HeldEvent {
    pub(crate) fn validate(&self, target: &TargetIdentity) -> Result<()> {
        if self.message_type.0 != 0x0100_0002 {
            bail!(
                "held event has unexpected message type {:#x}",
                self.message_type.0
            );
        }
        if self.vector != 1 {
            bail!("held event is vector {}, expected vector 1", self.vector);
        }
        if self.vp != target.vp || self.vtl != target.vtl || self.cpl != 0 {
            bail!("held event is not the bound VTL1 CPL0 VP");
        }
        if self.dispatcher_context.0 == 0 {
            bail!("held event has no dispatcher context");
        }
        if self.advance_instruction_pointer {
            bail!("held event requested native instruction-pointer advance");
        }
        if matches!(self.reason, StopReason::HardwareBreakpoint { slot } if slot > 3) {
            bail!("hardware breakpoint slot must be in 0..=3");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hello {
    pub(crate) protocol: u32,
    pub(crate) target: TargetIdentity,
    pub(crate) epoch: StopEpoch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Operation {
    Capabilities,
    BeginArm,
    FinishArm,
    PublishStop { event: HeldEvent },
    HeldEvent,
    ReadRegisters { registers: Vec<RegisterName> },
    WriteRegisters { writes: Vec<RegisterWrite> },
    Release,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) protocol: u32,
    pub(crate) id: u64,
    pub(crate) target: TargetIdentity,
    pub(crate) epoch: StopEpoch,
    pub(crate) operation: Operation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ReplyValue {
    Capabilities { value: Capabilities },
    ArmBegun,
    ArmFinished,
    StopPublished { event: HeldEvent },
    HeldEvent { event: HeldEvent },
    Registers { values: Vec<RegisterValue> },
    RegistersWritten { values: Vec<RegisterValue> },
    Released,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorCode {
    StaleEpoch,
    WrongTarget,
    Running,
    NotStopped,
    UnsupportedRegister,
    GuardMismatch,
    Provider,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderError {
    pub(crate) code: ErrorCode,
    pub(crate) detail: String,
}

/// A complete, aligned refusal from the provider. Callers may downcast `anyhow::Error` to this.
#[derive(Debug)]
pub(crate) struct ProviderRefusal {
    pub(crate) code: ErrorCode,
    pub(crate) detail: String,
}

impl fmt::Display for ProviderRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "provider refused with {:?}: {}",
            self.code, self.detail
        )
    }
}

impl std::error::Error for ProviderRefusal {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Outcome {
    Ok { value: ReplyValue },
    Error { error: ProviderError },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
    pub(crate) protocol: u32,
    pub(crate) id: u64,
    pub(crate) target: TargetIdentity,
    /// The current epoch after this operation. It changes only on a state-transition success.
    pub(crate) epoch: StopEpoch,
    pub(crate) outcome: Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Running,
    Arming,
    Stopped(HeldEvent),
}

/// Synchronous, single-owner client. The dedicated worker will own one on its engine thread.
pub(crate) struct ControlSession<R: BufRead, W: Write> {
    reader: R,
    writer: W,
    target: TargetIdentity,
    epoch: StopEpoch,
    issued_epochs: HashSet<StopEpoch>,
    next_id: u64,
    capabilities: Option<Capabilities>,
    phase: Phase,
    poisoned: bool,
}

impl<R: BufRead, W: Write> ControlSession<R, W> {
    #[cfg(test)]
    pub(crate) fn open(
        reader: R,
        writer: W,
        expected_target: TargetIdentity,
    ) -> Result<(Self, Vec<String>)> {
        expected_target.validate()?;
        Self::open_selected(
            reader,
            writer,
            TargetSelector {
                vm_id: expected_target.vm_id,
                partition_id: expected_target.partition_id,
                vp: expected_target.vp,
                expected_cr3: Some(expected_target.expected_cr3),
            },
        )
    }

    fn open_selected(
        mut reader: R,
        writer: W,
        expected_target: TargetSelector,
    ) -> Result<(Self, Vec<String>)> {
        expected_target.validate()?;
        let mut skipped = Vec::new();
        for _ in 0..MAX_BANNER_LINES {
            let line = read_line(&mut reader)?;
            let ready = line.trim();
            if ready.starts_with("windbg-mcp-sk-control/") && ready != READY_LINE {
                bail!("provider ready line is {ready:?}, expected {READY_LINE:?}");
            }
            if ready == READY_LINE {
                let hello_line = read_line(&mut reader).context("provider omitted its hello")?;
                let hello: Hello = serde_json::from_str(&hello_line)
                    .with_context(|| format!("invalid provider hello: {hello_line:?}"))?;
                if hello.protocol != PROTOCOL_VERSION {
                    bail!(
                        "provider protocol is {}, expected {PROTOCOL_VERSION}",
                        hello.protocol
                    );
                }
                expected_target.require(&hello.target)?;
                StopEpoch::new(hello.epoch.0.clone())?;
                let issued_epochs = HashSet::from([hello.epoch.clone()]);
                return Ok((
                    Self {
                        reader,
                        writer,
                        target: hello.target,
                        epoch: hello.epoch,
                        issued_epochs,
                        next_id: 1,
                        capabilities: None,
                        phase: Phase::Running,
                        poisoned: false,
                    },
                    skipped,
                ));
            }
            skipped.push(line);
        }
        bail!("provider printed {MAX_BANNER_LINES} lines without {READY_LINE:?}")
    }

    pub(crate) fn target(&self) -> &TargetIdentity {
        &self.target
    }

    pub(crate) fn epoch(&self) -> &StopEpoch {
        &self.epoch
    }

    pub(crate) fn capabilities(&mut self) -> Result<Capabilities> {
        let response = self.exchange(Operation::Capabilities)?;
        let ReplyValue::Capabilities { value } = response else {
            bail!("provider returned the wrong reply to capabilities")
        };
        value.validate()?;
        self.capabilities = Some(value.clone());
        Ok(value)
    }

    pub(crate) fn begin_arm(&mut self) -> Result<()> {
        self.require_capability(Capability::BeginArm)?;
        if self.phase != Phase::Running {
            bail!("begin_arm requires running state");
        }
        if self.exchange(Operation::BeginArm)? != ReplyValue::ArmBegun {
            bail!("provider returned the wrong reply to begin_arm");
        }
        self.phase = Phase::Arming;
        Ok(())
    }

    pub(crate) fn finish_arm(&mut self) -> Result<()> {
        self.require_capability(Capability::FinishArm)?;
        if self.phase != Phase::Arming {
            bail!("finish_arm requires arming state");
        }
        if self.exchange(Operation::FinishArm)? != ReplyValue::ArmFinished {
            bail!("provider returned the wrong reply to finish_arm");
        }
        self.phase = Phase::Running;
        Ok(())
    }

    pub(crate) fn publish_stop(&mut self, event: HeldEvent) -> Result<()> {
        self.require_capability(Capability::PublishStop)?;
        if self.phase != Phase::Running {
            bail!("cannot publish a second event while one is held");
        }
        event.validate(&self.target)?;
        let response = self.exchange(Operation::PublishStop {
            event: event.clone(),
        })?;
        let ReplyValue::StopPublished { event: echoed } = response else {
            bail!("provider returned the wrong reply to publish_stop")
        };
        if echoed != event {
            self.poisoned = true;
            bail!("provider changed the held-event identity")
        }
        self.phase = Phase::Stopped(event);
        Ok(())
    }

    pub(crate) fn held_event(&mut self) -> Result<HeldEvent> {
        self.require_stopped()?;
        self.require_capability(Capability::HeldEvent)?;
        let response = self.exchange(Operation::HeldEvent)?;
        let ReplyValue::HeldEvent { event } = response else {
            bail!("provider returned the wrong reply to held_event")
        };
        event.validate(&self.target)?;
        if Some(&event) != self.held() {
            self.poisoned = true;
            bail!("provider returned a different held-event identity")
        }
        Ok(event)
    }

    pub(crate) fn read_registers(
        &mut self,
        registers: Vec<RegisterName>,
    ) -> Result<Vec<RegisterValue>> {
        self.require_register_stop()?;
        self.require_capability(Capability::ReadRegisters)?;
        self.validate_register_names(&registers, false)?;
        let response = self.exchange(Operation::ReadRegisters {
            registers: registers.clone(),
        })?;
        let ReplyValue::Registers { values } = response else {
            bail!("provider returned the wrong reply to read_registers")
        };
        if let Err(error) = validate_values(&registers, &values) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(values)
    }

    pub(crate) fn write_registers(
        &mut self,
        writes: Vec<RegisterWrite>,
    ) -> Result<Vec<RegisterValue>> {
        self.require_register_stop()?;
        self.require_capability(Capability::WriteRegisters)?;
        if writes.is_empty() {
            bail!("write_registers requires at least one guarded write");
        }
        let names: Vec<_> = writes.iter().map(|write| write.name).collect();
        self.validate_register_names(&names, true)?;
        let response = self.exchange(Operation::WriteRegisters { writes })?;
        let ReplyValue::RegistersWritten { values } = response else {
            bail!("provider returned the wrong reply to write_registers")
        };
        if let Err(error) = validate_values(&names, &values) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(values)
    }

    pub(crate) fn release(&mut self) -> Result<()> {
        self.require_stopped()?;
        self.require_capability(Capability::Release)?;
        let response = self.exchange(Operation::Release)?;
        if response != ReplyValue::Released {
            bail!("provider returned the wrong reply to release")
        }
        self.phase = Phase::Running;
        Ok(())
    }

    fn held(&self) -> Option<&HeldEvent> {
        match &self.phase {
            Phase::Running | Phase::Arming => None,
            Phase::Stopped(event) => Some(event),
        }
    }

    fn require_register_stop(&self) -> Result<()> {
        if self.phase == Phase::Running {
            bail!("register access is refused while the target is running")
        }
        Ok(())
    }

    fn require_stopped(&self) -> Result<()> {
        if self.held().is_none() {
            bail!("operation requires a held event")
        }
        Ok(())
    }

    fn require_capability(&self, capability: Capability) -> Result<()> {
        let capabilities = self
            .capabilities
            .as_ref()
            .context("capabilities must be negotiated before control operations")?;
        if !capabilities.capabilities.contains(&capability) {
            bail!("provider did not advertise {capability:?}");
        }
        Ok(())
    }

    fn validate_register_names(&self, registers: &[RegisterName], writes: bool) -> Result<()> {
        if registers.is_empty() || registers.len() > MAX_REGISTERS {
            bail!("register request size must be in 1..={MAX_REGISTERS}");
        }
        unique(registers, "register")?;
        let capabilities = self
            .capabilities
            .as_ref()
            .context("capabilities were not negotiated")?;
        if registers.len() > usize::from(capabilities.max_registers_per_request) {
            bail!("register request exceeds the provider's declared maximum");
        }
        let allowed = if writes {
            &capabilities.writable_registers
        } else {
            &capabilities.readable_registers
        };
        if let Some(register) = registers
            .iter()
            .find(|register| !allowed.contains(register))
        {
            bail!("provider does not support requested register {register:?}");
        }
        Ok(())
    }

    fn exchange(&mut self, operation: Operation) -> Result<ReplyValue> {
        if self.poisoned {
            bail!("control protocol desynchronised; no further request is allowed");
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .context("control request id exhausted")?;
        let expected = ExpectedReply::for_operation(&operation);
        let request = Request {
            protocol: PROTOCOL_VERSION,
            id,
            target: self.target.clone(),
            epoch: self.epoch.clone(),
            operation,
        };
        let mut encoded = serde_json::to_vec(&request)?;
        encoded.push(b'\n');
        self.poisoned = true;
        self.writer.write_all(&encoded)?;
        self.writer.flush()?;
        let line = read_line(&mut self.reader)?;
        let response: Response = serde_json::from_str(&line)
            .with_context(|| format!("invalid provider response: {line:?}"))?;
        if response.protocol != PROTOCOL_VERSION
            || response.id != id
            || response.target != self.target
        {
            bail!("provider response did not match protocol, request id, and target identity");
        }
        match response.outcome {
            Outcome::Error { error } => {
                if response.epoch != self.epoch {
                    bail!("an error response changed the epoch");
                }
                self.poisoned = false;
                Err(anyhow::Error::new(ProviderRefusal {
                    code: error.code,
                    detail: error.detail,
                }))
            }
            Outcome::Ok { value } => {
                if !expected.matches(&value) {
                    bail!("provider returned a reply for a different operation");
                }
                let changes_epoch = matches!(
                    value,
                    ReplyValue::ArmBegun
                        | ReplyValue::ArmFinished
                        | ReplyValue::StopPublished { .. }
                        | ReplyValue::Released
                );
                if changes_epoch {
                    if self.issued_epochs.contains(&response.epoch) {
                        bail!("a state transition reused an epoch issued earlier in this session");
                    }
                    StopEpoch::new(response.epoch.0.clone())?;
                    self.issued_epochs.insert(response.epoch.clone());
                    self.epoch = response.epoch;
                } else if response.epoch != self.epoch {
                    bail!("a non-transitioning operation changed the epoch");
                }
                self.poisoned = false;
                Ok(value)
            }
        }
    }
}

/// Moves blocking pipe reads off the engine thread and gives each provider line a hard deadline.
/// The reader owns stdout until the provider exits; dropping the receiver makes its next send end
/// the thread, and [`ChildGuard`] closes a provider which remains blocked in its own write loop.
struct TimedChildReader {
    lines: Receiver<io::Result<Vec<u8>>>,
    current: Vec<u8>,
    offset: usize,
    eof: bool,
    reply_grace: Duration,
    outer_deadline: Option<Instant>,
}

impl TimedChildReader {
    fn spawn(stdout: ChildStdout) -> Result<Self> {
        let (send, lines) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("sk-control-reader".into())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    let mut line = Vec::new();
                    let read = {
                        let mut limited = Read::take(&mut reader, MAX_LINE_BYTES);
                        limited.read_until(b'\n', &mut line)
                    };
                    match read {
                        Ok(0) => {
                            let _ = send.send(Ok(Vec::new()));
                            break;
                        }
                        Ok(_) => {
                            if send.send(Ok(line)).is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = send.send(Err(error));
                            break;
                        }
                    }
                }
            })
            .context("spawning the control-provider reader failed")?;
        Ok(Self {
            lines,
            current: Vec::new(),
            offset: 0,
            eof: false,
            reply_grace: PROVIDER_REPLY_GRACE,
            outer_deadline: None,
        })
    }

    #[cfg(test)]
    fn from_receiver(lines: Receiver<io::Result<Vec<u8>>>, reply_grace: Duration) -> Self {
        Self {
            lines,
            current: Vec::new(),
            offset: 0,
            eof: false,
            reply_grace,
            outer_deadline: None,
        }
    }

    fn set_outer_deadline(&mut self, deadline: Option<Instant>) {
        self.outer_deadline = deadline;
    }

    fn receive(&mut self) -> io::Result<()> {
        if self.eof || self.offset < self.current.len() {
            return Ok(());
        }
        self.current.clear();
        self.offset = 0;
        let wait = match self.outer_deadline {
            Some(deadline) => deadline
                .saturating_duration_since(Instant::now())
                .min(self.reply_grace),
            None => self.reply_grace,
        };
        if wait.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "control-provider operation reached its outer deadline",
            ));
        }
        match self.lines.recv_timeout(wait) {
            Ok(Ok(line)) if line.is_empty() => self.eof = true,
            Ok(Ok(line)) => self.current = line,
            Ok(Err(error)) => return Err(error),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "control provider sent no complete line within {} seconds",
                        wait.as_secs_f64()
                    ),
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "control provider reader stopped",
                ));
            }
        }
        Ok(())
    }
}

impl Read for TimedChildReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let length = output.len().min(available.len());
        output[..length].copy_from_slice(&available[..length]);
        self.consume(length);
        Ok(length)
    }
}

impl BufRead for TimedChildReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.receive()?;
        Ok(&self.current[self.offset..])
    }

    fn consume(&mut self, amount: usize) {
        self.offset = self.current.len().min(self.offset.saturating_add(amount));
    }
}

/// Owns one operator provider and closes its request pipe before applying the bounded child-process
/// teardown. The live-control worker keeps this object on its engine thread beside its dispatcher.
pub(crate) struct ControlProcess {
    session: Option<ControlSession<TimedChildReader, ChildStdin>>,
    child: ChildGuard,
}

impl ControlProcess {
    pub(crate) fn spawn(
        transport: &str,
        expected_target: TargetIdentity,
    ) -> Result<(Self, Vec<String>)> {
        Self::spawn_selected(
            transport,
            TargetSelector {
                vm_id: expected_target.vm_id,
                partition_id: expected_target.partition_id,
                vp: expected_target.vp,
                expected_cr3: Some(expected_target.expected_cr3),
            },
        )
    }

    pub(crate) fn spawn_selected(
        transport: &str,
        expected_target: TargetSelector,
    ) -> Result<(Self, Vec<String>)> {
        let mut parts = crate::livesrc::split_command(transport);
        let program = parts
            .first()
            .cloned()
            .context("the control provider command line is empty")?;
        let mut command = Command::new(&program);
        command
            .args(parts.split_off(1))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let child = {
            let _guard = crate::engine::spawn_guard();
            command
                .spawn()
                .with_context(|| format!("spawning the control provider {program:?} failed"))?
        };
        let mut child = ChildGuard(Some(child));
        let stdin = child
            .0
            .as_mut()
            .and_then(|child| child.stdin.take())
            .context("the provider has no stdin")?;
        let stdout = child
            .0
            .as_mut()
            .and_then(|child| child.stdout.take())
            .context("the provider has no stdout")?;
        let (session, skipped) = ControlSession::open_selected(
            TimedChildReader::spawn(stdout)?,
            stdin,
            expected_target,
        )?;
        Ok((
            Self {
                session: Some(session),
                child,
            },
            skipped,
        ))
    }

    fn session(&self) -> &ControlSession<TimedChildReader, ChildStdin> {
        self.session
            .as_ref()
            .expect("a live ControlProcess always owns its session")
    }

    fn session_mut(&mut self) -> &mut ControlSession<TimedChildReader, ChildStdin> {
        self.session
            .as_mut()
            .expect("a live ControlProcess always owns its session")
    }

    pub(crate) fn target(&self) -> &TargetIdentity {
        self.session().target()
    }

    pub(crate) fn epoch(&self) -> &StopEpoch {
        self.session().epoch()
    }

    pub(crate) fn capabilities(&mut self) -> Result<Capabilities> {
        self.session_mut().capabilities()
    }

    pub(crate) fn begin_arm(&mut self) -> Result<()> {
        self.session_mut().begin_arm()
    }

    pub(crate) fn finish_arm(&mut self) -> Result<()> {
        self.session_mut().finish_arm()
    }

    pub(crate) fn publish_stop(&mut self, event: HeldEvent) -> Result<()> {
        self.session_mut().publish_stop(event)
    }

    pub(crate) fn held_event(&mut self) -> Result<HeldEvent> {
        self.session_mut().held_event()
    }

    pub(crate) fn read_registers(
        &mut self,
        registers: Vec<RegisterName>,
    ) -> Result<Vec<RegisterValue>> {
        self.session_mut().read_registers(registers)
    }

    pub(crate) fn read_registers_until(
        &mut self,
        registers: Vec<RegisterName>,
        deadline: Instant,
    ) -> Result<Vec<RegisterValue>> {
        if Instant::now() >= deadline {
            bail!("control-provider register read reached its outer deadline");
        }
        let session = self.session_mut();
        session.reader.set_outer_deadline(Some(deadline));
        let result = session.read_registers(registers);
        session.reader.set_outer_deadline(None);
        result
    }

    pub(crate) fn set_outer_deadline(&mut self, deadline: Option<Instant>) {
        self.session_mut().reader.set_outer_deadline(deadline);
    }

    pub(crate) fn write_registers(
        &mut self,
        writes: Vec<RegisterWrite>,
    ) -> Result<Vec<RegisterValue>> {
        self.session_mut().write_registers(writes)
    }

    pub(crate) fn release(&mut self) -> Result<()> {
        self.session_mut().release()
    }
}

impl Drop for ControlProcess {
    fn drop(&mut self) {
        drop(self.session.take());
        self.child.reap();
    }
}

#[derive(Clone, Copy)]
enum ExpectedReply {
    Capabilities,
    ArmBegun,
    ArmFinished,
    StopPublished,
    HeldEvent,
    Registers,
    RegistersWritten,
    Released,
}

impl ExpectedReply {
    fn for_operation(operation: &Operation) -> Self {
        match operation {
            Operation::Capabilities => Self::Capabilities,
            Operation::BeginArm => Self::ArmBegun,
            Operation::FinishArm => Self::ArmFinished,
            Operation::PublishStop { .. } => Self::StopPublished,
            Operation::HeldEvent => Self::HeldEvent,
            Operation::ReadRegisters { .. } => Self::Registers,
            Operation::WriteRegisters { .. } => Self::RegistersWritten,
            Operation::Release => Self::Released,
        }
    }

    fn matches(self, value: &ReplyValue) -> bool {
        matches!(
            (self, value),
            (Self::Capabilities, ReplyValue::Capabilities { .. })
                | (Self::ArmBegun, ReplyValue::ArmBegun)
                | (Self::ArmFinished, ReplyValue::ArmFinished)
                | (Self::StopPublished, ReplyValue::StopPublished { .. })
                | (Self::HeldEvent, ReplyValue::HeldEvent { .. })
                | (Self::Registers, ReplyValue::Registers { .. })
                | (Self::RegistersWritten, ReplyValue::RegistersWritten { .. })
                | (Self::Released, ReplyValue::Released)
        )
    }
}

fn validate_values(wanted: &[RegisterName], values: &[RegisterValue]) -> Result<()> {
    if wanted.len() != values.len() {
        bail!(
            "provider returned {} register values for {} names",
            values.len(),
            wanted.len()
        );
    }
    let names: Vec<_> = values.iter().map(|value| value.name).collect();
    unique(&names, "returned register")?;
    if names != wanted {
        bail!("provider returned registers in a different order or with different names");
    }
    Ok(())
}

fn unique<T: Eq>(values: &[T], what: &str) -> Result<()> {
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            bail!("duplicate {what}");
        }
    }
    Ok(())
}

fn read_line(reader: &mut impl BufRead) -> Result<String> {
    let mut line = String::new();
    let mut limited = std::io::Read::take(reader, MAX_LINE_BYTES);
    let read = limited.read_line(&mut line)?;
    if read == 0 {
        bail!("provider closed its stdout");
    }
    if read as u64 == MAX_LINE_BYTES && !line.ends_with('\n') {
        bail!("provider sent {MAX_LINE_BYTES} bytes without a newline");
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// One-shot handshake/capability probe for an operator-supplied provider.
pub(crate) fn run_probe(args: &[String]) -> Result<()> {
    let mut transport = None;
    let mut vm_id = None;
    let mut partition_id = None;
    let mut expected_cr3 = None;
    let mut vp = 0;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--transport" => {
                transport = Some(
                    iter.next()
                        .context("--transport needs a command line")?
                        .clone(),
                );
            }
            "--vm-id" => vm_id = Some(iter.next().context("--vm-id needs a GUID")?.clone()),
            "--partition-id" => {
                partition_id = Some(cli_word(
                    "partition-id",
                    iter.next().context("--partition-id needs a value")?,
                )?)
            }
            "--expected-cr3" => {
                expected_cr3 = Some(cli_word(
                    "expected-cr3",
                    iter.next().context("--expected-cr3 needs a value")?,
                )?)
            }
            "--vp" => {
                vp = iter
                    .next()
                    .context("--vp needs a number")?
                    .parse()
                    .context("--vp must be an unsigned decimal number")?;
            }
            other => bail!("unknown argument {other:?}\n\n{}", usage()),
        }
    }
    let transport = transport.context(usage())?;
    let expected_target = TargetIdentity {
        vm_id: vm_id.context("--vm-id is required")?,
        partition_id: HexU64(partition_id.context("--partition-id is required")?),
        vp,
        vtl: 1,
        expected_cr3: HexU64(expected_cr3.context("--expected-cr3 is required")?),
    };
    expected_target.validate()?;
    let (mut session, skipped) = ControlProcess::spawn(&transport, expected_target)?;
    for line in skipped {
        eprintln!("provider: {line}");
    }
    let capabilities = session.capabilities()?;
    println!("build       {}", crate::BUILD_VERSION);
    println!("transport   {transport}");
    println!("target      {}", serde_json::to_string(session.target())?);
    println!("epoch       {}", session.epoch());
    println!("capabilities {}", serde_json::to_string(&capabilities)?);
    Ok(())
}

fn usage() -> String {
    format!(
        "usage: windbg-mcp {CONTROL_PROBE_FLAG} --transport \"<command line>\" \
         --vm-id <guid> --partition-id <number> --expected-cr3 <number> [--vp <number>]\n\n\
         The operator supplies the provider and exact target. This command validates only its \
         identity, epoch and capability handshake."
    )
}

fn cli_word(name: &str, value: &str) -> Result<u64> {
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse(),
    }
    .with_context(|| format!("--{name} must be a hexadecimal 0x value or unsigned decimal"))
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn reap(&mut self) {
        let Some(child) = self.0.as_mut() else {
            return;
        };
        let deadline = Instant::now() + TEARDOWN_GRACE;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.0.take();
                    return;
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => break,
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        self.0.take();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.reap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const EPOCH_RUNNING: &str = "running-0000000000000001";
    const EPOCH_STOPPED: &str = "stopped-0000000000000001";
    const EPOCH_RESUMED: &str = "running-0000000000000003";

    fn target() -> TargetIdentity {
        TargetIdentity {
            vm_id: "11111111-2222-3333-4444-555555555555".into(),
            partition_id: HexU64(0x85),
            vp: 0,
            vtl: 1,
            expected_cr3: HexU64(0x120_1000),
        }
    }

    #[test]
    fn selector_accepts_provider_cr3_when_operator_supplies_no_assertion() {
        let actual = target();
        let selector = TargetSelector {
            vm_id: actual.vm_id.clone(),
            partition_id: actual.partition_id,
            vp: actual.vp,
            expected_cr3: None,
        };
        selector.require(&actual).unwrap();

        let mut other = actual.clone();
        other.expected_cr3 = HexU64(0x220_1000);
        selector.require(&other).unwrap();
    }

    fn event() -> HeldEvent {
        HeldEvent {
            message_type: HexU64(0x0100_0002),
            vector: 1,
            vp: 0,
            vtl: 1,
            cpl: 0,
            dispatcher_context: HexU64(0x236_c8b4_53d0),
            advance_instruction_pointer: false,
            reason: StopReason::DebugException,
        }
    }

    fn capabilities() -> Capabilities {
        let readable_registers = vec![
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
            RegisterName::VsmVpStatus,
        ];
        Capabilities {
            capabilities: vec![
                Capability::BeginArm,
                Capability::FinishArm,
                Capability::PublishStop,
                Capability::HeldEvent,
                Capability::ReadRegisters,
                Capability::WriteRegisters,
                Capability::Release,
            ],
            writable_registers: readable_registers
                .iter()
                .copied()
                .filter(|register| register.writable())
                .collect(),
            readable_registers,
            max_registers_per_request: 16,
            requires_stop_epoch: true,
            writes_while_running: false,
        }
    }

    fn response(id: u64, epoch: &str, value: ReplyValue) -> String {
        serde_json::to_string(&Response {
            protocol: PROTOCOL_VERSION,
            id,
            target: target(),
            epoch: StopEpoch::new(epoch).unwrap(),
            outcome: Outcome::Ok { value },
        })
        .unwrap()
    }

    fn refusal(id: u64, code: ErrorCode, detail: &str) -> String {
        serde_json::to_string(&Response {
            protocol: PROTOCOL_VERSION,
            id,
            target: target(),
            epoch: StopEpoch::new(EPOCH_RUNNING).unwrap(),
            outcome: Outcome::Error {
                error: ProviderError {
                    code,
                    detail: detail.into(),
                },
            },
        })
        .unwrap()
    }

    fn scripted(lines: &[String]) -> ControlSession<Cursor<Vec<u8>>, Vec<u8>> {
        let hello = serde_json::to_string(&Hello {
            protocol: PROTOCOL_VERSION,
            target: target(),
            epoch: StopEpoch::new(EPOCH_RUNNING).unwrap(),
        })
        .unwrap();
        let mut input = format!("banner from provider\n{READY_LINE}\n{hello}\n");
        for line in lines {
            input.push_str(line);
            input.push('\n');
        }
        let (session, skipped) =
            ControlSession::open(Cursor::new(input.into_bytes()), Vec::new(), target()).unwrap();
        assert_eq!(skipped, ["banner from provider"]);
        session
    }

    #[test]
    fn a_fake_provider_exercises_the_complete_stopped_epoch_protocol() {
        let event = event();
        let read = vec![
            RegisterValue {
                name: RegisterName::Rip,
                status: 0,
                low: HexU64(0xffff_f807_304b_512b),
                high: HexU64(0),
            },
            RegisterValue {
                name: RegisterName::Dr7,
                status: 0,
                low: HexU64(0x401),
                high: HexU64(0),
            },
        ];
        let written = vec![RegisterValue {
            name: RegisterName::Dr7,
            status: 0,
            low: HexU64(0x400),
            high: HexU64(0),
        }];
        let lines = vec![
            response(
                1,
                EPOCH_RUNNING,
                ReplyValue::Capabilities {
                    value: capabilities(),
                },
            ),
            response(2, "arming-0000000000000001", ReplyValue::ArmBegun),
            response(
                3,
                "arming-0000000000000001",
                ReplyValue::Registers {
                    values: read.clone(),
                },
            ),
            response(
                4,
                "arming-0000000000000001",
                ReplyValue::RegistersWritten {
                    values: written.clone(),
                },
            ),
            response(5, "running-0000000000000002", ReplyValue::ArmFinished),
            response(
                6,
                EPOCH_STOPPED,
                ReplyValue::StopPublished {
                    event: event.clone(),
                },
            ),
            response(
                7,
                EPOCH_STOPPED,
                ReplyValue::HeldEvent {
                    event: event.clone(),
                },
            ),
            response(
                8,
                EPOCH_STOPPED,
                ReplyValue::Registers {
                    values: read.clone(),
                },
            ),
            response(
                9,
                EPOCH_STOPPED,
                ReplyValue::RegistersWritten {
                    values: written.clone(),
                },
            ),
            response(10, EPOCH_RESUMED, ReplyValue::Released),
        ];
        let mut session = scripted(&lines);
        assert_eq!(session.capabilities().unwrap(), capabilities());
        session.begin_arm().unwrap();
        assert_eq!(
            session
                .read_registers(vec![RegisterName::Rip, RegisterName::Dr7])
                .unwrap(),
            read
        );
        assert_eq!(
            session
                .write_registers(vec![RegisterWrite {
                    name: RegisterName::Dr7,
                    expected: HexU64(0x401),
                    value: HexU64(0x400),
                }])
                .unwrap(),
            written
        );
        session.finish_arm().unwrap();
        session.publish_stop(event.clone()).unwrap();
        assert_eq!(session.epoch().0, EPOCH_STOPPED);
        assert_eq!(session.held_event().unwrap(), event);
        assert_eq!(
            session
                .read_registers(vec![RegisterName::Rip, RegisterName::Dr7])
                .unwrap(),
            read
        );
        assert_eq!(
            session
                .write_registers(vec![RegisterWrite {
                    name: RegisterName::Dr7,
                    expected: HexU64(0x401),
                    value: HexU64(0x400),
                }])
                .unwrap(),
            written
        );
        session.release().unwrap();
        assert_eq!(session.epoch().0, EPOCH_RESUMED);

        let requests = String::from_utf8(session.writer).unwrap();
        let parsed: Vec<Request> = requests
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(parsed.len(), 10);
        assert!(parsed.iter().all(|request| request.target == target()));
        assert_eq!(parsed[0].epoch.0, EPOCH_RUNNING);
        assert_eq!(parsed[1].epoch.0, EPOCH_RUNNING);
        assert!(
            parsed[2..=4]
                .iter()
                .all(|request| request.epoch.0 == "arming-0000000000000001")
        );
        assert_eq!(parsed[5].epoch.0, "running-0000000000000002");
        assert!(
            parsed[6..]
                .iter()
                .take(3)
                .all(|request| request.epoch.0 == EPOCH_STOPPED)
        );
        assert_eq!(parsed[9].epoch.0, EPOCH_STOPPED);
    }

    #[test]
    fn writes_are_refused_locally_while_running() {
        let mut session = scripted(&[response(
            1,
            EPOCH_RUNNING,
            ReplyValue::Capabilities {
                value: capabilities(),
            },
        )]);
        session.capabilities().unwrap();
        let error = session
            .write_registers(vec![RegisterWrite {
                name: RegisterName::Dr7,
                expected: HexU64(0x400),
                value: HexU64(0x401),
            }])
            .unwrap_err();
        assert!(format!("{error}").contains("running"));
        assert_eq!(
            String::from_utf8(session.writer).unwrap().lines().count(),
            1
        );
    }

    #[test]
    fn a_stale_epoch_reply_poisoned_the_stream_before_state_can_change() {
        let lines = vec![
            response(
                1,
                EPOCH_RUNNING,
                ReplyValue::Capabilities {
                    value: capabilities(),
                },
            ),
            response(2, EPOCH_RUNNING, ReplyValue::ArmBegun),
        ];
        let mut session = scripted(&lines);
        session.capabilities().unwrap();
        let error = session.begin_arm().unwrap_err();
        assert!(format!("{error}").contains("reused an epoch"));
        let error = session.capabilities().unwrap_err();
        assert!(format!("{error}").contains("desynchronised"));
    }

    #[test]
    fn a_non_adjacent_reused_epoch_is_refused_before_it_can_become_current_again() {
        let lines = vec![
            response(
                1,
                EPOCH_RUNNING,
                ReplyValue::Capabilities {
                    value: capabilities(),
                },
            ),
            response(2, EPOCH_STOPPED, ReplyValue::ArmBegun),
            response(3, EPOCH_RESUMED, ReplyValue::ArmFinished),
            response(4, EPOCH_STOPPED, ReplyValue::ArmBegun),
        ];
        let mut session = scripted(&lines);
        session.capabilities().unwrap();
        session.begin_arm().unwrap();
        session.finish_arm().unwrap();

        let error = session.begin_arm().unwrap_err();

        assert!(format!("{error}").contains("reused an epoch"));
        assert_eq!(session.epoch().0, EPOCH_RESUMED);
        assert!(
            session
                .capabilities()
                .unwrap_err()
                .to_string()
                .contains("desynchronised")
        );
    }

    #[test]
    fn a_structured_refusal_keeps_the_stream_aligned_and_its_code_typed() {
        let lines = vec![
            response(
                1,
                EPOCH_RUNNING,
                ReplyValue::Capabilities {
                    value: capabilities(),
                },
            ),
            refusal(2, ErrorCode::StaleEpoch, "the event was already released"),
            response(
                3,
                EPOCH_RUNNING,
                ReplyValue::Capabilities {
                    value: capabilities(),
                },
            ),
        ];
        let mut session = scripted(&lines);
        session.capabilities().unwrap();
        let error = session.capabilities().unwrap_err();
        let refusal = error.downcast_ref::<ProviderRefusal>().unwrap();
        assert_eq!(refusal.code, ErrorCode::StaleEpoch);
        assert_eq!(refusal.detail, "the event was already released");
        assert_eq!(session.capabilities().unwrap(), capabilities());
    }

    #[test]
    fn addresses_are_fixed_width_hex_strings_on_the_wire() {
        let encoded = serde_json::to_string(&HexU64(0xffff_f807_304b_512b)).unwrap();
        assert_eq!(encoded, "\"0xfffff807304b512b\"");
        assert!(serde_json::from_str::<HexU64>("18446744073709551615").is_err());
        assert!(serde_json::from_str::<HexU64>("\"0x1\"").is_err());
    }

    #[test]
    fn identity_rejects_a_wrong_vtl_or_unaligned_cr3() {
        let mut identity = target();
        identity.vtl = 0;
        assert!(format!("{}", identity.validate().unwrap_err()).contains("VTL1"));
        identity = target();
        identity.expected_cr3 = HexU64(0x120_1001);
        assert!(format!("{}", identity.validate().unwrap_err()).contains("page-aligned"));
    }

    #[test]
    fn a_valid_hello_for_the_wrong_vm_is_refused_before_any_request_is_sent() {
        let hello = serde_json::to_string(&Hello {
            protocol: PROTOCOL_VERSION,
            target: target(),
            epoch: StopEpoch::new(EPOCH_RUNNING).unwrap(),
        })
        .unwrap();
        let mut expected = target();
        expected.vm_id = "51749a1f-f939-44f5-b251-1251ef5b64a3".into();
        let error = ControlSession::open(
            Cursor::new(format!("{READY_LINE}\n{hello}\n").into_bytes()),
            Vec::new(),
            expected,
        )
        .err()
        .unwrap();
        assert!(format!("{error}").contains("requested by the operator"));
    }

    #[test]
    fn the_raw_debug_exception_schema_requires_protocol_two() {
        let old_ready = "windbg-mcp-sk-control/1";
        let error = ControlSession::open(
            Cursor::new(format!("{old_ready}\n").into_bytes()),
            Vec::new(),
            target(),
        )
        .err()
        .unwrap();

        assert_ne!(old_ready, READY_LINE);
        assert!(format!("{error:#}").contains(READY_LINE));
    }

    #[test]
    fn a_provider_which_stays_alive_but_sends_no_reply_is_bounded() {
        let (_writer, lines) = mpsc::sync_channel(1);
        let mut reader = TimedChildReader::from_receiver(lines, Duration::from_millis(1));
        let error = read_line(&mut reader).unwrap_err();
        assert!(format!("{error:#}").contains("no complete line"));
    }

    #[test]
    fn a_provider_reader_which_dies_is_an_eof_not_an_unbounded_wait() {
        let (writer, lines) = mpsc::sync_channel(1);
        drop(writer);
        let mut reader = TimedChildReader::from_receiver(lines, Duration::from_secs(1));
        let error = read_line(&mut reader).unwrap_err();
        assert!(format!("{error:#}").contains("reader stopped"));
    }

    #[test]
    fn an_outer_deadline_caps_the_provider_reply_wait() {
        let (_writer, lines) = mpsc::sync_channel(1);
        let mut reader = TimedChildReader::from_receiver(lines, Duration::from_secs(1));
        reader.set_outer_deadline(Some(Instant::now()));

        let error = read_line(&mut reader).unwrap_err();
        assert!(format!("{error:#}").contains("outer deadline"));
    }
}
