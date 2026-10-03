//! Epoch-bound state machine for one live Secure Kernel execution-control session.
//!
//! The control provider owns guarded VTL1 register access. A build-specific adapter in the engine
//! worker owns the matching `vmwp` debugger attachment, handler, and native event completion. This
//! module joins those two owners without putting either one in the MCP supervisor. It deliberately
//! knows no private VID layout and constructs no [`dbgscope::DebugEngine`].
//!
//! A provider transition to running necessarily happens before native dispatcher completion: once
//! `vmwp` completes the held event, the next vector-1 event may arrive immediately. The outer
//! [`LivePhase::Releasing`] state covers that gap. Any failure in it is terminal and runs the same
//! bounded recovery path as an unexpected debugger stop.

#![allow(
    dead_code,
    reason = "the K4.2 state machine is consumed by the build-specific worker adapter in K4.3"
)]

use anyhow::{Context, Result, anyhow, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::skcontrol::{
    Capabilities, ControlProcess, ControlSession, HeldEvent, HexU64, RegisterName, RegisterValue,
    RegisterWrite, StopEpoch, StopReason, TargetIdentity,
};

const TF: u64 = 1 << 8;
const RF: u64 = 1 << 16;
const DR6_CAUSE_MASK: u64 = 0xe00f;
const DR7_ENABLE_MASK: u64 = 0xff;
const DR7_SLOT0_KIND_MASK: u64 = 0xf << 16;
const MAX_INSTRUCTION_BYTES: usize = 15;
const MAX_STEP_DESTINATIONS: usize = 4;
const PROFILE_SCHEMA: &str = "windbg-mcp.sk-live-dispatcher-profile.v1";
const MAX_PROFILE_BYTES: u64 = 64 * 1024;
const MAX_SCRATCH_BYTES: u32 = 64 * 1024;

const SNAPSHOT_REGISTERS: [RegisterName; 12] = [
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

const WRITTEN_REGISTERS: [RegisterName; 9] = [
    RegisterName::Rip,
    RegisterName::Rsp,
    RegisterName::Rflags,
    RegisterName::Dr0,
    RegisterName::Dr1,
    RegisterName::Dr2,
    RegisterName::Dr3,
    RegisterName::Dr6,
    RegisterName::Dr7,
];

/// The provider operations the state machine uses. Its production implementation is the versioned
/// JSON-line [`ControlSession`]; tests use an in-memory provider with the same transition rules.
pub(crate) trait ControlProvider {
    fn target(&self) -> &TargetIdentity;
    fn epoch(&self) -> &StopEpoch;
    fn capabilities(&mut self) -> Result<Capabilities>;
    fn begin_arm(&mut self) -> Result<()>;
    fn finish_arm(&mut self) -> Result<()>;
    fn publish_stop(&mut self, event: HeldEvent) -> Result<()>;
    fn held_event(&mut self) -> Result<HeldEvent>;
    fn read_registers(&mut self, registers: Vec<RegisterName>) -> Result<Vec<RegisterValue>>;
    fn write_registers(&mut self, writes: Vec<RegisterWrite>) -> Result<Vec<RegisterValue>>;
    fn release(&mut self) -> Result<()>;
}

impl<R: std::io::BufRead, W: std::io::Write> ControlProvider for ControlSession<R, W> {
    fn target(&self) -> &TargetIdentity {
        ControlSession::target(self)
    }

    fn epoch(&self) -> &StopEpoch {
        ControlSession::epoch(self)
    }

    fn capabilities(&mut self) -> Result<Capabilities> {
        ControlSession::capabilities(self)
    }

    fn begin_arm(&mut self) -> Result<()> {
        ControlSession::begin_arm(self)
    }

    fn finish_arm(&mut self) -> Result<()> {
        ControlSession::finish_arm(self)
    }

    fn publish_stop(&mut self, event: HeldEvent) -> Result<()> {
        ControlSession::publish_stop(self, event)
    }

    fn held_event(&mut self) -> Result<HeldEvent> {
        ControlSession::held_event(self)
    }

    fn read_registers(&mut self, registers: Vec<RegisterName>) -> Result<Vec<RegisterValue>> {
        ControlSession::read_registers(self, registers)
    }

    fn write_registers(&mut self, writes: Vec<RegisterWrite>) -> Result<Vec<RegisterValue>> {
        ControlSession::write_registers(self, writes)
    }

    fn release(&mut self) -> Result<()> {
        ControlSession::release(self)
    }
}

impl ControlProvider for ControlProcess {
    fn target(&self) -> &TargetIdentity {
        ControlProcess::target(self)
    }

    fn epoch(&self) -> &StopEpoch {
        ControlProcess::epoch(self)
    }

    fn capabilities(&mut self) -> Result<Capabilities> {
        ControlProcess::capabilities(self)
    }

    fn begin_arm(&mut self) -> Result<()> {
        ControlProcess::begin_arm(self)
    }

    fn finish_arm(&mut self) -> Result<()> {
        ControlProcess::finish_arm(self)
    }

    fn publish_stop(&mut self, event: HeldEvent) -> Result<()> {
        ControlProcess::publish_stop(self, event)
    }

    fn held_event(&mut self) -> Result<HeldEvent> {
        ControlProcess::held_event(self)
    }

    fn read_registers(&mut self, registers: Vec<RegisterName>) -> Result<Vec<RegisterValue>> {
        ControlProcess::read_registers(self, registers)
    }

    fn write_registers(&mut self, writes: Vec<RegisterWrite>) -> Result<Vec<RegisterValue>> {
        ControlProcess::write_registers(self, writes)
    }

    fn release(&mut self) -> Result<()> {
        ControlProcess::release(self)
    }
}

/// What the worker's build-specific debugger adapter observed while `vmwp` is stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservedStop {
    pub(crate) event: HeldEvent,
    /// A second read of the exact instruction selected when the breakpoint was armed.
    pub(crate) instruction: InstructionGuard,
}

/// The narrow boundary around the one-thread DbgEng owner.
///
/// Every method is called on the engine thread. Implementations must bound their own waits. A
/// failing `begin_arm`, `finish_arm`, or `release_event` must leave the debuggee stopped, because
/// recovery decides explicitly whether it is safe to resume. `recover(false, ..)` must leave the VM
/// deliberately paused; it may remove only resources whose ownership it can still prove.
pub(crate) trait EventDispatcher {
    /// Pause the target and return the exact native callback context owned by this adapter.
    fn begin_arm(
        &mut self,
        target: &TargetIdentity,
        instruction: &InstructionGuard,
    ) -> Result<HexU64>;
    fn finish_arm(&mut self) -> Result<()>;
    /// Re-read a proposed current instruction while the owned event remains held.
    fn verify_instruction(&mut self, instruction: &InstructionGuard) -> Result<()>;
    fn wait_for_stop(
        &mut self,
        target: &TargetIdentity,
        instruction: &InstructionGuard,
    ) -> Result<ObservedStop>;
    fn release_event(&mut self, event: &HeldEvent, mode: ReleaseMode) -> Result<()>;
    fn recover(&mut self, safe_to_resume: bool, event: Option<&HeldEvent>) -> Result<()>;
    fn teardown(&mut self) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReleaseMode {
    /// Arm the dispatcher stop first, then let DbgEng begin pumping only when `wait_for_stop` runs.
    ArmNextStop,
    /// Complete the event and detach it as handled so `vmwp` and the guest really resume.
    Resume,
}

/// Original bytes at one build-specific vmwp stop site. The adapter verifies them after every
/// breakpoint removal, so an RVA from another build cannot silently become executable again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispatcherSite {
    pub(crate) rva: HexU64,
    pub(crate) original: Vec<u8>,
}

/// Offsets within the operator-owned callback scratch allocation and the private dispatcher
/// records. Values live in the local profile rather than this repository's source because they are
/// build-specific private ABI, not a Windows contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispatcherLayout {
    pub(crate) returned_context: u32,
    pub(crate) handler_descriptor: u32,
    pub(crate) callback_descriptor: u32,
    pub(crate) callback_mirror: u32,
    pub(crate) event_context: u32,
    /// VP index in the exact-build native vector-event record.
    pub(crate) event_vp: u32,
    pub(crate) exchange_advance: u32,
    pub(crate) callback_pointer: u32,
    pub(crate) callback_flags: u32,
    pub(crate) register_stack_handler: u32,
    pub(crate) register_stack_context: u32,
}

/// Exact-build input for the DbgEng dispatcher adapter. It contains only numbers and byte guards;
/// no field is debugger command text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispatcherProfile {
    pub(crate) schema: String,
    pub(crate) vmwp_image: std::path::PathBuf,
    pub(crate) vmwp_sha256: String,
    pub(crate) vmwp_size_of_image: u32,
    pub(crate) scratch_base: HexU64,
    pub(crate) scratch_size: u32,
    pub(crate) registration_tag: HexU64,
    pub(crate) register_handler_rva: HexU64,
    pub(crate) unregister_handler_rva: HexU64,
    pub(crate) callback_stub_rva: HexU64,
    pub(crate) callback_resume_rva: HexU64,
    pub(crate) event_held: DispatcherSite,
    pub(crate) callback_entry: DispatcherSite,
    pub(crate) handle_return: DispatcherSite,
    pub(crate) native_return: DispatcherSite,
    pub(crate) deferred_cleanup: DispatcherSite,
    pub(crate) layout: DispatcherLayout,
}

impl DispatcherProfile {
    pub(crate) fn load(path: &std::path::Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("opening dispatcher profile {}", path.display()))?;
        let length = file
            .metadata()
            .with_context(|| format!("reading dispatcher profile size {}", path.display()))?
            .len();
        if length == 0 || length > MAX_PROFILE_BYTES {
            bail!("dispatcher profile size must be in 1..={MAX_PROFILE_BYTES} bytes, got {length}");
        }
        let profile: Self = serde_json::from_reader(file)
            .with_context(|| format!("parsing dispatcher profile {}", path.display()))?;
        profile.validate()?;
        Ok(profile)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != PROFILE_SCHEMA {
            bail!(
                "dispatcher profile schema is {:?}, expected {PROFILE_SCHEMA:?}",
                self.schema
            );
        }
        if self.vmwp_sha256.len() != 64
            || !self
                .vmwp_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("vmwp_sha256 must contain exactly 64 hexadecimal digits");
        }
        if !self.vmwp_image.is_absolute()
            || !self
                .vmwp_image
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("vmwp.exe"))
        {
            bail!("vmwp_image must be an absolute path ending in vmwp.exe");
        }
        if self.vmwp_size_of_image == 0 {
            bail!("vmwp_size_of_image must be nonzero");
        }
        if self.scratch_base.0 == 0 || self.scratch_base.0 & 0xfff != 0 {
            bail!("scratch_base must be a nonzero page-aligned address");
        }
        if self.scratch_size == 0
            || self.scratch_size > MAX_SCRATCH_BYTES
            || !self.scratch_size.is_multiple_of(0x1000)
        {
            bail!("scratch_size must be a page multiple in 0x1000..={MAX_SCRATCH_BYTES:#x}");
        }
        for (name, rva) in [
            ("register_handler_rva", self.register_handler_rva.0),
            ("unregister_handler_rva", self.unregister_handler_rva.0),
            ("callback_stub_rva", self.callback_stub_rva.0),
            ("callback_resume_rva", self.callback_resume_rva.0),
        ] {
            self.validate_rva(name, rva, 1)?;
        }
        let sites = [
            ("event_held", &self.event_held),
            ("callback_entry", &self.callback_entry),
            ("handle_return", &self.handle_return),
            ("native_return", &self.native_return),
            ("deferred_cleanup", &self.deferred_cleanup),
        ];
        for (name, site) in sites {
            if site.original.is_empty() || site.original.len() > MAX_INSTRUCTION_BYTES {
                bail!("{name}.original must contain 1..={MAX_INSTRUCTION_BYTES} bytes");
            }
            self.validate_rva(name, site.rva.0, site.original.len() as u64)?;
        }
        for (index, (_, left)) in sites.iter().enumerate() {
            for (_, right) in &sites[index + 1..] {
                let left_end = left.rva.0 + left.original.len() as u64;
                let right_end = right.rva.0 + right.original.len() as u64;
                if left.rva.0 < right_end && right.rva.0 < left_end {
                    bail!("dispatcher breakpoint byte guards overlap");
                }
            }
        }
        for (name, offset) in [
            ("returned_context", self.layout.returned_context),
            ("handler_descriptor", self.layout.handler_descriptor),
            ("callback_descriptor", self.layout.callback_descriptor),
            ("callback_mirror", self.layout.callback_mirror),
        ] {
            self.validate_scratch(name, offset, 8)?;
        }
        for (name, offset) in [
            ("event_context", self.layout.event_context),
            ("exchange_advance", self.layout.exchange_advance),
            ("callback_pointer", self.layout.callback_pointer),
            ("callback_flags", self.layout.callback_flags),
        ] {
            if offset > 0x1000 {
                bail!("dispatcher field offset {name} exceeds the bounded record window");
            }
        }
        if self.layout.event_vp > 0x1000 || !self.layout.event_vp.is_multiple_of(4) {
            bail!(
                "dispatcher field offset event_vp is unaligned or exceeds the bounded record window"
            );
        }
        for (name, offset) in [
            ("register_stack_handler", self.layout.register_stack_handler),
            ("register_stack_context", self.layout.register_stack_context),
        ] {
            if !(0x20..=0x100).contains(&offset) || !offset.is_multiple_of(8) {
                bail!("{name} must be an aligned x64 stack-argument offset in 0x20..=0x100");
            }
        }
        let callback_mirror = self
            .layout
            .callback_descriptor
            .checked_add(self.layout.callback_mirror)
            .context("callback mirror offset overflowed")?;
        self.validate_scratch("callback_descriptor+callback_mirror", callback_mirror, 8)?;
        Ok(())
    }

    fn validate_rva(&self, name: &str, rva: u64, size: u64) -> Result<()> {
        let end = rva
            .checked_add(size)
            .with_context(|| format!("{name} range overflowed"))?;
        if rva == 0 || end > u64::from(self.vmwp_size_of_image) {
            bail!(
                "{name} range {rva:#x}..{end:#x} is outside vmwp SizeOfImage {:#x}",
                self.vmwp_size_of_image
            );
        }
        Ok(())
    }

    fn validate_scratch(&self, name: &str, offset: u32, size: u32) -> Result<()> {
        let end = offset
            .checked_add(size)
            .with_context(|| format!("scratch field {name} overflowed"))?;
        if !offset.is_multiple_of(8) || end > self.scratch_size {
            bail!("scratch field {name} is misaligned or outside the allocation");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LivePhase {
    Running,
    Arming,
    Stopped,
    Releasing,
    Faulted,
    Closed,
}

/// Exact bytes for one instruction the controller may stop before or step over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstructionGuard {
    pub(crate) address: HexU64,
    pub(crate) bytes: Vec<u8>,
}

/// How the first hardware breakpoint is reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ArmMode {
    /// Redirect the saved RIP to the guarded instruction, then restore the complete baseline.
    #[default]
    Redirect,
    /// Leave RIP untouched and wait for guest control flow to reach the guarded instruction.
    Natural,
}

impl InstructionGuard {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.address.0 == 0 {
            bail!("the breakpoint address must be nonzero");
        }
        if self.bytes.is_empty() || self.bytes.len() > MAX_INSTRUCTION_BYTES {
            bail!("the guarded instruction must contain 1..={MAX_INSTRUCTION_BYTES} bytes");
        }
        self.address
            .0
            .checked_add(self.bytes.len() as u64)
            .context("the guarded instruction crosses the address-space limit")?;
        Ok(())
    }

    fn successor(&self) -> u64 {
        self.address.0 + self.bytes.len() as u64
    }
}

/// Exact current instruction and the bounded RIP set accepted after one trap-flag step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StepGuard {
    pub(crate) instruction: Option<InstructionGuard>,
    pub(crate) expected_rips: Vec<HexU64>,
}

impl StepGuard {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(instruction) = &self.instruction {
            instruction.validate()?;
        }
        if self.expected_rips.len() > MAX_STEP_DESTINATIONS {
            bail!("a step may name at most {MAX_STEP_DESTINATIONS} expected destination addresses");
        }
        for (index, address) in self.expected_rips.iter().enumerate() {
            if address.0 == 0 {
                bail!("an expected step destination must be nonzero");
            }
            if self.expected_rips[..index].contains(address) {
                bail!("expected step destinations must be distinct");
            }
        }
        Ok(())
    }

    fn resolve(self, stop: &StopRecord) -> Result<(InstructionGuard, Vec<HexU64>)> {
        self.validate()?;
        let rip = stop.registers.low(RegisterName::Rip)?;
        let instruction = match self.instruction {
            Some(instruction) => instruction,
            None if stop.instruction.address.0 == rip => stop.instruction.clone(),
            None => {
                bail!(
                    "a repeated step requires the exact instruction address and bytes at the current RIP"
                )
            }
        };
        if instruction.address.0 != rip {
            bail!(
                "the step instruction address {:#x} does not match the stopped RIP {rip:#x}",
                instruction.address.0
            );
        }

        let expected_rips = if self.expected_rips.is_empty() {
            vec![HexU64(instruction.successor())]
        } else {
            self.expected_rips
        };
        Ok((instruction, expected_rips))
    }
}

/// Complete register evidence retained for one stop. Status and high halves remain visible instead
/// of being discarded after validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisterSnapshot {
    pub(crate) values: Vec<RegisterValue>,
}

impl RegisterSnapshot {
    fn from_values(values: Vec<RegisterValue>, target: &TargetIdentity) -> Result<Self> {
        if values.len() != SNAPSHOT_REGISTERS.len() {
            bail!(
                "register snapshot returned {} values, expected {}",
                values.len(),
                SNAPSHOT_REGISTERS.len()
            );
        }
        for (wanted, value) in SNAPSHOT_REGISTERS.iter().zip(&values) {
            if value.name != *wanted {
                bail!("register snapshot returned values in the wrong order");
            }
            if value.status != 0 {
                bail!(
                    "provider returned status {:#x} for {:?}",
                    value.status,
                    value.name
                );
            }
            if value.name != RegisterName::Cs && value.high.0 != 0 {
                bail!("provider returned a nonzero high half for {:?}", value.name);
            }
        }
        let snapshot = Self { values };
        if snapshot.low(RegisterName::Cr3)? != target.expected_cr3.0 {
            bail!("the stopped CR3 does not match the bound target identity");
        }
        Ok(snapshot)
    }

    fn value(&self, name: RegisterName) -> Result<&RegisterValue> {
        self.values
            .iter()
            .find(|value| value.name == name)
            .with_context(|| format!("register snapshot omitted {name:?}"))
    }

    fn low(&self, name: RegisterName) -> Result<u64> {
        Ok(self.value(name)?.low.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct StopRecord {
    pub(crate) epoch: StopEpoch,
    pub(crate) target: TargetIdentity,
    pub(crate) event: HeldEvent,
    pub(crate) registers: RegisterSnapshot,
    pub(crate) instruction: InstructionGuard,
    /// RIP values accepted for this stop. Hardware stops name the breakpoint address; single-step
    /// stops retain the caller's bounded destination set.
    pub(crate) expected_rips: Vec<HexU64>,
    pub(crate) arm_mode: ArmMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct FaultRecord {
    pub(crate) cause: String,
    pub(crate) recovery_errors: Vec<String>,
    pub(crate) target_left_paused: bool,
}

/// The running-side result of arming, stepping or continuing. `epoch` names this exact transition;
/// the next stop returns a different epoch which is the only one a mutating stopped operation
/// accepts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiveTransition {
    pub(crate) phase: LivePhase,
    pub(crate) epoch: StopEpoch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderPhase {
    Running,
    Arming,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExpectedStop {
    Hardware,
    SingleStep { expected_rips: Vec<HexU64> },
}

#[derive(Clone, Debug)]
enum State {
    Running,
    Arming,
    Stopped(StopRecord),
    Releasing,
    Faulted(FaultRecord),
    Closed,
}

/// One-selected-VP, one-breakpoint coordinator. The dispatcher pauses the whole VM while this
/// state changes. It is synchronous because its owner is the worker's single engine thread.
pub(crate) struct LiveControl<P> {
    provider: P,
    target: TargetIdentity,
    provider_phase: ProviderPhase,
    state: State,
    baseline: Option<RegisterSnapshot>,
    instruction: Option<InstructionGuard>,
    arm_mode: Option<ArmMode>,
    dispatcher_context: Option<HexU64>,
    expected_stop: Option<ExpectedStop>,
}

impl<P: ControlProvider> LiveControl<P> {
    pub(crate) fn open(mut provider: P) -> Result<Self> {
        provider.target().validate()?;
        let capabilities = provider.capabilities()?;
        require_registers(&capabilities, &SNAPSHOT_REGISTERS, false)?;
        require_registers(&capabilities, &WRITTEN_REGISTERS, true)?;
        let target = provider.target().clone();
        Ok(Self {
            provider,
            target,
            provider_phase: ProviderPhase::Running,
            state: State::Running,
            baseline: None,
            instruction: None,
            arm_mode: None,
            dispatcher_context: None,
            expected_stop: None,
        })
    }

    pub(crate) fn phase(&self) -> LivePhase {
        match self.state {
            State::Running => LivePhase::Running,
            State::Arming => LivePhase::Arming,
            State::Stopped(_) => LivePhase::Stopped,
            State::Releasing => LivePhase::Releasing,
            State::Faulted(_) => LivePhase::Faulted,
            State::Closed => LivePhase::Closed,
        }
    }

    pub(crate) fn epoch(&self) -> &StopEpoch {
        self.provider.epoch()
    }

    pub(crate) fn fault(&self) -> Option<&FaultRecord> {
        match &self.state {
            State::Faulted(fault) => Some(fault),
            _ => None,
        }
    }

    pub(crate) fn stopped(&self) -> Option<&StopRecord> {
        match &self.state {
            State::Stopped(stop) => Some(stop),
            _ => None,
        }
    }

    /// Pause the dispatcher, save the original VTL1 state, and install DR0. Redirect mode moves
    /// RIP to the guarded instruction; natural mode leaves RIP untouched.
    pub(crate) fn arm(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        instruction: InstructionGuard,
        mode: ArmMode,
    ) -> Result<StopEpoch> {
        self.require_running_unarmed()?;
        instruction.validate()?;
        self.state = State::Arming;
        // Recovery must know whether RIP is controller-owned even if a later arm write fails.
        self.arm_mode = Some(mode);
        if let Err(error) = self.arm_inner(dispatcher, &instruction, mode) {
            return Err(self.enter_fault(dispatcher, error, None));
        }
        self.instruction = Some(instruction);
        self.expected_stop = Some(ExpectedStop::Hardware);
        self.state = State::Running;
        Ok(self.provider.epoch().clone())
    }

    fn arm_inner(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        instruction: &InstructionGuard,
        mode: ArmMode,
    ) -> Result<()> {
        self.begin_dispatcher_arm(dispatcher, instruction)?;
        self.provider.begin_arm()?;
        self.provider_phase = ProviderPhase::Arming;
        let baseline = self.read_snapshot()?;
        if baseline.low(RegisterName::Dr7)? & DR7_ENABLE_MASK != 0 {
            bail!("the guest already has an enabled hardware breakpoint");
        }
        self.baseline = Some(baseline.clone());

        let original_dr7 = baseline.low(RegisterName::Dr7)?;
        let original_rflags = baseline.low(RegisterName::Rflags)?;
        if mode == ArmMode::Natural && original_rflags & (TF | RF) != 0 {
            bail!("natural-flow arming requires TF and RF to be clear in the saved state");
        }
        let armed_dr7 = (original_dr7 & !(DR7_ENABLE_MASK | DR7_SLOT0_KIND_MASK)) | 1;
        self.write_one(
            RegisterName::Dr7,
            original_dr7,
            original_dr7 & !DR7_ENABLE_MASK,
        )?;
        self.write_one(
            RegisterName::Dr0,
            baseline.low(RegisterName::Dr0)?,
            instruction.address.0,
        )?;
        self.write_one(
            RegisterName::Dr6,
            baseline.low(RegisterName::Dr6)?,
            baseline.low(RegisterName::Dr6)? & !DR6_CAUSE_MASK,
        )?;
        if mode == ArmMode::Redirect {
            self.write_one(
                RegisterName::Rip,
                baseline.low(RegisterName::Rip)?,
                instruction.address.0,
            )?;
            self.write_one(
                RegisterName::Rflags,
                original_rflags,
                original_rflags & !(TF | RF),
            )?;
        }
        self.write_one(
            RegisterName::Dr7,
            original_dr7 & !DR7_ENABLE_MASK,
            armed_dr7,
        )?;

        self.provider.finish_arm()?;
        self.provider_phase = ProviderPhase::Running;
        dispatcher.finish_arm()?;
        Ok(())
    }

    /// Wait for and validate the next owned vector-1 event. Two complete register reads must agree
    /// before the stop becomes visible to a caller.
    pub(crate) fn wait_for_stop(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
    ) -> Result<StopRecord> {
        if !matches!(self.state, State::Running) || self.expected_stop.is_none() {
            bail!("wait_for_stop requires an armed running session");
        }
        let instruction = self
            .instruction
            .clone()
            .context("the armed session has no instruction guard")?;
        let expected_stop = self
            .expected_stop
            .clone()
            .context("the armed session has no expected stop")?;
        let observed = match dispatcher.wait_for_stop(&self.target, &instruction) {
            Ok(observed) => observed,
            Err(error) => return Err(self.enter_fault(dispatcher, error, None)),
        };
        if let Err(error) = self.validate_observation(&observed, &expected_stop) {
            return Err(self.enter_fault(dispatcher, error, Some(observed.event)));
        }
        if let Err(error) = self.provider.publish_stop(observed.event.clone()) {
            return Err(self.enter_fault(dispatcher, error, Some(observed.event)));
        }
        self.provider_phase = ProviderPhase::Stopped;
        let result = (|| {
            let echoed = self.provider.held_event()?;
            if echoed != observed.event {
                bail!("provider changed the dispatcher event after publication");
            }
            let first = self.read_snapshot()?;
            let second = self.read_snapshot()?;
            if first != second {
                bail!("VTL1 registers changed while the dispatcher event was held");
            }
            self.validate_stop_registers(&observed.event, &first, &instruction, &expected_stop)?;
            let expected_rips = match &expected_stop {
                ExpectedStop::Hardware => vec![instruction.address],
                ExpectedStop::SingleStep { expected_rips } => expected_rips.clone(),
            };
            Ok(StopRecord {
                epoch: self.provider.epoch().clone(),
                target: self.target.clone(),
                event: observed.event.clone(),
                registers: first,
                instruction,
                expected_rips,
                arm_mode: self.arm_mode.context("the armed session has no arm mode")?,
            })
        })();
        match result {
            Ok(stop) => {
                self.expected_stop = None;
                self.state = State::Stopped(stop.clone());
                Ok(stop)
            }
            Err(error) => Err(self.enter_fault(dispatcher, error, Some(observed.event))),
        }
    }

    /// Consume an owned stop and arm one architectural trap-flag step. The first step can reuse
    /// the hardware-breakpoint guard. Every later step must name and prove the instruction at the
    /// current RIP. A caller may admit a bounded destination set for a branch.
    pub(crate) fn step(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        epoch: &StopEpoch,
        guard: StepGuard,
    ) -> Result<StopEpoch> {
        let stop = self.require_stop_epoch(epoch)?.clone();
        let (instruction, expected_rips) = guard.resolve(&stop)?;
        // This read has no target-side effect. A bad caller guard leaves the current stop and
        // epoch intact so it can be corrected or continued safely.
        dispatcher.verify_instruction(&instruction)?;
        self.state = State::Releasing;
        let result = (|| {
            let baseline = self
                .baseline
                .clone()
                .context("the stopped session has no baseline")?;
            let dr6 = stop.registers.low(RegisterName::Dr6)?;
            let rflags = stop.registers.low(RegisterName::Rflags)?;
            self.write_one(
                RegisterName::Dr7,
                stop.registers.low(RegisterName::Dr7)?,
                baseline.low(RegisterName::Dr7)? & !DR7_ENABLE_MASK,
            )?;
            self.write_one(
                RegisterName::Dr0,
                stop.registers.low(RegisterName::Dr0)?,
                baseline.low(RegisterName::Dr0)?,
            )?;
            self.write_one(RegisterName::Dr6, dr6, dr6 & !DR6_CAUSE_MASK)?;
            self.write_one(RegisterName::Rflags, rflags, (rflags | TF) & !RF)?;
            self.provider.release()?;
            self.provider_phase = ProviderPhase::Running;
            dispatcher.release_event(&stop.event, ReleaseMode::ArmNextStop)?;
            Ok(())
        })();
        if let Err(error) = result {
            return Err(self.enter_fault(dispatcher, error, Some(stop.event)));
        }
        self.instruction = Some(instruction);
        self.expected_stop = Some(ExpectedStop::SingleStep { expected_rips });
        self.state = State::Running;
        Ok(self.provider.epoch().clone())
    }

    /// Restore the complete writable baseline and release the exact event once.
    pub(crate) fn continue_from(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        epoch: &StopEpoch,
    ) -> Result<StopEpoch> {
        let stop = self.require_stop_epoch(epoch)?.clone();
        self.state = State::Releasing;
        let result = (|| {
            self.restore_owned_state()?;
            self.provider.release()?;
            self.provider_phase = ProviderPhase::Running;
            dispatcher.release_event(&stop.event, ReleaseMode::Resume)?;
            Ok(())
        })();
        if let Err(error) = result {
            return Err(self.enter_fault(dispatcher, error, Some(stop.event)));
        }
        self.baseline = None;
        self.instruction = None;
        self.arm_mode = None;
        self.expected_stop = None;
        self.state = State::Running;
        Ok(self.provider.epoch().clone())
    }

    /// Restore or release anything this session still owns, then remove the handler and detach.
    pub(crate) fn close(&mut self, dispatcher: &mut impl EventDispatcher) -> Result<()> {
        match self.state.clone() {
            State::Closed => return Ok(()),
            State::Faulted(fault) => {
                let teardown = dispatcher.teardown();
                match teardown {
                    Ok(()) => bail!(
                        "the terminal live-control fault remains after teardown: {}",
                        fault.cause
                    ),
                    Err(error) => bail!(
                        "the terminal live-control fault remains and teardown failed: {}; {error:#}",
                        fault.cause
                    ),
                }
            }
            State::Stopped(stop) => {
                self.continue_from(dispatcher, &stop.epoch)?;
            }
            State::Running if self.baseline.is_some() => {
                self.state = State::Arming;
                let result = (|| {
                    let instruction = self
                        .instruction
                        .clone()
                        .context("the armed session has no instruction guard")?;
                    self.begin_dispatcher_arm(dispatcher, &instruction)?;
                    self.provider.begin_arm()?;
                    self.provider_phase = ProviderPhase::Arming;
                    self.restore_owned_state()?;
                    self.provider.finish_arm()?;
                    self.provider_phase = ProviderPhase::Running;
                    dispatcher.finish_arm()?;
                    Ok(())
                })();
                if let Err(error) = result {
                    return Err(self.enter_fault(dispatcher, error, None));
                }
                self.baseline = None;
                self.instruction = None;
                self.arm_mode = None;
                self.expected_stop = None;
                self.state = State::Running;
            }
            State::Running => {}
            State::Arming | State::Releasing => {
                return Err(self.enter_fault(
                    dispatcher,
                    anyhow!("close observed an incomplete control transition"),
                    None,
                ));
            }
        }
        if let Err(error) = dispatcher.teardown() {
            return Err(self.enter_fault(dispatcher, error, None));
        }
        self.state = State::Closed;
        Ok(())
    }

    fn validate_observation(
        &self,
        observed: &ObservedStop,
        expected_stop: &ExpectedStop,
    ) -> Result<()> {
        observed.event.validate(&self.target)?;
        if Some(observed.event.dispatcher_context) != self.dispatcher_context {
            bail!("the dispatcher event context does not match the registered handler");
        }
        if observed.instruction != *self.instruction.as_ref().context("no instruction guard")? {
            bail!("the guarded instruction changed before the stop was accepted");
        }
        match (expected_stop, &observed.event.reason) {
            (ExpectedStop::Hardware, StopReason::HardwareBreakpoint { slot: 0 })
            | (ExpectedStop::SingleStep { .. }, StopReason::SingleStep) => Ok(()),
            _ => bail!("the dispatcher event reason did not match the armed operation"),
        }
    }

    fn validate_stop_registers(
        &self,
        event: &HeldEvent,
        registers: &RegisterSnapshot,
        instruction: &InstructionGuard,
        expected_stop: &ExpectedStop,
    ) -> Result<()> {
        if registers.low(RegisterName::Cs)? & 3 != u64::from(event.cpl) {
            bail!("the held event CPL does not match the provider's CS register");
        }
        match event.reason {
            StopReason::HardwareBreakpoint { slot: 0 } => {
                if registers.low(RegisterName::Rip)? != instruction.address.0
                    || registers.low(RegisterName::Dr0)? != instruction.address.0
                    || registers.low(RegisterName::Dr6)? & 1 == 0
                    || registers.low(RegisterName::Dr7)? & 1 == 0
                {
                    bail!("slot-0 stop register evidence does not match the armed breakpoint");
                }
            }
            StopReason::SingleStep => {
                let ExpectedStop::SingleStep { expected_rips } = expected_stop else {
                    bail!("single-step register evidence arrived for a different operation");
                };
                if !expected_rips.contains(&HexU64(registers.low(RegisterName::Rip)?))
                    || registers.low(RegisterName::Dr6)? & (1 << 14) == 0
                    || registers.low(RegisterName::Rflags)? & TF == 0
                    || registers.low(RegisterName::Rflags)? & RF != 0
                {
                    bail!(
                        "single-step register evidence does not carry the allowed RIP, DR6.BS, TF, and clear RF"
                    );
                }
            }
            StopReason::HardwareBreakpoint { slot } => {
                bail!("the first revision owns slot 0, not slot {slot}");
            }
        }
        Ok(())
    }

    fn read_snapshot(&mut self) -> Result<RegisterSnapshot> {
        RegisterSnapshot::from_values(
            self.provider.read_registers(SNAPSHOT_REGISTERS.to_vec())?,
            &self.target,
        )
    }

    fn begin_dispatcher_arm(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        instruction: &InstructionGuard,
    ) -> Result<()> {
        let context = dispatcher.begin_arm(&self.target, instruction)?;
        if context.0 == 0 {
            bail!("the debugger adapter returned a zero handler context");
        }
        if let Some(expected) = self.dispatcher_context
            && context != expected
        {
            bail!("the debugger adapter changed its registered handler context");
        }
        self.dispatcher_context = Some(context);
        Ok(())
    }

    fn write_one(&mut self, name: RegisterName, expected: u64, value: u64) -> Result<()> {
        let written = self.provider.write_registers(vec![RegisterWrite {
            name,
            expected: HexU64(expected),
            value: HexU64(value),
        }])?;
        let [written] = written.as_slice() else {
            bail!("provider returned the wrong number of guarded-write results");
        };
        if written.name != name || written.status != 0 || written.low.0 != value {
            bail!("provider did not verify the guarded write to {name:?}");
        }
        Ok(())
    }

    fn restore_owned_state(&mut self) -> Result<()> {
        match self.arm_mode.context("there is no saved arm mode")? {
            ArmMode::Redirect => self.restore_redirect_baseline(),
            ArmMode::Natural => self.restore_natural_control(),
        }
    }

    fn restore_redirect_baseline(&mut self) -> Result<()> {
        let baseline = self
            .baseline
            .clone()
            .context("there is no saved VTL1 baseline")?;
        let current = self.read_snapshot()?;
        for name in [
            RegisterName::Dr7,
            RegisterName::Rflags,
            RegisterName::Rip,
            RegisterName::Rsp,
            RegisterName::Dr0,
            RegisterName::Dr1,
            RegisterName::Dr2,
            RegisterName::Dr3,
            RegisterName::Dr6,
            RegisterName::Dr7,
        ] {
            let expected = if name == RegisterName::Dr7 {
                // The first write disables all slots; the last restores the exact original word.
                self.read_snapshot()?.low(name)?
            } else {
                current.low(name)?
            };
            let value = if name == RegisterName::Dr7 && expected != baseline.low(name)? {
                expected & !DR7_ENABLE_MASK
            } else {
                baseline.low(name)?
            };
            self.write_one(name, expected, value)?;
        }
        let restored = self.read_snapshot()?;
        if restored != baseline {
            bail!("restored VTL1 state does not match the saved baseline");
        }
        Ok(())
    }

    /// Natural-flow execution is real guest progress. Restore only state this controller owns;
    /// rewinding RIP, RSP, or ordinary flags would replay work the guest already performed.
    fn restore_natural_control(&mut self) -> Result<()> {
        let baseline = self
            .baseline
            .clone()
            .context("there is no saved VTL1 baseline")?;
        let mut current = self.read_snapshot()?;
        let current_dr7 = current.low(RegisterName::Dr7)?;
        self.write_one(
            RegisterName::Dr7,
            current_dr7,
            current_dr7 & !DR7_ENABLE_MASK,
        )?;
        current = self.read_snapshot()?;
        let current_flags = current.low(RegisterName::Rflags)?;
        let restored_flags =
            (current_flags & !(TF | RF)) | (baseline.low(RegisterName::Rflags)? & (TF | RF));
        self.write_one(RegisterName::Rflags, current_flags, restored_flags)?;
        for name in [
            RegisterName::Dr0,
            RegisterName::Dr1,
            RegisterName::Dr2,
            RegisterName::Dr3,
            RegisterName::Dr6,
        ] {
            let expected = self.read_snapshot()?.low(name)?;
            self.write_one(name, expected, baseline.low(name)?)?;
        }
        let disabled_dr7 = self.read_snapshot()?.low(RegisterName::Dr7)?;
        self.write_one(
            RegisterName::Dr7,
            disabled_dr7,
            baseline.low(RegisterName::Dr7)?,
        )?;

        let restored = self.read_snapshot()?;
        for name in [
            RegisterName::Dr0,
            RegisterName::Dr1,
            RegisterName::Dr2,
            RegisterName::Dr3,
            RegisterName::Dr6,
            RegisterName::Dr7,
        ] {
            if restored.low(name)? != baseline.low(name)? {
                bail!("restored natural-flow debug state does not match the saved baseline");
            }
        }
        if restored.low(RegisterName::Rflags)? & (TF | RF)
            != baseline.low(RegisterName::Rflags)? & (TF | RF)
        {
            bail!("restored natural-flow TF/RF state does not match the saved baseline");
        }
        Ok(())
    }

    fn require_running_unarmed(&self) -> Result<()> {
        if !matches!(self.state, State::Running) {
            bail!("arming requires running state");
        }
        if self.baseline.is_some() || self.instruction.is_some() || self.expected_stop.is_some() {
            bail!("the session already owns a breakpoint");
        }
        Ok(())
    }

    fn require_stop_epoch(&self, epoch: &StopEpoch) -> Result<&StopRecord> {
        let State::Stopped(stop) = &self.state else {
            bail!("operation requires a stopped session");
        };
        if &stop.epoch != epoch || self.provider.epoch() != epoch {
            bail!("the supplied stop epoch is stale");
        }
        Ok(stop)
    }

    fn enter_fault(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        cause: anyhow::Error,
        event: Option<HeldEvent>,
    ) -> anyhow::Error {
        let mut recovery_errors = Vec::new();
        let mut safe_to_resume = self.baseline.is_none();

        if self.baseline.is_some() {
            let entered_arm = match self.provider_phase {
                ProviderPhase::Running => match self.provider.begin_arm() {
                    Ok(()) => {
                        self.provider_phase = ProviderPhase::Arming;
                        true
                    }
                    Err(error) => {
                        recovery_errors.push(format!("begin recovery arm: {error:#}"));
                        false
                    }
                },
                ProviderPhase::Arming | ProviderPhase::Stopped => true,
            };
            if entered_arm {
                match self.restore_owned_state() {
                    Ok(()) => safe_to_resume = true,
                    Err(error) => {
                        safe_to_resume = false;
                        recovery_errors.push(format!("restore VTL1 baseline: {error:#}"));
                    }
                }
            }
        }

        if safe_to_resume {
            let transition = match self.provider_phase {
                ProviderPhase::Arming => self.provider.finish_arm(),
                ProviderPhase::Stopped => self.provider.release(),
                ProviderPhase::Running => Ok(()),
            };
            match transition {
                Ok(()) => self.provider_phase = ProviderPhase::Running,
                Err(error) => {
                    safe_to_resume = false;
                    recovery_errors.push(format!("return provider to running: {error:#}"));
                }
            }
        }

        let owned_event = event.as_ref().filter(|event| {
            event.validate(&self.target).is_ok()
                && Some(event.dispatcher_context) == self.dispatcher_context
        });
        let dispatcher_safe = safe_to_resume && (event.is_none() || owned_event.is_some());
        let dispatcher_recovered = if let Err(error) =
            dispatcher.recover(dispatcher_safe, owned_event.filter(|_| dispatcher_safe))
        {
            recovery_errors.push(format!("dispatcher recovery: {error:#}"));
            false
        } else {
            true
        };
        let fault = FaultRecord {
            cause: format!("{cause:#}"),
            recovery_errors,
            target_left_paused: !dispatcher_safe || !dispatcher_recovered,
        };
        self.state = State::Faulted(fault.clone());
        anyhow!(
            "live Secure Kernel control faulted: {}; recovery_errors={:?}; target_left_paused={}",
            fault.cause,
            fault.recovery_errors,
            fault.target_left_paused
        )
    }
}

fn require_registers(
    capabilities: &Capabilities,
    registers: &[RegisterName],
    writes: bool,
) -> Result<()> {
    let offered = if writes {
        &capabilities.writable_registers
    } else {
        &capabilities.readable_registers
    };
    if let Some(missing) = registers.iter().find(|name| !offered.contains(name)) {
        bail!("control provider does not support required register {missing:?}");
    }
    if usize::from(capabilities.max_registers_per_request) < SNAPSHOT_REGISTERS.len() {
        bail!("control provider's register request limit is too small for an atomic snapshot");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::skcontrol::Capability;

    const BASE_RIP: u64 = 0xffff_f803_60ab_0035;
    const TARGET_RIP: u64 = 0xffff_f803_660a_512b;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FakePhase {
        Running,
        Arming,
        Stopped,
    }

    struct FakeProvider {
        target: TargetIdentity,
        epoch: StopEpoch,
        serial: u64,
        phase: FakePhase,
        held: Option<HeldEvent>,
        registers: Vec<RegisterValue>,
        hardware_rip: u64,
        single_step_rips: VecDeque<u64>,
        unstable_once: bool,
        fail_reads_while_stopped: Option<&'static str>,
        wrong_cr3_while_stopped: bool,
    }

    impl FakeProvider {
        fn new() -> Self {
            Self {
                target: target(),
                epoch: epoch("running", 0),
                serial: 0,
                phase: FakePhase::Running,
                held: None,
                registers: register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46),
                hardware_rip: TARGET_RIP,
                single_step_rips: VecDeque::new(),
                unstable_once: false,
                fail_reads_while_stopped: None,
                wrong_cr3_while_stopped: false,
            }
        }

        fn with_hardware_rip(mut self, rip: u64) -> Self {
            self.hardware_rip = rip;
            self
        }

        fn with_single_step_rips(mut self, rips: impl IntoIterator<Item = u64>) -> Self {
            self.single_step_rips = rips.into_iter().collect();
            self
        }

        fn with_stopped_read_failure(mut self, reason: &'static str) -> Self {
            self.fail_reads_while_stopped = Some(reason);
            self
        }

        fn with_stopped_cr3_change(mut self) -> Self {
            self.wrong_cr3_while_stopped = true;
            self
        }

        fn rotate(&mut self, phase: &str) {
            self.serial += 1;
            self.epoch = epoch(phase, self.serial);
        }

        fn set_stop(&mut self, reason: &StopReason) {
            let (rip, dr6) = match reason {
                StopReason::HardwareBreakpoint { .. } => (self.hardware_rip, 0xffff_0ff1),
                StopReason::SingleStep => (
                    self.single_step_rips
                        .pop_front()
                        .unwrap_or(self.hardware_rip + 5),
                    0xffff_4ff0,
                ),
            };
            set_low(&mut self.registers, RegisterName::Rip, rip);
            set_low(&mut self.registers, RegisterName::Dr6, dr6);
            if self.wrong_cr3_while_stopped {
                set_low(&mut self.registers, RegisterName::Cr3, 0xdead_0000);
            }
        }
    }

    impl ControlProvider for FakeProvider {
        fn target(&self) -> &TargetIdentity {
            &self.target
        }

        fn epoch(&self) -> &StopEpoch {
            &self.epoch
        }

        fn capabilities(&mut self) -> Result<Capabilities> {
            Ok(capabilities())
        }

        fn begin_arm(&mut self) -> Result<()> {
            if self.phase != FakePhase::Running {
                bail!("not running");
            }
            self.phase = FakePhase::Arming;
            self.rotate("arming");
            Ok(())
        }

        fn finish_arm(&mut self) -> Result<()> {
            if self.phase != FakePhase::Arming {
                bail!("not arming");
            }
            self.phase = FakePhase::Running;
            self.rotate("running");
            Ok(())
        }

        fn publish_stop(&mut self, event: HeldEvent) -> Result<()> {
            if self.phase != FakePhase::Running {
                bail!("not running");
            }
            self.set_stop(&event.reason);
            self.held = Some(event);
            self.phase = FakePhase::Stopped;
            self.rotate("stopped");
            Ok(())
        }

        fn held_event(&mut self) -> Result<HeldEvent> {
            self.held.clone().context("no held event")
        }

        fn read_registers(&mut self, registers: Vec<RegisterName>) -> Result<Vec<RegisterValue>> {
            if self.phase == FakePhase::Stopped
                && let Some(reason) = self.fail_reads_while_stopped
            {
                bail!("{reason}");
            }
            let mut answer: Vec<_> = registers
                .iter()
                .map(|name| {
                    self.registers
                        .iter()
                        .find(|value| value.name == *name)
                        .unwrap()
                        .clone()
                })
                .collect();
            if self.unstable_once && self.phase == FakePhase::Stopped {
                self.unstable_once = false;
                answer[0].low.0 ^= 1;
            }
            Ok(answer)
        }

        fn write_registers(&mut self, writes: Vec<RegisterWrite>) -> Result<Vec<RegisterValue>> {
            if self.phase == FakePhase::Running {
                bail!("writes while running");
            }
            for write in &writes {
                let current = self
                    .registers
                    .iter_mut()
                    .find(|value| value.name == write.name)
                    .unwrap();
                if current.low != write.expected {
                    bail!("guard mismatch");
                }
                current.low = write.value;
            }
            Ok(writes
                .iter()
                .map(|write| {
                    self.registers
                        .iter()
                        .find(|value| value.name == write.name)
                        .unwrap()
                        .clone()
                })
                .collect())
        }

        fn release(&mut self) -> Result<()> {
            if self.phase != FakePhase::Stopped {
                bail!("not stopped");
            }
            self.phase = FakePhase::Running;
            self.held = None;
            self.rotate("running");
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Action {
        BeginArm,
        FinishArm,
        Verify(InstructionGuard),
        Wait,
        Release(ReleaseMode),
        Recover { safe: bool, owned_event: bool },
        Teardown,
    }

    struct FakeDispatcher {
        stops: VecDeque<ObservedStop>,
        actions: Vec<Action>,
        fail_release: bool,
        fail_begin: Option<&'static str>,
        fail_wait: Option<&'static str>,
        fail_recover: Option<&'static str>,
    }

    impl FakeDispatcher {
        fn new(stops: impl IntoIterator<Item = ObservedStop>) -> Self {
            Self {
                stops: stops.into_iter().collect(),
                actions: Vec::new(),
                fail_release: false,
                fail_begin: None,
                fail_wait: None,
                fail_recover: None,
            }
        }
    }

    impl EventDispatcher for FakeDispatcher {
        fn begin_arm(
            &mut self,
            _target: &TargetIdentity,
            _instruction: &InstructionGuard,
        ) -> Result<HexU64> {
            self.actions.push(Action::BeginArm);
            if let Some(reason) = self.fail_begin {
                bail!("{reason}");
            }
            Ok(HexU64(0x2000_0000_1000))
        }

        fn finish_arm(&mut self) -> Result<()> {
            self.actions.push(Action::FinishArm);
            Ok(())
        }

        fn verify_instruction(&mut self, instruction: &InstructionGuard) -> Result<()> {
            self.actions.push(Action::Verify(instruction.clone()));
            Ok(())
        }

        fn wait_for_stop(
            &mut self,
            _target: &TargetIdentity,
            _instruction: &InstructionGuard,
        ) -> Result<ObservedStop> {
            self.actions.push(Action::Wait);
            if let Some(reason) = self.fail_wait {
                bail!("{reason}");
            }
            self.stops.pop_front().context("no scripted stop")
        }

        fn release_event(&mut self, _event: &HeldEvent, mode: ReleaseMode) -> Result<()> {
            self.actions.push(Action::Release(mode));
            if self.fail_release {
                bail!("scripted native completion failure");
            }
            Ok(())
        }

        fn recover(&mut self, safe_to_resume: bool, event: Option<&HeldEvent>) -> Result<()> {
            self.actions.push(Action::Recover {
                safe: safe_to_resume,
                owned_event: event.is_some(),
            });
            if let Some(reason) = self.fail_recover {
                bail!("{reason}");
            }
            Ok(())
        }

        fn teardown(&mut self) -> Result<()> {
            self.actions.push(Action::Teardown);
            Ok(())
        }
    }

    #[test]
    fn hardware_stop_step_and_continue_consume_two_distinct_epochs() {
        let mut dispatcher = FakeDispatcher::new([
            observed(StopReason::HardwareBreakpoint { slot: 0 }),
            observed(StopReason::SingleStep),
        ]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap();

        let hardware = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(control.phase(), LivePhase::Stopped);
        assert_eq!(
            hardware.registers.low(RegisterName::Rip).unwrap(),
            TARGET_RIP
        );
        let stale = epoch("stopped", 999);
        assert!(
            control
                .step(&mut dispatcher, &stale, straight_step())
                .unwrap_err()
                .to_string()
                .contains("stale")
        );

        control
            .step(&mut dispatcher, &hardware.epoch, straight_step())
            .unwrap();
        let stepped = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(
            stepped.registers.low(RegisterName::Rip).unwrap(),
            TARGET_RIP + 5
        );
        control
            .continue_from(&mut dispatcher, &stepped.epoch)
            .unwrap();
        assert_eq!(control.phase(), LivePhase::Running);
        assert_eq!(
            control.provider.registers,
            register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46)
        );
        assert_eq!(
            dispatcher.actions,
            vec![
                Action::BeginArm,
                Action::FinishArm,
                Action::Wait,
                Action::Verify(instruction()),
                Action::Release(ReleaseMode::ArmNextStop),
                Action::Wait,
                Action::Release(ReleaseMode::Resume),
            ]
        );
    }

    #[test]
    fn natural_flow_leaves_rip_untouched_and_preserves_guest_progress_on_release() {
        let natural = InstructionGuard {
            address: HexU64(BASE_RIP),
            bytes: vec![0x0f, 0x1f, 0x44, 0x00, 0x00],
        };
        let mut dispatcher = FakeDispatcher::new([
            ObservedStop {
                event: event(StopReason::HardwareBreakpoint { slot: 0 }),
                instruction: natural.clone(),
            },
            ObservedStop {
                event: event(StopReason::SingleStep),
                instruction: natural.clone(),
            },
        ]);
        let provider = FakeProvider::new().with_hardware_rip(BASE_RIP);
        let mut control = LiveControl::open(provider).unwrap();

        control
            .arm(&mut dispatcher, natural, ArmMode::Natural)
            .unwrap();
        assert_eq!(
            control.provider.registers[0].low.0, BASE_RIP,
            "natural arming must not redirect RIP"
        );
        let hardware = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(hardware.arm_mode, ArmMode::Natural);
        control
            .step(&mut dispatcher, &hardware.epoch, straight_step())
            .unwrap();
        let stepped = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(
            stepped.registers.low(RegisterName::Rip).unwrap(),
            BASE_RIP + 5
        );
        control
            .continue_from(&mut dispatcher, &stepped.epoch)
            .unwrap();

        assert_eq!(
            control.provider.registers[0].low.0,
            BASE_RIP + 5,
            "natural release must not replay the path from the saved RIP"
        );
        for name in [
            RegisterName::Dr0,
            RegisterName::Dr1,
            RegisterName::Dr2,
            RegisterName::Dr3,
            RegisterName::Dr6,
            RegisterName::Dr7,
        ] {
            assert_eq!(
                control
                    .provider
                    .registers
                    .iter()
                    .find(|r| r.name == name)
                    .unwrap(),
                register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46)
                    .iter()
                    .find(|r| r.name == name)
                    .unwrap()
            );
        }
    }

    #[test]
    fn repeated_step_requires_a_current_guard_and_accepts_a_bounded_branch_destination() {
        let branch = InstructionGuard {
            address: HexU64(TARGET_RIP + 5),
            bytes: vec![0xeb, 0x19],
        };
        let branch_target = HexU64(TARGET_RIP + 0x20);
        let mut dispatcher = FakeDispatcher::new([
            observed(StopReason::HardwareBreakpoint { slot: 0 }),
            observed(StopReason::SingleStep),
            ObservedStop {
                event: event(StopReason::SingleStep),
                instruction: branch.clone(),
            },
        ]);
        let provider = FakeProvider::new().with_single_step_rips([TARGET_RIP + 5, branch_target.0]);
        let mut control = LiveControl::open(provider).unwrap();
        control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap();

        let hardware = control.wait_for_stop(&mut dispatcher).unwrap();
        control
            .step(&mut dispatcher, &hardware.epoch, straight_step())
            .unwrap();
        let first_step = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(first_step.expected_rips, vec![HexU64(TARGET_RIP + 5)]);

        let error = control
            .step(&mut dispatcher, &first_step.epoch, straight_step())
            .unwrap_err();
        assert!(error.to_string().contains("repeated step"), "{error:#}");
        assert_eq!(control.stopped().unwrap().epoch, first_step.epoch);

        let destinations = vec![HexU64(TARGET_RIP + 7), branch_target];
        control
            .step(
                &mut dispatcher,
                &first_step.epoch,
                StepGuard {
                    instruction: Some(branch.clone()),
                    expected_rips: destinations.clone(),
                },
            )
            .unwrap();
        let branch_stop = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(
            branch_stop.registers.low(RegisterName::Rip).unwrap(),
            branch_target.0
        );
        assert_eq!(branch_stop.instruction, branch);
        assert_eq!(branch_stop.expected_rips, destinations);
        control
            .continue_from(&mut dispatcher, &branch_stop.epoch)
            .unwrap();
    }

    #[test]
    fn natural_flow_refuses_a_saved_trap_or_resume_flag() {
        let mut provider = FakeProvider::new();
        set_low(&mut provider.registers, RegisterName::Rflags, 0x46 | TF);
        let mut control = LiveControl::open(provider).unwrap();
        let mut dispatcher = FakeDispatcher::new([]);
        let error = control
            .arm(&mut dispatcher, instruction(), ArmMode::Natural)
            .unwrap_err();
        assert!(error.to_string().contains("TF and RF"), "{error:#}");
        assert_eq!(control.phase(), LivePhase::Faulted);
    }

    #[test]
    fn changed_instruction_faults_and_restores_before_completing_the_owned_event() {
        let mut changed = instruction();
        changed.bytes[0] ^= 1;
        let mut dispatcher = FakeDispatcher::new([ObservedStop {
            event: event(StopReason::HardwareBreakpoint { slot: 0 }),
            instruction: changed,
        }]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap();
        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();

        assert!(error.to_string().contains("guarded instruction changed"));
        assert_eq!(control.phase(), LivePhase::Faulted);
        assert_eq!(
            control.provider.registers,
            register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46)
        );
        assert_eq!(
            dispatcher.actions.last(),
            Some(&Action::Recover {
                safe: true,
                owned_event: true
            })
        );
    }

    #[test]
    fn unrelated_event_faults_without_authorising_native_completion() {
        let mut unrelated = event(StopReason::HardwareBreakpoint { slot: 0 });
        unrelated.dispatcher_context = HexU64(0x2000_0000_2000);
        let mut dispatcher = FakeDispatcher::new([ObservedStop {
            event: unrelated,
            instruction: instruction(),
        }]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap();
        control.wait_for_stop(&mut dispatcher).unwrap_err();

        assert_eq!(control.phase(), LivePhase::Faulted);
        assert_eq!(
            dispatcher.actions.last(),
            Some(&Action::Recover {
                safe: false,
                owned_event: false
            })
        );
        assert!(control.fault().unwrap().target_left_paused);
    }

    #[test]
    fn unstable_held_registers_fault_and_restore_the_original_state() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        let mut provider = FakeProvider::new();
        provider.unstable_once = true;
        let mut control = LiveControl::open(provider).unwrap();
        control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap();
        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();

        assert!(error.to_string().contains("changed while"));
        assert_eq!(control.phase(), LivePhase::Faulted);
        assert_eq!(
            control.provider.registers,
            register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46)
        );
    }

    #[test]
    fn native_completion_failure_is_terminal_after_bounded_restoration() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        dispatcher.fail_release = true;
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap();
        let stopped = control.wait_for_stop(&mut dispatcher).unwrap();
        let error = control
            .continue_from(&mut dispatcher, &stopped.epoch)
            .unwrap_err();

        assert!(error.to_string().contains("native completion failure"));
        assert_eq!(control.phase(), LivePhase::Faulted);
        assert!(!control.fault().unwrap().target_left_paused);
        assert_eq!(
            dispatcher.actions.last(),
            Some(&Action::Recover {
                safe: true,
                owned_event: true
            })
        );
    }

    #[test]
    fn close_while_stopped_restores_releases_tears_down_and_is_idempotent() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap();
        control.wait_for_stop(&mut dispatcher).unwrap();
        control.close(&mut dispatcher).unwrap();
        control.close(&mut dispatcher).unwrap();

        assert_eq!(control.phase(), LivePhase::Closed);
        assert_eq!(dispatcher.actions.last(), Some(&Action::Teardown));
        assert_eq!(
            control.provider.registers,
            register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46)
        );
    }

    #[test]
    fn dispatcher_timeout_restores_the_baseline_and_resumes_before_faulting() {
        let mut dispatcher = FakeDispatcher::new([]);
        dispatcher.fail_wait = Some("dispatcher wait timed out");
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap();

        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error:#}");
        assert_eq!(control.phase(), LivePhase::Faulted);
        assert!(!control.fault().unwrap().target_left_paused);
        assert_eq!(
            control.provider.registers,
            register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46)
        );
        assert_eq!(
            dispatcher.actions.last(),
            Some(&Action::Recover {
                safe: true,
                owned_event: false,
            })
        );
    }

    #[test]
    fn provider_death_while_stopped_contains_the_vm_without_native_completion() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        let provider = FakeProvider::new().with_stopped_read_failure("provider pipe closed");
        let mut control = LiveControl::open(provider).unwrap();
        control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap();

        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();
        assert!(
            error.to_string().contains("provider pipe closed"),
            "{error:#}"
        );
        assert!(control.fault().unwrap().target_left_paused);
        assert_eq!(
            dispatcher.actions.last(),
            Some(&Action::Recover {
                safe: false,
                owned_event: false,
            })
        );
    }

    #[test]
    fn debugger_loss_after_restoration_is_reported_as_deliberately_paused() {
        let mut dispatcher = FakeDispatcher::new([]);
        dispatcher.fail_wait = Some("debugger process exited");
        dispatcher.fail_recover = Some("debugger is unavailable");
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap();

        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();
        assert!(error.to_string().contains("debugger process exited"));
        let fault = control.fault().unwrap();
        assert!(fault.target_left_paused);
        assert!(
            fault
                .recovery_errors
                .iter()
                .any(|error| error.contains("debugger is unavailable"))
        );
    }

    #[test]
    fn vm_reset_identity_change_refuses_restoration_and_leaves_it_paused() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        let mut control = LiveControl::open(FakeProvider::new().with_stopped_cr3_change()).unwrap();
        control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap();

        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();
        assert!(error.to_string().contains("CR3"), "{error:#}");
        assert!(control.fault().unwrap().target_left_paused);
    }

    #[test]
    fn build_mismatch_before_provider_mutation_recovers_and_resumes() {
        let mut dispatcher = FakeDispatcher::new([]);
        dispatcher.fail_begin = Some("vmwp SHA-256 does not match the dispatcher profile");
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();

        let error = control
            .arm(&mut dispatcher, instruction(), ArmMode::Redirect)
            .unwrap_err();
        assert!(error.to_string().contains("SHA-256"), "{error:#}");
        assert_eq!(control.phase(), LivePhase::Faulted);
        assert!(!control.fault().unwrap().target_left_paused);
        assert_eq!(control.provider.phase, FakePhase::Running);
        assert_eq!(
            dispatcher.actions,
            vec![
                Action::BeginArm,
                Action::Recover {
                    safe: true,
                    owned_event: false,
                },
            ]
        );
    }

    #[test]
    fn dispatcher_profile_accepts_only_bounded_numeric_build_inputs() {
        let profile = dispatcher_profile();
        profile.validate().unwrap();
        let encoded = serde_json::to_string(&profile).unwrap();
        assert!(!encoded.contains("command"));

        let mut bad_hash = profile.clone();
        bad_hash.vmwp_sha256 = "not-a-hash".into();
        assert!(
            bad_hash
                .validate()
                .unwrap_err()
                .to_string()
                .contains("64 hexadecimal")
        );

        let mut bad_stack = profile.clone();
        bad_stack.layout.register_stack_handler = 0x21;
        assert!(
            bad_stack
                .validate()
                .unwrap_err()
                .to_string()
                .contains("stack-argument")
        );
    }

    #[test]
    fn dispatcher_profile_rejects_overlapping_or_out_of_image_stop_sites() {
        let mut overlap = dispatcher_profile();
        overlap.callback_entry.rva = overlap.event_held.rva;
        assert!(
            overlap
                .validate()
                .unwrap_err()
                .to_string()
                .contains("overlap")
        );

        let mut outside = dispatcher_profile();
        outside.native_return.rva = HexU64(u64::from(outside.vmwp_size_of_image));
        assert!(
            outside
                .validate()
                .unwrap_err()
                .to_string()
                .contains("outside vmwp")
        );

        let mut unaligned_vp = dispatcher_profile();
        unaligned_vp.layout.event_vp = 0x11;
        assert!(
            unaligned_vp
                .validate()
                .unwrap_err()
                .to_string()
                .contains("event_vp")
        );
    }

    fn target() -> TargetIdentity {
        TargetIdentity {
            vm_id: "11111111-2222-3333-4444-555555555555".into(),
            partition_id: HexU64(0x91),
            vp: 0,
            vtl: 1,
            expected_cr3: HexU64(0x120_1000),
        }
    }

    fn dispatcher_profile() -> DispatcherProfile {
        DispatcherProfile {
            schema: PROFILE_SCHEMA.into(),
            vmwp_image: r"C:\Windows\System32\vmwp.exe".into(),
            vmwp_sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            vmwp_size_of_image: 0x300000,
            scratch_base: HexU64(0x2000_0000_0000),
            scratch_size: 0x1000,
            registration_tag: HexU64(0x4b34_4155_544f_5354),
            register_handler_rva: HexU64(0x10000),
            unregister_handler_rva: HexU64(0x11000),
            callback_stub_rva: HexU64(0x12000),
            callback_resume_rva: HexU64(0x13000),
            event_held: site(0x20000),
            callback_entry: site(0x21000),
            handle_return: site(0x22000),
            native_return: site(0x23000),
            deferred_cleanup: site(0x24000),
            layout: DispatcherLayout {
                returned_context: 0,
                handler_descriptor: 0x100,
                callback_descriptor: 0x200,
                callback_mirror: 0x30,
                event_context: 8,
                event_vp: 0x10,
                exchange_advance: 0x148,
                callback_pointer: 0x80,
                callback_flags: 0x88,
                register_stack_handler: 0x28,
                register_stack_context: 0x30,
            },
        }
    }

    fn site(rva: u64) -> DispatcherSite {
        DispatcherSite {
            rva: HexU64(rva),
            original: vec![0x48, 0x89, 0x5c, 0x24, 0x08],
        }
    }

    fn epoch(phase: &str, serial: u64) -> StopEpoch {
        StopEpoch::new(format!("{phase}-{serial:016x}")).unwrap()
    }

    fn instruction() -> InstructionGuard {
        InstructionGuard {
            address: HexU64(TARGET_RIP),
            bytes: vec![0x0f, 0x1f, 0x44, 0x00, 0x00],
        }
    }

    fn straight_step() -> StepGuard {
        StepGuard {
            instruction: None,
            expected_rips: Vec::new(),
        }
    }

    fn event(reason: StopReason) -> HeldEvent {
        HeldEvent {
            message_type: HexU64(0x0100_0002),
            vector: 1,
            vp: 0,
            vtl: 1,
            cpl: 0,
            dispatcher_context: HexU64(0x2000_0000_1000),
            advance_instruction_pointer: false,
            reason,
        }
    }

    fn observed(reason: StopReason) -> ObservedStop {
        ObservedStop {
            event: event(reason),
            instruction: instruction(),
        }
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
            ],
            readable_registers: SNAPSHOT_REGISTERS.to_vec(),
            writable_registers: WRITTEN_REGISTERS.to_vec(),
            max_registers_per_request: SNAPSHOT_REGISTERS.len() as u16,
            requires_stop_epoch: true,
            writes_while_running: false,
        }
    }

    fn register_values(rip: u64, dr6: u64, dr7: u64, rflags: u64) -> Vec<RegisterValue> {
        SNAPSHOT_REGISTERS
            .iter()
            .map(|name| RegisterValue {
                name: *name,
                status: 0,
                low: HexU64(match name {
                    RegisterName::Rip => rip,
                    RegisterName::Rsp => 0xffff_9700_7961_eec8,
                    RegisterName::Rflags => rflags,
                    RegisterName::Cr3 => 0x120_1000,
                    RegisterName::Cs => 0,
                    RegisterName::Dr0
                    | RegisterName::Dr1
                    | RegisterName::Dr2
                    | RegisterName::Dr3 => 0,
                    RegisterName::Dr6 => dr6,
                    RegisterName::Dr7 => dr7,
                    RegisterName::VsmVpStatus => 0x0003_0010,
                }),
                high: HexU64(if *name == RegisterName::Cs {
                    0x209b_0010_0000_0000
                } else {
                    0
                }),
            })
            .collect()
    }

    fn set_low(values: &mut [RegisterValue], name: RegisterName, value: u64) {
        values
            .iter_mut()
            .find(|register| register.name == name)
            .unwrap()
            .low = HexU64(value);
    }
}
