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

use anyhow::{Context, Result, anyhow, bail};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::skcontrol::{
    Capabilities, ControlProcess, ControlSession, HeldEvent, HexU64, RegisterName, RegisterValue,
    RegisterWrite, StopEpoch, StopReason, TargetIdentity,
};

const TF: u64 = 1 << 8;
const RF: u64 = 1 << 16;
const DR6_CAUSE_MASK: u64 = 0xe00f;
const DR7_ENABLE_MASK: u64 = 0xff;
const MAX_INSTRUCTION_BYTES: usize = 15;
const MAX_HARDWARE_BREAKPOINTS: usize = 4;
pub(crate) const MAX_LIVE_CONTROL_VPS: usize = 16;
const MAX_STEP_DESTINATIONS: usize = 4;
const PROFILE_SCHEMA: &str = "windbg-mcp.sk-live-dispatcher-profile.v1";
const MAX_PROFILE_BYTES: u64 = 64 * 1024;
const MAX_PROFILE_CATALOG_ENTRIES: usize = 128;
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
    fn capabilities(&mut self) -> Result<Capabilities>;
    fn begin_arm(&mut self) -> Result<()>;
    fn finish_arm(&mut self) -> Result<()>;
    fn publish_stop(&mut self, event: HeldEvent) -> Result<()>;
    fn held_event(&mut self) -> Result<HeldEvent>;
    fn read_registers(&mut self, registers: Vec<RegisterName>) -> Result<Vec<RegisterValue>>;
    fn read_registers_until(
        &mut self,
        registers: Vec<RegisterName>,
        _deadline: Instant,
    ) -> Result<Vec<RegisterValue>> {
        self.read_registers(registers)
    }
    fn set_outer_deadline(&mut self, _deadline: Option<Instant>) {}
    fn write_registers(&mut self, writes: Vec<RegisterWrite>) -> Result<Vec<RegisterValue>>;
    fn release(&mut self) -> Result<()>;
}

impl<R: std::io::BufRead, W: std::io::Write> ControlProvider for ControlSession<R, W> {
    fn target(&self) -> &TargetIdentity {
        ControlSession::target(self)
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

    fn read_registers_until(
        &mut self,
        registers: Vec<RegisterName>,
        deadline: Instant,
    ) -> Result<Vec<RegisterValue>> {
        ControlProcess::read_registers_until(self, registers, deadline)
    }

    fn set_outer_deadline(&mut self, deadline: Option<Instant>) {
        ControlProcess::set_outer_deadline(self, deadline);
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
    /// A second read of every exact instruction selected when the breakpoints were armed.
    pub(crate) instructions: Vec<InstructionGuard>,
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
        targets: &[TargetIdentity],
        breakpoints: &[BreakpointGuard],
    ) -> Result<HexU64>;
    /// Detach before pausing an armed target that produced no event, then reattach while paused so
    /// provider state and the registered handler can be removed without deadlocking Hyper-V.
    fn begin_disarm(&mut self, targets: &[TargetIdentity]) -> Result<()>;
    fn finish_arm(&mut self) -> Result<()>;
    /// Whether every provider whose registers may be accessed is currently quiesced.
    fn provider_writes_quiesced(&self) -> bool;
    /// Finish any pending transition and prove provider-write quiescence for fault recovery.
    fn establish_recovery_pause(&mut self, targets: &[TargetIdentity]) -> Result<()>;
    fn establish_recovery_pause_until(
        &mut self,
        targets: &[TargetIdentity],
        _deadline: Instant,
    ) -> Result<()> {
        self.establish_recovery_pause(targets)
    }
    /// Re-read a proposed current instruction while the owned event remains held.
    fn verify_instruction(&mut self, instruction: &InstructionGuard) -> Result<()>;
    fn verify_instruction_until(
        &mut self,
        instruction: &InstructionGuard,
        _deadline: Instant,
    ) -> Result<()> {
        self.verify_instruction(instruction)
    }
    fn retained_pause_deadline(&self) -> Option<Instant> {
        None
    }
    fn retained_recovery_deadline(&self) -> Option<Instant> {
        self.retained_pause_deadline()
    }
    /// Return an owned event only after every provider whose registers may be accessed is quiesced.
    fn wait_for_stop(
        &mut self,
        targets: &[TargetIdentity],
        instructions: &[InstructionGuard],
    ) -> Result<ObservedStop>;
    /// Rebind live virtual-memory translation to the CR3 proved by the held register snapshot.
    fn bind_stop_cr3(&mut self, cr3: u64) -> Result<()>;
    fn bind_stop_cr3_until(&mut self, cr3: u64, _deadline: Instant) -> Result<()> {
        self.bind_stop_cr3(cr3)
    }
    fn release_event(&mut self, event: &HeldEvent, mode: ReleaseMode) -> Result<()>;
    fn release_event_until(
        &mut self,
        event: &HeldEvent,
        mode: ReleaseMode,
        _deadline: Instant,
    ) -> Result<()> {
        self.release_event(event, mode)
    }
    fn recover(&mut self, safe_to_resume: bool, event: Option<&HeldEvent>) -> Result<()>;
    fn recover_until(
        &mut self,
        safe_to_resume: bool,
        event: Option<&HeldEvent>,
        _deadline: Instant,
    ) -> Result<()> {
        self.recover(safe_to_resume, event)
    }
    fn teardown(&mut self) -> Result<()>;
    fn teardown_until(&mut self, _deadline: Instant) -> Result<()> {
        self.teardown()
    }
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

/// Exact-build site used to learn this boot's dispatcher identity before handler registration.
/// It is optional so existing profiles remain valid until their discovery bytes are measured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispatcherDiscoveryProfile {
    pub(crate) entry: DispatcherSite,
    pub(crate) vid_image: std::path::PathBuf,
    pub(crate) vid_sha256: String,
    pub(crate) vid_size_of_image: u32,
}

/// Build-relative Secure Kernel instruction used to create the KD facade's first held stop.
/// The live-memory provider supplies the boot-specific image base; the exact bytes remain in the
/// build profile so an MCP caller never has to supply a coordinate derived by another debugger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecureKernelInitialProfile {
    pub(crate) rva: HexU64,
    pub(crate) original: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecureKernelDebuggerDataProfile {
    pub(crate) list_head_rva: HexU64,
    pub(crate) block_rva: HexU64,
    pub(crate) loaded_module_list_rva: HexU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecureKernelKdProfile {
    pub(crate) build: u16,
    pub(crate) initial: SecureKernelInitialProfile,
    pub(crate) debugger_data: SecureKernelDebuggerDataProfile,
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
    #[serde(default)]
    pub(crate) discovery: Option<DispatcherDiscoveryProfile>,
    #[serde(default)]
    pub(crate) secure_kernel_kd: Option<SecureKernelKdProfile>,
    pub(crate) event_held: DispatcherSite,
    pub(crate) callback_entry: DispatcherSite,
    pub(crate) handle_return: DispatcherSite,
    pub(crate) native_return: DispatcherSite,
    pub(crate) deferred_cleanup: DispatcherSite,
    pub(crate) layout: DispatcherLayout,
}

impl DispatcherProfile {
    pub(crate) fn load(path: &std::path::Path) -> Result<Self> {
        let path = path
            .canonicalize()
            .with_context(|| format!("canonicalizing dispatcher profile {}", path.display()))?;
        if path.is_dir() {
            return Self::load_catalog(&path);
        }
        Self::load_file(&path)
    }

    fn load_file(path: &std::path::Path) -> Result<Self> {
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

    fn load_catalog(path: &std::path::Path) -> Result<Self> {
        let directory = std::fs::read_dir(path)
            .with_context(|| format!("reading dispatcher profile catalog {}", path.display()))?;
        let mut entries = Vec::new();
        for (index, entry) in directory.enumerate() {
            if index == MAX_PROFILE_CATALOG_ENTRIES {
                bail!(
                    "dispatcher profile catalog may contain at most {MAX_PROFILE_CATALOG_ENTRIES} total entries"
                );
            }
            let entry = entry
                .with_context(|| {
                    format!("enumerating dispatcher profile catalog {}", path.display())
                })?
                .path();
            if entry
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
            {
                let entry = entry.canonicalize().with_context(|| {
                    format!(
                        "canonicalizing dispatcher profile entry {}",
                        entry.display()
                    )
                })?;
                if entry.parent() != Some(path) {
                    bail!(
                        "dispatcher profile entry {} resolves outside catalog {}",
                        entry.display(),
                        path.display()
                    );
                }
                entries.push(entry);
            }
        }
        entries.sort();
        if entries.is_empty() {
            bail!("dispatcher profile catalog contains no JSON profiles");
        }

        let mut matching = Vec::new();
        for entry in entries {
            let profile = Self::load_file(&entry)?;
            if profile.local_image_matches()? {
                matching.push((entry, profile));
            }
        }
        match matching.as_slice() {
            [(_, profile)] => Ok(profile.clone()),
            [] => bail!(
                "no dispatcher profile in {} matches its current local vmwp.exe image",
                path.display()
            ),
            _ => bail!(
                "dispatcher profile catalog {} has {} entries matching local vmwp.exe images; selection must be unique",
                path.display(),
                matching.len()
            ),
        }
    }

    fn local_image_matches(&self) -> Result<bool> {
        let bytes = match std::fs::read(&self.vmwp_image) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("reading profiled vmwp image {}", self.vmwp_image.display())
                });
            }
        };
        let actual = crate::client::sha256(&bytes)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        Ok(actual.eq_ignore_ascii_case(&self.vmwp_sha256))
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
        let mut sites = vec![
            ("event_held", &self.event_held),
            ("callback_entry", &self.callback_entry),
            ("handle_return", &self.handle_return),
            ("native_return", &self.native_return),
            ("deferred_cleanup", &self.deferred_cleanup),
        ];
        if let Some(discovery) = &self.discovery {
            sites.push(("discovery.entry", &discovery.entry));
            if !discovery.vid_image.is_absolute()
                || !discovery
                    .vid_image
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case("vid.dll"))
            {
                bail!("discovery.vid_image must be an absolute path ending in vid.dll");
            }
            if discovery.vid_sha256.len() != 64
                || !discovery
                    .vid_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                bail!("discovery.vid_sha256 must contain exactly 64 hexadecimal digits");
            }
            if discovery.vid_size_of_image == 0 {
                bail!("discovery.vid_size_of_image must be nonzero");
            }
        }
        if let Some(kd) = &self.secure_kernel_kd {
            if kd.build == 0 {
                bail!("secure_kernel_kd.build must be nonzero");
            }
            let initial = &kd.initial;
            if initial.original.is_empty() || initial.original.len() > MAX_INSTRUCTION_BYTES {
                bail!(
                    "secure_kernel_kd.initial.original must contain 1..={MAX_INSTRUCTION_BYTES} bytes"
                );
            }
            let end = initial
                .rva
                .0
                .checked_add(initial.original.len() as u64)
                .context("secure_kernel_kd.initial range overflowed")?;
            if initial.rva.0 == 0 || end > u64::from(u32::MAX) + 1 {
                bail!("secure_kernel_kd.initial must be a nonzero 32-bit image-relative range");
            }
            for (name, rva) in [
                ("list_head_rva", kd.debugger_data.list_head_rva.0),
                ("block_rva", kd.debugger_data.block_rva.0),
                (
                    "loaded_module_list_rva",
                    kd.debugger_data.loaded_module_list_rva.0,
                ),
            ] {
                if rva == 0 || rva > u64::from(u32::MAX) {
                    bail!("secure_kernel_kd.debugger_data.{name} must be a nonzero 32-bit RVA");
                }
            }
        }
        for (name, site) in &sites {
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

/// One execution breakpoint owned by a live-control arm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BreakpointGuard {
    /// Architectural debug-register slot, in `0..=3`.
    pub(crate) slot: u8,
    pub(crate) instruction: InstructionGuard,
}

impl BreakpointGuard {
    pub(crate) fn validate(&self) -> Result<()> {
        if usize::from(self.slot) >= MAX_HARDWARE_BREAKPOINTS {
            bail!("a hardware breakpoint slot must be in 0..=3");
        }
        self.instruction.validate()
    }

    fn register(&self) -> RegisterName {
        match self.slot {
            0 => RegisterName::Dr0,
            1 => RegisterName::Dr1,
            2 => RegisterName::Dr2,
            3 => RegisterName::Dr3,
            _ => unreachable!("validated breakpoint slot"),
        }
    }

    fn enable_mask(&self) -> u64 {
        1 << (u32::from(self.slot) * 2)
    }

    fn kind_mask(&self) -> u64 {
        0xf << (16 + u32::from(self.slot) * 4)
    }
}

pub(crate) fn validate_breakpoints(breakpoints: &[BreakpointGuard], mode: ArmMode) -> Result<()> {
    if breakpoints.is_empty() || breakpoints.len() > MAX_HARDWARE_BREAKPOINTS {
        bail!("an arm requires 1..={MAX_HARDWARE_BREAKPOINTS} hardware breakpoints");
    }
    if mode == ArmMode::Redirect && breakpoints.len() != 1 {
        bail!("redirect arming requires exactly one hardware breakpoint");
    }
    for (index, breakpoint) in breakpoints.iter().enumerate() {
        breakpoint.validate()?;
        for earlier in &breakpoints[..index] {
            if earlier.slot == breakpoint.slot {
                bail!("hardware breakpoint slots must be distinct");
            }
            if earlier.instruction.address == breakpoint.instruction.address {
                bail!("hardware breakpoint addresses must be distinct");
            }
        }
    }
    Ok(())
}

/// How the first hardware breakpoint is reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ArmMode {
    /// Redirect the saved RIP to the guarded instruction, then restore the complete baseline.
    Redirect,
    /// Leave RIP untouched and wait for guest control flow to reach the guarded instruction.
    #[default]
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
        validate_step_instruction_class(&instruction)?;

        let expected_rips = if self.expected_rips.is_empty() {
            vec![HexU64(instruction.successor())]
        } else {
            self.expected_rips
        };
        Ok((instruction, expected_rips))
    }
}

/// Refuses x64 instructions for which TF does not guarantee a trap at the next architectural
/// instruction. The MCP and KD front ends share this gate so choosing the other protocol cannot
/// bypass the retained-stop invariant.
pub(crate) fn validate_step_instruction_class(instruction: &InstructionGuard) -> Result<()> {
    let mut decoder = Decoder::with_ip(
        64,
        &instruction.bytes,
        instruction.address.0,
        DecoderOptions::NONE,
    );
    let decoded = decoder.decode();
    if decoded.is_invalid() || decoded.len() != instruction.bytes.len() {
        bail!("the guarded VTL1 bytes do not decode as exactly one AMD64 instruction");
    }
    let writes_ss = decoded.op0_kind() == OpKind::Register
        && decoded.op0_register() == Register::SS
        && matches!(decoded.mnemonic(), Mnemonic::Mov | Mnemonic::Pop);
    let repeats = decoded.is_string_instruction()
        && (decoded.has_rep_prefix() || decoded.has_repe_prefix() || decoded.has_repne_prefix());
    if repeats {
        bail!(
            "single-step is refused for repeated {:?} at {:#x}; the trap can stop before the \
             guarded destination",
            decoded.mnemonic(),
            instruction.address.0
        );
    }
    if writes_ss || decoded.mnemonic() == Mnemonic::Lss {
        bail!(
            "single-step is refused because {:?} can defer the trap-flag exception past the \
             guarded destination at {:#x}",
            decoded.mnemonic(),
            instruction.address.0
        );
    }
    Ok(())
}

/// Complete register evidence retained for one stop. Status and high halves remain visible instead
/// of being discarded after validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisterSnapshot {
    pub(crate) values: Vec<RegisterValue>,
}

impl RegisterSnapshot {
    fn from_values(
        values: Vec<RegisterValue>,
        expected_cr3: Option<u64>,
        allow_transition_cr3: bool,
    ) -> Result<Self> {
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
        let observed_cr3 = snapshot.low(RegisterName::Cr3)?;
        match expected_cr3 {
            Some(expected) if observed_cr3 != expected => {
                bail!("the stopped CR3 does not match the required address space");
            }
            None if !allow_transition_cr3 => {
                bail!("a transition CR3 was not enabled for this session");
            }
            None if observed_cr3 == 0 || observed_cr3 & 0xfff != 0 => {
                bail!("the transition CR3 must be nonzero and page aligned");
            }
            _ => {}
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
    SingleStep {
        instruction: InstructionGuard,
        expected_rips: Vec<HexU64>,
        cr3: HexU64,
    },
}

#[derive(Clone, Debug)]
enum State {
    Running,
    Arming,
    Stopped(StopRecord),
    Releasing,
    Faulted,
    Closed,
}

struct VpControl<P> {
    provider: P,
    target: TargetIdentity,
    max_registers_per_request: usize,
    provider_phase: ProviderPhase,
    baseline: Option<RegisterSnapshot>,
    observed_cr3: Option<u64>,
}

/// One-VM coordinator for selected VPs and up to four execution breakpoints per VP. The dispatcher
/// pauses the whole VM while this state changes. It is synchronous because its owner is the
/// worker's single engine thread.
pub(crate) struct LiveControl<P> {
    providers: Vec<VpControl<P>>,
    active_provider: Option<usize>,
    epoch_nonce: String,
    epoch_serial: u64,
    public_epoch: StopEpoch,
    state: State,
    breakpoints: Vec<BreakpointGuard>,
    arm_mode: Option<ArmMode>,
    dispatcher_context: Option<HexU64>,
    dispatcher_event: Option<HeldEvent>,
    expected_stop: Option<ExpectedStop>,
    allow_transition_cr3: bool,
    fault: Option<FaultRecord>,
}

impl<P: ControlProvider> LiveControl<P> {
    #[cfg(test)]
    pub(crate) fn open(provider: P) -> Result<Self> {
        Self::open_with_transition(provider, false)
    }

    pub(crate) fn open_with_transition(provider: P, allow_transition_cr3: bool) -> Result<Self> {
        Self::open_many_with_transition(vec![provider], allow_transition_cr3)
    }

    #[cfg(test)]
    pub(crate) fn open_many(providers: Vec<P>) -> Result<Self> {
        Self::open_many_with_transition(providers, false)
    }

    fn open_many_with_transition(
        mut providers: Vec<P>,
        allow_transition_cr3: bool,
    ) -> Result<Self> {
        if providers.is_empty() {
            bail!("live control requires at least one VP provider");
        }
        if providers.len() > MAX_LIVE_CONTROL_VPS {
            bail!("live control accepts at most {MAX_LIVE_CONTROL_VPS} VP providers");
        }
        let epoch_nonce = crate::client::generate_token()
            .context("generating the live-control session epoch nonce")?;
        let mut controls = Vec::with_capacity(providers.len());
        for mut provider in providers.drain(..) {
            provider.target().validate()?;
            let capabilities = provider.capabilities()?;
            require_registers(&capabilities, &SNAPSHOT_REGISTERS, false)?;
            require_registers(&capabilities, &WRITTEN_REGISTERS, true)?;
            let max_registers_per_request = usize::from(capabilities.max_registers_per_request);
            let target = provider.target().clone();
            if controls.iter().any(|control: &VpControl<P>| {
                control.target.vm_id.eq_ignore_ascii_case(&target.vm_id)
                    && control.target.vp == target.vp
            }) {
                bail!("live-control VP targets must be distinct");
            }
            if let Some(first) = controls.first()
                && (!first.target.vm_id.eq_ignore_ascii_case(&target.vm_id)
                    || first.target.partition_id != target.partition_id
                    || first.target.vtl != target.vtl
                    || first.target.expected_cr3 != target.expected_cr3)
            {
                bail!("all live-control VP providers must name one VM, partition, VTL and CR3");
            }
            controls.push(VpControl {
                provider,
                target,
                max_registers_per_request,
                provider_phase: ProviderPhase::Running,
                baseline: None,
                observed_cr3: None,
            });
        }
        Ok(Self {
            providers: controls,
            active_provider: None,
            epoch_nonce: epoch_nonce.clone(),
            epoch_serial: 0,
            public_epoch: StopEpoch::new(format!(
                "control-{epoch_nonce}-running-0000000000000000"
            ))?,
            state: State::Running,
            breakpoints: Vec::new(),
            arm_mode: None,
            dispatcher_context: None,
            dispatcher_event: None,
            expected_stop: None,
            allow_transition_cr3,
            fault: None,
        })
    }

    pub(crate) fn phase(&self) -> LivePhase {
        match self.state {
            State::Running => LivePhase::Running,
            State::Arming => LivePhase::Arming,
            State::Stopped(_) => LivePhase::Stopped,
            State::Releasing => LivePhase::Releasing,
            State::Faulted => LivePhase::Faulted,
            State::Closed => LivePhase::Closed,
        }
    }

    #[cfg(test)]
    pub(crate) fn fault(&self) -> Option<&FaultRecord> {
        self.fault.as_ref()
    }

    pub(crate) fn stopped(&self) -> Option<&StopRecord> {
        match &self.state {
            State::Stopped(stop) => Some(stop),
            _ => None,
        }
    }

    pub(crate) fn selected_target(&self) -> &TargetIdentity {
        &self.providers[0].target
    }

    /// Read additional architectural state while the exact published event remains held.
    ///
    /// The stop snapshot contains the registers needed to prove control ownership. Debugger
    /// clients also need the general-purpose registers, so those are fetched on demand and must
    /// agree across two complete reads before they are exposed.
    #[cfg(test)]
    pub(crate) fn read_stopped_registers(
        &mut self,
        epoch: &StopEpoch,
        registers: Vec<RegisterName>,
    ) -> Result<Vec<RegisterValue>> {
        self.read_stopped_registers_inner(epoch, registers, None)
    }

    pub(crate) fn read_stopped_registers_until(
        &mut self,
        epoch: &StopEpoch,
        registers: Vec<RegisterName>,
        deadline: Instant,
    ) -> Result<Vec<RegisterValue>> {
        self.read_stopped_registers_inner(epoch, registers, Some(deadline))
    }

    fn read_stopped_registers_inner(
        &mut self,
        epoch: &StopEpoch,
        registers: Vec<RegisterName>,
        deadline: Option<Instant>,
    ) -> Result<Vec<RegisterValue>> {
        self.require_stop_epoch(epoch)?;
        if registers.is_empty() {
            bail!("stopped register read requires at least one register");
        }
        for (index, name) in registers.iter().enumerate() {
            if registers[..index].contains(name) {
                bail!("stopped register names must be distinct");
            }
        }
        let active = self
            .active_provider
            .context("the stopped session has no active VP provider")?;
        let max = self.providers[active].max_registers_per_request;
        let read_all = |provider: &mut P| -> Result<Vec<RegisterValue>> {
            let mut values = Vec::with_capacity(registers.len());
            for batch in registers.chunks(max) {
                values.extend(match deadline {
                    Some(deadline) => provider.read_registers_until(batch.to_vec(), deadline)?,
                    None => provider.read_registers(batch.to_vec())?,
                });
            }
            Ok(values)
        };
        let first = read_all(&mut self.providers[active].provider)?;
        let second = read_all(&mut self.providers[active].provider)?;
        let wrong_order = |values: &[RegisterValue]| {
            values.len() != registers.len()
                || values
                    .iter()
                    .zip(&registers)
                    .any(|(value, expected)| value.name != *expected)
        };
        if wrong_order(&first) || wrong_order(&second) {
            bail!("provider returned stopped registers in the wrong order");
        }
        if let Some(value) = first.iter().chain(&second).find(|value| value.status != 0) {
            bail!(
                "provider returned status {:#x} for {:?}",
                value.status,
                value.name
            );
        }
        if first != second {
            bail!("VTL1 registers changed while the dispatcher event was held");
        }
        Ok(first)
    }

    #[cfg(test)]
    fn test_provider(&self) -> &P {
        &self.providers[0].provider
    }

    /// Pause the dispatcher, save the original VTL1 state, and install the selected debug-register
    /// slots. Redirect mode moves RIP to its single guarded instruction; natural mode leaves RIP
    /// untouched.
    pub(crate) fn arm(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        breakpoints: Vec<BreakpointGuard>,
        mode: ArmMode,
    ) -> Result<StopEpoch> {
        self.require_running_unarmed()?;
        validate_breakpoints(&breakpoints, mode)?;
        if self.allow_transition_cr3 && mode != ArmMode::Natural {
            bail!("transition CR3 control requires natural arm mode");
        }
        if mode == ArmMode::Redirect && self.providers.len() != 1 {
            bail!("redirect arming requires exactly one VP provider");
        }
        let next_epoch = self.next_epoch("running")?;
        self.state = State::Arming;
        // Recovery must know whether RIP is controller-owned even if a later arm write fails.
        self.arm_mode = Some(mode);
        if let Err(error) = self.arm_inner(dispatcher, &breakpoints, mode) {
            return Err(self.enter_fault(dispatcher, error, None));
        }
        self.breakpoints = breakpoints;
        self.expected_stop = Some(ExpectedStop::Hardware);
        self.state = State::Running;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vm_id = %self.providers[0].target.vm_id,
            vp = self.providers[0].target.vp,
            mode = ?mode,
            breakpoint_count = self.breakpoints.len(),
            "live Secure Kernel control armed VTL1 execution breakpoints"
        );
        Ok(self.commit_epoch(next_epoch))
    }

    fn arm_inner(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        breakpoints: &[BreakpointGuard],
        mode: ArmMode,
    ) -> Result<()> {
        self.begin_dispatcher_arm(dispatcher, breakpoints)?;
        for index in 0..self.providers.len() {
            self.providers[index].provider.begin_arm()?;
            self.providers[index].provider_phase = ProviderPhase::Arming;
            self.arm_provider(index, breakpoints, mode)?;
            self.providers[index].provider.finish_arm()?;
            self.providers[index].provider_phase = ProviderPhase::Running;
        }
        dispatcher.finish_arm()?;
        Ok(())
    }

    fn arm_provider(
        &mut self,
        index: usize,
        breakpoints: &[BreakpointGuard],
        mode: ArmMode,
    ) -> Result<()> {
        self.providers[index].observed_cr3 = None;
        let baseline = self.read_snapshot(index, self.providers[index].target.expected_cr3.0)?;
        if baseline.low(RegisterName::Dr7)? & DR7_ENABLE_MASK != 0 {
            bail!("the guest already has an enabled hardware breakpoint");
        }
        self.providers[index].baseline = Some(baseline.clone());

        let original_dr7 = baseline.low(RegisterName::Dr7)?;
        let original_rflags = baseline.low(RegisterName::Rflags)?;
        if mode == ArmMode::Natural && original_rflags & (TF | RF) != 0 {
            bail!("natural-flow arming requires TF and RF to be clear in the saved state");
        }
        let owned_enable_mask = breakpoints
            .iter()
            .fold(0, |mask, breakpoint| mask | breakpoint.enable_mask());
        let owned_kind_mask = breakpoints
            .iter()
            .fold(0, |mask, breakpoint| mask | breakpoint.kind_mask());
        let armed_dr7 = (original_dr7 & !(DR7_ENABLE_MASK | owned_kind_mask)) | owned_enable_mask;
        self.write_one(
            index,
            RegisterName::Dr7,
            original_dr7,
            original_dr7 & !DR7_ENABLE_MASK,
        )?;
        for breakpoint in breakpoints {
            let register = breakpoint.register();
            self.write_one(
                index,
                register,
                baseline.low(register)?,
                breakpoint.instruction.address.0,
            )?;
        }
        self.write_one(
            index,
            RegisterName::Dr6,
            baseline.low(RegisterName::Dr6)?,
            baseline.low(RegisterName::Dr6)? & !DR6_CAUSE_MASK,
        )?;
        if mode == ArmMode::Redirect {
            let instruction = &breakpoints[0].instruction;
            self.write_one(
                index,
                RegisterName::Rip,
                baseline.low(RegisterName::Rip)?,
                instruction.address.0,
            )?;
            self.write_one(
                index,
                RegisterName::Rflags,
                original_rflags,
                original_rflags & !(TF | RF),
            )?;
        }
        self.write_one(
            index,
            RegisterName::Dr7,
            original_dr7 & !DR7_ENABLE_MASK,
            armed_dr7,
        )?;
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
        let next_epoch = self.next_epoch("stopped")?;
        let expected_stop = self
            .expected_stop
            .clone()
            .context("the armed session has no expected stop")?;
        let expected_instructions = match &expected_stop {
            ExpectedStop::Hardware => self
                .breakpoints
                .iter()
                .map(|breakpoint| breakpoint.instruction.clone())
                .collect::<Vec<_>>(),
            ExpectedStop::SingleStep { instruction, .. } => vec![instruction.clone()],
        };
        let targets = match &expected_stop {
            ExpectedStop::Hardware => self.targets(),
            ExpectedStop::SingleStep { .. } => {
                let Some(active) = self.active_provider else {
                    return Err(self.enter_fault(
                        dispatcher,
                        anyhow!("a single-step wait has no active VP provider"),
                        None,
                    ));
                };
                vec![self.providers[active].target.clone()]
            }
        };
        let observed = match dispatcher.wait_for_stop(&targets, &expected_instructions) {
            Ok(observed) => observed,
            Err(error) => return Err(self.enter_fault(dispatcher, error, None)),
        };
        let Some(active) = self
            .providers
            .iter()
            .position(|provider| provider.target.vp == observed.event.vp)
        else {
            return Err(self.enter_fault(
                dispatcher,
                anyhow!("the dispatcher returned an event for an unbound VP"),
                Some(observed.event),
            ));
        };
        self.active_provider = Some(active);
        if let Err(error) = self.validate_observation(active, &observed, &expected_stop) {
            return Err(self.enter_fault(dispatcher, error, Some(observed.event)));
        }
        let pause_deadline = dispatcher.retained_pause_deadline();
        for provider in &mut self.providers {
            provider.provider.set_outer_deadline(pause_deadline);
        }
        let result = (|| {
            if pause_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                bail!("the absolute Secure Kernel pause bound expired while accepting the stop");
            }
            self.providers[active]
                .provider
                .publish_stop(observed.event.clone())?;
            self.providers[active].provider_phase = ProviderPhase::Stopped;
            let echoed = self.providers[active].provider.held_event()?;
            if echoed != observed.event {
                bail!("provider changed the dispatcher event after publication");
            }
            self.restore_inactive_providers(active)?;
            let first =
                if matches!(expected_stop, ExpectedStop::Hardware) && self.allow_transition_cr3 {
                    self.read_transition_snapshot(active)?
                } else {
                    let required = match &expected_stop {
                        ExpectedStop::Hardware => self.providers[active].target.expected_cr3.0,
                        ExpectedStop::SingleStep { cr3, .. } => cr3.0,
                    };
                    self.read_snapshot(active, required)?
                };
            let stop_cr3 = first.low(RegisterName::Cr3)?;
            self.providers[active].observed_cr3 = Some(stop_cr3);
            let second = self.read_snapshot(active, stop_cr3)?;
            if first != second {
                bail!("VTL1 registers changed while the dispatcher event was held");
            }
            match pause_deadline {
                Some(deadline) => dispatcher.bind_stop_cr3_until(stop_cr3, deadline)?,
                None => dispatcher.bind_stop_cr3(stop_cr3)?,
            }
            if self.allow_transition_cr3 {
                for instruction in &expected_instructions {
                    match pause_deadline {
                        Some(deadline) => {
                            dispatcher.verify_instruction_until(instruction, deadline)?
                        }
                        None => dispatcher.verify_instruction(instruction)?,
                    }
                }
            }
            let (reason, instruction, expected_rips) =
                self.validate_stop_registers(&observed.event, &first, &expected_stop)?;
            let mut event = observed.event.clone();
            event.reason = reason;
            Ok(StopRecord {
                epoch: next_epoch.1.clone(),
                target: self.providers[active].target.clone(),
                event,
                registers: first,
                instruction,
                expected_rips,
                arm_mode: self.arm_mode.context("the armed session has no arm mode")?,
            })
        })();
        for provider in &mut self.providers {
            provider.provider.set_outer_deadline(None);
        }
        match result {
            Ok(stop) => {
                self.dispatcher_event = Some(observed.event);
                self.expected_stop = None;
                self.commit_epoch(next_epoch);
                self.state = State::Stopped(stop.clone());
                tracing::info!(
                    target: "windbg_mcp::secure_kernel_mutation",
                    vm_id = %stop.target.vm_id,
                    vp = stop.target.vp,
                    reason = ?stop.event.reason,
                    "live Secure Kernel control retained a VTL1 stop"
                );
                Ok(stop)
            }
            Err(error) => Err(self.enter_fault(dispatcher, error, Some(observed.event))),
        }
    }

    /// Consume an owned stop and arm one architectural trap-flag step. The first step can reuse
    /// the hardware-breakpoint guard. Every later step must name and prove the instruction at the
    /// current RIP. A caller may admit a bounded destination set for a branch.
    #[cfg(test)]
    pub(crate) fn step(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        epoch: &StopEpoch,
        guard: StepGuard,
    ) -> Result<StopEpoch> {
        self.step_inner(dispatcher, epoch, guard, None)
    }

    pub(crate) fn step_until(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        epoch: &StopEpoch,
        guard: StepGuard,
        deadline: Instant,
    ) -> Result<StopEpoch> {
        self.step_inner(dispatcher, epoch, guard, Some(deadline))
    }

    fn step_inner(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        epoch: &StopEpoch,
        guard: StepGuard,
        deadline: Option<Instant>,
    ) -> Result<StopEpoch> {
        let stop = self.require_stop_epoch(epoch)?.clone();
        let (instruction, expected_rips) = guard.resolve(&stop)?;
        // This read has no target-side effect. A bad caller guard leaves the current stop and
        // epoch intact so it can be corrected or continued safely.
        match deadline {
            Some(deadline) => dispatcher.verify_instruction_until(&instruction, deadline)?,
            None => dispatcher.verify_instruction(&instruction)?,
        }
        let next_epoch = self.next_epoch("running")?;
        let dispatcher_event = self
            .dispatcher_event
            .clone()
            .context("the stopped session has no dispatcher event")?;
        let active = self
            .active_provider
            .context("the stopped session has no active VP provider")?;
        let recovery_deadline = dispatcher.retained_recovery_deadline().or(deadline);
        self.providers[active].provider.set_outer_deadline(deadline);
        self.state = State::Releasing;
        let result = (|| {
            let baseline = self.providers[active]
                .baseline
                .clone()
                .context("the stopped session has no baseline")?;
            let dr6 = stop.registers.low(RegisterName::Dr6)?;
            let rflags = stop.registers.low(RegisterName::Rflags)?;
            self.write_one(
                active,
                RegisterName::Dr7,
                stop.registers.low(RegisterName::Dr7)?,
                baseline.low(RegisterName::Dr7)? & !DR7_ENABLE_MASK,
            )?;
            for register in [
                RegisterName::Dr0,
                RegisterName::Dr1,
                RegisterName::Dr2,
                RegisterName::Dr3,
            ] {
                self.write_one(
                    active,
                    register,
                    stop.registers.low(register)?,
                    baseline.low(register)?,
                )?;
            }
            self.write_one(active, RegisterName::Dr6, dr6, dr6 & !DR6_CAUSE_MASK)?;
            self.write_one(active, RegisterName::Rflags, rflags, (rflags | TF) & !RF)?;
            self.providers[active].provider.release()?;
            self.providers[active].provider_phase = ProviderPhase::Running;
            match deadline {
                Some(deadline) => dispatcher.release_event_until(
                    &dispatcher_event,
                    ReleaseMode::ArmNextStop,
                    deadline,
                )?,
                None => dispatcher.release_event(&dispatcher_event, ReleaseMode::ArmNextStop)?,
            }
            Ok(())
        })();
        self.providers[active].provider.set_outer_deadline(None);
        if let Err(error) = result {
            return Err(self.enter_fault_inner(
                dispatcher,
                error,
                Some(dispatcher_event),
                recovery_deadline,
            ));
        }
        self.dispatcher_event = None;
        self.expected_stop = Some(ExpectedStop::SingleStep {
            instruction,
            expected_rips,
            cr3: HexU64(stop.registers.low(RegisterName::Cr3)?),
        });
        self.state = State::Running;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vm_id = %self.providers[active].target.vm_id,
            vp = self.providers[active].target.vp,
            "live Secure Kernel control armed trap-flag single-step"
        );
        Ok(self.commit_epoch(next_epoch))
    }

    /// Restore the complete writable baseline and release the exact event once.
    pub(crate) fn continue_from(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        epoch: &StopEpoch,
    ) -> Result<StopEpoch> {
        self.continue_from_inner(dispatcher, epoch, None)
    }

    pub(crate) fn continue_from_until(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        epoch: &StopEpoch,
        deadline: Instant,
    ) -> Result<StopEpoch> {
        self.continue_from_inner(dispatcher, epoch, Some(deadline))
    }

    fn continue_from_inner(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        epoch: &StopEpoch,
        deadline: Option<Instant>,
    ) -> Result<StopEpoch> {
        self.require_stop_epoch(epoch)?;
        let next_epoch = self.next_epoch("running")?;
        let dispatcher_event = self
            .dispatcher_event
            .clone()
            .context("the stopped session has no dispatcher event")?;
        let active = self
            .active_provider
            .context("the stopped session has no active VP provider")?;
        let recovery_deadline = dispatcher.retained_recovery_deadline().or(deadline);
        self.providers[active].provider.set_outer_deadline(deadline);
        self.state = State::Releasing;
        let result = (|| {
            self.restore_owned_state(active)?;
            self.providers[active].provider.release()?;
            self.providers[active].provider_phase = ProviderPhase::Running;
            match deadline {
                Some(deadline) => dispatcher.release_event_until(
                    &dispatcher_event,
                    ReleaseMode::Resume,
                    deadline,
                )?,
                None => dispatcher.release_event(&dispatcher_event, ReleaseMode::Resume)?,
            }
            Ok(())
        })();
        if let Err(error) = result {
            let error = self.enter_fault_inner(
                dispatcher,
                error,
                Some(dispatcher_event),
                recovery_deadline,
            );
            self.providers[active].provider.set_outer_deadline(None);
            return Err(error);
        }
        self.providers[active].provider.set_outer_deadline(None);
        self.providers[active].baseline = None;
        self.providers[active].observed_cr3 = None;
        self.active_provider = None;
        self.breakpoints.clear();
        self.arm_mode = None;
        self.dispatcher_event = None;
        self.expected_stop = None;
        self.state = State::Running;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vm_id = %self.providers[active].target.vm_id,
            vp = self.providers[active].target.vp,
            "live Secure Kernel control restored the VTL1 baseline and resumed"
        );
        Ok(self.commit_epoch(next_epoch))
    }

    /// Resume an owned stop with a replacement set of execute breakpoints already installed.
    ///
    /// This is the debugger-loop transition: restoring the prior arm and releasing the event before
    /// installing its successor creates a race in which the guest can pass the requested address.
    /// The held event keeps the VP quiesced while the old owned state is restored and the new set is
    /// written, then the dispatcher begins waiting for the next vector-1 event as it releases this
    /// one.
    #[cfg(test)]
    pub(crate) fn continue_to_breakpoints(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        epoch: &StopEpoch,
        breakpoints: Vec<BreakpointGuard>,
    ) -> Result<StopEpoch> {
        self.continue_to_breakpoints_inner(dispatcher, epoch, breakpoints, None)
    }

    pub(crate) fn continue_to_breakpoints_until(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        epoch: &StopEpoch,
        breakpoints: Vec<BreakpointGuard>,
        deadline: Instant,
    ) -> Result<StopEpoch> {
        self.continue_to_breakpoints_inner(dispatcher, epoch, breakpoints, Some(deadline))
    }

    fn continue_to_breakpoints_inner(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        epoch: &StopEpoch,
        breakpoints: Vec<BreakpointGuard>,
        deadline: Option<Instant>,
    ) -> Result<StopEpoch> {
        validate_breakpoints(&breakpoints, ArmMode::Natural)?;
        self.require_stop_epoch(epoch)?;
        // Verification is read-only and precedes the releasing state. A stale breakpoint guard
        // therefore leaves the exact stop and epoch available for correction.
        for breakpoint in &breakpoints {
            match deadline {
                Some(deadline) => {
                    dispatcher.verify_instruction_until(&breakpoint.instruction, deadline)?
                }
                None => dispatcher.verify_instruction(&breakpoint.instruction)?,
            }
        }
        let next_epoch = self.next_epoch("running")?;
        let dispatcher_event = self
            .dispatcher_event
            .clone()
            .context("the stopped session has no dispatcher event")?;
        let active = self
            .active_provider
            .context("the stopped session has no active VP provider")?;
        let recovery_deadline = dispatcher.retained_recovery_deadline().or(deadline);
        self.providers[active].provider.set_outer_deadline(deadline);
        self.state = State::Releasing;
        let result = (|| {
            self.restore_owned_state(active)?;
            let baseline = self.providers[active]
                .baseline
                .clone()
                .context("the stopped session has no saved baseline")?;
            let flags = baseline.low(RegisterName::Rflags)?;
            if flags & (TF | RF) != 0 {
                bail!("continuing to breakpoints requires the saved TF and RF to be clear");
            }
            let original_dr7 = baseline.low(RegisterName::Dr7)?;
            let owned_enable_mask = breakpoints
                .iter()
                .fold(0, |mask, breakpoint| mask | breakpoint.enable_mask());
            let owned_kind_mask = breakpoints
                .iter()
                .fold(0, |mask, breakpoint| mask | breakpoint.kind_mask());
            for breakpoint in &breakpoints {
                let register = breakpoint.register();
                self.write_one(
                    active,
                    register,
                    baseline.low(register)?,
                    breakpoint.instruction.address.0,
                )?;
            }
            self.write_one(
                active,
                RegisterName::Dr6,
                baseline.low(RegisterName::Dr6)?,
                baseline.low(RegisterName::Dr6)? & !DR6_CAUSE_MASK,
            )?;
            self.write_one(
                active,
                RegisterName::Dr7,
                original_dr7,
                (original_dr7 & !(DR7_ENABLE_MASK | owned_kind_mask)) | owned_enable_mask,
            )?;
            self.providers[active].provider.release()?;
            self.providers[active].provider_phase = ProviderPhase::Running;
            match deadline {
                Some(deadline) => dispatcher.release_event_until(
                    &dispatcher_event,
                    ReleaseMode::ArmNextStop,
                    deadline,
                )?,
                None => dispatcher.release_event(&dispatcher_event, ReleaseMode::ArmNextStop)?,
            }
            Ok(())
        })();
        self.providers[active].provider.set_outer_deadline(None);
        if let Err(error) = result {
            return Err(self.enter_fault_inner(
                dispatcher,
                error,
                Some(dispatcher_event),
                recovery_deadline,
            ));
        }
        self.active_provider = None;
        self.breakpoints = breakpoints;
        self.arm_mode = Some(ArmMode::Natural);
        self.dispatcher_event = None;
        self.expected_stop = Some(ExpectedStop::Hardware);
        self.state = State::Running;
        Ok(self.commit_epoch(next_epoch))
    }

    /// Restore or release anything this session still owns, then remove the handler and detach.
    pub(crate) fn close(&mut self, dispatcher: &mut impl EventDispatcher) -> Result<()> {
        self.close_inner(dispatcher, None)
    }

    pub(crate) fn close_until(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        deadline: Instant,
    ) -> Result<()> {
        self.close_inner(dispatcher, Some(deadline))
    }

    fn close_inner(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        deadline: Option<Instant>,
    ) -> Result<()> {
        match self.state.clone() {
            State::Closed => return Ok(()),
            State::Faulted => {
                let cause = self
                    .fault
                    .as_ref()
                    .context("the faulted session has no fault record")?
                    .cause
                    .clone();
                let teardown = match deadline {
                    Some(deadline) => dispatcher.teardown_until(deadline),
                    None => dispatcher.teardown(),
                };
                if let Err(error) = teardown {
                    bail!(
                        "the terminal live-control fault remains and teardown failed: {cause}; {error:#}"
                    );
                }
                self.state = State::Closed;
                return Ok(());
            }
            State::Stopped(stop) => match deadline {
                Some(deadline) => {
                    self.continue_from_until(dispatcher, &stop.epoch, deadline)?;
                }
                None => {
                    self.continue_from(dispatcher, &stop.epoch)?;
                }
            },
            State::Running
                if self
                    .providers
                    .iter()
                    .any(|provider| provider.baseline.is_some()) =>
            {
                self.state = State::Arming;
                let result = (|| {
                    if self.breakpoints.is_empty() {
                        bail!("the armed session has no breakpoint guards");
                    }
                    dispatcher.begin_disarm(&self.targets())?;
                    if !dispatcher.provider_writes_quiesced() {
                        bail!("the dispatcher did not prove quiescence for disarming providers");
                    }
                    for index in 0..self.providers.len() {
                        if self.providers[index].baseline.is_none() {
                            continue;
                        }
                        self.providers[index].provider.begin_arm()?;
                        self.providers[index].provider_phase = ProviderPhase::Arming;
                        self.restore_owned_state(index)?;
                        self.providers[index].provider.finish_arm()?;
                        self.providers[index].provider_phase = ProviderPhase::Running;
                    }
                    dispatcher.finish_arm()?;
                    Ok(())
                })();
                if let Err(error) = result {
                    return Err(self.enter_fault_inner(dispatcher, error, None, deadline));
                }
                for provider in &mut self.providers {
                    provider.baseline = None;
                }
                self.active_provider = None;
                self.breakpoints.clear();
                self.arm_mode = None;
                self.dispatcher_event = None;
                self.expected_stop = None;
                self.state = State::Running;
            }
            State::Running => {}
            State::Arming | State::Releasing => {
                return Err(self.enter_fault_inner(
                    dispatcher,
                    anyhow!("close observed an incomplete control transition"),
                    None,
                    deadline,
                ));
            }
        }
        let teardown = match deadline {
            Some(deadline) => dispatcher.teardown_until(deadline),
            None => dispatcher.teardown(),
        };
        if let Err(error) = teardown {
            return Err(self.enter_fault_inner(dispatcher, error, None, deadline));
        }
        self.state = State::Closed;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vm_id = %self.providers[0].target.vm_id,
            vp = self.providers[0].target.vp,
            "live Secure Kernel control completed guarded teardown"
        );
        Ok(())
    }

    fn validate_observation(
        &self,
        provider: usize,
        observed: &ObservedStop,
        expected_stop: &ExpectedStop,
    ) -> Result<()> {
        observed.event.validate(&self.providers[provider].target)?;
        if Some(observed.event.dispatcher_context) != self.dispatcher_context {
            bail!("the dispatcher event context does not match the registered handler");
        }
        let expected_instructions = match expected_stop {
            ExpectedStop::Hardware => self
                .breakpoints
                .iter()
                .map(|breakpoint| breakpoint.instruction.clone())
                .collect::<Vec<_>>(),
            ExpectedStop::SingleStep { instruction, .. } => vec![instruction.clone()],
        };
        if observed.instructions != expected_instructions {
            bail!("a guarded instruction changed before the stop was accepted");
        }
        if observed.event.reason != StopReason::DebugException {
            bail!("the dispatcher classified a vector-1 event before register validation");
        }
        Ok(())
    }

    fn validate_stop_registers(
        &self,
        event: &HeldEvent,
        registers: &RegisterSnapshot,
        expected_stop: &ExpectedStop,
    ) -> Result<(StopReason, InstructionGuard, Vec<HexU64>)> {
        if registers.low(RegisterName::Cs)? & 3 != u64::from(event.cpl) {
            bail!("the held event CPL does not match the provider's CS register");
        }
        if event.reason != StopReason::DebugException {
            bail!("the held dispatcher event is not an unclassified debug exception");
        }
        match expected_stop {
            ExpectedStop::Hardware => {
                let causes = registers.low(RegisterName::Dr6)? & 0xf;
                if causes.count_ones() != 1 {
                    bail!("hardware-stop DR6 must name exactly one breakpoint slot");
                }
                let slot = causes.trailing_zeros() as u8;
                let breakpoint = self
                    .breakpoints
                    .iter()
                    .find(|breakpoint| breakpoint.slot == slot)
                    .with_context(|| {
                        format!("DR6 named unowned hardware breakpoint slot {slot}")
                    })?;
                if registers.low(RegisterName::Rip)? != breakpoint.instruction.address.0
                    || registers.low(breakpoint.register())? != breakpoint.instruction.address.0
                    || registers.low(RegisterName::Dr7)? & breakpoint.enable_mask() == 0
                {
                    bail!("slot-{slot} stop register evidence does not match the armed breakpoint");
                }
                Ok((
                    StopReason::HardwareBreakpoint { slot },
                    breakpoint.instruction.clone(),
                    vec![breakpoint.instruction.address],
                ))
            }
            ExpectedStop::SingleStep {
                instruction,
                expected_rips,
                ..
            } => {
                if !expected_rips.contains(&HexU64(registers.low(RegisterName::Rip)?))
                    || registers.low(RegisterName::Dr6)? & (1 << 14) == 0
                    || registers.low(RegisterName::Dr6)? & 0xf != 0
                    || registers.low(RegisterName::Rflags)? & TF == 0
                    || registers.low(RegisterName::Rflags)? & RF != 0
                {
                    bail!(
                        "single-step register evidence does not carry the allowed RIP, DR6.BS, TF, and clear RF"
                    );
                }
                Ok((
                    StopReason::SingleStep,
                    instruction.clone(),
                    expected_rips.clone(),
                ))
            }
        }
    }

    fn targets(&self) -> Vec<TargetIdentity> {
        self.providers
            .iter()
            .map(|provider| provider.target.clone())
            .collect()
    }

    fn read_snapshot(&mut self, provider: usize, expected_cr3: u64) -> Result<RegisterSnapshot> {
        RegisterSnapshot::from_values(
            self.providers[provider]
                .provider
                .read_registers(SNAPSHOT_REGISTERS.to_vec())?,
            Some(expected_cr3),
            self.allow_transition_cr3,
        )
    }

    fn read_transition_snapshot(&mut self, provider: usize) -> Result<RegisterSnapshot> {
        RegisterSnapshot::from_values(
            self.providers[provider]
                .provider
                .read_registers(SNAPSHOT_REGISTERS.to_vec())?,
            None,
            self.allow_transition_cr3,
        )
    }

    fn provider_cr3(&self, provider: usize) -> u64 {
        self.providers[provider]
            .observed_cr3
            .unwrap_or(self.providers[provider].target.expected_cr3.0)
    }

    fn begin_dispatcher_arm(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        breakpoints: &[BreakpointGuard],
    ) -> Result<()> {
        let context = dispatcher.begin_arm(&self.targets(), breakpoints)?;
        if !dispatcher.provider_writes_quiesced() {
            bail!("the dispatcher did not prove quiescence for provider writes");
        }
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

    fn write_one(
        &mut self,
        provider: usize,
        name: RegisterName,
        expected: u64,
        value: u64,
    ) -> Result<()> {
        let written = self.providers[provider]
            .provider
            .write_registers(vec![RegisterWrite {
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
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vm_id = %self.providers[provider].target.vm_id,
            vp = self.providers[provider].target.vp,
            register = ?name,
            expected = format_args!("{expected:#x}"),
            value = format_args!("{value:#x}"),
            "live Secure Kernel control verified a VTL1 register mutation"
        );
        Ok(())
    }

    fn restore_owned_state(&mut self, provider: usize) -> Result<()> {
        match self.arm_mode.context("there is no saved arm mode")? {
            ArmMode::Redirect => self.restore_redirect_baseline(provider),
            ArmMode::Natural => self.restore_natural_control(provider),
        }
    }

    fn restore_redirect_baseline(&mut self, provider: usize) -> Result<()> {
        let baseline = self.providers[provider]
            .baseline
            .clone()
            .context("there is no saved VTL1 baseline")?;
        let cr3 = self.provider_cr3(provider);
        let current = self.read_snapshot(provider, cr3)?;
        let current_dr7 = current.low(RegisterName::Dr7)?;
        self.write_one(
            provider,
            RegisterName::Dr7,
            current_dr7,
            current_dr7 & !DR7_ENABLE_MASK,
        )?;
        for name in [
            RegisterName::Rflags,
            RegisterName::Rip,
            RegisterName::Rsp,
            RegisterName::Dr0,
            RegisterName::Dr1,
            RegisterName::Dr2,
            RegisterName::Dr3,
            RegisterName::Dr6,
        ] {
            self.write_one(provider, name, current.low(name)?, baseline.low(name)?)?;
        }
        let disabled_dr7 = self.read_snapshot(provider, cr3)?.low(RegisterName::Dr7)?;
        self.write_one(
            provider,
            RegisterName::Dr7,
            disabled_dr7,
            baseline.low(RegisterName::Dr7)?,
        )?;
        let restored = self.read_snapshot(provider, cr3)?;
        if restored != baseline {
            bail!("restored VTL1 state does not match the saved baseline");
        }
        Ok(())
    }

    /// Natural-flow execution is real guest progress. Restore only state this controller owns;
    /// rewinding RIP, RSP, or ordinary flags would replay work the guest already performed.
    fn restore_natural_control(&mut self, provider: usize) -> Result<()> {
        let baseline = self.providers[provider]
            .baseline
            .clone()
            .context("there is no saved VTL1 baseline")?;
        let cr3 = self.provider_cr3(provider);
        let mut current = self.read_snapshot(provider, cr3)?;
        let current_dr7 = current.low(RegisterName::Dr7)?;
        self.write_one(
            provider,
            RegisterName::Dr7,
            current_dr7,
            current_dr7 & !DR7_ENABLE_MASK,
        )?;
        current = self.read_snapshot(provider, cr3)?;
        let current_flags = current.low(RegisterName::Rflags)?;
        let restored_flags =
            (current_flags & !(TF | RF)) | (baseline.low(RegisterName::Rflags)? & (TF | RF));
        self.write_one(
            provider,
            RegisterName::Rflags,
            current_flags,
            restored_flags,
        )?;
        for name in [
            RegisterName::Dr0,
            RegisterName::Dr1,
            RegisterName::Dr2,
            RegisterName::Dr3,
            RegisterName::Dr6,
        ] {
            let expected = self.read_snapshot(provider, cr3)?.low(name)?;
            self.write_one(provider, name, expected, baseline.low(name)?)?;
        }
        let disabled_dr7 = self.read_snapshot(provider, cr3)?.low(RegisterName::Dr7)?;
        self.write_one(
            provider,
            RegisterName::Dr7,
            disabled_dr7,
            baseline.low(RegisterName::Dr7)?,
        )?;

        let restored = self.read_snapshot(provider, cr3)?;
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

    /// Once one VP owns the native event, remove this arm from every other selected VP before the
    /// stop is exposed. That leaves the held VP as the only possible source of the following TF
    /// event and prevents an ordinary scheduler decision from racing a second breakpoint hit.
    fn restore_inactive_providers(&mut self, active: usize) -> Result<()> {
        for provider in 0..self.providers.len() {
            if provider == active || self.providers[provider].baseline.is_none() {
                continue;
            }
            self.providers[provider].provider.begin_arm()?;
            self.providers[provider].provider_phase = ProviderPhase::Arming;
            self.restore_owned_state(provider)?;
            self.providers[provider].provider.finish_arm()?;
            self.providers[provider].provider_phase = ProviderPhase::Running;
            self.providers[provider].baseline = None;
        }
        Ok(())
    }

    fn require_running_unarmed(&self) -> Result<()> {
        if !matches!(self.state, State::Running) {
            bail!("arming requires running state");
        }
        if self
            .providers
            .iter()
            .any(|provider| provider.baseline.is_some())
            || !self.breakpoints.is_empty()
            || self.expected_stop.is_some()
            || self.dispatcher_event.is_some()
        {
            bail!("the session already owns a breakpoint");
        }
        Ok(())
    }

    fn next_epoch(&self, phase: &str) -> Result<(u64, StopEpoch)> {
        let serial = self
            .epoch_serial
            .checked_add(1)
            .context("the live-control epoch counter overflowed")?;
        Ok((
            serial,
            StopEpoch::new(format!(
                "control-{}-{phase}-{serial:016x}",
                self.epoch_nonce
            ))?,
        ))
    }

    fn commit_epoch(&mut self, next: (u64, StopEpoch)) -> StopEpoch {
        self.epoch_serial = next.0;
        self.public_epoch = next.1;
        self.public_epoch.clone()
    }

    fn require_stop_epoch(&self, epoch: &StopEpoch) -> Result<&StopRecord> {
        let State::Stopped(stop) = &self.state else {
            bail!("operation requires a stopped session");
        };
        if &stop.epoch != epoch || &self.public_epoch != epoch {
            bail!("the supplied stop epoch is stale");
        }
        let active = self
            .active_provider
            .context("the stopped session has no active VP provider")?;
        if self.providers[active].provider_phase != ProviderPhase::Stopped {
            bail!("the active provider is not stopped");
        }
        Ok(stop)
    }

    fn enter_fault(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        cause: anyhow::Error,
        event: Option<HeldEvent>,
    ) -> anyhow::Error {
        let deadline = dispatcher.retained_recovery_deadline();
        self.enter_fault_inner(dispatcher, cause, event, deadline)
    }

    fn enter_fault_inner(
        &mut self,
        dispatcher: &mut impl EventDispatcher,
        cause: anyhow::Error,
        event: Option<HeldEvent>,
        deadline: Option<Instant>,
    ) -> anyhow::Error {
        let mut recovery_errors = Vec::new();
        for provider in &mut self.providers {
            provider.provider.set_outer_deadline(deadline);
        }
        let owns_provider_state = self
            .providers
            .iter()
            .any(|provider| provider.baseline.is_some());
        let mut safe_to_resume = !owns_provider_state || dispatcher.provider_writes_quiesced();
        if owns_provider_state && !safe_to_resume {
            let recovery_targets = self
                .providers
                .iter()
                .filter(|provider| provider.baseline.is_some())
                .map(|provider| provider.target.clone())
                .collect::<Vec<_>>();
            let recovery_pause = match deadline {
                Some(deadline) => {
                    dispatcher.establish_recovery_pause_until(&recovery_targets, deadline)
                }
                None => dispatcher.establish_recovery_pause(&recovery_targets),
            };
            if let Err(error) = recovery_pause {
                recovery_errors.push(format!(
                    "establish provider-write quiescence for VTL1 recovery: {error:#}"
                ));
            }
            safe_to_resume = dispatcher.provider_writes_quiesced();
        }
        if owns_provider_state && !safe_to_resume {
            recovery_errors.push(
                "skipped VTL1 baseline restoration because provider-write quiescence was not proved"
                    .to_string(),
            );
        }

        if safe_to_resume {
            for provider in 0..self.providers.len() {
                if self.providers[provider].baseline.is_none() {
                    continue;
                }
                let entered_arm = match self.providers[provider].provider_phase {
                    ProviderPhase::Running => match self.providers[provider].provider.begin_arm() {
                        Ok(()) => {
                            self.providers[provider].provider_phase = ProviderPhase::Arming;
                            true
                        }
                        Err(error) => {
                            recovery_errors.push(format!(
                                "begin VP {} recovery arm: {error:#}",
                                self.providers[provider].target.vp
                            ));
                            false
                        }
                    },
                    ProviderPhase::Arming | ProviderPhase::Stopped => true,
                };
                if !entered_arm {
                    safe_to_resume = false;
                    continue;
                }
                if let Err(error) = self.restore_owned_state(provider) {
                    safe_to_resume = false;
                    recovery_errors.push(format!(
                        "restore VP {} VTL1 baseline: {error:#}",
                        self.providers[provider].target.vp
                    ));
                }
            }
        }

        if safe_to_resume {
            for provider in 0..self.providers.len() {
                let transition = match self.providers[provider].provider_phase {
                    ProviderPhase::Arming => self.providers[provider].provider.finish_arm(),
                    ProviderPhase::Stopped => self.providers[provider].provider.release(),
                    ProviderPhase::Running => Ok(()),
                };
                match transition {
                    Ok(()) => self.providers[provider].provider_phase = ProviderPhase::Running,
                    Err(error) => {
                        safe_to_resume = false;
                        recovery_errors.push(format!(
                            "return VP {} provider to running: {error:#}",
                            self.providers[provider].target.vp
                        ));
                    }
                }
            }
        }

        let owned_event = event.as_ref().filter(|event| {
            self.providers.iter().any(|provider| {
                event.validate(&provider.target).is_ok()
                    && Some(event.dispatcher_context) == self.dispatcher_context
            })
        });
        let dispatcher_safe = safe_to_resume && (event.is_none() || owned_event.is_some());
        let dispatcher_recovery = match deadline {
            Some(deadline) => dispatcher.recover_until(
                dispatcher_safe,
                owned_event.filter(|_| dispatcher_safe),
                deadline,
            ),
            None => dispatcher.recover(dispatcher_safe, owned_event.filter(|_| dispatcher_safe)),
        };
        let dispatcher_recovered = if let Err(error) = dispatcher_recovery {
            recovery_errors.push(format!("dispatcher recovery: {error:#}"));
            false
        } else {
            true
        };
        for provider in &mut self.providers {
            provider.provider.set_outer_deadline(None);
        }
        let fault = FaultRecord {
            cause: format!("{cause:#}"),
            recovery_errors,
            target_left_paused: !dispatcher_safe || !dispatcher_recovered,
        };
        self.fault = Some(fault.clone());
        self.state = State::Faulted;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vm_id = %self.providers[0].target.vm_id,
            vp = self.providers[0].target.vp,
            target_left_paused = fault.target_left_paused,
            recovery_errors = fault.recovery_errors.len(),
            "live Secure Kernel control entered fail-closed recovery"
        );
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

    #[test]
    fn natural_guest_execution_is_the_default_arm_mode() {
        assert_eq!(ArmMode::default(), ArmMode::Natural);
    }
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
        capabilities: Capabilities,
        epoch: StopEpoch,
        serial: u64,
        phase: FakePhase,
        held: Option<HeldEvent>,
        registers: Vec<RegisterValue>,
        hardware_rip: u64,
        hardware_slot: Option<u8>,
        single_step_rips: VecDeque<u64>,
        unstable_once: bool,
        fail_reads_while_stopped: Option<&'static str>,
        wrong_cr3_while_stopped: bool,
        read_requests: Vec<Vec<RegisterName>>,
        outer_deadline: Option<Instant>,
        deadline_updates: Vec<Option<Instant>>,
        write_deadlines: Vec<Option<Instant>>,
        release_deadlines: Vec<Option<Instant>>,
    }

    impl FakeProvider {
        fn new() -> Self {
            Self {
                target: target(),
                capabilities: capabilities(),
                epoch: epoch("running", 0),
                serial: 0,
                phase: FakePhase::Running,
                held: None,
                registers: register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46),
                hardware_rip: TARGET_RIP,
                hardware_slot: None,
                single_step_rips: VecDeque::new(),
                unstable_once: false,
                fail_reads_while_stopped: None,
                wrong_cr3_while_stopped: false,
                read_requests: Vec::new(),
                outer_deadline: None,
                deadline_updates: Vec::new(),
                write_deadlines: Vec::new(),
                release_deadlines: Vec::new(),
            }
        }

        fn with_hardware_rip(mut self, rip: u64) -> Self {
            self.hardware_rip = rip;
            self
        }

        fn with_hardware_slot(mut self, slot: u8) -> Self {
            self.hardware_slot = Some(slot);
            self
        }

        fn with_vp(mut self, vp: u32) -> Self {
            self.target.vp = vp;
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

        fn with_readable_registers(mut self, registers: &[RegisterName]) -> Self {
            for (index, name) in registers.iter().enumerate() {
                if !self.capabilities.readable_registers.contains(name) {
                    self.capabilities.readable_registers.push(*name);
                }
                if !self.registers.iter().any(|value| value.name == *name) {
                    self.registers.push(RegisterValue {
                        name: *name,
                        status: 0,
                        low: HexU64(index as u64 + 1),
                        high: HexU64(0),
                    });
                }
            }
            self
        }

        fn rotate(&mut self, phase: &str) {
            self.serial += 1;
            self.epoch = epoch(phase, self.serial);
        }

        fn set_stop(&mut self) {
            let rflags = self
                .registers
                .iter()
                .find(|register| register.name == RegisterName::Rflags)
                .unwrap()
                .low
                .0;
            let (rip, dr6) = if rflags & TF != 0 {
                (
                    self.single_step_rips
                        .pop_front()
                        .unwrap_or(self.hardware_rip + 5),
                    0xffff_4ff0,
                )
            } else {
                let dr7 = self
                    .registers
                    .iter()
                    .find(|register| register.name == RegisterName::Dr7)
                    .unwrap()
                    .low
                    .0;
                let slot = self.hardware_slot.map(usize::from).unwrap_or_else(|| {
                    (0..4)
                        .find(|slot| dr7 & (1 << (slot * 2)) != 0)
                        .expect("a scripted hardware stop has an enabled slot")
                });
                assert!(
                    dr7 & (1 << (slot * 2)) != 0,
                    "a scripted hardware stop must select an enabled slot"
                );
                let register = [
                    RegisterName::Dr0,
                    RegisterName::Dr1,
                    RegisterName::Dr2,
                    RegisterName::Dr3,
                ][slot];
                let rip = self
                    .registers
                    .iter()
                    .find(|value| value.name == register)
                    .unwrap()
                    .low
                    .0;
                (rip, 0xffff_0ff0 | (1 << slot))
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

        fn capabilities(&mut self) -> Result<Capabilities> {
            Ok(self.capabilities.clone())
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
            self.set_stop();
            self.held = Some(event);
            self.phase = FakePhase::Stopped;
            self.rotate("stopped");
            Ok(())
        }

        fn held_event(&mut self) -> Result<HeldEvent> {
            self.held.clone().context("no held event")
        }

        fn read_registers(&mut self, registers: Vec<RegisterName>) -> Result<Vec<RegisterValue>> {
            if registers.len() > usize::from(self.capabilities.max_registers_per_request) {
                bail!("register request exceeds scripted provider maximum");
            }
            self.read_requests.push(registers.clone());
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
            self.write_deadlines.push(self.outer_deadline);
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
            self.release_deadlines.push(self.outer_deadline);
            if self.phase != FakePhase::Stopped {
                bail!("not stopped");
            }
            self.phase = FakePhase::Running;
            self.held = None;
            self.rotate("running");
            Ok(())
        }

        fn set_outer_deadline(&mut self, deadline: Option<Instant>) {
            self.outer_deadline = deadline;
            self.deadline_updates.push(deadline);
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Action {
        BeginArm,
        BeginDisarm,
        FinishArm,
        Verify(InstructionGuard),
        Wait,
        EstablishRecoveryPause,
        Release(ReleaseMode),
        Recover { safe: bool, owned_event: bool },
        Teardown,
    }

    struct FakeDispatcher {
        stops: VecDeque<ObservedStop>,
        actions: Vec<Action>,
        wait_targets: Vec<Vec<u32>>,
        bound_cr3s: Vec<u64>,
        verification_roots: Vec<Option<u64>>,
        current_root: Option<u64>,
        fail_release: bool,
        fail_begin: Option<&'static str>,
        fail_wait: Option<&'static str>,
        fail_wait_quiesced: bool,
        fail_recovery_pause: Option<&'static str>,
        provider_writes_quiesced: bool,
        fail_recover: Option<&'static str>,
        fail_teardown: Option<&'static str>,
        fail_verify: Option<&'static str>,
        release_deadlines: Vec<Option<Instant>>,
        retained_recovery_deadline: Option<Instant>,
        recovery_deadlines: Vec<Option<Instant>>,
        teardown_deadlines: Vec<Option<Instant>>,
    }

    impl FakeDispatcher {
        fn new(stops: impl IntoIterator<Item = ObservedStop>) -> Self {
            Self {
                stops: stops.into_iter().collect(),
                actions: Vec::new(),
                wait_targets: Vec::new(),
                bound_cr3s: Vec::new(),
                verification_roots: Vec::new(),
                current_root: None,
                fail_release: false,
                fail_begin: None,
                fail_wait: None,
                fail_wait_quiesced: true,
                fail_recovery_pause: None,
                provider_writes_quiesced: false,
                fail_recover: None,
                fail_teardown: None,
                fail_verify: None,
                release_deadlines: Vec::new(),
                retained_recovery_deadline: None,
                recovery_deadlines: Vec::new(),
                teardown_deadlines: Vec::new(),
            }
        }
    }

    impl EventDispatcher for FakeDispatcher {
        fn begin_arm(
            &mut self,
            _targets: &[TargetIdentity],
            _breakpoints: &[BreakpointGuard],
        ) -> Result<HexU64> {
            self.actions.push(Action::BeginArm);
            self.provider_writes_quiesced = true;
            if let Some(reason) = self.fail_begin {
                bail!("{reason}");
            }
            Ok(HexU64(0x2000_0000_1000))
        }

        fn begin_disarm(&mut self, _targets: &[TargetIdentity]) -> Result<()> {
            self.actions.push(Action::BeginDisarm);
            self.provider_writes_quiesced = true;
            if let Some(reason) = self.fail_begin {
                bail!("{reason}");
            }
            Ok(())
        }

        fn finish_arm(&mut self) -> Result<()> {
            self.actions.push(Action::FinishArm);
            Ok(())
        }

        fn provider_writes_quiesced(&self) -> bool {
            self.provider_writes_quiesced
        }

        fn establish_recovery_pause(&mut self, _targets: &[TargetIdentity]) -> Result<()> {
            self.actions.push(Action::EstablishRecoveryPause);
            self.provider_writes_quiesced = false;
            if let Some(reason) = self.fail_recovery_pause {
                bail!("{reason}");
            }
            self.provider_writes_quiesced = true;
            Ok(())
        }

        fn verify_instruction(&mut self, instruction: &InstructionGuard) -> Result<()> {
            self.actions.push(Action::Verify(instruction.clone()));
            self.verification_roots.push(self.current_root);
            if let Some(reason) = self.fail_verify {
                bail!("{reason}");
            }
            Ok(())
        }

        fn retained_recovery_deadline(&self) -> Option<Instant> {
            self.retained_recovery_deadline
        }

        fn wait_for_stop(
            &mut self,
            targets: &[TargetIdentity],
            _instructions: &[InstructionGuard],
        ) -> Result<ObservedStop> {
            self.actions.push(Action::Wait);
            self.wait_targets
                .push(targets.iter().map(|target| target.vp).collect());
            if let Some(reason) = self.fail_wait {
                self.provider_writes_quiesced = self.fail_wait_quiesced;
                bail!("{reason}");
            }
            self.provider_writes_quiesced = true;
            self.stops.pop_front().context("no scripted stop")
        }

        fn bind_stop_cr3(&mut self, cr3: u64) -> Result<()> {
            self.bound_cr3s.push(cr3);
            self.current_root = Some(cr3);
            Ok(())
        }

        fn release_event(&mut self, _event: &HeldEvent, mode: ReleaseMode) -> Result<()> {
            self.release_deadlines.push(None);
            self.actions.push(Action::Release(mode));
            if self.fail_release {
                bail!("scripted native completion failure");
            }
            if mode == ReleaseMode::Resume {
                self.provider_writes_quiesced = false;
            }
            Ok(())
        }

        fn release_event_until(
            &mut self,
            _event: &HeldEvent,
            mode: ReleaseMode,
            deadline: Instant,
        ) -> Result<()> {
            self.release_deadlines.push(Some(deadline));
            self.actions.push(Action::Release(mode));
            if self.fail_release {
                bail!("scripted native completion failure");
            }
            if mode == ReleaseMode::Resume {
                self.provider_writes_quiesced = false;
            }
            Ok(())
        }

        fn recover(&mut self, safe_to_resume: bool, event: Option<&HeldEvent>) -> Result<()> {
            self.recovery_deadlines.push(None);
            self.recover_inner(safe_to_resume, event)
        }

        fn recover_until(
            &mut self,
            safe_to_resume: bool,
            event: Option<&HeldEvent>,
            deadline: Instant,
        ) -> Result<()> {
            self.recovery_deadlines.push(Some(deadline));
            self.recover_inner(safe_to_resume, event)
        }

        fn teardown(&mut self) -> Result<()> {
            self.teardown_deadlines.push(None);
            self.teardown_inner()
        }

        fn teardown_until(&mut self, deadline: Instant) -> Result<()> {
            self.teardown_deadlines.push(Some(deadline));
            self.teardown_inner()
        }
    }

    impl FakeDispatcher {
        fn teardown_inner(&mut self) -> Result<()> {
            self.actions.push(Action::Teardown);
            if let Some(reason) = self.fail_teardown {
                bail!("{reason}");
            }
            Ok(())
        }
    }

    impl FakeDispatcher {
        fn recover_inner(&mut self, safe_to_resume: bool, event: Option<&HeldEvent>) -> Result<()> {
            self.actions.push(Action::Recover {
                safe: safe_to_resume,
                owned_event: event.is_some(),
            });
            if let Some(reason) = self.fail_recover {
                bail!("{reason}");
            }
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
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
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
            control.test_provider().registers,
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
    fn bounded_resume_keeps_the_deadline_on_provider_writes_and_release() {
        let replacement = InstructionGuard {
            address: HexU64(TARGET_RIP + 0x20),
            bytes: vec![0x90],
        };
        let mut dispatcher = FakeDispatcher::new([
            observed(StopReason::HardwareBreakpoint { slot: 0 }),
            observed(StopReason::SingleStep),
        ]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let hardware = control.wait_for_stop(&mut dispatcher).unwrap();

        let step_writes = control.test_provider().write_deadlines.len();
        let step_releases = control.test_provider().release_deadlines.len();
        let step_deadline = Instant::now() + std::time::Duration::from_secs(1);
        control
            .step_until(
                &mut dispatcher,
                &hardware.epoch,
                straight_step(),
                step_deadline,
            )
            .unwrap();
        let provider = control.test_provider();
        assert!(
            provider.write_deadlines[step_writes..]
                .iter()
                .all(|deadline| *deadline == Some(step_deadline))
        );
        assert_eq!(
            provider.release_deadlines[step_releases..],
            [Some(step_deadline)]
        );
        assert_eq!(provider.outer_deadline, None);
        assert_eq!(dispatcher.release_deadlines, [Some(step_deadline)]);

        let stepped = control.wait_for_stop(&mut dispatcher).unwrap();
        let continue_writes = control.test_provider().write_deadlines.len();
        let continue_releases = control.test_provider().release_deadlines.len();
        let continue_deadline = Instant::now() + std::time::Duration::from_secs(1);
        control
            .continue_to_breakpoints_until(
                &mut dispatcher,
                &stepped.epoch,
                vec![BreakpointGuard {
                    slot: 2,
                    instruction: replacement,
                }],
                continue_deadline,
            )
            .unwrap();
        let provider = control.test_provider();
        assert!(
            provider.write_deadlines[continue_writes..]
                .iter()
                .all(|deadline| *deadline == Some(continue_deadline))
        );
        assert_eq!(
            provider.release_deadlines[continue_releases..],
            [Some(continue_deadline)]
        );
        assert_eq!(provider.outer_deadline, None);
        assert_eq!(provider.deadline_updates.last(), Some(&None));
        assert_eq!(
            dispatcher.release_deadlines,
            [Some(step_deadline), Some(continue_deadline)]
        );
    }

    #[test]
    fn a_completed_cycle_can_arm_the_same_session_again() {
        let mut dispatcher = FakeDispatcher::new([
            observed(StopReason::HardwareBreakpoint { slot: 0 }),
            observed(StopReason::HardwareBreakpoint { slot: 0 }),
        ]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();

        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let first = control.wait_for_stop(&mut dispatcher).unwrap();
        control
            .continue_from(&mut dispatcher, &first.epoch)
            .unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let second = control.wait_for_stop(&mut dispatcher).unwrap();

        assert_eq!(
            second.event.reason,
            StopReason::HardwareBreakpoint { slot: 0 }
        );
        assert_eq!(
            dispatcher.actions,
            vec![
                Action::BeginArm,
                Action::FinishArm,
                Action::Wait,
                Action::Release(ReleaseMode::Resume),
                Action::BeginArm,
                Action::FinishArm,
                Action::Wait,
            ]
        );
    }

    #[test]
    fn a_held_stop_installs_replacement_breakpoints_before_release() {
        let replacement = InstructionGuard {
            address: HexU64(TARGET_RIP + 0x20),
            bytes: vec![0x90],
        };
        let mut dispatcher = FakeDispatcher::new([
            observed(StopReason::HardwareBreakpoint { slot: 0 }),
            ObservedStop {
                event: event(StopReason::DebugException),
                instructions: vec![replacement.clone()],
            },
        ]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let first = control.wait_for_stop(&mut dispatcher).unwrap();

        control
            .continue_to_breakpoints(
                &mut dispatcher,
                &first.epoch,
                vec![BreakpointGuard {
                    slot: 2,
                    instruction: replacement,
                }],
            )
            .unwrap();
        assert_eq!(control.phase(), LivePhase::Running);
        let provider = control.test_provider();
        assert_eq!(
            provider
                .registers
                .iter()
                .find(|value| value.name == RegisterName::Dr2)
                .unwrap()
                .low,
            HexU64(TARGET_RIP + 0x20)
        );
        assert_ne!(
            provider
                .registers
                .iter()
                .find(|value| value.name == RegisterName::Dr7)
                .unwrap()
                .low
                .0
                & (1 << 4),
            0
        );

        let second = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(
            second.event.reason,
            StopReason::HardwareBreakpoint { slot: 2 }
        );
        assert_eq!(second.arm_mode, ArmMode::Natural);
        control
            .continue_from(&mut dispatcher, &second.epoch)
            .unwrap();
        assert_eq!(
            dispatcher.actions,
            vec![
                Action::BeginArm,
                Action::FinishArm,
                Action::Wait,
                Action::Verify(InstructionGuard {
                    address: HexU64(TARGET_RIP + 0x20),
                    bytes: vec![0x90],
                }),
                Action::Release(ReleaseMode::ArmNextStop),
                Action::Wait,
                Action::Release(ReleaseMode::Resume),
            ]
        );
    }

    #[test]
    fn replacement_breakpoint_verification_failure_preserves_the_held_stop() {
        let replacement = InstructionGuard {
            address: HexU64(TARGET_RIP + 0x20),
            bytes: vec![0x90],
        };
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let stop = control.wait_for_stop(&mut dispatcher).unwrap();
        dispatcher.fail_verify = Some("replacement bytes changed");

        let error = control
            .continue_to_breakpoints(
                &mut dispatcher,
                &stop.epoch,
                vec![BreakpointGuard {
                    slot: 2,
                    instruction: replacement.clone(),
                }],
            )
            .unwrap_err();

        assert!(error.to_string().contains("replacement bytes changed"));
        assert_eq!(control.phase(), LivePhase::Stopped);
        assert_eq!(control.stopped().unwrap().epoch, stop.epoch);
        assert_eq!(control.test_provider().phase, FakePhase::Stopped);
        assert_eq!(
            dispatcher.actions.last(),
            Some(&Action::Verify(replacement))
        );
        assert!(
            !dispatcher
                .actions
                .iter()
                .any(|action| matches!(action, Action::Release(_)))
        );
    }

    #[test]
    fn stopped_register_reads_are_batched_to_the_provider_limit() {
        let registers = [
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
            RegisterName::Ds,
            RegisterName::Es,
            RegisterName::Fs,
            RegisterName::Gs,
            RegisterName::Ss,
        ];
        let provider = FakeProvider::new().with_readable_registers(&registers);
        let mut control = LiveControl::open(provider).unwrap();
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let stop = control.wait_for_stop(&mut dispatcher).unwrap();

        let values = control
            .read_stopped_registers(&stop.epoch, registers.to_vec())
            .unwrap();

        assert_eq!(
            values.iter().map(|value| value.name).collect::<Vec<_>>(),
            registers
        );
        let requests = &control.test_provider().read_requests;
        assert_eq!(
            requests[requests.len() - 4..]
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            [12, 8, 12, 8]
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
                event: event(StopReason::DebugException),
                instructions: vec![natural.clone()],
            },
            ObservedStop {
                event: event(StopReason::DebugException),
                instructions: vec![natural.clone()],
            },
        ]);
        let provider = FakeProvider::new().with_hardware_rip(BASE_RIP);
        let mut control = LiveControl::open(provider).unwrap();

        control
            .arm(
                &mut dispatcher,
                vec![BreakpointGuard {
                    slot: 0,
                    instruction: natural,
                }],
                ArmMode::Natural,
            )
            .unwrap();
        assert_eq!(
            control.test_provider().registers[0].low.0,
            BASE_RIP,
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
            control.test_provider().registers[0].low.0,
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
                    .test_provider()
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
    fn natural_flow_arms_multiple_slots_and_reports_the_exact_hit() {
        let first = InstructionGuard {
            address: HexU64(TARGET_RIP),
            bytes: vec![0x90],
        };
        let second = InstructionGuard {
            address: HexU64(TARGET_RIP + 0x20),
            bytes: vec![0xcc],
        };
        let breakpoints = vec![
            BreakpointGuard {
                slot: 1,
                instruction: first.clone(),
            },
            BreakpointGuard {
                slot: 3,
                instruction: second.clone(),
            },
        ];
        let mut dispatcher = FakeDispatcher::new([ObservedStop {
            event: event(StopReason::DebugException),
            instructions: vec![first.clone(), second],
        }]);
        let mut control = LiveControl::open(FakeProvider::new().with_hardware_slot(3)).unwrap();

        control
            .arm(&mut dispatcher, breakpoints, ArmMode::Natural)
            .unwrap();
        let stopped = control.wait_for_stop(&mut dispatcher).unwrap();

        assert_eq!(
            stopped.event.reason,
            StopReason::HardwareBreakpoint { slot: 3 }
        );
        assert_eq!(stopped.instruction.address, HexU64(TARGET_RIP + 0x20));
        control
            .continue_from(&mut dispatcher, &stopped.epoch)
            .unwrap();
        assert_eq!(
            control
                .test_provider()
                .registers
                .iter()
                .find(|register| register.name == RegisterName::Rip)
                .unwrap()
                .low,
            HexU64(TARGET_RIP + 0x20)
        );
        for register in [
            RegisterName::Dr0,
            RegisterName::Dr1,
            RegisterName::Dr2,
            RegisterName::Dr3,
            RegisterName::Dr6,
            RegisterName::Dr7,
        ] {
            assert_eq!(
                control
                    .test_provider()
                    .registers
                    .iter()
                    .find(|value| value.name == register),
                register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46)
                    .iter()
                    .find(|value| value.name == register)
            );
        }
    }

    #[test]
    fn natural_flow_accepts_the_first_selected_vp_and_disarms_the_rest() {
        let mut vp1_hardware = event(StopReason::DebugException);
        vp1_hardware.vp = 1;
        let mut vp1_step = event(StopReason::DebugException);
        vp1_step.vp = 1;
        let mut dispatcher = FakeDispatcher::new([
            ObservedStop {
                event: vp1_hardware,
                instructions: vec![instruction()],
            },
            ObservedStop {
                event: vp1_step,
                instructions: vec![instruction()],
            },
        ]);
        let mut control =
            LiveControl::open_many(vec![FakeProvider::new(), FakeProvider::new().with_vp(1)])
                .unwrap();

        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Natural)
            .unwrap();
        let stopped = control.wait_for_stop(&mut dispatcher).unwrap();

        assert_eq!(stopped.target.vp, 1);
        assert_eq!(control.active_provider, Some(1));
        assert!(control.providers[0].baseline.is_none());
        assert_eq!(
            control.providers[0].provider.registers,
            register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46)
        );
        control
            .step(&mut dispatcher, &stopped.epoch, straight_step())
            .unwrap();
        let stepped = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(dispatcher.wait_targets, vec![vec![0, 1], vec![1]]);
        control
            .continue_from(&mut dispatcher, &stepped.epoch)
            .unwrap();
        assert!(control.providers.iter().all(|provider| {
            provider.baseline.is_none() && provider.provider.phase == FakePhase::Running
        }));
    }

    #[test]
    fn controller_epochs_cannot_be_reused_when_a_different_vp_wins() {
        let vp0 = ObservedStop {
            event: event(StopReason::DebugException),
            instructions: vec![instruction()],
        };
        let mut vp1_event = event(StopReason::DebugException);
        vp1_event.vp = 1;
        let vp1 = ObservedStop {
            event: vp1_event,
            instructions: vec![instruction()],
        };
        let mut dispatcher = FakeDispatcher::new([vp0, vp1]);
        let mut control =
            LiveControl::open_many(vec![FakeProvider::new(), FakeProvider::new().with_vp(1)])
                .unwrap();

        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Natural)
            .unwrap();
        let first = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(first.target.vp, 0);
        assert_ne!(first.epoch, control.providers[0].provider.epoch);
        control
            .continue_from(&mut dispatcher, &first.epoch)
            .unwrap();

        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Natural)
            .unwrap();
        let second = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(second.target.vp, 1);
        assert_ne!(second.epoch, first.epoch);
        assert_ne!(second.epoch, control.providers[1].provider.epoch);

        let error = control
            .continue_from(&mut dispatcher, &first.epoch)
            .unwrap_err();
        assert!(error.to_string().contains("stale"), "{error:#}");
        assert_eq!(control.stopped().unwrap().epoch, second.epoch);
        control
            .continue_from(&mut dispatcher, &second.epoch)
            .unwrap();
    }

    #[test]
    fn controller_epochs_are_unique_across_concurrent_live_sessions() {
        let mut first_dispatcher = FakeDispatcher::new([observed(StopReason::DebugException)]);
        let mut second_dispatcher = FakeDispatcher::new([observed(StopReason::DebugException)]);
        let mut first = LiveControl::open(FakeProvider::new()).unwrap();
        let mut second = LiveControl::open(FakeProvider::new()).unwrap();

        first
            .arm(&mut first_dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        second
            .arm(&mut second_dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let first_stop = first.wait_for_stop(&mut first_dispatcher).unwrap();
        let second_stop = second.wait_for_stop(&mut second_dispatcher).unwrap();

        assert_ne!(first.epoch_nonce, second.epoch_nonce);
        assert_ne!(first_stop.epoch, second_stop.epoch);
        first
            .continue_from(&mut first_dispatcher, &first_stop.epoch)
            .unwrap();
        second
            .continue_from(&mut second_dispatcher, &second_stop.epoch)
            .unwrap();
    }

    #[test]
    fn provider_set_rejects_duplicate_vps_and_mismatched_vm_identity() {
        let duplicate = LiveControl::open_many(vec![FakeProvider::new(), FakeProvider::new()])
            .err()
            .unwrap();
        assert!(duplicate.to_string().contains("distinct"), "{duplicate:#}");

        let mut mismatched = FakeProvider::new().with_vp(1);
        mismatched.target.expected_cr3.0 += 0x1000;
        let mismatch = LiveControl::open_many(vec![FakeProvider::new(), mismatched])
            .err()
            .unwrap();
        assert!(mismatch.to_string().contains("one VM"), "{mismatch:#}");

        let too_many = (0..=MAX_LIVE_CONTROL_VPS)
            .map(|vp| FakeProvider::new().with_vp(vp as u32))
            .collect();
        let excessive = LiveControl::open_many(too_many).err().unwrap();
        assert!(
            excessive.to_string().contains("at most 16"),
            "{excessive:#}"
        );
    }

    #[test]
    fn multi_vp_timeout_repauses_and_restores_every_provider_before_resuming() {
        let baseline = register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46);
        let mut dispatcher = FakeDispatcher::new([]);
        dispatcher.fail_wait = Some("dispatcher wait timed out");
        dispatcher.fail_wait_quiesced = false;
        let mut control =
            LiveControl::open_many(vec![FakeProvider::new(), FakeProvider::new().with_vp(1)])
                .unwrap();

        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Natural)
            .unwrap();
        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();

        assert!(error.to_string().contains("timed out"), "{error:#}");
        assert!(!control.fault().unwrap().target_left_paused);
        assert!(control.providers.iter().all(|provider| {
            provider.provider.phase == FakePhase::Running && provider.provider.registers == baseline
        }));
        assert!(dispatcher.actions.ends_with(&[
            Action::EstablishRecoveryPause,
            Action::Recover {
                safe: true,
                owned_event: false,
            },
        ]));
    }

    #[test]
    fn failed_pause_barrier_contains_without_touching_losing_vps() {
        let mut dispatcher = FakeDispatcher::new([]);
        dispatcher.fail_wait = Some("Suspend-VM timed out after the winning intercept");
        dispatcher.fail_wait_quiesced = false;
        dispatcher.fail_recovery_pause = Some("recovery Suspend-VM timed out");
        let mut control =
            LiveControl::open_many(vec![FakeProvider::new(), FakeProvider::new().with_vp(1)])
                .unwrap();

        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Natural)
            .unwrap();
        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();

        assert!(error.to_string().contains("Suspend-VM"), "{error:#}");
        assert!(control.fault().unwrap().target_left_paused);
        assert!(
            control
                .fault()
                .unwrap()
                .recovery_errors
                .iter()
                .any(|error| error.contains("recovery Suspend-VM timed out"))
        );
        assert!(
            control
                .fault()
                .unwrap()
                .recovery_errors
                .iter()
                .any(|error| {
                    error.contains("baseline restoration")
                        && error.contains("quiescence was not proved")
                })
        );
        assert!(control.providers.iter().all(|provider| {
            provider.provider.phase == FakePhase::Running
                && provider.provider.serial == 2
                && provider.baseline.is_some()
                && provider
                    .provider
                    .registers
                    .iter()
                    .find(|register| register.name == RegisterName::Dr7)
                    .unwrap()
                    .low
                    .0
                    & DR7_ENABLE_MASK
                    != 0
        }));
        assert_eq!(
            dispatcher.actions.last(),
            Some(&Action::Recover {
                safe: false,
                owned_event: false,
            })
        );
    }

    #[test]
    fn breakpoint_set_rejects_duplicate_slots_and_redirect_fanout() {
        let first = BreakpointGuard {
            slot: 2,
            instruction: instruction(),
        };
        let mut second = first.clone();
        second.instruction.address.0 += 0x20;
        assert!(
            validate_breakpoints(&[first.clone(), second.clone()], ArmMode::Natural)
                .unwrap_err()
                .to_string()
                .contains("distinct")
        );
        second.slot = 3;
        assert!(
            validate_breakpoints(&[first, second], ArmMode::Redirect)
                .unwrap_err()
                .to_string()
                .contains("exactly one")
        );
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
                event: event(StopReason::DebugException),
                instructions: vec![branch.clone()],
            },
        ]);
        let provider = FakeProvider::new().with_single_step_rips([TARGET_RIP + 5, branch_target.0]);
        let mut control = LiveControl::open(provider).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
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
            .arm(&mut dispatcher, breakpoints(), ArmMode::Natural)
            .unwrap_err();
        assert!(error.to_string().contains("TF and RF"), "{error:#}");
        assert_eq!(control.phase(), LivePhase::Faulted);
    }

    #[test]
    fn changed_instruction_faults_and_restores_before_completing_the_owned_event() {
        let mut changed = instruction();
        changed.bytes[0] ^= 1;
        let mut dispatcher = FakeDispatcher::new([ObservedStop {
            event: event(StopReason::DebugException),
            instructions: vec![changed],
        }]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();

        assert!(error.to_string().contains("guarded instruction changed"));
        assert_eq!(control.phase(), LivePhase::Faulted);
        assert_eq!(
            control.test_provider().registers,
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
        let mut unrelated = event(StopReason::DebugException);
        unrelated.dispatcher_context = HexU64(0x2000_0000_2000);
        let mut dispatcher = FakeDispatcher::new([ObservedStop {
            event: unrelated,
            instructions: vec![instruction()],
        }]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
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
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();

        assert!(error.to_string().contains("changed while"));
        assert_eq!(control.phase(), LivePhase::Faulted);
        assert_eq!(
            control.test_provider().registers,
            register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46)
        );
    }

    #[test]
    fn native_completion_failure_uses_the_reserved_recovery_deadline() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        dispatcher.fail_release = true;
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let stopped = control.wait_for_stop(&mut dispatcher).unwrap();
        let service_deadline = Instant::now() + std::time::Duration::from_secs(1);
        let recovery_deadline = Instant::now() + std::time::Duration::from_secs(2);
        dispatcher.retained_recovery_deadline = Some(recovery_deadline);
        let error = control
            .continue_from_until(&mut dispatcher, &stopped.epoch, service_deadline)
            .unwrap_err();

        assert!(error.to_string().contains("native completion failure"));
        assert_eq!(control.phase(), LivePhase::Faulted);
        assert!(!control.fault().unwrap().target_left_paused);
        assert_eq!(dispatcher.release_deadlines, [Some(service_deadline)]);
        assert_eq!(dispatcher.recovery_deadlines, [Some(recovery_deadline)]);
        assert!(
            control
                .test_provider()
                .deadline_updates
                .contains(&Some(recovery_deadline))
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
    fn close_while_stopped_restores_releases_tears_down_and_is_idempotent() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        control.wait_for_stop(&mut dispatcher).unwrap();
        control.close(&mut dispatcher).unwrap();
        control.close(&mut dispatcher).unwrap();

        assert_eq!(control.phase(), LivePhase::Closed);
        assert_eq!(dispatcher.actions.last(), Some(&Action::Teardown));
        assert_eq!(
            control.test_provider().registers,
            register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46)
        );
    }

    #[test]
    fn bounded_close_keeps_one_deadline_through_restoration_and_event_release() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        control.wait_for_stop(&mut dispatcher).unwrap();
        let writes = control.test_provider().write_deadlines.len();
        let releases = control.test_provider().release_deadlines.len();
        let deadline = Instant::now() + std::time::Duration::from_secs(1);

        control.close_until(&mut dispatcher, deadline).unwrap();

        let provider = control.test_provider();
        assert!(
            provider.write_deadlines[writes..]
                .iter()
                .all(|observed| *observed == Some(deadline))
        );
        assert_eq!(provider.release_deadlines[releases..], [Some(deadline)]);
        assert_eq!(provider.outer_deadline, None);
        assert_eq!(dispatcher.release_deadlines, [Some(deadline)]);
        assert_eq!(dispatcher.teardown_deadlines, [Some(deadline)]);
        assert_eq!(control.phase(), LivePhase::Closed);
    }

    #[test]
    fn faulted_close_keeps_the_retained_deadline_through_teardown() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        dispatcher.fail_release = true;
        let recovery_deadline = Instant::now() + std::time::Duration::from_secs(2);
        dispatcher.retained_recovery_deadline = Some(recovery_deadline);
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let stopped = control.wait_for_stop(&mut dispatcher).unwrap();
        control
            .continue_from_until(
                &mut dispatcher,
                &stopped.epoch,
                Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap_err();

        control
            .close_until(&mut dispatcher, recovery_deadline)
            .unwrap();

        assert_eq!(dispatcher.teardown_deadlines, [Some(recovery_deadline)]);
        assert_eq!(control.phase(), LivePhase::Closed);
    }

    #[test]
    fn teardown_failure_keeps_the_close_deadline_through_fault_recovery() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        dispatcher.fail_teardown = Some("handler removal failed");
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        control.wait_for_stop(&mut dispatcher).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(2);

        let error = control.close_until(&mut dispatcher, deadline).unwrap_err();

        assert!(error.to_string().contains("handler removal failed"));
        assert_eq!(dispatcher.teardown_deadlines, [Some(deadline)]);
        assert_eq!(dispatcher.recovery_deadlines.last(), Some(&Some(deadline)));
        assert_eq!(control.phase(), LivePhase::Faulted);
    }

    #[test]
    fn close_while_armed_restores_every_selected_vp_before_teardown() {
        let baseline = register_values(BASE_RIP, 0xffff_0ff0, 0x400, 0x46);
        let mut dispatcher = FakeDispatcher::new([]);
        let mut control =
            LiveControl::open_many(vec![FakeProvider::new(), FakeProvider::new().with_vp(1)])
                .unwrap();

        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Natural)
            .unwrap();
        control.close(&mut dispatcher).unwrap();

        assert_eq!(control.phase(), LivePhase::Closed);
        assert!(control.providers.iter().all(|provider| {
            provider.baseline.is_none()
                && provider.provider.phase == FakePhase::Running
                && provider.provider.registers == baseline
        }));
        assert_eq!(
            dispatcher.actions,
            vec![
                Action::BeginArm,
                Action::FinishArm,
                Action::BeginDisarm,
                Action::FinishArm,
                Action::Teardown,
            ]
        );
    }

    #[test]
    fn dispatcher_timeout_restores_the_baseline_and_resumes_before_faulting() {
        let mut dispatcher = FakeDispatcher::new([]);
        dispatcher.fail_wait = Some("dispatcher wait timed out");
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();

        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error:#}");
        assert_eq!(control.phase(), LivePhase::Faulted);
        assert!(!control.fault().unwrap().target_left_paused);
        assert_eq!(
            control.test_provider().registers,
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
    fn redirect_restoration_preserves_disabled_dr7_kind_bits() {
        let baseline_dr7 = 0x0001_0400;
        let mut provider = FakeProvider::new();
        set_low(&mut provider.registers, RegisterName::Dr7, baseline_dr7);
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        let mut control = LiveControl::open(provider).unwrap();

        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        let stopped = control.wait_for_stop(&mut dispatcher).unwrap();
        control
            .continue_from(&mut dispatcher, &stopped.epoch)
            .unwrap();

        assert_eq!(
            control
                .test_provider()
                .registers
                .iter()
                .find(|register| register.name == RegisterName::Dr7)
                .unwrap()
                .low,
            HexU64(baseline_dr7)
        );
    }

    #[test]
    fn successful_fault_teardown_closes_and_retains_the_fault_record() {
        let mut dispatcher = FakeDispatcher::new([]);
        dispatcher.fail_wait = Some("dispatcher wait timed out");
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        control.wait_for_stop(&mut dispatcher).unwrap_err();
        let fault = control.fault().unwrap().clone();

        control.close(&mut dispatcher).unwrap();
        control.close(&mut dispatcher).unwrap();

        assert_eq!(control.phase(), LivePhase::Closed);
        assert_eq!(control.fault(), Some(&fault));
        assert_eq!(
            dispatcher
                .actions
                .iter()
                .filter(|action| **action == Action::Teardown)
                .count(),
            1
        );
    }

    #[test]
    fn failed_fault_teardown_remains_retryable_until_it_succeeds() {
        let mut dispatcher = FakeDispatcher::new([]);
        dispatcher.fail_wait = Some("dispatcher wait timed out");
        dispatcher.fail_teardown = Some("handler removal failed");
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();
        control.wait_for_stop(&mut dispatcher).unwrap_err();

        let error = control.close(&mut dispatcher).unwrap_err();
        assert!(error.to_string().contains("handler removal failed"));
        assert_eq!(control.phase(), LivePhase::Faulted);

        dispatcher.fail_teardown = None;
        control.close(&mut dispatcher).unwrap();
        assert_eq!(control.phase(), LivePhase::Closed);
    }

    #[test]
    fn provider_death_while_stopped_contains_the_vm_without_native_completion() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        let provider = FakeProvider::new().with_stopped_read_failure("provider pipe closed");
        let mut control = LiveControl::open(provider).unwrap();
        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
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
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
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
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap();

        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();
        assert!(error.to_string().contains("CR3"), "{error:#}");
        assert!(control.fault().unwrap().target_left_paused);
    }

    #[test]
    fn natural_transition_cr3_is_bound_through_step_and_restored_control_state() {
        let mut dispatcher = FakeDispatcher::new([
            observed(StopReason::HardwareBreakpoint { slot: 0 }),
            observed(StopReason::SingleStep),
        ]);
        let mut control =
            LiveControl::open_with_transition(FakeProvider::new().with_stopped_cr3_change(), true)
                .unwrap();
        let redirect = control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap_err();
        assert!(redirect.to_string().contains("natural arm mode"));

        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Natural)
            .unwrap();
        let hardware = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(
            hardware.registers.low(RegisterName::Cr3).unwrap(),
            0xdead_0000
        );
        assert_eq!(dispatcher.verification_roots, [Some(0xdead_0000)]);
        control
            .step(&mut dispatcher, &hardware.epoch, straight_step())
            .unwrap();
        let stepped = control.wait_for_stop(&mut dispatcher).unwrap();
        assert_eq!(
            stepped.registers.low(RegisterName::Cr3).unwrap(),
            0xdead_0000
        );
        control
            .continue_from(&mut dispatcher, &stepped.epoch)
            .unwrap();

        assert_eq!(dispatcher.bound_cr3s, [0xdead_0000, 0xdead_0000]);
        assert_eq!(
            dispatcher.verification_roots,
            [Some(0xdead_0000), Some(0xdead_0000), Some(0xdead_0000)]
        );
        let registers = &control.test_provider().registers;
        for name in [
            RegisterName::Dr0,
            RegisterName::Dr1,
            RegisterName::Dr2,
            RegisterName::Dr3,
        ] {
            assert_eq!(
                registers
                    .iter()
                    .find(|value| value.name == name)
                    .unwrap()
                    .low
                    .0,
                0
            );
        }
        assert_eq!(
            registers
                .iter()
                .find(|value| value.name == RegisterName::Dr7)
                .unwrap()
                .low
                .0,
            0x400
        );
    }

    #[test]
    fn transition_cr3_guard_failure_faults_after_rebinding_the_stop_root() {
        let mut dispatcher =
            FakeDispatcher::new([observed(StopReason::HardwareBreakpoint { slot: 0 })]);
        dispatcher.fail_verify = Some("guard changed in the transition address space");
        let mut control =
            LiveControl::open_with_transition(FakeProvider::new().with_stopped_cr3_change(), true)
                .unwrap();

        control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Natural)
            .unwrap();
        let error = control.wait_for_stop(&mut dispatcher).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("guard changed in the transition address space"),
            "{error:#}"
        );
        assert_eq!(dispatcher.bound_cr3s, [0xdead_0000]);
        assert_eq!(dispatcher.verification_roots, [Some(0xdead_0000)]);
        assert_eq!(control.phase(), LivePhase::Faulted);
    }

    #[test]
    fn build_mismatch_before_provider_mutation_recovers_and_resumes() {
        let mut dispatcher = FakeDispatcher::new([]);
        dispatcher.fail_begin = Some("vmwp SHA-256 does not match the dispatcher profile");
        let mut control = LiveControl::open(FakeProvider::new()).unwrap();

        let error = control
            .arm(&mut dispatcher, breakpoints(), ArmMode::Redirect)
            .unwrap_err();
        assert!(error.to_string().contains("SHA-256"), "{error:#}");
        assert_eq!(control.phase(), LivePhase::Faulted);
        assert!(!control.fault().unwrap().target_left_paused);
        assert_eq!(control.test_provider().phase, FakePhase::Running);
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
    fn dispatcher_profile_catalog_selects_the_current_exact_build() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "windbg-mcp-sk-profile-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let image = directory.join("vmwp.exe");
        std::fs::write(&image, b"current guarded vmwp fixture").unwrap();
        let digest = crate::client::sha256(&std::fs::read(&image).unwrap())
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();

        let mut current = dispatcher_profile();
        current.vmwp_image = image.clone();
        current.vmwp_sha256 = digest;
        let mut stale = current.clone();
        stale.vmwp_sha256 =
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into();
        std::fs::write(
            directory.join("current.json"),
            serde_json::to_vec(&current).unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.join("stale.json"),
            serde_json::to_vec(&stale).unwrap(),
        )
        .unwrap();

        let selected = DispatcherProfile::load(&directory).unwrap();
        assert_eq!(selected, current);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn dispatcher_profile_catalog_bounds_all_directory_entries_while_iterating() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "windbg-mcp-sk-profile-bound-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        for index in 0..=MAX_PROFILE_CATALOG_ENTRIES {
            std::fs::write(directory.join(format!("unrelated-{index:03}.txt")), []).unwrap();
        }

        let error = DispatcherProfile::load(&directory).unwrap_err();

        assert!(
            error.to_string().contains("at most 128 total entries"),
            "{error:#}"
        );
        std::fs::remove_dir_all(directory).unwrap();
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

    #[test]
    fn every_step_front_end_refuses_instructions_that_can_defer_the_trap() {
        let guard = |bytes: &[u8]| InstructionGuard {
            address: HexU64(TARGET_RIP),
            bytes: bytes.to_vec(),
        };
        assert!(validate_step_instruction_class(&guard(&[0x90])).is_ok());
        for bytes in [
            &[0x8e, 0xd0][..],
            &[0x48, 0x0f, 0xb2, 0x20][..],
            &[0xf3, 0xa4][..],
        ] {
            assert!(validate_step_instruction_class(&guard(bytes)).is_err());
        }
    }

    #[test]
    fn dispatcher_discovery_site_is_optional_but_uses_the_same_byte_guards() {
        let profile = dispatcher_profile();
        let mut legacy = serde_json::to_value(&profile).unwrap();
        legacy.as_object_mut().unwrap().remove("discovery");
        let decoded: DispatcherProfile = serde_json::from_value(legacy).unwrap();
        assert!(decoded.discovery.is_none());
        decoded.validate().unwrap();

        let mut discovered = profile.clone();
        discovered.discovery = Some(DispatcherDiscoveryProfile {
            entry: site(0x25000),
            vid_image: r"C:\Windows\System32\vid.dll".into(),
            vid_sha256: "B".repeat(64),
            vid_size_of_image: 0x40000,
        });
        discovered.validate().unwrap();

        discovered.discovery.as_mut().unwrap().entry.rva = discovered.event_held.rva;
        assert!(
            discovered
                .validate()
                .unwrap_err()
                .to_string()
                .contains("overlap")
        );
    }

    #[test]
    fn secure_kernel_initial_site_is_optional_and_image_relative() {
        let profile = dispatcher_profile();
        let mut legacy = serde_json::to_value(&profile).unwrap();
        legacy.as_object_mut().unwrap().remove("secure_kernel_kd");
        let decoded: DispatcherProfile = serde_json::from_value(legacy).unwrap();
        assert!(decoded.secure_kernel_kd.is_none());

        let mut profiled = profile;
        profiled.secure_kernel_kd = Some(SecureKernelKdProfile {
            build: 26_100,
            initial: SecureKernelInitialProfile {
                rva: HexU64(0xb12b),
                original: vec![0x0f, 0x1f, 0x44, 0, 0],
            },
            debugger_data: SecureKernelDebuggerDataProfile {
                list_head_rva: HexU64(0x1335c0),
                block_rva: HexU64(0x1335e0),
                loaded_module_list_rva: HexU64(0x127770),
            },
        });
        profiled.validate().unwrap();

        profiled.secure_kernel_kd.as_mut().unwrap().initial.rva = HexU64(0);
        assert!(
            profiled
                .validate()
                .unwrap_err()
                .to_string()
                .contains("nonzero 32-bit")
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
            discovery: None,
            secure_kernel_kd: None,
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

    fn breakpoints() -> Vec<BreakpointGuard> {
        vec![BreakpointGuard {
            slot: 0,
            instruction: instruction(),
        }]
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

    fn observed(_reason: StopReason) -> ObservedStop {
        ObservedStop {
            event: event(StopReason::DebugException),
            instructions: vec![instruction()],
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
                    _ => 0,
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
