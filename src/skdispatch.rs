//! Build-guarded `vmwp` dispatcher adapter for live Secure Kernel control.
//!
//! This module never constructs a debugger engine. The engine worker lends it the one
//! [`DebugEngine`] created on that worker's engine thread for the duration of an operation. The
//! retained state contains only the exact build profile, the live VTL1 byte source and resources
//! this adapter owns in `vmwp`.
//!
//! The private dispatcher ABI is data, not code: a local profile supplies RVAs, record offsets and
//! original instruction bytes. Every command issued here is a fixed command whose substituted
//! fields have already been validated as numbers. No caller can supply debugger command text.

use std::fmt;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use dbgscope::dbgeng::{
    BreakpointAt, BreakpointKind, BreakpointSpec, DebugEngine, Interruption, RegisterValue,
};

use crate::sk;
use crate::sk::RawSource;
use crate::skcontrol::{HeldEvent, HexU64, StopReason, TargetIdentity};
use crate::sklive::{
    ArmMode, BreakpointGuard, DispatcherProfile, DispatcherSite, EventDispatcher, InstructionGuard,
    LiveControl, LivePhase, LiveTransition, ObservedStop, ReleaseMode, StopRecord,
};

pub(crate) const LIVE_CONTROL_FLAG: &str = "--sk-live-control";

const DEBUG_WAIT: u32 = 60_000;
const NATIVE_SETTLE_WAIT: u32 = 1_000;
const COMPLETION_KICK_AFTER: Duration = Duration::from_secs(12);
const POWERSHELL_WAIT: Duration = Duration::from_secs(60);
const LIVE_MEMORY_WAIT: Duration = Duration::from_secs(60);
const CLEANUP_SETTLE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(20);
const EVENT_TYPE_VECTOR_1: u64 = 0x0100_0002;

/// One complete live-control session. Both halves remain on the worker engine thread; each method
/// creates only a short-lived borrow tying the dispatcher state to that thread's engine.
pub(crate) struct Session {
    control: LiveControl<crate::skcontrol::ControlProcess>,
    dispatcher: VmwpDispatcherState,
}

impl Session {
    pub(crate) fn open(request: &OpenRequest) -> Result<(Self, Vec<String>)> {
        if !request.additional_vps.is_empty() {
            bail!(
                "the build-guarded live adapter currently accepts exactly one selected VP; the \
                 native vmwp dispatcher serializes held callbacks, so multi-provider control \
                 requires a separate release-and-quiesce protocol"
            );
        }
        request.target.validate()?;
        let profile = DispatcherProfile::load(&request.profile)?;
        let dispatcher = VmwpDispatcherState::new(
            profile,
            request.vmwp_pid,
            request.dispatcher_vnd,
            request.live_transport.clone(),
        )?;
        let (provider, skipped) = crate::skcontrol::ControlProcess::spawn(
            &request.control_transport,
            request.target.clone(),
        )?;
        let skipped = skipped
            .into_iter()
            .map(|line| format!("VP {}: {line}", request.target.vp))
            .collect::<Vec<_>>();
        let control = LiveControl::open(provider)?;
        Ok((
            Self {
                control,
                dispatcher,
            },
            skipped,
        ))
    }

    pub(crate) fn phase(&self) -> LivePhase {
        self.control.phase()
    }

    pub(crate) fn stopped(&self) -> Option<&StopRecord> {
        self.control.stopped()
    }

    pub(crate) fn arm(
        &mut self,
        engine: &DebugEngine,
        breakpoints: Vec<BreakpointGuard>,
        mode: ArmMode,
    ) -> Result<LiveTransition> {
        let mut dispatcher = self.dispatcher.bind(engine);
        let epoch = self.control.arm(&mut dispatcher, breakpoints, mode)?;
        Ok(LiveTransition {
            phase: self.control.phase(),
            epoch,
        })
    }

    pub(crate) fn wait_for_stop(&mut self, engine: &DebugEngine) -> Result<StopRecord> {
        let mut dispatcher = self.dispatcher.bind(engine);
        self.control.wait_for_stop(&mut dispatcher)
    }

    pub(crate) fn step(
        &mut self,
        engine: &DebugEngine,
        epoch: &crate::skcontrol::StopEpoch,
        guard: crate::sklive::StepGuard,
    ) -> Result<LiveTransition> {
        let mut dispatcher = self.dispatcher.bind(engine);
        let epoch = self.control.step(&mut dispatcher, epoch, guard)?;
        Ok(LiveTransition {
            phase: self.control.phase(),
            epoch,
        })
    }

    pub(crate) fn continue_from(
        &mut self,
        engine: &DebugEngine,
        epoch: &crate::skcontrol::StopEpoch,
    ) -> Result<LiveTransition> {
        let mut dispatcher = self.dispatcher.bind(engine);
        let epoch = self.control.continue_from(&mut dispatcher, epoch)?;
        Ok(LiveTransition {
            phase: self.control.phase(),
            epoch,
        })
    }

    pub(crate) fn read_memory(&self, address: u64, size: u32) -> Result<LiveMemoryRead> {
        crate::sksession::readable(address, size).map_err(anyhow::Error::msg)?;
        let stop = self
            .control
            .stopped()
            .context("live VTL1 memory can be read only while the session is stopped")?;
        self.dispatcher
            .read_memory(stop.epoch.clone(), address, size)
    }

    pub(crate) fn close(&mut self, engine: &DebugEngine) -> Result<()> {
        let mut dispatcher = self.dispatcher.bind(engine);
        self.control.close(&mut dispatcher)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpenRequest {
    pub(crate) profile: std::path::PathBuf,
    pub(crate) control_transport: String,
    pub(crate) live_transport: String,
    pub(crate) vmwp_pid: u32,
    pub(crate) dispatcher_vnd: u64,
    pub(crate) target: TargetIdentity,
    #[serde(default)]
    pub(crate) additional_vps: Vec<AdditionalVp>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdditionalVp {
    pub(crate) control_transport: String,
    pub(crate) target: TargetIdentity,
}

impl fmt::Debug for OpenRequest {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("OpenRequest")
            .field("profile", &self.profile)
            .field("control_transport", &"<redacted>")
            .field("live_transport", &"<redacted>")
            .field("vmwp_pid", &self.vmwp_pid)
            .field(
                "dispatcher_vnd",
                &format_args!("{:#x}", self.dispatcher_vnd),
            )
            .field("target", &self.target)
            .field("additional_vps", &self.additional_vps.len())
            .finish()
    }
}

/// A stopped VTL1 read, tied to the epoch whose register snapshot it accompanies.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiveMemoryRead {
    pub(crate) epoch: crate::skcontrol::StopEpoch,
    pub(crate) address: HexU64,
    pub(crate) gpa: HexU64,
    pub(crate) requested_size: u32,
    pub(crate) read_size: u32,
    /// Uppercase hexadecimal bytes with no separators.
    pub(crate) data: String,
}

pub(crate) fn render_transition(transition: &LiveTransition) -> String {
    format!(
        "VTL1 control is {:?} at epoch {}.",
        transition.phase, transition.epoch
    )
}

pub(crate) fn render_stop(stop: &StopRecord) -> String {
    let rip = stop
        .registers
        .values
        .iter()
        .find(|value| value.name == crate::skcontrol::RegisterName::Rip)
        .map(|value| value.low.0);
    format!(
        "VTL1 VP {} stopped for {:?}{} at epoch {}. The guarded instruction begins at {:#x}.",
        stop.target.vp,
        stop.event.reason,
        rip.map(|value| format!(" at RIP {value:#x}"))
            .unwrap_or_default(),
        stop.epoch,
        stop.instruction.address.0,
    )
}

pub(crate) fn render_read(read: &LiveMemoryRead) -> String {
    format!(
        "{} byte(s) of stopped VTL1 at {:#x} (physical {:#x}, epoch {})\n{}",
        read.read_size, read.address.0, read.gpa.0, read.epoch, read.data
    )
}

struct AcceptanceRequest {
    open: OpenRequest,
    instruction: InstructionGuard,
    arm_mode: ArmMode,
}

impl AcceptanceRequest {
    fn parse(args: &[String]) -> Result<Self> {
        let mut profile = None;
        let mut control_transport = None;
        let mut live_transport = None;
        let mut vmwp_pid = None;
        let mut dispatcher_vnd = None;
        let mut vm_id = None;
        let mut partition_id = None;
        let mut vp = 0u32;
        let mut expected_cr3 = None;
        let mut instruction_address = None;
        let mut instruction_bytes = None;
        let mut arm_mode = ArmMode::Redirect;
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            let value = |iter: &mut std::slice::Iter<'_, String>| {
                iter.next()
                    .cloned()
                    .with_context(|| format!("{arg} needs a value"))
            };
            match arg.as_str() {
                "--profile" => profile = Some(value(&mut iter)?.into()),
                "--control-transport" => control_transport = Some(value(&mut iter)?),
                "--live-transport" => live_transport = Some(value(&mut iter)?),
                "--vmwp-pid" => {
                    vmwp_pid = Some(value(&mut iter)?.parse().context("invalid --vmwp-pid")?)
                }
                "--dispatcher-vnd" => {
                    dispatcher_vnd = Some(cli_word("dispatcher-vnd", &value(&mut iter)?)?)
                }
                "--vm-id" => vm_id = Some(value(&mut iter)?),
                "--partition-id" => {
                    partition_id = Some(cli_word("partition-id", &value(&mut iter)?)?)
                }
                "--vp" => vp = value(&mut iter)?.parse().context("invalid --vp")?,
                "--expected-cr3" => {
                    expected_cr3 = Some(cli_word("expected-cr3", &value(&mut iter)?)?)
                }
                "--instruction-address" => {
                    instruction_address = Some(cli_word("instruction-address", &value(&mut iter)?)?)
                }
                "--instruction-bytes" => {
                    instruction_bytes = Some(parse_hex_bytes(&value(&mut iter)?)?)
                }
                "--arm-mode" => {
                    arm_mode = match value(&mut iter)?.as_str() {
                        "redirect" => ArmMode::Redirect,
                        "natural" => ArmMode::Natural,
                        other => {
                            bail!("invalid --arm-mode {other:?}; expected redirect or natural")
                        }
                    }
                }
                other => bail!("unknown argument {other:?}\n\n{}", live_control_usage()),
            }
        }
        let target = TargetIdentity {
            vm_id: vm_id.context(live_control_usage())?,
            partition_id: HexU64(partition_id.context(live_control_usage())?),
            vp,
            vtl: 1,
            expected_cr3: HexU64(expected_cr3.context(live_control_usage())?),
        };
        target.validate()?;
        let instruction = InstructionGuard {
            address: HexU64(instruction_address.context(live_control_usage())?),
            bytes: instruction_bytes.context(live_control_usage())?,
        };
        Ok(Self {
            open: OpenRequest {
                profile: profile.context(live_control_usage())?,
                control_transport: control_transport.context(live_control_usage())?,
                live_transport: live_transport.context(live_control_usage())?,
                vmwp_pid: vmwp_pid.context(live_control_usage())?,
                dispatcher_vnd: dispatcher_vnd.context(live_control_usage())?,
                target,
                additional_vps: Vec::new(),
            },
            instruction,
            arm_mode,
        })
    }
}

#[derive(serde::Serialize)]
struct AcceptanceResult {
    schema: &'static str,
    hardware_stop: StopRecord,
    single_step_stop: StopRecord,
    final_phase: LivePhase,
}

pub(crate) fn run_acceptance(args: &[String], engine: &DebugEngine) -> Result<()> {
    let request = AcceptanceRequest::parse(args)?;
    let instruction = request.instruction.clone();
    let (mut session, skipped) = Session::open(&request.open)?;
    for line in skipped {
        eprintln!("control provider: {line}");
    }
    let result = (|| {
        session.arm(
            engine,
            vec![BreakpointGuard {
                slot: 0,
                instruction,
            }],
            request.arm_mode,
        )?;
        let hardware_stop = session.wait_for_stop(engine)?;
        session.step(
            engine,
            &hardware_stop.epoch,
            crate::sklive::StepGuard {
                instruction: None,
                expected_rips: Vec::new(),
            },
        )?;
        let single_step_stop = session.wait_for_stop(engine)?;
        session.continue_from(engine, &single_step_stop.epoch)?;
        session.close(engine)?;
        Ok(AcceptanceResult {
            schema: "windbg-mcp.sk-live-control-acceptance.v1",
            hardware_stop,
            single_step_stop,
            final_phase: session.phase(),
        })
    })();
    match result {
        Ok(result) => {
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        Err(primary) => match session.close(engine) {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(anyhow!("{primary:#}; cleanup: {cleanup:#}")),
        },
    }
}

fn live_control_usage() -> &'static str {
    "usage: windbg-mcp --sk-live-control --profile <json> \
     --control-transport \"<command line>\" --live-transport \"<command line>\" \
     --vmwp-pid <pid> --dispatcher-vnd <address> --vm-id <guid> \
     --partition-id <number> --expected-cr3 <number> \
     --instruction-address <number> --instruction-bytes <hex> \
     [--arm-mode <redirect|natural>] [--vp <number>]"
}

fn cli_word(name: &str, value: &str) -> Result<u64> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(|| value.parse(), |hex| u64::from_str_radix(hex, 16))
        .with_context(|| format!("--{name} must be hexadecimal 0x or unsigned decimal"))
}

pub(crate) fn parse_hex_bytes(text: &str) -> Result<Vec<u8>> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .collect();
    if compact.is_empty() || compact.len() > 30 || !compact.len().is_multiple_of(2) {
        bail!("--instruction-bytes must contain 1..=15 whole hexadecimal bytes");
    }
    (0..compact.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&compact[at..at + 2], 16)
                .context("--instruction-bytes contains a non-hexadecimal byte")
        })
        .collect()
}

/// Persistent half of the adapter. It is kept beside the live-control state machine in the
/// worker; [`VmwpDispatcher`] borrows it together with the worker's engine for one operation.
#[derive(Clone, Debug)]
struct RetainedEvent {
    system_id: u32,
    return_ip: u64,
    event: HeldEvent,
}

pub(crate) struct VmwpDispatcherState {
    profile: DispatcherProfile,
    vmwp_pid: u32,
    dispatcher_vnd: u64,
    live_transport: String,
    targets: Vec<TargetIdentity>,
    memory: Option<LiveGuestMemory>,
    vmwp_base: Option<u64>,
    handler_context: Option<u64>,
    scratch_allocated: bool,
    breakpoint: Option<OwnedBreakpoint>,
    phase: DispatcherPhase,
    attached: bool,
    threads_frozen: bool,
    /// A pause may have taken effect, so an idempotent resume is owed during safe cleanup.
    vm_paused: bool,
    /// The selected provider is held by an outstanding native event, or Suspend-VM completed before
    /// the dispatcher registered an event.
    provider_writes_quiesced: bool,
    /// Exact callback thread retained until this provider's debug state is restored.
    retained_event: Option<RetainedEvent>,
    completion_kick: Option<VmTransition>,
    unregister: Option<UnregisterProgress>,
}

impl VmwpDispatcherState {
    pub(crate) fn new(
        profile: DispatcherProfile,
        vmwp_pid: u32,
        dispatcher_vnd: u64,
        live_transport: String,
    ) -> Result<Self> {
        profile.validate()?;
        if vmwp_pid == 0 {
            bail!("vmwp_pid must be nonzero");
        }
        if dispatcher_vnd == 0 {
            bail!("dispatcher_vnd must be nonzero");
        }
        if live_transport.trim().is_empty() {
            bail!("the live-memory transport command line is empty");
        }
        Ok(Self {
            profile,
            vmwp_pid,
            dispatcher_vnd,
            live_transport,
            targets: Vec::new(),
            memory: None,
            vmwp_base: None,
            handler_context: None,
            scratch_allocated: false,
            breakpoint: None,
            phase: DispatcherPhase::Fresh,
            attached: false,
            threads_frozen: false,
            vm_paused: false,
            provider_writes_quiesced: false,
            retained_event: None,
            completion_kick: None,
            unregister: None,
        })
    }

    pub(crate) fn bind<'a>(&'a mut self, engine: &'a DebugEngine) -> VmwpDispatcher<'a> {
        VmwpDispatcher {
            engine,
            state: self,
        }
    }

    fn record_handler_context(&mut self, context: u64) -> Result<()> {
        if context == 0 {
            bail!("handler registration returned a zero context");
        }
        if self.handler_context.is_some() {
            bail!("the dispatcher already owns a registered handler context");
        }
        self.handler_context = Some(context);
        Ok(())
    }

    fn claim_vm_pause(&mut self, targets: &[TargetIdentity]) -> Result<()> {
        if !self.targets.is_empty() && self.targets != targets {
            bail!("the dispatcher adapter is already bound to another target");
        }
        self.targets = targets.to_vec();
        // Claim this before Suspend-VM: a helper timeout or failed final verification cannot tell
        // whether the VM changed state, so recovery must conservatively issue Resume-VM.
        self.vm_paused = true;
        self.provider_writes_quiesced = false;
        Ok(())
    }

    fn confirm_vm_pause(&mut self) -> Result<()> {
        if !self.vm_paused {
            bail!("cannot confirm a VM pause the dispatcher does not own");
        }
        self.provider_writes_quiesced = true;
        Ok(())
    }

    fn confirm_retained_provider_stop(&mut self, targets: &[TargetIdentity]) -> Result<()> {
        let target = targets
            .first()
            .filter(|_| targets.len() == 1)
            .context("provider quiescence requires exactly one selected VP")?;
        let retained = self
            .retained_event
            .as_ref()
            .context("the selected provider has no retained dispatcher event")?;
        if retained.event.vp != target.vp || retained.event.vtl != target.vtl {
            bail!("the retained dispatcher event does not name the selected provider");
        }
        self.provider_writes_quiesced = true;
        Ok(())
    }

    fn begin_vm_resume(&mut self) {
        // Once a resume is possible, provider register access is forbidden until a later pause or
        // retained provider stop has completed successfully.
        self.provider_writes_quiesced = false;
    }

    fn refuse_unsafe_recovery(&mut self) -> Result<()> {
        if matches!(self.unregister, Some(UnregisterProgress::Calling)) {
            let why =
                "handler unregister did not reach its return boundary; vmwp remains contained"
                    .to_string();
            self.phase = DispatcherPhase::Contained(why.clone());
            bail!("{why}");
        }
        if self.unregister.is_some() {
            bail!(
                "handler unregister succeeded but deferred cleanup is incomplete; vmwp remains \
                 attached for a teardown retry"
            );
        }
        match &self.phase {
            DispatcherPhase::Registering => {
                let why = "handler registration did not reach and restore its return boundary; \
                           the VM remains paused with vmwp contained"
                    .to_string();
                self.phase = DispatcherPhase::Contained(why.clone());
                bail!("{why}");
            }
            DispatcherPhase::Contained(why) => bail!("the dispatcher is fail-closed: {why}"),
            _ => Ok(()),
        }
    }

    fn finish_completion_kick(&mut self) -> Result<()> {
        let Some(kick) = self.completion_kick.take() else {
            return Ok(());
        };
        if let Err(error) = kick.finish() {
            // Every transition held here ends in Resume-VM; a delayed completion kick first pauses
            // the VM. If the helper fails, the only safe retained state is that a pause may have
            // succeeded. Recovery and teardown will issue an idempotent resume before release.
            self.vm_paused = true;
            self.provider_writes_quiesced = false;
            return Err(error.context(
                "the Hyper-V transition failed, so the VM is conservatively retained as paused",
            ));
        }
        Ok(())
    }

    fn retry_unregister_scratch_free(&mut self) -> Result<()> {
        if !matches!(self.unregister, Some(UnregisterProgress::FreeingScratch))
            || !self.scratch_allocated
            || self.handler_context.is_none()
        {
            bail!("scratch-free retry was requested outside its owned unregister state");
        }
        self.unregister = Some(UnregisterProgress::ReadyToFreeScratch);
        Ok(())
    }

    fn read_memory(
        &self,
        epoch: crate::skcontrol::StopEpoch,
        address: u64,
        size: u32,
    ) -> Result<LiveMemoryRead> {
        let memory = self
            .memory
            .as_ref()
            .context("the live VTL1 memory source is absent")?;
        let at = sk::Gva(address);
        let gpa = memory
            .space
            .translate(at)
            .with_context(|| format!("nothing in live VTL1 maps {address:#x}"))?;
        let bytes = memory
            .read_span(at, size as usize, "stopped live VTL1 memory read")
            .map_err(|why| anyhow!("reading live VTL1 at {address:#x} failed: {why:#}"))?;
        Ok(LiveMemoryRead {
            epoch,
            address: HexU64(address),
            gpa: HexU64(gpa.0),
            requested_size: size,
            read_size: bytes.len() as u32,
            data: bytes.iter().map(|byte| format!("{byte:02X}")).collect(),
        })
    }
}

/// The operation-scoped half. Its lifetime proves that DbgEng never leaves the engine thread.
pub(crate) struct VmwpDispatcher<'a> {
    engine: &'a DebugEngine,
    state: &'a mut VmwpDispatcherState,
}

#[derive(Clone, Debug)]
enum DispatcherPhase {
    Fresh,
    Registering,
    ReadyForStop,
    Holding(HeldEvent),
    ReturningCallback(HeldEvent),
    CallbackEntry(HeldEvent),
    ReturningHandle(HeldEvent),
    HandleReturn(HeldEvent),
    ReturningNative(HeldEvent),
    NativeReturn(HeldEvent),
    Detached,
    Contained(String),
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum UnregisterProgress {
    Calling,
    WaitingCleanup,
    ReturningCleanup { return_address: u64 },
    CleanupReturned,
    ReadyToFreeScratch,
    FreeingScratch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArmPreparation {
    OpenAndRegister,
    VerifyAttached,
    Reattach,
}

impl DispatcherPhase {
    fn arm_preparation(&self) -> Result<ArmPreparation> {
        match self {
            Self::Fresh => Ok(ArmPreparation::OpenAndRegister),
            Self::ReadyForStop | Self::NativeReturn(_) => Ok(ArmPreparation::VerifyAttached),
            Self::Detached => Ok(ArmPreparation::Reattach),
            Self::Contained(why) => bail!("the dispatcher is fail-closed: {why}"),
            Self::Closed => bail!("the dispatcher is closed"),
            _ => bail!("cannot arm while the dispatcher owns a held event"),
        }
    }

    fn held_event(&self) -> Option<&HeldEvent> {
        match self {
            Self::Holding(event)
            | Self::ReturningCallback(event)
            | Self::CallbackEntry(event)
            | Self::ReturningHandle(event)
            | Self::HandleReturn(event)
            | Self::ReturningNative(event)
            | Self::NativeReturn(event) => Some(event),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct OwnedBreakpoint {
    id: u32,
    address: u64,
    original: Vec<u8>,
}

struct LiveGuestMemory {
    source: crate::livesrc::LiveSource,
    root: sk::Gpa,
    space: sk::AddressSpace,
}

struct DeadlineLiveSource<'a> {
    source: &'a crate::livesrc::LiveSource,
    operation: &'a str,
    deadline: Instant,
    expired: std::cell::Cell<bool>,
}

impl<'a> DeadlineLiveSource<'a> {
    fn new(source: &'a crate::livesrc::LiveSource, operation: &'a str) -> Self {
        Self {
            source,
            operation,
            deadline: Instant::now() + LIVE_MEMORY_WAIT,
            expired: std::cell::Cell::new(false),
        }
    }

    fn require_within_deadline(&self) -> Result<()> {
        if self.expired.get() || Instant::now() >= self.deadline {
            self.expired.set(true);
            bail!(
                "{} exceeded its {} second deadline",
                self.operation,
                LIVE_MEMORY_WAIT.as_secs()
            );
        }
        Ok(())
    }
}

impl RawSource for DeadlineLiveSource<'_> {
    fn shape(&self) -> sk::GuestShape {
        self.source.shape()
    }

    fn max_read(&self) -> usize {
        self.source.max_read()
    }

    fn read_chunk(&self, gpa: sk::Gpa, out: &mut [u8]) -> Result<(), sk::ReadFailure> {
        if Instant::now() >= self.deadline {
            self.expired.set(true);
            return Err(sk::ReadFailure::SourceError {
                detail: format!("{} reached its deadline", self.operation),
            });
        }
        let result = self.source.read_chunk_until(gpa, out, self.deadline);
        if Instant::now() >= self.deadline {
            self.expired.set(true);
        }
        result
    }
}

impl LiveGuestMemory {
    fn open(command: &str, target: &TargetIdentity) -> Result<Self> {
        let source = crate::livesrc::LiveSource::spawn(command)?;
        let shape = source.shape();
        if shape.cr3 != Some(target.expected_cr3.0) {
            bail!(
                "live-memory source CR3 {:?} does not match the bound CR3 {:#x}",
                shape.cr3,
                target.expected_cr3.0
            );
        }
        let root = sk::walkable(&shape)
            .map_err(|why| anyhow!("live-memory source is not walkable: {why:?}"))?;
        let space = Self::walk_space(&source, root, "walk")?;
        Ok(Self {
            source,
            root,
            space,
        })
    }

    fn refresh(&mut self) -> Result<()> {
        self.space = Self::walk_space(&self.source, self.root, "refresh")?;
        Ok(())
    }

    fn walk_space(
        source: &crate::livesrc::LiveSource,
        root: sk::Gpa,
        operation: &str,
    ) -> Result<sk::AddressSpace> {
        let description = format!("live VTL1 page-table {operation}");
        let source = DeadlineLiveSource::new(source, &description);
        let reader = sk::Reader::new(&source);
        let (leaves, stats) = sk::walk(&reader, root);
        source.require_within_deadline()?;
        if !stats.complete() {
            bail!("live VTL1 page-table {operation} was incomplete: {stats:?}");
        }
        Ok(sk::AddressSpace::new(leaves))
    }

    fn read_span(&self, at: sk::Gva, size: usize, operation: &str) -> Result<Vec<u8>> {
        let source = DeadlineLiveSource::new(&self.source, operation);
        let reader = sk::Reader::new(&source);
        let result = sk::Space::new(&reader, &self.space).read_span(at, size);
        source.require_within_deadline()?;
        result.map_err(|why| anyhow!("{why:?}"))
    }

    fn read_guard(&self, guard: &InstructionGuard) -> Result<InstructionGuard> {
        let bytes = self
            .read_span(
                sk::Gva(guard.address.0),
                guard.bytes.len(),
                "live VTL1 instruction guard read",
            )
            .map_err(|why| anyhow!("reading guarded VTL1 instruction failed: {why:?}"))?;
        Ok(InstructionGuard {
            address: guard.address,
            bytes,
        })
    }
}

impl EventDispatcher for VmwpDispatcher<'_> {
    fn begin_arm(
        &mut self,
        targets: &[TargetIdentity],
        breakpoints: &[BreakpointGuard],
    ) -> Result<HexU64> {
        let target = targets.first().context("no live-control VP targets")?;
        for candidate in targets {
            candidate.validate()?;
            if !candidate.vm_id.eq_ignore_ascii_case(&target.vm_id)
                || candidate.partition_id != target.partition_id
                || candidate.vtl != target.vtl
                || candidate.expected_cr3 != target.expected_cr3
            {
                bail!("dispatcher VP targets do not share one VM identity");
            }
        }
        if !self.state.targets.is_empty() && self.state.targets != targets {
            bail!("the dispatcher adapter is already bound to another target");
        }

        match self.state.phase.arm_preparation()? {
            ArmPreparation::OpenAndRegister => self.open_and_register(targets, breakpoints)?,
            ArmPreparation::VerifyAttached => {
                self.pause_for_provider_writes(targets)?;
                self.verify_breakpoints(breakpoints)?;
            }
            ArmPreparation::Reattach => self.reattach_registered_handler(targets, breakpoints)?,
        }
        Ok(HexU64(
            self.state
                .handler_context
                .context("the registered handler returned no context")?,
        ))
    }

    fn finish_arm(&mut self) -> Result<()> {
        if !matches!(
            self.state.phase,
            DispatcherPhase::ReadyForStop | DispatcherPhase::NativeReturn(_)
        ) {
            bail!("finish_arm requires a debugger-stopped, armed dispatcher");
        }
        Ok(())
    }

    fn provider_writes_quiesced(&self) -> bool {
        self.state.provider_writes_quiesced
    }

    fn establish_recovery_pause(&mut self, targets: &[TargetIdentity]) -> Result<()> {
        if self.state.retained_event.is_some() {
            // A delayed completion kick cannot be joined while its pause request is blocked behind
            // this native event. The event itself is the selected provider's write barrier; safe
            // recovery completes the callback, detaches, and joins the helper in that order.
            return self.state.confirm_retained_provider_stop(targets);
        }
        // A wait may fail while its asynchronous Resume-VM is still outstanding. With no retained
        // event, join that helper before a fresh Suspend-VM proves recovery quiescence. An incomplete
        // callback whose exact thread was not retained remains fail-closed.
        let transition_error = self.state.finish_completion_kick().err();
        let pause = if matches!(
            self.state.phase,
            DispatcherPhase::Holding(_)
                | DispatcherPhase::ReturningCallback(_)
                | DispatcherPhase::CallbackEntry(_)
                | DispatcherPhase::ReturningHandle(_)
                | DispatcherPhase::HandleReturn(_)
                | DispatcherPhase::ReturningNative(_)
        ) {
            Err(anyhow!(
                "an incomplete native callback has no retained thread identity"
            ))
        } else {
            self.pause_for_provider_writes(targets)
        };
        match (transition_error, pause) {
            (None, result) => result,
            (Some(error), Ok(())) => Err(error
                .context("the pending VM transition failed before recovery quiescence was proved")),
            (Some(transition), Err(pause)) => bail!(
                "the pending VM transition failed: {transition:#}; recovery quiescence also \
                 failed: {pause:#}"
            ),
        }
    }

    fn verify_instruction(&mut self, instruction: &InstructionGuard) -> Result<()> {
        VmwpDispatcher::verify_instruction(self, instruction)
    }

    fn wait_for_stop(
        &mut self,
        targets: &[TargetIdentity],
        instructions: &[InstructionGuard],
    ) -> Result<ObservedStop> {
        if targets.is_empty()
            || targets
                .iter()
                .any(|target| !self.state.targets.contains(target))
        {
            bail!("the stop request does not match the dispatcher target");
        }
        let primary = targets.first().context("no live-control VP targets")?;
        match &self.state.phase {
            DispatcherPhase::ReadyForStop => {}
            other => bail!("wait_for_stop requires an armed dispatcher, got {other:?}"),
        }
        if self.state.retained_event.is_some() {
            bail!("wait_for_stop found dispatcher events retained from an earlier stop");
        }
        let event_site = self.site_address(&self.state.profile.event_held)?;
        if self.state.breakpoint.is_none() {
            let site = self.state.profile.event_held.clone();
            self.set_site_breakpoint(&site)?;
        }

        if self.state.vm_paused {
            // A completed step can leave the delayed native-completion kick pending while the VM
            // remains paused. Cancel that delay and begin the resume needed for this exact wait.
            self.state.finish_completion_kick()?;
            self.state.begin_vm_resume();
            self.state.completion_kick = Some(VmTransition::immediate(
                primary.vm_id.clone(),
                VmAction::Resume,
            ));
        }

        let deadline = Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT));
        let (event_pointer, event) = self.wait_for_owned_event(targets, event_site, deadline)?;
        self.retain_current_event(event_pointer, event_site, &event)?;
        self.state.vm_paused = false;
        self.state.confirm_retained_provider_stop(targets)?;
        let memory = self
            .state
            .memory
            .as_mut()
            .context("the live VTL1 memory source is absent")?;
        memory.refresh()?;
        let observed_instructions = instructions
            .iter()
            .map(|instruction| memory.read_guard(instruction))
            .collect::<Result<Vec<_>>>()?;
        Ok(ObservedStop {
            event,
            instructions: observed_instructions,
        })
    }

    fn release_event(&mut self, event: &HeldEvent, mode: ReleaseMode) -> Result<()> {
        let retained = self
            .state
            .retained_event
            .as_ref()
            .map(|retained| &retained.event)
            .context("the dispatcher owns no event to release")?;
        if retained != event {
            bail!("release does not name the event held by the dispatcher");
        }
        self.complete_event(mode)
    }

    fn recover(&mut self, safe_to_resume: bool, event: Option<&HeldEvent>) -> Result<()> {
        self.state.refuse_unsafe_recovery()?;
        if !safe_to_resume {
            let why = if self.state.vm_paused {
                "VTL1 restoration was not proved; the VM remains paused"
            } else {
                "VTL1 restoration was not proved; vmwp remains stopped on the worker engine"
            };
            self.state.phase = DispatcherPhase::Contained(why.to_string());
            return Ok(());
        }

        if let Some(held) = self
            .state
            .retained_event
            .as_ref()
            .map(|retained| retained.event.clone())
        {
            if let Some(expected) = event
                && expected != &held
            {
                bail!("recovery event does not match the event held by the dispatcher");
            }
            return self.release_event(&held, ReleaseMode::Resume);
        }

        if self.state.breakpoint.is_some() {
            self.remove_owned_breakpoint()?;
        }
        if self.state.threads_frozen {
            self.engine.execute_command("~* u").map_err(debugger)?;
            self.state.threads_frozen = false;
        }
        if self.state.attached {
            self.detach_handled()?;
        }
        self.state.finish_completion_kick()?;
        if self.state.vm_paused {
            self.state.begin_vm_resume();
            run_vm_action(self.bound_vm_id()?, VmAction::Resume, POWERSHELL_WAIT)?;
            self.state.vm_paused = false;
        }
        Ok(())
    }

    fn teardown(&mut self) -> Result<()> {
        match &self.state.phase {
            DispatcherPhase::Closed => return Ok(()),
            DispatcherPhase::Contained(why) => {
                bail!("refusing to detach a contained dispatcher: {why}")
            }
            DispatcherPhase::Registering => {
                bail!("refusing teardown while handler registration is incomplete")
            }
            DispatcherPhase::Holding(_)
            | DispatcherPhase::ReturningCallback(_)
            | DispatcherPhase::CallbackEntry(_)
            | DispatcherPhase::ReturningHandle(_)
            | DispatcherPhase::HandleReturn(_)
            | DispatcherPhase::ReturningNative(_) => {
                bail!("refusing teardown while a native event is incomplete")
            }
            _ => {}
        }

        // A successful native unregister is irreversible. If its later deferred-cleanup sequence
        // failed, resume that recorded sequence before any generic breakpoint removal or detach;
        // neither recovery nor a retry may issue the unregister call a second time.
        if self.state.unregister.is_some() {
            self.unregister_handler()?;
            return self.finish_teardown();
        }

        if self.state.breakpoint.is_some() {
            self.remove_owned_breakpoint()?;
        }
        if self.state.threads_frozen {
            self.engine.execute_command("~* u").map_err(debugger)?;
            self.state.threads_frozen = false;
        }
        if self.state.attached {
            self.detach_handled()?;
        }
        self.state.finish_completion_kick()?;
        if self.state.handler_context.is_some() {
            self.unregister_handler()?;
        } else if self.state.scratch_allocated {
            self.free_unregistered_scratch()?;
        }
        self.finish_teardown()
    }
}

impl VmwpDispatcher<'_> {
    fn finish_teardown(&mut self) -> Result<()> {
        if self.state.vm_paused {
            self.state.begin_vm_resume();
            run_vm_action(self.bound_vm_id()?, VmAction::Resume, POWERSHELL_WAIT)?;
            self.state.vm_paused = false;
        }
        self.state.phase = DispatcherPhase::Closed;
        Ok(())
    }

    fn prepare_held_event(&mut self) -> Result<()> {
        self.state.finish_completion_kick()?;
        if self.state.breakpoint.is_some() {
            self.remove_owned_breakpoint()?;
        }
        Ok(())
    }

    fn wait_for_owned_event(
        &self,
        targets: &[TargetIdentity],
        event_site: u64,
        deadline: Instant,
    ) -> Result<(u64, HeldEvent)> {
        loop {
            self.run_to_current_breakpoint(deadline)?;
            if self.engine.instruction_pointer().map_err(debugger)? != event_site {
                bail!("debugger stopped away from the owned dispatcher breakpoint");
            }
            let message_type = self.register("rcx")?;
            let event_pointer = self.register("r14")?;
            let context = self.read_u64(
                event_pointer
                    .checked_add(u64::from(self.state.profile.layout.event_context))
                    .context("event context address overflowed")?,
            )?;
            let vp = self.read_u32(
                event_pointer
                    .checked_add(u64::from(self.state.profile.layout.event_vp))
                    .context("event VP address overflowed")?,
            )?;
            if message_type == EVENT_TYPE_VECTOR_1
                && context == self.state.handler_context.context("no handler context")?
                && let Some(target) = targets.iter().find(|target| target.vp == vp)
            {
                return Ok((
                    event_pointer,
                    HeldEvent {
                        message_type: HexU64(EVENT_TYPE_VECTOR_1),
                        vector: 1,
                        vp: target.vp,
                        vtl: target.vtl,
                        cpl: 0,
                        dispatcher_context: HexU64(context),
                        advance_instruction_pointer: false,
                        reason: StopReason::DebugException,
                    },
                ));
            }
            if Instant::now() >= deadline {
                bail!("too many unrelated dispatcher events before the owned vector-1 event");
            }
        }
    }

    fn retain_current_event(
        &mut self,
        event_pointer: u64,
        event_site: u64,
        event: &HeldEvent,
    ) -> Result<()> {
        // Name the native event before any fallible inspection. Once the exact callback thread is
        // known, retain that identity before cleanup so recovery can either complete it or contain
        // vmwp without detaching from an outstanding event.
        self.state.phase = DispatcherPhase::Holding(event.clone());
        let system_id = self.engine.current_thread_system_id().map_err(debugger)?;
        if self.state.retained_event.is_some() {
            bail!("the dispatcher already retains a native event thread");
        }
        self.state.retained_event = Some(RetainedEvent {
            system_id,
            return_ip: event_site,
            event: event.clone(),
        });
        let advance = self.read_u8(
            event_pointer
                .checked_add(u64::from(self.state.profile.layout.exchange_advance))
                .context("event advance address overflowed")?,
        )?;
        if advance != 0 {
            bail!("the native dispatcher event already requests instruction-pointer advance");
        }
        self.prepare_held_event()
    }

    fn pause_for_provider_writes(&mut self, targets: &[TargetIdentity]) -> Result<()> {
        let target = targets.first().context("no live-control VP targets")?;
        self.state.finish_completion_kick()?;
        self.state.claim_vm_pause(targets)?;
        run_vm_action(&target.vm_id, VmAction::Pause, POWERSHELL_WAIT)?;
        self.state.confirm_vm_pause()
    }

    fn open_and_register(
        &mut self,
        targets: &[TargetIdentity],
        breakpoints: &[BreakpointGuard],
    ) -> Result<()> {
        let target = targets.first().context("no live-control VP targets")?;
        self.pause_for_provider_writes(targets)?;
        verify_vmwp_pid(&target.vm_id, self.state.vmwp_pid)?;
        if self.state.memory.is_none() {
            self.state.memory = Some(LiveGuestMemory::open(&self.state.live_transport, target)?);
        }
        self.verify_breakpoints(breakpoints)?;
        let pending = self
            .engine
            .attach_process_begin(self.state.vmwp_pid)
            .map_err(debugger)?;
        self.state.attached = true;
        pending.wait().map_err(debugger)?;
        self.engine.execute_command("sxd 6ba").map_err(debugger)?;
        self.engine
            .execute_command("sxd e06d7363")
            .map_err(debugger)?;

        self.verify_vmwp_build()?;
        self.verify_all_sites()?;
        self.allocate_scratch()?;
        self.register_handler()?;
        let site = self.state.profile.event_held.clone();
        self.set_site_breakpoint(&site)?;
        self.state.phase = DispatcherPhase::ReadyForStop;
        Ok(())
    }

    fn reattach_registered_handler(
        &mut self,
        targets: &[TargetIdentity],
        breakpoints: &[BreakpointGuard],
    ) -> Result<()> {
        let target = targets.first().context("no live-control VP targets")?;
        if self.state.handler_context.is_none() || !self.state.scratch_allocated {
            bail!("the detached dispatcher no longer owns a registered handler");
        }
        self.pause_for_provider_writes(targets)?;
        verify_vmwp_pid(&target.vm_id, self.state.vmwp_pid)?;
        let pending = self
            .engine
            .attach_process_begin(self.state.vmwp_pid)
            .map_err(debugger)?;
        self.state.attached = true;
        pending.wait().map_err(debugger)?;
        self.engine.execute_command("sxd 6ba").map_err(debugger)?;
        self.engine
            .execute_command("sxd e06d7363")
            .map_err(debugger)?;
        self.verify_vmwp_build()?;
        self.verify_all_sites()?;
        self.verify_breakpoints(breakpoints)?;
        let site = self.state.profile.event_held.clone();
        self.set_site_breakpoint(&site)?;
        self.state.phase = DispatcherPhase::ReadyForStop;
        Ok(())
    }

    fn verify_vmwp_build(&mut self) -> Result<()> {
        let module = self.engine.module("vmwp").map_err(debugger)?;
        if module.size != self.state.profile.vmwp_size_of_image {
            bail!(
                "vmwp SizeOfImage is {:#x}, profile requires {:#x}",
                module.size,
                self.state.profile.vmwp_size_of_image
            );
        }
        if !module.loaded_image_name.is_empty()
            && !same_path(&module.loaded_image_name, &self.state.profile.vmwp_image)
        {
            bail!("DbgEng loaded vmwp from a different path than the dispatcher profile");
        }
        let bytes = std::fs::read(&self.state.profile.vmwp_image).with_context(|| {
            format!(
                "reading profiled vmwp image {}",
                self.state.profile.vmwp_image.display()
            )
        })?;
        let digest = crate::client::sha256(&bytes);
        let actual = digest
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        if !actual.eq_ignore_ascii_case(&self.state.profile.vmwp_sha256) {
            bail!("loaded vmwp SHA-256 does not match the dispatcher profile");
        }
        self.state.vmwp_base = Some(module.base);
        Ok(())
    }

    fn verify_all_sites(&self) -> Result<()> {
        for site in [
            &self.state.profile.event_held,
            &self.state.profile.callback_entry,
            &self.state.profile.handle_return,
            &self.state.profile.native_return,
            &self.state.profile.deferred_cleanup,
        ] {
            self.verify_site(site)?;
        }
        Ok(())
    }

    fn verify_instruction(&mut self, instruction: &InstructionGuard) -> Result<()> {
        let memory = self
            .state
            .memory
            .as_mut()
            .context("the live VTL1 memory source is absent")?;
        memory.refresh()?;
        let observed = memory.read_guard(instruction)?;
        if &observed != instruction {
            bail!("the guarded VTL1 instruction does not match live memory");
        }
        Ok(())
    }

    fn verify_breakpoints(&mut self, breakpoints: &[BreakpointGuard]) -> Result<()> {
        for breakpoint in breakpoints {
            self.verify_instruction(&breakpoint.instruction)?;
        }
        Ok(())
    }

    fn allocate_scratch(&mut self) -> Result<()> {
        let base = self.state.profile.scratch_base.0;
        if self.engine.read_memory(base, 1).is_ok() {
            bail!("the requested callback scratch address is already mapped");
        }
        self.engine
            .execute_command(&format!(
                ".dvalloc /b {base:016x} {:x}",
                self.state.profile.scratch_size
            ))
            .map_err(debugger)?;
        // A successful command created target-process state. Claim it before the verification
        // read so any read failure still makes recovery and teardown issue the matching free.
        self.state.scratch_allocated = true;
        self.engine
            .read_memory(
                base,
                usize::try_from(self.state.profile.scratch_size).unwrap(),
            )
            .map_err(debugger)?;

        let returned = self.scratch(self.state.profile.layout.returned_context)?;
        let handler = self.scratch(self.state.profile.layout.handler_descriptor)?;
        let callback = self.scratch(self.state.profile.layout.callback_descriptor)?;
        let mirror = callback
            .checked_add(u64::from(self.state.profile.layout.callback_mirror))
            .context("callback mirror address overflowed")?;
        let callback_stub = self.image(self.state.profile.callback_stub_rva.0)?;
        self.write_u64(returned, 0)?;
        self.write_u64(handler, callback)?;
        self.write_u64(callback, callback_stub)?;
        self.write_u64(mirror, callback_stub)?;
        Ok(())
    }

    fn register_handler(&mut self) -> Result<()> {
        let rsp = self.register("rsp")?;
        let return_address = self.read_u64(rsp)?;
        let stack_handler = rsp
            .checked_add(u64::from(self.state.profile.layout.register_stack_handler))
            .context("handler stack address overflowed")?;
        let stack_context = rsp
            .checked_add(u64::from(self.state.profile.layout.register_stack_context))
            .context("context stack address overflowed")?;
        let saved_handler = self.read_u64(stack_handler)?;
        let saved_context = self.read_u64(stack_context)?;

        self.engine.execute_command("~* f").map_err(debugger)?;
        self.engine.execute_command("~# u").map_err(debugger)?;
        self.state.threads_frozen = true;
        self.set_dynamic_breakpoint(return_address)?;
        // From the first guest-memory mutation until the return boundary and original stack are
        // proved, recovery must keep vmwp attached and the VM paused. Detaching would let a
        // partially injected registration finish without a context this adapter can unregister.
        self.state.phase = DispatcherPhase::Registering;
        self.write_u64(
            stack_handler,
            self.scratch(self.state.profile.layout.handler_descriptor)?,
        )?;
        self.write_u64(
            stack_context,
            self.scratch(self.state.profile.layout.returned_context)?,
        )?;
        self.write_register("rcx", self.state.dispatcher_vnd)?;
        self.write_register("rdx", 1)?;
        self.write_register("r8", 0)?;
        self.write_register("r9", self.state.profile.registration_tag.0)?;
        self.write_register(
            "rip",
            self.image(self.state.profile.register_handler_rva.0)?,
        )?;
        self.run_to_current_breakpoint(
            Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT)),
        )?;
        if self.engine.instruction_pointer().map_err(debugger)? != return_address {
            bail!("handler registration stopped away from its return address");
        }
        self.remove_owned_breakpoint()?;
        if self.register("rax")? != 0 {
            bail!("handler registration returned failure");
        }
        let context = self.read_u64(self.scratch(self.state.profile.layout.returned_context)?)?;
        // Registration is already live in vmwp. Record its context before any fallible local
        // restoration so teardown must unregister it rather than free callback scratch directly.
        self.state.record_handler_context(context)?;
        self.write_u64(stack_handler, saved_handler)?;
        self.write_u64(stack_context, saved_context)?;
        self.engine.execute_command("~* u").map_err(debugger)?;
        self.state.threads_frozen = false;
        self.state.phase = DispatcherPhase::Fresh;
        Ok(())
    }

    fn complete_event(&mut self, mode: ReleaseMode) -> Result<()> {
        let event = self
            .state
            .retained_event
            .as_ref()
            .map(|retained| retained.event.clone())
            .context("the dispatcher owns no retained event to complete")?;
        self.complete_retained_event(&event)?;

        match mode {
            ReleaseMode::ArmNextStop => {
                let site = self.state.profile.event_held.clone();
                self.set_site_breakpoint(&site)?;
                self.state.phase = DispatcherPhase::ReadyForStop;
            }
            ReleaseMode::Resume => {
                self.settle_native_completion()?;
                self.detach_handled()?;
                self.state.finish_completion_kick()?;
                if self.state.vm_paused {
                    self.state.begin_vm_resume();
                    run_vm_action(self.bound_vm_id()?, VmAction::Resume, POWERSHELL_WAIT)?;
                    self.state.vm_paused = false;
                }
                self.state.phase = DispatcherPhase::Detached;
            }
        }
        Ok(())
    }

    fn settle_native_completion(&self) -> Result<()> {
        // The native return proves success before vmwp has executed past the call. Let the existing
        // DbgEng watchdog interrupt that ordinary execution, then detach before joining the Hyper-V
        // helper whose pause request is blocked while the callback remains debugger-stopped.
        let run = self
            .engine
            .execute_and_wait("g", NATIVE_SETTLE_WAIT)
            .map_err(debugger)?;
        if run.target_gone {
            bail!("vmwp left the debugger while settling native event completion");
        }
        match run.cut_short {
            Some(Interruption::Deadline { .. }) => Ok(()),
            Some(Interruption::OnRequest) => {
                bail!("native event completion was interrupted on request")
            }
            None => bail!("vmwp stopped unexpectedly while settling native event completion"),
        }
    }

    fn complete_retained_event(&mut self, event: &HeldEvent) -> Result<()> {
        let phase_event = self.state.phase.held_event();
        if phase_event != Some(event) || matches!(self.state.phase, DispatcherPhase::Holding(_)) {
            self.restore_retained_event(event)?;
        }
        self.complete_event_to_native_return()?;
        if !matches!(&self.state.phase, DispatcherPhase::NativeReturn(held) if held == event) {
            bail!("dispatcher completion did not reach the named native return");
        }
        let retained = self
            .state
            .retained_event
            .take()
            .context("the completed dispatcher event lost its retained-thread record")?;
        if &retained.event != event {
            self.state.retained_event = Some(retained);
            bail!("the completed dispatcher event changed its retained-thread record");
        }
        self.state.provider_writes_quiesced = false;
        Ok(())
    }

    fn complete_event_to_native_return(&mut self) -> Result<()> {
        let held = match &self.state.phase {
            DispatcherPhase::Holding(event) => event.clone(),
            DispatcherPhase::ReturningCallback(event)
            | DispatcherPhase::CallbackEntry(event)
            | DispatcherPhase::ReturningHandle(event)
            | DispatcherPhase::HandleReturn(event)
            | DispatcherPhase::ReturningNative(event)
            | DispatcherPhase::NativeReturn(event) => event.clone(),
            _ => bail!("the dispatcher is not in a releasable event phase"),
        };

        if matches!(self.state.phase, DispatcherPhase::Holding(_)) {
            let site = self.state.profile.callback_entry.clone();
            self.set_site_breakpoint(&site)?;
            self.state.phase = DispatcherPhase::ReturningCallback(held.clone());
        }

        if matches!(self.state.phase, DispatcherPhase::ReturningCallback(_)) {
            let site = self.state.profile.callback_entry.clone();
            let target = self.require_owned_site_breakpoint(&site)?;
            if self.engine.instruction_pointer().map_err(debugger)? != target {
                self.run_to_current_breakpoint(
                    Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT)),
                )?;
            }
            self.require_site(&site)?;
            let message = self.register("rcx")?;
            let context = self.register("rbx")?;
            let callback = self.read_u64(
                context
                    .checked_add(u64::from(self.state.profile.layout.callback_pointer))
                    .context("callback pointer address overflowed")?,
            )?;
            if message != held.message_type.0
                || context != held.dispatcher_context.0
                || callback != self.scratch(self.state.profile.layout.handler_descriptor)?
            {
                bail!("native callback entry does not match the held event and handler");
            }
            self.remove_owned_breakpoint()?;
            self.state.phase = DispatcherPhase::CallbackEntry(held.clone());
        }

        if matches!(self.state.phase, DispatcherPhase::CallbackEntry(_)) {
            let site = self.state.profile.handle_return.clone();
            self.set_site_breakpoint(&site)?;
            // From here recovery owns the installed handle-return breakpoint. Record that before
            // either the RIP write or the wait can fail, so retry does not install it twice.
            self.state.phase = DispatcherPhase::ReturningHandle(held.clone());
        }

        if matches!(self.state.phase, DispatcherPhase::ReturningHandle(_)) {
            let entry = self.site_address(&self.state.profile.callback_entry)?;
            let site = self.state.profile.handle_return.clone();
            let target = self.require_owned_site_breakpoint(&site)?;
            let rip = self.engine.instruction_pointer().map_err(debugger)?;
            if rip == entry {
                self.write_register("rip", self.image(self.state.profile.callback_resume_rva.0)?)?;
            }
            if rip != target {
                self.run_to_current_breakpoint(
                    Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT)),
                )?;
            }
            self.require_site(&site)?;
            if self.register("rax")? != 1 {
                bail!("registered callback did not report the event handled");
            }
            self.remove_owned_breakpoint()?;
            self.state.phase = DispatcherPhase::HandleReturn(held.clone());
        }

        if matches!(self.state.phase, DispatcherPhase::HandleReturn(_)) {
            let site = self.state.profile.native_return.clone();
            self.set_site_breakpoint(&site)?;
            // The retained breakpoint is recoverable before even resolving the VM coordinate for
            // the completion kick.
            self.state.phase = DispatcherPhase::ReturningNative(held.clone());
        }

        if matches!(self.state.phase, DispatcherPhase::ReturningNative(_)) {
            let site = self.state.profile.native_return.clone();
            let target = self.require_owned_site_breakpoint(&site)?;
            if self.state.completion_kick.is_none() {
                self.state.begin_vm_resume();
                self.state.completion_kick = Some(VmTransition::completion_kick(
                    self.bound_vm_id()?.to_string(),
                ));
            }
            if self.engine.instruction_pointer().map_err(debugger)? != target {
                self.run_to_current_breakpoint(
                    Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT)),
                )?;
            }
            self.require_site(&site)?;
            if self.register("rax")? != 1 {
                bail!("native dispatcher completion did not report success");
            }
            self.remove_owned_breakpoint()?;
            self.state.phase = DispatcherPhase::NativeReturn(held.clone());
        }
        Ok(())
    }

    fn unregister_handler(&mut self) -> Result<()> {
        let context = self.state.handler_context.context("no handler context")?;
        if self.state.unregister.is_none() {
            self.begin_unregister_call(context)?;
        }
        loop {
            match self.state.unregister.clone() {
                Some(UnregisterProgress::Calling) => {
                    bail!("handler unregister return was not proved")
                }
                Some(UnregisterProgress::WaitingCleanup) => {
                    self.wait_for_unregister_cleanup(context)?
                }
                Some(UnregisterProgress::ReturningCleanup { return_address }) => {
                    self.finish_unregister_cleanup_return(return_address)?
                }
                Some(UnregisterProgress::CleanupReturned) => {
                    self.settle_unregister_cleanup(context)?
                }
                Some(UnregisterProgress::ReadyToFreeScratch) => {
                    self.issue_unregister_scratch_free(context)?
                }
                Some(UnregisterProgress::FreeingScratch) => {
                    self.verify_unregister_scratch_free()?;
                }
                None => return Ok(()),
            }
        }
    }

    fn begin_unregister_call(&mut self, context: u64) -> Result<()> {
        verify_vmwp_pid(self.bound_vm_id()?, self.state.vmwp_pid)?;
        let pending = self
            .engine
            .attach_process_begin(self.state.vmwp_pid)
            .map_err(debugger)?;
        self.state.attached = true;
        pending.wait().map_err(debugger)?;
        self.verify_vmwp_build()?;
        self.verify_all_sites()?;
        self.engine.execute_command("sxd 6ba").map_err(debugger)?;
        self.engine
            .execute_command("sxd e06d7363")
            .map_err(debugger)?;

        let rsp = self.register("rsp")?;
        let return_address = self.read_u64(rsp)?;
        self.engine.execute_command("~* f").map_err(debugger)?;
        self.engine.execute_command("~# u").map_err(debugger)?;
        self.state.threads_frozen = true;
        self.set_dynamic_breakpoint(return_address)?;
        // From the first register mutation until the return value is proved, a failed call cannot
        // be retried or detached: either could complete an unregister whose result we no longer
        // know. Post-return cleanup uses the resumable states below instead.
        self.state.unregister = Some(UnregisterProgress::Calling);
        self.write_register("rcx", self.state.dispatcher_vnd)?;
        self.write_register("rdx", context)?;
        self.write_register(
            "rip",
            self.image(self.state.profile.unregister_handler_rva.0)?,
        )?;
        self.run_to_current_breakpoint(
            Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT)),
        )?;
        if self.engine.instruction_pointer().map_err(debugger)? != return_address {
            bail!("handler unregister stopped away from its return address");
        }
        self.remove_owned_breakpoint()?;
        if self.register("rax")? != 1 {
            bail!("handler unregister returned failure");
        }

        self.state.unregister = Some(UnregisterProgress::WaitingCleanup);
        Ok(())
    }

    fn wait_for_unregister_cleanup(&mut self, context: u64) -> Result<()> {
        let cleanup = self.state.profile.deferred_cleanup.clone();
        let cleanup_address = self.site_address(&cleanup)?;
        if self.state.breakpoint.is_none() {
            self.set_site_breakpoint(&cleanup)?;
        }
        if self.state.threads_frozen {
            self.engine.execute_command("~* u").map_err(debugger)?;
            self.state.threads_frozen = false;
        }
        let deadline = Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT));
        loop {
            if self.engine.instruction_pointer().map_err(debugger)? == cleanup_address
                && self.register("rcx")? == context
            {
                break;
            }
            self.run_to_current_breakpoint(deadline)?;
            self.require_site(&cleanup)?;
            if Instant::now() >= deadline {
                bail!("deferred cleanup did not reach the registered handler context");
            }
        }
        let cleanup_return = self.read_u64(self.register("rsp")?)?;
        self.state.unregister = Some(UnregisterProgress::ReturningCleanup {
            return_address: cleanup_return,
        });
        Ok(())
    }

    fn finish_unregister_cleanup_return(&mut self, cleanup_return: u64) -> Result<()> {
        if let Some(owned) = &self.state.breakpoint {
            let cleanup_address = self.site_address(&self.state.profile.deferred_cleanup)?;
            if owned.address != cleanup_address && owned.address != cleanup_return {
                bail!("unregister cleanup owns an unexpected breakpoint");
            }
            if owned.address == cleanup_address {
                self.remove_owned_breakpoint()?;
            }
        }
        if self.state.breakpoint.is_none() {
            self.set_dynamic_breakpoint(cleanup_return)?;
        }
        if self.engine.instruction_pointer().map_err(debugger)? != cleanup_return {
            self.run_to_current_breakpoint(
                Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT)),
            )?;
        }
        if self.engine.instruction_pointer().map_err(debugger)? != cleanup_return {
            bail!("deferred cleanup stopped away from its return address");
        }
        self.remove_owned_breakpoint()?;
        self.state.unregister = Some(UnregisterProgress::CleanupReturned);
        Ok(())
    }

    fn settle_unregister_cleanup(&mut self, context: u64) -> Result<()> {
        if self.state.attached {
            self.detach_handled()?;
        }
        thread::sleep(CLEANUP_SETTLE);
        if !self.state.attached {
            let pending = self
                .engine
                .attach_process_begin(self.state.vmwp_pid)
                .map_err(debugger)?;
            self.state.attached = true;
            pending.wait().map_err(debugger)?;
        }
        let callback = self.read_u64(
            context
                .checked_add(u64::from(self.state.profile.layout.callback_pointer))
                .context("old callback pointer address overflowed")?,
        )?;
        let flags = self.read_u64(
            context
                .checked_add(u64::from(self.state.profile.layout.callback_flags))
                .context("old callback flags address overflowed")?,
        )?;
        if callback != self.scratch(self.state.profile.layout.handler_descriptor)? || flags == 0 {
            bail!("old callback record changed before scratch release");
        }
        self.state.unregister = Some(UnregisterProgress::ReadyToFreeScratch);
        Ok(())
    }

    fn issue_unregister_scratch_free(&mut self, context: u64) -> Result<()> {
        self.verify_owned_scratch(context)?;
        let scratch = self.state.profile.scratch_base.0;
        // Claim the free before the fallible command: if DbgEng loses the reply, a teardown retry
        // verifies whether the allocation remains. A still-owned mapping returns to the ready
        // state before a later retry issues the command again; an absent mapping is never freed
        // twice.
        self.state.unregister = Some(UnregisterProgress::FreeingScratch);
        self.engine
            .execute_command(&format!(".dvfree {scratch:016x} 0"))
            .map_err(debugger)?;
        Ok(())
    }

    fn verify_owned_scratch(&self, context: u64) -> Result<()> {
        let callback = self.scratch(self.state.profile.layout.callback_descriptor)?;
        let callback_stub = self.image(self.state.profile.callback_stub_rva.0)?;
        let mirror = callback
            .checked_add(u64::from(self.state.profile.layout.callback_mirror))
            .context("callback mirror address overflowed")?;
        if self.read_u64(self.scratch(self.state.profile.layout.returned_context)?)? != context
            || self.read_u64(self.scratch(self.state.profile.layout.handler_descriptor)?)?
                != callback
            || self.read_u64(callback)? != callback_stub
            || self.read_u64(mirror)? != callback_stub
        {
            bail!("callback scratch changed before release");
        }
        Ok(())
    }

    fn verify_unregister_scratch_free(&mut self) -> Result<()> {
        let scratch = self.state.profile.scratch_base.0;
        if self.engine.read_memory(scratch, 1).is_ok() {
            let context = self.state.handler_context.context("no handler context")?;
            self.verify_owned_scratch(context)?;
            self.state.retry_unregister_scratch_free()?;
            bail!(
                "callback scratch remained readable after .dvfree; its contents still belong to \
                 this controller, so retry end_session to issue the free again"
            );
        }
        self.state.scratch_allocated = false;
        self.state.handler_context = None;
        self.state.unregister = None;
        if self.state.attached {
            self.detach_handled()?;
        }
        Ok(())
    }

    fn run_to_current_breakpoint(&self, deadline: Instant) -> Result<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("the debugger did not reach the owned breakpoint before its deadline");
        }
        let timeout = remaining.as_millis().min(u128::from(u32::MAX)) as u32;
        let run = self
            .engine
            .execute_and_wait("g", timeout)
            .map_err(debugger)?;
        if let Some(interruption) = run.cut_short {
            match interruption {
                Interruption::OnRequest => bail!("the debugger wait was interrupted on request"),
                Interruption::Deadline { .. } => {
                    bail!("the debugger wait reached its deadline")
                }
            }
        }
        if run.target_gone {
            bail!("vmwp left the debugger while an owned breakpoint was pending");
        }
        let expected = self
            .state
            .breakpoint
            .as_ref()
            .context("no owned breakpoint is armed")?
            .address;
        if self.engine.instruction_pointer().map_err(debugger)? == expected {
            return Ok(());
        }
        bail!("the debugger stopped for an event the live-control adapter does not own")
    }

    fn set_site_breakpoint(&mut self, site: &DispatcherSite) -> Result<()> {
        let address = self.site_address(site)?;
        self.set_guarded_breakpoint(address, site.original.clone())
    }

    fn require_owned_site_breakpoint(&self, site: &DispatcherSite) -> Result<u64> {
        let address = self.site_address(site)?;
        let owned = self
            .state
            .breakpoint
            .as_ref()
            .context("the resumable event stage owns no breakpoint")?;
        if owned.address != address || owned.original != site.original {
            bail!("the resumable event stage owns an unexpected breakpoint");
        }
        let still_owned = self
            .engine
            .breakpoints()
            .map_err(debugger)?
            .into_iter()
            .find(|breakpoint| breakpoint.id == owned.id)
            .context("the resumable event breakpoint disappeared")?;
        if still_owned.address != Some(address)
            || still_owned.kind != BreakpointKind::Code
            || !still_owned.enabled
        {
            bail!("the resumable event breakpoint id was reused, changed or disabled");
        }
        Ok(address)
    }

    fn set_dynamic_breakpoint(&mut self, address: u64) -> Result<()> {
        let original = self.engine.read_memory(address, 8).map_err(debugger)?;
        self.set_guarded_breakpoint(address, original)
    }

    fn set_guarded_breakpoint(&mut self, address: u64, original: Vec<u8>) -> Result<()> {
        if self.state.breakpoint.is_some() {
            bail!("the adapter already owns a breakpoint");
        }
        if self
            .engine
            .read_memory(address, original.len())
            .map_err(debugger)?
            != original
        {
            bail!("breakpoint original-byte guard does not match at {address:#x}");
        }
        if self
            .engine
            .breakpoints()
            .map_err(debugger)?
            .iter()
            .any(|breakpoint| breakpoint.address == Some(address))
        {
            bail!("a breakpoint already exists at owned address {address:#x}");
        }
        let set = self
            .engine
            .set_breakpoint(&BreakpointSpec::code(BreakpointAt::Address(address)))
            .map_err(debugger)?;
        if set.cut_short.is_some()
            || set.breakpoint.kind != BreakpointKind::Code
            || set.breakpoint.address != Some(address)
            || !set.breakpoint.enabled
            || !set.replaced.is_empty()
        {
            bail!("DbgEng did not create the requested owned code breakpoint");
        }
        self.state.breakpoint = Some(OwnedBreakpoint {
            id: set.breakpoint.id,
            address,
            original,
        });
        Ok(())
    }

    fn remove_owned_breakpoint(&mut self) -> Result<()> {
        let owned = self
            .state
            .breakpoint
            .as_ref()
            .context("the adapter owns no breakpoint to remove")?;
        let still_owned = self
            .engine
            .breakpoints()
            .map_err(debugger)?
            .into_iter()
            .find(|breakpoint| breakpoint.id == owned.id)
            .context("the owned breakpoint disappeared before removal")?;
        if still_owned.address != Some(owned.address) || still_owned.kind != BreakpointKind::Code {
            bail!("the owned breakpoint id was reused or changed");
        }
        self.engine.remove_breakpoint(owned.id).map_err(debugger)?;
        if self
            .engine
            .read_memory(owned.address, owned.original.len())
            .map_err(debugger)?
            != owned.original
        {
            bail!("original bytes were not restored after breakpoint removal");
        }
        self.state.breakpoint = None;
        Ok(())
    }

    fn verify_site(&self, site: &DispatcherSite) -> Result<()> {
        let address = self.site_address(site)?;
        let bytes = self
            .engine
            .read_memory(address, site.original.len())
            .map_err(debugger)?;
        if bytes != site.original {
            bail!("dispatcher site byte guard does not match at {address:#x}");
        }
        Ok(())
    }

    fn require_site(&self, site: &DispatcherSite) -> Result<()> {
        let expected = self.site_address(site)?;
        let actual = self.engine.instruction_pointer().map_err(debugger)?;
        if actual != expected {
            bail!("debugger stopped at {actual:#x}, expected {expected:#x}");
        }
        Ok(())
    }

    fn site_address(&self, site: &DispatcherSite) -> Result<u64> {
        self.image(site.rva.0)
    }

    fn image(&self, rva: u64) -> Result<u64> {
        self.state
            .vmwp_base
            .context("the vmwp image base is unknown")?
            .checked_add(rva)
            .context("vmwp image address overflowed")
    }

    fn scratch(&self, offset: u32) -> Result<u64> {
        self.state
            .profile
            .scratch_base
            .0
            .checked_add(u64::from(offset))
            .context("callback scratch address overflowed")
    }

    fn restore_retained_event(&mut self, event: &HeldEvent) -> Result<()> {
        let retained = self
            .state
            .retained_event
            .as_ref()
            .filter(|retained| &retained.event == event)
            .cloned()
            .context("the dispatcher has no retained thread for the named event")?;
        self.engine
            .execute_command(&format!("~~[{:x}]s", retained.system_id))
            .map_err(debugger)?;
        let selected = self.engine.current_thread_system_id().map_err(debugger)?;
        if selected != retained.system_id {
            bail!(
                "reselected vmwp thread {selected:#x}, expected {:#x}",
                retained.system_id
            );
        }
        let actual = self.engine.instruction_pointer().map_err(debugger)?;
        self.state.phase = DispatcherPhase::Holding(event.clone());
        if actual != retained.return_ip {
            bail!(
                "held vmwp thread moved to {actual:#x}, expected event site {:#x}",
                retained.return_ip
            );
        }
        Ok(())
    }

    fn register(&self, name: &str) -> Result<u64> {
        let register = self
            .engine
            .register_values()
            .map_err(debugger)?
            .into_iter()
            .find(|register| register.name.eq_ignore_ascii_case(name))
            .with_context(|| format!("DbgEng omitted register {name}"))?;
        match register.value {
            RegisterValue::Int(value) => Ok(value),
            _ => bail!("DbgEng register {name} is not an integer"),
        }
    }

    fn write_register(&self, name: &'static str, value: u64) -> Result<()> {
        if !matches!(name, "rax" | "rcx" | "rdx" | "r8" | "r9" | "rip") {
            bail!("{name} is not an adapter-owned writable register");
        }
        self.engine
            .execute_command(&format!("r {name}={value:016x}"))
            .map_err(debugger)?;
        if self.register(name)? != value {
            bail!("DbgEng did not verify the write to {name}");
        }
        Ok(())
    }

    fn read_u8(&self, address: u64) -> Result<u8> {
        Ok(self.engine.read_memory(address, 1).map_err(debugger)?[0])
    }

    fn read_u32(&self, address: u64) -> Result<u32> {
        let bytes = self.engine.read_memory(address, 4).map_err(debugger)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u64(&self, address: u64) -> Result<u64> {
        let bytes = self.engine.read_memory(address, 8).map_err(debugger)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn write_u64(&self, address: u64, value: u64) -> Result<()> {
        self.engine
            .execute_command(&format!("eq {address:016x} {value:016x}"))
            .map_err(debugger)?;
        if self.read_u64(address)? != value {
            bail!("DbgEng did not verify the write at {address:#x}");
        }
        Ok(())
    }

    fn detach_handled(&mut self) -> Result<()> {
        self.engine
            .execute_command(".detach /h")
            .map_err(debugger)?;
        self.state.attached = false;
        self.state.phase = DispatcherPhase::Detached;
        Ok(())
    }

    fn free_unregistered_scratch(&mut self) -> Result<()> {
        if !self.state.attached {
            verify_vmwp_pid(self.bound_vm_id()?, self.state.vmwp_pid)?;
            let pending = self
                .engine
                .attach_process_begin(self.state.vmwp_pid)
                .map_err(debugger)?;
            self.state.attached = true;
            pending.wait().map_err(debugger)?;
        }
        let scratch = self.state.profile.scratch_base.0;
        self.engine
            .execute_command(&format!(".dvfree {scratch:016x} 0"))
            .map_err(debugger)?;
        if self.engine.read_memory(scratch, 1).is_ok() {
            bail!("unregistered callback scratch remained readable after .dvfree");
        }
        self.state.scratch_allocated = false;
        self.detach_handled()
    }

    fn bound_vm_id(&self) -> Result<&str> {
        Ok(&self
            .state
            .targets
            .first()
            .context("the dispatcher target is not bound")?
            .vm_id)
    }
}

fn debugger(error: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("DbgEng: {error}")
}

fn same_path(left: &str, right: &std::path::Path) -> bool {
    std::path::Path::new(left)
        .canonicalize()
        .ok()
        .zip(right.canonicalize().ok())
        .is_some_and(|(left, right)| left == right)
}

#[derive(Clone, Copy, Debug)]
enum VmAction {
    VerifyPid(u32),
    Pause,
    Resume,
}

fn verify_vmwp_pid(vm_id: &str, pid: u32) -> Result<()> {
    run_vm_action(vm_id, VmAction::VerifyPid(pid), POWERSHELL_WAIT)
}

fn run_vm_action(vm_id: &str, action: VmAction, timeout: Duration) -> Result<()> {
    let script = match action {
        VmAction::VerifyPid(_) => {
            "$ErrorActionPreference='Stop'; $id=$env:WINDBG_MCP_SK_VM_ID; \
             $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$env:WINDBG_MCP_SK_VMWP_PID); \
             if($null -eq $p -or $p.Name -ne 'vmwp.exe' -or \
                $p.CommandLine -notmatch [regex]::Escape($id)){throw 'PID does not own the selected VM'}"
        }
        VmAction::Pause => {
            "$ErrorActionPreference='Stop'; \
             $vm=Get-VM -Id ([guid]$env:WINDBG_MCP_SK_VM_ID) -ErrorAction Stop; \
             if($vm.State.ToString() -eq 'Running'){Suspend-VM -VM $vm -ErrorAction Stop} \
             elseif($vm.State.ToString() -ne 'Paused'){throw ('cannot pause VM from '+$vm.State)}; \
             if((Get-VM -Id $vm.VMId).State.ToString() -ne 'Paused'){throw 'VM did not pause'}"
        }
        VmAction::Resume => {
            "$ErrorActionPreference='Stop'; \
             $vm=Get-VM -Id ([guid]$env:WINDBG_MCP_SK_VM_ID) -ErrorAction Stop; \
             if($vm.State.ToString() -eq 'Paused'){Resume-VM -VM $vm -ErrorAction Stop} \
             elseif($vm.State.ToString() -ne 'Running'){throw ('cannot resume VM from '+$vm.State)}; \
             if((Get-VM -Id $vm.VMId).State.ToString() -ne 'Running'){throw 'VM did not resume'}"
        }
    };
    let mut command = Command::new("powershell.exe");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("WINDBG_MCP_SK_VM_ID", vm_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(crate::engine::without_a_console_window());
    if let VmAction::VerifyPid(pid) = action {
        command.env("WINDBG_MCP_SK_VMWP_PID", pid.to_string());
    }
    crate::client::strip_credentials(&mut command);
    let mut child = {
        let _guard = crate::engine::spawn_guard();
        command
            .spawn()
            .context("spawning Hyper-V PowerShell helper")?
    };
    wait_child(&mut child, timeout, action)
}

fn wait_child(child: &mut Child, timeout: Duration, action: VmAction) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    let _ = pipe.read_to_string(&mut stdout);
                }
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                if status.success() {
                    return Ok(());
                }
                bail!(
                    "Hyper-V PowerShell helper {action:?} failed ({status}): stdout={stdout:?}; stderr={stderr:?}"
                );
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("Hyper-V PowerShell helper {action:?} exceeded {timeout:?}");
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("waiting for Hyper-V PowerShell helper");
            }
        }
    }
}

struct VmTransition {
    cancel: mpsc::Sender<()>,
    result: mpsc::Receiver<Result<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl VmTransition {
    fn immediate(vm_id: String, action: VmAction) -> Self {
        Self::spawn(vm_id, Duration::ZERO, move |vm_id| {
            run_vm_action(vm_id, action, POWERSHELL_WAIT)
        })
    }

    fn completion_kick(vm_id: String) -> Self {
        Self::spawn(vm_id, COMPLETION_KICK_AFTER, |vm_id| {
            run_vm_action(vm_id, VmAction::Pause, POWERSHELL_WAIT)?;
            run_vm_action(vm_id, VmAction::Resume, POWERSHELL_WAIT)
        })
    }

    fn spawn(
        vm_id: String,
        delay: Duration,
        operation: impl FnOnce(&str) -> Result<()> + Send + 'static,
    ) -> Self {
        let (cancel_tx, cancel_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = match cancel_rx.recv_timeout(delay) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => Ok(()),
                Err(mpsc::RecvTimeoutError::Timeout) => operation(&vm_id),
            };
            let _ = result_tx.send(result);
        });
        Self {
            cancel: cancel_tx,
            result: result_rx,
            thread: Some(thread),
        }
    }

    fn finish(mut self) -> Result<()> {
        let _ = self.cancel.send(());
        let result = self
            .result
            .recv_timeout(POWERSHELL_WAIT + POWERSHELL_WAIT + Duration::from_secs(5))
            .context("Hyper-V transition helper did not finish")?;
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow!("Hyper-V transition helper panicked"))?;
        }
        result
    }

    #[cfg(test)]
    fn completed_for_test(result: Result<()>) -> Self {
        let (cancel, cancel_rx) = mpsc::channel();
        drop(cancel_rx);
        let (result_tx, result_rx) = mpsc::channel();
        result_tx.send(result).unwrap();
        Self {
            cancel,
            result: result_rx,
            thread: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sklive::DispatcherLayout;

    #[test]
    fn acceptance_request_keeps_the_runtime_vnd_out_of_the_build_profile() {
        let args = [
            "--profile",
            r"C:\private\profile.json",
            "--control-transport",
            "provider --control",
            "--live-transport",
            "provider --memory",
            "--vmwp-pid",
            "4242",
            "--dispatcher-vnd",
            "0x200000001000",
            "--vm-id",
            "11111111-2222-3333-4444-555555555555",
            "--partition-id",
            "0x27",
            "--expected-cr3",
            "0x3456000",
            "--instruction-address",
            "0xfffff80001234560",
            "--instruction-bytes",
            "0f 1f 44 00 00",
        ]
        .map(str::to_string);
        let request = AcceptanceRequest::parse(&args).unwrap();

        assert_eq!(request.open.vmwp_pid, 4242);
        assert_eq!(request.open.dispatcher_vnd, 0x200000001000);
        assert_eq!(request.open.target.partition_id, HexU64(0x27));
        assert_eq!(request.instruction.bytes, [0x0f, 0x1f, 0x44, 0, 0]);
        assert!(
            !serde_json::to_string(&profile())
                .unwrap()
                .contains("dispatcher_vnd")
        );
    }

    #[test]
    fn concrete_live_adapter_refuses_fan_out_before_loading_a_profile() {
        let mut additional = target();
        additional.vp = 1;
        let request = OpenRequest {
            profile: r"Z:\definitely-missing\profile.json".into(),
            control_transport: "provider --vp 0".into(),
            live_transport: "memory-provider".into(),
            vmwp_pid: 4242,
            dispatcher_vnd: 0x2000_0000_1000,
            target: target(),
            additional_vps: vec![AdditionalVp {
                control_transport: "provider --vp 1".into(),
                target: additional,
            }],
        };

        let error = match Session::open(&request) {
            Ok(_) => panic!("multi-provider concrete session unexpectedly opened"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("exactly one selected VP"));
    }

    #[test]
    fn profile_addresses_are_checked_before_the_engine_is_borrowed() {
        let mut profile = profile();
        profile.scratch_base = HexU64(u64::MAX - 0x7ff);
        assert!(profile.validate().is_err());
    }

    #[test]
    fn a_detached_registered_dispatcher_reattaches_before_the_next_arm() {
        assert_eq!(
            DispatcherPhase::Detached.arm_preparation().unwrap(),
            ArmPreparation::Reattach
        );
        assert_eq!(
            DispatcherPhase::Fresh.arm_preparation().unwrap(),
            ArmPreparation::OpenAndRegister
        );
        assert!(DispatcherPhase::Closed.arm_preparation().is_err());
    }

    #[test]
    fn a_matched_event_remains_owned_for_recovery_before_validation_finishes() {
        let event = HeldEvent {
            message_type: HexU64(EVENT_TYPE_VECTOR_1),
            vector: 1,
            vp: 0,
            vtl: 1,
            cpl: 0,
            dispatcher_context: HexU64(0x2000_0000_2000),
            advance_instruction_pointer: false,
            reason: StopReason::HardwareBreakpoint { slot: 0 },
        };

        assert_eq!(
            DispatcherPhase::Holding(event.clone()).held_event(),
            Some(&event)
        );
        assert_eq!(
            DispatcherPhase::ReturningCallback(event.clone()).held_event(),
            Some(&event)
        );
        assert_eq!(
            DispatcherPhase::ReturningHandle(event.clone()).held_event(),
            Some(&event)
        );
        assert_eq!(
            DispatcherPhase::ReturningNative(event.clone()).held_event(),
            Some(&event)
        );
        assert!(DispatcherPhase::ReadyForStop.held_event().is_none());
    }

    #[test]
    fn provider_stop_requires_the_selected_vp_event() {
        let event = HeldEvent {
            message_type: HexU64(EVENT_TYPE_VECTOR_1),
            vector: 1,
            vp: 1,
            vtl: 1,
            cpl: 0,
            dispatcher_context: HexU64(0x2000_0000_2000),
            advance_instruction_pointer: false,
            reason: StopReason::DebugException,
        };
        let mut state =
            VmwpDispatcherState::new(profile(), 4242, 0x2000_0000_1000, "provider".into()).unwrap();
        state.phase = DispatcherPhase::Holding(event.clone());
        state.retained_event = Some(RetainedEvent {
            system_id: 0x1234,
            return_ip: 0x2000_0000_3000,
            event,
        });
        let mut selected = target();
        selected.vp = 1;

        state
            .confirm_retained_provider_stop(std::slice::from_ref(&selected))
            .unwrap();

        assert!(!state.vm_paused);
        assert!(state.provider_writes_quiesced);
        selected.vp = 0;
        assert!(state.confirm_retained_provider_stop(&[selected]).is_err());
    }

    #[test]
    fn a_successful_registration_context_is_owned_before_cleanup_can_fail() {
        let mut state =
            VmwpDispatcherState::new(profile(), 4242, 0x2000_0000_1000, "provider".into()).unwrap();

        assert!(state.record_handler_context(0).is_err());
        state.record_handler_context(0x2000_0000_2000).unwrap();
        assert_eq!(state.handler_context, Some(0x2000_0000_2000));
        assert!(state.record_handler_context(0x2000_0000_3000).is_err());
    }

    #[test]
    fn a_failed_completion_kick_retains_conservative_pause_ownership() {
        let mut state =
            VmwpDispatcherState::new(profile(), 4242, 0x2000_0000_1000, "provider".into()).unwrap();
        state.completion_kick = Some(VmTransition::completed_for_test(Err(anyhow!(
            "Resume-VM failed after Suspend-VM"
        ))));
        state.vm_paused = true;
        state.provider_writes_quiesced = true;

        let error = state.finish_completion_kick().unwrap_err();

        assert!(error.to_string().contains("conservatively retained"));
        assert!(state.vm_paused);
        assert!(!state.provider_writes_quiesced);
        assert!(state.completion_kick.is_none());
    }

    #[test]
    fn pause_ownership_is_claimed_with_the_exact_target_before_suspend() {
        let mut state =
            VmwpDispatcherState::new(profile(), 4242, 0x2000_0000_1000, "provider".into()).unwrap();
        let target = target();

        state.claim_vm_pause(std::slice::from_ref(&target)).unwrap();

        assert_eq!(state.targets, vec![target.clone()]);
        assert!(state.vm_paused);
        assert!(!state.provider_writes_quiesced);
        state.confirm_vm_pause().unwrap();
        assert!(state.provider_writes_quiesced);
        let mut other = target.clone();
        other.expected_cr3 = HexU64(0x120_2000);
        assert!(state.claim_vm_pause(&[other]).is_err());
        assert_eq!(state.targets, vec![target]);
    }

    #[test]
    fn incomplete_registration_is_contained_before_recovery_can_detach() {
        let mut state =
            VmwpDispatcherState::new(profile(), 4242, 0x2000_0000_1000, "provider".into()).unwrap();
        state.phase = DispatcherPhase::Registering;

        let error = state.refuse_unsafe_recovery().unwrap_err();

        assert!(error.to_string().contains("registration did not reach"));
        assert!(matches!(state.phase, DispatcherPhase::Contained(_)));
        assert!(state.refuse_unsafe_recovery().is_err());
    }

    #[test]
    fn unproved_unregister_contains_but_proved_cleanup_remains_retryable() {
        let mut state =
            VmwpDispatcherState::new(profile(), 4242, 0x2000_0000_1000, "provider".into()).unwrap();
        state.unregister = Some(UnregisterProgress::Calling);

        assert!(state.refuse_unsafe_recovery().is_err());
        assert!(matches!(state.phase, DispatcherPhase::Contained(_)));

        let mut cleanup =
            VmwpDispatcherState::new(profile(), 4242, 0x2000_0000_1000, "provider".into()).unwrap();
        cleanup.phase = DispatcherPhase::Detached;
        cleanup.unregister = Some(UnregisterProgress::WaitingCleanup);
        let error = cleanup.refuse_unsafe_recovery().unwrap_err();
        assert!(error.to_string().contains("cleanup is incomplete"));
        assert!(matches!(cleanup.phase, DispatcherPhase::Detached));
    }

    #[test]
    fn a_proved_unfreed_unregister_scratch_allocation_becomes_retryable() {
        let mut state =
            VmwpDispatcherState::new(profile(), 4242, 0x2000_0000_1000, "provider".into()).unwrap();
        state.handler_context = Some(0x2000_0000_2000);
        state.scratch_allocated = true;
        state.unregister = Some(UnregisterProgress::FreeingScratch);

        state.retry_unregister_scratch_free().unwrap();

        assert_eq!(
            state.unregister,
            Some(UnregisterProgress::ReadyToFreeScratch)
        );
        assert_eq!(state.handler_context, Some(0x2000_0000_2000));
        assert!(state.scratch_allocated);
        assert!(state.retry_unregister_scratch_free().is_err());
    }

    fn target() -> TargetIdentity {
        TargetIdentity {
            vm_id: "11111111-2222-3333-4444-555555555555".into(),
            partition_id: HexU64(0x85),
            vp: 0,
            vtl: 1,
            expected_cr3: HexU64(0x120_1000),
        }
    }

    fn profile() -> DispatcherProfile {
        let site = |rva| DispatcherSite {
            rva: HexU64(rva),
            original: vec![0x90],
        };
        DispatcherProfile {
            schema: "windbg-mcp.sk-live-dispatcher-profile.v1".into(),
            vmwp_image: r"C:\Windows\System32\vmwp.exe".into(),
            vmwp_sha256: "A".repeat(64),
            vmwp_size_of_image: 0x30_0000,
            scratch_base: HexU64(0x2000_0000_0000),
            scratch_size: 0x1000,
            registration_tag: HexU64(0x4b34_4155_544f_5354),
            register_handler_rva: HexU64(0x1000),
            unregister_handler_rva: HexU64(0x2000),
            callback_stub_rva: HexU64(0x3000),
            callback_resume_rva: HexU64(0x4000),
            event_held: site(0x5000),
            callback_entry: site(0x6000),
            handle_return: site(0x7000),
            native_return: site(0x8000),
            deferred_cleanup: site(0x9000),
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
}
