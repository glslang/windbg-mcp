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
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use dbgscope::dbgeng::{
    BreakpointAt, BreakpointKind, BreakpointSpec, DebugEngine, Interruption, PendingTarget,
    RegisterValue, WaitOutcome,
};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_ALL_AMD64, CONTEXT_FULL_AMD64, GetThreadContext, SetThreadContext,
};
use windows_sys::Win32::System::Threading::CreateMutexW;
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
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

fn completion_wait_deadline(outer: Option<Instant>) -> Instant {
    outer.unwrap_or_else(|| {
        let now = Instant::now();
        now.checked_add(Duration::from_millis(u64::from(DEBUG_WAIT)))
            .unwrap_or(now)
    })
}

fn require_completion_deadline(deadline: Option<Instant>) -> Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        bail!("the absolute Secure Kernel pause bound expired during dispatcher completion");
    }
    Ok(())
}

fn require_retention_deadline(deadline: Option<Instant>) -> Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        bail!("the absolute Secure Kernel pause bound expired during retention cleanup");
    }
    Ok(())
}

fn debug_wait_remaining(deadline: Instant, activity: Option<&WaitActivity>) -> Duration {
    activity.map_or_else(
        || deadline.saturating_duration_since(Instant::now()),
        WaitActivity::remaining_idle,
    )
}

fn wait_for_process_attach(
    engine: &DebugEngine,
    pending: PendingTarget<'_>,
    pid: u32,
    deadline: Option<Instant>,
) -> Result<()> {
    let Some(deadline) = deadline else {
        return pending.wait().map_err(debugger);
    };
    loop {
        require_completion_deadline(Some(deadline))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = remaining.as_millis().clamp(1, u128::from(u32::MAX)) as u32;
        match engine.wait_for_event(timeout).map_err(debugger)? {
            WaitOutcome::Stopped {
                process: Some((_, system_pid)),
            } if system_pid == pid => return Ok(()),
            WaitOutcome::Stopped { .. } => {}
            WaitOutcome::Expired | WaitOutcome::Deadline => {
                bail!("the absolute Secure Kernel pause bound expired while attaching to vmwp")
            }
            WaitOutcome::OnRequest => bail!("the vmwp attach was interrupted on request"),
        }
    }
}

/// One complete live-control session. Both halves remain on the worker engine thread; each method
/// creates only a short-lived borrow tying the dispatcher state to that thread's engine.
pub(crate) struct Session {
    control: Option<LiveControl<crate::skcontrol::ControlProcess>>,
    dispatcher: VmwpDispatcherState,
    pending: Option<PendingControl>,
    preparation_failed: Option<String>,
    max_pause_ms: u64,
    _reservation: VmReservation,
}

struct VmReservation(HANDLE);

impl VmReservation {
    fn acquire(vm_id: &str) -> Result<Self> {
        let mut name = format!(
            "Global\\windbg-mcp-secure-kernel-{}",
            vm_id.to_ascii_lowercase()
        )
        .encode_utf16()
        .collect::<Vec<_>>();
        name.push(0);
        // SAFETY: the name is NUL-terminated and the returned handle is owned by this object.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("creating the cross-process Secure Kernel controller reservation");
        }
        // SAFETY: read immediately after CreateMutexW on this thread as required by Win32.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: the non-null handle was returned above.
            unsafe { CloseHandle(handle) };
            bail!(
                "another process already reserves Secure Kernel control for VM {vm_id}; do not \
                 attach a second live-control or KD facade"
            );
        }
        Ok(Self(handle))
    }
}

impl Drop for VmReservation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is the non-null handle returned by CreateMutexW.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct PendingControl {
    control_transport: String,
    live_transport: String,
    target: TargetRequest,
    allow_transition_cr3: bool,
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
        let reservation = VmReservation::acquire(&request.target.vm_id)?;
        let profile = DispatcherProfile::load(&request.profile)?;
        let dispatcher = VmwpDispatcherState::new(
            profile,
            request.vmwp_pid,
            request.dispatcher_vnd,
            request.target.vm_id.clone(),
        )?;
        Ok((
            Self {
                control: None,
                dispatcher,
                pending: Some(PendingControl {
                    control_transport: request.control_transport.clone(),
                    live_transport: request.live_transport.clone(),
                    target: request.target.clone(),
                    allow_transition_cr3: request.allow_transition_cr3,
                }),
                preparation_failed: None,
                max_pause_ms: request.max_pause_ms,
                _reservation: reservation,
            },
            Vec::new(),
        ))
    }

    pub(crate) fn phase(&self) -> LivePhase {
        if self.preparation_failed.is_some() {
            LivePhase::Faulted
        } else {
            self.control
                .as_ref()
                .map(LiveControl::phase)
                .unwrap_or(LivePhase::Running)
        }
    }

    pub(crate) fn max_pause_ms(&self) -> u64 {
        self.max_pause_ms
    }

    pub(crate) fn stopped(&self) -> Option<&StopRecord> {
        self.control.as_ref().and_then(LiveControl::stopped)
    }

    pub(crate) fn kernel_base(&self) -> Option<u64> {
        self.dispatcher
            .memory
            .as_ref()
            .and_then(|memory| memory.source.kernel_base())
    }

    pub(crate) fn secure_kernel_kd(&self) -> Option<crate::sklive::SecureKernelKdProfile> {
        self.dispatcher.profile.secure_kernel_kd.clone()
    }

    /// Complete worker-owned discovery before the KD facade resolves its build-relative first
    /// stop. `arm` calls the same idempotent preparation path for the ordinary live tools.
    pub(crate) fn prepare_for_kd(&mut self, engine: &DebugEngine) -> Result<Vec<String>> {
        let skipped = self.prepare(engine)?;
        let target = self.control()?.selected_target().clone();
        self.dispatcher.open_memory(&target)?;
        Ok(skipped)
    }

    fn prepare(&mut self, engine: &DebugEngine) -> Result<Vec<String>> {
        self.ensure_preparation_succeeded()?;
        let Some(pending) = self.pending.take() else {
            return Ok(Vec::new());
        };
        let prepared = self.prepare_pending(engine, pending);
        if let Err(error) = &prepared {
            self.preparation_failed = Some(format!("{error:#}"));
        }
        prepared
    }

    fn prepare_pending(
        &mut self,
        engine: &DebugEngine,
        pending: PendingControl,
    ) -> Result<Vec<String>> {
        let found = {
            let mut dispatcher = self.dispatcher.bind(engine);
            dispatcher.prepare_identity(pending.target.partition_id.map(|value| value.0))?
        };
        let partial = TargetIdentity {
            vm_id: pending.target.vm_id.clone(),
            partition_id: HexU64(found.partition_id),
            vp: pending.target.vp,
            vtl: 1,
            expected_cr3: pending.target.expected_cr3.unwrap_or(HexU64(0x1000)),
        };
        let control_transport = expand_target_command(
            &pending.control_transport,
            &partial,
            pending.target.expected_cr3.is_some(),
        )?;
        let (provider, skipped) = crate::skcontrol::ControlProcess::spawn_selected(
            &control_transport,
            crate::skcontrol::TargetSelector {
                vm_id: pending.target.vm_id.clone(),
                partition_id: HexU64(found.partition_id),
                vp: pending.target.vp,
                expected_cr3: pending.target.expected_cr3,
            },
        )?;
        let target = provider.target().clone();
        let live_transport = expand_target_command(&pending.live_transport, &target, true)?;
        self.dispatcher
            .bind_identity(found, live_transport, &target)?;
        let control = LiveControl::open_with_transition(provider, pending.allow_transition_cr3)?;
        self.control = Some(control);
        Ok(skipped
            .into_iter()
            .map(|line| format!("VP {}: {line}", target.vp))
            .collect())
    }

    fn ensure_preparation_succeeded(&self) -> Result<()> {
        if let Some(error) = &self.preparation_failed {
            bail!(
                "live Secure Kernel target preparation failed earlier: {error}; call \
                 `end_session` before attempting another operation"
            );
        }
        Ok(())
    }

    fn control(&self) -> Result<&LiveControl<crate::skcontrol::ControlProcess>> {
        self.ensure_preparation_succeeded()?;
        self.control
            .as_ref()
            .context("live Secure Kernel control has not completed target discovery")
    }

    fn control_mut(&mut self) -> Result<&mut LiveControl<crate::skcontrol::ControlProcess>> {
        self.ensure_preparation_succeeded()?;
        self.control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")
    }

    pub(crate) fn arm(
        &mut self,
        engine: &DebugEngine,
        breakpoints: Vec<BreakpointGuard>,
        mode: ArmMode,
    ) -> Result<LiveTransition> {
        let _skipped = self.prepare(engine)?;
        self.ensure_preparation_succeeded()?;
        let control = self
            .control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")?;
        let mut dispatcher = self.dispatcher.bind(engine);
        let epoch = control.arm(&mut dispatcher, breakpoints, mode)?;
        Ok(LiveTransition {
            phase: control.phase(),
            epoch,
        })
    }

    pub(crate) fn wait_for_stop(&mut self, engine: &DebugEngine) -> Result<StopRecord> {
        self.ensure_preparation_succeeded()?;
        let control = self
            .control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")?;
        let mut dispatcher = self.dispatcher.bind(engine);
        control.wait_for_stop(&mut dispatcher)
    }

    /// Wait while exposing only the lifetime of the owned DbgEng wait to a transport thread.
    ///
    /// The transport may use that fact to deliver DbgEng's documented cross-thread
    /// `SetInterrupt`. It cannot reach the engine, dispatcher state or live-control providers.
    pub(crate) fn wait_for_stop_interruptible(
        &mut self,
        engine: &DebugEngine,
        activity: &WaitActivity,
    ) -> Result<StopRecord> {
        self.ensure_preparation_succeeded()?;
        self.dispatcher.wait_activity = Some(activity.clone());
        let control = self
            .control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")?;
        let result = {
            let mut dispatcher = self.dispatcher.bind(engine);
            control.wait_for_stop(&mut dispatcher)
        };
        activity.finish();
        self.dispatcher.wait_activity = None;
        result
    }

    pub(crate) fn step(
        &mut self,
        engine: &DebugEngine,
        epoch: &crate::skcontrol::StopEpoch,
        guard: crate::sklive::StepGuard,
    ) -> Result<LiveTransition> {
        self.ensure_preparation_succeeded()?;
        let control = self
            .control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")?;
        let mut dispatcher = self.dispatcher.bind(engine);
        let epoch = control.step(&mut dispatcher, epoch, guard)?;
        Ok(LiveTransition {
            phase: control.phase(),
            epoch,
        })
    }

    pub(crate) fn step_until(
        &mut self,
        engine: &DebugEngine,
        epoch: &crate::skcontrol::StopEpoch,
        guard: crate::sklive::StepGuard,
        deadline: Instant,
    ) -> Result<LiveTransition> {
        self.ensure_preparation_succeeded()?;
        let control = self
            .control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")?;
        let mut dispatcher = self.dispatcher.bind(engine);
        let epoch = control.step_until(&mut dispatcher, epoch, guard, deadline)?;
        Ok(LiveTransition {
            phase: control.phase(),
            epoch,
        })
    }

    pub(crate) fn continue_from(
        &mut self,
        engine: &DebugEngine,
        epoch: &crate::skcontrol::StopEpoch,
    ) -> Result<LiveTransition> {
        self.ensure_preparation_succeeded()?;
        let control = self
            .control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")?;
        let mut dispatcher = self.dispatcher.bind(engine);
        let epoch = control.continue_from(&mut dispatcher, epoch)?;
        Ok(LiveTransition {
            phase: control.phase(),
            epoch,
        })
    }

    pub(crate) fn read_memory(&self, address: u64, size: u32) -> Result<LiveMemoryRead> {
        self.read_memory_inner(address, size, None)
    }

    pub(crate) fn read_memory_until(
        &self,
        address: u64,
        size: u32,
        deadline: Instant,
    ) -> Result<LiveMemoryRead> {
        self.read_memory_inner(address, size, Some(deadline))
    }

    fn read_memory_inner(
        &self,
        address: u64,
        size: u32,
        deadline: Option<Instant>,
    ) -> Result<LiveMemoryRead> {
        crate::sksession::readable(address, size).map_err(anyhow::Error::msg)?;
        let stop = self
            .control()?
            .stopped()
            .context("live VTL1 memory can be read only while the session is stopped")?;
        self.dispatcher
            .read_memory(stop.epoch.clone(), address, size, deadline)
    }

    pub(crate) fn continue_to_breakpoints_until(
        &mut self,
        engine: &DebugEngine,
        epoch: &crate::skcontrol::StopEpoch,
        breakpoints: Vec<BreakpointGuard>,
        deadline: Instant,
    ) -> Result<LiveTransition> {
        self.ensure_preparation_succeeded()?;
        let control = self
            .control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")?;
        let mut dispatcher = self.dispatcher.bind(engine);
        let epoch =
            control.continue_to_breakpoints_until(&mut dispatcher, epoch, breakpoints, deadline)?;
        Ok(LiveTransition {
            phase: control.phase(),
            epoch,
        })
    }

    pub(crate) fn read_stopped_registers_until(
        &mut self,
        epoch: &crate::skcontrol::StopEpoch,
        registers: Vec<crate::skcontrol::RegisterName>,
        deadline: Instant,
    ) -> Result<Vec<crate::skcontrol::RegisterValue>> {
        self.control_mut()?
            .read_stopped_registers_until(epoch, registers, deadline)
    }

    pub(crate) fn close(&mut self, engine: &DebugEngine) -> Result<()> {
        self.close_inner(engine, None)
    }

    pub(crate) fn close_until(&mut self, engine: &DebugEngine, deadline: Instant) -> Result<()> {
        self.close_inner(engine, Some(deadline))
    }

    fn close_inner(&mut self, engine: &DebugEngine, deadline: Option<Instant>) -> Result<()> {
        let deadline = deadline.or(self.dispatcher.recovery_deadline);
        let mut dispatcher = self.dispatcher.bind(engine);
        if let Some(control) = self.control.as_mut() {
            match deadline {
                Some(deadline) => control.close_until(&mut dispatcher, deadline),
                None => control.close(&mut dispatcher),
            }
        } else {
            match deadline {
                Some(deadline) => dispatcher.teardown_until(deadline),
                None => dispatcher.teardown(),
            }
        }
    }
}

/// Substitute only target coordinates discovered or checked by this worker. Keeping expansion here
/// prevents an MCP client from turning an unverified value into a privileged child argument before
/// the provider and memory source are bound to the same identity.
fn expand_target_command(
    command: &str,
    target: &TargetIdentity,
    cr3_known: bool,
) -> Result<String> {
    let mut words = crate::livesrc::split_command(command);
    if words.is_empty() {
        bail!("the provider command line is empty");
    }
    for argument in words.iter_mut().skip(1) {
        *argument = argument
            .replace("{vp}", &target.vp.to_string())
            .replace("{partition_id}", &format!("0x{:x}", target.partition_id.0));
    }
    if cr3_known {
        for argument in words.iter_mut().skip(1) {
            *argument = argument.replace("{cr3}", &format!("0x{:x}", target.expected_cr3.0));
        }
    } else if words
        .iter()
        .skip(1)
        .any(|argument| argument.contains("{cr3}"))
    {
        bail!(
            "the provider command uses {{cr3}}, but no CR3 assertion was supplied; the provider \
             must discover CR3 and report it in its hello"
        );
    }
    Ok(crate::skpolicy::render_transport(&words))
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpenRequest {
    pub(crate) profile: std::path::PathBuf,
    pub(crate) control_transport: String,
    pub(crate) live_transport: String,
    pub(crate) vmwp_pid: u32,
    pub(crate) dispatcher_vnd: Option<u64>,
    pub(crate) target: TargetRequest,
    /// Absolute operator-fixed bound for one arm/stop/step lifecycle.
    pub(crate) max_pause_ms: u64,
    #[serde(default)]
    pub(crate) allow_transition_cr3: bool,
    #[serde(default)]
    pub(crate) additional_vps: Vec<AdditionalVp>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetRequest {
    pub(crate) vm_id: String,
    pub(crate) partition_id: Option<HexU64>,
    pub(crate) vp: u32,
    pub(crate) expected_cr3: Option<HexU64>,
}

impl TargetRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        TargetIdentity {
            vm_id: self.vm_id.clone(),
            partition_id: self.partition_id.unwrap_or(HexU64(1)),
            vp: self.vp,
            vtl: 1,
            expected_cr3: self.expected_cr3.unwrap_or(HexU64(0x1000)),
        }
        .validate()
    }
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
            .field("dispatcher_vnd", &self.dispatcher_vnd.map(HexU64))
            .field("target", &self.target)
            .field("max_pause_ms", &self.max_pause_ms)
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
        let mut arm_mode = ArmMode::Natural;
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
        let vm_id = vm_id.context(live_control_usage())?;
        let vmwp_pid = match vmwp_pid {
            Some(pid) => pid,
            None => resolve_vmwp_pid(&vm_id, None)?,
        };
        let target = TargetRequest {
            vm_id,
            partition_id: partition_id.map(HexU64),
            vp,
            expected_cr3: expected_cr3.map(HexU64),
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
                vmwp_pid,
                dispatcher_vnd,
                target,
                max_pause_ms: 600_000,
                allow_transition_cr3: false,
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
     --vm-id <guid> \
     --instruction-address <number> --instruction-bytes <hex> \
     [--arm-mode <redirect|natural>] [--vp <number>] \
     [--vmwp-pid <assertion>] [--dispatcher-vnd <assertion>] \
     [--partition-id <assertion>] [--expected-cr3 <assertion>]"
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
    validation_complete: bool,
    release_eligible: bool,
}

pub(crate) struct VmwpDispatcherState {
    profile: DispatcherProfile,
    vmwp_pid: u32,
    vm_id: String,
    dispatcher_vnd: Option<u64>,
    discovered_identity: Option<DiscoveredIdentity>,
    identity_discovered: bool,
    live_transport: Option<String>,
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
    /// Absolute end of the cleanup reserve for the current stop. It outlives the retained event,
    /// because native completion consumes that event before later detach or VM-resume work can
    /// fail and leave teardown retryable.
    recovery_deadline: Option<Instant>,
    completion_kick: Option<VmTransition>,
    unregister: Option<UnregisterProgress>,
    /// Present only for the KD facade's current running wait. It exposes no DbgEng object.
    wait_activity: Option<WaitActivity>,
}

impl VmwpDispatcherState {
    pub(crate) fn new(
        profile: DispatcherProfile,
        vmwp_pid: u32,
        dispatcher_vnd: Option<u64>,
        vm_id: String,
    ) -> Result<Self> {
        profile.validate()?;
        if vmwp_pid == 0 {
            bail!("vmwp_pid must be nonzero");
        }
        if dispatcher_vnd == Some(0) {
            bail!("dispatcher_vnd assertion must be nonzero");
        }
        TargetRequest {
            vm_id: vm_id.clone(),
            partition_id: None,
            vp: 0,
            expected_cr3: None,
        }
        .validate()?;
        Ok(Self {
            profile,
            vmwp_pid,
            vm_id,
            dispatcher_vnd,
            discovered_identity: None,
            identity_discovered: false,
            live_transport: None,
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
            recovery_deadline: None,
            completion_kick: None,
            unregister: None,
            wait_activity: None,
        })
    }

    pub(crate) fn bind<'a>(&'a mut self, engine: &'a DebugEngine) -> VmwpDispatcher<'a> {
        VmwpDispatcher {
            engine,
            state: self,
        }
    }

    fn bind_identity(
        &mut self,
        found: DiscoveredIdentity,
        live_transport: String,
        target: &TargetIdentity,
    ) -> Result<()> {
        if live_transport.trim().is_empty() {
            bail!("the live-memory transport command line is empty");
        }
        if !target.vm_id.eq_ignore_ascii_case(&self.vm_id)
            || target.partition_id.0 != found.partition_id
        {
            bail!("provider identity does not match the worker-discovered VM partition");
        }
        self.dispatcher_vnd = Some(found.dispatcher_vnd);
        self.discovered_identity = Some(found);
        self.identity_discovered = true;
        self.live_transport = Some(live_transport);
        Ok(())
    }

    fn open_memory(&mut self, target: &TargetIdentity) -> Result<()> {
        if self.memory.is_none() {
            self.memory = Some(LiveGuestMemory::open(
                self.live_transport
                    .as_deref()
                    .context("the live-memory transport has not been bound")?,
                target,
            )?);
        }
        Ok(())
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

    fn freeze_other_threads(&mut self, mut execute: impl FnMut(&str) -> Result<()>) -> Result<()> {
        if self.threads_frozen {
            bail!("vmwp threads are already frozen");
        }
        execute("~* f")?;
        // The first command changed debugger state, so cleanup owns that state even
        // when selecting the current thread fails.
        self.threads_frozen = true;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            "dispatcher froze all vmwp threads for a guarded native call"
        );
        if let Err(primary) = execute("~# u") {
            let thawed = execute("~* u");
            if thawed.is_ok() {
                self.threads_frozen = false;
                tracing::info!(
                    target: "windbg_mcp::secure_kernel_mutation",
                    "dispatcher released its vmwp thread freezes after partial setup"
                );
            }
            return match thawed {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(anyhow!(
                    "{primary:#}; releasing the partially frozen vmwp threads also failed: \
                     {cleanup:#}"
                )),
            };
        }
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            "dispatcher released the current vmwp thread for its guarded native call"
        );
        Ok(())
    }

    fn finish_discovery_call_cleanup(&mut self, returned: bool) {
        self.threads_frozen = false;
        if returned {
            self.phase = DispatcherPhase::Fresh;
        }
    }

    fn claim_created_breakpoint(
        &mut self,
        created: CreatedBreakpoint,
        requested_address: u64,
        original: Vec<u8>,
    ) -> Result<()> {
        if self.breakpoint.is_some() {
            bail!("the adapter already owns a breakpoint");
        }
        // DbgEng has already created this id. Claim it before rejecting any read-back field so
        // recovery cannot detach while an untracked breakpoint remains in the session.
        self.breakpoint = Some(OwnedBreakpoint {
            id: created.id,
            address: requested_address,
            original,
        });
        if created.replaced {
            let why = "DbgEng replaced a pre-existing breakpoint while creating the owned one; \
                       the displaced debugger state cannot be reconstructed, so vmwp remains \
                       contained"
                .to_string();
            self.phase = DispatcherPhase::Contained(why.clone());
            bail!(why);
        }
        if created.cut_short
            || created.kind != BreakpointKind::Code
            || created.address != Some(requested_address)
            || !created.enabled
        {
            bail!("DbgEng did not create the requested owned code breakpoint");
        }
        Ok(())
    }

    fn claim_vm_pause(&mut self, targets: &[TargetIdentity]) -> Result<()> {
        if !self.targets.is_empty() && self.targets != targets {
            bail!("the dispatcher adapter is already bound to another target");
        }
        if targets
            .iter()
            .any(|target| !target.vm_id.eq_ignore_ascii_case(&self.vm_id))
        {
            bail!("the dispatcher target does not match the reserved VM");
        }
        self.targets = targets.to_vec();
        // Claim this before Suspend-VM: a helper timeout or failed final verification cannot tell
        // whether the VM changed state, so recovery must conservatively issue Resume-VM.
        self.vm_paused = true;
        self.provider_writes_quiesced = false;
        Ok(())
    }

    fn claim_discovery_pause(&mut self) -> Result<()> {
        if !self.targets.is_empty() {
            bail!("target discovery must complete before the dispatcher binds a provider");
        }
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
        if matches!(
            self.retained_event,
            Some(RetainedEvent {
                release_eligible: false,
                ..
            })
        ) {
            let why =
                "the retained native event failed validation; vmwp remains contained".to_string();
            self.phase = DispatcherPhase::Contained(why.clone());
            bail!("{why}");
        }
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
            DispatcherPhase::Discovering | DispatcherPhase::Registering => {
                let operation = if matches!(self.phase, DispatcherPhase::Discovering) {
                    "partition discovery"
                } else {
                    "handler registration"
                };
                let why = format!(
                    "{operation} did not reach and restore its return boundary; the VM remains \
                     paused with vmwp contained"
                )
                .to_string();
                self.phase = DispatcherPhase::Contained(why.clone());
                bail!("{why}");
            }
            DispatcherPhase::Contained(why) => bail!("the dispatcher is fail-closed: {why}"),
            _ => Ok(()),
        }
    }

    fn finish_completion_kick(&mut self) -> Result<()> {
        self.finish_completion_kick_until(None)
    }

    fn finish_completion_kick_until(&mut self, deadline: Option<Instant>) -> Result<()> {
        let Some(kick) = self.completion_kick.as_mut() else {
            return Ok(());
        };
        let result = kick.finish_until(deadline);
        if kick.finished() {
            self.completion_kick = None;
        }
        if let Err(error) = result {
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
        deadline: Option<Instant>,
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
            .read_span_until(at, size as usize, "stopped live VTL1 memory read", deadline)
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

const WAIT_ARMED: u8 = 0;
const WAIT_ACTIVE: u8 = 1;
const WAIT_FINISHED: u8 = 2;

/// Cross-thread observation of the exact interval in which DbgEng waits for the owned vmwp site.
///
/// This carries no engine interface. The KD transport pairs it with an `InterruptHandle`, whose
/// sole operation is the repository's documented `SetInterrupt` exception.
#[derive(Clone)]
pub(crate) struct WaitActivity(Arc<WaitActivityState>);

struct WaitActivityState {
    phase: AtomicU8,
    scope_gate: Mutex<()>,
    last_traffic: Mutex<Instant>,
    idle_timeout: Duration,
    managed_job: Option<u64>,
    pause_bound: Option<Duration>,
    recovery_bound: Option<Duration>,
    retained_since: Mutex<Option<Instant>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitActivityPhase {
    Armed,
    Active,
    Finished,
}

impl WaitActivity {
    #[cfg(test)]
    pub(crate) fn new(idle_timeout: Duration) -> Self {
        Self::with_options(idle_timeout, None, None, None)
    }

    pub(crate) fn for_kd(
        idle_timeout: Duration,
        pause_bound: Duration,
        recovery_bound: Duration,
    ) -> Self {
        Self::with_options(idle_timeout, Some(pause_bound), Some(recovery_bound), None)
    }

    pub(crate) fn for_managed_kd(
        idle_timeout: Duration,
        pause_bound: Duration,
        recovery_bound: Duration,
        job: u64,
    ) -> Self {
        Self::with_options(
            idle_timeout,
            Some(pause_bound),
            Some(recovery_bound),
            Some(job),
        )
    }

    fn with_options(
        idle_timeout: Duration,
        pause_bound: Option<Duration>,
        recovery_bound: Option<Duration>,
        managed_job: Option<u64>,
    ) -> Self {
        debug_assert!(
            pause_bound
                .zip(recovery_bound)
                .is_none_or(|(pause, recovery)| pause <= recovery)
        );
        Self(Arc::new(WaitActivityState {
            phase: AtomicU8::new(WAIT_ARMED),
            scope_gate: Mutex::new(()),
            last_traffic: Mutex::new(Instant::now()),
            idle_timeout,
            managed_job,
            pause_bound,
            recovery_bound,
            retained_since: Mutex::new(None),
        }))
    }

    fn mark_stop_retained(&self, since: Instant) -> Option<Instant> {
        let bound = self.0.pause_bound?;
        let mut retained = self
            .0
            .retained_since
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let since = *retained.get_or_insert(since);
        Some(since.checked_add(bound).unwrap_or(since))
    }

    pub(crate) fn retained_since(&self) -> Option<Instant> {
        *self
            .0
            .retained_since
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn pause_deadline(&self) -> Option<Instant> {
        let since = self.retained_since()?;
        Some(since.checked_add(self.0.pause_bound?).unwrap_or(since))
    }

    fn recovery_deadline(&self) -> Option<Instant> {
        let since = self.retained_since()?;
        Some(since.checked_add(self.0.recovery_bound?).unwrap_or(since))
    }

    pub(crate) fn phase(&self) -> WaitActivityPhase {
        match self.0.phase.load(Ordering::Acquire) {
            WAIT_ARMED => WaitActivityPhase::Armed,
            WAIT_ACTIVE => WaitActivityPhase::Active,
            WAIT_FINISHED => WaitActivityPhase::Finished,
            _ => unreachable!("WaitActivity stores only declared phases"),
        }
    }

    pub(crate) fn finish(&self) {
        let _scope = self
            .0
            .scope_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.0.phase.store(WAIT_FINISHED, Ordering::Release);
    }

    pub(crate) fn while_active<T>(&self, operation: impl FnOnce() -> T) -> Option<T> {
        let _scope = self
            .0
            .scope_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        (self.0.phase.load(Ordering::Acquire) == WAIT_ACTIVE).then(operation)
    }

    pub(crate) fn same_wait(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(crate) fn note_traffic(&self) {
        *self
            .0
            .last_traffic
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Instant::now();
    }

    pub(crate) fn remaining_idle(&self) -> Duration {
        self.0.idle_timeout.saturating_sub(
            self.0
                .last_traffic
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .elapsed(),
        )
    }

    fn enter(&self) -> Result<WaitActivityGuard> {
        let scope = self
            .0
            .scope_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.0.phase.load(Ordering::Acquire) != WAIT_ARMED {
            bail!("the interruptible DbgEng wait was entered more than once");
        }
        let managed = match self.0.managed_job {
            Some(job) => match crate::worker::begin_kd_wait(job) {
                Some(guard) => Some(guard),
                None => {
                    self.0.phase.store(WAIT_FINISHED, Ordering::Release);
                    bail!("the managed Secure Kernel KD session is ending");
                }
            },
            None => None,
        };
        // Publish the interruptible phase only after the worker's binding guard exists. The scope
        // gate also prevents a transport interrupt from racing the closing transition below.
        self.0.phase.store(WAIT_ACTIVE, Ordering::Release);
        drop(scope);
        Ok(WaitActivityGuard {
            activity: self.clone(),
            managed,
        })
    }
}

struct WaitActivityGuard {
    activity: WaitActivity,
    managed: Option<crate::worker::KdWaitGuard>,
}

impl Drop for WaitActivityGuard {
    fn drop(&mut self) {
        // Stop transport interrupts, waiting out one already inside the scope gate, before
        // releasing the worker's binding guard. The published interval is therefore wholly
        // contained by the owned DbgEng wait.
        self.activity.finish();
        drop(self.managed.take());
    }
}

#[derive(Clone, Debug)]
enum DispatcherPhase {
    Fresh,
    Discovering,
    Registering,
    ReadyForStop,
    /// The event-site breakpoint remained armed until a deadline or scoped request interrupted
    /// ordinary vmwp execution. This is the only no-event stop that may detach before Suspend-VM.
    ReadyForStopInterrupted,
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

#[derive(Clone, Copy, Debug)]
struct CreatedBreakpoint {
    id: u32,
    kind: BreakpointKind,
    address: Option<u64>,
    enabled: bool,
    cut_short: bool,
    replaced: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DiscoveredIdentity {
    dispatcher_vnd: u64,
    partition_handle: u64,
    partition_id: u64,
}

#[cfg(target_arch = "x86_64")]
struct HijackContext {
    thread: HANDLE,
    context: CONTEXT,
}

#[cfg(not(target_arch = "x86_64"))]
struct HijackContext;

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
        Self::new_until(source, operation, Instant::now() + LIVE_MEMORY_WAIT)
    }

    fn new_until(
        source: &'a crate::livesrc::LiveSource,
        operation: &'a str,
        outer_deadline: Instant,
    ) -> Self {
        Self {
            source,
            operation,
            deadline: outer_deadline.min(Instant::now() + LIVE_MEMORY_WAIT),
            expired: std::cell::Cell::new(false),
        }
    }

    fn require_within_deadline(&self) -> Result<()> {
        if self.expired.get() || Instant::now() >= self.deadline {
            self.expired.set(true);
            bail!("{} reached its deadline", self.operation);
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
        let result = self.source.read_chunk_until_cancelled(
            gpa,
            out,
            self.deadline,
            crate::worker::kd_teardown_requested,
        );
        if Instant::now() >= self.deadline {
            self.expired.set(true);
        }
        result
    }
}

impl LiveGuestMemory {
    fn open(command: &str, target: &TargetIdentity) -> Result<Self> {
        let source = crate::livesrc::LiveSource::spawn(command)?;
        let provider = crate::livesrc::split_command(command)
            .into_iter()
            .next()
            .unwrap_or_else(|| "<empty>".to_string());
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vm_id = %target.vm_id,
            vp = target.vp,
            provider = %provider,
            "started the operator-authorized Secure Kernel memory provider"
        );
        let kernel_base = source.kernel_base();
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
        let memory = Self {
            source,
            root,
            space,
        };
        if let Some(kernel_base) = kernel_base {
            memory.validate_kernel_base(kernel_base)?;
        }
        Ok(memory)
    }

    fn refresh(&mut self) -> Result<()> {
        self.space = Self::walk_space(&self.source, self.root, "refresh")?;
        Ok(())
    }

    fn refresh_until(&mut self, deadline: Instant) -> Result<()> {
        self.space = Self::walk_space_until(&self.source, self.root, "refresh", Some(deadline))?;
        Ok(())
    }

    fn bind_root(&mut self, cr3: u64) -> Result<()> {
        self.bind_root_inner(cr3, None)
    }

    fn bind_root_until(&mut self, cr3: u64, deadline: Instant) -> Result<()> {
        self.bind_root_inner(cr3, Some(deadline))
    }

    fn bind_root_inner(&mut self, cr3: u64, deadline: Option<Instant>) -> Result<()> {
        if cr3 == 0 || cr3 & 0xfff != 0 {
            bail!("live VTL1 stop CR3 must be nonzero and page aligned");
        }
        let root = sk::Gpa(cr3);
        self.space = Self::walk_space_until(&self.source, root, "stop-CR3 rebind", deadline)?;
        self.root = root;
        Ok(())
    }

    fn walk_space(
        source: &crate::livesrc::LiveSource,
        root: sk::Gpa,
        operation: &str,
    ) -> Result<sk::AddressSpace> {
        Self::walk_space_until(source, root, operation, None)
    }

    fn walk_space_until(
        source: &crate::livesrc::LiveSource,
        root: sk::Gpa,
        operation: &str,
        deadline: Option<Instant>,
    ) -> Result<sk::AddressSpace> {
        let description = format!("live VTL1 page-table {operation}");
        let source = match deadline {
            Some(deadline) => DeadlineLiveSource::new_until(source, &description, deadline),
            None => DeadlineLiveSource::new(source, &description),
        };
        let reader = sk::Reader::new(&source);
        let (leaves, stats) = sk::walk(&reader, root);
        source.require_within_deadline()?;
        if !stats.complete() {
            bail!("live VTL1 page-table {operation} was incomplete: {stats:?}");
        }
        Ok(sk::AddressSpace::new(leaves))
    }

    fn read_span(&self, at: sk::Gva, size: usize, operation: &str) -> Result<Vec<u8>> {
        self.read_span_until(at, size, operation, None)
    }

    fn read_span_until(
        &self,
        at: sk::Gva,
        size: usize,
        operation: &str,
        deadline: Option<Instant>,
    ) -> Result<Vec<u8>> {
        let source = match deadline {
            Some(deadline) => DeadlineLiveSource::new_until(&self.source, operation, deadline),
            None => DeadlineLiveSource::new(&self.source, operation),
        };
        let reader = sk::Reader::new(&source);
        let result = sk::Space::new(&reader, &self.space).read_span(at, size);
        source.require_within_deadline()?;
        result.map_err(|why| anyhow!("{why:?}"))
    }

    fn read_guard_until(
        &self,
        guard: &InstructionGuard,
        deadline: Option<Instant>,
    ) -> Result<InstructionGuard> {
        let bytes = self
            .read_span_until(
                sk::Gva(guard.address.0),
                guard.bytes.len(),
                "live VTL1 instruction guard read",
                deadline,
            )
            .map_err(|why| anyhow!("reading guarded VTL1 instruction failed: {why:?}"))?;
        Ok(InstructionGuard {
            address: guard.address,
            bytes,
        })
    }

    fn validate_kernel_base(&self, kernel_base: u64) -> Result<()> {
        if kernel_base & (sk::PAGE - 1) != 0 {
            bail!("live-memory source kernel_base must be page aligned");
        }
        let header = self
            .read_span(
                sk::Gva(kernel_base),
                sk::PAGE as usize,
                "Secure Kernel image-header validation",
            )
            .map_err(|why| {
                anyhow!(
                    "reading the provider-reported Secure Kernel base {kernel_base:#x} failed: \
                     {why}"
                )
            })?;
        let identity = sk::pe_identity(&header).with_context(|| {
            format!(
                "provider-reported Secure Kernel base {kernel_base:#x} does not contain a PE64 \
                 image"
            )
        })?;
        if identity.machine != 0x8664 || identity.size_of_image == 0 {
            bail!(
                "provider-reported Secure Kernel base {kernel_base:#x} contains an unexpected PE \
                 identity (machine={:#x}, size={:#x})",
                identity.machine,
                identity.size_of_image
            );
        }
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
impl HijackContext {
    fn capture(dispatcher: &VmwpDispatcher<'_>) -> Result<Self> {
        let system_id = dispatcher
            .engine
            .current_thread_system_id()
            .map_err(debugger)?;
        // SAFETY: the numeric thread id came from the attached engine target. The handle is closed
        // by Drop, and this object never leaves the worker's engine thread.
        let thread = unsafe {
            OpenThread(
                THREAD_GET_CONTEXT
                    | THREAD_SET_CONTEXT
                    | THREAD_QUERY_INFORMATION
                    | THREAD_SUSPEND_RESUME,
                0,
                system_id,
            )
        };
        if thread.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("opening the stopped vmwp thread for context preservation");
        }
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_ALL_AMD64,
            ..Default::default()
        };
        // SAFETY: `thread` has THREAD_GET_CONTEXT, the debugger has the target stopped, and
        // `context` is a correctly sized writable x64 CONTEXT whose flags request legacy state.
        if unsafe { GetThreadContext(thread, &mut context) } == 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: this is the non-null handle returned by OpenThread above.
            unsafe { CloseHandle(thread) };
            return Err(error).context("capturing the stopped vmwp thread context");
        }
        Ok(Self { thread, context })
    }

    fn restore(&self) -> Result<()> {
        // A debugger event prevents execution, but it is not a Win32 suspend count. Windows may
        // reject SetThreadContext with ERROR_NOACCESS unless the selected thread is explicitly
        // suspended. Take one count around the complete Set/Get verification and always give
        // exactly that count back; any count another owner held remains in place.
        // SAFETY: capture opened this handle with THREAD_SUSPEND_RESUME and the thread remains in
        // the attached vmwp process.
        if unsafe { SuspendThread(self.thread) } == u32::MAX {
            return Err(std::io::Error::last_os_error())
                .context("suspending the stopped vmwp thread for context restoration");
        }
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            "dispatcher added a temporary vmwp thread suspend for context restoration"
        );
        let restored = (|| {
            // The call can change control, integer and floating-point state. It cannot change
            // segment selectors or debug registers; Windows rejects writing those protected
            // classes on this vmwp thread with ERROR_NOACCESS. Keep them in the saved CONTEXT and
            // the complete verification below, but ask SetThreadContext to write only the state
            // execution could have changed.
            let mut writable = self.context;
            writable.ContextFlags = CONTEXT_FULL_AMD64;
            // SAFETY: the explicitly suspended thread and context captured above remain owned
            // here; no other worker thread can access either.
            if unsafe { SetThreadContext(self.thread, &writable) } == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("restoring the stopped vmwp thread context");
            }
            let mut observed = CONTEXT {
                ContextFlags: CONTEXT_ALL_AMD64,
                ..Default::default()
            };
            // SAFETY: identical handle and buffer requirements to capture().
            if unsafe { GetThreadContext(self.thread, &mut observed) } == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("verifying the restored vmwp thread context");
            }
            if let Some((offset, expected, actual)) = context_difference(&self.context, &observed) {
                bail!(
                    "the restored vmwp thread context first differed at byte {offset:#x}: expected \
                     {expected:#04x}, observed {actual:#04x}"
                );
            }
            tracing::info!(
                target: "windbg_mcp::secure_kernel_mutation",
                "dispatcher restored and verified the hijacked vmwp thread context"
            );
            Ok(())
        })();
        // SAFETY: balances the successful SuspendThread above, including on every error path.
        let resumed = if unsafe { ResumeThread(self.thread) } == u32::MAX {
            Err(std::io::Error::last_os_error())
                .context("releasing the vmwp thread after context restoration")
        } else {
            tracing::info!(
                target: "windbg_mcp::secure_kernel_mutation",
                "dispatcher released its temporary vmwp thread suspend"
            );
            Ok(())
        };
        match (restored, resumed) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(restore), Err(resume)) => Err(anyhow!(
                "{restore:#}; releasing the vmwp thread also failed: {resume:#}"
            )),
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for HijackContext {
    fn drop(&mut self) {
        // SAFETY: this is the non-null handle returned by OpenThread in capture().
        unsafe { CloseHandle(self.thread) };
    }
}

#[cfg(target_arch = "x86_64")]
fn context_bytes(context: &CONTEXT) -> &[u8] {
    // SAFETY: CONTEXT is a plain C data structure and the returned slice cannot outlive it.
    unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(context).cast::<u8>(),
            std::mem::size_of::<CONTEXT>(),
        )
    }
}

#[cfg(target_arch = "x86_64")]
fn context_difference(expected: &CONTEXT, observed: &CONTEXT) -> Option<(usize, u8, u8)> {
    let eflags = std::mem::offset_of!(CONTEXT, EFlags);
    context_bytes(expected)
        .iter()
        .copied()
        .zip(context_bytes(observed).iter().copied())
        .enumerate()
        .find_map(|(offset, (expected, actual))| {
            // GetThreadContext reports the architecturally fixed EFLAGS bit 1 set on the
            // original stop, while a Set/Get round trip can report that reserved bit clear.
            // It is not mutable processor state, so normalize only that bit and retain the
            // byte-for-byte check for every other part of the x64 CONTEXT.
            let mask = if offset == eflags { !0x02 } else { u8::MAX };
            ((expected & mask) != (actual & mask)).then_some((offset, expected, actual))
        })
}

#[cfg(not(target_arch = "x86_64"))]
impl HijackContext {
    fn capture(_dispatcher: &VmwpDispatcher<'_>) -> Result<Self> {
        bail!("vmwp partition discovery requires an x64 worker")
    }

    fn restore(&self) -> Result<()> {
        bail!("vmwp partition discovery requires an x64 worker")
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
                self.state
                    .memory
                    .as_mut()
                    .context("the live VTL1 memory source is absent")?
                    .bind_root(target.expected_cr3.0)?;
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

    fn begin_disarm(&mut self, targets: &[TargetIdentity]) -> Result<()> {
        targets
            .first()
            .context("running disarm requires at least one selected VP")?;
        if self.state.targets != targets
            || !matches!(self.state.phase, DispatcherPhase::ReadyForStop)
            || self.state.retained_event.is_some()
            || !self.state.attached
            || self.state.breakpoint.is_none()
        {
            bail!("running disarm requires the armed target set with no retained event");
        }

        // Suspend-VM can block behind an attached DbgEng target even when no native event exists.
        // Stop vmwp with the ordinary watchdog, remove the exact owned breakpoint, and detach
        // before asking Hyper-V to pause. Reattach only after that pause proves provider-write
        // quiescence; teardown still owns the registered callback and scratch allocation.
        self.settle_native_completion(None)?;
        self.pause_armed_without_event(targets)
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
        self.establish_recovery_pause_inner(targets, None)
    }

    fn establish_recovery_pause_until(
        &mut self,
        targets: &[TargetIdentity],
        deadline: Instant,
    ) -> Result<()> {
        self.establish_recovery_pause_inner(targets, Some(deadline))
    }

    fn verify_instruction(&mut self, instruction: &InstructionGuard) -> Result<()> {
        VmwpDispatcher::verify_instruction(self, instruction)
    }

    fn verify_instruction_until(
        &mut self,
        instruction: &InstructionGuard,
        deadline: Instant,
    ) -> Result<()> {
        VmwpDispatcher::verify_instruction_until(self, instruction, deadline)
    }

    fn retained_pause_deadline(&self) -> Option<Instant> {
        self.state
            .wait_activity
            .as_ref()
            .and_then(WaitActivity::pause_deadline)
    }

    fn retained_recovery_deadline(&self) -> Option<Instant> {
        self.state.recovery_deadline.or_else(|| {
            self.state
                .wait_activity
                .as_ref()
                .and_then(WaitActivity::recovery_deadline)
        })
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
        // The callback is held as soon as the owned breakpoint returns. Start the absolute budget
        // before any retention cleanup, including a pending Hyper-V transition join.
        let retained_at = Instant::now();
        let pause_deadline = self
            .state
            .wait_activity
            .as_ref()
            .and_then(|activity| activity.mark_stop_retained(retained_at));
        self.retain_current_event(event_pointer, event_site, &event, pause_deadline)?;
        self.state.vm_paused = false;
        self.state.confirm_retained_provider_stop(targets)?;
        let memory = self
            .state
            .memory
            .as_mut()
            .context("the live VTL1 memory source is absent")?;
        match pause_deadline {
            Some(deadline) => memory.refresh_until(deadline)?,
            None => memory.refresh()?,
        }
        let observed_instructions = instructions
            .iter()
            .map(|instruction| memory.read_guard_until(instruction, pause_deadline))
            .collect::<Result<Vec<_>>>()?;
        Ok(ObservedStop {
            event,
            instructions: observed_instructions,
        })
    }

    fn bind_stop_cr3(&mut self, cr3: u64) -> Result<()> {
        self.state
            .memory
            .as_mut()
            .context("the live VTL1 memory source is absent")?
            .bind_root(cr3)
    }

    fn bind_stop_cr3_until(&mut self, cr3: u64, deadline: Instant) -> Result<()> {
        self.state
            .memory
            .as_mut()
            .context("the live VTL1 memory source is absent")?
            .bind_root_until(cr3, deadline)
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
        self.complete_event(mode, None)
    }

    fn release_event_until(
        &mut self,
        event: &HeldEvent,
        mode: ReleaseMode,
        deadline: Instant,
    ) -> Result<()> {
        let retained = self
            .state
            .retained_event
            .as_ref()
            .map(|retained| &retained.event)
            .context("the dispatcher owns no event to release")?;
        if retained != event {
            bail!("release does not name the event held by the dispatcher");
        }
        self.complete_event(mode, Some(deadline))
    }

    fn recover(&mut self, safe_to_resume: bool, event: Option<&HeldEvent>) -> Result<()> {
        self.recover_inner(safe_to_resume, event, None)
    }

    fn recover_until(
        &mut self,
        safe_to_resume: bool,
        event: Option<&HeldEvent>,
        deadline: Instant,
    ) -> Result<()> {
        self.recover_inner(safe_to_resume, event, Some(deadline))
    }

    fn teardown(&mut self) -> Result<()> {
        self.teardown_inner(None)
    }

    fn teardown_until(&mut self, deadline: Instant) -> Result<()> {
        self.teardown_inner(Some(deadline))
    }
}

impl VmwpDispatcher<'_> {
    fn claim_attach(&mut self) {
        self.state.attached = true;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vmwp_pid = self.state.vmwp_pid,
            "dispatcher began an owned debugger attach to vmwp"
        );
    }

    fn set_exception_policy(&self) -> Result<()> {
        self.engine.execute_command("sxd 6ba").map_err(debugger)?;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            exception = "0x6ba",
            "dispatcher changed vmwp's debugger exception policy"
        );
        self.engine
            .execute_command("sxd e06d7363")
            .map_err(debugger)?;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            exception = "0xe06d7363",
            "dispatcher changed vmwp's debugger exception policy"
        );
        Ok(())
    }

    fn thaw_threads(&mut self) -> Result<()> {
        self.engine.execute_command("~* u").map_err(debugger)?;
        self.state.threads_frozen = false;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            "dispatcher released its vmwp thread freezes"
        );
        Ok(())
    }

    fn teardown_inner(&mut self, deadline: Option<Instant>) -> Result<()> {
        require_completion_deadline(deadline)?;
        match &self.state.phase {
            DispatcherPhase::Closed => return Ok(()),
            DispatcherPhase::Contained(why) => {
                bail!("refusing to detach a contained dispatcher: {why}")
            }
            DispatcherPhase::Discovering | DispatcherPhase::Registering => {
                bail!("refusing teardown while a vmwp call is incomplete")
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
            self.unregister_handler_inner(deadline)?;
            return self.finish_teardown(deadline);
        }

        require_completion_deadline(deadline)?;
        if self.state.breakpoint.is_some() {
            self.remove_owned_breakpoint()?;
        }
        require_completion_deadline(deadline)?;
        if self.state.threads_frozen {
            self.thaw_threads()?;
        }
        require_completion_deadline(deadline)?;
        if self.state.attached {
            self.detach_handled()?;
        }
        self.state.finish_completion_kick_until(deadline)?;
        require_completion_deadline(deadline)?;
        if self.state.handler_context.is_some() {
            self.unregister_handler_inner(deadline)?;
        } else if self.state.scratch_allocated {
            self.free_unregistered_scratch_inner(deadline)?;
        }
        self.finish_teardown(deadline)
    }
}

impl VmwpDispatcher<'_> {
    fn establish_recovery_pause_inner(
        &mut self,
        targets: &[TargetIdentity],
        deadline: Option<Instant>,
    ) -> Result<()> {
        if self.state.retained_event.is_some() {
            // A delayed completion kick cannot be joined while its pause request is blocked behind
            // this native event. The event itself is the selected provider's write barrier; safe
            // recovery completes the callback, detaches, and joins the helper in that order.
            return self.state.confirm_retained_provider_stop(targets);
        }
        // A wait may fail while its asynchronous Resume-VM is still outstanding. With no retained
        // event, join that helper before a fresh Suspend-VM proves recovery quiescence. An incomplete
        // callback whose exact thread was not retained remains fail-closed.
        let transition_error = self.state.finish_completion_kick_until(deadline).err();
        let pause = if matches!(self.state.phase, DispatcherPhase::ReadyForStopInterrupted) {
            self.pause_armed_without_event_inner(targets, deadline)
        } else if matches!(
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
            self.pause_for_provider_writes_inner(targets, deadline)
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

    fn recover_inner(
        &mut self,
        safe_to_resume: bool,
        event: Option<&HeldEvent>,
        deadline: Option<Instant>,
    ) -> Result<()> {
        if self
            .state
            .retained_event
            .as_ref()
            .is_some_and(|retained| retained.validation_complete && !retained.release_eligible)
        {
            // A pause deadline may expire while joining the prior completion kick or removing the
            // event-site breakpoint. The event itself was already validated, so recovery may
            // finish that owned cleanup before deciding whether the callback can be released.
            self.prepare_held_event(deadline)?;
            self.state
                .retained_event
                .as_mut()
                .context("the validated native event lost its retained-thread record")?
                .release_eligible = true;
        }
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
            return self.complete_event(ReleaseMode::Resume, deadline);
        }

        require_completion_deadline(deadline)?;
        if self.state.breakpoint.is_some() {
            self.remove_owned_breakpoint()?;
        }
        require_completion_deadline(deadline)?;
        if self.state.threads_frozen {
            self.thaw_threads()?;
        }
        require_completion_deadline(deadline)?;
        if self.state.attached {
            self.detach_handled()?;
        }
        self.state.finish_completion_kick_until(deadline)?;
        if self.state.vm_paused {
            self.state.begin_vm_resume();
            run_vm_action_until(self.bound_vm_id()?, VmAction::Resume, deadline)?;
            self.state.vm_paused = false;
        }
        Ok(())
    }

    fn finish_teardown(&mut self, deadline: Option<Instant>) -> Result<()> {
        require_completion_deadline(deadline)?;
        if self.state.vm_paused {
            self.state.begin_vm_resume();
            run_vm_action_until(self.bound_vm_id()?, VmAction::Resume, deadline)?;
            self.state.vm_paused = false;
        }
        self.state.phase = DispatcherPhase::Closed;
        self.state.recovery_deadline = None;
        Ok(())
    }

    fn prepare_held_event(&mut self, deadline: Option<Instant>) -> Result<()> {
        require_retention_deadline(deadline)?;
        self.state.finish_completion_kick_until(deadline)?;
        require_retention_deadline(deadline)?;
        if self.state.breakpoint.is_some() {
            self.remove_owned_breakpoint()?;
        }
        require_retention_deadline(deadline)?;
        Ok(())
    }

    fn wait_for_owned_event(
        &mut self,
        targets: &[TargetIdentity],
        event_site: u64,
        deadline: Instant,
    ) -> Result<(u64, HeldEvent)> {
        let activity = self.state.wait_activity.clone();
        let _activity = activity.as_ref().map(WaitActivity::enter).transpose()?;
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
            let deadline_expired = self
                .state
                .wait_activity
                .as_ref()
                .map(|activity| activity.remaining_idle().is_zero())
                .unwrap_or_else(|| Instant::now() >= deadline);
            if deadline_expired {
                bail!("too many unrelated dispatcher events before the owned vector-1 event");
            }
        }
    }

    fn retain_current_event(
        &mut self,
        event_pointer: u64,
        event_site: u64,
        event: &HeldEvent,
        deadline: Option<Instant>,
    ) -> Result<()> {
        // Name the native event before any fallible inspection. Once the exact callback thread is
        // known, retain that identity before cleanup so recovery can either complete it or contain
        // vmwp without detaching from an outstanding event.
        self.state.phase = DispatcherPhase::Holding(event.clone());
        let system_id = self.engine.current_thread_system_id().map_err(debugger)?;
        if self.state.retained_event.is_some() {
            bail!("the dispatcher already retains a native event thread");
        }
        let recovery_deadline = self
            .state
            .wait_activity
            .as_ref()
            .and_then(WaitActivity::recovery_deadline);
        self.state.recovery_deadline = recovery_deadline;
        self.state.retained_event = Some(RetainedEvent {
            system_id,
            return_ip: event_site,
            event: event.clone(),
            validation_complete: false,
            release_eligible: false,
        });
        let advance = self.read_u8(
            event_pointer
                .checked_add(u64::from(self.state.profile.layout.exchange_advance))
                .context("event advance address overflowed")?,
        )?;
        if advance != 0 {
            bail!("the native dispatcher event already requests instruction-pointer advance");
        }
        self.state
            .retained_event
            .as_mut()
            .context("the validated native event lost its retained-thread record")?
            .validation_complete = true;
        self.prepare_held_event(deadline)?;
        self.state
            .retained_event
            .as_mut()
            .context("the validated native event lost its retained-thread record")?
            .release_eligible = true;
        Ok(())
    }

    fn pause_for_provider_writes(&mut self, targets: &[TargetIdentity]) -> Result<()> {
        self.pause_for_provider_writes_inner(targets, None)
    }

    fn pause_for_provider_writes_inner(
        &mut self,
        targets: &[TargetIdentity],
        deadline: Option<Instant>,
    ) -> Result<()> {
        let target = targets.first().context("no live-control VP targets")?;
        self.state.finish_completion_kick_until(deadline)?;
        self.state.claim_vm_pause(targets)?;
        run_vm_action_until(&target.vm_id, VmAction::Pause, deadline)?;
        self.state.confirm_vm_pause()
    }

    fn pause_armed_without_event(&mut self, targets: &[TargetIdentity]) -> Result<()> {
        self.pause_armed_without_event_inner(targets, None)
    }

    fn pause_armed_without_event_inner(
        &mut self,
        targets: &[TargetIdentity],
        deadline: Option<Instant>,
    ) -> Result<()> {
        let target = targets
            .first()
            .context("no-event disarm requires at least one selected VP")?;
        if self.state.targets != targets
            || !matches!(
                self.state.phase,
                DispatcherPhase::ReadyForStop | DispatcherPhase::ReadyForStopInterrupted
            )
            || self.state.retained_event.is_some()
            || !self.state.attached
            || self.state.breakpoint.is_none()
        {
            bail!("no-event disarm requires the debugger-stopped armed target set");
        }

        self.remove_owned_breakpoint()?;
        self.detach_handled()?;
        self.state.finish_completion_kick_until(deadline)?;
        self.state.claim_vm_pause(targets)?;
        run_vm_action_until(&target.vm_id, VmAction::Pause, deadline)?;
        self.state.confirm_vm_pause()?;

        require_retention_deadline(deadline)?;
        verify_vmwp_pid(&target.vm_id, self.state.vmwp_pid)?;
        let pending = self
            .engine
            .attach_process_begin(self.state.vmwp_pid)
            .map_err(debugger)?;
        self.claim_attach();
        wait_for_process_attach(self.engine, pending, self.state.vmwp_pid, deadline)?;
        require_retention_deadline(deadline)?;
        self.set_exception_policy()?;
        self.verify_vmwp_build()?;
        self.verify_all_sites()?;
        self.state.phase = DispatcherPhase::ReadyForStop;
        Ok(())
    }

    fn open_and_register(
        &mut self,
        targets: &[TargetIdentity],
        breakpoints: &[BreakpointGuard],
    ) -> Result<()> {
        let target = targets.first().context("no live-control VP targets")?;
        if !self.state.identity_discovered {
            bail!("worker target discovery has not completed");
        }
        self.pause_for_provider_writes(targets)?;
        verify_vmwp_pid(&target.vm_id, self.state.vmwp_pid)?;
        if self.state.memory.is_none() {
            self.state.memory = Some(LiveGuestMemory::open(
                self.state
                    .live_transport
                    .as_deref()
                    .context("the live-memory transport has not been bound")?,
                target,
            )?);
        }
        self.verify_breakpoints(breakpoints)?;
        let pending = self
            .engine
            .attach_process_begin(self.state.vmwp_pid)
            .map_err(debugger)?;
        self.claim_attach();
        pending.wait().map_err(debugger)?;
        self.set_exception_policy()?;

        self.verify_vmwp_build()?;
        self.verify_all_sites()?;
        self.allocate_scratch()?;
        self.register_handler()?;
        let site = self.state.profile.event_held.clone();
        self.set_site_breakpoint(&site)?;
        self.state.phase = DispatcherPhase::ReadyForStop;
        Ok(())
    }

    fn prepare_identity(&mut self, asserted_partition: Option<u64>) -> Result<DiscoveredIdentity> {
        if let Some(found) = self.state.discovered_identity.clone() {
            return Ok(found);
        }
        if self.state.profile.discovery.is_none() {
            let found = DiscoveredIdentity {
                dispatcher_vnd: self
                    .state
                    .dispatcher_vnd
                    .context("a profile without discovery requires a dispatcher_vnd assertion")?,
                partition_handle: 0,
                partition_id: asserted_partition
                    .context("a profile without discovery requires a partition_id assertion")?,
            };
            self.state.discovered_identity = Some(found.clone());
            self.state.identity_discovered = true;
            return Ok(found);
        }

        self.state.claim_discovery_pause()?;
        run_vm_action(&self.state.vm_id, VmAction::Pause, POWERSHELL_WAIT)?;
        self.state.confirm_vm_pause()?;
        self.discover_identity(asserted_partition)
    }

    fn discover_identity(&mut self, asserted_partition: Option<u64>) -> Result<DiscoveredIdentity> {
        let discovery = self
            .state
            .profile
            .discovery
            .clone()
            .context("the dispatcher profile has no discovery site")?;
        verify_vmwp_pid(&self.state.vm_id, self.state.vmwp_pid)?;
        let pending = self
            .engine
            .attach_process_begin(self.state.vmwp_pid)
            .map_err(debugger)?;
        self.claim_attach();
        pending.wait().map_err(debugger)?;
        self.set_exception_policy()?;
        self.verify_vmwp_build()?;
        self.verify_site(&discovery.entry)?;
        self.set_site_breakpoint(&discovery.entry)?;

        self.state.begin_vm_resume();
        let mut transition = VmTransition::immediate(self.state.vm_id.clone(), VmAction::Resume);
        let stop = self.run_to_current_breakpoint(
            Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT)),
        );
        let resumed = transition.finish_until(None);
        match (stop, resumed) {
            (Ok(()), Ok(())) => {
                self.state.vm_paused = false;
            }
            (Err(stop), Ok(())) => return Err(stop),
            (Ok(()), Err(resume)) => return Err(resume),
            (Err(stop), Err(resume)) => bail!(
                "dispatcher discovery did not reach its entry: {stop:#}; the VM transition also \
                 failed: {resume:#}"
            ),
        }
        self.require_site(&discovery.entry)?;
        let dispatcher_pointer = self.register("rcx")?;
        let dispatcher_vnd = self.read_u64(dispatcher_pointer)?;
        let partition_handle = self.register("rdx")?;
        if dispatcher_vnd == 0 || partition_handle == 0 {
            bail!("dispatcher discovery returned a zero VND or partition handle");
        }
        self.remove_owned_breakpoint()?;

        let partition_id = self.call_vid_get_hv_partition_id(partition_handle, &discovery)?;
        let found = DiscoveredIdentity {
            dispatcher_vnd,
            partition_handle,
            partition_id,
        };
        if let Some(asserted_vnd) = self.state.dispatcher_vnd
            && found.dispatcher_vnd != asserted_vnd
        {
            bail!(
                "discovered dispatcher VND {:#x} does not match asserted VND {:#x}",
                found.dispatcher_vnd,
                asserted_vnd
            );
        }
        if let Some(asserted_partition) = asserted_partition
            && found.partition_id != asserted_partition
        {
            bail!(
                "discovered Hyper-V partition {:#x} does not match asserted partition {:#x}",
                found.partition_id,
                asserted_partition
            );
        }
        self.state.dispatcher_vnd = Some(found.dispatcher_vnd);
        self.state.discovered_identity = Some(found.clone());
        self.state.identity_discovered = true;
        self.detach_handled()?;
        self.state.phase = DispatcherPhase::Fresh;
        Ok(found)
    }

    fn call_vid_get_hv_partition_id(
        &mut self,
        partition_handle: u64,
        discovery: &crate::sklive::DispatcherDiscoveryProfile,
    ) -> Result<u64> {
        let export = self.verify_vid_build(discovery)?;
        self.allocate_discovery_scratch()?;
        // Capture before changing debugger freeze state. The target is already stopped, and a
        // capture failure must not leave vmwp threads frozen while no hijack has begun.
        let saved = HijackContext::capture(self)?;
        let engine = self.engine;
        self.state.freeze_other_threads(|command| {
            engine
                .execute_command(command)
                .map(|_| ())
                .map_err(debugger)
        })?;
        self.state.phase = DispatcherPhase::Discovering;
        // From this point every exit goes through the cleanup below. The call temporarily owns
        // the selected thread's context, one dynamic breakpoint and the other threads' freeze.
        let mut returned = false;
        let operation = (|| {
            let return_address = self.read_u64(self.register("rsp")?)?;
            self.set_dynamic_breakpoint(return_address)?;
            self.write_u64(self.state.profile.scratch_base.0, 0)?;
            self.write_register("rcx", partition_handle)?;
            self.write_register("rdx", self.state.profile.scratch_base.0)?;
            self.write_register("rip", export)?;
            self.run_to_current_breakpoint(
                Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT)),
            )?;
            if self.engine.instruction_pointer().map_err(debugger)? != return_address {
                bail!("VidGetHvPartitionId stopped away from its return address");
            }
            returned = true;
            if self.register("rax")? != 1 {
                bail!("VidGetHvPartitionId returned failure");
            }
            let partition_id = self.read_u64(self.state.profile.scratch_base.0)?;
            if partition_id == 0 {
                bail!("VidGetHvPartitionId returned partition zero");
            }
            Ok(partition_id)
        })();

        let restored = saved.restore();
        let breakpoint_cleanup = if self.state.breakpoint.is_some() {
            self.remove_owned_breakpoint()
        } else {
            Ok(())
        };
        let thawed = if restored.is_ok() && breakpoint_cleanup.is_ok() {
            Some(
                self.engine
                    .execute_command("~* u")
                    .map(|_| ())
                    .map_err(debugger),
            )
        } else {
            None
        };
        if matches!(thawed, Some(Ok(()))) {
            // Even when an interrupted call did not return, record that the debugger freeze was
            // released. Keep Discovering in that case so teardown contains vmwp.
            self.state.finish_discovery_call_cleanup(returned);
            tracing::info!(
                target: "windbg_mcp::secure_kernel_mutation",
                "dispatcher released its vmwp thread freezes"
            );
        }

        let mut cleanup_errors = Vec::new();
        if let Err(error) = restored {
            cleanup_errors.push(format!(
                "restoring the hijacked vmwp thread context: {error:#}"
            ));
        }
        if let Err(error) = breakpoint_cleanup {
            cleanup_errors.push(format!(
                "removing the VidGetHvPartitionId return breakpoint: {error:#}"
            ));
        }
        if let Some(Err(error)) = thawed {
            cleanup_errors.push(format!("releasing the frozen vmwp threads: {error:#}"));
        }
        match (operation, cleanup_errors.is_empty()) {
            (Ok(partition_id), true) => Ok(partition_id),
            (Err(error), true) => Err(error),
            (Ok(_), false) => bail!(
                "VidGetHvPartitionId cleanup failed: {}",
                cleanup_errors.join("; ")
            ),
            (Err(error), false) => bail!(
                "VidGetHvPartitionId call failed: {error:#}; cleanup also failed: {}",
                cleanup_errors.join("; ")
            ),
        }
    }

    fn verify_vid_build(
        &self,
        discovery: &crate::sklive::DispatcherDiscoveryProfile,
    ) -> Result<u64> {
        let module = self.engine.module("vid").map_err(debugger)?;
        if module.size != discovery.vid_size_of_image {
            bail!(
                "vid SizeOfImage is {:#x}, profile requires {:#x}",
                module.size,
                discovery.vid_size_of_image
            );
        }
        if !module.loaded_image_name.is_empty()
            && !same_path(&module.loaded_image_name, &discovery.vid_image)
        {
            bail!("DbgEng loaded vid.dll from a different path than the discovery profile");
        }
        let bytes = std::fs::read(&discovery.vid_image).with_context(|| {
            format!(
                "reading profiled vid image {}",
                discovery.vid_image.display()
            )
        })?;
        let actual = crate::client::sha256(&bytes)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        if !actual.eq_ignore_ascii_case(&discovery.vid_sha256) {
            bail!("loaded vid.dll SHA-256 does not match the discovery profile");
        }
        let export_rva = pe_export_rva(&bytes, "VidGetHvPartitionId")?;
        let export = module
            .base
            .checked_add(u64::from(export_rva))
            .context("VidGetHvPartitionId address overflowed")?;
        let end = module
            .base
            .checked_add(u64::from(module.size))
            .context("vid.dll image range overflowed")?;
        if !(module.base..end).contains(&export) {
            bail!("VidGetHvPartitionId resolved outside the verified vid.dll image");
        }
        Ok(export)
    }

    fn allocate_discovery_scratch(&mut self) -> Result<()> {
        let base = self.state.profile.scratch_base.0;
        if self.state.scratch_allocated {
            return Ok(());
        }
        if self.engine.read_memory(base, 1).is_ok() {
            bail!("the requested callback scratch address is already mapped");
        }
        self.engine
            .execute_command(&format!(
                ".dvalloc /b {base:016x} {:x}",
                self.state.profile.scratch_size
            ))
            .map_err(debugger)?;
        self.state.scratch_allocated = true;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            address = format_args!("{base:#x}"),
            size = self.state.profile.scratch_size,
            "dispatcher allocated vmwp discovery scratch"
        );
        self.engine.read_memory(base, 8).map_err(debugger)?;
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
        self.claim_attach();
        pending.wait().map_err(debugger)?;
        self.set_exception_policy()?;
        self.verify_vmwp_build()?;
        self.verify_all_sites()?;
        self.state
            .memory
            .as_mut()
            .context("the live VTL1 memory source is absent")?
            .bind_root(target.expected_cr3.0)?;
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
        self.verify_instruction_inner(instruction, None)
    }

    fn verify_instruction_until(
        &mut self,
        instruction: &InstructionGuard,
        deadline: Instant,
    ) -> Result<()> {
        self.verify_instruction_inner(instruction, Some(deadline))
    }

    fn verify_instruction_inner(
        &mut self,
        instruction: &InstructionGuard,
        deadline: Option<Instant>,
    ) -> Result<()> {
        let memory = self
            .state
            .memory
            .as_mut()
            .context("the live VTL1 memory source is absent")?;
        match deadline {
            Some(deadline) => memory.refresh_until(deadline)?,
            None => memory.refresh()?,
        }
        let observed = memory.read_guard_until(instruction, deadline)?;
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
        if !self.state.scratch_allocated {
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
            tracing::info!(
                target: "windbg_mcp::secure_kernel_mutation",
                address = format_args!("{base:#x}"),
                size = self.state.profile.scratch_size,
                "dispatcher allocated vmwp callback scratch"
            );
        }
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

        let engine = self.engine;
        self.state.freeze_other_threads(|command| {
            engine
                .execute_command(command)
                .map(|_| ())
                .map_err(debugger)
        })?;
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
        self.write_register(
            "rcx",
            self.state
                .dispatcher_vnd
                .context("the dispatcher VND has not been discovered")?,
        )?;
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
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            context = format_args!("{context:#x}"),
            "dispatcher registered its temporary vmwp exception handler"
        );
        self.write_u64(stack_handler, saved_handler)?;
        self.write_u64(stack_context, saved_context)?;
        self.thaw_threads()?;
        self.state.phase = DispatcherPhase::Fresh;
        Ok(())
    }

    fn complete_event(&mut self, mode: ReleaseMode, deadline: Option<Instant>) -> Result<()> {
        require_completion_deadline(deadline)?;
        let event = self
            .state
            .retained_event
            .as_ref()
            .map(|retained| retained.event.clone())
            .context("the dispatcher owns no retained event to complete")?;
        self.complete_retained_event(&event, deadline)?;
        require_completion_deadline(deadline)?;

        match mode {
            ReleaseMode::ArmNextStop => {
                let site = self.state.profile.event_held.clone();
                self.set_site_breakpoint(&site)?;
                self.state.phase = DispatcherPhase::ReadyForStop;
            }
            ReleaseMode::Resume => {
                self.settle_native_completion(deadline)?;
                require_completion_deadline(deadline)?;
                self.detach_handled()?;
                self.state.finish_completion_kick_until(deadline)?;
                if self.state.vm_paused {
                    self.state.begin_vm_resume();
                    run_vm_action_until(self.bound_vm_id()?, VmAction::Resume, deadline)?;
                    self.state.vm_paused = false;
                }
                self.state.phase = DispatcherPhase::Detached;
            }
        }
        self.state.recovery_deadline = None;
        Ok(())
    }

    fn settle_native_completion(&self, deadline: Option<Instant>) -> Result<()> {
        // The native return proves success before vmwp has executed past the call. Let the existing
        // DbgEng watchdog interrupt that ordinary execution, then detach before joining the Hyper-V
        // helper whose pause request is blocked while the callback remains debugger-stopped.
        let remaining = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        if remaining.is_some_and(|remaining| remaining.is_zero()) {
            bail!("the absolute Secure Kernel pause bound expired during dispatcher completion");
        }
        let wait = remaining
            .map(|remaining| remaining.min(Duration::from_millis(u64::from(NATIVE_SETTLE_WAIT))))
            .unwrap_or_else(|| Duration::from_millis(u64::from(NATIVE_SETTLE_WAIT)));
        let timeout = wait.as_millis().clamp(1, u128::from(u32::MAX)) as u32;
        let outer_limited = remaining.is_some_and(|remaining| {
            remaining <= Duration::from_millis(u64::from(NATIVE_SETTLE_WAIT))
        });
        let run = self
            .engine
            .execute_and_wait("g", timeout)
            .map_err(debugger)?;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            "dispatcher resumed vmwp to settle native event completion"
        );
        if run.target_gone {
            bail!("vmwp left the debugger while settling native event completion");
        }
        match run.cut_short {
            Some(Interruption::Deadline { .. }) if !outer_limited => Ok(()),
            Some(Interruption::Deadline { .. }) => {
                bail!("the absolute Secure Kernel pause bound expired during dispatcher completion")
            }
            Some(Interruption::OnRequest) => {
                bail!("native event completion was interrupted on request")
            }
            None => bail!("vmwp stopped unexpectedly while settling native event completion"),
        }
    }

    fn complete_retained_event(
        &mut self,
        event: &HeldEvent,
        deadline: Option<Instant>,
    ) -> Result<()> {
        let phase_event = self.state.phase.held_event();
        if phase_event != Some(event) || matches!(self.state.phase, DispatcherPhase::Holding(_)) {
            self.restore_retained_event(event)?;
        }
        self.complete_event_to_native_return(deadline)?;
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

    fn complete_event_to_native_return(&mut self, deadline: Option<Instant>) -> Result<()> {
        require_completion_deadline(deadline)?;
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
            require_completion_deadline(deadline)?;
            let site = self.state.profile.callback_entry.clone();
            self.set_site_breakpoint(&site)?;
            self.state.phase = DispatcherPhase::ReturningCallback(held.clone());
        }

        if matches!(self.state.phase, DispatcherPhase::ReturningCallback(_)) {
            require_completion_deadline(deadline)?;
            let site = self.state.profile.callback_entry.clone();
            let target = self.require_owned_site_breakpoint(&site)?;
            if self.engine.instruction_pointer().map_err(debugger)? != target {
                self.run_to_current_breakpoint(completion_wait_deadline(deadline))?;
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
            require_completion_deadline(deadline)?;
            let site = self.state.profile.handle_return.clone();
            self.set_site_breakpoint(&site)?;
            // From here recovery owns the installed handle-return breakpoint. Record that before
            // either the RIP write or the wait can fail, so retry does not install it twice.
            self.state.phase = DispatcherPhase::ReturningHandle(held.clone());
        }

        if matches!(self.state.phase, DispatcherPhase::ReturningHandle(_)) {
            require_completion_deadline(deadline)?;
            let entry = self.site_address(&self.state.profile.callback_entry)?;
            let site = self.state.profile.handle_return.clone();
            let target = self.require_owned_site_breakpoint(&site)?;
            let rip = self.engine.instruction_pointer().map_err(debugger)?;
            if rip == entry {
                self.write_register("rip", self.image(self.state.profile.callback_resume_rva.0)?)?;
            }
            if rip != target {
                self.run_to_current_breakpoint(completion_wait_deadline(deadline))?;
            }
            self.require_site(&site)?;
            if self.register("rax")? != 1 {
                bail!("registered callback did not report the event handled");
            }
            self.remove_owned_breakpoint()?;
            self.state.phase = DispatcherPhase::HandleReturn(held.clone());
        }

        if matches!(self.state.phase, DispatcherPhase::HandleReturn(_)) {
            require_completion_deadline(deadline)?;
            let site = self.state.profile.native_return.clone();
            self.set_site_breakpoint(&site)?;
            // The retained breakpoint is recoverable before even resolving the VM coordinate for
            // the completion kick.
            self.state.phase = DispatcherPhase::ReturningNative(held.clone());
        }

        if matches!(self.state.phase, DispatcherPhase::ReturningNative(_)) {
            require_completion_deadline(deadline)?;
            let site = self.state.profile.native_return.clone();
            let target = self.require_owned_site_breakpoint(&site)?;
            if self.state.completion_kick.is_none() {
                self.state.begin_vm_resume();
                self.state.completion_kick = Some(VmTransition::completion_kick(
                    self.bound_vm_id()?.to_string(),
                ));
            }
            if self.engine.instruction_pointer().map_err(debugger)? != target {
                self.run_to_current_breakpoint(completion_wait_deadline(deadline))?;
            }
            self.require_site(&site)?;
            if self.register("rax")? != 1 {
                bail!("native dispatcher completion did not report success");
            }
            self.remove_owned_breakpoint()?;
            self.state.phase = DispatcherPhase::NativeReturn(held.clone());
        }
        require_completion_deadline(deadline)?;
        Ok(())
    }

    fn unregister_handler_inner(&mut self, deadline: Option<Instant>) -> Result<()> {
        require_completion_deadline(deadline)?;
        let context = self.state.handler_context.context("no handler context")?;
        if self.state.unregister.is_none() {
            self.begin_unregister_call(context, deadline)?;
        }
        loop {
            require_completion_deadline(deadline)?;
            match self.state.unregister.clone() {
                Some(UnregisterProgress::Calling) => {
                    bail!("handler unregister return was not proved")
                }
                Some(UnregisterProgress::WaitingCleanup) => {
                    self.wait_for_unregister_cleanup(context, deadline)?
                }
                Some(UnregisterProgress::ReturningCleanup { return_address }) => {
                    self.finish_unregister_cleanup_return(return_address, deadline)?
                }
                Some(UnregisterProgress::CleanupReturned) => {
                    self.settle_unregister_cleanup(context, deadline)?
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

    fn begin_unregister_call(&mut self, context: u64, deadline: Option<Instant>) -> Result<()> {
        require_completion_deadline(deadline)?;
        verify_vmwp_pid(self.bound_vm_id()?, self.state.vmwp_pid)?;
        let pending = self
            .engine
            .attach_process_begin(self.state.vmwp_pid)
            .map_err(debugger)?;
        self.claim_attach();
        wait_for_process_attach(self.engine, pending, self.state.vmwp_pid, deadline)?;
        require_completion_deadline(deadline)?;
        self.verify_vmwp_build()?;
        self.verify_all_sites()?;
        self.set_exception_policy()?;

        let rsp = self.register("rsp")?;
        let return_address = self.read_u64(rsp)?;
        let engine = self.engine;
        self.state.freeze_other_threads(|command| {
            engine
                .execute_command(command)
                .map(|_| ())
                .map_err(debugger)
        })?;
        self.set_dynamic_breakpoint(return_address)?;
        // From the first register mutation until the return value is proved, a failed call cannot
        // be retried or detached: either could complete an unregister whose result we no longer
        // know. Post-return cleanup uses the resumable states below instead.
        self.state.unregister = Some(UnregisterProgress::Calling);
        self.write_register(
            "rcx",
            self.state
                .dispatcher_vnd
                .context("the dispatcher VND has not been discovered")?,
        )?;
        self.write_register("rdx", context)?;
        self.write_register(
            "rip",
            self.image(self.state.profile.unregister_handler_rva.0)?,
        )?;
        self.run_to_current_breakpoint(completion_wait_deadline(deadline))?;
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

    fn wait_for_unregister_cleanup(
        &mut self,
        context: u64,
        deadline: Option<Instant>,
    ) -> Result<()> {
        require_completion_deadline(deadline)?;
        let cleanup = self.state.profile.deferred_cleanup.clone();
        let cleanup_address = self.site_address(&cleanup)?;
        if self.state.breakpoint.is_none() {
            self.set_site_breakpoint(&cleanup)?;
        }
        if self.state.threads_frozen {
            self.thaw_threads()?;
        }
        let wait_deadline = completion_wait_deadline(deadline);
        loop {
            if self.engine.instruction_pointer().map_err(debugger)? == cleanup_address
                && self.register("rcx")? == context
            {
                break;
            }
            self.run_to_current_breakpoint(wait_deadline)?;
            self.require_site(&cleanup)?;
            if Instant::now() >= wait_deadline {
                bail!("deferred cleanup did not reach the registered handler context");
            }
        }
        let cleanup_return = self.read_u64(self.register("rsp")?)?;
        self.state.unregister = Some(UnregisterProgress::ReturningCleanup {
            return_address: cleanup_return,
        });
        Ok(())
    }

    fn finish_unregister_cleanup_return(
        &mut self,
        cleanup_return: u64,
        deadline: Option<Instant>,
    ) -> Result<()> {
        require_completion_deadline(deadline)?;
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
            self.run_to_current_breakpoint(completion_wait_deadline(deadline))?;
        }
        if self.engine.instruction_pointer().map_err(debugger)? != cleanup_return {
            bail!("deferred cleanup stopped away from its return address");
        }
        self.remove_owned_breakpoint()?;
        self.state.unregister = Some(UnregisterProgress::CleanupReturned);
        Ok(())
    }

    fn settle_unregister_cleanup(&mut self, context: u64, deadline: Option<Instant>) -> Result<()> {
        require_completion_deadline(deadline)?;
        if self.state.attached {
            self.detach_handled()?;
        }
        if deadline.is_some_and(|deadline| {
            deadline.saturating_duration_since(Instant::now()) < CLEANUP_SETTLE
        }) {
            bail!("the absolute Secure Kernel pause bound has no time left for cleanup settling");
        }
        thread::sleep(CLEANUP_SETTLE);
        require_completion_deadline(deadline)?;
        if !self.state.attached {
            let pending = self
                .engine
                .attach_process_begin(self.state.vmwp_pid)
                .map_err(debugger)?;
            self.claim_attach();
            wait_for_process_attach(self.engine, pending, self.state.vmwp_pid, deadline)?;
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
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            address = format_args!("{scratch:#x}"),
            "dispatcher issued callback scratch release"
        );
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
        let context = self.state.handler_context;
        self.state.scratch_allocated = false;
        self.state.handler_context = None;
        self.state.unregister = None;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            context = ?context.map(HexU64),
            address = format_args!("{scratch:#x}"),
            "dispatcher verified handler unregistration and callback scratch release"
        );
        if self.state.attached {
            self.detach_handled()?;
        }
        Ok(())
    }

    fn run_to_current_breakpoint(&mut self, deadline: Instant) -> Result<()> {
        let expected = self
            .state
            .breakpoint
            .as_ref()
            .context("no owned breakpoint is armed")?
            .address;
        loop {
            let remaining = debug_wait_remaining(deadline, self.state.wait_activity.as_ref());
            if remaining.is_zero() {
                if matches!(self.state.phase, DispatcherPhase::ReadyForStop) {
                    self.state.phase = DispatcherPhase::ReadyForStopInterrupted;
                }
                bail!("the debugger did not reach the owned breakpoint before its deadline");
            }
            let timeout = remaining.as_millis().clamp(1, u128::from(u32::MAX)) as u32;
            let run = self
                .engine
                .execute_and_wait("g", timeout)
                .map_err(debugger)?;
            tracing::info!(
                target: "windbg_mcp::secure_kernel_mutation",
                expected = format_args!("{expected:#x}"),
                "dispatcher resumed vmwp toward its owned breakpoint"
            );
            if run.target_gone {
                bail!("vmwp left the debugger while an owned breakpoint was pending");
            }
            if let Some(interruption) = run.cut_short {
                match interruption {
                    Interruption::OnRequest => {
                        if matches!(self.state.phase, DispatcherPhase::ReadyForStop) {
                            self.state.phase = DispatcherPhase::ReadyForStopInterrupted;
                        }
                        bail!("the debugger wait was interrupted on request")
                    }
                    Interruption::Deadline { .. }
                        if self.engine.instruction_pointer().map_err(debugger)? == expected =>
                    {
                        return Ok(());
                    }
                    Interruption::Deadline { .. }
                        if self.state.wait_activity.as_ref().is_some_and(|activity| {
                            !debug_wait_remaining(deadline, Some(activity)).is_zero()
                        }) =>
                    {
                        continue;
                    }
                    Interruption::Deadline { .. } => {
                        if matches!(self.state.phase, DispatcherPhase::ReadyForStop) {
                            self.state.phase = DispatcherPhase::ReadyForStopInterrupted;
                        }
                        bail!("the debugger wait reached its deadline")
                    }
                }
            }
            if self.engine.instruction_pointer().map_err(debugger)? == expected {
                return Ok(());
            }
            bail!("the debugger stopped for an event the live-control adapter does not own")
        }
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
        let created = CreatedBreakpoint {
            id: set.breakpoint.id,
            kind: set.breakpoint.kind,
            address: set.breakpoint.address,
            enabled: set.breakpoint.enabled,
            cut_short: set.cut_short.is_some(),
            replaced: !set.replaced.is_empty(),
        };
        self.state
            .claim_created_breakpoint(created, address, original)?;
        let owned = self
            .state
            .breakpoint
            .as_ref()
            .expect("breakpoint was claimed");
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            breakpoint_id = owned.id,
            address = format_args!("{address:#x}"),
            "dispatcher installed an owned vmwp breakpoint"
        );
        Ok(())
    }

    fn remove_owned_breakpoint(&mut self) -> Result<()> {
        let owned = self
            .state
            .breakpoint
            .as_ref()
            .context("the adapter owns no breakpoint to remove")?;
        let owned_id = owned.id;
        let owned_address = owned.address;
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
        self.engine.remove_breakpoint(owned_id).map_err(debugger)?;
        if self
            .engine
            .read_memory(owned_address, owned.original.len())
            .map_err(debugger)?
            != owned.original
        {
            bail!("original bytes were not restored after breakpoint removal");
        }
        self.state.breakpoint = None;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            breakpoint_id = owned_id,
            address = format_args!("{owned_address:#x}"),
            "dispatcher removed its owned vmwp breakpoint and verified original bytes"
        );
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
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            thread_id = retained.system_id,
            "dispatcher reselected its retained vmwp event thread"
        );
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
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            register = name,
            value = format_args!("{value:#x}"),
            "dispatcher verified a vmwp register write"
        );
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
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            address = format_args!("{address:#x}"),
            value = format_args!("{value:#x}"),
            "dispatcher verified a vmwp memory write"
        );
        Ok(())
    }

    fn detach_handled(&mut self) -> Result<()> {
        self.engine
            .execute_command(".detach /h")
            .map_err(debugger)?;
        self.state.attached = false;
        self.state.phase = DispatcherPhase::Detached;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vmwp_pid = self.state.vmwp_pid,
            "dispatcher detached from vmwp with the event handled"
        );
        Ok(())
    }

    fn free_unregistered_scratch_inner(&mut self, deadline: Option<Instant>) -> Result<()> {
        require_completion_deadline(deadline)?;
        if !self.state.attached {
            verify_vmwp_pid(self.bound_vm_id()?, self.state.vmwp_pid)?;
            let pending = self
                .engine
                .attach_process_begin(self.state.vmwp_pid)
                .map_err(debugger)?;
            self.claim_attach();
            wait_for_process_attach(self.engine, pending, self.state.vmwp_pid, deadline)?;
        }
        require_completion_deadline(deadline)?;
        let scratch = self.state.profile.scratch_base.0;
        self.engine
            .execute_command(&format!(".dvfree {scratch:016x} 0"))
            .map_err(debugger)?;
        if self.engine.read_memory(scratch, 1).is_ok() {
            bail!("unregistered callback scratch remained readable after .dvfree");
        }
        self.state.scratch_allocated = false;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            address = format_args!("{scratch:#x}"),
            "dispatcher freed and verified vmwp callback scratch"
        );
        self.detach_handled()
    }

    fn bound_vm_id(&self) -> Result<&str> {
        Ok(&self.state.vm_id)
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

/// Resolve one named export from the verified on-disk PE. Discovery must not turn a missing PDB
/// or symbol-server outage into permission to call an address supplied by the debugger engine.
fn pe_export_rva(bytes: &[u8], wanted: &str) -> Result<u32> {
    let e_lfanew = usize::try_from(pe_u32(bytes, 0x3c)?).context("PE header offset overflowed")?;
    if bytes.get(e_lfanew..e_lfanew.saturating_add(4)) != Some(b"PE\0\0") {
        bail!("profiled vid image has no PE signature");
    }
    let sections = usize::from(pe_u16(bytes, e_lfanew + 6)?);
    let optional_size = usize::from(pe_u16(bytes, e_lfanew + 20)?);
    let optional = e_lfanew
        .checked_add(24)
        .context("PE optional-header offset overflowed")?;
    if pe_u16(bytes, optional)? != 0x20b {
        bail!("profiled vid image is not PE32+");
    }
    if pe_u32(bytes, optional + 108)? == 0 {
        bail!("profiled vid image declares no data directories");
    }
    let export_rva = pe_u32(bytes, optional + 112)?;
    let export_size = pe_u32(bytes, optional + 116)?;
    if export_rva == 0 || export_size < 40 {
        bail!("profiled vid image has no export directory");
    }
    let section_table = optional
        .checked_add(optional_size)
        .context("PE section-table offset overflowed")?;
    let export = pe_rva_offset(bytes, section_table, sections, export_rva, 40)?;
    let functions = pe_u32(bytes, export + 20)?;
    let names = pe_u32(bytes, export + 24)?;
    let function_table = pe_u32(bytes, export + 28)?;
    let name_table = pe_u32(bytes, export + 32)?;
    let ordinal_table = pe_u32(bytes, export + 36)?;
    if functions == 0 || names == 0 || names > 1_000_000 || functions > 1_000_000 {
        bail!("profiled vid image has an invalid export-table count");
    }
    for index in 0..names {
        let name_slot = name_table
            .checked_add(
                index
                    .checked_mul(4)
                    .context("export name table overflowed")?,
            )
            .context("export name table overflowed")?;
        let name_slot = pe_rva_offset(bytes, section_table, sections, name_slot, 4)?;
        let name_rva = pe_u32(bytes, name_slot)?;
        let name_offset = pe_rva_offset(bytes, section_table, sections, name_rva, 1)?;
        let tail = &bytes[name_offset..];
        let length = tail
            .iter()
            .position(|byte| *byte == 0)
            .context("unterminated PE export name")?;
        if tail.get(..length) != Some(wanted.as_bytes()) {
            continue;
        }

        let ordinal_slot = ordinal_table
            .checked_add(
                index
                    .checked_mul(2)
                    .context("export ordinal table overflowed")?,
            )
            .context("export ordinal table overflowed")?;
        let ordinal_slot = pe_rva_offset(bytes, section_table, sections, ordinal_slot, 2)?;
        let ordinal = u32::from(pe_u16(bytes, ordinal_slot)?);
        if ordinal >= functions {
            bail!("VidGetHvPartitionId export ordinal is outside the function table");
        }
        let function_slot = function_table
            .checked_add(
                ordinal
                    .checked_mul(4)
                    .context("export function table overflowed")?,
            )
            .context("export function table overflowed")?;
        let function_slot = pe_rva_offset(bytes, section_table, sections, function_slot, 4)?;
        let rva = pe_u32(bytes, function_slot)?;
        let export_end = export_rva
            .checked_add(export_size)
            .context("export directory range overflowed")?;
        if (export_rva..export_end).contains(&rva) {
            bail!("VidGetHvPartitionId is a forwarded export");
        }
        return Ok(rva);
    }
    bail!("verified vid.dll does not export VidGetHvPartitionId")
}

fn pe_rva_offset(
    bytes: &[u8],
    section_table: usize,
    sections: usize,
    rva: u32,
    size: usize,
) -> Result<usize> {
    for index in 0..sections {
        let section = section_table
            .checked_add(
                index
                    .checked_mul(40)
                    .context("PE section table overflowed")?,
            )
            .context("PE section table overflowed")?;
        let virtual_size = pe_u32(bytes, section + 8)?;
        let virtual_address = pe_u32(bytes, section + 12)?;
        let raw_size = pe_u32(bytes, section + 16)?;
        let raw_pointer = pe_u32(bytes, section + 20)?;
        let span = virtual_size.max(raw_size);
        let Some(delta) = rva.checked_sub(virtual_address) else {
            continue;
        };
        if delta >= span || u64::from(delta) + size as u64 > u64::from(raw_size) {
            continue;
        }
        let offset = usize::try_from(raw_pointer)
            .ok()
            .and_then(|raw| raw.checked_add(delta as usize))
            .context("PE export file offset overflowed")?;
        if offset
            .checked_add(size)
            .is_some_and(|end| end <= bytes.len())
        {
            return Ok(offset);
        }
        bail!("PE export range lies outside the profiled vid image");
    }
    bail!("PE export RVA {rva:#x} is outside every raw section")
}

fn pe_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .context("profiled vid image ended inside a PE field")?;
    Ok(u16::from_le_bytes(value.try_into().unwrap()))
}

fn pe_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .context("profiled vid image ended inside a PE field")?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

#[derive(Clone, Copy, Debug)]
enum VmAction {
    ResolvePid,
    VerifyPid(u32),
    Pause,
    Resume,
}

pub(crate) fn resolve_vmwp_pid(vm_id: &str, asserted_pid: Option<u32>) -> Result<u32> {
    let output = run_vm_query(vm_id, VmAction::ResolvePid, POWERSHELL_WAIT)?;
    let pid = parse_vmwp_pid(&output)?;
    if let Some(asserted_pid) = asserted_pid {
        if asserted_pid == 0 {
            bail!("the optional vmwp_pid assertion must be nonzero");
        }
        if pid != asserted_pid {
            bail!(
                "VM {vm_id} is currently owned by vmwp PID {pid}, not asserted PID {asserted_pid}"
            );
        }
    }
    Ok(pid)
}

fn parse_vmwp_pid(output: &str) -> Result<u32> {
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let value = lines
        .next()
        .context("Hyper-V lookup returned no vmwp PID")?;
    if lines.next().is_some() {
        bail!("Hyper-V lookup returned more than one vmwp PID");
    }
    let pid = value
        .parse::<u32>()
        .context("Hyper-V lookup returned a non-decimal vmwp PID")?;
    if pid == 0 {
        bail!("Hyper-V lookup returned PID zero");
    }
    Ok(pid)
}

fn verify_vmwp_pid(vm_id: &str, pid: u32) -> Result<()> {
    run_vm_action(vm_id, VmAction::VerifyPid(pid), POWERSHELL_WAIT)
}

fn run_vm_action(vm_id: &str, action: VmAction, timeout: Duration) -> Result<()> {
    run_vm_query(vm_id, action, timeout)?;
    trace_vm_action(vm_id, action);
    Ok(())
}

fn trace_vm_action(vm_id: &str, action: VmAction) {
    if matches!(action, VmAction::Pause | VmAction::Resume) {
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vm_id,
            action = ?action,
            "Hyper-V VM state mutation completed and was verified"
        );
    }
}

fn run_vm_action_until(vm_id: &str, action: VmAction, deadline: Option<Instant>) -> Result<()> {
    require_completion_deadline(deadline)?;
    let timeout = deadline
        .map(|deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .min(POWERSHELL_WAIT)
        })
        .unwrap_or(POWERSHELL_WAIT);
    run_vm_action(vm_id, action, timeout)?;
    require_completion_deadline(deadline)
}

fn run_vm_query(vm_id: &str, action: VmAction, timeout: Duration) -> Result<String> {
    run_vm_query_inner(vm_id, action, timeout, None)
}

fn run_vm_query_inner(
    vm_id: &str,
    action: VmAction,
    timeout: Duration,
    cancel: Option<&mpsc::Receiver<()>>,
) -> Result<String> {
    let script = match action {
        VmAction::ResolvePid => {
            "$ErrorActionPreference='Stop'; $id=$env:WINDBG_MCP_SK_VM_ID; \
             $p=@(Get-CimInstance Win32_Process -Filter \"Name='vmwp.exe'\" | \
                Where-Object {$_.CommandLine -match [regex]::Escape($id)}); \
             if($p.Count -ne 1){throw ('expected exactly one vmwp for the selected VM; found '+$p.Count)}; \
             [Console]::Out.WriteLine([string]$p[0].ProcessId)"
        }
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
    wait_child(&mut child, timeout, action, cancel)
}

fn wait_child(
    child: &mut Child,
    timeout: Duration,
    action: VmAction,
    cancel: Option<&mpsc::Receiver<()>>,
) -> Result<String> {
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
                    return Ok(stdout);
                }
                bail!(
                    "Hyper-V PowerShell helper {action:?} failed ({status}): stdout={stdout:?}; stderr={stderr:?}"
                );
            }
            Ok(None) if Instant::now() < deadline => {
                let cancelled = cancel.is_some_and(|cancel| {
                    matches!(
                        cancel.try_recv(),
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected)
                    )
                });
                if cancelled {
                    // The debugger reached the exact breakpoint whose VM transition this helper
                    // initiated. Resume-VM can remain blocked because vmwp is debugger-stopped at
                    // that breakpoint; the stop itself is stronger evidence that resume happened.
                    // End only the helper client. Hyper-V owns the already-issued transition.
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(String::new());
                }
                thread::sleep(POLL);
            }
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
        Self::spawn(vm_id, Duration::ZERO, move |vm_id, cancel| {
            run_vm_query_inner(vm_id, action, POWERSHELL_WAIT, Some(cancel))?;
            trace_vm_action(vm_id, action);
            Ok(())
        })
    }

    fn completion_kick(vm_id: String) -> Self {
        Self::spawn(vm_id, COMPLETION_KICK_AFTER, |vm_id, _cancel| {
            run_vm_action(vm_id, VmAction::Pause, POWERSHELL_WAIT)?;
            run_vm_action(vm_id, VmAction::Resume, POWERSHELL_WAIT)
        })
    }

    fn spawn(
        vm_id: String,
        delay: Duration,
        operation: impl FnOnce(&str, &mpsc::Receiver<()>) -> Result<()> + Send + 'static,
    ) -> Self {
        let (cancel_tx, cancel_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = match cancel_rx.recv_timeout(delay) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => Ok(()),
                Err(mpsc::RecvTimeoutError::Timeout) => operation(&vm_id, &cancel_rx),
            };
            let _ = result_tx.send(result);
        });
        Self {
            cancel: cancel_tx,
            result: result_rx,
            thread: Some(thread),
        }
    }

    fn finish_until(&mut self, deadline: Option<Instant>) -> Result<()> {
        let _ = self.cancel.send(());
        let maximum = POWERSHELL_WAIT + POWERSHELL_WAIT + Duration::from_secs(5);
        let wait = deadline
            .map(|deadline| {
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(maximum)
            })
            .unwrap_or(maximum);
        require_retention_deadline(deadline)?;
        let result = match self.result.recv_timeout(wait) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                require_retention_deadline(deadline)?;
                bail!("Hyper-V transition helper did not finish before its cleanup bound")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(thread) = self.thread.take() {
                    thread
                        .join()
                        .map_err(|_| anyhow!("Hyper-V transition helper panicked"))?;
                }
                bail!("Hyper-V transition helper exited without reporting its result")
            }
        };
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow!("Hyper-V transition helper panicked"))?;
        }
        require_retention_deadline(deadline)?;
        result
    }

    fn finished(&self) -> bool {
        self.thread.is_none()
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

    fn export_fixture(function_rva: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x600];
        let put16 = |bytes: &mut [u8], at: usize, value: u16| {
            bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        };
        let put32 = |bytes: &mut [u8], at: usize, value: u32| {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        bytes[..2].copy_from_slice(b"MZ");
        put32(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut bytes, 0x86, 1);
        put16(&mut bytes, 0x94, 0xf0);
        let optional = 0x98;
        put16(&mut bytes, optional, 0x20b);
        put32(&mut bytes, optional + 108, 16);
        put32(&mut bytes, optional + 112, 0x1000);
        put32(&mut bytes, optional + 116, 0x100);
        let section = optional + 0xf0;
        put32(&mut bytes, section + 8, 0x400);
        put32(&mut bytes, section + 12, 0x1000);
        put32(&mut bytes, section + 16, 0x400);
        put32(&mut bytes, section + 20, 0x200);
        let export = 0x200;
        put32(&mut bytes, export + 20, 1);
        put32(&mut bytes, export + 24, 1);
        put32(&mut bytes, export + 28, 0x1040);
        put32(&mut bytes, export + 32, 0x1044);
        put32(&mut bytes, export + 36, 0x1048);
        put32(&mut bytes, 0x240, function_rva);
        put32(&mut bytes, 0x244, 0x1050);
        put16(&mut bytes, 0x248, 0);
        bytes[0x250..0x250 + 20].copy_from_slice(b"VidGetHvPartitionId\0");
        bytes
    }

    #[test]
    fn partition_export_is_resolved_from_the_verified_pe_without_symbols() {
        let bytes = export_fixture(0x1100);
        assert_eq!(
            pe_export_rva(&bytes, "VidGetHvPartitionId").unwrap(),
            0x1100
        );
        assert!(pe_export_rva(&bytes, "NotTheExport").is_err());

        let forwarded = export_fixture(0x1080);
        assert!(pe_export_rva(&forwarded, "VidGetHvPartitionId").is_err());
    }

    #[test]
    fn target_placeholders_expand_only_from_the_bound_identity() {
        let target = target();
        assert_eq!(
            expand_target_command(
                "provider --partition {partition_id} --vp {vp} --cr3 {cr3}",
                &target,
                true,
            )
            .unwrap(),
            "provider --partition 0x85 --vp 0 --cr3 0x1201000"
        );
    }

    #[test]
    fn target_placeholders_never_rewrite_the_authorized_executable() {
        let target = target();
        let expanded = expand_target_command(
            r#""C:\provider {vp} {cr3}.exe" --partition {partition_id} --vp {vp}"#,
            &target,
            false,
        )
        .unwrap();
        let words = crate::livesrc::split_command(&expanded);

        assert_eq!(words[0], r"C:\provider {vp} {cr3}.exe");
        assert_eq!(&words[1..], ["--partition", "0x85", "--vp", "0"]);
    }

    #[test]
    fn vmwp_lookup_accepts_exactly_one_nonzero_decimal_pid() {
        assert_eq!(parse_vmwp_pid("4242\r\n").unwrap(), 4242);
        assert!(parse_vmwp_pid("").is_err());
        assert!(parse_vmwp_pid("0\n").is_err());
        assert!(parse_vmwp_pid("0x1092\n").is_err());
        assert!(parse_vmwp_pid("4242\n4343\n").is_err());
    }

    #[test]
    fn interruptible_wait_activity_exposes_only_its_owned_interval() {
        let activity = WaitActivity::new(Duration::from_secs(1));
        assert_eq!(activity.phase(), WaitActivityPhase::Armed);
        assert_eq!(activity.while_active(|| 7), None);
        {
            let _guard = activity.enter().unwrap();
            assert_eq!(activity.phase(), WaitActivityPhase::Active);
            assert_eq!(activity.while_active(|| 7), Some(7));
        }
        assert_eq!(activity.phase(), WaitActivityPhase::Finished);
        assert_eq!(activity.while_active(|| 7), None);

        let cancelled_before_entry = WaitActivity::new(Duration::from_secs(1));
        cancelled_before_entry.finish();
        assert_eq!(cancelled_before_entry.phase(), WaitActivityPhase::Finished);
        assert!(cancelled_before_entry.enter().is_err());
    }

    #[test]
    fn the_pause_budget_starts_when_the_wait_retains_a_stop() {
        let activity = WaitActivity::for_kd(
            Duration::from_secs(30),
            Duration::from_secs(10),
            Duration::from_secs(20),
        );
        assert_eq!(activity.retained_since(), None);
        let retained_at = Instant::now();

        let deadline = activity.mark_stop_retained(retained_at).unwrap();
        let retained = activity.retained_since().unwrap();
        assert_eq!(retained, retained_at);
        assert_eq!(deadline, retained + Duration::from_secs(10));
        assert_eq!(
            activity.recovery_deadline(),
            Some(retained + Duration::from_secs(20))
        );
        assert_eq!(
            activity.mark_stop_retained(retained_at + Duration::from_secs(1)),
            Some(deadline)
        );
    }

    #[test]
    fn dispatcher_completion_reuses_the_absolute_pause_deadline() {
        let deadline = Instant::now() + Duration::from_secs(10);
        assert_eq!(completion_wait_deadline(Some(deadline)), deadline);
        assert!(require_completion_deadline(Some(deadline)).is_ok());

        let activity = WaitActivity::new(Duration::from_secs(3_600));
        assert!(
            debug_wait_remaining(Instant::now(), Some(&activity)) > Duration::from_secs(3_500),
            "a managed wait must use its configured idle bound instead of the legacy deadline"
        );
        assert!(debug_wait_remaining(Instant::now(), None).is_zero());
        assert!(
            require_completion_deadline(Some(Instant::now()))
                .unwrap_err()
                .to_string()
                .contains("absolute Secure Kernel pause bound")
        );
    }

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
        assert_eq!(request.open.dispatcher_vnd, Some(0x200000001000));
        assert_eq!(request.open.target.partition_id, Some(HexU64(0x27)));
        assert_eq!(request.instruction.bytes, [0x0f, 0x1f, 0x44, 0, 0]);
        assert!(
            !serde_json::to_string(&profile())
                .unwrap()
                .contains("dispatcher_vnd")
        );
    }

    #[test]
    fn acceptance_request_treats_discovered_coordinates_as_optional_assertions() {
        let args = [
            "--profile",
            r"C:\private\profile.json",
            "--control-transport",
            "provider --partition {partition_id} --vp {vp}",
            "--live-transport",
            "memory --partition {partition_id} --cr3 {cr3}",
            "--vmwp-pid",
            "4242",
            "--vm-id",
            "11111111-2222-3333-4444-555555555555",
            "--instruction-address",
            "0xfffff80001234560",
            "--instruction-bytes",
            "90",
        ]
        .map(str::to_string);
        let request = AcceptanceRequest::parse(&args).unwrap();
        assert_eq!(request.open.dispatcher_vnd, None);
        assert_eq!(request.open.target.partition_id, None);
        assert_eq!(request.open.target.expected_cr3, None);
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
            dispatcher_vnd: Some(0x2000_0000_1000),
            target: target_request(),
            max_pause_ms: 600_000,
            allow_transition_cr3: false,
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
    fn a_failed_preparation_stays_faulted_and_preserves_its_cause() {
        let mut session = Session {
            control: None,
            dispatcher: VmwpDispatcherState::new(
                profile(),
                4242,
                Some(0x2000_0000_1000),
                "11111111-2222-3333-4444-555555555555".into(),
            )
            .unwrap(),
            pending: None,
            preparation_failed: Some("partition discovery failed".into()),
            max_pause_ms: 600_000,
            // No kernel object is needed for a state-only test.
            _reservation: VmReservation(std::ptr::null_mut()),
        };

        assert_eq!(session.phase(), LivePhase::Faulted);
        let error = match session.control() {
            Ok(_) => panic!("failed preparation unexpectedly exposed live control"),
            Err(error) => error,
        };
        let mutable_error = match session.control_mut() {
            Ok(_) => panic!("failed preparation unexpectedly exposed mutable live control"),
            Err(error) => error,
        };
        for error in [error, mutable_error] {
            let message = error.to_string();
            assert!(message.contains("partition discovery failed"), "{message}");
            assert!(message.contains("end_session"), "{message}");
        }
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
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        state.phase = DispatcherPhase::Holding(event.clone());
        state.retained_event = Some(RetainedEvent {
            system_id: 0x1234,
            return_ip: 0x2000_0000_3000,
            event,
            validation_complete: true,
            release_eligible: true,
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
    fn the_cleanup_deadline_outlives_the_consumed_event_record() {
        let event = HeldEvent {
            message_type: HexU64(EVENT_TYPE_VECTOR_1),
            vector: 1,
            vp: 0,
            vtl: 1,
            cpl: 0,
            dispatcher_context: HexU64(0x2000_0000_2000),
            advance_instruction_pointer: false,
            reason: StopReason::DebugException,
        };
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        state.recovery_deadline = Some(deadline);
        state.retained_event = Some(RetainedEvent {
            system_id: 0x1234,
            return_ip: 0x2000_0000_3000,
            event,
            validation_complete: true,
            release_eligible: true,
        });

        state.retained_event.take().unwrap();

        assert_eq!(state.recovery_deadline, Some(deadline));
    }

    #[test]
    fn an_unvalidated_retained_event_is_contained_before_recovery_can_release_it() {
        let event = HeldEvent {
            message_type: HexU64(EVENT_TYPE_VECTOR_1),
            vector: 1,
            vp: 0,
            vtl: 1,
            cpl: 0,
            dispatcher_context: HexU64(0x2000_0000_2000),
            advance_instruction_pointer: false,
            reason: StopReason::DebugException,
        };
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        state.phase = DispatcherPhase::Holding(event.clone());
        state.retained_event = Some(RetainedEvent {
            system_id: 0x1234,
            return_ip: 0x2000_0000_3000,
            event,
            validation_complete: false,
            release_eligible: false,
        });

        let error = state.refuse_unsafe_recovery().unwrap_err();

        assert!(error.to_string().contains("failed validation"));
        assert!(matches!(state.phase, DispatcherPhase::Contained(_)));
        assert!(state.retained_event.is_some());
    }

    #[test]
    fn a_successful_registration_context_is_owned_before_cleanup_can_fail() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();

        assert!(state.record_handler_context(0).is_err());
        state.record_handler_context(0x2000_0000_2000).unwrap();
        assert_eq!(state.handler_context, Some(0x2000_0000_2000));
        assert!(state.record_handler_context(0x2000_0000_3000).is_err());
    }

    #[test]
    fn a_failed_current_thread_selection_releases_the_partial_freeze() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        let mut commands = Vec::new();

        let error = state
            .freeze_other_threads(|command| {
                commands.push(command.to_string());
                if command == "~# u" {
                    Err(anyhow!("current-thread thaw failed"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();

        assert!(error.to_string().contains("current-thread thaw failed"));
        assert_eq!(commands, ["~* f", "~# u", "~* u"]);
        assert!(!state.threads_frozen);
    }

    #[test]
    fn a_failed_partial_freeze_cleanup_retains_ownership_for_teardown() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        let mut commands = Vec::new();

        let error = state
            .freeze_other_threads(|command| {
                commands.push(command.to_string());
                if command == "~* f" {
                    Ok(())
                } else {
                    Err(anyhow!("{command} failed"))
                }
            })
            .unwrap_err();

        assert!(error.to_string().contains("partially frozen"));
        assert_eq!(commands, ["~* f", "~# u", "~* u"]);
        assert!(state.threads_frozen);
    }

    #[test]
    fn discovery_cleanup_requires_the_call_return_boundary_before_becoming_fresh() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        state.phase = DispatcherPhase::Discovering;
        state.threads_frozen = true;

        state.finish_discovery_call_cleanup(false);

        assert!(!state.threads_frozen);
        assert!(matches!(state.phase, DispatcherPhase::Discovering));

        state.threads_frozen = true;
        state.finish_discovery_call_cleanup(true);

        assert!(!state.threads_frozen);
        assert!(matches!(state.phase, DispatcherPhase::Fresh));
    }

    #[test]
    fn a_rejected_created_breakpoint_remains_owned_for_cleanup() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        let address = 0x2000_0000_3000;
        let original = vec![0x90; 8];

        let error = state
            .claim_created_breakpoint(
                CreatedBreakpoint {
                    id: 7,
                    kind: BreakpointKind::Code,
                    address: Some(address),
                    enabled: false,
                    cut_short: false,
                    replaced: false,
                },
                address,
                original.clone(),
            )
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("requested owned code breakpoint")
        );
        let owned = state.breakpoint.expect("created breakpoint remains owned");
        assert_eq!(owned.id, 7);
        assert_eq!(owned.address, address);
        assert_eq!(owned.original, original);
    }

    #[test]
    fn a_created_breakpoint_replacement_contains_before_cleanup_can_detach() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        let address = 0x2000_0000_3000;

        let error = state
            .claim_created_breakpoint(
                CreatedBreakpoint {
                    id: 7,
                    kind: BreakpointKind::Code,
                    address: Some(address),
                    enabled: true,
                    cut_short: false,
                    replaced: true,
                },
                address,
                vec![0x90; 8],
            )
            .unwrap_err();

        assert!(error.to_string().contains("pre-existing breakpoint"));
        assert!(state.breakpoint.is_some());
        assert!(matches!(state.phase, DispatcherPhase::Contained(_)));
        assert!(state.refuse_unsafe_recovery().is_err());
    }

    #[test]
    fn a_failed_completion_kick_retains_conservative_pause_ownership() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
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
    fn an_expired_retention_cleanup_keeps_the_transition_owned_for_retry() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        let (begun_tx, begun_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        state.completion_kick = Some(VmTransition::spawn(
            state.vm_id.clone(),
            Duration::ZERO,
            move |_vm_id, _cancel| {
                begun_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            },
        ));
        begun_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let error = state
            .finish_completion_kick_until(Some(Instant::now() + Duration::from_millis(10)))
            .unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("pause bound expired"), "{message}");
        assert!(state.completion_kick.is_some());
        assert!(state.vm_paused);
        release_tx.send(()).unwrap();
        state.finish_completion_kick().unwrap();
        assert!(state.completion_kick.is_none());
    }

    #[test]
    fn pause_ownership_is_claimed_with_the_exact_target_before_suspend() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
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
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        state.phase = DispatcherPhase::Registering;

        let error = state.refuse_unsafe_recovery().unwrap_err();

        assert!(error.to_string().contains("registration did not reach"));
        assert!(matches!(state.phase, DispatcherPhase::Contained(_)));
        assert!(state.refuse_unsafe_recovery().is_err());
    }

    #[test]
    fn unproved_unregister_contains_but_proved_cleanup_remains_retryable() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        state.unregister = Some(UnregisterProgress::Calling);

        assert!(state.refuse_unsafe_recovery().is_err());
        assert!(matches!(state.phase, DispatcherPhase::Contained(_)));

        let mut cleanup = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
        cleanup.phase = DispatcherPhase::Detached;
        cleanup.unregister = Some(UnregisterProgress::WaitingCleanup);
        let error = cleanup.refuse_unsafe_recovery().unwrap_err();
        assert!(error.to_string().contains("cleanup is incomplete"));
        assert!(matches!(cleanup.phase, DispatcherPhase::Detached));
    }

    #[test]
    fn a_proved_unfreed_unregister_scratch_allocation_becomes_retryable() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();
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

    fn target_request() -> TargetRequest {
        let target = target();
        TargetRequest {
            vm_id: target.vm_id,
            partition_id: Some(target.partition_id),
            vp: target.vp,
            expected_cr3: Some(target.expected_cr3),
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
            discovery: None,
            secure_kernel_kd: None,
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
