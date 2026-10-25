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
    WaitOutcome,
};
use iced_x86::{Decoder, DecoderOptions};
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
use crate::skcontrol::{HeldEvent, HexU64, RegisterName, StopReason, TargetIdentity};
use crate::sklive::{
    AppliedMemoryWrite, ArmMode, BreakWake, BreakpointGuard, Disarmed, DispatcherProfile,
    DispatcherSite, EventDispatcher, GuardedMemoryWrite, InstructionGuard, LiveControl,
    LiveMemoryWrite, LivePhase, LiveTransition, ObservedStop, PreparedMemoryWrite, ReleaseMode,
    StopRecord, is_break_wake,
};

pub(crate) const LIVE_CONTROL_FLAG: &str = "--sk-live-control";

const DEBUG_WAIT: u32 = 60_000;
const NATIVE_SETTLE_WAIT: u32 = 1_000;
/// One `g` slice of the running disarm: vmwp runs under the event-site breakpoint for this long
/// before the watchdog stops it so the pending Hyper-V pause can be polled.
const DISARM_PUMP_SLICE: Duration = Duration::from_millis(250);
const COMPLETION_KICK_AFTER: Duration = Duration::from_secs(12);
const POWERSHELL_WAIT: Duration = Duration::from_secs(60);
const LIVE_MEMORY_WAIT: Duration = Duration::from_secs(60);
pub(crate) const CLEANUP_SETTLE: Duration = Duration::from_secs(5);
/// Controller restoration, event completion and handler removal run before the mandatory settle.
/// Keep their reserve larger than the settle itself instead of making every minimum-bound cleanup
/// fail as soon as any preceding teardown work consumes time.
pub(crate) const CLEANUP_RESERVE: Duration = Duration::from_secs(30);
/// Smallest pause window that leaves equal service and bounded controller-cleanup intervals.
pub(crate) const MIN_PAUSE_MS: u64 = CLEANUP_RESERVE.as_millis() as u64 * 2;
const POLL: Duration = Duration::from_millis(20);
const EVENT_TYPE_VECTOR: u64 = 0x0100_0002;
const DEBUG_VECTOR: u8 = 1;
const BREAKPOINT_VECTOR: u8 = 3;
const MAX_AMD64_INSTRUCTION_BYTES: usize = 15;
const MAX_PENDING_MEMORY_WRITES: usize = 64;

/// Stop accepting work early enough to preserve a bounded controller-cleanup interval.
pub(crate) fn service_pause_bound(max_pause: Duration) -> Duration {
    let cleanup_reserve = (max_pause / 2).min(CLEANUP_RESERVE);
    max_pause.saturating_sub(cleanup_reserve)
}

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PauseWindow {
    service_deadline: Instant,
    recovery_deadline: Instant,
}

pub(crate) struct Session {
    control: Option<LiveControl<crate::skcontrol::ControlProcess>>,
    dispatcher: VmwpDispatcherState,
    pending: Option<PendingControl>,
    preparation_failed: Option<String>,
    max_pause_ms: u64,
    pause_window: Option<PauseWindow>,
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
    allow_memory_writes: bool,
    additional_vps: Vec<AdditionalVp>,
}

impl Session {
    pub(crate) fn open(request: &OpenRequest) -> Result<(Self, Vec<String>)> {
        request.target.validate()?;
        if request.additional_vps.len() + 1 > crate::sklive::MAX_LIVE_CONTROL_VPS {
            bail!(
                "live control accepts at most {} VP providers",
                crate::sklive::MAX_LIVE_CONTROL_VPS
            );
        }
        for (index, additional) in request.additional_vps.iter().enumerate() {
            additional.target.validate()?;
            if !additional
                .target
                .vm_id
                .eq_ignore_ascii_case(&request.target.vm_id)
                || additional.target.partition_id != request.target.partition_id
                || additional.target.expected_cr3 != request.target.expected_cr3
            {
                bail!("all live-control VP requests must name one VM, partition and CR3");
            }
            if additional.target.vp == request.target.vp
                || request.additional_vps[..index]
                    .iter()
                    .any(|earlier| earlier.target.vp == additional.target.vp)
            {
                bail!("live-control VP requests must be distinct");
            }
        }
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
                    allow_memory_writes: request.allow_memory_writes,
                    additional_vps: request.additional_vps.clone(),
                }),
                preparation_failed: None,
                max_pause_ms: request.max_pause_ms,
                pause_window: None,
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

    /// Admit and arm the M6 exact-build service trace from one retained stop. Every image and
    /// instruction read completes before `continue_to_breakpoints` starts the existing atomic
    /// debug-register replacement transition.
    #[allow(dead_code)] // M6.2 wires the pre-mutation gate into the worker-owned trace job.
    pub(crate) fn arm_service_trace(
        &mut self,
        engine: &DebugEngine,
        epoch: &crate::skcontrol::StopEpoch,
        manifest: &crate::skservice::ServiceManifest,
    ) -> Result<ServiceTraceArm> {
        let (stop, image_base) = self.service_trace_identity(epoch)?;
        let deadline = self.stopped_service_deadline()?;
        let proof = manifest
            .verify_live_image(|rva, size| {
                let address = image_base
                    .checked_add(u64::from(rva))
                    .ok_or_else(|| "live image RVA wraps its address".to_string())?;
                let size =
                    u32::try_from(size).map_err(|_| "live image read is too large".to_string())?;
                let read = self
                    .read_memory_until(address, size, deadline)
                    .map_err(|error| format!("{error:#}"))?;
                decode_live_hex(&read.data)
            })
            .map_err(anyhow::Error::msg)?;
        let breakpoints = manifest
            .breakpoints(image_base)
            .map_err(anyhow::Error::msg)?;
        let transition = self.continue_to_breakpoints(engine, epoch, breakpoints)?;
        Ok(ServiceTraceArm {
            transition,
            target: stop.target,
            image_base: HexU64(image_base),
            proof,
        })
    }

    fn service_trace_identity(
        &self,
        epoch: &crate::skcontrol::StopEpoch,
    ) -> Result<(StopRecord, u64)> {
        self.ensure_preparation_succeeded()?;
        let stop = self
            .control()?
            .stopped()
            .cloned()
            .context("service tracing requires one retained VTL1 stop")?;
        if &stop.epoch != epoch {
            bail!("service trace arm supplied a stale stop epoch");
        }
        if self.control()?.provider_count() != 1 {
            bail!(
                "service tracing requires exactly one selected VP; multi-VP ordering is not proved"
            );
        }
        if !self
            .dispatcher
            .memory
            .as_ref()
            .context("service tracing has no live-memory source")?
            .source
            .explicit_refresh_capability()
        {
            bail!(
                "service tracing requires a live-memory source with explicit stop-scoped refresh"
            );
        }
        let image_base = self
            .kernel_base()
            .context("the live-memory provider did not report a Secure Kernel image base")?;
        Ok((stop, image_base))
    }

    /// Run one M6 service trace wholly on the live worker's engine thread. The published shared
    /// handle contains only the engine-free recorder and stop bit; all controller and provider
    /// work remains in this call.
    #[allow(dead_code)] // M6.2's worker op publishes and drives this loop in the next slice.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_service_trace(
        &mut self,
        engine: &DebugEngine,
        job: u64,
        epoch: &crate::skcontrol::StopEpoch,
        trace_id: String,
        label: Option<String>,
        limits: crate::skservicetrace::TraceLimits,
        manifest: crate::skservice::ServiceManifest,
        publish: impl FnOnce(crate::skservicetrace::SharedTrace),
        mut pause_changed: impl FnMut(bool),
    ) -> Result<crate::skservicetrace::ServiceTrace> {
        // Build every engine-free object before the first register mutation. Once arm succeeds,
        // the remaining fallible paths all pass through restoration below.
        let (candidate, image_base) = self.service_trace_identity(epoch)?;
        let recorder = crate::skservicetrace::Recorder::new(
            trace_id,
            label,
            manifest.clone(),
            candidate.target.clone(),
            HexU64(image_base),
            limits,
        )
        .map_err(anyhow::Error::msg)?;
        let shared = crate::skservicetrace::SharedTrace::new(recorder);
        let mut decoder = crate::skservicetrace::ObservationDecoder::new(
            manifest.clone(),
            candidate.target,
            HexU64(image_base),
        )
        .map_err(anyhow::Error::msg)?;
        let breakpoints = manifest
            .breakpoints(image_base)
            .map_err(anyhow::Error::msg)?;
        let armed = self.arm_service_trace(engine, epoch, &manifest)?;
        debug_assert_eq!(armed.image_base, HexU64(image_base));
        pause_changed(false);
        publish(shared.clone());
        let mut runtime = LiveServiceTraceRuntime {
            session: self,
            engine,
            job,
            pause_changed: &mut pause_changed,
        };
        drive_service_trace(
            &mut runtime,
            &shared,
            &mut decoder,
            &breakpoints,
            limits.per_buffer_bytes,
        )
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
        if pending.allow_memory_writes {
            self.dispatcher.cache_vm_processor_count()?;
        }
        let found = {
            let mut dispatcher = self.dispatcher.bind(engine);
            dispatcher.prepare_identity(pending.target.partition_id.map(|value| value.0))?
        };
        let partition_id = found.partition_id;
        let partial = TargetIdentity {
            vm_id: pending.target.vm_id.clone(),
            partition_id: HexU64(partition_id),
            vp: pending.target.vp,
            vtl: 1,
            expected_cr3: pending.target.expected_cr3.unwrap_or(HexU64(0x1000)),
        };
        let control_transport = expand_target_command(
            &pending.control_transport,
            &partial,
            pending.target.expected_cr3.is_some(),
            None,
        )?;
        let (provider, skipped) = crate::skcontrol::ControlProcess::spawn_selected(
            &control_transport,
            crate::skcontrol::TargetSelector {
                vm_id: pending.target.vm_id.clone(),
                partition_id: HexU64(partition_id),
                vp: pending.target.vp,
                expected_cr3: pending.target.expected_cr3,
            },
        )?;
        let target = provider.target().clone();
        let live_transport = expand_target_command(
            &pending.live_transport,
            &target,
            true,
            Some((self.dispatcher.vmwp_pid, found.partition_handle)),
        )?;
        self.dispatcher.bind_identity(
            found,
            live_transport,
            &target,
            pending.allow_transition_cr3,
            pending.allow_memory_writes,
        )?;
        let mut providers = vec![provider];
        let mut skipped = skipped
            .into_iter()
            .map(|line| format!("VP {}: {line}", target.vp))
            .collect::<Vec<_>>();
        for additional in pending.additional_vps {
            let partial = TargetIdentity {
                vm_id: additional.target.vm_id.clone(),
                partition_id: HexU64(partition_id),
                vp: additional.target.vp,
                vtl: 1,
                expected_cr3: additional.target.expected_cr3.unwrap_or(HexU64(0x1000)),
            };
            let command = expand_target_command(
                &additional.control_transport,
                &partial,
                additional.target.expected_cr3.is_some(),
                None,
            )?;
            let (provider, provider_skipped) = crate::skcontrol::ControlProcess::spawn_selected(
                &command,
                crate::skcontrol::TargetSelector {
                    vm_id: additional.target.vm_id,
                    partition_id: HexU64(partition_id),
                    vp: additional.target.vp,
                    expected_cr3: additional.target.expected_cr3,
                },
            )?;
            let vp = provider.target().vp;
            skipped.extend(
                provider_skipped
                    .into_iter()
                    .map(|line| format!("VP {vp}: {line}")),
            );
            providers.push(provider);
        }
        let control =
            LiveControl::open_many_with_transition(providers, pending.allow_transition_cr3)?;
        self.dispatcher
            .bind_software_breakpoint_capability(control.supports_software_breakpoint_events())?;
        self.control = Some(control);
        Ok(skipped)
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

    /// Wait under the policy pause bound and report the instant the owned callback is retained.
    ///
    /// The notice is deliberately emitted from the engine thread at the retention boundary,
    /// before adapter cleanup or provider validation can stall. The dispatcher keeps the matching
    /// absolute recovery deadline so a later `EndSession` spends only the reserved cleanup time.
    pub(crate) fn wait_for_stop(
        &mut self,
        engine: &DebugEngine,
        retained: impl FnMut(),
    ) -> Result<StopRecord> {
        self.wait_for_stop_inner(engine, None, retained)
    }

    /// The ordinary MCP wait, bound to the worker job that may be woken by `sk_live_break`.
    pub(crate) fn wait_for_stop_for_job(
        &mut self,
        engine: &DebugEngine,
        job: u64,
        retained: impl FnMut(),
    ) -> Result<StopRecord> {
        self.wait_for_stop_inner(engine, Some(job), retained)
    }

    fn wait_for_stop_inner(
        &mut self,
        engine: &DebugEngine,
        live_job: Option<u64>,
        mut retained: impl FnMut(),
    ) -> Result<StopRecord> {
        self.ensure_preparation_succeeded()?;
        let max_pause = Duration::from_millis(self.max_pause_ms);
        let idle = Duration::from_millis(u64::from(DEBUG_WAIT));
        let activity = match (self.pause_window, live_job) {
            (Some(window), Some(job)) => WaitActivity::for_live_control_until(
                idle,
                window.service_deadline,
                window.recovery_deadline,
                job,
            ),
            (Some(window), None) => {
                WaitActivity::for_kd_until(idle, window.service_deadline, window.recovery_deadline)
            }
            (None, Some(job)) => {
                WaitActivity::for_live_control(idle, service_pause_bound(max_pause), max_pause, job)
            }
            (None, None) => WaitActivity::for_kd(idle, service_pause_bound(max_pause), max_pause),
        };
        self.dispatcher.wait_activity = Some(activity.clone());
        let result = (|| {
            let control = self
                .control
                .as_mut()
                .context("live Secure Kernel control has not completed target discovery")?;
            let mut dispatcher = self
                .dispatcher
                .bind_with_retention_notice(engine, &mut retained);
            control.wait_for_stop(&mut dispatcher)
        })();
        if activity.retained_since().is_some()
            && let (Some(service_deadline), Some(recovery_deadline)) =
                (activity.pause_deadline(), activity.recovery_deadline())
        {
            let retained = PauseWindow {
                service_deadline,
                recovery_deadline,
            };
            self.pause_window = Some(match self.pause_window {
                Some(original) => PauseWindow {
                    service_deadline: original.service_deadline.min(retained.service_deadline),
                    recovery_deadline: original.recovery_deadline.min(retained.recovery_deadline),
                },
                None => retained,
            });
            self.dispatcher.recovery_deadline = Some(
                self.dispatcher
                    .recovery_deadline
                    .map(|deadline| deadline.min(recovery_deadline))
                    .unwrap_or(recovery_deadline),
            );
        }
        activity.finish();
        self.dispatcher.wait_activity = None;
        if result.as_ref().is_err_and(is_break_wake) {
            return self.break_on_demand(engine, retained);
        }
        result
    }

    /// Request a stop without depending on a preselected guest instruction.
    ///
    /// This first M2 surface runs as one engine-thread operation. The controller pauses and arms
    /// the transient target-side breakpoint before entering the ordinary owned-event wait, so the
    /// mutation remains uninterruptible and the rendezvous retains the existing recovery rules.
    pub(crate) fn break_on_demand(
        &mut self,
        engine: &DebugEngine,
        retained: impl FnMut(),
    ) -> Result<StopRecord> {
        self.ensure_preparation_succeeded()?;
        let now = Instant::now();
        let deadline = now
            .checked_add(Duration::from_millis(u64::from(DEBUG_WAIT)))
            .unwrap_or(now);
        {
            let control = self
                .control
                .as_mut()
                .context("live Secure Kernel control has not completed target discovery")?;
            let mut dispatcher = self.dispatcher.bind(engine);
            control.request_break_until(&mut dispatcher, deadline)?;
        }
        self.pause_window = None;
        self.wait_for_stop(engine, retained)
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
        let deadline = self.stopped_service_deadline()?;
        self.step_until(engine, epoch, guard, deadline)
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

    pub(crate) fn continue_to_breakpoints(
        &mut self,
        engine: &DebugEngine,
        epoch: &crate::skcontrol::StopEpoch,
        breakpoints: Vec<BreakpointGuard>,
    ) -> Result<LiveTransition> {
        let deadline = self.stopped_service_deadline()?;
        self.ensure_preparation_succeeded()?;
        let control = self
            .control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")?;
        let mut dispatcher = self.dispatcher.bind(engine);
        let epoch =
            control.continue_to_breakpoints_until(&mut dispatcher, epoch, breakpoints, deadline)?;
        // The retained event has been completed. A later stop starts a fresh bounded pause window
        // in `wait_for_stop`; carrying this one across guest execution would spend that budget
        // while the target is running and could make the next stop impossible to service.
        self.pause_window = None;
        Ok(LiveTransition {
            phase: control.phase(),
            epoch,
        })
    }

    pub(crate) fn continue_to_software_breakpoints(
        &mut self,
        engine: &DebugEngine,
        epoch: &crate::skcontrol::StopEpoch,
        instructions: Vec<crate::sklive::InstructionGuard>,
    ) -> Result<LiveTransition> {
        let deadline = self.stopped_service_deadline()?;
        self.ensure_preparation_succeeded()?;
        let control = self
            .control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")?;
        let mut dispatcher = self.dispatcher.bind(engine);
        let epoch = control.continue_to_software_breakpoints_until(
            &mut dispatcher,
            epoch,
            instructions,
            deadline,
        )?;
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
        let deadline = self.stopped_service_deadline()?;
        self.continue_from_until(engine, epoch, deadline)
    }

    fn continue_from_until(
        &mut self,
        engine: &DebugEngine,
        epoch: &crate::skcontrol::StopEpoch,
        deadline: Instant,
    ) -> Result<LiveTransition> {
        self.ensure_preparation_succeeded()?;
        let control = self
            .control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")?;
        let mut dispatcher = self.dispatcher.bind(engine);
        let epoch = control.continue_from_until(&mut dispatcher, epoch, deadline)?;
        self.pause_window = None;
        Ok(LiveTransition {
            phase: control.phase(),
            epoch,
        })
    }

    pub(crate) fn read_memory(&self, address: u64, size: u32) -> Result<LiveMemoryRead> {
        let deadline = self.stopped_service_deadline()?;
        self.read_memory_inner(address, size, Some(deadline))
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

    pub(crate) fn write_memory(
        &mut self,
        engine: &DebugEngine,
        epoch: &crate::skcontrol::StopEpoch,
        write: GuardedMemoryWrite,
    ) -> Result<LiveMemoryWrite> {
        let deadline = self.stopped_service_deadline()?;
        self.ensure_preparation_succeeded()?;
        let control = self
            .control
            .as_mut()
            .context("live Secure Kernel control has not completed target discovery")?;
        let mut dispatcher = self.dispatcher.bind(engine);
        control.guarded_write_until(&mut dispatcher, epoch, write, deadline)
    }

    /// End ordinary stopped work before the absolute deadline's cleanup reserve begins.
    fn stopped_service_deadline(&self) -> Result<Instant> {
        if let Some(window) = self.pause_window {
            return Ok(window.service_deadline);
        }
        let recovery_deadline = self
            .dispatcher
            .recovery_deadline
            .context("the live Secure Kernel stop has no retained recovery deadline")?;
        let max_pause = Duration::from_millis(self.max_pause_ms);
        let cleanup_reserve = max_pause.saturating_sub(service_pause_bound(max_pause));
        recovery_deadline
            .checked_sub(cleanup_reserve)
            .context("the live Secure Kernel service deadline underflowed")
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
        // A caller-facing teardown needs its own bound even while no retained stop lends it one.
        // The supervisor waits slightly longer than this reserve so the worker can report either
        // proved release or a fail-closed error instead of becoming an unresolved operation at
        // the supervisor's shorter ordinary-session deadline.
        let now = Instant::now();
        let deadline = now.checked_add(CLEANUP_RESERVE).unwrap_or(now);
        self.close_inner(engine, Some(deadline))
    }

    pub(crate) fn close_until(&mut self, engine: &DebugEngine, deadline: Instant) -> Result<()> {
        self.close_inner(engine, Some(deadline))
    }

    fn close_inner(&mut self, engine: &DebugEngine, deadline: Option<Instant>) -> Result<()> {
        let deadline = [
            deadline,
            self.dispatcher.recovery_deadline,
            self.pause_window.map(|window| window.recovery_deadline),
        ]
        .into_iter()
        .flatten()
        .min();
        let mut dispatcher = self.dispatcher.bind(engine);
        let result = if let Some(control) = self.control.as_mut() {
            match deadline {
                Some(deadline) => control.close_until(&mut dispatcher, deadline),
                None => control.close(&mut dispatcher),
            }
        } else {
            match deadline {
                Some(deadline) => dispatcher.teardown_until(deadline),
                None => dispatcher.teardown(),
            }
        };
        if result.is_ok() {
            self.pause_window = None;
        }
        result
    }
}

/// Substitute only target coordinates discovered or checked by this worker. Keeping expansion here
/// prevents an MCP client from turning an unverified value into a privileged child argument before
/// the provider and memory source are bound to the same identity.
fn expand_target_command(
    command: &str,
    target: &TargetIdentity,
    cr3_known: bool,
    memory_handle: Option<(u32, u64)>,
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
    let uses_memory_handle = words
        .iter()
        .skip(1)
        .any(|argument| argument.contains("{vmwp_pid}") || argument.contains("{partition_handle}"));
    if uses_memory_handle {
        let Some((vmwp_pid, partition_handle)) = memory_handle else {
            bail!(
                "only the live-memory command may use {{vmwp_pid}} or {{partition_handle}}, and \
                 the profile must support worker discovery"
            );
        };
        if partition_handle == 0 {
            bail!("worker discovery did not produce a partition handle for the memory provider");
        }
        for argument in words.iter_mut().skip(1) {
            *argument = argument
                .replace("{vmwp_pid}", &vmwp_pid.to_string())
                .replace("{partition_handle}", &format!("0x{partition_handle:x}"));
        }
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
    /// Startup-policy authority for guarded live-memory mutation. The transport must separately
    /// advertise bounded instruction-coherent writes during its handshake.
    #[serde(default)]
    pub(crate) allow_memory_writes: bool,
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
    pub(crate) target: TargetRequest,
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
            .field("allow_memory_writes", &self.allow_memory_writes)
            .field("additional_vps", &self.additional_vps.len())
            .finish()
    }
}

/// The production M6 loop's only controller/provider boundary. Keeping the orchestration behind
/// these operations lets the offline tier inject every wait, decode, re-arm and restoration
/// failure without constructing a debugger engine or weakening the worker-thread ownership rule.
trait ServiceTraceRuntime {
    fn wait_for_trace_stop(&mut self, stop_requested: bool) -> Result<StopRecord>;
    fn complete_trace_stop(&mut self, _stop: &mut StopRecord) -> Result<()> {
        Ok(())
    }
    fn read_trace_memory(&mut self, address: u64, size: u32) -> Result<Vec<u8>, String>;
    fn rearm_trace(
        &mut self,
        epoch: &crate::skcontrol::StopEpoch,
        breakpoints: &[BreakpointGuard],
    ) -> Result<()>;
    fn restore_trace(&mut self, epoch: &crate::skcontrol::StopEpoch) -> Result<()>;
}

struct LiveServiceTraceRuntime<'a> {
    session: &'a mut Session,
    engine: &'a DebugEngine,
    job: u64,
    pause_changed: &'a mut dyn FnMut(bool),
}

impl ServiceTraceRuntime for LiveServiceTraceRuntime<'_> {
    fn wait_for_trace_stop(&mut self, _stop_requested: bool) -> Result<StopRecord> {
        let pause_changed = &mut self.pause_changed;
        // Always cross the ordinary owned-event wait, including when a stop bit was set between
        // the preceding observation and re-arm. A generic entry event can win that race at the
        // dispatcher's owned event-site breakpoint. Calling `break_on_demand` directly would
        // treat that real event as an unexpected stop while trying to settle native execution;
        // the ordinary wait instead retains it, after which the loop restores from its exact
        // epoch. The service manifest's generic entry breakpoint supplies the bounded rendezvous.
        let stopped = self
            .session
            .wait_for_stop_for_job(self.engine, self.job, || (**pause_changed)(true));
        crate::worker::drain_service_trace_interrupt(self.engine, self.job);
        stopped
    }

    fn complete_trace_stop(&mut self, stop: &mut StopRecord) -> Result<()> {
        // The controller's primary snapshot is deliberately limited to ownership and recovery
        // state. M6 needs these semantic registers too, so read them twice while this exact epoch
        // remains held and append only after the provider proves the two complete reads agree.
        let registers = [
            RegisterName::Rax,
            RegisterName::Rcx,
            RegisterName::Rdx,
            RegisterName::R8,
            RegisterName::R9,
            RegisterName::R14,
        ];
        let deadline = self.session.stopped_service_deadline()?;
        let values =
            self.session
                .read_stopped_registers_until(&stop.epoch, registers.to_vec(), deadline)?;
        if values.iter().any(|value| value.high.0 != 0) {
            bail!("service-trace general register has a nonzero high half");
        }
        stop.registers.values.extend(values);
        Ok(())
    }

    fn read_trace_memory(&mut self, address: u64, size: u32) -> Result<Vec<u8>, String> {
        let deadline = self
            .session
            .stopped_service_deadline()
            .map_err(|error| format!("{error:#}"))?;
        let read = self
            .session
            .read_memory_until(address, size, deadline)
            .map_err(|error| format!("{error:#}"))?;
        decode_live_hex(&read.data)
    }

    fn rearm_trace(
        &mut self,
        epoch: &crate::skcontrol::StopEpoch,
        breakpoints: &[BreakpointGuard],
    ) -> Result<()> {
        self.session
            .continue_to_breakpoints(self.engine, epoch, breakpoints.to_vec())?;
        (self.pause_changed)(false);
        Ok(())
    }

    fn restore_trace(&mut self, epoch: &crate::skcontrol::StopEpoch) -> Result<()> {
        self.session.continue_from(self.engine, epoch)?;
        (self.pause_changed)(false);
        Ok(())
    }
}

fn finish_service_trace(
    runtime: &mut impl ServiceTraceRuntime,
    epoch: &crate::skcontrol::StopEpoch,
    shared: &crate::skservicetrace::SharedTrace,
) -> Result<crate::skservicetrace::ServiceTrace> {
    // Seal first so a concurrent read can never observe `armed: true` after restoration has
    // begun. Restoration still runs if sealing finds an internal record error.
    let finished = shared.finish().map_err(anyhow::Error::msg);
    let restored = runtime.restore_trace(epoch);
    match (finished, restored) {
        (Ok(trace), Ok(())) => Ok(trace),
        (Err(finish), Ok(())) => Err(finish),
        (Ok(_), Err(restore)) => Err(restore),
        (Err(finish), Err(restore)) => {
            Err(restore.context(format!("the recorder also failed to seal: {finish:#}")))
        }
    }
}

fn drive_service_trace(
    runtime: &mut impl ServiceTraceRuntime,
    shared: &crate::skservicetrace::SharedTrace,
    decoder: &mut crate::skservicetrace::ObservationDecoder,
    breakpoints: &[BreakpointGuard],
    per_buffer_bytes: u32,
) -> Result<crate::skservicetrace::ServiceTrace> {
    loop {
        let mut stop = match runtime.wait_for_trace_stop(shared.stop_requested()) {
            Ok(stop) => stop,
            Err(error) => {
                // LiveControl's wait failure path owns fault recovery because no retained epoch
                // may exist. This layer still seals its public prefix before propagating it.
                let finish = shared.finish().map_err(anyhow::Error::msg);
                return match finish {
                    Ok(_) => Err(error),
                    Err(finish) => {
                        Err(error.context(format!("the recorder also failed to seal: {finish:#}")))
                    }
                };
            }
        };

        if shared.stop_requested() {
            return finish_service_trace(runtime, &stop.epoch, shared);
        }

        if let Err(error) = runtime.complete_trace_stop(&mut stop) {
            let restored = finish_service_trace(runtime, &stop.epoch, shared);
            return match restored {
                Ok(_) => Err(error.context("service-trace register capture failed")),
                Err(restoration) => Err(restoration.context(format!(
                    "service-trace register capture failed before restoration: {error:#}"
                ))),
            };
        }

        // Provider reads stay outside the shared recorder lock. The decoded observation then
        // crosses the same one-lock boundary as a reader-side stop request: whichever wins is
        // authoritative, and a stop that arrived during the reads discards the observation.
        let decoded = decoder.decode(&stop, per_buffer_bytes, |address, size| {
            runtime.read_trace_memory(address, size)
        });
        let observed =
            decoded.and_then(|decoded| shared.observe(move |recorder| decoded.apply(recorder)));
        if let Err(error) = observed {
            let restored = finish_service_trace(runtime, &stop.epoch, shared);
            return match restored {
                Ok(_) => Err(anyhow::Error::msg(error)),
                Err(restoration) => Err(restoration.context(format!(
                    "service observation failed before restoration: {error}"
                ))),
            };
        }
        if shared.stop_requested() || shared.capacity_reached() {
            return finish_service_trace(runtime, &stop.epoch, shared);
        }

        if let Err(error) = runtime.rearm_trace(&stop.epoch, breakpoints) {
            // Guard verification can fail before the replacement transition mutates anything,
            // leaving this exact stop retained and fully releasable. Do not merely seal the
            // recorder and strand it: take the same restore-and-resume path as capacity, stop and
            // decode failures.
            let restored = finish_service_trace(runtime, &stop.epoch, shared);
            return match restored {
                Ok(_) => Err(error),
                Err(restoration) => Err(restoration.context(format!(
                    "service re-arm failed before restoration: {error:#}"
                ))),
            };
        }
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

#[allow(dead_code)] // Returned by the M6.2 worker arm once that operation is exposed.
pub(crate) struct ServiceTraceArm {
    pub(crate) transition: LiveTransition,
    pub(crate) target: TargetIdentity,
    pub(crate) image_base: HexU64,
    pub(crate) proof: crate::skservice::LiveImageProof,
}

#[allow(dead_code)] // Used by the adjacent M6.2 pre-mutation gate.
fn decode_live_hex(encoded: &str) -> Result<Vec<u8>, String> {
    if !encoded.len().is_multiple_of(2) {
        return Err("live-memory provider returned odd-length hexadecimal data".into());
    }
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| {
                "live-memory provider returned non-ASCII hexadecimal data".to_string()
            })?;
            u8::from_str_radix(text, 16)
                .map_err(|_| "live-memory provider returned non-hexadecimal data".to_string())
        })
        .collect()
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

pub(crate) fn render_write(write: &LiveMemoryWrite) -> String {
    format!(
        "Guarded {} byte live VTL1 write at {:#x} (physical {:#x}, epoch {}) verified; rollback is pending until release.\n{} -> {}",
        write.size, write.address.0, write.gpa.0, write.epoch, write.before, write.after
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
                allow_memory_writes: false,
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
        let hardware_stop = session.wait_for_stop(engine, || {})?;
        session.step(
            engine,
            &hardware_stop.epoch,
            crate::sklive::StepGuard {
                instruction: None,
                expected_rips: Vec::new(),
            },
        )?;
        let single_step_stop = session.wait_for_stop(engine, || {})?;
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
    /// Held by the running disarm while a stop was wanted. The next `wait_for_stop` adopts it as
    /// its stop instead of pumping for another.
    adoptable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HandlerRegistration {
    vector: u8,
    context: u64,
}

pub(crate) struct VmwpDispatcherState {
    profile: DispatcherProfile,
    vmwp_pid: u32,
    vm_id: String,
    dispatcher_vnd: Option<u64>,
    discovered_identity: Option<DiscoveredIdentity>,
    identity_discovered: bool,
    live_transport: Option<String>,
    allow_transition_cr3: bool,
    allow_memory_writes: bool,
    /// Derived from startup mutation policy and the selected provider topology/capabilities.
    /// Merely authorizing guarded writes must not install a guest-visible vector-3 intercept.
    software_breakpoint_events_enabled: bool,
    targets: Vec<TargetIdentity>,
    memory: Option<LiveGuestMemory>,
    /// Applied in stopped order and restored in reverse before guest execution is released.
    memory_writes: Vec<PreparedMemoryWrite>,
    /// One-shot `INT3` patches which alone may survive an execution release. They are restored
    /// under the retained sole-VP event before the resulting stop is exposed.
    software_breakpoints: Vec<PreparedMemoryWrite>,
    /// Read from Hyper-V before target discovery can pause or debugger-stop `vmwp`. The exact
    /// worker PID binds this boot-stable configuration to the live-control session.
    vm_processor_count: Option<u32>,
    vmwp_base: Option<u64>,
    handler_contexts: Vec<HandlerRegistration>,
    last_registered_context: Option<u64>,
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
            allow_transition_cr3: false,
            allow_memory_writes: false,
            software_breakpoint_events_enabled: false,
            targets: Vec::new(),
            memory: None,
            memory_writes: Vec::new(),
            software_breakpoints: Vec::new(),
            vm_processor_count: None,
            vmwp_base: None,
            handler_contexts: Vec::new(),
            last_registered_context: None,
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
            retention_notice: None,
        }
    }

    fn cache_vm_processor_count(&mut self) -> Result<()> {
        if self.vm_processor_count.is_none() {
            self.vm_processor_count = Some(resolve_vm_processor_count(&self.vm_id)?);
        }
        Ok(())
    }

    fn require_single_processor_software_breakpoint_scope(&self) -> Result<()> {
        match self.vm_processor_count {
            Some(1) => Ok(()),
            Some(processor_count) => bail!(
                "software breakpoints currently require a Hyper-V VM with exactly one virtual processor; found {processor_count}"
            ),
            None => bail!(
                "software breakpoint mutation lacks a processor count cached during target preparation"
            ),
        }
    }

    fn bind_with_retention_notice<'a>(
        &'a mut self,
        engine: &'a DebugEngine,
        retention_notice: &'a mut dyn FnMut(),
    ) -> VmwpDispatcher<'a> {
        VmwpDispatcher {
            engine,
            state: self,
            retention_notice: Some(retention_notice),
        }
    }

    fn bind_identity(
        &mut self,
        found: DiscoveredIdentity,
        live_transport: String,
        target: &TargetIdentity,
        allow_transition_cr3: bool,
        allow_memory_writes: bool,
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
        self.allow_transition_cr3 = allow_transition_cr3;
        self.allow_memory_writes = allow_memory_writes;
        Ok(())
    }

    fn bind_software_breakpoint_capability(&mut self, supported: bool) -> Result<()> {
        if !matches!(self.phase, DispatcherPhase::Fresh) || !self.handler_contexts.is_empty() {
            bail!("software-breakpoint capability must be bound before handler registration");
        }
        self.software_breakpoint_events_enabled = self.allow_memory_writes && supported;
        Ok(())
    }

    fn open_memory(&mut self, target: &TargetIdentity) -> Result<()> {
        if self.memory.is_none() {
            self.memory = Some(LiveGuestMemory::open(
                self.live_transport
                    .as_deref()
                    .context("the live-memory transport has not been bound")?,
                target,
                self.allow_transition_cr3,
                self.allow_memory_writes,
            )?);
        }
        Ok(())
    }

    fn prepare_guarded_write_until(
        &self,
        write: &GuardedMemoryWrite,
        deadline: Instant,
    ) -> Result<PreparedMemoryWrite> {
        if !self.allow_memory_writes {
            bail!("Secure Kernel memory writes are disabled by startup policy");
        }
        if self.memory_writes.len() >= MAX_PENDING_MEMORY_WRITES {
            bail!(
                "a stopped session may retain at most {MAX_PENDING_MEMORY_WRITES} guarded writes"
            );
        }
        let prepared = self
            .memory
            .as_ref()
            .context("the live VTL1 memory source is absent")?
            .prepare_guarded_write_until(write, deadline)?;
        let start = prepared.address.0;
        let end = start + prepared.original.len() as u64;
        if self.memory_writes.iter().any(|earlier| {
            let earlier_start = earlier.address.0;
            let earlier_end = earlier_start + earlier.original.len() as u64;
            start < earlier_end && earlier_start < end
        }) {
            bail!("guarded writes in one stop may not overlap");
        }
        Ok(prepared)
    }

    fn apply_guarded_write_until(
        &mut self,
        write: PreparedMemoryWrite,
        deadline: Instant,
    ) -> Result<AppliedMemoryWrite> {
        if !self.vm_paused || !self.provider_writes_quiesced {
            bail!("guarded memory mutation requires a proved VM-wide pause");
        }
        // Record rollback ownership before the first mutation attempt. A failed provider response
        // is ambiguous about whether bytes landed, so recovery must restore this range too.
        self.memory_writes.push(write.clone());
        let memory = self
            .memory
            .as_ref()
            .context("the live VTL1 memory source is absent")?;
        memory.write_physical_until(write.gpa, &write.replacement, deadline)?;
        memory.verify_virtual_until(
            write.address,
            &write.replacement,
            "guarded live VTL1 write read-back",
            deadline,
        )?;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            address = format_args!("{:#x}", write.address.0),
            gpa = format_args!("{:#x}", write.gpa.0),
            size = write.replacement.len(),
            "live Secure Kernel control verified a guarded memory write"
        );
        Ok(AppliedMemoryWrite {
            address: write.address,
            gpa: write.gpa,
            original: write.original,
            replacement: write.replacement,
        })
    }

    fn restore_memory_writes_until(&mut self, deadline: Option<Instant>) -> Result<()> {
        while let Some(write) = self.memory_writes.last().cloned() {
            require_completion_deadline(deadline)?;
            let deadline = deadline.unwrap_or_else(|| Instant::now() + LIVE_MEMORY_WAIT);
            let memory = self
                .memory
                .as_ref()
                .context("the live VTL1 memory source is absent during rollback")?;
            memory.write_physical_until(write.gpa, &write.original, deadline)?;
            memory.verify_virtual_until(
                write.address,
                &write.original,
                "guarded live VTL1 rollback read-back",
                deadline,
            )?;
            self.memory_writes.pop();
            tracing::info!(
                target: "windbg_mcp::secure_kernel_mutation",
                address = format_args!("{:#x}", write.address.0),
                gpa = format_args!("{:#x}", write.gpa.0),
                size = write.original.len(),
                "live Secure Kernel control restored a guarded memory write"
            );
        }
        Ok(())
    }

    fn arm_software_breakpoints_until(
        &mut self,
        instructions: &[InstructionGuard],
        deadline: Instant,
    ) -> Result<()> {
        if !self.allow_memory_writes {
            bail!("Secure Kernel software breakpoints are disabled by startup policy");
        }
        if !self.vm_paused || !self.provider_writes_quiesced {
            bail!("software breakpoint mutation requires a proved VM-wide pause");
        }
        self.require_single_processor_software_breakpoint_scope()?;
        if !self.memory_writes.is_empty() {
            bail!("generic guarded writes must be rolled back before software breakpoints run");
        }
        if !self.software_breakpoints.is_empty() {
            bail!("software breakpoints are already armed");
        }
        if instructions.is_empty() || instructions.len() > crate::sklive::MAX_SOFTWARE_BREAKPOINTS {
            bail!(
                "software breakpoint arming requires 1..={} guarded instructions",
                crate::sklive::MAX_SOFTWARE_BREAKPOINTS
            );
        }

        let mut prepared = Vec::with_capacity(instructions.len());
        for instruction in instructions {
            instruction.validate()?;
            let write = GuardedMemoryWrite {
                address: instruction.address,
                expected: vec![instruction.bytes[0]],
                replacement: vec![0xcc],
            };
            write.validate()?;
            let patch = self.prepare_guarded_write_until(&write, deadline)?;
            if prepared
                .iter()
                .any(|earlier: &PreparedMemoryWrite| earlier.address == patch.address)
            {
                bail!("software breakpoint addresses must be distinct");
            }
            prepared.push(patch);
        }

        for patch in prepared {
            // Retain restoration ownership before the first ambiguous provider write.
            self.software_breakpoints.push(patch.clone());
            let memory = self
                .memory
                .as_ref()
                .context("the live VTL1 memory source is absent")?;
            memory.write_physical_until(patch.gpa, &patch.replacement, deadline)?;
            memory.verify_virtual_until(
                patch.address,
                &patch.replacement,
                "software breakpoint patch read-back",
                deadline,
            )?;
        }
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            count = self.software_breakpoints.len(),
            "live Secure Kernel control armed one-shot software breakpoints"
        );
        Ok(())
    }

    fn restore_software_breakpoints_until(&mut self, deadline: Instant) -> Result<()> {
        let sole_vp_event_barrier = self.vm_processor_count == Some(1)
            && self.provider_writes_quiesced
            && self
                .retained_event
                .as_ref()
                .is_some_and(|retained| retained.event.vector == BREAKPOINT_VECTOR);
        if !(self.vm_paused && self.provider_writes_quiesced) && !sole_vp_event_barrier {
            bail!(
                "software breakpoint restoration requires a proved VM-wide pause or sole-VP event"
            );
        }
        while let Some(patch) = self.software_breakpoints.last().cloned() {
            require_completion_deadline(Some(deadline))?;
            let memory = self
                .memory
                .as_ref()
                .context("the live VTL1 memory source is absent during breakpoint restoration")?;
            let current = memory.read_span_until(
                sk::Gva(patch.address.0),
                patch.original.len(),
                "owned software breakpoint before restoration",
                Some(deadline),
            )?;
            if current == patch.original {
                // A failed write reply is ambiguous. Proving the original is already present is a
                // complete rollback; do not demand that the replacement must have landed.
                self.software_breakpoints.pop();
                continue;
            }
            if current != patch.replacement {
                bail!(
                    "owned software breakpoint at {:#x} contains neither its patch nor original",
                    patch.address.0
                );
            }
            memory.write_physical_until(patch.gpa, &patch.original, deadline)?;
            memory.verify_virtual_until(
                patch.address,
                &patch.original,
                "software breakpoint restoration read-back",
                deadline,
            )?;
            self.software_breakpoints.pop();
        }
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            "live Secure Kernel control restored all one-shot software breakpoints"
        );
        Ok(())
    }

    fn record_handler_context(&mut self, vector: u8, context: u64) -> Result<()> {
        if !matches!(vector, DEBUG_VECTOR | BREAKPOINT_VECTOR) {
            bail!("unsupported owned exception vector {vector}");
        }
        if context == 0 {
            bail!("handler registration returned a zero context");
        }
        if self
            .handler_contexts
            .iter()
            .any(|registered| registered.vector == vector || registered.context == context)
        {
            bail!("the dispatcher already owns that handler vector or context");
        }
        self.handler_contexts
            .push(HandlerRegistration { vector, context });
        self.last_registered_context = Some(context);
        Ok(())
    }

    fn handler_context(&self, vector: u8) -> Option<u64> {
        self.handler_contexts
            .iter()
            .find(|registered| registered.vector == vector)
            .map(|registered| registered.context)
    }

    fn current_unregister_handler(&self) -> Option<HandlerRegistration> {
        self.handler_contexts.last().copied()
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
        let retained = self
            .retained_event
            .as_ref()
            .context("the selected provider has no retained dispatcher event")?;
        if !targets
            .iter()
            .any(|target| retained.event.vp == target.vp && retained.event.vtl == target.vtl)
        {
            bail!("the retained dispatcher event does not name the selected provider");
        }
        // A native event holds only its own VP. It is a complete provider-write barrier only for a
        // one-provider controller; fan-out must complete it and prove a VM-wide pause first.
        self.provider_writes_quiesced = targets.len() == 1;
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
            || self.handler_contexts.is_empty()
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
    retention_notice: Option<&'a mut dyn FnMut()>,
}

const WAIT_ARMED: u8 = 0;
const WAIT_ACTIVE: u8 = 1;
const WAIT_FINISHED: u8 = 2;
const WAKE_NONE: u8 = 0;
const WAKE_BREAK: u8 = 1;

/// Cross-thread observation of the exact interval in which DbgEng waits for the owned vmwp site.
///
/// This carries no engine interface. The KD transport pairs it with an `InterruptHandle`, whose
/// sole operation is the repository's documented `SetInterrupt` exception.
#[derive(Clone)]
pub(crate) struct WaitActivity(Arc<WaitActivityState>);

struct WaitActivityState {
    phase: AtomicU8,
    wake: AtomicU8,
    scope_gate: Mutex<()>,
    last_traffic: Mutex<Instant>,
    idle_timeout: Duration,
    owner: Option<WaitOwner>,
    pause_bound: Option<Duration>,
    recovery_bound: Option<Duration>,
    absolute_pause_deadline: Option<Instant>,
    absolute_recovery_deadline: Option<Instant>,
    retained_since: Mutex<Option<Instant>>,
}

#[derive(Clone, Copy)]
enum WaitOwner {
    ManagedKd(u64),
    LiveControl(u64),
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
            Some(WaitOwner::ManagedKd(job)),
        )
    }

    fn for_live_control(
        idle_timeout: Duration,
        pause_bound: Duration,
        recovery_bound: Duration,
        job: u64,
    ) -> Self {
        Self::with_options(
            idle_timeout,
            Some(pause_bound),
            Some(recovery_bound),
            Some(WaitOwner::LiveControl(job)),
        )
    }

    fn for_kd_until(
        idle_timeout: Duration,
        pause_deadline: Instant,
        recovery_deadline: Instant,
    ) -> Self {
        debug_assert!(pause_deadline <= recovery_deadline);
        let mut activity = Self::with_options(idle_timeout, None, None, None);
        let state = Arc::get_mut(&mut activity.0).expect("a new wait activity is uniquely owned");
        state.absolute_pause_deadline = Some(pause_deadline);
        state.absolute_recovery_deadline = Some(recovery_deadline);
        activity
    }

    fn for_live_control_until(
        idle_timeout: Duration,
        pause_deadline: Instant,
        recovery_deadline: Instant,
        job: u64,
    ) -> Self {
        debug_assert!(pause_deadline <= recovery_deadline);
        let mut activity =
            Self::with_options(idle_timeout, None, None, Some(WaitOwner::LiveControl(job)));
        let state = Arc::get_mut(&mut activity.0).expect("a new wait activity is uniquely owned");
        state.absolute_pause_deadline = Some(pause_deadline);
        state.absolute_recovery_deadline = Some(recovery_deadline);
        activity
    }

    fn with_options(
        idle_timeout: Duration,
        pause_bound: Option<Duration>,
        recovery_bound: Option<Duration>,
        owner: Option<WaitOwner>,
    ) -> Self {
        debug_assert!(
            pause_bound
                .zip(recovery_bound)
                .is_none_or(|(pause, recovery)| pause <= recovery)
        );
        Self(Arc::new(WaitActivityState {
            phase: AtomicU8::new(WAIT_ARMED),
            wake: AtomicU8::new(WAKE_NONE),
            scope_gate: Mutex::new(()),
            last_traffic: Mutex::new(Instant::now()),
            idle_timeout,
            owner,
            pause_bound,
            recovery_bound,
            absolute_pause_deadline: None,
            absolute_recovery_deadline: None,
            retained_since: Mutex::new(None),
        }))
    }

    fn mark_stop_retained(&self, since: Instant) -> Option<Instant> {
        let mut retained = self
            .0
            .retained_since
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let since = *retained.get_or_insert(since);
        self.0.absolute_pause_deadline.or_else(|| {
            let bound = self.0.pause_bound?;
            Some(since.checked_add(bound).unwrap_or(since))
        })
    }

    pub(crate) fn retained_since(&self) -> Option<Instant> {
        *self
            .0
            .retained_since
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn pause_deadline(&self) -> Option<Instant> {
        if let Some(deadline) = self.0.absolute_pause_deadline {
            return Some(deadline);
        }
        let since = self.retained_since()?;
        Some(since.checked_add(self.0.pause_bound?).unwrap_or(since))
    }

    fn recovery_deadline(&self) -> Option<Instant> {
        if let Some(deadline) = self.0.absolute_recovery_deadline {
            return Some(deadline);
        }
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

    pub(crate) fn request_break(&self) -> bool {
        self.0
            .wake
            .compare_exchange(WAKE_NONE, WAKE_BREAK, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn cancel_break(&self) {
        let _ = self.0.wake.compare_exchange(
            WAKE_BREAK,
            WAKE_NONE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn break_requested(&self) -> bool {
        self.0.wake.load(Ordering::Acquire) == WAKE_BREAK
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
        let idle = self.0.idle_timeout.saturating_sub(
            self.0
                .last_traffic
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .elapsed(),
        );
        self.pause_deadline()
            .map(|deadline| idle.min(deadline.saturating_duration_since(Instant::now())))
            .unwrap_or(idle)
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
        let (managed, live) = match self.0.owner {
            Some(WaitOwner::ManagedKd(job)) => match crate::worker::begin_kd_wait(job) {
                Some(guard) => (Some(guard), None),
                None => {
                    self.0.phase.store(WAIT_FINISHED, Ordering::Release);
                    bail!("the managed Secure Kernel KD session is ending");
                }
            },
            Some(WaitOwner::LiveControl(job)) => {
                match crate::worker::begin_live_wait(job, self.clone()) {
                    crate::worker::LiveWaitEntry::Entered(guard) => (None, Some(guard)),
                    crate::worker::LiveWaitEntry::BreakRequested => {
                        self.0.phase.store(WAIT_FINISHED, Ordering::Release);
                        return Err(BreakWake.into());
                    }
                    crate::worker::LiveWaitEntry::Refused => {
                        self.0.phase.store(WAIT_FINISHED, Ordering::Release);
                        bail!("the live Secure Kernel session is ending");
                    }
                }
            }
            None => (None, None),
        };
        // Publish the interruptible phase only after the worker's binding guard exists. The scope
        // gate also prevents a transport interrupt from racing the closing transition below.
        self.0.phase.store(WAIT_ACTIVE, Ordering::Release);
        drop(scope);
        Ok(WaitActivityGuard {
            activity: self.clone(),
            managed,
            live,
        })
    }
}

struct WaitActivityGuard {
    activity: WaitActivity,
    managed: Option<crate::worker::KdWaitGuard>,
    live: Option<crate::worker::LiveWaitGuard>,
}

impl Drop for WaitActivityGuard {
    fn drop(&mut self) {
        // Stop transport interrupts, waiting out one already inside the scope gate, before
        // releasing the worker's binding guard. The published interval is therefore wholly
        // contained by the owned DbgEng wait.
        self.activity.finish();
        drop(self.live.take());
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
    /// ordinary vmwp execution. With the VM already paused this no-event stop may detach before
    /// Suspend-VM; otherwise a disarm pumps it under the installed breakpoint until Hyper-V pauses
    /// the VM or an owned event arrives (`pause_or_hold_running_target`).
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunningDisarmPreparation {
    /// The VP may still run and the trace is armed: pump vmwp under the event-site breakpoint
    /// while Hyper-V pauses the VM, holding any owned event that arrives first.
    PumpUntilPausedOrHeld,
    /// A completed step or an earlier transition left the VM paused, so no VP can raise an event:
    /// remove the breakpoint, detach and prove the pause the ordinary way.
    AlreadyPaused,
}

/// What one bounded `g` slice of the running disarm decided (`pause_or_hold_running_target`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DisarmPumpStep {
    /// vmwp stopped at the owned event site: that event is the disarm point.
    HoldEvent,
    /// Hyper-V reported the pause complete while vmwp sat at a watchdog break: no VP can raise an
    /// event any more, and provider writes are quiesced.
    Paused,
    /// The slice expired with the pause still pending and no event; run another.
    KeepPumping,
    /// A host asked for this engine wait to end; the disarm does not continue past that.
    Interrupted,
    /// vmwp stopped somewhere this adapter does not own.
    UnownedStop,
}

/// An arrival at the event site wins over every other reading of the slice, because the event is
/// outstanding whatever else happened and nothing but this adapter may carry it. `pause` is the
/// helper's verdict so far: `None` while it is still running, `Some(true)` once the VM is paused.
fn disarm_pump_step(
    cut_short: Option<&Interruption>,
    at_event_site: bool,
    pause: Option<bool>,
) -> DisarmPumpStep {
    if at_event_site {
        return DisarmPumpStep::HoldEvent;
    }
    match (cut_short, pause) {
        (None, _) => DisarmPumpStep::UnownedStop,
        (Some(Interruption::OnRequest), _) => DisarmPumpStep::Interrupted,
        (Some(Interruption::Deadline { .. }), Some(true)) => DisarmPumpStep::Paused,
        (Some(Interruption::Deadline { .. }), _) => DisarmPumpStep::KeepPumping,
    }
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

    fn running_disarm_preparation(&self, vm_paused: bool) -> Option<RunningDisarmPreparation> {
        match self {
            Self::ReadyForStop | Self::ReadyForStopInterrupted if vm_paused => {
                Some(RunningDisarmPreparation::AlreadyPaused)
            }
            Self::ReadyForStop | Self::ReadyForStopInterrupted => {
                Some(RunningDisarmPreparation::PumpUntilPausedOrHeld)
            }
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
    fn initial_root(
        shape: &sk::GuestShape,
        target: &TargetIdentity,
        allow_transition_cr3: bool,
    ) -> Result<sk::Gpa> {
        let source_root = sk::walkable(shape)
            .map_err(|why| anyhow!("live-memory source is not walkable: {why:?}"))?;
        if source_root.0 != target.expected_cr3.0 && !allow_transition_cr3 {
            bail!(
                "live-memory source CR3 {:?} does not match the bound CR3 {:#x}",
                shape.cr3,
                target.expected_cr3.0
            );
        }
        // The memory transport advertises the canonical Secure Kernel root, while a transition
        // provider may currently be stopped in a trustlet root. Physical reads support either;
        // breakpoint validation must start in the provider's paused address space.
        Ok(sk::Gpa(target.expected_cr3.0))
    }

    fn open(
        command: &str,
        target: &TargetIdentity,
        allow_transition_cr3: bool,
        allow_memory_writes: bool,
    ) -> Result<Self> {
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
        if allow_memory_writes && source.guarded_write_capability().is_none() {
            bail!(
                "startup policy authorized Secure Kernel memory writes, but the live-memory \
                 transport did not advertise bounded instruction-coherent writes"
            );
        }
        let shape = source.shape();
        let root = Self::initial_root(&shape, target, allow_transition_cr3)?;
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
        if self.source.explicit_refresh_capability() {
            let deadline = deadline.unwrap_or_else(|| Instant::now() + LIVE_MEMORY_WAIT);
            self.source
                .refresh_until_cancelled(deadline, crate::worker::kd_teardown_requested)?;
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

    fn read_instruction_until(
        &self,
        address: u64,
        deadline: Option<Instant>,
    ) -> Result<InstructionGuard> {
        let bytes_in_page = sk::PAGE - (address & (sk::PAGE - 1));
        let first_count =
            usize::try_from(bytes_in_page.min(u64::try_from(MAX_AMD64_INSTRUCTION_BYTES).unwrap()))
                .unwrap();
        let mut bytes = self
            .read_span_until(
                sk::Gva(address),
                first_count,
                "live VTL1 break-request instruction read",
                deadline,
            )
            .map_err(|why| anyhow!("reading the break-request instruction failed: {why:?}"))?;
        if instruction_length(&bytes, address).is_none()
            && first_count < MAX_AMD64_INSTRUCTION_BYTES
        {
            let continuation_address = address
                .checked_add(first_count as u64)
                .context("break-request instruction address overflowed at a page boundary")?;
            bytes.extend(
                self.read_span_until(
                    sk::Gva(continuation_address),
                    MAX_AMD64_INSTRUCTION_BYTES - first_count,
                    "live VTL1 break-request instruction continuation read",
                    deadline,
                )
                .context("reading the next page of the break-request instruction")?,
            );
        }
        let length = instruction_length(&bytes, address)
            .context("the paused VTL1 bytes do not decode as one AMD64 instruction")?;
        Ok(InstructionGuard {
            address: HexU64(address),
            bytes: bytes[..length].to_vec(),
        })
    }

    fn prepare_guarded_write_until(
        &self,
        write: &GuardedMemoryWrite,
        deadline: Instant,
    ) -> Result<PreparedMemoryWrite> {
        write.validate()?;
        let max_write = self
            .source
            .guarded_write_capability()
            .context("the live-memory transport does not support guarded writes")?;
        if write.replacement.len() > max_write {
            bail!(
                "the guarded write is {} bytes, exceeding the transport's {max_write}-byte limit",
                write.replacement.len()
            );
        }
        let address = write.address.0;
        if (address & (sk::PAGE - 1)) + write.replacement.len() as u64 > sk::PAGE {
            bail!("a guarded write must remain within one 4 KiB virtual page");
        }
        let gpa = self
            .space
            .translate(sk::Gva(address))
            .with_context(|| format!("nothing in live VTL1 maps {address:#x}"))?;
        if (gpa.0 & (sk::PAGE - 1)) + write.replacement.len() as u64 > sk::PAGE {
            bail!("a guarded write must remain within one 4 KiB physical page");
        }
        let observed = self
            .read_span_until(
                sk::Gva(address),
                write.expected.len(),
                "guarded live VTL1 compare read",
                Some(deadline),
            )
            .with_context(|| format!("comparing guarded VTL1 bytes at {address:#x}"))?;
        if observed != write.expected {
            bail!(
                "guarded write compare failed at {address:#x}: expected {}, observed {}",
                hex(&write.expected),
                hex(&observed)
            );
        }
        Ok(PreparedMemoryWrite {
            address: write.address,
            gpa: HexU64(gpa.0),
            original: observed,
            replacement: write.replacement.clone(),
        })
    }

    fn write_physical_until(&self, gpa: HexU64, bytes: &[u8], deadline: Instant) -> Result<()> {
        self.source.write_chunk_until_cancelled(
            sk::Gpa(gpa.0),
            bytes,
            deadline,
            crate::worker::kd_teardown_requested,
        )
    }

    fn verify_virtual_until(
        &self,
        address: HexU64,
        expected: &[u8],
        operation: &str,
        deadline: Instant,
    ) -> Result<()> {
        let observed = self
            .read_span_until(
                sk::Gva(address.0),
                expected.len(),
                operation,
                Some(deadline),
            )
            .with_context(|| format!("reading live VTL1 at {:#x}", address.0))?;
        if observed != expected {
            bail!(
                "{operation} mismatch at {:#x}: expected {}, observed {}",
                address.0,
                hex(expected),
                hex(&observed)
            );
        }
        Ok(())
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn instruction_length(bytes: &[u8], address: u64) -> Option<usize> {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    (!instruction.is_invalid() && instruction.len() != 0).then(|| instruction.len())
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

impl VmwpDispatcher<'_> {
    fn begin_disarm_inner(
        &mut self,
        targets: &[TargetIdentity],
        deadline: Option<Instant>,
    ) -> Result<Disarmed> {
        targets
            .first()
            .context("running disarm requires at least one selected VP")?;
        let preparation = self
            .state
            .phase
            .running_disarm_preparation(self.state.vm_paused);
        if self.state.targets != targets
            || preparation.is_none()
            || self.state.retained_event.is_some()
            || !self.state.attached
            || self.state.breakpoint.is_none()
        {
            bail!("running disarm requires the armed target set with no retained event");
        }

        match preparation {
            Some(RunningDisarmPreparation::PumpUntilPausedOrHeld) => {
                self.pause_or_hold_running_target(targets, deadline)
            }
            // Suspend-VM can block behind an attached DbgEng target even when no native event
            // exists. With the VM already paused no VP can raise one, so remove the exact owned
            // breakpoint and detach before asking Hyper-V to confirm the pause; reattach only
            // after it proves provider-write quiescence. Teardown still owns the registered
            // callback and scratch allocation.
            Some(RunningDisarmPreparation::AlreadyPaused) | None => {
                self.pause_armed_without_event_inner(targets, deadline)?;
                Ok(Disarmed::Paused)
            }
        }
    }

    /// Disarm a target whose VP may still run.
    ///
    /// The trace is armed while the stop is wanted, so it can fire at any instant, and the VTL1
    /// slots cannot be cleared until the VP is quiescent: held in an owned event, or stopped by a
    /// VM-wide pause. Hyper-V cannot pause the VM while vmwp is debugger-stopped, and the
    /// event-site breakpoint cannot stay installed across a detach, so the one ordering that
    /// observes every intercept the armed slots can raise is this: ask Hyper-V to pause from a
    /// helper thread, and pump vmwp under the installed breakpoint until either the pause is
    /// reported complete at a watchdog break (no VP can raise an event any more) or an owned
    /// event arrives and is retained exactly as a wait retains one. That event is the disarm
    /// point: the controller restores the VTL1 baseline under it, and the pending pause completes
    /// once the event has been carried natively.
    ///
    /// Measured 2026-10-24 (M7.1a run 20261024T210251): the previous shape ran a one-second settle
    /// whose only accepted ending was its own deadline while the trace stayed armed; the next
    /// event faulted the session, and recovery then asked Hyper-V to pause a vmwp the debugger
    /// still held. Its no-event path also opened a window between breakpoint removal, detach and
    /// Suspend-VM in which an intercept would have reached vmwp's handler with nothing watching
    /// it; what the native handler does with a VTL1 `#DB` nobody is waiting for is unmeasured,
    /// and this ordering never finds out.
    fn pause_or_hold_running_target(
        &mut self,
        targets: &[TargetIdentity],
        deadline: Option<Instant>,
    ) -> Result<Disarmed> {
        let target = targets
            .first()
            .context("running disarm requires at least one selected VP")?;
        if self.state.targets != targets
            || self.state.retained_event.is_some()
            || !self.state.attached
            || !matches!(
                self.state.phase,
                DispatcherPhase::ReadyForStop | DispatcherPhase::ReadyForStopInterrupted
            )
        {
            bail!(
                "the running disarm requires the attached armed target set with no retained event"
            );
        }
        let event_site = self.site_address(&self.state.profile.event_held)?;
        let owned = self
            .state
            .breakpoint
            .as_ref()
            .context("the running disarm requires the installed event-site breakpoint")?;
        if owned.address != event_site {
            bail!("the owned vmwp breakpoint is not at the event site");
        }
        // vmwp may already sit at the site with an unread event: a request-owned stop or a fault
        // can land there.
        if self.engine.instruction_pointer().map_err(debugger)? == event_site
            && let Some((event_pointer, event)) =
                self.classify_event_at_site(targets, event_site)?
        {
            return self.hold_event_at_site(event_pointer, event_site, event, targets, deadline);
        }
        // A pause this disarm asked for earlier (recovery re-entering after a fault) is reused; any
        // other pending transition, such as a step's resume kick, is joined before a pause is asked
        // for.
        let pause_pending = self
            .state
            .completion_kick
            .as_ref()
            .is_some_and(|kick| matches!(kick.action, Some(VmAction::Pause)));
        if !pause_pending {
            self.state.finish_completion_kick_until(deadline)?;
        }
        self.state.claim_vm_pause(targets)?;
        if !pause_pending {
            self.state.completion_kick = Some(VmTransition::immediate(
                target.vm_id.clone(),
                VmAction::Pause,
            ));
        }
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vm_id = %target.vm_id,
            "dispatcher asked Hyper-V to pause the VM and is pumping vmwp under its event-site \
             breakpoint until the pause completes or an owned event arrives"
        );
        let bound = deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT)));
        loop {
            let remaining = bound.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.state.phase = DispatcherPhase::ReadyForStopInterrupted;
                bail!(
                    "neither a VM pause nor an owned event arrived before the running disarm \
                     deadline; the VM is retained as possibly paused"
                );
            }
            let slice = remaining.min(DISARM_PUMP_SLICE);
            let timeout = slice.as_millis().clamp(1, u128::from(u32::MAX)) as u32;
            let run = self
                .engine
                .execute_and_wait("g", timeout)
                .map_err(debugger)?;
            if run.target_gone {
                bail!("vmwp left the debugger during the running disarm");
            }
            let rip = self.engine.instruction_pointer().map_err(debugger)?;
            let pause = match self.state.completion_kick.as_mut() {
                Some(kick) => kick.try_finish(),
                None => Some(Ok(())),
            };
            let pause = match pause {
                None => None,
                Some(Ok(())) => {
                    self.state.completion_kick = None;
                    Some(true)
                }
                Some(Err(error)) => {
                    // The helper may have paused the VM before failing its verification; recovery
                    // and teardown issue an idempotent resume.
                    self.state.completion_kick = None;
                    self.state.vm_paused = true;
                    self.state.provider_writes_quiesced = false;
                    return Err(error.context(
                        "the Hyper-V pause failed during the running disarm, so the VM is \
                         conservatively retained as paused",
                    ));
                }
            };
            match disarm_pump_step(run.cut_short.as_ref(), rip == event_site, pause) {
                DisarmPumpStep::HoldEvent => {
                    if let Some((event_pointer, event)) =
                        self.classify_event_at_site(targets, event_site)?
                    {
                        return self.hold_event_at_site(
                            event_pointer,
                            event_site,
                            event,
                            targets,
                            deadline,
                        );
                    }
                    // A handler event this adapter does not own; vmwp carries it natively, as the
                    // ordinary wait lets it.
                }
                DisarmPumpStep::Paused => {
                    self.state.confirm_vm_pause()?;
                    self.state.phase = DispatcherPhase::ReadyForStop;
                    tracing::info!(
                        target: "windbg_mcp::secure_kernel_mutation",
                        vm_id = %target.vm_id,
                        "dispatcher proved the VM pause with its event-site breakpoint still \
                         installed and no event outstanding"
                    );
                    return Ok(Disarmed::Paused);
                }
                DisarmPumpStep::KeepPumping => {}
                DisarmPumpStep::Interrupted => {
                    self.state.phase = DispatcherPhase::ReadyForStopInterrupted;
                    bail!("the running disarm was interrupted on request");
                }
                DisarmPumpStep::UnownedStop => bail!(
                    "vmwp stopped at {rip:#x} for an event the live-control adapter does not own \
                     during the running disarm"
                ),
            }
        }
    }

    /// Retain the owned event vmwp holds at the event site as the disarm point.
    fn hold_event_at_site(
        &mut self,
        event_pointer: u64,
        event_site: u64,
        event: HeldEvent,
        targets: &[TargetIdentity],
        deadline: Option<Instant>,
    ) -> Result<Disarmed> {
        // The pending pause cannot complete while this event is outstanding, so retention must not
        // join it: set it aside, and it is joined after the event has been carried natively.
        let pending_pause = self.state.completion_kick.take();
        let retained = self.retain_current_event(event_pointer, event_site, &event, deadline);
        if self.state.completion_kick.is_none() {
            self.state.completion_kick = pending_pause;
        }
        retained?;
        self.state
            .retained_event
            .as_mut()
            .context("the held event lost its retained-thread record")?
            .adoptable = true;
        self.state.confirm_retained_provider_stop(targets)?;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            vp = event.vp,
            vector = event.vector,
            "dispatcher held a VTL1 event that arrived during the disarm; it is the disarm point"
        );
        Ok(Disarmed::Held(event))
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
        Ok(HexU64(self.state.handler_context(DEBUG_VECTOR).context(
            "the registered vector-1 handler returned no context",
        )?))
    }

    fn software_breakpoint_context(&self) -> Option<HexU64> {
        self.state.handler_context(BREAKPOINT_VECTOR).map(HexU64)
    }

    fn verify_software_breakpoint_scope_until(&mut self, deadline: Instant) -> Result<()> {
        require_completion_deadline(Some(deadline))?;
        self.state
            .require_single_processor_software_breakpoint_scope()
    }

    fn begin_disarm(&mut self, targets: &[TargetIdentity]) -> Result<Disarmed> {
        self.begin_disarm_inner(targets, None)
    }

    fn begin_disarm_until(
        &mut self,
        targets: &[TargetIdentity],
        deadline: Instant,
    ) -> Result<Disarmed> {
        self.begin_disarm_inner(targets, Some(deadline))
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

    fn has_pending_guarded_writes(&self) -> bool {
        !self.state.memory_writes.is_empty()
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

    fn capture_instruction(&mut self, address: u64) -> Result<InstructionGuard> {
        self.state
            .memory
            .as_ref()
            .context("the live VTL1 memory source is absent")?
            .read_instruction_until(address, None)
    }

    fn capture_instruction_until(
        &mut self,
        address: u64,
        deadline: Instant,
    ) -> Result<InstructionGuard> {
        self.state
            .memory
            .as_ref()
            .context("the live VTL1 memory source is absent")?
            .read_instruction_until(address, Some(deadline))
    }

    fn prepare_guarded_write_until(
        &mut self,
        write: &GuardedMemoryWrite,
        deadline: Instant,
    ) -> Result<PreparedMemoryWrite> {
        self.state.prepare_guarded_write_until(write, deadline)
    }

    fn apply_guarded_write_until(
        &mut self,
        write: PreparedMemoryWrite,
        deadline: Instant,
    ) -> Result<AppliedMemoryWrite> {
        self.state.apply_guarded_write_until(write, deadline)
    }

    fn arm_software_breakpoints_until(
        &mut self,
        instructions: &[InstructionGuard],
        deadline: Instant,
    ) -> Result<()> {
        self.state
            .arm_software_breakpoints_until(instructions, deadline)
    }

    fn restore_software_breakpoints_until(&mut self, deadline: Instant) -> Result<()> {
        self.state.restore_software_breakpoints_until(deadline)
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
        let adoptable = match (&self.state.phase, &self.state.retained_event) {
            (DispatcherPhase::Holding(held), Some(retained))
                if retained.adoptable && &retained.event == held =>
            {
                Some(held.clone())
            }
            _ => None,
        };
        let (event, pause_deadline) = if let Some(event) = adoptable {
            // The running disarm held this event while a stop was wanted
            // (`pause_or_hold_running_target`). It is this wait's stop; the VM pause the disarm
            // asked for stays pending behind it and is joined after the event has been carried
            // natively, so nothing here may join the transition.
            self.state
                .retained_event
                .as_mut()
                .context("the adoptable event lost its retained-thread record")?
                .adoptable = false;
            let pause_deadline = self
                .state
                .wait_activity
                .as_ref()
                .and_then(|activity| activity.mark_stop_retained(Instant::now()));
            if let Some(notice) = self.retention_notice.take() {
                notice();
            }
            self.state.confirm_retained_provider_stop(targets)?;
            tracing::info!(
                target: "windbg_mcp::secure_kernel_mutation",
                vp = event.vp,
                "live Secure Kernel wait adopted the VTL1 event held by the disarm as its stop"
            );
            (event, pause_deadline)
        } else {
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
                // A completed step can leave the delayed native-completion kick pending while the
                // VM remains paused. Cancel that delay and begin the resume needed for this exact
                // wait.
                self.state.finish_completion_kick()?;
                self.state.begin_vm_resume();
                self.state.completion_kick = Some(VmTransition::immediate(
                    primary.vm_id.clone(),
                    VmAction::Resume,
                ));
            }

            let deadline = Instant::now() + Duration::from_millis(u64::from(DEBUG_WAIT));
            let (event_pointer, event) =
                self.wait_for_owned_event(targets, event_site, deadline)?;
            // The callback is held as soon as the owned breakpoint returns. Start the absolute
            // budget before any retention cleanup, including a pending Hyper-V transition join.
            let retained_at = Instant::now();
            let pause_deadline = self
                .state
                .wait_activity
                .as_ref()
                .and_then(|activity| activity.mark_stop_retained(retained_at));
            if let Some(notice) = self.retention_notice.take() {
                notice();
            }
            self.retain_current_event(event_pointer, event_site, &event, pause_deadline)?;
            self.state.vm_paused = false;
            self.state.confirm_retained_provider_stop(targets)?;
            (event, pause_deadline)
        };
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

    fn release_event_and_pause(
        &mut self,
        event: &HeldEvent,
        targets: &[TargetIdentity],
    ) -> Result<()> {
        self.release_event_and_pause_inner(event, targets, None)
    }

    fn release_event_and_pause_until(
        &mut self,
        event: &HeldEvent,
        targets: &[TargetIdentity],
        deadline: Instant,
    ) -> Result<()> {
        self.release_event_and_pause_inner(event, targets, Some(deadline))
    }

    fn release_paused(&mut self) -> Result<()> {
        self.release_paused_inner(None)
    }

    fn release_paused_until(&mut self, deadline: Instant) -> Result<()> {
        self.release_paused_inner(Some(deadline))
    }

    fn retain_pause_for_software_breakpoint_wait_until(&mut self, deadline: Instant) -> Result<()> {
        require_completion_deadline(Some(deadline))?;
        if self.state.retained_event.is_some()
            || !self.state.vm_paused
            || !self.state.provider_writes_quiesced
            || !matches!(self.state.phase, DispatcherPhase::ReadyForStop)
            || !self.state.attached
            || self.state.threads_frozen
        {
            bail!("software-breakpoint wait requires a proved attached VM pause");
        }
        if self.state.software_breakpoints.is_empty() {
            bail!("software-breakpoint wait has no owned patches");
        }
        if !self.state.memory_writes.is_empty() {
            bail!("software-breakpoint wait found generic guarded writes still applied");
        }
        if self.state.breakpoint.is_none() {
            let site = self.state.profile.event_held.clone();
            self.set_site_breakpoint(&site)?;
        }
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            "live Secure Kernel control retained its pause for the software-breakpoint wait"
        );
        Ok(())
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
    fn release_event_and_pause_inner(
        &mut self,
        event: &HeldEvent,
        targets: &[TargetIdentity],
        deadline: Option<Instant>,
    ) -> Result<()> {
        let retained = self
            .state
            .retained_event
            .as_ref()
            .map(|retained| &retained.event)
            .context("the dispatcher owns no event to release before the VM pause")?;
        if retained != event {
            bail!("post-event pause does not name the event held by the dispatcher");
        }
        self.state.restore_memory_writes_until(deadline)?;
        self.complete_retained_event(event, deadline)?;
        self.pause_armed_without_event_inner(targets, deadline)?;
        self.state.recovery_deadline = None;
        Ok(())
    }

    fn release_paused_inner(&mut self, deadline: Option<Instant>) -> Result<()> {
        if self.state.retained_event.is_some()
            || !self.state.vm_paused
            || !self.state.provider_writes_quiesced
            || !matches!(self.state.phase, DispatcherPhase::ReadyForStop)
        {
            bail!("release_paused requires a proved post-event VM pause");
        }
        self.state.restore_memory_writes_until(deadline)?;
        if !self.state.software_breakpoints.is_empty() {
            bail!("refusing to resume while software breakpoint patches remain applied");
        }
        require_completion_deadline(deadline)?;
        if self.state.breakpoint.is_some() {
            self.remove_owned_breakpoint()?;
        }
        if self.state.threads_frozen {
            self.thaw_threads()?;
        }
        if self.state.attached {
            self.detach_handled()?;
        }
        self.state.finish_completion_kick_until(deadline)?;
        self.state.begin_vm_resume();
        run_vm_action_until(self.bound_vm_id()?, VmAction::Resume, deadline)?;
        self.state.vm_paused = false;
        self.state.phase = DispatcherPhase::Detached;
        self.state.recovery_deadline = None;
        Ok(())
    }

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

        self.state.restore_memory_writes_until(deadline)?;
        if !self.state.software_breakpoints.is_empty() {
            if !self.state.vm_paused || !self.state.provider_writes_quiesced {
                bail!("teardown cannot restore software breakpoints without a proved VM pause");
            }
            self.state.restore_software_breakpoints_until(
                deadline.unwrap_or_else(|| Instant::now() + LIVE_MEMORY_WAIT),
            )?;
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
        if !self.state.handler_contexts.is_empty() {
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
        // A debugger-held vmwp blocks Suspend-VM, and a trace still armed can raise an event at
        // any instant, so recovery from a running arm has the same two safe endings as a disarm:
        // an owned event held under the installed breakpoint, or a pause proved while vmwp runs.
        // Pausing from here with vmwp stopped was the 60 s VMMS hang measured on 2026-10-24
        // (M7.1a run 20261024T210251). A pause the failed disarm already asked for is reused.
        if self.state.attached
            && self.state.breakpoint.is_some()
            && matches!(
                self.state.phase,
                DispatcherPhase::ReadyForStop | DispatcherPhase::ReadyForStopInterrupted
            )
        {
            return self
                .pause_or_hold_running_target(targets, deadline)
                .map(|_| ());
        }
        // A wait may fail while its asynchronous Resume-VM is still outstanding. With no retained
        // event, join that helper before a fresh Suspend-VM proves recovery quiescence. An incomplete
        // callback whose exact thread was not retained remains fail-closed.
        let transition_error = self.state.finish_completion_kick_until(deadline).err();
        let pause = if matches!(
            self.state.phase,
            DispatcherPhase::ReadyForStopInterrupted | DispatcherPhase::NativeReturn(_)
        ) {
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
        if !self.state.software_breakpoints.is_empty() {
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
            } else if !self.state.vm_paused || !self.state.provider_writes_quiesced {
                let targets = self.state.targets.clone();
                self.pause_for_provider_writes_inner(&targets, deadline)?;
            }
            // A retained vector-3 event on the Hyper-V-proved sole VP is itself a complete
            // execution barrier. Restore the bytes before that event can ever be completed; doing
            // it afterward would let the rewound VP immediately execute the still-present INT3.
            self.state.restore_software_breakpoints_until(
                deadline.unwrap_or_else(|| Instant::now() + LIVE_MEMORY_WAIT),
            )?;
        }
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

        self.state.restore_memory_writes_until(deadline)?;
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
        if !self.state.memory_writes.is_empty() || !self.state.software_breakpoints.is_empty() {
            bail!("refusing to finish teardown with live-memory mutations still applied");
        }
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
            if let Some(owned) = self.classify_event_at_site(targets, event_site)? {
                return Ok(owned);
            }
            let deadline_expired = self
                .state
                .wait_activity
                .as_ref()
                .map(|activity| activity.remaining_idle().is_zero())
                .unwrap_or_else(|| Instant::now() >= deadline);
            if deadline_expired {
                bail!("too many unrelated dispatcher events before an owned exception event");
            }
        }
    }

    /// Read the native event vmwp holds at the event site and decide whether this adapter owns it:
    /// a vector event for a selected VP through one of its registered handler contexts.
    fn classify_event_at_site(
        &self,
        targets: &[TargetIdentity],
        event_site: u64,
    ) -> Result<Option<(u64, HeldEvent)>> {
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
        let vector = self
            .state
            .handler_contexts
            .iter()
            .find(|registered| registered.context == context)
            .map(|registered| registered.vector);
        if message_type == EVENT_TYPE_VECTOR
            && let Some(vector @ (DEBUG_VECTOR | BREAKPOINT_VECTOR)) = vector
            && let Some(target) = targets.iter().find(|target| target.vp == vp)
        {
            return Ok(Some((
                event_pointer,
                HeldEvent {
                    message_type: HexU64(EVENT_TYPE_VECTOR),
                    vector,
                    vp: target.vp,
                    vtl: target.vtl,
                    cpl: 0,
                    dispatcher_context: HexU64(context),
                    advance_instruction_pointer: false,
                    reason: if vector == DEBUG_VECTOR {
                        StopReason::DebugException
                    } else {
                        StopReason::BreakpointException
                    },
                },
            )));
        }
        Ok(None)
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
            adoptable: false,
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

    fn pause_armed_without_event_inner(
        &mut self,
        targets: &[TargetIdentity],
        deadline: Option<Instant>,
    ) -> Result<()> {
        let target = targets
            .first()
            .context("no-event disarm requires at least one selected VP")?;
        let armed = matches!(
            self.state.phase,
            DispatcherPhase::ReadyForStop | DispatcherPhase::ReadyForStopInterrupted
        ) && self.state.breakpoint.is_some();
        let completed_event = matches!(self.state.phase, DispatcherPhase::NativeReturn(_))
            && self.state.breakpoint.is_none();
        if self.state.targets != targets
            || !(armed || completed_event)
            || self.state.retained_event.is_some()
            || !self.state.attached
        {
            bail!("no-event disarm requires the debugger-stopped armed target set");
        }

        if completed_event {
            self.settle_native_completion(deadline)?;
        } else {
            self.remove_owned_breakpoint()?;
        }
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
                self.state.allow_transition_cr3,
                self.state.allow_memory_writes,
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
        self.register_handler(DEBUG_VECTOR)?;
        if self.state.software_breakpoint_events_enabled {
            // SetThreadContext restores the OS thread exactly, but DbgEng retains the event's old
            // register cache until a new attach. A second injected call in this attach would read
            // the post-return RSP and mistake a non-code stack word for its return boundary.
            self.reattach_after_registration_context_restore()?;
            self.register_handler(BREAKPOINT_VECTOR)?;
        }
        let site = self.state.profile.event_held.clone();
        self.set_site_breakpoint(&site)?;
        self.state.phase = DispatcherPhase::ReadyForStop;
        Ok(())
    }

    fn reattach_after_registration_context_restore(&mut self) -> Result<()> {
        self.detach_handled()?;
        verify_vmwp_pid(&self.state.vm_id, self.state.vmwp_pid)?;
        let pending = self
            .engine
            .attach_process_begin(self.state.vmwp_pid)
            .map_err(debugger)?;
        self.claim_attach();
        pending.wait().map_err(debugger)?;
        self.set_exception_policy()?;
        self.verify_vmwp_build()?;
        self.verify_all_sites()?;
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
        if self.state.handler_context(DEBUG_VECTOR).is_none() || !self.state.scratch_allocated {
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

    fn register_handler(&mut self, vector: u8) -> Result<()> {
        if !matches!(vector, DEBUG_VECTOR | BREAKPOINT_VECTOR) {
            bail!("unsupported owned exception vector {vector}");
        }
        // Each registration is a complete guarded call. In particular, restore RSP before a
        // second vector is registered: the native return pops its synthetic return address, and
        // treating the next stack word as another return boundary can resume into non-code data.
        let saved = HijackContext::capture(self)?;
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
        // From the first guest-memory mutation until the return boundary, original stack and full
        // thread context are proved, recovery must keep vmwp attached and the VM paused. Detaching
        // would let a partially injected registration finish without a context this adapter can
        // unregister.
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
        self.write_register("rdx", u64::from(vector))?;
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
        self.state.record_handler_context(vector, context)?;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            context = format_args!("{context:#x}"),
            vector,
            "dispatcher registered its temporary vmwp exception handler"
        );
        self.write_u64(stack_handler, saved_handler)?;
        self.write_u64(stack_context, saved_context)?;
        saved.restore()?;
        self.thaw_threads()?;
        self.state.phase = DispatcherPhase::Fresh;
        Ok(())
    }

    fn complete_event(&mut self, mode: ReleaseMode, deadline: Option<Instant>) -> Result<()> {
        require_completion_deadline(deadline)?;
        self.state.restore_memory_writes_until(deadline)?;
        if !self.state.software_breakpoints.is_empty() {
            bail!("software breakpoint patches must be restored before an event can be released");
        }
        inject_live_debugger_loss_after_restore()?;
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
            None => {
                let rip = self.engine.instruction_pointer().map_err(debugger)?;
                bail!(
                    "vmwp stopped unexpectedly while settling native event completion at \
                     {rip:#x}; debugger_output={:?}",
                    run.output.trim()
                )
            }
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
        loop {
            require_completion_deadline(deadline)?;
            if self.state.unregister.is_none() && self.state.handler_contexts.is_empty() {
                return Ok(());
            }
            let registered = self
                .state
                .current_unregister_handler()
                .context("no handler context")?;
            let context = registered.context;
            if self.state.unregister.is_none() {
                self.begin_unregister_call(context, deadline)?;
            }
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
                None => continue,
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
        if self.state.handler_contexts.len() > 1 {
            let removed = self
                .state
                .handler_contexts
                .pop()
                .context("the unregistering handler context disappeared")?;
            if removed.context != context {
                bail!("the unregistering handler context changed during cleanup");
            }
            self.state.unregister = None;
            if self.state.attached {
                self.detach_handled()?;
            }
        } else {
            self.state.unregister = Some(UnregisterProgress::ReadyToFreeScratch);
        }
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

    fn verify_owned_scratch(&self, _context: u64) -> Result<()> {
        let callback = self.scratch(self.state.profile.layout.callback_descriptor)?;
        let callback_stub = self.image(self.state.profile.callback_stub_rva.0)?;
        let mirror = callback
            .checked_add(u64::from(self.state.profile.layout.callback_mirror))
            .context("callback mirror address overflowed")?;
        if self.read_u64(self.scratch(self.state.profile.layout.returned_context)?)?
            != self
                .state
                .last_registered_context
                .context("the callback scratch has no recorded registration result")?
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
            let context = self
                .state
                .current_unregister_handler()
                .context("no handler context")?
                .context;
            self.verify_owned_scratch(context)?;
            self.state.retry_unregister_scratch_free()?;
            bail!(
                "callback scratch remained readable after .dvfree; its contents still belong to \
                 this controller, so retry end_session to issue the free again"
            );
        }
        let contexts = std::mem::take(&mut self.state.handler_contexts);
        self.state.scratch_allocated = false;
        self.state.last_registered_context = None;
        self.state.unregister = None;
        tracing::info!(
            target: "windbg_mcp::secure_kernel_mutation",
            contexts = ?contexts,
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
                        // The event-site breakpoint may have won the race with the request. Keep
                        // that real guest stop; treating it as a wake would discard the native
                        // event that the controller is already at the exact owned site to retain.
                        if self.engine.instruction_pointer().map_err(debugger)? == expected {
                            return Ok(());
                        }
                        if matches!(self.state.phase, DispatcherPhase::ReadyForStop) {
                            self.state.phase = DispatcherPhase::ReadyForStopInterrupted;
                        }
                        if self
                            .state
                            .wait_activity
                            .as_ref()
                            .is_some_and(WaitActivity::break_requested)
                        {
                            return Err(BreakWake.into());
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

    /// One register of the held vmwp thread, by the engine's own name for it.
    ///
    /// One index lookup and one value, rather than the whole register bank filtered down to one
    /// name. Every read here is against a **live kernel over KD**, a bank read is one `GetValue`
    /// per register — 214 on the one kernel dbgscope has counted, an ARM64 one — and seventeen of
    /// these reads sit along a single hypercall. The x64 bank this dispatcher actually reads is a
    /// different count and the same shape.
    ///
    /// The names passed are the engine's own lowercase spelling, which is what its index lookup
    /// wants. The case-insensitive match this replaced was against names the engine had just
    /// handed us, so it was comparing its own spelling with itself.
    fn register(&self, name: &str) -> Result<u64> {
        self.engine.integer_register(name).map_err(debugger)
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

fn inject_live_debugger_loss_after_restore() -> Result<()> {
    #[cfg(debug_assertions)]
    if std::env::var_os("WINDBG_MCP_SK_LIVE_FAULT").as_deref()
        == Some(std::ffi::OsStr::new("debugger_loss_after_restore"))
    {
        bail!("injected debugger loss after provider baseline restoration");
    }
    Ok(())
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
    ResolveProcessorCount,
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

fn resolve_vm_processor_count(vm_id: &str) -> Result<u32> {
    let output = run_vm_query(vm_id, VmAction::ResolveProcessorCount, POWERSHELL_WAIT)?;
    parse_vm_processor_count(&output)
}

fn parse_vm_processor_count(output: &str) -> Result<u32> {
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let value = lines
        .next()
        .context("Hyper-V lookup returned no virtual processor count")?;
    if lines.next().is_some() {
        bail!("Hyper-V lookup returned more than one virtual processor count");
    }
    let count = value
        .parse::<u32>()
        .context("Hyper-V lookup returned a non-decimal virtual processor count")?;
    if count == 0 {
        bail!("Hyper-V lookup returned zero virtual processors");
    }
    Ok(count)
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
        VmAction::ResolveProcessorCount => {
            "$ErrorActionPreference='Stop'; \
             $vm=Get-VM -Id ([guid]$env:WINDBG_MCP_SK_VM_ID) -ErrorAction Stop; \
             $processor=Get-VMProcessor -VM $vm -ErrorAction Stop; \
             [Console]::Out.WriteLine([string]$processor.Count)"
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
    /// The single action an immediate transition performs; `None` for the delayed completion kick,
    /// which pauses and then resumes.
    action: Option<VmAction>,
}

impl VmTransition {
    fn immediate(vm_id: String, action: VmAction) -> Self {
        let mut transition = Self::spawn(vm_id, Duration::ZERO, move |vm_id, cancel| {
            run_vm_query_inner(vm_id, action, POWERSHELL_WAIT, Some(cancel))?;
            trace_vm_action(vm_id, action);
            Ok(())
        });
        transition.action = Some(action);
        transition
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
            action: None,
        }
    }

    /// The helper's verdict if it has reported one, without waiting for it. `None` while it is
    /// still running; afterwards the transition is finished and must not be joined again.
    fn try_finish(&mut self) -> Option<Result<()>> {
        let result = match self.result.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return None,
            Err(mpsc::TryRecvError::Disconnected) => Err(anyhow!(
                "Hyper-V transition helper exited without reporting its result"
            )),
        };
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            return Some(Err(anyhow!("Hyper-V transition helper panicked")));
        }
        Some(result)
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
            action: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skcontrol::{HeldEvent, RegisterName, RegisterValue, StopEpoch, StopReason};
    use crate::sklive::{ArmMode, DispatcherLayout, RegisterSnapshot};
    use std::collections::{HashMap, VecDeque};

    const TRACE_IMAGE_BASE: u64 = 0xffff_f807_0000_0000;
    const TRACE_REQUEST: u64 = 0xffff_8000_0000_2000;
    const TRACE_STACK: u64 = 0xffff_8000_0000_3000;

    fn trace_stop(
        manifest: &crate::skservice::ServiceManifest,
        phase: &str,
        epoch: u64,
    ) -> StopRecord {
        let site = manifest
            .sites
            .iter()
            .find(|site| site.phase == phase)
            .unwrap();
        let instruction = manifest
            .breakpoints(TRACE_IMAGE_BASE)
            .unwrap()
            .into_iter()
            .find(|breakpoint| breakpoint.slot == site.slot)
            .unwrap()
            .instruction;
        let phase_registers = match phase {
            "entry" => vec![
                (RegisterName::Rsp, TRACE_STACK),
                (RegisterName::Rcx, TRACE_REQUEST),
                (RegisterName::Rdx, 2),
                (RegisterName::R8, 3),
                (RegisterName::R9, 4),
            ],
            "dispatch" => vec![(RegisterName::R14, TRACE_REQUEST)],
            "return" => vec![(RegisterName::Rax, 0)],
            other => panic!("unknown trace phase {other}"),
        };
        let mut values = phase_registers
            .into_iter()
            .map(|(name, value)| RegisterValue {
                name,
                status: 0,
                low: HexU64(value),
                high: HexU64(0),
            })
            .collect::<Vec<_>>();
        values.push(RegisterValue {
            name: RegisterName::Cr3,
            status: 0,
            low: target().expected_cr3,
            high: HexU64(0),
        });
        StopRecord {
            epoch: StopEpoch::new(format!("trace-stop-{epoch:016x}")).unwrap(),
            target: target(),
            event: HeldEvent {
                message_type: HexU64(1),
                vector: 1,
                vp: 0,
                vtl: 1,
                cpl: 0,
                dispatcher_context: HexU64(0x2000),
                advance_instruction_pointer: false,
                reason: StopReason::HardwareBreakpoint { slot: site.slot },
            },
            registers: RegisterSnapshot { values },
            instruction,
            expected_rips: vec![HexU64(TRACE_IMAGE_BASE + u64::from(site.rva))],
            arm_mode: ArmMode::Natural,
        }
    }

    struct FakeTraceRuntime {
        stops: VecDeque<Result<StopRecord, &'static str>>,
        memory: HashMap<u64, u8>,
        actions: Vec<String>,
        fail_complete: bool,
        fail_rearm: bool,
        fail_restore: bool,
    }

    impl FakeTraceRuntime {
        fn new(stops: impl IntoIterator<Item = Result<StopRecord, &'static str>>) -> Self {
            let mut memory = HashMap::new();
            for (offset, byte) in (TRACE_IMAGE_BASE + 0x2200)
                .to_le_bytes()
                .into_iter()
                .enumerate()
            {
                memory.insert(TRACE_STACK + offset as u64, byte);
            }
            let manifest = crate::skservice::service_manifest().unwrap();
            let mut request = vec![0x11; manifest.request_layout.size as usize];
            request[2..4].copy_from_slice(&47_u16.to_le_bytes());
            for (offset, byte) in request.into_iter().enumerate() {
                memory.insert(TRACE_REQUEST + offset as u64, byte);
            }
            Self {
                stops: stops.into_iter().collect(),
                memory,
                actions: Vec::new(),
                fail_complete: false,
                fail_rearm: false,
                fail_restore: false,
            }
        }

        fn selected_service(&mut self, service: u16) {
            for (offset, byte) in service.to_le_bytes().into_iter().enumerate() {
                self.memory.insert(TRACE_REQUEST + 2 + offset as u64, byte);
            }
        }
    }

    impl ServiceTraceRuntime for FakeTraceRuntime {
        fn wait_for_trace_stop(&mut self, stop_requested: bool) -> Result<StopRecord> {
            self.actions.push(if stop_requested {
                "break_wait".into()
            } else {
                "wait".into()
            });
            self.stops
                .pop_front()
                .unwrap_or(Err("fake trace exhausted its stops"))
                .map_err(anyhow::Error::msg)
        }

        fn complete_trace_stop(&mut self, _stop: &mut StopRecord) -> Result<()> {
            if self.fail_complete {
                bail!("injected semantic-register read failure");
            }
            Ok(())
        }

        fn read_trace_memory(&mut self, address: u64, size: u32) -> Result<Vec<u8>, String> {
            (0..u64::from(size))
                .map(|offset| {
                    self.memory
                        .get(&(address + offset))
                        .copied()
                        .ok_or_else(|| format!("unreadable {:#x}", address + offset))
                })
                .collect()
        }

        fn rearm_trace(
            &mut self,
            epoch: &StopEpoch,
            _breakpoints: &[BreakpointGuard],
        ) -> Result<()> {
            self.actions.push(format!("rearm:{epoch}"));
            if self.fail_rearm {
                bail!("injected re-arm failure");
            }
            Ok(())
        }

        fn restore_trace(&mut self, epoch: &StopEpoch) -> Result<()> {
            self.actions.push(format!("restore:{epoch}"));
            if self.fail_restore {
                bail!("injected restoration failure");
            }
            Ok(())
        }
    }

    fn trace_parts(
        trace_id: &str,
        records: u32,
    ) -> (
        crate::skservicetrace::SharedTrace,
        crate::skservicetrace::ObservationDecoder,
        Vec<BreakpointGuard>,
    ) {
        let manifest = crate::skservice::service_manifest().unwrap();
        let limits = crate::skservicetrace::TraceLimits::checked(records, 16, 1_024).unwrap();
        let recorder = crate::skservicetrace::Recorder::new(
            trace_id.into(),
            None,
            manifest.clone(),
            target(),
            HexU64(TRACE_IMAGE_BASE),
            limits,
        )
        .unwrap();
        let decoder = crate::skservicetrace::ObservationDecoder::new(
            manifest.clone(),
            target(),
            HexU64(TRACE_IMAGE_BASE),
        )
        .unwrap();
        (
            crate::skservicetrace::SharedTrace::new(recorder),
            decoder,
            manifest.breakpoints(TRACE_IMAGE_BASE).unwrap(),
        )
    }

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
                None,
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
            None,
        )
        .unwrap();
        let words = crate::livesrc::split_command(&expanded);

        assert_eq!(words[0], r"C:\provider {vp} {cr3}.exe");
        assert_eq!(&words[1..], ["--partition", "0x85", "--vp", "0"]);
    }

    #[test]
    fn memory_handle_placeholders_expand_only_from_worker_discovery() {
        let target = target();
        let command = "memory --pid {vmwp_pid} --handle {partition_handle} --cr3 {cr3}";
        assert_eq!(
            expand_target_command(command, &target, true, Some((4242, 0x2e0))).unwrap(),
            "memory --pid 4242 --handle 0x2e0 --cr3 0x1201000"
        );
        let error = expand_target_command(command, &target, true, None).unwrap_err();
        assert!(error.to_string().contains("only the live-memory command"));
    }

    #[test]
    fn discovery_free_memory_command_does_not_require_a_partition_handle() {
        let target = target();
        let command = "memory --partition {partition_id} --cr3 {cr3}";
        assert_eq!(
            expand_target_command(command, &target, true, Some((4242, 0))).unwrap(),
            "memory --partition 0x85 --cr3 0x1201000"
        );

        let error = expand_target_command(
            "memory --handle {partition_handle}",
            &target,
            true,
            Some((4242, 0)),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("did not produce a partition handle")
        );
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
    fn vm_processor_lookup_accepts_exactly_one_nonzero_decimal_count() {
        assert_eq!(parse_vm_processor_count("1\r\n").unwrap(), 1);
        assert_eq!(parse_vm_processor_count("16\n").unwrap(), 16);
        assert!(parse_vm_processor_count("").is_err());
        assert!(parse_vm_processor_count("0\n").is_err());
        assert!(parse_vm_processor_count("0x1\n").is_err());
        assert!(parse_vm_processor_count("1\n2\n").is_err());
    }

    #[test]
    fn software_breakpoint_scope_requires_a_cached_single_processor() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();

        assert!(
            state
                .require_single_processor_software_breakpoint_scope()
                .unwrap_err()
                .to_string()
                .contains("cached during target preparation")
        );
        state.vm_processor_count = Some(16);
        assert!(
            state
                .require_single_processor_software_breakpoint_scope()
                .unwrap_err()
                .to_string()
                .contains("found 16")
        );
        state.vm_processor_count = Some(1);
        state
            .require_single_processor_software_breakpoint_scope()
            .unwrap();
    }

    #[test]
    fn vector_three_handler_requires_both_mutation_policy_and_provider_capability() {
        let mut state = VmwpDispatcherState::new(
            profile(),
            4242,
            Some(0x2000_0000_1000),
            "11111111-2222-3333-4444-555555555555".into(),
        )
        .unwrap();

        state.bind_software_breakpoint_capability(true).unwrap();
        assert!(!state.software_breakpoint_events_enabled);

        state.allow_memory_writes = true;
        state.bind_software_breakpoint_capability(false).unwrap();
        assert!(!state.software_breakpoint_events_enabled);

        state.bind_software_breakpoint_capability(true).unwrap();
        assert!(state.software_breakpoint_events_enabled);
    }

    #[test]
    fn write_enabled_preparation_caches_processor_count_before_discovery() {
        let source = include_str!("skdispatch.rs").replace("\r\n", "\n");
        let preparation = source
            .split_once("    fn prepare_pending(\n")
            .expect("pending preparation exists")
            .1
            .split_once("    fn ensure_preparation_succeeded(")
            .expect("pending preparation ends before its result guard")
            .0;
        let cache = preparation
            .find("self.dispatcher.cache_vm_processor_count()?;")
            .expect("write-enabled preparation caches the processor count");
        let discovery = preparation
            .find("dispatcher.prepare_identity(")
            .expect("pending preparation discovers the dispatcher identity");
        assert!(cache < discovery);

        let transition_gate = source
            .split_once("    fn verify_software_breakpoint_scope_until(")
            .expect("software-breakpoint transition gate exists")
            .1
            .split_once("    fn begin_disarm(")
            .expect("transition gate ends before disarm")
            .0;
        assert!(transition_gate.contains("require_single_processor_software_breakpoint_scope"));
        assert!(!transition_gate.contains("ResolveProcessorCount"));
        assert!(!transition_gate.contains("run_vm_query"));
    }

    #[test]
    fn fake_trace_loop_records_one_selected_call_and_restores_at_capacity() {
        let manifest = crate::skservice::service_manifest().unwrap();
        let stops = [
            Ok(trace_stop(&manifest, "entry", 1)),
            Ok(trace_stop(&manifest, "dispatch", 2)),
            Ok(trace_stop(&manifest, "return", 3)),
        ];
        let mut runtime = FakeTraceRuntime::new(stops);
        let (shared, mut decoder, breakpoints) = trace_parts("sktrace-fake-complete", 1);

        let trace =
            drive_service_trace(&mut runtime, &shared, &mut decoder, &breakpoints, 16).unwrap();
        assert_eq!(trace.records.len(), 1);
        assert!(trace.records[0].complete);
        assert!(trace.full);
        assert!(!trace.armed);
        assert_eq!(
            runtime.actions,
            [
                "wait".to_string(),
                format!("rearm:{}", trace_stop(&manifest, "entry", 1).epoch),
                "wait".to_string(),
                format!("rearm:{}", trace_stop(&manifest, "dispatch", 2).epoch),
                "wait".to_string(),
                format!("restore:{}", trace_stop(&manifest, "return", 3).epoch),
            ]
        );
    }

    #[test]
    fn fake_trace_loop_stops_capacity_reached_at_selected_terminal_phases() {
        let manifest = crate::skservice::service_manifest().unwrap();
        let scenarios = [
            vec![
                Ok(trace_stop(&manifest, "entry", 20)),
                Ok(trace_stop(&manifest, "dispatch", 21)),
                Ok(trace_stop(&manifest, "dispatch", 22)),
            ],
            vec![
                Ok(trace_stop(&manifest, "entry", 30)),
                Ok(trace_stop(&manifest, "dispatch", 31)),
                Ok(trace_stop(&manifest, "return", 32)),
            ],
        ];

        for (index, stops) in scenarios.into_iter().enumerate() {
            let mut runtime = FakeTraceRuntime::new(stops);
            let (shared, mut decoder, breakpoints) =
                trace_parts(&format!("sktrace-capacity-{index}"), 1);
            let trace =
                drive_service_trace(&mut runtime, &shared, &mut decoder, &breakpoints, 16).unwrap();
            assert!(trace.full, "scenario {index} did not reach capacity");
            assert!(!trace.armed);
            assert_eq!(
                runtime
                    .actions
                    .iter()
                    .filter(|action| action.starts_with("restore:"))
                    .count(),
                1,
                "scenario {index} did not restore exactly once"
            );
        }
    }

    #[test]
    fn fake_trace_loop_ignores_unproved_reentry_and_out_of_order_return() {
        let manifest = crate::skservice::service_manifest().unwrap();

        let mut nonselected = FakeTraceRuntime::new([
            Ok(trace_stop(&manifest, "entry", 40)),
            Ok(trace_stop(&manifest, "dispatch", 41)),
            Ok(trace_stop(&manifest, "return", 42)),
            Err("injected no-hit bound"),
        ]);
        nonselected.selected_service(48);
        let (shared, mut decoder, breakpoints) = trace_parts("sktrace-nonselected-loop", 8);
        assert!(
            drive_service_trace(&mut nonselected, &shared, &mut decoder, &breakpoints, 16,)
                .unwrap_err()
                .to_string()
                .contains("no-hit")
        );
        let trace = shared.snapshot("sktrace-nonselected-loop").unwrap();
        assert!(trace.records.is_empty());
        assert!(!trace.armed);

        let mut reentry = FakeTraceRuntime::new([
            Ok(trace_stop(&manifest, "entry", 50)),
            Ok(trace_stop(&manifest, "entry", 51)),
            Ok(trace_stop(&manifest, "dispatch", 52)),
            Ok(trace_stop(&manifest, "return", 53)),
            Ok(trace_stop(&manifest, "return", 54)),
            Err("injected no-hit bound"),
        ]);
        let (shared, mut decoder, breakpoints) = trace_parts("sktrace-reentry-loop", 8);
        let _ = drive_service_trace(&mut reentry, &shared, &mut decoder, &breakpoints, 16);
        let trace = shared.snapshot("sktrace-reentry-loop").unwrap();
        assert_eq!(trace.records.len(), 1);
        assert!(trace.records[0].complete);
    }

    #[test]
    fn fake_trace_loop_stop_and_rearm_failure_both_restore_the_exact_epoch() {
        let manifest = crate::skservice::service_manifest().unwrap();
        let stopped = trace_stop(&manifest, "entry", 60);
        let stopped_epoch = stopped.epoch.clone();
        let mut runtime = FakeTraceRuntime::new([Ok(stopped)]);
        let (shared, mut decoder, breakpoints) = trace_parts("sktrace-reader-stop", 8);
        assert_eq!(
            shared.request_stop("sktrace-reader-stop").unwrap(),
            crate::skservicetrace::StopRequest::First
        );
        let trace =
            drive_service_trace(&mut runtime, &shared, &mut decoder, &breakpoints, 16).unwrap();
        assert!(trace.records.is_empty());
        assert_eq!(
            runtime.actions,
            ["break_wait".to_string(), format!("restore:{stopped_epoch}")]
        );

        let stopped = trace_stop(&manifest, "entry", 61);
        let stopped_epoch = stopped.epoch.clone();
        let mut runtime = FakeTraceRuntime::new([Ok(stopped)]);
        runtime.fail_rearm = true;
        let (shared, mut decoder, breakpoints) = trace_parts("sktrace-rearm-failure", 8);
        let error =
            drive_service_trace(&mut runtime, &shared, &mut decoder, &breakpoints, 16).unwrap_err();
        assert!(error.to_string().contains("re-arm failure"), "{error:#}");
        assert_eq!(
            runtime.actions.last(),
            Some(&format!("restore:{stopped_epoch}"))
        );
        assert!(!shared.snapshot("sktrace-rearm-failure").unwrap().armed);
    }

    #[test]
    fn fake_trace_loop_register_failure_seals_and_restores_the_exact_epoch() {
        let manifest = crate::skservice::service_manifest().unwrap();
        let stopped = trace_stop(&manifest, "entry", 62);
        let stopped_epoch = stopped.epoch.clone();
        let mut runtime = FakeTraceRuntime::new([Ok(stopped)]);
        runtime.fail_complete = true;
        let (shared, mut decoder, breakpoints) = trace_parts("sktrace-register-failure", 8);

        let error =
            drive_service_trace(&mut runtime, &shared, &mut decoder, &breakpoints, 16).unwrap_err();
        assert!(error.to_string().contains("register capture"), "{error:#}");
        assert_eq!(
            runtime.actions.last(),
            Some(&format!("restore:{stopped_epoch}"))
        );
        let trace = shared.snapshot("sktrace-register-failure").unwrap();
        assert!(!trace.armed);
        assert!(trace.records.is_empty());
    }

    #[test]
    fn fake_trace_loop_restoration_failure_is_reported_after_the_trace_is_sealed() {
        let manifest = crate::skservice::service_manifest().unwrap();
        let mut runtime = FakeTraceRuntime::new([Ok(trace_stop(&manifest, "entry", 70))]);
        runtime.fail_restore = true;
        let (shared, mut decoder, breakpoints) = trace_parts("sktrace-restore-failure", 8);
        shared.request_stop("sktrace-restore-failure").unwrap();

        let error =
            drive_service_trace(&mut runtime, &shared, &mut decoder, &breakpoints, 16).unwrap_err();
        assert!(
            error.to_string().contains("restoration failure"),
            "{error:#}"
        );
        assert!(!shared.snapshot("sktrace-restore-failure").unwrap().armed);
        assert_eq!(
            runtime
                .actions
                .iter()
                .filter(|action| action.starts_with("restore:"))
                .count(),
            1
        );
    }

    #[test]
    fn fake_trace_loop_reused_epoch_is_refused_then_restored_once() {
        let manifest = crate::skservice::service_manifest().unwrap();
        let entry = trace_stop(&manifest, "entry", 80);
        let epoch = entry.epoch.clone();
        let mut runtime = FakeTraceRuntime::new([Ok(entry.clone()), Ok(entry)]);
        let (shared, mut decoder, breakpoints) = trace_parts("sktrace-reused-epoch", 8);

        let error =
            drive_service_trace(&mut runtime, &shared, &mut decoder, &breakpoints, 16).unwrap_err();
        assert!(error.to_string().contains("stale stop epoch"), "{error:#}");
        assert_eq!(
            runtime
                .actions
                .iter()
                .filter(|action| *action == &format!("restore:{epoch}"))
                .count(),
            1
        );
        let trace = shared.snapshot("sktrace-reused-epoch").unwrap();
        assert!(trace.records.is_empty());
        assert!(!trace.armed);
    }

    #[test]
    fn service_trace_proves_the_live_image_before_breakpoint_mutation() {
        let source = include_str!("skdispatch.rs").replace("\r\n", "\n");
        let body = source
            .split_once("    pub(crate) fn arm_service_trace(\n")
            .expect("the service-trace arm gate exists")
            .1
            .split_once("    fn service_trace_identity(\n")
            .expect("the service-trace arm gate ends before its identity helper")
            .0;
        let identity = source
            .split_once("    fn service_trace_identity(\n")
            .expect("the service-trace identity gate exists")
            .1
            .split_once("    /// Run one M6 service trace")
            .expect("the identity gate ends before the trace loop")
            .0;
        assert!(identity.contains("provider_count() != 1"));
        assert!(identity.contains("explicit_refresh_capability()"));
        let admitted = body
            .find("self.service_trace_identity(epoch)")
            .expect("the arm gate checks the retained identity and single-VP scope");
        let live_proof = body
            .find(".verify_live_image(")
            .expect("the arm gate proves the complete live image");
        let breakpoint_derivation = body
            .find(".breakpoints(image_base)")
            .expect("breakpoints are derived from the proved manifest");
        let mutation = body
            .find("self.continue_to_breakpoints(")
            .expect("the existing atomic breakpoint transition is used");

        assert!(admitted < live_proof);
        assert!(live_proof < breakpoint_derivation);
        assert!(breakpoint_derivation < mutation);
        assert_eq!(body.matches("self.continue_to_breakpoints(").count(), 1);
    }

    #[test]
    fn service_trace_loop_prepares_before_arm_and_seals_before_restore() {
        let source = include_str!("skdispatch.rs").replace("\r\n", "\n");
        let run = source
            .split_once("    pub(crate) fn run_service_trace(\n")
            .expect("the service-trace loop exists")
            .1
            .split_once("    pub(crate) fn secure_kernel_kd(")
            .expect("the service-trace entry point ends before the KD accessor")
            .0;
        let recorder = run
            .find("crate::skservicetrace::Recorder::new(")
            .expect("the recorder is constructed");
        let decoder = run
            .find("crate::skservicetrace::ObservationDecoder::new(")
            .expect("the decoder is constructed");
        let breakpoints = run
            .find(".breakpoints(image_base)")
            .expect("the breakpoint set is derived");
        let arm = run
            .find("self.arm_service_trace(engine, epoch, &manifest)?")
            .expect("the guarded arm starts the live loop");
        let publish = run
            .find("publish(shared.clone())")
            .expect("the shared trace is published after arming");
        let drive = run
            .find("drive_service_trace(")
            .expect("the fakeable trace loop is entered");
        assert!(recorder < arm && decoder < arm && breakpoints < arm && arm < publish);
        assert!(publish < drive);

        let finish = source
            .split_once("fn finish_service_trace(\n")
            .expect("the restoration helper exists")
            .1
            .split_once("fn drive_service_trace(\n")
            .expect("the restoration helper ends before the loop")
            .0;
        let seal = finish
            .find("shared.finish()")
            .expect("the recorder is sealed");
        let restore = finish
            .find("runtime.restore_trace(epoch)")
            .expect("the exact stopped epoch crosses the restoration boundary");
        assert!(seal < restore);

        let driver = source
            .split_once("fn drive_service_trace(\n")
            .expect("the fakeable service-trace loop exists")
            .1
            .split_once("/// A stopped VTL1 read")
            .expect("the fakeable loop ends before the read schema")
            .0;
        assert!(driver.matches("finish_service_trace(").count() >= 4);

        let production = source
            .split_once("impl ServiceTraceRuntime for LiveServiceTraceRuntime<'_> {")
            .expect("the production trace runtime exists")
            .1
            .split_once("fn finish_service_trace(\n")
            .expect("the production runtime ends before the restoration helper")
            .0;
        for register in ["Rax", "Rcx", "Rdx", "R8", "R9", "R14"] {
            assert!(
                production.contains(&format!("RegisterName::{register}")),
                "the production trace runtime omitted {register}"
            );
        }
        assert!(production.contains("read_stopped_registers_until("));
        assert!(production.contains("wait_for_stop_for_job("));
        assert!(!production.contains("break_on_demand("));
        assert!(production.contains("self.session.continue_from(self.engine, epoch)?"));
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

        let break_wake = WaitActivity::new(Duration::from_secs(1));
        assert!(break_wake.request_break());
        assert!(break_wake.break_requested());
        assert!(!break_wake.request_break());
        break_wake.cancel_break();
        assert!(!break_wake.break_requested());
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
    fn a_post_step_wait_is_capped_by_the_original_absolute_pause_window() {
        let now = Instant::now();
        let service_deadline = now + Duration::from_secs(2);
        let recovery_deadline = now + Duration::from_secs(4);
        let activity = WaitActivity::for_kd_until(
            Duration::from_secs(60),
            service_deadline,
            recovery_deadline,
        );

        assert!(activity.remaining_idle() <= Duration::from_secs(2));
        assert_eq!(
            activity.mark_stop_retained(now + Duration::from_secs(1)),
            Some(service_deadline)
        );
        assert_eq!(activity.pause_deadline(), Some(service_deadline));
        assert_eq!(activity.recovery_deadline(), Some(recovery_deadline));
    }

    #[test]
    fn step_and_software_rearm_reuse_the_pause_window_until_a_true_continue() {
        let source = include_str!("skdispatch.rs").replace("\r\n", "\n");
        let wait = source
            .split_once("pub(crate) fn wait_for_stop(\n")
            .expect("the ordinary wait exists")
            .1
            .split_once("pub(crate) fn wait_for_stop_interruptible(")
            .expect("the interruptible wait follows it")
            .0;
        let step = source
            .split_once("pub(crate) fn step_until(\n")
            .expect("the ordinary step exists")
            .1
            .split_once("pub(crate) fn continue_to_breakpoints(\n")
            .expect("continue-to-breakpoints follows it")
            .0;
        let rearmed = source
            .split_once("pub(crate) fn continue_to_breakpoints(\n")
            .expect("continue-to-breakpoints exists")
            .1
            .split_once("pub(crate) fn continue_to_software_breakpoints(\n")
            .expect("continue-to-software-breakpoints follows it")
            .0;
        let software = source
            .split_once("pub(crate) fn continue_to_software_breakpoints(\n")
            .expect("continue-to-software-breakpoints exists")
            .1
            .split_once("pub(crate) fn continue_from(\n")
            .expect("continue follows it")
            .0;
        let continued = source
            .split_once("fn continue_from_until(\n")
            .expect("the ordinary continue exists")
            .1
            .split_once("pub(crate) fn read_memory(")
            .expect("the stopped read follows it")
            .0;

        assert!(
            wait.contains("WaitActivity::for_kd_until(")
                && wait.contains("self.pause_window = Some("),
            "a wait after step must reuse and retain the original absolute pause window: {wait}"
        );
        assert!(
            !step.contains("self.pause_window = None"),
            "step must not end the original absolute pause window: {step}"
        );
        assert!(
            rearmed.contains("self.pause_window = None"),
            "continue-to-breakpoints must end the retained event's pause window: {rearmed}"
        );
        assert!(
            !software.contains("self.pause_window = None"),
            "software re-arm must retain the absolute pause window until its wait: {software}"
        );
        assert!(
            continued.contains("self.pause_window = None"),
            "a successful true continue must end the absolute pause window: {continued}"
        );
    }

    #[test]
    fn ordinary_pause_notice_precedes_all_retention_cleanup() {
        let source = include_str!("skdispatch.rs");
        let flow = source
            .split_once("let retained_at = Instant::now();")
            .expect("the retained-stop boundary exists")
            .1
            .split_once("self.state.vm_paused = false;")
            .expect("the post-retention flow exists")
            .0;
        let notice = flow
            .find("self.retention_notice.take()")
            .expect("the ordinary pause notice is present");
        let cleanup = flow
            .find("self.retain_current_event")
            .expect("retention cleanup is present");

        assert!(
            notice < cleanup,
            "the supervisor deadline must be armed before retention cleanup or provider I/O"
        );
    }

    #[test]
    fn ordinary_stopped_operations_spend_only_the_retained_service_interval() {
        let source = include_str!("skdispatch.rs").replace("\r\n", "\n");
        for (method, bounded_call) in [
            ("pub(crate) fn step(\n", "self.step_until("),
            (
                "pub(crate) fn continue_from(\n",
                "self.continue_from_until(",
            ),
            (
                "pub(crate) fn read_memory(&self,",
                "self.read_memory_inner(address, size, Some(deadline))",
            ),
        ] {
            let body = source
                .split_once(method)
                .unwrap_or_else(|| panic!("{method:?} exists"))
                .1
                .split_once("\n    }")
                .expect("the method body ends")
                .0;
            assert!(
                body.contains("self.stopped_service_deadline()") && body.contains(bounded_call),
                "{method:?} must pass the retained service deadline to {bounded_call:?}: {body}"
            );
        }
    }

    #[test]
    fn session_close_is_bounded_by_the_cleanup_reserve() {
        let source = include_str!("skdispatch.rs").replace("\r\n", "\n");
        let body = source
            .split_once("pub(crate) fn close(&mut self, engine: &DebugEngine) -> Result<()> {\n")
            .expect("the session close method exists")
            .1
            .split_once("\n    }")
            .expect("the session close method ends")
            .0;

        assert!(body.contains("checked_add(CLEANUP_RESERVE)"), "{body}");
        assert!(
            body.contains("self.close_inner(engine, Some(deadline))"),
            "{body}"
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
    fn concrete_live_adapter_loads_the_profile_before_preparing_fan_out() {
        let mut additional = target_request();
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
            allow_memory_writes: false,
            additional_vps: vec![AdditionalVp {
                control_transport: "provider --vp 1".into(),
                target: additional,
            }],
        };

        let error = match Session::open(&request) {
            Ok(_) => panic!("missing profile unexpectedly opened"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("profile"), "{error:#}");
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
            pause_window: None,
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
    fn running_disarm_pumps_unless_the_vm_is_already_paused() {
        assert_eq!(
            DispatcherPhase::ReadyForStop.running_disarm_preparation(false),
            Some(RunningDisarmPreparation::PumpUntilPausedOrHeld)
        );
        assert_eq!(
            DispatcherPhase::ReadyForStop.running_disarm_preparation(true),
            Some(RunningDisarmPreparation::AlreadyPaused)
        );
        // A request-owned debugger stop leaves the trace armed and the VP running exactly as an
        // ordinary wait expiry does, so it takes the same pump rather than detaching first.
        assert_eq!(
            DispatcherPhase::ReadyForStopInterrupted.running_disarm_preparation(false),
            Some(RunningDisarmPreparation::PumpUntilPausedOrHeld)
        );
        assert_eq!(
            DispatcherPhase::ReadyForStopInterrupted.running_disarm_preparation(true),
            Some(RunningDisarmPreparation::AlreadyPaused)
        );
        assert_eq!(
            DispatcherPhase::Detached.running_disarm_preparation(true),
            None
        );
    }

    /// Measured 2026-10-24 (M7.1a run 20261024T210251): with the trace armed, the stop path ran a
    /// settle that accepted only its own deadline, and the event that arrived inside it faulted the
    /// session. An arrival is the disarm point whatever else the slice reports.
    #[test]
    fn an_event_arriving_during_the_disarm_is_the_disarm_point_not_a_fault() {
        let deadline = Interruption::Deadline { after_ms: 250 };
        for cut_short in [None, Some(&Interruption::OnRequest), Some(&deadline)] {
            for pause in [None, Some(true), Some(false)] {
                assert_eq!(
                    disarm_pump_step(cut_short, true, pause),
                    DisarmPumpStep::HoldEvent,
                    "{cut_short:?} {pause:?}"
                );
            }
        }
        assert_eq!(
            disarm_pump_step(Some(&deadline), false, None),
            DisarmPumpStep::KeepPumping
        );
        assert_eq!(
            disarm_pump_step(Some(&deadline), false, Some(true)),
            DisarmPumpStep::Paused
        );
        assert_eq!(
            disarm_pump_step(Some(&Interruption::OnRequest), false, None),
            DisarmPumpStep::Interrupted
        );
        assert_eq!(
            disarm_pump_step(None, false, None),
            DisarmPumpStep::UnownedStop
        );
        assert_eq!(
            disarm_pump_step(None, false, Some(true)),
            DisarmPumpStep::UnownedStop
        );
    }

    #[test]
    fn a_pending_transition_is_polled_without_blocking() {
        let mut delayed = VmTransition::spawn("vm".into(), Duration::from_secs(60), |_, _| Ok(()));
        assert!(delayed.try_finish().is_none());
        assert!(!delayed.finished());
        let _ = delayed.cancel.send(());
        let bound = Instant::now() + Duration::from_secs(5);
        let verdict = loop {
            if let Some(verdict) = delayed.try_finish() {
                break verdict;
            }
            assert!(
                Instant::now() < bound,
                "a cancelled transition reports promptly"
            );
            thread::sleep(Duration::from_millis(5));
        };
        verdict.unwrap();
        assert!(delayed.finished());

        let mut completed = VmTransition::completed_for_test(Ok(()));
        completed.try_finish().unwrap().unwrap();
        assert!(matches!(
            VmTransition::immediate("vm".into(), VmAction::Pause).action,
            Some(VmAction::Pause)
        ));
    }

    /// The running disarm keeps vmwp attached with the event-site breakpoint installed for its
    /// whole pump, asks Hyper-V to pause before the first slice, and never runs the settle that
    /// refuses an arrival. Recovery from a running arm takes the same path instead of pausing a
    /// debugger-held vmwp.
    #[test]
    fn the_running_disarm_pumps_under_its_breakpoint_instead_of_settling() {
        let source = include_str!("skdispatch.rs").replace("\r\n", "\n");
        let disarm = source
            .split_once("    fn begin_disarm_inner(\n")
            .expect("the running disarm exists")
            .1
            .split_once("    fn pause_or_hold_running_target(\n")
            .expect("the pump follows the disarm")
            .0;
        assert!(disarm.contains("pause_or_hold_running_target(targets, deadline)"));
        assert!(!disarm.contains("settle_native_completion"));

        let pump = source
            .split_once("    fn pause_or_hold_running_target(\n")
            .expect("the pump exists")
            .1
            .split_once("    fn hold_event_at_site(\n")
            .expect("the hold follows the pump")
            .0;
        let pause = pump
            .find("VmTransition::immediate(")
            .expect("the pump asks Hyper-V to pause");
        let first_slice = pump
            .find("execute_and_wait(\"g\"")
            .expect("the pump runs vmwp");
        assert!(
            pause < first_slice,
            "the pause is asked for before vmwp first runs"
        );
        assert!(!pump.contains("remove_owned_breakpoint"));
        assert!(!pump.contains("detach_handled"));
        assert!(!pump.contains("settle_native_completion"));
        assert!(
            !pump.contains("run_vm_action"),
            "the pump never blocks on a VMMS call"
        );

        let recovery = source
            .split_once("    fn establish_recovery_pause_inner(\n")
            .expect("recovery quiescence exists")
            .1
            .split_once("    fn recover_inner(\n")
            .expect("recovery follows its pause")
            .0;
        let pump_route = recovery
            .find("pause_or_hold_running_target(targets, deadline)")
            .expect("recovery from a running arm pumps");
        let join = recovery
            .find("finish_completion_kick_until(deadline)")
            .expect("recovery joins a pending transition");
        assert!(
            pump_route < join,
            "a pending pause is reused by the pump rather than joined with vmwp held"
        );
    }

    #[test]
    fn a_matched_event_remains_owned_for_recovery_before_validation_finishes() {
        let event = HeldEvent {
            message_type: HexU64(EVENT_TYPE_VECTOR),
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
            message_type: HexU64(EVENT_TYPE_VECTOR),
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
            adoptable: false,
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
            message_type: HexU64(EVENT_TYPE_VECTOR),
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
            adoptable: false,
        });

        state.retained_event.take().unwrap();

        assert_eq!(state.recovery_deadline, Some(deadline));
    }

    #[test]
    fn an_unvalidated_retained_event_is_contained_before_recovery_can_release_it() {
        let event = HeldEvent {
            message_type: HexU64(EVENT_TYPE_VECTOR),
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
            adoptable: false,
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

        assert!(state.record_handler_context(DEBUG_VECTOR, 0).is_err());
        state
            .record_handler_context(DEBUG_VECTOR, 0x2000_0000_2000)
            .unwrap();
        assert_eq!(state.handler_context(DEBUG_VECTOR), Some(0x2000_0000_2000));
        assert!(
            state
                .record_handler_context(DEBUG_VECTOR, 0x2000_0000_3000)
                .is_err()
        );
        state
            .record_handler_context(BREAKPOINT_VECTOR, 0x2000_0000_3000)
            .unwrap();
        assert_eq!(
            state.handler_context(BREAKPOINT_VECTOR),
            Some(0x2000_0000_3000)
        );
        assert!(state.record_handler_context(4, 0x2000_0000_4000).is_err());
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
    fn every_handler_registration_restores_its_hijacked_thread_context() {
        let source = include_str!("skdispatch.rs").replace("\r\n", "\n");
        let registration = source
            .split_once("    fn register_handler(&mut self, vector: u8) -> Result<()> {\n")
            .expect("handler registration exists")
            .1
            .split_once("    fn complete_event(")
            .expect("handler registration ends before event completion")
            .0;

        let capture = registration
            .find("let saved = HijackContext::capture(self)?;")
            .expect("registration captures the selected thread context");
        let call = registration
            .find("self.run_to_current_breakpoint(")
            .expect("registration runs the guarded native call");
        let restore = registration
            .find("saved.restore()?;")
            .expect("registration restores the selected thread context");
        let thaw = registration
            .find("self.thaw_threads()?;")
            .expect("registration thaws the other vmwp threads");
        assert!(capture < call && call < restore && restore < thaw);
    }

    #[test]
    fn vector_three_registration_starts_in_a_fresh_dbgeng_attach() {
        let source = include_str!("skdispatch.rs").replace("\r\n", "\n");
        let opening = source
            .split_once("    fn open_and_register(\n")
            .expect("open-and-register exists")
            .1
            .split_once("    fn reattach_after_registration_context_restore(")
            .expect("context-refresh helper follows open-and-register")
            .0;

        let debug = opening
            .find("self.register_handler(DEBUG_VECTOR)?;")
            .expect("vector one is registered");
        let capability_gate = opening
            .find("if self.state.software_breakpoint_events_enabled {")
            .expect("vector three is gated by policy and provider capability");
        let refresh = opening
            .find("self.reattach_after_registration_context_restore()?;")
            .expect("DbgEng is reattached after the first context restoration");
        let breakpoint = opening
            .find("self.register_handler(BREAKPOINT_VECTOR)?;")
            .expect("vector three is registered");
        assert!(debug < capability_gate && capability_gate < refresh && refresh < breakpoint);

        let helper = source
            .split_once("    fn reattach_after_registration_context_restore(")
            .expect("context-refresh helper exists")
            .1
            .split_once("    fn prepare_identity(")
            .expect("context-refresh helper ends before identity preparation")
            .0;
        let detach = helper
            .find("self.detach_handled()?;")
            .expect("context refresh detaches the stale debugger view");
        let attach = helper
            .find(".attach_process_begin(self.state.vmwp_pid)")
            .expect("context refresh starts a new attach");
        assert!(detach < attach);
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
        state.handler_contexts.push(HandlerRegistration {
            vector: DEBUG_VECTOR,
            context: 0x2000_0000_2000,
        });
        state.last_registered_context = Some(0x2000_0000_2000);
        state.scratch_allocated = true;
        state.unregister = Some(UnregisterProgress::FreeingScratch);

        state.retry_unregister_scratch_free().unwrap();

        assert_eq!(
            state.unregister,
            Some(UnregisterProgress::ReadyToFreeScratch)
        );
        assert_eq!(state.handler_context(DEBUG_VECTOR), Some(0x2000_0000_2000));
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

    #[test]
    fn strict_memory_binding_rejects_a_different_source_root() {
        let shape = sk::GuestShape {
            cr3: Some(0x220_1000),
            ..sk::GuestShape::default()
        };

        let error = LiveGuestMemory::initial_root(&shape, &target(), false).unwrap_err();

        assert!(error.to_string().contains("does not match the bound CR3"));
    }

    #[test]
    fn transition_memory_binding_starts_in_the_paused_provider_root() {
        let shape = sk::GuestShape {
            cr3: Some(0x220_1000),
            ..sk::GuestShape::default()
        };

        assert_eq!(
            LiveGuestMemory::initial_root(&shape, &target(), true).unwrap(),
            sk::Gpa(target().expected_cr3.0)
        );
    }

    #[test]
    fn transition_memory_binding_still_requires_a_walkable_source() {
        let error =
            LiveGuestMemory::initial_root(&sk::GuestShape::default(), &target(), true).unwrap_err();

        assert!(error.to_string().contains("source is not walkable"));
    }

    #[test]
    fn break_request_instruction_decoder_requires_one_complete_instruction() {
        assert_eq!(instruction_length(&[0x90], 0x1fff), Some(1));
        assert_eq!(instruction_length(&[0xe8], 0x1fff), None);
        assert_eq!(instruction_length(&[0xe8, 0, 0, 0, 0], 0x1fff), Some(5));
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
