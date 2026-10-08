//! Native KD named-pipe facade over the guarded Secure Kernel live-control session.
//!
//! WinDbg is the protocol client. The actual target remains the one-VP VTL1 controller in
//! [`crate::skdispatch`]: virtual reads use its stopped address space, and execution requests are
//! translated to its hardware-breakpoint and trap-flag transitions. No DbgEng instance is created
//! here; [`crate::worker`] lends this role its one engine on the same thread.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::c_void;
use std::fmt;
use std::os::windows::io::AsRawHandle;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use dbgscope::dbgeng::{BreakRequest, DebugEngine, InterruptHandle};
use iced_x86::{Decoder as InstructionDecoder, DecoderOptions, FlowControl};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::sync::mpsc;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::kdapi::{Amd64Context, Amd64ContextValues, ManipulateRequest, Version64};
use crate::kdwire::{Decoder, Frame, TargetLink};
use crate::skcontrol::{RegisterName, RegisterValue};
use crate::sklive::{ArmMode, BreakpointGuard, InstructionGuard, StepGuard, StopRecord};

pub(crate) const TARGET_FLAG: &str = "--sk-kd-target";

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_MAX_PAUSE: Duration = Duration::from_secs(600);
const MAX_PIPE_NAME: usize = 128;
const MAX_INSTRUCTION_BYTES: u32 = 15;
const COMPATIBILITY_PAGE_BYTES: u64 = 0x1000;
const CODE_BACKSCAN_BYTES: u64 = 0x2b;
const CODE_LOOKAHEAD_BYTES: u64 = 0x80;
const STACK_BOOKKEEPING_BYTES: u64 = 0x80;
const KUSER_SHARED_DATA: u64 = 0xffff_f780_0000_0000;
const TRANSPORT_QUEUE_DEPTH: usize = 64;
const NULL_STARTUP_PROBES: [(u64, u32); 2] = [(0, 4), (4, 0x0c)];
const KUSER_STARTUP_PROBES: [(u64, u32); 4] = [
    (KUSER_SHARED_DATA + 0x268, 1),
    (KUSER_SHARED_DATA + 0x3d8, 0x358),
    (KUSER_SHARED_DATA + 0x14, 0x80),
    (KUSER_SHARED_DATA + 0x08, 0x0c),
];

#[derive(Debug)]
struct Disconnected;

impl fmt::Display for Disconnected {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("WinDbg disconnected from the Secure Kernel KD pipe")
    }
}

impl std::error::Error for Disconnected {}

#[derive(Debug)]
struct ManagedTeardown;

impl fmt::Display for ManagedTeardown {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("the MCP supervisor requested Secure Kernel KD teardown")
    }
}

impl std::error::Error for ManagedTeardown {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManagedCompletion {
    TeardownPending,
    Released,
}

enum TransportMessage {
    Frame(Frame),
    Disconnected,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum WaitWakeReason {
    BreakIn,
    Reset,
    Disconnected,
    Transport(String),
    Idle,
}

impl fmt::Display for WaitWakeReason {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BreakIn => out.write_str("WinDbg requested Ctrl+Break while VTL1 was running"),
            Self::Reset => out.write_str("WinDbg reset the KD link while VTL1 was running"),
            Self::Disconnected => out.write_str("WinDbg disconnected while VTL1 was running"),
            Self::Transport(why) => {
                write!(out, "the KD reader failed while VTL1 was running: {why}")
            }
            Self::Idle => {
                out.write_str("WinDbg sent no KD traffic before the running idle timeout")
            }
        }
    }
}

struct ActiveWait {
    activity: crate::skdispatch::WaitActivity,
    reason: Option<WaitWakeReason>,
}

#[derive(Default)]
struct WaitWakeState {
    active: Option<ActiveWait>,
    pending: VecDeque<WaitWakeReason>,
}

impl WaitWakeState {
    fn begin(
        &mut self,
        activity: crate::skdispatch::WaitActivity,
    ) -> Option<crate::skdispatch::WaitActivity> {
        let reason = self.pending.pop_front();
        let wake = reason.as_ref().map(|_| activity.clone());
        self.active = Some(ActiveWait { activity, reason });
        wake
    }

    fn finish(&mut self) -> Option<WaitWakeReason> {
        self.active.take().and_then(|wait| wait.reason)
    }

    fn request(
        &mut self,
        expected: Option<&crate::skdispatch::WaitActivity>,
        reason: WaitWakeReason,
    ) -> Option<crate::skdispatch::WaitActivity> {
        let Some(wait) = self.active.as_mut() else {
            if expected.is_none() {
                self.pending.push_back(reason);
            }
            return None;
        };
        if expected.is_some_and(|expected| !wait.activity.same_wait(expected))
            || wait.reason.is_some()
        {
            return None;
        }
        wait.reason = Some(reason);
        Some(wait.activity.clone())
    }

    fn consume_frame(&mut self, frame: &Frame) {
        let matches = matches!(
            (self.pending.front(), frame),
            (Some(WaitWakeReason::BreakIn), Frame::BreakIn)
                | (
                    Some(WaitWakeReason::Reset),
                    Frame::Control {
                        packet_type: crate::kdwire::PACKET_TYPE_RESET,
                        ..
                    },
                )
                | (
                    Some(WaitWakeReason::Transport(_)),
                    Frame::Malformed { fatal: true, .. }
                )
        );
        if matches {
            self.pending.pop_front();
        }
    }
}

#[derive(Clone)]
struct WaitWaker {
    interrupt: Arc<InterruptHandle>,
    state: Arc<Mutex<WaitWakeState>>,
}

impl WaitWaker {
    fn new(interrupt: InterruptHandle) -> Self {
        Self {
            interrupt: Arc::new(interrupt),
            state: Arc::new(Mutex::new(WaitWakeState::default())),
        }
    }

    fn begin(&self, activity: crate::skdispatch::WaitActivity) {
        let wake = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .begin(activity);
        if let Some(activity) = wake {
            self.spawn_interrupt(activity);
        }
    }

    fn finish(&self) -> Option<WaitWakeReason> {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .finish()
    }

    fn note_traffic(&self) {
        if let Some(wait) = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .active
            .as_mut()
        {
            wait.activity.note_traffic();
        }
    }

    fn consume_frame(&self, frame: &Frame) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .consume_frame(frame);
    }

    fn request(&self, reason: WaitWakeReason) {
        self.request_for(None, reason);
    }

    fn request_for(
        &self,
        expected: Option<&crate::skdispatch::WaitActivity>,
        reason: WaitWakeReason,
    ) {
        let activity = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .request(expected, reason);
        if let Some(activity) = activity {
            self.spawn_interrupt(activity);
        }
    }

    fn spawn_interrupt(&self, activity: crate::skdispatch::WaitActivity) {
        let interrupt = self.interrupt.clone();
        tokio::spawn(async move {
            loop {
                match activity.phase() {
                    crate::skdispatch::WaitActivityPhase::Armed => {}
                    crate::skdispatch::WaitActivityPhase::Active => match interrupt.interrupt() {
                        Ok(BreakRequest::Raised { .. }) => return,
                        Ok(BreakRequest::NothingRunning) => {}
                        Err(error) => {
                            eprintln!("KD wait interrupt failed: {error}");
                            return;
                        }
                    },
                    crate::skdispatch::WaitActivityPhase::Finished => return,
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }

    fn start_idle_watchdog(&self, activity: crate::skdispatch::WaitActivity) {
        let wake = self.clone();
        tokio::spawn(async move {
            loop {
                let remaining = {
                    let active = wake.state.lock().unwrap_or_else(|error| error.into_inner());
                    let Some(wait) = active.active.as_ref() else {
                        return;
                    };
                    if !wait.activity.same_wait(&activity) {
                        return;
                    }
                    if wait.reason.is_some() {
                        return;
                    }
                    wait.activity.remaining_idle()
                };
                if remaining.is_zero() {
                    wake.request_for(Some(&activity), WaitWakeReason::Idle);
                    return;
                }
                tokio::time::sleep(remaining).await;
            }
        });
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedRequest {
    pub(crate) open: crate::skdispatch::OpenRequest,
    pub(crate) pipe: String,
    pub(crate) kernel_base: Option<u64>,
    pub(crate) build: Option<u16>,
    /// Optional standalone assertion for the profile-derived first stop.
    pub(crate) initial: Option<InstructionGuard>,
    pub(crate) arm_mode: ArmMode,
    pub(crate) connect_timeout_ms: u64,
    pub(crate) idle_timeout_ms: u64,
    pub(crate) max_pause_ms: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedOptions {
    pipe: String,
    kernel_base: Option<u64>,
    build: Option<u16>,
    initial: Option<InstructionGuard>,
    arm_mode: ArmMode,
    connect_timeout: Duration,
    idle_timeout: Duration,
    max_pause: Duration,
}

impl ManagedRequest {
    fn parse(args: &[String]) -> Result<Self> {
        let mut profile = None;
        let mut control_transport = None;
        let mut live_transport = None;
        let mut vmwp_pid = None;
        let mut dispatcher_vnd = None;
        let mut vm_id = None;
        let mut partition_id = None;
        let mut vp = 0;
        let mut expected_cr3 = None;
        let mut pipe = None;
        let mut kernel_base = None;
        let mut build = None;
        let mut instruction_address = None;
        let mut instruction_bytes = None;
        let mut arm_mode = ArmMode::Redirect;
        let mut connect_timeout = DEFAULT_CONNECT_TIMEOUT;
        let mut idle_timeout = DEFAULT_IDLE_TIMEOUT;
        let mut max_pause = DEFAULT_MAX_PAUSE;
        let mut at = 0;
        while at < args.len() {
            let value = |at: &mut usize| -> Result<&String> {
                *at += 1;
                args.get(*at)
                    .with_context(|| format!("{} requires a value", args[*at - 1]))
            };
            match args[at].as_str() {
                "--profile" => profile = Some(value(&mut at)?.into()),
                "--control-transport" => control_transport = Some(value(&mut at)?.clone()),
                "--live-transport" => live_transport = Some(value(&mut at)?.clone()),
                "--vmwp-pid" => {
                    vmwp_pid = Some(value(&mut at)?.parse().context("invalid --vmwp-pid")?)
                }
                "--dispatcher-vnd" => {
                    dispatcher_vnd = Some(parse_word("dispatcher-vnd", value(&mut at)?)?)
                }
                "--vm-id" => vm_id = Some(value(&mut at)?.clone()),
                "--partition-id" => {
                    partition_id = Some(parse_word("partition-id", value(&mut at)?)?)
                }
                "--vp" => vp = value(&mut at)?.parse().context("invalid --vp")?,
                "--expected-cr3" => {
                    expected_cr3 = Some(parse_word("expected-cr3", value(&mut at)?)?)
                }
                "--pipe" => pipe = Some(value(&mut at)?.clone()),
                "--kernel-base" => kernel_base = Some(parse_word("kernel-base", value(&mut at)?)?),
                "--build" => build = Some(value(&mut at)?.parse().context("invalid --build")?),
                "--instruction-address" => {
                    instruction_address = Some(parse_word("instruction-address", value(&mut at)?)?)
                }
                "--instruction-bytes" => {
                    instruction_bytes = Some(crate::skdispatch::parse_hex_bytes(value(&mut at)?)?)
                }
                "--arm-mode" => {
                    arm_mode = match value(&mut at)?.as_str() {
                        "redirect" => ArmMode::Redirect,
                        "natural" => ArmMode::Natural,
                        other => {
                            bail!("invalid --arm-mode {other:?}; expected redirect or natural")
                        }
                    }
                }
                "--connect-timeout-ms" => {
                    let milliseconds: u64 = value(&mut at)?
                        .parse()
                        .context("invalid --connect-timeout-ms")?;
                    if milliseconds == 0 || milliseconds > 3_600_000 {
                        bail!("--connect-timeout-ms must be in 1..=3600000");
                    }
                    connect_timeout = Duration::from_millis(milliseconds);
                }
                "--idle-timeout-ms" => {
                    let milliseconds: u64 = value(&mut at)?
                        .parse()
                        .context("invalid --idle-timeout-ms")?;
                    if milliseconds == 0 || milliseconds > 3_600_000 {
                        bail!("--idle-timeout-ms must be in 1..=3600000");
                    }
                    idle_timeout = Duration::from_millis(milliseconds);
                }
                "--max-pause-ms" => {
                    let milliseconds: u64 =
                        value(&mut at)?.parse().context("invalid --max-pause-ms")?;
                    if milliseconds == 0 || milliseconds > 3_600_000 {
                        bail!("--max-pause-ms must be in 1..=3600000");
                    }
                    max_pause = Duration::from_millis(milliseconds);
                }
                other => bail!("unknown Secure Kernel KD argument {other:?}\n\n{}", usage()),
            }
            at += 1;
        }
        let pipe = pipe.context(usage())?;
        if pipe.is_empty()
            || pipe.len() > MAX_PIPE_NAME
            || !pipe
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            bail!(
                "--pipe must contain 1..={MAX_PIPE_NAME} ASCII letters, digits, dots, dashes or underscores"
            );
        }
        let vm_id = vm_id.context(usage())?;
        let vmwp_pid = match vmwp_pid {
            Some(pid) => pid,
            None => crate::skdispatch::resolve_vmwp_pid(&vm_id, None)?,
        };
        let target = crate::skdispatch::TargetRequest {
            vm_id,
            partition_id: partition_id.map(crate::skcontrol::HexU64),
            vp,
            expected_cr3: expected_cr3.map(crate::skcontrol::HexU64),
        };
        target.validate()?;
        Ok(Self {
            open: crate::skdispatch::OpenRequest {
                profile: profile.context(usage())?,
                control_transport: control_transport.context(usage())?,
                live_transport: live_transport.context(usage())?,
                vmwp_pid,
                dispatcher_vnd,
                target,
                allow_transition_cr3: false,
                additional_vps: Vec::new(),
            },
            pipe,
            kernel_base,
            build,
            initial: match (instruction_address, instruction_bytes) {
                (Some(address), Some(bytes)) => Some(InstructionGuard {
                    address: crate::skcontrol::HexU64(address),
                    bytes,
                }),
                (None, None) => None,
                _ => {
                    bail!("--instruction-address and --instruction-bytes must be supplied together")
                }
            },
            arm_mode,
            connect_timeout_ms: connect_timeout.as_millis() as u64,
            idle_timeout_ms: idle_timeout.as_millis() as u64,
            max_pause_ms: max_pause.as_millis() as u64,
        })
    }
}

pub(crate) fn run(args: &[String], engine: &DebugEngine) -> Result<()> {
    let request = ManagedRequest::parse(args)?;
    let (mut session, options, skipped) = open_managed(&request)?;
    for line in skipped {
        eprintln!("control provider: {line}");
    }
    // DbgEng remains on this calling thread. Tokio's worker threads service only the KD pipe and
    // may use the engine's narrow `InterruptHandle` while this thread is inside the owned wait.
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(run_async(&options, engine, &mut session, false, None));
    if result
        .as_ref()
        .is_err_and(|error| error.downcast_ref::<Disconnected>().is_some())
    {
        eprintln!("WinDbg disconnected; restoring the held Secure Kernel stop");
    }
    match (result, session.close(engine)) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) if primary.downcast_ref::<Disconnected>().is_some() => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup.context("closing Secure Kernel KD target")),
        (Err(primary), Err(cleanup)) => Err(anyhow!("{primary:#}; cleanup: {cleanup:#}")),
    }
}

pub(crate) fn open_managed(
    request: &ManagedRequest,
) -> Result<(crate::skdispatch::Session, ManagedOptions, Vec<String>)> {
    validate_pipe_name(&request.pipe)?;
    if request.connect_timeout_ms == 0 || request.connect_timeout_ms > 3_600_000 {
        bail!("Secure Kernel KD connect_timeout_ms must be in 1..=3600000");
    }
    if request.idle_timeout_ms == 0 || request.idle_timeout_ms > 3_600_000 {
        bail!("Secure Kernel KD idle_timeout_ms must be in 1..=3600000");
    }
    if request.max_pause_ms == 0 || request.max_pause_ms > 3_600_000 {
        bail!("Secure Kernel KD max_pause_ms must be in 1..=3600000");
    }
    if let Some(initial) = &request.initial {
        initial.validate()?;
    }
    let (session, skipped) = crate::skdispatch::Session::open(&request.open)?;
    Ok((
        session,
        ManagedOptions {
            pipe: request.pipe.clone(),
            kernel_base: request.kernel_base,
            build: request.build,
            initial: request.initial.clone(),
            arm_mode: request.arm_mode,
            connect_timeout: Duration::from_millis(request.connect_timeout_ms),
            idle_timeout: Duration::from_millis(request.idle_timeout_ms),
            max_pause: Duration::from_millis(request.max_pause_ms),
        },
        skipped,
    ))
}

pub(crate) fn serve_managed(
    options: &ManagedOptions,
    engine: &DebugEngine,
    session: &mut crate::skdispatch::Session,
    job: u64,
) -> Result<()> {
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(run_async(options, engine, session, true, Some(job)));
    let teardown_requested = result
        .as_ref()
        .is_err_and(|error| error.downcast_ref::<ManagedTeardown>().is_some())
        || crate::worker::kd_teardown_requested();
    if !teardown_requested {
        report_managed_phase(Some(job), crate::proto::SecureKernelKdPhase::Releasing);
        if let Err(error) = &result {
            eprintln!(
                "Secure Kernel KD service ended ({error:#}); restoring and releasing its controller"
            );
        }
    }
    let completion = finish_managed(result, teardown_requested, || session.close(engine))?;
    if completion == ManagedCompletion::Released {
        report_managed_phase(Some(job), crate::proto::SecureKernelKdPhase::Released);
    }
    Ok(())
}

fn finish_managed(
    result: Result<()>,
    teardown_requested: bool,
    close: impl FnOnce() -> Result<()>,
) -> Result<ManagedCompletion> {
    if teardown_requested
        || result
            .as_ref()
            .is_err_and(|error| error.downcast_ref::<ManagedTeardown>().is_some())
    {
        return Ok(ManagedCompletion::TeardownPending);
    }
    let cleanup = close();
    match (result, cleanup) {
        (Ok(()), Ok(())) | (Err(_), Ok(())) => Ok(ManagedCompletion::Released),
        (Ok(()), Err(cleanup)) => Err(cleanup.context("closing Secure Kernel KD target")),
        (Err(primary), Err(cleanup)) => Err(anyhow!(
            "{primary:#}; closing Secure Kernel KD target also failed: {cleanup:#}"
        )),
    }
}

fn validate_pipe_name(pipe: &str) -> Result<()> {
    if pipe.is_empty()
        || pipe.len() > MAX_PIPE_NAME
        || !pipe
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!(
            "KD pipe must contain 1..={MAX_PIPE_NAME} ASCII letters, digits, dots, dashes or \
             underscores"
        );
    }
    Ok(())
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this owns the handle returned by OpenProcess or OpenProcessToken.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: both conversion APIs document their output as LocalFree-owned.
            unsafe { LocalFree(self.0) };
        }
    }
}

pub(crate) fn create_kd_pipe(
    path: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle for this process.
    let sid = process_user_sid(unsafe { GetCurrentProcess() })
        .map_err(|error| std::io::Error::other(format!("{error:#}")))?;

    // Protected DACL: the exact server account, LocalSystem and builtin Administrators only.
    let mut sddl = format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)(A;;GA;;;BA)")
        .encode_utf16()
        .collect::<Vec<_>>();
    sddl.push(0);
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and `descriptor` is a writable output pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let descriptor = LocalAllocation(descriptor);
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: `attributes` and its descriptor stay live until CreateNamedPipeW returns. Windows
    // captures the descriptor into the new object, so freeing it after this call is valid.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                path,
                std::ptr::from_mut(&mut attributes).cast::<c_void>(),
            )
    }
}

pub(crate) fn pipe_client_identity(
    pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Result<(u32, String)> {
    let mut pid = 0;
    // SAFETY: the Tokio pipe owns a connected server handle and `pid` is a writable out pointer.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("reading the Secure Kernel KD pipe client PID");
    }
    if pid == 0 {
        bail!("the Secure Kernel KD pipe reported client PID zero");
    }
    // SAFETY: the returned process handle is owned here and closed by `OwnedHandle`.
    let process = OwnedHandle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    if process.0.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening Secure Kernel KD pipe client PID {pid}"));
    }
    let sid = process_user_sid(process.0)
        .with_context(|| format!("reading Secure Kernel KD pipe client PID {pid} token"))?;
    let owner = process_user_sid(unsafe { GetCurrentProcess() })?;
    if sid != owner && sid != "S-1-5-18" {
        bail!(
            "Secure Kernel KD pipe client PID {pid} runs as {sid}, not the server account {owner} \
             or LocalSystem"
        );
    }
    Ok((pid, sid))
}

fn process_user_sid(process: HANDLE) -> Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is a valid process or pseudo-handle and `token` is writable.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("opening process token");
    }
    let token = OwnedHandle(token);
    let mut required = 0;
    // SAFETY: a null buffer with size zero is the documented size query.
    unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut required) };
    if required == 0 {
        return Err(std::io::Error::last_os_error()).context("sizing token user information");
    }
    let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0usize; words];
    // SAFETY: `storage` is aligned for TOKEN_USER and has the byte length Windows requested.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("reading token user information");
    }
    // SAFETY: a successful TokenUser query begins with a TOKEN_USER.
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text = std::ptr::null_mut();
    // SAFETY: the SID pointer belongs to the token-information buffer and remains live here.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_text) } == 0 {
        return Err(std::io::Error::last_os_error()).context("formatting token user SID");
    }
    let sid_text_guard = LocalAllocation(sid_text.cast());
    let mut length = 0;
    // SAFETY: ConvertSidToStringSidW returned a NUL-terminated UTF-16 allocation.
    while unsafe { *sid_text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: the loop found the terminator inside the API-owned string.
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, length) })
        .context("token user SID is not valid UTF-16")?;
    drop(sid_text_guard);
    Ok(text)
}

fn report_managed_phase(managed_job: Option<u64>, phase: crate::proto::SecureKernelKdPhase) {
    if managed_job.is_some() {
        crate::worker::report_sk_kd_phase(phase);
    }
}

async fn run_async(
    options: &ManagedOptions,
    engine: &DebugEngine,
    session: &mut crate::skdispatch::Session,
    reconnect: bool,
    managed_job: Option<u64>,
) -> Result<()> {
    refuse_managed_teardown()?;
    report_managed_phase(managed_job, crate::proto::SecureKernelKdPhase::Discovering);
    for line in session.prepare_for_kd(engine)? {
        eprintln!("control provider: {line}");
    }
    let provider_kernel_base = session
        .kernel_base()
        .context("the live-memory provider did not report the Secure Kernel base")?;
    if let Some(asserted) = options.kernel_base
        && asserted != provider_kernel_base
    {
        bail!(
            "provider-reported Secure Kernel base {provider_kernel_base:#x} does not match assertion {asserted:#x}"
        );
    }
    let profile = session
        .secure_kernel_kd()
        .context("the dispatcher profile has no secure_kernel_kd section")?;
    if let Some(asserted) = options.build
        && asserted != profile.build
    {
        bail!(
            "profiled Secure Kernel build {} does not match standalone assertion {asserted}",
            profile.build
        );
    }
    let initial_rva = profile.initial.rva.0;
    let initial = InstructionGuard {
        address: crate::skcontrol::HexU64(
            provider_kernel_base
                .checked_add(initial_rva)
                .context("profiled Secure Kernel initial address overflowed")?,
        ),
        bytes: profile.initial.original.clone(),
    };
    initial.validate()?;
    if let Some(asserted) = &options.initial
        && asserted != &initial
    {
        bail!(
            "profile-derived Secure Kernel initial stop {:#x} does not match the standalone assertion",
            initial.address.0
        );
    }
    // WinDbg gives a serial target only a few seconds after reset before it reconnects. Capture the
    // initial event first, so accepting the pipe promises that a state-change packet is ready now.
    eprintln!(
        "arming initial Secure Kernel stop at {:#x}",
        initial.address.0
    );
    report_managed_phase(managed_job, crate::proto::SecureKernelKdPhase::Arming);
    session.arm(
        engine,
        vec![BreakpointGuard {
            slot: 0,
            instruction: initial,
        }],
        options.arm_mode,
    )?;
    report_managed_phase(managed_job, crate::proto::SecureKernelKdPhase::Running);
    let initial_activity = wait_activity(options.idle_timeout, managed_job);
    let mut stop = session.wait_for_stop_interruptible(engine, &initial_activity)?;
    let mut stopped_since = Instant::now();
    let mut stopped_deadline = pause_deadline(stopped_since, options.max_pause)?;
    refuse_managed_teardown()?;
    report_managed_phase(managed_job, crate::proto::SecureKernelKdPhase::Stopped);
    let kernel_base = provider_kernel_base;
    let metadata = validate_debugger_metadata(
        session,
        kernel_base,
        &profile.debugger_data,
        stopped_deadline,
    )?;
    let (mut values, mut context) = read_context(session, &stop, stopped_deadline)?;
    let mut reported_instruction = read_instruction_guard(session, values.rip, stopped_deadline)?;

    let path = format!(r"\\.\pipe\{}", options.pipe);
    let mut reconnecting = false;
    'connections: loop {
        let connect_wait =
            bounded_pause_wait(options.connect_timeout, stopped_since, options.max_pause)?;
        let pipe = create_kd_pipe(&path)
            .with_context(|| format!("creating Secure Kernel KD pipe {path}"))?;
        eprintln!(
            "Secure Kernel stop held at {:#x}; waiting for WinDbg on {path}",
            values.rip
        );
        report_managed_phase(
            managed_job,
            if reconnecting {
                crate::proto::SecureKernelKdPhase::Reconnecting
            } else {
                crate::proto::SecureKernelKdPhase::WaitingForPeer
            },
        );
        tokio::select! {
            connected = tokio::time::timeout(connect_wait, pipe.connect()) => {
                connected
                    .with_context(|| {
                        if stopped_since.elapsed() >= options.max_pause {
                            "the absolute Secure Kernel pause bound expired while waiting for WinDbg"
                        } else {
                            "waiting for WinDbg to connect timed out"
                        }
                    })??;
            }
            () = wait_for_managed_teardown() => return Err(ManagedTeardown.into()),
        }
        let (client_pid, client_sid) = pipe_client_identity(&pipe)?;
        eprintln!("accepted Secure Kernel KD client PID {client_pid} as {client_sid}");
        report_managed_phase(managed_job, crate::proto::SecureKernelKdPhase::Stopped);

        let (reader, mut writer) = tokio::io::split(pipe);
        let (transport_tx, mut transport_rx) = mpsc::channel(TRANSPORT_QUEUE_DEPTH);
        let wait_waker = WaitWaker::new(engine.interrupt_handle());
        let reader_waker = wait_waker.clone();
        tokio::spawn(read_transport(reader, transport_tx, reader_waker));
        let mut link = TargetLink::new();
        let reset_wait =
            bounded_pause_wait(options.connect_timeout, stopped_since, options.max_pause)?;
        let reset = tokio::select! {
            reset = tokio::time::timeout(
                reset_wait,
                wait_for_reset(
                    &mut writer,
                    &mut transport_rx,
                    &mut link,
                    stopped_since,
                    options.max_pause,
                    &wait_waker,
                ),
            ) => {
                reset.with_context(|| {
                    if stopped_since.elapsed() >= options.max_pause {
                        "the absolute Secure Kernel pause bound expired while waiting for WinDbg's KD reset"
                    } else {
                        "waiting for WinDbg's KD reset timed out"
                    }
                })?
            }
            () = wait_for_managed_teardown() => return Err(ManagedTeardown.into()),
        };
        if let Err(error) = reset {
            if reconnect && error.downcast_ref::<Disconnected>().is_some() {
                reconnecting = true;
                continue 'connections;
            }
            return Err(error);
        }
        send_stop(
            &mut writer,
            &mut link,
            &reported_instruction.bytes,
            &values,
            stopped_since,
            options.max_pause,
        )
        .await?;
        eprintln!("initial KD state change sent");

        let mut breakpoints = BTreeMap::<u32, BreakpointGuard>::new();
        let mut compatibility = CompatibilityMemory::default();
        loop {
            let frame_wait =
                bounded_pause_wait(options.idle_timeout, stopped_since, options.max_pause)?;
            let next = tokio::select! {
                frame = tokio::time::timeout(frame_wait, read_frame(&mut transport_rx, &wait_waker)) => {
                    frame.with_context(|| {
                        if stopped_since.elapsed() >= options.max_pause {
                            "the absolute Secure Kernel pause bound expired while serving WinDbg"
                        } else {
                            "WinDbg sent no KD traffic before the idle timeout"
                        }
                    })?
                }
                () = wait_for_managed_teardown() => return Err(ManagedTeardown.into()),
            };
            let frame = match next {
                Ok(frame) => frame,
                Err(error) if reconnect && error.downcast_ref::<Disconnected>().is_some() => {
                    reconnecting = true;
                    continue 'connections;
                }
                Err(error) => return Err(error),
            };
            let inbound = link.receive(frame);
            let peer_reset = inbound.peer_reset;
            let break_in = inbound.break_in;
            let protocol_error = inbound.protocol_error;
            for write in inbound.writes {
                write_stopped_pipe(&mut writer, &write, stopped_since, options.max_pause).await?;
            }
            if let Some(error) = protocol_error {
                flush_stopped_pipe(&mut writer, stopped_since, options.max_pause).await?;
                bail!("KD peer exceeded the consecutive framing-error bound: {error}");
            }
            if break_in {
                tracing::warn!(
                    "Secure Kernel KD break-in is unsupported while the target is already stopped; \
                     the retained stop was left unchanged"
                );
                flush_stopped_pipe(&mut writer, stopped_since, options.max_pause).await?;
                continue;
            }
            if peer_reset {
                compatibility = CompatibilityMemory::default();
                breakpoints.clear();
                send_stop(
                    &mut writer,
                    &mut link,
                    &reported_instruction.bytes,
                    &values,
                    stopped_since,
                    options.max_pause,
                )
                .await?;
                eprintln!("KD peer reset; current held stop resent");
                continue;
            }
            let Some(packet) = inbound.packet else {
                flush_stopped_pipe(&mut writer, stopped_since, options.max_pause).await?;
                continue;
            };
            if packet.packet_type != crate::kdwire::PACKET_TYPE_STATE_MANIPULATE {
                flush_stopped_pipe(&mut writer, stopped_since, options.max_pause).await?;
                continue;
            }
            let request = match ManipulateRequest::decode(&packet.payload) {
                Ok(request) => request,
                Err(error) => {
                    tracing::warn!("refusing malformed Secure Kernel KD request: {error}");
                    let response = link
                        .send(
                            crate::kdwire::PACKET_TYPE_STATE_MANIPULATE,
                            &ManipulateRequest::failure_for_payload(&packet.payload),
                        )
                        .map_err(anyhow::Error::msg)?;
                    write_stopped_pipe(&mut writer, &response, stopped_since, options.max_pause)
                        .await?;
                    flush_stopped_pipe(&mut writer, stopped_since, options.max_pause).await?;
                    continue;
                }
            };
            let response = if request.api_number() == crate::kdapi::DBGKD_GET_VERSION_API {
                tracing::info!(
                    build = profile.build,
                    kernel_base = format_args!("{kernel_base:#x}"),
                    debugger_data_list = format_args!("{:#x}", metadata.debugger_data_list),
                    loaded_module_list = format_args!("{:#x}", metadata.loaded_module_list),
                    "serving synthesized Secure Kernel KD version record"
                );
                request.get_version_response(Version64 {
                    build: profile.build,
                    kernel_base,
                    loaded_module_list: metadata.loaded_module_list,
                    debugger_data_list: metadata.debugger_data_list,
                })
            } else if let Some(read) = request.read_virtual_memory() {
                let count = read
                    .count
                    .min((crate::kdwire::MAX_PACKET_BYTES - crate::kdapi::MANIPULATE_BYTES) as u32);
                if let Some(bytes) = compatibility.read(
                    read.address,
                    count,
                    values.gpr[4],
                    values.rip,
                    reported_instruction.bytes.len(),
                ) {
                    tracing::info!(
                        address = format_args!("{:#x}", read.address),
                        count,
                        "serving synthesized Secure Kernel KD compatibility memory"
                    );
                    request.read_virtual_memory_response(&bytes)?
                } else {
                    match session.read_memory_until(read.address, count, stopped_deadline) {
                        Ok(read_result) => {
                            eprintln!(
                                "KD virtual read {:#x}+{count:#x} served by Secure Kernel memory",
                                read.address
                            );
                            request.read_virtual_memory_response(&decode_hex(&read_result.data)?)?
                        }
                        Err(error) => {
                            eprintln!("KD virtual read at {:#x} failed: {error:#}", read.address);
                            request.failure_response()
                        }
                    }
                }
            } else if let Some(read) = request.read_control_space() {
                if read.address == crate::kdapi::AMD64_DEBUG_CONTROL_SPACE_KSPECIAL
                    && read.count as usize <= crate::kdapi::AMD64_SPECIAL_REGISTERS_BYTES
                {
                    let special = crate::kdapi::amd64_special_registers(
                        &values,
                        stopped_low(&stop, RegisterName::Cr3)?,
                    );
                    eprintln!(
                        "KD AMD64 special-register read {:#x}+{:#x}",
                        read.address, read.count
                    );
                    request.read_control_space_response(&special[..read.count as usize])?
                } else {
                    eprintln!(
                        "KD control-space read {:#x}+{:#x} is unsupported",
                        read.address, read.count
                    );
                    request.failure_response()
                }
            } else if let Some((write, _)) = request.write_control_space() {
                eprintln!(
                    "KD control-space write {:#x}+{:#x} is unsupported",
                    write.address, write.count
                );
                request.failure_response()
            } else if request.api_number() == crate::kdapi::DBGKD_GET_CONTEXT_API {
                eprintln!("KD GetContext");
                request.get_context_response(&context)?
            } else if let Some(range) = request.get_context_ex() {
                eprintln!(
                    "KD GetContextEx offset {:#x}, count {:#x}",
                    range.offset, range.count
                );
                match request.get_context_ex_response(&context) {
                    Ok(response) => response,
                    Err(error) => {
                        tracing::warn!("refusing Secure Kernel KD context range: {error}");
                        request.failure_response()
                    }
                }
            } else if let Some(written) = request.set_context() {
                let matches = context.matches_prefix(written);
                eprintln!(
                    "KD SetContext supplied {:#x} bytes, unchanged={matches}",
                    written.len()
                );
                if matches {
                    request.success_response()
                } else {
                    request.failure_response()
                }
            } else if let Some(address) = request.write_breakpoint_address() {
                match insert_breakpoint(session, &mut breakpoints, address, stopped_deadline) {
                    Ok(handle) => request.write_breakpoint_response(handle)?,
                    Err(error) => {
                        eprintln!("KD breakpoint at {address:#x} was refused: {error:#}");
                        request.failure_response()
                    }
                }
            } else if let Some(handle) = request.restore_breakpoint_handle() {
                breakpoints.remove(&handle);
                request.success_response()
            } else if let Some(trace) = request.continue2_trace() {
                eprintln!("KD Continue2 trace={trace}");
                report_managed_phase(managed_job, crate::proto::SecureKernelKdPhase::Running);
                let activity = wait_activity(options.idle_timeout, managed_job);
                wait_waker.begin(activity.clone());
                let resume = if trace {
                    stopped_low(&stop, RegisterName::Rip).and_then(|rip| {
                        read_instruction_guard(session, rip, stopped_deadline)
                            .and_then(fallthrough_step_guard)
                            .and_then(|guard| {
                                session
                                    .step_until(engine, &stop.epoch, guard, stopped_deadline)
                                    .map(|_| ())
                            })
                    })
                } else {
                    if breakpoints.is_empty() {
                        Err(anyhow!(
                            "WinDbg requested continue with no hardware breakpoint installed"
                        ))
                    } else {
                        session
                            .continue_to_breakpoints_until(
                                engine,
                                &stop.epoch,
                                breakpoints.values().cloned().collect(),
                                stopped_deadline,
                            )
                            .map(|_| ())
                    }
                };
                if let Err(error) = resume {
                    activity.finish();
                    wait_waker.finish();
                    if session.phase() != crate::sklive::LivePhase::Stopped {
                        return Err(error);
                    }
                    report_managed_phase(managed_job, crate::proto::SecureKernelKdPhase::Stopped);
                    eprintln!("KD Continue2 refused; current held stop preserved: {error:#}");
                    send_stop(
                        &mut writer,
                        &mut link,
                        &reported_instruction.bytes,
                        &values,
                        stopped_since,
                        options.max_pause,
                    )
                    .await?;
                    continue;
                }
                wait_waker.start_idle_watchdog(activity.clone());
                if let Err(error) = bounded_pipe_io(
                    writer.flush(),
                    options.idle_timeout,
                    "WinDbg did not consume the pending KD output while VTL1 was running",
                )
                .await
                {
                    activity.finish();
                    wait_waker.finish();
                    return Err(error);
                }
                let waited = session.wait_for_stop_interruptible(engine, &activity);
                let wake = wait_waker.finish();
                if crate::worker::kd_teardown_requested() {
                    return Err(ManagedTeardown.into());
                }
                stop = match (waited, wake) {
                    (Ok(stop), _) => stop,
                    (Err(_), Some(WaitWakeReason::Disconnected)) => return Err(Disconnected.into()),
                    (Err(error), Some(reason)) => return Err(error.context(reason.to_string())),
                    (Err(error), None) => return Err(error),
                };
                report_managed_phase(managed_job, crate::proto::SecureKernelKdPhase::Stopped);
                stopped_since = Instant::now();
                stopped_deadline = pause_deadline(stopped_since, options.max_pause)?;
                (values, context) = read_context(session, &stop, stopped_deadline)?;
                reported_instruction =
                    read_instruction_guard(session, values.rip, stopped_deadline)?;
                compatibility = CompatibilityMemory::default();
                send_stop(
                    &mut writer,
                    &mut link,
                    &reported_instruction.bytes,
                    &values,
                    stopped_since,
                    options.max_pause,
                )
                .await?;
                continue;
            } else {
                eprintln!("KD API {:#x} is not implemented", request.api_number());
                request.failure_response()
            };
            let response = link
                .send(crate::kdwire::PACKET_TYPE_STATE_MANIPULATE, &response)
                .map_err(anyhow::Error::msg)?;
            write_stopped_pipe(&mut writer, &response, stopped_since, options.max_pause).await?;
            flush_stopped_pipe(&mut writer, stopped_since, options.max_pause).await?;
        }
    }
}

fn wait_activity(idle_timeout: Duration, job: Option<u64>) -> crate::skdispatch::WaitActivity {
    match job {
        Some(job) => crate::skdispatch::WaitActivity::for_managed_kd(idle_timeout, job),
        None => crate::skdispatch::WaitActivity::new(idle_timeout),
    }
}

fn refuse_managed_teardown() -> Result<()> {
    if crate::worker::kd_teardown_requested() {
        return Err(ManagedTeardown.into());
    }
    Ok(())
}

fn remaining_pause(since: Instant, bound: Duration) -> Result<Duration> {
    bound.checked_sub(since.elapsed()).context(
        "the absolute Secure Kernel pause bound expired; the worker will close the controller",
    )
}

fn pause_deadline(since: Instant, bound: Duration) -> Result<Instant> {
    let deadline = since
        .checked_add(bound)
        .context("the absolute Secure Kernel pause deadline overflowed")?;
    if Instant::now() >= deadline {
        bail!(
            "the absolute Secure Kernel pause bound expired; the worker will close the controller"
        );
    }
    Ok(deadline)
}

fn bounded_pause_wait(requested: Duration, since: Instant, bound: Duration) -> Result<Duration> {
    Ok(requested.min(remaining_pause(since, bound)?))
}

async fn bounded_pipe_io<T>(
    operation: impl std::future::Future<Output = std::io::Result<T>>,
    within: Duration,
    timeout: &str,
) -> Result<T> {
    tokio::select! {
        result = tokio::time::timeout(within, operation) => {
            result.with_context(|| timeout.to_string())?.map_err(Into::into)
        }
        () = wait_for_managed_teardown() => Err(ManagedTeardown.into()),
    }
}

async fn write_stopped_pipe<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    stopped_since: Instant,
    max_pause: Duration,
) -> Result<()> {
    let within = remaining_pause(stopped_since, max_pause)?;
    bounded_pipe_io(
        writer.write_all(bytes),
        within,
        "the absolute Secure Kernel pause bound expired while writing KD output",
    )
    .await
}

async fn flush_stopped_pipe<W: AsyncWrite + Unpin>(
    writer: &mut W,
    stopped_since: Instant,
    max_pause: Duration,
) -> Result<()> {
    let within = remaining_pause(stopped_since, max_pause)?;
    bounded_pipe_io(
        writer.flush(),
        within,
        "the absolute Secure Kernel pause bound expired while flushing KD output",
    )
    .await
}

async fn wait_for_managed_teardown() {
    while !crate::worker::kd_teardown_requested() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_reset<W: AsyncWrite + Unpin>(
    writer: &mut W,
    transport: &mut mpsc::Receiver<TransportMessage>,
    link: &mut TargetLink,
    stopped_since: Instant,
    max_pause: Duration,
    wait_waker: &WaitWaker,
) -> Result<()> {
    loop {
        let inbound = link.receive(read_frame(transport, wait_waker).await?);
        let protocol_error = inbound.protocol_error;
        for write in inbound.writes {
            write_stopped_pipe(writer, &write, stopped_since, max_pause).await?;
        }
        flush_stopped_pipe(writer, stopped_since, max_pause).await?;
        if let Some(error) = protocol_error {
            bail!("KD peer exceeded the consecutive framing-error bound: {error}");
        }
        if inbound.peer_reset {
            return Ok(());
        }
    }
}

async fn read_frame(
    transport: &mut mpsc::Receiver<TransportMessage>,
    wait_waker: &WaitWaker,
) -> Result<Frame> {
    match transport.recv().await {
        Some(TransportMessage::Frame(frame)) => {
            wait_waker.consume_frame(&frame);
            Ok(frame)
        }
        Some(TransportMessage::Disconnected) | None => Err(Disconnected.into()),
        Some(TransportMessage::Failed(why)) => bail!("reading the WinDbg KD stream failed: {why}"),
    }
}

async fn read_transport<R: AsyncRead + Unpin>(
    mut reader: R,
    transport: mpsc::Sender<TransportMessage>,
    wait_waker: WaitWaker,
) {
    let mut decoder = Decoder::default();
    let mut consecutive_decode_failures = 0usize;
    loop {
        loop {
            let frame = match decoder.next() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(error) => {
                    let why = error.to_string();
                    consecutive_decode_failures += 1;
                    let fatal = consecutive_decode_failures >= 3;
                    if fatal {
                        wait_waker.request(WaitWakeReason::Transport(why.clone()));
                    }
                    if !queue_transport(
                        &transport,
                        TransportMessage::Frame(Frame::Malformed {
                            why: why.clone(),
                            fatal,
                        }),
                        &wait_waker,
                    ) {
                        return;
                    }
                    if fatal {
                        return;
                    }
                    continue;
                }
            };
            consecutive_decode_failures = 0;
            wait_waker.note_traffic();
            let wake = match &frame {
                Frame::BreakIn => Some(WaitWakeReason::BreakIn),
                Frame::Control {
                    packet_type: crate::kdwire::PACKET_TYPE_RESET,
                    ..
                } => Some(WaitWakeReason::Reset),
                _ => None,
            };
            if let Some(reason) = wake {
                wait_waker.request(reason);
            }
            if !queue_transport(&transport, TransportMessage::Frame(frame), &wait_waker) {
                return;
            }
        }
        let mut bytes = [0; 4096];
        match reader.read(&mut bytes).await {
            Ok(0) => {
                wait_waker.request(WaitWakeReason::Disconnected);
                let _ = queue_transport(&transport, TransportMessage::Disconnected, &wait_waker);
                return;
            }
            Ok(read) => decoder.push(&bytes[..read]),
            Err(error) => {
                let why = error.to_string();
                wait_waker.request(WaitWakeReason::Transport(why.clone()));
                let _ = queue_transport(&transport, TransportMessage::Failed(why), &wait_waker);
                return;
            }
        }
    }
}

fn queue_transport(
    transport: &mpsc::Sender<TransportMessage>,
    message: TransportMessage,
    wait_waker: &WaitWaker,
) -> bool {
    match transport.try_send(message) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Closed(_)) => false,
        Err(mpsc::error::TrySendError::Full(_)) => {
            wait_waker.request(WaitWakeReason::Transport(format!(
                "the bounded KD input queue exceeded {TRANSPORT_QUEUE_DEPTH} frames"
            )));
            false
        }
    }
}

async fn send_stop<W: AsyncWrite + Unpin>(
    writer: &mut W,
    link: &mut TargetLink,
    instruction: &[u8],
    values: &Amd64ContextValues,
    stopped_since: Instant,
    max_pause: Duration,
) -> Result<()> {
    tracing::info!(
        processor = 0u16,
        number_processors = 1u32,
        synthetic_thread = format_args!("{:#x}", crate::kdapi::SYNTHETIC_THREAD),
        rip = format_args!("{:#x}", values.rip),
        "serving Secure Kernel KD state change; processor 0 maps to the selected guest VP"
    );
    let state = crate::kdapi::breakpoint_state_change(values, instruction)?;
    let packet = link
        .send(crate::kdwire::PACKET_TYPE_STATE_CHANGE64, &state)
        .map_err(anyhow::Error::msg)?;
    write_stopped_pipe(writer, &packet, stopped_since, max_pause).await?;
    flush_stopped_pipe(writer, stopped_since, max_pause).await?;
    Ok(())
}

fn read_context(
    session: &mut crate::skdispatch::Session,
    stop: &StopRecord,
    deadline: Instant,
) -> Result<(Amd64ContextValues, Amd64Context)> {
    let extra = session.read_stopped_registers_until(
        &stop.epoch,
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
            RegisterName::Ds,
            RegisterName::Es,
            RegisterName::Fs,
            RegisterName::Gs,
            RegisterName::Ss,
        ],
        deadline,
    )?;
    let values = context_values(stop, &extra)?;
    let context = Amd64Context::from_values(&values);
    Ok((values, context))
}

fn context_values(stop: &StopRecord, extra: &[RegisterValue]) -> Result<Amd64ContextValues> {
    let all = stop.registers.values.iter().chain(extra);
    let value = |name| {
        all.clone()
            .find(|value| value.name == name)
            .with_context(|| format!("stopped context omitted {name:?}"))
    };
    let low = |name| value(name).map(|value| value.low.0);
    let selector = |name| value(name).map(|value| ((value.high.0 >> 32) & 0xffff) as u16);
    Ok(Amd64ContextValues {
        gpr: [
            low(RegisterName::Rax)?,
            low(RegisterName::Rcx)?,
            low(RegisterName::Rdx)?,
            low(RegisterName::Rbx)?,
            low(RegisterName::Rsp)?,
            low(RegisterName::Rbp)?,
            low(RegisterName::Rsi)?,
            low(RegisterName::Rdi)?,
            low(RegisterName::R8)?,
            low(RegisterName::R9)?,
            low(RegisterName::R10)?,
            low(RegisterName::R11)?,
            low(RegisterName::R12)?,
            low(RegisterName::R13)?,
            low(RegisterName::R14)?,
            low(RegisterName::R15)?,
        ],
        rip: low(RegisterName::Rip)?,
        rflags: low(RegisterName::Rflags)? as u32,
        segments: [
            selector(RegisterName::Cs)?,
            selector(RegisterName::Ds)?,
            selector(RegisterName::Es)?,
            selector(RegisterName::Fs)?,
            selector(RegisterName::Gs)?,
            selector(RegisterName::Ss)?,
        ],
        debug: [
            low(RegisterName::Dr0)?,
            low(RegisterName::Dr1)?,
            low(RegisterName::Dr2)?,
            low(RegisterName::Dr3)?,
            low(RegisterName::Dr6)?,
            low(RegisterName::Dr7)?,
        ],
    })
}

fn insert_breakpoint(
    session: &crate::skdispatch::Session,
    breakpoints: &mut BTreeMap<u32, BreakpointGuard>,
    address: u64,
    deadline: Instant,
) -> Result<u32> {
    if let Some((handle, _)) = breakpoints
        .iter()
        .find(|(_, breakpoint)| breakpoint.instruction.address.0 == address)
    {
        return Ok(*handle);
    }
    let handle = (1..=4)
        .find(|handle| !breakpoints.contains_key(handle))
        .context("all four VTL1 hardware-breakpoint slots are in use")?;
    let instruction = read_instruction_guard(session, address, deadline)?;
    breakpoints.insert(
        handle,
        BreakpointGuard {
            slot: (handle - 1) as u8,
            instruction,
        },
    );
    Ok(handle)
}

fn read_instruction_guard(
    session: &crate::skdispatch::Session,
    address: u64,
    deadline: Instant,
) -> Result<InstructionGuard> {
    let bytes_in_page = COMPATIBILITY_PAGE_BYTES - (address & (COMPATIBILITY_PAGE_BYTES - 1));
    let first_count = u32::try_from(bytes_in_page.min(u64::from(MAX_INSTRUCTION_BYTES))).unwrap();
    let mut bytes = decode_hex(
        &session
            .read_memory_until(address, first_count, deadline)?
            .data,
    )?;
    if instruction_length(&bytes, address).is_none() && first_count < MAX_INSTRUCTION_BYTES {
        let continuation_address = address
            .checked_add(u64::from(first_count))
            .context("instruction address overflowed at the page boundary")?;
        let continuation = session
            .read_memory_until(
                continuation_address,
                MAX_INSTRUCTION_BYTES - first_count,
                deadline,
            )
            .context("reading the next page for an instruction that did not decode before it")?;
        bytes.extend(decode_hex(&continuation.data)?);
    }
    let length = instruction_length(&bytes, address)
        .context("the stopped VTL1 bytes do not decode as one AMD64 instruction")?;
    Ok(InstructionGuard {
        address: crate::skcontrol::HexU64(address),
        bytes: bytes[..length].to_vec(),
    })
}

fn instruction_length(bytes: &[u8], address: u64) -> Option<usize> {
    let mut decoder = InstructionDecoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    (!instruction.is_invalid() && instruction.len() != 0).then(|| instruction.len())
}

/// Build the one-instruction guard accepted by the current KD facade.
///
/// A branch, call, return, interrupt or exception can stop anywhere other than the linear
/// successor. Until the facade can prove that destination from the held context, refusing it here
/// preserves the stop instead of letting a valid vector-1 event fault the session after release.
fn fallthrough_step_guard(instruction: InstructionGuard) -> Result<StepGuard> {
    crate::sklive::validate_step_instruction_class(&instruction)?;
    let mut decoder = InstructionDecoder::with_ip(
        64,
        &instruction.bytes,
        instruction.address.0,
        DecoderOptions::NONE,
    );
    let decoded = decoder.decode();
    if decoded.is_invalid() || decoded.len() != instruction.bytes.len() {
        bail!("the guarded VTL1 bytes do not decode as exactly one AMD64 instruction");
    }
    if decoded.flow_control() != FlowControl::Next {
        bail!(
            "WinDbg single-step is refused for {:?} control flow at {:#x}",
            decoded.flow_control(),
            instruction.address.0
        );
    }
    Ok(StepGuard {
        instruction: Some(instruction),
        expected_rips: Vec::new(),
    })
}

fn stopped_low(stop: &StopRecord, name: RegisterName) -> Result<u64> {
    stop.registers
        .values
        .iter()
        .find(|value| value.name == name)
        .map(|value| value.low.0)
        .with_context(|| format!("stopped snapshot omitted {name:?}"))
}

fn decode_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        bail!("live memory returned an odd-length hexadecimal byte string");
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).context("invalid live-memory hex"))
        .collect()
}

#[derive(Clone, Copy, Debug)]
struct KdMetadata {
    loaded_module_list: u64,
    debugger_data_list: u64,
}

fn validate_debugger_metadata(
    session: &crate::skdispatch::Session,
    kernel_base: u64,
    profile: &crate::sklive::SecureKernelDebuggerDataProfile,
    deadline: Instant,
) -> Result<KdMetadata> {
    let address = |name: &str, rva: u64| {
        kernel_base
            .checked_add(rva)
            .with_context(|| format!("profiled Secure Kernel {name} address overflowed"))
    };
    let list_head = address("debugger-data list", profile.list_head_rva.0)?;
    let block = address("debugger-data block", profile.block_rva.0)?;
    let loaded_module_list = address("loaded-module list", profile.loaded_module_list_rva.0)?;
    let read = |at, size| {
        session
            .read_memory_until(at, size, deadline)
            .and_then(|read| decode_hex(&read.data))
    };
    let head = read(list_head, 0x10)?;
    let data = read(block, 0x50)?;
    let modules = read(loaded_module_list, 0x10)?;
    let quad = |bytes: &[u8], at: usize| -> u64 {
        u64::from_le_bytes(
            bytes[at..at + 8]
                .try_into()
                .expect("bounded metadata field"),
        )
    };
    if quad(&head, 0) != block
        || quad(&head, 8) != block
        || quad(&data, 0) != list_head
        || quad(&data, 8) != list_head
    {
        bail!("profiled Secure Kernel debugger-data list links are not initialized");
    }
    if &data[0x10..0x14] != b"KDBG" {
        bail!("profiled Secure Kernel debugger-data block has no KDBG owner tag");
    }
    let size = u32::from_le_bytes(data[0x14..0x18].try_into().unwrap());
    if !(0x50..=0x1000).contains(&size) {
        bail!("Secure Kernel debugger-data size {size:#x} is implausible");
    }
    if quad(&data, 0x18) != kernel_base {
        bail!("Secure Kernel debugger-data block names a different kernel base");
    }
    if quad(&data, 0x48) != loaded_module_list {
        bail!("Secure Kernel debugger-data block names a different loaded-module list");
    }
    let canonical = |value: u64| value >> 48 == 0xffff;
    if !canonical(quad(&modules, 0)) || !canonical(quad(&modules, 8)) {
        bail!("Secure Kernel loaded-module list has noncanonical links");
    }
    tracing::info!(
        debugger_data_list = format_args!("{list_head:#x}"),
        debugger_data_block = format_args!("{block:#x}"),
        loaded_module_list = format_args!("{loaded_module_list:#x}"),
        size = format_args!("{size:#x}"),
        "validated live Secure Kernel debugger metadata"
    );
    Ok(KdMetadata {
        loaded_module_list,
        debugger_data_list: list_head,
    })
}

/// Supplies the bounded scaffolding that WinDbg reads while treating this non-NT target as KD.
///
/// The synthetic thread page is the wait-state identity. Its zero links make WinDbg perform two
/// exact null-page reads. Four exact KUSER reads cover shared-data probes made during startup.
/// WinDbg also probes the reported RSP as an NT trap frame and disassembles backwards across bytes
/// preceding the current instruction. Neither assumption holds for this redirected Secure Kernel
/// stop: the selected NOP follows embedded data, and the backscan changes WinDbg's current address
/// to a 16-bit `CS:IP`. Each stop-specific startup probe is served at most once. A later explicit
/// debugger read of the same real address therefore reaches guest memory instead of receiving
/// fabricated bytes.
struct CompatibilityMemory {
    stack_bookkeeping: bool,
    code_backscan: bool,
    code_lookahead: bool,
    null_startup_probes: [bool; NULL_STARTUP_PROBES.len()],
    kuser_startup_probes: [bool; KUSER_STARTUP_PROBES.len()],
}

impl Default for CompatibilityMemory {
    fn default() -> Self {
        Self {
            stack_bookkeeping: true,
            code_backscan: true,
            code_lookahead: true,
            null_startup_probes: [true; NULL_STARTUP_PROBES.len()],
            kuser_startup_probes: [true; KUSER_STARTUP_PROBES.len()],
        }
    }
}

impl CompatibilityMemory {
    fn read(
        &mut self,
        address: u64,
        count: u32,
        stopped_rsp: u64,
        stopped_rip: u64,
        instruction_bytes: usize,
    ) -> Option<Vec<u8>> {
        let end = address.checked_add(u64::from(count))?;
        let inside = |base: u64| {
            address >= base
                && end <= base + COMPATIBILITY_PAGE_BYTES
                && u64::from(count) <= COMPATIBILITY_PAGE_BYTES
        };
        if inside(crate::kdapi::SYNTHETIC_THREAD) {
            return Some(vec![0; count as usize]);
        }
        if let Some((index, _)) = NULL_STARTUP_PROBES
            .iter()
            .enumerate()
            .find(|(index, probe)| {
                self.null_startup_probes[*index] && address == probe.0 && count == probe.1
            })
        {
            self.null_startup_probes[index] = false;
            return Some(vec![0; count as usize]);
        }
        if let Some((index, _)) = KUSER_STARTUP_PROBES
            .iter()
            .enumerate()
            .find(|(index, probe)| {
                self.kuser_startup_probes[*index] && address == probe.0 && count == probe.1
            })
        {
            self.kuser_startup_probes[index] = false;
            return Some(vec![0; count as usize]);
        }
        let stack_bookkeeping = self.stack_bookkeeping
            && address == stopped_rsp
            && u64::from(count) == STACK_BOOKKEEPING_BYTES
            && stopped_rsp != 0;
        let code_backscan = self.code_backscan
            && stopped_rip.checked_sub(CODE_BACKSCAN_BYTES) == Some(address)
            && u64::from(count) == CODE_BACKSCAN_BYTES;
        let code_lookahead = self.code_lookahead
            && stopped_rip
                .checked_add(instruction_bytes as u64)
                .is_some_and(|after| after == address)
            && u64::from(count) == CODE_LOOKAHEAD_BYTES;
        if stack_bookkeeping {
            self.stack_bookkeeping = false;
        }
        if code_backscan {
            self.code_backscan = false;
        }
        if code_lookahead {
            self.code_lookahead = false;
        }
        (stack_bookkeeping || code_backscan || code_lookahead).then(|| vec![0; count as usize])
    }
}

fn parse_word(name: &str, value: &str) -> Result<u64> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(|| value.parse(), |hex| u64::from_str_radix(hex, 16))
        .with_context(|| format!("--{name} must be hexadecimal 0x or unsigned decimal"))
}

fn usage() -> &'static str {
    "usage: windbg-mcp --sk-kd-target --pipe <name> \
     --profile <json> --control-transport \"<command line>\" \
     --live-transport \"<command line>\" --vm-id <guid> \
     [--instruction-address <assertion> --instruction-bytes <assertion>] \
     [--arm-mode <redirect|natural>] [--vp <number>] \
     [--vmwp-pid <assertion>] [--dispatcher-vnd <assertion>] \
     [--partition-id <assertion>] [--expected-cr3 <assertion>] \
     [--kernel-base <assertion>] \
     [--build <number>] [--connect-timeout-ms <milliseconds>] \
     [--idle-timeout-ms <milliseconds>] [--max-pause-ms <milliseconds>]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_decoder_is_exact() {
        assert_eq!(decode_hex("00A5ff").unwrap(), [0, 0xa5, 0xff]);
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("GG").is_err());
    }

    #[test]
    fn compatibility_memory_is_confined_to_protocol_bookkeeping() {
        let mut memory = CompatibilityMemory::default();
        assert_eq!(
            memory.read(crate::kdapi::SYNTHETIC_THREAD + 8, 16, 0x8000, 0x9000, 5),
            Some(vec![0; 16])
        );
        for (address, count) in NULL_STARTUP_PROBES {
            assert_eq!(
                memory.read(address, count, 0x8000, 0x9000, 5),
                Some(vec![0; count as usize])
            );
            assert_eq!(
                memory.read(address, count, 0x8000, 0x9000, 5),
                None,
                "an explicit repeat must read the real null page"
            );
        }
        assert_eq!(
            memory.read(0, 16, 0x8000, 0x9000, 5),
            None,
            "unmeasured null-page request shapes are never synthetic"
        );
        for (address, count) in KUSER_STARTUP_PROBES {
            assert_eq!(
                memory.read(address, count, 0x8000, 0x9000, 5),
                Some(vec![0; count as usize])
            );
            assert_eq!(
                memory.read(address, count, 0x8000, 0x9000, 5),
                None,
                "an explicit repeat must read the real KUSER page"
            );
        }
        assert_eq!(
            memory.read(KUSER_SHARED_DATA + 0x268, 8, 0x8000, 0x9000, 5),
            None,
            "unmeasured KUSER request shapes are never synthetic"
        );
        assert_eq!(
            memory.read(
                crate::kdapi::SYNTHETIC_THREAD + 0xff8,
                16,
                0x8000,
                0x9000,
                5
            ),
            None
        );
        assert_eq!(
            memory.read(0x8000, STACK_BOOKKEEPING_BYTES as u32, 0x8000, 0x9000, 5),
            Some(vec![0; STACK_BOOKKEEPING_BYTES as usize])
        );
        assert_eq!(
            memory.read(0x8000, STACK_BOOKKEEPING_BYTES as u32, 0x8000, 0x9000, 5),
            None,
            "an explicit repeat must read the real Secure Kernel stack"
        );
        assert_eq!(
            memory.read(0x9000 - CODE_BACKSCAN_BYTES, 0x2b, 0x8000, 0x9000, 5),
            Some(vec![0; CODE_BACKSCAN_BYTES as usize])
        );
        assert_eq!(
            memory.read(0x9005, CODE_LOOKAHEAD_BYTES as u32, 0x8000, 0x9000, 5),
            Some(vec![0; CODE_LOOKAHEAD_BYTES as usize])
        );
        assert_eq!(memory.read(0x8000, 0x7f, 0x8000, 0x9000, 5), None);
        assert_eq!(memory.read(0x8010, 0x70, 0x8000, 0x9000, 5), None);
        assert_eq!(memory.read(0x1000, 1, 0x8000, 0x9000, 5), None);
        assert_eq!(memory.read(u64::MAX, 2, 0x8000, 0x9000, 5), None);
    }

    #[test]
    fn single_step_accepts_only_linear_control_flow() {
        let guard = |bytes: &[u8]| InstructionGuard {
            address: crate::skcontrol::HexU64(0x1000),
            bytes: bytes.to_vec(),
        };
        assert!(fallthrough_step_guard(guard(&[0x90])).is_ok());
        for bytes in [&[0xeb, 0x05][..], &[0xe8, 0, 0, 0, 0], &[0xc3]] {
            let error = fallthrough_step_guard(guard(bytes)).unwrap_err();
            assert!(error.to_string().contains("control flow"), "{error:#}");
        }
    }

    #[test]
    fn instruction_decode_accepts_a_complete_instruction_at_the_page_end() {
        assert_eq!(instruction_length(&[0x90], 0x1fff), Some(1));
        assert_eq!(instruction_length(&[0xe8], 0x1fff), None);
        assert_eq!(instruction_length(&[0xe8, 0, 0, 0, 0], 0x1fff), Some(5));
    }

    #[test]
    fn single_step_rejects_linear_instructions_that_defer_the_debug_trap() {
        let guard = |bytes: &[u8]| InstructionGuard {
            address: crate::skcontrol::HexU64(0x1000),
            bytes: bytes.to_vec(),
        };
        for bytes in [
            &[0x8e, 0xd0][..],
            &[0x48, 0x0f, 0xb2, 0x20][..],
            &[0xf3, 0xa4][..],
        ] {
            let error = fallthrough_step_guard(guard(bytes)).unwrap_err();
            assert!(
                error.to_string().contains("defer") || error.to_string().contains("repeated"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn target_options_refuse_an_unbounded_pipe_name_before_opening_any_target() {
        let args = ["--pipe".to_string(), r"bad\pipe".to_string()];
        assert!(
            ManagedRequest::parse(&args)
                .unwrap_err()
                .to_string()
                .contains("ASCII")
        );
    }

    #[test]
    fn target_options_do_not_require_boot_specific_identity_assertions() {
        let args = [
            "--pipe",
            "windbg-mcp-test",
            "--profile",
            r"C:\private\profile.json",
            "--control-transport",
            "provider --partition {partition_id}",
            "--live-transport",
            "memory --partition {partition_id} --cr3 {cr3}",
            "--vmwp-pid",
            "4242",
            "--vm-id",
            "11111111-2222-3333-4444-555555555555",
        ]
        .map(str::to_string);
        let request = ManagedRequest::parse(&args).unwrap();
        assert_eq!(request.open.dispatcher_vnd, None);
        assert_eq!(request.open.target.partition_id, None);
        assert_eq!(request.open.target.expected_cr3, None);
        assert_eq!(request.kernel_base, None);
        assert_eq!(request.initial, None);
    }

    #[test]
    fn every_protocol_wait_is_capped_by_the_absolute_pause_bound() {
        let since = Instant::now() - Duration::from_secs(4);
        let wait =
            bounded_pause_wait(Duration::from_secs(30), since, Duration::from_secs(10)).unwrap();
        assert!(wait <= Duration::from_secs(6));
        assert!(wait > Duration::from_secs(5));

        let expired = bounded_pause_wait(
            Duration::from_secs(1),
            Instant::now() - Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(
            expired
                .to_string()
                .contains("absolute Secure Kernel pause bound")
        );
    }

    #[test]
    fn a_disconnect_queued_before_continue_wakes_the_new_running_wait() {
        let mut state = WaitWakeState::default();
        assert!(state.request(None, WaitWakeReason::Disconnected).is_none());

        let activity = crate::skdispatch::WaitActivity::new(Duration::from_secs(1));
        assert!(state.begin(activity).is_some());
        assert_eq!(state.finish(), Some(WaitWakeReason::Disconnected));
    }

    #[test]
    fn consuming_a_stopped_wake_frame_preserves_the_later_disconnect() {
        let mut state = WaitWakeState::default();
        state.request(None, WaitWakeReason::BreakIn);
        state.request(None, WaitWakeReason::Disconnected);
        state.consume_frame(&Frame::BreakIn);

        let activity = crate::skdispatch::WaitActivity::new(Duration::from_secs(1));
        assert!(state.begin(activity).is_some());
        assert_eq!(state.finish(), Some(WaitWakeReason::Disconnected));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_pipe_write_cannot_outlive_the_absolute_pause_bound() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let error = write_stopped_pipe(
            &mut writer,
            &[0, 1],
            Instant::now(),
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("absolute Secure Kernel pause bound"),
            "{error:#}"
        );
    }

    #[test]
    fn a_managed_service_failure_attempts_normal_close_before_recovery() {
        let closes = std::cell::Cell::new(0);

        let completed = finish_managed(Err(anyhow!("idle bound expired")), false, || {
            closes.set(closes.get() + 1);
            Ok(())
        })
        .unwrap();

        assert_eq!(completed, ManagedCompletion::Released);
        assert_eq!(closes.get(), 1);

        let error = finish_managed(Err(anyhow!("idle bound expired")), false, || {
            Err(anyhow!("restore failed"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("idle bound expired"));
        assert!(error.to_string().contains("restore failed"));
    }

    #[test]
    fn a_managed_teardown_leaves_close_to_the_queued_end_session() {
        let closes = std::cell::Cell::new(0);

        let completed = finish_managed(Err(ManagedTeardown.into()), true, || {
            closes.set(closes.get() + 1);
            Ok(())
        })
        .unwrap();

        assert_eq!(completed, ManagedCompletion::TeardownPending);
        assert_eq!(closes.get(), 0);
    }
}
