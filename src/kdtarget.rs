//! Native KD named-pipe facade over the guarded Secure Kernel live-control session.
//!
//! WinDbg is the protocol client. The actual target remains the one-VP VTL1 controller in
//! [`crate::skdispatch`]: virtual reads use its stopped address space, and execution requests are
//! translated to its hardware-breakpoint and trap-flag transitions. No DbgEng instance is created
//! here; [`crate::worker`] lends this role its one engine on the same thread.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use dbgscope::dbgeng::{BreakRequest, DebugEngine, InterruptHandle};
use iced_x86::{
    Decoder as InstructionDecoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::sync::mpsc;

use crate::kdapi::{Amd64Context, Amd64ContextValues, ManipulateRequest, Version64};
use crate::kdwire::{Decoder, Frame, TargetLink};
use crate::skcontrol::{RegisterName, RegisterValue};
use crate::sklive::{ArmMode, BreakpointGuard, InstructionGuard, StepGuard, StopRecord};

pub(crate) const TARGET_FLAG: &str = "--sk-kd-target";

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
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

enum TransportMessage {
    Frame(Frame),
    Disconnected,
    Failed(String),
}

#[derive(Clone, Debug)]
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

#[derive(Clone)]
struct WaitWaker {
    interrupt: Arc<InterruptHandle>,
    active: Arc<Mutex<Option<ActiveWait>>>,
}

impl WaitWaker {
    fn new(interrupt: InterruptHandle) -> Self {
        Self {
            interrupt: Arc::new(interrupt),
            active: Arc::new(Mutex::new(None)),
        }
    }

    fn begin(&self, activity: crate::skdispatch::WaitActivity) {
        *self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(ActiveWait {
            activity,
            reason: None,
        });
    }

    fn finish(&self) -> Option<WaitWakeReason> {
        self.active
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .and_then(|wait| wait.reason)
    }

    fn note_traffic(&self) {
        if let Some(wait) = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_mut()
        {
            wait.activity.note_traffic();
        }
    }

    fn request(&self, reason: WaitWakeReason) {
        self.request_for(None, reason);
    }

    fn request_for(
        &self,
        expected: Option<&crate::skdispatch::WaitActivity>,
        reason: WaitWakeReason,
    ) {
        let activity = {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let Some(wait) = active.as_mut() else {
                return;
            };
            if expected.is_some_and(|expected| !wait.activity.same_wait(expected)) {
                return;
            }
            if wait.reason.is_some() {
                return;
            }
            wait.reason = Some(reason);
            wait.activity.clone()
        };
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
                    let active = wake
                        .active
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    let Some(wait) = active.as_ref() else {
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

#[derive(Debug)]
struct Options {
    open: crate::skdispatch::OpenRequest,
    pipe: String,
    kernel_base: u64,
    build: u16,
    initial: InstructionGuard,
    arm_mode: ArmMode,
    connect_timeout: Duration,
    idle_timeout: Duration,
}

impl Options {
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
        let mut build = 26_100;
        let mut instruction_address = None;
        let mut instruction_bytes = None;
        let mut arm_mode = ArmMode::Redirect;
        let mut connect_timeout = DEFAULT_CONNECT_TIMEOUT;
        let mut idle_timeout = DEFAULT_IDLE_TIMEOUT;
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
                "--build" => build = value(&mut at)?.parse().context("invalid --build")?,
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
        let target = crate::skcontrol::TargetIdentity {
            vm_id: vm_id.context(usage())?,
            partition_id: crate::skcontrol::HexU64(partition_id.context(usage())?),
            vp,
            vtl: 1,
            expected_cr3: crate::skcontrol::HexU64(expected_cr3.context(usage())?),
        };
        target.validate()?;
        Ok(Self {
            open: crate::skdispatch::OpenRequest {
                profile: profile.context(usage())?,
                control_transport: control_transport.context(usage())?,
                live_transport: live_transport.context(usage())?,
                vmwp_pid: vmwp_pid.context(usage())?,
                dispatcher_vnd: dispatcher_vnd.context(usage())?,
                target,
                allow_transition_cr3: false,
                additional_vps: Vec::new(),
            },
            pipe,
            kernel_base: kernel_base.context(usage())?,
            build,
            initial: InstructionGuard {
                address: crate::skcontrol::HexU64(instruction_address.context(usage())?),
                bytes: instruction_bytes.context(usage())?,
            },
            arm_mode,
            connect_timeout,
            idle_timeout,
        })
    }
}

pub(crate) fn run(args: &[String], engine: &DebugEngine) -> Result<()> {
    let options = Options::parse(args)?;
    let (mut session, skipped) = crate::skdispatch::Session::open(&options.open)?;
    for line in skipped {
        eprintln!("control provider: {line}");
    }
    // DbgEng remains on this calling thread. Tokio's worker threads service only the KD pipe and
    // may use the engine's narrow `InterruptHandle` while this thread is inside the owned wait.
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(run_async(&options, engine, &mut session));
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

async fn run_async(
    options: &Options,
    engine: &DebugEngine,
    session: &mut crate::skdispatch::Session,
) -> Result<()> {
    // WinDbg gives a serial target only a few seconds after reset before it reconnects. Capture the
    // initial event first, so accepting the pipe promises that a state-change packet is ready now.
    eprintln!(
        "arming initial Secure Kernel stop at {:#x}",
        options.initial.address.0
    );
    session.arm(
        engine,
        vec![BreakpointGuard {
            slot: 0,
            instruction: options.initial.clone(),
        }],
        options.arm_mode,
    )?;
    let mut stop = session.wait_for_stop(engine)?;
    let (mut values, mut context) = read_context(session, &stop)?;
    let mut reported_instruction = read_instruction_guard(session, values.rip)?;

    let path = format!(r"\\.\pipe\{}", options.pipe);
    let pipe = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&path)
        .with_context(|| format!("creating Secure Kernel KD pipe {path}"))?;
    eprintln!(
        "Secure Kernel stop held at {:#x}; waiting for WinDbg on {path}",
        values.rip
    );
    tokio::time::timeout(options.connect_timeout, pipe.connect())
        .await
        .context("waiting for WinDbg to connect timed out")??;

    let (reader, mut writer) = tokio::io::split(pipe);
    let (transport_tx, mut transport_rx) = mpsc::channel(TRANSPORT_QUEUE_DEPTH);
    let wait_waker = WaitWaker::new(engine.interrupt_handle());
    let reader_waker = wait_waker.clone();
    tokio::spawn(read_transport(reader, transport_tx, reader_waker));
    let mut link = TargetLink::new();
    tokio::time::timeout(
        options.connect_timeout,
        wait_for_reset(&mut writer, &mut transport_rx, &mut link),
    )
    .await
    .context("waiting for WinDbg's KD reset timed out")??;
    send_stop(&mut writer, &mut link, &reported_instruction.bytes, &values).await?;
    eprintln!("initial KD state change sent");

    let mut breakpoints = BTreeMap::<u32, BreakpointGuard>::new();
    let mut compatibility = CompatibilityMemory::default();
    loop {
        let frame = tokio::time::timeout(options.idle_timeout, read_frame(&mut transport_rx))
            .await
            .context("WinDbg sent no KD traffic before the idle timeout")??;
        let inbound = link.receive(frame);
        let peer_reset = inbound.peer_reset;
        for write in inbound.writes {
            writer.write_all(&write).await?;
        }
        if peer_reset {
            compatibility = CompatibilityMemory::default();
            breakpoints.clear();
            send_stop(&mut writer, &mut link, &reported_instruction.bytes, &values).await?;
            eprintln!("KD peer reset; current held stop resent");
            continue;
        }
        let Some(packet) = inbound.packet else {
            writer.flush().await?;
            continue;
        };
        if packet.packet_type != crate::kdwire::PACKET_TYPE_STATE_MANIPULATE {
            writer.flush().await?;
            continue;
        }
        let request = ManipulateRequest::decode(&packet.payload)?;
        let response = if request.api_number() == crate::kdapi::DBGKD_GET_VERSION_API {
            request.get_version_response(Version64 {
                build: options.build,
                kernel_base: options.kernel_base,
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
                eprintln!(
                    "KD virtual read {:#x}+{count:#x} served by compatibility memory",
                    read.address
                );
                request.read_virtual_memory_response(&bytes)?
            } else {
                match session.read_memory(read.address, count) {
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
            let count = read
                .count
                .min((crate::kdwire::MAX_PACKET_BYTES - crate::kdapi::MANIPULATE_BYTES) as u32);
            request.read_control_space_response(&vec![0; count as usize])?
        } else if let Some((write, _)) = request.write_control_space() {
            eprintln!(
                "KD control-space write {:#x}+{:#x} is unsupported",
                write.address, write.count
            );
            request.failure_response()
        } else if let Some(range) = request.get_context_ex() {
            eprintln!(
                "KD GetContextEx offset {:#x}, count {:#x}",
                range.offset, range.count
            );
            request.get_context_ex_response(&context)?
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
            match insert_breakpoint(session, &mut breakpoints, address) {
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
            let resume = if trace {
                let rip = stopped_low(&stop, RegisterName::Rip)?;
                read_instruction_guard(session, rip)
                    .and_then(fallthrough_step_guard)
                    .and_then(|guard| session.step(engine, &stop.epoch, guard).map(|_| ()))
            } else {
                if breakpoints.is_empty() {
                    Err(anyhow!(
                        "WinDbg requested continue with no hardware breakpoint installed"
                    ))
                } else {
                    session
                        .continue_to_breakpoints(
                            engine,
                            &stop.epoch,
                            breakpoints.values().cloned().collect(),
                        )
                        .map(|_| ())
                }
            };
            if let Err(error) = resume {
                if session.phase() != crate::sklive::LivePhase::Stopped {
                    return Err(error);
                }
                eprintln!("KD Continue2 refused; current held stop preserved: {error:#}");
                send_stop(&mut writer, &mut link, &reported_instruction.bytes, &values).await?;
                continue;
            }
            writer.flush().await?;
            let activity = crate::skdispatch::WaitActivity::new(options.idle_timeout);
            wait_waker.begin(activity.clone());
            wait_waker.start_idle_watchdog(activity.clone());
            let waited = session.wait_for_stop_interruptible(engine, &activity);
            let wake = wait_waker.finish();
            stop = match (waited, wake) {
                (Ok(stop), _) => stop,
                (Err(_), Some(WaitWakeReason::Disconnected)) => return Err(Disconnected.into()),
                (Err(error), Some(reason)) => return Err(error.context(reason.to_string())),
                (Err(error), None) => return Err(error),
            };
            (values, context) = read_context(session, &stop)?;
            reported_instruction = read_instruction_guard(session, values.rip)?;
            send_stop(&mut writer, &mut link, &reported_instruction.bytes, &values).await?;
            continue;
        } else {
            eprintln!("KD API {:#x} is not implemented", request.api_number());
            request.failure_response()
        };
        let response = link
            .send(crate::kdwire::PACKET_TYPE_STATE_MANIPULATE, &response)
            .map_err(anyhow::Error::msg)?;
        writer.write_all(&response).await?;
        writer.flush().await?;
    }
}

async fn wait_for_reset<W: AsyncWrite + Unpin>(
    writer: &mut W,
    transport: &mut mpsc::Receiver<TransportMessage>,
    link: &mut TargetLink,
) -> Result<()> {
    loop {
        let inbound = link.receive(read_frame(transport).await?);
        for write in inbound.writes {
            writer.write_all(&write).await?;
        }
        writer.flush().await?;
        if inbound.peer_reset {
            return Ok(());
        }
    }
}

async fn read_frame(transport: &mut mpsc::Receiver<TransportMessage>) -> Result<Frame> {
    match transport.recv().await {
        Some(TransportMessage::Frame(frame)) => Ok(frame),
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
    loop {
        loop {
            let frame = match decoder.next() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(error) => {
                    let why = error.to_string();
                    wait_waker.request(WaitWakeReason::Transport(why.clone()));
                    let _ = queue_transport(&transport, TransportMessage::Failed(why), &wait_waker);
                    return;
                }
            };
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
) -> Result<()> {
    let state = crate::kdapi::breakpoint_state_change(values, instruction)?;
    let packet = link
        .send(crate::kdwire::PACKET_TYPE_STATE_CHANGE64, &state)
        .map_err(anyhow::Error::msg)?;
    writer.write_all(&packet).await?;
    writer.flush().await?;
    Ok(())
}

fn read_context(
    session: &mut crate::skdispatch::Session,
    stop: &StopRecord,
) -> Result<(Amd64ContextValues, Amd64Context)> {
    let extra = session.read_stopped_registers(
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
    let instruction = read_instruction_guard(session, address)?;
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
) -> Result<InstructionGuard> {
    let bytes_in_page = COMPATIBILITY_PAGE_BYTES - (address & (COMPATIBILITY_PAGE_BYTES - 1));
    let first_count = u32::try_from(bytes_in_page.min(u64::from(MAX_INSTRUCTION_BYTES))).unwrap();
    let mut bytes = decode_hex(&session.read_memory(address, first_count)?.data)?;
    if instruction_length(&bytes, address).is_none() && first_count < MAX_INSTRUCTION_BYTES {
        let continuation_address = address
            .checked_add(u64::from(first_count))
            .context("instruction address overflowed at the page boundary")?;
        let continuation = session
            .read_memory(continuation_address, MAX_INSTRUCTION_BYTES - first_count)
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
    let writes_ss = decoded.op0_kind() == OpKind::Register
        && decoded.op0_register() == Register::SS
        && matches!(decoded.mnemonic(), Mnemonic::Mov | Mnemonic::Pop);
    let repeats = decoded.is_string_instruction()
        && (decoded.has_rep_prefix() || decoded.has_repe_prefix() || decoded.has_repne_prefix());
    if repeats {
        bail!(
            "WinDbg single-step is refused for repeated {:?} at {:#x}; the trap can stop before \
             the linear successor",
            decoded.mnemonic(),
            instruction.address.0
        );
    }
    if writes_ss || decoded.mnemonic() == Mnemonic::Lss {
        bail!(
            "WinDbg single-step is refused because {:?} can defer the trap-flag exception past \
             the linear successor at {:#x}",
            decoded.mnemonic(),
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
    "usage: windbg-mcp --sk-kd-target --pipe <name> --kernel-base <address> \
     --profile <json> --control-transport \"<command line>\" \
     --live-transport \"<command line>\" --vmwp-pid <pid> \
     --dispatcher-vnd <address> --vm-id <guid> --partition-id <number> \
     --expected-cr3 <number> --instruction-address <number> \
     --instruction-bytes <hex> [--arm-mode <redirect|natural>] [--vp <number>] \
     [--build <number>] [--connect-timeout-ms <milliseconds>] \
     [--idle-timeout-ms <milliseconds>]"
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
            Options::parse(&args)
                .unwrap_err()
                .to_string()
                .contains("ASCII")
        );
    }
}
