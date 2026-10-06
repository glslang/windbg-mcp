//! Executable compatibility gate for WinDbg's named-pipe KD transport.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ServerOptions;

use crate::kdwire::{Decoder, Frame, PACKET_TYPE_RESET, TargetLink};

pub(crate) const WIRE_PROBE_FLAG: &str = "--sk-kd-wire-probe";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PIPE_NAME: usize = 128;

#[derive(Debug)]
struct Options {
    pipe: String,
    capture: Option<PathBuf>,
    state_change: Option<PathBuf>,
    context: Option<PathBuf>,
    kernel_base: Option<u64>,
    timeout: Duration,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut pipe = None;
        let mut capture = None;
        let mut state_change = None;
        let mut context = None;
        let mut kernel_base = None;
        let mut timeout = DEFAULT_TIMEOUT;
        let mut at = 0;
        while at < args.len() {
            match args[at].as_str() {
                "--pipe" => {
                    at += 1;
                    pipe = Some(args.get(at).context("--pipe requires a value")?.clone());
                }
                "--capture" => {
                    at += 1;
                    capture = Some(PathBuf::from(
                        args.get(at).context("--capture requires a path")?,
                    ));
                }
                "--state-change" => {
                    at += 1;
                    state_change = Some(PathBuf::from(
                        args.get(at).context("--state-change requires a path")?,
                    ));
                }
                "--context" => {
                    at += 1;
                    context = Some(PathBuf::from(
                        args.get(at).context("--context requires a path")?,
                    ));
                }
                "--kernel-base" => {
                    at += 1;
                    kernel_base = Some(parse_u64(
                        args.get(at).context("--kernel-base requires a value")?,
                    )?);
                }
                "--timeout-ms" => {
                    at += 1;
                    let milliseconds: u64 = args
                        .get(at)
                        .context("--timeout-ms requires a value")?
                        .parse()
                        .context("--timeout-ms must be an unsigned integer")?;
                    if milliseconds == 0 || milliseconds > 300_000 {
                        bail!("--timeout-ms must be in 1..=300000");
                    }
                    timeout = Duration::from_millis(milliseconds);
                }
                other => bail!("unknown wire-probe argument {other:?}"),
            }
            at += 1;
        }
        let pipe = pipe.context("--pipe is required")?;
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
        Ok(Self {
            pipe,
            capture,
            state_change,
            context,
            kernel_base,
            timeout,
        })
    }
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    pipe: String,
    received_bytes: usize,
    reset_packets: usize,
    target_reset_hex: String,
    state_change_acknowledged: Option<bool>,
    manipulate_packets: usize,
    manipulate_apis: Vec<u32>,
    read_requests: Vec<ReadRequest>,
    restored_breakpoints: Vec<u32>,
    context_requests: usize,
    context_writes: usize,
    control_writes: usize,
    continue_requests: usize,
    responses_sent: usize,
}

#[derive(Serialize)]
struct ReadRequest {
    api: u32,
    address: String,
    count: u32,
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let options = Options::parse(args).with_context(usage)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run_async(options))
}

async fn run_async(options: Options) -> Result<()> {
    let supplied_context = options
        .context
        .as_ref()
        .map(|path| {
            std::fs::read(path).with_context(|| format!("reading context {}", path.display()))
        })
        .transpose()?;
    let supplied_context = supplied_context
        .as_deref()
        .map(crate::kdapi::Amd64Context::decode)
        .transpose()?;
    let state_change = options
        .state_change
        .as_ref()
        .map(|path| {
            std::fs::read(path)
                .with_context(|| format!("reading state-change payload {}", path.display()))
        })
        .transpose()?;
    if state_change
        .as_ref()
        .is_some_and(|payload| payload.len() != crate::kdapi::WAIT_STATE_CHANGE64_BYTES)
    {
        bail!(
            "--state-change must be exactly {} bytes",
            crate::kdapi::WAIT_STATE_CHANGE64_BYTES
        );
    }
    let path = format!(r"\\.\pipe\{}", options.pipe);
    let mut pipe = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&path)
        .with_context(|| format!("creating KD wire-probe pipe {path}"))?;
    eprintln!("waiting for WinDbg on {path}");
    tokio::time::timeout(options.timeout, pipe.connect())
        .await
        .context("waiting for WinDbg to connect timed out")?
        .with_context(|| format!("accepting WinDbg on {path}"))?;

    let mut decoder = Decoder::default();
    let mut link = TargetLink::new();
    let mut captured = Vec::new();
    let mut resets = 0;
    let mut deadline = tokio::time::Instant::now() + options.timeout;
    let target_reset = 'outer: loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            bail!("WinDbg connected but sent no valid KD reset packet");
        }
        let mut buffer = [0u8; 512];
        let read = tokio::time::timeout(left, pipe.read(&mut buffer))
            .await
            .context("waiting for the WinDbg KD reset timed out")??;
        if read == 0 {
            bail!("WinDbg disconnected before sending a KD reset packet");
        }
        captured.extend_from_slice(&buffer[..read]);
        decoder.push(&buffer[..read]);
        while let Some(frame) = decoder.next().context("decoding the WinDbg KD stream")? {
            let is_reset = matches!(
                frame,
                Frame::Control {
                    packet_type: PACKET_TYPE_RESET,
                    ..
                }
            );
            let inbound = link.receive(frame);
            if is_reset {
                resets += 1;
            }
            let peer_reset = inbound.peer_reset;
            for write in inbound.writes {
                pipe.write_all(&write).await?;
                if peer_reset {
                    pipe.flush().await?;
                    break;
                }
            }
            if peer_reset {
                break 'outer crate::kdwire::control(PACKET_TYPE_RESET, 0);
            }
        }
    };

    let mut manipulate_apis = Vec::new();
    let mut read_requests = Vec::new();
    let mut restored_breakpoints = Vec::new();
    let mut context_requests = 0;
    let mut context_writes = 0;
    let mut control_writes = 0;
    let mut continue_requests = 0;
    let mut responses_sent = 0;
    let state_change_acknowledged = if let Some(payload) = state_change {
        let context =
            supplied_context.unwrap_or(crate::kdapi::Amd64Context::from_wait_state(&payload)?);
        let packet = link
            .send(crate::kdwire::PACKET_TYPE_STATE_CHANGE64, &payload)
            .map_err(anyhow::Error::msg)?;
        pipe.write_all(&packet).await?;
        pipe.flush().await?;
        deadline = tokio::time::Instant::now() + options.timeout;
        let mut last_activity_after_ack = None;
        let mut repeat_state_after_ack = false;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                if last_activity_after_ack.is_some() {
                    break Some(true);
                }
                bail!("WinDbg did not acknowledge the supplied KD state-change packet");
            }
            let observe_for = last_activity_after_ack
                .map(|at: tokio::time::Instant| {
                    (at + Duration::from_secs(2))
                        .saturating_duration_since(tokio::time::Instant::now())
                })
                .unwrap_or(left);
            if observe_for.is_zero() {
                break Some(true);
            }
            let mut buffer = [0u8; 4096];
            let read =
                match tokio::time::timeout(left.min(observe_for), pipe.read(&mut buffer)).await {
                    Ok(read) => read.context("reading KD traffic after the state change")?,
                    Err(_) if last_activity_after_ack.is_some() => break Some(true),
                    Err(_) => bail!("waiting for the state-change acknowledgement timed out"),
                };
            if read == 0 {
                if last_activity_after_ack.is_some() {
                    break Some(true);
                }
                bail!("WinDbg disconnected before acknowledging the KD state change");
            }
            captured.extend_from_slice(&buffer[..read]);
            decoder.push(&buffer[..read]);
            while let Some(frame) = decoder.next().context("decoding the WinDbg KD stream")? {
                let inbound = link.receive(frame);
                let peer_reset = inbound.peer_reset;
                for write in inbound.writes {
                    pipe.write_all(&write).await?;
                }
                if peer_reset {
                    resets += 1;
                    last_activity_after_ack = None;
                    repeat_state_after_ack = false;
                    let packet = link
                        .send(crate::kdwire::PACKET_TYPE_STATE_CHANGE64, &payload)
                        .map_err(anyhow::Error::msg)?;
                    pipe.write_all(&packet).await?;
                    continue;
                }
                if repeat_state_after_ack && !link.awaiting_acknowledgement() {
                    let packet = link
                        .send(crate::kdwire::PACKET_TYPE_STATE_CHANGE64, &payload)
                        .map_err(anyhow::Error::msg)?;
                    pipe.write_all(&packet).await?;
                    repeat_state_after_ack = false;
                }
                let Some(packet) = inbound.packet else {
                    continue;
                };
                if packet.packet_type != crate::kdwire::PACKET_TYPE_STATE_MANIPULATE {
                    continue;
                }
                let request = crate::kdapi::ManipulateRequest::decode(&packet.payload)?;
                manipulate_apis.push(request.api_number());
                last_activity_after_ack = Some(tokio::time::Instant::now());
                let continue_request = request.continue2_trace().is_some();
                let response = if request.api_number() == crate::kdapi::DBGKD_GET_VERSION_API {
                    options.kernel_base.map(|kernel_base| {
                        request.get_version_response(crate::kdapi::Version64::fixture(kernel_base))
                    })
                } else if let Some(read) = request.read_virtual_memory() {
                    read_requests.push(ReadRequest {
                        api: request.api_number(),
                        address: format!("{:#018x}", read.address),
                        count: read.count,
                    });
                    let count = usize::try_from(read.count)
                        .unwrap_or(usize::MAX)
                        .min(crate::kdwire::MAX_PACKET_BYTES - crate::kdapi::MANIPULATE_BYTES);
                    Some(request.read_virtual_memory_response(&vec![0; count])?)
                } else if let Some(read) = request.read_control_space() {
                    read_requests.push(ReadRequest {
                        api: request.api_number(),
                        address: format!("{:#018x}", read.address),
                        count: read.count,
                    });
                    let count = usize::try_from(read.count)
                        .unwrap_or(usize::MAX)
                        .min(crate::kdwire::MAX_PACKET_BYTES - crate::kdapi::MANIPULATE_BYTES);
                    Some(request.read_control_space_response(&vec![0; count])?)
                } else if let Some(handle) = request.restore_breakpoint_handle() {
                    restored_breakpoints.push(handle);
                    Some(request.success_response())
                } else if request.get_context_ex().is_some() {
                    context_requests += 1;
                    Some(request.get_context_ex_response(&context)?)
                } else if let Some(written) = request.set_context() {
                    if !context.matches_prefix(written) {
                        bail!("WinDbg changed the fixture context unexpectedly");
                    }
                    context_writes += 1;
                    Some(request.success_response())
                } else if request.write_control_space().is_some() {
                    control_writes += 1;
                    Some(request.failure_response())
                } else if continue_request {
                    continue_requests += 1;
                    Some(request.success_response())
                } else {
                    None
                };
                if let Some(response) = response {
                    let response = link
                        .send(crate::kdwire::PACKET_TYPE_STATE_MANIPULATE, &response)
                        .map_err(anyhow::Error::msg)?;
                    pipe.write_all(&response).await?;
                    responses_sent += 1;
                    if continue_request {
                        repeat_state_after_ack = true;
                    }
                }
            }
            pipe.flush().await?;
            if !link.awaiting_acknowledgement() && last_activity_after_ack.is_none() {
                last_activity_after_ack = Some(tokio::time::Instant::now());
            }
        }
    } else {
        None
    };

    if let Some(capture) = options.capture {
        std::fs::write(&capture, &captured)
            .with_context(|| format!("writing KD capture {}", capture.display()))?;
    }
    let report = Report {
        schema: "windbg-mcp.sk-kd-wire-probe.v1",
        pipe: path,
        received_bytes: captured.len(),
        reset_packets: resets,
        target_reset_hex: hex(&target_reset),
        state_change_acknowledged,
        manipulate_packets: manipulate_apis.len(),
        manipulate_apis,
        read_requests,
        restored_breakpoints,
        context_requests,
        context_writes,
        control_writes,
        continue_requests,
        responses_sent,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn usage() -> &'static str {
    "usage: windbg-mcp --sk-kd-wire-probe --pipe <name> [--capture <path>] \
     [--state-change <payload.bin>] [--context <amd64-context.bin>] \
     [--kernel-base <address>] [--timeout-ms <1..=300000>]"
}

fn parse_u64(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    match digits {
        Some(digits) => u64::from_str_radix(digits, 16).context("invalid hexadecimal address"),
        None => value.parse().context("invalid address"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_require_a_bounded_local_name() {
        assert!(
            Options::parse(&[])
                .unwrap_err()
                .to_string()
                .contains("--pipe")
        );
        assert!(
            Options::parse(&["--pipe".into(), r"bad\name".into()])
                .unwrap_err()
                .to_string()
                .contains("ASCII")
        );
        let parsed = Options::parse(&[
            "--pipe".into(),
            "sk-kd.1".into(),
            "--timeout-ms".into(),
            "25".into(),
        ])
        .unwrap();
        assert_eq!(parsed.pipe, "sk-kd.1");
        assert_eq!(parsed.timeout, Duration::from_millis(25));
    }

    #[test]
    fn options_accept_a_hexadecimal_kernel_base() {
        let parsed = Options::parse(&[
            "--pipe".into(),
            "sk-kd.1".into(),
            "--kernel-base".into(),
            "0xFFFFF8039E600000".into(),
        ])
        .unwrap();
        assert_eq!(parsed.kernel_base, Some(0xffff_f803_9e60_0000));
    }
}
