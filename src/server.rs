//! The MCP server: a curated set of debugger tools plus a raw command passthrough.
//!
//! Every tool marshals its work onto the engine thread via [`EngineHandle`]. Most
//! tools are thin wrappers over `execute_command` (the universal DbgEng escape
//! hatch, returning full text); session-management tools call the typed
//! `win-kexp` methods and then wait for the target to stop.

use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::engine::EngineHandle;
use crate::ttd;

/// How long to wait for a target to stop after open/attach/launch (ms).
const LOAD_WAIT_MS: u32 = 60_000;
/// How long to wait for an execution-control command (go/step/reverse) to reach its
/// next stop (ms).
const EXEC_WAIT_MS: u32 = 60_000;

#[derive(Clone)]
pub struct WindbgServer {
    engine: EngineHandle,
}

/// Maps any error to a `String` for the engine `Reply` channel.
fn es<E: ToString>(e: E) -> String {
    e.to_string()
}

fn text_result(s: String) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![Content::text(s)]))
}

/// Parses a decimal or `0x`-prefixed hex integer.
fn parse_u64(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let parsed = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16)
    } else {
        t.parse::<u64>()
    };
    parsed.map_err(|_| format!("invalid number: {s}"))
}

fn hexdump(base: u64, bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let addr = base + (i * 16) as u64;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{addr:016x}  {:<47}  {ascii}\n", hex.join(" ")));
    }
    out
}

/// Decodes a 32-bit Windows IOCTL control code into its `CTL_CODE` fields and
/// renders a human-readable report. Pure (no debugger) so it is unit-testable and
/// works without a live session.
///
/// Layout: `DeviceType` = bits 16–31, `RequiredAccess` = bits 14–15,
/// `FunctionCode` = bits 2–13, `Method` = bits 0–1.
fn decode_ioctl_text(code: u64) -> String {
    let c = code as u32;
    let device_type = (c >> 16) & 0xFFFF;
    let access = (c >> 14) & 0x3;
    let function = (c >> 2) & 0xFFF;
    let method = c & 0x3;

    let method_name = match method {
        0 => "METHOD_BUFFERED",
        1 => "METHOD_IN_DIRECT",
        2 => "METHOD_OUT_DIRECT",
        _ => "METHOD_NEITHER",
    };
    let access_name = match access {
        0 => "FILE_ANY_ACCESS",
        1 => "FILE_READ_DATA",
        2 => "FILE_WRITE_DATA",
        _ => "FILE_READ_DATA | FILE_WRITE_DATA",
    };

    let mut out = String::new();
    out.push_str(&format!("IOCTL 0x{c:08x}\n"));
    out.push_str(&format!(
        "  CTL_CODE(0x{device_type:04x}, 0x{function:03x}, {method_name}, {access_name})\n"
    ));
    out.push_str(&format!("  DeviceType     0x{device_type:04x}\n"));
    out.push_str(&format!("  FunctionCode   0x{function:03x}\n"));
    out.push_str(&format!("  Method         {method} ({method_name})\n"));
    out.push_str(&format!("  RequiredAccess {access} ({access_name})\n"));

    // Surface the two fields that matter most for reachability / bug-class triage.
    if method == 3 {
        out.push_str(
            "  [!] METHOD_NEITHER: the driver receives raw user-mode pointers \
             (Type3InputBuffer / UserBuffer) — classic input-validation bug surface.\n",
        );
    }
    if access == 0 {
        out.push_str(
            "  [!] FILE_ANY_ACCESS: no access gate — the I/O manager delivers this IOCTL \
             on any handle, even one opened with minimal access.\n",
        );
    }
    out
}

// ---- Tool parameter types ------------------------------------------------

#[derive(Deserialize, JsonSchema)]
pub struct PathArgs {
    /// Filesystem path to the dump (.dmp) or TTD trace (.run) file.
    pub path: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ConnectionArgs {
    /// Kernel debugging connection string, e.g. "net:port=50000,key=...".
    pub connection: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct PidArgs {
    /// Process ID to attach to.
    pub pid: u32,
}

#[derive(Deserialize, JsonSchema)]
pub struct CommandLineArgs {
    /// Full command line of the program to launch under the debugger.
    pub command_line: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ExecuteArgs {
    /// Raw debugger command to run (e.g. "!analyze -v", "u rip", "dt nt!_EPROCESS").
    pub command: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ReadMemoryArgs {
    /// Virtual address (decimal or 0x-hex).
    pub address: String,
    /// Number of bytes to read.
    pub size: u32,
}

#[derive(Deserialize, JsonSchema)]
pub struct DisassembleArgs {
    /// Address or symbol to disassemble at; uses the current instruction pointer if omitted.
    #[serde(default)]
    pub address: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct DxArgs {
    /// Data-model (LINQ) expression, e.g. "@$cursession.TTD.Calls(\"ntdll!*\")".
    pub expression: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct BreakpointArgs {
    /// Breakpoint location: symbol, address, or expression (e.g. "nt!NtCreateFile").
    pub expression: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct PositionArgs {
    /// TTD position to travel to, e.g. "12:0" or "0" for the start of the trace.
    pub position: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct RecordArgs {
    /// Directory to write the .run/.idx trace files into.
    pub out_dir: String,
    /// Program (with optional arguments) to launch and record.
    pub target: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct TtdCallsArgs {
    /// Function symbol or wildcard pattern to find calls to, e.g.
    /// "kernelbase!CreateFileW" or "ntdll!Nt*".
    pub function: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct TtdMemoryArgs {
    /// Start virtual address of the range to watch (decimal or 0x-hex).
    pub address: String,
    /// Number of bytes in the range.
    pub size: u32,
    /// Optional access filter: any combination of r(ead), w(rite), e/c(execute).
    /// Omit to report every access.
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct DecodeIoctlArgs {
    /// 32-bit IOCTL control code (decimal or 0x-hex), e.g. "0x70000".
    pub code: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct DriverObjectArgs {
    /// Driver object name, e.g. "mydriver" or "\\Driver\\mydriver".
    pub name: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct DeviceObjectArgs {
    /// Device object: a name (e.g. "\\Device\\MyDevice") or an address (0x-hex).
    pub device: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct IrpStackArgs {
    /// IRP address (decimal or 0x-hex). Defaults to `@rdx` — the PIRP passed to the
    /// dispatch routine on x64, valid only at the dispatch *entry*, before any step
    /// clobbers the register.
    #[serde(default)]
    pub irp: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct IoctlTraceArgs {
    /// Virtual address of the IRP_MJ_DEVICE_CONTROL dispatch routine, rebased to the
    /// live load base. Recover it via `driver_object` (MajorFunction[0x0e]).
    pub dispatch: String,
}

// ---- Tools ---------------------------------------------------------------

#[rmcp::tool_router]
impl WindbgServer {
    pub fn new(engine: EngineHandle) -> Self {
        Self { engine }
    }

    /// Open a crash dump (.dmp) or a Time Travel Debugging trace (.run) and wait for it to load.
    #[rmcp::tool]
    async fn open_dump(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| {
                e.open_dump(&args.path).map_err(es)?;
                e.wait_for_event(LOAD_WAIT_MS).map_err(es)?;
                // Load the WinDbg extension DLL so `!`-extension commands resolve — most
                // importantly `!ext.analyze -v`, the crash-dump triage workhorse. A bare
                // engine doesn't auto-load it, and even after `.load ext` the unqualified
                // `!analyze` won't resolve, so callers must use `!ext.analyze`. Best-effort:
                // a minimal engine without a bundled `winext\` directory simply won't have
                // ext.dll, which must not fail the open (live/dump state is still usable).
                let _ = e.execute_command(".load ext");
                e.execute_command("lm").map_err(es)
            })
            .await?;
        text_result(out)
    }

    /// Open a TTD trace (.run); alias of open_dump. Enables time-travel navigation and TTD queries.
    #[rmcp::tool]
    async fn open_trace(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| {
                e.open_trace(&args.path).map_err(es)?;
                e.wait_for_event(LOAD_WAIT_MS).map_err(es)?;
                // Confirm TTD replay is active and report the trace's position span.
                e.execute_command("dx @$curprocess.TTD.Lifetime")
                    .map_err(es)
            })
            .await?;
        text_result(out)
    }

    /// Attach to the local kernel (live local kernel debugging).
    #[rmcp::tool]
    async fn attach_kernel_local(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| {
                // attach_local_kernel breaks the target in internally (INITIAL_BREAK +
                // an INFINITE wait, as a live kernel requires).
                e.attach_local_kernel().map_err(es)?;
                e.execute_command("vertarget").map_err(es)
            })
            .await?;
        text_result(out)
    }

    /// Attach to a kernel target over a connection string (e.g. KDNET).
    #[rmcp::tool]
    async fn attach_kernel(
        &self,
        Parameters(args): Parameters<ConnectionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| {
                // attach_kernel connects, requests an initial break, and waits (INFINITE,
                // as a live kernel requires) for the break-in — all internally.
                e.attach_kernel(&args.connection).map_err(es)?;
                e.execute_command("vertarget").map_err(es)
            })
            .await?;
        text_result(out)
    }

    /// Attach to an existing user-mode process by PID and break in.
    #[rmcp::tool]
    async fn attach_process(
        &self,
        Parameters(args): Parameters<PidArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let pid = args.pid;
        let out = self
            .engine
            .run(move |e| {
                // attach_process waits for the break-in internally.
                e.attach_process(pid).map_err(es)?;
                e.execute_command("r").map_err(es)
            })
            .await?;
        text_result(out)
    }

    /// Launch a new user-mode process under the debugger, stopping at the initial breakpoint.
    #[rmcp::tool]
    async fn launch(
        &self,
        Parameters(args): Parameters<CommandLineArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| {
                // launch_process waits for the initial break internally.
                e.launch_process(&args.command_line).map_err(es)?;
                e.execute_command("r").map_err(es)
            })
            .await?;
        text_result(out)
    }

    /// End the current debug session (detach/close the target) without exiting the server.
    #[rmcp::tool]
    async fn end_session(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| {
                e.end_session()
                    .map(|_| "session ended".to_string())
                    .map_err(es)
            })
            .await?;
        text_result(out)
    }

    /// Run a raw debugger command and return its full output. The universal escape hatch.
    #[rmcp::tool]
    async fn execute(
        &self,
        Parameters(args): Parameters<ExecuteArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| e.execute_command(&args.command).map_err(es))
            .await?;
        text_result(out)
    }

    /// Show the current register set.
    #[rmcp::tool]
    async fn registers(&self) -> Result<CallToolResult, ErrorData> {
        let out = self.engine.run(move |e| e.registers().map_err(es)).await?;
        text_result(out)
    }

    /// Read process/kernel virtual memory and return a hex dump.
    #[rmcp::tool]
    async fn read_memory(
        &self,
        Parameters(args): Parameters<ReadMemoryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let size = args.size;
        let out = self
            .engine
            .run(move |e| {
                let addr = parse_u64(&args.address)?;
                let bytes = e.read_memory(addr, size as usize).map_err(es)?;
                Ok(hexdump(addr, &bytes))
            })
            .await?;
        text_result(out)
    }

    /// Show the call stack of the current thread (`k`).
    #[rmcp::tool]
    async fn backtrace(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| e.execute_command("k").map_err(es))
            .await?;
        text_result(out)
    }

    /// List loaded modules (`lm`).
    #[rmcp::tool]
    async fn modules(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| e.execute_command("lm").map_err(es))
            .await?;
        text_result(out)
    }

    /// List threads (`~`).
    #[rmcp::tool]
    async fn threads(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| e.execute_command("~").map_err(es))
            .await?;
        text_result(out)
    }

    /// Disassemble at an address/symbol (or the current IP).
    #[rmcp::tool]
    async fn disassemble(
        &self,
        Parameters(args): Parameters<DisassembleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let cmd = match args.address {
            Some(a) => format!("u {a}"),
            None => "u".to_string(),
        };
        let out = self
            .engine
            .run(move |e| e.execute_command(&cmd).map_err(es))
            .await?;
        text_result(out)
    }

    /// Evaluate a data-model (LINQ) expression with `dx` — ideal for TTD queries.
    #[rmcp::tool]
    async fn dx(&self, Parameters(args): Parameters<DxArgs>) -> Result<CallToolResult, ErrorData> {
        let cmd = format!("dx {}", args.expression);
        let out = self
            .engine
            .run(move |e| e.execute_command(&cmd).map_err(es))
            .await?;
        text_result(out)
    }

    /// TTD: find every call to a function across the whole trace
    /// (`dx @$cursession.TTD.Calls(...)`). Each result carries the time, thread,
    /// parameters, and return value. Append LINQ in a follow-up `dx`/`execute` to
    /// filter (e.g. `.Where(c => c.ReturnValue != 0)`).
    #[rmcp::tool]
    async fn ttd_calls(
        &self,
        Parameters(args): Parameters<TtdCallsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let cmd = format!("dx @$cursession.TTD.Calls(\"{}\")", args.function);
        let out = self
            .engine
            .run(move |e| e.execute_command(&cmd).map_err(es))
            .await?;
        text_result(out)
    }

    /// TTD: find every access to a memory range across the trace
    /// (`dx @$cursession.TTD.Memory(start, end, mode)`) — when and from where it was
    /// read, written, or executed.
    #[rmcp::tool]
    async fn ttd_memory(
        &self,
        Parameters(args): Parameters<TtdMemoryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let size = args.size;
        let mode = args.mode.clone();
        let out = self
            .engine
            .run(move |e| {
                let start = parse_u64(&args.address)?;
                let end = start.saturating_add(size as u64);
                let cmd = match mode {
                    Some(m) if !m.trim().is_empty() => format!(
                        "dx @$cursession.TTD.Memory(0x{start:x}, 0x{end:x}, \"{}\")",
                        m.trim()
                    ),
                    _ => format!("dx @$cursession.TTD.Memory(0x{start:x}, 0x{end:x})"),
                };
                e.execute_command(&cmd).map_err(es)
            })
            .await?;
        text_result(out)
    }

    /// TTD: list trace events — module loads/unloads, thread create/exit, and
    /// exceptions (`dx @$curprocess.TTD.Events`). Events and Threads hang off
    /// `@$curprocess.TTD`; Calls and Memory hang off `@$cursession.TTD`.
    #[rmcp::tool]
    async fn ttd_events(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| {
                e.execute_command("dx -r2 @$curprocess.TTD.Events")
                    .map_err(es)
            })
            .await?;
        text_result(out)
    }

    /// Set a breakpoint at a symbol, address, or expression (`bp`).
    #[rmcp::tool]
    async fn set_breakpoint(
        &self,
        Parameters(args): Parameters<BreakpointArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let cmd = format!("bp {}", args.expression);
        let out = self
            .engine
            .run(move |e| e.execute_command(&cmd).map_err(es))
            .await?;
        text_result(out)
    }

    /// Continue execution (`g`). Runs to the next breakpoint, or the end of a TTD trace.
    #[rmcp::tool]
    async fn go(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| e.execute_and_wait("g", EXEC_WAIT_MS).map_err(es))
            .await?;
        text_result(out)
    }

    /// Step over one source/instruction step (`p`).
    #[rmcp::tool]
    async fn step_over(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| e.execute_and_wait("p", EXEC_WAIT_MS).map_err(es))
            .await?;
        text_result(out)
    }

    /// Step into one instruction (`t`).
    #[rmcp::tool]
    async fn step_into(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| e.execute_and_wait("t", EXEC_WAIT_MS).map_err(es))
            .await?;
        text_result(out)
    }

    /// Step backward one instruction in a TTD trace (`t-`). Reverse of step_into.
    #[rmcp::tool]
    async fn step_back(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| e.execute_and_wait("t-", EXEC_WAIT_MS).map_err(es))
            .await?;
        text_result(out)
    }

    /// Step over one call backward in a TTD trace (`p-`). Reverse of step_over.
    #[rmcp::tool]
    async fn step_over_back(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| e.execute_and_wait("p-", EXEC_WAIT_MS).map_err(es))
            .await?;
        text_result(out)
    }

    /// Reverse-continue: run the TTD trace backward until a breakpoint or its start (`g-`).
    #[rmcp::tool]
    async fn reverse_go(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| e.execute_and_wait("g-", EXEC_WAIT_MS).map_err(es))
            .await?;
        text_result(out)
    }

    /// Travel to a specific position in a TTD trace (`!tt <position>`).
    #[rmcp::tool]
    async fn goto_position(
        &self,
        Parameters(args): Parameters<PositionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let cmd = format!("!tt {}", args.position);
        let out = self
            .engine
            .run(move |e| e.execute_command(&cmd).map_err(es))
            .await?;
        text_result(out)
    }

    /// Rebuild the index of the currently open TTD trace (`!tt.index`).
    #[rmcp::tool]
    async fn index_trace(&self) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| e.execute_command("!tt.index").map_err(es))
            .await?;
        text_result(out)
    }

    /// Record a new TTD trace by launching a target under TTD.exe (requires elevation).
    /// Reports an error if the recorder fails to start (e.g. not running elevated).
    #[rmcp::tool]
    async fn record_trace(
        &self,
        Parameters(args): Parameters<RecordArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Locating TTD touches the filesystem and record_launch briefly blocks watching
        // the recorder, so run the whole thing on a blocking thread (not the engine
        // thread — recording is independent of the debug session).
        let res = tokio::task::spawn_blocking(move || {
            let ttd = ttd::find_ttd().ok_or_else(|| {
                "TTD.exe not found (install the Windows debugging tools / WinDbg)".to_string()
            })?;
            ttd::record_launch(&ttd, &args.out_dir, &args.target)
        })
        .await
        .map_err(|e| ErrorData::internal_error(format!("record task panicked: {e}"), None))?;

        match res {
            Ok(msg) => text_result(msg),
            Err(e) => Err(ErrorData::internal_error(e, None)),
        }
    }

    /// Decode a 32-bit IOCTL control code into its CTL_CODE fields (DeviceType,
    /// FunctionCode, Method, RequiredAccess) and flag METHOD_NEITHER / FILE_ANY_ACCESS.
    /// Pure — needs no debug session.
    #[rmcp::tool]
    async fn decode_ioctl(
        &self,
        Parameters(args): Parameters<DecodeIoctlArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let code = parse_u64(&args.code).map_err(|e| ErrorData::invalid_params(e, None))?;
        text_result(decode_ioctl_text(code))
    }

    /// Dump a driver object's dispatch table and devices (`!drvobj <name> 7`).
    /// The MajorFunction table's index 0x0e is the IRP_MJ_DEVICE_CONTROL handler — the
    /// IOCTL dispatch routine. Root of the device-tree walk.
    #[rmcp::tool]
    async fn driver_object(
        &self,
        Parameters(args): Parameters<DriverObjectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let cmd = format!("!drvobj {} 7", args.name);
        let out = self
            .engine
            .run(move |e| e.execute_command(&cmd).map_err(es))
            .await?;
        text_result(out)
    }

    /// Inspect a device object (`!devobj <device>`): device type, characteristics
    /// (e.g. FILE_DEVICE_SECURE_OPEN), and the SecurityDescriptor pointer. To answer the
    /// *openable* gate, decode that DACL with `!sd <SecurityDescriptor>` via `execute`.
    #[rmcp::tool]
    async fn device_object(
        &self,
        Parameters(args): Parameters<DeviceObjectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let cmd = format!("!devobj {}", args.device);
        let out = self
            .engine
            .run(move |e| e.execute_command(&cmd).map_err(es))
            .await?;
        text_result(out)
    }

    /// Dump the current IO_STACK_LOCATION of an IRP (`!irp <irp> 1`): major/minor,
    /// IoControlCode, input/output buffer lengths, and buffer pointers. Defaults the IRP
    /// to `@rdx` (the PIRP at the dispatch entry on x64) — valid only before stepping.
    #[rmcp::tool]
    async fn irp_stack(
        &self,
        Parameters(args): Parameters<IrpStackArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let irp = args.irp.unwrap_or_else(|| "@rdx".to_string());
        let cmd = format!("!irp {irp} 1");
        let out = self
            .engine
            .run(move |e| e.execute_command(&cmd).map_err(es))
            .await?;
        text_result(out)
    }

    /// Install a conditional logging breakpoint at the IOCTL dispatch routine that prints
    /// each IoControlCode + input/output lengths and continues (`gc`), so the IOCTL sweep
    /// needs no hand-assembled offsets. Reads the current IO_STACK_LOCATION via
    /// `poi(@rdx+0xb8)` (x64); confirm the offset with `dt nt!_IRP` / `dt nt!_IO_STACK_LOCATION`
    /// on the target. Requires a real KDNET/VM target — a local kernel cannot set code bp's.
    #[rmcp::tool]
    async fn ioctl_trace(
        &self,
        Parameters(args): Parameters<IoctlTraceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // IRP in @rdx at dispatch entry (x64). CurrentStackLocation = poi(Irp+0xb8).
        // Within IO_STACK_LOCATION: OutputBufferLength +0x08, InputBufferLength +0x10,
        // IoControlCode +0x18 (Parameters union begins at +0x08).
        let cmd = format!(
            "bp {} \".printf \\\"IOCTL %08x in=%x out=%x\\\\n\\\", \
             dwo(poi(@rdx+0xb8)+0x18), dwo(poi(@rdx+0xb8)+0x10), dwo(poi(@rdx+0xb8)+0x08); gc\"",
            args.dispatch
        );
        let out = self
            .engine
            .run(move |e| e.execute_command(&cmd).map_err(es))
            .await?;
        text_result(out)
    }
}

#[rmcp::tool_handler(
    instructions = "Drive WinDbg/DbgEng for live user-mode, kernel, crash-dump, and Time Travel Debugging (TTD) analysis. \
Open a dump or .run trace, attach to a process or the kernel, inspect registers/memory/stacks/modules, and set breakpoints. \
Navigate a TTD trace in both directions: go/step_over/step_into forward, and reverse_go/step_over_back/step_back backward, \
or jump with goto_position. Analyze a trace with the data-model tools ttd_calls (calls to a function), ttd_memory (accesses \
to an address range), and ttd_events (module/thread/exception events), or run any data-model query with dx. Record new traces \
with record_trace (needs elevation). For driver IOCTL work: decode_ioctl (decode a control code), driver_object \
and device_object (walk the driver/device tree and security), irp_stack (dump an IRP's IO_STACK_LOCATION), and \
ioctl_trace (log every dispatched IOCTL). Use `execute` for any raw command not covered by a dedicated tool."
)]
impl rmcp::ServerHandler for WindbgServer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_u64_decimal() {
        assert_eq!(parse_u64("4096"), Ok(4096));
        assert_eq!(parse_u64("0"), Ok(0));
    }

    #[test]
    fn parse_u64_hex_either_case_prefix() {
        assert_eq!(parse_u64("0x1000"), Ok(0x1000));
        assert_eq!(parse_u64("0X1000"), Ok(0x1000));
        assert_eq!(parse_u64("0xdeadbeef"), Ok(0xdead_beef));
    }

    #[test]
    fn parse_u64_trims_surrounding_whitespace() {
        assert_eq!(parse_u64("  4096  "), Ok(4096));
        assert_eq!(parse_u64("\t0x10\n"), Ok(0x10));
    }

    #[test]
    fn parse_u64_boundaries() {
        assert_eq!(parse_u64("18446744073709551615"), Ok(u64::MAX));
        assert_eq!(parse_u64("0xffffffffffffffff"), Ok(u64::MAX));
    }

    #[test]
    fn parse_u64_rejects_invalid() {
        for bad in ["xyz", "", "0xZZ", "0x", "-1", "12.3"] {
            let err = parse_u64(bad).unwrap_err();
            assert!(
                err.starts_with("invalid number:"),
                "unexpected error for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn hexdump_empty_is_empty() {
        assert_eq!(hexdump(0, &[]), "");
    }

    #[test]
    fn hexdump_short_row_pads_hex_column() {
        // Three bytes: the hex column is left-aligned to 47 chars, then the ASCII
        // column follows. Printable bytes pass through verbatim. Build the expected
        // padding with the same width constant rather than hand-counting spaces.
        let out = hexdump(0, b"abc");
        let expected = format!("0000000000000000  {:<47}  abc\n", "61 62 63");
        assert_eq!(out, expected);
    }

    #[test]
    fn hexdump_full_row_then_partial_advances_address() {
        let bytes: Vec<u8> = (0u8..18).collect();
        let out = hexdump(0x1000, &bytes);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("0000000000001000  "));
        // Second chunk starts 16 bytes (0x10) on.
        assert!(lines[1].starts_with("0000000000001010  "));
    }

    #[test]
    fn hexdump_renders_nonprintable_as_dot() {
        // 0x00 and 0x7f are non-printable; 'A' (0x41) is printable.
        let out = hexdump(0, &[0x00, 0x41, 0x7f]);
        assert!(out.ends_with(".A.\n"), "got: {out:?}");
    }

    #[test]
    fn decode_ioctl_disk_get_drive_geometry() {
        // IOCTL_DISK_GET_DRIVE_GEOMETRY = CTL_CODE(IOCTL_DISK_BASE=0x7, 0, BUFFERED, ANY).
        let out = decode_ioctl_text(0x70000);
        assert!(out.contains("DeviceType     0x0007"), "got: {out}");
        assert!(out.contains("FunctionCode   0x000"), "got: {out}");
        assert!(
            out.contains("Method         0 (METHOD_BUFFERED)"),
            "got: {out}"
        );
        assert!(
            out.contains("RequiredAccess 0 (FILE_ANY_ACCESS)"),
            "got: {out}"
        );
        // FILE_ANY_ACCESS is flagged; METHOD_NEITHER is not.
        assert!(out.contains("[!] FILE_ANY_ACCESS"), "got: {out}");
        assert!(!out.contains("[!] METHOD_NEITHER"), "got: {out}");
    }

    #[test]
    fn decode_ioctl_neither_write_flags_both_warnings() {
        // CTL_CODE(DeviceType=0x8000, Function=0x800, METHOD_NEITHER, FILE_WRITE_DATA).
        let code = (0x8000u32 << 16) | (2u32 << 14) | (0x800u32 << 2) | 3;
        let out = decode_ioctl_text(code as u64);
        assert!(out.contains("DeviceType     0x8000"), "got: {out}");
        assert!(out.contains("FunctionCode   0x800"), "got: {out}");
        assert!(
            out.contains("Method         3 (METHOD_NEITHER)"),
            "got: {out}"
        );
        assert!(
            out.contains("RequiredAccess 2 (FILE_WRITE_DATA)"),
            "got: {out}"
        );
        assert!(out.contains("[!] METHOD_NEITHER"), "got: {out}");
        // FILE_WRITE_DATA is an access gate, so the ANY_ACCESS warning must be absent.
        assert!(!out.contains("[!] FILE_ANY_ACCESS"), "got: {out}");
    }
}
