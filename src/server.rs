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
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        out.push_str(&format!("{addr:016x}  {:<47}  {ascii}\n", hex.join(" ")));
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
                e.execute_command("dx @$curprocess.TTD.Lifetime").map_err(es)
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
                e.attach_local_kernel();
                e.wait_for_event(LOAD_WAIT_MS).map_err(es)?;
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
                e.attach_kernel(&args.connection);
                e.wait_for_event(LOAD_WAIT_MS).map_err(es)?;
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
            .run(move |e| e.end_session().map(|_| "session ended".to_string()).map_err(es))
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
    async fn dx(
        &self,
        Parameters(args): Parameters<DxArgs>,
    ) -> Result<CallToolResult, ErrorData> {
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
            .run(move |e| e.execute_command("dx -r2 @$curprocess.TTD.Events").map_err(es))
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
}

#[rmcp::tool_handler(
    instructions = "Drive WinDbg/DbgEng for live user-mode, kernel, crash-dump, and Time Travel Debugging (TTD) analysis. \
Open a dump or .run trace, attach to a process or the kernel, inspect registers/memory/stacks/modules, and set breakpoints. \
Navigate a TTD trace in both directions: go/step_over/step_into forward, and reverse_go/step_over_back/step_back backward, \
or jump with goto_position. Analyze a trace with the data-model tools ttd_calls (calls to a function), ttd_memory (accesses \
to an address range), and ttd_events (module/thread/exception events), or run any data-model query with dx. Record new traces \
with record_trace (needs elevation). Use `execute` for any raw command not covered by a dedicated tool."
)]
impl rmcp::ServerHandler for WindbgServer {}
