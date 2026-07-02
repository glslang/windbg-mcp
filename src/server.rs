//! The MCP server: a curated set of debugger tools plus a raw command passthrough.
//!
//! Every tool marshals its work onto the engine thread via [`EngineHandle`]. Most
//! tools are thin wrappers over `execute_command` (the universal DbgEng escape
//! hatch, returning full text); session-management tools call the typed
//! `win-kexp` methods and then wait for the target to stop.

use std::collections::{HashMap, HashSet, VecDeque};

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
fn decode_ioctl_text(c: u32) -> String {
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

// ---- IOCTL dispatch reachability (static call-graph walk) ----------------
//
// Answers "is the code block at <target> reachable from the IOCTL dispatch
// routine?" with a bounded breadth-first walk over the call graph, built from
// repeated `uf` (unassemble-function) disassembly parsed as text. The whole
// algorithm is engine-free — `reachability` takes a disassembler closure — so it
// unit-tests without a live debugger (like `decode_ioctl_text` above).

/// Parses a WinDbg address token into a `u64`. Accepts the `hi`lo` backtick form
/// ("fffff803`3e254750"), a plain hex run ("00401000"), and tokens wrapped or
/// trailed by parens/commas ("(fffff803`3e2547f0)"). Requires >= 8 hex digits so
/// it never mistakes a mnemonic, a short immediate, or a "module!Symbol:" label
/// for an address.
fn parse_windbg_addr(tok: &str) -> Option<u64> {
    let cleaned: String = tok
        .trim_matches(|c| c == '(' || c == ')' || c == ',')
        .chars()
        .filter(|&c| c != '`')
        .collect();
    if cleaned.len() < 8 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(&cleaned, 16).ok()
}

/// The resolved target of a direct branch/call is the last parenthesized address
/// WinDbg prints on the line ("... (fffff803`3e2547f0)"). Register/memory-indirect
/// operands print no such address (or the *pointer's* address, which callers
/// exclude via the `[` guard in [`parse_uf`]) and are not followed.
fn branch_target(line: &str) -> Option<u64> {
    let open = line.rfind('(')?;
    let rest = &line[open..];
    let close = rest.find(')')?;
    parse_windbg_addr(&rest[..=close])
}

/// One function's `uf` disassembly, reduced to what the call-graph walk needs.
#[derive(Debug, Default, PartialEq)]
struct UfBlock {
    /// First instruction address (the function entry), if any lines parsed.
    entry: Option<u64>,
    /// Address of every instruction in the function body.
    instrs: Vec<u64>,
    /// (call-site, resolved direct-call target).
    calls: Vec<(u64, u64)>,
    /// (site, unconditional `jmp` target).
    jmps: Vec<(u64, u64)>,
    /// (site, conditional-branch target: je/jne/jz/jg/...).
    branches: Vec<(u64, u64)>,
}

/// Parses `uf <fn>` output. Each instruction line is `<addr> <bytes> <mnem> <ops>`;
/// label lines ("module!Foo:"), blanks, and jump-table data lines have no leading
/// address token and are skipped. Only *direct*, resolvable branch/call targets are
/// recorded — memory-indirect operands (`call qword ptr [..]`) and register-indirect
/// (`call rax`) are skipped so a REACHABLE verdict stays sound.
fn parse_uf(text: &str) -> UfBlock {
    let mut b = UfBlock::default();
    for line in text.lines() {
        let mut toks = line.split_whitespace();
        let Some(addr) = toks.next().and_then(parse_windbg_addr) else {
            continue;
        };
        let _bytes = toks.next(); // raw opcode-bytes column
        if b.entry.is_none() {
            b.entry = Some(addr);
        }
        b.instrs.push(addr);
        let Some(mnem) = toks.next() else {
            continue; // address with no mnemonic — treat as a bare instr line
        };
        // Memory-indirect operands are not directly resolvable; skip them (register-
        // indirect operands have no parenthesized target and are dropped below).
        if line.contains('[') {
            continue;
        }
        let Some(t) = branch_target(line) else {
            continue;
        };
        if mnem.starts_with("call") {
            b.calls.push((addr, t));
        } else if mnem == "jmp" {
            b.jmps.push((addr, t));
        } else if mnem.starts_with('j') {
            b.branches.push((addr, t));
        }
    }
    b
}

/// The first address token in `lm m <module>` output is the module's live start
/// (its base). Header lines ("Browse full module list", the "start end module"
/// legend) have no leading address and are skipped by the >= 8 hex-digit rule.
fn parse_lm_base(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.split_whitespace().next().and_then(parse_windbg_addr))
}

/// Outcome of a reachability walk. `verdict_reachable` is sound (a concrete static
/// path exists); a false verdict is best-effort within the explored bounds.
struct Report {
    verdict_reachable: bool,
    /// Resolved entry of the `from` function (None if `from` didn't disassemble).
    from_entry: Option<u64>,
    target: u64,
    /// Entry of the function containing `target`, when reachable.
    containing_fn: Option<u64>,
    /// Call path seed -> ... -> containing function: (site, "call"/"jmp", callee).
    path: Vec<(u64, &'static str, u64)>,
    funcs_explored: usize,
    max_depth_seen: usize,
    /// True if a function/depth bound was hit (so the caller can raise it and retry).
    bound_hit: bool,
    max_functions: usize,
    max_depth: usize,
}

/// Walks the call/branch graph from `from`, running `uf(arg)` for each discovered
/// function, until `target` is found among some function's instructions, the graph
/// is exhausted, or a bound is hit. `uf` returns the raw `uf <arg>` text or `None`
/// (bad address / forwarded export / disassembly failure) to prune that branch.
fn reachability(
    from: &str,
    target: u64,
    max_functions: usize,
    max_depth: usize,
    mut uf: impl FnMut(&str) -> Option<String>,
) -> Report {
    let mut visited: HashSet<u64> = HashSet::new(); // function entries already uf'd
    let mut enqueued: HashSet<u64> = HashSet::new(); // target tokens scheduled
    // child token -> (caller token (None = seed), call site, kind).
    let mut parent: HashMap<u64, (Option<u64>, u64, &'static str)> = HashMap::new();
    let mut queue: VecDeque<(String, Option<u64>, usize)> = VecDeque::new();
    queue.push_back((from.to_string(), None, 0));

    let mut rpt = Report {
        verdict_reachable: false,
        from_entry: None,
        target,
        containing_fn: None,
        path: Vec::new(),
        funcs_explored: 0,
        max_depth_seen: 0,
        bound_hit: false,
        max_functions,
        max_depth,
    };

    while let Some((arg, token, depth)) = queue.pop_front() {
        if rpt.funcs_explored >= max_functions || depth > max_depth {
            rpt.bound_hit = true;
            continue;
        }
        let Some(text) = uf(&arg) else {
            continue; // disassembly failed — prune this branch
        };
        let block = parse_uf(&text);
        let Some(entry) = block.entry else {
            continue;
        };
        if !visited.insert(entry) {
            continue; // this function was already explored (dedupe cycles)
        }
        if token.is_none() {
            rpt.from_entry = Some(entry);
        }
        rpt.funcs_explored += 1;
        rpt.max_depth_seen = rpt.max_depth_seen.max(depth);

        if block.instrs.iter().any(|&i| i == target) {
            rpt.verdict_reachable = true;
            rpt.containing_fn = Some(entry);
            rpt.path = reconstruct(&parent, token);
            return rpt;
        }

        let in_func: HashSet<u64> = block.instrs.iter().copied().collect();
        let mut schedule =
            |site: u64,
             t: u64,
             kind: &'static str,
             q: &mut VecDeque<(String, Option<u64>, usize)>| {
                if enqueued.insert(t) {
                    parent.insert(t, (token, site, kind));
                    q.push_back((format!("0x{t:x}"), Some(t), depth + 1));
                }
            };
        for &(site, t) in &block.calls {
            schedule(site, t, "call", &mut queue);
        }
        // Follow only jmp/branch targets that LEAVE this function (tail calls,
        // cross-function jumps). Intra-function branches are already inside this `uf`.
        for &(site, t) in block.jmps.iter().chain(block.branches.iter()) {
            if !in_func.contains(&t) {
                schedule(site, t, "jmp", &mut queue);
            }
        }
    }
    rpt
}

/// Rebuilds the call path from the seed to the function reached via `token`, by
/// walking the `parent` chain backward and reversing it.
fn reconstruct(
    parent: &HashMap<u64, (Option<u64>, u64, &'static str)>,
    token: Option<u64>,
) -> Vec<(u64, &'static str, u64)> {
    let mut hops = Vec::new();
    let mut cur = token;
    while let Some(t) = cur {
        let Some(&(caller, site, kind)) = parent.get(&t) else {
            break;
        };
        hops.push((site, kind, t));
        cur = caller;
    }
    hops.reverse();
    hops
}

/// Formats a WinDbg-style `hi`lo` address.
fn fmt_addr(a: u64) -> String {
    format!("{:08x}`{:08x}", a >> 32, a & 0xffff_ffff)
}

/// Renders a [`Report`] as the tool's text output.
fn format_report(r: &Report) -> String {
    let mut out = String::new();
    out.push_str("IOCTL dispatch reachability\n");
    match r.from_entry {
        Some(e) => out.push_str(&format!("  from   : entry {}\n", fmt_addr(e))),
        None => out.push_str("  from   : <unresolved>\n"),
    }
    out.push_str(&format!("  target : {}\n", fmt_addr(r.target)));
    if r.verdict_reachable {
        out.push_str("VERDICT: REACHABLE\n");
        if let Some(f) = r.containing_fn {
            out.push_str(&format!("  Containing function entry: {}\n", fmt_addr(f)));
        }
        if r.path.is_empty() {
            out.push_str("  Call path: target is inside the start function (0 hops)\n");
        } else {
            out.push_str(&format!("  Call path ({} hops):\n", r.path.len()));
            for (site, kind, callee) in &r.path {
                out.push_str(&format!(
                    "    {}  {:<4} -> {}\n",
                    fmt_addr(*site),
                    kind,
                    fmt_addr(*callee)
                ));
            }
        }
    } else {
        out.push_str("VERDICT: NOT REACHABLE (within bounds)\n");
        out.push_str(&format!(
            "  Bound hit: {}\n",
            if r.bound_hit {
                "yes — raise max_functions/max_depth and retry"
            } else {
                "no — the reachable call graph was fully explored"
            }
        ));
    }
    out.push_str(&format!(
        "  Functions explored: {} (bound {})   Max depth reached: {} (bound {})\n",
        r.funcs_explored, r.max_functions, r.max_depth_seen, r.max_depth
    ));
    out.push_str(
        "  Caveats: indirect/computed calls (call [ptr], call reg) and unresolved jump tables\n",
    );
    out.push_str(
        "           are NOT followed. REACHABLE is sound; NOT REACHABLE within bounds does not\n",
    );
    out.push_str(
        "           prove unreachability — raise max_functions/max_depth, or pass a specific\n",
    );
    out.push_str("           handler VA as `from` to scope past a jump-table switch dispatch.\n");
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

#[derive(Deserialize, JsonSchema)]
pub struct ReachabilityArgs {
    /// Start of the search: the IRP_MJ_DEVICE_CONTROL dispatch routine — a symbol,
    /// address, or expression `uf` accepts (e.g. "mydriver!DispatchDeviceControl" or
    /// "fffff8033e254750"). Recover it via `driver_object` (MajorFunction[0x0e]). Pass
    /// a specific handler VA instead to scope the walk past a jump-table switch.
    pub from: String,
    /// Target code block as an absolute virtual address (decimal or 0x-hex). Provide
    /// this OR `module`+`rva`, not both.
    #[serde(default)]
    pub address: Option<String>,
    /// Module name for a module+RVA target, e.g. "mydriver". Its live base is read from
    /// `lm m <module>` and added to `rva`. Required (with `rva`) when `address` is omitted.
    #[serde(default)]
    pub module: Option<String>,
    /// Relative virtual address (decimal or 0x-hex) added to `module`'s live base.
    #[serde(default)]
    pub rva: Option<String>,
    /// Max distinct functions to disassemble before giving up (default 256). Bounds runtime.
    #[serde(default)]
    pub max_functions: Option<usize>,
    /// Max call-graph depth to explore from `from` (default 32).
    #[serde(default)]
    pub max_depth: Option<usize>,
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
                // The driver_object/device_object/irp_stack tools use kernel-extension
                // commands (!drvobj/!devobj/!irp) from kdexts.dll, which a bare engine does
                // not auto-load. Best-effort, like open_dump's `.load ext`; harmless if the
                // extension isn't bundled (those tools then report a clean "no export").
                let _ = e.execute_command(".load kdexts");
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
                // Load kdexts.dll so the driver_object/device_object/irp_stack tools'
                // !drvobj/!devobj/!irp commands resolve (see attach_kernel_local). Best-effort.
                let _ = e.execute_command(".load kdexts");
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
        // An IOCTL is a 32-bit value; reject anything wider rather than silently
        // truncating it to a different code.
        let code = u32::try_from(code).map_err(|_| {
            ErrorData::invalid_params(
                format!("IOCTL must be a 32-bit value (got 0x{code:x})"),
                None,
            )
        })?;
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
    /// (e.g. FILE_DEVICE_SECURE_OPEN), and the SecurityDescriptor pointer — the inputs to the
    /// *openable* gate. (`!sd <SecurityDescriptor>` decodes the DACL where that extension is
    /// available; it is not in the bundled engine.)
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

    /// Static, best-effort control-flow reachability: is the code block at `address`
    /// (or `module`+`rva`) reachable from the IOCTL dispatch routine `from`? Runs a
    /// bounded breadth-first walk over the call graph via repeated `uf` disassembly,
    /// following direct calls and cross-function tail jumps. "REACHABLE" is sound (a
    /// concrete static path exists, and the call path is reported); "NOT REACHABLE"
    /// means only that the block was not found within the bounds — indirect calls
    /// through function pointers and unresolved compiler jump tables are NOT followed.
    #[rmcp::tool]
    async fn reachable_from_dispatch(
        &self,
        Parameters(args): Parameters<ReachabilityArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .engine
            .run(move |e| {
                // Resolve the target VA: an absolute address, or module+RVA rebased
                // against the module's live base from `lm m <module>`.
                let target = match (&args.address, &args.module, &args.rva) {
                    (Some(a), _, _) => parse_u64(a)?,
                    (None, Some(m), Some(r)) => {
                        let rva = parse_u64(r)?;
                        let lm = e.execute_command(&format!("lm m {m}")).map_err(es)?;
                        let base = parse_lm_base(&lm).ok_or_else(|| {
                            format!("module `{m}` not found (`lm m {m}` returned):\n{lm}")
                        })?;
                        base.checked_add(rva)
                            .ok_or_else(|| "module base + rva overflowed u64".to_string())?
                    }
                    _ => {
                        return Err("provide `address`, or both `module` and `rva`".to_string());
                    }
                };

                let max_functions = args.max_functions.unwrap_or(256);
                let max_depth = args.max_depth.unwrap_or(32);

                let rpt = reachability(&args.from, target, max_functions, max_depth, |arg| {
                    // A real `uf` lists backtick addresses or at least a "module!Func:"
                    // label; error text ("Couldn't resolve...", "no code") lacks both
                    // and prunes the branch. parse_uf then discards any non-disassembly.
                    match e.execute_command(&format!("uf {arg}")) {
                        Ok(t) if t.contains('`') || t.contains(':') => Some(t),
                        _ => None,
                    }
                });

                if rpt.from_entry.is_none() {
                    return Err(format!(
                        "could not disassemble `from` ({}): `uf` returned no function. \
                         Check the symbol/address and that the module is loaded.",
                        args.from
                    ));
                }
                Ok(format_report(&rpt))
            })
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
and device_object (walk the driver/device tree and security), irp_stack (dump an IRP's IO_STACK_LOCATION), \
ioctl_trace (log every dispatched IOCTL), and reachable_from_dispatch (statically test, via a bounded \
uf-based call-graph walk, whether a code block — by address or module+RVA — is reachable from the IOCTL \
dispatch routine; REACHABLE is sound, NOT REACHABLE is best-effort). Use `execute` for any raw command not \
covered by a dedicated tool."
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
        // Device type 0x8000 sets bit 31 — exercises a full 32-bit (unsigned) code.
        let code = (0x8000u32 << 16) | (2u32 << 14) | (0x800u32 << 2) | 3;
        let out = decode_ioctl_text(code);
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

    // ---- reachability: parsing --------------------------------------------

    #[test]
    fn parse_windbg_addr_forms() {
        assert_eq!(
            parse_windbg_addr("fffff803`3e254750"),
            Some(0xfffff803_3e254750)
        );
        assert_eq!(
            parse_windbg_addr("(fffff803`3e2547f0)"),
            Some(0xfffff803_3e2547f0)
        );
        // Plain 32-bit (x86) hex, no backtick.
        assert_eq!(parse_windbg_addr("00401000"), Some(0x0040_1000));
        // Mnemonics, registers, labels, and short immediates are not addresses.
        assert_eq!(parse_windbg_addr("call"), None);
        assert_eq!(parse_windbg_addr("rax"), None);
        assert_eq!(parse_windbg_addr("mydriver!Foo:"), None);
        assert_eq!(parse_windbg_addr("28h"), None);
    }

    #[test]
    fn parse_uf_classifies_targets_and_skips_indirect() {
        // A function with a direct call, a conditional branch, an unconditional jmp,
        // and a memory-indirect call (which must NOT be recorded as a direct target).
        let text = "\
mydriver!Dispatch:
fffff803`3e254750 4c8bdc          mov     r11,rsp
fffff803`3e254758 e893000000      call    mydriver!Helper (fffff803`3e2547f0)
fffff803`3e25475d 85c0            test    eax,eax
fffff803`3e25475f 0f8541000000    jne     mydriver!Dispatch+0x56 (fffff803`3e2547a6)
fffff803`3e254765 ff15aabbccdd    call    qword ptr [mydriver!Ptr (fffff803`3e260000)]
fffff803`3e25476b e9c0000000      jmp     mydriver!Tail (fffff803`3e254830)
fffff803`3e254770 c3              ret
";
        let b = parse_uf(text);
        assert_eq!(b.entry, Some(0xfffff803_3e254750));
        assert_eq!(b.instrs.len(), 7); // 7 instruction lines; the label line is not one
        assert_eq!(b.calls, vec![(0xfffff803_3e254758, 0xfffff803_3e2547f0)]);
        assert_eq!(b.branches, vec![(0xfffff803_3e25475f, 0xfffff803_3e2547a6)]);
        assert_eq!(b.jmps, vec![(0xfffff803_3e25476b, 0xfffff803_3e254830)]);
        // The `call qword ptr [..]` line contributed an instruction but no direct call.
        assert!(!b.calls.iter().any(|&(_, t)| t == 0xfffff803_3e260000));
    }

    #[test]
    fn parse_lm_base_reads_module_start() {
        let text = "\
Browse full module list
start             end                 module name
fffff803`3e250000 fffff803`3e270000   mydriver   (pdb symbols)
";
        assert_eq!(parse_lm_base(text), Some(0xfffff803_3e250000));
        assert_eq!(parse_lm_base("Unable to enumerate modules\n"), None);
    }

    // ---- reachability: graph walk -----------------------------------------

    /// Builds a `uf` block whose entry is `entry`, with the given follow-on lines
    /// appended (each already a full `uf` instruction line).
    fn uf_fn(label: &str, entry: u64, body: &[&str]) -> String {
        let mut s = format!("{label}:\n{} 90              nop\n", fmt_addr(entry));
        for l in body {
            s.push_str(l);
            s.push('\n');
        }
        s
    }

    #[test]
    fn reachability_direct_call_chain() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[&format!(
                    "{} e8xx call A!B ({})",
                    fmt_addr(0x1004),
                    fmt_addr(0x2000)
                )],
            ),
        );
        m.insert(
            "0x2000".to_string(),
            uf_fn("B", 0x2000, &[&format!("{} c3 ret", fmt_addr(0x2008))]),
        );
        let r = reachability("start", 0x2008, 256, 32, |a| m.get(a).cloned());
        assert!(r.verdict_reachable);
        assert_eq!(r.from_entry, Some(0x1000));
        assert_eq!(r.containing_fn, Some(0x2000));
        assert_eq!(r.path, vec![(0x1004, "call", 0x2000)]);
    }

    #[test]
    fn reachability_follows_tail_jmp() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[&format!(
                    "{} e9xx jmp A!B ({})",
                    fmt_addr(0x1004),
                    fmt_addr(0x2000)
                )],
            ),
        );
        m.insert(
            "0x2000".to_string(),
            uf_fn("B", 0x2000, &[&format!("{} c3 ret", fmt_addr(0x2008))]),
        );
        let r = reachability("start", 0x2008, 256, 32, |a| m.get(a).cloned());
        assert!(r.verdict_reachable);
        assert_eq!(r.path, vec![(0x1004, "jmp", 0x2000)]);
    }

    #[test]
    fn reachability_target_in_seed_is_zero_hops() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn("A", 0x1000, &[&format!("{} c3 ret", fmt_addr(0x1004))]),
        );
        let r = reachability("start", 0x1004, 256, 32, |a| m.get(a).cloned());
        assert!(r.verdict_reachable);
        assert_eq!(r.containing_fn, Some(0x1000));
        assert!(r.path.is_empty());
    }

    #[test]
    fn reachability_indirect_only_is_not_reached() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[&format!(
                    "{} ff15aa call qword ptr [A!Ptr ({})]",
                    fmt_addr(0x1004),
                    fmt_addr(0x9000)
                )],
            ),
        );
        // The target sits behind the indirect call, which is never followed.
        let r = reachability("start", 0x2008, 256, 32, |a| m.get(a).cloned());
        assert!(!r.verdict_reachable);
        assert!(!r.bound_hit); // graph exhausted, not a bound
    }

    #[test]
    fn reachability_cycle_terminates() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[&format!(
                    "{} e8xx call A!B ({})",
                    fmt_addr(0x1004),
                    fmt_addr(0x2000)
                )],
            ),
        );
        m.insert(
            "0x2000".to_string(),
            uf_fn(
                "B",
                0x2000,
                &[&format!(
                    "{} e8xx call B!A ({})",
                    fmt_addr(0x2004),
                    fmt_addr(0x1000)
                )],
            ),
        );
        // Target is absent — the A<->B cycle must not loop forever.
        let r = reachability("start", 0x7777, 256, 32, |a| m.get(a).cloned());
        assert!(!r.verdict_reachable);
        assert_eq!(r.funcs_explored, 2);
    }

    #[test]
    fn reachability_respects_function_bound() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[&format!(
                    "{} e8xx call A!B ({})",
                    fmt_addr(0x1004),
                    fmt_addr(0x2000)
                )],
            ),
        );
        m.insert(
            "0x2000".to_string(),
            uf_fn("B", 0x2000, &[&format!("{} c3 ret", fmt_addr(0x2004))]),
        );
        // Bound to a single function: B (which contains the target) is never explored.
        let r = reachability("start", 0x2004, 1, 32, |a| m.get(a).cloned());
        assert!(!r.verdict_reachable);
        assert!(r.bound_hit);
        assert_eq!(r.funcs_explored, 1);
    }
}
