//! Transactional debugger batches: ordered steps, assertions, and a rollback the **worker** owns.
//!
//! Everything here exists because of one asymmetry. A tool call is a request/response, so a client
//! driving a multi-step debugger transaction has to decide *after* each answer what to do next —
//! and the case that matters is precisely the one where no answer arrives. A call that times out,
//! or a client that disconnects, leaves whatever the earlier calls changed in place: a patched
//! instruction, an armed breakpoint, a target left running. On a kernel target that is not an
//! inconvenience; an un-restored patch or a missed detach costs the VM.
//!
//! So the sequence is submitted as one op and executed inside the session's worker process, where
//! the cleanup block can be run by the same code that ran the mutations, on the same engine
//! thread, before the reply is written. The client's timeout can no longer land between a mutation
//! and its undo, because there is nothing for it to land *between*.
//!
//! Three things follow from that, and they are the whole design:
//!
//! * **The deadline is the worker's.** [`run`] is handed a total budget and reserves part of it for
//!   the `always` block before it starts, so "the steps ran out of time" and "the rollback ran out
//!   of time" are different events. The supervisor sizes that budget from the caller's remaining
//!   patience (`worker::batch_budget`) so the report lands *before* the tool call gives up.
//! * **`always` is reached on every path.** Success, a debugger error, an assertion that did not
//!   hold, an expired deadline, a panic out of the debugger — all of them fall through to the same
//!   block, cleanup continues past its own failures, and a failure inside it is recorded beside the
//!   original rather than replacing it. What the reserve buys is *time to run*, not a guarantee: a
//!   step that overruns far enough to consume the reserve too leaves cleanup with no budget, and
//!   skipped and the report says the rollback is incomplete. That is the honest edge, and it is
//!   pinned by a test rather than left to be discovered.
//! * **The executor never touches DbgEng.** It drives a [`Debuggee`], which the worker implements
//!   over a real engine and the tests implement over a script. Assertion failure, a command failure
//!   after a mutation, deadline expiry and a rollback that itself fails are therefore all testable
//!   without a debugger — which matters because those four paths are the ones a live target is
//!   least willing to reproduce on demand.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::server::{
    EXEC_WAIT_MS, Quotes, changes_debug_target, fmt_addr, parse_eval, reject_command_breakers,
};

/// The most steps one batch may carry, per block.
///
/// A bound rather than a judgement: the whole batch runs as one indivisible job on the session's
/// engine thread, so its length is also how long every other call to that session waits. Well past
/// the eighteen-step sequence that motivated this (see the `messagemanager` walkthrough), and far
/// short of a batch that could hold a session for its own reasons.
pub const MAX_STEPS: usize = 64;

/// The most assertions one step may carry. An `eval` check costs an engine round trip, so this
/// bounds the hidden work behind a step as much as it bounds the argument.
pub const MAX_CHECKS: usize = 16;

/// How much of the total budget is held back for the `always` block, so a rollback still runs
/// after the steps have used the clock up.
///
/// Reserved *up front* rather than taken from what is left, because "what is left" after a step
/// that ran to its own deadline is nothing. Capped at half the budget so a short batch still
/// spends most of its time on the work it was asked to do.
const ROLLBACK_RESERVE: Duration = Duration::from_secs(30);

/// The smallest watchdog a step is armed with. Zero *disables* win-kexp's watchdog, so a step
/// dequeued at or past the deadline must not round down to it.
const MIN_STEP_BUDGET_MS: u32 = 1_000;

/// How far past its budget a batch can still legitimately be running.
///
/// The budget bounds what may be **started**, not what may be finishing: an operation that begins a
/// moment before the deadline is still armed with [`MIN_STEP_BUDGET_MS`], because a watchdog of
/// zero is no watchdog at all. Three of those can stack at the end of a batch — the last cleanup
/// step's action, an assertion inside it, and the state probe, which runs unconditionally — and
/// win-kexp's watchdog needs a moment beyond that to interrupt and unwind.
///
/// Public because it is the difference between the budget and a bound the worker can actually
/// *keep*, and something outside is relying on that bound: a teardown is told when the batch will
/// be done and terminates the worker if it is not. Advertising the bare budget would have it kill
/// a worker in the middle of the restore it was waiting for — which is the whole failure being
/// avoided, arriving three seconds later.
pub const OVERRUN_ALLOWANCE: Duration = Duration::from_millis(4 * MIN_STEP_BUDGET_MS as u64);

/// Default deadline for a whole batch, when the caller names none (ms).
///
/// Comfortably more than a sequence of ordinary commands needs, and comfortably inside the default
/// call budget so the rollback report lands before the caller gives up. A batch that wants longer
/// asks for it; the worker still clamps it to the caller's remaining patience.
pub const DEFAULT_BATCH_MS: u32 = 120_000;

/// The shortest deadline a batch may ask for.
///
/// **Derived, not chosen.** For a short batch the reserve is half the budget, so the steps get the
/// other half — and the floor below means the very first step is armed for [`MIN_STEP_BUDGET_MS`]
/// however little of that half is left. Any budget under twice that floor therefore lets step one
/// run past the steps deadline and spend the reserve the rollback needs, which is the failure this
/// whole module is built to prevent, arriving through the argument meant to bound it.
///
/// At exactly this value the two are equal: the steps get one floor's worth, the reserve keeps
/// one, and a step that overruns can eat into the reserve but cannot exhaust it.
pub const MIN_BATCH_MS: u32 = 2 * MIN_STEP_BUDGET_MS;

/// The budget a batch is built with, from what the caller asked for.
///
/// Separate from [`validate`] because it answers a different question — that one is about the
/// steps, this is about the clock — and because the answer is a value the caller's request is
/// replaced by rather than a yes/no.
pub fn budget_ms(requested: Option<u32>) -> Result<u32, String> {
    match requested {
        None => Ok(DEFAULT_BATCH_MS),
        Some(ms) if ms < MIN_BATCH_MS => Err(format!(
            "`timeout_ms` is {ms}; a batch needs at least {MIN_BATCH_MS} ms. Part of the budget is \
             reserved for the `always` block, and a step is armed with at least \
             {MIN_STEP_BUDGET_MS} ms, so a deadline this short would spend the rollback's reserve \
             on the first step. Omit `timeout_ms` for the {DEFAULT_BATCH_MS} ms default."
        )),
        Some(ms) => Ok(ms),
    }
}

/// How much of a step's output the report carries, and how much it carries for the step that
/// failed. The failing step is what the caller has to act on, so it gets the bigger share; the
/// rest are context.
const STEP_OUTPUT_CHARS: usize = 1_500;
const FAILED_OUTPUT_CHARS: usize = 8_000;

// ---- the step language ----------------------------------------------------

/// What one step does.
///
/// Internally tagged and flattened into [`BatchStep`], so a step reads as one flat object
/// (`{"op": "command", "command": "bp nt!Foo"}`) rather than a wrapper around a wrapper. The
/// vocabulary is deliberately small: almost every typed tool in this server is a thin wrapper over
/// `execute_command`, so [`Self::Command`] already covers them, and the variants that exist beside
/// it are the ones a raw command genuinely cannot express as a single unit — a wait for the target
/// to stop, a run-to verdict, a value this batch can bind a name to.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum StepAction {
    /// Run a raw debugger command to completion and keep its output.
    ///
    /// Note what this does **not** assert: DbgEng prints most failures and returns success, so a
    /// command that says "Couldn't resolve error at 'nt!Nope'" is a step that *succeeded* with
    /// that text. Assert on it with a `contains` check if it matters.
    Command { command: String },
    /// Run a command that moves the target (`g`, `p`, `t`, `g @$ra`, a TTD reverse) and wait for
    /// the next stop.
    Resume {
        command: String,
        /// How long to wait for the stop, in ms. Clamped to what is left of the batch's budget.
        #[serde(default)]
        timeout_ms: Option<u32>,
    },
    /// Run until `address` and report a verdict: HIT, STOPPED ELSEWHERE, or TIMEOUT. The verdict
    /// is text in the step's output, so assert on it with `contains`.
    RunTo {
        address: String,
        #[serde(default)]
        timeout_ms: Option<u32>,
    },
    /// Evaluate a MASM expression (`@rcx`, `poi(@rsp+0x18)`, `nt!NtCreateFile`) and keep its
    /// value. The only step a `capture` may be attached to.
    Eval { expr: String },
    /// Hex-dump `size` bytes at `address`.
    ///
    /// `address` is a **number** — decimal or `0x`-hex — not a debugger expression, matching the
    /// `read_memory` tool. That is not a limitation in a batch: an `eval` step binds its value as
    /// `0x`-hex, so `@rsp` or `poi(@rbx+8)` is one `eval` with a `capture` and then `{{name}}`
    /// here.
    ReadMemory { address: String, size: u32 },
}

impl StepAction {
    /// Whether `key` is one this variant legitimately occupies in a flattened step.
    ///
    /// Spelled out rather than derived because serde will not tell us: a flattened internally
    /// tagged enum leaves the keys it matched in the shared buffer, so this is the only way to
    /// tell a variant's own field from a caller's typo. `a_well_formed_step_leaves_nothing_in_the
    /// _catch_all` is what stops this list drifting from the variants above.
    fn owns(&self, key: &str) -> bool {
        let fields: &[&str] = match self {
            Self::Command { .. } => &["command"],
            Self::Resume { .. } => &["command", "timeout_ms"],
            Self::RunTo { .. } => &["address", "timeout_ms"],
            Self::Eval { .. } => &["expr"],
            Self::ReadMemory { .. } => &["address", "size"],
        };
        key == "op" || fields.contains(&key)
    }

    /// The command line this action runs, for the report. Not what is sent to the engine for the
    /// non-command variants — it is what a reader needs to see to know what the step did.
    fn rendered(&self) -> String {
        match self {
            Self::Command { command } | Self::Resume { command, .. } => command.clone(),
            Self::RunTo { address, .. } => format!("run to {address}"),
            Self::Eval { expr } => format!("? {expr}"),
            Self::ReadMemory { address, size } => format!("read {size} bytes at {address}"),
        }
    }

    /// This action with every `{{name}}` reference resolved.
    fn substituted(
        &self,
        resolve: &mut impl FnMut(&str) -> Option<String>,
    ) -> Result<Self, String> {
        Ok(match self {
            Self::Command { command } => Self::Command {
                command: substitute(command, resolve)?,
            },
            Self::Resume {
                command,
                timeout_ms,
            } => Self::Resume {
                command: substitute(command, resolve)?,
                timeout_ms: *timeout_ms,
            },
            Self::RunTo {
                address,
                timeout_ms,
            } => Self::RunTo {
                address: substitute(address, resolve)?,
                timeout_ms: *timeout_ms,
            },
            Self::Eval { expr } => Self::Eval {
                expr: substitute(expr, resolve)?,
            },
            Self::ReadMemory { address, size } => Self::ReadMemory {
                address: substitute(address, resolve)?,
                size: *size,
            },
        })
    }
}

/// One assertion over a step's result.
///
/// `eval` is the general one: it evaluates two MASM expressions and compares them numerically, so
/// a register, a memory word, a symbol address and any relation between them are all one check —
/// `{"check": "eval", "expr": "(@rcx > 0x1000)", "equals": "1"}` asserts an inequality without
/// needing a check kind for it. The two text checks exist because verdicts and stop reasons arrive
/// as debugger prose, not as numbers.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum Check {
    /// The step's output must contain `text` (case-insensitive).
    Contains { text: String },
    /// The step's output must not contain `text` (case-insensitive).
    NotContains { text: String },
    /// `expr` and `equals` must evaluate to the same value. Both are MASM expressions, so
    /// `equals` may be a literal (`0x41414141`) or another expression (`nt!Foo`).
    Eval { expr: String, equals: String },
}

impl Check {
    fn substituted(
        &self,
        resolve: &mut impl FnMut(&str) -> Option<String>,
    ) -> Result<Self, String> {
        Ok(match self {
            Self::Contains { text } => Self::Contains {
                text: substitute(text, resolve)?,
            },
            Self::NotContains { text } => Self::NotContains {
                text: substitute(text, resolve)?,
            },
            Self::Eval { expr, equals } => Self::Eval {
                expr: substitute(expr, resolve)?,
                equals: substitute(equals, resolve)?,
            },
        })
    }
}

/// One step: an action, what must hold after it, and optionally a name for its value.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BatchStep {
    /// A label for the report. Defaults to the command the step runs.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(flatten)]
    pub action: StepAction,
    /// Assertions evaluated after the action succeeds. The first that does not hold fails the
    /// step — and so the batch.
    #[serde(default)]
    pub expect: Vec<Check>,
    /// Binds this step's value to a name later steps interpolate as `{{name}}`. Only an `eval`
    /// step has a value to bind.
    #[serde(default)]
    pub capture: Option<String>,
    /// Every key the step carried alongside the named fields above — the action's own included.
    ///
    /// Here so [`Self::unknown_fields`] can find the ones that belong to nothing. Serde ignores
    /// unknown fields by default, which is the wrong default for a step: a misspelt `expect` is a
    /// step that asserts nothing while reading as though it asserts, and it fails *open* — the
    /// batch commits. `deny_unknown_fields` cannot say so here, because serde makes that attribute
    /// and `flatten` mutually exclusive and `action` is flattened to keep a step one flat object.
    ///
    /// It collects the action's keys too, rather than only the leftovers: serde hands the same
    /// buffered content to every flattened field, so an internally tagged enum does not consume
    /// what it matched. Subtracting them is [`StepAction::owns`]'s job.
    ///
    /// **Never serialized.** This exists for one check at the supervisor's edge and has no business
    /// on the wire — and writing it there is not merely redundant, it is corrupting: flattening a
    /// map that already holds `op` and the action's fields emits each of them *twice*, and the
    /// worker rejects the duplicate key, discards the request, and answers nobody. That costs the
    /// caller the session, not the call (see [`crate::proto`]).
    #[serde(flatten, skip_serializing)]
    #[schemars(skip)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl BatchStep {
    /// The keys this step carried that nothing in the schema claims — a typo, in practice.
    fn unknown_fields(&self) -> Vec<&str> {
        self.extra
            .keys()
            .map(String::as_str)
            .filter(|key| !self.action.owns(key))
            .collect()
    }

    fn label(&self) -> String {
        match &self.name {
            Some(name) if !name.trim().is_empty() => name.clone(),
            _ => self.action.rendered(),
        }
    }
}

/// The op as it crosses to the worker: both blocks, the deadline the caller asked for, and the
/// deadline the caller's own patience allows.
///
/// `patience_ms` is filled in by the supervisor's pump, exactly as it is for
/// [`crate::proto::EngineOp::BoundedCommand`] — the value a caller constructs is ignored. It is
/// what keeps the reply ahead of the tool call's timeout, which is the only reason the rollback
/// report is worth anything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOp {
    pub steps: Vec<BatchStep>,
    pub always: Vec<BatchStep>,
    pub budget_ms: u32,
    pub patience_ms: u32,
}

// ---- capture references ---------------------------------------------------

/// Replaces every `{{name}}` in `text` with what `resolve` returns for it.
///
/// `{{` always opens a reference: no debugger command language in this server's vocabulary uses a
/// doubled brace, so there is nothing to escape and no ambiguity about whether a batch meant to
/// interpolate. A malformed or unresolvable reference is an error rather than a passthrough,
/// because the alternative is running `eb {{orig}} 41` against a target.
fn substitute(
    text: &str,
    resolve: &mut impl FnMut(&str) -> Option<String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            return Err(format!(
                "`{{{{` is never closed by `}}}}` in `{text}`; a capture reference is written \
                 `{{{{name}}}}`"
            ));
        };
        let name = &after[..close];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!(
                "`{{{{{name}}}}}` is not a capture name — letters, digits and `_` only"
            ));
        }
        let Some(value) = resolve(name) else {
            return Err(format!("`{{{{{name}}}}}` is not bound"));
        };
        out.push_str(&value);
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Whether `name` is usable as a capture name.
fn is_capture_name(name: &str) -> bool {
    !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ---- validation -----------------------------------------------------------

/// Checks a batch before any of it runs.
///
/// Everything here is decidable without a debugger, and all of it is worth deciding *first*: the
/// failure this rejects is a batch that applies three mutations and then trips over a typo in the
/// fourth step, which is the exact shape the rollback block exists to survive but which nobody
/// should have to survive.
///
/// The reference rule is the interesting part, and it is one rule for both blocks: a `{{name}}`
/// must be captured by an **earlier** step in execution order — `steps` then `always` — so a batch
/// cannot be written that could only work in a different order.
///
/// What that rule deliberately *permits* is the ordinary rollback: `always` runs after every step,
/// so a cleanup step may name a capture from anywhere in `steps`, including one the batch may never
/// reach. Whether it was actually bound is a runtime question, and [`run`] answers it by skipping
/// the step and saying which capture was missing. Refusing it here would reject "restore what step
/// 5 saved" on the grounds that step 5 *might* not run — which is precisely when the restore
/// matters.
pub fn validate(steps: &[BatchStep], always: &[BatchStep]) -> Result<(), String> {
    if steps.is_empty() {
        return Err("`steps` is empty; a batch needs at least one step".to_string());
    }
    for (block, name) in [(steps, "steps"), (always, "always")] {
        if block.len() > MAX_STEPS {
            return Err(format!(
                "`{name}` has {} steps; at most {MAX_STEPS} are allowed. A batch runs as one \
                 indivisible job on its session, so its length is also how long every other call \
                 to that session waits.",
                block.len()
            ));
        }
    }

    let mut bound: BTreeSet<String> = BTreeSet::new();
    for (block, block_name) in [(steps, "steps"), (always, "always")] {
        for (index, step) in block.iter().enumerate() {
            let where_ = format!("`{block_name}` step {}", index + 1);
            // First, because it is the check that catches a batch which *looks* right. Refused
            // rather than ignored: the dangerous typo here is silent and fails open — a misspelt
            // `expect` is a step that asserts nothing and lets the batch commit.
            let unknown = step.unknown_fields();
            if !unknown.is_empty() {
                return Err(format!(
                    "{where_} has field(s) this tool does not know: {}. A step takes `op` and that \
                     op's own fields, plus `name`, `expect` and `capture` — check the spelling.",
                    unknown.join(", ")
                ));
            }
            validate_operands(step, &where_)?;
            if step.expect.len() > MAX_CHECKS {
                return Err(format!(
                    "{where_} has {} checks; at most {MAX_CHECKS} are allowed",
                    step.expect.len()
                ));
            }
            // `bound` accumulates in execution order across both blocks, so it *is* "what an
            // earlier step bound" for either of them — no special case for `always`.
            let visible = &bound;
            let mut resolve = |name: &str| visible.contains(name).then(String::new);
            let unresolved = |e: String| {
                format!(
                    "{where_}: {e}. A step can only use a capture bound by an earlier step; the \
                     captures in scope here are {}.",
                    if visible.is_empty() {
                        "none".to_string()
                    } else {
                        visible
                            .iter()
                            .map(|n| format!("`{{{{{n}}}}}`"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                )
            };
            step.action.substituted(&mut resolve).map_err(&unresolved)?;
            for check in &step.expect {
                check.substituted(&mut resolve).map_err(&unresolved)?;
            }

            if let Some(capture) = &step.capture {
                if !is_capture_name(capture) {
                    return Err(format!(
                        "{where_}: `{capture}` is not a capture name — it must start with a \
                         letter or `_` and hold only letters, digits and `_`"
                    ));
                }
                if !matches!(step.action, StepAction::Eval { .. }) {
                    return Err(format!(
                        "{where_} captures `{capture}`, but only an `eval` step has a value to \
                         bind. Add an `eval` step for the value you want — `{{\"op\": \"eval\", \
                         \"expr\": \"@rcx\", \"capture\": \"{capture}\"}}` — and interpolate it \
                         as `{{{{{capture}}}}}`."
                    ));
                }
                if !bound.insert(capture.clone()) {
                    return Err(format!(
                        "{where_} captures `{capture}`, which an earlier step already bound. A \
                         capture names one value for the whole batch."
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Refuses an operand that could end the command this batch builds around it.
///
/// The same reasoning as [`reject_command_breakers`] in the typed tools, applied to the two step
/// fields that are interpolated into a command rather than *being* one: a `;` in an `eval`
/// expression turns `? <expr>` into a command list. Raw `command`/`resume` steps are exempt for
/// the same reason `execute` is — chaining is what they are for — and are scanned for
/// target-changing commands instead ([`retires_handle`]).
///
/// Interpolation cannot re-open this hole: a capture is bound to a `0x`-prefixed number, so no
/// value a batch can produce carries a separator.
fn validate_operands(step: &BatchStep, where_: &str) -> Result<(), String> {
    let operand = |field: &str, value: &str| {
        reject_command_breakers(field, value, Quotes::Rejected)
            .map_err(|e| format!("{where_}: {e}"))
    };
    match &step.action {
        StepAction::RunTo { address, .. } | StepAction::ReadMemory { address, .. } => {
            operand("address", address)?;
        }
        StepAction::Eval { expr } => operand("expr", expr)?,
        StepAction::Command { .. } | StepAction::Resume { .. } => {}
    }
    for check in &step.expect {
        if let Check::Eval { expr, equals } = check {
            operand("expr", expr)?;
            operand("equals", equals)?;
        }
    }
    Ok(())
}

/// Whether any command in this batch replaces or releases the debug target, and so must retire the
/// session handle before the batch runs.
///
/// Read on the supervisor side, over the batch as written: interpolation only ever substitutes
/// numbers, so a command that looks harmless here cannot become a `.detach` by the time it runs.
pub fn retires_handle(steps: &[BatchStep], always: &[BatchStep]) -> bool {
    steps.iter().chain(always).any(|step| match &step.action {
        StepAction::Command { command } | StepAction::Resume { command, .. } => {
            changes_debug_target(command)
        }
        _ => false,
    })
}

// ---- what a step changed --------------------------------------------------

/// Commands that write target memory. Session-control commands are deliberately absent:
/// [`mutation`] asks [`changes_debug_target`] for those first, so `.detach` is not looked for here.
const MEMORY_WRITES: &[&str] = &[
    "e", "ea", "eb", "ed", "ef", "ep", "eq", "eu", "ew", "ez", "eza", "ezu", "f", "fp", "m",
    ".readmem", ".fillmem",
];
const BREAKPOINTS: &[&str] = &[
    "ba", "bc", "bd", "be", "bm", "bp", "br", "bs", "bsc", "bu", "sxd", "sxe", "sxi", "sxn",
];
const EXECUTION: &[&str] = &[
    "g", "gc", "gh", "gn", "gu", "p", "pa", "pc", "pt", "t", "ta", "tb", "tc", "tt", "wt", "-g",
    "-p", "-t",
];
const ENGINE: &[&str] = &[
    ".load",
    ".loadby",
    ".unload",
    ".unloadall",
    ".reload",
    ".sympath",
    ".sympath+",
    ".symfix",
    ".symfix+",
    ".srcpath",
    ".srcpath+",
    ".exepath",
];

/// What a raw command changes, as far as a first-token match can tell.
///
/// **Best-effort, and biased toward reporting a change.** DbgEng has more ways to touch a target
/// than a name list can enumerate, and the two errors are not symmetric: an over-report costs one
/// line of text in a report, while a missed one leaves a mutation the reader does not know to undo.
/// This is a reporting aid — it decides nothing about what runs — and the `always` block, not this
/// list, is what actually makes a mutation recoverable.
pub fn mutation(command: &str) -> Option<String> {
    let mut kinds: Vec<&'static str> = Vec::new();
    for segment in command.split([';', '\n', '\r']) {
        let Some(first) = segment.split_whitespace().next() else {
            continue;
        };
        let token = first.to_ascii_lowercase();
        let kind = if changes_debug_target(segment) {
            "the debug target"
        } else if MEMORY_WRITES.contains(&token.as_str()) {
            "memory"
        } else if token == "r" && segment.contains('=') {
            "registers"
        } else if BREAKPOINTS.contains(&token.as_str()) {
            "breakpoints"
        } else if EXECUTION.contains(&token.as_str()) {
            "execution"
        } else if ENGINE.contains(&token.as_str()) {
            "engine settings"
        } else {
            continue;
        };
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    (!kinds.is_empty()).then(|| kinds.join(" + "))
}

/// What an action changes, for the report.
fn action_mutation(action: &StepAction) -> Option<String> {
    match action {
        StepAction::Command { command } => mutation(command),
        // A resume moves the target by definition, whatever else its command does.
        StepAction::Resume { command, .. } => Some(match mutation(command) {
            Some(more) if more != "execution" => more,
            _ => "execution".to_string(),
        }),
        StepAction::RunTo { .. } => Some("execution".to_string()),
        StepAction::Eval { .. } | StepAction::ReadMemory { .. } => None,
    }
}

// ---- the engine seam ------------------------------------------------------

/// What [`run`] needs from a debugger. Implemented over a real engine by the worker, and over a
/// script by the tests — see the module docs for why that seam is where it is.
pub trait Debuggee {
    /// Run a command to completion, self-aborting after `budget_ms`.
    fn command(&mut self, command: &str, budget_ms: u32) -> Result<String, String>;
    /// Run a command that moves the target, waiting up to `timeout_ms` for the next stop.
    fn resume(&mut self, command: &str, timeout_ms: u32) -> Result<String, String>;
    /// Run to `address` and report a verdict.
    fn run_to(&mut self, address: &str, timeout_ms: u32) -> Result<String, String>;
    /// Hex-dump `size` bytes at `address`.
    fn read_memory(&mut self, address: &str, size: u32) -> Result<String, String>;
    /// How long this batch has been running.
    fn elapsed(&self) -> Duration;
    /// Whether something outside the batch has asked it to stop early and roll back — a client
    /// disconnect, or an `end_session` for the session it is running on.
    ///
    /// Read between steps, never mid-step: this cannot reach a call already inside DbgEng, and
    /// pretending otherwise would be a promise the mechanism cannot keep. What it *is* is the
    /// difference between a rollback that runs and a worker terminated with the patch still
    /// applied, because the teardown that sets it then waits out the step in flight and the
    /// `always` block after it — the batch's whole remaining budget, which is why nothing here
    /// has to be shortened to fit a teardown.
    fn abandoned(&self) -> bool;
}

/// Runs one engine call, turning a panic into a step failure so [`run`] still reaches `always`.
///
/// Needed because the only other guard is `worker::engine_thread`'s, which wraps a whole op — an
/// unwind from a step would pass straight through the rollback. Not hypothetical: several win-kexp
/// methods use `.expect`, and a step calls into them.
fn guarded(call: impl FnOnce() -> Result<String, String>) -> Result<String, String> {
    catch_unwind(AssertUnwindSafe(call)).unwrap_or_else(|payload| {
        // The message, when the payload carries one. A bare "panicked" would tell a caller that
        // their transaction stopped without telling them what stopped it, and this is a report
        // whose whole job is to say which step and why.
        let why = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned());
        match why {
            Some(why) => Err(format!("the debugger operation panicked: {why}")),
            None => Err("the debugger operation panicked".to_string()),
        }
    })
}

// ---- results --------------------------------------------------------------

/// How one step ended.
#[derive(Debug, Clone, PartialEq)]
pub enum StepResult {
    Ok,
    /// The debugger refused the operation.
    Failed(String),
    /// The action succeeded and an assertion did not hold.
    Unmet(String),
    /// Never attempted, and why.
    Skipped(String),
}

impl StepResult {
    fn tag(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Failed(_) => "FAILED",
            Self::Unmet(_) => "UNMET",
            Self::Skipped(_) => "SKIPPED",
        }
    }

    fn detail(&self) -> Option<&str> {
        match self {
            Self::Ok => None,
            Self::Failed(why) | Self::Unmet(why) | Self::Skipped(why) => Some(why),
        }
    }
}

/// One step, as the report tells it.
#[derive(Debug, Clone)]
pub struct StepOutcome {
    /// 1-based position within its block.
    pub position: usize,
    pub label: String,
    /// The action after interpolation — what actually ran, not what was written.
    pub rendered: String,
    /// What this step changed, if [`mutation`] recognised anything. Recorded whether or not the
    /// step then succeeded: a command that errors may already have written.
    pub changes: Option<String>,
    pub result: StepResult,
    pub output: String,
}

impl StepOutcome {
    fn skipped(position: usize, step: &BatchStep, why: impl Into<String>) -> Self {
        Self {
            position,
            label: step.label(),
            rendered: step.action.rendered(),
            changes: None,
            result: StepResult::Skipped(why.into()),
            output: String::new(),
        }
    }

    fn ok(&self) -> bool {
        self.result == StepResult::Ok
    }
}

/// How the batch as a whole ended.
#[derive(Debug, Clone, PartialEq)]
pub enum BatchOutcome {
    /// Every step ran and every assertion held.
    Committed,
    /// A step failed; `at` is its 1-based position.
    Failed { at: usize },
    /// The deadline expired; `at` is the 1-based position of the first step not attempted.
    TimedOut { at: usize },
    /// The session is being torn down — the client disconnected, or someone ended it — so the
    /// batch stopped and went to its rollback. `at` is the 1-based position of the first step not
    /// attempted.
    ///
    /// Its own outcome rather than a timeout, because nothing about the target or the budget was
    /// wrong: the steps that did not run were not *refused*, they were cut short by something the
    /// batch has no quarrel with. Resubmitting from the top is the right next move, which is not
    /// what a caller should conclude from either of the other two.
    Abandoned { at: usize },
}

/// What the session holds once the batch is done — the question a caller cannot answer from the
/// step list alone, and the one that decides whether their next call is safe.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionAfter {
    /// The engine answered with a current instruction pointer.
    Stopped { ip: String },
    /// The target was told to run and never reported a stop, and the probe found no stopped
    /// context either.
    Running { why: String },
    /// A step released or replaced the target.
    Detached { by: String },
    /// The probe failed and nothing in the batch explains it.
    Uncertain { why: String },
}

#[derive(Debug, Clone)]
pub struct BatchReport {
    pub steps: Vec<StepOutcome>,
    pub always: Vec<StepOutcome>,
    pub outcome: BatchOutcome,
    pub after: SessionAfter,
    /// Total budget the worker was given, for the report's header.
    pub budget: Duration,
    pub elapsed: Duration,
}

impl BatchReport {
    pub fn committed(&self) -> bool {
        self.outcome == BatchOutcome::Committed
    }

    /// Whether every `always` step completed. A rollback that did not is the thing a caller most
    /// needs to see, so it gets its own predicate rather than being inferred from the list.
    pub fn rollback_complete(&self) -> bool {
        self.always.iter().all(StepOutcome::ok)
    }

    fn mutations(&self) -> Vec<&StepOutcome> {
        self.steps
            .iter()
            .chain(&self.always)
            .filter(|s| s.changes.is_some() && !matches!(s.result, StepResult::Skipped(_)))
            .collect()
    }
}

// ---- execution ------------------------------------------------------------

/// Runs a batch to completion and reports what happened.
///
/// Never returns early and never propagates: every path — including an expired deadline — falls
/// through to the `always` block and then to the state probe, because the report is the product
/// here and a half-written one is the failure mode this tool exists to remove.
pub fn run(d: &mut impl Debuggee, op: &BatchOp, budget: Duration) -> BatchReport {
    // Reserved before a single step runs. Taken from what is left afterwards it would routinely
    // be nothing, which is exactly the case the rollback is for.
    let reserve = ROLLBACK_RESERVE.min(budget / 2);
    let steps_deadline = budget.saturating_sub(reserve);

    let mut bound: BTreeMap<String, String> = BTreeMap::new();
    let mut steps: Vec<StepOutcome> = Vec::with_capacity(op.steps.len());
    let mut outcome = BatchOutcome::Committed;

    for (index, step) in op.steps.iter().enumerate() {
        let position = index + 1;
        // The reason matters: "an earlier step failed" and "the clock ran out" call for opposite
        // next moves, and a step skipped after a timeout would otherwise be told the wrong one.
        match &outcome {
            BatchOutcome::Committed => {}
            BatchOutcome::Failed { at } => {
                steps.push(StepOutcome::skipped(
                    position,
                    step,
                    format!("step {at} failed, so the batch stopped there"),
                ));
                continue;
            }
            BatchOutcome::TimedOut { at } => {
                steps.push(StepOutcome::skipped(
                    position,
                    step,
                    format!("the batch ran out of time at step {at}"),
                ));
                continue;
            }
            BatchOutcome::Abandoned { at } => {
                steps.push(StepOutcome::skipped(
                    position,
                    step,
                    format!(
                        "the session was torn down while the batch was running, so it stopped at \
                         step {at} and went to its rollback"
                    ),
                ));
                continue;
            }
        }
        // Before the deadline check, because the two are not the same news and this one is the
        // more urgent: something is tearing this session down and the rollback is what is left
        // worth doing. Between steps only — a step already inside DbgEng runs to its own end.
        if d.abandoned() {
            outcome = BatchOutcome::Abandoned { at: position };
            steps.push(StepOutcome::skipped(
                position,
                step,
                "the session was torn down before this step started",
            ));
            continue;
        }
        if d.elapsed() >= steps_deadline {
            outcome = BatchOutcome::TimedOut { at: position };
            steps.push(StepOutcome::skipped(
                position,
                step,
                "the batch ran out of time before this step started",
            ));
            continue;
        }
        let done = run_step(d, step, position, steps_deadline, &mut bound);
        if !done.ok() {
            outcome = match &done.result {
                // An assertion that did not hold is a verdict about the target, and stays one
                // however long the step took to reach it.
                StepResult::Unmet(_) => BatchOutcome::Failed { at: position },
                // A step that ran out of its own budget is a timeout, not a plain failure: the
                // advice differs (raise `timeout_ms` or narrow the batch, versus fix the step).
                _ if d.elapsed() >= steps_deadline => BatchOutcome::TimedOut { at: position },
                _ => BatchOutcome::Failed { at: position },
            };
        }
        steps.push(done);
    }

    // The rollback block, on every path. Its own deadline is the *whole* budget, which is what the
    // reserve above bought it — and that holds when the batch is abandoned too, rather than the
    // rollback being cut short to fit a teardown's grace. The grace is sized from this budget
    // instead (`worker::BatchSignal::abandon`), so shortening the block here would only mean
    // skipping cleanup the teardown was already waiting for.
    let mut always: Vec<StepOutcome> = Vec::with_capacity(op.always.len());
    for (index, step) in op.always.iter().enumerate() {
        let position = index + 1;
        if d.elapsed() >= budget {
            always.push(StepOutcome::skipped(
                position,
                step,
                "the batch ran out of time before this cleanup step started",
            ));
            continue;
        }
        // Cleanup continues past its own failures, deliberately: the steps are ordered, but a
        // patch that cannot be restored must not stop a breakpoint from being cleared.
        always.push(run_step(d, step, position, budget, &mut bound));
    }

    let after = probe_state(d, &steps, &always, budget);
    BatchReport {
        steps,
        always,
        outcome,
        after,
        budget,
        elapsed: d.elapsed(),
    }
}

/// The watchdog for a step, given the deadline it must finish inside.
fn step_budget_ms(elapsed: Duration, deadline: Duration) -> u32 {
    deadline
        .saturating_sub(elapsed)
        .as_millis()
        .min(u32::MAX as u128) as u32
}

fn run_step(
    d: &mut impl Debuggee,
    step: &BatchStep,
    position: usize,
    deadline: Duration,
    bound: &mut BTreeMap<String, String>,
) -> StepOutcome {
    let budget_ms = step_budget_ms(d.elapsed(), deadline).max(MIN_STEP_BUDGET_MS);
    let mut resolve = |name: &str| bound.get(name).cloned();

    // Resolved before anything runs, so an unbound reference costs nothing. In `always` this is
    // the ordinary case, not an error in the batch: the step that would have bound it never ran.
    let action = match step.action.substituted(&mut resolve) {
        Ok(action) => action,
        Err(why) => return StepOutcome::skipped(position, step, why),
    };
    let checks: Result<Vec<Check>, String> = step
        .expect
        .iter()
        .map(|check| check.substituted(&mut resolve))
        .collect();
    let checks = match checks {
        Ok(checks) => checks,
        Err(why) => return StepOutcome::skipped(position, step, why),
    };

    let rendered = action.rendered();
    let changes = action_mutation(&action);
    let wait_ms = |requested: Option<u32>| {
        requested
            .unwrap_or(EXEC_WAIT_MS)
            .min(budget_ms)
            .max(MIN_STEP_BUDGET_MS)
    };
    let ran = guarded(|| match &action {
        StepAction::Command { command } => d.command(command, budget_ms),
        StepAction::Resume {
            command,
            timeout_ms,
        } => d.resume(command, wait_ms(*timeout_ms)),
        StepAction::RunTo {
            address,
            timeout_ms,
        } => d.run_to(address, wait_ms(*timeout_ms)),
        StepAction::Eval { expr } => d.command(&format!("? {expr}"), budget_ms),
        StepAction::ReadMemory { address, size } => d.read_memory(address, *size),
    });

    let output = match ran {
        Ok(output) => output,
        Err(why) => {
            return StepOutcome {
                position,
                label: step.label(),
                rendered,
                changes,
                result: StepResult::Failed(why),
                output: String::new(),
            };
        }
    };

    let mut result = StepResult::Ok;
    for check in &checks {
        // Re-read the clock between checks, not once for the step. An `eval` check is two engine
        // queries, and a step may carry several — arming each of them with the budget computed
        // before the *first* one would let a step's assertions run for a multiple of the time the
        // step was given, and eat the reserve the rollback depends on.
        if d.elapsed() >= deadline {
            result = StepResult::Failed(
                "the batch ran out of time before this step's assertions could be checked"
                    .to_string(),
            );
            break;
        }
        match evaluate(d, check, &output, deadline) {
            Ok(()) => {}
            Err(CheckFailed::Unmet(why)) => {
                result = StepResult::Unmet(why);
                break;
            }
            // Not `Unmet`: nothing was learned about the target, so calling it a failed
            // assertion would report a verdict the batch never reached.
            Err(CheckFailed::Expired(why)) => {
                result = StepResult::Failed(why);
                break;
            }
        }
    }

    // The capture binds only on a step that fully succeeded: a value read from a step whose
    // assertions did not hold is a value about a state the batch has already rejected.
    if result == StepResult::Ok
        && let Some(capture) = &step.capture
    {
        match parse_eval(&output) {
            Some(value) => {
                bound.insert(capture.clone(), format!("{value:#x}"));
            }
            None => {
                result = StepResult::Failed(format!(
                    "`{rendered}` printed no value to capture as `{capture}`. The debugger \
                     answered:\n{}",
                    output.trim()
                ));
            }
        }
    }

    // Clipped **here**, not at render time, and the difference is memory rather than presentation.
    // The full text has done its work by now — the assertions read it and the capture parsed it —
    // and a step that keeps it holds it until the whole batch ends. A `read_memory` step may
    // return a megabyte of target memory as some five megabytes of hexdump, and a batch may carry
    // sixty-four steps, so keeping every one whole would let a valid batch exhaust the worker and
    // cost its session — walking straight past the read-size guard that exists to prevent exactly
    // that.
    //
    // Clipping once, against the cap this step will actually be shown at, also keeps the dropped
    // count honest: a second clip in the renderer would count from the first one's remainder and
    // report a fraction of what was really left out.
    let cap = report_cap(&result);
    StepOutcome {
        position,
        label: step.label(),
        rendered,
        changes,
        result,
        output: clip(&output, cap),
    }
}

/// How much of a step's output survives into the report. The step that did not succeed is the one
/// the caller has to act on, so it gets the larger share; the rest are context.
fn report_cap(result: &StepResult) -> usize {
    if matches!(result, StepResult::Ok) {
        STEP_OUTPUT_CHARS
    } else {
        FAILED_OUTPUT_CHARS
    }
}

/// Why an assertion did not hold, which is not one thing.
///
/// An assertion that was *checked and failed* is a verdict about the target; one that never got
/// checked because the clock ran out is a verdict about the batch. They read the same in a report
/// unless they are kept apart here, and they call for opposite next moves — fix the target, or
/// give the batch more room.
enum CheckFailed {
    Unmet(String),
    Expired(String),
}

/// One side of an [`Check::Eval`] comparison: what the debugger makes of a MASM expression.
///
/// Takes the *deadline* rather than a budget and re-reads the clock itself, because a check is two
/// of these and the second must be told what the first one left. It refuses outright rather than
/// falling back on [`MIN_STEP_BUDGET_MS`] when nothing is left: that floor exists so a query which
/// *has* to run is never armed with a disabled watchdog, and using it to start a query that did
/// not have to run would spend the rollback's reserve on an assertion.
fn eval_value(d: &mut impl Debuggee, expr: &str, deadline: Duration) -> Result<u64, CheckFailed> {
    if d.elapsed() >= deadline {
        return Err(CheckFailed::Expired(format!(
            "the batch ran out of time before `? ({expr})` could be evaluated"
        )));
    }
    let budget_ms = step_budget_ms(d.elapsed(), deadline).max(MIN_STEP_BUDGET_MS);
    // Parenthesized, so a relational expression (`@rcx > 0x1000`) is evaluated as one value
    // rather than losing its precedence against whatever `?` does with the rest of the line.
    let text = guarded(|| d.command(&format!("? ({expr})"), budget_ms))
        .map_err(|why| CheckFailed::Unmet(format!("`? ({expr})` failed: {why}")))?;
    parse_eval(&text).ok_or_else(|| {
        CheckFailed::Unmet(format!(
            "`? ({expr})` printed no value; the debugger answered: {}",
            text.trim()
        ))
    })
}

/// Evaluates one assertion, `Ok(())` when it holds.
fn evaluate(
    d: &mut impl Debuggee,
    check: &Check,
    output: &str,
    deadline: Duration,
) -> Result<(), CheckFailed> {
    match check {
        Check::Contains { text } => {
            // Case-insensitive: debugger output mixes symbol casing freely, and a check that
            // fails on `Verdict` versus `VERDICT` would be a trap rather than an assertion.
            if output
                .to_ascii_lowercase()
                .contains(&text.to_ascii_lowercase())
            {
                Ok(())
            } else {
                Err(CheckFailed::Unmet(format!(
                    "the output does not contain \"{text}\""
                )))
            }
        }
        Check::NotContains { text } => {
            if output
                .to_ascii_lowercase()
                .contains(&text.to_ascii_lowercase())
            {
                Err(CheckFailed::Unmet(format!(
                    "the output contains \"{text}\", which it must not"
                )))
            } else {
                Ok(())
            }
        }
        Check::Eval { expr, equals } => {
            let left = eval_value(d, expr, deadline)?;
            let right = eval_value(d, equals, deadline)?;
            if left == right {
                Ok(())
            } else {
                Err(CheckFailed::Unmet(format!(
                    "`{expr}` is {} ({left:#x}), `{equals}` is {} ({right:#x})",
                    fmt_addr(left),
                    fmt_addr(right)
                )))
            }
        }
    }
}

/// Asks what the session holds now.
///
/// The probe is one expression, `? @$ip`, and it is read conservatively. An answer means the
/// engine has a stopped thread context, which is the only claim made. A refusal is *not* read as
/// "detached" — that verdict is drawn from what the batch itself ran, because a probe cannot tell
/// a released target apart from one that is merely running, and turning "could not read" into
/// "detached" would be a verdict this code has not earned.
fn probe_state(
    d: &mut impl Debuggee,
    steps: &[StepOutcome],
    always: &[StepOutcome],
    budget: Duration,
) -> SessionAfter {
    let released = steps
        .iter()
        .chain(always)
        .filter(|s| !matches!(s.result, StepResult::Skipped(_)))
        .find(|s| {
            s.changes
                .as_deref()
                .is_some_and(|c| c.contains("the debug target"))
        });
    if let Some(step) = released {
        return SessionAfter::Detached {
            by: format!("`{}`", step.rendered),
        };
    }

    // Told to run and never reported a stop: the target may still be running, and the probe below
    // cannot distinguish that from a target that is gone.
    let ran_on = steps.iter().chain(always).any(|s| {
        s.changes
            .as_deref()
            .is_some_and(|c| c.contains("execution"))
            && !s.ok()
    });

    let budget_ms = step_budget_ms(d.elapsed(), budget).max(MIN_STEP_BUDGET_MS);
    match guarded(|| d.command("? @$ip", budget_ms)) {
        Ok(text) => match parse_eval(&text) {
            Some(ip) => SessionAfter::Stopped { ip: fmt_addr(ip) },
            None => SessionAfter::Uncertain {
                why: format!(
                    "`? @$ip` printed no address; the debugger answered: {}",
                    text.trim()
                ),
            },
        },
        Err(why) if ran_on => SessionAfter::Running {
            why: format!(
                "a step resumed the target and did not report a stop, and `? @$ip` failed: {why}"
            ),
        },
        Err(why) => SessionAfter::Uncertain {
            why: format!("`? @$ip` failed: {why}"),
        },
    }
}

// ---- rendering ------------------------------------------------------------

/// Truncates `text` to `limit` characters, saying how much it dropped.
fn clip(text: &str, limit: usize) -> String {
    let text = text.trim_end();
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let kept: String = text.chars().take(limit).collect();
    let dropped = text.chars().count() - limit;
    format!("{kept}\n… {dropped} more characters not shown")
}

fn indent(text: &str, prefix: &str) -> String {
    text.lines()
        .map(|line| format!("{prefix}{line}\n"))
        .collect()
}

/// Renders one block of steps.
fn render_block(out: &mut String, title: &str, block: &[StepOutcome]) {
    if block.is_empty() {
        return;
    }
    let _ = writeln!(out, "\n---- {title} ----");
    for step in block {
        let changes = match &step.changes {
            Some(changes) => format!("   [changes {changes}]"),
            None => String::new(),
        };
        // An unlabelled step's label *is* its command, so printing both would say it twice.
        let _ = if step.label == step.rendered {
            writeln!(
                out,
                "{:>3}. {:<8} `{}`{changes}",
                step.position,
                step.result.tag(),
                step.rendered
            )
        } else {
            writeln!(
                out,
                "{:>3}. {:<8} {}\n     `{}`{changes}",
                step.position,
                step.result.tag(),
                step.label,
                step.rendered
            )
        };
        if let Some(detail) = step.result.detail() {
            out.push_str(&indent(detail, "     ! "));
        }
        // Already clipped to this step's cap when the outcome was built, so that the text was not
        // carried whole for the life of the batch — see `run_step`.
        if !step.output.trim().is_empty() {
            out.push_str(&indent(&step.output, "     | "));
        }
    }
}

/// Renders the report as the tool's text output.
pub fn render(report: &BatchReport) -> String {
    let total = report.steps.len();
    let mut out = match &report.outcome {
        BatchOutcome::Committed => format!("BATCH: COMMITTED — all {total} step(s) ran\n"),
        BatchOutcome::Failed { at } => format!("BATCH: FAILED at step {at} of {total}\n"),
        BatchOutcome::TimedOut { at } => format!(
            "BATCH: TIMED OUT at step {at} of {total} — the batch was given {:.0}s and used \
             {:.0}s\n",
            report.budget.as_secs_f64(),
            report.elapsed.as_secs_f64()
        ),
        BatchOutcome::Abandoned { at } => format!(
            "BATCH: ABANDONED at step {at} of {total} — the session was being torn down (the \
             client disconnected, or the session was ended), so the batch stopped there and ran \
             its rollback. Nothing was wrong with the steps or the budget; resubmit the whole \
             batch on a fresh session.\n"
        ),
    };

    let mutations = report.mutations();
    if mutations.is_empty() {
        out.push_str("mutations: none recognised\n");
    } else {
        let _ = writeln!(
            out,
            "mutations: {} step(s) changed state —",
            mutations.len()
        );
        for step in mutations {
            let _ = writeln!(
                out,
                "  {} `{}` [{}]{}",
                step.label,
                step.rendered,
                step.changes.as_deref().unwrap_or(""),
                if step.ok() {
                    ""
                } else {
                    " (the step did not succeed; it may still have changed something)"
                }
            );
        }
    }

    if report.always.is_empty() {
        out.push_str(
            "rollback: no `always` block was supplied, so nothing was undone. Anything listed \
             above is still in place.\n",
        );
    } else if report.rollback_complete() {
        let _ = writeln!(
            out,
            "rollback: COMPLETE — all {} `always` step(s) ran",
            report.always.len()
        );
    } else {
        let stuck = report.always.iter().filter(|s| !s.ok()).count();
        let _ = writeln!(
            out,
            "rollback: INCOMPLETE — {stuck} of {} `always` step(s) did not complete. See the \
             `always` block below; this is reported beside the batch's own outcome, not instead \
             of it.",
            report.always.len()
        );
    }

    let _ = writeln!(
        out,
        "session after: {}",
        match &report.after {
            SessionAfter::Stopped { ip } => format!("STOPPED at {ip}"),
            SessionAfter::Running { why } => format!("RUNNING (or gone) — {why}"),
            SessionAfter::Detached { by } =>
                format!("DETACHED/REPLACED by {by}; this session's handle is retired"),
            SessionAfter::Uncertain { why } => format!("UNCERTAIN — {why}"),
        }
    );

    render_block(&mut out, "steps", &report.steps);
    render_block(&mut out, "always (rollback)", &report.always);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- a scripted debuggee ----------------------------------------------

    /// One scripted answer: what the fake returns, and how long the call "takes".
    struct Answer {
        result: Result<String, String>,
        costs: Duration,
    }

    /// A [`Debuggee`] that answers from a script and carries a virtual clock.
    ///
    /// The clock is the point. Deadline expiry is otherwise only reproducible by waiting, and a
    /// test that waits out a 30s reserve is a test nobody runs — so time advances by whatever the
    /// scripted answer says its call cost, and the executor's arithmetic is exercised exactly as
    /// it would be against a slow target.
    #[derive(Default)]
    struct Script {
        answers: Vec<(String, Answer)>,
        calls: Vec<String>,
        clock: Duration,
        /// Call fragments this script panics on rather than answers; see [`Script::panics`].
        panic_on: Vec<String>,
        /// How many calls this debuggee answers before it starts reporting itself abandoned; see
        /// [`Script::abandoned_after`].
        abandon_after: Option<usize>,
    }

    /// The message a scripted panic carries, so the report can be asserted to have kept it.
    const PANIC: &str = "called `Option::unwrap()` on a `None` value";

    impl Script {
        fn new() -> Self {
            Self::default()
        }

        /// Answers any call whose text contains `matching`.
        fn on(mut self, matching: &str, result: Result<&str, &str>) -> Self {
            self.answers.push((
                matching.to_string(),
                Answer {
                    result: result.map(str::to_string).map_err(str::to_string),
                    costs: Duration::ZERO,
                },
            ));
            self
        }

        /// Answers any call containing `matching` by panicking, the way several win-kexp methods
        /// do (`.expect`).
        fn panics(mut self, matching: &str) -> Self {
            // Not an `answers` entry: the panic fires before the lookup, so one would only be
            // there to look like an answer that is never given.
            self.panic_on.push(matching.to_string());
            self
        }

        /// Reports the batch abandoned once `calls` calls have been answered — the scripted stand-in
        /// for a teardown arriving mid-transaction, which is otherwise only reproducible by
        /// disconnecting a client from a real worker.
        fn abandoned_after(mut self, calls: usize) -> Self {
            self.abandon_after = Some(calls);
            self
        }

        /// As [`Self::on`], and the call advances the clock by `costs`.
        fn slow(mut self, matching: &str, result: Result<&str, &str>, costs: Duration) -> Self {
            self.answers.push((
                matching.to_string(),
                Answer {
                    result: result.map(str::to_string).map_err(str::to_string),
                    costs,
                },
            ));
            self
        }

        fn answer(&mut self, call: &str) -> Result<String, String> {
            self.calls.push(call.to_string());
            if self.panic_on.iter().any(|m| call.contains(m.as_str())) {
                panic!("{PANIC}");
            }
            let found = self
                .answers
                .iter()
                .find(|(matching, _)| call.contains(matching.as_str()));
            match found {
                Some((_, answer)) => {
                    let (result, costs) = (answer.result.clone(), answer.costs);
                    self.clock += costs;
                    result
                }
                // An unscripted call is a test bug, and a silent empty answer would hide it.
                None => panic!(
                    "the script has no answer for `{call}`; calls so far: {:?}",
                    self.calls
                ),
            }
        }

        fn ran(&self, matching: &str) -> bool {
            self.calls.iter().any(|c| c.contains(matching))
        }
    }

    impl Debuggee for Script {
        fn command(&mut self, command: &str, _budget_ms: u32) -> Result<String, String> {
            self.answer(command)
        }
        fn resume(&mut self, command: &str, _timeout_ms: u32) -> Result<String, String> {
            self.answer(command)
        }
        fn run_to(&mut self, address: &str, _timeout_ms: u32) -> Result<String, String> {
            self.answer(&format!("run to {address}"))
        }
        fn read_memory(&mut self, address: &str, size: u32) -> Result<String, String> {
            self.answer(&format!("read {size} at {address}"))
        }
        fn elapsed(&self) -> Duration {
            self.clock
        }
        fn abandoned(&self) -> bool {
            self.abandon_after
                .is_some_and(|after| self.calls.len() >= after)
        }
    }

    /// `? @$ip` answers, so every batch below can reach the state probe.
    fn stopped() -> Script {
        Script::new().on("? @$ip", Ok("Evaluate expression: 1 = fffff803`1a2b3c4d"))
    }

    fn step(action: StepAction) -> BatchStep {
        BatchStep {
            name: None,
            action,
            expect: Vec::new(),
            capture: None,
            extra: BTreeMap::new(),
        }
    }

    fn cmd(command: &str) -> BatchStep {
        step(StepAction::Command {
            command: command.to_string(),
        })
    }

    fn op(steps: Vec<BatchStep>, always: Vec<BatchStep>) -> BatchOp {
        BatchOp {
            steps,
            always,
            budget_ms: 60_000,
            patience_ms: 60_000,
        }
    }

    const BUDGET: Duration = Duration::from_secs(60);

    /// What `? (…)` prints for a value of 1.
    const EVAL_ONE: &str = "Evaluate expression: 1 = 00000000`00000001";

    // ---- the four paths the issue asks for --------------------------------

    /// An assertion that does not hold stops the batch *and* runs the rollback — the case a
    /// client-side loop gets right only when it is still there to notice.
    #[test]
    fn an_unmet_assertion_stops_the_batch_and_still_rolls_back() {
        let mut d = stopped()
            .on("eb fffff800", Ok(""))
            .on(
                "run to ",
                Ok("VERDICT: TIMEOUT — did not reach fffff803`00001000\n"),
            )
            .on("never", Ok(""))
            .on("eb restore", Ok(""));
        let batch = op(
            vec![
                cmd("eb fffff800`00001000 90"),
                BatchStep {
                    expect: vec![Check::Contains {
                        text: "VERDICT: HIT".to_string(),
                    }],
                    ..step(StepAction::RunTo {
                        address: "fffff803`00001000".to_string(),
                        timeout_ms: None,
                    })
                },
                cmd("never runs"),
            ],
            vec![cmd("eb restore 41")],
        );

        let report = run(&mut d, &batch, BUDGET);

        assert_eq!(report.outcome, BatchOutcome::Failed { at: 2 });
        assert!(matches!(report.steps[1].result, StepResult::Unmet(_)));
        assert!(matches!(report.steps[2].result, StepResult::Skipped(_)));
        assert!(!d.ran("never"), "a step after the failure must not run");
        assert!(d.ran("eb restore"), "the rollback must run");
        assert!(report.rollback_complete());

        let text = render(&report);
        assert!(text.contains("BATCH: FAILED at step 2 of 3"), "{text}");
        assert!(text.contains("VERDICT: HIT"), "{text}");
        assert!(text.contains("rollback: COMPLETE"), "{text}");
    }

    /// A command that fails *after* a mutation: the mutation is reported even though the batch
    /// did not commit, because it happened.
    #[test]
    fn a_command_failure_after_a_mutation_reports_both() {
        let mut d = stopped()
            .on("bp nt!NtCreateFile", Ok("breakpoint 0 set"))
            .on(
                "eb fffff800",
                Err("Memory access error at 'fffff800`00001000'"),
            )
            .on("bc *", Ok(""));
        let batch = op(
            vec![cmd("bp nt!NtCreateFile"), cmd("eb fffff800`00001000 90")],
            vec![cmd("bc *")],
        );

        let report = run(&mut d, &batch, BUDGET);

        assert_eq!(report.outcome, BatchOutcome::Failed { at: 2 });
        let text = render(&report);
        // The breakpoint landed and must be listed as a mutation, and the failed write must be
        // listed too — a write that errored may still have written.
        assert!(text.contains("[breakpoints]"), "{text}");
        assert!(text.contains("[memory]"), "{text}");
        assert!(
            text.contains("it may still have changed something"),
            "{text}"
        );
        assert!(text.contains("Memory access error"), "{text}");
    }

    /// The deadline expires mid-batch: the remaining steps are skipped, and the rollback still
    /// runs inside the reserve that was held back for it.
    #[test]
    fn an_expired_deadline_skips_the_rest_and_still_rolls_back() {
        let mut d = stopped()
            .slow(
                "g",
                Ok("Break instruction exception"),
                Duration::from_secs(45),
            )
            .on("second", Ok(""))
            .on("bc *", Ok(""));
        let batch = op(
            vec![
                step(StepAction::Resume {
                    command: "g".to_string(),
                    timeout_ms: None,
                }),
                cmd("second step"),
            ],
            vec![cmd("bc *")],
        );

        // 60s budget, 30s reserve → the steps get 30s and the first one costs 45s.
        let report = run(&mut d, &batch, BUDGET);

        assert_eq!(report.outcome, BatchOutcome::TimedOut { at: 2 });
        assert!(!d.ran("second"), "a step past the deadline must not run");
        assert!(d.ran("bc *"), "the reserve exists so this still runs");
        assert!(report.rollback_complete());
        let text = render(&report);
        assert!(text.contains("BATCH: TIMED OUT at step 2 of 2"), "{text}");
    }

    /// A teardown arriving mid-transaction: the batch stops where it is and unwinds, rather than
    /// running on to be killed with the patch still applied.
    ///
    /// This is the disconnect path. Nothing is wrong with the target or the budget — the session
    /// is simply going away — so the outcome is neither a failure nor a timeout, and the steps that
    /// did not run say which of the three it was, because the next move differs for each.
    #[test]
    fn an_abandoned_batch_stops_where_it_is_and_still_rolls_back() {
        let mut d = stopped()
            .on("eb fffff800", Ok(""))
            .on("second", Ok(""))
            .on("third", Ok(""))
            .on("eb restore", Ok(""))
            // The signal lands after the first step's command; `? @$ip` at the end is the only
            // other call, and by then the rollback has run.
            .abandoned_after(1);
        let batch = op(
            vec![
                cmd("eb fffff800`00001000 90"),
                cmd("second step"),
                cmd("third step"),
            ],
            vec![cmd("eb restore 41")],
        );

        let report = run(&mut d, &batch, BUDGET);

        assert_eq!(report.outcome, BatchOutcome::Abandoned { at: 2 });
        assert!(!d.ran("second"), "a step after the signal must not run");
        assert!(!d.ran("third"), "nor any step after that one");
        assert!(
            d.ran("eb restore"),
            "the rollback is the whole reason for stopping early"
        );
        assert!(report.rollback_complete());
        // Every skipped step says the session went away — not that something failed, and not that
        // the clock ran out, which would send a caller looking for a bug or a bigger budget.
        for step in &report.steps[1..] {
            let StepResult::Skipped(why) = &step.result else {
                panic!(
                    "step {} should have been skipped: {:?}",
                    step.position, step
                );
            };
            assert!(why.contains("torn down"), "{why}");
        }
        let text = render(&report);
        assert!(text.contains("BATCH: ABANDONED at step 2 of 3"), "{text}");
        assert!(text.contains("rollback: COMPLETE"), "{text}");
    }

    /// **The bound the worker advertises to a teardown has to be one this executor keeps.**
    ///
    /// A teardown is told when the batch will be done and terminates the worker if it is not, so an
    /// under-stated bound kills a worker in the middle of the restore the teardown was waiting for.
    /// The budget alone is under-stated: it bounds what may be *started*, and everything started
    /// just inside it is still armed with the watchdog floor — the last cleanup step's action, an
    /// assertion within it, and the state probe, which runs whatever else happened.
    ///
    /// So this drives the worst case rather than asserting the arithmetic: a cleanup step that
    /// starts a hair inside the budget and overruns, with an assertion behind it, and the probe
    /// after that. What it must not exceed is `budget + OVERRUN_ALLOWANCE`.
    #[test]
    fn a_batch_finishes_inside_the_bound_its_worker_advertises() {
        let step = Duration::from_millis(u64::from(MIN_STEP_BUDGET_MS));
        // 60s budget, 30s reserve: the steps block ends at 30s, so the first step lands the clock a
        // hair inside the *cleanup* deadline, and everything after it is a floor-armed overrun.
        let mut d = stopped()
            .slow("burn", Ok(""), Duration::from_millis(59_900))
            .slow("restore", Ok(""), step)
            .slow("? (1", Ok(EVAL_ONE), step)
            .slow(
                "? @$ip",
                Ok("Evaluate expression: 1 = fffff803`1a2b3c4d"),
                step,
            );
        let batch = op(
            vec![cmd("burn the budget")],
            vec![BatchStep {
                expect: vec![Check::Eval {
                    expr: "1".to_string(),
                    equals: "1".to_string(),
                }],
                ..cmd("restore it")
            }],
        );

        let report = run(&mut d, &batch, BUDGET);

        assert!(
            report.elapsed <= BUDGET + OVERRUN_ALLOWANCE,
            "the batch ran {:?}, past the {:?} bound its worker advertises to a teardown — which \
             would have the worker terminated mid-restore",
            report.elapsed,
            BUDGET + OVERRUN_ALLOWANCE
        );
        assert!(
            report.elapsed > BUDGET,
            "this test is only worth anything if it actually reaches past the budget"
        );
    }

    /// **An abandoned batch's rollback keeps the whole budget**, exactly like every other path. It
    /// is not shortened to fit the teardown's grace — the grace is sized from that budget instead
    /// (`worker::BatchSignal::abandon`), so shortening it here would only skip cleanup somebody was
    /// already waiting for.
    ///
    /// Both halves of this were once wrong in the same way. Holding the rollback to the reserve
    /// dropped the third step below, *and* it depended on the outcome — so a signal arriving during
    /// the batch's **last** step, where no further loop iteration exists to notice it, left the
    /// outcome `Committed` and the cleanup on a different bound from an identical signal one step
    /// earlier. The second run here is that case, and it must be indistinguishable from the first.
    #[test]
    fn an_abandoned_rollback_keeps_the_budget_every_other_path_gets() {
        // Cleanup steps costing 20s each against a 60s budget: three of them fit, where the
        // reserve (30s) would have seated two.
        let scripted = || {
            stopped()
                .on("first", Ok(""))
                .slow("restore", Ok(""), Duration::from_secs(20))
                .slow("clear", Ok(""), Duration::from_secs(20))
                .slow("bc *", Ok(""), Duration::from_secs(20))
        };
        let cleanup = || vec![cmd("restore it"), cmd("clear it"), cmd("bc *")];

        // Signalled mid-batch: the outcome is `Abandoned`, and the rollback still runs whole.
        let mut midway = scripted().abandoned_after(1);
        let stopped_early = run(
            &mut midway,
            &op(vec![cmd("first step"), cmd("never runs")], cleanup()),
            BUDGET,
        );
        assert_eq!(stopped_early.outcome, BatchOutcome::Abandoned { at: 2 });
        assert!(
            stopped_early.rollback_complete(),
            "cleanup was cut short to fit a grace that is sized from the budget anyway: {:?}",
            stopped_early.always
        );

        // Signalled during the *last* step, so `run`'s loop never sees it: the batch commits, and
        // the rollback must be bounded identically. A bound that read the outcome would differ
        // here, silently, in the case hardest to notice.
        let mut at_the_end = scripted().abandoned_after(1);
        let committed = run(
            &mut at_the_end,
            &op(vec![cmd("first step")], cleanup()),
            BUDGET,
        );
        assert_eq!(
            committed.outcome,
            BatchOutcome::Committed,
            "every step ran and every assertion held, whatever became of the session"
        );
        assert_eq!(
            committed
                .always
                .iter()
                .map(|s| s.result.tag())
                .collect::<Vec<_>>(),
            stopped_early
                .always
                .iter()
                .map(|s| s.result.tag())
                .collect::<Vec<_>>(),
            "the rollback's bound must not depend on which step the signal landed in"
        );
    }

    /// A rollback step that itself fails is reported beside the original failure, never instead
    /// of it — and the later cleanup steps still run.
    #[test]
    fn a_failed_rollback_step_neither_hides_the_failure_nor_stops_the_cleanup() {
        let mut d = stopped()
            .on("eb fffff800", Ok(""))
            .on(
                "bp nowhere!Nope",
                Err("Couldn't resolve error at 'nowhere!Nope'"),
            )
            .on("eb restore", Err("Memory access error"))
            .on("bc *", Ok(""));
        let batch = op(
            vec![cmd("eb fffff800`00001000 90"), cmd("bp nowhere!Nope")],
            vec![cmd("eb restore 41"), cmd("bc *")],
        );

        let report = run(&mut d, &batch, BUDGET);

        assert_eq!(report.outcome, BatchOutcome::Failed { at: 2 });
        assert!(!report.rollback_complete());
        assert!(
            d.ran("bc *"),
            "cleanup continues past a failed cleanup step"
        );

        let text = render(&report);
        assert!(text.contains("BATCH: FAILED at step 2 of 2"), "{text}");
        assert!(text.contains("rollback: INCOMPLETE — 1 of 2"), "{text}");
        assert!(text.contains("Couldn't resolve error"), "{text}");
    }

    /// A panic out of the debugger is the third path that would skip the rollback, and the least
    /// visible: nothing in this module raises it, and the worker's own `catch_unwind` is around
    /// the whole op, so an unwind from a step would leave `run` without ever reaching `always`.
    /// win-kexp methods do panic — that worker guard exists because several use `.expect`.
    #[test]
    fn a_panicking_step_fails_that_step_and_still_rolls_back() {
        let mut d = stopped()
            .on("eb fffff800", Ok(""))
            .panics("!analyze")
            .on("never", Ok(""))
            .on("eb restore", Ok(""));
        let batch = op(
            vec![
                cmd("eb fffff800`00001000 90"),
                cmd("!analyze -v"),
                cmd("never runs"),
            ],
            vec![cmd("eb restore 41")],
        );

        let report = run(&mut d, &batch, BUDGET);

        assert_eq!(report.outcome, BatchOutcome::Failed { at: 2 });
        assert!(d.ran("eb restore"), "the rollback must run: {:?}", d.calls);
        assert!(report.rollback_complete());
        assert!(!d.ran("never"), "the batch must stop at the panic");

        // The panic's own message has to survive into the report: "your transaction stopped" is
        // not an answer to "why".
        let text = render(&report);
        assert!(text.contains("panicked"), "{text}");
        assert!(text.contains(PANIC), "{text}");
    }

    /// A panicking *cleanup* step must not take the rest of the cleanup with it.
    #[test]
    fn a_panicking_rollback_step_does_not_stop_the_rest_of_the_cleanup() {
        let mut d = stopped()
            .on(
                "bp nowhere",
                Err("Couldn't resolve error at 'nowhere!Nope'"),
            )
            .panics("eb restore")
            .on("bc *", Ok(""));
        let report = run(
            &mut d,
            &op(
                vec![cmd("bp nowhere!Nope")],
                vec![cmd("eb restore 41"), cmd("bc *")],
            ),
            BUDGET,
        );

        assert_eq!(report.outcome, BatchOutcome::Failed { at: 1 });
        assert!(!report.rollback_complete());
        assert!(
            d.ran("bc *"),
            "cleanup continues past a panic: {:?}",
            d.calls
        );
        let text = render(&report);
        // Both survive: the original failure and the panic in the cleanup.
        assert!(text.contains("Couldn't resolve error"), "{text}");
        assert!(text.contains("panicked"), "{text}");
    }

    // ---- captures ----------------------------------------------------------

    #[test]
    fn a_capture_is_interpolated_into_a_later_step() {
        let mut d = stopped()
            .on(
                "? @rcx",
                Ok("Evaluate expression: 4096 = 00000000`00001000"),
            )
            .on("dt nt!_EPROCESS 0x1000", Ok("+0x000 Pcb"));
        let batch = op(
            vec![
                BatchStep {
                    capture: Some("obj".to_string()),
                    ..step(StepAction::Eval {
                        expr: "@rcx".to_string(),
                    })
                },
                cmd("dt nt!_EPROCESS {{obj}}"),
            ],
            vec![],
        );

        let report = run(&mut d, &batch, BUDGET);

        assert!(report.committed(), "{}", render(&report));
        assert!(
            d.ran("dt nt!_EPROCESS 0x1000"),
            "the capture should have been substituted: {:?}",
            d.calls
        );
    }

    /// `read_memory` takes a number, not an expression — so the documented way to dump memory at
    /// `@rsp` is an `eval` step in front of it. A capture binds as `0x`-hex, which is exactly what
    /// that step accepts, so the two compose without the caller converting anything.
    #[test]
    fn a_capture_feeds_a_read_memory_step_that_takes_only_numbers() {
        let mut d = stopped()
            .on("? @rsp", Ok("Evaluate expression: 1 = ffff8001`0000f000"))
            .on(
                "read 64 at 0xffff80010000f000",
                Ok("ffff80010000f000  90 90"),
            );
        let batch = op(
            vec![
                BatchStep {
                    capture: Some("sp".to_string()),
                    ..step(StepAction::Eval {
                        expr: "@rsp".to_string(),
                    })
                },
                step(StepAction::ReadMemory {
                    address: "{{sp}}".to_string(),
                    size: 64,
                }),
            ],
            vec![],
        );

        let report = run(&mut d, &batch, BUDGET);
        assert!(report.committed(), "{}", render(&report));
        assert!(
            d.ran("read 64 at 0xffff80010000f000"),
            "the capture should have arrived as a number: {:?}",
            d.calls
        );
    }

    /// The rollback case the validator deliberately does not reject: a cleanup step that restores
    /// a value the failing run never captured. It is skipped, and says which capture was missing.
    #[test]
    fn a_rollback_that_needs_an_unbound_capture_is_skipped_with_the_reason() {
        let mut d = stopped()
            .on(
                "bp nowhere!Nope",
                Err("Couldn't resolve error at 'nowhere!Nope'"),
            )
            .on("? poi(", Ok("Evaluate expression: 1 = 00000000`00000001"))
            .on("bc *", Ok(""));
        let batch = op(
            vec![
                cmd("bp nowhere!Nope"),
                BatchStep {
                    capture: Some("orig".to_string()),
                    ..step(StepAction::Eval {
                        expr: "poi(fffff800`00001000)".to_string(),
                    })
                },
            ],
            vec![cmd("eq fffff800`00001000 {{orig}}"), cmd("bc *")],
        );

        let report = run(&mut d, &batch, BUDGET);

        assert!(matches!(report.always[0].result, StepResult::Skipped(_)));
        assert!(!report.rollback_complete());
        let text = render(&report);
        assert!(text.contains("`{{orig}}` is not bound"), "{text}");
        assert!(d.ran("bc *"), "the rest of the cleanup still runs");
    }

    #[test]
    fn an_eval_step_that_prints_no_value_fails_rather_than_binding_nothing() {
        let mut d = stopped().on("? bogus!Nope", Ok("Couldn't resolve error at 'bogus!Nope'"));
        let batch = op(
            vec![BatchStep {
                capture: Some("x".to_string()),
                ..step(StepAction::Eval {
                    expr: "bogus!Nope".to_string(),
                })
            }],
            vec![],
        );

        let report = run(&mut d, &batch, BUDGET);
        assert_eq!(report.outcome, BatchOutcome::Failed { at: 1 });
    }

    // ---- assertions --------------------------------------------------------

    #[test]
    fn an_eval_check_compares_two_expressions_and_reports_both_sides() {
        let mut d = stopped()
            .on("!drvobj", Ok("Driver object (ffffb00`0000) is for:"))
            .on(
                "? (@rcx)",
                Ok("Evaluate expression: 65 = 00000000`00000041"),
            )
            .on(
                "? (0x42)",
                Ok("Evaluate expression: 66 = 00000000`00000042"),
            );
        let batch = op(
            vec![BatchStep {
                expect: vec![Check::Eval {
                    expr: "@rcx".to_string(),
                    equals: "0x42".to_string(),
                }],
                ..cmd("!drvobj \\Driver\\HEVD 7")
            }],
            vec![],
        );

        let report = run(&mut d, &batch, BUDGET);
        assert_eq!(report.outcome, BatchOutcome::Failed { at: 1 });
        let text = render(&report);
        assert!(text.contains("00000000`00000041"), "{text}");
        assert!(text.contains("00000000`00000042"), "{text}");
    }

    #[test]
    fn a_not_contains_check_fails_when_the_text_is_present() {
        let mut d = stopped().on("!analyze", Ok("PAGE_FAULT_IN_NONPAGED_AREA"));
        let batch = op(
            vec![BatchStep {
                expect: vec![Check::NotContains {
                    text: "PAGE_FAULT".to_string(),
                }],
                ..cmd("!analyze -v")
            }],
            vec![],
        );
        assert_eq!(
            run(&mut d, &batch, BUDGET).outcome,
            BatchOutcome::Failed { at: 1 }
        );
    }

    // ---- session state -----------------------------------------------------

    #[test]
    fn a_batch_that_detaches_reports_the_target_as_gone_without_probing() {
        let mut d = Script::new().on(".detach", Ok("Detached"));
        let batch = op(vec![cmd(".detach")], vec![]);

        let report = run(&mut d, &batch, BUDGET);

        assert!(matches!(report.after, SessionAfter::Detached { .. }));
        assert!(
            !d.ran("@$ip"),
            "a released target must not be probed: {:?}",
            d.calls
        );
        assert!(render(&report).contains("DETACHED/REPLACED"));
    }

    #[test]
    fn a_resume_that_never_stopped_leaves_the_session_reported_as_running() {
        let mut d = Script::new()
            .on("g", Err("the target did not stop within the timeout"))
            .on("? @$ip", Err("No runnable debuggees error"));
        let batch = op(
            vec![step(StepAction::Resume {
                command: "g".to_string(),
                timeout_ms: Some(5_000),
            })],
            vec![],
        );

        let report = run(&mut d, &batch, BUDGET);
        assert!(
            matches!(report.after, SessionAfter::Running { .. }),
            "{:?}",
            report.after
        );
        assert!(render(&report).contains("session after: RUNNING"));
    }

    /// A probe that fails with nothing in the batch to explain it must not be read as "detached".
    #[test]
    fn an_unexplained_probe_failure_is_uncertain_not_detached() {
        let mut d = Script::new()
            .on("lm", Ok("start end module"))
            .on("? @$ip", Err("No current thread"));
        let report = run(&mut d, &op(vec![cmd("lm")], vec![]), BUDGET);
        assert!(
            matches!(report.after, SessionAfter::Uncertain { .. }),
            "{:?}",
            report.after
        );
    }

    // ---- mutation classification -------------------------------------------

    #[test]
    fn mutations_are_classified_by_the_command_that_makes_them() {
        assert_eq!(mutation("eb fffff800`1000 90").as_deref(), Some("memory"));
        assert_eq!(mutation("r rax=1").as_deref(), Some("registers"));
        assert_eq!(
            mutation("bp nt!NtCreateFile").as_deref(),
            Some("breakpoints")
        );
        assert_eq!(mutation("g").as_deref(), Some("execution"));
        assert_eq!(mutation(".detach").as_deref(), Some("the debug target"));
        // A register *read* is not a write.
        assert_eq!(mutation("r rax"), None);
        assert_eq!(mutation("dt nt!_EPROCESS"), None);
        // Every segment counts, and each kind is named once.
        assert_eq!(
            mutation("bp nt!Foo; eb fffff800`1000 90; bc 0").as_deref(),
            Some("breakpoints + memory")
        );
    }

    #[test]
    fn a_resume_always_counts_as_changing_execution() {
        assert_eq!(
            action_mutation(&StepAction::Resume {
                command: "g @$ra".to_string(),
                timeout_ms: None,
            })
            .as_deref(),
            Some("execution")
        );
        assert_eq!(
            action_mutation(&StepAction::Eval {
                expr: "@rcx".to_string()
            }),
            None
        );
    }

    // ---- validation --------------------------------------------------------

    /// The catch-all must take *only* what the schema does not name. If serde routed a variant's
    /// own fields into it too, every well-formed step would be refused — so this pins the shape
    /// the typo check depends on.
    #[test]
    fn a_well_formed_step_leaves_nothing_in_the_catch_all() {
        for json in [
            serde_json::json!({"op": "command", "command": "lm"}),
            serde_json::json!({
                "op": "run_to", "address": "nt!Foo", "timeout_ms": 5000,
                "name": "go", "expect": [{"check": "contains", "text": "HIT"}]
            }),
            serde_json::json!({"op": "eval", "expr": "@rcx", "capture": "x"}),
            serde_json::json!({"op": "read_memory", "address": "0x1000", "size": 64}),
            serde_json::json!({"op": "resume", "command": "g"}),
        ] {
            let step: BatchStep = serde_json::from_value(json.clone()).expect("valid step");
            assert!(
                step.unknown_fields().is_empty(),
                "{json} left {:?} unaccounted for",
                step.unknown_fields()
            );
        }
    }

    /// A batch is a value that crosses a process boundary, so it has to survive its own encoding.
    ///
    /// Pinned because it did not, once: the typo-catching map is flattened, so serializing it wrote
    /// `op` and the action's fields a second time, and the worker rejected the duplicate key and
    /// discarded the request — which costs a caller their session rather than their call, because
    /// only a reply removes the supervisor's waiter. Unit tests over `run` never touch the wire, so
    /// nothing but the smoke tier saw it.
    #[test]
    fn a_batch_survives_being_encoded_for_the_worker() {
        let (steps, always) = messagemanager_sequence();
        let sent = BatchOp {
            steps,
            always,
            budget_ms: 60_000,
            patience_ms: 60_000,
        };
        let line = serde_json::to_string(&sent).expect("a batch must encode");
        let back: BatchOp = serde_json::from_str(&line).expect("and decode");

        assert_eq!(back.steps.len(), sent.steps.len());
        assert_eq!(back.always.len(), sent.always.len());
        for (before, after) in sent.steps.iter().zip(&back.steps) {
            assert_eq!(before.action.rendered(), after.action.rendered());
            assert_eq!(before.expect.len(), after.expect.len());
            assert_eq!(before.capture, after.capture);
        }
        // And what came back is still a batch this server would accept.
        validate(&back.steps, &back.always).expect("a round-tripped batch stays valid");
    }

    /// A step's output is clipped when the outcome is built, not when it is rendered, so a batch
    /// cannot accumulate every step's full text and take the worker — and its session — down with
    /// an allocation the read-size guard was supposed to bound.
    #[test]
    fn a_steps_output_is_bounded_when_it_is_recorded_not_when_it_is_printed() {
        let huge = "A".repeat(FAILED_OUTPUT_CHARS * 4);
        let mut d = stopped().on("db ", Ok(&huge));
        let report = run(
            &mut d,
            &op(vec![cmd("db fffff800`00001000 L20000")], vec![]),
            BUDGET,
        );

        let kept = report.steps[0].output.chars().count();
        assert!(
            kept <= STEP_OUTPUT_CHARS + 64,
            "a successful step kept {kept} characters of a {}-character output",
            huge.len()
        );
        // And the note says how much went missing, counted against the real output rather than
        // against an already-truncated copy of it.
        assert!(
            report.steps[0].output.contains(&format!(
                "{} more characters",
                huge.len() - STEP_OUTPUT_CHARS
            )),
            "the dropped count must be measured against the whole output: {}",
            &report.steps[0].output[report.steps[0].output.len().saturating_sub(80)..]
        );
    }

    /// The typo that fails *open*: a misspelt `expect` is a step that asserts nothing and commits.
    #[test]
    fn a_misspelt_step_field_is_refused_rather_than_ignored() {
        let step: BatchStep = serde_json::from_value(serde_json::json!({
            "op": "command",
            "command": "eb fffff800`00001000 90",
            "expects": [{"check": "contains", "text": "never seen"}]
        }))
        .expect("serde accepts it — which is the problem");
        assert_eq!(step.expect.len(), 0, "the assertions were silently dropped");

        let why = validate(&[step], &[]).unwrap_err();
        assert!(why.contains("expects"), "{why}");
        assert!(why.contains("check the spelling"), "{why}");
    }

    #[test]
    fn a_forward_capture_reference_is_refused_before_anything_runs() {
        let batch = vec![
            cmd("eb fffff800`00001000 {{later}}"),
            BatchStep {
                capture: Some("later".to_string()),
                ..step(StepAction::Eval {
                    expr: "@rcx".to_string(),
                })
            },
        ];
        let why = validate(&batch, &[]).unwrap_err();
        assert!(why.contains("`{{later}}` is not bound"), "{why}");
        assert!(why.contains("steps` step 1"), "{why}");
    }

    #[test]
    fn a_capture_on_a_non_eval_step_is_refused_with_the_alternative() {
        let batch = vec![BatchStep {
            capture: Some("out".to_string()),
            ..cmd("lm")
        }];
        let why = validate(&batch, &[]).unwrap_err();
        assert!(why.contains("only an `eval` step"), "{why}");
        assert!(why.contains("\"op\": \"eval\""), "{why}");
    }

    #[test]
    fn a_duplicate_capture_is_refused() {
        let twice = |name: &str| BatchStep {
            capture: Some(name.to_string()),
            ..step(StepAction::Eval {
                expr: "@rcx".to_string(),
            })
        };
        let why = validate(&[twice("x"), twice("x")], &[]).unwrap_err();
        assert!(why.contains("already bound"), "{why}");
    }

    /// The rollback's forward reference is the one that must be *allowed*: a cleanup step
    /// restoring what a later main step captured is the ordinary shape.
    #[test]
    fn a_rollback_may_name_a_capture_from_any_step() {
        let steps = vec![
            cmd("eb fffff800`00001000 90"),
            BatchStep {
                capture: Some("orig".to_string()),
                ..step(StepAction::Eval {
                    expr: "poi(fffff800`00001000)".to_string(),
                })
            },
        ];
        validate(&steps, &[cmd("eq fffff800`00001000 {{orig}}")]).expect("allowed");
    }

    /// …but the rule is still "an earlier step", in execution order: a cleanup step may not name a
    /// capture a *later* cleanup step binds, which could only ever be unbound when it ran.
    #[test]
    fn a_rollback_may_not_name_a_capture_from_a_later_rollback_step() {
        let always = vec![
            cmd("eq fffff800`00001000 {{late}}"),
            BatchStep {
                capture: Some("late".to_string()),
                ..step(StepAction::Eval {
                    expr: "@rcx".to_string(),
                })
            },
        ];
        let why = validate(&[cmd("lm")], &always).unwrap_err();
        assert!(why.contains("`always` step 1"), "{why}");
        assert!(why.contains("`{{late}}` is not bound"), "{why}");
    }

    #[test]
    fn a_separator_in_a_typed_operand_is_refused() {
        let why = validate(
            &[step(StepAction::Eval {
                expr: "@rcx; .detach".to_string(),
            })],
            &[],
        )
        .unwrap_err();
        assert!(why.contains("contains a `;`"), "{why}");
        // A raw command may chain — that is what it is for.
        validate(&[cmd("bp nt!Foo; g")], &[]).expect("a raw command may chain");
    }

    #[test]
    fn an_empty_batch_and_an_oversized_one_are_both_refused() {
        assert!(validate(&[], &[]).unwrap_err().contains("empty"));
        let many: Vec<BatchStep> = (0..=MAX_STEPS).map(|_| cmd("lm")).collect();
        assert!(validate(&many, &[]).unwrap_err().contains("at most"));
    }

    #[test]
    fn a_target_changing_command_in_either_block_retires_the_handle() {
        assert!(retires_handle(&[cmd(".opendump other.dmp")], &[]));
        assert!(retires_handle(&[cmd("lm")], &[cmd(".detach")]));
        assert!(!retires_handle(
            &[cmd("lm"), cmd("bp nt!Foo")],
            &[cmd("bc *")]
        ));
    }

    // ---- the sequence this tool was filed for -------------------------------

    /// The MessageManager CTF sequence, as `debug_batch` expresses it — issue #82's last
    /// acceptance criterion, discharged against the workflow itself rather than against a guess
    /// at it.
    ///
    /// Transcribed from the longest single invocation of the throwaway PowerShell client the CTF
    /// session grew (`target/mcp_batch.ps1`, 32 steps in one call), plus the rollback that client
    /// hard-coded by its final revision. Every construct the script had a verb for is here: a
    /// run-to verdict (`@run`), a register assertion against a saved pseudo-register
    /// (`@asserttarget`), a structure assertion over three memory words (`@assertfake`), code
    /// patches and their restores, and `bc *`.
    ///
    /// Two of the script's verbs are **not** here and cannot be: `@chunkt1` and `@census` call the
    /// `pool_chunk`/`pool_census` tools, and a batch step cannot reach a typed tool that is not a
    /// debugger command. Nine of the workflow's 1,681 steps were pool queries; the other 1,672 are
    /// the shapes below.
    fn messagemanager_sequence() -> (Vec<BatchStep>, Vec<BatchStep>) {
        // The verdict check the script open-coded as `if ($verdict -notmatch 'VERDICT: HIT')`.
        let run_to = |address: &str, ms: u32| BatchStep {
            expect: vec![Check::Contains {
                text: "VERDICT: HIT".to_string(),
            }],
            ..step(StepAction::RunTo {
                address: address.to_string(),
                timeout_ms: Some(ms),
            })
        };
        // `@asserttarget`: the script could not compare two values, so it emitted
        // `.if ($register != @$t6) { .echo MM_TARGET_MISMATCH }` and regex-matched the echo. An
        // `eval` check is the same assertion without the round trip through prose.
        let assert_target = |register: &str| BatchStep {
            name: Some(format!("the break belongs to our MESSAGE ({register})")),
            expect: vec![Check::Eval {
                expr: register.to_string(),
                equals: "@$t6".to_string(),
            }],
            ..step(StepAction::Eval {
                expr: register.to_string(),
            })
        };
        let steps = vec![
            run_to("fffff806159516e4", 270_000),
            cmd("r @$t7=fffff80615950000; r @$t6=@rbx; r; dd @$t6 L4"),
            assert_target("@rbx"),
            cmd("bc *"),
            cmd("ed @$t6 3; eb @$t7+16e4 eb fe 90 90"),
            run_to("fffff80615951502", 30_000),
            assert_target("@rsi"),
            cmd("bc *"),
            cmd("ed @$t7+16e4 08538d48"),
            run_to("fffff80615951706", 30_000),
            assert_target("@rbx"),
            cmd("bc *"),
            run_to("fffff8061595151b", 30_000),
            assert_target("@rsi"),
            cmd("r @$t1=@rsi; db @$t1 L68"),
            cmd("bc *"),
            cmd("eb @$t7+1f00 f3 90 eb fc e9 27 f3 ff ff; eb @$t7+1230 e9 cb 0c 00 00"),
            run_to("fffff80615951210", 90_000),
            cmd("bc *"),
            cmd("eb @$t7+1230 48 89 5c 24 08"),
            run_to("fffff80615951560", 30_000),
            // `@assertfake`: three fields of the reclaiming allocation. The script's first cut
            // chained them into one `.if`, which did not evaluate as written, so its eighth
            // revision replaced it with three `r @$tN=` assignments and three regexes over the
            // printed output. Three `eval` checks say it once.
            BatchStep {
                name: Some("the reclaim landed on our fake MESSAGE".to_string()),
                expect: vec![
                    Check::Eval {
                        expr: "poi(@$t1+18)".to_string(),
                        equals: "0".to_string(),
                    },
                    Check::Eval {
                        expr: "poi(@$t1+20)".to_string(),
                        equals: "0x400".to_string(),
                    },
                    Check::Eval {
                        expr: "by(@$t1+60)".to_string(),
                        equals: "1".to_string(),
                    },
                ],
                ..cmd("db @$t1 L68")
            },
            cmd("bc *"),
            run_to("fffff8067fafa240", 30_000),
            cmd("r; ln @rip; kv"),
        ];
        // Verbatim from the client's final revision — the restore it ran on the failure paths it
        // could reach, and could not run on the ones it could not.
        let always = vec![
            cmd(
                "ed @$t7+16e4 08538d48; eb @$t7+1656 54 66 75 62; eb @$t7+165e 00 01 00 00; \
                 eb @$t7+1f03 00; eb @$t7+1230 48 89 5c 24 08",
            ),
            cmd("bc *"),
        ];
        (steps, always)
    }

    #[test]
    fn the_messagemanager_sequence_is_a_valid_batch() {
        let (steps, always) = messagemanager_sequence();
        assert_eq!(steps.len(), 25);
        validate(&steps, &always).expect("the sequence the tool was filed for must validate");
        // It patches code and clears breakpoints, so it must not be mistaken for inspection.
        assert!(
            steps
                .iter()
                .filter_map(|s| action_mutation(&s.action))
                .any(|m| m.contains("memory")),
            "the code patches must be recognised as mutations"
        );
    }

    /// The failure the client hand-rolled a rollback for: the race breakpoint fires for a
    /// *different* MESSAGE than the one that was saved. Here it is one `eval` check, and the
    /// restore is not conditional on anyone still being connected to send it.
    #[test]
    fn a_wrong_target_stops_the_messagemanager_sequence_and_restores_the_patches() {
        let (steps, always) = messagemanager_sequence();
        let mut d = stopped()
            .on(
                "run to ",
                Ok("VERDICT: HIT — execution reached fffff806`159516e4"),
            )
            // The saved object and the one this break belongs to are different — the mismatch.
            .on("? (@rbx)", Ok("Evaluate expression: 1 = ffffb08e`e358c080"))
            .on("? (@$t6)", Ok("Evaluate expression: 1 = ffffb08e`e358d100"))
            // Everything else — the `r`/`dd`/`eb`/`ed`/`bc` traffic — answers blank.
            .on("", Ok(""));
        let batch = op(steps, always);

        let report = run(&mut d, &batch, BUDGET);

        // Step 3 is the first `@asserttarget`.
        assert_eq!(report.outcome, BatchOutcome::Failed { at: 3 });
        assert!(report.rollback_complete(), "{}", render(&report));
        assert!(
            d.ran("ed @$t7+16e4 08538d48") && d.ran("bc *"),
            "the code patches must be restored: {:?}",
            d.calls
        );
        // Nothing past the failure ran — including the patches that would have been applied.
        assert!(
            !d.ran("eb @$t7+1f00"),
            "the batch must stop at the mismatch: {:?}",
            d.calls
        );
        let text = render(&report);
        assert!(text.contains("BATCH: FAILED at step 3 of 25"), "{text}");
        assert!(text.contains("ffffb08e`e358c080"), "{text}");
        assert!(text.contains("ffffb08e`e358d100"), "{text}");
    }

    // ---- budget arithmetic --------------------------------------------------

    #[test]
    fn the_rollback_reserve_never_takes_more_than_half_the_budget() {
        // A 10s batch reserves 5s, not the full 30s — otherwise the steps would get none.
        let mut d = stopped().on("lm", Ok("start end module"));
        let report = run(
            &mut d,
            &op(vec![cmd("lm")], vec![]),
            Duration::from_secs(10),
        );
        assert!(report.committed(), "{}", render(&report));
    }

    /// Assertions are engine work too, and a step may carry several — each an `eval` check worth
    /// two queries. Arming them all from the clock as it stood before the *first* one would let a
    /// step's checks run for a multiple of the time the step was given, and eat the reserve the
    /// rollback depends on. The loop re-reads the clock between checks and stops at the deadline.
    #[test]
    fn assertions_cannot_run_past_the_step_deadline_and_eat_the_reserve() {
        // 60s budget → 30s reserve → the steps get 30s. Each `?` query costs 20s.
        let mut d = stopped()
            .on("lm", Ok("start end module"))
            .slow("? (first", Ok(EVAL_ONE), Duration::from_secs(20))
            .slow("? (1)", Ok(EVAL_ONE), Duration::from_secs(20))
            .on("? (second", Ok(EVAL_ONE))
            .on("bc *", Ok(""));
        let batch = op(
            vec![BatchStep {
                expect: vec![
                    Check::Eval {
                        expr: "first".to_string(),
                        equals: "1".to_string(),
                    },
                    Check::Eval {
                        expr: "second".to_string(),
                        equals: "1".to_string(),
                    },
                ],
                ..cmd("lm")
            }],
            vec![cmd("bc *")],
        );

        let report = run(&mut d, &batch, BUDGET);

        // The first check's two queries put the clock at 40s, past the 30s step deadline, so the
        // second check never starts.
        assert!(
            !d.ran("? (second"),
            "assertions must stop at the step deadline: {:?}",
            d.calls
        );
        assert_eq!(report.outcome, BatchOutcome::TimedOut { at: 1 });
        // And the reserve did its job: the cleanup still ran.
        assert!(d.ran("bc *"), "the rollback must survive: {:?}", d.calls);
        assert!(report.rollback_complete());
    }

    /// The path where the rollback guarantee genuinely fails: a step overran so far that even the
    /// reserve is gone. Nothing can be done about it — but the report must say so rather than
    /// leave a caller believing the cleanup ran.
    /// Within one `eval` check the two queries are sequential, so the second must be told what the
    /// first left. Falling back on the minimum watchdog would start debugger work the step no
    /// longer had time for — and spend the rollback's reserve on an assertion.
    #[test]
    fn the_second_half_of_an_eval_check_does_not_start_past_the_deadline() {
        // 60s budget → 30s steps deadline. The left query alone costs 35s.
        let mut d = stopped()
            .on("lm", Ok("start end module"))
            .slow("? (left", Ok(EVAL_ONE), Duration::from_secs(35))
            .on("? (right", Ok(EVAL_ONE))
            .on("bc *", Ok(""));
        let batch = op(
            vec![BatchStep {
                expect: vec![Check::Eval {
                    expr: "left".to_string(),
                    equals: "right".to_string(),
                }],
                ..cmd("lm")
            }],
            vec![cmd("bc *")],
        );

        let report = run(&mut d, &batch, BUDGET);

        assert!(
            !d.ran("? (right"),
            "the right-hand query must not start past the deadline: {:?}",
            d.calls
        );
        // A timeout, not an unmet assertion: nothing was learned about the target.
        assert_eq!(report.outcome, BatchOutcome::TimedOut { at: 1 });
        assert!(
            render(&report).contains("ran out of time"),
            "{}",
            render(&report)
        );
        assert!(d.ran("bc *"), "the reserve survived: {:?}", d.calls);
    }

    #[test]
    fn a_cleanup_step_past_the_whole_budget_is_skipped_and_reported_as_incomplete() {
        // One step costs 100s against a 60s budget, so the `always` block cannot start at all.
        // The state probe still runs: past the deadline is exactly when a caller most needs to be
        // told what the session is left holding.
        let mut d = stopped().slow("lm", Ok(""), Duration::from_secs(100));
        let report = run(
            &mut d,
            &op(vec![cmd("lm")], vec![cmd("bc *"), cmd("eb restore 41")]),
            BUDGET,
        );

        assert!(
            !d.ran("bc *") && !d.ran("eb restore"),
            "there was no time left to run cleanup: {:?}",
            d.calls
        );
        assert!(!report.rollback_complete());
        let text = render(&report);
        assert!(text.contains("rollback: INCOMPLETE — 2 of 2"), "{text}");
        assert!(
            text.contains("ran out of time before this cleanup step started"),
            "{text}"
        );
    }

    #[test]
    fn a_batch_deadline_too_short_to_run_anything_is_refused() {
        // Zero is the one a caller writes by accident, and it yields a batch that skips every step
        // *and* every cleanup step — silently, without the reserve ever mattering.
        let why = budget_ms(Some(0)).unwrap_err();
        assert!(why.contains("at least"), "{why}");
        assert!(why.contains("reserved for the `always` block"), "{why}");
        assert!(budget_ms(Some(MIN_BATCH_MS - 1)).is_err());
        assert_eq!(budget_ms(Some(MIN_BATCH_MS)), Ok(MIN_BATCH_MS));
        assert_eq!(budget_ms(None), Ok(DEFAULT_BATCH_MS));
    }

    #[test]
    fn a_step_is_never_armed_with_a_zero_watchdog() {
        // Zero disables win-kexp's watchdog, so the floor matters more than the arithmetic.
        assert_eq!(
            step_budget_ms(Duration::from_secs(90), Duration::from_secs(60)),
            0
        );
        let mut d = stopped().slow("lm", Ok(""), Duration::from_secs(90));
        let report = run(&mut d, &op(vec![cmd("lm"), cmd("lm")], vec![]), BUDGET);
        assert_eq!(report.outcome, BatchOutcome::TimedOut { at: 2 });
    }
}
