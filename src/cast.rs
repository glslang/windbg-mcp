//! Rendering a transcript as a terminal recording — [asciicast v2].
//!
//! The second half of [#87](https://github.com/glslang/windbg-mcp/issues/87), and the half with
//! the evidence behind it: the recordings checked in under `examples/` are captioned
//! *"Reconstructed terminal session"*, and one of them says outright that *"timing is illustrative
//! because live recording was not enabled for the original run"*. A cast reconstructed afterwards
//! is a drawing of a session, not a recording of one.
//!
//! # Derived, not written twice
//!
//! This renders from the JSONL that [`crate::record`] already wrote, offline, rather than emitting
//! a `.cast` alongside it as the session runs. One source of truth, and three things fall out of
//! it: a cast can be made from a transcript recorded weeks ago, the rendering can be changed
//! without re-running anything, and the timings are the recorded ones — `mono_ms`, measured on a
//! monotonic clock, so they cannot go backwards and cannot be reordered by a clock that steps.
//!
//! # What a viewer sees
//!
//! A terminal session: each tool call as a prompt line, its result printed under it, and the facts
//! the transcript derived — a stop position, a mutation, a batch verdict, a session opening or
//! being let go — as marked lines between them. It is the debugger's side of the conversation,
//! which is the part worth watching; the model's prompts are not in the transcript and are not
//! this server's to record.
//!
//! [asciicast v2]: https://docs.asciinema.org/manual/asciicast/v2/

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;

use serde_json::Value;

use crate::record::{Capped, Event, Record};

/// The flag that selects this role. See [`crate::main`].
pub const RENDER_FLAG: &str = "--render-cast";

/// How wide the recorded terminal is said to be.
///
/// Wide enough for the tables this server prints — a pool census row, a module listing — which
/// wrap into illegibility at 80. A player scales the recording to fit, so this is a shape rather
/// than a requirement on the viewer.
const DEFAULT_WIDTH: u32 = 120;
const DEFAULT_HEIGHT: u32 = 32;

/// What a player is told to shorten a pause to, in seconds.
///
/// Not a change to the timings — every event keeps the instant it happened at, and this is a
/// header field a player applies while playing. It is here because a real session has real gaps
/// in it: a minute while somebody reads a stack trace is a minute of nothing, and a recording
/// nobody watches to the end proves nothing. `--idle-limit 0` turns it off and plays the session
/// at the speed it happened.
const DEFAULT_IDLE_LIMIT: f64 = 2.0;

/// How much of a result is shown before the rendering says how much more there was.
///
/// The transcript's own cap is about what is *kept*; this one is about what is *watchable*. A
/// 400-line module listing scrolling past is not a demonstration of anything, and the transcript
/// still holds every byte of it that was recorded.
const DEFAULT_MAX_LINES: usize = 24;

/// What to render, and how.
#[derive(Debug)]
pub struct Options {
    pub input: PathBuf,
    pub output: PathBuf,
    pub width: u32,
    pub height: u32,
    pub title: Option<String>,
    pub idle_limit: f64,
    pub max_lines: usize,
}

impl Options {
    /// Reads the role's command line. `Err` carries the usage message, which the caller prints.
    ///
    /// Hand-rolled because this is the whole of it: the server takes no other options, and a
    /// dependency for one flag list is a dependency in every build of the MCP server too.
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut input = None;
        let mut output = None;
        let mut width = DEFAULT_WIDTH;
        let mut height = DEFAULT_HEIGHT;
        let mut title = None;
        let mut idle_limit = DEFAULT_IDLE_LIMIT;
        let mut max_lines = DEFAULT_MAX_LINES;
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            let mut value = |what: &str| {
                rest.next()
                    .cloned()
                    .ok_or_else(|| format!("`{what}` needs a value"))
            };
            match arg.as_str() {
                "--out" | "-o" => output = Some(PathBuf::from(value("--out")?)),
                "--width" => width = number(&value("--width")?, "--width")?,
                "--height" => height = number(&value("--height")?, "--height")?,
                "--title" => title = Some(value("--title")?),
                "--idle-limit" => {
                    idle_limit = value("--idle-limit")?
                        .parse()
                        .map_err(|_| "`--idle-limit` takes a number of seconds".to_string())?;
                }
                "--max-lines" => {
                    max_lines = number(&value("--max-lines")?, "--max-lines")? as usize
                }
                other if other.starts_with('-') => return Err(format!("unknown option `{other}`")),
                path if input.is_none() => input = Some(PathBuf::from(path)),
                extra => return Err(format!("unexpected argument `{extra}`")),
            }
        }
        let input = input.ok_or_else(|| "no transcript named".to_string())?;
        Ok(Self {
            output: output.unwrap_or_else(|| input.with_extension("cast")),
            input,
            width,
            height,
            title,
            idle_limit,
            max_lines,
        })
    }
}

fn number(value: &str, what: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("`{what}` takes a whole number"))
}

pub const USAGE: &str = "\
usage: windbg-mcp --render-cast <transcript.jsonl> [options]

Renders a session transcript (WINDBG_MCP_TRANSCRIPT) as an asciicast v2 recording.

  -o, --out <file>       where to write it (default: the transcript's name, with .cast)
      --title <text>     the recording's title
      --width <cols>     terminal width  (default: 120)
      --height <rows>    terminal height (default: 32)
      --idle-limit <s>   what a player shortens a pause to; 0 plays it at real speed (default: 2)
      --max-lines <n>    how much of a long result to show; 0 shows all of it (default: 24)
";

/// Renders `options.input` into `options.output`, and reports what it wrote.
pub fn render(options: &Options) -> Result<Summary, String> {
    // Before anything is read, because what follows would destroy the evidence. Writing the cast
    // truncates its output, and two ways of asking lead here: `--out` naming the input, and a
    // transcript that already ends in `.cast`, whose default output is itself. The render would
    // then *succeed* — the records are in memory by then — and replace the only JSONL copy of the
    // session with a rendering of it. That is the one failure this whole feature exists to
    // prevent, arriving through the tool meant to make the session shareable.
    if same_file(&options.input, &options.output) {
        return Err(format!(
            "the rendering would be written over the transcript it is made from (`{}`). Name a \
             different `--out`: the transcript is the record, and a cast is a rendering of it that \
             can be made again.",
            options.input.display()
        ));
    }
    let transcript = std::fs::read_to_string(&options.input)
        .map_err(|e| format!("could not read `{}`: {e}", options.input.display()))?;
    let (records, unreadable) = parse(&transcript);
    if records.is_empty() {
        return Err(format!(
            "`{}` holds no transcript records. A file this server wrote has one JSON object per \
             line, the first of them a `start`.",
            options.input.display()
        ));
    }
    let runs = runs(&records).len();
    let timeline = timeline(&records);
    let mut out = String::new();
    writeln!(out, "{}", header(options, &records)).map_err(|e| e.to_string())?;
    let mut frames = 0;
    for (index, at) in &timeline {
        let Some(text) = frame(&records[*index], options.max_lines) else {
            continue;
        };
        // `[time, "o", data]`, where the time is the recorded one in seconds. Serialized as an
        // array so the escaping is serde's problem — a debugger's output carries control
        // characters, quotes and half-finished escape sequences, and a hand-built line would be
        // the one thing that could make a cast unplayable.
        let event = Value::Array(vec![
            Value::from(*at as f64 / 1000.0),
            Value::from("o"),
            Value::from(text),
        ]);
        writeln!(out, "{event}").map_err(|e| e.to_string())?;
        frames += 1;
    }
    if let Some(parent) = options
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create `{}`: {e}", parent.display()))?;
    }
    // Truncating, unlike the transcript: a rendering is derived, so rewriting it is how it is
    // updated, and appending would produce a file with two headers and no valid reading.
    let mut file = std::fs::File::create(&options.output)
        .map_err(|e| format!("could not write `{}`: {e}", options.output.display()))?;
    file.write_all(out.as_bytes())
        .map_err(|e| format!("could not write `{}`: {e}", options.output.display()))?;
    Ok(Summary {
        records: records.len(),
        frames,
        unreadable,
        runs,
        duration_ms: timeline.last().map_or(0, |(_, at)| *at),
    })
}

/// What a render produced. `unreadable` is reported rather than swallowed: a transcript whose tail
/// was cut off by a crash is exactly the case the format is designed to survive, and a renderer
/// that said nothing about it would hide how much of the session it had.
#[derive(Debug)]
pub struct Summary {
    pub records: usize,
    pub frames: usize,
    pub unreadable: usize,
    /// How many server runs the transcript holds. More than one is ordinary — the file is
    /// appended to — and worth reporting, because it is why a cast can be longer than any single
    /// session was.
    pub runs: usize,
    pub duration_ms: u64,
}

/// Whether two paths name the same file.
///
/// By identity where the filesystem can say so — `canonicalize` resolves `.`, `..`, a symlink and
/// (on Windows) the case of a path that exists, which a string comparison of
/// `run.jsonl` against `./RUN.jsonl` would not. It only answers for paths that exist, and the
/// output usually does not yet, so the comparison falls back to the paths as given: enough for
/// the two ways this is actually reached, both of which produce literally equal paths.
fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// The records in playback order, each with the time it plays at — never decreasing.
///
/// Three things have to be reconciled, and they are all consequences of a transcript being a file
/// that is *appended* to.
///
/// **Runs.** `mono_ms` is measured from the start of its own run, so a file holding two of them
/// has a second that begins again at zero. Written out as they stand those offsets step backwards
/// at the join and a player refuses the recording. The runs are laid end to end instead — keeping
/// the earlier one, which is the part somebody kept the file for — separated by the **wall
/// clock's** gap, since that is how long the server was actually down. When the stamps cannot
/// answer (a clock that stepped, an unreadable one) the runs are butted together with [`RUN_GAP`],
/// which reads as a join rather than a wait.
///
/// **Interleaving.** Two supervisors can share a path, so the runs are grouped by `run` id rather
/// than by position: their lines alternate in the file, and taking the file in order would tell
/// one story out of two.
///
/// **Order within a run** is `seq`, not file order — and the records are *reordered*, not merely
/// restamped. Rising timestamps on lines still emitted in file order would show a result before
/// the request that produced it, which is a recording of something that did not happen. The two
/// agree for anything this build writes, since `Recorder::write` numbers under the same lock it
/// writes under; a file from before that fix still has to play, and to play correctly.
fn timeline(records: &[Record]) -> Vec<(usize, u64)> {
    let mut playback = Vec::with_capacity(records.len());
    let mut base = 0u64;
    let mut previous: Option<usize> = None;
    for run in runs(records) {
        let Some(&first) = run.first() else { continue };
        // Where this run begins on the playback clock: after everything before it, plus however
        // long the server was down in between.
        let start = match previous {
            None => 0,
            Some(previous) => base + gap(&records[previous], &records[first]),
        };
        let mut last = start;
        for index in run {
            last = last.max(start + records[index].mono_ms);
            playback.push((index, last));
            previous = Some(index);
        }
        base = last;
    }
    playback
}

/// How long the server was down between two runs, in milliseconds, from their wall clocks.
///
/// [`RUN_GAP`] when the stamps cannot answer — either is unreadable, or the later one is not later,
/// which a clock that stepped backwards produces. Never zero, so a join is always visible.
fn gap(before: &Record, after: &Record) -> u64 {
    crate::record::unix_seconds(&after.at)
        .zip(crate::record::unix_seconds(&before.at))
        .and_then(|(after, before)| after.checked_sub(before))
        .map(|secs| secs.saturating_mul(1000))
        .filter(|gap| *gap > 0)
        .unwrap_or(RUN_GAP)
}

/// The stand-in gap between two runs whose wall clocks cannot be compared. Long enough to read as
/// a break, short enough not to be a wait.
const RUN_GAP: u64 = 1_000;

/// The record indices of each run, in the order the runs happened, each sorted by `seq`.
///
/// Grouped by the `run` field first, which is what separates two servers appending to one file.
/// Then split again at every `start` record, because a run id is missing from a transcript written
/// before the field existed (they all read as run `0`) and because a `start` is where a run begins
/// whatever else is true. Records before the first `start` are a run of their own, so a file whose
/// head was lost still renders.
fn runs(records: &[Record]) -> Vec<Vec<usize>> {
    let mut order: Vec<u64> = Vec::new();
    let mut grouped: std::collections::HashMap<u64, Vec<Vec<usize>>> =
        std::collections::HashMap::new();
    for (index, record) in records.iter().enumerate() {
        let segments = grouped.entry(record.run).or_insert_with(|| {
            order.push(record.run);
            Vec::new()
        });
        // A `start` opens a segment; so does the first record of a group that did not begin with
        // one.
        if segments.is_empty() || matches!(record.event, Event::Start { .. }) {
            segments.push(Vec::new());
        }
        segments
            .last_mut()
            .expect("a segment was just opened")
            .push(index);
    }
    let mut runs: Vec<Vec<usize>> = order
        .into_iter()
        .flat_map(|run| grouped.remove(&run).unwrap_or_default())
        .collect();
    // By where each run first appears, so interleaved groups still come out in the order they
    // started, and by `seq` within one.
    runs.sort_by_key(|run| run.first().copied().unwrap_or(usize::MAX));
    for run in &mut runs {
        run.sort_by_key(|index| records[*index].seq);
    }
    runs
}

/// Reads a transcript, skipping what it cannot parse.
///
/// One record per line, so a line that will not read costs that record and nothing after it. The
/// case this is for is the last line of a file whose server died mid-write — the property the
/// single-`write_all` rule in [`crate::record`] exists to give.
fn parse(transcript: &str) -> (Vec<Record>, usize) {
    let mut records = Vec::new();
    let mut unreadable = 0;
    for line in transcript.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<Record>(line) {
            Ok(record) => records.push(record),
            Err(_) => unreadable += 1,
        }
    }
    (records, unreadable)
}

/// The asciicast header: version, shape, when it was recorded, and what to call it.
fn header(options: &Options, records: &[Record]) -> Value {
    let mut header = serde_json::json!({
        "version": 2,
        "width": options.width,
        "height": options.height,
        "env": { "TERM": "xterm-256color" },
    });
    // The wall clock of the first record — the moment the session actually started, which is the
    // one thing the monotonic times cannot say.
    if let Some(at) = records
        .first()
        .and_then(|r| crate::record::unix_seconds(&r.at))
    {
        header["timestamp"] = Value::from(at);
    }
    if options.idle_limit > 0.0 {
        header["idle_time_limit"] = Value::from(options.idle_limit);
    }
    let title = options.title.clone().or_else(|| {
        records.iter().find_map(|r| match &r.event {
            Event::SessionOpen { kind, target, .. } => {
                Some(format!("windbg-mcp — {kind} {}", target.text))
            }
            _ => None,
        })
    });
    if let Some(title) = title {
        header["title"] = Value::from(title);
    }
    header
}

// ---- rendering one record --------------------------------------------------

/// A terminal line's worth of output for one record, or `None` for one that shows nothing.
///
/// Line endings are `\r\n`: this is a terminal recording, and a bare newline leaves the cursor in
/// the column it was in.
fn frame(record: &Record, max_lines: usize) -> Option<String> {
    let mut out = String::new();
    match &record.event {
        Event::Start { version, .. } => {
            line(
                &mut out,
                &format!(
                    "{DIM}windbg-mcp {} — session transcript{RESET}",
                    visible(version)
                ),
            );
        }
        Event::ToolRequest { tool, args, .. } => {
            let args = args.as_ref().map_or_else(String::new, render_args);
            line(
                &mut out,
                &format!(
                    "{PROMPT}${RESET} {TOOL}{}{RESET} {DIM}{args}{RESET}",
                    visible(tool)
                ),
            );
        }
        Event::ToolResult {
            verdict,
            text,
            elapsed_ms,
            ..
        } => {
            body(&mut out, text, max_lines);
            let failed = *verdict == crate::record::Verdict::Error;
            let mark = if failed {
                format!("{FAIL}error{RESET}")
            } else {
                format!("{OK}ok{RESET}")
            };
            line(
                &mut out,
                &format!("{DIM}[{mark}{DIM} in {elapsed_ms} ms]{RESET}"),
            );
            out.push_str("\r\n");
        }
        Event::SessionOpen {
            session,
            kind,
            target,
            engine_pid,
        } => note(
            &mut out,
            NOTE,
            &format!(
                "session {session} — {kind} `{}` (engine pid {engine_pid})",
                target.text
            ),
        ),
        Event::SessionState {
            session,
            state,
            detail,
        } => note(
            &mut out,
            NOTE,
            &format!("session {session} → {state}{}", suffix(detail)),
        ),
        Event::SessionEnd {
            session, released, ..
        } => note(
            &mut out,
            if *released { NOTE } else { FAIL },
            &match released {
                true => format!("session {session} released its target"),
                false => format!("session {session} ENDED WITHOUT RELEASING its target"),
            },
        ),
        Event::WorkerLost { session, detail } => note(
            &mut out,
            FAIL,
            &format!("session {session} lost its engine: {}", detail.text),
        ),
        Event::CallTimeout { session, budget_ms } => note(
            &mut out,
            FAIL,
            &format!(
                "session {session}: a wait was abandoned after {budget_ms} ms (the job may still be running)"
            ),
        ),
        Event::Interrupt {
            session, delivered, ..
        } => note(
            &mut out,
            NOTE,
            &match delivered {
                true => format!("session {session} interrupted"),
                false => format!("session {session}: an interrupt was not acknowledged"),
            },
        ),
        Event::Stop {
            command,
            stopped_at,
            interrupted,
            ..
        } => note(
            &mut out,
            STOP,
            &format!(
                "`{command}` stopped at {}{}",
                stopped_at.as_deref().unwrap_or("an unknown position"),
                if *interrupted { " (on request)" } else { "" }
            ),
        ),
        Event::RunTo {
            verdict,
            target,
            stopped_at,
            ..
        } => note(
            &mut out,
            STOP,
            &format!(
                "run to {target}: {}{}",
                verdict.to_uppercase(),
                stopped_at
                    .as_deref()
                    .map(|at| format!(" at {at}"))
                    .unwrap_or_default()
            ),
        ),
        // The one a person scrubbing through a recording is looking for.
        Event::Mutation { detail, step, .. } => note(
            &mut out,
            MUTATION,
            &format!(
                "changed: {}{}",
                detail.text,
                step.as_ref()
                    .map(|s| format!(" [{}]", s.text))
                    .unwrap_or_default()
            ),
        ),
        Event::Assertion { step, detail, .. } => note(
            &mut out,
            FAIL,
            &format!("assertion did not hold at {}: {}", step.text, detail.text),
        ),
        Event::Batch {
            outcome,
            at_step,
            rollback_complete,
            after,
            ..
        } => note(
            &mut out,
            if *rollback_complete && outcome == "committed" {
                OK
            } else {
                FAIL
            },
            &format!(
                "batch {}{} — rollback {}, session {after}",
                outcome.to_uppercase(),
                at_step
                    .map(|at| format!(" at step {at}"))
                    .unwrap_or_default(),
                if *rollback_complete {
                    "complete"
                } else {
                    "INCOMPLETE"
                }
            ),
        ),
        Event::Shutdown { sessions } => note(
            &mut out,
            DIM,
            &format!("server shutting down, releasing {sessions} session(s)"),
        ),
        Event::LeaseExpired { sessions } => note(
            &mut out,
            DIM,
            &format!("client lease expired, releasing {sessions} session(s)"),
        ),
        // Shown rather than skipped: a viewer has to know a record was here and what it was, or
        // the recording quietly misses a step of the session it claims to be.
        Event::Oversized { of, bytes } => note(
            &mut out,
            FAIL,
            &format!("a `{of}` record was {bytes} bytes and was not stored"),
        ),
    }
    (!out.is_empty()).then_some(out)
}

/// A tool's arguments as one line. Kept short: the prompt is a reminder of what was asked, and the
/// transcript is where the whole of it lives.
fn render_args(args: &Value) -> String {
    let rendered = serde_json::to_string(args).unwrap_or_default();
    let clipped: String = rendered.chars().take(160).collect();
    let ellipsis = if clipped.chars().count() < rendered.chars().count() {
        "…"
    } else {
        ""
    };
    format!("{}{ellipsis}", visible(&clipped))
}

/// A result's text, clipped to what is watchable and saying how much was left out.
fn body(out: &mut String, text: &Capped, max_lines: usize) {
    if text.text.is_empty() {
        return;
    }
    let lines: Vec<&str> = text.text.lines().collect();
    let shown = match max_lines {
        0 => lines.len(),
        n => lines.len().min(n),
    };
    for l in &lines[..shown] {
        line(out, &visible(l));
    }
    // Two different elisions, and they are not the same fact: this one is the *rendering* holding
    // back, and `dropped` is the *transcript* having done so. A viewer who cannot tell them apart
    // does not know whether the rest exists.
    let hidden = lines.len() - shown;
    if hidden > 0 {
        line(
            out,
            &format!("{DIM}… {hidden} more line(s) in the transcript{RESET}"),
        );
    }
    if let Some(dropped) = text.dropped {
        line(
            out,
            &format!("{DIM}… {dropped} more byte(s) were not recorded (field cap){RESET}"),
        );
    }
}

/// A marked line between the frames. `text` is built from transcript values, so it is made
/// visible here — one of the two doors everything from the transcript comes through, the other
/// being [`body`].
fn note(out: &mut String, colour: &str, text: &str) {
    line(out, &format!("{colour}  · {}{RESET}", visible(text)));
}

fn suffix(detail: &Option<Capped>) -> String {
    detail
        .as_ref()
        .map(|d| format!(" — {}", d.text))
        .unwrap_or_default()
}

/// One terminal line. `\r\n`, because a player is driving a terminal and not writing a file.
fn line(out: &mut String, text: &str) {
    out.push_str(text);
    out.push_str("\r\n");
}

/// Text from the transcript, made safe to put in a frame a terminal will interpret.
///
/// **This is a security boundary, not tidying.** A cast frame is a stream of bytes a player writes
/// straight to a terminal, and the text in a transcript is whatever the *target* produced —
/// symbol names, strings out of a dump, a driver's own `DbgPrint`. A target chosen for analysis is
/// frequently the least trustworthy program anyone has, and it can put an escape sequence in a
/// string: OSC 52 writes the viewer's clipboard, others retitle the window, redraw what is already
/// on screen, or query the terminal and have it type the answer back. None of that is content;
/// all of it executes when someone plays the recording, on the machine of whoever was sent it.
///
/// So every control character from the transcript is rendered as a *visible* escape and never
/// passed through. The renderer's own styling is added outside this, from constants in this file,
/// which is the whole reason the two can be told apart at all: what this server writes is
/// interpreted, what the target wrote is shown.
fn visible(text: &str) -> String {
    if !text
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            // Kept, because the renderer builds lines out of them: a result is many lines and is
            // meant to be read as many lines. `\r` is not — a lone carriage return moves the
            // cursor back over what was already drawn.
            '\n' => out.push('\n'),
            '\t' => out.push('\t'),
            // `^[`, the caret notation a terminal cannot act on. `U+2028`/`U+2029` are not
            // control characters by `is_control` but do break a line in a renderer that knows
            // Unicode, so they are named too.
            c if c.is_control() => out.push_str(&format!("^{}", caret(c))),
            '\u{2028}' => out.push_str("<U+2028>"),
            '\u{2029}' => out.push_str("<U+2029>"),
            c => out.push(c),
        }
    }
    out
}

/// A control character in caret notation: `ESC` is `^[`, `NUL` is `^@`.
fn caret(c: char) -> char {
    match u32::from(c) {
        code @ 0..=0x1f => char::from_u32(code + 0x40).unwrap_or('?'),
        0x7f => '?',
        _ => '?',
    }
}

// SGR sequences, spelled out rather than pulled from a crate: there are six of them and they are
// the whole of this renderer's styling.
const RESET: &str = "\u{1b}[0m";
const DIM: &str = "\u{1b}[2m";
const PROMPT: &str = "\u{1b}[1;32m";
const TOOL: &str = "\u{1b}[1;36m";
const OK: &str = "\u{1b}[32m";
const FAIL: &str = "\u{1b}[1;31m";
const NOTE: &str = "\u{1b}[34m";
const STOP: &str = "\u{1b}[33m";
const MUTATION: &str = "\u{1b}[1;35m";

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::record::Recorder;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("windbg-mcp-cast-tests");
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir.join(format!("{name}-{}.jsonl", std::process::id()))
    }

    /// A transcript with one of everything a rendering has to cope with.
    fn transcript(name: &str) -> Options {
        let input = scratch(name);
        let _ = std::fs::remove_file(&input);
        let rec = Recorder::to_file(&input, 0).expect("a transcript");
        rec.write(Event::SessionOpen {
            session: "sess-1".to_string(),
            kind: "crash dump".to_string(),
            target: Capped::of(r"C:\dumps\a.dmp", 0),
            engine_pid: 42,
        });
        let call = rec.tool_request("go", Some(&serde_json::json!({ "session_id": "sess-1" })));
        rec.tool_result(
            call,
            false,
            "Breakpoint 0 hit\nnt!KeBugCheckEx:",
            Some(&serde_json::json!({
                "status": "ok",
                "command": "g",
                "stopped_at": "0xfffff8031ab10000",
                "interrupted": false,
                "output": "Breakpoint 0 hit",
            })),
        );
        rec.write(Event::Shutdown { sessions: 1 });
        Options {
            output: input.with_extension("cast"),
            input,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            title: None,
            idle_limit: DEFAULT_IDLE_LIMIT,
            max_lines: DEFAULT_MAX_LINES,
        }
    }

    /// Reads a cast back the way a player does: a header object, then one event array per line.
    fn read_cast(path: &Path) -> (Value, Vec<(f64, String, String)>) {
        let text = std::fs::read_to_string(path).expect("the cast exists");
        let mut lines = text.lines();
        let header: Value =
            serde_json::from_str(lines.next().expect("a header line")).expect("the header is JSON");
        let events = lines
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let event: Vec<Value> = serde_json::from_str(l)
                    .unwrap_or_else(|e| panic!("an event line is not an array ({e}): {l}"));
                assert_eq!(event.len(), 3, "an asciicast event is a 3-tuple: {l}");
                (
                    event[0].as_f64().expect("the time is a number"),
                    event[1].as_str().expect("the code is a string").to_string(),
                    event[2].as_str().expect("the data is a string").to_string(),
                )
            })
            .collect();
        (header, events)
    }

    /// The acceptance criterion: what comes out validates as asciicast v2.
    #[test]
    fn a_rendering_is_a_valid_asciicast_v2() {
        let options = transcript("valid");
        let summary = render(&options).expect("the render succeeds");
        assert_eq!(summary.unreadable, 0);
        assert!(summary.frames > 0);

        let (header, events) = read_cast(&options.output);
        assert_eq!(header["version"], 2);
        assert_eq!(header["width"], DEFAULT_WIDTH);
        assert_eq!(header["height"], DEFAULT_HEIGHT);
        assert!(
            header["timestamp"].as_u64().unwrap_or(0) > 1_700_000_000,
            "the header carries when this was recorded: {header}"
        );
        assert!(!events.is_empty());
        assert!(events.iter().all(|(_, code, _)| code == "o"));
        // Times are non-decreasing, which is the one thing a player cannot cope with.
        assert!(
            events.windows(2).all(|w| w[0].0 <= w[1].0),
            "an asciicast's times must not go backwards"
        );
        assert!(events.iter().all(|(t, _, _)| *t >= 0.0));
    }

    /// The timings are the recorded ones. This is the whole reason the feature exists: a cast
    /// reconstructed afterwards has to caption its own timing as illustrative.
    #[test]
    fn the_times_are_the_transcripts_own() {
        let options = transcript("timing");
        render(&options).expect("the render succeeds");
        let recorded: Vec<u64> = std::fs::read_to_string(&options.input)
            .expect("the transcript")
            .lines()
            .filter_map(|l| serde_json::from_str::<Record>(l).ok())
            .map(|r| r.mono_ms)
            .collect();
        let (_, events) = read_cast(&options.output);
        // Every frame's time is one of the recorded instants, to the millisecond.
        for (at, _, _) in &events {
            let ms = (at * 1000.0).round() as u64;
            assert!(
                recorded.contains(&ms),
                "{at}s is not an instant this transcript recorded: {recorded:?}"
            );
        }
    }

    /// What a viewer is actually shown: the call, its output, and the derived facts.
    #[test]
    fn the_rendering_shows_the_call_its_output_and_what_it_did() {
        let options = transcript("content");
        render(&options).expect("the render succeeds");
        let (_, events) = read_cast(&options.output);
        let screen: String = events.iter().map(|(_, _, data)| data.clone()).collect();
        for expected in [
            "go",                 // the tool
            "Breakpoint 0 hit",   // its output
            "0xfffff8031ab10000", // the stop the typed half derived
            "crash dump",         // the session it ran against
            "shutting down",      // the end of the transcript
        ] {
            assert!(
                screen.contains(expected),
                "`{expected}` is missing:\n{screen}"
            );
        }
        // A terminal recording, so every line ends with a carriage return.
        assert!(
            !screen.contains('\n')
                || screen.matches('\n').count() == screen.matches("\r\n").count()
        );
    }

    /// A transcript is **appended** to, so one file can hold several runs — and each run's
    /// `mono_ms` starts again at zero.
    ///
    /// Written into a cast as they stand, those offsets step backwards at the join and a player
    /// refuses the whole recording. The runs are laid end to end instead, which keeps the earlier
    /// one — it is the part somebody kept the file for.
    #[test]
    fn several_runs_in_one_file_render_as_one_rising_timeline() {
        let input = scratch("two-runs");
        let _ = std::fs::remove_file(&input);
        for run in 0..2 {
            let rec = Recorder::to_file(&input, 0).expect("a transcript");
            let call = rec.tool_request("modules", None);
            // Long enough that the second run's own offsets are unambiguously small numbers,
            // which is what would step backwards without the fix.
            std::thread::sleep(std::time::Duration::from_millis(30));
            rec.tool_result(call, false, &format!("run {run}"), None);
            rec.write(Event::Shutdown { sessions: 0 });
        }
        let options = Options {
            output: input.with_extension("cast"),
            input,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            title: None,
            idle_limit: DEFAULT_IDLE_LIMIT,
            max_lines: 0,
        };
        let summary = render(&options).expect("the render succeeds");
        assert_eq!(summary.runs, 2, "the file holds two runs");

        let (_, events) = read_cast(&options.output);
        assert!(
            events.windows(2).all(|w| w[0].0 <= w[1].0),
            "the join went backwards: {:?}",
            events.iter().map(|(t, _, _)| *t).collect::<Vec<_>>()
        );
        // Both runs are in it, in the order they happened.
        let screen: Vec<String> = events.iter().map(|(_, _, d)| d.clone()).collect();
        let of = |needle: &str| screen.iter().position(|d| d.contains(needle));
        assert!(of("run 0") < of("run 1"), "{screen:#?}");
        // And the second run really is offset past the first, rather than restarting.
        let second = events[of("run 1").expect("the second run is rendered")].0;
        let first = events[of("run 0").expect("the first run is rendered")].0;
        assert!(second > first, "{first} -> {second}");
    }

    /// Within a run, order comes from `seq` rather than from the order the lines happen to sit in
    /// — and the records are **reordered**, not merely restamped.
    ///
    /// The distinction is the whole test. Rising timestamps on lines still emitted in file order
    /// would satisfy a player and show a result *before* the request that produced it: a recording
    /// of something that did not happen, which is worse than one that will not play. So this
    /// asserts the content order and treats the times as the secondary claim.
    ///
    /// `Recorder::write` numbers under the same lock it writes under, so the two agree for
    /// anything this build produces. A file from a build *before* that fix has to render, and
    /// render correctly.
    #[test]
    fn a_file_whose_lines_are_out_of_order_is_reordered_not_just_restamped() {
        let input = scratch("out-of-order");
        let _ = std::fs::remove_file(&input);
        let rec = Recorder::to_file(&input, 0).expect("a transcript");
        let call = rec.tool_request("modules", None);
        rec.tool_result(call, false, "the answer", None);
        rec.write(Event::Shutdown { sessions: 0 });
        drop(rec);

        // The request and its result, swapped — as a race between two writers would have left
        // them before the numbering moved inside the file lock.
        let mut lines: Vec<String> = std::fs::read_to_string(&input)
            .expect("the transcript")
            .lines()
            .map(str::to_string)
            .collect();
        lines.swap(1, 2);
        std::fs::write(&input, lines.join("\n")).expect("rewrite");

        let options = Options {
            output: input.with_extension("cast"),
            input,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            title: None,
            idle_limit: 0.0,
            max_lines: 0,
        };
        render(&options).expect("the render succeeds");
        let (_, events) = read_cast(&options.output);
        let screen: Vec<String> = events.iter().map(|(_, _, d)| d.clone()).collect();
        let asked = screen
            .iter()
            .position(|d| d.contains("modules"))
            .unwrap_or_else(|| panic!("the call is not rendered: {screen:#?}"));
        let answered = screen
            .iter()
            .position(|d| d.contains("the answer"))
            .unwrap_or_else(|| panic!("the result is not rendered: {screen:#?}"));
        assert!(
            asked < answered,
            "the result was played before the call that produced it: {screen:#?}"
        );
        assert!(
            events.windows(2).all(|w| w[0].0 <= w[1].0),
            "times went backwards: {:?}",
            events.iter().map(|(t, _, _)| *t).collect::<Vec<_>>()
        );
    }

    /// Two servers pointed at one path, which [`Recorder::to_file`] allows: their records
    /// interleave in the file, and a reader taking it in order tells one story out of two.
    ///
    /// Grouped by the run each record names, so each server's session comes out whole. Without the
    /// `run` field the second `start` would look like the beginning of a single later run, and
    /// everything after it — two sets of sequence numbers, request ids and sessions, each numbered
    /// from scratch — would be attributed to it.
    #[test]
    fn two_servers_sharing_a_file_render_as_two_runs() {
        let input = scratch("interleaved");
        let _ = std::fs::remove_file(&input);
        // Two recorders on one path, writing alternately — which is what concurrent supervisors
        // produce, and what append mode is for.
        let first = Recorder::to_file(&input, 0).expect("a transcript");
        let second = Recorder::to_file(&input, 0).expect("the same transcript");
        let a = first.tool_request("registers", None);
        let b = second.tool_request("modules", None);
        first.tool_result(a, false, "from the first server", None);
        second.tool_result(b, false, "from the second server", None);
        first.write(Event::Shutdown { sessions: 0 });
        second.write(Event::Shutdown { sessions: 0 });

        let options = Options {
            output: input.with_extension("cast"),
            input,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            title: None,
            idle_limit: 0.0,
            max_lines: 0,
        };
        let summary = render(&options).expect("the render succeeds");
        assert_eq!(summary.runs, 2, "two servers wrote this file");

        let (_, events) = read_cast(&options.output);
        let screen: Vec<String> = events.iter().map(|(_, _, d)| d.clone()).collect();
        let at = |needle: &str| {
            screen
                .iter()
                .position(|d| d.contains(needle))
                .unwrap_or_else(|| panic!("`{needle}` is not rendered: {screen:#?}"))
        };
        // Each server's call and its answer are adjacent, rather than one server's result landing
        // between the other's call and its own.
        assert!(at("registers") < at("from the first server"), "{screen:#?}");
        assert!(at("modules") < at("from the second server"), "{screen:#?}");
        assert!(
            at("from the first server") < at("modules"),
            "the two runs are interleaved rather than laid end to end: {screen:#?}"
        );
        assert!(
            events.windows(2).all(|w| w[0].0 <= w[1].0),
            "times went backwards: {:?}",
            events.iter().map(|(t, _, _)| *t).collect::<Vec<_>>()
        );
    }

    /// A transcript whose tail was cut off mid-write still renders — that is what one record per
    /// `write_all` buys, and a renderer that refused the file would throw it away.
    #[test]
    fn a_truncated_transcript_still_renders_what_it_has() {
        let options = transcript("truncated");
        let mut text = std::fs::read_to_string(&options.input).expect("the transcript");
        text.push_str("{\"v\":1,\"seq\":99,\"at\":\"2026-08-16T06:00:00.0");
        std::fs::write(&options.input, &text).expect("write the truncated transcript");

        let summary = render(&options).expect("a truncated transcript still renders");
        assert_eq!(
            summary.unreadable, 1,
            "the torn line is reported, not hidden"
        );
        assert!(summary.frames > 0, "everything before it is still there");
        read_cast(&options.output);
    }

    /// A cast frame is bytes a player writes straight to a terminal, and the text in a transcript
    /// is whatever the **target** produced. So a target can put an escape sequence in a string and
    /// have it *execute* on the machine of whoever plays the recording.
    ///
    /// That is not hypothetical for this server: the targets are dumps and drivers chosen for
    /// analysis, frequently the least trustworthy program anyone has, and a recording is made
    /// precisely to be sent to somebody else. OSC 52 writes the viewer's clipboard; other
    /// sequences retitle the window, redraw the screen above, or query the terminal and have it
    /// type the answer back as input.
    ///
    /// Everything from the transcript is rendered visible; the renderer's own styling, added from
    /// constants outside that, still works. Both halves are asserted here, because a fix that
    /// escaped the styling too would leave a cast of unreadable noise.
    #[test]
    fn a_target_cannot_smuggle_terminal_control_sequences_into_a_cast() {
        let input = scratch("hostile-output");
        let _ = std::fs::remove_file(&input);
        let rec = Recorder::to_file(&input, 0).expect("a transcript");
        let call = rec.tool_request("execute", None);
        // OSC 52 (clipboard write), a window retitle, and a bare carriage return that would
        // overdraw the line above it.
        rec.tool_result(
            call,
            false,
            "\u{1b}]52;c;aGVsbG8=\u{7}pwned\u{1b}]0;gotcha\u{7}\roverdrawn",
            None,
        );
        let options = Options {
            output: input.with_extension("cast"),
            input,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            title: None,
            idle_limit: 0.0,
            max_lines: 0,
        };
        render(&options).expect("the render succeeds");

        let (_, events) = read_cast(&options.output);
        let screen: String = events.iter().map(|(_, _, d)| d.clone()).collect();
        // The renderer's own styling is intact...
        assert!(
            screen.contains(RESET),
            "the styling should survive: {screen:?}"
        );
        // ...and every escape the target wrote is shown rather than performed.
        assert!(
            !screen.contains("\u{1b}]"),
            "an OSC sequence from the target reached the frame: {screen:?}"
        );
        assert!(
            !screen.contains('\u{7}'),
            "a BEL from the target reached the frame: {screen:?}"
        );
        assert!(screen.contains("^["), "shown in caret notation: {screen:?}");
        // The text itself is still readable, which is the point of showing rather than dropping.
        assert!(
            screen.contains("pwned") && screen.contains("overdrawn"),
            "{screen:?}"
        );
        // A lone carriage return is not passed through — only the line endings this renderer
        // writes, which always follow a newline.
        assert_eq!(
            screen.matches('\r').count(),
            screen.matches("\r\n").count(),
            "a bare carriage return would overdraw the line above: {screen:?}"
        );
    }

    /// The rendering must never be written over the transcript it came from.
    ///
    /// The render would *succeed* — the records are in memory by the time the output is truncated
    /// — and the only JSONL copy of the session would be replaced by a rendering of it. Two ways
    /// in: `--out` naming the input, and a transcript already called `.cast`, whose default output
    /// is itself. Both are checked, and both before a single byte is read.
    #[test]
    fn a_rendering_never_overwrites_the_transcript_it_came_from() {
        let input = scratch("self-overwrite");
        let _ = std::fs::remove_file(&input);
        let rec = Recorder::to_file(&input, 0).expect("a transcript");
        rec.write(Event::Shutdown { sessions: 0 });
        drop(rec);
        let before = std::fs::read_to_string(&input).expect("the transcript");

        // Explicitly, with `--out`.
        let options = Options::parse(&[
            input.display().to_string(),
            "--out".to_string(),
            input.display().to_string(),
        ])
        .expect("parse");
        let error = render(&options).expect_err("this would destroy the transcript");
        assert!(error.contains("written over the transcript"), "{error}");

        // And by default, for a transcript that happens to be named `.cast`.
        let named_cast = input.with_extension("cast");
        std::fs::copy(&input, &named_cast).expect("copy");
        let options = Options::parse(&[named_cast.display().to_string()]).expect("parse");
        assert_eq!(options.output, options.input, "the default collides here");
        let error = render(&options).expect_err("this would destroy the transcript");
        assert!(error.contains("written over the transcript"), "{error}");

        assert_eq!(
            std::fs::read_to_string(&input).expect("the transcript"),
            before,
            "the transcript was modified by a render that should have refused"
        );
        let _ = std::fs::remove_file(&named_cast);
    }

    /// An empty or non-transcript file is refused with an explanation rather than producing a cast
    /// of nothing, which would look like a session in which nothing happened.
    #[test]
    fn a_file_that_is_not_a_transcript_is_refused() {
        let path = scratch("not-a-transcript");
        std::fs::write(&path, "hello\nthis is not JSON\n").expect("write");
        let options = Options::parse(&[path.display().to_string()]).expect("parse");
        let error = render(&options).expect_err("this is not a transcript");
        assert!(error.contains("no transcript records"), "{error}");
    }

    /// A long result is clipped to what is watchable, and says so — a viewer has to be able to
    /// tell "there was more" from "that was all of it".
    #[test]
    fn a_long_result_is_clipped_and_says_so() {
        let input = scratch("clipped");
        let _ = std::fs::remove_file(&input);
        let rec = Recorder::to_file(&input, 0).expect("a transcript");
        let call = rec.tool_request("modules", None);
        rec.tool_result(
            call,
            false,
            &(1..=100).map(|i| format!("line {i}\n")).collect::<String>(),
            None,
        );
        let options = Options {
            output: input.with_extension("cast"),
            input,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            title: None,
            idle_limit: 0.0,
            max_lines: 10,
        };
        render(&options).expect("the render succeeds");
        let (header, events) = read_cast(&options.output);
        assert!(
            header.get("idle_time_limit").is_none(),
            "`--idle-limit 0` plays it at the speed it happened: {header}"
        );
        let screen: String = events.iter().map(|(_, _, d)| d.clone()).collect();
        assert!(screen.contains("line 10"), "{screen}");
        assert!(!screen.contains("line 11"), "{screen}");
        assert!(screen.contains("90 more line(s)"), "{screen}");
    }

    /// The two elisions are different facts and must read differently: one is this renderer
    /// holding back, the other is the transcript never having had the bytes.
    #[test]
    fn a_field_the_transcript_capped_is_reported_separately() {
        let input = scratch("capped");
        let _ = std::fs::remove_file(&input);
        // A tiny field cap, so the transcript itself drops most of the result.
        let rec = Recorder::to_file(&input, 32).expect("a transcript");
        let call = rec.tool_request("modules", None);
        rec.tool_result(call, false, &"m".repeat(500), None);
        let options = Options {
            output: input.with_extension("cast"),
            input,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            title: None,
            idle_limit: DEFAULT_IDLE_LIMIT,
            max_lines: 0,
        };
        render(&options).expect("the render succeeds");
        let (_, events) = read_cast(&options.output);
        let screen: String = events.iter().map(|(_, _, d)| d.clone()).collect();
        assert!(
            screen.contains("were not recorded (field cap)"),
            "the viewer has to know the bytes were never kept:\n{screen}"
        );
    }

    /// The options, including the default output path — the one a caller gets by naming nothing.
    #[test]
    fn options_default_the_output_beside_the_transcript() {
        let options = Options::parse(&["run.jsonl".to_string()]).expect("parse");
        assert_eq!(options.output, PathBuf::from("run.cast"));
        assert_eq!(options.width, DEFAULT_WIDTH);
        assert_eq!(options.idle_limit, DEFAULT_IDLE_LIMIT);

        let options = Options::parse(&[
            "run.jsonl".to_string(),
            "--out".to_string(),
            "proof.cast".to_string(),
            "--width".to_string(),
            "80".to_string(),
            "--idle-limit".to_string(),
            "0".to_string(),
            "--title".to_string(),
            "MessageManager".to_string(),
        ])
        .expect("parse");
        assert_eq!(options.output, PathBuf::from("proof.cast"));
        assert_eq!(options.width, 80);
        assert_eq!(options.idle_limit, 0.0);
        assert_eq!(options.title.as_deref(), Some("MessageManager"));
    }

    /// A mistyped flag is an error with a name in it, not a silently ignored argument.
    #[test]
    fn a_bad_option_is_refused() {
        for (args, expected) in [
            (vec![], "no transcript named"),
            (vec!["--nope".to_string()], "unknown option"),
            (
                vec!["a.jsonl".to_string(), "--width".to_string()],
                "needs a value",
            ),
            (
                vec![
                    "a.jsonl".to_string(),
                    "--width".to_string(),
                    "wide".to_string(),
                ],
                "whole number",
            ),
            (
                vec!["a.jsonl".to_string(), "b.jsonl".to_string()],
                "unexpected argument",
            ),
        ] {
            let error = Options::parse(&args).expect_err("this should not parse");
            assert!(
                error.contains(expected),
                "`{error}` should mention `{expected}`"
            );
        }
    }
}
