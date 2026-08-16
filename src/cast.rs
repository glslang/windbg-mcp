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
    let mut out = String::new();
    writeln!(out, "{}", header(options, &records)).map_err(|e| e.to_string())?;
    let mut frames = 0;
    for record in &records {
        let Some(text) = frame(record, options.max_lines) else {
            continue;
        };
        // `[time, "o", data]`, where the time is the recorded one in seconds. Serialized as an
        // array so the escaping is serde's problem — a debugger's output carries control
        // characters, quotes and half-finished escape sequences, and a hand-built line would be
        // the one thing that could make a cast unplayable.
        let event = Value::Array(vec![
            Value::from(record.mono_ms as f64 / 1000.0),
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
        duration_ms: records.last().map_or(0, |r| r.mono_ms),
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
    pub duration_ms: u64,
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
                Some(format!("windbg-mcp — {kind} {target}"))
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
                &format!("{DIM}windbg-mcp {version} — session transcript{RESET}"),
            );
        }
        Event::ToolRequest { tool, args, .. } => {
            let args = args.as_ref().map_or_else(String::new, render_args);
            line(
                &mut out,
                &format!("{PROMPT}${RESET} {TOOL}{tool}{RESET} {args}"),
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
            &format!("session {session} — {kind} `{target}` (engine pid {engine_pid})"),
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
                step.as_deref()
                    .map(|s| format!(" [{s}]"))
                    .unwrap_or_default()
            ),
        ),
        Event::Assertion { step, detail, .. } => note(
            &mut out,
            FAIL,
            &format!("assertion did not hold at {step}: {}", detail.text),
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
    }
    (!out.is_empty()).then_some(out)
}

/// A tool's arguments as one line. Kept short: the prompt is a reminder of what was asked, and the
/// transcript is where the whole of it lives.
fn render_args(args: &Value) -> String {
    let rendered = serde_json::to_string(args).unwrap_or_default();
    let clipped: String = rendered.chars().take(160).collect();
    match clipped.chars().count() < rendered.chars().count() {
        true => format!("{DIM}{clipped}…{RESET}"),
        false => format!("{DIM}{clipped}{RESET}"),
    }
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
        line(out, l);
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

fn note(out: &mut String, colour: &str, text: &str) {
    line(out, &format!("{colour}  · {text}{RESET}"));
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
            target: r"C:\dumps\a.dmp".to_string(),
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
