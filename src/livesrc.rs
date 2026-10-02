//! A [`sk::RawSource`] over a transport the **operator** supplies — `FOLLOWUPS.md` item 103.
//!
//! Gate S1 decodes a guest's VTL1 out of a byte source and gate S3 holds one open as a session, and
//! both have only ever been driven by a Hyper-V capture. The seam was built for this:
//! [`sk::RawSource`]'s own doc says *"a future driver-backed live source joins here and changes
//! nothing above it"*, [`sk::RawSource::max_read`] exists because `HvCallReadGpa` moves at most
//! sixteen bytes, and [`sk::ReadFailure::Refused`] exists **for** the live case, because H4 measured
//! that hypercall answering `HV_STATUS_SUCCESS` with zeros and a per-access `ReadIntercept`. Until
//! this module there was no implementation, so `Refused` had never been produced by anything but a
//! fixture.
//!
//! # Why a subprocess, and why this repository ships no transport
//!
//! Reading another partition's VTL1 live needs something this repository will not contain. Every
//! route measured on the bench — `hvlib.dll` with its own kernel driver, a hypercall through a
//! test-signed driver of our own — is a component the operator installs, test-signs and accepts the
//! posture of. That is item 103's standing decision: **the repository distributes no driver and the
//! operator supplies the transport.** It is the same shape as the live-kernel tier, which needs
//! KDNET wiring and a local profile, and the engine bundle, which needs a one-time copy.
//!
//! So the seam is a **child process speaking a line protocol on its stdio**. What ships here is the
//! client half, which contains no privileged code, links nothing, and can be read in one sitting.
//! The operator's half can be anything that can read their guest: on this bench it is a Python
//! script driving `hvlib`, and a second mode of the same script driving `HvCallReadGpa` through the
//! probe driver — which is the one that *refuses*.
//!
//! A DLL with an agreed export would have been the other option and is worse here: it would put
//! unsafe FFI and a vendor ABI in this crate, and a provider that `__fastfail`s — which gate S0
//! measured `vmsavedstatedumpprovider.dll` doing — would take the whole process down. A child
//! process that dies costs one read and reports why.
//!
//! # The protocol
//!
//! Requests are one line of ASCII on the child's stdin. Responses are one status line on its
//! stdout, and for a successful read exactly the requested bytes after it.
//!
//! **The transport opens by printing [`READY_LINE`], and everything before that is ignored.** That
//! is not politeness about banners: a provider an operator installs prints during its own setup, and
//! on this bench `hvlib.py` prints a partition menu with an ordinary `print()` — so the client's
//! first read would otherwise take `[ 0 ] Lab Guest Hyper-V` as a `SHAPE` reply. The alternative was
//! for the transport to redirect its own stdout around the provider, and that was **tried and
//! abandoned**: duplicating the descriptor and pointing `fd 1` elsewhere crashed the Python host
//! with an access violation inside its allocator, deterministically, every run. A sentinel costs one
//! line and needs the provider to cooperate about nothing.
//!
//! Skipped lines are echoed to this process's stderr with a `transport:` prefix, because a
//! misconfigured provider's explanation of itself is the thing an operator most needs to see.
//!
//! ```text
//! <- (any number of lines the provider prints while starting)
//! <- windbg-mcp-gpa/1
//! -> SHAPE
//! <- SHAPE cr3=0x1201000 vtl_enabled=1 paging=long cr0=0x80050033 cr4=0x350ef8 efer=0xd01 max_read=4096
//! -> READ 0xCD12DF 16
//! <- OK 16
//! <- <16 raw bytes>
//! -> READ 0x107593000 16
//! <- REFUSED ReadIntercept
//! -> READ 0xFFFFFFFFFF 16
//! <- NOTPRESENT
//! -> READ 0x1000 16
//! <- ERROR the driver is not loaded
//! ```
//!
//! Every field of `SHAPE` is optional but `max_read`, because [`sk::GuestShape`] is deliberately a
//! bag of maybes: a source that cannot read `EFER` must say so rather than have the decode read a
//! missing register as a machine not in long mode. An unknown key is **refused** rather than
//! ignored — a transport whose `cr3` was misspelled would otherwise look like a guest with no
//! page-table root, which is a different and much more plausible-looking result.
//!
//! The four status words are the four [`sk::ReadFailure`] variants, and keeping them distinct is the
//! whole point of the trait: a source that collapsed them would produce silent zeros exactly where
//! the protected memory is.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::sk::{self, Gpa, GuestShape, PagingMode, ReadFailure, Reader};

pub(crate) const LIVE_FLAG: &str = "--sk-live";

/// The line a transport prints when its own setup is finished and stdout is the protocol's.
pub(crate) const READY_LINE: &str = "windbg-mcp-gpa/1";

/// How many lines of a transport's own output to skip before giving up on the sentinel.
///
/// A bound rather than reading until it appears: a transport that prints the wrong thing — the wrong
/// program, or one writing a log to stdout — is refused instead of being read until it exits.
///
/// **It bounds completed lines and not time, and there is no read deadline anywhere in this module.**
/// A transport that starts and then produces no newline at all blocks this role indefinitely: the
/// length bound in [`Transport::line`] only fires once [`MAX_LINE_BYTES`] have *arrived*, and
/// [`TEARDOWN_GRACE`] applies after `Drop` has begun, which a blocked read never reaches. So a
/// provider that hangs during startup leaves `--sk-live` and its child running until the operator
/// interrupts it.
///
/// That is **declined rather than unnoticed** (raised in review on #434). The remedy is a watchdog —
/// a reader thread, or non-blocking IO plus a deadline on every exchange — which is real machinery in
/// a role that is a foreground command, run by the operator who wrote the transport, and
/// interruptible from the terminal where its diagnostics are already printing. The same hang in the
/// MCP server would be a different judgement, and this module is deliberately not reachable from it:
/// see `main.rs`'s dispatch, and gate S5x for the other reason.
const MAX_BANNER_LINES: usize = 64;

/// The most one line of a transport's output may be. See [`Transport::line`].
const MAX_LINE_BYTES: u64 = 64 * 1024;

/// How long [`LiveSource`]'s teardown waits for the transport to exit before killing it.
///
/// A bound rather than a plain `wait()`, because `wait()` returns an error only on a real failure
/// and **not** because the child is still alive — so a transport that ignores its stdin closing, or
/// hangs tearing its own provider down, would block teardown for ever and never reach the kill.
const TEARDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// The most a transport may declare for `max_read`.
///
/// Not a protocol limit but a guard on *our* allocation: `read_chunk` is handed a buffer by
/// [`Reader`], which sizes it from this number, so a transport answering `max_read=0xFFFFFFFF`
/// would have us allocate 4 GB before a byte was read.
const MAX_DECLARED_READ: usize = 1 << 20;

/// One request/response exchange with a transport, over anything readable and writable.
///
/// Generic on purpose: the framing is the part that can be wrong in ways a live guest would hide,
/// so it is tested against in-memory pipes rather than only against the bench's own server.
pub(crate) struct Transport<R: BufRead, W: Write> {
    reader: R,
    writer: W,
    max_read: usize,
    /// Set by a framing fault, after which the stream's position is unknown.
    poisoned: bool,
}

/// What a transport said about the processor, before it is turned into a [`GuestShape`].
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ShapeReply {
    pub(crate) shape: GuestShape,
    pub(crate) max_read: usize,
}

impl<R: BufRead, W: Write> Transport<R, W> {
    pub(crate) fn new(reader: R, writer: W) -> Transport<R, W> {
        Transport {
            reader,
            writer,
            // Until `SHAPE` answers. One byte is a legal transfer width and a useless one, which is
            // the right default for a field that must not be guessed generously.
            max_read: 1,
            poisoned: false,
        }
    }

    /// Read past whatever the transport printed while starting, up to its sentinel.
    ///
    /// Returns the lines it skipped, so the caller can show them: they are the only explanation a
    /// misconfigured provider gives.
    pub(crate) fn await_ready(&mut self) -> Result<Vec<String>> {
        let mut skipped = Vec::new();
        for _ in 0..MAX_BANNER_LINES {
            let line = self.line()?;
            if line.trim() == READY_LINE {
                return Ok(skipped);
            }
            skipped.push(line);
        }
        bail!(
            "the transport printed {MAX_BANNER_LINES} lines without {READY_LINE:?}; it is probably \
             not a transport. What it said: {skipped:?}"
        )
    }

    /// Send one request line — **the only path to the writer**, and that is the point.
    ///
    /// Every exchange has exactly two IO chokepoints, this and [`Transport::line`], and the rule for
    /// both is total: *refuse a poisoned transport before touching a pipe, and poison it on any
    /// failure.* Three review rounds on #434 arrived at it one site at a time — the guard first
    /// checked only on the read side of an exchange that writes first, then poisoned only on the
    /// failures after a status line had been read — so it is stated here as a contract rather than
    /// left to be rediscovered at the next call site.
    ///
    /// **Every error path, and why each one poisons:**
    ///
    /// | path | poisons | because |
    /// |---|---|---|
    /// | already poisoned | n/a | nothing is written; this is the refusal |
    /// | `write_all`/`flush` fails | **yes** | the request may be half on the wire, so the child's next read is a truncated line |
    /// | `line` read fails, or EOF, or over-long | **yes** | bytes may already be consumed, and the over-long case certainly consumed [`MAX_LINE_BYTES`] |
    /// | `parse_status` says `REFUSED`/`NOTPRESENT` | **no** | a complete status line with no payload: the stream is still aligned, and poisoning would make one protected page kill the walk |
    /// | `parse_status` fails otherwise, or a payload is short or unsent | **yes** | sender and reader disagree about where the next line starts |
    ///
    /// Only the one row that is an *answer* declines to poison, which is why it is the row with the
    /// reason spelled out. With the writer private to this method, forgetting the check means not
    /// sending anything at all.
    fn send(&mut self, request: &str) -> Result<()> {
        if self.poisoned {
            bail!(
                "this transport desynchronised on an earlier framing fault, so nothing further may \
                 be sent to it"
            );
        }
        // A partial write leaves the child reading a truncated request, so a write that fails is a
        // framing fault like any other.
        self.poisoned = true;
        self.writer.write_all(request.as_bytes())?;
        self.writer.flush()?;
        // Cleared only once the whole request is on the wire. Set-then-clear rather than
        // set-on-failure so that a `?` added to this method later cannot skip it.
        self.poisoned = false;
        Ok(())
    }

    /// Ask for the processor state, and remember the transfer width it declares.
    pub(crate) fn shape(&mut self) -> Result<ShapeReply> {
        self.send("SHAPE\n")?;
        let line = self.line()?;
        let reply = parse_shape(&line)?;
        self.max_read = reply.max_read;
        Ok(reply)
    }

    /// Fill `out` from guest physical memory, or say why not.
    fn read_chunk(&mut self, gpa: Gpa, out: &mut [u8]) -> Result<(), ReadFailure> {
        self.send(&format!("READ {:#X} {}\n", gpa.0, out.len()))
            .map_err(|e| ReadFailure::SourceError {
                detail: format!("sending the request failed: {e}"),
            })?;
        let line = self.line().map_err(|e| ReadFailure::SourceError {
            detail: format!("reading the status line failed: {e}"),
        })?;
        // A framing fault **poisons the transport**, because after one the stream's position is no
        // longer known and this protocol has no resync token to recover it with. The case that makes
        // this necessary rather than tidy: `OK 4` against a 16-byte request used to return `Short`
        // without consuming the four bytes it announced, and the decode carries on after a failed
        // read — so the *next* request read those bytes as its status line, and every exchange after
        // that was misaligned. Consuming the announced bytes instead would not fix it, because a
        // transport that announced four and sends two leaves the same problem one step later.
        let status = parse_status(&line, out.len()).inspect_err(|failure| {
            if framing_fault(failure) {
                self.poisoned = true;
            }
        })?;
        match status {
            // A short count is not an error to report later: the trait says a short read *is* a
            // failed read, so it is one here rather than something a caller might judge on.
            Some(got) if got != out.len() => {
                self.poisoned = true;
                Err(ReadFailure::Short {
                    got,
                    want: out.len(),
                })
            }
            Some(got) => {
                self.reader.read_exact(&mut out[..got]).map_err(|e| {
                    self.poisoned = true;
                    ReadFailure::SourceError {
                        detail: format!(
                            "the transport announced {got} bytes and did not send them: {e}"
                        ),
                    }
                })?;
                Ok(())
            }
            None => unreachable!("parse_status returns Err for every non-OK status"),
        }
    }

    /// One line of the transport's output, bounded.
    ///
    /// **The bound is on the line's length as well as on the number of lines**, because
    /// [`MAX_BANNER_LINES`] limits only the count: a transport that writes a binary log to its
    /// stdout, or any provider that prints without a newline, would otherwise grow this buffer
    /// until the process ran out of memory. `read_line` has no limit of its own. The failure is a
    /// misconfigured transport rather than a hostile one — the operator wrote it — but *out of
    /// memory* is the wrong way to report that, and the skipped lines are echoed to stderr, so a
    /// gigabyte of them would be printed as well as held.
    ///
    /// A fresh `take` per call, so the allowance is per line rather than per transport.
    ///
    /// **Any failure poisons the transport**, and that is total rather than a list: an `Err` from here
    /// may have consumed part of a frame — the over-long case certainly consumed [`MAX_LINE_BYTES`] —
    /// so the stream position is no longer known. The call sites used to decide this, which meant the
    /// rule was as complete as whoever wrote the last one remembered it: `read_chunk` poisoned on a
    /// bad status line and on a short payload but not on a failed *read* of the status line, so an
    /// over-long line left the flag clear and the next request walked into the leftovers. Deciding it
    /// here makes the caller's list unnecessary. Raised in review on #434, as the third finding on
    /// this one rule.
    fn line(&mut self) -> Result<String> {
        let outcome = self.read_one_line();
        if outcome.is_err() {
            self.poisoned = true;
        }
        outcome
    }

    fn read_one_line(&mut self) -> Result<String> {
        if self.poisoned {
            bail!(
                "this transport desynchronised on an earlier framing fault, so its stream position \
                 is unknown and nothing further can be read from it"
            );
        }
        let mut line = String::new();
        // `Read::take` by its full path with an explicit `&mut R` receiver: written as
        // `self.reader.by_ref().take(..)` the auto-deref picks `take` on `R` itself and moves the
        // reader out of `self`, which does not compile.
        let mut limited = std::io::Read::take(&mut self.reader, MAX_LINE_BYTES);
        let read = limited.read_line(&mut line)?;
        if read == 0 {
            bail!("the transport closed its stdout");
        }
        // Hitting the allowance with no newline is the overlong case, and it has to be told from a
        // final line at EOF, which also arrives without one — that one is short and is legal.
        if read as u64 == MAX_LINE_BYTES && !line.ends_with('\n') {
            bail!(
                "the transport sent {MAX_LINE_BYTES} bytes with no newline; a status line is one \
                 line, so this is not one"
            );
        }
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }
}

/// `SHAPE cr3=0x... max_read=...` into the shape the decode takes.
///
/// An unknown or malformed key is an error rather than a default: see the module docs.
pub(crate) fn parse_shape(line: &str) -> Result<ShapeReply> {
    let rest = line
        .strip_prefix("SHAPE")
        .with_context(|| format!("expected a SHAPE reply, got {line:?}"))?;
    let mut reply = ShapeReply::default();
    let mut max_read = None;
    for field in rest.split_whitespace() {
        let (key, value) = field
            .split_once('=')
            .with_context(|| format!("field {field:?} is not key=value"))?;
        match key {
            "cr0" => reply.shape.cr0 = Some(number(key, value)?),
            "cr3" => reply.shape.cr3 = Some(number(key, value)?),
            "cr4" => reply.shape.cr4 = Some(number(key, value)?),
            "efer" => reply.shape.efer = Some(number(key, value)?),
            // Kept as `u64` here and narrowed only after the bound is applied. Casting first is
            // target-width-dependent: on the shipped `i686-pc-windows-msvc` image a declaration of
            // `4294967297` truncates to `1`, passes the bound, and the decode then runs the whole
            // walk as tens of millions of one-byte exchanges instead of refusing the handshake.
            // Raised in review on #434.
            "max_read" => max_read = Some(number(key, value)?),
            "vtl_enabled" => {
                reply.shape.vtl_enabled = Some(match value {
                    "1" => true,
                    "0" => false,
                    other => bail!("vtl_enabled must be 0 or 1, got {other:?}"),
                })
            }
            "paging" => {
                reply.shape.paging_mode = Some(match value {
                    "long" => PagingMode::Long,
                    other => bail!("this decode only walks long mode; transport said {other:?}"),
                })
            }
            // The transport's own way of saying the VTL could not be selected. On a VBS-off guest
            // this *is* the result, so it travels rather than failing the run.
            "switch_refused" => reply.shape.switch_refused = Some(value.replace('_', " ")),
            // A register the transport was asked for and could not get. Recorded with its reason,
            // so a report says which question went unanswered.
            "unreadable" => {
                let (name, why) = value.split_once(':').unwrap_or((value, "no reason given"));
                reply.shape.unreadable.push((
                    match name {
                        "cr0" => "cr0",
                        "cr3" => "cr3",
                        "cr4" => "cr4",
                        "efer" => "efer",
                        other => bail!("unreadable names an unknown register {other:?}"),
                    },
                    why.replace('_', " "),
                ));
            }
            other => bail!(
                "unknown SHAPE field {other:?}; a misspelled key would read as a guest that \
                 cannot answer, so it is refused instead"
            ),
        }
    }
    let declared = max_read.context("SHAPE must declare max_read")?;
    if declared == 0 || declared > MAX_DECLARED_READ as u64 {
        bail!("max_read={declared} is outside 1..={MAX_DECLARED_READ}");
    }
    // Only now, and still fallibly: the bound above already guarantees it fits, so a failure here
    // would mean the bound and the target width disagree, which is worth an error rather than a cast.
    reply.max_read = usize::try_from(declared)
        .with_context(|| format!("max_read={declared} does not fit this build's usize"))?;
    Ok(reply)
}

/// A status line into either a byte count to read, or the failure it names.
///
/// `want` is only used to reject a count larger than what was asked for: a transport that announced
/// more bytes than the buffer holds must not be allowed to decide how much is read.
pub(crate) fn parse_status(line: &str, want: usize) -> Result<Option<usize>, ReadFailure> {
    let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
    match word {
        "OK" => {
            let got: usize = rest.trim().parse().map_err(|_| ReadFailure::SourceError {
                detail: format!("OK with an unparseable count: {line:?}"),
            })?;
            if got > want {
                return Err(ReadFailure::SourceError {
                    detail: format!("transport announced {got} bytes for a {want}-byte request"),
                });
            }
            Ok(Some(got))
        }
        // The variant this whole module exists to be able to produce: the source was told no, per
        // access. Bytes may well have been written into a buffer; they are not an answer.
        "REFUSED" => Err(ReadFailure::Refused {
            detail: if rest.trim().is_empty() {
                "the transport refused and gave no detail".to_string()
            } else {
                rest.trim().to_string()
            },
        }),
        "NOTPRESENT" => Err(ReadFailure::NotPresent),
        "ERROR" => Err(ReadFailure::SourceError {
            detail: rest.trim().to_string(),
        }),
        other => Err(ReadFailure::SourceError {
            detail: format!("unknown status word {other:?} in {line:?}"),
        }),
    }
}

/// Whether a failure leaves bytes on the wire that nothing has read.
///
/// `Refused`, `NotPresent` and a transport-reported `ERROR` are *answers*: the status line is
/// complete and no payload follows, so the stream is still aligned and the next request is fine.
/// A malformed status, or an announced length this side will not accept, means the sender and the
/// reader disagree about where the next line starts.
fn framing_fault(failure: &ReadFailure) -> bool {
    match failure {
        ReadFailure::Refused { .. } | ReadFailure::NotPresent => false,
        ReadFailure::Short { .. } => true,
        // `SourceError` covers both: `ERROR <detail>` from the transport, which is an answer, and
        // an unparseable or over-long `OK`, which is not. The detail is not inspected to tell them
        // apart -- matching on a message is how that goes wrong later -- so this is conservative
        // and poisons both. Costing an operator one re-run beats reading a misaligned stream.
        ReadFailure::SourceError { .. } => true,
    }
}

fn number(key: &str, value: &str) -> Result<u64> {
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse(),
    };
    parsed.with_context(|| format!("{key}={value:?} is not a number"))
}

/// The operator's transport, running as a child process.
pub(crate) struct LiveSource {
    child: Child,
    /// `Option` so [`Drop`] can **take** it: dropping the transport closes the child's stdin, and
    /// until that pipe closes a well-behaved transport is still waiting for a request, so a `wait()`
    /// with it open hangs. `Drop::drop` runs before any field is dropped, so field order cannot do
    /// this for us.
    transport: std::cell::RefCell<Option<Transport<BufReader<ChildStdout>, ChildStdin>>>,
    shape: GuestShape,
    max_read: usize,
}

impl LiveSource {
    /// Spawn `command` and complete the `SHAPE` handshake.
    ///
    /// The handshake is at the open rather than on first read, for the same reason
    /// [`sk::RawSource::shape`] is documented as cheap: a transport that cannot say what processor
    /// it is reading should fail before a decode starts walking from a root it invented.
    pub(crate) fn spawn(command: &str) -> Result<LiveSource> {
        let mut parts = split_command(command);
        let program = parts
            .first()
            .cloned()
            .context("the transport command line is empty")?;
        let mut command = Command::new(&program);
        command
            .args(parts.split_off(1))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Deliberately **not** piped: a transport's diagnostics go to this process's own stderr,
            // where an operator debugging their script can see them, and a pipe nothing drains would
            // deadlock the child the moment it filled. The same rule
            // `.claude/rules/powershell-scripts.md` states for driving this server from a script.
            .stderr(Stdio::inherit());
        let mut child = {
            // Every process creation in this crate takes this, and a unit test enforces it. The
            // hazard is not a race between two spawns: a worker's protocol-channel handles are
            // marked inheritable for a window, and **any** child started during that window
            // inherits them — a process holding a worker's message write end keeps that pipe from
            // ever reporting EOF, so the supervisor never learns the worker exited. This role runs
            // before the runtime and holds no session, but the flag is a property of the process
            // rather than of the spawn that set it, so "this one cannot collide" is exactly the
            // reasoning the guard exists to make unnecessary. Held across the creation and no
            // longer — the transport runs for the whole decode.
            let _guard = crate::engine::spawn_guard();
            command
                .spawn()
                .with_context(|| format!("spawning the transport {program:?} failed"))?
        };
        let stdin = child.stdin.take().context("the child has no stdin")?;
        let stdout = child.stdout.take().context("the child has no stdout")?;
        // **Constructed before the handshake, not after**, so that every failure below runs this
        // type's `Drop` and the transport is reaped. Dropping a bare `std::process::Child` neither
        // kills nor waits for the process, so a `?` on the handshake used to leave a transport
        // running with whatever privileged provider and driver handles it had opened — and the CLI
        // reported failure and exited, so nothing would ever close them. The shape is a placeholder
        // until `handshake` fills it in; a source whose handshake failed is returned to no caller
        // and so reaches no `Reader`.
        let mut source = LiveSource {
            child,
            transport: std::cell::RefCell::new(Some(Transport::new(BufReader::new(stdout), stdin))),
            shape: GuestShape::default(),
            max_read: 1,
        };
        source.handshake()?;
        Ok(source)
    }

    /// The `SHAPE` exchange, run against a source that already owns its child.
    fn handshake(&mut self) -> Result<()> {
        let mut held = self.transport.borrow_mut();
        let transport = held.as_mut().context("the transport was already closed")?;
        for line in transport
            .await_ready()
            .context("the transport never said it was ready")?
        {
            eprintln!("transport: {line}");
        }
        let reply = transport.shape().context("the SHAPE handshake failed")?;
        drop(held);
        self.shape = reply.shape;
        self.max_read = reply.max_read;
        Ok(())
    }
}

impl Drop for LiveSource {
    fn drop(&mut self) {
        // Closing stdin is the transport's cue to exit, which lets an operator's script tear its own
        // provider down in order — on this bench that means `SdkCloseAllPartitions` and a driver
        // handle. So the kill is a fallback rather than the method, because a provider killed
        // mid-read can leave that handle open.
        self.transport.borrow_mut().take();
        reap(&mut self.child, TEARDOWN_GRACE);
    }
}

/// Wait for a transport to exit, then kill it if it will not.
///
/// **Polled to a deadline rather than waited on.** `Child::wait` answers an error only when the wait
/// itself fails, never because the child is still alive — so a transport that ignores EOF, or hangs
/// tearing its provider down, would block here for ever and the kill would be unreachable. An
/// earlier version did exactly that, and its comment called the kill a fallback while nothing could
/// reach it.
///
/// The grace is a parameter rather than read from [`TEARDOWN_GRACE`] so that a test can pin the
/// bound: at the constant it would take ten seconds to find out whether the bound exists at all.
fn reap(child: &mut Child, grace: std::time::Duration) {
    let deadline = std::time::Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            // Either the grace expired or the wait itself failed. Both end the same way.
            _ => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

impl sk::RawSource for LiveSource {
    fn shape(&self) -> GuestShape {
        self.shape.clone()
    }

    fn max_read(&self) -> usize {
        self.max_read
    }

    fn read_chunk(&self, gpa: Gpa, out: &mut [u8]) -> Result<(), ReadFailure> {
        match self.transport.borrow_mut().as_mut() {
            Some(transport) => transport.read_chunk(gpa, out),
            // Only reachable if a read were attempted during teardown. It is a source error rather
            // than an `unwrap`, because a decode must never be able to panic on a transport's state.
            None => Err(ReadFailure::SourceError {
                detail: "the transport has already been closed".to_string(),
            }),
        }
    }
}

/// Split a command line on whitespace, honouring double quotes.
///
/// Not a shell: there is no expansion, no escaping and no single-quote handling, because the string
/// comes from an operator's own command line and a surprise expansion in *this* role would run
/// something they did not type.
///
/// **Quoting groups whitespace; it does not create a word.** A token is emitted only when it has
/// accumulated something, so `""` contributes no argument at all and an explicit empty positional
/// cannot be expressed here — a transport needing one is named through a wrapper script instead.
/// Raised in review on #435, against the shipped skill that documented this grammar.
fn split_command(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in command.chars() {
        match ch {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// `--sk-live`: drive gate S1's decode against an operator-supplied live transport.
pub(crate) fn run(args: &[String]) -> Result<()> {
    let mut transport = None;
    let mut image = None;
    let mut cross_check = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--transport" => {
                transport = Some(
                    iter.next()
                        .context("--transport needs a command line")?
                        .clone(),
                )
            }
            "--image" => image = Some(iter.next().context("--image needs a path")?.clone()),
            "--cross-check" => cross_check = true,
            other => bail!("unknown argument {other:?}\n\n{}", usage()),
        }
    }
    let transport = transport.context(usage())?;
    let image = image.context("--image is required: identification is against it")?;

    let disk = sk::DiskImage::open(std::path::Path::new(&image)).map_err(|e| anyhow::anyhow!(e))?;
    println!("build      {}", crate::BUILD_VERSION);
    println!(
        "image      {} ({} bytes, {} sections, timestamp {:#010X})",
        disk.path, disk.file_size, disk.identity.sections, disk.identity.timestamp
    );
    println!("transport  {transport}");

    let source = LiveSource::spawn(&transport)?;
    let shape = sk::RawSource::shape(&source);
    println!(
        "shape      cr3={} vtl_enabled={:?} paging={:?} max_read={}",
        shape
            .cr3
            .map(|v| format!("{v:#X}"))
            .unwrap_or_else(|| "none".into()),
        shape.vtl_enabled,
        shape.paging_mode,
        sk::RawSource::max_read(&source)
    );
    for (name, why) in &shape.unreadable {
        println!("           {name} unreadable: {why}");
    }

    let reader = Reader::new(&source);
    match sk::locate(&reader, &disk, cross_check) {
        // `report_landmarks` ends with the read counts, so nothing is printed here on this arm:
        // a second copy would be a figure that can disagree with itself.
        Ok(landmarks) => crate::skinspect::report_landmarks(&landmarks),
        // A refusal is an answer here exactly as it is for a capture, and on a transport that
        // refuses VTL1 per access it is the *expected* answer — so this arm has to carry the
        // counts itself. They are the point of the whole exercise, and the reason `ReadStats` is
        // counted at the primitive rather than by each caller: `refused` is above zero only if a
        // source really refused, per access, which no capture can do.
        Err(why) => {
            println!("\nnot walkable: {}", crate::skinspect::refusal(&why));
            let stats = reader.stats();
            println!(
                "reads      {} attempted, {} failed, {} refused, {} bytes",
                stats.attempted, stats.failed, stats.refused, stats.bytes
            );
        }
    }
    Ok(())
}

fn usage() -> String {
    format!(
        "usage: windbg-mcp {LIVE_FLAG} --transport \"<command line>\" --image <securekernel.exe> \
         [--cross-check]\n\n\
         The transport is a program the OPERATOR supplies, speaking the line protocol in \
         src/livesrc.rs on its stdio. This repository ships none."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A canned server: the framing is what can be wrong in ways a live guest would hide, so it is
    /// exercised against bytes rather than only against the bench.
    fn exchange(script: &str) -> Transport<Cursor<Vec<u8>>, Vec<u8>> {
        Transport::new(Cursor::new(script.as_bytes().to_vec()), Vec::new())
    }

    #[test]
    fn a_shape_reply_becomes_the_shape_the_decode_takes() {
        let reply = parse_shape(
            "SHAPE cr0=0x80050033 cr3=0x1201000 cr4=0x350ef8 efer=0xd01 vtl_enabled=1 \
             paging=long max_read=4096",
        )
        .unwrap();
        assert_eq!(reply.max_read, 4096);
        assert_eq!(reply.shape.cr3, Some(0x1201000));
        assert_eq!(reply.shape.cr0, Some(0x8005_0033));
        assert_eq!(reply.shape.vtl_enabled, Some(true));
        assert_eq!(reply.shape.paging_mode, Some(PagingMode::Long));
        assert!(reply.shape.unreadable.is_empty());
    }

    #[test]
    fn a_misspelled_shape_key_is_refused_rather_than_read_as_a_guest_with_no_root() {
        // The failure this guard exists for: `cr_3` silently ignored leaves `cr3: None`, which the
        // decode reports as `NotWalkable::NoRoot` -- a plausible-looking result from a typo.
        let err = parse_shape("SHAPE cr_3=0x1201000 max_read=16").unwrap_err();
        assert!(format!("{err}").contains("unknown SHAPE field"), "{err}");
    }

    #[test]
    fn a_shape_without_max_read_is_refused_because_the_width_must_not_be_guessed() {
        let err = parse_shape("SHAPE cr3=0x1201000").unwrap_err();
        assert!(format!("{err}").contains("max_read"), "{err}");
    }

    #[test]
    fn an_absurd_max_read_is_refused_before_it_sizes_an_allocation() {
        let err = parse_shape("SHAPE max_read=4294967295").unwrap_err();
        assert!(format!("{err}").contains("outside"), "{err}");
    }

    #[test]
    fn a_max_read_that_would_truncate_into_range_is_refused_whatever_the_target_width() {
        // 0x1_0000_0001 narrows to 1 in a 32-bit `usize`, which is inside the bound -- so a build of
        // the shipped `x86\windbg-mcp.exe` would have accepted it and then run the entire walk as
        // one-byte exchanges. The bound is applied to the `u64` for that reason, and this passes on a
        // 64-bit host for the ordinary reason as well, so it pins the ordering rather than the width.
        for absurd in ["4294967297", "4294967296", "18446744073709551615"] {
            let err = parse_shape(&format!("SHAPE max_read={absurd}")).unwrap_err();
            assert!(
                format!("{err}").contains("outside"),
                "max_read={absurd} was not refused: {err}"
            );
        }
        // And the largest legal value still is legal, so the bound was not simply made stricter.
        assert_eq!(
            parse_shape(&format!("SHAPE max_read={MAX_DECLARED_READ}"))
                .unwrap()
                .max_read,
            MAX_DECLARED_READ
        );
    }

    #[test]
    fn a_register_the_transport_could_not_read_travels_with_its_reason() {
        let reply =
            parse_shape("SHAPE cr3=0x1201000 unreadable=efer:not_exposed max_read=16").unwrap();
        assert_eq!(
            reply.shape.unreadable,
            vec![("efer", "not exposed".to_string())]
        );
        // And the decode must not read a missing EFER as a machine out of long mode.
        assert_eq!(reply.shape.efer, None);
    }

    #[test]
    fn a_refusal_becomes_the_refusal_variant_and_nothing_else() {
        let err = parse_status("REFUSED ReadIntercept", 16).unwrap_err();
        assert_eq!(
            err,
            ReadFailure::Refused {
                detail: "ReadIntercept".into()
            }
        );
    }

    #[test]
    fn the_four_status_words_map_onto_the_four_failure_variants() {
        assert_eq!(parse_status("OK 16", 16).unwrap(), Some(16));
        assert!(matches!(
            parse_status("REFUSED x", 16),
            Err(ReadFailure::Refused { .. })
        ));
        assert_eq!(parse_status("NOTPRESENT", 16), Err(ReadFailure::NotPresent));
        assert!(matches!(
            parse_status("ERROR no driver", 16),
            Err(ReadFailure::SourceError { .. })
        ));
        // An unknown word is a source error rather than a panic or a silent zero fill.
        assert!(matches!(
            parse_status("MAYBE", 16),
            Err(ReadFailure::SourceError { .. })
        ));
    }

    #[test]
    fn a_transport_that_announces_more_bytes_than_were_asked_for_is_refused() {
        // Otherwise the transport decides how much of our buffer to fill, and a 4096-byte answer to
        // a 16-byte request would be a write past the end of it.
        let err = parse_status("OK 4096", 16).unwrap_err();
        assert!(
            matches!(&err, ReadFailure::SourceError { detail } if detail.contains("16-byte")),
            "{err:?}"
        );
    }

    #[test]
    fn a_short_answer_is_a_failed_read_rather_than_a_small_one() {
        let mut transport = exchange("OK 4\nabcd");
        let mut out = [0u8; 16];
        let err = transport.read_chunk(Gpa(0x1000), &mut out).unwrap_err();
        assert_eq!(err, ReadFailure::Short { got: 4, want: 16 });
    }

    #[test]
    fn a_framing_fault_poisons_the_transport_rather_than_leaving_the_stream_misaligned() {
        // The defect: `OK 4` against a 16-byte request left `abcd` unread, and the decode carries on
        // after a failed read -- so the next request took those bytes as its status line. Here the
        // second exchange would otherwise read `abcd` and then `OK 4` as data.
        let mut transport = exchange("OK 4\nabcdOK 4\nefgh");
        let mut out = [0u8; 16];
        assert_eq!(
            transport.read_chunk(Gpa(0x1000), &mut out).unwrap_err(),
            ReadFailure::Short { got: 4, want: 16 }
        );
        let second = transport.read_chunk(Gpa(0x2000), &mut out).unwrap_err();
        assert!(
            matches!(&second, ReadFailure::SourceError { detail } if detail.contains("desynchronised")),
            "a poisoned transport must refuse rather than read the leftover payload: {second:?}"
        );
        // And it must refuse **before writing**, which is a stronger claim than refusing. The guard
        // sat in `line()` only, after `read_chunk` had already pushed its `READ` — so a poisoned
        // transport kept being fed requests it answered into a pipe nobody drained, which deadlocks
        // both sides instead of failing. One request on the wire, not two.
        assert_eq!(
            String::from_utf8(transport.writer.clone()).unwrap(),
            "READ 0x1000 16\n",
            "a second request reached the wire after the transport was poisoned"
        );
    }

    #[test]
    fn a_status_line_that_fails_to_read_poisons_the_transport_too() {
        // The path the first two poison fixes both left open: `read_chunk` poisoned on a bad status
        // line and on a short payload, and not on a failed *read* of the status line. An over-long
        // line has certainly consumed MAX_LINE_BYTES, so the stream is misaligned and the next
        // request would walk into the leftovers -- or deadlock against a child nobody is draining.
        let flood = "z".repeat(MAX_LINE_BYTES as usize + 16) + "\nOK 4\nwxyz";
        let mut transport = exchange(&flood);
        let mut out = [0u8; 4];
        let first = transport.read_chunk(Gpa(0x1000), &mut out).unwrap_err();
        assert!(
            matches!(&first, ReadFailure::SourceError { detail } if detail.contains("no newline")),
            "{first:?}"
        );
        let second = transport.read_chunk(Gpa(0x2000), &mut out).unwrap_err();
        assert!(
            matches!(&second, ReadFailure::SourceError { detail } if detail.contains("desynchronised")),
            "an over-long status line must poison: {second:?}"
        );
        // And no second request reached the wire, which is the half that prevents the deadlock.
        assert_eq!(
            String::from_utf8(transport.writer.clone()).unwrap(),
            "READ 0x1000 4\n"
        );
    }

    #[test]
    fn an_answer_that_carries_no_payload_does_not_poison_the_transport() {
        // The other side of it, and the reason the classifier exists: a refusal is a complete status
        // line with nothing after it, so the stream is still aligned and the walk must be able to go
        // on to the next page. Poisoning here would turn one protected page into a dead transport.
        let mut transport = exchange("REFUSED ReadIntercept\nNOTPRESENT\nOK 4\nwxyz");
        let mut out = [0u8; 4];
        assert!(matches!(
            transport.read_chunk(Gpa(0x1000), &mut out),
            Err(ReadFailure::Refused { .. })
        ));
        assert_eq!(
            transport.read_chunk(Gpa(0x2000), &mut out),
            Err(ReadFailure::NotPresent)
        );
        transport.read_chunk(Gpa(0x3000), &mut out).unwrap();
        assert_eq!(&out, b"wxyz");
    }

    #[test]
    fn a_full_answer_lands_in_the_buffer_and_the_request_is_what_was_sent() {
        let mut transport = exchange("OK 4\nwxyz");
        let mut out = [0u8; 4];
        transport.read_chunk(Gpa(0xCD12DF), &mut out).unwrap();
        assert_eq!(&out, b"wxyz");
        assert_eq!(
            String::from_utf8(transport.writer.clone()).unwrap(),
            "READ 0xCD12DF 4\n"
        );
    }

    #[test]
    fn a_transport_that_closes_its_stdout_is_an_error_rather_than_a_hang() {
        let mut transport = exchange("");
        let mut out = [0u8; 4];
        let err = transport.read_chunk(Gpa(0x1000), &mut out).unwrap_err();
        assert!(
            matches!(&err, ReadFailure::SourceError { detail } if detail.contains("status line")),
            "{err:?}"
        );
    }

    #[test]
    fn a_transport_that_announces_bytes_and_does_not_send_them_is_an_error() {
        let mut transport = exchange("OK 16\nshort");
        let mut out = [0u8; 16];
        let err = transport.read_chunk(Gpa(0x1000), &mut out).unwrap_err();
        assert!(
            matches!(&err, ReadFailure::SourceError { detail } if detail.contains("did not send")),
            "{err:?}"
        );
    }

    #[test]
    fn a_providers_own_banner_is_skipped_up_to_the_sentinel_and_handed_back() {
        // The exact failure this exists for: hvlib's partition menu read as a SHAPE reply.
        let mut transport = exchange(
            "[ 0 ] Lab Guest Hyper-V . (PartitionId =  5 )\nActive partitions count:  2\n\
             windbg-mcp-gpa/1\nSHAPE cr3=0x1201000 max_read=16\n",
        );
        let skipped = transport.await_ready().unwrap();
        assert_eq!(skipped.len(), 2);
        assert!(skipped[0].contains("Lab Guest"));
        // And the next line really is the protocol's, not the one after the banner.
        assert_eq!(transport.shape().unwrap().shape.cr3, Some(0x1201000));
    }

    #[test]
    fn a_transport_that_never_says_it_is_ready_fails_rather_than_reading_for_ever() {
        let noise = "not a transport\n".repeat(MAX_BANNER_LINES + 10);
        let err = exchange(&noise).await_ready().unwrap_err();
        assert!(format!("{err}").contains("probably"), "{err}");
    }

    #[test]
    fn an_unterminated_line_is_refused_rather_than_read_until_memory_runs_out() {
        // `MAX_BANNER_LINES` bounds how many lines are read and not how long one is, so a transport
        // writing a binary log to its stdout -- or any provider printing without a newline -- would
        // grow this buffer until the process died. Rather more than the allowance, with no newline
        // anywhere in it.
        let flood = "x".repeat(MAX_LINE_BYTES as usize + 4096);
        let err = exchange(&flood).await_ready().unwrap_err();
        assert!(format!("{err}").contains("no newline"), "{err}");
    }

    #[test]
    fn a_line_at_the_allowance_that_does_end_in_a_newline_is_still_read() {
        // The other side of it: the bound must not refuse a legal line that happens to be long, and
        // must not refuse a final line at EOF, which also arrives with no newline.
        let long = "y".repeat(MAX_LINE_BYTES as usize - 1);
        let mut transport = exchange(&(long.clone() + "\n"));
        assert_eq!(transport.line().unwrap(), long);
        assert_eq!(
            exchange("short, no newline").line().unwrap(),
            "short, no newline"
        );
    }

    #[test]
    fn a_transport_that_will_not_exit_is_killed_at_the_grace_rather_than_waited_on_for_ever() {
        // The defect this pins: `Child::wait` does not fail because a child is alive, so a teardown
        // built on it never reaches its own kill. A child that outlives the grace by a long way is
        // what tells a bound from no bound -- against `wait()` this test does not fail, it hangs for
        // thirty seconds, which is the reading to expect when mutating it back.
        let mut child = {
            let _guard = crate::engine::spawn_guard();
            Command::new("cmd")
                .args(["/c", "ping", "-n", "30", "127.0.0.1"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("cmd is on every Windows host")
        };
        let started = std::time::Instant::now();
        reap(&mut child, std::time::Duration::from_millis(50));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "teardown took {:?}, so it waited rather than bounding",
            started.elapsed()
        );
        // And it was reaped rather than merely abandoned: a killed-and-waited child has a status.
        assert!(
            matches!(child.try_wait(), Ok(Some(_))),
            "the child was not reaped"
        );
    }

    #[test]
    fn a_quoted_path_with_spaces_stays_one_argument() {
        assert_eq!(
            split_command("\"C:\\Program Files\\python.exe\" server.py --mode direct"),
            vec![
                "C:\\Program Files\\python.exe",
                "server.py",
                "--mode",
                "direct"
            ]
        );
    }
}
