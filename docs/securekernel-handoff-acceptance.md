# Read-only Secure Kernel handoff

## Status — 2026-09-15

The maintained [handoff probe](../tools/securekernel_handoff_probe.py) and offline
refusal/preservation tests are implemented. Live acceptance is **not run**: the
existing WinDbg MCP listener returned an empty session inventory during
authenticated, read-only discovery. The temporary SSH tunnel was closed. No
debugger session was attached, interrupted, resumed or ended.

[Discovery evidence](samples/securekernel-handoff-discovery-20260915.json) records
the retrieval time, available tools and empty inventory. This leaves follow-up
62 open. The earlier [generic fixture acceptance](similarity-windbg-acceptance.md)
remains independent evidence.

## Preconditions and invocation

Use an existing disposable remote-kernel session, already paused with its current
instruction inside the selected `securekernel.exe`. This stricter starting
condition establishes Secure Kernel context before the probe reads the selected
match. A module in an ordinary NT inventory alone is insufficient.

The companion must already hold the selected target binary and comparison.
Supply a result ID from that comparison. Keep other clients from operating on
these inputs/session during the capture. The probe compares before/after state;
it cannot detect another client briefly resuming and returning to the same state.

Use the companion's Python 3.13 environment with `mcp==2.1.1`. Each private
connection file contains `url` and `token`; HTTP must use loopback, and HTTPS
verifies certificates. Redirects and environment proxies are disabled.

```console
python tools/securekernel_handoff_probe.py \
  --windbg-connection /private/lab/windbg.json \
  --companion-connection /private/lab/companion.json \
  --session-id SELECTED_SESSION --binary-id TARGET_BINARY \
  --comparison-id COMPARISON --result-id MATCH \
  --size 32 --output /private/lab/handoff.json
```

The output is a private file with mode `0600`. Review and sanitize it before
publishing: debugger responses can contain target paths. Credentials are not
copied into the report, and connection exceptions record only their type.

## What is checked

- Required input fields and structured outputs are discovered through `tools/list`.
- The selected session is an open remote kernel, with no outstanding running job.
  `current_location` must succeed with a mapped Secure Kernel instruction pointer.
- The match's target binary, generation, image identity and RVA are checked against
  the companion view. Modified input views, ambiguous/truncated module listings,
  wrong PE/PDB identities and ranges outside the image are refused.
- Static architecture must agree with the debugger's register-name set (`pc`/`x0`
  or `rip`/`rax`). This is a consistency check alongside PE identity, rather than
  an independent runtime PE-machine read.
- Navigation uses the target coordinate and expected generation. A guarded read
  returns 1–256 bytes at the expected runtime address. Partial reads are retained
  explicitly; a zero-byte or inconsistent read fails acceptance.
- A second read replaces only the identity with the reference build's identity.
  It must produce the structured PE/PDB identity-mismatch refusal. Other errors,
  including a running target or transport failure, do not pass that check.
- Session membership, worker PID, instruction/thread/processor context and
  breakpoint text are compared afterward, including on capture failures.

Breakpoint inspection uses `execute` with the fixed command `bl` and a five-second
timeout because this tool surface has no separate breakpoint-list operation. The
probe rejects any other debugger command and any launch, execution-control,
breakpoint mutation or session-teardown tool. It creates no pairing or comparison
and leaves the supplied debugger session open. Client connection cleanup does not
replace the original capture failure.

## Offline verification

```console
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools -p test_followup_probes.py
```

The tests inject running targets, wrong identity/architecture, stale inputs,
partial/invalid reads, misleading wrong-build errors, missing guarded schemas,
cleanup failures and changed debugger state. An independent recording client
also rejects mutation calls. These tests establish probe behavior, not live
VTL1 access. Full Secure Kernel lab setup and execution testing remain separate.
