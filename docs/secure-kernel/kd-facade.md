# The Secure Kernel KD facade

`windbg-mcp --sk-kd-target` puts an installed WinDbg in front of the live Secure Kernel controller
that [`live-control-provider.md`](live-control-provider.md) describes. WinDbg is the **protocol
client**: the role serves the serial KD packet stream over a local named pipe and translates the
requests it understands into the same guarded operations the seven `sk_live_*` tools make. The
target is still one selected VTL1 VP behind the operator's providers, and the facade creates no
DbgEng instance of its own — `src/worker.rs` lends it the one engine, on the thread that built it.
It shipped in 0.22.0 ([#463](https://github.com/glslang/windbg-mcp/pull/463), merged 2026-10-06)
with no tracked record, which `FOLLOWUPS.md` item 115 filed and this page closes; items 116, 117
and 119 carry what is still open about it.

**What it is not.** It is not KDNET: there is no UDP discovery, no key exchange and no encryption,
and the transport is a named pipe on the debugger host (`src/kdwire.rs` keeps the framing
transport-neutral for a network envelope nobody has attempted). It is not EXDI, which the research
record parked ([`README.md`](README.md)). It is not an MCP session: the role speaks no MCP, appears
in no `session_status`, and ends when the debugger disconnects or quits. And it is not a KD
transport inside the guest. Secure Kernel still ships none — gate S5a's finding stands — so this is
a host-side facade over the root-driven controller, and nothing here changes what the guest can do.

## What has been measured

One live run, 2026-10-05, on the disposable K3 VM behind the private providers. `kd` from WinDbg
**10.0.29617.1000** connected to the pipe, received the held stop at `securekernel.exe+0xb12b`, and
ran `t`, `r` and `q`. (The PR body says "WinDbg 10.0.26100"; that is the *target's* build, as the
debugger's own banner has it: "Connected to Windows 10 26100 x64 target".) The `t` arrived as
`Continue2` with the trace flag; the controller removed its hardware arm, set TF and released the
retained `vmwp` event in one transition, then published the returned vector-1 stop at the
five-byte NOP's successor, and WinDbg displayed the real VTL1 registers at the new RIP. `r` printed
the general-purpose registers, selectors and flags, then "Unable to get program counter" (see the
limits). `q` restored the saved baseline and released the second retained event; the same `vmwp`
stayed healthy and the VM reached Off.

Two things that run also measured, both load-bearing for anyone running it again. WinDbg's serial
reconnect window is a few seconds, and the arm-and-stop transition took about five, so the role
captures its initial stop **before** it creates the pipe. And `kd -c "r;t;t;r;q"` did not execute
five commands — it stranded kd at its prompt — so commands go in a `-cf` file, one per line.

Nothing else has run live. The `g`-to-breakpoint path is coded and unit-tested against a fake
dispatcher, and no run has installed a breakpoint from WinDbg and continued to it. The review that
filed items 115–119 read the facade and did not run it.

## Running it

```console
windbg-mcp --sk-kd-target --pipe <name> --kernel-base <address> --profile <json> \
  --control-transport "<command line>" --live-transport "<command line>" --vmwp-pid <pid> \
  --dispatcher-vnd <address> --vm-id <guid> --partition-id <number> --expected-cr3 <number> \
  --instruction-address <number> --instruction-bytes <hex> \
  [--arm-mode redirect|natural] [--vp <number>] [--build <number>] \
  [--connect-timeout-ms <milliseconds>] [--idle-timeout-ms <milliseconds>]
```

The required arguments are the live-control inputs `open_sk_live_control` takes — profile, the two
provider command lines, `vmwp` PID, dispatcher VND, VM GUID, partition id and expected CR3, with
`--vp` defaulting to 0 — the initial guarded instruction, and two the facade adds. `--pipe` names
the pipe (1 to 128 ASCII letters, digits, dots, dashes or underscores; the role creates
`\\.\pipe\<name>` as the first instance). `--kernel-base` is the guest's `securekernel.exe` base
and goes into the KD version record **unchecked**, as does `--build` (default 26100): item 116.
`--arm-mode` defaults to `redirect`. Where the values come from is outside this repository, and
item 119 records that no tool derives them.

1. The role opens the controller session and runs the provider handshake, arms slot 0 on the initial
   instruction in the chosen mode, and waits for that stop. No pipe exists yet.
2. It creates the pipe and prints `Secure Kernel stop held at <rip>; waiting for WinDbg on
   \\.\pipe\<name>` to stderr. The connect wait and the KD reset wait that follows are each bounded
   by `--connect-timeout-ms` (default 30 s; 1 ms to 1 h).
3. Start the debugger. WinDbg takes the same `-k` string as kd:

   ```console
   kd -k com:pipe,port=\\.\pipe\<name>,resets=0 -cf <commands.txt>
   ```

   The facade answers the reset and sends the held stop as a state-change packet.
4. While stopped, every manipulate request is answered as the limits below say, and silence longer
   than `--idle-timeout-ms` (default 300 s; 1 ms to 1 h) ends the session. While running — after a
   `t` or a `g` — the same idle bound covers the wait, and a KD reset, a disconnect, a Ctrl+Break or
   a transport failure cancels the controller's wait through the one cross-thread `SetInterrupt` the
   repository allows (`AGENTS.md`), which enters the controller's fail-closed recovery.
5. `q`, or a disconnect, runs the controller's normal close: the baseline is restored and the
   retained event released. A disconnect logs "WinDbg disconnected; restoring the held Secure Kernel
   stop" and exits 0 once the close succeeds.

## Known product limits

The private bench plan's seven limits, re-derived against `src/kdtarget.rs`, `src/kdapi.rs` and
`src/sklive.rs` on 2026-10-07 rather than copied:

- **Named-pipe serial KD only.** No KDNET network transport.
- **One selected VTL1 VP, and four hardware execute breakpoints.** A `bp` arrives as
  `WriteBreakpoint` and takes a DR slot; a fifth is refused. `StateChange64` reports one processor
  at index 0 whatever `--vp` named, so nothing on the wire says which guest VP that is (item 116).
- **The version record says `NOMM`, with a null module list and a null debugger data list**, so
  WinDbg prints "Debugger data list address is NULL", "Module List address is NULL - debugger not
  initialized properly", "WARNING: .reload failed" and "KdDebuggerDataBlock not available!" at
  connect. There is no `lm`, no `securekernel` symbol, and none of the NT process, thread or
  memory-manager extensions. The capture decode already locates the real block; item 116 is the
  route to pointing WinDbg at it.
- **`t` must be the first execution command at a fresh stop.** A standalone `r` first makes WinDbg
  reconstruct an NT scope — on the bench, one refused `ReadControlSpace` and 33 `RestoreBreakpoint`
  requests — after which its cached program counter is wrong and a later `t` does not reach the
  wire. `r` after the returned stop displays the real context and still ends in "Unable to get
  program counter", because control space is refused; nothing promises another execution command
  after that.
- **`t` steps the linear successor only.** A branch, call, return, interrupt or exception is
  refused; so is a `rep`-prefixed string instruction, and anything that writes `ss` (`mov ss`,
  `pop ss`, `lss`), because the trap can land somewhere other than the successor. `g` needs at least
  one hardware breakpoint installed and is refused otherwise. A refusal resends the held stop, so
  the session survives it. The facade reads one bit of `Continue2`, the trace flag; whatever WinDbg
  sends for `p` is handled by those same two arms.
- **The proven redirected step is one five-byte NOP.** On that bench the next instruction used the
  interrupted context's RBX, so the acceptance takes one step and quits.
- **`SetContext` succeeds only for WinDbg's unchanged compatibility write**; a changed byte is
  refused. No guest memory is written and no general-purpose register is: the only writes are the
  controller's own — debug registers for a breakpoint, TF for a step — and the baseline restores
  them at release.
- **Break-in while the Secure Kernel is running is not implemented.** The break-in byte cancels the
  controller's wait, which is a fault with recovery and a process exit, not a stop; while stopped it
  is set and never read (item 117).
- **Everything else answers `0xC0000001`**: `WriteVirtual`, `GetContext`, `ReadPhysical`,
  `SearchMemory`, MSR reads and writes, `SwitchProcessor`, `QueryMemory`, `SetContextEx`, `Reboot`,
  `CauseBugCheck`, and control-space reads and writes. Malformed input does not get a status: a bad
  checksum, a manipulate packet under 0x38 bytes or a `GetContextEx` range outside the context ends
  the session (item 117).

## What WinDbg reads that the guest never held

Secure Kernel has no NT `KTHREAD`, and WinDbg dereferences the wait-state thread field before it
will issue `t`. The facade therefore reports a synthetic thread at `0xfffffffefffe0000` and serves
zeros for the page there, for the life of the connection. It also serves zeros **once each** for the
bookkeeping reads WinDbg makes while constructing an NT scope — two null-page probes, four
`KUSER_SHARED_DATA` probes, 0x80 bytes at RSP, 0x2b bytes ending at RIP and 0x80 bytes after the
instruction — and that once-only window resets on a KD peer reset, not per stop. Those bytes exist
only in the KD view. Every other read goes to guarded VTL1 memory through the live source, clamped
to 3,944 bytes a request. The facade's stderr says which happened for every read, `served by
compatibility memory` against `served by Secure Kernel memory`, and that log is the only place the
two are told apart: item 116 is about WinDbg having no way to.

## Pipe and host safety

- **The pipe carries the process token's default descriptor and the role checks no client.** The
  first client to send a KD reset is served; a read-only client can take the single instance, after
  which the reset wait times out and the session closes. Item 117 has the measured default and the
  hardening it wants. Until then, pick a name nobody else on the host would guess, and know whose
  default DACL the role runs under.
- **The 2026-10-05 run is the leading suspect for a Kernel-Power 41 host reset** with
  `BugcheckCode=0`, no dump and no WHEA record. Causation is not proven. The controller's log ended
  after a complete restore and release; what the failed runner had left behind was a kd in its
  reconnect loop — from the pre-fix reset timing and the mis-parsed `-c` string — which could
  outlive the runner's short wait and block VM cleanup. The mitigations live in the bench's private
  runner, not in the facade: one command per `-cf` line; kd and the target monitored together under
  a 60-second command bound; kd asked to quit twice with bounded waits before it is terminated; the
  facade never killed while it may own `vmwp` state — the disposable VM is powered off first; VM and
  service cleanup run even when teardown reports an error; `Stop-VM -TurnOff` only after controller
  cleanup, or as the emergency containment path; and the disposable VM's `AutomaticStartAction` set
  to `Nothing`.

## What is tested, and what has no gate

The four modules' unit tests — `kdwire` 6, `kdapi` 9, `kdtarget` 6, `kdprobe` 2, counted
2026-10-07 — all run over inline packet vectors. Nothing exercises the pipe loop, the wait waker or the `Continue2` path
against a connected debugger, and there is no `WINDBG_MCP_SMOKE_SK_KD` tier;
[`docs/smoke-test.md`](../smoke-test.md) says so beside the live Secure Kernel gate.

`windbg-mcp --sk-kd-wire-probe --pipe <name>` is the transport-only fixture: one pipe, no VM, no
DbgEng, no MCP. It answers a connected WinDbg's reset, optionally sends a supplied state-change
packet (`--state-change`) and context (`--context`) under a `--kernel-base`, answers reads with
zeros, can write the traffic to `--capture`, and exits at `--timeout-ms` (default 15 s). It is a
handshake fixture rather than a replay, and it is what isolated the 2026-10-05 failure to command
order rather than to the context encoding: replaying the full live context through it still
produced `Continue2` with the trace flag.

## Distance from a debugging session

Item 119 holds the ordered ladder. In one line: once the version record names the real debugger
data list (item 116), control space is served and a stack has a bound, WinDbg would behave like a
kernel debugger with hardware breakpoints only and no write support — a usable inspection tool on a
disposable guest. Break-in, stepping over anything but a fall-through, repeated run-break-run, more
than one VP and writes are what is left, and each is bounded by a guard that already exists in
`src/sklive.rs`.
