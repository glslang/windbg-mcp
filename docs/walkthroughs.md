# Walkthroughs

- [`coordinates.md`](coordinates.md) — pairing this server with a disassembler, which is a
  coordinate rather than an integration: `(module, image identity, RVA)`, the symbol-server key it
  builds, and a worked join of a `crash_triage` frame to a function in an image fetched on another
  machine from two integers.
- [`crash-dump-walkthrough.md`](crash-dump-walkthrough.md) — triaging a real kernel
  minidump ([`docs/samples/052126-34312-01.dmp`](samples/052126-34312-01.dmp)): a
  `0x9F DRIVER_POWER_STATE_FAILURE` traced to `nvlddmkm.sys` — `crash_triage` for the bug check as
  fields, then `!ext.analyze -v` and a manual device-stack walk for the culprit it cannot name, with
  the real outputs and the partial-minidump (`0x80040205`) gotcha. Ends on a second sample, a
  `0x13A` in a third-party driver, recorded on a host with no `triage\` beside the engine, where
  `!analyze` says `Unknown_Module` and the frame says `MessageManager+0x1654` — the same offset in
  five dumps that loaded the driver at five addresses.
- [`ttd-walkthrough.md`](ttd-walkthrough.md) — a hands-on tour of the TTD tools against the
  [`xusheng6/TTD_lab`](https://github.com/xusheng6/TTD_lab) `helloworld` sample: opening a `.run`,
  surveying events/threads, forward/reverse navigation, memory analysis, and counting `printf` calls
  with symbols (with the real outputs and the gotchas). It maps each tool to the lab's exercises.
- [`flareauthenticator-ttd-walkthrough.md`](flareauthenticator-ttd-walkthrough.md) — a full
  **TTD → Z3 solve** of an obfuscated Qt crackme (Flare-On 12 #8). Defeats an anti-analysis env guard,
  records a wrong-guess run, and uses `ttd_calls`/`ttd_memory`/reverse-navigation to peel control-flow
  flattening + computed calls + encrypted strings down to the exact check: a per-keystroke rolling hash
  that reduces to a pure weighted sum. The 25 weights come from the replay, the 250 `g` values from
  debugger function-evaluation, and Z3 finds a satisfying code — which reveals the flag (the code is
  intentionally non-unique). Runnable solver in [`examples/flareauthenticator/`](../examples/flareauthenticator/);
  recorded terminal session in [`flareauthenticator.cast`](flareauthenticator.cast)
  (`asciinema play`) — [rendered as a GIF](flareauthenticator.gif) in the walkthrough.
- [`driver-ioctl-walkthrough.md`](driver-ioctl-walkthrough.md) — enumerating a driver's IOCTL
  surface and deciding user-mode reachability on a live KDNET kernel: `driver_object`/`uf` to recover
  the `\Driver\mountmgr` dispatch switch, `decode_ioctl` for the access tiers, the device DACL parsed
  from memory, and an `ioctl_trace` sweep — ending with a reachability report (which codes a standard
  user can reach vs. what the I/O manager blocks).
- [`explorer-crash-walkthrough.md`](explorer-crash-walkthrough.md) — the server debugging **its own
  host**: a Windows 11 shell that would not start, traced through three consecutive faults to a
  malformed AppModel State Repository. A user-mode counterpart to the kernel walkthroughs, and the
  one with no checked-in sample — the target was the live machine. Its subject was a fact no typed
  tool returned: the **HRESULT thrown through `winrt::check_hresult`**, dug out of the C++ exception
  record by hand (`.exr`, the `0x19930520` EH magic, the `0xAABBCCDD` sentinel, `!error`) three
  times in one evening. §9 is the argument that made it a primitive, and now records what shipped —
  `exception_triage` and `decode_error_reporting`, and the three ways the tool differs from the
  recipe. Also contrasts the two shapes of `0xc0000409`: a CRT `abort` that hides the code in the
  thrown object against a WIL fail-fast that puts it in a parameter.
