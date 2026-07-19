# FlareAuthenticator (Flare-On 12 #8) — TTD → Z3 solve

A worked example of using `windbg-mcp`'s Time Travel Debugging tools to reverse a heavily-obfuscated
crackme down to a clean mathematical constraint, then handing that constraint to an SMT solver. Full
narrative with the real tool calls and outputs: [`docs/flareauthenticator-ttd-walkthrough.md`](../../docs/flareauthenticator-ttd-walkthrough.md).
A recorded terminal session of the workflow: [`docs/flareauthenticator.cast`](../../docs/flareauthenticator.cast)
(asciicast v2 — `asciinema play docs/flareauthenticator.cast`), rendered as a
[GIF](../../docs/flareauthenticator.gif).

## What the tool recovered

The OK handler folds each keystroke into a 64-bit rolling hash that reduces (after de-obfuscation) to a
**pure weighted sum**, checked against a constant:

```text
hash = Σ_{i=0..24}  Y[i] * g( (i+1)*256 + '0' + d[i] )   ≡  0x0bc42d5779fec401   (mod 2^64),   d[i] ∈ [0,9]
```

- `Y[i]` — 25 per-position weights, read from a TTD replay at the per-keystroke addend site.
- `g` — a pseudo-random function of its argument, proven independent of the running hash; its 250
  needed values were obtained by **function-evaluation in a live debug session** (set `rcx/rdx/rip`,
  run past the call, read `rax`) and captured in [`gtable.txt`](gtable.txt). Because `g` depends only
  on its argument, `gtable.txt` is a stable artifact of the binary.

## Files

- **`data.js`** — the 25 weights `Y[i]`, the check `target`, and the wrong-run cross-check hash.
- **`gtable.txt`** — `g[pos][digit]` for all 25 positions × 10 digits (`G <pos> <digit> <hex>`).
- **`solve.js`** — builds the BitVec(64) model in [Z3](https://github.com/Z3Prover/z3) and solves it.

## Run

```sh
npm install z3-solver      # WASM build; runs in Node, no native Z3 needed
node solve.js
```

Expected output:

```text
sanity: my hash = 5b735c36628fcab / expected 5b735c36628fcab OK
z3: sat
SOLUTION: 4498291314891210521449296
verify hash = bc42d5779fec401 / target bc42d5779fec401 OK
```

## The twist

That one 64-bit equation is **under-determined** — roughly 2¹⁹ different 25-digit codes satisfy it, so
there is no unique password. The flag is derived from the hash *value* (equal to the target for every
solution), so **any** satisfying code unlocks the same flag:

```text
s0m3t1mes_1t_do3s_not_m4ke_any_s3n5e@flare-on.com
```
