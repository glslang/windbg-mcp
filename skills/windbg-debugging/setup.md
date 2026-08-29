# Setup: build, engine bundling, symbols, elevation

Most `windbg` failures are environment problems, not debugging mistakes. Work through the
section for the workflow you're about to run before blaming the target.

## Platform

- **Windows x64 is the supported and tested configuration.** Host bitness must match the target
  for *live* debugging.
- `dbgeng.dll` / `dbghelp.dll` ship in `System32` on modern Windows 11 (verified on
  `10.0.26100`). That is enough for live user-mode/kernel debugging and crash-dump
  analysis — **but not for TTD `.run` replay** (see below).

### ARM64 hosts

Crash-dump analysis works on Windows on ARM, and the dump does **not** have to be ARM64: an ARM64
engine reads an x64 kernel minidump in full — `!analyze -v`, symbols, failure bucket, pool tag, the
`EPROCESS` behind `process_name`, and `walk_memory` / `disassemble` against the captured address
space.

**With the engine bundle below beside `windbg-mcp.exe`, and not without it.** An engine that
resolves no symbols still reads a dump's *structure* — bug check, module list, stack attribution,
all of it out of the dump's own headers — and fails everything that follows a **pointer** with
`0x8007001E` / `0x80040205`, because a kernel dump's virtual addresses are translated through
structures it locates with `nt`'s symbols. That is what
[#142](https://github.com/glslang/windbg-mcp/issues/142) was, and it was first read as an
architecture limitation, which it is not: the same host reads x64 and ARM64 dumps alike once
symbols resolve, and reads neither when they do not.

`symsrv.dll` is the file this usually comes down to. System32 always ships `dbghelp.dll` and
**often has no `symsrv.dll` beside it**, and a machine without one cannot download a PDB over a
`srv*` path at all — the symptom being not "no symbols" but a memory read failing. Whether it is
there is worth checking rather than assuming: `where.exe symsrv.dll`. Of the two GitHub Actions
Windows images, the x64 one has a System32 `symsrv.dll` and the ARM64 one does not.

Live user-mode and live kernel are untested on ARM64, and the bitness rule above still applies to
those.

Two things change when you bundle the engine.

**Match the payload to `windbg-mcp.exe`'s architecture, not to the host's.** A process loads DLLs
of its own architecture, so an x64 binary running under emulation on an ARM64 host needs the
**`amd64`** engine and cannot load the `arm64` one — it will fail to initialise the debugger rather
than fall back. Which you need therefore depends on where the binary came from:

| `windbg-mcp.exe` | Package payload (store or bundle) | SDK directory |
| --- | --- | --- |
| Prebuilt release zip (Option A) — **always x64** | `\amd64` | `Debuggers\x64` |
| Built from source on an ARM64 host (Option B) | `\arm64` | `Debuggers\arm64` |

The releases this repo publishes are x64 only, so downloading one onto an ARM64 host and reaching
for `arm64` DLLs — the intuitive move — is the wrong pairing. `cargo build --release` on the host
is what gets you a native binary worth pairing with `arm64`.

**Where the payload comes from is a separate question, and not an ARM64 one.** Three sources
supply it and they differ in what they hold — an installed store package, the same package's
`.msixbundle` unpacked without installing it, and the Windows SDK Debugging Tools, which ship
everything except `msdia140.dll` and `ttd\`. See *WinDbg engine + extensions* below, which names
all three and then runs one copy. The architecture rule above applies whichever you pick.

## Get the server binary

The plugin ships the source, not a binary. Put `windbg-mcp.exe` in place so the path in
`plugin.json` (`${CLAUDE_PLUGIN_ROOT}/target/release/windbg-mcp.exe`) resolves — either
option below lands it there.

> **Installing from the [MCP registry](https://registry.modelcontextprotocol.io) or an
> [MCPB](https://github.com/anthropics/mcpb) bundle instead?** Add
> **`io.github.glslang/windbg-mcp`** and your client fetches + SHA-256-verifies the prebuilt
> `.mcpb` itself — skip Options A/B, which exist to populate the plugin's source layout. You
> still do the one-time **engine bundling below**, dropping those DLLs next to the
> *client-extracted* `windbg-mcp.exe` (its `${__dirname}`).

A package-manager install lands outside the plugin layout in the same way:

> **Already installed with [Scoop](https://scoop.sh)** from the community
> [`gitfool/scoop-dungeon`](https://github.com/gitfool/scoop-dungeon) bucket? That also skips
> Options A/B — point the client at
> `%USERPROFILE%\scoop\apps\windbg-mcp\current\windbg-mcp.exe` rather than the plugin path. Its
> `post_install` does the **engine bundling below** — the DLLs plus `ttd\`, `winext\` and `winxp\`,
> copied from the `Microsoft.WinDbg` store package on the machine, when one is installed. Check the
> directory for `dbgeng.dll` before repeating any of it; if it is missing, WinDbg wasn't installed
> when Scoop was, and the copy below (or `scoop update --force windbg-mcp`) is still needed.
>
> **Never run `scoop install` on the user's behalf.** That bucket is community-maintained, outside
> this project's control, and a Scoop manifest is code: `post_install` is arbitrary PowerShell, run
> against whatever download URL and hash the manifest carries at that moment — and excavator
> rewrites both automatically on each new release, so what a reader once checked is not what a
> later install fetches. Options A/B are the paths this project can vouch for: a SHA-256 published
> with the release, and `gh attestation verify` tying the zip to the workflow that built it. If the
> user wants Scoop, they ask for it and they run it.

### Option A — download a prebuilt release (no Rust required)

Each `vX.Y.Z` tag publishes a Windows x64 build on the
[releases page](https://github.com/glslang/windbg-mcp/releases). From the installed
plugin / repo directory:

```pwsh
$dst = "target\release"
New-Item $dst -ItemType Directory -Force | Out-Null
$rel   = Invoke-RestMethod https://api.github.com/repos/glslang/windbg-mcp/releases/latest
$asset = $rel.assets | Where-Object name -Like 'windbg-mcp-*-windows-x64.zip'
$zip   = Join-Path $env:TEMP $asset.name
Invoke-WebRequest $asset.browser_download_url -OutFile $zip
$sum = ((Invoke-RestMethod ($rel.assets | Where-Object name -EQ 'SHA256SUMS.txt').browser_download_url) -split '\s+')[0]
if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $sum) { throw "SHA256 mismatch for $($asset.name)" }
Unblock-File $zip   # clear Mark-of-the-Web so the extracted exe isn't blocked
Expand-Archive $zip $dst -Force
```

Optionally, with the [GitHub CLI](https://cli.github.com/), verify the zip's build provenance
(proves it was built by this repo's release workflow, not tampered with):

```pwsh
gh attestation verify $zip --repo glslang/windbg-mcp `
   --signer-workflow glslang/windbg-mcp/.github/workflows/release.yml
```

**If Defender quarantines the exe**, most likely as `Trojan:Win32/Bearfoos.B!ml`: that suffix marks
a machine-learning score rather than a signature match, so the same file lands either side of the
line on different days, and it is a known shape for a small unsigned Windows executable —
Microsoft's own shipped binaries have drawn the same verdict. The release is **not** Authenticode
signed today; what it does carry is a SHA-256 published beside it and the Sigstore build-provenance
attestation the block above verifies.

Verify both — but be clear about what they settle. They establish **provenance**: that this file is
the one this repo's release workflow built, unmodified. They do **not** establish that it is benign,
because a compromised dependency, workflow or runner would be attested exactly as faithfully. So a
verdict that survives them is not thereby a false positive, and the right next step is to have it
adjudicated rather than to wave it through:
[submit the file to Microsoft](https://www.microsoft.com/wdsi/filesubmission) and leave it in
quarantine until they answer, or inspect it yourself. Restoring it and excluding the directory you
extracted it into would run the flagged file on the strength of a check that does not cover this,
and leave that directory unscanned for everything written there afterwards. Do not disable Defender.

### Option B — build from source

```pwsh
# From the installed plugin / repo directory.
cargo build --release
```

[`dbgscope`](https://github.com/glslang/dbgscope) is fetched automatically as a git
dependency — no sibling checkout needed.

> **Developing from the repo? Disconnect the `windbg` MCP server before a release build.**
> While the server is connected it *runs* `target\release\windbg-mcp.exe`, so the file is
> locked and `cargo build --release` fails with `failed to remove file … windbg-mcp.exe:
> Access is denied (os error 5)`. End-to-end testing of a change can't happen until the
> rebuilt binary is in place, so:
>
> 1. Disconnect it — disable the `windbg` server (the `/mcp` menu) or the plugin for this session.
> 2. `cargo build --release` (or download a release), then `/reload-plugins` to reconnect.
>
> To iterate on logic without disconnecting, use the **dev profile** (writes `target\debug`,
> which is *not* locked): `cargo test` compiles everything and runs the unit tests, and
> `cargo clippy --all-targets` lints — neither touches the locked release binary.

Either way, run `/reload-plugins` afterwards so Claude Code connects the `windbg` MCP server.

## WinDbg engine + extensions — for `.run` replay, crash-dump `!analyze`, and the kernel driver tools

Drop a **WinDbg engine payload** next to `windbg-mcp.exe` (the `$dst` below — for a
registry/MCPB install that's the client's extraction directory, **not** `target\release`) for
three reasons:

- **TTD `.run` replay** — System32's `dbgeng.dll` **rejects** traces with `0x80070057`.
- **Crash-dump `!analyze`** — it lives in the `winext\` extensions, which System32 doesn't ship
  (so a `.dmp`-only user still needs the `winext\` copy below, even though dump *loading* itself
  works on System32's engine).
- **`driver_object`/`device_object`/`irp_stack`** — they run `!drvobj`/`!devobj`/`!irp` from
  `winxp\kdexts.dll`, which System32 doesn't ship either (so a live-kernel-only user needs the
  `winxp\` copy below, even though the attach itself works on the System32 engine).

`DebugCreate` binds to whichever `dbgeng.dll` the loader finds first, and the app directory is
searched before `System32`, so the copied engine wins.

**Three sources supply that payload**, and what separates them is what they leave out:

| Source | Holds | Costs |
| --- | --- | --- |
| The installed **WinDbg store package** | everything below | an interactive install — MSIX will not register over SSH |
| The same **`.msixbundle`, unpacked** | everything below | a ~1.1 GB download; no install, so it is the one source a remote session can use |
| The **Windows SDK Debugging Tools** | everything **except `msdia140.dll` and `ttd\`** | no TTD replay, and PDB parsing left to the `dbghelp.dll` you bundle ([#132](https://github.com/glslang/windbg-mcp/issues/132)) |

All three are the **same layout** — a directory with `dbgeng.dll` beside `ttd\`, `winext\`,
`winxp\` and `triage\` — so they differ only in how you set `$wd`, and the copy below is the same
copy whichever you take:

```pwsh
# Match $arch to windbg-mcp.exe, not to the machine: a process loads DLLs of its
# own architecture, and the published release zip is x64 even on an ARM64 host.
# See the table under "ARM64 hosts" — "amd64" is right for every x64 binary,
# including one running under emulation.
$arch = "amd64"

# Then pick ONE of these three and leave the other two commented out.
# (a) the installed store package
$wd = (Get-AppxPackage Microsoft.WinDbg).InstallLocation + "\$arch"
# (b) the unpacked .msixbundle — $w comes from "Unpacking the .msixbundle" below
# $wd = "$w\p\$arch"
# (c) the SDK Debugging Tools — "arm64" keeps its name here, but amd64 is spelled x64
# $wd = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
```

From **(c)**, drop `msdia140.dll` from the file list and skip the `ttd\` line — neither is there.
`!analyze`, the driver tools and symbol resolution all work from it; TTD replay does not, which is
the whole of why (b) exists.

Symbols are the interesting omission in (c). `msdia140.dll` is documented below as required for PDB
parsing, but on the ARM64 host this was tested on full private symbols resolved
(`nt!RtlpHpVsSlotFreeList`, not an export) with **no `msdia140.dll` anywhere on the machine and none
registered** — the SDK's own `dbghelp.dll` read the PDBs unaided. Treat that requirement as a
property of the `dbghelp.dll` you bundle rather than a universal one, and check with `lm m <mod>`
(`(pdb symbols)` versus `(export symbols)`) rather than assuming either way.

One-time, with `$wd` set from whichever source you took:

```pwsh
# Set $dst to the folder that actually holds windbg-mcp.exe — pick the one for
# your install (do not leave it as the placeholder):
#   plugin / build-from-source layout      -> <plugin dir>\target\release
#   installed from the MCP registry / MCPB -> the client's extraction dir (the
#     extension's ${__dirname}, under the client's extensions folder)
$dst = "<folder that holds windbg-mcp.exe>"
Copy-Item "$wd\dbgeng.dll","$wd\dbghelp.dll","$wd\dbgcore.dll","$wd\dbgmodel.dll",`
          "$wd\symsrv.dll","$wd\msdia140.dll" $dst -Force
Copy-Item "$wd\ttd"    "$dst\ttd"    -Recurse -Force   # TTDReplay*.dll, TtdExt.dll, TTDAnalyze.dll, ...
Copy-Item "$wd\winext" "$dst\winext" -Recurse -Force   # ext.dll (!analyze), kext.dll, … — for crash dumps
Copy-Item "$wd\triage" "$dst\triage" -Recurse -Force   # triage.ini, pooltag.txt — !analyze's module attribution
New-Item   "$dst\winxp" -ItemType Directory -Force | Out-Null
Copy-Item "$wd\winxp\kdexts.dll" "$dst\winxp" -Force   # !drvobj/!devobj/!irp — for the driver-IOCTL tools (kernel)
```

- The `ttd\` subdir provides the `@$cursession.TTD` / `@$curprocess.TTD` data model and the
  `!tt` time-travel commands. It also carries **`TTD.exe`** itself, at `ttd\TTD.exe` — so the copy
  above brings the recorder `record_trace` needs along with the replay engine, and the server looks
  there: it probes `PATH` first, then its own `ttd\` directory, then the SDK and `WindowsApps`
  layouts. Bundling an engine therefore gets you recording as well as replay, with nothing to put
  on `PATH`.
- The `winext\` subdir provides `ext.dll` (which exports `!analyze`) and the other `!`-extensions.
  Required for crash-dump triage — without it `!analyze` returns *"No export analyze found"*.
  Whether the **unqualified `!analyze` then resolves is engine- and Windows-version-dependent**, so
  do not read either outcome as the rule: it did *not* on the x64 host this note was first written
  against, and it *did* on an ARM64 host running the SDK engine. Where it does not, the
  module-qualified **`!ext.analyze -v`** works. `crash_triage` tries both and reports which one
  answered, so `analysis.command` settles it for the host in front of you.
- The `triage\` subdir provides `triage.ini` and `pooltag.txt`, which `!analyze` reads to attribute
  a crash to a module and to name pool tags. **Its absence does not produce an error**, which is
  what makes it worth listing: `!analyze` runs, and reports `ANALYSIS_INCONCLUSIVE` /
  `Unknown_Module` / `Unknown_Image` with the bucket id built from those. Measured on the same dump
  with and without it, the failure bucket goes from `0x13a_8_TNf__MessageManager!unknown_function`
  to `0x13a_8_TNf__ANALYSIS_INCONCLUSIVE!unknown_function` — a missing file that reads as an
  inconclusive crash.
- `winxp\kdexts.dll` provides the kernel-object extensions `!drvobj`/`!devobj`/`!irp` used by the
  `driver_object`/`device_object`/`irp_stack` tools. `attach_kernel` / `attach_kernel_local`
  `.load kdexts` automatically; without the file those tools return *"No export drvobj found"*.
  (Note it lives in `winxp\`, not `winext\`, and the engine already searches a `WINXP` subdir.)
- `cargo clean` (when building from source) wipes `target\`, so re-copy after one.
- **Stop the server before copying over an engine that is already there.** A running
  `windbg-mcp.exe` holds `dbgeng.dll` open even with no session on it — the engine is an
  import-table dependency of the image, so the loader maps it before `main` whatever role the
  process plays — and `Copy-Item` then fails with *"being used by another process"*. An idle
  supervisor reporting an empty session list is not idle enough; `Stop-Service windbg-mcp` (or
  closing the client that spawned it) is. A first-time copy into a directory with no engine yet has
  nothing to overwrite and needs none of this.

### Unpacking the `.msixbundle` — source (b)

A `.msixbundle` is an ordinary zip, and the one Microsoft serves from `aka.ms/windbg/download`
holds the same `amd64\`, `arm64\` and `x86\` payload trees the installed package does. So the
engine can be had **without installing anything**, which is the only route open to a host that
cannot register an MSIX at all — see [*When the store package will not
install*](#when-the-store-package-will-not-install).

```pwsh
$ProgressPreference = 'SilentlyContinue'   # or Invoke-WebRequest spends longer rendering than downloading
$w = "$env:TEMP\wdbg"; New-Item $w -ItemType Directory -Force | Out-Null
# -OutFile, not .Content: 5.1 hands back a Byte[] here and the [xml] cast fails.
Invoke-WebRequest 'https://aka.ms/windbg/download' -OutFile "$w\windbg.appinstaller" -UseBasicParsing
$uri = ([xml](Get-Content "$w\windbg.appinstaller" -Raw)).AppInstaller.MainBundle.Uri
Invoke-WebRequest $uri -OutFile "$w\windbg.msixbundle" -UseBasicParsing      # ~1.1 GB

# Verify the publisher before unpacking anything.
$sig = Get-AuthenticodeSignature "$w\windbg.msixbundle"
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike '*O=Microsoft Corporation*') {
  throw "unexpected signature: $($sig.Status) / $($sig.SignerCertificate.Subject)"
}

# Expand-Archive dispatches on the extension, so both hops need a .zip name.
Copy-Item "$w\windbg.msixbundle" "$w\b.zip" -Force
Expand-Archive "$w\b.zip" "$w\b" -Force
# Note the two spellings: the .msix is named x64/arm64, while the payload
# directory inside it is amd64/arm64.
$msix = if ($arch -eq "arm64") { "windbg_win-arm64.msix" } else { "windbg_win-x64.msix" }
Copy-Item "$w\b\$msix" "$w\p.zip" -Force
Expand-Archive "$w\p.zip" "$w\p" -Force
```

`$w\p\$arch` is then the payload root: set `$wd` to it and run the copy block above.

**What the signature check settles, and what it does not.** It establishes that the file is the one
Microsoft signed, unmodified — which is the question that matters for a DLL you are about to load
into the debugger. It does **not** make an unregistered payload a supported Microsoft
configuration, and it is not a claim that the engine is fit for anything in particular. Treat it as
this project's floor for telling you to unpack somebody else's package, not as an endorsement by
the publisher.

Three limits worth taking on knowingly:

- **There is no update path, and re-running alone does not give you one.** A copied engine is a
  snapshot and does not follow WinDbg, so re-run the copy when you would have taken an update; the
  `.appinstaller` above always names the *current* bundle, so nothing here needs a version bump.
  But `Expand-Archive -Force` and `Copy-Item -Force` overwrite what collides and delete nothing, so
  a second run **merges** the new payload into the old one — leaving anything the new package
  renamed or dropped in place, a stale `TTDReplay*.dll` beside a new `dbgeng.dll` among them. Clear
  the directories that are copied wholesale first, with the server stopped (see above — a running
  one holds these open):

  ```pwsh
  Remove-Item "$w\b","$w\p" -Recurse -Force -ErrorAction SilentlyContinue   # staging
  Remove-Item "$dst\ttd","$dst\winext","$dst\triage","$dst\winxp" `
              -Recurse -Force -ErrorAction SilentlyContinue
  ```

  **Not `$dst` itself**, which holds `windbg-mcp.exe`. The six loose DLLs need no such treatment:
  they are copied by an explicit list of fixed names, so they have no orphan to leave. The risk is
  entirely in the four `-Recurse` directory copies.
- **The layout inside the bundle is Microsoft's to change.** Run on 2026-08-29 the bundle held
  `windbg_win-arm64.msix`, `windbg_win-x64.msix` and `windbg_win-x86.msix`, and the payload inside
  the ARM64 one carried `amd64\`, `arm64\` and `x86\` trees, each complete — `msdia140.dll`
  included. If `Expand-Archive` produces something else, list `$w\b` and take the `.msix` matching
  your architecture rather than editing the guess.
- **Pick the architecture by `windbg-mcp.exe`**, exactly as the copy block says — not by the host,
  and not by which `.msix` you happened to unpack. Each bundle carries `amd64\`, `arm64\` and
  `x86\` (an ARM64 bundle ships all three), so there is no default to fall back on and a copy that
  takes the first match takes the emulation build. That is the same ordering trap as
  [#131](https://github.com/glslang/windbg-mcp/issues/131), which is easy to walk into twice.

### 32-bit .NET targets need a 32-bit server

Only for **32-bit .NET Framework** targets — a 32-bit dump, which is what `procdump.exe -ma` (as
opposed to `procdump64.exe -ma`) produces, or an `attach_process` on a 32-bit (WoW64) process.
Native analysis of either — stacks, modules, memory — has always worked on the x64 engine and still
does. What does not is SOS, and no amount of configuration fixes that in one process:

- the **32-bit** `sos.dll` cannot be loaded by an x64 debugger at all — `Win32 error 0n193`;
- the **64-bit** one loads and then refuses the target — `Failed to load data access DLL,
  0x80004005` — because `mscordacwks` is paired to the *target's* architecture as well as the
  host's.

An extension DLL is loaded into the debugger's own process, so the only way to load one that
matches the target is to put the engine in a process that matches it too — and a process's
architecture is fixed when its image loads, so that means a second image. The release zip ships
one: a 32-bit build of this same server, at `x86\windbg-mcp.exe`. The server spawns it instead of
re-executing itself when the target is a 32-bit user-mode one, and nothing about the session looks
different from outside — same handle, same tools, same client.

How it knows differs between the two, and neither needs an engine to answer: a dump carries its
architecture in its own header, and a live process answers `IsWow64Process2`. Both are read in the
server before the worker starts, because afterwards is too late.

**One thing a 32-bit worker still cannot give you, and it is not about the worker.** The five
`heap_*` tools refuse any target that is not x64 — *"heap walking supports x64 targets only
(machine 0x14c)"* — because the walker decodes x64 segment-heap structures, so a 32-bit target has
no heap tools whichever engine holds it. SOS's own `!dumpheap` and `!eeheap` are the managed
equivalent and do work here, which is the reason to be on this page at all.

**And one thing it is a trade rather than a win: `attach_process` on a running WoW64 process no
longer shows you the 64-bit half of it.** A WoW64 process has two: the 32-bit program, and the
emulation layer (`wow64.dll`, `wow64cpu.dll`, `wow64win.dll` and the 64-bit `ntdll`) living above
4 GiB. The 64-bit engine sees both and switches between them with `!wow64exts.sw`; the 32-bit
engine sees only the 32-bit one — measured on the same process, 36 modules against 30. That is the
right trade when you are here for SOS, which is what a 32-bit .NET session is for, and the wrong
one if you are debugging the thunk layer itself. Nothing is lost on a **dump**, where a 32-bit
capture never held the 64-bit side to begin with; if you want both halves of a live process, take a
capture with the 64-bit `procdump64.exe -ma` and open that instead, which routes to the x64 engine.

What it needs beside it is a 32-bit engine. It comes from the **same three sources** as the payload
above and from the same `x86\` tree inside each — an ARM64 or x64 package carries the 32-bit
payload as well as its own — so pick the source you already took and copy that tree into the
`x86\` subdirectory:

```pwsh
# $dst is the same folder as the copy block above — the one that holds windbg-mcp.exe.
$dst = "<folder that holds windbg-mcp.exe>"
# Same three sources, x86 tree. Pick ONE, as above.
$wd86 = (Get-AppxPackage Microsoft.WinDbg).InstallLocation + "\x86"   # (a)
# $wd86 = "$w\p\x86"                                                 # (b) unpacked bundle
# $wd86 = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86"      # (c) SDK — no msdia140.dll
New-Item "$dst\x86" -ItemType Directory -Force | Out-Null
Copy-Item "$wd86\dbgeng.dll","$wd86\dbghelp.dll","$wd86\dbgcore.dll",`
          "$wd86\dbgmodel.dll","$wd86\symsrv.dll","$wd86\msdia140.dll" "$dst\x86" -Force
Copy-Item "$wd86\winext" "$dst\x86\winext" -Recurse -Force
```

**Building from source, the worker is yours to put there as well** — the release zip already
carries it, a `cargo build` does not:

```pwsh
cargo build --release --target i686-pc-windows-msvc
Copy-Item target\i686-pc-windows-msvc\release\windbg-mcp.exe "$dst\x86" -Force
```

The file name matters: the server looks for `x86\windbg-mcp.exe`, or for whatever the running
image is called if that differs. Check the directory holds both halves — `windbg-mcp.exe` and
`dbgeng.dll` — because either one alone routes nothing.

Three things about this differ from the copy block above, and each of them is a way to get it
wrong:

- **It must be a subdirectory, never beside `windbg-mcp.exe` itself.** The loader searches an
  executable's own directory first — which is exactly what makes the subdirectory work, since
  `x86\windbg-mcp.exe` finds the engine sitting next to it. Drop an x86 `dbgeng.dll` next to the
  x64 one instead and the wrong process finds it, and neither works. The package's own `amd64\` /
  `x86\` layout is this same rule.
- **`$arch` is *not* matched to the `windbg-mcp.exe` you launch.** Everywhere else in this document
  the rule is "match the DLLs to the binary that loads them", and that still holds — these DLLs are
  loaded by `x86\windbg-mcp.exe`, not by the one beside them. This payload is x86 because the
  *target* is.
- **`x86\windbg-mcp.exe` has to be there too**, which is the block above rather than this one.
  The engine payload alone is not enough: without the 32-bit server the dump still opens, on the
  x64 build, and the session reports a `limitation` saying SOS is unreachable — so a half-populated
  `x86\` fails quietly in the sense that everything works except the one thing you came for.

From **(c)**, drop `msdia140.dll` from that file list as well — its `x86` tree has none, so the copy
fails with it left in. If the `dbghelp.dll` you put there cannot then read a PDB unaided, private
symbols for the 32-bit target need that file from elsewhere: the same caveat, and the same
dependence on the `dbghelp.dll` you bundle, as the payload above.

### When the store package will not install

`Get-AppxPackage Microsoft.WinDbg` returning nothing is not always a matter of installing it. MSIX
registration fails from a **non-interactive** session — `Add-AppxPackage` returns `0x80070005` even
when elevated — and leaves the payload staged but unrunnable, because `WindowsApps` denies execute
to an unregistered package. So the files can be on disk and every one of them refuse to run.
Installing from the machine's own console session is the fix and the first thing to reach for.

Where that is not available, **the bundle needs no install at all**: source (b) above, [*Unpacking
the `.msixbundle`*](#unpacking-the-msixbundle--source-b), is the same payload as an ordinary zip
download, and it is a supported path here rather than a trick — this repository's own TTD smoke
tier runs against an engine bundled that way. The SDK Debugging Tools, source (c), are the other
way through and stop short of TTD: they hold everything **except `msdia140.dll` and `ttd\`**.

[#132](https://github.com/glslang/windbg-mcp/issues/132) is why this is written down rather than
assumed away. Note that `open_trace` reports a missing `ttd\` explicitly instead of leaving you with
`0x80070057` — but it checks that the directory is *there*, not that what is in it matches your
binary, so a wrong-architecture copy still surfaces as the bare engine error.

## Symbols — required for `module!func` name resolution

Symbol *names* fail silently without all three of:

1. **`msdia140.dll` bundled next to the binary** (the copy above). Without it `dbghelp`
   can't parse any PDB (`dia error 0x8007007e`) and falls back to *export* symbols, so
   `module!name` lookups fail even with the right PDB cached. `symsrv.dll` is needed to
   read a symbol-store cache.
2. **A symbol path:** use the **`set_symbol_path`** tool with
   `srv*C:\ProgramData\Dbg\sym*https://msdl.microsoft.com/download/symbols` and
   `append: true`. It goes through DbgEng's `Append/SetSymbolPath`, so it avoids
   `.sympath`'s habit of swallowing the rest of the command line. Naming the cache
   explicitly is *recommended*, not required — `.symfix` with no argument uses the `sym`
   subdirectory of the debugger's installation directory — but an explicit path is
   predictable and lets several binaries share one store.
3. **A `.reload /f <mod>` at a stopped position** (after a `go`/breakpoint, not off a bare
   `!tt`), module-qualified so it fetches the PDB you actually want rather than walking
   every loaded module. Under `!sym noisy` when it does not work, so the search is
   visible. Confirm with `execute` → `lm m <mod>`: `(pdb symbols)` means it worked,
   `(export symbols)` means it didn't.

### Check the engine before blaming the path

**This is the one that actually bit, and the path is the tempting explanation.** The same
`file not found` appears when the PDB *is* in the cache and the engine simply cannot read
it. `dbgeng.dll` exists in System32, so a binary with no DLLs beside it opens targets and
runs commands quite happily — it just has no `symsrv.dll` to read a symbol store and no
`msdia140.dll` to parse a PDB. Under `!sym noisy` you get:

```text
DBGHELP: ntkrnlmp.pdb - file not found
DBGHELP: nt - export symbols
```

with **no `SYMSRV:` line above it**, and an error summary blaming the store (`invalid UNC
store`, `pingme.txt` missing) when the store is fine and the PDB is sitting in it. Nothing
in that output points at the engine, which is why it is worth knowing.

`!lmi <mod>` separates the two, and is worth running before changing any path:

```text
Debug Data Dirs: Type  Size     VA  Pointer
             CODEVIEW    25, 54ea8,   54ea8 RSDS - GUID: {3E0BF93D-...-9CDCB8C7}
               Age: 1, Pdb: ntkrnlmp.pdb
    Symbol Type: EXPORT   - PDB not found
```

A **CODEVIEW line with a GUID** means the identity was read from the image and the lookup
still failed — engine or store, not the target. The store directory for that PDB is the GUID
with the age appended (`3E0BF93D…9CDCB8C71`), so you can check by hand whether it is already
cached. **No CODEVIEW line** is the other failure: the image headers could not be read, and
no symbol server can be queried without them.

Two more things that mislead here:

- `.reload /f <mod>` fetches one module's PDB; bare `.reload /f` walks every loaded module,
  which on a live kernel is a couple of hundred of them and correspondingly slow. Reach for
  the unqualified form only to rule the module name out as the variable.
- `x <mod>!<symbol>` prints **nothing at all** for an unresolved name — no error, no
  diagnostic. Its silence is not confirmation. `lm m <mod>` is the check that answers.

Symbols are never fetched from the target over the KD wire, so all of this is about the
**debugging host**, whatever the target is.

### Allocator tools need private `nt` or `ntdll` types

`pool_find_tag`, `pool_census`, `pool_chunk` and `pool_diagnostics` decode the kernel pool's
segment allocator internals (`_EX_POOL_HEAP_MANAGER_STATE`, the page-range descriptors, the VS and LFH
headers). Exports are not enough. Without full type information every pool query fails up
front with `missing allocator symbols (ExPoolState); run '.reload /f nt' and retry` — which
is a symbol problem on this host, not a statement about the target's pool.

Offline / no symbols? Navigation, memory reads, disassembly, and the data model still work
— query by address instead of by name.

The user-mode `heap_list`, `heap_allocations`, `heap_chunk`, `heap_census` and
`heap_diagnostics` tools have the same requirement for the exact loaded `ntdll` PDB. Use
`.reload /f ntdll.dll` for them, and `.reload /f nt` for `pool_*`; the error guidance is deliberately
module-specific. `heap_list` still lists classic NT heaps as unsupported once the PDB is loaded;
use `!heap` for those rather than treating them as missing Segment Heap coverage.

## Kernel connection profiles — configure once, keep the key out of the transcript

A KDNET connection string carries the target's debug key (`net:port=50000,key=<w.x.y.z>`), and a
key passed as a tool argument is in the MCP client's transcript from then on — copied through
messages, tool calls, context snapshots and compaction summaries. Configure the connection on
**this host** instead and `attach_kernel { "profile": "<name>" }` names it without the key ever
entering the request.

Either source works; the environment is checked first, then the file. **They differ in when a
change takes effect**, which decides which one to reach for:

**File** — `%USERPROFILE%\.windbg-mcp\profiles.json`, or wherever `WINDBG_MCP_PROFILES` points.
Re-read on **every attach**, so an edit works immediately, with nothing restarted. This is the one
to add a profile to mid-session:

```json
{
  "ctf-vm": "net:port=50000,key=1.2.3.4",
  "lab":    "net:port=50001,key=5.6.7.8"
}
```

**Environment**, in whatever launches the MCP server — the client's server definition, or the shell
the client itself was started from. The variable's suffix is the profile name, lowercased, so this
defines `ctf_vm` (and `ctf-vm` resolves to it too):

```pwsh
$env:WINDBG_MCP_PROFILE_CTF_VM = "net:port=50000,key=1.2.3.4"
```

The server reads its *own* environment, which was fixed when it started, so setting this in a shell
alongside a running server changes nothing until that server is restarted. Use it for a profile you
want configured permanently; use the file for one you want now.

This file holds keys: keep it out of every repository, and out of any directory that gets synced
or shared. Names are matched case-insensitively with `-`, `_` and `.` equivalent, and the sources
are re-read on every attach — adding a profile does not mean restarting the MCP client. Two
consequences of that matching worth knowing:

- `ctf-vm` and `ctf.vm` in the **same** source are one name. If they point at different targets,
  *neither* resolves until you rename or remove one — guessing would open a session on the wrong
  machine while reporting it as the right one. (Two spellings of the *same* connection are fine,
  and the environment overriding the file is the documented precedence, not a conflict.)
- An entry whose name is not a name (letters, digits, `-`, `_`, `.`) is skipped, and not quoted
  back in the error — the usual cause is an entry written the wrong way round, which would make
  the name the connection string.

Raw connection strings stay supported (`attach_kernel { "connection": "net:port=…,key=…" }`) for a
target no profile covers. Either way the session reports itself with the key masked —
`kernel target: profile "ctf-vm" (net:port=50000,key=<redacted>)` — so `session_status` can still
tell two kernel targets apart. `attach_kernel` with no arguments lists the profiles this host has.

## Elevation matrix

| Operation | Administrator? |
|-----------|----------------|
| Crash-dump analysis (`open_dump`) | No |
| TTD replay (`open_trace`) | No |
| Live user-mode (`launch` / `attach_process`) | No (unless the target requires it) |
| Live kernel (`attach_kernel_local` / `attach_kernel`) | **Yes** |
| TTD recording (`record_trace`) | **Yes** + a `TTD.exe` — the bundled `ttd\TTD.exe` will do; `PATH` only overrides it |

`record_trace` captures the recorder's startup output to `<out_dir>\ttd_record.log` and
watches it briefly, so a fast failure (e.g. un-elevated → `0x80070005 Access is denied`)
is reported as an error rather than a false "recording started".

## The server on another machine

Everything above is about the machine the **server** runs on, which need not be the machine the
client and the model run on. DbgEng is Windows-only and holds one debuggee per process; nothing
about the client is. So the engine bundle, the symbols and the elevation table are the *debugger
host's* problem, and the setup question that changes when the client is elsewhere is only how it
gets there.

```console
# on the debugger host, with WINDBG_MCP_LISTEN_TOKEN set to a long random string
windbg-mcp.exe --listen 127.0.0.1:8765
# on the client machine — the same string, spelled out: the variable is set on the
# debugger host, and a shell that does not have it expands it to nothing, which is
# an `Authorization: Bearer ` header and a `401` on every call
ssh -N -L 8765:127.0.0.1:8765 <debugger-host>
claude mcp add windbg-vm --transport http http://127.0.0.1:8765/ \
  --header "Authorization: Bearer <the same string>"
```

Four things decide whether that works, and each fails in a way that reads as something else:

- **A token is required and the server refuses to start without one.** This endpoint runs
  `execute`, `debug_batch` and `launch`, so an unauthenticated port is arbitrary code on the host
  holding your kernel debugger. A start that exits immediately, having said so on stderr, is this.
- **Bind loopback and forward over ssh.** The token is sent in clear, and a hypervisor's guest
  network is not private when the machine being debugged is on it. A non-loopback bind warns on
  every start rather than refusing, because sometimes you mean it.
- **Symbols are still fetched by the server**, from the debugger host's `_NT_SYMBOL_PATH` — never
  over the link from the client, and never over the KD wire from the target. A client with symbols
  configured and a server without resolves nothing.
- **For anything longer than one session, install it as a service** (`--install-service --listen
  <addr>`, elevated, **from a directory Windows protects**) — and then **start it**. Installing only
  *registers* it; "starts automatically" means from the next boot, so `Start-Service windbg-mcp` is
  what gets you an endpoint in this one. Skip that and everything keeps working until the foreground
  listener stops, and there is nothing listening after it. The **directory** is a refusal rather
  than advice: the SCM stores that exact path for a `LocalSystem` auto-start service, so
  `--install-service` rejects an exe outside `%ProgramFiles%`, `%ProgramFiles(x86)%` or
  `%SystemRoot%` — which a downloaded zip, a Scoop shim and a `target\release` build all are. Move
  the whole deployment there first, engine DLLs and `x86\` included; `--allow-unprotected-path`
  installs in place, and is a development install rather than a deployment.
  Once running it survives logout, comes back at boot, and
  has a defined working directory — which is what decides whether the engine DLLs beside the exe
  are the ones that load. Note `LocalSystem` does not read *your* `%USERPROFILE%`, so kernel
  profiles have to be configured machine-wide for a service to see them. Giving it a **second
  client** later costs neither a reinstall nor the sessions it is holding —
  `--add-listen-client <name>`, elevated, which generates the token, leaves it beside the
  credential file and prints only a fingerprint. Add `--tools <spec>` to serve that client a
  surface of its own — usually a smaller one, though the spec *replaces* the run's rather than
  narrowing it, so a wider one is served too. `--set-listen-client-tools <name> --tools <spec>`
  changes it afterwards, and the same command with **no** `--tools` puts the client back on the
  run's surface. That is how a local model shares a listener with a full client.
  `--list-listen-clients` prints who may connect and what each is served without changing
  anything — the only one of the five that is safe to run when you just want to look.

Two behaviours differ from stdio and are worth knowing before they surprise you.

**A disconnect is not a teardown, and what reclaims an abandoned target depends on the revision the
client negotiated.** Under stdio, closing the connection releases every session. Over HTTP there is
no such event, and two different mechanisms cover it:

- A client whose revision still mints an `Mcp-Session-Id` holds a **lease**: silence past the grace
  releases everything that credential has open, and coming back *inside* the grace adopts what it
  left — which is what keeps a client restart from costing a KDNET attach.
- On **`2026-07-28`** — which is what most clients now negotiate — there is no session id, so no
  lease is ever armed. What reclaims a target there is the per-session **idle release**: 30 minutes
  since the last call that *reached that session's engine*. It is deliberately not the lease: a
  stateless client is legitimately silent for a long time (a model thinking between calls), and
  releasing a live kernel from under someone who is merely thinking is worse than holding an
  abandoned one for half an hour.
  - **Polling does not count as using it.** `session_status` and `server_log` name a session but are
    answered by the supervisor and never routed to its worker — which is what keeps them working
    while that session is wedged — so neither touches the idle clock. A loop that watches a session
    without asking it anything will watch it be released.

That second mechanism **spares a session with a call still outstanding**, and a parked
`attach_kernel` is exactly that — so a kernel attach whose target never dialled in is held until
somebody ends it, not until a timer notices. `session_status` says how long it has been waiting;
`end_session` reclaims it and terminates the worker.

**Every client authenticates as itself.** Two tokens are two namespaces, so a session opened under
one is *unknown* to the other rather than refused. If a handle has "vanished", check which token the
request carried.

`docs/remote-listener.md` in the repository is the operator's reference for the rest — the grace
and how to change it, what a `409` means, running behind a service, and adding, revoking or
rotating a client while it runs.

## What drives the server — there is a choice

Everything above assumes an MCP client with a hosted model, over stdio or the listener. That is one
of three arrangements, and the other two need nothing added to this server: a listener is an HTTP
MCP endpoint, and anything that speaks MCP can hold one.

- **An MCP client with a hosted model** — Claude Code, an editor. The default; nothing else in this
  file changes.
- **A model in ollama.** An MCP client that drives an ollama model holds the listener exactly as an
  editor does — ollama ships integrations for several of them (`ollama launch` lists them), nothing
  here has to be installed, and this server never learns which kind of model answered. The
  repository's `tools/local_model_drive.py` is **not** that route: it is the benchmark's batch
  driver, it wants a checkout and Python, and it ships in no release.
- **A model in ollama's cloud.** The same endpoint and the same script; a cloud tag changes the
  model name and nothing else.

Four things decide whether the ollama route works, and none of them is about the debugger:

- **Give it a credential of its own**, never the one your editor is registered with. Two tokens are
  two namespaces, so a run on a shared one can see, route to, and at the four-session cap cause the
  reclamation of, the targets you are working in. `--add-listen-client <name>` mints one, and
  `--tools <spec>` beside it serves that client a surface of its own.
- **A `tools` capability is necessary and not sufficient.** The driver picks the first installed
  model that declares one, because a model without it fails at the first call with an error about
  something else. A *cloud* tag can declare it and still not be runnable — it is a registered name
  with no local weights, and the entitlement is resolved at inference — so send it one token first
  (`/api/generate` with `num_predict: 1`) rather than discovering it mid-run.
- **A model that goes quiet can lose its sessions, and which of the two clocks above takes them
  depends on the revision its client negotiated** — so the remedy is not the same one. A client
  still minting an `Mcp-Session-Id` holds the **lease**, whose grace is derived from how long a
  *call* may take, on the assumption that the server is the slow party; a thinking model or a queued
  cloud request is silence with nothing in flight, and *any* admitted request renews it, which is
  why the benchmark's driver simply pings. A client on `2026-07-28` — most of them now — is never
  leased, and what reclaims its targets is the 30-minute **idle release** instead, which a ping
  cannot refresh: only a call that reaches that session's engine counts, which is the same rule that
  makes `session_status` polling useless above. So do not fit a keepalive to a stateless client. It
  needs real work, a longer `WINDBG_MCP_SESSION_IDLE_SECS`, or nothing at all — thirty minutes of
  thinking is a much rarer thing than the lease's grace, and a session with a call still outstanding
  is spared either way.
- **The surface is the fixed cost and a single answer is the variable one.** All 51 tools are about
  70 kB of JSON, paid once per conversation and narrowable per client with `--tools`; one careless
  `read_memory` is up to ~4 MiB, paid on the spot. Narrowing costs fewer *answers* than it does
  tools — most facts here are reachable by more than one route — so it is a real option rather than
  a mutilation.

`docs/local-model.md` in the repository is the runbook for that route: the listener, the link, the
credential, choosing a tag, and what a cloud tag can no longer tell you about its own run.
`docs/local-model-eval.md` is the graded grid behind the claim about narrowing.
