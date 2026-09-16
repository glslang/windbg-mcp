<#
.SYNOPSIS
    Build the 32-bit worker, put it where the supervisor looks, and refuse one the tier cannot use.

.DESCRIPTION
    The 32-bit managed-target tier needs `x86\windbg-mcp.exe` beside a 32-bit engine, and
    `cargo build` does not produce it: it builds the host triple only, and the i686 build lands
    in `target\i686-pc-windows-msvc\<profile>\` rather than in `target\<profile>\x86\`. Two gaps,
    so two steps, which is what this script is.

    It builds the supervisor too, because the check below is a comparison and both halves have to
    be current for it to mean anything - and on a fresh tree there is no supervisor at all, `target`
    being ignored.

    **What "usable" means is two conditions, and they are answered in one place**
    (`Get-WorkerFaults`), because answering whichever one is in front of you is how this file drew
    three rounds of review:

    - The worker's stamp matches the supervisor's. `build.rs` watches `.git\HEAD` and the branch
      ref, so a `git commit` re-stamps the supervisor from `<commit>-dirty.<digest>` to a clean
      `<commit>` while a worker built minutes earlier keeps the old one. The supervisor then turns
      the worker away and the tier fails saying this host could not give the target a 32-bit
      worker, which reads as a missing file rather than a stale one.
    - A 32-bit `dbgeng.dll` sits beside the worker. `engine::x86_worker_image` probes for it and
      returns nothing without it, so the worker is never spawned - and `x86_engine_tier` *skips*
      in that state rather than failing, reporting `test result: ok. 2 passed` with both tests
      stood down. Nothing downstream would contradict a success reported here.

    Neither is a runtime hazard: the supervisor falls back to the 64-bit build. Only the tier
    is affected, and in the second case only by quietly covering less than it appears to.

.PARAMETER Profile
    Which profile to refresh, `debug` (the default, what `cargo test` runs) or `release`.

.PARAMETER Check
    Report whether the tier has a worker it can use, and exit; build and copy nothing.
    Exit code 0 means yes, 1 means no, on exactly the conditions the build path enforces.

    It compares the two binaries **as they are on disk**, and there is one state it therefore
    cannot see: both being older than the tree. Run straight after a commit, before anything is
    rebuilt, it finds two stale binaries that agree with each other and reports green - and then
    `cargo test` rebuilds the supervisor and not the worker, and they disagree by the time the
    tier runs. Seeing that would mean reproducing `build.rs`'s revision stamp here, and a gate
    that reimplements the rule it is checking is the thing `x86_engine_tier`'s own comment warns
    against. So: after an edit or a commit, run the build path rather than -Check.

.PARAMETER SkipEngine
    Do not copy engine DLLs. An engine must still be present for this to succeed: the switch says
    where the engine comes from, not whether the worker needs one.

.EXAMPLE
    .\tools\refresh-x86-worker.ps1
    Build both binaries, place the worker, and confirm the tier can use it.

.EXAMPLE
    .\tools\refresh-x86-worker.ps1 -Check
    Ask whether the tier would run for real, without building anything.

.NOTES
    Windows PowerShell 5.1 clean, and deliberately ASCII only: 5.1 decodes a BOM-less UTF-8 file
    in the ANSI code page, so one non-ASCII character can abort the parse tens of lines away from
    where it sits. See .claude\rules\powershell-scripts.md.
#>
[CmdletBinding()]
param(
    [ValidateSet('debug', 'release')]
    [string] $Profile = 'debug',

    [switch] $Check,

    [switch] $SkipEngine
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Triple = 'i686-pc-windows-msvc'

$root = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $root 'Cargo.toml'
$hostExe = Join-Path (Join-Path $root 'target') (Join-Path $Profile 'windbg-mcp.exe')
$workerDir = Join-Path (Join-Path $root 'target') (Join-Path $Profile 'x86')
$workerExe = Join-Path $workerDir 'windbg-mcp.exe'
$workerEngine = Join-Path $workerDir 'dbgeng.dll'
$builtExe = Join-Path (Join-Path $root 'target') (Join-Path $Triple (Join-Path $Profile 'windbg-mcp.exe'))

# The 64-bit payload this bench keeps beside the release build, and the 32-bit one inside its
# `x86\`. The 32-bit engine cannot come from the 64-bit tree: the worker in `x86\` has to find a
# 32-bit `dbgeng.dll` next to itself, which is the whole reason it sits in a subdirectory.
$engineSource = Join-Path (Join-Path $root 'target') 'release'
$engineSourceX86 = Join-Path $engineSource 'x86'

function Get-Stamp {
    param([string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    # The stamped identity rides in ProductVersion; FileVersion stays the bare release, so reading
    # the wrong one compares two strings that agree on every build and proves nothing.
    return (Get-Item -LiteralPath $Path).VersionInfo.ProductVersion
}

# Everything that makes the 32-bit tier unable to use this worker, in one place and phrased for
# whoever reads it. One function rather than a check on each path, because the two conditions are
# independent and every path has to answer both: two review rounds on this file were each one
# condition enforced where the author was looking and not where the caller was.
function Get-WorkerFaults {
    param([string] $HostStamp, [string] $WorkerStamp)

    $faults = @()

    if ($null -eq $HostStamp) {
        $faults += ("There is no supervisor at {0}." -f $hostExe)
    }
    elseif ($null -eq $WorkerStamp) {
        $faults += ("There is no worker at {0}." -f $workerExe)
    }
    elseif ($WorkerStamp -ne $HostStamp) {
        $faults += (
            "The worker's stamp is {0} and the supervisor's is {1}, so the supervisor will turn " +
            "it away and fall back to the 64-bit build." -f $WorkerStamp, $HostStamp)
    }

    if (-not (Test-Path -LiteralPath $workerEngine)) {
        $faults += (
            ("There is no 32-bit engine at {0}. The supervisor probes for it before spawning a " +
             "32-bit worker and falls back without one, and the tier stands down rather than " +
             "failing in that state - it reports two passing tests having run neither. The copy " +
             "block is in skills\windbg-debugging\setup.md.") -f $workerEngine)
    }

    # `return ,` so an empty array survives: the pipeline unrolls a bare empty array into nothing,
    # the caller gets $null, and every `.Count` on it fails under Set-StrictMode.
    # See .claude\rules\powershell-scripts.md.
    return , $faults
}

function Show-Outcome {
    param([string] $HostStamp, [string] $WorkerStamp)

    Write-Host ("{0} profile:" -f $Profile)
    if ($null -eq $HostStamp) {
        Write-Host ("  supervisor : (absent, at {0})" -f $hostExe)
    }
    else {
        Write-Host ("  supervisor : {0}" -f $HostStamp)
    }
    if ($null -eq $WorkerStamp) {
        Write-Host ("  worker     : (absent, at {0})" -f $workerExe)
    }
    else {
        Write-Host ("  worker     : {0}" -f $WorkerStamp)
    }
    if (Test-Path -LiteralPath $workerEngine) {
        Write-Host "  engine     : present"
    }
    else {
        Write-Host "  engine     : (absent)"
    }

    $faults = Get-WorkerFaults -HostStamp $HostStamp -WorkerStamp $WorkerStamp
    if ($faults.Count -eq 0) {
        Write-Host "The 32-bit tier has a worker it can use." -ForegroundColor Green
        return $true
    }
    foreach ($fault in $faults) {
        Write-Host ""
        Write-Host $fault -ForegroundColor Yellow
    }
    return $false
}

function Copy-Engine {
    param([string] $From, [string] $To, [string] $What)

    if ($SkipEngine) {
        return
    }
    if (Test-Path -LiteralPath (Join-Path $To 'dbgeng.dll')) {
        return
    }
    if (-not (Test-Path -LiteralPath (Join-Path $From 'dbgeng.dll'))) {
        Write-Host ("  {0}: no engine at {1} to copy" -f $What, $From)
        return
    }

    Write-Host ("  {0}: copying the engine from {1}" -f $What, $From)
    # The payload is the DLLs plus the extension directories; `windbg-mcp.exe` is excluded because
    # this script writes it itself, and a `.stale` left by a release rebuild must not be dragged
    # along. `sym` is a symbol cache rather than part of the engine.
    Get-ChildItem -LiteralPath $From -Filter '*.dll' | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $To -Force
    }
    foreach ($directory in @('winext', 'winxp', 'triage', 'ttd')) {
        $source = Join-Path $From $directory
        if (Test-Path -LiteralPath $source) {
            Copy-Item -LiteralPath $source -Destination $To -Recurse -Force
        }
    }
}

function Invoke-Cargo {
    param([string[]] $CargoArguments, [string] $What)

    Write-Host ("{0}..." -f $What)
    & cargo @CargoArguments --manifest-path $manifest
    # Checked directly, and never through a pipeline: a build whose output is piped reports the
    # pipeline's success, and a copy after it would place a stale binary that looks freshly built.
    return ($LASTEXITCODE -eq 0)
}

if ($Check) {
    if (Show-Outcome -HostStamp (Get-Stamp -Path $hostExe) -WorkerStamp (Get-Stamp -Path $workerExe)) {
        exit 0
    }
    Write-Host ""
    Write-Host ("Re-run this script without -Check to fix what it can: .\tools\refresh-x86-worker.ps1 -Profile {0}" -f $Profile)
    exit 1
}

$installed = & rustup target list --installed 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "rustup is not on PATH, so the 32-bit target cannot be checked." -ForegroundColor Red
    exit 1
}
if ($installed -notcontains $Triple) {
    Write-Host ("The {0} target is not installed." -f $Triple) -ForegroundColor Red
    Write-Host ("Install it with: rustup target add {0}" -f $Triple)
    exit 1
}

# The supervisor first, because the stamps are compared against it and a comparison against a stale
# one is the mismatch this script exists to explain rather than to cause. On a fresh tree there is
# no supervisor at all, `target` being ignored, so without this the documented one-command refresh
# would stop before building anything.
$hostArguments = @('build')
$workerArguments = @('build', '--target', $Triple)
if ($Profile -eq 'release') {
    $hostArguments += '--release'
    $workerArguments += '--release'
}

if (-not (Invoke-Cargo -CargoArguments $hostArguments -What ("Building the supervisor ({0})" -f $Profile))) {
    if (Test-Path -LiteralPath $hostExe) {
        Write-Host "The supervisor build failed; carrying on with the binary already there." -ForegroundColor Yellow
        Write-Host "The stamp check below is what says whether that one is usable."
        if ($Profile -eq 'release') {
            Write-Host "A release exe held by a running server cannot be replaced ('Access is denied"
            Write-Host "(os error 5)'); rename it aside first - CLAUDE.md has the recipe."
        }
    }
    else {
        Write-Host "The supervisor build failed and there is none to fall back on." -ForegroundColor Red
        exit 1
    }
}

if (-not (Invoke-Cargo -CargoArguments $workerArguments -What ("Building the 32-bit worker ({0}, {1})" -f $Triple, $Profile))) {
    Write-Host "The 32-bit build failed; nothing was copied." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path -LiteralPath $builtExe)) {
    Write-Host ("The build reported success but produced no {0}." -f $builtExe) -ForegroundColor Red
    exit 1
}

if (-not (Test-Path -LiteralPath $workerDir)) {
    New-Item -ItemType Directory -Path $workerDir | Out-Null
}

if ($Profile -ne 'release') {
    Copy-Engine -From $engineSource -To (Split-Path -Parent $hostExe) -What '64-bit'
}
Copy-Engine -From $engineSourceX86 -To $workerDir -What '32-bit'

Copy-Item -LiteralPath $builtExe -Destination $workerExe -Force

$hostStamp = Get-Stamp -Path $hostExe
$workerStamp = Get-Stamp -Path $workerExe
if (Show-Outcome -HostStamp $hostStamp -WorkerStamp $workerStamp) {
    exit 0
}

if ($null -ne $hostStamp -and $null -ne $workerStamp -and $hostStamp -ne $workerStamp) {
    Write-Host ""
    Write-Host "Both were just built, so a stamp mismatch here means one of them declined to build:"
    Write-Host "cargo's freshness is mtime-based, and a git checkout or reset --hard can rewrite a"
    Write-Host "source in the same second as the target built from it. Force it and re-run:"
    Write-Host "  (Get-Item build.rs).LastWriteTime = Get-Date"
    Write-Host ("  .\tools\refresh-x86-worker.ps1 -Profile {0}" -f $Profile)
}
exit 1
