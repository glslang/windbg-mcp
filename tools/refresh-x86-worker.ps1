<#
.SYNOPSIS
    Build the 32-bit worker, put it where the supervisor looks, and refuse a stale one.

.DESCRIPTION
    The 32-bit managed-target tier needs `x86\windbg-mcp.exe` beside a 32-bit engine, and
    `cargo build` does not produce it: it builds the host triple only, and the i686 build lands
    in `target\i686-pc-windows-msvc\<profile>\` rather than in `target\<profile>\x86\`. Two gaps,
    so two steps, which is what this script is.

    It builds the supervisor too, because the check below is a comparison and both halves have to
    be current for it to mean anything - and on a fresh tree there is no supervisor at all, `target`
    being ignored.

    The check is the reason this exists rather than a note in a rule: `build.rs` watches `.git\HEAD`
    and the branch ref, so a `git commit` re-stamps the supervisor from `<commit>-dirty.<digest>` to
    a clean `<commit>` while a worker built minutes earlier keeps the old one. The tier then fails
    saying this host could not give the target a 32-bit worker, which reads as a missing file rather
    than a stale one.

    A mismatch is not a runtime hazard: the supervisor turns the worker away and the session falls
    back to the 64-bit build. Only the tier fails.

    A 32-bit worker with no 32-bit `dbgeng.dll` beside it **is** treated as a failure. The
    supervisor probes for both before spawning, so a worker without the engine is never used - and
    the tier stands down rather than failing in that state, so nothing else would say so.

.PARAMETER Profile
    Which profile to refresh, `debug` (the default, what `cargo test` runs) or `release`.

.PARAMETER Check
    Report whether the worker matches the supervisor and exit; build and copy nothing.
    Exit code 0 means they agree, 1 means they do not or either binary is absent.

.PARAMETER SkipEngine
    Do not copy engine DLLs. The 32-bit engine must still be present for this to succeed: the
    switch says where the engine comes from, not whether the worker needs one.

.EXAMPLE
    .\tools\refresh-x86-worker.ps1
    Build both binaries, place the worker, and confirm the stamps agree.

.EXAMPLE
    .\tools\refresh-x86-worker.ps1 -Check
    Ask whether the tier would fail on a stale worker, without building anything.

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

function Show-Stamps {
    param([string] $HostStamp, [string] $WorkerStamp)

    Write-Host ("  supervisor : {0}" -f $HostStamp)
    if ($null -eq $WorkerStamp) {
        Write-Host "  worker     : (absent)"
    }
    else {
        Write-Host ("  worker     : {0}" -f $WorkerStamp)
    }
}

function Copy-Engine {
    param([string] $From, [string] $To, [string] $What, [switch] $Required)

    $destination = Join-Path $To 'dbgeng.dll'
    $present = Test-Path -LiteralPath $destination

    if (-not $present -and -not $SkipEngine -and (Test-Path -LiteralPath (Join-Path $From 'dbgeng.dll'))) {
        Write-Host ("  {0}: copying the engine from {1}" -f $What, $From)
        # The payload is the DLLs plus the extension directories; `windbg-mcp.exe` is excluded
        # because this script writes it itself, and a `.stale` left by a release rebuild must not
        # be dragged along. `sym` is a symbol cache rather than part of the engine.
        Get-ChildItem -LiteralPath $From -Filter '*.dll' | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination $To -Force
        }
        foreach ($directory in @('winext', 'winxp', 'triage', 'ttd')) {
            $source = Join-Path $From $directory
            if (Test-Path -LiteralPath $source) {
                Copy-Item -LiteralPath $source -Destination $To -Recurse -Force
            }
        }
        $present = Test-Path -LiteralPath $destination
    }

    # Required only of the 32-bit engine. The 64-bit half legitimately falls back to the one in
    # System32 for basic live and crash-dump work; the 32-bit half has no such fallback, because
    # `engine::x86_worker_image` probes for `dbgeng.dll` beside the worker and returns nothing
    # without it. A worker placed into that state is never spawned, and `x86_engine_tier` *skips*
    # rather than failing, so exiting 0 here would report a capability nothing has.
    if ($Required -and -not $present) {
        Write-Host ""
        Write-Host ("No 32-bit engine at {0}." -f $destination) -ForegroundColor Red
        if (-not (Test-Path -LiteralPath (Join-Path $From 'dbgeng.dll'))) {
            Write-Host ("There is none to copy from {0} either." -f $From)
        }
        Write-Host "The supervisor probes for it before spawning a 32-bit worker and falls back to"
        Write-Host "the 64-bit build without one, so the worker built here would never be used - and"
        Write-Host "the 32-bit tier stands down rather than failing, so nothing else would say so."
        Write-Host "The copy block is in skills\windbg-debugging\setup.md."
        exit 1
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
    $hostStamp = Get-Stamp -Path $hostExe
    $workerStamp = Get-Stamp -Path $workerExe
    Write-Host ("{0} profile:" -f $Profile)
    if ($null -eq $hostStamp) {
        Write-Host ("  supervisor : (absent, at {0})" -f $hostExe)
    }
    else {
        Show-Stamps -HostStamp $hostStamp -WorkerStamp $workerStamp
    }
    if ($null -ne $hostStamp -and $workerStamp -eq $hostStamp) {
        Write-Host "The worker matches; the 32-bit tier has a worker to use." -ForegroundColor Green
        exit 0
    }
    Write-Host "Stale, or not built yet. Re-run this script without -Check." -ForegroundColor Yellow
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

$hostStamp = Get-Stamp -Path $hostExe
if ($null -eq $hostStamp) {
    Write-Host ("The build reported success but produced no {0}." -f $hostExe) -ForegroundColor Red
    exit 1
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
Copy-Engine -From $engineSourceX86 -To $workerDir -What '32-bit' -Required

Copy-Item -LiteralPath $builtExe -Destination $workerExe -Force

$workerStamp = Get-Stamp -Path $workerExe
Write-Host ("{0} profile:" -f $Profile)
Show-Stamps -HostStamp $hostStamp -WorkerStamp $workerStamp

if ($workerStamp -ne $hostStamp) {
    Write-Host ""
    Write-Host "The worker still does not match the supervisor." -ForegroundColor Yellow
    Write-Host "Both were just built, so the likely cause is that one of them declined to build:"
    Write-Host "cargo's freshness is mtime-based, and a git checkout or reset --hard can rewrite a"
    Write-Host "source in the same second as the target built from it. Force it and re-run:"
    Write-Host "  (Get-Item build.rs).LastWriteTime = Get-Date"
    Write-Host ("  .\tools\refresh-x86-worker.ps1 -Profile {0}" -f $Profile)
    Write-Host ""
    Write-Host "If the supervisor's build failed above, that is the cause instead."
    exit 1
}

Write-Host "The worker matches; the 32-bit tier has a worker to use." -ForegroundColor Green
exit 0
