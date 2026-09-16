<#
.SYNOPSIS
    Rebuild the 32-bit worker and put it where the supervisor looks.

.DESCRIPTION
    The 32-bit managed-target tier needs `x86\windbg-mcp.exe` beside a 32-bit engine, and
    `cargo build` does not produce it: it builds the host triple only, and the i686 build lands
    in `target\i686-pc-windows-msvc\<profile>\` rather than in `target\<profile>\x86\`. Two gaps,
    so two steps, which is what this script is.

    It also refuses a worker whose build stamp does not match the supervisor's. That check is the
    reason this exists rather than a note in a rule: `build.rs` watches `.git\HEAD` and the branch
    ref, so a `git commit` re-stamps the supervisor from `<commit>-dirty.<digest>` to a clean
    `<commit>` while the worker built minutes earlier keeps the old one. The tier then fails
    saying this host could not give the target a 32-bit worker, which reads as a missing file
    rather than a stale one. Build the worker AFTER committing, not before.

    A mismatch is not a runtime hazard: the supervisor turns the worker away and the session falls
    back to the 64-bit build. Only the tier fails.

.PARAMETER Profile
    Which profile to refresh, `debug` (the default, what `cargo test` runs) or `release`.

.PARAMETER Check
    Report whether the worker matches the supervisor and exit; build and copy nothing.
    Exit code 0 means they agree, 1 means they do not or the worker is absent.

.PARAMETER SkipEngine
    Do not mirror engine DLLs. By default a missing engine beside either binary is copied from
    `target\release`, which is where this bench keeps the WinDbg payload.

.EXAMPLE
    .\tools\refresh-x86-worker.ps1
    Rebuild and copy the debug worker, then confirm the stamps agree.

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
    param([string] $From, [string] $To, [string] $What)

    if (-not (Test-Path -LiteralPath (Join-Path $From 'dbgeng.dll'))) {
        Write-Host ("  {0}: no engine at {1}; skipping" -f $What, $From)
        return
    }
    if (Test-Path -LiteralPath (Join-Path $To 'dbgeng.dll')) {
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

$hostStamp = Get-Stamp -Path $hostExe
if ($null -eq $hostStamp) {
    Write-Host ("No supervisor at {0}." -f $hostExe) -ForegroundColor Red
    if ($Profile -eq 'release') {
        Write-Host "Build it with: cargo build --release"
    }
    else {
        Write-Host "Build it with: cargo build"
    }
    exit 1
}

if ($Check) {
    $workerStamp = Get-Stamp -Path $workerExe
    Write-Host ("{0} profile:" -f $Profile)
    Show-Stamps -HostStamp $hostStamp -WorkerStamp $workerStamp
    if ($workerStamp -eq $hostStamp) {
        Write-Host "The worker matches; the 32-bit tier has a worker to use." -ForegroundColor Green
        exit 0
    }
    Write-Host "The worker is stale or absent. Re-run this script without -Check." -ForegroundColor Yellow
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

Write-Host ("Building the 32-bit worker ({0}, {1})..." -f $Triple, $Profile)
if ($Profile -eq 'release') {
    & cargo build --release --target $Triple
}
else {
    & cargo build --target $Triple
}
# Checked before the copy, and never through a pipeline: a build whose output is piped reports the
# pipeline's success, and the copy below would then place a stale binary that looks freshly built.
if ($LASTEXITCODE -ne 0) {
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

if (-not $SkipEngine) {
    if ($Profile -ne 'release') {
        Copy-Engine -From $engineSource -To (Split-Path -Parent $hostExe) -What '64-bit'
    }
    Copy-Engine -From $engineSourceX86 -To $workerDir -What '32-bit'
}

Copy-Item -LiteralPath $builtExe -Destination $workerExe -Force

$workerStamp = Get-Stamp -Path $workerExe
Write-Host ("{0} profile:" -f $Profile)
Show-Stamps -HostStamp $hostStamp -WorkerStamp $workerStamp

if ($workerStamp -ne $hostStamp) {
    Write-Host ""
    Write-Host "The worker still does not match the supervisor." -ForegroundColor Yellow
    Write-Host "Two causes, and the stamps above say which is yours:"
    Write-Host ""
    Write-Host "  The supervisor is stale - its stamp is the older one. The tree changed after it"
    Write-Host "  was last built, and a commit counts as a change. Rebuild it, then re-run this:"
    if ($Profile -eq 'release') {
        Write-Host "    cargo build --release"
    }
    else {
        Write-Host "    cargo build"
    }
    Write-Host ("    .\tools\refresh-x86-worker.ps1 -Profile {0}" -f $Profile)
    Write-Host ""
    Write-Host "  The build above declined to run - the worker's stamp is the older one, and cargo"
    Write-Host "  reported Finished in well under a second. Cargo's freshness is mtime-based, and a"
    Write-Host "  git checkout or reset --hard can rewrite a source in the same second as the target"
    Write-Host "  built from it, so the build is skipped and this copies what was already there:"
    Write-Host "    (Get-Item build.rs).LastWriteTime = Get-Date"
    Write-Host ("    .\tools\refresh-x86-worker.ps1 -Profile {0}" -f $Profile)
    exit 1
}

Write-Host "The worker matches; the 32-bit tier has a worker to use." -ForegroundColor Green
exit 0
