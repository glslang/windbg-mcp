<#
.SYNOPSIS
    Run the windbg-mcp live regression tier against the MessageManager CTF VM.

.DESCRIPTION
    Builds and deploys a benign fixture that retains real Tgsm allocations, waits for its
    ready line over WinRM, then runs the ignored Rust smoke test that drives windbg-mcp over
    stdio. The test attaches over KDNET, verifies MessageManager.sys, finds Tgsm through the
    structured pool tools, checks that the session remains responsive, and detaches cleanly.

    KDNET connection strings and credentials are inputs only. The transcript redacts key= and
    never serializes the PSCredential. The target driver must already be installed and running.

.EXAMPLE
    $cred = Get-Credential
    $env:WINDBG_MCP_SMOKE_KERNEL = 'net:port=50000,key=<w.x.y.z>'
    .\ctf_regression.ps1 -TargetHost ctf-vm -Credential $cred

.EXAMPLE
    $cred = Import-Clixml "$env:USERPROFILE\.credentials\ctf.xml"
    .\ctf_regression.ps1 -TargetHost ctf-vm -Credential $cred `
        -Connection $env:WINDBG_MCP_SMOKE_KERNEL `
        -SymbolPath 'srv*C:\symbols*https://msdl.microsoft.com/download/symbols'
#>
[CmdletBinding()]
param(
    [string] $Connection = $env:WINDBG_MCP_SMOKE_KERNEL,

    [Parameter(Mandatory = $true)]
    [string] $TargetHost,

    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential] $Credential,

    [ValidateRange(30, 3600)]
    [int] $FixtureSeconds = 900,

    [ValidateRange(1, 4096)]
    [int] $MessageCount = 256,

    [string] $SymbolPath = $env:WINDBG_MCP_SMOKE_SYMBOLS,

    [string] $RemoteDirectory = 'C:\Windows\Temp\windbg-mcp-ctf-regression',

    [switch] $SkipHarnessBuild,
    [switch] $KeepRemoteArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Connection) -or $Connection -match '<[^>]+>') {
    throw 'Pass a real KDNET connection with -Connection or WINDBG_MCP_SMOKE_KERNEL.'
}
if ($RemoteDirectory -notmatch '^[A-Za-z]:\\[^\\].+' -or
    $RemoteDirectory -match '(^|\\)\.\.(\\|$)') {
    throw 'RemoteDirectory must be a specific absolute directory without parent traversal.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$artifactDirectory = Join-Path $repoRoot 'target\ctf-regression'
[void] (New-Item -ItemType Directory -Force -Path $artifactDirectory)
$localFixture = Join-Path $artifactDirectory 'mm_fixture.exe'
$source = Join-Path $PSScriptRoot 'mm_exploit.c'
$build = Join-Path $PSScriptRoot 'build.cmd'

if (-not $SkipHarnessBuild) {
    & $build $source $localFixture
    if ($LASTEXITCODE -ne 0) { throw "MessageManager fixture build failed: $LASTEXITCODE" }
}
if (-not (Test-Path -LiteralPath $localFixture -PathType Leaf)) {
    throw "Fixture executable does not exist: $localFixture"
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcript = Join-Path $artifactDirectory "ctf-regression-$stamp.log"
$remoteFixture = "$RemoteDirectory\mm_fixture.exe"
$remoteStdout = "$RemoteDirectory\fixture.out.log"
$remoteStderr = "$RemoteDirectory\fixture.err.log"
$remoteStop = "$RemoteDirectory\fixture.stop"
$session = $null
$fixturePid = $null
$testSucceeded = $false

function Protect-TranscriptLine([string] $Line) {
    if ($null -eq $Line) { return '' }
    $safe = $Line.Replace($Connection, '<KDNET connection redacted>')
    return [regex]::Replace($safe, '(?i)(key\s*=\s*)[^,\s"'']+', '$1<redacted>')
}

function Write-TranscriptLine([string] $Line) {
    $safe = Protect-TranscriptLine $Line
    Write-Host $safe
    [System.IO.File]::AppendAllText($transcript, $safe + [Environment]::NewLine)
}

try {
    $option = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 60000
    $session = New-PSSession -ComputerName $TargetHost -Credential $Credential `
        -SessionOption $option

    Invoke-Command -Session $session -ScriptBlock {
        param($Directory, $Stdout, $Stderr, $StopFile)
        [void] (New-Item -ItemType Directory -Force -Path $Directory)
        foreach ($path in @($Stdout, $Stderr, $StopFile)) {
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        }
    } -ArgumentList $RemoteDirectory, $remoteStdout, $remoteStderr, $remoteStop

    Copy-Item -LiteralPath $localFixture -Destination $remoteFixture -ToSession $session -Force

    $fixture = Invoke-Command -Session $session -ScriptBlock {
        param($Executable, $Seconds, $Messages, $StopFile, $Stdout, $Stderr, $Directory)
        $arguments = @(
            'fixture',
            $Seconds.ToString(),
            $Messages.ToString(),
            ('"{0}"' -f $StopFile)
        )
        $process = Start-Process -FilePath $Executable -ArgumentList $arguments `
            -WorkingDirectory $Directory -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr
        [pscustomobject] @{ Pid = $process.Id }
    } -ArgumentList $remoteFixture, $FixtureSeconds, $MessageCount, $remoteStop,
        $remoteStdout, $remoteStderr, $RemoteDirectory
    $fixturePid = [int] $fixture.Pid

    $readyDeadline = [DateTime]::UtcNow.AddSeconds(60)
    $fixtureState = $null
    do {
        $fixtureState = Invoke-Command -Session $session -ScriptBlock {
            param($FixtureProcessId, $Stdout, $Stderr)
            $process = Get-Process -Id $FixtureProcessId -ErrorAction SilentlyContinue
            [pscustomobject] @{
                Running = $null -ne $process
                Stdout = if (Test-Path -LiteralPath $Stdout) {
                    Get-Content -Raw -LiteralPath $Stdout
                } else { '' }
                Stderr = if (Test-Path -LiteralPath $Stderr) {
                    Get-Content -Raw -LiteralPath $Stderr
                } else { '' }
            }
        } -ArgumentList $fixturePid, $remoteStdout, $remoteStderr

        if ($fixtureState.Stdout -match '\[fixture\] ready:') { break }
        if (-not $fixtureState.Running) {
            throw "Fixture exited before ready.`nstdout:`n$($fixtureState.Stdout)`nstderr:`n$($fixtureState.Stderr)"
        }
        if ([DateTime]::UtcNow -ge $readyDeadline) {
            throw "Timed out waiting for fixture readiness.`nstdout:`n$($fixtureState.Stdout)"
        }
        Start-Sleep -Milliseconds 500
    } while ($true)

    Write-TranscriptLine "fixture ready on $TargetHost (pid $fixturePid, messages $MessageCount)"
    foreach ($line in @($fixtureState.Stdout -split "`r?`n")) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { Write-TranscriptLine $line }
    }

    $oldKernel = $env:WINDBG_MCP_SMOKE_KERNEL
    $oldCtf = $env:WINDBG_MCP_SMOKE_CTF
    $oldSymbols = $env:WINDBG_MCP_SMOKE_SYMBOLS
    try {
        $env:WINDBG_MCP_SMOKE_KERNEL = $Connection
        $env:WINDBG_MCP_SMOKE_CTF = '1'
        if (-not [string]::IsNullOrWhiteSpace($SymbolPath)) {
            $env:WINDBG_MCP_SMOKE_SYMBOLS = $SymbolPath
        }

        Push-Location $repoRoot
        $testExit = 1
        $oldErrorActionPreference = $ErrorActionPreference
        try {
            # Windows PowerShell 5.1 wraps native stderr records as non-terminating errors.
            # Cargo writes ordinary progress there, so `Stop` would abort before its exit code
            # can be inspected even though `2>&1` intentionally captures the stream.
            $ErrorActionPreference = 'Continue'
            & cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 `
                a_messagemanager_ctf_fixture_is_visible_through_mcp 2>&1 | ForEach-Object {
                    Write-TranscriptLine $_.ToString()
                }
            $testExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $oldErrorActionPreference
            Pop-Location
        }
        if ($testExit -ne 0) { throw "CTF regression test failed: cargo exit $testExit" }
        $testSucceeded = $true
    } finally {
        $env:WINDBG_MCP_SMOKE_KERNEL = $oldKernel
        $env:WINDBG_MCP_SMOKE_CTF = $oldCtf
        $env:WINDBG_MCP_SMOKE_SYMBOLS = $oldSymbols
    }
} finally {
    if ($null -ne $session -and $null -ne $fixturePid) {
        try {
            $cleanup = Invoke-Command -Session $session -ScriptBlock {
                param($FixtureProcessId, $StopFile, $Stdout, $Stderr)
                [void] (New-Item -ItemType File -Force -Path $StopFile)
                $deadline = [DateTime]::UtcNow.AddSeconds(30)
                while ($null -ne (Get-Process -Id $FixtureProcessId -ErrorAction SilentlyContinue) -and
                       [DateTime]::UtcNow -lt $deadline) {
                    Start-Sleep -Milliseconds 250
                }
                $forced = $null -ne (Get-Process -Id $FixtureProcessId -ErrorAction SilentlyContinue)
                if ($forced) {
                    Stop-Process -Id $FixtureProcessId -Force -ErrorAction SilentlyContinue
                }
                [pscustomobject] @{
                    Forced = $forced
                    Stdout = if (Test-Path -LiteralPath $Stdout) {
                        Get-Content -Raw -LiteralPath $Stdout
                    } else { '' }
                    Stderr = if (Test-Path -LiteralPath $Stderr) {
                        Get-Content -Raw -LiteralPath $Stderr
                    } else { '' }
                }
            } -ArgumentList $fixturePid, $remoteStop, $remoteStdout, $remoteStderr
            if ($cleanup.Forced) {
                Write-Warning 'Fixture did not stop cleanly and was terminated.'
            }
            foreach ($line in @($cleanup.Stdout -split "`r?`n")) {
                if (-not [string]::IsNullOrWhiteSpace($line) -and
                    $line -notmatch '\[fixture\] ready:') {
                    Write-TranscriptLine $line
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($cleanup.Stderr)) {
                Write-TranscriptLine "fixture stderr: $($cleanup.Stderr)"
            }
        } catch {
            Write-Warning "Remote fixture cleanup failed; verify the VM is running: $_"
        }
    }
    if ($null -ne $session -and -not $KeepRemoteArtifacts) {
        try {
            Invoke-Command -Session $session -ScriptBlock {
                param($Fixture, $Stdout, $Stderr, $StopFile)
                foreach ($path in @($Fixture, $Stdout, $Stderr, $StopFile)) {
                    if (Test-Path -LiteralPath $path) {
                        Remove-Item -LiteralPath $path -Force
                    }
                }
            } -ArgumentList $remoteFixture, $remoteStdout, $remoteStderr, $remoteStop
        } catch {
            Write-Warning "Remote artifact cleanup failed: $_"
        }
    }
    if ($null -ne $session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
}

if (-not $testSucceeded) { exit 1 }
Write-Host "PASS: MessageManager CTF regression completed. Transcript: $transcript" `
    -ForegroundColor Green
