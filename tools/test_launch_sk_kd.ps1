[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'launch_sk_kd.ps1') -LibraryOnly

function Assert-SkLauncher {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) {
        throw $Message
    }
}

$testRoot = Join-Path (Join-Path $PSScriptRoot '..\target') ("sk launcher test " + [guid]::NewGuid())
$resolvedRoot = [System.IO.Path]::GetFullPath($testRoot)
[void] (New-Item -ItemType Directory -Path $resolvedRoot -Force)
try {
    $debugger = Join-Path $resolvedRoot 'debugger with spaces.exe'
    [System.IO.File]::WriteAllBytes($debugger, [byte[]] @(0))
    $resolved = Resolve-SkDebugger -Kind Classic -ExplicitPath $debugger
    Assert-SkLauncher ($resolved -eq $debugger) 'an explicit debugger path containing spaces was not preserved'

    $missing = Join-Path $resolvedRoot 'missing debugger.exe'
    $missingRefused = $false
    try {
        [void] (Resolve-SkDebugger -Kind WinDbgX -ExplicitPath $missing)
    } catch {
        $missingRefused = $_.Exception.Message.Contains('does not exist')
    }
    Assert-SkLauncher $missingRefused 'a missing debugger was not refused before opening a session'

    $events = New-Object System.Collections.Generic.List[string]
    $connection = 'com:pipe,port=\\.\pipe\typed-test,resets=0'
    $fakeOpened = [pscustomobject] @{
        status = 'ok'
        session_id = 'fake-session'
        connection = $connection
    }
    [void] (Invoke-SkKdLauncherCore `
        -OpenSession { [void] $events.Add('open'); return $fakeOpened } `
        -ReadySession { param($actual) [void] $events.Add("ready:$actual") } `
        -LaunchDebugger {
            param($actual)
            [void] $events.Add("launch:$actual")
            return 0
        } `
        -EndSession {
            param($actual)
            [void] $events.Add("end:$actual")
            return [pscustomobject] @{ status = 'ok'; released = $true }
        })
    Assert-SkLauncher (($events -join '|') -eq "open|ready:fake-session|launch:$connection|end:fake-session") `
        'the fake client did not carry the typed connection through ordered cleanup'

    $events.Clear()
    $earlyExitReported = $false
    try {
        [void] (Invoke-SkKdLauncherCore `
            -OpenSession { [void] $events.Add('open'); return $fakeOpened } `
            -ReadySession { param($actual) [void] $events.Add("ready:$actual") } `
            -LaunchDebugger { param($actual) [void] $events.Add('early-exit'); return 23 } `
            -EndSession {
                param($actual)
                [void] $events.Add("end:$actual")
                return [pscustomobject] @{ status = 'ok'; released = $true }
            })
    } catch {
        $earlyExitReported = $_.Exception.Message.Contains('exited with code 23')
    }
    Assert-SkLauncher $earlyExitReported 'an early debugger exit was not reported'
    Assert-SkLauncher (($events -join '|') -eq 'open|ready:fake-session|early-exit|end:fake-session') `
        'an early debugger exit did not end the managed session'

    $events.Clear()
    $readinessFailureReported = $false
    try {
        [void] (Invoke-SkKdLauncherCore `
            -OpenSession { [void] $events.Add('open'); return $fakeOpened } `
            -ReadySession { param($actual) [void] $events.Add('ready-failed'); throw 'pipe readiness failed' } `
            -LaunchDebugger { throw 'must not launch' } `
            -EndSession {
                param($actual)
                [void] $events.Add("end:$actual")
                return [pscustomobject] @{ status = 'ok'; released = $true }
            })
    } catch {
        $readinessFailureReported = $_.Exception.Message.Contains('pipe readiness failed')
    }
    Assert-SkLauncher $readinessFailureReported 'a pipe-readiness failure was not reported'
    Assert-SkLauncher (($events -join '|') -eq 'open|ready-failed|end:fake-session') `
        'a pipe-readiness failure did not release the managed session before launch'

    $events.Clear()
    $failedOpen = [pscustomobject] @{
        status = 'error'
        error = [pscustomobject] @{
            message = 'scripted post-commit failure'
            session_id = 'recovery-session'
        }
    }
    $openFailureReported = $false
    try {
        [void] (Invoke-SkKdLauncherCore `
            -OpenSession { [void] $events.Add('open'); return $failedOpen } `
            -ReadySession { throw 'must not wait for readiness' } `
            -LaunchDebugger { throw 'must not launch' } `
            -EndSession {
                param($actual)
                [void] $events.Add("end:$actual")
                return [pscustomobject] @{ status = 'ok'; released = $true }
            })
    } catch {
        $openFailureReported = $_.Exception.Message.Contains('scripted post-commit failure')
    }
    Assert-SkLauncher $openFailureReported 'a post-commit open failure was not reported'
    Assert-SkLauncher (($events -join '|') -eq 'open|end:recovery-session') `
        'a failed open carrying a handle was not ended through the fake client'

    $unreleasedReported = $false
    try {
        [void] (Invoke-SkKdLauncherCore `
            -OpenSession { return $fakeOpened } `
            -ReadySession { return } `
            -LaunchDebugger { return 0 } `
            -EndSession { return [pscustomobject] @{ status = 'ok'; released = $false } })
    } catch {
        $unreleasedReported = $_.Exception.Message.Contains('did not prove')
    }
    Assert-SkLauncher $unreleasedReported 'an unproved controller release was reported as cleanup'

    $quoted = Join-SkNativeArguments @('-k', 'a path with spaces', 'ends in slash\')
    Assert-SkLauncher ($quoted.Contains('"a path with spaces"')) 'space-bearing native arguments were not quoted'
    Assert-SkLauncher ($quoted.EndsWith('"ends in slash\\"')) 'a trailing slash was not doubled before its quote'

    foreach ($phase in @('recovery_required', 'live_control_unresolved', 'failed', 'closed', 'released')) {
        Assert-SkLauncher (Test-SkKdTerminalPhase $phase) "terminal phase $phase was not recognized"
    }
    Assert-SkLauncher (-not (Test-SkKdTerminalPhase 'waiting_for_peer')) `
        'the ready phase was classified as terminal'

    $launcherSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'launch_sk_kd.ps1') -Raw
    $packageCandidate = $launcherSource.IndexOf('Get-AppxPackage Microsoft.WinDbg')
    $aliasCandidate = $launcherSource.IndexOf('Get-Command WinDbgX.exe')
    Assert-SkLauncher ($packageCandidate -ge 0 -and $packageCandidate -lt $aliasCandidate) `
        'WinDbgX resolution did not prefer the package executable over its execution alias'

    $stopEvents = New-Object System.Collections.Generic.List[string]
    $fakeStopInput = [pscustomobject] @{ Events = $stopEvents }
    $fakeStopInput | Add-Member -MemberType ScriptMethod -Name Close -Value {
        [void] $this.Events.Add('input:closed')
    }
    $fakeStopProcess = [pscustomobject] @{ Events = $stopEvents }
    $fakeStopProcess | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {
        param([int] $TimeoutMs)
        [void] $this.Events.Add("wait:$TimeoutMs")
        return $true
    }
    $fakeStopProcess | Add-Member -MemberType ScriptMethod -Name Kill -Value {
        [void] $this.Events.Add('kill')
    }
    Stop-SkMcpClient @{ Input = $fakeStopInput; Process = $fakeStopProcess } 4321
    Assert-SkLauncher (($stopEvents -join '|') -eq 'input:closed|wait:4321') `
        'the launcher did not wait its configured cleanup budget for orderly server shutdown'

    $firstRead = New-Object 'System.Threading.Tasks.TaskCompletionSource[string]'
    $secondRead = New-Object 'System.Threading.Tasks.TaskCompletionSource[string]'
    $reads = New-Object 'System.Collections.Generic.Queue[System.Threading.Tasks.Task[string]]'
    $reads.Enqueue($firstRead.Task)
    $reads.Enqueue($secondRead.Task)
    $reader = [pscustomobject] @{ Reads = $reads }
    $reader | Add-Member -MemberType ScriptMethod -Name ReadLineAsync -Value {
        return $this.Reads.Dequeue()
    }
    $written = New-Object System.Collections.Generic.List[string]
    $fakeInput = [pscustomobject] @{ Lines = $written }
    $fakeInput | Add-Member -MemberType ScriptMethod -Name WriteLine -Value {
        param([string] $Line)
        [void] $this.Lines.Add($Line)
    }
    $fakeClient = @{
        Process = [pscustomobject] @{ StandardOutput = $reader }
        Input = $fakeInput
        NextId = 1
        PendingRead = $null
    }
    $requestTimedOut = $false
    try {
        [void] (Send-SkMcpRequest $fakeClient 'session_status' $null 100)
    } catch {
        $requestTimedOut = $_.Exception.Message.Contains('Timed out')
    }
    Assert-SkLauncher $requestTimedOut 'the scripted MCP request did not time out'
    Assert-SkLauncher ($fakeClient.PendingRead.Id -eq $firstRead.Task.Id) `
        'a timed-out MCP request discarded its outstanding stdout read'

    $firstRead.SetResult('{"jsonrpc":"2.0","id":1,"result":{}}')
    $secondRead.SetResult('{"jsonrpc":"2.0","id":2,"result":{"released":true}}')
    $afterTimeout = Send-SkMcpRequest $fakeClient 'tools/call' $null 1000
    Assert-SkLauncher ((Get-SkProperty $afterTimeout 'id') -eq 2) `
        'the request after a timeout did not drain the old response and receive its own'
    Assert-SkLauncher ($null -eq $fakeClient.PendingRead) `
        'the completed MCP request retained a stale stdout read'
    Assert-SkLauncher ($written.Count -eq 2) 'the fake MCP client did not send both requests'

    Write-Output 'Secure Kernel KD launcher tests passed.'
} finally {
    $targetRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target'))
    if (-not $resolvedRoot.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to remove launcher test path outside target: $resolvedRoot"
    }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force -ErrorAction SilentlyContinue
}
