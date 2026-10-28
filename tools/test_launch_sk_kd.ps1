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

    Write-Output 'Secure Kernel KD launcher tests passed.'
} finally {
    $targetRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target'))
    if (-not $resolvedRoot.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to remove launcher test path outside target: $resolvedRoot"
    }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force -ErrorAction SilentlyContinue
}
