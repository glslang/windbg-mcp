<#
.SYNOPSIS
    Proves that a console Ctrl+C leaves an engine worker time to release its target.

.DESCRIPTION
    The supervisor does not terminate its workers when it goes: killing pre-empts the release,
    and a live kernel left attached-but-halted is a machine that needs rebooting. Instead a
    worker treats stdin EOF as "the supervisor is gone" and asks its engine to let go first.

    Ctrl+C is the route where that guarantee is hardest to keep. It is delivered to every process
    attached to the console, and a child inherits its parent's process group -- so without
    CREATE_NEW_PROCESS_GROUP the worker takes the default console handler and dies where it
    stands, before its stdin ever closes. It is also the route where the supervisor can help
    least: its *own* default handler ends it, so it never runs its shutdown.

    This script reproduces exactly that and checks the worker still let go.

    Two things make it work, and both are easy to get backwards:

      1. Ctrl+C cannot be aimed. `GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)` hits everything on
         the console -- which, run from your shell, would include your shell. So the scenario runs
         in a console of its own: this script relaunches itself with Start-Process, and the event
         stays inside that window.

      2. The scenario's own half must survive the Ctrl+C it sends, so it disables Ctrl+C for
         itself -- but *after* starting the server. The "ignore Ctrl+C" attribute is inherited by
         child processes, so doing it first would immunise the server too and the run would prove
         nothing.

    The evidence is the worker's log line, not the worker's death: it dies either way, killed by
    Ctrl+C before the fix and exiting through EOF after it. Only the release path logs
    "supervisor is gone".

.PARAMETER Exe
    The server to test. Defaults to the release build, like the other example drivers.
    Point it at target\debug\windbg-mcp.exe to test a working-tree build.

.EXAMPLE
    .\ctrl_c_teardown.ps1
    .\ctrl_c_teardown.ps1 -Exe ..\target\debug\windbg-mcp.exe

.NOTES
    Known limit: CREATE_NEW_PROCESS_GROUP disables **Ctrl+C** for the worker's group, not
    Ctrl+Break. An interactive Ctrl+Break still reaches every process on the console and would end
    a worker mid-release. Rare enough not to chase, but do not read a pass here as covering it.
#>
param(
    [string]$Exe = "$PSScriptRoot\..\target\release\windbg-mcp.exe",
    [string]$Dump = "$PSScriptRoot\..\docs\samples\052126-34312-01.dmp",
    [int]$TimeoutSeconds = 60,

    # Internal. Marks the half that runs inside the private console; not for direct use.
    [switch]$InConsole,
    [string]$ResultPath
)

$ErrorActionPreference = "Stop"

# ---- outer half: hand the scenario its own console -----------------------------------------

if (-not $InConsole) {
    if (-not (Test-Path $Exe))  { throw "server not found at $Exe (cargo build --release?)" }
    if (-not (Test-Path $Dump)) { throw "sample dump not found at $Dump" }
    $Exe = (Resolve-Path $Exe).Path
    $Dump = (Resolve-Path $Dump).Path

    $result = Join-Path ([System.IO.Path]::GetTempPath()) "ctrl_c_teardown_$PID.txt"
    if (Test-Path $result) { Remove-Item $result -Force }

    Write-Host "[ctrl+c] server : $Exe"
    Write-Host "[ctrl+c] running the scenario in its own console so the event cannot reach this one"

    $powershell = (Get-Process -Id $PID).Path
    $arguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"",
        "-InConsole",
        "-Exe", "`"$Exe`"",
        "-Dump", "`"$Dump`"",
        "-ResultPath", "`"$result`"",
        "-TimeoutSeconds", $TimeoutSeconds
    )
    $inner = Start-Process -FilePath $powershell -ArgumentList $arguments `
        -WindowStyle Hidden -Wait -PassThru

    if (-not (Test-Path $result)) {
        Write-Host "[ctrl+c] INCONCLUSIVE: the scenario left no result file (exit $($inner.ExitCode))" `
            -ForegroundColor Yellow
        exit 2
    }
    $report = Get-Content $result -Raw
    Write-Host $report
    Remove-Item $result -Force

    if ($report -match "(?m)^VERDICT: PASS") {
        Write-Host "[ctrl+c] PASS -- the worker released its target on the way out" -ForegroundColor Green
        exit 0
    }
    if ($report -match "(?m)^VERDICT: ") {
        Write-Host "[ctrl+c] FAIL" -ForegroundColor Red
        exit 1
    }
    # No verdict at all: the scenario died before it could reach one, which for this script is
    # itself a finding -- most likely it failed to make itself immune to the Ctrl+C it sent.
    Write-Host "[ctrl+c] INCONCLUSIVE: the scenario stopped before reporting (see above)" `
        -ForegroundColor Yellow
    exit 2
}

# ---- inner half: runs in the private console ------------------------------------------------

$script:report = New-Object System.Collections.ArrayList
function Note([string]$line) {
    [void]$script:report.Add($line)
    # Written as we go, so a scenario that dies unexpectedly still says how far it got.
    Set-Content -Path $ResultPath -Value ($script:report -join "`r`n") -Encoding utf8
}

Add-Type -Namespace Win32 -Name Console -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent, uint dwProcessGroupId);
"@

$CTRL_C_EVENT = 0
$THIS_CONSOLE = 0

try {
    # ---- start the server, capturing the stderr both processes share ----
    #
    # A worker inherits the supervisor's stderr, so this one pipe carries both. ReadToEndAsync
    # consumes it as it arrives (no buffer stall) and completes only when *every* writer has
    # closed it -- which is to say, when the worker is finally gone.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $psi.StandardOutputEncoding = $utf8
    $psi.StandardErrorEncoding = $utf8
    $psi.EnvironmentVariables["RUST_LOG"] = "info"

    $server = [System.Diagnostics.Process]::Start($psi)
    $stderr = $server.StandardError.ReadToEndAsync()
    $stdin = New-Object System.IO.StreamWriter($server.StandardInput.BaseStream, $utf8)
    $stdin.AutoFlush = $true
    Note "supervisor pid $($server.Id)"

    $script:nextId = 1
    function Send-Request([string]$method, $params, [int]$timeoutMs = 60000) {
        $id = $script:nextId; $script:nextId++
        $message = @{ jsonrpc = "2.0"; id = $id; method = $method }
        if ($params) { $message.params = $params }
        $stdin.WriteLine(($message | ConvertTo-Json -Depth 20 -Compress))
        $deadline = [DateTime]::UtcNow.AddMilliseconds($timeoutMs)
        while ($true) {
            $remaining = ($deadline - [DateTime]::UtcNow).TotalMilliseconds
            if ($remaining -le 0) { throw "timed out waiting for $method" }
            $read = $server.StandardOutput.ReadLineAsync()
            if (-not $read.Wait([int]$remaining)) { throw "timed out waiting for $method" }
            if ($null -eq $read.Result) { throw "the server closed stdout during $method" }
            if ($read.Result.Trim() -eq "") { continue }
            $reply = $read.Result | ConvertFrom-Json
            if ($reply.PSObject.Properties.Name -contains 'id' -and $reply.id -eq $id) { return $reply }
        }
    }
    function Call-Tool([string]$name, $arguments) {
        $reply = Send-Request "tools/call" @{ name = $name; arguments = $arguments }
        if ($reply.error) { throw "$name failed: $($reply.error | ConvertTo-Json -Compress)" }
        return (($reply.result.content | Where-Object { $_.type -eq 'text' }).text -join "`n")
    }

    [void](Send-Request "initialize" @{
            protocolVersion = "2025-06-18"
            capabilities    = @{}
            clientInfo      = @{ name = "ctrl-c-teardown"; version = "1" }
        } 30000)
    $notify = @{ jsonrpc = "2.0"; method = "notifications/initialized" }
    $stdin.WriteLine(($notify | ConvertTo-Json -Depth 5 -Compress))

    # ---- open a session, so there is a worker with something to let go of ----
    [void](Call-Tool "open_dump" @{ path = $Dump })
    $status = Call-Tool "session_status" @{}
    if ($status -notmatch 'engine pid (\d+)') { throw "no engine pid in session_status:`n$status" }
    $workerPid = [int]$Matches[1]
    Note "worker pid $workerPid"
    if (-not (Get-Process -Id $workerPid -ErrorAction SilentlyContinue)) {
        throw "the worker was not running before the test even started"
    }

    # ---- arm, then fire ----
    #
    # Order matters: the server is already started, so it does *not* inherit this. Immunising
    # first would make the server ignore Ctrl+C too, and the run would prove nothing.
    if (-not [Win32.Console]::SetConsoleCtrlHandler([IntPtr]::Zero, $true)) {
        throw "could not make this process immune to Ctrl+C"
    }
    Note "armed: this process now ignores Ctrl+C, the server does not"

    if (-not [Win32.Console]::GenerateConsoleCtrlEvent($CTRL_C_EVENT, $THIS_CONSOLE)) {
        throw "GenerateConsoleCtrlEvent failed: $([ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)"
    }
    Note "sent Ctrl+C to this console"

    # ---- what should follow: the supervisor dies, the worker notices and lets go ----
    $budget = $TimeoutSeconds * 1000
    $supervisorExited = $server.WaitForExit($budget)
    Note "supervisor exited: $supervisorExited"

    # The worker's own pid is the signal to wait on, not the stderr task. A worker that never
    # exits is a *result* this script has to report, and waiting on the transcript first would
    # mean waiting on a pipe that worker is still holding open -- so the regression this exists to
    # catch would hang it instead of failing it.
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ((Get-Process -Id $workerPid -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 100
    }
    $workerGone = -not (Get-Process -Id $workerPid -ErrorAction SilentlyContinue)
    Note "worker gone: $workerGone"

    if (-not $workerGone) {
        # It still holds the write end, so the transcript cannot be read while it lives. The
        # verdict is already recorded, so end it -- the log is worth more than the process.
        Note "worker outlived the budget; ending it so its output can still be read"
        Stop-Process -Id $workerPid -Force -ErrorAction SilentlyContinue
    }

    # Completes when the last holder of that stderr pipe closes it -- the worker. Never touch
    # .Result unless Wait said so: on a task that has not completed, reading it blocks with no
    # timeout at all, which would swallow the verdict this script exists to produce.
    $log = ""
    if ($stderr.Wait(5000)) {
        $log = $stderr.Result
        if ($null -eq $log) { $log = "" }
    }
    else {
        Note "stderr never closed, so no transcript is available to read"
    }

    # The discriminator. A worker killed by the Ctrl+C never reaches this line; one that met EOF
    # logs it before asking its engine to detach.
    $released = $log -match 'supervisor is gone'
    Note "worker logged the release: $released"
    foreach ($line in ($log -split "`r?`n" | Where-Object { $_ -match 'worker|shutting down' })) {
        Note "  | $line"
    }

    # Named individually, because the three failures want different reactions and a single
    # catch-all message sends you looking at the wrong one.
    $reasons = New-Object System.Collections.ArrayList
    if (-not $supervisorExited) {
        [void]$reasons.Add("the supervisor survived the Ctrl+C, so nothing was actually tested")
    }
    if (-not $released) {
        [void]$reasons.Add("the worker never logged the release, so it was killed before it could detach")
    }
    if (-not $workerGone) {
        [void]$reasons.Add("the worker outlived its budget rather than exiting on EOF")
    }
    if ($reasons.Count -eq 0) {
        Note "VERDICT: PASS"
    }
    else {
        Note "VERDICT: FAIL -- $($reasons -join '; ')"
    }
}
catch {
    Note "VERDICT: FAIL -- $($_.Exception.Message)"
}
finally {
    if ($server -and -not $server.HasExited) { $server.Kill() }
    if ($workerPid) {
        $stray = Get-Process -Id $workerPid -ErrorAction SilentlyContinue
        if ($stray) { $stray.Kill() }
    }
}
