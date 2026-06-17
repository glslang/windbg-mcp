param(
    # Pass your target's real KDNET connection string via -Connection.
    [string]$Connection = "net:port=50000,key=<KDNET-KEY>",
    # Driver object name for !drvobj, e.g. "mydriver" or "\Driver\mydriver".
    [string]$Driver = "mydriver",
    # Rebased VA of the IRP_MJ_DEVICE_CONTROL dispatch routine (MajorFunction[0x0e],
    # from the driver_object output). Leave empty on a first pass to just inspect the
    # dispatch table, then re-run with -Dispatch to install the logging sweep.
    [string]$Dispatch = "",
    # Number of consecutive collection windows. The server caps each `go` at
    # EXEC_WAIT_MS (~60s) regardless of the client timeout, so to keep logging while the
    # target-side sender runs we issue several back-to-back `go`s rather than one long one.
    [int]$Sweeps = 2,
    [string]$Exe = "$PSScriptRoot\..\target\release\windbg-mcp.exe"
)

$ErrorActionPreference = "Stop"

# ----------------------------------------------------------------------------
# This is the HOST side. The debugger attaches over KDNET and installs the
# logging breakpoint. The user-mode sender that actually issues the IOCTLs runs
# on the TARGET VM (it cannot cross the KDNET boundary from here) -- run the
# companion script send_ioctls_target.ps1 on the target during the `go` window,
# once as a normal user and once elevated. Reachability is answered per token:
# a code rejected by the I/O manager's RequiredAccess check never reaches the bp.
# ----------------------------------------------------------------------------

# Start the MCP server with stdin/stdout redirected (UTF-8, no BOM).
# stderr is left inheriting the console so logs are visible and no buffer deadlock occurs.
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Exe
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $false
$utf8 = New-Object System.Text.UTF8Encoding($false)
# .NET Framework (PS 5.1) has StandardOutputEncoding but not StandardInputEncoding.
$psi.StandardOutputEncoding = $utf8
$psi.WorkingDirectory = Split-Path $Exe

$proc = [System.Diagnostics.Process]::Start($psi)
# Wrap stdin with a UTF-8 (no BOM) writer so we control the encoding ourselves.
$stdin = New-Object System.IO.StreamWriter($proc.StandardInput.BaseStream, $utf8)
$stdin.AutoFlush = $true
Write-Host "[driver] started windbg-mcp pid=$($proc.Id)" -ForegroundColor Cyan

$script:nextId = 1

function Send-Notification([string]$method, $params) {
    $msg = @{ jsonrpc = "2.0"; method = $method }
    if ($params) { $msg.params = $params }
    $json = $msg | ConvertTo-Json -Depth 20 -Compress
    $stdin.WriteLine($json)
}

function Send-Request([string]$method, $params, [int]$timeoutMs = 120000) {
    $id = $script:nextId; $script:nextId++
    $msg = @{ jsonrpc = "2.0"; id = $id; method = $method }
    if ($params) { $msg.params = $params }
    $json = $msg | ConvertTo-Json -Depth 20 -Compress
    $stdin.WriteLine($json)

    $deadline = [DateTime]::UtcNow.AddMilliseconds($timeoutMs)
    while ($true) {
        $remaining = ($deadline - [DateTime]::UtcNow).TotalMilliseconds
        if ($remaining -le 0) { throw "timeout waiting for response id=$id ($method)" }
        $task = $proc.StandardOutput.ReadLineAsync()
        if (-not $task.Wait([int]$remaining)) { throw "timeout waiting for response id=$id ($method)" }
        $line = $task.Result
        if ($null -eq $line) { throw "server closed stdout while waiting for id=$id ($method)" }
        if ($line.Trim() -eq "") { continue }
        try { $obj = $line | ConvertFrom-Json } catch { Write-Host "[driver] non-JSON stdout: $line"; continue }
        if ($obj.PSObject.Properties.Name -contains 'id' -and $obj.id -eq $id) { return $obj }
        # ignore notifications / mismatched ids
    }
}

function Show-ToolResult([string]$label, $resp) {
    Write-Host "`n========== $label ==========" -ForegroundColor Yellow
    if ($resp.error) {
        Write-Host "ERROR: $($resp.error | ConvertTo-Json -Depth 20 -Compress)" -ForegroundColor Red
        return
    }
    $r = $resp.result
    if ($null -ne $r.isError -and $r.isError) { Write-Host "[isError=true]" -ForegroundColor Red }
    if ($r.content) {
        foreach ($c in $r.content) { if ($c.type -eq 'text') { Write-Host $c.text } }
    } else {
        Write-Host ($r | ConvertTo-Json -Depth 20 -Compress)
    }
}

function Call-Tool([string]$name, $arguments, [int]$timeoutMs = 120000) {
    $params = @{ name = $name }
    if ($arguments) { $params.arguments = $arguments } else { $params.arguments = @{} }
    return Send-Request "tools/call" $params $timeoutMs
}

try {
    # ---- MCP handshake ----
    $init = Send-Request "initialize" @{
        protocolVersion = "2024-11-05"
        capabilities    = @{}
        clientInfo      = @{ name = "ioctl-sweep"; version = "0.1" }
    } 30000
    Write-Host "[driver] initialize ok: server=$($init.result.serverInfo.name) v$($init.result.serverInfo.version)" -ForegroundColor Cyan
    Send-Notification "notifications/initialized" $null

    # ---- Attach to the live kernel (connects + breaks in) ----
    Show-ToolResult "attach_kernel  (BREAK IN)" (Call-Tool "attach_kernel" @{ connection = $Connection } 120000)

    # ---- Static: dispatch table + load base (for rebasing the dispatch VA) ----
    Show-ToolResult "driver_object (MajorFunction index 0x0e = IOCTL dispatch)" (Call-Tool "driver_object" @{ name = $Driver } 60000)
    Show-ToolResult "modules (lm) -- rebase the static RVA to the live base" (Call-Tool "modules" @{} 60000)

    if ([string]::IsNullOrWhiteSpace($Dispatch)) {
        Write-Host "`n[driver] No -Dispatch given. Note MajorFunction[0x0e] above, rebase it to" -ForegroundColor Cyan
        Write-Host "[driver] the live load base, then re-run with -Dispatch to install the sweep." -ForegroundColor Cyan
        Show-ToolResult "end_session (resume + detach)" (Call-Tool "end_session" @{} 30000)
        return
    }

    # ---- Dynamic: install the logging-bp sweep, then run the target sender ----
    Show-ToolResult "ioctl_trace (logging bp + gc)" (Call-Tool "ioctl_trace" @{ dispatch = $Dispatch } 60000)
    Show-ToolResult "execute: bl (confirm breakpoint)" (Call-Tool "execute" @{ command = "bl" } 60000)

    Write-Host "`n[driver] >>> Now run send_ioctls_target.ps1 on the TARGET VM (normal user, then" -ForegroundColor Green
    Write-Host "[driver] >>> elevated). The logging bp prints each delivered IOCTL into 'go' below." -ForegroundColor Green

    # Each `go` runs while the bp logs-and-continues (gc) and is force-broken at the
    # server's ~60s cap, returning that window's accumulated IOCTL log. The client timeout
    # (90s) stays above the server cap so we wait for its return, not time out first. Loop
    # so the operator's sender (normal user, then elevated) can span more than one window.
    for ($i = 1; $i -le $Sweeps; $i++) {
        Show-ToolResult "go (collection window $i/$Sweeps, server-capped ~60s)" (Call-Tool "go" @{} 90000)
    }

    # ---- Cleanup ----
    Show-ToolResult "execute: bc * (clear breakpoints)" (Call-Tool "execute" @{ command = "bc *" } 60000)
    Show-ToolResult "end_session (resume + detach, leaves target running)" (Call-Tool "end_session" @{} 30000)

    Write-Host "`n[driver] sweep complete" -ForegroundColor Green
}
finally {
    try { $stdin.Close() } catch {}
    Start-Sleep -Milliseconds 500
    try { if (-not $proc.HasExited) { $proc.Kill() } } catch {}
}
