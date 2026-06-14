param(
    # Pass your target's real KDNET connection string via -Connection.
    [string]$Connection = "net:port=50000,key=<KDNET-KEY>",
    [string]$Exe = "$PSScriptRoot\..\target\release\windbg-mcp.exe"
)

$ErrorActionPreference = "Stop"

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
        clientInfo      = @{ name = "ps-driver"; version = "0.1" }
    } 30000
    Write-Host "[driver] initialize ok: server=$($init.result.serverInfo.name) v$($init.result.serverInfo.version) proto=$($init.result.protocolVersion)" -ForegroundColor Cyan
    Send-Notification "notifications/initialized" $null

    # ---- 1. Attach to the live kernel (this connects + breaks in) ----
    $r = Call-Tool "attach_kernel" @{ connection = $Connection } 120000
    Show-ToolResult "attach_kernel  (BREAK IN)" $r

    # ---- Confirm we have a live, stopped context ----
    Show-ToolResult "execute: .echo connected" (Call-Tool "execute" @{ command = ".echo === post-attach ===" } 60000)
    Show-ToolResult "registers" (Call-Tool "registers" @{} 60000)
    Show-ToolResult "backtrace (k)" (Call-Tool "backtrace" @{} 60000)
    Show-ToolResult "execute: !running -t (current state)" (Call-Tool "execute" @{ command = "!pcr" } 60000)

    # ---- 2. Set a breakpoint that the running system will hit promptly ----
    Show-ToolResult "set_breakpoint nt!NtCreateFile" (Call-Tool "set_breakpoint" @{ expression = "nt!NtCreateFile" } 60000)
    Show-ToolResult "execute: bl (list breakpoints)" (Call-Tool "execute" @{ command = "bl" } 60000)

    # ---- 3. Resume; should run until the breakpoint is hit ----
    Show-ToolResult "go  (RESUME -> expect breakpoint hit)" (Call-Tool "go" @{} 120000)
    Show-ToolResult "registers @ breakpoint" (Call-Tool "registers" @{} 60000)
    Show-ToolResult "backtrace @ breakpoint" (Call-Tool "backtrace" @{} 60000)

    # ---- Cleanup: clear breakpoints and let the target run, then detach ----
    Show-ToolResult "execute: bc * (clear breakpoints)" (Call-Tool "execute" @{ command = "bc *" } 60000)
    Show-ToolResult "execute: g (set running, no wait)" (Call-Tool "execute" @{ command = "g" } 15000)
    Show-ToolResult "end_session (detach, leave target running)" (Call-Tool "end_session" @{} 30000)

    Write-Host "`n[driver] sequence complete" -ForegroundColor Green
}
finally {
    try { $stdin.Close() } catch {}
    Start-Sleep -Milliseconds 500
    try { if (-not $proc.HasExited) { $proc.Kill() } } catch {}
}
