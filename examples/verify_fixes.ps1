param(
    [string]$Exe = "$PSScriptRoot\..\target\release\windbg-mcp.exe"
)
$ErrorActionPreference = "Stop"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Exe
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $false
$utf8 = New-Object System.Text.UTF8Encoding($false)
$psi.StandardOutputEncoding = $utf8
$psi.WorkingDirectory = Split-Path $Exe
$proc = [System.Diagnostics.Process]::Start($psi)
$stdin = New-Object System.IO.StreamWriter($proc.StandardInput.BaseStream, $utf8)
$stdin.AutoFlush = $true
Write-Host "[verify] windbg-mcp pid=$($proc.Id)" -ForegroundColor Cyan

$script:nextId = 1
function Send-Notification([string]$m, $p) {
    $msg = @{ jsonrpc = "2.0"; method = $m }; if ($p) { $msg.params = $p }
    $stdin.WriteLine(($msg | ConvertTo-Json -Depth 20 -Compress))
}
function Send-Request([string]$m, $p, [int]$timeoutMs = 60000) {
    $id = $script:nextId; $script:nextId++
    $msg = @{ jsonrpc = "2.0"; id = $id; method = $m }; if ($p) { $msg.params = $p }
    $stdin.WriteLine(($msg | ConvertTo-Json -Depth 20 -Compress))
    $deadline = [DateTime]::UtcNow.AddMilliseconds($timeoutMs)
    while ($true) {
        $rem = ($deadline - [DateTime]::UtcNow).TotalMilliseconds
        if ($rem -le 0) { throw "timeout id=$id ($m)" }
        $t = $proc.StandardOutput.ReadLineAsync()
        if (-not $t.Wait([int]$rem)) { throw "timeout id=$id ($m)" }
        $line = $t.Result
        if ($null -eq $line) { throw "SERVER CLOSED STDOUT (crash) while waiting id=$id ($m)" }
        if ($line.Trim() -eq "") { continue }
        try { $o = $line | ConvertFrom-Json } catch { continue }
        if (($o.PSObject.Properties.Name -contains 'id') -and $o.id -eq $id) { return $o }
    }
}
function Call([string]$name, $toolArgs, [int]$t = 60000) {
    if (-not $toolArgs) { $toolArgs = @{} }
    $p = @{ name = $name; arguments = $toolArgs }
    return Send-Request "tools/call" $p $t
}
function Report([string]$label, $resp, [string]$expectSubstr) {
    Write-Host "`n--- $label ---" -ForegroundColor Yellow
    $msg = $null
    if ($resp.error) { $msg = $resp.error.message; Write-Host "error.message: $msg" }
    elseif ($resp.result.content) { $msg = ($resp.result.content | Where-Object { $_.type -eq 'text' } | ForEach-Object { $_.text }) -join "`n"; Write-Host "result: $msg" }
    if ($expectSubstr) {
        if ($msg -match [regex]::Escape($expectSubstr)) { Write-Host "PASS: contains '$expectSubstr'" -ForegroundColor Green }
        else { Write-Host "FAIL: expected '$expectSubstr'" -ForegroundColor Red }
    }
}

try {
    Send-Request "initialize" @{ protocolVersion = "2024-11-05"; capabilities = @{}; clientInfo = @{ name = "verify"; version = "0.1" } } 30000 | Out-Null
    Send-Notification "notifications/initialized" $null

    Write-Host "`n========== BUG 2: execution control with no debuggee must not crash ==========" -ForegroundColor Magenta
    Report "go (no target)"         (Call "go" @{})        "No active debuggee"
    Report "step_into (no target)"  (Call "step_into" @{}) "No active debuggee"
    Report "step_over (no target)"  (Call "step_over" @{}) "No active debuggee"
    # Liveness probe: if the process had crashed on the go calls above, this throws "SERVER CLOSED STDOUT".
    Report "modules (server still alive?)" (Call "modules" @{}) $null
    Write-Host "[verify] server survived execution-control-with-no-debuggee calls" -ForegroundColor Green

    Write-Host "`n========== BUG 1: attach failure must be a clean error, not a panic ==========" -ForegroundColor Magenta
    # Occupy UDP 50000 with a background kd so windbg-mcp's AttachKernel fails (port in use).
    $kd  = "C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2603.20001.0_x64__8wekyb3d8bbwe\amd64\kd.exe"
    $key = "<KDNET-KEY>" # replace with your target's KDNET key to exercise this path
    $kdout = "$PSScriptRoot\..\target\kd_hold.out"
    $kp = $null
    if (Test-Path $kd) {
        $kp = Start-Process -FilePath $kd -ArgumentList ('-k net:port=50000,key=' + $key) -RedirectStandardOutput $kdout -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 3  # let kd bind the port
        $bound = Get-NetUDPEndpoint -LocalPort 50000 -ErrorAction SilentlyContinue
        Write-Host "[verify] port 50000 held by kd pid=$($kp.Id): $([bool]$bound)"
    } else { Write-Host "[verify] kd.exe not found; attach will hit no_debuggee path instead" }

    $r = Call "attach_kernel" @{ connection = "net:port=50000,key=$key" } 90000
    Report "attach_kernel (port held / failure path)" $r $null
    $m = if ($r.error) { $r.error.message } else { "" }
    if ($m -match 'panic') { Write-Host "FAIL: still panics ($m)" -ForegroundColor Red }
    elseif ($m -match 'attach|Failed to attach|Not implemented|0x') { Write-Host "PASS: clean error, no panic" -ForegroundColor Green }
    else { Write-Host "NOTE: unexpected: $m" -ForegroundColor Yellow }

    if ($kp -and -not $kp.HasExited) { Stop-Process -Id $kp.Id -Force -ErrorAction SilentlyContinue }

    Write-Host "`n[verify] done" -ForegroundColor Green
}
finally {
    try { $stdin.Close() } catch {}
    Start-Sleep -Milliseconds 400
    try { if (-not $proc.HasExited) { $proc.Kill() } } catch {}
}
