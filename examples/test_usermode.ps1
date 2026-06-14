param([string]$Exe = "$PSScriptRoot\..\target\release\windbg-mcp.exe")
$ErrorActionPreference = "Stop"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Exe; $psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $false
$utf8 = New-Object System.Text.UTF8Encoding($false); $psi.StandardOutputEncoding = $utf8
$psi.WorkingDirectory = Split-Path $Exe
$proc = [System.Diagnostics.Process]::Start($psi)
$stdin = New-Object System.IO.StreamWriter($proc.StandardInput.BaseStream, $utf8); $stdin.AutoFlush = $true
$script:nextId = 1
function Note($m,$p){ $msg=@{jsonrpc="2.0";method=$m}; if($p){$msg.params=$p}; $stdin.WriteLine(($msg|ConvertTo-Json -Depth 20 -Compress)) }
function Req($m,$p,[int]$t=90000){
  $id=$script:nextId; $script:nextId++; $msg=@{jsonrpc="2.0";id=$id;method=$m}; if($p){$msg.params=$p}
  $stdin.WriteLine(($msg|ConvertTo-Json -Depth 20 -Compress))
  $dl=[DateTime]::UtcNow.AddMilliseconds($t)
  while($true){ $rem=($dl-[DateTime]::UtcNow).TotalMilliseconds; if($rem-le 0){throw "timeout $m"}
    $tk=$proc.StandardOutput.ReadLineAsync(); if(-not $tk.Wait([int]$rem)){throw "timeout $m"}
    $ln=$tk.Result; if($null -eq $ln){throw "SERVER CLOSED STDOUT (crash) $m"}; if($ln.Trim()-eq""){continue}
    try{$o=$ln|ConvertFrom-Json}catch{continue}; if(($o.PSObject.Properties.Name -contains 'id') -and $o.id -eq $id){return $o} }
}
function Tool($n,$a,[int]$t=90000){ if(-not $a){$a=@{}}; return Req "tools/call" @{name=$n;arguments=$a} $t }
function Show($label,$r){ Write-Host "`n--- $label ---" -ForegroundColor Yellow
  if($r.error){Write-Host "error: $($r.error.message)" -ForegroundColor Red}
  elseif($r.result.content){ ($r.result.content|?{$_.type -eq 'text'}|%{$_.text}) -join "`n" | Write-Host } }
try{
  Req "initialize" @{protocolVersion="2024-11-05";capabilities=@{};clientInfo=@{name="um";version="0.1"}} 30000 | Out-Null
  Note "notifications/initialized" $null
  Show "launch cmd.exe (breaks at loader bp; result is 'r')" (Tool "launch" @{command_line="cmd.exe"} 90000)
  Show "registers" (Tool "registers" @{} 60000)
  Show "modules (head)" (Tool "modules" @{} 60000)
  Show "set_breakpoint kernel32!CreateFileW" (Tool "set_breakpoint" @{expression="kernel32!CreateFileW"} 60000)
  Show "end_session" (Tool "end_session" @{} 30000)
}finally{ try{$stdin.Close()}catch{}; Start-Sleep -Milliseconds 400; try{if(-not $proc.HasExited){$proc.Kill()}}catch{} }
