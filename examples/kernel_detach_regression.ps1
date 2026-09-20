#requires -Version 5.1
<#
Runs a live-kernel MCP test and independently checks that the target is still EXECUTING
afterwards, which the debugger's own report cannot establish.

Why this exists. `end_session` on a live kernel answers `released: true` and
`target_left_running: true` from the debugger's side of the wire. On 2026-09-20 a hypervisor
target answered exactly that while the guest was frozen, and only an independent check over
WinRM found it (see examples/hypervisor_detach_regression.ps1 and FOLLOWUPS.md item 93). The
teardown underneath is shared: dbgscope's `end_session` branches on `is_live_kernel()`, not on
which kernel, so ordinary NT takes the same `clear_all_breakpoints` + `qd` path the hypervisor
does. That path is not validated on NT (dbgscope #173), and this script is how it gets measured.

The positive control matters as much as the postcondition. A KDNET break-in halts the whole
machine, so the guest must become UNREACHABLE while the test holds it. Without that check a run
where the attach never landed passes trivially: the guest was up before, up after, and never
debugged. The probe below records that window and the run fails if it never closed.

No configuration changes, resets, or automatic recovery. Use a disposable VM.
#>
[CmdletBinding()]
param(
    # Kernel profile name as %USERPROFILE%\.windbg-mcp\profiles.json holds it. The connection
    # string it resolves to carries the target's debug key, so it is read here and passed to the
    # test through the environment -- never as an argument, which every process on the box can read.
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Profile,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ComputerName,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateRange(1,10)][int]$Cycles=1,
    [string]$TestName='a_live_kernel_session_attaches_coexists_and_detaches_cleanly',
    # The guest's WinRM port, which is what the frozen-window probe knocks on.
    [ValidateRange(1,65535)][int]$ProbePort=5985
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$sessionOptions=New-PSSessionOption -OpenTimeout 5000 -OperationTimeout 15000
function Read-GuestHealth {
    $arguments=@{ComputerName=$ComputerName;SessionOption=$sessionOptions}
    if($null -ne $Credential){$arguments['Credential']=$Credential}
    else{$arguments['Authentication']='Negotiate'}
    $health=Invoke-Command @arguments -ScriptBlock {
        $os=Get-CimInstance Win32_OperatingSystem
        $cs=Get-CimInstance Win32_ComputerSystem
        [pscustomobject]@{
            Name=$env:COMPUTERNAME
            BootTicks=$os.LastBootUpTime.ToUniversalTime().Ticks
            UptimeSeconds=((Get-Date)-$os.LastBootUpTime).TotalSeconds
            LogicalProcessors=[int]$cs.NumberOfLogicalProcessors
        }
    }
    if($health.Name -ne $ExpectedComputerName){throw 'Guest identity mismatch; do not attach'}
    return $health
}

# Resolved here rather than taken as a parameter: the string holds the debug key, and anything on
# a command line is readable by every process on this machine.
function Resolve-Connection {
    if(-not [string]::IsNullOrWhiteSpace($env:WINDBG_MCP_SMOKE_KERNEL)){return $env:WINDBG_MCP_SMOKE_KERNEL}
    $path=Join-Path $env:USERPROFILE '.windbg-mcp\profiles.json'
    if($env:WINDBG_MCP_PROFILES){$path=$env:WINDBG_MCP_PROFILES}
    if(-not (Test-Path -LiteralPath $path)){throw "No WINDBG_MCP_SMOKE_KERNEL set and no profile file at $path"}
    $profiles=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    # Names match the server's own rule: case-insensitive, with - _ . equivalent.
    $wanted=$Profile.ToLowerInvariant() -replace '[-_.]',''
    foreach($named in $profiles.PSObject.Properties){
        if(($named.Name.ToLowerInvariant() -replace '[-_.]','') -eq $wanted){return $named.Value}
    }
    throw "Profile '$Profile' is not in $path"
}

# One TCP knock with its own short clock. Deliberately not Test-NetConnection: that takes seconds
# to give up, and this has to resolve inside the poll interval to place the frozen window.
#
# **Each sample is written to a file as it is taken**, rather than returned when the loop ends.
# The loop is always ended early -- the test finishes and the probe is stopped -- and a job's
# output is what the job has *emitted*, so collecting into a list and returning it at the end
# collects nothing at all. That is not hypothetical: it is what the first run of this script did,
# and the guard below correctly refused to call the result a pass.
$probeSource=@'
param($Target,$Port,$Seconds,$Interval,$Path)
$deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
while([DateTime]::UtcNow -lt $deadline){
    $client=New-Object Net.Sockets.TcpClient
    $answered=$false
    try{
        $async=$client.BeginConnect($Target,$Port,$null,$null)
        $answered=$async.AsyncWaitHandle.WaitOne(1000) -and $client.Connected
    }catch{
        $answered=$false
    }finally{
        $client.Close()
    }
    Add-Content -LiteralPath $Path -Encoding Ascii -Value ('{0:o},{1}' -f [DateTime]::UtcNow,$answered)
    Start-Sleep -Milliseconds $Interval
}
'@
$probeBlock=[ScriptBlock]::Create($probeSource)

$previousKernel=$env:WINDBG_MCP_SMOKE_KERNEL
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $env:WINDBG_MCP_SMOKE_KERNEL=Resolve-Connection
    for($cycle=1;$cycle -le $Cycles;$cycle++) {
        $before=Read-GuestHealth
        Write-Host "Cycle $cycle of $Cycles; profile=$Profile; guest=$ExpectedComputerName; processors=$($before.LogicalProcessors); test=$TestName"
        # Started before the test and given a generous window: it is stopped as soon as the test
        # returns, so a long budget costs nothing and a short one would end mid-attach. The
        # interval is short because the window it has to land inside is short -- a detach-only
        # test holds the target for a couple of seconds.
        $probeLog=Join-Path ([IO.Path]::GetTempPath()) ("windbg-mcp-frozen-probe-{0}.csv" -f [Guid]::NewGuid())
        $probe=Start-Job -ScriptBlock $probeBlock -ArgumentList $ComputerName,$ProbePort,600,250,$probeLog
        $testExit=1
        $samples=@()
        try {
            & cargo test --locked --test mcp_smoke $TestName -- --ignored --exact --nocapture --test-threads=1
            $testExit=$LASTEXITCODE
        } finally {
            try {
                Stop-Job -Job $probe -ErrorAction SilentlyContinue
                if(Test-Path -LiteralPath $probeLog){
                    $samples=@(Get-Content -LiteralPath $probeLog | ForEach-Object {
                        $fields=$_.Split(',')
                        [pscustomobject]@{At=[DateTime]::Parse($fields[0]);Answered=[bool]::Parse($fields[1])}
                    })
                    Remove-Item -LiteralPath $probeLog -Force -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Warning "The frozen-window probe could not be read: $($_.Exception.Message)"
            }
            Remove-Job -Job $probe -Force -ErrorAction SilentlyContinue
            # Health is read whatever the test did. No second controller and no reset on failure.
            try {
                $after=Read-GuestHealth
                Start-Sleep -Seconds 2
                $later=Read-GuestHealth
                if($before.BootTicks -ne $after.BootTicks -or $after.BootTicks -ne $later.BootTicks) {
                    throw 'The guest rebooted; this is not a successful detach'
                }
                if($later.UptimeSeconds -le $after.UptimeSeconds) {
                    throw 'Guest uptime did not advance after detach'
                }
            } catch {
                throw "Guest health is unconfirmed after the test: $($_.Exception.Message). Inspect the console; do not reset or start another debugger blindly."
            }
        }
        if($testExit -ne 0){throw "MCP regression failed (exit $testExit), although the guest answered WinRM"}

        $answered=@($samples | Where-Object { $_.Answered })
        $silent=@($samples | Where-Object { -not $_.Answered })
        Write-Host "Probe: $($samples.Count) samples, $($answered.Count) answered, $($silent.Count) silent"
        if($samples.Count -eq 0) {
            throw 'The frozen-window probe collected nothing, so this run cannot say the target was ever halted. The health check above is not evidence on its own.'
        }
        if($silent.Count -eq 0) {
            # The postcondition is vacuous without this: a guest that was never halted is up before
            # and after whatever the debugger did, including nothing at all.
            throw "The guest answered on every probe, so it was never halted and this run says nothing about detaching from a halted kernel. Check that the attach landed."
        }
        $window=($silent | Measure-Object -Property At -Minimum -Maximum)
        Write-Host ("PASS: halted from {0:HH:mm:ss} to {1:HH:mm:ss} UTC, then released; WinRM answered twice and uptime advanced without a reboot." -f $window.Minimum, $window.Maximum)
    }
} finally {
    $env:WINDBG_MCP_SMOKE_KERNEL=$previousKernel
    Pop-Location
}
