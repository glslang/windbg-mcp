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
    [ValidateRange(1,65535)][int]$ProbePort=5985,
    # What counts as "the target was halted": consecutive refused knocks, and how long they must
    # span. One is a network blip on any network worth testing over; two in a row is a machine
    # that stopped.
    #
    # **This is an instrument, and it has a resolution.** A knock costs its own timeout when it
    # goes unanswered, so a halt shorter than about twice that cannot be seen however the bar is
    # set -- and a *warm* detach-only run holds the target for only a few hundred milliseconds,
    # which is under it. That is reported rather than papered over: the run fails saying the test
    # does not hold the target long enough to be seen, and the fix is to run one that does
    # (`-TestName a_live_kernel_pool_walk_is_bounded_and_leaves_its_session_usable` walks every
    # committed pool page over the wire, with the target halted throughout).
    [ValidateRange(1,100)][int]$MinSilentSamples=2,
    [ValidateRange(0.0,600.0)][double]$MinSilentSeconds=0.5,
    # Resolve the profile and read the guest's health, then stop -- without attaching to
    # anything. For checking the wiring before committing to a halt, which is the moment the
    # mistakes this script guards against are cheapest to find.
    [switch]$PreflightOnly
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

# How far the guest's reported boot time may move between two readings and still be the same boot.
#
# It is not a constant of the guest: `LastBootUpTime` is derived, and a clock synchronisation moves
# it. Measured on the hypervisor lab, 333 microseconds of drift across ten hours with no reboot --
# which an equality test reads as "the guest rebooted" and reports against a detach that worked.
# Two seconds is chosen because no reboot can fit inside it: a guest that has restarted cannot
# answer WinRM for tens of seconds afterwards, and its new boot time is a whole uptime away from
# the old one.
$script:BootDriftTicks=20000000
function Test-SameBoot([long]$first,[long]$second){
    return ([math]::Abs($first-$second) -le $script:BootDriftTicks)
}

# Resolved here rather than taken as a parameter: the string holds the debug key, and anything on
# a command line is readable by every process on this machine.
#
# **`-Profile` wins, and a leftover `WINDBG_MCP_SMOKE_KERNEL` that disagrees with it stops the
# run.** Taking the variable first looks harmless -- it is what the tier's own documentation tells
# you to set -- and it is the one mistake this script must not make: the health checks and the
# frozen-window probe are aimed at `-ComputerName`, so a stale variable would halt one machine
# while this script certified another. Neither value is printed on the mismatch; which of the two
# is wrong is the operator's to work out from where they came from.
function Normalize-ProfileName([string]$name) {
    return ($name.ToLowerInvariant() -replace '[^a-z0-9]','_')
}

function Resolve-Connection {
    $wanted=Normalize-ProfileName $Profile
    # **The environment first, because that is what the server does.** `Profiles::from_host`
    # admits `WINDBG_MCP_PROFILE_<NAME>` entries before the file's and keeps the one already
    # there, so an operator who defined a profile that way is naming the environment's target --
    # and a resolver that read only the file would halt whatever the file's stale entry of the
    # same name points at, while the WinRM checks below watched the one they meant. The prefix
    # matches case-insensitively, as Windows variable names do; `WINDBG_MCP_PROFILES` names the
    # file and is not a profile, which the trailing underscore already excludes.
    foreach($variable in Get-ChildItem Env:){
        if($variable.Name.Length -le 19){continue}
        if(-not $variable.Name.Substring(0,19).Equals('WINDBG_MCP_PROFILE_',[StringComparison]::OrdinalIgnoreCase)){continue}
        $suffix=$variable.Name.Substring(19)
        if([string]::IsNullOrWhiteSpace($suffix) -or [string]::IsNullOrWhiteSpace($variable.Value)){continue}
        if((Normalize-ProfileName $suffix) -eq $wanted){
            Write-Host "Profile '$Profile' resolved from the environment ($($variable.Name))"
            $fromEnv=$variable.Value.Trim()
            if(-not [string]::IsNullOrWhiteSpace($env:WINDBG_MCP_SMOKE_KERNEL) -and
               $env:WINDBG_MCP_SMOKE_KERNEL -ne $fromEnv) {
                throw "WINDBG_MCP_SMOKE_KERNEL is set and does not match profile '$Profile'. One of them names a different target from the one this script is checking over WinRM, and attaching would halt that one instead. Clear the variable or correct the profile; neither value is printed here because both carry the debug key."
            }
            return $fromEnv
        }
    }
    $path=Join-Path $env:USERPROFILE '.windbg-mcp\profiles.json'
    if($env:WINDBG_MCP_PROFILES){$path=$env:WINDBG_MCP_PROFILES}
    if(-not (Test-Path -LiteralPath $path)){throw "No profile file at $path and no WINDBG_MCP_PROFILE_ variable, so '$Profile' cannot be resolved"}
    $profiles=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    # **The server's rule, character for character**: lowercase, and every non-alphanumeric
    # character becomes `_` (`kdconn::normalize`). Separators are *translated*, not deleted --
    # `lab-vm` and `lab_vm` are the same profile and `labvm` is a different one. Deleting them
    # instead collapses that third name onto the first two, and the collapse is not a naming
    # nicety here: picking the wrong entry attaches to one kernel while everything below checks
    # the health of another.
    $matched=@($profiles.PSObject.Properties | Where-Object { (Normalize-ProfileName $_.Name) -eq $wanted })
    if($matched.Count -gt 1){
        # Refused rather than resolved, like every other ambiguity in this script: two file keys
        # that normalize alike are two targets, and nothing here can tell which was meant.
        throw ("Profile '$Profile' matches more than one entry in {0}: {1}. They normalize to the same name, so which kernel this would halt is ambiguous; rename one." -f $path, (($matched | ForEach-Object { $_.Name }) -join ', '))
    }
    if($matched.Count -eq 0){throw "Profile '$Profile' is not in $path"}
    Write-Host "Profile '$Profile' resolved from entry '$($matched[0].Name)' in the profile file"
    $resolved=$matched[0].Value
    if(-not [string]::IsNullOrWhiteSpace($env:WINDBG_MCP_SMOKE_KERNEL) -and
       $env:WINDBG_MCP_SMOKE_KERNEL -ne $resolved) {
        throw "WINDBG_MCP_SMOKE_KERNEL is set and does not match profile '$Profile'. One of them names a different target from the one this script is checking over WinRM, and attaching would halt that one instead. Clear the variable or correct the profile; neither value is printed here because both carry the debug key."
    }
    return $resolved
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
param($Target,$Port,$Seconds,$Interval,$Timeout,$Path)
$deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
while([DateTime]::UtcNow -lt $deadline){
    $client=New-Object Net.Sockets.TcpClient
    $answered=$false
    try{
        $async=$client.BeginConnect($Target,$Port,$null,$null)
        $answered=$async.AsyncWaitHandle.WaitOne($Timeout) -and $client.Connected
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
        if($PreflightOnly){
            Write-Host 'PREFLIGHT ONLY: the profile resolved and the guest answered; nothing was attached.'
            continue
        }
        # Started before the test and given a generous window: it is stopped as soon as the test
        # returns, so a long budget costs nothing and a short one would end mid-attach. The
        # interval is short because the window it has to land inside is short -- a detach-only
        # test holds the target for a couple of seconds.
        $probeLog=Join-Path ([IO.Path]::GetTempPath()) ("windbg-mcp-frozen-probe-{0}.csv" -f [Guid]::NewGuid())
        $probe=Start-Job -ScriptBlock $probeBlock -ArgumentList $ComputerName,$ProbePort,600,50,500,$probeLog
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
                if(-not (Test-SameBoot $before.BootTicks $after.BootTicks) -or
                   -not (Test-SameBoot $after.BootTicks $later.BootTicks)) {
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
        # **The longest *consecutive* run, not the count.** One refused connection is a network
        # blip on any network worth testing over, and taking `silent.Count > 0` as proof of a halt
        # would let a blip certify an experiment whose whole claim is that the target stopped. A
        # halt is a run of them -- the 32-second one measured here was 26 consecutive -- so what
        # has to clear the bar is a sustained window.
        $longest=@()
        $current=@()
        foreach($sample in $samples) {
            if($sample.Answered) {
                if($current.Count -gt $longest.Count){$longest=$current}
                $current=@()
            } else {
                $current+=$sample
            }
        }
        if($current.Count -gt $longest.Count){$longest=$current}
        $span=0.0
        if($longest.Count -gt 1) {
            $span=($longest[-1].At - $longest[0].At).TotalSeconds
        }
        Write-Host ("Probe: {0} samples, {1} answered, {2} silent; longest silent run {3} samples over {4:N1}s" -f $samples.Count, $answered.Count, $silent.Count, $longest.Count, $span)
        if($samples.Count -eq 0) {
            throw 'The frozen-window probe collected nothing, so this run cannot say the target was ever halted. The health check above is not evidence on its own.'
        }
        if($longest.Count -lt $MinSilentSamples -or $span -lt $MinSilentSeconds) {
            # The postcondition is vacuous without this: a guest that was never halted is up before
            # and after whatever the debugger did, including nothing at all.
            throw "The guest was never silent for a sustained window ($($longest.Count) consecutive samples over $([math]::Round($span,1))s, wanted $MinSilentSamples over $MinSilentSeconds s), so this run says nothing about detaching from a halted kernel. Check that the attach landed, or that the test holds the target long enough to be seen."
        }
        Write-Host ("PASS: halted from {0:HH:mm:ss} to {1:HH:mm:ss} UTC ({2:N1}s unreachable), then released; WinRM answered twice and uptime advanced without a reboot." -f $longest[0].At, $longest[-1].At, $span)
    }
} finally {
    $env:WINDBG_MCP_SMOKE_KERNEL=$previousKernel
    Pop-Location
}
