#requires -Version 5.1
<#
Runs an MCP hypervisor test and independently checks the named guest over WinRM.
The profile must already name THAT guest's hypervisor endpoint. This script cannot
prove that mapping; verify its debugger host address and port before running.
No configuration changes, resets, or automatic recovery. Use a disposable VM.

-Session runs the broader test (inspection, one step, breakpoint set and clear, detach)
instead of the detach-only one. -BreakpointHit adds the half that runs to a return
address off the target's own stack and hits a breakpoint there; it implies -Session.

That breakpoint sits in code every processor runs, so on a guest with N processors the
hit leaves N-1 queued break exceptions behind it - measured, one per other processor -
and a teardown that does not spend them hands the target's one continue to the first:
the four-processor lab froze that way in 2 of 4 runs (FOLLOWUPS.md item 93). So
-BreakpointHit is REFUSED on a multiprocessor guest unless -AllowMultiprocessor is
passed, which is the operator saying they know that and have a recovery route. The
route, if it does freeze: attach_kernel with the plain shape (no break-on-connect),
which finds the target stopped at the breakpoint's own address, then end_session.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Profile,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ComputerName,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [ValidateRange(1,10)][int]$Cycles=3,
    [switch]$ExperimentalBreakOnConnect,
    [switch]$Session,
    [switch]$BreakpointHit,
    [switch]$AllowMultiprocessor
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$sessionOptions=New-PSSessionOption -OpenTimeout 5000 -OperationTimeout 10000
function Read-GuestHealth {
    $health=Invoke-Command -ComputerName $ComputerName -Authentication Negotiate -SessionOption $sessionOptions -ScriptBlock {
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
# it. Measured on this lab, 333 microseconds of drift across ten hours with no reboot -- which an
# equality test reads as "the guest rebooted" and reports against a detach that worked. Two seconds
# is chosen because no reboot can fit inside it: a guest that has restarted cannot answer WinRM for
# tens of seconds afterwards, and its new boot time is a whole uptime away from the old one. So the
# tolerance separates the two cases completely rather than trading one error for the other.
$script:BootDriftTicks=20000000
function Test-SameBoot([long]$first,[long]$second){
    return ([math]::Abs($first-$second) -le $script:BootDriftTicks)
}
# -BreakpointHit is the wider test plus its own opt-in, so asking for it asks for -Session too.
if($BreakpointHit){$Session=$true}
$previousProfile=$env:WINDBG_MCP_SMOKE_HYPERVISOR_PROFILE
$previousHit=$env:WINDBG_MCP_SMOKE_HYPERVISOR_BREAKPOINT_HIT
$previousBonc=$env:WINDBG_MCP_SMOKE_HYPERVISOR_BREAK_ON_CONNECT
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $env:WINDBG_MCP_SMOKE_HYPERVISOR_PROFILE=$Profile
    # Set for the -Session test, which takes whichever attach shape it is told. The two
    # detach-only tests carry their own shape and ignore this.
    if($ExperimentalBreakOnConnect){$env:WINDBG_MCP_SMOKE_HYPERVISOR_BREAK_ON_CONNECT='1'}
    else{$env:WINDBG_MCP_SMOKE_HYPERVISOR_BREAK_ON_CONNECT=$null}
    if($BreakpointHit){$env:WINDBG_MCP_SMOKE_HYPERVISOR_BREAKPOINT_HIT='1'}
    else{$env:WINDBG_MCP_SMOKE_HYPERVISOR_BREAKPOINT_HIT=$null}
    for($cycle=1;$cycle -le $Cycles;$cycle++) {
        $before=Read-GuestHealth
        # Checked before every cycle and not once at the start: the guest is somebody else's
        # disposable VM and its processor count is changed by restarting it, which is exactly
        # what happened between the two 2026-09-20 demonstrations.
        if($BreakpointHit -and $before.LogicalProcessors -ne 1 -and -not $AllowMultiprocessor) {
            throw "-BreakpointHit refused: $ExpectedComputerName reports $($before.LogicalProcessors) logical processors, so the hit leaves $($before.LogicalProcessors - 1) queued break exceptions behind it, one per other processor. On 2026-09-20 that left a four-processor lab frozen after a reported detach (FOLLOWUPS.md item 93). Pass -AllowMultiprocessor to run it anyway on a guest you can recover, run without -BreakpointHit, or give the VM one processor."
        }
        Write-Host "Cycle $cycle of $Cycles; profile=$Profile; guest=$ExpectedComputerName; processors=$($before.LogicalProcessors)"
        $testExit=1
        try {
            if($Session){$testName='a_live_hypervisor_session_inspects_steps_and_detaches'}
            elseif($ExperimentalBreakOnConnect){$testName='a_live_hypervisor_announcement_attach_detaches_at_the_first_stop'}
            else{$testName='a_live_hypervisor_detaches_at_the_initial_break'}
            & cargo test --locked --test mcp_smoke $testName -- --ignored --exact --nocapture --test-threads=1
            $testExit=$LASTEXITCODE
        } finally {
            # Check health even if cargo/test failed. No second controller or reset on failure.
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
        Write-Host 'PASS: MCP test succeeded; WinRM answered twice and uptime advanced without a reboot.'
    }
} finally {
    $env:WINDBG_MCP_SMOKE_HYPERVISOR_PROFILE=$previousProfile
    $env:WINDBG_MCP_SMOKE_HYPERVISOR_BREAKPOINT_HIT=$previousHit
    $env:WINDBG_MCP_SMOKE_HYPERVISOR_BREAK_ON_CONNECT=$previousBonc
    Pop-Location
}
