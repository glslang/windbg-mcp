#requires -Version 5.1
<#
Runs an MCP hypervisor test and independently checks the named guest over WinRM.
The profile must already name THAT guest's hypervisor endpoint. This script cannot
prove that mapping; verify its debugger host address and port before running.
No configuration changes, resets, or automatic recovery. Use a disposable VM.

-Session runs the broader test (inspection, one step, breakpoint set and clear, detach)
instead of the detach-only one. -BreakpointHit adds the half that runs to a return
address off the target's own stack and hits a breakpoint there; it implies -Session and
is REFUSED unless the guest reports exactly one logical processor, because on a
four-processor lab that sequence left the guest frozen until a separately authorised
recovery connection released further stops (FOLLOWUPS.md item 93).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Profile,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ComputerName,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [ValidateRange(1,10)][int]$Cycles=3,
    [switch]$ExperimentalBreakOnConnect,
    [switch]$Session,
    [switch]$BreakpointHit
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
        if($BreakpointHit -and $before.LogicalProcessors -ne 1) {
            throw "-BreakpointHit refused: $ExpectedComputerName reports $($before.LogicalProcessors) logical processors. The breakpoint-hit sequence has only been seen to detach cleanly on one vCPU; on four it left the guest frozen (FOLLOWUPS.md item 93). Run without -BreakpointHit, or give the VM one processor."
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
        Write-Host 'PASS: MCP test succeeded; WinRM answered twice and uptime advanced without a reboot.'
    }
} finally {
    $env:WINDBG_MCP_SMOKE_HYPERVISOR_PROFILE=$previousProfile
    $env:WINDBG_MCP_SMOKE_HYPERVISOR_BREAKPOINT_HIT=$previousHit
    $env:WINDBG_MCP_SMOKE_HYPERVISOR_BREAK_ON_CONNECT=$previousBonc
    Pop-Location
}
