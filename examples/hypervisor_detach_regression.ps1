#requires -Version 5.1
<#
Runs the detach-only MCP test and independently checks the named guest over WinRM.
The profile must already name THAT guest's hypervisor endpoint. This script cannot
prove that mapping; verify its debugger host address and port before running.
No configuration changes, resets, or automatic recovery. Use a disposable VM.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Profile,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ComputerName,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [ValidateRange(1,10)][int]$Cycles=3
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$sessionOptions=New-PSSessionOption -OpenTimeout 5000 -OperationTimeout 10000
function Read-GuestHealth {
    $health=Invoke-Command -ComputerName $ComputerName -Authentication Negotiate -SessionOption $sessionOptions -ScriptBlock {
        $os=Get-CimInstance Win32_OperatingSystem
        [pscustomobject]@{
            Name=$env:COMPUTERNAME
            BootTicks=$os.LastBootUpTime.ToUniversalTime().Ticks
            UptimeSeconds=((Get-Date)-$os.LastBootUpTime).TotalSeconds
        }
    }
    if($health.Name -ne $ExpectedComputerName){throw 'Guest identity mismatch; do not attach'}
    return $health
}
$previousProfile=$env:WINDBG_MCP_SMOKE_HYPERVISOR_PROFILE
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $env:WINDBG_MCP_SMOKE_HYPERVISOR_PROFILE=$Profile
    for($cycle=1;$cycle -le $Cycles;$cycle++) {
        $before=Read-GuestHealth
        Write-Host "Cycle $cycle of $Cycles; profile=$Profile; guest=$ExpectedComputerName"
        $testExit=1
        try {
            & cargo test --locked --test mcp_smoke a_live_hypervisor_detaches_at_the_initial_break -- --ignored --exact --nocapture --test-threads=1
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
        Write-Host 'PASS: MCP detach succeeded; WinRM answered twice and uptime advanced without a reboot.'
    }
} finally {
    $env:WINDBG_MCP_SMOKE_HYPERVISOR_PROFILE=$previousProfile
    Pop-Location
}
