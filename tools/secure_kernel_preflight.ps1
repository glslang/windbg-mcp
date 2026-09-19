#requires -Version 5.1
<#
.SYNOPSIS
    Record the Secure Kernel plan's host prerequisites and native KDNET gate.
.DESCRIPTION
    Read-only apart from starting kdnet.exe with -?; never configures debugging.
    Run elevated to read package and virtualization metadata. JSON includes local
    paths and verbatim help; review it before sharing. No connection profiles,
    debug keys, or boot configuration are read.
.PARAMETER WinDbgDirectory
    Installed or unpacked WinDbg package root, containing AppxManifest.xml and amd64.
.PARAMETER EngineDirectory
    Server directory whose bundled x64 engine is being checked.
#>
[CmdletBinding()]
param(
    [string] $WinDbgDirectory,
    [string] $EngineDirectory = (Join-Path $PSScriptRoot '..\target\release')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $WinDbgDirectory) {
    $package = Get-AppxPackage Microsoft.WinDbg |
        Sort-Object { [version] $_.Version } -Descending | Select-Object -First 1
    if (-not $package) {
        throw 'WinDbg is not registered for this user. Supply -WinDbgDirectory for an unpacked package.'
    }
    $WinDbgDirectory = $package.InstallLocation
}
$WinDbgDirectory = (Resolve-Path -LiteralPath $WinDbgDirectory).ProviderPath
$EngineDirectory = (Resolve-Path -LiteralPath $EngineDirectory).ProviderPath
$manifest = [xml] (Get-Content -LiteralPath (Join-Path $WinDbgDirectory 'AppxManifest.xml') -Raw)
$packageVersion = [version] $manifest.Package.Identity.Version
$sourceEngine = Get-Item -LiteralPath (Join-Path $WinDbgDirectory 'amd64\dbgeng.dll')
$bundledEngine = Get-Item -LiteralPath (Join-Path $EngineDirectory 'dbgeng.dll')
$kdnet = Get-Item -LiteralPath (Join-Path $WinDbgDirectory 'amd64\kdnet.exe')

$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = $kdnet.FullName
$startInfo.Arguments = '-?'
$startInfo.WorkingDirectory = $kdnet.DirectoryName
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$process = New-Object System.Diagnostics.Process
$process.StartInfo = $startInfo
try {
    if (-not $process.Start()) { throw 'Could not start kdnet help.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(15000)) {
        $process.Kill()
        throw 'kdnet -? did not exit within 15 seconds; help capture is inconclusive.'
    }
    $help = $stdout.GetAwaiter().GetResult()
    $helpError = $stderr.GetAwaiter().GetResult()
    $helpExitCode = $process.ExitCode
} finally {
    $process.Dispose()
}

# Match the dedicated switch description, never the unrelated -SkipSecureBoot.
$hasSecureKernelSwitch = ($help + "`n" + $helpError) -match '(?im)^\s+s\s+-\s+enable[s]?\s+securekernel debugging\s*$'
$hasRecognizedHelp = ($help + "`n" + $helpError) -match '(?im)^kdnet\.exe \[host\] \[port\]'
$engineMatches = (Get-FileHash -LiteralPath $sourceEngine.FullName -Algorithm SHA256).Hash -eq
    (Get-FileHash -LiteralPath $bundledEngine.FullName -Algorithm SHA256).Hash
$nativeGate = 'pending_update'
if ($packageVersion -ge [version] '1.2606.22001.0') {
    if ($helpExitCode -ne 0 -or -not $hasRecognizedHelp) { $nativeGate = 'inconclusive_help' }
    elseif (-not $hasSecureKernelSwitch) { $nativeGate = 'closed_missing_switch' }
    elseif (-not $engineMatches) { $nativeGate = 'pending_engine_bundle' }
    else { $nativeGate = 'ready_for_lab' }
}

$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$computer = Get-CimInstance Win32_ComputerSystem
$systemDisk = Get-CimInstance Win32_LogicalDisk |
    Where-Object { $_.DeviceID -eq $env:SystemDrive } | Select-Object -First 1
$processors = @(Get-CimInstance Win32_Processor | Select-Object Name,
    VirtualizationFirmwareEnabled, SecondLevelAddressTranslationExtensions)
$deviceGuard = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard
$hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All

[ordered] @{
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    host = [ordered] @{
        architecture = $env:PROCESSOR_ARCHITECTURE
        display_version = $os.DisplayVersion
        build = "$($os.CurrentBuild).$($os.UBR)"
        manufacturer = $computer.Manufacturer
        model = $computer.Model
        hypervisor_present = $computer.HypervisorPresent
        memory_bytes = $computer.TotalPhysicalMemory
        logical_processors = $computer.NumberOfLogicalProcessors
        system_disk = [ordered] @{
            drive = $systemDisk.DeviceID
            size_bytes = $systemDisk.Size
            free_bytes = $systemDisk.FreeSpace
        }
        processors = $processors
        hyperv_feature_state = $hyperv.State.ToString()
        hyperv_management_available = [bool] (Get-Command Get-VM -ErrorAction SilentlyContinue)
        vbs_status = $deviceGuard.VirtualizationBasedSecurityStatus
        security_services_running = @($deviceGuard.SecurityServicesRunning)
    }
    windbg = [ordered] @{
        package_version = $packageVersion.ToString()
        package_directory = $WinDbgDirectory
        source_engine_version = $sourceEngine.VersionInfo.FileVersion
        bundled_engine_directory = $EngineDirectory
        bundled_engine_version = $bundledEngine.VersionInfo.FileVersion
        bundled_engine_matches_source_sha256 = $engineMatches
        kdnet_version = $kdnet.VersionInfo.FileVersion
        kdnet_help_exit_code = $helpExitCode
        kdnet_help_stdout = $help
        kdnet_help_stderr = $helpError
        secure_kernel_switch_present = $hasSecureKernelSwitch
    }
    native_gate = $nativeGate
    scope = 'Package and on-disk engine only; does not verify running MCP DLLs, a guest, or VTL1 debugging.'
} | ConvertTo-Json -Depth 6
