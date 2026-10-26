[CmdletBinding()]
param(
    [ValidateSet('Classic', 'WinDbgX')]
    [string] $Frontend = 'Classic',

    [string] $ConfigPath,

    [string] $ServerPath = (Join-Path $PSScriptRoot '..\target\release\windbg-mcp.exe'),

    [string] $DebuggerPath,

    [ValidateRange(1000, 3600000)]
    [int] $OpenTimeoutMs = 600000,

    [ValidateRange(1000, 3600000)]
    [int] $EndTimeoutMs = 120000,

    [switch] $LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-SkFile {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $Description
    )

    try {
        $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    } catch {
        throw "$Description does not exist: $Path"
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Description is not a file: $resolved"
    }
    return $resolved
}

function Resolve-SkDebugger {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Classic', 'WinDbgX')]
        [string] $Kind,

        [string] $ExplicitPath
    )

    if ($ExplicitPath) {
        return Resolve-SkFile -Path $ExplicitPath -Description "$Kind debugger"
    }

    $candidates = New-Object System.Collections.Generic.List[string]
    if ($Kind -eq 'Classic') {
        $command = Get-Command windbg.exe -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $command) {
            $candidates.Add($command.Source)
        }
        foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
            if ($root) {
                $candidates.Add((Join-Path $root 'Windows Kits\10\Debuggers\x64\windbg.exe'))
            }
        }
    } else {
        $command = Get-Command WinDbgX.exe -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $command) {
            $candidates.Add($command.Source)
        }
        if ($null -ne (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {
            $packages = Get-AppxPackage Microsoft.WinDbg -ErrorAction SilentlyContinue |
                Sort-Object Version -Descending
            foreach ($package in $packages) {
                $candidates.Add((Join-Path $package.InstallLocation 'WinDbgX.exe'))
                $candidates.Add((Join-Path $package.InstallLocation 'amd64\WinDbgX.exe'))
            }
        }
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).ProviderPath
        }
    }
    throw "Could not find the $Kind debugger. Supply -DebuggerPath with its executable path."
}

# ProcessStartInfo.ArgumentList is absent from Windows PowerShell's .NET Framework. Quote one
# argument according to CommandLineToArgvW so paths containing spaces work without invoking a
# shell. No live-control configuration value is ever placed in this string.
function ConvertTo-SkNativeArgument {
    param([AllowEmptyString()][string] $Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $builder = New-Object System.Text.StringBuilder
    [void] $builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            if ($slashes -gt 0) {
                [void] $builder.Append(('\' * ($slashes * 2)))
            }
            [void] $builder.Append('\"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void] $builder.Append(('\' * $slashes))
            $slashes = 0
        }
        [void] $builder.Append($character)
    }
    if ($slashes -gt 0) {
        [void] $builder.Append(('\' * ($slashes * 2)))
    }
    [void] $builder.Append('"')
    return $builder.ToString()
}

function Join-SkNativeArguments {
    param([string[]] $ArgumentList)
    return (($ArgumentList | ForEach-Object { ConvertTo-SkNativeArgument $_ }) -join ' ')
}

function Get-SkProperty {
    param($InputObject, [string] $Name)
    if ($null -eq $InputObject) {
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Start-SkMcpClient {
    param([Parameter(Mandatory = $true)][string] $Executable)

    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = Join-SkNativeArguments @('--tools', 'securekernel')
    $info.WorkingDirectory = Split-Path -Parent $Executable
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $false
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $info.StandardOutputEncoding = $utf8
    $process = [System.Diagnostics.Process]::Start($info)
    if ($null -eq $process) {
        throw 'Starting windbg-mcp returned no process.'
    }
    $input = New-Object System.IO.StreamWriter($process.StandardInput.BaseStream, $utf8)
    $input.AutoFlush = $true
    return @{
        Process = $process
        Input = $input
        NextId = 1
    }
}

function Send-SkMcpNotification {
    param($Client, [string] $Method)
    $message = @{ jsonrpc = '2.0'; method = $Method }
    $Client.Input.WriteLine(($message | ConvertTo-Json -Depth 32 -Compress))
}

function Send-SkMcpRequest {
    param(
        $Client,
        [string] $Method,
        $Parameters,
        [int] $TimeoutMs
    )

    $id = $Client.NextId
    $Client.NextId = $id + 1
    $message = @{ jsonrpc = '2.0'; id = $id; method = $Method }
    if ($null -ne $Parameters) {
        $message.params = $Parameters
    }
    $Client.Input.WriteLine(($message | ConvertTo-Json -Depth 32 -Compress))
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ($true) {
        $remaining = [int] [Math]::Min([int]::MaxValue, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if ($remaining -le 0) {
            throw "Timed out waiting for MCP request $Method."
        }
        $read = $Client.Process.StandardOutput.ReadLineAsync()
        if (-not $read.Wait($remaining)) {
            throw "Timed out waiting for MCP request $Method."
        }
        $line = $read.Result
        if ($null -eq $line) {
            throw "windbg-mcp closed stdout while $Method was in flight."
        }
        if (-not $line.Trim()) {
            continue
        }
        try {
            $response = $line | ConvertFrom-Json -ErrorAction Stop
        } catch {
            continue
        }
        if ((Get-SkProperty $response 'id') -eq $id) {
            $protocolError = Get-SkProperty $response 'error'
            if ($null -ne $protocolError) {
                throw "MCP request $Method failed: $(Get-SkProperty $protocolError 'message')"
            }
            return $response
        }
    }
}

function Invoke-SkMcpTool {
    param(
        $Client,
        [string] $Name,
        $Arguments,
        [int] $TimeoutMs
    )

    $response = Send-SkMcpRequest $Client 'tools/call' @{
        name = $Name
        arguments = $Arguments
    } $TimeoutMs
    $result = Get-SkProperty $response 'result'
    $structured = Get-SkProperty $result 'structuredContent'
    if ($null -eq $structured) {
        throw "MCP tool $Name returned no structured result."
    }
    return $structured
}

function Stop-SkMcpClient {
    param($Client)
    if ($null -eq $Client) {
        return
    }
    try { $Client.Input.Close() } catch {}
    try {
        if (-not $Client.Process.WaitForExit(5000)) {
            $Client.Process.Kill()
            [void] $Client.Process.WaitForExit(5000)
        }
    } catch {}
}

function Start-SkDebuggerAndWait {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string] $Connection
    )

    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = Join-SkNativeArguments @('-k', $Connection)
    $info.WorkingDirectory = Split-Path -Parent $Executable
    $info.UseShellExecute = $true
    $process = [System.Diagnostics.Process]::Start($info)
    if ($null -eq $process) {
        throw 'Starting the debugger returned no process.'
    }
    $process.WaitForExit()
    return $process.ExitCode
}

function Get-SkOpenFailureMessage {
    param($Opened)
    $detail = Get-SkProperty (Get-SkProperty $Opened 'error') 'message'
    if ($detail) {
        return $detail
    }
    return 'open_sk_kd failed without a diagnostic.'
}

# The lifecycle is factored around three callbacks so its cleanup contract can be tested without
# a disposable VM. The production callbacks below are the MCP client and the actual debugger.
function Invoke-SkKdLauncherCore {
    param(
        [Parameter(Mandatory = $true)][scriptblock] $OpenSession,
        [Parameter(Mandatory = $true)][scriptblock] $LaunchDebugger,
        [Parameter(Mandatory = $true)][scriptblock] $EndSession
    )

    $opened = $null
    $sessionId = $null
    $failure = $null
    $cleanupFailure = $null
    try {
        $opened = & $OpenSession
        if ((Get-SkProperty $opened 'status') -eq 'ok') {
            $sessionId = Get-SkProperty $opened 'session_id'
            $connection = Get-SkProperty $opened 'connection'
            if (-not $sessionId) {
                throw 'open_sk_kd succeeded without a session_id.'
            }
            if (-not $connection) {
                throw 'open_sk_kd succeeded without its typed generated connection.'
            }
            $exitCode = & $LaunchDebugger $connection
            if ($exitCode -ne 0) {
                throw "The debugger exited with code $exitCode."
            }
        } else {
            $sessionId = Get-SkProperty (Get-SkProperty $opened 'error') 'session_id'
            throw (Get-SkOpenFailureMessage $opened)
        }
    } catch {
        $failure = $_
    } finally {
        if ($sessionId) {
            try {
                $ended = & $EndSession $sessionId
                if ((Get-SkProperty $ended 'status') -ne 'ok') {
                    $message = Get-SkProperty (Get-SkProperty $ended 'error') 'message'
                    throw "end_session failed: $message"
                }
                if ((Get-SkProperty $ended 'released') -ne $true) {
                    throw 'end_session did not prove that the Secure Kernel controller was released.'
                }
            } catch {
                $cleanupFailure = $_
            }
        }
    }
    if ($null -ne $cleanupFailure) {
        if ($null -ne $failure) {
            throw "$($failure.Exception.Message) Cleanup also failed: $($cleanupFailure.Exception.Message)"
        }
        throw $cleanupFailure
    }
    if ($null -ne $failure) {
        throw $failure
    }
    return $opened
}

function Invoke-SkKdLauncher {
    param(
        [Parameter(Mandatory = $true)][string] $Configuration,
        [Parameter(Mandatory = $true)][string] $Server,
        [Parameter(Mandatory = $true)][string] $Debugger,
        [int] $OpenTimeout,
        [int] $EndTimeout
    )

    $configFile = Resolve-SkFile -Path $Configuration -Description 'Secure Kernel KD config'
    $serverFile = Resolve-SkFile -Path $Server -Description 'windbg-mcp executable'
    $arguments = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $arguments -or $arguments -is [System.Array]) {
        throw 'The Secure Kernel KD config must be one JSON object containing open_sk_kd arguments.'
    }

    $client = $null
    try {
        $client = Start-SkMcpClient $serverFile
        [void] (Send-SkMcpRequest $client 'initialize' @{
            protocolVersion = '2025-11-25'
            capabilities = @{}
            clientInfo = @{ name = 'windbg-mcp-sk-launcher'; version = '1' }
        } 30000)
        Send-SkMcpNotification $client 'notifications/initialized'

        [void] (Invoke-SkKdLauncherCore `
            -OpenSession { Invoke-SkMcpTool $client 'open_sk_kd' $arguments $OpenTimeout } `
            -LaunchDebugger { param($connection) Start-SkDebuggerAndWait $Debugger $connection } `
            -EndSession { param($session) Invoke-SkMcpTool $client 'end_session' @{ session_id = $session } $EndTimeout })
    } finally {
        Stop-SkMcpClient $client
    }
}

if (-not $LibraryOnly) {
    if (-not $ConfigPath) {
        throw '-ConfigPath is required.'
    }
    $resolvedDebugger = Resolve-SkDebugger -Kind $Frontend -ExplicitPath $DebuggerPath
    Write-Host "Opening a managed Secure Kernel KD session for $Frontend."
    Invoke-SkKdLauncher `
        -Configuration $ConfigPath `
        -Server $ServerPath `
        -Debugger $resolvedDebugger `
        -OpenTimeout $OpenTimeoutMs `
        -EndTimeout $EndTimeoutMs
    Write-Host 'The debugger exited and the managed Secure Kernel session was ended.'
}
