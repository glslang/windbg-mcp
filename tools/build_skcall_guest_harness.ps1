param(
    [string] $Output = (Join-Path $PSScriptRoot '..\target\skcall_guest_harness.exe')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer vswhere.exe was not found.'
}
$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) {
    throw 'Visual Studio C++ build tools were not found.'
}
$developerShell = Join-Path $installation 'Common7\Tools\Launch-VsDevShell.ps1'
if (-not (Test-Path -LiteralPath $developerShell)) {
    throw "Visual Studio developer shell was not found at $developerShell"
}

& $developerShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
$source = Join-Path $PSScriptRoot 'skcall_guest_harness.c'
$outputPath = [IO.Path]::GetFullPath($Output)
$outputDirectory = Split-Path -Parent $outputPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

& cl.exe /nologo /W4 /WX /O2 /MT /DUNICODE /D_UNICODE $source "/Fe:$outputPath" `
    /link /incremental:no onecore.lib
if ($LASTEXITCODE -ne 0) {
    throw "cl.exe failed with exit code $LASTEXITCODE"
}

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath).Hash.ToLowerInvariant()
[pscustomobject]@{
    schema = 'windbg-mcp.skcall-guest-build.v1'
    output = $outputPath
    sha256 = $hash
} | ConvertTo-Json
