[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $PSScriptRoot '..\target\vtl1-control-probe'
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "vswhere.exe was not found at $vswhere"
}

$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) {
    throw 'Visual Studio C++ Build Tools were not found'
}

$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
$source = Join-Path $PSScriptRoot 'vtl1_control_probe.c'
$output = Join-Path $OutputDirectory 'vtl1_control_probe.exe'
$object = Join-Path $OutputDirectory 'vtl1_control_probe.obj'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$command = '"{0}" && cl.exe /nologo /std:c17 /W4 /WX /O2 /guard:cf /DUNICODE /D_UNICODE "{1}" /Fo:"{2}" /Fe:"{3}" version.lib ole32.lib' -f $vcvars, $source, $object, $output
& $env:ComSpec /d /s /c $command
if ($LASTEXITCODE -ne 0) {
    throw "cl.exe failed with exit code $LASTEXITCODE"
}

Write-Output $output
