<#
.SYNOPSIS
    Send one IOCTL to a device - the out-of-band, driver-side counterpart to the
    windbg-mcp `run_to_address` tool.

.DESCRIPTION
    windbg-mcp's `reachable_from_dispatch` emits a "path recipe": the IoControlCode, the
    input/output buffer lengths, and the input-buffer fields that keep control on the path
    to a target block. This script consumes that recipe verbatim and drives the driver so
    the debugger - halted with a one-shot `g <block>` via `run_to_address` - can observe
    whether the block is actually reached (HIT) with that input.

    The windbg-mcp server itself cannot issue DeviceIoControl (it only drives the
    debugger), so this runs standalone on the *target* machine being kernel-debugged,
    out-of-band from the debug session. No compiler needed - it P/Invokes the Win32 API.

.PARAMETER Device
    Win32 device path to open, e.g. "\\.\MyDevice". The user-mode name of the driver's
    device object (see `device_object` in windbg-mcp for the \Device\... object).

.PARAMETER Code
    32-bit IOCTL control code. Accepts hex ("0x222003") or decimal. This is the value the
    dispatch switch routes on - the recipe states it (implied by the handler you targeted).

.PARAMETER InputHex
    Input-buffer bytes as hex. Spaces/underscores are ignored, so "41 42 43 00" and
    "41424300" are equivalent. These are the bytes the on-path `cmp/test` predicates read
    (SystemBuffer for buffered IOCTLs, Type3InputBuffer for METHOD_NEITHER).

.PARAMETER InLen
    Input length passed to DeviceIoControl. Defaults to the decoded InputHex length. Set a
    larger value to satisfy an `InputBufferLength >= N` gate without supplying every byte.

.PARAMETER OutLen
    Output-buffer size to allocate/report (satisfies an `OutputBufferLength >= N` gate).

.EXAMPLE
    .\ioctl_harness.ps1 -Device \\.\MyDevice -Code 0x222003 -InputHex "01000000" -OutLen 0x20
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Device,
    [Parameter(Mandatory = $true)] [string] $Code,
    [string] $InputHex = "",
    [int]    $InLen = -1,
    [int]    $OutLen = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -Namespace Ioctl -Name Native -MemberDefinition @'
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    public static extern System.IntPtr CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, System.IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, System.IntPtr hTemplateFile);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        System.IntPtr hDevice, uint dwIoControlCode,
        byte[] lpInBuffer, uint nInBufferSize,
        byte[] lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, System.IntPtr lpOverlapped);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(System.IntPtr hObject);
'@

function ConvertFrom-HexString([string] $s) {
    $clean = ($s -replace '[\s_]', '')
    # The unary comma matters: a bare `return [byte[]] @()` is unrolled by the pipeline into
    # nothing at all, so the caller gets $null and every `.Length` on it fails under StrictMode -
    # which is what an IOCTL taking no input buffer (the -InputHex default) hits.
    if ($clean.Length -eq 0) { return , ([byte[]] @()) }
    if ($clean.Length % 2 -ne 0) { throw "InputHex must have an even number of hex digits (got $($clean.Length))." }
    $bytes = New-Object byte[] ($clean.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
    }
    return $bytes
}

# --- parse inputs -----------------------------------------------------------
$ioctl = if ($Code -match '^(0x|0X)') { [Convert]::ToUInt32($Code, 16) } else { [uint32] $Code }
$inBytes = ConvertFrom-HexString $InputHex
$inLength = if ($InLen -ge 0) { [uint32] $InLen } else { [uint32] $inBytes.Length }
# When -InLen exceeds the supplied bytes (the documented pattern for satisfying an
# `InputBufferLength >= N` gate), zero-pad the buffer so DeviceIoControl never reads past
# the managed array (which would send garbage or fault).
if ($inLength -gt $inBytes.Length) {
    $padded = New-Object byte[] $inLength
    [Array]::Copy($inBytes, $padded, $inBytes.Length)
    $inBytes = $padded
}
$outLength = [uint32] $OutLen
$outBytes = if ($outLength -gt 0) { New-Object byte[] $outLength } else { $null }

# Windows PowerShell 5.1 reads a hex literal that does not fit Int32 as an Int32 *bit pattern*,
# so `0x80000000` is negative there and the uint32 parameter below refuses it - while PowerShell 7
# widens the same literal to Int64 and the call goes through. `[Convert]::ToUInt32` takes digits
# and a base, so it reads the same on both.
$GENERIC_READ = [Convert]::ToUInt32('80000000', 16)
$GENERIC_WRITE = [Convert]::ToUInt32('40000000', 16)
$FILE_SHARE_RW = 0x00000003
$OPEN_EXISTING = 3
$INVALID_HANDLE = [System.IntPtr] (-1)

Write-Host ("Device       : {0}" -f $Device)
Write-Host ("IoControlCode: 0x{0:x8}" -f $ioctl)
Write-Host ("Input        : {0} byte(s), InLen={1}" -f $inBytes.Length, $inLength)
Write-Host ("OutLen       : {0}" -f $outLength)

# --- open the device --------------------------------------------------------
$handle = [Ioctl.Native]::CreateFileW(
    $Device, ($GENERIC_READ -bor $GENERIC_WRITE), $FILE_SHARE_RW,
    [System.IntPtr]::Zero, $OPEN_EXISTING, 0, [System.IntPtr]::Zero)

if ($handle -eq $INVALID_HANDLE) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw ("CreateFile('{0}') failed: Win32 error {1} (0x{1:x8}) - {2}" -f `
        $Device, $err, ([System.ComponentModel.Win32Exception] $err).Message)
}

try {
    # --- send the IOCTL -----------------------------------------------------
    [uint32] $returned = 0
    $ok = [Ioctl.Native]::DeviceIoControl(
        $handle, $ioctl, $inBytes, $inLength, $outBytes, $outLength,
        [ref] $returned, [System.IntPtr]::Zero)
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($ok) {
        Write-Host ("RESULT       : SUCCESS, {0} byte(s) returned" -f $returned) -ForegroundColor Green
    } else {
        Write-Host ("RESULT       : FAILED, Win32 error {0} (0x{0:x8}) - {1}" -f `
            $err, ([System.ComponentModel.Win32Exception] $err).Message) -ForegroundColor Yellow
    }

    if ($outBytes -and $returned -gt 0) {
        $n = [Math]::Min([int] $returned, $outBytes.Length)
        $hex = ($outBytes[0..($n - 1)] | ForEach-Object { $_.ToString("x2") }) -join ' '
        Write-Host ("Output       : {0}" -f $hex)
    }
    exit ([int] (-not $ok))
} finally {
    [void][Ioctl.Native]::CloseHandle($handle)
}
