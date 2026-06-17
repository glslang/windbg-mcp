# Runs on the TARGET VM (not the debugger host). Opens the device and fires each
# candidate IOCTL so the host-side logging breakpoint (ioctl_trace) records it.
# Run once as a normal user, then again from an elevated prompt, and compare which
# codes appear in the host log under each token -- that difference IS the per-token
# reachability answer. See ../skills/windbg-debugging/driver-ioctl.md.
#
#   .\send_ioctls_target.ps1 -DeviceName "\\.\MyDevice" -Codes 0x0022e004,0x0022e008
#   .\send_ioctls_target.ps1 -DeviceName "\\.\MyDevice" -DesiredAccess 0xC0000000
param(
    [string]$DeviceName = "\\.\MyDevice",
    # Candidate IOCTL codes as strings (0x-hex or decimal) so the full unsigned 32-bit
    # space works -- e.g. a vendor code whose device type sets bit 31, 0x80008003, which
    # would overflow a signed [int].
    [string[]]$Codes = @("0x0022e004"),
    # Handle access to request. Reachability is per (token, access): run with 0 (minimal
    # -- tests pure openability and FILE_ANY_ACCESS IOCTLs), 0x80000000 (GENERIC_READ),
    # 0x40000000 (GENERIC_WRITE), or 0xC0000000 (both). An IOCTL whose RequiredAccess
    # exceeds the handle's granted access is dropped by the I/O manager. 0x-hex or decimal.
    [string]$DesiredAccess = "0"
)

# Parse 0x-hex or decimal into a UInt32 (PowerShell would otherwise read 0x8000xxxx as a
# negative [int] and fail the cast to the unsigned CreateFile/DeviceIoControl arguments).
function ConvertTo-UInt32([string]$s) {
    $t = $s.Trim()
    if ($t -match '^0[xX]') { return [Convert]::ToUInt32($t.Substring(2), 16) }
    return [Convert]::ToUInt32($t, 10)
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Io {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFile(string name, uint access, uint share,
        IntPtr sec, uint disp, uint flags, IntPtr templ);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inBuf,
        uint inLen, byte[] outBuf, uint outLen, out uint ret, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
}
"@

# Share read+write so a device another process already holds open doesn't fail with
# ERROR_SHARING_VIOLATION (32) -- which would be a false "not openable", distinct from a
# genuine access-denied (5).
$FILE_SHARE_RW = 0x00000003
$OPEN_EXISTING = 3
$access = ConvertTo-UInt32 $DesiredAccess

$h = [Io]::CreateFile($DeviceName, $access, $FILE_SHARE_RW, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
if ($h -eq [IntPtr]-1) {
    $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host ("CreateFile({0}, access=0x{1:x8}) failed (gle={2})." -f $DeviceName, $access, $gle)
    Write-Host "  gle=5 access denied (not openable as this token) | gle=32 sharing violation | gle=2 no such device/symlink"
    exit 1
}

$inBuf = New-Object byte[] 16
$outBuf = New-Object byte[] 16
$ret = 0
foreach ($cs in $Codes) {
    $c = ConvertTo-UInt32 $cs
    $ok = [Io]::DeviceIoControl($h, $c, $inBuf, $inBuf.Length, $outBuf, $outBuf.Length, [ref]$ret, [IntPtr]::Zero)
    $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host ("IOCTL 0x{0:x8}  ok={1} gle={2} ret={3}" -f $c, $ok, $gle, $ret)
}
[Io]::CloseHandle($h) | Out-Null
