# Runs on the TARGET VM (not the debugger host). Opens the device and fires each
# candidate IOCTL so the host-side logging breakpoint (ioctl_trace) records it.
# Run once as a normal user, then again from an elevated prompt, and compare which
# codes appear in the host log under each token -- that difference IS the per-token
# reachability answer. See ../skills/windbg-debugging/driver-ioctl.md.
#
#   .\send_ioctls_target.ps1 -DeviceName "\\.\MyDevice" -Codes 0x0022e004,0x0022e008
param(
    [string]$DeviceName = "\\.\MyDevice",
    [int[]]$Codes = @(0x0022e004)
)

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

# GENERIC_READ | GENERIC_WRITE. The `L` suffix forces Int64 so 0xC0000000 isn't
# parsed as a negative Int32 before the cast to the uint `access` parameter.
$GENERIC_RW = [uint32]0xC0000000L
$OPEN_EXISTING = 3
$h = [Io]::CreateFile($DeviceName, $GENERIC_RW, 0, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
if ($h -eq [IntPtr]-1) {
    $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host "CreateFile failed (gle=$gle) -- device not openable as this token (the *openable* gate)."
    exit 1
}

$inBuf = New-Object byte[] 16
$outBuf = New-Object byte[] 16
$ret = 0
foreach ($c in $Codes) {
    $ok = [Io]::DeviceIoControl($h, [uint32]$c, $inBuf, $inBuf.Length, $outBuf, $outBuf.Length, [ref]$ret, [IntPtr]::Zero)
    $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host ("IOCTL 0x{0:x8}  ok={1} gle={2} ret={3}" -f $c, $ok, $gle, $ret)
}
[Io]::CloseHandle($h) | Out-Null
