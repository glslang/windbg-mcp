"""The smallest program that reproduces the `vmsavedstatedumpprovider.dll` fast-fail.

One call, one argument, no VM named and nothing written. `LoadSavedStateFile` is asked to open a
Hyper-V saved state and the result is printed:

    python tools/vmsavedstate_load_probe.py <capture.vmrs> [provider.dll]

On a capture the provider understands this prints `returned hr=0x00000000` and releases the handle.
On a **capture taken while the VM had `EncryptStateAndVmMigrationTraffic` enabled** the process does
not reach the second print at all: the DLL fast-fails with `0xC0000409`
(`STATUS_STACK_BUFFER_OVERRUN`), which no caller can catch. See
`docs/secure-kernel/vmsavedstatedumpprovider-crash.md` for the report this exists for, and for what
the same call does on corrupt, truncated and random input -- which it refuses cleanly.

Read-only: the capture is opened by the provider, this script opens nothing itself, and a crash
leaves the file untouched. It is checked in because a bug report whose repro cannot be run is an
assertion, and because the same script is how a later SDK gets re-tested.
"""

import ctypes
import glob
import os
import platform
import sys
from ctypes import wintypes

KIT = r"C:\Program Files (x86)\Windows Kits\10\bin"


def provider_arch():
    """The SDK subdirectory whose DLL this *process* can load.

    Derived from the pointer width and the machine family, **not** from
    `PROCESSOR_ARCHITECTURE`: that names the machine, so a 32-bit Python on an x64 host would
    select the x64 provider, and `ctypes.WinDLL` would then refuse the image before
    `LoadSavedStateFile` was ever called -- an unrelated loader error wearing the shape of this
    report's repro.
    """
    if sys.maxsize <= 2**32:
        return "x86"
    return "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x64"


ARCH = provider_arch()


def newest_provider():
    """The highest-versioned provider DLL installed, for this process's architecture.

    The DLL has to match the *process*, not the guest: a 64-bit Python loads the x64 provider and
    reads an x64 guest's capture through it.
    """
    found = glob.glob(os.path.join(KIT, "*", ARCH, "vmsavedstatedumpprovider.dll"))
    if not found:
        raise SystemExit(f"no vmsavedstatedumpprovider.dll under {KIT}\\*\\{ARCH}")
    return max(found, key=lambda path: [int(part) for part in path.split(os.sep)[-3].split(".")])


def main(argv):
    if len(argv) < 2:
        raise SystemExit(
            "usage: python tools/vmsavedstate_load_probe.py <capture.vmrs> [provider.dll]"
        )
    capture = argv[1]
    dll = argv[2] if len(argv) > 2 else newest_provider()
    print(f"provider {dll}")
    print(f"capture  {capture} ({os.path.getsize(capture)} bytes)")
    lib = ctypes.WinDLL(dll)
    lib.LoadSavedStateFile.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    lib.LoadSavedStateFile.restype = ctypes.c_long
    lib.ReleaseSavedStateFiles.argtypes = [ctypes.c_void_p]
    lib.ReleaseSavedStateFiles.restype = ctypes.c_long
    handle = ctypes.c_void_p()
    print("calling LoadSavedStateFile", flush=True)
    hr = lib.LoadSavedStateFile(capture, ctypes.byref(handle))
    # Reaching this line at all is the pass: the failure under report kills the process inside the
    # call above, so an `hr` of any value -- including a failure -- is the provider behaving.
    print(f"returned hr=0x{hr & 0xFFFFFFFF:08X} handle={handle.value}", flush=True)
    if hr >= 0 and handle.value:
        lib.ReleaseSavedStateFiles(handle)
        print("released", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
