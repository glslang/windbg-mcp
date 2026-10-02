"""Try to activate a Hyper-V device-model COM object outside `vmwp.exe`.

Written for `FOLLOWUPS.md` item 103, where the costing of a VID/VSM rig (step 8)
rests on a question nobody had asked: the device model is **registered** as 24
in-proc COM servers backed by seven `vm*.dll`s, and registration is not
activation. The record said so in terms -- *"Nothing here activated anything: a
class factory can refuse, a dependency can be missing, and process context can
decide it"* -- and then **no call was made**, for weeks. This makes the call.

**What it measures and what it cannot.** Activating `IUnknown` says whether a
class object exists, whether its DLL loads into an ordinary process, and whether
`DllGetClassObject`/`CreateInstance` refuse. It says nothing about *driving* one:
these objects implement private interfaces this probe does not have the IIDs for,
and an object that constructs may still refuse every call on it. So a success here
removes the next obstacle and does not establish tier B.

**`IID_IUnknown` is the discriminator, chosen deliberately.** Asking for a private
interface would fail for a second reason -- a missing IID -- and every arm would
then fail alike, which is the shape of a probe that cannot see its own negative.
Every COM object implements `IUnknown`, so a refusal here is the class factory's.

**`CLSCTX_INPROC_SERVER` only, also deliberately.** Allowing a local server or a
surrogate would let COM *start a process* to satisfy the call, and the question is
whether the object can be created **in this** process. A surrogate activation
would answer a different question and look like a success.

**One child process per CLSID, with a deadline on each.** A device-model DLL reached with none of the
context `vmwp.exe` supplies may fault rather than return a failing `HRESULT`, and
a fault in the census process would cost every result after it. Each activation
therefore runs in a subprocess (`--one <clsid>`), whose crash is recorded as an
exit status next to the 23 that answered. **A class that blocks costs the same as
one that faults**, and the subprocess alone does not isolate it, so each child
also has a deadline and a timeout is recorded as a result of its own: *this class
did not answer* is a reading, where a missing row is not.

**The controls are checked before the total is printed**, and a bad one suppresses
it. `ACTIVATED=0` beside a positive control that also failed measures this probe's
own call path and says nothing about Hyper-V, which is the reading the controls
exist to prevent -- so leaving them unread would have made them decoration. A
failed control exits non-zero.

The output pointer is poisoned with `0xAA` before each call, so a provider that
writes nothing cannot be read as one that wrote null -- the same rule as the rest
of this bench's probes.

Usage::

    python tools/devmodel_activation_probe.py            # all 24, plus controls
    python tools/devmodel_activation_probe.py --one '{...}'   # one, as JSON
"""

from __future__ import annotations

import argparse
import ctypes
import json
import subprocess
import sys
from ctypes import wintypes

# The seven modules the step-8 census found the device model in. Matched against
# `InprocServer32` case-insensitively; the registry spells `VmSynthNic` mixed.
BACKING_DLLS = (
    "vmchipset",
    "vmuidevices",
    "vmsynthstor",
    "vmsynthnic",
    "vmbusvdev",
    "vmtpm",
    "vmdynmem",
)

# A registered in-proc class that must activate here, so a run of 24 failures can
# be told from a broken call path. Verified at runtime to be in-proc and *not*
# one of the seven, rather than asserted.
CONTROL_POSITIVE = "{F6D90F16-9C73-11D3-B32E-00C04F990BB4}"  # msxml3 XMLHTTP

# How long one activation may take before it is recorded as not having answered. A
# device-model class that blocks is as costly as one that faults, and the
# one-child-per-CLSID design only isolates the second without this.
ACTIVATION_TIMEOUT_S = 30

# Well-formed and registered nowhere: the negative control, which must come back
# REGDB_E_CLASSNOTREG. Without it, that code on a real CLSID cannot be read.
CONTROL_NEGATIVE = "{D0D0D0D0-1111-2222-3333-444455556666}"

CLSCTX_INPROC_SERVER = 0x1
COINIT_MULTITHREADED = 0x0

HRESULTS = {
    0x00000000: "S_OK",
    0x80004002: "E_NOINTERFACE",
    0x80004005: "E_FAIL",
    0x8000FFFF: "E_UNEXPECTED",
    0x80040111: "CLASS_E_CLASSNOTAVAILABLE",
    0x80040154: "REGDB_E_CLASSNOTREG",
    0x80070005: "E_ACCESSDENIED",
    0x8007007E: "ERROR_MOD_NOT_FOUND",
    0x8007000E: "E_OUTOFMEMORY",
    0x80070057: "E_INVALIDARG",
    0x800401F0: "CO_E_NOTINITIALIZED",
    0x80010106: "RPC_E_CHANGED_MODE",
}


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def hr_name(hr: int) -> str:
    return HRESULTS.get(hr & 0xFFFFFFFF, "")


def enumerate_device_model_clsids() -> list[dict]:
    """Every CLSID under HKLM whose in-proc server is one of the seven DLLs."""
    import winreg

    out = []
    root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE" "\\" "Classes" "\\" "CLSID")
    i = 0
    while True:
        try:
            name = winreg.EnumKey(root, i)
        except OSError:
            break
        i += 1
        try:
            server = winreg.OpenKey(root, name + "\\" "InprocServer32")
            path, _ = winreg.QueryValueEx(server, "")
        except OSError:
            continue
        low = path.lower()
        backing = next((d for d in BACKING_DLLS if d + ".dll" in low), None)
        if backing is None:
            continue
        try:
            threading, _ = winreg.QueryValueEx(server, "ThreadingModel")
        except OSError:
            threading = "(none)"
        try:
            friendly, _ = winreg.QueryValueEx(winreg.OpenKey(root, name), "")
        except OSError:
            friendly = ""
        out.append(
            {
                "clsid": name,
                "dll": backing,
                "path": path,
                "threading": threading,
                "name": friendly,
            }
        )
    return out


def loaded_modules() -> set[str]:
    """Lower-cased base names of the modules in this process, via the PEB loader.

    Used before and after each activation: a DLL that appears is a class factory
    that was reached, which separates a refusal from a lookup that never got
    there. `EnumProcessModules` would do, except that it needs psapi and a handle
    for no gain -- `GetModuleHandleW` per candidate answers exactly the question.
    """
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetModuleHandleW.restype = wintypes.HMODULE
    k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    present = set()
    for d in BACKING_DLLS:
        if k32.GetModuleHandleW(d + ".dll"):
            present.add(d)
    return present


def clsid_bytes_in_module(clsid_text: str, path: str) -> bool | None:
    """Whether the DLL's own image contains this CLSID's 16 little-endian bytes.

    `DllGetClassObject` compares an incoming CLSID against a table of the classes
    the module implements, and that table is GUID literals in `.rdata`. So a
    `CLASS_E_CLASSNOTAVAILABLE` whose GUID is **absent from the image** is a
    registration naming a module that never implemented it -- a packaging
    artifact -- where one whose GUID is *present* is the module declining a class
    it knows about, which is the interesting case. A byte search cannot tell a
    class table from any other use of the GUID, so this is corroboration and not
    a decode.
    """
    import os
    import uuid

    expanded = os.path.expandvars(path.strip('"'))
    try:
        with open(expanded, "rb") as fh:
            image = fh.read()
    except OSError:
        return None
    return uuid.UUID(clsid_text).bytes_le in image


def activate_one(clsid_text: str) -> dict:
    """`CoCreateInstance(clsid, IID_IUnknown, CLSCTX_INPROC_SERVER)`, measured."""
    ole = ctypes.WinDLL("ole32", use_last_error=True)

    clsid = GUID()
    hr = ole.CLSIDFromString(ctypes.c_wchar_p(clsid_text), ctypes.byref(clsid))
    if hr != 0:
        return {"clsid": clsid_text, "error": "CLSIDFromString 0x%08X" % (hr & 0xFFFFFFFF)}

    iid_unknown = GUID()
    ole.IIDFromString(
        ctypes.c_wchar_p("{00000000-0000-0000-C000-000000000046}"),
        ctypes.byref(iid_unknown),
    )

    init = ole.CoInitializeEx(None, COINIT_MULTITHREADED)
    result: dict = {
        "clsid": clsid_text,
        "coinit": "0x%08X" % (init & 0xFFFFFFFF),
        "modules_before": sorted(loaded_modules()),
    }

    # Poisoned, so "wrote nothing" cannot read as "wrote null".
    punk = ctypes.c_void_p(0xAAAAAAAAAAAAAAAA)
    hr = ole.CoCreateInstance(
        ctypes.byref(clsid),
        None,
        CLSCTX_INPROC_SERVER,
        ctypes.byref(iid_unknown),
        ctypes.byref(punk),
    )
    hr &= 0xFFFFFFFF
    result["hr"] = "0x%08X" % hr
    result["hr_name"] = hr_name(hr)
    result["last_error"] = ctypes.get_last_error()
    result["ptr"] = "0x%X" % (punk.value or 0)
    result["ptr_untouched"] = punk.value == 0xAAAAAAAAAAAAAAAA
    result["modules_after"] = sorted(loaded_modules())

    if hr == 0 and punk.value and not result["ptr_untouched"]:
        # Refcount through the vtable: AddRef then Release, and report what the
        # object itself said. A created object that cannot be refcounted would be
        # a far stranger result than a refusal.
        # `WINFUNCTYPE`, not `CFUNCTYPE`: COM vtable methods are `stdcall`. The two conventions
        # coincide on x64, so an x64 run cannot tell them apart and this probe's own results do not
        # establish which was right -- on x86 the `cdecl` version would corrupt the stack on the
        # first `AddRef`, and the parent would record the child as dead rather than as an activation
        # that worked. Raised in review on #434.
        vtbl = ctypes.cast(punk, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))
        query = ctypes.WINFUNCTYPE(
            ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
        )(vtbl[0][0])
        add_ref = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vtbl[0][1])
        release = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vtbl[0][2])
        result["after_addref"] = add_ref(punk)
        result["after_release"] = release(punk)

        # One call *on the object*, which is the obstacle after construction. The
        # IID is one nothing implements, so `E_NOINTERFACE` is the object's own
        # vtable dispatching -- it distinguishes a live object from a pointer to
        # something that merely constructed. A private interface cannot be asked
        # for here: this record has never read one of their IIDs.
        junk_iid = GUID()
        ole.IIDFromString(
            ctypes.c_wchar_p("{DEADBEEF-0000-0000-0000-000000000001}"),
            ctypes.byref(junk_iid),
        )
        sink = ctypes.c_void_p(0xAAAAAAAAAAAAAAAA)
        qi = query(punk, ctypes.byref(junk_iid), ctypes.byref(sink)) & 0xFFFFFFFF
        result["qi_unknown_iid"] = "0x%08X" % qi
        result["qi_name"] = hr_name(qi)
        result["qi_nulled_out"] = sink.value in (0, None)

        result["final_release"] = release(punk)

    ole.CoUninitialize()
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--one", help="activate a single CLSID and print one JSON line")
    args = ap.parse_args()

    if args.one:
        print(json.dumps(activate_one(args.one)))
        return 0

    targets = enumerate_device_model_clsids()
    print("device-model CLSIDs registered here: %d" % len(targets))
    rows = []
    for entry in (
        [{"clsid": CONTROL_POSITIVE, "dll": "(control+)", "name": "msxml3 XMLHTTP", "threading": "?"}]
        + [{"clsid": CONTROL_NEGATIVE, "dll": "(control-)", "name": "unregistered", "threading": "-"}]
        + targets
    ):
        # A deadline, because the one-child-per-CLSID design is for a device model that *faults* and
        # a blocking one costs just as much without it: `subprocess.run` would wait for ever, so the
        # remaining CLSIDs are never tried and no census is printed. A timeout is recorded as a
        # result of its own -- "this class did not answer" is a reading, where a missing row is not.
        try:
            child = subprocess.run(
                [sys.executable, __file__, "--one", entry["clsid"]],
                capture_output=True,
                text=True,
                timeout=ACTIVATION_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired:
            rows.append(
                {
                    **entry,
                    "hr": "(timed out)",
                    "hr_name": "no answer in %ds" % ACTIVATION_TIMEOUT_S,
                }
            )
            continue
        if child.returncode != 0 or not child.stdout.strip():
            rows.append(
                {
                    **entry,
                    "hr": "(child died)",
                    "hr_name": "exit 0x%08X" % (child.returncode & 0xFFFFFFFF),
                    "stderr": child.stderr.strip()[-200:],
                }
            )
            continue
        rows.append({**entry, **json.loads(child.stdout.strip().splitlines()[-1])})

    width = max(len(r.get("name") or "") for r in rows)
    for r in rows:
        loaded = set(r.get("modules_after") or []) - set(r.get("modules_before") or [])
        print(
            "  %-38s %-*s %-12s %-26s loaded=%-12s qi=%s"
            % (
                r["clsid"],
                width,
                r.get("name") or "",
                r["hr"],
                r.get("hr_name") or "",
                ",".join(sorted(loaded)) or "-",
                r.get("qi_name") or r.get("qi_unknown_iid") or "-",
            )
        )
    print()

    refused = [r for r in rows if r["hr"] == "0x80040111"]
    if refused:
        print("the refusals, against whether their module carries the GUID at all:")
        for r in refused:
            print(
                "  %s %-24s %s  guid_in_image=%s"
                % (r["clsid"], r.get("name"), r["dll"], clsid_bytes_in_module(r["clsid"], r["path"]))
            )
        print()
    # The controls are read BEFORE the total, and a bad one suppresses it. They exist to tell a
    # device-model refusal from a broken probe, and a run that prints `ACTIVATED=0` with a positive
    # control that also failed has measured its own call path and nothing about Hyper-V -- which is
    # exactly the reading the controls were added to prevent, so leaving them unchecked made them
    # decoration. Raised in review on #434.
    by_clsid = {r["clsid"]: r for r in rows}
    positive = by_clsid.get(CONTROL_POSITIVE, {})
    negative = by_clsid.get(CONTROL_NEGATIVE, {})
    broken = []
    if positive.get("hr") != "0x00000000":
        broken.append(
            "the positive control (%s) did not activate: %s %s"
            % (CONTROL_POSITIVE, positive.get("hr"), positive.get("hr_name") or "")
        )
    if negative.get("hr") != "0x80040154":
        broken.append(
            "the negative control (%s) was not REGDB_E_CLASSNOTREG: %s %s"
            % (CONTROL_NEGATIVE, negative.get("hr"), negative.get("hr_name") or "")
        )
    if broken:
        print("CONTROLS FAILED -- no total is reported, because it would not mean anything:")
        for why in broken:
            print("  %s" % why)
        return 1

    ok = [r for r in rows if r["hr"] == "0x00000000" and r["dll"] not in ("(control+)", "(control-)")]
    print("controls   positive=S_OK  negative=REGDB_E_CLASSNOTREG")
    print("ACTIVATED=%d of %d device-model classes" % (len(ok), len(targets)))
    for r in ok:
        print("  %s %s  refcount after AddRef=%s" % (r["clsid"], r.get("name"), r.get("after_addref")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
