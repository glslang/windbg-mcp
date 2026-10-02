"""Prove that six minimum inbox Hyper-V devices initialize outside vmwp.

This is the fatal K1.1 spike from FOLLOWUPS.md item 110.  The parent starts one
30-second child per device so an inbox DLL fault or hang cannot erase the other
results.  RTC is the repository/ABI control.  The other five devices each get a
fresh process-local VID partition whose GUID is also returned as the repository
VM ID.  This proves independent initialization paths; it does not compose the
devices into a runnable motherboard.

The private interfaces and VID entry points are build-specific.  Every child
checks the exact SHA-256, size, and (for the device DLLs) CodeView identity
before activating a class or creating a partition.

Run from an elevated x64 PowerShell prompt::

    python tools/vdev_initialization_probe.py

Read-only identity checking does not require elevation::

    python tools/vdev_initialization_probe.py --identity-only
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import pathlib
import struct
import subprocess
import sys
import uuid
from ctypes import wintypes
from dataclasses import dataclass


CHILD_TIMEOUT_SECONDS = 30
VID_SETUP_BYTES = 0xCAE0

IID_IUNKNOWN = "{00000000-0000-0000-C000-000000000046}"
IID_IVIRTUAL_DEVICE = "{0693ED7D-8A8A-4D87-A468-1103B8C63D9C}"
IID_IVIRTUAL_DEVICE_MEMORY_INFO = "{2E223C59-62C4-4D03-93E4-05674B3B94EB}"
IID_IVIRTUAL_DEVICE_REPOSITORY = "{355AC5A8-8A94-44A9-BE14-ECF7FB8F7C3B}"
IID_IVIRTUAL_DEVICE_SERVICES = "{20BEEF08-C3AB-44D8-92C3-03EC0CF398DC}"

IID_SECURITY_MANAGER = "{5315507B-19F0-4E86-AB51-18F159F1A197}"


@dataclass(frozen=True)
class Dependency:
    name: str
    iid: str
    required: bool = True


@dataclass(frozen=True)
class DeviceSpec:
    kind: str
    name: str
    clsid: str
    module: str
    vtable_rvas: tuple[int, int, int]
    dependencies: tuple[Dependency, ...]
    xml: str | None
    owner_partition: bool
    repository_calls: tuple[int, ...]
    service_calls: tuple[tuple[str, tuple[int, ...]], ...] = ()
    provided_interfaces: tuple[tuple[str, str], ...] = ()


def dependency(name: str, iid: str, required: bool = True) -> Dependency:
    return Dependency(name, iid.upper(), required)


DEVICES = {
    "guest": DeviceSpec(
        "guest",
        "GuestEmulationDevice",
        "{455C0F1B-D51B-40B1-BEAC-87377FE6E041}",
        "vmchipset.dll",
        (0x629E0, 0x63E10, 0x6B830),
        (
            dependency("ISecurityManager", IID_SECURITY_MANAGER),
            dependency("IVmBios", "{9BE0B79F-68DF-4C59-9D88-4BFC1BF7A73D}"),
            dependency("IVmBootMemoryTopology", "{B80FE14E-B5F6-43D4-B206-40B3BF511959}"),
            dependency("IVmbusServices", "{ECE3F556-F87F-4120-9E37-AAA55E5E0CA9}"),
            dependency("IVmGuestCrashServices", "{4F80E76E-0D0F-44E8-87BD-0280E1799351}"),
            dependency("IVmGuestMemoryAccess", "{2461C824-4E2A-4848-BB65-5708B27F06D9}"),
            dependency("IVmGuestStateRawStorage", "{F299B139-1550-4327-84F7-C1F433258EEF}"),
            dependency("IVmMemoryTopology", "{4F99E8B7-37BC-4EE4-B539-50263B4783B6}"),
            dependency("IVmPowerServices", "{3EE9144C-27D7-4C8E-A07E-5DD5F7A0207D}"),
            dependency("IVmProcessorServices", "{5F662E9D-2097-4EB5-8527-658BA54AC049}"),
            dependency("IVmTimeSource", "{E162FE7A-72C6-4D0E-93DD-7DF91A5B979D}"),
            dependency("IVpciServices", "{C8769BE0-2C2B-4DED-BD3C-FF7515D74E90}"),
            dependency("IVmCrashRegisterServices", "{F0109DC7-3F96-41B1-B0BC-5AEA911C404C}"),
            dependency("IVpmemController", "{521087AB-2963-4859-B6D9-D6F1EC9F3382}", False),
            dependency("IVmPsp", "{B0C36D19-3F91-4B3D-B8DC-EEE5BB2C9ABA}", False),
            dependency("IProxiedPciVgaDevice", "{FCB3759F-D139-46BE-8500-5C50A6FBFF9B}", False),
        ),
        "<GuestEmulationDevice><VDEVVersion>256</VDEVVersion><version>1</version>"
        "<ForceProtocol>0</ForceProtocol><OfferLogPipe>false</OfferLogPipe>"
        "</GuestEmulationDevice>",
        True,
        (11, 3, 17, 7, 40, 18, 17, 23, 18),
        (("ISecurityManager", (11,)),),
    ),
    "bios": DeviceSpec(
        "bios",
        "BiosVdev",
        "{AC6B8DC1-3257-4A70-B1B2-A9C9215659AD}",
        "vmchipset.dll",
        (0x44D30, 0x46180, 0x4A7D0),
        (
            dependency("IVmbusServices", "{ECE3F556-F87F-4120-9E37-AAA55E5E0CA9}"),
            dependency("IVmAmd64EmulationServices", "{FCACE8D2-AB0D-480D-B979-55C2DA5F9579}"),
            dependency("IVmGuestMemoryAccess", "{2461C824-4E2A-4848-BB65-5708B27F06D9}"),
            dependency("IVmProcessorServices", "{5F662E9D-2097-4EB5-8527-658BA54AC049}"),
            dependency("IVmBootMemoryTopology", "{B80FE14E-B5F6-43D4-B206-40B3BF511959}"),
            dependency("IVmBootStateImporter", "{034E6428-672E-403A-A342-4F4C8D6A705C}"),
            dependency("IVmMemoryTopology", "{4F99E8B7-37BC-4EE4-B539-50263B4783B6}"),
            dependency("IVmPowerManagementDevice", "{3F60DA8B-E8EF-403A-8173-9EF5C6EE0152}"),
            dependency("IVmIoApic", "{9D33829B-58BE-4BBF-AB6E-3B16DBCEF954}"),
            dependency("IVmManagementAccess", "{BB011455-A4F6-4E08-9982-09AFD303DF20}"),
            dependency("IVmPowerServices", "{3EE9144C-27D7-4C8E-A07E-5DD5F7A0207D}"),
            dependency("IVmTimeSource", "{E162FE7A-72C6-4D0E-93DD-7DF91A5B979D}"),
            dependency("IVmMemoryManagement", "{E7BB1D35-AD97-464B-8A3F-95F43E0F4389}"),
            dependency("ISecurityManager", IID_SECURITY_MANAGER),
            dependency("IVmPartitionServices", "{773E9A95-1B2D-4479-955F-402000EBE6C2}"),
            dependency("IVmHandleBrokerServices", "{E9E61D12-A2C3-4E55-AC35-B8F26D216A69}"),
            dependency("IVmPsp", "{B0C36D19-3F91-4B3D-B8DC-EEE5BB2C9ABA}", False),
            dependency("IVmBattery", "{2A811607-C21C-47DA-84A0-3C3B29AAD4E4}", False),
            dependency("IVpmemController", "{521087AB-2963-4859-B6D9-D6F1EC9F3382}", False),
            dependency("IVmGuestStateAccess", "{96DDF97A-0B79-4966-8B56-740F0D766E2E}", False),
        ),
        "<BiosLoader><VDEVVersion>512</VDEVVersion><version>1</version></BiosLoader>",
        True,
        (11, 3, 17, 7, 40, 18, 17, 23, 18),
        (("ISecurityManager", (12, 13, 10)),),
        provided_interfaces=(
            ("IVmBios", "{9BE0B79F-68DF-4C59-9D88-4BFC1BF7A73D}"),
        ),
    ),
    "rtc": DeviceSpec(
        "rtc",
        "RtcVdev",
        "{E51B7EF6-4A7F-4780-AAAE-D4B291AACD2E}",
        "vmchipset.dll",
        (0x7CA70, 0x7CEC0, 0x7D730),
        (
            dependency("IVmBios", "{9BE0B79F-68DF-4C59-9D88-4BFC1BF7A73D}"),
            dependency("IVmAmd64EmulationServices", "{FCACE8D2-AB0D-480D-B979-55C2DA5F9579}"),
            dependency("IVmIoApic", "{9D33829B-58BE-4BBF-AB6E-3B16DBCEF954}"),
            dependency("IVmManagementAccess", "{BB011455-A4F6-4E08-9982-09AFD303DF20}"),
            dependency("ISecurityManager", IID_SECURITY_MANAGER),
            dependency("IVmTimeSource", "{E162FE7A-72C6-4D0E-93DD-7DF91A5B979D}"),
        ),
        None,
        False,
        (11, 3, 17, 7, 40, 18, 39),
    ),
    "ioapic": DeviceSpec(
        "ioapic",
        "IoApicVdev",
        "{72682FC4-040A-430A-BE0B-224574B953FE}",
        "vmchipset.dll",
        (0x77830, 0x77D20, 0x78650),
        (
            dependency("ISecurityManager", IID_SECURITY_MANAGER),
            dependency("IVmAmd64EmulationServices", "{FCACE8D2-AB0D-480D-B979-55C2DA5F9579}"),
            dependency("IVmPartitionServices", "{773E9A95-1B2D-4479-955F-402000EBE6C2}"),
            dependency("IVmProcessorServices", "{5F662E9D-2097-4EB5-8527-658BA54AC049}"),
            dependency("IVmPicService", "{81A7B678-73B5-4188-AE42-882BFCDC7562}", False),
        ),
        "<IoApicDevice><VDEVVersion>256</VDEVVersion><version>1</version>"
        "<ForceLegacyRteWidth>false</ForceLegacyRteWidth></IoApicDevice>",
        True,
        (11, 3, 17, 7, 40, 18),
        provided_interfaces=(
            ("IVmIoApic", "{9D33829B-58BE-4BBF-AB6E-3B16DBCEF954}"),
        ),
    ),
    "vmbus": DeviceSpec(
        "vmbus",
        "VmbusVdev",
        "{D41A1872-3740-41CE-A1EE-4522AB82F991}",
        "vmbusvdev.dll",
        (0x10A20, 0x12720, 0x17780),
        (
            dependency("ISecurityManager", IID_SECURITY_MANAGER),
            dependency("IVmMemoryManagement", "{E7BB1D35-AD97-464B-8A3F-95F43E0F4389}"),
            dependency("IVmPartitionServices", "{773E9A95-1B2D-4479-955F-402000EBE6C2}"),
            dependency("IVmHandleBrokerServices", "{E9E61D12-A2C3-4E55-AC35-B8F26D216A69}"),
        ),
        "<VMBusDevice><VDEVVersion>513</VDEVVersion><version>1</version>"
        "<MessageRedirection>false</MessageRedirection></VMBusDevice>",
        True,
        (11, 3, 17, 7, 40, 18),
        (("IVmHandleBrokerServices", (3,)),),
        provided_interfaces=(
            ("IVmbusServices", "{ECE3F556-F87F-4120-9E37-AAA55E5E0CA9}"),
        ),
    ),
    "synthstor": DeviceSpec(
        "synthstor",
        "SynthStor",
        "{D422512D-2BF2-4752-809D-7B82B5FCB1B4}",
        "vmsynthstor.dll",
        (0x17D80, 0x191E0, 0x26290),
        (
            dependency("IVmHandleBrokerServices", "{E9E61D12-A2C3-4E55-AC35-B8F26D216A69}"),
            dependency("IVmManagementAccess", "{BB011455-A4F6-4E08-9982-09AFD303DF20}"),
            dependency("IVmPowerServices", "{3EE9144C-27D7-4C8E-A07E-5DD5F7A0207D}"),
            dependency("IVmbusServices", "{ECE3F556-F87F-4120-9E37-AAA55E5E0CA9}"),
        ),
        "<SyntheticStorageDevice><VDEVVersion>256</VDEVVersion><version>1</version>"
        "</SyntheticStorageDevice>",
        True,
        (11, 3, 17, 7, 40, 18, 39, 17, 26, 18),
    ),
}

CONFIG_FIELDS = {
    "guest": (
        "VDEVVersion",
        "version",
        "DevicePlatformSettings",
        "DevicePlatformSettingsV2",
        "ForceProtocol",
        "OfferLogPipe",
    ),
    "bios": (
        "VDEVVersion",
        "version",
        "bios_guid",
        "bios_serial_number",
        "num_lock",
        "base_board",
        "chassis",
        "secure_boot_enabled",
        "secure_boot_template_id",
        "bios_flags",
        "pause_after_boot_failure",
        "pxe_preferred_protocol",
        "console_mode",
        "boot",
        "imc_data",
        "memory_attributes_table",
        "nvram",
        "boot_next",
        "FirmwareMode",
        "BiosLockString",
        "EnableHibernation",
        "memoryprotection_mode",
        "LinuxKernelDirect",
        "DisableFrontpage",
        "ApplySbTemplate",
        "EnableProcessorIdling",
        "SystemInformation",
        "MemoryDeviceSerialNumber",
        "DisableSha384Pcr",
        "WatchdogEnabled",
        "LegacyPcrMeasurement",
    ),
    "rtc": (),
    "ioapic": ("VDEVVersion", "version", "ForceLegacyRteWidth"),
    "vmbus": ("VDEVVersion", "version", "MessageRedirection"),
    "synthstor": (
        "VDEVVersion",
        "version",
        "ElementName",
        "ChannelInstanceGuid",
        "DisableInterruptBatching",
        "VPCPerChannel",
        "ThreadsPerChannel",
        "controller0",
        "TargetVtl",
    ),
}

S_OK = 0
S_FALSE = 1
E_NOINTERFACE = 0x80004002
E_NOTIMPL = 0x80004001
ERROR_FILE_NOT_FOUND_HR = 0x80070002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class GuardedFile:
    def __init__(
        self,
        relative_path: str,
        size: int,
        sha256: str,
        version: str,
        pdb_guid: str | None = None,
        pdb_age: int | None = None,
    ) -> None:
        self.relative_path = relative_path
        self.size = size
        self.sha256 = sha256
        self.version = version
        self.pdb_guid = pdb_guid
        self.pdb_age = pdb_age


GUARDS = {
    "vid.dll": GuardedFile(
        "System32/vid.dll",
        263_552,
        "9B538C07FA65C09D406956371EF3C68F4BCE4E1FA9F694E4CCB727409366FA26",
        "10.0.26100.8457",
    ),
    "Vid.sys": GuardedFile(
        "System32/drivers/Vid.sys",
        910_816,
        "6611BCD768EFCFF90C13D39C4D9770315269C43201B3A58B638977486AB06697",
        "10.0.26100.9278",
    ),
    "vmchipset.dll": GuardedFile(
        "System32/vmchipset.dll",
        1_177_064,
        "8C13A65575EC35C73B4AABA631F7E7E1E52F88D503A3186B3EAECD375C2BE2D9",
        "10.0.26100.8457",
        "{2E91C425-4BBA-1675-375F-8AF8720410F8}",
        1,
    ),
    "vmbusvdev.dll": GuardedFile(
        "System32/vmbusvdev.dll",
        271_840,
        "64104CEFE36B4E7695D39550FF64CE94A0CD21F2D9693171E8331BCC60A51736",
        "10.0.26100.8457",
        "{A1F04F82-DB3B-3AF6-6744-C606F24BEEB9}",
        1,
    ),
    "vmsynthstor.dll": GuardedFile(
        "System32/vmsynthstor.dll",
        517_624,
        "E7972B586FA2E8540ED9738C3CA5B6D9D0EF0EB02C1A7FAAABAC33689790446B",
        "10.0.26100.8457",
        "{894A49E8-F56D-3957-E8EB-2214733ECA28}",
        1,
    ),
    "vmwp.exe": GuardedFile(
        "System32/vmwp.exe",
        3_720_352,
        "AC076752BD5424B57C994D4529C5179BB153F9DA0119FB23AD1C13AC9A571B20",
        "10.0.26100.8457",
        "{DC281C89-2BE3-8A04-AC2B-1C27F20A2865}",
        1,
    ),
    "vmfirmware.dll": GuardedFile(
        "System32/vmfirmware.dll",
        6_436_256,
        "4FE86E4B71D814F2D679D32BFC813B9B2600A4F1CBFE67C3FEB6689E681A53F6",
        "10.0.26100.7623",
    ),
}

PDB_NAMES = {
    "vmchipset.dll": "vmchipset.pdb",
    "vmbusvdev.dll": "vmbusvdev.pdb",
    "vmsynthstor.dll": "VmSynthStor.pdb",
    "vmwp.exe": "vmwp.pdb",
}

BINARY_ROLES = {
    "vmwp.exe": "symbol source for motherboard lifecycle and device ordering",
    "vmfirmware.dll": "firmware resource consumed by BiosVdev",
}

CONTRACT_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "docs"
    / "secure-kernel"
    / "vdev-contract-26100.8457.json"
)


def contract_manifest() -> dict[str, object]:
    binaries: dict[str, object] = {}
    for name, guard in GUARDS.items():
        entry: dict[str, object] = {
            "version": guard.version,
            "size": guard.size,
            "sha256": guard.sha256,
        }
        if guard.pdb_guid is not None:
            entry.update(
                {
                    "pdb_guid": guard.pdb_guid,
                    "pdb_age": guard.pdb_age,
                    "pdb_name": PDB_NAMES[name],
                }
            )
        elif name == "vmfirmware.dll":
            entry["codeview"] = None
        if name in BINARY_ROLES:
            entry["role"] = BINARY_ROLES[name]
        binaries[name] = entry

    devices = []
    for spec in DEVICES.values():
        required = [item for item in spec.dependencies if item.required]
        optional = [item for item in spec.dependencies if not item.required]
        devices.append(
            {
                "kind": spec.kind,
                "name": spec.name,
                "clsid": spec.clsid,
                "module": spec.module,
                "ivirtual_device": {
                    "iid": IID_IVIRTUAL_DEVICE,
                    "lifecycle": [
                        {"slot": 3, "method": "GetDependencies", "rva": f"0x{spec.vtable_rvas[0]:X}"},
                        {"slot": 4, "method": "Initialize", "rva": f"0x{spec.vtable_rvas[1]:X}"},
                        {"slot": 5, "method": "Teardown", "rva": f"0x{spec.vtable_rvas[2]:X}"},
                    ],
                },
                "owner_partition": spec.owner_partition,
                "get_dependencies_order": [
                    {"name": item.name, "iid": item.iid, "required": item.required}
                    for item in spec.dependencies
                ],
                "required_count": len(required),
                "initialize_dependency_order": [
                    item.name for item in (*required, *reversed(optional))
                ],
                "provided_interfaces": [
                    {"name": name, "iid": iid}
                    for name, iid in spec.provided_interfaces
                ],
                "configuration_fields": list(CONFIG_FIELDS[spec.kind]),
                "minimum_xml": spec.xml,
                "observed_repository_slots": list(spec.repository_calls),
                "observed_service_calls": {
                    name: list(slots) for name, slots in spec.service_calls
                },
            }
        )

    return {
        "schema_version": 1,
        "observed_on": "2026-10-02",
        "scope": {
            "result": "six independent initialization and teardown paths pass",
            "does_not_prove": [
                "one composed device graph",
                "RAM-construction-complete notification",
                "firmware execution",
                "synthetic disk I/O",
            ],
        },
        "interfaces": {
            "IVirtualDevice": IID_IVIRTUAL_DEVICE,
            "IVirtualDeviceMemoryInfo": IID_IVIRTUAL_DEVICE_MEMORY_INFO,
            "IVirtualDeviceRepository": IID_IVIRTUAL_DEVICE_REPOSITORY,
            "IVirtualDeviceServices": IID_IVIRTUAL_DEVICE_SERVICES,
        },
        "repository_slots": {
            "3": "GetId",
            "7": "ReadVersion",
            "9": "GetDeviceId",
            "11": "GetVmNameAndId",
            "17": "Open",
            "18": "Close",
            "23": "ReadString",
            "26": "ReadBoolean",
            "39": "GetRuntimeConfiguration",
            "40": "ExportConfiguration",
        },
        "repository_values": {
            "/generation_id": "00000000-0000-0000-0000-000000000000",
            "/PreallocatedResources": False,
        },
        "binary_identities": binaries,
        "devices": devices,
    }


def verify_contract_file() -> None:
    try:
        recorded = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RuntimeError(f"missing contract manifest: {CONTRACT_PATH}") from error
    expected = contract_manifest()
    if recorded != expected:
        raise RuntimeError(
            f"contract manifest is stale: regenerate {CONTRACT_PATH} with --contract-only"
        )


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class ComObject(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(ctypes.c_void_p)), ("refs", ctypes.c_ulong)]


ole = ctypes.WinDLL("ole32")
oleaut = ctypes.WinDLL("oleaut32")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

ole.IIDFromString.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(GUID)]
ole.IIDFromString.restype = ctypes.c_long
ole.StringFromGUID2.argtypes = [ctypes.POINTER(GUID), ctypes.c_wchar_p, ctypes.c_int]
ole.StringFromGUID2.restype = ctypes.c_int
ole.CoCreateInstance.argtypes = [
    ctypes.POINTER(GUID),
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(GUID),
    ctypes.POINTER(ctypes.c_void_p),
]
ole.CoCreateInstance.restype = ctypes.c_long
ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
oleaut.SysAllocString.argtypes = [ctypes.c_wchar_p]
oleaut.SysAllocString.restype = ctypes.c_void_p
kernel32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
kernel32.VirtualQuery.restype = ctypes.c_size_t
kernel32.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, wintypes.DWORD]
kernel32.GetModuleFileNameW.restype = wintypes.DWORD

QI = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)
)
REF = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)
GENERIC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
OPEN = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_int, ctypes.c_int)
READ_VERSION = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
)
GET_RUNTIME = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
)
GET_VM_NAME_ID = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(GUID),
)
GET_TWO_GUIDS = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.POINTER(GUID)
)
GET_SERVICE = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)
)
EXPORT = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)
)
STREAM_WRITE = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
)
READ_STRING = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)
)
READ_BOOLEAN = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(wintypes.BOOL)
)
SET_U32 = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)
)


def emit(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def hresult(value: int) -> str:
    return f"0x{value & 0xFFFFFFFF:08X}"


def make_guid(text: str) -> GUID:
    value = GUID()
    result = ole.IIDFromString(text, ctypes.byref(value))
    if result:
        raise OSError(result & 0xFFFFFFFF, f"IIDFromString({text})")
    return value


def guid_text(value: GUID) -> str:
    output = ctypes.create_unicode_buffer(40)
    if ole.StringFromGUID2(ctypes.byref(value), output, len(output)) != 39:
        raise RuntimeError("StringFromGUID2 returned an unexpected length")
    return output.value.upper()


def _rva_to_offset(image: bytes, sections: list[tuple[int, int, int, int]], rva: int) -> int:
    for virtual_address, virtual_size, raw_offset, raw_size in sections:
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            return raw_offset + rva - virtual_address
    if rva < len(image):
        return rva
    raise ValueError(f"RVA 0x{rva:X} is outside the image")


def codeview_identity(path: pathlib.Path) -> tuple[str, int, str]:
    image = path.read_bytes()
    if image[:2] != b"MZ":
        raise ValueError("missing DOS signature")
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe : pe + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    section_count = struct.unpack_from("<H", image, pe + 6)[0]
    optional_size = struct.unpack_from("<H", image, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", image, optional)[0]
    data_directories = optional + (112 if magic == 0x20B else 96 if magic == 0x10B else -1)
    if data_directories < optional:
        raise ValueError("unsupported optional header")
    debug_rva, debug_size = struct.unpack_from("<II", image, data_directories + 6 * 8)
    section_table = optional + optional_size
    sections = []
    for index in range(section_count):
        entry = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", image, entry + 8
        )
        sections.append((virtual_address, virtual_size, raw_offset, raw_size))
    debug_offset = _rva_to_offset(image, sections, debug_rva)
    for offset in range(debug_offset, debug_offset + debug_size, 28):
        kind = struct.unpack_from("<I", image, offset + 12)[0]
        data_size = struct.unpack_from("<I", image, offset + 16)[0]
        data_offset = struct.unpack_from("<I", image, offset + 24)[0]
        if kind != 2 or data_size < 24 or image[data_offset : data_offset + 4] != b"RSDS":
            continue
        pdb_guid = "{" + str(uuid.UUID(bytes_le=image[data_offset + 4 : data_offset + 20])).upper() + "}"
        age = struct.unpack_from("<I", image, data_offset + 20)[0]
        raw_name = image[data_offset + 24 : data_offset + data_size].split(b"\0", 1)[0]
        return pdb_guid, age, raw_name.decode("utf-8", errors="replace")
    raise ValueError("no CodeView RSDS record")


def guarded_path(name: str) -> tuple[pathlib.Path, dict[str, object]]:
    guard = GUARDS[name]
    root = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
    relative = pathlib.PurePosixPath(guard.relative_path)
    path = root.joinpath(*relative.parts)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest().upper()
    if len(data) != guard.size or digest != guard.sha256:
        raise RuntimeError(
            f"{path} does not match guarded {guard.version}: "
            f"size={len(data)} sha256={digest}"
        )
    result: dict[str, object] = {
        "path": str(path),
        "guarded_version": guard.version,
        "size": len(data),
        "sha256": digest,
    }
    if guard.pdb_guid is not None:
        pdb_guid, pdb_age, pdb_name = codeview_identity(path)
        if pdb_guid != guard.pdb_guid or pdb_age != guard.pdb_age:
            raise RuntimeError(
                f"{path} CodeView mismatch: guid={pdb_guid} age={pdb_age}"
            )
        result.update({"pdb_guid": pdb_guid, "pdb_age": pdb_age, "pdb_name": pdb_name})
    return path, result


def verify_identities(kind: str | None = None) -> dict[str, dict[str, object]]:
    if kind is None:
        names = tuple(GUARDS)
    else:
        spec = DEVICES[kind]
        names = (spec.module, "vid.dll", "Vid.sys") if spec.owner_partition else (spec.module,)
    identities = {}
    for name in names:
        _, identities[name] = guarded_path(name)
    return identities


def module_and_rva(address: int) -> tuple[pathlib.Path, int]:
    class MemoryBasicInformation(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("PartitionId", wintypes.WORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    info = MemoryBasicInformation()
    if not kernel32.VirtualQuery(ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    output = ctypes.create_unicode_buffer(32768)
    if not kernel32.GetModuleFileNameW(info.AllocationBase, output, len(output)):
        raise ctypes.WinError(ctypes.get_last_error())
    base = int(info.AllocationBase or 0)
    return pathlib.Path(output.value), address - base


class OwnerPartition:
    def __init__(self, vm_id: str) -> None:
        vid_path, _ = guarded_path("vid.dll")
        self.module = ctypes.WinDLL(str(vid_path), use_last_error=True)
        self.create = self.module.VidCreatePartition
        self.create.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
        self.create.restype = ctypes.c_void_p
        self.attach = self.module.VidAttachPartition
        self.attach.argtypes = [ctypes.c_void_p]
        self.attach.restype = wintypes.BOOL
        self.get_partition_id = self.module.VidGetHvPartitionId
        self.get_partition_id.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
        self.get_partition_id.restype = wintypes.BOOL
        self.delete = self.module.VidDeletePartition
        self.delete.argtypes = [ctypes.c_void_p]
        self.delete.restype = None
        setup = ctypes.create_string_buffer(VID_SETUP_BYTES)
        struct.pack_into("<I", setup, 0, 0x600)
        struct.pack_into("<Q", setup, 0x20, 2)
        struct.pack_into("<I", setup, 0x28, 1)
        struct.pack_into("<I", setup, 0x30, 1)
        struct.pack_into("<I", setup, 0xC8A8, 0)
        name = vm_id.strip("{}")
        self.handle = self.create(name, "windbg-mcp inbox device initialization probe", setup)
        ctypes.memset(setup, 0, len(setup))
        if self.handle in (None, INVALID_HANDLE_VALUE):
            raise ctypes.WinError(ctypes.get_last_error())
        if not self.attach(self.handle):
            error = ctypes.get_last_error()
            self.delete(self.handle)
            self.handle = None
            raise ctypes.WinError(error)
        partition_id = ctypes.c_uint64()
        if not self.get_partition_id(self.handle, ctypes.byref(partition_id)):
            error = ctypes.get_last_error()
            self.delete(self.handle)
            self.handle = None
            raise ctypes.WinError(error)
        self.partition_id = partition_id.value
        emit("owner_partition_created", vm_id=vm_id, partition_id=f"0x{self.partition_id:X}")

    def close(self) -> None:
        if self.handle not in (None, INVALID_HANDLE_VALUE):
            self.delete(self.handle)
            self.handle = None
            emit("owner_partition_deleted", partition_id=f"0x{self.partition_id:X}")


class RecordingRepository:
    def __init__(self, class_id: str, vm_id: str, xml: str | None) -> None:
        self.class_id = class_id
        self.vm_id = vm_id
        self.device_id = "{" + str(uuid.uuid4()).upper() + "}"
        self.xml = xml
        self.calls: list[int] = []
        self.callbacks: list[object] = []
        self.vtable = (ctypes.c_void_p * 43)()
        self.obj = ComObject(ctypes.cast(self.vtable, ctypes.POINTER(ctypes.c_void_p)), 1)
        accepted = {bytes(make_guid(IID_IUNKNOWN)), bytes(make_guid(IID_IVIRTUAL_DEVICE_REPOSITORY))}

        @QI
        def query(_this, requested, output):
            if ctypes.string_at(requested, 16) in accepted:
                output[0] = ctypes.addressof(self.obj)
                self.obj.refs += 1
                return S_OK
            output[0] = None
            return E_NOINTERFACE

        @REF
        def add_ref(_this):
            self.obj.refs += 1
            return self.obj.refs

        @REF
        def release(_this):
            self.obj.refs -= 1
            return self.obj.refs

        self.callbacks.extend((query, add_ref, release))
        self.vtable[0] = ctypes.cast(query, ctypes.c_void_p)
        self.vtable[1] = ctypes.cast(add_ref, ctypes.c_void_p)
        self.vtable[2] = ctypes.cast(release, ctypes.c_void_p)

        for index in range(3, len(self.vtable)):
            def make_missing(slot):
                @GENERIC
                def missing(_this):
                    self.calls.append(slot)
                    emit("repository_call", slot=slot, result="E_NOTIMPL")
                    return E_NOTIMPL

                return missing

            callback = make_missing(index)
            self.callbacks.append(callback)
            self.vtable[index] = ctypes.cast(callback, ctypes.c_void_p)

        @GET_TWO_GUIDS
        def get_id(_this, class_output, instance_output):
            self.calls.append(3)
            class_output[0] = make_guid(self.class_id)
            instance_output[0] = make_guid(self.device_id)
            emit("repository_call", slot=3, class_id=self.class_id, device_id=self.device_id)
            return S_OK

        @READ_VERSION
        def read_version(_this, minimum, maximum, output):
            self.calls.append(7)
            output[0] = minimum
            emit("repository_call", slot=7, minimum=minimum, maximum=maximum, value=minimum)
            return S_OK

        @GET_TWO_GUIDS
        def get_device_id(_this, class_output, instance_output):
            self.calls.append(9)
            class_output[0] = make_guid(self.class_id)
            instance_output[0] = make_guid(self.device_id)
            emit("repository_call", slot=9, class_id=self.class_id, device_id=self.device_id)
            return S_OK

        @GET_VM_NAME_ID
        def get_vm_name_id(_this, name_output, id_output):
            self.calls.append(11)
            name_output[0] = oleaut.SysAllocString("OwnedVdevInitializationProbe")
            id_output[0] = make_guid(self.vm_id)
            emit("repository_call", slot=11, vm_id=self.vm_id)
            return S_OK

        @READ_STRING
        def read_string(_this, name, output):
            self.calls.append(23)
            if name != "/generation_id":
                output[0] = None
                emit("repository_call", slot=23, name=name, result="E_NOTIMPL")
                return E_NOTIMPL
            value = "00000000-0000-0000-0000-000000000000"
            output[0] = oleaut.SysAllocString(value)
            emit("repository_call", slot=23, name=name, value=value, result="S_OK")
            return S_OK

        @READ_BOOLEAN
        def read_boolean(_this, name, output):
            self.calls.append(26)
            if name != "/PreallocatedResources":
                emit("repository_call", slot=26, name=name, result="E_NOTIMPL")
                return E_NOTIMPL
            output[0] = False
            emit("repository_call", slot=26, name=name, value=False, result="S_OK")
            return S_OK

        @OPEN
        def open_repository(_this, configuration, access):
            self.calls.append(17)
            emit("repository_call", slot=17, configuration=configuration, access=access)
            return S_OK

        @GENERIC
        def close_repository(_this):
            self.calls.append(18)
            emit("repository_call", slot=18, result="S_OK")
            return S_OK

        @GET_RUNTIME
        def get_runtime(_this, output):
            self.calls.append(39)
            output[0] = None
            emit("repository_call", slot=39, result="S_FALSE")
            return S_FALSE

        @EXPORT
        def export_configuration(_this, stream, exported):
            self.calls.append(40)
            if self.xml is None:
                emit("repository_call", slot=40, result="ERROR_FILE_NOT_FOUND")
                return ERROR_FILE_NOT_FOUND_HR
            encoded = self.xml.encode("utf-16-le")
            payload = ctypes.create_string_buffer(encoded)
            stream_vtable = ctypes.cast(
                stream, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))
            )[0]
            written = wintypes.DWORD()
            result = STREAM_WRITE(stream_vtable[4])(
                stream, payload, len(encoded), ctypes.byref(written)
            )
            if exported:
                exported[0] = written.value
            emit(
                "repository_call",
                slot=40,
                bytes=len(encoded),
                written=written.value,
                result=hresult(result),
            )
            return result

        overrides = {
            3: get_id,
            7: read_version,
            9: get_device_id,
            11: get_vm_name_id,
            17: open_repository,
            18: close_repository,
            23: read_string,
            26: read_boolean,
            39: get_runtime,
            40: export_configuration,
        }
        self.callbacks.extend(overrides.values())
        for index, callback in overrides.items():
            self.vtable[index] = ctypes.cast(callback, ctypes.c_void_p)

    @property
    def pointer(self) -> ctypes.c_void_p:
        return ctypes.c_void_p(ctypes.addressof(self.obj))


class RecordingService:
    def __init__(self, name: str, service_id: str) -> None:
        self.name = name
        self.service_id = service_id.upper()
        self.calls: list[int] = []
        self.callbacks: list[object] = []
        self.vtable = (ctypes.c_void_p * 64)()
        self.obj = ComObject(ctypes.cast(self.vtable, ctypes.POINTER(ctypes.c_void_p)), 1)

        @QI
        def query(_this, requested, output):
            requested_text = guid_text(requested[0])
            if requested_text in (IID_IUNKNOWN.upper(), self.service_id):
                output[0] = ctypes.addressof(self.obj)
                self.obj.refs += 1
                return S_OK
            output[0] = None
            return E_NOINTERFACE

        @REF
        def add_ref(_this):
            self.obj.refs += 1
            return self.obj.refs

        @REF
        def release(_this):
            self.obj.refs -= 1
            return self.obj.refs

        self.callbacks.extend((query, add_ref, release))
        self.vtable[0] = ctypes.cast(query, ctypes.c_void_p)
        self.vtable[1] = ctypes.cast(add_ref, ctypes.c_void_p)
        self.vtable[2] = ctypes.cast(release, ctypes.c_void_p)
        for index in range(3, len(self.vtable)):
            def make_missing(slot):
                @GENERIC
                def missing(_this):
                    self.calls.append(slot)
                    emit("service_call", service=self.name, slot=slot, result="E_NOTIMPL")
                    return E_NOTIMPL

                return missing

            callback = make_missing(index)
            self.callbacks.append(callback)
            self.vtable[index] = ctypes.cast(callback, ctypes.c_void_p)

        if self.service_id == IID_SECURITY_MANAGER.upper():
            for index in (10, 11, 12, 13):
                def make_zero(slot):
                    @SET_U32
                    def zero(_this, output):
                        self.calls.append(slot)
                        output[0] = 0
                        emit(
                            "service_call",
                            service=self.name,
                            slot=slot,
                            value=0,
                            result="S_OK",
                        )
                        return S_OK

                    return zero

                callback = make_zero(index)
                self.callbacks.append(callback)
                self.vtable[index] = ctypes.cast(callback, ctypes.c_void_p)

    @property
    def pointer(self) -> int:
        return ctypes.addressof(self.obj)

    def add_reference(self) -> None:
        self.obj.refs += 1


class ComInterfaceService:
    def __init__(self, name: str, service_id: str, pointer: ctypes.c_void_p) -> None:
        self.name = name
        self.service_id = service_id.upper()
        self.calls: list[int] = []
        self._pointer = pointer
        self._closed = False

    @property
    def pointer(self) -> int:
        if self._closed or not self._pointer.value:
            raise RuntimeError(f"{self.name} interface is closed")
        return int(self._pointer.value)

    def add_reference(self) -> None:
        vtable = ctypes.cast(
            self._pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))
        )[0]
        REF(vtable[1])(self._pointer)

    def close(self) -> None:
        if not self._closed and self._pointer.value:
            vtable = ctypes.cast(
                self._pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))
            )[0]
            REF(vtable[2])(self._pointer)
            self._closed = True


class RecordingServices:
    def __init__(
        self,
        dependencies: tuple[Dependency, ...],
        overrides: dict[str, ComInterfaceService] | None = None,
    ) -> None:
        supplied = overrides or {}
        self.services = {}
        for item in dependencies:
            service = supplied.get(item.iid)
            if service is not None and service.name != item.name:
                raise RuntimeError(
                    f"service name mismatch for {item.iid}: {service.name} != {item.name}"
                )
            self.services[item.iid] = service or RecordingService(item.name, item.iid)
        self.callbacks: list[object] = []
        self.vtable = (ctypes.c_void_p * 4)()
        self.obj = ComObject(ctypes.cast(self.vtable, ctypes.POINTER(ctypes.c_void_p)), 1)

        @QI
        def query(_this, requested, output):
            requested_text = guid_text(requested[0])
            if requested_text in (IID_IUNKNOWN.upper(), IID_IVIRTUAL_DEVICE_SERVICES.upper()):
                output[0] = ctypes.addressof(self.obj)
                self.obj.refs += 1
                return S_OK
            output[0] = None
            return E_NOINTERFACE

        @REF
        def add_ref(_this):
            self.obj.refs += 1
            return self.obj.refs

        @REF
        def release(_this):
            self.obj.refs -= 1
            return self.obj.refs

        @GET_SERVICE
        def get_service(_this, requested, output):
            service_id = guid_text(requested[0])
            service = self.services.get(service_id)
            if service is None:
                output[0] = None
                return E_NOINTERFACE
            output[0] = service.pointer
            service.add_reference()
            emit("dependency_resolved", service=service.name, iid=service_id)
            return S_OK

        self.callbacks.extend((query, add_ref, release, get_service))
        for index, callback in enumerate(self.callbacks):
            self.vtable[index] = ctypes.cast(callback, ctypes.c_void_p)

    @property
    def pointer(self) -> ctypes.c_void_p:
        return ctypes.c_void_p(ctypes.addressof(self.obj))


def activate(clsid_text: str) -> ctypes.c_void_p:
    clsid = make_guid(clsid_text)
    iid = make_guid(IID_IVIRTUAL_DEVICE)
    output = ctypes.c_void_p()
    result = ole.CoCreateInstance(
        ctypes.byref(clsid), None, 1, ctypes.byref(iid), ctypes.byref(output)
    )
    if result:
        raise OSError(result & 0xFFFFFFFF, "CoCreateInstance(IID_IVirtualDevice)")
    return output


def read_dependencies(
    obj: ctypes.c_void_p,
    vtable: ctypes.POINTER(ctypes.c_void_p),
    repository: RecordingRepository,
) -> tuple[list[str], int]:
    count = wintypes.DWORD()
    required = wintypes.DWORD()
    entries = ctypes.c_void_p()
    method = ctypes.WINFUNCTYPE(
        ctypes.c_long,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )(vtable[3])
    result = method(
        obj,
        repository.pointer,
        ctypes.byref(count),
        ctypes.byref(entries),
        ctypes.byref(required),
    )
    if result < 0:
        raise RuntimeError(f"GetDependencies returned {hresult(result)}")
    if required.value > count.value or (count.value and not entries.value):
        raise RuntimeError(
            f"GetDependencies returned count={count.value} required={required.value} entries={entries.value}"
        )
    try:
        array = ctypes.cast(entries, ctypes.POINTER(GUID))
        return [guid_text(array[index]) for index in range(count.value)], required.value
    finally:
        if entries.value:
            ole.CoTaskMemFree(entries)


def run_child(kind: str, vm_id: str) -> int:
    spec = DEVICES[kind]
    identities = verify_identities(kind)
    emit("identities_verified", kind=kind, files=identities)
    expected_module_path, _ = guarded_path(spec.module)
    owner = None
    obj = None
    initialized = False
    ole.CoInitializeEx(None, 0)
    try:
        if spec.owner_partition:
            owner = OwnerPartition(vm_id)
        obj = activate(spec.clsid)
        vtable = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
        observed_rvas = []
        for slot in range(3, 6):
            module, rva = module_and_rva(int(vtable[slot] or 0))
            if os.path.normcase(os.path.abspath(module)) != os.path.normcase(
                os.path.abspath(expected_module_path)
            ):
                raise RuntimeError(f"IVirtualDevice slot {slot} came from {module}")
            observed_rvas.append(rva)
        if tuple(observed_rvas) != spec.vtable_rvas:
            raise RuntimeError(
                "IVirtualDevice slot RVAs changed: "
                f"observed={observed_rvas} expected={spec.vtable_rvas}"
            )
        emit("vtable_verified", module=spec.module, slots_3_to_5=observed_rvas)

        for interface_name, interface_id in spec.provided_interfaces:
            interface = ctypes.c_void_p()
            query_result = QI(vtable[0])(
                obj, ctypes.byref(make_guid(interface_id)), ctypes.byref(interface)
            )
            if query_result < 0 or not interface.value:
                raise RuntimeError(
                    f"QueryInterface({interface_name}) returned {hresult(query_result)}"
                )
            interface_vtable = ctypes.cast(
                interface, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))
            )[0]
            REF(interface_vtable[2])(interface)
            emit(
                "provided_interface_verified",
                name=interface_name,
                iid=interface_id,
            )

        repository = RecordingRepository(spec.clsid, vm_id, spec.xml)
        observed_dependencies, observed_required = read_dependencies(obj, vtable, repository)
        expected_dependencies = [item.iid for item in spec.dependencies]
        if observed_dependencies != expected_dependencies:
            raise RuntimeError(
                f"dependency list changed: observed={observed_dependencies} expected={expected_dependencies}"
            )
        expected_required = sum(item.required for item in spec.dependencies)
        if observed_required != expected_required:
            raise RuntimeError(
                "required dependency count changed: "
                f"observed={observed_required} expected={expected_required}"
            )
        emit(
            "dependencies_verified",
            dependencies=[
                {"name": item.name, "iid": item.iid, "required": item.required}
                for item in spec.dependencies
            ],
            required=observed_required,
        )

        services = RecordingServices(spec.dependencies)
        initialize = ctypes.WINFUNCTYPE(
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.c_void_p,
        )(vtable[4])
        initialize_result = initialize(obj, repository.pointer, 0, services.pointer)
        emit("initialize", kind=kind, result=hresult(initialize_result))
        if initialize_result < 0:
            raise RuntimeError(f"Initialize returned {hresult(initialize_result)}")
        initialized = True

        teardown = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)(vtable[5])
        teardown_result = teardown(obj)
        initialized = False
        emit("teardown", kind=kind, result=hresult(teardown_result))
        if teardown_result < 0:
            raise RuntimeError(f"Teardown returned {hresult(teardown_result)}")
        if tuple(repository.calls) != spec.repository_calls:
            raise RuntimeError(
                "repository calls changed: "
                f"observed={repository.calls} expected={spec.repository_calls}"
            )
        service_calls = {
            service.name: service.calls
            for service in services.services.values()
            if service.calls
        }
        expected_service_calls = {
            name: list(slots) for name, slots in spec.service_calls
        }
        if service_calls != expected_service_calls:
            raise RuntimeError(
                f"service callbacks changed: observed={service_calls} expected={expected_service_calls}"
            )
        if services.obj.refs != 1 or any(
            service.obj.refs != 1 for service in services.services.values()
        ):
            raise RuntimeError("dependency references were not released by Teardown")
        emit(
            "result",
            kind=kind,
            passed=True,
            initialize="S_OK",
            teardown="S_OK",
            repository_calls=repository.calls,
            service_calls=service_calls,
            partition_id=(f"0x{owner.partition_id:X}" if owner else None),
        )
        return 0
    except BaseException as error:
        emit("result", kind=kind, passed=False, error=f"{type(error).__name__}: {error}")
        return 1
    finally:
        if initialized and obj is not None:
            try:
                vtable = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
                ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)(vtable[5])(obj)
            except BaseException:
                pass
        if obj is not None:
            vtable = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
            REF(vtable[2])(obj)
        if owner is not None:
            owner.close()
        ole.CoUninitialize()


def parse_json_lines(output: str | bytes) -> list[object]:
    if isinstance(output, bytes):
        output = output.decode(errors="replace")
    events: list[object] = []
    for line in output.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"event": "unparsed_output", "text": line})
    return events


def run_parent() -> int:
    verify_contract_file()
    children = []
    passed = True
    for kind in DEVICES:
        vm_id = "{" + str(uuid.uuid4()).upper() + "}"
        command = [
            sys.executable,
            str(pathlib.Path(__file__).resolve()),
            "--child",
            kind,
            "--vm-id",
            vm_id,
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=CHILD_TIMEOUT_SECONDS,
                check=False,
            )
            events = parse_json_lines(completed.stdout)
            child_passed = completed.returncode == 0 and any(
                isinstance(event, dict)
                and event.get("event") == "result"
                and event.get("passed") is True
                for event in events
            )
            children.append(
                {
                    "kind": kind,
                    "returncode": completed.returncode,
                    "timed_out": False,
                    "passed": child_passed,
                    "events": events,
                    "stderr": completed.stderr.splitlines(),
                }
            )
        except subprocess.TimeoutExpired as error:
            child_passed = False
            children.append(
                {
                    "kind": kind,
                    "returncode": None,
                    "timed_out": True,
                    "passed": False,
                    "events": parse_json_lines(error.stdout or ""),
                    "stderr": (error.stderr or "").splitlines(),
                }
            )
        passed &= child_passed
    print(
        json.dumps(
            {
                "probe": "inbox_vdev_initialization",
                "deadline_seconds_per_child": CHILD_TIMEOUT_SECONDS,
                "passed": passed,
                "children": children,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity-only", action="store_true")
    parser.add_argument("--contract-only", action="store_true")
    parser.add_argument("--check-contract", action="store_true")
    parser.add_argument("--child", choices=tuple(DEVICES), help=argparse.SUPPRESS)
    parser.add_argument("--vm-id", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error("the guarded interfaces require 64-bit Python")
    if sum((args.identity_only, args.contract_only, args.check_contract)) > 1:
        parser.error("select at most one read-only mode")
    if args.contract_only:
        print(json.dumps(contract_manifest(), indent=2) + "\n", end="")
        return 0
    if args.check_contract:
        verify_contract_file()
        print(json.dumps({"contract": str(CONTRACT_PATH), "current": True}, indent=2))
        return 0
    if args.identity_only:
        verify_contract_file()
        print(
            json.dumps(
                {"contract": str(CONTRACT_PATH), "identities": verify_identities()},
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.child:
        if not args.vm_id:
            parser.error("--child requires --vm-id")
        try:
            vm_id = "{" + str(uuid.UUID(args.vm_id)).upper() + "}"
        except ValueError as error:
            parser.error(str(error))
        return run_child(args.child, vm_id)
    if args.vm_id:
        parser.error("--vm-id is internal to child mode")
    return run_parent()


if __name__ == "__main__":
    raise SystemExit(main())
