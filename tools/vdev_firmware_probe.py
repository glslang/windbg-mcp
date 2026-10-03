"""Build and apply the diskless inbox UEFI boot state without starting a VP.

This is the K1.3 preflight from FOLLOWUPS.md item 110.  Each bounded child
creates a fresh owner partition, composes the six-device graph, supplies the
minimum firmware-time services, powers the five devices that do not require a
storage LUN, and applies the UEFI register state to VP0.  It deliberately does
not start the VP or claim that firmware executed.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from ctypes import wintypes

import vdev_graph_probe as graph
import vdev_initialization_probe as contract


CHILD_TIMEOUT_SECONDS = 45
REPETITIONS = 3
POWERED_DEVICES = graph.GRAPH_ORDER[:-1]
BOOT_MEMORY_RANGES = tuple((start, size) for _name, start, size in graph.RAM_SPANS)
POWER_LIFECYCLE_RVAS = {
    "vmbus": (0x146B0, 0x145B0),
    "ioapic": (0x781D0, 0x77E80),
    "bios": (0x8900, 0x47AA0),
    "rtc": (0x7D210, 0x7D170),
    "guest": (0x6A1F0, 0x69A10),
    "synthstor": (0x1E970, 0x1D410),
}
EXPECTED_IMPORTS = (
    (0x100, 0x600, 1, 0x600000),
    (0x700, 6, 1, 0x6000),
    (0x706, 1, 1, 24),
    (0x707, 2, 1, 0),
    (0x709, 1, 1, 704),
)
EXPECTED_REGISTERS = (
    0x70001,
    0x60003,
    0x60000,
    0x60004,
    0x60005,
    0x60002,
    0x60001,
    0x40000,
    0x40002,
    0x40003,
    0x80001,
    0x80004,
    0x20011,
    0x20005,
    0x20010,
    0x20008,
    0x20009,
    0x2000A,
    0x2000B,
)
SCALAR_REGISTERS = {
    0x40000: ("cr0", 0x80000023),
    0x40002: ("cr3", 0x700000),
    0x40003: ("cr4", 0x660),
    0x80001: ("efer", 0xD00),
    0x80004: ("pat", 0x7040600070406),
    0x20011: ("rflags", 2),
    0x20005: ("rbp", 0x6E0000),
}
E_INVALIDARG = -2147024809
E_OUTOFMEMORY = -2147024882
E_UNEXPECTED = -2147418113


def emit(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def acpi_table(signature: bytes, revision: int, body: bytes) -> bytes:
    """Build one checksummed ACPI table with the measured Hyper-V OEM fields."""

    if len(signature) != 4:
        raise ValueError("an ACPI signature is exactly four bytes")
    header = struct.pack(
        "<4sIBB6s8sI4sI",
        signature,
        36 + len(body),
        revision,
        0,
        b"VRTUAL",
        b"MICROSOFT",
        1,
        b"MSFT",
        1,
    )
    table = bytearray(header + body)
    table[9] = (-sum(table)) & 0xFF
    return bytes(table)


def firmware_acpi_tables() -> dict[str, bytes]:
    madt = acpi_table(
        b"APIC",
        4,
        struct.pack("<II", 0xFEE00000, 0)
        + struct.pack("<BBBBIH", 2, 10, 0, 9, 9, 0x000D)
        + struct.pack("<BBBBH", 4, 6, 1, 0, 0)
        + struct.pack("<BBBBII", 1, 12, 0, 0, 0xFEC00000, 0)
        + struct.pack("<BBBBI", 0, 8, 1, 0, 1),
    )
    srat = acpi_table(
        b"SRAT",
        2,
        bytes(12)
        + struct.pack("<BBBBIB3sI", 0, 16, 0, 0, 1, 0, bytes(3), 0)
        + struct.pack("<BBIHQQIIQ", 1, 40, 0, 0, 0, 0xF8000000, 0, 1, 0)
        + struct.pack(
            "<BBIHQQIIQ", 1, 40, 0, 0, 0x100000000, 0x8000000, 0, 1, 0
        ),
    )
    return {"madt": madt, "srat": srat, "slit": b"", "pptt": b""}


def encode_boot_memory_range(index: int) -> bytes:
    """Encode one IVmBootMemoryTopology range in bytes, as UEFI consumes it."""

    if index < 0 or index >= len(BOOT_MEMORY_RANGES):
        raise IndexError(index)
    start, length = BOOT_MEMORY_RANGES[index]
    return struct.pack(
        "<IIIIQQ",
        index,
        int(index + 1 == len(BOOT_MEMORY_RANGES)),
        0,
        0,
        start,
        length,
    )


@dataclass(frozen=True)
class ImportedPages:
    gpa_page: int
    page_count: int
    page_kind: int
    data_size: int
    sha256: str
    readback: bool


@dataclass
class FirmwareState:
    topology: graph.WindowsRamTopology | None = None
    imports: list[ImportedPages] = field(default_factory=list)
    registers: list[tuple[int, int, bytes]] = field(default_factory=list)
    callback_errors: list[str] = field(default_factory=list)
    callbacks: list[object] = field(default_factory=list)

    def fail_callback(self, name: str, error: BaseException) -> int:
        detail = f"{name}: {type(error).__name__}: {error}"
        self.callback_errors.append(detail)
        emit("firmware_callback_error", callback=name, error=detail)
        return E_UNEXPECTED


def verify_power_vtable(
    kind: str, obj: ctypes.c_void_p
) -> ctypes.POINTER(ctypes.c_void_p):
    vtable = graph.vtable_of(obj)
    expected_path, _ = contract.guarded_path(contract.DEVICES[kind].module)
    observed = []
    for slot in (10, 12):
        module, rva = contract.module_and_rva(int(vtable[slot] or 0))
        if pathlib.Path(module).resolve() != expected_path.resolve():
            raise RuntimeError(f"{kind} power slot {slot} came from {module}")
        observed.append(rva)
    if tuple(observed) != POWER_LIFECYCLE_RVAS[kind]:
        raise RuntimeError(
            f"{kind} power vtable changed: observed={observed} "
            f"expected={POWER_LIFECYCLE_RVAS[kind]}"
        )
    emit("power_vtable_verified", kind=kind, slots={"10": observed[0], "12": observed[1]})
    return vtable


def required_dependencies() -> tuple[contract.Dependency, ...]:
    return tuple(item for item in graph.unique_dependencies() if item.required)


def install_firmware_services(
    services: contract.RecordingServices, state: FirmwareState
) -> dict[str, bytes]:
    """Replace the recovered firmware-time service slots with typed callbacks."""

    tables = firmware_acpi_tables()
    contract.ole.CoTaskMemAlloc.argtypes = [ctypes.c_size_t]
    contract.ole.CoTaskMemAlloc.restype = ctypes.c_void_p

    def install(name: str, slot: int, callback: object) -> None:
        matches = [item for item in services.services.values() if item.name == name]
        if len(matches) != 1 or not isinstance(matches[0], contract.RecordingService):
            raise RuntimeError(f"expected one recording service named {name}")
        service = matches[0]
        service.callbacks.append(callback)
        service.vtable[slot] = ctypes.cast(callback, ctypes.c_void_p)
        state.callbacks.append(callback)

    def record(name: str, slot: int) -> None:
        service = next(item for item in services.services.values() if item.name == name)
        service.calls.append(slot)

    blob_type = ctypes.WINFUNCTYPE(
        ctypes.c_long,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_void_p),
    )

    def blob(name: str, slot: int, payload: bytes) -> None:
        @blob_type
        def callback(_this, size, data):
            try:
                record(name, slot)
                if payload:
                    allocation = contract.ole.CoTaskMemAlloc(len(payload))
                    if not allocation:
                        return E_OUTOFMEMORY
                    ctypes.memmove(allocation, payload, len(payload))
                    size[0] = len(payload)
                    data[0] = allocation
                else:
                    size[0] = 0
                    data[0] = None
                emit("firmware_service", service=name, slot=slot, size=len(payload))
                return contract.S_OK
            except BaseException as error:
                return state.fail_callback(f"{name}[{slot}]", error)

        install(name, slot, callback)

    blob("IVmMemoryTopology", 3, tables["srat"])
    blob("IVmMemoryTopology", 11, tables["madt"])
    blob("IVmMemoryTopology", 13, tables["slit"])
    blob("IVmMemoryTopology", 14, tables["pptt"])

    mmio_type = ctypes.WINFUNCTYPE(
        ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)
    )

    @mmio_type
    def mmio_ranges(_this, output):
        try:
            record("IVmMemoryTopology", 4)
            ranges = (0xF8000, 0x8000, 0xFE0000, 0x20000)
            for index, value in enumerate(ranges):
                output[index] = value
            emit("firmware_service", service="IVmMemoryTopology", slot=4, ranges=ranges)
            return contract.S_OK
        except BaseException as error:
            return state.fail_callback("IVmMemoryTopology[4]", error)

    install("IVmMemoryTopology", 4, mmio_ranges)

    u32_type = ctypes.WINFUNCTYPE(
        ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)
    )

    def u32_value(name: str, slot: int, value: int) -> None:
        @u32_type
        def callback(_this, output):
            try:
                record(name, slot)
                output[0] = value
                emit("firmware_service", service=name, slot=slot, value=value)
                return contract.S_OK
            except BaseException as error:
                return state.fail_callback(f"{name}[{slot}]", error)

        install(name, slot, callback)

    u32_value("IVmMemoryTopology", 7, 1)
    u32_value("IVmMemoryTopology", 10, 1)
    u32_value("IVmProcessorServices", 3, 1)
    u32_value("IVmBootStateImporter", 6, 0)
    u32_value("IVmMemoryManagement", 14, 0)
    u32_value("ISecurityManager", 15, 0)

    import_pages_type = ctypes.WINFUNCTYPE(
        ctypes.c_long,
        ctypes.c_void_p,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint64,
    )

    @import_pages_type
    def import_pages(_this, gpa_page, page_count, page_kind, data, data_size):
        try:
            record("IVmBootStateImporter", 4)
            total_size = page_count * graph.PAGE_SIZE
            if not page_count or data_size > total_size or (data_size and not data):
                return E_INVALIDARG
            end_page = gpa_page + page_count
            if any(
                gpa_page < item.gpa_page + item.page_count
                and item.gpa_page < end_page
                for item in state.imports
            ):
                return E_INVALIDARG
            if state.topology is None:
                return E_UNEXPECTED
            payload = ctypes.string_at(data, data_size) if data_size else b""
            state.topology.write_pages(gpa_page, page_count, payload)
            expected = payload + bytes(total_size - len(payload))
            observed = state.topology.read_page_bytes(gpa_page, page_count)
            readback = observed == expected
            if not readback:
                return E_UNEXPECTED
            imported = ImportedPages(
                gpa_page,
                page_count,
                page_kind,
                data_size,
                hashlib.sha256(payload).hexdigest().upper(),
                readback,
            )
            state.imports.append(imported)
            emit(
                "firmware_page_import",
                gpa_page=f"0x{gpa_page:X}",
                page_count=page_count,
                page_kind=page_kind,
                data_size=data_size,
                sha256=imported.sha256,
                readback=readback,
            )
            return contract.S_OK
        except (ValueError, OverflowError):
            return E_INVALIDARG
        except BaseException as error:
            return state.fail_callback("IVmBootStateImporter[4]", error)

    install("IVmBootStateImporter", 4, import_pages)

    import_register_type = ctypes.WINFUNCTYPE(
        ctypes.c_long,
        ctypes.c_void_p,
        ctypes.c_uint8,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )

    @import_register_type
    def import_register(_this, vp_index, register_name, value):
        try:
            record("IVmBootStateImporter", 5)
            if not value:
                return E_INVALIDARG
            register_value = ctypes.string_at(value, 16)
            state.registers.append((vp_index, register_name, register_value))
            emit(
                "firmware_register_import",
                vp_index=vp_index,
                register_name=f"0x{register_name:X}",
                register_value=register_value.hex(),
            )
            return contract.S_OK
        except BaseException as error:
            return state.fail_callback("IVmBootStateImporter[5]", error)

    install("IVmBootStateImporter", 5, import_register)

    ram_range_type = ctypes.WINFUNCTYPE(
        ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p
    )

    @ram_range_type
    def ram_range(_this, output):
        try:
            record("IVmBootMemoryTopology", 6)
            if not output:
                return E_INVALIDARG
            index = ctypes.c_uint32.from_address(output).value
            if index >= len(BOOT_MEMORY_RANGES):
                return E_INVALIDARG
            start, length = BOOT_MEMORY_RANGES[index]
            value = encode_boot_memory_range(index)
            ctypes.memmove(output, value, len(value))
            emit(
                "firmware_service",
                service="IVmBootMemoryTopology",
                slot=6,
                index=index,
                start_byte=f"0x{start:X}",
                length_bytes=length,
            )
            return contract.S_OK
        except BaseException as error:
            return state.fail_callback("IVmBootMemoryTopology[6]", error)

    install("IVmBootMemoryTopology", 6, ram_range)

    simple_type = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)

    @simple_type
    def power_management_device(_this):
        try:
            record("IVmPowerManagementDevice", 3)
            emit("firmware_service", service="IVmPowerManagementDevice", slot=3)
            return contract.S_OK
        except BaseException as error:
            return state.fail_callback("IVmPowerManagementDevice[3]", error)

    install("IVmPowerManagementDevice", 3, power_management_device)
    return tables


def validate_imported_boot_state(state: FirmwareState) -> dict[str, object]:
    if state.callback_errors:
        raise RuntimeError("firmware callbacks failed: " + "; ".join(state.callback_errors))
    observed_imports = tuple(
        (item.gpa_page, item.page_count, item.page_kind, item.data_size)
        for item in state.imports
    )
    if observed_imports != EXPECTED_IMPORTS:
        raise RuntimeError(
            f"firmware page imports changed: {observed_imports} != {EXPECTED_IMPORTS}"
        )
    register_names = tuple(name for _vp, name, _value in state.registers)
    if register_names != EXPECTED_REGISTERS:
        raise RuntimeError(
            f"firmware register imports changed: {register_names} != {EXPECTED_REGISTERS}"
        )
    if any(vp != 0 for vp, _name, _value in state.registers):
        raise RuntimeError("firmware supplied boot state for a nonzero VP")
    values = {name: int.from_bytes(value[:8], "little") for _vp, name, value in state.registers}
    for name, (label, expected) in SCALAR_REGISTERS.items():
        if values[name] != expected:
            raise RuntimeError(
                f"firmware {label} changed: 0x{values[name]:X} != 0x{expected:X}"
            )
    rip = values[0x20010]
    if not 0x100000 <= rip < 0x700000:
        raise RuntimeError(f"firmware RIP 0x{rip:X} is outside the imported UEFI image")
    return {
        "rip": f"0x{rip:X}",
        **{
            label: f"0x{values[name]:X}"
            for name, (label, _expected) in SCALAR_REGISTERS.items()
        },
    }


def apply_register_state(
    owner: contract.OwnerPartition, state: FirmwareState
) -> dict[str, object]:
    registers = state.registers
    names = (ctypes.c_uint32 * len(registers))(
        *(register_name for _vp, register_name, _value in registers)
    )
    values = (ctypes.c_ubyte * (16 * len(registers)))()
    for index, (_vp, _register_name, value) in enumerate(registers):
        ctypes.memmove(ctypes.addressof(values) + index * 16, value, 16)
    signature = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint8,
        ctypes.c_void_p,
    ]
    set_state = owner.module.VidSetVirtualProcessorStateEx
    set_state.argtypes = signature
    set_state.restype = wintypes.BOOL
    if not set_state(owner.handle, 0, 0x10, names, len(registers), values):
        raise ctypes.WinError(ctypes.get_last_error(), "VidSetVirtualProcessorStateEx")
    get_state = owner.module.VidGetVirtualProcessorStateEx
    get_state.argtypes = signature
    get_state.restype = wintypes.BOOL
    observed = (ctypes.c_ubyte * len(values))()
    if not get_state(owner.handle, 0, 0x10, names, len(registers), observed):
        raise ctypes.WinError(ctypes.get_last_error(), "VidGetVirtualProcessorStateEx")
    expected_bytes = bytes(values)
    observed_bytes = bytes(observed)
    normalized = []
    normalization = {}
    for index, (_vp, name, _value) in enumerate(registers):
        start = index * 16
        if expected_bytes[start : start + 16] != observed_bytes[start : start + 16]:
            normalized.append(f"0x{name:X}")
            normalization[f"0x{name:X}"] = {
                "imported": expected_bytes[start : start + 16].hex(),
                "readback": observed_bytes[start : start + 16].hex(),
            }
    canonical_bytes = bytearray(expected_bytes)
    cr0_offset = EXPECTED_REGISTERS.index(0x40000) * 16
    canonical_cr0 = int.from_bytes(
        canonical_bytes[cr0_offset : cr0_offset + 8], "little"
    ) | 0x10
    canonical_bytes[cr0_offset : cr0_offset + 8] = canonical_cr0.to_bytes(8, "little")
    if observed_bytes != bytes(canonical_bytes):
        raise RuntimeError(
            "VID register readback differed beyond the fixed CR0.ET canonicalization: "
            + json.dumps(normalization, sort_keys=True)
        )
    for name in (*SCALAR_REGISTERS, 0x20010):
        index = EXPECTED_REGISTERS.index(name)
        start = index * 16
        imported_scalar = int.from_bytes(expected_bytes[start : start + 8], "little")
        expected_scalar = imported_scalar | 0x10 if name == 0x40000 else imported_scalar
        observed_scalar = int.from_bytes(observed_bytes[start : start + 8], "little")
        if expected_scalar != observed_scalar:
            raise RuntimeError(
                f"VID changed scalar register 0x{name:X} during readback: "
                f"0x{imported_scalar:X} -> 0x{observed_scalar:X}"
            )
    result = {
        "count": len(registers),
        "exact_readback": expected_bytes == observed_bytes,
        "normalized_registers": normalized,
        "normalization": normalization,
        "critical_scalars_match": True,
    }
    emit("firmware_register_state_applied", **result)
    return result


def call_lifecycle(result: int, operation: str) -> None:
    emit("lifecycle", operation=operation, result=contract.hresult(result))
    if result < 0:
        raise RuntimeError(f"{operation} returned {contract.hresult(result)}")


def run_child(vm_id: str, iteration: int) -> int:
    objects: dict[str, ctypes.c_void_p] = {}
    vtables: dict[str, ctypes.POINTER(ctypes.c_void_p)] = {}
    repositories: dict[str, contract.RecordingRepository] = {}
    provided: dict[str, contract.ComInterfaceService] = {}
    initialized: list[str] = []
    reserving: list[str] = []
    reserved: list[str] = []
    powered: list[str] = []
    services = None
    owner = None
    topology = None
    state = FirmwareState()
    initialize_type = ctypes.WINFUNCTYPE(
        ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p
    )
    start_reserving_type = ctypes.WINFUNCTYPE(
        ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD
    )
    finish_reserving_type = ctypes.WINFUNCTYPE(
        ctypes.c_long, ctypes.c_void_p, wintypes.DWORD
    )
    free_resources_type = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
    teardown_type = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
    power_type = ctypes.WINFUNCTYPE(
        ctypes.c_long, ctypes.c_void_p, wintypes.DWORD
    )
    contract.ole.CoInitializeEx(None, 0)
    try:
        identities = contract.verify_identities()
        emit("identities_verified", files=identities)
        owner = contract.OwnerPartition(vm_id)
        for kind in graph.GRAPH_ORDER:
            spec = contract.DEVICES[kind]
            obj = contract.activate(spec.clsid)
            objects[kind] = obj
            graph.verify_vtable(kind, obj)
            vtables[kind] = verify_power_vtable(kind, obj)
            repositories[kind] = contract.RecordingRepository(
                spec.clsid, vm_id, spec.xml
            )
        provided = graph.query_provided_interfaces(objects)
        services = contract.RecordingServices(required_dependencies(), provided)
        optional_iids = {
            item.iid for item in graph.unique_dependencies() if not item.required
        }
        if optional_iids & services.services.keys():
            raise RuntimeError("an optional firmware service was installed")
        tables = install_firmware_services(services, state)

        for kind in graph.GRAPH_ORDER:
            call_lifecycle(
                initialize_type(vtables[kind][4])(
                    objects[kind], repositories[kind].pointer, 0, services.pointer
                ),
                f"initialize:{kind}",
            )
            initialized.append(kind)
        for kind in graph.GRAPH_ORDER:
            call_lifecycle(
                start_reserving_type(vtables[kind][6])(objects[kind], None, 0),
                f"start_reserving_resources:{kind}",
            )
            reserving.append(kind)

        topology = graph.WindowsRamTopology(owner)
        state.topology = topology
        memory_info_devices = graph.notify_ram_construction_complete(objects)
        for kind in graph.GRAPH_ORDER:
            call_lifecycle(
                finish_reserving_type(vtables[kind][7])(objects[kind], 0),
                f"finish_reserving_resources:{kind}",
            )
            reserving.remove(kind)
            reserved.append(kind)

        for kind in POWERED_DEVICES:
            call_lifecycle(
                power_type(vtables[kind][10])(objects[kind], 0),
                f"power_on_cold:{kind}",
            )
            powered.append(kind)

        boot_state = validate_imported_boot_state(state)
        register_readback = apply_register_state(owner, state)

        while powered:
            kind = powered.pop()
            call_lifecycle(
                power_type(vtables[kind][12])(objects[kind], 0),
                f"power_off:{kind}",
            )
        while reserved:
            kind = reserved.pop()
            call_lifecycle(
                free_resources_type(vtables[kind][8])(objects[kind]),
                f"free_reserved_resources:{kind}",
            )
        while initialized:
            kind = initialized.pop()
            call_lifecycle(
                teardown_type(vtables[kind][5])(objects[kind]), f"teardown:{kind}"
            )

        for service in provided.values():
            service.close()
        provided.clear()
        for kind in reversed(graph.GRAPH_ORDER):
            contract.REF(vtables[kind][2])(objects.pop(kind))
        if services.obj.refs != 1:
            raise RuntimeError("a device retained IVirtualDeviceServices")
        for service in services.services.values():
            if isinstance(service, contract.RecordingService) and service.obj.refs != 1:
                raise RuntimeError(f"a device retained {service.name}")
        for kind in graph.GRAPH_ORDER:
            if repositories[kind].obj.refs != 1:
                raise RuntimeError(f"{kind} retained its repository after destruction")

        topology_description = topology.describe()
        topology.close()
        topology = None
        state.topology = None
        emit(
            "result",
            passed=True,
            iteration=iteration,
            partition_id=f"0x{owner.partition_id:X}",
            initialized=list(graph.GRAPH_ORDER),
            powered=list(POWERED_DEVICES),
            synthstor_powered=False,
            vp_started=False,
            acpi={
                name: {"bytes": len(value), "checksum": sum(value) & 0xFF}
                for name, value in tables.items()
            },
            imports=[item.__dict__ for item in state.imports],
            boot_state=boot_state,
            register_readback=register_readback,
            ram_topology=topology_description,
            ram_construction_complete={
                "issued": True,
                "notified": memory_info_devices,
            },
        )
        return 0
    except BaseException as error:
        emit(
            "result",
            passed=False,
            iteration=iteration,
            error=f"{type(error).__name__}: {error}",
            callback_errors=state.callback_errors,
        )
        return 1
    finally:
        while powered:
            kind = powered.pop()
            try:
                power_type(vtables[kind][12])(objects[kind], 0)
            except BaseException:
                pass
        while reserving:
            kind = reserving.pop()
            try:
                if finish_reserving_type(vtables[kind][7])(objects[kind], 1) >= 0:
                    free_resources_type(vtables[kind][8])(objects[kind])
            except BaseException:
                pass
        while reserved:
            kind = reserved.pop()
            try:
                free_resources_type(vtables[kind][8])(objects[kind])
            except BaseException:
                pass
        while initialized:
            kind = initialized.pop()
            try:
                teardown_type(vtables[kind][5])(objects[kind])
            except BaseException:
                pass
        for service in provided.values():
            try:
                service.close()
            except BaseException:
                pass
        for kind in reversed(graph.GRAPH_ORDER):
            obj = objects.get(kind)
            if obj is not None:
                try:
                    contract.REF(vtables[kind][2])(obj)
                except BaseException:
                    pass
        if topology is not None:
            try:
                topology.close()
            except BaseException:
                pass
        if owner is not None:
            owner.close()
        contract.ole.CoUninitialize()


def parse_json_lines(output: str | bytes) -> list[object]:
    if isinstance(output, bytes):
        output = output.decode(errors="replace")
    events = []
    for line in output.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"event": "unparsed_output", "text": line})
    return events


def run_parent() -> int:
    contract.verify_contract_file()
    children = []
    passed = True
    for iteration in range(1, REPETITIONS + 1):
        vm_id = "{" + str(uuid.uuid4()).upper() + "}"
        command = [
            sys.executable,
            str(pathlib.Path(__file__).resolve()),
            "--child",
            "--vm-id",
            vm_id,
            "--iteration",
            str(iteration),
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
                    "iteration": iteration,
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
                    "iteration": iteration,
                    "returncode": None,
                    "timed_out": True,
                    "passed": False,
                    "events": parse_json_lines(error.stdout or ""),
                    "stderr": parse_json_lines(error.stderr or ""),
                }
            )
        passed &= child_passed
    print(
        json.dumps(
            {
                "probe": "inbox_vdev_diskless_firmware_preflight",
                "scope": "uefi_boot_state_import_and_apply_without_vp_start",
                "deadline_seconds_per_child": CHILD_TIMEOUT_SECONDS,
                "repetitions": REPETITIONS,
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
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--vm-id", help=argparse.SUPPRESS)
    parser.add_argument("--iteration", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error("the guarded interfaces require 64-bit Python")
    if args.child:
        if not args.vm_id or args.iteration is None:
            parser.error("--child requires --vm-id and --iteration")
        try:
            vm_id = "{" + str(uuid.UUID(args.vm_id)).upper() + "}"
        except ValueError as error:
            parser.error(str(error))
        return run_child(vm_id, args.iteration)
    if args.vm_id or args.iteration is not None:
        parser.error("child arguments are internal")
    return run_parent()


if __name__ == "__main__":
    raise SystemExit(main())
