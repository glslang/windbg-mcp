"""Compose the six minimum inbox devices in one owner-created VID partition.

This is the composition and lifecycle subgate of K1.2 from FOLLOWUPS.md item
110.  Each child
creates one fresh partition, activates all six devices, supplies the concrete
VMBus, BIOS, and IOAPIC interfaces to their consumers, initializes in dependency
order, installs the measured fixed 4 GiB Windows RAM topology, mirrors the
recovered RAM-construction-complete query loop, and tears down in reverse
order.  The parent requires three clean runs.

The probe intentionally does not start a VP or execute firmware.  Those remain
later gates.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import pathlib
import struct
import subprocess
import sys
import uuid
from ctypes import wintypes

import vdev_initialization_probe as contract


CHILD_TIMEOUT_SECONDS = 30
GRAPH_ORDER = ("vmbus", "ioapic", "bios", "rtc", "guest", "synthstor")
REPETITIONS = 3
PAGE_SIZE = 4096
VSM_CONFIG_BYTES = 24
MEMORY_BLOCK_VA_BACKED = 0x08
MEMORY_BLOCK_VSM_CAPABLE = 0x01
GPA_RANGE_APPLY_VTL_PROTECTIONS = 0x08
RAM_SPANS = (
    ("low", 0x000000000, 0x0F8000000),
    ("high", 0x100000000, 0x008000000),
)


def emit(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def unique_dependencies() -> tuple[contract.Dependency, ...]:
    by_iid: dict[str, contract.Dependency] = {}
    for kind in GRAPH_ORDER:
        for item in contract.DEVICES[kind].dependencies:
            previous = by_iid.get(item.iid)
            if previous is not None and previous.name != item.name:
                raise RuntimeError(
                    f"dependency name mismatch for {item.iid}: "
                    f"{previous.name} != {item.name}"
                )
            by_iid.setdefault(item.iid, item)
    return tuple(by_iid.values())


def vtable_of(pointer: ctypes.c_void_p) -> ctypes.POINTER(ctypes.c_void_p):
    return ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]


def verify_vtable(kind: str, obj: ctypes.c_void_p) -> ctypes.POINTER(ctypes.c_void_p):
    spec = contract.DEVICES[kind]
    expected_path, _ = contract.guarded_path(spec.module)
    vtable = vtable_of(obj)
    observed = []
    for slot in range(3, 6):
        module, rva = contract.module_and_rva(int(vtable[slot] or 0))
        if os.path.normcase(os.path.abspath(module)) != os.path.normcase(
            os.path.abspath(expected_path)
        ):
            raise RuntimeError(f"{kind} IVirtualDevice slot {slot} came from {module}")
        observed.append(rva)
    if tuple(observed) != spec.vtable_rvas:
        raise RuntimeError(
            f"{kind} vtable changed: observed={observed} expected={spec.vtable_rvas}"
        )
    emit("vtable_verified", kind=kind, module=spec.module, slots_3_to_5=observed)
    return vtable


class MemoryBlockDescriptor(ctypes.Structure):
    _fields_ = [("words", ctypes.c_uint64 * 14)]


class WindowsRamTopology:
    """Install the two RAM spans measured in the one-VP managed VBS capture."""

    def __init__(self, owner: contract.OwnerPartition) -> None:
        self.owner = owner
        self.blocks: list[int] = []
        self.ranges: list[int] = []
        self.mappings: list[int] = []

        module = owner.module
        self.set_vsm_config = module.VidVsmSetPartitionConfig
        self.set_vsm_config.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
        self.set_vsm_config.restype = wintypes.BOOL
        self.create_memory_block = module.VidCreateMemoryBlock
        self.create_memory_block.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(MemoryBlockDescriptor),
            ctypes.POINTER(ctypes.c_uint64),
        ]
        self.create_memory_block.restype = wintypes.BOOL
        self.destroy_memory_block = module.VidDestroyMemoryBlock
        self.destroy_memory_block.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        self.destroy_memory_block.restype = wintypes.BOOL
        self.create_gpa_range = module.VidCreateVaGpaRange
        self.create_gpa_range.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64),
        ]
        self.create_gpa_range.restype = wintypes.BOOL
        self.destroy_gpa_range = module.VidDestroyGpaRange
        self.destroy_gpa_range.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        self.destroy_gpa_range.restype = wintypes.BOOL
        self.map_pages = module.VidMapMemoryBlockPageRange
        self.map_pages.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_uint64,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint64),
        ]
        self.map_pages.restype = wintypes.BOOL
        self.unmap_pages = module.VidUnmapMemoryBlockPageRange
        self.unmap_pages.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        self.unmap_pages.restype = wintypes.BOOL
        self.read_pages = module.VidReadMemoryBlockPageRange
        self.read_pages.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_uint64,
        ]
        self.read_pages.restype = wintypes.BOOL
        self.setup_message_queue = module.VidSetupMessageQueue
        self.setup_message_queue.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        self.setup_message_queue.restype = wintypes.BOOL
        self.set_notification_queue = module.VidSetMemoryBlockNotificationQueue
        self.set_notification_queue.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.c_uint64,
        ]
        self.set_notification_queue.restype = wintypes.BOOL

        try:
            self._configure_vsm()
            self._check(
                self.setup_message_queue(self.owner.handle, 1),
                "VidSetupMessageQueue",
            )
            for index, (name, start, size) in enumerate(RAM_SPANS):
                self._create_span(index, name, start, size)
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass
            raise

    @staticmethod
    def _check(ok: int, operation: str) -> None:
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error(), operation)

    def _configure_vsm(self) -> None:
        config = ctypes.create_string_buffer(VSM_CONFIG_BYTES)
        struct.pack_into("<I", config, 0, 3)
        struct.pack_into("<I", config, 4, 0)
        struct.pack_into("<I", config, 12, 0xF)
        self._check(
            self.set_vsm_config(self.owner.handle, len(config), config),
            "VidVsmSetPartitionConfig",
        )
        ctypes.memset(config, 0, len(config))
        emit("vsm_configured", enabled_vtl_set=3, vtl1_default_protection=0xF)

    def _create_span(self, index: int, name: str, start: int, size: int) -> None:
        if start % PAGE_SIZE or size % PAGE_SIZE:
            raise RuntimeError(f"unaligned RAM span {name}")
        page_count = size // PAGE_SIZE
        descriptor = MemoryBlockDescriptor()
        descriptor.words[0] = page_count
        descriptor.words[1] = page_count
        descriptor.words[2] = MEMORY_BLOCK_VA_BACKED | MEMORY_BLOCK_VSM_CAPABLE
        block = ctypes.c_uint64()
        self._check(
            self.create_memory_block(
                self.owner.handle, ctypes.byref(descriptor), ctypes.byref(block)
            ),
            f"VidCreateMemoryBlock({name})",
        )
        self.blocks.append(block.value)
        self._check(
            self.set_notification_queue(self.owner.handle, block.value, 0),
            f"VidSetMemoryBlockNotificationQueue({name})",
        )

        gpa_range = ctypes.c_uint64()
        self._check(
            self.create_gpa_range(
                self.owner.handle,
                start // PAGE_SIZE,
                page_count,
                block.value,
                GPA_RANGE_APPLY_VTL_PROTECTIONS,
                ctypes.byref(gpa_range),
            ),
            f"VidCreateVaGpaRange({name})",
        )
        self.ranges.append(gpa_range.value)

        mapped = ctypes.c_void_p()
        mapping = ctypes.c_uint64()
        self._check(
            self.map_pages(
                self.owner.handle,
                block.value,
                0,
                1,
                2,
                ctypes.byref(mapped),
                ctypes.byref(mapping),
            ),
            f"VidMapMemoryBlockPageRange({name})",
        )
        self.mappings.append(mapping.value)
        marker = struct.pack("<QQ", 0x4B3152414D535041, index)
        ctypes.memmove(mapped, marker, len(marker))
        verify = ctypes.create_string_buffer(PAGE_SIZE)
        self._check(
            self.read_pages(
                self.owner.handle,
                block.value,
                0,
                1,
                verify,
                len(verify),
            ),
            f"VidReadMemoryBlockPageRange({name})",
        )
        if verify.raw[: len(marker)] != marker:
            raise RuntimeError(f"{name} RAM span readback changed")
        ctypes.memset(mapped, 0, len(marker))
        self._check(
            self.unmap_pages(self.owner.handle, mapping.value),
            f"VidUnmapMemoryBlockPageRange({name})",
        )
        self.mappings.pop()
        emit(
            "ram_span_created",
            name=name,
            start=f"0x{start:X}",
            size=f"0x{size:X}",
            pages=page_count,
            block=f"0x{block.value:X}",
            gpa_range=f"0x{gpa_range.value:X}",
            readback=True,
        )

    def describe(self) -> dict[str, object]:
        total = sum(size for _name, _start, size in RAM_SPANS)
        return {
            "source": "managed one-VP VBS checkpoint memory chunks",
            "page_size": PAGE_SIZE,
            "total_bytes": total,
            "hole": {"start": "0xF8000000", "size": "0x8000000"},
            "spans": [
                {
                    "name": name,
                    "start": f"0x{start:X}",
                    "size": f"0x{size:X}",
                    "pages": size // PAGE_SIZE,
                }
                for name, start, size in RAM_SPANS
            ],
        }

    def close(self) -> None:
        failures = []
        while self.mappings:
            mapping = self.mappings.pop()
            if not self.unmap_pages(self.owner.handle, mapping):
                failures.append(f"unmap 0x{mapping:X}: {ctypes.get_last_error()}")
        while self.ranges:
            gpa_range = self.ranges.pop()
            if not self.destroy_gpa_range(self.owner.handle, gpa_range):
                failures.append(f"destroy range 0x{gpa_range:X}: {ctypes.get_last_error()}")
        while self.blocks:
            block = self.blocks.pop()
            if not self.destroy_memory_block(self.owner.handle, block):
                failures.append(f"destroy block 0x{block:X}: {ctypes.get_last_error()}")
        if failures:
            raise RuntimeError("RAM topology cleanup failed: " + "; ".join(failures))
        emit("ram_topology_destroyed")


def query_provided_interfaces(
    objects: dict[str, ctypes.c_void_p],
) -> dict[str, contract.ComInterfaceService]:
    supplied: dict[str, contract.ComInterfaceService] = {}
    for kind in GRAPH_ORDER:
        spec = contract.DEVICES[kind]
        vtable = vtable_of(objects[kind])
        for name, iid in spec.provided_interfaces:
            pointer = ctypes.c_void_p()
            result = contract.QI(vtable[0])(
                objects[kind],
                ctypes.byref(contract.make_guid(iid)),
                ctypes.byref(pointer),
            )
            if result < 0 or not pointer.value:
                raise RuntimeError(
                    f"{kind} QueryInterface({name}) returned {contract.hresult(result)}"
                )
            supplied[iid.upper()] = contract.ComInterfaceService(name, iid, pointer)
            emit("provided_interface", kind=kind, name=name, iid=iid)
    return supplied


def expected_service_calls() -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for kind in GRAPH_ORDER:
        for name, slots in contract.DEVICES[kind].service_calls:
            result.setdefault(name, []).extend(slots)
    return result


def notify_ram_construction_complete(
    objects: dict[str, ctypes.c_void_p],
) -> list[dict[str, object]]:
    """Mirror VirtualMotherboard::NotifyAllDevicesRamConstructionComplete."""
    interface_id = contract.make_guid(contract.IID_IVIRTUAL_DEVICE_MEMORY_INFO)
    notify_type = ctypes.WINFUNCTYPE(
        ctypes.c_long, ctypes.c_void_p, wintypes.DWORD
    )
    notified = []
    for kind in GRAPH_ORDER:
        interface = ctypes.c_void_p()
        vtable = vtable_of(objects[kind])
        query_result = contract.QI(vtable[0])(
            objects[kind], ctypes.byref(interface_id), ctypes.byref(interface)
        )
        if query_result & 0xFFFFFFFF == contract.E_NOINTERFACE:
            emit("ram_construction_complete", kind=kind, supported=False)
            continue
        if query_result < 0 or not interface.value:
            raise RuntimeError(
                f"{kind} QueryInterface(IVirtualDeviceMemoryInfo) returned "
                f"{contract.hresult(query_result)}"
            )
        interface_vtable = vtable_of(interface)
        module, rva = contract.module_and_rva(int(interface_vtable[4] or 0))
        try:
            result = notify_type(interface_vtable[4])(interface, 0)
        finally:
            contract.REF(interface_vtable[2])(interface)
        emit(
            "ram_construction_complete",
            kind=kind,
            supported=True,
            argument=0,
            result=contract.hresult(result),
            module=str(module),
            slot=4,
            rva=f"0x{rva:X}",
        )
        if result < 0:
            raise RuntimeError(
                f"{kind} IVirtualDeviceMemoryInfo slot 4 returned "
                f"{contract.hresult(result)}"
            )
        notified.append(
            {"kind": kind, "module": pathlib.Path(module).name, "rva": f"0x{rva:X}"}
        )
    return notified


def run_child(vm_id: str, iteration: int) -> int:
    objects: dict[str, ctypes.c_void_p] = {}
    vtables: dict[str, ctypes.POINTER(ctypes.c_void_p)] = {}
    repositories: dict[str, contract.RecordingRepository] = {}
    provided: dict[str, contract.ComInterfaceService] = {}
    initialized: list[str] = []
    services = None
    owner = None
    topology = None
    contract.ole.CoInitializeEx(None, 0)
    try:
        identities = contract.verify_identities()
        emit("identities_verified", files=identities)
        owner = contract.OwnerPartition(vm_id)
        topology = WindowsRamTopology(owner)

        for kind in GRAPH_ORDER:
            spec = contract.DEVICES[kind]
            obj = contract.activate(spec.clsid)
            objects[kind] = obj
            vtables[kind] = verify_vtable(kind, obj)
            repositories[kind] = contract.RecordingRepository(
                spec.clsid, vm_id, spec.xml
            )

        provided = query_provided_interfaces(objects)
        services = contract.RecordingServices(unique_dependencies(), provided)

        initialize_type = ctypes.WINFUNCTYPE(
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.c_void_p,
        )
        for kind in GRAPH_ORDER:
            result = initialize_type(vtables[kind][4])(
                objects[kind], repositories[kind].pointer, 0, services.pointer
            )
            emit("initialize", kind=kind, result=contract.hresult(result))
            if result < 0:
                raise RuntimeError(
                    f"{kind} Initialize returned {contract.hresult(result)}"
                )
            initialized.append(kind)

        memory_info_devices = notify_ram_construction_complete(objects)

        teardown_type = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
        while initialized:
            kind = initialized.pop()
            result = teardown_type(vtables[kind][5])(objects[kind])
            emit("teardown", kind=kind, result=contract.hresult(result))
            if result < 0:
                raise RuntimeError(f"{kind} Teardown returned {contract.hresult(result)}")

        for kind in GRAPH_ORDER:
            expected = contract.DEVICES[kind].repository_calls
            observed = tuple(repositories[kind].calls)
            if observed != expected:
                raise RuntimeError(
                    f"{kind} repository calls changed: observed={observed} expected={expected}"
                )

        observed_service_calls = {
            service.name: service.calls
            for service in services.services.values()
            if service.calls
        }
        expected_calls = expected_service_calls()
        if observed_service_calls != expected_calls:
            raise RuntimeError(
                "service callbacks changed: "
                f"observed={observed_service_calls} expected={expected_calls}"
            )
        if services.obj.refs != 1:
            raise RuntimeError("a device retained IVirtualDeviceServices")
        for service in services.services.values():
            if isinstance(service, contract.RecordingService) and service.obj.refs != 1:
                raise RuntimeError(f"a device retained {service.name}")

        concrete_service_names = [service.name for service in provided.values()]
        for service in provided.values():
            service.close()
        provided.clear()
        for kind in reversed(GRAPH_ORDER):
            obj = objects.pop(kind)
            contract.REF(vtable_of(obj)[2])(obj)
        for kind in GRAPH_ORDER:
            if repositories[kind].obj.refs != 1:
                raise RuntimeError(f"{kind} retained its repository after destruction")

        topology_description = topology.describe()
        topology.close()
        topology = None
        emit(
            "result",
            passed=True,
            iteration=iteration,
            initialized=list(GRAPH_ORDER),
            teardown=list(reversed(GRAPH_ORDER)),
            concrete_services=concrete_service_names,
            ram_topology=topology_description,
            ram_construction_complete={
                "issued": True,
                "argument": 0,
                "notified": memory_info_devices,
            },
            partition_id=f"0x{owner.partition_id:X}",
        )
        return 0
    except BaseException as error:
        emit(
            "result",
            passed=False,
            iteration=iteration,
            error=f"{type(error).__name__}: {error}",
        )
        return 1
    finally:
        teardown_type = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
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
        for kind in reversed(GRAPH_ORDER):
            obj = objects.get(kind)
            if obj is not None:
                contract.REF(vtable_of(obj)[2])(obj)
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
    events: list[object] = []
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
                    "stderr": (error.stderr or "").splitlines(),
                }
            )
        passed &= child_passed
    print(
        json.dumps(
            {
                "probe": "inbox_vdev_composed_initialization",
                "scope": "windows_ram_topology_ram_complete_and_teardown_without_vp_start",
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
