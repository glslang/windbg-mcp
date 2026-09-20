"""The in-GUI half of the capture: open a driver, type it, and write a companion capture.

Imported only inside an owned Binary Ninja process started by `capture.py` beside this file.
**Binary Ninja Personal has no headless API**, so this runs in the real GUI -- in a disposable
`BN_USER_DIRECTORY` profile, driven by a generated plugin, quitting itself when it is done. That is
the same mechanism `tools/bn_followup_probe.py` uses for the CLRBHB probes.

What it produces is a *capture*: the companion adapter's own reading of the binary, which
`binja_windbg_mcp.analysis.ioctl_map` then interprets. It is **not** a companion test fixture --
those carry `expected_mappings` reviewed by hand in the UI, and nothing here reviews anything. A
capture is one implementation's answer, which is all the diff wants and all this claims.
"""

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

# The four NT types the adapter reads, written for ARM64 (8-byte pointers). Offsets are not
# guessed: every one below was read off the live ARM64 kernel with `dt` on 2026-09-20 and agrees
# with the layouts the companion's own `mountmgr` fixture recorded from a PDB --
# `_IO_STACK_LOCATION.Parameters` at 8 and `DeviceObject` at 0x28, `_DRIVER_OBJECT.MajorFunction`
# at 0x70 with the struct 0x150 wide, `_IRP` 0xd0 wide with `Tail.Overlay.CurrentStackLocation` at
# 0xb8, `_UNICODE_STRING.Buffer` at 8. The capture records what the view actually resolved
# (`types.validated_layouts`), so a wrong declaration here shows up as a layout rather than as a
# quietly empty map.
#
# **`_DEVICE_OBJECT` is deliberately opaque.** Nothing reads its members -- it exists so the
# dispatch prototype's first parameter has the right width and name -- and a fabricated member
# list would look like evidence.
NT_TYPES = """
struct _UNICODE_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    uint16_t* Buffer;
};
struct _LIST_ENTRY { struct _LIST_ENTRY* Flink; struct _LIST_ENTRY* Blink; };
struct _DEVICE_OBJECT { uint8_t Opaque[336]; };
struct _DRIVER_OBJECT {
    int16_t Type;
    int16_t Size;
    struct _DEVICE_OBJECT* DeviceObject;
    uint32_t Flags;
    void* DriverStart;
    uint32_t DriverSize;
    void* DriverSection;
    void* DriverExtension;
    struct _UNICODE_STRING DriverName;
    struct _UNICODE_STRING* HardwareDatabase;
    void* FastIoDispatch;
    void* DriverInit;
    void* DriverStartIo;
    void* DriverUnload;
    void* MajorFunction[28];
};
struct _IO_STACK_LOCATION {
    uint8_t MajorFunction;
    uint8_t MinorFunction;
    uint8_t Flags;
    uint8_t Control;
    union {
        struct {
            uint32_t OutputBufferLength;
            uint32_t Reserved0;
            uint32_t InputBufferLength;
            uint32_t Reserved1;
            uint32_t IoControlCode;
            void* Type3InputBuffer;
        } DeviceIoControl;
        struct { void* Argument1; void* Argument2; void* Argument3; void* Argument4; } Others;
    } Parameters;
    struct _DEVICE_OBJECT* DeviceObject;
    void* FileObject;
    void* CompletionRoutine;
    void* Context;
};
struct _IRP {
    int16_t Type;
    uint16_t Size;
    uint16_t AllocationProcessorNumber;
    uint16_t Reserved1;
    void* MdlAddress;
    uint32_t Flags;
    uint32_t Reserved2;
    void* AssociatedIrp;
    struct _LIST_ENTRY ThreadListEntry;
    void* IoStatusStatus;
    uint64_t IoStatusInformation;
    char RequestorMode;
    uint8_t PendingReturned;
    char StackCount;
    char CurrentLocation;
    uint8_t Cancel;
    uint8_t CancelIrql;
    char ApcEnvironment;
    uint8_t AllocationFlags;
    void* UserIosb;
    void* UserEvent;
    void* OverlayAsynchronousContext;
    void* OverlayThread;
    void* CancelRoutine;
    void* UserBuffer;
    struct {
        struct {
            void* DriverContext[4];
            void* Thread;
            char* AuxiliaryBuffer;
            struct _LIST_ENTRY ListEntry;
            struct _IO_STACK_LOCATION* CurrentStackLocation;
            void* OriginalFileObject;
            void* IrpExtension;
        } Overlay;
    } Tail;
};
"""

# What the offsets above have to come out as, checked after the view has parsed them. A struct that
# parsed but landed differently -- one padding rule apart -- reads every displacement in the
# driver against the wrong field, and the failure is an empty map rather than an error.
EXPECTED = {
    "_DRIVER_OBJECT": (336, {"MajorFunction": 112}),
    "_IO_STACK_LOCATION": (72, {"Parameters": 8, "DeviceObject": 40, "Context": 64}),
    "_IRP": (208, {}),
    "_UNICODE_STRING": (16, {"Buffer": 8}),
}
IOCTL_OFFSETS = {"OutputBufferLength": 8, "InputBufferLength": 16, "IoControlCode": 24}

ENTRY_PROTOTYPE = (
    "int32_t DriverEntry(struct _DRIVER_OBJECT* DriverObject, "
    "struct _UNICODE_STRING* RegistryPath)"
)
DISPATCH_PROTOTYPE = "int32_t Dispatch(struct _DEVICE_OBJECT* DeviceObject, struct _IRP* Irp)"


def open_view(path):
    """The GUI's own open, which is what a Personal licence allows."""
    from binaryninjaui import FileContext, UIContext

    def opened():
        (context,) = UIContext.allContexts()
        return context.openFilename(path)

    from binja_windbg_mcp.adapter import main_thread

    if not main_thread(opened):
        raise RuntimeError(f"Binary Ninja would not open {path}")
    wanted = Path(path).resolve()
    for context in FileContext.getOpenFileContexts():
        for view in context.getAllDataViews():
            if Path(view.file.original_filename).resolve() == wanted and view.view_type != "Raw":
                return view
    raise RuntimeError("the opened file has no analysable view")


def define_types(view, report):
    """Parse the NT declarations into this view and check where their members landed."""
    parsed = view.platform.parse_types_from_source(NT_TYPES)
    for name, value in parsed.types.items():
        view.define_user_type(name, value)
    view.update_analysis_and_wait()
    landed, wrong = {}, []
    for name, (width, offsets) in EXPECTED.items():
        value = view.get_type_by_name(name)
        if value is None:
            wrong.append(f"{name}: not defined")
            continue
        members = {m.name: m.offset for m in getattr(value, "members", [])}
        landed[name] = {"width": value.width, "members": members}
        if value.width != width:
            wrong.append(f"{name}: width {value.width}, expected {width}")
        for member, offset in offsets.items():
            if members.get(member) != offset:
                wrong.append(f"{name}.{member}: {members.get(member)}, expected {offset}")
    report["types_landed"] = landed
    if wrong:
        raise RuntimeError("NT types parsed into a different layout: " + "; ".join(wrong))


def prototype(view, function, text):
    """Apply a signature, through whichever setter this API revision exposes.

    `Function.function_type` and `Function.type` have swapped places between releases and the
    wrong one is an `AttributeError` at the end of a ten-minute analysis, so both are tried and
    the failure names the type rather than the attribute.
    """
    value, _ = view.parse_type_string(text)
    for attribute in ("type", "function_type"):
        try:
            setattr(function, attribute, value)
            return
        except AttributeError:
            continue
    raise RuntimeError(f"no setter on Function accepted {text}")


def dump_function(view, function, limit=400):
    """The applied signature and the HLIL, for reading why a registration was not recovered."""
    if function is None:
        return None
    try:
        lines = [str(instruction) for instruction in function.hlil.instructions][:limit]
    except Exception as error:
        lines = [f"<hlil unavailable: {type(error).__name__}: {error}>"]
    return {
        "rva": hex(function.start - view.start),
        "type": str(function.type),
        "parameters": [str(p) for p in function.parameter_vars],
        "hlil": lines,
    }


def registrations_for(view, report, budget_factory):
    """One `capture_driver` pass, and the device-control roots it recovered."""
    from binja_windbg_mcp import analysis
    from binja_windbg_mcp.adapter import capture_driver

    taken = capture_driver(view, budget_factory(120))
    registered = analysis.driver_entry(taken, budget_factory(60))
    roots = sorted(
        {
            root["callback_rva"]
            for root in registered["roots"]
            if root.get("major_function") in (14, 15) and root.get("callback_rva")
        }
    )
    return taken, registered, roots


def recover_roots(view, config, report, save):
    """Type whichever routine actually registers the dispatch, escalating only as far as needed.

    **The image entry is often not `DriverEntry`.** MSVC emits a `/GS` stub that initialises the
    security cookie and tail-calls the real one, so typing the entry point alone leaves the
    registering function's `PDRIVER_OBJECT` parameter untyped and `MajorFunction[14] = handler`
    is never an array write to a known struct -- measured on `rdyboost`, where the entry and both
    of its direct callees recover nothing.

    So the prototype is applied outward from the entry, a call at a time, stopping at the first
    hop that recovers a device-control registration and at `--entry-hops` (3) regardless. Every
    hop is recorded. It is bounded rather than applied to the whole image for a reason: a
    `PDRIVER_OBJECT` first parameter on a function that has no such thing makes any store of a
    pointer at `+0x70 + 8n` read as a registration, and that is a fact this capture would be
    inventing rather than reading.
    """
    from binja_windbg_mcp.core import Budget

    def budget(seconds):
        return Budget(seconds=seconds)

    attempts = []
    wanted = int(config["dispatch_rva"], 16) if config.get("dispatch_rva") else None
    entry = view.get_function_at(view.entry_point)
    if entry is None:
        raise RuntimeError("no function at the entry point")
    if config.get("entry_rva"):
        given = view.get_function_at(view.start + int(config["entry_rva"], 16))
        if given is None:
            raise RuntimeError(f"no function at --entry-rva {config['entry_rva']}")
        frontier, label = [given], "supplied --entry-rva"
    else:
        frontier, label = [entry], "image entry point"

    taken = registered = None
    seen = set()
    # `or 3` would throw away an explicit 0, which is the caller asking for the entry routine and
    # nothing beyond it -- the one setting that keeps a prototype off functions it was not meant
    # for. Raised on review of #354.
    hops = config.get("entry_hops")
    for hop in range(int(3 if hops is None else hops) + 1):
        frontier = [f for f in frontier if f.start not in seen]
        if not frontier:
            break
        seen.update(f.start for f in frontier)
        for function in frontier:
            prototype(view, function, ENTRY_PROTOTYPE)
        view.update_analysis_and_wait()
        taken, registered, roots = registrations_for(view, report, budget)
        attempts.append(
            {
                "typed": label if hop == 0 else f"{hop} call(s) from it",
                "rvas": sorted(hex(f.start - view.start) for f in frontier),
                "registrations": len(registered["roots"]),
                "device_control_roots": roots,
            }
        )
        report["entry_attempts"] = attempts
        report["registrations"] = registered["roots"]
        save()
        # **Stopping at any root is not stopping at the right one.** With `--dispatch-rva` given,
        # an early hop that recovers some *other* device-control registration -- major 15 in a
        # wrapper, say, while the requested handler is registered deeper -- would end the walk and
        # the cross-check would then reject the capture, with the remaining hops and the
        # address-referrer fallback never tried. Raised on review of #354.
        if roots and (wanted is None or any(int(rva, 16) == wanted for rva in roots)):
            report["dispatch_source"] = attempts[-1]["typed"]
            return taken, registered, roots
        frontier = [callee for f in frontier for callee in f.callees]

    # **A prototype is not always enough, because MSVC clobbers the binding.** On ARM64 a driver
    # compiled with `/GS` opens `DriverEntry` with `__security_push_cookie`, which really does
    # preserve the argument registers but is not declared to -- Binary Ninja models it as
    # *returning* `x0` and `x1`, so the typed parameter dies at the first call and every later use
    # is an untyped `void* x0`. Measured on `rdyboost`: the signature applies, and the table fill
    # still reads `*(x0 + 0x70) = SmdDispatchGeneric` rather than `DriverObject->MajorFunction[0]`.
    #
    # So the entry register is typed as well. `x0` on entry **is** the driver object under the
    # kernel ABI, which is the same claim the prototype makes; what makes it checkable rather than
    # asserted is the cross-check below -- a recovered `MajorFunction[14]` that disagrees with the
    # live driver object's is a wrong reading, and the capture refuses rather than publishing it.
    driver_object = view.get_type_by_name("_DRIVER_OBJECT")
    if driver_object is not None:
        import binaryninja as bn

        pointer = bn.Type.pointer(view.arch, driver_object)
        typed = []
        for start in sorted(seen):
            function = view.get_function_at(start)
            if function is None:
                continue
            for variable in function.vars:
                if variable.name == "x0":
                    function.create_user_var(variable, pointer, variable.name)
                    typed.append(hex(start - view.start))
        if typed:
            view.update_analysis_and_wait()
            taken, registered, roots = registrations_for(view, report, budget)
            attempts.append(
                {
                    "typed": "the entry register of the routines above, as PDRIVER_OBJECT",
                    "rvas": sorted(set(typed)),
                    "registrations": len(registered["roots"]),
                    "device_control_roots": roots,
                }
            )
            report["entry_attempts"] = attempts
            report["registrations"] = registered["roots"]
            save()
            if roots and (wanted is None or any(int(rva, 16) == wanted for rva in roots)):
                report["dispatch_source"] = attempts[-1]["typed"]
                return taken, registered, roots

    # **Last resort: type whoever takes the dispatch routine's address.** `rdyboost` fills its
    # table somewhere the walk above does not reach, and the one fact that finds the filler is the
    # dispatch RVA -- which comes from the **live driver object**, the OS's own answer about which
    # routine is registered for `IRP_MJ_DEVICE_CONTROL`, not from the implementation this capture
    # is going to be diffed against. Every control *code* still comes out of Binary Ninja alone,
    # which is what the diff compares; the provenance records that this one address did not.
    if config.get("dispatch_rva"):
        address = view.start + int(config["dispatch_rva"], 16)
        referrers = {}
        for ref in view.get_code_refs(address):
            function = ref.function
            if function is not None and function.start != address:
                referrers[function.start] = function
        for function in referrers.values():
            prototype(view, function, ENTRY_PROTOTYPE)
        if referrers:
            view.update_analysis_and_wait()
            taken, registered, roots = registrations_for(view, report, budget)
            attempts.append(
                {
                    "typed": "functions referencing the supplied --dispatch-rva",
                    "rvas": sorted(hex(start - view.start) for start in referrers),
                    "registrations": len(registered["roots"]),
                    "device_control_roots": roots,
                }
            )
            report["entry_attempts"] = attempts
            report["registrations"] = registered["roots"]
            save()
            if roots and (wanted is None or any(int(rva, 16) == wanted for rva in roots)):
                report["dispatch_source"] = attempts[-1]["typed"]
                return taken, registered, roots
    # Nothing worked: record what the routines this typed actually look like, because the next
    # question is always whether the prototype took and what shape the table fill has.
    report["diagnostics"] = {
        hex(start - view.start): dump_function(view, view.get_function_at(start))
        for start in sorted(seen | {view.start + int(rva, 16) for rva in config.get("dump_hlil") or []})
    }
    save()
    return taken, registered, []


def capture(config, report, save):
    import binaryninja as bn
    from binja_windbg_mcp import analysis
    from binja_windbg_mcp.adapter import capture_driver
    from binja_windbg_mcp.core import Budget, original_hash, pe_identity

    view = open_view(config["image"])
    view.update_analysis_and_wait()
    report["view"] = {
        "type": view.view_type,
        "architecture": view.arch.name,
        "functions": len(list(view.functions)),
    }
    save()
    define_types(view, report)

    # **Which routine is the device-control dispatch is asked of the driver, not of the other
    # implementation.** A `MajorFunction[14] = handler` write is the registration, and recovering
    # it here is what keeps the second opinion independent -- the diff compares control *codes*,
    # and every one of those still comes out of Binary Ninja's own analysis.
    first, registered, roots = recover_roots(view, config, report, save)
    if not roots:
        raise RuntimeError(
            "no IRP_MJ_DEVICE_CONTROL registration was recovered; give --entry-rva for the real "
            "DriverEntry, or --dispatch-rva so the routine that takes its address can be typed"
        )
    # **The registration is checked against the one the OS resolved**, when that is supplied.
    # Everything above types code so Binary Ninja can read a table write, and a mistyped variable
    # would read *some* write -- so a recovered device-control callback that is not the live
    # driver object's is a wrong reading, and this refuses rather than publishing it.
    if config.get("dispatch_rva"):
        wanted = int(config["dispatch_rva"], 16)
        if not any(int(rva, 16) == wanted for rva in roots):
            raise RuntimeError(
                f"recovered device-control roots {roots} do not include the live driver "
                f"object's {config['dispatch_rva']}"
            )
        roots = [rva for rva in roots if int(rva, 16) == wanted]
    elif len(roots) > 1:
        raise RuntimeError(
            f"this driver registers {len(roots)} device-control routines ({roots}); pass "
            "--dispatch-rva to say which one to capture"
        )
    # **One dispatch routine, because that is what the diff compares.** The tool half asks
    # `ioctl_map` about a single `--dispatch`, while `analysis.ioctl_map` takes the union of
    # majors 14 and 15 -- so a driver registering different callbacks for device control and
    # *internal* device control would have both typed here and the companion would answer for
    # both, every code from the second reading as one only it found. Raised on review of #354.
    report["dispatch_rvas"] = roots
    save()

    for rva in roots:
        function = view.get_function_at(view.start + int(rva, 16))
        if function is None:
            raise RuntimeError(f"no function at dispatch {rva}")
        prototype(view, function, DISPATCH_PROTOTYPE)
    view.update_analysis_and_wait()

    final = capture_driver(view, Budget(120))
    if final.get("truncated"):
        raise RuntimeError("the capture is truncated; it is not a complete second opinion")
    layouts = final["types"]["validated_layouts"]
    control = layouts.get("_IO_STACK_LOCATION.Parameters.DeviceIoControl", {})
    off = {name: field["offset"] for name, field in control.items()}
    if off != IOCTL_OFFSETS:
        raise RuntimeError(f"the view resolved the IOCTL fields at {off}, expected {IOCTL_OFFSETS}")

    identity, architecture = pe_identity(view.file.raw.read)
    digest = original_hash(view)
    if digest is None:
        raise RuntimeError("the original file bytes are not recoverable; identity unpinned")
    record = {
        "capture": final,
        "file_sha256": digest,
        "architecture": architecture,
        "identity": identity.model_dump(),
        "analysis_version": final["analysis_version"],
        "provenance": {
            "source": "tools/binja_oracle/bn_capture.py in an owned Binary Ninja GUI",
            "image_sha256": hashlib.sha256(Path(config["image"]).read_bytes()).hexdigest(),
            "nt_types": "declared in this probe; offsets checked against the live ARM64 kernel",
            "types_landed": report["types_landed"],
            "dispatch_source": report["dispatch_source"],
            "entry_attempts": report.get("entry_attempts"),
            "dispatch_rvas": roots,
            "expected_mappings": "none -- this is an implementation's answer, not reviewed "
            "ground truth, and must not be read as one",
            "captured_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    Path(config["capture_path"]).write_text(json.dumps(record, indent=2) + "\n")
    report["capture_path"] = config["capture_path"]
    report["cases"] = len(analysis.ioctl_map(final, Budget(60))["cases"])
    report["ok"] = True
    if bn.core_product_type():
        report["edition"] = bn.core_product_type()


def start(config_path):
    import binaryninja as bn
    from binaryninjaui import UIContext
    from PySide6.QtWidgets import QApplication

    config = json.loads(Path(config_path).read_text())
    output = Path(config["output"])
    report = {
        "schema_version": 1,
        "ok": False,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "bn_version": bn.core_version(),
        "image": config["image"],
    }

    def save():
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")

    app = QApplication.instance()
    app.aboutToQuit.connect(lambda: (report.update(about_to_quit=True), save()))
    save()

    def quit_action():
        (context,) = UIContext.allContexts()
        handler = context.getCurrentActionHandler()
        if not handler.isValidAction("Quit"):
            raise RuntimeError("Quit action unavailable")
        handler.executeAction("Quit")

    def background():
        try:
            capture(config, report, save)
        except Exception as error:
            report["error"] = type(error).__name__ + ": " + str(error)
            report["ok"] = False
        finally:
            save()

            def finish():
                try:
                    from binaryninjaui import FileContext

                    # **Quit asks to save a modified database, and nobody is here to answer.**
                    # This probe defines types and applies prototypes, so the file genuinely is
                    # modified; clearing the flag is what keeps the prompt from appearing. These
                    # views exist only in this disposable process, so there is nothing to lose.
                    for context in FileContext.getOpenFileContexts():
                        for view in context.getAllDataViews():
                            view.file.modified = False
                    # And if something else already has a modal up, say so and close it rather
                    # than leaving the launcher to time out against a window it cannot see.
                    modal = app.activeModalWidget()
                    if modal is not None:
                        report["modal_at_quit"] = modal.windowTitle() or type(modal).__name__
                        save()
                        modal.close()
                    quit_action()
                    # Measured: the Quit still does not always complete here, and the launcher's
                    # short leash after this verdict is what bounds that. The capture is already
                    # on disk, so a killed GUI costs nothing but the leash.
                except Exception as error:
                    report["cleanup_error"] = str(error)
                    save()

            bn.execute_on_main_thread(finish)

    threading.Thread(target=background, name="binja-oracle-capture", daemon=True).start()
