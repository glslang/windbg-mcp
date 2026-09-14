"""Diff `ioctl_map` against Ghidra and Driver Buddy Revolutions, by code.

See README.md beside this for what the bench needs and how to read the answer. Manual lane: a run
is about a minute per driver and needs Ghidra on the host.

**This file must not be moved next to a directory called `ghidra`** -- see the README's third trap.
"""

import argparse
import collections
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
GHIDRA = pathlib.Path(os.environ.get("GHIDRA_INSTALL_DIR", r"C:\ghidra_12.1.3_PUBLIC"))
JAVA_HOME = os.environ.get(
    "JAVA_HOME", r"C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot"
)
DBR = pathlib.Path.home() / "ghidra_scripts" / "ghidra_vuln_finder.py"

# The defaults are the checked-in x64 driver crash and the cached image that matches it. The
# directory name ends in `SizeOfImage`, and only this copy has an instruction at the dispatch RVA.
DUMP = REPO / "docs" / "samples" / "081226-2187-01.dmp"
IMAGE = REPO / "target" / "release" / "sym" / "mountmgr.sys" / "F7AA24C61f000" / "mountmgr.sys"
DISPATCH = "mountmgr!MountMgrDeviceControl"
SERVER = REPO / "target" / "debug" / "windbg-mcp.exe"


# ---- the tool ----------------------------------------------------------------------------


def ask_the_tool(dump: pathlib.Path, dispatch: str, profile: str | None = None) -> dict:
    """`ioctl_map`'s own answer, over stdio, so this needs no running server.

    stderr goes to `DEVNULL` rather than a pipe, deliberately: a pipe nobody drains fills once
    `RUST_LOG` is widened and the server blocks mid-request, which reads as a hung debugger
    (`.claude/rules/powershell-scripts.md`). Discarded cannot fill.
    """
    proc = subprocess.Popen(
        [str(SERVER)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    seq = [0]

    def call(method, params=None, notify=False):
        seq[0] += 1
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            msg["id"] = seq[0]
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        if notify:
            return None
        while True:
            line = proc.stdout.readline()
            if not line:
                raise SystemExit("the server closed the pipe")
            reply = json.loads(line)
            if reply.get("id") == msg["id"]:
                return reply

    def tool(name, arguments):
        return call("tools/call", {"name": name, "arguments": arguments})["result"].get(
            "structuredContent", {}
        )

    call(
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "ghidra-oracle", "version": "0"},
        },
    )
    call("notifications/initialized", {}, notify=True)
    # **A live kernel by profile, never by connection string**, which is how the rest of this
    # repo reaches one: the debug key stays out of the argument and out of anything this prints.
    opened = (
        tool("attach_kernel", {"profile": profile, "timeout_ms": 120000})
        if profile
        else tool("open_dump", {"path": str(dump)})
    )
    if opened.get("status") != "ok":
        raise SystemExit("the target did not open: " + json.dumps(opened)[:400])
    session = opened["session_id"]
    if profile:
        # A fresh attach's module inventory holds `nt` and little else, and a driver loaded before
        # it is then absent from the inventory rather than from the target.
        tool("modules", {"session_id": session, "refresh": True, "limit": 1})
    try:
        # Asked of another tool first: a routine whose pages are missing disassembles as `???`,
        # and an empty map for want of code is not an answer to compare against anything.
        probe = tool(
            "disassemble", {"session_id": session, "address": dispatch, "count": 1}
        )
        first = (probe.get("instructions") or [{}])[0]
        if "?" in (first.get("text") or "?"):
            raise SystemExit(
                "this host cannot disassemble the driver: a kernel minidump carries no driver "
                "pages, so the image file has to be served. Nothing to compare."
            )
        answer = tool("ioctl_map", {"session_id": session, "dispatch": dispatch})
        if answer.get("status") != "ok":
            raise SystemExit("ioctl_map failed: " + json.dumps(answer)[:400])
        return answer
    finally:
        tool("end_session", {"session_id": session})
        proc.stdin.close()
        proc.wait(timeout=30)


# ---- the two oracles ---------------------------------------------------------------------


def ask_ghidra(image: pathlib.Path, rva: str, work: pathlib.Path) -> dict:
    out = work / "ghidra.json"
    # Headless aborts rather than creating one: "Directory not found".
    (work / "proj").mkdir(exist_ok=True)
    env = dict(os.environ, JAVA_HOME=JAVA_HOME)
    subprocess.run(
        [
            str(GHIDRA / "support" / "analyzeHeadless.bat"),
            str(work / "proj"),
            "oracle",
            "-import",
            str(image),
            "-scriptPath",
            str(pathlib.Path(__file__).parent),
            "-postScript",
            "IoctlOracle.java",
            rva,
            str(out),
            "-deleteProject",
        ],
        check=True,
        env=env,
        capture_output=True,
        text=True,
    )
    return json.loads(out.read_text(encoding="utf-8"))


def ask_driver_buddy(image: pathlib.Path, work: pathlib.Path) -> str:
    """Driver Buddy Revolutions, through `pyghidra` because headless refuses a `.py` post-script.

    Run as a child process from a directory that has no `ghidra` folder in it, which is the
    README's third trap and is not something this file can guarantee for its own caller.
    """
    runner = work / "run_dbr.py"
    runner.write_text(
        "import pyghidra\n"
        "pyghidra.start()\n"
        f"pyghidra.run_script(r{str(image)!r}, r{str(DBR)!r},\n"
        f"                    project_location=r{str(work / 'dbrproj')!r},\n"
        "                    project_name='dbr', analyze=True)\n",
        encoding="utf-8",
    )
    (work / "dbrproj").mkdir(exist_ok=True)
    done = subprocess.run(
        [sys.executable, str(runner)],
        cwd=str(work),
        env=dict(os.environ, JAVA_HOME=JAVA_HOME, GHIDRA_INSTALL_DIR=str(GHIDRA)),
        capture_output=True,
        text=True,
    )
    # **A crash is not an empty code set.** Read regardless of the exit code, a PyGhidra that died
    # -- a missing companion GDT, an analysis fault -- comes back as "Driver Buddy found nothing",
    # which is a comparison against an oracle that never ran and looks exactly like a real result.
    if done.returncode != 0:
        tail = (done.stdout + done.stderr).strip().splitlines()[-8:]
        raise SystemExit(
            "Driver Buddy Revolutions exited "
            + f"{done.returncode}; its answer is not usable:\n  "
            + "\n  ".join(tail)
        )
    return done.stdout + done.stderr


# ---- the diff ----------------------------------------------------------------------------


def norm(code) -> str:
    return f"0x{int(str(code), 16):08x}"


def ghidra_equalities(report: dict) -> set:
    """The constants Ghidra compares the control code against **for equality**.

    Its `compare_values` holds every constant in any comparison, relational bounds included: a
    dense switch is bracketed by `INT_LESS` against one past each end, so `0x6dc001` and `0x6d4021`
    are in `mountmgr`'s list and are not codes. Promoting them made the diff report known
    non-codes as missing from `ioctl_map` -- an oracle contradicting its own README.
    """
    return {
        norm(compare["value"])
        for compare in report["compares"]
        if compare["op"] in ("INT_EQUAL", "INT_NOTEQUAL") and compare.get("traced", True)
    }


def ghidra_untraced(report: dict) -> set:
    """Equality constants whose other side never came from memory.

    A device type is sixteen bits of a constant, so a status, a length or a magic number can wear
    one. The control code arrives from a load; these did not, and calling them codes `ioctl_map`
    missed would be this lane inventing findings. Reported apart rather than dropped, because
    Ghidra's reach here is bounded and "did not trace" is not "is not a code".
    """
    return {
        norm(compare["value"])
        for compare in report["compares"]
        if compare["op"] in ("INT_EQUAL", "INT_NOTEQUAL") and not compare.get("traced", True)
    }


def ghidra_tables(report: dict) -> list:
    """Each switch, as labels grouped by the block they reach.

    **The default is not inferred.** Taking the most frequent destination works on `mountmgr`,
    where 68 of 81 slots go to one place, and fails on a switch whose labels legitimately share a
    handler or whose destinations are all distinct -- the first discards real labels, the second
    drops one at random. Ghidra's own metadata does not expose which arm is the default, so this
    reports the grouping and leaves the reading to whoever is looking.
    """
    grouped = []
    for table in report["tables"]:
        by_dest = collections.defaultdict(list)
        for pair in table["pairs"]:
            by_dest[pair["dest_rva"]].append(norm(pair["label"]))
        grouped.append((table["switch_rva"], by_dest))
    return grouped


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", type=pathlib.Path, default=DUMP)
    parser.add_argument(
        "--profile",
        help="attach this kernel connection profile instead of opening --dump, for a driver that "
        "is only on a live target. By name, never a connection string, so no debug key reaches "
        "an argument or a transcript",
    )
    parser.add_argument("--image", type=pathlib.Path, default=IMAGE)
    parser.add_argument("--dispatch", default=DISPATCH)
    parser.add_argument(
        "--device-type",
        default="0x6d",
        help="the driver's own device type, which is what makes the three lists comparable",
    )
    args = parser.parse_args()

    needed = [args.image, SERVER, DBR]
    if not args.profile:
        needed.append(args.dump)
    for path in needed:
        if not path.exists():
            raise SystemExit(f"not found: {path}")

    device = int(args.device_type, 16)
    with tempfile.TemporaryDirectory(prefix="ioctl-oracle-") as tmp:
        work = pathlib.Path(tmp)

        print("asking `ioctl_map` ...", flush=True)
        tool = ask_the_tool(args.dump, args.dispatch, args.profile)
        rva = tool["dispatch"].get("rva") or "0x0"
        tool_codes = {norm(case["code"]) for case in tool["cases"]}
        print(
            f"  {len(tool['cases'])} records over {len(tool_codes)} codes at {rva}", flush=True
        )

        print("asking Ghidra ...", flush=True)
        gh = ask_ghidra(args.image, rva, work)
        # **A decompilation that did not happen is not an empty answer.** The Java side says so
        # deliberately, and consuming the empty lists beside it reports Ghidra as finding no codes
        # -- a failed oracle wearing the face of a real result, which is the same shape as reading
        # Driver Buddy's output past a non-zero exit.
        if not gh.get("decompiled"):
            raise SystemExit(
                "Ghidra could not decompile the dispatch routine, so its half of this comparison "
                "never ran. Check the RVA names a function in this image."
            )
        # **Equality compares only.** A relational bound is not a code, and the switch half is
        # reported rather than diffed, because naming a table's default needs metadata
        # Ghidra does not give.
        gh_codes = {c for c in ghidra_equalities(gh) if (int(c, 16) >> 16) == device}
        gh_untraced = {
            c for c in ghidra_untraced(gh) if (int(c, 16) >> 16) == device
        } - gh_codes
        tables = ghidra_tables(gh)
        print(f"  dispatch {gh['dispatch']['rva']}, {len(gh_codes)} codes compared for equality, "
              f"{len(tables)} switch table(s)", flush=True)

        print("asking Driver Buddy Revolutions ...", flush=True)
        dbr_text = ask_driver_buddy(args.image, work)
        rows = re.findall(r"^\s*([0-9a-f]+)\s*:\s*(0x[0-9A-Fa-f]+)\s*\|", dbr_text, re.M)
        dbr_all = {norm(code) for _, code in rows}
        dbr_codes = {c for c in dbr_all if (int(c, 16) >> 16) == device}
        print(f"  {len(dbr_codes)} codes of device type {args.device_type}", flush=True)

        print()
        print(f"{'code':<14}{'ioctl_map':<12}{'ghidra':<10}{'DriverBuddy':<12}")
        print("-" * 62)
        for code in sorted(tool_codes | gh_codes | dbr_codes):
            here = [code in tool_codes, code in gh_codes, code in dbr_codes]
            print(
                f"{code:<14}"
                + "".join(
                    f"{'yes' if flag else 'NO':<{width}}"
                    for flag, width in zip(here, (12, 10, 12))
                )
                + ("" if all(here) else "  <-- differs")
            )

        print()
        # **Nothing here is a finding, and two heuristics agreeing does not make one.** Ghidra
        # admits a value because it came from memory; Driver Buddy because it looks like a control
        # code. An unrelated loaded field compared against a device-type-matching constant
        # satisfies both, so their intersection is two opinions rather than provenance -- and
        # neither traces the IRP's control-code field, which is the only thing that would settle
        # it. Tracing it here would be this lane adopting the assumption of the pass it exists to
        # check, so the answer is not a better filter but a weaker claim: these are candidates,
        # ranked by how many implementations saw them, and the decompiled C decides. That is how
        # `0x6dc000` was settled -- the lane pointed, and a handler with a name string is what made
        # it a finding.
        both = sorted((gh_codes & dbr_codes) - tool_codes)
        either = sorted((gh_codes ^ dbr_codes) - tool_codes)
        print(f"  agreed by all three             : {len(tool_codes & gh_codes & dbr_codes)}")
        print(f"  candidates, both implementations: {both}")
        print(f"  candidates, one implementation  : {either}")
        missing = both + either
        print(f"  `ioctl_map` has, Driver Buddy   : {sorted(tool_codes - dbr_codes)}")
        print(f"  Driver Buddy, other device type : {sorted(dbr_all - dbr_codes)}")
        if gh_untraced:
            print(f"  ghidra equalities not traced to a load: {sorted(gh_untraced)}")
            print("    -- the right device type and no provenance, so not counted as codes here")

        # **The switch half, as a subset question rather than a default-guessing one.** Every code
        # the tool recovered from a jump table has to be a label Ghidra put on the same switch, at
        # the same destination. That needs no opinion about which arm is the default -- which is
        # good, because Ghidra's metadata does not say.
        by_switch = {rva.lstrip("0").rjust(3, "0"): groups for rva, groups in tables}
        for switch, groups in tables:
            short = "0x" + switch[2:].lstrip("0")
            labelled = {
                label: dest for dest, labels in groups.items() for label in labels
            }
            from_table = [
                case
                for case in tool["cases"]
                if case.get("recovered") == "jump_table" and case["at"].get("rva") == short
            ]
            print()
            print(f"  switch {short}: ghidra {sum(len(v) for v in groups.values())} labels over "
                  f"{len(groups)} destination(s); `ioctl_map` took {len(from_table)}")
            for dest, labels in sorted(groups.items(), key=lambda kv: -len(kv[1])):
                taken = sum(1 for case in from_table if norm(case["code"]) in labels)
                print(f"    -> {dest}  {len(labels):>3} label(s), {taken} of them cases")

            # **And where each one lands, which is the half this used to only claim.** Counting a
            # code's membership among the labels says the table was read; comparing the block it
            # routes to says it was read *correctly*. A map that recovers the right label and sends
            # it to the wrong handler passed the old check clean.
            stray, misrouted = [], []
            for case in from_table:
                code = norm(case["code"])
                if code not in labelled:
                    stray.append(code)
                    continue
                theirs = labelled[code]
                ours = case.get("case_rva")
                if ours is None:
                    continue
                if int(ours, 16) != int(theirs, 16):
                    misrouted.append(f"{code} -> {ours} (ghidra {theirs})")
            print(f"    codes `ioctl_map` took that ghidra does not label here: {stray or 'none'}")
            print(f"    codes routed somewhere ghidra does not: {misrouted or 'none'}")

        if missing:
            print()
            print("  Every line above is a candidate rather than a finding: neither implementation")
            print("  traces the IRP's control-code field, so a constant with the right device type")
            print("  and memory provenance may still be a length, a status or a magic number that")
            print("  `ioctl_map` was right to exclude. What settles it is the decompiled C beside")
            print("  the JSON -- a case is a handler, usually with a name string; a bound is a")
            print("  comparison the switch is bracketed by.")


if __name__ == "__main__":
    main()
