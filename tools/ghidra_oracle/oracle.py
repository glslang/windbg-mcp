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


def ask_the_tool(dump: pathlib.Path, dispatch: str) -> dict:
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
    opened = tool("open_dump", {"path": str(dump)})
    if opened.get("status") != "ok":
        raise SystemExit("the dump did not open: " + json.dumps(opened)[:400])
    session = opened["session_id"]
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
    return done.stdout + done.stderr


# ---- the diff ----------------------------------------------------------------------------


def norm(code) -> str:
    return f"0x{int(str(code), 16):08x}"


def ghidra_codes(report: dict) -> tuple[set, set]:
    """Codes Ghidra reaches, split from the raw compare constants it also emits.

    A dense switch covers its whole index range and sends every slot it has no case for to one
    place, so the default is the block the most slots reach and the rest are codes.
    """
    reached = set()
    for table in report["tables"]:
        seen = collections.Counter(pair["dest_rva"] for pair in table["pairs"])
        if not seen:
            continue
        default = seen.most_common(1)[0][0]
        reached |= {
            norm(pair["label"]) for pair in table["pairs"] if pair["dest_rva"] != default
        }
    return reached, {norm(v) for v in report["compare_values"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", type=pathlib.Path, default=DUMP)
    parser.add_argument("--image", type=pathlib.Path, default=IMAGE)
    parser.add_argument("--dispatch", default=DISPATCH)
    parser.add_argument(
        "--device-type",
        default="0x6d",
        help="the driver's own device type, which is what makes the three lists comparable",
    )
    args = parser.parse_args()

    for needed in (args.dump, args.image, SERVER, DBR):
        if not needed.exists():
            raise SystemExit(f"not found: {needed}")

    device = int(args.device_type, 16)
    with tempfile.TemporaryDirectory(prefix="ioctl-oracle-") as tmp:
        work = pathlib.Path(tmp)

        print("asking `ioctl_map` ...", flush=True)
        tool = ask_the_tool(args.dump, args.dispatch)
        rva = tool["dispatch"].get("rva") or "0x0"
        tool_codes = {norm(case["code"]) for case in tool["cases"]}
        print(
            f"  {len(tool['cases'])} records over {len(tool_codes)} codes at {rva}", flush=True
        )

        print("asking Ghidra ...", flush=True)
        gh = ask_ghidra(args.image, rva, work)
        reached, compared = ghidra_codes(gh)
        gh_codes = reached | {c for c in compared if (int(c, 16) >> 16) == device}
        print(f"  dispatch {gh['dispatch']['rva']}, {len(gh_codes)} codes", flush=True)

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
        missing = sorted((gh_codes | dbr_codes) - tool_codes)
        print(f"  agreed by all three             : {len(tool_codes & gh_codes & dbr_codes)}")
        print(f"  missing from `ioctl_map`        : {missing}")
        print(f"  `ioctl_map` has, Driver Buddy   : {sorted(tool_codes - dbr_codes)}")
        print(f"  Driver Buddy, other device type : {sorted(dbr_all - dbr_codes)}")
        if missing:
            print()
            print("  A code only `ioctl_map` lacks is a finding until it is explained. Read the")
            print("  decompiled C beside the JSON: a range bound is `INT_LESS`, a case is a")
            print("  handler with a name string.")


if __name__ == "__main__":
    main()
