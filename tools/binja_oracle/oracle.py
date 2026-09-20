"""Diff `ioctl_map` against the Binary Ninja companion, by code and by route.

The ARM64 half of the second opinion `tools/ghidra_oracle/` gives x64. See README.md beside this
for what the bench needs, why the two lanes are separate directories, and how to read the answer.

Both halves are replays rather than installs: the companion's is
`binja_windbg_mcp.analysis.ioctl_map` over a checked-in capture, which needs the companion checkout
and its venv but **not** Binary Ninja; this side's is a recorded `ioctl_map` result, or one taken
now by driving a `windbg-mcp` over stdio -- locally on Windows, or through `ssh` from a Mac.
"""

import argparse
import collections
import json
import os
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
COMPANION = pathlib.Path(
    os.environ.get("BINJA_WINDBG_MCP", pathlib.Path.home() / "workspace" / "binja-windbg-mcp")
)
SERVER = REPO / "target" / "debug" / "windbg-mcp.exe"


# ---- this implementation's half ----------------------------------------------------------


def drive(server: list, dispatch: str, profile=None, dump=None, module=None) -> dict:
    """`ioctl_map`'s own answer over stdio, with the build that gave it.

    `server` is a command rather than a path so the same lane reaches a Windows bench from a Mac:
    `--ssh <host>` makes it `ssh <host> <exe>`, and the protocol is the same newline-delimited
    JSON-RPC either way.

    **stderr goes to a file, never to a pipe.** A pipe nobody drains fills once `RUST_LOG` is
    widened and the server blocks mid-request, which reads as a hung debugger
    (`.claude/rules/powershell-scripts.md`). It is kept rather than discarded because over `ssh`
    the same stream carries ssh's own refusals, and "the server closed the pipe" is not a useful
    report of a host that would not let you in.
    """
    with tempfile.NamedTemporaryFile(prefix="binja-oracle-", suffix=".log", delete=False) as log:
        errors = pathlib.Path(log.name)
    proc = subprocess.Popen(
        server,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=errors.open("w"),
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
                tail = errors.read_text(encoding="utf-8", errors="replace").strip().splitlines()
                raise SystemExit(
                    "the server closed the pipe; its last words were:\n  "
                    + ("\n  ".join(tail[-8:]) or "(nothing on stderr)")
                )
            line = line.strip()
            if not line:
                continue
            reply = json.loads(line)
            if reply.get("id") == msg["id"]:
                return reply

    def tool(name, arguments):
        reply = call("tools/call", {"name": name, "arguments": arguments})
        if "error" in reply:
            raise SystemExit(f"{name} failed: " + json.dumps(reply["error"])[:400])
        return reply["result"].get("structuredContent", {})

    started = call(
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "binja-oracle", "version": "0"},
        },
    )
    # **The build that answered, recorded beside the figures it gave.** A number measured against
    # the VM is a reading of the binary that answered rather than of the checkout beside it, and
    # nothing else in this result says which (`.claude/rules/measurement-provenance.md`).
    info = started["result"]["serverInfo"]
    call("notifications/initialized", {}, notify=True)
    # A live kernel **by profile, never by connection string**: the target's debug key stays on the
    # host that resolves it and out of this argument, this transcript and the recorded JSON.
    opened = (
        tool("attach_kernel", {"profile": profile, "timeout_ms": 180000})
        if profile
        else tool("open_dump", {"path": dump})
    )
    if opened.get("status") != "ok":
        raise SystemExit("the target did not open: " + json.dumps(opened)[:400])
    session = opened["session_id"]
    try:
        if profile:
            # A fresh attach's inventory holds `nt` and little else, so a driver loaded before the
            # debugger dialled in is absent from the inventory rather than from the target.
            tool("modules", {"session_id": session, "refresh": True, "limit": 1})
        answer = tool("ioctl_map", {"session_id": session, "dispatch": dispatch})
        if answer.get("status") != "ok":
            raise SystemExit("ioctl_map failed: " + json.dumps(answer)[:400])
        return {
            "server": info,
            "target": {"profile": profile} if profile else {"dump": dump},
            "dispatch": dispatch,
            "module": module or (answer.get("dispatch") or {}).get("module"),
            "result": answer,
        }
    finally:
        tool("end_session", {"session_id": session})
        proc.stdin.close()
        proc.wait(timeout=60)
        errors.unlink(missing_ok=True)


# ---- the companion's half ----------------------------------------------------------------


def ask_companion(checkout: pathlib.Path, python: pathlib.Path, fixture: pathlib.Path) -> dict:
    """`binja_windbg_mcp.analysis.ioctl_map` over one of the companion's captures.

    Run as a child under the companion's own interpreter, because it needs a Python this lane does
    not: 3.13 with the companion's pinned `pydantic`, which is what `.venv` beside the checkout is.
    Binary Ninja is **not** needed -- a capture is the adapter's output, and the analysis over it is
    plain Python.
    """
    script = (
        "import json, sys\n"
        f"sys.path.insert(0, {str(checkout)!r})\n"
        "from binja_windbg_mcp import analysis\n"
        "from binja_windbg_mcp.core import Budget\n"
        f"doc = json.load(open({str(fixture)!r}))\n"
        "out = analysis.ioctl_map(doc['capture'], Budget(seconds=120))\n"
        "json.dump({'result': out, 'identity': doc.get('identity'),\n"
        "           'file_sha256': doc.get('file_sha256'),\n"
        "           'architecture': doc.get('architecture'),\n"
        "           'analysis_version': doc.get('analysis_version'),\n"
        "           'file_version': doc.get('file_version')}, sys.stdout)\n"
    )
    done = subprocess.run(
        [str(python), "-c", script], capture_output=True, text=True, encoding="utf-8"
    )
    # **A companion that did not run is not an empty map.** Reading its stdout past a non-zero exit
    # turns a missing checkout or an unimportable pydantic into "the second opinion found no
    # cases", which is the shape of a real result and agrees with nothing.
    if done.returncode != 0:
        tail = (done.stdout + done.stderr).strip().splitlines()[-8:]
        raise SystemExit(
            f"the companion replay exited {done.returncode}; its answer is not usable:\n  "
            + "\n  ".join(tail)
        )
    return json.loads(done.stdout)


# ---- the diff ------------------------------------------------------------------------------
#
# **Every way these two answers can differ, and which side of the line it is on.** Written after
# three review rounds landed on one of them (#354), because enumerating the cases once is cheaper
# than meeting them one at a time -- and the fifth below was found by doing it.
#
#   1. The **build** the two halves answered for. Gated first; a mismatch ends the run at exit 2,
#      because no RVA in one build is an RVA in the other.
#   2. A **code only one side has**. This side's alone is a finding. The companion's alone is one
#      too, unless every record carrying it came from a jump table by its own evidence -- this
#      walk drops a table slot that goes to the default, and the companion publishes it.
#   3. A code **routed elsewhere**. Inside the forward window it is the two case-address
#      conventions; outside it, a finding.
#   4. A code with **no address** on one side or both. Compared as a code, never as a route, and
#      the count of such cases is printed.
#   5. A **length** both sides prove differently **on a paired route**. A finding. A length on a
#      record that did not pair, or carries no address, has no counterpart to compare against.
#
# Everything else these answers carry is either derived from the code (`device_type`, `function`,
# `method`, `required_access` -- identical whenever the codes are) or has no counterpart on the
# other side (`accepted`, `proved`, `untracked`, `unresolved`), and those are printed rather than
# compared. This list is what the lane checks, not a proof that nothing else can differ.


def norm(code) -> str:
    return f"0x{int(str(code), 16):08x}"


def rva(value):
    return None if value is None else int(str(value), 16)


def codes(cases: list) -> set:
    """Every code in the answer, whether or not its landing site has an address.

    **`case_rva` is optional on both sides** -- `structured::IoctlCase` documents it absent for a
    case whose landing site is in no module the session knows -- so building the code sets out of
    the routes below would drop such a code from the comparison entirely, and report a code both
    implementations found as one-sided because one of them could not attribute its address.
    """
    return {norm(case["code"]) for case in cases}


def placed(cases: list) -> dict:
    """code -> [(destination or None, record)], sorted, addressless records last.

    **Every record is here, whether or not it carries an address.** `case_rva` is optional on both
    sides -- `structured::IoctlCase` documents it absent for a landing site in no module the
    session knows -- and a map that dropped those would leave them out of the reconciliation as
    well, which is where a record one side has and the other does not is caught. They cannot pair
    on an address, so they pair on the code, positionally, against the other side's addressless
    records for that code.

    The **record** travels with its address on purpose. Classifying by a `(code, rva)` key instead
    means several records collapse into one question, and the answer is then the most permissive of
    them: a switch slot and a missed comparison converging on one handler would both read as
    switch-derived, and the comparison miss disappears.

    Both implementations answer per record, and a code legitimately has more than one: `mountmgr`
    routes each of its codes from a host context and a silo one.
    """
    by_code = collections.defaultdict(list)
    for case in cases:
        by_code[norm(case["code"])].append((rva(case.get("case_rva")), case))
    return {
        code: sorted(rows, key=lambda row: (row[0] is None, row[0] or 0))
        for code, rows in by_code.items()
    }


def pair_routes(ours: dict, theirs: dict, window: int, slotted=lambda case: False):
    """Pair the two sides' records per code, and hand back what did not pair.

    The companion names *"the first source-mapped statement"* of a case and this walk names the
    block the branch enters, so on A64 -- where a case block opens by materialising an address --
    the companion's address is **at or after** ours by the length of that prologue. Measured: a
    constant `0x18` on every one of HEVD's 29 cases, and `0`, `4`, `8`, `0xc` or `0x10` across
    `rdyboost`'s, because the prologues differ per case.

    So the rule is a **bound**, not a fitted constant: forward, and shorter than the shortest gap
    between two case blocks on these drivers, so a destination cannot pair with its neighbour. A
    displacement chosen to make the most records line up would be a parameter tuned to hide
    disagreement; a stated window is a property of the two conventions, applied uniformly, and
    anything outside it is reported.

    **Table-derived records are paired first**, which only matters when two companion records sit
    at one address with different provenance and one of them must be the surplus. Either choice is
    arbitrary on the addresses alone, so it is made in the direction that reports: the comparison
    record is the one left over, and the lane calls it a difference rather than hiding it behind
    its switch-derived twin.

    **Records with no address pair with each other**, by code and in order, once the addressed
    ones are done. They cannot pair on a destination, and refusing to pair them at all would make
    every such case a difference on both sides at once; leaving them out of the pairing entirely
    -- which is what two review rounds of this function did -- loses the case where one side has
    one and the other does not.

    Returns the matched pairs, the displacement spread, and the **records** each side has left.
    """
    paired, spread = [], collections.Counter()
    unpaired_ours, unpaired_theirs = [], []
    for code in sorted(set(ours) | set(theirs)):
        mine, yours = list(ours.get(code, [])), list(theirs.get(code, []))
        yours = sorted(yours, key=lambda row: (row[0] is None, not slotted(row[1]), row[0] or 0))
        taken = set()
        for where, mine_case in mine:
            if where is None:
                continue
            hit = next(
                (
                    index
                    for index, (other, _) in enumerate(yours)
                    if index not in taken
                    and other is not None
                    and 0 <= other - where <= window
                ),
                None,
            )
            if hit is None:
                unpaired_ours.append(mine_case)
                continue
            taken.add(hit)
            spread[yours[hit][0] - where] += 1
            paired.append((mine_case, yours[hit][1]))
        # Then the addressless ones, against each other, in order.
        spare = [index for index, (other, _) in enumerate(yours) if other is None]
        for _, mine_case in [row for row in mine if row[0] is None]:
            if spare:
                index = spare.pop(0)
                taken.add(index)
                paired.append((mine_case, yours[index][1]))
            else:
                unpaired_ours.append(mine_case)
        unpaired_theirs += [case for index, (_, case) in enumerate(yours) if index not in taken]
    return paired, spread, unpaired_theirs, unpaired_ours


def identity_of(result: dict, module: str):
    for image in result.get("images") or []:
        if image.get("module") == module:
            return image.get("identity")
    return None


def same_build(ours, theirs) -> tuple:
    """Whether the two halves answered for the same image, and what differs if not.

    `timestamp`+`size` is the coordinate this repo joins a module on (`docs/coordinates.md`); the
    PDB identity is compared when both sides carry one, and a live driver whose symbols are still
    deferred carries none.
    """
    if not ours or not theirs:
        return False, ["one half carries no image identity"]
    differs = [
        f"{field}: ioctl_map {ours.get(field)!r}, capture {theirs.get(field)!r}"
        for field in ("timestamp", "size")
        if ours.get(field) != theirs.get(field)
    ]
    mine, yours = ours.get("pdb"), theirs.get("pdb")
    if mine and yours and (mine.get("guid"), mine.get("age")) != (yours.get("guid"), yours.get("age")):
        differs.append(f"pdb: ioctl_map {mine!r}, capture {yours!r}")
    return not differs, differs


def table_sites(result: dict) -> set:
    """The switch sites this walk resolved, as integers."""
    return {
        rva((table.get("at") or {}).get("rva"))
        for table in result.get("tables") or []
        if (table.get("at") or {}).get("rva") is not None
    }


def from_a_table(case: dict, sites: set, same_build: bool) -> bool:
    """Whether a companion record is a jump-table slot, **by its own evidence**.

    The companion publishes `{"kind": "switch", "site": ...}` beside `goto_target` on a record it
    took from a table, and `{"kind": "comparison", ...}` on one it took from a compare. That is
    provenance; a count is not. Measured 2026-09-20: `mountmgr`'s 45 surplus records all carry
    `switch` evidence at `0x1940c`, `0x1944c` and `0x19730`, which are exactly the three tables
    this side resolved -- while `rdyboost`'s two carry `comparison` and are real misses.

    The site is matched against this walk's own tables when the two halves answered for the same
    binary. Across builds the RVAs mean nothing, so only the kind is read, and the caller says so.
    """
    for evidence in case.get("evidence") or []:
        if evidence.get("kind") != "switch":
            continue
        if not same_build:
            return True
        site = rva(evidence.get("site"))
        if site is not None and site in sites:
            return True
    return False


def dropped_slots(result: dict) -> int:
    """Table entries this implementation read and did **not** turn into a case.

    It publishes both numbers per table, so the count needs no opinion about which arm is the
    default -- which is the point, because naming one from the data is the inference
    `tools/ghidra_oracle/README.md` refuses on x64.
    """
    return sum(
        (table.get("entries") or 0) - (table.get("followed") or 0)
        for table in result.get("tables") or []
    )


def compare(tool: dict, companion: dict, module: str, window=0x20, allow_mismatch=False) -> int:
    ours, theirs = tool["result"], companion["result"]
    our_cases, their_cases = ours.get("cases") or [], theirs.get("cases") or []
    print(f"module {module}")
    print(f"  ioctl_map  : {tool['server'].get('name')} {tool['server'].get('version')}, "
          f"{len(our_cases)} record(s), {len(codes(our_cases))} code(s), "
          f"{len(ours.get('tables') or [])} table(s)")
    print(f"  companion  : Binary Ninja {companion.get('analysis_version')} capture, "
          f"{len(their_cases)} record(s), {len(codes(their_cases))} code(s)")

    # **The identity gate, which is this lane's whole claim to be comparing anything.** The x64
    # lane's third trap is that the image has to be the one the dump mapped; here the two halves
    # are a capture taken once and a driver read off a live target, and the target's copy moves
    # underneath the capture without anything in either answer saying so.
    mine = identity_of(ours, module)
    yours = companion.get("identity")
    agreed, differs = same_build(mine, yours)
    print()
    print("build")
    print(f"  ioctl_map  : {json.dumps(mine)}")
    print(f"  capture    : {json.dumps(yours)}  sha256 {companion.get('file_sha256')}")
    if not agreed:
        for line in differs:
            print(f"  DIFFERENT  : {line}")
        print("  -- RVAs from two builds are not comparable, so the routes below are not read at")
        print("     all and only the code sets are. Whether those agree is weaker evidence than")
        print("     this lane is for: same source, different compile.")
        if not allow_mismatch:
            print()
            print("  Pass --allow-build-mismatch to see the code sets anyway. Capturing the build")
            print("  the target is actually running is what makes the rest of this lane run.")
            return 2

    # **The companion is asked about the same dispatch routine this side was.** `ioctl_map`
    # answers for one `--dispatch`; `analysis.ioctl_map` takes the union of majors 14 and 15, so a
    # driver registering a different callback for *internal* device control would have every code
    # from that second routine read as one only the companion found. Both sides name the root the
    # same way, as the registered function's RVA, so the narrowing is a comparison rather than a
    # guess -- and it is applied here rather than to the capture, because what the capture holds
    # is not this lane's to trim. Raised on review of #354.
    our_dispatch = rva((ours.get("dispatch") or {}).get("rva"))
    if agreed and our_dispatch is not None:
        elsewhere = [
            case
            for case in their_cases
            if case.get("dispatch_rva") is not None
            and rva(case["dispatch_rva"]) != our_dispatch
        ]
        if elsewhere:
            roots = sorted({case["dispatch_rva"] for case in elsewhere})
            print(f"  companion records from another dispatch: {len(elsewhere)} at {roots}"
                  f" -- set aside; this side answered for {(ours.get('dispatch') or {}).get('rva')}")
            their_cases = [case for case in their_cases if case not in elsewhere]

    our_codes, their_codes = codes(our_cases), codes(their_cases)
    our_routes, their_routes = placed(our_cases), placed(their_cases)
    unplaced = [
        (name, sum(1 for case in cases if not case.get("case_rva")))
        for name, cases in (("ioctl_map", our_cases), ("companion", their_cases))
    ]
    print()
    print(f"{'code':<14}{'ioctl_map':<12}{'companion':<12}")
    print("-" * 44)
    for code in sorted(our_codes | their_codes):
        here = [code in our_codes, code in their_codes]
        print(
            f"{code:<14}"
            + "".join(f"{'yes' if flag else 'NO':<12}" for flag in here)
            + ("" if all(here) else "  <-- differs")
        )
    only_ours = sorted(our_codes - their_codes)
    only_theirs = sorted(their_codes - our_codes)

    verdict = 0
    print()
    print(f"  agreed codes            : {len(our_codes & their_codes)}")
    print(f"  only `ioctl_map`        : {only_ours or 'none'}")
    print(f"  only the companion      : {only_theirs or 'none'}")
    for name, count in unplaced:
        if count:
            print(f"  {name} cases with no case_rva: {count} -- compared as codes, not as routes")

    # **The surplus, accounted for by a number rather than explained away.** The companion
    # publishes a record per jump-table slot, the default's included; this walk drops a slot whose
    # target is the bounds check's own branch, so it emits fewer records **by design**. What
    # settles whether that is the whole of the difference is a count both sides already publish:
    # the slots this side read and did not take. It needs no opinion about which arm is the
    # default -- naming one from the data is the inference `tools/ghidra_oracle/README.md` refuses
    # on x64 -- and it is a count of records, so it survives the two halves being different builds.
    dropped = dropped_slots(ours)
    sites = table_sites(ours)
    unrouted = [case for case in their_cases if norm(case["code"]) in set(only_theirs)]
    slotted = [case for case in unrouted if from_a_table(case, sites, agreed)]
    unexplained = [case for case in unrouted if case not in slotted]
    print()
    print(f"  table slots `ioctl_map` dropped: {dropped}"
          f"  {[(t.get('entries'), t.get('followed')) for t in ours.get('tables') or []]}")
    print(f"  companion records on codes it does not route: {len(unrouted)}"
          f" over {len(only_theirs)} code(s)")
    caveat = "" if agreed else " (kind only, since the sites are another build's)"
    print(f"    from a jump table by their own evidence: {len(slotted)}{caveat}")
    print(f"    from a compare, so a real difference    : {len(unexplained)}")
    for case in unexplained[:8]:
        print(f"      {norm(case['code'])} at {case.get('case_rva')}")
    # **Attribution here, the count at route level.** Equal counts are not provenance: one missed
    # compare beside one dropped slot balances, and suppressing that would hide exactly the finding
    # this lane exists to make. So a surplus record is set aside only when the companion's own
    # evidence says it came from a switch this walk resolved.
    #
    # **What is deliberately not checked here is `dropped`**, because these two count different
    # things: `dropped` counts table *slots*, and `unrouted` counts only the records whose code is
    # absent from this side's set. A driver whose dropped slots carry codes it also handles
    # elsewhere has no unrouted records at all and a non-zero `dropped`, and comparing them would
    # call that a difference while the route level correctly accounts for it. Both raised on review
    # of #354, the second against the fix for the first.
    if unexplained:
        print("  -- those are records the companion took from a compare, so they are a real")
        print("     difference rather than this side's default-slot reporting.")
        verdict = 1
    elif unrouted:
        print("  -- every one carries switch evidence, so the code-set difference is reporting;")
        print("     whether their *number* is the slots dropped here is the route check below.")

    if not agreed:
        print()
        print("  Across two builds that is consistent-with rather than evidence-of: the counts")
        print("  come from different compiles of the same source, and no RVA below was read.")
        return 2
    if only_ours:
        verdict = 1

    # **The routes, read through the convention between them.** Comparing destinations without
    # this reports a deliberate difference in *naming a case's address* as disagreement, once per
    # record -- 29 times on HEVD, where every case is a constant 0x18 apart.
    shared = set(our_routes) & set(their_routes)
    paired, spread, extra, lost = pair_routes(
        our_routes, their_routes, window, lambda case: from_a_table(case, sites, agreed)
    )
    print()
    print("routes")
    print(f"  window applied          : 0x0 to {window:#x}, forward only")
    if len(spread) == 1 and paired:
        print(f"  every paired record lands {next(iter(spread)):+#x} from ours -- one convention, "
              f"not a disagreement")
    elif spread:
        print(f"  displacements           : {dict(sorted(spread.items()))}")
    unpaired = {norm(case["code"]) for case in extra + lost}
    routed = sorted(code for code in shared if code not in unpaired)
    print(f"  codes routed the same   : {len(routed)} of {len(shared)}")
    # **The surplus is every companion record that did not pair, and nothing is assembled.**
    # Four review rounds of #354 were this set being built from parts -- placed records only, then
    # placed plus the companion-only codes -- and each round found a record that fell between the
    # parts: one with no address, then one with no address whose code was shared. `pair_routes`
    # pairs every record now, so what is left over is the whole of the difference by construction.
    surplus = extra
    surplus_slotted = [case for case in surplus if from_a_table(case, sites, agreed)]
    grouped = collections.Counter(
        rva(case.get("case_rva")) for case in surplus if case.get("case_rva")
    )
    unplaced_surplus = sum(1 for case in surplus if not case.get("case_rva"))
    print(f"  companion-only records  : {len(surplus)}"
          + (f" ({unplaced_surplus} with no address)" if unplaced_surplus else ""))
    for where, count in sorted(grouped.items(), key=lambda kv: -kv[1])[:12]:
        print(f"    -> {where:#x}  {count} record(s)")
    print(f"  `ioctl_map`-only records: {len(lost)}")
    for case in lost[:12]:
        where = case.get("case_rva")
        print(f"    {norm(case['code'])} at {where or 'no address'}")

    print()
    if len(surplus) == len(surplus_slotted) == dropped and dropped:
        print(f"  all {len(surplus)} companion-only record(s) carry switch evidence, and {dropped}")
        print("  is what this side dropped -- so at route level too the two differ in what they")
        print("  report rather than in what they recovered.")
    elif surplus or dropped:
        print(f"  {len(surplus)} companion-only record(s), {len(surplus_slotted)} of them from a")
        print(f"  jump table, against {dropped} dropped slot(s): the route-level surplus is not")
        print("  accounted for by the default slots.")
        verdict = 1
    if lost:
        verdict = 1

    # **What this fixture cannot decide.** Two implementations reporting no buffer size is correct
    # behaviour agreeing with correct behaviour when the driver's length checks are not in the
    # dispatch routine's case blocks -- so a clean run here is not evidence that either proves one.
    def proves(cases):
        return sum(1 for case in cases if case.get("in_size") or case.get("out_size"))

    # A length check this side *saw* and could not call exact is the tier below a proved size, and
    # it is the one worth printing beside the zero: `null` is "not proven" rather than "no
    # requirement", so a fixture where both answer null has asked the two implementations nothing.
    checked = sum(1 for case in our_cases if case.get("evidence"))
    proved, theirs_proved = proves(our_cases), proves(their_cases)
    print()
    print(f"  sizes proved: `ioctl_map` {proved} (length checks seen: {checked}), "
          f"companion {theirs_proved}")
    # **Per paired route, not per code.** One code can be routed from more than one site with a
    # different length proved at each, and keying by code alone keeps whichever record came last:
    # `(32, 64)` against `(16, 64)` then ends at `64` on both sides and reads as agreement.
    # Comparing on the pairs is the only place a case of one side has a counterpart in the other.
    # Raised on review of #354, against the check added the round before.
    disputed = [
        (norm(mine["code"]), field, mine[field], yours[field])
        for mine, yours in paired
        for field in ("in_size", "out_size")
        if mine.get(field) is not None
        and yours.get(field) is not None
        and mine[field] != yours[field]
    ]
    for code, field, mine, yours in disputed:
        print(f"    {code} {field}: `ioctl_map` {mine}, companion {yours}  <-- differs")
    if proved or theirs_proved:
        print(f"    compared on {len(paired)} paired route(s); a size on a record with no address,"
              " or on one that did not pair, has no counterpart to compare against")
    if disputed:
        verdict = 1
    if not proved and not theirs_proved:
        print("  -- neither proves one here, which separates the two implementations not at all.")

    for name, entries in (("untracked", ours.get("untracked")), ("unresolved", ours.get("unresolved"))):
        if entries:
            print(f"  `ioctl_map` {name}: {len(entries)}")
    if theirs.get("unresolved"):
        print(f"  companion unresolved: {len(theirs['unresolved'])}")
    return verdict


# ---- the lane ------------------------------------------------------------------------------


def selftest() -> int:
    """The lane's own failure modes, since a diff that cannot fail is the thing this replaces."""
    build = {"timestamp": 1, "size": 2}
    images = [{"module": "d", "identity": build}]

    def tool(cases, tables=(), dispatch=None):
        result = {"cases": list(cases), "tables": list(tables), "images": images}
        if dispatch is not None:
            result["dispatch"] = {"rva": hex(dispatch)}
        return {"server": {"name": "x", "version": "0"}, "result": result}

    def companion(cases, identity=build):
        return {"result": {"cases": list(cases)}, "identity": identity, "analysis_version": "t"}

    def case(code, where, evidence=()):
        record = {"code": code, "evidence": list(evidence)}
        if where is not None:
            record["case_rva"] = hex(where)
        return record

    def table(site, entries, followed):
        return {"at": {"rva": hex(site)}, "entries": entries, "followed": followed}

    switch = [{"kind": "switch", "site": "0x500"}, {"kind": "goto_target", "site": "0x500"}]
    compare_at = [{"kind": "comparison", "site": "0x900"}]

    checks = [
        ("agreement", tool([case("0x1", 0x100)]), companion([case("0x1", 0x100)]), 0),
        ("a convention offset is not a finding",
         tool([case("0x1", 0x100), case("0x2", 0x200)]),
         companion([case("0x1", 0x118), case("0x2", 0x218)]), 0),
        ("a destination past the window is a finding, not a convention",
         tool([case("0x1", 0x100)]), companion([case("0x1", 0x100 + 0x40)]), 1),
        ("a code only one side has fails",
         tool([case("0x1", 0x100)]), companion([case("0x1", 0x100), case("0x2", 0x200)]), 1),
        ("a route only one side has fails",
         tool([case("0x1", 0x100), case("0x1", 0x180)]),
         companion([case("0x1", 0x100)]), 1),
        ("codes reached only through dropped slots are accounted for",
         tool([case("0x1", 0x100)], [table(0x500, 3, 1)]),
         companion([case("0x1", 0x100), case("0x2", 0x900, switch),
                    case("0x3", 0x900, switch)]), 0),
        ("one more companion record than slots dropped is a finding",
         tool([case("0x1", 0x100)], [table(0x500, 3, 1)]),
         companion([case("0x1", 0x100), case("0x2", 0x900, switch), case("0x3", 0x900, switch),
                    case("0x4", 0x900, switch)]), 1),
        # Codex's P1 on #354: with one missed compare beside one dropped slot the counts balance,
        # and a lane that read equality as provenance would exit 0 over a code only one side has.
        ("a missed compare is a finding although the count balances",
         tool([case("0x1", 0x100)], [table(0x500, 2, 1)]),
         companion([case("0x1", 0x100), case("0x2", 0x900, compare_at)]), 1),
        # And the round after that: dropped slots whose codes this side *does* recover elsewhere
        # leave nothing unrouted, so a code-level check against `dropped` would call the shape a
        # difference. The route level is where that count belongs.
        ("dropped slots reusing a shared code are accounted for at route level",
         tool([case("0x1", 0x100)], [table(0x500, 2, 1)]),
         companion([case("0x1", 0x100), case("0x1", 0x900, switch)]), 0),
        # And the round after that: two companion records at one address with different
        # provenance. Either can be the surplus on the addresses alone, so the table-derived one
        # is paired first and the compare is what is left over -- in **both** input orders, or the
        # classification would depend on the capture's record order.
        ("a compare sharing an address with a slot is still a finding",
         tool([case("0x1", 0x100)], [table(0x500, 2, 1)]),
         companion([case("0x1", 0x100, switch), case("0x1", 0x100, compare_at)]), 1),
        ("the same, with the records the other way round",
         tool([case("0x1", 0x100)], [table(0x500, 2, 1)]),
         companion([case("0x1", 0x100, compare_at), case("0x1", 0x100, switch)]), 1),
        # And its P2: a case whose landing site is in no known module has no `case_rva` at all.
        ("a code with no case_rva is still compared",
         tool([case("0x1", 0x100)]), companion([case("0x1", 0x100), case("0x2", None)]), 1),
        ("a code with no case_rva on both sides agrees",
         tool([case("0x1", 0x100), case("0x2", None)]),
         companion([case("0x1", 0x100), case("0x2", None)]), 0),
        # Found by enumerating rather than by a review round: the sizes were counted on each
        # side and never compared, so two implementations proving one length each, differently,
        # read as `1, 1`.
        ("a length both sides prove differently is a finding",
         tool([dict(case("0x1", 0x100), in_size=32)]),
         companion([dict(case("0x1", 0x100), in_size=64)]), 1),
        ("the same length on both sides is not",
         tool([dict(case("0x1", 0x100), in_size=32)]),
         companion([dict(case("0x1", 0x100), in_size=32)]), 0),
        ("a length only one side proves is not a finding",
         tool([dict(case("0x1", 0x100), in_size=32)]),
         companion([case("0x1", 0x100)]), 0),
        # Round four: the same code at two sites with different lengths. Keying by code kept the
        # last, so (32, 64) against (16, 64) ended at 64 on both sides and read as agreement.
        ("one site's length disagreeing is a finding although the other's agrees",
         tool([dict(case("0x1", 0x100), in_size=32), dict(case("0x1", 0x200), in_size=64)]),
         companion([dict(case("0x1", 0x100), in_size=16),
                    dict(case("0x1", 0x200), in_size=64)]), 1),
        # And a companion-only record with no address at all: absent from the route map, so the
        # code level's deferral to the route reconciliation would have lost it entirely. It has to
        # be **attributable** — switch evidence at a table this side resolved — or the code level
        # catches it first and the reconciliation is never asked, which is how the first draft of
        # this case passed with the reconciliation mutated out.
        ("an unplaced switch record still counts against the slots dropped",
         tool([case("0x1", 0x100)], [table(0x500, 2, 1)]),
         companion([case("0x1", 0x100), case("0x2", 0x900, switch),
                    case("0x3", None, switch)]), 1),
        # Round five: an extra addressless record for a code **both** sides have. It was in
        # neither half of the assembled surplus -- `placed()` dropped it and its code was not
        # companion-only -- so the lane printed the count and exited 0.
        ("an extra addressless record for a shared code is a finding",
         tool([case("0x1", 0x100)]),
         companion([case("0x1", 0x100), case("0x1", None, compare_at)]), 1),
        ("and the same record on this side is one too",
         tool([case("0x1", 0x100), case("0x1", None)]),
         companion([case("0x1", 0x100)]), 1),
        # And the companion answering for a *second* dispatch routine: `analysis.ioctl_map` takes
        # majors 14 and 15, so a driver with a separate internal-device-control handler hands back
        # the union while this side answered for one routine.
        ("codes from another dispatch routine are set aside, not reported",
         tool([dict(case("0x1", 0x100), dispatch_rva="0x10")], dispatch=0x10),
         companion([dict(case("0x1", 0x100), dispatch_rva="0x10"),
                    dict(case("0x2", 0x200), dispatch_rva="0x20")]), 0),
        ("a build mismatch refuses to compare",
         tool([case("0x1", 0x100)]),
         companion([case("0x1", 0x100)], {"timestamp": 9, "size": 2}), 2),
    ]
    bad = 0
    for name, ours, theirs, want in checks:
        print(f"\n=== {name} (expect {want}) ===")
        got = compare(ours, theirs, "d")
        if got != want:
            print(f"  SELFTEST FAILED: {name} answered {got}")
            bad = 1
    # The three middle cases are the set worth stating together: a code the companion reaches only
    # through slots this side dropped is **not** a finding, which is what stops `mountmgr`'s 45
    # from being reported as 45; one more record than slots dropped **is**; and a surplus record
    # the companion took from a *compare* is one whatever the count says, which is what stops the
    # subtraction from being a blanket licence.
    print("\nselftest: " + ("FAILED" if bad else "every case answered as written"))
    return bad


def half(path: pathlib.Path, which: str) -> dict:
    """One half of a recorded run, taken from a `--record` file or from a file holding it alone."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc[which] if which in doc else doc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=pathlib.Path,
                        help="a companion capture, e.g. <checkout>/tests/fixtures/"
                             "mountmgr-arm64-bn6.json")
    parser.add_argument("--companion", type=pathlib.Path, default=COMPANION)
    parser.add_argument("--companion-python", type=pathlib.Path,
                        help="default: `.venv/bin/python` under --companion")
    parser.add_argument("--companion-json", type=pathlib.Path,
                        help="a replay recorded earlier, instead of running one")
    parser.add_argument("--tool-json", type=pathlib.Path,
                        help="an `ioctl_map` answer recorded earlier, instead of taking one")
    parser.add_argument("--dispatch", help="the dispatch routine, e.g. `mountmgr!MountMgrDeviceControl`")
    parser.add_argument("--profile", help="attach this kernel connection profile, by name")
    parser.add_argument("--dump", help="open this dump instead")
    parser.add_argument("--server", default=str(SERVER), help="the windbg-mcp to drive")
    parser.add_argument("--ssh", help="run --server on this host over ssh, which is what makes "
                                      "the lane runnable from a Mac")
    parser.add_argument("--module", help="which image the capture is of; default: the dispatch's")
    parser.add_argument("--record", type=pathlib.Path, help="write both halves' answers here")
    parser.add_argument(
        "--route-window",
        default="0x20",
        help="how far after this walk's case address the companion's may name the same case",
    )
    parser.add_argument("--allow-build-mismatch", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        raise SystemExit(selftest())
    if not args.capture and not args.companion_json:
        raise SystemExit("give --capture (a companion fixture) or --companion-json")

    if args.companion_json:
        companion = half(args.companion_json, "companion")
    else:
        python = args.companion_python or args.companion / ".venv" / "bin" / "python"
        for path in (args.companion / "binja_windbg_mcp" / "analysis.py", python, args.capture):
            if not pathlib.Path(path).exists():
                raise SystemExit(f"not found: {path}")
        companion = ask_companion(args.companion, python, args.capture)

    if args.tool_json:
        tool = half(args.tool_json, "tool")
    else:
        if not args.dispatch or not (args.profile or args.dump):
            raise SystemExit("give --tool-json, or --dispatch with --profile or --dump")
        server = ([ "ssh", args.ssh ] if args.ssh else []) + [args.server]
        tool = drive(server, args.dispatch, args.profile, args.dump, args.module)

    module = args.module or tool.get("module")
    if not module:
        raise SystemExit("which image is this? pass --module")
    if args.record:
        args.record.write_text(
            json.dumps({"tool": tool, "companion": companion}, indent=1) + "\n", encoding="utf-8"
        )
        print(f"recorded both halves in {args.record}")
    raise SystemExit(
        compare(tool, companion, module, rva(args.route_window), args.allow_build_mismatch)
    )


if __name__ == "__main__":
    main()
