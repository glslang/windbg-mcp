# Acquisition and release evidence

Run the helper with Python 3.10 or later; it uses the standard library. Paths below
are relative to this skill directory. Each command requires a new output directory
and preserves source metadata. Downloads are limited to 128 MiB per binary.

## MSRC lookup

```console
python3 scripts/evidence.py msrc CVE-2026-83498 --out /private/tmp/cve-83498-msrc
```

The [official CVRF API](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API/blob/main/docs/swagger.json)
provides `updates/{CVE}` to identify documents and `cvrf/{document-ID}` to retrieve
them using `Accept: application/json`. The helper joins product IDs to names and
preserves exact vulnerability records. It does not guess a release or filename.
Errors, HTML or unexpected formats mean retrieval failed, not that the CVE is absent.

Use [Windows release health](https://learn.microsoft.com/en-us/windows/release-health/)
and its product update histories to check dates, Preview/OOB labels, KBs and
supersedence. Stable means non-preview production updates in the selected product.

## Binary inventory and download

Winbindex is a metadata index; binary bytes come from Microsoft. Its
[source/data layout](https://github.com/m417z/winbindex) and
[ARM64 index](https://github.com/m417z/winbindex-data-arm64) are public. Check the
product lane and PE machine type. Shared updates can name additional Windows
versions; retain that relationship in the manifest.

```console
python3 scripts/evidence.py inventory vertdll.dll --arch x64 --windows 11-24H2 \
  --kb KB5124008 --out /private/tmp/cve-83498-current-index
python3 scripts/evidence.py inventory vertdll.dll --arch x64 --windows 11-24H2 \
  --kb KB5121003 --out /private/tmp/cve-83498-previous-index
python3 scripts/evidence.py download \
  --inventory /private/tmp/cve-83498-current-index/inventory.json \
  --sha256 SELECTED_SHA256 --out /private/tmp/cve-83498-target
```

Choose a hash from `inventory.json`; resolve multiple entries using assembly/path
metadata instead of choosing the first. Repeat download for the reference.
`download.json` records the entry, Microsoft URL, SHA-256 and measured PE identity.
A matching hash verifies consistency with selected metadata. Independently verify
Authenticode/catalog signatures where tooling is available; otherwise record
`not_verified`. Index signature metadata is not a local signature verification.

For missing artifacts, follow the remediation link to
[Microsoft Update Catalog](https://www.catalog.update.microsoft.com/), verify the
product/architecture/KB and download its actual linked Microsoft package URL.
Preserve package hashes and file lists. Extract without installing. Modern
checkpoint/delta packages may require a matching base and Windows servicing tools.
Do not rename a delta into a DLL or borrow a same-named file from another branch.
Report unavailable bases/tooling and preserve completed work.

## Worked selection: CVE-2026-83498

MSRC's September 2026 record, retrieved 2026-09-09, identifies a VBS Enclave issue.
For Windows 11 24H2 x64/ARM64, its remediation is KB5124008, fixed OS build
10.0.26100.9445, with `Supercedence: 5121003`. Other products have different fixed
builds/KBs; do not reuse this pair for every affected product.

The record's `AffectedFiles` lists are empty. Microsoft documents
[vertdll.dll as a VBS enclave API component](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-vertdll),
so it is a defensible **candidate**, not an MSRC-confirmed affected filename.
For 24H2 x64, Winbindex associates file version 10.0.26100.9444 with KB5124008 and
10.0.26100.8972 with KB5121003. File versions differ from the OS builds. Intervening
KB5120998 is labeled Preview and excluded from the stable pair. Recheck Microsoft
update history when using this example; these dated observations are not a permanent
definition of current and previous stable.

A changed vertdll.dll function is evidence about those files. The CVE number does
not by itself establish which function fixes the vulnerability.

## GUI capture fallback

When native MCP is unavailable, the bundled [GUI capture helper](../scripts/gui_capture.py)
can run in an empty, disposable BN6 Personal GUI. For an isolated process use
`--new-instance`, `BN_USER_DIRECTORY` and `BN_QSETTINGS_POSTFIX` as described in
[BN troubleshooting](https://docs.binary.ninja/guide/troubleshooting.html). Merely
changing the user directory can forward the launch to an existing instance.
Put the companion checkout and
this skill's `scripts` directory on that GUI's Python path, with the companion's
dependencies installed, then run from its Python console:

```python
from gui_capture import start

start(
    "/private/tmp/cve-83498-reference/vertdll.dll",
    "/private/tmp/cve-83498-target/vertdll.dll",
    "/absolute/path/to/bindiff",
    "/private/tmp/cve-83498-capture",
)
```

The helper opens only these two files, creates its own companion workspace, records
all match/unmatched pages and up to ten diffs, navigates to a target match, compares
before/after hashes of analysis state and bytes, and writes `capture.json`.
It closes its comparison and workspace. It leaves the views open by default;
`quit_on_finish=True` requests exit of that disposable GUI; confirm it actually
exits before recording quit acceptance. This is a direct companion API
capture, not an MCP transport or live WinDbg test.

If a previous capture shows generation changes caused by displaying the target
function, rerun in a fresh disposable GUI with `prepare_target_rva` set to that
target RVA (an integer, for example `0x1000`). The helper navigates there and waits
for analysis before taking its baseline, recording this preparation in the capture.
It still checks generations across comparison and result navigation. Use an RVA
from the exact target build's prior capture; preparation does not establish CVE
relevance or justify accepting generation changes during the measured run.
