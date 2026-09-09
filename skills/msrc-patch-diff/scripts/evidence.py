#!/usr/bin/env python3
"""Fetch MSRC evidence and exact, hash-verified Windows binaries; never execute them."""

import argparse
import gzip
import hashlib
import io
import json
import re
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API = "https://api.msrc.microsoft.com/cvrf/v3.0"
INDEX = {
    "x64": "https://winbindex.m417z.com/data",
    "arm64": "https://m417z.com/winbindex-data-arm64",
}
MACHINES = {"x64": 0x8664, "arm64": 0xAA64}
MAX_METADATA = 32 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024


def checked(value, pattern, label):
    if not re.fullmatch(pattern, value):
        raise ValueError(f"invalid {label}")
    return value


def filename(value):
    return checked(
        value.lower(), r"[a-z0-9_][a-z0-9_.-]*\.(dll|exe|sys)", "PE filename"
    )


def fetch(url, limit):
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "msrc-patch-diff/1"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("download exceeded size limit")
        return data, response.url


def save_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=True)
        stream.write("\n")


def provenance(url, final_url, data):
    # Symbol-server redirects may contain temporary signed download credentials.
    final = urllib.parse.urlsplit(final_url)
    return {
        "url": url,
        "final_url": urllib.parse.urlunsplit(final._replace(query="", fragment="")),
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def products(tree):
    found = {}
    if isinstance(tree, dict):
        if "ProductID" in tree and "Value" in tree:
            found[str(tree["ProductID"])] = tree["Value"]
        for value in tree.values():
            found.update(products(value))
    elif isinstance(tree, list):
        for value in tree:
            found.update(products(value))
    return found


def extract_cve(document, cve):
    records = [v for v in document["Vulnerability"] if v.get("CVE") == cve]
    if len(records) != 1:
        raise ValueError(f"expected one exact {cve} record, found {len(records)}")
    names = products(document["ProductTree"])
    record = records[0]
    ids = {
        str(pid)
        for group in ("ProductStatuses", "Remediations")
        for entry in record.get(group, [])
        for pid in entry.get("ProductID", [])
    }
    return {
        "vulnerability": record,
        "products": {pid: names.get(pid) for pid in sorted(ids)},
    }


def msrc(args):
    cve = checked(args.cve.upper(), r"CVE-[0-9]{4}-[0-9]{4,}", "CVE")
    url = f"{API}/updates/{cve}"
    raw, final = fetch(url, MAX_METADATA)
    (args.out / "updates.json").write_bytes(raw)
    updates = json.loads(raw)["value"]
    sources = [provenance(url, final, raw)]
    records = []
    for update in updates:
        document_id = checked(update["ID"], r"[0-9]{4}-[A-Za-z]{3}", "CVRF document ID")
        url = f"{API}/cvrf/{document_id}"
        raw, final = fetch(url, MAX_METADATA)
        (args.out / f"{document_id}.json").write_bytes(raw)
        records.append(
            {"document_id": document_id, **extract_cve(json.loads(raw), cve)}
        )
        sources.append(provenance(url, final, raw))
    if not records:
        raise ValueError(
            "MSRC returned no CVRF documents; verify the CVE/page before proceeding"
        )
    save_json(
        args.out / "msrc.json", {"cve": cve, "sources": sources, "records": records}
    )
    print(f"Saved {len(records)} MSRC record(s) to {args.out / 'msrc.json'}")


def inventory_rows(data, arch, windows, kb):
    rows = []
    for sha, entry in data.items():
        info = entry.get("fileInfo", {})
        if info.get("machineType") != MACHINES[arch]:
            continue
        associations = []
        for lane, updates in entry.get("windowsVersions", {}).items():
            if kb not in updates:
                continue
            update = updates[kb]
            shared = update.get("updateInfo", {}).get("otherWindowsVersions", [])
            if windows == lane or windows in shared:
                associations.append(
                    {"indexed_windows": lane, "kb": kb, "metadata": update}
                )
        if associations:
            checked(sha, r"[a-f0-9]{64}", "index SHA-256")
            rows.append(
                {"sha256": sha, "file_info": info, "associations": associations}
            )
    return sorted(rows, key=lambda row: row["sha256"])


def inventory(args):
    name = filename(args.filename)
    kb = checked(args.kb.upper(), r"KB[0-9]+", "KB")
    url = f"{INDEX[args.arch]}/by_filename_compressed/{name}.json.gz"
    raw, final = fetch(url, MAX_METADATA)
    (args.out / "index.json.gz").write_bytes(raw)
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        data = stream.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        raise ValueError("decompressed metadata exceeded size limit")
    rows = inventory_rows(json.loads(data), args.arch, args.windows, kb)
    save_json(
        args.out / "inventory.json",
        {
            "filename": name,
            "architecture": args.arch,
            "windows": args.windows,
            "kb": kb,
            "source": provenance(url, final, raw),
            "entries": rows,
        },
    )
    print(
        f"Saved {len(rows)} exact KB/product candidates to {args.out / 'inventory.json'}"
    )
    if not rows:
        raise ValueError(
            "exact artifact missing from index; consult the Microsoft package/file list"
        )


def pe_identity(data):
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("not a complete PE file")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset + 24 + 64 > len(data) or data[offset : offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE header")
    machine = struct.unpack_from("<H", data, offset + 4)[0]
    timestamp = struct.unpack_from("<I", data, offset + 8)[0]
    optional = offset + 24
    optional_size = struct.unpack_from("<H", data, offset + 20)[0]
    if optional_size < 64 or optional + optional_size > len(data):
        raise ValueError("truncated PE optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("unsupported PE optional header")
    image_base = struct.unpack_from(
        "<Q" if magic == 0x20B else "<I",
        data,
        optional + (24 if magic == 0x20B else 28),
    )[0]
    size = struct.unpack_from("<I", data, optional + 56)[0]
    return {
        "machine": machine,
        "timestamp": timestamp,
        "size_of_image": size,
        "image_base": f"0x{image_base:016x}",
    }


def verify_binary(data, row, arch):
    info = row["file_info"]
    if hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise ValueError(
            "SHA-256 mismatch; refusing substituted/colliding symbol-server file"
        )
    if len(data) != info["size"]:
        raise ValueError("file size mismatch")
    identity = pe_identity(data)
    if (
        identity["machine"] != MACHINES[arch]
        or identity["machine"] != info["machineType"]
        or identity["timestamp"] != info["timestamp"]
        or identity["size_of_image"] != info["virtualSize"]
    ):
        raise ValueError("PE identity mismatch")
    return identity


def symbol_url(name, info):
    name = filename(name)
    timestamp, size = info["timestamp"], info["virtualSize"]
    if not (
        type(timestamp) is int
        and 0 <= timestamp <= 0xFFFFFFFF
        and type(size) is int
        and 0 < size <= 0xFFFFFFFF
    ):
        raise ValueError("invalid symbol-server identity")
    return f"https://msdl.microsoft.com/download/symbols/{name}/{timestamp:08X}{size:x}/{name}"


def download(args):
    manifest = json.loads(args.inventory.read_text())
    sha = checked(args.sha256.lower(), r"[a-f0-9]{64}", "SHA-256")
    entries = [r for r in manifest["entries"] if r["sha256"] == sha]
    if len(entries) != 1:
        raise ValueError("choose exactly one SHA-256 from the inventory")
    row = entries[0]
    if not 0 < row["file_info"]["size"] <= MAX_BINARY:
        raise ValueError("indexed binary exceeds download size limit")
    name = filename(manifest["filename"])
    url = symbol_url(name, row["file_info"])
    data, final = fetch(url, row["file_info"]["size"])
    identity = verify_binary(data, row, manifest["architecture"])
    with (args.out / name).open("xb") as stream:
        stream.write(data)
    save_json(
        args.out / "download.json",
        {
            "filename": name,
            "architecture": manifest["architecture"],
            "windows": manifest["windows"],
            "kb": manifest["kb"],
            "index_source": manifest["source"],
            "selected_entry": row,
            "download": provenance(url, final, data),
            "pe_identity": identity,
            "signature_verification": "not_verified",
        },
    )
    print(f"Verified {name}: {sha}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    ms = commands.add_parser("msrc")
    ms.add_argument("cve")
    inv = commands.add_parser("inventory")
    inv.add_argument("filename")
    inv.add_argument("--arch", choices=INDEX, required=True)
    inv.add_argument("--windows", required=True)
    inv.add_argument("--kb", required=True)
    dl = commands.add_parser("download")
    dl.add_argument("--inventory", type=Path, required=True)
    dl.add_argument("--sha256", required=True)
    for command in (ms, inv, dl):
        command.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        args.out.mkdir(parents=True, mode=0o700, exist_ok=False)
        {"msrc": msrc, "inventory": inventory, "download": download}[args.command](args)
    except (ValueError, KeyError, TypeError, OSError, urllib.error.URLError) as error:
        print(f"{args.command} failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
