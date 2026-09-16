"""Compare two built upstream ARM64 decoder libraries on an instruction corpus."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path


def library(path):
    result = ctypes.CDLL(str(path.resolve()))
    result.aarch64_decompose.argtypes = [
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint64,
    ]
    result.aarch64_decompose.restype = ctypes.c_int
    result.aarch64_disassemble.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    result.aarch64_disassemble.restype = ctypes.c_int
    return result


def decode(lib, word):
    # Aligned storage larger than Instruction in the pinned upstream revision.
    instruction = (ctypes.c_uint64 * 512)()
    text = ctypes.create_string_buffer(1024)
    status = lib.aarch64_decompose(word, instruction, 0x8000000000000004)
    formatting = (
        lib.aarch64_disassemble(instruction, text, 1024) if status == 0 else None
    )
    return {"decode": status, "format": formatting, "text": text.value.decode()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("before", "after", "corpus", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    before, after = library(args.before), library(args.after)
    words = [
        int(line[:8], 16)
        for line in args.corpus.read_text().splitlines()
        if line and not line.startswith("//")
    ]
    differences = []
    for word in words:
        old, new = decode(before, word), decode(after, word)
        if old != new:
            differences.append({"word": hex(word), "before": old, "after": new})
    report = {
        "schema_version": 1,
        "corpus_count": len(words),
        "corpus_sha256": hashlib.sha256(args.corpus.read_bytes()).hexdigest(),
        "before_sha256": hashlib.sha256(args.before.read_bytes()).hexdigest(),
        "after_sha256": hashlib.sha256(args.after.read_bytes()).hexdigest(),
        "changed": differences,
        "clrbhb": {
            "before": decode(before, 0xD50322DF),
            "after": decode(after, 0xD50322DF),
        },
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Compared {len(words)} corpus entries; {len(differences)} changed")
    # A newly decoded CLRBHB may itself be present in a future corpus.
    unexpected = [r for r in differences if r["word"] != "0xd50322df"]
    baseline = report["clrbhb"]["before"]
    fixed = report["clrbhb"]["after"]
    raise SystemExit(
        1
        if unexpected
        or baseline != {"decode": -9, "format": None, "text": ""}
        or fixed != {"decode": 0, "format": 0, "text": "clrbhb"}
        else 0
    )


if __name__ == "__main__":
    main()
