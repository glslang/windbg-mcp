"""Compare two built upstream ARM64 decoder libraries on an instruction corpus."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path


# Corpus from upstream revision 905a5a98d769bb832ba85674b004fec7ac5a224e.
CORPUS_COUNT = 42639
CORPUS_SHA256 = "54b25d800c93d01e895b99ba48034e3bdc7e393104f63590b644387336a71b7f"


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
    corpus = args.corpus.read_bytes()
    corpus_sha256 = hashlib.sha256(corpus).hexdigest()
    if corpus_sha256 != CORPUS_SHA256:
        raise SystemExit("corpus SHA-256 does not match the pinned upstream corpus")
    words = [
        int(line[:8], 16)
        for line in corpus.decode("utf-8").splitlines()
        if line and not line.startswith("//")
    ]
    if len(words) != CORPUS_COUNT:
        raise SystemExit("corpus count does not match the pinned upstream corpus")
    before, after = library(args.before), library(args.after)
    differences = []
    for word in words:
        old, new = decode(before, word), decode(after, word)
        if old != new:
            differences.append({"word": hex(word), "before": old, "after": new})
    report = {
        "schema_version": 1,
        "corpus_count": len(words),
        "corpus_sha256": corpus_sha256,
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
