import argparse
import hashlib
import json
import sys
from pathlib import Path


EXPECTED = {
    "reference": set(range(0x14010FC00, 0x140110000, 0x80)),
    "target": set(range(0x14011AC00, 0x14011B000, 0x80)),
}


def inspect(side, path, pb):
    proto = pb.BinExport2()
    data = path.read_bytes()
    proto.ParseFromString(data)

    addresses = []
    following = 0
    for instruction in proto.instruction:
        address = instruction.address if instruction.HasField("address") else following
        addresses.append(address)
        following = address + len(instruction.raw_bytes)

    rows = []
    for graph_index, graph in enumerate(proto.flow_graph):
        block_index = graph.entry_basic_block_index
        block = proto.basic_block[block_index]
        if not block.instruction_index:
            continue
        instruction_index = block.instruction_index[0].begin_index
        address = addresses[instruction_index]
        if address not in EXPECTED[side]:
            continue
        instruction = proto.instruction[instruction_index]
        mnemonic = proto.mnemonic[instruction.mnemonic_index].name
        rows.append(
            {
                "flow_graph_index": graph_index,
                "entry_basic_block_index": block_index,
                "entry_instruction_range_index": 0,
                "entry_instruction_begin_index": instruction_index,
                "instruction_address": hex(address),
                "address_source": "explicit"
                if instruction.HasField("address")
                else "reconstructed",
                "raw_bytes": instruction.raw_bytes.hex(),
                "mnemonic_index": instruction.mnemonic_index,
                "mnemonic": mnemonic,
            }
        )

    found = {int(row["instruction_address"], 16) for row in rows}
    assert found == EXPECTED[side], (side, found ^ EXPECTED[side])
    assert len(rows) == 8
    assert all(row["raw_bytes"] == "df2203d5" for row in rows)
    assert all(row["mnemonic"] == "clrbhb" for row in rows)
    return {
        "side": side,
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "total_flow_graphs": len(proto.flow_graph),
        "recovered_graph_count": len(rows),
        "recovered_graphs": rows,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pb2-dir", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.pb2_dir))
    import binexport2_pb2

    result = {
        "schema": "securekernel-binexport-graph-inspection-v1",
        "checks": {
            "exact_expected_entries": True,
            "eight_graphs_per_side": True,
            "entry_raw_bytes_are_clrbhb": True,
            "entry_mnemonics_are_clrbhb": True,
        },
        "exports": [
            inspect("reference", args.reference, binexport2_pb2),
            inspect("target", args.target, binexport2_pb2),
        ],
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
