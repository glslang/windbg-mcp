// An independent second opinion on `ioctl_map`, taken from Ghidra's own analysis.
//
// **Deliberately leans on Ghidra rather than reimplementing the walk.** The point of an oracle is
// that it is not the thing under test, so nothing here decides what an IOCTL code looks like or
// how a switch is laid out: the constants come from the decompiler's own p-code after its own
// value propagation, and the switch tables come from `HighFunction.getJumpTables()`, which is
// Ghidra's recovery, not a second copy of mine.
//
// Everything is reported in **RVAs**, because that is the only coordinate a disassembler and a
// debugger can both state: Ghidra knows an image, the debugger knows a mapping.
//
// Args: <rva of the dispatch routine, e.g. 0x14750> <output .json path>
//@category Oracle

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;

public class IoctlOracle extends GhidraScript {

    private long imageBase;

    private long rva(Address at) {
        return at.getOffset() - imageBase;
    }

    private static String hex(long v) {
        return String.format("0x%08x", v & 0xFFFFFFFFL);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long wantRva = Long.decode(args[0]);
        String outPath = args[1];

        imageBase = currentProgram.getImageBase().getOffset();
        Address entry = currentProgram.getImageBase().add(wantRva);

        Function f = getFunctionContaining(entry);
        if (f == null) {
            f = createFunction(entry, null);
        }
        if (f == null) {
            throw new Exception("no function at RVA " + hex(wantRva));
        }

        // ---- the decompiler's view -------------------------------------------------------
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        DecompileResults res = ifc.decompileFunction(f, 300, monitor);
        HighFunction hf = res.getHighFunction();

        // Constants the decompiler compares against, after **its** value propagation. Recorded
        // with the RVA of the comparison, so a code found in two places is two records -- the
        // same "a case per site" rule the tool uses, arrived at independently.
        List<String> compares = new ArrayList<>();
        TreeSet<Long> compareValues = new TreeSet<>();
        if (hf != null) {
            Iterator<PcodeOpAST> ops = hf.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                int code = op.getOpcode();
                boolean isCompare = code == PcodeOp.INT_EQUAL
                        || code == PcodeOp.INT_NOTEQUAL
                        || code == PcodeOp.INT_LESS
                        || code == PcodeOp.INT_LESSEQUAL
                        || code == PcodeOp.INT_SLESS
                        || code == PcodeOp.INT_SLESSEQUAL;
                if (!isCompare) {
                    continue;
                }
                for (Varnode in : op.getInputs()) {
                    if (in == null || !in.isConstant()) {
                        continue;
                    }
                    long value = in.getOffset();
                    Address at = op.getSeqnum().getTarget();
                    // **Where the other side came from**, so a constant is not taken for a control
                    // code on the strength of its top sixteen bits alone. A status, a length and a
                    // magic number can all share a device type; only one of them arrives from
                    // memory. Reported rather than filtered on -- deciding that a particular
                    // displacement is the code would be this oracle adopting the assumption of the
                    // pass it exists to check.
                    boolean traced = false;
                    for (Varnode other : op.getInputs()) {
                        if (other != null && !other.isConstant() && reachesALoad(other, 12)) {
                            traced = true;
                        }
                    }
                    compares.add("{\"value\": \"" + hex(value) + "\", \"rva\": \"" + hex(rva(at))
                            + "\", \"op\": \"" + op.getMnemonic() + "\""
                            + ", \"traced\": " + traced + "}");
                    compareValues.add(value & 0xFFFFFFFFL);
                }
            }
        }

        // ---- the switch tables, as Ghidra recovered them -----------------------------------
        //
        // `getLabelValues` is the case constant per destination, which is the half a listing walk
        // cannot give: the destinations alone say where, never for which code.
        List<String> tables = new ArrayList<>();
        TreeSet<Long> tableValues = new TreeSet<>();
        if (hf != null) {
            JumpTable[] jts = hf.getJumpTables();
            for (JumpTable jt : jts) {
                Address switchAt = jt.getSwitchAddress();
                Address[] dests = jt.getCases();
                StringBuilder labels = new StringBuilder();
                int labelCount = 0;
                try {
                    Integer[] values = jt.getLabelValues();
                    if (values != null) {
                        for (Integer v : values) {
                            if (labels.length() > 0) {
                                labels.append(", ");
                            }
                            labels.append("\"").append(hex(v.longValue())).append("\"");
                            tableValues.add(v.longValue() & 0xFFFFFFFFL);
                            labelCount++;
                        }
                    }
                } catch (Throwable t) {
                    labels.setLength(0);
                }
                TreeSet<String> distinctDests = new TreeSet<>();
                for (Address d : dests) {
                    distinctDests.add(hex(rva(d)));
                }
                // **Each label beside the block it reaches**, which is the pairing that decides
                // whether a slot is a code the driver accepts or one more index falling through to
                // the default. A label list alone cannot say.
                StringBuilder pairs = new StringBuilder();
                try {
                    Integer[] values = jt.getLabelValues();
                    for (int i = 0; i < dests.length && values != null && i < values.length; i++) {
                        if (pairs.length() > 0) {
                            pairs.append(", ");
                        }
                        pairs.append("{\"label\": \"").append(hex(values[i].longValue()))
                             .append("\", \"dest_rva\": \"").append(hex(rva(dests[i])))
                             .append("\"}");
                    }
                } catch (Throwable t) {
                    pairs.setLength(0);
                }
                tables.add("{\"switch_rva\": \"" + hex(rva(switchAt))
                        + "\", \"destinations\": " + dests.length
                        + ", \"distinct_destinations\": " + distinctDests.size()
                        + ", \"label_count\": " + labelCount
                        + ", \"labels\": [" + labels + "]"
                        + ", \"pairs\": [" + pairs + "]}");
            }
        }

        // ---- and the listing's own computed jumps, as a cross-check on the above -----------
        List<String> computed = new ArrayList<>();
        InstructionIterator listing = currentProgram.getListing().getInstructions(f.getBody(), true);
        TreeMap<String, Integer> cmpScalars = new TreeMap<>();
        while (listing.hasNext()) {
            Instruction ins = listing.next();
            String mnemonic = ins.getMnemonicString().toUpperCase();
            if (mnemonic.startsWith("CMP") || mnemonic.startsWith("SUB")) {
                for (int i = 0; i < ins.getNumOperands(); i++) {
                    Object[] parts = ins.getOpObjects(i);
                    for (Object part : parts) {
                        if (part instanceof Scalar) {
                            long v = ((Scalar) part).getUnsignedValue();
                            if (v > 0xFF) {
                                String key = hex(v);
                                cmpScalars.merge(key, 1, Integer::sum);
                            }
                        }
                    }
                }
            }
            if (ins.getFlowType().isJump() && ins.getFlowType().isComputed()) {
                int found = 0;
                for (Reference r : ins.getReferencesFrom()) {
                    if (r.getReferenceType() == RefType.COMPUTED_JUMP) {
                        found++;
                    }
                }
                computed.add("{\"rva\": \"" + hex(rva(ins.getAddress()))
                        + "\", \"resolved_destinations\": " + found + "}");
            }
        }

        // ---- write it out ------------------------------------------------------------------
        try (PrintWriter out = new PrintWriter(outPath, "UTF-8")) {
            out.println("{");
            out.println("  \"program\": \"" + currentProgram.getName() + "\",");
            out.println("  \"image_base\": \"" + hex(imageBase) + "\",");
            out.println("  \"dispatch\": {\"name\": \"" + f.getName()
                    + "\", \"rva\": \"" + hex(rva(f.getEntryPoint()))
                    + "\", \"body_bytes\": " + f.getBody().getNumAddresses() + "},");
            out.println("  \"decompiled\": " + (hf != null));
            out.println("  ,\"compares\": [");
            out.println("    " + String.join(",\n    ", compares));
            out.println("  ],");
            out.println("  \"compare_values\": [" + joinHex(compareValues) + "],");
            out.println("  \"tables\": [");
            out.println("    " + String.join(",\n    ", tables));
            out.println("  ],");
            out.println("  \"table_values\": [" + joinHex(tableValues) + "],");
            out.println("  \"computed_jumps\": [");
            out.println("    " + String.join(",\n    ", computed));
            out.println("  ],");
            StringBuilder scalars = new StringBuilder();
            for (String key : cmpScalars.keySet()) {
                if (scalars.length() > 0) {
                    scalars.append(", ");
                }
                scalars.append("{\"value\": \"").append(key).append("\", \"sites\": ")
                        .append(cmpScalars.get(key)).append("}");
            }
            out.println("  \"listing_cmp_scalars\": [" + scalars + "]");
            out.println("}");
        }

        // The decompiled C beside it, as the evidence a person reads.
        if (res.getDecompiledFunction() != null) {
            try (PrintWriter c = new PrintWriter(outPath.replace(".json", ".c"), "UTF-8")) {
                c.print(res.getDecompiledFunction().getC());
            }
        }
        println("IoctlOracle: wrote " + outPath);
    }

    /// Whether a varnode's definition chain reaches a `LOAD` within `depth` steps.
    ///
    /// The control code arrives from memory -- `[[Irp+0xb8]+0x18]` -- so a compare against
    /// something that never came from a load is not a compare against it. Bounded rather than
    /// exhaustive: this is a second opinion, not a solver, and an unbounded walk over a decompiled
    /// function is a way to hang a manual lane.
    private boolean reachesALoad(Varnode start, int depth) {
        if (depth <= 0 || start == null) {
            return false;
        }
        PcodeOp def = start.getDef();
        if (def == null) {
            return false;
        }
        if (def.getOpcode() == PcodeOp.LOAD) {
            return true;
        }
        for (Varnode in : def.getInputs()) {
            if (in != null && !in.isConstant() && reachesALoad(in, depth - 1)) {
                return true;
            }
        }
        return false;
    }

    private static String joinHex(TreeSet<Long> values) {
        StringBuilder sb = new StringBuilder();
        for (Long v : values) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("\"").append(hex(v)).append("\"");
        }
        return sb.toString();
    }
}
