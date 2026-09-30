// What gates IOCTL 0x221148 in Vid.sys?
//
// Step 7's receiver arm measured STATUS_ACCESS_DENIED (0xC0000022) from a handle duplicated out of
// vmwp.exe, and could not tell apart two explanations: the driver's own ownership check, or the
// driver checking for an access right the duplicate does not carry. Both predicted the observation
// because the object's security descriptor refuses a wider duplicate. This reads the handler
// instead of inferring from the return code.
//
// Prints: which function holds the control code, the decompiled C of the handler chain, and every
// site in it that yields 0xC0000022.
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class VidGate extends GhidraScript {

    private static final long REGISTER_CODE = 0x221148L;
    private static final long UNREGISTER_CODE = 0x2211E8L;
    private static final long ACCESS_DENIED = 0xC0000022L;
    private static final long DUPLICATE_HANDLER = 0xC0370001L;

    @Override
    public void run() throws Exception {
        println("=== functions containing the control codes as immediates ===");
        Set<Function> holders = new LinkedHashSet<>();
        holders.addAll(findScalar(REGISTER_CODE, "register 0x221148"));
        holders.addAll(findScalar(UNREGISTER_CODE, "unregister 0x2211E8"));

        println("");
        println("=== functions yielding 0xC0000022 (ACCESS_DENIED) ===");
        List<Function> deniers = findScalar(ACCESS_DENIED, "STATUS_ACCESS_DENIED");

        println("");
        println("=== functions yielding 0xC0370001 (VID_DUPLICATE_HANDLER), for orientation ===");
        findScalar(DUPLICATE_HANDLER, "STATUS_VID_DUPLICATE_HANDLER");

        // Decompile the handler chain plus any denier whose name looks like the exception path.
        Set<Function> want = new LinkedHashSet<>(holders);
        for (Function f : deniers) {
            String n = f.getName().toLowerCase();
            if (n.contains("handler") || n.contains("exception") || n.contains("iocontrol")
                    || n.contains("partition") || n.contains("register")) {
                want.add(f);
            }
        }
        for (String n : new String[] { "VidIoControlPartition", "VidHandlerpExceptionRegisterEntry",
                                       "VidHandlerExceptionRegister", "VidIoControlDispatch" }) {
            for (Function f : getGlobalFunctions(n)) {
                want.add(f);
            }
        }

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        try {
            for (Function f : want) {
                println("");
                println("################ " + f.getName() + "  @ " + f.getEntryPoint()
                        + "  (rva " + rva(f.getEntryPoint()) + ")  body=" + f.getBody().getNumAddresses() + "B");
                DecompileResults res = di.decompileFunction(f, 120, monitor);
                if (res == null || res.getDecompiledFunction() == null) {
                    println("   <decompilation failed>");
                    continue;
                }
                println(res.getDecompiledFunction().getC());
            }
        } finally {
            di.dispose();
        }
    }

    private String rva(Address a) {
        long base = currentProgram.getImageBase().getOffset();
        return "0x" + Long.toHexString(a.getOffset() - base);
    }

    private List<Function> findScalar(long value, String label) {
        List<Function> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            for (int op = 0; op < ins.getNumOperands(); op++) {
                for (Object o : ins.getOpObjects(op)) {
                    if (!(o instanceof Scalar)) {
                        continue;
                    }
                    long v = ((Scalar) o).getUnsignedValue();
                    if (v != value && (v & 0xFFFFFFFFL) != (value & 0xFFFFFFFFL)) {
                        continue;
                    }
                    Function f = getFunctionContaining(ins.getAddress());
                    String name = (f == null) ? "<none>" : f.getName();
                    String key = name + "@" + ins.getAddress();
                    if (seen.add(key)) {
                        println("   " + label + "  " + ins.getAddress() + " (rva " + rva(ins.getAddress())
                                + ")  in " + name + "   [" + ins + "]");
                        if (f != null && !out.contains(f)) {
                            out.add(f);
                        }
                    }
                }
            }
        }
        if (seen.isEmpty()) {
            println("   " + label + ": no immediate found");
        }
        return out;
    }
}
