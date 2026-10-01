// Decompile named functions or RVAs into one deterministic text report.
//
// Use ConfigurePdb.java as a pre-script when a matching PDB is available.
//@category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class DecompileFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                    "usage: DecompileFunctions.java <output> <function-name-or-rva>...");
        }

        Path output = Path.of(args[0]);
        Set<Function> functions = new LinkedHashSet<>();
        List<String> missing = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            String selector = args[i];
            if (selector.startsWith("0x") || selector.startsWith("0X")) {
                long rva = Long.parseUnsignedLong(selector.substring(2), 16);
                Address address = currentProgram.getImageBase().add(rva);
                Function function = getFunctionContaining(address);
                if (function == null) {
                    missing.add(selector);
                }
                else {
                    functions.add(function);
                }
                continue;
            }

            List<Function> named = getGlobalFunctions(selector);
            if (named.isEmpty()) {
                FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
                while (iterator.hasNext()) {
                    Function candidate = iterator.next();
                    if (candidate.getName(true).equals(selector)
                            || candidate.getName().equals(selector)) {
                        named.add(candidate);
                    }
                }
            }
            if (named.isEmpty()) {
                missing.add(selector);
            }
            else {
                functions.addAll(named);
            }
        }

        Files.createDirectories(output.toAbsolutePath().getParent());
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(
                Files.newBufferedWriter(output, StandardCharsets.UTF_8))) {
            out.println("image=" + currentProgram.getExecutablePath());
            out.println("image_base=" + currentProgram.getImageBase());
            out.println("missing=" + String.join(",", missing));
            for (Function function : functions) {
                long rva = function.getEntryPoint().subtract(currentProgram.getImageBase());
                out.println();
                out.println("################ " + function.getName() + " rva=0x"
                        + Long.toHexString(rva) + " body="
                        + function.getBody().getNumAddresses());
                DecompileResults result = decompiler.decompileFunction(function, 300, monitor);
                if (result == null || result.getDecompiledFunction() == null) {
                    out.println("<decompilation failed>");
                }
                else {
                    out.println(result.getDecompiledFunction().getC());
                }
            }
        }
        finally {
            decompiler.dispose();
        }

        println("wrote " + functions.size() + " function(s) to " + output);
        if (!missing.isEmpty()) {
            println("selectors not found: " + String.join(", ", missing));
        }
    }
}
