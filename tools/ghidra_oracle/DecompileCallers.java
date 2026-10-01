// Decompile every function that calls a named function or image-relative RVA.
//@category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;

public class DecompileCallers extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException(
                    "usage: DecompileCallers.java <output> <callee-name-or-rva>");
        }

        Path output = Path.of(args[0]);
        String calleeName = args[1];
        Set<Address> destinations = new LinkedHashSet<>();
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(calleeName);
        if (calleeName.startsWith("0x")) {
            destinations.add(currentProgram.getImageBase().add(
                    Long.parseUnsignedLong(calleeName.substring(2), 16)));
        }
        else {
            while (symbols.hasNext()) {
                destinations.add(symbols.next().getAddress());
            }
        }
        if (destinations.isEmpty() && calleeName.contains("::")) {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function function = functions.next();
                if (calleeName.equals(function.getName(true))) {
                    destinations.add(function.getEntryPoint());
                }
            }
        }

        // Imports commonly have both an external symbol and a thunk. Include the
        // thunk so an ordinary direct CALL is found as well as an IAT reference.
        Set<Address> expanded = new LinkedHashSet<>(destinations);
        for (Address destination : destinations) {
            ReferenceIterator references = currentProgram.getReferenceManager()
                    .getReferencesTo(destination);
            while (references.hasNext()) {
                Reference reference = references.next();
                Function function = getFunctionAt(reference.getFromAddress());
                if (function != null && function.isThunk()) {
                    expanded.add(function.getEntryPoint());
                }
            }
        }

        Set<Function> callers = new LinkedHashSet<>();
        for (Address destination : expanded) {
            ReferenceIterator references = currentProgram.getReferenceManager()
                    .getReferencesTo(destination);
            while (references.hasNext()) {
                Reference reference = references.next();
                Function caller = getFunctionContaining(reference.getFromAddress());
                if (caller != null && !caller.isThunk()) {
                    callers.add(caller);
                }
            }
        }

        Files.createDirectories(output.toAbsolutePath().getParent());
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(
                Files.newBufferedWriter(output, StandardCharsets.UTF_8))) {
            out.println("image=" + currentProgram.getExecutablePath());
            out.println("image_base=" + currentProgram.getImageBase());
            out.println("callee=" + calleeName);
            for (Symbol symbol : symbolsAt(expanded)) {
                out.println("target=" + symbol.getName(true) + "@" + symbol.getAddress());
            }
            out.println("callers=" + callers.size());
            for (Function function : callers) {
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

        println("wrote " + callers.size() + " caller(s) to " + output);
    }

    private Set<Symbol> symbolsAt(Set<Address> addresses) {
        Set<Symbol> result = new LinkedHashSet<>();
        for (Address address : addresses) {
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
            if (symbol != null) {
                result.add(symbol);
            }
        }
        return result;
    }
}
