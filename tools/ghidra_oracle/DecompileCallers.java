// Decompile the functions that reference a named function or image-relative RVA.
//
// NOT "every function that calls": what this finds is the references Ghidra resolved to the
// target and its thunks, split into calls and address-taken. A call reached only through a
// pointer slot Ghidra left unresolved is not among them, and the report says so in its
// `scope=` line rather than leaving `callers=0` to be read as none existing.
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
        // An unresolved target FAILS rather than producing a report, because `callers=0` would
        // otherwise mean two different things -- "the target was found and nothing references it" and
        // "the name was misspelled, or is absent from the PDB that loaded" -- and this script is an
        // oracle whose zero is read as evidence about the image. A misread of that kind is what the
        // lane's README warns about in the other direction, and writing no report at all is the only
        // answer that cannot be mistaken for one. Raised in review on #434.
        //
        // `DecompileFunctions.java` keeps going in the same situation and is right to: it takes
        // several selectors and names the unresolved ones in a `missing=` line, so its report
        // distinguishes them. This script takes one target, so there is nothing left to report.
        if (destinations.isEmpty()) {
            throw new IllegalArgumentException(
                    "no address for callee " + calleeName + " in " + currentProgram.getExecutablePath()
                    + " -- it resolved to no symbol, no image-relative RVA and no fully qualified "
                    + "function name, so a caller count would be a claim about a target that was "
                    + "never located. Check the spelling and that a PDB is loaded (ConfigurePdb.java).");
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

        // Split by reference TYPE, because `getReferencesTo` returns every reference and not only
        // calls. A function that merely takes the callee's address -- registering a callback, filling
        // a dispatch-table slot, a bare `lea` -- was being reported as a caller, which is an oracle
        // stating something the image does not say. Nothing is filtered away: an address taken is how
        // an indirect call happens, so it is often the row this script is run to find. Same
        // convention as `tools/vid_field_census.py`, which reports `lea` separately for this reason.
        //
        // THREE buckets rather than two, because `!isCall()` is not the same as "takes the address".
        // A tail call or a shared-epilogue jump straight to the target is `isJump()`, and calling that
        // an address-taken would be a second wrong claim in place of the first. Reported as its own
        // row instead -- it is nearer a caller than a data reference, and conflating it either way
        // loses which one the image actually holds. Raised in review on #434.
        Set<Function> callers = new LinkedHashSet<>();
        Set<Function> jumps = new LinkedHashSet<>();
        Set<Function> addressTaken = new LinkedHashSet<>();
        for (Address destination : expanded) {
            ReferenceIterator references = currentProgram.getReferenceManager()
                    .getReferencesTo(destination);
            while (references.hasNext()) {
                Reference reference = references.next();
                Function from = getFunctionContaining(reference.getFromAddress());
                if (from == null || from.isThunk()) {
                    continue;
                }
                if (reference.getReferenceType().isCall()) {
                    callers.add(from);
                }
                else if (reference.getReferenceType().isJump()) {
                    jumps.add(from);
                }
                else {
                    addressTaken.add(from);
                }
            }
        }
        // The three sets MAY OVERLAP, deliberately. An earlier version subtracted the callers out of
        // the address-taken set so the counts would not double-count, which silently deleted the
        // interesting case: a function that both calls the target and stores its address can be
        // reached either way, and the second route is exactly what an indirect-call investigation is
        // looking for. The report says the counts overlap rather than making them disjoint by
        // dropping evidence.

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
            // What the report covers, said in the report rather than left to be inferred from
            // `callers=0`. A call reached only through a pointer slot Ghidra did not resolve to one
            // of these addresses is not counted here, and the honest form of that is to name the
            // scope rather than to claim completeness this script cannot deliver.
            out.println("scope=references Ghidra resolved to the target addresses above and their "
                    + "thunks, split by reference type; a call through an unresolved pointer slot is "
                    + "in none of the three counts, and the counts MAY OVERLAP because one function "
                    + "can reference the target in more than one way");
            out.println("callers=" + callers.size());
            out.println("jumps=" + jumps.size());
            for (Function function : jumps) {
                long rva = function.getEntryPoint().subtract(currentProgram.getImageBase());
                out.println("jumps_to=" + function.getName() + " rva=0x" + Long.toHexString(rva));
            }
            out.println("address_taken=" + addressTaken.size());
            for (Function function : addressTaken) {
                long rva = function.getEntryPoint().subtract(currentProgram.getImageBase());
                out.println("address_taken_by=" + function.getName() + " rva=0x"
                        + Long.toHexString(rva));
            }
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
            // `PrintWriter` swallows every `IOException` and records a flag instead, so
            // without this a report truncated by a full disk is announced as a success.
            // Flushed first, so the only write left for `close()` is an empty buffer.
            out.flush();
            if (out.checkError()) {
                throw new java.io.IOException("writing " + output + " failed");
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
