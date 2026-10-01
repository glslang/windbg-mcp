// Bind an explicitly named PDB before headless auto-analysis starts.
//
// analyzeHeadless does not search an arbitrary symbol cache by default.  The
// universal PDB analyzer tells the operator to set this option from a
// pre-script; keeping that step here makes later reports name the functions
// they discuss instead of relying on remembered RVAs.
//@category Analysis

import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.app.script.GhidraScript;

import java.io.File;

public class ConfigurePdb extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: ConfigurePdb.java <pdb-path>");
        }

        File pdb = new File(args[0]);
        if (!pdb.isFile()) {
            throw new IllegalArgumentException("PDB does not exist: " + pdb);
        }

        PdbUniversalAnalyzer.setPdbFileOption(currentProgram, pdb);
        println("configured PDB: " + pdb.getCanonicalPath());
    }
}
