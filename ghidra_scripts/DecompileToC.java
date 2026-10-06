// DecompileToC.java — Ghidra headless postScript.
//
// Decompiles every function in the loaded program to a single C-like listing
// and writes it to the path given in the first script argument (or the
// GHIDRA_DECOMP_OUT environment variable). Java is used instead of a Python
// script so it runs under stock headless Ghidra without PyGhidra/CPython.
//
// Invoked by pipeline.report via analyzeHeadless:
//   analyzeHeadless <proj_dir> <proj_name> -import <file.sys> \
//       -scriptPath ghidra_scripts -postScript DecompileToC.java <out.c>
//
// @category HID-collect
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class DecompileToC extends GhidraScript {

    private String outPath() {
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && args[0] != null && !args[0].isEmpty()) {
            return args[0];
        }
        String env = System.getenv("GHIDRA_DECOMP_OUT");
        if (env != null && !env.isEmpty()) {
            return env;
        }
        return "decompiled.c";
    }

    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        String out = outPath();

        DecompInterface iface = new DecompInterface();
        iface.openProgram(prog);

        int total = prog.getFunctionManager().getFunctionCount();

        PrintWriter w = new PrintWriter(out, "UTF-8");
        try {
            w.println("/* Ghidra full decompilation");
            w.println(" * program  : " + prog.getName());
            w.println(" * sha256   : " + prog.getMetadata().get("Executable SHA256"));
            w.println(" * format   : " + prog.getMetadata().get("Executable Format"));
            w.println(" * language : " + prog.getLanguageID());
            w.println(" * image    : " + prog.getImageBase());
            w.println(" * functions: " + total);
            w.println(" */");
            w.println();

            int done = 0;
            for (Function fn : prog.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) {
                    break;
                }
                w.println();
                w.println("/* ---- " + fn.getName() + " @ " + fn.getEntryPoint() + " ---- */");
                DecompileResults res = iface.decompileFunction(fn, 60, monitor);
                if (res != null && res.decompileCompleted()) {
                    w.print(res.getDecompiledFunction().getC());
                } else {
                    String err = (res != null) ? res.getErrorMessage() : "no result";
                    w.println("/* decompile failed: " + err + " */");
                }
                w.println();
                done++;
                if (done % 50 == 0) {
                    println("  decompiled " + done + "/" + total + " functions");
                }
            }
        } finally {
            w.close();
            iface.dispose();
        }
        println("DecompileToC: wrote " + total + " functions to " + out);
    }
}
