// Diagnostic script: exercises the Decompiler helper directly inside Ghidra and
// prints exactly what each stage returns. Used to debug decompilation failures
// that the bridge can only report as "no code".
//
//   analyzeHeadless <projDir> <projName> -process <file> -noanalysis \
//       -scriptPath <dir> -postScript DiagnoseDecompiler.java
//
//@category GhidraMCP12

import com.ghidramcp.core.Decompiler;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

public class DiagnoseDecompiler extends GhidraScript {

	@Override
	public void run() throws Exception {
		println("program: " + currentProgram.getName() + " lang=" + currentProgram.getLanguageID());

		// 1. Raw DecompInterface, the way Ghidra's own actions do it.
		DecompInterface di = new DecompInterface();
		println("openProgram -> " + di.openProgram(currentProgram));
		println("simplification style: " + di.getSimplificationStyle());

		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		int checked = 0;
		int rawOk = 0;
		int helperOk = 0;
		while (it.hasNext() && checked < 5) {
			Function f = it.next();
			if (f.isExternal() || f.isThunk()) {
				continue;
			}
			checked++;

			DecompileResults r = di.decompileFunction(f, 60, new ConsoleTaskMonitor());
			println("--- raw  " + f.getName() + " @ " + f.getEntryPoint());
			if (r == null) {
				println("    result: null");
			}
			else {
				println("    completed=" + r.decompileCompleted()
					+ " timedOut=" + r.isTimedOut()
					+ " failedToStart=" + r.failedToStart()
					+ " error='" + r.getErrorMessage() + "'");
				println("    decompiledFunction=" + r.getDecompiledFunction()
					+ " highFunction=" + (r.getHighFunction() != null));
				if (r.getDecompiledFunction() != null) {
					String c = r.getDecompiledFunction().getC();
					println("    C length=" + (c == null ? -1 : c.length()));
					rawOk++;
				}
			}

			// 2. The bridge's cached helper, which is what the HTTP endpoints use.
			Decompiler.Result br = Decompiler.decompile(currentProgram, f, 60);
			println("--- mcp  " + f.getName()
				+ " code=" + (br.code() == null ? "null" : br.code().length() + " chars")
				+ " timedOut=" + br.timedOut()
				+ " error='" + br.error() + "'");
			if (br.code() != null) {
				helperOk++;
			}
		}
		println("checked=" + checked + " rawOk=" + rawOk + " helperOk=" + helperOk);
		di.dispose();
	}
}
