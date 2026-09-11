/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import com.ghidramcp.api.ApiContext;
import com.ghidramcp.api.ApiException;
import com.ghidramcp.api.Jsonify;

/**
 * Decompiler access.
 *
 * <p>One {@link DecompInterface} is kept per program because constructing and
 * priming one is expensive (it spawns the native decompiler process and feeds
 * it the program's data types). Reusing it turns a suite of decompile calls
 * from "seconds each" into "milliseconds each".
 *
 * <p>The cache entry is dropped when the program's modification number changes,
 * otherwise a decompile after a rename would return stale C code.
 */
public final class Decompiler {

	private Decompiler() {
	}

	private static final class Entry {
		final long modificationNumber;
		final DecompInterface iface;

		Entry(long modificationNumber, DecompInterface iface) {
			this.modificationNumber = modificationNumber;
			this.iface = iface;
		}
	}

	private static final Map<Program, Entry> CACHE =
		Collections.synchronizedMap(new WeakHashMap<>());

	/** Result of a decompilation, shaped for the JSON layer. */
	public record Result(String code, String signature, boolean timedOut, String error) {
	}

	private static DecompInterface iface(Program program) {
		synchronized (CACHE) {
			Entry e = CACHE.get(program);
			long mod = program.getModificationNumber();
			if (e != null && e.modificationNumber == mod) {
				return e.iface;
			}
			if (e != null) {
				try {
					e.iface.dispose();
				}
				catch (RuntimeException ignored) {
					// A disposed decompiler throwing here is harmless.
				}
			}
			DecompInterface di = new DecompInterface();
			// The decompiler runs in its own process; an exception here means the
			// native binary is missing, which we surface on first use instead.
			di.toggleCCode(true);
			di.toggleSyntaxTree(true);
			di.setSimplificationStyle("decompile");
			di.openProgram(program);
			CACHE.put(program, new Entry(mod, di));
			return di;
		}
	}

	/** Drops the cached decompiler for a program (call after mutations). */
	public static void invalidate(Program program) {
		synchronized (CACHE) {
			Entry e = CACHE.remove(program);
			if (e != null) {
				try {
					e.iface.dispose();
				}
				catch (RuntimeException ignored) {
					// ignore
				}
			}
		}
	}

	/** Decompiles {@code function} to C, never throwing for a failed decompile. */
	public static Result decompile(Program program, Function function, int timeoutSeconds) {
		DecompInterface di = iface(program);
		DecompileResults results;
		try {
			results = di.decompileFunction(function,
				Math.max(1, timeoutSeconds), new ConsoleTaskMonitor());
		}
		catch (Throwable t) {
			Msg.error(Decompiler.class, "decompiler failed for " + function.getName(), t);
			return new Result(null, null, false,
				"decompiler error: " + (t.getMessage() == null ? t.toString() : t.getMessage()));
		}
		if (results == null) {
			return new Result(null, null, false, "decompiler returned no results");
		}
		if (results.isTimedOut()) {
			// A timed-out decompile still often yields partial C, which is more
			// useful to an agent than nothing at all.
			String partial = results.getDecompiledFunction() == null
				? null : results.getDecompiledFunction().getC();
			return new Result(partial, null, true,
				"decompilation timed out after " + timeoutSeconds + "s");
		}
		if (!results.decompileCompleted()) {
			return new Result(null, null, false,
				"decompilation failed: " + results.getErrorMessage());
		}
		var df = results.getDecompiledFunction();
		return new Result(df == null ? null : df.getC(), df == null ? null : df.getSignature(),
			false, null);
	}

	/** Returns the decompiler's high-level representation, or null. */
	public static HighFunction highFunction(Program program, Function function, int timeoutSeconds) {
		DecompileResults results = iface(program)
			.decompileFunction(function, Math.max(1, timeoutSeconds), new ConsoleTaskMonitor());
		if (results == null || !results.decompileCompleted()) {
			return null;
		}
		return results.getHighFunction();
	}

	/** Full decompile results, used by the variable tools. */
	public static DecompileResults results(Program program, Function function, int timeoutSeconds) {
		return iface(program).decompileFunction(function, Math.max(1, timeoutSeconds),
			new ConsoleTaskMonitor());
	}

	// ------------------------------------------------------------------- p-code

	/** P-code listing for a function. */
	public static Map<String, Object> pcode(Program program, Function function, boolean ssa,
			int timeoutSeconds) {
		HighFunction hf = highFunction(program, function, timeoutSeconds);
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("function", function.getName());
		body.put("address", function.getEntryPoint().toString());
		body.put("ssa", ssa);
		if (hf == null) {
			body.put("error", "could not produce a high function (decompilation failed)");
			body.put("operations", List.of());
			return body;
		}

		List<Object> ops = new ArrayList<>();
		StringBuilder text = new StringBuilder();
		PcodeOp[] raw = ssa ? hf.getPcodeOps() == null ? null : toArray(hf) : rawOps(function);
		if (raw != null) {
			for (PcodeOp op : raw) {
				Map<String, Object> m = new LinkedHashMap<>();
				m.put("seq", op.getSeqnum() == null ? null : op.getSeqnum().getTarget().toString());
				m.put("time", op.getSeqnum() == null ? null : op.getSeqnum().getTime());
				m.put("opcode", op.getMnemonic());
				m.put("output", op.getOutput() == null ? null : op.getOutput().toString());
				List<Object> inputs = new ArrayList<>();
				for (int i = 0; i < op.getNumInputs(); i++) {
					inputs.add(op.getInput(i) == null ? null : op.getInput(i).toString());
				}
				m.put("inputs", inputs);
				ops.add(m);
				text.append(m.get("seq")).append(": ").append(op.getMnemonic()).append(' ')
					.append(m.get("output")).append(" <- ").append(inputs).append('\n');
			}
		}
		body.put("operationCount", ops.size());
		body.put("operations", ops);
		body.put("text", text.toString());
		return body;
	}

	private static PcodeOp[] toArray(HighFunction hf) {
		List<PcodeOp> ops = new ArrayList<>();
		// getPcodeOps() yields PcodeOpAST (an SSA-bearing PcodeOp) in address order.
		java.util.Iterator<ghidra.program.model.pcode.PcodeOpAST> it = hf.getPcodeOps();
		while (it.hasNext()) {
			ops.add(it.next());
		}
		return ops.toArray(new PcodeOp[0]);
	}

	private static PcodeOp[] rawOps(Function function) {
		List<PcodeOp> ops = new ArrayList<>();
		var it = function.getProgram().getListing()
			.getInstructions(function.getBody(), true);
		while (it.hasNext()) {
			var instr = it.next();
			for (PcodeOp op : instr.getPcode()) {
				ops.add(op);
			}
		}
		return ops.toArray(new PcodeOp[0]);
	}

	// --------------------------------------------------------------- prototypes

	/**
	 * Applies a C prototype string to a function.
	 *
	 * <p>Parsing is done by Ghidra's own {@code FunctionSignatureParser} so that
	 * typedefs, calling conventions and complex declarators behave exactly as they
	 * do in the GUI.
	 *
	 * <p>The parser needs a "base prototype" to fill in whatever the supplied text
	 * omits (return type, storage, calling convention). Passing the function's
	 * existing signature is what the GUI does, and it is also the only variant
	 * that works for a function whose signature has never been set: with
	 * {@code null} the parser treats a leading {@code __cdecl} as a return type and
	 * fails with "Can't resolve return type: int __cdecl".
	 */
	public static Map<String, Object> applyPrototype(ApiContext ctx, Program program,
			Function function, String prototype) {
		DataTypeManager dtm = program.getDataTypeManager();
		ghidra.app.services.DataTypeQueryService queryService =
			ctx.guiAvailable() ? ctx.tool().getService(ghidra.app.services.DataTypeQueryService.class)
				: null;

		// Ghidra's FunctionSignatureParser does not understand calling convention
		// keywords: given "int __cdecl f(...)" it reports "Can't resolve return type:
		// int __cdecl". The GUI's own action strips the keyword and applies it
		// separately, so do the same.
		CallingConventionSplit split = splitCallingConvention(program, prototype);
		String parseable = split.prototype;

		ghidra.program.model.data.FunctionDefinitionDataType signature = null;
		String lastError = null;
		for (ghidra.program.model.listing.FunctionSignature base : candidateBases(function)) {
			try {
				var parser = new ghidra.app.util.parser.FunctionSignatureParser(dtm, queryService);
				signature = parser.parse(base, parseable);
				if (signature != null) {
					break;
				}
			}
			catch (Exception e) {
				lastError = e.getMessage();
				signature = null;
			}
		}
		if (signature == null) {
			throw ApiException.badRequest("could not parse prototype '" + prototype + "': " +
				(lastError == null ? "no candidate signature matched" : lastError) +
				hintFor(prototype));
		}

		if (split.convention != null) {
			try {
				signature.setCallingConvention(split.convention);
			}
			catch (Exception e) {
				throw ApiException.badRequest("unknown calling convention '" + split.convention +
					"' for " + program.getLanguageID() + "; available: " +
					String.join(", ", callingConventionNames(program)));
			}
		}

		FunctionDefinitionDataType finalSignature = signature;
		int tx = program.startTransaction("Set function prototype via MCP");
		boolean commit = false;
		try {
			var cmd = new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
				function.getEntryPoint(), finalSignature, SourceType.USER_DEFINED);
			boolean ok = cmd.applyTo(program, TaskMonitor.DUMMY);
			if (!ok) {
				throw ApiException.internal("Ghidra rejected the prototype: " + cmd.getStatusMsg(), null);
			}
			commit = true;
		}
		finally {
			program.endTransaction(tx, commit);
		}

		Map<String, Object> result = new LinkedHashMap<>();
		result.put("function", function.getName());
		result.put("address", function.getEntryPoint().toString());
		result.put("prototype", parseable);
		result.put("callingConvention", split.convention);
		result.put("signature", Jsonify.safe(() -> function.getPrototypeString(false, false)));
		result.put("returnType", Jsonify.safe(() -> function.getReturnType().getName()));
		result.put("parameters", Jsonify.parameters(function));
		return result;
	}

	/** A prototype with any calling-convention keyword removed, plus that keyword. */
	private record CallingConventionSplit(String prototype, String convention) {
	}

	/**
	 * Pulls a calling convention keyword out of a prototype string.
	 *
	 * <p>Matches against the conventions the program's compiler spec actually
	 * defines, so "int __cdecl f(int)" and "int __stdcall f(int)" are handled while
	 * a type that merely contains an underscore is left alone.
	 */
	static CallingConventionSplit splitCallingConvention(Program program, String prototype) {
		if (prototype == null || prototype.isBlank()) {
			return new CallingConventionSplit(prototype, null);
		}
		for (String name : callingConventionNames(program)) {
			// Match the keyword as a whole word, with and without a leading
			// underscore (agents write both "__cdecl" and "_cdecl").
			for (String token : new String[] { name, name.startsWith("_") ? name : "_" + name }) {
				java.util.regex.Matcher m = java.util.regex.Pattern
					.compile("(?<![A-Za-z0-9_])" + java.util.regex.Pattern.quote(token)
						+ "(?![A-Za-z0-9_])")
					.matcher(prototype);
				if (m.find()) {
					String cleaned = (prototype.substring(0, m.start()) + " " +
						prototype.substring(m.end())).replaceAll("\\s+", " ").trim();
					return new CallingConventionSplit(cleaned, name);
				}
			}
		}
		return new CallingConventionSplit(prototype, null);
	}

	private static List<String> callingConventionNames(Program program) {
		List<String> names = new ArrayList<>();
		try {
			for (ghidra.program.model.lang.PrototypeModel model : program.getCompilerSpec()
					.getCallingConventions()) {
				if (model.getName() != null) {
					names.add(model.getName());
				}
			}
		}
		catch (RuntimeException e) {
			// A program without a compiler spec simply has no keywords to strip.
		}
		return names;
	}

	/**
	 * Base signatures to try, in order of how much context they provide.
	 *
	 * <p>The function's live signature first, then one rebuilt from the database
	 * (which matters right after a rename, when the decompiler's cached signature
	 * can still be the auto-analysis one), and finally {@code null} so a bare
	 * "int f(char *s)" still parses.
	 */
	private static List<ghidra.program.model.listing.FunctionSignature> candidateBases(Function f) {
		List<ghidra.program.model.listing.FunctionSignature> bases = new ArrayList<>();
		try {
			bases.add(new ghidra.program.model.data.FunctionDefinitionDataType(f, false));
		}
		catch (RuntimeException e) {
			// A function whose signature is not yet defined can still be parsed
			// against the null base below.
		}
		bases.add(f.getSignature());
		bases.add(null);
		return bases;
	}

	private static String hintFor(String prototype) {
		return ". Prototype must look like C, e.g. 'int __cdecl f(char *name, int count)'. " +
			"Unknown types are the usual cause of a parse failure.";
	}

	/** Address of the first instruction of a function (helper for callers). */
	public static Address entry(Function function) {
		return function.getEntryPoint();
	}

	/** Names of the decompiler's local symbols, used for suggestions. */
	public static List<String> localNames(Program program, Function function) {
		HighFunction hf = highFunction(program, function, 60);
		List<String> names = new ArrayList<>();
		if (hf == null || hf.getLocalSymbolMap() == null) {
			return names;
		}
		java.util.Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
		while (it.hasNext()) {
			names.add(it.next().getName());
		}
		return names;
	}
}
