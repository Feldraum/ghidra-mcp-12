/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.handlers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.ghidramcp.api.ApiContext;
import com.ghidramcp.api.ApiException;
import com.ghidramcp.api.ApiRequest;
import com.ghidramcp.api.Jsonify;
import com.ghidramcp.api.Router;
import com.ghidramcp.api.Types;
import com.ghidramcp.core.Decompiler;
import com.ghidramcp.util.ApiResponse;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;

/**
 * Parameters and local variables, including the decompiler-driven renames and
 * retypes.
 *
 * <p>Renaming a variable in Ghidra is not a simple setter: the decompiler owns
 * its own symbol table, and the database is only updated through
 * {@link HighFunctionDBUtil}. The subtlety that bites implementations is that
 * changing a <em>parameter</em> may require committing the whole (possibly
 * edited) prototype first - see {@link #requiresFullCommit}.
 */
public final class VariableHandlers {

	private VariableHandlers() {
	}

	public static void register(Router router, ApiContext ctx) {

		router.lookup("/variables", "variable",
			"List parameters and locals of a function (address|name)", req ->
				ctx.read(() -> {
					Program p = ctx.requireProgram();
					Function f = FunctionHandlers.requireFunction(p,
						req.firstOf("address", "addr", "name", "function"));
					Map<String, Object> body = new LinkedHashMap<>();
					body.put("function", f.getName());
					body.put("address", f.getEntryPoint().toString());
					body.put("parameters", Jsonify.parameters(f));
					body.put("localVariables", Jsonify.locals(f));
					body.put("decompilerSymbols", decompilerSymbols(ctx, p, f));
					return ApiResponse.json(body);
				}));

		router.post("/variables/rename", "variable",
			"Rename a parameter or local variable (function, oldName, newName)", req ->
				rename(ctx, req));

		router.post("/variables/retype", "variable",
			"Change a parameter or local variable's data type (function, variable, type)", req ->
				retype(ctx, req));

		router.post("/variables/set-comment", "variable",
			"Set a variable's comment", req ->
				ctx.mutateJson("Set variable comment", () -> {
					Program p = ctx.requireProgram();
					Function f = FunctionHandlers.requireFunction(p,
						req.firstOf("function", "address", "addr", "name"));
					String varName = req.require("variable", "variableName", "oldName");
					Variable v = findVariable(f, varName);
					if (v == null) {
						throw ApiException.notFound("no variable named '" + varName + "' in " +
							f.getName() + variableHint(p, f, varName));
					}
					v.setComment(req.param("comment", ""));
					Map<String, Object> body = new LinkedHashMap<>();
					body.put("variable", v.getName());
					body.put("comment", String.valueOf(v.getComment()));
					return body;
				}));

		router.post("/variables/set-storage", "variable",
			"Retarget a local variable to an explicit location: register=EAX | stack=-8 | address=0x... " +
				"(+ length)",
			req -> ctx.mutateJson("Set variable storage", () -> {
				Program p = ctx.requireProgram();
				Function f = FunctionHandlers.requireFunction(p,
					req.firstOf("function", "address", "addr", "name"));
				String varName = req.require("variable", "variableName", "oldName");
				Variable v = findVariable(f, varName);
				if (v == null) {
					throw ApiException.notFound("no variable named '" + varName + "' in " +
						f.getName() + variableHint(p, f, varName));
				}

				ghidra.program.model.listing.VariableStorage storage =
					parseStorage(p, req, v.getLength());
				// setDataType(type, storage, force, source): the storage overload is the
				// only way to move a local, and force=false lets Ghidra reject a bad fit.
				v.setDataType(v.getDataType(), storage, false, SourceType.USER_DEFINED);

				Map<String, Object> body = new LinkedHashMap<>();
				body.put("variable", v.getName());
				body.put("storage", String.valueOf(v.getVariableStorage()));
				return body;
			}));

		router.lookup("/variables/decompiler", "variable",
			"Decompiler symbol table for a function (names as shown in the C output)", req ->
				ctx.readJson(() -> {
					Program p = ctx.requireProgram();
					Function f = FunctionHandlers.requireFunction(p,
						req.firstOf("address", "addr", "name", "function"));
					return com.ghidramcp.util.Json.list(decompilerSymbols(ctx, p, f));
				}));
	}

	// ----------------------------------------------------------------- rename

	private static ApiResponse rename(ApiContext ctx, ApiRequest req) {
		return ctx.mutateJson("Rename variable via MCP", () -> {
			Program p = ctx.requireProgram();
			Function f = FunctionHandlers.requireFunction(p,
				req.firstOf("function", "address", "addr", "name"));
			String oldName = req.require("oldName", "old_name", "variable", "variableName");
			String newName = req.require("newName", "new_name");

			Variable direct = findVariable(f, oldName);
			if (direct != null) {
				direct.setName(newName, SourceType.USER_DEFINED);
				Map<String, Object> body = new LinkedHashMap<>();
				body.put("function", f.getName());
				body.put("oldName", oldName);
				body.put("newName", direct.getName());
				body.put("mechanism", "database variable");
				return body;
			}

			// Not a database variable: it is a decompiler-only symbol, which is the
			// common case for temporaries. Those must go through HighFunctionDBUtil.
			HighSymbol symbol = findHighSymbol(p, f, oldName);
			if (symbol == null) {
				throw ApiException.notFound("no variable named '" + oldName + "' in " + f.getName() +
					variableHint(p, f, oldName));
			}
			if (findHighSymbol(p, f, newName) != null) {
				throw ApiException.conflict("a variable named '" + newName + "' already exists in " +
					f.getName());
			}
			DecompileResults results = Decompiler.results(p, f, 60);
			HighFunction hf = results == null ? null : results.getHighFunction();
			if (hf == null) {
				throw ApiException.internal("could not decompile " + f.getName() +
					" to rename its variables", null);
			}
			if (requiresFullCommit(symbol, hf)) {
				HighFunctionDBUtil.commitParamsToDatabase(hf, false,
					HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, f.getSignatureSource());
			}
			HighFunctionDBUtil.updateDBVariable(symbol, newName, null, SourceType.USER_DEFINED);

			Map<String, Object> body = new LinkedHashMap<>();
			body.put("function", f.getName());
			body.put("oldName", oldName);
			body.put("newName", newName);
			body.put("mechanism", "decompiler symbol");
			return body;
		});
	}

	// ----------------------------------------------------------------- retype

	private static ApiResponse retype(ApiContext ctx, ApiRequest req) {
		return ctx.mutateJson("Retype variable via MCP", () -> {
			Program p = ctx.requireProgram();
			Function f = FunctionHandlers.requireFunction(p,
				req.firstOf("function", "address", "addr", "name"));
			String varName = req.require("variable", "variableName", "oldName", "name");
			String typeName = req.require("type", "newType", "dataType");

			DataType dt = Types.resolve(p, typeName);
			if (dt == null) {
				throw ApiException.badRequest("unknown data type '" + typeName + "'. " +
					"Known examples: " + String.join(", ", Types.suggestions(p, typeName, 8)));
			}

			Variable direct = findVariable(f, varName);
			if (direct != null) {
				direct.setDataType(dt, SourceType.USER_DEFINED);
				Map<String, Object> body = new LinkedHashMap<>();
				body.put("function", f.getName());
				body.put("variable", direct.getName());
				body.put("dataType", dt.getName());
				body.put("dataTypePath", dt.getPathName());
				body.put("mechanism", "database variable");
				return body;
			}

			HighSymbol symbol = findHighSymbol(p, f, varName);
			if (symbol == null) {
				throw ApiException.notFound("no variable named '" + varName + "' in " + f.getName() +
					variableHint(p, f, varName));
			}
			DecompileResults results = Decompiler.results(p, f, 60);
			HighFunction hf = results == null ? null : results.getHighFunction();
			if (hf == null) {
				throw ApiException.internal("could not decompile " + f.getName(), null);
			}
			if (requiresFullCommit(symbol, hf)) {
				HighFunctionDBUtil.commitParamsToDatabase(hf, false,
					HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, f.getSignatureSource());
			}
			HighFunctionDBUtil.updateDBVariable(symbol, symbol.getName(), dt, SourceType.USER_DEFINED);

			Map<String, Object> body = new LinkedHashMap<>();
			body.put("function", f.getName());
			body.put("variable", varName);
			body.put("dataType", dt.getName());
			body.put("dataTypePath", dt.getPathName());
			body.put("mechanism", "decompiler symbol");
			return body;
		});
	}

	// ---------------------------------------------------------------- helpers

	/**
	 * Builds a {@code VariableStorage} from {@code register=}, {@code stack=} or
	 * {@code address=} parameters.
	 *
	 * <p>Ghidra 12 requires a {@code ProgramArchitecture} (which {@code Program}
	 * implements) plus varnodes/registers/addresses; there is no longer a
	 * convenient string constructor.
	 */
	private static ghidra.program.model.listing.VariableStorage parseStorage(Program p,
			ApiRequest req, int defaultLength) {
		int length = Math.max(1, req.intParam("length", defaultLength <= 0 ? 4 : defaultLength));
		String register = req.firstOf("register", "reg");
		String stack = req.param("stack");
		String address = req.firstOf("address", "addr", "at");

		try {
			if (register != null) {
				ghidra.program.model.lang.Register reg = p.getLanguage().getRegister(register);
				if (reg == null) {
					throw ApiException.badRequest("unknown register '" + register +
						"' for language " + p.getLanguageID());
				}
				if (reg.getNumBytes() < length) {
					// A wider alias of the same register (EAX -> RAX) may exist; fall
					// back to the register as-is rather than failing, since Ghidra
					// validates the fit internally.
					ghidra.program.model.lang.Register wider =
						p.getLanguage().getRegister(reg.getAddress(), length);
					if (wider != null) {
						reg = wider;
					}
				}
				return new ghidra.program.model.listing.VariableStorage(p, reg);
			}
			if (stack != null) {
				long offset = parseLong(stack);
				return new ghidra.program.model.listing.VariableStorage(p, (int) offset, length);
			}
			if (address != null) {
				var addr = com.ghidramcp.core.Lookup.address(p, address);
				return new ghidra.program.model.listing.VariableStorage(p, addr, length);
			}
		}
		catch (ghidra.util.exception.InvalidInputException e) {
			throw ApiException.badRequest("invalid storage: " + e.getMessage());
		}
		throw ApiException.badRequest(
			"provide one of 'register', 'stack' or 'address' to set the storage");
	}

	private static long parseLong(String s) {
		String t = s.trim().toLowerCase();
		try {
			if (t.startsWith("0x")) {
				return Long.parseUnsignedLong(t.substring(2), 16);
			}
			if (t.startsWith("-0x")) {
				return -Long.parseUnsignedLong(t.substring(3), 16);
			}
			return Long.parseLong(t);
		}
		catch (NumberFormatException e) {
			throw ApiException.badRequest("cannot parse number '" + s + "'");
		}
	}

	/** Finds a parameter or local variable by name (exact, then case-insensitive). */
	static Variable findVariable(Function f, String name) {
		for (Parameter param : f.getParameters()) {
			if (param.getName().equals(name)) {
				return param;
			}
		}
		for (Variable v : f.getLocalVariables()) {
			if (v.getName().equals(name)) {
				return v;
			}
		}
		for (Parameter param : f.getParameters()) {
			if (param.getName().equalsIgnoreCase(name)) {
				return param;
			}
		}
		for (Variable v : f.getLocalVariables()) {
			if (v.getName().equalsIgnoreCase(name)) {
				return v;
			}
		}
		return null;
	}

	private static HighSymbol findHighSymbol(Program p, Function f, String name) {
		HighFunction hf = Decompiler.highFunction(p, f, 60);
		if (hf == null || hf.getLocalSymbolMap() == null) {
			return null;
		}
		LocalSymbolMap map = hf.getLocalSymbolMap();
		java.util.Iterator<HighSymbol> it = map.getSymbols();
		HighSymbol ignoringCase = null;
		while (it.hasNext()) {
			HighSymbol s = it.next();
			if (s.getName().equals(name)) {
				return s;
			}
			if (ignoringCase == null && s.getName().equalsIgnoreCase(name)) {
				ignoringCase = s;
			}
		}
		return ignoringCase;
	}

	private static List<Object> decompilerSymbols(ApiContext ctx, Program p, Function f) {
		HighFunction hf = Decompiler.highFunction(p, f, 60);
		List<Object> out = new ArrayList<>();
		if (hf == null || hf.getLocalSymbolMap() == null) {
			return out;
		}
		LocalSymbolMap map = hf.getLocalSymbolMap();
		java.util.Iterator<HighSymbol> it = map.getSymbols();
		while (it.hasNext()) {
			HighSymbol s = it.next();
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("name", s.getName());
			m.put("dataType", Jsonify.safe(() -> s.getDataType().getName()));
			m.put("isParameter", s.isParameter());
			m.put("categoryIndex", s.getCategoryIndex());
			m.put("storage", Jsonify.safe(() -> s.getStorage().toString()));
			HighVariable hv = s.getHighVariable();
			m.put("highVariable", hv == null ? null : hv.getName());
			out.add(m);
		}
		return out;
	}

	/**
	 * Mirrors {@code AbstractDecompilerAction.checkFullCommit}.
	 *
	 * <p>When the decompiler's prototype no longer matches the database's (for
	 * example the user retyped a parameter), a parameter change must be preceded
	 * by committing the entire prototype, otherwise the change is silently lost
	 * on the next decompile.
	 */
	private static boolean requiresFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}
		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			// compareTo (not equals) so DynamicVariableStorage still matches.
			if (0 != param.getStorage().compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}
		return false;
	}

	/** "did you mean" list built from both the database and the decompiler. */
	private static String variableHint(Program p, Function f, String attempted) {
		List<String> names = new ArrayList<>();
		for (Parameter param : f.getParameters()) {
			names.add(param.getName());
		}
		for (Variable v : f.getLocalVariables()) {
			names.add(v.getName());
		}
		for (String n : Decompiler.localNames(p, f)) {
			if (!names.contains(n)) {
				names.add(n);
			}
		}
		if (names.isEmpty()) {
			return "";
		}
		List<String> near = new ArrayList<>();
		String needle = attempted == null ? "" : attempted.toLowerCase();
		for (String n : names) {
			if (n.toLowerCase().contains(needle) || needle.contains(n.toLowerCase())) {
				near.add(n);
			}
			if (near.size() >= 12) {
				break;
			}
		}
		if (near.isEmpty()) {
			near = names.size() > 12 ? names.subList(0, 12) : names;
		}
		return "; available variables: " + String.join(", ", near);
	}
}
