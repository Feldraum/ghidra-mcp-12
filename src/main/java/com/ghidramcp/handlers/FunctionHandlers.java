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
import com.ghidramcp.api.ProgramIndex;
import com.ghidramcp.api.Router;
import com.ghidramcp.core.Decompiler;
import com.ghidramcp.core.Lookup;
import com.ghidramcp.util.ApiResponse;
import com.ghidramcp.util.Json;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

/**
 * Functions: enumeration, search, decompilation, disassembly, p-code, call
 * graphs and the mutating operations (create, delete, rename, prototype).
 *
 * <p>The decompiler is the single most valuable thing an agent asks Ghidra for,
 * so {@link Decompiler} keeps one warmed up per program instead of paying for a
 * fresh {@code DecompInterface} (which re-reads the binary's metadata) on every
 * request.
 */
public final class FunctionHandlers {

	private FunctionHandlers() {
	}

	public static void register(Router router, ApiContext ctx) {

		// ---------------------------------------------------------------- reads
		router.get("/functions", "function",
			"List functions (compact records). Filters: name (substring), namespace, range",
			req -> ApiResponse.json(pageFunctions(ctx, req, 200)));

		router.get("/functions/list", "function", "Alias of /functions",
			req -> ApiResponse.json(pageFunctions(ctx, req, 200)));

		router.get("/functions/count", "function", "Number of functions in the program",
			req -> ctx.readJson(() -> Map.of("count",
				ctx.index(ctx.requireProgram()).functions().size())));

		router.get("/functions/search", "function",
			"Search functions by name substring, optionally including thunks/externals",
			req -> ApiResponse.json(searchFunctions(ctx, req)));

		router.get("/functions/{address}", "function",
			"Full details for the function at an address or with a given name", req ->
				ctx.readJson(() -> {
					Program p = ctx.requireProgram();
					String target = pathParam(req);
					Function f = Lookup.function(p, target);
					if (f == null) {
						throw ApiException.notFound("no function at or containing '" + target + "'");
					}
					Map<String, Object> body = Jsonify.functionDetailed(f);
					body.put("callers", callers(p, f));
					body.put("callees", callees(p, f));
					body.put("strings", referencedStrings(p, f));
					return body;
				}));

		router.get("/functions/by-address", "function", "Function containing an address",
			req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				Function f = p.getFunctionManager().getFunctionContaining(a);
				if (f == null) {
					throw ApiException.notFound("no function contains " + a);
				}
				Map<String, Object> body = Jsonify.functionDetailed(f);
				body.put("callers", callers(p, f));
				body.put("callees", callees(p, f));
				body.put("strings", referencedStrings(p, f));
				return body;
			}));

		// Decompile/disassemble are registered for both verbs: the original
		// GhidraMCP API POSTs a name or address to them, while a plain GET is the
		// natural REST shape for a read. Parameters are read from the body, the
		// query string or the raw text body, whichever the client used.
		router.any("/decompile", "function",
			"Decompile a function by name or address and return C source", req ->
				ctx.read(() -> {
					Program p = ctx.requireProgram();
					String target = req.firstOf("name", "function", "address", "addr");
					if (target == null) {
						target = req.paramOrBody("name");
					}
					return ApiResponse.json(decompile(ctx, p, target, req));
				}));

		router.any("/decompile_function", "function", "Alias of /decompile (legacy)",
			req -> ctx.read(() -> {
				Program p = ctx.requireProgram();
				String target = req.firstOf("address", "addr", "name", "function");
				if (target == null) {
					target = req.paramOrBody("name");
				}
				return ApiResponse.json(decompile(ctx, p, target, req));
			}));

		router.any("/disassemble", "function",
			"Disassemble a function (name or address) to address/instruction/comment lines",
			req -> ctx.read(() -> {
				Program p = ctx.requireProgram();
				String target = req.firstOf("name", "function", "address", "addr");
				if (target == null) {
					target = req.paramOrBody("name");
				}
				return ApiResponse.json(disassemble(p, target, req));
			}));

		router.any("/disassemble_function", "function", "Alias of /disassemble (legacy)",
			req -> ctx.read(() -> {
				Program p = ctx.requireProgram();
				String target = req.firstOf("address", "addr", "name", "function");
				if (target == null) {
					target = req.paramOrBody("name");
				}
				return ApiResponse.json(disassemble(p, target, req));
			}));

		router.get("/functions/pcode", "function",
			"P-code (intermediate representation) for a function", req ->
				ctx.read(() -> {
					Program p = ctx.requireProgram();
					Function f = requireFunction(p, req.firstOf("name", "function", "address", "addr"));
					boolean ssa = req.boolParam("ssa", false);
					return ApiResponse.json(Decompiler.pcode(p, f, ssa, req.intParam("timeout", 60)));
				}));

		router.get("/functions/callees", "function",
			"Functions called by a function (outgoing call graph, one level)", req ->
				ctx.read(() -> {
					Program p = ctx.requireProgram();
					Function f = requireFunction(p, req.firstOf("name", "function", "address", "addr"));
					return ApiResponse.json(Json.list(callees(p, f)));
				}));

		router.get("/functions/callers", "function",
			"Functions that call a function (incoming call graph, one level)", req ->
				ctx.read(() -> {
					Program p = ctx.requireProgram();
					Function f = requireFunction(p, req.firstOf("name", "function", "address", "addr"));
					return ApiResponse.json(Json.list(callers(p, f)));
				}));

		router.get("/functions/callgraph", "function",
			"Breadth-first call graph from a function (parameters: depth, direction)",
			req -> ctx.readJson(() -> callGraph(ctx.requireProgram(), req)));

		router.get("/functions/basic-blocks", "function",
			"Basic blocks with their instruction ranges and successors", req ->
				ctx.read(() -> {
					Program p = ctx.requireProgram();
					Function f = requireFunction(p, req.firstOf("name", "function", "address", "addr"));
					return ApiResponse.json(basicBlocks(p, f));
				}));

		// ------------------------------------------------------------- mutations
		router.post("/functions/rename", "function",
			"Rename a function (parameters: address|name, newName)", req ->
				mutateFunction(ctx, req, (p, f) -> {
					String newName = req.require("newName", "new_name", "name");
					f.setName(newName, SourceType.USER_DEFINED);
					return Map.of("name", f.getName(), "address", f.getEntryPoint().toString());
				}));

		router.post("/functions/set-prototype", "function",
			"Apply a C function prototype, e.g. 'int __cdecl f(char *s, int n)'", req ->
				mutateFunction(ctx, req, (p, f) -> Decompiler.applyPrototype(ctx, p, f,
					req.require("prototype", "signature"))));

		router.post("/functions/set-comment", "function",
			"Set a function comment (parameters: address|name, comment)", req ->
				mutateFunction(ctx, req, (p, f) -> {
					String comment = req.param("comment", "");
					f.setComment(comment);
					return Map.of("comment", String.valueOf(f.getComment()));
				}));

		router.post("/functions/create", "function",
			"Create a function at an address (optionally from an explicit body range)", req ->
				ctx.mutateJson("Create function via MCP", () -> {
					Program p = ctx.requireProgram();
					Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
					if (p.getFunctionManager().getFunctionAt(a) != null) {
						throw ApiException.conflict("a function already exists at " + a);
					}
					Function f = p.getFunctionManager().createFunction(
						req.param("name", null), a, null, SourceType.USER_DEFINED);
					if (f == null) {
						throw ApiException.internal("Ghidra refused to create a function at " + a, null);
					}
					return Map.of("name", f.getName(), "address", f.getEntryPoint().toString());
				}));

		router.post("/functions/delete", "function",
			"Delete a function, leaving its bytes in place", req ->
				mutateFunction(ctx, req, (p, f) -> {
					String name = f.getName();
					String addr = f.getEntryPoint().toString();
					p.getFunctionManager().removeFunction(f.getEntryPoint());
					return Map.of("deleted", name, "address", addr);
				}));

		router.post("/functions/set-thunk", "function",
			"Mark a function as a thunk of another function", req ->
				mutateFunction(ctx, req, (p, f) -> {
					Function target = requireFunction(p,
						req.require("target", "targetFunction"));
					f.setThunkedFunction(target);
					return Map.of("thunk", f.getName(), "target", target.getName());
				}));

		router.post("/functions/tag", "function",
			"Add a function tag to a function", req ->
				mutateFunction(ctx, req, (p, f) -> {
					String tag = req.require("tag");
					var tagMgr = p.getFunctionManager().getFunctionTagManager();
					var functionTag = tagMgr.getFunctionTag(tag);
					if (functionTag == null) {
						functionTag = tagMgr.createFunctionTag(tag, "Created via GhidraMCP12");
					}
					f.addTag(tag);
					return Map.of("tag", functionTag.getName(), "function", f.getName());
				}));

		router.post("/functions/auto-analyze", "function",
			"Run auto analysis over a function's body range", req ->
				ctx.mutateJson("Auto-analyze function", () -> {
					Program p = ctx.requireProgram();
					Function f = requireFunction(p, req.firstOf("name", "function", "address", "addr"));
					var manager =
						ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(p);
					if (manager == null) {
						throw ApiException.internal(
							"Ghidra has no AutoAnalysisManager for this program", null);
					}
					manager.reAnalyzeAll(f.getBody());
					manager.startAnalysis(ghidra.util.task.TaskMonitor.DUMMY);
					Map<String, Object> body = new LinkedHashMap<>();
					body.put("function", f.getName());
					body.put("address", f.getEntryPoint().toString());
					body.put("bodyRange", f.getBody().toString());
					body.put("analysisStarted", true);
					return body;
				}));

		// --------------------------------------------------------------- thunks
		router.get("/functions/externals", "function", "List external (imported) functions", req ->
				ctx.read(() -> {
					Program p = ctx.requireProgram();
					List<Object> items = new ArrayList<>();
					FunctionIterator it = p.getFunctionManager().getExternalFunctions();
					while (it.hasNext()) {
						items.add(Jsonify.function(it.next()));
					}
					return ApiResponse.json(
						com.ghidramcp.util.Page.of(items, req, 500));
				}));

		router.get("/functions/thunks", "function", "List thunk functions", req ->
				ctx.read(() -> {
					Program p = ctx.requireProgram();
					List<Object> items = new ArrayList<>();
					for (Function f : ctx.index(p).functions()) {
						if (f.isThunk()) {
							items.add(Jsonify.function(f));
						}
					}
					return ApiResponse.json(Json.list(items));
				}));
	}

	// ------------------------------------------------------------------- reads

	private static Map<String, Object> pageFunctions(ApiContext ctx, ApiRequest req, int defaultLimit) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			String nameFilter = req.param("name");
			String namespaceFilter = req.param("namespace");
			List<Object> items = new ArrayList<>();
			for (Function f : ctx.index(p).functions()) {
				if (nameFilter != null && !f.getName().toLowerCase()
						.contains(nameFilter.toLowerCase())) {
					continue;
				}
				if (namespaceFilter != null && !namespaceContains(f, namespaceFilter)) {
					continue;
				}
				items.add(Jsonify.function(f));
			}
			var paging = req.paging(defaultLimit);
			List<Object> slice = paging.slice(items);
			Map<String, Object> envelope = new LinkedHashMap<>();
			envelope.put("count", items.size());
			envelope.put("offset", paging.offset());
			envelope.put("limit", paging.limit());
			envelope.put("truncated", paging.offset() + paging.limit() < items.size());
			envelope.put("items", slice);
			return envelope;
		});
	}

	private static boolean namespaceContains(Function f, String filter) {
		Namespace ns = f.getParentNamespace();
		return ns != null && ns.getName(true).toLowerCase().contains(filter.toLowerCase());
	}

	private static ApiResponse searchFunctions(ApiContext ctx, ApiRequest req) {
		String query = req.require("query", "q", "name");
		boolean caseSensitive = req.boolParam("caseSensitive", false);
		String needle = caseSensitive ? query : query.toLowerCase();
		return ApiResponse.json(ctx.read(() -> {
			Program p = ctx.requireProgram();
			List<Object> items = new ArrayList<>();
			for (Function f : ctx.index(p).functions()) {
				String n = caseSensitive ? f.getName() : f.getName().toLowerCase();
				if (n.contains(needle)) {
					items.add(Jsonify.function(f));
				}
			}
			var paging = req.paging(200);
			Map<String, Object> envelope = new LinkedHashMap<>();
			envelope.put("query", query);
			envelope.put("count", items.size());
			envelope.put("offset", paging.offset());
			envelope.put("limit", paging.limit());
			envelope.put("truncated", paging.offset() + paging.limit() < items.size());
			envelope.put("items", paging.slice(items));
			return envelope;
		}));
	}

	/** Resolves a function from a name/address string, failing with a useful error. */
	static Function requireFunction(Program p, String target) {
		if (target == null || target.isBlank()) {
			throw ApiException.badRequest("provide 'address' or 'name' of a function");
		}
		Function f = Lookup.function(p, target);
		if (f == null) {
			ProgramIndex idx = ProgramIndex.of(p);
			List<String> near = new ArrayList<>();
			for (Function cand : idx.functions()) {
				if (cand.getName().toLowerCase().contains(target.toLowerCase())) {
					near.add(cand.getName() + " @ " + cand.getEntryPoint());
					if (near.size() >= 10) {
						break;
					}
				}
			}
			throw ApiException.notFound("no function at or containing '" + target + "'" +
				(near.isEmpty() ? "" : "; similar functions: " + String.join(", ", near)));
		}
		return f;
	}

	private static Map<String, Object> decompile(ApiContext ctx, Program p, String target,
			ApiRequest req) {
		if (target == null || target.isBlank()) {
			throw ApiException.badRequest("provide 'address' or 'name' of a function to decompile");
		}
		Function f = requireFunction(p, target);
		int timeout = Math.min(Math.max(req.intParam("timeout", 60), 1), 600);
		boolean includeSignature = req.boolParam("includeSignature", true);
		var result = Decompiler.decompile(p, f, timeout);
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("function", f.getName());
		body.put("address", f.getEntryPoint().toString());
		body.put("nameWithNamespace", f.getName(true));
		body.put("decompiled", result.code());
		if (includeSignature) {
			body.put("signature", result.signature());
			body.put("prototype", Jsonify.safe(() -> f.getPrototypeString(false, false)));
		}
		body.put("timedOut", result.timedOut());
		body.put("error", result.error());
		body.put("parameters", Jsonify.parameters(f));
		body.put("localVariables", Jsonify.locals(f));
		return body;
	}

	private static Map<String, Object> disassemble(Program p, String target, ApiRequest req) {
		Function f = requireFunction(p, target);
		boolean withBytes = req.boolParam("bytes", false);
		Listing listing = p.getListing();
		List<Object> lines = new ArrayList<>();
		StringBuilder text = new StringBuilder();

		InstructionIterator it = listing.getInstructions(f.getBody(), true);
		while (it.hasNext()) {
			Instruction instr = it.next();
			Address a = instr.getAddress();
			String eol = listing.getComment(CommentType.EOL, a);
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("address", a.toString());
			m.put("instruction", instr.toString());
			m.put("mnemonic", instr.getMnemonicString());
			m.put("comment", eol);
			if (withBytes) {
				m.put("bytes", com.ghidramcp.api.Jsonify.safe(() -> instr.getBytes().length > 0
					? hex(instr.getBytes()) : null));
			}
			lines.add(m);
			text.append(a).append(": ").append(instr)
				.append(eol == null ? "" : "  ; " + eol).append('\n');
		}

		Map<String, Object> body = new LinkedHashMap<>();
		body.put("function", f.getName());
		body.put("address", f.getEntryPoint().toString());
		body.put("instructionCount", lines.size());
		body.put("text", text.toString());
		body.put("instructions", lines);
		return body;
	}

	private static String hex(byte[] data) {
		StringBuilder sb = new StringBuilder(data.length * 2);
		for (byte b : data) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	static List<Object> callees(Program p, Function f) {
		List<Object> out = new ArrayList<>();
		java.util.Set<String> seen = new java.util.LinkedHashSet<>();
		for (Function callee : f.getCalledFunctions(ghidra.util.task.TaskMonitor.DUMMY)) {
			String key = callee.getEntryPoint().toString();
			if (seen.add(key)) {
				Map<String, Object> m = new LinkedHashMap<>();
				m.put("name", callee.getName());
				m.put("address", key);
				m.put("isExternal", callee.isExternal());
				m.put("isThunk", callee.isThunk());
				out.add(m);
			}
		}
		// Direct call references catch calls Ghidra has not turned into functions.
		InstructionIterator it = p.getListing().getInstructions(f.getBody(), true);
		while (it.hasNext()) {
			Instruction instr = it.next();
			if (!instr.getFlowType().isCall()) {
				continue;
			}
			for (Reference r : instr.getReferencesFrom()) {
				if (!r.getReferenceType().isCall()) {
					continue;
				}
				Address to = r.getToAddress();
				if (seen.add(to.toString())) {
					Function target = p.getFunctionManager().getFunctionAt(to);
					Map<String, Object> m = new LinkedHashMap<>();
					m.put("name", target == null ? null : target.getName());
					m.put("address", to.toString());
					m.put("resolved", target != null);
					out.add(m);
				}
			}
		}
		return out;
	}

	static List<Object> callers(Program p, Function f) {
		List<Object> out = new ArrayList<>();
		java.util.Set<String> seen = new java.util.LinkedHashSet<>();
		for (Function caller : f.getCallingFunctions(ghidra.util.task.TaskMonitor.DUMMY)) {
			String key = caller.getEntryPoint().toString();
			if (seen.add(key)) {
				Map<String, Object> m = new LinkedHashMap<>();
				m.put("name", caller.getName());
				m.put("address", key);
				out.add(m);
			}
		}
		var refs = p.getReferenceManager().getReferencesTo(f.getEntryPoint());
		while (refs.hasNext()) {
			Reference r = refs.next();
			Function caller = p.getFunctionManager().getFunctionContaining(r.getFromAddress());
			if (caller != null && seen.add(caller.getEntryPoint().toString())) {
				Map<String, Object> m = new LinkedHashMap<>();
				m.put("name", caller.getName());
				m.put("address", caller.getEntryPoint().toString());
				m.put("callSite", r.getFromAddress().toString());
				out.add(m);
			}
		}
		return out;
	}

	/** Strings referenced by a function, either directly or through a pointer. */
	private static List<Object> referencedStrings(Program p, Function f) {
		List<Object> out = new ArrayList<>();
		java.util.Set<String> seen = new java.util.LinkedHashSet<>();
		InstructionIterator it = p.getListing().getInstructions(f.getBody(), true);
		while (it.hasNext()) {
			Instruction instr = it.next();
			for (Reference r : instr.getReferencesFrom()) {
				Address to = r.getToAddress();
				if (!seen.add(to.toString())) {
					continue;
				}
				Data d = p.getListing().getDataAt(to);
				if (d != null && com.ghidramcp.api.Types.isStringLike(d.getDataType())) {
					Map<String, Object> m = new LinkedHashMap<>();
					m.put("address", to.toString());
					m.put("value", com.ghidramcp.api.Jsonify.safe(() -> d.getValue().toString()));
					m.put("type", com.ghidramcp.api.Jsonify.safe(() -> d.getDataType().getName()));
					out.add(m);
				}
			}
		}
		return out;
	}

	private static Map<String, Object> callGraph(Program p, ApiRequest req) {
		Function root = requireFunction(p, req.firstOf("name", "function", "address", "addr"));
		int depth = Math.min(Math.max(req.intParam("depth", 2), 1), 6);
		String direction = req.param("direction", "callees");

		List<Object> nodes = new ArrayList<>();
		List<Object> edges = new ArrayList<>();
		java.util.Set<String> visited = new java.util.LinkedHashSet<>();
		java.util.Deque<Function> frontier = new java.util.ArrayDeque<>();
		frontier.add(root);
		visited.add(root.getEntryPoint().toString());
		nodes.add(node(root));

		int level = 0;
		while (!frontier.isEmpty() && level < depth) {
			int size = frontier.size();
			for (int i = 0; i < size; i++) {
				Function current = frontier.poll();
				List<Object> next = "callers".equalsIgnoreCase(direction)
					? callers(p, current) : callees(p, current);
				for (Object o : next) {
					if (!(o instanceof Map<?, ?> m)) {
						continue;
					}
					Object addr = m.get("address");
					Object name = m.get("name");
					if (addr == null) {
						continue;
					}
					Map<String, Object> edge = new LinkedHashMap<>();
					edge.put("from", current.getEntryPoint().toString());
					edge.put("to", addr.toString());
					edges.add(edge);

					if (visited.add(addr.toString())) {
						Function f = p.getFunctionManager().getFunctionAt(
							p.getAddressFactory().getAddress(addr.toString()));
						Map<String, Object> n = new LinkedHashMap<>();
						n.put("name", name);
						n.put("address", addr.toString());
						n.put("isExternal", f != null && f.isExternal());
						nodes.add(n);
						if (f != null) {
							frontier.add(f);
						}
					}
				}
			}
			level++;
		}

		Map<String, Object> body = new LinkedHashMap<>();
		body.put("root", root.getName());
		body.put("rootAddress", root.getEntryPoint().toString());
		body.put("direction", direction);
		body.put("depth", depth);
		body.put("nodes", nodes);
		body.put("edges", edges);
		return body;
	}

	private static Map<String, Object> node(Function f) {
		Map<String, Object> n = new LinkedHashMap<>();
		n.put("name", f.getName());
		n.put("address", f.getEntryPoint().toString());
		n.put("isExternal", f.isExternal());
		return n;
	}

	private static Map<String, Object> basicBlocks(Program p, Function f) {
		List<Object> blocks = new ArrayList<>();
		int index = 0;
		for (var range : f.getBody()) {
			Map<String, Object> b = new LinkedHashMap<>();
			b.put("index", index++);
			b.put("start", range.getMinAddress().toString());
			b.put("end", range.getMaxAddress().toString());
			List<Object> instrs = new ArrayList<>();
			InstructionIterator instrIt = p.getListing().getInstructions(
				new ghidra.program.model.address.AddressSet(range), true);
			String lastInstruction = null;
			while (instrIt.hasNext()) {
				Instruction instr = instrIt.next();
				instrs.add(instr.getAddress().toString());
				lastInstruction = instr.toString();
			}
			b.put("instructionCount", instrs.size());
			b.put("instructions", instrs);
			b.put("lastInstruction", lastInstruction);
			blocks.add(b);
		}
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("function", f.getName());
		body.put("address", f.getEntryPoint().toString());
		body.put("blockCount", blocks.size());
		body.put("blocks", blocks);
		return body;
	}

	// --------------------------------------------------------------- mutations

	/** Shared plumbing for "resolve the function, then change it". */
	private static ApiResponse mutateFunction(ApiContext ctx, ApiRequest req,
			FunctionMutation mutation) {
		return ApiResponse.json(ctx.mutate("GhidraMCP12: " + req.path(), () -> {
			Program p = ctx.requireProgram();
			Function f = requireFunction(p, req.firstOf("address", "addr", "name", "function"));
			return mutation.apply(p, f);
		}));
	}

	/** A change applied to one resolved function. */
	@FunctionalInterface
	private interface FunctionMutation {
		Map<String, Object> apply(Program p, Function f) throws Exception;
	}

	/**
	 * The target of a {@code /functions/{address}} request.
	 *
	 * <p>The router captures the path segment as a path parameter, so this is
	 * normally a straight read; the query-parameter fallbacks keep the endpoint
	 * usable when it is called as {@code /functions?address=...}.
	 */
	private static String pathParam(ApiRequest req) {
		String p = req.pathParam("address");
		if (p != null && !p.isBlank()) {
			return p;
		}
		String target = req.firstOf("address", "addr", "name", "function");
		if (target == null) {
			throw ApiException.badRequest("provide the function address or name in the path");
		}
		return target;
	}
}
