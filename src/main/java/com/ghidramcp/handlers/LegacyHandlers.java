/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 *
 * Compatibility layer for the original GhidraMCP HTTP API.
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
import com.ghidramcp.core.Decompiler;
import com.ghidramcp.core.Lookup;
import com.ghidramcp.util.ApiResponse;
import com.ghidramcp.util.Json;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * The original GhidraMCP endpoints, re-implemented on top of the new handlers.
 *
 * <p>Why keep a legacy surface at all? Prompts and MCP client configurations in
 * the wild already say "call list_methods / decompile_function / rename_function".
 * Keeping those verbs answerable means an existing setup keeps working after
 * upgrading the plugin, and the old Python bridge can talk to this server too.
 *
 * <p>The original API was inconsistent about verb and encoding: some endpoints
 * took a raw text body, some took form parameters, some were GET with query
 * parameters. Every alias here therefore accepts GET and POST and reads
 * parameters from whichever place they arrived ({@link ApiRequest#param}).
 */
public final class LegacyHandlers {

	private LegacyHandlers() {
	}

	public static void register(Router router, ApiContext ctx) {

		router.any("/methods", "legacy",
			"Legacy: function names with pagination (alias of /functions)", req -> {
				Program p = ctx.requireProgram();
				List<Object> names = new ArrayList<>();
				for (Function f : ctx.index(p).functions()) {
					names.add(f.getName());
				}
				return MetaHandlers.page(names, req, 100);
			});

		router.any("/classes", "legacy",
			"Legacy: namespace names with pagination", req ->
				MetaHandlers.page(namespaces(ctx), req, 100));

		router.any("/renameFunction", "legacy",
			"Legacy: rename a function by its current name", req -> {
				String oldName = req.require("oldName", "old_name");
				String newName = req.require("newName", "new_name");
				return ApiResponse.json(ctx.mutate("Rename function via MCP", () -> {
					Program p = ctx.requireProgram();
					Function f = FunctionHandlers.requireFunction(p, oldName);
					String previous = f.getName();
					f.setName(newName, SourceType.USER_DEFINED);
					Map<String, Object> body = new LinkedHashMap<>();
					body.put("oldName", previous);
					body.put("newName", f.getName());
					body.put("address", f.getEntryPoint().toString());
					return body;
				}));
			});

		router.any("/renameData", "legacy",
			"Legacy: label the data at an address", req ->
				ApiResponse.json(ctx.mutate("Rename data via MCP", () -> {
					Program p = ctx.requireProgram();
					Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
					String newName = req.require("newName", "new_name", "name");
					AnalysisHandlers.renameAt(p, a, newName);
					return Map.of("address", a.toString(), "newName", newName);
				})));

		router.any("/renameVariable", "legacy",
			"Legacy: rename a local variable (functionName, oldName, newName)", req -> {
				String functionName = req.require("functionName", "function", "name");
				String oldName = req.require("oldName", "old_name");
				String newName = req.require("newName", "new_name");
				return reDispatch(router, ctx, "/variables/rename", Map.of(
					"function", functionName,
					"oldName", oldName,
					"newName", newName));
			});

		router.any("/list_functions", "legacy",
			"Legacy: 'name at address' lines for every function", req -> {
				Program p = ctx.requireProgram();
				List<Object> lines = new ArrayList<>();
				for (Function f : ctx.index(p).functions()) {
					lines.add(f.getName() + " at " + f.getEntryPoint());
				}
				return MetaHandlers.page(lines, req, 100000);
			});

		router.any("/get_function_by_address", "legacy",
			"Legacy: function details for an address", req -> ctx.read(() -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				Function f = p.getFunctionManager().getFunctionContaining(a);
				if (f == null) {
					throw ApiException.notFound("no function at " + a);
				}
				return ApiResponse.json(Jsonify.functionDetailed(f));
			}));

		router.any("/rename_function_by_address", "legacy",
			"Legacy: rename the function at an address", req ->
				ApiResponse.json(ctx.mutate("Rename function via MCP", () -> {
					Program p = ctx.requireProgram();
					Function f = FunctionHandlers.requireFunction(p,
						req.require("function_address", "address", "addr"));
					f.setName(req.require("new_name", "newName"), SourceType.USER_DEFINED);
					return Map.of("name", f.getName(), "address", f.getEntryPoint().toString());
				})));

		router.any("/set_function_prototype", "legacy",
			"Legacy: apply a C prototype to the function at an address", req ->
				ApiResponse.json(ctx.mutate("Set function prototype via MCP", () -> Decompiler.applyPrototype(
					ctx, ctx.requireProgram(),
					FunctionHandlers.requireFunction(ctx.requireProgram(),
						req.require("function_address", "address", "addr")),
					req.require("prototype")))));

		router.any("/set_local_variable_type", "legacy",
			"Legacy: change a local variable's type", req ->
				reDispatch(router, ctx, "/variables/retype", Map.of(
					"function", req.require("function_address", "address", "addr"),
					"variable", req.require("variable_name", "variable", "oldName"),
					"type", req.require("new_type", "type"))));

		router.any("/searchFunctions", "legacy",
			"Legacy: substring search over function names", req -> {
				String query = req.require("query", "q");
				Program p = ctx.requireProgram();
				List<Object> lines = new ArrayList<>();
				for (Function f : ctx.index(p).functions()) {
					if (f.getName().toLowerCase().contains(query.toLowerCase())) {
						lines.add(f.getName() + " @ " + f.getEntryPoint());
					}
				}
				return MetaHandlers.page(lines, req, 100);
			});

		router.any("/xrefs_to", "legacy", "Legacy/alias of /xrefs/to", req ->
			SymbolHandlers.legacyXrefs(ctx, req, true));

		router.any("/xrefs_from", "legacy", "Legacy/alias of /xrefs/from", req ->
			SymbolHandlers.legacyXrefs(ctx, req, false));

		router.any("/function_xrefs", "legacy",
			"Legacy: references to a function by name", req ->
				SymbolHandlers.legacyFunctionXrefs(ctx, req));

		router.any("/set_decompiler_comment", "legacy",
			"Legacy: comment shown in the decompiler", req ->
				reDispatch(router, ctx, "/comments/set", Map.of(
					"address", MetaHandlers.requireAddress(req),
					"comment", req.require("comment", "text"),
					"kind", "eol")));

		router.any("/set_disassembly_comment", "legacy",
			"Legacy: comment shown in the disassembly listing", req ->
				reDispatch(router, ctx, "/comments/set", Map.of(
					"address", MetaHandlers.requireAddress(req),
					"comment", req.require("comment", "text"),
					"kind", "eol")));

		// The original /data endpoint listed "address: label = value" lines.
		router.any("/data_items", "legacy", "Legacy: 'address: label = value' lines", req -> {
			List<Object> lines = new ArrayList<>();
			for (Object o : legacyDataLines(ctx, req)) {
				lines.add(o);
			}
			return MetaHandlers.page(lines, req, 100);
		});
	}

	// ---------------------------------------------------------------- helpers

	private static List<Object> legacyDataLines(ApiContext ctx, ApiRequest req) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			List<Object> lines = new ArrayList<>();
			var it = p.getListing().getDefinedData(true);
			while (it.hasNext()) {
				var d = it.next();
				String label = d.getLabel() == null ? "(unnamed)" : d.getLabel();
				lines.add(d.getAddress() + ": " + label + " = " +
					Jsonify.safe(() -> d.getDefaultValueRepresentation()));
			}
			return lines;
		});
	}

	private static List<Object> namespaces(ApiContext ctx) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			java.util.Set<String> seen = new java.util.LinkedHashSet<>();
			for (Symbol s : ctx.index(p).symbols()) {
				var ns = s.getParentNamespace();
				if (ns != null && !ns.isGlobal()) {
					seen.add(ns.getName(true));
				}
			}
			List<String> sorted = new ArrayList<>(seen);
			java.util.Collections.sort(sorted);
			return new ArrayList<Object>(sorted);
		});
	}

	/**
	 * Re-dispatches a legacy call onto a modern endpoint through the router.
	 *
	 * <p>Routing the call instead of duplicating the logic keeps one
	 * implementation per operation, so a legacy verb cannot silently drift away
	 * from the modern one (including its error messages).
	 */
	private static ApiResponse reDispatch(Router router, ApiContext ctx, String target,
			Map<String, String> form) {
		try {
			return router.handle("POST", target, ApiRequest.synthetic(target, Map.of(), form));
		}
		catch (ApiException e) {
			throw e;
		}
		catch (Exception e) {
			throw ApiException.internal(e.getMessage(), e);
		}
	}
}
