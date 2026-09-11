/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.handlers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.ghidramcp.api.ApiContext;
import com.ghidramcp.api.ApiException;
import com.ghidramcp.api.ApiRequest;
import com.ghidramcp.api.Jsonify;
import com.ghidramcp.api.ProgramIndex;
import com.ghidramcp.api.Router;
import com.ghidramcp.core.Lookup;
import com.ghidramcp.util.ApiResponse;
import com.ghidramcp.util.Json;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Symbols, namespaces, labels and cross references.
 *
 * <p>Everything here resolves names the same way ({@link Lookup}), so an agent
 * that learns "I can pass either a name or an address" has that hold across all
 * of these endpoints.
 */
public final class SymbolHandlers {

	private SymbolHandlers() {
	}

	public static void register(Router router, ApiContext ctx) {

		// ------------------------------------------------------------- listings
		router.get("/symbols", "symbol",
			"All symbols (paginated). Filters: name (substring), type, external",
			req -> ApiResponse.json(symbols(ctx, req)));

		router.get("/symbols/count", "symbol", "Number of symbols",
			req -> ctx.readJson(() -> Map.of("count",
				ctx.index(ctx.requireProgram()).symbols().size())));

		router.get("/symbols/search", "symbol", "Search symbols whose name contains a substring",
			req -> ApiResponse.json(search(ctx, req)));

		router.get("/namespaces", "symbol", "All non-global namespaces / classes",
			req -> ApiResponse.json(namespaces(ctx, req)));

		router.get("/imports", "symbol", "Imported (external) symbols",
			req -> ApiResponse.json(externalSymbols(ctx, req, false)));

		router.get("/exports", "symbol", "Exported entry points", req ->
				ctx.readJson(() -> {
					Program p = ctx.requireProgram();
					List<Object> items = new ArrayList<>();
					SymbolIterator it = p.getSymbolTable().getAllSymbols(true);
					while (it.hasNext()) {
						Symbol s = it.next();
						if (s.isExternalEntryPoint()) {
							items.add(Jsonify.symbol(s));
						}
					}
					var paging = req.paging(500);
					return com.ghidramcp.util.Page.of(items, paging);
				}));

		router.get("/symbols/entrypoints", "symbol", "Program entry points",
			req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				List<Object> items = new ArrayList<>();
				for (Address a : p.getSymbolTable().getExternalEntryPointIterator()) {
					Map<String, Object> m = new LinkedHashMap<>();
					m.put("address", a.toString());
					Function f = p.getFunctionManager().getFunctionAt(a);
					m.put("function", f == null ? null : f.getName());
					items.add(m);
				}
				return Json.list(items);
			}));

		router.get("/symbols/at", "symbol", "Symbols defined exactly at an address",
			req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				List<Object> items = new ArrayList<>();
				for (Symbol s : p.getSymbolTable().getSymbols(a)) {
					items.add(Jsonify.symbol(s));
				}
				return Json.list(items);
			}));

		// ---------------------------------------------------------- references
		router.get("/xrefs", "symbol", "All references to an address (alias of /xrefs/to)",
			req -> ApiResponse.json(
				com.ghidramcp.util.Page.map(referenceTargets(ctx, req), req.paging(500))));

		router.get("/xrefs/to", "symbol", "References to an address or symbol name",
			req -> ApiResponse.json(
				com.ghidramcp.util.Page.map(referenceTargets(ctx, req), req.paging(500))));

		router.get("/xrefs/from", "symbol", "References from an address",
			req -> ApiResponse.json(
				com.ghidramcp.util.Page.map(referenceSources(ctx, req), req.paging(500))));

		router.get("/xrefs/function", "symbol",
			"Call sites that reference a function (by name or address)",
			req -> ApiResponse.json(functionXrefs(ctx, req)));

		router.get("/references/strings", "symbol",
			"Strings referenced from an address range or function",
			req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				Function f = FunctionHandlers.requireFunction(p,
					req.firstOf("function", "name", "address", "addr"));
				List<Object> out = new ArrayList<>();
				Set<String> seen = new LinkedHashSet<>();
				var it = p.getListing().getInstructions(f.getBody(), true);
				while (it.hasNext()) {
					var instr = it.next();
					for (Reference r : instr.getReferencesFrom()) {
						Address to = r.getToAddress();
						if (!seen.add(to.toString())) {
							continue;
						}
						Data d = p.getListing().getDataAt(to);
						if (d != null && com.ghidramcp.api.Types.isStringLike(d.getDataType())) {
							Map<String, Object> m = new LinkedHashMap<>();
							m.put("stringAddress", to.toString());
							m.put("value", Jsonify.safe(() -> String.valueOf(d.getValue())));
							m.put("referencedFrom", instr.getAddress().toString());
							out.add(m);
						}
					}
				}
				return Json.list(out);
			}));

		// ----------------------------------------------------------- mutations
		router.post("/symbols/rename", "symbol",
			"Rename the symbol at an address (address, newName)", req ->
				ApiResponse.json(mutate(ctx, req, (p, a, newName) -> {
					SymbolTable st = p.getSymbolTable();
					Symbol primary = st.getPrimarySymbol(a);
					if (primary == null) {
						Symbol created = st.createLabel(a, newName, SourceType.USER_DEFINED);
						return Map.of("address", a.toString(), "name", created.getName(),
							"created", true);
					}
					primary.setName(newName, SourceType.USER_DEFINED);
					return Map.of("address", a.toString(), "name", primary.getName(),
						"created", false);
				})));

		router.post("/symbols/create", "symbol",
			"Create a label at an address (address|name, newName, namespace?)", req ->
				ApiResponse.json(ctx.mutate("Create symbol", () -> {
					Program p = ctx.requireProgram();
					Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
					String name = req.require("newName", "name", "label");
					String namespacePath = req.param("namespace");
					SymbolTable st = p.getSymbolTable();
					Symbol symbol;
					if (namespacePath != null && !namespacePath.isBlank()) {
						Namespace ns = resolveOrCreateNamespace(p, namespacePath);
						symbol = st.createLabel(a, name, ns, SourceType.USER_DEFINED);
					}
					else {
						symbol = st.createLabel(a, name, SourceType.USER_DEFINED);
					}
					return Jsonify.symbol(symbol);
				})));

		router.post("/symbols/delete", "symbol",
			"Delete a symbol by address (+ optional name)", req ->
				ApiResponse.json(ctx.mutate("Delete symbol", () -> {
					Program p = ctx.requireProgram();
					Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
					String name = req.param("name");
					List<String> deleted = new ArrayList<>();
					SymbolTable st = p.getSymbolTable();
					List<Symbol> targets = new ArrayList<>();
					for (Symbol s : st.getSymbols(a)) {
						if (name == null || s.getName().equals(name)) {
							targets.add(s);
						}
					}
					for (Symbol s : targets) {
						deleted.add(s.getName());
						st.removeSymbolSpecial(s);
					}
					if (deleted.isEmpty()) {
						throw ApiException.notFound("no symbol to delete at " + a);
					}
					return Map.of("address", a.toString(), "deleted", deleted);
				})));

		router.post("/symbols/set-primary", "symbol",
			"Make a named symbol at an address the primary symbol", req ->
				ApiResponse.json(ctx.mutate("Set primary symbol", () -> {
					Program p = ctx.requireProgram();
					Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
					String name = req.require("name");
					var it = p.getSymbolTable().getSymbols(a);
					for (Symbol s : it) {
						if (s.getName().equals(name)) {
							s.setPrimary();
							return Map.of("address", a.toString(), "primary", s.getName());
						}
					}
					throw ApiException.notFound("no symbol named '" + name + "' at " + a);
				})));

		router.post("/namespaces/create", "symbol",
			"Create a namespace (dot or / separated paths are nested automatically)", req ->
				ctx.mutateJson("Create namespace", () -> {
					Program p = ctx.requireProgram();
					String path = req.require("name", "path", "namespace");
					Namespace ns = resolveOrCreateNamespace(p, path);
					Map<String, Object> body = new LinkedHashMap<>();
					body.put("name", ns.getName());
					body.put("nameWithNamespace", ns.getName(true));
					body.put("address", ns.getSymbol() == null || ns.getSymbol().getAddress() == null
						? null : ns.getSymbol().getAddress().toString());
					return body;
				}));

		router.post("/symbols/set-external-entry", "symbol",
			"Mark or unmark an address as an external entry point (export)", req ->
				ctx.mutateJson("Set external entry point", () -> {
					Program p = ctx.requireProgram();
					Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
					boolean isEntry = req.boolParam("isEntry", true);
					var st = p.getSymbolTable();
					if (isEntry) {
						st.addExternalEntryPoint(a);
					}
					else {
						st.removeExternalEntryPoint(a);
					}
					Map<String, Object> body = new LinkedHashMap<>();
					body.put("address", a.toString());
					body.put("isExternalEntryPoint", isEntry);
					return body;
				}));

		router.post("/symbols/import", "symbol",
			"Add an imported (external) function, e.g. library=kernel32.dll name=CreateFileA", req ->
				ctx.mutateJson("Import external symbol", () -> {
					Program p = ctx.requireProgram();
					String name = req.require("name");
					String library = req.param("library", "<unknown>");
					var loc = p.getExternalManager().addExtFunction(library, name, null,
						SourceType.USER_DEFINED);
					Map<String, Object> body = new LinkedHashMap<>();
					body.put("name", name);
					body.put("library", library);
					body.put("label", loc == null ? null : loc.getLabel());
					body.put("address", loc == null || loc.getAddress() == null
						? null : loc.getAddress().toString());
					return body;
				}));

		router.get("/symbols/external-locations", "symbol",
			"External locations (imports linking to libraries)", req ->
				ApiResponse.json(externalSymbols(ctx, req, true)));
	}

	// ------------------------------------------------------------------- reads

	private static Map<String, Object> symbols(ApiContext ctx, ApiRequest req) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			String nameFilter = req.param("name");
			String typeFilter = req.param("type");
			boolean onlyExternal = req.boolParam("external", false);
			List<Object> items = new ArrayList<>();
			for (Symbol s : ctx.index(p).symbols()) {
				if (nameFilter != null && !s.getName().toLowerCase()
						.contains(nameFilter.toLowerCase())) {
					continue;
				}
				if (typeFilter != null && !Jsonify.symbolTypeName(s.getSymbolType())
						.equalsIgnoreCase(typeFilter)) {
					continue;
				}
				if (onlyExternal && !s.isExternal()) {
					continue;
				}
				items.add(Jsonify.symbol(s));
			}
			var paging = req.paging(500);
			return toEnvelope(items, paging);
		});
	}

	private static Map<String, Object> search(ApiContext ctx, ApiRequest req) {
		String query = req.require("query", "q", "name");
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			String needle = query.toLowerCase();
			List<Object> items = new ArrayList<>();
			for (Symbol s : ctx.index(p).symbols()) {
				if (s.getName().toLowerCase().contains(needle)) {
					items.add(Jsonify.symbol(s));
				}
			}
			var paging = req.paging(500);
			return toEnvelope(items, paging);
		});
	}

	private static Map<String, Object> namespaces(ApiContext ctx, ApiRequest req) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			Set<String> seen = new LinkedHashSet<>();
			List<Object> items = new ArrayList<>();
			for (Symbol s : ctx.index(p).symbols()) {
				Namespace ns = s.getParentNamespace();
				if (ns != null && !ns.isGlobal() && seen.add(ns.getName(true))) {
					Map<String, Object> m = new LinkedHashMap<>();
					m.put("name", ns.getName());
					m.put("nameWithNamespace", ns.getName(true));
					m.put("address", ns.getSymbol() == null || ns.getSymbol().getAddress() == null
						? null : ns.getSymbol().getAddress().toString());
					m.put("type", Jsonify.symbolTypeName(ns.getSymbol() == null
						? null : ns.getSymbol().getSymbolType()));
					m.put("id", ns.getID());
					items.add(m);
				}
			}
			var paging = req.paging(500);
			return toEnvelope(items, paging);
		});
	}

	private static Object externalSymbols(ApiContext ctx, ApiRequest req, boolean locations) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			List<Object> items = new ArrayList<>();
			SymbolTable st = p.getSymbolTable();
			SymbolIterator it = st.getExternalSymbols();
			while (it.hasNext()) {
				Symbol s = it.next();
				Map<String, Object> m = Jsonify.symbol(s);
				if (locations) {
					var loc = p.getExternalManager().getExternalLocation(s);
					m.put("library", loc == null ? null : loc.getLibraryName());
					m.put("originalName", loc == null ? null : loc.getOriginalImportedName());
				}
				items.add(m);
			}
			var paging = req.paging(1000);
			return com.ghidramcp.util.Page.of(items, paging);
		});
	}

	/** Every reference pointing at the requested address or symbol name. */
	private static List<Object> referenceTargets(ApiContext ctx, ApiRequest req) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			String target = req.firstOf("address", "addr", "name", "symbol");
			if (target == null) {
				throw ApiException.badRequest("provide 'address' or 'name' to find references to");
			}
			Address a = Lookup.address(p, target);
			List<Object> items = new ArrayList<>();
			ReferenceManager rm = p.getReferenceManager();
			ReferenceIterator it = rm.getReferencesTo(a);
			while (it.hasNext()) {
				Reference r = it.next();
				items.add(Jsonify.reference(p, r.getFromAddress(), r.getToAddress(),
					r.getReferenceType().getName(), r.isPrimary()));
			}
			return items;
		});
	}

	/** Every reference originating at the requested address. */
	private static List<Object> referenceSources(ApiContext ctx, ApiRequest req) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
			List<Object> items = new ArrayList<>();
			for (Reference r : p.getReferenceManager().getReferencesFrom(a)) {
				items.add(Jsonify.reference(p, r.getFromAddress(), r.getToAddress(),
					r.getReferenceType().getName(), r.isPrimary()));
			}
			return items;
		});
	}

	/** Call sites that reference a function, as a paginated envelope. */
	private static Map<String, Object> functionXrefs(ApiContext ctx, ApiRequest req) {
		return toEnvelope(functionXrefList(ctx, req), req.paging(500));
	}

	/** Call sites that reference a function, before pagination. */
	private static List<Object> functionXrefList(ApiContext ctx, ApiRequest req) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			Function f = FunctionHandlers.requireFunction(p,
				req.firstOf("name", "function", "address", "addr"));
			List<Object> items = new ArrayList<>();
			ReferenceIterator it = p.getReferenceManager().getReferencesTo(f.getEntryPoint());
			while (it.hasNext()) {
				Reference r = it.next();
				Map<String, Object> m = Jsonify.reference(p, r.getFromAddress(), r.getToAddress(),
					r.getReferenceType().getName(), r.isPrimary());
				m.put("kind", r.getReferenceType().isCall() ? "call" : "reference");
				items.add(m);
			}
			return items;
		});
	}

	// --------------------------------------------------------------- mutations

	/** Shared plumbing for address + new name mutations. */
	private static Map<String, Object> mutate(ApiContext ctx, ApiRequest req, SymbolMutation work) {
		return ctx.mutate("GhidraMCP12: " + req.path(), () -> {
			Program p = ctx.requireProgram();
			Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
			String newName = req.require("newName", "new_name", "name", "label");
			return work.apply(p, a, newName);
		});
	}

	@FunctionalInterface
	private interface SymbolMutation {
		Map<String, Object> apply(Program p, Address a, String newName) throws Exception;
	}

	/**
	 * Resolves a dotted/slashed/:: namespace path, creating missing levels.
	 *
	 * <p>Accepting all three separators matters because agents produce
	 * {@code MyClass::method}, {@code MyClass.method} and {@code MyClass/method}
	 * interchangeably depending on what the symbol table showed them.
	 */
	static Namespace resolveOrCreateNamespace(Program p, String path) {
		SymbolTable st = p.getSymbolTable();
		String[] parts = path.contains("::") ? path.split("::")
			: path.contains("/") ? path.split("/") : path.split("\\.");
		Namespace current = p.getGlobalNamespace();
		for (String part : parts) {
			if (part.isBlank()) {
				continue;
			}
			Namespace next = st.getNamespace(part, current);
			if (next == null) {
				next = findChildNamespace(st, current, part);
			}
			if (next == null) {
				try {
					next = st.createNameSpace(current, part, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					throw ApiException.internal("could not create namespace '" + part + "' under '" +
						current.getName(true) + "': " + e.getMessage(), e);
				}
			}
			current = next;
		}
		return current;
	}

	private static Namespace findChildNamespace(SymbolTable st, Namespace parent, String name) {
		for (Symbol s : st.getSymbols(name, parent)) {
			if (s.getObject() instanceof Namespace ns) {
				return ns;
			}
		}
		return null;
	}

	/**
	 * Slices the request's page out of a full item list.
	 *
	 * <p>Callers pass the complete list; the envelope exposes the total as
	 * {@code count} and a {@code truncated} flag computed against it, so an agent
	 * can always tell whether it has seen everything.
	 */
	static Map<String, Object> toEnvelope(List<Object> items, ApiRequest.Paging paging) {
		return com.ghidramcp.util.Page.map(items, paging);
	}

	/** Unused-but-kept helper documenting how comments attach to symbols. */
	static String commentOf(Program p, Symbol s) {
		CodeUnit cu = p.getListing().getCodeUnitAt(s.getAddress());
		return cu == null ? null : cu.getComment(ghidra.program.model.listing.CommentType.EOL);
	}
	/** Legacy {@code /xrefs_to} and {@code /xrefs_from}: reference lines as text. */
	static ApiResponse legacyXrefs(ApiContext ctx, ApiRequest req, boolean to) {
		List<Object> lines = new ArrayList<>();
		for (Object o : (to ? referenceTargets(ctx, req) : referenceSources(ctx, req))) {
			if (o instanceof Map<?, ?> m) {
				lines.add(to
					? "From " + m.get("from") + " [" + m.get("type") + "]"
					: "To " + m.get("to") + " [" + m.get("type") + "]");
			}
		}
		return ApiResponse.json(com.ghidramcp.util.Page.ofSlice(lines));
	}

	/** Legacy {@code /function_xrefs}: call sites of a function, as text lines. */
	static ApiResponse legacyFunctionXrefs(ApiContext ctx, ApiRequest req) {
		List<Object> lines = new ArrayList<>();
		for (Object o : functionXrefList(ctx, req)) {
			if (o instanceof Map<?, ?> m) {
				lines.add("From " + m.get("from") + " [" + m.get("type") + "]");
			}
		}
		return ApiResponse.json(com.ghidramcp.util.Page.ofSlice(lines));
	}
}
