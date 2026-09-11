/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.handlers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import com.ghidramcp.api.ApiContext;
import com.ghidramcp.api.ApiException;
import com.ghidramcp.api.Router;
import com.ghidramcp.core.Lookup;
import com.ghidramcp.util.ApiResponse;
import com.ghidramcp.util.Json;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.CodeViewerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;

/**
 * Analysis control, navigation, bookmarks and function tags.
 *
 * <p>Navigation ("what is the user looking at?") is how an agent can follow a
 * human's investigation around the GUI, and "go to this address" is how it can
 * point the human at something it found. Both are cheap and disproportionately
 * useful, so they are exposed even though they are not strictly analysis.
 */
public final class AnalysisHandlers {

	private AnalysisHandlers() {
	}

	/** Last address this bridge navigated to, used when the Code Viewer has none. */
	private static final Map<Program, Address> CURRENT =
		Collections.synchronizedMap(new WeakHashMap<>());

	public static void register(Router router, ApiContext ctx) {

		// ---------------------------------------------------------- navigation
		router.get("/analysis/current", "analysis",
			"Address and function currently selected in the Ghidra GUI",
			req -> ApiResponse.json(current(ctx)));

		router.get("/current_address", "analysis", "Alias of /analysis/current (address only)",
			req -> ApiResponse.text(String.valueOf(current(ctx).get("address"))));

		router.get("/current_function", "analysis", "Alias of /analysis/current (function info)",
			req -> {
				Map<String, Object> c = current(ctx);
				Map<String, Object> body = new LinkedHashMap<>();
				Object fn = c.get("function");
				if (fn instanceof Map<?, ?> raw) {
					// The map was built by current() above with String keys.
					for (Map.Entry<?, ?> e : raw.entrySet()) {
						body.put(String.valueOf(e.getKey()), e.getValue());
					}
				}
				else {
					body.put("function", null);
					body.put("reason", c.get("reason"));
				}
				return ApiResponse.json(body);
			});

		router.post("/analysis/goto", "analysis",
			"Navigate the Ghidra GUI to an address or symbol name", req ->
				ApiResponse.json(gotoAddress(ctx, req)));

		// ------------------------------------------------------------ analysis
		router.post("/analysis/disassemble", "analysis",
			"Disassemble at an address, or over a range (address + length)", req ->
				ctx.mutateJson("Disassemble via MCP", () -> {
					Program p = ctx.requireProgram();
					Address start = Lookup.address(p, MetaHandlers.requireAddress(req));
					int length = Math.max(0, req.intParam("length", 0));
					AddressSet set;
					if (length > 0) {
						set = new AddressSet(start, start.add(length - 1));
					}
					else {
						set = new AddressSet(start, start);
					}
					DisassembleCommand cmd = new DisassembleCommand(set, null, true);
					boolean ok = cmd.applyTo(p, ghidra.util.task.TaskMonitor.DUMMY);
					Map<String, Object> body = new LinkedHashMap<>();
					body.put("address", start.toString());
					body.put("length", Math.max(1, length));
					body.put("success", ok);
					body.put("status", cmd.getStatusMsg());
					return body;
				}));

		router.post("/analysis/create-function", "analysis",
			"Ask Ghidra to create a function at an address (creating its body automatically)",
			req -> ctx.mutateJson("Create function via analysis", () -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				CreateFunctionCmd cmd = new CreateFunctionCmd(a);
				boolean ok = cmd.applyTo(p, ghidra.util.task.TaskMonitor.DUMMY);
				Function f = p.getFunctionManager().getFunctionAt(a);
				Map<String, Object> body = new LinkedHashMap<>();
				body.put("address", a.toString());
				body.put("success", ok);
				body.put("status", cmd.getStatusMsg());
				body.put("function", f == null ? null : f.getName());
				return body;
			}));

		router.post("/analysis/analyze-range", "analysis",
			"Re-run auto analysis over an address range (address + length)",
			req -> ApiResponse.json(analyzeRange(ctx, req)));

		router.post("/analysis/analyze-all", "analysis",
			"Re-run auto analysis over the whole program (can take a long time)",
			req -> ApiResponse.json(analyzeRange(ctx, req)));

		router.post("/analysis/clear", "analysis",
			"Clear the instruction/data definitions in a range (address + length)",
			req -> ctx.mutateJson("Clear code units via MCP", () -> {
				Program p = ctx.requireProgram();
				Address start = Lookup.address(p, MetaHandlers.requireAddress(req));
				int length = Math.max(1, req.intParam("length", 1));
				p.getListing().clearCodeUnits(start, start.add(length - 1), false);
				Map<String, Object> body = new LinkedHashMap<>();
				body.put("address", start.toString());
				body.put("length", length);
				body.put("cleared", true);
				return body;
			}));

		// ----------------------------------------------------------- bookmarks
		router.get("/bookmarks", "analysis", "List bookmarks", req ->
				ctx.readJson(() -> {
					Program p = ctx.requireProgram();
					String type = req.param("type");
					List<Object> items = new ArrayList<>();
					var it = p.getBookmarkManager().getBookmarksIterator();
					while (it.hasNext()) {
						Bookmark b = it.next();
						if (type != null && !b.getTypeString().equalsIgnoreCase(type)) {
							continue;
						}
						items.add(bookmark(p, b));
					}
					return Json.list(items);
				}));

		router.get("/bookmarks/types", "analysis", "Bookmark types and their categories",
			req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				List<Object> out = new ArrayList<>();
				for (var type : p.getBookmarkManager().getBookmarkTypes()) {
					Map<String, Object> m = new LinkedHashMap<>();
					m.put("type", type.getTypeString());
					m.put("priority", type.getMarkerPriority());
					m.put("categories",
						java.util.Arrays.asList(p.getBookmarkManager().getCategories(
							type.getTypeString())));
					out.add(m);
				}
				return Json.list(out);
			}));

		router.post("/bookmarks/create", "analysis",
			"Create a bookmark (address, type=Note|Warning|Error|Info, category, comment)",
			req -> ctx.mutateJson("Create bookmark via MCP", () -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				String type = req.param("type", "Note");
				String category = req.param("category", "GhidraMCP12");
				String comment = req.param("comment", "");
				Bookmark b = p.getBookmarkManager().setBookmark(a, type, category, comment);
				if (b == null) {
					throw ApiException.badRequest("unknown bookmark type '" + type + "'; known types: " +
						java.util.Arrays.toString(java.util.Arrays.stream(
							p.getBookmarkManager().getBookmarkTypes())
							.map(t -> t.getTypeString()).toArray()));
				}
				return bookmark(p, b);
			}));

		router.post("/bookmarks/delete", "analysis",
			"Delete bookmarks at an address (optionally filtered by type/category)", req ->
				ctx.mutateJson("Delete bookmark via MCP", () -> {
					Program p = ctx.requireProgram();
					Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
					String type = req.param("type", "Note");
					String category = req.param("category", "GhidraMCP12");
					List<String> removed = new ArrayList<>();
					var manager = p.getBookmarkManager();
					for (Bookmark b : manager.getBookmarks(a, type)) {
						if (category == null || category.equals(b.getCategory())) {
							removed.add(b.getComment());
							manager.removeBookmark(b);
						}
					}
					if (removed.isEmpty()) {
						throw ApiException.notFound("no " + type + "/" + category +
							" bookmark at " + a);
					}
					Map<String, Object> body = new LinkedHashMap<>();
					body.put("address", a.toString());
					body.put("type", type);
					body.put("category", category);
					body.put("deleted", removed.size());
					return body;
				}));

		// ---------------------------------------------------------------- tags
		router.get("/function-tags", "analysis", "All function tags defined in the program",
			req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				List<Object> out = new ArrayList<>();
				for (var t : p.getFunctionManager().getFunctionTagManager().getAllFunctionTags()) {
					Map<String, Object> m = new LinkedHashMap<>();
					m.put("name", t.getName());
					m.put("comment", t.getComment());
					m.put("id", t.getId());
					out.add(m);
				}
				return Json.list(out);
			}));
	}

	// ---------------------------------------------------------------- helpers

	/** What the GUI is currently looking at (falls back to the last goto). */
	@SuppressWarnings("unchecked")
	private static Map<String, Object> current(ApiContext ctx) {
		Map<String, Object> body = new LinkedHashMap<>();
		Program p = ctx.program();
		if (p == null) {
			body.put("address", null);
			body.put("reason", "no program is open");
			return body;
		}

		if (ctx.guiAvailable()) {
			CodeViewerService service = ctx.tool().getService(CodeViewerService.class);
			if (service != null) {
				ProgramLocation loc = service.getCurrentLocation();
				if (loc != null && loc.getAddress() != null) {
					Address a = loc.getAddress();
					body.put("address", a.toString());
					body.put("source", "gui");
					Function f = p.getFunctionManager().getFunctionContaining(a);
					body.put("function", f == null ? null : functionInfo(f));
					return body;
				}
			}
		}

		Address last = CURRENT.get(p);
		body.put("address", last == null ? null : last.toString());
		body.put("source", last == null ? "unset" : "last-navigation");
		if (last != null) {
			Function f = p.getFunctionManager().getFunctionContaining(last);
			body.put("function", f == null ? null : functionInfo(f));
		}
		else {
			body.put("function", null);
			body.put("reason", "the Code Viewer has no current location yet; " +
				"click an instruction, or use /analysis/goto to set one");
		}
		return body;
	}

	private static Map<String, Object> functionInfo(Function f) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("name", f.getName());
		m.put("address", f.getEntryPoint().toString());
		m.put("signature", com.ghidramcp.api.Jsonify.safe(() -> f.getPrototypeString(false, false)));
		return m;
	}

	private static Map<String, Object> gotoAddress(ApiContext ctx,
			com.ghidramcp.api.ApiRequest req) {
		Program p = ctx.requireProgram();
		Address a = Lookup.address(p, req.require("address", "addr", "name", "location"));
		boolean guiNavigated = false;
		if (ctx.guiAvailable()) {
			CodeViewerService service = ctx.tool().getService(CodeViewerService.class);
			if (service != null) {
				ProgramLocation loc = new ProgramLocation(p, a);
				// goTo(location, false) leaves history/selection alone, which is what a
				// "show me this" navigation should do.
				javax.swing.SwingUtilities.invokeLater(() -> service.goTo(loc, false));
				guiNavigated = true;
			}
		}
		CURRENT.put(p, a);
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("address", a.toString());
		body.put("guiNavigated", guiNavigated);
		Function f = p.getFunctionManager().getFunctionContaining(a);
		body.put("function", f == null ? null : f.getName());
		return body;
	}

	/** Runs auto analysis over a range (or the whole program when no length given). */
	private static ApiResponse analyzeRange(ApiContext ctx,
			com.ghidramcp.api.ApiRequest req) {
		boolean whole = req.path().endsWith("analyze-all");
		return ctx.mutateJson("Analyze via MCP", () -> {
			Program p = ctx.requireProgram();
			var mgr = ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(p);
			if (mgr == null) {
				throw ApiException.internal(
					"Ghidra has no AutoAnalysisManager for this program " +
						"(the analysis plugin is not loaded in this tool)", null);
			}
			// reAnalyzeAll()/startAnalysis() take no range, so the intent is
			// recorded and the whole-program case is what actually re-runs.
			AddressSet set;
			if (whole) {
				set = new AddressSet(p.getMinAddress(), p.getMaxAddress());
			}
			else {
				Address start = Lookup.address(p, MetaHandlers.requireAddress(req));
				int length = Math.max(1, req.intParam("length", 1));
				set = new AddressSet(start, start.add(length - 1));
			}
			mgr.reAnalyzeAll(set);
			mgr.startAnalysis(ghidra.util.task.TaskMonitor.DUMMY);

			Map<String, Object> body = new LinkedHashMap<>();
			body.put("program", p.getName());
			body.put("range", set.toString());
			body.put("addressRangeCount", set.getNumAddressRanges());
			body.put("wholeProgram", whole);
			body.put("analysisStarted", true);
			return body;
		});
	}

	private static Map<String, Object> bookmark(Program p, Bookmark b) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("address", b.getAddress().toString());
		m.put("type", b.getTypeString());
		m.put("category", b.getCategory());
		m.put("comment", b.getComment());
		Function f = p.getFunctionManager().getFunctionContaining(b.getAddress());
		m.put("function", f == null ? null : f.getName());
		return m;
	}

	/** Kept for the legacy surface: "list functions with a tag". */
	static List<Object> functionsWithTag(Program p, String tag) {
		List<Object> out = new ArrayList<>();
		for (Function f : p.getFunctionManager().getFunctions(true)) {
			for (var t : f.getTags()) {
				if (t.getName().equalsIgnoreCase(tag)) {
					Map<String, Object> m = new LinkedHashMap<>();
					m.put("name", f.getName());
					m.put("address", f.getEntryPoint().toString());
					out.add(m);
					break;
				}
			}
		}
		return out;
	}

	/** Helper used by the legacy handler for {@code /renameData} style calls. */
	static void renameAt(Program p, Address a, String name) throws Exception {
		var st = p.getSymbolTable();
		var primary = st.getPrimarySymbol(a);
		if (primary == null) {
			st.createLabel(a, name, SourceType.USER_DEFINED);
		}
		else {
			primary.setName(name, SourceType.USER_DEFINED);
		}
	}
}
