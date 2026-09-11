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
import com.ghidramcp.util.ApiResponse;
import com.ghidramcp.util.Json;

/**
 * Liveness and program-level metadata endpoints.
 *
 * <p>{@code /_health} is what an MCP client should probe first: it answers even
 * with no program loaded, which distinguishes "Ghidra is not running" from
 * "Ghidra is running but has no program open" - a distinction that otherwise
 * costs an agent several confusing round trips.
 */
public final class MetaHandlers {

	private MetaHandlers() {
	}

	public static void register(Router router, ApiContext ctx) {

		router.get("/_health", "meta", "Server liveness, port and open-program summary",
			req -> {
				Map<String, Object> body = new LinkedHashMap<>();
				body.put("status", "ok");
				body.putAll(ctx.stats());

				List<Object> open = new ArrayList<>();
				for (var p : ctx.programs().allOpen()) {
					Map<String, Object> m = new LinkedHashMap<>();
					m.put("name", p.getName());
					m.put("path", Jsonify.safe(() -> p.getDomainFile().getPathname()));
					m.put("language", Jsonify.safe(() -> p.getLanguageID().toString()));
					open.add(m);
				}
				body.put("openPrograms", open);
				var current = ctx.program();
				body.put("hasCurrentProgram", current != null);
				body.put("currentProgram", current == null ? null : current.getName());
				body.put("guiAvailable", ctx.guiAvailable());
				return ApiResponse.json(body);
			});

		router.get("/_ping", "meta", "Minimal liveness probe", req -> ApiResponse.text("pong"));

		router.get("/ping", "meta", "Alias of /_ping", req -> ApiResponse.text("pong"));

		router.get("/info", "meta", "Program metadata: name, format, language, base address, hashes",
			req -> ApiResponse.json(programInfo(ctx)));

		router.get("/program/info", "meta", "Alias of /info", req -> ApiResponse.json(programInfo(ctx)));

		router.get("/program/summary", "meta",
			"Counts of functions, symbols, data types, strings and instructions",
			req -> ApiResponse.json(summary(ctx)));
	}

	/** Shared implementation for {@code /info} and {@code /program/info}. */
	static Map<String, Object> programInfo(ApiContext ctx) {
		return ctx.read(() -> {
			var p = ctx.requireProgram();
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("name", p.getName());
			m.put("path", Jsonify.safe(() -> p.getDomainFile().getPathname()));
			m.put("executablePath", p.getExecutablePath());
			m.put("languageId", Jsonify.safe(() -> p.getLanguageID().toString()));
			m.put("languageDescription", Jsonify.safe(() -> p.getLanguage().getLanguageDescription().toString()));
			m.put("compilerSpec", Jsonify.safe(() -> p.getCompilerSpec().getCompilerSpecID().toString()));
			m.put("processor", Jsonify.safe(() -> p.getLanguage().getProcessor().toString()));
			m.put("endian", Jsonify.safe(() -> p.getLanguage().isBigEndian() ? "big" : "little"));
			m.put("addressSizeBits", Jsonify.safeInt(() -> p.getDefaultPointerSize() * 8));
			m.put("pointerSize", p.getDefaultPointerSize());
			m.put("imageBase", Jsonify.safe(() -> p.getImageBase().toString()));
			m.put("minAddress", Jsonify.safe(() -> p.getMinAddress() == null ? null : p.getMinAddress().toString()));
			m.put("maxAddress", Jsonify.safe(() -> p.getMaxAddress() == null ? null : p.getMaxAddress().toString()));
			m.put("format", Jsonify.safe(() -> p.getExecutableFormat()));
			m.put("executableFormat", p.getExecutableFormat());
			m.put("isBigEndian", Jsonify.safeBool(() -> p.getLanguage().isBigEndian()));
			m.put("isChanged", p.isChanged());
			m.put("isChangeable", p.isChangeable());
			m.put("modificationNumber", p.getModificationNumber());
			m.put("md5", Jsonify.safe(() -> p.getExecutableMD5()));
			m.put("sha256", Jsonify.safe(() -> p.getExecutableSHA256()));
			m.put("creationDate", Jsonify.safe(() -> String.valueOf(p.getCreationDate())));
			m.put("functionCount", ctx.index(p).functions().size());
			m.put("symbolCount", ctx.index(p).symbols().size());
			m.put("memoryBlockCount", p.getMemory().getBlocks().length);
			return m;
		});
	}

	static Map<String, Object> summary(ApiContext ctx) {
		return ctx.read(() -> {
			var p = ctx.requireProgram();
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("program", p.getName());
			m.put("functions", p.getFunctionManager().getFunctionCount());
			m.put("externalFunctions", p.getFunctionManager().getExternalFunctions().hasNext());
			m.put("symbols", ctx.index(p).symbols().size());
			m.put("dataTypes", Jsonify.safeInt(() -> count(p)));

			int dataCount = 0;
			int stringCount = 0;
			var dataIt = p.getListing().getDefinedData(true);
			while (dataIt.hasNext()) {
				var d = dataIt.next();
				dataCount++;
				if (com.ghidramcp.api.Types.isStringLike(d.getDataType())) {
					stringCount++;
				}
			}
			m.put("definedData", dataCount);
			m.put("strings", stringCount);
			m.put("instructions", Jsonify.safeInt(() -> p.getListing().getNumInstructions()));
			m.put("memoryBytes", Jsonify.safeLong(() -> {
				long total = 0;
				for (var b : p.getMemory().getBlocks()) {
					total += b.getSize();
				}
				return total;
			}));
			m.put("namespaces", countNamespaces(p));
			return m;
		});
	}

	private static int count(ghidra.program.model.listing.Program p) {
		int n = 0;
		var it = p.getDataTypeManager().getAllDataTypes();
		while (it.hasNext()) {
			it.next();
			n++;
		}
		return n;
	}

	private static int countNamespaces(ghidra.program.model.listing.Program p) {
		int n = 0;
		var it = p.getSymbolTable().getAllSymbols(true);
		java.util.Set<String> seen = new java.util.HashSet<>();
		while (it.hasNext()) {
			var ns = it.next().getParentNamespace();
			if (ns != null && !ns.isGlobal() && seen.add(ns.getName(true))) {
				n++;
			}
		}
		return n;
	}

	/** Guard used by handler groups that need a parameter but tolerate an alias. */
	static String requireAddress(ApiRequest req) {
		String a = req.firstOf("address", "addr", "offset");
		if (a == null) {
			throw ApiException.badRequest("missing required parameter 'address'");
		}
		return a;
	}

	/** Serialises a list with pagination metadata. */
	static ApiResponse page(List<?> items, ApiRequest req, int defaultLimit) {
		return ApiResponse.json(com.ghidramcp.util.Page.of(items, req, defaultLimit));
	}
}
