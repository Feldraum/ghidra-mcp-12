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
import com.ghidramcp.api.Router;
import com.ghidramcp.core.Lookup;
import com.ghidramcp.util.ApiResponse;
import com.ghidramcp.util.Json;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

/**
 * Comments.
 *
 * <p>Uses the {@link CommentType} enum introduced in Ghidra 11.4; the
 * {@code CodeUnit.EOL_COMMENT} int constants and the corresponding
 * {@code Listing} overloads are deprecated for removal in 12.1.3.
 *
 * <p>Comment kinds and where they show up:
 * <ul>
 *   <li>{@code eol} - trailing comment on an instruction (also shown in the
 *       decompiler, which is why "set the decompiler comment" maps here);</li>
 *   <li>{@code pre} - block comment above the line;</li>
 *   <li>{@code post} - block comment below the line;</li>
 *   <li>{@code plate} - banner shown above a function/data item;</li>
 *   <li>{@code repeatable} - repeated at every reference to the address.</li>
 * </ul>
 */
public final class CommentHandlers {

	private CommentHandlers() {
	}

	public static void register(Router router, ApiContext ctx) {

		router.get("/comments", "comment", "All comments at an address (or on a function)",
			req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				Address a = resolve(ctx, p, req);
				return commentsAt(p, a);
			}));

		router.get("/comments/function", "comment",
			"Every comment inside a function's body, in address order",
			req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				Function f = FunctionHandlers.requireFunction(p,
					req.firstOf("function", "name", "address", "addr"));
				List<Object> out = new ArrayList<>();
				Listing listing = p.getListing();
				for (CommentType kind : CommentType.values()) {
					var it = listing.getCommentCodeUnitIterator(kind, f.getBody());
					while (it.hasNext()) {
						var cu = it.next();
						Map<String, Object> m = commentsAt(p, cu.getAddress());
						m.put("kind", kind.name().toLowerCase());
						m.put("codeUnit", cu.toString());
						out.add(m);
					}
				}
				return Json.list(out);
			}));

		router.post("/comments/set", "comment",
			"Set a comment. kind=eol|pre|post|plate|repeatable (default eol)",
			req -> setComment(ctx, req, null));

		router.post("/comments/delete", "comment",
			"Delete a comment. kind=eol|pre|post|plate|repeatable (default eol)",
			req -> ctx.mutateJson("Delete comment via MCP", () -> {
				Program p = ctx.requireProgram();
				Address a = resolve(ctx, p, req);
				CommentType type = parseKind(req.param("kind", req.param("type", "eol")));
				p.getListing().setComment(a, type, null);
				Map<String, Object> body = new LinkedHashMap<>();
				body.put("address", a.toString());
				body.put("kind", type.name());
				body.put("deleted", true);
				return body;
			}));

		// -------------------------------------------------------------- aliases
		router.post("/comments/decompiler", "comment",
			"Set the comment shown in the decompiler (alias of kind=eol)", req ->
				setComment(ctx, req, CommentType.EOL));

		router.post("/comments/disassembly", "comment",
			"Set the comment shown in the disassembly listing (alias of kind=eol)", req ->
				setComment(ctx, req, CommentType.EOL));

		router.post("/comments/plate", "comment", "Set the plate (banner) comment",
			req -> setComment(ctx, req, CommentType.PLATE));

		router.get("/comments/history", "comment",
			"Comment change history at an address", req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				Address a = resolve(ctx, p, req);
				List<Object> out = new ArrayList<>();
				for (CommentType t : CommentType.values()) {
					for (var h : p.getListing().getCommentHistory(a, t)) {
						Map<String, Object> m = new LinkedHashMap<>();
						m.put("kind", t.name().toLowerCase());
						m.put("comments", h.getComments());
						m.put("user", h.getUserName());
						m.put("timestamp", h.getModificationDate() == null
							? null : h.getModificationDate().toInstant().toString());
						out.add(m);
					}
				}
				return Json.list(out);
			}));
	}

	// ---------------------------------------------------------------- helpers

	private static com.ghidramcp.util.ApiResponse setComment(ApiContext ctx,
			com.ghidramcp.api.ApiRequest req, CommentType forcedKind) {
		return ctx.mutateJson("Set comment via MCP", () -> {
			Program p = ctx.requireProgram();
			Address a = resolve(ctx, p, req);
			String comment = req.require("comment", "text", "message");
			CommentType type = forcedKind != null ? forcedKind
				: parseKind(req.param("kind", req.param("type", "eol")));
			p.getListing().setComment(a, type, comment);
			Map<String, Object> body = new LinkedHashMap<>();
			body.put("address", a.toString());
			body.put("kind", type.name());
			body.put("comment", comment);
			Function f = p.getFunctionManager().getFunctionContaining(a);
			body.put("function", f == null ? null : f.getName());
			return body;
		});
	}

	private static Map<String, Object> commentsAt(Program p, Address a) {
		Listing listing = p.getListing();
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("address", a.toString());
		for (CommentType t : CommentType.values()) {
			m.put(t.name().toLowerCase(), listing.getComment(t, a));
		}
		m.put("hasAny", listing.getComment(CommentType.EOL, a) != null
			|| listing.getComment(CommentType.PRE, a) != null
			|| listing.getComment(CommentType.POST, a) != null
			|| listing.getComment(CommentType.PLATE, a) != null
			|| listing.getComment(CommentType.REPEATABLE, a) != null);
		Function f = p.getFunctionManager().getFunctionContaining(a);
		m.put("function", f == null ? null : f.getName());
		return m;
	}

	/** Resolves the target address, accepting a function name as well. */
	private static Address resolve(ApiContext ctx, Program p,
			com.ghidramcp.api.ApiRequest req) {
		String function = req.firstOf("function");
		if (function != null) {
			return FunctionHandlers.requireFunction(p, function).getEntryPoint();
		}
		String address = req.firstOf("address", "addr", "at");
		if (address == null) {
			String name = req.firstOf("name");
			if (name != null) {
				return Lookup.address(p, name);
			}
			throw ApiException.badRequest("provide 'address' (and optionally 'kind')");
		}
		return Lookup.address(p, address);
	}

	/** Maps a user supplied comment kind onto Ghidra's enum. */
	private static CommentType parseKind(String kind) {
		if (kind == null || kind.isBlank()) {
			return CommentType.EOL;
		}
		return switch (kind.trim().toLowerCase()) {
			case "eol", "end-of-line", "end_of_line", "line", "decompiler", "disassembly" ->
				CommentType.EOL;
			case "pre", "pre-comment", "before", "above" -> CommentType.PRE;
			case "post", "post-comment", "after", "below" -> CommentType.POST;
			case "plate", "banner", "header" -> CommentType.PLATE;
			case "repeatable", "repeat" -> CommentType.REPEATABLE;
			default -> throw ApiException.badRequest("unknown comment kind '" + kind +
				"'; use eol, pre, post, plate or repeatable");
		};
	}
}
