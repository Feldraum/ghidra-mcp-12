/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.handlers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.ghidramcp.api.ApiContext;
import com.ghidramcp.api.ProgramIndex;
import com.ghidramcp.api.Router;
import com.ghidramcp.core.Lookup;
import com.ghidramcp.util.ApiResponse;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Program listing, project browsing and the memory map.
 *
 * <p>Read-only. Anything that changes a program lives in the category handlers
 * so that "which endpoints mutate my database?" stays answerable by looking at
 * the route categories.
 */
public final class ProgramHandlers {

	private ProgramHandlers() {
	}

	public static void register(Router router, ApiContext ctx) {

		// ------------------------------------------------------------ programs
		router.get("/programs", "program", "List programs currently open in Ghidra", req -> {
			List<Object> items = new ArrayList<>();
			for (Program p : ctx.programs().allOpen()) {
				Map<String, Object> m = new LinkedHashMap<>();
				m.put("name", p.getName());
				m.put("path", com.ghidramcp.api.Jsonify.safe(() -> p.getDomainFile().getPathname()));
				m.put("languageId", com.ghidramcp.api.Jsonify.safe(() -> p.getLanguageID().toString()));
				m.put("isCurrent", p == ctx.program());
				items.add(m);
			}
			return ApiResponse.json(com.ghidramcp.util.Json.list(items));
		});

		router.post("/program/activate", "program",
			"Make a named program the current one (for multi-program tools)", req -> {
				String name = req.require("name", "program");
				Program p = ctx.programs().activate(name);
				return ApiResponse.json(Map.of("success", true, "current", p.getName()));
			});

		router.post("/program/save", "program", "Save the current program to its project", req ->
				ctx.readJson(() -> {
					Program p = ctx.requireProgram();
					if (p.isClosed()) {
						throw com.ghidramcp.api.ApiException.conflict(
							p.getName() + " is closed and cannot be saved");
					}
					if (!p.canSave()) {
						// Say which of the two causes it is: a genuinely read-only file
						// needs a different action from a program that simply has no
						// project behind it.
						throw com.ghidramcp.api.ApiException.conflict(p.getName() +
							" cannot be saved: canSave() is false (the file is read-only, or " +
							"the program was not opened from a project)");
					}
					try {
						// DomainObject.save returns void and throws on failure, so the
						// success flag is "it did not throw".
						p.save(req.param("comment", "Saved via GhidraMCP12"),
							ghidra.util.task.TaskMonitor.DUMMY);
					}
					catch (java.io.IOException e) {
						throw com.ghidramcp.api.ApiException.internal(
							"could not save " + p.getName() + ": " + e.getMessage(), e);
					}
					catch (ghidra.util.exception.CancelledException e) {
						throw com.ghidramcp.api.ApiException.internal(
							"save of " + p.getName() + " was cancelled", e);
					}
					ProgramIndex.invalidate(p);
					Map<String, Object> body = new LinkedHashMap<>();
					body.put("success", true);
					body.put("program", p.getName());
					body.put("isChanged", p.isChanged());
					body.put("changeable", p.isChangeable());
					return body;
				}));

		router.post("/program/open", "program",
			"Open a program from the active project by its project path", req -> {
				String path = req.require("path");
				boolean readOnly = req.boolParam("readOnly", false);
				try {
					Program p = ctx.programs().openFromProject(path, readOnly);
					return ApiResponse.json(Map.of("success", true, "name", p.getName()));
				}
				catch (Exception e) {
					throw com.ghidramcp.api.ApiException.internal(
						"could not open " + path + ": " + e.getMessage(), e);
				}
			});

		router.get("/project/files", "program",
			"List files and folders in the active Ghidra project", req -> {
				Project project = ctx.guiAvailable() ? ctx.tool().getProject() : null;
				if (project == null) {
					throw new com.ghidramcp.api.ApiException(409,
						"no Ghidra project is open (this endpoint requires the Ghidra GUI)");
				}
				String folder = req.param("folder", "/");
				List<Object> items = new ArrayList<>();
				collect(project, folder, items);
				return ApiResponse.json(com.ghidramcp.util.Json.list(items));
			});

		// -------------------------------------------------------------- memory
		router.get("/memory/blocks", "memory",
			"Memory map: block names, address ranges, permissions, sizes", req ->
				MetaHandlers.page(blocks(ctx), req, 200));

		router.get("/memory/block", "memory", "Details for one memory block by name or address",
			req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				String name = req.param("name");
				String address = req.firstOf("address", "addr");
				Address probe = address == null ? null : Lookup.address(p, address);
				for (MemoryBlock b : p.getMemory().getBlocks()) {
					if ((name != null && b.getName().equals(name)) ||
						(probe != null && b.contains(probe))) {
						return com.ghidramcp.api.Jsonify.memoryBlock(b);
					}
				}
				throw com.ghidramcp.api.ApiException.notFound(
					"no memory block matches " + (name != null ? "name=" + name : "address=" + address));
			}));

		router.get("/memory/read", "memory",
			"Read raw bytes as hex/ASCII (parameters: address, length)", req -> memoryRead(ctx, req));

		router.get("/memory/bytes", "memory", "Alias of /memory/read",
			req -> memoryRead(ctx, req));

		router.get("/memory/strings", "memory",
			"Alias of /strings (defined strings with addresses)", req ->
				MetaHandlers.page(DataHandlers.strings(ctx, req.param("filter")), req, 2000));

		router.get("/memory/search", "memory",
			"Search memory for hex bytes (e.g. bytes=488b05) or ASCII text (text=hello)", req ->
				ctx.read(() -> {
					Program p = ctx.requireProgram();
					String hexPattern = req.param("bytes");
					String text = req.param("text");
					int max = Math.min(Math.max(req.intParam("max", 50), 1), 1000);
					List<Object> found = new ArrayList<>();

					if (hexPattern != null && !hexPattern.isBlank()) {
						byte[] needle = parseHex(hexPattern);
						searchBytes(p, needle, max, found);
					}
					else if (text != null && !text.isBlank()) {
						searchBytes(p, text.getBytes(java.nio.charset.StandardCharsets.UTF_8), max, found);
					}
					else {
						throw com.ghidramcp.api.ApiException.badRequest(
							"provide either 'bytes' (hex) or 'text' to search for");
					}
					return ApiResponse.json(com.ghidramcp.util.Json.list(found));
				}));

		router.get("/segments", "memory", "Alias of /memory/blocks (legacy GhidraMCP shape)",
			req -> {
				List<Object> lines = new ArrayList<>();
				for (Object o : blocks(ctx)) {
					if (o instanceof Map<?, ?> m) {
						lines.add(m.get("name") + ": " + m.get("start") + " - " + m.get("end"));
					}
				}
				return MetaHandlers.page(lines, req, 200);
			});
	}

	// ------------------------------------------------------------------ helpers

	/** Shared implementation for {@code /memory/read} and {@code /memory/bytes}. */
	private static ApiResponse memoryRead(ApiContext ctx, com.ghidramcp.api.ApiRequest req) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
			int length = Math.min(Math.max(req.intParam("length", 64), 1), 65536);
			byte[] data = new byte[length];
			int read;
			try {
				read = p.getMemory().getBytes(a, data);
			}
			catch (Exception e) {
				throw com.ghidramcp.api.ApiException.notFound(
					"cannot read memory at " + a + ": " + e.getMessage());
			}
			if (read <= 0) {
				throw com.ghidramcp.api.ApiException.notFound("no bytes at " + a);
			}
			if (read < length) {
				data = java.util.Arrays.copyOf(data, read);
			}
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("address", a.toString());
			m.put("length", data.length);
			m.put("hex", hex(data));
			m.put("ascii", ascii(data));
			m.put("words", words(p, a, data.length));
			return ApiResponse.json(m);
		});
	}

	private static List<Object> blocks(ApiContext ctx) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			List<Object> items = new ArrayList<>();
			for (MemoryBlock b : p.getMemory().getBlocks()) {
				Map<String, Object> m = com.ghidramcp.api.Jsonify.memoryBlock(b);
				m.put("containsCode", b.isExecute());
				items.add(m);
			}
			return items;
		});
	}

	private static void collect(Project project, String folder, List<Object> items) {
		var root = project.getProjectData().getRootFolder();
		var target = "/".equals(folder) ? root : project.getProjectData().getFolder(folder);
		if (target == null) {
			throw com.ghidramcp.api.ApiException.notFound("no project folder " + folder);
		}
		for (DomainFile f : target.getFiles()) {
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("kind", "file");
			m.put("name", f.getName());
			m.put("path", f.getPathname());
			m.put("contentType", f.getContentType());
			m.put("readOnly", f.isReadOnly());
			m.put("version", f.getVersion());
			items.add(m);
		}
		for (var sub : target.getFolders()) {
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("kind", "folder");
			m.put("name", sub.getName());
			m.put("path", sub.getPathname());
			items.add(m);
		}
	}

	private static String hex(byte[] data) {
		StringBuilder sb = new StringBuilder(data.length * 2);
		for (byte b : data) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	private static String ascii(byte[] data) {
		StringBuilder sb = new StringBuilder(data.length);
		for (byte b : data) {
			int c = b & 0xff;
			sb.append(c >= 32 && c < 127 ? (char) c : '.');
		}
		return sb.toString();
	}

	/** Decodes the bytes at an address using the program's own endianness. */
	private static List<Object> words(Program program, Address base, int length) {
		List<Object> out = new ArrayList<>();
		boolean big = program.getLanguage().isBigEndian();
		byte[] data = new byte[length];
		try {
			program.getMemory().getBytes(base, data);
		}
		catch (Exception e) {
			return out;
		}
		for (int off = 0; off + 4 <= data.length && out.size() < 16; off += 4) {
			int v = big
				? ((data[off] & 0xff) << 24) | ((data[off + 1] & 0xff) << 16) | ((data[off + 2] & 0xff) << 8) | (data[off + 3] & 0xff)
				: ((data[off + 3] & 0xff) << 24) | ((data[off + 2] & 0xff) << 16) | ((data[off + 1] & 0xff) << 8) | (data[off] & 0xff);
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("address", base.add(off).toString());
			m.put("uint32", Integer.toUnsignedString(v));
			m.put("int32", v);
			m.put("hex", String.format("0x%08x", v));
			out.add(m);
		}
		return out;
	}

	private static byte[] parseHex(String s) {
		String t = s.replaceAll("[^0-9a-fA-F]", "");
		if (t.length() % 2 != 0) {
			throw com.ghidramcp.api.ApiException.badRequest("hex pattern must have an even number of digits");
		}
		byte[] out = new byte[t.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(t.substring(i * 2, i * 2 + 2), 16);
		}
		return out;
	}

	private static void searchBytes(Program program, byte[] needle, int max, List<Object> found) {
		if (needle.length == 0) {
			return;
		}
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.isInitialized() || found.size() >= max) {
				continue;
			}
			long offset = 0;
			Address start = block.getStart();
			while (offset < block.getSize() && found.size() < max) {
				Address at = start.add(offset);
				Address hit = program.getMemory().findBytes(at, block.getEnd(), needle, null, true,
					ghidra.util.task.TaskMonitor.DUMMY);
				if (hit == null) {
					break;
				}
				Map<String, Object> m = Lookup.describe(program, hit);
				found.add(m);
				long delta = hit.subtract(block.getStart()) + 1;
				offset = delta;
			}
		}
	}
}
