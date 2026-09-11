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
import com.ghidramcp.core.Lookup;
import com.ghidramcp.util.ApiResponse;
import com.ghidramcp.util.Json;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

/**
 * Defined data: strings, data items, byte patching and type application.
 *
 * <p>The string endpoints are the ones agents lean on hardest, so they filter on
 * Ghidra's own {@code isStringLike} notion (which follows typedef chains) rather
 * than on a type-name substring match, which misclassifies {@code wchar_t*} and
 * misses {@code TerminatedCString}.
 */
public final class DataHandlers {

	private DataHandlers() {
	}

	public static void register(Router router, ApiContext ctx) {

		router.get("/strings", "data",
			"Defined strings with addresses. Filters: filter (substring), minLength, block",
			req -> {
				List<Object> items = strings(ctx, req.param("filter"));
				return MetaHandlers.page(items, req, 2000);
			});

		router.get("/strings/search", "data", "Alias of /strings with a filter",
			req -> MetaHandlers.page(strings(ctx, req.require("query", "q", "filter")), req, 2000));

		router.get("/strings/count", "data", "Number of defined strings",
			req -> ctx.readJson(() -> Map.of("count", strings(ctx, null).size())));

		router.get("/data", "data",
			"Defined data items. Filters: address range, type, minLength",
			req -> MetaHandlers.page(dataItems(ctx, req), req, 500));

		router.get("/data/items", "data", "Alias of /data",
			req -> MetaHandlers.page(dataItems(ctx, req), req, 500));

		router.get("/data/at", "data", "The data item at an address, with its value",
			req -> ctx.read(() -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				Data d = p.getListing().getDataContaining(a);
				if (d == null) {
					throw ApiException.notFound("no defined data at " + a);
				}
				Map<String, Object> body = Jsonify.data(d, true);
				body.put("components", components(d));
				body.put("isContaining", !d.getAddress().equals(a));
				return ApiResponse.json(body);
			}));

		router.get("/data/type", "data", "Data type of the item at an address",
			req -> ctx.read(() -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				Data d = p.getListing().getDataContaining(a);
				if (d == null) {
					throw ApiException.notFound("no defined data at " + a);
				}
				return ApiResponse.json(Map.of(
					"address", d.getAddress().toString(),
					"dataType", d.getDataType().getName(),
					"dataTypePath", d.getDataType().getPathName(),
					"length", d.getLength()));
			}));

		router.get("/data/read", "data",
			"Read a primitive value at an address (type: byte|word|dword|qword|float|double|pointer)",
			req -> ctx.readJson(() -> readValue(ctx.requireProgram(), req)));

		// ------------------------------------------------------------ mutations
		router.post("/data/create", "data",
			"Define data at an address (address, type, optional length/count)",
			req -> ApiResponse.json(ctx.mutate("Create data via MCP", () -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				String typeName = req.require("type", "dataType");
				DataType dt = Types.resolve(p, typeName);
				if (dt == null) {
					throw ApiException.badRequest("unknown data type '" + typeName + "'. Examples: " +
						String.join(", ", Types.suggestions(p, typeName, 8)));
				}
				Listing listing = p.getListing();
				Data created;
				if (dt.getLength() <= 0) {
					int length = Math.max(1, req.intParam("length", 1));
					created = listing.createData(a, dt, length);
				}
				else {
					created = listing.createData(a, dt);
				}
				Map<String, Object> body = Jsonify.data(created, true);
				body.put("created", true);
				return body;
			})));

		router.post("/data/delete", "data",
			"Clear the data definition at an address (keeps the bytes)",
			req -> ApiResponse.json(ctx.mutate("Clear data via MCP", () -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				p.getListing().clearCodeUnits(a, a, false);
				return Map.of("address", a.toString(), "cleared", true);
			})));

		router.post("/data/retype", "data",
			"Change the data type of the item at an address",
			req -> ApiResponse.json(ctx.mutate("Retype data via MCP", () -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				String typeName = req.require("type", "dataType", "newType");
				DataType dt = Types.resolve(p, typeName);
				if (dt == null) {
					throw ApiException.badRequest("unknown data type '" + typeName + "'");
				}
				p.getListing().clearCodeUnits(a, a, false);
				Data d = p.getListing().createData(a, dt);
				return Jsonify.data(d, true);
			})));

		router.post("/data/rename", "data",
			"Set the label of the data at an address (legacy /renameData)",
			req -> ApiResponse.json(ctx.mutate("Rename data via MCP", () -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				String newName = req.require("newName", "new_name", "name");
				var st = p.getSymbolTable();
				var primary = st.getPrimarySymbol(a);
				if (primary == null) {
					primary = st.createLabel(a, newName, SourceType.USER_DEFINED);
				}
				else {
					primary.setName(newName, SourceType.USER_DEFINED);
				}
				return Map.of("address", a.toString(), "name", primary.getName());
			})));

		router.post("/memory/write", "data",
			"Patch bytes in memory (address, hex='90 90' or '9090'). Set clearCodeUnits=true to " +
				"overwrite bytes that Ghidra currently models as an instruction or data item",
			req -> ctx.mutateJson("Patch bytes via MCP", () -> {
				Program p = ctx.requireProgram();
				Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
				String hex = req.require("hex", "bytes");
				byte[] data = parseHex(hex);
				Address end = a.add(data.length - 1L);

				// Ghidra refuses to write over defined code/data ("Memory change
				// conflicts with instruction at ..."). Clearing the definitions is
				// what File > Patch Data does after prompting, so it is offered here
				// as an explicit opt-in rather than silently destroying analysis.
				Listing listing = p.getListing();
				boolean hasCodeUnits = listing.getCodeUnitAt(a) != null
					|| listing.getCodeUnitContaining(a) != null;
				if (hasCodeUnits) {
					if (!req.boolParam("clearCodeUnits", false)) {
						throw ApiException.conflict("the range " + a + "-" + end +
							" contains defined code or data, which Ghidra will not overwrite. " +
							"Retry with clearCodeUnits=true to clear those definitions first " +
							"(their analysis is lost).");
					}
					listing.clearCodeUnits(a, end, false);
				}

				p.getMemory().setBytes(a, data);
				byte[] verify = new byte[data.length];
				int readBack = p.getMemory().getBytes(a, verify);
				Map<String, Object> body = new LinkedHashMap<>();
				body.put("address", a.toString());
				body.put("written", data.length);
				body.put("clearedCodeUnits", hasCodeUnits);
				body.put("verifiedBytes", readBack);
				body.put("bytes", hex(data));
				body.put("matches", readBack == data.length
					&& java.util.Arrays.equals(data, verify));
				return body;
			}));

		router.post("/memory/fill", "data",
			"Fill a range with a byte value (address, length, value)",
			req -> ctx.mutateJson("Fill memory via MCP", () -> {
				Program p = ctx.requireProgram();
				Address start = Lookup.address(p, MetaHandlers.requireAddress(req));
				int length = Math.min(Math.max(req.intParam("length", 1), 1), 1 << 20);
				int value = req.intParam("value", 0x90) & 0xff;
				Address end = start.add(length - 1L);
				if (req.boolParam("clearCodeUnits", false)) {
					p.getListing().clearCodeUnits(start, end, false);
				}
				try {
					p.getMemory().setBytes(start, repeat((byte) value, length));
				}
				catch (Exception e) {
					throw ApiException.internal("could not fill memory: " + e.getMessage() +
						". If the range contains defined code or data, retry with " +
						"clearCodeUnits=true.", e);
				}
				Map<String, Object> body = new LinkedHashMap<>();
				body.put("start", start.toString());
				body.put("end", end.toString());
				body.put("length", length);
				body.put("value", String.format("0x%02x", value));
				return body;
			}));
	}

	// ------------------------------------------------------------------- reads

	/**
	 * Collects defined strings, applying an optional substring filter and an
	 * optional minimum length. Shared by {@code /strings}, {@code /strings/search}
	 * and the legacy {@code /strings} alias.
	 */
	static List<Object> strings(ApiContext ctx, String filter) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			String needle = filter == null ? null : filter.toLowerCase();
			int minLength = 0;
			List<Object> items = new ArrayList<>();
			DataIterator it = p.getListing().getDefinedData(true);
			while (it.hasNext()) {
				Data d = it.next();
				if (!Types.isStringLike(d.getDataType()) || d.getLength() < minLength) {
					continue;
				}
				String value = Jsonify.safe(() -> String.valueOf(d.getValue()));
				if (value == null) {
					continue;
				}
				if (needle != null && !value.toLowerCase().contains(needle)) {
					continue;
				}
				Map<String, Object> m = new LinkedHashMap<>();
				m.put("address", d.getAddress().toString());
				m.put("value", value);
				m.put("length", d.getLength());
				m.put("dataType", d.getDataType().getName());
				m.put("label", d.getLabel());
				Function f = p.getFunctionManager().getFunctionContaining(d.getAddress());
				m.put("function", f == null ? null : f.getName());
				items.add(m);
			}
			return items;
		});
	}

	private static List<Object> dataItems(ApiContext ctx, ApiRequest req) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			String typeFilter = req.param("type");
			String addressFilter = req.firstOf("address", "addr", "start");
			int minLength = req.intParam("minLength", 0);

			Address from = addressFilter == null ? null : Lookup.address(p, addressFilter);
			List<Object> items = new ArrayList<>();
			DataIterator it = from == null
				? p.getListing().getDefinedData(true)
				: p.getListing().getDefinedData(from, true);
			while (it.hasNext()) {
				Data d = it.next();
				if (d.getLength() < minLength) {
					continue;
				}
				if (typeFilter != null && (d.getDataType() == null ||
					!d.getDataType().getName().toLowerCase()
						.contains(typeFilter.toLowerCase()))) {
					continue;
				}
				items.add(Jsonify.data(d, true));
			}
			return items;
		});
	}

	private static List<Object> components(Data d) {
		List<Object> out = new ArrayList<>();
		if (d.getNumComponents() <= 1) {
			return out;
		}
		for (int i = 0; i < d.getNumComponents(); i++) {
			Data c = d.getComponent(i);
			if (c == null) {
				continue;
			}
			final int index = i;
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("index", index);
			m.put("fieldName", Jsonify.safe(() -> d.getComponent(index).getFieldName()));
			m.put("address", c.getAddress().toString());
			m.put("dataType", c.getDataType() == null ? null : c.getDataType().getName());
			m.put("length", c.getLength());
			m.put("value", Jsonify.safe(() -> c.getDefaultValueRepresentation()));
			out.add(m);
		}
		return out;
	}

	/** Reads a typed primitive, honouring the program's endianness. */
	private static Map<String, Object> readValue(Program p, ApiRequest req) {
		Address a = Lookup.address(p, MetaHandlers.requireAddress(req));
		String type = req.param("type", "dword").toLowerCase();
		boolean big = p.getLanguage().isBigEndian();
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("address", a.toString());
		body.put("type", type);
		try {
			switch (type) {
				case "byte", "uint8", "u8" -> {
					byte v = p.getMemory().getByte(a);
					body.put("value", v & 0xff);
					body.put("signed", (int) v);
				}
				case "char", "int8" -> body.put("value", (int) p.getMemory().getByte(a));
				case "word", "uint16", "u16", "short" -> {
					short v = p.getMemory().getShort(a, big);
					body.put("value", v & 0xffff);
					body.put("signed", (int) v);
				}
				case "dword", "uint32", "u32", "int", "int32" -> {
					int v = p.getMemory().getInt(a, big);
					body.put("value", Integer.toUnsignedString(v));
					body.put("signed", v);
					body.put("hex", String.format("0x%08x", v));
				}
				case "qword", "uint64", "u64", "long", "int64" -> {
					long v = p.getMemory().getLong(a, big);
					body.put("value", Long.toUnsignedString(v));
					body.put("signed", v);
					body.put("hex", String.format("0x%016x", v));
				}
				case "float", "single" -> {
					int bits = p.getMemory().getInt(a, big);
					body.put("value", Float.intBitsToFloat(bits));
				}
				case "double" -> {
					long bits = p.getMemory().getLong(a, big);
					body.put("value", Double.longBitsToDouble(bits));
				}
				case "pointer", "ptr" -> {
					int size = p.getDefaultPointerSize();
					if (size <= 0 || size > 8) {
						size = 8;
					}
					long raw = size <= 4
						? Integer.toUnsignedLong(p.getMemory().getInt(a, big))
						: p.getMemory().getLong(a, big);
					Address target = null;
					try {
						target = p.getAddressFactory().getDefaultAddressSpace().getAddress(raw);
					}
					catch (ghidra.program.model.address.AddressOutOfBoundsException ignored) {
						// Out of range for the space: report the raw value only.
					}
					body.put("value", target == null ? null : target.toString());
					body.put("raw", "0x" + Long.toUnsignedString(raw, 16));
					body.put("size", size);
				}
				case "string", "cstring", "ascii" -> {
					int max = Math.min(Math.max(req.intParam("length", 256), 1), 4096);
					byte[] buf = new byte[max];
					int read = p.getMemory().getBytes(a, buf);
					int end = 0;
					while (end < read && buf[end] != 0) {
						end++;
					}
					body.put("value", new String(buf, 0, Math.max(0, end),
						java.nio.charset.StandardCharsets.US_ASCII));
				}
				default -> throw ApiException.badRequest("unsupported type '" + type +
					"'; use one of byte/word/dword/qword/float/double/pointer/string");
			}
		}
		catch (ghidra.program.model.mem.MemoryAccessException e) {
			throw ApiException.notFound("cannot read a " + type + " at " + a + ": " + e.getMessage());
		}
		return body;
	}

	// ---------------------------------------------------------------- utilities

	static byte[] parseHex(String s) {
		String t = s.replaceAll("0x", "").replaceAll("[^0-9a-fA-F]", "");
		if (t.length() % 2 != 0) {
			throw ApiException.badRequest("hex string must have an even number of digits");
		}
		byte[] out = new byte[t.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(t.substring(i * 2, i * 2 + 2), 16);
		}
		return out;
	}

	private static String hex(byte[] data) {
		StringBuilder sb = new StringBuilder(data.length * 2);
		for (byte b : data) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	private static byte[] repeat(byte v, int n) {
		byte[] out = new byte[n];
		java.util.Arrays.fill(out, v);
		return out;
	}

	/** Counts data items in a memory block (used by the summary endpoint). */
	static int countInBlock(Program p, MemoryBlock block) {
		int n = 0;
		DataIterator it = p.getListing().getDefinedData(block.getStart(), true);
		while (it.hasNext()) {
			Data d = it.next();
			if (!block.contains(d.getAddress())) {
				break;
			}
			n++;
		}
		return n;
	}

	/** Exposed for the legacy handler, which lists strings page by page. */
	static List<Object> stringLines(ApiContext ctx, String filter) {
		List<Object> out = new ArrayList<>();
		for (Object o : strings(ctx, filter)) {
			if (o instanceof Map<?, ?> m) {
				out.add(m.get("address") + ": \"" + m.get("value") + "\"");
			}
		}
		return out;
	}
}
