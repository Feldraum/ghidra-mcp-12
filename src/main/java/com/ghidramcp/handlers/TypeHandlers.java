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
import com.ghidramcp.api.Jsonify;
import com.ghidramcp.api.Router;
import com.ghidramcp.api.Types;
import com.ghidramcp.util.ApiResponse;
import com.ghidramcp.util.Json;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;

/**
 * Data type discovery, creation and application.
 *
 * <p>An agent that can mint a struct and apply it to a pointer turns a wall of
 * {@code *(int *)(param_1 + 8)} into readable field accesses, which is usually
 * the highest-leverage edit available. The creation endpoints are therefore
 * first class rather than an afterthought.
 */
public final class TypeHandlers {

	private TypeHandlers() {
	}

	public static void register(Router router, ApiContext ctx) {

		router.get("/types", "type",
			"List data types built into / defined in the program. Filters: name, category, kind",
			req -> ApiResponse.json(list(ctx, req)));

		router.get("/types/count", "type", "Number of data types",
			req -> ctx.readJson(() -> Map.of("count", ctx.index(ctx.requireProgram())
				.dataTypeNames().size())));

		router.get("/types/search", "type", "Search data types by name (substring)",
			req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				String needle = req.require("query", "q", "name").toLowerCase();
				List<Object> items = new ArrayList<>();
				java.util.Iterator<DataType> it = p.getDataTypeManager().getAllDataTypes();
				while (it.hasNext()) {
					DataType dt = it.next();
					if (dt.getName().toLowerCase().contains(needle)) {
						items.add(Jsonify.dataType(dt));
					}
				}
				return Json.list(items);
			}));

		router.get("/types/detail", "type",
			"Structure/union/enum layout: members with offsets, sizes and types",
			req -> ctx.readJson(() -> detail(ctx.requireProgram(), req.require("name", "type"))));

		router.get("/types/resolve", "type",
			"Check how a type name resolves, with suggestions when it does not",
			req -> ctx.readJson(() -> {
				Program p = ctx.requireProgram();
				String name = req.require("name", "type");
				DataType dt = Types.resolve(p, name);
				Map<String, Object> body = new LinkedHashMap<>();
				body.put("query", name);
				body.put("resolved", dt != null);
				if (dt != null) {
					body.put("dataType", Jsonify.dataType(dt));
				}
				else {
					body.put("suggestions", Types.suggestions(p, name, 15));
				}
				return ApiResponse.json(body);
			}));

		// ------------------------------------------------------------ mutations
		router.post("/types/struct/create", "type",
			"Create a structure. fields='int a, char *b' (a field with no name gets fieldN)",
			req -> ctx.mutateJson("Create structure via MCP", () -> {
				Program p = ctx.requireProgram();
				String name = req.require("name");
				String fields = req.param("fields", "");
				List<String> parsed = new ArrayList<>();
				for (String f : fields.split(",")) {
					if (!f.isBlank()) {
						parsed.add(f.trim());
					}
				}
				Structure s = Types.createStructure(p, name, parsed);
				return structureLayout(s);
			}));

		router.post("/types/enum/create", "type",
			"Create an enum. values='RED=1,GREEN=2,BLUE=4' (values optional)",
			req -> ctx.mutateJson("Create enum via MCP", () -> {
				Program p = ctx.requireProgram();
				String name = req.require("name");
				String values = req.param("values", "");
				int size = Math.min(Math.max(req.intParam("size", 4), 1), 8);
				ghidra.program.model.data.EnumDataType en =
					new ghidra.program.model.data.EnumDataType(category(), name, size,
						p.getDataTypeManager());
				long next = 0;
				for (String pair : values.split(",")) {
					if (pair.isBlank()) {
						continue;
					}
					int eq = pair.indexOf('=');
					String key = eq < 0 ? pair.trim() : pair.substring(0, eq).trim();
					long value = eq < 0 ? next : parseLong(pair.substring(eq + 1).trim());
					en.add(key, value);
					next = value + 1;
				}
				DataType added = p.getDataTypeManager().addDataType(en,
					ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER);
				return Jsonify.dataType(added);
			}));

		router.post("/types/union/create", "type",
			"Create a union. fields='int a, char *b'",
			req -> ctx.mutateJson("Create union via MCP", () -> {
				Program p = ctx.requireProgram();
				String name = req.require("name");
				ghidra.program.model.data.UnionDataType u =
					new ghidra.program.model.data.UnionDataType(category(), name,
						p.getDataTypeManager());
				String fields = req.param("fields", "");
				for (String f : fields.split(",")) {
					String field = f.trim();
					if (field.isEmpty()) {
						continue;
					}
					int space = field.lastIndexOf(' ');
					String typeName = space < 0 ? field : field.substring(0, space).trim();
					String fieldName = space < 0 ? "field" : field.substring(space + 1).trim();
					DataType ft = Types.resolve(p, typeName);
					if (ft == null) {
						throw ApiException.badRequest("unknown field type '" + typeName + "'");
					}
					u.add(ft, fieldName, null);
				}
				DataType added = p.getDataTypeManager().addDataType(u,
					ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER);
				return Jsonify.dataType(added);
			}));

		router.post("/types/typedef/create", "type",
			"Create a typedef (name, baseType)",
			req -> ctx.mutateJson("Create typedef via MCP", () -> {
				Program p = ctx.requireProgram();
				String name = req.require("name");
				DataType base = Types.resolve(p, req.require("baseType", "type"));
				if (base == null) {
					throw ApiException.badRequest("unknown base type '" + req.param("baseType") + "'");
				}
				ghidra.program.model.data.TypedefDataType td =
					new ghidra.program.model.data.TypedefDataType(category(), name, base,
						p.getDataTypeManager());
				DataType added = p.getDataTypeManager().addDataType(td,
					ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER);
				return Jsonify.dataType(added);
			}));

		router.post("/types/c/parse", "type",
			"Parse and install C declarations, e.g. 'struct S { int a; char b[8]; };'",
			req -> ctx.mutateJson("Parse C declarations via MCP", () -> {
				Program p = ctx.requireProgram();
				String source = req.require("source", "declaration", "code");
				var cpp = new ghidra.app.util.cparser.C.CParser(p.getDataTypeManager());
				try {
					DataType parsed = cpp.parse(source);
					Map<String, Object> body = new LinkedHashMap<>();
					body.put("dataType", parsed == null ? null : Jsonify.dataType(parsed));
					body.put("parseMessages", cpp.getParseMessages());
					body.put("parseSucceeded", cpp.didParseSucceed());
					if (!cpp.didParseSucceed()) {
						throw ApiException.badRequest("C parse failed: " + cpp.getParseMessages());
					}
					return body;
				}
				catch (ghidra.app.util.cparser.C.ParseException e) {
					throw ApiException.badRequest("C parse failed: " + e.getMessage() +
						" (" + cpp.getParseMessages() + ")");
				}
			}));

		router.post("/types/delete", "type",
			"Remove a data type from the program (built-in types cannot be removed)",
			req -> ctx.mutateJson("Delete data type via MCP", () -> {
				Program p = ctx.requireProgram();
				String name = req.require("name", "type");
				DataType dt = Types.resolve(p, name);
				if (dt == null) {
					throw ApiException.notFound("no data type named '" + name + "'");
				}
				DataTypeManager dtm = p.getDataTypeManager();
				boolean removed = dtm.remove(dt);
				Map<String, Object> body = new LinkedHashMap<>();
				body.put("name", dt.getName());
				body.put("path", dt.getPathName());
				body.put("removed", removed);
				return body;
			}));
	}

	/** Category used for every type this bridge creates. */
	private static ghidra.program.model.data.CategoryPath category() {
		return new ghidra.program.model.data.CategoryPath("/mcp");
	}

	// ------------------------------------------------------------------- reads

	private static Map<String, Object> list(ApiContext ctx, com.ghidramcp.api.ApiRequest req) {
		return ctx.read(() -> {
			Program p = ctx.requireProgram();
			String nameFilter = req.param("name");
			String categoryFilter = req.param("category");
			String kindFilter = req.param("kind");
			List<Object> items = new ArrayList<>();
			java.util.Iterator<DataType> it = p.getDataTypeManager().getAllDataTypes();
			while (it.hasNext()) {
				DataType dt = it.next();
				if (nameFilter != null && !dt.getName().toLowerCase()
						.contains(nameFilter.toLowerCase())) {
					continue;
				}
				if (categoryFilter != null && !dt.getCategoryPath().getPath()
						.toLowerCase().contains(categoryFilter.toLowerCase())) {
					continue;
				}
				if (kindFilter != null && !dt.getClass().getSimpleName()
						.toLowerCase().contains(kindFilter.toLowerCase())) {
					continue;
				}
				items.add(Jsonify.dataType(dt));
			}
			var paging = req.paging(1000);
			Map<String, Object> envelope = new LinkedHashMap<>();
			envelope.put("count", items.size());
			envelope.put("offset", paging.offset());
			envelope.put("limit", paging.limit());
			envelope.put("truncated", paging.offset() + paging.limit() < items.size());
			envelope.put("items", paging.slice(items));
			return envelope;
		});
	}

	/** Layout of a structure/union/enum, which is what an agent needs to read fields. */
	private static Map<String, Object> detail(Program p, String name) {
		DataType dt = Types.resolve(p, name);
		if (dt == null) {
			throw ApiException.notFound("no data type named '" + name + "'; try " +
				String.join(", ", Types.suggestions(p, name, 6)));
		}
		Object composite = Types.composite(dt);
		Map<String, Object> body = new LinkedHashMap<>(Jsonify.dataType(dt));
		if (composite instanceof Structure s) {
			body.put("kind", "struct");
			body.put("size", s.getLength());
			body.put("members", members(s));
		}
		else if (composite instanceof Union u) {
			body.put("kind", "union");
			body.put("size", u.getLength());
			body.put("members", members(u));
		}
		else if (dt instanceof Enum en) {
			body.put("kind", "enum");
			body.put("size", en.getLength());
			List<Object> values = new ArrayList<>();
			for (String n : en.getNames()) {
				Map<String, Object> v = new LinkedHashMap<>();
				v.put("name", n);
				v.put("value", en.getValue(n));
				values.add(v);
			}
			body.put("values", values);
		}
		else {
			body.put("kind", dt.getClass().getSimpleName());
			body.put("size", dt.getLength());
		}
		return body;
	}

	private static List<Object> members(ghidra.program.model.data.Composite composite) {
		List<Object> out = new ArrayList<>();
		DataTypeComponent[] comps = composite.getComponents();
		for (DataTypeComponent c : comps) {
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("offset", c.getOffset());
			m.put("name", c.getFieldName());
			m.put("dataType", c.getDataType() == null ? null : c.getDataType().getName());
			m.put("dataTypePath", c.getDataType() == null ? null : c.getDataType().getPathName());
			m.put("length", c.getLength());
			m.put("comment", c.getComment());
			out.add(m);
		}
		return out;
	}

	private static Map<String, Object> structureLayout(Structure s) {
		Map<String, Object> body = new LinkedHashMap<>(Jsonify.dataType(s));
		body.put("kind", "struct");
		body.put("size", s.getLength());
		body.put("members", members(s));
		return body;
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
			throw ApiException.badRequest("cannot parse enum value '" + s + "'");
		}
	}
}
