/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.api;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

/**
 * Converts Ghidra domain objects into plain maps so the JSON layer stays dumb.
 *
 * <p>Field names are stable and documented in {@code docs/API.md}; agents are
 * told to rely on them, so renaming a key is a breaking change.
 */
public final class Jsonify {

	private Jsonify() {
	}

	/** Compact function descriptor used by list endpoints. */
	public static Map<String, Object> function(Function f) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("name", f.getName());
		m.put("nameWithNamespace", f.getName(true));
		m.put("address", f.getEntryPoint().toString());
		m.put("signature", safe(() -> f.getPrototypeString(false, false)));
		m.put("returnType", safe(() -> f.getReturnType().getName()));
		m.put("parameterCount", safeInt(() -> f.getParameterCount()));
		m.put("namespace", safe(() -> f.getParentNamespace().getName(true)));
		m.put("isExternal", f.isExternal());
		m.put("isThunk", f.isThunk());
		m.put("hasVarArgs", safeBool(() -> f.hasVarArgs()));
		m.put("hasNoReturn", safeBool(() -> f.hasNoReturn()));
		m.put("isInline", safeBool(() -> f.isInline()));
		m.put("signatureSource", String.valueOf(f.getSignatureSource()));
		m.put("bodySize", bodySize(f));
		return m;
	}

	/** Full function descriptor including parameters, locals and callers. */
	public static Map<String, Object> functionDetailed(Function f) {
		Map<String, Object> m = function(f);
		m.put("bodyMin", safe(() -> f.getBody().getMinAddress().toString()));
		m.put("bodyMax", safe(() -> f.getBody().getMaxAddress().toString()));
		m.put("comment", f.getComment());
		m.put("repeatableComment", f.getRepeatableComment());
		m.put("callingConvention", safe(() -> f.getCallingConventionName()));
		m.put("stackFrameSize", safeInt(() -> f.getStackFrame().getFrameSize()));
		m.put("parameters", parameters(f));
		m.put("localVariables", locals(f));
		List<Object> tags = new ArrayList<>();
		for (FunctionTag t : f.getTags()) {
			tags.add(t.getName());
		}
		m.put("tags", tags);
		return m;
	}

	public static List<Object> parameters(Function f) {
		List<Object> out = new ArrayList<>();
		Parameter[] params = f.getParameters();
		for (int i = 0; i < params.length; i++) {
			out.add(variable(params[i], i));
		}
		return out;
	}

	public static List<Object> locals(Function f) {
		List<Object> out = new ArrayList<>();
		Variable[] vars = f.getLocalVariables();
		for (int i = 0; i < vars.length; i++) {
			out.add(variable(vars[i], i));
		}
		return out;
	}

	/** Variable (parameter or local) descriptor. */
	public static Map<String, Object> variable(Variable v, int ordinal) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("name", v.getName());
		m.put("ordinal", ordinal);
		m.put("dataType", safe(() -> v.getDataType().getName()));
		m.put("dataTypePath", safe(() -> v.getDataType().getPathName()));
		m.put("storage", safe(() -> v.getVariableStorage().toString()));
		m.put("length", safeInt(() -> v.getLength()));
		m.put("isParameter", v instanceof Parameter);
		m.put("comment", v.getComment());
		return m;
	}

	public static Map<String, Object> symbol(Symbol s) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("name", s.getName());
		m.put("nameWithNamespace", s.getName(true));
		m.put("address", s.getAddress().toString());
		m.put("type", symbolTypeName(s.getSymbolType()));
		m.put("namespace", s.getParentNamespace() == null ? null : s.getParentNamespace().getName(true));
		m.put("isPrimary", s.isPrimary());
		m.put("isExternal", s.isExternal());
		m.put("isGlobal", s.isGlobal());
		m.put("source", String.valueOf(s.getSource()));
		m.put("referenceCount", safeInt(s::getReferenceCount));
		return m;
	}

	public static String symbolTypeName(SymbolType t) {
		return t == null ? "unknown" : t.toString();
	}

	/** Lightweight data-item descriptor (no value, which can be huge). */
	public static Map<String, Object> data(Data d, boolean includeValue) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("address", d.getAddress().toString());
		DataType dt = d.getDataType();
		m.put("dataType", dt == null ? null : dt.getName());
		m.put("length", d.getLength());
		m.put("label", d.getLabel());
		m.put("pathName", safe(d::getPathName));
		m.put("isString", Types.isStringLike(dt));
		if (includeValue) {
			m.put("value", safe(() -> d.getDefaultValueRepresentation()));
		}
		return m;
	}

	public static Map<String, Object> dataType(DataType dt) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("name", dt.getName());
		m.put("pathName", dt.getPathName());
		m.put("category", safe(() -> dt.getCategoryPath().getPath()));
		m.put("length", dt.getLength());
		m.put("description", dt.getDescription());
		m.put("kind", dt.getClass().getSimpleName());
		m.put("isNotYetDefined", dt.isNotYetDefined());
		return m;
	}

	public static Map<String, Object> memoryBlock(MemoryBlock b) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("name", b.getName());
		m.put("start", b.getStart().toString());
		m.put("end", b.getEnd().toString());
		m.put("size", b.getSize());
		m.put("permissions", permissions(b));
		m.put("isInitialized", b.isInitialized());
		m.put("isRead", b.isRead());
		m.put("isWrite", b.isWrite());
		m.put("isExecute", b.isExecute());
		m.put("isVolatile", b.isVolatile());
		m.put("type", String.valueOf(b.getType()));
		m.put("comment", b.getComment());
		m.put("sourceName", b.getSourceName());
		return m;
	}

	public static String permissions(MemoryBlock b) {
		return (b.isRead() ? "r" : "-") + (b.isWrite() ? "w" : "-") + (b.isExecute() ? "x" : "-");
	}

	public static Map<String, Object> reference(Program program, Address from, Address to,
			String typeName, boolean isPrimary) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("from", from == null ? null : from.toString());
		m.put("to", to == null ? null : to.toString());
		m.put("type", typeName);
		m.put("isPrimary", isPrimary);
		if (from != null) {
			Function f = program.getFunctionManager().getFunctionContaining(from);
			m.put("fromFunction", f == null ? null : f.getName());
			m.put("fromFunctionAddress", f == null ? null : f.getEntryPoint().toString());
		}
		if (to != null) {
			Function tf = program.getFunctionManager().getFunctionAt(to);
			if (tf != null) {
				m.put("toFunction", tf.getName());
			}
			Symbol s = program.getSymbolTable().getPrimarySymbol(to);
			if (s != null) {
				m.put("toSymbol", s.getName(true));
			}
			Data d = program.getListing().getDataAt(to);
			if (d != null) {
				m.put("toDataType", d.getDataType() == null ? null : d.getDataType().getName());
			}
		}
		return m;
	}

	// ------------------------------------------------------------- safe accessors
	// Ghidra getters throw on half-analysed programs (no stack frame, disposed
	// program, ...). A bridge that dies on those would be unusable, so every
	// derived field goes through a guarded accessor.

	public interface Supplier<T> {
		T get() throws Exception;
	}

	public static String safe(Supplier<?> s) {
		try {
			Object v = s.get();
			return v == null ? null : String.valueOf(v);
		}
		catch (Exception | LinkageError e) {
			return null;
		}
	}

	public static Integer safeInt(Supplier<?> s) {
		try {
			Object v = s.get();
			if (v instanceof Number n) {
				return n.intValue();
			}
			return v == null ? null : Integer.valueOf(String.valueOf(v));
		}
		catch (Exception | LinkageError e) {
			return null;
		}
	}

	public static Long safeLong(Supplier<?> s) {
		try {
			Object v = s.get();
			if (v instanceof Number n) {
				return n.longValue();
			}
			return v == null ? null : Long.valueOf(String.valueOf(v));
		}
		catch (Exception | LinkageError e) {
			return null;
		}
	}

	public static Boolean safeBool(Supplier<?> s) {
		try {
			Object v = s.get();
			return v instanceof Boolean b ? b : null;
		}
		catch (Exception | LinkageError e) {
			return null;
		}
	}

	public static long bodySize(Function f) {
		try {
			return f.getBody().getNumAddresses();
		}
		catch (Exception e) {
			return -1;
		}
	}
}
