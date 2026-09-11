/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.api;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;

/**
 * Data type helpers: name resolution, pointer sugar and struct synthesis.
 *
 * <p>The original GhidraMCP {@code resolveDataType} silently fell back to
 * {@code int} for unknown names, which made "I set the prototype" succeed while
 * producing nonsense. Here an unresolvable type is an error with suggestions.
 */
public final class Types {

	private Types() {
	}

	/**
	 * Resolves a C-ish type name against a program's data type manager.
	 *
	 * <p>Accepts Ghidra names and common C spellings, including pointer suffixes
	 * ({@code char *}), array suffixes ({@code char[16]}), Windows typedefs
	 * ({@code DWORD}, {@code PVOID}, {@code LPCSTR}) and typedef chains.
	 *
	 * @return the resolved type, or {@code null} when nothing matches
	 */
	public static DataType resolve(Program program, String name) {
		if (name == null || name.isBlank()) {
			return null;
		}
		String s = name.trim();
		DataTypeManager dtm = program.getDataTypeManager();

		// Pointer suffix: "char *", "char*", "char **"
		int stars = 0;
		while (s.endsWith("*")) {
			stars++;
			s = s.substring(0, s.length() - 1).trim();
		}
		// Array suffix: "char[16]"
		Integer arrayLen = null;
		int bracket = s.indexOf('[');
		if (bracket > 0 && s.endsWith("]")) {
			try {
				arrayLen = Integer.parseInt(s.substring(bracket + 1, s.length() - 1).trim());
				s = s.substring(0, bracket).trim();
			}
			catch (NumberFormatException ignored) {
				arrayLen = null;
			}
		}
		if (s.endsWith("const")) {
			// "const char *" -> "char *"
			s = s.substring(0, s.length() - 5).trim();
		}

		DataType base = resolveBase(dtm, s);
		if (base == null) {
			return null;
		}
		if (arrayLen != null) {
			base = new ArrayDataType(base, arrayLen, base.getLength() > 0 ? base.getLength() : 1);
		}
		for (int i = 0; i < stars; i++) {
			base = new PointerDataType(base, dtm);
		}
		return base;
	}

	/** Resolves a base (non pointer/array) type name. */
	public static DataType resolveBase(DataTypeManager dtm, String name) {
		String s = name.trim();
		DataType dt = dtm.getDataType(new CategoryPath("/"), s);
		if (dt != null) {
			return dt;
		}
		dt = dtm.getDataType("/" + s);
		if (dt != null) {
			return dt;
		}

		// Built-in aliases for the notations agents actually emit.
		String alias = switch (s.toLowerCase()) {
			case "int8_t", "sbyte", "int8" -> "/char";
			case "uint8_t", "uchar", "byte", "unsigned char", "uint8" -> "/byte";
			case "int16_t", "int16", "short" -> "/short";
			case "uint16_t", "uint16", "ushort", "unsigned short", "word" -> "/ushort";
			case "int32_t", "int32", "int", "long" -> "/int";
			case "uint32_t", "uint32", "uint", "unsigned int", "unsigned long", "dword" -> "/uint";
			case "int64_t", "int64", "longlong", "__int64", "qword" -> "/longlong";
			case "uint64_t", "uint64", "ulonglong", "unsigned __int64", "unsigned long long" -> "/ulonglong";
			case "float", "single" -> "/float";
			case "double" -> "/double";
			case "long double" -> "/longdouble";
			case "bool", "boolean", "_bool" -> "/bool";
			case "wchar_t" -> "/wchar_t";
			case "void" -> "/void";
			case "size_t", "uintptr_t", "ulong_ptr", "dword_ptr" -> "/uint";
			case "ssize_t", "intptr_t", "long_ptr" -> "/int";
			case "string", "lpstr", "lpcstr", "pchar" -> "/string";
			case "pvoid", "lpvoid", "handle", "hmodule", "hinstance" -> "/void";
			default -> null;
		};
		if (alias != null) {
			DataType aliased = "/string".equals(alias) ? stringType(dtm) : dtm.getDataType(alias);
			if (aliased != null) {
				return aliased;
			}
		}

		// Case-insensitive scan, then a typedef unwrap (CodeTypes often show up as
		// WORD/DWORD typedefs in Windows binaries).
		java.util.Iterator<DataType> it = dtm.getAllDataTypes();
		DataType ignoringCase = null;
		while (it.hasNext()) {
			DataType cand = it.next();
			if (cand.getName().equalsIgnoreCase(s)) {
				ignoringCase = cand;
				break;
			}
		}
		return ignoringCase;
	}

	private static DataType stringType(DataTypeManager dtm) {
		DataType dt = dtm.getDataType("/string");
		if (dt != null) {
			return dt;
		}
		dt = dtm.getDataType("/char *");
		return dt;
	}

	/** Candidate type names for "did you mean" hints. */
	public static List<String> suggestions(Program program, String name, int max) {
		List<String> out = new ArrayList<>();
		if (name == null) {
			return out;
		}
		String needle = name.toLowerCase().replace("*", "").trim();
		Set<String> seen = new LinkedHashSet<>();
		java.util.Iterator<DataType> it = program.getDataTypeManager().getAllDataTypes();
		while (it.hasNext() && out.size() < max) {
			DataType dt = it.next();
			String n = dt.getName();
			if (seen.add(n) && (n.toLowerCase().contains(needle) || needle.contains(n.toLowerCase()))) {
				out.add(dt.getPathName());
			}
		}
		if (out.isEmpty()) {
			// Fall back to a few universally useful built-ins.
			out.addAll(List.of("/int", "/uint", "/char", "/void", "/undefined8", "/string"));
		}
		return out;
	}

	/** True when the type renders as text (used by string endpoints). */
	public static boolean isStringLike(DataType dt) {
		if (dt == null) {
			return false;
		}
		DataType base = dt;
		while (base instanceof TypeDef td) {
			base = td.getBaseDataType();
		}
		String n = base.getName().toLowerCase();
		if (n.contains("string") || n.contains("unicode") || n.contains("char")) {
			return true;
		}
		String cls = base.getClass().getSimpleName().toLowerCase();
		return cls.contains("string");
	}

	/** Returns the struct/union behind {@code dt}, or null. */
	public static Object composite(DataType dt) {
		DataType base = dt;
		while (base instanceof TypeDef td) {
			base = td.getBaseDataType();
		}
		if (base instanceof Structure || base instanceof Union) {
			return base;
		}
		return null;
	}

	/**
	 * Creates (or refreshes) a structure definition in the program.
	 *
	 * @param fields comma or newline separated {@code "typeName fieldName"} pairs
	 */
	public static Structure createStructure(Program program, String name, List<String> fields) {
		DataTypeManager dtm = program.getDataTypeManager();
		StructureDataType struct = new StructureDataType(new CategoryPath("/mcp"), name, 0, dtm);
		for (String field : fields) {
			String f = field.trim();
			if (f.isEmpty()) {
				continue;
			}
			int space = f.lastIndexOf(' ');
			String typeName = space < 0 ? f : f.substring(0, space).trim();
			String fieldName = space < 0 ? "field" : f.substring(space + 1).trim();
			DataType ft = resolve(program, typeName);
			if (ft == null) {
				throw ApiException.badRequest("unknown field type '" + typeName + "' in '" + field + "'");
			}
			struct.add(ft, fieldName, null);
		}
		DataType added = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
		return (Structure) added;
	}
}
