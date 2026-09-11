/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.api;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Lazily-built, per-program lookup index.
 *
 * <p>Several endpoints need "the function called X" or "the data type called
 * {@code DWORD}" and the naive implementation is an O(n) walk of the whole
 * symbol table. Agents call those endpoints in tight loops, so the index is
 * built once per program (and invalidated whenever the program's modification
 * number changes) and cached in a weak map keyed by program.
 */
public final class ProgramIndex {

	private static final Map<Program, ProgramIndex> CACHE =
		Collections.synchronizedMap(new WeakHashMap<>());

	private final long modificationNumber;
	private final List<Function> functions;
	private final Map<String, List<Function>> functionsByName;
	private final List<Symbol> symbols;
	private final Map<String, List<Symbol>> symbolsByName;
	private final Map<String, DataType> dataTypesByName;

	private ProgramIndex(Program program) {
		this.modificationNumber = program.getModificationNumber();

		List<Function> funcs = new ArrayList<>();
		FunctionIterator fit = program.getFunctionManager().getFunctions(true);
		while (fit.hasNext()) {
			funcs.add(fit.next());
		}
		this.functions = List.copyOf(funcs);

		Map<String, List<Function>> byName = new HashMap<>();
		for (Function f : functions) {
			byName.computeIfAbsent(f.getName(), k -> new ArrayList<>()).add(f);
		}
		this.functionsByName = byName;

		List<Symbol> syms = new ArrayList<>();
		SymbolTable st = program.getSymbolTable();
		SymbolIterator sit = st.getAllSymbols(true);
		while (sit.hasNext()) {
			syms.add(sit.next());
		}
		this.symbols = List.copyOf(syms);

		Map<String, List<Symbol>> symByName = new HashMap<>();
		for (Symbol s : symbols) {
			symByName.computeIfAbsent(s.getName(), k -> new ArrayList<>()).add(s);
		}
		this.symbolsByName = symByName;

		Map<String, DataType> types = new HashMap<>();
		DataTypeManager dtm = program.getDataTypeManager();
		java.util.Iterator<DataType> dit = dtm.getAllDataTypes();
		while (dit.hasNext()) {
			DataType dt = dit.next();
			// First writer wins so that built-in types shadow program types with
			// the same simple name, matching what the Ghidra GUI shows by default.
			types.putIfAbsent(dt.getName(), dt);
			types.putIfAbsent(dt.getPathName(), dt);
		}
		this.dataTypesByName = types;
	}

	/** Returns a cached index, rebuilding it when the program has changed. */
	public static ProgramIndex of(Program program) {
		synchronized (CACHE) {
			ProgramIndex idx = CACHE.get(program);
			if (idx == null || idx.modificationNumber != program.getModificationNumber()) {
				idx = new ProgramIndex(program);
				CACHE.put(program, idx);
			}
			return idx;
		}
	}

	/** Drops the cached index; called after mutating endpoints run. */
	public static void invalidate(Program program) {
		CACHE.remove(program);
	}

	public List<Function> functions() {
		return functions;
	}

	public List<Symbol> symbols() {
		return symbols;
	}

	/** All functions with the given exact name (overloads included). */
	public List<Function> functionsNamed(String name) {
		return functionsByName.getOrDefault(name, List.of());
	}

	/** Case-insensitive function lookup, used when an agent guesses casing. */
	public List<Function> functionsNamedIgnoreCase(String name) {
		List<Function> out = new ArrayList<>();
		for (Function f : functions) {
			if (f.getName().equalsIgnoreCase(name)) {
				out.add(f);
			}
		}
		return out;
	}

	public List<Symbol> symbolsNamed(String name) {
		return symbolsByName.getOrDefault(name, List.of());
	}

	/** Case-insensitive data type lookup by simple name or full path. */
	public DataType dataType(String name) {
		DataType dt = dataTypesByName.get(name);
		if (dt != null) {
			return dt;
		}
		for (Map.Entry<String, DataType> e : dataTypesByName.entrySet()) {
			if (e.getKey().equalsIgnoreCase(name)) {
				return e.getValue();
			}
		}
		return null;
	}

	public List<String> dataTypeNames() {
		List<String> names = new ArrayList<>(dataTypesByName.keySet());
		Collections.sort(names);
		return names;
	}
}
