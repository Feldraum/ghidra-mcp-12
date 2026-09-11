/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Address and symbol lookup helpers shared by the API handlers.
 *
 * <p>GhidraMCP's original handlers each implemented their own "find a function
 * by this string" logic, which led to inconsistent behaviour between endpoints
 * (some accepted {@code 0x401000}, some only {@code 00401000}, some resolved
 * names, most did not). Everything here accepts all of those forms.
 */
public final class Lookup {

	private Lookup() {
	}

	/**
	 * Parses an address in any of the forms an agent is likely to produce:
	 * {@code 0x401000}, {@code 401000}, {@code 00401000}, {@code ram:00401000},
	 * or a symbol/function name.
	 *
	 * @throws IllegalArgumentException when the text cannot be resolved
	 */
	public static Address address(Program program, String text) {
		if (text == null || text.isBlank()) {
			throw new IllegalArgumentException("address is required");
		}
		String s = text.trim();

		// Explicit space:offset form.
		int colon = s.indexOf(':');
		AddressFactory af = program.getAddressFactory();
		if (colon > 0) {
			String spaceName = s.substring(0, colon);
			String offset = s.substring(colon + 1);
			AddressSpace space = af.getAddressSpace(spaceName);
			if (space != null) {
				try {
					return space.getAddress(offset);
				}
				catch (Exception e) {
					throw new IllegalArgumentException(
						"cannot parse offset '" + offset + "' in space '" + spaceName + "'");
				}
			}
		}

		// Numeric forms.
		try {
			String hex = s;
			if (hex.startsWith("0x") || hex.startsWith("0X")) {
				hex = hex.substring(2);
			}
			else if (hex.startsWith("0b") || hex.startsWith("0B")) {
				return af.getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(hex.substring(2), 2));
			}
			else if (!hex.matches("(?i)[0-9a-f]+")) {
				// Not hex-looking: fall through to symbol resolution.
				return byName(program, s);
			}
			return af.getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(hex, 16));
		}
		catch (NumberFormatException e) {
			return byName(program, s);
		}
	}

	/** Resolves the address of a symbol or function by name. */
	public static Address byName(Program program, String name) {
		Function f = functionByName(program, name);
		if (f != null) {
			return f.getEntryPoint();
		}
		SymbolTable st = program.getSymbolTable();
		SymbolIterator it = st.getSymbols(name);
		List<Symbol> found = new ArrayList<>();
		while (it.hasNext()) {
			Symbol s = it.next();
			if (s.getName(true).equals(name) || s.getName().equals(name)) {
				found.add(s);
			}
		}
		if (found.isEmpty()) {
			// Last resort: a substring search, which is what users usually mean.
			it = st.getAllSymbols(true);
			while (it.hasNext()) {
				Symbol s = it.next();
				if (s.getName().equalsIgnoreCase(name)) {
					found.add(s);
					break;
				}
			}
		}
		if (found.isEmpty()) {
			throw new IllegalArgumentException("cannot resolve address or symbol '" + name + "'");
		}
		if (found.size() > 1) {
			// Prefer a function entry point when the name is ambiguous.
			for (Symbol s : found) {
				if (s.isExternalEntryPoint() || program.getFunctionManager()
						.getFunctionAt(s.getAddress()) != null) {
					return s.getAddress();
				}
			}
		}
		return found.get(0).getAddress();
	}

	/** Finds a function by exact name, then by case-insensitive name, then by address text. */
	public static Function functionByName(Program program, String name) {
		if (name == null || name.isBlank()) {
			return null;
		}
		var fm = program.getFunctionManager();
		Function exact = null;
		Function ignoringCase = null;
		for (Function f : fm.getFunctions(true)) {
			String n = f.getName();
			if (n.equals(name)) {
				return f;
			}
			if (ignoringCase == null && n.equalsIgnoreCase(name)) {
				ignoringCase = f;
			}
		}
		if (ignoringCase != null) {
			return ignoringCase;
		}
		// Qualified name match (Namespace::name).
		for (Function f : fm.getFunctions(true)) {
			if (f.getName(true).equals(name)) {
				exact = f;
				break;
			}
		}
		return exact;
	}

	/**
	 * Resolves a function from either its address or its name, preferring the
	 * function that contains the address when no function starts exactly there.
	 */
	public static Function function(Program program, String text) {
		if (text == null || text.isBlank()) {
			throw new IllegalArgumentException("function address or name is required");
		}
		Function byName = functionByName(program, text.trim());
		if (byName != null) {
			return byName;
		}
		Address a = address(program, text);
		var fm = program.getFunctionManager();
		Function f = fm.getFunctionAt(a);
		if (f != null) {
			return f;
		}
		f = fm.getFunctionContaining(a);
		if (f != null) {
			return f;
		}
		// The address may point at a thunk or an external location.
		return fm.getFunctionAt(a);
	}

	/** True when the address is inside a loaded memory block. */
	public static boolean inMemory(Program program, Address a) {
		Memory mem = program.getMemory();
		return mem.getBlock(a) != null;
	}

	/** Human readable description of an address' contents, used in several tools. */
	public static Map<String, Object> describe(Program program, Address a) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("address", a.toString());
		var block = program.getMemory().getBlock(a);
		m.put("block", block == null ? null : block.getName());
		Function f = program.getFunctionManager().getFunctionContaining(a);
		m.put("function", f == null ? null : f.getName());
		Symbol s = program.getSymbolTable().getPrimarySymbol(a);
		m.put("symbol", s == null ? null : s.getName(true));
		return m;
	}
}
