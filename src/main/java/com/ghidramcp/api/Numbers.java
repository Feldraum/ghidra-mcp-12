/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.api;

/** Lenient numeric parsing for HTTP parameters. */
final class Numbers {

	private Numbers() {
	}

	/** Parses decimal, {@code 0x} hex, {@code 0b} binary and {@code 0o}/{@code 0} octal. */
	static Long tryLong(String s) {
		if (s == null) {
			return null;
		}
		String t = s.trim();
		if (t.isEmpty()) {
			return null;
		}
		boolean neg = false;
		if (t.startsWith("-")) {
			neg = true;
			t = t.substring(1);
		}
		else if (t.startsWith("+")) {
			t = t.substring(1);
		}
		try {
			long v;
			String lower = t.toLowerCase();
			if (lower.startsWith("0x")) {
				v = Long.parseUnsignedLong(t.substring(2), 16);
			}
			else if (lower.startsWith("0b")) {
				v = Long.parseUnsignedLong(t.substring(2), 2);
			}
			else if (lower.startsWith("0o")) {
				v = Long.parseUnsignedLong(t.substring(2), 8);
			}
			else if (t.length() > 1 && t.startsWith("0") && t.chars().allMatch(c -> c >= '0' && c <= '7')) {
				v = Long.parseUnsignedLong(t, 8);
			}
			else {
				v = Long.parseLong(t);
			}
			return neg ? -v : v;
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	static Integer tryInt(String s) {
		Long v = tryLong(s);
		if (v == null) {
			return null;
		}
		if (v > Integer.MAX_VALUE || v < Integer.MIN_VALUE) {
			return null;
		}
		return v.intValue();
	}

	static int toInt(String s, int defaultValue) {
		Integer v = tryInt(s);
		return v == null ? defaultValue : v;
	}

	static long toLong(String s, long defaultValue) {
		Long v = tryLong(s);
		return v == null ? defaultValue : v;
	}
}
