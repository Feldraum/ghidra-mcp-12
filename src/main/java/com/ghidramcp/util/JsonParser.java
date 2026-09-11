/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 *
 * Minimal, dependency-free JSON reader (RFC 8259 subset, plus lenient handling
 * of the extensions LLM clients actually emit: unquoted NaN/Infinity,
 * leading/trailing whitespace and single trailing commas).
 */
package com.ghidramcp.util;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Parses a JSON document into {@code Map<String,Object>}, {@code List<Object>}, String, Double, Boolean or null. */
public final class JsonParser {

	private final String src;
	private int pos;

	private JsonParser(String src) {
		this.src = src;
	}

	/** Parses {@code text}; throws {@link IllegalArgumentException} on malformed input. */
	public static Object parse(String text) {
		if (text == null) {
			throw new IllegalArgumentException("json input is null");
		}
		JsonParser p = new JsonParser(text);
		p.skipWs();
		Object v = p.parseValue();
		p.skipWs();
		if (p.pos < p.src.length()) {
			throw p.error("trailing content");
		}
		return v;
	}

	/** Parses {@code text} and requires an object at the root. */
	@SuppressWarnings("unchecked")
	public static Map<String, Object> parseObject(String text) {
		Object v = parse(text);
		if (!(v instanceof Map)) {
			throw new IllegalArgumentException("expected a JSON object at the root");
		}
		return (Map<String, Object>) v;
	}

	private Object parseValue() {
		if (pos >= src.length()) {
			throw error("unexpected end of input");
		}
		char c = src.charAt(pos);
		return switch (c) {
			case '{' -> parseObjectValue();
			case '[' -> parseArray();
			case '"' -> parseString();
			case 't', 'f' -> parseBoolean();
			case 'n' -> parseNull();
			default -> parseNumber();
		};
	}

	private Map<String, Object> parseObjectValue() {
		expect('{');
		Map<String, Object> map = new LinkedHashMap<>();
		skipWs();
		if (peek() == '}') {
			pos++;
			return map;
		}
		while (true) {
			skipWs();
			if (peek() == '}') { // tolerate trailing comma
				pos++;
				return map;
			}
			String key = parseString();
			skipWs();
			expect(':');
			skipWs();
			map.put(key, parseValue());
			skipWs();
			char c = peek();
			if (c == ',') {
				pos++;
				continue;
			}
			if (c == '}') {
				pos++;
				return map;
			}
			throw error("expected ',' or '}'");
		}
	}

	private List<Object> parseArray() {
		expect('[');
		List<Object> list = new java.util.ArrayList<>();
		skipWs();
		if (peek() == ']') {
			pos++;
			return list;
		}
		while (true) {
			skipWs();
			if (peek() == ']') {
				pos++;
				return list;
			}
			list.add(parseValue());
			skipWs();
			char c = peek();
			if (c == ',') {
				pos++;
				continue;
			}
			if (c == ']') {
				pos++;
				return list;
			}
			throw error("expected ',' or ']'");
		}
	}

	private String parseString() {
		expect('"');
		StringBuilder out = new StringBuilder();
		while (true) {
			if (pos >= src.length()) {
				throw error("unterminated string");
			}
			char c = src.charAt(pos++);
			if (c == '"') {
				return out.toString();
			}
			if (c != '\\') {
				out.append(c);
				continue;
			}
			if (pos >= src.length()) {
				throw error("unterminated escape");
			}
			char e = src.charAt(pos++);
			switch (e) {
				case '"' -> out.append('"');
				case '\\' -> out.append('\\');
				case '/' -> out.append('/');
				case 'b' -> out.append('\b');
				case 'f' -> out.append('\f');
				case 'n' -> out.append('\n');
				case 'r' -> out.append('\r');
				case 't' -> out.append('\t');
				case 'u' -> {
					if (pos + 4 > src.length()) {
						throw error("bad \\u escape");
					}
					String hex = src.substring(pos, pos + 4);
					pos += 4;
					out.append((char) Integer.parseInt(hex, 16));
				}
				default -> throw error("bad escape '\\" + e + "'");
			}
		}
	}

	private Boolean parseBoolean() {
		if (src.startsWith("true", pos)) {
			pos += 4;
			return Boolean.TRUE;
		}
		if (src.startsWith("false", pos)) {
			pos += 5;
			return Boolean.FALSE;
		}
		throw error("invalid literal");
	}

	private Object parseNull() {
		if (src.startsWith("null", pos)) {
			pos += 4;
			return null;
		}
		// Lenient: bare NaN / Infinity tokens
		if (src.startsWith("NaN", pos)) {
			pos += 3;
			return Double.NaN;
		}
		if (src.startsWith("Infinity", pos)) {
			pos += 8;
			return Double.POSITIVE_INFINITY;
		}
		throw error("invalid literal");
	}

	private Double parseNumber() {
		int start = pos;
		if (peek() == '-' || peek() == '+') {
			pos++;
		}
		while (pos < src.length()) {
			char c = src.charAt(pos);
			if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
				pos++;
			}
			else {
				break;
			}
		}
		String num = src.substring(start, pos);
		if (num.isEmpty()) {
			throw error("invalid number");
		}
		try {
			return Double.valueOf(num);
		}
		catch (NumberFormatException ex) {
			throw error("invalid number '" + num + "'");
		}
	}

	private char peek() {
		if (pos >= src.length()) {
			throw error("unexpected end of input");
		}
		return src.charAt(pos);
	}

	private void expect(char c) {
		if (pos >= src.length() || src.charAt(pos) != c) {
			throw error("expected '" + c + "'");
		}
		pos++;
	}

	private void skipWs() {
		while (pos < src.length()) {
			char c = src.charAt(pos);
			if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
				pos++;
			}
			else {
				break;
			}
		}
	}

	private IllegalArgumentException error(String msg) {
		int from = Math.max(0, pos - 30);
		int to = Math.min(src.length(), pos + 30);
		return new IllegalArgumentException(
			"JSON parse error at offset " + pos + ": " + msg + " [..." + src.substring(from, to) + "...]");
	}
}
