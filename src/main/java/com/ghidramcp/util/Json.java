/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.util;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Helpers for turning Java values into JSON without pulling a JSON library into
 * the extension class loader.
 */
public final class Json {

	private Json() {
	}

	/** Serialises {@code value} (Map/Iterable/array/Number/Boolean/String) to JSON. */
	public static String serialize(Object value) {
		JsonWriter w = new JsonWriter();
		w.any(value);
		return w.toString();
	}

	/**
	 * Serialises a complete (already fully materialised) listing as a page.
	 *
	 * <p>There is deliberately no overload that accepts an already-sliced list:
	 * the {@code truncated} flag has to be computed against the total, so callers
	 * must supply it. Routing every paginated endpoint through
	 * {@link Page#of} keeps that honest.
	 */
	public static String page(List<?> items, int total, int offset, int limit) {
		int size = items == null ? 0 : items.size();
		JsonWriter w = new JsonWriter();
		w.beginObject();
		w.field("count", total);
		w.field("offset", offset);
		w.field("limit", limit);
		w.field("returned", size);
		w.field("truncated", offset + size < total);
		w.name("items").any(items == null ? List.of() : items);
		w.endObject();
		return w.toString();
	}

	/** Simple list envelope without pagination metadata. */
	public static String list(List<?> items) {
		JsonWriter w = new JsonWriter();
		w.beginObject();
		w.field("count", items == null ? 0 : items.size());
		w.name("items").any(items == null ? List.of() : items);
		w.endObject();
		return w.toString();
	}

	/** Standard error envelope used by the HTTP layer. */
	public static String errorBody(int status, String message) {
		JsonWriter w = new JsonWriter();
		w.beginObject();
		w.field("success", false);
		w.field("status", status);
		w.field("error", message);
		w.endObject();
		return w.toString();
	}

	/** Standard success envelope for mutating endpoints. */
	public static String okBody(String message, Object extra) {
		JsonWriter w = new JsonWriter();
		w.beginObject();
		w.field("success", true);
		w.field("message", message);
		if (extra instanceof Map<?, ?> m) {
			for (Map.Entry<?, ?> e : m.entrySet()) {
				w.name(String.valueOf(e.getKey())).any(e.getValue());
			}
		}
		w.endObject();
		return w.toString();
	}

	/** Truncates a collection description defensively for log lines. */
	public static int sizeOf(Collection<?> c) {
		return c == null ? 0 : c.size();
	}
}
