/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 *
 * Minimal, dependency-free JSON writer.
 *
 * Ghidra ships its own copy of Gson, but extension class loaders are isolated
 * from (and in some configurations ordered after) the core class loaders, so
 * relying on third party JSON libraries from an extension is a portability
 * hazard. This writer produces standard JSON with no external dependencies and
 * is covered by JsonWriterTest.
 */
package com.ghidramcp.util;

/**
 * Streaming JSON writer.
 *
 * <pre>
 * JsonWriter w = new JsonWriter();
 * w.beginObject();
 * w.name("name").value("main");
 * w.name("items").beginArray().value(1).value(2).endArray();
 * w.endObject();
 * String json = w.toString();
 * </pre>
 *
 * <p>State is tracked per nesting level (see {@link #needsComma}): a container
 * remembers whether it has already emitted a member, independent of what its
 * children did. Tracking a single flat flag is the classic bug here - the
 * child's "I just wrote a value" state leaks into the parent and makes the
 * parent think a member is still pending.
 *
 * <p>Values of type {@code double}/{@code float} that are NaN or infinite are
 * emitted as {@code null} so that the result always parses.
 */
public final class JsonWriter {

	/** One nesting level: whether the next write needs a leading comma. */
	private static final class Level {
		final boolean object;
		boolean needsComma;

		Level(boolean object) {
			this.object = object;
		}
	}

	private final StringBuilder sb = new StringBuilder(256);
	private Level[] stack = new Level[16];
	private int depth;

	public JsonWriter() {
	}

	/** Begins a new JSON object. */
	public JsonWriter beginObject() {
		startValue();
		sb.append('{');
		push(true);
		return this;
	}

	/** Ends the current JSON object. */
	public JsonWriter endObject() {
		pop(true);
		sb.append('}');
		return this;
	}

	/** Begins a new JSON array. */
	public JsonWriter beginArray() {
		startValue();
		sb.append('[');
		push(false);
		return this;
	}

	/** Ends the current JSON array. */
	public JsonWriter endArray() {
		pop(false);
		sb.append(']');
		return this;
	}

	/** Writes a member name. Only legal inside an object. */
	public JsonWriter name(String name) {
		if (depth == 0 || !stack[depth - 1].object) {
			throw new IllegalStateException("name() outside of an object");
		}
		Level level = stack[depth - 1];
		if (level.needsComma) {
			sb.append(',');
		}
		quote(name == null ? "" : name);
		sb.append(':');
		// A name was just written, so the value that follows must not add a comma
		// of its own.
		level.needsComma = false;
		return this;
	}

	public JsonWriter value(String v) {
		startValue();
		if (v == null) {
			sb.append("null");
		}
		else {
			quote(v);
		}
		return this;
	}

	public JsonWriter value(boolean v) {
		startValue();
		sb.append(v);
		return this;
	}

	public JsonWriter value(long v) {
		startValue();
		sb.append(v);
		return this;
	}

	public JsonWriter value(int v) {
		return value((long) v);
	}

	public JsonWriter value(double v) {
		startValue();
		if (Double.isNaN(v) || Double.isInfinite(v)) {
			sb.append("null");
		}
		else if (v == Math.rint(v) && Math.abs(v) < 1e15) {
			sb.append((long) v);
		}
		else {
			sb.append(v);
		}
		return this;
	}

	/** Emits an explicit JSON null. */
	public JsonWriter nullValue() {
		startValue();
		sb.append("null");
		return this;
	}

	/** Convenience: writes a named string member. */
	public JsonWriter field(String name, String v) {
		return name(name).value(v);
	}

	/** Convenience: writes a named long member. */
	public JsonWriter field(String name, long v) {
		return name(name).value(v);
	}

	/** Convenience: writes a named boolean member. */
	public JsonWriter field(String name, boolean v) {
		return name(name).value(v);
	}

	/**
	 * Convenience: writes a named member of any supported type, delegating to
	 * {@link #any(Object)}.
	 */
	public JsonWriter field(String name, Object v) {
		return name(name).any(v);
	}

	/** Serialises an arbitrary object: Map, Iterable, array, Number, Boolean, String ... */
	public JsonWriter any(Object o) {
		if (o == null) {
			return nullValue();
		}
		if (o instanceof String s) {
			return value(s);
		}
		if (o instanceof Boolean b) {
			return value(b.booleanValue());
		}
		if (o instanceof Number n) {
			return value(n.doubleValue());
		}
		if (o instanceof java.util.Map<?, ?> m) {
			beginObject();
			for (java.util.Map.Entry<?, ?> e : m.entrySet()) {
				name(String.valueOf(e.getKey()));
				any(e.getValue());
			}
			return endObject();
		}
		if (o instanceof Iterable<?> it) {
			beginArray();
			for (Object e : it) {
				any(e);
			}
			return endArray();
		}
		if (o.getClass().isArray()) {
			beginArray();
			int len = java.lang.reflect.Array.getLength(o);
			for (int i = 0; i < len; i++) {
				any(java.lang.reflect.Array.get(o, i));
			}
			return endArray();
		}
		return value(String.valueOf(o));
	}

	// ------------------------------------------------------------------ internals

	/**
	 * Emits the delimiter for a value about to be written at the current level and
	 * records that the level has now produced an element.
	 *
	 * <p>Inside an array a value may follow a previous element, so a comma is
	 * written when one is due. Inside an object this must immediately follow a
	 * member name: {@link #name(String)} has already emitted any comma and cleared
	 * the flag, so this method must not add another - and if the flag is still set,
	 * no name was written, which means the caller is building invalid JSON.
	 */
	private void startValue() {
		if (depth == 0) {
			return;
		}
		Level level = stack[depth - 1];
		if (level.object) {
			if (level.needsComma) {
				throw new IllegalStateException(
					"value written without a member name inside an object");
			}
		}
		else if (level.needsComma) {
			sb.append(',');
		}
		level.needsComma = true;
	}

	private void push(boolean object) {
		if (depth == stack.length) {
			Level[] grown = new Level[stack.length * 2];
			System.arraycopy(stack, 0, grown, 0, stack.length);
			stack = grown;
		}
		stack[depth++] = new Level(object);
	}

	/**
	 * Closes the current level.
	 *
	 * <p>The parent's "something was written here" flag was already set by
	 * {@link #startValue()} before this container was opened, so nothing needs to
	 * be restored here - the parent level object is simply discarded.
	 */
	private void pop(boolean expectObject) {
		if (depth == 0) {
			throw new IllegalStateException("unbalanced JSON writer: unexpected close");
		}
		Level level = stack[depth - 1];
		if (level.object != expectObject) {
			throw new IllegalStateException("unbalanced JSON writer: closed the wrong container");
		}
		stack[depth - 1] = null;
		depth--;
	}

	private void quote(String s) {
		sb.append('"');
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				case '\n' -> sb.append("\\n");
				case '\r' -> sb.append("\\r");
				case '\t' -> sb.append("\\t");
				case '\b' -> sb.append("\\b");
				case '\f' -> sb.append("\\f");
				default -> {
					if (c < 0x20 || c == 0x7f) {
						sb.append(String.format("\\u%04x", (int) c));
					}
					else {
						sb.append(c);
					}
				}
			}
		}
		sb.append('"');
	}

	@Override
	public String toString() {
		if (depth != 0) {
			throw new IllegalStateException("unbalanced JSON writer: " + depth +
				" container(s) left open");
		}
		return sb.toString();
	}
}
