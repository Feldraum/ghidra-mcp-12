/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.api;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.ghidramcp.util.JsonParser;

/**
 * Immutable view over one HTTP request.
 *
 * <p>Parameters may arrive in four different ways depending on the client:
 * as query string, as {@code application/x-www-form-urlencoded} body, as a raw
 * JSON object body, or (for the original GhidraMCP API) as a bare text body.
 * {@link #param(String)} hides that difference so handlers stay small.
 */
public final class ApiRequest {

	/** Upper bound on a request body, so a bad client cannot exhaust the JVM heap. */
	private static final int MAX_BODY_BYTES = 8 * 1024 * 1024;

	private final String method;
	private final String path;
	private final Map<String, String> query;
	private final Map<String, String> form;
	private final String rawBody;
	private final Map<String, Object> json;
	private final Map<String, String> pathParams = new LinkedHashMap<>();

	private ApiRequest(String method, String path, Map<String, String> query,
			Map<String, String> form, String rawBody, Map<String, Object> json) {
		this.method = method;
		this.path = path;
		this.query = query;
		this.form = form;
		this.rawBody = rawBody;
		this.json = json;
	}

	/** Builds a request from its raw HTTP parts. */
	public static ApiRequest of(String method, String path, String queryString,
			String contentType, InputStream bodyStream) throws IOException {
		return of(method, path, queryString, contentType, bodyStream, -1);
	}

	/**
	 * Builds a request from its raw HTTP parts.
	 *
	 * <p>{@code contentLength} matters: reading a request body with
	 * {@code readAllBytes()} blocks until the client closes the connection, and a
	 * GET (or a POST without a body) never does - the client is waiting for the
	 * response. That is a deadlock, not a slow request, so the body is only read
	 * when the request actually declares one. -1 means "read until EOF", which is
	 * only safe for chunked/streaming bodies.
	 */
	public static ApiRequest of(String method, String path, String queryString,
			String contentType, InputStream bodyStream, long contentLength) throws IOException {
		Map<String, String> query = parsePairs(queryString);
		String upperMethod = method == null ? "GET" : method.toUpperCase();
		boolean mayHaveBody = "POST".equals(upperMethod) || "PUT".equals(upperMethod)
			|| "PATCH".equals(upperMethod);
		String body = mayHaveBody ? readBody(bodyStream, contentLength) : null;
		Map<String, String> form = new LinkedHashMap<>();
		Map<String, Object> json = null;

		String ct = contentType == null ? "" : contentType.toLowerCase();
		if (body != null && !body.isEmpty()) {
			if (ct.contains("json") || looksLikeJson(body)) {
				try {
					Object parsed = JsonParser.parse(body);
					if (parsed instanceof Map<?, ?> m) {
						@SuppressWarnings("unchecked")
						Map<String, Object> cast = (Map<String, Object>) m;
						json = cast;
					}
				}
				catch (IllegalArgumentException e) {
					// Not JSON after all: fall through and treat it as text.
					json = null;
				}
			}
			if (json == null) {
				form = parsePairs(body);
			}
		}
		return new ApiRequest(upperMethod, path, query, form, body, json);
	}

	/** Builds a synthetic request, used by the MCP stdio bridge and tests. */
	public static ApiRequest synthetic(String path, Map<String, String> query,
			Map<String, String> form) {
		return new ApiRequest("GET", path, query == null ? Map.of() : query,
			form == null ? Map.of() : form, null, null);
	}

	private static boolean looksLikeJson(String body) {
		String t = body.trim();
		return t.startsWith("{") || t.startsWith("[");
	}

	/**
	 * Reads a request body without ever blocking on a connection whose client is
	 * waiting for the response.
	 *
	 * <p>Preferring Content-Length means the read terminates exactly at the end of
	 * the declared body; the EOF fallback only applies to chunked bodies, where the
	 * framing itself guarantees a terminator.
	 */
	private static String readBody(InputStream in, long contentLength) throws IOException {
		if (in == null || contentLength == 0) {
			return null;
		}
		if (contentLength > 0) {
			if (contentLength > MAX_BODY_BYTES) {
				throw ApiException.badRequest("request body too large (" + contentLength +
					" bytes; limit is " + MAX_BODY_BYTES + ")");
			}
			byte[] data = in.readNBytes((int) contentLength);
			return new String(data, StandardCharsets.UTF_8);
		}
		// No Content-Length: read what is already buffered rather than waiting for
		// EOF, which would deadlock against a client that is waiting for us.
		int available = in.available();
		if (available <= 0) {
			return null;
		}
		byte[] data = in.readNBytes(Math.min(available, MAX_BODY_BYTES));
		return new String(data, StandardCharsets.UTF_8);
	}

	private static Map<String, String> parsePairs(String s) {
		Map<String, String> out = new LinkedHashMap<>();
		if (s == null || s.isEmpty()) {
			return out;
		}
		for (String pair : s.split("&")) {
			if (pair.isEmpty()) {
				continue;
			}
			int eq = pair.indexOf('=');
			String k = eq < 0 ? pair : pair.substring(0, eq);
			String v = eq < 0 ? "" : pair.substring(eq + 1);
			try {
				k = URLDecoder.decode(k, StandardCharsets.UTF_8);
				v = URLDecoder.decode(v, StandardCharsets.UTF_8);
			}
			catch (IllegalArgumentException ignored) {
				// Keep the undecoded value: malformed escapes are common in the wild.
			}
			out.put(k, v);
		}
		return out;
	}

	public String method() {
		return method;
	}

	public String path() {
		return path;
	}

	public String rawBody() {
		return rawBody;
	}

	public Map<String, Object> json() {
		return json == null ? Map.of() : json;
	}

	public boolean hasJson() {
		return json != null;
	}

	/** All parameter names, across query/form/JSON. */
	public List<String> names() {
		List<String> names = new ArrayList<>(query.keySet());
		for (String k : form.keySet()) {
			if (!names.contains(k)) {
				names.add(k);
			}
		}
		for (String k : json().keySet()) {
			if (!names.contains(k)) {
				names.add(k);
			}
		}
		return names;
	}

	/**
	 * Values captured from placeholders in the matched route pattern, e.g. the
	 * address in {@code /functions/{address}}.
	 *
	 * <p>Populated by the router before the handler runs; a handler that can be
	 * reached both as {@code /functions/1234} and {@code /functions?address=1234}
	 * reads the placeholder first.
	 */
	public String pathParam(String name) {
		return pathParams.get(name);
	}

	/** The placeholder value under {@code name}, or {@code null}. */
	public Map<String, String> pathParams() {
		return pathParams;
	}

	/** Returns a copy carrying the route's captured placeholder values. */
	ApiRequest withPathParams(Map<String, String> captured) {
		ApiRequest copy = new ApiRequest(method, path, query, form, rawBody, json);
		copy.pathParams.putAll(captured);
		return copy;
	}

	/**
	 * Looks a parameter up in the route's path placeholders, the JSON body, the
	 * form body and the query string, in that order, returning {@code null} when
	 * absent.
	 */
	public String param(String name) {
		String fromPath = pathParams.get(name);
		if (fromPath != null) {
			return fromPath;
		}
		Object v = json().get(name);
		if (v != null || json().containsKey(name)) {
			return stringify(v);
		}
		String f = form.get(name);
		if (f != null) {
			return f;
		}
		return query.get(name);
	}

	/** Like {@link #param(String)} but falls back to the raw body for text-only calls. */
	public String paramOrBody(String name) {
		String v = param(name);
		if (v != null && !v.isEmpty()) {
			return v;
		}
		return rawBody == null ? null : rawBody.trim();
	}

	/** Returns the first present parameter among {@code names}, or null. */
	public String firstOf(String... names) {
		for (String n : names) {
			String v = param(n);
			if (v != null && !v.isEmpty()) {
				return v;
			}
		}
		return null;
	}

	/** Returns the first present parameter among {@code names}. */
	public String require(String... names) {
		String v = firstOf(names);
		if (v == null || v.isEmpty()) {
			throw ApiException.badRequest("missing required parameter: " + String.join("/", names));
		}
		return v;
	}

	public String param(String name, String defaultValue) {
		String v = param(name);
		return v == null || v.isEmpty() ? defaultValue : v;
	}

	public int intParam(String name, int defaultValue) {
		return Numbers.toInt(param(name), defaultValue);
	}

	/** Returns the first alias that parses as an integer, else {@code defaultValue}. */
	public int intParam(String[] aliases, int defaultValue) {
		for (String n : aliases) {
			Integer v = Numbers.tryInt(param(n));
			if (v != null) {
				return v;
			}
		}
		return defaultValue;
	}

	public long longParam(String name, long defaultValue) {
		return Numbers.toLong(param(name), defaultValue);
	}

	public boolean boolParam(String name, boolean defaultValue) {
		String v = param(name);
		if (v == null || v.isEmpty()) {
			return defaultValue;
		}
		return v.equalsIgnoreCase("true") || v.equals("1") || v.equalsIgnoreCase("yes")
				|| v.equalsIgnoreCase("on");
	}

	/** Parsed offset/limit pair, clamped to sane bounds for very large programs. */
	public Paging paging(int defaultLimit) {
		int offset = Math.max(0, intParam("offset", 0));
		int limit = intParam("limit", defaultLimit);
		if (limit <= 0) {
			limit = defaultLimit;
		}
		return new Paging(offset, Math.min(limit, 1_000_000));
	}

	/** Debug representation that never leaks a huge body into logs. */
	@Override
	public String toString() {
		String b = rawBody == null ? "" : rawBody;
		if (b.length() > 200) {
			b = b.substring(0, 200) + "...";
		}
		return method + " " + path + " query=" + query + " form=" + form
			+ (b.isEmpty() ? "" : " body=" + b);
	}

	private static String stringify(Object v) {
		if (v == null) {
			return null;
		}
		if (v instanceof String s) {
			return s;
		}
		if (v instanceof Double d) {
			if (d == Math.rint(d) && Math.abs(d) < 1e15) {
				return String.valueOf(d.longValue());
			}
			return String.valueOf(d);
		}
		if (v instanceof List<?> l) {
			StringBuilder sb = new StringBuilder();
			for (Object o : l) {
				if (sb.length() > 0) {
					sb.append(',');
				}
				sb.append(stringify(o));
			}
			return sb.toString();
		}
		return String.valueOf(v);
	}

	/** Immutable offset/limit pair. */
	public record Paging(int offset, int limit) {
		public <T> List<T> slice(List<T> items) {
			if (items == null || items.isEmpty()) {
				return Collections.emptyList();
			}
			if (offset >= items.size()) {
				return Collections.emptyList();
			}
			int end = Math.min(items.size(), offset + limit);
			return items.subList(offset, end);
		}
	}
}
