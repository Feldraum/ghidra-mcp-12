/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.api;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import com.ghidramcp.util.ApiResponse;

/**
 * A hand-rolled router.
 *
 * <p>An embedded HTTP server is a small enough surface that a couple of hundred
 * lines of routing code is easier to audit than adding a web framework to an
 * extension's class loader. Routes are also self-documenting: every route
 * carries the metadata used to generate {@code /_tools}, which is what the MCP
 * layer (and curious humans) consume.
 */
public final class Router {

	/** One registered route. */
	public record Route(String method, String path, String summary, String category,
			ApiHandler handler) {
	}

	/** Handles one decoded request. */
	@FunctionalInterface
	public interface ApiHandler {
		ApiResponse handle(ApiRequest request) throws Exception;
	}

	/**
	 * A route whose path contains {@code {placeholder}} segments.
	 *
	 * <p>Kept separate from the exact-match map so a literal route such as
	 * {@code /functions/by-address} always wins over {@code /functions/{address}}.
	 */
	private record PatternRoute(String method, String pattern, java.util.regex.Pattern regex,
			List<String> names, String summary, String category, ApiHandler handler) {

		/** Returns the captured placeholders, or null when the path does not match. */
		Map<String, String> match(String path) {
			java.util.regex.Matcher m = regex.matcher(path);
			if (!m.matches()) {
				return null;
			}
			Map<String, String> captured = new LinkedHashMap<>();
			for (int i = 0; i < names.size(); i++) {
				captured.put(names.get(i), m.group(i + 1));
			}
			return captured;
		}
	}

	private final Map<String, Route> routes = new TreeMap<>();
	private final List<PatternRoute> patterns = new ArrayList<>();

	/** Registers a JSON-returning GET route. */
	public Router get(String path, String category, String summary, ApiHandler handler) {
		return route("GET", path, category, summary, handler);
	}

	/** Registers a JSON-returning POST route. */
	public Router post(String path, String category, String summary, ApiHandler handler) {
		return route("POST", path, category, summary, handler);
	}

	/**
	 * Registers a route reachable with either verb.
	 *
	 * <p>Read-only helpers are exposed this way so that they keep working with the
	 * original GhidraMCP Python client, which issues GET for some calls and POST
	 * for others, and with agents that reach for POST whenever they are sending
	 * parameters.
	 */
	public Router any(String path, String category, String summary, ApiHandler handler) {
		route("GET", path, category, summary, handler);
		route("POST", path, category, summary, handler);
		return this;
	}

	/**
	 * Registers a read-only lookup that takes parameters, reachable by either verb.
	 *
	 * <p>Same as {@link #any} but named to make the intent obvious at the call
	 * site: this endpoint reads state and is safe to retry, it just happens to
	 * need arguments.
	 */
	public Router lookup(String path, String category, String summary, ApiHandler handler) {
		return any(path, category, summary, handler);
	}

	public Router route(String method, String path, String category, String summary,
			ApiHandler handler) {
		String methodUpper = method.toUpperCase();
		String normalized = normalize(path);
		if (normalized.contains("{")) {
			patterns.add(compilePattern(methodUpper, normalized, category, summary, handler));
			return this;
		}
		String key = key(methodUpper, normalized);
		if (routes.containsKey(key)) {
			throw new IllegalStateException("duplicate route: " + method + " " + path);
		}
		routes.put(key, new Route(methodUpper, normalized, summary, category, handler));
		return this;
	}

	/** Turns {@code /functions/{address}} into a regex plus the placeholder names. */
	private static PatternRoute compilePattern(String method, String path, String category,
			String summary, ApiHandler handler) {
		List<String> names = new ArrayList<>();
		StringBuilder regex = new StringBuilder("^");
		for (String segment : path.split("/")) {
			if (segment.isEmpty()) {
				continue;
			}
			regex.append('/');
			if (segment.startsWith("{") && segment.endsWith("}")) {
				String name = segment.substring(1, segment.length() - 1);
				names.add(name);
				// Addresses and names both appear here, so capture one path segment
				// without assuming a format.
				regex.append("([^/]+)");
			}
			else {
				regex.append(java.util.regex.Pattern.quote(segment));
			}
		}
		regex.append("$");
		return new PatternRoute(method, path, java.util.regex.Pattern.compile(regex.toString()),
			List.copyOf(names), summary, category, handler);
	}

	public boolean isEmpty() {
		return routes.isEmpty() && patterns.isEmpty();
	}

	/** Number of registered endpoints, including placeholder patterns. */
	public int size() {
		return routes.size() + patterns.size();
	}

	/** All registered routes, ordered by path then method. */
	public List<Route> all() {
		List<Route> list = new ArrayList<>(routes.values());
		for (PatternRoute pr : patterns) {
			list.add(new Route(pr.method(), pr.pattern(), pr.summary(), pr.category(),
				pr.handler()));
		}
		list.sort(Comparator.comparing(Route::path).thenComparing(Route::method));
		return list;
	}

	/** Distinct categories, in registration order. */
	public Set<String> categories() {
		Set<String> out = new LinkedHashSet<>();
		for (Route r : all()) {
			out.add(r.category());
		}
		return out;
	}

	/**
	 * Resolves and runs a route.
	 *
	 * <p>Resolution order is exact match first, then the placeholder patterns
	 * ({@code /functions/{address}}). Exact routes win so that a literal path such
	 * as {@code /functions/by-address} is never shadowed by {@code /functions/{x}}.
	 *
	 * <p>A POST is allowed to fall back to a GET-only route. MCP clients are
	 * inconsistent about verbs, and every GET route here is a read, so accepting
	 * the POST is both harmless (no route has different behaviour per verb - the
	 * few that could are registered with {@link #any}) and much friendlier than a
	 * 405 that an agent will not know how to recover from.
	 *
	 * @throws ApiException with status 404 when no route matches. The HTTP layer
	 *   converts that into a JSON error body.
	 */
	public ApiResponse handle(String method, String path, ApiRequest request) throws Exception {
		String normalized = normalize(path);
		String upper = method == null ? "GET" : method.toUpperCase();

		Route r = routes.get(key(upper, normalized));
		if (r == null && "POST".equals(upper)) {
			r = routes.get(key("GET", normalized));
		}
		if (r == null && "GET".equals(upper)) {
			r = routes.get(key("POST", normalized));
		}
		if (r != null) {
			return r.handler().handle(request);
		}

		// Placeholder patterns, e.g. /functions/{address}. The concrete request
		// carries the captured value so handlers read it like any other parameter.
		for (PatternRoute pr : patterns) {
			if (!pr.method().equals(upper) && !pr.method().equals("ANY")) {
				continue;
			}
			Map<String, String> captured = pr.match(normalized);
			if (captured != null) {
				return pr.handler().handle(request.withPathParams(captured));
			}
		}

		throw ApiException.notFound("unknown endpoint: " + upper + " " + path);
	}

	/** Registers the router's own introspection endpoint. */
	public Router registerIntrospection() {
		get("/_tools", "meta", "List every bridge endpoint with its parameters", req -> {
			Map<String, Object> byCategory = new LinkedHashMap<>();
			for (String category : categories()) {
				List<Object> entries = new ArrayList<>();
				for (Route r : all()) {
					if (!r.category().equals(category)) {
						continue;
					}
					Map<String, Object> e = new LinkedHashMap<>();
					e.put("method", r.method());
					e.put("path", r.path());
					e.put("summary", r.summary());
					entries.add(e);
				}
				byCategory.put(category, entries);
			}
			Map<String, Object> root = new LinkedHashMap<>();
			root.put("endpointCount", routes.size());
			root.put("categories", byCategory);
			return ApiResponse.json(root);
		});
		return this;
	}

	private static String key(String method, String path) {
		return (method == null ? "GET" : method.toUpperCase()) + " " + normalize(path);
	}

	static String normalize(String path) {
		if (path == null || path.isEmpty()) {
			return "/";
		}
		String p = path;
		int q = p.indexOf('?');
		if (q >= 0) {
			p = p.substring(0, q);
		}
		if (!p.startsWith("/")) {
			p = "/" + p;
		}
		while (p.length() > 1 && p.endsWith("/")) {
			p = p.substring(0, p.length() - 1);
		}
		return p;
	}
}
