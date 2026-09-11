/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.core;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

import com.ghidramcp.api.ApiException;
import com.ghidramcp.api.ApiRequest;
import com.ghidramcp.api.Router;
import com.ghidramcp.util.ApiResponse;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * The embedded HTTP/JSON server.
 *
 * <p>Uses {@code com.sun.net.httpserver}, part of the JDK ({@code jdk.httpserver}
 * module), so the extension needs no third party web framework. The server
 * binds to the loopback interface by default: exposing a reverse engineering
 * session to the network is a decision the user should make explicitly.
 */
public final class McpHttpServer {

	/** Configuration resolved from tool options / command line / script args. */
	public static final class Config {
		public int port = 8192;
		public String bindAddress = "127.0.0.1";
		public boolean allowRemote = false;
		public boolean quiet = false;
		/**
		 * Optional path for a plain-text trace of every request. Ghidra's log is
		 * awkward to read from outside the GUI, and the trace is the quickest way to
		 * see where a request stopped, so the plugin exposes it as a tool option and
		 * the test harness passes it directly.
		 */
		public String debugLogFile = "";

		public Config copy() {
			Config c = new Config();
			c.port = port;
			c.bindAddress = bindAddress;
			c.allowRemote = allowRemote;
			c.quiet = quiet;
			c.debugLogFile = debugLogFile;
			return c;
		}
	}

	private final Router router;
	private final Config config;
	private final AtomicLong requestCount = new AtomicLong();
	private final AtomicLong errorCount = new AtomicLong();

	private HttpServer server;
	private ExecutorService executor;
	private String boundAddress;

	public McpHttpServer(Router router, Config config) {
		this.router = router;
		this.config = config.copy();
	}

	/** Starts the server. Idempotent: a second call is a no-op while running. */
	public synchronized void start() throws IOException {
		if (server != null) {
			return;
		}
		String host = config.bindAddress;
		if (host == null || host.isBlank()) {
			host = config.allowRemote ? "0.0.0.0" : "127.0.0.1";
		}
		if (!config.allowRemote && !isLoopback(host)) {
			throw new IOException("refusing to bind " + host +
				": set allowRemote=true (and understand the risk) to expose the bridge");
		}

		server = HttpServer.create(new InetSocketAddress(host, config.port), 64);
		boundAddress = server.getAddress().getAddress().getHostAddress();
		executor = Executors.newFixedThreadPool(8, daemonFactory());
		server.setExecutor(executor);
		server.createContext("/", this::dispatch);
		server.start();
	}

	private static ThreadFactory daemonFactory() {
		AtomicLong n = new AtomicLong();
		return r -> {
			Thread t = new Thread(r, "GhidraMCP12-http-" + n.incrementAndGet());
			t.setDaemon(true);
			return t;
		};
	}

	private static boolean isLoopback(String host) {
		if ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host)) {
			return true;
		}
		try {
			return InetAddress.getByName(host).isLoopbackAddress();
		}
		catch (Exception e) {
			return false;
		}
	}

	/** Stops the server and releases the port. */
	public synchronized void stop() {
		if (server != null) {
			server.stop(1);
			server = null;
		}
		if (executor != null) {
			executor.shutdownNow();
			executor = null;
		}
	}

	public synchronized boolean isRunning() {
		return server != null;
	}

	public int port() {
		if (server != null) {
			return server.getAddress().getPort();
		}
		return config.port;
	}

	public String address() {
		return boundAddress;
	}

	public long requestCount() {
		return requestCount.get();
	}

	public long errorCount() {
		return errorCount.get();
	}

	// ------------------------------------------------------------------ dispatch

	private void dispatch(HttpExchange exchange) {
		requestCount.incrementAndGet();
		long started = System.nanoTime();
		debug("--> " + exchange.getRequestMethod() + " " + exchange.getRequestURI());
		ApiResponse response;
		try {
			String path = exchange.getRequestURI().getPath();
			debug("    parsing request (contentLength=" + contentLength(exchange) + ")");
			ApiRequest request = ApiRequest.of(
				exchange.getRequestMethod(),
				path,
				exchange.getRequestURI().getRawQuery(),
				firstHeader(exchange, "Content-Type"),
				exchange.getRequestBody(),
				contentLength(exchange));
			debug("    dispatching to router");
			response = router.handle(exchange.getRequestMethod(), path, request);
			debug("    router returned");
		}
		catch (ApiException e) {
			errorCount.incrementAndGet();
			response = ApiResponse.status(e.status(), e.getMessage());
		}
		catch (IllegalArgumentException e) {
			errorCount.incrementAndGet();
			response = ApiResponse.badRequest(e.getMessage());
		}
		catch (Throwable t) {
			errorCount.incrementAndGet();
			response = ApiResponse.serverError(describe(t));
			debug("    handler threw: " + t);
			if (!config.quiet) {
				logError("MCP bridge request failed: " + exchange.getRequestURI(), t);
			}
		}

		debug("<-- " + response.status() + " " + response.body().length() + " bytes: " +
			preview(response.body()));
		try {
			send(exchange, response, started);
		}
		catch (Throwable e) {
			debug("    send failed: " + e);
			exchange.close();
		}
	}

	/**
	 * Logs to Ghidra's log without ever letting logging itself break a request.
	 *
	 * <p>{@code Msg.error} walks the log configuration, which can throw while the
	 * plugin is still initialising; an exception escaping here would abort the
	 * request before any response bytes are written, which is the worst possible
	 * failure mode for a bridge.
	 */
	private void logError(String message, Throwable t) {
		try {
			ghidra.util.Msg.error(this, message, t);
		}
		catch (Throwable ignored) {
			// Diagnostics must never be able to kill a request.
		}
	}

	/** First part of a body, for the debug trace. */
	private static String preview(String body) {
		if (body == null) {
			return "";
		}
		String flat = body.replace('\n', ' ').replace('\r', ' ');
		return flat.length() <= 300 ? flat : flat.substring(0, 300) + "...";
	}

	/** Appends one line to the optional debug trace file. */
	private void debug(String message) {
		if (config.debugLogFile == null || config.debugLogFile.isBlank()) {
			return;
		}
		try {
			java.nio.file.Files.writeString(java.nio.file.Path.of(config.debugLogFile),
				message + System.lineSeparator(),
				java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
		}
		catch (Throwable ignored) {
			// Tracing is best effort.
		}
	}

	private static String describe(Throwable t) {
		String message = t.getMessage();
		if (message == null || message.isBlank()) {
			message = t.getClass().getName();
		}
		return message;
	}

	private static String firstHeader(HttpExchange exchange, String name) {
		java.util.List<String> values = exchange.getRequestHeaders().get(name);
		return values == null || values.isEmpty() ? null : values.get(0);
	}

	/** Declared body length, or -1 when the request carries no Content-Length. */
	private static long contentLength(HttpExchange exchange) {
		String value = firstHeader(exchange, "Content-Length");
		if (value == null || value.isBlank()) {
			return -1;
		}
		try {
			return Long.parseLong(value.trim());
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}

	private void send(HttpExchange exchange, ApiResponse response, long startedNanos)
			throws IOException {
		byte[] bytes = response.body().getBytes(StandardCharsets.UTF_8);
		var headers = exchange.getResponseHeaders();
		headers.set("Content-Type", response.contentType());
		headers.set("Cache-Control", "no-store");
		// Agents sometimes run through a local proxy; permissive CORS keeps that
		// working and is safe because the default bind is loopback only.
		headers.set("Access-Control-Allow-Origin", "*");
		headers.set("Access-Control-Allow-Headers", "Content-Type");
		headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

		if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
			exchange.sendResponseHeaders(204, -1);
			exchange.close();
			return;
		}

		exchange.sendResponseHeaders(response.status(), bytes.length == 0 ? -1 : bytes.length);
		debug("    headers sent (" + bytes.length + " byte body)");
		if (bytes.length > 0) {
			try (OutputStream os = exchange.getResponseBody()) {
				os.write(bytes);
			}
		}
		else {
			exchange.close();
		}
		debug("    body written");
		long elapsedMs = (System.nanoTime() - startedNanos) / 1_000_000;
		if (config.debugLogFile != null && !config.debugLogFile.isBlank()) {
			debug("    sent in " + elapsedMs + "ms");
		}
		else {
			ghidra.util.Msg.trace(this, "served " + exchange.getRequestURI() + " in " + elapsedMs + "ms");
		}
	}

	/** Snapshot of runtime state, used by the health endpoint. */
	public Map<String, Object> stats() {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("running", isRunning());
		m.put("port", port());
		m.put("address", address());
		m.put("requests", requestCount.get());
		m.put("errors", errorCount.get());
		m.put("endpoints", router.size());
		return m;
	}
}
