/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 *
 * Ghidra plugin entry point: builds the route table and owns the HTTP server.
 */
package com.ghidramcp;

import java.io.IOException;
import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

import com.ghidramcp.api.ApiContext;
import com.ghidramcp.api.Router;
import com.ghidramcp.core.McpHttpServer;
import com.ghidramcp.core.ProgramService;

/**
 * The Ghidra-side half of the MCP bridge.
 *
 * <p>Registers an option category so the listening port can be configured from
 * {@code Edit > Tool Options > GhidraMCP12} and starts the embedded HTTP server.
 * All Ghidra knowledge lives behind {@link Router} routes, so the endpoint surface
 * is defined in exactly one place ({@code GhidraMCPRoutes}).
 */
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ghidra.app.DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "MCP bridge (HTTP/JSON server for AI agents)",
	description = "Runs an embedded HTTP/JSON server that exposes programs, functions, symbols, " +
		"references, decompilation, disassembly, data, types and analysis operations to Model " +
		"Context Protocol (MCP) clients such as Claude Desktop, Claude Code and Cursor. " +
		"Configure the port under Edit > Tool Options > GhidraMCP12."
)
public class GhidraMCPPlugin extends Plugin {

	public static final String OPTION_CATEGORY = "GhidraMCP12";
	public static final String OPT_PORT = "Server Port";
	public static final String OPT_BIND = "Bind Address";
	public static final String OPT_ALLOW_REMOTE = "Allow Remote Connections";
	public static final String OPT_AUTOSTART = "Start Server On Launch";
	public static final String OPT_DEBUG_LOG = "Debug Log File";

	public static final int DEFAULT_PORT = 8192;
	private static final String VERSION = "1.0.0";

	private ProgramService programs;
	private ApiContext context;
	private Router router;
	private McpHttpServer server;

	public GhidraMCPPlugin(PluginTool tool) {
		super(tool);
		Msg.info(this, "GhidraMCP12 loading...");

		registerOptions();

		this.programs = new ProgramService(tool);
		this.context = new ApiContext(programs, tool, VERSION);
		this.context.setStatsSupplier(this::serverStats);
		this.router = GhidraMCPRoutes.build(context);

		if (readOption(OPT_AUTOSTART, true)) {
			try {
				startServer();
			}
			catch (IOException e) {
				Msg.error(this, "GhidraMCP12: could not start the HTTP server on port " +
					readOption(OPT_PORT, DEFAULT_PORT) + ": " + e.getMessage(), e);
			}
		}
		else {
			Msg.info(this, "GhidraMCP12: server autostart disabled; use the plugin's " +
				"\"Start MCP Server\" action or restart with the option enabled");
		}
		Msg.info(this, "GhidraMCP12 loaded (" + router.size() + " endpoints)");
	}

	private void registerOptions() {
		Options options = tool.getOptions(OPTION_CATEGORY);
		HelpLocation help = new HelpLocation("GhidraMCP12", "GhidraMCP12");
		options.registerOption(OPT_PORT, DEFAULT_PORT, help,
			"TCP port for the MCP bridge HTTP server. Changes take effect on restart.");
		options.registerOption(OPT_BIND, "127.0.0.1", help,
			"Interface to bind. 127.0.0.1 keeps the bridge local to this machine.");
		options.registerOption(OPT_ALLOW_REMOTE, false, help,
			"Allow binding to a non-loopback interface. SECURITY: anyone who can reach the " +
				"port can read and modify your programs.");
		options.registerOption(OPT_AUTOSTART, true, help,
			"Start the MCP bridge HTTP server when this plugin loads.");
		options.registerOption(OPT_DEBUG_LOG, "", help,
			"Optional path to a file that receives a one-line trace of every request " +
				"and response. Leave empty for normal operation; useful when an agent " +
				"reports a call that never returns.");
	}

	private <T> T readOption(String name, T fallback) {
		Options options = tool.getOptions(OPTION_CATEGORY);
		if (fallback instanceof Integer) {
			@SuppressWarnings("unchecked")
			T v = (T) Integer.valueOf(options.getInt(name, (Integer) fallback));
			return v;
		}
		if (fallback instanceof Boolean) {
			@SuppressWarnings("unchecked")
			T v = (T) Boolean.valueOf(options.getBoolean(name, (Boolean) fallback));
			return v;
		}
		@SuppressWarnings("unchecked")
		T v = (T) options.getString(name, String.valueOf(fallback));
		return v;
	}

	/** Starts the HTTP server (no-op when already running). */
	public synchronized void startServer() throws IOException {
		if (server != null && server.isRunning()) {
			return;
		}
		McpHttpServer.Config config = new McpHttpServer.Config();
		config.port = readOption(OPT_PORT, DEFAULT_PORT);
		config.bindAddress = readOption(OPT_BIND, "127.0.0.1");
		config.allowRemote = readOption(OPT_ALLOW_REMOTE, false);
		config.debugLogFile = readOption(OPT_DEBUG_LOG, "");
		server = new McpHttpServer(router, config);
		server.start();
		Msg.info(this, "GhidraMCP12 HTTP server listening on http://" +
			config.bindAddress + ":" + server.port() + "/");
		Msg.info(this, "GhidraMCP12 endpoint index: http://" + config.bindAddress + ":" +
			server.port() + "/_tools");
	}

	/** Stops the HTTP server if it is running. */
	public synchronized void stopServer() {
		if (server != null) {
			server.stop();
			Msg.info(this, "GhidraMCP12 HTTP server stopped");
		}
	}

	/** Snapshot of server state, surfaced through {@code /_health}. */
	public Map<String, Object> serverStats() {
		Map<String, Object> m = new LinkedHashMap<>();
		if (server != null) {
			m.putAll(server.stats());
		}
		else {
			m.put("running", false);
			m.put("port", readOption(OPT_PORT, DEFAULT_PORT));
		}
		m.put("version", VERSION);
		m.put("plugin", "GhidraMCP12");
		m.put("bindAddress", readOption(OPT_BIND, "127.0.0.1"));
		m.put("allowRemote", readOption(OPT_ALLOW_REMOTE, false));
		return m;
	}

	public ApiContext context() {
		return context;
	}

	public Router router() {
		return router;
	}

	/** Utility used by the plugin's error messages to show the reachable URL. */
	public String describeUrl() {
		if (server == null || !server.isRunning()) {
			return "(not running)";
		}
		String host = server.address();
		if (host == null || host.isBlank() || "0.0.0.0".equals(host)) {
			try {
				host = InetAddress.getLoopbackAddress().getHostAddress();
			}
			catch (Exception e) {
				host = "127.0.0.1";
			}
		}
		return "http://" + host + ":" + server.port() + "/";
	}

	@Override
	public void dispose() {
		stopServer();
		super.dispose();
	}
}
