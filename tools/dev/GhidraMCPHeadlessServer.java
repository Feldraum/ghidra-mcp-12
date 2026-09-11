// GhidraMCP12 - DEVELOPMENT-ONLY headless test fixture. NOT part of the plugin.
//
// The plugin is a GUI tool: it is enabled from File > Configure > Developer and
// serves the bridge for as long as Ghidra is open. This script exists purely so
// tools/e2e.ps1 can exercise the plugin's code paths in CI or on a machine with
// no display - it is not shipped in the extension zip and is not a supported way
// to use the plugin.
//
// It starts the same GhidraMCPRoutes router against a program supplied by
// analyzeHeadless, which is exactly what the plugin does, minus the GUI:
//
//   analyzeHeadless <projectDir> <projectName> -import <binary> \
//       -scriptPath tools/dev \
//       -postScript GhidraMCPHeadlessServer.java [port] [runSeconds] \
//                    [bindAddress] [allowRemote] [debugLogFile]
//
// Examples:
//   ... -postScript GhidraMCPHeadlessServer.java 8192 60
//   ... -postScript GhidraMCPHeadlessServer.java 8192 0 0.0.0.0 true C:\temp\mcp.log
//
// Arguments:
//   port         TCP port to listen on (default 8192)
//   runSeconds   how long to keep the server alive; 0 blocks forever (default 0)
//   bindAddress  interface to bind (default 127.0.0.1)
//   allowRemote  "true" to permit binding a non-loopback interface
//   debugLogFile optional file to append a request/response trace to
//
// A running server (rather than one that returns immediately) is the point: a
// script that exits would let analyzeHeadless shut down the JVM and close the
// port. Press Ctrl-C, or pass runSeconds, to stop it.
//
//@category GhidraMCP12

import com.ghidramcp.GhidraMCPRoutes;
import com.ghidramcp.api.ApiContext;
import com.ghidramcp.api.Router;
import com.ghidramcp.core.McpHttpServer;
import com.ghidramcp.core.ProgramService;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

public class GhidraMCPHeadlessServer extends GhidraScript {

	private McpHttpServer server;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		int port = args.length > 0 ? parseInt(args[0], 8192) : 8192;
		int runSeconds = args.length > 1 ? parseInt(args[1], 0) : 0;
		String bind = args.length > 2 ? args[2] : "127.0.0.1";
		boolean allowRemote = args.length > 3 && Boolean.parseBoolean(args[3]);

		Program program = currentProgram;
		if (program == null) {
			println("GhidraMCP12: WARNING - no program is loaded in this headless session.");
			println("GhidraMCP12: the bridge will start but will report 'no program is open'.");
			println("GhidraMCP12: import a binary, or pass -postScript with -import.");
		}
		else {
			println("GhidraMCP12: serving program " + program.getName() +
				" (" + program.getLanguageID() + ")");
		}

		ProgramService programs = ProgramService.headless(program);
		programs.setLabel("headless");
		ApiContext ctx = new ApiContext(programs, null, "1.0.0");

		Router router = GhidraMCPRoutes.build(ctx);

		McpHttpServer.Config config = new McpHttpServer.Config();
		config.port = port;
		config.bindAddress = bind;
		config.allowRemote = allowRemote;
		if (args.length > 4 && args[4] != null && !args[4].isBlank() && !"none".equals(args[4])) {
			config.debugLogFile = args[4];
		}

		server = new McpHttpServer(router, config);
		server.start();

		String url = "http://" + (allowRemote && !"127.0.0.1".equals(bind)
			? (server.address() == null ? bind : server.address()) : "127.0.0.1") +
			":" + server.port();
		println("GhidraMCP12: HTTP server listening on " + url + "/");
		println("GhidraMCP12: endpoint index at " + url + "/_tools");
		println("GhidraMCP12: " + router.size() + " endpoints registered");

		if (runSeconds <= 0) {
			println("GhidraMCP12: running until interrupted (Ctrl-C to stop)");
			while (!monitor.isCancelled()) {
				Thread.sleep(500);
			}
		}
		else {
			println("GhidraMCP12: running for " + runSeconds + " second(s)");
			long deadline = System.currentTimeMillis() + runSeconds * 1000L;
			while (System.currentTimeMillis() < deadline && !monitor.isCancelled()) {
				Thread.sleep(500);
			}
		}

		server.stop();
		println("GhidraMCP12: server stopped");
	}

	private static int parseInt(String s, int fallback) {
		try {
			return Integer.parseInt(s.trim());
		}
		catch (NumberFormatException e) {
			return fallback;
		}
	}
}
