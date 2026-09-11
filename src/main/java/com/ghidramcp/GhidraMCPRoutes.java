/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 *
 * Assembles the complete route table. Every endpoint the bridge exposes is
 * registered here, which keeps "what can this thing do?" answerable by reading
 * exactly one file (and at runtime by GET /_tools).
 */
package com.ghidramcp;

import com.ghidramcp.api.ApiContext;
import com.ghidramcp.api.Router;
import com.ghidramcp.handlers.AnalysisHandlers;
import com.ghidramcp.handlers.CommentHandlers;
import com.ghidramcp.handlers.DataHandlers;
import com.ghidramcp.handlers.FunctionHandlers;
import com.ghidramcp.handlers.LegacyHandlers;
import com.ghidramcp.handlers.MetaHandlers;
import com.ghidramcp.handlers.ProgramHandlers;
import com.ghidramcp.handlers.ScriptHandlers;
import com.ghidramcp.handlers.SymbolHandlers;
import com.ghidramcp.handlers.TypeHandlers;
import com.ghidramcp.handlers.VariableHandlers;

/** Builds the full {@link Router}. */
public final class GhidraMCPRoutes {

	private GhidraMCPRoutes() {
	}

	/** Registers every endpoint group and returns the populated router. */
	public static Router build(ApiContext ctx) {
		Router router = new Router();

		MetaHandlers.register(router, ctx);
		ProgramHandlers.register(router, ctx);
		FunctionHandlers.register(router, ctx);
		VariableHandlers.register(router, ctx);
		SymbolHandlers.register(router, ctx);
		DataHandlers.register(router, ctx);
		TypeHandlers.register(router, ctx);
		CommentHandlers.register(router, ctx);
		AnalysisHandlers.register(router, ctx);
		ScriptHandlers.register(router, ctx);

		// Registered last: these mirror the original GhidraMCP API so existing
		// prompts and clients keep working against the new plugin.
		LegacyHandlers.register(router, ctx);

		router.registerIntrospection();
		return router;
	}
}
