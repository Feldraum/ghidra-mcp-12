/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.api;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import com.ghidramcp.core.ProgramService;

/**
 * Shared state handed to every API handler group.
 *
 * <p>Handlers never talk to {@code PluginTool} directly: they go through
 * {@link #programs()}, which is where every "which program is this?" question is
 * answered.
 */
public final class ApiContext {

	private final ProgramService programs;
	private final PluginTool tool;
	private final String version;
	private volatile java.util.function.Supplier<java.util.Map<String, Object>> statsSupplier;
	private volatile boolean scriptExecutionAllowed = true;

	public ApiContext(ProgramService programs, PluginTool tool, String version) {
		this.programs = programs;
		this.tool = tool;
		this.version = version;
	}

	/**
	 * Whether {@code /scripts/execute} may run arbitrary code. On by default
	 * because it is the bridge's escape hatch for analysis that has no dedicated
	 * endpoint; an operator who does not want an agent capable of executing code
	 * in the Ghidra JVM can turn it off.
	 */
	public boolean isScriptExecutionAllowed() {
		return scriptExecutionAllowed;
	}

	public void setScriptExecutionAllowed(boolean allowed) {
		this.scriptExecutionAllowed = allowed;
	}

	/**
	 * Registers a callback that reports runtime statistics (server port, request
	 * counts, ...) for the {@code /_health} endpoint. Only the plugin can provide
	 * this; without it the health endpoint simply omits those fields.
	 */
	public void setStatsSupplier(java.util.function.Supplier<java.util.Map<String, Object>> supplier) {
		this.statsSupplier = supplier;
	}

	/** Runtime statistics, or an empty map when none are available. */
	public java.util.Map<String, Object> stats() {
		java.util.function.Supplier<java.util.Map<String, Object>> s = statsSupplier;
		if (s == null) {
			return java.util.Map.of();
		}
		try {
			return s.get();
		}
		catch (RuntimeException e) {
			return java.util.Map.of();
		}
	}

	public ProgramService programs() {
		return programs;
	}

	/**
	 * The Ghidra tool the plugin is running in, which is where services such as
	 * {@code ProgramManager}, {@code CodeViewerService} and
	 * {@code DataTypeManagerService} come from.
	 *
	 * <p>Returned as nullable and paired with {@link #guiAvailable()} because the
	 * request handlers are also driven by the test harness, which builds a context
	 * with no tool. Handler code must therefore not assume a tool is present.
	 */
	public PluginTool tool() {
		return tool;
	}

	/** Whether {@link #tool()} is present. */
	public boolean guiAvailable() {
		return tool != null;
	}

	public String version() {
		return version;
	}

	/** The program requests act on. */
	public Program program() {
		return programs.current();
	}

	/** The current program, or an {@link ApiException} describing what is missing. */
	public Program requireProgram() {
		Program p = programs.current();
		if (p == null) {
			throw new ApiException(409,
				"No program is open. Open a program in Ghidra, or start the bridge with a binary path " +
					"(see mcp/README.md).");
		}
		return p;
	}

	/** Lazily built lookup index for a program. */
	public ProgramIndex index(Program program) {
		return ProgramIndex.of(program);
	}

	/** Index for the current program. */
	public ProgramIndex index() {
		return ProgramIndex.of(requireProgram());
	}

	/** Runs a read operation against the current program. */
	public <T> T read(java.util.concurrent.Callable<T> work) {
		requireProgram();
		return programs.read(work);
	}

	/**
	 * Runs a read operation and serialises its result as a JSON body.
	 *
	 * <p>Handlers that build a {@code Map} or {@code String} would otherwise have
	 * to wrap every call site in {@code ApiResponse.json(...)}; this keeps the
	 * route lambdas readable. It is a distinct method (rather than an overload of
	 * {@link #read}) because both erase to {@code Callable}.
	 */
	public com.ghidramcp.util.ApiResponse readJson(Outcome work) {
		requireProgram();
		return com.ghidramcp.util.ApiResponse.json(programs.read(work::get));
	}

	/**
	 * Runs a mutation in a transaction, invalidates caches, and serialises the
	 * result as a JSON body.
	 */
	public com.ghidramcp.util.ApiResponse mutateJson(String transactionName, Outcome work) {
		Program p = requireProgram();
		try {
			return com.ghidramcp.util.ApiResponse.json(
				programs.mutate(transactionName, work::get));
		}
		finally {
			ProgramIndex.invalidate(p);
		}
	}

	/** A value-producing computation that may fail with a checked exception. */
	@FunctionalInterface
	public interface Outcome {
		Object get() throws Exception;
	}

	/**
	 * Runs a mutation in a transaction and invalidates the lookup index
	 * afterwards so subsequent reads observe the change.
	 */
	public <T> T mutate(String transactionName, java.util.concurrent.Callable<T> work) {
		Program p = requireProgram();
		try {
			return programs.mutate(transactionName, work);
		}
		finally {
			ProgramIndex.invalidate(p);
		}
	}

	/** Convenience for mutations whose result is uninteresting. */
	public void mutateVoid(String transactionName, Runnable work) {
		mutate(transactionName, () -> {
			work.run();
			return Boolean.TRUE;
		});
	}
}
