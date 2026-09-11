/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.handlers;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.ghidramcp.api.ApiContext;
import com.ghidramcp.api.ApiException;
import com.ghidramcp.api.Router;
import com.ghidramcp.util.ApiResponse;
import com.ghidramcp.util.Json;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Ghidra script discovery and execution - the bridge's escape hatch.
 *
 * <p>No finite endpoint list covers every question a reverse engineer asks, so
 * agents get the ability to run a GhidraScript. Both directions are supported:
 * run a script that already lives in a Ghidra script directory, or execute
 * source supplied inline.
 *
 * <p>This is arbitrary code execution inside the Ghidra JVM by design, so it is
 * worth being explicit: anything an agent can reach this way, it can also reach
 * by asking for a dedicated endpoint. Operators who want a read-only bridge
 * should disable it (the plugin exposes the switch) rather than rely on
 * obscurity.
 */
public final class ScriptHandlers {

	private ScriptHandlers() {
	}

	public static void register(Router router, ApiContext ctx) {

		router.get("/scripts", "script",
			"List available GhidraScripts (name, extension, path, provider)", req ->
				ApiResponse.json(Json.list(listScripts(req.param("name")))));

		router.get("/scripts/providers", "script", "Installed script providers (Java, Python, ...)",
			req -> {
				List<Object> out = new ArrayList<>();
				for (GhidraScriptProvider p : GhidraScriptUtil.getProviders()) {
					Map<String, Object> m = new LinkedHashMap<>();
					m.put("extension", p.getExtension());
					m.put("description", p.getDescription());
					m.put("runtimeEnvironment", p.getRuntimeEnvironmentName());
					m.put("class", p.getClass().getName());
					out.add(m);
				}
				return ApiResponse.json(Json.list(out));
			});

		router.lookup("/scripts/source", "script", "Read the source of a script by name", req -> {
			String name = req.require("name", "script");
			ResourceFile file = GhidraScriptUtil.findScriptByName(name);
			if (file == null || !file.exists()) {
				throw ApiException.notFound("no script named '" + name + "'" + scriptHint(name));
			}
			try {
				return ApiResponse.text(java.nio.file.Files.readString(
					java.nio.file.Path.of(file.getAbsolutePath())));
			}
			catch (Exception e) {
				throw ApiException.internal("could not read " + file.getAbsolutePath() +
					": " + e.getMessage(), e);
			}
		});

		router.post("/scripts/execute", "script",
			"Run a GhidraScript: name=MyScript (existing) or source=<code> with language=java|py",
			req -> ApiResponse.json(execute(ctx, req)));
	}

	// ------------------------------------------------------------------ listing

	private static List<Object> listScripts(String nameFilter) {
		List<Object> out = new ArrayList<>();
		java.util.Set<String> seen = new java.util.HashSet<>();
		for (ResourceFile dir : GhidraScriptUtil.getScriptSourceDirectories()) {
			if (!dir.isDirectory()) {
				continue;
			}
			for (ResourceFile f : dir.listFiles()) {
				collect(f, nameFilter, seen, out);
			}
		}
		return out;
	}

	private static void collect(ResourceFile f, String nameFilter, java.util.Set<String> seen,
			List<Object> out) {
		if (f.isDirectory()) {
			for (ResourceFile child : f.listFiles()) {
				collect(child, nameFilter, seen, out);
			}
			return;
		}
		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(f);
		if (provider == null) {
			return;
		}
		String base = GhidraScriptUtil.getBaseName(f);
		if (nameFilter != null && !base.toLowerCase().contains(nameFilter.toLowerCase())) {
			return;
		}
		if (!seen.add(f.getAbsolutePath())) {
			return;
		}
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("name", base);
		m.put("fileName", f.getName());
		m.put("extension", provider.getExtension());
		m.put("path", f.getAbsolutePath());
		m.put("isSystemScript", GhidraScriptUtil.isSystemScript(f));
		out.add(m);
	}

	// ---------------------------------------------------------------- execution

	private static Map<String, Object> execute(ApiContext ctx,
			com.ghidramcp.api.ApiRequest req) {
		if (!ctx.isScriptExecutionAllowed()) {
			throw new ApiException(403,
				"script execution is disabled on this bridge (ScriptHandlers.setScriptExecutionAllowed)");
		}
		String name = req.param("name", req.param("script"));
		String source = req.param("source", req.param("code"));
		String language = req.param("language", "java");
		String[] args = splitArgs(req.param("args"));

		StagedScript staged = null;
		ResourceFile scriptFile;
		if (name != null && !name.isBlank()) {
			scriptFile = GhidraScriptUtil.findScriptByName(name);
			if (scriptFile == null || !scriptFile.exists()) {
				throw ApiException.notFound("no script named '" + name + "'" + scriptHint(name));
			}
		}
		else if (source != null && !source.isBlank()) {
			staged = writeTemporaryScript(ctx, source, language);
			scriptFile = staged.file();
		}
		else {
			throw ApiException.badRequest(
				"provide 'name' of an existing script, or 'source' with inline code " +
					"(plus 'language' = java|py)");
		}

		Program program = ctx.program();
		StringWriter console = new StringWriter();
		PrintWriter consoleWriter = new PrintWriter(console);
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("script", scriptFile.getName());
		body.put("temporary", staged != null);
		if (staged != null) {
			body.put("bundleRegistered", staged.bundleRegistered());
		}

		try {
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
			if (provider == null) {
				throw ApiException.badRequest("no script provider handles " + scriptFile.getName() +
					"; installed script extensions: " + providerExtensions());
			}
			GhidraScript script = provider.getScriptInstance(scriptFile, consoleWriter);
			if (script == null) {
				throw ApiException.internal("provider " + provider.getClass().getSimpleName() +
					" could not instantiate " + scriptFile.getName(), null);
			}
			if (args.length > 0) {
				script.setScriptArgs(args);
			}
			Project project = ctx.guiAvailable() ? ctx.tool().getProject() : null;
			GhidraState state = new GhidraState(ctx.tool(), project, program,
				program == null ? null : new ProgramLocation(program, program.getMinAddress()),
				null, null);

			TaskMonitor monitor = TaskMonitor.DUMMY;
			// The (state, monitor, writer) overload is deprecated for removal in
			// 12.1.3; ScriptControls is the supported way to supply the monitor and
			// the two output writers.
			var controls = new ghidra.app.script.ScriptControls(
				consoleWriter, consoleWriter, monitor);
			script.execute(state, controls);
			consoleWriter.flush();

			body.put("success", true);
			body.put("provider", provider.getDescription());
			body.put("output", console.toString());
			return body;
		}
		catch (ApiException e) {
			throw e;
		}
		catch (Throwable t) {
			consoleWriter.flush();
			body.put("success", false);
			body.put("error", t.toString());
			body.put("output", console.toString());
			if (t instanceof Exception e) {
				throw new ApiException(500, "script failed: " + e + "\n--- console ---\n" +
					console, e);
			}
			throw new ApiException(500, "script failed: " + t);
		}
		finally {
			if (staged != null) {
				cleanupStaged(staged);
			}
			// Scripts routinely mutate the database; drop caches so the next call
			// observes the change.
			if (program != null) {
				com.ghidramcp.api.ProgramIndex.invalidate(program);
				com.ghidramcp.core.Decompiler.invalidate(program);
			}
		}
	}

	/** Removes a staged inline script and its bundle registration. */
	private static void cleanupStaged(StagedScript staged) {
		try {
			var host = GhidraScriptUtil.getBundleHost();
			if (host != null && staged.bundleRegistered()) {
				host.remove(new ResourceFile(staged.directory().toFile()));
			}
		}
		catch (Throwable t) {
			// Removing a bundle that was never fully installed is not an error.
		}
		try (var paths = java.nio.file.Files.walk(staged.directory())) {
			paths.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
				try {
					java.nio.file.Files.deleteIfExists(p);
				}
				catch (java.io.IOException ignored) {
					// Best effort: the OS temp cleaner will get it eventually.
				}
			});
		}
		catch (java.io.IOException ignored) {
			// Best effort.
		}
	}

	/** Human-readable list of installed script provider extensions. */
	private static String providerExtensions() {
		List<String> exts = new ArrayList<>();
		for (GhidraScriptProvider p : GhidraScriptUtil.getProviders()) {
			exts.add(String.valueOf(p.getExtension()));
		}
		return String.join(", ", exts);
	}

	/**
	 * Writes inline source into a directory Ghidra's script providers can see.
	 *
	 * <p>Two constraints shape this:
	 *
	 * <ul>
	 *   <li>Java scripts are compiled by the provider, which requires the public
	 *       class name to match the file name. A bare body is therefore wrapped in
	 *       a generated class, and a supplied class is renamed if necessary.</li>
	 *   <li>The provider resolves scripts through the OSGi bundle host, so the
	 *       directory has to be registered as a bundle before the script can be
	 *       instantiated.</li>
	 * </ul>
	 */
	private static StagedScript writeTemporaryScript(ApiContext ctx, String source,
			String language) {
		String shownExtension = extensionFor(language);
		String ext = shownExtension.startsWith(".") ? shownExtension.substring(1) : shownExtension;
		String className = "McpInline" + Math.abs(System.nanoTime() % 1_000_000_000L);
		String body = source;

		if ("java".equals(ext)) {
			body = ensureJavaClass(source, className);
		}

		try {
			java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("ghidramcp-script");
			java.nio.file.Path file = dir.resolve(className + "." + ext);
			java.nio.file.Files.writeString(file, body);
			ResourceFile resourceFile = new ResourceFile(file.toFile());

			// Register the directory so the Java provider (and anything else that
			// walks bundle roots) can find the script by name.
			boolean registered = false;
			try {
				var host = GhidraScriptUtil.getBundleHost();
				if (host != null) {
					host.add(new ResourceFile(dir.toFile()), false, true);
					registered = true;
				}
			}
			catch (Throwable t) {
				// Logging must not be able to fail the request, and this is only a
				// diagnostic: the script may still run if the provider resolves it.
				try {
					ghidra.util.Msg.warn(ScriptHandlers.class,
						"could not register the inline script directory with the bundle host: " + t);
				}
				catch (Throwable ignored) {
					// nothing useful to do
				}
			}
			return new StagedScript(resourceFile, dir, className, registered);
		}
		catch (java.io.IOException e) {
			throw ApiException.internal("could not stage the inline script: " + e.getMessage(), e);
		}
	}

	/**
	 * Makes {@code source} compile as a class named {@code className}.
	 *
	 * <p>Agents send either a full script class or just the statements they want
	 * run; both are accepted, because rejecting the bare-body form would make the
	 * most convenient shape unusable.
	 */
	static String ensureJavaClass(String source, String className) {
		String trimmed = source == null ? "" : source.trim();
		boolean looksLikeClass = trimmed.contains("class ") && trimmed.contains("GhidraScript");
		if (looksLikeClass) {
			// Rename the declared class so it matches the file name.
			java.util.regex.Matcher m = java.util.regex.Pattern
				.compile("(public\\s+)?class\\s+([A-Za-z_$][A-Za-z0-9_$]*)")
				.matcher(trimmed);
			if (m.find()) {
				String declared = m.group(2);
				if (!declared.equals(className)) {
					return trimmed.substring(0, m.start(2)) + className +
						trimmed.substring(m.end(2));
				}
			}
			return trimmed;
		}
		// Bare statements: wrap them in a script class. Imports are hoisted so a
		// snippet that begins with "import ..." still compiles, and each statement
		// is placed on its own line because agents frequently send the whole
		// snippet as a single line.
		List<String> imports = new ArrayList<>();
		List<String> statements = new ArrayList<>();
		for (String rawLine : trimmed.split("\n")) {
			String line = rawLine.trim();
			if (line.isEmpty()) {
				continue;
			}
			if (line.startsWith("import ")) {
				// A single line may carry "import x; import y; println(...)".
				for (String part : splitAfterSemicolons(line)) {
					if (part.startsWith("import ")) {
						imports.add(part);
					}
					else {
						statements.add(part);
					}
				}
				continue;
			}
			statements.add(line);
		}

		StringBuilder importBlock = new StringBuilder();
		for (String imp : imports) {
			importBlock.append(imp).append('\n');
		}
		StringBuilder bodyBlock = new StringBuilder();
		for (String stmt : statements) {
			bodyBlock.append("        ").append(stmt).append('\n');
		}

		return """
			// Generated by GhidraMCP12 for an inline script request.
			import ghidra.app.script.GhidraScript;
			%s
			public class %s extends GhidraScript {
				@Override
				public void run() throws Exception {
			%s	}
			}
			""".formatted(importBlock, className, bodyBlock);
	}

	/**
	 * Splits a line into statement-sized pieces at semicolons, keeping the
	 * semicolon, treating anything after the first {@code import} as its own
	 * statement.
	 */
	private static List<String> splitAfterSemicolons(String line) {
		List<String> parts = new ArrayList<>();
		int start = 0;
		for (int i = 0; i < line.length(); i++) {
			if (line.charAt(i) == ';') {
				String part = line.substring(start, i + 1).trim();
				if (!part.isEmpty()) {
					parts.add(part);
				}
				start = i + 1;
			}
		}
		String tail = line.substring(start).trim();
		if (!tail.isEmpty()) {
			parts.add(tail);
		}
		return parts.isEmpty() ? List.of(line) : parts;
	}

	/** A staged inline script plus what is needed to clean it up. */
	private record StagedScript(ResourceFile file, java.nio.file.Path directory,
			String className, boolean bundleRegistered) {
	}

	/**
	 * Maps a requested language onto an installed script provider's extension.
	 *
	 * <p>Provider extensions are reported with a leading dot (".java", ".py"), so
	 * they must be normalised before comparison; otherwise the lookup fails and the
	 * caller is told no provider exists while several are installed.
	 */
	private static String extensionFor(String language) {
		String lang = language == null ? "java" : language.trim().toLowerCase();
		if (lang.startsWith(".")) {
			lang = lang.substring(1);
		}
		List<String> installed = new ArrayList<>();
		for (GhidraScriptProvider p : GhidraScriptUtil.getProviders()) {
			String ext = p.getExtension();
			if (ext == null) {
				continue;
			}
			String normalized = ext.startsWith(".") ? ext.substring(1) : ext;
			installed.add(normalized);
			boolean matches = normalized.equalsIgnoreCase(lang)
				|| ("python".equals(lang) && "py".equalsIgnoreCase(normalized));
			if (matches) {
				return ext;
			}
		}
		throw ApiException.badRequest("no installed script provider for language '" + language +
			"'; installed script extensions: " + String.join(", ", installed));
	}

	private static String[] splitArgs(String args) {
		if (args == null || args.isBlank()) {
			return new String[0];
		}
		// Accept both comma separated and JSON-ish bracketed lists.
		String cleaned = args.trim();
		if (cleaned.startsWith("[") && cleaned.endsWith("]")) {
			cleaned = cleaned.substring(1, cleaned.length() - 1);
		}
		List<String> out = new ArrayList<>();
		for (String part : cleaned.split(",")) {
			String v = part.trim();
			if (v.length() >= 2 && ((v.startsWith("\"") && v.endsWith("\""))
				|| (v.startsWith("'") && v.endsWith("'")))) {
				v = v.substring(1, v.length() - 1);
			}
			if (!v.isEmpty()) {
				out.add(v);
			}
		}
		return out.toArray(new String[0]);
	}

	private static String scriptHint(String name) {
		List<String> names = new ArrayList<>();
		for (Object o : listScripts(null)) {
			if (o instanceof Map<?, ?> m && m.get("name") != null) {
				String n = String.valueOf(m.get("name"));
				if (name == null || n.toLowerCase().contains(name.toLowerCase())) {
					names.add(n);
				}
			}
			if (names.size() >= 10) {
				break;
			}
		}
		return names.isEmpty() ? "" : "; available scripts include: " + String.join(", ", names);
	}
}
