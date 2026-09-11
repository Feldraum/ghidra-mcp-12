/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.api;

/**
 * Signals a client-visible failure (4xx/5xx). Handlers throw this instead of
 * returning magic error strings so that the HTTP layer can pick an accurate
 * status code and the MCP layer can surface a clean error to the agent.
 */
public class ApiException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	private final int status;

	public ApiException(int status, String message) {
		super(message);
		this.status = status;
	}

	public ApiException(int status, String message, Throwable cause) {
		super(message, cause);
		this.status = status;
	}

	public int status() {
		return status;
	}

	public static ApiException badRequest(String message) {
		return new ApiException(400, message);
	}

	public static ApiException notFound(String message) {
		return new ApiException(404, message);
	}

	public static ApiException conflict(String message) {
		return new ApiException(409, message);
	}

	public static ApiException internal(String message, Throwable cause) {
		return new ApiException(500, message, cause);
	}
}
