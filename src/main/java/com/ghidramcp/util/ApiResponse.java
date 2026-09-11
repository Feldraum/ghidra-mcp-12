/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.util;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A tiny, allocation-friendly HTTP response value object.
 *
 * <p>The bridge deliberately avoids returning raw strings from handlers so that a
 * handler can select a status code and content type without every call site
 * having to know about {@code HttpExchange}.
 */
public final class ApiResponse {

	private static final String JSON = "application/json; charset=utf-8";
	private static final String TEXT = "text/plain; charset=utf-8";

	private final int status;
	private final String contentType;
	private final String body;

	private ApiResponse(int status, String contentType, String body) {
		this.status = status;
		this.contentType = contentType;
		this.body = body == null ? "" : body;
	}

	/** {@code 200 OK} with a JSON body. */
	public static ApiResponse json(String body) {
		return new ApiResponse(200, JSON, body);
	}

	/** {@code 200 OK} with a plain text body. */
	public static ApiResponse text(String body) {
		return new ApiResponse(200, TEXT, body);
	}

	/** {@code 200 OK} with a JSON body built from an object. */
	public static ApiResponse json(Object root) {
		return json(Json.serialize(root));
	}

	/** {@code 200 OK} with an empty body. */
	public static ApiResponse ok() {
		return new ApiResponse(200, JSON, "");
	}

	public static ApiResponse status(int status, String body) {
		return new ApiResponse(status, JSON, Json.errorBody(status, body));
	}

	public static ApiResponse badRequest(String message) {
		return status(400, message);
	}

	public static ApiResponse notFound(String message) {
		return status(404, message);
	}

	public static ApiResponse serverError(String message) {
		return status(500, message);
	}

	public static ApiResponse conflict(String message) {
		return status(409, message);
	}

	public int status() {
		return status;
	}

	public String contentType() {
		return contentType;
	}

	public String body() {
		return body;
	}

	/** Small helper used by the {@code /_health} style endpoints. */
	public static ApiResponse keyValues(Map<String, Object> values) {
		Map<String, Object> copy = new LinkedHashMap<>(values);
		return json(copy);
	}
}
