/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.ghidramcp.api.ApiRequest;

/**
 * The single place that turns "a list of everything" into "a page of it".
 *
 * <p>Every list endpoint goes through here so that all of them report the same
 * fields. That matters more than it sounds: an agent that cannot tell a truncated
 * page from the end of the data will silently under-report findings, so
 * {@code count} is the total and {@code truncated} is computed against the
 * unsliced list.
 */
public final class Page {

	private Page() {
	}

	/**
	 * Slices {@code all} according to the request's offset/limit and returns the
	 * standard envelope as JSON.
	 */
	public static String of(List<?> all, ApiRequest request, int defaultLimit) {
		return of(all, request.paging(defaultLimit));
	}

	/** Slices {@code all} and returns the standard envelope as JSON. */
	public static String of(List<?> all, ApiRequest.Paging paging) {
		List<?> items = all == null ? List.of() : all;
		List<?> slice = paging.slice(items);
		return Json.page(slice, items.size(), paging.offset(), paging.limit());
	}

	/** Slices {@code all} and returns the standard envelope as a map. */
	public static Map<String, Object> map(List<?> all, ApiRequest.Paging paging) {
		List<?> items = all == null ? List.of() : all;
		List<?> slice = paging.slice(items);
		Map<String, Object> envelope = new LinkedHashMap<>();
		envelope.put("count", items.size());
		envelope.put("offset", paging.offset());
		envelope.put("limit", paging.limit());
		envelope.put("returned", slice.size());
		envelope.put("truncated", paging.offset() + slice.size() < items.size());
		envelope.put("items", slice);
		return envelope;
	}

	/** Wraps an already-sliced list, without pagination metadata. */
	public static String ofSlice(List<?> items) {
		return Json.list(new ArrayList<>(items));
	}
}
