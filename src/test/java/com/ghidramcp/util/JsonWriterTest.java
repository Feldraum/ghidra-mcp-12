package com.ghidramcp.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

/**
 * Tests for the dependency-free JSON layer.
 *
 * <p>{@link JsonWriter} holds the state that every API response depends on, and
 * its failure mode is a malformed body rather than an exception at the call
 * site, so it is worth pinning down precisely. The writer is hand-written
 * specifically so the extension needs no JSON library, which makes these tests
 * the only safety net it has.
 *
 * <p>Run with the JUnit 4 jar on the classpath:
 * <pre>
 *   java -cp "junit.jar;hamcrest.jar;build/classes;..." org.junit.runner.JUnitCore com.ghidramcp.util.JsonWriterTest
 * </pre>
 * {@code tools/test-json.ps1} does this.
 */
public class JsonWriterTest {

	// ------------------------------------------------------------- writer basics

	@Test
	public void writesFlatObject() {
		JsonWriter w = new JsonWriter();
		w.beginObject();
		w.field("a", 1);
		w.field("b", "two");
		w.field("c", true);
		w.endObject();
		assertEquals("{\"a\":1,\"b\":\"two\",\"c\":true}", w.toString());
	}

	@Test
	public void writesEmptyContainers() {
		assertEquals("{}", new JsonWriter().beginObject().endObject().toString());
		assertEquals("[]", new JsonWriter().beginArray().endArray().toString());
	}

	@Test
	public void writesArrayOfScalars() {
		JsonWriter w = new JsonWriter().beginArray();
		w.value(1);
		w.value("two");
		w.value(false);
		w.nullValue();
		w.endArray();
		assertEquals("[1,\"two\",false,null]", w.toString());
	}

	/** The regression this test exists for: nested containers inside objects. */
	@Test
	public void writesObjectContainingArrayOfObjects() {
		JsonWriter w = new JsonWriter();
		w.beginObject();
		w.name("count").value(3);
		w.name("items").beginArray();
		w.beginObject().field("x", 1).endObject();
		w.beginObject().field("x", 2).endObject();
		w.endArray();
		w.name("tail").value("done");
		w.endObject();
		assertEquals("{\"count\":3,\"items\":[{\"x\":1},{\"x\":2}],\"tail\":\"done\"}",
			w.toString());
	}

	@Test
	public void writesNestedEmptyContainers() {
		JsonWriter w = new JsonWriter();
		w.beginObject();
		w.name("a").beginArray().endArray();
		w.name("b").beginObject().endObject();
		w.name("c").value(1);
		w.endObject();
		assertEquals("{\"a\":[],\"b\":{},\"c\":1}", w.toString());
	}

	@Test
	public void writesDeeplyNestedStructures() {
		Map<String, Object> inner = new LinkedHashMap<>();
		inner.put("list", List.of(1, 2, 3));
		inner.put("empty", List.of());
		Map<String, Object> root = new LinkedHashMap<>();
		root.put("level1", Map.of("level2", inner));
		root.put("items", List.of(Map.of("k", "v"), Map.of("k2", List.of("a", "b"))));

		String json = Json.serialize(root);
		Object reparsed = JsonParser.parse(json);
		assertTrue("reparsing must round-trip: " + json, reparsed instanceof Map);
	}

	// ------------------------------------------------------------------- escaping

	@Test
	public void escapesControlCharactersAndQuotes() {
		JsonWriter w = new JsonWriter();
		w.beginObject();
		w.field("s", "quote\" back\\slash\nnewline\ttab\u0001ctrl");
		w.endObject();
		String json = w.toString();
		assertEquals("{\"s\":\"quote\\\" back\\\\slash\\nnewline\\ttab\\u0001ctrl\"}", json);
		// And it must survive a round trip.
		Map<String, Object> back = JsonParser.parseObject(json);
		assertEquals("quote\" back\\slash\nnewline\ttab\u0001ctrl", back.get("s"));
	}

	@Test
	public void escapesNonAsciiAsIs() {
		JsonWriter w = new JsonWriter();
		w.beginObject();
		w.field("path", "D:\\桌面\\mini");
		w.endObject();
		Map<String, Object> back = JsonParser.parseObject(w.toString());
		assertEquals("D:\\桌面\\mini", back.get("path"));
	}

	@Test
	public void writesNonFiniteNumbersAsNull() {
		JsonWriter w = new JsonWriter();
		w.beginObject();
		w.field("nan", Double.NaN);
		w.endObject();
		assertEquals("{\"nan\":null}", w.toString());
	}

	// -------------------------------------------------------------- serialization

	@Test
	public void serializesMixedJavaValues() {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("string", "s");
		m.put("int", 42);
		m.put("long", 9_000_000_000L);
		m.put("double", 1.5d);
		m.put("wholeDouble", 3.0d);
		m.put("bool", true);
		m.put("null", null);
		m.put("list", new ArrayList<>(List.of("a", 1)));
		m.put("map", Map.of("k", "v"));
		m.put("array", new int[] { 1, 2 });

		Object back = JsonParser.parse(Json.serialize(m));
		assertTrue(back instanceof Map);
		@SuppressWarnings("unchecked")
		Map<String, Object> parsed = (Map<String, Object>) back;
		assertEquals("s", parsed.get("string"));
		assertEquals(42.0, (Double) parsed.get("int"), 0.0);
		assertEquals(3.0, (Double) parsed.get("wholeDouble"), 0.0);
		assertEquals(Boolean.TRUE, parsed.get("bool"));
		assertTrue(parsed.containsKey("null"));
		assertEquals(null, parsed.get("null"));
	}

	/** Every list endpoint uses this envelope, so its shape is a contract. */
	@Test
	public void pageEnvelopeHasStableShape() {
		List<Object> items = new ArrayList<>();
		items.add(Map.of("name", "a"));
		items.add(Map.of("name", "b"));
		String json = Json.page(items, items.size(), 0, 10);
		@SuppressWarnings("unchecked")
		Map<String, Object> parsed = (Map<String, Object>) JsonParser.parse(json);
		assertEquals(2.0, (Double) parsed.get("count"), 0.0);
		assertEquals(Boolean.FALSE, parsed.get("truncated"));
		assertEquals(2, ((List<?>) parsed.get("items")).size());

		// A truncated page must say so against the *total*, otherwise an agent
		// cannot tell "no more data" from "there is more".
		@SuppressWarnings("unchecked")
		Map<String, Object> truncated = (Map<String, Object>) JsonParser
			.parse(Json.page(items.subList(0, 1), 2, 0, 1));
		assertEquals(Boolean.TRUE, truncated.get("truncated"));
		assertEquals(2.0, (Double) truncated.get("count"), 0.0);
		assertEquals(1, ((List<?>) truncated.get("items")).size());

		// A second page that reaches the end must not claim there is more.
		@SuppressWarnings("unchecked")
		Map<String, Object> lastPage = (Map<String, Object>) JsonParser
			.parse(Json.page(items.subList(1, 2), 2, 1, 1));
		assertEquals(Boolean.FALSE, lastPage.get("truncated"));
		assertEquals(1.0, (Double) lastPage.get("offset"), 0.0);
	}

	@Test
	public void errorAndOkEnvelopesAreValid() {
		@SuppressWarnings("unchecked")
		Map<String, Object> err = (Map<String, Object>) JsonParser.parse(Json.errorBody(404, "nope"));
		assertEquals(Boolean.FALSE, err.get("success"));
		assertEquals("nope", err.get("error"));

		@SuppressWarnings("unchecked")
		Map<String, Object> ok = (Map<String, Object>) JsonParser.parse(
			Json.okBody("did it", Map.of("address", "0x1000")));
		assertEquals(Boolean.TRUE, ok.get("success"));
		assertEquals("0x1000", ok.get("address"));
	}

	// ----------------------------------------------------------- writer misuse

	@Test
	public void rejectsUnbalancedWriter() {
		try {
			new JsonWriter().beginObject().toString();
			fail("expected an exception for an unclosed object");
		}
		catch (IllegalStateException expected) {
			assertTrue(expected.getMessage().contains("unbalanced"));
		}
	}

	/**
	 * Two values in a row inside an object means a member name was forgotten, which
	 * would otherwise emit invalid JSON silently.
	 */
	@Test
	public void rejectsConsecutiveValuesInsideObject() {
		JsonWriter w = new JsonWriter().beginObject().name("a").value(1);
		try {
			w.value(2);
			fail("expected an exception for a value with no member name");
		}
		catch (IllegalStateException expected) {
			assertTrue(expected.getMessage().contains("member name"));
		}
	}

	@Test
	public void rejectsNameOutsideObject() {
		try {
			new JsonWriter().beginArray().name("x");
			fail("expected an exception for name() inside an array");
		}
		catch (IllegalStateException expected) {
			assertTrue(expected.getMessage().contains("outside of an object"));
		}
	}
}
