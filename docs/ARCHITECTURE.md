# Architecture

## Why an HTTP bridge instead of an MCP server inside Ghidra

A Ghidra extension can only use what Ghidra's class loader exposes. Extension
class loaders are isolated from, and in some configurations ordered after, the
core loaders, so pulling in a JSON library or a web framework is a portability
hazard that shows up as `NoClassDefFoundError` on somebody else's machine.

So the split is:

* **Inside Ghidra** — a plugin with *zero* third-party dependencies. JSON is
  hand-written (`util/JsonWriter`, `util/JsonParser`), HTTP is the JDK's
  `com.sun.net.httpserver`, and the wire format is plain JSON over loopback.
* **Outside Ghidra** — the MCP server, where a protocol upgrade is a `pip
  install` rather than a rebuild of a Ghidra extension, and where the official
  SDK can be used.

It also means any language can drive the bridge, and that a stuck agent can be
debugged with `curl` instead of a protocol trace.

## Layers

```
handlers/        endpoint implementations, one class per category
   │  uses
api/             ApiContext, Router, ApiRequest/ApiResponse, ProgramIndex,
   │             Jsonify/Types/Page (Ghidra -> JSON mapping)
   │  uses
core/            McpHttpServer (transport), ProgramService (threading +
   │             transactions), Decompiler (cached), Lookup (address resolution)
   │  uses
util/            dependency-free JSON, pagination envelope
```

`GhidraMCPRoutes.build(context)` is the single place the whole endpoint surface is
assembled, which keeps "what can this thing do?" answerable by reading one file.

`ApiContext` is the seam that makes headless mode work without a second code path.
Handlers never touch `PluginTool`; they go through `ApiContext`, which in GUI mode
wraps a `PluginTool` and in headless mode has `tool == null` and a directly-held
`Program`. The same handler code serves both.

## Threading and transactions

Ghidra is not thread-safe from the outside, and the bridge serves requests from
an 8-thread pool. Two rules keep that safe:

**Reads** take a per-program fair `ReentrantLock`. Ghidra's `DomainObject` has no
consumer lock to take (`lock()`/`unlock()` operate the on-disk project lock), and
the bridge's index and deserialisation code is not reentrant, so the bridge keeps
its own lock. A `WeakHashMap` keyed by program means two open programs do not
serialise each other.

**Writes** run inside `program.startTransaction(...)` and — in GUI mode — on the
Swing thread via `invokeAndWait`. Ghidra's undo manager and many model listeners
assume the EDT; doing otherwise produces intermittent
`ConcurrentModificationException`s *inside Ghidra*, which is a miserable bug to
attribute to a plugin. Every write is therefore exactly one undo step.

Mutations also invalidate the two caches below before the next read.

## Caches

| Cache | Keyed by | Invalidated when |
|---|---|---|
| `ProgramIndex` | program (weak) | program modification number changes |
| `Decompiler` | program (weak) | program modification number changes |

`HttpServer`'s decompiler spins up the native decompiler process and feeds it the
program's data types; doing that per request costs seconds. `ProgramIndex`
precomputes name→function and name→data-type maps so `Lookup.function` is a hash
lookup rather than a full symbol-table walk — agents call it in tight loops.

Both key off `program.getModificationNumber()`, which is the cheapest correct
invalidation available: it changes on any database edit, including edits made by
the user in the GUI.

## Request handling

`ApiRequest` hides the fact that the original GhidraMCP API and modern clients
disagree about everything. A parameter may arrive as a path segment, a query
parameter, a form field, a JSON object member or a raw text body, and
`param(name)` finds it in all of them. That is why a legacy call such as
`POST /decompile` with a bare `main` body still works, as does
`GET /decompile?name=main` and `{"name":"main"}`.

Two details that exist because their absence caused real bugs:

* **Request bodies are read only when the request declares one.** Reading a body
  with `readAllBytes()` blocks until the client closes the connection — and a GET
  client is waiting for the response. That is a deadlock, not a slow request. The
  reader is keyed off `Content-Length` (and falls back to `available()` for
  chunked bodies).
* **Diagnostics can never kill a request.** Ghidra's `Msg.error` has been observed
  to throw while a headless script is starting; logging is wrapped so a request is
  never lost to its own error path.

## Routing

Exact routes are a `TreeMap` keyed by `"METHOD path"`; placeholder routes
(`/functions/{address}`) are a separate list matched only after exact routing
fails, so `/functions/by-address` is never shadowed. A POST that misses falls back
to the GET route — every GET route is a read and MCP clients are inconsistent
about verbs, so a 405 would be a trap an agent cannot reason its way out of.

## The MCP layer

`ghidra_mcp_server.py` wraps ~58 operations as typed tools and exposes
`ghidra_find_operations` + `ghidra_call` for the rest, discovering endpoints from
`/_tools` at runtime. This is the deliberate choice that keeps the two halves from
drifting: there is no second list of endpoints to maintain.

## Verification strategy

The layers are tested where they can fail:

| Layer | Test | Why there |
|---|---|---|
| JSON writer/parser | `tools/test-json.ps1` (JUnit) | Hand-written, no library safety net, and its failure mode is a malformed body rather than an exception at the call site |
| Archive layout | `tools/verify_zip.ps1` | Reimplements Ghidra's `ExtensionUtils` acceptance rule; a wrong layout installs "successfully" and does nothing |
| HTTP + routing + handlers | `tools/e2e.ps1` | Sweeps all endpoints against a real Ghidra session, then performs every mutation and reads it back |
| MCP protocol | `tests/mcp_client_test.py` | Drives the server with the official SDK, so a protocol mistake cannot hide |

`tools/Debugging`-style harnesses that were useful during development live in the
repo as `tools/DiagnoseDecompiler.java` (proves the decompiler works inside Ghidra
independently of the bridge).
