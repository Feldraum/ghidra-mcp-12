# GhidraMCP12

**An MCP server for Ghidra 12.1.3.** It lets AI agents — Claude, Cursor, or any
MCP client — drive a live Ghidra session: list and decompile functions, follow
cross-references, rename symbols, apply C types, patch bytes, and run Ghidra
scripts.

```
MCP client                  MCP server                   Ghidra extension
(Claude, Cursor,   ──stdio──▶ ghidra_mcp_server.py ──HTTP──▶ GhidraMCPPlugin
 any agent)                   58 tools, runtime-discovered    (inside Ghidra)
                                endpoint index                       │
                                                              Ghidra API
```

Two pieces ship together:

| Piece | What it is | Where |
|---|---|---|
| **Ghidra extension** | A plugin that runs a dependency-free HTTP/JSON server inside the Ghidra JVM | `src/main/java` → extension zip |
| **MCP server** | A Python server translating MCP tool calls into bridge requests | `mcp/ghidra_mcp_server.py` |

The split is deliberate. Ghidra's extension class loader is isolated and hostile
to third-party dependencies, so the extension is **dependency-free Java** — the
JDK's own `com.sun.net.httpserver` and a hand-written JSON layer, no Gson, no web
framework. The MCP protocol lives outside, where it can use the official SDK, and
where a protocol upgrade is a `pip install` rather than a Ghidra extension rebuild.

## Requirements

| | |
|---|---|
| Ghidra | **12.1.3** (built and verified against `ghidra_12.1.3_PUBLIC`) |
| JDK | **21 or newer** — Ghidra 12 requires it. Verified with JDK 26. |
| Python | **3.10+** for the MCP server, with `mcp>=1.2.0,<2` and `requests` |

## Install

**1. Build the extension**

```powershell
powershell -File tools\build.ps1
```

This compiles against your Ghidra install, produces
`dist\ghidra_12.1.3_PUBLIC_<date>_GhidraMCP12.zip`, and validates the archive. It
needs no network and no Gradle. (The official Gradle path also works — see
[Build](#build).)

**2. Install it**

```powershell
powershell -File tools\install.ps1
```

Or use Ghidra itself: **File → Install Extensions → +** and pick the zip.

**3. Enable the plugin**

Start Ghidra, open a program, then **File → Configure → Developer → GhidraMCP12**.
The log shows the listening URL (default `http://127.0.0.1:8192`). Confirm:

```powershell
curl.exe http://127.0.0.1:8192/_health
```

`/_health` answers even with no program open, which is what distinguishes "Ghidra
is not running" from "Ghidra is running but has no program open".

**4. Connect your MCP client**

```powershell
pip install "mcp>=1.2.0,<2" requests
```

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": ["<path-to-repo>/mcp/ghidra_mcp_server.py"],
      "env": { "GHIDRA_MCP_URL": "http://127.0.0.1:8192" }
    }
  }
}
```

See [docs/MCP.md](docs/MCP.md) for Claude Desktop/Code, Cursor, and the HTTP
transport.

### Options

**Edit → Tool Options → GhidraMCP12**

| Option | Default | Meaning |
|---|---|---|
| `Server Port` | `8192` | Restart the tool after changing it |
| `Bind Address` | `127.0.0.1` | Interface to bind |
| `Allow Remote Connections` | `false` | Must be enabled to bind non-loopback. **Anyone who can reach the port can read and modify your programs.** |
| `Start Server On Launch` | `true` | Start with the plugin |
| `Debug Log File` | *(empty)* | Optional request/response trace, for diagnosing a call that never returns |

## What it can do

162 endpoints across 12 categories. The full table is in
[docs/API.md](docs/API.md); at runtime the server documents itself at
`GET /_tools`.

* **Programs & memory** — metadata and hashes, memory map, raw reads, typed
  reads (byte/word/dword/qword/float/double/pointer/string), memory search by hex
  or text.
* **Functions** — list and search, full detail (signature, parameters, locals,
  callers, callees, referenced strings), decompile to C, disassembly with raw
  bytes, decompiler **P-code** (raw and SSA), basic blocks, call graphs,
  externals, thunks.
* **Symbols & references** — symbols, namespaces/classes, imports, exports, entry
  points, xrefs to/from/in, referenced strings.
* **Editing** — rename functions, symbols and variables; retype variables; apply
  C prototypes; create/delete functions; labels and namespaces; comments
  (eol/pre/post/plate/repeatable); structs, unions, enums, typedefs; parse C
  declarations; apply data types; patch and fill memory.
* **Analysis & navigation** — re-run auto analysis over a range or a function,
  disassemble ranges, current GUI location, `goto`, bookmarks, function tags.
* **Scripting** — list/read GhidraScripts, run an existing one or inline
  Java/Python. The escape hatch for anything without a dedicated endpoint.

Everything mutating runs inside a Ghidra transaction, so a wrong turn is one
Ctrl-Z.

## The MCP tool surface

58 tools. The usual flow:

1. `ghidra_health` — confirm Ghidra and a program
2. `get_program_info`, `get_program_summary`
3. `search_functions` / `list_functions`
4. `decompile_function` (or `get_pcode` when the C is ambiguous)
5. `get_xrefs_to` / `get_call_graph`
6. rename and type as you go: `rename_function`, `rename_variable`,
   `set_function_prototype`, `create_struct`
7. `set_comment` / `create_bookmark` — leave conclusions where the human sees them

Beyond the typed tools, `ghidra_find_operations` searches the bridge's endpoint
index by keyword and `ghidra_call` invokes any of the 162 endpoints. This is why
the Python tool list can never fall behind the Java route table: there is no
second list to maintain.

## Design notes

The decisions that separate this from a demo:

* **No dependencies in the extension.** `JsonWriter`/`JsonParser` are ~500 lines
  and covered by unit tests, precisely because there is no library safety net.
* **Mutations run on the Swing thread inside a transaction.** Ghidra's undo
  manager and model listeners assume the EDT; doing otherwise produces
  intermittent `ConcurrentModificationException`s *inside Ghidra*.
* **One decompiler per program, cached.** Constructing a `DecompInterface` primes
  a native process; reusing it turns a suite of decompile calls from seconds each
  into milliseconds each. Invalidated on modification-number change.
* **Errors are data.** Handlers throw `ApiException`, the HTTP layer emits
  `{"success":false,"status":N,"error":"..."}`, and the messages are written for
  an agent to act on: *"no function at or containing 'X'; similar functions: …"*,
  *"unknown data type 'Y'. Known examples: …"*, *"retry with
  `clearCodeUnits=true`"*.
* **Request bodies are read only when declared.** Reading a body with
  `readAllBytes()` deadlocks against a GET client waiting for the response. This
  was a real bug during development; the reader is now keyed off `Content-Length`.
* **`data/ExtensionPoint.manifest` is required.** Without it Ghidra never
  discovers the `Plugin` class, and the extension installs "successfully" while
  doing nothing.

More in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Documentation

| | |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Install, options, troubleshooting |
| [docs/MCP.md](docs/MCP.md) | MCP server usage and client configuration |
| [docs/API.md](docs/API.md) | All 162 endpoints, generated from the live route table |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layers, threading, caches, verification strategy |

## Build

Both paths produce the same archive.

**Offline (no Gradle, no network)** — what this project was developed with:

```powershell
powershell -File tools\build.ps1
```

**Gradle (official)**:

```powershell
$env:GHIDRA_INSTALL_DIR = "D:\zstudytools\ghidra_12.1.3_PUBLIC"
& "$env:GHIDRA_INSTALL_DIR\support\gradle\gradlew.bat" -p . buildExtension
```

The Gradle wrapper downloads its distribution (~140 MB) on first use. Running
both paths caught a packaging bug the offline path could not: Ghidra's
`buildExtension` zips the whole project directory, so `tests/` and
`gradle.properties` were ending up inside the extension. Both paths now exclude
the same set explicitly.

## Verification

| Check | Command | Result |
|---|---|---|
| Archive layout, by Ghidra's own acceptance rules | `tools\verify_zip.ps1` | pass |
| JSON layer unit tests (JUnit) | `tools\test-json.ps1` | 15/15 |
| Every endpoint against a live Ghidra session | `tools\e2e.ps1` | **75/75** |
| MCP protocol + tool surface, as a real MCP client | `tests\mcp_client_test.py` | 21/21 |
| Official Gradle build path | `gradlew.bat -p . buildExtension` | BUILD SUCCESSFUL |

`tools\e2e.ps1` sweeps every registered endpoint (no 5xx, no empty bodies, clear
4xx for missing parameters) and then performs every mutating operation and reads
each change back. It drives the router headlessly through a development fixture,
because a Ghidra plugin otherwise only lives inside the GUI — the plugin's
tool-option and menu wiring is therefore not covered by automation.

## Layout

```
ghidra-mcp-12/
├─ build.gradle, settings.gradle, gradle.properties   build
├─ extension.properties, Module.manifest              extension metadata
├─ data/ExtensionPoint.manifest                       what makes Ghidra find the Plugin
├─ src/main/java/com/ghidramcp/
│  ├─ GhidraMCPPlugin.java    plugin: tool options + HTTP server lifecycle
│  ├─ GhidraMCPRoutes.java    the complete route table
│  ├─ api/                    router, request/response, index, type mapping
│  ├─ core/                   HTTP server, program service, decompiler, lookup
│  ├─ handlers/               endpoint implementations by category
│  └─ util/                   dependency-free JSON, pagination envelope
├─ src/test/java/             JUnit tests for the JSON layer
├─ mcp/ghidra_mcp_server.py   the MCP server
├─ docs/                      INSTALL, MCP, API, ARCHITECTURE
├─ tests/                     MCP client test
└─ tools/                     build, install, verify, test
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports are most useful with the
Ghidra version, the bridge's `/_health` output, and the failing request (add a
`Debug Log File` path to capture the trace).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

This project is independent of, and shares no code with,
[LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP). It does honour
that project's HTTP API: the `legacy` endpoint category answers the original
endpoints (`/methods`, `/decompile`, `/renameFunction`, `/renameData`,
`/renameVariable`, `/set_function_prototype`, `/xrefs_to`, `/searchFunctions`, …),
so prompts and clients written for it keep working. See
[docs/API.md § Compatibility surface](docs/API.md#compatibility-surface).
