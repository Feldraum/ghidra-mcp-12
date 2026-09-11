# GhidraMCP12 HTTP/JSON API

This is the API the Ghidra extension exposes. The MCP server in `mcp/` calls it;
you can also drive it directly with `curl` or from your own tooling.

* **Base URL** — `http://127.0.0.1:8192` by default.
* **Live index** — `GET /_tools` returns every endpoint with its method and
  purpose. The table below is generated from it, so it cannot drift.
* **Bodies** — parameters may be sent as a query string, as
  `application/x-www-form-urlencoded`, or as a JSON object. Handlers read all
  three, so `{"address":"0x401000"}` and `?address=0x401000` are equivalent.
* **Verbs** — GET-only routes also accept POST. Every GET route is a read, and
  MCP clients are inconsistent about verbs, so accepting the POST is friendlier
  than a 405.
* **Path parameters** — `/functions/{address}` captures the segment, so both
  `/functions/0x401000` and `/functions?address=0x401000` work.

## Response conventions

Single-object endpoints return the object directly:

```json
{"name":"target.exe","languageId":"x86:LE:64:default","functionCount":72}
```

List endpoints return a pagination envelope. `count` is the total before slicing,
and `truncated` says whether more items exist — that is what lets an agent tell
"no more data" from "there is more":

```json
{"count":72,"offset":0,"limit":200,"returned":72,"truncated":false,"items":[…]}
```

Errors are always JSON, with a message written to be acted on:

```json
{"success":false,"status":404,"error":"no function at or containing '0x1234'; similar functions: mc_add @ 0x401000"}
```

Status codes: `400` malformed or missing parameters, `403` disabled feature,
`404` unknown endpoint or no match, `405` reserved, `409` no program open or a
conflicting state, `500` a Ghidra operation failed.

## Common parameters

| Parameter | Meaning |
|---|---|
| `address` | `0x401000`, `401000`, `ram:00401000`, or a symbol/function name. Anything that resolves is accepted. |
| `name` | A symbol or function name (case-insensitive fallback). |
| `offset`, `limit` | Pagination for list endpoints. |
| `timeout` | Decompiler timeout in seconds (default 60). |

## Endpoints

<!-- BEGIN GENERATED TABLE -->

### meta (7)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/_health` | Server liveness, port and open-program summary |
| `GET` | `/_ping` | Minimal liveness probe |
| `GET` | `/_tools` | List every bridge endpoint with its parameters |
| `GET` | `/info` | Program metadata: name, format, language, base address, hashes |
| `GET` | `/ping` | Alias of /_ping |
| `GET` | `/program/info` | Alias of /info |
| `GET` | `/program/summary` | Counts of functions, symbols, data types, strings and instructions |

### program (5)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/program/activate` | Make a named program the current one (for multi-program tools) |
| `POST` | `/program/open` | Open a program from the active project by its project path |
| `POST` | `/program/save` | Save the current program to its project |
| `GET` | `/programs` | List programs currently open in Ghidra |
| `GET` | `/project/files` | List files and folders in the active Ghidra project |

### memory (7)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/memory/block` | Details for one memory block by name or address |
| `GET` | `/memory/blocks` | Memory map: block names, address ranges, permissions, sizes |
| `GET` | `/memory/bytes` | Alias of /memory/read |
| `GET` | `/memory/read` | Read raw bytes as hex/ASCII (parameters: address, length) |
| `GET` | `/memory/search` | Search memory for hex bytes (e.g. bytes=488b05) or ASCII text (text=hello) |
| `GET` | `/memory/strings` | Alias of /strings (defined strings with addresses) |
| `GET` | `/segments` | Alias of /memory/blocks (legacy GhidraMCP shape) |

### function (25)

| Method | Path | Purpose |
|---|---|---|
| `GET/POST` | `/decompile` | Decompile a function by name or address and return C source |
| `GET/POST` | `/decompile_function` | Alias of /decompile (legacy) |
| `GET/POST` | `/disassemble` | Disassemble a function (name or address) to address/instruction/comment lines |
| `GET/POST` | `/disassemble_function` | Alias of /disassemble (legacy) |
| `GET` | `/functions` | List functions (compact records). Filters: name (substring), namespace, range |
| `POST` | `/functions/auto-analyze` | Run auto analysis over a function's body range |
| `GET` | `/functions/basic-blocks` | Basic blocks with their instruction ranges and successors |
| `GET` | `/functions/by-address` | Function containing an address |
| `GET` | `/functions/callees` | Functions called by a function (outgoing call graph, one level) |
| `GET` | `/functions/callers` | Functions that call a function (incoming call graph, one level) |
| `GET` | `/functions/callgraph` | Breadth-first call graph from a function (parameters: depth, direction) |
| `GET` | `/functions/count` | Number of functions in the program |
| `POST` | `/functions/create` | Create a function at an address (optionally from an explicit body range) |
| `POST` | `/functions/delete` | Delete a function, leaving its bytes in place |
| `GET` | `/functions/externals` | List external (imported) functions |
| `GET` | `/functions/list` | Alias of /functions |
| `GET` | `/functions/pcode` | P-code (intermediate representation) for a function |
| `POST` | `/functions/rename` | Rename a function (parameters: address|name, newName) |
| `GET` | `/functions/search` | Search functions by name substring, optionally including thunks/externals |
| `POST` | `/functions/set-comment` | Set a function comment (parameters: address|name, comment) |
| `POST` | `/functions/set-prototype` | Apply a C function prototype, e.g. 'int __cdecl f(char *s, int n)' |
| `POST` | `/functions/set-thunk` | Mark a function as a thunk of another function |
| `POST` | `/functions/tag` | Add a function tag to a function |
| `GET` | `/functions/thunks` | List thunk functions |
| `GET` | `/functions/{address}` | Full details for the function at an address or with a given name |

### variable (6)

| Method | Path | Purpose |
|---|---|---|
| `GET/POST` | `/variables` | List parameters and locals of a function (address|name) |
| `GET/POST` | `/variables/decompiler` | Decompiler symbol table for a function (names as shown in the C output) |
| `POST` | `/variables/rename` | Rename a parameter or local variable (function, oldName, newName) |
| `POST` | `/variables/retype` | Change a parameter or local variable's data type (function, variable, type) |
| `POST` | `/variables/set-comment` | Set a variable's comment |
| `POST` | `/variables/set-storage` | Retarget a local variable to an explicit location: register=EAX | stack=-8 | address=0x... (+ length) |

### symbol (21)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/exports` | Exported entry points |
| `GET` | `/imports` | Imported (external) symbols |
| `GET` | `/namespaces` | All non-global namespaces / classes |
| `POST` | `/namespaces/create` | Create a namespace (dot or / separated paths are nested automatically) |
| `GET` | `/references/strings` | Strings referenced from an address range or function |
| `GET` | `/symbols` | All symbols (paginated). Filters: name (substring), type, external |
| `GET` | `/symbols/at` | Symbols defined exactly at an address |
| `GET` | `/symbols/count` | Number of symbols |
| `POST` | `/symbols/create` | Create a label at an address (address|name, newName, namespace?) |
| `POST` | `/symbols/delete` | Delete a symbol by address (+ optional name) |
| `GET` | `/symbols/entrypoints` | Program entry points |
| `GET` | `/symbols/external-locations` | External locations (imports linking to libraries) |
| `POST` | `/symbols/import` | Add an imported (external) function, e.g. library=kernel32.dll name=CreateFileA |
| `POST` | `/symbols/rename` | Rename the symbol at an address (address, newName) |
| `GET` | `/symbols/search` | Search symbols whose name contains a substring |
| `POST` | `/symbols/set-external-entry` | Mark or unmark an address as an external entry point (export) |
| `POST` | `/symbols/set-primary` | Make a named symbol at an address the primary symbol |
| `GET` | `/xrefs` | All references to an address (alias of /xrefs/to) |
| `GET` | `/xrefs/from` | References from an address |
| `GET` | `/xrefs/function` | Call sites that reference a function (by name or address) |
| `GET` | `/xrefs/to` | References to an address or symbol name |

### data (14)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/data` | Defined data items. Filters: address range, type, minLength |
| `GET` | `/data/at` | The data item at an address, with its value |
| `POST` | `/data/create` | Define data at an address (address, type, optional length/count) |
| `POST` | `/data/delete` | Clear the data definition at an address (keeps the bytes) |
| `GET` | `/data/items` | Alias of /data |
| `GET` | `/data/read` | Read a primitive value at an address (type: byte|word|dword|qword|float|double|pointer) |
| `POST` | `/data/rename` | Set the label of the data at an address (legacy /renameData) |
| `POST` | `/data/retype` | Change the data type of the item at an address |
| `GET` | `/data/type` | Data type of the item at an address |
| `POST` | `/memory/fill` | Fill a range with a byte value (address, length, value) |
| `POST` | `/memory/write` | Patch bytes in memory (address, hex='90 90' or '9090'). Set clearCodeUnits=true to overwrite bytes that Ghidra currently models as an instruction or data item |
| `GET` | `/strings` | Defined strings with addresses. Filters: filter (substring), minLength, block |
| `GET` | `/strings/count` | Number of defined strings |
| `GET` | `/strings/search` | Alias of /strings with a filter |

### type (11)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/types` | List data types built into / defined in the program. Filters: name, category, kind |
| `POST` | `/types/c/parse` | Parse and install C declarations, e.g. 'struct S { int a; char b[8]; };' |
| `GET` | `/types/count` | Number of data types |
| `POST` | `/types/delete` | Remove a data type from the program (built-in types cannot be removed) |
| `GET` | `/types/detail` | Structure/union/enum layout: members with offsets, sizes and types |
| `POST` | `/types/enum/create` | Create an enum. values='RED=1,GREEN=2,BLUE=4' (values optional) |
| `GET` | `/types/resolve` | Check how a type name resolves, with suggestions when it does not |
| `GET` | `/types/search` | Search data types by name (substring) |
| `POST` | `/types/struct/create` | Create a structure. fields='int a, char *b' (a field with no name gets fieldN) |
| `POST` | `/types/typedef/create` | Create a typedef (name, baseType) |
| `POST` | `/types/union/create` | Create a union. fields='int a, char *b' |

### comment (8)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/comments` | All comments at an address (or on a function) |
| `POST` | `/comments/decompiler` | Set the comment shown in the decompiler (alias of kind=eol) |
| `POST` | `/comments/delete` | Delete a comment. kind=eol|pre|post|plate|repeatable (default eol) |
| `POST` | `/comments/disassembly` | Set the comment shown in the disassembly listing (alias of kind=eol) |
| `GET` | `/comments/function` | Every comment inside a function's body, in address order |
| `GET` | `/comments/history` | Comment change history at an address |
| `POST` | `/comments/plate` | Set the plate (banner) comment |
| `POST` | `/comments/set` | Set a comment. kind=eol|pre|post|plate|repeatable (default eol) |

### analysis (14)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/analysis/analyze-all` | Re-run auto analysis over the whole program (can take a long time) |
| `POST` | `/analysis/analyze-range` | Re-run auto analysis over an address range (address + length) |
| `POST` | `/analysis/clear` | Clear the instruction/data definitions in a range (address + length) |
| `POST` | `/analysis/create-function` | Ask Ghidra to create a function at an address (creating its body automatically) |
| `GET` | `/analysis/current` | Address and function currently selected in the Ghidra GUI |
| `POST` | `/analysis/disassemble` | Disassemble at an address, or over a range (address + length) |
| `POST` | `/analysis/goto` | Navigate the Ghidra GUI to an address or symbol name |
| `GET` | `/bookmarks` | List bookmarks |
| `POST` | `/bookmarks/create` | Create a bookmark (address, type=Note|Warning|Error|Info, category, comment) |
| `POST` | `/bookmarks/delete` | Delete bookmarks at an address (optionally filtered by type/category) |
| `GET` | `/bookmarks/types` | Bookmark types and their categories |
| `GET` | `/current_address` | Alias of /analysis/current (address only) |
| `GET` | `/current_function` | Alias of /analysis/current (function info) |
| `GET` | `/function-tags` | All function tags defined in the program |

### script (4)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/scripts` | List available GhidraScripts (name, extension, path, provider) |
| `POST` | `/scripts/execute` | Run a GhidraScript: name=MyScript (existing) or source=<code> with language=java|py |
| `GET` | `/scripts/providers` | Installed script providers (Java, Python, ...) |
| `GET/POST` | `/scripts/source` | Read the source of a script by name |

### legacy (17)

| Method | Path | Purpose |
|---|---|---|
| `GET/POST` | `/classes` | Legacy: namespace names with pagination |
| `GET/POST` | `/data_items` | Legacy: 'address: label = value' lines |
| `GET/POST` | `/function_xrefs` | Legacy: references to a function by name |
| `GET/POST` | `/get_function_by_address` | Legacy: function details for an address |
| `GET/POST` | `/list_functions` | Legacy: 'name at address' lines for every function |
| `GET/POST` | `/methods` | Legacy: function names with pagination (alias of /functions) |
| `GET/POST` | `/renameData` | Legacy: label the data at an address |
| `GET/POST` | `/renameFunction` | Legacy: rename a function by its current name |
| `GET/POST` | `/renameVariable` | Legacy: rename a local variable (functionName, oldName, newName) |
| `GET/POST` | `/rename_function_by_address` | Legacy: rename the function at an address |
| `GET/POST` | `/searchFunctions` | Legacy: substring search over function names |
| `GET/POST` | `/set_decompiler_comment` | Legacy: comment shown in the decompiler |
| `GET/POST` | `/set_disassembly_comment` | Legacy: comment shown in the disassembly listing |
| `GET/POST` | `/set_function_prototype` | Legacy: apply a C prototype to the function at an address |
| `GET/POST` | `/set_local_variable_type` | Legacy: change a local variable's type |
| `GET/POST` | `/xrefs_from` | Legacy/alias of /xrefs/from |
| `GET/POST` | `/xrefs_to` | Legacy/alias of /xrefs/to |

<!-- END GENERATED TABLE -->

## Notes on the mutating endpoints

Writes are the part of an API that can ruin someone's afternoon, so these
behaviours are deliberate:

* **Every mutation runs in a Ghidra transaction**, so a single undo step reverses
  it. In GUI mode it also runs on the Swing thread, which Ghidra's undo manager
  and model listeners require.
* **`/functions/set-prototype`** strips a calling-convention keyword
  (`__cdecl`, `__stdcall`, …) before parsing and applies it separately, because
  Ghidra's signature parser does not understand those keywords and reports
  "Can't resolve return type: int __cdecl". Both `int __cdecl f(char *s)` and
  `int f(char *s)` work.
* **`/variables/rename` and `/variables/retype`** work for both database
  variables and decompiler-only temporaries. For parameters they commit the
  prototype first when the decompiler's idea of it has diverged from the
  database's, otherwise the change is silently lost on the next decompile.
* **`/memory/write` refuses to overwrite defined code or data** and tells you to
  retry with `clearCodeUnits=true` — that flag discards the existing analysis, so
  it is opt-in rather than automatic.
* **`/types/struct/create`** etc. place new types under the `/mcp` category, which
  keeps agent-created types findable and separable from the program's own.
* **`/scripts/execute`** runs arbitrary code in the Ghidra JVM. Inline Java is
  wrapped in a generated `GhidraScript` subclass; the staging directory is
  registered as an OSGi bundle and cleaned up afterwards. It can be disabled
  host-side with `ApiContext.setScriptExecutionAllowed(false)`.

## Compatibility surface

The `legacy` category mirrors the original GhidraMCP HTTP API
(`/methods`, `/decompile` by text body, `/renameFunction`, `/renameData`,
`/renameVariable`, `/set_function_prototype`, `/set_local_variable_type`,
`/xrefs_to`, `/function_xrefs`, `/searchFunctions`, `/set_decompiler_comment`, …)
so existing prompts and clients keep working. Those handlers re-dispatch through
the modern routes rather than duplicating logic, so they cannot drift.
