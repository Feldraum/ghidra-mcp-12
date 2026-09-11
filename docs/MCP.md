# Using the MCP server

`mcp/ghidra_mcp_server.py` exposes the bridge as MCP tools. It is a thin,
stateless translator: it holds no Ghidra state and no copy of the endpoint list.

## Install

```powershell
pip install "mcp>=1.2.0,<2" requests
```

The script also carries PEP 723 inline metadata, so `uv run mcp/ghidra_mcp_server.py`
works without a manual install.

## Run

```powershell
python mcp\ghidra_mcp_server.py --ghidra-url http://127.0.0.1:8192
```

| Flag | Env var | Default | Meaning |
|---|---|---|---|
| `--ghidra-url` | `GHIDRA_MCP_URL` | `http://127.0.0.1:8192` | Where the bridge is listening |
| `--transport` | `GHIDRA_MCP_TRANSPORT` | `stdio` | `stdio`, `sse` or `streamable-http` |
| `--host` | `GHIDRA_MCP_HOST` | `127.0.0.1` | Bind address for HTTP transports |
| `--port` | `GHIDRA_MCP_PORT` | `8765` | Bind port for HTTP transports |
| `--timeout` | `GHIDRA_MCP_TIMEOUT` | `60` | Per-request bridge timeout (seconds) |

## Client configuration

**Claude Desktop** (`claude_desktop_config.json`) / **Claude Code** (`.mcp.json`):

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": ["D:\\桌面\\mini\\ghidra-mcp-12\\mcp\\ghidra_mcp_server.py"],
      "env": { "GHIDRA_MCP_URL": "http://127.0.0.1:8192" }
    }
  }
}
```

**Cursor** (`.cursor/mcp.json`) uses the same shape. For HTTP transports:

```json
{
  "mcpServers": {
    "ghidra": { "url": "http://127.0.0.1:8765/mcp" }
  }
}
```

## Tools

58 tools. The high-traffic ones:

| Tool | What it does |
|---|---|
| `ghidra_health` | Is Ghidra up, and is a program open? Call this first — it separates "not running" from "no program" |
| `get_program_info` / `get_program_summary` | Program metadata and analysis counts |
| `list_functions` / `search_functions` / `get_function` | Find functions and read their signatures, parameters, callers, callees |
| `decompile_function` | C code for a function (usually the highest-value call) |
| `disassemble_function` | Instructions with addresses and comments |
| `get_pcode` | Decompiler P-code, raw or SSA — for semantics the C output hides |
| `get_call_graph` / `get_basic_blocks` | Structure at a glance |
| `get_xrefs_to` / `get_xrefs_from` / `get_function_xrefs` | Follow references |
| `list_strings` / `search_memory` / `read_memory` / `read_value` | Find and read data |
| `rename_function` / `rename_symbol` / `rename_variable` | Label what you have understood |
| `set_function_prototype` / `set_variable_type` | Apply types so the decompiler output becomes readable |
| `create_struct` / `create_enum` / `parse_c_declarations` | Define types from C |
| `set_comment` / `create_bookmark` | Leave notes for the human |
| `run_script` | Run a GhidraScript, or inline Java/Python — the escape hatch |
| `ghidra_find_operations` / `ghidra_call` | Discover and invoke *any* of the 162 endpoints |

### Why `ghidra_find_operations` + `ghidra_call` exist

Wrapping all 162 endpoints as individual tools would be a maintenance liability
and would bury the useful ones. Instead the server exposes the ~58 operations
agents actually use as typed tools, and two generic ones:

```
ghidra_find_operations(keyword="xref")   ->  list of matching endpoints
ghidra_call(path="/xrefs/function", method="GET", params='{"name":"main"}')
```

That means the Python tool list can never fall behind the Java route table: a new
endpoint is reachable immediately, and discoverable by keyword.

## Error behaviour

Errors come back as text an agent can act on, never as a stack trace:

* bridge unreachable → "Cannot reach the Ghidra MCP bridge at … Is Ghidra running
  with the GhidraMCP12 plugin enabled?"
* no program open → the bridge's 409 message
* bad parameter → the bridge's 400 message, e.g. "unknown data type 'DWORD2'.
  Known examples: /int, /uint, /char …"

Errors are *returned*, not raised, so one failed call does not tear down the MCP
session.

## Suggested agent workflow

1. `ghidra_health` — confirm Ghidra and a program.
2. `get_program_info` + `get_program_summary` — what am I looking at?
3. `list_functions` / `search_functions` — find the interesting function.
4. `decompile_function` — read it. (`get_pcode` when the C is ambiguous.)
5. `get_xrefs_to` / `get_function_xrefs` — work outwards.
6. Rename and type as you go (`rename_function`, `rename_variable`,
   `set_function_prototype`, `create_struct`), so the next decompile is clearer.
7. `set_comment` / `create_bookmark` — record conclusions where the human will
   see them.

Because mutations go through Ghidra transactions, a wrong turn is one Ctrl-Z in
the GUI.

## Testing the server

```powershell
# with the bridge running
python tests\mcp_client_test.py
```

This drives the server over stdio with the official SDK and checks the handshake,
the tool surface, endpoint discovery, a real decompile round trip, and error
propagation.
