# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp>=1.2.0,<2", "requests>=2,<3"]
# ///
"""GhidraMCP12 - MCP server for Ghidra 12.1.3.

Translates Model Context Protocol tool calls into requests against the
GhidraMCP12 Ghidra extension's embedded HTTP/JSON API.

Why a separate server at all? Ghidra runs a JVM with its own class loader, and
speaking MCP over stdio from inside it would mean shipping an MCP implementation
inside the extension. Keeping the extension a plain HTTP service means the
transport can be Python (this file), or any other client, and the extension
itself stays dependency free.

Two families of tools are exposed:

* A small set of typed, well-described tools for the operations agents use most
  (decompile, disassemble, rename, retype, xrefs, ...).
* ``ghidra_find_operations`` / ``ghidra_call`` which discover and invoke *any*
  endpoint the bridge exposes. That keeps this file from having to duplicate the
  Java route table, so the two can never drift apart.

Configuration (environment variables, or CLI flags):

* ``GHIDRA_MCP_URL``   base URL of the bridge   (default http://127.0.0.1:8192)
* ``GHIDRA_MCP_HOST``  host to bind in HTTP mode (default 127.0.0.1)
* ``GHIDRA_MCP_PORT``  port to bind in HTTP mode (default 8765)
* ``GHIDRA_MCP_TRANSPORT``  ``stdio`` (default) or ``streamable-http`` / ``sse``
* ``GHIDRA_MCP_TIMEOUT``  per-request timeout in seconds (default 60)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any

import requests

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - guidance for a missing dependency
    sys.stderr.write(
        "ERROR: the 'mcp' package is required.\n"
        "Install it with:  pip install \"mcp>=1.2.0,<2\" requests\n"
    )
    raise

DEFAULT_URL = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8192")
DEFAULT_TIMEOUT = float(os.environ.get("GHIDRA_MCP_TIMEOUT", "60"))

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
log = logging.getLogger("ghidra-mcp")

mcp = FastMCP("ghidra-mcp")


class Settings:
    """Runtime configuration, set once in main().

    Held in an object rather than module-level globals reassigned via `global`:
    a `global` statement after the module has already read the name is a
    SyntaxError in Python, which turns a config tweak into a server that will not
    start at all.
    """

    url: str = DEFAULT_URL.rstrip("/")
    timeout: float = DEFAULT_TIMEOUT


settings = Settings()

# Cached endpoint index from /_tools, used by ghidra_find_operations.
_endpoint_cache: dict[str, Any] | None = None


# --------------------------------------------------------------------------- io


def _url(path: str) -> str:
    return f"{settings.url}/{path.lstrip('/')}"


def _request(method: str, path: str, params: dict | None = None,
             data: dict | None = None) -> tuple[bool, Any]:
    """Performs one bridge call.

    Returns ``(ok, payload)``. On failure ``payload`` is a human-readable string
    explaining what went wrong - an agent can act on "no program is open" or
    "connection refused", but not on a stack trace, so errors are returned rather
    than raised.
    """
    if params:
        params = {k: v for k, v in params.items() if v is not None}
    if data:
        data = {k: v for k, v in data.items() if v is not None}
    try:
        response = requests.request(method, _url(path), params=params, data=data,
                                    timeout=settings.timeout)
    except requests.exceptions.ConnectionError:
        return False, (f"Cannot reach the Ghidra MCP bridge at {settings.url}. "
                       "Is Ghidra running with the GhidraMCP12 plugin enabled "
                       "(or the headless server script started)?")
    except requests.exceptions.Timeout:
        return False, (f"The Ghidra MCP bridge did not answer within "
                       f"{settings.timeout:.0f}s. Large programs or a running "
                       "auto-analysis can cause this; retry, or raise GHIDRA_MCP_TIMEOUT.")
    except Exception as exc:  # noqa: BLE001 - surfaced to the agent verbatim
        return False, f"Request to the Ghidra MCP bridge failed: {exc}"

    body = response.text
    try:
        parsed = json.loads(body) if body else None
    except ValueError:
        parsed = body

    if response.ok:
        return True, parsed

    detail = parsed.get("error") if isinstance(parsed, dict) else body
    return False, f"HTTP {response.status_code} from {path}: {detail}"


def _pretty(payload: Any, compact: bool) -> str:
    if isinstance(payload, str):
        return payload
    if compact:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _get(path: str, params: dict | None = None, compact: bool = True) -> str:
    ok, payload = _request("GET", path, params=params)
    if not ok:
        return payload
    return _pretty(payload, compact)


def _post(path: str, data: dict | None = None, compact: bool = True) -> str:
    ok, payload = _request("POST", path, data=data)
    if not ok:
        return payload
    return _pretty(payload, compact)


# ------------------------------------------------------------- generic surface


@mcp.tool()
def ghidra_health() -> str:
    """Check that Ghidra and the MCP bridge are alive.

    Call this first. It distinguishes "Ghidra is not running" from "Ghidra is
    running but no program is open", and reports the bridge port and version.
    """
    ok, payload = _request("GET", "/_health")
    if not ok:
        return payload
    return _pretty(payload, compact=False)


@mcp.tool()
def ghidra_find_operations(keyword: str = "", category: str = "") -> str:
    """Search the bridge's endpoint index, e.g. keyword="decompile".

    Use this to discover capabilities beyond the convenience tools in this
    server, then call the endpoint with ghidra_call. Returns matching endpoints
    with their HTTP method, path and description.
    """
    global _endpoint_cache
    if _endpoint_cache is None:
        ok, payload = _request("GET", "/_tools")
        if not ok:
            return payload
        _endpoint_cache = payload
    if not isinstance(_endpoint_cache, dict):
        return "Unexpected response from /_tools."

    needle = keyword.lower().strip()
    want_cat = category.lower().strip()
    matches: list[str] = []
    for cat, entries in (_endpoint_cache.get("categories") or {}).items():
        if want_cat and want_cat not in cat.lower():
            continue
        for entry in entries or []:
            haystack = f"{entry.get('method','')} {entry.get('path','')} {entry.get('summary','')}".lower()
            if needle and needle not in haystack:
                continue
            matches.append(f"{entry.get('method','')} {entry.get('path','')} - {entry.get('summary','')}")
    if not matches:
        return (f"No endpoint matches keyword={keyword!r} category={category!r}. "
                f"Categories: {', '.join(sorted((_endpoint_cache.get('categories') or {}).keys()))}")
    return "\n".join(sorted(matches))


@mcp.tool()
def ghidra_call(path: str, method: str = "GET", params: str = "") -> str:
    """Call any bridge endpoint directly.

    Args:
        path: endpoint path, e.g. "/functions/search".
        method: "GET" or "POST".
        params: parameters as a JSON object string, e.g. '{"query":"main","limit":20}'.
    """
    try:
        parsed = json.loads(params) if params.strip() else {}
    except ValueError as exc:
        return f"params must be a JSON object: {exc}"
    if not isinstance(parsed, dict):
        return "params must be a JSON object, e.g. {\"query\": \"main\"}"
    if method.upper() == "POST":
        return _post(path, parsed)
    return _get(path, parsed)


# ------------------------------------------------------------------- programs


@mcp.tool()
def get_program_info() -> str:
    """Metadata for the current program: name, format, language, base, hashes."""
    return _get("/program/info")


@mcp.tool()
def get_program_summary() -> str:
    """Counts of functions, symbols, data types, strings and instructions."""
    return _get("/program/summary")


@mcp.tool()
def list_programs() -> str:
    """List programs currently open in Ghidra, marking the current one."""
    return _get("/programs")


@mcp.tool()
def list_memory_blocks() -> str:
    """The memory map: block names, address ranges, permissions and sizes."""
    return _get("/memory/blocks")


@mcp.tool()
def read_memory(address: str, length: int = 64) -> str:
    """Read raw bytes at an address, as hex, ASCII and 32-bit words."""
    return _get("/memory/read", {"address": address, "length": length})


@mcp.tool()
def read_value(address: str, type: str = "dword") -> str:
    """Read a typed value at an address.

    Args:
        address: target address, e.g. "0x140001040".
        type: one of byte, word, dword, qword, float, double, pointer, string.
    """
    return _get("/data/read", {"address": address, "type": type})


@mcp.tool()
def search_memory(text: str = "", hex_bytes: str = "") -> str:
    """Search the program's memory for text (ASCII) or a hex byte pattern.

    Args:
        text: ASCII text to look for, e.g. "config.ini".
        hex_bytes: hex byte pattern, e.g. "488b05" (even number of digits).
    """
    params = {}
    if text:
        params["text"] = text
    if hex_bytes:
        params["bytes"] = hex_bytes
    if not params:
        return "Provide either text or hex_bytes."
    return _get("/memory/search", params)


# ------------------------------------------------------------------ functions


@mcp.tool()
def list_functions(offset: int = 0, limit: int = 200, name: str = "",
                   namespace: str = "") -> str:
    """List functions with signatures and addresses (paginated).

    Args:
        offset: pagination offset.
        limit: maximum number of functions to return.
        name: optional case-insensitive substring filter on the function name.
        namespace: optional namespace/class filter.
    """
    return _get("/functions", {"offset": offset, "limit": limit,
                               "name": name or None,
                               "namespace": namespace or None})


@mcp.tool()
def search_functions(query: str, case_sensitive: bool = False,
                     offset: int = 0, limit: int = 200) -> str:
    """Search for functions whose name contains the given substring."""
    return _get("/functions/search", {"query": query, "offset": offset,
                                      "limit": limit,
                                      "caseSensitive": str(case_sensitive).lower()})


@mcp.tool()
def get_function(address: str = "", name: str = "") -> str:
    """Full details of one function: signature, parameters, locals, callers, callees.

    Args:
        address: function entry address or any address inside it.
        name: function name (used when address is not given).
    """
    target = address or name
    if not target:
        return "Provide either address or name."
    return _get("/functions/by-address" if address else "/functions/" + target,
                {"address": address} if address else None)


@mcp.tool()
def decompile_function(address: str = "", name: str = "", timeout: int = 60) -> str:
    """Decompile a function and return its C code plus parameters and locals.

    This is usually the highest-value call: pass either the entry address or the
    function name.

    Args:
        address: function address, e.g. "0x140001000".
        name: function name, e.g. "mc_add".
        timeout: decompiler timeout in seconds.
    """
    target = address or name
    if not target:
        return "Provide either address or name."
    return _post("/decompile", {"address": address or None, "name": name or None,
                                "timeout": timeout})


@mcp.tool()
def disassemble_function(address: str = "", name: str = "", include_bytes: bool = False) -> str:
    """Disassemble a function into address/instruction/comment lines.

    Args:
        address: function address.
        name: function name.
        include_bytes: include the raw instruction bytes.
    """
    target = address or name
    if not target:
        return "Provide either address or name."
    return _post("/disassemble", {"address": address or None, "name": name or None,
                                  "bytes": str(include_bytes).lower()})


@mcp.tool()
def get_pcode(address: str = "", name: str = "", ssa: bool = False) -> str:
    """Return a function's P-code (Ghidra's intermediate representation).

    Useful for reasoning about semantics that the C output obscures.

    Args:
        ssa: request SSA form (decompiler-derived) rather than raw instruction P-code.
    """
    target = address or name
    if not target:
        return "Provide either address or name."
    return _get("/functions/pcode", {"address": address or None, "name": name or None,
                                     "ssa": str(ssa).lower()})


@mcp.tool()
def get_call_graph(address: str = "", name: str = "", direction: str = "callees",
                   depth: int = 2) -> str:
    """Breadth-first call graph around a function.

    Args:
        direction: "callees" (what it calls) or "callers" (who calls it).
        depth: how many levels to follow (1-6).
    """
    target = address or name
    if not target:
        return "Provide either address or name."
    return _get("/functions/callgraph", {"address": address or None,
                                         "name": name or None,
                                         "direction": direction, "depth": depth})


@mcp.tool()
def get_basic_blocks(address: str = "", name: str = "") -> str:
    """Basic blocks of a function with their instruction ranges."""
    target = address or name
    if not target:
        return "Provide either address or name."
    return _get("/functions/basic-blocks", {"address": address or None, "name": name or None})


@mcp.tool()
def rename_function(address: str = "", name: str = "", old_name: str = "",
                    new_name: str = "") -> str:
    """Rename a function.

    Args:
        address: function address (preferred).
        name: current function name (alternative to address).
        old_name: alias of name, matching the original GhidraMCP API.
        new_name: the new name.
    """
    target = address or name or old_name
    if not target or not new_name:
        return "Provide the function (address/name/old_name) and new_name."
    return _post("/functions/rename", {"address": address or None,
                                       "name": name or old_name or None,
                                       "newName": new_name})


@mcp.tool()
def set_function_prototype(address: str = "", name: str = "", prototype: str = "") -> str:
    """Apply a C prototype to a function, e.g. "int __cdecl mc_add(int a, int b)".

    Args:
        prototype: the full C declaration; unknown type names are the usual
            cause of a failure and the error lists suggestions.
    """
    target = address or name
    if not target or not prototype:
        return "Provide the function (address/name) and the prototype."
    return _post("/functions/set-prototype", {"address": address or None,
                                              "name": name or None,
                                              "prototype": prototype})


@mcp.tool()
def set_function_comment(address: str = "", name: str = "", comment: str = "") -> str:
    """Set the comment shown on a function (in the listing and decompiler)."""
    target = address or name
    if not target:
        return "Provide the function (address/name)."
    return _post("/functions/set-comment", {"address": address or None,
                                            "name": name or None,
                                            "comment": comment})


@mcp.tool()
def create_function(address: str, name: str = "") -> str:
    """Create a function at an address, letting Ghidra determine its body."""
    return _post("/functions/create", {"address": address, "name": name or None})


@mcp.tool()
def delete_function(address: str = "", name: str = "") -> str:
    """Delete a function (its bytes remain in the listing)."""
    target = address or name
    if not target:
        return "Provide either address or name."
    return _post("/functions/delete", {"address": address or None, "name": name or None})


# ------------------------------------------------------------------ variables


@mcp.tool()
def list_variables(address: str = "", name: str = "") -> str:
    """Parameters and local variables of a function, plus decompiler symbols."""
    target = address or name
    if not target:
        return "Provide either address or name."
    return _get("/variables", {"address": address or None, "name": name or None})


@mcp.tool()
def rename_variable(function_address: str = "", function_name: str = "",
                    old_name: str = "", new_name: str = "") -> str:
    """Rename a parameter or local variable inside a function.

    Works for both database variables and decompiler-only temporaries.
    """
    target = function_address or function_name
    if not target or not old_name or not new_name:
        return "Provide the function, old_name and new_name."
    return _post("/variables/rename", {"function": target, "oldName": old_name,
                                       "newName": new_name})


@mcp.tool()
def set_variable_type(function_address: str = "", function_name: str = "",
                      variable_name: str = "", new_type: str = "") -> str:
    """Change a variable's data type, e.g. new_type="MyStruct *" or "char[16]"."""
    target = function_address or function_name
    if not target or not variable_name or not new_type:
        return "Provide the function, variable_name and new_type."
    return _post("/variables/retype", {"function": target, "variable": variable_name,
                                       "type": new_type})


# ------------------------------------------------------- symbols and references


@mcp.tool()
def list_symbols(offset: int = 0, limit: int = 500, name: str = "",
                 type: str = "", external: bool = False) -> str:
    """List symbols (paginated), optionally filtered by name substring or type."""
    return _get("/symbols", {"offset": offset, "limit": limit,
                             "name": name or None, "type": type or None,
                             "external": str(external).lower()})


@mcp.tool()
def search_symbols(query: str, limit: int = 500) -> str:
    """Search symbols whose name contains a substring."""
    return _get("/symbols/search", {"query": query, "limit": limit})


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 500) -> str:
    """List namespaces/classes in the program."""
    return _get("/namespaces", {"offset": offset, "limit": limit})


@mcp.tool()
def list_imports(offset: int = 0, limit: int = 1000) -> str:
    """List imported (external) symbols and the libraries they come from."""
    return _get("/symbols/external-locations", {"offset": offset, "limit": limit})


@mcp.tool()
def list_exports(offset: int = 0, limit: int = 500) -> str:
    """List exported entry points."""
    return _get("/exports", {"offset": offset, "limit": limit})


@mcp.tool()
def get_xrefs_to(address: str = "", name: str = "", offset: int = 0,
                 limit: int = 500) -> str:
    """Everything that references an address or symbol (incoming references)."""
    target = address or name
    if not target:
        return "Provide either address or name."
    return _get("/xrefs/to", {"address": address or None, "name": name or None,
                              "offset": offset, "limit": limit})


@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 500) -> str:
    """Everything an address references (outgoing references)."""
    return _get("/xrefs/from", {"address": address, "offset": offset, "limit": limit})


@mcp.tool()
def get_function_xrefs(address: str = "", name: str = "", limit: int = 500) -> str:
    """Call sites that reference a function."""
    target = address or name
    if not target:
        return "Provide either address or name."
    return _get("/xrefs/function", {"address": address or None, "name": name or None,
                                    "limit": limit})


@mcp.tool()
def rename_symbol(address: str, new_name: str) -> str:
    """Rename (or create) the label at an address."""
    return _post("/symbols/rename", {"address": address, "newName": new_name})


@mcp.tool()
def create_symbol(address: str, new_name: str, namespace: str = "") -> str:
    """Create a label at an address, optionally inside a namespace."""
    return _post("/symbols/create", {"address": address, "newName": new_name,
                                     "namespace": namespace or None})


@mcp.tool()
def create_namespace(name: str) -> str:
    """Create a namespace; dot, slash and :: separated paths nest automatically."""
    return _post("/namespaces/create", {"name": name})


# --------------------------------------------------------------- data and types


@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = "") -> str:
    """List defined strings with their addresses; filter matches the content."""
    return _get("/strings", {"offset": offset, "limit": limit,
                             "filter": filter or None})


@mcp.tool()
def list_data(offset: int = 0, limit: int = 500, type: str = "") -> str:
    """List defined data items with their types and values."""
    return _get("/data", {"offset": offset, "limit": limit, "type": type or None})


@mcp.tool()
def list_data_types(offset: int = 0, limit: int = 1000, name: str = "",
                    category: str = "") -> str:
    """List data types available in the program."""
    return _get("/types", {"offset": offset, "limit": limit,
                           "name": name or None, "category": category or None})


@mcp.tool()
def get_data_type_detail(name: str) -> str:
    """Structure/union/enum layout: members with offsets, sizes and types."""
    return _get("/types/detail", {"name": name})


@mcp.tool()
def create_struct(name: str, fields: str) -> str:
    """Create a structure definition.

    Args:
        name: struct name.
        fields: comma separated "type name" pairs, e.g. "int count, char *name, char buf[16]".
    """
    return _post("/types/struct/create", {"name": name, "fields": fields})


@mcp.tool()
def create_enum(name: str, values: str = "", size: int = 4) -> str:
    """Create an enum. values is "NAME=1,OTHER=2"; omitted values auto-increment."""
    return _post("/types/enum/create", {"name": name, "values": values, "size": size})


@mcp.tool()
def parse_c_declarations(source: str) -> str:
    """Parse and install C declarations, e.g. "struct S { int a; char b[8]; };"."""
    return _post("/types/c/parse", {"source": source})


@mcp.tool()
def retype_data(address: str, type: str) -> str:
    """Change the data type of the item at an address."""
    return _post("/data/retype", {"address": address, "type": type})


@mcp.tool()
def define_data(address: str, type: str, length: int = 0) -> str:
    """Define data at an address (type may need an explicit length, e.g. undefined)."""
    return _post("/data/create", {"address": address, "type": type,
                                  "length": length or None})


@mcp.tool()
def patch_bytes(address: str, hex_bytes: str) -> str:
    """Write bytes into the program (analysis/patching).

    Args:
        hex_bytes: hex byte string, e.g. "90 90" or "9090".
    """
    return _post("/memory/write", {"address": address, "hex": hex_bytes})


# ------------------------------------------------------------------- comments


@mcp.tool()
def get_comments(address: str) -> str:
    """All comments attached to an address."""
    return _get("/comments", {"address": address})


@mcp.tool()
def set_comment(address: str, comment: str, kind: str = "eol") -> str:
    """Set a comment at an address.

    Args:
        kind: eol (trailing, also visible in the decompiler), pre (block above),
            post (block below), plate (banner) or repeatable.
    """
    return _post("/comments/set", {"address": address, "comment": comment,
                                   "kind": kind})


@mcp.tool()
def list_function_comments(address: str = "", name: str = "") -> str:
    """Every comment inside a function's body."""
    target = address or name
    if not target:
        return "Provide either address or name."
    return _get("/comments/function", {"address": address or None, "name": name or None})


# ------------------------------------------------------ analysis, nav, bookmarks


@mcp.tool()
def get_current_location() -> str:
    """What the human is currently looking at in the Ghidra GUI."""
    return _get("/analysis/current", compact=False)


@mcp.tool()
def goto_address(address: str) -> str:
    """Navigate the Ghidra GUI to an address or symbol name."""
    return _post("/analysis/goto", {"address": address})


@mcp.tool()
def disassemble_range(address: str, length: int = 16) -> str:
    """Disassemble at an address, or over length bytes."""
    return _post("/analysis/disassemble", {"address": address, "length": length})


@mcp.tool()
def analyze_range(address: str, length: int = 16) -> str:
    """Re-run auto analysis over an address range."""
    return _post("/analysis/analyze-range", {"address": address, "length": length})


@mcp.tool()
def list_bookmarks(type: str = "") -> str:
    """List bookmarks, optionally filtered by type (Note, Warning, Error, Info)."""
    return _get("/bookmarks", {"type": type or None})


@mcp.tool()
def create_bookmark(address: str, comment: str, type: str = "Note",
                    category: str = "GhidraMCP12") -> str:
    """Create a bookmark at an address."""
    return _post("/bookmarks/create", {"address": address, "comment": comment,
                                       "type": type, "category": category})


# ------------------------------------------------------------------- scripting


@mcp.tool()
def list_scripts(name: str = "") -> str:
    """List available GhidraScripts (Java and any installed script providers)."""
    return _get("/scripts", {"name": name or None})


@mcp.tool()
def run_script(name: str = "", source: str = "", language: str = "java",
               args: str = "") -> str:
    """Run a GhidraScript - the escape hatch for analysis with no dedicated tool.

    Args:
        name: name of an existing script (see list_scripts).
        source: inline code to run instead, e.g. a short Java or Python script.
        language: "java" or "py" (requires the matching script provider).
        args: comma separated arguments exposed to the script.
    """
    if not name and not source:
        return "Provide either name (existing script) or source (inline code)."
    return _post("/scripts/execute", {"name": name or None, "source": source or None,
                                      "language": language, "args": args or None})


# ------------------------------------------------------------------------ main


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MCP server bridging to the GhidraMCP12 Ghidra extension")
    parser.add_argument("--ghidra-url", default=DEFAULT_URL,
                        help=f"base URL of the Ghidra bridge (default {DEFAULT_URL})")
    parser.add_argument("--transport", default=os.environ.get("GHIDRA_MCP_TRANSPORT", "stdio"),
                        choices=["stdio", "sse", "streamable-http"],
                        help="MCP transport (default stdio)")
    parser.add_argument("--host", default=os.environ.get("GHIDRA_MCP_HOST", "127.0.0.1"),
                        help="host to bind in HTTP transports")
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("GHIDRA_MCP_PORT", "8765")),
                        help="port to bind in HTTP transports")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="per-request bridge timeout in seconds")
    parsed = parser.parse_args()

    settings.url = parsed.ghidra_url.rstrip("/")
    settings.timeout = parsed.timeout
    mcp.settings.host = parsed.host
    mcp.settings.port = parsed.port

    log.warning("GhidraMCP12 bridge: %s (transport=%s)", settings.url, parsed.transport)
    mcp.run(transport=parsed.transport)


if __name__ == "__main__":
    main()
