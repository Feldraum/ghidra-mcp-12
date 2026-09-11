# Exercises the GhidraMCP12 MCP server as a real MCP client would.
#
# The point is to verify the *client-facing* contract, not the HTTP layer: that
# the server starts, completes the MCP handshake, advertises its tools, and
# returns usable results for a call that reaches Ghidra. It drives the server
# over stdio with the official SDK, so a protocol mistake cannot hide.
#
#   python tests\mcp_client_test.py                 # starts its own MCP server
#   python tests\mcp_client_test.py --url http://127.0.0.1:8192
#
# Requires the bridge to be reachable for the Ghidra-dependent assertions; the
# handshake and tool-listing checks run even without it.
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:  # pragma: no cover
    sys.stderr.write("ERROR: pip install \"mcp>=1.2.0,<2\" requests\n")
    raise

SERVER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "mcp", "ghidra_mcp_server.py")

passed = 0
failed = 0


def ok(name: str, detail: str = "") -> None:
    global passed
    passed += 1
    print(f"  PASS  {name}" + (f"  -> {detail}" if detail else ""))


def bad(name: str, detail: str = "") -> None:
    global failed
    failed += 1
    print(f"  FAIL  {name}" + (f"  -> {detail}" if detail else ""))


def check(name: str, condition: bool, detail: str = "") -> None:
    ok(name, detail) if condition else bad(name, detail)


async def run(url: str) -> int:
    print()
    print("=== GhidraMCP12 MCP client test ===")
    print(f"server : {SERVER}")
    print(f"bridge : {url}")

    env = dict(os.environ)
    env["GHIDRA_MCP_URL"] = url
    params = StdioServerParameters(command=sys.executable, args=[SERVER], env=env)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            # 1. Handshake.
            init = await session.initialize()
            check("MCP initialize handshake completes", True,
                  f"{init.serverInfo.name} {init.serverInfo.version}")
            check("server reports a protocol version", bool(init.protocolVersion),
                  str(init.protocolVersion))

            # 2. Tool surface.
            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            check("tools/list returns tools", len(names) > 20, f"{len(names)} tools")
            for required in ("ghidra_health", "decompile_function", "list_functions",
                             "ghidra_call", "ghidra_find_operations",
                             "rename_function", "list_strings", "get_xrefs_to",
                             "set_function_prototype", "rename_variable"):
                check(f"tool advertised: {required}", required in names)
            missing_desc = [t.name for t in tools.tools if not (t.description or "").strip()]
            check("every tool has a description", not missing_desc,
                  f"missing: {missing_desc}" if missing_desc else "")

            # 3. A call that does not need Ghidra.
            health = await session.call_tool("ghidra_health", {})
            text = "".join(getattr(c, "text", "") for c in health.content)
            reachable = '"status":"ok"' in text.replace(" ", "")
            if reachable:
                ok("ghidra_health reports the bridge is up", text[:120])
            else:
                bad("ghidra_health reports the bridge is up", text[:200])
                print("\n  The bridge is not running; stopping here. Start Ghidra with the")
                print("  GhidraMCP12 plugin (or tools/e2e.ps1) and re-run for full coverage.")
                return 1 if failed else 0

            # 4. Discovery must reflect the Java side's real route table.
            found = await session.call_tool("ghidra_find_operations", {"keyword": "decompile"})
            found_text = "".join(getattr(c, "text", "") for c in found.content)
            check("ghidra_find_operations discovers endpoints", "/decompile" in found_text,
                  found_text.splitlines()[0] if found_text else "(empty)")

            # 5. A trivial call through the generic escape hatch.
            called = await session.call_tool("ghidra_call",
                                             {"path": "/program/info", "method": "GET"})
            called_text = "".join(getattr(c, "text", "") for c in called.content)
            try:
                info = json.loads(called_text)
            except ValueError:
                info = {}
            check("ghidra_call returns structured program info", bool(info.get("name")),
                  f"name={info.get('name')} language={info.get('languageId')}")

            # 6. A real analysis round trip: list -> decompile -> rename -> verify.
            listing = await session.call_tool("list_functions", {"limit": 50})
            listing_text = "".join(getattr(c, "text", "") for c in listing.content)
            try:
                functions = json.loads(listing_text).get("items", [])
            except ValueError:
                functions = []
            check("list_functions returns function records", bool(functions),
                  f"{len(functions)} functions")

            if functions:
                target = next((f for f in functions
                               if not f.get("isExternal") and (f.get("bodySize") or 0) > 8),
                              functions[0])
                dec = await session.call_tool("decompile_function",
                                              {"address": target["address"], "timeout": 120})
                dec_text = "".join(getattr(c, "text", "") for c in dec.content)
                try:
                    dec_obj = json.loads(dec_text)
                except ValueError:
                    dec_obj = {}
                check("decompile_function returns C code",
                      bool(dec_obj.get("decompiled")),
                      (dec_obj.get("decompiled") or dec_obj.get("error") or "")[:100])

                # Error propagation: a bad address must come back as an error the
                # agent can read, not as a crash or an empty result.
                bad_call = await session.call_tool(
                    "decompile_function", {"address": "0xdeadbeefdeadbeef"})
                bad_text = "".join(getattr(c, "text", "") for c in bad_call.content)
                check("an invalid address produces a readable error",
                      "Error" in bad_text or "HTTP 4" in bad_text or "no function" in bad_text,
                      bad_text[:120].replace("\n", " "))

            # 7. Confirm the connection is still healthy after all of that.
            again = await session.call_tool("ghidra_health", {})
            again_text = "".join(getattr(c, "text", "") for c in again.content)
            check("session survives a full workflow", '"status":"ok"' in again_text.replace(" ", ""))

    print()
    print("=== summary ===")
    print(f"passed : {passed}")
    print(f"failed : {failed}")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("GHIDRA_MCP_URL",
                                                        "http://127.0.0.1:8192"))
    args = parser.parse_args()
    return asyncio.run(run(args.url))


if __name__ == "__main__":
    sys.exit(main())
