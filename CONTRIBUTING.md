# Contributing

Thanks for taking a look. This is a small, focused project: one Ghidra extension,
one MCP server, and a test suite that runs against a real Ghidra installation.

## Getting set up

```powershell
git clone <this repo>
cd ghidra-mcp-12

# Build the extension (offline; needs only a JDK 21+ and a Ghidra 12.1.3 install)
powershell -File tools\build.ps1 -GhidraDir "C:\path\to\ghidra_12.1.3_PUBLIC"

# Install it, then restart Ghidra and enable the plugin once:
#   File > Configure > Developer > GhidraMCP12
powershell -File tools\install.ps1 -GhidraDir "C:\path\to\ghidra_12.1.3_PUBLIC"

# MCP server
pip install "mcp>=1.2.0,<2" requests
python mcp\ghidra_mcp_server.py
```

Both `-GhidraDir` values default to a machine-specific path, so pass your own.

## Before opening a pull request

Run the checks that apply to what you changed:

| Change | Run |
|---|---|
| Any Java | `powershell -File tools\build.ps1` — fails on warnings |
| `util/Json*` | `powershell -File tools\test-json.ps1` |
| Any endpoint or handler | `powershell -File tools\e2e.ps1` |
| `mcp/ghidra_mcp_server.py` | `python tests\mcp_client_test.py` (bridge must be running) |

`tools\build.ps1` compiles with `-Werror` on the warning categories this project
controls (`deprecation`, `unchecked`, `rawtypes`, …), so a clean build is a hard
requirement. If you add a deprecation, say why in the PR.

## Adding an endpoint

1. Add the route in the relevant `handlers/*.java` class. Prefer going through
   `ApiContext.read` / `readJson` / `mutate` / `mutateJson` rather than touching
   Ghidra directly — that is what keeps locking, transactions and the Swing
   dispatch correct.
2. Use `router.lookup(...)` for a parameterised read (`GET` and `POST` both work)
   and `router.post(...)` for anything that mutates.
3. Throw `ApiException` with a message an agent can act on. Include suggestions
   when a lookup fails; "not found" alone is not useful to a client.
4. Extend `tools\test_endpoints.ps1` so the new endpoint is covered. Every
   endpoint is swept automatically, but content checks are hand-written and that
   is where real regressions get caught.
5. If the endpoint should be a first-class MCP tool, add a wrapper in
   `mcp/ghidra_mcp_server.py`. Otherwise it is already reachable through
   `ghidra_call` and discoverable through `ghidra_find_operations` — do not add a
   tool just for symmetry.

## Adding a data type or symbol operation

`api/Types.java` and `api/Lookup.java` are the shared resolution layers. Extend
those rather than writing a fourth private "find a type by name" helper: the
original inconsistency (some endpoints accepting `0x401000`, others only
`00401000`, most not resolving names at all) came from exactly that.

## Style

The code follows Ghidra's conventions: **tabs** for indentation, 100-column
lines, no wildcard imports, Javadoc on anything non-obvious. Comments should
explain *why* a thing is the way it is — especially where the reason is a Ghidra
quirk, because that is the knowledge that is expensive to rediscover.

Windows-specific traps are documented in the scripts that work around them
(`tools/build.ps1`, `tools/e2e.ps1`). Read those comments before changing how
arguments or paths are passed.

## Reporting a bug

A useful report includes:

* Ghidra version (`Help > About`) and JDK version
* output of `curl.exe http://127.0.0.1:8192/_health`
* the failing request — method, path and parameters
* if a request hangs or returns something unexpected, a trace: set
  **Edit → Tool Options → GhidraMCP12 → Debug Log File** to a path, reproduce,
  and include the tail of that file

## License

By contributing you agree your contribution is licensed under the Apache License
2.0, as described in [LICENSE](LICENSE).
