# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
For a Ghidra extension the version also tracks the Ghidra release it targets, so
`1.0.0` means "built and verified against Ghidra 12.1.3".

## [Unreleased]

Nothing yet.

## [1.0.0] — 2026-09-11

First release. Targets **Ghidra 12.1.3** and requires **JDK 21+**.

### Added

- **Ghidra extension** (`GhidraMCPPlugin`) serving a dependency-free HTTP/JSON API
  on loopback, with tool options for port, bind address, remote binding, autostart
  and an optional request trace.
  - 162 endpoints over 12 categories: programs and memory, functions,
    decompilation and disassembly, P-code, symbols and references, data,
    data types, variables, comments, analysis, scripting, and a compatibility
    surface for the original GhidraMCP API.
  - `GET /_tools` exposes the complete endpoint index at runtime.
  - All mutations run inside a Ghidra transaction on the Swing thread, so each is
    a single undo step.
  - Cached per-program `DecompInterface` and symbol/type index, both invalidated
    by program modification number.
  - Hand-written JSON writer and parser, covered by JUnit tests, so the extension
    pulls in no third-party libraries.
- **MCP server** (`mcp/ghidra_mcp_server.py`) exposing 58 typed tools over stdio,
  SSE or streamable HTTP, plus `ghidra_find_operations` and `ghidra_call` for
  reaching any endpoint by discovery.
- **Build paths**: an offline `javac`/`jar` build that validates its own output
  (`tools/build.ps1`), and the official Gradle `buildExtension` path.
- **Verification**: unit tests for the JSON layer, an end-to-end sweep that
  exercises every endpoint against a real Ghidra session, and an MCP client test
  that drives the server through the official SDK.
- Documentation: installation and troubleshooting, MCP client setup, a complete
  endpoint reference generated from the live route table, and architecture notes.

[Unreleased]: https://github.com/Feldraum/ghidra-mcp-12/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Feldraum/ghidra-mcp-12/releases/tag/v1.0.0
