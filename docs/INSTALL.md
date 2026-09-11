# Installing GhidraMCP12

Verified against Ghidra **12.1.3** (PUBLIC) on Windows with JDK 26 building for
`--release 21`.

## 1. Requirements

| Requirement | Notes |
|---|---|
| Ghidra 12.1.3 | Built and verified against `ghidra_12.1.3_PUBLIC`. Ghidra's `application.properties` sets `application.java.compiler=21`. |
| JDK 21 or newer | Ghidra 12 requires JDK 21 to run. JDK 26 is what was used here; there is no maximum. |
| A Ghidra project | The plugin needs an open program to be useful. It starts without one and reports that state, so you can verify the install first. |
| Python 3.10+ and `mcp>=1.2.0,<2`, `requests` | Only for the MCP server. The extension itself needs no Python. |

## 2. Build the extension

### Option A — offline, no Gradle (recommended here)

```powershell
powershell -File tools\build.ps1
```

This compiles `src/main/java` against the Ghidra jars, packages
`dist\ghidra_12.1.3_PUBLIC_<date>_GhidraMCP12.zip`, and runs
`tools\verify_zip.ps1` on the result. It needs no network and no Gradle.

Options:

```powershell
# explicit paths, and install into Ghidra in one step
powershell -File tools\build.ps1 -GhidraDir "D:\zstudytools\ghidra_12.1.3_PUBLIC" `
    -JdkHome "D:\java\jdk-26" -Install
```

### Option B — official Gradle build

```powershell
$env:GHIDRA_INSTALL_DIR = "D:\zstudytools\ghidra_12.1.3_PUBLIC"
& "$env:GHIDRA_INSTALL_DIR\support\gradle\gradlew.bat" -p . buildExtension
```

The Gradle wrapper needs to download its distribution the first time (~140 MB).
On a slow connection that can take a very long time; the offline path exists for
exactly that reason.

`gradle.properties` already sets `GHIDRA_INSTALL_DIR`, and the build script
applies `<install>/support/buildExtension.gradle`, which is the authoritative
recipe: it applies `java-library` itself and globs every jar under the install's
`Framework`, `Features`, `Debug` and `Processors` directories. Do not add a
`dependencies` block enumerating Ghidra jars, and do not apply the `java` plugin
yourself.

## 3. Install into Ghidra

```powershell
powershell -File tools\install.ps1
```

This extracts the zip to `<GhidraDir>\Ghidra\Extensions\GhidraMCP12` as a **module
directory**. That form is used rather than leaving the zip in `Extensions\Ghidra`
because both the GUI and `analyzeHeadless` discover extensions by scanning for
`Module.manifest` plus a `lib/` directory, and the extracted form works in both
without a separate registration step.

Only one copy may be installed: two extensions defining the same plugin class
make `ClassSearcher` log a conflict and pick one arbitrarily. To remove it:

```powershell
powershell -File tools\install.ps1 -Uninstall
```

A GUI installation is also supported: **File → Install Extensions → +** and pick
the zip. That path extracts into `<UserSettings>\Extensions` instead and applies
Ghidra's own version compatibility check.

## 4. Enable the plugin

1. Start Ghidra and open a program (the plugin needs a program to be useful, but
   it starts without one and reports that state).
2. **File → Configure → Developer → GhidraMCP12**.
3. Check the log for `GhidraMCP12 HTTP server listening on http://127.0.0.1:8192/`.

Options live under **Edit → Tool Options → GhidraMCP12**:

| Option | Default | Meaning |
|---|---|---|
| `Server Port` | `8192` | TCP port. Restart the plugin/tool after changing it. |
| `Bind Address` | `127.0.0.1` | Interface to bind. |
| `Allow Remote Connections` | `false` | Must be enabled to bind a non-loopback address. **Anyone who can reach the port can read and modify your programs.** |
| `Start Server On Launch` | `true` | Start the server when the plugin loads. |
| `Debug Log File` | *(empty)* | Optional path for a one-line trace of every request and response. Leave empty normally; set it when a call hangs or returns something unexpected. |

Confirm it is alive:

```powershell
curl.exe http://127.0.0.1:8192/_health
# {"status":"ok","port":8192,...,"currentProgram":"target.exe",...}
```

`/_health` answers even with no program open, which is what distinguishes
"Ghidra is not running" from "Ghidra is running but has no program open".

The bridge is reachable for as long as Ghidra is open. There is no separate
start/stop action: closing Ghidra, disabling the plugin, or setting
`Start Server On Launch` to false and restarting the tool all stop it.

## 5. Run the MCP server

```powershell
pip install "mcp>=1.2.0,<2" requests
python mcp\ghidra_mcp_server.py --ghidra-url http://127.0.0.1:8192
```

It speaks MCP over stdio by default. See [MCP.md](MCP.md) for client
configuration and the HTTP/SSE transport.

## 7. Verify the installation

```powershell
powershell -File tools\verify_zip.ps1      # archive layout Ghidra will accept
powershell -File tools\test-json.ps1       # JSON layer unit tests
powershell -File tools\e2e.ps1             # full endpoint sweep against real Ghidra
python tests\mcp_client_test.py            # MCP protocol + tool surface
```

## Troubleshooting

**The plugin never appears in Configure.**
`data/ExtensionPoint.manifest` is missing from the archive. Ghidra discovers
plugins by matching class-name suffixes listed in that file; without a `Plugin`
line the extension installs and is silently never loaded.
Check with `powershell -File tools\verify_zip.ps1`.

**`Module manifest file error ... Invalid line encountered: GHIDRA_MODULE_NAME=...`**
The legacy `Module.manifest` keys are not valid in Ghidra 12. Use the modern
format (see this project's `Module.manifest`).

**`File > Install Extensions` does not accept the zip.**
The archive layout is wrong. Ghidra's loader only accepts an
`extension.properties` whose path splits into **exactly two** parts on `/`
(`Name/extension.properties`). An extra top-level directory, or backslash
separators, makes the archive invisible. `tools\verify_zip.ps1` checks all of
this.

**A request hangs with no response.**
Set **Edit → Tool Options → GhidraMCP12 → Debug Log File** to a path, reproduce,
and look at where the trace stops — it records the request, each stage, and the
response size, so the last line tells you which stage blocked. The most common
historical cause was reading a request body the client never sent (a
`Content-Length`-less GET), which deadlocks against a client waiting for the
response; the reader is now keyed off `Content-Length`.

**`no installed script provider for language 'java'`** — check what is installed:
`curl.exe http://127.0.0.1:8192/scripts/providers`. Java and Python scripting ship
with Ghidra; `.py` scripts use the PyGhidra bundle.

**Patching memory fails with "Memory change conflicts with instruction at …".**
Ghidra refuses to overwrite bytes it currently models as an instruction or data
item. Retry with `clearCodeUnits=true`, which clears those definitions first —
that discards the existing analysis for the range, so it is opt-in rather than
automatic.

**`/program/save` reports `canSave() is false`.**
The program is read-only, or it was not opened from a project. This is a property
of how Ghidra opened the file, not of the bridge.

**Build fails with `需要 class、interface、enum 或 record` / `class, interface, enum, or record expected`.**
A UTF-8 BOM got into a `.java` file. Windows PowerShell 5.1's
`Set-Content -Encoding UTF8` adds one. Strip it or write with
`[System.IO.File]::WriteAllText($p, $t, (New-Object System.Text.UTF8Encoding($false)))`.

**Build fails with `invalid flag: ?-encoding` or mangled paths.**
`javac`/`jar` are native tools that read `@argfile` contents in the ANSI code
page. This project path contains non-ASCII characters, so arguments must be
passed directly and intermediate artifacts must live at an ASCII path —
`tools\build.ps1` already does both.
