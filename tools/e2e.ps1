# End-to-end verification of the plugin, driven through analyzeHeadless.
#
#   powershell -File tools/e2e.ps1
#   powershell -File tools/e2e.ps1 -Binary C:\Windows\System32\version.dll -RunSeconds 600
#
# The plugin itself is a GUI tool, so this harness starts the same router against
# a program supplied headlessly (tools/dev/GhidraMCPHeadlessServer.java) and then
# calls every endpoint over HTTP. It verifies the request handlers, routing, JSON
# and error handling; it deliberately does not test the plugin's tool-option and
# GUI wiring, which needs a display.
#
[CmdletBinding()]
param(
    [string]$GhidraDir = "D:\zstudytools\ghidra_12.1.3_PUBLIC",
    [string]$Binary = "C:\Windows\System32\version.dll",
    # A throwaway Ghidra project. Kept in the system temp directory, not in the
    # repo: it is an artifact of the test, and leaving it in the project tree once
    # caused a subsequent run to fail with "conflicting program file in project".
    [string]$ProjectDir = (Join-Path $env:TEMP "ghidramcp12-e2e"),
    [string]$ProjectName = "MCPE2E",
    [int]$Port = 8192,
    [int]$RunSeconds = 420,
    [switch]$SkipAnalysis,
    [switch]$NoDebugLog
)

$ErrorActionPreference = "Stop"
$ProjectDirFull = [System.IO.Path]::GetFullPath($ProjectDir)
$scriptDir = $PSScriptRoot

# The headless fixture lives in tools/dev and is deliberately NOT shipped in the
# extension zip. It is copied into a scratch directory before use rather than
# pointing -scriptPath straight at tools/dev: Ghidra compiles a script into an
# OSGi bundle together with everything else under the directory it finds, and a
# directory containing the plugin's own sources produces a bundle that cannot
# resolve (the plugin's packages are not exported to OSGi). A directory holding
# nothing but the fixture compiles cleanly.
$FixtureSource = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PSScriptRoot) "tools\dev"))
$FixtureDir = Join-Path $env:TEMP "ghidramcp12-headless-fixture"

function Info($m) { Write-Host "[e2e] $m" -ForegroundColor Cyan }

if (-not (Test-Path $Binary)) { throw "test binary not found: $Binary" }
if (-not (Test-Path (Join-Path $FixtureSource "GhidraMCPHeadlessServer.java"))) {
    throw "headless test fixture not found in $FixtureSource"
}
if (Test-Path $FixtureDir) { Remove-Item $FixtureDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $FixtureDir | Out-Null
Copy-Item (Join-Path $FixtureSource "GhidraMCPHeadlessServer.java") $FixtureDir -Force

# Fresh project every run, so renames and patches cannot accumulate and a failed
# run cannot poison the next one (leaving the previous project behind produced a
# "conflicting program file in project" failure).
if (Test-Path $ProjectDirFull) { Remove-Item $ProjectDirFull -Recurse -Force }
New-Item -ItemType Directory -Force -Path $ProjectDirFull | Out-Null

$env:JAVA_HOME = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { "D:\java\jdk-26" }
$log = Join-Path $ProjectDirFull "analyzeHeadless.log"
if (Test-Path $log) { Remove-Item $log -Force }

$debugLogArg = if ($NoDebugLog) { "none" } else { Join-Path $ProjectDirFull "bridge-debug.log" }
$analyzeArgs = @(
    $ProjectDirFull, $ProjectName,
    "-import", $Binary,
    "-scriptPath", $FixtureDir,
    "-postScript", "GhidraMCPHeadlessServer.java", "$Port", "$RunSeconds",
    "127.0.0.1", "false", $debugLogArg
)
if ($SkipAnalysis) { $analyzeArgs += "-noanalysis" }
$debugLog = Join-Path $ProjectDirFull "bridge-debug.log"
if (Test-Path $debugLog) { Remove-Item $debugLog -Force }

Info "starting analyzeHeadless (log: $log)"
$proc = Start-Process -FilePath (Join-Path $GhidraDir "support\analyzeHeadless.bat") `
    -ArgumentList $analyzeArgs -NoNewWindow -PassThru `
    -RedirectStandardOutput $log -RedirectStandardError "$log.err"

try {
    # analyzeHeadless.bat runs under cmd.exe, which exits as soon as it has
    # spawned java, so the wrapper's HasExited is not a failure signal. Poll the
    # bridge and detect real failures by watching the log instead.
    Info "waiting for the bridge on port $Port ..."
    $ready = $false
    for ($i = 0; $i -lt 180; $i++) {
        Start-Sleep -Seconds 2
        # curl, not Invoke-WebRequest: PowerShell throws (in Chinese, with the body
        # lost) for any non-2xx status, which turns a diagnosable 4xx into noise.
        $probe = & curl.exe -s -m 5 -o NUL -w "%{http_code}" "http://127.0.0.1:$Port/_health" 2>$null
        if ($probe -eq "200") { $ready = $true; break }
        if ((Test-Path $log) -and (Select-String -Path $log -Pattern "REPORT: Import failed|Abort due to|ERROR.*Script" -Quiet)) {
            break
        }
    }
    if (-not $ready) {
        Info "bridge did not come up; last log lines:"
        if (Test-Path $log) { Get-Content $log -Tail 40 }
        if (Test-Path "$log.err") { Get-Content "$log.err" -Tail 20 }
        throw "bridge failed to start"
    }
    Info "bridge is up; running endpoint tests"
    & (Join-Path $scriptDir "test_endpoints.ps1") -BaseUrl "http://127.0.0.1:$Port"
    $testExit = $LASTEXITCODE
    Info "endpoint tests finished with exit code $testExit"
}
finally {
    if (-not $proc.HasExited) {
        Info "stopping Ghidra (pid $($proc.Id))"
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    # analyzeHeadless.bat spawns java; make sure nothing is left holding the port.
    Get-CimInstance Win32_Process -Filter "Name = 'java.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match "GhidraMCPHeadlessServer" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

exit $testExit
