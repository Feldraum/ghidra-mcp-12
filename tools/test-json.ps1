# Runs the extension's unit tests (JUnit 4) without Gradle.
#
# The tests cover the hand-written JSON layer, which is the one part of the
# bridge with no third party library behind it. JUnit jars are downloaded once
# into lib/test/ and are never shipped inside the extension zip.
#
#   powershell -File tools/test-json.ps1
#
[CmdletBinding()]
param(
    [string]$JdkHome = $env:JAVA_HOME,
    [string]$BuildRoot = (Join-Path $env:LOCALAPPDATA "GhidraMCP12-build")
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $PSScriptRoot
$LibDir = Join-Path $ProjectDir "lib\test"
$OutDir = Join-Path $BuildRoot "test-classes"
$Classes = Join-Path $BuildRoot "build\classes"

if (-not $JdkHome) { $JdkHome = "D:\java\jdk-26" }
$Javac = Join-Path $JdkHome "bin\javac.exe"
$Java = Join-Path $JdkHome "bin\java.exe"

function Info($m) { Write-Host "[test] $m" -ForegroundColor Cyan }

$JUnit = Join-Path $LibDir "junit-4.13.2.jar"
$Hamcrest = Join-Path $LibDir "hamcrest-core-1.3.jar"

New-Item -ItemType Directory -Force -Path $LibDir, $OutDir | Out-Null

foreach ($dep in @(
    @{ path = $JUnit; url = "https://repo1.maven.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar" },
    @{ path = $Hamcrest; url = "https://repo1.maven.org/maven2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar" }
)) {
    if (-not (Test-Path $dep.path)) {
        Info "downloading $(Split-Path -Leaf $dep.path)"
        try {
            Invoke-WebRequest -Uri $dep.url -OutFile $dep.path -UseBasicParsing -TimeoutSec 120
        }
        catch {
            throw "could not download $($dep.url): $($_.Exception.Message)"
        }
    }
}

# The JSON layer is deliberately free of any Ghidra (and any com.ghidramcp.api)
# dependency, so it can be compiled and tested on a machine with no Ghidra
# installation at all. Json, JsonWriter, JsonParser and ApiResponse are listed
# explicitly; Page is not, because it references ApiRequest.
$jsonSources = @("Json.java", "JsonWriter.java", "JsonParser.java", "ApiResponse.java") |
    ForEach-Object { Join-Path $ProjectDir "src\main\java\com\ghidramcp\util\$_" }
foreach ($f in $jsonSources) {
    if (-not (Test-Path $f)) { throw "expected source missing: $f" }
}
$mainSources = $jsonSources

$sources = @(Get-ChildItem (Join-Path $ProjectDir "src\test\java") -Recurse -Filter *.java |
    Select-Object -ExpandProperty FullName)

Info "compiling $($sources.Count) test source(s)"
$cp = "$JUnit;$Hamcrest"
& $Javac -encoding UTF-8 -d $OutDir -cp $cp $mainSources $sources
if ($LASTEXITCODE -ne 0) { throw "test compile failed" }

Info "running tests"
& $Java -cp "$OutDir;$JUnit;$Hamcrest" org.junit.runner.JUnitCore com.ghidramcp.util.JsonWriterTest
$exit = $LASTEXITCODE
if ($exit -eq 0) { Info "all tests passed" } else { Write-Host "[test] FAILURES (exit $exit)" -ForegroundColor Red }
exit $exit
