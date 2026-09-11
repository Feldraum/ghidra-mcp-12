# GhidraMCP12 - offline build script (no Gradle required)
#
# Ghidra's official extension build uses Gradle, but that needs a ~140MB Gradle
# distribution download which is not always possible on restricted networks.
# This script produces an equivalent extension zip using only javac/jar from a
# JDK plus the Ghidra installation itself, and validates the archive layout with
# Ghidra's own rules (tools/verify_zip.ps1).
#
#   powershell -File tools/build.ps1
#   powershell -File tools/build.ps1 -Install
#
# NOTES
#   * All javac/jar arguments are passed directly (never through an @argfile).
#     javac/jar are native tools that read argfiles using the ANSI code page, so
#     a project path containing non-ASCII characters ("D:\桌面\...") or the build
#     root containing spaces ("C:\Users\yerry ann\...") is silently mangled.
#     Direct arguments go through the Windows wide-character API and survive.
#   * Intermediate artifacts live outside the (possibly non-ASCII) project tree
#     so that native tools never have to interpret a Unicode path at all.
#
[CmdletBinding()]
param(
    [string]$GhidraDir = "D:\zstudytools\ghidra_12.1.3_PUBLIC",
    [string]$JdkHome = $env:JAVA_HOME,
    [string]$BuildRoot = (Join-Path $env:LOCALAPPDATA "GhidraMCP12-build"),
    [switch]$Install,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path -Parent $PSScriptRoot
$SrcDir = Join-Path $ProjectDir "src\main\java"
$DistDir = Join-Path $ProjectDir "dist"
$ExtName = "GhidraMCP12"

$BuildDir = Join-Path $BuildRoot "build"
$ClassesDir = Join-Path $BuildDir "classes"

function Info($m) { Write-Host "[build] $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "[build] ERROR: $m" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $GhidraDir)) { Fail "Ghidra dir not found: $GhidraDir" }
if (-not $JdkHome -or -not (Test-Path (Join-Path $JdkHome "bin\javac.exe"))) {
    Fail "JDK not found (JAVA_HOME='$JdkHome'). Set -JdkHome explicitly."
}
$Javac = Join-Path $JdkHome "bin\javac.exe"
$JarExe = Join-Path $JdkHome "bin\jar.exe"

Info "jdk      : $JdkHome"
Info "project  : $ProjectDir"
Info "build    : $BuildDir"

# ---------------------------------------------------------------- Ghidra facts
$GhidraProps = @{}
Get-Content (Join-Path $GhidraDir "Ghidra\application.properties") | ForEach-Object {
    if ($_ -match '^\s*([^#=]+)=(.*)$') { $GhidraProps[$Matches[1].Trim()] = $Matches[2].Trim() }
}
$GhidraVersion = $GhidraProps["application.version"]
$ReleaseName = $GhidraProps["application.release.name"]
$JavaTarget = $GhidraProps["application.java.compiler"]
Info "target   : Ghidra $GhidraVersion ($ReleaseName), javac --release $JavaTarget"

if ($Clean -and (Test-Path $BuildDir)) { Remove-Item -Recurse -Force $BuildDir }
if (Test-Path $ClassesDir) { Remove-Item -Recurse -Force $ClassesDir }
New-Item -ItemType Directory -Force -Path $ClassesDir | Out-Null
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# ------------------------------------------------------------- build classpath
$Jars = @(Get-ChildItem (Join-Path $GhidraDir "Ghidra") -Recurse -Filter *.jar |
    Where-Object { $_.FullName -match '\\(Framework|Features|Debug|Processors)\\[^\\]+\\lib\\' } |
    Select-Object -ExpandProperty FullName)
if ($Jars.Count -lt 20) { Fail "Only found $($Jars.Count) Ghidra jars - is the install complete?" }
$SourceFiles = @(Get-ChildItem -Path $SrcDir -Recurse -Filter *.java |
    Select-Object -ExpandProperty FullName)
Info "classpath: $($Jars.Count) jars / sources: $($SourceFiles.Count)"
if ($SourceFiles.Count -eq 0) { Fail "no sources found under $SrcDir" }

# --------------------------------------------------------------- compile java
$cp = $Jars -join ';'
# Warnings are errors, but only for the categories this project can actually
# control. -Xlint:all is not usable here: Ghidra's javadoc references jars it does
# not ship (guava, xercesImpl, ...) and javac reports each as a "bad path element",
# which would fail every build for reasons outside the source.
$javacArgs = @('-encoding', 'UTF-8', '-d', $ClassesDir, '--release', $JavaTarget,
    '-Xlint:deprecation,unchecked,rawtypes,fallthrough,static,serial,finally,divzero',
    '-Werror', '-cp', $cp) + $SourceFiles

Info "compiling..."
# javac is a native tool and writes diagnostics using the console code page
# (936/GBK on zh-CN Windows), which PowerShell then mangles while it converts
# native stderr into ErrorRecords. Redirect its output to files and decode them
# as GBK so real compiler errors stay readable. This also keeps the complete
# error list instead of whatever fitted in the terminal buffer.
$stdoutFile = Join-Path $BuildDir "javac.out"
$stderrFile = Join-Path $BuildDir "javac.err"
foreach ($f in @($stdoutFile, $stderrFile, (Join-Path $BuildDir "compile.log"))) {
    if (Test-Path $f) { Remove-Item -Force $f }
}
$argList = @()
foreach ($a in $javacArgs) {
    if ($a -match '[\s"]') { $argList += '"' + ($a -replace '"', '\"') + '"' } else { $argList += $a }
}
$proc = Start-Process -FilePath $Javac -ArgumentList $argList -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
$javacExit = $proc.ExitCode

$diag = ""
foreach ($f in @($stderrFile, $stdoutFile)) {
    if (Test-Path $f) {
        $bytes = [System.IO.File]::ReadAllBytes($f)
        if ($bytes.Length -gt 0) {
            $diag += [System.Text.Encoding]::GetEncoding(936).GetString($bytes)
        }
    }
}
if ($diag.Trim().Length -gt 0) {
    [System.IO.File]::WriteAllText((Join-Path $BuildDir "compile.log"), $diag,
        (New-Object System.Text.UTF8Encoding($false)))
    if ($javacExit -ne 0) { Write-Host $diag }
    else { Info "javac warnings -> $(Join-Path $BuildDir 'compile.log')" }
}
if ($javacExit -ne 0) { Fail "javac failed with exit code $javacExit" }
$classFiles = @(Get-ChildItem $ClassesDir -Recurse -Filter *.class)
if ($classFiles.Count -eq 0) { Fail "no class files produced" }
Info "compile OK ($($classFiles.Count) classes)"

# ----------------------------------------------------------------- module jar
$JarPath = Join-Path $BuildDir "$ExtName.jar"
if (Test-Path $JarPath) { Remove-Item -Force $JarPath }
& $JarExe --create --file $JarPath -C $ClassesDir .
if ($LASTEXITCODE -ne 0) { Fail "jar failed" }
Info "jar OK: $JarPath ($([math]::Round((Get-Item $JarPath).Length/1KB,1)) KB)"

# --------------------------------------------------- assemble extension staging
$StageRoot = Join-Path $BuildDir "stage"
$Stage = Join-Path $StageRoot $ExtName
if (Test-Path $StageRoot) { Remove-Item -Recurse -Force $StageRoot }
New-Item -ItemType Directory -Force -Path (Join-Path $Stage "lib") | Out-Null
Copy-Item $JarPath (Join-Path $Stage "lib\$ExtName.jar")

foreach ($f in @("extension.properties", "Module.manifest", "README.md", "LICENSE")) {
    $p = Join-Path $ProjectDir $f
    if (Test-Path $p) { Copy-Item $p (Join-Path $Stage $f) }
}

$srcZip = Join-Path $BuildDir "$ExtName-src.zip"
if (Test-Path $srcZip) { Remove-Item -Force $srcZip }
& $JarExe --create --file $srcZip -C (Join-Path $ProjectDir "src") "main/java"
if ($LASTEXITCODE -eq 0) { Copy-Item $srcZip (Join-Path $Stage "lib\$ExtName-src.zip") -Force }

# Extra payload directories that must land inside the extension. Anything not
# listed here is NOT shipped: tests/, tools/ and docs/ contain the harness, the
# throwaway Ghidra project created by tools/e2e.ps1, and documentation, none of
# which belongs in an installed extension. build.gradle excludes the same set.
foreach ($dir in @("mcp", "data", "os")) {
    $p = Join-Path $ProjectDir $dir
    if (Test-Path $p) {
        Copy-Item $p (Join-Path $Stage $dir) -Recurse
        Info "payload  : $dir"
    }
}

$propFile = Join-Path $Stage "extension.properties"
if (Test-Path $propFile) {
    $txt = (Get-Content $propFile -Raw).Replace('@extversion@', $GhidraVersion).Replace('@extname@', $ExtName)
    [System.IO.File]::WriteAllText($propFile, $txt, (New-Object System.Text.UTF8Encoding($false)))
}

# ------------------------------------------------------------------ zip it up
# Entries are written explicitly with '/' separators. Ghidra's extension loader
# only accepts an "extension.properties" that splits into exactly two path parts
# on '/', so a stray base directory or backslash separators make the archive
# invisible to File > Install Extensions.
$Date = Get-Date -Format 'yyyyMMdd'
$ZipName = "ghidra_${GhidraVersion}_${ReleaseName}_${Date}_${ExtName}.zip"
$ZipPath = Join-Path $DistDir $ZipName
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }

Add-Type -AssemblyName System.IO.Compression
$zipStream = [System.IO.File]::Create($ZipPath)
try {
    $zip = New-Object System.IO.Compression.ZipArchive(
        $zipStream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in Get-ChildItem $Stage -Recurse -File) {
            $rel = $file.FullName.Substring($Stage.Length).TrimStart('\', '/') -replace '\\', '/'
            $entry = $zip.CreateEntry("$ExtName/$rel", [System.IO.Compression.CompressionLevel]::Optimal)
            $entryStream = $entry.Open()
            try {
                $input = [System.IO.File]::OpenRead($file.FullName)
                try { $input.CopyTo($entryStream) } finally { $input.Dispose() }
            }
            finally { $entryStream.Dispose() }
        }
    }
    finally { $zip.Dispose() }
}
finally { $zipStream.Dispose() }
Info "zip      : $ZipPath ($([math]::Round((Get-Item $ZipPath).Length/1KB,1)) KB)"

# ------------------------------------------------------- validate the archive
& (Join-Path $PSScriptRoot "verify_zip.ps1") -Zip $ZipPath
if ($LASTEXITCODE -ne 0) { Fail "extension archive failed validation" }

# --------------------------------------------------------------- install (opt)
if ($Install) {
    $InstRoot = $null
    $ghidraUser = Join-Path $env:USERPROFILE ".ghidra"
    if (Test-Path $ghidraUser) {
        $cand = Get-ChildItem $ghidraUser -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*PUBLIC*" -or $_.Name -like "*ghidra_*" } |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($cand) { $InstRoot = Join-Path $cand.FullName "Extensions" }
    }
    if (-not $InstRoot) { $InstRoot = Join-Path $GhidraDir "Extensions\Ghidra" }
    New-Item -ItemType Directory -Force -Path $InstRoot | Out-Null
    $dest = Join-Path $InstRoot $ZipName
    Copy-Item $ZipPath $dest -Force
    Info "installed: $dest"
    Info "(restart Ghidra, then File > Install Extensions > check $ExtName)"
}

Write-Host ""
Info "DONE - $ZipName"
