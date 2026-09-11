# Verifies that a built extension archive has the exact internal layout Ghidra's
# extension loader requires.
#
# Ghidra's ExtensionUtils.getProperties() only accepts a properties file that
# sits at exactly TWO path parts ("<Name>/extension.properties") and computes
# those parts by splitting on '/'. An archive produced with an extra "stage"
# level, or with backslash separators, is silently rejected (the GUI shows
# nothing, and the loader NPEs internally), so this check is part of the build.
#
#   powershell -File tools/verify_zip.ps1 [-Zip <path>]
#
[CmdletBinding()]
param(
    [string]$Zip
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $PSScriptRoot

if (-not $Zip) {
    $Zip = Get-ChildItem (Join-Path $ProjectDir "dist") -Filter *.zip |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $Zip -or -not (Test-Path $Zip)) { Write-Host "no zip to verify" -ForegroundColor Red; exit 1 }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($Zip)
$problems = New-Object System.Collections.Generic.List[string]
try {
    $names = @($archive.Entries | ForEach-Object { [string]$_.FullName })
    Write-Host "archive : $(Split-Path -Leaf $Zip)"
    Write-Host "entries : $($names.Count)"

    # 1. No backslashes, no drive letters, no "..".
    foreach ($n in $names) {
        if ($n.Contains('\')) { $problems.Add("entry uses backslash: $n") }
        if ($n -match '^[A-Za-z]:') { $problems.Add("entry has a drive letter: $n") }
        if (($n -split '/') -contains '..') { $problems.Add("entry escapes the archive: $n") }
    }

    # 2. Exactly one top level directory, and it matches the extension name.
    $tops = @($names | ForEach-Object { @(($_ -split '/'))[0] } | Sort-Object -Unique)
    if ($tops.Count -ne 1) { $problems.Add("expected exactly 1 top level dir, found: $($tops -join ', ')") }
    $extName = [string]$tops[0]
    Write-Host "ext name: $extName"

    # 3. extension.properties at exactly "<Name>/extension.properties".
    $propEntry = @($names | Where-Object { @($_ -split '/').Count -eq 2 -and $_ -like '*/extension.properties' })
    if (-not $propEntry) {
        $problems.Add("no <Name>/extension.properties at the top level (Ghidra will not see this extension)")
    }
    else {
        $reader = New-Object System.IO.StreamReader($archive.GetEntry($propEntry).Open())
        $text = $reader.ReadToEnd(); $reader.Dispose()
        foreach ($key in @('name', 'description', 'author', 'createdOn', 'version')) {
            if ($text -notmatch "(?m)^\s*$key\s*=") { $problems.Add("extension.properties is missing '$key'") }
        }
        $text.Trim() -split "`n" | ForEach-Object { Write-Host "  $_" }
        if ($text -match '@ext(version|name)@') { $problems.Add("extension.properties still contains an unsubstituted @placeholder@") }
    }

    # 4. The module jar must be at <Name>/lib/<Name>.jar.
    if ($names -notcontains "$extName/lib/$extName.jar") {
        $problems.Add("missing module jar at $extName/lib/$extName.jar")
    }
    if ($names -notcontains "$extName/Module.manifest") {
        Write-Host "warn    : no Module.manifest (Ghidra tolerates this)" -ForegroundColor Yellow
    }
    if ($names -notcontains "$extName/data/ExtensionPoint.manifest") {
        $problems.Add("missing $extName/data/ExtensionPoint.manifest - Ghidra will not discover Plugin classes")
    }
}
finally { $archive.Dispose() }

Write-Host ""
if ($problems.Count -gt 0) {
    foreach ($p in $problems) { Write-Host "  FAIL: $p" -ForegroundColor Red }
    Write-Host "ARCHIVE INVALID" -ForegroundColor Red
    exit 1
}
Write-Host "ARCHIVE OK" -ForegroundColor Green
exit 0
