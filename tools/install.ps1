# Installs (or removes) the GhidraMCP12 extension in a Ghidra installation.
#
# The extension is extracted as a module directory rather than left as a zip,
# because analyzeHeadless and the GUI both discover modules by scanning
# <install>/Ghidra/Extensions/<Name>/Module.manifest plus its lib/ jars.
#
#   powershell -File tools/install.ps1                 # install/refresh
#   powershell -File tools/install.ps1 -Uninstall      # remove
#
[CmdletBinding()]
param(
    [string]$GhidraDir = "D:\zstudytools\ghidra_12.1.3_PUBLIC",
    [string]$Zip,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $PSScriptRoot
$ExtName = "GhidraMCP12"
$Target = Join-Path $GhidraDir "Ghidra\Extensions\$ExtName"

function Info($m) { Write-Host "[install] $m" -ForegroundColor Cyan }

if ($Uninstall) {
    if (Test-Path $Target) {
        Remove-Item $Target -Recurse -Force
        Info "removed $Target"
    }
    else {
        Info "nothing to remove at $Target"
    }
    exit 0
}

if (-not $Zip) {
    $Zip = Get-ChildItem (Join-Path $ProjectDir "dist") -Filter *.zip |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $Zip -or -not (Test-Path $Zip)) { throw "no extension zip found; run tools/build.ps1 first" }

if (Test-Path $Target) { Remove-Item $Target -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Target | Out-Null

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($Zip)
try {
    foreach ($entry in $archive.Entries) {
        if ([string]::IsNullOrEmpty($entry.Name)) { continue }  # directory entry
        $relative = $entry.FullName
        # Strip the leading "<ExtName>/" the archive layout requires.
        if ($relative.StartsWith("$ExtName/")) { $relative = $relative.Substring($ExtName.Length + 1) }
        $dest = Join-Path $Target ($relative -replace '/', '\')
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
    }
}
finally { $archive.Dispose() }

Info "installed $(Split-Path -Leaf $Zip) -> $Target"
Get-ChildItem $Target -Recurse -File | ForEach-Object {
    Info ("  " + $_.FullName.Substring($Target.Length + 1) + "  (" + [math]::Round($_.Length/1KB,1) + " KB)")
}
