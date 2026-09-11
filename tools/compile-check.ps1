# Developer helper: run the build and print javac diagnostics in a readable form.
#
# Windows consoles here run code page 936, while javac (JDK 18+) emits messages in
# UTF-8, so raw output arrives as mojibake. This wrapper reads the compile log
# with an explicit encoding so real errors are legible.
#
#   powershell -File tools/compile-check.ps1
#
[CmdletBinding()]
param(
    [string]$LogFile = (Join-Path $env:LOCALAPPDATA "GhidraMCP12-build\build\compile.log")
)

$ErrorActionPreference = "Continue"
$ProjectDir = Split-Path -Parent $PSScriptRoot

$output = & (Join-Path $PSScriptRoot "build.ps1") *>&1
$exit = $LASTEXITCODE

if ($exit -eq 0) {
    $output | Where-Object { $_ -match '\[build\]' } | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
    Write-Host "BUILD OK" -ForegroundColor Green
    exit 0
}

Write-Host "BUILD FAILED (exit $exit)" -ForegroundColor Red
if (Test-Path $LogFile) {
    $bytes = [System.IO.File]::ReadAllBytes($LogFile)
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    Write-Host "---- javac diagnostics ----" -ForegroundColor Yellow
    Write-Host $text
}
$output | Where-Object { $_ -match '\[build\]' } | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
exit $exit
