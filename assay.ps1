[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$ReleaseBin = Join-Path $ScriptDir "target\release\assay.exe"
$DebugBin = Join-Path $ScriptDir "target\debug\assay.exe"

if (Test-Path $ReleaseBin) {
    & $ReleaseBin @Arguments
} elseif (Test-Path $DebugBin) {
    & $DebugBin @Arguments
} else {
    Write-Host "[assay] Compiling release binary..." -ForegroundColor Cyan
    Push-Location $ScriptDir
    try {
        cargo build --release
    } finally {
        Pop-Location
    }
    & $ReleaseBin @Arguments
}
