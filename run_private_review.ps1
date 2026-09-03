[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8512
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

$handoffRoot = Get-ChildItem -LiteralPath (Join-Path $projectRoot "data\private\handoff") -Directory -ErrorAction Stop |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $handoffRoot) { throw "No private handoff folder was found." }

$sanitizedPath = Join-Path $handoffRoot.FullName "sanitized\events.sanitized.jsonl"
if (-not (Test-Path -LiteralPath $sanitizedPath)) { throw "Sanitized handoff file was not found: $sanitizedPath" }

$env:OT_PUBLIC_DATA_PATH = $sanitizedPath
Write-Host "Starting OT Sentinel local review with sanitized observed data at http://localhost:$Port"
Write-Host "This mode reads the private handoff locally; it does not publish or contact Oracle."
& (Join-Path $projectRoot "run_dashboard.ps1") -Port $Port
