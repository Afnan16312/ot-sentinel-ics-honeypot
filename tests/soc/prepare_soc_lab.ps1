$ErrorActionPreference = "Stop"

$LabRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VendorRoot = Join-Path $LabRoot "vendor\wazuh-docker"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is required. Install Docker Desktop before preparing the SOC lab."
}

if (-not (Test-Path -LiteralPath $VendorRoot)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $VendorRoot) | Out-Null
    git clone --depth 1 --branch v4.14.7 `
        https://github.com/wazuh/wazuh-docker.git $VendorRoot
}

$SingleNode = Join-Path $VendorRoot "single-node"
Push-Location $SingleNode
try {
    docker compose -f generate-indexer-certs.yml run --rm generator
}
finally {
    Pop-Location
}

Write-Host "Prepared pinned Wazuh 4.14.7 lab assets."
Write-Host "Run the commands in tests/soc/README.md from the repository root."
