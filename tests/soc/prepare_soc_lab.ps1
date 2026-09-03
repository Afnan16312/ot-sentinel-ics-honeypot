$ErrorActionPreference = "Stop"

$LabRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VendorRoot = Join-Path $LabRoot "vendor\wazuh-docker"
$GeneratedRoot = Join-Path $LabRoot "generated"
$StagingRoot = Join-Path $LabRoot "staging"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is required. Install Docker Desktop before preparing the SOC lab."
}

if (-not (Test-Path -LiteralPath $VendorRoot)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $VendorRoot) | Out-Null
    git clone --depth 1 --branch v4.14.7 `
        https://github.com/wazuh/wazuh-docker.git $VendorRoot
}

$SingleNode = Join-Path $VendorRoot "single-node"
$CertificateRoot = Join-Path $SingleNode "config\wazuh_indexer_ssl_certs"
$RequiredCertificates = @(
    "root-ca.pem",
    "admin.pem",
    "admin-key.pem",
    "wazuh.indexer.pem",
    "wazuh.indexer-key.pem",
    "wazuh.manager.pem",
    "wazuh.manager-key.pem",
    "wazuh.dashboard.pem",
    "wazuh.dashboard-key.pem"
)
$MissingCertificate = $RequiredCertificates | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $CertificateRoot $_))
}
if ($MissingCertificate) {
    Push-Location $SingleNode
    try {
        docker compose -f generate-indexer-certs.yml run --rm generator
        if ($LASTEXITCODE -ne 0) {
            throw "Wazuh certificate generation failed."
        }
    }
    finally {
        Pop-Location
    }
}
else {
    Write-Host "Pinned Wazuh certificates already exist; generation skipped."
}

New-Item -ItemType Directory -Force -Path $GeneratedRoot | Out-Null
New-Item -ItemType Directory -Force -Path $StagingRoot | Out-Null
$StagingEvents = Join-Path $StagingRoot "events.jsonl"
if (-not (Test-Path -LiteralPath $StagingEvents)) {
    New-Item -ItemType File -Path $StagingEvents | Out-Null
}
$BaseManagerConfig = Join-Path $SingleNode "config\wazuh_cluster\wazuh_manager.conf"
$LocalfileFragment = Join-Path $LabRoot "wazuh-localfile.conf"
$GeneratedManagerConfig = Join-Path $GeneratedRoot "wazuh_manager.conf"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$ManagerContent = (Get-Content -Raw -LiteralPath $BaseManagerConfig).TrimEnd() + "`n`n" + `
    (Get-Content -Raw -LiteralPath $LocalfileFragment).Trim() + "`n"
[System.IO.File]::WriteAllText($GeneratedManagerConfig, $ManagerContent, $Utf8NoBom)

Write-Host "Prepared pinned Wazuh 4.14.7 lab assets."
Write-Host "Prepared ignored historical-ingestion staging and manager configuration."
Write-Host "Run the commands in tests/soc/README.md from the repository root."
