param(
  [Parameter(Mandatory = $true)][string]$SshPublicKeyPath,
  [Parameter(Mandatory = $true)][string]$AdminCidr,
  [string]$ResourceGroup = "rg-ot-sentinel-research",
  [string]$Location = "uaenorth"
)

$ErrorActionPreference = "Stop"
$resolvedKey = (Resolve-Path -LiteralPath $SshPublicKeyPath).Path
$sshKey = Get-Content -Raw -LiteralPath $resolvedKey

az group create --name $ResourceGroup --location $Location | Out-Null
az deployment group create `
  --resource-group $ResourceGroup `
  --template-file "$PSScriptRoot/main.bicep" `
  --parameters adminSshKey=$sshKey adminCidr=$AdminCidr location=$Location

Write-Output "Deployment complete. Keep the subscription spending limit enabled."

