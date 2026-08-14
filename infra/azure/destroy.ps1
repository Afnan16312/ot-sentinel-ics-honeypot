param([string]$ResourceGroup = "rg-ot-sentinel-research")

$ErrorActionPreference = "Stop"
$group = az group show --name $ResourceGroup --output json 2>$null
if (-not $group) {
  Write-Output "Resource group '$ResourceGroup' does not exist."
  exit 0
}

Write-Output "Deleting only the resolved project resource group: $ResourceGroup"
az group delete --name $ResourceGroup --yes --no-wait
Write-Output "Deletion requested. Confirm completion in Azure Cost Management."

