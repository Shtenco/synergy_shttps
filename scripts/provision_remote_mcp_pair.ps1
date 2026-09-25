param(
  [string]$DeployDir = "deploy\\remote_mcp"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $DeployDir | Out-Null
$Secrets = Join-Path $DeployDir "secrets"
New-Item -ItemType Directory -Force -Path $Secrets | Out-Null
$RootSecret = Join-Path $DeployDir "root.identity.json"
$RootPublic = Join-Path $DeployDir "root.json"
$Registry = Join-Path $DeployDir "federation.json"

if (-not (Test-Path $RootSecret) -or -not (Test-Path $RootPublic)) {
  shttps-federation root-init --secret $RootSecret --public $RootPublic
}
shttps-federation provision-all `
  --source "config\\remote_mcp_federation_source.example.json" `
  --root-secret $RootSecret `
  --root-public $RootPublic `
  --secrets-dir $Secrets `
  --registry-out $Registry

Write-Host ""
Write-Host "Provisioning complete."
Write-Host "KEEP OFFLINE / DO NOT COPY TO NODES: $RootSecret"
Write-Host "COPY TO BOTH SIDES: $RootPublic and $Registry"
Write-Host "SERVER IDENTITY: $(Join-Path $Secrets 'synergy_shttps.identity.json')"
Write-Host "CONTROLLER IDENTITY: $(Join-Path $Secrets 'synergy_remote_mcp_controller.identity.json')"
