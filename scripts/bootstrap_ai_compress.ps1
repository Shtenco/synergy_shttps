param(
  [string]$Root = "vendor\ai_compress"
)
$ErrorActionPreference = "Stop"
$Commit = "551fae36eacb5713aa503fc9da2fbc44fe8f2e84"
if (-not (Test-Path (Join-Path $Root ".git"))) {
  git clone https://github.com/Shtenco/synegy_ai_compress.git $Root
}
git -C $Root fetch origin $Commit
git -C $Root checkout --detach $Commit
$Resolved = (Resolve-Path $Root).Path
Write-Host "Set this for the current shell:"
Write-Host '$env:SHTTPS_AI_COMPRESS_PATH="'$Resolved'"'
