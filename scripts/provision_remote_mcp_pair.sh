#!/usr/bin/env bash
set -euo pipefail
DEPLOY_DIR="${1:-deploy/remote_mcp}"
mkdir -p "$DEPLOY_DIR/secrets"
ROOT_SECRET="$DEPLOY_DIR/root.identity.json"
ROOT_PUBLIC="$DEPLOY_DIR/root.json"
REGISTRY="$DEPLOY_DIR/federation.json"

if [[ ! -f "$ROOT_SECRET" || ! -f "$ROOT_PUBLIC" ]]; then
  shttps-federation root-init --secret "$ROOT_SECRET" --public "$ROOT_PUBLIC"
fi

shttps-federation provision-all \
  --source config/remote_mcp_federation_source.example.json \
  --root-secret "$ROOT_SECRET" \
  --root-public "$ROOT_PUBLIC" \
  --secrets-dir "$DEPLOY_DIR/secrets" \
  --registry-out "$REGISTRY"

chmod 600 "$ROOT_SECRET" "$DEPLOY_DIR"/secrets/*.json 2>/dev/null || true
echo
echo "Provisioning complete."
echo "KEEP OFFLINE / DO NOT COPY TO NODES: $ROOT_SECRET"
echo "COPY TO BOTH SIDES: $ROOT_PUBLIC and $REGISTRY"
echo "SERVER IDENTITY: $DEPLOY_DIR/secrets/synergy_shttps.identity.json"
echo "CONTROLLER IDENTITY: $DEPLOY_DIR/secrets/synergy_remote_mcp_controller.identity.json"
