#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-vendor/ai_compress}"
COMMIT="551fae36eacb5713aa503fc9da2fbc44fe8f2e84"
if [ ! -d "$ROOT/.git" ]; then
  git clone https://github.com/Shtenco/synegy_ai_compress.git "$ROOT"
fi
git -C "$ROOT" fetch origin "$COMMIT"
git -C "$ROOT" checkout --detach "$COMMIT"
echo "export SHTTPS_AI_COMPRESS_PATH=$(cd "$ROOT" && pwd)"
