#!/usr/bin/env bash
set -euo pipefail

R2_BASE="https://pub-ef10768896384fdf9617f26d43e11a65.r2.dev"
KEYS_DIR="$(dirname "$0")/../keys"

mkdir -p "$KEYS_DIR"

echo "Downloading rs256_verifying.key..."
curl -fL --progress-bar "$R2_BASE/rs256_verifying.key" -o "$KEYS_DIR/rs256_verifying.key"
echo "Saved to $KEYS_DIR/rs256_verifying.key"
