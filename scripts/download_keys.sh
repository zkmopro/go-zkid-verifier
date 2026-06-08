#!/usr/bin/env bash
set -euo pipefail

RELEASE_URL="https://github.com/privacy-ethereum/zkID/releases/download/RSA-X.509-Cert-latest"
KEYS_DIR="$(cd "$(dirname "$0")/.." && pwd)/keys"

KEYS=(
  cert_chain_rs2048_verifying.key
  cert_chain_rs4096_verifying.key
  user_sig_rs2048_verifying.key
)

mkdir -p "$KEYS_DIR"

for key in "${KEYS[@]}"; do
  if [[ -f "$KEYS_DIR/$key" ]]; then
    echo "$key already exists, skipping."
    continue
  fi

  echo "Downloading $key.gz..."
  curl -fL --progress-bar "$RELEASE_URL/$key.gz" -o "$KEYS_DIR/$key.gz"
  gunzip -f "$KEYS_DIR/$key.gz"
  echo "Extracted $key"
done

echo "All verifying keys ready in $KEYS_DIR"
