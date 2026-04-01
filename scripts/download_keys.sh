#!/usr/bin/env bash
set -euo pipefail

ZIP_URL="https://github.com/zkmopro/zkID/releases/download/latest/ecdsa-spartan2-keys.zip"
KEYS_DIR="$(cd "$(dirname "$0")/.." && pwd)/keys"
ZIP_PATH="$KEYS_DIR/ecdsa-spartan2-keys.zip"

mkdir -p "$KEYS_DIR"

if [[ -f "$ZIP_PATH" ]]; then
  echo "ecdsa-spartan2-keys.zip already exists, skipping download."
else
  echo "Downloading ecdsa-spartan2-keys.zip..."
  curl -fL --progress-bar "$ZIP_URL" -o "$ZIP_PATH"
  echo "Saved to $ZIP_PATH"
fi

UNZIP_DIR=$(mktemp -d)
trap 'rm -rf "$UNZIP_DIR"' EXIT

unzip -o "$ZIP_PATH" -d "$UNZIP_DIR"
cp -r "$UNZIP_DIR"/wallet-unit-poc/ecdsa-spartan2/keys/. "$KEYS_DIR/"
echo "Keys extracted to $KEYS_DIR"

rm -f "$ZIP_PATH"
echo "Cleaned up $ZIP_PATH"
