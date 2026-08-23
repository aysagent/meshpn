#!/usr/bin/env bash
# One-time dev environment setup for meshvpn device firmware (macOS).
set -euo pipefail

IDF_VERSION="${IDF_VERSION:-v5.4.1}"
IDF_PATH="${IDF_PATH:-$HOME/esp/esp-idf}"

echo "==> Installing Homebrew dependencies (if missing)"
for pkg in cmake ninja dfu-util python3; do
  if ! command -v "${pkg%%@*}" >/dev/null 2>&1; then
    brew install "$pkg"
  fi
done

if ! xcode-select -p >/dev/null 2>&1; then
  echo "==> Xcode Command Line Tools required"
  xcode-select --install || true
fi

if [[ ! -f "$IDF_PATH/export.sh" ]]; then
  echo "==> Cloning ESP-IDF $IDF_VERSION to $IDF_PATH"
  mkdir -p "$(dirname "$IDF_PATH")"
  git clone -b "$IDF_VERSION" --recursive https://github.com/espressif/esp-idf.git "$IDF_PATH"
fi

echo "==> Installing ESP-IDF toolchains for esp32s3"
cd "$IDF_PATH"
./install.sh esp32s3

MARKER="# meshvpn ESP-IDF"
if ! grep -q "$MARKER" "$HOME/.zshrc" 2>/dev/null; then
  {
    echo ""
    echo "$MARKER"
    echo "export IDF_PATH=\"$IDF_PATH\""
    echo ". \"\$IDF_PATH/export.sh\""
  } >> "$HOME/.zshrc"
  echo "==> Added IDF_PATH to ~/.zshrc"
fi

echo "==> Done. Run: source ~/.zshrc"
