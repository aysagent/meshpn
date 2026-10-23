#!/usr/bin/env bash
# One-time dev environment setup for meshvpn device firmware (macOS).
set -euo pipefail

IDF_VERSION="v5.5.5"
# iot_bridge patches lwIP in IDF_PATH. Keep this checkout separate from camic.
if [[ "${IDF_PATH:-}" == "$HOME/esp/esp-idf" &&
      "$(git -C "$IDF_PATH" describe --tags --exact-match 2>/dev/null || true)" != "$IDF_VERSION" ]]; then
  IDF_PATH="$HOME/esp/esp-idf-meshpn-v5.5.5"
else
  IDF_PATH="${IDF_PATH:-$HOME/esp/esp-idf-meshpn-v5.5.5}"
fi

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
if [[ "$(git -C "$IDF_PATH" describe --tags --exact-match 2>/dev/null || true)" != "$IDF_VERSION" ]]; then
  echo "Expected ESP-IDF $IDF_VERSION at $IDF_PATH; select a different IDF_PATH" >&2
  exit 1
fi

echo "==> Installing ESP-IDF toolchains for esp32s3 and esp32p4"
cd "$IDF_PATH"
./install.sh esp32s3,esp32p4

echo "==> Done. Build and flash commands activate ESP-IDF themselves."
