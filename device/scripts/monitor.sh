#!/usr/bin/env bash
# UART monitor on XIAO ESP32-S3 debug pins (D6/D7) or USB-JTAG when available.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${PORT:-}"

if [[ -z "$PORT" ]]; then
  for p in /dev/cu.usbmodem* /dev/cu.SLAB_USBtoUART /dev/cu.wchusbserial*; do
    [[ -e "$p" ]] || continue
    PORT="$p"
    break
  done
fi

if [[ -z "$PORT" ]]; then
  echo "No serial port found. Set PORT=/dev/cu...." >&2
  exit 1
fi

unset IDF_PYTHON_ENV_PATH
if [[ -n "${IDF_PATH:-}" && -f "$IDF_PATH/export.sh" ]]; then
  selected_idf="$IDF_PATH"
elif [[ -f "$HOME/esp/esp-idf-meshpn-v5.5.5/export.sh" ]]; then
  selected_idf="$HOME/esp/esp-idf-meshpn-v5.5.5"
else
  echo "ESP-IDF 5.5.5 not found. Run device/scripts/setup-macos.sh." >&2
  exit 1
fi
if [[ "$(git -C "$selected_idf" describe --tags --exact-match 2>/dev/null || true)" != v5.5.5 ]]; then
  echo "MeshPN requires ESP-IDF v5.5.5 at IDF_PATH, got: $selected_idf" >&2
  exit 1
fi
source "$selected_idf/export.sh"

cd "$ROOT/device"
idf.py monitor -p "$PORT" -b 115200
