#!/usr/bin/env bash
# UART monitor on XIAO ESP32-S3 debug pins (D6/D7) or USB-JTAG when available.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${PORT:-}"

if [[ -z "$PORT" ]]; then
  ports=()
  for p in /dev/cu.usbmodem* /dev/cu.SLAB_USBtoUART /dev/cu.wchusbserial*; do
    [[ -e "$p" ]] || continue
    ports+=("$p")
  done
  if [[ "${#ports[@]}" -gt 1 ]]; then
    echo "Multiple serial ports; set PORT explicitly. Refusing to monitor/reset an arbitrary board." >&2
    exit 1
  fi
  [[ "${#ports[@]}" -eq 0 ]] || PORT="${ports[0]}"
fi

if [[ -z "$PORT" ]]; then
  echo "No serial port found. Set PORT=/dev/cu...." >&2
  exit 1
fi

unset IDF_PYTHON_ENV_PATH
default_idf="$HOME/esp/esp-idf-meshpn-v5.5.5"
if [[ "${IDF_PATH:-}" == "$HOME/esp/esp-idf" &&
      "$(git -C "$IDF_PATH" describe --tags --exact-match 2>/dev/null || true)" != v5.5.5 ]]; then
  selected_idf="$default_idf"
elif [[ -n "${IDF_PATH:-}" && -f "$IDF_PATH/export.sh" ]]; then
  selected_idf="$IDF_PATH"
elif [[ -f "$default_idf/export.sh" ]]; then
  selected_idf="$default_idf"
else
  echo "ESP-IDF 5.5.5 not found. Run device/scripts/setup-macos.sh." >&2
  exit 1
fi
if [[ ! -f "$selected_idf/export.sh" ]]; then
  echo "ESP-IDF 5.5.5 not found at $selected_idf. Run device/scripts/setup-macos.sh." >&2
  exit 1
fi
if [[ "$(git -C "$selected_idf" describe --tags --exact-match 2>/dev/null || true)" != v5.5.5 ]]; then
  echo "MeshPN requires ESP-IDF v5.5.5 at IDF_PATH, got: $selected_idf" >&2
  exit 1
fi
source "$selected_idf/export.sh"

cd "$ROOT/device"
idf.py -B "${BUILD_DIR:-build}" monitor -p "$PORT" -b 115200
