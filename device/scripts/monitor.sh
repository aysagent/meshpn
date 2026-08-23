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

if [[ -f "$HOME/esp/esp-idf/export.sh" ]]; then
  source "$HOME/esp/esp-idf/export.sh"
fi

cd "$ROOT/device"
idf.py monitor -p "$PORT" -b 115200
