#!/usr/bin/env bash
# Build and flash meshvpn device firmware.
# Usage:
#   ./device/scripts/flash.sh              # xiao_esp32s3 + ncm (iPhone)
#   ./device/scripts/flash.sh rndis        # Windows
#   ./device/scripts/flash.sh ecm monitor  # Linux/macOS ECM + serial monitor
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEVICE_DIR="$ROOT/device"
BOARD="${BOARD:-xiao_esp32s3}"
PROFILE="${1:-ncm}"
MONITOR="${2:-}"

if [[ -f "$HOME/esp/esp-idf/export.sh" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/esp/esp-idf/export.sh"
elif [[ -n "${IDF_PATH:-}" && -f "${IDF_PATH}/export.sh" ]]; then
  # shellcheck disable=SC1091
  source "${IDF_PATH}/export.sh"
else
  echo "ESP-IDF not found. Run: ./device/scripts/setup-macos.sh" >&2
  exit 1
fi

export BOARD
export USB_PROFILE="$PROFILE"

PORT="${PORT:-}"
if [[ -z "$PORT" ]]; then
  for p in /dev/cu.usbmodem* /dev/cu.SLAB_USBtoUART /dev/cu.wchusbserial*; do
    [[ -e "$p" ]] || continue
    PORT="$p"
    break
  done
fi

cd "$DEVICE_DIR"

"$DEVICE_DIR/scripts/sync-embed-assets.sh" || true

# An existing sdkconfig overrides sdkconfig.defaults, so values edited in the
# defaults would silently not apply. Drop it whenever a defaults file is newer.
if [[ -f sdkconfig ]]; then
  STALE=""
  if ! grep -q '^CONFIG_BRIDGE_ENABLE=' sdkconfig 2>/dev/null; then
    STALE="missing bridge defaults"
  elif ! grep -q '^CONFIG_BRIDGE_DATA_FORWARDING_NETIF_USB=y' sdkconfig 2>/dev/null; then
    STALE="USB bridge disabled in sdkconfig"
  elif grep -q '^CONFIG_ESP_BROWNOUT_DET=y' sdkconfig 2>/dev/null; then
    STALE="brownout still enabled (phone USB)"
  fi
  for f in sdkconfig.defaults "boards/$BOARD/sdkconfig.defaults" "profiles/usb_$PROFILE.defconfig"; do
    [[ -f "$f" && "$f" -nt sdkconfig ]] && STALE="$f changed"
  done
  if [[ -n "$STALE" ]]; then
    echo "==> Regenerating sdkconfig ($STALE)"
    rm -f sdkconfig sdkconfig.old
  fi
fi

if [[ ! -f sdkconfig ]] || ! grep -q 'IDF_TARGET="esp32s3"' sdkconfig 2>/dev/null; then
  idf.py set-target esp32s3
fi

BUILD_ARGS=(build)
if [[ -n "$PORT" ]]; then
  BUILD_ARGS+=(flash -p "$PORT")
  echo "==> Flashing to $PORT (board=$BOARD profile=$PROFILE)"
else
  echo "==> Building only (no serial port found; hold BOOT to flash later)"
fi

idf.py "${BUILD_ARGS[@]}"

if [[ -n "$PORT" ]]; then
  echo ""
  echo "==> After flash: unplug USB from phone, replug, wait ~5s for Ethernet in Settings"
  echo "    Admin: http://192.168.7.1/login  (password: admin)"
  echo "    Custom browser profile: MESHVPN_BROWSER_PROFILE_SRC=/path/to/browser-profile.json ./device/scripts/flash.sh"
  echo "    If Ethernet/WiFi act up: cd device && idf.py -p $PORT erase-flash flash"
fi

if [[ "$MONITOR" == "monitor" ]]; then
  if [[ -z "$PORT" ]]; then
    echo "No PORT for monitor" >&2
    exit 1
  fi
  idf.py monitor -p "$PORT"
fi
