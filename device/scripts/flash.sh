#!/usr/bin/env bash
# Build/flash the existing selected USB profile. Compatibility expansion is deferred.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEVICE_DIR="$ROOT/device"
BOARD="${BOARD:-xiao_esp32s3}"
PROFILE="${1:-${USB_PROFILE:-ncm}}"
MONITOR="${2:-}"
case "$PROFILE" in ncm|ecm|rndis) ;; *) echo "Invalid USB profile: $PROFILE" >&2; exit 1;; esac
if [[ ! -f "$DEVICE_DIR/boards/$BOARD/sdkconfig.defaults" ]]; then
  echo "Unknown board: $BOARD" >&2; exit 1
fi
if [[ -n "${IDF_PATH:-}" && -f "$IDF_PATH/export.sh" ]]; then
  source "$IDF_PATH/export.sh"
elif [[ -f "$HOME/esp/esp-idf/export.sh" ]]; then
  source "$HOME/esp/esp-idf/export.sh"
else
  echo "ESP-IDF not found. Run device/scripts/setup-macos.sh." >&2; exit 1
fi
export BOARD USB_PROFILE="$PROFILE"
# Preserve previous builds and menuconfig files. A changed set of defaults gets
# a new sdkconfig, so security settings and profile changes cannot stay stale.
config_id="$(cksum "$DEVICE_DIR/sdkconfig.defaults" "$DEVICE_DIR/boards/$BOARD/sdkconfig.defaults" "$DEVICE_DIR/profiles/usb_$PROFILE.defconfig" "$DEVICE_DIR/main/idf_component.yml" | cksum | awk '{print $1}')"
BUILD_DIR="$DEVICE_DIR/build-$BOARD-$PROFILE-$config_id"
mkdir -p "$BUILD_DIR"
PORT="${PORT:-}"
if [[ -z "$PORT" ]]; then
  for candidate in /dev/cu.usbmodem* /dev/cu.SLAB_USBtoUART /dev/cu.wchusbserial* /dev/ttyACM* /dev/ttyUSB*; do
    [[ -e "$candidate" ]] || continue
    PORT="$candidate"; break
  done
fi
args=(-C "$DEVICE_DIR" -B "$BUILD_DIR" -D "SDKCONFIG=$BUILD_DIR/sdkconfig" -D IDF_TARGET=esp32s3 build)
if [[ -n "$PORT" ]]; then
  args+=(flash -p "$PORT")
else
  echo "No serial port found; building only. Hold BOOT while plugging in to flash."
fi
idf.py "${args[@]}"
echo "Build artifacts: $BUILD_DIR"
if [[ "$MONITOR" == monitor ]]; then
  [[ -n "$PORT" ]] || { echo "No PORT for monitor" >&2; exit 1; }
  idf.py -C "$DEVICE_DIR" -B "$BUILD_DIR" -p "$PORT" monitor
fi
