#!/usr/bin/env bash
# Build/flash the selected board and USB profile.
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
TARGET_FILE="$DEVICE_DIR/boards/$BOARD/target"
if [[ ! -f "$TARGET_FILE" ]]; then
  echo "Board $BOARD has no target metadata" >&2; exit 1
fi
IDF_TARGET="$(tr -d '[:space:]' < "$TARGET_FILE")"
case "$IDF_TARGET" in esp32s3|esp32p4) ;; *) echo "Invalid target for $BOARD: $IDF_TARGET" >&2; exit 1;; esac
if [[ -n "${IDF_PATH:-}" && -f "$IDF_PATH/export.sh" ]]; then
  source "$IDF_PATH/export.sh"
elif [[ -f "$HOME/esp/esp-idf/export.sh" ]]; then
  source "$HOME/esp/esp-idf/export.sh"
else
  echo "ESP-IDF not found. Run device/scripts/setup-macos.sh." >&2; exit 1
fi
export BOARD USB_PROFILE="$PROFILE" USB_DIAGNOSTICS="${USB_DIAGNOSTICS:-0}"
if [[ "$IDF_TARGET" == esp32s3 ]]; then
  export DWC2_TELEMETRY="${DWC2_TELEMETRY:-1}"
else
  export DWC2_TELEMETRY="${DWC2_TELEMETRY:-0}"
fi
case "$DWC2_TELEMETRY" in 0|1) ;; *) echo "DWC2_TELEMETRY must be 0 or 1" >&2; exit 1;; esac
case "$USB_DIAGNOSTICS" in 0|1) ;; *) echo "USB_DIAGNOSTICS must be 0 or 1" >&2; exit 1;; esac
# Preserve previous builds and menuconfig files. A changed set of defaults gets
# a new sdkconfig, so security settings and profile changes cannot stay stale.
config_files=("$DEVICE_DIR/sdkconfig.defaults" "$DEVICE_DIR/boards/$BOARD/sdkconfig.defaults" "$TARGET_FILE" "$DEVICE_DIR/profiles/usb_$PROFILE.defconfig" "$DEVICE_DIR/main/idf_component.yml")
if [[ "$USB_DIAGNOSTICS" == 1 ]]; then
  config_files+=("$DEVICE_DIR/profiles/usb_diagnostics.defconfig")
fi
if [[ "$DWC2_TELEMETRY" == 0 ]]; then
  config_files+=("$DEVICE_DIR/profiles/dwc2_telemetry_off.defconfig")
fi
config_id="$(cksum "${config_files[@]}" | cksum | awk '{print $1}')"
BUILD_DIR="$DEVICE_DIR/build-$BOARD-$PROFILE-$config_id"
mkdir -p "$BUILD_DIR"
PORT="${PORT:-}"
if [[ -z "$PORT" ]]; then
  for candidate in /dev/cu.usbmodem* /dev/cu.SLAB_USBtoUART /dev/cu.wchusbserial* /dev/ttyACM* /dev/ttyUSB*; do
    [[ -e "$candidate" ]] || continue
    PORT="$candidate"; break
  done
fi
args=(-C "$DEVICE_DIR" -B "$BUILD_DIR" -D "SDKCONFIG=$BUILD_DIR/sdkconfig" -D "IDF_TARGET=$IDF_TARGET" build)
if [[ -n "$PORT" ]]; then
  args+=(flash -p "$PORT")
else
  echo "No serial port found; building only. Hold BOOT while connecting the programming port to flash."
fi
echo "Board: $BOARD; target: $IDF_TARGET; USB profile: $PROFILE"
idf.py "${args[@]}"
echo "Build artifacts: $BUILD_DIR"
if [[ "$MONITOR" == monitor ]]; then
  [[ -n "$PORT" ]] || { echo "No PORT for monitor" >&2; exit 1; }
  idf.py -C "$DEVICE_DIR" -B "$BUILD_DIR" -p "$PORT" monitor
fi
