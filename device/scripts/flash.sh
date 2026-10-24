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
unset IDF_PYTHON_ENV_PATH
default_idf="$HOME/esp/esp-idf-meshpn-v5.5.5"
if [[ "${IDF_PATH:-}" == "$HOME/esp/esp-idf" &&
      "$(git -C "$IDF_PATH" describe --tags --exact-match 2>/dev/null || true)" != v5.5.5 ]]; then
  # Older terminals may still export the old 5.4 checkout from ~/.zshrc.
  selected_idf="$default_idf"
elif [[ -n "${IDF_PATH:-}" && -f "$IDF_PATH/export.sh" ]]; then
  selected_idf="$IDF_PATH"
elif [[ -f "$default_idf/export.sh" ]]; then
  selected_idf="$default_idf"
else
  echo "ESP-IDF 5.5.5 not found. Run device/scripts/setup-macos.sh." >&2; exit 1
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
export BOARD USB_PROFILE="$PROFILE" USB_DIAGNOSTICS="${USB_DIAGNOSTICS:-0}"
if [[ "${DEVICE_BIND_ONLY:-0}" == 1 ]]; then
  python "$DEVICE_DIR/scripts/flash-device.py" --device-dir "$DEVICE_DIR" \
    --build-dir "$DEVICE_DIR" --target "$IDF_TARGET" --profile "$PROFILE" --bind
  exit 0
fi
if [[ "$IDF_TARGET" == esp32s3 ]]; then
  export DWC2_TELEMETRY="${DWC2_TELEMETRY:-1}"
else
  export DWC2_TELEMETRY="${DWC2_TELEMETRY:-0}"
fi
case "$DWC2_TELEMETRY" in 0|1) ;; *) echo "DWC2_TELEMETRY must be 0 or 1" >&2; exit 1;; esac
case "$USB_DIAGNOSTICS" in 0|1) ;; *) echo "USB_DIAGNOSTICS must be 0 or 1" >&2; exit 1;; esac
WIREGUARD_PERF="${WIREGUARD_PERF:-1}"
case "$WIREGUARD_PERF" in 0|1) ;; *) echo "WIREGUARD_PERF must be 0 or 1" >&2; exit 1;; esac
# Preserve previous builds and menuconfig files. A changed set of defaults gets
# a new sdkconfig, so security settings and profile changes cannot stay stale.
config_files=("$DEVICE_DIR/sdkconfig.defaults" "$DEVICE_DIR/boards/$BOARD/sdkconfig.defaults" "$TARGET_FILE" "$DEVICE_DIR/profiles/usb_$PROFILE.defconfig" "$DEVICE_DIR/main/idf_component.yml")
if [[ "$IDF_TARGET" == esp32p4 ]]; then
  config_files+=("$DEVICE_DIR/target_components/esp32p4_bridge_config/Kconfig")
fi
if [[ "$USB_DIAGNOSTICS" == 1 ]]; then
  config_files+=("$DEVICE_DIR/profiles/usb_diagnostics.defconfig")
fi
if [[ "$DWC2_TELEMETRY" == 0 ]]; then
  config_files+=("$DEVICE_DIR/profiles/dwc2_telemetry_off.defconfig")
fi
config_id="$(cksum "${config_files[@]}" | cksum | awk '{print $1}')"
BUILD_DIR="$DEVICE_DIR/build-$BOARD-$PROFILE-$config_id-wg$WIREGUARD_PERF"
mkdir -p "$BUILD_DIR"
# Build before disturbing the running network or entering ROM download mode.
args=(-C "$DEVICE_DIR" -B "$BUILD_DIR" -D "SDKCONFIG=$BUILD_DIR/sdkconfig" -D "IDF_TARGET=$IDF_TARGET" -D "MESHVPN_WIREGUARD_PERF=$WIREGUARD_PERF" build)
echo "Board: $BOARD; target: $IDF_TARGET; USB profile: $PROFILE"
idf.py "${args[@]}"
echo "Build artifacts: $BUILD_DIR"
case "${BUILD_ONLY:-0}" in
  1) exit 0;;
  0) ;;
  *) echo "BUILD_ONLY must be 0 or 1" >&2; exit 1;;
esac
flash_args=(--device-dir "$DEVICE_DIR" --build-dir "$BUILD_DIR" --target "$IDF_TARGET" --profile "$PROFILE")
[[ -z "${PORT:-}" ]] || flash_args+=(--port "$PORT")
[[ "$MONITOR" != monitor ]] || flash_args+=(--monitor)
python "$DEVICE_DIR/scripts/flash-device.py" "${flash_args[@]}"
