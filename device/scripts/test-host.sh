#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
test_dir="$(mktemp -d /tmp/meshpn-host-tests.XXXXXX)"
cd "$root"
cc="${CC:-cc}"
flags=(-std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined)
"$cc" "${flags[@]}" -Idevice/components/meshvpn_vpn/include device/tests/test_vpn_frame.c \
  device/components/meshvpn_vpn/meshvpn_vpn_frame.c -o "$test_dir/vpn-frame"
"$test_dir/vpn-frame"
"$cc" "${flags[@]}" -Idevice/components/meshvpn_vpn/include device/tests/test_vpn_stream.c \
  device/components/meshvpn_vpn/meshvpn_vpn_stream.c device/components/meshvpn_vpn/meshvpn_vpn_frame.c -o "$test_dir/vpn-stream"
"$test_dir/vpn-stream"
"$cc" "${flags[@]}" -Idevice/components/meshvpn_vpn/include device/tests/test_vpn_profile.c \
  device/components/meshvpn_vpn/meshvpn_vpn_profile.c -o "$test_dir/vpn-profile"
"$test_dir/vpn-profile"
node device/tests/test-vpn-wire.mjs "$test_dir/vpn-frame"
node device/tests/test-vpn-routing.mjs
node device/tests/test-vpn-storage.mjs
node device/tests/test-vpn-probe.mjs
node device/tests/test-vpn-ingress.mjs
node device/tests/test-vpn-queue.mjs
node device/tests/test-vpn-udp-batch.mjs
wg_src=device/managed_components/esphome__wireguard/src
if [[ -f "$wg_src/crypto/refc/chacha20.c" ]]; then
  for optimization in Og O2; do
    # Upstream has a signed loop counter; match IDF's warning policy without
    # editing dependency sources. Sanitizers and assertions stay enabled.
    "$cc" "${flags[@]}" -Wno-sign-compare "-$optimization" -I"$wg_src" -Idevice/tests/wg_crypto_stubs \
      device/tests/test_wg_aead.c "$wg_src/crypto.c" \
      "$wg_src/crypto/refc/chacha20.c" "$wg_src/crypto/refc/chacha20poly1305.c" \
      "$wg_src/crypto/refc/poly1305-donna.c" -o "$test_dir/wg-aead-$optimization"
  done
  node device/tests/test-wg-aead.mjs "$test_dir/wg-aead-Og" "$test_dir/wg-aead-O2"
else
  echo "WireGuard AEAD tests skipped: install device managed dependencies."
fi
"$cc" "${flags[@]}" -pthread -Idevice/tests/wifi_stubs -Idevice/tests/usb_stubs -Idevice/tests/cpu_stubs \
  -Idevice/components/meshvpn_wifi/include -Idevice/components/meshvpn_vpn/include \
  device/tests/test_wifi_diag.c -o "$test_dir/wifi-diag"
"$test_dir/wifi-diag"
"$cc" "${flags[@]}" -pthread -Idevice/tests/led_stubs -Idevice/tests/usb_stubs \
  -Idevice/components/meshvpn_board/include device/tests/test_board_led.c \
  device/components/meshvpn_board/meshvpn_board_led.c -o "$test_dir/board-led"
"$test_dir/board-led"
"$cc" "${flags[@]}" -DTEST_USER_LED=1 -Idevice/tests/stubs \
  -Idevice/components/meshvpn_config/include device/tests/test_https_config.c \
  device/components/meshvpn_config/meshvpn_config_web.c -o "$test_dir/led-config"
"$test_dir/led-config"
"$cc" "${flags[@]}" -Idevice/components/meshvpn_web/include device/tests/test_local_download.c -o "$test_dir/local-download"
"$test_dir/local-download"
"$cc" "${flags[@]}" -Idevice/tests/dhcp_stubs -Idevice/tests/stubs \
  -Idevice/components/meshvpn_net/include device/tests/test_lan_dhcp.c \
  device/components/meshvpn_net/meshvpn_net_dhcp.c -o "$test_dir/lan-dhcp"
"$test_dir/lan-dhcp"
for variant in 0:0 1:0 1:1; do
  queue_enabled=${variant%:*}; event_enabled=${variant#*:}
  "$cc" "${flags[@]}" -pthread -DCONFIG_MESHVPN_USB_TX_EVENT_WAIT="$event_enabled" -DCONFIG_MESHVPN_USB_PROFILE_NCM=1 -DCONFIG_MESHVPN_USB_TX_QUEUE="$queue_enabled" \
    -Idevice/tests/usb_stubs -Idevice/tests/cpu_stubs \
    -Idevice/components/meshvpn_usb/include -Idevice/components/meshvpn_vpn/include \
    device/tests/test_usb_tx.c -o "$test_dir/usb-tx-$queue_enabled-$event_enabled"
  "$test_dir/usb-tx-$queue_enabled-$event_enabled"
done
"$cc" "${flags[@]}" -pthread -DCONFIG_MESHVPN_USB_NCM_DOUBLE_BUFFER=1 \
  -DCONFIG_MESHVPN_USB_PROFILE_NCM=1 -Idevice/tests/usb_stubs -Idevice/tests/cpu_stubs \
  -Idevice/components/meshvpn_usb/include -Idevice/components/meshvpn_vpn/include \
  device/tests/test_usb_tx.c -o "$test_dir/usb-double-fifo"
"$test_dir/usb-double-fifo"
for event_enabled in 0 1; do
  "$cc" "${flags[@]}" -pthread -DCONFIG_MESHVPN_USB_TX_EVENT_WAIT="$event_enabled" -DCONFIG_MESHVPN_USB_TX_QUEUE=1 \
    -DCONFIG_MESHVPN_NCM_TELEMETRY="$event_enabled" \
    -Idevice/tests/queue_stubs -Idevice/tests/usb_stubs -Idevice/tests/cpu_stubs \
    -Idevice/components/meshvpn_usb/include device/tests/test_usb_tx_queue.c -o "$test_dir/usb-tx-queue-$event_enabled"
  "$test_dir/usb-tx-queue-$event_enabled"
done
"$cc" "${flags[@]}" -pthread -Idevice/tests/usb_stubs -Idevice/tests/cpu_stubs \
  -Idevice/components/meshvpn_usb/include device/tests/test_ncm_diag.c -o "$test_dir/ncm-diag"
"$test_dir/ncm-diag"
python3 -B device/tests/test_instrument_ncm.py
python3 -B device/tests/test_instrument_dwc2.py
python3 -B device/tests/test_flash_device.py
"$cc" "${flags[@]}" -pthread -Idevice/tests/usb_stubs -Idevice/tests/cpu_stubs \
  -Idevice/components/meshvpn_usb/include device/tests/test_dwc2_diag.c -o "$test_dir/dwc2-diag"
"$test_dir/dwc2-diag"
ncm_src=device/managed_components/espressif__tinyusb/src
if [[ -f "$ncm_src/class/net/ncm_device.c" ]]; then
  python3 -B device/tests/test_dwc2_fifo.py
  usb_wrapper=device/managed_components/espressif__esp_tinyusb
  for cdc_count in 0 1; do
    "$cc" "${flags[@]}" -DCFG_TUD_CDC="$cdc_count" -DCONFIG_TINYUSB_CDC_ENABLED="$cdc_count" \
      -DMESHVPN_DESCRIPTOR_SOURCE="\"$root/$usb_wrapper/usb_descriptors.c\"" \
      -Idevice/tests/ncm_stubs -Idevice/tests/cpu_stubs -I"$ncm_src" \
      -I"$usb_wrapper/include_private" -I"$usb_wrapper/include" \
      -Idevice/components/meshvpn_usb/include device/tests/test_usb_fifo.c -o "$test_dir/usb-fifo-descriptor-$cdc_count"
    "$test_dir/usb-fifo-descriptor-$cdc_count"
  done
  python3 device/scripts/instrument-ncm.py "$ncm_src/class/net/ncm_device.c" "$test_dir/ncm_device.c"
  for variant in 0:0 1:0 1:1; do
    event_enabled=${variant%:*}; dwc_enabled=${variant#*:}
    "$cc" "${flags[@]}" -pthread -DCONFIG_MESHVPN_DWC2_TELEMETRY="$dwc_enabled" -DCONFIG_MESHVPN_USB_TX_EVENT_WAIT="$event_enabled" -DMESHVPN_NCM_SOURCE="\"$test_dir/ncm_device.c\"" \
      -Idevice/tests/ncm_stubs -Idevice/tests/usb_stubs -Idevice/tests/cpu_stubs \
      -I"$ncm_src" -I"$ncm_src/class/net" -Idevice/components/meshvpn_usb/include \
      device/tests/test_ncm_driver.c device/components/meshvpn_usb/meshvpn_ncm_diag.c \
      device/components/meshvpn_usb/meshvpn_dwc2_diag.c -o "$test_dir/ncm-driver-$event_enabled-$dwc_enabled"
    "$test_dir/ncm-driver-$event_enabled-$dwc_enabled"
  done
else
  echo "Actual NCM driver tests skipped: install device managed dependencies."
fi
"$cc" "${flags[@]}" device/tests/test_perf_bind.c -o "$test_dir/perf-bind"
"$test_dir/perf-bind"
for psram_enabled in 0 1; do
  "$cc" "${flags[@]}" -DCONFIG_SPIRAM="$psram_enabled" -DpdTRUE=1 \
    -Idevice/tests/log_stubs -Idevice/tests/cpu_stubs -Idevice/tests/stubs \
    -Idevice/components/meshvpn_log/include device/tests/test_log_buffer.c -o "$test_dir/log-buffer-$psram_enabled"
  "$test_dir/log-buffer-$psram_enabled"
done
"$cc" "${flags[@]}" -Idevice/components/meshvpn_web/include \
  device/tests/test_cpu_math.c -o "$test_dir/cpu-math"
"$test_dir/cpu-math"
"$cc" "${flags[@]}" -Idevice/components/meshvpn_routing/include \
  device/tests/test_dns_ranges.c device/components/meshvpn_routing/meshvpn_dns_wire.c \
  device/components/meshvpn_routing/meshvpn_ip_ranges.c -o "$test_dir/dns-ranges"
"$test_dir/dns-ranges"
"$cc" "${flags[@]}" -Idevice/tests/stubs -Idevice/components/meshvpn_net/include \
  -Idevice/components/meshvpn_web/include device/tests/test_ingress_session.c \
  device/components/meshvpn_net/meshvpn_net_hooks.c -o "$test_dir/ingress-session"
"$test_dir/ingress-session"
node device/tests/test-ip-ranges.mjs
node device/tests/test-web-ui.mjs
node device/tests/test-web-bursts.mjs
for default_https in 0 1; do
  "$cc" "${flags[@]}" -DCONFIG_MESHVPN_WEB_HTTPS="$default_https" \
    -Idevice/tests/stubs -Idevice/components/meshvpn_config/include \
    device/tests/test_https_config.c device/components/meshvpn_config/meshvpn_config_web.c \
    -o "$test_dir/https-config-$default_https"
  "$test_dir/https-config-$default_https"
done
bash -n device/scripts/flash.sh device/scripts/setup-macos.sh device/scripts/create-admin-ca.sh
for board_target in \
  xiao_esp32s3:esp32s3 \
  m5_stamp_p4_c6:esp32p4 \
  waveshare_esp32_p4_wifi6:esp32p4; do
  board=${board_target%:*}
  expected=${board_target#*:}
  actual=$(tr -d '[:space:]' < "device/boards/$board/target")
  [[ "$actual" == "$expected" ]] || { echo "$board target: expected $expected, got $actual" >&2; exit 1; }
  [[ -f "device/boards/$board/sdkconfig.defaults" ]] || { echo "$board defaults missing" >&2; exit 1; }
done
if [[ -n "${IDF_PATH:-}" ]]; then
  json_dir="$IDF_PATH/components/json/cJSON"
  "$cc" "${flags[@]}" -pthread -Idevice/tests/wg_diag_stubs -Idevice/tests/usb_stubs \
    -Idevice/tests/cpu_stubs -Idevice/components/meshvpn_vpn/include \
    -Idevice/components/meshvpn_web/include -I"$json_dir" \
    device/tests/test_wg_diag.c "$json_dir/cJSON.c" -o "$test_dir/wg-diag"
  "$test_dir/wg-diag"
  for runtime_enabled in 0 1; do
    for psram_enabled in 0 1; do
      "$cc" "${flags[@]}" -DCONFIG_FREERTOS_GENERATE_RUN_TIME_STATS="$runtime_enabled" \
        -DCONFIG_SPIRAM="$psram_enabled" \
        -Idevice/tests/cpu_stubs -Idevice/components/meshvpn_web/include -I"$json_dir" \
        -Idevice/components/meshvpn_vpn/include \
        device/tests/test_cpu_sampler.c "$json_dir/cJSON.c" -lm -o "$test_dir/cpu-sampler-$runtime_enabled-$psram_enabled"
      "$test_dir/cpu-sampler-$runtime_enabled-$psram_enabled"
    done
  done
  source_dir="$IDF_PATH/components/mbedtls/mbedtls"
  cmake -S "$source_dir" -B "$test_dir/mbedtls" -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF > "$test_dir/mbedtls.log" 2>&1
  cmake --build "$test_dir/mbedtls" -j 4 >> "$test_dir/mbedtls.log" 2>&1
  node device/tests/test-vpn-config.mjs "$test_dir/mbedtls/library/libmbedcrypto.a"
  bash device/scripts/create-admin-ca.sh "$test_dir/tls" > "$test_dir/certificates.log" 2>&1
  "$cc" "${flags[@]}" -Idevice/tests/stubs -Idevice/components/meshvpn_web/include \
    -I"$source_dir/include" device/tests/test_tls_identity.c \
    "$test_dir/mbedtls/library/libmbedx509.a" "$test_dir/mbedtls/library/libmbedcrypto.a" -o "$test_dir/tls-identity"
  "$test_dir/tls-identity" "$test_dir/tls/device.crt" "$test_dir/tls/device.key"
else
  echo "TLS identity test skipped: set IDF_PATH to an ESP-IDF 5.4.1 checkout to include it."
fi
echo "Host test artifacts: $test_dir"
