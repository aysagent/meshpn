#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
test_dir="$(mktemp -d /tmp/meshpn-host-tests.XXXXXX)"
cd "$root"
cc="${CC:-cc}"
flags=(-std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined)
for variant in 0:0 1:0 1:1; do
  queue_enabled=${variant%:*}; event_enabled=${variant#*:}
  "$cc" "${flags[@]}" -pthread -DCONFIG_MESHVPN_USB_TX_EVENT_WAIT="$event_enabled" -DCONFIG_MESHVPN_USB_PROFILE_NCM=1 -DCONFIG_MESHVPN_USB_TX_QUEUE="$queue_enabled" \
    -Idevice/tests/usb_stubs -Idevice/tests/cpu_stubs \
    -Idevice/components/meshvpn_usb/include device/tests/test_usb_tx.c -o "$test_dir/usb-tx-$queue_enabled-$event_enabled"
  "$test_dir/usb-tx-$queue_enabled-$event_enabled"
done
for event_enabled in 0 1; do
  "$cc" "${flags[@]}" -pthread -DCONFIG_MESHVPN_USB_TX_EVENT_WAIT="$event_enabled" -DCONFIG_MESHVPN_USB_TX_QUEUE=1 \
    -Idevice/tests/queue_stubs -Idevice/tests/usb_stubs -Idevice/tests/cpu_stubs \
    -Idevice/components/meshvpn_usb/include device/tests/test_usb_tx_queue.c -o "$test_dir/usb-tx-queue-$event_enabled"
  "$test_dir/usb-tx-queue-$event_enabled"
done
"$cc" "${flags[@]}" -pthread -Idevice/tests/usb_stubs -Idevice/tests/cpu_stubs \
  -Idevice/components/meshvpn_usb/include device/tests/test_ncm_diag.c -o "$test_dir/ncm-diag"
"$test_dir/ncm-diag"
python3 -B device/tests/test_instrument_ncm.py
ncm_src=device/managed_components/espressif__tinyusb/src
if [[ -f "$ncm_src/class/net/ncm_device.c" ]]; then
  python3 device/scripts/instrument-ncm.py "$ncm_src/class/net/ncm_device.c" "$test_dir/ncm_device.c"
  for event_enabled in 0 1; do
    "$cc" "${flags[@]}" -pthread -DCONFIG_MESHVPN_USB_TX_EVENT_WAIT="$event_enabled" -DMESHVPN_NCM_SOURCE="\"$test_dir/ncm_device.c\"" \
      -Idevice/tests/ncm_stubs -Idevice/tests/usb_stubs -Idevice/tests/cpu_stubs \
      -I"$ncm_src" -I"$ncm_src/class/net" -Idevice/components/meshvpn_usb/include \
      device/tests/test_ncm_driver.c device/components/meshvpn_usb/meshvpn_ncm_diag.c -o "$test_dir/ncm-driver-$event_enabled"
    "$test_dir/ncm-driver-$event_enabled"
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
for default_https in 0 1; do
  "$cc" "${flags[@]}" -DCONFIG_MESHVPN_WEB_HTTPS="$default_https" \
    -Idevice/tests/stubs -Idevice/components/meshvpn_config/include \
    device/tests/test_https_config.c device/components/meshvpn_config/meshvpn_config_web.c \
    -o "$test_dir/https-config-$default_https"
  "$test_dir/https-config-$default_https"
done
bash -n device/scripts/flash.sh device/scripts/create-admin-ca.sh
if [[ -n "${IDF_PATH:-}" ]]; then
  json_dir="$IDF_PATH/components/json/cJSON"
  for runtime_enabled in 0 1; do
    for psram_enabled in 0 1; do
      "$cc" "${flags[@]}" -DCONFIG_FREERTOS_GENERATE_RUN_TIME_STATS="$runtime_enabled" \
        -DCONFIG_SPIRAM="$psram_enabled" \
        -Idevice/tests/cpu_stubs -Idevice/components/meshvpn_web/include -I"$json_dir" \
        device/tests/test_cpu_sampler.c "$json_dir/cJSON.c" -lm -o "$test_dir/cpu-sampler-$runtime_enabled-$psram_enabled"
      "$test_dir/cpu-sampler-$runtime_enabled-$psram_enabled"
    done
  done
  source_dir="$IDF_PATH/components/mbedtls/mbedtls"
  cmake -S "$source_dir" -B "$test_dir/mbedtls" -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF > "$test_dir/mbedtls.log" 2>&1
  cmake --build "$test_dir/mbedtls" -j 4 >> "$test_dir/mbedtls.log" 2>&1
  bash device/scripts/create-admin-ca.sh "$test_dir/tls" > "$test_dir/certificates.log" 2>&1
  "$cc" "${flags[@]}" -Idevice/tests/stubs -Idevice/components/meshvpn_web/include \
    -I"$source_dir/include" device/tests/test_tls_identity.c \
    "$test_dir/mbedtls/library/libmbedx509.a" "$test_dir/mbedtls/library/libmbedcrypto.a" -o "$test_dir/tls-identity"
  "$test_dir/tls-identity" "$test_dir/tls/device.crt" "$test_dir/tls/device.key"
else
  echo "TLS identity test skipped: set IDF_PATH to an ESP-IDF 5.4.1 checkout to include it."
fi
echo "Host test artifacts: $test_dir"
