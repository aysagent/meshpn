#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
test_dir="$(mktemp -d /tmp/meshpn-host-tests.XXXXXX)"
cd "$root"
cc="${CC:-cc}"
flags=(-std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined)
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
bash -n device/scripts/flash.sh device/scripts/create-admin-ca.sh
if [[ -n "${IDF_PATH:-}" ]]; then
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
