#!/usr/bin/env bash
# Build only; never stop services or overwrite the installed boring-tls helper.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
for cv_tool in cmake git patch c++ node flock; do
  if ! command -v "$cv_tool" >/dev/null; then
    echo "Missing $cv_tool. Install prerequisites: apt-get install build-essential cmake git patch pkg-config perl python3" >&2
    exit 1
  fi
done
mkdir -p native/clean_vpn/build
exec 9>native/clean_vpn/build/radxa-operation.lock
if ! flock -n 9; then
  echo 'Another native build/trial is running; no changes made.' >&2
  exit 1
fi
cv_log="$PWD/native/clean_vpn/build/radxa-build.log"
echo "Building native M1 (one compiler job); old VPN stays running. Log: $cv_log"
if (
  # A separate dependency tree is necessary even when using the SAME checkout:
  # configuring the legacy helper tree applies patches to its BoringSSL source.
  cmake -S native/boring_tls -B native/clean_vpn/build-deps-helper -DCMAKE_BUILD_TYPE=Release &&
  cmake -S native/clean_vpn -B native/clean_vpn/build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCVPN_SANITIZE=OFF \
    "-DCVPN_BORINGSSL_SOURCE=$PWD/native/clean_vpn/build-deps-helper/_deps/boringssl-src" \
    "-DCVPN_JSON_SOURCE=$PWD/native/clean_vpn/build-deps-helper/_deps/json-src" &&
  cmake --build native/clean_vpn/build --target clean-vpn-engine protocol-test dns-wire-test --parallel 1 &&
  ctest --test-dir native/clean_vpn/build --output-on-failure &&
  native/clean_vpn/build/clean-vpn-engine --capabilities
) >"$cv_log" 2>&1; then
  echo 'NATIVE_BUILD=passed (services unchanged)'
  tail -n 14 "$cv_log"
else
  echo 'NATIVE_BUILD=failed (services unchanged)' >&2
  tail -n 60 "$cv_log" >&2
  exit 1
fi
