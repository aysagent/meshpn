#!/usr/bin/env bash
# Build only; never stop services or overwrite the installed boring-tls helper.
set -euo pipefail
cv_low_memory=OFF
if [ "$#" -gt 1 ]; then
  echo 'Usage: bash scripts/build-clean-vpn-native.sh [--low-memory|--help]' >&2
  exit 2
fi
case "${1-}" in
  '') ;;
  --low-memory) cv_low_memory=ON ;;
  --help)
    echo 'Usage: bash scripts/build-clean-vpn-native.sh [--low-memory]'
    echo 'One compiler job, services unchanged. --low-memory omits debug information, keeps -O2 and all tests.'
    echo 'It does not create swap or guarantee a build with insufficient RAM.'
    exit 0 ;;
  *) echo 'Unknown argument; use --help.' >&2; exit 2 ;;
esac
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
echo "Building native (one compiler job); running services unchanged. Log: $cv_log"
if [ "$cv_low_memory" = ON ]; then
  echo 'Low-memory build: debug information disabled; optimization and tests retained. No swap/system changes.'
fi
if (
  echo "NATIVE_BUILD_PROFILE: RelWithDebInfo; low_memory=$cv_low_memory; jobs=1"
  # A separate dependency tree is necessary even when using the SAME checkout:
  # configuring the legacy helper tree applies patches to its BoringSSL source.
  cmake -S native/boring_tls -B native/clean_vpn/build-deps-helper -DCMAKE_BUILD_TYPE=Release &&
  cmake -S native/clean_vpn -B native/clean_vpn/build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCVPN_SANITIZE=OFF \
    "-DCVPN_LOW_MEMORY_BUILD=$cv_low_memory" \
    "-DCVPN_BORINGSSL_SOURCE=$PWD/native/clean_vpn/build-deps-helper/_deps/boringssl-src" \
    "-DCVPN_JSON_SOURCE=$PWD/native/clean_vpn/build-deps-helper/_deps/json-src" &&
  cmake --build native/clean_vpn/build --target clean-vpn-engine protocol-test dns-wire-test service-notify-test transparent-test transparent-socket-test transparent-replay-test combo-test throughput-test --parallel 1 &&
  ctest --test-dir native/clean_vpn/build --output-on-failure &&
  native/clean_vpn/build/clean-vpn-engine --capabilities
) >"$cv_log" 2>&1; then
  echo 'NATIVE_BUILD=passed (services unchanged)'
  tail -n 14 "$cv_log"
else
  echo 'NATIVE_BUILD=failed (services unchanged)' >&2
  tail -n 60 "$cv_log" >&2
  echo 'If the compiler was killed/terminated, inspect kernel OOM logs; --low-memory cannot replace missing RAM/swap.' >&2
  exit 1
fi
