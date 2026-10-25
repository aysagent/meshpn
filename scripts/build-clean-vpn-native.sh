#!/usr/bin/env bash
# Build only; never stop services or overwrite the installed boring-tls helper.
set -euo pipefail
cv_low_memory=OFF
cv_jobs=1
cv_jobs_seen=0
if [ "$#" -eq 1 ] && [ "$1" = --help ]; then
  echo 'Usage: bash scripts/build-clean-vpn-native.sh [--low-memory] [--jobs=1..8]'
  echo 'Default: one compiler job. --jobs sets an explicit memory-conscious limit; services unchanged.'
  echo '--low-memory omits debug information, keeps -O2 and all tests.'
  echo 'It does not create swap or guarantee a build with insufficient RAM/swap.'
  exit 0
fi
for cv_arg in "$@"; do
  case "$cv_arg" in
    --low-memory)
      if [ "$cv_low_memory" = ON ]; then echo 'Duplicate --low-memory.' >&2; exit 2; fi
      cv_low_memory=ON ;;
    --jobs=[1-8])
      if [ "$cv_jobs_seen" -eq 1 ]; then echo 'Duplicate --jobs.' >&2; exit 2; fi
      cv_jobs=${cv_arg#--jobs=}; cv_jobs_seen=1 ;;
    *) echo 'Unknown argument; use --help. Jobs must be 1..8.' >&2; exit 2 ;;
  esac
done
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
echo "Building native ($cv_jobs compiler jobs); running services unchanged. Log: $cv_log"
if [ "$cv_low_memory" = ON ]; then
  echo 'Low-memory build: debug information disabled; optimization and tests retained. No swap/system changes.'
fi
if (
  echo "NATIVE_BUILD_PROFILE: RelWithDebInfo; low_memory=$cv_low_memory; jobs=$cv_jobs"
  # A separate dependency tree is necessary even when using the SAME checkout:
  # configuring the legacy helper tree applies patches to its BoringSSL source.
  cmake -S native/boring_tls -B native/clean_vpn/build-deps-helper -DCMAKE_BUILD_TYPE=Release &&
  cmake -S native/clean_vpn -B native/clean_vpn/build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCVPN_SANITIZE=OFF \
    "-DCVPN_LOW_MEMORY_BUILD=$cv_low_memory" \
    "-DCVPN_BORINGSSL_SOURCE=$PWD/native/clean_vpn/build-deps-helper/_deps/boringssl-src" \
    "-DCVPN_JSON_SOURCE=$PWD/native/clean_vpn/build-deps-helper/_deps/json-src" &&
  cmake --build native/clean_vpn/build --target clean-vpn-engine protocol-test dns-wire-test service-notify-test transparent-test transparent-socket-test transparent-replay-test combo-test throughput-test --parallel "$cv_jobs" &&
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
