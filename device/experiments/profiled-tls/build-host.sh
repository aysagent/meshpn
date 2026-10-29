#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
[[ $# == 1 && ! -e "$1" ]] || { echo 'Usage: build-host.sh NEW_ARTIFACT_DIRECTORY' >&2; exit 2; }
mkdir -m 700 -p "$1"
out="$(cd "$1" && pwd)"
idf="${IDF_PATH:-$HOME/esp/esp-idf-meshpn-v5.5.5}"
[[ "$(git -C "$idf" describe --tags --exact-match)" == v5.5.5 ]] || { echo 'Requires ESP-IDF v5.5.5' >&2; exit 2; }
bssl="${BSSL_SOURCE:-$here/../../../native/boring_tls/build/_deps/boringssl-src}"
python3 "$here/prepare-bssl.py" "$bssl" "$out/bssl-source" >"$out/prepare.log"
cmake -S "$idf/components/mbedtls/mbedtls" -B "$out/mbedtls" -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF >"$out/mbedtls-build.log" 2>&1
cmake --build "$out/mbedtls" -j 4 >>"$out/mbedtls-build.log" 2>&1
cmake -S "$out/bssl-source" -B "$out/bssl" -DBUILD_TESTING=OFF -DOPENSSL_SMALL=ON -DOPENSSL_NO_ASM=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS=-DMESHPN_PROBE_ALLOCATOR >"$out/bssl-build.log" 2>&1
cmake --build "$out/bssl" --target ssl crypto -j 4 >>"$out/bssl-build.log" 2>&1
cc -O2 -Wall -Wextra -Werror -I"$idf/components/mbedtls/mbedtls/include" "$here/mbedtls_probe.c" "$out/mbedtls/library/libmbedtls.a" "$out/mbedtls/library/libmbedx509.a" "$out/mbedtls/library/libmbedcrypto.a" -o "$out/mbedtls-probe"
c++ -std=c++17 -O2 -Wall -Wextra -Werror -I"$out/bssl-source/include" "$here/bssl_probe.cc" "$here/heap_hooks.cc" "$out/bssl/libssl.a" "$out/bssl/libcrypto.a" -o "$out/bssl-probe"
node "$here/run-host.mjs" "$out/run" "$out/mbedtls-probe" "$out/bssl-probe" "${BSSL_HELPER:-$here/../../../native/boring_tls/build/boring-tls-helper}"
