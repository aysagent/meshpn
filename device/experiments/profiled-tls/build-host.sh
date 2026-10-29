#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
[[ $# == 1 && ! -e "$1" ]] || { echo 'Usage: build-host.sh NEW_ARTIFACT_DIRECTORY' >&2; exit 2; }
mkdir -m 700 -p "$1"
out="$(cd "$1" && pwd)"
idf="${IDF_PATH:-$HOME/esp/esp-idf-meshpn-v5.5.5}"
[[ "$(git -C "$idf" describe --tags --exact-match)" == v5.5.5 ]] || { echo 'Requires ESP-IDF v5.5.5' >&2; exit 2; }
bash "$here/prepare-brotli.sh" "$out/brotli-source"
cmake -S "$out/brotli-source" -B "$out/brotli" -DBUILD_SHARED_LIBS=OFF -DBROTLI_DISABLE_TESTS=ON -DCMAKE_BUILD_TYPE=Release >"$out/brotli-build.log" 2>&1
cmake --build "$out/brotli" --target brotlidec brotlicommon brotlienc -j 4 >>"$out/brotli-build.log" 2>&1
bssl="${BSSL_SOURCE:-$here/../../../native/boring_tls/build/_deps/boringssl-src}"
python3 "$here/prepare-bssl.py" "$bssl" "$out/bssl-source" >"$out/prepare.log"
cmake -S "$idf/components/mbedtls/mbedtls" -B "$out/mbedtls" -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF >"$out/mbedtls-build.log" 2>&1
cmake --build "$out/mbedtls" -j 4 >>"$out/mbedtls-build.log" 2>&1
cmake -S "$out/bssl-source" -B "$out/bssl" -DBUILD_TESTING=OFF -DOPENSSL_SMALL=ON -DOPENSSL_NO_ASM=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS=-DMESHPN_PROBE_ALLOCATOR >"$out/bssl-build.log" 2>&1
cmake --build "$out/bssl" --target ssl crypto -j 4 >>"$out/bssl-build.log" 2>&1
cc -O2 -Wall -Wextra -Werror -I"$idf/components/mbedtls/mbedtls/include" "$here/mbedtls_probe.c" "$out/mbedtls/library/libmbedtls.a" "$out/mbedtls/library/libmbedx509.a" "$out/mbedtls/library/libmbedcrypto.a" -o "$out/mbedtls-probe"
c++ -std=c++17 -O2 -Wall -Wextra -Werror -I"$out/bssl-source/include" -I"$out/brotli-source/c/include" -I"$here/../../components/meshvpn_profiled_tls/include" -I"$here/../../components/meshvpn_profiled_tls" "$here/bssl_probe.cc" "$here/../../components/meshvpn_profiled_tls/profile_client.cc" "$here/../../components/meshvpn_profiled_tls/profile_gate.cc" "$here/heap_hooks.cc" "$out/bssl/libssl.a" "$out/bssl/libcrypto.a" "$out/brotli/libbrotlidec.a" "$out/brotli/libbrotlicommon.a" -o "$out/bssl-probe"
node "$here/run-host.mjs" "$out/run" "$out/mbedtls-probe" "$out/bssl-probe" "${BSSL_HELPER:-$here/../../../native/boring_tls/build/boring-tls-helper}"

c++ -std=c++17 -O2 -Wall -Wextra -Werror -I"$out/bssl-source/include" -I"$out/brotli-source/c/include" "$here/compression_server.cc" "$here/heap_hooks.cc" "$out/bssl/libssl.a" "$out/bssl/libcrypto.a" "$out/brotli/libbrotlienc.a" "$out/brotli/libbrotlicommon.a" -o "$out/compression-server"
node "$here/test-compression.mjs" "$out/compression-server" "$out/bssl-probe" "$out/run"
c++ -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -I"$out/bssl-source/include" -I"$out/brotli-source/c/include" -I"$here/../../components/meshvpn_profiled_tls/include" -I"$here/../../components/meshvpn_profiled_tls" "$here/test_gate.cc" "$here/../../components/meshvpn_profiled_tls/profile_gate.cc" "$here/heap_hooks.cc" "$out/bssl/libssl.a" "$out/bssl/libcrypto.a" "$out/brotli/libbrotlidec.a" "$out/brotli/libbrotlienc.a" "$out/brotli/libbrotlicommon.a" -o "$out/test-gate"
"$out/test-gate" "$out/run/bssl-prefs-0.bin"
node "$here/test-worker.mjs"

node "$here/../../tests/test-profiled-tunnel.mjs" "$out"
