#!/usr/bin/env bash
set -euo pipefail
deps=/lab/worktree/native/clean_vpn/build
bssl=/lab/worktree/native/boring_tls/build/_deps/boringssl-src
json=/lab/worktree/native/boring_tls/build/_deps/json-src
[[ "$(git -C "$bssl" rev-parse HEAD)" == a7481f34712bc056a47ab91015536166b3a6cebb ]]
[[ "$(git -C "$deps/_deps/nghttp2-src" rev-parse HEAD)" == 534b74b72524e962c18c7146470914632ca7eb2d ]]
# The cached native libraries must correspond to these patch/adapter sources.
diff -qr /source/native/boring_tls/patches /lab/worktree/native/boring_tls/patches
cmp /source/native/clean_vpn/http2_alps_adapter.c /lab/worktree/native/clean_vpn/http2_alps_adapter.c
cmp /source/native/clean_vpn/http2_alps_adapter.h /lab/worktree/native/clean_vpn/http2_alps_adapter.h
c++ -std=c++17 -O1 -g0 -Wall -Wextra -Werror -DCVPN_TEST_PACKET_FD=1 \
  -I"$bssl/include" -I"$json/single_include" \
  -I"$deps/_deps/brotli-src/c/include" \
  -I"$deps/_deps/nghttp2-src/lib/includes" -I"$deps/_deps/nghttp2-build/lib/includes" \
  /source/native/clean_vpn/engine.cc -o /artifacts/clean-vpn-engine-fixture \
  "$deps/_deps/brotli-build/libbrotlienc.a" "$deps/bssl/libssl.a" "$deps/bssl/libcrypto.a" \
  "$deps/libcvpn_http2_alps.a" "$deps/_deps/brotli-build/libbrotlidec.a" \
  "$deps/_deps/nghttp2-build/lib/libnghttp2.a" "$deps/_deps/brotli-build/libbrotlicommon.a" -lm -pthread
sha256sum /source/native/clean_vpn/engine.cc /source/native/clean_vpn/*.hpp \
  /source/native/clean_vpn/http2_alps_adapter.c /artifacts/clean-vpn-engine-fixture > /artifacts/sources.sha256
/artifacts/clean-vpn-engine-fixture --capabilities > /artifacts/capabilities.json
