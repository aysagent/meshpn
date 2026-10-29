#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
[[ $# == 2 && ( "$1" == esp32s3 || "$1" == esp32p4 ) && ! -e "$2" ]] || {
 echo 'Usage: build-idf.sh esp32s3|esp32p4 NEW_ARTIFACT_DIRECTORY (compile only)' >&2; exit 2;
}
export IDF_PATH="${IDF_PATH:-$HOME/esp/esp-idf-meshpn-v5.5.5}"
[[ "$(git -C "$IDF_PATH" describe --tags --exact-match)" == v5.5.5 ]] || { echo 'Requires IDF v5.5.5' >&2; exit 2; }
mkdir -m 700 -p "$2"
out="$(cd "$2" && pwd)"
python3 "$here/prepare-bssl.py" "${BSSL_SOURCE:-$here/../../../native/boring_tls/build/_deps/boringssl-src}" "$out/bssl-source" >"$out/prepare.log"
export MESHPN_PROBE_BSSL_SOURCE="$out/bssl-source" IDF_TARGET="$1"
# All dependencies are local SDK components; no registry resolution is needed.
export IDF_COMPONENT_MANAGER=0
unset IDF_PYTHON_ENV_PATH
source "$IDF_PATH/export.sh" >"$out/idf-environment.log" 2>&1
idf.py -C "$here/idf" -B "$out/build" -D SDKCONFIG="$out/sdkconfig" build size >"$out/build.log" 2>&1
python3 "$here/summarize-build.py" "$out/build" "$out/size-stack.json"
echo "Compile-only probe: $out (not flashed)"
