#!/usr/bin/env bash
# Build current native engine source against the existing isolated Linux lab's
# pinned libraries. Read-only cache/source; no TUN, network or host settings.
set -euo pipefail
[[ $# == 1 && ! -e "$1" ]] || { echo 'Usage: build-native-exit-lab.sh NEW_DIRECTORY' >&2; exit 2; }
root="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -m 700 -p "$1"
out="$(cd "$1" && pwd)"
connection="${MESHPN_PODMAN_CONNECTION:-meshpn-clean-vpn-lab-root}"
image="${MESHPN_NATIVE_LAB_IMAGE:-localhost/meshpn-clean-vpn-lab:1f35b200e5e912e7}"
cache="${MESHPN_NATIVE_LAB_CACHE:-meshpn-clean-vpn-lab-cache}"
podman --connection "$connection" run --rm --network=none --cap-drop=all --platform=linux/amd64 \
  -v "$root:/source:ro" -v "$cache:/lab:ro" -v "$out:/artifacts" "$image" \
  bash /source/device/tests/helpers/build-native-exit.sh
printf '%s\n' "$out"
