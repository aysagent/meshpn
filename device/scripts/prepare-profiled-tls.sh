#!/usr/bin/env bash
# Sourced by flash.sh. Isolated, pinned dependencies; never edits the desktop helper.
profile_lab="$DEVICE_DIR/experiments/profiled-tls"
profile_patch_dir="$DEVICE_DIR/../native/boring_tls/patches"
profile_deps_id="$(cksum "$profile_lab/prepare-bssl.py" "$profile_lab/patch-order.py" "$profile_lab/prepare-brotli.sh" "$profile_patch_dir"/*.patch | cksum | awk '{print $1}')"
profile_deps="$DEVICE_DIR/build-profiled-deps-$profile_deps_id"
if [[ ! -d "$profile_deps" ]]; then
  profile_tmp="$(mktemp -d "$DEVICE_DIR/build-profiled-deps-tmp.XXXXXX")"
  profile_src="${BSSL_SOURCE:-$DEVICE_DIR/../native/boring_tls/build/_deps/boringssl-src}"
  if [[ ! -d "$profile_src" ]]; then
    profile_src="$profile_tmp/upstream"
    git init -q "$profile_src"
    git -C "$profile_src" remote add origin https://github.com/google/boringssl.git
    git -C "$profile_src" fetch -q --depth=1 origin a7481f34712bc056a47ab91015536166b3a6cebb
    git -C "$profile_src" checkout -q --detach FETCH_HEAD
    for profile_patch in tls13-cipher-order client-signature-algorithms-cert client-hello-extra-extensions extra-extensions-emit-dedup tls12-cipher-wire-and-ems signature-algorithms-clienthello-wire; do
      (cd "$profile_src" && patch -p0 -i "$profile_patch_dir/boringssl-meshvpn-$profile_patch.patch")
    done
  fi
  python3 "$profile_lab/prepare-bssl.py" "$profile_src" "$profile_tmp/bssl"
  bash "$profile_lab/prepare-brotli.sh" "$profile_tmp/brotli"
  mv "$profile_tmp" "$profile_deps"
fi
export MESHPN_PROBE_BSSL_SOURCE="$profile_deps/bssl"
export MESHPN_PROBE_BROTLI_SOURCE="$profile_deps/brotli"
profile_h2_id="$(cksum "$profile_lab/prepare-nghttp2.sh" | awk '{print $1}')"
profile_h2_deps="$DEVICE_DIR/build-profiled-nghttp2-$profile_h2_id"
if [[ ! -d "$profile_h2_deps" ]]; then
  profile_h2_tmp="$(mktemp -d "$DEVICE_DIR/build-profiled-nghttp2-tmp.XXXXXX")"
  bash "$profile_lab/prepare-nghttp2.sh" "$profile_h2_tmp/source"
  mv "$profile_h2_tmp/source" "$profile_h2_deps"
  rmdir "$profile_h2_tmp"
fi
export MESHPN_PROBE_NGHTTP2_SOURCE="$profile_h2_deps"
