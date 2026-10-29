#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 && ! -e "$1" ]] || { echo 'Usage: prepare-nghttp2.sh NEW_DIRECTORY' >&2; exit 2; }
dest="$1"
pin=534b74b72524e962c18c7146470914632ca7eb2d
if [[ -n "${NGHTTP2_SOURCE:-}" ]]; then
  [[ "$(git -C "$NGHTTP2_SOURCE" rev-parse HEAD)" == "$pin" ]] || { echo 'Unexpected nghttp2 revision' >&2; exit 2; }
  mkdir -p "$dest"
  # Export committed sources, never copy unrelated changes/build outputs.
  git -C "$NGHTTP2_SOURCE" archive "$pin" | tar -x -C "$dest"
else
  git init -q "$dest"
  git -C "$dest" remote add origin https://github.com/nghttp2/nghttp2.git
  git -C "$dest" fetch -q --depth=1 origin "$pin"
  git -C "$dest" checkout -q --detach FETCH_HEAD
fi
python3 - "$dest" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1])/'lib/includes/nghttp2'
s=(p/'nghttp2ver.h.in').read_text()
(p/'nghttp2ver.h').write_text(s.replace('@PACKAGE_VERSION@','1.68.0').replace('@PACKAGE_VERSION_NUM@','0x014400'))
PY
printf '%s\n' "$pin" > "$dest/meshpn-source-revision"
