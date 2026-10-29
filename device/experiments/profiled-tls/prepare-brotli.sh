#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 && ! -e "$1" ]] || { echo 'Expected new Brotli source directory' >&2; exit 2; }
pin=028fb5a23661f123017c060daa546b55cf4bde29
if [[ -n "${BROTLI_SOURCE:-}" ]]; then
  [[ "$(git -C "$BROTLI_SOURCE" rev-parse HEAD)" == "$pin" ]] || { echo 'Wrong Brotli revision' >&2; exit 2; }
  [[ -z "$(git -C "$BROTLI_SOURCE" status --porcelain --untracked-files=no)" ]] || { echo 'Brotli source is modified' >&2; exit 2; }
  python3 - "$BROTLI_SOURCE" "$1" <<'PY'
import shutil,sys
shutil.copytree(sys.argv[1],sys.argv[2],ignore=shutil.ignore_patterns('.git'))
PY
else
  git init -q "$1"
  git -C "$1" remote add origin https://github.com/google/brotli.git
  git -C "$1" fetch -q --depth=1 origin "$pin"
  git -C "$1" checkout -q --detach FETCH_HEAD
fi
printf '%s\n' "$pin" > "$1/meshpn-source-revision"
