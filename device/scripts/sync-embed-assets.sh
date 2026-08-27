#!/usr/bin/env bash
# Copy lab assets into meshvpn_storage before build (optional).
# Usage:
#   MESHVPN_BROWSER_PROFILE_SRC=/path/to/browser-profile.json ./device/scripts/sync-embed-assets.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST_DIR="$ROOT/device/components/meshvpn_storage/profiles"
DEST="$DEST_DIR/browser.json"

mkdir -p "$DEST_DIR"

SRC="${MESHVPN_BROWSER_PROFILE_SRC:-${CLEAN_VPN_BORING_TLS_CLIENTHELLO_PROFILE:-}}"
for cand in "$SRC" "$ROOT/browser-profile.json" "$ROOT/../meshpn/browser-profile.json"; do
  [[ -n "$cand" && -f "$cand" ]] || continue
  cp "$cand" "$DEST"
  echo "==> browser profile: $cand -> $DEST"
  exit 0
done

echo "browser-profile.json not found (embed uses existing $DEST if present)" >&2
exit 0
