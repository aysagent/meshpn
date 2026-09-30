#!/usr/bin/env bash
# Audited persist-mode removal; unfinished recovery never removes the guard.
# sudo env "PATH=$PATH" scripts/autostart/uninstall.sh
# SERVICE_NAME and NODE_BIN are optional. Tied-mode removal requires review.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="${NODE_BIN:-$(command -v node)}"
exec "$NODE_BIN" "$SCRIPT_DIR/../clean-vpn-uninstall.mjs" "$@"
