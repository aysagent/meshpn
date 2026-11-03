#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
exec "${NODE_BIN:-node}" scripts/clean-vpn-setup.mjs install "$@"
