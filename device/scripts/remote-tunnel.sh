#!/usr/bin/env bash
# Run on the Mac: expose its local SSH service only on the Linux server's loopback.
set -euo pipefail

target="${1:-}"
if [[ $# -ne 1 || ! "$target" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*@[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]]; then
  echo "Usage: npm run device:remote tunneluser@SERVER" >&2
  exit 2
fi

remote_port="${MESHPN_REMOTE_PORT:-22022}"
if [[ ! "$remote_port" =~ ^[1-9][0-9]{3,4}$ ]] || (( remote_port < 1024 || remote_port > 65535 )); then
  echo "MESHPN_REMOTE_PORT must be an unprivileged TCP port (1024..65535)" >&2
  exit 2
fi

if ! command -v ssh >/dev/null 2>&1; then
  echo "OpenSSH client not found" >&2
  exit 1
fi

echo "Opening reverse SSH tunnel to $target (server 127.0.0.1:$remote_port -> Mac 127.0.0.1:22)."
echo "Keep this command running while the board is connected; Ctrl-C closes the tunnel."
echo "macOS Remote Login must be enabled for the Mac user."
exec ssh -N -T \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -R "127.0.0.1:$remote_port:127.0.0.1:22" \
  -- "$target"
