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
retry_seconds="${MESHPN_REMOTE_RETRY_SECONDS:-5}"
max_attempts="${MESHPN_REMOTE_MAX_ATTEMPTS:-0}"
if [[ ! "$retry_seconds" =~ ^[0-9]+$ || ! "$max_attempts" =~ ^[0-9]+$ ]]; then
  echo "MESHPN_REMOTE_RETRY_SECONDS and MESHPN_REMOTE_MAX_ATTEMPTS must be non-negative integers" >&2
  exit 2
fi

stopping=0
trap 'stopping=1' INT TERM
attempts=0
while (( ! stopping )); do
  attempts=$((attempts + 1))
  if ssh -N -T \
    -o ExitOnForwardFailure=yes \
    -o BatchMode=yes \
    -o ConnectTimeout=5 \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -R "127.0.0.1:$remote_port:127.0.0.1:22" \
    -- "$target"; then
    status=0
  else
    status=$?
  fi
  (( stopping )) && break
  if (( max_attempts > 0 && attempts >= max_attempts )); then
    exit "$status"
  fi
  echo "SSH tunnel ended (status $status); retrying in ${retry_seconds}s. Ctrl-C to stop." >&2
  sleep "$retry_seconds" || true
done
