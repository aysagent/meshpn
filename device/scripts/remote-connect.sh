#!/usr/bin/env bash
# Run on the Linux server after remote-tunnel.sh is connected from the Mac.
set -euo pipefail

remote_port="${MESHPN_REMOTE_PORT:-22022}"
if [[ ! "$remote_port" =~ ^[1-9][0-9]{3,4}$ ]] || (( remote_port < 1024 || remote_port > 65535 )); then
  echo "MESHPN_REMOTE_PORT must be an unprivileged TCP port (1024..65535)" >&2
  exit 2
fi

remote_tty="${MESHPN_REMOTE_TTY:-0}"
case "$remote_tty" in
  0) tty_args=() ;;
  1) tty_args=(-t) ;;
  *) echo "MESHPN_REMOTE_TTY must be 0 or 1" >&2; exit 2 ;;
esac

mac_user="${MESHPN_MAC_SSH_USER:-$(id -un)}"
if [[ $# -gt 0 ]]; then
  mac_user="$1"
  shift
fi
if [[ ! "$mac_user" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ ]]; then
  echo "Usage: npm run device:remote:connect [mac-user] [remote-command]" >&2
  exit 2
fi

if ! command -v ssh >/dev/null 2>&1; then
  echo "OpenSSH client not found" >&2
  exit 1
fi

exec ssh -p "$remote_port" \
  -o ConnectTimeout=5 \
  -o HostKeyAlias=meshpn-mac-via-tunnel \
  "${tty_args[@]}" \
  -- "$mac_user@127.0.0.1" "$@"
