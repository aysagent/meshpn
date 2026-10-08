#!/usr/bin/env bash
# Temporary, explicitly owned swap for building clean-vpn-native on small hosts.
set -euo pipefail

cv_swap_dir=/var/lib/clean-vpn-native-build-swap
cv_swap_file=$cv_swap_dir/swapfile
cv_swap_marker=$cv_swap_dir/owner
cv_marker_value=clean-vpn-native-build-swap-v1

cv_usage() {
  echo 'Usage: sudo bash scripts/clean-vpn-native-swap.sh on|off'
  echo 'on creates and enables a private 2 GiB build swap; off disables and removes it.'
  echo 'The command never edits /etc/fstab.'
}

if [ "$#" -ne 1 ]; then
  cv_usage >&2
  exit 2
fi
case "$1" in
  --help|-h) cv_usage; exit 0 ;;
  on|off) cv_action=$1 ;;
  *) cv_usage >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root (for example with sudo); no changes made.' >&2
  exit 1
fi
for cv_tool in fallocate mkswap swapon swapoff stat; do
  if ! command -v "$cv_tool" >/dev/null; then
    echo "Missing required command: $cv_tool; no changes made." >&2
    exit 1
  fi
done

cv_active() {
  swapon --noheadings --show=NAME 2>/dev/null | grep -Fx -- "$cv_swap_file" >/dev/null
}

cv_owned() {
  [ -d "$cv_swap_dir" ] && [ ! -L "$cv_swap_dir" ] &&
    [ -f "$cv_swap_file" ] && [ ! -L "$cv_swap_file" ] &&
    [ -f "$cv_swap_marker" ] && [ ! -L "$cv_swap_marker" ] &&
    [ "$(stat -c '%u:%g:%a' "$cv_swap_dir")" = '0:0:700' ] &&
    [ "$(stat -c '%u:%g:%a' "$cv_swap_file")" = '0:0:600' ] &&
    [ "$(stat -c '%u:%g:%a' "$cv_swap_marker")" = '0:0:600' ] &&
    [ "$(cat "$cv_swap_marker")" = "$cv_marker_value" ]
}

if [ "$cv_action" = on ]; then
  if [ -e "$cv_swap_dir" ] || [ -L "$cv_swap_dir" ]; then
    if ! cv_owned; then
      echo "Refusing unowned or unexpected state at $cv_swap_dir; no changes made." >&2
      exit 1
    fi
    if cv_active; then
      echo "CLEAN_VPN_NATIVE_SWAP=on (already active; file=$cv_swap_file)"
      swapon --show
      exit 0
    fi
    swapon "$cv_swap_file"
    echo "CLEAN_VPN_NATIVE_SWAP=on (reactivated; file=$cv_swap_file)"
    swapon --show
    exit 0
  fi

  cv_created=0
  cv_cleanup_failed_on() {
    cv_status=$?
    if [ "$cv_status" -ne 0 ] && [ "$cv_created" -eq 1 ]; then
      if cv_active; then swapoff "$cv_swap_file" || true; fi
      rm -f -- "$cv_swap_marker" "$cv_swap_file"
      rmdir -- "$cv_swap_dir" 2>/dev/null || true
      echo 'Swap activation failed; files created by this attempt were removed.' >&2
    fi
    exit "$cv_status"
  }
  trap cv_cleanup_failed_on EXIT
  mkdir -m 0700 -- "$cv_swap_dir"
  cv_created=1
  fallocate -l 2G -- "$cv_swap_file"
  chmod 0600 -- "$cv_swap_file"
  mkswap --label clean-vpn-native-build -- "$cv_swap_file" >/dev/null
  printf '%s\n' "$cv_marker_value" >"$cv_swap_marker"
  chmod 0600 -- "$cv_swap_marker"
  swapon "$cv_swap_file"
  cv_created=0
  trap - EXIT
  echo "CLEAN_VPN_NATIVE_SWAP=on (created 2 GiB; file=$cv_swap_file)"
  swapon --show
  exit 0
fi

if [ ! -e "$cv_swap_dir" ] && [ ! -L "$cv_swap_dir" ]; then
  echo 'CLEAN_VPN_NATIVE_SWAP=off (already absent)'
  exit 0
fi
if ! cv_owned; then
  echo "Refusing to remove unowned or unexpected state at $cv_swap_dir; no changes made." >&2
  exit 1
fi
if cv_active; then swapoff "$cv_swap_file"; fi
rm -- "$cv_swap_marker" "$cv_swap_file"
rmdir -- "$cv_swap_dir"
echo 'CLEAN_VPN_NATIVE_SWAP=off (disabled and removed)'
