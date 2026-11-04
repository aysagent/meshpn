#!/usr/bin/env bash
# Stage a persistent name for one ipheth device. Never rename a live interface.
set -euo pipefail
action=${1:-plan}
case "$action" in plan|install|uninstall) ;; *) echo 'Usage: bash scripts/clean-vpn-iphone-uplink.sh plan|install|uninstall' >&2; exit 2;; esac
[[ $# -le 1 ]] || exit 2
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
rule="$source_dir/usb/10-clean-vpn-iphone.link"
target=/etc/systemd/network/10-clean-vpn-iphone.link
if [[ "$action" == plan ]]; then
  printf 'Target: %s\nActivation: next device connection or boot; live links unchanged.\n' "$target"
  cat "$rule"
  exit 0
fi
[[ $(uname -s) == Linux && $EUID == 0 ]] || { echo 'Linux root required' >&2; exit 1; }
[[ ! -L "$target" ]] || { echo 'Refusing symlink destination' >&2; exit 1; }
if [[ -e "$target" ]]; then
  [[ -f "$target" ]] && cmp -s "$rule" "$target" || { echo 'Existing rule differs; refusing to overwrite/remove it' >&2; exit 1; }
fi
if [[ "$action" == install ]]; then
  count=0
  for device in /sys/class/net/*; do
    driver=$(readlink -f "$device/device/driver" 2>/dev/null || true)
    if [[ ${driver##*/} == ipheth ]]; then count=$((count+1)); fi
    if [[ ${device##*/} == iphone0 && ${driver##*/} != ipheth ]]; then
      echo 'iphone0 belongs to another device' >&2; exit 1
    fi
  done
  [[ $count -le 1 ]] || { echo 'Only one connected ipheth device is supported' >&2; exit 1; }
  if [[ ! -e "$target" ]]; then
    install -d -m 0755 /etc/systemd/network
    temporary=$(mktemp /etc/systemd/network/.clean-vpn-iphone.XXXXXX)
    trap 'rm -f -- "$temporary"' EXIT
    install -m 0644 "$rule" "$temporary"
    mv -T --no-clobber "$temporary" "$target"
    cmp -s "$rule" "$target" || { echo 'Rule publication collision' >&2; exit 1; }
  fi
else
  if [[ -e "$target" ]]; then rm -- "$target"; fi
fi
udevadm control --reload
printf 'IPHONE_UPLINK=%s; takes effect on next connection/boot; live links unchanged\n' "$action"
