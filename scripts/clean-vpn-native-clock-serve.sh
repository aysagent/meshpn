#!/bin/sh
# Restricted SSH time provider, including older systemd/glibc hosts.
# authorized_keys must force: /usr/bin/timeout 5s /absolute/this-script
# The caller's command and nonce are data, never executed.
set -eu
export LC_ALL=C
[ "$#" = 0 ] && [ "${SSH_ORIGINAL_COMMAND:-}" = clean-vpn-clock-v1 ] || exit 1
IFS= read -r nonce || exit 1
[ "${#nonce}" = 64 ] || exit 1
case "$nonce" in *[!0-9a-f]*) exit 1;; esac
synchronized=$(/usr/bin/busctl get-property org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 NTPSynchronized)
[ "$synchronized" = 'b true' ] || exit 1
now=$(/bin/date +%s)
case "$now" in ''|*[!0-9]*) exit 1;; esac
[ "$now" -ge 1767225600 ] && [ "$now" -lt 4102444800 ] || exit 1
printf '{"version":1,"nonce":"%s","unix_seconds":%s,"synchronized":true}\n' "$nonce" "$now"
