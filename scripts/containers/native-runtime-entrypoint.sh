#!/bin/sh
set -eu
umask 077
test "$#" = 1 || { echo 'Usage: native-runtime /config/engine.json' >&2; exit 2; }
node "${CVPN_CONTROL_DIRECTORY:-/opt/clean-vpn}/clean-vpn-native-runtime.mjs" "$1"
exec "${CVPN_ENGINE:-/usr/local/bin/clean-vpn-engine}" --config "${CVPN_STATE_DIRECTORY:-/run/clean-vpn}/engine.json" --service
