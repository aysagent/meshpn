#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p native/clean_vpn/build
c++ -std=c++17 -O2 -Wall -Wextra -Werror native/clean_vpn/owned_tun.cc -o native/clean_vpn/build/clean-vpn-tun-helper
if [[ "${1:-}" == --admin-ui ]]; then
  cc -O2 -Wall -Wextra -Werror admin/mdns.c -o native/clean_vpn/build/clean-vpn-mdns-helper $(pkg-config --cflags --libs avahi-client)
fi
