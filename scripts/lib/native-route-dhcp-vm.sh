#!/bin/sh
# Disposable guest DHCP hook, not a production network configuration script.
set -eu
test "$(cat /sys/class/dmi/id/sys_vendor)" = QEMU
grep -qw meshpn.native-routes=1 /proc/cmdline
test "$interface" = wlan0
case "$1" in
deconfig)
  /usr/bin/ip -4 route del default dev wlan0 2>/dev/null || true
  /usr/bin/ip -4 addr flush dev wlan0 scope global
  ;;
bound|renew)
  case "$ip:$router:$subnet" in
    192.0.2.2:192.0.2.1:255.255.255.0|192.0.2.99:192.0.2.1:255.255.255.0|192.0.2.100:192.0.2.254:255.255.255.0) ;;
    *) exit 1 ;;
  esac
  /usr/bin/ip -4 addr replace "$ip/24" dev wlan0
  /usr/bin/ip -4 route replace default via "$router" dev wlan0 proto dhcp
  echo "NATIVE_DHCP_LEASE $ip $router"
  ;;
esac
