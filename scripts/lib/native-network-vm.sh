#!/bin/sh
set -eu
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
test "$(cat /sys/class/dmi/id/sys_vendor)" = QEMU
grep -qw meshpn.native-network=1 /proc/cmdline
test "$(cat /proc/1/comm)" = systemd
ip() { /usr/bin/ip "$@"; }
ctl() { /usr/bin/systemctl "$@"; }
prop() { ctl show "native-$1.service" -p "$2" --value; }
check() { echo "NATIVE_NETWORK_$1_PASS"; }
probe() { ip netns exec nlan /native/socket-test probe; }
wait_active() {
  for attempt in $(seq 1 60); do if [ "$(prop "$1" ActiveState)" = active ]; then return; fi; sleep 1; done
  return 1
}
case "$1" in
network)
  for ns in nc2 nexit nwan nlan; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
  for spec in 'nc2 nwan client 192.0.3.2/24 192.0.3.1/24' 'nexit nwan exit 192.0.2.1/24 192.0.2.254/24' 'nc2 nlan lan 192.168.7.1/24 192.168.7.19/24'; do
    set -- $spec
    ip link add "left$3" type veth peer name "right$3"
    ip link set "left$3" netns "$1"; ip link set "right$3" netns "$2"
    dev=wan0; if [ "$3" = lan ]; then dev=lan0; fi
    ip -n "$1" link set "left$3" name "$dev"
    ip -n "$1" addr add "$4" dev "$dev"
    ip -n "$2" addr add "$5" dev "right$3"
    ip -n "$2" link set "right$3" up
  done
  ip -n nexit addr add 154.62.226.216/32 dev lo
  ip -n nwan addr add 1.1.1.1/32 dev lo
  ip -n nwan addr add 8.8.8.8/32 dev lo
  ip -n nwan route add 154.62.226.216/32 via 192.0.2.1
  ip netns exec nwan sysctl -w net.ipv4.ip_forward=1
  ip -n nlan route add default via 192.168.7.1
  ;;
defaults)
  for spec in 'nc2 192.0.3.1' 'nexit 192.0.2.254'; do
    set -- $spec
    current=$(ip -n "$1" -4 route show default | sed 's/ *$//')
    if [ -z "$current" ]; then ip -n "$1" route add default via "$2";
    else test "$current" = "default via $2 dev wan0"; fi
  done
  ;;
driver)
  passed=0
  finish() {
    cat /run/native-c2-network.log /run/native-exit-network.log /run/native-route-control.log 2>/dev/null || true
    if [ "$passed" != 1 ]; then
      ctl --no-pager status native-c2-network native-exit-network native-c2 native-exit native-c2-routes || true
      /usr/bin/journalctl --no-pager -u native-c2-network -u native-exit-network -u native-c2 -u native-exit -n 80 || true
      for ns in nc2 nexit; do ip -n "$ns" route show || true; ip netns exec "$ns" iptables-save || true; done
      echo NATIVE_NETWORK_LAB_FAILED
    fi
    sync
    if [ "$passed" = 1 ] && grep -qw meshpn.native-site-boot=1 /proc/cmdline && [ ! -e /run/native-site-reboot ]; then
      /usr/bin/node /project/scripts/lib/native-site-boot-vm.mjs save
      /bin/busybox reboot -f
    else /bin/busybox poweroff -f; fi
  }
  trap finish EXIT
  if [ -e /run/native-site-reboot ]; then
    /usr/bin/ip netns exec nwan /native/socket-test serve >/run/native-origin.log 2>&1 &
    origin=$!
    wait_active c2; wait_active exit
    probe
    check REBOOT_AUTOSTART_DATA
    ip netns exec nlan /native/socket-test dns 203.0.113.53
    check REBOOT_NATIVE_DNS
    /usr/bin/node /project/scripts/lib/native-site-boot-vm.mjs verify
    ctl stop native-c2.target native-exit.target
    test "$(prop c2 MainPID)" = 0; test "$(prop exit MainPID)" = 0
    if probe; then exit 1; fi
    check REBOOT_TARGET_STOP_BLOCKED
    kill "$origin"; wait "$origin" || true
    passed=1
    echo NATIVE_NETWORK_REBOOT_OK
    exit 0
  fi
  ctl start native-lab-network.service
  /usr/bin/node /project/scripts/lib/native-site-vm-install.mjs
  ctl daemon-reload
  test "$(prop c2 MainPID)" = 0
  test "$(prop exit MainPID)" = 0
  ctl start native-c2-network.service native-exit-network.service
  ip -n nc2 link show wan0 | grep -q 'state DOWN'
  ip -n nexit link show wan0 | grep -q 'state DOWN'
  ip netns exec nc2 iptables -S OUTPUT | grep -q -- '-P OUTPUT DROP'
  ip netns exec nexit ip6tables -S FORWARD | grep -q -- '-P FORWARD DROP'
  check PROFILES_BEFORE_UPLINK
  ctl start native-c2-uplink.service native-exit-uplink.service
  ctl start native-lab-defaults.service
  /usr/bin/ip netns exec nwan /native/socket-test serve >/run/native-origin.log 2>&1 &
  origin=$!
  ctl start native-exit.target native-c2.target
  wait_active c2
  probe
  for name in c2 exit; do test "$(readlink /proc/$(prop "$name" MainPID)/exe)" = /opt/clean-vpn-native/$name/engine; done
  check NATIVE_LAN_DATA
  # Neither address hosts DNS. Passing proves interception, not direct origin DNS.
  ip netns exec nlan /native/socket-test dns 203.0.113.53
  ip netns exec nc2 /native/socket-test dns 203.0.113.53
  check NATIVE_DNS_INTERCEPTION
  ip netns exec nc2 iptables -t nat -L POSTROUTING -v -n -x | awk '$3=="SNAT" && $1>0 {ok=1} END {exit !ok}'
  ip netns exec nexit iptables -t nat -L POSTROUTING -v -n -x | awk '$3=="MASQUERADE" && $1>0 {ok=1} END {exit !ok}'
  check DOUBLE_NAT
  ctl restart native-c2-network.service
  ctl start native-c2-routes.service
  wait_active c2; probe
  check RESTART_AUDIT
  ctl kill --kill-whom=main --signal=SIGKILL native-c2.service
  sleep 1
  test "$(prop c2 MainPID)" = 0
  if probe; then exit 1; fi
  # Remove only fixture-owned split routes to exercise the direct fallback guard.
  ctl stop native-c2-routes.service
  ip -n nc2 route del 0.0.0.0/1 dev tun0 proto 186 metric 42760
  ip -n nc2 route del 128.0.0.0/1 dev tun0 proto 186 metric 42760
  if probe; then exit 1; fi
  check CLIENT_CRASH_BLOCKED
  ctl start native-c2-routes.service; wait_active c2; probe
  check CLIENT_RESTART
  ctl kill --kill-whom=main --signal=SIGKILL native-exit.service
  sleep 1
  test "$(prop exit MainPID)" = 0
  if probe; then exit 1; fi
  check EXIT_CRASH_BLOCKED
  ctl start native-exit.service
  sleep 2; probe
  check EXIT_RESTART
  # Foreign restrictive rule: restart refuses drift and leaves it in place.
  ip netns exec nc2 iptables -A OUTPUT -d 203.0.113.99 -j DROP
  if ctl restart native-c2-network.service; then exit 1; fi
  test "$(prop c2 MainPID)" = 0
  ip netns exec nc2 iptables -C OUTPUT -d 203.0.113.99 -j DROP
  check FOREIGN_GUARD_REFUSED
  ip netns exec nc2 iptables -D OUTPUT -d 203.0.113.99 -j DROP
  ctl start native-c2-network.service native-c2-routes.service
  wait_active c2; probe
  ctl stop native-c2-network.service
  test "$(prop c2 MainPID)" = 0
  if probe; then exit 1; fi
  check GUARD_STOP_BLOCKED
  ctl stop native-c2.target native-exit.target
  kill "$origin"; wait "$origin" || true
  test "$(prop exit MainPID)" = 0
  check CLEANUP
  passed=1
  echo NATIVE_NETWORK_LAB_OK
  ;;
*) exit 2;;
esac
