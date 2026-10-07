#!/bin/sh
set -eu
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
test "$(cat /sys/class/dmi/id/sys_vendor)" = QEMU
grep -qw meshpn.native-routes=1 /proc/cmdline
test "$(cat /proc/1/comm)" = systemd
ip() { /usr/bin/ip "$@"; }
ctl() { /usr/bin/systemctl "$@"; }
property() { ctl show "native-$1.service" -p "$2" --value; }
probe() { ip netns exec "nc$1" /native/socket-test probe; }
check() { echo "NATIVE_ROUTES_$1_PASS"; }
wait_active() {
  for attempt in $(seq 1 60); do
    if [ "$(property c2 ActiveState)" = active ] && [ "$(property c2 MainPID)" != "${1:-0}" ]; then return; fi
    sleep 1
  done
  return 1
}
wait_stopped() {
  for attempt in $(seq 1 30); do
    if [ "$(property c2 MainPID)" = 0 ]; then return; fi
    sleep 1
  done
  return 1
}
lease() {
  for attempt in $(seq 1 45); do
    if ip -n nc2 -4 addr show wlan0 | grep -q "$1/24"; then return; fi
    sleep 1
  done
  return 1
}
change_lease() {
  kill -USR2 "$dhcp_client"
  wait_stopped
  kill "$dhcp_server"; wait "$dhcp_server" || true
  /usr/bin/ip netns exec nexit /bin/busybox udhcpd -f -a 0 "/native/dhcp$1.conf" >>/run/dhcp-server.log 2>&1 &
  dhcp_server=$!
  sleep 1
  kill -USR1 "$dhcp_client"
  lease "$2"
}
passed=0
finish() {
  cat /run/native-route-control.log /run/dhcp-client.log 2>/dev/null || true
  if [ "$passed" != 1 ]; then
    ctl --no-pager status native-c2 native-routes-c2 native-exit || true
    /usr/bin/journalctl --no-pager -u native-routes-c2 -u native-c2 -n 60 || true
    cat /run/dhcp-client.log /run/dhcp-server.log 2>/dev/null || true
    ip -n nc2 -4 route show || true
    echo NATIVE_ROUTES_LAB_FAILED
  fi
  sync
  /bin/busybox poweroff -f
}
trap finish EXIT
ctl start native-lab-network.service native-lab-guard.service
# Only this fixture DHCP client owns these addresses/default; native owns neither.
ip -n nc2 route del default
ip -n nc2 addr del 192.0.2.2/30 dev wlan0
ip -n nexit addr replace 192.0.2.1/24 dev from2
ip -n nexit addr add 192.0.2.254/24 dev from2
ip netns exec nc2 iptables -A OUTPUT -o wlan0 -p udp --sport 68 --dport 67 -j ACCEPT
ip -n nc3 route add 1.1.1.1/32 dev tun0
ip -n nc3 route add 8.8.8.8/32 dev tun0
/usr/bin/ip netns exec nexit /native/socket-test serve >/run/native-origin.log 2>&1 &
origin=$!
/usr/bin/ip netns exec nexit /bin/busybox udhcpd -f -a 0 /native/dhcp1.conf >/run/dhcp-server.log 2>&1 &
dhcp_server=$!
/usr/bin/ip netns exec nc2 /bin/busybox udhcpc -f -i wlan0 -s /native/dhcp-hook.sh -t 3 -T 1 -A 1 >/run/dhcp-client.log 2>&1 &
dhcp_client=$!
ctl start native-exit.service native-c3.service native-routes-c2.service
lease 192.0.2.2
wait_active
check INITIAL_DHCP
probe 2; probe 3
ip netns exec nc2 /native/socket-test dns 10.99.0.2 1053
test "$(readlink /proc/$(property c2 MainPID)/exe)" = /native/clean-vpn-engine
check TWO_NATIVE_PEERS
old_pid=$(property c2 MainPID)
change_lease 2 192.0.2.99
wait_active "$old_pid"
probe 2; probe 3
check DHCP_ADDRESS_CHANGE
old_pid=$(property c2 MainPID)
change_lease 3 192.0.2.100
wait_active "$old_pid"
ip -n nc2 -4 route show 154.62.226.216/32 | grep -q 'via 192.0.2.254'
probe 2; probe 3
check DHCP_GATEWAY_CHANGE
ip -n nc2 route del default
wait_stopped
if probe 2; then exit 1; fi
probe 3
check DEFAULT_LOSS_BLOCKED
ip -n nc2 route add default via 192.0.2.254 dev wlan0 proto dhcp
wait_active
probe 2
check DEFAULT_RECOVERY
old_pid=$(property c2 MainPID)
ip -n nc2 route del 154.62.226.216/32 via 192.0.2.254 dev wlan0 proto 186 metric 42760
wait_active "$old_pid"
probe 2
check OWNED_ROUTE_REPAIR
ctl stop native-routes-c2.service
wait_stopped
ip -n nc2 route del 154.62.226.216/32 via 192.0.2.254 dev wlan0 proto 186 metric 42760
ip -n nc2 route add 154.62.226.216/32 via 192.0.2.254 dev wlan0 proto static metric 123
next_line=$(( $(wc -l </run/native-route-control.log) + 1 ))
ctl start native-routes-c2.service
refused=0
for attempt in $(seq 1 30); do
  if tail -n +"$next_line" /run/native-route-control.log | grep -q '"stage":"ownership"'; then refused=1; break; fi
  sleep 1
done
test "$refused" = 1
ctl is-active --quiet native-routes-c2.service
test "$(property c2 MainPID)" = 0
ip -n nc2 -4 route show 154.62.226.216/32 | grep -q 'metric 123'
check FOREIGN_ROUTE_REFUSED
ip -n nc2 route del 154.62.226.216/32 via 192.0.2.254 dev wlan0 proto static metric 123
wait_active
probe 2
check FOREIGN_REMOVED_RECOVERY
ctl kill --kill-whom=main --signal=SIGKILL native-routes-c2.service
wait_stopped
ctl is-active --quiet native-lab-guard.service
# Force direct default selection while manager is dead; independent guard persists.
ip -n nc2 route del 0.0.0.0/1 dev tun0 proto 186 metric 42760
ip -n nc2 route del 128.0.0.0/1 dev tun0 proto 186 metric 42760
if probe 2; then exit 1; fi
probe 3
check COORDINATOR_CRASH_BLOCKED
ctl start native-routes-c2.service
wait_active
probe 2
check COORDINATOR_RESTART
ctl stop native-lab-guard.service
wait_stopped
test "$(property routes-c2 MainPID)" = 0
if probe 2; then exit 1; fi
check GUARD_STOP_BLOCKED
kill "$dhcp_client" "$dhcp_server" "$origin"
wait "$dhcp_client" "$dhcp_server" "$origin" || true
test "$(property c3 MainPID)" = 0
test "$(property exit MainPID)" = 0
check CLEANUP
passed=1
echo NATIVE_ROUTES_LAB_OK
