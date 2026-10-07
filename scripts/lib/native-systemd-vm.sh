#!/bin/sh
# Never run on a real machine: both independent VM identity checks are required.
set -eu
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
test "$(cat /sys/class/dmi/id/sys_vendor)" = QEMU
grep -qw meshpn.native-systemd=1 /proc/cmdline
test "$(cat /proc/1/comm)" = systemd
ip() { /usr/bin/ip "$@"; }
ctl() { /usr/bin/systemctl "$@"; }
property() { ctl show "native-$1.service" -p "$2" --value; }
probe() { ip netns exec "nc$1" /native/socket-test probe; }
check() { echo "NATIVE_SYSTEMD_$1_PASS"; }
wait_active() {
  for attempt in $(seq 1 45); do
    if [ "$(property "$1" ActiveState)" = active ]; then return; fi
    sleep 1
  done
  return 1
}
changed_pid() {
  for attempt in $(seq 1 30); do
    current=$(property "$1" MainPID)
    if [ "$current" != 0 ] && [ "$current" != "$2" ] && [ "$(property "$1" ActiveState)" = active ]; then return; fi
    sleep 1
  done
  return 1
}
case "$1" in
network)
  for ns in nc2 nc3 nexit; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
  ip -n nexit addr add 154.62.226.216/32 dev lo
  ip -n nexit addr add 1.1.1.1/32 dev lo
  ip -n nexit addr add 8.8.8.8/32 dev lo
  for last in 2 3; do
    ip link add "to$last" type veth peer name "from$last"
    ip link set "to$last" netns "nc$last"
    ip -n "nc$last" link set "to$last" name wlan0
    ip link set "from$last" netns nexit
    ip -n "nc$last" addr add "192.0.$last.2/30" dev wlan0
    ip -n nexit addr add "192.0.$last.1/30" dev "from$last"
    ip -n "nc$last" link set wlan0 up
    ip -n nexit link set "from$last" up
    ip -n "nc$last" route add default via "192.0.$last.1"
    ip netns exec "nc$last" ip tuntap add dev tun0 mode tun
    ip -n "nc$last" addr add "10.99.0.$last/32" dev tun0
    ip -n "nc$last" link set tun0 mtu 1400 up
  done
  ip netns exec nexit ip tuntap add dev tun0 mode tun
  ip -n nexit addr add 10.99.0.1/24 dev tun0
  ip -n nexit link set tun0 mtu 1400 up
  ;;
guard)
  test ! -e /run/native-fail-guard
  for last in 2 3; do
    # Remain installed through engine/guard unit stop. Never flush on stop.
    ip netns exec "nc$last" iptables -P OUTPUT DROP
    ip netns exec "nc$last" iptables -P FORWARD DROP
    ip netns exec "nc$last" iptables -A OUTPUT -o lo -j ACCEPT
    ip netns exec "nc$last" iptables -A OUTPUT -o tun0 -j ACCEPT
    ip netns exec "nc$last" iptables -A OUTPUT -o wlan0 -d 154.62.226.216 -p tcp --dport 443 -j ACCEPT
    ip netns exec "nc$last" ip6tables -P OUTPUT DROP
    ip netns exec "nc$last" ip6tables -P FORWARD DROP
    ip netns exec "nc$last" ip6tables -A OUTPUT -o lo -j ACCEPT
  done
  ip netns exec nexit iptables -P FORWARD DROP
  ;;
driver)
  passed=0
  finish() {
    if [ "$passed" != 1 ]; then
      ctl --no-pager status native-c2 native-c3 native-exit || true
      /usr/bin/journalctl --no-pager -u native-c2 -u native-c3 -u native-exit -n 70 || true
      echo NATIVE_SYSTEMD_LAB_FAILED
    fi
    sync
    /bin/busybox poweroff -f
  }
  trap finish EXIT
  ctl start native-lab-network.service
  ip netns exec nexit /native/socket-test serve >/run/native-origin.log 2>&1 &
  origin_pid=$!
  sleep 1
  probe 2
  probe 3
  check DIRECT_CONTROL
  touch /run/native-fail-guard
  if ctl start native-c2.service; then exit 1; fi
  test "$(property c2 MainPID)" = 0
  check GUARD_REFUSAL
  rm /run/native-fail-guard
  ctl reset-failed native-lab-guard.service
  ctl start native-lab-guard.service
  for last in 2 3; do
    ip -n "nc$last" route add 1.1.1.1/32 dev tun0
    ip -n "nc$last" route add 8.8.8.8/32 dev tun0
  done
  ctl start --no-block native-c2.service
  sleep 2
  test "$(property c2 ActiveState)" = activating
  check NOTIFY_WAIT
  ctl start native-exit.service native-c3.service
  wait_active c2
  probe 2
  probe 3
  for last in 2 3; do ip netns exec "nc$last" /native/socket-test dns "10.99.0.$last" 1053; done
  for name in c2 c3 exit; do
    test "$(readlink /proc/$(property "$name" MainPID)/exe)" = /native/clean-vpn-engine
    test "$(property "$name" Type)" = notify
  done
  check TWO_PEERS
  old_pid=$(property c2 MainPID)
  ctl stop native-c2.service
  probe 3
  if probe 2; then exit 1; fi
  check CLIENT_STOP_ISOLATED
  ctl start native-c2.service
  changed_pid c2 "$old_pid"
  probe 2
  check CLIENT_RESTART
  old_pid=$(property c2 MainPID)
  ctl kill --kill-whom=main --signal=SIGKILL native-c2.service
  changed_pid c2 "$old_pid"
  test "$(property c2 NRestarts)" -ge 1
  probe 2
  probe 3
  check CLIENT_CRASH_RESTART
  old_pid=$(property exit MainPID)
  ctl kill --kill-whom=main --signal=SIGKILL native-exit.service
  changed_pid exit "$old_pid"
  sleep 2
  probe 2
  probe 3
  check EXIT_CRASH_RESTART
  ip -n nc2 link set wlan0 down
  if probe 2; then exit 1; fi
  probe 3
  ip -n nc2 link set wlan0 up
  ip -n nc2 route replace default via 192.0.2.1
  sleep 8
  probe 2
  check UPLINK_RECOVERY
  ctl stop native-lab-guard.service
  for name in c2 c3 exit; do test "$(property "$name" ActiveState)" = inactive; done
  check GUARD_STOP_BINDS
  for last in 2 3; do
    ip -n "nc$last" route del 1.1.1.1/32 dev tun0
    ip -n "nc$last" route del 8.8.8.8/32 dev tun0
    ip -n "nc$last" route get 1.1.1.1 | grep -q wlan0
    if probe "$last"; then exit 1; fi
  done
  check STOP_FAIL_CLOSED
  for name in c2 c3 exit; do test "$(property "$name" MainPID)" = 0; done
  kill "$origin_pid"
  wait "$origin_pid" || true
  check CLEANUP
  passed=1
  echo NATIVE_SYSTEMD_LAB_OK
  ;;
*) exit 2;;
esac
