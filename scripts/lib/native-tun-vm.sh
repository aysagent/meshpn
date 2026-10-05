#!/bin/sh
# Disposable NIC-less VM only. Existing guard/DNS plan/SNAT rules, not mocks.
set -eu
ip() { /usr/bin/ip "$@"; }
test "$(cat /proc/cmdline | tr ' ' '\n' | sed -n '/^meshpn.native-lab=1$/p')" = meshpn.native-lab=1
for ns in cvclient cvexit peer; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add wlan0 type veth peer name eth0
ip link set wlan0 netns cvclient
ip link set eth0 netns cvexit
ip -n cvclient addr add 154.62.226.2/24 dev wlan0
ip -n cvexit addr add 154.62.226.216/24 dev eth0
ip -n cvclient link set wlan0 up
ip -n cvexit link set eth0 up
ip -n cvclient route add default via 154.62.226.216
ip link add usb0 address 02:00:00:00:00:02 type veth peer name usbpeer
ip link set usb0 netns cvclient
ip link set usbpeer netns peer
ip -n cvclient addr add 192.168.7.1/24 dev usb0
ip -n peer addr add 192.168.7.19/24 dev usbpeer
ip -n cvclient link set usb0 up
ip -n peer link set usbpeer up
ip -n peer route add default via 192.168.7.1
ip -n cvclient -6 addr add 2001:db8:1::2/64 dev wlan0 nodad
ip -n cvexit -6 addr add 2001:db8:1::216/64 dev eth0 nodad
ip -n cvclient -6 addr add 2001:db8:7::1/64 dev usb0 nodad
ip -n peer -6 addr add 2001:db8:7::19/64 dev usbpeer nodad
ip -n peer -6 route add default via 2001:db8:7::1
ip -n cvexit -6 route add 2001:db8:7::/64 via 2001:db8:1::2
ip netns exec cvclient sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec cvclient sysctl -w net.ipv4.ip_forward=1
ip -n cvexit addr add 1.1.1.1/32 dev lo
ip -n cvexit addr add 8.8.8.8/32 dev lo
ip -n cvexit addr add 192.168.1.1/32 dev lo
ip netns exec cvclient iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
/usr/bin/ip netns exec cvexit /native/socket-test serve >/run/origin.log 2>&1 &
origin_pid=$!
/usr/bin/ip netns exec cvexit /native/socket-test serve 8.8.8.8 >/run/backup-origin.log 2>&1 &
backup_pid=$!
/usr/bin/ip netns exec cvexit /native/socket-test serve 192.168.1.1 >/run/private-origin.log 2>&1 &
private_pid=$!
/usr/bin/ip netns exec cvexit /native/socket-test ipv6-serve >/run/ipv6-origin.log 2>&1 &
ipv6_pid=$!
sleep 1
# Positive direct-path control before protection: a broken guard could leak.
ip netns exec peer /native/socket-test probe
ip netns exec peer /native/socket-test data 192.168.1.1
ip netns exec peer /native/socket-test ipv6-probe
echo NATIVE_DIRECT_POSITIVE_CONTROL_PASS
ip netns exec cvclient /bin/bash /project/scripts/autostart/killswitch.sh up --server=154.62.226.216 --usb-dns=1 --usb-strict=1
for ns in cvclient cvexit; do
  ip netns exec "$ns" /usr/bin/ip tuntap add dev tun0 mode tun
  ip -n "$ns" link set tun0 mtu 1400 up
done
ip -n cvclient addr add 10.99.0.2/30 dev tun0
ip -n cvexit addr add 10.99.0.1/30 dev tun0
ip netns exec cvclient /bin/sh /native/snat.sh
mkdir -p /run/sshd
/usr/bin/ip netns exec cvclient /usr/sbin/sshd -D -e -f /native/sshd_config >/run/ssh.log 2>&1 &
ssh_pid=$!
admin() { ip netns exec peer /usr/bin/ssh -F /dev/null -i /native/admin -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/native/known_hosts -o ConnectTimeout=3 -p 2222 root@192.168.7.1 'printf USB_ADMIN_OK' || { cat /run/ssh.log; return 1; }; }
sleep 1
admin
mkfifo /run/native-client-control /run/native-exit-control
exec 3<>/run/native-client-control
exec 4<>/run/native-exit-control
/usr/bin/ip netns exec cvexit /native/clean-vpn-engine --config /native/exit.json <&4 >/run/exit.log 2>&1 &
exit_pid=$!
/usr/bin/ip netns exec cvclient /usr/bin/node /project/scripts/clean-vpn-native.mjs --config /native/client.json --usb-profile <&3 >/run/client.log 2>&1 &
client_pid=$!
wait_client() {
  for attempt in $(seq 1 180); do
    if grep -q '"state":"ready"' /run/client.log; then sleep 1; return 0; fi
    kill -0 "$client_pid" || { cat /run/client.log; return 1; }
    if [ "$((attempt % 20))" = 0 ]; then tail -5 /run/client.log; fi
    sleep 1
  done
  cat /run/client.log /run/exit.log; ps; return 1
}
wait_old_client() {
  for attempt in $(seq 1 180); do
    if grep -q 'рукопожатие OK' /run/old-client.log; then sleep 1; return 0; fi
    kill -0 "$old_client_pid" || { cat /run/old-client.log; return 1; }
    sleep 1
  done
  cat /run/old-client.log /run/old-exit.log /run/exit.log; return 1
}
wait_client
/usr/bin/ip netns exec cvclient tcpdump -Z root -l -ni any -nn -v -c 60 'host 1.1.1.1 or host 10.99.0.2' >/run/packets.log 2>&1 &
capture_pid=$!
sleep 1
if ! ip netns exec peer /native/socket-test probe; then
  printf '{"op":"status"}\n' >&3
  printf '{"op":"status"}\n' >&4
  sleep 1
  cat /run/client.log /run/exit.log /run/origin.log /run/packets.log
  ip netns exec cvclient iptables -nvL
  ip netns exec cvclient iptables -t nat -nvL
  ip -n cvclient route get 1.1.1.1 from 192.168.7.19 iif usb0
  ip -n cvclient -s link show tun0
  ip netns exec cvclient cat /proc/net/snmp /proc/net/netstat
  exit 1
fi
kill "$capture_pid" 2>/dev/null || true
/usr/bin/ip netns exec cvclient tcpdump -Z root -q -n -i wlan0 -Q out -s 64 '(udp or tcp) and port 53' >/run/dns-uplink.log 2>&1 &
dns_capture_pid=$!
sleep 1
grep -q 'listening on wlan0' /run/dns-uplink.log
ip netns exec cvclient /native/socket-test dns 192.168.1.1
ip netns exec peer /native/socket-test dns 192.168.1.1
ip netns exec peer /native/socket-test dns 154.62.226.216
if ip netns exec peer /native/socket-test dns 10.99.0.2 1053; then echo UNEXPECTED_DIRECT_STUB_ACCESS; exit 1; fi
admin
echo NATIVE_USB_DNS_ADMIN_PASS
ip netns exec cvexit iptables -I INPUT -d 1.1.1.1 -p udp --dport 53 -j DROP
ip netns exec cvexit iptables -I INPUT -d 1.1.1.1 -p tcp --dport 53 -j DROP
ip netns exec peer /native/socket-test dns 192.168.1.1
ip netns exec cvexit iptables -D INPUT -d 1.1.1.1 -p udp --dport 53 -j DROP
ip netns exec cvexit iptables -D INPUT -d 1.1.1.1 -p tcp --dport 53 -j DROP
echo NATIVE_DNS_UPSTREAM_FALLBACK_PASS
kill -INT "$dns_capture_pid"
wait "$dns_capture_pid"
grep -q '^0 packets captured' /run/dns-uplink.log
if ip netns exec peer /native/socket-test data 192.168.1.1; then echo UNEXPECTED_USB_PRIVATE_BYPASS; exit 1; fi
if ip netns exec peer /native/socket-test ipv6-probe; then echo UNEXPECTED_USB_IPV6_BYPASS; exit 1; fi
echo NATIVE_USB_PRIVATE_IPV6_AND_DNS_UPLINK_BLOCK_PASS
for round in 1 2 3; do /usr/bin/node /project/scripts/lib/native-benchmark.mjs "native-$round" "$client_pid" "$exit_pid"; done
ip -n cvclient route del default via 154.62.226.216
ip -n cvclient route flush proto 186 dev wlan0
sleep 1
admin
ip -n cvclient route add default via 154.62.226.216
sleep 2
ip netns exec peer /native/socket-test probe
echo NATIVE_TUN_RECONNECT_PASS
printf '{"op":"stop"}\n' >&4
wait "$exit_pid"
# Keep the native client/ownership intact while replacing only its exit.
/usr/bin/ip netns exec cvexit /usr/bin/node /project/scripts/clean-vpn.js --role=exit --type=tls --server=0.0.0.0:443 --ext=eth0 --ipv6=off --tls-cert-dir=/native/certs --shared-hmac-key=/native/psk --tls-public-name=localhost >/run/old-exit.log 2>&1 &
old_exit_pid=$!
# The old CLI provisions its TUN/NAT before listening; under TCG this can
# exceed a packet probe's timeout. Await authenticated attachment, not a delay.
old_exit_ready=0
for attempt in $(seq 1 180); do
  if grep -q 'tls vpn: connected' /run/old-exit.log; then old_exit_ready=1; break; fi
  kill -0 "$old_exit_pid" || break
  sleep 1
done
if [ "$old_exit_ready" != 1 ]; then cat /run/client.log /run/old-exit.log; exit 1; fi
if ! ip netns exec peer /native/socket-test probe; then cat /run/client.log /run/old-exit.log; exit 1; fi
echo NATIVE_CLIENT_OLD_EXIT_PACKETS_PASS
printf '{"op":"stop"}\n' >&3
wait "$client_pid"
if ip netns exec peer /native/socket-test probe; then echo UNEXPECTED_BYPASS; exit 1; fi
admin
echo NATIVE_TUN_STOP_BLOCKS_PASS
# Graceful controller cleanup must already have removed owned split routes.
test -z "$(ip -n cvclient route show 0.0.0.0/1)"
test -z "$(ip -n cvclient route show 128.0.0.0/1)"
if ip netns exec peer /native/socket-test probe; then echo UNEXPECTED_DIRECT_BYPASS; exit 1; fi
if ip netns exec peer /native/socket-test dns 192.168.1.1; then echo UNEXPECTED_DNS_BYPASS; exit 1; fi
admin
ip netns exec cvclient /bin/bash /project/scripts/autostart/killswitch.sh status
echo NATIVE_PRODUCTION_GUARD_RETAINED_PASS
# Same TUN/USB/MTU/SNAT/guard and same application fixture for compatibility
# and comparison. Old endpoint deliberately remains the existing implementation.
# Legacy CLI allocates the first FREE TUN instead of attaching a provisioned
# persistent device. Release the disconnected fixture so it allocates tun0,
# the exact interface protected by the unchanged guard/SNAT/MSS rules.
ip netns exec cvclient /usr/bin/ip tuntap del dev tun0 mode tun
kill -TERM "$old_exit_pid"
wait "$old_exit_pid" || true
sleep 1
/usr/bin/ip netns exec cvexit /native/clean-vpn-engine --config /native/exit.json <&4 >/run/exit.log 2>&1 &
exit_pid=$!
/usr/bin/ip netns exec cvclient /usr/bin/node /project/scripts/clean-vpn.js --role=client --type=boring-tls --server=154.62.226.216:443 --split-default --dns-mode=off --ipv6=off --tls-cert-dir=/native/certs --shared-hmac-key=/native/psk --tls-server-name=localhost --tls-client-sni=localhost >/run/old-client.log 2>&1 &
old_client_pid=$!
wait_old_client
if ! ip netns exec peer /native/socket-test data; then cat /run/old-client.log /run/exit.log; exit 1; fi
echo OLD_CLIENT_NATIVE_EXIT_PACKETS_PASS
kill -TERM "$old_client_pid"
wait "$old_client_pid" || true
printf '{"op":"stop"}\n' >&4
wait "$exit_pid"
sleep 1
/usr/bin/ip netns exec cvexit /usr/bin/node /project/scripts/clean-vpn.js --role=exit --type=tls --server=0.0.0.0:443 --ext=eth0 --ipv6=off --tls-cert-dir=/native/certs --shared-hmac-key=/native/psk --tls-public-name=localhost >/run/old-exit.log 2>&1 &
old_exit_pid=$!
/usr/bin/ip netns exec cvclient /usr/bin/node /project/scripts/clean-vpn.js --role=client --type=boring-tls --server=154.62.226.216:443 --split-default --dns-mode=off --ipv6=off --tls-cert-dir=/native/certs --shared-hmac-key=/native/psk --tls-server-name=localhost --tls-client-sni=localhost >/run/old-client.log 2>&1 &
old_client_pid=$!
wait_old_client
if ! ip netns exec peer /native/socket-test data; then cat /run/old-client.log /run/old-exit.log; exit 1; fi
for round in 1 2 3; do
  if ! /usr/bin/node /project/scripts/lib/native-benchmark.mjs "legacy-$round" "$old_client_pid" "$old_exit_pid"; then cat /run/old-client.log /run/old-exit.log; exit 1; fi
done
kill -TERM "$old_client_pid" "$old_exit_pid"
wait "$old_client_pid" || true
wait "$old_exit_pid" || true
# Client engine crash: protection must outlive both engine and controller.
ip netns exec cvclient /usr/bin/ip tuntap add dev tun0 mode tun
ip -n cvclient link set tun0 mtu 1400 up
ip -n cvclient addr add 10.99.0.2/30 dev tun0
/usr/bin/ip netns exec cvexit /native/clean-vpn-engine --config /native/exit.json <&4 >/run/exit.log 2>&1 &
exit_pid=$!
/usr/bin/ip netns exec cvclient /usr/bin/node /project/scripts/clean-vpn-native.mjs --config /native/client.json --usb-profile <&3 >/run/client.log 2>&1 &
client_pid=$!
wait_client
ip netns exec peer /native/socket-test probe
engine_pid=''
for child in $(cat /proc/$client_pid/task/$client_pid/children); do
  case "$(readlink /proc/$child/exe)" in */clean-vpn-engine) engine_pid=$child;; esac
done
test -n "$engine_pid"
kill -KILL "$engine_pid"
if wait "$client_pid"; then echo UNEXPECTED_CRASH_SUCCESS; exit 1; fi
if ip netns exec peer /native/socket-test data; then echo UNEXPECTED_CRASH_BYPASS; exit 1; fi
ip -n cvclient route del 0.0.0.0/1 dev tun0
ip -n cvclient route del 128.0.0.0/1 dev tun0
if ip netns exec peer /native/socket-test data; then echo UNEXPECTED_CRASH_DIRECT_BYPASS; exit 1; fi
if ip netns exec peer /native/socket-test dns 192.168.1.1; then echo UNEXPECTED_CRASH_DNS_BYPASS; exit 1; fi
admin
echo NATIVE_CLIENT_CRASH_GUARD_ADMIN_PASS
printf '{"op":"stop"}\n' >&4
wait "$exit_pid"
kill "$origin_pid" "$backup_pid" "$private_pid" "$ipv6_pid" "$ssh_pid"
for child in "$origin_pid" "$backup_pid" "$private_pid" "$ipv6_pid" "$ssh_pid"; do wait "$child" || true; done
if ps | grep -E '[c]lean-vpn-engine|[b]oring-tls-helper|[c]lean-vpn.js|[c]lean-vpn-native.mjs'; then echo UNEXPECTED_ENGINE_PROCESS_RETAINED; exit 1; fi
echo NATIVE_PROCESS_CLEANUP_PASS
cat /run/client.log /run/exit.log
echo NATIVE_TUN_VM_PASS
