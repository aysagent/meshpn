#!/bin/sh
# ONLY inside the NIC-less disposable VM. No physical machine invocation.
set -eux
test "$(ls /sys/class/net)" = lo
test "$(cat /proc/1/comm)" = procd
media=/mnt/cvpn-payload
work=/tmp/cvpn-openwrt-native
apk --no-network --repositories-file=/dev/null --repository "$media/packages.adb" update
apk --no-network --repositories-file=/dev/null --repository "$media/packages.adb" add kmod-tun
modprobe tun
test -c /dev/net/tun
"$media/tun-device" create cvctun0
"$media/tun-device" create cvetun0
ip link set cvctun0 up mtu 1280
ip link set cvetun0 up mtu 1280
ip addr add 10.99.0.2/32 dev lo
ip addr add 198.18.0.80/32 dev lo
for dev in all default lo cvctun0 cvetun0; do
 sysctl -w "net.ipv4.conf.$dev.rp_filter=0"
 sysctl -w "net.ipv4.conf.$dev.accept_local=1"
done
# Each injected TUN packet is delivered locally before the source policy below.
# Each locally originated request/reply must cross the opposite native TUN.
ip rule add pref 10 iif cvctun0 lookup local
ip rule add pref 11 iif cvetun0 lookup local
ip rule add pref 100 from 10.99.0.2 to 198.18.0.80 table 100
ip rule add pref 101 from 198.18.0.80 to 10.99.0.2 table 101
ip rule add pref 1000 lookup local
ip rule del pref 0
ip route add 198.18.0.80/32 dev cvctun0 table 100
ip route add unreachable default table 100
ip route add 10.99.0.2/32 dev cvetun0 table 101
ip route add unreachable default table 101
# One owned fw4 zone: no flush and no change to existing zone policies.
uci set firewall.cvpn_lab=zone
uci set firewall.cvpn_lab.name=cvpn_lab
uci add_list firewall.cvpn_lab.device=cvctun0
uci add_list firewall.cvpn_lab.device=cvetun0
uci set firewall.cvpn_lab.input=ACCEPT
uci set firewall.cvpn_lab.output=ACCEPT
uci set firewall.cvpn_lab.forward=REJECT
uci commit firewall
/etc/init.d/firewall reload
engine="$media/engine"
if test -x /usr/sbin/clean-vpn-engine; then engine=/usr/sbin/clean-vpn-engine; fi
ready() {
 count=0
 until grep -q '"state":"ready"' "$1"; do
  kill -0 "$2"
  count=$((count+1)); test "$count" -lt 15
  sleep 1
 done
}
for protocol in 2 1.1; do
 "$engine" --config "$work/tun-exit-$protocol.json" --service >"$work/exit.log" 2>&1 & exit_pid=$!
 "$engine" --config "$work/tun-client.json" --service >"$work/client.log" 2>&1 & client_pid=$!
 ready "$work/client.log" "$client_pid"
 ready "$work/exit.log" "$exit_pid"
 ping -I 10.99.0.2 -c 3 -W 2 198.18.0.80
 # Prevent a false PASS through the guest's LOCAL route table.
 ip route del 198.18.0.80/32 dev cvctun0 table 100
 if ping -I 10.99.0.2 -c 1 -W 1 198.18.0.80; then echo route_negative_failed; exit 1; fi
 ip route add 198.18.0.80/32 dev cvctun0 table 100
 ping -I 10.99.0.2 -c 1 -W 2 198.18.0.80
 kill -TERM "$client_pid"
 wait "$client_pid"
 if ping -I 10.99.0.2 -c 1 -W 1 198.18.0.80; then echo stop_negative_failed; exit 1; fi
 kill -TERM "$exit_pid"
 wait "$exit_pid"
 for role in client exit; do
  tail -n 1 "$work/$role.log" >"$work/final.json"
  test "$(jsonfilter -i "$work/final.json" -e '@.state')" = stopped
  test "$(jsonfilter -i "$work/final.json" -e '@.tx_packets')" -ge 4
  test "$(jsonfilter -i "$work/final.json" -e '@.rx_packets')" -ge 4
 done
 printf 'CVPN_OPENWRT_NORMAL_TUN_%s=passed\n' "$protocol"
 "$engine" --config "$work/tun-exit-$protocol.json" --service >"$work/exit-bad.log" 2>&1 & exit_pid=$!
 "$engine" --config "$work/tun-bad-client.json" --service >"$work/client-bad.log" 2>&1 & client_pid=$!
 count=0
 until grep -q '"state":"auth_rejected"' "$work/exit-bad.log"; do
  kill -0 "$exit_pid"; kill -0 "$client_pid"
  count=$((count+1)); test "$count" -lt 15
  sleep 1
 done
 if grep -q '"state":"ready"' "$work/client-bad.log"; then echo bad_psk_ready; exit 1; fi
 if ping -I 10.99.0.2 -c 1 -W 1 198.18.0.80; then echo bad_psk_packet; exit 1; fi
 kill -TERM "$client_pid"; wait "$client_pid"
 kill -TERM "$exit_pid"; wait "$exit_pid"
 for role in client exit; do
  tail -n 1 "$work/$role-bad.log" >"$work/final.json"
  test "$(jsonfilter -i "$work/final.json" -e '@.tx_packets')" = 0
  test "$(jsonfilter -i "$work/final.json" -e '@.rx_packets')" = 0
 done
 printf 'CVPN_OPENWRT_NORMAL_PSK_%s=rejected\n' "$protocol"
done
# Actual normal engines under procd, distinct from the initial sleep fixture.
# This temporary service is not an installed network owner or production adapter.
cat >/etc/init.d/clean-vpn-native-lab <<EOF
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
start_service() {
 procd_open_instance exit
 procd_set_param command "$engine" --config "$work/tun-exit-2.json" --service
 procd_set_param respawn 3600 1 3
 procd_set_param stdout 1
 procd_set_param stderr 1
 procd_close_instance
 procd_open_instance client
 procd_set_param command "$engine" --config "$work/tun-client.json" --service
 procd_set_param respawn 3600 1 3
 procd_set_param stdout 1
 procd_set_param stderr 1
 procd_close_instance
}
EOF
chmod 755 /etc/init.d/clean-vpn-native-lab
/etc/init.d/clean-vpn-native-lab start
native_pid() {
 ubus -t 5 call service list '{"name":"clean-vpn-native-lab"}' | jsonfilter -e "@[\"clean-vpn-native-lab\"].instances.$1.pid"
}
packet_ready() {
 count=0
 until ping -I 10.99.0.2 -c 1 -W 1 198.18.0.80; do
  count=$((count+1)); test "$count" -lt 15
  sleep 1
 done
}
packet_ready
ubus -t 5 call service list '{"name":"clean-vpn-native-lab"}'
old_client=$(native_pid client); supervised_exit=$(native_pid exit)
test -n "$old_client"; test -n "$supervised_exit"
kill -KILL "$old_client"
count=0
while :; do
 # A missing PID is expected between reap and respawn; jsonfilter returns 1.
 new_client=$(native_pid client || true)
 if test -n "$new_client" && test "$new_client" != "$old_client"; then break; fi
 count=$((count+1)); test "$count" -lt 15
 sleep 1
done
test ! -e "/proc/$old_client"
test -e "/proc/$new_client"
test "$(native_pid exit)" = "$supervised_exit"
packet_ready
/etc/init.d/clean-vpn-native-lab stop
count=0
while test -e "/proc/$new_client" || test -e "/proc/$supervised_exit"; do
 count=$((count+1)); test "$count" -lt 10
 sleep 1
done
test -z "$(native_pid client)"; test -z "$(native_pid exit)"
test ! -e "/proc/$new_client"; test ! -e "/proc/$supervised_exit"
if ping -I 10.99.0.2 -c 1 -W 1 198.18.0.80; then echo procd_stop_negative_failed; exit 1; fi
rm /etc/init.d/clean-vpn-native-lab
printf 'CVPN_OPENWRT_NATIVE_PROCD=passed\n'
ip rule add pref 0 lookup local
for pref in 10 11 100 101 1000; do ip rule del pref "$pref"; done
ip route flush table 100
ip route flush table 101
ip addr del 10.99.0.2/32 dev lo
ip addr del 198.18.0.80/32 dev lo
"$media/tun-device" delete cvctun0
"$media/tun-device" delete cvetun0
uci delete firewall.cvpn_lab
uci commit firewall
/etc/init.d/firewall reload
test "$(ls /sys/class/net)" = lo
printf 'CVPN_OPENWRT_NORMAL_TUN=passed\n'
