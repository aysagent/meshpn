#!/usr/bin/env bash
# Read-only, bounded capture that survives moving the USB cable to a phone.
set -euo pipefail
umask 077
BASE=/var/lib/clean-vpn-phone-capture
UNIT=clean-vpn-phone-capture
usage() { echo "Usage: sudo bash $0 start [seconds:60..1800] | status | stop"; }
[[ ${EUID} == 0 ]] || { echo 'Linux root required' >&2; exit 1; }
[[ $(uname -s) == Linux ]] || { echo 'Linux required' >&2; exit 1; }
action=${1:-}
case "$action" in
start)
  [[ $# -le 2 ]] || { usage; exit 1; }
  seconds=${2:-900}
  [[ $seconds =~ ^[0-9]{2,4}$ ]] && ((10#$seconds >= 60 && 10#$seconds <= 1800)) || { usage; exit 1; }
  for tool in systemd-run systemctl tcpdump ip iptables-save timeout journalctl; do command -v "$tool" >/dev/null; done
  ip link show usb0 >/dev/null
  state=$(systemctl show "$UNIT.service" -p ActiveState --value 2>/dev/null || true)
  [[ $state != active && $state != activating && $state != deactivating ]] || { echo 'Capture already running'; exit 1; }
  install -d -m 700 "$BASE"
  directory=$(mktemp -d "$BASE/run-XXXXXXXX")
  script=$(readlink -f "$0")
  systemd-run --quiet --collect --unit="$UNIT" --property=Type=exec --property=UMask=0077 --property=RuntimeMaxSec="$((10#$seconds+20))" --property=TimeoutStopSec=10 --property=KillMode=control-group /bin/bash "$script" _record "$directory" "$seconds"
  echo "CAPTURE_STARTED=$directory"
  echo "DURATION_SECONDS=$seconds"
  echo 'Move USB to the phone, open internet.yandex.ru, then return USB to the laptop.'
  ;;
status)
  systemctl show "$UNIT.service" -p ActiveState -p SubState -p Result 2>/dev/null || true
  if [[ -d $BASE ]]; then find "$BASE" -maxdepth 2 -type f -name summary.txt -exec cat {} \;; fi
  ;;
stop)
  systemctl stop "$UNIT.service"
  echo 'Capture stopped; records retained.'
  ;;
_record)
  [[ $# == 3 && $2 == "$BASE"/run-* && -d $2 && ! -L $2 ]] || exit 1
  directory=$2; seconds=$3
  exec >"$directory/summary.txt" 2>&1
  echo "DIRECTORY=$directory"
  echo "STARTED=$(date -u +%FT%TZ)"
  started=$(date +%s)
  children=()
  snapshot() {
    date -u +%FT%TZ
    ip -br address
    ip -4 route show table all
    ip -6 route show table all
    ip -4 rule; ip -6 rule
    ip neigh show dev usb0
    iptables-save -c
    command -v ip6tables-save >/dev/null && ip6tables-save -c
    systemctl show native-combo-daily.service native-combo-daily-network.service clean-vpn-killswitch.service -p Id -p ActiveState -p SubState -p MainPID -p StatusText
    cat /var/lib/misc/dnsmasq.leases 2>/dev/null || true
  }
  finish() {
    trap - EXIT TERM INT
    for pid in "${children[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    for pid in "${children[@]}"; do wait "$pid" 2>/dev/null || true; done
    snapshot >"$directory/after.txt" 2>&1 || true
    journalctl --since="@$started" --no-pager -o short-iso -u native-combo-daily.service -u native-combo-daily-network.service -u dnsmasq.service >"$directory/services.log" 2>&1 || true
    echo "FINISHED=$(date -u +%FT%TZ)"
  }
  trap finish EXIT
  trap 'exit 0' TERM INT
  snapshot >"$directory/before.txt" 2>&1 || true
  # 256 bytes retain L2/L3/L4 headers and short DNS messages. The first bytes
  # of application payload can also be present: keep the directory private.
  # Each interface uses at most two ~4 MB files; rotation replaces old data.
  for iface in usb0 wlan0 tun0; do
    if ip link show "$iface" >/dev/null 2>&1; then
      tcpdump -n -i "$iface" -s 256 -U -C 4 -W 2 -w "$directory/$iface.pcap" >"$directory/$iface.log" 2>&1 &
      children+=("$!")
    fi
  done
  sleep 1
  for pid in "${children[@]}"; do kill -0 "$pid" || { echo 'CAPTURE_FAILED'; exit 1; }; done
  echo 'CAPTURE_READY'
  deadline=$((SECONDS+seconds))
  while (( SECONDS < deadline )); do
    { date -u +%FT%TZ; ip -s link show usb0; ip neigh show dev usb0; ss -nto; } >>"$directory/timeline.txt" 2>&1 || true
    sleep 10 &
    wait $! || true
  done
  ;;
*) usage; exit 1;;
esac
