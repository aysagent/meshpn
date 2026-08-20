#!/usr/bin/env bash
#
# clean-vpn kill-switch: блокирует любой трафик мимо туннеля.
#
# Ставит правила в ВЫДЕЛЕННЫХ цепочках (изолированно от того, что делает сам
# clean-vpn.js), поэтому включение/выключение kill-switch не конфликтует с
# intercept/NAT-правилами clean-vpn и полностью идемпотентно.
#
# Логика (v4):
#   OUTPUT  (трафик самой платы)      → CLEANVPN_KS_OUT
#   FORWARD (форвардинг LAN-клиентов) → CLEANVPN_KS_FWD
# В цепочке пропускаем (RETURN): loopback, established/related, RFC1918,
# IP VPN-сервера (bypass для установки туннеля), tun-интерфейс, DHCP/broadcast.
# Всё остальное → DROP. Так до поднятия туннеля (и если он упал) наружу мимо
# tun ничего не уходит.
#
# IPv6: туннель IPv4-only, поэтому весь IPv6-egress режем, кроме link-local,
# ULA (fc00::/7) и multicast (ND/RA/DHCPv6).
#
# Использование:
#   killswitch.sh up   --server=IP[,IP...] [--scope=both|fwd] [--ipv6=block|leave] [--tun=tun0]
#   killswitch.sh down [--tun=tun0]
#   killswitch.sh status
#
set -euo pipefail

log() { printf '[clean-vpn-killswitch] %s\n' "$*"; }
die() { printf '[clean-vpn-killswitch] ОШИБКА: %s\n' "$*" >&2; exit 1; }

# --- цепочки ---
CH_OUT="CLEANVPN_KS_OUT"
CH_FWD="CLEANVPN_KS_FWD"

# --- параметры ---
ACTION="${1:-}"; shift || true
SERVERS=""
SCOPE="both"     # both | fwd
IPV6="block"     # block | leave
TUN="tun0"

for a in "$@"; do
  case "$a" in
    --server=*) SERVERS="${a#*=}" ;;
    --scope=*)  SCOPE="${a#*=}" ;;
    --ipv6=*)   IPV6="${a#*=}" ;;
    --tun=*)    TUN="${a#*=}" ;;
    *) die "неизвестный аргумент: $a" ;;
  esac
done

IPT="$(command -v iptables || true)"
IP6T="$(command -v ip6tables || true)"
[[ -n "$IPT" ]] || die "iptables не найден"
# -w: ждать xtables lock, чтобы не конфликтовать с clean-vpn.
ipt() { "$IPT" -w "$@"; }
ip6() { [[ -n "$IP6T" ]] && "$IP6T" -w "$@"; }

RFC1918=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)

# Удалить все вхождения jump-правила из базовой цепочки (идемпотентно).
del_hook_v4() {
  local base="$1" ch="$2"
  while ipt -C "$base" -j "$ch" 2>/dev/null; do
    ipt -D "$base" -j "$ch" 2>/dev/null || break
  done
}
del_hook_v6() {
  local base="$1" ch="$2"
  [[ -n "$IP6T" ]] || return 0
  while ip6 -C "$base" -j "$ch" 2>/dev/null; do
    ip6 -D "$base" -j "$ch" 2>/dev/null || break
  done
}

down() {
  # v4
  del_hook_v4 OUTPUT "$CH_OUT"
  del_hook_v4 FORWARD "$CH_FWD"
  ipt -F "$CH_OUT" 2>/dev/null || true
  ipt -X "$CH_OUT" 2>/dev/null || true
  ipt -F "$CH_FWD" 2>/dev/null || true
  ipt -X "$CH_FWD" 2>/dev/null || true
  # v6
  del_hook_v6 OUTPUT "$CH_OUT"
  del_hook_v6 FORWARD "$CH_FWD"
  ip6 -F "$CH_OUT" 2>/dev/null || true
  ip6 -X "$CH_OUT" 2>/dev/null || true
  ip6 -F "$CH_FWD" 2>/dev/null || true
  ip6 -X "$CH_FWD" 2>/dev/null || true
}

build_v4_out() {
  ipt -N "$CH_OUT"
  ipt -A "$CH_OUT" -o lo -j RETURN
  ipt -A "$CH_OUT" -o "$TUN" -j RETURN
  ipt -A "$CH_OUT" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  local net
  for net in "${RFC1918[@]}"; do
    ipt -A "$CH_OUT" -d "$net" -j RETURN
  done
  # DHCP-клиент (до получения адреса established ещё нет).
  ipt -A "$CH_OUT" -p udp --sport 68 --dport 67 -j RETURN
  ipt -A "$CH_OUT" -d 255.255.255.255 -j RETURN
  # bypass к VPN-серверу(ам) — чтобы clean-vpn мог поднять туннель.
  local ip
  for ip in ${SERVERS//,/ }; do
    [[ -n "$ip" ]] && ipt -A "$CH_OUT" -d "$ip" -j RETURN
  done
  ipt -A "$CH_OUT" -j DROP
}

build_v4_fwd() {
  ipt -N "$CH_FWD"
  ipt -A "$CH_FWD" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  # Форвардинг В туннель — ок.
  ipt -A "$CH_FWD" -o "$TUN" -j RETURN
  # LAN↔LAN.
  local net
  for net in "${RFC1918[@]}"; do
    ipt -A "$CH_FWD" -d "$net" -j RETURN
  done
  ipt -A "$CH_FWD" -j DROP
}

build_v6() {
  [[ -n "$IP6T" ]] || { log "ip6tables нет — IPv6 не трогаю"; return 0; }
  # OUTPUT
  ip6 -N "$CH_OUT"
  ip6 -A "$CH_OUT" -o lo -j RETURN
  ip6 -A "$CH_OUT" -o "$TUN" -j RETURN
  ip6 -A "$CH_OUT" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  ip6 -A "$CH_OUT" -d fe80::/10 -j RETURN       # link-local (ND/RA/DHCPv6-LL)
  ip6 -A "$CH_OUT" -d fc00::/7  -j RETURN       # ULA / локальные IPv6-сети
  ip6 -A "$CH_OUT" -d ff00::/8  -j RETURN       # multicast (ND/RA/MLD)
  ip6 -A "$CH_OUT" -j DROP
  # FORWARD
  ip6 -N "$CH_FWD"
  ip6 -A "$CH_FWD" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  ip6 -A "$CH_FWD" -d fe80::/10 -j RETURN
  ip6 -A "$CH_FWD" -d fc00::/7  -j RETURN
  ip6 -A "$CH_FWD" -d ff00::/8  -j RETURN
  ip6 -A "$CH_FWD" -j DROP
}

up() {
  [[ "$SCOPE" == "both" || "$SCOPE" == "fwd" ]] || die "недопустимый --scope=$SCOPE (both|fwd)"
  [[ "$IPV6" == "block" || "$IPV6" == "leave" ]] || die "недопустимый --ipv6=$IPV6 (block|leave)"

  # Чистим прошлое состояние — up идемпотентен.
  down

  # v4 FORWARD ставим всегда (both и fwd оба включают форвардинг).
  build_v4_fwd
  ipt -I FORWARD 1 -j "$CH_FWD"

  if [[ "$SCOPE" == "both" ]]; then
    build_v4_out
    ipt -I OUTPUT 1 -j "$CH_OUT"
  fi

  if [[ "$IPV6" == "block" ]]; then
    build_v6
    if [[ -n "$IP6T" ]]; then
      ip6 -I FORWARD 1 -j "$CH_FWD"
      [[ "$SCOPE" == "both" ]] && ip6 -I OUTPUT 1 -j "$CH_OUT"
    fi
  fi

  log "включён (scope=$SCOPE ipv6=$IPV6 tun=$TUN server=${SERVERS:-—})"
}

status() {
  echo "== iptables filter OUTPUT/FORWARD (v4) =="
  ipt -S OUTPUT | grep -- "$CH_OUT" || echo "  (нет hook в OUTPUT)"
  ipt -S FORWARD | grep -- "$CH_FWD" || echo "  (нет hook в FORWARD)"
  echo "-- $CH_OUT --"; ipt -S "$CH_OUT" 2>/dev/null || echo "  (нет)"
  echo "-- $CH_FWD --"; ipt -S "$CH_FWD" 2>/dev/null || echo "  (нет)"
  if [[ -n "$IP6T" ]]; then
    echo "== ip6tables (v6) =="
    ip6 -S OUTPUT | grep -- "$CH_OUT" || echo "  (нет hook в OUTPUT v6)"
    ip6 -S FORWARD | grep -- "$CH_FWD" || echo "  (нет hook в FORWARD v6)"
  fi
}

case "$ACTION" in
  up)     up ;;
  down)   down; log "выключен" ;;
  status) status ;;
  *) die "usage: killswitch.sh up|down|status [--server=IP,...] [--scope=both|fwd] [--ipv6=block|leave] [--tun=tun0]" ;;
esac
