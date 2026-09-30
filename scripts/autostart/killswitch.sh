#!/usr/bin/env bash
# Public-egress guard. Exceptions: TUN, LAN, IPv4 exit IPs, DHCP and inbound
# SSH replies (--ssh-port=22; 0 disables). Allowed traffic RETURNs to the existing
# firewall. Own chains are audited, then rebuilt using restore --noflush.
# No implicit down/global flush. Legacy or foreign contents are refused.
# IPv4 and IPv6 commits are separate; first installation is protected only after
# successful up. Early boot and crash/restart coordination belong to the service.
set -euo pipefail
umask 077
log() { printf '[clean-vpn-killswitch] %s\n' "$*"; }
die() { printf '[clean-vpn-killswitch] ОШИБКА: %s\n' "$*" >&2; exit 1; }
ACTION="${1:-}"; shift || true
SERVERS='' SCOPE=both IPV6=block TUN=tun0 SSH_PORT=22
declare -A seen=() IPT=() RESTORE=() SNAP=() OLD=() PLAN=()
for arg in "$@"; do
  key="${arg%%=*}"
  [[ "$arg" == *=* && -n "$key" ]] || die "invalid argument: $arg"
  [[ -z "${seen[$key]:-}" ]] || die "duplicate argument: $key"
  seen[$key]=1
  case "$key" in
    --server) SERVERS="${arg#*=}" ;;
    --scope) SCOPE="${arg#*=}" ;;
    --ipv6) IPV6="${arg#*=}" ;;
    --tun) TUN="${arg#*=}" ;;
    --ssh-port) SSH_PORT="${arg#*=}" ;;
    *) die "unknown argument: $key" ;;
  esac
done
case "$ACTION" in up|down|status|plan) ;; *) die 'usage: killswitch.sh up|down|status|plan --server=IPv4[,IPv4...] [--scope=both|fwd] [--ipv6=block|leave] [--tun=tun0] [--ssh-port=22]' ;; esac
validate() {
  local scope="$1" ipv6="$2" tun="$3" servers="$4" port="$5" addr octet first
  local -a ips parts
  [[ "$scope" == both || "$scope" == fwd ]] || die 'invalid scope'
  [[ "$ipv6" == block || "$ipv6" == leave ]] || die 'invalid ipv6 mode'
  [[ "$tun" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$ && "$tun" != lo ]] || die 'invalid TUN name'
  [[ "$port" =~ ^(0|[1-9][0-9]{0,4})$ ]] && (( port <= 65535 )) || die 'invalid SSH port'
  [[ -n "$servers" && "$servers" != *, && ${#servers} -le 255 ]] || die 'numeric IPv4 --server required'
  local marker="cvks2:$scope:$ipv6:$tun:$servers:$port"
  (( ${#marker} < 256 )) || die 'guard configuration exceeds comment limit'
  IFS=, read -r -a ips <<< "$servers"
  (( ${#ips[@]} <= 16 )) || die 'too many exit addresses'
  for addr in "${ips[@]}"; do
    [[ "$addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'exit must be numeric IPv4'
    IFS=. read -r -a parts <<< "$addr"
    for octet in "${parts[@]}"; do
      [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( octet <= 255 )) || die 'invalid IPv4 octet'
    done
    first="${parts[0]}"
    (( first > 0 && first < 224 && first != 127 )) || die 'exit must be unicast, non-loopback IPv4'
  done
}
if [[ "$ACTION" == up || "$ACTION" == plan ]]; then validate "$SCOPE" "$IPV6" "$TUN" "$SERVERS" "$SSH_PORT"; fi
NEW="cvks2:$SCOPE:$IPV6:$TUN:$SERVERS:$SSH_PORT"
CHAINS=(CLEANVPN_KS_OUT CLEANVPN_KS_FWD)
hook() { printf -- '-A %s -m comment --comment cvks2-hook -j %s\n' "$1" "$2"; }
# Canonical iptables -S form, without comment quotes. Kernel text is never eval'd.
rules() {
  local family="$1" config="$2" version scope ipv6 tun servers port chain net addr
  IFS=: read -r version scope ipv6 tun servers port <<< "$config"
  [[ "$version" == cvks2 ]] || die 'unknown guard version'
  validate "$scope" "$ipv6" "$tun" "$servers" "$port"
  [[ "$family" == 4 || "$ipv6" == block ]] || return 0
  for chain in "${CHAINS[@]}"; do
    [[ "$chain" != CLEANVPN_KS_OUT || "$scope" == both ]] || continue
    printf -- '-N %s\n-A %s -m comment --comment %s\n' "$chain" "$chain" "$config"
    if [[ "$chain" == CLEANVPN_KS_OUT ]]; then
      printf -- '-A %s -o lo -j RETURN\n' "$chain"
      if (( port > 0 )); then
        printf -- '-A %s -p tcp -m tcp --sport %s -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN\n' "$chain" "$port"
      fi
    else
      printf -- '-A %s -i %s -j RETURN\n' "$chain" "$tun"
    fi
    printf -- '-A %s -o %s -j RETURN\n' "$chain" "$tun"
    if [[ "$family" == 4 ]]; then
      for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do printf -- '-A %s -d %s -j RETURN\n' "$chain" "$net"; done
      if [[ "$chain" == CLEANVPN_KS_OUT ]]; then
        printf -- '-A %s -p udp -m udp --sport 68 --dport 67 -j RETURN\n' "$chain"
        printf -- '-A %s -d 255.255.255.255/32 -j RETURN\n' "$chain"
        for addr in ${servers//,/ }; do printf -- '-A %s -d %s/32 -j RETURN\n' "$chain" "$addr"; done
      fi
    else
      for net in fe80::/10 fc00::/7 ff02::/16; do printf -- '-A %s -d %s -j RETURN\n' "$chain" "$net"; done
    fi
    printf -- '-A %s -j DROP\n' "$chain"
  done
}
render_up() {
  local family="$1" line chain base content
  content="$(rules "$family" "$NEW")"
  [[ -n "$content" ]] || return 0
  printf '*filter\n'
  # Declared user chains are rebuilt inside one table COMMIT, even with -n.
  while IFS= read -r line; do [[ "$line" != '-N '* ]] || printf ':%s - [0:0]\n' "${line#-N }"; done <<< "$content"
  while IFS= read -r line; do [[ "$line" != '-A '* ]] || printf '%s\n' "$line"; done <<< "$content"
  for chain in "${CHAINS[@]}"; do
    [[ "$content" == *"-N $chain"* ]] || continue
    base=FORWARD; [[ "$chain" != CLEANVPN_KS_OUT ]] || base=OUTPUT
    if [[ -n "${OLD[$family]:-}" ]]; then line="$(hook "$base" "$chain")"; printf '%s\n' "${line/-A /-D }"; fi
    printf -- '-I %s 1 -m comment --comment cvks2-hook -j %s\n' "$base" "$chain"
  done
  printf 'COMMIT\n'
}
if [[ "$ACTION" == plan ]]; then render_up 4; render_up 6; exit 0; fi
[[ "$EUID" == 0 ]] || die 'root required (plan needs no root)'
for family in 4 6; do
  tool=iptables; [[ "$family" == 4 ]] || tool=ip6tables
  IPT[$family]="$(command -v "$tool")" || die "$tool missing; protection retained"
  RESTORE[$family]="$(command -v "$tool-restore")" || die "$tool-restore missing"
  a="$("${IPT[$family]}" --version)"; b="$("${RESTORE[$family]}" --version)"
  [[ "${a#* }" == "${b#* }" ]] || die 'iptables/restore backend mismatch'
done
# Private directory/persistent inode. Children inherit fd 9, including restore.
LOCK_DIR=/run/clean-vpn-killswitch
[[ ! -L "$LOCK_DIR" ]] || die 'unsafe lock directory'
if [[ ! -e "$LOCK_DIR" ]]; then mkdir -m 0700 "$LOCK_DIR"; fi
[[ -d "$LOCK_DIR" && "$(stat -c '%u:%a' "$LOCK_DIR")" == 0:700 ]] || die 'unsafe lock directory'
if [[ -e "$LOCK_DIR/lock" || -L "$LOCK_DIR/lock" ]]; then
  [[ ! -L "$LOCK_DIR/lock" && -f "$LOCK_DIR/lock" && "$(stat -c '%u:%a:%h' "$LOCK_DIR/lock")" == 0:600:1 ]] || die 'unsafe lock file'
fi
exec 9>>"$LOCK_DIR/lock"
flock -w 10 9 || die 'another guard operation is active'
audit() {
  local family="$1" line chain base config='' expected actual selected want count first
  SNAP[$family]="$("${IPT[$family]}" -w 5 -t filter -S)"
  SNAP[$family]="${SNAP[$family]//\"/}"
  while IFS= read -r line; do
    if [[ "$line" == '-A CLEANVPN_KS_FWD -m comment --comment cvks2:'* ]]; then
      [[ -z "$config" ]] || die 'duplicate ownership marker'
      config="${line#-A CLEANVPN_KS_FWD -m comment --comment }"
    fi
  done <<< "${SNAP[$family]}"
  expected=''; [[ -z "$config" ]] || expected="$(rules "$family" "$config")"
  for chain in "${CHAINS[@]}"; do
    actual='' selected='' count=0 first=''
    base=FORWARD; [[ "$chain" != CLEANVPN_KS_OUT ]] || base=OUTPUT
    want="$(hook "$base" "$chain")"
    while IFS= read -r line; do
      if [[ "$line" == "-N $chain" || "$line" == "-A $chain "* ]]; then actual+="$line"$'\n'; fi
      if [[ "$line" == *"-j $chain"* || "$line" == *"-g $chain"* ]]; then
        [[ "$line" == "$want" ]] || die "foreign reference to $chain; no changes"
        count=$((count + 1))
      fi
      if [[ -z "$first" && "$line" == "-A $base "* ]]; then first="$line"; fi
    done <<< "${SNAP[$family]}"
    while IFS= read -r line; do
      if [[ "$line" == "-N $chain" || "$line" == "-A $chain "* ]]; then selected+="$line"$'\n'; fi
    done <<< "$expected"
    [[ "$actual" == "$selected" ]] || die "foreign/legacy/modified $chain (IPv$family); no changes"
    if [[ -n "$selected" ]]; then
      [[ "$count" == 1 && "$first" == "$want" ]] || die "missing/duplicate/shadowed $chain hook; no changes"
    else [[ "$count" == 0 ]] || die "orphan $chain hook"; fi
  done
  OLD[$family]="$config"
}
for family in 4 6; do audit "$family"; done
if [[ "$ACTION" == status ]]; then
  for family in 4 6; do log "IPv$family: ${OLD[$family]:-absent}"; done
  exit 0
fi
for family in 4 6; do
  if [[ "$ACTION" == up ]]; then
    if [[ -n "${OLD[$family]}" ]]; then
      IFS=: read -r version old_scope old_ipv6 rest <<< "${OLD[$family]}"
      [[ "$SCOPE" == "$old_scope" && "$IPV6" == "$old_ipv6" ]] || die 'live scope/IPv6-mode change refused; explicit down required'
    fi
    PLAN[$family]="$(render_up "$family")"
  else
    PLAN[$family]=''
    if [[ -n "${OLD[$family]}" ]]; then
      content="$(rules "$family" "${OLD[$family]}")"
      payload=$'*filter\n'
      for chain in "${CHAINS[@]}"; do
        [[ "$content" == *"-N $chain"* ]] || continue
        base=FORWARD; [[ "$chain" != CLEANVPN_KS_OUT ]] || base=OUTPUT
        line="$(hook "$base" "$chain")"
        payload+="${line/-A /-D }"$'\n'"-F $chain"$'\n'"-X $chain"$'\n'
      done
      PLAN[$family]="${payload}COMMIT"
    fi
  fi
done
# Validate both families first. Never remove protection on an up failure.
for family in 6 4; do
  [[ -z "${PLAN[$family]}" ]] || "${RESTORE[$family]}" -w 5 --noflush --test <<< "${PLAN[$family]}"
done
for family in 6 4; do
  [[ -z "${PLAN[$family]}" ]] || "${RESTORE[$family]}" -w 5 --noflush <<< "${PLAN[$family]}"
done
log "$ACTION completed (per-family atomic; explicit LAN/exit/SSH exceptions)"
