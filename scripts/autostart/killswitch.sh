#!/usr/bin/env bash
# Public-egress guard. Exceptions: TUN, LAN, IPv4 exit IPs, DHCP and inbound
# SSH replies (--ssh-port=22; 0 disables). With --usb-dns=1, USB DNS must use TUN;
# LAN exceptions never authorize usb0 UDP/TCP destination port 53 outside it.
# Host DNS must also use TUN/loopback so a local DNS proxy cannot bypass this.
# Allowed traffic RETURNs to the existing
# firewall. Own chains are audited, then rebuilt using restore --noflush.
# No implicit down/global flush. Legacy or foreign contents are refused.
# IPv4 and IPv6 commits are separate; first installation is protected only after
# successful up. Early boot and crash/restart coordination belong to the service.
set -euo pipefail
umask 077
log() { printf '[clean-vpn-killswitch] %s\n' "$*"; }
die() { printf '[clean-vpn-killswitch] ОШИБКА: %s\n' "$*" >&2; exit 1; }
ACTION="${1:-}"; shift || true
SERVERS='' SCOPE=both IPV6=block TUN=tun0 SSH_PORT=22 FAMILY='' USB_DNS=0 USB_STRICT=0
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
    --family) FAMILY="${arg#*=}" ;;
    --usb-dns) USB_DNS="${arg#*=}" ;;
    --usb-strict) USB_STRICT="${arg#*=}" ;;
    *) die "unknown argument: $key" ;;
  esac
done
case "$ACTION" in up|down|status|plan|audit-snapshot) ;; *) die 'usage: killswitch.sh up|down|status|plan [options]; audit-snapshot --family=4|6 < filter-S.txt' ;; esac
if [[ "$ACTION" == audit-snapshot ]]; then
  [[ ${#seen[@]} == 1 && ( "$FAMILY" == 4 || "$FAMILY" == 6 ) ]] || die 'audit-snapshot requires only --family=4|6'
else [[ -z "${seen[--family]:-}" ]] || die '--family is only for audit-snapshot'; fi
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
[[ "$USB_DNS" == 0 || "$USB_DNS" == 1 ]] || die 'invalid USB DNS mode'
[[ "$USB_STRICT" == 0 || "$USB_STRICT" == 1 ]] || die 'invalid USB strict mode'
VERSION=cvks2; [[ "$USB_DNS" != 1 ]] || VERSION=cvks3
if [[ "$USB_STRICT" == 1 ]]; then
  [[ "$USB_DNS" == 1 && "$SCOPE" == both && "$IPV6" == block && "$TUN" != usb0 ]] || die 'strict USB requires both/block and USB DNS protection'
  VERSION=cvks4
fi
NEW="$VERSION:$SCOPE:$IPV6:$TUN:$SERVERS:$SSH_PORT"
CHAINS=(CLEANVPN_KS_OUT CLEANVPN_KS_FWD)
hook() { printf -- '-A %s -m comment --comment cvks2-hook -j %s\n' "$1" "$2"; }
# Canonical iptables -S form, without comment quotes. Kernel text is never eval'd.
rules() {
  local family="$1" config="$2" version scope ipv6 tun servers port chain net addr proto
  IFS=: read -r version scope ipv6 tun servers port <<< "$config"
  [[ "$version" == cvks2 || "$version" == cvks3 || "$version" == cvks4 ]] || die 'unknown guard version'
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
    if [[ "$version" == cvks4 && "$chain" == CLEANVPN_KS_FWD ]]; then
      if [[ "$family" == 4 ]]; then
        # Route withdrawal must not send LAN packets into the TUN queue and
        # later deliver them via exit. DNS DNAT/local SSH use INPUT instead.
        for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
          printf -- '-A %s -d %s -i usb0 -j DROP\n' "$chain" "$net"
        done
        printf -- '-A %s -s 192.168.7.0/24 -i usb0 -o %s -j RETURN\n' "$chain" "$tun"
      fi
      # No LAN/exit/port exceptions for forwarded USB. INPUT (SSH/DNS to
      # the board) is separate. IPv6 is fail-closed until peer IPv6 is supported.
      printf -- '-A %s -i usb0 -j DROP\n' "$chain"
    fi
    printf -- '-A %s -o %s -j RETURN\n' "$chain" "$tun"
    # USB profile opts into v3; other deployments retain their v2 semantics.
    # Local USB DNS terminates in INPUT and is not affected.
    if [[ "$version" == cvks3 || "$version" == cvks4 ]]; then
      for proto in udp tcp; do
        if [[ "$chain" == CLEANVPN_KS_FWD ]]; then
          printf -- '-A %s -i usb0 -p %s -m %s --dport 53 -j DROP\n' "$chain" "$proto" "$proto"
        else
          printf -- '-A %s -p %s -m %s --dport 53 -j DROP\n' "$chain" "$proto" "$proto"
        fi
      done
    fi
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
# Read-only audit admits only these complete, canonical host-client plans before
# the guard hook. No arbitrary matches/targets, goto, nested jumps or trust based
# on a comment alone. RETURN in these user chains continues at the guard; REJECT
# terminates with denial. Mutation still requires the guard hook FIRST.
chain_text() {
  local family="$1" chain="$2" line
  while IFS= read -r line; do
    [[ "$line" != "-N $chain" && "$line" != "-A $chain "* ]] || printf '%s\n' "$line"
  done <<< "${SNAP[$family]}"
}
safe_dns_chain() {
  local family="$1" tag="$2" tun="$3" actual line addr expected='-N CVPN-DNS-OUT' count=0 previous=''
  local head='-A CVPN-DNS-OUT -s 10.99.0.2/32 -d ' tail="/32 -o $tun -m comment --comment $tag -j RETURN"
  actual="$(chain_text "$family" CVPN-DNS-OUT)"
  while IFS= read -r line; do
    if [[ "$line" == "$head"*"$tail" ]]; then
      addr="${line#"$head"}"; addr="${addr%"$tail"}"
      validate both block "$tun" "$addr" 0
      [[ "$addr" != "$previous" ]] || return 1
      previous="$addr"; count=$((count + 1)); expected+=$'\n'"$line"
    fi
  done <<< "$actual"
  (( count >= 1 && count <= 2 )) || return 1
  expected+=$'\n'"-A CVPN-DNS-OUT -d 127.0.0.0/8 -m comment --comment $tag -j RETURN"
  expected+=$'\n'"-A CVPN-DNS-OUT -m comment --comment $tag -j REJECT --reject-with icmp-port-unreachable"
  [[ "$actual" == "$expected" ]]
}
safe_ipv6_chain() {
  local tag="$1" chain="$2" tun="$3" expected="-N $2" spec
  for spec in '-o lo' '-d fe80::/10' '-d ff02::/16' \
    "-s fd42:6376:706e::2/128 -d 2000::/3 -o $tun" \
    "-s fd42:6376:706e::2/128 -d fd42:6376:706e::1/128 -o $tun"; do
    expected+=$'\n'"-A $chain $spec -m comment --comment $tag -j RETURN"
  done
  expected+=$'\n'"-A $chain -m comment --comment $tag -j REJECT --reject-with icmp6-adm-prohibited"
  [[ "$(chain_text 6 "$chain")" == "$expected" ]]
}
safe_prefix_rule() {
  local family="$1" base="$2" line="$3" config="$4" version scope ipv6 tun servers port tag protocol id chain
  IFS=: read -r version scope ipv6 tun servers port <<< "$config"
  # USB administration may publish one IPv4 mDNS alias. Match the entire
  # rule, never trust a comment, wildcard interface or broad multicast range.
  if [[ "$family" == 4 && "$base" == OUTPUT && "$line" == '-A OUTPUT -s 192.168.7.1/32 -d 224.0.0.251/32 -o usb0 -p udp -m udp --sport 5353 --dport 5353 -m comment --comment meshpn-admin-usb-mdns-v1 -j ACCEPT' ]]; then return 0; fi
  local dns_tag=' --comment (clean-vpn-dns-tunnel(-[a-f0-9]{24})?) '
  if [[ "$line" =~ $dns_tag ]]; then
    tag="${BASH_REMATCH[1]}"
    if [[ "$base" == FORWARD && "$version" == cvks4 ]]; then
      for protocol in tcp udp; do
        if [[ "$family" == 4 ]]; then
          for port in 53 1053; do
            local destination=''; [[ "$port" != 1053 ]] || destination='-d 10.99.0.2/32 '
            [[ "$line" != "-A FORWARD -s 192.168.7.0/24 ${destination}-i usb0 -p $protocol -m comment --comment $tag -m $protocol --dport $port -j REJECT --reject-with icmp-port-unreachable" ]] || return 0
          done
        else
          [[ "$line" != "-A FORWARD -i usb0 -p $protocol -m comment --comment $tag -m $protocol --dport 53 -j REJECT --reject-with icmp6-port-unreachable" ]] || return 0
        fi
      done
      return 1
    fi
    [[ "$base" == OUTPUT ]] || return 1
    for protocol in tcp udp; do
      if [[ "$family" == 4 ]]; then
        [[ "$line" != "-A OUTPUT -d 10.99.0.2/32 -p $protocol -m comment --comment $tag -m addrtype ! --dst-type LOCAL -m $protocol --dport 1053 -j REJECT --reject-with icmp-port-unreachable" ]] || return 0
        if [[ "$line" == "-A OUTPUT -p $protocol -m comment --comment $tag -m $protocol --dport 53 -j CVPN-DNS-OUT" ]]; then
          safe_dns_chain "$family" "$tag" "$tun"; return $?
        fi
      else
        [[ "$line" != "-A OUTPUT ! -d ::1/128 -p $protocol -m comment --comment $tag -m $protocol --dport 53 -j REJECT --reject-with icmp6-port-unreachable" ]] || return 0
      fi
    done
  fi
  local v6_jump='^-A OUTPUT -m comment --comment clean-vpn-ipv6-([a-f0-9]{24}) -j (CV6_[a-f0-9]{16})$'
  if [[ "$family" == 6 && "$line" =~ $v6_jump ]]; then
    id="${BASH_REMATCH[1]}"; chain="${BASH_REMATCH[2]}"
    [[ "$chain" == "CV6_${id:0:16}" ]] || return 1
    safe_ipv6_chain "clean-vpn-ipv6-$id" "$chain" "$tun"; return $?
  fi
  return 1
}
audit() {
  local family="$1" line chain base config='' expected actual selected want count first prefix
  SNAP[$family]="${SNAP[$family]//\"/}"
  while IFS= read -r line; do
    if [[ "$line" == '-A CLEANVPN_KS_FWD -m comment --comment cvks2:'* || "$line" == '-A CLEANVPN_KS_FWD -m comment --comment cvks3:'* || "$line" == '-A CLEANVPN_KS_FWD -m comment --comment cvks4:'* ]]; then
      [[ -z "$config" ]] || die 'duplicate ownership marker'
      config="${line#-A CLEANVPN_KS_FWD -m comment --comment }"
    fi
  done <<< "${SNAP[$family]}"
  expected=''; [[ -z "$config" ]] || expected="$(rules "$family" "$config")"
  for chain in "${CHAINS[@]}"; do
    actual='' selected='' count=0 first='' prefix=''
    base=FORWARD; [[ "$chain" != CLEANVPN_KS_OUT ]] || base=OUTPUT
    want="$(hook "$base" "$chain")"
    while IFS= read -r line; do
      if [[ "$line" == "-N $chain" || "$line" == "-A $chain "* ]]; then actual+="$line"$'\n'; fi
      if [[ "$line" == *"-j $chain"* || "$line" == *"-g $chain"* ]]; then
        [[ "$line" == "$want" ]] || die "foreign reference to $chain; no changes"
        count=$((count + 1))
      fi
      if [[ -z "$first" && "$line" == "-A $base "* ]]; then first="$line"; fi
      if [[ "$count" == 0 && "$line" == "-A $base "* ]]; then prefix+="$line"$'\n'; fi
    done <<< "${SNAP[$family]}"
    while IFS= read -r line; do
      if [[ "$line" == "-N $chain" || "$line" == "-A $chain "* ]]; then selected+="$line"$'\n'; fi
    done <<< "$expected"
    [[ "$actual" == "$selected" ]] || die "foreign/legacy/modified $chain (IPv$family); no changes"
    if [[ -n "$selected" ]]; then
      [[ "$count" == 1 ]] || die "missing/duplicate $chain hook (IPv$family); no changes"
      if [[ "$first" != "$want" ]]; then
        [[ "$ACTION" == status || "$ACTION" == audit-snapshot ]] || die "shadowed $chain hook (IPv$family); mutation requires first hook; no changes"
        while IFS= read -r line; do
          [[ -z "$line" ]] || safe_prefix_rule "$family" "$base" "$line" "$config" || die "unverified prefix before $chain hook (IPv$family); no changes"
        done <<< "$prefix"
      fi
    else [[ "$count" == 0 ]] || die "orphan $chain hook"; fi
  done
  OLD[$family]="$config"
}
if [[ "$ACTION" == audit-snapshot ]]; then
  # Offline regression/diagnosis only. No tools, root, locks or network access.
  SNAP[$FAMILY]=''
  while IFS= read -r line || [[ -n "$line" ]]; do
    SNAP[$FAMILY]+="$line"$'\n'
    (( ${#SNAP[$FAMILY]} <= 1048576 )) || die 'snapshot too large'
  done
  [[ "${SNAP[$FAMILY]}" == *'-P OUTPUT '* ]] || die 'missing OUTPUT policy in snapshot'
  audit "$FAMILY"; log "snapshot IPv$FAMILY: ${OLD[$FAMILY]:-absent} (offline only)"; exit 0
fi
[[ "$EUID" == 0 ]] || die 'root required (plan/audit-snapshot need no root)'
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
for family in 4 6; do SNAP[$family]="$("${IPT[$family]}" -w 5 -t filter -S)"; audit "$family"; done
if [[ "$ACTION" == status ]]; then
  for family in 4 6; do log "IPv$family: ${OLD[$family]:-absent}"; done
  exit 0
fi
for family in 4 6; do
  if [[ "$ACTION" == up ]]; then
    if [[ -n "${OLD[$family]}" ]]; then
      IFS=: read -r version old_scope old_ipv6 rest <<< "${OLD[$family]}"
      [[ "$version" != cvks3 || "$USB_DNS" == 1 ]] || die 'live USB DNS protection downgrade refused; no changes'
      [[ "$version" != cvks4 || "$USB_STRICT" == 1 ]] || die 'live strict USB protection downgrade refused; no changes'
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
