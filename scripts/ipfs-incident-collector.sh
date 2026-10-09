#!/usr/bin/env bash
# Read-only live triage for an unexpected Kubo/IPFS installation.
# It writes only to a newly-created output directory and archives under --output.
set -uo pipefail

umask 077

cv_days=45
cv_output_base=/var/tmp
cv_deep=1
cv_local_api=1

cv_usage() {
  cat <<'EOF'
Usage: sudo bash scripts/ipfs-incident-collector.sh [options]

Collect read-only live-triage evidence about the unexpected ipfs-storage and
ipfs-storage-agent services. The script does not stop/start services, execute
the installed IPFS/agent binaries, change configuration, or contact the Internet.

Options:
  --days=N          journal/history window in days (default: 45)
  --output=DIR      parent directory for the result (default: /var/tmp)
  --no-deep         skip SHA-256 hashing of every regular IPFS repository file
  --no-local-api    do not query the read-only API on 127.0.0.1:5001
  -h, --help        show this help

The private archive can contain shell history, service scripts and credentials.
Do not paste or upload it. The report archive is intended for review, but still
contains usernames, addresses, hostnames, command lines and authentication logs.
EOF
}

for cv_arg in "$@"; do
  case "$cv_arg" in
    --days=*) cv_days=${cv_arg#*=} ;;
    --output=*) cv_output_base=${cv_arg#*=} ;;
    --no-deep) cv_deep=0 ;;
    --no-local-api) cv_local_api=0 ;;
    -h|--help) cv_usage; exit 0 ;;
    *) echo "Unknown option: $cv_arg" >&2; cv_usage >&2; exit 2 ;;
  esac
done

case "$cv_days" in
  ''|*[!0-9]*) echo '--days must be an integer from 1 to 3650.' >&2; exit 2 ;;
esac
if [ "$cv_days" -lt 1 ] || [ "$cv_days" -gt 3650 ]; then
  echo '--days must be an integer from 1 to 3650.' >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root (for example with sudo); no collection was performed.' >&2
  exit 1
fi
if [ ! -d "$cv_output_base" ] || [ -L "$cv_output_base" ]; then
  echo "Output parent must be an existing non-symlink directory: $cv_output_base" >&2
  exit 1
fi
for cv_tool in date find mktemp sha256sum stat tar; do
  if ! command -v "$cv_tool" >/dev/null 2>&1; then
    echo "Missing required command: $cv_tool" >&2
    exit 1
  fi
done

cv_started_utc=$(date -u +%Y%m%dT%H%M%SZ)
cv_host=$(hostname 2>/dev/null || echo unknown-host)
cv_safe_host=$(printf '%s' "$cv_host" | tr -c 'A-Za-z0-9._-' '_')
cv_root=$(mktemp -d -p "$cv_output_base" "ipfs-incident-${cv_safe_host}-${cv_started_utc}.XXXXXX") || exit 1
chmod 0700 "$cv_root"
cv_case=$(basename "$cv_root")
cv_report=$cv_root/report
cv_private=$cv_root/private-evidence
cv_raw=$cv_report/raw
cv_meta=$cv_report/path-metadata
cv_redacted=$cv_report/redacted
mkdir -m 0700 -p "$cv_raw" "$cv_meta" "$cv_redacted" "$cv_private/files"
cv_actions=$cv_report/collector-actions.tsv
cv_errors=$cv_report/collector-errors.txt
cv_summary=$cv_report/SUMMARY.txt
: >"$cv_actions"
: >"$cv_errors"
cv_failures=0

cv_progress() {
  printf 'IPFS_COLLECTOR_PROGRESS=%s\n' "$1" >&2
}

cv_note_action() {
  # timestamp, result, logical name, shell-escaped argv
  cv_na_result=$1
  cv_na_name=$2
  shift 2
  {
    printf '%s\t%s\t%s\t' "$(date -u +%FT%TZ)" "$cv_na_result" "$cv_na_name"
    printf '%q ' "$@"
    printf '\n'
  } >>"$cv_actions"
}

cv_capture() {
  cv_c_name=$1
  shift
  cv_c_file=$cv_raw/$cv_c_name.txt
  if [ "$#" -eq 0 ]; then
    printf 'collector error: empty command\n' >"$cv_c_file"
    cv_note_action error "$cv_c_name" '(empty command)'
    cv_failures=$((cv_failures + 1))
    return 1
  fi
  if ! command -v "$1" >/dev/null 2>&1 && [[ "$1" != */* ]]; then
    printf 'unavailable command: %s\n' "$1" >"$cv_c_file"
    cv_note_action unavailable "$cv_c_name" "$@"
    return 0
  fi
  cv_note_action started "$cv_c_name" "$@"
  "$@" >"$cv_c_file" 2>&1
  cv_c_status=$?
  if [ "$cv_c_status" -eq 0 ]; then
    cv_note_action ok "$cv_c_name" "$@"
  else
    printf '%s\texit=%s\n' "$cv_c_name" "$cv_c_status" >>"$cv_errors"
    cv_note_action "exit-$cv_c_status" "$cv_c_name" "$@"
    cv_failures=$((cv_failures + 1))
  fi
  return 0
}

cv_capture_shell() {
  cv_cs_name=$1
  cv_cs_script=$2
  cv_capture "$cv_cs_name" /bin/bash -o pipefail -c "$cv_cs_script"
}

cv_copy_private() {
  cv_cp_source=$1
  if [ ! -e "$cv_cp_source" ] && [ ! -L "$cv_cp_source" ]; then
    return 0
  fi
  cv_cp_rel=${cv_cp_source#/}
  cv_cp_dest=$cv_private/files/$cv_cp_rel
  mkdir -p "$(dirname "$cv_cp_dest")"
  if cp -a --no-dereference -- "$cv_cp_source" "$cv_cp_dest" 2>>"$cv_errors"; then
    cv_note_action ok private-copy cp -a --no-dereference -- "$cv_cp_source" "$cv_cp_dest"
  else
    printf 'private-copy\tpath=%s\n' "$cv_cp_source" >>"$cv_errors"
    cv_note_action failed private-copy cp -a --no-dereference -- "$cv_cp_source" "$cv_cp_dest"
    cv_failures=$((cv_failures + 1))
  fi
}

cv_path_metadata() {
  cv_pm_path=$1
  cv_pm_label=$(printf '%s' "${cv_pm_path#/}" | tr '/ ' '__')
  cv_pm_file=$cv_meta/$cv_pm_label.txt
  {
    printf 'path=%q\n' "$cv_pm_path"
    if [ ! -e "$cv_pm_path" ] && [ ! -L "$cv_pm_path" ]; then
      echo 'status=absent'
      return 0
    fi
    echo '--- lstat ---'
    stat --printf='name=%n\ntype=%F\nmode=%a (%A)\nuid=%u\ngid=%g\nuser=%U\ngroup=%G\nsize=%s\ninode=%i\nlinks=%h\ndevice=%D\nbirth=%w (%W)\nmodify=%y (%Y)\nchange=%z (%Z)\naccess=%x (%X)\n' -- "$cv_pm_path" 2>&1
    if [ -L "$cv_pm_path" ]; then
      printf 'symlink_target=%s\n' "$(readlink -- "$cv_pm_path" 2>&1)"
      echo '--- target stat ---'
      stat -L --printf='name=%n\ntype=%F\nmode=%a (%A)\nuid=%u\ngid=%g\nuser=%U\ngroup=%G\nsize=%s\ninode=%i\nlinks=%h\ndevice=%D\nbirth=%w (%W)\nmodify=%y (%Y)\nchange=%z (%Z)\naccess=%x (%X)\n' -- "$cv_pm_path" 2>&1 || true
    fi
    if [ -f "$cv_pm_path" ] && [ ! -L "$cv_pm_path" ]; then
      echo '--- sha256 ---'
      sha256sum -- "$cv_pm_path" 2>&1 || true
      if command -v file >/dev/null 2>&1; then
        echo '--- file ---'
        file -b -- "$cv_pm_path" 2>&1 || true
      fi
    fi
    if command -v getfacl >/dev/null 2>&1; then
      echo '--- acl ---'
      getfacl -p -- "$cv_pm_path" 2>&1 || true
    fi
    if command -v getfattr >/dev/null 2>&1; then
      echo '--- xattrs ---'
      getfattr -d -m- --absolute-names -- "$cv_pm_path" 2>&1 || true
    fi
  } >"$cv_pm_file"
  cv_note_action ok path-metadata stat/hash "$cv_pm_path"
}

cv_copy_glob_matches() {
  cv_cg_pattern=$1
  while IFS= read -r -d '' cv_cg_path; do
    cv_path_metadata "$cv_cg_path"
    cv_copy_private "$cv_cg_path"
  done < <(find "$(dirname "$cv_cg_pattern")" -maxdepth 1 -name "$(basename "$cv_cg_pattern")" -print0 2>/dev/null)
}

cv_redact() {
  sed -E \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/-]+/\1<REDACTED>/Ig' \
    -e 's/("(pass(word|wd)?|secret|token|api[_-]?key|authorization|credential)"[[:space:]]*:[[:space:]]*")[^"]+/\1<REDACTED>/Ig' \
    -e 's/((pass(word|wd)?|secret|token|api[_-]?key|authorization|credential)[[:space:]]*[:=][[:space:]]*)[^[:space:]"]+/\1<REDACTED>/Ig'
}

cv_make_report_copy_redacted() {
  cv_mr_name=$1
  cv_mr_source=$cv_raw/$cv_mr_name.txt
  [ -f "$cv_mr_source" ] || return 0
  mkdir -p "$cv_private/live-output"
  cp -a -- "$cv_mr_source" "$cv_private/live-output/$cv_mr_name.txt" 2>>"$cv_errors" || true
  cv_mr_temp=$cv_mr_source.redacted
  if cv_redact <"$cv_mr_source" >"$cv_mr_temp"; then
    chmod --reference="$cv_mr_source" "$cv_mr_temp" 2>/dev/null || true
    mv -f -- "$cv_mr_temp" "$cv_mr_source"
  else
    mv -f -- "$cv_mr_temp" "$cv_private/live-output/$cv_mr_name-redaction-failed.txt" 2>/dev/null || true
    printf 'redaction-failed\tfile=%s\n' "$cv_mr_source" >>"$cv_errors"
    cv_failures=$((cv_failures + 1))
  fi
}

printf 'collection_root=%s\nstarted_utc=%s\nhost=%s\ndays=%s\ndeep=%s\nlocal_api=%s\n' \
  "$cv_root" "$cv_started_utc" "$cv_host" "$cv_days" "$cv_deep" "$cv_local_api" \
  >"$cv_report/collector-context.txt"
if [ -r "$0" ]; then
  sha256sum -- "$0" >"$cv_report/collector-script.sha256" 2>/dev/null || true
fi

# Time and host identity. These are needed to correlate journal, file and provider logs.
cv_progress host-and-time
cv_capture date-utc date -u --iso-8601=ns
cv_capture date-local date --iso-8601=ns
cv_capture timedatectl timedatectl show --all
cv_capture hostnamectl hostnamectl
cv_capture uname uname -a
cv_capture uptime uptime
cv_capture boot-id /bin/bash -c 'cat /proc/sys/kernel/random/boot_id'
cv_capture os-release /bin/bash -c 'cat /etc/os-release'
cv_capture mounts findmnt -A -o TARGET,SOURCE,FSTYPE,OPTIONS
cv_capture disk-free df -hT
cv_capture memory free -h
cv_capture swap swapon --show --bytes

# Accounts, sessions and authentication state. Password hashes and private SSH keys are excluded.
cv_progress accounts-and-sessions
cv_capture passwd-database getent passwd
cv_capture group-database getent group
cv_capture uid-zero-accounts awk -F: '$3 == 0 { print }' /etc/passwd
cv_capture interactive-accounts awk -F: '$7 !~ /(nologin|false)$/ { print }' /etc/passwd
cv_capture current-sessions who -a
cv_capture current-users w
cv_capture loginctl-sessions loginctl list-sessions --no-legend
cv_capture loginctl-users loginctl list-users --no-legend
cv_capture last-logins last -Faiwx
cv_capture failed-logins lastb -Faiwx
cv_capture lastlog lastlog
cv_capture ipfs-storage-account getent passwd ipfs-storage
cv_capture ipfs-storage-group getent group ipfs-storage
cv_capture sshd-effective-config sshd -T
cv_path_metadata /etc/passwd
cv_path_metadata /etc/group
cv_path_metadata /etc/shadow
cv_path_metadata /etc/sudoers
cv_copy_private /etc/passwd
cv_copy_private /etc/group
cv_copy_private /etc/sudoers
cv_copy_private /etc/sudoers.d
cv_copy_private /etc/ssh/sshd_config
cv_copy_private /etc/ssh/sshd_config.d
cv_path_metadata /etc/ssh/sshd_config

# Processes, sockets and routing/firewall state.
cv_progress runtime-and-network
cv_capture process-list ps -eo user,group,uid,gid,pid,ppid,lstart,etimes,stat,%cpu,%mem,rss,vsz,args --sort=pid
cv_capture process-tree pstree -alpu
cv_make_report_copy_redacted process-list
cv_make_report_copy_redacted process-tree
cv_capture sockets ss -H -lntup
cv_capture socket-connections ss -H -pantou
cv_capture ip-addresses ip -details address show
cv_capture ip-routes-v4 ip -details -4 route show table all
cv_capture ip-rules-v4 ip -details -4 rule show
cv_capture ip-routes-v6 ip -details -6 route show table all
cv_capture ip-rules-v6 ip -details -6 rule show
cv_capture nft-ruleset nft list ruleset
cv_capture iptables-save iptables-save
cv_capture ip6tables-save ip6tables-save
cv_capture kernel-modules lsmod
cv_capture sysctl-forwarding sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding

# Unit definitions, activation edges and lifecycle records.
cv_progress services-and-journals
cv_capture service-principals systemctl show ipfs-storage.service ipfs-storage-agent.service \
  -p Id -p User -p Group -p MainPID -p ActiveState -p UnitFileState -p FragmentPath -p ExecStart -p WantedBy -p Wants -p Requires
cv_make_report_copy_redacted service-principals
for cv_unit in ipfs-storage.service ipfs-storage-agent.service; do
  cv_unit_label=${cv_unit//./_}
  cv_capture "unit-status-$cv_unit_label" systemctl status "$cv_unit" --no-pager -l
  cv_capture "unit-show-$cv_unit_label" systemctl show "$cv_unit" --all
  cv_capture "unit-cat-$cv_unit_label" systemctl cat "$cv_unit"
  cv_capture "unit-dependencies-$cv_unit_label" systemctl list-dependencies "$cv_unit" --all --no-pager
  cv_capture "unit-reverse-dependencies-$cv_unit_label" systemctl list-dependencies --reverse "$cv_unit" --all --no-pager
  cv_capture "unit-journal-$cv_unit_label" journalctl --utc --no-pager -o short-iso-precise --since "$cv_days days ago" -u "$cv_unit"
  cv_capture "unit-security-$cv_unit_label" systemd-analyze security "$cv_unit" --no-pager
  cv_make_report_copy_redacted "unit-status-$cv_unit_label"
  cv_make_report_copy_redacted "unit-show-$cv_unit_label"
  cv_make_report_copy_redacted "unit-cat-$cv_unit_label"
  cv_make_report_copy_redacted "unit-journal-$cv_unit_label"
done
cv_capture unit-files systemctl list-unit-files --all --no-pager
cv_capture running-units systemctl list-units --type=service --state=running --all --no-pager
cv_capture timers systemctl list-timers --all --no-pager
cv_capture failed-units systemctl --failed --all --no-pager
cv_capture journal-boots journalctl --list-boots --no-pager
cv_capture journal-disk-usage journalctl --disk-usage
cv_capture journal-verify journalctl --verify

cv_suspect_paths=(
  /etc/systemd/system/ipfs-storage.service
  /etc/systemd/system/ipfs-storage-agent.service
  /etc/systemd/system/multi-user.target.wants/ipfs-storage-agent.service
  /etc/systemd/system/multi-user.target.wants/ipfs-storage.service
  /usr/local/bin/ipfs
  /usr/local/bin/ipfs-storage-agent
  /var/lib/ipfs-storage
)
for cv_path in "${cv_suspect_paths[@]}"; do
  cv_path_metadata "$cv_path"
done
for cv_path in \
  /etc/systemd/system/ipfs-storage.service \
  /etc/systemd/system/ipfs-storage-agent.service \
  /etc/systemd/system/multi-user.target.wants/ipfs-storage-agent.service \
  /etc/systemd/system/multi-user.target.wants/ipfs-storage.service \
  /usr/local/bin/ipfs \
  /usr/local/bin/ipfs-storage-agent; do
  cv_copy_private "$cv_path"
done

# Package ownership and binary structure without executing untrusted files.
cv_capture package-owner-ipfs dpkg-query -S /usr/local/bin/ipfs
cv_capture package-owner-agent dpkg-query -S /usr/local/bin/ipfs-storage-agent
cv_capture installed-packages dpkg-query -W '-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'
cv_capture apt-history /bin/bash -c 'zcat -f /var/log/apt/history.log* 2>/dev/null'
cv_capture dpkg-history /bin/bash -c 'zcat -f /var/log/dpkg.log* 2>/dev/null'
if [ -f /usr/local/bin/ipfs ]; then
  cv_capture ipfs-elf-header readelf -h -n /usr/local/bin/ipfs
  cv_capture ipfs-strings strings -a -n 10 /usr/local/bin/ipfs
  cv_capture ipfs-go-build-info go version -m /usr/local/bin/ipfs
fi
if [ -f /usr/local/bin/ipfs-storage-agent ]; then
  cv_redact </usr/local/bin/ipfs-storage-agent >"$cv_redacted/ipfs-storage-agent.txt" 2>/dev/null || true
fi

# Runtime provenance for the two services. No signal is sent and no process is started.
for cv_unit in ipfs-storage.service ipfs-storage-agent.service; do
  cv_unit_label=${cv_unit//./_}
  cv_pid=$(systemctl show "$cv_unit" -p MainPID --value 2>/dev/null || true)
  case "$cv_pid" in
    ''|*[!0-9]*|0|1) continue ;;
  esac
  if [ ! -d "/proc/$cv_pid" ]; then continue; fi
  cv_capture "proc-$cv_unit_label-status" /bin/bash -c "cat /proc/$cv_pid/status"
  cv_capture "proc-$cv_unit_label-cgroup" /bin/bash -c "cat /proc/$cv_pid/cgroup"
  cv_capture "proc-$cv_unit_label-limits" /bin/bash -c "cat /proc/$cv_pid/limits"
  cv_capture "proc-$cv_unit_label-cmdline" /bin/bash -c "tr '\\0' ' ' </proc/$cv_pid/cmdline; echo"
  cv_capture "proc-$cv_unit_label-links" /bin/bash -c "ls -la /proc/$cv_pid/cwd /proc/$cv_pid/root /proc/$cv_pid/exe /proc/$cv_pid/ns/* /proc/$cv_pid/fd 2>&1"
  cv_capture "proc-$cv_unit_label-maps" /bin/bash -c "cat /proc/$cv_pid/maps"
  cv_capture "proc-$cv_unit_label-exe-hash" sha256sum "/proc/$cv_pid/exe"
  cv_make_report_copy_redacted "proc-$cv_unit_label-cmdline"
  if [ -r "/proc/$cv_pid/environ" ]; then
    mkdir -p "$cv_private/proc/$cv_pid"
    cp -a -- "/proc/$cv_pid/environ" "$cv_private/proc/$cv_pid/environ" 2>>"$cv_errors" || true
    tr '\0' '\n' <"/proc/$cv_pid/environ" | cv_redact >"$cv_redacted/proc-$cv_unit_label-environ.txt" || true
  fi
done

# Authentication events and likely installation activity.
cv_progress authentication-and-installation-logs
cv_capture ssh-journal journalctl --utc --no-pager -o short-iso-precise --since "$cv_days days ago" _COMM=sshd
cv_capture ssh-unit-journal journalctl --utc --no-pager -o short-iso-precise --since "$cv_days days ago" -u ssh.service -u sshd.service
cv_capture sudo-journal journalctl --utc --no-pager -o short-iso-precise --since "$cv_days days ago" SYSLOG_IDENTIFIER=sudo
cv_capture login-journal journalctl --utc --no-pager -o short-iso-precise --since "$cv_days days ago" -u systemd-logind.service
cv_capture account-change-journal journalctl --utc --no-pager -o short-iso-precise --since "$cv_days days ago" SYSLOG_IDENTIFIER=useradd SYSLOG_IDENTIFIER=usermod SYSLOG_IDENTIFIER=userdel SYSLOG_IDENTIFIER=groupadd SYSLOG_IDENTIFIER=groupmod SYSLOG_IDENTIFIER=passwd
cv_capture ipfs-all-journal-matches journalctl --utc --no-pager -o short-iso-precise --since "$cv_days days ago" --case-sensitive=no --grep 'ipfs|ipfshost|ipfs-storage'
cv_capture daemon-reload-journal journalctl --utc --no-pager -o short-iso-precise --since "$cv_days days ago" --case-sensitive=no --grep 'daemon-reload|Created symlink|enabled.*service|systemctl enable'
cv_capture auth-log-text /bin/bash -c 'zcat -f /var/log/auth.log* /var/log/secure* 2>/dev/null'
cv_capture log-ipfs-matches /bin/bash -o pipefail -c "zgrep -hEin 'ipfs|ipfshost|ipfs-storage|/usr/local/bin/ipfs' /var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages* /var/log/cloud-init*.log* /var/log/apt/history.log* /var/log/dpkg.log* 2>/dev/null"
for cv_sensitive_capture in \
  ssh-journal ssh-unit-journal sudo-journal login-journal account-change-journal \
  ipfs-all-journal-matches daemon-reload-journal auth-log-text log-ipfs-matches; do
  cv_make_report_copy_redacted "$cv_sensitive_capture"
done

for cv_log_pattern in \
  '/var/log/auth.log*' '/var/log/secure*' '/var/log/syslog*' '/var/log/messages*' \
  '/var/log/audit/audit.log*' '/var/log/fail2ban.log*' '/var/log/cloud-init.log*' \
  '/var/log/cloud-init-output.log*' '/var/log/apt/history.log*' '/var/log/dpkg.log*' \
  '/var/log/wtmp*' '/var/log/btmp*' '/var/log/lastlog' '/var/log/faillog'; do
  cv_copy_glob_matches "$cv_log_pattern"
done

# Persistence and recent filesystem changes. The listing is metadata-only.
cv_progress persistence-and-recent-files
cv_capture recent-system-files find /etc /usr/local /root /home /var/spool/cron /var/spool/at /tmp /var/tmp /dev/shm \
  -xdev -path "$cv_root" -prune -o -newermt "$cv_days days ago" \
  -printf '%T@\t%C@\t%B@\t%u\t%g\t%m\t%s\t%y\t%p -> %l\n'
cv_capture systemd-persistence find /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system \
  -xdev -printf '%T@\t%C@\t%B@\t%u\t%g\t%m\t%s\t%y\t%p -> %l\n'
cv_capture cron-system find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron \
  -xdev -printf '%T@\t%C@\t%B@\t%u\t%g\t%m\t%s\t%y\t%p -> %l\n'
cv_capture at-queue atq
cv_capture user-crontabs /bin/bash -c 'while IFS=: read -r user _; do echo "===== $user ====="; crontab -u "$user" -l 2>&1 || true; done </etc/passwd'
cv_make_report_copy_redacted user-crontabs
cv_capture persistence-file-contents /bin/bash -c 'grep -RIn --exclude-dir=.git "" /etc/cron.d /var/spool/cron /etc/rc.local 2>/dev/null'
cv_make_report_copy_redacted persistence-file-contents
cv_copy_private /etc/cron.d
cv_copy_private /var/spool/cron
cv_copy_private /etc/rc.local

# Authorized public keys and shell histories for every local home. Histories remain private.
: >"$cv_report/authorized-key-fingerprints.txt"
while IFS=: read -r cv_user _ cv_uid _ _ cv_home cv_shell; do
  [ -n "$cv_home" ] || continue
  if [ -f "$cv_home/.ssh/authorized_keys" ]; then
    cv_path_metadata "$cv_home/.ssh/authorized_keys"
    cv_copy_private "$cv_home/.ssh/authorized_keys"
    {
      printf 'user=%s uid=%s home=%s shell=%s\n' "$cv_user" "$cv_uid" "$cv_home" "$cv_shell"
      if command -v ssh-keygen >/dev/null 2>&1; then
        ssh-keygen -lf "$cv_home/.ssh/authorized_keys" 2>&1 || true
      else
        sha256sum "$cv_home/.ssh/authorized_keys" 2>&1 || true
      fi
    } >>"$cv_report/authorized-key-fingerprints.txt"
  fi
  for cv_history in .bash_history .zsh_history .local/share/fish/fish_history; do
    cv_history_path=$cv_home/$cv_history
    if [ -f "$cv_history_path" ]; then
      cv_path_metadata "$cv_history_path"
      cv_copy_private "$cv_history_path"
      grep -Ein -B1 -A1 'ipfs|ipfshost|curl|wget|systemctl|useradd|usermod|passwd|chmod|chown|/usr/local/bin|authorized_keys' \
        "$cv_history_path" 2>/dev/null | cv_redact \
        >>"$cv_redacted/suspicious-history-matches.txt" || true
    fi
  done
done </etc/passwd

# IPFS repository inventory. Config is redacted; private identity material is never copied.
cv_progress ipfs-repository
cv_repo=/var/lib/ipfs-storage
if [ -d "$cv_repo" ] && [ ! -L "$cv_repo" ]; then
  cv_capture ipfs-repo-size du -a -x --block-size=1 "$cv_repo"
  cv_capture ipfs-repo-files find "$cv_repo" -xdev -printf '%T@\t%C@\t%B@\t%u\t%g\t%m\t%s\t%y\t%p -> %l\n'
  if [ -f "$cv_repo/config" ]; then
    cv_path_metadata "$cv_repo/config"
    if command -v jq >/dev/null 2>&1; then
      jq 'walk(if type == "object" then with_entries(if (.key | test("priv|secret|token|password|authorization|credential|key"; "i")) then .value = "<REDACTED>" else . end) else . end)' \
        "$cv_repo/config" >"$cv_redacted/ipfs-config.json" 2>>"$cv_errors" || true
    else
      cv_redact <"$cv_repo/config" >"$cv_redacted/ipfs-config.txt" 2>/dev/null || true
    fi
  fi
  for cv_repo_file in version datastore_spec; do
    cv_path_metadata "$cv_repo/$cv_repo_file"
    cv_copy_private "$cv_repo/$cv_repo_file"
  done
  cv_path_metadata "$cv_repo/keystore"
  cv_path_metadata "$cv_repo/blocks"
  cv_path_metadata "$cv_repo/datastore"
  if [ "$cv_deep" -eq 1 ]; then
    cv_capture_shell ipfs-repo-sha256 "find '$cv_repo' -xdev -type f -print0 | sort -z | xargs -0 -r sha256sum --"
  else
    printf 'Skipped by --no-deep.\n' >"$cv_raw/ipfs-repo-sha256.txt"
  fi
fi

# Optional read-only localhost queries. Responses come from the suspect daemon and are not
# independently authoritative; they are useful for comparing live pins with the raw repository.
if [ "$cv_local_api" -eq 1 ] && command -v curl >/dev/null 2>&1; then
  cv_capture ipfs-api-id curl --noproxy '*' --silent --show-error --fail-with-body --max-time 15 -X POST http://127.0.0.1:5001/api/v0/id
  cv_capture ipfs-api-repo-stat curl --noproxy '*' --silent --show-error --fail-with-body --max-time 30 -X POST 'http://127.0.0.1:5001/api/v0/repo/stat?human=true'
  cv_capture ipfs-api-pins curl --noproxy '*' --silent --show-error --fail-with-body --max-time 30 -X POST 'http://127.0.0.1:5001/api/v0/pin/ls?type=all'
  cv_capture ipfs-api-local-refs curl --noproxy '*' --silent --show-error --fail-with-body --max-time 60 -X POST http://127.0.0.1:5001/api/v0/refs/local
  cv_capture ipfs-api-mfs-root curl --noproxy '*' --silent --show-error --fail-with-body --max-time 30 -X POST 'http://127.0.0.1:5001/api/v0/files/ls?long=true'
  cv_capture ipfs-api-swarm-peers curl --noproxy '*' --silent --show-error --fail-with-body --max-time 30 -X POST 'http://127.0.0.1:5001/api/v0/swarm/peers?verbose=true'
else
  printf 'Skipped (--no-local-api or curl unavailable).\n' >"$cv_raw/ipfs-api-pins.txt"
fi

# Extract a review-friendly authentication/IP summary from the collected, immutable text copies.
{
  echo 'Accepted SSH logins (raw matching lines):'
  grep -hEi 'Accepted (password|publickey|keyboard-interactive|hostbased).* from ' \
    "$cv_raw/ssh-journal.txt" "$cv_raw/ssh-unit-journal.txt" "$cv_raw/auth-log-text.txt" 2>/dev/null | sort -u || true
  echo
  echo 'Accepted SSH source IP counts:'
  grep -hEi 'Accepted (password|publickey|keyboard-interactive|hostbased).* from ' \
    "$cv_raw/ssh-journal.txt" "$cv_raw/ssh-unit-journal.txt" "$cv_raw/auth-log-text.txt" 2>/dev/null \
    | sed -E 's/.* from ([^ ]+) port .*/\1/' | sort | uniq -c | sort -nr || true
  echo
  echo 'Failed/invalid SSH source IP counts:'
  grep -hEi 'Failed (password|publickey)|Invalid user|authentication failure' \
    "$cv_raw/ssh-journal.txt" "$cv_raw/ssh-unit-journal.txt" "$cv_raw/auth-log-text.txt" 2>/dev/null \
    | sed -nE 's/.* from ([^ ]+) port .*/\1/p; s/.*rhost=([^ ]+).*/\1/p' \
    | sort | uniq -c | sort -nr || true
} >"$cv_report/ssh-ip-summary.txt"

cv_finished_utc=$(date -u +%Y%m%dT%H%M%SZ)
{
  echo 'IPFS INCIDENT LIVE-TRIAGE SUMMARY'
  echo "host: $cv_host"
  echo "collection started UTC: $cv_started_utc"
  echo "collection finished UTC: $cv_finished_utc"
  echo "journal window: $cv_days days"
  echo "collector command failures/unavailable live state: $cv_failures (see collector-errors.txt)"
  echo
  echo 'Important interpretation limits:'
  echo '- This is live triage, not a forensic disk image or RAM capture.'
  echo '- Reading a live host changes some state; the host may keep changing during collection.'
  echo '- Birth/change times, logs and history can suggest installation time/user, but cannot prove attribution when records are absent, rotated or altered.'
  echo '- Local IPFS API output is supplied by the suspect daemon and must be compared with filesystem evidence.'
  echo '- Provider console, provider firewall/flow logs and provider account audit logs are outside this host and are not collected.'
  echo '- No installed IPFS or agent executable was run by this collector; no external network request was made.'
  echo
  echo 'High-value files:'
  echo '- raw/unit-show-*.txt and raw/unit-journal-*.txt: service identity and lifecycle'
  echo '- path-metadata/*ipfs*: timestamps, ownership and hashes'
  echo '- ssh-ip-summary.txt and raw/ssh-*.txt: login IP evidence still retained locally'
  echo '- redacted/suspicious-history-matches.txt: possible installation commands'
  echo '- raw/recent-system-files.txt: files changed in the investigation window'
  echo '- raw/ipfs-repo-files.txt and raw/ipfs-repo-sha256.txt: all repository objects visible on disk'
  echo '- private-evidence archive: exact scripts, units, histories and logs; NEVER share casually'
} >"$cv_summary"

# Hash each collection before archiving. The private manifest contains no source file content.
cv_progress manifests-and-archives
(
  cd "$cv_report" || exit 1
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 -r sha256sum -- >SHA256SUMS
)
(
  cd "$cv_private" || exit 1
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 -r sha256sum -- >SHA256SUMS
)

cv_report_archive=$cv_output_base/$cv_case-report.tar.gz
cv_private_archive=$cv_output_base/$cv_case-PRIVATE.tar.gz
cv_archive_error=0
tar -C "$cv_root" -czf "$cv_report_archive" report || cv_archive_error=1
tar -C "$cv_root" -czf "$cv_private_archive" private-evidence || cv_archive_error=1
if [ "$cv_archive_error" -ne 0 ]; then
  echo "Archive creation failed; unarchived evidence remains at $cv_root" >&2
  exit 1
fi
chmod 0600 "$cv_report_archive" "$cv_private_archive"
sha256sum -- "$cv_report_archive" "$cv_private_archive" >"$cv_root/ARCHIVE-SHA256SUMS"
chmod 0600 "$cv_root/ARCHIVE-SHA256SUMS"

echo '=== IPFS INCIDENT COLLECTION BEGIN ==='
cat "$cv_summary"
echo
echo "FULL_DIRECTORY=$cv_root"
echo "REPORT_ARCHIVE=$cv_report_archive"
echo "PRIVATE_ARCHIVE=$cv_private_archive"
echo "ARCHIVE_HASHES=$cv_root/ARCHIVE-SHA256SUMS"
cat "$cv_root/ARCHIVE-SHA256SUMS"
echo 'PRIVATE_ARCHIVE contains potentially sensitive evidence; do not send it.'
echo 'Send SUMMARY.txt, ssh-ip-summary.txt and the report archive for analysis.'
echo '=== IPFS INCIDENT COLLECTION END ==='
