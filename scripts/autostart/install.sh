#!/usr/bin/env bash
#
# clean-vpn systemd autostart installer (+ kill-switch).
#
# Ставит/обновляет systemd-сервис, который запускает clean-vpn.js из ЭТОГО репозитория
# (dev/тест) с переданными аргументами. Аргументы зашиваются в генерируемый
# /usr/local/bin/<SERVICE_NAME>-run.sh, поэтому повторный запуск с новыми аргументами
# полностью перезаписывает сервис и делает restart.
#
# Для --role=client дополнительно ставится kill-switch: пока туннель не поднят (или упал),
# трафик мимо tun блокируется. Kill-switch привязан к сервису (стартует ДО clean-vpn,
# снимается при остановке сервиса).
#
# Использование:
#   sudo env "PATH=$PATH" scripts/autostart/install.sh <аргументы clean-vpn>
#
# Пример (client):
#   sudo env "PATH=$PATH" scripts/autostart/install.sh \
#     --role=client --server=154.62.226.216:443 --type=combo-tls --keep-alive=5 \
#     --split-default --tls-client-sni=www.trustpilot.com --tls-public-name=www.trustpilot.com \
#     --boring-tls-clienthello-profile=/root/dev/meshpn/browser-profile.json \
#     --client-lan-subnet=192.168.7.0/24
#
# Опции установщика (через env, чтобы не путать с аргументами clean-vpn):
#   SERVICE_NAME       имя сервиса (default: clean-vpn); влияет и на имя run.sh
#   NODE_BIN           путь к node (default: автодетект)
#   KILLSWITCH         1|0 — ставить kill-switch (default: 1 для client, 0 для exit)
#   KILLSWITCH_PERSIST 1 — kill-switch НЕ привязан к сервису: активен с раннего boot и
#                      держится, даже если сервис остановлен (снимается только uninstall)
#   KS_SCOPE           both|fwd — блокировать и OUTPUT платы, и FORWARD LAN (default both)
#   KS_IPV6            block|leave — резать IPv6-egress (default block; туннель IPv4-only)
#   KS_SERVER_IPS      IP[,IP...] — bypass к серверу(ам), если не удалось извлечь из --server
#
set -euo pipefail

log() { printf '[clean-vpn-autostart] %s\n' "$*"; }
die() { printf '[clean-vpn-autostart] ОШИБКА: %s\n' "$*" >&2; exit 1; }

# --- root ---
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  die "нужен root. Запустите: sudo env \"PATH=\$PATH\" scripts/autostart/install.sh <аргументы clean-vpn>"
fi

# --- пути ---
SERVICE_NAME="${SERVICE_NAME:-clean-vpn}"
if [[ ! "$SERVICE_NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
  die "недопустимое SERVICE_NAME='$SERVICE_NAME' (разрешены [A-Za-z0-9._-])"
fi

SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLEAN_VPN_JS="$REPO_ROOT/scripts/clean-vpn.js"
[[ -f "$CLEAN_VPN_JS" ]] || die "не найден $CLEAN_VPN_JS (запускайте скрипт из клонированного репозитория)"
KS_SRC="$SCRIPT_DIR/killswitch.sh"

RUN_SH="/usr/local/bin/${SERVICE_NAME}-run.sh"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
KS_SH="/usr/local/bin/${SERVICE_NAME}-killswitch.sh"
KS_UNIT_NAME="${SERVICE_NAME}-killswitch.service"
KS_UNIT_PATH="/etc/systemd/system/${KS_UNIT_NAME}"

# --- node ---
NODE_BIN="${NODE_BIN:-}"
if [[ -z "$NODE_BIN" ]]; then
  NODE_BIN="$(command -v node || true)"
fi
if [[ -z "$NODE_BIN" && -n "${SUDO_USER:-}" ]]; then
  # nvm: node часто есть у обычного пользователя, но не в root-PATH.
  NODE_BIN="$(sudo -u "$SUDO_USER" bash -lc 'command -v node' 2>/dev/null || true)"
fi
[[ -n "$NODE_BIN" ]] || die "не найден node. Запустите как 'sudo env \"PATH=\$PATH\" ...' или задайте NODE_BIN=/путь/к/node"
[[ -x "$NODE_BIN" ]] || die "NODE_BIN='$NODE_BIN' не исполняемый"

# --- аргументы clean-vpn ---
if [[ "$#" -eq 0 ]]; then
  die "не переданы аргументы clean-vpn (напр. --role=exit --type=combo-tls ...)"
fi

# Роль и адрес сервера — из аргументов.
ROLE=""
SERVER_RAW=""
for a in "$@"; do
  case "$a" in
    --role=*)   ROLE="${a#*=}" ;;
    --server=*) SERVER_RAW="${a#*=}" ;;
  esac
done
[[ -n "$ROLE" ]] || log "ВНИМАНИЕ: среди аргументов нет --role= — clean-vpn может не стартовать."

# --- kill-switch: параметры ---
# По умолчанию kill-switch только для client; exit сам раздаёт интернет — там он вреден.
if [[ -z "${KILLSWITCH:-}" ]]; then
  if [[ "$ROLE" == "client" ]]; then KILLSWITCH=1; else KILLSWITCH=0; fi
fi
KS_SCOPE="${KS_SCOPE:-both}"
KS_IPV6="${KS_IPV6:-block}"
KILLSWITCH_PERSIST="${KILLSWITCH_PERSIST:-0}"

# IP VPN-сервера для bypass (иначе kill-switch не даст поднять туннель).
KS_SERVER_IPS="${KS_SERVER_IPS:-}"
if [[ "$KILLSWITCH" == "1" && -z "$KS_SERVER_IPS" && -n "$SERVER_RAW" ]]; then
  host="$SERVER_RAW"
  # срезаем :port (для IPv4/hostname; IPv6 в [..] не наш кейс — задайте KS_SERVER_IPS)
  host="${host%:*}"
  host="${host#[}"; host="${host%]}"
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    KS_SERVER_IPS="$host"
  else
    # hostname → резолвим на момент установки (на boot IP может измениться — тогда задайте KS_SERVER_IPS)
    resolved="$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, - || true)"
    if [[ -n "$resolved" ]]; then
      KS_SERVER_IPS="$resolved"
      log "ВНИМАНИЕ: --server=$host — резолвлю в $KS_SERVER_IPS для kill-switch. Если IP сервера меняется, задайте KS_SERVER_IPS."
    else
      log "ВНИМАНИЕ: не удалось извлечь IP сервера из '$SERVER_RAW' — задайте KS_SERVER_IPS=IP для bypass, иначе туннель не поднимется."
    fi
  fi
fi

if [[ "$KILLSWITCH" == "1" ]]; then
  [[ -f "$KS_SRC" ]] || die "не найден $KS_SRC"
  [[ -n "$KS_SERVER_IPS" ]] || log "ВНИМАНИЕ: KS_SERVER_IPS пуст — kill-switch может заблокировать подключение к серверу."
fi

# Безопасно сериализуем аргументы для вставки в run.sh (сохраняет кавычки/пробелы).
ARGS_QUOTED="$(printf '%q ' "$@")"

log "REPO_ROOT   = $REPO_ROOT"
log "NODE_BIN    = $NODE_BIN"
log "SERVICE     = $SERVICE_NAME"
log "run.sh      = $RUN_SH"
log "unit        = $UNIT_PATH"
log "role        = ${ROLE:-—}"
if [[ "$KILLSWITCH" == "1" ]]; then
  log "kill-switch = ON (scope=$KS_SCOPE ipv6=$KS_IPV6 persist=$KILLSWITCH_PERSIST server_ips=${KS_SERVER_IPS:-—})"
else
  log "kill-switch = off"
fi
log "args        = $*"

# --- генерируем run.sh ---
cat > "$RUN_SH" <<EOF
#!/usr/bin/env bash
# Сгенерировано scripts/autostart/install.sh — не редактируйте вручную,
# перезапустите установщик с нужными аргументами.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin"
cd "$REPO_ROOT"
exec "$NODE_BIN" "$CLEAN_VPN_JS" $ARGS_QUOTED
EOF
chmod 0755 "$RUN_SH"

# --- kill-switch: скрипт + unit ---
KS_DEPS=""
if [[ "$KILLSWITCH" == "1" ]]; then
  install -m 0755 "$KS_SRC" "$KS_SH"

  KS_UP_ARGS="up --scope=$KS_SCOPE --ipv6=$KS_IPV6 --tun=tun0"
  [[ -n "$KS_SERVER_IPS" ]] && KS_UP_ARGS="$KS_UP_ARGS --server=$KS_SERVER_IPS"

  if [[ "$KILLSWITCH_PERSIST" == "1" ]]; then
    # Не привязан к сервису: активен с раннего boot, держится всегда.
    cat > "$KS_UNIT_PATH" <<EOF
[Unit]
Description=clean-vpn kill-switch ($SERVICE_NAME, persist)
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
Conflicts=shutdown.target
Before=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$KS_SH $KS_UP_ARGS
ExecStop=$KS_SH down --tun=tun0

[Install]
WantedBy=multi-user.target
EOF
  else
    # tied: стартует ДО clean-vpn (pulled по Requires), снимается при остановке сервиса (PartOf).
    cat > "$KS_UNIT_PATH" <<EOF
[Unit]
Description=clean-vpn kill-switch ($SERVICE_NAME)
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
Conflicts=shutdown.target
Before=shutdown.target
PartOf=$SERVICE_NAME.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$KS_SH $KS_UP_ARGS
ExecStop=$KS_SH down --tun=tun0
EOF
  fi
  chmod 0644 "$KS_UNIT_PATH"
  # Основной сервис требует kill-switch и стартует ПОСЛЕ него (fail-closed).
  KS_DEPS=$'Requires='"$KS_UNIT_NAME"$'\nAfter='"$KS_UNIT_NAME"
else
  # Уберём kill-switch, если он был поставлен ранее для этого SERVICE_NAME.
  if [[ -f "$KS_UNIT_PATH" ]]; then
    systemctl disable --now "$KS_UNIT_NAME" 2>/dev/null || true
    [[ -x "$KS_SH" ]] && "$KS_SH" down --tun=tun0 2>/dev/null || true
    rm -f "$KS_UNIT_PATH" "$KS_SH"
  fi
fi

# --- генерируем основной unit ---
cat > "$UNIT_PATH" <<EOF
[Unit]
Description=clean-vpn ($SERVICE_NAME)
After=network-online.target
Wants=network-online.target
${KS_DEPS}
# Не сдаваться после нескольких быстрых падений (иначе сервис уходит в failed и не стартует).
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=$RUN_SH
Restart=always
RestartSec=2
# clean-vpn ловит SIGTERM и откатывает маршруты/NAT — даём время на cleanup.
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT_PATH"

# --- применяем ---
log "systemctl daemon-reload"
systemctl daemon-reload
log "systemctl enable $SERVICE_NAME"
systemctl enable "$SERVICE_NAME"
if [[ "$KILLSWITCH" == "1" && "$KILLSWITCH_PERSIST" == "1" ]]; then
  systemctl enable "$KS_UNIT_NAME"
fi
# --no-block: не ждём завершения job'а. Иначе restart блокируется, пока systemd в этой
# же транзакции поднимает network-online.target (wait-online может висеть десятки секунд).
log "systemctl restart --no-block $SERVICE_NAME"
systemctl restart --no-block "$SERVICE_NAME"

log "Готово. Сервис запускается в фоне (первый старт может подождать network-online.target)."
if [[ "$KILLSWITCH" == "1" ]]; then
  log "kill-switch активен; проверить правила: $KS_SH status"
fi
log "Проверить/следить:"
log "  systemctl status $SERVICE_NAME"
log "  journalctl -u $SERVICE_NAME -f"
log "  scripts/autostart/uninstall.sh   (SERVICE_NAME=$SERVICE_NAME для снятия)"
