#!/usr/bin/env bash
#
# clean-vpn systemd autostart installer.
#
# Ставит/обновляет systemd-сервис, который запускает clean-vpn.js из ЭТОГО репозитория
# (dev/тест) с переданными аргументами. Аргументы зашиваются в генерируемый
# /usr/local/bin/<SERVICE_NAME>-run.sh, поэтому повторный запуск с новыми аргументами
# полностью перезаписывает сервис и делает restart.
#
# Использование:
#   sudo env "PATH=$PATH" scripts/autostart/install.sh <аргументы clean-vpn>
#
# Всё, что после install.sh — это аргументы clean-vpn.js (as-is), например:
#   sudo env "PATH=$PATH" scripts/autostart/install.sh \
#     --role=exit --server=0.0.0.0:443 --type=combo-tls --keep-alive=5 \
#     --tls-probe-target=www.trustpilot.com:443 --tls-public-name=www.trustpilot.com
#
# Опции установщика (через env, чтобы не путать с аргументами clean-vpn):
#   SERVICE_NAME  имя сервиса (default: clean-vpn); влияет и на имя run.sh
#   NODE_BIN      путь к node (default: автодетект)
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
REPO_ROOT="$(cd "$(dirname "$SCRIPT_PATH")/../.." && pwd)"
CLEAN_VPN_JS="$REPO_ROOT/scripts/clean-vpn.js"
[[ -f "$CLEAN_VPN_JS" ]] || die "не найден $CLEAN_VPN_JS (запускайте скрипт из клонированного репозитория)"

RUN_SH="/usr/local/bin/${SERVICE_NAME}-run.sh"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

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
if ! printf '%s\n' "$@" | grep -q -- '--role='; then
  log "ВНИМАНИЕ: среди аргументов нет --role= — clean-vpn может не стартовать."
fi

# Безопасно сериализуем аргументы для вставки в run.sh (сохраняет кавычки/пробелы).
ARGS_QUOTED="$(printf '%q ' "$@")"

log "REPO_ROOT   = $REPO_ROOT"
log "NODE_BIN    = $NODE_BIN"
log "SERVICE     = $SERVICE_NAME"
log "run.sh      = $RUN_SH"
log "unit        = $UNIT_PATH"
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

# --- генерируем unit ---
cat > "$UNIT_PATH" <<EOF
[Unit]
Description=clean-vpn ($SERVICE_NAME)
After=network-online.target
Wants=network-online.target

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
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || systemctl enable "$SERVICE_NAME"
log "systemctl restart $SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

log "Готово. Полезные команды:"
log "  systemctl status $SERVICE_NAME"
log "  journalctl -u $SERVICE_NAME -f"
log "  scripts/autostart/uninstall.sh   (SERVICE_NAME=$SERVICE_NAME для снятия)"
