#!/usr/bin/env bash
#
# clean-vpn systemd autostart uninstaller.
#
# Останавливает и удаляет сервис, созданный install.sh.
#
# Использование:
#   sudo scripts/autostart/uninstall.sh
#   sudo SERVICE_NAME=clean-vpn-exit scripts/autostart/uninstall.sh
#
set -euo pipefail

log() { printf '[clean-vpn-autostart] %s\n' "$*"; }
die() { printf '[clean-vpn-autostart] ОШИБКА: %s\n' "$*" >&2; exit 1; }

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  die "нужен root. Запустите: sudo scripts/autostart/uninstall.sh"
fi

SERVICE_NAME="${SERVICE_NAME:-clean-vpn}"
if [[ ! "$SERVICE_NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
  die "недопустимое SERVICE_NAME='$SERVICE_NAME'"
fi

RUN_SH="/usr/local/bin/${SERVICE_NAME}-run.sh"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

log "systemctl disable --now $SERVICE_NAME"
systemctl disable --now "$SERVICE_NAME" 2>/dev/null || log "сервис $SERVICE_NAME не активен/не найден — продолжаю"

if [[ -f "$UNIT_PATH" ]]; then
  rm -f "$UNIT_PATH"
  log "удалён $UNIT_PATH"
else
  log "нет $UNIT_PATH"
fi

if [[ -f "$RUN_SH" ]]; then
  rm -f "$RUN_SH"
  log "удалён $RUN_SH"
else
  log "нет $RUN_SH"
fi

log "systemctl daemon-reload"
systemctl daemon-reload
systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true

log "Готово. Сервис $SERVICE_NAME снят."
