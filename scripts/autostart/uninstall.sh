#!/usr/bin/env bash
#
# clean-vpn systemd autostart uninstaller (+ kill-switch).
#
# Останавливает и удаляет сервис и kill-switch, созданные install.sh.
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
KS_SH="/usr/local/bin/${SERVICE_NAME}-killswitch.sh"
KS_UNIT_NAME="${SERVICE_NAME}-killswitch.service"
KS_UNIT_PATH="/etc/systemd/system/${KS_UNIT_NAME}"

if [[ -f "$UNIT_PATH" ]]; then
  log "systemctl stop $SERVICE_NAME"
  systemctl stop "$SERVICE_NAME" || die 'VPN stop failed; installed files retained for recovery'
fi

# kill-switch
if [[ -f "$KS_UNIT_PATH" ]]; then
  log "systemctl stop $KS_UNIT_NAME"
  systemctl stop "$KS_UNIT_NAME" || die 'guard stop failed; installed files retained for recovery'
fi
# На всякий случай снимаем правила напрямую (если unit уже удалён/не сработал ExecStop).
if [[ -x "$KS_SH" ]]; then
  "$KS_SH" down --tun=tun0 || die 'guard removal refused; installed files retained for recovery'
fi

# Disable/remove only after successful stop and audited guard removal. A failed
# ownership check must not delete the recovery tool or claim success.
if [[ -f "$UNIT_PATH" ]]; then systemctl disable "$SERVICE_NAME"; fi
if [[ -f "$KS_UNIT_PATH" ]]; then systemctl disable "$KS_UNIT_NAME"; fi

for f in "$UNIT_PATH" "$KS_UNIT_PATH" "$RUN_SH" "$KS_SH"; do
  if [[ -f "$f" ]]; then
    rm -f "$f"
    log "удалён $f"
  fi
done

log "systemctl daemon-reload"
systemctl daemon-reload
systemctl reset-failed "$SERVICE_NAME" "$KS_UNIT_NAME" 2>/dev/null || true

log "Готово. Сервис $SERVICE_NAME и kill-switch сняты."
