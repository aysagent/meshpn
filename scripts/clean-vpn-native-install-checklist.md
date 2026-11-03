# Проверка install/uninstall для агента

Пользовательский путь: [короткая установка](clean-vpn-native-new-pair.md).
Этот список не является обязательным набором ручных шагов пользователя.

## Перед установкой

- Проверить роль, интерфейсы и свободный TCP 443 exit; не останавливать чужой сервис.
- Сохранить `sysctl -n net.ipv4.ip_forward`, `iptables-save`, список активных
  служб. На клиенте проверить системный Wi-Fi (`wpa_cli -i wlan0 ping` → PONG),
  наличие одного UDC и известный/отсутствующий gadget-script.
- `bash install.sh --role=... --plan` не должен менять систему.
- Не использовать команды нового installer поверх физической пары,
  установленной прежним низкоуровневым инструментом: автоматической миграции нет.

## После установки

1. `bash install.sh --check --role=exit`: owner active, engine listening.
   На клиенте после подключения Wi-Fi: owner active, engine ready.
2. `sysctl -n net.ipv4.ip_forward` → 1. TUN: `ip -d address show cvexit0`
   на exit, `ip -d address show tun0` на клиенте. У TUN есть owner alias.
3. `systemctl is-enabled native-exit-network.service` / `native-client-network.service`
   → enabled. Сам engine запускается сетевым owner, отдельно enable не нужен.
4. С USB-устройства получить DHCP-адрес `192.168.7.10–50`, router/DNS `192.168.7.1`.
   Открыть `http://mpn.local/` и `http://192.168.7.1/`, сменить пароль admin.
   Проверить настройку Wi-Fi, VPN/guard on/off и отображение текущего транспорта.
5. С USB проверить DNS, HTTPS, загрузку **и отдачу**. Проверка только с самой
   платы не подтверждает USB forwarding/transparent. Внешний IP должен совпасть
   с exit. IPv6 не должен обходить guard. В combo сверить обе ветки по observer.
6. Проверить `journalctl -u native-client.service -u native-client-network.service
   -u meshpn-admin-broker.service --since '-5 min' --no-pager` без вывода секретов.
7. Повторить install с теми же аргументами: unchanged, без смены ключей,
   сертификатов, replay и пароля админки.
8. Только на одноразовой машине: uninstall дважды, сверка исходного forwarding
   и чужих firewall rules; повторный install с тем же bundle, прежние ключи/пароль.
9. Физическая проверка отдельным этапом: штатный reboot и холодное включение,
   DHCP с подключённым iPhone, затем ready/DNS/HTTPS. Не выдавать veth за USB-тест.

## Порядок служб

- Guard: `DefaultDependencies=no`, перед `network-pre.target`;
  networkd service/socket требуют guard. Остановка guard-service сама правила
  не снимает; явное отключение выполняет broker либо uninstall.
- `dnsmasq.service` должен быть активен **до** `usb-gadget.service`/UDC bind.
  Gadget использует `ip address replace`, никогда `ip addr flush usb0`.
- Native network owner создаёт принадлежащий ему TUN, DNS/маршруты/REDIRECT,
  затем запускает engine. `BindsTo` и независимый `ExecStopPost` обеспечивают cleanup.
- Админка: broker + USB socket/captive. Socket включён через multi-user,
  зависит от USB device; его нельзя переносить в ранний sockets.target.
- Clock recovery не запускается при каждом boot: только коды 75/76/77,
  проверенный SSH endpoint, одна попытка за boot, без отключения TLS validation.

## Лаборатория и ограничения

`test-native-setup-systemd.mjs` запускается только с `CVPN_DISPOSABLE_SETUP=1`
в отдельном Podman/systemd-клиенте. Его USB fixture — veth с отдельным namespace
телефона; два явных обхода касаются только физического USB preflight и отсутствия
udev device-unit в контейнере. В production CLI таких флагов нет.
Проверяются реальный TLS client/exit, SSH time probe, DHCP-before-gadget,
HTTP админки через veth, Avahi, install/uninstall/reinstall и неизменность ключей.
`test-native-setup-dhcp.mjs` выполняет OFFER/ACK из namespace телефона;
`test-native-setup-clock-systemd.mjs` проверяет настоящий systemd sandbox,
условие ошибки времени и лимит попыток. У тестовой clock-службы намеренно
отсутствует `CAP_SYS_TIME`, поэтому менять часы ядра она не может.
Python в проверочных контейнерах отключён. Часы ядра в Podman не меняются.

Дополнительно: `test-native-setup.mjs`, `test-native-clock-node.mjs`,
`test-native-host-install.mjs`, `test-native-install-clock.mjs`,
`test-native-usb-preflight.mjs`; сетевые регрессии
`test-native-host-network-linux.mjs` / `test-native-exit-host-linux.mjs`
запускать только в отдельных disposable network+mount namespaces.

Это не проверка физического UDC другой платы, power-loss или установки
на произвольный дистрибутив. NetworkManager/OpenWrt и миграция чужих служб
не входят в этот host installer. Для контейнеров остаётся отдельный Compose.
