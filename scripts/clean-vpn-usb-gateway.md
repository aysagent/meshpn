# Постоянный USB-режим в общем установщике

Профиль пока намеренно узкий: `clean-vpn`, native TLS/H2,
`154.62.226.216:443`, `--split-default --ipv6=auto`, persistent both/block
kill-switch с networkd gate, SSH 22, USB `192.168.7.1/24` с MAC
`02:00:00:00:00:02`, TUN `10.99.0.2`. Установка не создаёт gadget,
не настраивает DHCP для Mac и не включает `ip_forward`: на этой Radxa
это уже настроено. Forwarding должен быть включён и после загрузки.
Не применять как универсальный установщик на неподготовленной плате.

## Уже установленный VPN (текущая Radxa)

Держать USB SSH открытым. Проверка без записи:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-usb-gateway.mjs
```

Применение через **общий установщик**, без повторной установки VPN:

```bash
sudo env "PATH=$PATH" bash scripts/autostart/install.sh --usb-gateway
```

Это не обходит запрет перезаписи основной установки: особый режим только
добавляет rescue и постоянный SNAT к проверенному установленному профилю.
Не передавать вместе с `--usb-gateway` аргументы VPN. Основной процесс,
Wi-Fi/networkd, guard, gadget и существующий SSH не перезапускаются.
Уже установленные rescue-файлы принимаются только при точном совпадении
и безопасном владельце/правах, без переопределений systemd.

## Новая установка

К прежней команде установки добавить `USB_GATEWAY=1`:

```bash
sudo env "PATH=$PATH" SERVICE_NAME=clean-vpn \
  USB_GATEWAY=1 KILLSWITCH=1 KILLSWITCH_PERSIST=1 NETWORKD_GUARD=1 \
  KS_SCOPE=both KS_IPV6=block KS_SSH_PORT=22 KS_SERVER_IPS=154.62.226.216 \
  bash scripts/autostart/install.sh \
  --role=client --server=154.62.226.216:443 --type=tls \
  --split-default --ipv6=auto \
  --tls-client-sni=www.trustpilot.com --tls-public-name=www.trustpilot.com
```

Установщик сначала устанавливает/запускает rescue, затем публикует основную
установку и включает SNAT. Rescue не зависит от успешного запуска VPN/guard.
Открытый socket **не подтверждает успешную аутентификацию**: до перезагрузки
нужно проверить с Mac `ssh -p 2222 root@192.168.7.1`.
Существующая политика sshd и firewall не ослабляются.

## Что сохраняется

- Rescue: прежние socket/address/template units и helper, автозапуск на 2222.
- SNAT: `/usr/local/bin/clean-vpn-usb-snat.mjs` и
  `/etc/systemd/system/clean-vpn-usb-snat.service`, enabled.
- Служба SNAT проверяет guard, адреса, маршруты и существующий firewall.
  Если VPN/USB ещё не готов, повторяет попытку через 5 секунд. После успеха
  остаётся `active (exited)`, без постоянного polling и без перезапуска VPN.
- Правило SNAT остаётся при штатном stop/start VPN и повторно устанавливается
  службой после загрузки. Выход разрешается только через `tun0`;
  persistent kill-switch остаётся ответственным за блокировку прямого выхода.
- Это не watchdog произвольных изменений firewall: после чужого flush
  успешная oneshot-служба сама правило не восстановит. Параллельные
  администраторы firewall/установщики не поддерживаются.

Проверка:

```bash
systemctl --no-pager show clean-vpn-usb-snat.service \
  clean-vpn-usb-rescue.socket --property=Id,ActiveState,SubState,Result,NRestarts
sudo /usr/local/bin/clean-vpn-killswitch.sh status
```

С Mac — rescue SSH и `curl -q -4 --noproxy '*' --interface en9 https://ifconfig.me/ip`.
Успех HTTPS не доказывает защиту всех DNS/IPv6 потоков Mac. Его другие
интерфейсы и VPN не управляются этой установкой.

## Удаление и частичная установка

Только постоянный SNAT, с сохранением VPN и rescue:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-usb-gateway.mjs --remove --apply
```

Общий `scripts/autostart/uninstall.sh` также проверяет и удаляет SNAT
после штатного stop VPN и аудита журналов, **до** снятия kill-switch.
Если удаление SNAT не удалось, guard сохраняется. **Rescue намеренно остаётся**:
автоматическое удаление последнего канала доступа не является частью uninstall.
Старый runtime-only helper с `--remove` при включённой службе не является
удалением постоянной установки — использовать команду выше.

Изменённые/частичные файлы и чужие units отклоняются, а не перезаписываются.
Сбой публикации оставляет файлы для проверки; автоматического rollback нет.
Во fresh-режиме `--prepare` может оставить rescue и ещё не включённый SNAT,
если последующая установка VPN отказала. Сеть/guard автоматически не откатываются.

## Проверки и границы

`test-usb-gateway.mjs` проверяет план, повторное применение, владельцев,
чужие файлы/drop-ins/NAT, частичную установку и удаление только собственных
объектов. `test-autostart-stop-contract.mjs` проверяет порядок cleanup относительно
остановки VPN, блокировок журналов и снятия guard.

`clean-vpn-usb-rescue-lab.mjs BASE TOOLS --gateway` запускает два отдельных
NIC-less QEMU boot: реальный systemd, iptables и аутентифицированный rescue SSH,
отложенная готовность TUN, повторы SNAT, идемпотентная установка и cleanup.
Второй boot получает заранее опубликованные файлы и enable-ссылки (не тот же
диск). Состояние VPN задаётся fixture, это не проверка реального TLS или
физического USB, не полный shell-install на новой ОС. Реальную перезагрузку
Radxa с этим расширением нужно подтвердить отдельно.

Результат разработки: 216/216 регрессионных тестов, два VM boot — 26 и 24
проверки, PASS. Отчёт `/var/tmp/meshpn-usb-gateway-lab-N1543s/report.json`;
хеши всех включённых исходников совпадают. Проверены реальные логины SSH
при ожидающем SNAT, работа после отложенной готовности TUN, отсутствие
дубликатов и сохранение guard/rescue при cleanup. Два предварительных
неуспешных прогона сохранены: исправлены отсутствующий стандартный каталог
для публикации helper (теперь `/usr/local/bin`) и раскладка `ip` в VM
(`/usr/sbin/ip`, как на Radxa).
