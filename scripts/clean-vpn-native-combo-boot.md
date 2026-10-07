# Native combo: fresh installer, systemd и reboot

Проверено 2026-10-07: **23/23** gates на двух загрузках VM, **416/416**
native/routes regression, CTest normal и ASAN/UBSAN **6/6** в каждой сборке,
combo/installer/transparent integration с ASAN/UBSAN **16/16**.
Точные hashes и boot IDs: [отчёт лаборатории](fixtures/clean-vpn-native-combo-boot-report.json).
Это завершённая лабораторная точка fresh install/lifecycle, не физическая или
полная product-wide приёмка. Скорость в эмуляторе здесь не измеряется.

Installer принимает `combo-tls` client/exit только с `--site-profile`. Внешние
произвольные `--network-unit`/`--guard-unit` вместо связанного профиля не подходят.
Проверяются обе вложенные конфигурации: общий endpoint/порт, роли, TUN, DNS/peer
address, transparent listener и public-HTTPS policy. Ключ transparent должен
отличаться по байтам от каждого boring peer key; это проверяет C++ engine.

## Установленный bundle

- В `/opt/clean-vpn-native/NAME` копируются native executable, PKI boring-ветки,
  отдельный `relay.psk` и отдельные boring peer PSK. Переписываются пути **внутри
  обеих вложенных конфигураций**, включая multi-peer exit. Config/keys — `0600`.
- Для exit создаётся приватный replay-каталог `0700` и однократно вызывается
  native `--init-transparent-replay` до публикации units. Существующий source
  replay state не принимается. В runtime нет автоматической инициализации/reset.
- Client получает пять units: network guard, uplink gate, route coordinator,
  прямой C++ engine и activation target. Exit — четыре, без route coordinator.
- Engine запускается systemd напрямую с `Type=notify`, без shell/Node bridge.
  Combo имеет доступ к `/dev/net/tun` и необходимые network capabilities;
  только exit имеет `ReadWritePaths` для replay. Остальной bundle read-only.
- Guard/gate/route dependencies остаются обязательными. `Restart=on-failure`
  перезапускает engine, а остановка target останавливает весь экземпляр,
  не удаляя firewall. Node управляет только конфигурацией/маршрутами/жизненным
  циклом; пакеты и TLS/DNS остаются в C++.

Dry-run ничего не публикует. `--apply` возвращает `installed-disabled`: installer
не делает enable/start и не меняет сеть. Частичная установка не принимается
повторно и не откатывается вслепую; артефакты сохраняются для разбора. Установки
существующих Radxa/VPS этим изменением не обновляются.

## Двухзагрузочная лаборатория

```bash
node --test scripts/test-native-combo-install.mjs scripts/test-native-combo-boot.mjs
node scripts/clean-vpn-native-lab.mjs \
  /absolute/path/to/verified-host-boot-base \
  /absolute/path/to/qemu-tools-root --native-combo-boot
```

Runner проверяет base image и hash kernel, создаёт NIC-less QEMU и приватный
ext4-диск; host shared filesystem и доступ к физическим устройствам отсутствуют.
Внутренний VM driver нельзя использовать как установочную команду на сервере:
он отказывает вне QEMU с нужным kernel marker и смонтированным fixture-диском.

Первая загрузка — 13 gates: fresh disabled install, guard-before-uplink,
прямые C++ процессы с notify, TLS 1.2/TLS 1.3-HRR, настоящие TUN/TCP/UDP и
host/LAN DNS, журнальные маршруты, запрет неподдержанных HTTPS-направлений,
SIGKILL/обычный autorestart каждой роли, отдельные fault-окна `Restart=no` с
блокировкой обоих путей, target stop и сохранение непустого replay на ext4.

Вторая загрузка — 10 gates: другой boot ID, inventory файлов/каталогов/прав и
точные replay-байты до старта, автозапуск enabled targets, TLS/TUN/DNS и route
coordinator, policy refusal, отсутствие автоматического reset при missing/
corrupt replay, восстановление только явно сохранённых fixture-байтов, target stop.

Лабораторный link owner создаёт DOWN-интерфейсы и адреса. Отдельный default-route
owner каждой роли запускается после её uplink gate. Общей зависимости defaults
между client/exit нет: отказ exit не должен останавливать gateway и тем самым
маскировать проверку блокировки. Client split routes и endpoint bypass создаёт
установленный route coordinator, не тестовый driver.

Артефакты установленного дерева переносятся между initramfs через ext4 с
сохранением прав, включая replay `0700`. Это механизм стенда, не production
adoption/restore. `--root` installer — staging, не chroot; тесты отдельно проверяют
инициализацию nested replay с реальными staging-путями PKI/PSK.

Границы: controlled reboot, не power loss; сохранность journal bytes, не live-token
replay через reboot; один boring peer в VM (multi-peer copying проверяется отдельно);
статические адреса/default, не DHCP/network-manager; выбранные IPv4-пробы, не
независимый early-boot/all-egress/IPv6 capture. Это не physical ARM64 acceptance,
не speedtest, не browser profiles/UI, ECH/0-RTT, key rotation или live upgrade.
