# Native-only установка и boot/reboot: лабораторный checkpoint

2026-10-07. Установка boring-tls client и multi-peer exit без Node data plane.
Исходный режим принимает внешние network/guard units. Добавлен
[`--site-profile` для dedicated native-only сети](clean-vpn-native-network.md):
установщик выпускает TUN/guard/DNS/NAT/MSS, route coordinator и общий target.
Адреса/DHCP/default остаются внешней обязанностью link owner; это **не**
готовая миграция существующей Radxa/VPS или произвольного firewall.

## Контракт установщика

`clean-vpn-native-install.mjs` создаёт только новую именованную установку.
Без `--apply` проверяет входные данные, не пишет файлы и не запускает службы.
Пример dry-run для заранее подготовленных конфигурации и зависимостей:

```bash
node scripts/clean-vpn-native-install.mjs \
  --name=client \
  --binary=/absolute/clean-vpn-engine \
  --config=/absolute/client.json \
  --network-unit=site-network.service \
  --guard-unit=site-guard.service
```

Входной executable должен быть доверенным: проверка вызывает его `--capabilities`
и `--check-config`. Это не песочница для чужих бинарников и не проверка подписи.
Требуется `service_mode=true`, `packet_ipc=false`. Конфигурация проверяется native
движком; пути не могут быть symlink, секреты должны принадлежать запускающему
пользователю и не быть доступны группе/остальным. Для системной установки нужен
root. Concurrent privileged administrators не поддерживаются.

С `--apply` создаются:

- `/opt/clean-vpn-native/NAME/`: отдельная копия engine, config с переписанными
  путями, TLS-материалы, отдельные PSK; каталог `0700`, секреты/config `0600`;
- `prepared.json` и `installed.json`: перечень файлов, режимы и SHA-256,
  хеши внешних network/guard units, без содержимого ключей;
- `/etc/systemd/system/native-NAME.service`: прямой C++ service.

Файлы синхронизируются до публикации unit; публикация через no-replace hard link
внутри каталога units не требует общей файловой системы с `/opt`. Существующая
или незавершённая установка не перезаписывается. При ошибке файлы сохраняются
для ручного разбора; автоматического rollback/delete/adopt/update нет.
Скрытый `.native-NAME.service.prepared` намеренно остаётся рядом с unit.

Установщик **не делает** daemon-reload, enable/start, не меняет сеть/firewall/DNS.
Результат `installed-disabled` означает именно публикацию файлов, не готовый VPN.
Активация — отдельное явное действие после проверки внешних зависимостей.
Renderer требует обе зависимости; их содержимое не считается автоматически
проверенной политикой безопасности. Динамические библиотеки ОС не упаковываются.

`--root=/absolute/staging` предназначен для тестового дерева, не является chroot:
входной binary исполняется на текущей машине, конечные config paths остаются
`/opt/...`. Каталоги `/opt` и `/etc/systemd/system`, а также network/guard units
должны уже существовать внутри выбранного root.

## Лаборатория с постоянным диском

```bash
node scripts/clean-vpn-native-lab.mjs HOST_BOOT_BASE QEMU_TOOLS_ROOT --native-boot
```

NIC-less QEMU, без host shared filesystem, настоящий systemd PID1. Два клиента
и один multi-peer exit запускаются из установленного `/opt` с настоящими TUN.
Node только устанавливает/управляет; TCP/UDP/fragmentation и DNS проверяет C++
fixture. Новый приватный ext4 disk image сохраняется между тремя загрузками:

1. Настоящий CLI installer публикует три выключенных службы; лаборатория отдельно
   включает их и проверяет оба TUN/DNS и запуск guard до uplink — 18 gates.
2. Новый kernel boot: автоматический старт из сохранённых units, передача данных,
   побайтовая сохранность установленных файлов и режимов — 13 gates.
3. Новый kernel boot с отказом guard: native-процессы не стартуют, клиентские
   uplink остаются down без default route, файлы сохранены — 10 gates.

Проверяются три различных boot ID и фактические reboot/poweroff. Это не повторный
запуск сервисов внутри одной загрузки. Установленные артефакты сохраняются на
ext4 и перед systemd восстанавливаются в новый initramfs; это не полноценный
дистрибутив на постоянном root filesystem. Сеть статическая, не DHCP.
Нет независимого packet capture ранней загрузки; не заявляется универсальная
защита от boot leak или проверка physical ARM64. Скорость не измеряется.

Продолжение: [route coordinator с журналами и DHCP/gateway recovery](clean-vpn-native-routes.md).
Незакрытая упаковочная часть boring-tls — полный native-only сетевой профиль
TUN/guard/DNS/SNAT и его installer/boot приёмка. Затем native transparent/combo;
только после полного native перехода — замеры скорости.

## Зафиксированный результат

Окончательная сборка: **41/41 gates, три загрузки**, `status=passed`.
Полный отчёт: `/var/tmp/meshpn-native-lab-vQSD2k/report.json`.
Компактное свидетельство с boot ID, хешами и всеми gates:
[clean-vpn-native-boot-report.json](fixtures/clean-vpn-native-boot-report.json).
Предыдущие успешные boot-прогоны: `Grr8my`, `tiXspv`; первые попытки выявили
ошибку валидации корневого пути `/` установщика, исправленную до этой приёмки.

Повторный отдельный lifecycle/crash-прогон: **12/12**, отчёт
`/var/tmp/meshpn-native-lab-A5zxOs/report.json`.
Регрессии: **385/385**, CTest: **3/3**; ASAN/UBSAN: **18/18** integration
и **3/3** CTest. Инструментирован собственный код, не сторонние зависимости.
SHA-256 native engine:
`9dd9fc2be86da4d62ffb522042f60c7405ae1f25091f63755835d2b57cf970a5`.
Radxa, VPS, Mac и роутер не изменялись; benchmark не запускался.
