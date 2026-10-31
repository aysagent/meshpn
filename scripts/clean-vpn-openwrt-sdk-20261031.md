# OpenWrt SDK: локальные APK и real TUN acceptance

31 октября: engine-only APK **`clean-vpn-native 0.0.0-r1`** собраны официальными
OpenWrt 25.12.6 SDK для `x86/64` и `armsr/armv8`. Оба установлены в одноразовые
VM соответствующей архитектуры и прошли normal-engine TUN/auth/procd gates.
Здесь принят `boring-tls`; `combo-tls`/`transparent-tls` на OpenWrt ещё требуют
своей отдельной матрицы.
[Машиночитаемый receipt](../fixtures/clean-vpn-openwrt-sdk-20261031.json).

| Target | Размер APK | Установленный engine | SHA256 engine |
| --- | --- | --- | --- |
| x86_64 | 1 418 895 B | 2 938 571 B | `0affde8ebde701e66cdcdab48c65a87fc8cfdf0daeb8a35687464ac4f42d274e` |
| aarch64_generic | 1 373 591 B | 2 917 907 B | `e767a7582ed82474f0746582d73a503890a71325a4919524ee83b4debe8ba75d` |

APK SHA, SDK/image hashes, исходные файлы, dependency commits/patch hash,
builder ID/versions, ELF headers и VM cleanup сохранены отдельно в receipt.
Артефакты также сохранены локально в игнорируемом Git каталоге
`native/clean_vpn/build/openwrt-20261031/{amd64,arm64}/` вместе с manifests.
В Git идут исходники/receipts; бинарники в публичный feed не отправлялись.
Подкаталог `lab/` сохраняет public image/kernel, TUN module/index, lab helper и
профиль с SHA в `inputs.json`: следующий VM smoke не требует повторной SDK
компиляции. PSK и private keys туда не копировались; payload helper каждый раз
генерирует новые test credentials. QEMU images и SDK volumes оставлены в cache.

## Что проверено

- APK inventory: normal engine, три публичных TLS-профиля, четыре dependency
  notices и стандартный package file list. Нет PSK, CA/key, service/init,
  UCI/network/firewall files или fixture binaries.
- После установки SHA `/usr/sbin/clean-vpn-engine` совпал с извлечённым из APK.
  Capabilities подтверждают `packet_ipc:false`, `prewire_check:true`; config
  проходит обычный loader. Профиль — Chromium-derived bounded HTTP, не полный Chrome.
- Сам **установленный** engine в двух ролях передаёт ICMP через настоящие TUN
  и TLS на H2 и H1. Source-policy routing не допускает обход через LOCAL table.
  Удаление маршрута даёт unreachable; восстановление возвращает пакеты; stop
  клиента прекращает обмен. Счётчики обоих normal процессов подтверждают I/O.
- На обоих HTTP protocols неверный PSK приводит к `auth_rejected`, без ready
  клиента и с нулевыми packet counters. Это отдельная проверка normal engine.
- Временная настоящая procd service: две native instances, SIGKILL клиента,
  новый PID при прежнем exit PID, восстановленный обмен, затем stop обоих и
  отсутствие пакетов. Test interfaces/zone/rules удалены, snapshot отброшен.
- Пять preflight tests без пропусков: bad hash/symlink/connection, dynamic/foreign
  ELF, неполный TUN input, неверный module/index hash и запрет normal-only без TUN.

В APK-тестах **нет FD fixture**. Прежние generic-musl FD/CTest результаты —
[отдельные артефакты](clean-vpn-openwrt-native.md), не SDK acceptance.
`--normal-only` требует реальную TUN-проверку. Официальный TUN module установлен
через подписанный offline repository index со штатными guest keys. Для нашего
локального APK `--allow-untrusted` применён только внутри одноразовой VM;
host/physical trust store не менялись.

## Сборка и исправления

[Source recipe и повтор](../openwrt/README.md), [SDK Makefile](../openwrt/clean-vpn-native/Makefile).
Compile — UID1000, без сети/capabilities, по одному CPU, 2 GiB memory cap.
Публичные source caches скопированы в собственный SDK workspace; original cache
permissions не менялись. SDK prerequisite checks не обходились.

Fortify GNU wrappers требуют system-header classification при нашем Wpedantic;
fortify и собственный Werror сохранены. SDK static GCC specs не добавляет
exception unwinder: явные `-lstdc++ -lgcc_eh` исправляют линковку с exceptions
движка. Эти первые неудачные сборки не учитываются как успешная приёмка.

SDK по умолчанию удалил промежуточные CMake builds после успешной упаковки.
Попытка собрать fixture после этого остановилась на отсутствующем build dir.
Для будущего сохранения compile cache инструкция отключает AUTOREMOVE **до**
сборки. Завершённая приёмка APK использует только его normal binary и потому
не зависит от сохранности промежуточного fixture build.

Оба engine — static **ET_EXEC**, без PT_INTERP, с non-executable GNU_STACK и
GNU_RELRO header. Это не заявление о PIE или всей runtime hardening policy.
Builder APT packages не snapshot-locked; текущие image IDs/versions закреплены
в receipt, bit-for-bit будущий rebuild не обещается. Release GPG signature не
проверялась; SHA загрузок получены с официального HTTPS каталога.

## Что остаётся OpenWrt v1

Это engine-only эксперимент, **не готовое LuCI-приложение**. Один guest с двумя
ролями и loopback/test aliases не подтверждает WAN/NAT, DNS/kill switch,
netifd/fw4 ownership, crash journal, reboot/update recovery, несколько физических
клиентов, производительность или произвольный роутер/другую версию OpenWrt.

Следующий этап — UCI validation и procd/network/DNS adapter с bounded rollback,
затем rpcd ACL/LuCI и полный capture/profile/independent observer workflow.
Сам APK ничего не включает и не перенастраивает. Рабочие Radxa/VPS этой
подготовкой не обновлялись и не перезапускались.
