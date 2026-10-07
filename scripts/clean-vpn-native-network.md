# Native-only site profile

Лабораторный профиль выделенного IPv4 client/exit. Весь packet/DNS/TLS data plane
остаётся C++. Node выполняет установку файлов, netlink/systemd/firewall команды,
но не принимает и не пересылает payload. `--site-profile` расширяет fresh-only
установщик; ничего не включает и не запускает автоматически.

## Контракт

- Выделенный хост/network namespace, пустые управляемые IPv4 filter/nat/mangle
  и IPv6 filter, отсутствующий TUN, forwarding выключен. Существующие правила
  и TUN не принимаются во владение. Нет параллельных firewall administrators.
- Внешний `link_unit` подготавливает реальные интерфейсы **administratively DOWN**,
  адреса и DHCP/default-маршруты. Этот профиль не заменяет networkd/NetworkManager,
  не управляет Wi-Fi credentials и не переделывает существующую сеть Radxa.
  DHCP/default могут появиться после активации интерфейса; coordinator дождётся их.
- TUN: client `10.99.0.2…254/32`, exit `10.99.0.1/24`; MTU 1280…1500.
  Дополнительная LAN client — выбранный интерфейс и `192.168.x.x/16…30` subnet.
  Адрес LAN и маршруты LAN-клиента подготавливает внешний владелец.
- IPv6, кроме loopback, закрыт; native IPv6 transport не реализован.
- Системные утилиты, iptables legacy-compatible backend/modules, Node и systemd
  должны быть установлены заранее. Проверено в Linux x86-64 VM, не на ARM hardware.

## Что устанавливается

Вместо `--network-unit`/`--guard-unit` передаётся `--site-profile=/absolute/site.json`:

```json
{
  "link_unit": "site-links.service",
  "profile": {
    "version": 1,
    "role": "client",
    "tun": "tun0",
    "tun_address": "10.99.0.2/32",
    "mtu": 1400,
    "uplink": "wlan0",
    "endpoint": "154.62.226.216",
    "port": 443,
    "lan": {"interface": "usb0", "subnet": "192.168.7.0/24"}
  }
}
```

Файл owner-only. Role/TUN/endpoint/port/peer address сверяются с engine config;
для client обязательны `dns:true` и capability `dns_socket_mark=0x43564e`.
Exit использует `role:exit`, `tun_address:10.99.0.1/24`, `lan:null`.
PKI и peer secrets берутся из обычного native engine config.

Установщик копирует бинарник, ключи, конфигурации, фиксированный набор
control-plane модулей и units в приватный `/opt/clean-vpn-native/NAME`.
В manifest сохраняются их хеши, modes и внешний link-unit dependency.
Каждый unit публикуется no-replace, activation target — последним.
Незавершённая публикация не продолжается вслепую. Обновления и удаление пока
не поддержаны; `--root` — staging root, не sandbox.

Порядок активации target `native-NAME.target`:

1. Внешний link owner создаёт/подготавливает выключенные интерфейсы.
2. `native-NAME-network.service` ставит защиту IPv6/IPv4, DNS/NAT/MSS, создаёт
   persistent TUN, проверяет read-back и включает forwarding при необходимости.
3. `native-NAME-uplink.service` повторно проверяет журнал и только затем поднимает
   выбранные uplink/LAN. Не назначает адреса и не меняет DHCP/default.
4. Client: route coordinator ждёт default, устанавливает собственные маршруты
   и запускает C++ engine. Exit: запускается непосредственно C++ engine.

Все компоненты `PartOf` target, движки связаны с защитой/управляющей службой
через `BindsTo`. Остановка target/guard останавливает движки, **не снимая firewall**.
Клиент отдельно в `multi-user.target` не включается.
`active` у target означает запуск цепочки управления, а не проверенный egress:
готовность C++ engine и прикладной probe проверяются отдельно.

Это контракт интеграции, не готовая команда миграции существующей Radxa/VPS.
Нельзя поднимать uplink внешним менеджером до завершения network service.
Межсемейной атомарности IPv4/IPv6 нет — поэтому на fresh-install links DOWN
является обязательным условием, а не рекомендацией.

## DNS, forwarding и журнал

Client перехватывает UDP/TCP 53 с LAN и обычные host DNS, кроме loopback, в
C++ listener на TUN:1053. Native upstream UDP/TCP sockets получают `SO_MARK`
`0x43564e`; только сочетание этой метки, native source и `1.1.1.1/8.8.8.8:53`
обходит повторный DNAT. Отказ поставить метку не допускает unmarked fallback.
Метка — средство исключения рекурсии, не защита от привилегированного процесса.
DoH/DoT здесь не распознаются; проходят как обычный VPN-трафик.

LAN forwarding разрешён только LAN→TUN с SNAT в peer address и обратными
established/related ответами; TCP MSS равен MTU−40. Exit выполняет forwarding
TUN→uplink и MASQUERADE только tunnel subnet. IPv4 host OUTPUT client разрешает
loopback, TUN, DHCP и TCP к заданному VPN endpoint. Management SSH LAN:2222
сохраняется, но SSH daemon профиль не устанавливает. На exit новые WAN SSH
соединения не разрешены: активация требует отдельного console/rescue-доступа
и заранее согласованной management policy. Не включать этот лабораторный
профиль по единственному SSH-каналу на действующем VPS.

`/run/clean-vpn-native-network-NETNS_ID` содержит same-boot журнал под lifetime
flock. Перед изменениями сохраняется intent, после каждого этапа checkpoint.
Read-back проверяет policies, число правил и каждое правило через `iptables -C`.
Повторный запуск сверяет полные snapshots управляемых tables (без counters),
namespace/boot, config fingerprint, ifindex/link identity, TUN/MTU/address и
forwarding. Drift/partial install требует review; нет автоматического flush,
удаления чужих правил, восстановления старых allow-политик или снятия защиты.
Journal `/run` не переживает reboot; при новом boot профиль создаётся заново
из установленного bundle до поднятия интерфейсов. Это не постоянный монитор
изменений firewall — concurrent administrators не входят в контракт.

## Лабораторные проверки

```bash
node scripts/clean-vpn-native-lab.mjs HOST_BOOT_BASE QEMU_TOOLS_ROOT --native-network
node scripts/clean-vpn-native-lab.mjs HOST_BOOT_BASE QEMU_TOOLS_ROOT --native-site-boot
```

NIC-less VM без shared filesystem. Отдельные namespace для LAN client, native
client, native exit и внешнего тестового сервера. Реальные TUN, два NAT,
systemd units устанавливаются настоящим fresh installer. Трафик генерирует и
проверяет C++ `socket-test`: TCP, UDP, fragmentation и UDP/TCP DNS на адрес,
где вообще нет DNS-сервера (положительная проверка DNAT).
Fixture drop-ins задают network namespace и `Restart=no`, чтобы наблюдать
окно отказа до явного restart; штатный engine unit сохраняет `Restart=on-failure`.

Проверяются неактивная установка, защита до uplink, client/exit crash, direct
fallback при мёртвом клиенте, restart, отказ при чужом firewall rule и stop
target. Boot-режим сохраняет bundle/units/enabled targets на ext4 и проверяет
другой kernel boot_id, autostart, bytes/modes, порядок защиты и LAN data/DNS.

Не является Speedtest, замером скорости, all-egress leak acceptance,
проверкой физического USB/WG/Wi-Fi, произвольного distro boot/network manager,
автоматическим обновлением или готовым production rollout.

## Проверенный результат 2026-10-07

Окончательная версия: `/var/tmp/meshpn-native-lab-OMuqm6/report.json`,
**17/17 gates на двух различных kernel boot_id**, `status=passed`.
Первый boot: настоящая inactive установка, 13 lifecycle/network/crash gates;
второй: autostart, LAN data/DNS, inventory/order и target-stop block — ещё 4.
Отдельный одно-загрузочный installed-site прогон `mot7BW` — 13/13.

Регрессии выбранного native/routes набора **349/349**, CTest **3/3**;
ASAN/UBSAN integration **17/17** и CTest **3/3**. Это не весь repository test suite.
Ранние VM попытки выявили отсутствие iptables-save/mark plugin в минимальном
образе и ошибочную зависимость наблюдателя `Requires=defaults`: он завершался
при остановке проверяемого target. Fixture исправлен, добавлена регрессия;
эти попытки не засчитаны как полноценная reboot приёмка.

Все gates, ограничения и сверенные с текущими исходниками хеши:
[clean-vpn-native-site-report.json](fixtures/clean-vpn-native-site-report.json).
Native boring-tls лабораторная основа готова для следующего этапа — C++
transparent relay, затем combo. Distro-specific deployment/management policy,
hardware boot, update/uninstall и full leak acceptance остаются отдельными задачами.
