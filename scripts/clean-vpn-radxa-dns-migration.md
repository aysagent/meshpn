# Radxa: dnsmasq → штатные службы Armbian (исследование, 2026-10-28)

**Миграция не выполнена.** Файлы DNS/DHCP/Netplan, `/etc/resolv.conf` и
состояние resolved/dnsmasq оставлены прежними. Это проект перехода для
проверенной Radxa Zero 3W; не универсальный рецепт для любого Armbian.

## Что работает сейчас

На плате Debian 12 / systemd 252. В обоих `/etc/netplan/*.yaml` указан
`renderer: networkd`; действуют `systemd-networkd` и `netplan-wpa-wlan0`.
Wi-Fi управляется wpa_supplicant с генерируемым `/run/netplan/wpa-wlan0.conf`.
NetworkManager не установлен. `systemd-resolved` установлен, но выключен;
`/etc/resolv.conf` ссылается на отсутствующий resolved stub.

`dnsmasq` выполняет **две разные функции: DNS-прокси и DHCP-сервер**:

| Файл | Назначение |
|---|---|
| `/etc/dnsmasq.d/usb0.conf` | USB 192.168.7.1, DHCP 192.168.7.10–50, lease 12h, router 192.168.7.1 |
| тот же файл | `no-resolv`, upstream 1.1.1.1 и 8.8.8.8; одновременно две декларации DHCP DNS option 6: 192.168.7.1 и 1.1.1.1 |
| `/etc/dnsmasq.d/bt-pan.conf` | Bluetooth `pan0`, DHCP 10.12.0.50–150, локальная запись `myproject.local` → 10.12.0.1 |

Наличие файла pan0 не доказывает, что Bluetooth сейчас используется. Но удаление
его возможностей без отдельного решения не является эквивалентной миграцией.
Поведение повторной option 6 нужно подтвердить DHCP OFFER/ACK, а не угадывать
по порядку строк. При VPN существующий DNS journal перехватывает запросы;
исправная резолюция сама по себе не означает исправный `/etc/resolv.conf`.

USB rescue-address, SSH socket 2222, SNAT/MSS и kill switch — отдельные владельцы.
Нельзя одновременно поручить назначение адреса и forwarding новой `.network`
конфигурации, оставив старые владельцы без согласования.

## Чем заменить

У Armbian нет единственного DNS-стека для всех образов. Документация описывает
Netplan с networkd для minimal и NetworkManager для CLI/desktop. Здесь выбран
networkd по фактической конфигурации платы.
[Armbian networking](https://docs.armbian.com/user-guide/networking/).

Для этой платы подходящая комбинация:

- **systemd-networkd** раздаёт DHCP на usb0 (и отдельно pan0, если он нужен).
  В systemd 252 есть `DHCPServer=yes`, секция `[DHCPServer]`, `PoolOffset`,
  `PoolSize`, `DefaultLeaseTimeSec`, `MaxLeaseTimeSec`, `EmitDNS`, `DNS`,
  `EmitRouter`. DNS в выдаваемом lease задаётся явно адресом шлюза, иначе
  возможен выбор DNS uplink.
  [systemd.network v252](https://github.com/systemd/systemd/blob/v252/man/systemd.network.xml).
- **systemd-resolved** обслуживает DNS хоста и дополнительные USB TCP/UDP
  listeners через `DNSStubListenerExtra=192.168.7.1` (при необходимости и
  10.12.0.1). Эта настройка уже существует в v252. Upstream и правила выбора
  DNS должны вести к native DNS через проверенный lifecycle; `FallbackDNS=`
  очищается, DHCP/RA DNS uplink не должны становиться обходом VPN.
  [resolved.conf v252](https://github.com/systemd/systemd/blob/v252/man/resolved.conf.xml).
- **Avahi** продолжает обслуживать `.local`/mDNS. Админка уже публикует
  `mpn.local` только на usb0, с отдельной entry group и без изменения имени
  Linux. Это не DNS upstream и не второй рекурсивный DNS-прокси.

Таким образом можно убрать dnsmasq, оставив один DNS-прокси (resolved).
DHCP при этом выполняет уже работающий сетевой менеджер. Нельзя заменить
dnsmasq одним resolved: resolved не раздаёт DHCP.

## План перехода — отдельная будущая работа

1. Снять журнал исходного состояния: содержимое/права/ссылки конфигураций,
   effective networkd match/drop-ins, адреса/маршруты, unit enable/active,
   DNS listeners и DHCP выдачу. Сохранить независимый USB rescue 2222 и
   подготовить таймер отката **до** изменения DNS/DHCP.
2. В VM воспроизвести именно эту схему: networkd + USB DHCP + pan0 fixture +
   resolved + native DNS + guard. Проверить DHCP DORA, TCP/UDP DNS, отказ native,
   restart resolved/networkd и boot recovery. Netplan-generated `/run` не
   редактировать: использовать устойчивые исходные файлы или проверенные
   drop-ins к фактически выбранной `.network`.
3. Развести владельцев адресов: либо существующий rescue остаётся единственным
   владельцем USB IP, либо его роль меняется отдельной журналируемой операцией.
   Не запускать `netplan apply` на рабочем Wi-Fi ради USB-правки.
4. Подготовить DHCP с одной option 6 = 192.168.7.1, прежними диапазоном/router/
   lease. `PoolOffset=10`, `PoolSize=41` для USB /24. Для pan0 аналогично
   offset 50, size 101 — только после подтверждения его адресного владельца.
   Не включать глобальный forwarding/NAT автоматически.
5. Согласовать native DNS upstream и fail-closed защиту resolved. Порт 53
   dnsmasq сейчас занят; остановка старого и запуск нового выполняются
   транзакцией с возвратом. Не держать двух DHCP-серверов на одном интерфейсе.
6. После ready listener проверить NSS/resolv.conf; существующая ссылка станет
   рабочей только при реально работающем stub. Проверить LAN-имена и отсутствие
   прямых UDP/TCP DNS запросов на Wi-Fi при работающем/упавшем VPN.
7. Проверить, что нужно от `myproject.local`: dnsmasq `address=/.../` может
   обслуживать также поддомены, resolved `/etc/hosts` этому не эквивалентен.
   Для одного имени можно использовать запись hosts/мDNS с нужной областью;
   wildcard-зону нельзя молча заменить одной записью.
8. Сначала bounded trial и возврат. Удаление dnsmasq/старых файлов — только после
   принятого результата и отдельного решения о постоянной миграции.

Не нужно менять DNS только ради админки. Её HTTP API, USB-имя и Wi-Fi управление
работают поверх текущих владельцев. Совмещение DNS-миграции с первой установкой
админки усложнило бы проверку причин сетевых отказов.
