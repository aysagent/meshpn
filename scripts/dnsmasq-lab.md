# Radxa dnsmasq: изолированные DNS и USB/DHCP стенды

Статус: настоящий dnsmasq и существующий DNS exit adapter; **не live backend**.
Используется конфиг USB gadget из сообщения пользователя, включая намеренно
оставленную в baseline дублирующую DHCP option 6. Строгий fixture compiler
отвергает незнакомые опции, includes, scripts, другие интерфейсы/сети. Это не
универсальный редактор dnsmasq и не инструмент миграции хоста.

```bash
npm run test:dnsmasq-config
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq npm run dns:dnsmasq-lab
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq npm run dns:dnsmasq-lab -- --usb
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq npm run test:dnsmasq-real
npm run test:dhcp-lab-wire
```

Нужен Linux с user/net/PID/mount namespaces, Node 22+, iproute2, openssl и локальный
dnsmasq; для `--usb` также iptables/ip6tables. Путь задаётся явно; автоскачивания,
установки службы и sudo нет.
Runner проверяет private namespaces и запускает dnsmasq только с собственным
временным конфигом и leasefile. Без флага DNS high port, с `--usb` настоящий
порт 53 и отдельный сетевой namespace USB-клиента, соединённый veth с usb0.
Система хоста не переключается; host TUN/firewall не меняются. В `--usb` правила
DNS guard создаются **только в namespace лабораторного шлюза**. Внешних NIC нет.

В простом режиме создаётся dummy usb0, в USB-режиме — veth-пара. Локальные aliases
1.1.1.1/8.8.8.8 (в USB-режиме также 2001:db8:53::1) с
собственными UDP/TCP наблюдателями: это **не запросы в интернет**. Защищённый
путь использует настоящий adapter → enc-SNI exit → TLS DoH fixture.

14 проверок: исходный DNS UDP/TCP, protected A/AAAA UDP/TCP, отказ exit по UDP/TCP,
возврат exit, SIGKILL/restart dnsmasq с managed config, отказ adapter, ноль
обращений к исходным DNS во время managed mode, explicit restore UDP/TCP.
Точный исходный текст восстанавливается только во временном файле; это пока
не durable журнал и не восстановление системного baseline после аварии.
При мёртвом adapter UDP может закончиться deadline клиента; отчёт отличает его
от DNS error. Кэш стенда выключен, имена проверок уникальны.

## USB/DHCP: 36 проверок

Клиент в отдельном namespace выполняет настоящий DISCOVER → OFFER → REQUEST → ACK
по UDP 68/67, принимает адрес/маску/шлюз/DNS/lease time из пакета и настраивает
**только свой** usbpeer. До получения IPv4 устанавливается namespace-local route
через usbpeer для broadcast и reverse-path проверки ответа сервера. После ACK
устанавливаются полученный адрес /24 и default route через 192.168.7.1.
Это ограниченный тестовый клиент, не DHCP-клиент для установки в ОС:
нет автоматических retries, T1/T2 renewal, DHCPv6 или support option overload.
Пакеты ограничены, проверяются xid, chaddr, cookie и все используемые DHCP options.
[RFC 2131](https://www.rfc-editor.org/rfc/rfc2131),
[RFC 2132](https://www.rfc-editor.org/rfc/rfc2132).

Шесть настоящих DHCP-обменов: baseline, managed, при выключенном exit, после
SIGKILL/restart dnsmasq, при мёртвом adapter и после explicit restore. Проверяются
сохранность диапазона/шлюза/lease, правильный DNS, сохранение адреса через restart.
DNS-запросы идут на адрес, полученный в DHCP ACK, на настоящий порт 53.
Есть UDP/TCP A/AAAA через adapter и локальное имя usb-client из DHCP leases,
включая его доступность при мёртвом adapter.

Исходный fixture на dnsmasq 2.90 реально выдаёт **1.1.1.1**, после согласованной
в lab нормализации option 6 — **192.168.7.1**. Перезапуск сервера не обновляет
настройку уже полученной клиентом аренды: до нового обмена guard блокирует старый
прямой DNS. Этот временный отказ явно проверен, а не скрыт как бесшовная миграция.
Политика обновления настоящих USB-клиентов ещё нужна для live-интеграции.

Прямые DNS-запросы к лабораторным upstream по IPv4/IPv6 × UDP/TCP сначала
успешны, затем блокируются guard, после explicit disable снова успешны.
Эти адреса принадлежат самому namespace шлюза, поэтому трафиком проверен
**INPUT**, не FORWARD. FORWARD-правила также установлены, но их транзитный путь
ещё требует отдельного внешнего peer. Это не полный шлюзовой DNS kill-switch.
Для IPv6 заданы статические documentation addresses только внутри стенда;
это не DHCPv6/RA и не IPv6 data plane clean-vpn.

## Ограничения

Нет системного NSS/resolv.conf takeover,
independent pcap, boot guard или crash/reboot recovery. Нулевые счётчики baseline
upstreams не объявляются полной проверкой DNS-утечек. Эта x64 проверка не заменяет
пилот Radxa/arm64. При окончании дочерние процессы остановлены; проверены отсутствие
зомби и неизменность host resolv.conf. Временные файлы самого прогона удаляются.

На 2026-09-26 проверен dnsmasq 2.90, собранный без DBus/UBus/IDN/Lua/DNSSEC/conntrack
в отдельном `/tmp` из HTTPS-архива официального сайта (не системная установка).
SHA256 исходного архива: `8f6666b542403b5ee7ccce66ea73a4a51cf19dd49392aaccd37231a2c51b303b`.
Отчёт каждого запуска содержит версию и SHA256 использованного executable.
Наличие этих хешей не означает проверку независимой подписи релиза.

Для настоящей интеграции нельзя считать SIGHUP перечитыванием основного конфигурационного
файла: dnsmasq этого не делает. Выбор restart или отдельного managed servers-file
потребует ownership/journal и проверки сохранности DHCP.
[Официальная документация dnsmasq](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html).
Следующие шаги: транзитный FORWARD guard, durable recovery, resolved 249/networkd
по [матрице клиентов](dns-client-matrix.md). Физическая USB-связь и arm64 не проверены.
