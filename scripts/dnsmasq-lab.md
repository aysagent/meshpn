# Radxa dnsmasq: первый изолированный стенд

Статус: настоящий dnsmasq и существующий DNS exit adapter; **не live backend**.
Используется конфиг USB gadget из сообщения пользователя, включая намеренно
оставленную в baseline дублирующую DHCP option 6. Строгий fixture compiler
отвергает незнакомые опции, includes, scripts, другие интерфейсы/сети. Это не
универсальный редактор dnsmasq и не инструмент миграции хоста.

```bash
npm run test:dnsmasq-config
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq npm run dns:dnsmasq-lab
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq npm run test:dnsmasq-real
```

Нужен Linux с user/net/PID/mount namespaces, Node 22+, iproute2, openssl и локальный
dnsmasq. Путь задаётся явно; автоскачивания, установки службы и sudo нет.
Runner проверяет private namespaces и запускает dnsmasq только с собственным
временным конфигом, leasefile и DNS high port. Система хоста не переключается,
TUN/firewall не меняются. Исходящий сетевой интерфейс в namespace отсутствует.

В тестовой сети создаются dummy usb0 и локальные aliases 1.1.1.1/8.8.8.8 с
собственными UDP/TCP наблюдателями: это **не запросы в интернет**. Защищённый
путь использует настоящий adapter → enc-SNI exit → TLS DoH fixture.

14 проверок: исходный DNS UDP/TCP, protected A/AAAA UDP/TCP, отказ exit по UDP/TCP,
возврат exit, SIGKILL/restart dnsmasq с managed config, отказ adapter, ноль
обращений к исходным DNS во время managed mode, explicit restore UDP/TCP.
Точный исходный текст восстанавливается только во временном файле; это пока
не durable журнал и не восстановление системного baseline после аварии.
При мёртвом adapter UDP может закончиться deadline клиента; отчёт отличает его
от DNS error. Кэш стенда выключен, имена проверок уникальны.

DHCP-диапазон и шлюз сохраняются; новая конфигурация проходит реальный `dnsmasq --test`, но **DHCP lease
exchange с USB peer ещё не проверен**. Нет системного NSS/resolv.conf takeover,
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
Следующие шаги: [матрица клиентов](dns-client-matrix.md).
