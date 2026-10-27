# Native runtime: выбранный ingress и DNS шлюза

Теперь вместо зашитой VM-рецептуры есть `clean-vpn-native-gateway.mjs`:
`plan`, `preflight`, ограниченный по времени `apply`, `status`, независимый
`recover`. Параметры — JSON, пример в
[`fixtures/native-runtime-gateway.example.json`](../fixtures/native-runtime-gateway.example.json).

**Исполняемый контракт пока только для выделенного Linux network namespace.**
Нужен `CVPN_PARENT_NETNS`, отличный от текущего namespace. Скрипт не подключает
физический интерфейс к контейнеру и не разрешает запуск непосредственно в сети
хоста. На Mac работает только offline `plan`; Linux испытания идут внутри
выделенной Podman/QEMU лаборатории. Постоянная физическая установка отложена.

## Путь и настройки

```text
USB/WG-like app → ingress interface → собственная policy table
  → private bridge → native client LAN → boring-tls → exit → origin

other LAN → прежний маршрут
gateway process → прежний маршрут
USB app → локальный rescue
local dnsmasq с выделенным UID → явно заданный native upstream → exit
```

Указываются ingress interface/subnet, private bridge interface/subnet,
адрес шлюза и next hop client, свободные table/priority, список private IPv4
исключений. Проверяются каноничность подсетей, отсутствие перекрытий, локальная
достижимость next hop, UP интерфейсов и свободная policy table. Конфиг —
root-owned regular file 0600. Preflight требует уже настроенного
`ip_forward=1`, `rp_filter=2` на ingress/bridge; сам sysctl не меняет.

Сначала ставятся собственные DROP-правила, затем policy routing, SNAT и
перехват ingress DNS. Запасной `unreachable default` предотвращает возврат
выбранного интернет-трафика в main при исчезновении bridge. `bypass` содержит
только явно указанные private IPv4 сети: это намеренные прямые исключения.
IPv6 FORWARD выбранного интерфейса блокируется. INPUT и маршруты самого
шлюза не перенастраиваются; локальный rescue остаётся доступен.

Имена `usb0`/`wg0` не зашиты в контроллер. В VM оба варианта моделируются veth:
проверяется Linux routing/netfilter, а не USB gadget или WireGuard handshake.
Runtime client пока принимает LAN в 192.168.0.0/16; ingress может быть другой
неперекрывающейся RFC1918 подсетью. Неподходящий конфиг отклоняется.

## DNS локального прокси

`dnsUid: null` в примере означает только перехват DNS **входящего LAN-трафика**.
Чтобы контролировать DNS самого шлюза, нужен отдельный не-root UID прокси и
явный upstream в конфигурации, которой владеет этот прокси, например:

```ini
no-resolv
server=192.168.88.2@192.168.88.1
```

Все старые `server=1.1.1.1`/`server=8.8.8.8` в этом режиме нужно исключить из
эффективной конфигурации. Это не инструкция сейчас переписывать Radxa:
сначала проверяются владелец конфигурации, UID и процедура возврата. Нельзя
использовать UID другого сервиса или общий UID `nobody` без проверки.

В gateway JSON `dnsUid` выбирает только UDP/TCP OUTPUT на порт 53 этого UID:
допускается native upstream через private bridge, остальные IPv4/IPv6 пути
блокируются. Остальные процессы хоста не затрагиваются. DNSmasq настраивается
**явно**, без прозрачной подмены его уже привязанных upstream-сокетов.
Неверный старый upstream в тесте блокируется; владелец fixture переключает
свой dnsmasq и при завершении восстанавливает исходные аргументы.

Контроллер не редактирует dnsmasq/resolv.conf, не включает resolved, не меняет
DHCP option 6. Если host NSS сейчас не использует этот прокси, одного gateway
JSON недостаточно для смены DNS хоста. DoH/DoT сторонних приложений и
произвольные демоны вне выбранного UID не входят в этот контракт.

В VM работает настоящий dnsmasq с loopback и USB listener, отключённым кешем.
DNS origin фиксирует peer: для запросов через native это exit, а не gateway.
Проверяются UDP/TCP, старые direct upstream, обрыв engine, отсутствие direct
fallback в наблюдаемом сценарии, сохранность DNS остальных процессов и возврат.
Отдельный DORA probe получает настоящие DHCP OFFER/ACK с router и единственным
DNS option 6, указывающим на gateway. Probe не устанавливает lease на свой
интерфейс. Для реальной Radxa конфликтующие DHCP option 6 нужно разбирать в её
эффективной конфигурации; текущий инструмент её не переписывает.

## Журнал и завершение

Журнал `/run/clean-vpn-gateway-NETNS/journal.json` содержит boot/netns/userns,
проверенный конфиг, случайный tag, identities интерфейсов и курсор операций.
Команды восстанавливаются кодом. Stable-inode `flock` держит единственного
владельца; дочерняя сетевая команда также удерживает lock при гибели controller.
Intent fsync предшествует мутации, rename и directory fsync атомарно публикуют
новую запись. Уникальные временные файлы не мешают recovery после SIGKILL.

Rollback удаляет только собственные точные правила/маршруты, не делает flush
или restore всей таблицы. Чужая запись в owned chain/table, подменённый интерфейс
или чужой boot/namespace приводят к отказу. Исчезнувший bridge обрабатывается
отдельно. Совпавшие table/route/ifindex не разрешают удаление маршрутов, если
не сохранилось ни одного собственного случайного firewall tag. Повторный
recovery после завершения сообщает `no-active-journal`.

`apply --seconds=10..900` по таймеру или SIGTERM возвращает исходное состояние.
SIGKILL голого controller оставляет guard и журнал до явного recovery.
Отказ native engine **сам по себе** не снимает guard. `status` различает живого
владельца и незавершённую запись; это не DNS/туннельный health probe.

Offline renderer `clean-vpn-native-runtime-unit.mjs --kind=gateway` создаёт
unit для **ограниченного trial**: `ExecStopPost` выполняет recovery после гибели
controller. Это намеренное окончание trial и возврат baseline, который может
разрешать прямой интернет. Такая unit не является постоянным VPN kill switch.
Unit engine использует `Type=notify`, restart on failure и сохраняет guard
своего namespace при stop. Ни одна unit автоматически не устанавливается и
не включается; жизненным циклом namespace владеет отдельный setup.

## Команды в подготовленном Linux namespace

Сохранить namespace родителя до `ip netns exec`, конфиг подготовить отдельно:

```bash
# Offline plan допустим и на Mac.
node scripts/clean-vpn-native-gateway.mjs plan --config=/absolute/gateway.json

# Linux lab; cvpn-gateway уже создан владельцем лаборатории.
export CVPN_PARENT_NETNS="$(readlink /proc/self/ns/net)"
ip netns exec cvpn-gateway node scripts/clean-vpn-native-gateway.mjs preflight --config=/absolute/gateway.json
ip netns exec cvpn-gateway node scripts/clean-vpn-native-gateway.mjs apply --config=/absolute/gateway.json --seconds=300
# Во второй консоли с тем же parent anchor:
ip netns exec cvpn-gateway node scripts/clean-vpn-native-gateway.mjs status
# После аварии владельца:
ip netns exec cvpn-gateway node scripts/clean-vpn-native-gateway.mjs recover
```

Preflight не создаёт журнал и не делает DNS-запросов. Apply дополнительно
проверяет DNS UDP/TCP непосредственно через выбранный client, затем включает
wiring. Невозможно запустить второй apply поверх незавершённого первого.

## Лабораторное повторение

```bash
CVPN_REPORTS=$(mktemp -d /tmp/cvpn-host-wiring.XXXXXX)
podman --connection=meshpn-clean-vpn-lab-root run --rm \
  --platform=linux/amd64 --network=none \
  -v meshpn-clean-vpn-lab-cache:/lab \
  -v "$PWD:/source:ro" -v "$CVPN_REPORTS:/reports" \
  -e CVPN_BUILD=/lab/worktree/native/clean_vpn/build \
  --workdir=/source --entrypoint=node \
  localhost/meshpn-clean-vpn-lab:1f35b200e5e912e7 \
  scripts/clean-vpn-native-runtime-vm.mjs /reports/run.json --reboot
```

`--host-wiring` — без systemd; `--systemd` — один boot с настоящим PID1;
`--reboot` — два boot того же гостя с private ext4 диском. Гость не получает
NIC, host shares, published ports или физические устройства. Raw report,
serial logs и pcap сохраняются приватно. В варианте reboot pcap отдельный
для каждого boot. Используются production engine и независимый ClientHello
observer, не mock TLS.

Проверяются точный baseline, прерывания setup/recovery, foreign drift,
настраиваемые интерфейсы/table, systemd stop/SIGKILL/ExecStopPost/restart,
неверные часы и профиль. Reboot сохраняет credentials и отвергает старый
scope журнала до сетевых изменений; topology создаётся заново владельцем VM.
Это **не power-loss тест** и не доказательство отсутствия раннего boot gap на
постоянном физическом шлюзе: постоянная установка и её порядок старта ещё
не выполнялись. Итоговые результаты — в local readiness report/плане.
