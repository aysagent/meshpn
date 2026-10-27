# Native runtime: выбранный ingress на Linux-шлюзе

Пункт ночного плана о host-side wiring проверяется **в NIC-less QEMU VM**.
Это воспроизводимая модель шлюза, не установщик для настоящего `wg0`/`usb0`.
Скрипт `lib/native-runtime-host-wiring-fixture.mjs` отказывает без специального
параметра командной строки ядра гостя. На Mac и физических узлах он не запускался.

## Проверяемый путь

```text
USB-like app 192.168.7.2 → gateway usb0 192.168.7.1
  → policy rule iif usb0 → table 19998
  → cvlbr0 192.168.88.1 → native client LAN 192.168.88.2
  → authenticated boring-tls → exit → HTTPS origin

other app → gateway lan1 → прежний прямой маршрут
gateway process → прежний прямой маршрут
USB-like app → gateway 192.168.7.1:2222 → локальный rescue
```

`usb0` здесь — veth в госте. Проверяются Linux routing/netfilter и native
runtime; USB gadget hardware и WireGuard driver этим не проверяются.
Origin возвращает адрес реально подключившегося peer: при включённой policy
это exit, до запуска/после recovery — прямой источник. Простого успешного
HTTP-ответа недостаточно для положительного результата.

Модель требует уже настроенного шлюза: `ip_forward=1`, loose `rp_filter=2`
на ingress и private bridge. Это явные предусловия fixture, не скрытая смена
sysctl установщиком. Адреса, table/priority/chain фиксированы только для лаборатории.

Правила для выбранного ingress:

- Собственная цепочка с DROP устанавливается до policy routing.
- Отдельная таблица содержит next hop на client и запасной `unreachable
  default`: исчезновение bridge не должно вернуть выбранный трафик в main.
- Private IPv4 prefixes обходятся через `throw` и исходную main table;
  локальный rescue обрабатывается INPUT и сохраняется.
- UDP/TCP DNS ingress, в том числе запрос к IP самого шлюза, DNAT к native
  listener клиента. Host OUTPUT и `/etc/resolv.conf` не переписываются.
- Выбранный IPv6 FORWARD блокируется; IPv6 других источников сохраняется.
- SNAT к private bridge не требует маршрута в контейнере обратно в USB LAN.

Такая схема перехватывает **запросы LAN-клиента**. Она не отправляет через
VPN новые запросы, которые самостоятельно создаёт `dnsmasq` на шлюзе.
DHCP-конфигурация и приватные DNS исключения реального узла требуют отдельного
решения перед физическим подключением.

## Аварии и восстановление

Приватный журнал содержит boot/netns identity, PID/start time владельца и
курсор операций. Команды восстановления берутся из кода, не из журнала.
Intent сохраняется до изменения ядра; recovery умеет обработать незавершённую
операцию. Живой владелец исключает конкурентный recovery.
Для атомарной записи используются уникальные временные файлы: оставшийся
после SIGKILL файл не блокирует следующую запись recovery. Синхронизируются
файл и родительская директория; это не меняет привязку журнала к одному boot.

SIGKILL контроллера оставляет защиту включённой. После SIGKILL native client
новые выбранные HTTPS/DNS запросы не проходят; другие источники и rescue
остаются работоспособны. Явный recovery удаляет только свои правила/маршруты.
После него сравниваются IPv4/IPv6 policy rules и routes, firewall rules,
forwarding/rp_filter и resolver baseline. Чужая sentinel-цепочка сохраняется.

Отдельно проверяются kill до rename журнала, между intent и mutation, после
mutation до проверки результата и исчезновение private bridge. После bridge
fault сама fixture восстанавливает свой bridge с прежним MAC, заново поднимает
собственный backend-port в исходном порядке и ждёт IPv6 DAD. Сравнение маршрутов
остаётся строгим, включая порядок; это не действие production recovery.

Журнал fixture расположен в `/run` и привязан к одному boot. Это проверка
process-crash recovery, **не доказательство power-loss восстановления
host-side wiring**. Existing native boot tests имеют отдельную отсечку.

## Повторение в подготовленной лаборатории

На Mac нужен уже подготовленный rootful Podman lab и его x86 toolchain/cache.
Ниже image, использованный при проверке; при пересборке lab выбрать его
актуальный tag. Новый путь отчёта обязателен.

```bash
CVPN_REPORTS=$(mktemp -d /tmp/cvpn-host-wiring.XXXXXX)
podman --connection=meshpn-clean-vpn-lab-root run --rm \
  --platform=linux/amd64 --network=none \
  -v meshpn-clean-vpn-lab-cache:/lab \
  -v "$PWD:/source:ro" -v "$CVPN_REPORTS:/reports" \
  -e CVPN_BUILD=/lab/worktree/native/clean_vpn/build \
  --workdir=/source --entrypoint=node \
  localhost/meshpn-clean-vpn-lab:1f35b200e5e912e7 \
  scripts/clean-vpn-native-runtime-vm.mjs /reports/run.json --host-wiring
```

Гость не получает NIC, host shares, порты или физические устройства. В него
копируются только необходимые файлы initramfs. Проверки standalone, неправильных
часов и независимого ClientHello capture выполняются после wiring-сценария.
Приватные JSON, serial log и pcap сохраняются в `CVPN_REPORTS`.

Перенос этой модели на физический шлюз остаётся отдельной задачей: выбор
существующих интерфейсов и свободной policy table, проверка менеджера сети,
DHCP/DNS политики, устойчивый журнал и независимый rollback на конкретном узле.
Ночной scope не разрешает постоянную установку и этот перенос не выполняет.
