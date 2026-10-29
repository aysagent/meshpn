# Native VPN и админка в одном Compose

Один проект запускает два сервиса: `vpn` (client **или** exit) и `admin`.
Лабораторная пара — два проекта с разными private volumes, IP и портами админки.
Работающая установка на Radxa/VPS этой упаковкой автоматически не заменяется.

VPN-контейнер имеет собственный network namespace, TUN, маршруты и firewall.
Внутри него ограниченный Node supervisor запускает один C++ engine; web/API
обращается к нему по Unix socket. Docker/Podman socket, host systemd и host
network namespace supervisor не получает. `stop` останавливает engine, сохраняя
защитные правила namespace. После SIGKILL engine supervisor делает ограниченный
restart; `stop` через API сохраняется в private state и переживает пересоздание.
При завершении контейнера namespace удаляется самим container engine.

## Границы поддержки

- Linux rootful Docker/Podman, `/dev/net/tun`, NET_ADMIN/NET_RAW внутри namespace.
  Реальная проверка выполнена на ARM64 Podman machine и отдельно на Docker
  28.5.2 / Compose 2.40.3 внутри изолированной Linux-лаборатории. На macOS Linux-сеть находится внутри Podman VM.
- `boring-tls` и `combo-tls` используют существующий native runtime. Для combo
  нужна отдельная LAN сеть и инициализированный durable replay state.
- UI показывает только поддержанные возможности: start/stop/restart, состояние,
  bounded logs, DNS probe клиента, настройку клиента и импорт профиля с
  валидацией/rollback, browser capture. Exit может включить управление клиентами.
- Настройки Wi-Fi, hostname/mDNS, USB DHCP, host DNS и host kill switch здесь не
  реализованы. Перехват независимым наблюдателем требует отдельного namespace
  с захватом; контейнерный broker не притворяется таким наблюдателем.
- `.mpn` zone на основе реестра — отдельная интеграция; данный Compose сам
  DNS-зону хоста не подключает.
- Админка использует host networking **Linux engine**, но слушает только
  `127.0.0.1`. У неё нет capabilities и управляющего сокета container engine.
  Доступ: SSH forwarding либо отдельно настроенный USB-bound host proxy.
  Это не публичный HTTP listener и не автоматический `mpn.local` на Mac.

## Сборка

Создать allowlisted context (не использовать корень проекта как build context):

```sh
node scripts/clean-vpn-native-runtime-context.mjs /tmp/cvpn-managed-context
```

Для Podman machine добавляйте `--connection meshpn-clean-vpn-lab-root` ко всем
Podman командам. На Linux Docker команды build совместимы по аргументам.

```sh
podman build --target runtime -f /tmp/cvpn-managed-context/scripts/containers/clean-vpn-native-alpine.Containerfile \
  -t localhost/cvpn-native:alpine /tmp/cvpn-managed-context
podman build --target vpn --build-arg VPN_IMAGE=localhost/cvpn-native:alpine \
  -f /tmp/cvpn-managed-context/scripts/containers/clean-vpn-managed.Containerfile \
  -t localhost/cvpn-managed:alpine /tmp/cvpn-managed-context
podman build --target web-alpine \
  -f /tmp/cvpn-managed-context/scripts/containers/clean-vpn-managed.Containerfile \
  -t localhost/cvpn-admin:alpine /tmp/cvpn-managed-context
```

Для Ubuntu можно передать source-built Ubuntu runtime в `VPN_IMAGE`; frontend
собрать target `web` (Node 24 Debian). Systemd/QEMU лаборатория остаётся Ubuntu.
Подробнее о musl, размерах и архитектурах: [Alpine](clean-vpn-native-alpine.md).

## Подготовка одной роли

Нужен container-mode bundle из существующего native runtime config/export:
`engine.json` с путями `/config/<file>` и только файлами этой роли. Не монтировать
каталог authority с CA private key в работающий VPN. Импортёр копирует только
явно указанные config references, отказывается от существующих volumes и
проверяет конфигурацию engine. Никакие сети/сервисы он не запускает.

```sh
node scripts/clean-vpn-native-managed-prepare.mjs \
  --engine=podman --connection=meshpn-clean-vpn-lab-root \
  --image=localhost/cvpn-managed:alpine --source=/private/path/bundle/client-1 \
  --config-volume=cvpn-client-config --web-volume=cvpn-client-web \
  --web-port=18080 --capture-port=18443
```

Для exit с реестром клиентов добавить к импорту exit bundle:
`--ca=/path/ca.pem --profile=/path/profile.json --clients-endpoint=EXIT_IP
--server-name=EXIT_TLS_NAME`. Это только public CA/profile; приватный CA не нужен.
В Compose выставить `CVPN_CLIENTS_DIRECTORY=/config/clients`. Для combo
автоматический init реестра пока не поддержан: требуется явная relay identity
map через native clients CLI, затем установка того же фиксированного пути.
Нельзя сбрасывать существующий replay state ради перезапуска.

Нужна заранее созданная **контейнерная** uplink network с выбранной подсетью.
Она не должна пересекаться с текущими маршрутами. Для закрытой лаборатории:

```sh
podman network create --internal --subnet=10.77.91.0/24 cvpn-lab-uplink
```

Production uplink имеет обычную внешнюю связность Linux container engine;
настройки физического интерфейса, host DNS и default route этот проект не меняет.
Обычные правила NAT/bridge самого Docker/Podman остаются его ответственностью.

Получить Linux host namespace anchor (только чтение):

```sh
podman run --rm --network=host --entrypoint=readlink localhost/cvpn-managed:alpine /proc/self/ns/net
```

Указать полученное `net:[...]` и параметры роли в отдельном env-файле:

```dotenv
COMPOSE_PROJECT_NAME=cvpn-client
CVPN_MANAGED_IMAGE=localhost/cvpn-managed:alpine
CVPN_ADMIN_IMAGE=localhost/cvpn-admin:alpine
CVPN_PARENT_NETNS=net:[REPLACE_WITH_ACTUAL_ID]
CVPN_CONFIG_VOLUME=cvpn-client-config
CVPN_WEB_VOLUME=cvpn-client-web
CVPN_UPLINK_NETWORK=cvpn-lab-uplink
CVPN_CONTAINER_IP=10.77.91.3
```

```sh
podman compose --env-file ./client.env -f scripts/containers/native-managed.compose.yml up -d
podman compose --env-file ./client.env -f scripts/containers/native-managed.compose.yml ps
podman compose --env-file ./client.env -f scripts/containers/native-managed.compose.yml down
```

Для remote Podman необходимо настроить compose provider на **ту же** connection.
Не использовать молча другой default engine. В лабораторном тесте это явно
задаётся `CVPN_CONTAINER_COMMAND` и `CVPN_COMPOSE_COMMAND`.

Exit использует другой project/env/IP/admin ports. Для публикации добавить
`-f scripts/containers/native-managed.exit.yml`: по умолчанию `127.0.0.1:3443`
Linux engine → `443` в контейнере. Публичный bind задаётся явно через
`CVPN_BIND_ADDRESS`. Для combo client добавить
`native-managed.client-lan.yml`, `CVPN_LAN_NETWORK`, `CVPN_LAN_IP`,
`CVPN_LAN_SUBNET`: это отдельная virtual LAN, физический NIC не перемещается.

## Админка и capture

Начальный пароль `admin`; перед изменениями потребуется смена пароля. State и
сессии находятся в отдельном web volume UID/GID 1000. HTTP/API и capture порты
надо отдельно пробросить через SSH; для capture используется `localhost` и
собственный сертификат из UI. Доверие к нему подтверждается явно, проверку CA
VPN-соединения это не отключает. Импорт браузерного профиля не доказывает полную
эквивалентность браузеру: проверяются поддержанные ClientHello поля.

Реестр exit выдаёт адреса и применяет peers через подтверждённый SIGHUP с hash
конфига. Add/revoke не перезапускают engine и не обрывают другого клиента.
Экспорт с ключом — отдельное authenticated/CSRF download действие; списки и jobs
не содержат PSK. Не удалять config/web/replay volumes как способ обновления.

## Проверка

`test-native-container-broker.mjs`: четыре теста ограничений API, settings
rollback, сохранения stop и отказа host-команд. `test-native-managed-compose.mjs`
поднимает изолированную пару, проверяет реальный TUN, обе HTTP админки, проверяемый
TLS capture, add/revoke без смены PID, stop/start и SIGKILL recovery; затем
удаляет только свои контейнеры, volumes и bridge. Он использует 10.77.91.0/24 и
порты VM loopback 18181/18182/19181/19182; запускать без другого такого теста.
Результаты и ограничения — [отчёт](../fixtures/clean-vpn-native-containers-20261030.json).

## Optional private DNS sidecar

Для exit с реестром клиентов добавить
`-f scripts/containers/native-managed.private-dns.yml`. При первоначальном
импорте exit bundle указать `--private-peer-dns` вместе с
`--clients-endpoint=...`; это ставит `private_peer_dns:true` в native exit
config. Для combo флаг находится в `boring`, а реестр и replay identity map
готовятся отдельно. Нужен engine, объявляющий `private_peer_dns` в capabilities.

Sidecar слушает только `127.0.0.1:1055` внутри namespace VPN. Native exit
передаёт ему авторизованные приватные запросы из TUN, а клиент направляет
`*.mpn` и приватные PTR только в этот канал. Публичные имена продолжают
использовать обычные upstream. Отказ sidecar даёт SERVFAIL для private zone;
открытого fallback для неё нет. Смена, добавление и отзыв имён видны без
перезапуска; pending registry transaction означает SERVFAIL.

Сервис root, cap_drop ALL, read-only rootfs/config и no-new-privileges; у него
нет container-engine socket и опубликованных портов. **Это доверенный
control-plane сервис:** read-only config volume содержит ключи, и root sidecar
технически может их прочитать, хотя resolver код читает только registry и
соседний journal. Web volume ключей не получает. Отдельная проекция без ключей
потребует своего атомарного протокола публикации/инвалидации. Монтирование одного
registry файла не подходит: atomic rename оставит mount на старом inode.

Compose задаёт `CVPN_CONTAINER_DNS` (по умолчанию `1.1.1.1`) именно для
resolver VPN-контейнера. Podman может записать адрес своего bridge proxy
в `/etc/resolv.conf`, сохранив upstream в настройках engine. Клиентский runtime
перехватывает UDP/TCP53 и
передаёт запросы native DNS stub; это не изменение DNS хоста. Явный адрес нужен
также в internal bridge, где Podman иначе может оставить пустой resolver config.
Sidecar не выполняет рекурсивных запросов и собственный resolver не использует.

Этот overlay обеспечивает `.mpn` для клиентов через native DNS. Собственный
`getent <client>.mpn` внутри exit-контейнера пока не подключён: localhost:1055
не является libc resolver на порту53. На exit доступен явный запрос к
127.0.0.1:1055; host systemd-resolved zone integration остаётся отдельной
процедурой. Широкий redirect DNS exit/хоста этим overlay не устанавливается.

Лаборатория: `CVPN_MANAGED_PRIVATE_DNS=1` добавляет overlay только exit-проекту
`test-native-managed-compose.mjs`. Проверяются UDP/TCP `.mpn`, обычный NSS
`getent`, публичный DNS positive control, registry transaction/revoke, остановка
и запуск sidecar, отсутствие приватных запросов в журнале public fixture.

Для DNS к on-link bridge resolver добавлено узкое разрешение OUTPUT только
`own-TUN-IP:1053` после `conntrack DNAT` и при `addrtype LOCAL`. Оно учитывает
сохранённый первоначальный uplink в OUTPUT hook после DNAT и не открывает DNS
наружу до создания TUN/адреса. `test-native-runtime-local-dns.mjs` подтверждает
pre-TUN drop и canonical audit в отдельном namespace без NIC; общий Compose
проверяет обычный NSS и отсутствие port53 fallback при остановленном engine.

## Получение адреса клиента от exit

Для нового client bundle с `address_assignment: "v1"` и без `peer_ipv4`
добавить `-f scripts/containers/native-managed.address-discovery.yml` к
клиентскому Compose. Overlay передаёт runtime `CVPN_ADDRESS_DISCOVERY=1`.
Exit должен поддерживать authenticated address discovery и знать ключ этого
клиента. Адрес сохраняет exit registry; это стабильное назначение по identity,
а не случайная DHCP-аренда при каждом соединении.

Первый запуск выполняется в новом namespace. До получения проверенного ответа
разрешён только точный endpoint exit; затем runtime создаёт эффективный config
и маршруты с выданным адресом. Исходный `/config/engine.json` остаётся без
фиксированного IP. `/status.vpn.assignedIPv4` и `/settings.vpn.assignedIPv4`
показывают адрес из эффективного `/run/clean-vpn/engine.json` либо `null`,
если назначения ещё нет. Значение `.2` по умолчанию не подставляется.

Обычный restart подтверждает то же назначение. При изменении source config
или назначения на exit контейнер нужно пересоздать: имеющийся namespace нельзя
молча перенастроить под другой peer. Настройки DNS/маршрутов хоста не меняются.

`CVPN_MANAGED_ADDRESS_DISCOVERY=1 CVPN_MANAGED_PRIVATE_DNS=1` в
`test-native-managed-compose.mjs` проверяет фактическое назначение `.3`,
неизменность source config, TUN, публичный/приватный NSS, stop/start и SIGKILL.
На ARM64 Alpine этот прогон прошёл 12/12; результат и точные images сохранены
в [отчёте](../fixtures/clean-vpn-native-managed-address-20261030.json).
