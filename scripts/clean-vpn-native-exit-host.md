# Native boring-tls exit на существующем VPS

`--exit-profile` устанавливает **выключенный** native exit и отдельный сетевой
owner. Подходит для IPv4 VPS с уже настроенным forwarding, где нельзя заменять
чужие firewall tables, Docker/x-ui или существующие маршруты.
Физическая постоянная установка в текущем поручении не выполняется.

## Контракт

- Engine role `exit`, transport `boring-tls` (или поле transport отсутствует).
- `address` — локальный IPv4 адрес listener; `port` проверяется engine при bind.
  За внешним NAT публичный адрес для клиентов может отличаться от локального bind.
- TUN: `cvexit` с необязательным суффиксом до восьми строчных букв/цифр,
  например `cvexit0`; адрес `10.99.0.1/24`, MTU 1400.
- `net.ipv4.ip_forward` уже равен 1. Owner его не меняет, включая recovery.
- Uplink уже существует и поднят. Переключение uplink между интерфейсами не поддерживается.
- Подсеть `10.99.0.0/24` не пересекается с существующими недефолтными IPv4 маршрутами.
- Нет другого администратора собственного TUN/правил/peer subnet. Изменения
  посторонних firewall rules допускаются и не откатываются снимком таблицы.
- Системный DNS, default route, INPUT policy и разрешение порта не меняются.
  Существующий firewall должен разрешать вход на выбранный listener.

Native engine поддерживает `secret_path` либо `peers` с отдельными PSK/IP.
Сам owner не вводит второй протокол авторизации: аутентификацию и проверку
источника packet payload выполняет C++. Эта новая lifecycle-матрица проверяет
одного живого клиента; [multi-peer](clean-vpn-native-clients.md) имеет отдельные
тесты. Radxa client host-profile пока фиксирует `10.99.0.2`, поэтому нельзя
выдавать нескольким таким client одинаковый адрес и считать их независимыми.

## Установка и управление

Приватный профиль, root-owned 0600:

```json
{"version":1,"uplink":"eth0"}
```

План без публикации файлов и сетевых изменений:

```sh
node scripts/clean-vpn-native-install.mjs \
  --name=exit \
  --binary=/absolute/clean-vpn-engine \
  --config=/absolute/private/exit.json \
  --exit-profile=/absolute/private/exit-host.json
```

В `exit.json` требуется TUN подходящего имени, абсолютные пути сертификата,
ключа и PSK; для создания credentials есть
[offline runtime bundle generator](clean-vpn-native-runtime.md).
`--exit-profile` несовместим с `--host-profile`, `--site-profile` и внешними
`--network-unit/--guard-unit`. Он не предназначен для transparent/combo.

После отдельной публикации с `--apply` и `systemctl daemon-reload`:

```sh
node /opt/clean-vpn-native/exit/control/clean-vpn-native-exit-host.mjs \
  preflight --config=/opt/clean-vpn-native/exit/network.json
systemctl start native-exit-network.service
systemctl show native-exit-network.service native-exit.service \
  -p Id -p ActiveState -p MainPID -p Result -p StatusText
systemctl stop native-exit-network.service
```

Это команды для выбранной установки, не bounded remote trial. Installer не
делает `start/enable`; на физических узлах текущая ночная работа их не применяет.
Для автозагрузки предназначен network owner; прямой engine unit не имеет
секции Install. Используются текущий абсолютный путь Node, Python 3, iproute2,
iptables и flock. Сетевые пакеты, TLS и DNS обрабатываются C++.

## Владение и отказ

Журнал `/run/clean-vpn-native-exit-host-NETNS` содержит boot/net/user namespace,
конфигурацию, случайный owner tag, alias/ifindex TUN и intent каждого правила.
TUN становится persistent только после установки alias/address/MTU. До этого
авария удаляет ephemeral TUN; после — recovery может проверить durable intent.

Owner добавляет два FORWARD ACCEPT и один MASQUERADE с собственным tag.
Правила ограничены TUN, uplink и peer subnet. Восстановление удаляет только
проверенные собственные операции. Подменённый TUN, дубликаты или подмена
помеченных правил приводят к отказу и сохранению журнала для разбора.

На exit один owner владеет и TUN, и scoped forwarding rules; engine зависит
от него через BindsTo/After. Отдельный client kill switch этим не заменяется:
у client остаются независимые guard и network dependencies.
SIGKILL owner останавливает engine, независимый ExecStopPost восстанавливает
сеть, затем systemd повторяет запуск. SIGKILL engine не пересоздаёт сеть.
Штатный stop удаляет свой TUN/rules, сохраняя исходные host routes/forwarding.

Binary updater поддерживает этот именованный boring-tls instance: enrollment
при остановленном engine, проверка hashes owned units, здоровое обновление и
rollback плохого кандидата проверены. Параллельные ручные операции обновления
и изменения собственных сетевых объектов не входят в контракт.

## Проверки

[Машиночитаемый отчёт](../fixtures/clean-vpn-native-exit-host-report.json):

- 23 реальных kernel/netns сценария, включая прерывания до/после persistence,
  conflict/refusal, смену instance и сохранение нового чужого firewall rule;
- 11 systemd/native сценариев: реальный forwarding/NAT до отдельного origin,
  HTTPS и DNS UDP/TCP, SIGKILL engine/owner, update/rollback, stop/restart/cleanup;
- 21 kernel-регрессия client после расширения общего TUN helper/store;
- 32 общие installer/unit проверки, без пропусков.

Первая расширенная регрессия использовала старую копию одного теста из image
(ожидал прежний KillMode); после копирования текущих тестов все 32 прошли.
Первый kernel fixture отказал на небезопасном mode временного `/run`; стенд
исправлен на 0755, production-проверка прав сохранена.

Повторение: `CVPN_DISPOSABLE_EXIT_HOST=1 node scripts/test-native-exit-host-linux.mjs`
только в пустом netns с отдельным `/run`; systemd fixture —
`CVPN_DISPOSABLE_EXIT_SYSTEMD=1 node scripts/lib/native-exit-host-systemd-lab.mjs`
только в одноразовом NIC-less окружении с `/project` и native engine.
Boot-матрица новой пары выполняется отдельно; контейнер не доказывает cold boot
или физический power loss VPS.
