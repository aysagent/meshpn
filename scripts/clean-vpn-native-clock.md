# Native clock recovery: только после отказа по времени

Продолжение 2026-10-28: [установочный bundle, блокировка с updater и физический pilot](clean-vpn-native-installed-lifecycle.md).
Постоянная интеграция позднее включена и проверена на реальном отставании часов:
[физическая приёмка 29 октября](clean-vpn-native-daily-20261029.md).

Checkpoint 2026-10-28. Есть opt-in интеграция с systemd: native engine →
OnFailure → отдельная служба восстановления → повторный запуск engine.
На момент этого checkpoint интеграция ещё не была установлена на физических узлах.
Никакого безусловного `ExecStartPre` для синхронизации часов нет.

## Условие запуска

1. Сначала клиент делает обычное соединение с полной проверкой CA, имени,
   срока сертификата и exporter-bound PSK.
2. Только `tls_verify_expired`, `tls_verify_not_yet_valid` или
   `auth_clock_skew` разрешают запрос доверенного времени. Первые два кода —
   причина проверить часы, не доказательство, что виноваты именно они.
3. В opt-in режиме engine завершает работу с одним из кодов 75/76/77.
   Systemd не перезапускает его обычным Restart=on-failure для этих кодов.
   Независимый guard остаётся активен. Recovery проверяет MainPID=0, отсутствие
   start job, Result=exit-code, точный ExecMainStatus и InvocationID; проверка
   повторяется перед изменением времени. Before=consumer упорядочивает restart.
4. Отдельный SSH-ключ обращается по IP к закреплённому raw Ed25519 host key.
   SSH agent, пользовательский config, multiplex, proxy, password и TOFU не
   используются. Host key получают по уже проверенному каналу, не доверяют
   результату одного `ssh-keyscan`.
5. Ответ содержит свежий nonce, Unix time и признак синхронизации VPS.
   Проверяются формат, размер, RTT ≤5 секунд, неизменность локальных часов
   во время запроса и нижняя граница ранее принятого времени.
6. Часы меняются только при отличии больше погрешности измерения. Если
   SSH-время совпадает с локальным, helper ничего не переводит. Просроченный
   сертификат нельзя «чинить» переводом часов к его сроку действия.
7. Только после фактической коррекции часов recovery ставит start consumer
   в очередь systemd. Он начнётся после завершения recovery и повторит обычное
   TLS-соединение с теми же проверками. Совпавшее время, ошибка SSH или
   израсходованный бюджет не дают автоматический restart.

`ready`, таймауты/обрывы, неверный PSK, CA или hostname не разрешают recovery.
Одна автоматическая попытка на загрузку: `attempt.json` публикуется с fsync до
SSH. Ошибка запроса и restart службы не сбрасывают бюджет; после неудачи нужна
диагностика, а не бесконечные запросы. Новая загрузка сама запрос не вызывает:
сначала снова нужна одна из трёх ошибок. Read-only `probe` — отдельная ручная
диагностика, не boot hook и не автоматическая смена времени.

## Как отличаем неверный PSK от неверных часов

Клиент передаёт `x-clean-vpn-window` внутри уже защищённого H2. Это то же
15-минутное окно, которым подписан `authorization`. Обычная проверка ±1 окно
не меняется. Если она не прошла, exit проверяет MAC для заявленного окна,
используя настроенный peer PSK и TLS exporter **этого** соединения.

Только правильный MAC вне текущего окна получает `409` +
`x-clean-vpn-error: clock-skew`. Это отказ: peer address не захватывается,
`ready` не устанавливается, пакеты не принимаются. Неверный PSK, повтор MAC
из другого TLS-соединения, нечисловое/слишком длинное окно и произвольный
заголовок сами по себе такого ответа не дают. Граница unauthenticated
соединений и deadline остаются прежними.

Старый клиент с правильным временем продолжает работать без нового заголовка.
Старый exit не умеет выдавать этот диагноз; общий auth failure не заменяет
его и не включает SSH recovery. Изменяется H2 control header, не ClientHello.

## Ограничения доверия и установки

SSH доказывает, что время пришло от закреплённого VPS, а не что оно абсолютно
верно. Скомпрометированный VPS или ошибочный источник его времени могут
сообщить неверную дату. `NTPSynchronized=yes` — необходимое состояние сервера,
а не криптографическое доказательство правильности NTP.

На сервере нужен отдельный непривилегированный пользователь, отдельный ключ
клиента и root-owned helper. В `authorized_keys` обязательны **оба** ограничения:

```text
restrict,command="/usr/bin/timeout 5s /usr/bin/python3 -I /opt/clean-vpn-clock/clean-vpn-native-clock.py serve" ssh-ed25519 PUBLIC_KEY
```

Это пример для будущего установщика, не команда установки. Пользователь не
должен иметь password login, изменяемые им helper/authorized_keys, дополнительные
ключи с широкими правами или интерактивный доступ. Shell должен позволять
исполнить forced command; один `nologin` может заблокировать и этот путь.
`serve` принимает только `SSH_ORIGINAL_COMMAND=clean-vpn-clock-v1` и nonce.

Один `command=` не запрещает forwarding: нужен `restrict`.
[Документация OpenSSH authorized_keys](https://man.openbsd.org/sshd.8),
[параметры клиента SSH](https://man.openbsd.org/ssh_config.5).

Конфигурация клиента — root-owned regular file 0600, без symlink:

```json
{
  "version": 1,
  "host": "192.0.2.1",
  "port": 22,
  "user": "cvpn-clock",
  "identity": "/etc/clean-vpn-clock/identity",
  "known_hosts": "/etc/clean-vpn-clock/known_hosts",
  "state_dir": "/var/lib/clean-vpn-clock",
  "consumer_unit": "clean-vpn.service"
}
```

`known_hosts` содержит одну строку `clean-vpn-clock ssh-ed25519 BASE64`.
`state_dir` — 0700; ключ и state-файлы — 0600. Не использовать SSH certificate
вместо raw host key: bootstrap должен работать до восстановления даты.

API helper:

```sh
python3 -I scripts/clean-vpn-native-clock.py probe --config=/etc/clean-vpn-clock/config.json
# Только после отказа своего engine и завершённого stop consumer:
python3 -I scripts/clean-vpn-native-clock.py apply --config=/etc/clean-vpn-clock/config.json --failure=auth_clock_skew
```

`--failure` — assertion доверенного root lifecycle, не самостоятельное
доказательство события. Передавать код из своего контролируемого engine,
не из пользовательского ввода, сетевых заголовков или произвольного журнала.
Ручной `apply` не останавливает и не перезапускает VPN. Автоматический `recover`
сам получает причину из systemd, не принимает `--failure` и ставит restart в
очередь только после коррекции. Оба режима не меняют firewall, DNS, RTC или
конфигурацию NTP и отказываются работать на macOS.

## Подключение к systemd

Это opt-in для **pure boring-tls client**. Без флага прежний retry не меняется.
Exit, combo и transparent с `--clock-recovery` отклоняются до запуска data plane.

- Consumer: `--config … --service --clock-recovery`, `OnFailure=…`,
  `RestartPreventExitStatus=75 76 77`. MainPID остаётся C++ engine;
  `CAP_SYS_TIME` у него нет.
- Recovery: Python `recover`, `Before=consumer`, `Restart=no`, отдельный
  `CAP_SYS_TIME`, root-owned config/key/pin и writable state directory 0700.
  `CAP_NET_ADMIN` у recovery нет. Не добавлять WantedBy или ExecStartPre.
- 75 — сертификат ещё не действителен; 76 — просрочен; 77 — exit подтвердил
  правильный MAC для другого временного окна. Произвольный лог не является
  основанием для recovery. Любая другая причина отказа не разрешает SSH recovery.
- Независимый guard должен разрешать **только заданный IP/порт SSH exit** для
  этого control plane, иначе bootstrap до VPN работать не сможет. Renderer
  не добавляет это правило сам. Для сетевого namespace recovery должен
  использовать тот же namespace, где доступен этот маршрут.
- Не запускать consumer параллельно внешним supervisor во время recovery.
  Встроенный systemd порядок и повторные проверки защищают штатный lifecycle;
  они не являются блокировкой от произвольных действий root.

Offline renderer только печатает units; ничего не устанавливает и не включает:

```sh
node scripts/clean-vpn-native-clock-unit.mjs --kind=consumer \
  --binary=/opt/clean-vpn/clean-vpn-engine --config=/etc/clean-vpn/client.json \
  --network-unit=clean-vpn-network.service --guard-unit=clean-vpn-guard.service \
  --recovery-unit=clean-vpn-clock.service

node scripts/clean-vpn-native-clock-unit.mjs --kind=recovery \
  --consumer-unit=clean-vpn.service --script=/opt/clean-vpn-clock/clean-vpn-native-clock.py \
  --config=/etc/clean-vpn-clock/config.json --state-directory=/var/lib/clean-vpn-clock
```

Имена consumer в helper config и recovery unit должны совпадать. Recovery unit
сохраняют под именем из OnFailure consumer. State directory создаётся заранее;
закреплённые SSH-ключи получают через уже проверенный канал. Это ещё не
автоматический установщик для существующих DNS/route owners физического хоста.

## Проверки

- `python3 -B scripts/test-native-clock.py`: policy, формат/права/nonce,
  ограничение попыток, отказ при изменившемся InvocationID, pending restart,
  просроченный сертификат при правильном времени, параллельная смена часов.
- `node --test scripts/test-native-clock-unit.mjs scripts/test-native-service-unit.mjs`:
  opt-in, конкретные exit codes, раздельные права, injection rejection.
- `CVPN_BUILD=... node --test scripts/test-native-clock-auth.mjs`:
  реальный TLS/H2, ±13 часов/2017 в fixture, PSK/exporter, malformed windows,
  старый клиент. Часы хоста не меняются.
- `scripts/test-native-clock-ssh.py`: только disposable Linux container,
  `CVPN_DISPOSABLE_CLOCK_SSH_LAB=1`; настоящий sshd, отказ неверному pin/identity,
  запрет shell/forwarding. Не запускать на рабочем хосте: создаёт тестового пользователя.

### Холодные загрузки в VM

`scripts/clean-vpn-native-clock-vm.mjs REPORT.json` запускается в подготовленном
Linux x64 lab image с kernel/QEMU и `CVPN_BUILD` на свежую native сборку.
Не требует сети контейнера, privileged или CAP_SYS_TIME контейнера.
Два отдельных Linux-ядра соединены только private Unix stream QEMU; нет TAP,
SLIRP, внешнего NIC и файлового share. Часы Mac/Podman/физических узлов не меняются.

Три загрузки client используют один disposable ext4 state disk: RTC=2017,
правильная дата, снова RTC=2017. Exit работает непрерывно с отдельными часами.
Реальные production engine, systemd OnFailure и SSH forced command восстанавливают
часы; готовность проверяется по native MainPID и ICMP через TUN. Отдельно проверяются
13-часовой HMAC skew, неверные PSK/CA/hostname/SSH pin, timeout, действительно
просроченный сертификат, сохранение бюджета и независимого guard после stop.
Exit считает реально выполненные SSH forced commands, а не только отчёты клиента.

Прогон завершён: три загрузки, 16 проверенных шагов; exit зафиксировал ровно
четыре forced-command запроса (3 / 0 / 1 по фазам). В первой фазе fault-кейсы
используют отдельные consumer/state directories; лимит — один запрос на загрузку
для каждого consumer. У основного consumer число запросов по загрузкам — 1 / 0 / 1.
[Машиночитаемый отчёт с SHA-256](../fixtures/clean-vpn-native-clock-lifecycle-20261028.json).

Источник времени **этой офлайн-лабы** — RTC QEMU; флаг синхронизации ядра явно
устанавливается только в exit guest. Сам helper читает настоящий timedatectl
через D-Bus. Это проверка lifecycle/протокола, не точности внешнего NTP.

Следующий физический этап: согласовать интеграцию с существующими route/DNS
owners, временно проверить bootstrap на Radxa с закреплённым ключом VPS и
rollback; затем отдельная приёмка постоянного запуска. VM не заменяет проверку
автозагрузки, USB rescue и DHCP на конкретной Radxa.

Предыдущий checkpoint: [conditional-clock 2026-10-27](../fixtures/clean-vpn-native-conditional-clock-20261027.json).

### Совместная приёмка host-profile, 29 октября

Режим `scripts/clean-vpn-native-clock-vm.mjs REPORT.json --host-profile`
использует настоящий `installNative`, network owner, cvks4 guard, native DNS,
журналы и независимый ExecStopPost. TUN создаёт установленный owner. После
готовности проверяются обычные UDP/TCP DNS-запросы через DNAT и пакетный путь,
а после stop — отсутствие собственных TUN/NAT/DNS/policy rules и живой guard.

[Успешный отчёт](../fixtures/clean-vpn-native-host-clock-20261029.json): три
разные загрузки, 19 шагов, четыре реально исполненных SSH forced commands
на независимом exit (3/0/1). Правильная дата не вызывает recovery; неверные
CA/hostname/PSK, молчаливый timeout и неправильный SSH pin не разрешают
необоснованную коррекцию. Настоящий expired certificate при верной дате не
исправляется откатом. Повторный restart не сбрасывает бюджет попыток.

RTC задан как 2017, но systemd может сначала поднять часы до своей build-time
границы; проверяется фактический TLS not-yet-valid и коррекция, а не утверждение,
что TLS обязательно видел 2017. HMAC skew отдельно воспроизведён на 13 часов.
Engine не имеет CAP_SYS_TIME. State сохраняется на отдельном ext4 диске между
загрузками, обе VM используют отдельные ядра и private QEMU connection.

В ранних попытках исправлены только ошибки сборки стенда: недостающие guest
утилиты/modules, права каталогов initramfs при umask 077 и некорректная инъекция
timeout (закрытый порт давал RST). Для timeout теперь exit guest явно отбрасывает
TCP/445. Production TLS/clock checks и лимиты SSH не ослаблялись.
Хэши в отчёте фиксируют проверенный snapshot и engine. Позднейшее opt-in ingress
расширение имеет отдельную приёмку и не включено в эту VM-матрицу. Физическая
Radxa, её RTC/DHCP/USB rescue и power-loss остаются отдельной проверкой.
