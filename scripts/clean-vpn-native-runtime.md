# Native runtime: standalone Linux и Docker/Podman

Новый opt-in runtime для **boring-tls**, без постоянной установки на физические
узлы. TLS, HTTP/2 carrier, IP-пакеты и DNS обслуживает C++ engine. Node.js нужен
для однократной подготовки сети и health probe; entrypoint затем делает `exec`
engine. Рабочего Node proxy/controller в data plane нет.

Текущие проверки и границы перечислены в
`fixtures/clean-vpn-native-runtime-report.json`. Этот runtime не объявляет
`combo-tls`/`transparent-tls` production: их конфиги здесь пока отклоняются.
`tls` из Node-версии также не является отдельным C++ транспортом.

## Контракт

- Linux, rootful Docker/Podman либо явно выделенный network namespace.
- Собственный `cvpn0`: client `10.99.0.2/32` (или `peer_ipv4`), exit
  `10.99.0.1/24`; MTU по умолчанию 1400, `CVPN_MTU=1280..1500`.
- Uplink `eth0` (`CVPN_UPLINK`), числовой IPv4 exit; исходный on-link маршрут
  или gateway до exit сохраняется отдельным /32. Остальное IPv4 через TUN.
- Конфиг engine с абсолютными путями; внутри image рекомендуются `/config/*`.
  Client: `dns: true`, `tun: "cvpn0"`, CA, TLS-имя и PSK. Exit: certificate/key
  и peer PSK (до 32 разных `peers`, каждому свой адрес и ключ).
- Config/CA/profile доступны только для чтения. PSK — **32 сырых байта**, owner
  UID 0, mode 0600. Конфиг и остальные файлы не writable для group/others.
- `/run` — частный tmpfs контейнера; журнал содержит namespace/fingerprint и
  фазы подготовки. Готовый журнал при повторном запуске проверяется вместе
  с реальными rules/TUN/routes. Частично завершённый setup требует нового
  namespace; защита автоматически не снимается.
- `CVPN_PARENT_NETNS=net:[N]` — идентификатор сети Linux container host,
  полученный readonly probe. Совпадение с текущим namespace запрещает запуск
  **до изменений**. Это защита от ошибки оператора, не граница против root,
  который намеренно подменил anchor или имеет NET_ADMIN.
- Изменяются только собственные цепочки `CVPN_R_*`, TUN и маршруты namespace.
  Чужие цепочки сохраняются; свои jumps ставятся первыми. IPv6 за пределами
  loopback блокируется. Недоступность firewall API — отказ, без fallback.
- `CVPN_IPTABLES_BACKEND=nft` по умолчанию. `legacy` выбирается только явно;
  одновременно применять разные API к одному namespace не следует.

DNS всех приложений в namespace, включая Docker `127.0.0.11`, направляется
в native listener `peer_ipv4:1053`. Native upstream sockets помечены и идут
строго через TUN к текущим фиксированным upstream `1.1.1.1`/`8.8.8.8`.
Health client делает живые UDP **и** TCP DNS запросы через этот listener;
успешный PID или ранее записанный `ready` не достаточны. Health exit означает
только готовый listener; полный exit проверяется клиентом. Никакой записи
`/etc/resolv.conf` хоста, запуска resolved или изменения системного DNS нет.

## Сборка образа

Контекст формируется allowlist-скриптом: в него не попадают `.git`, ключи,
пользовательские конфиги, `certs.tar.gz` и лабораторные образы.

```bash
node scripts/clean-vpn-native-runtime-context.mjs /tmp/cvpn-runtime-context
podman build --format=docker --platform=linux/arm64 --build-arg JOBS=2 \
  -f /tmp/cvpn-runtime-context/scripts/containers/clean-vpn-native-runtime.Containerfile \
  -t localhost/clean-vpn-native:local /tmp/cvpn-runtime-context
```

Для Docker заменить `podman build --format=docker` на `docker build`.
Для amd64 выбрать `--platform=linux/amd64`. Требуется новая директория контекста.
На Mac все команды Podman выполнять с
`--connection=meshpn-clean-vpn-lab-root`, включая build: image должен попасть
в тот же rootful engine, в котором запускается launcher.
Платформа сборки не доказывает работу TUN/netfilter под userspace-эмулятором:
amd64 netfilter не заработал через Rosetta на ARM Podman VM; amd64 standalone
проверен в QEMU с настоящим x86 ядром. Смотрите матрицу отчёта.

Базовый Ubuntu multiarch index закреплён digest; BoringSSL/nghttp2/Brotli —
репозиторными SHA. APT использует подписанные текущие репозитории: это пока
**не побитово воспроизводимый APT snapshot**. Runtime содержит
`/usr/local/bin/engine.sha256` и `/opt/clean-vpn/source-provenance.json` с SHA
реальных исходников. В test-only режиме `ENGINE_STAGE=artifact` можно упаковать
проверенный бинарник из `artifacts/`; это отмечается отдельно от source build.
Нельзя подкладывать бинарник другой архитектуры или выдавать такой build за
повторную компиляцию. Runtime не включает компилятор, git, QEMU или test engine.

## Запуск контейнера

Сначала создайте отдельную bridge network средствами выбранного container
engine. Подготовьте **свои** credentials/config. Никаких ключей в образе нет.
Пример client config (IP и имена заменить своими):

```json
{
  "version": 1,
  "role": "client",
  "address": "192.0.2.10",
  "port": 443,
  "tun": "cvpn0",
  "dns": true,
  "peer_ipv4": "10.99.0.2",
  "server_name": "vpn.example.net",
  "ca": "/config/ca.pem",
  "secret_path": "/config/psk",
  "tls_profile_path": "/config/profile.json"
}
```

В `profile.json` можно сохранить репозиторный
`fixtures/native-tls-profiles/chromium-156-bounded-cold.json`. Это ограниченный
cold Chromium-derived профиль, не полное воспроизведение Chrome. Совпадение
JA3/JA4 не означает одинаковые HTTP/2 запросы, TCP stack или поведение браузера.

```bash
node scripts/clean-vpn-native-container.mjs start --engine=docker \
  --name=cvpn-client --role=client --image=clean-vpn-native:local \
  --network=cvpn-uplink --config-dir=/absolute/private/client-config
node scripts/clean-vpn-native-container.mjs status --engine=docker --name=cvpn-client
```

Для Podman: `--engine=podman`, на Mac дополнительно
`--connection=meshpn-clean-vpn-lab-root`. Mac работает через выделенную Linux VM;
маршруты/Wi-Fi/DNS macOS не перенастраиваются. Bind-файлы должны иметь корректного
владельца **в Linux namespace**; альтернативно используется подготовленный
`--config-volume=NAME` с файлами UID 0. `--config-file=client.json` меняет имя
внутри `/config`, по умолчанию `engine.json`.

Exit запускается аналогично с `--role=exit`, статическим `--ip=...` в выбранной
network и config `address`, равным этому IP. Для внешнего входа на порт 443
добавить `--publish=443` (port config должен быть 443). Это явная публикация
порта Linux container host; без `--publish` наружу ничего не публикуется.
На client порты не публикуются. Existing legacy сервисы launcher не останавливает.

Launcher использует read-only rootfs, `--cap-drop=ALL`, только NET_ADMIN,
NET_RAW, NET_BIND_SERVICE, `/dev/net/tun`, no-new-privileges и private `/run`.
Лимиты launcher: 256 MiB RAM и 128 процессов/потоков; это ограничение ресурсов,
а не обещание производительности или приёмка 32 одновременно нагруженных peers.
У exit включается **namespaced** ip_forward. Нет `--privileged`, host networking,
restart policy/autostart. Сначала дождитесь `healthy`, затем запускайте приложение:

```bash
docker run --rm --network=container:cvpn-client --cap-drop=ALL \
  YOUR_APPLICATION_IMAGE
node scripts/clean-vpn-native-container.mjs stop --engine=docker --name=cvpn-client
node scripts/clean-vpn-native-container.mjs remove --engine=docker --name=cvpn-client
```

Для удаления проверяется ownership label; чужой контейнер с похожим именем
не удаляется. Сначала удалите контейнеры приложений, использующие его network
namespace, затем удалите VPN-контейнер. Podman требует этого даже для остановленных
приложений; launcher не удаляет их автоматически.
Если приложение удерживает старый namespace после аварии, оно остаётся
заблокированным. Новый client не переподключает такое приложение автоматически:
его нужно пересоздать в сети нового client. PSK/CA/profile приложениям не нужны.

## Явный LAN/gateway ingress

Опционально: `--lan-network=NAME --lan-ip=192.168.88.2
--lan-subnet=192.168.88.0/24` у launcher client. Это **вторая контейнерная
network**. Launcher явно выбирает `CVPN_UPLINK=auto` и `CVPN_LAN_INTERFACE=auto`:
интерфейсы определяются по маршруту до exit и единственному совпадению LAN
подсети. Это учитывает перестановку ethN при Docker restart. LAN network должна быть internal,
без второго default route. Runtime проверяет интерфейс/подсеть и запрещает
совпадение с uplink. Сейчас принимаются только сети `192.168.0.0/16` с /16–/30.

Клиент LAN должен явно использовать этот адрес шлюза. DNS ingress перехватывается
в native relay; пакеты SNAT к peer IPv4 и идут только в TUN, TCP MSS ограничен.
Потеря engine не открывает прямой forward в uplink. Эти сценарии проверяются
отдельным LAN namespace в лаборатории. Хостовый `wg0`/`usb0` **не появляется** в
контейнере автоматически. Подключение физического интерфейса/host bridge,
правила DHCP и маршруты реальных LAN устройств — отдельная операция;
данный launcher её не выполняет. DNS-прокси хоста не превращается в ingress.

Host-side policy routing, ingress DNS, IPv6 guard и аварийный rollback
проверены отдельно в [модели Linux-шлюза](clean-vpn-native-runtime-host-wiring.md).
Это не установка на физический интерфейс: в NIC-less VM моделируется `usb0`
и проверяется сохранение второго LAN, локального rescue и сети самого шлюза.

## Compose и standalone

`scripts/containers/native-runtime.compose.yml` — opt-in pair на одном container
host, с адресами exit `172.30.77.2`, client `172.30.77.3`. Для обоих config
`address` — `172.30.77.2`. Образы и credentials готовятся отдельно. Anchor:

```bash
export CVPN_IMAGE=clean-vpn-native:local
export CVPN_PARENT_NETNS="$(docker run --rm --network=host --cap-drop=ALL \
  --entrypoint=readlink "$CVPN_IMAGE" /proc/self/ns/net)"
export CVPN_EXIT_CONFIG=/absolute/private/exit-config
export CVPN_CLIENT_CONFIG=/absolute/private/client-config
docker compose -f scripts/containers/native-runtime.compose.yml up -d
docker compose -f scripts/containers/native-runtime.compose.yml down
```

Readonly anchor probe не меняет сеть. Compose-файл не устанавливает сервисы
на постоянку и не публикует порты. Проверку syntax и фактический Compose run
следует различать — см. отчёт.

В изолированном Docker ARM64 проверен и сам шаблон: `up`, healthy обоих ролей,
DNS UDP/TCP и HTTPS через fixture upstream, затем `down` и удаление сети.
Это не проверка маршрутизации физических LAN устройств.

Standalone использует тот же скрипт подготовки и тот же binary, в уже
подготовленном отдельном Linux netns. Снаружи сохранить
`CVPN_PARENT_NETNS=$(readlink /proc/self/ns/net)`, внутри задать
`CVPN_ENGINE=/absolute/clean-vpn-engine`, `CVPN_CONTROL_DIRECTORY=/absolute/repo/scripts`,
`CVPN_STATE_DIRECTORY=/run/clean-vpn-NAME` и выполнить
`sh /absolute/repo/scripts/containers/native-runtime-entrypoint.sh /absolute/engine.json`.
Network namespace и state directory должны принадлежать именно этому запуску.
При выходе guard сохраняется; уничтожение принадлежащего запуску namespace
освобождает его TUN/routes/firewall. Не запускайте это непосредственно в netns
реального хоста. Создание physical host-side wiring этот скрипт не берёт на себя.

## Проверки и отсечка

`clean-vpn-native-runtime-lab.mjs NEW_REPORT.json` управляет уникальными временными
container/volume/network, всегда выполняет cleanup. `CVPN_CONTAINER_COMMAND`
— JSON argv выбранного **лабораторного** engine, `CVPN_RUNTIME_IMAGE` — image,
`CVPN_OBSERVER_IMAGE` — отдельный tcpdump image. `CVPN_GATEWAY=1` добавляет LAN,
`CVPN_SOAK_SECONDS=3600` — ограниченный часовой прогон с малым трафиком,
RSS/FD/socket/thread/process counters и restart каждые пять минут. Считаются
также zombie processes и TCP ESTABLISHED/TIME_WAIT. Задержки `*WallMs` включают
container exec и измеряют длительность всей проверки, **не сетевой RTT**.
`transactionLatency` измеряется уже внутри приложения: DNS UDP/TCP отдельно,
HTTPS request с новой TLS-сессией, TCP echo и UDP echo. Это небольшие запросы
к fixture origin в той же лаборатории, не задержки реального Интернета и
не throughput benchmark. Завершённые samples сохраняются и при позднем отказе;
`restartEvents` отмечают намеренные остановки и возвращение readiness.
Для короткого повторения restart regression есть `CVPN_SOAK_RESTART_SECONDS`
(по умолчанию 300, допустимо 5–600; проверяется между probe-итерациями).
Свидетель удерживает старый namespace: его foreign sentinel проверяется после
рестарта, а новый namespace получает новый sentinel fixture. Номера inode
без такого удержания могут повторно использоваться ядром. Runtime сохраняет
чужие правила существующего namespace, но не переносит чужую политику из
уничтоженного namespace в новый контейнер.
Не запускайте несколько таких прогонов
параллельно в одном daemon: используются фиксированные изолированные подсети.

Пример повторения короткого полного smoke в **выделенной** Podman VM:

```bash
podman --connection=meshpn-clean-vpn-lab-root build --format=docker \
  --build-arg RUNTIME=localhost/clean-vpn-native:local \
  -f scripts/containers/native-runtime-observer.Containerfile \
  -t localhost/clean-vpn-observer:local scripts/containers
mkdir -m 700 /tmp/cvpn-runtime-results
CVPN_CONTAINER_COMMAND='["podman","--connection","meshpn-clean-vpn-lab-root"]' \
CVPN_RUNTIME_IMAGE=localhost/clean-vpn-native:local \
CVPN_OBSERVER_IMAGE=localhost/clean-vpn-observer:local \
CVPN_GATEWAY=1 CVPN_TEST_LAUNCHER=1 \
  node scripts/clean-vpn-native-runtime-lab.mjs /tmp/cvpn-runtime-results/run.json
```

Для Docker на отдельном Linux test host: `CVPN_CONTAINER_COMMAND='["docker"]'`.
Нужен новый путь отчёта. Для soak добавить `CVPN_SOAK_SECONDS=3600`.

`clean-vpn-native-runtime-vm.mjs NEW_REPORT.json` работает из существующего
Linux toolchain image и создаёт NIC-less QEMU guest. Проверяет standalone на
настоящем x86 kernel, а не эмуляцию netfilter syscalls через Rosetta.
Независимый observer читает pcap, не логи engine; алгоритмы JA3/JA4 общие с
репозиторным sniffer, что явно отмечается в report. Сырые capture/ключи не
попадают в git. Capture сохраняется рядом с приватным отчётом как `.json.pcap`,
mode 0600, и может быть независимо разобран тем же sniffer ещё раз.
Остановка контейнера не является reboot физического клиента.

## Экспериментальные транспорты и replay volume

| Режим | Проверка runtime-упаковки | Публичный launcher |
|---|---|---|
| `boring-tls` | TUN, DNS, profile, приложение и LAN, lifecycle/soak | Поддерживается в описанном isolated-netns контракте |
| `transparent-tls` | Production engine, SO_ORIGINAL_DST, настоящий TLS relay, durable replay после пересоздания | Пока отклоняет конфиг |
| `combo-tls` | Production engine, аутентификация boring-ветки и TLS relay через один exit listener, durable replay | Пока отклоняет конфиг |
| `tls` из Node реализации | Не отдельный C++ transport | Нет |

Новый совместимый с runtime-образом тест:

```bash
CVPN_CONTAINER_COMMAND='["podman","--connection","meshpn-clean-vpn-lab-root"]' \
CVPN_RUNTIME_IMAGE=localhost/clean-vpn-native:local \
  node scripts/clean-vpn-native-runtime-replay-lab.mjs /tmp/cvpn-runtime-results/replay.json
```

Проверены ARM64 Podman и настоящий Docker в выделенной Linux VM.
Для Docker задать `CVPN_CONTAINER_COMMAND='["docker"]'`.
Это `--network=none` контейнеры
без опубликованных портов, с отдельным временным state volume и read-only rootfs.
Поверх production engine работает **тестовый** controller/origin/byte observer;
они не включены в runtime image и не заменяют runtime launcher.

Каждый transport проходит явную инициализацию replay, отказ без инициализации,
отказ повторной инициализации и второго владельца, настоящий TLS-запрос,
SIGKILL всего контейнера, read-only mount отказ и пересоздание с тем же volume.
Перехваченный ClientHello не открывает origin повторно; свежий запрос работает.
Для исключения ложного успеха из-за expiry/corruption тот же перехваченный
токен принимается в **другом, явно инициализированном тестовом состоянии**.
Рабочее replay state при этом не сбрасывается. Config/PSK/capture и volume
удаляются ownership cleanup; в отчёте остаются hashes и названия проверок.

Второй владелец проверяется со свободным портом и отдельным TUN, чтобы отказ
не оказался обычным bind/EBUSY. После освобождения replay lock этот же конфиг
успешно запускается. Для read-only combo-проверки TUN также заранее создан:
отсутствующий интерфейс не может подменить проверку недоступной записи state.

Дополнительные `SETUID/SETGID` нужны только fixture: тестовое приложение
работает от UID 65534, а REDIRECT выбирается по owner, чтобы exit не перехватил
свой origin socket. Production boring launcher этих capability не получает.

Для combo в этом тесте подтверждены аутентификация packet-ветки и relay,
но не передача IP payload через TUN или маршрутизация gateway. Такая
проверка совместимости не закрывает production container lifecycle для
combo/transparent: ещё нужны их provisioning/guard/recovery и health contract.
Наличие durable volume само по себе не разрешает автоматически делать
`--init-transparent-replay` при каждом запуске или потере состояния.

Lab записывает приватный `.ownership.json` до создания ресурсов. При аварии
управляющего процесса `clean-vpn-native-runtime-cleanup.mjs OWNERSHIP.json`
проверяет owner/mode журнала, точный случайный prefix **и** labels контейнеров,
volume и network. Без совпадения cleanup отказывает. Это отдельный recovery
для лаборатории, подходящий для `ExecStopPost` временного systemd unit;
он не управляет production VPN или чужими контейнерами.
