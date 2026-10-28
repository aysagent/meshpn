# MeshPN: админка Radxa через USB

Для OpenWrt подготовлен отдельный [план локальных пакетов и LuCI](../scripts/clean-vpn-openwrt.md)
с захватом профиля и независимым наблюдателем. Текущий installer ниже предназначен
для Radxa; OpenWrt-пакеты пока не реализованы.

На проверенной Radxa: **http://mpn.local/**, запасной адрес
**http://192.168.7.1/**. Первый пароль **`admin`**. Перед изменением настроек
его нужно сменить в разделе «Устройство». После смены требуется новый вход.
Админка использует HTTP на доверенном USB-кабеле; пароль/сессия не шифруются
HTTP. Не публикуйте этот порт в LAN или интернете.

## Что доступно

- Node API + отдельная веб-страница, без npm-зависимостей на плате.
- Время именно в timezone платы, температура, нагрузка по ядрам, RAM/swap,
  счётчики интерфейсов, состояние Wi-Fi, служб VPN и kill switch.
- Включение/остановка/restart установленной VPN-службы. Остановка VPN не
  отключает защиту. Отключение kill switch требует явного подтверждения и
  останавливает VPN, чтобы штатный владелец сначала убрал свои DNS/route rules.
  Защита OFF — разрешение прямого выхода. После reboot штатная guard-служба
  снова включается; это **временное**, не постоянное отключение автозащиты.
- До 256 отдельных Wi-Fi-профилей: SSID, WPA2 Personal/open, пароль,
  приоритет, hidden, enabled, scan, connect, delete. Старые сети Netplan
  не импортируются и не переписываются. Новые профили хранятся отдельно;
  broker восстанавливает их после старта/перезапуска wpa_supplicant.
- Имя `name.local` только на usb0 через Avahi; Linux hostname не меняется.
  Если имя занято или mDNS недоступен, USB-IP остаётся запасным входом.
- Native boring-tls: SNI, имя сертификата, выбор/import сохранённого профиля.
  Перед сохранением — настоящий `engine --check-config`. При привязке свежей
  админки через `--native-name` настройки применяются к установленному native
  instance с журналом и откатом; start/stop управляют его сетевым owner.
  Существующая физическая админка пока не перепривязана: без `nativeManaged`
  сохраняется только **candidate**. Новую привязку проверили в Linux-лаборатории.
- DNS/HTTPS/ICMP-пробы, последние 120 строк журнала, выгрузка диагностики.
- `/capture`: отдельный TLS/H2 сервер на USB:8443, 3 минуты, до 32 образцов,
  token/authority validation, bundle с JA3/JA4, структурой Hello, H2 и
  несовместимостями. Совместимый кандидат можно отправить на native-проверку
  и сохранить. Он не активируется автоматически.
- Независимый наблюдатель: настоящий tcpdump на Wi-Fi к текущему exit,
  5–60 секунд, до 5000 пакетов/16 MiB. JA3/JA4 и поля берутся из pcap,
  сравниваются с выбранным candidate-профилем. Исходный pcap можно скачать.

Смена endpoint пока отклоняется: сначала требуется согласованная миграция
маршрута к exit и разрешений guard. DNS upstream в данном native engine
фиксированы, поэтому редактирование не имитируется. Правила IP/domain/GeoIP,
WPA3/Enterprise, AP и управление другими транспортами ещё не реализованы.
`active` у systemd не доказывает рабочий интернет — используйте отдельную пробу.
Совпадение профиля не означает полную неотличимость от браузера.

Применение native-настроек использует приватный журнал
`vpn-settings-transaction.json` в state broker. Перед перезапуском сохраняются
прежние config/settings; при ошибке они восстанавливаются. После обрыва broker
восстановление завершается до открытия API. Ручные изменения этих файлов во
время операции вызывают отказ, а не перезаписываются. При незавершённом откате
журнал сохраняется, новые изменения блокируются; состояние видно в
`vpnSettingsRecovery` диагностики. Журнал содержит конфигурацию и имеет режим
`0600`; его не следует публиковать.

Для работающего native-клиента требуются активный guard, `Type=notify` и
подтверждение `ready` от движка после рестарта. Это проверка TLS/VPN handshake,
не проверка доступности всех сайтов. Если VPN остановлен, настройки сохраняются
с `requiresStart=true`, без автоматического включения. Без `nativeManaged` конфигурация сохраняется без активации. Порядок восстановления
при холодной загрузке задают native network/engine/clock units, не веб-сервер.

## Установка и systemd

Installer сейчас предназначен **для проверенного existing-host профиля Radxa**,
с установленным native `--host-profile`, cvks4 guard и USB 192.168.7.1/24. Старый
Node VPN не требуется. Он не подходит
для произвольной Linux-машины. Сначала читается plan:

```sh
sudo /absolute/path/to/node admin/install.mjs --plan --native-name=daily
sudo /absolute/path/to/node admin/install.mjs --apply --native-name=daily
```

`--apply` проверяет владельцев/порты/USB, копирует текущий Node и исходники в
`/opt/meshpn-admin`, создаёт системного пользователя `meshpn-admin`, приватные
state-каталоги и три unit. Используется config уже выбранной native-установки;
её профиль не подменяется. VPN не включается установщиком админки. Netplan и
конфигурация системного resolver не меняются. Автозапуск:
`meshpn-admin-broker.service` и `meshpn-admin.socket`; web активируется сокетом.

**Граница доступа:** systemd слушает 192.168.7.1:80/8443 с
`BindToDevice=usb0`. Node дополнительно проверяет локальный IP, USB subnet,
Host/Origin, сессию и CSRF. Web работает непривилегированно. Root broker имеет
только UNIX socket и фиксированный набор операций, без произвольных команд,
путей, systemd unit names или Docker socket из API.

mDNS нужен UDP 5353 к 224.0.0.251 на usb0. Свежая native-установка требует
актуальный guard с поддержкой аудита этого правила; installer админки не
заменяет guard script. Broker добавляет/убирает одну
помеченную OUTPUT-запись, ограниченную source 192.168.7.1, usb0 и UDP5353.
Изменения guard по-прежнему требуют первого hook и отказываются при чужих
правилах. При остановке broker mDNS-запись удаляется через ExecStopPost.

Наблюдатель запускается отдельным transient systemd unit с UID `meshpn-admin`,
единственной capability `CAP_NET_RAW`, без promiscuous mode. systemd ограничивает
время и завершает процесс независимо от браузера/broker; `CAP_KILL` broker
не выдаётся. Сервер захвата browser TLS не получает root-доступ.

```sh
# После git pull. Сохраняет пароль, сети и настройки; остановит только админку.
sudo /absolute/path/to/node admin/install.mjs --update
# Остановить/отключить собственные службы, убрать mDNS-rule и вернуть guard script:
sudo /absolute/path/to/node admin/install.mjs --remove
```

Удаление сохраняет state, исходники и аккаунт для проверки; свежая установка
на те же пути намеренно откажется. Нельзя одновременно менять эти файлы другим
администратором. Для потерянного пароля: остановить только web, сохранить
`/var/lib/meshpn-admin-web/auth.json` под root, убрать этот файл, снова запустить
web — будет создан `admin`. Это локальная root-операция, не HTTP endpoint.

## Docker / Podman

Контейнеризуется **web/API**, а broker и USB socket activation остаются на
Linux-хосте. Контейнеру не выдаются root, privileged mode, системная D-Bus,
`/etc` целиком, raw sockets, network-admin или Docker/Podman socket.

```sh
# На Linux Radxa после обычной установки, из корня репозитория:
export MPN_ADMIN_UID=$(id -u meshpn-admin)
export MPN_ADMIN_GID=$(id -g meshpn-admin)
docker compose -f admin/containers/compose.yml build
docker compose -f admin/containers/compose.yml up -d
sudo /absolute/path/to/node admin/install.mjs --container
```

Для Podman применим тот же compose-файл через установленный compose provider
(`podman compose ...`), либо эквивалентный `podman run` с теми же mount/UID,
read-only root, cap-drop ALL, no-new-privileges и host network. Для указанного
UID и host broker требуется rootful runtime. Автозапуск runtime/compose должен
быть включён средствами его Linux-хоста; `restart: unless-stopped` задан.

Контейнер слушает **только loopback** 8080/18443. Снаружи работают прежние
USB-bound systemd sockets 80/8443 и непривилегированный двухпортовый proxy.
Таким образом контейнерная упаковка не ослабляет ограничение по интерфейсу.
Не добавляйте `ports: 0.0.0.0...`. Если контейнер остановлен, админка недоступна,
но VPN/guard продолжают работать. Пароль/state общие с standalone.

```sh
# Вернуться к standalone web, затем остановить контейнер:
sudo /absolute/path/to/node admin/install.mjs --standalone
docker compose -f admin/containers/compose.yml down
```

Mac используется только как браузер и хозяин изолированной Podman-лаборатории.
Ни installer, ни broker не работают на macOS; сеть Mac не перенастраивается.

## Захват браузера

1. Войти, сменить `admin`, открыть `/capture`, указать реальную версию/платформу.
2. Запустить, скачать сертификат, установить доверие **в тестовом окружении
   браузера**. Админка не устанавливает CA на компьютер. Защиту сертификатов
   native VPN не отключать.
3. Открыть ссылку захвата из трёх независимых cold browser processes. Простая
   перезагрузка вкладки часто использует то же TLS-соединение.
4. Скачать bundle и изучить `assessment`. При `unsupported` или `inconsistent`
   нельзя выдавать его за воспроизводимый профиль. Совместимый кандидат сначала
   проверяется engine, затем отдельно выбирается в VPN.
5. Наблюдатель включается **до** нового соединения client-exit. Его pcap можно
   независимо разобрать `scripts/clean-vpn-pcap-fingerprints.mjs`. Профиль сравнивается с фактическим клиентским соединением, а не только с
   конфигурацией engine.

Identity/trust context в bundle заявляется оператором, а не аттестуется.
Сырой pcap содержит реальные сетевые метаданные и TLS-пакеты; держите его
приватным. Никакие ключи VPN и пароли Wi-Fi API не возвращает.

## Проверки

```sh
node --test admin/test/admin.test.mjs scripts/test-native-browser-capture.mjs
# Linux / Bash 4+:
node --test scripts/test-killswitch-plan.mjs
podman build -t meshpn-admin-test -f admin/containers/Containerfile .
podman run --rm --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --tmpfs /tmp:rw,size=64m \
  meshpn-admin-test node admin/test/container-smoke.mjs
# Аналогично: node admin/test/socket-proxy-smoke.mjs
```

Фактические результаты и ограничения: [отчёт ночного этапа](NIGHT-REPORT.md).
DNS migration — [только исследование](../scripts/clean-vpn-radxa-dns-migration.md).

Дополнительные локальные проверки без Radxa/VPS:

```sh
node --test admin/test/vpn-settings-transaction.test.mjs admin/test/admin.test.mjs
npm run lab:native:mac -- --native-admin
node admin/test/systemd-container-lab.mjs
```

Последняя команда требует запущенную выделенную Podman machine
`meshpn-clean-vpn-lab` и кешированный ARM64 runtime image
`localhost/clean-vpn-native-runtime:final-arm64`. Она собирает два временных
контейнера из Git-tracked исходников: systemd/broker/native fixture и обычный
frontend. Сеть fixture — `none`, frontend разделяет только его namespace;
порты на Mac не публикуются. Временные контейнеры и volumes удаляются в `finally`.
Отчёт последнего успешного запуска сохраняется в `admin/test/last-container-report.json`.

Проверяются реальное TLS-соединение и TUN/DNS, применение профиля, откат неверного
TLS-имени, остановленный VPN, SIGKILL broker во время запуска candidate, сохранение
guard и systemd `BindToDevice` на veth с именем usb0. Только systemd fixture имеет
SYS_ADMIN/NET_ADMIN/NET_RAW; frontend — UID 65534, read-only rootfs, без capabilities.
В этом fixture отключены PSI и `ProtectControlGroups` у вложенных native units;
полный host unit проверяется отдельно в QEMU. На SELinux обе части fixture имеют
общие `container_init_t`/MCS, чтобы Unix RPC был разрешён без отключения SELinux.
Это проверка интеграции, **не** готовая SELinux-политика установки на произвольный
хост. Физический USB/Wi-Fi, WAN, перезагрузка и обновление бинарника этим прогоном
не подтверждаются.

### Standalone network owner

`broker.json` содержит `vpnUnit` для C++ engine и `networkUnit` для владельца
TUN/routes/DNS/NAT. Кнопки VPN управляют `networkUnit`; зависимый engine
останавливается через BindsTo. После включения broker ждёт готовность engine.
Параметры браузерного профиля перезапускают только engine, сохраняя сеть.
Смена IP/порта exit пока требует отдельного согласованного изменения guard и
network config. Статус и журнал сетевой службы доступны отдельно.

Существующая админка не перепривязывается командой `--update`: сначала нужно
выбрать и проверить native instance и его разрешения записи. Свежая установка
отказывает при коллизии файлов/пользователя, ничего не перезаписывая.

Локальная проверка 29 октября: 23 unit tests и 9 сценариев настоящего systemd
с C++ client/exit, свежим installer, входом в web, profile apply и stop/restart.
[Отчёт](../fixtures/clean-vpn-native-host-admin-report.json) содержит хеши исходников.
Контейнерный стенд очищает только `BindToDevice` в собственном socket drop-in,
поскольку у его PID1 нет udev device units. Привязка к адресу/subnet остаётся;
этот прогон не доказывает аппаратную USB socket activation.

```sh
# Только выделенная Linux-лаборатория; без host mounts и опубликованных портов.
podman build -t meshpn-admin-systemd-lab:local -f admin/test/systemd-host.Containerfile .
podman build -t clean-vpn-host-admin-lab:local -f admin/test/native-host.Containerfile .
podman run -d --name cvpn-host-admin-lab --privileged --network=none \
  --systemd=always --memory=1g --pids-limit=512 clean-vpn-host-admin-lab:local
podman exec -e CVPN_DISPOSABLE_HOST_ADMIN=1 cvpn-host-admin-lab \
  node /project/scripts/lib/native-host-admin-lab.mjs
podman stop cvpn-host-admin-lab
podman rm cvpn-host-admin-lab
```
