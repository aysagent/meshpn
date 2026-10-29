# Самостоятельный native lifecycle на существующем хосте

Физическая установка `daily` уже активна с автозапуском:
[результаты reboot, админка и команды](clean-vpn-native-daily-20261029.md).
Сам installer по-прежнему устанавливает выключенные службы и не активирует их неявно.

Checkpoint 2026-10-29. Новый `--host-profile` устанавливает выключенный сетевой
owner для проверенного Radxa IPv4-профиля. Старый Node.js VPN не запускается,
не анализируется и не восстанавливается. Node остаётся только control plane;
TUN payload, TLS и DNS обслуживает C++ engine.

## Ограниченный контракт

- boring-tls client, `tun0`, peer IPv4 `10.99.0.2–10.99.0.254/32` (по умолчанию `.2`), MTU 1400, native DNS включён;
- uplink `wlan0` с единственным IPv4 default gateway;
- USB `usb0`, `192.168.7.1/24`, уже настроенный forwarding=1;
- независимый активный cvks4 guard both/block с тем же exit и SSH port 22;
- старые VPN/TUN и USB SNAT owner заранее остановлены; существующий TUN не принимается;
- guard, USB rescue, dnsmasq, resolver-файлы, Wi-Fi и чужие службы не перенастраиваются;
- нет конкурирующего администратора собственных маршрутов/DNS/NAT;
- этот профиль не является универсальным установщиком Linux или exit.

Пример приватного host profile (не команда автоматического применения на плате):

```json
{"version":1,"guard_unit":"clean-vpn-killswitch.service","guard_script":"/usr/local/bin/clean-vpn-killswitch.sh"}
```

Передать установщику `--host-profile=/absolute/host.json` вместо внешнего
`--network-unit/--guard-unit` или dedicated `--site-profile`. Engine config,
CA/PSK и опциональный clock-profile передаются обычным способом.
Установщик публикует файлы, но ничего не запускает и не включает.
После проверки активируется `native-NAME-network.service`, а не engine напрямую.
Сам C++ остаётся отдельным systemd MainPID `native-NAME.service`.

Минимальный **план установки**, без запуска и без публикации файлов:

```sh
node scripts/clean-vpn-native-install.mjs \
  --name=daily \
  --binary=/absolute/clean-vpn-engine \
  --config=/absolute/private/client.json \
  --host-profile=/absolute/private/host.json
```

`client.json` содержит абсолютные пути CA/PSK/profile; `host.json` — объект
выше. Файлы private root-owned 0600, каталоги без небезопасных writable parents.
Для работы owner нужны Node по сохранённому абсолютному пути, Python 3,
iproute2, iptables, util-linux/flock и systemd. Сам installer проверяет native
config/capabilities, но его успешный plan не заменяет live network preflight.

После отдельной публикации с `--apply` и `systemctl daemon-reload` проверка
установленного instance:

```sh
node /opt/clean-vpn-native/daily/control/clean-vpn-native-host-network.mjs \
  preflight --config=/opt/clean-vpn-native/daily/network.json
systemctl show native-daily-network.service native-daily.service \
  -p Id -p ActiveState -p MainPID -p Result -p StatusText
```

Штатные команды для уже выбранной установки: `systemctl start
native-daily-network.service`, `systemctl stop native-daily-network.service`,
`journalctl -u native-daily-network.service -u native-daily.service -n 80 --no-pager`.
`active` сетевого owner не означает готовый туннель: проверяются также notify
engine и отдельные DNS/HTTPS пробы. `enable` не является частью проверки;
физическая постоянная активация в текущем поручении отложена. Для временного
удалённого испытания требуется отдельный ограниченный по времени stop/recovery,
как в выполненном physical trial; простой `start` такого ограничения не создаёт.

## Владение и восстановление

Сетевой owner удерживает namespace lock и журнал в `/run`. TUN создаётся
непостоянным, получает уникальный alias и только затем становится persistent.
Прерывание до persistence удаляет TUN вместе с FD; после persistence восстановление
проверяет alias, а после фиксации identity — также ifindex. Подмена означает отказ.

Существующие host-route/DNS journals сохраняют intent перед изменением и удаляют
только собственные операции. USB SNAT и два MSS-правила имеют отдельный случайный
owner tag. Нет flush или восстановления снимка чужой таблицы.
DNS перенаправляется в native listener; его временная недоступность не разрешает
прямой upstream. Файлы системного DNS и конфигурация dnsmasq не меняются.

Engine зависит через BindsTo/After от owner и guard. `ExecStopPost` отдельно
восстанавливает сеть после штатного stop или SIGKILL owner, проверяя остановку
engine. Guard не снимается. SIGKILL engine допускает его обычный systemd restart
без пересоздания сети. Сбой owner запускает recovery перед новой попыткой.
Журнал `/run` same-boot; это не сохранение kernel state между загрузками.

## Проверки на этом checkpoint

- 21 проверка в настоящем ARM64 Linux netns (потеря default route и смена instance): TUN/DNS/routes/NAT, повторный запуск,
  intent cut-points, чужой alias, active engine, guard failure, точный возврат
  исходных настроек и сохранение sentinel. Systemd-состояние в этой матрице injected.
- 14 сценариев в отдельном systemd-контейнере без внешней сети: настоящие native
  client/exit, USB HTTPS, UDP/TCP DNS, engine SIGKILL, owner SIGKILL/ExecStopPost,
  stop/restart, отказ/возврат exit, отсутствие direct fallback.
- 23 Linux-регрессии установщика boring/transparent/combo/clock/host — PASS.
- На Mac базовый installer test использует `/tmp` и отказал на symlink_destination;
  тот же тест пройден на Linux. Kernel netns-тест через amd64 эмуляцию не получил
  поддержку iptables; успешная матрица выполнена на native ARM64.

Дополнительно прошли три настоящие загрузки QEMU с ext4 state disk, 30 checks:
установка, autostart, native update/rollback, crash recovery owner, guard failure.
[Отчёт](../fixtures/clean-vpn-native-host-boot-report.json). Сохранены ограничения:
fixture-сеть, восстановление артефактов в initramfs, без time fault и физического
power loss. В nested TCG на cleanup+повторный запуск требуется больше 90 секунд;
для VM использован конечный бюджет 240 секунд. Найденная гонка stop с синхронным аудитом исправлена через `KillMode=mixed`: SIGTERM
получает основной процесс, остаточные дети уничтожаются после его выхода или
таймаута. Отдельная ARM64 systemd-матрица теперь содержит 11 проверок, включая
принудительную остановку во время задержанного дочернего audit command.

На ядрах Radxa и VPS прошла предыдущая матрица 18 checks в отдельных net/mount
namespace с tmpfs `/run`, без изменения их рабочей сети. Вслед за этим прошёл короткий [физический smoke](../fixtures/clean-vpn-native-host-physical-report.json):
boring-tls client → packet branch combo exit, DNS/HTTPS, engine SIGKILL, cleanup
и два независимо снятых ClientHello, совпавших с профилем. Полный leak/soak,
physical power loss и ежедневная установка этим не подтверждаются.

Воспроизведение kernel matrix: `CVPN_DISPOSABLE_HOST_NET=1 node
scripts/test-native-host-network-linux.mjs` только в отдельном пустом netns.
Systemd fixture: `CVPN_DISPOSABLE_HOST_SYSTEMD=1 node
scripts/lib/native-host-systemd-lab.mjs` только в одноразовом NIC-less Linux
systemd окружении, с кодом в `/project` и engine в `/usr/local/bin`.


Для boot-матрицы на Mac используется существующая выделенная Podman-лаборатория:

```sh
node scripts/clean-vpn-native-macos-lab.mjs --native-host-boot
```

Установщик использует фактический путь Node (в том числе NVM). Не удаляйте эту
версию Node, пока на неё ссылается network unit. При отсутствии uplink guard/DNS
остаются закрытыми; service restart не исчерпывает фиксированный start-limit.


Контроллер ждёт собственный `wlan0` через preflight/retry. Общий
`network-online.target` не запрашивается: на Radxa он ожидал неиспользуемые
интерфейсы и задержал первый физический запуск. Guard остаётся обязательным.
Остановка старого `clean-vpn-usb-snat.service` сама по себе не удаляет его три
правила; перед первым native запуском их убирают штатным
`clean-vpn-usb-snat.mjs --remove --apply`. Чужой uplink MASQUERADE сохраняется.

Свежий instance может запускаться после журнала со стадией `released` другого
instance в том же namespace. Журнал с незавершёнными операциями остаётся привязан
к исходной конфигурации и не принимается новым владельцем. Перед новой установкой
по-прежнему проверяется отсутствие чужого TUN, правил и активных child journals.

Повторный физический запуск на `7ef3bb4` прошёл после смены имени instance:
готовность за 13.979 с, восстановление после SIGKILL сетевого owner за 37.886 с
(включая RestartSec=10). DNS UDP/TCP, NSS, HTTPS и отрицательная проверка прямого
HTTPS повторены. Обе службы штатно остановились с Result=success; временные
unit-файлы удалены, bundles архивированы приватно. Guard/USB rescue сохранены,
постоянный native autostart не включён. Это измерения короткого физического
сценария, а не обещание такой задержки на любом устройстве.

Дополнительная [systemd-матрица](../fixtures/clean-vpn-native-host-systemd-report.json)
проверяет отсутствие default route при старте: после как минимум трёх неудачных
попыток службы engine/TUN не запущены, guard активен. Появление uplink запускает
VPN автоматически. Отдельный live link down/up сохраняет PID owner и
восстанавливает HTTPS без ручного restart. Это veth-модель, не тест DHCP/Wi-Fi
драйвера физической платы.

Смена gateway в той же veth-модели также проверена: owner автоматически
перезапускается, собственный exit route получает новый gateway, DNS/HTTPS
восстанавливаются. Это не проверка переезда между произвольными Wi-Fi сетями.

[15-минутный soak](../fixtures/clean-vpn-native-host-soak-report.json) дал 87
замеров и четыре SIGKILL (engine/owner попеременно). RSS engine 6588–6656 KiB,
FD всегда 8; owner 66520–67144 KiB, обычно 27 FD с двумя краткими замерами 35.
В конце жизни каждого PID число FD вернулось к исходному. Recovery engine
2.154–2.334 с, owner 12.236–12.627 с в этой ARM64 VM. Измеряются parent RSS/FD,
не whole-cgroup peaks; 900 секунд не доказывают отсутствие долгосрочных утечек.

Для повторения добавить `CVPN_HOST_SOAK_SECONDS=900` к systemd fixture; допустимо
0–3600 секунд. Запуск только в новом одноразовом NIC-less контейнере, не на
физической системе. Сохранённый soak выполнен до добавления uplink-сценариев;
они отдельно прошли в итоговой 14-case матрице с теми же production-модулями.


## Несколько host-клиентов на одном exit

Каждому клиенту назначаются **свой PSK и свой `peer_ipv4`** в engine config.
Например, первый использует `10.99.0.2`, второй — `10.99.0.37`. Exit получает
массив `peers` с соответствующими `ipv4` и `secret_path` вместо общего
`secret_path`. Движок допускает до 32 записей; это лимит конфигурации, не
результат нагрузочного теста на 32 клиента.

Host installer переносит этот адрес в сетевой профиль. TUN, USB SNAT,
DNS listener/DNAT, policy routes и recovery journal используют одну идентичность.
USB-подсети разных клиентов могут совпадать: каждая транслируется в свой peer IP.
На одном клиентском хосте по-прежнему допускается один владелец `tun0` и DNS.
Копирование одного ключа/адреса на несколько одновременных клиентов не является
поддерживаемой схемой независимых клиентов.

В native host-profile исключение из DNS DNAT определяется `SO_MARK=0x43564e`,
который ставит C++ upstream socket. Исключать все пакеты с source=peer IP нельзя:
обычное приложение тоже может получить этот source после установки TUN-маршрута.
Такие запросы теперь попадают в native listener. Default прежних Node DNS-планов
не меняется; журнал сохраняет выбранный режим и восстанавливает именно его.

Изолированный двухклиентный стенд: `CVPN_DISPOSABLE_HOST_MULTI=1 node
scripts/lib/native-host-multi-lab.mjs` в свежем NIC-less systemd-контейнере,
подготовленном из `admin/test/native-host.Containerfile`. Он проверяет host/USB
HTTPS, UDP/TCP DNS, разные peer IP, остановку и crash recovery одного клиента,
общий crash exit, отказ неправильной пары ключ/IP и cleanup с сохранением guard.

Результат расширения: [двухклиентный отчёт](../fixtures/clean-vpn-native-host-multi-report.json),
9 real-systemd сценариев, 23 kernel checks и 100 regression tests прошли.
Окончательная проверка installer/journal/exit-plan — ещё 27 tests (частично
пересекаются с общей регрессией). Физические узлы этим расширением не обновлялись.

Для peer, отличного от `.2`, требуется актуальный guard с ответом
`native_peer_dns: true` на `capabilities`. Installer/control plane не подменяет
уже установленный guard: старый helper отклоняется до изменения сети.

## Combo на существующем хосте

`--host-profile` теперь принимает client `combo-tls`, а `--exit-profile` — его
exit. Отдельный `--site-profile` для этой схемы не требуется. Ограничения Radxa
профиля сохраняются: `usb0`, `192.168.7.0/24`, `wlan0`, `tun0`, независимый guard.
Combo config должен использовать единый exit endpoint, native DNS, relay listener
`0.0.0.0` и policy `public-https`. Профиль выбирается по структуре engine config.

Owner после подготовки маршрутов/DNS устанавливает журналируемый USB HTTPS
REDIRECT. HTTPS с USB идёт через transparent relay; исключённые адреса блокируются
без перехода на boring packet branch. Прочий USB-трафик и локальный трафик платы
используют boring-tls. Это не перехват HTTPS приложений самой платы.
При остановке engine сначала quiesced, затем снимаются interception, NAT/DNS,
маршруты и TUN; guard сохраняется. Exit replay state переживает остановки owner
и engine. Условный SSH clock bootstrap по-прежнему поддержан только для boring-tls.

[Combo-отчёт](../fixtures/clean-vpn-native-combo-host-report.json): 11 сценариев
с двумя установленными клиентами и exit, 27 real-kernel checks, 116 regression
tests и отдельная проверка отказа старого guard. Повторная boring-tls матрица
на том же control plane прошла все 9 сценариев. В ней используются разные packet
PSK/IP и общий relay PSK группы; relay PSK сам по себе не является идентификатором
отдельного клиента. Физические узлы не менялись.

Повторение combo: добавить `CVPN_HOST_MULTI_COMBO=1` к приведённому выше
одноразовому systemd-стенду. Этот результат не заменяет физический reboot,
нагрузочный тест или независимый захват отпечатков.

Опциональные входящие соединения с exit: [persistent connection mode и узкий
TCP grant](clean-vpn-native-incoming.md). Разрешение не включается по умолчанию;
проверено отдельно для boring-tls и packet-ветки combo.
