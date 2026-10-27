# Native runtime: ночная приёмка 2026-10-27

Рабочие команды: [standalone и Docker/Podman](clean-vpn-native-runtime.md).
Машиночитаемые результаты, SHA образов/бинарников/capture и ограничения:
[runtime report](../fixtures/clean-vpn-native-runtime-report.json).

## Дополнение после сверки с исходным ночным планом

Первый отчёт закрыл основной runtime, но остановка была преждевременной:
пункт о host-side wiring и часть измерений soak ещё не были выполнены.
Ниже — закрытие именно этих пробелов и отдельная проверка расширения.
Постоянная установка на физических узлах по-прежнему исключена пользователем.

| Пункт исходного плана | Доказательство и граница |
|---|---|
| 1. Общий native runtime-контракт | C++ engine после однократного provisioning; standalone и rootful контейнеры |
| 2. amd64/arm64 image | Native ARM64 полный source image; amd64 CMake + проверенный artifact image; CTest 10/10 на каждой архитектуре |
| 3. Launcher/Compose/capabilities | Docker/Podman launcher и реальный Compose pair; негативные grants и host-netns refusal |
| 4. Приложение и host-side gateway wiring | Отдельная NIC-less VM-модель `usb0` → policy routing → client LAN; IPv4/IPv6, DNS, rescue, другой LAN, строгий rollback |
| 5. Lifecycle/fail-closed | Короткие Docker/Podman smoke, engine/controller SIGKILL, wrong CA/name/PSK, отсутствие upstream, восстановление собственных ресурсов |
| 6. Partial профиль на wire | Отдельный tcpdump и pcap parsing; cold Chromium-derived поля, без обещания browser equivalence |
| 7. systemd/boot/clock faults | 3 boot-фазы существующей native scheme в VM; clock faults в standalone VM; физический RTC/power-loss не проверен |
| 8. Временный физический smoke | Docker amd64 на VPS пройден с восстановлением baseline; Radxa только readonly, runtime там не устанавливался |
| 9. Ограниченный soak и измерения | Первый час RSS/FD, второй час с LAN/socket/thread/process counters; отдельные 30 минут transaction latency внутри того же стенда |
| Расширение: experimental replay packaging | По 26 проверок для Podman и Docker ARM64, production engine, настоящий TLS relay, SIGKILL/recreate с persistent volume |

Gateway VM: **22/22**. Проверены восстановление после прерванного rename
журнала, intent до mutation и mutation до проверки результата. Уникальный
временный файл устраняет блокировку recovery оставшимся файлом убитого writer.
После уничтожения fixture bridge его MAC и порт восстанавливаются в исходном
порядке; сравнение IPv4/IPv6 routes/rules остаётся строгим, включая порядок.
Это [лабораторная модель](clean-vpn-native-runtime-host-wiring.md), не live-host
installer и не power-loss журнал для физического шлюза.

Relay packaging: **26/26 Podman + 26/26 Docker**. Сохранившийся replay volume
отвергает уже принятый ClientHello после SIGKILL всего контейнера и пересоздания.
Положительный контроль принимает тот же токен в отдельном свежем тестовом
состоянии: отказ не объясняется expiry/corruption. Проверены read-only volume,
второй владелец и запрет повторного init. Combo прошёл аутентификацию boring
ветки на общем listener и TLS relay; IP payload/gateway для combo в этом новом
тесте не проверяются. Публичный launcher остаётся boring-tls-only.

Финальная интеграция измерений проверена полным Docker smoke **27/27** и
коротким soak 30 секунд. Unit tests **11/11**. Задержки `*WallMs` включают CLI;
`transactionLatency` измеряется внутри приложения, отдельно для DNS UDP/TCP,
нового HTTPS соединения и TCP/UDP echo. Это локальная fixture-нагрузка,
не Internet RTT, не throughput benchmark и не приёмка 32 клиентов.

**Важное различие:** час измерений прошёл, но общий raw report этого запуска
остался **failed**: завершающий gate ошибочно ожидал чужое правило из уже
заменённого container namespace. Не меняя engine, исправили harness: отдельный
witness удерживает старый namespace и проверяет его firewall после restart.
Один readlink недостаточен — ядро повторно использует inode уничтоженного netns.
Исправление проверено полными Docker/Podman smoke со специально ускоренными
рестартами: 10 / 6 циклов, старое правило сохранено во всех.
Результаты исходного неудачного запуска не переименованы в passed.

Повторный час нагрузки: **3600 секунд**, 331 выборка,
11 чередующихся SIGTERM/SIGKILL рестартов, LAN и публичный launcher.
Пиковый RSS client/exit — **6276/6180 KiB**;
FD — 7/6, socket FD — 3/2,
threads — 2/1. На роль всегда один native
process, zombies — 0. Изменение RSS от тёплой выборки к последней:
client 0 KiB, exit 432 KiB.
Другие процессы в PID namespace — кратковременные health/measurement probes.
Подробные ranges TCP ESTABLISHED/TIME_WAIT и UDP sockets сохранены в JSON.

Параллельный замер transaction latency — **1801 с**: 650 успешных
наборов запросов (по 325 от client и LAN), ошибок — 0.
Каждый набор включает пять транзакций. Время запуска CLI в цифры ниже не входит.

| Транзакция | Client p50 / p95, мс | LAN p50 / p95, мс |
|---|---:|---:|
| DNS UDP | 5.17 / 6.32 | 5.24 / 6.24 |
| DNS TCP | 4.26 / 5.49 | 4.31 / 5.30 |
| Новый HTTPS request | 17.66 / 20.57 | 17.56 / 20.04 |
| TCP echo | 0.91 / 1.31 | 0.92 / 1.24 |
| UDP echo | 0.42 / 0.57 | 0.42 / 0.58 |

После интеграции transaction timers выполнен также окончательный Podman
smoke **27/27** с целевым restart regression 135 с (фактически 137 с). Пересобирать engine не требовалось:
хеши всех **56/56** production-исходников обоих образов совпали с рабочим деревом.
В этом продолжении физические VPS/Radxa не менялись. Временные контейнеры,
сети и volumes удалены; lab VM остановлена, build caches сохранены.

Приватные raw reports/pcap: `/private/tmp/cvpn-night-followup-20261027/`.
В git — только агрегаты, hashes, код и документация. Неудачные промежуточные
прогоны сохранены рядом с успешными; они не включены в число passed.

## Что сделано

- Один C++ engine работает непосредственно в выделенном Linux netns и в
  rootful Docker/Podman. Новый entrypoint выполняет однократную подготовку
  сети, затем `exec` native engine; постоянного Node data plane нет.
- Отдельный runtime image собирается из allowlist-контекста. В нём нет ключей,
  `.git`, QEMU и компилятора. Есть hashes фактических исходников и бинарника.
- Launcher предоставляет `start/status/stop/remove`, config bind/volume,
  явную публикацию exit-порта и необязательную вторую LAN bridge network.
  Docker restart больше не зависит от перестановки `eth0`/`eth1`.
- Есть native DNS UDP/TCP, перехват Docker `127.0.0.11`, живой health check,
  запрет прямого fallback после SIGKILL, безопасное пересоздание namespace.
- Лаборатория пишет ownership-журнал до создания ресурсов. Обычный cleanup
  и отдельный аварийный recovery проверяют и случайное имя, и label.
  Shared-namespace зависимости удаляются до их владельцев; `--depend`, который
  мог бы захватить чужие приложения, не используется. Docker/VPS smoke был
  выполнен до этого уточнения; окончательный порядок проверен unit-тестом
  и отдельным Podman recovery/smoke.
- Исправлена Release-сборка GCC/aarch64 HTTP/2 callback без отключения `-Werror`
  и без изменения лимита очереди.

## Проверенная матрица

| Среда | Результат |
|---|---|
| Native ARM64 build | CTest 10/10; полный multistage source build |
| Linux amd64 build | CTest 10/10; проверенный бинарник упакован artifact stage |
| Runtime unit tests | 11/11 |
| Docker ARM64 в выделенной Linux VM | 27/27: launcher, LAN, DNS, TCP/UDP/HTTPS, faults, capture, cleanup |
| Podman ARM64 | 27/27 с LAN/launcher/restart witnesses; часовые прогоны и их разные статусы разобраны выше |
| Standalone amd64 в QEMU с настоящим x86 kernel | 10/10, включая SIGKILL/restart и clock faults; guest без NIC/host shares |
| Docker Compose ARM64 | Реальный `up`, healthy, DNS UDP/TCP, HTTPS, `down`, сеть удалена |
| Docker amd64 на физическом VPS | 26/26; transient unit 37 секунд, независимый ExecStopPost; peak контроллера 96.7 MiB |
| Existing native systemd/boot regression | 3 boot-фазы, 18 + 13 + 10 проверок |

Boot regression проверяет существующую native systemd-схему с текущим engine.
Он не заменяет reboot приёмку нового контейнерного deployment на физической
машине. Под Rosetta amd64 netfilter не заработал; поддержка amd64 подтверждается
настоящим x86 kernel в QEMU и Docker на VPS, а не названием `--platform`.

Часовой soak прошёл: 3600 секунд, 336 выборок с DNS/HTTPS/TCP/UDP передачами,
11 чередующихся SIGTERM/SIGKILL рестартов. Пиковый RSS client/exit — 6232/6180 KiB,
FD — 7/6, как и после прогрева. Последний RSS client/exit — 6216/6164 KiB;
exit вырос относительно ранней тёплой выборки на 416 KiB, client уменьшился
на 12 KiB. Ограничения по RSS/FD выдержаны. Это не доказательство отсутствия
утечек на любых нагрузках и не throughput benchmark. Его запуск начался до добавления LAN/auto-interface;
native binary тот же, а функциональная приёмка окончательной упаковки отдельная.
В старом harness дважды продлевалось время жизни **только** fixture config-holder:
исходный sleep был короче soak. Client/exit/observer при этом не останавливались.
В актуальном harness срок fixture сразу равен `soakSeconds + 1800`.

Окончательный Podman recovery отдельно проверен после SIGKILL контроллера:
удалены 5 собственных контейнеров, volume и 2 сети; чужой sentinel остался
работать. Временные ресурсы обоих container engines удалены, выделенная Podman
VM остановлена. Образы и два build-cache volume сохранены для следующего запуска.

## Профиль и безопасность

Внешний tcpdump observer и offline parser подтверждают
`chromium-156-bounded-cold-v1`. JA4:
`t13d0915h2_f91f431d341e_54d72502093d`. Ordered JA3 меняется при перестановке
extensions; сравниваются также сами поля ClientHello. Сырые pcap новых smoke
сохранены приватно рядом с отчётами, engine не сообщает observer результат.
Алгоритм JA3/JA4 всё ещё общий с репозиторным sniffer — это не независимая
реализация вычисления fingerprint.

Это частичная мимикрия cold ClientHello. Она не обещает неотличимость Chrome,
его HTTP/2 запросы, TCP stack, resumption/tickets или trust-anchor negotiation.
Проверки CA/hostname/PSK не ослаблялись. Неверные часы в VM приводят к отказу
сертификата; после исправления часов tunnel восстанавливается. Native time
bootstrap с exit пока отсутствует.

## Состояние физических машин

На VPS код обновлён только git fast-forward. Тест работал в собственных
контейнерах и bridge-сетях, без публикации портов и смены default route хоста.
После cleanup совпали маршруты, policy rules, порядок IPv4/IPv6 firewall rules,
ip_forward, состояния служб и ID чужих Docker ресурсов. При сравнении исключены
только положительный countdown IPv6 RA lifetime, packet counters и timestamps
`iptables-save`. Импортированные тестовые образы и архивы удалены. В приватной
директории осталось около 236 KiB отчётов, снимков и pcap.

Radxa проверена только чтением: время корректное, legacy VPN/kill switch
активны, Docker не установлен. Пакеты не устанавливались, службы/сеть не менялись.
RTC после физического power loss этим не проверен. Mac Wi-Fi, DNS, маршруты
и firewall вручную не перенастраивались; работа шла в выделенной Podman VM.

## Что дальше

1. Для временного использования доступны boring-tls runtime и partial профиль.
   Первый практический сценарий — приложения в namespace client-контейнера.
2. Следующий отдельный этап: перенос проверенной VM-модели wiring на физический
   `wg0`/`usb0`, DHCP/DNS LAN и устойчивый recovery. Установщика для реального
   хоста этот ночной scope не создаёт.
3. Затем — production container lifecycle для combo/transparent: replay
   packaging уже проверен, но launcher/provisioning/health ещё не готовы;
   также остаются дополнительные browser profiles и дальнейшее HTTP/2 fidelity.
4. Постоянная установка, физический reboot и RTC power-loss остаются
   отложены по указанию пользователя. IPv6 tunnel, rootless и нагрузка 32 peers
   не входят в закрываемую здесь приёмку.
