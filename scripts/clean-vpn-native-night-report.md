# Native runtime: ночная приёмка 2026-10-27

Рабочие команды: [standalone и Docker/Podman](clean-vpn-native-runtime.md).
Машиночитаемые результаты, SHA образов/бинарников/capture и ограничения:
[runtime report](../fixtures/clean-vpn-native-runtime-report.json).

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
| Runtime unit tests | 9/9 |
| Docker ARM64 в выделенной Linux VM | 26/26: launcher, LAN, DNS, TCP/UDP/HTTPS, faults, capture, cleanup |
| Podman ARM64 | 26/26 на окончательном runtime с LAN/launcher/cleanup; отдельно часовой single-uplink soak |
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
2. Отдельный следующий этап: wiring физического `wg0`/`usb0`, DHCP/DNS LAN
   клиентов и его recovery. Изолированный LAN smoke этого не заменяет.
3. Затем — container lifecycle для combo/transparent и их replay state,
   дополнительные реальные browser profiles и дальнейшее HTTP/2 fidelity.
4. Постоянная установка, физический reboot и RTC power-loss остаются
   отложены по указанию пользователя. IPv6 tunnel, rootless и нагрузка 32 peers
   не входят в закрываемую здесь приёмку.
