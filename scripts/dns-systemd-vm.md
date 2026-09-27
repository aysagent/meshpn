# DNS: настоящий systemd lifecycle в изолированной VM

Следующий этап после [boot-fault матрицы](dns-vm-lab.md), в пределах
[конечного DNS v1](dns-v1.md). Это **VM-only интеграция**, не установщик на VPS
или Radxa и не разрешение копировать лабораторные unit-файлы в `/etc/systemd` хоста.

```bash
npm run dns:vm-lab -- \
  --tools=/absolute/private-tools-directory \
  --kernel=/boot/vmlinuz-MATCHING-RUNNING-KERNEL \
  --resolved=/absolute/trusted/systemd-resolved \
  --case=systemd
npm run test:dns-vm
```

Те же требования к Linux/TCG, происхождению инструментов и изоляции, что у
основной VM-лаборатории. Дополнительно builder копирует локальные systemd,
systemd-executor, systemd-shutdown, systemctl, systemd-notify и явный набор
стандартных shutdown units. Host unit/config directories не импортируются.
Перед упаковкой выполняется offline `systemd-analyze verify --root=GUEST`
для сгенерированных units; нужен локальный systemd-analyze.
Временный образ не требует установки пакетов или служб на хосте.

Для `--case=systemd` теперь явно выделены **2 vCPU, MTTCG**; остальные случаи
сохраняют1 vCPU. Это не увеличение DNS deadline: client, exit/origin и controller
размещены в одной эмулируемой машине, хотя в целевой эксплуатации exit отдельный.
Прежний1-vCPU прогон воспроизвёл `DNS_TIMEOUT`: 1718мс при deadline1500мс,
inflight1, requests0/timers0 в момент обработки отказа, RSS≈65MB. Отчёт:
`/var/tmp/meshpn-dns-vm-z0rskP/report.json`, подробности в `serial-1.log`.
Сам timeout установлен прямо; влияние CPU contention проверяется сравнением,
а не объявляется доказанным только по этому счётчику.
[QEMU MTTCG](https://www.qemu.org/docs/master/devel/multi-thread-tcg.html).

## Что проверяется

Текущая итерация подключает [ранний boot guard CLI](dns-boot-guard.md) вместо
fixture-only root worker: фиксированная policy, inherited flock и настоящий
unit sandbox. Две новые проверки в каждой загрузке: stop сохраняет собственные
chains; guard ExecMainExit предшествует network ExecMainStart. **16/16 PASS**;
исторические12-проверочные результаты ниже относятся к прежнему guard.
У guest `/run` теперь явно0755, а boot policy0600; `/tmp` остаётся1777.

Последний прогон соединяет boot policy с persistent guard journal и DNS
controller под одним flock. Убрано fixture-разрешение release `() => true`:
каждое удаление требует durable resolved restore-complete и точного live
context/baseline. Проверяются также отказ release при active DNS и отсутствие
автоматического bind после потери guard journal рядом с DNS-транзакцией.
Оба сценария повторяются после reboot; итоговая матрица20 проверок.
Расширенный запуск прошёл **20/20 в двух загрузках**. Старые результаты ниже сохранены.

BusyBox `/init` монтирует гостевые файловые системы и устанавливает DNS53 guard
до `exec systemd`. Затем **systemd действительно является PID1**. У гостя нет
NIC, shared filesystem, TUN, доступа к сети хоста или интернету. DNS adapter,
enc-SNI exit и TLS DoH origin — реальные процессы/сокеты, но все адреса fixture
принадлежат только гостевому loopback. DNS upstream transport в этом режиме IPv4;
A/AAAA не означает поддержку IPv6 data plane VPN.

Минимальная цепочка запуска:

```text
early guest guard → systemd PID1 → guard.service → network.service
                                                   ├─ dbus → resolved → baseline
                                                   ├─ exit/origin fixture → adapter CLI
                                                   └─ independent DNS sentinels
resolved + adapter + guard + baseline → controller → consumer
```

Управляет порядком настоящий systemd; `Type=notify` у adapter подтверждается
после четырёх UDP/TCP A/AAAA protected probes. Используется настоящий
`dns-exit-adapter.mjs --ready-name=systemd-ready.test --systemd-notify`, а не
объединённый worker: exit/origin теперь живут в независимом fixture service.
Проверяется MainPID и argv адаптера, ровно четыре ответа до завершения start;
при первом запуске с отключённым exit unit отказывает до создания journal/consumer.
Unit строится из [клиентского service plan](dns-adapter-service-plan.md):
DynamicUser, credentials, readonly filesystem и capability restrictions не
снимаются. В VM отличаются boot dependencies, диагностический preload и вывод
(null вместо journald, отсутствующего в минимальном образе). Проверяются ненулевые UID,
нулевой CapEff, NoNewPrivs=1 и EACCES при чтении исходного PSK от этого UID.
Credentials используются из отдельной runtime-копии, а код действительно
размещён в `/opt/clean-vpn`, без симлинка на лабораторный checkout.
Controller использует существующий persistent
resolved journal, реальные D-Bus setters/read-back и отдельный `flock`.
Consumer запускает glibc lookup и фиксирует успешную готовность.
`BindsTo` вместе с `After` связывает остановку зависимых служб с зависимостью.
[systemd.unit v255](https://github.com/systemd/systemd/blob/v255/man/systemd.unit.xml),
[systemd.service v255](https://github.com/systemd/systemd/blob/v255/man/systemd.service.xml).

Фиксированная матрица:

1. Отказ guard unit: наши network/adapter/controller/consumer не запускаются,
   журнал не создаётся. Это тест dependency ordering; реальная ошибка iptables
   без CAP_NET_ADMIN проверяется отдельно boot-fault сценарием. Systemd сам
   может поднимать lo — его защищает внешний guard до запуска PID1.
2. Readiness → takeover → успешные DNS A/AAAA → запуск consumer.
3. `stop` controller останавливает consumer, **но не снимает guard** и не
   возвращает открытый DNS. Повторный start восстанавливает ту же транзакцию.
4. Отказ exit не вызывает baseline DNS fallback; восстановление exit возвращает DNS.
5. SIGKILL adapter unit останавливает зависимые controller/consumer;
   guard и журнал остаются; exit/origin service продолжает работу с прежним PID.
   Start на том же порту восстанавливает transaction ID.
6. Чужое изменение Domains: disable отклоняется, чужие свойства и journal
   сохраняются. Исправление конфликта в fixture — отдельное явное действие.
7. Только explicit disable под flock восстанавливает принадлежащий контексту
   baseline, после чего снимает guard. Positive UDP/TCP control проверяет observer.
   Повторный start со старым released journal отклоняется, но перед отказом
   реальные guard rules устанавливаются заново: `active` у oneshot unit недостаточно.
8. Настоящий `systemctl reboot`: shutdown/sync/unmount и новый boot ID.
   Старый journal не принимается новым bus/context, baseline не перезаписывается,
   consumer не запускается. Явно разрешённая **только сценарием** архивация старой
   эпохи позволяет создать новую, проверить DNS и выполнить disable.

Сравниваются `/etc/resolv.conf` гостя и DNS/NSS файлы хоста до/после. Отдельные
sentinels считают запрещённые baseline запросы IPv4/IPv6; guard проверяется
реальными UDP/TCP попытками, а не только наличием правила. Protected bootstrap
не вызывает системный DNS.

## Ограничения

На одну VM до15 минут, две загрузки, ограниченный serial log. Это TCG acceptance,
не benchmark: glibc deadline5s вместо1s, без дополнительного retry или fallback.
Ошибка прекращает матрицу, незавершённый/проваленный запуск не считается PASS.
После ожидаемого `reboot-ready`/`passed` допускается только завершение driver
с systemd result `signal`: shutdown может опередить возврат systemctl. До маркера
это ошибка, другие failed results остаются ошибками и после него. Маркер сам по
себе недостаточен: sync/unmount, exit QEMU, reboot и обе boot identity всё ещё
обязательны. Эта гонка остановила прежний прогон `MFbU7s` после `reboot-ready`;
он не считается успешным.
Reboot всё ещё использует `-no-reboot` и перезапуск QEMU с тем же private disk,
не in-process hot reset; физическая потеря host page cache не моделируется.

В `--case=systemd` SIGKILL относится только к настоящему CLI adapter; fixture
exit/origin остаётся жив. Другие VM cases пока сохраняют свой объединённый
fixture; результат этого режима нельзя автоматически переносить на них.
CLI использует обычные production deadlines (DoH1500мс, readiness2000мс на запрос),
не увеличенные fixture DNS deadlines. Adapter работает без root; остальные
fixture/controller units остаются лабораторными root services.
VM-only `--import` observer сохраняет последние16 отказов (код, время, counters,
RSS/heap) в PrivateTmp. При ошибке driver читает их через namespace root процесса
и добавляет `adapter-diagnostics` перед `failed`. Нет QNAME/IP/ключей, retries
или изменения deadline; в клиентский service plan observer не включён.

Synthetic D-Bus policy и root fixture/controller services удобны для изолированной
проверки, **не являются production controller hardening**. Adapter service plan
не устанавливает эти зависимости на клиент. Entry points проверяют QEMU marker,
PID1, root guest namespaces и отсутствие посторонних NIC; на обычном хосте
отказывают до изменений. Backend не пишет resolv.conf. Автоматического adoption
старого журнала после reboot нет: fail-closed может требовать операторского review.

Этот стенд не доказывает корректность NetworkManager/networkd/DHCP конкретного
дистрибутива, сторонних ранних сервисов, LAN, IPv6 kill-switch или настоящего uplink.
Перенос на клиент требует выбора устройства, review DNS ownership, конфигурации
adapter/exit, клиентских units/guard и аварийного доступа. В v1 не добавляются
остальные DNS backends. Реальный24-часовой пилот не заменяется этой VM.

## Зафиксированный результат

Регрессионный повтор при подключении coupled controller: **20/20 PASS**, две
загрузки, `/var/tmp/meshpn-dns-vm-hYAVIb/report.json` (2026-09-27).
Shared-lock factory не нарушил прежний resolved lifecycle; host DNS unchanged,
baseline queries0. Окончательные coupled-образ и результаты учитываются отдельно.

2026-09-27: boot policy + guard journal + resolved fixture controller:
**20/20 PASS в двух загрузках**, `/var/tmp/meshpn-dns-vm-YsGwNF/report.json`.
Один inherited flock, точный ID установленной policy, обязательный current
restore proof перед снятием guard. В обеих загрузках active DNS не разрешил
release, а потеря guard journal не создала новую эпоху. Старые DNS/guard журналы
отклонены после reboot без перезаписи; только explicit fixture archive разрешил
новую транзакцию.464 JS copies совпали с image manifest; host DNS/guest
resolv.conf неизменны, baseline queries0, shutdown/sync/unmount подтверждены.
Node1670/1670 PASS, `/var/tmp/meshpn-acceptance-ES0qES/report.json`.
Промежуточный18-проверочный прогон `G9gHz0` тоже PASS, но финальный snapshot —YsGwNF.
Это не целевой coupled backend VPS2 и не Radxa backend; подключение первого
проверяется отдельно в [coupled VM](dns-coupled-vm.md), Radxa остаётся,
как и постоянный uninstall boot policy/dependency dropins и клиентские пилоты.

### Предыдущий результат: boot CLI без guard journal

2026-09-27: CLI adapter + **настоящий boot guard CLI —16/16 PASS в двух загрузках**,
`/var/tmp/meshpn-dns-vm-7CL1sN/report.json`. Systemd255/legacy firewall,
QEMU8.2.2 TCG2 vCPU. Guard stop оставляет chains; старт измеренно завершён до
network; после reboot stale DNS journal отклонён без direct fallback.
Host DNS/guest resolv.conf неизменны, baseline queries0;462 JS copies совпали
с image manifest. Реальные sync/unmount, kernel reboot/new boot ID и poweroff.
Node1659/1659 PASS, `/var/tmp/meshpn-acceptance-3CbkEG/report.json`.
Namespace guard/journal повторён:16 SIGKILL,2 lock conflicts,11 packet checks PASS.
Подготовительные отказы перечислены в [boot guard](dns-boot-guard.md).
Persistent guard journal пока отдельно; VM release всё ещё fixture-only после
проверки baseline. Совместный installed lifecycle/rollback не объявлен готовым.

### Предыдущий результат: DynamicUser adapter и fixture guard

2026-09-27: настоящий CLI с **DynamicUser/credentials —12/12 PASS в двух загрузках**,
`/var/tmp/meshpn-dns-vm-WlsDhv/report.json`. Systemd255/x64, QEMU8.2.2,
2 vCPU MTTCG, штатные CLI deadlines; 444 копии JS исходников совпали с manifest.
`unprivilegedAdapter=true`, `systemdCredentials=true`, baseline queries0,
host DNS и guest resolv.conf неизменны. Проверены настоящие sync/unmount,
kernel reboot и разные boot ID; второй запуск завершился poweroff.
Node-регрессия **1572/1572 PASS**, `/var/tmp/meshpn-acceptance-0wWNMq/report.json`.

Предшествующие failed попытки не входят в PASS: `PGF8u0` — несовместимый tty
sink при PrivateDevices, `836N7E` — symlink entrypoint вместо реального /opt layout,
`4tfNnf` — поздний SERVFAIL, `z0rskP` — его инструментированное воспроизведение
с DNS_TIMEOUT, `MFbU7s` — гонка driver shutdown после успешного первого boot.
Полные пути: `/var/tmp/meshpn-dns-vm-<имя>/report.json`.
2-vCPU результат согласуется с гипотезой CPU contention в эмуляции, но не доказывает
производительность живой Radxa и не принимает прежние failed прогоны задним числом.

### Исторический результат исходного fixture

Текущий CLI-прогон: **PASS:2 загрузки systemd 255 PID1,12 проверок
(10 разных критериев)**, `/var/tmp/meshpn-dns-vm-fZOFw7/report.json`.
`adapterImplementation=cli`, `separateExitFixture=true`,
`readinessQueriesPerStart=4`; `hostDnsFilesUnchanged=true`,
`resolvConfUnchanged=true`, `baselineQueriesDuringProtection=0`,
`automaticStaleAdoption=false`. Оба shutdown прошли sync/unmount;
218 JS исходников image manifest совпали с рабочим деревом.
Node regression **1545/1545 PASS**, без skips,
`/var/tmp/meshpn-acceptance-KGIaIf/report.json`. Это не новый browser acceptance,
не power-cut прогон и не проверка клиентских версий/arm64.

Исторический результат до выделения CLI: **PASS:2 загрузки systemd PID1,
11 проверок (9 разных критериев)**,
`/var/tmp/meshpn-dns-vm-lJHO3D/report.json`.
`hostDnsFilesUnchanged=true`, `resolvConfUnchanged=true`,
`baselineQueriesDuringProtection=0`, `automaticStaleAdoption=false`.
Оба завершения прошли реальные systemd sync/unmount; reboot дополнительно
подтверждён сообщением ядра и новым boot ID. Все144 скопированных JS исходника
сверены с рабочим деревом через image manifest, несовпадений нет.

Unit/CLI проверки входят в **1051 Node +14 Chrome/Firefox PASS**,
`/var/tmp/meshpn-acceptance-KwYJYR/report.json`; отдельно10/10 real namespace DNS
lifecycle tests PASS. Предшествующие неудачные сборки/прогоны VM в результат не включены.
