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

## Что проверяется

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
                                                   ├─ adapter (protected readiness)
                                                   └─ independent DNS sentinels
resolved + adapter + guard + baseline → controller → consumer
```

Управляет порядком настоящий systemd; `Type=notify` у adapter подтверждается
после UDP/TCP protected probes. Controller использует существующий persistent
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
   guard и журнал остаются. Start на том же порту восстанавливает transaction ID.
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
Reboot всё ещё использует `-no-reboot` и перезапуск QEMU с тем же private disk,
не in-process hot reset; физическая потеря host page cache не моделируется.

Сервис fixture объединяет adapter/exit/origin. Его SIGKILL шире, чем авария одного
adapter; отдельный adapter-only SIGKILL проверяется
[namespace process-стендом](dns-adapter-process.md).

Synthetic D-Bus policy и root fixture services удобны для изолированной проверки,
**не являются production unit hardening**. Entry points проверяют QEMU marker,
PID1, root guest namespaces и отсутствие посторонних NIC; на обычном хосте
отказывают до изменений. Backend не пишет resolv.conf. Автоматического adoption
старого журнала после reboot нет: fail-closed может требовать операторского review.

Этот стенд не доказывает корректность NetworkManager/networkd/DHCP конкретного
дистрибутива, сторонних ранних сервисов, LAN, IPv6 kill-switch или настоящего uplink.
Перенос на клиент требует выбора устройства, review DNS ownership, конфигурации
adapter/exit, клиентских units/guard и аварийного доступа. В v1 не добавляются
остальные DNS backends. Реальный24-часовой пилот не заменяется этой VM.

## Зафиксированный результат

**PASS:2 загрузки systemd PID1,11 проверок (9 разных критериев)**,
`/var/tmp/meshpn-dns-vm-lJHO3D/report.json`.
`hostDnsFilesUnchanged=true`, `resolvConfUnchanged=true`,
`baselineQueriesDuringProtection=0`, `automaticStaleAdoption=false`.
Оба завершения прошли реальные systemd sync/unmount; reboot дополнительно
подтверждён сообщением ядра и новым boot ID. Все144 скопированных JS исходника
сверены с рабочим деревом через image manifest, несовпадений нет.

Unit/CLI проверки входят в **1051 Node +14 Chrome/Firefox PASS**,
`/var/tmp/meshpn-acceptance-KwYJYR/report.json`; отдельно10/10 real namespace DNS
lifecycle tests PASS. Предшествующие неудачные сборки/прогоны VM в результат не включены.
