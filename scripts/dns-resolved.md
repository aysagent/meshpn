# Экспериментальный systemd-resolved backend: только namespace

Реализован owned-link backend через настоящий D-Bus API systemd-resolved и
изолированный стенд. **Нет live CLI, установки службы, включения resolved на
Radxa или переключения DNS работающего VPS.** Код не подключается к системной
шине хоста; адаптер шины существует только внутри namespace fixture.

```bash
npm run test:dns-resolved
npm run test:dns-resolved-journal

# Нужен уже доступный локальный бинарник systemd-resolved:
MESHPN_SYSTEMD_RESOLVED=/path/to/systemd-resolved npm run test:dns-resolved-real
MESHPN_SYSTEMD_RESOLVED=/path/to/systemd-resolved npm run test:dns-resolved-journal-real
MESHPN_SYSTEMD_RESOLVED=/path/to/systemd-resolved npm run test:dns-adapter-process-real

# Один сценарий, JSON в stdout:
MESHPN_SYSTEMD_RESOLVED=/path/to/systemd-resolved \
  npm run dns:lifecycle-lab -- --family=4 --resolved

# Дополнительно persistent journal и SIGKILL контроллера между setters:
MESHPN_SYSTEMD_RESOLVED=/path/to/systemd-resolved \
  npm run dns:lifecycle-lab -- --family=4 --resolved-journal
```

По умолчанию binary path `/usr/lib/systemd/systemd-resolved`. Автоскачивания,
установки, пропусков теста при отсутствии инструмента и fallback на host bus нет.
Нужны зависимости базового [DNS lifecycle стенда](dns-lifecycle.md), а также
`dbus-daemon`, `busctl`, `hostname`, поддержка dummy links и UTS namespace.
Запуск без sudo, от непривилегированного пользователя; mapping UID0 отклоняется.
`--resolved`/`--resolved-journal` нельзя сочетать с `--crash` (другой backend).
Для отдельной [матрицы смерти/перезапуска adapter](dns-adapter-process.md) есть
`--resolved-adapter`; она не совмещается с controller-crash матрицей.
Deadline обычного resolved запуска120с, journal-матрицы240с, одного контроллера15с,
RPC10с; busctl —2с/64KiB output cap.

## Что делает backend

`lib/dns-resolved-backend.mjs` получает уже выделенный интерфейс и bounded bus
adapter от fixture. Он читает `DNSEx`, `Domains`, `DefaultRoute`, сохраняет
snapshot и unique D-Bus owner resolved, а также identity интерфейса.

Включение: независимый DNS guard → ownership check → защищённый readiness probe
через DNS adapter → повторная проверка → три D-Bus setters с read-back после
каждого. Managed config: `127.0.0.1:ADAPTER_HIGH_PORT`, route-only domain `~.`,
`DefaultRoute=true`. Файл resolv.conf не меняется этим backend. Поддержка порта
без DNAT обеспечивается `SetLinkDNSEx`; API описывает порт и отдельное TLS-имя.
[systemd resolve1 API](https://raw.githubusercontent.com/systemd/systemd/v255/man/org.freedesktop.resolve1.xml).

Явное отключение: сохранить guard → сверить текущие свойства и owner/identity →
восстановить **сохранённые значения** всех трёх свойств → проверить → снять guard.
`RevertLink` не используется: сброс к defaults не равен восстановлению snapshot.
Смена owner после рестарта, замена интерфейса, посторонние значения или потерянный
ответ setter приводят к отказу вместо перезаписи. Параллельные операции одного
экземпляра контроллера отвергаются. Это описание исходного in-memory контроллера
(`--resolved`); persistent вариант ниже умеет разбирать потерянный ответ setter
и использует межпроцессную блокировку.

Пустой baseline DNSEx отвергается. Непустой список сам по себе не доказывает
работоспособность baseline: реальный стенд подтверждает её положительным DNS
контролем до takeover. На настоящем клиенте ещё нужен preflight resolved,
корректности stub/NSS и исходной DNS-доступности. Оборванную ссылку Radxa нельзя
молча считать исправной конфигурацией для последующего восстановления.

## Реальный стенд

После23 базовых DNS lifecycle lookups выполняются9 дополнительных:
baseline UDP/TCP, protected A/AAAA, exit down/recovered, explicit restore,
daemon down и protected lookup после daemon restart. По два сценария — с
IPv4 и IPv6 pinned exit/upstream, combo enc-SNI fixture, без TUN и uplink.

В private network/mount/PID/user/**UTS** namespaces запускаются настоящие
`dbus-daemon` и `systemd-resolved`. Есть приватные `/run`, `/etc/systemd`,
passwd/group/NSS fixtures; hostname тестовый. Это позволяет EXTERNAL D-Bus auth
работать даже при host NSS через недоступный из namespace сервис. Host passwd,
group, resolv.conf и nsswitch.conf сравниваются до/после. Bus socket приватный,
автоактивация/интерактивный polkit отключены; host system bus не используется.
Lab D-Bus policy разрешает тестовым процессам операции внутри изолированной шины;
это **не проверка production polkit/system bus permissions**.

Отдельный dummy link получает baseline DNS sentinel. Приложение обращается к
настоящему stub `127.0.0.53:53`; resolved направляет запрос в high-port adapter,
тот — DoH через exit. В отличие от базовой fixture, DNAT на127.0.0.53 удалён.
Guard разрешает app→stub, блокирует остальные UDP/TCP53 IPv4/IPv6. Fixture
отключает fallback, cache, LLMNR/mDNS, DNSSEC и DoT в приватном resolved.conf;
на живой системе таких изменений код не делает. TLS/CA upstream проверяет adapter.

Sentinel positive controls доказывают доступность baseline до/после; во время
защиты его счётчик не растёт. Проверяются отказ восстановления при foreign domain,
сохранение search domain/routeOnly/DefaultRoute и неизменность fixture resolv.conf.

Resolved убивается настоящим SIGKILL. Пока daemon мёртв, glibc DNS завершается
ошибкой. В проверенной версии255.4 runtime link settings переживают restart,
поэтому защищённые запросы снова работают. Но unique bus owner другой: старый
контроллер отказывает в disable, не присваивая себе новое состояние автоматически.
Конец этого сценария — явная очистка оператором стенда, **не автоматический recovery**.
При завершении нет дочерних процессов/zombies, adapter sockets/jobs/timers=0.

## Persistent journal и аварии контроллера

`--resolved-journal` подключает `dns-resolved-journal.mjs` к context-checked
D-Bus adapter. Отдельный дочерний процесс держит `flock` до завершения/гибели.
Журнал хранит transaction ID, namespace scope, bus ID (`GetId`), unique owner,
ifindex/name/MAC и snapshots трёх свойств. Unique names уникальны в пределах
одной шины; bus ID нужен, чтобы не принять новую шину с повторившимся `:1.x` за
старую. [D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-get-id).

Перед каждым setter сохраняется intent: exclusive temporary file → fsync →
rename → fsync directory. Только затем D-Bus вызов, read-back и durable ack.
После аварии принимаются ровно два состояния pending setter: сохранённое
«до» или ожидаемое «после». В первом случае вызов выполняется, во втором уже
применённый setter не повторяется. Третье состояние — conflict, без перезаписи.
Проверяются все три свойства целиком, не только изменяемое.

Recovery продолжает записанное направление apply/restore. Явный disable может
перевести частичный apply в restore, предварительно сохранив новый intent.
Guard снимается только после проверки восстановленного snapshot и context.
Missing/corrupt/stale journal, смена owner/link/bus, другой порт adapter,
неуспешный protected probe или чужие настройки оставляют guard включённым.
Restart resolved автоматически не усыновляется, даже если значения совпадают.
Released journal сохраняется как terminal record; новый enable с тем же
каталогом отклоняется. Автоматической ротации/удаления журнала нет.

Directory0700, journal0600; regular file, same UID, single link, no symlink,
bounded64KiB и строгая схема. В отличие от inode/hash fixture, **этот журнал
содержит исходные DNS-адреса и домены**, необходимые для восстановления: его
нельзя публиковать. В JSON-отчёт стенда snapshots и IDs не попадают. Незавершённые
temporary files не используются как источник recovery.

Матрица включает27 точек прерывания: intent/set/ack всех трёх свойств при
apply/restore, границы fsync/rename и снятие guard. Дополнительно проверяются
missing/corrupt/foreign/stale/bus-ID/outage/daemon-owner отказы, конкурирующий
flock и disable частичного apply. Всего31 настоящий SIGKILL контроллера на
семью IP. Baseline отличается по всем трём свойствам; стандартный DNS порт
сохраняется в каноническом read-back виде resolved (`0`, а не `53`). До takeover
и после восстановления есть положительные glibc DNS controls; между аварией
и recovery, а также после отказов проверяются DNS-ответы/ошибки и sentinel counters.

В этом режиме `durableResolvedRecoveryImplemented=true` означает реализацию
и проверку **только внутри namespace**. Обычный `--resolved` smoke по-прежнему
in-memory и это поле false; `--resolved-adapter` тоже использует journal и true.
При SIGKILL контроллера D-Bus adapter,
DNS adapter, guard и namespace init остаются живы.

## Границы и следующий этап

Стенд использует явно заданные baseline settings. Snapshot сохраняет значения
свойств API, но не происхождение конфигурации и не различие explicit/default
для автоматически вычисляемых настроек; восстановление состояния сетевого
менеджера целиком этим ещё не обеспечено.

Crash самого adapter проверяется отдельным режимом `--resolved-adapter`.
Нет reboot/power loss, boot ordering, arbitrary
DHCP/NetworkManager races, сложного split DNS, конкурирующих links/route domains,
IPv6 локального stub, политики DoT/DNSSEC для реального link. Read/check/set —
не атомарный CAS resolved. Пока это выделенный управляемый link в пустой сети,
не разрешение менять рабочий uplink или глобальные DNS-настройки.
Guard53 не является универсальным VPN kill-switch и не блокирует DoH приложений.

Отдельный [process lifecycle adapter](dns-adapter-process.md) уже проверяет
SIGKILL/restart, стабильный endpoint, readiness и сохранение guard.
Добавлены [offline boot/recovery protocol и VM preflight](dns-boot.md);
VM reboot/power-loss tests пока не выполнены.
Восстановление штатного resolved на Radxa и live opt-in — отдельно
согласуемые операции, не побочный эффект запуска VPN.
