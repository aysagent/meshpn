# Постоянный журнал клиентского DNS guard

`lib/dns-client-guard-journal.mjs` связывает [общий guard executor](dns-client-guard.md)
с write-ahead журналом. Это исполняемый модуль controller, не установщик и не
готовый системный boot service. Он не меняет resolver/dnsmasq и не восстанавливает
их baseline; разрешение снять защиту обязан подтвердить общий DNS controller.

## Состояния и операции

| Состояние | Значение | Восстановление |
| --- | --- | --- |
| `installing` | ID/политика/контекст уже долговечно записаны; семьи могут быть применены частично | Проверить обе семьи, применить недостающие, затем записать `active` |
| `active` | Обе семьи подтверждены при завершении транзакции | Перепроверить; при пропавшей семье сначала записать новый install intent |
| `releasing` | Явное отключение разрешено после проверки восстановленного baseline | Продолжить только снятие, с новой проверкой baseline перед каждой семьёй |
| `released` | Обе семьи сняты, журнал сохранён | Проверить отсутствие правил; не использовать этот journal как новый enable |

`enable` допустим только без существующего журнала и guard-цепочек. Случайный
128-bit ID сохраняется до первого firewall setter. `start` — обычный start
службы — принимает только `installing`/`active`: незавершённый disable нельзя
молча отменить. `recover` следует записанному направлению. `disable` переводит
install/active в releasing только после явного подтверждения baseline.
`inspect` читает состояния и не вызывает setters, пробы или journal writes.

`bind-boot` — отдельная явная операция для [установленной boot policy](dns-boot-guard.md):
отсутствующий journal, точный установленный ID/config, обе семьи уже present,
стабильный context. Записывает active без firewall setters. При installed policy
обычный enable запрещён: он не должен создавать другой случайный ID. Existing
stale/released journal не архивируется и не принимается автоматически.

Для каждой семьи commit атомарен в проверенном backend; общей атомарности IPv4+
IPv6 нет. После SIGKILL фактическое состояние читается заново: подтверждение
commit могло потеряться. Частичное состояние не превращается в полный PASS.
Снятие одной семьи уже разрешает её исходный DNS — поэтому restore proof нужен
**до** записи release intent, повторно перед дальнейшими удалениями и перед
финальной записью `released`, даже если обе семьи уже отсутствуют после обрыва.

## Хранение и контекст

Используется существующее private journal storage: directory0700, regular
single-link journal0600, текущий UID, nofollow, предел8KiB, exclusive temporary
file → fsync → rename → directory fsync. Временные файлы не считаются recovery
authority. Журнал не удаляется после release. Caller держит стабильный
process-lifetime flock; библиотечный API сам lock не создаёт.

Сохраняются boot ID, network namespace, dev:ino каталога, выбранные firewall
backends и для Radxa имя/ifindex/MAC/IPv4 USB-интерфейса. Смешанные IPv4/IPv6
backends запрещены. Политика сравнивается с текущим согласованным config,
не выбирается из чужого журнала. `createDnsGuardJournalBackend` перепроверяет
context/policy перед командами и требует актуальный callback restore proof.
Конкретные executable paths, root layout и версия команд контролируются
[boot entrypoint](dns-boot-guard.md), а не берутся из journal. Его factory также
проверяет ID journal против installed policy на каждом guard read/commit.

Смена загрузки, namespace, directory, backend или интерфейса приводит к отказу
без присвоения старого контекста. Это **не автоматический reboot recovery** и
не обещание доступного DNS после новой загрузки: независимый ранний boot guard
подключён в VM, но клиентский установщик ещё нужен. Один этот модуль
нельзя устанавливать как готовую boot-защиту. Он также не делает active oneshot
service доказательством текущего наличия правил.

## Проверки

```bash
npm run test:dns-client-guard-journal
MESHPN_DNSMASQ=/absolute/trusted/dnsmasq npm run dns:client-guard-lab -- --journal
```

Второй скрипт работает только в private namespaces, без host sudo/SSH. Родитель
PID1 исполняет проверенный firewall backend, дочерний контроллер под flock ведёт
настоящий журнал. SIGKILL происходит после подтверждённой операции, когда RPC
setter уже завершился; это не имитация убийства самого iptables во время commit.
16 остановок: по8 для каждого клиентского профиля — durable install, после IPv4,
после IPv6, rename active, durable release, после удаления IPv4, после IPv6,
rename released. Проверяются сохранённый ID, направление recovery, обе семьи,
неизменность посторонних правил и два отказа конкурирующему flock.

Матрица дополнена6 binding SIGKILL: для обоих профилей после fsync temp,
rename и fsync directory. При первом checkpoint journal действительно отсутствует,
но обе семьи остаются; retry не меняет policy ID. Ещё два конфликта flock.
Расширенный namespace-прогон: **22/22 SIGKILL,4/4 lock conflicts,11/11 packet
checks PASS**, host DNS/forwarding snapshots неизменны. Это настоящие process
SIGKILL, не whole-guest power loss или убийство iptables внутри commit.

2026-09-27: **52/52 journal/lifecycle unit PASS**, Node1670/1670 PASS,
`/var/tmp/meshpn-acceptance-ES0qES/report.json`. Shared boot/journal lifecycle
настоящего CLI в [resolved VM](dns-systemd-vm.md):20/20 в двух загрузках PASS.
Целевой [VPS2 coupled controller](dns-coupled-vm.md) теперь также использует этот
журнал/lock:19/19 в двух загрузках VM PASS, отдельный root/link restore proof.
Binding и release proof не означают установленный live VPS2/Radxa backend.

Исторический результат: **41/41 journal unit PASS**, общий guard+journal71/71;
**16/16 controller SIGKILL,2/2 lock conflicts,11/11 packet checks PASS**,
iptables1.8.10 nf_tables/dnsmasq2.90. Host resolver/NSS/forwarding неизменны.
Node-регрессия **1643/1643 PASS**, `/var/tmp/meshpn-acceptance-l2aoDI/report.json`.
Physical power loss, reboot нового guard, legacy и live VPS2/ARM здесь не проверены.

Далее: завершить совместный boot/journal lifecycle и restore proof Radxa,
подготовить live controllers, opt-in установку и откат, затем согласованные
пилоты. Этот результат не закрывает DNS v1.
