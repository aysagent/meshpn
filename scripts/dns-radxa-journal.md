# Radxa: общий координатор dnsmasq и системного resolver

Только private namespace fixture, **не live-установщик**. Продолжение
[транзакции объекта resolver](dns-resolver-object.md): теперь один controller и
один process-lifetime flock управляют обоими дочерними журналами.

## Порядок и восстановление

```text
guard → подготовка обоих объектов и трёх журналов
      → dnsmasq config/daemon → resolver → active
disable → resolver rollback → dnsmasq config/daemon rollback → restored (guard остаётся)
```

`dns-radxa-journal.mjs` хранит `radxa/journal.json` с общим transaction ID,
неизменяемыми исходными записями обоих детей и durable фазой координатора.
Дочерние журналы находятся в фиксированных `journal.json` и
`resolver-etc/journal.json`; пути из JSON не исполняются. Фаза сохраняется
до передачи управления дочерней транзакции; recovery завершает её и только
потом переводит координатор на следующий этап.

Перед изменениями проверяются **оба** журнала: ID, immutable snapshots/context,
допустимые фазы, реальные объекты, namespace/boot/executable/USB link identity.
Конфликт resolver отклоняется до попытки чинить dnsmasq, и наоборот. Старый
boot/context не принимается. Полностью подготовленные дочерние журналы без
журнала координатора считаются orphan evidence, не присваиваются новой сессии.
Подготовка может оставить snapshots/temp files после сбоя; их не удаляют и не
применяют автоматически. До успешной записи master journal действующие объекты
не переключаются.

Включение сначала согласует файл и процесс dnsmasq, проверяет adapter, затем
локальный dnsmasq UDP/TCP, после чего выбирает managed `resolv.conf`.
Повторный recover восстанавливает отсутствующий dnsmasq, даже если файл уже
согласован. Откат работает при недоступном exit/adapter и возвращает resolver
**до** baseline upstream dnsmasq. После полного отката recovery также может
вернуть dnsmasq/DHCP, не снимая DNS guard.

У дочернего dnsmasq прежняя фаза `released` означает окончание его транзакции;
в paired режиме его `removeGuard` намеренно no-op. Единственный внешний результат
отката — `status: restored, protectionRetained: true`. Это важно: исходная
dangling symlink не становится исправным baseline и не даёт разрешения на
прямой DNS. У координатора вообще нет backend-метода снятия guard.

Все операции пары должны идти через координатор и общий lock. Standalone
дочерние runners оставлены для своих изолированных тестов, их нельзя смешивать
с paired lifecycle. Это не защита от постороннего root/same-UID writer.

## Проверки

```bash
npm run test:dns-radxa
MESHPN_DNSMASQ=/absolute/path/dnsmasq npm run test:dns-radxa-real
# Подробный JSON, без установки пакетов или настройки хоста:
MESHPN_DNSMASQ=/absolute/path/dnsmasq node scripts/dnsmasq-lab.mjs --radxa-journal
```

Флаг включает synthetic `/etc`/`/run`, USB/DHCP peer и guards прежнего
[стенда](dnsmasq-lab.md). Deadline всего namespace — 180 секунд, одного paired
controller — 30 секунд, RPC ограничен 512 сообщениями/256 KiB. Parent-owned
backend переживает SIGKILL дочернего контроллера; это не whole-guest crash.

На x64/dnsmasq 2.90 выполнено:

- **15 настоящих controller SIGKILL**: 8 apply и 7 restore, включая границы
  между дочерними транзакциями, config/daemon setters и смену resolver.
- Конфликт общего flock, read-only inspect, отказ recovery при недоступном exit.
- 9 NSS-проверок через настоящий getent, A/AAAA и UDP/TCP, отказ exit/adapter,
  восстановление dnsmasq. 3 отказа при чужом inode, mountpoint и появлении
  resolved target с сохранением всех трёх журналов.
- 62 dnsmasq/USB проверки, 7 DHCP DORA, включая DHCP после SIGKILL уже
  восстановленного baseline dnsmasq. Во время защиты ноль запросов старому
  upstream/внешнему DNS; в конце один процесс, ноль zombies.
- Точный rollback обоих объектов и сохранение host resolver/NSS/identity files
  и forwarding. Живые VPS/Radxa не менялись.

Для финальных baseline positive controls **сам стенд явно снимает guard** после
проверок удержания: это отдельное fixture teardown, не действие координатора
и не модель разрешённого live-disable.

Unit-набор — **56/56 PASS**: fsync/rename точки master journal, orphan seeds,
offline disable из каждой apply-фазы, ID/context/файловые конфликты, guard failure,
dry-run, restart daemon. Node acceptance — **1432/1432 PASS**, без skips;
пять настоящих namespace-сценариев (новый и четыре прежних) — PASS.

## Дальше

Дополнение: `--radxa-journal --localhost-baseline` проверяет также заранее
выбранный regular localhost resolver, без изменения исходного DHCP/upstream
fixture. Recovery и offline disable различают объекты по inode даже при
одинаковых байтах; guard остаётся. Это не автоматический repair живой Radxa.

[Пара проверена под настоящим systemd в VM](dns-radxa-vm.md): 12/12 проверок
в двух загрузках, сохранность трёх журналов и отказ старого epoch; три
whole-guest crash точки — 3/3 PASS (ещё шесть загрузок).
Далее opt-in установщик/откат и согласованные пилоты VPS 2/Radxa. Требуются
проверка реальных units/includes, baseline policy и отдельное разрешение на
изменения клиента. ARM64/физический USB/живой reboot этим стендом не проверены.
DNS v1 пока не завершён; его [фиксированные критерии](dns-v1.md) не изменены.
