# Radxa: транзакция объекта системного resolver (только стенд)

Проверяется исходная схема Radxa: dnsmasq обслуживает localhost и USB, а
`/etc/resolv.conf` — dangling symlink на
`/run/systemd/resolve/stub-resolv.conf`. Автоматического включения resolved нет.
Это не live-установщик и не команда исправления DNS на настоящем клиенте.
Также поддержан **явно выбранный** исходный regular file 0644 с единственной
строкой `nameserver 127.0.0.1\n`. Это основа будущего согласованного baseline
Radxa, не автоматическое исправление её текущей ссылки. Доступность dnsmasq и
его upstream проверяется отдельно; наличие файла само по себе не доказывает здоровье DNS.

## Что реализовано

Отдельный журнал `dns-resolver-object-journal.mjs` и файловый backend
`dns-resolver-object-files.mjs` работают только с фиксированными именами в
принадлежащем процессу приватном каталоге 0700. Фазы:

```text
prepared → apply-intent → active → restore-intent → restored
```

До изменений устанавливается guard. До выбора managed resolver проверяются
adapter и настоящий localhost dnsmasq по UDP/TCP. Managed объект — обычный файл
0644 с `nameserver 127.0.0.1`. Подготовленные объекты выбираются атомарным rename,
с fsync файла/каталога; журнал сохраняется до действия и после readback.
Symlink проверяется через lstat/readlink, а не открытием его target. Regular file
читается с O_NOFOLLOW и проверками inode, uid/gid, mode, nlink и содержимого.

Disable возвращает **точный текст и метаданные ссылки**, но не исходный inode.
В режиме `localhost-file` возвращаются точные байты, uid/gid и mode исходного
файла. Original/managed/restored имеют три разных inode, даже при одинаковых
байтах. Recovery проверяет выбор baseline, не принимает чужой файл по одному hash.
По умолчанию backend по-прежнему требует dangling link; обычный файл не выбирается
автоматически. Только фиксированные bytes/mode, не произвольный `resolv.conf`.
Возврат dangling symlink — точный rollback, **не исправление baseline DNS**.
Журнал resolver не снимает guard: `protectionRetained: true`. Снятием владеет
внешняя интеграция. Исчезнувший/повреждённый журнал, чужой inode даже с тем же
содержимым, другой boot/namespace, заменённые snapshots требуют отказа и review.
Это не CAS против враждебного процесса с тем же UID/root: нужны owned directory
и внешний flock.

## Настоящий изолированный сценарий

```bash
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq npm run test:dns-resolver-object-real
```

Либо подробный JSON-отчёт:

```bash
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq node scripts/dnsmasq-lab.mjs --resolver-object
```

Проверка пары с заранее выбранным localhost baseline в synthetic `/etc`:

```bash
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq node scripts/dnsmasq-lab.mjs --radxa-journal --localhost-baseline
```

Дополнительные NSS-пробы проверяют блокировку после offline rollback под guard,
затем успешный UDP/TCP lookup после **отдельного явного fixture teardown** guard.
Для заблокированного baseline TCP dnsmasq может держать запрос без ответа:
отрицательная проверка ограничена 5 секундами и учитывает завершение getent по
дедлайну отдельно в `boundedBlockedLookups`. Это не успешный DNS-ответ и не
измерение production resolver timeout. Успешные пробы никогда не принимают timeout.
Нулевые счётчики baseline upstream проверяются также после заблокированных NSS-проб.
Прогон 2026-09-27: PASS, 15 controller SIGKILL, 13 NSS-проб, 62 USB/dnsmasq
проверки и 7 DHCP DORA. Legacy paired и standalone resolver также повторены, PASS.
Первый новый прогон остановился на TCP deadline после rollback; отдельно учтённая
bounded negative probe исправляет модель ожидания, не ослабляет guard. Целевые
unit/protocol проверки resolver/paired/config/VM — 202/202 PASS.
Node acceptance сначала 1478/1478 PASS (`/var/tmp/meshpn-acceptance-S01I6C/report.json`),
повтор 1476/1478 (`/var/tmp/meshpn-acceptance-RxCxSd/report.json`) выявил ESRCH-race
в старом process-cleanup тесте; он исправляется отдельно. DNS-тесты прошли,
но неуспешный общий прогон не считается acceptance.
После отдельных исправлений ESRCH и UDP-test race: **3 × 1481/1481 PASS**,
`/var/tmp/meshpn-acceptance-FuyURi/report.json`. Браузеры и VM заново не запускались.

Пакеты автоматически не устанавливаются. Нужны инструменты прежнего
[dnsmasq namespace-стенда](dnsmasq-lab.md); `--resolver-object` включает USB и
journal режимы. Тайм-аут процесса 180 секунд. Запускать с sudo не требуется.
Namespace gate проверяет отдельные net/PID/mount namespaces и private mount
propagation. Внутри подменяется **каталог** `/etc` синтетической fixture, а `/run`
— пустым приватным каталогом. Поэтому rename действительно виден новому glibc
resolver, в отличие от file bind mount. Исходный target ссылки отсутствует.
В synthetic `/etc` создаются минимальные passwd/group/NSS и четыре ссылки на
firewall executables для Debian alternatives; конфиги хоста не копируются.

Фиксированный localhost:53 probe имеет отдельный namespace gate; прежний
`queryLabDns` по-прежнему разрешает только непривилегированные порты. В OUTPUT
разрешён только loopback IPv4 DNS к dnsmasq, при сохранении IPv4/IPv6 запрета
прямых upstream. USB INPUT/FORWARD защита сохраняется.

Проверено на x64 с dnsmasq 2.90:

- 7 настоящих controller SIGKILL: prepared, apply-intent, apply:set, active,
  restore-intent, restore:set, restored; конфликт flock и read-only dry-run.
- 9 системных NSS-проверок отдельными getent-процессами: A/AAAA по UDP/TCP,
  отказ exit/adapter, восстановление после рестарта dnsmasq.
- 3 реальных отказа без изменения журнала и снятия guard: чужой inode с теми
  же байтами, bind mount resolver, появление target resolved. Чужие данные
  сохраняются; fixture возвращает свои объекты только явными тестовыми действиями.
- Сохранены 61 проверка dnsmasq/USB, 6 DHCP DORA и ещё 7 SIGKILL dnsmasq journal;
  ноль запросов старым upstream/внешним DNS во время защиты, в конце один
  процесс и ноль zombies.
- Launcher сравнивает inode/метаданные/ссылки/содержимое host resolv.conf,
  nsswitch.conf, passwd/group, а также forwarding до/после изоляции.

Unit-команда `npm run test:dns-resolver-object` покрывает промежуточные fsync/
rename точки, offline disable, конфликты, orphan preparation и отказ host probe.
Результат **53/53 PASS**; весь Node acceptance **1376/1376 PASS**, без skips.
Все четыре настоящих namespace-теста (новый и три прежних dnsmasq) — PASS.

## Граница результата и следующий шаг

Результат — same-namespace recovery. Родительский backend переживает смерть
дочернего контроллера; смерть всей VM/ядра этим тестом не моделируется. Новый
resolver journal теперь [связан одним durable coordinator с dnsmasq journal](dns-radxa-journal.md)
в отдельном `--radxa-journal` режиме; старый `--resolver-object` остаётся standalone тестом.
Для dangling-link пары [systemd/reboot и три power-cut точки VM](dns-radxa-vm.md)
уже PASS. Новый localhost-file baseline пока проверяется отдельно в namespace,
не подменяет VM результат другой исходной конфигурации.

Дальше: клиентские ownership/preflight, opt-in установщик и согласованный
baseline/rollback на Radxa с проверкой реальных units/config в VM.
Для живого этапа нужны проверенные daemon/includes/владелец настроек и отдельное
разрешение пользователя. Включать resolved, менять DNS хоста или подключаться
по SSH этот стенд не разрешает. Физический USB, arm64, долгоживущие resolver
кеши, ACL/xattrs, произвольные ссылки и прочие менеджеры не проверены.
DNS v1 остаётся открытым по [фиксированным критериям](dns-v1.md).
