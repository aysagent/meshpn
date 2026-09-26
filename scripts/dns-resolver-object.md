# Radxa: транзакция объекта системного resolver (только стенд)

Проверяется исходная схема Radxa: dnsmasq обслуживает localhost и USB, а
`/etc/resolv.conf` — dangling symlink на
`/run/systemd/resolve/stub-resolv.conf`. Автоматического включения resolved нет.
Это не live-установщик и не команда исправления DNS на настоящем клиенте.

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
resolver journal **ещё не связан одним durable coordinator с dnsmasq journal**.
Прежний dnsmasq VM PASS не распространяется на новую транзакцию resolver.

Дальше: общий координатор и порядок apply/disable обоих журналов, systemd/reboot
в VM, затем opt-in установщик и согласованный baseline/rollback на Radxa.
Для живого этапа нужны проверенные daemon/includes/владелец настроек и отдельное
разрешение пользователя. Включать resolved, менять DNS хоста или подключаться
по SSH этот стенд не разрешает. Физический USB, arm64, долгоживущие resolver
кеши, ACL/xattrs, произвольные ссылки и прочие менеджеры не проверены.
DNS v1 остаётся открытым по [фиксированным критериям](dns-v1.md).
