# Проверка opt-in установленного DNS-контроллера

`lib/dns-installed-authority.mjs` — read-only граница будущего системного
entrypoint. `scripts/dns-client.mjs` имеет только `--help` и read-only `--inspect`;
`--start`, `--disable`, `--install` пока отвергаются. **Это не команда установки
или включения DNS.** Файл boot
policy разрешает только guard; наличие его или корректного DNS journal не
разрешает самостоятельно переключать resolver.

Loader требует отдельно установленные root-owned0600 `client-opt-in.json`
и `client.json` в `/etc/clean-vpn/dns`. Opt-in содержит ровно schema/kind,
`enabled:true`, выбранный `vps2`/`radxa`, guard ID, SHA256 manifest кода и SHA256
клиентской конфигурации. ID/клиент должны совпасть с boot policy. Hash определяет
согласованный вход, **не доказывает пригодность профиля или владение DNS**:
проверки менеджеров, выбранных config sources, reserved IP и readiness остаются
обязанностью клиентской OS factory. Сейчас её подключения ещё нет.

Код предполагается в `/opt/clean-vpn`, manifest `bundle.json`0644 перечисляет
относительные `scripts/*.mjs/js/json` и их SHA256. Обязательны сам модуль проверки
и `scripts/dns-client.mjs`. Инвентаризация ограничена512 файлами/1024
entries/16MiB code, обход каталогов потоковый: отсутствующие/неперечисленные файлы, symlink/hardlink, writable dirs,
неверные mode/owner/hash отвергаются. Каталоги кода0755 доступны также DynamicUser
адаптера, в отличие от закрытого config/state. Code files0644, не executable: unit будет
вызывать их явно через Node. Настоящий установщик ещё должен собирать полный
набор зависимостей; inventory не является анализатором import/require.

Кроме файлов loader проверяет:

- root, systemd PID1, initial net/mnt/pid namespaces и собственный inherited
  exclusive flock того же DNS/guard lock;
- собственный installed path и точный entrypoint
  `/opt/clean-vpn/scripts/dns-client.mjs`;
- Node24.13+ ветки24, interpreter, соответствующий `/usr/bin/node`, root-owned
  executable/ancestors без записи для group/other; только известный аргумент memory limit;
- отсутствие перечисленных Node/loader/OpenSSL injection environment variables.

Возвращается process-local branded token. Повторная проверка сверяет epoch,
lock, opt-in/config/guard identity, interpreter и metadata перечисленных файлов
и каталогов. Изменение конфигурации требует новой согласованной операции, не
hot reload. Token нельзя получить из JSON, копии объекта или результата
read-only inventory. Нет произвольного authority callback, root/path параметра
у loader, переменной окружения или VM-флага для обхода проверки.

Это не защита от враждебного root и не отмена уже выполненного preload/import.
Установщик/unit обязаны обеспечить trusted code и очищенное окружение **до**
запуска Node. Сам модуль не пишет файлы, не исполняет subprocess, не делает DNS,
не ставит firewall и не подменяет VM gates прежних fixtures.

## Проверки и оставшаяся интеграция

`node --test scripts/test-dns-installed-authority.mjs`:23/23 PASS на реальных
private temp files. Проверены формат/ограничения opt-in/manifest, полный inventory,
подмена bytes/mode/owner, missing/unlisted/oversized/malformed файлы, symlink/
hardlink и отказ выдавать token обычному repo-процессу/поддельным объектам.
Это **не положительная VM-проверка installed loader**: read-only main entrypoint
ещё предстоит прогнать в VM; mutating commands и OS factories пока не подключены.
Успешный `--inspect` будет сообщать `dnsOwnershipVerified:false`, а не готовность
к переключению DNS. Ошибки CLI редактируются до фиксированного кода без путей,
конфигурации и stack trace; `--help` не читает системные файлы.
Полная Node-регрессия1803/1803 PASS, без skips:
`/var/tmp/meshpn-acceptance-nrWdSd/report.json` (2026-09-27).
Прежний общий `meshpn-acceptance-KdDWdH` — FAIL: тест ошибочно ожидал root-владельца
у host `/usr/bin/true`, видимого в текущем user namespace как UID65534. Исправлено
ожидание теста, не owner check; положительный installed runtime по-прежнему
требует VM. Это не положительный installed/live acceptance.

## Read-only baseline VPS 2

`--inspect` теперь дополнительно проверяет VPS2 baseline через настоящий fixed
system bus и pinned command runner. Требуется строгий `client.json`:

```json
{
  "schema": 1,
  "kind": "clean-vpn-dns-client",
  "client": "vps2",
  "uplink": "eth0",
  "networkFile": {
    "path": "/run/systemd/network/10-netplan-eth0.network",
    "sha256": "SHA256_СОГЛАСОВАННОГО_ФАЙЛА"
  },
  "adapterPort": 2053,
  "readyName": "example.com",
  "domainPolicy": {
    "schema": 1,
    "denySuffixes": ["auto.internal", "ru-central1.internal"]
  }
}
```

Это пример формы, **не выбранная за пользователя live-политика** и не готовый
файл установки. Hash должен быть64 lowercase hex. Неизвестные поля, неявный
uplink/deny-policy, неподходящий readiness-name отвергаются. В этой версии
поддержано явное блокирование внутренних доменов, не protected cloud resolver.

Проверяются активные resolved/networkd и совпадение MainPID с уникальным D-Bus
владельцем, invocation, executable и net namespace. Файлы перечитываются с
проверкой identity; root-owned конфигурация отделена от runtime-файлов служб,
для которых разрешён UID соответствующего D-Bus peer только в его runtime tree.
Проверяются выбранный networkd-файл/hash, stub symlink, NSS `files dns`,
uplink/default route, отсутствие `cvdns*` и конфликтов адреса/маршрута192.0.2.1,
отсутствие global/чужих DNS-источников и resolved fallback. Все наблюдаемые
search/route domains должны покрываться явной deny-policy; policy на диске
должна совпадать с `/etc/clean-vpn/dns/domains.json`.

Это **проверка исходного состояния**, не active recovery и не разрешение setters:
`baselineChecksPassed:true`, но `activationAuthorized:false`,
`dnsOwnershipVerified:false`. Нет доказательства loaded adapter credentials,
исключения будущего DNS-link из networkd, непрерывного manager lock/readiness.
Radxa пока проходит только прежнюю authority-проверку (`baseline:null`).
Новый collector не имеет injectable IO или обхода installed authority; чистый
assessor принимает тестовые данные, но не выдаёт token.

62/62 targeted tests и1839/1839 Node PASS (без skips),
`/var/tmp/meshpn-acceptance-KwkR6E/report.json`. Это unit/read-only evidence,
не положительный VM installed acceptance; такой прогон следующий.

Далее — завершение client-specific ownership checks, installed entrypoint,
controller units и связь install/activate/disable/uninstall. Только установщик
после проверки всех artifacts и неактивного deployment сможет публиковать opt-in;
пять файлов прежней [файловой транзакции](dns-deployment-files.md) его ещё не
создают. Вручную создавать эти файлы или запускать новый путь на VPS/Radxa пока
не предлагается. [DNS v1](dns-v1.md) остаётся открытым.
