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
обязанностью клиентской OS factory. Подключены только read-only baseline
проверки VPS2; mutation authority/readiness пока не подключены.

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
Эти unit tests сами по себе **не положительная VM-проверка installed loader**;
последующий реальный installed прогон описан ниже. Mutating commands и OS
factories пока не подключены.
Успешный `--inspect` сообщает `dnsOwnershipVerified:false`, а не готовность
к переключению DNS. Ошибки CLI редактируются до фиксированного кода; для
installed path допускается также `DNS_CLIENT_LOCATION=модуль.mjs:строка`
из фиксированного allowlist. Абсолютные пути, значения конфигурации, assertion
message и полный stack trace не выводятся; `--help` не читает системные файлы.
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
`/var/tmp/meshpn-acceptance-KwkR6E/report.json` — первый срез baseline.
Последующий VM запуск выявил ошибку string property: `get-property` возвращает
`ResolvConfMode` как строку, а не singleton method tuple. Исправлены парсер и
тест, требования к владельцам/политике не ослаблены. Node1841/1841 PASS,
`/var/tmp/meshpn-acceptance-N3lmI5/report.json`.

В existing coupled VM добавлен реальный read-only installed CLI: bundle/code
0644/0755, opt-in/config0600, тот же flock, настоящий networkd и resolved.
Проверяются положительный baseline и отказы без opt-in, без lock, при другой
policy на диске. Fixture затем удаляет временный opt-in и возвращает прежний
sentinel, NSS/resolver и маршрут перед обычным lifecycle; controller всё ещё
использует VM-gated backend, а не installed setters. Нет проверки loaded
adapter credentials: adapter ещё не запущен на этапе inspection.

Для inspection используется синтетический нелокальный DNS10.129.0.2 без
запросов к нему. Loopback sentinel не подходит для строгого VPS2 uplink-profile:
resolved публикует для localhost DNS индекс loopback, независимо от link;
это видно в [dns_server_ifindex systemd v255](https://github.com/systemd/systemd/blob/v255/src/resolve/resolved-dns-server.c#L581).
Строгий отказ collector для такого неоднозначного baseline сохранён.

Последующее дополнение: теперь baseline также читает root-owned0644
`/etc/systemd/network/00-clean-vpn-dns.network`, требует точное тело renderer
и повторно сверяет identity. Результат содержит
`networkdExclusionFileVerified:true`; это проверка файла, **не** доказательство
его загрузки или текущего unmanaged state ещё не созданного link. Такая
runtime-проверка добавлена в отдельный networkd249 namespace-стенд и остаётся
обязательной для будущего installed setter backend. Прежний21-check VM ниже
предшествует этому дополнению, не является его положительной VM-проверкой.

Сохранённые неудачные прогоны: `meshpn-dns-vm-2Tmfnt` — в минимальном guest
не было пользователя systemd-network; `t4Qnjh` — generic refused до исправления
scalar property; `fGT77Y`/`bX7iYP` — отказ проверки DNS-источника (в bX7iYP
точно локализован на ifindex-check). Reports/manifests/serial logs сохранены,
пересоздаваемые guest/initrd/kernel/disks удалены для освобождения места.

Итоговый installed + coupled lifecycle: **21/21 PASS, две загрузки**,
`/var/tmp/meshpn-dns-vm-KXJ20n/report.json`. В каждой загрузке прошёл настоящий
installed `--inspect` и три отрицательных сценария. После возврата fixture
прошли прежние lifecycle/guard/откат проверки; baseline queries0 под guard,
positive controls PASS, host DNS unchanged. Все502 JS-копии manifest сверены
с исходниками этой записи. Минимальный x64 guest/systemd255, не настоящий
VPS2 systemd249 и не Radxa ARM64; VM не заменяет пилоты или live-установщик.

Далее — завершение client-specific ownership checks, installed entrypoint,
controller units и связь install/activate/disable/uninstall. Только установщик
после проверки всех artifacts и неактивного deployment сможет публиковать opt-in;
пять файлов прежней [файловой транзакции](dns-deployment-files.md) его ещё не
создают. Вручную создавать эти файлы или запускать новый путь на VPS/Radxa пока
не предлагается. [DNS v1](dns-v1.md) остаётся открытым.
