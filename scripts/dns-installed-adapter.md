# Проверка загруженного DNS-adapter

`dns-client.mjs --inspect-adapter` — read-only команда только для проверенной
установки `/opt/clean-vpn`, явного client opt-in и удерживаемого общего guard
flock. Запуск из checkout отказывается до системных вызовов. Это ещё не
команда включения DNS, установщик, readiness или проверка утечек.

Проверяются:

- Реальный active/running `clean-vpn-dns-adapter.service`, `Type=notify`,
  DynamicUser, MainPID, InvocationID, отсутствие drop-ins и pending daemon-reload.
- Доверенный Node, точный argv, отсутствие переменных инъекции, ненулевой UID,
  нулевые capabilities, NoNewPrivs, системный service cgroup и network namespace.
- Unit на диске совпадает с нашим полным шаблоном для фактических аргументов
  процесса и текущих upstream/domain-policy; порт, readiness-имя и политика
  совпадают с client config.
- Три credentials в mount namespace процесса побайтно совпадают с исходными
  root-owned0600 файлами: upstream.json, domains.json, hmac.key. Credential mount
  read-only; файл regular, без hardlink/symlink. Ключ строго32 байта.
- Контекст службы/процесса, argv/environment, unit и исходные credentials не
  изменились за время проверки. Буферы ключа обнуляются; credentials, argv,
  environment и хеш ключа не попадают в JSON-отчёт.

systemd может выдать чтение root-owned credentials через ACL либо использовать
UID службы на read-only mount. Учитываются оба представления, а не ошибочное
требование всегда иметь владельцем DynamicUser.
[Реализация systemd249 write_credential](https://github.com/systemd/systemd/blob/v249/src/core/execute.c#L2282).

Ограничения: это снимок состояния, не блокировка systemd и не защита от
враждебного root. Пока не доказаны принадлежность UDP/TCP listener и защищённый
readiness непосредственно перед takeover; `activationAuthorized=false`.
Успешная проверка не разрешает installed start/disable сама по себе.

Тесты: `node --test scripts/test-dns-installed-adapter.mjs` проверяет точный
шаблон, аргументы, unit state, несовпадения политики и отказ поддельного token.
Позитивная OS-проверка добавлена в существующую NIC-less coupled VM: настоящий
adapter без preload, отказ до его запуска, проверка credentials, изменение
ключа только на диске с ожидаемым отказом и повтор после восстановления ключа.
Синтетическая служба и alias guard удаляются до остальных lifecycle-проверок.
Результат текущего VM-прогона нужно оценивать по его report.json, не по наличию
этих тестов в коде.

Текущий срез:77/77 targeted tests,1870/1870 общей Node-регрессии PASS
(`/var/tmp/meshpn-acceptance-Z1w7qw/report.json`). В первом boot
`/var/tmp/meshpn-dns-vm-TJnMKi` уже прошёл `installed-cli-baseline-and-refusals`,
включающий настоящий adapter, отличие загруженного ключа от файла на диске
и повторную проверку после возврата ключа. Полный двухзагрузочный lifecycle
на момент этой записи ещё выполняется; это не итоговый VM PASS.

Предыдущий `meshpn-dns-vm-wTzDMt` остановился до запуска adapter: минимальному
guest не хватало `sysinit.target`. В fixture добавлены пассивные sysinit/basic/
network-online targets, production-unit не менялся. Это не проверка полного
дистрибутивного boot graph или wait-online. Неудачный report/serial/manifest
сохранены; пересоздаваемые guest/initrd/kernel/state удалены.
