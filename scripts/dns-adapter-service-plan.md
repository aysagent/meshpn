# DNS adapter: offline план systemd-сервиса

Часть будущего opt-in deployment, **не установщик**. Команда читает один JSON
и печатает план с содержимым трёх файлов и SHA256. Не создаёт эти файлы, не
вызывает systemctl, не читает PSK, не делает DNS-запросов и не меняет систему.
`installationAllowed=false` всегда. Не копируйте результат в `/etc` до проверки
полной клиентской интеграции, guard/controller и согласованного live-перехода.

```bash
node scripts/dns-adapter-service-plan.mjs --config=/path/service-input.json
```

Вход — regular non-symlink UTF-8 JSON до128KiB, ровно следующие поля:

```json
{
  "schema": 1,
  "exitIp": "YOUR_PUBLIC_EXIT_IP",
  "exitPort": 443,
  "publicName": "YOUR_EXIT_PUBLIC_NAME",
  "listenPort": 1053,
  "readyName": "example.com",
  "upstream": {
    "schema": 1,
    "transport": "doh",
    "hostname": "YOUR_DOH_TLS_HOSTNAME",
    "port": 443,
    "path": "/dns-query",
    "bootstrap": { "addresses": ["YOUR_VERIFIED_PUBLIC_RESOLVER_IP"] },
    "trust": { "mode": "bundled" }
  },
  "domainPolicy": { "schema": 1, "denySuffixes": ["YOUR_EXPLICIT_DENIED_SUFFIX"] }
}
```

`YOUR_…` — обязательные замены, с ними план отклоняется. `upstream` — уже
согласованный [upstream JSON](dns-upstream-config.md), включая custom CA при
необходимости. Публичный resolver, exit и политика внутренних имён автоматически
не выбираются. Для VPS2 выбор cloud-name policy остаётся отдельным решением.
`domainPolicy` обязателен, проверяется существующим compiler; readiness-имя не
может быть запрещено. Проверяется public числовой exit IPv4/IPv6, hostname-форма,
порты, enc-SNI размер и лимиты будущих config-файлов. Расширения/пустые поля,
неизвестные опции, обход TLS и direct fallback отклоняются.

План содержит upstream IP/имя/публичные CA и DNS suffixes: это не секретный ключ,
но перед публикацией просмотрите эти сведения. Ошибка — только
`DNS_SERVICE_PLAN_INVALID`, exit1, без input/PSK/stack.

## Фиксированный layout и обязанности установщика

- `/etc/systemd/system/clean-vpn-dns-adapter.service`, root0644.
- `/etc/clean-vpn/dns/upstream.json` и `domains.json`, root0600.
- Уже согласованный 32-байтовый PSK в `/etc/clean-vpn/dns/hmac.key`, root0600;
  **его нет в плане**, новый ключ не генерируется.
- Проверенные root-owned исходники в `/opt/clean-vpn` и совместимый Node в
  `/usr/bin/node`. Запуск из пользовательского writable checkout или NVM-home
  не является поддержанным deployment layout.

Дальнейший установщик должен проверить весь ownership/context и исходные
состояния, сохранить журнал, установить guard и лишь затем управлять adapter/OS
DNS. Сам план не проверяет наличие этих файлов, актуальность preflight-отчёта,
живой exit, зависимости unit или реальную загрузку конфигов. Hash в JSON —
идентификатор содержимого, не подпись и не разрешение на установку.

## Политика сервиса

Адаптер не нуждается в root: `DynamicUser=yes`, пустой capability set,
`NoNewPrivileges=yes`, readonly system/home, private tmp/devices и запрет core
dumps. Node JIT не ограничивается несовместимым `MemoryDenyWriteExecute`.
Разрешены только AF_UNIX/INET/INET6; это ограничение семейств, **не firewall**.
FD256/tasks64 и Node heap192MiB — первоначальные бюджеты, не лимит всего RSS.

Три входа передаются через `LoadCredential`; корневой PSK не открывается
непривилегированным процессом напрямую и не кладётся в argv/Environment.
В ExecStart используется `${CREDENTIALS_DIRECTORY}`, без shell и без зависимости
от более нового `%d` specifier. Семантика credentials/DynamicUser:
[systemd.exec 249](https://github.com/systemd/systemd/blob/v249/man/systemd.exec.xml);
подстановка одного аргумента —
[systemd.service 249](https://github.com/systemd/systemd/blob/v249/man/systemd.service.xml).

`Type=notify` и четыре защищённые A/AAAA UDP/TCP пробы предшествуют READY.
`BindsTo`/`After` требуют отдельный `clean-vpn-dns-guard.service` (здесь он не
генерируется). Состояние active у guard само по себе не доказывает наличие rules:
контроллер всё равно обязан перепроверять их перед takeover/recovery.
`Restart=no`, нет `[Install]`, ExecStop rollback или автоматического boot enable.
Остановка адаптера не разрешает снимать защиту или менять DNS-настройки.
Перезапуск и восстановление зависимостей — задача общего контроллера.

## Проверки и границы

`npm run test:dns-adapter-service-plan`: deterministic artifacts/hashes, strict
input/size limits, ошибки без секретов, IPv6 literal, отсутствие сетевых вызовов,
read-only CLI и совместимость аргументов с настоящим adapter parser.
Настоящий unprivileged/credentials service проверяется отдельно в
[systemd VM](dns-systemd-vm.md); это не live PASS на VPS2/Radxa. Другие VM cases
сохраняют прежние fixture units до отдельного переноса.

Результат: **25/25 unit/CLI PASS**, **12/12 VM lifecycle PASS в двух загрузках**,
`/var/tmp/meshpn-dns-vm-WlsDhv/report.json`. Проверены UID>0, CapEff0, NNP1,
runtime credentials и отказ чтения исходного PSK от UID адаптера; SIGKILL/recovery,
reboot и disable. Node-регрессия:1572/1572, `/var/tmp/meshpn-acceptance-0wWNMq/report.json`.
В VM2 vCPU MTTCG; deadlines/retry не ослаблены. Прежний1-vCPU SERVFAIL
инструментирован: DNS_TIMEOUT1718мс при deadline1500мс, не доказательство утечки.
История исправлений стенда и ограничения — в [VM-документе](dns-systemd-vm.md).
Это systemd255/x64 без journald, не проверка systemd249/ARM на живых клиентах.
Установщик, guard/controller deployment и live-пилоты всё ещё требуются.
