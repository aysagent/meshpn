# Read-only диагностика DNS настоящего клиента

## Один полный отчёт для разбора

В каталоге проекта на будущем **клиенте**, без обязательного sudo:

```bash
node scripts/dns-diagnostic.mjs --probe
```

Скопируйте весь вывод от `CLEAN-VPN DNS DIAGNOSTIC BEGIN` до `END`. Если терминал
обрезает вывод, сохраните в новый приватный файл и передайте файл:

```bash
report_file=$(mktemp /tmp/clean-vpn-dns.XXXXXX) &&
node scripts/dns-diagnostic.mjs --probe > "$report_file" 2>&1 &&
printf 'Файл отчёта: %s\n' "$report_file"
```

Команда диагностики
не меняет настройки, маршруты, firewall, файлы или службы; ничего не устанавливает.
`--probe` разрешает пять проверок для `example.com` через **текущую** конфигурацию:
системный NSS, DNS A/AAAA по UDP/TCP. Эти запросы могут идти напрямую, если так
настроен клиент. NSS использует обычное поведение ОС, включая её on-demand resolver
services. Без `--probe` сетевые проверки не выполняются.

Отчёт содержит исходный `dns-inspect`, версии, resolver/NSS, адреса, маршруты,
policy rules, слушателей 53, состояния служб, отфильтрованные DNS-поля конфигурации
resolved/networkd и текущие DNS-свойства resolved через D-Bus. При чтении D-Bus служба не активируется:
`busctl --auto-start=no`, свойства читаются у найденного уникального владельца.
При PID1 не systemd обращения к system bus пропускаются. Нет setters, вызовов
`start/restart`, journalctl, чтения argv процессов, `.env`, `.netdev`, приватных
ключей или NetworkManager connection profiles. Полные конфиги не печатаются.

Раздел `dnsmasq` читает только `/etc/dnsmasq.conf` и до 16 файлов в
`/etc/dnsmasq.d`. Выводит простые literal upstream/listen IP, интерфейсы,
`no-resolv`, DNS/router DHCP options и простой диапазон IPv4. Другие значения,
скрипты и vendor DHCP options не печатаются; includes отмечаются без чтения
их целей. Это не effective config: argv, нестандартные пути, включение каталога
и правила исключения файлов не определяются. Две декларации option 6 в инвентаре
означают необходимость review, а не доказательство конкретного DHCP OFFER.

**В отличие от краткого dns-inspect, отчёт содержит IP-адреса, DNS-домены, имена
интерфейсов и пути системных конфигов.** Он предназначен для передачи на разбор,
а не для публичной публикации. Пароли/PSK/приватные ключи намеренно не собираются.

Отсутствующая утилита, неизвестное D-Bus свойство, недостаток прав или ошибка
чтения отображаются внутри отчёта; это не повод менять систему ради диагностики.
Без root имена владельцев некоторых сокетов могут отсутствовать. Лимиты: 3 секунды
и 8 KiB на команду, общий бюджет команд 60 секунд (завершение дочерних процессов
может занять ещё до 5 секунд), 8 resolved links, 48 network-файлов/drop-ins.
Все вложенные опросы разделяют один лимит: максимум 4 команды одновременно.
Отсутствующие службы краткой проверки теперь обозначаются `not-found` по
LoadState; ошибки доступа/таймауты остаются `unknown`.
Обрезание инвентаря отмечается явно. DNS-ответы могут быть кэшированными; успешный
probe не доказывает отсутствие утечек. Инвентарь конфигов не вычисляет итоговый
приоритет всех настроек и не доказывает владение ими.
`status: ok` у команды означает успешное выполнение команды, а не автоматически
здоровый DNS: например, DNS RCODE нужно смотреть внутри ответа dig.

Автоматически определить намерение «будущий client/exit», схему `--from-tun` или
наличие аварийной консоли нельзя без догадок/чтения argv. Достаточно при передаче
написать одной строкой, на какой машине запускали и включён ли VPN.

## Краткий отчёт без адресов и доменов

```bash
# В каталоге проекта именно на Linux-машине с clean-vpn client, без sudo
npm run dns:inspect

# Только JSON, без заголовка npm:
node scripts/dns-inspect.mjs
```

Команда ничего не переключает: нет записи файлов, изменения DNS, systemd units,
маршрутов, firewall, TUN, запросов к DNS/upstream или подключения к exit.
Можно запускать при работающем VPN. Вывод — JSON в stdout, не файл отчёта.
Требуется Linux и Node22+. Нельзя передать `--apply`, адрес SSH или произвольный
путь. Это диагностика только **текущей машины**, не удалённого VPS.

Что читается:

- `/etc/resolv.conf`: тип файла/известная категория symlink target, количество
  IPv4/IPv6/loopback nameserver, наличие search/domain и подсказок менеджера.
- `/etc/nsswitch.conf`: только схема hosts lookup. Неизвестные NSS plugins
  представлены как `other`, действия в квадратных скобках не интерпретируются.
- `/proc/1/comm`: только признак systemd/other/unknown.
- `/proc/self/mountinfo`: является ли resolver отдельной точкой монтирования.
- Только если PID1 — systemd: `systemctl --system --no-pager is-active` для
  resolved, NetworkManager, networkd и resolvconf. Четыре фиксированных запроса
  с deadline2с и лимитом вывода4KiB каждый, без restart/reload/enable.

Чтение ограничено64KiB на файл (mountinfo1MiB); special files и oversized input
отклоняются. Ошибки/нет доступа отражаются как `unavailable`/`unknown`, а не
«сервиса нет». systemctl использует минимальный environment и абсолютный путь
`/usr/bin/systemctl`; на системе без него service evidence будет `unknown`.
Если PID1 не systemd, обращения к потенциально проброшенной host system bus нет.

Оборванный symlink больше не теряется при ошибке realpath: `object=symlink`,
`targetKind` отражает известную категорию объявленного назначения,
`targetStatus=missing`, reason `dangling-resolver-symlink`. `readError` различает
missing/permission-denied/symlink-loop/unavailable без раскрытия raw error/path.
Объявленный target — не доказательство работающего сервиса. Пустые строки
mountinfo игнорируются; недоступные metadata не создают ложный `mountpoint=true`.

В отчёт не попадают IP-адреса, search domains, hostname, произвольные пути,
mount source/device IDs, комментарии конфигов, журналы, connection profiles,
PSK/CA и тексты ошибок. Содержимое файлов используется только локально для
фиксированных признаков. Отчёт всё же раскрывает схему DNS и состояния сервисов;
перед публикацией его стоит просмотреть.

## Как читать результат

`assessment.candidates` — **подсказки для исследования**, не достоверный владелец
настроек. `backend` всегда `unselected`, `actualClientConfirmed` всегда `false`:
оператор должен подтвердить, что запуск выполнен на нужном клиенте.

Regular resolv.conf + отсутствие активного менеджера не доказывают unmanaged DNS:
его могут обновлять DHCP hooks, другой init, VPN, контейнерный runtime или скрипт.
Комментарии и symlink могут оказаться устаревшими. Четыре show-запроса служб не
покрывают все возможные службы. Снимок не атомарен и не доказывает здоровье DNS.

NetworkManager и resolved могут присутствовать **одновременно**: один передаёт
DNS-конфигурацию другому, не обязательно переписывая resolv.conf. Выбирать между
ними по принципу «какой сервис активен» нельзя. Нужно проверить эффективную
конфигурацию и владельца link/connection settings.
[NetworkManager DNS/rc-manager](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager.conf.html).

Symlink на resolved stub — признак использования его compatibility resolver,
но не разрешение заменить файл собственным. Для network configuration managers
предусмотрен отдельный API конфигурации resolved.
[Рекомендации systemd для сетевых менеджеров](https://wiki.freedesktop.org/www/Software/systemd/writing-network-configuration-managers/).

Диагностика не проверяет effective manager config, split DNS, маршруты, слушателей
53, доступность upstream, kill-switch, reboot readiness и отсутствие DNS bypass.
`systemDnsChanged=false`/`dnsQueriesSent=0` описывают только действия этой команды,
не состояние защиты VPN или параллельную работу других приложений.

Следующий шаг: передать JSON с **настоящего клиента** и подтвердить роль машины.
По нему выбрать адресную read-only проверку конфигурации менеджера, затем backend.
Установка и live переключение требуют отдельного согласования. До этого остаётся
[изолированный lifecycle/crash стенд](dns-lifecycle.md).
