# Read-only диагностика DNS настоящего клиента

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
Комментарии и symlink могут оказаться устаревшими. Четыре is-active запроса не
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
