# Radxa Zero 3W → второй exit, 12 ноября 2026

Zero (`192.168.7.1`, USB `usb0`, Wi-Fi `wlan0`) перенесена с
`154.62.226.216:443` на **`84.201.14.124:443`**. Транспорт — `combo-tls`,
отдельная packet identity `10.99.0.6` и relay identity `radxa-zero3`.
A7Z и проектор используют другие ключи/адреса. Установка Zero остаётся в
`/opt/clean-vpn-native/combo-daily`; network owner включён в автозапуск.
Браузерный профиль `native-daily-installed.json` (Chromium 156 bounded cold)
сохранён, engine не заменялся.

## Причина ошибки админки

Форма меняла `boring.address`, оставляя `transparent.exit.ipv4` старым.
Native проверка отвергала несогласованный combo-кандидат как `command_failed`
раньше предусмотренного отказа миграции endpoint. Действующие файлы при этом
не менялись. Проверка endpoint теперь выполняется раньше; UI объясняет,
что переноса одних IP/порта недостаточно. Автоматическая миграция между exit
через эту форму по-прежнему не реализована.

## Применённые изменения

- На exit добавлены отдельные packet/relay PSK и новый replay journal.
  Persistent и runtime config проверены; SIGHUP подтверждён событием
  `peer_reload: applied`, revision 2. PID и время запуска контейнера прежние;
  другие identities сохранены. Серверный приватный TLS/CA key не копировался.
- На Zero согласованно обновлены обе ветки combo, CA, packet/relay ключи,
  `network.json` (включая DNS peer и USB redirect), endpoint guard,
  SSH identity/host pin и адрес ограниченного восстановления часов.
  Inactive combo settings и соответствующие installed digests обновлены.
- Собственное USB mDNS-исключение снимается перед обновлением guard и
  возвращается после: старый guard требует свой OUTPUT hook первым.
  Попытка без этого порядка была отвергнута без изменения firewall.
- Перед переносом сохранена копия настроек; был установлен независимый
  12-минутный systemd rollback timer. После успешных проверок перенос отмечен
  committed, timer остановлен. Kill switch остался включён.
- Правка админки получена на Zero через git и применена только к broker/UI;
  службы админки перезапущены. Настройки Wi-Fi, USB gadget/DHCP и сеть Mac
  не менялись. Полного обновления установленного runtime не выполнялось.

Приватные материалы: на Zero `/root/zero-exit-migration-20261112/`,
на VPS `/var/lib/clean-vpn-new-exit/radxa-zero3-20261112/`.
Экспорт нового клиента на VPS:
`/var/lib/clean-vpn-new-exit/exports/radxa-zero3.bundle.json` (0600).
В Git ключи, bundle и копии конфигураций не добавляются.

## Проверено

- 36 локальных тестов broker/транзакций/сообщений UI прошли.
- Native `--check-config`: client combo и exit с 5 packet / 4 relay identities.
- Реальный TLS/PSK: Zero `ready`; HTTPS через `tun0` возвращает IP нового VPS.
- Ограниченный SSH clock probe проверяет закреплённый host key и возвращает
  synchronized=true; часы Zero при проверке не изменялись.
- USB smoke с Mac: A/AAAA DNS по UDP/TCP; HTTP/HTTPS example.org;
  internet.yandex.ru отвечает 302, www.speedtest.net — 200;
  HTTP и HTTPS api.ipify.org возвращают `84.201.14.124`;
  download 1 MiB и upload 256 KiB проходят. TLS validation включена.
- Вход в настоящую web-админку и сохранение текущих параметров через API:
  job passed, saved/restarted/applied=true; после restart — ready,
  guard=true, pending recovery=false.

Это проверка ограниченных запросов через USB, не браузерного замера Speedtest
и не iPhone. Перезагрузка Zero в этой операции не выполнялась.

## Исправление после перезагрузки пользователем

После следующей загрузки Zero engine не стартовал: network owner был active,
но `native-combo-daily-binary-recovery.service` завершалась с
`update_bound_unit_or_controller_changed`. При миграции был обновлён digest
guard в `installed.json`, но пропущена его отдельная статическая привязка
в `binary-updates/service.json`. Уже активная oneshot recovery скрыла ошибку
при первоначальном сохранении через UI; после boot она выполнилась заново.

Исправление выполнено под `binary-updates/operation.lock` при остановленном
engine и отсутствии `transaction.json`. Проверены все статические hashes:
отличался ровно guard unit. Его исходный hash совпал с резервной копией,
а новые байты — с единственной заменой `--server=154.62.226.216` на
`--server=84.201.14.124`. Новый hash уже соответствовал installed manifest;
активный engine совпал с `active.json`. Обновлён только этот pin, исходный
`service.json` сохранён рядом с резервной копией миграции. Guard unit получил
обычный режим 0644; ранее umask миграции оставил 0600 (это давало warning
systemd, но причиной отказа был именно digest).

Проверка целостности и Requires/After не отключались. Для последующих
миграций обязательны проверка `--status` установленного update controller
и новый запуск recovery unit, а не только restart engine с уже активной
oneshot recovery. Не перепривязывать весь inventory к текущему содержимому:
изменённые файлы должны быть отдельно сверены с разрешённой миграцией;
при pending binary transaction перенос запрещён.

После исправления `--status` прошёл, pending=false. Engine и recovery oneshot
были остановлены отдельно, затем VPN включён именно web API админки:
job `vpn-start` passed (2.8 с), recovery заново выполнилась успешно, engine ready,
guard=true. Повторный USB smoke прошёл все 8 запросов, включая HTTP/HTTPS
внешний IP нового VPS, DNS UDP/TCP и download/upload. Плата оставлена с VPN
и защитой включёнными. Полной перезагрузки платы в этой проверке не было.
