# Клиенты exit в админке

Backend и страница поддерживают список, добавление по имени, переименование,
экспорт комплекта, ротацию и отзыв доступа через общий NativeClientManager.
Адрес выбирает менеджер, имя формирует `<client>.mpn`. В обычном списке нет
ключей или путей к ключам; статус соединения пока `unknown`, если источник
не предоставляет фактическое состояние. Разрешённый доступ не означает online.

## Явное подключение существующего реестра

Привилегированный host broker принимает дополнительный **доверенный параметр
конфигурации** `clientsDirectory`, указывающий на уже инициализированный приватный
реестр менеджера. Его `configPath` обязан совпадать с `vpnConfig` broker.
Роль engine должна быть `exit`. `engine` и `vpnUnit` тоже берутся только из
конфига broker; API не принимает произвольные пути, unit или команды.

Перед изменением проверяется поддержка peer reload. Менеджер проверяет identity
процесса/конфигурации, валидирует новый config и ждёт подтверждения применения.
Ошибки возвращаются через историю операций. Init и восстановление незавершённой
транзакции остаются явными CLI-операциями, админка не усыновляет чужой config.

**Штатный USB installer остаётся предназначен для Radxa client.** Для host exit
добавлен [отдельный localhost installer](EXIT-INSTALL.md): он подключает готовый
реестр, создаёт ограниченные broker/web unit и не открывает публичный TCP API.
Физические узлы этим изменением не обновлялись.

## API и секретные данные

Все endpoints сохраняют существующие session/Host/Origin/CSRF проверки.
Мутации требуют предварительно сменить стандартный пароль `admin`.

| Endpoint | Метод и тело |
| --- | --- |
| `/api/clients` | GET |
| `/api/clients/add` | POST `{ "name": "laptop" }` |
| `/api/clients/rename` | POST `{ "name": "laptop", "newName": "work-laptop" }` |
| `/api/clients/rotate` | POST `{ "name": "laptop", "confirm": true }` |
| `/api/clients/revoke` | POST `{ "name": "laptop", "confirm": true }` |
| `/api/clients/export` | POST `{ "name": "laptop" }` |

Мутации используют существующую очередь jobs. Список и результаты проходят
явную проекцию публичных полей. Экспорт возвращается **только отдельным
attachment** `laptop.meshpn.json` с `Cache-Control: no-store`, не сохраняется
в jobs/history/diagnostics и не становится GET-ссылкой. Комплект содержит
секреты конкретного клиента; его нужно передавать только этому устройству.

## Роли и контейнеры

Страница «Клиенты» видна только при `role: exit, clients: true` в capabilities.
Host exit broker отвергает операции Wi-Fi/kill-switch/profile-settings,
предназначенные для клиента. Frontend также скрывает элементы, которые backend
явно отключил: Wi-Fi, переключатель guard, hostname, observer, profile import,
VPN settings и probes. Контейнерный supervisor может предоставить свою матрицу
возможностей без ложных кнопок управления Linux-хостом.

Захват браузерного ClientHello остаётся отдельной страницей. Если backend
не умеет импортировать профиль или работает как exit, кнопка сохранения
кандидата скрыта. Сам захват не меняет exit/browser profile.

## Проверки

`node --test admin/test/*.test.mjs` — **40/40**; вместе с DNS `.mpn` — **60/60**
на Linux ARM64 в одноразовом Podman-контейнере `--network none`. Проверены
permissions/API boundaries, CSRF, default password, attachment, отсутствие
секретов в history, role restrictions и сохранение прежних admin regressions.

`node admin/test/clients-browser.mjs` — отдельный Chromium с настоящим DOM,
API frontend и fixture broker: роль exit, скрытые неподдерживаемые элементы,
добавление, таблица и подтверждённый отзыв. Все запросы браузера ограничены
loopback; это не проверка реального engine из браузера. Chromium в этом окружении
не выполнял rAF polling; smoke использует конечный interval polling и DOM submit.

Системная маршрутизация зоны `.mpn` и импорт комплекта на новый клиент описываются
отдельно; запись имени в списке не означает, что системный resolver уже подключён.
