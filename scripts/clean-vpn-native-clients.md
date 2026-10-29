# Клиенты exit: имя, автоматический адрес и готовый комплект

`clean-vpn-native-clients.mjs` управляет существующим exit, не создавая новый CA
и не меняя ключи уже подключённых устройств. Это control plane; пакеты остаются
в native engine. Поддержаны boring и combo, максимум 32 активные идентичности.

## Однократное подключение

На Linux сначала установите engine с capability `peer_reload`. Действующие
daily-бинарники на физических устройствах этой ночной работой не заменяются.
Старый engine без capability отклоняется до изменения конфигурации.

Пример для собственной установки (пути CA/profile указать фактические):

```sh
sudo install -d -m 700 /var/lib/clean-vpn
sudo node scripts/clean-vpn-native-clients.mjs init \
  --engine=/opt/clean-vpn-native/daily-exit/engine \
  --unit=native-daily-exit.service \
  --config=/opt/clean-vpn-native/daily-exit/config.json \
  --endpoint=154.62.226.216 --server-name=vpn.example.net \
  --ca=/private/ca.pem --profile=/private/profile.json
```

Registry по умолчанию `/var/lib/clean-vpn/clients/registry.json`; каталог должен
быть новым. Для другой установки задайте `--directory=/private/clients` во всех
командах. Engine/unit запоминаются при init. Сертификаты и профиль не берутся
наугад из соседних каталогов: CA должен соответствовать действующему exit.
`--profile` необязателен, но нужен для выбранной браузерной мимикрии.

Существующие адреса получают временные имена `client-2`, `client-3` и т. д.
Для combo при init необходим `--relay-map=/private/map.json`: JSON-объект
`{"10.99.0.2":"client-1"}` явно связывает packet IP с существующим relay id.
Нельзя угадывать соответствие по порядку массивов: отзыв мог бы отключить
чужую relay-идентичность. Файл map должен иметь права 0600.

## Повседневные команды

```sh
sudo node scripts/clean-vpn-native-clients.mjs rename client-2 radxa
sudo node scripts/clean-vpn-native-clients.mjs add laptop
sudo node scripts/clean-vpn-native-clients.mjs list
sudo node scripts/clean-vpn-native-clients.mjs export laptop --output=/root/laptop.bundle
sudo node scripts/clean-vpn-native-clients.mjs rotate laptop
sudo node scripts/clean-vpn-native-clients.mjs revoke laptop
```

`add` назначает первый свободный адрес `10.99.0.2..254`. Он остаётся за
идентичностью после переподключения и отзыва: автоматического повторного
использования адреса отозванного клиента нет. Это стабильное автоматическое
назначение при регистрации, **не выдача адреса в TLS handshake**.
Имя — одна строчная DNS-метка, например `laptop`; DNS-имя — `laptop.mpn`.
[Resolver зоны](clean-vpn-native-peer-dns.md) включается отдельно.

`list` не раскрывает ключи; connectionState пока `unknown`, это реестр, не
счётчик активных сессий. `export` создаёт новый файл 0600, ничего не печатает
из ключевого материала в stdout и не перезаписывает существующий файл.
Комплект содержит секреты: передавать только нужному клиенту. После ротации
нужно экспортировать новый комплект. Имя можно менять без ротации.

Для заведомо остановленной/офлайн установки вместо unit используйте `--offline`.
Результат прямо сообщает `requiresReload:true`; это не применение в работающий
процесс. Сам скрипт не останавливает службу и не меняет маршруты или firewall.

## Импорт на клиенте

```sh
sudo node scripts/clean-vpn-native-clients.mjs import \
  --bundle=/root/laptop.bundle --directory=/root/laptop-config \
  --engine=/absolute/path/clean-vpn-engine
```

Создаются только новый каталог и role-specific config/credentials. `--check-config`
обязателен; активировать сеть этим скриптом нельзя. Engine config остаётся
совместимым с существующими network/runtime installers. Для переноса в `/config`
контейнера импорт выполняйте с конечными путями внутри контейнерного окружения.
При неуспешной native-валидации новый каталог сохраняется для диагностики,
но не активируется. Повторный импорт поверх существующего каталога запрещён.

## Применение и восстановление

До mutation проверяется capability и identity работающего unit: actual process
должен исполнять указанный engine с этим config path. Затем готовится candidate,
проверяется engine, сохраняется журнал точных предыдущих/новых config и registry.
После atomic replace посылается SIGHUP только главному процессу unit.
Успех требует события `peer_reload` с SHA256 точных байтов конфигурации из journal.
Неизменённые сессии продолжают работу; отозванные/rotated закрываются.

Ошибки применения вызывают возврат предыдущих файлов и reload. При аварии:

```sh
sudo node scripts/clean-vpn-native-clients.mjs recover
```

Kernel flock не остаётся захваченным после SIGKILL. Pending journal запрещает
другие операции до recovery. Внешние изменения config/registry вызывают конфликт:
не затираем настройки администратора восстановлением вслепую.
Для Linux нужен `flock` (util-linux); macOS unit tests используют Python fcntl,
но systemd activation предназначена только для Linux.

Combo создаёт новый replay id при добавлении/ротации, инициализирует только его
журнал и сохраняет старые журналы. Ключи и replay-каталоги не удаляются
автоматически после отзыва/неуспешной транзакции; это приватные остатки для
проверяемого восстановления, не разрешение доступа.

## Проверки

```sh
node --test scripts/test-native-clients.mjs scripts/test-native-client-manager.mjs
CVPN_BUILD=/absolute/linux/build node --test scripts/test-native-client-enrollment.mjs
```

Проверены отдельные ключи, стабильные адреса, лимиты, import path validation,
конкуренция, rollback, SIGKILL и сохранение посторонней правки. Linux enrollment
соединяет экспортированного клиента .3 с настоящим native exit: boring/combo,
H1/H2, пакеты генерирует C++ socketpair fixture. Это не системная DNS-интеграция,
не обновление физической daily-установки и не выдача адресов при подключении.

Старый offline `--manifest=... --directory=...` интерфейс и экспортируемые
`planNativeClients`/`prepareNativeClients` сохранены для существующих site labs.
[Его отдельная документация](clean-vpn-native-client-bundles.md); он создаёт новый
комплект и не добавляет пользователей в действующий exit.
