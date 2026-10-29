# Native: HTTP/1.1 и HTTP/2 между client и exit

29 октября 2026: добавлена HTTP/1.1-ветка внешнего TLS-туннеля native engine.
Она доступна для `boring-tls` и `boring` внутри `combo-tls`, в standalone и
контейнерном runtime. Маршруты, DNS, guard и transparent-ветка от выбора HTTP
не зависят. На физической Radxa/VPS это обновление пока не установлено.

Речь именно о **внешнем client–exit соединении**. HTTP/1.1 приложений внутри
IP-туннеля и исходный HTTPS в transparent могли передаваться и раньше.
Отдельного native backend с названием `tls` сейчас нет: TLS завершает BoringSSL.

## Настройка

В engine JSON есть необязательное строковое поле `http_version`:

| Значение | Client | Exit |
| --- | --- | --- |
| `"2"` | Только согласованный `h2`; значение по умолчанию | Принимает только `h2` |
| `"1.1"` | Только согласованный `http/1.1` | Принимает только `http/1.1` |
| `"auto"` | Предлагает обе версии, либо точный ALPN сохранённого профиля | Принимает обе, предпочитает `h2`; значение по умолчанию |

Без сохранённого профиля, чтобы использовать HTTP/1.1, добавьте в client JSON:

```json
"http_version": "1.1"
```

Обновлённый exit с настройками по умолчанию примет такой client. Для явного
ограничения exit тоже можно задать `"http_version":"1.1"`. Один exit в `auto`
обслуживает клиентов обеих версий одновременно с прежними независимыми PSK/IP.
В combo поле добавляется **внутрь `boring`**, а не на верхний уровень JSON.

После изменения конфигураций сначала выполнить на соответствующих узлах:

```sh
native/clean_vpn/build/clean-vpn-engine --check-config /absolute/engine.json
native/clean_vpn/build/clean-vpn-engine --capabilities
```

Затем управляемо перезапустить соответствующий экземпляр. Проверка конфигурации
сама не создаёт TUN/listener и не меняет сеть. Оба бинарника должны поддерживать
новый режим; новый client в HTTP/1.1 не сможет подключиться к прежнему h2-only
exit. При `auto` версия выбирается ALPN в одном TLS handshake: нет повторной
попытки с ослаблением проверки сертификата, открытого HTTP или режима без ALPN.

Параметр пока задаётся в engine JSON; переключатель в веб-админке не добавлен.
Настройки читаются при запуске, а не меняют уже открытое соединение.

## Сохранённый браузерный профиль

Список ALPN профиля **не переписывается**. Поддерживаются `h2`, `h2,http/1.1`
и `http/1.1`. Если профиль содержит только `http/1.1`, client должен использовать
`1.1` либо `auto`; несовместимый профиль отклоняется до сетевого соединения.

Для существующего Chromium-профиля с `h2,http/1.1`, чтобы проверить именно H1:

- Client: `"http_version":"auto"`, прежний `tls_profile_path`.
- Exit: `"http_version":"1.1"`.

Так сохраняются предлагаемые браузером параметры ClientHello, а exit выбирает
HTTP/1.1 из предложенного списка. Принудительный client `1.1` с таким смешанным
профилем отклоняется: иначе пришлось бы незаметно удалить `h2` из ClientHello
либо разрешить противоположный результат negotiation.

ALPS регистрируется только для `h2`; при выбранном H1 H2 SETTINGS не отправляются.
Профиль H1-only не может содержать ALPS для отсутствующего `h2`.
Независимый наблюдатель продолжает сравнивать реальный ClientHello с JSON и
считать JA3/JA4. ALPN-компонент JA4 описывает предложение в ClientHello,
а не обязательно выбранный сервером протокол: у смешанного профиля он может
оставаться `h2` при фактически согласованном HTTP/1.1.

Это не полная HTTP-мимикрия браузера: User-Agent, набор/порядок HTTP-заголовков
и длительный POST не копируются из захвата. Страница browser capture пока
по-прежнему измеряет H2; её смешанный TLS-профиль можно использовать указанным
способом. Отдельный H1 ClientHello можно проверить/скомпилировать через
`clean-vpn-native-profile-observe.mjs`.

## Формат и ограничения

После TLS и ALPN client отправляет `POST /clean-vpn HTTP/1.1`, Host,
exporter-bound Bearer и окно времени. Запрос и ответ `200` имеют
`Transfer-Encoding: chunked`, `Content-Type: application/octet-stream` и
`X-Clean-Vpn-Protocol: h1-v1`. Это один двунаправленный поток на соединение.
Chunked framing описан в [RFC 9112, §7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1).

Внутри тела сохраняется `uint32be length + IPv4 packet`; длины 0/1 зарезервированы
под ping/pong с 8-байтовым nonce. HTTP-чанки и TLS records могут произвольно
фрагментировать эти записи. Проверяется IPv4 checksum/длина и принадлежность
адреса аутентифицированному клиенту; межклиентская маршрутизация не разрешается.

Сохраняются CA/hostname/time verification, привязка PSK к TLS exporter,
диагностика доказанного рассогласования часов и запрет пакетов до аутентификации.
Нативный reactor и очереди по 1 MiB общие с H2. Ping отправляется через 2 секунды,
ожидание совпадающего pong ограничено 5 секундами; peer control ограничен
16 записями в секунду. После обрыва используются прежние reconnect/stop и
`connection_mode`. Корректный конец chunked response переводит on-demand client
в ожидание нового трафика.

HTTP parser ограничен 8 KiB/32 полями заголовков, 256 байтами строки размера
чанка и 1 MiB на объявленный чанк; он не накапливает весь чанк в памяти.
Отвергаются дубли полей, CL+TE, obs-fold, Upgrade, Expect, Content-Encoding,
непустые trailers и дополнительные HTTP messages. Это ограниченный протокол
между двумя управляемыми endpoint, не универсальный HTTP proxy. Native H1
использует собственный `h1-v1` контракт; совместимость со старым Node H1 не заявляется.

## Локальная приёмка

Linux ARM64, отдельный Podman-контейнер без WAN и без TUN/routes хоста:

```sh
ctest --test-dir "$CVPN_BUILD" --output-on-failure
node --test scripts/test-native-data-plane.mjs scripts/test-native-multi-peer.mjs
node --test scripts/test-native-http1.mjs scripts/test-native-tls-profile.mjs
node --test scripts/test-native-clock-auth.mjs scripts/test-native-profile-policy.mjs
```

`CVPN_BUILD` — абсолютный каталог Linux-сборки с production engine,
`clean-vpn-engine-fixture` и `integration-test`. Packet-fd применяется только
в fixture binary; production binary его отвергает.

Проверены двунаправленные пакеты до 65535 байт, 2000 пакетов, reconnect,
зависший peer, backpressure, стабильные FD/RSS, stop/service mode,
неверные CA/hostname/PSK, clock proof, HTTP framing attacks, независимый Node
HTTP peer, смешанные H1/H2 клиенты (включая 32), изоляция адресов, профили и combo.
Новый parser также прогнан с ASan/UBSan.
Сводка: [HTTP/1.1 lab report](../fixtures/clean-vpn-native-http1-20261029.json).
[Физический WAN smoke](clean-vpn-native-physical-20261029-evening.md) прошёл
на Radxa/VPS: boring и packet-ветка combo, H1/H2, внешние pcap/profile checks.
Он использует fixture packet-fd; сравнение скорости через настоящий TUN
остаётся отдельной проверкой. Daily engine пока не заменялся.
