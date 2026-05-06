# Поддержка HTTP/2 в `--type=tls`: оценка и варианты

Краткий итог: HTTP/2 поддерживается в Node «из коробки» (`node:http2`), технически добавить можно за день-два. Но **выигрыш для маскировки невелик**, и есть несколько архитектурных развилок.

## Что даёт HTTP/2 для маскировки

Полезно:

- В реальном браузере при ALPN `[h2, http/1.1]` сервер чаще всего выбирает `h2` — наш текущий exit выбирает `http/1.1`. Активный сканер, поднявший свой TLS, видит «предложил h2, согласовался h1.1» — это редкая для современных сайтов комбинация.
- Внутри h2 трафик нарезан на DATA-фреймы с хедерами, есть SETTINGS/PING/WINDOW_UPDATE — DPI с поверхностной семантической детекцией такое распознаёт как «реальный h2».

Не помогает:

- В TLS 1.3 **выбранный** ALPN зашифрован → пассивный наблюдатель уже сейчас не видит, что выбрали `http/1.1`.
- Шумовой профиль трафика (двунаправленный поток MTU-пакетов) — определяется самим VPN, а не транспортом поверх. h2-фреймы не маскируют то, что внутри идёт «не браузерный» поток.
- Активный сканер, попадающий на `It works!`, всё равно видит правдоподобную страницу — что h1.1, что h2.

То есть h2 — это «ещё на пол-шага ближе к Chrome», а не качественный скачок.

## Варианты реализации

### Вариант A. Тот же `--type=tls`, h2 как апгрейд при согласовании

Exit предлагает `['h2', 'http/1.1']`, client offer'ит `['h2', 'http/1.1']` (как сейчас). После handshake обе стороны смотрят `tlsSock.alpnProtocol`:

- `'h2'` → поверх той же TLSSocket поднимается `http2`-сессия (`http2.connect({ createConnection: () => tlsSock })` на client; на exit — отдельная `http2.createSecureServer` или ручное оборачивание сокета). Открывается один stream `:method GET :path /clean-vpn :authorization Bearer …`, exit отвечает `:status 200`, дальше `Http2Stream` (он `Duplex`) работает как socket-like для `attachTunBridge`.
- `'http/1.1'` → текущий путь без изменений (fallback).

Плюсы: ClientHello идентичен браузерному, пассивно не отличить; есть честный fallback; код нового всего ~200-300 строк.

Минусы: на exit при текущем pre-handshake passthrough (`SNI mismatch → пробрасываем чужой ClientHello`) интеграция с `http2.createSecureServer` чуть труднее — нужно либо

1. оставить `tls.createServer` + ручной `tls.TLSSocket`, а h2-сессию поднимать поверх готовой TLSSocket через `http2.createServer({ allowHTTP1: false })` + `server.emit('connection', tlsSock)` — это рабочий, но не вполне публичный путь;
2. либо переписать exit на `http2.createSecureServer({ allowHTTP1: true })` и ловить «чужой» ClientHello через событие `unknownProtocol`/`tlsClientError`. Чище, но больше переписывать.

В обе стороны достаточно тонкой обёртки h2-stream → socket-like (по образцу [`quicBidiToSocketLike`](clean-vpn.js)), потому что `Http2Stream` и так `Duplex`.

Сложность: **средняя**, ~1-2 дня + тесты. Основное — exit-сторона интеграции h2 с существующим SNI-passthrough.

### Вариант B. Отдельный транспорт `--type=h2`

Использует `http2.createSecureServer` на exit и `http2.connect` на client — без h1.1-ветки. ALPN только `['h2']`.

Плюсы: чище код, нет ветвления.

Минусы:

- ALPN `['h2']` без `'http/1.1'` — само по себе **fingerprint**: реальный Chrome всегда предлагает оба. Это снижает маскировку по сравнению с вариантом A.
- Лишний `--type` для пользователя.
- Дублирование кода `--type=tls` (cert/SNI/passthrough).

Не рекомендовал бы.

### Вариант C. HTTP/2 CONNECT (RFC 7540/8441)

Вместо `GET /clean-vpn` использовать стандартный CONNECT-tunneling — это то, как браузеры через corporate-proxy и WebSocket-over-h2 (extended CONNECT) делают тунели:

```
:method = CONNECT
:protocol = clean-vpn       (Extended CONNECT, RFC 8441; на exit нужен SETTINGS_ENABLE_CONNECT_PROTOCOL)
:authority = <verifyName>
authorization = Bearer …
```

Плюсы: семантически «правильный» способ туннелировать произвольные байты в h2-stream; меньше «странных» эвристик.

Минусы: примерно та же сложность, что и Вариант A; чуть менее знакомый паттерн для отладки.

## Рекомендация

1. **Пока — не добавлять.** Текущее состояние (TLS 1.3 + ClientHello `[h2, http/1.1]` + HTTP-преамбула + Bearer) уже закрывает основные классы пассивных и активных сканеров. h2 даст «третий знак после запятой» по маскировке.

2. **Если всё-таки хочется** — Вариант A: добавить h2 в существующий `--type=tls` с h1.1 fallback. ALPN-список в ClientHello не меняется → SNI/JA3-профиль ClientHello остаётся прежним; внутри ServerHello уже не видно (TLS 1.3). Можно сделать новый CLI-флаг `--tls-prefer-h2` (default = true) для отката при проблемах.

3. **Если бюджет на маскировку большой** — то лучше потратить его на HTTP/3 (QUIC + h3). Это, во-первых, реальный преобладающий транспорт у Chrome к крупным сайтам сегодня, а во-вторых, в проекте уже есть `--type=quic` и `--type=quic-ext` — поверх них прикрутить h3-фрейминг проще, чем строить h3 с нуля. Но это уже отдельный, более крупный разговор.

## Точки интеграции для Варианта A (если решим делать)

В [scripts/clean-vpn.js](clean-vpn.js):

- `connectCleanVpnTlsClient` — после handshake ветвление по `sock.alpnProtocol`; для `'h2'` поднять `http2.connect` поверх готовой TLSSocket через `createConnection`, открыть stream с `:method=GET :path=/clean-vpn` + Bearer, ждать `:status=200`, дальше отдать stream как socket-like.
- `handleTlsExitInbound` / `wireExitTlsSocket` — после `secure` смотреть `alpnProtocol`; для `'h2'` принять сессию `http2.createServer` (или `createSecureServer` с переписыванием pre-handshake passthrough), валидировать заголовки и Bearer, отвечать `:status=200`, отдавать stream в `startBridge(stream, null, 'tcp')`.
- Новая утилита `http2StreamToSocketLike(stream)` — тонкая обёртка над `Duplex` (по образцу [`quicBidiToSocketLike`](clean-vpn.js)).
- Опциональный CLI-флаг `--tls-prefer-h2=bool` (default true) — отключение h2 для дебага без слома совместимости.
