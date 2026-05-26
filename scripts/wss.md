# WSS как транспорт: DPI-сравнение с TLS и план реализации

Документ отвечает на два вопроса:

1. Чем WSS отличается от текущего `--type=tls` с точки зрения DPI.
2. Как поднять WSS поверх уже реализованных TLS-вариаций (`tls`, `boring-tls`, `combo-tls`).

`transparent-tls` для WSS **не подходит** — там TLS-handshake не наш, мы только перехватываем и подменяем SNI; внутрь TLS не залезть без полного MITM с подменой сертификата на клиенте.

---

## 1. TLS vs WSS — что видит DPI

### Пассивный DPI (без TLS inspection)

Здесь TLS и WSS **практически неотличимы**, если:

- одинаковый TLS-стек (ClientHello/JA3/JA4 — у нас это `boring-tls`),
- одинаковый набор шифров/curves (`TLS_VPN_CIPHERS_1_3`, `TLS_VPN_ECDH_CURVES`, [`clean-vpn.js`](clean-vpn.js) ~263-266),
- ALPN — сопоставимый.

Единственный значимый сигнал в открытой части — **ALPN**:

| Транспорт | Типичный ALPN |
|-----------|---------------|
| `--type=tls` (у нас) | `[h2, http/1.1]` (`TLS_ALPN_PREFER_H2`, [`clean-vpn.js:249`](clean-vpn.js)) — как у Chrome |
| WSS, классический RFC 6455 | `http/1.1` |
| WSS поверх HTTP/2 (RFC 8441 Extended CONNECT) | `h2` |

Если предложить `[h2, http/1.1]` в WSS-варианте и согласовать `http/1.1` — ALPN на проводе тот же, что у обычного браузерного HTTPS-сайта без HTTP/2. Для **pure passive DPI** разницы между нашим текущим `tls` и WSS нет.

### Активный probing / DPI с MITM-инспекцией

Здесь WSS даёт **существенно более естественный профиль поведения** после handshake.

| Этап | `--type=tls` (текущий) | WSS |
|------|-------------------------|-----|
| HTTP request | `POST /clean-vpn` h2 или `GET /clean-vpn` http/1.1 + `Authorization: Bearer <hex>` ([`clean-vpn.js`](clean-vpn.js) ~882-893, ~1106-1112) | `GET / HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Key: ...\r\nSec-WebSocket-Version: 13` |
| HTTP response | `200 OK` | `101 Switching Protocols` + `Sec-WebSocket-Accept` |
| Что идёт дальше | h2: бинарь в HTTP/2 DATA-фреймах; http/1.1: **hijacked socket → сырой бинарь без HTTP framing** | **WebSocket binary frames** (`0x82 <len> <payload>`) — самоописательный фрейминг |
| Бинарный поток после handshake | hijacked — нетипично для HTTP/1.1 | **WS** — стандарт |
| Долгоживущая сессия | h2 stream долгий; http/1.1 hijacked — необычно | **WS** — норма для chat / gaming / трейдинга |
| Поведение «много мелких бинарных кадров» | hijacked — слабый профиль | WS — естественный профиль |

### Где WSS объективно лучше TLS-HTTP-VPN

1. **Behavioral fingerprint после handshake.** WS-framing — стандарт; любой WS-aware DPI узнаёт его как валидный протокол. После HTTP/1.1 hijacked на проводе сразу идут `uint32 BE + IPv4`, без HTTP-грамматики — это **детектируемая аномалия** при MITM-инспекции.

2. **Долгоживущая сессия с двусторонним трафиком — норма для WS.** HTTP/2 POST с открытым телом — тоже норма (gRPC), но в комбинации с маленькими ответами exit'а выглядит как «странный gRPC».

3. **Правдоподобный cover.** Сейчас при неверном Bearer exit отдаёт `It works!` ([`clean-vpn.js`](clean-vpn.js) ~4746-4802). У WSS-cover можно ответить `426 Upgrade Required` или полноценный echo-WS — это куда правдоподобнее.

### Где WSS НЕ лучше или равно

- **TLS fingerprint (JA3/JA4)** — идентичный, при том же стеке.
- **SNI/ALPN на проводе** — одинаковые, если настроить совпадение.
- **Поверхность атаки Bearer** — те же 15-минутные окна (H-2 в [`clean-vpn-security-analysis.md`](clean-vpn-security-analysis.md)).

### Итог по DPI

- **Пассивный DPI** — разница невелика, если ALPN/JA3 совпадают.
- **Активный DPI с MITM** или поведенческий классификатор — WSS даёт значимый выигрыш: внутри TLS виден **стандартный WS**, а не нестандартный hijacked-бинарь.

---

## 2. Реализация WSS поверх существующих TLS-вариаций

### Что уже готово

1. **TLS-handshake** реализован в обеих ветках:
   - Node TLS: `connectCleanVpnTlsClient` ([`clean-vpn.js`](clean-vpn.js) ~1359-1156) на client, `tlsExitHttp2Server` + cover ([`clean-vpn.js`](clean-vpn.js) ~6572-6624) на exit.
   - **boring-tls**: helper отдаёт «TLS plaintext»-сокет через stdin/stdout (`BridgeLoop`). Для Node это обычный поток.

2. **WebSocket уже работает** в `--type=websocket` и `--type=ws-chrome`:

```6373:6378:clean-vpn.js
      wss.handleUpgrade(request, socket, head, (ws) => {
```

Точно тот же `handleUpgrade` примет TLS-socket (или TLS-plaintext stream из boring-tls) вместо plain TCP.

3. **Мост TUN ↔ WebSocket** уже отлажен в `attachTunBridge(tun, 'websocket', ws, ...)` (см. [`clean-vpn.js`](clean-vpn.js) ~6337, ~6370, ~7217 + framing ~3980-4011, ~4222-4268).

### Вариант A: «WSS-режим» для `--type=tls` (Node TLS)

**Client:** после `tls.connect` вместо HTTP/2 POST или HTTP/1.1 GET — отправить WS upgrade. Самый простой путь — использовать `ws`-библиотеку с custom socket:

```js
import { WebSocket } from 'ws';
const ws = new WebSocket(`wss://${checkHost}/clean-vpn`, {
  createConnection: () => tlsSock,
  headers: { authorization: `Bearer ${token}` },
});
// после 'open' — attachTunBridge(tun, 'websocket', ws, ...)
```

**Exit:** в `handleTlsExitInbound` ([`clean-vpn.js:5222`](clean-vpn.js)) добавить ветку «если запрос содержит `Upgrade: websocket`» → `WebSocketServer({ noServer: true }).handleUpgrade(...)` поверх TLS-socket'а. Bearer проверяется тем же `verifyTlsVpnBearerToken` ([`clean-vpn.js`](clean-vpn.js) ~619-635). Cover при отсутствии Bearer — то же `It works!`, либо честный echo-WS.

**Сложность:** S (4-8 часов). Бóльшая часть — корректная обработка peek-буфера для разбора первой строки HTTP-upgrade.

### Вариант B: WSS через `boring-tls`

Helper отдаёт «plaintext»-stream, который для Node выглядит как обычный duplex stream. Поверх него:

```js
import { WebSocket } from 'ws';
const boringTlsLikeStream = openBoringTlsHelper(...);
const ws = new WebSocket(null, {
  createConnection: () => boringTlsLikeStream
});
```

либо ручной WS handshake через прямую запись `GET ... Upgrade: websocket\r\n...` в stream + парсинг 101 (~1106-1156 — есть готовый шаблон для HTTP/1.1).

**Сложность:** S–M (день). Сложность чуть выше из-за того, что boring-tls plaintext-stream должен корректно поддерживать события `data`/`end`/`close` для `ws`.

### Вариант C: WSS в `--type=combo-tls`

Combo уже мультиплексирует CVPTX + TLS на одном `:443`. WSS-ветка добавляется как ещё один вариант **внутри TLS-ветки**: если после TLS пришёл `Upgrade: websocket` — поднимаем WS-мост; иначе — текущая HTTP/2 ветка.

**Сложность:** S (4 часа).

### Вариант D (отложить): WSS поверх HTTP/2 (RFC 8441)

HTTP/2 WebSocket через Extended CONNECT (`:protocol=websocket`). Node http2 поддерживает с какой-то версии, надо протестировать. Это даст ещё больший «маскировочный» эффект (ALPN h2 + WS upgrade в h2 stream).

**Сложность:** M (несколько дней).

### Авторизация в WSS

Все варианты совместимы с текущим Bearer-механизмом:

| Способ | Пример | Заметки |
|--------|--------|---------|
| HTTP header `Authorization: Bearer` | `Authorization: Bearer <hex>` | Самый стандартный (как сейчас); browser JS-API не позволяет, но наш custom client может |
| `Sec-WebSocket-Protocol` | `Sec-WebSocket-Protocol: clean-vpn.v1+<bearer-hex>` | Браузер поддерживает; server валидирует и возвращает в Accept |
| Query string | `wss://host/clean-vpn?t=<hex>` | Виден в логах reverse-proxy; нежелательно |
| Cookie | `Cookie: cv=<hex>` | Браузер поддерживает; «реалистичнее» в логах |

Лучший выбор — `Sec-WebSocket-Protocol` (нативно для WS) или `Authorization` (универсально).

### Бонус: уже есть готовый «полу-WSS»

`--type=ws-chrome` на exit поднимает `WebSocketServer` + HTTP-page (`/clean-vpn-chrome`) на одном порту:

```6373:6378:clean-vpn.js
      wss.handleUpgrade(request, socket, head, (ws) => {
```

Если положить это **позади** нашего TLS-сервера (тот же `tls.createSecureServer` или `http2.createSecureServer`), получится готовый WSS endpoint практически бесплатно. То же на client: `WebSocket('wss://...')` через `ws`-библиотеку + TLS-сокет от наших уже отлаженных функций.

### Сводно по сложности

| Что | Объём | Время |
|-----|-------|-------|
| Минимальный `--type=tls-ws` (Node TLS) | 1 ветка в `runExit` + 1 в `runClient`, WS upgrade, переиспользовать `verifyTlsVpnBearerToken` и cover | S, 4–8 часов |
| `--type=boring-tls-ws` | + интеграция WS поверх helper-stream | S–M, 1 день |
| `--type=combo-tls-ws` | + ветвление внутри combo | S, 4 часа |
| HTTP/2 WebSocket (RFC 8441) | extended CONNECT, `:protocol=websocket` в Node http2 | M, несколько дней |

---

## 3. Рекомендация

1. **Самое выгодное соотношение «работа / эффект»** — добавить WSS-режим в `--type=tls` (Node) и `--type=combo-tls`. Это даёт лучший behavioral fingerprint при том же TLS-стеке.
2. **Для `--type=boring-tls`** — реализовать следующим, когда захочется полного Chrome-like профиля (JA3/JA4 от BoringSSL + WSS framing).
3. **Bearer и cover** не трогать — переиспользовать как есть; только заменить пост-handshake протокол с «HTTP + hijack» на «HTTP + WS upgrade».
4. **HTTP/2 WS (RFC 8441)** — отложить, пока не появится конкретный DPI, который различает h2-stream и h2-CONNECT.

---

## Связь с другими документами

- [`clean-vpn-security-analysis.md`](clean-vpn-security-analysis.md) — общий аудит транспортов; узкие места H-2 (Bearer-окно) и предложения по фиксам применимы и к WSS-варианту.
- [`cloudflare.md`](cloudflare.md) — Cloudflare proxy/Tunnel требует именно WSS для проксирования VPN через CDN (см. там же про текущее состояние `--type=websocket` — только `ws://`).
- [`nginx.md`](nginx.md) — частный случай WSS-фронтенда через nginx (`stream` или `http`+`Upgrade`).
- [`boring-tls-plan.md`](boring-tls-plan.md) — устройство BoringSSL helper'а, на основе которого добавится `boring-tls-ws`.
