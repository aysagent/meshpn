# Поддержка HTTP/2 в `--type=tls`: вариант A (реализовано)

Exit предлагает ALPN **`['h2', 'http/1.1']`** (приоритет h2); клиент в ClientHello шлёт тот же набор. После TLS handshake выбирается прикладной протокол (`sock.alpnProtocol`).

## Трафик VPN после handshake

| ALPN | Клиент | Exit |
|------|--------|------|
| `http/1.1` | `GET /clean-vpn` + `Authorization: Bearer …`; после ответа `200 OK` — прежний бинарный поток `uint32 BE + IPv4` на том же TLS-сокете | Разбор HTTP/1.1-преамбулы + Bearer → VPN или cover (`It works!`) |
| `h2` | `POST /clean-vpn` в одном HTTP/2 stream, Bearer в заголовках; **`endStream` для запроса не ставится** (полудуплекс запроса остаётся открытым для uplink VPN DATA); после ответных HEADERS `:status 200` — тот же фрейминг поверх DATA этого stream | `Http2SecureServer.emit('secureConnection', TLSSocket)` после локального TLS handshake (не используется на passthrough-пути); на stream допускается только **`POST /clean-vpn`** + Bearer |

Обновляйте **client и exit вместе** при смешанных версиях либо принудительно дерите **`--http-vers=1.1`** на **обеих** сторонах для только GET-пути.

## Принудительный HTTP/1.1

`--http-vers=1.1` (только `--type=tls`, обе стороны): ALPN только **`['http/1.1']`**, только GET + Bearer; для проверки регрессий без HTTP/2.

## Что даёт HTTP/2 для маскировки

- В активном сканировании с полным TLS чаще согласуется **`h2`**, как у типичных сайтов при том же ClientHello (`h2` + `http/1.1`).
- Пассивный наблюдатель TLS 1.3 по-прежнему не видит выбранный ALPN в открытом виде после handshake.

## Passthrough (active probe)

Ветки `parse_fail` и при включённом `--tls-public-name` неверный SNI по-прежнему до создания локального `TLSSocket` уходят в байтовый passthrough к `--tls-probe-target`. Рукопожатие TLS завершается на upstream; если клиент предложил `h2`, HTTP/2 обрабатывается между клиентом и целевым хостом — локальный HTTP/2-код exit не участвует.

## Риски и версии Node

Привязка HTTP/2-сессии к уже принятому `TLSSocket`: **`http2.createSecureServer(...).emit('secureConnection', tlsSock)`** после **`tls.createServer(...).emit('connection', tcp)`**. Рекомендуется проверять на вашей LTS Node.
