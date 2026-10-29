# Профилированный TLS на XIAO / Stamp P4 / Waveshare P4

Транспорт `boring-tls` использует TLS 1.3, фиксированный браузерный ClientHello,
проверку сертификата/имени/времени и clean-vpn Bearer **v2** с TLS exporter.
Поддержаны **HTTP/2 и HTTP/1.1**, как у JS clean-vpn `boring-tls`: выбор через ALPN,
по умолчанию сервер предпочитает HTTP/2. Версии HTTP/1.2 в этом протоколе нет.
Каждый новый ClientHello, включая повторный после HRR, проверяется локально до
отправки. При несовпадении JA3 или JA4 соединение закрывается.

Поддержан один профиль: `chromium156-capture1` из сохранённого capture #1.
Это совпадение TLS JA3/JA4, **не** полная имитация браузера: HTTP User-Agent/поведение
браузера не воспроизводятся. Импорт произвольных профилей пока не поддержан.
Обычный `tls` остаётся отдельным raw TLS 1.2 транспортом на esp-tls/mbedTLS.

## Сборка

Команды из корня репозитория. Backend экспериментальный и включается явно:

```sh
BUILD_ONLY=1 PROFILED_TLS=1 BOARD=xiao_esp32s3 npm run device:flash
BUILD_ONLY=1 PROFILED_TLS=1 BOARD=m5_stamp_p4_c6 npm run device:flash
BUILD_ONLY=1 PROFILED_TLS=1 BOARD=waveshare_esp32_p4_wifi6 npm run device:flash
```

`BUILD_ONLY=1` только собирает. Когда нужна прошивка выбранной и привязанной
платы — убрать `BUILD_ONLY=1`, сохранить `BOARD` и `PROFILED_TLS=1`.
Механизм выбора/проверки USB-идентичности платы не изменён.

Скрипт готовит изолированные pinned BoringSSL/Brotli sources в игнорируемом
`device/build-profiled-deps-*`. Если checkout helper отсутствует, он получает
фиксированный BoringSSL commit и применяет шесть патчей из репозитория.
Первичная подготовка может требовать интернет; установленный ESP-IDF и исходники
desktop helper не изменяются. Кэш отделён от обычных сборок. HTTP/2 использует библиотечную часть nghttp2
1.68.0, commit `534b74b72524e962c18c7146470914632ca7eb2d`, в отдельном
`device/build-profiled-nghttp2-*`; установленный SDK не изменяется.

Без `PROFILED_TLS=1` выбор транспорта виден, но его включение возвращает явную
ошибку «not compiled». Сохранённый включённый профиль в такой сборке не
переключается автоматически на DIRECT при включённом kill switch.

## Exit и настройки

Использовать обычный JS exit, **без `--tls-raw`**. Пример с уже
подготовленными сертификатами и 32-байтовым shared key:

```sh
sudo env PATH="$PATH" node scripts/clean-vpn.js \
  --role=exit --server=0.0.0.0:443 --type=tls \
  --tls-cert-dir=/absolute/path/to/certs \
  --shared-hmac-key=/absolute/path/to/clean-vpn-hmac.key
```

Для принудительной проверки HTTP/1.1 можно добавить `--http-vers=1.1` на exit.
Без этого ограничения плата автоматически использует согласованный HTTP/2.
На плате отдельный переключатель версии HTTP не требуется.

HTTP/1.1 открывает GET `/clean-vpn`; HTTP/2 — один POST stream того же пути.
В обоих случаях IP передаётся только после корректного tunnel ACK, с тем же
Bearer v2. В HTTP/2 кадры IPv4 идут внутри DATA; SETTINGS, HPACK, PING и окна
потока обрабатывает nghttp2. HTTP/3 этим транспортом не реализуется.

Если используется `--tls-public-name`, он должен соответствовать TLS server name
на плате; иначе exit может направить соединение в cover/passthrough.
Для первой проверки не задавайте короткий idle `--keep-alive=5`.

В админке:

1. Transport: **boring-tls**.
2. Server: числовой IPv4 exit и порт, например `192.0.2.1:443`.
3. TLS server name: DNS-имя из сертификата exit.
4. Trusted exit CA: импортировать PEM CA, которому доверяется этот сертификат.
   CA общая с обычным TLS и сохраняется при переключении транспорта.
5. Browser profile: **Chromium 156 — capture #1**.
6. Shared HMAC key: 64 hex-символа, представляющие **содержимое** 32-байтового
   `clean-vpn-hmac.key`. Это не WireGuard key, пароль или путь к файлу.
   На exit получить представление можно командой
   `xxd -p -c 32 /absolute/path/to/clean-vpn-hmac.key`.
7. Enable VPN и Kill switch → Save and apply.

Пустое поле shared key сохраняет прежний ключ. Для удаления — выключить VPN,
отметить Remove saved shared key и сохранить. Ключ никогда не возвращается API;
без flash encryption NVS не является шифрованным хранилищем. Настраивать через
доверенный USB или HTTPS.

Endpoint профилированного TLS, shared key и профиль сохраняются независимо от
TCP/UDP/raw TLS/WireGuard. Ранее сохранённые настройки мигрируют в NVS v6.
Optional mTLS из раздела basic TLS к этому транспорту не применяется: здесь
аутентификация клиента — Bearer v2. Fallback к Bearer v1 или plaintext отсутствует.

## Статус и ошибки

`vpn.connected=true` появляется только после всех трёх проверок:
проверенный TLS, точный профиль, корректный HTTP tunnel ACK. HTTP 200 с публичной
страницей не считается ACK. После этого доступность интернета отдельно проверяет
существующая кнопка TCP 1.1.1.1:443; она не подтверждает DNS/HTTPS.

`vpn.profiled_tls` содержит attempt/generation, phase, expected/actual JA3 и JA4,
match, ClientHello count, ALPN, authenticated, SSL/verification error и `http2_error`.
`http2_error` содержит код библиотеки nghttp2 (отрицательный) либо код GOAWAY
(неотрицательный); причину закрытия уточняет `phase`.
`tls_bytes_sent` — снимок на момент смены phase, не непрерывный счётчик нагрузки.
Диагностика очищается при смене конфигурации и начале новой попытки — прошлый
match не разрешает новое соединение. Детальная последняя ошибка также остаётся
в `vpn.socket.last_failure`.

| Phase | Значение |
|---|---|
| `profile_mismatch` | Реальный ClientHello не совпал; он не отправлен |
| `tls_handshake` / `certificate` | Проверить CA, имя, сроки сертификата, SSL/verify error |
| `unsupported_alpn` | Exit не выбрал h2 или http/1.1 |
| `h2_alps_unsupported` | Exit прислал непустые ALPS settings; этот вариант пока не интегрирован |
| `h2_protocol` / `h2_headers_limit` | Некорректный HTTP/2 или превышен лимит заголовков |
| `h2_reset` / `h2_goaway` / `h2_end_stream` | Exit закрыл поток/сессию; клиент переподключается |
| `h2_flow_timeout` | В очереди есть данные, но нет прогресса отправки 5 секунд |
| `tls_version` | Требуется TLS 1.3; raw TLS exit несовместим |
| `auth_rejected` | Неверный shared key, время или получена cover/некорректная страница |
| `auth_wait` / `tx_timeout` | Истёк ограниченный срок ожидания |
| `profile_worker` / `no_memory` | Не удалось создать worker или выделить память; fallback отсутствует |
| `invalid_frame` | Ответ не соответствует ограниченному IPv4 framing |
| `cancelled` | Смена поколения конфигурации или отключение VPN |

Весь BoringSSL lifecycle и RX/TX выполняются на одном worker со стеком 32 KiB
в PSRAM; обычный 6 KiB VPN worker лишь готовит/закрывает сокет и загружает CA.
Чтение NVS вынесено до PSRAM worker. Криптографические allocations ограничены
1 MiB без fallback во внутреннюю/DMA RAM. Worker завершается кооперативно;
его задача не удаляется посреди SSL-вызова. nghttp2 session/HPACK/output
используют тот же ограниченный PSRAM allocator. Две небольшие временные структуры
настройки nghttp2 используют системный malloc и освобождаются сразу после создания
сессии. Лимит decoded response headers — 4096 байт/64 поля, HPACK — 4096 байт;
разрешён один поток, push отключён. Окна приёма — 256 KiB, это разрешённый объём
в полёте, а не отдельный буфер такого размера. После окончания сессии доступен
`last_worker_stack_spare_bytes`; достаточность запаса на платах ещё не измерена.

На P4 сборка с backend включает внутренний SAR entropy source при инициализации
VPN и оставляет его активным: RF отдельного C6 не является источником шума P4.
SAR ADC зарезервирован для RNG; перед добавлением измерений ADC потребуется
согласовать владение этим ресурсом. На S3 источник — работающее локальное радио.

## Проверки без платы

```sh
# Новый каталог: готовит зависимости и выполняет все TLS/profile/transport тесты.
bash device/experiments/profiled-tls/build-host.sh /tmp/meshpn-profiled-host-new
# Либо повторно только туннель на уже подготовленных host-библиотеках:
node device/tests/test-profiled-tunnel.mjs /tmp/meshpn-profiled-host-new
bash device/scripts/test-host.sh
```

Host-тест запускает настоящий JS exit с заменой только TUN/настройки хоста,
через реальные loopback TCP/TLS sockets. Рабочий процесс не меняет маршруты,
NAT, firewall и Wi-Fi. Это проверка протокола, отмены, framing и памяти, не
подтверждение аппаратной скорости, Wi-Fi/USB/NAPT или stack high-water ESP32.

Host-тесты проверяют обе версии с настоящим JS exit, многократные соединения,
передачу за пределами окна, нулевые/малые окна и некорректные HTTP/2 кадры.
Непустые ALPS settings от native exit пока отклоняются явно; совместимость
с native exit этим тестом не подтверждается. HTTP/2 SETTINGS и HTTP-заголовки
не воспроизводят браузерный HTTP-отпечаток; точность JA3/JA4 сохраняется отдельно.

Далее: прошить подключённую плату, проверить USB/AP → VPN, публичный IP,
переподключение/kill switch и high-water/heap под нагрузкой. Затем повторить
с остальными платами. Производительность пока не заявляется.
