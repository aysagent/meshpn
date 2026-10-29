# Профилированный TLS на XIAO / Stamp P4 / Waveshare P4

Транспорт `boring-tls` использует TLS 1.3, фиксированный браузерный ClientHello,
проверку сертификата/имени/времени и clean-vpn Bearer **v2** с TLS exporter.
С **native clean-vpn** проверен HTTP/2, с ALPS и без него.
HTTP/1.1 также поддержан клиентом; выбор через ALPN. Версии HTTP/1.2 в этом протоколе нет.
Каждый новый ClientHello, включая повторный после HRR, проверяется локально до
отправки. При несовпадении JA3 или JA4 соединение закрывается.

Есть встроенный `chromium156-capture1` и четыре сохраняемых пользовательских профиля.
[Захват прямо на плате и выбор профиля](browser-profile-capture.md).
Это совпадение TLS JA3/JA4, **не** полная имитация браузера: HTTP User-Agent/поведение
браузера не воспроизводятся. Импорт ограничен поддержанными TLS-полями и
успешным формированием точного JA3/JA4 до сохранения.
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

### Актуальный native exit

Использовать native `boring-tls` listener с HTTP/2. На плате выбрать `boring-tls`,
указать адрес/порт, имя сертификата, доверенный CA и shared key выбранного peer.
32-байтовый файл `secret_path` native exit соответствует 64 hex-символам поля
Shared HMAC key на плате. Статический IPv4 peer должен совпадать с профилем платы:

| Плата | IPv4 peer |
|---|---|
| XIAO | `10.99.0.2` |
| Waveshare | `10.99.0.3` |
| Stamp | `10.99.0.4` |

Это не DHCP: exit не выдаёт адрес плате. Для одновременных клиентов нужны
отдельные peer-записи и ключи; существующий клиент `.2` остаётся на своём адресе.
Адрес задаёт `CONFIG_MESHVPN_TUNNEL_HOST_OCTET` при сборке, одинаково для
TCP, UDP, TLS и boring-tls. WireGuard использует сохранённый Address.

ALPS на exit можно оставить выключенным либо включить `"alps": true` в его
конфигурации: оба режима проверены. На плате дополнительного переключателя нет.
При ALPS настройки HTTP/2 применяются до открытия stream 1, без лишнего ACK.
Поддержан codepoint 17613 и ограниченный формат текущего native exit; некорректные
настройки отклоняются до HTTP-авторизации и отправки IP. SETTINGS на проводе
после handshake продолжают обрабатываться обычным образом.

Native engine запускается через его существующий config/service, а не командой
`node scripts/clean-vpn.js`. Развёртывание и управление:
[native exit](../../scripts/clean-vpn-native-exit-host.md),
[настройки ALPS](../../scripts/clean-vpn-native-alps.md).
Эти тесты не проверяют публичный combo-dispatch/transparent relay: проверен
непосредственно native boring-tls listener.

### Старый JS exit (обратная совместимость)

Старый JS exit жёстко настраивает TUN/маршруты/NAT для `10.99.0.2`.
Приведённые ниже команды относятся к XIAO или сборке с
`CONFIG_MESHVPN_TUNNEL_HOST_OCTET=2`; новые defaults P4 `.3`/`.4`
требуют native exit с соответствующими peers.

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
match, ClientHello count, ALPN, authenticated, SSL/verification error и `http2_error`, `alps` и `alps_bytes`.
`http2_error` содержит код библиотеки nghttp2 (отрицательный) либо код GOAWAY
(неотрицательный); причину закрытия уточняет `phase`.
`cipher` — согласованный TLS cipher. `tls_bytes_sent` и `io` обновляются при
смене phase и примерно раз в секунду во время обмена. `io` содержит число,
байты и длительность SSL read/write, максимальную длительность одного вызова
и время ожидания сокета. Это счётчики **одного соединения после handshake**;
байты включают HTTP framing, длительность — I/O и вытеснение другими задачами,
поэтому это не отдельный замер криптографии. `io.sampled_us` — время снимка
по часам uptime платы. После reconnect нельзя вычитать старые значения из новых.
`ssl_error=2/3` при активном соединении означает WANT_READ/WANT_WRITE, а не
разрыв; состояние ошибки определяется по `error` и `phase`.
`tcp` — снимок внешнего TCP-сокета по точной паре адресов и портов, снятый
на потоке lwIP: congestion/receive/send windows, незавершённые и ожидающие
отправки байты, out-of-order bytes, scales и MSS. `retransmits` — текущий
счётчик повторов lwIP, который сбрасывается после ACK, **не накопленные потери**.
RTT/RTO имеют грубую дискретность таймера lwIP; для точной задержки нужен
отдельный замер. Снимок может пропустить короткий всплеск между обновлениями.
Подсчёт очередей ограничен 512 сегментами на очередь; при `queues_truncated=true`
соответствующие byte gauges являются нижней границей, а не полным размером.
Диагностика очищается при смене конфигурации и начале новой попытки — прошлый
match не разрешает новое соединение. Детальная последняя ошибка также остаётся
в `vpn.socket.last_failure`.

| Phase | Значение |
|---|---|
| `profile_mismatch` | Реальный ClientHello не совпал; он не отправлен |
| `tls_handshake` / `certificate` | Проверить CA, имя, сроки сертификата, SSL/verify error |
| `unsupported_alpn` | Exit не выбрал h2 или http/1.1 |
| `h2_alps_invalid` | ALPS peer не соответствует поддержанному ограниченному формату |
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
Отдельный тест запускает актуальный native engine в изолированном Linux-контейнере
с AF_UNIX вместо TUN. Проверены ALPS on/off, повторные сессии, bulk, неверный ключ/CA/имя
и семь повреждённых ALPS payload. Это проверка production TLS/H2/auth/framing,
а не системного развёртывания exit, NAT или VPS. HTTP/2 SETTINGS и HTTP-заголовки
не воспроизводят браузерный HTTP-отпечаток; точность JA3/JA4 сохраняется отдельно.

Далее: прошить подключённую плату, проверить USB/AP → VPN, публичный IP,
переподключение/kill switch и high-water/heap под нагрузкой. Затем повторить
с остальными платами. Производительность пока не заявляется.

### Воспроизведение native interoperability

На Mac используется существующая лаборатория Podman. Нужны её build image и
read-only cache с pinned native библиотеками; команда их не обновляет и не
запускает сеть/маршрутизацию. Каталог результатов должен находиться под общей с
VM директорией проекта, не в Mac `/tmp`.

Из `device/`:

```sh
bash tests/build-native-exit-lab.sh perf-results/native-device-build-new
# HOST_RUN — каталог, напечатанный test-profiled-tunnel.mjs после успешного запуска.
node tests/test-native-profiled-tunnel.mjs HOST_RUN/client perf-results/native-device-build-new
```

`MESHPN_PODMAN_CONNECTION`, `MESHPN_NATIVE_LAB_IMAGE`, `MESHPN_NATIVE_LAB_CACHE`
позволяют указать другую подготовленную лабораторию. Контейнер использует
`--network=none --cap-drop=all`. Mac proxy слушает только 127.0.0.1 и пересылает
зашифрованный TLS через stdio в loopback native engine. Корневой `native/` не
изменяется; engine компилируется из текущего исходника, SHA сохраняются с отчётом.
[Результат проверки](../reports/2026-10-29-native-profiled-tls-alps.md).
