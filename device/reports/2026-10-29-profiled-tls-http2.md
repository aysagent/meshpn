# HTTP/2 для профилированного TLS — 29 октября 2026

## Что изменилось

В `scripts/clean-vpn.js` клиент `boring-tls` выбирает HTTP/2 или HTTP/1.1 по
ALPN; штатный сервер предпочитает h2. HTTP/1.2 здесь нет. На платах добавлена
та же пара версий: GET `/clean-vpn` для H1, открытый POST stream для H2,
exporter-bound Bearer v2 и framed IPv4 внутри H2 DATA. Состояние connected
разрешается только после строгого ACK. Ordinary raw `tls` не изменён.

Общий компонент работает на XIAO S3, Stamp P4 + C6 и Waveshare P4 + C6.
HTTP/2 реализован библиотечной частью nghttp2 1.68.0, pin
`534b74b72524e962c18c7146470914632ca7eb2d`. SDK и desktop helper не изменяются.
Сессия, HPACK и output используют общий с BoringSSL allocator с лимитом 1 MiB
в PSRAM; две временные структуры настройки используют системный malloc и
немедленно освобождаются. Все операции выполняются на прежнем 32 KiB worker.

Ограничения: один stream, push выключен, headers ≤4096 байт/64 поля,
HPACK table ≤4096 байт, receive windows 256 KiB, bounded SETTINGS/ACK/CONTINUATION.
Нет IP-трафика до ACK; DATA подтверждается очереди только после записи в TLS.
WANT_READ/WANT_WRITE сохраняют pending output. Нулевое окно с ожидающим TX
ограничено таймаутом 5 секунд. RST, GOAWAY, END_STREAM, malformed frames и
смена поколения закрывают сессию без plaintext fallback.

Диагностика и админка показывают согласованный HTTP и `http2_error`/phase.
Сборка остаётся opt-in `PROFILED_TLS=1`; все настройки сохранены совместимо.

## Проверки

- Production C++ session + настоящий JS exit через loopback TCP/TLS; подменены
  только TUN и изменение маршрутов/NAT. По 30 успешных коротких сессий H1/H2
  (10 отдельных процессов + 20 повторов в одном) и дополнительный H2 bulk.
  Через настоящий exit прошли 4864 IPv4 round-trips, включая 1024 пакета по
  1400 байт в H2 bulk — больше окна потока.
- Независимый capture каждого ClientHello на exit совпал с локальным gate:
  JA3 `ed63604b6e93c62437468be3f6b387c3`,
  JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`.
- Дополнительные H2 peers: окно 1024 байта, окно 0, задержка ACK, PING,
  отказ авторизации, cover, заголовки сверх лимита, content-length, RST/GOAWAY
  до/после ACK, END_STREAM, DATA до ACK, неверный HPACK, flood SETTINGS/PING/
  CONTINUATION, zero WINDOW_UPDATE, PUSH, oversized frame и отмена.
- Всего 78 записей сценариев / 116 попыток с учётом repeat. ASan/UBSan на
  session/nghttp2/adapter/framing прошли. Host allocator peak 52 562 байта;
  live после каждой сессии 328 байт (неизменяемый BIO method), без роста на repeat.
  Это не измерение общего heap или стека на ESP32; BoringSSL/Brotli host archives
  собраны отдельно, не весь процесс инструментирован санитайзерами.
- Полный `scripts/test-host.sh` и `tests/test-web-ui.mjs` прошли.
- `BUILD_ONLY=1 PROFILED_TLS=1` — прошли полные сборки XIAO, Stamp и Waveshare
  на ESP-IDF 5.5.5. Сборка XIAO с `PROFILED_TLS=0` тоже прошла.
  Устройства не прошивались.

Артефакты последнего запуска (локальные, не секреты в git):

- `/var/folders/k_/2lrssx3x5klcpnnrsz2_3b080000gn/T/meshpn-profile-tunnel-LrHHak/result.json`
- `device/perf-results/offline-real-exit-XgVko9` (H1)
- `device/perf-results/offline-real-exit-WlPJhT` (H2)
- `/tmp/meshpn-host-tests.ktbyZP` (общие регрессии)
- `/tmp/meshpn-h2-build-s3-final.log`, `/tmp/meshpn-h2-build-stamp-final.log`,
  `/tmp/meshpn-h2-build-waveshare.log` (сборки).

## Границы результата и следующий шаг

HTTP/2 SETTINGS/порядок HTTP-заголовков не имитируют браузерный HTTP fingerprint;
точные JA3/JA4 относятся к TLS. Импорт произвольного профиля ещё не реализован.
Непустые ALPS settings от peer отклоняются как `h2_alps_unsupported`: JS exit
не присылает их, а для native exit нужен отдельный adapter и тест совместимости.

Без плат и VPS не подтверждены аппаратные heap/stack, скорость, USB/AP→VPN,
публичный IP, RNG и поведение при реальных обрывах STA. Следующий шаг — такая
приёмка сначала на одной P4, затем второй и XIAO; переключение H2/H1 на одном
exit позволит измерить разницу без изменения профиля. Mac Wi-Fi/firewall,
роутер и C6 в этой работе не менялись.

[Настройка и команда exit](../docs/profiled-tls.md).
