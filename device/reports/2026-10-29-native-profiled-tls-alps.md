# Клиент платы → native exit, ALPS — 29 октября 2026

## Результат

Основная целевая реализация уточнена: текущий `native/clean_vpn/engine.cc`,
а не старый `scripts/clean-vpn.js`. Native listener принимает только HTTP/2.
Его Bearer v2/exporter и framed IPv4 совместимы с клиентом платы; несовместимость
при ALPS была в прежнем явном отказе `h2_alps_unsupported` на клиенте.

Добавлен ограниченный ALPS adapter для того же nghttp2 pin, который использует
native: `534b74b72524e962c18c7146470914632ca7eb2d`. Он применяет peer settings
к новой H2-сессии до открытия stream 1. Настройки, подтверждённые TLS, не
порождают SETTINGS ACK; не используются h2c upgrade и поддельные wire frames.

Поддержан codepoint 17613, пустой payload либо один non-ACK SETTINGS frame,
stream 0, максимум 45 байт/6 уникальных IDs 1–6; значения валидируются до
изменения сессии. Ограничения совпадают с текущим native ALPS subset. Ошибки —
`h2_alps_invalid`, до HTTP-авторизации и IP-передачи. Обычные последующие wire
SETTINGS остаются в ведении nghttp2. Диагностика: `alps`, `alps_bytes`,
`http2_error`, phase; админка показывает факт согласования ALPS.

Фиксированный профиль, JA3/JA4, CA/name/date verification, PSK, allocator и
32 KiB PSRAM worker сохранены. HTTP/1.1 остаётся для старого JS exit.
Корневой native-код не изменён.

## Как проверено

Host binary использует production device `profile_tunnel.cc`, профиль/gate,
allocator и framing. ASan/UBSan включены в адаптер/клиент/nghttp2; BoringSSL/Brotli
archives собраны отдельно. Это не полная sanitizer-сборка native engine.

Актуальный native engine скомпилирован из текущих исходников с
`CVPN_TEST_PACKET_FD=1`, pinned зависимости взяты из существующего read-only
Linux lab cache. Совпадение BoringSSL/nghttp2 pins, patch tree и native ALPS
adapter проверяется перед сборкой. SHA исходников/бинарника сохранены.
Вместо TUN — AF_UNIX SOCK_DGRAM: fixture возвращает адресованный клиенту IP-пакет.
TLS, ALPN, HTTP/2, PSK-аутентификация, peer isolation и framing остаются в engine.

Контейнер: `--network=none --cap-drop=all`, без `/dev/net/tun`, маршрутов,
NAT, firewall, DNS или VPS. Mac loopback proxy пересылает зашифрованные байты
через stdio в loopback engine; поэтому throughput этого теста не является
замером реальной скорости. Proxy независимо считывает ClientHello до TLS.

Прошли:

- ALPS off и on: по 2368 пакетов в каждую сторону. На режим — одна обычная
  сессия, 20 повторов в одном процессе, bulk 1024×1400 байт и отмена после ACK.
- Неверный PSK, неверное имя, неверный CA, неподдержанный профиль — 0 IP-пакетов.
- Семь invalid ALPS от настоящего BoringSSL/native fixture: ACK flag, stream≠0,
  усечение, лишний frame, недопустимое окно, неизвестный ID, повтор ID.
  Во всех случаях ready=0, sent=0, phase=`h2_alps_invalid`.
- Wire observer native exit подтвердил пустой client ALPS, его wire SETTINGS
  и отсутствие лишнего SETTINGS ACK за ALPS.
- Всего 61 попытка; 59 независимо захваченных ClientHello совпали с локальным
  gate: JA3 `ed63604b6e93c62437468be3f6b387c3`,
  JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`.
- Host PSRAM-adapter peak 45 503 байта; repeat проверяет неизменность live после
  каждой сессии. Это не общий heap, не стек и не измерение ESP32.
- Unit adapter: проверка remote window, запрет повторного применения, malformed
  settings без частичного изменения, отсутствие synthetic ACK.
- Старые JS H1/H2 regression tests и полный `scripts/test-host.sh` прошли.
  `test-web-ui.mjs` прошёл. Финальные opt-in сборки XIAO, Stamp и Waveshare — прошли.

## Артефакты и воспроизведение

- Native result: `device/perf-results/native-profiled-Chqbz7/result.json`,
  рядом marker `passed`, engine logs, counts для каждого сценария.
- Native build: `device/perf-results/native-alps-build-20261029b/`.
- SHA256 engine.cc: `62d7aa2a194ccdbc4be64feb4da1d32aa99e5ba0228fabe3936b423a0a9466d9`.
- SHA256 engine fixture: `d58e86d85a56784d29e1ccb1a01f9542858f6268a1b76edb3690fca62e042b00`.
- JS regression + host client: `/var/folders/k_/2lrssx3x5klcpnnrsz2_3b080000gn/T/meshpn-profile-tunnel-JKBtw4`.
- Общие host tests: `/tmp/meshpn-host-tests.yRCCfI`.
- Firmware logs: `/tmp/meshpn-alps-final-xiao_esp32s3.log`,
  `/tmp/meshpn-alps-final-m5_stamp_p4_c6.log`,
  `/tmp/meshpn-alps-final-waveshare_esp32_p4_wifi6.log`.

[Test commands и настройка](../docs/profiled-tls.md). Каталоги содержат disposable
ключи/сертификаты и игнорируются git; в репозиторий попадает только отчёт.

## Что осталось

Платы не подключались и не прошивались. На железе ещё нужны USB/AP→native VPN,
публичный IP, реальный DNS/HTTPS, reconnect/kill switch, heap/stack и нагрузка.
VPS/NAT/installed service и combo-dispatch/transparent relay здесь не проверены.
Произвольный импорт профилей и браузерный HTTP/2 fingerprint не реализованы:
точное совпадение JA3/JA4 относится к TLS, не к SETTINGS/HTTP-заголовкам браузера.
