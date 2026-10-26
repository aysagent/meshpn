# Native ALPS и HTTP/2

Экспериментальный opt-in для native `boring-tls` и Boring-ветки `combo-tls`.
Поддерживается cold TLS 1.3 с ALPS codepoint **17613** и ALPN `h2`.
Это рабочая семантика negotiated settings, а не полная мимикрия Chrome.
`browser_profiles:false` сохраняется.

## Как включить

Client: указать абсолютный `tls_profile_path` на файл по образцу
[synthetic cold ALPS](../fixtures/native-tls-profiles/cold-alps.json).
Профиль содержит `tls.application_settings:["h2"]`, ext17613 в
`tls.extension_types` и обязательный верхнеуровневый объект:

```json
"http2": {
  "settings": [[1,8192],[2,0],[3,1],[4,524288],[6,4096]],
  "connection_window": 786432
}
```

Порядок пар сохраняется в одном реальном SETTINGS frame. Connection window
выставляется настоящим WINDOW_UPDATE; это размер окна, не величина increment.
Пример синтетический и не выдаётся за снятые настройки браузера.

Exit: добавить `"alps":true` в native конфигурацию; для combo — в объект
`boring`. Клиенту этот флаг не разрешён: он включает ALPS только через профиль.
Проверить оба JSON через `clean-vpn-engine --check-config /absolute/config.json`.
По умолчанию ALPS выключен. Exit с ALPS принимает также прежних клиентов;
профильный клиент работает с exit без ALPS и посылает те же профильные H2 SETTINGS.

## Что действительно происходит

BoringSSL сам создаёт extension и включает application settings в TLS transcript.
Первый ClientHello проверяется до отправки: codepoint и protocol list должны
соответствовать профилю. Независимый JS TCP observer проверяет те же поля и JA3/JA4.

Client ALPS payload пустой: клиент объявляет поддержку, затем отправляет свои
SETTINGS обычным H2 frame. Exit ALPS payload содержит один SETTINGS frame:
`[[3,1],[4,1048576],[6,8192]]`. При согласовании ALPS эти настройки применяются к
обоим nghttp2 sessions до открытия stream 1. Exit не отправляет повторный initial
SETTINGS, клиент не создаёт лишний ACK за настройки, уже подтверждённые TLS.
Обычные последующие SETTINGS продолжают обрабатываться с ACK.

Это следует семантике экспериментальных drafts
[TLS ALPS](https://www.ietf.org/archive/id/draft-vvv-tls-alps-01.html) и
[HTTP/2 ALPS](https://www.ietf.org/archive/id/draft-vvv-httpbis-alps-01.html),
не обещание поддержки любого ALPS endpoint или стандарта RFC.

У nghttp2 нет используемого здесь публичного ALPS API. Узкий C adapter вызывает
внутренние settings handlers закреплённого commit
`534b74b72524e962c18c7146470914632ca7eb2d`. CMake отказывает при другом revision.
Обновление nghttp2 требует повторного аудита adapter и тестов: совпадения имён
функций недостаточно. Не используются фиктивный h2c upgrade, резервирование
stream 1, поддельный client preface или удаление ACK из отправляемых байтов.

## Границы

- Локальные SETTINGS: уникальные IDs 1–6; обязательны 2=0 (push), 3=1 (streams),
  4 (stream window), 6 (header limit). Header table ≤64 KiB; stream/connection
  window 65535–1048576; max frame size, если задан, 16384; header limit 1024–8192.
- Peer ALPS: пустой payload либо один non-ACK SETTINGS frame, stream 0,
  максимум 6 уникальных IDs 1–6 и 45 bytes. HPACK table ≤64 KiB, остальные значения
  проверяются в пределах поддерживаемой H2 семантики. Неизвестные frames/settings,
  ACK, дубли, усечения и лишние bytes отвергаются до отправки HTTP авторизации.
  45 bytes — лимит принятого application payload после TLS handshake, не общий
  лимит allocations/RSS TLS стека.
- На exit принимается только пустой client ALPS; произвольные настройки клиента
  внутри TLS не игнорируются молча. Codepoint 17513 и ACCEPT_CH не поддержаны.
- TLS CA, hostname, время сертификата и exporter-bound PSK остаются обязательными.
  ALPS не разрешает пакеты до успешной авторизации.
- Нет resumption/0-RTT, подгонки HTTP headers, приоритетов, HPACK стратегии,
  TLS record sizes или timing. Ограничения памяти могут не позволять буквально
  воспроизвести H2-настройки конкретного браузера.

Из одного ClientHello нельзя получить будущие SETTINGS/window. Capture сохраняет
ALPS protocols, но оставляет candidate `unsupported` с причиной
`alps-requires-explicit-http2-settings`. Никакие браузерные настройки не
додумываются автоматически. Исторический Chromium bundle не переписывается.

## Проверка

```bash
npm run lab:native:mac -- --tls-profiles
```

CTest проверяет parser, реальные состояния nghttp2, отсутствие лишнего ACK,
сохранение stream 1, проверку client magic и последующий обмен SETTINGS.
Интеграционные тесты используют реальные TLS client/exit, HRR, compression,
combo, CA/name/PSK negatives и повреждённые negotiated ALPS.

Test-only observer разбирает байты после SSL_read **до nghttp2** и выводит только
bounded SETTINGS/WINDOW_UPDATE до первого другого frame. JS отдельно декодирует
их и сравнивает с профилем. Заголовки авторизации и packet payload не выводятся.
Это проверка H2 байтов на тестовом endpoint; внешний наблюдатель зашифрованного
TCP видит только ClientHello и JA3/JA4. Fixture hooks отсутствуют в production.

Результаты: **10/10 CTest, 13/13 native profile tests и 21/21 capture/build/JA tests**.
Финальный профильный прогон выполнен с `--network=none`; ASAN/UBSAN отдельно
проверил parser, adapter и pinned nghttp2 на macOS ARM64. Это не whole-engine TLS
sanitizer certification. [Отчёт checkpoint](../fixtures/clean-vpn-native-alps-report.json)
содержит SHA-256 production binary, измеренные ClientHello/JA3/JA4 и H2 frames.
[Реальный H2 capture и сравнение](clean-vpn-native-http2-capture.md) добавлены
следующим checkpoint. Теперь нужно выбирать поддержанный
browser build и закрывать его оставшиеся TLS gaps; не включать запрещённые cipher
suites ради одного совпадающего fingerprint.
