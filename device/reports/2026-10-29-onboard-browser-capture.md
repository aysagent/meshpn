# Локальный захват браузерного профиля на плате

Дата: 2026-10-29. Плат нет; прошивка, Wi-Fi Mac, firewall, роутер и VPS не менялись.

## Результат

В VPN → boring-tls добавлена **Capture this browser on device**. Админка запускает
временный listener на плате и скрытый HTTPS iframe на её настроенное `.local` имя.
Listener захватывает ClientHello **до сертификата**, не отправляет TLS-данных и
закрывает подключение. Не нужны интернет, внешний сервер, сертификат или JSON-файл.
Профиль проверяется production генератором, сохраняется в существующий NVS-каталог
и выбирается в форме. Применение — отдельной существующей кнопкой Save and apply.

Сырой ClientHello не сохраняется: после разбора буфер очищается. Структурная модель
содержит допустимые ciphers/extensions/groups/signatures, ALPN и JA3/JA4.
Проверка JA3/JA4 на каждом VPN-соединении осталась обязательной.

## Ограничения и управление ресурсами

- API требует существующей авторизации админки; body до 256 байт.
- Listener bind — локальный IPv4 admin-соединения; accept — только IPv4 инициатора.
- Один захват одновременно, случайный порт 49152–65535, максимум 25 секунд,
  восемь подключений, три секунды на одно чтение; 8192 байта ClientHello,
  максимум 16 records и 16 KiB потока.
- Это адресная привязка, не TLS-аутентификация: путь `/capture` не требуется
  передавать, TLS завершается до HTTP. Listener не принимает прикладной трафик.
- Сборщик использует 4 KiB task stack, сырой буфер/model — PSRAM; разбор и
  пробный ClientHello — существующий 32 KiB PSRAM worker. NVS пишет HTTP task.
- При закрытой странице listener истекает сам; профиль без authenticated poll
  не записывается. После завершения raw buffer освобождается; небольшой job/model
  остаётся до poll или следующего start. Это один ограниченный объект.
- Отмена проверяется также при потреблении готового результата: исправлена гонка
  cancel ↔ worker completion, которая могла сохранять отменённый профиль.
- Каталог: четыре пользовательских профиля; существующий идентичный ID используется
  повторно, несовпадающий по содержимому не перезаписывается. Браузер может менять
  порядок расширений и создавать новые JA3/записи.
- Опциональный внешний capture/import инструмент сохранён для разработки.

## Проверки

1. Настоящий Chromium 156.0.8078.47 в disposable Linux container, `--network=none`.
   Обычная HTTP-страница (`isSecureContext=false`) исполняет actual embedded capture
   JS и `loadBrowserProfiles` из `web_ui.h`. API/NVS в этом browser lab имитируются.
   Скрытый локальный TLS получил реальный ClientHello; foreground не перенаправлен,
   диалогов нет, TLS-байтов сервер не отправил. Профиль выбран в форме.
   Сертификаты не устанавливались, certificate-ignore flags не использовались.
   `.local` направлен на loopback только browser-specific resolver rule внутри lab.
2. Production C record parser + C++ converter + patched BoringSSL preview: реальный
   захваченный hello и три ранее захваченных структурных профиля. Независимый Node
   observer подтвердил совпадение JA3 и JA4 вновь сгенерированных ClientHello.
   ASan/UBSan: дробление TCP по байтам, разделение handshake на TLS records,
   все усечённые префиксы, неверные типы/длины, лимит records, другой SNI,
   недопустимое имя, стабильный ID при переименовании.
3. Production C service с pthread/socket host adapters: активный захват, чужой peer,
   неверный ticket, timeout, cancel (включая гонку публикации), повторное сохранение,
   конфликт ID, NVS/alloc/task/parse/preview failures и cleanup. NVS-save проверяется
   на HTTP/main thread. Disabled build stubs возвращают NOT_SUPPORTED.
4. `IDF_PATH=.../esp-idf-meshpn-v5.5.5 bash scripts/test-host.sh` — PASS, включая
   существующие VPN, TLS trust, JS-exit compatibility, storage/API и UI проверки.
   `node tests/test-web-ui.mjs` — PASS.
5. BUILD_ONLY=1 PROFILED_TLS=1: ESP-IDF v5.5.5, три цели собраны без прошивки.

| Плата | App bytes (hex) | Свободно в app partition |
|---|---:|---:|
| XIAO ESP32-S3 | 0x229830 | 28% |
| Stamp-P4 + AddOn C6 | 0x236180 | 26% |
| Waveshare ESP32-P4-WIFI6 | 0x238770 | 26% |

Локальные артефакты (не добавляются в git):
`device/perf-results/onboard-capture-20261029/{result.json,profile.json,hello.bin}`.
Host summary: `/tmp/meshpn-local-capture-host.log`;
parser: `/tmp/meshpn-local-parser-tests.log`;
builds: `/tmp/meshpn-local-final-<board>.log`.

Повторить parser checks:

```sh
node device/tests/test-local-capture.mjs /path/to/bssl-host-deps \
  device/perf-results/onboard-capture-20261029/hello.bin
node device/tests/test-local-capture-service.mjs
```

## Осталось на оборудовании

На телефоне/плате этот сценарий ещё не проверен. Нужны реальные Safari/Chrome,
USB/AP/mDNS, свободная internal/DMA память при одновременном VPN, cancel/reconnect
и сохранность после reboot. Неподдержанные browser TLS fields отклоняются явно;
совместимость с произвольным браузером, включая любой Safari, не заявляется.
Измеряется профиль конкретного подключения к локальному имени, а не обещается
идентичность всем подключениям этого браузера к другим сайтам. HTTP headers,
SETTINGS и тайминги не являются частью этой проверки JA3/JA4.
