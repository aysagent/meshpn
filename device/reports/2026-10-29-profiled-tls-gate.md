# Точный TLS-профиль и отдельный стек для нового backend

29 октября 2026, продолжение [feasibility](2026-10-29-profiled-tls-feasibility.md).
**Прототип воспроизводит оба сохранённых отпечатка и успешно завершает TLS
handshake.** Общий компонент для S3/P4 использует отдельный PSRAM worker;
ML-KEM больше не предполагается запускать на 6 KiB стека `vpn_rx`.

Это интеграция backend в дерево компонентов и отдельное IDF-приложение.
Подключение к VPN transport selector, clean-vpn HTTP/auth/exporter binding и
настройки профиля в админке ещё не реализованы. Обычный `tls` не заменён.
Аппаратных замеров, прошивки плат и обращения к VPS не было.

## Что сделано

- Добавлен общий `components/meshvpn_profiled_tls`, выключенный по умолчанию.
  Прототип и будущая интеграция используют один код, а не два варианта backend.
- Добавлен порядок **нативных** extension writers в отдельной копии BoringSSL.
  Порядок применяется до сериализации/хеширования transcript; криптографические
  байты ClientHello не переписываются после генерации. Неизвестные/повторяющиеся
  ID отклоняются; неожиданные нативные расширения не удаляются молча.
- Подключены настоящие ALPS, trust-anchor request, ECH GREASE и Brotli decoder.
  Client key shares — X25519MLKEM768 и X25519. CA/name verification сохранена.
- Локальный ограниченный парсер вычисляет точные wire JA3 и FoxIO JA4 по
  фактическому handshake сообщению. Состояние принадлежит одному SSL object;
  новое соединение и второй ClientHello после HRR проверяются заново.
- Socket BIO не отправляет данные до успешной проверки и блокирует запись
  после несовпадения. Кэшировать прошлый `match` для нового соединения нельзя.
  Независимый JS observer проверяет фактический первый ClientHello на loopback.

Поддерживается **один фиксированный cold-профиль**, взятый из существующего
Chromium capture #1. Никакой декларации совместимости со всеми браузерами,
arbitrary profile import или воспроизведения HTTP fingerprint нет.
Приватный CA/automation flags исходного capture остаются его ограничением.

## Исправление бюджета памяти

`meshvpn_profiled_tls_run()` создаёт worker со стеком **32 KiB в PSRAM**,
вызывает ограниченную по времени/отмене операцию и освобождает worker/стек до
возврата. При отказе semaphore/task allocation возвращает ошибку, не запускает
работу на стеке вызывающего `vpn_rx` и не использует internal RAM как fallback.
Размер можно увеличить до 64 KiB; уменьшение ниже 32 KiB запрещено Kconfig и
compile-time assertion. API возвращает stack spare для будущих замеров на плате.

Это устраняет выявленную архитектурную ошибку с 6 KiB, но **не доказывает**
достаточность 32 KiB на всех сертификатах/профилях. В S3 статические frames
ML-KEM остаются 6 240 + 2 704 байта; frame локальной проверки — 3 184 байта.
Они не составляют полного call-graph high-water. Аппаратная приёмка обязательна.

BoringSSL использует PSRAM allocator с общим лимитом **1 MiB**, включая headers,
без fallback в internal/DMA RAM. Лимит — верхняя граница, не постоянное
резервирование мегабайта. Освобождаемая память обнуляется. Brotli дополнительно
ограничен: output 64 KiB, live decoder allocations 256 KiB, cumulative allocation
1 MiB на сертификат. Ошибки и превышение лимитов закрывают handshake.

Существующий 6 KiB worker обычного mbedTLS **не увеличен**: постоянно отнимать
ещё 26 KiB internal RAM у Wi-Fi ради пока выключенного backend не требуется.
RNG использует SDK; standalone приложение включает entropy при неактивном
радио. Финальная интеграция должна обеспечить активный источник entropy,
валидное время и отсутствие cache-disabled flash/NVS операций на PSRAM stack.

## Проверки без платы

Один чистый запуск `build-host.sh` завершил всю последовательность:

| Проверка | Результат |
|---|---|
| Независимые captures | 30 новых ClientHello; все **12 профилированных BoringSSL captures совпали** |
| Контрольные backend | 18 mbedTLS/default/helper captures не совпадают, как и ожидается |
| TLS 1.3 + exporter | 12 успешных handshake: 3 mbedTLS, 3 профиль BoringSSL, 3 hybrid-only, 3 HRR/P-256 |
| Brotli + ALPS | Ещё 3 BoringSSL handshake с реально сжатым сертификатом и согласованным ALPS; exporter совпал |
| Отрицательные handshake | 7: чужой CA у двух backend, неподдержанный hybrid-only у mbedTLS, четыре мутации gate |
| Только JA3 отличается | Перестановка расширений: отказ, **0 TLS bytes sent** |
| Только JA4 отличается | Перестановка signature algorithms: отказ, **0 TLS bytes sent** |
| ALPN / отсутствует observer | Отказ, **0 TLS bytes sent** |
| HRR | Во всех трёх соединениях локальный gate увидел и проверил **2 ClientHello** |
| Парсер | Все обрезанные префиксы валидного ClientHello + 50 000 мутаций под ASan/UBSan, без находок |
| Brotli decoder | Round trip, truncation, trailing input, неверный output size и превышения лимитов отвергнуты |
| Worker/allocator | Ошибки создания, возврат результата, 100 create/cleanup циклов, переполнение/лимиты и rollback после OOM прошли |
| IDF prototype | Чистые сборки ESP32-S3 и ESP32-P4 с общим компонентом прошли |
| Обычные прошивки | XIAO S3, M5Stack Stamp P4 + C6 и Waveshare P4 собраны с backend, выключенным по умолчанию; без прошивки плат |

Ожидаемые и фактические значения совпали:

- JA3: `ed63604b6e93c62437468be3f6b387c3`.
- JA4: `t13d1517h2_8daaf6152771_cb7bf5808d99`.

Host: macOS arm64, Node 24.13.0 / OpenSSL 3.5.4. Worker/PSRAM unit tests используют
host-адаптеры FreeRTOS/heap API, а не реальную память/планирование ESP32.
ASan/UBSan инструментируют наш parser/decoder glue/worker/allocator; собранные
статические библиотеки BoringSSL/Brotli этим не объявляются полностью фаззированными.

Standalone `.bin`: S3 **870 304 байта**, P4 **956 016 байт**. Это whole-image
размер с IDF/PSRAM/probe, не прирост MeshPN. P4 size tool сохраняет предупреждение
о `sram_seg`; таблица памяти не является полным бюджетом платы.

## Что осталось до VPN-транспорта

1. Добавить clean-vpn HTTP/auth/exporter binding и передачу IP-пакетов. Успешный
   TLS handshake и exporter сами по себе этот протокол не реализуют. Нельзя
   отправлять raw IP framing на соединении с согласованным HTTP/2.
2. Подключить bounded nonblocking I/O, cooperative cancellation и управление
   жизненным циклом к VPN. Не удалять задачу посреди работы BoringSSL; текущий
   executor рассчитан на callback с собственным deadline/cancel.
3. Добавить ограниченный импорт/выбор профиля и диагностику его применения.
   Не объявлять неподдержанный профиль успешно применённым.
4. На платах измерить handshake stack/heap, отказ без PSRAM, reconnect/OOM,
   совместную работу с Wi-Fi/USB и реальный туннель. Производительность не измерена.

Код и воспроизведение: [компонент](../components/meshvpn_profiled_tls/README.md),
[lab](../experiments/profiled-tls/README.md).
Артефакты локально:
[perf-results/2026-10-29-profiled-tls-gate](../perf-results/2026-10-29-profiled-tls-gate/).
В архиве нет приватных PKI ключей или exporter secrets; generated keys остались
в приватном `/tmp` output. Исходники native clean-vpn другого агента не менялись.
