# Профилированный TLS: feasibility без плат

29 октября 2026. **BoringSSL — основной кандидат для следующего прототипа,
но профилированный транспорт ещё не готов.** Минимальный порт собирается для
Xtensa ESP32-S3 и RISC-V ESP32-P4. На компьютере работают TLS 1.3, проверка CA/имени,
гибридный X25519MLKEM768 и exporter. Точного браузерного JA3/JA4 пока нет.

Эксперимент изолирован в [experiments/profiled-tls](../experiments/profiled-tls/README.md).
Рабочие прошивки, их TLS-настройки, SDK, desktop helper и его BoringSSL checkout
не менялись. Платы не подключались, прошивка не выполнялась; Wi-Fi Mac, firewall,
роутер, C6 и VPS не затрагивались. Проверки сети — только loopback.

## Что проверено

| Проверка | Результат |
|---|---|
| Фактические ClientHello | 27 разных захватов; каждый проверен отдельно по точному wire JA3 и FoxIO JA4 |
| Совпадение с браузерным эталоном | **0/27**, без подмены wire JA3 сортированным |
| TLS 1.3 и exporter | 9 успешных соединений: 3 mbedTLS, 3 BoringSSL, 3 BoringSSL с hybrid-only сервером |
| `EXPORTER-clean-vpn-bind` | 32 байта совпадают у клиента/сервера в каждом успешном соединении; значения различаются между соединениями |
| Отрицательные handshake | Чужой CA отвергнут обоими backend; mbedTLS отверг hybrid-only сервер |
| Xtensa / ESP32-S3 | Чистая сборка отдельного IDF probe прошла |
| RISC-V / ESP32-P4 | Чистая сборка отдельного IDF probe прошла |

Host: macOS arm64, Node 24.13.0 / OpenSSL 3.5.4. mbedTLS взят из ESP-IDF v5.5.5,
но собран с **host defaults**, не с конфигурацией прошивки. В продукте обычный
`tls` по-прежнему использует esp-tls/mbedTLS и TLS 1.2. Наличие TLS 1.3 в
[SDK](https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32s3/api-reference/protocols/mbedtls.html)
само по себе не означает, что он включён в прошивке.

BoringSSL: `a7481f34712bc056a47ab91015536166b3a6cebb`, шесть существующих патчей
clean-vpn; входной diff SHA256:
`014864ae964ae2b82c1fa58f66270473cfb9386d7c0d721a5780522d0a873c1e`.
Для копии добавлены Xtensa target, два исправления типа extension index и
опциональные host allocator hooks. Используются `OPENSSL_SMALL`, no-ASM,
pthread locks; на IDF отключены filesystem/POSIX socket BIO. Это экспериментальный
порт, а не заявленная upstream поддержка ESP32. [Описание сборки BoringSSL](https://boringssl.googlesource.com/boringssl/+/a7481f34712bc056a47ab91015536166b3a6cebb/BUILDING.md).

## Где расходится отпечаток

Эталон — одна реальная запись Chromium 156 из репозитория, с приватным тестовым
CA и automation flags. Это **не stock public-Web baseline** и не полный
replayable-профиль: opaque payloads в этом эталоне отсутствуют.
[Происхождение и формат](../docs/vpn-profile-validation.md).

Ожидаются JA3 `ed63604b6e93c62437468be3f6b387c3` и
JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`.

| Backend с preference-настройками | Фактический JA3 | Фактический JA4 |
|---|---|---|
| mbedTLS | `e664a87f14b0cd0e2501eecfc7eab3d9` | `t13d1610h2_1711a4c0508c_8846e450cd95` |
| BoringSSL probe | `b1870bcb9b0b2684a4bca0f94963a2e5` | `t13d1513h2_8daaf6152771_814117079121` |
| Существующий desktop helper с полями эталона | `64a2e166feb367d2b54aa7febed166a0` | `t13d1512h2_8daaf6152771_480f8f85d31b` |

BoringSSL probe воспроизводит **в точном порядке** cipher suites, supported groups,
signature algorithms и EC point formats. Недостающие расширения: ALPS (17613),
trust_anchors (51764), certificate_compression (27), ECH/GREASE (65037).
Порядок имеющихся расширений тоже отличается. У desktop helper в этом опыте
дополнительно отсутствует SCT (18); это не проверка его возможностей с полным
браузерным профилем.

У mbedTLS дополнительно есть SCSV 255, отсутствуют группа 4588
(X25519MLKEM768), ML-DSA signature algorithms 2308/2309/2310 и семь расширений.
Просто задать список предпочтений недостаточно: неподдержанные алгоритмы не
появились в фактическом ClientHello. Поэтому mbedTLS остаётся обычным TLS backend;
работу над точным профилем разумно продолжать с BoringSSL.

В закреплённом BoringSSL есть API для ALPS, trust anchors и ECH GREASE; они пока
не подключены к probe. Для certificate compression нужен настоящий обработчик
согласованного алгоритма. Добавлять только номера расширений или переписывать
ClientHello после формирования transcript нельзя считать корректным решением.

## Память, flash и стек

Чистые отдельные сборки с оптимизацией размера:

| Цель | `.bin`, байт | DIRAM по size tool | `.data` / `.bss` |
|---|---:|---:|---:|
| ESP32-S3 | 706 912 | 52 467 | 11 988 / 4 952 |
| ESP32-P4 | 783 872 | 71 904 | 9 332 / 8 664 |

Это весь standalone probe с IDF, **не прирост размера MeshPN**. Размер зависит и
от диагностических путей в исходниках. P4 size tool предупреждает, что не смог
сопоставить `sram_seg` с типом памяти; его таблица не является полным RAM-бюджетом.
Сборка P4 проверяет архитектуру, не отдельные USB/SDIO профили Stamp/Waveshare.

На host BoringSSL запросил максимум **29 370 байт heap** при успешном handshake,
29 452 при отказе из-за CA; крупнейшая аллокация — 7 816 байт. Учёт действительно
активен (390 allocations в успешном случае); обычные ELF weak hooks на macOS
не использовались. Это requested bytes без allocator overhead, стека и других
задач; 64-битный host отличается от ESP32. Остаток 320 байт снят в `atexit`;
порядок финального cleanup не исследован, поэтому этот остаток сам по себе не
доказывает утечку. Эти цифры **не замер RAM платы**.

Существенное ограничение: в сборке S3 frame `encrypt_cpa<3>` занимает **6 240 байт**,
а вызывающий его `mlkem_decap_no_self_test<3>` — ещё **2 704**. Оба символа реально
вошли в ELF; вместе только эти вложенные frames дают 8 944 байта, без остальных
вызовов TLS/RTOS. Для P4 соответственно 6 256 и 2 704. Текущий `vpn_rx` имеет
стек **6 144 байта** — подключать туда этот backend без переработки нельзя.
Большие frames из неиспользуемых self-tests в runtime-оценку не включались.

Standalone probe использует 64 KiB main stack и источник entropy, включённый
при неактивном радио. Ни этот размер, ни перенос аллокаций в PSRAM, ни coexistence
entropy с Wi-Fi ещё не подтверждены на устройстве. Полный hardware high-water,
internal/DMA minima и время handshake остаются обязательной приёмкой.

## Что делать дальше

1. Выбрать один полный воспроизводимый профиль, включая extension payloads и
   ALPN. Добавить нужную семантику расширений и управление порядком **до**
   сериализации/хеширования transcript. Проверить новые handshake с обычным и
   hybrid-only сервером, CA/name validation и фактический ClientHello.
2. Превратить сравнение JA3/JA4 в обязательный gate каждой новой сессии/reconnect:
   без свежей проверки не передавать VPN payload, не допускать plaintext или
   обычный TLS fallback под видом профилированного режима.
3. Отдельно адаптировать ESP32 I/O, cancellation, RNG, allocator и стек;
   выбрать ограничения для XIAO и P4 по измерениям, а не по объёму свободной PSRAM.
4. Реализовать совместимый clean-vpn HTTP/auth/exporter binding. Здесь проверена
   только примитивная операция exporter, не Bearer/HMAC, HTTP, tunnel payload,
   прозрачное проксирование или combo-tls.
5. На платах: многократные handshake/reconnect, OOM/cancel, пик памяти/стека,
   затем скорость/устойчивость. Ускорение AP/STA этим экспериментом не проверялось.

wolfSSL просмотрен как альтернативный API-кандидат, но не портирован и не
проверен на отпечатке; оснований объявлять его непригодным нет. [TLS 1.3](https://www.wolfssl.com/docs/tls13/),
[API настройки](https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html).

## Воспроизведение и артефакты

[Три команды сборки/проверки](../experiments/profiled-tls/README.md) прошли;
S3 summary повторно сформирован после уточнения сопоставления template symbols.
Исправлена гонка loopback runner: успешный клиент больше не сравнивается с ещё
не обработанным событием server handshake. Отрицательные случаи требуют именно
TLS-ошибки, а не сигнала/таймаута процесса.

Локально сохранены captures, result JSON, build logs, config, stack usage,
linked-symbol evidence, source manifest и SHA256:
[perf-results/2026-10-29-profiled-tls-feasibility](../perf-results/2026-10-29-profiled-tls-feasibility/).
Приватная PKI осталась в `/tmp`; она не включена в отчёт/коммит.
Транспорт в админке не добавлялся: ноль точных совпадений не позволяют назвать
профиль поддержанным.
