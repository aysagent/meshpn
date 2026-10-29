# Профилированный TLS подключён к VPN

29 октября 2026. Продолжение [проверки точного профиля](2026-10-29-profiled-tls-gate.md).

Отдельный `boring-tls` теперь проходит путь от настроек админки до проверенного
TLS 1.3, clean-vpn авторизации и передачи IP-пакетов. Включение сборки и команда
exit описаны в [инструкции](../docs/profiled-tls.md).

## Реализация

- Общий backend для XIAO, Stamp P4 и Waveshare P4. Опция `PROFILED_TLS=1`,
  изолированные pinned зависимости, обычные сборки остаются без backend.
- Один фиксированный Chromium capture, точный JA3/JA4 gate для каждого нового
  ClientHello до отправки, включая повторный Hello. Старый `match` не переиспользуется.
- Сертификат сервера проверяется по CA, имени и времени. Только TLS 1.3.
- HTTP/1.1 GET с Bearer v2: HMAC привязан к exporter текущей TLS-сессии и окну
  времени. Shared key, exporter и Bearer не выдаются статусом; временные копии
  ключевого материала обнуляются. Plaintext/v1 fallback отсутствует.
- До строгого HTTP tunnel ACK пакетный путь не запускается. Cover HTTP 200,
  chunked/content-length body, повторный Content-Type, folded или слишком большой
  заголовок не принимаются как туннель.
- Handshake/auth/I/O, отмена, чтение и запись принадлежат одной PSRAM-задаче
  с 32 KiB стека. Контекст SSL не используется одновременно двумя workers.
  При WANT повторяется тот же буфер записи; зависшая передача ограничена сроком.
- На P4 явно включается SAR entropy source при старте профилированной сборки:
  радио C6 не заменяет источник P4. В локальном ESP-IDF 5.5.5 bootloader вызывает
  `bootloader_random_disable()` перед приложением; повторного включения в проекте
  не было. SAR ADC приложением не используется и теперь резервируется для RNG.
  Основание: [Espressif RNG](https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32p4/api-reference/system/random.html)
  и проверенные `bootloader_utility.c` / `bootloader_random_esp32p4.c` используемого SDK.
- Существующие routing/NAPT, generation cancellation и kill switch используются
  новым транспортом. Фоновой raw TX-задаче не посылаются уведомления на каждый
  пакет профилированного транспорта.
- Админка хранит отдельный endpoint, профиль, HMAC key; пустой ввод сохраняет
  ключ, удаление явно управляется checkbox. NVS v1–v5 мигрируют в v6. Настройки
  WireGuard/TCP/UDP/raw TLS сохраняются. CA и TLS server name общие с raw TLS.
- В статусе — текущая попытка, generation, phase, expected/actual JA3/JA4,
  match/authenticated, ALPN, ошибки SSL/verify и запас стека завершившейся задачи.

При просмотре интеграции исправлена также вместимость общей RX batch для
минимальных IPv4-фрагментов: 8192 байта могут завершить 342 пакета с учётом
остатка предыдущего read. Старое ограничение 320 было недостаточным.
Профилированный TLS читает порциями до 4096 байт; соответствие вместимости
проверяется при компиляции.
Проверены крайние UDP batch настройки 1/32/64: уменьшение UDP batch больше не
уменьшает TCP/TLS буфер, а смещения пакетов не переполняются после 64 KiB.

## Проверки

Новый host-тест использует production TLS session, gate, allocator и IPv4
framing. Exit — настоящий JS `runExit`, с заменой только TUN/настройки ОС на
тестовую границу. TCP/TLS работают через loopback, без VPS и изменения сети Mac.

| Проверка | Результат |
|---|---|
| Реальный exit HTTP/1.1 | 10 отдельных процессов + 20 последовательных сессий в одном процессе; 1920 IP-пакетов прошли туда и обратно |
| Отпечатки | Независимый observer exit подтвердил ожидаемые JA3 и JA4; локальный gate проверяется на каждом соединении |
| Повторные сессии | Оставшиеся allocations не растут после каждой из 20 сессий; остаётся один immutable BIO method |
| Отказы | Неверные ключ/CA/имя, истёкший и будущий сертификат, неизвестный профиль, h2, malformed/cover ACK отклонены до IP-трафика |
| Lifecycle | Отмена во время handshake/auth и после ACK; disconnect, invalid IP frame, медленный auth и TX backpressure завершаются предсказуемо |
| OOM | Отказы allocations в начале и внутри handshake не допускают IP-трафик |
| Sanitizers | ASan/UBSan на session/gate/allocator/framing и host harness, без обнаруженных ошибок |
| Общая регрессия | `scripts/test-host.sh` прошёл, включая raw TLS и config/storage/routing/kill-switch tests |
| Плотная RX batch | Production decoder + collector принимают 342 минимальных фрагмента без переполнения; проверено ASan/UBSan |
| Сборки | ESP-IDF 5.5.5: XIAO S3, Stamp P4 + C6, Waveshare P4 WIFI6 с backend; обычная XIAO без backend |

Последний session run: 34 сценария/записи, 53 подключения с учётом повторов.
Host allocator имел максимум 32 724 байта в этих сценариях, оставшийся BIO method
занимал 328 байт. **Это не расход памяти ESP32**: ABI, сертификаты, нагрузка и
дополнительные задачи отличаются; PSRAM stack отдельно. Лимит allocator 1 MiB
остаётся верхней границей, не обещанием фактического расхода.

Артефакты локальной проверки:

- session JSON: `/var/folders/k_/2lrssx3x5klcpnnrsz2_3b080000gn/T/meshpn-profile-tunnel-ZmHAkA/result.json`;
- общая host-регрессия: `/tmp/meshpn-profile-final-regressions.log`;
- финальные сборки: `/tmp/meshpn-profile-build-{xiao_esp32s3,m5_stamp_p4_c6,waveshare_esp32_p4_wifi6,default}.log`.

Эти временные каталоги могут быть удалены ОС. Для воспроизведения предусмотрены
`experiments/profiled-tls/build-host.sh` и `tests/test-profiled-tunnel.mjs`.

## Что ещё не подтверждено

Плат не было: ничего не прошивалось. Не проверены реальные USB/AP → VPN,
интернет через exit, скорость, длительная нагрузка и device stack high-water.
Статические `.su` frames не равны полному расходу стека; 32 KiB требуется
проверить на каждой плате до включения backend по умолчанию.

Поддержан только HTTP/1.1 на exit (`--http-vers=1.1`, без `--tls-raw`). ClientHello
сохраняет browser ALPN `h2,http/1.1`; выбор h2 отклоняется явно. HTTP/2, импорт
произвольных профилей, HTTP fingerprint и возобновление браузерных сессий остаются
отдельной работой. Проверялся JS exit, не параллельно разрабатываемый native exit.

Следующий шаг — аппаратная приёмка этого backend, затем HTTP/2 и расширение
поддерживаемых профилей на основании реальных captures.
