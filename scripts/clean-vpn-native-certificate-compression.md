# Native Brotli certificate compression

Опциональный client decoder для TLS certificate compression, algorithm 2
(Brotli). Работает в native `boring-tls` и его ветке `combo-tls`. Это поддержка
одной возможности ClientHello, не приёмка полного профиля Chrome.

## Профиль

Пример: [synthetic cold Brotli](../fixtures/native-tls-profiles/cold-brotli.json).
В `tls` сохраняются два согласованных поля:

```json
"certificate_compression": [2],
"extension_types": [0, 10, 16, 13, 51, 45, 43, 27]
```

Поле `certificate_compression` опционально: отсутствие и `[]` отключают
расширение. Старые профили продолжают работать. Поддерживается только `[2]`;
дубли, неизвестные algorithms, null и противоречие с наличием ext27 отклоняются.
В примере включено `permute_extensions:true`; произвольный фиксированный порядок
по-прежнему не реализован. Перед запуском нужен обычный `--check-config`.

BoringSSL сам создаёт расширение и обрабатывает CompressedCertificate в TLS
transcript. Prewire gate проверяет не только ext27, но и список algorithms.
Independent observer также сравнивает этот список и переносит `[2]` в
capture-кандидат. Ни captured bytes, ни сжатая цепочка не переигрываются как
opaque extension. Если сервер не выбирает compression, обычный Certificate
принимается штатным TLS стеком.

## Проверка и ограничения ресурсов

Callback распаковывает TLS Certificate body, затем BoringSSL выполняет обычные
проверки структуры, цепочки, времени и hostname. Проверка exporter-bound PSK
по-прежнему обязательна до передачи VPN-пакетов.

- Сжатое сообщение и заявленный результат: каждый максимум 128 KiB.
- Память внутренних allocations Brotli: максимум 4 MiB одновременно, включая
  служебные заголовки нашего allocator; суммарные allocations за callback — 16 MiB.
- Выходной CRYPTO_BUFFER ограничен отдельно 128 KiB. Это не общий лимит RSS
  engine: память TLS/X509 и прочих компонентов сюда не входит.
- Результат должен иметь **ровно** заявленную длину, весь вход должен быть
  израсходован. Усечения, дополнительные данные, concatenated streams,
  недостаток/избыток output и ошибки allocation приводят к отказу handshake.
- Стандартные ограничения размера цепочки BoringSSL остаются действующими и
  могут быть строже лимита callback. Не обещается приём любой цепочки до 128 KiB.

В production binary линкуются только decoder/common. Encoder нужен исключительно
тестовым бинарникам. Production exit этим шагом не начинает сжимать сертификаты;
на production client декодер включается только явно выбранным профилем.

## Сборка

Добавлена статическая зависимость [Brotli v1.2.0](https://github.com/google/brotli/releases/tag/v1.2.0),
pinned commit `028fb5a23661f123017c060daa546b55cf4bde29` через CMake FetchContent.
Системная установка Brotli не нужна. Первый configure загружает исходник,
следующие сборки используют кэш. [Streaming decoder API](https://github.com/google/brotli/blob/028fb5a23661f123017c060daa546b55cf4bde29/c/include/brotli/decode.h)
используется с собственным allocator и фиксированным выходным буфером.

```bash
npm run lab:native:mac -- --tls-profiles
```

Лаборатория проверяет реальный обмен C++ client/exit через TCP. Только тестовый
engine-fixture может отправлять Brotli CompressedCertificate и повреждённые
варианты. Callback TLS сообщений отдельно подтверждает отправку handshake
message 25; наличие ext27 само по себе не считается такой проверкой.

Проверки: обычный Certificate fallback, compressed exchange, HRR, Boring-ветка
combo, CA/hostname/PSK rejection, truncated/trailing/wrong-size/garbage streams.
Отдельный C++ test проверяет размеры, budgets и мутации decoder input. ASAN/UBSAN
прогон инструментирует decoder/common и наш callback; prebuilt BoringSSL на Mac
не инструментирован, это не whole-engine sanitizer certification.

[Лабораторный отчёт](../fixtures/clean-vpn-native-certificate-compression-report.json):
9/9 CTest, 24/24 native core/session/profile регрессий, отдельная финальная
профильная проверка 9/9 с `--network=none`, 24/24 capture/build/JA тестов.
Профильные проверки в этих запусках пересекаются и не суммируются как разные тесты.

## Что остаётся

Исторический [Chromium capture bundle](../fixtures/native-browser-captures/chromium-linux-arm64-156.0.8078.47.json)
не переписывается: в нём сохранена оценка совместимости на момент захвата.
Новый capture-кандидат уже понимает Brotli/2. Прочие несовместимости сохраняются:
ALPS/H2, trust anchors, ML-DSA, session ticket lifecycle и запрещённые native
policy cipher suites. `browser_profiles:false` остаётся.

Следующий шаг — ALPS вместе с согласованным реальным H2 поведением и проверкой
сервера, а не добавление одного типа расширения ради JA3/JA4.
