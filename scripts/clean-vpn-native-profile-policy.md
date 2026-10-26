# Политика совместимости native профиля

`bounded-cold-v1` описывает текущий экспериментальный cold TLS/H2 subset.
Это **не профиль Chrome**. Он сохраняет ограничения ресурсов, проверку CA/имени
и exporter-bound PSK. `browser_profiles:false` остаётся.

Политика экспортируется самим `clean-vpn-engine --capabilities`. H2 ranges,
обязательные SETTINGS и TLS allowlists берутся из тех же C++ констант, которыми
пользуется загрузчик профиля. Неизвестные extensions отвергаются до генерации
ClientHello; точная prewire-проверка сохраняется.

## Проверить сохранённые измерения

На Linux с актуальной сборкой:

```bash
native/clean_vpn/build/clean-vpn-engine --capabilities > /tmp/native-capabilities.json
node scripts/clean-vpn-native-profile-policy.mjs \
  BROWSER.json /tmp/native-capabilities.json NATIVE.json
```

`BROWSER.json` и `NATIVE.json` — bundles из [отдельного TLS/H2 capture](clean-vpn-native-http2-capture.md).
Команда только читает файлы и печатает JSON; не запускает VPN, не генерирует
исполняемый профиль, не меняет сеть. Checksum обоих bundles обязателен.
Symlink и слишком большие файлы отвергаются. Корректный отчёт со статусом blocked
возвращает exit 0; ошибка входного формата — exit 1.

Воспроизвести текущий разбор на Mac без VM и сети:

```bash
node scripts/clean-vpn-native-profile-policy.mjs \
  fixtures/native-browser-captures/chromium-linux-arm64-156.0.8078.47-h2.json \
  fixtures/clean-vpn-native-profile-policy-capabilities.json \
  fixtures/native-browser-captures/native-cold-alps-h2.json
npm run test:native-profile-policy
```

[Сохранённый результат](../fixtures/clean-vpn-native-profile-policy-report.json):
**blocked**. Captures предыдущего checkpoint не перезаписаны; native reference
измерен на его fixture binary. Capabilities экспортированы после текущей сборки.
Этот разбор не является новым wire-прогоном и не доказывает идентичность сборок.

## Что означает результат

- `within-envelope` у отдельного поля: значение входит в опубликованную политику.
  Это не проверка работоспособности комбинации полей.
- `blocked`: есть явно неподдерживаемые параметры или несколько cold вариантов,
  которые нельзя объединять в один стабильный профиль.
- `incomplete`: не хватает TLS/H2 evidence либо трёх независимых samples с одной
  из сторон. Если одновременно есть блокеры, верхний статус — blocked, а пропуски
  остаются отдельными checks.
- `deviation`: измеренное отличие прикладного поведения от native carrier.
- `needs-native-validation`: явных блокеров и пропусков не найдено; обязательны
  реальный `--check-config`, handshake и независимое сравнение выходящего трафика.

Ни один результат не выставляет `nativeValidated`, `browserEquivalent` или
`profileActivated`. `executableProfile` всегда null. `unchanged` означает, что
этот инструмент не изменял настройки; это не аттестация полученного binary.
JSON checksum обнаруживает изменение bundle, но не подтверждает его автора.
Capabilities тоже являются входными данными, а не подписанным удостоверением engine.

## Граница текущей реализации

| Параметр | Измеренный Chromium 156 | Политика native |
| --- | --- | --- |
| TLS cipher suites | Включает static RSA/CBC | Только существующий AEAD subset; расширение ради JA3 запрещено текущей политикой |
| ML-DSA sigalgs | 2308, 2309, 2310 | Пока не разрешены |
| Дополнительные extensions | tickets 35, trust anchors 51764 | Пока не реализованы в profile contract |
| Brotli / ALPS | 2 / new codepoint 17613, h2 | Поддержаны экспериментально; negotiated ALPS проверяется отдельным стендом |
| H2 header table | 64 KiB | 0–64 KiB, опциональный ID 1 |
| H2 concurrent streams | ID 3 отсутствует | Обязательный ID 3 = 1 |
| H2 stream window | 6 MiB | 65 535–1 048 576 bytes |
| H2 connection window | 15 MiB | 65 535–1 048 576 bytes |
| H2 max header list | 256 KiB | 1–8 KiB |
| H2 push / max frame | push = 0, frame ID отсутствует | ID 2 = 0 обязателен; ID 5 опционален, только 16 KiB |
| HTTP request | GET-навигация, browser headers/priority | Фиксированный аутентифицированный POST; header order/values и priority отличаются |

Значения не обрезаются до caps, отсутствующие SETTINGS не добавляются в capture,
неподдерживаемые cipher suites не удаляются ради формального success. Для точного
воспроизведения все такие изменения были бы отклонениями от браузерного профиля.

Размер окна — разрешённый объём данных на wire, а не размер заранее выделенного
буфера. Увеличивать credit можно только после отдельной проверки bounded queues,
backpressure и суммарной памяти нескольких клиентов. В этом checkpoint лимиты
не повышались. Размер HPACK block не доказывает стратегию его кодирования.

Groups/key shares и сочетания TLS-полей окончательно проверяет реальный BoringSSL
prewire path. Порядок SETTINGS сохраняется в evidence, несколько кадров, дубли,
неподдерживаемые IDs и stream WINDOW_UPDATE в initial prefix отмечаются явно.
Resumption, поздние streams и timing этим отчётом не покрыты.

## Проверено и дальнейший порядок

Локальная Linux/Podman-лаборатория: CTest **10/10**, native TLS profile integration
**14/14**, включая проверку границ capabilities через настоящий `--check-config`.
Assessor/CLI: **10/10**, включая повреждённые checksum, частичные captures, варианты,
неизвестные SETTINGS, policy schema и отсутствие автоматической активации.
Тесты policy добавлены в обычный `--tls-profiles` runner.

1. Следующий лабораторный шаг — ML-DSA и trust-anchor extension: выяснить поддержку
   закреплённого BoringSSL, затем добавить только семантически проверенные knobs
   с положительными и отрицательными handshake-тестами. Сам факт объявления
   extension не считается поддержкой.
2. Ticket/resumption lifecycle — отдельный этап; cold capture не достаточен для
   его настройки. Не включать tickets или 0-RTT автоматически по одному снимку.
3. H2 budget — отдельный нагрузочный эксперимент с несколькими клиентами и
   медленным получателем, прежде чем обсуждать повышение окон/лимитов.
4. После изменений повторить независимый browser/native capture. Честно сохранять
   все оставшиеся отклонения: при нынешней cipher policy точный профиль этого
   Chromium всё равно останется недоступен. HTTP POST нельзя переименовать в
   браузерную навигацию заменой User-Agent.

Всё это можно делать локально в лаборатории. Повторного физического испытания
Radxa/VPS для данного checkpoint не проводилось.
