# Серия браузерных захватов для native TLS профиля

Новый [TLS + H2 checkpoint и сравнение с native](clean-vpn-native-http2-capture.md)
добавляет измерение первых SETTINGS, окон и заголовков.

Этот этап собирает **измерения**, а не включает мимикрию автоматически. Он
отделён от старого `ja3-snif-server.mjs` и его helper-профилей. Native engine
получает только свой строгий [cold TLS контракт](clean-vpn-native-tls-profiles.md).

## Автоматическая локальная лаборатория

На Mac с подготовленным Podman и зависимостями проекта:

```bash
npm run lab:native:mac -- --browser-capture
```

Первый запуск собирает отдельный ARM64 Debian/Chromium image. Последующие
используют кэш; образ native engine и его BoringSSL не пересобираются. Версия
Chromium берётся из фактически запущенного процесса и сохраняется вместе с
версиями пакетов. Tag отражает рецепт образа, не фиксирует будущие версии APT:
для сравнения разных запусков проверяйте версии в отчёте.

Сам эксперимент выполняется с `--network=none`, без опубликованных портов,
без capabilities и без writable mount хоста. Браузер работает как пользователь
`node`; Chromium sandbox выключен внутри этого одноразового контейнера, что
явно отражается в отчёте. Лабораторный CA импортируется только в его NSS DB.
Профиль браузера, CA и NSS DB удаляются вместе с контейнером. Системное
хранилище сертификатов, браузеры, DNS, маршруты и firewall Mac не меняются.

Проверки идут последовательно:

1. Браузер без лабораторного CA обязан отклонить сертификат. Неуспешный TLS
   handshake не становится образцом.
2. После импорта CA запускаются 20 отдельных процессов Chromium с новыми
   профилями. Каждый открывает HTTPS-страницу через TLS 1.3/H2.
3. Обновление страницы на существующем соединении не создаёт новый образец.
4. Скачанный JSON сравнивается с измерениями сервера.

Готовый отчёт экспортируется в
`~/Library/Caches/meshpn-clean-vpn-lab/results/cvpn-browser-capture-*.json`.
Команда печатает точный путь. Контейнер удаляется даже при ошибке. VM остаётся
запущенной для следующих экспериментов; остановка:

```bash
npm run lab:native:mac -- --stop
```

Это эталон **headless Chromium конкретной версии на Linux ARM64 с записанными
флагами**, не Chrome пользователя на macOS/Windows и не все Chromium-сборки.

## Страница захвата

Отдельная команда для ручного локального опыта:

```bash
node scripts/clean-vpn-native-browser-capture.mjs METADATA.json CERT.pem KEY.pem
```

Сертификат должен быть выпущен для `localhost` и уже доверен тестовым браузером.
Команда сама не устанавливает доверие и не отключает проверку сертификата.
Пример METADATA.json:

```json
{
  "schema": 1,
  "id": "my-browser-cold",
  "identity": {
    "browser": "Chromium",
    "version": "REPLACE-WITH-ACTUAL-FULL-BUILD",
    "versionSource": "operator-declared",
    "platform": "linux",
    "architecture": "arm64"
  },
  "context": {
    "scenario": "cold",
    "isolation": "operator-declared",
    "certificateValidation": "enabled",
    "http": "h2",
    "proxy": "none",
    "echMode": "grease",
    "extensionOrder": "permuted",
    "padding": "optional"
  }
}
```

Поля политики — явные заявления об условиях опыта, не догадки по одному
ClientHello. Для другого браузера их нужно проверить. ECH extension сам по
себе не доказывает, что это GREASE. `versionSource` — происхождение заявленного
значения, не криптографическая аттестация клиента.

Внешняя точка захвата и два внутренних relay-слушателя используют только
`127.0.0.1` и случайные порты. В stdout — адрес с временным
случайным token. Откройте его, затем скачайте bundle по ссылке на странице.
Измерения хранятся только в памяти: 180 секунд, максимум 32 образца и 8 соединений;
до 64 KiB на первый ClientHello. Неправильные token/authority/method/Origin не
сохраняют измерение. Повторный GET по тому же соединению не увеличивает счётчик.
Нет удалённого bind, автоматического применения профиля или изменения engine.

Нужен отдельный свежий процесс/профиль для каждого cold-образца. Сервер проверяет
отсутствие TLS resumption, но не может доказать свежесть всего браузерного профиля
или включённую проверку CA у произвольного ручного клиента.

## Содержимое bundle и граница совместимости

- Версия браузера, ОС/архитектура, заявленные условия захвата.
- Для каждого образца: согласованные TLS/ALPN, JA3/JA4, измеренные ciphers,
  groups, key-share groups/длины, sigalgs, versions, extension types.
- Размеры TLS records, длина ClientHello, позиции GREASE ciphers, порядок и
  длины расширений до удаления GREASE, certificate compression algorithms.
- Начальный H2 prefix до первого END_HEADERS: SETTINGS в wire-порядке, WINDOW_UPDATE,
  frame order, размер HPACK block и priority в HEADERS. Порядок декодированных
  заголовков и значения из явного публичного allowlist.
- Изменения стабильных TLS-полей между образцами и конкретные unsupported IDs.
- Контрольная сумма JSON-содержимого. Она не является подписью издателя.

Нет raw ClientHello, key-share bytes, random, session-ID bytes, SNI текста,
PSK binders, значений Cookie/Authorization/URL/authority, токена страницы или TLS
secrets. Сохраняются User-Agent, Accept/Accept-Language/Accept-Encoding, client hints
и некоторые другие публичные значения; bundle теперь содержит и эти метаданные.
Raw bytes нужны только кратковременно внутри observer и не экспортируются.

`assessment.status`:

| Статус | Значение |
| --- | --- |
| `insufficient-samples` | Меньше трёх образцов; это лишь минимальный порог |
| `inconsistent` | Различаются поля, которые выбранная политика считает стабильными |
| `unsupported` | Есть возможности, которые native контракт пока не поддерживает |
| `candidate` | Получился предварительный контракт; native проверка ещё обязательна |

`candidateProfile` отсутствует (`null`) при unsupported/inconsistent/недостатке
образцов. Даже при `candidate` поля `nativeValidated` и `browserEquivalent`
остаются `false`: обязательны `--check-config` с нужным SNI/CA и независимая
проверка нового native соединения. Расширения и слабые cipher suites не удаляются
ради получения совпадающего JA-хеша. Необязательный padding остаётся в измерении
и фактическом отпечатке.

`assessment.status` по-прежнему оценивает TLS candidate. H2 evidence идёт отдельно
в `samples[].http2`; наличие измерений не превращает их в исполняемый native профиль.
Если авторизованный запрос не был первым в соединении, H2 отмечается unavailable:
чужой initial prefix не сопоставляется с заголовками более позднего запроса.
HPACK strategy, повторные потоки, resumption и timing не измеряются.
Регистрация профиля для постоянного использования, его выбор в UI, resumption,
HRR browser fidelity и семантическая поддержка недостающих расширений — следующие
этапы. Эта страница даёт наблюдаемую исходную точку для этих доработок.

## Регрессия

Зафиксированный реальный baseline:
[Chromium 156.0.8078.47 / Linux ARM64](../fixtures/native-browser-captures/chromium-linux-arm64-156.0.8078.47.json).
20 fresh-process cold-сеансов: 20 JA3, один JA4
`t13d1517h2_8daaf6152771_cb7bf5808d99`, стабильные проверяемые поля после
заявленной нормализации перестановки. Это успешный **захват**, совместимость с
текущим engine — **unsupported**, исполняемый профиль не создан.

Обнаруженные пробелы задают следующий порядок работ:

Обновление: [ALPS/H2](clean-vpn-native-alps.md) и [захват H2](clean-vpn-native-http2-capture.md)
реализованы следующими checkpoint. [Brotli certificate compression](clean-vpn-native-certificate-compression.md)
реализована следующим этапом. Исторический bundle ниже не переоценивается и не
изменяется; полная совместимость этого браузера ещё отсутствует.

1. Certificate compression (ext 27, Brotli/algorithm 2): настоящая bounded
   декомпрессия и проверка handshake при выборе сервером, не raw body replay.
2. ALPS (ext 17613): реализация согласованных H2 settings вместе с фактическим
   H2 поведением. Одного объявления расширения недостаточно.
3. `trust_anchors` (51764 / 0xca34) и ML-DSA signature algorithms (0x0904–0x0906):
   явный контракт с действующей CA/verification policy и тесты ответов сервера.
   Названия сверены с заголовками pinned BoringSSL; их наличие в библиотеке само
   по себе не разрешает их в native-профиле.
4. Session ticket extension 35 и жизненный цикл сессий: отдельные cold/resumed
   правила. В данном cold capture ext35 пустое, это не захваченный session ticket.
5. Явно решить несовместимость политики cipher suites. Браузер предлагает
   static-RSA/CBC (`0x009c`, `0x009d`, `0x002f`, `0x0035`, `0xc013`, `0xc014`),
   которые текущий native контракт запрещает. Их нельзя включать или выкидывать
   молча ради совпадения JA3/JA4. Пока политика прежняя — точное совпадение с
   этим браузерным baseline не заявляется.

В key shares наблюдается X25519MLKEM768 (4588, 1216 bytes) и X25519 (29, 32 bytes).
Эти размеры сохранены в измерении; полные key bytes не сохраняются. Частный CA,
headless/automation flags и endpoint capabilities записаны в отчёте и являются
существенными условиями этого baseline.

```bash
node --test scripts/test-native-browser-capture.mjs scripts/test-native-macos-lab.mjs
```

Тесты проверяют реальные TLS/H2, недоверенный CA, авторизацию capture URL,
дедупликацию, лимиты, истечение времени, неоднозначные серии, unsupported
расширения, фрагментированный ClientHello, усечения и отсутствие сырых секретов
в bundle. Тестовые синтетические сообщения не выдаются за браузерные захваты.

На checkpoint 2026-10-26 также повторно прошли 7/7 native TLS profile tests
(capture roundtrip, CA/name/PSK отказ, combo и reconnect/backpressure). Изменений
в C++ data plane на этом этапе нет; физические Radxa/VPS не затронуты.
