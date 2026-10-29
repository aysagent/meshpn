# Native TLS profiles: первый ограниченный контракт

Опциональный сохранённый ClientHello-профиль для C++ client `boring-tls` и
Boring-ветки `combo-tls`. Это **экспериментальный cold TLS профиль**, не полная
мимикрия браузера. `browser_profiles:false` сохраняется; отдельная capability
`experimental_tls_profiles` описывает доступный этап. Физические узлы этим
этапом не меняются.

## Применение

В client engine JSON добавляется абсолютный `tls_profile_path`. Для combo поле
помещается внутрь `boring`. Exit и transparent-ветка это поле не принимают.
Например, в существующей client-конфигурации:

```json
"tls_profile_path": "/etc/clean-vpn/profiles/my-cold-profile.json"
```

Профиль читается один раз при запуске, максимум 16 KiB, regular file без symlink.
Изменение файла не меняет уже работающий engine: необходим управляемый restart.
Перед запуском:

```bash
native/clean_vpn/build/clean-vpn-engine --check-config /absolute/client.json
```

Проверка не создаёт TUN/listener и не отправляет пакеты. Она применяет настройки
к BoringSSL, генерирует одноразовый ClientHello в memory BIO и проверяет его.
При успехе `tls_profile` содержит ID, SHA-256 канонического JSON (не подпись),
pinned BoringSSL revision, настройки и ограничения. Неподдержанный/несовместимый
профиль отклоняется. Неизвестные поля не игнорируются. Старый helper schema v1
**не** принимается как новая схема автоматически.

Каждое реальное соединение получает новый SSL object, свежие random и key shares.
Его первый ClientHello также формируется в memory BIO и проверяется до отправки
TLS-байтов. После проверки отправляются именно эти байты с сохранением TLS
transcript. CA/hostname и exporter-bound PSK остаются действующими. Negotiated
ALPN должен соответствовать `http_version`; [доступны H2 и HTTP/1.1](clean-vpn-native-http1.md).
Профиль не меняет маршруты, DNS или firewall.

## Схема

Примеры — [cold-h2](../fixtures/native-tls-profiles/cold-h2.json),
[cold-modern](../fixtures/native-tls-profiles/cold-modern.json) и
[cold-mldsa](../fixtures/native-tls-profiles/cold-mldsa.json).
Все **синтетические**, не захваты Chrome/Firefox и не эталоны конкретного browser build.

- `schema:1`, `kind:clean-vpn-native-tls-profile`, ID и `scenario:cold` обязательны.
- TLS 1.3 обязателен; допускается явное предложение TLS 1.2. TLS 1.0/1.1 запрещены.
- TLS 1.3 ciphers задаются через уже существующий патч BoringSSL. Для TLS 1.2
  разрешены только реализованные ECDHE AES-GCM/ChaCha20; static-RSA/CBC запрещены.
- Groups, initial key-share groups и signature algorithms применяются штатными
  API стека. Unsupported IDs, дубли и неверный порядок shares отклоняются.
  [ML-DSA 44/65/87](clean-vpn-native-mldsa.md) включаются явно в signature algorithms;
  trust-anchor extension пока запрещено до реализации выбора цепочки/retry.
- ALPN: `h2`, `h2,http/1.1` либо `http/1.1`. Native реализует обе версии;
  для смешанного профиля разрешение выбора H1 задаётся `http_version:"auto"`.
  ALPN сохранённого профиля не переписывается. ALPS поддержан только для H2.
- GREASE, permutation, ECH GREASE, запросы OCSP/SCT включаются API BoringSSL.
  ECH GREASE не шифрует реальный SNI. Запрос OCSP/SCT не означает самостоятельную
  политику обязательной проверки stapled response/CT.
- `extension_types` — обязательные типы без GREASE. При `permute_extensions:false`
  проверяется порядок, при `true` — состав. Произвольный фиксированный порядок
  не реализован: несовпадение с BoringSSL отклоняется до wire.
- `optional_extension_types` — `[]` или `[21]`. Только padding может быть явно
  необязательным; если присутствует, он должен идти последним. Из-за переменного
  размера ECH GREASE стандартный BoringSSL padding может появляться не всегда.
  Наблюдатель сохраняет фактический тип 21 и фактические JA3/JA4, не прячет отличие.
- Raw extension bodies, random, captured public/private key bytes, tickets,
  PSK/binders, ранние данные, UA и HTTP settings в исполняемой схеме отсутствуют.
  Brotli certificate compression включается отдельным `certificate_compression:[2]`
  вместе с ext27; [реализация и лимиты](clean-vpn-native-certificate-compression.md).
  Отсутствие поля/`[]` сохраняет прежнее поведение. ALPS, ext50 и resumption пока не поддержаны.

Длина SNI и условия захвата могут менять padding; пример для localhost нельзя
без проверки считать подходящим для любого имени exit.

## Независимое наблюдение и нормализация

Инструмент читает TLS record bytes первого ClientHello, **не pcap и не логи engine**:

```bash
node scripts/clean-vpn-native-profile-observe.mjs PROFILE.json TLS_RECORDS.bin
```

Выход: фактические поля, отличия по полям, JA3/JA4, длины key shares/session ID.
Секреты, key-share bytes, random и SNI не выводятся. Exit code 0 означает совпадение
проверяемых полей, 2 — mismatch, 1 — некорректный ввод. Это не полная TLS/browser
эквивалентность и не подтверждение корректности произвольного профиля в engine.

Для кандидата из захвата все политики выбираются явно:

```bash
node scripts/clean-vpn-native-profile-observe.mjs \
  --candidate my-capture permuted optional grease TLS_RECORDS.bin > candidate.json
```

Параметры после ID: `fixed|permuted`, `exact|optional` padding, `disabled|grease`
ECH. Нельзя автоматически считать любой ECH extension GREASE: это заявленное
условие захвата. `candidate.json` разделяет измерение и `profile`. При известной
несовместимости `status:unsupported`, `profile:null` и перечислены причины.
При `candidate` поле `profile` можно сохранить отдельным JSON, затем обязательно
проверить engine `--check-config` с целевыми SNI/CA. Например, поддержка группы
окончательно определяется именно native stack. Кандидат ещё не applied profile.
Политики из одного образца не выводятся; browser build/provenance нужно хранить
на уровне будущего реестра capture bundles, не выдумывать из JA-хеша.

В лабораторном тесте независимый TCP observer пересылает неизменённые TLS bytes
между C++ client и C++ exit, записывает первый ClientHello, сравнивает его с файлом
и считает JA3/JA4 отдельной JS-реализацией. Генерация и проверка IP-пакетов остаются
в C++ fixture. Наблюдатель — только тестовый компонент, в transport его нет.

## Проверки и продолжение

```bash
# macOS: cached Linux build + CTest + real TCP/profile/auth regressions
npm run lab:native:mac -- --tls-profiles

# Linux с готовой сборкой
node --test --test-concurrency=1 scripts/test-native-tls-profile.mjs
```

Тесты охватывают strict schema/prewire mismatch, реальные packet handshakes,
свежие random и X25519 key shares, фиксированный и permuted ClientHello, ECH GREASE, roundtrip
capture/profile, HRR с пустыми initial shares, CA/name/PSK rejection и Boring-ветку
combo. Profiled client также проходит reconnect/blackhole/backpressure с проверкой
числа открытых дескрипторов и свежести ClientHello. Отдельный C++ decoder mutation
test можно запускать с ASAN/UBSAN.
HRR-проверка подтверждает работоспособность handshake и обмена, **не** соответствие
ClientHello2 браузерному эталону. Resumption остаётся отключённым, а не считается
прошедшим. Производительность profiled режима пока не измерялась.

Результат этого этапа и границы проверок:
[лабораторный отчёт](../fixtures/clean-vpn-native-tls-profile-report.json).

Следующий реализованный checkpoint: [страница и серия браузерных захватов](clean-vpn-native-browser-capture.md).
20 реальных Chromium cold-сеансов сохранены как unsupported bundle с конкретными
пробелами; исполняемый профиль этого браузера пока не создан.
Остаются семантическая поддержка недостающих browser extensions, browser-profile
registry, H2/HTTP согласованность и session lifecycle. Старые настройки
helper не переносятся как opaque extras для достижения красивого JA-хеша.
