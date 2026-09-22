# План улучшения мимикрии под сохранённый браузерный профиль

Дата: 2026-09-22. Основание: код на HEAD `4bfec57` и [собранный контекст](clean-vpn-context.md). Ниже предложения, а не уже реализованные возможности. Изменений транспортного кода при подготовке этого плана нет.

Параллельно появившийся незакоммиченный `--tls-raw` — отдельный тестовый режим без HTTP/Bearer; предлагаемые изменения browser profile относятся к обычному boring-tls/TLS-пути, не превращают raw-стенд в аутентифицированный VPN.

Решение пользователя от 2026-09-22: динамическое клонирование ClientHello текущего приложения в новое BoringSSL-соединение к exit полностью исключено, включая экспериментальный вариант. Для сохранения поведения индивидуальных HTTPS-соединений выбран приоритет улучшения transparent relay. Этот документ остаётся планом для сохранённых профилей общего TUN-транспорта, а не автоматического per-flow копирования. Динамические поля самого TLS (GREASE, свежие ключи, перестановки) по-прежнему необходимы и не означают отвергнутый режим.

## 1. Цель и модель наблюдателя

Рекомендуемая первая цель: воспроизводить TLS-поведение конкретного Chromium-based browser build на определённой ОС в явно заданном сценарии. Не абстрактный «Chrome», не все браузеры одновременно и не копию одного MD5.

Профиль должен описывать генератор допустимых соединений: стабильные поля, динамические поля, условные расширения, порядок/перестановки и переходы cold → resumed → HRR. Один ClientHello показывает только одно состояние этого генератора.

Разделять уровни проверки:

| Наблюдатель | Что доступно | Приоритет мимикрии |
| --- | --- | --- |
| Пассивный наблюдатель client→exit | IP/TCP, незашифрованный ClientHello, размеры records, направления и времена | TLS layout, GREASE/key shares, SNI/адрес назначения, record/flow shape |
| TLS endpoint или доверенный TLS-терминатор | Также HTTP/2, HPACK, заголовки, семантика запросов | Согласованность TLS + HTTP/2 + HTTP |
| Активный TLS-сервер | Выбирает группы/протокол, запрашивает HRR, использует объявленные extensions | Реально работающие заявленные возможности, не только красивый первый пакет |

User-Agent и HTTP/2 SETTINGS не видны пассивному наблюдателю напрямую внутри исправного TLS. Их всё равно следует согласовать, но для задачи DPI на канале client→exit я бы сначала исправлял видимые особенности ClientHello. Браузерный JavaScript/DOM fingerprint и отпечаток TCP другой ОС этим TLS-профилем не воспроизводятся.

## 2. Наиболее конкретные пробелы текущего кода

| Сейчас | Что улучшить | Зачем |
| --- | --- | --- |
| Экспорт удаляет GREASE, helper явно не включает его | Сохранять GREASE policy и включать генерацию стеком | JA3/JA4 исключают GREASE, поэтому его отсутствие скрывается за совпадением хеша |
| `supported_groups` есть, отдельного управления initial key shares нет | Сохранять groups/order/lengths key_share отдельно и генерировать новые ключи | Supported groups и реально отправленные shares — разные части ClientHello |
| `permute_extensions:true` ставится любому захваченному профилю | Выводить policy из серии захватов и конкретного browser build | Нельзя считать перестановку универсальным правилом всех браузеров |
| Opaque extras добавляются отдельным хвостом | Учитывать их в общем планировании расширений с TLS-ограничениями | «Случайная основная часть + постоянный хвост» отличается от общего browser layout |
| ECH/compression/ALPS могут попасть в raw extras | Использовать штатные механизмы с обработкой ответов; иначе явно unsupported | Реклама extension без реализации ломается при реальном выборе сервером |
| `tls_info.alpn`, versions, часть полей справочные | Сделать capability negotiation и отчёт applied/ignored/unsupported | Не создавать ложное впечатление применения всего JSON |
| SNI принудительно включается вопреки captured flag | Capture по hostname + явная policy `dns-name`/`ip-literal`; пересчитать ожидания | Убрать тихую подмену условий эталонного JA4 |
| Strict JA3 проверяется после `SSL_connect` | Сначала проверять фактически созданный outgoing ClientHello в буфере | Не отправлять заведомо неподходящий первый TLS-пакет |
| UA константа, HTTP/2 настроен на throughput | Общий profile context для TLS/H2/HTTP, отдельные browser/performance режимы | Убрать межслойные противоречия и скрытые env overrides |

## 3. Профиль v2: данные измерения отдельно от исполняемой конфигурации

Я бы разделил три сущности:

1. Capture bundle: исходные измерения и условия; не исполняется как конфигурация.
2. Browser profile: нормализованные правила поведения и заявленные сценарии.
3. Effective profile: результат проверки совместимости с конкретной сборкой helper, CLI и security policy.

Предлагаемая структура полей (не существующий CLI/формат):

| Блок | Содержимое |
| --- | --- |
| `identity` | browser/vendor/full build, OS/arch, capture date, profile ID, provenance; версия не угадывается только по UA |
| `capture_context` | hostname/IP, доверие сертификату, endpoint capabilities, тип запроса, flags, proxy, cold/resumed/HRR, TCP/H3 |
| `tls.static` | ciphers, supported versions/groups, sigalgs13 и sigalgs50 отдельно, ALPN, compression algorithms, параметры ALPS |
| `tls.dynamic` | GREASE policy, extension ordering policy, initial key-share groups/order, session-ID policy, ECH mode, padding/record constraints |
| `tls.scenarios` | Отдельные допустимые правила cold/resumed/HRR; условия присутствия PSK/early_data/других extensions |
| `http2` | Упорядоченные SETTINGS, initial connection WINDOW_UPDATE, stream windows, priority behavior, pseudo-header order, HPACK constraints |
| `http` | UA, headers и порядок для выбранного типа запроса, а не сборная солянка navigation/fetch/WebSocket |
| `expectations` | Нормализованные признаки, допустимые варианты, JA3/JA4 reference values, негативные условия |
| `compatibility` | Версия schema/helper/BoringSSL patches, обязательные возможности и явно разрешённые отклонения |

`random`, приватные ключи, key-share public bytes, PSK binders, cookies/auth, реальные session tickets и TLS secrets не становятся переносимым browser profile. Capture с такими данными — чувствительный лабораторный артефакт с ограниченным доступом, не fixture для публичного Git.

Файл профиля идентифицировать по ID + hash содержимого, не только по имени. Hash — контроль целостности/воспроизводимости, не подпись доверенного издателя. Профили можно обновлять атомарно для новых соединений, но в логах каждого соединения должен оставаться использованный hash.

## 4. Исправить сбор эталона до усложнения helper

Изменения вокруг [`ja3-snif-server.mjs`](../scripts/ja3-snif-server.mjs):

- Снимать профиль через hostname с корректным доверенным сертификатом. Не использовать заход по IP с certificate interstitial как единственный эталон DNS-соединения.
- Добавить режим negotiated h2, сохранив H1. Сейчас сервер предлагает только H1 и не собирает браузерное HTTP/2-поведение.
- Снимать несколько десятков независимых cold handshakes для первого практического baseline, а не перезаписывать один JSON последним GET. Число выборок — инженерный старт, не статистическое доказательство неразличимости.
- Отдельно снимать reconnect/resumption, HRR и поддерживаемые server capability combinations. Для compression/ALPS/ECH понадобится соответствующий тестовый TLS endpoint; текущего Node capture server может быть недостаточно.
- Фиксировать реальную версию установленного браузера и flags из запуска/диагностики. Для Chrome не путать поставляемый Puppeteer Chromium с пользовательским Google Chrome другой версии.
- Сохранять полные структурные поля ClientHello до GREASE filtering: presence/position/length, key-share lengths, session ID length, extension payload schema, TLS record boundaries. Для общей базы хранить редактированный/нормализованный вариант без секретов.
- У H2 сохранять поток кадров после TLS decode до высокоуровневого разбора: обычный `remoteSettings`-объект теряет исходный порядок и часть поведения. Аналогично, распакованные headers не заменяют измерение HPACK.
- Снимать тот же сценарий запроса, который предполагается воспроизводить. Браузерная навигация GET не эталон для бесконечного двунаправленного POST-туннеля.

Для первого этапа ограничить обещание: «cold TLS 1.3 + h2 для browser build X в заданных условиях». Остальные сценарии должны быть marked unsupported, а не автоматически считаться совпавшими.

## 5. BoringSSL: сначала штатные API, затем новые патчи

В уже закреплённом commit BoringSSL есть API для GREASE, initial key shares, ECH GREASE, ALPS и certificate compression. Это проверено по [ssl.h именно этого commit](https://github.com/google/boringssl/blob/a7481f34712bc056a47ab91015536166b3a6cebb/include/openssl/ssl.h). Наличие API не доказывает, что текущий helper его использует.

| Возможность | Предлагаемое подключение | Важное условие |
| --- | --- | --- |
| GREASE | `SSL_CTX_set_grease_enabled` | Значения создаёт стек; не повторять captured GREASE bytes |
| Initial key shares | `SSL_set1_client_key_shares` после настройки supported groups | Реальные свежие ключи, согласованный порядок и реально поддерживаемые группы |
| GREASE ECH | `SSL_set_enable_ech_grease` | Не путать с настоящим ECH, не replay captured payload |
| Настоящий ECH | `SSL_set1_ech_config_list` и корректный retry/verification flow | Только отдельная поддержанная конфигурация endpoint; не косметическое поле профиля |
| Certificate compression | `SSL_CTX_add_cert_compression_alg` | Рабочий decompress callback, ограничения размеров и корректная обработка ошибок |
| ALPS | `SSL_add_application_settings` | Поддержка negotiated settings и согласованность с реальным H2; не произвольный blob |
| Extension permutation | Уже используемый API + profile-specific policy | Сохранять требуемые TLS позиции/ограничения, не сортировать всё подряд |

Chromium сам конфигурирует GREASE, compression, key shares, ALPS и перестановку при создании TLS-соединения; это видно в [SSLClientSocketImpl](https://github.com/chromium/chromium/blob/main/net/socket/ssl_client_socket_impl.cc). Этот код — ориентир для возможностей, не вечный профиль Chrome: для конкретной мимикрии нужен соответствующий revision/build и его измерения.

Патчи, которые действительно могут понадобиться после измерений:

- Общий extension planner: штатные и разрешённые дополнительные extensions участвуют в одном алгоритме порядка; PSK сохраняет обязательное положение, padding и прочие исключения обрабатываются корректно.
- Режим fixed-order для конкретного эталона, если браузер действительно использует фиксированный порядок. Для Chromium с permutation целью остаётся соответствующая вариативность, а не один фиксированный JA3.
- Узкие недостающие layout/padding/record knobs — только для доказанного расхождения с целевым build.

Не предлагать старые/неподдерживаемые ciphers ради красивого JA3 в строгом production-профиле. Если helper не может выполнить заявленный алгоритм или обработать выбранное сервером расширение, profile compiler должен отказать или явно пометить лабораторный `advertise-only` режим. Безопасность TLS не ослабляется ради совпадения.

## 6. Проверка профиля до отправки ClientHello

Сейчас message callback считает отпечаток, а strict rejection происходит после завершения TLS handshake. Предлагаемая схема:

```text
profile → validate capabilities → configure SSL
        → SSL_do_handshake через буферизующий BIO
        → собрать реальный первый ClientHello/flight этого SSL-объекта
        → проверить нормализованные признаки
           ├─ mismatch: остановить, не отправлять ClientHello
           └─ match: выпустить буфер в socket, продолжить тот же handshake
```

Важно: не создавать второй SSL-объект после проверки «пробного» — у него будут другие random/GREASE/permutation. Не переписывать сформированный ClientHello постфактум: TLS transcript должен соответствовать реально отправленным сообщениям. Использовать bounded buffers, timeout и понятную обработку WANT_READ/WANT_WRITE. TCP connect сам по себе может предшествовать проверке; обещание здесь именно о неотправленном несовместимом ClientHello.

Сравнивать не весь пакет побайтно, а профильные ограничения:

- Точные упорядоченные списки там, где порядок стабилен: cipher suites, versions, groups, sigalgs, ALPN.
- Extension presence, ordering policy, длины и семантические поля каждого поддержанного расширения.
- GREASE slots/policy вместо буквальных случайных значений; key-share groups/lengths вместо публичных ключей.
- SNI binding к выбранному hostname, не буквальное повторение домена capture server.
- Отдельные правила для HRR ClientHello2 и resumed ClientHello; нельзя применять cold template ко всем состояниям.
- JA3/JA4 — дополнительные измерения, не единственный критерий. Не нормализовать все списки сортировкой: так можно скрыть реальное расхождение.

Структурированный результат сравнения: `applied`, `unsupported`, `overridden`, `mismatch`, путь поля, expected/actual и причина допустимости. Например: `tls.key_shares[0].group mismatch`, а не только «MD5 другой». В stdout data channel такие события не вставлять: отдельный IPC control fd либо чётко отделённая предварительная фаза протокола.

Предлагаемые режимы: `observe` (лог), `strict-compatible` (семантика и browser policy), `strict-fixed-layout` (только для поддержанного фиксированного эталона). Все названия новые; сейчас такого CLI нет.

## 7. HTTP/2 и HTTP: один effective profile на все слои

Изменения в `establishCleanVpnOverH2`, `resolveCleanVpnHttp2Settings`, `applyCleanVpnHttp2ConnWindow` и H1 request builder:

- Передавать один immutable profile context, использованный helper; выбирать UA из него, а не из `TLS_VPN_USER_AGENT`.
- Поддержать измеренные SETTINGS и connection WINDOW_UPDATE. Сейчас 16 MiB stream initial window, 1 MiB max frame и 128 MiB connection window выбраны как throughput-настройки, не browser baseline.
- Псевдозаголовки, обычные headers, приоритеты и HPACK проверить на реальном wire. Node предоставляет настройки H2, но нужный порядок/кодирование нельзя считать воспроизведёнными по виду JS-объекта. Для доступных knobs см. [Node HTTP/2 API](https://nodejs.org/api/http2.html).
- Разделить режимы browser fidelity и maximum throughput. Env overrides не должны молча ломать профиль: отказ в strict либо явно зафиксированное отклонение. Уменьшение окон/изменение batching может стоить скорости — это измеряемый trade-off.
- `sec-ch-ua*`, `sec-fetch-*`, Accept и другие headers добавлять только для соответствующего типа запроса и версии браузера. Не копировать navigation headers в произвольный POST; не имитировать поддержку контентного кодирования, которое клиент не понимает.
- H1-переход после GET к raw binary tunnel не станет обычным браузерным HTTP от замены UA. Его нужно отдельно маркировать как compatibility transport или менять прикладную схему по отдельному проекту.

Не начинать с самописного HTTP/2 стека. Сначала измерить разницу и пределы Node/nghttp2. Если конкретный обязательный wire-параметр недоступен, выбирать явно: принять отклонение, добавить узкую нативную HTTP/2-часть или использовать настоящий браузерный транспорт.

Сам бесконечный двунаправленный POST не следует считать точной моделью браузерного fetch. При требовании настоящей браузерной семантики лучше проектировать соответствующий канал (например, аутентифицированный WSS через браузер), а не обещать исправить всё одними SETTINGS.

## 8. Resumption и состояние между соединениями

Текущий helper запускается на одно соединение, полноценного browser-like session lifecycle нет. Сначала cold profile, затем отдельный этап:

- Получать реальные session tickets/SSL_SESSION от exit, хранить ограниченный cache на клиенте и использовать их для reconnect. Captured browser tickets не переносить.
- Cache разделять по профилю, назначению/SNI, ALPN, trust policy и идентичности авторизации; ограничить TTL/размер, очищать при смене соответствующей конфигурации.
- Post-handshake NewSessionTicket требует control IPC после начала передачи plaintext: отдельный fd или иной явно спроектированный канал, не JSON посреди VPN-пакетов.
- Не логировать session secrets. Предпочесть memory-only cache; если нужна персистентность — отдельная модель хранения секретов, не общий JSON-профиль.
- Проверять resumed fingerprint отдельно; при отказе resumption сервером корректно делать full handshake.
- Не включать 0-RTT для VPN по умолчанию: нужны отдельная replay-модель и допустимая семантика данных. Для похожести первого этапа это не обязательная жертва безопасности.

## 9. Проверки, доказывающие улучшение

Добавить сравнительный стенд browser↔helper на одном контролируемом endpoint и независимый TLS/JA4 decoder. Текущие JS+C++ реализации могут повторять одну ошибку; особо проверить расчёт JA4 при наличии одновременно ext 13 и 50.

Минимальная матрица:

| Проверка | Критерий |
| --- | --- |
| Повторные cold handshakes | Все стабильные признаки совпали; динамические меняются по ожидаемой policy, а не заморожены |
| Сохранение/загрузка профиля | Capture → normalize → compile → helper не теряет обязательные поля молча |
| Преднамеренный mismatch | Strict прекращает передачу до первого ClientHello; observe даёт field-level diff |
| Negotiated extensions | Сервер реально выбирает объявленные compression/ALPS/группы — handshake и обмен данными успешны |
| HRR | ClientHello2 корректен; профиль и криптография не ломаются |
| Session resume/reject/expiry | Корректные fingerprints и безопасный fallback; нет переносимости сессии между несовместимыми профилями |
| CA/hostname/PSK negative tests | Мимикрия не отключила аутентификацию; wrong trust/имя/ключ отвергаются |
| H2 | Измерены порядок/значения SETTINGS, WINDOW_UPDATE, headers/HPACK, согласованы ALPN/ALPS |
| Regression | Старые non-profile подключения работают; bounded memory, reconnect и shutdown проверены |
| Performance | Измерены throughput, latency, CPU/RAM и overhead в profile/performance режимах |

Report должен содержать browser build, helper build + patchset, profile hash, Node version, capture scenario, слой совпадения и список исключений. Результат «TLS cold соответствует профилю» честнее и полезнее, чем зелёное «полностью Chrome».

CI для целевого native job должен падать при отсутствии helper вместо успешного SKIP всех нативных тестов. Лёгкий JS-only job можно сохранить отдельно. Профили и golden fingerprints обновлять осознанно с diff, не автоматически принимать каждый новый хеш как правильный.

## 10. Практический порядок работ

1. **Измеримый baseline:** сборка helper + обязательные native tests; один конкретный browser build, hostname capture, cold h2, серия samples, независимая сверка.
2. **Schema v2 и effective profile:** provenance, capabilities, GREASE/key-share metadata, явные overrides и field-level diff; migration v1 с отчётом ограничений.
3. **Наибольший TLS-эффект:** GREASE, fresh key shares, штатный ECH GREASE, управляемые ALPN/versions; убрать replay динамических blobs. Compression/ALPS — только вместе с работающей семантикой.
4. **Strict до wire + extension layout:** buffered BIO gate, constraints на порядок, корректное включение extras, негативные тесты.
5. **Согласованность H2/HTTP:** UA, SETTINGS/windows, measured headers/HPACK; явный выбор fidelity vs throughput.
6. **Session lifecycle:** resumption, HRR coverage, затем record/flow-shape измерения. Не добавлять случайный padding/jitter без целевого baseline: собственная случайность тоже может стать отличительным признаком.

Для первой реализации я бы выбрал пункты 1–3 с узким обещанием cold Chromium TLS, затем пункт 4. Это даст более содержательное улучшение, чем дальнейшая подгонка одного JA3 opaque-расширениями.

Если конечное требование окажется «реальный browser network stack», отдельная альтернатива — усилить `ws-chrome` с корректным WSS и удалённой авторизацией. Это другой транспортный проект: обычный browser JS не получает текущий TLS exporter, поэтому нельзя просто перенести туда существующий v2 Bearer или незаметно заменить его менее строгой схемой. Для Firefox/Safari одного профиля поверх BoringSSL тоже недостаточно для гарантии полного поведения; начинать следует с отдельной совместимости и измерений.
