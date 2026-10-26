# Измерение HTTP/2 браузера и native

Capture-страница теперь сохраняет реальный начальный H2 prefix и первый
авторизованный запрос. Native engine не менялся: сравнение выполняет отдельный
endpoint, который получает байты по TLS, до обработки их Node/nghttp2.

## Одна команда на Mac

После обычной подготовки native fixture (`--tls-profiles`):

```bash
npm run lab:native:mac -- --http2-capture
```

Команда использует подготовленную Podman VM и кэш образов, запускает 20 свежих
процессов Chromium, затем native fixture-клиент и печатает пути трёх JSON:
браузерный bundle, native bundle и сравнение. Оба измерения проходят в отдельных
контейнерах с `--network=none`, без capabilities, опубликованных портов или
writable mount хоста. Сборка engine автоматически не выполняется: после изменения
C++ сначала запустить `--tls-profiles`. Native bundle содержит hash **фактически
запущенного fixture binary**, а не предположение о его соответствии git HEAD.

В браузере доверие CA добавляется только в NSS одноразового контейнера. Отказ
без CA проверяется перед захватом. Host trust store, DNS, маршруты и firewall не
меняются. Контейнеры удаляются; VM можно остановить `--stop`.

Ручные команды внутри Linux-лаборатории:

```bash
CVPN_BUILD=/lab/worktree/native/clean_vpn/build \
  node scripts/clean-vpn-native-h2-probe.mjs /tmp/native-h2.json \
  fixtures/native-tls-profiles/cold-alps.json

node scripts/clean-vpn-native-h2-compare.mjs BROWSER.json NATIVE.json
```

Probe запускает существующий C++ integration harness с socketpair вместо TUN.
Capture endpoint в явно включённом probe mode измеряет `/clean-vpn` POST и
отвечает **403**. Это ожидаемый отказ: VPN не авторизуется, пакеты не передаются,
системное сетевое состояние не меняется. Обычная capture-страница этот режим не
включает. Публичного VPN exit из capture endpoint не получается.

## Что сохраняется

TLS frontend пересылает шифрованный поток локальному TLS terminator. После
расшифрования bounded observer читает prefix до первого END_HEADERS и передаёт
тот же поток внутреннему cleartext H2 endpoint по loopback. Node декодирует HPACK,
а `rawHeaders` даёт порядок декодированных полей. Собственный HPACK decoder здесь
не написан. Префикс и заголовки связываются по соединению **и stream ID**.

- Порядок и значения SETTINGS, в том числе неизвестные IDs и дубли как измеренные
  данные. Они не разрешаются автоматически в native profile.
- WINDOW_UPDATE и stream ID; порядок, flags и размеры кадров до END_HEADERS.
- Размер HPACK block, padding и priority внутри HEADERS, включая CONTINUATION.
- Порядок известных имён заголовков. Неизвестные имена заменяются `<other>`.
- Значения только из фиксированного allowlist: User-Agent, Accept*, client hints,
  Sec-Fetch*, Priority, Content-Type, метод/схема и Upgrade-Insecure-Requests.

Значения Authorization, Cookie, URL, authority, Origin и Referer не экспортируются.
HPACK bytes, DATA, TLS secrets и ключевой материал не сохраняются. Размеры кадров
могут отражать длину скрытых полей. Публичные header values — тоже метаданные:
например, User-Agent и Accept-Language видны в скачанном bundle.

Лимиты observer: 64 KiB prefix после preface, 16 KiB frame payload, 32 кадра,
32 SETTINGS entries на кадр, 32 пары заголовков / 8 KiB decoded strings,
512 ASCII-символов на разрешённое значение. Суффикс после первого END_HEADERS
не накапливается. Нарушение формата/лимита даёт unavailable, не частичный success.

Если перед корректным GET на соединении уже были другие запросы, TLS можно
сохранить, но H2 получает `accepted-request-is-not-first`. Reload не создаёт
новый cold sample. ALPS на Node capture endpoint **не согласовывается**: здесь
измеряется обычный H2 path при fallback. Negotiated ALPS проверяется отдельно
[нативным ALPS стендом](clean-vpn-native-alps.md).

## Фактический checkpoint

[Chromium 156.0.8078.47, Linux ARM64, 20 fresh-process samples](../fixtures/native-browser-captures/chromium-linux-arm64-156.0.8078.47-h2.json)
сопоставлен с [6 native соединениями synthetic cold-alps](../fixtures/native-browser-captures/native-cold-alps-h2.json).
TLS: 20/6 разных JA3 из-за permutation, по одному JA4 на каждой стороне.
Сравнение H2: **different**, ни профиль, ни production-настройки не изменены.

| Измерено | Chromium | Исследованный native профиль |
| --- | --- | --- |
| SETTINGS IDs по порядку | 1, 2, 4, 6 | 1, 2, 3, 4, 6 |
| Header table size | 64 KiB | 8 KiB |
| Initial stream window | 6 MiB | 512 KiB |
| Connection window после initial WINDOW_UPDATE | 15 MiB | 768 KiB |
| Max header list size | 256 KiB | 4 KiB |
| Псевдозаголовки | method, authority, scheme, path | method, path, scheme, authority |
| User-Agent | HeadlessChrome/156 | отсутствует |
| HEADERS priority | exclusive, dependency 0, weight 256 | отсутствует |
| HPACK block bytes в этой серии | 473 | 56 |

Это значения **конкретного синтетического профиля**, не всех режимов native.
GET-навигация и бесконечный POST-туннель имеют разные прикладные контракты:
копирование browser navigation headers в POST не обеспечит браузерную семантику.
Размеры HPACK зависят также от скрытых URL/токенов/authority; их совпадение или
различие не доказывает эквивалентность encoder strategy.

Сохранённый UA сообщает Linux x86_64, хотя реальная лабораторная архитектура ARM64.
По UA нельзя подтверждать архитектуру. Условия headless, private CA и automation
flags сохранены в bundle; это не измерение обычного пользовательского Chrome.

**31/31 тест**, реальные Chromium/native прогоны и полный запуск общей команды
прошли. [Итоговый отчёт](../fixtures/clean-vpn-native-http2-capture-report.json) содержит
сравнение всех вариантов, hashes и результаты проверок. Comparator проверяет
content checksum, когда он есть; checksum не является подписью. Старый TLS-only
bundle сравнивается как incomplete. Даже matched-prefix не выставляет
`browserEquivalent:true` и не активирует профиль.

## Следующий шаг

Зафиксировать поддерживаемую цель и политику совместимости. Измеренный Chrome
просит окна и header limit выше текущих native caps; их нельзя молча обрезать и
называть точной мимикрией. Нужно отдельно решить бюджет памяти/flow control,
контракт HTTP-запроса и оставшиеся TLS gaps (ML-DSA, trust anchors, tickets,
запрещённые cipher suites), затем повторить тот же внешний capture/comparison.
