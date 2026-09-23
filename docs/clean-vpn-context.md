# Контекст clean-vpn и транспортных экспериментов

Срез: 2026-09-22, HEAD `4bfec57`. Это база контекста для дальнейшей работы, а не полный аудит безопасности или сертификат production-ready.

При финальной сверке появились параллельные незакоммиченные изменения в `device/` и `scripts/clean-vpn.js`. Они не принадлежат этой работе и не редактировались. Новый `--tls-raw` учтён ниже отдельно по прочитанному diff; остальные выводы относятся к исследованному срезу, не к законченной проверке параллельной разработки.

Область: `scripts/clean-vpn.js`, его библиотеки, TLS/браузерные профили, нативный BoringSSL-helper, классификатор, связанные планы и эксплуатационные скрипты. Реализация mesh VPN в `src/` намеренно не исследовалась. Существующие результаты в `device/` не менялись.

Источник истины о реализации — код; Markdown часто содержит предыдущие архитектуры и ещё не выполненные предложения. Ниже отдельно обозначены реализованное, ограничения по статическому чтению и фактически выполненные проверки.

Конкретные предложения по развитию сохранённых браузерных профилей вынесены в [план улучшения мимикрии](browser-profile-mimicry-plan.md): schema v2, GREASE/key shares, штатные API BoringSSL, проверка до отправки ClientHello, HTTP/2 и критерии приёмки.

### Принятое направление: transparent вместо динамического клонирования

Решение пользователя от 2026-09-22: полностью исключить вариант, при котором ClientHello каждого перехваченного приложения автоматически становится профилем нового BoringSSL TLS-соединения к exit. Не оставлять его экспериментальным режимом или пунктом реализации.

Для индивидуальных HTTPS-соединений приоритет — улучшение transparent/enc-SNI relay с сохранением настоящего TLS приложения. Сохранённые BoringSSL-профили общего TUN-транспорта этим решением не отменены. Речь о relay-ветке, в том числе внутри combo-tls, а не о признании безопасной raw TUN-ветки standalone transparent-tls.

Кандидаты на следующий отдельный этап исходного аудита: корректность ClientHello2/HRR и ECH, сохранение TLS record layout, защита route metadata от replay, лимиты/таймауты/backpressure, политика relay-направлений, приватность логов и end-to-end тесты. Последующие реализованные части отдельно зафиксированы в разделах 13–30; остальные пункты не следует считать выполненными.

## 1. Для чего существует этот контур

[`clean-vpn.js`](../scripts/clean-vpn.js) — самостоятельный Linux client↔exit VPN и стенд сравнения транспортов без mesh/onion/multipath. Из простого TUN-моста он вырос в отдельный контур для проверки производительности, NAT traversal, TLS-аутентификации и противодействия распознаванию транспорта.

Здесь решаются разные задачи, которые нельзя смешивать:

- Доставка IPv4 между клиентом и exit через разные носители.
- Конфиденциальность и допуск клиента: TLS/DTLS, проверка сертификата, PSK.
- Сходство с браузерным TLS: захват ClientHello, JSON-профиль, BoringSSL-патчи, сравнение отпечатков.
- Сохранение исходного HTTPS приложения: transparent/enc-SNI relay без завершения TLS на exit.
- Наблюдение за типами трафика для будущего выбора транспорта: отдельный классификатор.

Шифрованный транспорт не обязательно аутентифицирует клиента. Аутентифицированный VPN не обязательно похож на браузер. Совпадение JA3/JA4 не означает полное совпадение протокольного поведения или неразличимость для DPI.

## 2. Карта файлов

| Файл/группа | Назначение |
| --- | --- |
| [`clean-vpn.js`](../scripts/clean-vpn.js) | CLI, TUN, маршруты/NAT, транспортные реализации, TLS auth, Chrome bridge, reconnect и batching |
| [`tls-clienthello-ja3.mjs`](../scripts/lib/tls-clienthello-ja3.mjs) | Разбор первого ClientHello из TCP/TLS records; JA3 и внутренний sorted-JA3 |
| [`tls-clienthello-ja4.mjs`](../scripts/lib/tls-clienthello-ja4.mjs) | JA4/JA4_r для TLS поверх TCP и диагностический альтернативный вариант |
| [`ja3-snif-server.mjs`](../scripts/ja3-snif-server.mjs) | TLS-сервер захвата браузерного ClientHello и экспорта профиля |
| [`boring-tls-clienthello-profile.mjs`](../scripts/lib/boring-tls-clienthello-profile.mjs) | Схема, валидация, экспорт и преобразование JSON-профиля для helper |
| [`helper_main.cc`](../native/boring_tls/helper_main.cc), [`CMakeLists.txt`](../native/boring_tls/CMakeLists.txt) | Изолированный TLS-клиент, patched BoringSSL, IPC, измерение реально отправленного ClientHello |
| [`transparent-tls-enc-sni.mjs`](../scripts/lib/transparent-tls-enc-sni.mjs) | AEAD-кодирование маршрута в SNI, base62, сроки и ограничения hostname |
| [`transparent-tls-ch-rebuild.mjs`](../scripts/lib/transparent-tls-ch-rebuild.mjs) | Замена SNI с пересчётом длин ClientHello и TLS record |
| [`transparent-tls-runtime.mjs`](../scripts/lib/transparent-tls-runtime.mjs) | HTTPS intercept, восстановление SNI, маршрутизация relay, логи |
| [`traffic-classifier.js`](../scripts/traffic-classifier.js), [`traffic-routing-rules.json`](../scripts/traffic-routing-rules.json) | Самостоятельное pcap-наблюдение и эвристическая классификация потоков |
| [`autostart/README.md`](../scripts/autostart/README.md) | Уже существующие systemd-установка и kill-switch |
| [`probe.js`](../scripts/probe.js) | Активные TLS/HTTP-пробы; лабораторный клиент с отключённой проверкой сертификата |
| [`dev-print-boring-tls-ja3.mjs`](../scripts/dev-print-boring-tls-ja3.mjs) | Захват текущего JA3 helper для обновления эталонов smoke-тестов |

Скрипты `test-*-throughput.js` сравнивают сырые UDP/WS/WebRTC и node-datachannel. `check-webrtc-path.js` — диагностика direct/TURN. Часть старых утилит импортирует `werift`, которого нет в текущем `package.json`; они не являются гарантированно рабочими тестами актуального clean-vpn. В старой диагностике также встречаются встроенные настройки TURN и локальный debug-collector: перед запуском проверять конфигурацию и назначения соединений.

`stepwise-test*.js` добавляют слои Packet/crypto/onion из `src/`; изучение этих слоёв оставлено за рамками. `docs/linux-client-routing.md` и большая часть `docs/PERFORMANCE_DEBUG.md` описывают основной mesh, их параметры нельзя механически переносить в clean-vpn.

## 3. Общая механика clean-vpn

- Linux, TUN через N-API addon `native/tun_linux`; сборка `npm run build:tun-linux`. `postinstall` допускает ошибку сборки, поэтому успешный npm install не доказывает наличие addon.
- Фиксированная пара IPv4: exit `10.99.0.1`, client `10.99.0.2`, MTU 1400. Это не многопользовательский VPN-сервер с выдачей адресов и независимой авторизацией клиентов.
- Потоковые транспорты: `uint32_be(length) + raw IPv4 packet`. WS/UDP/DataChannel используют границы сообщений/датаграмм.
- Есть batching TUN и TCP frames, обработка backpressure, лимиты/сброс очередей и reconnect. Текущий TCP batch по умолчанию 8192 байт; настройки `CLEAN_VPN_FRAME_BATCH_BYTES` и `CLEAN_VPN_FRAME_BATCH_FLUSH_MS`.
- Exit включает forwarding и NAT. `setupExitNat` ставит scoped FORWARD-правила в начало цепочки; это важно после недавней проблемы с преждевременным firewall REJECT/RST.
- `--split-default` использует два IPv4 `/1`; exit и служебные адреса обходят туннель, частные сети остаются доступны напрямую. DNS через локальный LAN resolver также может идти вне VPN.
- IPv6-туннеля нет. Без отдельно проверенного ограничения IPv6 это не полный dual-stack VPN.
- Для WebRTC/punch есть обходные маршруты инфраструктуры и отложенное включение default routing. Поддержан LAN-клиент/шлюз через `--client-lan-subnet`.
- `--keep-alive=N` — в том числе таймер бездействия с отключением и ленивым переподключением, а не только heartbeat. У QUIC нет той же схемы lazy reconnect. Нельзя интерпретировать этот флаг как универсальную защиту от idle timeout CDN.
- `--ws-server` и `--signaling`/`--signalling` определяют сторону слушателя независимо от роли client/exit. Имя переменной `wss` означает WebSocketServer, не обязательно защищённый `wss://`.

Последние коммиты этого среза касаются TCP/UDP batching, socket burst stalls, packet tracing и приоритета exit forwarding rules. Это активная разработка, а не замороженный релиз.

## 4. Транспорты: защита и эксплуатационная готовность

Оценка относится к текущему коду и открытому Интернету, без подразумеваемых внешних SSH/VPN/firewall-обёрток. «Условно пригоден» означает кандидат для контролируемой личной эксплуатации после проверок, не безусловную гарантию безопасности.

| Тип | Что реально защищает | Вывод |
| --- | --- | --- |
| `tls` | TLS 1.3, CA/hostname verification, PSK Bearer, exporter channel binding v2 | Наиболее подготовленный базовый вариант; остаются legacy auth, routing/IPv6/операционные ограничения |
| `tls --tls-raw` (параллельный незакоммиченный diff) | TLS 1.3, затем raw IPv4 framing; без Bearer/HMAC и требования клиентского сертификата | Тестовый exit-режим; не наследует авторизацию обычного `tls`, не для открытого production |
| `boring-tls` | Та же TLS/auth-схема, клиентский patched BoringSSL | Условно пригоден при проверенной сборке; мимикрия экспериментальна, нативный fork требует сопровождения |
| `combo-tls` | TUN через boring-tls; HTTPS отдельно через enc-SNI relay | TUN-ветка защищена, но режим целиком экспериментальный из-за relay |
| `transparent-tls` | Исходный HTTPS остаётся TLS; метаданные маршрута защищены GCM | Не для открытого production: остальной TUN идёт сырым неаутентифицированным TCP |
| `webrtc`, клиент `rtc-chrome` | DTLS DataChannel + PSK-подпись fingerprint при включённом обязательном bind | Защита данных есть; сигналинг/доступность требуют доработки перед публичной эксплуатацией |
| `quic`, `quic-ext` | Шифрование QUIC/TLS, проверка сервера клиентом | Не для открытого production: на exit нет допуска клиента к TUN |
| `tcp` / legacy `socket`, `http` | Сырой поток; у HTTP только вступительный HTTP-обмен | Тестовые: без встроенных шифрования и авторизации |
| `websocket`, `ws-chrome` по умолчанию | Обычный WS; Chrome сам по себе не добавляет TLS | Тестовые в текущем plain-WS режиме; WSS override не добавляет авторизацию exit |
| `udp`, включая punch | Сырые IPv4-датаграммы, отдельные меры для сигналинга | Тестовые: нет защиты data plane, возможна смена peer по чужой датаграмме |

Особенности, важные для этой оценки:

- `boring-tls` по смыслу клиентский; exit обслуживается Node TLS. Текущая exit-ветка также принимает это имя как TLS-вариант.
- `quic` использует экспериментальный `node:quic`; собственная проверка CLI требует Node 25+ и соответствующую сборку/флаг. `quic-ext` использует `@infisical/quic`; `verifyPeer:false` на exit не требует клиентского сертификата. Retry HMAC — не PSK-допуск в VPN. Публичный CA-сертификат не является паролем: посторонний клиент может просто не проверять сервер.
- У WebRTC PSK bind подписывает DTLS fingerprint, но не весь сигналинг. В слушающей exit-ветке новое WS-соединение закрывает прежние соединения и уничтожает активный PeerConnection до проверки bind. Это конкретный риск отказа в обслуживании даже при корректной защите DTLS.
- `seenNonces` ограничен жизнью соединения/сигнальной сессии, не глобальный replay-cache. Не следует обещать абсолютную защиту сигналинга от повторов.
- `rtc-chrome` использует настоящий браузерный WebRTC/DTLS; JSON ClientHello-профиль BoringSSL — другой механизм.
- `ws-chrome` допускает `--ws-chrome-ws-url=wss://...`, но требует подходящей внешней TLS-инфраструктуры. Секрет локального Chrome bridge защищает локальный мост, а не авторизацию удалённого VPN exit.
- `bindOrMigrateUdpServerPeer` принимает смену адреса по входящей датаграмме. Это уже не просто «первый отправитель занимает слот». UDP punch не добавляет шифрование/аутентификацию пакетов туннеля.

## 5. TLS: сертификаты, авторизация, HTTP и прикрытие

Основные точки: `computeTlsVpnBearerToken`, `verifyTlsVpnBearerToken`, `connectCleanVpnTlsClient`, `connectCleanVpnBoringTlsClient` в [`clean-vpn.js`](../scripts/clean-vpn.js).

Реализовано:

- TLS 1.3, ALPN `h2` / `http/1.1`. Для h2 — двунаправленный POST `/clean-vpn`; для H1 — GET с последующим переходом к бинарному потоку.
- Общий 32-байтовый PSK: `clean-vpn-hmac.key`, `--shared-hmac-key`; legacy `quic-ext-hmac.key`/старый флаг ещё принимаются. Exit умеет создавать ключ с mode 0600; клиенту нужна его копия.
- Bearer v2: первые 16 байт HMAC-SHA256 от `"clean-vpn-tls-v2:" || exporter32 || ":" || window`. `exporter32` — сырые байты, не base64. Label — `EXPORTER-clean-vpn-bind`.
- Окно 15 минут, принимаются текущее и соседние ±1. IPC передаёт exporter в base64, но Node декодирует его перед HMAC.
- Имя для проверки сертификата и отправляемый SNI разделены: `--tls-server-name` и `--tls-client-sni`. Корректно переданный частный CA может быть надёжным trust anchor; Let's Encrypt не единственный вариант безопасной проверки.
- Есть SNI dispatch, ответы-прикрытия, ограниченный passthrough к заданному probe upstream и rate limits. Это не доказательство неотличимости сервиса при активном probing.

Ограничения:

- Exit всегда допускает fallback на v1 Bearer без exporter, даже когда exporter доступен. Перехваченный legacy-токен может повторяться в пределах допустимых окон; строгого v2-only режима нет. Это не означает возможность вычислить токен без PSK.
- User-Agent задан константой, не берётся из захваченного профиля. HTTP/2 SETTINGS, окна, framing и долгоживущий поток не воспроизводят поведение Chrome.
- TLS-терминирующий reverse proxy/CDN создаёт две разные TLS-сессии. Прямой перенос текущего exporter-bound auth через такой прокси не работает без пересмотра схемы.
- `--tls-log-bearer` раскрывает токены/exporter в логах; включать только осознанно для диагностики.
- CA-сертификат публичен; PSK и приватный серверный ключ секретны. Эти сущности нельзя смешивать в модели угроз.

## 6. Браузерные профили: capture → JSON → wire

```text
Браузер → ja3-snif-server /ja3-snif → JSON-профиль
                                          ↓ чтение на новом connect
clean-vpn → config IPC → boring-tls-helper + patched BoringSSL → exit TLS
                             ↓ callback исходящего ClientHello
                         реальный JA3/JA4 + profile_vs_wire
```

### Захват и хранение

[`ja3-snif-server.mjs`](../scripts/ja3-snif-server.mjs) снимает исходный ClientHello до TLS termination, принимает HTTP-запрос и возвращает UA, TLS-поля и отпечатки. Сервер предлагает TLS 1.2–1.3 и ALPN H1. По умолчанию слушает `0.0.0.0:8443`, не только localhost; локальный стенд следует явно ограничивать `127.0.0.1`.

`--profile-save-path` атомарно обновляет один JSON через временный файл и rename. Каждый подходящий GET перезаписывает профиль: это не каталог профилей браузеров и не версионированная база. Захват по hostname и по IP может отличаться наличием SNI.

JSON содержит UA, cipher suites, groups, EC point formats, extension types, signature algorithms, некоторые raw extension bodies, TLS-метаданные и ожидаемые JA3/JA4. Профиль перечитывается при новом TLS-соединении, не меняет уже установленную сессию.

### Что действительно управляет helper

- Cipher suites и их wire-порядок, supported groups, списки signature algorithms.
- Наличие ряда расширений (например, OCSP/EMS/session ticket), перестановка расширений и разрешённые opaque extensions.
- SNI/ALPN фактически задаются транспортом; `emit_sni` в JS принудительно true. Захваченный `clienthello_emit_sni:false` не воспроизводится буквально.
- `extension_types` — прежде всего эталон диагностики, не универсальная инструкция «создать все расширения в этом порядке».
- `ec_point_formats`, captured TLS versions/legacy version и UA не означают полного управления соответствующим wire/HTTP-поведением.
- `--boring-tls-profile=NAME` — label/резерв, не встроенный переключатель готовых Chrome/Firefox-пресетов. Рабочая настройка — JSON ClientHello-профиля.

### Нативный процесс и шесть патчей

[`CMakeLists.txt`](../native/boring_tls/CMakeLists.txt) фиксирует BoringSSL на `a7481f34712bc056a47ab91015536166b3a6cebb`, использует C++17 и nlohmann_json 3.11.3. Патчи применяются с проверками маркеров:

1. `tls13-cipher-order`: явный порядок TLS 1.3 suites.
2. `client-signature-algorithms-cert`: добавление extension 50.
3. `client-hello-extra-extensions`: opaque bodies дополнительных расширений.
4. `extra-extensions-emit-dedup`: не дублировать уже созданные стеком расширения.
5. `tls12-cipher-wire-and-ems`: отдельный advertised TLS 1.2 cipher list и управление EMS.
6. `signature-algorithms-clienthello-wire`: точный wire-список ext 13 с повторами отдельно от deduplicated verify preferences; разрешение повторов ext 50.

Один subprocess обслуживает одну TLS-сессию. Сначала `u32be + JSON config`, затем ответ `{ok, alpn, exporter}`, после него plaintext приложения идёт через stdin/stdout; TLS и проверка CA/hostname остаются внутри helper. stderr — диагностика. Есть таймаут запуска и завершение дочернего процесса.

Без профиля helper ограничен TLS 1.3; legacy suites в профиле могут включить диапазон TLS 1.2–1.3, но текущий VPN exit остаётся TLS 1.3. Реклама cipher/extension не равна реализации всей связанной криптографии. Opaque replay, например certificate compression/ECH bytes, не добавляет полноценную поддержку этих протоколов. Динамические stateful extensions исключены из простого replay.

Upstream BoringSSL не обещает API/ABI stability; pinned fork необходимо сопровождать. В CMake `BUILD_TESTING` выключен: сборка helper не равна запуску upstream crypto-тестов. Это следует и из [официальной политики BoringSSL](https://boringssl.googlesource.com/boringssl/+/HEAD/README.md).

### Expected vs actual и пределы совпадения

- JA3 — MD5 упорядоченных списков legacyVersion/ciphers/extensions/groups/pointFormats с удалением GREASE. Порядок влияет на результат; это соответствует [описанию Salesforce JA3](https://github.com/salesforce/ja3).
- `ja3_sorted` — собственная диагностическая нормализация, сортирующая компоненты. Это не канонический JA3 и не замена wire-проверке.
- JA4 содержит признаки версии/SNI/ALPN/числа элементов и усечённые SHA256. Сортировка suites/extensions уменьшает зависимость от перестановок; SNI/ALPN исключаются из списка для canonical JA4_c. Эталон — [FoxIO JA4 specification](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md).
- В репозитории есть также `fingerprint_alt` для отдельного варианта расчёта; его нельзя выдавать за canonical JA4.
- Текущий модуль разбирает TLS ClientHello поверх TCP, а не QUIC Initial. Наличие QUIC-транспортов не означает их поддержку этим анализатором.
- `permute_extensions` по умолчанию true. JS при обычной перестановке не передаёт ожидаемый wire JA3 как обязательный эталон; sorted-JA3 нужен для сравнения наборов.
- `--boring-tls-profile-ja3-strict` требует `permute_extensions:false`. Но выключение перестановки не превращает произвольный captured order в фиксированный порядок BoringSSL.
- Strict mismatch проверяется после успешного `SSL_connect`: ошибочный ClientHello уже отправлен в сеть. Это проверка пригодности соединения, не предварительное предотвращение утечки отпечатка.
- JA4 mismatch диагностический, не строгий запрет. `profile_vs_wire` сравнивает в том числе мультимножества extension types: равные наборы не доказывают равный порядок или payload.
- JS и C++ собирают sigalgs из ext 13 и 50 в порядке появления расширений. Этот случай требует независимой сверки с внешним JA4-анализатором, особенно при перестановке обоих расширений; локальное согласие двух реализаций недостаточно.
- Resumption, HRR, GREASE, key shares, record fragmentation, HTTP/2 и статистику трафика нужно проверять отдельно. Полная мимикрия браузера этим срезом не доказана.

## 7. Transparent TLS и combo: текущий enc-SNI v2

Актуальная архитектура — raw TCP relay с зашифрованным маршрутом внутри SNI, не прежний CVPTX-префикс из части документов.

```text
HTTPS приложения → локальный intercept :8443 → замена SNI на enc-labels.public-name
                 → TCP к exit → GCM decode → восстановление исходного SNI → origin

Остальной IPv4 → TUN → boring-tls (combo) / сырой TCP (transparent-tls) → exit NAT
```

- OUTPUT REDIRECT перехватывает локальный IPv4 TCP/443. Для LAN используются PREROUTING DNAT и второй listener на адресе шлюза. Есть вариант `--tunnel-peer` без этих redirect-правил.
- `SO_ORIGINAL_DST` получает исходное назначение, но зашифрованный маршрут содержит hostname и порт, не исходный IP. Exit заново разрешает имя; при split DNS/CDN это может быть другой адрес.
- Внутри metadata: версия 2, timestamp с допустимым отклонением ±5 минут, порт и hostname. AES-256-GCM, nonce 12 байт, tag 16 байт.
- Ключ выводится HMAC-SHA256 от PSK и `transparent-tls-enc-sni-v2\0`, не HKDF. Blob кодируется case-sensitive base62; suffix сравнивается без учёта регистра. Лимиты DNS label/hostname ограничивают длину исходного имени.
- DNS для выдуманного enc-hostname не нужен: клиент напрямую соединяется с exit. Поэтому нельзя бездумно нормализовать регистр encrypted labels как у обычного DNS-имени.
- На exit combo различает успешно декодируемый enc-SNI relay и обычную TLS VPN-ветку. В transparent остаётся raw IPv4-ветка без auth.
- TLS приложения не завершается на relay. ClientHello восстанавливается перед origin; защищённые TLS records затем пересылаются как есть. У intercepted HTTPS не запускается BoringSSL-helper на каждую сессию: используется ClientHello исходного приложения.

Ограничения по чтению кода, требующие отдельных интеграционных проверок:

- На момент исходного аудита не было replay-cache enc-label. Process-local cache добавлен в разделе 29; привязка metadata к ClientHello transcript, durable/distributed защита и предотвращение гонки первого предъявления не добавлены.
- На момент исходного аудита не было запрета relay-направлений на private/loopback IP; application-level public-unicast policy добавлена в разделе 30. PSK остаётся важной границей доверия. Полноценные per-client/socket квоты и защита от resource exhaustion не завершены.
- На момент исходного аудита очередь `pendingToOrigin` не ограничена, upstream backpressure несимметричен, client ClientHello не имеет явного timeout. Исправлено последующим пакетом в разделе 14.
- На момент исходного аудита переписывается только первый ClientHello, CH2 после HRR раскрывает исходный SNI. Исправление начального TLS 1.3 HRR handshake и его ограничения описаны в разделе 16.
- На момент исходного аудита rebuild склеивает ClientHello в один TLS record. Последующее обратимое сохранение layout с ограничениями описано в разделе 15.
- GREASE ECH сейчас пропускается и покрыт roundtrip-тестом. Работоспособность настоящего ECH этим не доказана: видимый outer SNI может не описывать фактический origin, а исходный destination IP не передаётся.
- HTTP/3/QUIC UDP/443 не перехватывается этой TCP-схемой; в combo он попадает в общий IPv4 TUN.
- На момент исходного аудита `origin_sni` пишется в обычные логи. Последующее исправление скрывает SNI без verbose — см. раздел 14.

Нельзя утверждать, что отсутствие собственного MAC у raw relay позволяет незаметно менять HTTPS payload: TLS имеет Finished и AEAD. Эти гарантии описаны в [TLS 1.3 RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.4). Незащищённость отдельного raw TUN и replay метаданных маршрута — другие проблемы.

## 8. SNI dictionary: ещё план

[`transperent-sni-dictionary.md`](../scripts/transperent-sni-dictionary.md) предлагает сокращать повторяющиеся маршруты до коротких aliases вместо полного enc-SNI. Реализации отдельного dictionary module, sync endpoint или рабочего CLI-флага в просмотренном коде нет.

Текущий enc-SNI stateless. Dictionary потребует согласованного состояния client/exit: аутентифицированной синхронизации, epoch/restart semantics, TTL/eviction, разделения клиентов, обработки miss и fallback на полный маршрут. Кэш классификатора не является этим словарём.

## 9. Классификатор: что уже работает и чего нет

[`traffic-classifier.js`](../scripts/traffic-classifier.js) — самостоятельный pcap-процесс. Он не импортируется в clean-vpn и не переключает его транспорты.

Реализовано:

- IPv4 TCP/UDP flows с нормализованной двунаправленной парой endpoint.
- Небольшое окно статистики: последние 40 пакетов, классификация примерно раз в 3 секунды после минимум 8 пакетов, сглаживание последних 5 результатов.
- DNS UDP/53 A-records → IP/hostname; TLS SNI для TCP/443; HTTP Host на 80/8080; портовые, STUN/RTP и QUIC-подобные признаки.
- Классы `web`, `video`, `voice`, `bulk`, `default`; domain rules из JSON.
- Приоритеты: rule 100 > early strong 80 > cache 60 > statistical 50 > early weak 30 > default 0.
- Destination-cache с TTL 30 минут и пределом 4096, необязательное сохранение на диск.

Ограничения:

- Нет полноценного TCP reassembly: простое накопление TLS bytes до 16 KiB не учитывает sequence/retransmission/out-of-order.
- QUIC Initial не расшифровывается; STUN не обязательно voice, динамический RTP payload type сам по себе не задаёт приложение.
- DNS/shared CDN IP и выбор первого hostname создают неоднозначность. Cache key IP:port не включает protocol, вытеснение не полноценный LRU; приоритет cache выше statistical способен закреплять старую классификацию.
- Flows не имеют полноценного expiry; долгий capture требует проверки роста памяти.
- `--json` не гарантирует чистый NDJSON: периодическая текстовая сводка также идёт в stdout.
- Нет измеренной accuracy/confusion matrix на размеченном наборе и нет интеграции с транспортным scheduler. Проценты confidence — приоритеты эвристик, не доказанная вероятность правильного класса.

## 10. Эксплуатация и расхождения документации

[`autostart/install.sh`](../scripts/autostart/install.sh), [`killswitch.sh`](../scripts/autostart/killswitch.sh), uninstall и README уже существуют. Поэтому пункт старого TODO «сделать systemd» нельзя считать полностью невыполненным. Автоматическое provisioning VPS из [`clean-vpn-AUTOINSTALLER.md`](../scripts/clean-vpn-AUTOINSTALLER.md) — отдельное предложение; `deploy-exit.mjs` нет.

Kill-switch нельзя считать универсально fail-closed: он разрешает ESTABLISHED/RELATED и private ranges; IPv6 пропускается, если ip6tables отсутствует; default tun0 должен соответствовать реально выбранному интерфейсу. Правила перестраиваются неатомарно, цепочки общие, внешние STUN/TURN могут потребовать отдельных разрешений. Остановка сервиса и persist-mode имеют разную политику снятия правил. Нужен отдельный crash/restart/IPv6/DNS тест, а не доверие заголовку скрипта.

| Документ/утверждение | Как читать на этом срезе |
| --- | --- |
| Шапка clean-vpn: «без шифрования/auth» | Верно для ранних raw-транспортов, неверно как описание всех нынешних режимов |
| [`clean-vpn-security-analysis.md`](../scripts/clean-vpn-security-analysis.md), [`clean-vpn-diagrams.md`](../scripts/clean-vpn-diagrams.md), [`transparent-tls-plan.md`](../scripts/transparent-tls-plan.md) | Полезны как история, но CVPTX и ряд оценок безопасности устарели относительно enc-SNI |
| CA как пароль для QUIC | Неверная модель допуска клиента; QUIC exit сейчас не требует PSK/mTLS |
| Enc-SNI KDF называется HKDF | Код использует HMAC-SHA256 |
| В HMAC Bearer входит base64(exporter) | В коде входят сырые bytes exporter |
| [`boring-tls-plan.md`](../scripts/boring-tls-plan.md) описывает четыре патча | В CMake уже шесть |
| [`tls-obfuscation-plan.md`](../scripts/tls-obfuscation-plan.md): helper только будущий крайний вариант | Helper уже реализован; рекомендация ws-chrome сама по себе не обеспечивает auth/WSS |
| [`combo-tls-improvement.md`](../scripts/combo-tls-improvement.md) | Вариант C ближе к текущему enc-SNI; A/B — история вариантов, не параллельно реализованные режимы |
| [`wss.md`](../scripts/wss.md), [`nginx.md`](../scripts/nginx.md) | Архитектурные варианты, не доказательство наличия отдельного production `--type=wss` |
| [`http2.md`](../scripts/http2.md) | H2 уже есть в TLS-ветке; не все предлагаемые меры мимикрии реализованы |
| [`ipv6-plan.md`](../scripts/ipv6-plan.md) | IPv6 остаётся планом, kill-switch не равен IPv6 transport support |
| [`cloudflare.md`](../scripts/cloudflare.md) | Не переносить старые значения timeout/тарифов/условий как актуальные; учитывать TLS termination и смысл keep-alive |

Cloudflare завершает клиентский TLS, но это не «стирает JA3» для наблюдателя на участке client→Cloudflare. Текущая [документация Cloudflare WebSockets](https://developers.cloudflare.com/network/websockets/) говорит об idle timeout, heartbeat и необходимости reconnect при рестартах, а не даёт универсальное правило «все WS живут 100 секунд».

Node `exportKeyingMaterial` существует с 12.17.0/13.10.0, а не только с Node 19; источник — [Node TLS API](https://nodejs.org/api/tls.html#tlssocketexportkeyingmateriallength-label-context). Это не обещание совместимости всего проекта со старыми Node.

## 11. Что проверено в этой сессии

Окружение: Node v24.13.0, нет `node_modules` и собранного `native/boring_tls/build/boring-tls-helper`.

Выполнено без TUN/root routing и внешних сетевых проб:

```bash
node --check scripts/clean-vpn.js
node --check scripts/traffic-classifier.js
node --test scripts/test-tls-clienthello-ja4.mjs scripts/test-transparent-tls-enc-sni.mjs scripts/test-boring-tls-smoke.mjs
```

Результат: syntax checks успешны; 41 тест, 21 pass, 20 skipped, 0 fail. Из успешных: 9 JA4/profile, 11 enc-SNI/rebuild, 1 pure-JS sorted-JA3. Все 20 native smoke-проверок пропущены из-за отсутствия helper. Это не успешная проверка нативной мимикрии.

Не выполнялись npm install, сборка BoringSSL, реальные браузерные захваты, запуск VPN, изменение маршрутов/firewall, тестирование реального exit/DPI, throughput/soak или развёртывание. Синтетический roundtrip не доказывает end-to-end совместимость TLS/ECH/HRR.

## 12. Опорные точки для следующих задач

Не план самовольной доработки, а список проверок, которые не стоит пропускать при соответствующей будущей задаче:

1. Для профилей: собрать pinned helper, выполнить native smoke, захватить конкретные browser/version/OS, сравнить JSON↔helper callback↔независимый pcap-анализатор; отдельно проверить ext 13/50, GREASE, resumption и HRR.
2. Для TLS production hardening: строгий v2-only auth, отрицательные проверки CA/hostname/PSK, crash/reconnect/IPv6/DNS/kill-switch и лимиты ресурсов.
3. Для combo: отдельно принимать TUN-ветку и relay; проверять replay, адреса назначения, bounds/backpressure, HRR/ECH и приватность логов.
4. Для QUIC: сначала явная авторизация клиента, затем эксплуатационная оценка; сертификат сервера эту задачу не решает.
5. Для WebRTC: проверка допуска до вытеснения активного клиента, защита сигналинга и сценарии reconnect/replay/DoS.
6. Для классификатора: размеченные captures, метрики ошибок, управление сроком жизни flows/cache; только затем проектировать интеграцию с выбором транспорта.
7. Для dictionary: отдельный протокол состояния и синхронизации; не считать это небольшой заменой base62 на короткое имя.

Главная рабочая модель: standalone transport lab уже имеет серьёзную TLS/auth-базу и развитую диагностику ClientHello, но browser fidelity, transparent relay, автоматический выбор транспорта и полноценная эксплуатационная безопасность находятся на разных стадиях готовности.

## 13. Последующее дополнение: loopback integration lab

После исходного сбора контекста по запросу пользователя реализован [стенд transparent TLS](../scripts/transparent-tls-lab.md) на одном хосте, без TUN, iptables, root и npm-зависимостей.

- `node scripts/transparent-tls-lab.mjs`: запуск, самопроверка HTTP/1.1 и HTTP/2, затем остановка.
- `node scripts/transparent-tls-lab.mjs --serve`: тот же стенд остаётся доступным для локального curl; точная команда печатается в выводе.
- `node --test scripts/test-transparent-tls-integration.mjs`: реальные loopback-соединения, TLS 1.2/1.3, проверка сертификата, данные, ClientHello/JA3/JA4 в трёх точках, фрагментация и отрицательные сценарии.

В первом пакете стенд использует существующие relay-функции; в runtime тогда добавлен только optional `connectOrigin` для подключения к строго локальному origin. Lab-specific лимиты/idle timeout/ограничение назначения не являются исправлениями production relay. Последующая доработка общего runtime описана ниже.

Проверено на Node 24.13.0: 17 новых интеграционных тестов и 20 существующих JA4/enc-SNI тестов — 37 pass, 0 fail, 0 skipped; отдельно успешен реальный curl через serve-стенд с проверкой сертификата. Это дополняет, а не заменяет ограничения исходного аудита: HRR/ClientHello2, настоящий ECH, resumption/0-RTT и системная TUN-интеграция пока не проверены этим стендом.

## 14. Следующий пакет: bounded I/O transparent relay

Общий runtime client/exit переведён на [RelaySession](../scripts/lib/transparent-tls-io.mjs): первый ClientHello ≤64 КиБ, подготовленная первая запись ≤128 КиБ, абсолютные hello/connect deadlines по 10 с, drain/close deadline 30 с. Входной сокет приостанавливается до connect/записи префикса; исправлен риск потери байтов на client и убрана растущая очередь на exit. Симметричный backpressure, graceful EOF с ограниченным ожиданием, парный teardown и очистка своих listeners/timers проверены отдельно. SNI/enc-SNI в runtime-логах видны только с `ja3Verbose`; обычные ошибки имеют коды `TLS_RELAY_*` без домена назначения.

Подробные границы и параметры — [в документации стенда](../scripts/transparent-tls-lab.md#лимиты-общего-relay-runtime). Не путать с глобальным лимитом памяти/соединений, policy разрешённых origin, replay-защитой или полным аудитом внешнего peek-dispatch: они не реализованы этим пакетом. Idle established connections не ограничены runtime-таймером.

Проверено на Node 24.13.0: 26 новых runtime-регрессий + 17 integration + 20 JA4/enc-SNI = **63 pass, 0 fail, 0 skipped**. Есть настоящий TLS/H1/H2 с выключенными idle-таймерами обвязки и управляемые Duplex для connect/drain stall, отмены, порядка байтов и EOF. Ни native BoringSSL, ни mesh, ни TUN/firewall этим пакетом не затронуты.

После этого пакета приоритетом выбрано сохранение TLS record layout и всех соседних handshake bytes (реализация ниже), затем явная проверка HRR/ClientHello2, resumption/0-RTT и ECH. Динамическое клонирование профиля BoringSSL остаётся исключённым направлением.

## 15. Следующий пакет: обратимый TLS record layout

Rebuild теперь сохраняет число records, их индивидуальные legacy versions и байты после первого ClientHello внутри последнего record. Только record с первым байтом SNI меняет длину на разницу hostname; на exit обратная операция восстанавливает весь исходный префикс, включая границы records. Последующие полные/частичные records остаются нетронутыми. Wire-format enc-SNI не изменён; полная гарантия требует обновлённых client **и** exit.

Неподдержанное изменение размера отклоняется до исходящего connect (`TLS_RELAY_REBUILD`), в частности если выросший record превысил 16 КиБ; fallback с потерей layout не добавлен. Даже валидный исходный record возле предела может не поддерживаться relay. Размер record на участке client→exit отличается от оригинала. Подробнее: [алгоритм, ограничения, совместимость](../scripts/transparent-tls-lab.md#обратимое-сохранение-tls-records).

При стресс-фрагментации найдено квадратичное копирование в `parseFirstTlsClientHelloFromTcpBuf`: накопленный payload склеивался после каждого record. Теперь concat выполняется только один раз после полного сообщения. Это локальное исправление, не полный CPU/DoS-аудит всех анализаторов.

Проверки на Node 24.13.0: **80 pass, 0 fail, 0 skipped** — 19 enc-SNI/rebuild, 9 JA4, 22 интеграционных, 30 runtime. Unit-тесты перебирают все позиции двух-record разреза, однобайтовое/многократное разбиение, соседние handshake bytes, большой ClientHello и границы размеров. На настоящем TLS/H1/H2 проходят разрезы заголовка/SNI и однобайтовые records с отключёнными idle-таймерами стенда. Теперь `assertRelayTrace` сравнивает полный record-префикс побайтово, а не только handshake body и JA3/JA4.

После этого пакета выбран этап HRR/ClientHello2 (реализация ниже). Resumption/0-RTT, настоящий ECH, replay и destination policy остаются незакрытыми пунктами. Mesh/TUN/BoringSSL этим пакетом не менялись.

## 16. Следующий пакет: HRR / ClientHello2

Утечка CH2 воспроизведена настоящим TLS handshake: origin с P-256 вызывает HRR у клиента с X25519:P-256; до исправления HTTP работал, но на exit второй SNI был `localhost`, а не enc-SNI. Теперь [HRR guard](../scripts/lib/transparent-tls-retry.mjs) наблюдает ServerHello, разрешает один HRR и полностью собирает CH2 до отправки. Client использует прежний enc-SNI; exit восстанавливает имя на существующем соединении с origin. CH2 не меняет route и не открывает новое соединение.

Сохраняются records/JA3/JA4 каждого hello, cookie и новый key share. Проверяется соответствие SNI/legacy version/random/session ID исходному CH1. Dummy CCS не отключает guard; второй HRR, неожиданный CH2, подмена identity, переполнение или неполное сообщение закрывают сессию. Для TLS 1.3 запрещён соседний handshake suffix в том же record после CH1/CH2, чтобы не обойти проверку; это дополнительное runtime-ограничение поверх низкоуровневого rebuild.

В каждой фазе ожидания SH1, CH2 и финального SH действует абсолютный `helloTimeoutMs` (10 с); повторные байты/CCS не продлевают ожидание. Guard включается после исходящего connect, использует общие ограничения буферов/backpressure и очищается вместе с сессией. После обычного ServerHello возобновляется raw forwarding; полного TLS validator и обработки TLS 1.2 renegotiation здесь нет. Подробности: [документация стенда](../scripts/transparent-tls-lab.md#tls-13-helloretryrequest--clienthello2).

Проверено на Node 24.13.0: **108 pass, 0 fail, 0 skipped** — 24 integration, 36 runtime, 20 retry-state-machine, 19 enc-SNI/rebuild и 9 JA4. В настоящем H1/H2 HRR проверены CH1/CH2 в трёх точках, идентичность восстановленных records, enc-SNI вместо исходного hostname и ровно один origin connect. Дополнительно покрыты фрагментированные HRR/CH2, cookie, CCS, подмена identity, duplicate HRR, таймауты и backpressure CH2. Сопоставление captures теперь использует random **и** `flight`, поскольку CH2 сохраняет random.

Для устранения wire-утечки обязателен новый client; один новый exit только отклонит уже переданный старым клиентом plaintext CH2. Обновлять следует оба endpoint. Не считать закрытыми resumption/0-RTT, настоящий ECH, replay, destination policy, глобальные квоты или независимые браузерные captures. Mesh/TUN/BoringSSL этим пакетом не менялись.

## 17. Следующий пакет: session resumption без 0-RTT

[Новые реальные тесты](../scripts/test-transparent-tls-resumption.mjs) подтверждают ticket resumption на отдельных TCP-соединениях для TLS 1.2/1.3 и HTTP/1.1/2. Успех проверяется через `isSessionReused()` на обоих TLS endpoints; HTTP-ответ сам по себе не считается подтверждением. Изменений production relay не потребовалось: доработаны lab-обвязка, наблюдаемость и тесты.

Для TLS 1.3 проверены отказ от ticket после ротации ключей origin, полный handshake с выдачей нового пригодного ticket и resumption вместе с настоящим HRR. PSK identities/binders сохраняются побайтово; binder CH2 пересчитывает настоящий TLS-клиент, не relay. Для каждого CH сравниваются восстановленные records/JA3/JA4; равенство cold и resumed отпечатков не требуется. `early_data` отсутствует.

Дополнительно покрыты неверные CA/hostname при полном handshake после отказа от ticket, четыре параллельные сессии, echo и cleanup. При принятом resumption используется прежнее доверие к сессии; отрицательные тесты fallback не доказывают новую проверку сертификата на каждом resumed-соединении.

Lab-клиент получает session state только с `captureSession: true`, из TLS-события `session`, хранит максимум 64 КиБ в памяти и исключает его из JSON результата через non-enumerable свойство. Это чувствительные данные: явное логирование всё ещё возможно; общего session cache и сохранения в browser profile нет. Lab-only `rotateTicketKeys()` и `setOriginGroups()` дают управляемые отказ/HRR без раскрытия ключей. Подробности и границы — [в документации стенда](../scripts/transparent-tls-lab.md#tls-session-resumption-без-0-rtt).

На Node 24.13.0: **120 pass, 0 fail, 0 skipped** — прежние 108 и 12 resumption. Это не покрытие 0-RTT, естественного истечения tickets, всех браузеров или настоящего ECH. Replay, destination policy, глобальные квоты, независимые captures и длительный soak остаются отдельными задачами. Mesh/TUN/BoringSSL этим пакетом не менялись.

## 18. Следующий пакет: настоящий 0-RTT и поздние early records при HRR

[Новый OpenSSL-набор](../scripts/test-transparent-tls-early-data.mjs) проверяет принятие early data, отказ от повторно использованной сессии, малые TLS records, HRR и явную повторную отправку приложением после отказа. Используется настоящий `s_client`/`s_server` с проверкой CA/hostname и включённым origin anti-replay. Это TLS payloads без HTTP-семантики; прежние Node HTTP/1.1/2-наборы остаются отдельно.

Найден и воспроизведён runtime-дефект: HRR уже перевёл guard в ожидание CH2, а ранние records ещё идут в противоположном направлении. Они отклонялись с `TLS_RELAY_RETRY_SEQUENCE`. Исправление пропускает их до начала CH2, не отключая проверку второго hello и не продлевая абсолютный deadline. После начала фрагментированного CH2 и после его окончания до финального ServerHello такие records по-прежнему запрещены. Обновить нужно client и exit; wire-format не менялся.

Детерминированный TCP gate задерживает настоящие encrypted early records до прохождения HRR через оба guard, сохраняя порядок каждого направления. Проверены CH1/CH2, extension 42 только в первом, PSK последним, восстановленные records/JA3/JA4 и прежний enc-SNI. Origin получает принятый early payload точно один раз; отвергнутый не получает, пока приложение явно не отправит его после handshake. Relay не делает автоматический resend.

Lab-only `externalOriginPort` подключает origin tap к фиксированному loopback backend без нового CLI-режима и без ослабления destination pinning. Node-origin counters в этом режиме `null`, его ticket/group controls недоступны. Passive capture ограниченно пропускает opaque records, чтобы не потерять CH2. OpenSSL CLI требует Linux, OpenSSL 3.x и GNU `stdbuf`; секретный session state живёт в приватном временном каталоге (0700/0600) до cleanup, вывод процессов ограничен и не печатается. После SIGKILL runner cleanup не гарантирован.

На Linux с Node 24.13.0 / OpenSSL 3.0.13: **128 pass, 0 fail, 0 skipped** — прежние 120, 3 guard-регрессии и 5 OpenSSL/lab-тестов. Детальные границы — [в документации стенда](../scripts/transparent-tls-lab.md#настоящий-0-rtt-и-пересечение-ранних-данных-с-hrr). Origin anti-replay не означает защиту enc-SNI metadata или exactly-once для нескольких серверов. Максимальные объёмы early data, HTTP early requests и все причины server rejection не проверены.

Следующий этап — совместимость настоящего ECH с enc-SNI и явная политика неподдерживаемых случаев; затем реальные Chrome/Firefox через локальный CONNECT-стенд и независимые captures. Mesh/TUN/BoringSSL и динамическое клонирование профиля этим пакетом не затронуты.

## 19. Следующий пакет: настоящий ECH и явные границы поддержки

[Go crypto/tls fixture](../scripts/fixtures/transparent-ech/main.go) и [Node orchestration](../scripts/test-transparent-tls-ech.mjs) проверяют настоящий принятый ECH, не GREASE. Inner `hidden.ech.test` и outer `public.ech.test` различаются; ECHAccepted подтверждён обоими TLS endpoints, сертификат проверен для inner, HTTP payload проверен по длине/SHA-256. Client/exit не получают ECH private keys; имена теста не резолвятся публичным DNS.

Покрыты HTTP/1.1/2, отдельное resumed-соединение, HRR с однобайтовыми records для обоих outer ClientHello, устаревший ECHConfig с явным новым запросом по аутентифицированным retry configs, origin без ECH и ошибки CA/inner certificate/outer certificate при rejection. Отклонённый handshake не отправляет HTTP и не запускает автоматический non-ECH reconnect в тестовом клиенте. Проверяются ciphertext, восстановленные records/JA3/JA4, скрытое имя не встречается в plaintext captures. Отпечатки относятся к outer hello.

Две структурные runtime-регрессии подтверждают отказ до connect при ECH extension без outer SNI. Текущая политика: opaque passthrough ECH/GREASE с полным восстановлением outer hello; выбор маршрута по outer SNI+port; без strip/disable ECH, угадывания inner, raw fallback или автоматического применения retry configs. HRR сохраняет прежнюю outer identity-проверку; произвольные RFC-допустимые варианты второго outer hello не объявляются поддержанными.

Саму обработку ECH менять не потребовалось. **Общий ECH routing не решён:** v2 не передаёт исходный destination IP, а DNS outer имени на exit может привести не к тому endpoint, который выбрал клиент. Loopback origin pinning доказывает криптографическую совместимость этого пути, но не работу любых ECH/CDN/DNS deployments. Новое routing metadata потребовало бы отдельного решения по destination policy/SSRF, DNS и IPv6, поэтому не добавлялось скрыто в этот пакет.

При повторных прогонах найден отдельный runtime-дефект half-close: `net.Socket` по умолчанию закрывал writable-направление при FIN, теряя поздний ответ или запрос. Воспроизведено настоящими TCP-сокетами в обе стороны, а не только управляемыми Duplex. `RelaySession` теперь включает `allowHalfOpen` на обоих сокетах; EOF передаётся независимо, прежний абсолютный close deadline сохраняется. Третья реальная TCP-регрессия проверяет его срабатывание при зависшей стороне. Lab origin tap и фрагментирующий proxy тоже исправлены. Обновить client и exit; протокол не меняется.

Проверено на Linux / Node 24.13.0 / Go 1.26.8: **142 pass, 0 fail, 0 skipped** — прежние 128 и 14 новых. Для ECH-набора нужен Go 1.24+ (`MESHPN_ECH_GO` или PATH); сборка standard-library fixture проходит offline с временными binary/cache, никаких скачиваний при запуске тестов. Секреты эфемерны, stdout — ограниченные JSON-результаты, cleanup закрывает процессы и удаляет build artifacts. Подробные ограничения и запуск — [в документации стенда](../scripts/transparent-tls-lab.md#настоящий-ech-криптография-и-границы-маршрутизации).

Следом — локальный CONNECT-стенд без TUN для настоящих Chrome/Firefox и независимых captures. ECH+0-RTT, общий ECH routing, replay/destination policy и production-аудит остаются отдельными задачами. Mesh/TUN/динамическое BoringSSL-клонирование этим пакетом не затронуты.

## 20. CONNECT, настоящие браузеры и независимая проверка отпечатков

[CONNECT front door](../scripts/lib/transparent-connect-lab.mjs) принимает только
`localhost:<originPort>` и подключается к фиксированному loopback client relay.
CLI: `node scripts/transparent-tls-lab.mjs --serve --connect-port=0`.
Без TUN, перехвата, публичных listeners или произвольного proxy routing.
19 новых тестов покрывают verified H1/H2, плохой CA, allowlist/framing, лимиты,
fragmentation/coalescing, отказ connect и cleanup. Это lab-only, не новый
production-транспорт; runtime и wire-format не менялись.

[Браузерный runner](../scripts/transparent-browser-lab.mjs) запускает настоящие
headless Chrome/Firefox через CDP/BiDi. Свежие профили, эфемерные CA/leaf, проверка
TLS включена, sandbox не отключается. Chrome NSS DB изолирована private mount
namespace (реальный пользовательский trust store не трогается), Firefox —
собственным профилем. HOME неизменен. Старый CA:TRUE fixture не годится как
end entity для Firefox; это обнаружено настоящим прогоном, не обойдено флагом.

В новом rootless user/network namespace существует только lo. tcpdump снимает
реальные пакеты трёх lab-портов, tshark независимо сверяет SNI/JA3/JA4 с captures;
восстановленный ClientHello/records дополнительно сравнивается побайтово.
Положительные сценарии: TLS1.3 + HTTP/2, точное echo 88 КиБ, origin UA равен
navigator.userAgent; отрицательные: certificate error до первого HTTP-запроса.
Браузер формирует собственные TLS и HTTP/2, сохранённый JSON-профиль не нужен.

Проверено: **161 Node-тест и 4 browser-сценария**, Linux/Node 24.13.0,
Chrome for Testing 151.0.7922.10, Firefox 156.0.1, tshark 4.2.2. Все pass.
Инструменты не скачиваются runner, missing dependency — fail, не skip.
Временные pcap/ключи/профили приватны и удаляются при cleanup; SIGKILL не покрыт.
Команды, зависимости и ограничения — [документация стенда](../scripts/transparent-tls-lab.md#connect-настоящие-chromefirefox-и-независимый-pcap).

Следующий небольшой пакет: browser HRR/CH2 и session resumption с независимым
сопоставлением pcap по stream/random/flight, затем длительная нагрузка и обрывы.
Текущий browser baseline требует CH1 без HRR. Browser ECH/0-RTT/HTTP3, общий ECH
routing и replay/destination policy остаются отдельными задачами. Сходство
JA3/JA4 и нативные UA/HTTP2 не доказывают неотличимость TCP/таймингов от прямого
соединения. Mesh/TUN/динамическое BoringSSL-клонирование не затронуты.

## 21. Браузерные CH2/HRR, ticket resumption и независимая идентификация потоков

Браузерная матрица расширена до шести сценариев на Chrome/Firefox: untrusted CA,
cold baseline, HRR, resumption, resumption+HRR и rejected-ticket fallback.
Успех требует настоящих verified TLS1.3/HTTP2/echo, не только одинаковых хешей.
Для HRR origin ограничен P-256 в Chrome и P-384 в Firefox: Firefox 156 уже
отправляет P-256 share в CH1 и на таком origin не делает HRR. Настройки и
ClientHello браузера не меняются; неподходящий будущий browser fixture даст fail.

Для нового TLS-соединения `drainOriginHttp2()` закрывает текущую H2 session через
GOAWAY с deadline 5 с, не перезапуская браузер и не очищая tickets. Node-регрессии
проверяют сохранение возможности resume и отказ по deadline для незавершённого
request. Origin counters доказывают новый TCP/TLS и `isSessionReused`; число
CONNECT/origin соединений не допускает скрытых reconnect вместо HRR.
PSK/ticket bytes не извлекаются из браузера и не попадают в отчёт.

Новый [pcap matcher](../scripts/lib/browser-lab-pcap.mjs) сопоставляет stage,
peer port, tcp.stream, random и flight, а не первый найденный random.
Каждый CH1/CH2 проверяется по SNI/JA3/JA4 во всех трёх точках; полный ClientHello
и TLS record prefix дополнительно сравниваются побайтово. Проверяются порядок
CH1→HRR→CH2→SH, прежний enc-SNI token, PSK offer в CH и selection в SH.
CH2 binder при resumption+HRR остаётся частью исходного восстанавливаемого hello.
Отпечаток CH2 не обязан быть равен CH1; сравнение идёт отдельно по flight.

Важное наблюдение: Firefox в прогоне после resume не предложил PSK на третьем
соединении. Это не доказательство отклонения ticket сервером. Поэтому acceptance
и rejection используют разные свежие профили: rejection требует реального PSK
offer до origin со сменёнными ticket keys и полного handshake без PSK selection.
Отсутствующий PSK считается fail. Никакого принудительного reuse tickets или
ослабления проверки сертификатов для прохождения тестов не добавлено.

Проверено: **193 Node-теста и 12 browser-сценариев**, Linux/Node 24.13.0,
Chrome for Testing 151.0.7922.10, Firefox 156.0.1, tshark 4.2.2.
Новые 30 matcher-регрессий — синтетические строки fields, не сетевые captures;
два дополнительных Node-теста проверяют GOAWAY control. Полный browser-прогон
разбирает 66 ClientHello captures (18 попыток TLS-подключения через relay, три точки).
Ограничения и запуск — [документация](../scripts/transparent-tls-lab.md#браузерные-hrr-resumption-и-отклонение-ticket).

Следующий пакет: ограниченный параллельный прогон, обрывы/slow peers, контроль
освобождения сокетов и процессов. Browser ECH/0-RTT, ticket renewal после resume,
certificate-error при browser ticket fallback, общий ECH routing и replay policy
остаются отдельными задачами. Production runtime/wire-format, mesh/TUN/BoringSSL
не менялись; этот пакет усиливает стенд и доказательства совместимости.

## 22. Короткая нагрузка, slow peers, отмены HTTP/2 и владение процессами

[Load suite](../scripts/test-transparent-tls-load.mjs), `npm run test:transparent-load`:
72 verified независимых CONNECT/TLS-соединения (6×12, H1/H2, echo 18 МиБ),
72 обрыва неполного ClientHello, 24 обрыва H1 upload после handshake,
6 drip-fed hello и 6 CONNECT headers с абсолютными deadlines.
После волн обязателен нулевой счётчик lab/proxy сокетов и header timers;
внутренние idle-таймеры harness выключены. Здоровые запросы продолжают работать.

Отдельные реальные raw TCP pump тесты проверяют forward/reverse backpressure:
pause/drain, resume с точной передачей 32 МиБ или write deadline, очистку
session sockets/timers/listeners. Бюджет фиксирован, отсутствие настоящего
backpressure даёт fail. Наблюдаемые queue peaks 64/64 КиБ в проверенном окружении;
семплирование не доказывает предел каждого краткого пика. RSS диагностический,
не критерий отсутствия утечек/глобальный memory bound; суточный soak не запускался.

В Chrome/Firefox добавлен `parallel-abort`: 4×8 удерживаемых HTTP/2 requests,
в каждой волне четыре отмены после подтверждённого поступления на origin,
четыре успешных ответа и восемь параллельных echo по 64 КиБ.
Остаётся одно TLS/CONNECT-соединение: это multiplexed H2, а не независимые TCP.
Opt-in gate внутреннего origin ограничен 16 ответами / 5 с, по умолчанию отключён,
очищается при abort/close; три Node-теста проверяют лимит/release/deadline/config.

[Process suite](../scripts/test-browser-lab-process.mjs), `npm run test:browser-process`,
воспроизвёл реальную ошибку test driver: лидер завершился, таймер kill отменился,
потомок с SIGTERM handler продолжил работу. Driver теперь завершает оставшуюся
принадлежащую ему detached process group при exit лидера. Покрыты наследуемые
stdio pipes и обычная повторная остановка. /proc-проверка отличает работающий
процесс от zombie; PID 1 reaping и escaped process groups не контролируются.
Production relay менять не потребовалось; исправлена именно обвязка стенда.

Проверено: **208 Node-тестов + 14 browser-сценариев**, Linux/Node 24.13.0,
Chrome for Testing 151.0.7922.10, Firefox 156.0.1, tshark 4.2.2.
Новых Node-тестов 15 (12 load/gate + 3 process), browser-сценариев 2.
Детали и границы — [документация](../scripts/transparent-tls-lab.md#ограниченная-нагрузка-медленные-стороны-и-отмена-запросов).

Следующий пакет: единый acceptance runner с версиями инструментов, машинным
отчётом и ограниченными повторами. Длительный soak, browser multi-process/slow-reader,
ECH/0-RTT браузеров, production глобальные квоты, replay/destination policy и общий
ECH routing остаются отдельными задачами. Mesh/TUN/BoringSSL не затронуты.

## 23. Единый acceptance runner и машинный отчёт

[Runner](../scripts/transparent-acceptance.mjs), `npm run transparent-tls:acceptance`:
фиксированный manifest из 13 Node-файлов плюс 14 сценариев реальных Chrome/Firefox.
`--repeat=1..3` повторяет всю матрицу и прекращает её при первом сбое, не маскирует
flaky-падения повтором до успеха. `--suite=node` явно оставляет fullAcceptance=false.
Недостающий инструмент, timeout, skip/todo, неполная/дублированная матрица — fail.
Node reporter читает test events; браузер выдаёт структурированный результат только
после успешного сценария и cleanup. Сверяются manifest, версии внутри browser-матрицы,
числа соединений и ClientHello captures. Go auto-download отключён.

JSON schema 1: Git revision/dirty, ОС/kernel/Node/OpenSSL, пути и версии инструментов,
этапы/длительности/exit/reason, counts и имена проваленных тестов, browser scenarios.
NSS certutil проверяется через `-H`, version=null: проверка capability не версия.
Отчёт не архивирует dirty исходники/бинарники, не гарантирует воспроизводимость сборки.
Raw logs/stacks/pcap/TLS secrets не включаются. Новый файл 0600, по умолчанию в
приватном temp-каталоге; existing file/symlink не перезаписываются. SIGTERM даёт
aborted; SIGKILL/ошибка записи могут оставить неполный файл, поскольку запись в конце.
Дедлайны preflight/Node/browser — 15/180/240 с, bounded output, group cleanup grace 5 с.

Добавлены 27 runner/reporter-регрессий. Проверено **235 Node-тестов + 14 browser-сценариев
дважды подряд** (Node 24.13.0, Go 1.26.8, OpenSSL 3.0.13, Chrome 151.0.7922.10,
Firefox 156.0.1, tshark 4.2.2). Полные команды и ограничения —
[документация стенда](../scripts/transparent-tls-lab.md#единая-acceptance-проверка).

Следующий пакет: отдельный bounded soak с повторными волнами соединений/обрывов,
наблюдением сокетов/таймеров/процессов и трендов памяти. Два acceptance-повтора
не заменяют длительный прогон. Browser ECH/0-RTT, общий ECH routing,
replay/destination policy и production-квоты всё ещё отдельные задачи.
Mesh/TUN, wire-format и BoringSSL не менялись.

## 24. Persistent bounded soak и наблюдение ресурсов

[Soak CLI](../scripts/transparent-soak.mjs), `npm run transparent-tls:soak`: Linux/Node 22+,
один worker и один lab/proxy на весь прогон без перезапуска между волнами.
Default — 300 измеряемых секунд после трёх полных волн прогрева, concurrency 4;
границы CLI 1..3600 с и 2..12 клиентов. Нет браузеров/Go/внешней сети/TUN.
Acceptance теперь содержит 14 Node-файлов: добавлены 19 коротких регрессий soak,
полный набор **254 Node-теста + 14 browser-сценариев**.

Волна: параллельные verified H1/H2 echo по 64 КиБ, FIN неполного hello,
H1 upload abort после появления запроса на origin, drip-fed ClientHello и CONNECT
headers до настоящего deadline 300 мс, затем здоровый H2 echo. Полные ClientHello,
TLS records и JA3/JA4 сверяются в каждой волне; captures после проверки удаляются.
Это не HRR/resumption/browser/slow-reader soak — они остаются отдельными режимами.

Lab/proxy получили только test-only accounting возвращённых RelaySession handles:
active sessions/timers и cleanupFailures при closed; закрытые handles не удерживаются.
Также учитываются pendingClients и origin H2 sessions. До выдачи client handle
failed setup наблюдается по pendingClients/сокету, не прямым census всех unref timers.
После фаз все учитываемые ресурсы должны быть нулевыми, после каждой волны FD
не выше прогретого baseline и нет child processes worker. После остановки worker
не остаётся TCP/Timeout/Process handles, удерживающих event loop; supervisor ждёт
его естественного выхода, не маскирует остатки через process.exit().

JSON: Git revision/dirty, OS/Node/embedded OpenSSL, параметры, totals (с прогревом),
baseline/idle samples/final cleanup, фаза ошибки и код, exit/signal worker.
Секреты, payload, runtime stdout/stderr и FD targets не сохраняются. Samples примерно
раз в 5 с; RSS/heapUsed/external/arrayBuffers имеют first/last/peak/delta/slope без
forced GC. Пики только idle sampled, рост RSS сам по себе не равен утечке.
512 МиБ RSS — семплируемая страховка, не cgroup bound; измерения включают harness.
Deadline волны 20 с, drain 5 с, supervisor seconds+60 с и kill grace до 5 с.
SIGTERM regression требует aborted + cleanup, не ложный passed.

Отчёт — новый файл 0600 в приватном temp-каталоге или явный --report, без перезаписи.
Пишется в конце; SIGKILL/ошибка записи могут оставить неполный файл.
См. [полные команды и ограничения](../scripts/transparent-tls-lab.md#ограниченный-по-времени-soak).

Самостоятельно прогнано на VPS: 300.35 с / concurrency 4, 294+3 волны, 2079 TLS,
1485 echo (92.81 МиБ), 594 upload abort, 1188 hello abort и по 594 slow hello/header.
Idle FD 24 весь прогон, после shutdown 19, учитываемые sessions/sockets/timers нулевые,
worker exit 0. RSS 79.3→106.0 МиБ, heapUsed 12.8→13.0 МиБ; RSS во второй половине
ещё +1.25 МиБ, поэтому отсутствие утечки не заявляется. Дополнительно 60.40 с при
concurrency 12: 55+3 волны, 1102 TLS, FD 24→19, RSS 99.8→130.3 МиБ (peak 133.4).
Оба PASS. Финальный acceptance 254 Node + 14 Chrome/Firefox тоже PASS.

Следующий пакет: длительная проверка медленного чтения после handshake в обоих
направлениях, пауза/возобновление и write deadline под параллельными здоровыми
соединениями. Текущий slow-peer soak покрывает заголовки; backpressure пока проверен
отдельными короткими load-тестами. Более долгий browser soak, replay/destination
policy, production-квоты и общий ECH routing остаются отдельными задачами.
Production runtime/wire-format, mesh/TUN и BoringSSL не менялись.

## 25. TLS/H1 slow-reader soak с параллельными здоровыми запросами

В [soak CLI](../scripts/transparent-soak.mjs) добавлен `--profile=slow-reader`,
default остаётся basic. К basic-волне добавляются forward/reverse × resume/timeout:
реальные verified TLS1.3/H1 тела по 32 МиБ через тот же CONNECT/client/exit/origin.
Стенд не перезапускается. При forward origin приостанавливает request, при reverse
клиент приостанавливает TLS response. В обоих случаях требуется реально наблюдаемый
pause + writableNeedDrain на streaming relay, а не только ожидание по таймеру.
Параллельные H1/H2 echo обязаны завершиться до снятия паузы/таймаута slow stream.

Opt-in origin endpoints имеют фиксированный бюджет 32 МиБ, блоки 64 КиБ, cap 2,
deadline 15 с. Данные хешируются потоково, без накопления тела целиком.
Resume требует точного размера/SHA-256; timeout — именно TLS_RELAY_WRITE_TIMEOUT
runtime (2 с), не CONNECT (10 с) и не fixture (15 с). После доказанного timeout
paused reader разрешается дочитать EOF перед проверкой полного drain: иначе
TLS/HTTP origin сохранял pause и не видел закрытия уже остановленного relay.
Это исправление test fixture, production runtime/wire-format не менялись.

Test-only session tracker семплирует raw relay queues каждые 5 мс, граница —
соответствующий HWM + 64 КиБ. Не измеряются все kernel/TLS/HTTP/tap буферы и
мгновенные пики. JSON агрегирует cases/bytes/pressureSamples/queue peaks/timeout
по четырём случаям, включая warmup. В default lab новые endpoints отключены;
external origin запрещён, размер/назначение не управляются запросом.

Добавлены 11 регрессий: выбор профиля, оба направления pressure census, cleanup
drain listeners, cap/opt-in origin, корректный отказ H2 без connection-specific headers,
полная реальная матрица и SIGTERM непосредственно при observed backpressure.
Acceptance: 15 Node-файлов, **265 Node-тестов + 14 browser-сценариев**.
Команды и границы — [документация](../scripts/transparent-tls-lab.md#slow-reader-после-handshake-оба-направления).

Самостоятельный VPS-прогон: 300.87 с / concurrency 4, 47+3 волны — PASS.
По 50 случаев каждого вида: 100 resume (3.125 ГиБ, SHA-256 совпал), 100 runtime
write timeout; 1050 здоровых echo, всего 1350 TLS. Sampled readable/writable queues
65 624/65 536 байт; FD всегда 24 между волнами, после shutdown 19, ресурсы нулевые,
worker exit 0. RSS 94.3→134.0 МиБ (peak 158.7), heapUsed 10.1→12.1 МиБ,
без утверждения об отсутствии утечки. Дополнительно 60.00 с / concurrency 12 —
PASS, 9+3 волны, по 12 случаев каждого вида и 768 МиБ resume bodies, FD 24→19.

Следующий пакет: HTTP/2 flow-control — медленный stream рядом со здоровыми streams
на одном TLS-соединении, отмена stream без потери соседних, освобождение окон/ресурсов.
Сейчас H2 есть в здоровом параллельном трафике, но stalled stream — H1 на отдельном
TLS. Browser soak, replay/destination policy, production-квоты и общий ECH routing
остаются отдельными задачами. Mesh/TUN/BoringSSL не затронуты.

## 26. HTTP/2 stream flow-control на одном TLS-соединении

`--profile=h2-flow` в [soak CLI](../scripts/transparent-soak.mjs): basic-волна плюс
forward/reverse × resume/cancel на **одной TLS/H2 session за всю матрицу**.
Следующая волна создаёт новую session, сам стенд/exit/origin живут весь прогон.
Приостанавливается stream, не TCP socket. На принимающем endpoint необходимо
localWindowSize=0, у отправляющего stream — writableNeedDrain, connection remote
window при этом положителен. Это Node endpoint API, не расшифровка H2 pcap.
Настройки HTTP/2 окон не переопределяются.

До снятия блокировки проходят concurrency соседних 128-КиБ echo на той же session.
Resume требует точных 4 МиБ и SHA-256. При cancel уже находящиеся на origin `/hold`
запросы остаются живы: только slow stream получает RST_STREAM CANCEL=8, origin
подтверждает reset, соседи отвечают 200/released без reset. После каждого случая
новые echo снова проходят на той же session. CONNECT/TCP/TLS counters +1 за матрицу,
GOAWAY/session/runtime errors запрещены. Проверяется продолжение flow-control после
reset, но не точное число WINDOW_UPDATE frames или равенство остаточного credit.

Opt-in `h2Flow` origin: H2-only endpoints, тело 4 МиБ / блок 16 КиБ, cap 2 slow streams,
deadline 15 с закрывает только stream и считается ошибкой теста. H1 и external origin
запрещены. После случаев проверяется освобождение клиентских streams, fixture timers,
held responses; после матрицы — всего TLS/CONNECT и полный trace ClientHello.
H2 readable/writable queues семплируются раз в 5 мс, предел fixture 256 КиБ,
не OS/global memory bound. Production runtime/wire-format не менялись.

JSON `h2Flow`: TLS matrices/healthyEchoes и четыре агрегата cases, bytes,
zeroWindowSamples, healthyWhileBlocked/After, heldSurvived, rstCode, queue peaks.
Basic totals и H2 counters разделены; все включают warmup. Добавлены 12 регрессий,
включая отрицательные проверки flow evidence, cap/opt-in/H1 refusal, настоящую
матрицу и SIGTERM после наблюдаемого исчерпания окна.
Acceptance: 16 Node-файлов, **277 Node-тестов + 14 browser-сценариев**.
Подробности — [документация](../scripts/transparent-tls-lab.md#http2-flow-control-медленный-stream-и-соседи-на-одном-tls).

Первый длинный прогон: assertion на 57-й общей волне, по счётчикам — начало reverse-resume;
конкретное поле старый отчёт не сохранял. Найден дефект readiness: ожидались только
stream window/needDrain, а положительный connection window требовался уже отдельной
assertion. Исправлено ожидание всех трёх асинхронных условий и проверка того же
снимка без повторного чтения. Добавлены две регрессии позднего credit/повторного
чтения; новые failure reports содержат case/step/числовой снимок. Исходный fail
не маскируется повтором «до зелёного», production runtime не менялся.

Финальная проверка на VPS после исправления: 303.33 с / concurrency 4,
98+3 волны, 101 H2-матрица, по 101 случаю каждого вида — PASS.
202 resume доставили 808 МиБ (SHA-256), 202 CANCEL сохранили 808 уже ожидавших
соседних responses; 3333 H2 echo прошли на тех же sessions (basic-трафик отдельно).
Sampled readable/writable peaks 131 070/65 536 байт, FD 24 между волнами → 19
после cleanup, учитываемые ресурсы нулевые, fixture deadline 0, worker exit 0.
RSS 88.3→160.0 МиБ (peak 162.3), heapUsed 8.9→11.1 МиБ; отсутствие утечек не доказано.
Дополнительно PASS 61.71 с / concurrency 12: 13+3 волны, 128 МиБ resume, 32 CANCEL,
384 held survivors и 1552 H2 echo. Финальный acceptance 277 Node + 14 browser — PASS.

Следующий пакет: GOAWAY/drain при активных H2 streams, завершение уже принятых
запросов и явная ошибка новых без скрытой повторной отправки. Browser soak,
replay/destination policy, production-квоты и общий ECH routing остаются отдельными
задачами. Mesh/TUN/BoringSSL не затронуты.

## 27. GOAWAY/drain при активных H2 streams

Добавлен `--profile=h2-goaway`: basic-волна плюс origin-initiated graceful close
во время forward upload / reverse download. Каждый случай использует одну
verified TLS 1.3 / H2 session через CONNECT/client/exit; слушатели постоянные.
Медленный 4-МиБ stream должен исчерпать принимающее окно при backpressure и
доступном connection credit; рядом origin держит `concurrency` уже принятых POST.

Клиент получает GOAWAY(NO_ERROR); lastStreamID покрывает принятые streams,
не возрастает и в конце совпадает с последним принятым ID. Новый POST отклоняется
`ERR_HTTP2_GOAWAY_SESSION`. В течение 100 мс session/drain остаются незавершёнными,
streams — заблокированными/ожидающими. После release/resume все запросы завершаются
без reset, 4 МиБ проверяются по SHA-256; session закрывается естественно до cleanup.
Счётчики origin requests и TLS/TCP/CONNECT запрещают скрытые повторы и reconnect.

Lab-only `drainOriginHttp2()` уже существовал для browser resumption между
запросами; теперь его 5-секундный deadline явно очищается и виден в idle-проверках
как `h2DrainTimers`. Timeout и fixture reset не считаются успешным drain.
Добавлены 12 тестов: границы GOAWAY, отрицательные evidence, отсутствие sessions,
реальная матрица и SIGTERM в обоих направлениях с нулевыми остаточными ресурсами.
Подробности и команды — [документация](../scripts/transparent-tls-lab.md#http2-goaway-drain-с-активными-streams).

Ограничения: Node endpoints, не браузерный soak; все запросы приняты до GOAWAY,
admission race/REFUSED_STREAM/error GOAWAY не покрыты. Отсутствие дублей в этих
сценариях не означает общую exactly-once гарантию; H2 наблюдается endpoint API,
не расшифрованным pcap. Production runtime/wire-format, mesh/TUN/BoringSSL не менялись.

Полный acceptance на VPS: **289 Node-тестов + 14 Chrome/Firefox-сценариев**, PASS
без skipped/todo. Повторный полный прогон после усиления существующей проверки
истечения drain deadline также PASS. Manifest теперь содержит 17 Node-файлов.
Дополнительный soak concurrency 12: 61.41 с, 21+3 волны; 48 graceful closes,
192 МиБ SHA-256, 576 завершённых held responses, 48 явных отказов новых запросов.
FD 24→19, отслеживаемые ресурсы нулевые, worker exit 0; RSS 103.3→115.9 МиБ
(sampled peak 120.6). Это не доказательство отсутствия утечек.

Пятиминутная проверка concurrency 4: 301.64 с / 106+3 волны — PASS.
218 graceful closes, 872 МиБ с SHA-256, 872 завершённых held responses,
218 явно отклонённых новых запросов; hidden replay/reconnect не обнаружен.
Idle FD постоянно 24 → 19 после shutdown, owned sockets/streams/timers нулевые,
fixture CANCEL/deadline 0, worker естественно завершился с exit 0.
RSS 86.9→141.0 МиБ (peak 142.9), heapUsed 9.1→19.2 МиБ,
external 3.8→51.9 МиБ, arrayBuffers 0.3→48.3 МиБ; GC не форсировался,
отсутствие утечек из этих замеров не следует.

Следующий пакет: bounded browser soak с настоящими Chrome/Firefox, повторными
запросами/отменами и контролируемым переоткрытием H2 sessions, сохранением
браузерного профиля в пределах прогона и контролем дочерних процессов/FD/памяти.
Не динамическое клонирование ClientHello. Replay/destination policy,
production-квоты и общий ECH routing остаются отдельными задачами.

## 28. Bounded browser soak: реальные профили Chrome/Firefox

Добавлен `scripts/transparent-browser-soak.mjs`, по умолчанию последовательно
300 секунд **на каждый браузер** плюс три warmup-волны. Один процесс/временный
профиль/страница на браузер; lab/client/exit/origin/CONNECT живут весь прогон.
Каждая волна: параллельные 64-КиБ POST echo, уже принятые POST `/hold`, отмена
половины через AbortController, завершение остальных, проверка TLS 1.3/H2/native UA
и маркера в странице/localStorage. После всех ответов origin делает GOAWAY/drain,
следующий запрос открывает ровно одну новую TLS session без рестарта браузера.
Origin requests и TLS/TCP/CONNECT counters проверяют отсутствие дублей workload;
bounded ClientHello captures сверяют байты/record layout/JA3/JA4 и очищаются.
Реальное потребление браузером tickets не подменяется; resumption не обязателен
на каждом reconnect. Фоновые обращения браузера отвергает фиксированный CONNECT gate.

Worker работает как PID 1 в отдельных user/network/mount/PID namespaces с private
`/proc` и единственным `lo`. Учёт охватывает **всё** дерево browser+worker.
Kernel cleanup PID namespace покрывает и потомков в отдельных process groups;
два теста проверяют TERM-resistant detached child при SIGTERM/SIGKILL владельца.
Private profiles/NSS/CA/key удаляет supervisor; личные профили/trust store не трогаются.
CA/leaf generator выделен в общий helper с существующим browser acceptance.

Ресурсные tripwires: дерево ≤64 live процессов/64 zombies/4096 FD/3 ГиБ summed RSS,
worker ≤512 МиБ RSS. После warmup worker FD не растут; дерево ограничено baseline
+8 live/+8 zombies/+128 FD. RSS суммируется с повторным учётом общих страниц,
не является PSS/уникальной RAM. Измерения после каждой волны, JSON samples ≥5 с.
Cleanup требует единственного живого worker, нулевых relay/CONNECT ресурсов и
отсутствия TCP/server/timer/process handles. Zombies учитываются отдельно и
исчезают вместе с namespace, не выдаются за живые процессы.

Выявлены и сохранены как неуспешные диагностические прогоны: начальный лимит
1.5 ГиБ summed RSS оказался меньше холодного Chrome (~1.6 ГиБ), поэтому порог
откалиброван до 3 ГиБ до длинной проверки; Firefox сначала запускался без нужного
LD_LIBRARY_PATH к уже подготовленным GTK-библиотекам. Установок не было.
Первый длинный Firefox выполнил 300 секунд нагрузки, но завершился с cleanupFailed
(старый отчёт ещё не содержал конкретный код). При отдельных SIGTERM-проверках
подтверждён EACCES при чтении `/proc/<pid>/fd` завершающегося sandboxed процесса.
Теперь после остановки bounded wait ≤5 с требует **полный читаемый** снимок;
EACCES/EPERM не превращаются в нули, постоянная недоступность остаётся fail.
В обычной нагрузке чтение ресурсов остаётся fail-closed. Добавлены четыре
детерминированные регрессии этой гонки/таймаута/остаточных процессов.

Acceptance: 18 Node-файлов, **334 Node-теста + 14 Chrome/Firefox-сценариев** — PASS.
Отдельно `test:browser-soak-real`: четыре настоящих browser-теста, concurrency 12
и SIGTERM при ожидающих запросах в Chrome/Firefox — PASS, cleanup проверен.
Этот набор требует браузеры и не включён в Node-only suite. Команды/границы —
[документация](../scripts/transparent-tls-lab.md#bounded-soak-с-настоящими-chromefirefox).

Не добавлены независимый pcap в долгий soak (он остаётся в acceptance), browser
slow-reader/active GOAWAY, суточный тест, внешний сетевой путь или production
сертификация. Все изменения относятся к стенду; mesh/TUN/BoringSSL и production
relay/wire-format не менялись.

Финальные VPS-прогоны после исправления cleanup: Chrome 300.20 с / 592+3 волны,
2380 echo, 1190 abort и 1190 завершённых held, 596 TLS/1788 ClientHello traces;
Firefox 300.51 с / 574+3, 2308 echo, 1154 abort/1154 held, 578 TLS/1734 traces.
Оба PASS с одним browser launch, суммарно 293 МиБ точного echo. Worker FD постоянно
27 → 19 после cleanup; tree FD Chrome 611→582 (peak 612), Firefox 465→500 (peak 510).
Summed tree RSS Chrome 1648.5→1586.7 МиБ, Firefox 1030.5→1157.7 МиБ;
worker RSS 76.4→91.8 / 75.2→93.8 МиБ. Отсутствие утечек не доказано.
В финальном снимке только живой worker, owned sockets/timers нулевые; 7/11 zombies
учтены отдельно до выхода PID 1. Worker exit 0, privateFilesRemoved=true;
Firefox cleanup получил полный снимок после одного временного EACCES.
Дополнительно PASS финальные concurrency 12 / 60.38 с Chrome и 60.56 с Firefox:
1164/1068 echo, 582/534 abort, 98/90 TLS sessions. Все raw отчёты остались вне git.

Следующий отдельный пакет: негативные тесты повторного использования enc-SNI
route token и ограниченная replay-защита exit с учётом HRR/ClientHello2.
Политика разрешённых назначений exit, production-квоты и общий ECH routing
по-прежнему отдельные задачи; успешный soak их не заменяет.

## 29. Process-local replay-защита enc-SNI admission

Изменён общий production `wireTransparentTlsEncSniSession()`: по умолчанию один
`EncSniReplayGuard` на процесс для всех transparent/combo callers. Запись после
AES-GCM authentication, timestamp/rebuild/prelude checks, но **до** origin
DNS/TCP connect. Она синхронна и не снимается при disconnect/connect failure/
неуспешном TLS handshake. Гонка двух соединений с одним token допускает одно.
`clean-vpn.js`, TUN/mux dispatch и mesh не редактировались; их transparent-ветки
вызывают уже защищённый общий runtime. Wire format v2 и клиентский encoder не менялись.

Ключ cache — SHA-256 аутентифицированных бинарных nonce/ciphertext/tag, не текст
SNI: иное разбиение DNS-labels, пустые labels и uppercase public suffix не обходят
защиту. Меняющийся ClientHello random не разрешает второй admission старого token.
Decoder дополнительно возвращает `replayId`/`issuedAtSeconds`; в обычные логи они
не попадают. Cache не хранит hostname/PSK/raw token; поддельные token его не заполняют.

Default 65 536 записей, каждая удерживается 601 000 мс. Это покрывает всё окно
±300 секунд с целочисленной включительной границей, даже при первом предъявлении
future-skew token. Удаляются только истёкшие записи, лениво и в insertion order,
без per-entry timers. При заполнении fail-closed, без вытеснения живых записей.
Бюджет около 109 новых admissions/с на полном retention — лишь ориентир без
burst-запаса, не throughput promise или per-user quota. Уменьшить maxEntries можно
programmatically; отключение `null/false` запрещено, CLI disable/clear нет.

Clock high-water mark блокирует admissions при откате wall clock до его
восстановления: иначе уже удалённые записи могли бы снова стать валидными.
Timestamp ещё раз проверяется при reservation. Коды без route secrets:
`TLS_RELAY_REPLAY`, `_REPLAY_FULL`, `_REPLAY_CLOCK`, `_REPLAY_STALE`.
Системная коррекция часов назад может временно отказать легитимным новым
соединениям; уже открытые sessions не прерываются этим guard.

CH2 после HRR идёт через прежний session-local identity guard, не через новую
reservation. Работает и при capacity=1. Новый token в CH2 отвергается identity
guard, копия CH2 на другом TCP — replay guard. Combo classifier остаётся
stateless: peek не расходует token, валидный повтор не переключается в TLS mux.
Lab использует отдельный guard на весь lifetime; `stats().replay` — только
числовые entries/maxEntries/retentionMs. Ненулевые записи после закрытия sockets
намеренно сохраняются как security state, не означают leaked handles.

Гарантия **ограниченная**: один guard/process lifetime. Restart, другой worker/host
имеют независимую память. Гонка первого предъявления и привязка token к TLS
transcript не решены: перехватчик, успевший первым, может занять token. Не заменяет
origin TLS/0-RTT anti-replay, exactly-once HTTP, destination policy, глобальные
socket quotas и защиту raw TUN. Полный durable/distributed replay-cache не добавлен.

Добавлены 34 теста: настоящие захваченные CH1/CH2 с нулевым дополнительным origin
connect, HRR/alias/random, конкурентный default admission, отказ connector,
полный cache на 65 536, очистка, future timestamp/expiry/clock rollback и приватность
логов. Временные границы проверены управляемыми часами, не 10-минутным ожиданием.
Финальный acceptance: **368 Node-тестов (19 файлов) + 14 Chrome/Firefox-сценариев**
— PASS; ECH, HRR, resumption, 0-RTT сохранены. Четыре real-browser soak/SIGTERM
регрессии — PASS. Дополнительный browser soak concurrency 12: Chrome 60.11 с /
99 TLS / 1176 echo / 588 abort; Firefox 60.47 с / 90 TLS / 1068 echo / 534 abort.
Final replay entries 99/90, worker exit 0, сокеты/таймеры освобождены, FD 19,
живых browser-процессов после cleanup нет, private profiles удалены.
Подробности — [документация](../scripts/transparent-tls-lab.md#replay-защита-enc-sni-route-token).

Следующий пакет: явная destination policy exit — разрешённые назначения,
private/loopback адреса и защита от DNS rebinding, с отдельными негативными тестами.
Это не изменение mesh или динамическое клонирование браузерных профилей.

## 30. Application-level destination policy exit

В общем production runtime добавлена default `ExitDestinationPolicy`:
`scripts/lib/transparent-tls-destination.mjs`. Действует на transparent/enc-SNI
ветки transparent-tls и combo-tls, в том числе standalone listener. Это не
firewall: mesh/TUN, iptables/nftables, маршруты, системный DNS и запущенные
VPN-сервисы не менялись. Wire v2 и TLS transcript не менялись.

После auth/rebuild и replay reservation проверяется hostname/port. IP literal
v4 проходит без DNS; для имени один OS lookup абсолютного имени (`hostname.`),
`all:true, verbatim:true`. Проверяется весь возвращённый набор A/AAAA: если хотя
бы один адрес запрещён, отказ всему admission, включая public+private mix.
Default закрывает RFC1918/loopback/link-local/CGNAT/multicast/reserved/doc/benchmark
IPv4, а для IPv6 разрешает консервативное подмножество `2000::/3`, исключая
special ranges. Mapped IPv4, известные NAT64, 6to4/Teredo, ULA и scopes запрещены.
Точная политика/обоснование диапазонов — [документация стенда](../scripts/transparent-tls-lab.md#destination-policy-exit-и-dns-rebinding).

Первый проверенный IP копируется в immutable target, `net.connect` получает
только numeric address/family/port, без повторного DNS. Перед отправкой prelude
сверяется фактический peer IP/port. Подмена DNS между проверкой и connect не
изменяет target. Следующее новое соединение повторяет lookup+проверку. Combo
отказ не fallback в mux; HRR продолжает то же соединение. Отказ policy/DNS
не освобождает token и не позволяет тем же token повторять lookup.

Один connect deadline включает DNS+TCP; close/timeout прекращает ожидание,
поздний resolver result не открывает сокеты. Не более 64 OS lookups одновременно
на default process-local policy и 64 адресов на ответ; очередь не создаётся.
Неотменяемый OS lookup после timeout сохраняет слот до settlement — иначе
bounded session всё равно позволяла бы неограниченно забивать libuv запросами.
Коды: `TLS_RELAY_DESTINATION`, `_DESTINATION_PEER`, `_DNS`, `_DNS_BUSY`,
общий `_CONNECT_TIMEOUT`. Raw resolver message и ответы в обычный лог не выводятся.

Lab получает явный pin `{hostname:originName, port:boundOriginPort}` только на
`127.0.0.1`; другой hostname/port не разрешён. Generic `allowPrivate`/CLI bypass нет.
Programmatic connector теперь принимает `(address, port, family)`, не hostname.
Test doubles адаптированы явно; даже custom connector проходит policy/peer check.

37 новых тестов: IP ranges/encodings, malformed/local names, DNS mixed/rebinding,
default production path и numeric connector, wrong peer до отправки CH, exact
lab pin, quota/timeout/close/late resolve/reject, auth/replay ordering. Реальный
loopback negative test требует ноль origin accepts. Полный VPS acceptance:
**405 Node-тестов (20 файлов) + 14 Chrome/Firefox-сценариев** — PASS, без skips.
Отдельные четыре real-browser soak/SIGTERM регрессии Chrome/Firefox также PASS.

Изменение совместимости намеренное: private/split-DNS назначения закрываются.
Пока выбирается первый адрес OS без Happy Eyeballs/fallback; недоступный первый
не заменяется вторым. Это следующий короткий пакет для восстановления доступности
без DNS re-resolution — retries только по заранее проверенному набору, общий
deadline, без отправки prelude проигравшим sockets. Не решены публичные IP
самого exit, специфичная маршрутизация/DNAT/custom NAT64, provider service IP
в публичном диапазоне, domain/port allowlist, глобальные/per-client socket quotas.
Это не универсальная SSRF-изоляция и не защита non-transparent transport веток.

Пользователь дополнительно предложил защищённый реальный DNS и редкие прямые
cover-domain запросы. Зафиксирован [отдельный DNS-план](clean-vpn-dns-plan.md):
privacy и bootstrap сначала, cover DNS только после проверки согласованности
имени/ответа/exit и отдельного решения. Сейчас ни прямые cover-запросы, ни
перенастройка DNS не включены. `sni-dictionary` остаётся планом alias-cache;
`--tls-public-name` — список публичных SNI-имён, не domain allowlist resolver.
