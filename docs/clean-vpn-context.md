# Контекст clean-vpn и транспортных экспериментов

Срез: 2026-09-22, HEAD `4bfec57`. Это база контекста для дальнейшей работы, а не полный аудит безопасности или сертификат production-ready.

При финальной сверке появились параллельные незакоммиченные изменения в `device/` и `scripts/clean-vpn.js`. Они не принадлежат этой работе и не редактировались. Новый `--tls-raw` учтён ниже отдельно по прочитанному diff; остальные выводы относятся к исследованному срезу, не к законченной проверке параллельной разработки.

Область: `scripts/clean-vpn.js`, его библиотеки, TLS/браузерные профили, нативный BoringSSL-helper, классификатор, связанные планы и эксплуатационные скрипты. Реализация mesh VPN в `src/` намеренно не исследовалась. Существующие результаты в `device/` не менялись.

Источник истины о реализации — код; Markdown часто содержит предыдущие архитектуры и ещё не выполненные предложения. Ниже отдельно обозначены реализованное, ограничения по статическому чтению и фактически выполненные проверки.

Конкретные предложения по развитию сохранённых браузерных профилей вынесены в [план улучшения мимикрии](browser-profile-mimicry-plan.md): schema v2, GREASE/key shares, штатные API BoringSSL, проверка до отправки ClientHello, HTTP/2 и критерии приёмки.

### Дополнение 2026-09-25: выбор входного интерфейса

Добавлен пилотный `--from-tun=wg0`, вместо `--split-default` и независимо от транспорта. Общая реализация — `scripts/lib/ingress-routing.mjs`: policy routing по `iif`, SNAT через собственный TUN, scoped FORWARD guard и блокировка IPv6 forwarding выбранного входа. Host OUTPUT/default и DNS хоста не меняются. Нужен уже настроенный шлюз с `ip_forward=1`; частные/подключённые сети остаются исключениями.

Для transparent/combo HTTPS-перехват в этом режиме только через PREROUTING выбранного интерфейса, listener на собственном TUN IPv4; прежний OUTPUT-перехват не включается. Это не исправляет отсутствие защиты сырого TUN у standalone transparent. Штатный stop возвращает прежний forwarding; после fatal/SIGKILL guard/rules сохраняются и повторный запуск требует проверки остатков. Подробности, тесты и ограничения — [руководство ingress-шлюза](../scripts/clean-vpn-from-tun.md). Автоустановщик/systemd, DNS-прокси LAN и реальный WireGuard-пилот этим изменением не покрыты.

### Принятое направление: transparent вместо динамического клонирования

Решение пользователя от 2026-09-22: полностью исключить вариант, при котором ClientHello каждого перехваченного приложения автоматически становится профилем нового BoringSSL TLS-соединения к exit. Не оставлять его экспериментальным режимом или пунктом реализации.

Для индивидуальных HTTPS-соединений приоритет — улучшение transparent/enc-SNI relay с сохранением настоящего TLS приложения. Сохранённые BoringSSL-профили общего TUN-транспорта этим решением не отменены. Речь о relay-ветке, в том числе внутри combo-tls, а не о признании безопасной raw TUN-ветки standalone transparent-tls.

Кандидаты на следующий отдельный этап исходного аудита: корректность ClientHello2/HRR и ECH, сохранение TLS record layout, защита route metadata от replay, лимиты/таймауты/backpressure, политика relay-направлений, приватность логов и end-to-end тесты. Последующие реализованные части отдельно зафиксированы в разделах 13–32; остальные пункты не следует считать выполненными.

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

В исходном пакете первый проверенный IP копировался в immutable target (перебор
остальных добавлен в разделе 31). `net.connect` получает
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
В исходном пакете выбирался только первый адрес OS; pinned-IP fallback добавлен
в разделе 31. Не решены публичные IP
самого exit, специфичная маршрутизация/DNAT/custom NAT64, provider service IP
в публичном диапазоне, domain/port allowlist, глобальные/per-client socket quotas.
Это не универсальная SSRF-изоляция и не защита non-transparent transport веток.

Пользователь дополнительно предложил защищённый реальный DNS и редкие прямые
cover-domain запросы. Зафиксирован [отдельный DNS-план](clean-vpn-dns-plan.md):
privacy и bootstrap сначала, cover DNS только после проверки согласованности
имени/ответа/exit и отдельного решения. Сейчас ни прямые cover-запросы, ни
перенастройка DNS не включены. `sni-dictionary` остаётся планом alias-cache;
`--tls-public-name` — список публичных SNI-имён, не domain allowlist resolver.

## 31. Перебор проверенных IP сайта до TCP connect

`ExitDestinationPolicy.resolve()` теперь возвращает immutable массив immutable
`{address,family,port}`, а не один target. Проверяется весь DNS ответ (до 64 IP),
затем эквивалентные IP, включая разные IPv6 записи, дедуплицируются с сохранением
порядка. Даже последний запрещённый адрес блокирует весь набор до первого socket.
Sparse arrays также отвергаются. Ни один retry не вызывает DNS заново.

`connectRelayDestination()` перебирает IP последовательно. Отказ до TCP connect
(ECONNREFUSED/ECONNRESET/ETIMEDOUT/unreachable/down/EADDRNOTAVAIL) позволяет перейти
к следующему. Для незавершённой не-последней попытки выделяется 250 мс, затем
socket.destroy() и следующий адрес. Последнему достаётся остаток общего бюджета
DNS+TCP (default 10 с). При exhaustion — `TLS_RELAY_CONNECT_EXHAUSTED`, без raw
host/IP/errors. При общем deadline — прежний `TLS_RELAY_CONNECT_TIMEOUT`.

`RelaySession.connectCandidate()` допускает локальный отказ предварительного
TCP socket, не разрушая inbound и всю session. Отменённый socket остаётся owned
до close; отложенные error не становятся unhandled и не убивают новый candidate.
Connect/abort/timer listeners снимаются. После connect ошибки снова завершают
всю session. Клиентское подключение к exit использует прежний `connect()`.

Принципиальная граница: никакого retry после выбора TCP, ошибки TLS или отправки
ClientHello. Prelude и coalesced bytes попадают только выбранному socket. Peer
mismatch и локальные permission/resource/config ошибки не маскируются перебором.
HRR/CH2 идут по выбранному соединению. Один enc-SNI token и reservation на весь
перебор; внешний wire-format и поведение браузерного TLS не меняются.

27 новых проверок, всего 64 destination-теста. Управляемые часы проверяют 250 мс,
общий deadline, DNS latency и abort без реальных blackhole IP. Есть sync/async
failures, late events, 64-address bound/dedup, immutable answers, forbidden last
IP, wrong peer и reset после CH без повторной отправки. Два настоящих loopback
TLS 1.3 H2 echo по 64 КиБ (baseline/forced HRR): первый IP возвращает ECONNREFUSED,
второй работает, CA проверен, origin принимает ровно одно соединение. Несколько
loopback кандидатов допускаются test double, не расширением production policy.

На VPS полный acceptance: **432 Node-теста (20 файлов) + 14 Chrome/Firefox
сценариев** — PASS, без ошибок/пропусков. Отдельно четыре real-browser soak/SIGTERM
регрессии — PASS. Весь набор проверяет общий runtime после изменения lifecycle
предварительного подключения; публичные DNS/TCP destinations для failover-тестов
не использовались.

Ограничения: это bounded sequential fallback, не параллельный Happy Eyeballs;
порядок семейств OS не переставляется, RTT не запоминается. 250 мс может отсеять
медленный работающий IP. Общий deadline может закончиться до перебора всех 64.
Системный DNS, firewall, TUN, mesh и работающий VPN не менялись.

Следующий пакет: explicit-loopback стенд защищённого DNS с проверкой CA/hostname,
обрывов и отсутствия plaintext fallback, без изменения DNS системы. Декоративные
cover-запросы не добавляем; собственное публичное имя exit должно иметь реальные
DNS-записи. План — [clean-vpn-dns-plan.md](clean-vpn-dns-plan.md).

## 32. Explicit-loopback DNS → DoH через transparent relay

Добавлены `scripts/transparent-dns-lab.mjs`, `lib/transparent-dns-lab.mjs`,
`lib/lab-doh-stub.mjs`, `lib/lab-dns-wire.mjs`, 46 тестов в общем acceptance.
Команды: `npm run transparent-tls:dns-lab`, `npm run test:transparent-dns`.
Подробности — [DNS lab](../scripts/transparent-dns-lab.md).

Явный DNS client → loopback UDP/TCP stub → DoH POST через production transparent
client/exit runtime → локальный HTTPS resolver с синтетическими A/AAAA-ответами.
TLS 1.3 от stub до resolver, CA+hostname проверяются. Relay не получает TLS keys
этой сессии, не разбирает HTTP/DNS body. Wire DNS настоящий; resolver **не**
рекурсивный, никакого внешнего DNS для test names нет. Все IP/порты явные loopback;
OS resolver, `/etc/resolv.conf`, firewall, TUN, mesh и работающий VPN не менялись.

Одна IN question A/AAAA, DNS wire ≤4096 B, bounded compression/RR framing,
ID/question/QR matching. UDP 512 B или EDNS(0) 512..4096, большой ответ даёт TC;
явный TCP retry снова использует DoH. TCP fragmentation, pipelining/half-close,
NXDOMAIN, TTL=0 проверены. DoH query ID=0, клиентский ID восстанавливается.
Кэша нет: положительные/отрицательные ответы и HTTP caching/connection pooling
не внедрены. Fixture HTTP/1.1 POST-only, не полноценный публичный DoH server.

Ошибки сертификата/имени, timeout/reset, HTTP non-200/redirect/content-type/
encoding/oversize, DNS malformed/mismatched response дают SERVFAIL. Нет fallback
на plaintext DNS, другой URL/resolver или системный bootstrap. При неверном TLS
сертификате/имени origin не получает DNS HTTP body. Фактический stop/restart
HTTPS origin даёт отказ/восстановление без смены upstream.

In-flight и TCP connections ограничены (adapter default16, harness8, max64),
очереди DoH нет; pending TCP ≤8196 B; absolute TCP lifetime default5/3 с.
DoH timeout default1.5/1 с. RST TCP-клиента отменяет DoH, FIN сохраняет возможность
ответить после half-close. UDP отмены не имеет. `close()` ждёт close events,
обнуляет owned sockets/requests/jobs/timers; startup UDP bind failure откатывает TCP.
Первый запуск тестов выявил гонку `.closed` до события close и задержку обнаружения
RST при paused socket; исправлено ожиданием close и bounded чтением во время DoH.

Опциональный lab-only `observeWire` наблюдает копии входящих TCP bytes, включая
application records, по stage/peer port. Уникального QNAME нет на client→exit и
exit→resolver, но response подтверждает получение resolver. Spies дополнительно
запрещают name resolution и неожиданные TCP/UDP endpoints при success/reset/redirect.
Это **не независимый kernel pcap**, не reverse-direction capture и не доказательство
отсутствия DNS-утечек произвольных приложений/OS/LAN/IPv6. TLS resolver/public SNI,
IP и статистика трафика остаются наблюдаемыми.

VPS acceptance: **478 Node-тестов (21 файл) + 14 Chrome/Firefox-сценариев** — PASS,
без skips; отдельно четыре real-browser soak/SIGTERM регрессии PASS. CLI self-check:
8 queries, 5 success (включая NXDOMAIN), 3 ожидаемых SERVFAIL, нулевые owned
sockets/requests/jobs/timers после cleanup. Никаких внешних DNS/QNAME запросов.

Следующий пакет: независимый namespace pcap с позитивным plaintext leak control
и bounded DNS soak. Затем выбрать production upstream/bootstrap и отдельно
интегрировать клиент/OS/LAN/IPv6. Cover DNS не включаем; динамическое BoringSSL
клонирование не возвращаем. Parser/adapter пока лабораторные, не production DNS.

## 33. Независимый DNS pcap и namespace soak

`scripts/transparent-dns-soak.mjs` добавляет отдельный opt-in runner без TUN,
host firewall/DNS/routes, mesh и изменений работающего VPN. User/net/mount/PID
namespaces, только `lo`, worker PID1. Все адреса числовые loopback, resolver
синтетический. Команды и ограничения — [DNS lab](../scripts/transparent-dns-lab.md).

Перед нагрузкой tcpdump захватывает весь TCP/UDP namespace; tshark независимо
читает payload обоих направлений, без TLS keys. Уникальный label намеренно
передаётся открытым UDP DNS на отдельный fixture port: detector обязан найти
его и в запросе, и в ответе. У локального stub plaintext также ожидается.
На четырёх TLS legs, включая client↔exit и exit↔resolver, label отсутствует.
Собираются TCP stream/direction/sequence, split labels не обходят detector.
Gaps, conflicting retransmits, truncated packets, kernel drops, неизвестные
IP/ports, пустые направления/pcap, packet/output limits → FAIL, не skip.
Pcap покрывает короткую success/failure/restart матрицу **до soak**, не весь soak
и не DNS произвольных приложений, OS/LAN/IPv6. Положительный real-контроль — UDP;
split TCP plaintext detector проверяется отдельной регрессией.

Десять warmup waves, затем 1..600 с измерения (default60), concurrency1..8
(default4). Волна: normal/NXDOMAIN/large/reset/hold/redirect/origin offline/
recovered, по одной группе UDP/TCP A/AAAA запросов на режим. Реальные stop/restart
HTTPS resolver; ответы, expected SERVFAIL, counters, cleanup проверяются.
Worker V8 ограничен old-space64/semi-space8 MiB; это **lab-only**, не production
настройка. Core dumps выключены у дочернего namespace. RSS ≤256 MiB и рост
≤64 MiB от warmup high-water, heapUsed рост≤32 MiB, idle FDs не выше baseline.
После волн нет живых TCP client sockets/timers/processes; после close также
нет TCP listeners/UDP sockets. Replay entries удерживаются штатно (601 с,
65536 максимум) и не считаются открытыми ресурсами. Это sampled budgets, не
cgroup и не доказательство отсутствия утечки при других runtime settings.

Первый unconstrained V8 эксперимент остановился по росту RSS/heap: reserved
heap расширялся, а heapUsed после обычного GC возвращался к низким значениям.
Исправлен метод измерения (warmup high-water вместо единичного post-GC trough),
задан явный heap budget worker; принудительный GC не используется. Не следует
читать успешный constrained soak как подтверждение unlimited-V8 поведения.

Parent deadline seconds+45 с, kill grace5 с, сигналы → aborted+cleanup. JSON0600
создаётся исключительно новым файлом, без QNAME/keys/payload/raw logs. Private
pcap удаляется после завершения, включая штатные failure/signal. Kernel убирает
остатки PID namespace после выхода init. SIGKILL parent/авария ОС может оставить
temp files/неполный report; никакой гарантии аварийной файловой уборки нет.

VPS: **506 Node-тестов (22 файла) + 14 browser-сценариев**, отдельно **6 real DNS
регрессий** PASS, без skips. Последние проверяют concurrency1/8, SIGTERM, missing
tcpdump/tshark, запрет overwrite и запуска worker вне namespace.
120-секундный concurrency8 soak: 142 волны, 9088 measured queries (4544 expected
SERVFAIL), 142 restart, 9744 queries с прогревом/capture. RSS samples98.7–103.8 MiB,
heapUsed13.3–21.1 MiB, idleFD25, finalFD19, нулевые owned sockets/timers/jobs и
child processes. Pcap1020 packets/382738 B, положительный контроль PASS,
protected plaintext не найден. Acceptance report:
`/var/tmp/meshpn-acceptance-tMbS6J/report.json`; soak report:
`/var/tmp/meshpn-dns-soak-report-Tk4H57/report.json` (локальные артефакты, не git).

Дальше: production upstream/bootstrap configuration contract — TLS hostname
отдельно от endpoint IP, CA validation, pinned/проверенные IP, отсутствие
системного/plaintext fallback. Сначала validation и loopback tests, затем
отдельное согласованное включение клиента/OS/LAN/IPv6. Доверенный публичный
resolver пока не выбран, внешний трафик не включён. Кэш/pooling, cover DNS и
динамический BoringSSL cloning не добавлялись.

## 34. DNS upstream/bootstrap contract и offline checker

Добавлены `scripts/lib/dns-upstream-config.mjs`, `scripts/dns-upstream-check.mjs`,
шаблон `scripts/fixtures/dns-upstream.example.json` и 65 регрессий в общем
acceptance. [Формат, запуск и ограничения](../scripts/dns-upstream-config.md).
Команды: `npm run dns:check-upstream -- --config=/path/to/upstream.json`,
`npm run test:dns-upstream-config`. Это не запуск production DNS.

Строгий schema1 JSON: transport=doh, hostname, port, path, bootstrap.addresses,
trust. TLS SNI, certificate hostname check и HTTP Host используют одно
canonical ASCII имя; IP не подменяет TLS identity. HTTP Host добавляет port,
если он не443. Простой POST path без URL/query/fragment/escapes/credentials.
Нет произвольных TLS/HTTP options, insecure/fallback/allowPrivate switches.

Static bootstrap list1..8 содержит только numeric public IPv4/IPv6 по существующей
exit admission policy; mixed private/special-use set отвергается целиком.
Эквивалентные IP dedup с сохранением порядка; immutable address/family/port
snapshot. Offline compile не вызывает DNS/TCP/HTTP. Это **валидация кандидатов**,
не подтверждение доступности/принадлежности IP и не готовое переключение connector.

Trust modes: bundled — явно переданный Mozilla bundle текущего Node; custom —
1..8 отдельных CA PEM ≤16 KiB с проверкой CA flag/validity, без keys/мусора.
Custom заменяет bundled, не добавляется к нему. Нет неявного расширения доверия
через OS/default CA overrides или NODE_EXTRA_CA_CERTS. Не означает автоматическую
CRL/OCSP/revocation проверку. TLS1.3+, rejectUnauthorized=true, проверка имени
профиля обязательна независимо от переданного в callback имени dial target.

CLI читает regular non-symlink файл ≤128 KiB с bounded read, strict UTF-8,
duplicate/escaped-equivalent JSON keys и >16 nesting запрещены. Unknown keys,
невалидный trust/IP/path/hostname → стабильная redacted ошибка. Успешный summary
не содержит hostname/IP/PEM, имеет status=validated-offline/runtimeEnabled=false.
Шаблон намеренно содержит invalid placeholder, публичный resolver не выбран.

Явный compileLabDnsUpstream разрешает только127.0.0.1, дополнительно localhost;
он недоступен через JSON/CLI как режим. Публичный profile не принимается lab
target adapter. Обычные DNS smoke/pcap/soak теперь создают профиль через этот
контракт; старые ca/servername overrides остаются test fault injection.
Lab отображает logical identity/Host/path на фиксированные numeric loopback
порты transparent relay и синтетического resolver. Нет direct external connect.
Проверены нестандартные Host/path, UDP/TCP A/AAAA, wrong CA/hostname (resolver
не получает DNS body), snapshot isolation, запрет network I/O при compile.

Первый общий прогон при параллельном real DNS soak имел 570/571 PASS: упал
существующий `owner exit kills a TERM-resistant descendant (stdio=inherit)`
из test-browser-lab-process.mjs. Отдельный запуск его трёх тестов PASS;
production/browser process code не менялся. Первый report сохранён:
`/var/tmp/meshpn-acceptance-2IEaFj/report.json`. Нельзя считать его успешным
acceptance. Повторный полный прогон отдельно от real DNS soak: **дважды подряд
571 Node-тест (23 файла) + 14 browser-сценариев PASS**, без skips, report:
`/var/tmp/meshpn-acceptance-BnJv7y/report.json`. Отдельно **6 real DNS pcap/soak
регрессий PASS** уже с profile-backed default harness. Шаблон с placeholder
проверен CLI и ожидаемо отклонён; настоящие внешние DNS-запросы не выполнялись.

Рабочий exit **всё ещё использует OS resolver** для destination hostname:
загрузка JSON его не меняет. Следующий пакет — узкая операторская pinned route
для resolver hostname+port с подключением к configured snapshot IP без lookup,
без расширения общей destination policy и без изменения enc-SNI протокола.
Сначала loopback tests, затем отдельное включение. Bootstrap самого exit,
OS/LAN/IPv6 integration, cache/pooling и выбор реального resolver остаются
отдельными задачами. Mesh/firewall/TUN/system DNS/live VPN не менялись.

## 35. Opt-in pinned resolver route на exit

`ExitDestinationPolicy` принимает один operator `pinnedRoute` и повторно
валидирует public hostname/port/1..8 IP, family/port соответствие, отсутствие
private/special-use кандидатов. Копирует/dedup/freezes snapshot. Сочетание с
lab loopback exception запрещено. `dnsUpstreamExitPolicy(compiledProfile)`
принимает только настоящий public-contract profile, не lab/clone/forged object.

Точное case-insensitive hostname+port возвращает pinned IP без OS lookup и
без расхода DNS pending slots. То же имя на другом порту запрещено, не fallback
в DNS. Другие имена/subdomains/IP literals проходят прежнюю destination policy;
это не wildcard/domain allowlist и не защита всего DNS exit. Private/mixed
answers по обычному пути остаются запрещены. Pinned route работает даже когда
64 DNS slots заняты другими доменами. PSK/replay admission остаётся до route.

Используется существующий connector: numeric IP+port+family, autoSelectFamily=false,
последовательный failover только до выбранного TCP, общий deadline default10 с,
non-final attempt250 мс. Selected peer проверяется. ClientHello не дублируется
после успешного TCP; TLS/HTTP failure/reset не вызывает retry. Exhaustion →
TLS_RELAY_CONNECT_EXHAUSTED, без OS DNS/другого resolver/combo mux fallback.
Abort/deadline прекращают список, поздние completion не создают новое соединение.

`clean-vpn.js` получил флаг **`--tls-dns-upstream-config=PATH`** только для exit
transparent-tls/combo-tls. Флаг обрабатывается отдельным preflight helper перед
runExit/runClient (до TUN/NAT/listeners). Bad context, bare/empty/duplicate/
malformed flag, invalid/missing file → redacted failure. Общий bounded reader
вынесен в `lib/dns-upstream-config-file.mjs`, используется и offline checker.
Без флага default policy не меняется. Policy загружается один раз и передаётся
в обе enc-SNI ветки; mesh/mux/probe/обычный IP путь не модифицировались.
Нет hot reload/polling; изменение файла не меняет snapshot живого exit.

Флаг **не запускался на live exit**. Он не включает DNS stub на клиенте, не
меняет OS resolver и не выбирает публичный DNS provider. Exit проверяет адресную
route, не TLS certificate/HTTP path/body: TLS остаётся end-to-end, CA/name/path
проверяет будущий клиентский DoH adapter. Любая авторизованная enc-SNI session
к configured hostname+port использует pin — не per-client DNS ACL.

Тесты: 28 новых unit/runtime/preflight регрессий включены в общий acceptance,
**599 Node-тестов (24 файла) +14 Chrome/Firefox сценариев PASS**, без skips.
Report `/var/tmp/meshpn-acceptance-9X9rn3/report.json`. Проверены immutable pin,
exact/port matching, обычные routes, DNS saturation, failover, default numeric
connector, abort/deadline, peer mismatch, отсутствие повторной отправки CH,
auth/replay, startup validation/snapshot и wiring clean-vpn без запуска TUN.

Отдельно4 real namespace tests: IPv4/IPv6 × transparent-tls/combo-tls runtime.
Private user/net/mount/PID namespace, толькоlo, на нём public-unicast aliases;
никаких host/uplink изменений или внешней сети. Политика настоящая public,
без resolve mocks/private admission. Первый TCP IP refused, второй делает
реальный проверенный TLS1.3/DoH. Wrong CA не получает DNS body, reset не повторяет
запрос, оба IP down → exhaustion без lookup, restart → recovery. По5 запросов,
10 TCP attempts, 3 resolver bodies, 0 DNS lookups на case. После cleanup
owned sockets/timers=0, namespace children=0. Полный clean-vpn/TUN не запускался;
проверяется общий enc-SNI runtime обеих веток, dispatch wiring проверен отдельно.
Повторный отдельный запуск прежних6 real DNS pcap/soak tests и новых4 route tests:
**10/10 PASS**, без skips. Host DNS/firewall/routes/live VPN не менялись.

Дальше: explicit клиентский DNS adapter через **числовой exit endpoint**, с
hostname/port/path/CA из профиля, без прямого resolver connect/OS fallback.
Сначала отдельный no-TUN стенд, затем согласованное включение и OS/LAN/IPv6.
Bootstrap самого exit, cache/pooling и автоматическая ротация остаются отдельно.
Cover DNS и динамическое BoringSSL cloning не возвращаются.

## 36. Явный клиентский DNS adapter через числовой exit

Добавлен отдельный `npm run dns:exit-adapter -- ...`, инструкция
[`scripts/dns-exit-adapter.md`](../scripts/dns-exit-adapter.md). Только явный
loopback UDP/TCP listener на порту1024..65535; без TUN, system DNS, routes,
firewall или live VPN. Настоящий resolver не выбирался и не опрашивался.
Шесть обязательных CLI-аргументов: upstream config, exit-ip/exit-port,
public-name, shared-hmac-key, listen-port. Unknown/duplicate/malformed flags,
невалидный profile/IP/PSK отвергаются до listeners. JSON — прежний bounded
reader; PSK — non-symlink regular file ровно32 байта, без group/other permissions.
SIGINT/SIGTERM закрывают активные запросы и listeners; ошибки redacted.

`dns-exit-transport.mjs`: HTTPS agent создаёт TLS через `duplexPair` в памяти,
второй конец читает общий `attachTransparentTlsClientSession`. Нет отдельного
TCP HTTPS proxy listener. Единственный dial — numeric public-unicast IPv4/IPv6
exit с family и autoSelectFamily=false; OS hostname lookup запрещён. Исходный
TLS проверяет hostname и CA **resolver**, а enc-SNI передаёт hostname/port exit.
Bootstrap IP resolver не становится client TCP target. CA/Host/path берутся
из настоящего compiled public profile; cloned/lab profiles отвергаются.
Loopback test factory отдельная, CLI/JSON её не активируют. PSK/options копируются.

`startDnsExitAdapter` переиспользует bounded stub/parser, а не объявляет их
полноценным DNS stack. `lab-doh-stub.mjs` получил отдельный branded exitTransport
путь, несовместимый с lab profile/raw upstream overrides; прежний lab API сохранён.
IN A/AAAA,4096байт,16 in-flight/16 TCP,deadline1500мс,TCP lifetime5000мс по умолчанию.
Чужие CA/имя/PSK, timeout/reset, bad HTTP и недоступность дают SERVFAIL без
direct/system/plaintext fallback. HTTP redirects, cache/pooling/retries отсутствуют.
Client deadline может прервать exit failover раньше перебора всех8 IP.
Loopback доступен другим локальным процессам, нет per-user ACL/rate limiting.

Exit должен получить согласованный `--tls-dns-upstream-config`: adapter не может
удалённо доказать наличие pin и не включает его автоматически. Без pin exit
может использовать свой обычный resolver. Внешнего TLS-сертификата VPN в этой
ветке нет — это transparent relay, проверяется TLS-сертификат DoH origin.
IPv6 endpoint поддержан, но IPv6 VPN/системный DNS/общий killswitch не реализованы
этим пакетом. Состояние ready означает только bind, не доступность upstream.

Проверки:44 новых preflight/runtime/CLI регрессии включены в acceptance.
Проверены UDP/TCP A/AAAA, wrong CA/name/PSK, timeout/reset/redirect, exit down,
immutable snapshot, отказ name lookup, ровно exit+origin TCP dials в loopback
fixture, отсутствие QNAME в наблюдаемом TLS wire, rollback startup, отмена active
request, private PSK reader, SIGINT/SIGTERM и cleanup. Первые локальные прогоны
выявили ошибки новых test fixtures (не тот API loopback policy; dgram вызывает
lookup и для numeric bind); fixtures исправлены, runtime policy не ослаблялась.

Полный acceptance **643 Node-теста (25 файлов) +14 Chrome/Firefox PASS**, без
skips; report `/var/tmp/meshpn-acceptance-KMjvRH/report.json`. Дополнительно
**8/8 real namespace tests PASS**: прежние4 pinned route +4 нового adapter
(IPv4/IPv6 × transparent/combo runtime). Новый public adapter делает по8 запросов,
16 настоящих exit→origin TCP attempts,6 DoH bodies,0 DNS lookups на case:
refused first IP, trusted TLS, wrong CA без body, reset без retry после TCP,
all-down exhaustion, restart recovery, A/AAAA UDP/TCP. Public aliases живут
только наlo внутри отдельного namespace, uplink отсутствует. Сокеты, таймеры
и дочерние процессы освобождены; полный clean-vpn/TUN/mux не запускался.

Далее: независимый pcap и bounded soak **нового in-memory client→exit пути**.
Прежние pcap/soak использовали lab TLS через localhost TCP relay listener;
их результаты не являются проверкой нового adapter. Затем отдельно согласовать
OS/LAN/IPv6 integration. Динамические BoringSSL profiles и cover DNS не добавлялись.

## 37. Независимый pcap и bounded soak нового DNS adapter

Добавлен `npm run dns:adapter-soak`: отдельный namespace runner для реального
`startDnsExitAdapter` с in-memory TLS/enc-SNI, не старого localhost TLS listener.
Инструкция — [`scripts/dns-adapter-soak.md`](../scripts/dns-adapter-soak.md).
Используется настоящий public compiled profile и pinned route exit, ephemeral
CA и проверка имени resolver. Public IPv4/IPv6 aliases существуют только наlo
в приватном user/net/mount/PID namespace; uplink отсутствует. Linux namespace,
PID1/private proc и отсутствие других интерфейсов проверяются до fixture.
Mesh, clean-vpn CLI, TUN, host firewall/routes/system DNS/live VPN не менялись.

Общий launcher прежнего DNS soak выделен в вызываемую `dnsSoakMain`; старый CLI
и его workload сохранены. Новый entry выбирает строго свой parser/workload/
validator. Seconds1..600, concurrency1..8, family4/6 и две runtime modeTag.
Report exclusive0600, bounded stdout, parent deadline seconds+60с, SIGINT/SIGTERM
с cleanup и aborted. Нет аргументов deployment IP/config/PSK и нет сетевых
скачиваний. Ключи/pcap удаляются из собственного mkdtemp, report остаётся.

pcap: tcpdump всех namespace TCP/UDP, tshark без DNS/decryption keys.
Точные address+port endpoints: loopback stub, plaintext positive control,
exit, resolver, refused first IP. IPv4/IPv6, оба направления обязательны,
включая refused SYN/RST; payload на refused запрещён. Контрольный QNAME обязан
найтись у stub/control, но не на двух TLS legs. Reassembly проверяет prefix,
seq/gaps/overlap/retransmits; unknown endpoints/UDP на TLS/truncation/drop/empty
capture вызывают fail. Capture count сравнивается с tshark. Это короткая
fault-matrix перед soak, не захват всего длительного прогона. В одном worker
pcap не атрибутирует PID отправителя на разрешённом origin leg; дополнительно
проверяются exact dial/body counters и отдельные adapter tests.

Один adapter живёт весь workload.10 warmup waves; измеряемые циклы normal,
NXDOMAIN, large/UDP TC, reset/hold/redirect, origin down/restart, exit listener
down/restart, silent accepted exit, cut active exit, заполнение in-flight
лимита (лишний SERVFAIL без dial), TCP requester reset после origin body.
Fixture deadline250мс, production default1500мс не изменён. Проверяется
освобождение client sockets/jobs и exit sockets/sessions/timers, DNS lookups=0.
Parent сверяет точные counts ответов, ошибок, отказов/отмен, connection attempts
и bodies относительно baseline — не только exit0.

На каждом цикле idle fd/memory/active resources/private process tree сверяются
с бюджетами; JSON sample примерно раз в5с. V8 old64MiB/semi8MiB, без forced GC;
RSS ceiling256MiB, fd128, idle fd≤baseline, рост RSS≤64MiB/heapUsed≤32MiB от
warmup high-water. Replay cache удерживается штатные601с, не очищается между
запросами ради красивой памяти. Успех ограничен данными сценариями/временем;
не доказательство отсутствия всех side channels или вечных memory leaks.

Следующий шаг — расширение DNS wire contract за пределы IN A/AAAA перед
системной интеграцией. Затем отдельно согласовать opt-in client/OS/LAN/IPv6.

Real regression matrix:9 новых проверок PASS (IPv4/IPv6 × transparent/combo,
concurrency1/8; SIGINT/SIGTERM; missing tcpdump/tshark; exclusive report и отказ
worker вне namespace). Прежние6 DNS pcap/soak real tests также PASS после
выделения общего launcher. Новый real-набор повторён после усиления endpoint/
traffic-counter audit:9/9 PASS. Unit audit/validator/options:35 новых проверок,
включая injected plaintext обоих TLS legs/направлений, разрезанный marker,
gaps/overlap/truncation, чужие endpoints и фальсифицированные итоговые counters.

Два длительных прогона выполнены параллельно в разных namespaces, оба PASS:

- IPv4 transparent concurrency4:300.055с,279 waves,13671 replies (9207 ожидаемых
  SERVFAIL),558 listener restarts,279 overload rejects и279 TCP cancellations.
  Pcap1631 packets; sampled RSS106.93MiB / heap21.99MiB, рост от warmup6.06/3.09MiB.
  Report `/var/tmp/meshpn-dns-soak-report-3Pl6Ou/report.json`.
- IPv6 combo concurrency8:301.050с,228 waves,22116 replies (14820 ожидаемых
  SERVFAIL),456 restarts,228 rejects/cancellations. Pcap3119 packets;
  sampled RSS107.93MiB / heap23.42MiB, рост6.11/3.01MiB.
  Report `/var/tmp/meshpn-dns-soak-report-Libb6L/report.json`.

Final owned sockets/jobs/timers/sessions/listeners=0; worker fd23→19,
children/zombies=0, DNS lookups=0. Replay entries11893/19362 остаются в штатном
окне601с; память не «улучшалась» принудительной очисткой/GC. Expected failures
сверены точными counters. Raw pcap/ephemeral keys удалены, reports сохранены.

Финальный общий acceptance выполнен отдельно после soak: **678 Node-тестов
(26 файлов) +14 Chrome/Firefox сценариев PASS**, без skips. Report
`/var/tmp/meshpn-acceptance-kmeQCV/report.json`. Runtime DNS adapter и relay
в этом пакете не менялись: добавлены тестовый fixture, audit, workload/runner,
регрессии и документация. README обновлён с результатами и следующим этапом.

## 38. Расширение DNS wire contract (2026-09-23)

Снято ограничение только A/AAAA в общем bounded parser, используемом lab и
explicit client→exit adapter. Теперь обычные IN-типы, в том числе HTTPS/SVCB,
TXT, SRV, PTR и неизвестные типы, передаются без изменения RDATA. Проверяются
DNS envelope, question matching, RR/OPT lengths и limits, но не семантика новых
RDATA/подписи DNSSEC. Контракт и точные exclusions — [dns-wire.md](../scripts/dns-wire.md).

Бинарные labels принимаются; сравнение question ASCII-only с сохранением границ
labels, без коллизии embedded-dot и разделителя. Сканирование всех байтов question
на compression marker заменено проверкой реально разобранных указателей.
EDNS(0) допускает extended response RCODE, проверяет наличие request OPT;
UDP truncation больше не теряет high RCODE. Синтетический TC не содержит частичных
RR/ссылок на удалённые данные, сохраняет RA/RD/CD, сбрасывает AA/AD. Неизвестные
EDNS options передаются в полном сообщении, не копируются в локальную ошибку/TC.

Новые39 wire-регрессий и13 adapter-регрессий (12 для дополнительных типов UDP/TCP,
одна HTTPS UDP TC→TCP с extended RCODE). Восемь типов через реальный TLS
client→exit→resolver сверяются побайтно. Общий acceptance: **730 Node-тестов
(27 файлов) +14 Chrome/Firefox сценариев PASS**, без skips. Report:
`/var/tmp/meshpn-acceptance-r56pU9/report.json`.

Сохранены общий лимит4096 байт/128 RR, IN/QUERY/single-question policy; исключены
meta/transfer/ANY, другие EDNS versions. Это ещё не универсальный системный DNS.
Следующий этап: полный размер TCP/DoH DNS65535 с отдельным UDP cap и memory budgets,
EDNS negotiation и HTTP cache-age/TTL contract; затем согласовать opt-in OS/LAN/IPv6
lifecycle. Действующая система, OS DNS, firewall, TUN и mesh не менялись.

После изменения parser повторены4 public-contract real-теста IPv4/IPv6 ×
transparent/combo: PASS. Короткие повторные pcap/soak (старые A/AAAA fault-matrices,
не pcap всех новых типов) по30с измеряемой нагрузки, concurrency4:

- IPv4/transparent: PASS, `/var/tmp/meshpn-dns-soak-report-zoP4lN/report.json`.
- IPv6/combo: PASS, `/var/tmp/meshpn-dns-soak-report-UW5sYR/report.json`.

Оба прогона: ресурсные бюджеты соблюдены, после cleanup owned sockets/jobs/timers/
sessions/listeners=0, fd23→19, DNS lookups=0; raw pcap/PEM удалены. Отчёты сохранены.

## 39. Полный размер TCP/DoH, EDNS negotiation и HTTP Age (2026-09-23)

В shared DNS stub/parser TCP/DoH query и response теперь до65535 байт;
UDP input/output отдельно ограничен4096. Лимит128 RR и остальные pilot exclusions
сохранены. DNS/DoH body больше не собирается списком chunks: фиксированный
buffer65535; TCP pending input — фиксированные131074 байта (два максимальных
frames). Нет repeated concat растущего input. In-flight/socket caps, absolute
deadline/lifetime, cancellation по RST и backpressure сохранены. Stats добавляют
`peakTcpPendingBytes`/`peakDohBodyBytes`. Payload-buffer budget при default16/16
консервативно6MiB, при caps64/64 —24MiB, без Node/TLS/kernel overhead.

Unknown EDNS query version1..255 после проверки envelope получает локальный
BADVERS/version0 с пустым OPT до admission, без TCP dial/DoH/fallback. Invalid
extended query RCODE/options по-прежнему отбрасываются; response EDNS version>0
не принимается. Никакого автоматического downgrade/retry.

DoH request `Cache-Control: no-cache, no-store`. `dns-http-age.mjs` разбирает raw
Age headers: только один decimal delta-seconds, OWS только SP/HTAB; malformed/
duplicate → SERVFAIL, overflow насыщается на2^31. Возраст + целые monotonic секунды
exchange вычитаются из RR-header TTL всех секций с нижней границей0; high-bit TTL
трактуется как0. OPT/RDATA/signatures/AD полного ответа не переписываются.
Для Authority SOA в NOERROR/NXDOMAIN TTL сначала ограничивается MINIMUM, включая
ответ с CNAME chain; два SOA names и20 байт полей проверяются. Malformed SOA →
SERVFAIL, не попытка читать последние4 байта произвольного RDATA. Кэша/HTTP
revalidation/локальной DNSSEC validation нет. Детали и RFC — [wire contract](../scripts/dns-wire.md).

Добавлены23 wire-регрессии и17 adapter-регрессий: TXT4096/4097/65535, padded query65535,
local BADVERS без dial, chunked/Content-Length overflow, Age/negative SOA/CNAME,
slow body, буферизация и отмена. Public-contract real matrix расширена для всех
IPv4/IPv6 × transparent/combo:15 запросов на сценарий,26 pinned TCP attempts,
11 resolver bodies,0 DNS lookups; CA/reset/exhaustion/recovery/cleanup сохранены.
Все4 real-теста PASS после SOA/CNAME уточнения.

С новыми буферами повторены два60с soak, concurrency8, с независимым pcap перед
измерением. Матрица soak остаётся A/AAAA с обрывами/перегрузкой/отменой; **не**
длительный soak максимальных TXT65535. Каждый:48 волн,4656 ответов,3120 ожидаемых
SERVFAIL,384 NXDOMAIN,192 TC,96 рестартов,48 отклонений перегрузки и48 отмен.

- IPv4/transparent PASS: sampled RSS≤105.04MiB, heap≤18.50MiB;
  `/var/tmp/meshpn-dns-soak-report-iOjswX/report.json`.
- IPv6/combo PASS: sampled RSS≤106.80MiB, heap≤18.13MiB;
  `/var/tmp/meshpn-dns-soak-report-Gheu7M/report.json`.

Финал обоих: owned sockets/jobs/timers/sessions/listeners=0, fd23→19, children/
zombies=0, DNS lookups=0, ресурсные бюджеты соблюдены; raw pcap/PEM удалены.
Следующий шаг — согласованный opt-in OS/client/LAN/IPv6 lifecycle, сначала dry-run
и изолированный стенд. Live VPN, системный DNS, TUN/firewall и mesh не менялись.

Финальный acceptance после уточнений CNAME/SOA и strict HTTP OWS: **770 Node-тестов
(27 файлов) +14 Chrome/Firefox сценариев PASS**, без skips, выполнен отдельно
после soak. Report `/var/tmp/meshpn-acceptance-kuHqW2/report.json`.

## 40. DNS lifecycle: dry-run и системный resolver в namespace

Добавлены [описание и команды](../scripts/dns-lifecycle.md), чистая модель
`scripts/lib/dns-lifecycle.mjs`, offline CLI `npm run dns:lifecycle` и отдельный
`npm run dns:lifecycle-lab -- --family=4|6`. Host backend не выбран: пользователь
пока не знает владельца DNS на настоящем клиенте; нужна read-only диагностика.
Нет `--apply`, установки сервиса или автоматического изменения host DNS.

Контракт: snapshot → независимый guard → adapter/readiness probe → выбор DNS
с проверкой владения и отдельным acknowledgement. Потеря exit/listener не
восстанавливает открытый DNS. Restart сохраняет исходный snapshot. Чужое изменение
настроек → conflict без перезаписи. Только явный disable восстанавливает baseline
под guard, подтверждает восстановление и затем снимает guard.

Реальный стенд — user/net/mount/PID namespaces, private propagation, PID1, только
lo; mount guard проверяется до мутаций. Synthetic resolv.conf/nsswitch bind mounts,
приватный /run без host nscd, сравнение host файлов до/после. Namespace-only DNAT
port53→high-port adapter; остальные UDP/TCP53 блокируются IPv4/IPv6. Через glibc
getent проверены23 lookup на каждый IPv4/IPv6 combo exit/upstream вариант:
A/AAAA UDP/TCP, baseline positive controls, exit outage/recovery, недоступный
mapping, external config conflict, блокирование foreign DNS, explicit restore,
startup readiness failure. Флаг getent -A нужен для A lookup в IPv6-only fixture,
иначе AI_ADDRCONFIG подавляет запрос ещё до DNS.

Оба real-теста PASS: запросов к baseline во время защиты0, exit OS lookup0;
owned adapter sockets/jobs/timers0, children/zombies0 после cleanup.
Добавлены20 unit/CLI тестов, включены в acceptance manifest (теперь28 файлов).
Полный acceptance **790 Node +14 Chrome/Firefox сценариев PASS**, без skips;
report `/var/tmp/meshpn-acceptance-SBJc54/report.json`.

Ограничения: state model — не durable executor; fixture владеет жизнью adapter,
потеря mapping — не SIGKILL процесса. Не проверены reboot, journal recovery,
concurrent apply/restore, NetworkManager/resolved, LAN/split DNS. Sentinel counters
не заменяют pcap. Guard53 не блокирует произвольные DoH/DoT и не заменяет VPN
kill-switch; существующий autostart kill-switch с LAN exceptions и своим stop
lifecycle не подходит как готовый DNS guard. Текущий adapter требует enc-SNI exit,
не обычный tls-only. Host DNS/firewall/routes/TUN, live VPN и mesh не менялись.

Далее: диагностика клиента → один выбранный backend → durable ownership journal
и SIGKILL/reboot/interrupted transaction tests в изоляции → согласованный opt-in
live pilot. Production-статус combo-tls пока не повышаем.

## 41. Namespace journal и настоящие SIGKILL DNS-контроллера

В `dns:lifecycle-lab` добавлен `--crash`; отдельная команда проверки:
`npm run test:dns-lifecycle-crash-real`. Все изменения остаются в лаборатории,
host backend ещё не выбран. Основное описание — [DNS lifecycle](../scripts/dns-lifecycle.md).

`dns-lifecycle-journal.mjs`: фиксированный bounded JSON≤8192, UID/mode0600,
каталог0700, без symlink/hardlink и неизвестных полей. Private snapshot/managed
files fsync до journal commit. Journal writer: exclusive temp → file fsync →
rename → directory fsync. Незавершённый temp не используется при recovery.
Сохраняются ID транзакции, namespace scope, фаза, dev:ino и SHA-256 объектов;
restore hash обязан совпасть с original hash. Журнал не содержит DNS-текста,
путей для исполнения, ключей или команд.

`dns-lifecycle-transaction.mjs`: experimental executor поверх fixture backend.
Уточнён порядок enable и dry-run: guard до snapshot/journal. Если commit ещё нет,
missing journal оставляет защиту и требует ручного разбора, не угадывает baseline.
Recovery active/applying делает защищённый probe и сохраняет первоначальный ID.
Restoring/restored/released заканчивает ранее явно запрошенное отключение;
guard снимается после проверки восстановленного объекта, а не просто по факту
перезапуска. Released record сохраняется, автоматической ротации/new enable поверх
завершённого журнала нет. Это не durable OS backend общего назначения.

Отдельный controller-процесс держит flock на стабильном private lock inode,
через bounded RPC обращается к namespace init. Родитель посылает SIGKILL в
подтверждённых контрольных точках, ждёт реального завершения, затем запускает
новый процесс, читающий журнал с диска. Backend, adapter и namespace живут дальше.
Mount guard вынесен в общий `dns-lifecycle-namespace.mjs` и проверяется до мутаций.

Для IPv4 и IPv6 combo fixture прошли по13 SIGKILL:6 enable (prepared/apply intent/
applied/active temp fsync/rename/commit),6 disable (restore intent/mount/rename/
commit/guard removed/released),1 до первого commit. Проверяются getent до/после
recovery, сохранение ID, отказ второго контроллера с exit75 и освобождение flock
после смерти первого. Семь отказов recovery: missing/corrupt journal, foreign
inode с тем же текстом, чужой IPv6 DNS, stale namespace, повреждённый snapshot,
exit down. Настройки не перезаписываются, guard остаётся; baseline counters не
растут до разрешённого отключения. В конце sockets/jobs/timers0, children/zombies0.

Добавлены30 journal/transaction unit-тестов; acceptance manifest теперь29 файлов.
Повторная focused матрица: **54 теста PASS** (20 lifecycle +30 journal +4 real).
Финальный полный acceptance: **820 Node +14 Chrome/Firefox сценариев PASS**,
без skips; `/var/tmp/meshpn-acceptance-k2KMmC/report.json`.

Границы: это process crash в том же ядре, **не** reboot/power loss, не SIGKILL
adapter/backend/PID1, не arbitrary DNS manager race. Dev:ino+hash и проверки перед
mount не являются kernel CAS против внешнего менеджера. Каждый testcase имеет
свой каталог; между ними оператор стенда сбрасывает fixture, это не production
auto-recovery. Нет полного autostart lifecycle, LAN/split DNS или защиты от
произвольных DoH/DoT. Системный DNS/firewall/TUN, живой VPN и mesh не менялись.

Далее: read-only диагностика реального клиента и выбор backend; адаптация журнала
к его объектам/владению, полный lifecycle adapter, затем boot ordering и reboot/
power-loss tests в VM. Живой VPS ради этих тестов не перезагружаем.

## 42. Read-only DNS evidence collector

Добавлена команда `npm run dns:inspect` / `node scripts/dns-inspect.mjs`
([контракт](../scripts/dns-inspect.md)). Запуск без sudo на настоящем Linux VPN
клиенте; нет сетевых DNS/upstream probes, записи конфигов, установки сервиса,
SSH или автоматического выбора backend. JSON stdout не содержит nameserver IP,
search domains, hostname, произвольных путей, raw comments/errors или секретов.

Bounded reads фиксированных resolv.conf/nsswitch/proc1 comm/mountinfo; metadata
и известная категория resolver symlink, отдельная mountpoint, counts/booleans.
Только при PID1=systemd — четыре фиксированных read-only systemctl is-active,
2с/4KiB каждый, минимальное environment без remote bus settings. В другом init
service probes пропускаются, чтобы не обращаться к проброшенному host bus.
Нет доступа/ошибка → unknown/unavailable, не доказательство отсутствия менеджера.

Из symlink, NSS resolve, комментариев и service states получаем кандидатов,
но `backend=unselected`, `actualClientConfirmed=false`, `requiresReview=true`
остаются всегда. NM+resolved могут составлять цепочку управления, не конфликт.
Regular resolv.conf и отсутствие признаков сервисов не доказывают unmanaged DNS.
Это point-in-time evidence, не effective-config/ownership/health audit.

В доступном рабочем окружении PID1 не systemd, resolver regular, hosts=files dns;
это не подтверждённая машина VPN-клиента. Отчёт не использован для выбора backend.
Повторный запуск с побайтовой проверкой resolver/nss до/после подтвердил неизменность
обоих файлов. Живой VPN, DNS/firewall/routes/TUN и mesh не менялись.

Добавлены14 unit/CLI тестов: resolved/NM/resolvconf evidence, цепочка менеджеров,
отсутствие обращения к bus при другом init, redaction, denied/unknown, mountpoint,
bounded file reads и строгий CLI без apply/remote/file flags. Manifest30 файлов.
Полный acceptance: **834 Node +14 Chrome/Firefox сценариев PASS**, без skips;
`/var/tmp/meshpn-acceptance-ZMOhtn/report.json`.

Для продолжения нужен JSON этой команды именно с настоящего клиента и
подтверждение роли машины. Затем — адресная проверка эффективной конфигурации
менеджера, выбор одного backend, адаптация журнала; полный adapter lifecycle и
VM boot/reboot tests остаются впереди. Live переключение отдельно согласуется.

## 43. Исправление Radxa inspection и настоящий resolved backend в namespace

Уточнены реальные роли: VPS предполагается также использовать **клиентом другого
exit**, не self-connect. На VPS из отчёта пользователя active resolved/networkd.
На Radxa loaded resolved, inactive/dead, disabled; journal текущей загрузки пуст,
`/etc/resolv.conf` ссылается на отсутствующий `/run/systemd/resolve/stub-resolv.conf`.
Причина отключения неизвестна. Ничего на этих машинах агент не включал/не менял.

Исправлен баг `dns:inspect`: при unavailable metadata target был undefined,
пустая строка mountinfo давала undefined mount path, `.includes(undefined)`
ошибочно возвращал true. Теперь учитываются только валидные строки и строковые
пути, декодируются mount escapes. Реальный mount не теряется при metadata error.
Metadata читает lstat/readlink отдельно от realpath, сохраняет тип оборванной
ссылки и известную категорию declared target. В redacted JSON добавлены
`targetStatus`, `readError`; missing/permission-denied/symlink-loop различаются,
без raw paths/errors. Radxa case показывает dangling-resolver-symlink, не mount.
Добавлены4 регрессии, включая настоящий dangling symlink и loop во временных файлах.

Добавлен [экспериментальный resolved backend](../scripts/dns-resolved.md):
`dns-resolved-backend.mjs` с инъекцией namespace bus, snapshot DNSEx/Domains/
DefaultRoute, захватом unique D-Bus owner и identity выделенного link. Guard →
protected readiness → SetLinkDNSEx/SetLinkDomains/SetLinkDefaultRoute с read-back.
Managed destination127.0.0.1:high-port adapter, ~., DefaultRoute=true; resolv.conf
backend не переписывает. Явный disable восстанавливает снимок, не RevertLink.
Foreign properties, смена owner/link, lost setter reply → conflict, guard остаётся.
Пустой DNS baseline отклоняется; параллельные операции одного controller запрещены.

В `dns:lifecycle-lab --resolved` настоящий dbus-daemon и systemd-resolved запускаются
в private net/mount/PID/user/UTS, без systemd PID1 и host system bus. Private /run,
systemd config, passwd/group/NSS; имя хоста fixture. passwd нужен для D-Bus EXTERNAL:
host UID здесь обычно предоставляется cauth NSS, недоступным после изоляции /run.
Root-mapped запуск этого расширения отклоняется. Dummy link принадлежит fixture;
host resolver/NSS/passwd/group bytes проверяются до/после. No network uplink/TUN.
DNAT базового стенда удаляется: getent идёт в настоящий resolved stub, затем через
SetLinkDNSEx в high-port adapter → enc-SNI combo exit → проверенный DoH upstream.
Другие UDP/TCP53 блокируются для обеих семей, app→stub разрешён отдельно.

Тестовый binary: systemd255.4-1ubuntu8.17, пакет скачан `apt-get download` и
распакован `dpkg-deb --extract`, **не установлен**. Для повторения в этом окружении:
`MESHPN_SYSTEMD_RESOLVED=/tmp/meshpn-resolved-tools.IwwVqt/root/usr/lib/systemd/systemd-resolved
npm run test:dns-resolved-real` (переменная и команда на одной shell строке).
Host libsystemd-shared той же версии. Default CLI ничего не скачивает и не пропускает
проверки при отсутствии daemon/busctl/dbus-daemon.

IPv4 и IPv6 real tests PASS: каждый23 базовых+9 resolved glibc lookups, exact
snapshot restore, foreign-domain refusal, exit outage/recovery, настоящий SIGKILL
resolved. В255.4 link settings переживают restart в /run: защищённый DNS снова
работает, но owner изменён, старый controller отказывает в disable. Это не
неожиданный fallback и не успешный автоматический adoption нового daemon.
Baseline counters во время защиты не растут; final owned resources0,
children/zombies0. Повторно прошли все6 real-тестов: базовый lifecycle, journal
crash и resolved, каждый IPv4/IPv6. Добавлены16 resolved unit-тестов; manifest31 файл.
Полный acceptance: **854 Node +14 Chrome/Firefox сценариев PASS**, без skips;
`/var/tmp/meshpn-acceptance-010Gcb/report.json`.

Ограничения: snapshot resolved **in-memory**, не связан с inode journal.
Нет durableResolvedRecovery, controller-crash reconciliation D-Bus setters,
межпроцессного lock resolved backend, adapter crash, reboot/power loss,
production polkit и manager races, сложного split DNS/нескольких links. Snapshot
содержит значения API, не происхождение implicit/default настроек менеджера.
Базовая fixture отключает cache/fallback/LLMNR/mDNS/DoT/DNSSEC только внутри lab;
это не production политика. Guard53 не универсальный kill-switch.

Далее — journal schema owner/link/properties и per-setter intents, SIGKILL
контроллера на каждом переходе, далее adapter lifecycle и VM reboot. Восстановление
штатного resolved на Radxa и live opt-in на VPS отдельно согласуются. Живой VPN,
системный DNS/firewall/TUN и mesh не менялись.

## 44. Persistent journal для resolved и recovery между D-Bus setters

Раздел43 описывает прежний in-memory smoke; он сохранён. Новый opt-in стенда
`dns:lifecycle-lab --resolved-journal` связывает persistent transaction controller
с настоящим resolved backend. Live integration не включена.

`dns-resolved-journal.mjs`: отдельная строгая bounded схема, transaction ID,
scope net/mnt/pid, bus GetId, unique resolved owner, link ifindex/name/MAC,
original/managed/start snapshots DNSEx/Domains/DefaultRoute, direction/cursor/
pending/stage. Общие private read/write helpers вынесены из inode journal без
изменения старой схемы. Directory0700, regular single-link journal0600, UID check,
no-follow,64KiB cap. В resolved журнале есть **исходные адреса и домены**; он
не предназначен для публикации. В отчёте lab их нет.

Отдельный namespace child держит process-lifetime flock, shared worker выбирает
только file/resolved transaction. Для каждого setter: durable intent → D-Bus →
read-back → durable ack; каждая запись fsync(temp)/rename/fsync(directory).
При pending принимаются только полные snapshots «до»/«после» текущего setter;
успешный setter с потерянным ответом не повторяется. Любое третье состояние,
изменённый bus/owner/link/scope, отсутствующий/испорченный журнал → отказ с guard.
Для apply recovery проверяются прежний порт adapter и protected readiness.
Guard удаляется только после сверки восстановленных настроек и context.
Disable частичного apply сначала фиксирует restore intent; recovery следует
durable направлению, не придумывает rollback. Terminal released record остаётся;
повторный enable с ним отвергается, автоматической ротации нет.

Private bus adapter использует GetId: один unique owner не защищает от новой
шины с повторившимся именем. Смена owner resolved после SIGKILL/restart по-прежнему
не означает автоматическое разрешение на adoption. Read/check/set не CAS;
конкурирующие сетевые менеджеры и ABA этим протоколом не устранены.

Новая real-матрица:27 точек prepared, intent/set/ack каждого из трёх setters
apply/restore, fsync/rename, restore intent/completion и guard removal/released.
Ещё missing journal, corrupt, foreign pending state, stale scope, bus-ID mismatch,
exit outage, daemon-owner change; flock contention, partial-apply disable.
Всего31 реальный SIGKILL контроллера на семью IP. Baseline отличается во всех
свойствах; resolved нормализует стандартный DNS порт в DNSEx к0. Используется
baseline.test с явным route/search domain, положительными controls до/после и
реальными glibc lookups между crash/recovery и после отказов. UDP/TCP53 guards
и sentinel counters проверяют отсутствие fallback. Report содержит nested
resolved.journal; durableResolvedRecoveryImplemented=true только в этом режиме.

90 новых unit-тестов охватывают все fsync/rename/ack границы, lost replies,
recovery/disable частичного apply, identity/endpoint conflicts, readiness failure,
unsafe journal files, смену durable направления и проверку перед guard removal.
Acceptance manifest расширен до32 файлов. Тяжёлая real-матрица запускается отдельно:
`MESHPN_SYSTEMD_RESOLVED=/path/to/systemd-resolved npm run test:dns-resolved-journal-real`.

Границы: backend RPC/adapter/namespace init остаются живы при смерти контроллера;
это не проверка смерти DNS adapter, reboot/power loss, production polkit,
сложного split DNS или implicit/default происхождения настроек менеджера.
Следующий шаг — вынести adapter в отдельный управляемый процесс, проверить его
SIGKILL/перезапуск, стабильный endpoint, readiness и сохранение guard. Затем VM
reboot/power-loss. Radxa DNS repair и live opt-in остаются отдельным согласованием.

Проверено с настоящим systemd255.4-1ubuntu8.17: все8 real-тестов PASS без skips
(базовый lifecycle, file journal crash, in-memory resolved и resolved journal,
каждый IPv4/IPv6). Новая матрица занимает около99с на семью IP; deadline240с.
В каждой новой матрице31 controller SIGKILL,27 восстановленных checkpoints,
7 refusal cases и1 lock conflict. На завершении нет дочерних процессов/zombies,
adapter sockets/jobs/timers освобождены; файлы DNS/NSS/passwd/group хоста неизменны.
Полный acceptance: **944 Node +14 Chrome/Firefox сценариев PASS**, без skips;
`/var/tmp/meshpn-acceptance-HdpwwM/report.json` (рабочее дерево перед коммитом).

## 45. Настоящий процесс DNS-adapter: SIGKILL, прежний endpoint, readiness

Добавлен namespace-only режим `dns:lifecycle-lab --resolved-adapter` и
[его контракт](../scripts/dns-adapter-process.md). В отличие от раздел44 убивается
не controller, а процесс с настоящим `startDnsExitAdapter`. Родительская fixture
владеет guard, resolved/D-Bus, exit/origin и журналом. После штатного smoke старый
in-process adapter закрывается, child занимает тот же high port127.0.0.1.
Никаких изменений live DNS/firewall/TUN/mesh, systemd unit или установки resolved.

`dns-adapter-process.mjs` — explicit start/refresh/stop/close без autorestart,
до12 запусков/256 IPC запросов, один запрос одновременно, IPC5с, reaping с
SIGKILL escalation5с. `dns-adapter-process-worker.mjs` — private namespace child
с проверкой PID1 parent и provenance net/mnt/pid. Config и секрет идут по IPC,
не argv/env/file; child заново компилирует public pinned upstream profile.
Строгие поля, config15KiB/message16KiB, stdout/stderr4KiB, heap96MiB. Не live CLI.

Bind не равен readiness. Persistent resolved transaction перед apply/recover
требует живой child, его IPC snapshot и успешные UDP+TCP queries через exit/DoH.
При SIGKILL/неудачном bind/upstream outage guard остаётся, snapshot и journal
не перезаписываются, transaction ID сохраняется. Порт не меняется автоматически.
После смерти child кеш stats инвалидируется, не подменяется нулями. После
graceful shutdown реальные final stats проверяются, child reaped. Родительский
lab.stats продолжает описывать закрытый исходный adapter и общий exit/origin;
новый child проверяется отдельно через refresh, эти наблюдения не смешиваются.

Для каждой семьи pinned exit/upstream: initial enable без adapter, listener
при остановленном exit, protected recovery,3 idle SIGKILL,1 SIGKILL с2 реально
in-flight UDP/TCP queries (held DoH origin, child inflight/requests==2), UDP и
TCP bind conflicts, повторный старт, graceful stop, explicit disable при мёртвом
adapter.5 successful starts,2 failed starts,10 refused enable/recover операций.
62 glibc checks:23 базовых+9 resolved+30 process-lifecycle. Baseline positive
controls до/после, sentinel counters и guard checks в обоих IP families.

Обнаружено: glibc TCP к живому resolved при мёртвом upstream иногда не укладывается
в RES_OPTIONS timeout:1. Новый режим для ожидаемого отказа ограничивает getent3с;
такая отмена явно отмечена `:client-deadline` и не называется SERVFAIL/ответом.
Проверки ожидаемого успеха по-прежнему проваливаются на timeout. Доступность
ограничена: отсутствие утечки не означает немедленный возврат ошибки приложению.

35 новых unit/CLI tests, manifest33 файла; отдельные real tests для IPv4/IPv6.
Child idle RSS<192MiB,FD<64 и owned resources0; final namespace children/zombies0.
Это конечный lifecycle smoke, не длительный soak, не смерть namespace init,
не совместное падение controller+adapter и не reboot/power-loss. Непрерывная
доступность при рестарте, недоверенный локальный захват порта, implicit/default
настройки менеджера, split DNS и production permissions не подтверждены.

Далее — boot/recovery protocol и VM reboot/power-loss. Старый journal привязан
к scope/bus/owner/link; после смены context он безопасно отказывает, но не умеет
автоматически присваивать новое состояние. Runtime guard после reboot потерян:
нужны отдельные boot ordering/guard-before-DNS проверки, а не просто повторное
чтение JSON. Live opt-in и восстановление DNS Radxa отдельно согласуются.

Проверка с systemd255.4-1ubuntu8.17: все10 real-тестов PASS без skips — base,
file journal, in-memory resolved, resolved journal и adapter process, каждый
IPv4/IPv6. Новый process lifecycle занимает около31с на семью (deadline120с).
Отдельный повтор с явной проверкой2 in-flight jobs перед SIGKILL тоже PASS
для обеих семей. Host resolver/NSS/passwd/group bytes неизменны.
Полный acceptance: **979 Node +14 Chrome/Firefox сценариев PASS**, без skips;
`/var/tmp/meshpn-acceptance-5pqIe6/report.json` (рабочее дерево перед коммитом).

## 46. Offline boot/recovery protocol и VM preflight; VM ещё не запускалась

Следующий этап раздел45 начат с [контракта boot/recovery](../scripts/dns-boot.md),
pure state machine `lib/dns-boot.mjs`, CLI `npm run dns:boot` и read-only
`npm run dns:vm-preflight`. Это подготовка, **не завершённые reboot/power-cut tests**.
Не созданы live units/installer, VM launcher, guest image или новая journal schema.

Сценарии fresh/previous-boot/same-boot/corrupt/adapter-down/disable/power-loss
детерминированы; default previous-boot останавливается для review. После new-boot
сбрасываются guard/readiness/admission. Сначала явный opt-in, установка guard и
его acknowledgement; затем journal/current owner. Старый boot/context не даёт
права overwrite/restore; новый epoch требует operator approval, owned link,
текущий проверенный baseline и сохранение старого journal. Текущий durable
restore intent не превращается в apply. Adapter bound не readiness; нужны
protected UDP+TCP, matching context, DNS read-back и durable ack перед admission.
Explicit disable записывает intent до restore, guard снимается после проверки.

Это модель желаемых действий и входного evidence, не исполнитель и не измерение
реального guard. Boot ID — часть предлагаемого протокола, не молчаливая миграция
существующего namespace journal. Все JSON reports сохраняют vmStarted/rebootTested/
powerLossTested=false. Нельзя использовать offline scenario power-loss как
доказательство сохранности fsync при настоящем отключении питания.

Preflight смотрит metadata QEMU/kernel/initrd/disk без запуска процессов и без
записи. QEMU read/execute, непустые regular files, disk symlink/block-device
отклоняются; initrd/disk не выбираются из host defaults. Только kernel может
использовать `/boot/vmlinuz`. Никакого использования host initramfs. Path values
не выводятся. Даже при наличии всех файлов launchAuthorized=false,
artifactVerificationRequired=true; executable/image authenticity не проверяется.
TCG запланирован без KVM, без сетевых устройств, host shared folders/disks/ports.

Фактический preflight этого окружения: QEMU отсутствует, `/dev/kvm` отсутствует,
kernel доступен (7253760 bytes), guest initrd/disk не предоставлены. apt metadata
содержит QEMU, но пакеты/образы не скачивались и не устанавливались. Запрошено
отдельное подтверждение локальной загрузки/подготовки VM; ответа на момент этого
этапа нет. VM, guest reboot и QEMU power-cut **не выполнялись**.

43 новых unit/CLI tests, acceptance manifest34 файла. Документированы ограничения
systemd ordering: Before/After не гарантируют успешный запуск dependency;
network-pre.target сам не фильтрует DNS. Для VM нужны guard-before-consumer,
ошибки раннего boot, current-owner proof, сохранение прежнего journal, graceful
reboot и abrupt guest power-cut с описанной cache/flush моделью. SIGKILL QEMU
не уничтожает host page cache и не является физическим power-loss proof.
Полный acceptance: **1022 Node +14 Chrome/Firefox сценариев PASS**, без skips;
`/var/tmp/meshpn-acceptance-5vvunE/report.json` (рабочее дерево перед коммитом).
Новых real/VM тестов этот этап не добавляет; прежние namespace real suites
не выдаются за проверку настоящего reboot.

## 47. Настоящая изолированная QEMU VM: persistent journal и новые загрузки

Пользователь согласовал локальную VM после раздела46. Добавлен
[`dns:vm-lab`](../scripts/dns-vm-lab.md): explicit paths tools/kernel/resolved,
новые временные initramfs и raw ext4-диски, без установки пакетов на хост,
без host initramfs, общего filesystem, физического диска или сети VM.
QEMU8.2.2 распакован из Ubuntu `.deb`; hashes сверены с локальными APT pool
metadata. Минимальный гость использует доступное ядро5.4.210-39.1.pagevecsize,
BusyBox init и явный набор локальных ELF/библиотек; manifest хеширует inputs.
Это не скачанный полный Linux-дистрибутив и не systemd PID1.

1 vCPU/1024MiB/TCG, `-nic none`, отдельный256MiB ext4 на сценарий,
`cache=writeback` с guest flush. Внутри guest UID1000 и реальные private
user/net/mount/pid/uts namespaces, private D-Bus, systemd-resolved255,
настоящий DNS adapter→enc-SNI exit→TLS DoH fixture. Нет TUN или интернет-адресатов:
public-contract IP aliases принадлежат только loopback namespace.
Timeout adapter увеличен только параметром fixture для TCG; default250ms
существующих стендов не изменён. Fixture CA extension теперь явный, без
зависимости от host OpenSSL config; TLS verification не отключалась.

Guard UDP/TCP53 IPv4/IPv6 ставится до lo/workload. Реальные glibc запросы к
двум baseline sentinels блокируются; после explicit disable оба дают ответы
по UDP/TCP. Protected A/AAAA и UDP/TCP readiness идут через настоящий adapter.
После новой загрузки меняется boot ID, `/run` новый, link DNS runtime пустой.
Старый journal проверяется на ожидаемые direction/cursor/pending/stage,
но не применяется к новому bus/context. Missing committed journal не подменяется
orphan temp. Старый каталог сохраняется; новая эпоха разрешается **только
сценарием fixture** и начинает новую транзакцию текущего baseline. Это не
production adoption API и не изменение schema namespace journal.

Матрица: graceful guest reboot и8 SIGKILL QEMU checkpoints — prepared
file-fsync/rename, apply DNSEx intent-dir-fsync/set, Domains ack-dir-fsync,
restore DNSEx set/DefaultRoute ack-dir-fsync, guard-removed. 18 холодных загрузок
ядра на9 приватных дисках. На процесс QEMU deadline240s; serial logs bounded,
ошибка останавливает дальнейшие кейсы; артефакты приватные и сохраняются для разбора.

Важная обнаруженная граница: hot reset внутри одного QEMU зависал после
`Restarting system` (с1/2 vCPU и другим reboot method тоже). Эти запуски
завершены по deadline и не объявлены PASS. Рабочий graceful протокол:
guest sync/remount-ro → guest reboot syscall → QEMU `-no-reboot` exit →
перезапуск QEMU с тем же диском. Последняя версия отдельно проверяет marker
от init после sync/remount-ro и kernel restart message. Это настоящая новая
загрузка с потерей guest runtime, но **не успешный in-process hardware hot reset**.
SIGKILL QEMU сохраняет host page cache: physicalPowerLossTested=false.

Live clean-vpn/DNS/firewall/TUN хоста не менялись; данные `device/ap-*`
не включаются в этот этап. Дальше — guest boot-fault cases (guard/storage/
corrupt journal/adapter readiness), затем systemd PID1 и ordering ранних
consumer/services в госте. Для live opt-in по-прежнему нужен отдельный review
владельца DNS клиента; повреждённый resolv.conf Radxa не исправляется автоматически.

Регрессия этого этапа: 10 реальных DNS lifecycle-тестов PASS (IPv4/IPv6 для base,
file journal, resolved, resolved journal, adapter process). Полный acceptance:
**1040 Node +14 Chrome/Firefox сценариев PASS**, без skips,
`/var/tmp/meshpn-acceptance-7x4L83/report.json`. Добавлены18 unit/CLI VM checks,
acceptance manifest35 файлов. Строгий graceful reboot с marker после
sync/remount-ro и kernel restart evidence — PASS,
`/var/tmp/meshpn-dns-vm-J64ZJO/report.json`; hostDnsFilesUnchanged=true.

Полная VM-матрица: **9/9 сценариев PASS, 18 разных boot ID**, 8 SIGKILL QEMU,
`/var/tmp/meshpn-dns-vm-iTdXxF/report.json`; hostDnsFilesUnchanged=true,
baselineQueriesDuringProtection=0 во всех кейсах. Для prepared:file-synced
committed journal отсутствовал, orphan не принимался за recovery input;
после prepared:renamed (ещё без directory fsync) committed journal тоже отсутствовал.
Отсутствие журнала не снимало guard. Физический power-loss
и обычный systemd boot этим результатом не подтверждены.

Подготовленные здесь tools: `/tmp/meshpn-dns-vm-tools.dXb7TM`;
resolved: `/tmp/meshpn-resolved-tools.IwwVqt/root/usr/lib/systemd/systemd-resolved`;
kernel: `/boot/vmlinuz-5.4.210-39.1.pagevecsize`. Это локальные временные артефакты,
не переносимые зависимости репозитория; при повторе launcher снова сверяет
SHA-256 `.deb` с APT metadata. Бинарники/диски/serial logs в git не добавлены.

## DNS v1: boot faults и systemd VM (2026-09-25)

Зафиксирована конечная граница в [`scripts/dns-v1.md`](../scripts/dns-v1.md):
один выбранный клиент, systemd-resolved, без произвольного split DNS/LAN и без
автоматического присвоения чужих настроек. После VM — конфигурация/развёртывание
на согласованном клиенте и один24-часовой пилот по
[`dns-pilot.md`](../scripts/dns-pilot.md), затем возврат к транспорту.
VM не заменяет пилот; Radxa/VPS автоматически не перенастраиваются.

`dns:vm-lab --case=faults`:4/4 PASS,
`/var/tmp/meshpn-dns-vm-rnhZv5/report.json`, hostDnsFilesUnchanged=true.
Реальная ошибка iptables без CAP_NET_ADMIN до поднятия lo/consumers; bind-remount
journal read-only/EROFS; повреждённый JSON с сохранением bytes; stopped exit
и провал readiness до setters. После отказов — отсутствие baseline fallback,
явное восстановление protected A/AAAA и disable с positive controls обоих
baseline sentinels. Readiness recovery сохраняет transaction ID.

Новые режимы не расширяют `--case=all` молча: он по-прежнему9 reboot/cut кейсов;
`faults` —4 загрузки, `systemd` — отдельный двухзагрузочный lifecycle.
Обычный VM lookup теперь timeout5s/attempts1: в TCG старый1s обрывал здоровый
TLS-запрос; диагностика показала2 успешных probes и1 ещё in-flight без ошибок.
Production таймауты не менялись, проверки ответов/fallback не ослаблялись.

[`dns-systemd-vm.md`](../scripts/dns-systemd-vm.md): минимальный образ с настоящим
systemd255 PID1. Builder добавляет явные ELF/systemd-executor/shutdown/umount,
синтетические units/config и offline `systemd-analyze verify --root=GUEST`.
Guard ставится ещё BusyBox init до exec PID1; systemd сам может поднять lo.
Network/adapter/controller/consumer управляются настоящими unit dependencies,
не моделью в JS. Adapter Type=notify после protected UDP/TCP readiness;
controller — persistent resolved backend/journal под flock; BindsTo+After
останавливают consumers при потере зависимости.

`stop` и SIGKILL не выполняют disable. Включение перепроверяет реальные rules,
даже если oneshot guard unit показывает active: explicit disable мог их снять.
Released/stale journal не разрешает молчаливое повторное включение. Чужие Domains
не затираются; explicit disable восстанавливает только свой context baseline.
После reboot старый journal сохраняется, но не используется новым bus/link;
новая эпоха разрешается явным действием fixture, не автоматической live policy.
Это fail-closed, а не обещание unattended DNS availability после reboot.

Root fixture adapter объединяет adapter+exit+DoH origin в одном сервисе.
Его SIGKILL шире adapter-only; последний отдельно покрыт namespace process lab.
VM entrypoints отказывают на хосте до изменений; допустимы только QEMU marker,
systemd PID1, guest root namespaces и интерфейсы lo/dnsfixture. Fixture D-Bus
policy/units не переносятся в production. Системный DNS/маршруты/TUN хоста
и mesh-код не менялись; независимый uplink capture остаётся частью пилота.

При подготовке минимального образа обнаружены missing systemd-executor/umount,
неправильный StandardOutput=console (нужен tty), права synthetic /etc под umask077,
неверный владелец заранее созданного resolved runtime directory. Исправлены в
builder; ошибочные запуски не объявлялись PASS. Старое ядро5.4 отклоняет часть
auxiliary cgroup kill: тест использует точный systemctl SIGKILL MainPID сервиса.
Serial parser допускает приставленный без newline статус PID1, но не повреждённый
JSON; проверяет реальные sync/unmount и kernel reboot, а не только намерение.

Полная регрессия: **1051 Node +14 Chrome/Firefox PASS**, без skips,
`/var/tmp/meshpn-acceptance-KwYJYR/report.json`. Отдельно10/10 real DNS tests
IPv4/IPv6 (base/file journal/resolved/resolved journal/adapter process) PASS.
До запуска клиентского пилота нужны выбранный узел, ownership review, конкретная
service/guard конфигурация и разрешение/аварийный доступ. Документы не являются
установщиком и не объявляют DNS v1 или весь combo-tls production-ready.

Systemd VM завершена: **PASS,2 загрузки PID1,11 проверок/9 критериев**,
`/var/tmp/meshpn-dns-vm-lJHO3D/report.json`. Host DNS files и guest resolv.conf
не изменены, baselineQueriesDuringProtection=0, automaticStaleAdoption=false.
Оба shutdown прошли sync/unmount; reboot подтверждён ядром и разными boot ID.
Все144 JS files в image manifest совпадают с текущим рабочим деревом.

После systemd доработок обычная boot-fault матрица повторена на окончательном
коде: **4/4 PASS**, `/var/tmp/meshpn-dns-vm-fvtXdN/report.json`;
hostDnsFilesUnchanged=true, baselineQueriesDuringProtection=0 во всех кейсах.
